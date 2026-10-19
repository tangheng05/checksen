use std::sync::Arc;

use teloxide::prelude::*;
use teloxide::types::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, User};

use checksen::analyzers::indicators::{Indicator, IndicatorKind};
use checksen::analyzers::{Check, Signal, Subject};
use checksen::verdict::{self, Lang};

use crate::bot::Services;
use crate::guard::{Guard, Reply};
use crate::store::{REPORT_THRESHOLD, ReportOutcome, Store};

/// A KHQR reply asks whether the payee is who they meant to pay; other replies with a phone
/// number, username or unknown site in them offer to report it.
pub fn keyboard(
    store: Option<&Store>,
    guard: &Guard,
    reply: &Reply,
    lang: Lang,
) -> Option<InlineKeyboardMarkup> {
    let store = store?;
    if let Some(account) = &reply.account {
        let yes = store.callback_data(true, account)?;
        let no = store.callback_data(false, account)?;
        return Some(InlineKeyboardMarkup::new([[
            InlineKeyboardButton::callback(verdict::INTENDED_BUTTON.get(lang), yes),
            InlineKeyboardButton::callback(verdict::NOT_INTENDED_BUTTON.get(lang), no),
        ]]));
    }
    if reply.reportable.is_empty() {
        return None;
    }
    let report = store.report_callback(guard.report_button(&reply.reportable));
    Some(InlineKeyboardMarkup::new([[
        InlineKeyboardButton::callback(verdict::REPORT_BUTTON.get(lang), report),
    ]]))
}

pub async fn forget_reply(store: Option<&Store>, user: Option<&User>, lang: Lang) -> String {
    let (Some(store), Some(user)) = (store, user) else {
        return verdict::FORGET.get(lang).to_owned();
    };
    match store.forget(user.id.0).await {
        Ok(removed) => verdict::forgotten(removed, lang),
        Err(error) => {
            tracing::warn!(%error, "forget failed");
            verdict::FORGET_FAILED.get(lang).to_owned()
        }
    }
}

pub async fn handle_callback(
    bot: Bot,
    query: CallbackQuery,
    services: Arc<Services>,
) -> ResponseResult<()> {
    bot.answer_callback_query(query.id.clone()).await?;
    let (Some(store), Some(message), Some(data)) = (
        services.store.as_deref(),
        query.regular_message(),
        query.data.as_deref(),
    ) else {
        return Ok(());
    };
    let reported = store.verify_report_callback(data);
    let khqr = store.verify_callback(data);
    if reported.is_none() && khqr.is_none() {
        return Ok(());
    }
    if let Err(error) = bot
        .edit_message_reply_markup(message.chat.id, message.id)
        .await
    {
        tracing::warn!(%error, "could not remove report buttons");
    }

    let lang = message.text().and_then(Lang::of).unwrap_or(Lang::Km);
    let reporter = query.from.id.0;
    let (indicators, thanks) = match (reported, khqr) {
        (Some(id), _) => match services.guard.reported_by_button(id) {
            Some(indicators) => (indicators.to_vec(), &verdict::SCAM_REPORTED),
            None => (Vec::new(), &verdict::REPORT_EXPIRED),
        },
        (None, Some((false, account))) => {
            (vec![Indicator::khqr_account(&account)], &verdict::REPORTED)
        }
        _ => (Vec::new(), &verdict::INTENDED),
    };
    let reply = if indicators.is_empty() {
        thanks
    } else {
        match store.report_all(&indicators, reporter).await {
            Ok(ReportOutcome::Recorded | ReportOutcome::AlreadyReported) => thanks,
            Ok(ReportOutcome::DailyLimit) => &verdict::REPORT_LIMIT,
            Err(error) => {
                tracing::warn!(%error, "report failed");
                &verdict::REPORT_FAILED
            }
        }
    };
    bot.send_message(message.chat.id, reply.get(lang)).await?;
    Ok(())
}

pub async fn with_reports(mut checks: Vec<Check>, store: Option<&Store>) -> Vec<Check> {
    let Some(store) = store else {
        return checks;
    };
    for check in &mut checks {
        let Subject::Khqr(payee) = &check.subject else {
            continue;
        };
        match store
            .reporters(&Indicator::khqr_account(&payee.bakong_account_id))
            .await
        {
            Ok(reporters) if reporters >= REPORT_THRESHOLD => {
                check.signals.push(Signal::Reported(
                    u32::try_from(reporters).unwrap_or(u32::MAX),
                ));
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "report lookup failed"),
        }
    }
    checks
}

/// The site a link check ended up on, as a reportable indicator.
pub fn link_domain(check: &Check) -> Option<Indicator> {
    let Subject::Link(link) = &check.subject else {
        return None;
    };
    Indicator::domain(link.redirected_to.as_deref().unwrap_or(&link.host))
}

/// Adds `ReportedScam` where enough people reported a contact: sites to their link check,
/// phone numbers and usernames to the text check.
pub async fn flag_reported(
    store: Option<&Store>,
    indicators: &[Indicator],
    text_check: &mut Check,
    link_checks: &mut [Check],
) {
    let Some(store) = store.filter(|_| !indicators.is_empty()) else {
        return;
    };
    let reporters = match store.reporters_of(indicators).await {
        Ok(reporters) => reporters,
        Err(error) => {
            tracing::warn!(%error, "report lookup failed");
            return;
        }
    };
    for (indicator, reporters) in indicators.iter().zip(reporters) {
        if reporters < REPORT_THRESHOLD {
            continue;
        }
        let signal =
            Signal::ReportedScam(indicator.kind, u32::try_from(reporters).unwrap_or(u32::MAX));
        let check = match indicator.kind {
            IndicatorKind::Domain => link_checks
                .iter_mut()
                .find(|check| link_domain(check).as_ref() == Some(indicator)),
            _ => Some(&mut *text_check),
        };
        if let Some(check) = check
            && !check.signals.iter().any(
                |found| matches!(found, Signal::ReportedScam(kind, _) if *kind == indicator.kind),
            )
        {
            check.signals.push(signal);
        }
    }
}

#[cfg(test)]
mod tests {
    use checksen::analyzers::text;

    use super::*;

    #[tokio::test]
    async fn contacts_reported_by_enough_people_are_flagged() {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let store = Store::connect(&url, "test-secret-that-is-at-least-32-bytes")
            .await
            .unwrap();
        let user = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let message = format!("Call 0{} now", 12_000_000 + user % 1_000_000);
        let found = checksen::analyzers::indicators::in_text(&message);
        for reporter in 0..REPORT_THRESHOLD as u64 {
            store.report_all(&found, user + reporter).await.unwrap();
        }
        let mut text_check = text::check(&message);
        flag_reported(Some(&store), &found, &mut text_check, &mut []).await;
        assert!(matches!(
            text_check.signals[..],
            [Signal::ReportedScam(IndicatorKind::Phone, 3)]
        ));
    }
}
