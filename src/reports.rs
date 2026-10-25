use std::sync::Arc;

use teloxide::prelude::*;
use teloxide::types::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, User};

use checksen::analyzers::indicators::{Indicator, IndicatorKind};
use checksen::analyzers::{Check, Signal, Subject};
use checksen::verdict::{self, Lang};

use crate::bot::{self, Services};
use crate::guard::{Guard, Reply};
use crate::store::{REPORT_THRESHOLD, ReportOutcome, Reports, Review, Store};

/// A KHQR reply asks whether the payee is who they meant to pay; other replies with a phone
/// number, username or unknown site in them offer to report it. Every verdict asks 👍/👎.
pub fn keyboard(
    store: Option<&Store>,
    guard: &Guard,
    reply: &Reply,
    lang: Lang,
) -> Option<InlineKeyboardMarkup> {
    let store = store?;
    let mut rows = Vec::new();
    if let Some(account) = &reply.account {
        if let (Some(yes), Some(no)) = (
            store.callback_data(true, account),
            store.callback_data(false, account),
        ) {
            rows.push(vec![
                InlineKeyboardButton::callback(verdict::INTENDED_BUTTON.get(lang), yes),
                InlineKeyboardButton::callback(verdict::NOT_INTENDED_BUTTON.get(lang), no),
            ]);
        }
    } else if !reply.reportable.is_empty() {
        let report = store.report_callback(guard.report_button(&reply.reportable));
        rows.push(vec![InlineKeyboardButton::callback(
            verdict::REPORT_BUTTON.get(lang),
            report,
        )]);
    }
    if let Some(summary) = &reply.summary {
        let id = guard.feedback_button(summary);
        rows.push(vec![
            InlineKeyboardButton::callback(
                verdict::HELPFUL_BUTTON.get(lang),
                store.feedback_callback(true, id),
            ),
            InlineKeyboardButton::callback(
                verdict::NOT_HELPFUL_BUTTON.get(lang),
                store.feedback_callback(false, id),
            ),
        ]);
    }
    (!rows.is_empty()).then(|| InlineKeyboardMarkup::new(rows))
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
    bot::remove_row(&bot, message, data).await;

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
            Ok(ReportOutcome::Recorded) => {
                notify_if_due(&bot, store, &services, &indicators).await;
                thanks
            }
            Ok(ReportOutcome::AlreadyReported) => thanks,
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

/// Tells reviewers when a contact has just reached enough reports to warn people.
async fn notify_if_due(bot: &Bot, store: &Store, services: &Services, indicators: &[Indicator]) {
    if services.admins.is_empty() {
        return;
    }
    match store.reporters_of(indicators).await {
        Ok(reports)
            if reports.iter().any(|reports| {
                reports.reporters == REPORT_THRESHOLD && reports.review == Review::Unreviewed
            }) =>
        {
            services.admins.notify(bot, &services.guard).await;
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "report lookup failed"),
    }
}

pub async fn with_reports(mut checks: Vec<Check>, store: Option<&Store>) -> Vec<Check> {
    let Some(store) = store else {
        return checks;
    };
    for check in &mut checks {
        let Subject::Khqr(payee) = &check.subject else {
            continue;
        };
        let account = Indicator::khqr_account(&payee.bakong_account_id);
        match store.reporters(&account).await {
            Ok(reports) => check.signals.extend(signal(account.kind, reports)),
            Err(error) => tracing::warn!(%error, "report lookup failed"),
        }
    }
    checks
}

/// A reviewer's decision wins; until there is one, enough reporters make it suspicious.
fn signal(kind: IndicatorKind, reports: Reports) -> Option<Signal> {
    match reports.review {
        Review::Confirmed => Some(Signal::ConfirmedScam(kind)),
        Review::Cleared => None,
        Review::Unreviewed if reports.reporters >= REPORT_THRESHOLD => {
            let reporters = u32::try_from(reports.reporters).unwrap_or(u32::MAX);
            Some(match kind {
                IndicatorKind::KhqrAccount => Signal::Reported(reporters),
                _ => Signal::ReportedScam(kind, reporters),
            })
        }
        Review::Unreviewed => None,
    }
}

/// The site a link check ended up on, as a reportable indicator.
pub fn link_domain(check: &Check) -> Option<Indicator> {
    let Subject::Link(link) = &check.subject else {
        return None;
    };
    Indicator::domain(link.redirected_to.as_deref().unwrap_or(&link.host))
}

/// Flags reported contacts: sites on their link check, phone numbers and usernames on the
/// text check.
pub async fn flag_reported(
    store: Option<&Store>,
    indicators: &[Indicator],
    text_check: &mut Check,
    link_checks: &mut [Check],
) {
    let Some(store) = store.filter(|_| !indicators.is_empty()) else {
        return;
    };
    let reports = match store.reporters_of(indicators).await {
        Ok(reports) => reports,
        Err(error) => {
            tracing::warn!(%error, "report lookup failed");
            return;
        }
    };
    for (indicator, reports) in indicators.iter().zip(reports) {
        let Some(signal) = signal(indicator.kind, reports) else {
            continue;
        };
        let check = match indicator.kind {
            IndicatorKind::Domain => link_checks
                .iter_mut()
                .find(|check| link_domain(check).as_ref() == Some(indicator)),
            _ => Some(&mut *text_check),
        };
        if let Some(check) = check
            && !check.signals.iter().any(|found| same_kind(*found, signal))
        {
            check.signals.push(signal);
        }
    }
}

/// One reason per kind of contact is enough, so two reported numbers aren't listed twice.
fn same_kind(found: Signal, signal: Signal) -> bool {
    match (found, signal) {
        (Signal::ReportedScam(found, _), Signal::ReportedScam(kind, _)) => found == kind,
        (Signal::ConfirmedScam(found), Signal::ConfirmedScam(kind)) => found == kind,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use checksen::analyzers::text;

    use super::*;

    #[test]
    fn a_review_decides_over_the_report_count() {
        let reports = |reporters, review| Reports { reporters, review };
        let phone = IndicatorKind::Phone;
        assert_eq!(
            signal(phone, reports(0, Review::Confirmed)),
            Some(Signal::ConfirmedScam(phone))
        );
        assert_eq!(signal(phone, reports(50, Review::Cleared)), None);
        assert_eq!(
            signal(phone, reports(REPORT_THRESHOLD - 1, Review::Unreviewed)),
            None
        );
        assert_eq!(
            signal(phone, reports(REPORT_THRESHOLD, Review::Unreviewed)),
            Some(Signal::ReportedScam(phone, 3))
        );
        assert_eq!(
            signal(
                IndicatorKind::KhqrAccount,
                reports(REPORT_THRESHOLD, Review::Unreviewed)
            ),
            Some(Signal::Reported(3))
        );
    }

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
