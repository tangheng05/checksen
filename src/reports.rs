use std::sync::Arc;

use teloxide::prelude::*;
use teloxide::types::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, User};

use checksen::analyzers::{Check, Signal, Subject};
use checksen::verdict;

use crate::store::{REPORT_THRESHOLD, ReportOutcome, Store};

pub fn keyboard(store: Option<&Store>, account: Option<&str>) -> Option<InlineKeyboardMarkup> {
    let (store, account) = store.zip(account)?;
    let yes = store.callback_data(true, account)?;
    let no = store.callback_data(false, account)?;
    Some(InlineKeyboardMarkup::new([[
        InlineKeyboardButton::callback(verdict::INTENDED_BUTTON_KM, yes),
        InlineKeyboardButton::callback(verdict::NOT_INTENDED_BUTTON_KM, no),
    ]]))
}

pub async fn forget_reply(store: Option<&Store>, user: Option<&User>) -> String {
    let (Some(store), Some(user)) = (store, user) else {
        return verdict::FORGET_KM.to_owned();
    };
    match store.forget(user.id.0).await {
        Ok(removed) => verdict::forgotten_km(removed),
        Err(error) => {
            tracing::warn!(%error, "forget failed");
            verdict::REPORT_FAILED_KM.to_owned()
        }
    }
}

pub async fn handle_callback(
    bot: Bot,
    query: CallbackQuery,
    store: Option<Arc<Store>>,
) -> ResponseResult<()> {
    bot.answer_callback_query(query.id.clone()).await?;
    let (Some(store), Some(message)) = (store, query.regular_message()) else {
        return Ok(());
    };
    let Some((intended, account)) = query
        .data
        .as_deref()
        .and_then(|data| store.verify_callback(data))
    else {
        return Ok(());
    };
    if let Err(error) = bot
        .edit_message_reply_markup(message.chat.id, message.id)
        .await
    {
        tracing::warn!(%error, "could not remove report buttons");
    }

    let reply = if intended {
        verdict::INTENDED_KM
    } else {
        match store.report(&account, query.from.id.0).await {
            Ok(ReportOutcome::Recorded | ReportOutcome::AlreadyReported) => verdict::REPORTED_KM,
            Ok(ReportOutcome::DailyLimit) => verdict::REPORT_LIMIT_KM,
            Err(error) => {
                tracing::warn!(%error, "report failed");
                verdict::REPORT_FAILED_KM
            }
        }
    };
    bot.send_message(message.chat.id, reply).await?;
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
        match store.reporters(&payee.bakong_account_id).await {
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
