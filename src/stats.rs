use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Context;
use chrono::{Datelike, Days, NaiveDate, Utc};
use teloxide::prelude::*;
use teloxide::types::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Me, Recipient};

use checksen::env_var;
use checksen::verdict::{self, Lang};

use crate::bot::Services;
use crate::guard::Summary;
use crate::store::{Counted, Store};

const FLUSH_EVERY: Duration = Duration::from_secs(5 * 60);

/// Checks counted in memory and added to the database every few minutes, so no check waits
/// on a write.
#[derive(Default)]
pub struct Stats(Mutex<HashMap<Counted, i64>>);

impl Stats {
    pub fn count(&self, summary: &Summary) {
        let counted = Counted {
            subject: summary.subject,
            level: summary.level,
            category: summary.category,
        };
        *self.counts().entry(counted).or_default() += 1;
    }

    pub async fn flush(&self, store: &Store) {
        let counts: Vec<(Counted, i64)> = std::mem::take(&mut *self.counts()).into_iter().collect();
        if counts.is_empty() {
            return;
        }
        if let Err(error) = store.add_checks(&counts).await {
            tracing::warn!(%error, "could not save check counts; keeping them for next time");
            let mut kept = self.counts();
            for (counted, checks) in counts {
                *kept.entry(counted).or_default() += checks;
            }
        }
    }

    fn counts(&self) -> std::sync::MutexGuard<'_, HashMap<Counted, i64>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub async fn keep_flushing(stats: Arc<Stats>, store: Arc<Store>) {
    let mut every = tokio::time::interval(FLUSH_EVERY);
    every.tick().await;
    loop {
        every.tick().await;
        stats.flush(&store).await;
    }
}

/// `ALERT_CHANNEL` is a public `@name` or a numeric chat id.
pub fn channel_from_env() -> anyhow::Result<Option<Recipient>> {
    let Some(channel) = env_var("ALERT_CHANNEL") else {
        return Ok(None);
    };
    if channel.starts_with('@') {
        return Ok(Some(Recipient::ChannelUsername(channel)));
    }
    let id = channel
        .parse()
        .context("ALERT_CHANNEL must be a @name or a chat id")?;
    Ok(Some(Recipient::Id(ChatId(id))))
}

/// Cambodia has no daylight saving time, so its date is always UTC+7's.
fn today() -> NaiveDate {
    (Utc::now() + chrono::Duration::hours(7)).date_naive()
}

fn monday_of(day: NaiveDate) -> NaiveDate {
    day - Days::new(day.weekday().num_days_from_monday().into())
}

/// Once a week has ended, sends reviewers its numbers to post, once.
pub async fn send_weekly_drafts(bot: Bot, services: Arc<Services>) {
    let Some(store) = services.store.as_deref() else {
        return;
    };
    let mut hourly = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        hourly.tick().await;
        let last_week = monday_of(today()) - Days::new(7);
        // Counts still in memory belong to the week that just ended.
        services.stats.flush(store).await;
        match store.claim_week(last_week).await {
            Ok(true) => {
                if let Err(error) = send_draft(&bot, &services, store, last_week).await {
                    tracing::warn!(%error, "could not send the weekly numbers; retrying next hour");
                    if let Err(error) = store.unclaim_week(last_week).await {
                        tracing::warn!(%error, "could not retry the weekly numbers");
                    }
                }
            }
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "could not check the weekly numbers"),
        }
    }
}

async fn send_draft(
    bot: &Bot,
    services: &Services,
    store: &Store,
    week: NaiveDate,
) -> anyhow::Result<()> {
    let me = bot.get_me().await?;
    let Some(post) = post(store, week, &me).await? else {
        return Ok(());
    };
    for admin in services.admins.ids() {
        let lang = services.guard.language(admin.0, None);
        let mut draft = bot.send_message(
            *admin,
            format!("{}\n\n{post}", verdict::WEEKLY_DRAFT.get(lang)),
        );
        if services.alert_channel.is_some() {
            draft = draft.reply_markup(InlineKeyboardMarkup::new([[
                InlineKeyboardButton::callback(
                    verdict::POST_BUTTON.get(lang),
                    store.post_callback(week),
                ),
            ]]));
        }
        draft.await?;
    }
    Ok(())
}

/// A week's post in Khmer, then English; None for a week with no checks.
async fn post(store: &Store, week: NaiveDate, me: &Me) -> anyhow::Result<Option<String>> {
    let next = week + Days::new(7);
    let totals = store.totals(week, next).await?;
    if totals.checks == 0 {
        return Ok(None);
    }
    let (from, to) = (week.to_string(), (next - Days::new(1)).to_string());
    let [km, en] = [Lang::Km, Lang::En]
        .map(|lang| verdict::weekly_post(&from, &to, &totals, me.username(), lang));
    Ok(Some(format!("{km}\n\n{en}")))
}

/// The last 7 days, for a reviewer's `/stats`.
pub async fn show(
    bot: &Bot,
    chat: ChatId,
    services: &Services,
    store: &Store,
    me: &Me,
    lang: Lang,
) -> ResponseResult<()> {
    services.stats.flush(store).await;
    let to = today() + Days::new(1);
    let from = to - Days::new(7);
    let text = match store.totals(from, to).await {
        Ok(totals) => verdict::weekly_post(
            &from.to_string(),
            &today().to_string(),
            &totals,
            me.username(),
            lang,
        ),
        Err(error) => {
            tracing::warn!(%error, "could not load the numbers");
            verdict::STATS_FAILED.get(lang).to_owned()
        }
    };
    bot.send_message(chat, text).await?;
    Ok(())
}

pub fn is_post(query: CallbackQuery) -> bool {
    query.data.is_some_and(|data| data.starts_with("p:"))
}

pub async fn handle_callback(
    bot: Bot,
    query: CallbackQuery,
    me: Me,
    services: Arc<Services>,
) -> ResponseResult<()> {
    let lang = services.guard.language(query.from.id.0, None);
    let toast = |text: &verdict::Text| {
        bot.answer_callback_query(query.id.clone())
            .text(text.get(lang))
    };
    let (Some(store), Some(channel), Some(message), Some(week)) = (
        services.store.as_deref(),
        services.alert_channel.clone(),
        query.regular_message(),
        query
            .data
            .as_deref()
            .and_then(|data| services.store.as_deref()?.verify_post_callback(data)),
    ) else {
        bot.answer_callback_query(query.id.clone()).await?;
        return Ok(());
    };
    if !services.admins.contains(Some(&query.from)) {
        bot.answer_callback_query(query.id.clone()).await?;
        return Ok(());
    }
    // Claiming first means a second tap, or another reviewer, can't post the week twice.
    let posted = match store.mark_posted(week, true).await {
        Ok(false) => Ok(()),
        Ok(true) => match post(store, week, &me).await {
            Ok(Some(post)) => bot
                .send_message(channel, post)
                .await
                .map(drop)
                .map_err(Into::into),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    if let Err(error) = posted {
        tracing::warn!(%error, "could not post the weekly numbers");
        if let Err(error) = store.mark_posted(week, false).await {
            tracing::warn!(%error, "could not undo a failed weekly post");
        }
        toast(&verdict::POST_FAILED).await?;
        return Ok(());
    }
    toast(&verdict::POSTED).await?;
    if let Err(error) = bot
        .edit_message_reply_markup(message.chat.id, message.id)
        .await
    {
        tracing::warn!(%error, "could not remove the post button");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weeks_start_on_monday() {
        let sunday = NaiveDate::from_ymd_opt(2026, 10, 25).unwrap();
        let monday = NaiveDate::from_ymd_opt(2026, 10, 19).unwrap();
        assert_eq!(monday_of(sunday), monday);
        assert_eq!(monday_of(monday), monday);
    }
}
