use std::sync::Arc;

use anyhow::Context;
use teloxide::prelude::*;
use teloxide::types::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, ParseMode, User};

use checksen::env_var;
use checksen::verdict::{self, Lang};

use crate::bot::Services;
use crate::guard::Guard;
use crate::store::{Decision, Review, Store};

/// The people in `ADMIN_IDS`, who review reported contacts.
#[derive(Default)]
pub struct Admins(Vec<UserId>);

impl Admins {
    pub fn from_env() -> anyhow::Result<Self> {
        env_var("ADMIN_IDS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(|id| {
                id.parse()
                    .map(UserId)
                    .with_context(|| format!("ADMIN_IDS has an invalid user id: {id}"))
            })
            .collect::<anyhow::Result<_>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, user: Option<&User>) -> bool {
        user.is_some_and(|user| self.0.contains(&user.id))
    }

    pub async fn notify(&self, bot: &Bot, guard: &Guard) {
        for admin in &self.0 {
            let lang = guard.language(admin.0, None);
            if let Err(error) = bot
                .send_message(*admin, verdict::REVIEW_DUE.get(lang))
                .await
            {
                tracing::warn!(%error, "could not tell a reviewer about new reports");
            }
        }
    }
}

pub fn is_review(query: CallbackQuery) -> bool {
    query.data.is_some_and(|data| data.starts_with("v:"))
}

/// Shows the next reported contact, `skipped` places down the queue.
pub async fn show_next(
    bot: &Bot,
    chat: ChatId,
    store: &Store,
    skipped: i64,
    lang: Lang,
) -> ResponseResult<()> {
    let next = match store.next_to_review(skipped).await {
        Ok(next) => next,
        Err(error) => {
            tracing::warn!(%error, "could not load the review queue");
            bot.send_message(chat, verdict::REVIEW_FAILED.get(lang))
                .await?;
            return Ok(());
        }
    };
    let Some(item) = next else {
        bot.send_message(chat, verdict::REVIEW_EMPTY.get(lang))
            .await?;
        return Ok(());
    };
    let button = |label: &verdict::Text, decision| {
        InlineKeyboardButton::callback(
            label.get(lang),
            store.review_callback(decision, item.id, skipped),
        )
    };
    let keyboard = InlineKeyboardMarkup::new([[
        button(&verdict::REVIEW_SCAM_BUTTON, Decision::Confirm),
        button(&verdict::REVIEW_CLEAR_BUTTON, Decision::Clear),
        button(&verdict::REVIEW_SKIP_BUTTON, Decision::Skip),
    ]]);
    bot.send_message(
        chat,
        verdict::review_item(&item.indicator, item.reporters, lang),
    )
    .parse_mode(ParseMode::Html)
    .reply_markup(keyboard)
    .await?;
    Ok(())
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
    if !services.admins.contains(Some(&query.from)) {
        return Ok(());
    }
    let Some((decision, id, skipped)) = store.verify_review_callback(data) else {
        return Ok(());
    };
    let lang = services.guard.language(query.from.id.0, None);
    let chat = message.chat.id;
    let Some(review) = decision.review() else {
        if let Err(error) = bot.edit_message_reply_markup(chat, message.id).await {
            tracing::warn!(%error, "could not remove review buttons");
        }
        return show_next(&bot, chat, store, skipped + 1, lang).await;
    };
    let edited = match store.set_review(id, review).await {
        Ok(Some(indicator)) => {
            let text = verdict::reviewed(&indicator, review == Review::Confirmed, lang);
            bot.edit_message_text(chat, message.id, text)
                .parse_mode(ParseMode::Html)
                .await
                .map(drop)
        }
        Ok(None) => bot
            .edit_message_reply_markup(chat, message.id)
            .await
            .map(drop),
        Err(error) => {
            tracing::warn!(%error, "could not save a review");
            bot.send_message(chat, verdict::REVIEW_FAILED.get(lang))
                .await?;
            return Ok(());
        }
    };
    if let Err(error) = edited {
        tracing::warn!(%error, "could not mark a review as done");
    }
    show_next(&bot, chat, store, skipped, lang).await
}
