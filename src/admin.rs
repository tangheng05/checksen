use std::sync::Arc;

use anyhow::Context;
use teloxide::prelude::*;
use teloxide::types::{
    CallbackQuery, FileId, InlineKeyboardButton, InlineKeyboardMarkup, InputFile, ParseMode, User,
};

use checksen::env_var;
use checksen::verdict::{self, Lang};

use crate::bot::Services;
use crate::guard::Guard;
use crate::store::{Decision, Queue, Review, Store};

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

/// Shows the next reported contact, `skipped` places down the queue, then shared messages.
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
        return show_next_shared(bot, chat, store, 0, lang).await;
    };
    let keyboard = buttons(store, Queue::Contacts, item.id, skipped, lang);
    bot.send_message(
        chat,
        verdict::review_item(&item.indicator, item.reporters, lang),
    )
    .parse_mode(ParseMode::Html)
    .reply_markup(keyboard)
    .await?;
    Ok(())
}

async fn show_next_shared(
    bot: &Bot,
    chat: ChatId,
    store: &Store,
    skipped: i64,
    lang: Lang,
) -> ResponseResult<()> {
    let next = match store.next_shared(skipped).await {
        Ok(next) => next,
        Err(error) => {
            tracing::warn!(%error, "could not load shared messages");
            bot.send_message(chat, verdict::REVIEW_FAILED.get(lang))
                .await?;
            return Ok(());
        }
    };
    let Some(shared) = next else {
        bot.send_message(chat, verdict::REVIEW_EMPTY.get(lang))
            .await?;
        return Ok(());
    };
    let keyboard = buttons(store, Queue::Shared, shared.id, skipped, lang);
    match &shared.photo_file_id {
        Some(photo) => {
            // Telegram allows 1,024 characters in a photo's caption.
            let caption: Option<String> = shared
                .text
                .as_deref()
                .map(|text| text.chars().take(600).collect());
            let caption =
                verdict::shared_item(caption.as_deref(), &shared.level, &shared.signals, lang);
            bot.send_photo(chat, InputFile::file_id(FileId(photo.clone())))
                .caption(caption)
                .parse_mode(ParseMode::Html)
                .reply_markup(keyboard)
                .await?;
        }
        None => {
            let text =
                verdict::shared_item(shared.text.as_deref(), &shared.level, &shared.signals, lang);
            bot.send_message(chat, text)
                .parse_mode(ParseMode::Html)
                .reply_markup(keyboard)
                .await?;
        }
    }
    Ok(())
}

fn buttons(store: &Store, queue: Queue, id: i64, skipped: i64, lang: Lang) -> InlineKeyboardMarkup {
    let button = |label: &verdict::Text, decision| {
        InlineKeyboardButton::callback(
            label.get(lang),
            store.review_callback(queue, decision, id, skipped),
        )
    };
    let mut row = vec![
        button(&verdict::REVIEW_SCAM_BUTTON, Decision::Scam),
        button(&verdict::REVIEW_CLEAR_BUTTON, Decision::NotScam),
    ];
    if queue == Queue::Shared {
        row.push(button(&verdict::REVIEW_DELETE_BUTTON, Decision::Delete));
    }
    row.push(button(&verdict::REVIEW_SKIP_BUTTON, Decision::Skip));
    InlineKeyboardMarkup::new([row])
}

pub async fn handle_callback(
    bot: Bot,
    query: CallbackQuery,
    services: Arc<Services>,
) -> ResponseResult<()> {
    let (Some(store), Some(message), Some(data)) = (
        services.store.as_deref(),
        query.regular_message(),
        query.data.as_deref(),
    ) else {
        bot.answer_callback_query(query.id.clone()).await?;
        return Ok(());
    };
    let review = store.verify_review_callback(data);
    let Some((queue, decision, id, skipped)) =
        review.filter(|_| services.admins.contains(Some(&query.from)))
    else {
        bot.answer_callback_query(query.id.clone()).await?;
        return Ok(());
    };
    let lang = services.guard.language(query.from.id.0, None);
    let chat = message.chat.id;
    let saved = match (queue, decision) {
        (_, Decision::Skip) => Ok(None),
        (Queue::Contacts, Decision::Delete) => Ok(None),
        (Queue::Contacts, Decision::Scam | Decision::NotScam) => {
            let review = if decision == Decision::Scam {
                Review::Confirmed
            } else {
                Review::Cleared
            };
            store.set_review(id, review).await.map(|indicator| {
                indicator.map(|indicator| {
                    verdict::reviewed(&indicator, review == Review::Confirmed, lang)
                })
            })
        }
        (Queue::Shared, _) => store.decide_shared(id, decision).await.map(|()| None),
    };
    let done = match saved {
        Ok(done) => done,
        Err(error) => {
            tracing::warn!(%error, "could not save a review");
            bot.answer_callback_query(query.id.clone())
                .text(verdict::REVIEW_FAILED.get(lang))
                .await?;
            return Ok(());
        }
    };
    let mut answer = bot.answer_callback_query(query.id.clone());
    if decision != Decision::Skip {
        answer = answer.text(verdict::REVIEW_SAVED.get(lang));
    }
    answer.await?;
    let edited = match done {
        Some(text) => bot
            .edit_message_text(chat, message.id, text)
            .parse_mode(ParseMode::Html)
            .await
            .map(drop),
        None => bot
            .edit_message_reply_markup(chat, message.id)
            .await
            .map(drop),
    };
    if let Err(error) = edited {
        tracing::warn!(%error, "could not mark a review as done");
    }
    // A decided item leaves the queue; a skipped one stays, so step past it.
    let skipped = skipped + i64::from(decision == Decision::Skip);
    match queue {
        Queue::Contacts => show_next(&bot, chat, store, skipped, lang).await,
        Queue::Shared => show_next_shared(&bot, chat, store, skipped, lang).await,
    }
}
