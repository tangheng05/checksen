use std::sync::Arc;

use teloxide::prelude::*;
use teloxide::types::{
    CallbackQuery, InlineKeyboardButton, InlineKeyboardButtonKind, InlineKeyboardMarkup,
    ReplyParameters,
};

use checksen::verdict::{self, Lang, Text};

use crate::bot::{self, Services};
use crate::store::Store;

pub fn is_feedback(query: CallbackQuery) -> bool {
    query
        .data
        .is_some_and(|data| data.starts_with("f:") || data.starts_with("s:"))
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
    let lang = message.text().and_then(Lang::of).unwrap_or(Lang::Km);
    if let Some((helpful, id)) = store.verify_feedback_callback(data) {
        rate(&bot, &query, message, store, &services, helpful, id, lang).await
    } else if let Some((share, feedback)) = store.verify_share_callback(data) {
        bot.answer_callback_query(query.id.clone()).await?;
        answer_share(&bot, &query, message, store, share, feedback, lang).await
    } else {
        bot.answer_callback_query(query.id.clone()).await?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn rate(
    bot: &Bot,
    query: &CallbackQuery,
    message: &Message,
    store: &Store,
    services: &Services,
    helpful: bool,
    id: u64,
    lang: Lang,
) -> ResponseResult<()> {
    let toast = |text: &Text| {
        bot.answer_callback_query(query.id.clone())
            .text(text.get(lang))
    };
    let Some(summary) = services.guard.rated_by_button(id) else {
        toast(&verdict::FEEDBACK_EXPIRED).await?;
        return Ok(());
    };
    let feedback = match store
        .record_feedback(query.from.id.0, helpful, &summary)
        .await
    {
        Ok(Some(feedback)) => feedback,
        Ok(None) => {
            toast(&verdict::FEEDBACK_LIMIT).await?;
            return Ok(());
        }
        Err(error) => {
            tracing::warn!(%error, "could not save feedback");
            toast(&verdict::SHARE_FAILED).await?;
            return Ok(());
        }
    };
    remove_feedback_buttons(bot, message).await;
    // Only the person who sent it can agree to share it, so only in their own chat.
    let original = message
        .reply_to_message()
        .filter(|original| !helpful && message.chat.is_private() && shareable(original).is_some());
    let Some(original) = original else {
        toast(&verdict::FEEDBACK_THANKS).await?;
        return Ok(());
    };
    bot.answer_callback_query(query.id.clone()).await?;
    let keyboard = InlineKeyboardMarkup::new([[
        InlineKeyboardButton::callback(
            verdict::SHARE_BUTTON.get(lang),
            store.share_callback(true, feedback),
        ),
        InlineKeyboardButton::callback(
            verdict::NO_SHARE_BUTTON.get(lang),
            store.share_callback(false, feedback),
        ),
    ]]);
    // Replying to the original lets the Share button read it then, so nothing is held before.
    bot.send_message(message.chat.id, verdict::SHARE_ASK.get(lang))
        .reply_parameters(ReplyParameters::new(original.id))
        .reply_markup(keyboard)
        .await?;
    Ok(())
}

async fn answer_share(
    bot: &Bot,
    query: &CallbackQuery,
    message: &Message,
    store: &Store,
    share: bool,
    feedback: i64,
    lang: Lang,
) -> ResponseResult<()> {
    let reply = if !share {
        &verdict::NOT_SHARED
    } else {
        match message.reply_to_message().and_then(shareable) {
            Some((text, photo)) => {
                match store.share(feedback, query.from.id.0, text, photo).await {
                    Ok(()) => &verdict::SHARED,
                    Err(error) => {
                        tracing::warn!(%error, "could not save a shared message");
                        &verdict::SHARE_FAILED
                    }
                }
            }
            None => &verdict::SHARE_FAILED,
        }
    };
    bot.edit_message_text(message.chat.id, message.id, reply.get(lang))
        .await?;
    Ok(())
}

/// The text and photo a message can be shared with; files never are.
fn shareable(message: &Message) -> Option<(Option<&str>, Option<&str>)> {
    if message.document().is_some() {
        return None;
    }
    let text = message.text().or(message.caption());
    let photo = bot::largest_photo(message).map(|photo| photo.file.id.0.as_str());
    (text.is_some() || photo.is_some()).then_some((text, photo))
}

/// Keeps the other buttons under a verdict, like 🚩, after 👍/👎 is tapped.
async fn remove_feedback_buttons(bot: &Bot, message: &Message) {
    let Some(markup) = message.reply_markup() else {
        return;
    };
    let rows: Vec<Vec<InlineKeyboardButton>> = markup
        .inline_keyboard
        .iter()
        .filter(|row| {
            !row.iter().any(|button| {
                matches!(&button.kind, InlineKeyboardButtonKind::CallbackData(data) if data.starts_with("f:"))
            })
        })
        .cloned()
        .collect();
    if let Err(error) = bot
        .edit_message_reply_markup(message.chat.id, message.id)
        .reply_markup(InlineKeyboardMarkup::new(rows))
        .await
    {
        tracing::warn!(%error, "could not remove feedback buttons");
    }
}
