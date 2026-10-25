use std::collections::HashSet;
use std::sync::{PoisonError, RwLock};

use teloxide::prelude::*;
use teloxide::types::{Me, ReplyParameters};

use checksen::verdict::{self, Lang, Text};

use crate::store::Store;

/// Groups where an admin turned on `/protect`, kept in memory so every group message can be
/// checked against it for free, and saved when reports are on.
#[derive(Default)]
pub struct Protected(RwLock<HashSet<ChatId>>);

impl Protected {
    pub async fn load(store: Option<&Store>) -> anyhow::Result<Self> {
        let chats = match store {
            Some(store) => store.protected_chats().await?,
            None => Vec::new(),
        };
        Ok(Self(RwLock::new(chats.into_iter().map(ChatId).collect())))
    }

    pub fn contains(&self, chat: ChatId) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&chat)
    }

    fn set(&self, chat: ChatId, on: bool) {
        let mut chats = self.0.write().unwrap_or_else(PoisonError::into_inner);
        if on {
            chats.insert(chat);
        } else {
            chats.remove(&chat);
        }
    }
}

/// `/protect` and `/unprotect`, which only a group's admins may use.
pub async fn command(
    bot: &Bot,
    msg: &Message,
    me: &Me,
    protected: &Protected,
    store: Option<&Store>,
    on: bool,
    lang: Lang,
) -> ResponseResult<()> {
    let chat = msg.chat.id;
    let reply = if msg.chat.is_private() || msg.chat.is_channel() {
        &verdict::PROTECT_GROUPS_ONLY
    } else if !sent_by_admin(bot, msg).await {
        &verdict::PROTECT_ADMINS_ONLY
    } else if let Err(error) = save(store, chat, on).await {
        tracing::warn!(%error, "could not save group protection");
        &verdict::PROTECT_FAILED
    } else {
        protected.set(chat, on);
        match on {
            true if !sees_messages(bot, chat, me).await => &verdict::PROTECT_NEEDS_ADMIN,
            true => &verdict::PROTECT_ON,
            false => &verdict::PROTECT_OFF,
        }
    };
    say(bot, msg, reply, lang).await
}

/// Telegram gives a group a new id when it becomes a supergroup, which making the bot an
/// admin can trigger, so protection moves with it.
pub async fn migrate(protected: &Protected, store: Option<&Store>, from: ChatId, to: ChatId) {
    if !protected.contains(from) {
        return;
    }
    protected.set(to, true);
    protected.set(from, false);
    let saved = async {
        save(store, to, true).await?;
        save(store, from, false).await
    };
    if let Err(error) = saved.await {
        tracing::warn!(%error, "could not move group protection to the new group id");
    }
}

/// Without a database, protection lasts until the bot restarts.
async fn save(store: Option<&Store>, chat: ChatId, on: bool) -> anyhow::Result<()> {
    match store {
        Some(store) => store.set_protected(chat.0, on).await,
        None => Ok(()),
    }
}

async fn say(bot: &Bot, msg: &Message, text: &Text, lang: Lang) -> ResponseResult<()> {
    bot.send_message(msg.chat.id, text.get(lang))
        .reply_parameters(ReplyParameters::new(msg.id).allow_sending_without_reply())
        .await?;
    Ok(())
}

/// An anonymous admin writes as the group itself.
async fn sent_by_admin(bot: &Bot, msg: &Message) -> bool {
    if msg
        .sender_chat
        .as_ref()
        .is_some_and(|sender| sender.id == msg.chat.id)
    {
        return true;
    }
    let Some(user) = &msg.from else {
        return false;
    };
    match bot.get_chat_member(msg.chat.id, user.id).await {
        Ok(member) => member.is_privileged(),
        Err(error) => {
            tracing::warn!(%error, "could not check a group admin");
            false
        }
    }
}

/// Bots only see every group message as an admin, or with privacy mode turned off.
async fn sees_messages(bot: &Bot, chat: ChatId, me: &Me) -> bool {
    if me.can_read_all_group_messages {
        return true;
    }
    match bot.get_chat_member(chat, me.id).await {
        Ok(member) => member.is_privileged(),
        Err(error) => {
            tracing::warn!(%error, "could not check the bot's own rights");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_turns_on_and_off_per_group() {
        let protected = Protected::default();
        protected.set(ChatId(-1), true);
        assert!(protected.contains(ChatId(-1)));
        assert!(!protected.contains(ChatId(-2)));
        protected.set(ChatId(-1), false);
        assert!(!protected.contains(ChatId(-1)));
    }

    #[tokio::test]
    async fn protection_follows_a_group_that_becomes_a_supergroup() {
        let protected = Protected::default();
        protected.set(ChatId(-1), true);
        migrate(&protected, None, ChatId(-1), ChatId(-1001)).await;
        assert!(protected.contains(ChatId(-1001)));
        assert!(!protected.contains(ChatId(-1)));
        migrate(&protected, None, ChatId(-2), ChatId(-1002)).await;
        assert!(!protected.contains(ChatId(-1002)));
    }
}
