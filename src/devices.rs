use teloxide::prelude::*;
use teloxide::types::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup};

use checksen::verdict::{Device, Lang};

const PREFIX: &str = "d:";

fn data(device: Device) -> String {
    format!("{PREFIX}{device:?}")
}

pub fn keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new(Device::ALL.chunks(2).map(|row| {
        row.iter()
            .map(|&device| InlineKeyboardButton::callback(device.button(), data(device)))
            .collect::<Vec<_>>()
    }))
}

pub fn is_device(query: CallbackQuery) -> bool {
    query.data.is_some_and(|data| data.starts_with(PREFIX))
}

pub async fn handle_callback(bot: Bot, query: CallbackQuery) -> ResponseResult<()> {
    bot.answer_callback_query(query.id.clone()).await?;
    let device = Device::ALL
        .into_iter()
        .find(|&device| query.data.as_deref() == Some(data(device).as_str()));
    let (Some(device), Some(message)) = (device, query.regular_message()) else {
        return Ok(());
    };
    let lang = message.text().and_then(Lang::of).unwrap_or(Lang::Km);
    // The buttons stay, so a wrong tap can be changed.
    let edit = bot
        .edit_message_text(message.chat.id, message.id, device.steps(lang))
        .reply_markup(keyboard());
    if let Err(error) = edit.await {
        tracing::debug!(%error, "device steps not shown");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use checksen::verdict::OPENED_ASK;
    use teloxide::types::InlineKeyboardButtonKind;

    #[test]
    fn every_button_leads_to_its_device() {
        let buttons: Vec<_> = keyboard().inline_keyboard.concat();
        assert_eq!(keyboard().inline_keyboard.len(), 2);
        assert_eq!(buttons.len(), Device::ALL.len());
        for (button, device) in buttons.iter().zip(Device::ALL) {
            let InlineKeyboardButtonKind::CallbackData(data) = &button.kind else {
                panic!("not a callback button");
            };
            assert!(is_device(
                serde_json::from_value(serde_json::json!({
                    "id": "1", "from": {"id": 1, "is_bot": false, "first_name": "Sok"},
                    "chat_instance": "c", "data": data,
                }))
                .unwrap()
            ));
            assert_eq!(*data, super::data(device));
        }
        // The steps keep the language of the question they replace.
        for lang in [Lang::Km, Lang::En] {
            assert_eq!(Lang::of(OPENED_ASK.get(lang)), Some(lang));
            assert_eq!(Lang::of(&Device::Mac.steps(lang)), Some(lang));
        }
    }
}
