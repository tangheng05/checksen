//! Who a forwarded message came from: an official channel, or a personal account posing as a bank or Telegram.

use super::link;

/// Official Telegram channels, by username. Only add handles you have confirmed in Telegram itself.
const OFFICIAL_CHANNELS: &[(&str, &str)] = &[
    ("telegram", "Telegram"),
    ("telegramtips", "Telegram"),
    ("durov", "Telegram"),
];

/// Where a forwarded message came from, as Telegram reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sender {
    /// A person's account rather than a channel or group.
    pub personal: bool,
    pub name: String,
    pub username: Option<String>,
}

/// The owner of the official channel a message was forwarded from.
pub fn official(sender: &Sender) -> Option<&'static str> {
    if sender.personal {
        return None;
    }
    let username = sender.username.as_deref()?.to_ascii_lowercase();
    OFFICIAL_CHANNELS
        .iter()
        .find(|(handle, _)| *handle == username)
        .map(|(_, owner)| *owner)
}

/// The brand a personal account claims to be. Banks and Telegram never write to people from personal accounts.
pub fn impersonated(sender: &Sender) -> Option<&'static str> {
    if !sender.personal {
        return None;
    }
    let name_as_handle = sender.name.split_whitespace().collect::<Vec<_>>().join("_");
    sender
        .username
        .as_deref()
        .and_then(link::impersonated_brand)
        .or_else(|| link::impersonated_brand(&name_as_handle))
        .or_else(|| {
            sender
                .name
                .to_lowercase()
                .contains("telegram")
                .then_some("Telegram")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(name: &str, username: Option<&str>) -> Sender {
        Sender {
            personal: true,
            name: name.to_owned(),
            username: username.map(str::to_owned),
        }
    }

    #[test]
    fn personal_accounts_posing_as_banks_or_telegram_are_caught() {
        assert_eq!(impersonated(&person("ABA Bank Support", None)), Some("ABA"));
        assert_eq!(
            impersonated(&person("Sokha", Some("ACLEDA_Help_Desk"))),
            Some("ACLEDA")
        );
        assert_eq!(
            impersonated(&person("Telegram Security", None)),
            Some("Telegram")
        );
        assert_eq!(impersonated(&person("Wing", None)), None);
        assert_eq!(impersonated(&person("សុខា", Some("sokha_kh"))), None);
        let channel = Sender {
            personal: false,
            ..person("ABA Bank Support", None)
        };
        assert_eq!(impersonated(&channel), None);
    }

    #[test]
    fn only_listed_channels_are_official() {
        let channel = |username: &str| Sender {
            personal: false,
            name: "Telegram News".to_owned(),
            username: Some(username.to_owned()),
        };
        assert_eq!(official(&channel("Telegram")), Some("Telegram"));
        assert_eq!(official(&channel("telegram_news_kh")), None);
        assert_eq!(official(&person("Telegram", Some("telegram"))), None);
    }
}
