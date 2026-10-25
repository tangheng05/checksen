//! The contact details in a message that people can report as a scam: phone numbers, Telegram
//! usernames and websites. Only these are stored, never the message they came from.

use std::sync::LazyLock;

use regex::Regex;

use super::{link, sites, text};

/// Enough for any real message; a message stuffed with numbers isn't a reason to hit the database harder.
const MAX_INDICATORS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorKind {
    KhqrAccount,
    Phone,
    TelegramUsername,
    Domain,
}

impl IndicatorKind {
    /// The name stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KhqrAccount => "khqr_account",
            Self::Phone => "phone",
            Self::TelegramUsername => "telegram_username",
            Self::Domain => "domain",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::KhqrAccount,
            Self::Phone,
            Self::TelegramUsername,
            Self::Domain,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == name)
    }
}

/// A normalized value, so the same number or site written two ways counts as one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
}

impl Indicator {
    pub fn khqr_account(account: &str) -> Self {
        Self {
            kind: IndicatorKind::KhqrAccount,
            value: account.trim().to_lowercase(),
        }
    }

    /// The website a host belongs to, unless it's a known site that can't be reported as a whole.
    pub fn domain(host: &str) -> Option<Self> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        // Free hosting is reported per site (x.github.io), and other known sites never.
        if sites::identify(&host).is_some_and(|site| site.kind != sites::Kind::Hosting) {
            return None;
        }
        Some(Self {
            kind: IndicatorKind::Domain,
            value: psl::domain_str(&host)?.to_owned(),
        })
    }
}

/// Cambodian numbers: 0XX or +855 XX, then 6 or 7 digits, with optional spaces or dashes.
static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\+?855[\s.-]?|\b0)([1-9]\d)[\s.-]?(\d{3})[\s.-]?(\d{3,4})\b")
        .expect("valid regex")
});

/// Phone numbers and Telegram usernames in a message, without Telegram's own accounts.
pub fn in_text(message: &str) -> Vec<Indicator> {
    let digits: String = message
        .chars()
        .map(|c| match c {
            '០'..='៩' => char::from(b'0' + (c as u32 - '០' as u32) as u8),
            _ => c,
        })
        .collect();
    let phones = PHONE.captures_iter(&digits).map(|captures| Indicator {
        kind: IndicatorKind::Phone,
        value: format!("855{}{}{}", &captures[1], &captures[2], &captures[3]),
    });
    let usernames = text::telegram_usernames(message)
        .into_iter()
        .filter(|name| !link::is_official_telegram(name))
        .map(|name| Indicator {
            kind: IndicatorKind::TelegramUsername,
            value: name,
        });
    let mut found: Vec<Indicator> = Vec::new();
    for indicator in phones.chain(usernames) {
        if !found.contains(&indicator) {
            found.push(indicator);
        }
        if found.len() == MAX_INDICATORS {
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(message: &str) -> Vec<String> {
        in_text(message)
            .into_iter()
            .map(|found| found.value)
            .collect()
    }

    #[test]
    fn phone_numbers_are_found_however_they_are_written() {
        assert_eq!(values("Call 012 345 678 now"), ["85512345678"]);
        assert_eq!(values("តេ ០៩៦ ៧៧៧ ៨៨៨៨"), ["855967778888"]);
        assert_eq!(values("+855 12-345-678 or 012345678"), ["85512345678"]);
        assert!(values("Order #2024 costs 15,000 riel").is_empty());
    }

    #[test]
    fn usernames_are_found_but_not_telegrams_own() {
        assert_eq!(
            values("Contact @ABA_Support_KH or t.me/fast_loan_kh, not @telegram"),
            ["aba_support_kh", "fast_loan_kh"]
        );
    }

    #[test]
    fn only_unknown_sites_and_free_hosting_can_be_reported() {
        let domain = |host: &str| Indicator::domain(host).map(|found| found.value);
        assert_eq!(
            domain("login.aba-verify.top"),
            Some("aba-verify.top".to_owned())
        );
        assert_eq!(
            domain("aba-bank.github.io"),
            Some("aba-bank.github.io".to_owned())
        );
        assert_eq!(domain("www.ababank.com"), None);
        assert_eq!(domain("t.me"), None);
    }

    #[test]
    fn a_message_full_of_numbers_gives_a_few() {
        let message = (0..20).map(|n| format!("01{n:07} ")).collect::<String>();
        assert_eq!(in_text(&message).len(), MAX_INDICATORS);
    }
}
