//! Official ways to reach a bank, wallet or telco, each copied from its own website, so a reply
//! can say exactly whom to contact to check a message. The list is too short to call any other
//! number unofficial, so it never does. Only add a contact with the page it was copied from.

use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug)]
pub struct Official {
    pub name: &'static str,
    /// How to reach it, in Khmer and English.
    pub reach: (&'static str, &'static str),
    /// Its numbers, normalized the way `indicators::in_text` writes them.
    numbers: &'static [&'static str],
    /// Words that name it in a message; Latin ones match as whole words, ignoring case.
    names: &'static [&'static str],
}

const OFFICIAL: &[Official] = &[
    // wingbank.com.kh/en/company/security-awareness-center/scam-awareness: "app, verified
    // Facebook page and hotline 023 999 989" are Wing's only official channels.
    Official {
        name: "Wing",
        reach: ("ហតឡាញ 023 999 989", "hotline 023 999 989"),
        numbers: &["85523999989"],
        names: &["wing", "wingbank", "វីង"],
    },
    // canadiabank.com.kh, footer: "Customer Service Hotline: (+855) 23 868 222" (2026-10-25).
    Official {
        name: "Canadia Bank",
        reach: ("ហតឡាញ 023 868 222", "hotline 023 868 222"),
        numbers: &["85523868222"],
        names: &["canadia", "កាណាឌីយ៉ា"],
    },
    // acledabank.com.kh/kh/eng/, "Connect with us": WhatsApp wa.me/85510400613 (2026-10-25).
    Official {
        name: "ACLEDA",
        reach: ("WhatsApp 010 400 613", "WhatsApp 010 400 613"),
        numbers: &["85510400613"],
        names: &["acleda", "អេស៊ីលីដា"],
    },
    // smart.com.kh, footer: "+85510200888" (2026-10-25). "Smart" alone is an ordinary word.
    Official {
        name: "Smart",
        reach: ("010 200 888", "010 200 888"),
        numbers: &["85510200888"],
        names: &["smart axiata", "ស្មាត អាស៊ីអាតា"],
    },
];

static LATIN_NAMES: LazyLock<Vec<(Regex, &'static Official)>> = LazyLock::new(|| {
    OFFICIAL
        .iter()
        .flat_map(|official| {
            official
                .names
                .iter()
                .filter(|name| name.is_ascii())
                .map(move |name| {
                    (
                        Regex::new(&format!(r"(?i)\b{name}\b")).expect("valid name"),
                        official,
                    )
                })
        })
        .collect()
});

/// The institution a message names, if its official contact is known.
pub fn mentioned(text: &str) -> Option<&'static Official> {
    LATIN_NAMES
        .iter()
        .find(|(name, _)| name.is_match(text))
        .map(|(_, official)| *official)
        .or_else(|| {
            OFFICIAL.iter().find(|official| {
                official
                    .names
                    .iter()
                    .any(|name| !name.is_ascii() && text.contains(name))
            })
        })
}

/// Whose official number this is, for a number written as `indicators::in_text` writes it.
pub fn owner_of(number: &str) -> Option<&'static Official> {
    OFFICIAL
        .iter()
        .find(|official| official.numbers.contains(&number))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::indicators::in_text;

    #[test]
    fn names_are_found_as_words_in_english_and_khmer() {
        assert_eq!(
            mentioned("Your Wing account is locked").map(|o| o.name),
            Some("Wing")
        );
        assert_eq!(mentioned("គណនីវីងរបស់អ្នក").map(|o| o.name), Some("Wing"));
        assert_eq!(
            mentioned("ACLEDA Bank notice").map(|o| o.name),
            Some("ACLEDA")
        );
        assert!(mentioned("Buy a smart phone with chicken wings").is_none());
    }

    #[test]
    fn official_numbers_are_recognized_however_they_are_written() {
        for text in ["Call 023 999 989", "call +855 23 999 989", "០២៣ ៩៩៩ ៩៨៩"] {
            let numbers = in_text(text);
            assert_eq!(
                numbers
                    .iter()
                    .find_map(|n| owner_of(&n.value))
                    .map(|o| o.name),
                Some("Wing"),
                "{text}"
            );
        }
        assert!(owner_of("85512345678").is_none());
    }
}
