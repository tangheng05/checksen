use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moka::sync::Cache;

use checksen::analyzers::indicators::Indicator;
use checksen::verdict::Lang;

const CHECKS_PER_WINDOW: u32 = 30;
const WINDOW: Duration = Duration::from_secs(60 * 60);
const REPLY_TTL: Duration = Duration::from_secs(60 * 60);
const MODEL_CALLS_PER_DAY: u32 = 5_000;
const SCREENSHOT_CALLS_PER_DAY: u32 = 1_000;
// VirusTotal's free key allows 500 lookups a day.
const FILE_LOOKUPS_PER_DAY: u32 = 450;
const LANGUAGE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const REPORT_BUTTON_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub struct Reply {
    pub text: String,
    pub account: Option<String>,
    /// Phone numbers, usernames and sites in the message that can be reported as a scam.
    pub reportable: Vec<Indicator>,
    /// Verdicts use Telegram HTML; fixed answers are plain text.
    pub html: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelCall {
    Text,
    Screenshot,
    FileLookup,
}

impl ModelCall {
    fn daily_limit(self) -> u32 {
        match self {
            Self::Text => MODEL_CALLS_PER_DAY,
            Self::Screenshot => SCREENSHOT_CALLS_PER_DAY,
            Self::FileLookup => FILE_LOOKUPS_PER_DAY,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    LimitReached,
    Silent,
}

pub struct Guard {
    hasher: RandomState,
    checks: Cache<u64, Arc<AtomicU32>>,
    replies: Cache<u64, Arc<Reply>>,
    model_calls: Cache<(ModelCall, u64), Arc<AtomicU32>>,
    languages: Cache<u64, Lang>,
    report_buttons: Cache<u64, Arc<Vec<Indicator>>>,
}

impl Guard {
    pub fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            checks: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(WINDOW)
                .build(),
            replies: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(REPLY_TTL)
                .build(),
            model_calls: Cache::builder()
                .max_capacity(8)
                .time_to_live(Duration::from_secs(25 * 60 * 60))
                .build(),
            languages: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(LANGUAGE_TTL)
                .build(),
            report_buttons: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(REPORT_BUTTON_TTL)
                .build(),
        }
    }

    /// Keeps what a report button would report, and returns the id the button carries.
    pub fn report_button(&self, indicators: &[Indicator]) -> u64 {
        let id = self.key(("report", indicators));
        self.report_buttons
            .insert(id, Arc::new(indicators.to_vec()));
        id
    }

    pub fn reported_by_button(&self, id: u64) -> Option<Arc<Vec<Indicator>>> {
        self.report_buttons.get(&id)
    }

    pub fn key(&self, parts: impl Hash) -> u64 {
        self.hasher.hash_one(parts)
    }

    pub fn admit(&self, sender: u64) -> Admission {
        let count = self
            .checks
            .get_with(self.key(sender), || Arc::new(AtomicU32::new(0)));
        match count.fetch_add(1, Ordering::Relaxed) + 1 {
            checks if checks <= CHECKS_PER_WINDOW => Admission::Allowed,
            checks if checks == CHECKS_PER_WINDOW + 1 => Admission::LimitReached,
            _ => Admission::Silent,
        }
    }

    pub fn allow_model_call(&self, call: ModelCall) -> bool {
        let day = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
        let calls = self
            .model_calls
            .get_with((call, day), || Arc::new(AtomicU32::new(0)));
        calls.fetch_add(1, Ordering::Relaxed) < call.daily_limit()
    }

    /// Replies follow what the sender types, never what they forward, and default to Khmer.
    pub fn language(&self, sender: u64, typed: Option<Lang>) -> Lang {
        let key = self.key(("lang", sender));
        if let Some(lang) = typed {
            self.languages.insert(key, lang);
            return lang;
        }
        self.languages.get(&key).unwrap_or(Lang::Km)
    }

    pub fn cached(&self, key: u64) -> Option<Arc<Reply>> {
        self.replies.get(&key)
    }

    pub fn store(&self, key: u64, reply: Arc<Reply>) {
        self.replies.insert(key, reply);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_each_sender_and_notifies_once() {
        let guard = Guard::new();
        for _ in 0..CHECKS_PER_WINDOW {
            assert_eq!(guard.admit(1), Admission::Allowed);
        }
        assert_eq!(guard.admit(1), Admission::LimitReached);
        assert_eq!(guard.admit(1), Admission::Silent);
        assert_eq!(guard.admit(2), Admission::Allowed);
    }

    #[test]
    fn model_calls_stop_at_the_daily_cap() {
        let guard = Guard::new();
        for _ in 0..MODEL_CALLS_PER_DAY {
            assert!(guard.allow_model_call(ModelCall::Text));
        }
        assert!(!guard.allow_model_call(ModelCall::Text));
    }

    #[test]
    fn screenshot_cap_is_separate_from_the_text_cap() {
        let guard = Guard::new();
        for _ in 0..SCREENSHOT_CALLS_PER_DAY {
            assert!(guard.allow_model_call(ModelCall::Screenshot));
        }
        assert!(!guard.allow_model_call(ModelCall::Screenshot));
        assert!(guard.allow_model_call(ModelCall::Text));
    }

    #[test]
    fn typed_language_is_remembered() {
        let guard = Guard::new();
        assert_eq!(guard.language(1, None), Lang::Km);
        assert_eq!(guard.language(2, Some(Lang::En)), Lang::En);
        assert_eq!(guard.language(2, None), Lang::En);
        assert_eq!(guard.language(2, Some(Lang::Km)), Lang::Km);
        assert_eq!(guard.language(1, None), Lang::Km);
    }

    #[test]
    fn replies_round_trip() {
        let guard = Guard::new();
        let key = guard.key(("text", "hello"));
        assert!(guard.cached(key).is_none());
        guard.store(
            key,
            Arc::new(Reply {
                text: "reply".to_owned(),
                account: Some("sok@abaa".to_owned()),
                reportable: Vec::new(),
                html: true,
            }),
        );
        let cached = guard.cached(key).unwrap();
        assert_eq!(cached.text, "reply");
        assert_eq!(cached.account.as_deref(), Some("sok@abaa"));
    }

    #[test]
    fn report_buttons_find_their_indicators() {
        let guard = Guard::new();
        let found = vec![Indicator::khqr_account("sok@abaa")];
        let id = guard.report_button(&found);
        assert_eq!(guard.reported_by_button(id).as_deref(), Some(&found));
        assert!(guard.reported_by_button(id.wrapping_add(1)).is_none());
    }

    #[test]
    fn keys_depend_on_every_part() {
        let guard = Guard::new();
        let visible = (
            "text",
            "Your account is locked",
            vec!["https://ababank.com/"],
        );
        let hidden = (
            "text",
            "Your account is locked",
            vec!["https://aba-verify.top/"],
        );
        assert_eq!(guard.key(&visible), guard.key(&visible));
        assert_ne!(guard.key(&visible), guard.key(&hidden));
    }
}
