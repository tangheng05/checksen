use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moka::sync::Cache;

const CHECKS_PER_WINDOW: u32 = 30;
const WINDOW: Duration = Duration::from_secs(60 * 60);
const REPLY_TTL: Duration = Duration::from_secs(60 * 60);
const MODEL_CALLS_PER_DAY: u32 = 5_000;

pub struct Reply {
    pub text: String,
    pub account: Option<String>,
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
    model_calls: Cache<u64, Arc<AtomicU32>>,
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
                .max_capacity(4)
                .time_to_live(Duration::from_secs(25 * 60 * 60))
                .build(),
        }
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

    pub fn allow_model_call(&self) -> bool {
        let day = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
        let calls = self
            .model_calls
            .get_with(day, || Arc::new(AtomicU32::new(0)));
        calls.fetch_add(1, Ordering::Relaxed) < MODEL_CALLS_PER_DAY
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
            assert!(guard.allow_model_call());
        }
        assert!(!guard.allow_model_call());
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
            }),
        );
        let cached = guard.cached(key).unwrap();
        assert_eq!(cached.text, "reply");
        assert_eq!(cached.account.as_deref(), Some("sok@abaa"));
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
