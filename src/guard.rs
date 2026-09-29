use std::hash::{BuildHasher, Hash, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use moka::sync::Cache;

const CHECKS_PER_WINDOW: u32 = 30;
const WINDOW: Duration = Duration::from_secs(60 * 60);
const REPLY_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    LimitReached,
    Silent,
}

pub struct Guard {
    hasher: RandomState,
    checks: Cache<u64, Arc<AtomicU32>>,
    replies: Cache<u64, Arc<str>>,
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

    pub fn cached(&self, key: u64) -> Option<Arc<str>> {
        self.replies.get(&key)
    }

    pub fn store(&self, key: u64, reply: Arc<str>) {
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
    fn replies_round_trip() {
        let guard = Guard::new();
        let key = guard.key(("text", "hello"));
        assert!(guard.cached(key).is_none());
        guard.store(key, Arc::from("reply"));
        assert_eq!(guard.cached(key).as_deref(), Some("reply"));
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
