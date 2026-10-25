use anyhow::ensure;
use checksen::analyzers::indicators::{Indicator, IndicatorKind};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

type HmacSha256 = Hmac<Sha256>;

pub const REPORT_THRESHOLD: i64 = 3;
const REPORTS_PER_DAY: i64 = 10;
const MAX_ACCOUNT_BYTES: usize = 32;
const TAG_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Review {
    #[default]
    Unreviewed,
    Confirmed,
    Cleared,
}

impl Review {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Confirmed => "confirmed",
            Self::Cleared => "cleared",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "confirmed" => Self::Confirmed,
            "cleared" => Self::Cleared,
            _ => Self::Unreviewed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reports {
    pub reporters: i64,
    pub review: Review,
}

/// What a reviewer tapped under a reported contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Confirm,
    Clear,
    Skip,
}

impl Decision {
    pub fn review(self) -> Option<Review> {
        match self {
            Self::Confirm => Some(Review::Confirmed),
            Self::Clear => Some(Review::Cleared),
            Self::Skip => None,
        }
    }

    fn code(self) -> char {
        match self {
            Self::Confirm => 'c',
            Self::Clear => 'x',
            Self::Skip => 's',
        }
    }
}

pub struct ToReview {
    pub id: i64,
    pub indicator: Indicator,
    pub reporters: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReportOutcome {
    Recorded,
    AlreadyReported,
    DailyLimit,
}

pub struct Store {
    pool: PgPool,
    secret: Vec<u8>,
}

impl Store {
    pub async fn connect(url: &str, secret: &str) -> anyhow::Result<Self> {
        ensure!(
            secret.len() >= 32,
            "HASH_SECRET must be at least 32 characters"
        );
        let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
        sqlx::migrate!().run(&pool).await?;
        Ok(Self::with_pool(pool, secret))
    }

    fn with_pool(pool: PgPool, secret: &str) -> Self {
        Self {
            pool,
            secret: secret.as_bytes().to_vec(),
        }
    }

    fn mac(&self, purpose: &[u8], parts: &[&[u8]]) -> HmacSha256 {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key length");
        mac.update(purpose);
        for part in parts {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part);
        }
        mac
    }

    pub fn reporter_hash(&self, user_id: u64) -> Vec<u8> {
        self.mac(b"reporter", &[&user_id.to_be_bytes()])
            .finalize()
            .into_bytes()
            .to_vec()
    }

    pub fn callback_data(&self, intended: bool, account: &str) -> Option<String> {
        if account.len() > MAX_ACCOUNT_BYTES {
            return None;
        }
        let answer = if intended { "y" } else { "n" };
        let tag = self
            .mac(b"callback", &[answer.as_bytes(), account.as_bytes()])
            .finalize()
            .into_bytes();
        Some(format!(
            "{answer}:{account}:{}",
            hex::encode(&tag[..TAG_BYTES])
        ))
    }

    pub fn verify_callback(&self, data: &str) -> Option<(bool, String)> {
        let (answer, rest) = data.split_once(':')?;
        let (account, tag) = rest.rsplit_once(':')?;
        let intended = match answer {
            "y" => true,
            "n" => false,
            _ => return None,
        };
        let tag = hex::decode(tag).ok().filter(|tag| tag.len() == TAG_BYTES)?;
        self.mac(b"callback", &[answer.as_bytes(), account.as_bytes()])
            .verify_truncated_left(&tag)
            .ok()?;
        Some((intended, account.to_owned()))
    }

    fn signed(&self, purpose: &[u8], payload: &str) -> String {
        let tag = self
            .mac(purpose, &[payload.as_bytes()])
            .finalize()
            .into_bytes();
        format!("{payload}:{}", hex::encode(&tag[..TAG_BYTES]))
    }

    fn verified<'a>(&self, purpose: &[u8], data: &'a str) -> Option<&'a str> {
        let (payload, tag) = data.rsplit_once(':')?;
        let tag = hex::decode(tag).ok().filter(|tag| tag.len() == TAG_BYTES)?;
        self.mac(purpose, &[payload.as_bytes()])
            .verify_truncated_left(&tag)
            .ok()?;
        Some(payload)
    }

    /// The "report as a scam" button only carries an id; the indicators wait in memory.
    pub fn report_callback(&self, id: u64) -> String {
        self.signed(b"report", &format!("r:{id:016x}"))
    }

    pub fn verify_report_callback(&self, data: &str) -> Option<u64> {
        let id = self.verified(b"report", data)?.strip_prefix("r:")?;
        u64::from_str_radix(id, 16).ok()
    }

    /// `skipped` is how far into the queue the reviewer is, so Skip can move past an item.
    pub fn review_callback(&self, decision: Decision, id: i64, skipped: i64) -> String {
        self.signed(
            b"review",
            &format!("v:{}:{id:x}:{skipped:x}", decision.code()),
        )
    }

    pub fn verify_review_callback(&self, data: &str) -> Option<(Decision, i64, i64)> {
        let payload = self.verified(b"review", data)?.strip_prefix("v:")?;
        let mut parts = payload.split(':');
        let decision = match parts.next()? {
            "c" => Decision::Confirm,
            "x" => Decision::Clear,
            "s" => Decision::Skip,
            _ => return None,
        };
        let id = i64::from_str_radix(parts.next()?, 16).ok()?;
        let skipped = i64::from_str_radix(parts.next()?, 16).ok()?;
        parts.next().is_none().then_some((decision, id, skipped))
    }

    pub async fn reporters(&self, indicator: &Indicator) -> anyhow::Result<Reports> {
        Ok(self
            .reporters_of(std::slice::from_ref(indicator))
            .await?
            .first()
            .copied()
            .unwrap_or_default())
    }

    /// How many people reported each indicator, and what a reviewer decided, in one query.
    pub async fn reporters_of(&self, indicators: &[Indicator]) -> anyhow::Result<Vec<Reports>> {
        let kinds: Vec<&str> = indicators.iter().map(|found| found.kind.as_str()).collect();
        let values: Vec<&str> = indicators
            .iter()
            .map(|found| found.value.as_str())
            .collect();
        let rows: Vec<(i32, String, i64)> = sqlx::query_as(
            "SELECT wanted.n::int4, i.review,
                    count(DISTINCT r.reporter_hash) FILTER (WHERE r.status <> 'disputed')
             FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS wanted (kind, value, n)
             JOIN indicators i ON i.kind = wanted.kind AND i.value = wanted.value
             LEFT JOIN reports r ON r.indicator_id = i.id
             GROUP BY wanted.n, i.review",
        )
        .bind(&kinds)
        .bind(&values)
        .fetch_all(&self.pool)
        .await?;
        let mut reports = vec![Reports::default(); indicators.len()];
        for (position, review, reporters) in rows {
            if let Some(slot) = usize::try_from(position - 1)
                .ok()
                .and_then(|index| reports.get_mut(index))
            {
                *slot = Reports {
                    reporters,
                    review: Review::parse(&review),
                };
            }
        }
        Ok(reports)
    }

    /// The unreviewed contact `skipped` places down the queue, most reported first.
    pub async fn next_to_review(&self, skipped: i64) -> anyhow::Result<Option<ToReview>> {
        let row: Option<(i64, String, String, i64)> = sqlx::query_as(
            "SELECT i.id, i.kind, i.value, count(DISTINCT r.reporter_hash) AS reporters
             FROM indicators i
             JOIN reports r ON r.indicator_id = i.id AND r.status <> 'disputed'
             WHERE i.review = 'unreviewed'
             GROUP BY i.id
             ORDER BY reporters DESC, i.id
             OFFSET $1 LIMIT 1",
        )
        .bind(skipped)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(id, kind, value, reporters)| {
            Some(ToReview {
                id,
                indicator: Indicator {
                    kind: IndicatorKind::parse(&kind)?,
                    value,
                },
                reporters,
            })
        }))
    }

    /// Records a reviewer's decision and returns what was decided on.
    pub async fn set_review(&self, id: i64, review: Review) -> anyhow::Result<Option<Indicator>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "UPDATE indicators SET review = $2, reviewed_at = now() WHERE id = $1
             RETURNING kind, value",
        )
        .bind(id)
        .bind(review.as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(kind, value)| {
            Some(Indicator {
                kind: IndicatorKind::parse(&kind)?,
                value,
            })
        }))
    }

    /// Reports each indicator; the outcome is the first that isn't a repeat.
    pub async fn report_all(
        &self,
        indicators: &[Indicator],
        user_id: u64,
    ) -> anyhow::Result<ReportOutcome> {
        let mut outcome = ReportOutcome::AlreadyReported;
        for indicator in indicators {
            match self.report(indicator, user_id).await? {
                ReportOutcome::DailyLimit => return Ok(ReportOutcome::DailyLimit),
                ReportOutcome::Recorded => outcome = ReportOutcome::Recorded,
                ReportOutcome::AlreadyReported => {}
            }
        }
        Ok(outcome)
    }

    pub async fn report(
        &self,
        indicator: &Indicator,
        user_id: u64,
    ) -> anyhow::Result<ReportOutcome> {
        let reporter = self.reporter_hash(user_id);
        let mut tx = self.pool.begin().await?;
        let today: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM reports WHERE reporter_hash = $1 AND created_at > now() - interval '1 day'",
        )
        .bind(&reporter)
        .fetch_one(&mut *tx)
        .await?;
        if today >= REPORTS_PER_DAY {
            return Ok(ReportOutcome::DailyLimit);
        }
        let indicator: i64 = sqlx::query_scalar(
            "INSERT INTO indicators (kind, value) VALUES ($1, $2)
             ON CONFLICT (kind, value) DO UPDATE SET last_seen = now() RETURNING id",
        )
        .bind(indicator.kind.as_str())
        .bind(&indicator.value)
        .fetch_one(&mut *tx)
        .await?;
        let inserted = sqlx::query(
            "INSERT INTO reports (indicator_id, reporter_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(indicator)
        .bind(&reporter)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(if inserted == 0 {
            ReportOutcome::AlreadyReported
        } else {
            ReportOutcome::Recorded
        })
    }

    /// Deletes a person's reports, and any unreviewed value nobody else reported.
    pub async fn forget(&self, user_id: u64) -> anyhow::Result<u64> {
        let mut tx = self.pool.begin().await?;
        let removed = sqlx::query("DELETE FROM reports WHERE reporter_hash = $1")
            .bind(self.reporter_hash(user_id))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query(
            "DELETE FROM indicators i WHERE i.review = 'unreviewed'
             AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.indicator_id = i.id)",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-that-is-at-least-32-bytes";

    fn offline() -> Store {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused@localhost/unused")
            .unwrap();
        Store::with_pool(pool, SECRET)
    }

    #[tokio::test]
    async fn callback_data_round_trips_and_fits_telegram() {
        let store = offline();
        let data = store.callback_data(false, "abaakhppxxx@abaa").unwrap();
        assert!(data.len() <= 64, "{}", data.len());
        assert_eq!(
            store.verify_callback(&data),
            Some((false, "abaakhppxxx@abaa".to_owned()))
        );
        assert!(store.callback_data(false, &"a".repeat(33)).is_none());
    }

    #[tokio::test]
    async fn tampered_or_foreign_callbacks_are_rejected() {
        let store = offline();
        let data = store.callback_data(false, "victim@abaa").unwrap();
        let tag = data.rsplit_once(':').unwrap().1;
        assert!(
            store
                .verify_callback(&format!("n:other@abaa:{tag}"))
                .is_none()
        );
        assert!(
            store
                .verify_callback(&data.replacen("n:", "y:", 1))
                .is_none()
        );
        assert!(store.verify_callback("n:victim@abaa:00").is_none());
        let other = Store::with_pool(offline().pool, "a-different-secret-of-32-bytes-or-more");
        assert!(other.verify_callback(&data).is_none());
    }

    #[tokio::test]
    async fn reporter_hash_depends_on_the_secret() {
        let store = offline();
        let other = Store::with_pool(offline().pool, "a-different-secret-of-32-bytes-or-more");
        assert_eq!(store.reporter_hash(42), store.reporter_hash(42));
        assert_ne!(store.reporter_hash(42), store.reporter_hash(43));
        assert_ne!(store.reporter_hash(42), other.reporter_hash(42));
    }

    async fn database() -> Option<Store> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        Some(Store::connect(&url, SECRET).await.expect("test database"))
    }

    fn unique_account(label: &str) -> Indicator {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Indicator::khqr_account(&format!("{label}{}@test", nanos % 1_000_000_000_000))
    }

    fn unique_user() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[tokio::test]
    async fn reports_count_distinct_reporters_once_each() {
        let Some(store) = database().await else {
            return;
        };
        let account = unique_account("count");
        let first = unique_user();
        assert_eq!(
            store.report(&account, first).await.unwrap(),
            ReportOutcome::Recorded
        );
        assert_eq!(
            store.report(&account, first).await.unwrap(),
            ReportOutcome::AlreadyReported
        );
        store.report(&account, first + 1).await.unwrap();
        assert_eq!(store.reporters(&account).await.unwrap().reporters, 2);
        store
            .report(
                &Indicator::khqr_account(&account.value.to_uppercase()),
                first + 2,
            )
            .await
            .unwrap();
        assert_eq!(
            store.reporters(&account).await.unwrap().reporters,
            REPORT_THRESHOLD
        );
    }

    #[tokio::test]
    async fn disputed_reports_do_not_count() {
        let Some(store) = database().await else {
            return;
        };
        let account = unique_account("dispute");
        store.report(&account, unique_user()).await.unwrap();
        sqlx::query(
            "UPDATE reports SET status = 'disputed' WHERE indicator_id =
             (SELECT id FROM indicators WHERE value = $1)",
        )
        .bind(&account.value)
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(store.reporters(&account).await.unwrap().reporters, 0);
    }

    #[tokio::test]
    async fn reports_over_the_daily_limit_are_refused() {
        let Some(store) = database().await else {
            return;
        };
        let user = unique_user();
        for index in 0..REPORTS_PER_DAY {
            let account = unique_account(&format!("limit{index}x"));
            assert_eq!(
                store.report(&account, user).await.unwrap(),
                ReportOutcome::Recorded
            );
        }
        assert_eq!(
            store.report(&unique_account("limit"), user).await.unwrap(),
            ReportOutcome::DailyLimit
        );
    }

    #[tokio::test]
    async fn report_callbacks_round_trip_and_reject_tampering() {
        let store = offline();
        let data = store.report_callback(0xdead_beef);
        assert!(data.len() <= 64);
        assert_eq!(store.verify_report_callback(&data), Some(0xdead_beef));
        assert!(
            store
                .verify_report_callback(&data.replacen("deadbeef", "deadbeee", 1))
                .is_none()
        );
        assert!(store.verify_callback(&data).is_none());
    }

    #[tokio::test]
    async fn review_callbacks_round_trip_and_reject_tampering() {
        let store = offline();
        let data = store.review_callback(Decision::Clear, i64::MAX, 12);
        assert!(data.len() <= 64, "{}", data.len());
        assert_eq!(
            store.verify_review_callback(&data),
            Some((Decision::Clear, i64::MAX, 12))
        );
        assert!(
            store
                .verify_review_callback(&data.replacen("v:x:", "v:c:", 1))
                .is_none()
        );
        let report = store.report_callback(7);
        assert!(store.verify_review_callback(&report).is_none());
        assert!(store.verify_report_callback(&data).is_none());
    }

    #[tokio::test]
    async fn reviews_are_returned_and_outlast_forget() {
        let Some(store) = database().await else {
            return;
        };
        let account = unique_account("review");
        let user = unique_user();
        store.report(&account, user).await.unwrap();
        let id: i64 = sqlx::query_scalar("SELECT id FROM indicators WHERE value = $1")
            .bind(&account.value)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.set_review(id, Review::Confirmed).await.unwrap(),
            Some(account.clone())
        );
        store.forget(user).await.unwrap();
        assert_eq!(
            store.reporters(&account).await.unwrap(),
            Reports {
                reporters: 0,
                review: Review::Confirmed
            }
        );
    }

    #[tokio::test]
    async fn phones_usernames_and_sites_are_counted_together() {
        let Some(store) = database().await else {
            return;
        };
        let user = unique_user();
        let phone = Indicator {
            kind: checksen::analyzers::indicators::IndicatorKind::Phone,
            value: format!("85512{}", user % 1_000_000),
        };
        let site = Indicator::domain(&format!("scam{user}.example")).unwrap();
        let same_value_other_kind = Indicator::khqr_account(&phone.value);
        assert_eq!(
            store
                .report_all(&[phone.clone(), site.clone()], user)
                .await
                .unwrap(),
            ReportOutcome::Recorded
        );
        store.report(&phone, user + 1).await.unwrap();
        let reporters: Vec<i64> = store
            .reporters_of(&[site, phone, same_value_other_kind])
            .await
            .unwrap()
            .iter()
            .map(|reports| reports.reporters)
            .collect();
        assert_eq!(reporters, [1, 2, 0]);
    }

    #[tokio::test]
    async fn forget_removes_a_users_reports() {
        let Some(store) = database().await else {
            return;
        };
        let account = unique_account("forget");
        let user = unique_user();
        store.report(&account, user).await.unwrap();
        assert_eq!(store.forget(user).await.unwrap(), 1);
        assert_eq!(store.reporters(&account).await.unwrap().reporters, 0);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM indicators WHERE value = $1")
            .bind(&account.value)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
}
