use std::collections::HashMap;

use anyhow::ensure;
use checksen::analyzers::indicators::{Indicator, IndicatorKind};
use checksen::analyzers::llm::ScamCategory;
use checksen::analyzers::text::RULES_VERSION;
use checksen::verdict::Totals;
use chrono::NaiveDate;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::guard::Summary;

type HmacSha256 = Hmac<Sha256>;

pub const REPORT_THRESHOLD: i64 = 3;
const REPORTS_PER_DAY: i64 = 10;
const FEEDBACK_PER_DAY: i64 = 20;
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

/// The two things reviewers go through: reported contacts, then shared messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queue {
    Contacts,
    Shared,
}

/// What a reviewer tapped. On a shared message, `Scam` and `NotScam` label it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Scam,
    NotScam,
    Delete,
    Skip,
}

const QUEUES: [(Queue, char); 2] = [(Queue::Contacts, 'c'), (Queue::Shared, 'm')];
const DECISIONS: [(Decision, char); 4] = [
    (Decision::Scam, 's'),
    (Decision::NotScam, 'n'),
    (Decision::Delete, 'd'),
    (Decision::Skip, 'k'),
];

fn code<T: PartialEq>(table: &[(T, char)], value: &T) -> char {
    table
        .iter()
        .find(|(entry, _)| entry == value)
        .map_or('?', |(_, code)| *code)
}

fn decode<T: Copy>(table: &[(T, char)], code: &str) -> Option<T> {
    let mut chars = code.chars();
    let (Some(first), None) = (chars.next(), chars.next()) else {
        return None;
    };
    table
        .iter()
        .find(|(_, entry)| *entry == first)
        .map(|(value, _)| *value)
}

/// What a check is counted under in the daily numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Counted {
    pub subject: &'static str,
    pub level: &'static str,
    pub category: &'static str,
}

/// A labelled shared text, ready to become an eval row.
#[derive(sqlx::FromRow)]
pub struct Labelled {
    pub id: i64,
    pub text: String,
    pub label: String,
    pub day: String,
}

#[derive(sqlx::FromRow)]
pub struct SharedMessage {
    pub id: i64,
    pub text: Option<String>,
    pub photo_file_id: Option<String>,
    pub level: String,
    pub signals: Vec<String>,
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
    pub fn review_callback(
        &self,
        queue: Queue,
        decision: Decision,
        id: i64,
        skipped: i64,
    ) -> String {
        self.signed(
            b"review",
            &format!(
                "v:{}{}:{id:x}:{skipped:x}",
                code(&QUEUES, &queue),
                code(&DECISIONS, &decision)
            ),
        )
    }

    pub fn verify_review_callback(&self, data: &str) -> Option<(Queue, Decision, i64, i64)> {
        let payload = self.verified(b"review", data)?.strip_prefix("v:")?;
        let mut parts = payload.split(':');
        let codes = parts.next()?;
        let queue = decode(&QUEUES, codes.get(..1)?)?;
        let decision = decode(&DECISIONS, codes.get(1..)?)?;
        let id = i64::from_str_radix(parts.next()?, 16).ok()?;
        let skipped = i64::from_str_radix(parts.next()?, 16).ok()?;
        parts
            .next()
            .is_none()
            .then_some((queue, decision, id, skipped))
    }

    /// The weekly post's button carries the week it is for.
    pub fn post_callback(&self, week: NaiveDate) -> String {
        self.signed(b"post", &format!("p:{week}"))
    }

    pub fn verify_post_callback(&self, data: &str) -> Option<NaiveDate> {
        let week = self.verified(b"post", data)?.strip_prefix("p:")?;
        week.parse().ok()
    }

    /// 👍/👎 carry the id of the verdict summary waiting in memory.
    pub fn feedback_callback(&self, helpful: bool, id: u64) -> String {
        let answer = if helpful { "u" } else { "d" };
        self.signed(b"feedback", &format!("f:{answer}:{id:016x}"))
    }

    pub fn verify_feedback_callback(&self, data: &str) -> Option<(bool, u64)> {
        let (answer, id) = self
            .verified(b"feedback", data)?
            .strip_prefix("f:")?
            .split_once(':')?;
        let helpful = match answer {
            "u" => true,
            "d" => false,
            _ => return None,
        };
        Some((helpful, u64::from_str_radix(id, 16).ok()?))
    }

    /// The buttons under "share this message?" carry the feedback row they belong to.
    pub fn share_callback(&self, share: bool, feedback: i64) -> String {
        let answer = if share { "y" } else { "n" };
        self.signed(b"share", &format!("s:{answer}:{feedback:x}"))
    }

    pub fn verify_share_callback(&self, data: &str) -> Option<(bool, i64)> {
        let (answer, id) = self
            .verified(b"share", data)?
            .strip_prefix("s:")?
            .split_once(':')?;
        let share = match answer {
            "y" => true,
            "n" => false,
            _ => return None,
        };
        Some((share, i64::from_str_radix(id, 16).ok()?))
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

    /// Records a 👍/👎 and returns its id, or None once the person rated too much today.
    pub async fn record_feedback(
        &self,
        user_id: u64,
        helpful: bool,
        summary: &Summary,
    ) -> anyhow::Result<Option<i64>> {
        let reporter = self.reporter_hash(user_id);
        let today: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM feedback WHERE reporter_hash = $1 AND created_at > now() - interval '1 day'",
        )
        .bind(&reporter)
        .fetch_one(&self.pool)
        .await?;
        if today >= FEEDBACK_PER_DAY {
            return Ok(None);
        }
        let id = sqlx::query_scalar(
            "INSERT INTO feedback (reporter_hash, helpful, rules_version, level, subject, signals)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(&reporter)
        .bind(helpful)
        .bind(i32::try_from(RULES_VERSION)?)
        .bind(summary.level)
        .bind(summary.subject)
        .bind(&summary.signals)
        .fetch_one(&self.pool)
        .await?;
        Ok(Some(id))
    }

    /// Keeps a message its sender chose to share, against their own 👎. Repeats are ignored.
    pub async fn share(
        &self,
        feedback: i64,
        user_id: u64,
        text: Option<&str>,
        photo_file_id: Option<&str>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO shared (feedback_id, text, photo_file_id)
             SELECT id, $3, $4 FROM feedback WHERE id = $1 AND reporter_hash = $2
             ON CONFLICT (feedback_id) DO NOTHING",
        )
        .bind(feedback)
        .bind(self.reporter_hash(user_id))
        .bind(text)
        .bind(photo_file_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The unlabelled shared message `skipped` places down the queue, oldest first.
    pub async fn next_shared(&self, skipped: i64) -> anyhow::Result<Option<SharedMessage>> {
        Ok(sqlx::query_as(
            "SELECT s.id, s.text, s.photo_file_id, f.level, f.signals
             FROM shared s JOIN feedback f ON f.id = s.feedback_id
             WHERE s.label IS NULL
             ORDER BY s.id
             OFFSET $1 LIMIT 1",
        )
        .bind(skipped)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Labels a shared message as a scam or not, or deletes it.
    pub async fn decide_shared(&self, id: i64, decision: Decision) -> anyhow::Result<()> {
        let query = match decision {
            Decision::Scam => sqlx::query("UPDATE shared SET label = 'scam' WHERE id = $1"),
            Decision::NotScam => sqlx::query("UPDATE shared SET label = 'legit' WHERE id = $1"),
            Decision::Delete => sqlx::query("DELETE FROM shared WHERE id = $1"),
            Decision::Skip => return Ok(()),
        };
        query.bind(id).execute(&self.pool).await?;
        Ok(())
    }

    /// Labelled shared texts, oldest first; photos without a caption have no text to export.
    pub async fn labelled(&self) -> anyhow::Result<Vec<Labelled>> {
        Ok(sqlx::query_as(
            "SELECT id, text, label, to_char(created_at, 'YYYY-MM-DD') AS day FROM shared
             WHERE label IS NOT NULL AND text IS NOT NULL ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn delete_shared(&self, ids: &[i64]) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM shared WHERE id = ANY($1)")
            .bind(ids)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Adds checks counted in memory to today's numbers, in one query.
    pub async fn add_checks(&self, counts: &[(Counted, i64)]) -> anyhow::Result<()> {
        let subjects: Vec<&str> = counts.iter().map(|(key, _)| key.subject).collect();
        let levels: Vec<&str> = counts.iter().map(|(key, _)| key.level).collect();
        let categories: Vec<&str> = counts.iter().map(|(key, _)| key.category).collect();
        let checks: Vec<i64> = counts.iter().map(|(_, checks)| *checks).collect();
        sqlx::query(
            "INSERT INTO daily_checks (day, subject, level, category, checks)
             SELECT (now() AT TIME ZONE 'Asia/Phnom_Penh')::date, subject, level, category, checks
             FROM unnest($1::text[], $2::text[], $3::text[], $4::int8[])
                  AS counted (subject, level, category, checks)
             ON CONFLICT (day, subject, level, category)
             DO UPDATE SET checks = daily_checks.checks + EXCLUDED.checks",
        )
        .bind(&subjects)
        .bind(&levels)
        .bind(&categories)
        .bind(&checks)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Checks from `from` up to, not including, `to`, with the three most common scams.
    pub async fn totals(&self, from: NaiveDate, to: NaiveDate) -> anyhow::Result<Totals> {
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT level, category, sum(checks)::int8 FROM daily_checks
             WHERE day >= $1 AND day < $2 GROUP BY level, category",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut totals = Totals::default();
        let mut top: HashMap<ScamCategory, i64> = HashMap::new();
        for (level, category, checks) in rows {
            totals.checks += checks;
            match level.as_str() {
                "high_risk" => totals.high_risk += checks,
                "suspicious" => totals.suspicious += checks,
                _ => continue,
            }
            if let Some(category) = ScamCategory::from_name(&category) {
                *top.entry(category).or_default() += checks;
            }
        }
        totals.top = top.into_iter().collect();
        totals
            .top
            .sort_by(|a, b| b.1.cmp(&a.1).then(a.0.name().cmp(b.0.name())));
        totals.top.truncate(3);
        Ok(totals)
    }

    /// True the first time a week is claimed, so its draft is sent once across restarts.
    pub async fn claim_week(&self, week: NaiveDate) -> anyhow::Result<bool> {
        Ok(
            sqlx::query("INSERT INTO weekly_posts (week) VALUES ($1) ON CONFLICT DO NOTHING")
                .bind(week)
                .execute(&self.pool)
                .await?
                .rows_affected()
                == 1,
        )
    }

    pub async fn protected_chats(&self) -> anyhow::Result<Vec<i64>> {
        Ok(sqlx::query_scalar("SELECT chat_id FROM protected_chats")
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn set_protected(&self, chat: i64, on: bool) -> anyhow::Result<()> {
        let query = if on {
            "INSERT INTO protected_chats (chat_id) VALUES ($1) ON CONFLICT DO NOTHING"
        } else {
            "DELETE FROM protected_chats WHERE chat_id = $1"
        };
        sqlx::query(query).bind(chat).execute(&self.pool).await?;
        Ok(())
    }

    /// Lets a week be drafted again after its draft couldn't be sent.
    pub async fn unclaim_week(&self, week: NaiveDate) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM weekly_posts WHERE week = $1 AND posted_at IS NULL")
            .bind(week)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Marks a week posted, or not again after a failed post. True when it changed, so a
    /// second tap doesn't post twice.
    pub async fn mark_posted(&self, week: NaiveDate, posted: bool) -> anyhow::Result<bool> {
        let query = if posted {
            "UPDATE weekly_posts SET posted_at = now() WHERE week = $1 AND posted_at IS NULL"
        } else {
            "UPDATE weekly_posts SET posted_at = NULL WHERE week = $1"
        };
        Ok(sqlx::query(query)
            .bind(week)
            .execute(&self.pool)
            .await?
            .rows_affected()
            == 1)
    }

    /// Shared messages are kept for 30 days at most, labelled or not.
    pub async fn purge_shared(&self) -> anyhow::Result<u64> {
        Ok(
            sqlx::query("DELETE FROM shared WHERE created_at < now() - interval '30 days'")
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    /// Deletes a person's reports, ratings and shared messages, and any unreviewed value
    /// nobody else reported.
    pub async fn forget(&self, user_id: u64) -> anyhow::Result<u64> {
        let mut tx = self.pool.begin().await?;
        let removed = sqlx::query("DELETE FROM reports WHERE reporter_hash = $1")
            .bind(self.reporter_hash(user_id))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query("DELETE FROM feedback WHERE reporter_hash = $1")
            .bind(self.reporter_hash(user_id))
            .execute(&mut *tx)
            .await?;
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

    /// Microseconds differ between runs (some clocks round nanoseconds to them), and the
    /// counter between tests running at once; tests add small offsets for extra reporters.
    fn unique_user() -> u64 {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        micros * 1000 + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 10 * 100
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
        let data = store.review_callback(Queue::Shared, Decision::NotScam, i64::MAX, 12);
        assert!(data.len() <= 64, "{}", data.len());
        assert_eq!(
            store.verify_review_callback(&data),
            Some((Queue::Shared, Decision::NotScam, i64::MAX, 12))
        );
        assert!(
            store
                .verify_review_callback(&data.replacen("v:mn:", "v:ms:", 1))
                .is_none()
        );
        let report = store.report_callback(7);
        assert!(store.verify_review_callback(&report).is_none());
        assert!(store.verify_report_callback(&data).is_none());
    }

    #[tokio::test]
    async fn feedback_and_share_callbacks_round_trip() {
        let store = offline();
        let down = store.feedback_callback(false, u64::MAX);
        let share = store.share_callback(true, i64::MAX);
        assert!(down.len() <= 64 && share.len() <= 64);
        assert_eq!(
            store.verify_feedback_callback(&down),
            Some((false, u64::MAX))
        );
        assert_eq!(store.verify_share_callback(&share), Some((true, i64::MAX)));
        assert!(
            store
                .verify_feedback_callback(&down.replacen("f:d:", "f:u:", 1))
                .is_none()
        );
        assert!(store.verify_share_callback(&down).is_none());
        assert!(store.verify_feedback_callback(&share).is_none());
    }

    fn summary() -> Summary {
        Summary {
            level: "suspicious",
            subject: "text",
            category: "loan",
            signals: vec!["UpfrontFee".to_owned()],
        }
    }

    async fn shared_rows(store: &Store, feedback: i64) -> Vec<(Option<String>, Option<String>)> {
        sqlx::query_as("SELECT text, label FROM shared WHERE feedback_id = $1")
            .bind(feedback)
            .fetch_all(&store.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn only_the_rater_can_share_and_forget_removes_it() {
        let Some(store) = database().await else {
            return;
        };
        let user = unique_user();
        let feedback = store
            .record_feedback(user, false, &summary())
            .await
            .unwrap()
            .unwrap();
        store
            .share(feedback, user + 1, Some("someone else"), None)
            .await
            .unwrap();
        assert!(shared_rows(&store, feedback).await.is_empty());
        store
            .share(feedback, user, Some("pay the fee first"), None)
            .await
            .unwrap();
        store
            .share(feedback, user, Some("again"), None)
            .await
            .unwrap();
        assert_eq!(
            shared_rows(&store, feedback).await,
            [(Some("pay the fee first".to_owned()), None)]
        );
        let id: i64 = sqlx::query_scalar("SELECT id FROM shared WHERE feedback_id = $1")
            .bind(feedback)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        store.decide_shared(id, Decision::Scam).await.unwrap();
        assert_eq!(
            shared_rows(&store, feedback).await,
            [(
                Some("pay the fee first".to_owned()),
                Some("scam".to_owned())
            )]
        );
        let labelled = store.labelled().await.unwrap();
        assert!(
            labelled
                .iter()
                .any(|row| row.id == id && row.text == "pay the fee first" && row.label == "scam")
        );
        store.forget(user).await.unwrap();
        assert!(shared_rows(&store, feedback).await.is_empty());
    }

    #[tokio::test]
    async fn counted_checks_add_up_by_week() {
        let Some(store) = database().await else {
            return;
        };
        // A subject no real check uses, so other tests and old rows don't change the totals.
        let subject: &'static str = Box::leak(format!("test{}", unique_user()).into_boxed_str());
        let counted = |level, category| Counted {
            subject,
            level,
            category,
        };
        store
            .add_checks(&[
                (counted("high_risk", "loan"), 3),
                (counted("suspicious", "job"), 1),
                (counted("no_known_signals", ""), 5),
            ])
            .await
            .unwrap();
        store
            .add_checks(&[(counted("high_risk", "loan"), 2)])
            .await
            .unwrap();
        let mine: i64 = sqlx::query_scalar(
            "SELECT sum(checks)::int8 FROM daily_checks WHERE subject = $1 AND level = 'high_risk'",
        )
        .bind(subject)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(mine, 5);
        let day: NaiveDate =
            sqlx::query_scalar("SELECT day FROM daily_checks WHERE subject = $1 LIMIT 1")
                .bind(subject)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        let totals = store.totals(day, day + chrono::Days::new(1)).await.unwrap();
        assert!(totals.checks >= 11 && totals.high_risk >= 5 && totals.suspicious >= 1);
        assert!(
            totals
                .top
                .iter()
                .any(|(category, _)| *category == ScamCategory::Loan)
        );
        sqlx::query("DELETE FROM daily_checks WHERE subject = $1")
            .bind(subject)
            .execute(&store.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_week_is_drafted_and_posted_once() {
        let Some(store) = database().await else {
            return;
        };
        let week = NaiveDate::from_ymd_opt(1990, 1, 1).unwrap()
            + chrono::Days::new(7 * (unique_user() / 100 % 1_000_000));
        assert!(store.claim_week(week).await.unwrap());
        assert!(!store.claim_week(week).await.unwrap());
        store.unclaim_week(week).await.unwrap();
        assert!(store.claim_week(week).await.unwrap());
        assert!(store.mark_posted(week, true).await.unwrap());
        assert!(!store.mark_posted(week, true).await.unwrap());
        store.mark_posted(week, false).await.unwrap();
        assert!(store.mark_posted(week, true).await.unwrap());
        sqlx::query("DELETE FROM weekly_posts WHERE week = $1")
            .bind(week)
            .execute(&store.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn protected_groups_are_saved() {
        let Some(store) = database().await else {
            return;
        };
        let chat = -(unique_user() as i64 % 1_000_000_000_000);
        store.set_protected(chat, true).await.unwrap();
        store.set_protected(chat, true).await.unwrap();
        assert!(store.protected_chats().await.unwrap().contains(&chat));
        store.set_protected(chat, false).await.unwrap();
        assert!(!store.protected_chats().await.unwrap().contains(&chat));
    }

    #[tokio::test]
    async fn post_callbacks_round_trip() {
        let store = offline();
        let week = NaiveDate::from_ymd_opt(2026, 10, 19).unwrap();
        let data = store.post_callback(week);
        assert!(data.len() <= 64);
        assert_eq!(store.verify_post_callback(&data), Some(week));
        assert!(
            store
                .verify_post_callback(&data.replacen("10-19", "10-12", 1))
                .is_none()
        );
    }

    #[tokio::test]
    async fn exported_messages_are_deleted() {
        let Some(store) = database().await else {
            return;
        };
        let user = unique_user();
        let feedback = store
            .record_feedback(user, false, &summary())
            .await
            .unwrap()
            .unwrap();
        store.share(feedback, user, Some("hi"), None).await.unwrap();
        let id: i64 = sqlx::query_scalar("SELECT id FROM shared WHERE feedback_id = $1")
            .bind(feedback)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        store.delete_shared(&[id]).await.unwrap();
        assert!(shared_rows(&store, feedback).await.is_empty());
    }

    #[tokio::test]
    async fn shared_messages_older_than_30_days_are_purged() {
        let Some(store) = database().await else {
            return;
        };
        let user = unique_user();
        let feedback = store
            .record_feedback(user, false, &summary())
            .await
            .unwrap()
            .unwrap();
        store
            .share(feedback, user, None, Some("photo"))
            .await
            .unwrap();
        sqlx::query(
            "UPDATE shared SET created_at = now() - interval '31 days' WHERE feedback_id = $1",
        )
        .bind(feedback)
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store.purge_shared().await.unwrap() >= 1);
        assert!(shared_rows(&store, feedback).await.is_empty());
    }

    #[tokio::test]
    async fn feedback_over_the_daily_limit_is_refused() {
        let Some(store) = database().await else {
            return;
        };
        let user = unique_user();
        for _ in 0..FEEDBACK_PER_DAY {
            assert!(
                store
                    .record_feedback(user, true, &summary())
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            store
                .record_feedback(user, true, &summary())
                .await
                .unwrap()
                .is_none()
        );
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
