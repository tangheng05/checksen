use anyhow::ensure;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

type HmacSha256 = Hmac<Sha256>;

pub const REPORT_THRESHOLD: i64 = 3;
const REPORTS_PER_DAY: i64 = 5;
const MAX_ACCOUNT_BYTES: usize = 32;
const TAG_BYTES: usize = 8;

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

    pub async fn reporters(&self, account: &str) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT r.reporter_hash) FROM reports r
             JOIN indicators i ON i.id = r.indicator_id
             WHERE i.kind = 'khqr_account' AND i.value = $1 AND r.status <> 'disputed'",
        )
        .bind(normalize(account))
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn report(&self, account: &str, user_id: u64) -> anyhow::Result<ReportOutcome> {
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
            "INSERT INTO indicators (kind, value) VALUES ('khqr_account', $1)
             ON CONFLICT (kind, value) DO UPDATE SET last_seen = now() RETURNING id",
        )
        .bind(normalize(account))
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

    pub async fn forget(&self, user_id: u64) -> anyhow::Result<u64> {
        let removed = sqlx::query("DELETE FROM reports WHERE reporter_hash = $1")
            .bind(self.reporter_hash(user_id))
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(removed)
    }
}

fn normalize(account: &str) -> String {
    account.trim().to_lowercase()
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

    fn unique_account(label: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{label}{}@test", nanos % 1_000_000_000_000)
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
        assert_eq!(store.reporters(&account).await.unwrap(), 2);
        store
            .report(&account.to_uppercase(), first + 2)
            .await
            .unwrap();
        assert_eq!(store.reporters(&account).await.unwrap(), REPORT_THRESHOLD);
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
        .bind(&account)
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(store.reporters(&account).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn sixth_report_in_a_day_is_refused() {
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
    async fn forget_removes_a_users_reports() {
        let Some(store) = database().await else {
            return;
        };
        let account = unique_account("forget");
        let user = unique_user();
        store.report(&account, user).await.unwrap();
        assert_eq!(store.forget(user).await.unwrap(), 1);
        assert_eq!(store.reporters(&account).await.unwrap(), 0);
    }
}
