//! abuse.ch's free lookups, with one Auth-Key: MalwareBazaar knows malware files by their fingerprint,
//! and URLhaus knows links that spread malware. Both databases update every few minutes.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::bail;
use reqwest::{Client, Url};
use serde_json::Value;

use crate::env_var;

const MALWAREBAZAAR: &str = "https://mb-api.abuse.ch/api/v1/";
const URLHAUS: &str = "https://urlhaus-api.abuse.ch/v1/url/";
/// abuse.ch is free under fair use; this keeps a busy day well inside it.
const LOOKUPS_PER_DAY: u32 = 5_000;
const MAX_URLS: usize = 3;

pub struct AbuseCh {
    http: Client,
    key: String,
    /// The day number and how many lookups were made on it.
    today: Mutex<(u64, u32)>,
}

impl AbuseCh {
    pub fn from_env(timeout: Duration) -> anyhow::Result<Option<Self>> {
        let Some(key) = env_var("ABUSECH_AUTH_KEY") else {
            return Ok(None);
        };
        Ok(Some(Self {
            http: Client::builder().timeout(timeout).build()?,
            key,
            today: Mutex::new((0, 0)),
        }))
    }

    /// Whether MalwareBazaar knows the file. Only its SHA-256 is sent.
    pub async fn known_file(&self, sha256: &str) -> anyhow::Result<bool> {
        let body = self
            .post(MALWAREBAZAAR, &[("query", "get_info"), ("hash", sha256)])
            .await?;
        listed(&body, "hash_not_found")
    }

    /// Whether URLhaus lists any of the URLs, such as the hops of a redirect chain.
    pub async fn known_link(&self, urls: &[Url]) -> anyhow::Result<bool> {
        for url in urls.iter().take(MAX_URLS) {
            let body = self.post(URLHAUS, &[("url", url.as_str())]).await?;
            if listed(&body, "no_results")? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn post(&self, endpoint: &str, form: &[(&str, &str)]) -> anyhow::Result<Value> {
        if !self.allow_lookup() {
            bail!("daily abuse.ch budget used up");
        }
        let response = self
            .http
            .post(endpoint)
            .header("Auth-Key", &self.key)
            .form(form)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            bail!("abuse.ch HTTP {status}");
        }
        Ok(serde_json::from_slice(&response.bytes().await?)?)
    }

    fn allow_lookup(&self) -> bool {
        let day = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
        let Ok(mut today) = self.today.lock() else {
            return false;
        };
        if today.0 != day {
            *today = (day, 0);
        }
        today.1 += 1;
        today.1 <= LOOKUPS_PER_DAY
    }
}

/// `ok` means listed and `unknown` means not; anything else (a bad key, a malformed query) is an error.
fn listed(body: &Value, unknown: &str) -> anyhow::Result<bool> {
    match body["query_status"].as_str() {
        Some("ok") => Ok(true),
        Some(status) if status == unknown => Ok(false),
        status => bail!("abuse.ch replied {status:?}"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reads_lookup_replies() {
        assert!(listed(&json!({"query_status": "ok", "data": []}), "hash_not_found").unwrap());
        assert!(!listed(&json!({"query_status": "hash_not_found"}), "hash_not_found").unwrap());
        assert!(!listed(&json!({"query_status": "no_results"}), "no_results").unwrap());
        assert!(listed(&json!({"query_status": "unknown_auth_key"}), "no_results").is_err());
        assert!(listed(&json!({}), "no_results").is_err());
    }

    #[test]
    fn lookups_stop_at_the_daily_budget() {
        let client = AbuseCh {
            http: Client::new(),
            key: String::new(),
            today: Mutex::new((0, 0)),
        };
        assert!((0..LOOKUPS_PER_DAY).all(|_| client.allow_lookup()));
        assert!(!client.allow_lookup());
    }
}
