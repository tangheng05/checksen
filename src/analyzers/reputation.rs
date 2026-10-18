use std::time::Duration;

use anyhow::bail;
use reqwest::{Client, Url};
use serde_json::{Value, json};

use crate::env_var;

const ENDPOINT: &str = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threat {
    Phishing,
    Malware,
    UnwantedSoftware,
}

/// Google Safe Browsing's Lookup API: the full URLs are sent to Google.
pub struct SafeBrowsing {
    http: Client,
    api_key: String,
}

impl SafeBrowsing {
    pub fn from_env(timeout: Duration) -> anyhow::Result<Option<Self>> {
        let Some(api_key) = env_var("SAFE_BROWSING_API_KEY") else {
            return Ok(None);
        };
        Ok(Some(Self {
            http: Client::builder().timeout(timeout).build()?,
            api_key,
        }))
    }

    /// The worst threat listed for any of the URLs, such as every hop of a redirect chain.
    pub async fn lookup(&self, urls: &[Url]) -> anyhow::Result<Option<Threat>> {
        let response = self
            .http
            .post(ENDPOINT)
            .header("x-goog-api-key", &self.api_key)
            .json(&request(urls))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            bail!("Safe Browsing HTTP {status}");
        }
        Ok(worst_threat(&response.bytes().await?))
    }
}

fn request(urls: &[Url]) -> Value {
    let entries: Vec<Value> = urls
        .iter()
        .map(|url| json!({"url": url.as_str()}))
        .collect();
    json!({
        "client": {"clientId": "checksen", "clientVersion": env!("CARGO_PKG_VERSION")},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": entries,
        },
    })
}

fn worst_threat(body: &[u8]) -> Option<Threat> {
    let response: Value = serde_json::from_slice(body).ok()?;
    let threats = response["matches"].as_array()?.iter().filter_map(|found| {
        match found["threatType"].as_str()? {
            "SOCIAL_ENGINEERING" => Some(Threat::Phishing),
            "MALWARE" | "POTENTIALLY_HARMFUL_APPLICATION" => Some(Threat::Malware),
            "UNWANTED_SOFTWARE" => Some(Threat::UnwantedSoftware),
            _ => None,
        }
    });
    threats.min_by_key(|threat| match threat {
        Threat::Phishing => 0,
        Threat::Malware => 1,
        Threat::UnwantedSoftware => 2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_about_every_url() {
        let urls = [
            Url::parse("https://bit.ly/x").unwrap(),
            Url::parse("https://aba-verify.top/login").unwrap(),
        ];
        let body = request(&urls);
        let entries = body["threatInfo"]["threatEntries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1]["url"], "https://aba-verify.top/login");
    }

    #[test]
    fn reads_the_worst_match() {
        assert_eq!(worst_threat(b"{}"), None);
        let body = br#"{"matches":[
            {"threatType":"UNWANTED_SOFTWARE","threat":{"url":"a"}},
            {"threatType":"SOCIAL_ENGINEERING","threat":{"url":"b"}}]}"#;
        assert_eq!(worst_threat(body), Some(Threat::Phishing));
        let malware = br#"{"matches":[{"threatType":"POTENTIALLY_HARMFUL_APPLICATION"}]}"#;
        assert_eq!(worst_threat(malware), Some(Threat::Malware));
    }
}
