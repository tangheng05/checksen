use std::time::Duration;

use anyhow::{Context, ensure};
use futures::future::BoxFuture;
use reqwest::Client;
use serde_json::{Value, json};

use super::{
    Classification, Classifier, SYSTEM_PROMPT, ScamCategory, parse_classification, send_with_retry,
    user_prompt,
};
use crate::analyzers::Signal;

const DEFAULT_MODEL: &str = "gemini-3.8-flash";

// Gemini's free tier trains on and lets humans review what it is sent; only public benchmark data may go here.
pub struct GeminiClassifier {
    http: Client,
    api_key: String,
    endpoint: String,
    attempts: u32,
    schema: Value,
}

impl GeminiClassifier {
    pub fn from_env(timeout: Duration, attempts: u32) -> anyhow::Result<Option<Self>> {
        let Some(api_key) = std::env::var("GEMINI_API_KEY")
            .ok()
            .filter(|key| !key.is_empty())
        else {
            return Ok(None);
        };
        let model = std::env::var("GEMINI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_owned());
        Ok(Some(Self {
            http: Client::builder().timeout(timeout).build()?,
            api_key,
            endpoint: format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            ),
            attempts,
            schema: schema(),
        }))
    }
}

impl Classifier for GeminiClassifier {
    fn classify<'a>(
        &'a self,
        text: &'a str,
        found: &'a [Signal],
    ) -> BoxFuture<'a, anyhow::Result<Classification>> {
        let body = json!({
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt(text, found)}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": self.schema,
                "temperature": 0,
                "maxOutputTokens": 2048,
            },
        });
        Box::pin(send_with_retry(
            self.attempts,
            move || {
                self.http
                    .post(&self.endpoint)
                    .header("x-goog-api-key", &self.api_key)
                    .json(&body)
            },
            parse_response,
        ))
    }
}

fn schema() -> Value {
    json!({
        "type": "OBJECT",
        "properties": {
            "category": {"type": "STRING", "enum": ScamCategory::NAMES},
            "confidence": {"type": "STRING", "enum": ["low", "medium", "high"]},
            "cited_signals": {
                "type": "ARRAY",
                "items": {"type": "STRING", "enum": Signal::rule_names().collect::<Vec<_>>()},
            },
        },
        "required": ["category", "confidence", "cited_signals"],
        "propertyOrdering": ["category", "confidence", "cited_signals"],
    })
}

fn parse_response(body: &[u8]) -> anyhow::Result<Classification> {
    let response: Value = serde_json::from_slice(body)?;
    let candidate = &response["candidates"][0];
    let finish_reason = candidate["finishReason"].as_str();
    ensure!(
        finish_reason == Some("STOP"),
        "finishReason {finish_reason:?}"
    );
    let text: String = candidate["content"]["parts"]
        .as_array()
        .context("no parts")?
        .iter()
        .filter(|part| part["thought"] != true)
        .filter_map(|part| part["text"].as_str())
        .collect();
    parse_classification(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_structured_response() {
        let body = br#"{"candidates":[{"finishReason":"STOP","content":{"parts":[
            {"text":"{\"category\":\"none\",\"confidence\":\"high\",\"cited_signals\":[]}"}]}}]}"#;
        assert_eq!(parse_response(body).unwrap().category, ScamCategory::None);
    }

    #[test]
    fn blocked_or_truncated_responses_are_errors() {
        for reason in ["SAFETY", "MAX_TOKENS"] {
            let body = format!(
                r#"{{"candidates":[{{"finishReason":"{reason}","content":{{"parts":[]}}}}]}}"#
            );
            assert!(parse_response(body.as_bytes()).is_err());
        }
        assert!(parse_response(br#"{"promptFeedback":{"blockReason":"SAFETY"}}"#).is_err());
    }
}
