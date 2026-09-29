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

const ENDPOINT: &str = "https://api.anthropic.com/v1/messages";
const MODEL: &str = "claude-haiku-4-5";

pub struct AnthropicClassifier {
    http: Client,
    api_key: String,
    attempts: u32,
    schema: Value,
}

impl AnthropicClassifier {
    pub fn from_env(timeout: Duration, attempts: u32) -> anyhow::Result<Option<Self>> {
        let Some(api_key) = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|key| !key.is_empty())
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            http: Client::builder().timeout(timeout).build()?,
            api_key,
            attempts,
            schema: schema(),
        }))
    }
}

impl Classifier for AnthropicClassifier {
    fn classify<'a>(
        &'a self,
        text: &'a str,
        found: &'a [Signal],
    ) -> BoxFuture<'a, anyhow::Result<Classification>> {
        let body = json!({
            "model": MODEL,
            "max_tokens": 256,
            "temperature": 0,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_prompt(text, found)}],
            "output_config": {"format": {"type": "json_schema", "schema": self.schema}},
        });
        Box::pin(send_with_retry(
            self.attempts,
            move || {
                self.http
                    .post(ENDPOINT)
                    .header("x-api-key", &self.api_key)
                    .header("anthropic-version", "2023-06-01")
                    .json(&body)
            },
            parse_response,
        ))
    }
}

fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "category": {"type": "string", "enum": ScamCategory::NAMES},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "cited_signals": {
                "type": "array",
                "items": {"type": "string", "enum": Signal::rule_names().collect::<Vec<_>>()},
            },
        },
        "required": ["category", "confidence", "cited_signals"],
        "additionalProperties": false,
    })
}

fn parse_response(body: &[u8]) -> anyhow::Result<Classification> {
    let response: Value = serde_json::from_slice(body)?;
    let stop_reason = response["stop_reason"].as_str();
    ensure!(
        stop_reason == Some("end_turn"),
        "stop_reason {stop_reason:?}"
    );
    tracing::info!(
        model = MODEL,
        input_tokens = response["usage"]["input_tokens"].as_u64(),
        output_tokens = response["usage"]["output_tokens"].as_u64(),
        "classified"
    );
    let text = response["content"]
        .as_array()
        .and_then(|blocks| blocks.iter().find(|block| block["type"] == "text"))
        .and_then(|block| block["text"].as_str())
        .context("no text block")?;
    parse_classification(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_structured_response() {
        let body = br#"{"stop_reason":"end_turn","usage":{"input_tokens":900,"output_tokens":20},
            "content":[{"type":"text","text":"{\"category\":\"otp\",\"confidence\":\"high\",\"cited_signals\":[]}"}]}"#;
        assert_eq!(parse_response(body).unwrap().category, ScamCategory::Otp);
    }

    #[test]
    fn refusals_and_truncation_are_errors() {
        for stop_reason in ["refusal", "max_tokens"] {
            let body = format!(r#"{{"stop_reason":"{stop_reason}","content":[]}}"#);
            assert!(parse_response(body.as_bytes()).is_err());
        }
    }
}
