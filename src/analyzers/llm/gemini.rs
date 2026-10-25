use std::time::Duration;

use anyhow::{Context, anyhow, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures::future::BoxFuture;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Classification, Classifier, LISTEN_PROMPT, Media, OUTPUT_FIELDS, SYSTEM_PROMPT,
    TRANSCRIBE_PROMPT, Transcriber, output_schema, parse_classification, send_with_retry,
    user_prompt,
};
use crate::analyzers::Signal;
use crate::env_var;

// Each model has its own free-tier quota, so later ones take over when earlier ones run out.
const DEFAULT_MODELS: &str = "gemini-3.5-flash-lite,gemini-3.1-flash-lite";

// Gemini's free tier trains on and lets humans review the text and screenshots it is sent; /help and the README disclose this.
pub struct GeminiClassifier {
    http: Client,
    api_key: String,
    endpoints: Vec<String>,
    attempts: u32,
    schema: Value,
}

impl GeminiClassifier {
    pub fn from_env(timeout: Duration, attempts: u32) -> anyhow::Result<Option<Self>> {
        let Some(api_key) = env_var("GEMINI_API_KEY") else {
            return Ok(None);
        };
        let models = env_var("GEMINI_MODEL").unwrap_or_else(|| DEFAULT_MODELS.to_owned());
        Ok(Some(Self {
            http: Client::builder().timeout(timeout).build()?,
            api_key,
            endpoints: endpoints(&models),
            attempts,
            schema: schema(),
        }))
    }

    /// Tries each model in turn; only the last one gets the full retry budget.
    async fn generate<T>(
        &self,
        body: Value,
        parse: fn(&[u8]) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut last_error = anyhow!("no Gemini model configured");
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            let attempts = if index + 1 == self.endpoints.len() {
                self.attempts
            } else {
                1
            };
            let request = || {
                self.http
                    .post(endpoint)
                    .header("x-goog-api-key", &self.api_key)
                    .json(&body)
            };
            match send_with_retry(attempts, request, parse).await {
                Ok(parsed) => return Ok(parsed),
                Err(error) => {
                    tracing::warn!(%error, model = index, "Gemini model failed");
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }
}

fn endpoints(models: &str) -> Vec<String> {
    models
        .split(',')
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(|model| {
            format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            )
        })
        .collect()
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
                "thinkingConfig": {"thinkingLevel": "low"},
            },
        });
        Box::pin(self.generate(body, parse_response))
    }
}

impl Transcriber for GeminiClassifier {
    fn transcribe<'a>(
        &'a self,
        media: &'a [u8],
        kind: Media,
    ) -> BoxFuture<'a, anyhow::Result<Option<String>>> {
        Box::pin(self.generate(transcribe_body(media, kind), parse_transcript))
    }
}

fn transcribe_body(media: &[u8], kind: Media) -> Value {
    let (mime, prompt) = match kind {
        Media::Image => ("image/jpeg", TRANSCRIBE_PROMPT),
        Media::Voice => ("audio/ogg", LISTEN_PROMPT),
    };
    json!({
            "systemInstruction": {"parts": [{"text": prompt}]},
            "contents": [{"role": "user", "parts": [
                {"inlineData": {"mimeType": mime, "data": STANDARD.encode(media)}},
            ]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "is_message": {"type": "BOOLEAN"},
                        "text": {"type": "STRING"},
                    },
                    "required": ["is_message", "text"],
                    "propertyOrdering": ["is_message", "text"],
                },
                "temperature": 0,
                "maxOutputTokens": 4096,
                "thinkingConfig": {"thinkingLevel": "low"},
            },
    })
}

fn schema() -> Value {
    let mut schema = output_schema("OBJECT", "STRING", "ARRAY");
    schema["propertyOrdering"] = json!(OUTPUT_FIELDS);
    schema
}

fn parse_response(body: &[u8]) -> anyhow::Result<Classification> {
    parse_classification(&response_text(body)?)
}

#[derive(Deserialize)]
struct Transcript {
    is_message: bool,
    text: String,
}

fn parse_transcript(body: &[u8]) -> anyhow::Result<Option<String>> {
    let transcript: Transcript = serde_json::from_str(&response_text(body)?)?;
    Ok(transcript.is_message.then_some(transcript.text))
}

fn response_text(body: &[u8]) -> anyhow::Result<String> {
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
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::llm::ScamCategory;

    #[test]
    fn voice_is_sent_as_audio_with_the_listening_prompt() {
        let voice = transcribe_body(b"ogg", Media::Voice);
        assert_eq!(
            voice["contents"][0]["parts"][0]["inlineData"]["mimeType"],
            "audio/ogg"
        );
        assert_eq!(
            voice["systemInstruction"]["parts"][0]["text"],
            LISTEN_PROMPT
        );
        let image = transcribe_body(b"jpeg", Media::Image);
        assert_eq!(
            image["contents"][0]["parts"][0]["inlineData"]["mimeType"],
            "image/jpeg"
        );
    }

    async fn respond(socket: tokio::net::TcpStream) -> std::io::Result<()> {
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        while !String::from_utf8_lossy(&request).contains("\"maxOutputTokens\"") {
            socket.readable().await?;
            match socket.try_read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        let (status, body) = if request.starts_with(b"POST /busy") {
            ("429 Too Many Requests", "{}")
        } else {
            (
                "200 OK",
                r#"{"candidates":[{"finishReason":"STOP","content":{"parts":[{"text":"{\"category\":\"none\",\"confidence\":\"high\",\"cited_signals\":[],\"intent\":\"greeting\"}"}]}}]}"#,
            )
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut written = 0;
        while written < response.len() {
            socket.writable().await?;
            match socket.try_write(&response.as_bytes()[written..]) {
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_busy_model_falls_back_to_the_next() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(respond(socket));
            }
        });
        let gemini = GeminiClassifier {
            http: Client::new(),
            api_key: "test".to_owned(),
            endpoints: vec![
                format!("http://{address}/busy"),
                format!("http://{address}/free"),
            ],
            attempts: 1,
            schema: schema(),
        };
        let classification = gemini.classify("hello", &[]).await.unwrap();
        assert_eq!(classification.category, ScamCategory::None);
        assert_eq!(
            classification.intent,
            Some(crate::analyzers::intent::Intent::Greeting)
        );
    }

    #[test]
    fn model_list_becomes_endpoints_in_order() {
        let endpoints = endpoints(" gemini-a , gemini-b,,");
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints[0].ends_with("/models/gemini-a:generateContent"));
        assert!(endpoints[1].ends_with("/models/gemini-b:generateContent"));
    }

    #[test]
    fn parses_a_structured_response() {
        let body = br#"{"candidates":[{"finishReason":"STOP","content":{"parts":[
            {"text":"{\"category\":\"none\",\"confidence\":\"high\",\"cited_signals\":[]}"}]}}]}"#;
        assert_eq!(parse_response(body).unwrap().category, ScamCategory::None);
    }

    #[test]
    fn parses_a_transcript() {
        let message = br#"{"candidates":[{"finishReason":"STOP","content":{"parts":[
            {"text":"{\"is_message\":true,\"text\":\"Your account is locked\"}"}]}}]}"#;
        assert_eq!(
            parse_transcript(message).unwrap().as_deref(),
            Some("Your account is locked")
        );
        let photo = br#"{"candidates":[{"finishReason":"STOP","content":{"parts":[
            {"text":"{\"is_message\":false,\"text\":\"\"}"}]}}]}"#;
        assert!(parse_transcript(photo).unwrap().is_none());
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
