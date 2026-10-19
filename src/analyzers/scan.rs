use std::time::Duration;

use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::file::VirusTotal;
use crate::env_var;

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_REPLY_BYTES: u64 = 4 * 1024;

/// A local clamd, reached over its Unix socket (a path) or TCP (host:port). Files never leave the server.
pub struct ClamAv {
    address: String,
}

impl ClamAv {
    pub fn from_env() -> Option<Self> {
        env_var("CLAMD_ADDRESS").map(|address| Self { address })
    }

    pub async fn is_clean(&self, bytes: &[u8]) -> anyhow::Result<bool> {
        let reply = if self.address.starts_with('/') {
            #[cfg(unix)]
            {
                instream(tokio::net::UnixStream::connect(&self.address).await?, bytes).await?
            }
            #[cfg(not(unix))]
            bail!("Unix sockets need a Unix server")
        } else {
            instream(tokio::net::TcpStream::connect(&self.address).await?, bytes).await?
        };
        parse_clamd_reply(&reply)
    }
}

async fn instream(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    bytes: &[u8],
) -> anyhow::Result<String> {
    stream.write_all(b"zINSTREAM\0").await?;
    for chunk in bytes.chunks(CHUNK_BYTES) {
        stream
            .write_all(&(chunk.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(chunk).await?;
    }
    stream.write_all(&0u32.to_be_bytes()).await?;
    let mut reply = Vec::new();
    stream.take(MAX_REPLY_BYTES).read_to_end(&mut reply).await?;
    Ok(String::from_utf8_lossy(&reply)
        .trim_end_matches('\0')
        .trim()
        .to_owned())
}

fn parse_clamd_reply(reply: &str) -> anyhow::Result<bool> {
    if reply.ends_with("FOUND") {
        Ok(false)
    } else if reply.ends_with("OK") {
        Ok(true)
    } else {
        bail!("clamd replied {reply:?}")
    }
}

/// A file's SHA-256, the only thing sent to VirusTotal and MalwareBazaar.
pub fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// VirusTotal by hash only: the file itself is never uploaded, so private documents stay private.
pub struct VirusTotalClient {
    http: Client,
    api_key: String,
}

impl VirusTotalClient {
    pub fn from_env(timeout: Duration) -> anyhow::Result<Option<Self>> {
        let Some(api_key) = env_var("VIRUSTOTAL_API_KEY") else {
            return Ok(None);
        };
        Ok(Some(Self {
            http: Client::builder().timeout(timeout).build()?,
            api_key,
        }))
    }

    pub async fn lookup(&self, sha256: &str) -> anyhow::Result<VirusTotal> {
        let response = self
            .http
            .get(format!("https://www.virustotal.com/api/v3/files/{sha256}"))
            .header("x-apikey", &self.api_key)
            .send()
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(VirusTotal::Unknown),
            status if status.is_success() => parse_report(&response.bytes().await?),
            status => bail!("VirusTotal HTTP {status}"),
        }
    }
}

fn parse_report(body: &[u8]) -> anyhow::Result<VirusTotal> {
    let report: Value = serde_json::from_slice(body)?;
    let stats = &report["data"]["attributes"]["last_analysis_stats"];
    let count = |key: &str| u16::try_from(stats[key].as_u64().unwrap_or(0)).unwrap_or(u16::MAX);
    stats.as_object().context("no analysis stats")?;
    let malicious = count("malicious");
    let engines = ["malicious", "suspicious", "undetected", "harmless"]
        .into_iter()
        .map(count)
        .fold(0u16, u16::saturating_add);
    Ok(VirusTotal::Seen { malicious, engines })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_clamd_replies() {
        assert!(parse_clamd_reply("stream: OK").unwrap());
        assert!(!parse_clamd_reply("stream: Win.Test.EICAR_HDB-1 FOUND").unwrap());
        assert!(parse_clamd_reply("INSTREAM size limit exceeded. ERROR").is_err());
    }

    #[test]
    fn reads_virustotal_reports() {
        let body = br#"{"data":{"attributes":{"last_analysis_stats":
            {"malicious":41,"suspicious":2,"undetected":20,"harmless":0,"timeout":1,"type-unsupported":7}}}}"#;
        assert_eq!(
            parse_report(body).unwrap(),
            VirusTotal::Seen {
                malicious: 41,
                engines: 63
            }
        );
        assert!(parse_report(br#"{"error":{"code":"QuotaExceededError"}}"#).is_err());
    }

    #[tokio::test]
    async fn talks_to_clamd_over_instream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut command = [0; 10];
            socket.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"zINSTREAM\0");
            let mut received = Vec::new();
            loop {
                let length = socket.read_u32().await.unwrap() as usize;
                if length == 0 {
                    break;
                }
                let mut chunk = vec![0; length];
                socket.read_exact(&mut chunk).await.unwrap();
                received.extend(chunk);
            }
            let reply: &[u8] = if received.starts_with(b"X5O!") {
                b"stream: Eicar-Signature FOUND\0"
            } else {
                b"stream: OK\0"
            };
            socket.write_all(reply).await.unwrap();
        });
        let clamav = ClamAv { address };
        assert!(
            !clamav
                .is_clean(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
                .await
                .unwrap()
        );
    }
}
