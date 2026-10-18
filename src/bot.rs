use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{MessageEntityKind, PhotoSize};
use url::Url;

use checksen::analyzers::link::{self, LinkChecker};
use checksen::analyzers::llm::{self, Classifier, Transcriber};
use checksen::analyzers::text::RULES_VERSION;
use checksen::analyzers::{self, Check, Signal, Subject, khqr, text};
use checksen::verdict;

use crate::guard::{Admission, Guard, ModelCall, Reply};
use crate::reports;
use crate::store::Store;

const MAX_PHOTO_BYTES: u32 = 10 * 1024 * 1024;
const MAX_LINKS_PER_MESSAGE: usize = 3;
const MIN_TEXT_CHARS: usize = 20;
const CLASSIFIER_BUDGET: Duration = Duration::from_secs(3);
const TRANSCRIBE_BUDGET: Duration = Duration::from_secs(20);

struct Outcome {
    reply: Reply,
    cacheable: bool,
}

impl Outcome {
    fn of(checks: &[Check]) -> Self {
        let mut payees = checks.iter().filter_map(|check| match &check.subject {
            Subject::Khqr(payee) => Some(payee.bakong_account_id.clone()),
            _ => None,
        });
        let account = match (payees.next(), payees.next()) {
            (Some(account), None) => Some(account),
            _ => None,
        };
        Self {
            reply: Reply {
                text: verdict::render_km(checks),
                account,
            },
            cacheable: !checks.iter().any(|check| {
                check.signals.contains(&Signal::ModelUnavailable)
                    || matches!(check.subject, Subject::Link(_))
            }),
        }
    }

    fn text(text: impl Into<String>, cacheable: bool) -> Self {
        Self {
            reply: Reply {
                text: text.into(),
                account: None,
            },
            cacheable,
        }
    }
}

pub async fn handle(
    bot: Bot,
    msg: Message,
    links: Arc<LinkChecker>,
    classifier: Option<Arc<dyn Classifier>>,
    transcriber: Option<Arc<dyn Transcriber>>,
    guard: Arc<Guard>,
    store: Option<Arc<Store>>,
) -> ResponseResult<()> {
    if msg.text().is_some_and(|text| text.starts_with("/forget")) {
        let reply = reports::forget_reply(store.as_deref(), msg.from.as_ref()).await;
        bot.send_message(msg.chat.id, reply).await?;
        return Ok(());
    }
    let Some(key) = cache_key(&guard, &msg) else {
        bot.send_message(msg.chat.id, verdict::HELP_KM).await?;
        return Ok(());
    };

    let sender = msg
        .from
        .as_ref()
        .map_or(msg.chat.id.0 as u64, |user| user.id.0);
    match guard.admit(sender) {
        Admission::Allowed => {}
        Admission::LimitReached => {
            bot.send_message(msg.chat.id, verdict::RATE_LIMITED_KM)
                .await?;
            return Ok(());
        }
        Admission::Silent => return Ok(()),
    }

    let reply = match guard.cached(key) {
        Some(reply) => reply,
        None => {
            let outcome = check(
                &bot,
                &msg,
                &links,
                classifier.as_deref(),
                transcriber.as_deref(),
                &guard,
                store.as_deref(),
            )
            .await;
            let reply = Arc::new(outcome.reply);
            if outcome.cacheable {
                guard.store(key, reply.clone());
            }
            reply
        }
    };

    let keyboard = reports::keyboard(store.as_deref(), reply.account.as_deref());
    let request = bot.send_message(msg.chat.id, reply.text.as_str());
    match keyboard {
        Some(keyboard) => request.reply_markup(keyboard).await?,
        None => request.await?,
    };
    Ok(())
}

fn largest_photo(msg: &Message) -> Option<&PhotoSize> {
    msg.photo()
        .and_then(|sizes| sizes.iter().max_by_key(|size| size.width * size.height))
}

fn cache_key(guard: &Guard, msg: &Message) -> Option<u64> {
    if let Some(photo) = largest_photo(msg) {
        return Some(guard.key((RULES_VERSION, "photo", &photo.file.unique_id.0)));
    }
    if let Some(message) = msg.text().filter(|text| !text.starts_with('/')) {
        let urls: Vec<String> = urls_in(msg).iter().map(Url::to_string).collect();
        return Some(guard.key((RULES_VERSION, "text", message, urls)));
    }
    msg.document().map(|document| {
        guard.key((
            RULES_VERSION,
            "document",
            &document.file.unique_id.0,
            msg.caption().unwrap_or_default(),
        ))
    })
}

async fn check(
    bot: &Bot,
    msg: &Message,
    links: &LinkChecker,
    classifier: Option<&dyn Classifier>,
    transcriber: Option<&dyn Transcriber>,
    guard: &Guard,
    store: Option<&Store>,
) -> Outcome {
    if let Some(photo) = largest_photo(msg) {
        let image = match download_photo(bot, photo).await {
            Ok(image) => image,
            Err(error) => {
                tracing::warn!(%error, "photo download failed");
                return Outcome::text(verdict::render_km(&[]), false);
            }
        };
        return check_photo(image, links, classifier, transcriber, guard, store).await;
    }
    if let Some(payload) = msg.text().filter(|text| khqr::looks_like_khqr(text)) {
        return Outcome::of(&reports::with_reports(vec![khqr::check(payload)], store).await);
    }
    if let Some(message) = msg.text() {
        return check_text(msg, message, links, classifier, guard).await;
    }
    let file_name = msg
        .document()
        .and_then(|document| document.file_name.as_deref())
        .unwrap_or_default();
    let described = format!("{file_name} {}", msg.caption().unwrap_or_default());
    Outcome::of(&[text::check(&described)])
}

async fn check_text(
    msg: &Message,
    message: &str,
    links: &LinkChecker,
    classifier: Option<&dyn Classifier>,
    guard: &Guard,
) -> Outcome {
    let urls = urls_in(msg);
    let text_check = text::check(message);
    if text_check.signals.is_empty() && urls.is_empty() && message.chars().count() < MIN_TEXT_CHARS
    {
        return Outcome::text(verdict::HELP_KM, true);
    }

    let show_text = urls.is_empty();
    let (text_check, link_checks) = tokio::join!(
        classify_text(text_check, message, classifier, guard),
        join_all(urls.into_iter().map(|url| links.check(url)))
    );

    let mut checks = Vec::new();
    if show_text || !text_check.signals.is_empty() {
        checks.push(text_check);
    }
    checks.extend(link_checks);
    Outcome::of(&checks)
}

async fn classify_text(
    mut text_check: Check,
    message: &str,
    classifier: Option<&dyn Classifier>,
    guard: &Guard,
) -> Check {
    match classifier {
        Some(classifier) if guard.allow_model_call(ModelCall::Text) => {
            llm::classify(text_check, message, classifier, CLASSIFIER_BUDGET).await
        }
        Some(_) => {
            tracing::warn!("daily classifier budget used up");
            text_check.signals.push(Signal::ModelUnavailable);
            text_check
        }
        None => text_check,
    }
}

async fn download_photo(bot: &Bot, photo: &PhotoSize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(photo.file.size <= MAX_PHOTO_BYTES, "photo too large");
    let file = bot.get_file(photo.file.id.clone()).await?;
    let mut bytes = Vec::new();
    bot.download_file(&file.path, &mut bytes).await?;
    Ok(bytes)
}

async fn check_photo(
    image: Vec<u8>,
    links: &LinkChecker,
    classifier: Option<&dyn Classifier>,
    transcriber: Option<&dyn Transcriber>,
    guard: &Guard,
    store: Option<&Store>,
) -> Outcome {
    let decoded = tokio::task::spawn_blocking(move || {
        let payloads = khqr::payloads_from_image(&image);
        (image, payloads)
    })
    .await;
    let (image, payloads) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            tracing::warn!(%error, "QR decoding failed");
            return Outcome::text(verdict::render_km(&[]), false);
        }
    };
    if !payloads.is_empty() {
        let checks = join_all(
            payloads
                .iter()
                .map(|payload| analyzers::check_qr_payload(payload, links)),
        )
        .await;
        return Outcome::of(&reports::with_reports(checks, store).await);
    }

    let Some(transcriber) = transcriber else {
        return Outcome::of(&[]);
    };
    if !guard.allow_model_call(ModelCall::Screenshot) {
        tracing::warn!("daily screenshot budget used up");
        return Outcome::text(verdict::screenshot_unread_km(), false);
    }
    match llm::transcribe(&image, transcriber, TRANSCRIBE_BUDGET).await {
        Ok(Some(transcript)) => {
            let check =
                classify_text(text::check(&transcript), &transcript, classifier, guard).await;
            Outcome::of(&[check])
        }
        Ok(None) => Outcome::of(&[]),
        Err(error) => {
            tracing::warn!(%error, "screenshot transcription failed");
            Outcome::text(verdict::screenshot_unread_km(), false)
        }
    }
}

fn urls_in(msg: &Message) -> Vec<Url> {
    let mut urls: Vec<Url> = Vec::new();
    for entity in msg.parse_entities().unwrap_or_default() {
        let url = match entity.kind() {
            MessageEntityKind::Url => url_from_entity_text(entity.text()),
            MessageEntityKind::TextLink { url } => link::parse_http_url(url.as_str()),
            _ => None,
        };
        if let Some(url) = url.filter(|url| !urls.contains(url)) {
            urls.push(url);
        }
    }
    urls.truncate(MAX_LINKS_PER_MESSAGE);
    urls
}

fn url_from_entity_text(text: &str) -> Option<Url> {
    link::parse_http_url(text).or_else(|| link::parse_http_url(&format!("http://{text}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_urls_without_scheme_get_http() {
        assert_eq!(
            url_from_entity_text("aba-verify.com/login")
                .unwrap()
                .as_str(),
            "http://aba-verify.com/login"
        );
        assert_eq!(
            url_from_entity_text("https://bit.ly/x").unwrap().as_str(),
            "https://bit.ly/x"
        );
    }
}
