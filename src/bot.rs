use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{MessageEntityKind, PhotoSize};
use url::Url;

use checksen::analyzers::link::{self, LinkChecker};
use checksen::analyzers::llm::{self, anthropic::AnthropicClassifier};
use checksen::analyzers::text::RULES_VERSION;
use checksen::analyzers::{self, Check, Signal, Subject, khqr, text};
use checksen::verdict;

use crate::guard::{Admission, Guard, Reply};
use crate::reports;
use crate::store::Store;

const MAX_PHOTO_BYTES: u32 = 10 * 1024 * 1024;
const MAX_LINKS_PER_MESSAGE: usize = 3;
const MIN_TEXT_CHARS: usize = 20;
const CLASSIFIER_BUDGET: Duration = Duration::from_secs(3);

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
    classifier: Option<Arc<AnthropicClassifier>>,
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
    classifier: Option<&AnthropicClassifier>,
    guard: &Guard,
    store: Option<&Store>,
) -> Outcome {
    if let Some(photo) = largest_photo(msg) {
        return match check_photo(bot, photo, links).await {
            Ok(checks) => Outcome::of(&reports::with_reports(checks, store).await),
            Err(error) => {
                tracing::warn!(%error, "photo check failed");
                Outcome::text(verdict::render_km(&[]), false)
            }
        };
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
    classifier: Option<&AnthropicClassifier>,
    guard: &Guard,
) -> Outcome {
    let urls = urls_in(msg);
    let text_check = text::check(message);
    if text_check.signals.is_empty() && urls.is_empty() && message.chars().count() < MIN_TEXT_CHARS
    {
        return Outcome::text(verdict::HELP_KM, true);
    }

    let show_text = urls.is_empty();
    let classified = async {
        match classifier {
            Some(classifier) if guard.allow_model_call() => {
                llm::classify(text_check, message, classifier, CLASSIFIER_BUDGET).await
            }
            Some(_) => {
                tracing::warn!("daily classifier budget used up");
                let mut text_check = text_check;
                text_check.signals.push(Signal::ModelUnavailable);
                text_check
            }
            None => text_check,
        }
    };
    let (text_check, link_checks) = tokio::join!(
        classified,
        join_all(urls.into_iter().map(|url| links.check(url)))
    );

    let mut checks = Vec::new();
    if show_text || !text_check.signals.is_empty() {
        checks.push(text_check);
    }
    checks.extend(link_checks);
    Outcome::of(&checks)
}

async fn check_photo(
    bot: &Bot,
    photo: &PhotoSize,
    links: &LinkChecker,
) -> anyhow::Result<Vec<Check>> {
    anyhow::ensure!(photo.file.size <= MAX_PHOTO_BYTES, "photo too large");

    let file = bot.get_file(photo.file.id.clone()).await?;
    let mut bytes = Vec::new();
    bot.download_file(&file.path, &mut bytes).await?;

    let payloads = tokio::task::spawn_blocking(move || khqr::payloads_from_image(&bytes)).await?;
    Ok(join_all(
        payloads
            .iter()
            .map(|payload| analyzers::check_qr_payload(payload, links)),
    )
    .await)
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
