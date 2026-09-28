use std::sync::Arc;

use futures::future::join_all;
use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{MessageEntityKind, PhotoSize};
use url::Url;

use checksen::analyzers::link::{self, LinkChecker};
use checksen::analyzers::{self, Check, khqr, text};
use checksen::verdict;

const MAX_PHOTO_BYTES: u32 = 10 * 1024 * 1024;
const MAX_LINKS_PER_MESSAGE: usize = 3;
const MIN_TEXT_CHARS: usize = 20;

pub async fn handle(bot: Bot, msg: Message, links: Arc<LinkChecker>) -> ResponseResult<()> {
    let largest_photo = msg
        .photo()
        .and_then(|sizes| sizes.iter().max_by_key(|size| size.width * size.height));

    let reply = if let Some(photo) = largest_photo {
        let checks = check_photo(&bot, photo, &links)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "photo check failed");
                Vec::new()
            });
        verdict::render_km(&checks)
    } else if let Some(payload) = msg.text().filter(|text| khqr::looks_like_khqr(text)) {
        verdict::render_km(&[khqr::check(payload)])
    } else if let Some(message) = msg.text().filter(|text| !text.starts_with('/')) {
        check_text(&msg, message, &links).await
    } else {
        verdict::HELP_KM.to_owned()
    };

    bot.send_message(msg.chat.id, reply).await?;
    Ok(())
}

async fn check_text(msg: &Message, message: &str, links: &LinkChecker) -> String {
    let urls = urls_in(msg);
    let text_check = text::check(message);
    let no_signals = text_check.signals.is_empty();
    if no_signals && urls.is_empty() && message.chars().count() < MIN_TEXT_CHARS {
        return verdict::HELP_KM.to_owned();
    }

    let mut checks = Vec::new();
    if !no_signals || urls.is_empty() {
        checks.push(text_check);
    }
    checks.extend(join_all(urls.into_iter().map(|url| links.check(url))).await);
    verdict::render_km(&checks)
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
