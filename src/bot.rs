use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{ChatAction, Me, MessageEntityKind, PhotoSize, ReplyParameters};
use url::Url;

use checksen::analyzers::link::{self, LinkChecker};
use checksen::analyzers::llm::{self, Classifier, Transcriber};
use checksen::analyzers::text::RULES_VERSION;
use checksen::analyzers::{self, Check, Signal, Subject, khqr, text};
use checksen::verdict::{self, Lang, Text};

use crate::guard::{Admission, Guard, ModelCall, Reply};
use crate::reports;
use crate::store::Store;

const MAX_PHOTO_BYTES: u32 = 10 * 1024 * 1024;
const MAX_LINKS_PER_MESSAGE: usize = 3;
const MIN_TEXT_CHARS: usize = 20;
const CLASSIFIER_BUDGET: Duration = Duration::from_secs(5);
const SCREENSHOT_CLASSIFIER_BUDGET: Duration = Duration::from_secs(10);
const TRANSCRIBE_BUDGET: Duration = Duration::from_secs(20);
const TYPING_EVERY: Duration = Duration::from_secs(4);

pub struct Services {
    pub links: Arc<LinkChecker>,
    pub classifier: Option<Arc<dyn Classifier>>,
    pub transcriber: Option<Arc<dyn Transcriber>>,
    pub guard: Arc<Guard>,
    pub store: Option<Arc<Store>>,
}

struct Outcome {
    reply: Reply,
    cacheable: bool,
}

impl Outcome {
    fn of(checks: &[Check], lang: Lang) -> Self {
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
                text: verdict::render(checks, lang),
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

enum Photo {
    Checks(Vec<Check>),
    Unread,
    Failed,
}

pub async fn handle(bot: Bot, msg: Message, me: Me, services: Arc<Services>) -> ResponseResult<()> {
    let command = command(&msg, &me);
    let Some(target) = target(&msg, &me, command) else {
        return Ok(());
    };
    let guard = &services.guard;
    let sender = msg
        .from
        .as_ref()
        .map_or(msg.chat.id.0 as u64, |user| user.id.0);
    let lang = language(guard, sender, target);

    let fixed = match command {
        Some("forget") => {
            let user = msg.from.as_ref();
            let reply = reports::forget_reply(services.store.as_deref(), user, lang).await;
            answer(&bot, target, reply).await?;
            return Ok(());
        }
        Some("start") => Some(&verdict::WELCOME),
        Some("help") => Some(&verdict::HELP),
        _ => fixed_reply(target),
    };
    if let Some(text) = fixed {
        answer(&bot, target, text.get(lang)).await?;
        return Ok(());
    }
    let Some(key) = cache_key(guard, target, lang) else {
        answer(&bot, target, verdict::HELP.get(lang)).await?;
        return Ok(());
    };

    match guard.admit(sender) {
        Admission::Allowed => {}
        Admission::LimitReached => {
            answer(&bot, target, verdict::RATE_LIMITED.get(lang)).await?;
            return Ok(());
        }
        Admission::Silent => return Ok(()),
    }

    let reply = match guard.cached(key) {
        Some(reply) => reply,
        None => {
            let typing = tokio::spawn(keep_typing(bot.clone(), msg.chat.id));
            let outcome = check(&bot, target, lang, &services).await;
            typing.abort();
            let reply = Arc::new(outcome.reply);
            if outcome.cacheable {
                guard.store(key, reply.clone());
            }
            reply
        }
    };

    let keyboard = reports::keyboard(services.store.as_deref(), reply.account.as_deref(), lang);
    let request = answer(&bot, target, reply.text.as_str());
    match keyboard {
        Some(keyboard) => request.reply_markup(keyboard).await?,
        None => request.await?,
    };
    Ok(())
}

fn answer(bot: &Bot, to: &Message, text: impl Into<String>) -> <Bot as Requester>::SendMessage {
    bot.send_message(to.chat.id, text)
        .reply_parameters(ReplyParameters::new(to.id).allow_sending_without_reply())
}

async fn keep_typing(bot: Bot, chat: ChatId) {
    loop {
        if let Err(error) = bot.send_chat_action(chat, ChatAction::Typing).await {
            tracing::debug!(%error, "typing action failed");
        }
        tokio::time::sleep(TYPING_EVERY).await;
    }
}

/// A command meant for this bot, without the slash or the @username suffix.
fn command<'a>(msg: &'a Message, me: &Me) -> Option<&'a str> {
    let word = msg.text()?.strip_prefix('/')?.split_whitespace().next()?;
    match word.split_once('@') {
        Some((name, bot)) if bot.eq_ignore_ascii_case(me.username()) => Some(name),
        Some(_) => None,
        None => Some(word),
    }
}

/// In groups the bot only answers when asked, so it never replies to every message.
fn target<'a>(msg: &'a Message, me: &Me, command: Option<&str>) -> Option<&'a Message> {
    let asked = command.is_some() || mentions(msg, me);
    if asked
        && matches!(command, None | Some("check"))
        && let Some(replied) = msg.reply_to_message()
    {
        return Some(replied);
    }
    let replies_to_bot = msg
        .reply_to_message()
        .and_then(|replied| replied.from.as_ref())
        .is_some_and(|user| user.id == me.id);
    (msg.chat.is_private() || asked || replies_to_bot).then_some(msg)
}

fn mentions(msg: &Message, me: &Me) -> bool {
    entities(msg).iter().any(|entity| {
        matches!(entity.kind(), MessageEntityKind::Mention)
            && entity
                .text()
                .strip_prefix('@')
                .is_some_and(|name| name.eq_ignore_ascii_case(me.username()))
    })
}

fn fixed_reply(msg: &Message) -> Option<&'static Text> {
    if msg.voice().is_some()
        || msg.audio().is_some()
        || msg.video().is_some()
        || msg.video_note().is_some()
    {
        Some(&verdict::CANT_LISTEN)
    } else if msg.sticker().is_some() || msg.animation().is_some() {
        Some(&verdict::GREETING)
    } else if msg.contact().is_some() {
        Some(&verdict::ABOUT_CONTACT)
    } else if msg.location().is_some() || msg.venue().is_some() {
        Some(&verdict::NOTHING_TO_CHECK)
    } else {
        None
    }
}

fn language(guard: &Guard, sender: u64, msg: &Message) -> Lang {
    let written = msg
        .text()
        .or(msg.caption())
        .filter(|text| !text.starts_with('/'))
        .and_then(Lang::of);
    if msg.forward_origin().is_some() {
        guard.language(sender, None, written)
    } else {
        guard.language(sender, written, None)
    }
}

fn largest_photo(msg: &Message) -> Option<&PhotoSize> {
    msg.photo()
        .and_then(|sizes| sizes.iter().max_by_key(|size| size.width * size.height))
}

fn cache_key(guard: &Guard, msg: &Message, lang: Lang) -> Option<u64> {
    let urls: Vec<String> = urls_in(msg).iter().map(Url::to_string).collect();
    let caption = msg.caption().unwrap_or_default();
    if let Some(photo) = largest_photo(msg) {
        return Some(guard.key((
            RULES_VERSION,
            lang,
            "photo",
            &photo.file.unique_id.0,
            caption,
            urls,
        )));
    }
    if let Some(message) = msg.text().filter(|text| !text.starts_with('/')) {
        return Some(guard.key((RULES_VERSION, lang, "text", message, urls)));
    }
    msg.document().map(|document| {
        guard.key((
            RULES_VERSION,
            lang,
            "document",
            &document.file.unique_id.0,
            caption,
            urls,
        ))
    })
}

async fn check(bot: &Bot, msg: &Message, lang: Lang, services: &Services) -> Outcome {
    if let Some(photo) = largest_photo(msg) {
        let (photo, caption) = tokio::join!(
            check_photo(bot, photo, services),
            caption_checks(msg, services)
        );
        return combine(photo, caption, lang);
    }
    if let Some(payload) = msg.text().filter(|text| khqr::looks_like_khqr(text)) {
        let checks = vec![khqr::check(payload)];
        return Outcome::of(
            &reports::with_reports(checks, services.store.as_deref()).await,
            lang,
        );
    }
    if let Some(message) = msg.text() {
        return check_text(msg, message, lang, services).await;
    }
    let file_name = msg
        .document()
        .and_then(|document| document.file_name.as_deref())
        .unwrap_or_default();
    let described = format!("{file_name} {}", msg.caption().unwrap_or_default());
    let mut checks = vec![text::check(&described)];
    checks.extend(
        join_all(
            urls_in(msg)
                .into_iter()
                .map(|url| services.links.check(url)),
        )
        .await,
    );
    Outcome::of(&checks, lang)
}

fn combine(photo: Photo, mut caption: Vec<Check>, lang: Lang) -> Outcome {
    match photo {
        Photo::Checks(checks) if checks.is_empty() && !caption.is_empty() => {
            Outcome::of(&caption, lang)
        }
        Photo::Checks(mut checks) => {
            checks.append(&mut caption);
            Outcome::of(&checks, lang)
        }
        Photo::Unread if caption.is_empty() => {
            Outcome::text(verdict::screenshot_unread(lang), false)
        }
        Photo::Failed if caption.is_empty() => Outcome::text(verdict::render(&[], lang), false),
        Photo::Unread | Photo::Failed => Outcome {
            cacheable: false,
            ..Outcome::of(&caption, lang)
        },
    }
}

async fn check_text(msg: &Message, message: &str, lang: Lang, services: &Services) -> Outcome {
    let urls = urls_in(msg);
    if urls.is_empty()
        && message.chars().count() < MIN_TEXT_CHARS
        && text::check(message).signals.is_empty()
    {
        return Outcome::text(verdict::HELP.get(lang), true);
    }
    let show_text = urls.is_empty();
    Outcome::of(&text_checks(message, urls, show_text, services).await, lang)
}

async fn caption_checks(msg: &Message, services: &Services) -> Vec<Check> {
    match msg.caption() {
        Some(caption) => text_checks(caption, urls_in(msg), false, services).await,
        None => Vec::new(),
    }
}

/// The text check is always shown when `show_text` is set, otherwise only when it found something.
async fn text_checks(
    message: &str,
    urls: Vec<Url>,
    show_text: bool,
    services: &Services,
) -> Vec<Check> {
    let text_check = text::check(message);
    let classify = message.chars().count() >= MIN_TEXT_CHARS || !text_check.signals.is_empty();
    let (text_check, link_checks) = tokio::join!(
        async {
            if classify {
                classify_text(text_check, message, services, CLASSIFIER_BUDGET).await
            } else {
                text_check
            }
        },
        join_all(urls.into_iter().map(|url| services.links.check(url)))
    );

    let mut checks = Vec::new();
    if show_text
        || text_check
            .signals
            .iter()
            .any(|signal| signal.weight() > 0.0)
    {
        checks.push(text_check);
    }
    checks.extend(link_checks);
    checks
}

async fn classify_text(
    mut text_check: Check,
    message: &str,
    services: &Services,
    budget: Duration,
) -> Check {
    match services.classifier.as_deref() {
        Some(classifier) if services.guard.allow_model_call(ModelCall::Text) => {
            llm::classify(text_check, message, classifier, budget).await
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

async fn check_photo(bot: &Bot, photo: &PhotoSize, services: &Services) -> Photo {
    let image = match download_photo(bot, photo).await {
        Ok(image) => image,
        Err(error) => {
            tracing::warn!(%error, "photo download failed");
            return Photo::Failed;
        }
    };
    let decoded = tokio::task::spawn_blocking(move || {
        let payloads = khqr::payloads_from_image(&image);
        (image, payloads)
    })
    .await;
    let (image, payloads) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            tracing::warn!(%error, "QR decoding failed");
            return Photo::Failed;
        }
    };
    if !payloads.is_empty() {
        let checks = join_all(
            payloads
                .iter()
                .map(|payload| analyzers::check_qr_payload(payload, &services.links)),
        )
        .await;
        return Photo::Checks(reports::with_reports(checks, services.store.as_deref()).await);
    }

    let Some(transcriber) = services.transcriber.as_deref() else {
        return Photo::Checks(Vec::new());
    };
    if !services.guard.allow_model_call(ModelCall::Screenshot) {
        tracing::warn!("daily screenshot budget used up");
        return Photo::Unread;
    }
    match llm::transcribe(&image, transcriber, TRANSCRIBE_BUDGET).await {
        Ok(Some(transcript)) => {
            let check = classify_text(
                text::check(&transcript),
                &transcript,
                services,
                SCREENSHOT_CLASSIFIER_BUDGET,
            )
            .await;
            Photo::Checks(vec![check])
        }
        Ok(None) => Photo::Checks(Vec::new()),
        Err(error) => {
            tracing::warn!(%error, "screenshot transcription failed");
            Photo::Unread
        }
    }
}

fn entities(msg: &Message) -> Vec<teloxide::types::MessageEntityRef<'_>> {
    msg.parse_entities()
        .or_else(|| msg.parse_caption_entities())
        .unwrap_or_default()
}

fn urls_in(msg: &Message) -> Vec<Url> {
    let mut urls: Vec<Url> = Vec::new();
    for entity in entities(msg) {
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

    fn me() -> Me {
        serde_json::from_value(serde_json::json!({
            "id": 99, "is_bot": true, "first_name": "CheckSen", "username": "CheckSen_bot",
            "can_join_groups": true, "can_read_all_group_messages": false,
            "supports_inline_queries": false, "can_connect_to_business": false,
            "has_main_web_app": false
        }))
        .unwrap()
    }

    fn message(chat: &str, text: &str, reply_to: Option<serde_json::Value>) -> Message {
        let mut json = serde_json::json!({
            "message_id": 2, "date": 0,
            "chat": {"id": -5, "type": chat, "title": "Family"},
            "from": {"id": 7, "is_bot": false, "first_name": "Sok"},
            "text": text,
        });
        if let Some(reply_to) = reply_to {
            json["reply_to_message"] = reply_to;
        }
        if chat == "private" {
            json["chat"] = serde_json::json!({"id": 7, "type": "private", "first_name": "Sok"});
        }
        if let Some(offset) = text.find("@CheckSen_bot") {
            json["entities"] =
                serde_json::json!([{"type": "mention", "offset": offset, "length": 13}]);
        }
        serde_json::from_value(json).unwrap()
    }

    fn scam_message(from_bot: bool) -> serde_json::Value {
        serde_json::json!({
            "message_id": 1, "date": 0,
            "chat": {"id": -5, "type": "group", "title": "Family"},
            "from": {"id": if from_bot { 99 } else { 8 }, "is_bot": from_bot, "first_name": "Dara"},
            "text": "Send me the OTP code now",
        })
    }

    fn target_id(msg: &Message) -> Option<i32> {
        let me = me();
        target(msg, &me, command(msg, &me)).map(|target| target.id.0)
    }

    #[test]
    fn commands_for_other_bots_are_ignored() {
        let me = me();
        let command_of = |text| command(&message("private", text, None), &me).map(str::to_owned);
        assert_eq!(command_of("/start").as_deref(), Some("start"));
        assert_eq!(command_of("/check@CheckSen_bot").as_deref(), Some("check"));
        assert_eq!(command_of("/start@OtherBot"), None);
        assert_eq!(command_of("hello"), None);
    }

    #[test]
    fn groups_are_answered_only_when_asked() {
        assert_eq!(target_id(&message("group", "lol", None)), None);
        assert_eq!(
            target_id(&message("group", "lol", Some(scam_message(false)))),
            None
        );
        assert_eq!(
            target_id(&message("group", "/check", Some(scam_message(false)))),
            Some(1)
        );
        assert_eq!(
            target_id(&message(
                "group",
                "@CheckSen_bot is this real?",
                Some(scam_message(false))
            )),
            Some(1)
        );
        assert_eq!(
            target_id(&message("group", "why?", Some(scam_message(true)))),
            Some(2)
        );
        assert_eq!(target_id(&message("private", "hello there", None)), Some(2));
    }

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
