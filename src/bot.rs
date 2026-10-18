use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{
    ChatAction, Document, FileId, Me, MessageEntityKind, MessageOrigin, ParseMode, PhotoSize,
    ReplyParameters,
};
use url::Url;

use checksen::analyzers::file::{self, Content, FileKind, Scans, Unread};
use checksen::analyzers::intent::{self, Intent};
use checksen::analyzers::link::{self, LinkChecker};
use checksen::analyzers::llm::{self, Classifier, MessageKind, Reading, Transcriber};
use checksen::analyzers::scan::{ClamAv, VirusTotalClient};
use checksen::analyzers::text::RULES_VERSION;
use checksen::analyzers::{self, Check, Signal, Subject, khqr, text};
use checksen::verdict::{self, Lang, Level, Text};

use crate::guard::{Admission, Guard, ModelCall, Reply};
use crate::reports;
use crate::store::Store;

const MAX_PHOTO_BYTES: u32 = 10 * 1024 * 1024;
// The most a bot may download from Telegram.
const MAX_FILE_BYTES: u32 = 20 * 1024 * 1024;
const CLAMAV_BUDGET: Duration = Duration::from_secs(15);
const VIRUSTOTAL_BUDGET: Duration = Duration::from_secs(6);
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
    pub clamav: Option<ClamAv>,
    pub virustotal: Option<VirusTotalClient>,
}

enum Body {
    Checks(Vec<Check>),
    Text(String),
}

struct Outcome {
    body: Body,
    /// Fixed advice shown above the verdict, for people who were already scammed.
    preface: Option<&'static str>,
    cacheable: bool,
}

impl Outcome {
    fn of(checks: Vec<Check>) -> Self {
        let cacheable = !checks.iter().any(|check| {
            check.signals.contains(&Signal::ModelUnavailable)
                || matches!(check.subject, Subject::Link(_))
        });
        Self {
            body: Body::Checks(checks),
            preface: None,
            cacheable,
        }
    }

    fn text(text: impl Into<String>, cacheable: bool) -> Self {
        Self {
            body: Body::Text(text.into()),
            preface: None,
            cacheable,
        }
    }

    fn finish(self, about: verdict::About, lang: Lang) -> (Reply, bool) {
        let reply = match self.body {
            Body::Text(text) => Reply {
                text,
                account: None,
                html: false,
            },
            Body::Checks(checks) => {
                let mut payees = checks.iter().filter_map(|check| match &check.subject {
                    Subject::Khqr(payee) => Some(payee.bakong_account_id.clone()),
                    _ => None,
                });
                let account = match (payees.next(), payees.next()) {
                    (Some(account), None) => Some(account),
                    _ => None,
                };
                let verdict = verdict::render(&checks, about, lang);
                let text = match self.preface {
                    Some(preface) => format!("{}\n\n{verdict}", verdict::escape(preface)),
                    None => verdict,
                };
                Reply {
                    text,
                    account,
                    html: true,
                }
            }
        };
        (reply, self.cacheable)
    }
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
            let (reply, cacheable) = check(&bot, target, lang, &services).await;
            typing.abort();
            let reply = Arc::new(reply);
            if cacheable {
                guard.store(key, reply.clone());
            }
            reply
        }
    };

    let keyboard = reports::keyboard(services.store.as_deref(), reply.account.as_deref(), lang);
    let mut request = answer(&bot, target, reply.text.as_str());
    if reply.html {
        request = request.parse_mode(ParseMode::Html);
    }
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
    let typed = msg
        .text()
        .or(msg.caption())
        .filter(|text| msg.forward_origin().is_none() && !text.starts_with('/'))
        .and_then(Lang::of);
    guard.language(sender, typed)
}

fn largest_photo(msg: &Message) -> Option<&PhotoSize> {
    msg.photo()
        .and_then(|sizes| sizes.iter().max_by_key(|size| size.width * size.height))
}

fn cache_key(guard: &Guard, msg: &Message, lang: Lang) -> Option<u64> {
    let urls: Vec<String> = urls_in(msg).iter().map(Url::to_string).collect();
    let caption = (msg.caption().unwrap_or_default(), forwarded_from(msg));
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
        return Some(guard.key((RULES_VERSION, lang, "text", message, urls, caption)));
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

async fn check(bot: &Bot, msg: &Message, lang: Lang, services: &Services) -> (Reply, bool) {
    let (outcome, kind) = if let Some(photo) = largest_photo(msg) {
        check_photo(bot, msg, photo, lang, services).await
    } else if let Some(payload) = msg.text().filter(|text| khqr::looks_like_khqr(text)) {
        let checks = vec![khqr::check(payload)];
        let checks = reports::with_reports(checks, services.store.as_deref()).await;
        (Outcome::of(checks), None)
    } else if let Some(message) = msg.text() {
        check_text(msg, message, lang, services).await
    } else if let Some(document) = msg.document() {
        check_document(bot, msg, document, lang, services).await
    } else {
        (Outcome::of(Vec::new()), None)
    };
    let forwarded_from = forwarded_from(msg);
    let about = verdict::About {
        forwarded_from: forwarded_from.as_deref(),
        kind,
    };
    outcome.finish(about, lang)
}

fn forwarded_from(msg: &Message) -> Option<String> {
    match msg.forward_origin()? {
        MessageOrigin::User { sender_user, .. } => Some(sender_user.full_name()),
        MessageOrigin::HiddenUser {
            sender_user_name, ..
        } => Some(sender_user_name.clone()),
        MessageOrigin::Chat { sender_chat, .. } => sender_chat.title().map(str::to_owned),
        MessageOrigin::Channel { chat, .. } => chat.title().map(str::to_owned),
    }
}

async fn check_text(
    msg: &Message,
    message: &str,
    lang: Lang,
    services: &Services,
) -> (Outcome, Option<MessageKind>) {
    let urls = urls_in(msg);
    let rules = intent::detect(message);
    if urls.is_empty() {
        if let Some(intent @ (Intent::Greeting | Intent::Thanks)) = rules
            && let Some(answer) = verdict::answer(intent, lang)
        {
            return (Outcome::text(answer, true), None);
        }
        if message.chars().count() < MIN_TEXT_CHARS && text::check(message).signals.is_empty() {
            let answer = rules.and_then(|intent| verdict::answer(intent, lang));
            return (
                Outcome::text(answer.unwrap_or(verdict::HELP.get(lang)), true),
                None,
            );
        }
    }

    let has_links = !urls.is_empty();
    let (checks, reading) =
        text_checks(message, urls, !has_links, services, CLASSIFIER_BUDGET).await;
    let intent = intent::decide(rules, reading.intent, message);
    let flagged = has_links
        || checks
            .iter()
            .any(|check| verdict::decide(check) != Level::NoKnownSignals);
    let verdict = Outcome::of(checks);
    let outcome = match verdict::answer(intent, lang) {
        Some(answer) if intent == Intent::AlreadyScammed && flagged => Outcome {
            preface: Some(answer),
            ..verdict
        },
        Some(answer) if !flagged => Outcome::text(answer, verdict.cacheable),
        _ => verdict,
    };
    (outcome, reading.kind)
}

/// The text check is always shown when `show_text` is set, otherwise only when it found something.
async fn text_checks(
    message: &str,
    urls: Vec<Url>,
    show_text: bool,
    services: &Services,
    budget: Duration,
) -> (Vec<Check>, Reading) {
    let text_check = text::check(message);
    // A bare link is covered by the link check; the model only sees real text.
    let classify = prose_chars(message) >= MIN_TEXT_CHARS || !text_check.signals.is_empty();
    let ((text_check, reading), link_checks) = tokio::join!(
        async {
            if classify {
                classify_text(text_check, message, services, budget).await
            } else {
                (text_check, Reading::default())
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
    (checks, reading)
}

async fn classify_text(
    mut text_check: Check,
    message: &str,
    services: &Services,
    budget: Duration,
) -> (Check, Reading) {
    match services.classifier.as_deref() {
        Some(classifier) if services.guard.allow_model_call(ModelCall::Text) => {
            llm::classify(text_check, message, classifier, budget).await
        }
        Some(_) => {
            tracing::warn!("daily classifier budget used up");
            text_check.signals.push(Signal::ModelUnavailable);
            (text_check, Reading::default())
        }
        None => (text_check, Reading::default()),
    }
}

async fn download_photo(bot: &Bot, photo: &PhotoSize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(photo.file.size <= MAX_PHOTO_BYTES, "photo too large");
    download(bot, &photo.file.id).await
}

async fn check_document(
    bot: &Bot,
    msg: &Message,
    document: &Document,
    lang: Lang,
    services: &Services,
) -> (Outcome, Option<MessageKind>) {
    let name = document.file_name.as_deref().unwrap_or_default();
    let mime = document.mime_type.as_ref().map(|mime| mime.essence_str());
    let bytes = if document.file.size <= MAX_FILE_BYTES {
        download(bot, &document.file.id)
            .await
            .map_err(|error| tracing::warn!(%error, "file download failed"))
            .map_err(|()| Unread::DownloadFailed)
    } else {
        Err(Unread::TooBig)
    };

    // Screenshots and KHQR codes are often sent uncompressed, as files.
    if let Ok(image) = &bytes
        && image.len() <= MAX_PHOTO_BYTES as usize
        && file::kind_from_bytes(image) == Some(FileKind::Image)
    {
        let file_check = file::inspect(name, mime, Content::Bytes(image), Scans::default());
        let (mut outcome, kind) = check_image(image.clone(), msg, lang, services).await;
        if !file_check.signals.is_empty()
            && let Body::Checks(checks) = &mut outcome.body
        {
            checks.push(file_check);
        }
        return (outcome, kind);
    }

    let (content, (scans, scanned)) = match &bytes {
        Ok(bytes) => (Content::Bytes(bytes), scan(bytes, services).await),
        Err(why) => (
            Content::Unread(*why),
            (Scans::default(), *why == Unread::TooBig),
        ),
    };
    let mut checks = vec![file::inspect(name, mime, content, scans)];
    if let Some(caption) = msg.caption() {
        let (caption_checks, _) =
            text_checks(caption, urls_in(msg), false, services, CLASSIFIER_BUDGET).await;
        checks.extend(caption_checks);
    }
    let outcome = Outcome::of(checks);
    let cacheable = outcome.cacheable && scanned;
    (
        Outcome {
            cacheable,
            ..outcome
        },
        None,
    )
}

/// Runs the configured antivirus checks; the flag is false when one of them failed.
async fn scan(bytes: &[u8], services: &Services) -> (Scans, bool) {
    let clamav = async {
        let clamav = services.clamav.as_ref()?;
        match tokio::time::timeout(CLAMAV_BUDGET, clamav.is_clean(bytes)).await {
            Ok(Ok(clean)) => Some(Ok(clean)),
            Ok(Err(error)) => {
                tracing::warn!(%error, "ClamAV scan failed");
                Some(Err(()))
            }
            Err(_) => {
                tracing::warn!("ClamAV scan timed out");
                Some(Err(()))
            }
        }
    };
    let virustotal = async {
        let virustotal = services.virustotal.as_ref()?;
        if !services.guard.allow_model_call(ModelCall::FileLookup) {
            tracing::warn!("daily VirusTotal budget used up");
            return Some(Err(()));
        }
        match tokio::time::timeout(VIRUSTOTAL_BUDGET, virustotal.lookup(bytes)).await {
            Ok(Ok(report)) => Some(Ok(report)),
            Ok(Err(error)) => {
                tracing::warn!(%error, "VirusTotal lookup failed");
                Some(Err(()))
            }
            Err(_) => {
                tracing::warn!("VirusTotal lookup timed out");
                Some(Err(()))
            }
        }
    };
    let (clamav, virustotal) = tokio::join!(clamav, virustotal);
    let scanned = !matches!(clamav, Some(Err(()))) && !matches!(virustotal, Some(Err(())));
    let scans = Scans {
        clamav_clean: clamav.and_then(Result::ok),
        virustotal: virustotal.and_then(Result::ok),
    };
    (scans, scanned)
}

async fn download(bot: &Bot, id: &FileId) -> anyhow::Result<Vec<u8>> {
    let file = bot.get_file(id.clone()).await?;
    let mut bytes = Vec::new();
    bot.download_file(&file.path, &mut bytes).await?;
    Ok(bytes)
}

async fn check_photo(
    bot: &Bot,
    msg: &Message,
    photo: &PhotoSize,
    lang: Lang,
    services: &Services,
) -> (Outcome, Option<MessageKind>) {
    match download_photo(bot, photo).await {
        Ok(image) => check_image(image, msg, lang, services).await,
        Err(error) => {
            tracing::warn!(%error, "photo download failed");
            let failed = Outcome::text(verdict::no_qr_found(lang), false);
            caption_or(msg, services, failed).await
        }
    }
}

/// The text in the image and the caption are checked together, as one message.
async fn check_image(
    image: Vec<u8>,
    msg: &Message,
    lang: Lang,
    services: &Services,
) -> (Outcome, Option<MessageKind>) {
    let caption = msg.caption();
    let failed = || Outcome::text(verdict::no_qr_found(lang), false);
    let decoded = tokio::task::spawn_blocking(move || {
        let payloads = khqr::payloads_from_image(&image);
        (image, payloads)
    })
    .await;
    let (image, payloads) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => {
            tracing::warn!(%error, "QR decoding failed");
            return caption_or(msg, services, failed()).await;
        }
    };
    if !payloads.is_empty() {
        let checks = join_all(
            payloads
                .iter()
                .map(|payload| analyzers::check_qr_payload(payload, &services.links)),
        )
        .await;
        let mut checks = reports::with_reports(checks, services.store.as_deref()).await;
        if let Some(caption) = caption {
            let (caption_checks, _) =
                text_checks(caption, urls_in(msg), false, services, CLASSIFIER_BUDGET).await;
            checks.extend(caption_checks);
        }
        return (Outcome::of(checks), None);
    }

    let Some(transcriber) = services.transcriber.as_deref() else {
        return caption_or(msg, services, Outcome::of(Vec::new())).await;
    };
    let unread = || Outcome::text(verdict::screenshot_unread(lang), false);
    if !services.guard.allow_model_call(ModelCall::Screenshot) {
        tracing::warn!("daily screenshot budget used up");
        return caption_or(msg, services, unread()).await;
    }
    match llm::transcribe(&image, transcriber, TRANSCRIBE_BUDGET).await {
        Ok(Some(transcript)) => {
            let message = match caption {
                Some(caption) => format!("{caption}\n\n{transcript}"),
                None => transcript,
            };
            let urls = urls_in(msg);
            let show_text = urls.is_empty();
            let (checks, reading) = text_checks(
                &message,
                urls,
                show_text,
                services,
                SCREENSHOT_CLASSIFIER_BUDGET,
            )
            .await;
            (Outcome::of(checks), reading.kind)
        }
        Ok(None) => {
            let nothing = Outcome::text(verdict::NOTHING_IN_PHOTO.get(lang), true);
            caption_or(msg, services, nothing).await
        }
        Err(error) => {
            tracing::warn!(%error, "screenshot transcription failed");
            caption_or(msg, services, unread()).await
        }
    }
}

/// Checks the caption when the image itself gave nothing, otherwise replies with `fallback`.
async fn caption_or(
    msg: &Message,
    services: &Services,
    fallback: Outcome,
) -> (Outcome, Option<MessageKind>) {
    let Some(caption) = msg.caption() else {
        return (fallback, None);
    };
    let urls = urls_in(msg);
    let show_text = urls.is_empty();
    let (checks, reading) =
        text_checks(caption, urls, show_text, services, CLASSIFIER_BUDGET).await;
    let outcome = Outcome::of(checks);
    let cacheable = outcome.cacheable && fallback.cacheable;
    (
        Outcome {
            cacheable,
            ..outcome
        },
        reading.kind,
    )
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
        // One link per site, so a different site further down still gets checked.
        if let Some(url) = url.filter(|url| urls.iter().all(|seen| seen.host() != url.host())) {
            urls.push(url);
        }
    }
    urls.truncate(MAX_LINKS_PER_MESSAGE);
    urls
}

fn prose_chars(message: &str) -> usize {
    message
        .split_whitespace()
        .filter(|word| !(word.contains('.') && url_from_entity_text(word).is_some()))
        .map(|word| word.chars().count() + 1)
        .sum()
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
    fn links_alone_are_not_prose() {
        assert_eq!(prose_chars("https://github.com/tangheng05/checksen"), 0);
        assert_eq!(prose_chars("github.com/tangheng05"), 0);
        assert!(
            prose_chars("Your ABA account is locked, verify at aba-help.top now") >= MIN_TEXT_CHARS
        );
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
