mod admin;
mod bot;
mod feedback;
mod guard;
mod reports;
mod stats;
mod store;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use checksen::analyzers::abusech::AbuseCh;
use checksen::analyzers::link::LinkChecker;
use checksen::analyzers::llm::anthropic::AnthropicClassifier;
use checksen::analyzers::llm::gemini::GeminiClassifier;
use checksen::analyzers::llm::{Classifier, Transcriber};
use checksen::analyzers::reputation::SafeBrowsing;
use checksen::analyzers::scan::{ClamAv, VirusTotalClient};
use checksen::env_var;
use teloxide::prelude::*;
use teloxide::types::BotCommand;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tracing::info!("starting CheckSen");

    let safe_browsing = SafeBrowsing::from_env(Duration::from_secs(3))?;
    if safe_browsing.is_none() {
        tracing::warn!(
            "SAFE_BROWSING_API_KEY is not set; links are not checked against Google Safe Browsing"
        );
    }
    let abusech = AbuseCh::from_env(Duration::from_secs(4))?.map(Arc::new);
    if abusech.is_none() {
        tracing::warn!(
            "ABUSECH_AUTH_KEY is not set; links and files are not looked up on URLhaus and MalwareBazaar"
        );
    }
    let links = Arc::new(
        LinkChecker::new()?
            .with_safe_browsing(safe_browsing)
            .with_abusech(abusech.clone()),
    );
    let classifier = classifier()?;
    let transcriber = GeminiClassifier::from_env(Duration::from_secs(8), 3)?
        .map(|gemini| Arc::new(gemini) as Arc<dyn Transcriber>);
    if transcriber.is_none() {
        tracing::warn!("GEMINI_API_KEY is not set; photos are checked for QR codes only");
    }
    let store = match env_var("DATABASE_URL") {
        Some(url) => {
            let secret = env_var("HASH_SECRET").context(
                "set HASH_SECRET (at least 32 random characters) when DATABASE_URL is set",
            )?;
            Some(Arc::new(store::Store::connect(&url, &secret).await?))
        }
        None => {
            tracing::warn!("DATABASE_URL is not set; KHQR report buttons are off");
            None
        }
    };

    if let Some(store) = store.clone() {
        tokio::spawn(purge_shared(store));
    }
    let stats = Arc::new(stats::Stats::default());
    if let Some(store) = store.clone() {
        tokio::spawn(stats::keep_flushing(stats.clone(), store));
    }
    let alert_channel = stats::channel_from_env()?;
    let admins = admin::Admins::from_env()?;
    anyhow::ensure!(
        admins.is_empty() || store.is_some(),
        "ADMIN_IDS needs DATABASE_URL, since reviews are saved there"
    );

    let token = env_var("TELOXIDE_TOKEN").context("set TELOXIDE_TOKEN (see .env.example)")?;
    let (bot, max_file_mb) = match env_var("TELEGRAM_API_URL") {
        Some(url) => {
            tracing::info!("using a local Bot API server; files up to 100 MB are checked");
            // It downloads the whole file before answering getFile, so allow more time.
            let client = teloxide::net::default_reqwest_settings()
                .timeout(Duration::from_secs(60))
                .build()?;
            let url = url.parse().context("TELEGRAM_API_URL is not a valid URL")?;
            (Bot::with_client(token, client).set_api_url(url), 100)
        }
        // The most a bot may download through Telegram's own servers.
        None => (Bot::new(token), 20),
    };
    register_commands(&bot).await;
    let clamav = ClamAv::from_env();
    if clamav.is_none() {
        tracing::warn!("CLAMD_ADDRESS is not set; files are not scanned with ClamAV");
    }
    let virustotal = VirusTotalClient::from_env(Duration::from_secs(5))?;
    if virustotal.is_none() {
        tracing::warn!("VIRUSTOTAL_API_KEY is not set; files are not looked up on VirusTotal");
    }
    let services = Arc::new(bot::Services {
        links,
        classifier,
        transcriber,
        guard: Arc::new(guard::Guard::new()),
        store: store.clone(),
        clamav,
        virustotal,
        abusech,
        max_file_bytes: max_file_mb * 1024 * 1024,
        big_files: tokio::sync::Semaphore::new(2),
        albums: bot::Albums::default(),
        admins,
        stats: stats.clone(),
        alert_channel,
    });
    tokio::spawn(stats::send_weekly_drafts(bot.clone(), services.clone()));

    Dispatcher::builder(
        bot,
        dptree::entry()
            .branch(Update::filter_message().endpoint(bot::handle))
            .branch(
                Update::filter_callback_query()
                    .filter(admin::is_review)
                    .endpoint(admin::handle_callback),
            )
            .branch(
                Update::filter_callback_query()
                    .filter(stats::is_post)
                    .endpoint(stats::handle_callback),
            )
            .branch(
                Update::filter_callback_query()
                    .filter(feedback::is_feedback)
                    .endpoint(feedback::handle_callback),
            )
            .branch(Update::filter_callback_query().endpoint(reports::handle_callback)),
    )
    .dependencies(dptree::deps![services, store.clone()])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
    // Counts not yet saved would be lost on a restart.
    if let Some(store) = &store {
        stats.flush(store).await;
    }
    Ok(())
}

async fn register_commands(bot: &Bot) {
    let commands = |help: &str, forget: &str| {
        vec![
            BotCommand::new("help", help),
            BotCommand::new("forget", forget),
        ]
    };
    let khmer = bot.set_my_commands(commands("របៀបប្រើ CheckSen", "លុបការរាយការណ៍របស់ខ្ញុំ"));
    let english = bot
        .set_my_commands(commands("How to use CheckSen", "Delete my reports"))
        .language_code("en");
    for result in [khmer.await, english.await] {
        if let Err(error) = result {
            tracing::warn!(%error, "could not register bot commands");
        }
    }
}

fn classifier() -> anyhow::Result<Option<Arc<dyn Classifier>>> {
    let timeout = Duration::from_secs(10);
    if let Some(classifier) = AnthropicClassifier::from_env(timeout, 2)? {
        tracing::info!("text checks use Anthropic");
        return Ok(Some(Arc::new(classifier)));
    }
    if let Some(classifier) = GeminiClassifier::from_env(timeout, 2)? {
        tracing::info!("text checks use Gemini");
        return Ok(Some(Arc::new(classifier)));
    }
    tracing::warn!(
        "neither ANTHROPIC_API_KEY nor GEMINI_API_KEY is set; text checks use rules only"
    );
    Ok(None)
}

/// Shared messages are deleted after 30 days, so check every hour.
async fn purge_shared(store: Arc<store::Store>) {
    let mut hourly = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        hourly.tick().await;
        match store.purge_shared().await {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "deleted shared messages older than 30 days"),
            Err(error) => tracing::warn!(%error, "could not delete old shared messages"),
        }
    }
}
