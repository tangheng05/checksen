mod bot;
mod guard;
mod reports;
mod store;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

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
    let links = Arc::new(LinkChecker::new()?.with_safe_browsing(safe_browsing));
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

    let bot = Bot::new(env_var("TELOXIDE_TOKEN").context("set TELOXIDE_TOKEN (see .env.example)")?);
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
    });

    Dispatcher::builder(
        bot,
        dptree::entry()
            .branch(Update::filter_message().endpoint(bot::handle))
            .branch(Update::filter_callback_query().endpoint(reports::handle_callback)),
    )
    .dependencies(dptree::deps![services, store])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
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
