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
use checksen::env_var;
use teloxide::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tracing::info!("starting CheckSen");

    let links = Arc::new(LinkChecker::new()?);
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

    Dispatcher::builder(
        Bot::new(env_var("TELOXIDE_TOKEN").context("set TELOXIDE_TOKEN (see .env.example)")?),
        dptree::entry()
            .branch(Update::filter_message().endpoint(bot::handle))
            .branch(Update::filter_callback_query().endpoint(reports::handle_callback)),
    )
    .dependencies(dptree::deps![
        links,
        classifier,
        transcriber,
        Arc::new(guard::Guard::new()),
        store
    ])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
    Ok(())
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
