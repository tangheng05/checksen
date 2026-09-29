mod bot;
mod guard;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use checksen::analyzers::link::LinkChecker;
use checksen::analyzers::llm::anthropic::AnthropicClassifier;
use teloxide::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tracing::info!("starting CheckSen");

    let links = Arc::new(LinkChecker::new()?);
    let classifier = AnthropicClassifier::from_env(Duration::from_secs(3), 2)?.map(Arc::new);
    if classifier.is_none() {
        tracing::warn!("ANTHROPIC_API_KEY is not set; text checks use rules only");
    }
    Dispatcher::builder(
        Bot::new(std::env::var("TELOXIDE_TOKEN").context("set TELOXIDE_TOKEN (see .env.example)")?),
        Update::filter_message().endpoint(bot::handle),
    )
    .dependencies(dptree::deps![
        links,
        classifier,
        Arc::new(guard::Guard::new())
    ])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
    Ok(())
}
