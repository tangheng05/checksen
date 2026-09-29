mod bot;
mod guard;
mod reports;
mod store;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use checksen::analyzers::link::LinkChecker;
use checksen::analyzers::llm::anthropic::AnthropicClassifier;
use checksen::env_var;
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
        Arc::new(guard::Guard::new()),
        store
    ])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
    Ok(())
}
