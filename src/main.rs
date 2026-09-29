mod bot;

use std::sync::Arc;
use std::time::Duration;

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
        Bot::from_env(),
        Update::filter_message().endpoint(bot::handle),
    )
    .dependencies(dptree::deps![links, classifier])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
    Ok(())
}
