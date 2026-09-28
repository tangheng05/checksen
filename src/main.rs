mod analyzers;
mod bot;
mod verdict;

use std::sync::Arc;

use analyzers::link::LinkChecker;
use teloxide::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tracing::info!("starting CheckSen");

    let links = Arc::new(LinkChecker::new()?);
    Dispatcher::builder(
        Bot::from_env(),
        Update::filter_message().endpoint(bot::handle),
    )
    .dependencies(dptree::deps![links])
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;
    Ok(())
}
