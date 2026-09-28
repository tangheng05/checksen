mod analyzers;
mod bot;
mod verdict;

use teloxide::Bot;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tracing::info!("starting CheckSen");

    teloxide::repl(Bot::from_env(), bot::handle).await;
}
