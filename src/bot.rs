use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::PhotoSize;

use crate::analyzers::khqr::{self, KhqrCheck};
use crate::verdict;

const MAX_PHOTO_BYTES: u32 = 10 * 1024 * 1024;

pub async fn handle(bot: Bot, msg: Message) -> ResponseResult<()> {
    let largest_photo = msg
        .photo()
        .and_then(|sizes| sizes.iter().max_by_key(|size| size.width * size.height));

    let reply = if let Some(photo) = largest_photo {
        let checks = check_photo(&bot, photo).await.unwrap_or_else(|error| {
            tracing::warn!(%error, "photo check failed");
            Vec::new()
        });
        verdict::render_km(&checks)
    } else if let Some(payload) = msg.text().filter(|text| khqr::looks_like_khqr(text)) {
        verdict::render_km(&[khqr::check(payload)])
    } else {
        verdict::HELP_KM.to_owned()
    };

    bot.send_message(msg.chat.id, reply).await?;
    Ok(())
}

async fn check_photo(bot: &Bot, photo: &PhotoSize) -> anyhow::Result<Vec<KhqrCheck>> {
    anyhow::ensure!(photo.file.size <= MAX_PHOTO_BYTES, "photo too large");

    let file = bot.get_file(photo.file.id.clone()).await?;
    let mut bytes = Vec::new();
    bot.download_file(&file.path, &mut bytes).await?;

    let payloads = tokio::task::spawn_blocking(move || khqr::payloads_from_image(&bytes)).await?;
    Ok(payloads
        .iter()
        .map(|payload| khqr::check(payload))
        .collect())
}
