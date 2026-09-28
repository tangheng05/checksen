# Khmer Scam Shield

A Telegram bot for people in Cambodia. Forward it a suspicious message, link, KHQR code or screenshot, and it replies in Khmer within seconds with a risk level and the reasons behind it.

> **Status:** early development. Nothing is running yet. The public beta is planned for November 2026.

## What it checks

| You send | It checks |
| --- | --- |
| A KHQR code (photo or screenshot) | Who the QR really pays: merchant name, account, bank and amount, and whether the code is valid KHQR |
| A link | Where it redirects, how new the domain is, known-bad lists, and lookalikes of bank and government domains |
| A text message | Common scam patterns such as OTP requests, upfront fees for jobs or loans, and scripts others have already reported |
| A screenshot | Reads the text, QR codes and links in it, then checks each of them as above |

Each reply gives one of four levels: **High risk**, **Suspicious**, **No known risk signals** or **Can't tell**. The bot never says a message is "safe". Every reply reminds you to check in your own bank app before paying.

## How it works

- Fixed rules come first: QR parsing and checksum validation (via [khqr-rs](https://github.com/tangheng05/khqr-rs)), domain age, blocklists and known scam scripts.
- A language model classifies what the rules can't decide and writes the explanation in Khmer. It can't raise a verdict to High risk without evidence it can point to.
- A labeled benchmark of Khmer and English scam messages is checked in CI, so a change that lowers detection or flags more legitimate messages can't be merged.

## Privacy

- Images are never saved, and message text is deleted within 24 hours. What's kept is the verdict and any scam indicators found (links, domains, account IDs).
- Telegram user IDs are stored only as keyed hashes.
- `/forget` deletes everything linked to you.
- Example messages are kept only if you choose to donate them.

## Stack

Rust, [teloxide](https://docs.rs/teloxide/), axum, PostgreSQL with sqlx, Claude and Google Web Risk.

## License

MIT. See [LICENSE](LICENSE).
