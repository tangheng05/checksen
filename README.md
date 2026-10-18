# CheckSen (ឆែកសិន)

"Check first": a Telegram bot for people in Cambodia. Forward it a suspicious message, link, KHQR code or screenshot, and it replies in Khmer within seconds with a risk level and the reasons behind it.

> **Status:** early development. Nothing is running yet. The public beta is planned for November 2026.

## What it checks

| You send | It checks |
| --- | --- |
| A KHQR code (photo or screenshot) | Who the QR really pays: merchant name, account, bank and amount, and whether the code is valid KHQR |
| A link | Where it redirects, how new the domain is, and lookalikes of bank, wallet, Telegram and government domains |
| A text message | Common scam patterns in Khmer and English, such as OTP requests, upfront fees for loans, jobs or prizes, account-freeze threats and fake police |
| A screenshot of a message | Reads the text in it and checks it the same way as a text message |
| A file | Whether its name hides a program, such as `.apk` or `.pdf.scr` |

Known-bad lists and scripts other users have reported are planned.

Each reply gives one of four levels: **High risk**, **Suspicious**, **No known risk signals** or **Can't tell**. The bot never says a message is "safe". Every reply reminds you to check in your own bank app before paying.

## How it works

- Fixed rules come first: QR parsing and checksum validation (via [khqr-rs](https://github.com/tangheng05/khqr-rs)), domain age and lookalike checks, and Khmer and English scam-wording rules.
- A language model classifies what the rules can't decide. It returns only a category, so every reply is fixed Khmer text, and it can't raise a verdict to High risk without a rule signal it can point to.
- A labeled benchmark of Khmer and English scam messages is checked in CI, so a change that lowers detection or flags more legitimate messages can't be merged.

## Privacy

- Messages and images are checked in memory and never saved. Replies are cached for an hour under a hash of the content, and rate limits use a hash of your Telegram ID, both in memory only.
- When AI checking is on, message text and screenshots are sent to Google's Gemini API (free tier) to read and classify them. Google may use free-tier inputs to improve its products and have people review them, so `/help` asks you to hide account numbers and personal details first.
- If you tap "No" on a KHQR check, the bot stores a report against that payment account, linked only to a keyed hash of your Telegram ID. An account is shown as reported only after 3 different people report it.
- `/forget` deletes every report linked to you.

## Stack

Rust, [teloxide](https://docs.rs/teloxide/), reqwest, rxing and khqr-rs, moka, PostgreSQL with sqlx, and Gemini (free tier), with Claude Haiku as an option. Webhooks and Google Web Risk are planned.

## Website

The site is live at https://checksen.horizxon.tech. `web/` is a static site with no build step (Khmer at `/`, English at `/en/`). Preview it with `python3 -m http.server -d web`. On Vercel, import the repo, set Root Directory to `web` and Framework Preset to Other.

## License

MIT. See [LICENSE](LICENSE).
