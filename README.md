<a href="https://checksen.horizxon.tech"><img src="docs/images/banner.png" alt="CheckSen ឆែកសិន: check before you click or pay" width="100%"></a>

<p align="center">
  <a href="https://t.me/CheckSen_bot"><img src="https://img.shields.io/badge/Telegram-@CheckSen__bot-0E716B?logo=telegram&logoColor=white" alt="Open in Telegram"></a>
  <a href="https://checksen.horizxon.tech"><img src="https://img.shields.io/badge/website-checksen.horizxon.tech-0E716B" alt="Website"></a>
  <a href="https://github.com/tangheng05/checksen/actions/workflows/ci.yml"><img src="https://github.com/tangheng05/checksen/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-5CC4B8" alt="MIT license"></a>
</p>

# CheckSen (ឆែកសិន)

"Check first": a free Telegram bot for people in Cambodia. Before you click, open or pay, forward it the message, link, KHQR code, screenshot or file, and within seconds it replies with a risk level and the reasons behind it. Replies are in Khmer, or in English if you write to it in English.

**Try it:** [t.me/CheckSen_bot](https://t.me/CheckSen_bot). Nothing to install. The website at [checksen.horizxon.tech](https://checksen.horizxon.tech) shows example replies in Khmer and English.

> **Status:** live and free to use, but still early. The rules are tuned against real Cambodian scam messages, and they keep improving.

## What it checks

| You send | It checks |
| --- | --- |
| A KHQR code (photo or screenshot) | Who the QR really pays: merchant name, account, bank and amount, and whether the code is valid KHQR or was edited |
| A link | Who owns the site, where it redirects, how new the domain is, free hosting that anyone can use, lookalikes of bank, wallet, Telegram and government domains, and, for unknown sites, the page title, a bank's name in it, and password fields |
| A text message | Common scam patterns in Khmer and English: OTP requests, upfront fees for loans, jobs or prizes, account-freeze threats, fake police, scam-compound job ads, extortion, online gambling ads, Telegram accounts posing as bank support, and more |
| A screenshot of a message | Reads the text in it and checks it the same way as a text message, along with any caption and links |
| A file | Whether its name hides a program, such as `.apk` or `.pdf.scr` |
| A question, or "I already paid" | A fixed, reviewed answer: what to do right away if you were scammed, how to report, whether banks ever ask for codes, and what the bot can check |

Each reply gives one of four levels:

| Level | Meaning |
| --- | --- |
| 🔴 ហានិភ័យខ្ពស់ (High risk) | Clear scam signs. Don't pay, and don't share any code. |
| 🟠 គួរឱ្យសង្ស័យ (Suspicious) | Some warning signs. Check through an official number or app first. |
| ⚪ មិនទាន់រកឃើញសញ្ញាបោកប្រាស់ទេ (No scam signs found yet) | No known tricks found. The bot never says a message is "safe". |
| ❔ មិនអាចពិនិត្យបាន (Can't tell) | The image was unclear or couldn't be read. |

Every reply ends by reminding you to check the recipient's name in your own bank app before paying.

Voice messages and videos can't be checked yet; the bot asks for a screenshot or the text instead. In a group, it only replies when someone mentions @CheckSen_bot, replies to it, or sends `/check` in reply to a message.

<a href="https://checksen.horizxon.tech"><img src="docs/images/website.png" alt="The CheckSen website, with a live example of the bot's reply" width="100%"></a>

## How well it works

Every change is scored against labelled real-world messages in CI. Recall is the share of scams caught; the false positive rate is the share of genuine messages wrongly flagged.

| Benchmark | Rules only | Rules + Gemini |
| --- | --- | --- |
| v1: 87 real messages, mostly English | 80.4% recall, 0% false positives | 95.7% recall, 7.3% false positives |
| v2: 162 real Khmer messages | 52.9% recall, 3.1% false positives | 94.1% recall, 3.9% false positives |

The data, labels and how they were collected are in [`evals/`](evals/README.md). A pull request that lowers recall or raises false positives on the rules-only benchmark fails CI.

## How it works

- **Fixed rules come first:** QR parsing and checksum validation (via [khqr-rs](https://github.com/tangheng05/khqr-rs)), domain age and lookalike checks, and Khmer and English scam-wording rules.
- **A language model handles what the rules can't decide.** By default this is Google Gemini's free tier. It returns only a category and what the person seems to want (to check a message, ask a question, or get help after being scammed), so every reply is fixed, reviewed Khmer or English text. It can't raise a verdict to High risk without a rule signal it can point to, and low-confidence answers are dropped.
- **Screenshots:** QR codes in a photo are decoded first. Otherwise Gemini reads the text in the screenshot, and that text goes through the same rules.

## Privacy

- Messages and images are checked in memory and never saved. Replies are cached for an hour under a hash of the content, and rate limits use a hash of your Telegram ID, both in memory only.
- When AI checking is on, message text and screenshots are sent to Google's Gemini API (free tier) to read and classify them. Google may use free-tier inputs to improve its products and have people review them, so `/help` asks you to hide account numbers and personal details first.
- The language you write in is remembered in memory for 30 days, under a hash of your Telegram ID, so forwarded messages get replies in your language.
- For a link to a site it doesn't know, the bot opens the page once from its server to read the title. It never opens links to well-known services, so one-time login links aren't used up.
- If you tap "No" on a KHQR check, the bot stores a report against that payment account, linked only to a keyed hash of your Telegram ID. An account is shown as reported only after 3 different people report it.
- `/forget` deletes every report linked to you.

## Run it yourself

You need a recent stable Rust (1.96 or newer) and a bot token from [@BotFather](https://t.me/BotFather).

```sh
cp .env.example .env                 # then fill in the values below
docker compose up -d postgres        # optional, only for KHQR reports
cargo run --release --bin checksen
```

| Variable | Needed | What it does |
| --- | --- | --- |
| `TELOXIDE_TOKEN` | yes | The Telegram bot token |
| `GEMINI_API_KEY` | recommended | AI text checks and screenshot reading, using the free tier from [Google AI Studio](https://aistudio.google.com/apikey) |
| `GEMINI_MODEL` | no | A model, or a comma-separated list tried in order when one is busy or out of quota (default `gemini-3.5-flash-lite,gemini-3.1-flash-lite`). Use a single model for `eval --llm` runs |
| `ANTHROPIC_API_KEY` | no | Uses Claude for text checks instead of Gemini |
| `DATABASE_URL` | no | Postgres for KHQR reports; migrations run on start |
| `HASH_SECRET` | with `DATABASE_URL` | At least 32 random characters, used to hash reporter IDs |

To keep it running on a Linux server, a systemd service is enough:

```ini
# /etc/systemd/system/checksen.service
[Unit]
Description=CheckSen bot
After=network-online.target

[Service]
WorkingDirectory=/opt/checksen
ExecStart=/opt/checksen/target/release/checksen
Restart=always

[Install]
WantedBy=multi-user.target
```

Then `systemctl enable --now checksen`. To update: `git pull && cargo build --release && systemctl restart checksen`.

### Development

```sh
cargo test                           # DB tests skip unless TEST_DATABASE_URL is set
cargo run --bin eval                 # rules-only benchmark, fails if worse than evals/baseline.json
cargo run --bin eval -- --llm gemini # the same benchmark with the AI classifier
```

CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` and the benchmark.

## Website

`web/` is a static site with no build step: Khmer at `/` and English at `/en`. Preview it with `python3 -m http.server -d web`. On Vercel, import the repo, set the Root Directory to `web` and the Framework Preset to Other.

## Stack

Rust, [teloxide](https://docs.rs/teloxide/), reqwest, rxing and khqr-rs, moka, PostgreSQL with sqlx, and Gemini (free tier), with Claude as an option. Webhooks and Google Web Risk are planned.

## License

MIT. See [LICENSE](LICENSE).
