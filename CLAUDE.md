# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

CheckSen is a Telegram bot (Rust, teloxide) that checks forwarded KHQR codes, links, text and files for scam signals and replies in Khmer with a risk level.

## Commands

```sh
docker compose up -d postgres          # local DB for KHQR reports (optional)
cargo run --bin checksen               # run the bot; needs TELOXIDE_TOKEN in .env (see .env.example)
cargo test                             # all tests; DB tests skip unless TEST_DATABASE_URL is set
cargo test <name>                      # single test or module, e.g. cargo test analyzers::text
TEST_DATABASE_URL=postgres://checksen:checksen@127.0.0.1:5432/checksen cargo test store
cargo run --bin eval                   # rules-only benchmark; fails if worse than evals/baseline.json
cargo run --bin eval -- --update-baseline   # after an intended improvement; commit baseline + results
cargo run --bin eval -- --llm claude|gemini # v1 with a model classifier (needs API key)
```

CI runs, in order: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` (with Postgres), `cargo run --bin eval`. All must pass.

## Architecture

**Crate split.** `src/lib.rs` exposes `analyzers` and `verdict`, the pure detection logic shared by the bot and `src/bin/eval.rs`. The Telegram-only pieces (`bot`, `guard`, `reports`, `store`) are modules of the `checksen` binary in `src/main.rs`, so the eval cannot use them.

**Pipeline.** `bot::handle` hashes the message into a cache key (prefixed with `RULES_VERSION`), rate-limits via `guard::Guard` (moka, in memory), returns a cached reply if present, otherwise runs the analyzers. Every analyzer returns a `Check { subject, signals }` (`analyzers/mod.rs`). `verdict::decide` turns signals into a `Level`, and `verdict::render_km` builds the reply.

**Scoring.** Each `Signal` has a `weight()` and some are `is_hard()` (`analyzers/mod.rs`). In `verdict::decide`: any hard signal, or a score above 0.8 excluding uncited model signals, means HighRisk; a score of 0.4 or more means Suspicious; `Subject::Unreadable` means CantTell.

**LLM is advisory only** (`analyzers/llm/mod.rs::classify`): it's skipped when rules already give HighRisk, returns only a `ScamCategory` (never free text), low-confidence results are dropped, and `cited` is true only if it cites a signal the rules actually found. Failures and timeouts add `Signal::ModelUnavailable`, and those replies aren't cached. `main.rs` uses Anthropic (`anthropic.rs`) when `ANTHROPIC_API_KEY` is set, else the Gemini free tier (`gemini.rs`). The project has no budget for paid APIs, so Gemini is the expected provider. Its free tier may train on and human-review input, which `/help` and the README disclose; keep those in sync with what is sent.

**Intents** (`analyzers/intent.rs`): rules spot greetings, thanks, victims ("I already paid") and the person's own questions; the classifier also returns an `intent` field. Questions and greetings get a fixed answer from `verdict::answer` instead of a verdict, but only when nothing was flagged, so a forwarded scam that asks a question still gets checked. Victims get the help steps first, then the verdict.

**Screenshots** (`bot::check_photo`): QR payloads are decoded first. If a photo has none, Gemini transcribes it (`llm::transcribe`, `Transcriber` trait, its own daily cap in `guard.rs`) and the transcript goes through the same rules and classifier as a text message. URLs in transcripts are deliberately not link-checked, because a misread of a real bank domain would look like a lookalike.

**Adding or changing a text rule** touches several places: the regex `Rule` in `analyzers/text.rs`, a `Signal` variant with its weight, its snake_case name in `TEXT_RULE_SIGNALS` (the LLM cites signals by this name), its Khmer reason in `verdict::reason_km`, and a `RULES_VERSION` bump so cached replies and eval result files don't mix rule versions. Then run the eval.

**Replies.** All user-facing text is fixed Khmer/English pairs in `verdict.rs` (`Text`, or a `match` arm returning both), chosen by `Lang`. `Guard::language` remembers the language a person types in (in memory), which wins over the language of what they forward; Khmer is the default. Verdicts are Telegram HTML (`verdict::render`): the level in bold, one line on what it is, one 👉 action, then the details in an expandable blockquote. Every piece of text goes through `escape`; fixed answers are sent as plain text (`Reply::html`). Tests enforce that no reply says "safe" (or សុវត្ថិភាព) and that every verdict includes `BANK_APP_ADVICE` in both languages; it is shown inline for KHQR and flagged messages, and folded into the details otherwise. Attacker-controlled strings (QR payee fields, domains) must pass through `inert`/`visible`/`defang` so they can't render as links or hide text with bidi controls.

**Links** (`analyzers/link.rs`): follows redirects through a `PublicOnly` DNS resolver that refuses private and special addresses (SSRF guard), checks domain age via RDAP, and detects lookalikes of the brands in `BRANDS`. `analyzers/sites.rs` names the owner of well-known domains and marks free hosting (github.io, web.app); a domain listed there also counts as official, so only add ones you're sure of. For unlisted domains and free hosting, it also GETs the page (512 KB cap, same SSRF guard) to read its title and spot a password field or a bank name in the title (`BrandClaim`). Support-style Telegram usernames with a bank's name (`@ABA_Support_KH`) add `ImpersonatedAccount` in `text::check`. Link replies are never cached.

**Reports** (`store.rs`, `reports.rs`, `migrations/`): optional, enabled only when `DATABASE_URL` is set, and then `HASH_SECRET` (32+ chars) is required. Migrations run automatically on connect via `sqlx::migrate!`. Reporters are stored only as an HMAC of their Telegram ID; inline-button callback data is HMAC-signed and verified. An account is flagged (`Signal::Reported`) after `REPORT_THRESHOLD` distinct reporters; `/forget` deletes a user's reports.

## Evals

Datasets are in `evals/data/` (see `evals/README.md`). v1 is the real-world English-heavy number and v2 the real-world Khmer number; v0 was written by the rules' author and is optimistic. Never tune rules on rows with `split: test`. The regression gate compares recall and false positive rate per dataset against `evals/baseline.json`.

## Privacy constraints

Message text and images are processed in memory only and must never be persisted or logged. The only stored data is KHQR reports keyed by hashed reporter ID.
