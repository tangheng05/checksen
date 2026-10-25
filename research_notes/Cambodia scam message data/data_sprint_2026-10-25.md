# Data sprint (2026-10-25)

Goal: more real Khmer scam messages for v2, especially the thin categories (job 1, loan 2, shop 2, family 2, authority 2, investment 1), and a first benchmark for links.

## What didn't work

- **Quoted text in Khmer news.** 246 articles from the WordPress search APIs of kohsantepheapdaily, dap-news, cen and kampucheathmey (queries such as ការងារ/កម្ចី/លក់អនឡាញ/វិនិយោគ/Telegram + បោកប្រាស់). 59 quoted passages looked message-like; none was a scam message. They were victims' complaints, officials' statements and warnings. This confirms the v2 note: news shows scam messages only as screenshots.
- **Screenshots in those articles.** Most article images linked from 2024 and earlier now return 404. The rest were mugshots and a seller's profile page. No usable chat screenshot was found.

Don't repeat either approach; the yield was zero.

## What worked

- **`evals/data/links.jsonl`** (121 domains), built from the sourced tables in `phishing_domains.md`, scored offline by the eval. First run: 94.8% caught, 0 of 44 official domains flagged. The one tier-A miss, `canadias.com` (police warning, 2021), was a plural squat; `link::label_imitates` now treats a brand name of 6+ letters plus "s" as a lookalike (not `wings.com`). After that: 96.1%, all 11 tier-A domains caught, 0 false positives. The held-out misses (`www.khqrrkjp.com`, `abacun.online`) were left alone.

## Where real Khmer messages are

They need a person with a browser, or consent:
- The Anti-Cyber Crime Department and provincial police Facebook pages, and bank pages (ABA, ACLEDA, Wing), which post scam screenshots. Transcribe each by hand and mark it `transcribed` in `source`.
- Public Telegram job and market groups, for scam posts and genuine group posts (a hard-negative set for group protection). Business posts only, never private people's chat.
- CENTRAL's Job Scams Detector bot, which has collected hundreds of reported job ads. Ask for a labelled export.
- The bot's own opt-in sharing (👎 → Share → `/review` → `/export`), which feeds v3.
