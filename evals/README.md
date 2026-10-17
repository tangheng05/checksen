# Evals

`cargo run --bin eval` runs every example in `data/v0.jsonl`, `data/v1.jsonl` and `data/v2.jsonl` through the same text check and verdict as the bot. It writes `results/rules-v<N>-<dataset>.json` and fails if either dataset's recall is lower, or false positive rate higher, than its entry in `baseline.json`.

- **v0**: 100 messages written before the first rules, by the same author. Its scores are optimistic.
- **v2**: 162 Khmer and mixed Khmer/English texts (34 scam, 128 legit), all copied from public Cambodian pages: news, ministry notices, and bank, telco and brand sites. Each row's `source` links to its page, and every text was re-checked against that page. Legit rows are mostly hard negatives: official warnings, winner announcements, service notices and news about scams. Collection notes: `research_notes/Cambodia scam message data/khmer_v2_collection.md`. Treat v2 as the Khmer number.
- **v1**: 87 messages from published 2023–2026 Cambodian sources (bank and regulator warnings, news, real bank promotions and alerts); each row's `source` links to where it was published. 47 are verbatim, the rest reconstructed from published descriptions; the eval scores the two separately. Treat v1 as the real-world number. After an intended improvement, run `cargo run --bin eval -- --update-baseline` and commit both files.

CI scores the rules alone. Before changing the classifier prompt or model, also run `cargo run --bin eval -- --llm gemini` (free tier; needs `GEMINI_API_KEY`) and commit its `rules-v<N>+gemini-v1.json`.

Each line of `data/v0.jsonl` is one message:

| Field | Values |
| --- | --- |
| `id` | unique, `scam-<category>-NN` or `<category>-NN` |
| `text` | the message as a user would forward it |
| `lang` | `km`, `en` or `mixed` |
| `category` | scam type (`loan`, `job`, `otp`, `prize`, `account`, `authority`, `investment`, `mule`) or `legit-*` |
| `label` | `scam` or `legit` |
| `split` | `dev` or `test`; never tune rules on `test` |
| `source` | `synthetic`, `reconstructed: <url>` for a message rebuilt from a published warning, or `verbatim: <url>` |
| `verbatim`, `source_date` | v1 only |

v0 was written by the same author as the rules, from the same research, so its scores are optimistic. Replace synthetic rows with real, consented messages as they come in.
