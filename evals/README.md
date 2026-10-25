# Evals

`cargo run --bin eval` runs every example in `data/v0.jsonl`, `data/v1.jsonl` and `data/v2.jsonl` through the same text check and verdict as the bot. It writes `results/rules-v<N>-<dataset>.json` and fails if either dataset's recall is lower, or false positive rate higher, than its entry in `baseline.json`.

- **v0**: 100 messages written before the first rules, by the same author. Its scores are optimistic.
- **v2**: 162 Khmer and mixed Khmer/English texts (34 scam, 128 legit), all copied from public Cambodian pages: news, ministry notices, and bank, telco and brand sites. Each row's `source` links to its page, and every text was re-checked against that page. Legit rows are mostly hard negatives: official warnings, winner announcements, service notices and news about scams. Collection notes: `research_notes/Cambodia scam message data/khmer_v2_collection.md`. Treat v2 as the Khmer number.
- **v1**: 87 messages from published 2023–2026 Cambodian sources (bank and regulator warnings, news, real bank promotions and alerts); each row's `source` links to where it was published. 47 are verbatim, the rest reconstructed from published descriptions; the eval scores the two separately. Treat v1 as the real-world number. After an intended improvement, run `cargo run --bin eval -- --update-baseline` and commit both files.

CI scores the rules alone. Before changing the classifier prompt or model, also run `cargo run --bin eval -- --llm gemini` (free tier; needs `GEMINI_API_KEY`) and commit its `rules-v<N>+gemini-v1.json` and `rules-v<N>+gemini-v2.json`. Their `model_false_alarms` list what the model said (category, whether it cited a rule, and message type) for each genuine message it got wrong, so a false alarm's cause can be read without re-running it.

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

- **links**: 121 domains for the name-based lookalike check (`link::lookalike_signals`), scored offline with no network. 77 imitate a Cambodian bank, wallet, KHQR or government site and 44 are the official domains. Each row has a `tier`: `A` named in a warning by the bank or government, `B` listed by a threat feed or tagged phishing on urlscan, `unconfirmed` a lookalike seen on urlscan with no official word, or `official`. Rows are labelled `lookalike`, not phishing, because a domain that copies a bank's name but isn't the bank's is a lookalike whoever registered it. Phishing pages on unrelated names (thiqahbank.com, web.cbpost.online) are left out, since no name check can catch them; domain age, Safe Browsing and URLhaus cover those. Built from `research_notes/Cambodia scam message data/phishing_domains.md`.

**v3** (not scored yet) will hold messages people chose to share after tapping 👎. A reviewer labels them with `/review`, and `/export` sends them as rows in this format (ids `v3-shared-<n>`, every fifth row `test`) and deletes them from the bot. Remove names, account numbers and phone numbers of real people before adding rows to `data/v3.jsonl`, and add v3 to `DATASETS` in `src/bin/eval.rs` and to `baseline.json` once it has enough rows to mean something.
