# Evals

`cargo run --bin eval` runs every example in `data/v0.jsonl` through the same text check and verdict as the bot. It writes `results/rules-v<N>.json` and fails if recall is lower, or the false positive rate higher, than `baseline.json`. After an intended improvement, run `cargo run --bin eval -- --update-baseline` and commit both files.

Each line of `data/v0.jsonl` is one message:

| Field | Values |
| --- | --- |
| `id` | unique, `scam-<category>-NN` or `<category>-NN` |
| `text` | the message as a user would forward it |
| `lang` | `km`, `en` or `mixed` |
| `category` | scam type (`loan`, `job`, `otp`, `prize`, `account`, `authority`, `investment`, `mule`) or `legit-*` |
| `label` | `scam` or `legit` |
| `split` | `dev` or `test`; never tune rules on `test` |
| `source` | `synthetic`, or `reconstructed: <url>` for a message rebuilt from a published warning |

v0 was written by the same author as the rules, from the same research, so its scores are optimistic. Replace synthetic rows with real, consented messages as they come in.
