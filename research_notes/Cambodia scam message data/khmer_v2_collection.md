# Khmer v2 collection (2026-10-17)

How `evals/data/v2.jsonl` was built, and where to look next time.

Four research passes collected Khmer and mixed Khmer/English text, copied exactly from public pages. A script then re-downloaded every source and kept a row only if its text appeared on the page, ignoring whitespace and zero-width characters. Of 165 rows, 162 were kept: 2 were duplicates and 1 page no longer loads. Phone numbers, account numbers and personal names are replaced with [PHONE], [ACCOUNT] and [NAME]. That includes impersonated public figures such as Hun Sen and នាយពាង, whose names are the scam cue.

## What works

| Source | How |
|---|---|
| kohsantepheapdaily.com.kh, dap-news.com, cen.com.kh, kampucheathmey.com | `/wp-json/wp/v2/posts?search=<Khmer term>`. The response has full article bodies. Decode Kampuchea Thmey with utf-8-sig, because it has a BOM. |
| akp.gov.kh/kh | `/kh/search?q=`. Reprints ministry warnings as plain HTML. The best government source of quoted wording. |
| mptc.gov.kh | `/wp-json/wp/v2/posts?search=`. Mostly warnings that describe scams rather than quote them. |
| interior.gov.kh | `web-api.interior.gov.kh/api/v1/public/news?size=1000&page=N` and `/news/{hash}`. 27k items with no search parameter, so filter by title or do a full-text scan. |
| ababank.com/km | The live site returns 403, so use `web.archive.org/web/2026id_/https://www.ababank.com/km/aba-news/...`. About 40 more archived promo pages remain. |
| wingbank.com.kh/km, acledabank.com.kh/kh/khm/, kbprasacbank.com.kh/km (via its WordPress sitemap), smart.com.kh/km, cellcard /km, truemoney /kh | Plain curl. |
| grab.com/kh, coca-cola.com/kh/kh, tax.gov.kh, cambodiapost.com.kh, amret.com.kh/kh | Plain curl. These gave legitimate hard negatives. |

## What doesn't

- Blocked (403 or WAF): thmeythmey, postkhmer, freshnewsasia, khmertimeskh, police.gov.kh, trc.gov.kh and hattha.
- No connection: voakhmer, rfa.org/khmer, gdt.gov.kh and AMK. CamCERT also stopped connecting partway through, so use the Wayback Machine.
- JavaScript-only: Chip Mong, Vattanac, Pi Pay, Metfone, Bakong, current Canadia, foodpanda, BongThom, Khmer24, CamHR, LOLC, NSSF and verify.gov.kh.
- Fact Crescendo Cambodia has **no Khmer article text**. Even the root site is English, and the Khmer posts appear only in screenshots.
- Image-only or scanned PDFs: NBC press releases, Ministry of Labour fake-recruiter notices, EDC notices, several MPTC and CamCERT examples, and most scam screenshots in news stories.

## What the data shows

Real Khmer scam wording is colloquial and rarely matches rule phrasing. Rules v3 catch 4 of 34 scams, and the 4 caught are bank-published examples written in clean Khmer. They also flag Khmer warnings and news that quote scam phrases. Note the spelling variant ក្រើនរំឭក, which the rules only know as ក្រើនរំលឹក. They also flag Coca-Cola's real "you won, call us" messages, and Amret's real «កម្ចីរហ័ស» (quick loan) product line.

## Next sources worth trying

- Anti-Cyber Crime Department and provincial police Facebook pages. These are where most real messages are quoted, but they need a browser.
- OCR of the NBC, Labour and EDC image notices, with a human checking the result.
- A full-text scan of the Interior API, and archive.akp.gov.kh for 2019–2024.
- Consented forwards from real users once the bot is live. This is still the only route to verbatim Khmer loan, police and family scripts.
