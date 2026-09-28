# Public datasets of Khmer, Cambodian and Southeast Asian SMS spam, scam and phishing messages (for a CheckSen test benchmark)

Research date: 2026-09-28. Every license below was checked on the dataset's own page, dataset card, repo LICENSE file or the GitHub/PyPI API. If I could not read a license, the note says "unclear" or "none".

"Redistributable in an MIT repo" means the data file can be committed to this repo and shipped with it. The data keeps its own license and does not become MIT. CC BY and CC0 data can be vendored with an attribution/NOTICE file. NC, SA, GPL or unknown-license data should not be committed; fetch it with a script at eval time instead.

## Which public datasets exist and can they be used? (inventory table)

### Takeaway
No public Khmer-language SMS or Telegram scam dataset exists on HuggingFace or GitHub, and I found none in academic sources. The most useful Southeast Asian corpus is a new (2026), real-message, CC BY 4.0 Vietnamese SMS phishing dataset. For English, the Mishra & Soni smishing set and the UCI SMS Spam Collection (both CC BY 4.0) are the only well-known sets that can be redistributed. Both are old and UK/US-centric.

### Cited Findings

| # | Name | URL | Languages | Size | Labels | Date range of messages | License | Redistributable in MIT repo | Relevance to Cambodia (1-5) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Quality-Assured Vietnamese SMS Phishing Dataset (Tran et al.) | https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset | vi (accented and unaccented) | 2,991 (train 2,394 / test 597); 2,193 ham, 798 spam/scam | `label` 0 = legit, 1 = spam/scam; PII replaced with `[PHONE]`, `[BANK_ACC]`, `[MONEY]`, `[NUMBER]`, `[TIME]`, `[DATE]`, `[URL]` | 2026 (the `date` column shows May–Jul 2026) | CC BY 4.0 | Yes, with attribution | 4 |
| 2 | Same authors, 300-message sample | https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_phishing_sample | vi | 300 | card lists only `message_id`, `text` (HAM/SPAM task) | 2026 | CC BY 4.0 | Yes, with attribution | 3 |
| 3 | SMS Phishing Dataset for ML and Pattern Recognition (Mishra & Soni) | https://data.mendeley.com/datasets/f45bkkt8pr/1 | en | 5,971: 4,844 ham, 489 spam, 638 smishing | `LABEL` (ham / spam / Spam / Smishing / smishing, mixed case), `TEXT`, `URL`, `EMAIL`, `PHONE` flags | Published 2022-06-20; the text comes largely from older UCI-era messages plus some COVID-era smishing | CC BY 4.0 | Yes, with attribution | 2 |
| 4 | UCI SMS Spam Collection v.1 (Almeida, Gómez Hidalgo, Yamakami) | https://archive.ics.uci.edu/dataset/228/sms+spam+collection (HF mirror: https://huggingface.co/datasets/ucirvine/sms_spam) | en (UK/Singapore) | 5,574 (747 spam) | ham / spam | Paper 2011; messages are 2000s UK premium-rate spam | UCI page: CC BY 4.0. The HF mirror card says "unknown". | Yes (per UCI), with attribution | 1 |
| 5 | Smishing Dataset I (Smishtank.com, Timko & Rahman) | https://smishtank.com/dataset (paper: https://arxiv.org/abs/2402.18430) | mostly en (US) | 1,062 smishing | 10 message categories, 5 URL categories, brand, sender, VirusTotal and WHOIS fields | around 2023 (the paper does not give an exact range) | CC BY-NC-SA 4.0 | No (NC and SA are incompatible with MIT redistribution); fetch externally | 2 |
| 6 | Indonesia SMS Spam Dataset (bopbi) | https://github.com/bopbi/indonesia-sms-spam-dataset | id | 50 files: loan 26, prize 20, premium-sms 2, evil-service 1, non-provider-promo 1 | folder name = category | Undated; repo created 2021-07 | CC0 1.0 | Yes | 3 |
| 7 | Indonesian SMS spam (Wibisono/Rahmi, `dataset_sms_spam_v1`) | https://gist.github.com/agtbaskara/a1a7017027cc1df9d35cf06e1e5575b7 (origin: yudiwbs.wordpress.com, 2018) | id | not verified | `Teks,label` (sample rows show `promo`) | about 2015–2018 (dates appear in the texts) | none stated | Unclear, so no | 2 |
| 8 | Philippine Spam/Scam SMS (bwandowando, Kaggle) | https://www.kaggle.com/datasets/bwandowando/philippine-spam-sms-messages (GitHub copy with no license: https://github.com/AGR-Yes/ScamMessagesPhilippines/blob/main/Raw%20Datasets/SPAM_SMS.csv) | en/tl (Taglish) | about 270 lines in the GitHub copy; the Kaggle size was not verified | all spam; columns `_id, address (masked), date, text, threadId` | 2022-11-12 to 2023-05-30 | Kaggle license not retrievable (page is JS-rendered); the GitHub copy has none | Unclear, so no | 3 |
| 9 | PH Spam + Marketing SMS (w/ timestamps) | https://www.kaggle.com/datasets/scottleechua/ph-spam-marketing-sms-w-timestamps | en/tl | not verified | not verified | not verified | not verified | Unclear | 3 |
| 10 | asea-sms-scam-detection (Taglish 12-class) | https://github.com/ChrisThePCGamer/asea-sms-scam-detection | tl/en | not verified | 12 scam-intent classes | repo created 2026-09-25 | none (no LICENSE file) | No | 3 |
| 11 | Bantay-Bait merged corpus | https://github.com/jszulueta/Bantay-Bait | en/tl | 14,023 (safe 10,043, spam 3,807, malicious 173) per search summary | safe / spam / malicious | repo 2026 | none | No | 2 |
| 12 | Moses Ngeth, "Cutting the Grass, Not the Root" Telegram job-ad dataset | Report PDF: https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf ; post: https://www.mosesngeth.com/posts/cutting-the-grass-not-the-root-cambodia-scam-job-ads | km, zh, en | 4,991 ads from 37 public Telegram channels/groups, plus 306 ads (59 alleged scam) in an 18-day test | parsed fields: job title, location, market, pay, language; ad IDs | 2023-04 to 2026-07-20; test 2026-08-28 to 09-14 | Report says the dataset is "public", but I found no download URL and no license | Unclear, so no until the author confirms | 5 (for the job-recruitment lure category) |
| 13 | Tanailee/khmer-english-scam-safety-assistant | https://github.com/Tanailee/khmer-english-scam-safety-assistant | en + 16 km rows | 5,375 (4,530 safe, 845 scam), of which 5,158 are UCI | safe/scam + `scam_type` | Khmer rows are hand-written, not real | none | No | 1 |
| 14 | FredZhang7/all-scam-spam | https://huggingface.co/datasets/FredZhang7/all-scam-spam | 43 languages incl. vi, id, tl | 42,619 | `is_spam` 0/1 | mixed (UCI, Enron, SpamAssassin + 1,040 hand-collected rows) | Apache-2.0 claimed (the upstream sources carry their own terms) | Unclear (derivative of mixed sources) | 1 |
| 15 | SMS Spam Multilingual Collection | https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset | UCI machine-translated (M2M100) into id, jv and others | about 5.5k per language | ham/spam | 2000s source | GPL | No (copyleft, and the text is machine-translated) | 1 |
| 16 | Telegram spam/ham (English) | https://huggingface.co/datasets/thehamkercat/telegram-spam-ham | en | not verified | spam/ham | 2023 upload | WTFPL | Yes | 1 |
| 17 | alt-gnome/telegram-spam | https://huggingface.co/datasets/alt-gnome/telegram-spam | ru | not verified | spam/ham | 2025 | CC0 1.0 | Yes | 1 |
| 18 | angelfonsecar/phishing-compilation | https://github.com/angelfonsecar/phishing-compilation | en (6 merged sets) | not verified | phishing/ham | 2023 | MIT claimed on a compilation of upstream data | Unclear | 1 |

Sources for table rows:
- HF API listings and dataset cards (license tags came from the API): [HF datasets search](https://huggingface.co/api/datasets?search=smishing), [Vietnamese card](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset), [Vietnamese sample card](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_phishing_sample), [ucirvine/sms_spam](https://huggingface.co/datasets/ucirvine/sms_spam), [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam), [dbarbedillo multilingual](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)
- Mishra & Soni: license "CC BY 4.0", published June 20, 2022, 5,971 messages — [Mendeley Data](https://data.mendeley.com/datasets/f45bkkt8pr/1). I downloaded `Dataset_5971.zip` and counted the labels myself: ham 4,844; Smishing 616 + smishing 22; spam 466 + Spam 23.
- UCI license "Creative Commons Attribution 4.0 International", read from the page HTML — [UCI ML Repository](https://archive.ics.uci.edu/dataset/228/sms+spam+collection)
- Smishtank: "The full dataset has been made publicly available through this link https://smishtank.com/dataset", license CC BY-NC-SA 4.0, 1,062 messages — [arXiv 2402.18430](https://arxiv.org/html/2402.18430)
- bopbi: README says "the dataset license is CC 1.0 universal", and the GitHub API reports CC0-1.0 — [GitHub](https://github.com/bopbi/indonesia-sms-spam-dataset)
- bwandowando: messages received from November 12, 2022 to May 30, 2023 (per search result summary) — [Kaggle](https://www.kaggle.com/datasets/bwandowando/philippine-spam-sms-messages); GitHub copy — [AGR-Yes/ScamMessagesPhilippines](https://github.com/AGR-Yes/ScamMessagesPhilippines)
- Moses Ngeth report — [PDF](https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf), [ABC News](https://www.abc.net.au/news/2026-09-25/cambodia-scam-industry-job-advertisements/107185964), [CamboJA](https://cambojanews.com/cambodia-scam-recruitment-continued-despite-closure-claim-researcher-says/)
- Tanailee sources JSON (5,375 rows; km 16; "Manual Khmer scam examples" 10) — [GitHub](https://github.com/Tanailee/khmer-english-scam-safety-assistant)
- Bantay-Bait counts and ASEA description — [search result summary pointing at GitHub](https://github.com/jszulueta/Bantay-Bait), [asea repo](https://github.com/ChrisThePCGamer/asea-sms-scam-detection)

### Inferences
- Only rows 1, 2, 3, 4, 6, 16 and 17 can be vendored into the repo with confidence. Rows 1, 3, 4 and 6 are the relevant ones.
- The only candidate rated 5 for Cambodia (Ngeth) is recruitment ads aimed at workers, not messages aimed at victims. It fits a "job lure / trafficking" category, not the bank/OTP/KHQR categories.

### Gaps
- Kaggle licenses for rows 8 and 9 could not be read because the pages render client-side and there is no Kaggle CLI or API key here. Check them by hand.
- The row count and full label set for the Wibisono Indonesian dataset (row 7) were not verified.

## Are there public Khmer-language SMS/Telegram spam, scam or phishing datasets?

### Takeaway
No. The HuggingFace, GitHub and web searches all found nothing public. The closest items are a Khmer SMS classifier that ships only a trained model, an empty repo named "spam_dataset_khmer_english", and a student project with 10 hand-written Khmer scam lines (no license). CheckSen's own v0 benchmark is already ahead of anything public.

### Cited Findings
- HF dataset searches for "khmer spam", "khmer scam", "khmer phishing" returned nothing. A `language:km` filter over 200 datasets turned up no ID containing spam/scam/fraud/phish/sms/telegram. The Khmer datasets that do exist are speech, news, dictionaries, QA and POS — [HF API khmer](https://huggingface.co/api/datasets?search=khmer), [HF API cambodia](https://huggingface.co/api/datasets?search=cambodia)
- Khmer-relevant non-scam text on HF that could serve as legitimate (ham) Khmer text: `CADT-IDRI/Khmer_News_classification` (no license tag), `seanghay/khmer-dictionary-44k` (no license tag), `SEACrowd/khmer_alt_pos` (CC BY-NC-SA 4.0) — [HF API khmer](https://huggingface.co/api/datasets?search=khmer)
- `reanyouda/spam_dataset_khmer_english` on GitHub is an empty repository (the API returns "Git Repository is empty.") — [GitHub](https://github.com/reanyouda/spam_dataset_khmer_english)
- `VatanaChhorn/KhmerCoreMLSMSClassifier` (MIT, 2025) ships a compiled CoreML model `kh-sms-classifier.mlmodelc` and a text preprocessor, but no training data — [GitHub](https://github.com/VatanaChhorn/KhmerCoreMLSMSClassifier)
- `Tanailee/khmer-english-scam-safety-assistant` (no license) has `real_life_scam_examples.csv` with hand-written Khmer lines, e.g. "គណនី ABA របស់អ្នកត្រូវបានចាក់សោ សូមផ្ញើ OTP ឥឡូវនេះ" ("Fake bank lock plus OTP"). Its sources file lists them as "Manually authored Khmer/English examples", so they are not real messages — [GitHub](https://github.com/Tanailee/khmer-english-scam-safety-assistant)
- Other Cambodian anti-scam tools on GitHub are bots or URL checkers, not datasets: COPPSARY/broryat-bot (Apache-2.0, Khmer/English Telegram bot), VisaiCyber/PhishGuard-Cambodia, MoriartyPuth/NETH (KHQR) — [GitHub search results via API](https://github.com/COPPSARY/broryat-bot)
- A web search for a Khmer SMS spam dataset found only English and Vietnamese datasets — [search result: arXiv 1705.04003](https://arxiv.org/pdf/1705.04003). A search for Khmer Telegram spam papers found generic Telegram spam papers (e.g. "BES-SVM ... Telegram Spam Classification") and Khmer news classification, but nothing Khmer and spam at once — [ResearchGate BES-SVM](https://www.researchgate.net/publication/400557038_BES-SVM_ENHANCED_MACHINE_LEARNING_ALGORITHM_FOR_TELEGRAM_SPAM_CLASSIFICATION), [Khmer text classification arXiv 2112.06748](https://arxiv.org/pdf/2112.06748)

### Inferences
- A Khmer benchmark has to be built by hand. The inputs are official warnings (NPA, MPTC, NBC, bank advisories), user-forwarded messages with consent, and screenshots from Cambodian news. Nothing can be imported.
- Hand-written Khmer "examples" in student repos are biased toward the author's idea of a scam. Don't count them as real-world recall evidence.

### Gaps
- I did not search the ITC, RUPP or CADT institutional repositories directly (their theses are rarely indexed). None of their work surfaced in web or HF results (CADT-IDRI has news-classification data only). Emailing CADT's IDRI lab may turn up unpublished data.
- The BES-SVM Telegram paper's dataset language and availability were not checked.

## What Southeast Asian scam/spam datasets exist (Thai, Vietnamese, Lao, Indonesian, Malay, Filipino)?

### Takeaway
Vietnamese is the strongest (2026, real, CC BY 4.0, scam types that overlap with Cambodia's). Indonesian and Filipino data exist but are small, older or unlicensed. I found no public Thai, Lao or Malay SMS scam text dataset.

### Cited Findings
- The Vietnamese dataset says it is "tổng hợp từ các tin nhắn SMS thực tế ... Không AI-Generated hay dịch từ ngôn ngữ khác" (compiled from real SMS, not AI-generated or translated). It thanks "Team Chống Lừa Đảo" (the anti-scam team, chongluadao.vn) for a 50,000-URL list used as a labelling criterion. It reports PhoBERT-base F1 96.63% and char 3–5-gram SVM F1 93.40% under 5-fold CV after Jaccard ≥ 0.85 deduplication — [HF card](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset)
- The sample card cites "IEEE Access / Computer Science Domain, 2026" and an IRB reference "IRB-2026-NLP-0428". I could not verify either claim independently — [HF sample card](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_phishing_sample)
- Vietnamese spam rows I pulled from `full_dataset.csv` include a fake bank domain, gift points, gambling signup, a TikTok Shop "CTV" like-task job, VNeID government impersonation and an investment promising 30%/month (verbatim in the Examples section) — [HF file](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset/resolve/main/full_dataset.csv)
- Sample Vietnamese ham rows (label 0): "GHTK - [NUMBER] la ma xac nhan su dung de dang nhap ung dung iGHTK cua ban. Tuyet doi khong chia se OTP voi nguoi khac" and "Your Firebase App verification code is [NUMBER]" — [HF test.csv](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset/resolve/main/test.csv)
- An older Vietnamese corpus: 6,599 messages from Viettel and Vinaphone (5,557 legitimate, 1,042 spam), per the search summary of the paper. I did not find a public download — [arXiv 1705.04003](https://arxiv.org/pdf/1705.04003)
- Vietnamese spam *reviews* (not SMS): SEACrowd/vispamreviews (CC BY-NC 4.0); and `adamtc/scam_dialogues` (vi, Apache-2.0; content not inspected) — [HF API](https://huggingface.co/api/datasets?search=vi%20spam), [HF API scam](https://huggingface.co/api/datasets?search=scam)
- Indonesian bopbi sample (loan category, verbatim): "Ass,,Bpk/Ibu / Tersedia Pinjmn / Tmpa Agunan / Dngn / Bung 2%/Thn / Miniml 5 jt S/D 500jt / Untuk Inf0 Chat / Whatsap 0813…" — [GitHub loan/1.txt](https://github.com/bopbi/indonesia-sms-spam-dataset)
- Indonesian Wibisono sample rows (verbatim): `"[PROMO] Beli paket Flash mulai 1GB di MY TELKOMSEL APP dpt EXTRA kuota 2GB 4G LTE ...",promo` and `2.5 GB/30 hari hanya Rp 35 Ribu Spesial buat Anda yang terpilih. Aktifkan sekarang juga di *550*905#. Promo sd 30 Nov 2015...,promo` — [Gist](https://gist.github.com/agtbaskara/a1a7017027cc1df9d35cf06e1e5575b7)
- Other Indonesian repos have no license: FraudSense (about 3,800 labelled SMS + email, per search summary), fintext-qc, sms-spam-detector-indonesia — [FraudSense](https://github.com/keananj/FraudSense), [fintext-qc](https://github.com/Steven-Tampubolon/fintext-qc)
- Philippine sample rows (bwandowando via the GitHub copy): `"2022-11-12 14:02:10.079","Welcome ! your have P1222 for S!ot , Web: 11y.life Good Luck!C"`; `"2022-11-12 14:33:48.916","My god, at least 999P rewards waiting for you …"` (truncated) — [GitHub copy](https://github.com/AGR-Yes/ScamMessagesPhilippines/blob/main/Raw%20Datasets/SPAM_SMS.csv)
- The AGR-Yes project also points to an open, crowd-edited Google Sheet "Scam SMS Report" (scammer numbers, message type such as lotto or casino, text). It has no license — [README](https://github.com/AGR-Yes/ScamMessagesPhilippines)
- Philippine research: SMSegurado used "Tagalog-English datasets from Kaggle and the National Telecommunications Commission (NTC)"; BantayText used Kaggle Filipino/English/Taglish messages — [Springer SMSegurado](https://link.springer.com/chapter/10.1007/978-981-96-5848-0_54), [BantayText](https://www.researchgate.net/publication/403143574_BantayText_Machine_Learning-Based_Detection_of_Scam_SMS_in_the_Philippines)
- Thai: search found only `Aarish173/ThaiScamCall`, which is AI-generated Thai phone-call *audio*, not SMS text — [HF](https://huggingface.co/datasets/Aarish173/ThaiScamCall). HF searches for "thai spam", "thai sms", "malay spam", "indonesia spam", "tagalog spam" and "filipino spam" returned nothing — [HF API](https://huggingface.co/api/datasets?search=thai%20spam)

### Inferences
- The Vietnamese scam types (fake-bank lookalike domains, government ID/VNeID impersonation, TikTok/e-commerce "like task" jobs, investment/Ponzi, online gambling signups) closely match the patterns Cambodian authorities warn about (ABA/ACLEDA lookalikes, fake police, Telegram task jobs). This makes it the best cross-lingual stand-in.
- Its PII tokenization (`[URL]` in some rows, real URLs in others) means URL-based analyzers only get a partial test.
- Indonesian loan/prize SMS resemble Cambodian "quick loan" and prize bait, but the set is tiny (50 messages) and undated.

### Gaps
- No Lao, Malay or Thai SMS scam text corpora found. Thai SMS scam research likely exists in Thai-language venues; not searched.
- The Philippine Kaggle datasets' licenses and exact sizes were not verified.

## Well-known English SMS spam/phishing datasets: licenses and how representative they are of 2024–2026 scams

### Takeaway
UCI (CC BY 4.0) and Mishra & Soni (CC BY 4.0) can be redistributed but are mostly 2000s UK premium-rate spam. Smishtank is more modern (US smishing, around 2023) but is CC BY-NC-SA. None of them contain Telegram, KHQR/Bakong, Cambodian banks or pig-butchering conversations.

### Cited Findings
- UCI sample spam rows (verbatim, from the HF datasets-server): "Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121 to receive entry question(std txt rate)T&C's apply 08452810075over18's"; "WINNER!! As a valued network customer you have been selected to receivea £900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only." — [HF ucirvine/sms_spam](https://huggingface.co/datasets/ucirvine/sms_spam)
- UCI was published in 2011 and extends the NUS SMS corpus — [HF card](https://huggingface.co/datasets/ucirvine/sms_spam)
- Mishra & Soni rows labelled "smishing" include UCI-style premium-rate spam, e.g. "Do you want 750 anytime any network mins 150 text and a NEW video phone for only five pounds per week call 08000776320 now or reply for delivery Tomorrow". Rows labelled "Smishing" include COVID-era lures: "Please Stay At Home. To encourage the notion of staying at home. All tax-paying citizens are entitled to ï¿½305.96 or more emergency refund. smsg.io/fCVbD" and "BankOfAmerica Alert 137943. Please follow http://bit.do/cgjK-and re-activate" — [Mendeley Dataset_5971.zip](https://data.mendeley.com/datasets/f45bkkt8pr/1)
- Smishtank fields include brands, URLs, VirusTotal results and WHOIS; it was built from community submissions and is meant to be "continually updat[ed]" — [arXiv 2402.18430](https://arxiv.org/html/2402.18430)
- Many 2026 derived English sets on HF are UCI re-uploads or synthetic data (e.g. `itsG/smishing-synthetic`, `Ridham115/indian-scam-sms-synthetic-audited`, BothBosu scam-dialogue sets, Apache-2.0 and LLM-generated) — [HF API smishing](https://huggingface.co/api/datasets?search=smishing), [HF API scam](https://huggingface.co/api/datasets?search=scam)

### Inferences
- UCI and Mishra spam is useful mainly as English *ham* for false-positive testing and as generic "prize / call this number" bait. It will overstate recall if used as evidence that the bot catches modern Cambodian scams.
- Mishra & Soni overlaps heavily with UCI, and its labels need case-folding and dedup against UCI before use.
- Smishtank's category and URL-type labels map well onto CheckSen's link analyzer (deceptive subdomains/TLDs, random domains), but NC-SA means download-on-demand only.

### Gaps
- Search snippets mentioned a "Spam Hunter" 2022 Twitter-sourced set and an "SMS Gateways Smishing" 2023 set (68,029 messages). I did not verify their URLs or licenses.
- The 2026 arXiv paper "Johnny Still Receives Spam SMS" (https://arxiv.org/pdf/2609.01171) and the Scientific Reports review of recommended SMS spam datasets (https://www.nature.com/articles/s41598-025-92223-1, behind a login redirect) were not read. They may list more datasets and licenses.

## Are Cambodian scam Telegram job-ad datasets or scam-compound scripts publicly available?

### Takeaway
Moses Ngeth's 4,991-ad dataset (Apr 2023–Jul 2026, Khmer/Chinese/English) is described in his report as public, with channel names, usernames, links and contact handles removed. I could not find a download link, and no license is stated. The report's appendices quote ads, which is the only verbatim material available. I found no public scam-compound script dataset.

### Cited Findings
- "From April 2023 to July 2026, we collected 4,991 job postings from 37 public Telegram channels and groups that advertise work in Cambodia ... The recruiters write these ads themselves, in Khmer, Chinese and English" — [Report PDF](https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf)
- "Second, the full dataset is public: all 4,991 postings and the 59 postings of the 18-day test, with the complete original text of every ad, its date and its parsed fields. In this public file the channel and group names, the usernames, the links and the recruiters' contact handles inside the ad text have been removed ... Requests should be addressed to the author." — [Report PDF](https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf)
- The blog post links only the report PDF and a briefing PDF (`Cutting_the_Grass_Briefing.pdf`). There is no dataset link — [mosesngeth.com post](https://www.mosesngeth.com/posts/cutting-the-grass-not-the-root-cambodia-scam-job-ads)
- Job roles: "add contact", "model real face", "model AI", "killer", "money mule", "AI model developer"; salaries $600–$12,000/month; ad volume 899 in Jan 2026, 162 in May, 588 in July. The report and ABC give different figures for these months (see the next finding) — [ABC News](https://www.abc.net.au/news/2026-09-25/cambodia-scam-industry-job-advertisements/107185964)
- The report itself says the channels "posted 394 job ads in February 2026" and that ads were "back to 67 a month by July" for one category. This does not contradict ABC's totals, but the figures are per-category or per-month and should be read carefully — [Report PDF](https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf)
- Verbatim ad quotes in the report (the report translates ads that were in Khmer or Chinese): "Find only 5 clients per day; exceeding target pays $1 per person." [ad 1895]; "Position: Customer Service, replying to customer chats (Platform Game). Salary: $600 – $800 + $100. English 30% – 40%. Typing 30 wpm up." [ad 236]; "Find clients via SIM platform USA" [ad 7251]; "Make phone calls regarding law enforcement and judicial officials." [ad 4820] — [Report PDF](https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf)
- ABC quotes an ad: "Your passport and cellphone will NOT be held … You're free to go WHENEVER you want" — [ABC News](https://www.abc.net.au/news/2026-09-25/cambodia-scam-industry-job-advertisements/107185964)
- The report notes that WIRED reviewed Telegram job ads "that this investigation also collected" — [Report PDF](https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf)

### Inferences
- The ads recruit workers into scam compounds; they are not scams aimed at the bot's users. The part most relevant to CheckSen is the "too good to be true overseas job / free housing / no passport held" lure pattern, which victims of trafficking see.
- Before anything goes into the repo, the author must confirm the license in writing and send the file.

### Gaps
- Public dataset URL and license: not found. Ask the author through the site's /contact page.
- Scam-compound scripts (the "add contact" chat playbooks) are described in journalism (BBC/WIRED per the report), but I found no public text corpus of them. Synthetic English "scam-dialogue" sets on HF exist but are not Cambodia-specific.

## Khmer NLP tooling for normalization and segmentation

### Takeaway
For a Rust bot, the key tool is the SIL Khmer normalizer (MIT). It implements the Unicode L2/22-290 Khmer encoding proposal and is ported, among other languages, to Rust as `betterkhmer`. For segmentation, `khmer-nltk` and `khmercut` (both Apache-2.0, Python) are the standard tools. SEA-LION lists Khmer among its supported languages.

### Cited Findings
- sillsdev/khmer-normalizer: "normalizes Khmer text according to the proposed normal encoding structure at https://www.unicode.org/L2/L2022/22290-khmer-encoding.pdf ... It does not attempt to identify faulty text, merely to ensure that two strings that would have rendered the same are output as the same string." Example: "ខែ្មរ is corrected to ខ្មែរ". npm package `khmer-normalizer`; LICENSE.md: "The MIT License, Copyright (c) 2017-2024 SIL International" — [GitHub](https://github.com/sillsdev/khmer-normalizer)
- seanghay/betterkhmer: "Khmer Unicode normalizer ported to 18 languages. All implementations expose a single `normalize()` function and pass the same 10,085-line fixture suite." Ports include Rust (`rust/betterkhmer/src/lib.rs`), Python and Go. "This is not published to any package registry." The README says it is "Based on the original khmer-normalizer ... by SIL Global, MIT license", but the GitHub license API returns 404 (no LICENSE file detected), so the repo's own license is unclear — [GitHub](https://github.com/seanghay/betterkhmer)
- khmer-nltk: sentence segmentation, word segmentation, POS, NER; `pip install khmer-nltk`; Apache-2.0 (GitHub API; PyPI v1.6) — [GitHub](https://github.com/VietHoang1512/khmer-nltk), [PyPI](https://pypi.org/project/khmer-nltk/)
- khmercut: "A (fast) Khmer word segmentation toolkit"; a CRF tokenizer plus a distilled neural model (`khmercut[nn]`) that "can split compound words"; PyPI license "Apache License 2.0", v0.2.0 — [GitHub](https://github.com/seanghay/khmercut), [PyPI](https://pypi.org/project/khmercut/)
- seanghay/tha: "Khmer Text Normalization and Verbalization Toolkit", Apache-2.0 (numbers/dates to words, useful for digit handling); vengmony/khmer-nlp-toolkit: JS segmentation + normalization, MIT — [tha](https://github.com/seanghay/tha), [khmer-nlp-toolkit](https://github.com/vengmony/khmer-nlp-toolkit)
- The PrahokBART paper describes Khmer normalization as "invisible character removal and encoding normalization", because the complex script causes encoding ambiguities that hurt NLP models (per search summary) — [arXiv 2512.13552](https://arxiv.org/html/2512.13552v1)
- SEA-LION models support 11 SEA languages including Khmer; SEA-LION v4 is multimodal (Gemma-based) — [arXiv 2504.05747](https://arxiv.org/abs/2504.05747), [DeepMind Gemmaverse](https://deepmind.google/models/gemma/gemmaverse/sea-lion-v4/)

### Inferences
- Scammers can use visually identical but differently encoded Khmer (e.g. ែ before ្ម) to dodge naive substring rules. Running the SIL/betterkhmer normalization before keyword matching closes that gap cheaply. The current rules already strip zero-width spaces and map Khmer digits (per commit 04dc396).
- Keyword rules probably don't need segmentation. An ML or embedding path would need khmercut or khmer-nltk, via Python or ported dictionaries.

### Gaps
- I did not verify whether betterkhmer's Rust port is complete, tested in CI, or licensed. Confirm with the author or vendor SIL's MIT implementation instead.
- SEA-LION's Khmer quality on scam classification is not benchmarked in any source I found.

## Recommendation: which datasets to use and how

### Takeaway
Keep CheckSen's hand-curated Khmer/English v0 set as the primary benchmark, because no public Khmer data exists. Add attributed, redistributable external slices for cross-lingual and link checks: Vietnamese CC BY 4.0, Mishra & Soni CC BY 4.0, UCI CC BY 4.0 ham, and bopbi CC0. Keep NC and unknown-license sets (Smishtank, Kaggle PH, Ngeth) behind a fetch script and out of git.

### Cited Findings
- License facts for each recommendation are cited in the inventory table above (Vietnamese CC BY 4.0 [HF](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset); Mishra CC BY 4.0 [Mendeley](https://data.mendeley.com/datasets/f45bkkt8pr/1); UCI CC BY 4.0 [UCI](https://archive.ics.uci.edu/dataset/228/sms+spam+collection); bopbi CC0 [GitHub](https://github.com/bopbi/indonesia-sms-spam-dataset); Smishtank CC BY-NC-SA 4.0 [arXiv](https://arxiv.org/html/2402.18430)).

### Inferences
1. **Primary (Khmer):** keep growing `evals/data/v0.jsonl` from Cambodian official warnings and consented forwards. Tag each row with its provenance (`verbatim`, `source_url`, `source_date`), like the JSONL schema below. No public set can replace it.
2. **Vietnamese slice (vendorable):** copy `test.csv` (597 rows) into e.g. `evals/data/external/vi_tran2026_test.csv` with a NOTICE giving the authors, the HF URL and "CC BY 4.0". Use it (a) as a false-positive check that the Khmer/English rules don't fire on legitimate Vietnamese OTP/government notices, and (b) to test the language-independent link analyzer on the rows that keep real URLs (e.g. `vietcombank.vn-gll.top`, `vneid.chinhphu-gov.vip`). Report it as a separate score. Don't mix it into the Khmer recall number.
3. **English slice (vendorable):** take Mishra & Soni `Smishing` rows, case-fold the labels, dedup against UCI, and use them for English recall. Use a UCI ham sample for the English false-positive rate. Both need attribution. Treat them as "legacy English", not as 2024–2026 representative data.
4. **Indonesian (vendorable, tiny):** the bopbi loan and prize files (CC0) are a cheap extra check for loan/prize bait. Redact the phone numbers.
5. **Fetch-only:** Smishtank (NC-SA) for URL-category stress tests. Philippine Kaggle sets once their licenses are confirmed. Never commit them.
6. **Ngeth job ads:** email the author for the public file and license. If the terms allow, build a "job lure" category (Khmer/Chinese/English) from the anonymized ad text.
7. **Normalization:** vendor or port the SIL MIT normalizer (or betterkhmer's Rust port once its license is confirmed) and apply it before rule matching. Add a test case with a mis-ordered cluster such as "ខែ្មរ" vs "ខ្មែរ".

### Gaps
- The Vietnamese dataset's paper and IRB claims are unverified. It appeared on HF in July–August 2026 and may be revised.

## Examples (JSONL)

Real Southeast Asian scam/spam messages found during this research. None are Khmer: I found no real, public, licensed Khmer scam message corpus. Vietnamese rows are CC BY 4.0 (Tran et al.), Indonesian rows are CC0 (bopbi), the Philippine row's license is unclear, and the Ngeth rows are quotations from a report (fair-use quotation; not licensed for bulk reuse).

```jsonl
{"text":"Tai khoan cua ban dang duoc dang nhap tren thiet bi khac, neu khong phai ban dang nhap vui long vao https://vietcombank.vn-gll.top de sua doi mat khau hoac thoat khoi thiet bi kia","lang":"vi","category":"bank_impersonation_phishing_link","label":"scam","verbatim":true,"source_url":"https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset","source_date":"2026-05-28","notes":"CC BY 4.0. Lookalike bank domain (vietcombank.vn-gll.top); unaccented Vietnamese."}
{"text":"Kính gửi người dùng AgriBanK, điểm tài khoản của bạn đã được đổi thành điều kiện quà tặng. Vu lòng đăng nhập www.bank.vip ngay để đổi quà. Nếu quá hạn, nó sẽ không được chấp nhận.","lang":"vi","category":"bank_impersonation_reward_points","label":"scam","verbatim":true,"source_url":"https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset","source_date":"2026-06-04","notes":"CC BY 4.0. Dataset date '4/6/2026' read as d/m/y. Reward-points expiry urgency."}
{"text":"Chao ban, minh la nhan su tu TikTok Shop. Hien tai ben minh can tuyen CTV tuong tac like video, thu nhap [MONEY]-[MONEY]/ngay nhan luong theo gio. Bấm link nhận việc: [URL]","lang":"vi","category":"task_job_scam","label":"scam","verbatim":false,"source_url":"https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset","source_date":"2026-07-22","notes":"CC BY 4.0. PII tokens ([MONEY],[URL]) inserted by the dataset authors. Like-for-pay task scam, same pattern as Cambodian Telegram task scams."}
{"text":"[VNe-lD] Cục Cảnh sát QLHC thông báo: Hồ sơ định danh điện tử mức độ 2 của công dân bị lỗi đồng bộ dữ liệu dân cư. Yêu cầu truy cập để xác thực lại: http://vneid.chinhphu-gov.vip","lang":"vi","category":"government_police_impersonation","label":"scam","verbatim":true,"source_url":"https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset","source_date":"2026-07-22","notes":"CC BY 4.0. Police/national e-ID impersonation with lookalike gov domain; sender spoofed with l for I."}
{"text":"[DlNh_Ph0ng_Group] Dự án khởi nghiệp công nghệ 4.0, cam kết lợi nhuận 30%/tháng khg cần làm việc, chỉ cần đầu tư gói ban đầu. Xem slide dự án: http://dinhphong.dautu-40.online","lang":"vi","category":"investment_scam","label":"scam","verbatim":true,"source_url":"https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset","source_date":"2026-07-22","notes":"CC BY 4.0. Guaranteed 30%/month return; leetspeak sender name."}
{"text":"Rj https://DWOK.gemhay.me dang ky tai khoan nhan ngay 2'9'[MONEY], nap dau duoc thuong 1'0'0% xs","lang":"vi","category":"online_gambling_promo","label":"scam","verbatim":false,"source_url":"https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_dataset","source_date":"2026-07-21","notes":"CC BY 4.0. [MONEY] token inserted by dataset authors. Digits split with apostrophes to evade filters."}
{"text":"Ass,,Bpk/Ibu\nTersedia Pinjmn\nTmpa Agunan\nDngn\nBung 2%/Thn\nMiniml 5 jt S/D 500jt\nUntuk Inf0 Chat\nWhatsap [PHONE]","lang":"id","category":"loan_scam","label":"scam","verbatim":false,"source_url":"https://github.com/bopbi/indonesia-sms-spam-dataset/blob/main/loan/1.txt","source_date":"","notes":"CC0 1.0. Phone number redacted by me. No-collateral loan bait with abbreviations/leetspeak (Inf0). Undated; repo created 2021-07."}
{"text":"BIG PR0M0 CUCI GUDANG..!!!\nIPHONE:750ribu\nSAMSUNG:750ribu\nOPPO:750ribu\nVIVO:750ribu\ndan laptOp 1jt minat \nSilahkan cat/wa [PHONE]","lang":"id","category":"fake_shop_too_cheap","label":"scam","verbatim":false,"source_url":"https://github.com/bopbi/indonesia-sms-spam-dataset/blob/main/non-provider-promo/1.txt","source_date":"","notes":"CC0 1.0. Phone redacted by me. Too-good-to-be-true phone prices."}
{"text":"Welcome ! your have P1222 for S!ot , \nWeb: 11y.life     \nGood Luck!C","lang":"en","category":"online_gambling_promo","label":"scam","verbatim":true,"source_url":"https://github.com/AGR-Yes/ScamMessagesPhilippines/blob/main/Raw%20Datasets/SPAM_SMS.csv","source_date":"2022-11-12","notes":"Philippines (bwandowando Kaggle data, mirrored). License unclear, so don't commit. Obfuscated 'S!ot'."}
{"text":"Your passport and cellphone will NOT be held … You're free to go WHENEVER you want","lang":"en","category":"scam_compound_recruitment","label":"scam","verbatim":true,"source_url":"https://www.abc.net.au/news/2026-09-25/cambodia-scam-industry-job-advertisements/107185964","source_date":"2026-09-25","notes":"Quoted by ABC from Moses Ngeth's Cambodian Telegram job-ad dataset. Recruitment lure aimed at workers, not victims. Ellipsis is ABC's."}
{"text":"Position: Customer Service, replying to customer chats (Platform Game). Salary: $600 – $800 + $100. English 30% – 40%. Typing 30 wpm up.","lang":"en","category":"scam_compound_recruitment","label":"scam","verbatim":true,"source_url":"https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf","source_date":"","notes":"Ad 236 in Ngeth dataset (Apr 2023 – Jul 2026). Report translates Khmer/Chinese ads, so original language not certain."}
{"text":"Find only 5 clients per day; exceeding target pays $1 per person.","lang":"en","category":"scam_compound_recruitment","label":"scam","verbatim":true,"source_url":"https://cms.mosesngeth.com/wp-content/uploads/2026/09/Cutting_the_Grass_Not_the_Root.pdf","source_date":"","notes":"Ad 1895 ('Add Contact' victim-finder role). May be a translation by the report author."}
```
