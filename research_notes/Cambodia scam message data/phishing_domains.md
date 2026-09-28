# Phishing and lookalike domains targeting Cambodian banks, wallets, Bakong/NBC and gov.kh (2024–2026), plus official allow-list

Research date: 2026-09-28. Method: bank/government warnings (web search + curl where pages allowed it), Phishing.Database ACTIVE list, OpenPhish free feed, URLhaus text feed, urlscan.io public search API (prefix queries such as `page.domain:wingbank*` and title queries such as `page.title:"Wing Bank"`), DNS and HTTPS checks of official domains, and IANA and RDAP bootstrap lookups for `.kh`. No phishing page was visited; every suspicious domain below comes only from feed or search metadata.

Tool notes:
- crt.sh returned `[]` for `%ababank%`, `%acledabank%`, `%wingbank%` and `%bakong%`, with and without `exclude=expired`. It was unusable in this session, so every "CT" signal below is the `certstream-suspicious` source tag on urlscan.io, which scans domains that appear in CT logs.
- urlscan blocks leading wildcards for anonymous users, so only prefix queries (`brand*`) and title queries were possible.
- OpenPhish free feed (300 URLs) and the URLhaus text feed (59,227 URLs) had no Cambodian brand hits on 2026-09-28.
- The ababank.com, khmertimeskh.com and phnompenhpost.com pages sit behind a Cloudflare challenge (HTTP 403), so their content comes from search-engine snippets.

## Q1. Which phishing domains impersonating Cambodian banks, wallets, Bakong/NBC, Telegram or ministries were reported in 2024–2026?

### Takeaway
Few *officially confirmed* domains with dates exist in public sources. The confirmed ones are ABA's own warning lists (ababkonline.com, ababnkonline.com and four `.xyz` sender domains) and the Immigration Department's cambodia-e-arrival.com (9 Apr 2025). urlscan.io, however, shows a large and clearly malicious-looking cluster from 2025–2026:
- Wing "lucky wheel" sites (wingbank-win.com, wingbank-lucky-gift.com and similar) from Oct 2025
- ABA "loan" and "statement verification" clones
- ACLEDA internet-banking clones such as acledainternetbank.com and kh.bank.aceldaa.com

Most of these are unconfirmed by any official source.

### Cited Findings

#### Table 1: Confirmed phishing or fraudulent domains (official warning or feed-listed)

Confirmation tiers:
- **A** = official warning by the impersonated institution or the government.
- **B** = listed by a public threat feed or tagged `phishing` by a third-party urlscan submitter. This is automated and can be wrong; see the false-positive note below Table 1.

| Domain | Impersonated brand | Source URL | Date | Confirmed by (tier) |
|---|---|---|---|---|
| ababkonline.com | ABA Bank | [ABA "Be aware of financial scammers!"](https://www.ababank.com/en/aba-news/be-aware-of-financial-scammers/); also [ABA "Stay protected from financial scammers!"](https://www.ababank.com/en/aba-news/stay-protected-from-financial-scammers/) | Page date not visible (Cloudflare 403); found via search snippet 2026-09-28 | ABA Bank (A) |
| ababnkonline.com | ABA Bank | same as above | same | ABA Bank (A) |
| advancebankasia.xyz (email sender domain) | ABA (Advanced Bank of Asia) | [ABA "Phishing Security Advisory"](https://www.ababank.com/en/aba-news/phishing-security-advisory/) | Undated in snippet | ABA Bank (A) |
| ababankofasla.xyz (email; "asla" swaps i→l) | ABA | same | same | ABA Bank (A) |
| advancebankofasia.xyz (email) | ABA | same | same | ABA Bank (A) |
| ababnkofasla.xyz (email) | ABA | same | same | ABA Bank (A) |
| cambodia-e-arrival.com | General Dept. of Immigration / Ministry of Interior (e-Arrival) | [Asia News Network, 10 Apr 2025](https://asianews.network/cambodias-immigration-department-warns-of-illegal-arrival-website/) | GDI statement 2025-04-09 | GDI, Ministry of Interior (A). Official site named as `www.arrival.gov.kh` |
| (unnamed) fake e-entry-permit websites | GDI | [information.gov.kh article 171470](https://www.information.gov.kh/articles/171470) | Oct 2025 (per search snippet) | GDI (A). No domain names retrievable |
| (unnamed) fake Cambodia Post parcel-payment site | Cambodia Post | [Khmer Times 501662773](https://www.khmertimeskh.com/501662773/cambodia-post-warns-of-fake-website/); forum discussion dated 2025-04-06 at [Cambodia Expats Online](https://cambodiaexpatsonline.com/general-chatter/scam-warning-t60550.html) | ~Apr 2025 | Cambodia Post (A). Domain not retrievable (403) |
| wingbank-online.com, wingapp.xyz | Wing Bank | [Wing Bank Scam Awareness page](https://www.wingbank.com.kh/en/company/security-awareness-center/scam-awareness) | Page current 2026-09-28 | Wing Bank (A, but given as "e.g.", so possibly illustrative rather than observed) |
| ababank.life | ABA | [Phishing.Database ACTIVE list](https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt) | Listed as of 2026-09-28 | Phishing.Database (B) |
| ababnk.quickonline.pro (page title "Registration - ABA Bank") | ABA | [urlscan search](https://urlscan.io/api/v1/search/?q=page.title:%22ABA%20Bank%22) | scanned 2024-10-14 | urlscan tags `@ecarlesi, possiblethreat, phishing` (B) |
| wingbank-lucky-win.com (title "Wing Bank") | Wing Bank | [urlscan search](https://urlscan.io/api/v1/search/?q=page.title:%22Wing%20Bank%22) | scanned 2025-10-20 | urlscan tags `@ecarlesi, possiblethreat, phishing` (B) |
| aba-ssllottss.website (title "ABA Mobile") | ABA Mobile app | [urlscan search](https://urlscan.io/api/v1/search/?q=page.title:%22ABA%20Mobile%22) | scanned 2026-09-09 | urlscan tag `possiblethreat` (B, weak) |
| www.khqrrkjp.com | KHQR (NBC standard) | [urlscan search](https://urlscan.io/api/v1/search/?q=page.domain:khqr*) | scanned 2026-08-07 | urlscan tags `possiblethreat, phishing` (B). Brand link to KHQR is only by name |

Older, pre-2024 reference cases (outside the window but useful as test fixtures):
- www.canadias.com impersonated Canadia Bank in an SMS "your account has been logged in through another platform". The Department of Technology Crime warning was dated 2021-01-15 and the MPTC phishing warning 2021-01-21 ([Cambodia Expats Online repost](https://cambodiaexpatsonline.com/newsworthy/police-warn-fake-messages-from-canadia-bank-users-t42842.html)).
- cambodiaimmigration.org was named as a bogus e-visa site by MFAIC ([Daily Star](https://www.thedailystar.net/asia/news/fake-visa-sites-cambodia-warn-tourist-1698784); [Phnom Penh Post](https://www.phnompenhpost.com/national/govt-warns-tourists-over-use-fake-visa-websites)). The date is pre-2024 (the article id suggests ~2019). The official site is evisa.gov.kh.

False-positive warning on tier B: the same automated urlscan tagger (`@ecarlesi, possiblethreat`) also flagged **official** Hattha Bank hosts:
- hib.hatthabank.com (2026-05-04)
- hatthapay.hatthabank.com (2026-03-27)
- exclusive.hatthabank.com (2026-06-03)
- auth-api.hatthabank.com (2024-08-08)

Phishing.Database lists mail.mbbank.com.kh, law.puc.edu.kh and several `*.wakimart.com.kh`. These are likely compromised or misclassified legitimate `.kh` hosts, not brand lookalikes ([Phishing.Database ACTIVE](https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt); [urlscan hattha query](https://urlscan.io/api/v1/search/?q=page.domain:hattha*)).

#### Table 2: Suspicious registrations and scans (UNCONFIRMED: no official warning, no feed listing)

All come from urlscan.io search results on 2026-09-28. "Date" is the most recent urlscan scan date shown; for `certstream-suspicious` entries this is close to certificate issuance. The reason each one is suspicious is the domain shape and/or the page title that urlscan recorded, not a visit. Treat as test candidates, not ground truth.

| Domain | Brand | urlscan date | Signal (title / tag / host country) | Source query |
|---|---|---|---|---|
| ababank.biz | ABA | 2026-08-06 | Title "ABA Bank - កម្ចីរហ័ស និងងាយស្រួល" ("quick and easy loans"): fake-loan lure | [q](https://urlscan.io/api/v1/search/?q=page.title:%22ABA%20Bank%22) |
| theababank.com | ABA | 2026-08-06 | Title "The ABA Bank" | same |
| myababank.com | ABA | 2026-06-15 | Title "Home \| ABA Bank Cambodia" | same |
| thiqahbank.com | ABA | 2026-06-21 | Title "Home \| ABA Bank Cambodia" on an unrelated name (cloned site) | same |
| www.abafina.com.growmarts.com | ABA | 2026-03-26 | Title "Home - ABA Bank Cambodia" (subdomain abuse) | same |
| ababk.online | ABA | 2025-11-18 | Title "ABA BANK", ZA-hosted | same |
| verify.ababank.systems | ABA | 2025-09-05 | Title "ABA Bank Statement Verification"; certstream-suspicious | same |
| aba-bank.com | ABA | 2025-07-11 | Title "ABA Bank" | same |
| ababonline.com | ABA | 2024-12-29 | Title "Aba Bank" (one letter off the confirmed ababkonline.com) | same |
| abacun.online | ABA | 2024-12-23 | Title "Registration - ABA Bank" | same |
| aba-mobile.website | ABA Mobile | 2026-09-14 | Title "ABA Mobile" | [q](https://urlscan.io/api/v1/search/?q=page.title:%22ABA%20Mobile%22) |
| ababanh.com | ABA Mobile | 2026-05-02 | Title "ABA Mobile Remix", LT-hosted | same |
| abbabank.pages.dev | ABA | 2026-08-29 | Title "Bagi-Bagi Saldo ABA BANK Gratis" (Indonesian "free balance giveaway") | [q](https://urlscan.io/api/v1/search/?q=page.title:%22ABA%20Bank%22) |
| ababank.xyz, aba.ababank.xyz | ABA | 2025-08-25 / 2025-10-03 | SG-hosted | [q](https://urlscan.io/api/v1/search/?q=page.domain:ababank*) |
| ababank-com.tcp4.me | ABA | 2025-10-08 | Dynamic-DNS subdomain; certstream-suspicious | same |
| ababank365.sharepoing.com / ababank365.sharepoiny.com / ababank365.shareppint.com | ABA (staff O365) | 2026-09-11 / 2026-03-08 / 2025-11-07 | Typo-SharePoint domains, probably spear-phishing bank staff | same |
| ababank-91049help.zendesk.com | ABA | 2026-07-22 | Title "Zaloguj do ABA Bank" (Polish "log in"); Zendesk trial abuse | same |
| ababank24.com, ababank.info, ababank.net, ababank.forum, ababank.ru, ababank.ch | ABA | 2025-09 → 2026-09 | Alternate TLD/suffix squats, content unknown | same |
| acledainternetbank.com | ACLEDA | 2026-02-24 | Title "ACLEDA Retail Internet Banking", SG-hosted; official is acledainternetbank.**com.kh** | [q](https://urlscan.io/api/v1/search/?q=page.title:%22ACLEDA%22) |
| kh.bank.aceldaa.com | ACLEDA | 2025-09-21 | Title "ACLEDA Bank - Leading Financial Institution in Cambodia"; letter transposition | same |
| acle-da.com | ACLEDA | 2025-09-06 | Title "ACLEDA BANK", ZA-hosted | same |
| web.cbpost.online | ACLEDA | 2025-02-26 | Title "ACLEDA Bank Login", NL-hosted, unrelated domain | same |
| acledasb.com, acledabk.com | ACLEDA | 2025-02-10 / 2024-10-28 | Title "Acleda Plc - Empowering Your Finances…", FR-hosted | same |
| acledamfb.online | ACLEDA | 2025-04-07 | Title "Acleda MFB Global" | same |
| acledabankplc-87994.zendesk.com, acledabankplc-66273.zendesk.com, acledamobile0768802626.zendesk.com | ACLEDA | 2026-09-05, 2026-07-30, 2024-11-16 | Title "Anmelden bei ACLEDA Bank Plc." / "Sign in to ACLEDA Mobile"; Zendesk trial abuse | same |
| acledabank-express.com, www.acledabank-acc.com, www.acledabank-internetbanking.com, acledabank.vip, acledabank.net, acledabank.com (IN-hosted), www.acledabankcustomerservice.online, acleda-bank.com, acleda-khm.com, www.acleda.auths.co | ACLEDA | 2024-03 → 2026-09 | Brand+keyword / alt-TLD; several certstream-suspicious | [q](https://urlscan.io/api/v1/search/?q=page.domain:acleda*) |
| wingbank-win.com, wingbank-lucky-gift.com, lucky-wingbank.com | Wing | 2025-10-07 → 2025-10-16 | Title "Wing Bank Lucky Wheel - Spin to Win Amazing Prizes! 🎰" | [q](https://urlscan.io/api/v1/search/?q=page.title:%22Wing%20Bank%22) |
| wingbank-win-lucky.com, wingbank-spin-gift.com, wingbank-lucky.com | Wing | 2025-10-02 → 2026-01-31 | Title "Wing Bank"; VN/US-hosted; certstream-suspicious | same; [q](https://urlscan.io/api/v1/search/?q=page.domain:wingbank*) |
| wingbank.app | Wing | 2025-10-09 | Title "កង់នៃសំណាង - Wing Bank \| ចូលរួមឥឡូវនេះដើម្បីទទួលបានរង្វាន់ធំ" ("wheel of fortune… join now to receive a big prize"), VN-hosted | same |
| www.wimngeacash.com | Wing | 2025-12-02 | Khmer title "ចុះឈ្មោះ និងទទួលបានប្រាក់ឥឡូវនេះជាមួយធនា… \| Wing Bank" ("register and receive money now") | same |
| wingbkk.com, wingdigi.store, wingbank-2qlr8kzd.manus.space | Wing | 2025-10-25, 2026-08-11, 2025-11-24 | Title "Wing Bank Clone" / "Wing Bank UI Clone" (could be demos) | same |
| cambodiamybank.com | Wing | 2026-06-25 | Title "Wing Bank Trading Platform" (investment-scam lure) | same |
| wingbank.xyz / .shop / .vip / .online / .org / .co | Wing | all 2025-04-22 | Same-day bulk registration: either defensive or malicious, unknown | [q](https://urlscan.io/api/v1/search/?q=page.domain:wingbank*) |
| wingbanks.com, wingbanks.cc, wingbank.store, wingbank.site, wingbank.net, wingbank.loan, wingbank.com.bid, wingbank.com.date, wingbank.com.store | Wing | 2024-02 → 2026-07 | Alt-TLD / plural squats | same |
| bakongwallet.com | Bakong | 2025-03-20 | certstream-suspicious | [q](https://urlscan.io/api/v1/search/?q=page.domain:bakong*) |
| www.bakong029.com, bakong123.com, bakongex.pro, bakongmoney.com | Bakong | 2023-01 → 2025-08 | Brand + number / finance words | same |
| api-bakong-by-limvisa.shop | Bakong | 2026-09-18 | Namecheap-registered | [q](https://urlscan.io/api/v1/search/?q=page.title:%22Bakong%22) |
| khqr.rs-service.cam, khqr.digitalsmm.cam | KHQR | 2025-02-01, 2024-11-05 | `.cam` TLD; likely SMM-panel payment pages rather than phishing | [q](https://urlscan.io/api/v1/search/?q=page.domain:khqr*) |
| vattanaccommercialbank.com, vattanacbank.net, vattanacbank.biz | Vattanac | 2026-07-11, 2026-09-14, 2026-07-26 | certstream-suspicious; LU-hosted (first) | [q](https://urlscan.io/api/v1/search/?q=page.domain:vattanac*) |
| chipmongcommercialbank.com | Chip Mong Bank | 2026-03-14 | certstream-suspicious | [q](https://urlscan.io/api/v1/search/?q=page.domain:chipmong*) |
| sathapanabank.com, sathapana.global, sathapana.co.com | Sathapana | 2026-04-22, 2023-12-06 (tagged possiblethreat), 2024-03-14 | Alt names | [q](https://urlscan.io/api/v1/search/?q=page.domain:sathapana*) |
| hatthabanks.com | Hattha Bank | 2025-02-03 | Plural squat of hatthabank.com | [q](https://urlscan.io/api/v1/search/?q=page.domain:hattha*) |

Brand-hoarding noise to exclude from "Cambodia-targeted" counts:
- A single Linode IP (45.79.222.138) hosts `ababank.ph`, `acledabank.com.ph`, `acledainternetbank.ph`, `wingbank.ph`, `vattanacbank.ph` and hundreds of `truemoney-<brand>.com.ph` names, e.g. truemoney-bankofamerica.com.ph and truemoney-nhs.ph (Aug–Sep 2026).
- This is a generic `.ph` squatting operation across global brands, not a Cambodia-specific campaign ([urlscan truemoney-*](https://urlscan.io/api/v1/search/?q=page.domain:truemoney-*)).

Threat-intel context:
- Infoblox and Chong Lua Dao tied an Android banking-trojan malware-as-a-service to the K99 Triumph City compound in Cambodia. The operation registers about 35 new domains a month that spoof banks, social-security, tax, utilities and police in at least 21 countries (mainly Indonesia, Thailand, Spain and Türkiye), not Cambodian brands ([Infoblox blog](https://www.infoblox.com/blog/threat-intelligence/scams-slaves-and-malware-as-a-service-tracking-a-trojan-to-cambodias-scam-centers/); [Intelligent CISO, 2026-04-13](https://www.intelligentciso.com/2026/04/13/infoblox-threat-intelligence-links-global-mobile-banking-fraud-surge-to-cambodian-scam-compounds/)).
- Canadia Bank warns about "malware scam via fake apps or links" sent via SMS, Facebook and Telegram ([Canadia Bank knowledgebase](https://www.canadiabank.com.kh/knowledgebase-articles/malware-scam-via-fake-apps-or-links)).
- The NBC warned about scams misusing its name, logo and leaders' photos, and urged "maximum vigilance" with unfamiliar links and investment platforms ([Khmer Times](https://www.khmertimeskh.com/501789844/national-bank-of-cambodia-warns-of-escalating-scams-using-forged-identities-and-fake-investment-platforms/)). No domain names are quoted.
- ACLEDA warns against "untrusted third-party apps (PAI and PaiPay)" ([ACLEDA info page](https://acledabank.com.kh/kh/eng//info)). No domains are given.

### Inferences
- The strongest recent pattern for Wing is a **prize-wheel ("lucky wheel / spin gift") campaign**:
  - 7+ domains appeared within about three weeks in Oct 2025.
  - They share page titles and hosting (VN / US anycast).
  - Wing's own page describes "prize winnings" lures.
- For ABA the lures are **quick-loan** (ababank.biz) and **statement verification**.
- For ACLEDA they are **internet-banking login clones**, including on `.com` instead of `.com.kh`.
- Zendesk trial subdomains (`<brand>-<digits>.zendesk.com`) and typo-SharePoint hosts are a distinct subdomain-abuse vector. A rule that only checks the registrable domain misses them.

### Gaps
- No 2024–2026 CamCERT advisory listing Cambodian phishing domains was found. camcert.gov.kh is reachable, but no advisory list was located in the time available.
- ABA's warning pages are undated in the snippets and could not be fetched (Cloudflare), so exact dates for ababkonline.com and the `.xyz` domains are unknown.
- The fake Cambodia Post domain (Apr 2025) and the fake e-permit domains (Oct 2025) were not retrievable.
- No results were found for Prince Bank (the urlscan query errored), Canadia (the prefix query drowned in "canadian*"), AMK, TrueMoney KH, Pi Pay (drowned in Pi Network "pipayment" noise), Telegram lookalikes or ministry lookalikes for 2024–2026.
- PhishTank needs an API key; it was not queried.

## Q2. What naming patterns do they use?

### Takeaway
The patterns fall into eight groups:
1. Brand + lure word joined by a hyphen (win, lucky, gift, spin, express, acc, internetbanking, customerservice, help, verify).
2. Single-letter typos and transpositions (ababk, ababnk, aceldaa, acle-da, wimngeacash).
3. The same brand label on a different public suffix: `.com` instead of `.com.kh`, or `.xyz`, `.vip`, `.online`, `.site`, `.store`, `.biz`, `.app`, `.cam`, `.pro`, `.website`, `.life`, `.systems`.
4. Brand as a subdomain of an unrelated or free-hosting domain (zendesk.com, pages.dev, github.io, manus.space, tcp4.me, growmarts.com, auths.co).
5. Cloned page titles on unrelated domains.
6. "Legal-name" expansions (advancebankofasia, vattanaccommercialbank, chipmongcommercialbank).
7. Plurals (wingbanks, hatthabanks).
8. Brand + digits (bakong029, bakong123).

### Cited Findings

#### Table 4: Naming patterns

| Pattern | Examples (tier) | Source |
|---|---|---|
| Letter drop / transposition of the brand | ababkonline.com, ababnkonline.com (A); ababnkofasla.xyz (A); ababk.online, kh.bank.aceldaa.com, www.wimngeacash.com (unconf.) | [ABA](https://www.ababank.com/en/aba-news/be-aware-of-financial-scammers/); [urlscan](https://urlscan.io/api/v1/search/?q=page.title:%22ACLEDA%22) |
| Homoglyph i→l in words next to the brand | ababankof**asla**.xyz ("asia") (A) | [ABA advisory](https://www.ababank.com/en/aba-news/phishing-security-advisory/) |
| Brand + "online" | ababkonline, ababonline.com, wingbank-online.com | ABA; [Wing](https://www.wingbank.com.kh/en/company/security-awareness-center/scam-awareness) |
| Brand + prize words | wingbank-win / -lucky / -lucky-gift / -spin-gift / -win-lucky / lucky-wingbank (.com) | [urlscan](https://urlscan.io/api/v1/search/?q=page.title:%22Wing%20Bank%22) |
| Brand + banking/service words | acledabank-internetbanking, acledabank-express, acledabank-acc, acledabankcustomerservice.online, verify.ababank.systems | [urlscan](https://urlscan.io/api/v1/search/?q=page.domain:acleda*) |
| Legal-name expansion | advancebankasia.xyz, advancebankofasia.xyz (A); vattanaccommercialbank.com, chipmongcommercialbank.com | ABA; urlscan |
| Official label on the wrong suffix | acledainternetbank.com (vs .com.kh); acledabank.com / .net / .vip; ababank.xyz / .biz / .net / .info / .life; wingbank.xyz / .shop / .vip / .online / .site / .store / .app / .co | urlscan; Phishing.Database |
| Cheap / abused TLDs seen | .xyz, .vip, .online, .site, .store, .shop, .biz, .app, .cam, .pro, .website, .life, .systems, .buzz, .cyou, .click | urlscan results above |
| Subdomain abuse on SaaS / free hosting | ababank-91049help.zendesk.com, acledabankplc-87994.zendesk.com; abbabank.pages.dev; wingbank-2qlr8kzd.manus.space; ababank-com.tcp4.me (dynamic DNS); www.abafina.com.growmarts.com | urlscan |
| Typosquatted SaaS with the brand in the subdomain | ababank365.sharepoing.com / sharepoiny.com / shareppint.com | [urlscan](https://urlscan.io/api/v1/search/?q=page.domain:ababank*) |
| Plural / suffix squats | wingbanks.com, wingbanks.cc, hatthabanks.com | urlscan |
| Brand + digits | bakong029.com, bakong123.com | urlscan |
| Credential SMS lure with a lookalike (older) | "Your Canadia bank account has been logged in through another platform… Www.canadias.c*m" | [CEO repost of police/MPTC warnings, Jan 2021](https://cambodiaexpatsonline.com/newsworthy/police-warn-fake-messages-from-canadia-bank-users-t42842.html) |
| Punycode | No Cambodian-brand IDN lookalikes found. The only IDN seen was `xn--pbzip-qk9kk38f.chipmong18y.buzz`, which is a gambling-style domain containing "chipmong", not a Chip Mong Bank clone | [urlscan](https://urlscan.io/api/v1/search/?q=page.domain:chipmong*) |

Wing Bank's official red flags (verbatim):
- "URL looks strange (e.g., wingbank-online.com, wingapp.xyz)"
- "Website domain is not www.wingbank.com.kh"
- Fake Telegram groups have names "slightly different (e.g., 'Wing Loan Khmer')"

Source: [Wing](https://www.wingbank.com.kh/en/company/security-awareness-center/scam-awareness).

### Inferences
- Rules keyed only on `brand token + official registrable domain` will false-positive on the official secondary domains listed in Q3, and on third-party Bakong or KHQR integration subdomains:
  - acledainternetbank.com.kh, acledabankmb.com.kh, acledasecurities.com.kh, acledabank.com.la
  - bakong.acledabank.com.kh, bakong.maybank2u.com.kh, bakong.cimbcambodia.com, bakong.icbc.com.kh, bakong.ucb.com.kh, bakong.sbilhbank.com.kh, bakong.pg.prod.bridgebank.com.kh, bakong.bankofchina.com.kh, bakong.wbfinance.com.kh
- The short token "wing" also collides with many unrelated names. "wingbank" is a safer stem.
- The current checksen rules (`src/analyzers/link.rs`) have one `official` domain per brand. They will need multi-domain allow-lists.

### Gaps
- Telegram-lookalike domains (e.g. `telegram-*`, `t-me.*`) aimed at Cambodians were not found in the sources checked.
- Punycode Khmer-brand lookalikes were not observed. This is absence of evidence only, because leading-wildcard and regex queries were unavailable.

## Q3. What are the verified official domains per brand?

### Takeaway
Every domain below resolved in DNS on 2026-09-28. Most returned HTTPS 200 with a brand-matching `<title>`.
- Some are Cloudflare-challenged (ababank.com, hatthabank.com, mef.gov.kh, trc.gov.kh) or timed out from this vantage (wingmoney.com, princebank.com.kh, prasac.com.kh, gdt.gov.kh, mfaic.gov.kh).
- Where no institutional statement could be cited, the evidence is "live + brand title", or observation of official subdomains on urlscan. These are flagged in the table.

### Cited Findings

#### Table 3: Official domains (allow-list candidates)

Verification legend: **S** = named by the institution or government in a cited statement. **L** = live check on 2026-09-28 (DNS resolves; HTTPS status/title as shown). **U** = urlscan shows operational subdomains hosted in Cambodia (KH).

| Brand | Official domain(s) | Evidence |
|---|---|---|
| ABA Bank | ababank.com (incl. www, business.ababank.com, mapp., billzone., careers., pay., join.) | S: ABA says the legit site "has ababank.com in the domain name" and that emails come only from @ababank.com ([ABA](https://www.ababank.com/en/aba-news/be-aware-of-financial-scammers/)). L: 403 Cloudflare challenge. U: [urlscan](https://urlscan.io/api/v1/search/?q=page.domain:ababank*) |
| ABA PayWay | payway.com.kh | L: HTTPS 200 at https://www.payway.com.kh/ (empty title). Attribution to ABA not independently cited here (gap) |
| ABA (unclear) | aba-bank.workers.dev (pro-transaction-limits, mobile-app-chat-pre, uat-services…) | U only. Looks like ABA's Cloudflare Workers but ownership is unverified. Do **not** allow-list; do **not** treat as phishing |
| ACLEDA Bank | acledabank.com.kh | L: 200, title "ACLEDA Bank Plc. - Cambodia" ([site](https://www.acledabank.com.kh/)) |
| ACLEDA Internet Bank | acledainternetbank.com.kh | L: 200, redirects to /internetbank/login, title "ACLEDA Internet Banking" |
| ACLEDA merchant / mobile | acledabankmb.com.kh | L: redirects to epaymentportal.acledabank.com.kh "Login - ACLEDA merchant", which confirms ownership |
| ACLEDA Securities | acledasecurities.com.kh | L: 200, title "ACLEDA Securities Plc." |
| ACLEDA Laos (sister) | acledabank.com.la, acledainternetbank.com.la | U: hosted in KH/LA ([urlscan](https://urlscan.io/api/v1/search/?q=page.domain:acleda*)) |
| ACLEDA University | aub.edu.kh | U: title "ACLEDA University of Business - Cambodia" |
| Wing Bank | wingbank.com.kh (incl. ibanking.wingbank.com.kh); security@wingbank.com.kh | S: "Website domain is not www.wingbank.com.kh" is a red flag ([Wing](https://www.wingbank.com.kh/en/company/security-awareness-center/scam-awareness)). L: 200 |
| Wing (legacy / infra) | wingmoney.com; wingbank.com (vnet.wingbank.com hosted in KH) | L: wingmoney.com resolves (103.48.117.25) but timed out. U: vnet.wingbank.com in KH. Treat as probable legacy; not cited officially |
| NBC | nbc.gov.kh | L: 200, Khmer title "ធនាគារជាតិ នៃកម្ពុជា" |
| Bakong | bakong.nbc.gov.kh | L: 200, title "បាគង \| Bakong – The Next-Generation Mobile Payments" ([site](https://bakong.nbc.gov.kh/en/)). Official app on [Google Play](https://play.google.com/store/apps/details?id=jp.co.soramitsu.bakong) (package jp.co.soramitsu.bakong) and [Bakong Tourists](https://play.google.com/store/apps/details?id=kh.gov.nbc.bakong.tourist) (kh.gov.nbc.bakong.tourist) |
| NBC (legacy) | nbc.org.kh | L: resolves, timed out. Unverified |
| Canadia Bank | canadiabank.com.kh | L: 200, title "Canadia Bank Cambodia" |
| Prince Bank | princebank.com.kh | L: resolves (104.248.98.38), HTTPS timed out. Unverified |
| Sathapana Bank | sathapana.com.kh | L: 200, title "Sathapana Bank" |
| AMK Bank | amkbank.com.kh (current); amkcambodia.com (resolves, timed out, probably legacy) | L: amkbank.com.kh 200, title "AMK Bank Plc \| Leading Bank in Cambodia" |
| PRASAC | prasac.com.kh | L: resolves (162.241.51.144), HTTPS timed out. Unverified |
| Hattha Bank | hatthabank.com (hib., hatthapay., api., otp., doc.) | L: www 403 Cloudflare. U: many operational subdomains, doc.hatthabank.com hosted in KH. hattha.com.kh does not resolve |
| Chip Mong Bank | chipmongbank.com | L: 200, title "Home \| Chip Mong Bank" |
| Vattanac Bank | vattanacbank.com | L: 200, title "Vattanac Bank Cambodia - Personal Banking" |
| Maybank Cambodia | maybank2u.com.kh; maybank.com.kh (bakongmcp.maybank.com.kh seen) | L: www.maybank2u.com.kh 200, title "Welcome to Maybank Cambodia" |
| TrueMoney Cambodia | truemoney.com.kh (www only; apex has no A record) | L: 200, title "Wallet - TrueMoney Cambodia" |
| Pi Pay | pipay.com | L: 200, title "Pi Pay" |
| Other banks with Bakong subdomains (allow-list, not impersonation) | cimbcambodia.com, icbc.com.kh, bridgebank.com.kh, sbilhbank.com.kh, sbibank.com.kh, ucb.com.kh, wbfinance.com.kh, bankofchina.com.kh, alphabank.com.kh | U: `bakong.*` subdomains ([urlscan](https://urlscan.io/api/v1/search/?q=page.domain:bakong*)) |
| Smart Axiata | smart.com.kh | L: 200, "Smart Axiata" |
| Cellcard | cellcard.com.kh | L: 200, "សែលកាត" |
| Metfone | metfone.com.kh | L: 200 → metfone.com.kh/kh, "Metfone" |
| Immigration e-Arrival | arrival.gov.kh | S: "www.arrival.gov.kh is the only official government website" ([ANN](https://asianews.network/cambodias-immigration-department-warns-of-illegal-arrival-website/)). L: 200 "Cambodia e-Arrival" |
| e-Visa (MFAIC) | evisa.gov.kh | S: [Daily Star / MFAIC](https://www.thedailystar.net/asia/news/fake-visa-sites-cambodia-warn-tourist-1698784); [Embassy DC](https://www.embassyofcambodiadc.org/news1/list-of-fraud-e-visa-website). L: 302 |
| CamCERT | camcert.gov.kh | L: 200, "CamCERT – National CERT of Cambodia" |
| CamDX | camdx.gov.kh | L: 200 |
| MPTC, Interior, MEF, GDT, MFAIC, TRC | mptc.gov.kh, interior.gov.kh, mef.gov.kh, gdt.gov.kh, mfaic.gov.kh, trc.gov.kh | L: interior.gov.kh 200; mptc, mef and trc return Cloudflare 403; gdt and mfaic timed out; all resolve. TRC is the .kh registry per IANA ([IANA whois](https://www.iana.org/domains/root/db/kh.html)) |
| Cambodia Post | cambodiapost.com.kh | L: 200, "Cambodia-Post" ([privacy page](https://cambodiapost.com.kh/privacy-policy)) |
| Telegram | telegram.org, t.me | L: both resolve to 149.154.167.99 |

### Inferences
- A safe allow-list rule is "registrable domain ∈ the list above, or any `*.gov.kh`".
- Do not generalize to `*.com.kh`. Phishing.Database lists compromised `.com.kh` hosts (e.g. `*.wakimart.com.kh`), and the `.com.kh` suffix is open to any private business.

### Gaps
- No institutional statements were found that name payway.com.kh, wingmoney.com, princebank.com.kh, prasac.com.kh, hatthabank.com, amkbank.com.kh, chipmongbank.com, vattanacbank.com, truemoney.com.kh or pipay.com as official. Their evidence is live-site titles only.
- An NBC list of licensed institutions with websites would be the ideal citation but was not retrieved.

## Q4. Is .kh covered by RDAP/WHOIS for domain-age checks?

### Takeaway
No. `.kh` has no RDAP service in the IANA bootstrap and no public port-43 WHOIS server, so domain age for `.kh` names cannot be obtained programmatically from the registry. Use CT-log first-seen (crt.sh or certstream) or urlscan first-seen as a proxy, and treat `.kh` age as unknown rather than new.

### Cited Findings
#### Table 5: RDAP / .kh findings

| Check (2026-09-28) | Result | Source |
|---|---|---|
| IANA RDAP bootstrap `dns.json` (publication 2026-09-16T19:00:03Z) | `kh` **not present** | [data.iana.org/rdap/dns.json](https://data.iana.org/rdap/dns.json) |
| `rdap.org/domain/ababank.com.kh` | HTTP 404 | [rdap.org](https://rdap.org/domain/ababank.com.kh) |
| `whois -h whois.iana.org kh` | Registry "Telecommunication Regulator of Cambodia (TRC)"; `whois:` field **empty**; "Registration information: http://www.trc.gov.kh"; created 1996-02-20, changed 2026-02-26 | [IANA root db: .kh](https://www.iana.org/domains/root/db/kh.html) |
| `whois.nic.kh` | Hostname does not resolve | local lookup |
| www.trc.gov.kh | Cloudflare 403 to curl; no public lookup API found | local check |

### Inferences
- For `.com`, `.xyz` and similar lookalikes (nearly all the phishing above), RDAP works through the IANA bootstrap. Domain-age checks are useful exactly where the threats are.
- Official `.kh` domains will never produce an age, so a "young domain" rule must not fire on "age unknown".

### Gaps
- Whether TRC offers a web WHOIS (e.g. behind Cloudflare at trc.gov.kh) could not be confirmed.
- Whether crt.sh or certspotter give usable first-seen dates for `.kh` names was not confirmed, because crt.sh returned empty results in this session.

## Examples (JSONL)

Only one full verbatim scam message containing a lookalike link was found. It is pre-2024 and is included as a fixture. The domain was defanged by the source.

```jsonl
{"text":"Your Canadia bank account has been logged in through another platform , Please verify again to protect your rights. Www.canadias.c*m","lang":"en","category":"bank_phishing_link","label":"scam","verbatim":true,"source_url":"https://cambodiaexpatsonline.com/newsworthy/police-warn-fake-messages-from-canadia-bank-users-t42842.html","source_date":"2021-01-15","notes":"Reposted Department of Technology Crime warning; the link (defanged by the source as canadias.c*m, i.e. canadias.com) imitates canadiabank.com.kh; MPTC issued a matching phishing warning 2021-01-21. Outside the 2024–2026 window; no 2024–2026 verbatim message with a lookalike link was found."}
```
