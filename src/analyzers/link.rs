use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{ACCEPT, LOCATION};
use reqwest::{Client, Url, redirect};
use serde_json::Value;
use tokio::sync::OnceCell;
use tokio::time::{Instant, timeout_at};
use url::Host;

use super::{Check, Signal, Subject};

const MAX_REDIRECTS: usize = 5;
const NEW_DOMAIN_DAYS: i64 = 30;
const REDIRECT_BUDGET: Duration = Duration::from_secs(3);
const TOTAL_BUDGET: Duration = Duration::from_secs(4);
const RDAP_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";
const GOVERNMENT: &str = "គេហទំព័ររដ្ឋាភិបាល (gov.kh)";

struct Brand {
    name: &'static str,
    official: &'static [&'static str],
    tokens: &'static [&'static str],
    stems: &'static [&'static str],
    misspelled: &'static [&'static str],
}

const fn brand(
    name: &'static str,
    official: &'static [&'static str],
    tokens: &'static [&'static str],
    stems: &'static [&'static str],
    misspelled: &'static [&'static str],
) -> Brand {
    Brand {
        name,
        official,
        tokens,
        stems,
        misspelled,
    }
}

const BRANDS: [Brand; 11] = [
    brand(
        "ABA",
        &["ababank.com", "payway.com.kh"],
        &["aba", "ababank"],
        &["ababank", "advancebank", "advancedbank"],
        &["ababank"],
    ),
    brand(
        "ACLEDA",
        &[
            "acledabank.com.kh",
            "acledainternetbank.com.kh",
            "acledabankmb.com.kh",
            "acledasecurities.com.kh",
            "acledabank.com.la",
            "acledainternetbank.com.la",
        ],
        &["acleda", "acledabank"],
        &["acleda"],
        &["acleda"],
    ),
    brand(
        "Wing",
        &["wingbank.com.kh"],
        &["wing", "wingbank"],
        &["wingbank"],
        &["wingbank"],
    ),
    brand("Bakong", &["nbc.gov.kh"], &["bakong"], &["bakong"], &[]),
    brand(
        "Canadia",
        &["canadiabank.com.kh"],
        &["canadia", "canadiabank"],
        &["canadiabank"],
        &[],
    ),
    brand(
        "Vattanac",
        &["vattanacbank.com"],
        &["vattanac"],
        &["vattanac"],
        &[],
    ),
    brand(
        "Chip Mong",
        &["chipmongbank.com"],
        &["chipmongbank"],
        &["chipmongbank", "chipmongcommercial"],
        &[],
    ),
    brand(
        "Sathapana",
        &["sathapana.com.kh"],
        &["sathapana"],
        &["sathapana"],
        &[],
    ),
    brand(
        "Hattha",
        &["hatthabank.com"],
        &["hattha", "hatthabank"],
        &["hatthabank"],
        &[],
    ),
    brand(
        "PRASAC",
        &["prasac.com.kh", "kbprasacbank.com.kh"],
        &["prasac"],
        &["prasac"],
        &[],
    ),
    brand(
        "Telegram",
        &["telegram.org", "t.me", "telegram.me"],
        &["telegram"],
        &["telegram"],
        &[],
    ),
];

const OTHER_OFFICIAL: [&str; 20] = [
    "princebank.com.kh",
    "amkbank.com.kh",
    "maybank2u.com.kh",
    "maybank.com.kh",
    "cimbcambodia.com",
    "icbc.com.kh",
    "bridgebank.com.kh",
    "sbilhbank.com.kh",
    "ucb.com.kh",
    "wbfinance.com.kh",
    "bankofchina.com.kh",
    "alphabank.com.kh",
    "bidc.com.kh",
    "lolc.com.kh",
    "mbcambodia.com",
    "truemoney.com.kh",
    "pipay.com",
    "smart.com.kh",
    "cellcard.com.kh",
    "metfone.com.kh",
];

const GOVERNMENT_SERVICES: [&str; 4] = ["arrival", "evisa", "visa", "immigration"];

const BANKING_WORDS: [&str; 11] = [
    "bank", "bnk", "camb", "khmer", "asia", "online", "app", "pay", "login", "verify", "secure",
];

#[derive(Debug)]
pub struct LinkInfo {
    pub host: String,
    pub redirected_to: Option<String>,
    pub age_days: Option<i64>,
}

pub struct LinkChecker {
    http: Client,
    rdap_servers: OnceCell<HashMap<String, Url>>,
}

impl LinkChecker {
    pub fn new() -> reqwest::Result<Self> {
        let http = Client::builder()
            .redirect(redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .user_agent(concat!("CheckSen/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(PublicOnly))
            .build()?;
        Ok(Self {
            http,
            rdap_servers: OnceCell::new(),
        })
    }

    pub async fn check(&self, url: Url) -> Check {
        let start = Instant::now();
        let chain = self.follow_redirects(url, start + REDIRECT_BUDGET).await;
        let first = &chain[0];
        let last = &chain[chain.len() - 1];

        let mut signals = Vec::new();
        for signal in chain
            .iter()
            .filter_map(Url::domain)
            .flat_map(lookalike_signals)
        {
            if !signals.contains(&signal) {
                signals.push(signal);
            }
        }

        let age_days = match last.domain() {
            Some(domain) => timeout_at(start + TOTAL_BUDGET, self.domain_age_days(domain))
                .await
                .ok()
                .flatten(),
            None => None,
        };
        if is_new_domain(age_days) {
            signals.push(Signal::NewDomain);
        }

        let host = first.host_str().unwrap_or_default().to_owned();
        let final_host = last.host_str().unwrap_or_default();
        Check {
            subject: Subject::Link(LinkInfo {
                redirected_to: (final_host != host).then(|| final_host.to_owned()),
                host,
                age_days,
            }),
            signals,
        }
    }

    async fn follow_redirects(&self, url: Url, deadline: Instant) -> Vec<Url> {
        let mut chain = vec![url];
        while chain.len() <= MAX_REDIRECTS {
            let current = &chain[chain.len() - 1];
            if !is_fetchable(current) {
                break;
            }
            let Ok(Ok(response)) =
                timeout_at(deadline, self.http.head(current.clone()).send()).await
            else {
                break;
            };
            if !response.status().is_redirection() {
                break;
            }
            let next = response
                .headers()
                .get(LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| current.join(location).ok())
                .filter(|next| next.host().is_some());
            match next {
                Some(next) => chain.push(next),
                None => break,
            }
        }
        chain
    }

    async fn domain_age_days(&self, host: &str) -> Option<i64> {
        let domain = psl::domain_str(host)?;
        let servers = self
            .rdap_servers
            .get_or_try_init(|| self.fetch_rdap_servers())
            .await
            .ok()?;
        let tld = domain.rsplit('.').next()?;
        let url = servers.get(tld)?.join(&format!("domain/{domain}")).ok()?;
        let response = self
            .http
            .get(url)
            .header(ACCEPT, "application/rdap+json")
            .send()
            .await
            .ok()?;
        let registered = registration_date(&response.bytes().await.ok()?)?;
        Some((Utc::now() - registered).num_days())
    }

    async fn fetch_rdap_servers(&self) -> anyhow::Result<HashMap<String, Url>> {
        let response = self.http.get(RDAP_BOOTSTRAP).send().await?;
        let body = response.error_for_status()?.bytes().await?;
        parse_rdap_bootstrap(&body).ok_or_else(|| anyhow::anyhow!("invalid RDAP bootstrap"))
    }
}

fn is_new_domain(age_days: Option<i64>) -> bool {
    age_days.is_some_and(|days| days < NEW_DOMAIN_DAYS)
}

pub fn parse_http_url(text: &str) -> Option<Url> {
    Url::parse(text.trim())
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some())
}

pub fn lookalike_signals(host: &str) -> Vec<Signal> {
    let registrable = psl::domain_str(host).unwrap_or(host);
    let is_official = registrable.ends_with(".gov.kh")
        || OTHER_OFFICIAL.contains(&registrable)
        || BRANDS
            .iter()
            .any(|brand| brand.official.contains(&registrable));
    if is_official {
        return Vec::new();
    }

    let mut signals = Vec::new();
    if host.split('.').any(|label| label.starts_with("xn--")) {
        signals.push(Signal::Punycode);
    }

    let tokens: Vec<&str> = host.split(['.', '-']).collect();
    let suffix = psl::suffix_str(host).unwrap_or_default();
    let labels: Vec<&str> = host
        .strip_suffix(suffix)
        .unwrap_or(host)
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    if let Some(brand) = BRANDS
        .iter()
        .find(|brand| imitates(brand, &tokens, &labels))
    {
        signals.push(Signal::Lookalike(brand.name));
    } else if tokens.contains(&"gov") && (tokens.contains(&"kh") || tokens.contains(&"cambodia"))
        || host.contains("cambodia")
            && GOVERNMENT_SERVICES
                .iter()
                .any(|service| host.contains(service))
    {
        signals.push(Signal::Lookalike(GOVERNMENT));
    }
    signals
}

fn imitates(brand: &Brand, tokens: &[&str], labels: &[&str]) -> bool {
    tokens.iter().any(|token| brand.tokens.contains(token))
        || labels.iter().any(|label| label_imitates(brand, label))
}

fn label_imitates(brand: &Brand, label: &str) -> bool {
    let label = label.replace('-', "");
    let label = label.as_str();
    let brand_then_banking_word = |token: &&str| {
        label
            .strip_prefix(*token)
            .is_some_and(|rest| BANKING_WORDS.iter().any(|word| rest.contains(word)))
    };

    brand.stems.iter().any(|stem| label.contains(stem))
        || brand.tokens.iter().any(brand_then_banking_word)
        || brand
            .misspelled
            .iter()
            .any(|name| starts_with_misspelling(label, name))
}

fn starts_with_misspelling(label: &str, name: &str) -> bool {
    let (Some(start), Some(name_start)) = (label.get(..2), name.get(..2)) else {
        return false;
    };
    let same_start = start == name_start || start.chars().rev().eq(name_start.chars());
    let max_edits = if name.len() <= 6 { 1 } else { 2 };
    same_start
        && (name.len() - 2..=name.len() + 2)
            .filter_map(|len| label.get(..len))
            .any(|prefix| strsim::damerau_levenshtein(prefix, name) <= max_edits)
}

fn is_fetchable(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && match url.host() {
            Some(Host::Domain(_)) => true,
            Some(Host::Ipv4(ip)) => is_public(ip.into()),
            Some(Host::Ipv6(ip)) => is_public(ip.into()),
            None => false,
        }
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4() {
                return is_public_v4(v4);
            }
            let [first, second, ..] = ip.segments();
            if first == 0x64 && second == 0xff9b {
                let [.., a, b, c, d] = ip.octets();
                return is_public_v4(Ipv4Addr::new(a, b, c, d));
            }
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (first == 0x2001 && second == 0x0db8))
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("no public address".into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn parse_rdap_bootstrap(body: &[u8]) -> Option<HashMap<String, Url>> {
    let bootstrap: Value = serde_json::from_slice(body).ok()?;
    let mut servers = HashMap::new();
    for service in bootstrap["services"].as_array()? {
        let (Some(tlds), Some(bases)) = (service[0].as_array(), service[1].as_array()) else {
            continue;
        };
        let Some(base) = bases
            .iter()
            .filter_map(Value::as_str)
            .find(|base| base.starts_with("https://"))
        else {
            continue;
        };
        let with_slash = if base.ends_with('/') {
            base.to_owned()
        } else {
            format!("{base}/")
        };
        let Ok(base) = Url::parse(&with_slash) else {
            continue;
        };
        for tld in tlds.iter().filter_map(Value::as_str) {
            servers.insert(tld.to_ascii_lowercase(), base.clone());
        }
    }
    Some(servers)
}

fn registration_date(body: &[u8]) -> Option<DateTime<Utc>> {
    let rdap: Value = serde_json::from_slice(body).ok()?;
    rdap["events"]
        .as_array()?
        .iter()
        .find(|event| event["eventAction"] == "registration")?["eventDate"]
        .as_str()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_special_addresses_are_blocked() {
        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn official_and_unrelated_domains_are_not_lookalikes() {
        for host in [
            "ababank.com",
            "www.ababank.com",
            "link.payway.com.kh",
            "www.acledabank.com.kh",
            "www.wingbank.com.kh",
            "bakong.nbc.gov.kh",
            "www.mef.gov.kh",
            "google.com",
            "t.me",
            "facebook.com",
            "khmertimeskh.com",
            "abacus.com",
            "alabama.gov",
            "wingstop.com",
            "bangkokbank.com",
            "canadiabank.com.kh",
            "bankofamerica.com",
            "asiabank.com",
            "advancebooks.com",
            "princebank.com.kh",
            "sathapana.com.kh",
            "ppcbank.com.kh",
            "chipmongbank.com",
            "sabay.com.kh",
            "freshnewsasia.com",
            "smart.com.kh",
            "bakingclub.com",
            "acledainternetbank.com.kh",
            "acledabankmb.com.kh",
            "acledasecurities.com.kh",
            "acledabank.com.la",
            "bakong.acledabank.com.kh",
            "bakong.maybank2u.com.kh",
            "bakong.icbc.com.kh",
            "bakong.cimbcambodia.com",
            "web.telegram.org",
            "t.me",
            "arrival.gov.kh",
            "hatthabank.com",
            "kbprasacbank.com.kh",
            "academy.com",
            "accenture.com",
            "acer.com",
            "canadiantire.com",
            "chipmong.com",
            "telegraph.co.uk",
        ] {
            assert!(lookalike_signals(host).is_empty(), "{host}");
        }
    }

    #[test]
    fn phishing_domains_published_by_banks_are_lookalikes() {
        let cases = [
            ("ababkonline.com", "ABA"),
            ("ababnkonline.com", "ABA"),
            ("babbank.com", "ABA"),
            ("ababakn.com", "ABA"),
            ("ababnk.com", "ABA"),
            ("abacamb.com", "ABA"),
            ("ababcambodia.org", "ABA"),
            ("ababankonline.com", "ABA"),
            ("advancebankasia.com", "ABA"),
            ("advancedbankasia.com", "ABA"),
            ("ababankofasla.xyz", "ABA"),
            ("aba-verify.com", "ABA"),
            ("ababank.com.secure-login.top", "ABA"),
            ("acledab.com.cam", "ACLEDA"),
            ("acledabnk.com", "ACLEDA"),
            ("wingbank-online.com", "Wing"),
            ("wingapp.xyz", "Wing"),
            ("bakong-khqr.site", "Bakong"),
            ("gov-kh.site", GOVERNMENT),
            ("ababkonline.web.app", "ABA"),
            ("theababank.com", "ABA"),
            ("myababank.com", "ABA"),
            ("acle-da.com", "ACLEDA"),
            ("kh.bank.aceldaa.com", "ACLEDA"),
            ("acledainternetbank.com", "ACLEDA"),
            ("wingbank-lucky-gift.com", "Wing"),
            ("vattanaccommercialbank.com", "Vattanac"),
            ("chipmongcommercialbank.com", "Chip Mong"),
            ("hatthabanks.com", "Hattha"),
            ("sathapanabank.com", "Sathapana"),
            ("telegrams.org-web.net", "Telegram"),
            ("cambodia-e-arrival.com", GOVERNMENT),
            ("cambodiaimmigration.org", GOVERNMENT),
        ];
        for (host, brand) in cases {
            assert_eq!(
                lookalike_signals(host),
                [Signal::Lookalike(brand)],
                "{host}"
            );
        }
    }

    #[test]
    fn unknown_domain_age_is_never_new() {
        assert!(!is_new_domain(None));
        assert!(is_new_domain(Some(3)));
        assert!(!is_new_domain(Some(400)));
    }

    #[test]
    fn punycode_is_flagged() {
        assert!(lookalike_signals("xn--bkong-5ua.com").contains(&Signal::Punycode));
    }

    #[test]
    fn only_explicit_http_urls_are_parsed() {
        assert!(parse_http_url("https://bit.ly/abc").is_some());
        assert!(parse_http_url("HTTP://example.com").is_some());
        assert!(parse_http_url("ftp://example.com").is_none());
        assert!(parse_http_url("example.com").is_none());
        assert!(parse_http_url("00020101021229180014jonhsmith@nbcq5204").is_none());
    }

    #[tokio::test]
    async fn loopback_links_are_never_fetched() {
        let checker = LinkChecker::new().unwrap();
        let url = parse_http_url("http://127.0.0.1:9/").unwrap();
        let chain = checker
            .follow_redirects(url.clone(), Instant::now() + REDIRECT_BUDGET)
            .await;
        assert_eq!(chain, [url]);
    }

    #[tokio::test]
    #[ignore = "uses the network"]
    async fn live_official_bank_link() {
        let checker = LinkChecker::new().unwrap();
        let check = checker
            .check(parse_http_url("http://ababank.com").unwrap())
            .await;
        assert!(check.signals.is_empty(), "{:?}", check.signals);
        let Subject::Link(info) = check.subject else {
            panic!("expected a link");
        };
        assert_eq!(info.redirected_to.as_deref(), Some("www.ababank.com"));
        assert!(info.age_days.is_some_and(|days| days > 365 * 20));
    }

    #[test]
    fn parses_rdap_bootstrap_and_registration_date() {
        let bootstrap = br#"{"services": [[["com", "net"], ["http://rdap.example/", "https://rdap.example/v1"]]]}"#;
        let servers = parse_rdap_bootstrap(bootstrap).unwrap();
        assert_eq!(servers["com"].as_str(), "https://rdap.example/v1/");

        let rdap = br#"{"events": [{"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"}, {"eventAction": "registration", "eventDate": "2004-05-25T09:52:16Z"}]}"#;
        assert_eq!(
            registration_date(rdap).unwrap().to_rfc3339(),
            "2004-05-25T09:52:16+00:00"
        );
    }
}
