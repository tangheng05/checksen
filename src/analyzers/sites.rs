#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bank,
    Finance,
    Wallet,
    Telecom,
    Government,
    Messaging,
    Social,
    Video,
    Code,
    Files,
    Email,
    Tech,
    AppStore,
    Shopping,
    Classifieds,
    News,
    Reference,
    Ai,
    Ride,
    Shortener,
    Hosting,
}

impl Kind {
    pub fn anyone_can_post(self) -> bool {
        matches!(
            self,
            Self::Messaging
                | Self::Social
                | Self::Video
                | Self::Code
                | Self::Files
                | Self::AppStore
                | Self::Classifieds
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Site {
    pub domain: &'static str,
    pub name: &'static str,
    pub kind: Kind,
}

const fn site(domain: &'static str, name: &'static str, kind: Kind) -> Site {
    Site { domain, name, kind }
}

use Kind::*;

// A wrong domain here would mark a scam site as official, so only add ones you are sure of.
const SITES: &[Site] = &[
    site("ababank.com", "ABA", Bank),
    site("payway.com.kh", "ABA PayWay", Bank),
    site("acledabank.com.kh", "ACLEDA", Bank),
    site("acledainternetbank.com.kh", "ACLEDA", Bank),
    site("acledabankmb.com.kh", "ACLEDA", Bank),
    site("acledasecurities.com.kh", "ACLEDA Securities", Finance),
    site("acledabank.com.la", "ACLEDA Laos", Bank),
    site("acledainternetbank.com.la", "ACLEDA Laos", Bank),
    site("wingbank.com.kh", "Wing", Bank),
    site("canadiabank.com.kh", "Canadia", Bank),
    site("vattanacbank.com", "Vattanac", Bank),
    site("chipmongbank.com", "Chip Mong", Bank),
    site("sathapana.com.kh", "Sathapana", Bank),
    site("hatthabank.com", "Hattha", Bank),
    site("prasac.com.kh", "PRASAC", Bank),
    site("kbprasacbank.com.kh", "KB PRASAC", Bank),
    site("ppcbank.com.kh", "PPCBank", Bank),
    site("princebank.com.kh", "Prince Bank", Bank),
    site("amkbank.com.kh", "AMK", Bank),
    site("maybank2u.com.kh", "Maybank", Bank),
    site("maybank.com.kh", "Maybank", Bank),
    site("cimbcambodia.com", "CIMB", Bank),
    site("icbc.com.kh", "ICBC", Bank),
    site("bridgebank.com.kh", "Bridge Bank", Bank),
    site("sbilhbank.com.kh", "SBI LY HOUR Bank", Bank),
    site("ucb.com.kh", "UCB", Bank),
    site("bankofchina.com.kh", "Bank of China", Bank),
    site("alphabank.com.kh", "Alpha Bank", Bank),
    site("bidc.com.kh", "BIDC", Bank),
    site("mbcambodia.com", "MB Bank", Bank),
    site("wbfinance.com.kh", "WB Finance", Finance),
    site("lolc.com.kh", "LOLC", Finance),
    site("truemoney.com.kh", "TrueMoney", Wallet),
    site("pipay.com", "Pi Pay", Wallet),
    site("smart.com.kh", "Smart", Telecom),
    site("cellcard.com.kh", "Cellcard", Telecom),
    site("metfone.com.kh", "Metfone", Telecom),
    site(
        "nbc.gov.kh",
        "National Bank of Cambodia (Bakong)",
        Government,
    ),
    site("telegram.org", "Telegram", Messaging),
    site("t.me", "Telegram", Messaging),
    site("telegram.me", "Telegram", Messaging),
    site("whatsapp.com", "WhatsApp", Messaging),
    site("wa.me", "WhatsApp", Messaging),
    site("messenger.com", "Messenger", Messaging),
    site("m.me", "Messenger", Messaging),
    site("line.me", "LINE", Messaging),
    site("signal.org", "Signal", Messaging),
    site("discord.com", "Discord", Messaging),
    site("discord.gg", "Discord", Messaging),
    site("wechat.com", "WeChat", Messaging),
    site("facebook.com", "Facebook", Social),
    site("fb.com", "Facebook", Social),
    site("fb.me", "Facebook", Social),
    site("instagram.com", "Instagram", Social),
    site("threads.com", "Threads", Social),
    site("threads.net", "Threads", Social),
    site("tiktok.com", "TikTok", Social),
    site("x.com", "X (Twitter)", Social),
    site("twitter.com", "X (Twitter)", Social),
    site("linkedin.com", "LinkedIn", Social),
    site("reddit.com", "Reddit", Social),
    site("pinterest.com", "Pinterest", Social),
    site("youtube.com", "YouTube", Video),
    site("youtu.be", "YouTube", Video),
    site("github.com", "GitHub", Code),
    site("githubusercontent.com", "GitHub", Code),
    site("gitlab.com", "GitLab", Code),
    site("docs.google.com", "Google Docs", Files),
    site("drive.google.com", "Google Drive", Files),
    site("forms.gle", "Google Forms", Files),
    site("forms.office.com", "Microsoft Forms", Files),
    site("onedrive.live.com", "OneDrive", Files),
    site("1drv.ms", "OneDrive", Files),
    site("dropbox.com", "Dropbox", Files),
    site("mega.nz", "MEGA", Files),
    site("mail.google.com", "Gmail", Email),
    site("gmail.com", "Gmail", Email),
    site("outlook.com", "Outlook", Email),
    site("play.google.com", "Google Play", AppStore),
    site("apps.apple.com", "App Store", AppStore),
    site("google.com", "Google", Tech),
    site("microsoft.com", "Microsoft", Tech),
    site("live.com", "Microsoft", Tech),
    site("office.com", "Microsoft", Tech),
    site("microsoftonline.com", "Microsoft", Tech),
    site("apple.com", "Apple", Tech),
    site("icloud.com", "Apple", Tech),
    site("samsung.com", "Samsung", Tech),
    site("yahoo.com", "Yahoo", Tech),
    site("zoom.us", "Zoom", Tech),
    site("cloudflare.com", "Cloudflare", Tech),
    site("chatgpt.com", "ChatGPT", Ai),
    site("openai.com", "OpenAI", Ai),
    site("claude.ai", "Claude", Ai),
    site("anthropic.com", "Anthropic", Ai),
    site("amazon.com", "Amazon", Shopping),
    site("aliexpress.com", "AliExpress", Shopping),
    site("alibaba.com", "Alibaba", Shopping),
    site("taobao.com", "Taobao", Shopping),
    site("temu.com", "Temu", Shopping),
    site("shein.com", "SHEIN", Shopping),
    site("ebay.com", "eBay", Shopping),
    site("khmer24.com", "Khmer24", Classifieds),
    site("grab.com", "Grab", Ride),
    site("wikipedia.org", "Wikipedia", Reference),
    site("sabay.com.kh", "Sabay", News),
    site("freshnewsasia.com", "Fresh News", News),
    site("khmertimeskh.com", "Khmer Times", News),
    site("phnompenhpost.com", "Phnom Penh Post", News),
    site("bbc.com", "BBC", News),
    site("bbc.co.uk", "BBC", News),
    site("cnn.com", "CNN", News),
    site("reuters.com", "Reuters", News),
    site("bit.ly", "Bitly", Shortener),
    site("tinyurl.com", "TinyURL", Shortener),
    site("t.co", "X (Twitter)", Shortener),
    site("lnkd.in", "LinkedIn", Shortener),
    site("goo.gl", "Google", Shortener),
    site("is.gd", "is.gd", Shortener),
    site("cutt.ly", "Cuttly", Shortener),
    site("rebrand.ly", "Rebrandly", Shortener),
    site("shorturl.at", "ShortURL", Shortener),
    site("ow.ly", "Hootsuite", Shortener),
    site("sites.google.com", "Google Sites", Hosting),
    site("telegra.ph", "Telegraph", Hosting),
    site("linktr.ee", "Linktree", Hosting),
    site("github.io", "GitHub Pages", Hosting),
    site("vercel.app", "Vercel", Hosting),
    site("netlify.app", "Netlify", Hosting),
    site("pages.dev", "Cloudflare Pages", Hosting),
    site("workers.dev", "Cloudflare Workers", Hosting),
    site("web.app", "Firebase", Hosting),
    site("firebaseapp.com", "Firebase", Hosting),
    site("blogspot.com", "Blogger", Hosting),
    site("wixsite.com", "Wix", Hosting),
    site("weebly.com", "Weebly", Hosting),
    site("wordpress.com", "WordPress.com", Hosting),
    site("webflow.io", "Webflow", Hosting),
    site("framer.website", "Framer", Hosting),
    site("notion.site", "Notion", Hosting),
    site("canva.site", "Canva", Hosting),
    site("carrd.co", "Carrd", Hosting),
    site("godaddysites.com", "GoDaddy", Hosting),
    site("square.site", "Square", Hosting),
    site("onrender.com", "Render", Hosting),
    site("herokuapp.com", "Heroku", Hosting),
    site("glitch.me", "Glitch", Hosting),
    site("replit.app", "Replit", Hosting),
    site("ngrok-free.app", "ngrok", Hosting),
    site("ngrok.io", "ngrok", Hosting),
    site("000webhostapp.com", "000webhost", Hosting),
];

static GOVERNMENT: Site = site("gov.kh", "Cambodian government (.gov.kh)", Government);

pub fn identify(host: &str) -> Option<&'static Site> {
    let registrable = psl::domain_str(host).unwrap_or(host);
    let hosted_on = |site: &&Site| {
        host.strip_suffix(site.domain)
            .is_some_and(|rest| rest.ends_with('.'))
    };
    SITES
        .iter()
        .filter(|site| site.kind == Hosting)
        .find(hosted_on)
        .or_else(|| SITES.iter().find(|site| site.domain == host))
        .or_else(|| SITES.iter().find(|site| site.domain == registrable))
        .or_else(|| registrable.ends_with(".gov.kh").then_some(&GOVERNMENT))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_and_kind(host: &str) -> Option<(&'static str, Kind)> {
        identify(host).map(|site| (site.name, site.kind))
    }

    #[test]
    fn known_sites_are_named_by_their_owner() {
        assert_eq!(name_and_kind("github.com"), Some(("GitHub", Code)));
        assert_eq!(name_and_kind("www.ababank.com"), Some(("ABA", Bank)));
        assert_eq!(name_and_kind("m.facebook.com"), Some(("Facebook", Social)));
        assert_eq!(
            name_and_kind("docs.google.com"),
            Some(("Google Docs", Files))
        );
        assert_eq!(name_and_kind("www.google.com"), Some(("Google", Tech)));
        assert_eq!(
            name_and_kind("bakong.nbc.gov.kh").map(|(_, kind)| kind),
            Some(Government)
        );
        assert_eq!(
            name_and_kind("www.mef.gov.kh").map(|(_, kind)| kind),
            Some(Government)
        );
    }

    #[test]
    fn free_hosting_is_not_mistaken_for_its_platform() {
        assert_eq!(
            name_and_kind("ababkonline.web.app"),
            Some(("Firebase", Hosting))
        );
        assert_eq!(
            name_and_kind("aba-gift.github.io"),
            Some(("GitHub Pages", Hosting))
        );
        assert_eq!(
            name_and_kind("sites.google.com"),
            Some(("Google Sites", Hosting))
        );
        assert_eq!(name_and_kind("myweb.app"), None);
    }

    #[test]
    fn lookalikes_and_unknown_sites_are_not_identified() {
        for host in [
            "github.com.login-verify.top",
            "ababank-verify.com",
            "googIe.com",
            "example.com",
            "gov-kh.site",
        ] {
            assert_eq!(identify(host), None, "{host}");
        }
    }
}
