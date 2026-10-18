use khqr_core::{Currency, DecodedKhqr};

use crate::analyzers::intent::Intent;
use crate::analyzers::link::{self, LinkInfo};
use crate::analyzers::llm::ScamCategory;
use crate::analyzers::sites::{Kind, Site};
use crate::analyzers::{Check, Signal, Subject};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    Km,
    En,
}

impl Lang {
    /// Khmer script wins; otherwise Latin letters mean English.
    pub fn of(text: &str) -> Option<Self> {
        if text.chars().any(|c| ('\u{1780}'..='\u{17FF}').contains(&c)) {
            Some(Self::Km)
        } else if text.chars().any(|c| c.is_ascii_alphabetic()) {
            Some(Self::En)
        } else {
            None
        }
    }

    fn pick<'a>(self, km: &'a str, en: &'a str) -> &'a str {
        match self {
            Self::Km => km,
            Self::En => en,
        }
    }
}

pub struct Text {
    km: &'static str,
    en: &'static str,
}

impl Text {
    pub fn get(&self, lang: Lang) -> &'static str {
        lang.pick(self.km, self.en)
    }
}

const fn text(km: &'static str, en: &'static str) -> Text {
    Text { km, en }
}

pub const HELP: Text = text(
    "សូមផ្ញើសារ តំណ (link) កូដ KHQR ឬរូបថតអេក្រង់ ដែលអ្នកសង្ស័យ មកទីនេះ។ ខ្ញុំនឹងប្រាប់ថា QR បង់ប្រាក់ទៅអ្នកណា តំណនាំទៅគេហទំព័រណា និងសារនោះមានសញ្ញាបោកប្រាស់ឬអត់។\n\nCheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។ ដើម្បីពិនិត្យ អត្ថបទ និងរូបភាពអាចត្រូវបានផ្ញើទៅសេវា AI របស់ក្រុមហ៊ុនខាងក្រៅ ដែលអាចយកទៅកែលម្អសេវារបស់គេ ហើយមនុស្សអាចមើលឃើញ។ សូមបិទលេខគណនី និងព័ត៌មានផ្ទាល់ខ្លួនសិន មុនផ្ញើ។",
    "Send me a message, link, KHQR code or screenshot you're unsure about. I'll tell you who a QR really pays, where a link goes, and whether a message has scam signs.\n\nCheckSen doesn't keep your messages or images. To check them, text and images may be sent to an outside company's AI service, which may use them to improve its service and let people see them. Please hide account numbers and personal details before sending.",
);
pub const WELCOME: Text = text(
    "សួស្តី! ខ្ញុំជា CheckSen 👋\nមុនចុចតំណ ឬបង់ប្រាក់ ផ្ញើវាមកខ្ញុំពិនិត្យសិន៖\n• សារដែលអ្នកសង្ស័យ (forward មកក៏បាន)\n• តំណ (link)\n• រូប KHQR ឬរូបថតអេក្រង់\n• ឯកសារ ដូចជា .apk\n\nខ្ញុំនឹងប្រាប់កម្រិតហានិភ័យ និងហេតុផល ក្នុងរយៈពេលប៉ុន្មានវិនាទី។ ចុច /help ដើម្បីដឹងបន្ថែម។\n\nI reply in English too: just write to me in English.",
    "Hi! I'm CheckSen 👋\nBefore you click a link or pay, send it to me first:\n• a message you're unsure about (forwarding works)\n• a link\n• a KHQR code or a screenshot\n• a file, like an .apk\n\nWithin seconds I'll tell you the risk level and why. Tap /help to learn more.",
);
pub const GREETING: Text = text(
    "សួស្តី! 👋 ផ្ញើសារ តំណ QR ឬរូបថតអេក្រង់ ដែលអ្នកសង្ស័យ មកខ្ញុំពិនិត្យឱ្យ។",
    "Hi! 👋 Send me a message, link, QR code or screenshot you're unsure about, and I'll check it.",
);
pub const CANT_LISTEN: Text = text(
    "ខ្ញុំមិនទាន់អាចស្តាប់សារសំឡេង ឬមើលវីដេអូបានទេ។ សូមវាយអក្សរនូវអ្វីដែលគេនិយាយ ឬផ្ញើរូបថតអេក្រង់មកវិញ។",
    "I can't listen to voice messages or watch videos yet. Type what they said, or send me a screenshot instead.",
);
pub const ABOUT_CONTACT: Text = text(
    "CheckSen មិនទាន់អាចពិនិត្យលេខទូរស័ព្ទ ឬឈ្មោះមនុស្សបានទេ។\n• បើគេអះអាងថាមកពីធនាគារ ឬក្រុមហ៊ុន សូមតេទៅលេខដែលមានក្នុងកម្មវិធី ឬគេហទំព័រផ្លូវការរបស់គេ មិនមែនលេខដែលគេឱ្យអ្នកទេ។\n• បើគេឱ្យបង់ប្រាក់ សូមផ្ញើ QR ឬសារដែលគេផ្ញើមក ឱ្យខ្ញុំពិនិត្យ។",
    "CheckSen can't check phone numbers or people's names yet.\n• If they say they're from a bank or company, call the number in that company's official app or website, not a number they gave you.\n• If they want you to pay, send me their QR code or the message they sent, and I'll check it.",
);
pub const NOTHING_TO_CHECK: Text = text(
    "គ្មានអ្វីត្រូវពិនិត្យក្នុងទីតាំងទេ។ សូមផ្ញើសារ តំណ ឬ QR ដែលអ្នកសង្ស័យ មកវិញ។",
    "There's nothing to check in a location. Send me a message, link or QR code you're unsure about.",
);
const THANKS: Text = text(
    "រីករាយបានជួយ! ពេលណាអ្នកសង្ស័យសារ តំណ ឬ QR ណាមួយទៀត ផ្ញើមកខ្ញុំបានជានិច្ច។",
    "Happy to help! Whenever you're unsure about a message, link or QR code, send it to me.",
);
const ALREADY_SCAMMED: Text = text(
    "សូមធ្វើតាមនេះភ្លាមៗ៖\n1. តេទៅធនាគាររបស់អ្នកឥឡូវនេះ តាមលេខក្នុងកម្មវិធី ឬនៅខាងក្រោយកាត ហើយសុំឱ្យគេបញ្ឈប់ការផ្ទេរ ឬបង្កកគណនីសិន។\n2. បើអ្នកបានប្រាប់លេខកូដ ឬលេខសម្ងាត់ សូមប្តូរលេខសម្ងាត់ភ្លាម។ ក្នុង Telegram ចូល Settings → Devices ហើយបិទឧបករណ៍ផ្សេងទាំងអស់ រួចបើក Two-Step Verification។\n3. កុំបង់លុយឱ្យអ្នកណាដែលសន្យាថាអាចយកលុយមកវិញឱ្យ។ នោះក៏ជាការបោកប្រាស់ដែរ។\n4. ទុករូបថតអេក្រង់ និងលេខប្រតិបត្តិការ ហើយរាយការណ៍ទៅធនាគារ និងប៉ូលិស។",
    "Do this now:\n1. Call your bank right away on the number in its app or on the back of your card, and ask them to stop the transfer or freeze your account.\n2. If you shared a code or password, change your password now. In Telegram, go to Settings → Devices, end all other sessions, and turn on Two-Step Verification.\n3. Don't pay anyone who promises to get your money back. That's a scam too.\n4. Keep screenshots and the transaction ID, and report it to your bank and the police.",
);
const ABOUT_CODES: Text = text(
    "ធនាគារ Wing Telegram និងប៉ូលិស មិនដែលសុំលេខកូដ OTP លេខ PIN ឬលេខសម្ងាត់របស់អ្នកទេ មិនថាតាមសារ តាមទូរស័ព្ទ ឬតាមតំណឡើយ។ បើនរណាម្នាក់សុំ នោះជាការបោកប្រាស់។ លេខកូដ OTP សម្រាប់តែអ្នកវាយចូលក្នុងកម្មវិធីដោយខ្លួនឯងប៉ុណ្ណោះ។",
    "Banks, Wing, Telegram and the police never ask for your OTP code, PIN or password, whether by message, phone call or link. If someone asks, it's a scam. An OTP is only for you to type into the app yourself.",
);
const HOW_TO_REPORT: Text = text(
    "ដើម្បីរាយការណ៍៖\n• បើអ្នកបានបាត់លុយ ឬប្រាប់លេខកូដ សូមតេទៅធនាគាររបស់អ្នកមុនគេ តាមលេខក្នុងកម្មវិធី។\n• ក្នុង Telegram សូមបើកគណនី ឬឆានែលនោះ ចុច ⋮ ហើយជ្រើស Report។\n• អ្នកក៏អាចរាយការណ៍ទៅប៉ូលិសផងដែរ។",
    "To report a scam:\n• If you lost money or shared a code, call your bank first, on the number in its app.\n• In Telegram, open that account or channel, tap ⋮ and choose Report.\n• You can also report it to the police.",
);
const PRIVACY: Text = text(
    "CheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។ ដើម្បីពិនិត្យ អត្ថបទ និងរូបភាពអាចត្រូវបានផ្ញើទៅសេវា AI របស់ក្រុមហ៊ុនខាងក្រៅ ដែលអាចយកទៅកែលម្អសេវារបស់គេ ហើយមនុស្សអាចមើលឃើញ។ សូមបិទលេខគណនី និងព័ត៌មានផ្ទាល់ខ្លួនសិន មុនផ្ញើ។ ចុច /forget ដើម្បីលុបការរាយការណ៍ KHQR របស់អ្នក។",
    "CheckSen doesn't keep your messages or images. To check them, text and images may be sent to an outside company's AI service, which may use them to improve its service and let people see them. Please hide account numbers and personal details before sending. Tap /forget to delete your KHQR reports.",
);
const OTHER_QUESTION: Text = text(
    "ខ្ញុំអាចជួយពិនិត្យតែសារ តំណ កូដ QR រូបថតអេក្រង់ និងឯកសារ ដែលអ្នកសង្ស័យប៉ុណ្ណោះ។ សូម forward ឬចម្លងសារនោះមកខ្ញុំ ខ្ញុំនឹងប្រាប់ថាវាមានសញ្ញាបោកប្រាស់ឬអត់។",
    "I can only check messages, links, QR codes, screenshots and files you're unsure about. Forward or paste the message to me and I'll tell you whether it has scam signs.",
);

/// The fixed answer for anything other than a message to check.
pub fn answer(intent: Intent, lang: Lang) -> Option<&'static str> {
    let text = match intent {
        Intent::Check => return None,
        Intent::Greeting => &GREETING,
        Intent::Thanks => &THANKS,
        Intent::AlreadyScammed => &ALREADY_SCAMMED,
        Intent::AsksAboutContact => &ABOUT_CONTACT,
        Intent::AsksAboutCodes => &ABOUT_CODES,
        Intent::AsksHowToReport => &HOW_TO_REPORT,
        Intent::AsksWhatBotDoes => &WELCOME,
        Intent::AsksPrivacy => &PRIVACY,
        Intent::OtherQuestion => &OTHER_QUESTION,
    };
    Some(text.get(lang))
}

pub const FORGET: Text = text(
    "CheckSen មិនបានរក្សាទុកព័ត៌មានអ្វីរបស់អ្នកទេ ដូច្នេះគ្មានអ្វីត្រូវលុបទេ។",
    "CheckSen hasn't stored anything about you, so there's nothing to delete.",
);
pub const INTENDED_BUTTON: Text = text("✅ ត្រូវ", "✅ Yes");
pub const NOT_INTENDED_BUTTON: Text = text("❌ មិនត្រូវ", "❌ No");
pub const INTENDED: Text = text(
    "ល្អណាស់។ សូមពិនិត្យឈ្មោះអ្នកទទួលក្នុងកម្មវិធីធនាគារម្តងទៀត មុនចុចបង់ប្រាក់។",
    "Good. Check the recipient's name in your bank app once more before you pay.",
);
pub const REPORTED: Text = text(
    "អរគុណសម្រាប់ការរាយការណ៍។ កុំបង់ប្រាក់តាម QR នេះ ហើយសូមសួរអ្នកលក់ឱ្យប្រាកដពីគណនីរបស់គេ។",
    "Thanks for reporting. Don't pay with this QR, and ask the seller to confirm their account.",
);
pub const REPORT_LIMIT: Text = text(
    "ថ្ងៃនេះអ្នករាយការណ៍ច្រើនដងហើយ។ សូមកុំបង់ប្រាក់តាម QR នេះ ហើយរាយការណ៍ម្តងទៀតនៅថ្ងៃស្អែក។",
    "You've reported a lot today. Please don't pay with this QR, and report again tomorrow.",
);
pub const REPORT_FAILED: Text = text(
    "ពេលនេះមិនអាចរាយការណ៍បានទេ។ សូមកុំបង់ប្រាក់តាម QR នេះ។",
    "Reporting isn't working right now. Please don't pay with this QR.",
);
pub const RATE_LIMITED: Text = text(
    "អ្នកផ្ញើមកច្រើនពេកក្នុងពេលខ្លី។ សូមរង់ចាំបន្តិច ហើយសាកម្តងទៀត។",
    "You've sent a lot in a short time. Please wait a little and try again.",
);
const BANK_APP_ADVICE: Text = text(
    "⚠️ មុនពេលបង់ប្រាក់ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់នៅក្នុងកម្មវិធីធនាគាររបស់អ្នកឱ្យបានហ្មត់ចត់ជានិច្ច។",
    "⚠️ Before paying, always check the recipient's name and the amount in your bank app.",
);
const LINK_ADVICE: Text = text(
    "មិនត្រូវបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP តាមតំណភ្ជាប់ (Link) ណាមួយឡើយ។ បើចង់ពិនិត្យមើលគណនី សូមបើកចូលកម្មវិធីធនាគាររបស់អ្នកដោយផ្ទាល់។",
    "Never enter a password or OTP code through a link. To check your account, open your bank app yourself.",
);
const NO_TEXT_SIGNALS: Text = text(
    "មិនឃើញពាក្យដែលអ្នកបោកប្រាស់តែងប្រើទេ តែសូមនៅតែប្រយ័ត្ន។",
    "No words that scammers usually use, but stay careful.",
);
const NO_QR_FOUND: Text = text(
    "រកមិនឃើញ QR ក្នុងរូបនេះទេ។ សូមថតឱ្យច្បាស់ ឱ្យឃើញ QR ទាំងមូល ហើយផ្ញើម្តងទៀត។",
    "I couldn't find a QR code in this image. Take a clear photo of the whole QR and send it again.",
);
const SCREENSHOT_UNREAD: Text = text(
    "ពេលនេះមិនអាចអានអក្សរក្នុងរូបនេះបានទេ។ សូមសាកម្តងទៀតបន្តិចទៀត ឬចម្លងសារនោះ ហើយផ្ញើមកជាអក្សរ។",
    "I can't read the text in this image right now. Try again a bit later, or copy the message and send it as text.",
);

pub fn forgotten(removed: u64, lang: Lang) -> String {
    match lang {
        Lang::Km => {
            format!("បានលុបការរាយការណ៍របស់អ្នកចំនួន {removed} រួចហើយ។ CheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។")
        }
        Lang::En => format!(
            "Deleted {removed} of your reports. CheckSen doesn't keep your messages or images."
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    HighRisk,
    Suspicious,
    NoKnownSignals,
    CantTell,
}

impl Level {
    fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::HighRisk => lang.pick("🔴 ហានិភ័យខ្ពស់", "🔴 High risk"),
            Self::Suspicious => lang.pick("🟠 គួរឱ្យសង្ស័យ", "🟠 Suspicious"),
            Self::NoKnownSignals => {
                lang.pick("⚪ មិនទាន់រកឃើញសញ្ញាបោកប្រាស់ទេ", "⚪ No scam signs found yet")
            }
            Self::CantTell => lang.pick("❔ មិនអាចពិនិត្យបាន", "❔ Can't check"),
        }
    }
}

pub fn decide(check: &Check) -> Level {
    let score: f32 = check.signals.iter().map(|signal| signal.weight()).sum();
    let uncited_model: f32 = check
        .signals
        .iter()
        .filter(|signal| matches!(signal, Signal::Model { cited: false, .. }))
        .map(|signal| signal.weight())
        .sum();
    if check.signals.iter().any(|signal| signal.is_hard()) || score - uncited_model > 0.8 {
        Level::HighRisk
    } else if score >= 0.4 {
        Level::Suspicious
    } else if matches!(check.subject, Subject::Unreadable) {
        Level::CantTell
    } else {
        Level::NoKnownSignals
    }
}

pub fn screenshot_unread(lang: Lang) -> String {
    format!(
        "{}\n{}\n\n{}",
        Level::CantTell.label(lang),
        SCREENSHOT_UNREAD.get(lang),
        BANK_APP_ADVICE.get(lang)
    )
}

pub fn render(checks: &[Check], lang: Lang) -> String {
    let mut sections: Vec<String> = if checks.is_empty() {
        vec![format!(
            "{}\n{}",
            Level::CantTell.label(lang),
            NO_QR_FOUND.get(lang)
        )]
    } else {
        checks
            .iter()
            .map(|check| render_check(check, lang))
            .collect()
    };
    sections.push(BANK_APP_ADVICE.get(lang).to_owned());
    sections.join("\n\n")
}

fn render_check(check: &Check, lang: Lang) -> String {
    let mut lines = vec![decide(check).label(lang).to_owned()];
    lines.extend(check.signals.iter().map(|&signal| reason(signal, lang)));
    match &check.subject {
        Subject::Khqr(payee) => lines.push(render_payee(payee, lang)),
        Subject::Link(link) => lines.push(render_link(link, lang)),
        Subject::Text if check.signals.iter().all(|signal| signal.weight() == 0.0) => {
            lines.push(NO_TEXT_SIGNALS.get(lang).to_owned())
        }
        Subject::Text | Subject::Unreadable => {}
    }
    lines.join("\n")
}

fn reason(signal: Signal, lang: Lang) -> String {
    let (km, en) = match signal {
        Signal::NotKhqr => (
            "QR នេះមិនមែន KHQR ឬតំណទេ។ ពេលនេះ CheckSen ពិនិត្យបានតែ KHQR និងតំណប៉ុណ្ណោះ។",
            "This QR isn't a KHQR or a link. For now CheckSen can only check KHQR codes and links.",
        ),
        Signal::ChecksumInvalid => (
            "QR នេះអាចត្រូវគេកែ ឬខូច (លេខផ្ទៀងផ្ទាត់មិនត្រូវ)។ កុំបង់ប្រាក់តាម QR នេះ។",
            "This QR may have been edited or damaged (its check digits don't match). Don't pay with this QR.",
        ),
        Signal::DuplicateTag => (
            "QR នេះមានព័ត៌មានជាន់គ្នា ដែលអាចមកពីការកែបន្លំ។ កុំបង់ប្រាក់តាម QR នេះ។",
            "This QR has overlapping details, which can come from tampering. Don't pay with this QR.",
        ),
        Signal::Malformed => (
            "QR នេះមើលទៅដូច KHQR តែទម្រង់មិនត្រឹមត្រូវ។",
            "This QR looks like a KHQR, but its format is wrong.",
        ),
        Signal::Expired => (
            "QR នេះប្រើបានតែម្តង ហើយផុតកំណត់ហើយ។ សូមសុំ QR ថ្មីពីអ្នកលក់។",
            "This QR could only be used once and has expired. Ask the seller for a new one.",
        ),
        Signal::Lookalike(brand) => {
            let brand = brand_name(brand, lang);
            return match lang {
                Lang::Km => format!("ឈ្មោះគេហទំព័រនេះស្រដៀង {brand} តែមិនមែនគេហទំព័រផ្លូវការទេ។"),
                Lang::En => {
                    format!("This site's name looks like {brand}, but it isn't the official site.")
                }
            };
        }
        Signal::BrandClaim(brand) => {
            return match lang {
                Lang::Km => format!("ទំព័រនេះដាក់ឈ្មោះថា {brand} តែវាមិនមែនជាគេហទំព័រផ្លូវការរបស់ {brand} ទេ។"),
                Lang::En => {
                    format!("This page calls itself {brand}, but it isn't {brand}'s official site.")
                }
            };
        }
        Signal::PasswordPage => (
            "ទំព័រនេះសុំលេខសម្ងាត់។ កុំបញ្ចូលលេខសម្ងាត់ លើគេហទំព័រដែលអ្នកមិនស្គាល់ច្បាស់។",
            "This page asks for a password. Don't enter a password on a site you don't know well.",
        ),
        Signal::ImpersonatedAccount(brand) => {
            return match lang {
                Lang::Km => format!(
                    "គណនី Telegram នៅក្នុងសារនេះប្រើឈ្មោះ {brand}។ អ្នកណាក៏អាចបង្កើតគណនីដាក់ឈ្មោះធនាគារបាន។ សូមទុកចិត្តតែគណនីដែលមានតំណពីកម្មវិធី ឬគេហទំព័រផ្លូវការរបស់ {brand} ប៉ុណ្ណោះ។"
                ),
                Lang::En => format!(
                    "The Telegram account in this message uses the name {brand}. Anyone can make an account with a bank's name, so only trust accounts linked from {brand}'s official app or website."
                ),
            };
        }
        Signal::Punycode => (
            "ឈ្មោះគេហទំព័រនេះប្រើអក្សរចម្លែក ដើម្បីឱ្យមើលទៅដូចគេហទំព័រផ្សេង។",
            "This site's name uses unusual letters to look like a different site.",
        ),
        Signal::NewDomain => (
            "គេហទំព័រនេះទើបបង្កើតថ្មី មិនទាន់បាន ៣០ ថ្ងៃផង។",
            "This site was created less than 30 days ago.",
        ),
        Signal::OtpRequest => (
            "សារនេះសុំលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនពិតៗ មិនដែលសុំលេខទាំងនេះទេ។ កុំប្រាប់នរណាម្នាក់ឡើយ។",
            "This message asks for an OTP code or password. Real banks and companies never ask for these. Don't tell anyone.",
        ),
        Signal::UpfrontFee => (
            "សារនេះឱ្យបង់លុយមុន ទើបទទួលបានកម្ចី ការងារ ឬរង្វាន់។",
            "This message asks you to pay first to get a loan, a job or a prize.",
        ),
        Signal::MoveMoneyOut => (
            "សារនេះប្រាប់ឱ្យផ្ទេរលុយចេញពីគណនីរបស់អ្នក ទៅគណនីផ្សេង។",
            "This message tells you to move money out of your account into another one.",
        ),
        Signal::AccountRental => (
            "សារនេះសុំជួល ទិញ ឬខ្ចីគណនីធនាគាររបស់អ្នក។ គណនីបែបនេះតែងត្រូវគេប្រើលាងលុយ ហើយអ្នកអាចជាប់ទោសតាមច្បាប់។",
            "This message wants to rent, buy or borrow your bank account. Accounts like this are used to launder money, and you could be charged by law.",
        ),
        Signal::AuthorityThreat => (
            "សារនេះអះអាងថាមកពីប៉ូលិស តុលាការ ឬស្ថាប័នរដ្ឋ ហើយគំរាម ឬសុំលុយ។ ស្ថាប័នពិតមិនសុំឱ្យផ្ទេរលុយតាមសារទេ។",
            "This message claims to be from the police, a court or a government office, and threatens you or asks for money. Real offices don't ask you to transfer money by message.",
        ),
        Signal::FamilyImpersonation => (
            "សារនេះអះអាងថាជាសាច់ញាតិ ឬមិត្តភក្តិដែលប្តូរលេខថ្មី ហើយសុំលុយ។ សូមតេទៅលេខចាស់របស់គាត់ ដើម្បីបញ្ជាក់សិន។",
            "This message claims to be a relative or friend with a new number asking for money. Call their old number to check first.",
        ),
        Signal::AccountThreat => (
            "សារនេះគំរាមថានឹងបិទ ឬផ្អាកគណនីរបស់អ្នក ហើយឱ្យចុចតំណ ឬផ្ទៀងផ្ទាត់។",
            "This message threatens to close or freeze your account and asks you to click a link or verify.",
        ),
        Signal::LoanBait => (
            "សារនេះសន្យាឱ្យខ្ចីលុយងាយៗ មិនបាច់មានអ្នកធានា ឬទ្រព្យធានា។",
            "This message promises an easy loan with no guarantor or collateral.",
        ),
        Signal::JobBait => (
            "សារនេះសន្យាការងារស្រួលៗ តែបានលុយច្រើនពេក ដូចជាចុចឡាយ ឬវាយអក្សរ។",
            "This message promises easy work for too much money, like clicking likes or typing.",
        ),
        Signal::PrizeBait => (
            "សារនេះប្រាប់ថាអ្នកឈ្នះរង្វាន់ ឬបានលុយជំនួយ។",
            "This message says you won a prize or are getting aid money.",
        ),
        Signal::InvestmentBait => (
            "សារនេះធានាថាចំណេញខ្ពស់ ឬមិនខាត។ គ្មានការវិនិយោគណាអាចធានាបែបនេះបានទេ។",
            "This message promises high profits or no losses. No investment can promise that.",
        ),
        Signal::TelegramTakeover => (
            "សារនេះឱ្យផ្ទៀងផ្ទាត់ ឬការពារគណនី Telegram តាមតំណ។ Telegram មិនផ្ញើសារបែបនេះទេ ហើយតំណនោះអាចលួចគណនីរបស់អ្នក។",
            "This message asks you to verify or protect your Telegram account through a link. Telegram doesn't send messages like this, and the link can steal your account.",
        ),
        Signal::DonationRequest => (
            "សារនេះសុំឱ្យបរិច្ចាគលុយចូលគណនីមួយ។ ជនបោកប្រាស់ច្រើនតែយករឿងទាហាន ឬកុមារឈឺមកបញ្ឆោត។ សូមបរិច្ចាគតែតាមអង្គការដែលអ្នកស្គាល់ច្បាស់។",
            "This message asks you to donate money to an account. Scammers often use stories about soldiers or sick children. Only donate through organisations you know well.",
        ),
        Signal::Extortion => (
            "សារនេះគំរាមថានឹងផុសរូប ឬប្រាប់អ្នកដទៃ បើអ្នកមិនផ្ញើលុយ។ កុំផ្ញើលុយ ហើយទុកសារនេះជាភស្តុតាង។",
            "This message threatens to post photos or tell other people unless you send money. Don't send money, and keep this message as evidence.",
        ),
        Signal::PaymentRedirect => (
            "សារនេះឱ្យបង់ថ្លៃភ្លើង ថ្លៃសេវា ឬពន្ធ តាមភ្នាក់ងារ ឬគណនីផ្សេង មិនមែនតាមវិធីផ្លូវការទេ។ សូមបង់តាមកម្មវិធីផ្លូវការ ឬតេទៅស្ថាប័ននោះផ្ទាល់។",
            "This message asks you to pay a power bill, fee or tax through an agent or another account, not the official way. Pay through the official app or call the organisation directly.",
        ),
        Signal::RecruitmentBait => (
            "សារនេះផ្សាយការងារវាយអក្សរ ឆាត ឬ call center ប្រាក់ខែខ្ពស់ ដែលតែងជាការបោកទៅធ្វើការក្នុងទីតាំងបោកប្រាស់។ គេអាចដកលិខិតឆ្លងដែនរបស់អ្នក ហើយបង្ខំឱ្យធ្វើការ។",
            "This message advertises high-paid typing, chat or call-centre work, a common way of luring people into scam compounds. They may take your passport and force you to work.",
        ),
        Signal::MalwareFile => (
            "ឯកសារនេះជាកម្មវិធី (ដូចជា .apk ឬ .exe) មិនមែនឯកសារធម្មតាទេ។ កុំបើក ឬដំឡើង ព្រោះវាអាចចូលគ្រប់គ្រងទូរស័ព្ទរបស់អ្នក។",
            "This file is a program (like .apk or .exe), not a normal document. Don't open or install it, because it can take control of your phone.",
        ),
        Signal::GamblingBait => (
            "សារនេះផ្សាយល្បែងភ្នាល់ ឬកាស៊ីណូអនឡាញ។ ល្បែងស៊ីសងអនឡាញខុសច្បាប់នៅកម្ពុជា ហើយគេហទំព័របែបនេះច្រើនតែមិនឱ្យដកលុយវិញទេ។",
            "This message advertises online betting or a casino. Online gambling is illegal in Cambodia, and sites like this often won't let you withdraw your money.",
        ),
        Signal::Urgency => (
            "សារនេះប្រញាប់ឱ្យអ្នកធ្វើភ្លាមៗ។",
            "This message pushes you to act right away.",
        ),
        Signal::Reported(reporters) => {
            return match lang {
                Lang::Km => {
                    format!("មានអ្នកប្រើ {reporters} នាក់ រាយការណ៍ថាគណនីនេះមិនមែនជាអ្នកទទួលដែលពួកគេចង់បង់ឱ្យទេ។")
                }
                Lang::En => format!(
                    "{reporters} people reported that this account wasn't who they meant to pay."
                ),
            };
        }
        Signal::Model { category, .. } => {
            return match lang {
                Lang::Km => format!(
                    "AI រកឃើញថា សារនេះមានសញ្ញាប្រហាក់ប្រហែលនឹង{}។",
                    category_name(category, lang)
                ),
                Lang::En => format!(
                    "The AI thinks this message looks like {}.",
                    category_name(category, lang)
                ),
            };
        }
        Signal::ModelUnavailable => (
            "ពេលនេះ AI មិនអាចពិនិត្យបាន ដូច្នេះលទ្ធផលនេះមកពីការពិនិត្យស្វ័យប្រវត្តិតែប៉ុណ្ណោះ។",
            "The AI can't check right now, so this result comes from the automatic checks only.",
        ),
    };
    lang.pick(km, en).to_owned()
}

fn brand_name(brand: &str, lang: Lang) -> &str {
    if brand == link::GOVERNMENT {
        lang.pick(
            "គេហទំព័ររដ្ឋាភិបាល (gov.kh)",
            "a Cambodian government site (gov.kh)",
        )
    } else {
        brand
    }
}

fn category_name(category: ScamCategory, lang: Lang) -> &'static str {
    let (km, en) = match category {
        ScamCategory::Loan => ("កម្ចីក្លែងក្លាយ", "a fake loan"),
        ScamCategory::Job => ("ការងារក្លែងក្លាយ", "a fake job"),
        ScamCategory::Otp => ("ការសុំលេខកូដសម្ងាត់", "a request for a secret code"),
        ScamCategory::Prize => ("រង្វាន់ក្លែងក្លាយ", "a fake prize"),
        ScamCategory::Account => ("ការគំរាមបិទគណនី", "a threat to close your account"),
        ScamCategory::Authority => ("ការក្លែងខ្លួនជាអាជ្ញាធរ", "someone posing as the authorities"),
        ScamCategory::Investment => ("ការវិនិយោគក្លែងក្លាយ", "a fake investment"),
        ScamCategory::Mule => ("ការជួល ឬទិញគណនីធនាគារ", "renting or buying bank accounts"),
        ScamCategory::Family => (
            "ការក្លែងខ្លួនជាសាច់ញាតិ ឬមិត្តភក្តិ",
            "someone posing as family or a friend",
        ),
        ScamCategory::Telegram => ("ការលួចគណនី Telegram", "a Telegram account takeover"),
        ScamCategory::Malware => ("ការបោកប្រាស់", "harmful software"),
        ScamCategory::Charity => ("ការសុំបរិច្ចាគក្លែងក្លាយ", "a fake donation request"),
        ScamCategory::Shop => ("ការលក់ទំនិញក្លែងក្លាយ", "a fake seller"),
        ScamCategory::Gambling => ("ល្បែងស៊ីសង ឬឆ្នោតខុសច្បាប់", "illegal gambling or a lottery"),
        ScamCategory::Extortion => ("ការគំរាមយកលុយ", "extortion"),
        ScamCategory::Recruitment => ("ការជ្រើសរើសបុគ្គលិកក្លែងក្លាយ", "fake recruitment"),
        ScamCategory::OtherScam | ScamCategory::None => ("ការបោកប្រាស់", "a scam"),
    };
    lang.pick(km, en)
}

fn render_payee(payee: &DecodedKhqr, lang: Lang) -> String {
    let mut lines = vec![
        lang.pick("QR នេះបង់ប្រាក់ទៅ៖", "This QR pays:").to_owned(),
        format!(
            "{} {}",
            lang.pick("• ឈ្មោះអ្នកទទួល៖", "• Recipient:"),
            inert(&payee.merchant_name)
        ),
        format!(
            "{} {}",
            lang.pick("• គណនី៖", "• Account:"),
            inert(&payee.bakong_account_id)
        ),
    ];
    if let Some(bank) = &payee.acquiring_bank {
        lines.push(format!(
            "{} {}",
            lang.pick("• ធនាគារ៖", "• Bank:"),
            inert(bank)
        ));
    }
    if let Some(amount) = &payee.transaction_amount {
        let currency = match payee.currency() {
            Some(Currency::Khr) => "KHR",
            Some(Currency::Usd) => "USD",
            _ => payee.transaction_currency.as_str(),
        };
        lines.push(format!(
            "{} {} {}",
            lang.pick("• ចំនួនទឹកប្រាក់៖", "• Amount:"),
            visible(amount),
            visible(currency)
        ));
    }
    lines.push(format!(
        "{} {}",
        lang.pick("• ទីក្រុង៖", "• City:"),
        inert(&payee.merchant_city)
    ));
    lines.push(
        lang.pick(
            "តើឈ្មោះនេះត្រូវនឹងហាង ឬអ្នកដែលអ្នកចង់បង់ឱ្យទេ? បើមិនត្រូវ កុំបង់។",
            "Does this name match the shop or person you mean to pay? If not, don't pay.",
        )
        .to_owned(),
    );
    lines.join("\n")
}

fn render_link(link: &LinkInfo, lang: Lang) -> String {
    let mut lines = vec![format!(
        "{} {}",
        lang.pick("• គេហទំព័រ៖", "• Site:"),
        defang(&link.host)
    )];
    if let Some(destination) = &link.redirected_to {
        lines.push(format!(
            "{} {}",
            lang.pick("• នាំបន្តទៅ៖", "• Redirects to:"),
            defang(destination)
        ));
    }
    if let Some(title) = &link.title {
        lines.push(format!(
            "{} {}",
            lang.pick("• ចំណងជើងទំព័រ៖", "• Page title:"),
            inert(title)
        ));
    }
    let owner = lang.pick("• ម្ចាស់គេហទំព័រ៖", "• Owner:");
    lines.push(match link.site {
        Some(site) if site.kind == Kind::Hosting => {
            format!("{} {}", lang.pick("• បង្កើតលើ៖", "• Built on:"), site.name)
        }
        Some(site) if site.kind == Kind::Government => {
            format!("{owner} {}", site_name(site, lang))
        }
        Some(site) => format!("{owner} {} ({})", site.name, kind_name(site.kind, lang)),
        None => format!(
            "{owner} {}",
            lang.pick(
                "មិនមែនជាគេហទំព័រល្បី ដែល CheckSen ស្គាល់ទេ",
                "not a well-known site that CheckSen knows"
            )
        ),
    });
    if let Some(days) = link.age_days {
        let age = match (lang, days / 365) {
            (Lang::Km, 0) => format!("{}ថ្ងៃ", khmer_digits(days)),
            (Lang::Km, years) => format!("{}ឆ្នាំ", khmer_digits(years)),
            (Lang::En, 0) if days == 1 => "1 day".to_owned(),
            (Lang::En, 0) => format!("{days} days"),
            (Lang::En, 1) => "1 year".to_owned(),
            (Lang::En, years) => format!("{years} years"),
        };
        lines.push(format!(
            "{} {age}",
            lang.pick("• អាយុគេហទំព័រ៖", "• Site age:")
        ));
    }
    if let Some(note) = link.site.and_then(|site| site_note(site, lang)) {
        lines.push(note);
    }
    lines.push(LINK_ADVICE.get(lang).to_owned());
    lines.join("\n")
}

fn khmer_digits(number: i64) -> String {
    number
        .to_string()
        .chars()
        .map(|c| match c.to_digit(10) {
            Some(digit) => char::from_u32('០' as u32 + digit).unwrap_or(c),
            None => c,
        })
        .collect()
}

fn site_name(site: &Site, lang: Lang) -> &'static str {
    match (site.kind, site.domain) {
        (Kind::Government, "gov.kh") => lang.pick(
            "ស្ថាប័នរដ្ឋកម្ពុជា (.gov.kh)",
            "a Cambodian government office (.gov.kh)",
        ),
        (Kind::Government, "nbc.gov.kh") => lang.pick(
            "ធនាគារជាតិនៃកម្ពុជា (Bakong)",
            "National Bank of Cambodia (Bakong)",
        ),
        _ => site.name,
    }
}

fn site_note(site: &Site, lang: Lang) -> Option<String> {
    let name = site.name;
    Some(match (site.kind, lang) {
        (Kind::Hosting, Lang::Km) => format!(
            "អ្នកណាក៏អាចបង្កើតគេហទំព័រលើ {name} បាន ដោយឥតគិតថ្លៃ។ កុំទុកចិត្ត ដោយសារតែឈ្មោះក្នុងតំណ។"
        ),
        (Kind::Hosting, Lang::En) => format!(
            "Anyone can make a site on {name} for free. Don't trust it just because of the name in the link."
        ),
        (Kind::Shortener, _) => lang
            .pick(
                "នេះជាតំណខ្លី ដែលលាក់គេហទំព័រពិត ហើយ CheckSen មិនអាចដឹងថាវានាំទៅណាទេ។ សូមប្រយ័ត្ន។",
                "This is a short link that hides the real site, and CheckSen couldn't see where it goes. Be careful.",
            )
            .to_owned(),
        (kind, Lang::Km) if kind.anyone_can_post() => format!(
            "នេះជាគេហទំព័រផ្លូវការរបស់ {name} ប៉ុន្តែអ្នកណាក៏អាចបង្កើតទំព័រនៅលើនេះបានដែរ។ សូមពិនិត្យមើលឱ្យច្បាស់ថាអ្នកណាជាអ្នកបង្ហោះ មុនពេលសម្រេចចិត្តទុកចិត្ត។"
        ),
        (kind, Lang::En) if kind.anyone_can_post() => format!(
            "This is the real {name}, but anyone can post on it. Check who posted this before you trust it."
        ),
        _ => return None,
    })
}

fn kind_name(kind: Kind, lang: Lang) -> &'static str {
    let (km, en) = match kind {
        Kind::Bank => ("ធនាគារ", "bank"),
        Kind::Finance => ("ស្ថាប័នហិរញ្ញវត្ថុ", "financial institution"),
        Kind::Wallet => ("កាបូបលុយអេឡិចត្រូនិក", "e-wallet"),
        Kind::Telecom => ("ក្រុមហ៊ុនទូរស័ព្ទ", "mobile network"),
        Kind::Government => ("ស្ថាប័នរដ្ឋ", "government"),
        Kind::Messaging => ("កម្មវិធីផ្ញើសារ", "messaging app"),
        Kind::Social => ("បណ្តាញសង្គម", "social network"),
        Kind::Video => ("គេហទំព័រវីដេអូ", "video site"),
        Kind::Code => ("ជាកន្លែងសម្រាប់រក្សាទុក និងចែករំលែកកូដកម្មវិធី", "code hosting site"),
        Kind::Files => ("សេវាឯកសារ និងទម្រង់បំពេញ", "documents and forms"),
        Kind::Email => ("សេវាអ៊ីមែល", "email"),
        Kind::Tech => ("ក្រុមហ៊ុនបច្ចេកវិទ្យា", "tech company"),
        Kind::AppStore => ("ហាងកម្មវិធីទូរស័ព្ទ", "app store"),
        Kind::Shopping => ("ហាងទំនិញអនឡាញ", "online shop"),
        Kind::Classifieds => ("គេហទំព័រលក់ទិញ", "buy and sell site"),
        Kind::News => ("សារព័ត៌មាន", "news"),
        Kind::Reference => ("សព្វវចនាធិប្បាយអនឡាញ", "online encyclopedia"),
        Kind::Ai => ("សេវា AI", "AI service"),
        Kind::Ride => ("កម្មវិធីហៅឡាន និងកុម្ម៉ង់ម្ហូប", "ride and food delivery app"),
        Kind::Shortener => ("សេវាតំណខ្លី", "link shortener"),
        Kind::Hosting => ("សេវាបង្កើតគេហទំព័រ", "website builder"),
    };
    lang.pick(km, en)
}

fn defang(host: &str) -> String {
    host.replace('.', "[.]")
}

fn visible(value: &str) -> String {
    value
        .chars()
        .filter(|&c| {
            !c.is_control() && !matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

fn inert(value: &str) -> String {
    let value = visible(value);
    let mut out = String::with_capacity(value.len());
    let mut previous: Option<char> = None;
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' if chars.peek().is_some_and(|next| next.is_alphanumeric()) => out.push_str("[.]"),
            '@' if previous.is_none_or(char::is_whitespace) => out.push('＠'),
            _ => out.push(c),
        }
        previous = Some(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::khqr::{self, tests::INDIVIDUAL_KHR_500};

    fn render_km(checks: &[Check]) -> String {
        render(checks, Lang::Km)
    }

    fn check_with(signals: Vec<Signal>, valid: bool) -> Check {
        let subject = if valid {
            Subject::Khqr(Box::new(khqr_core::decode(INDIVIDUAL_KHR_500).unwrap()))
        } else {
            Subject::Unreadable
        };
        Check { subject, signals }
    }

    fn link_check(signals: Vec<Signal>) -> Check {
        Check {
            subject: Subject::Link(LinkInfo {
                host: "bit.ly".to_owned(),
                redirected_to: Some("ababank-verify.com".to_owned()),
                age_days: Some(3),
                site: None,
                title: Some("ABA Bank Login".to_owned()),
            }),
            signals,
        }
    }

    #[test]
    fn levels_follow_signals() {
        assert_eq!(
            decide(&check_with(vec![Signal::ChecksumInvalid], false)),
            Level::HighRisk
        );
        assert_eq!(
            decide(&check_with(vec![Signal::Expired], true)),
            Level::Suspicious
        );
        assert_eq!(
            decide(&check_with(vec![Signal::NotKhqr], false)),
            Level::CantTell
        );
        assert_eq!(decide(&check_with(vec![], true)), Level::NoKnownSignals);
        assert_eq!(
            decide(&link_check(vec![Signal::Lookalike("ABA")])),
            Level::Suspicious
        );
        assert_eq!(
            decide(&link_check(vec![
                Signal::Lookalike("ABA"),
                Signal::NewDomain
            ])),
            Level::HighRisk
        );
        assert_eq!(decide(&link_check(vec![])), Level::NoKnownSignals);
    }

    #[test]
    fn model_reaches_high_risk_only_with_cited_rule_evidence() {
        let text = |signals| Check {
            subject: Subject::Text,
            signals,
        };
        let model = |cited| Signal::Model {
            category: ScamCategory::Loan,
            cited,
        };
        assert_eq!(decide(&text(vec![model(false)])), Level::Suspicious);
        assert_eq!(
            decide(&text(vec![Signal::UpfrontFee, model(false)])),
            Level::Suspicious
        );
        assert_eq!(
            decide(&text(vec![Signal::LoanBait, model(true)])),
            Level::HighRisk
        );
        assert_eq!(
            decide(&text(vec![Signal::OtpRequest, model(false)])),
            Level::HighRisk
        );
    }

    #[test]
    fn reported_account_is_suspicious_alone_and_high_risk_with_evidence() {
        let reported = check_with(vec![Signal::Reported(3)], true);
        assert_eq!(decide(&reported), Level::Suspicious);
        assert!(render_km(&[reported]).contains("3 នាក់"));
        assert_eq!(
            decide(&check_with(
                vec![Signal::Reported(3), Signal::Expired],
                true
            )),
            Level::HighRisk
        );
    }

    #[test]
    fn every_reply_sends_user_to_bank_app_and_never_says_safe() {
        for lang in [Lang::Km, Lang::En] {
            let render_km = |checks: &[Check]| render(checks, lang);
            let replies = [
                screenshot_unread(lang),
                render_km(&[]),
                render_km(&[khqr::check(INDIVIDUAL_KHR_500)]),
                render_km(&[check_with(vec![Signal::ChecksumInvalid], false)]),
                render_km(&[check_with(vec![Signal::Expired], true)]),
                render_km(&[check_with(vec![Signal::NotKhqr], false)]),
                render_km(&[link_check(vec![
                    Signal::Lookalike("ABA"),
                    Signal::NewDomain,
                ])]),
                render_km(&[link_check(vec![])]),
                render_km(&[crate::analyzers::text::check("សូមផ្ញើលេខកូដ OTP មកខ្ញុំ")]),
                render_km(&[crate::analyzers::text::check("See you at the café at 6")]),
                render_km(&[Check {
                    subject: Subject::Text,
                    signals: vec![Signal::ModelUnavailable],
                }]),
                render_km(&[Check {
                    subject: Subject::Text,
                    signals: vec![Signal::Model {
                        category: ScamCategory::Prize,
                        cited: false,
                    }],
                }]),
            ];
            for reply in replies {
                assert!(reply.ends_with(BANK_APP_ADVICE.get(lang)), "{reply}");
                assert!(!reply.contains("សុវត្ថិភាព") && !reply.to_lowercase().contains("safe"));
            }
        }
    }

    #[test]
    fn valid_reply_shows_payee() {
        let reply = render_km(&[khqr::check(INDIVIDUAL_KHR_500)]);
        assert!(reply.contains("jonhsmith@nbcq") && reply.contains("500 KHR"));
    }

    #[test]
    fn fixed_answers_never_say_safe() {
        for lang in [Lang::Km, Lang::En] {
            for name in Intent::NAMES {
                let intent: Intent = serde_json::from_value(serde_json::json!(name)).unwrap();
                let Some(answer) = answer(intent, lang) else {
                    continue;
                };
                assert!(!answer.contains("សុវត្ថិភាព") && !answer.to_lowercase().contains("safe"));
            }
        }
    }

    #[test]
    fn language_follows_script() {
        assert_eq!(Lang::of("សួស្តី hi"), Some(Lang::Km));
        assert_eq!(Lang::of("Your account is locked"), Some(Lang::En));
        assert_eq!(Lang::of("012 345 678"), None);
    }

    #[test]
    fn qr_payee_fields_cannot_become_links_or_hide_text() {
        assert_eq!(inert("aba-help.top"), "aba-help[.]top");
        assert_eq!(inert("@ABA_Support KH"), "＠ABA_Support KH");
        assert_eq!(inert("sok@abaa"), "sok@abaa");
        assert_eq!(inert("Mr. Sok"), "Mr. Sok");
        assert_eq!(inert("SOK\u{202E}ARAD"), "SOKARAD");
    }

    #[test]
    fn link_reply_names_the_site_owner() {
        let reply = |host: &str| {
            render_km(&[Check {
                subject: Subject::Link(LinkInfo {
                    host: host.to_owned(),
                    redirected_to: None,
                    age_days: None,
                    site: crate::analyzers::sites::identify(host),
                    title: None,
                }),
                signals: vec![],
            }])
        };
        let github = reply("github.com");
        assert!(github.contains("GitHub (") && github.contains("អ្នកណាក៏អាចបង្កើតទំព័រនៅលើនេះបានដែរ"));
        assert!(reply("www.ababank.com").contains("ABA (ធនាគារ)"));
        assert!(reply("aba-gift.github.io").contains("បង្កើតលើ៖ GitHub Pages"));
        assert!(reply("example.com").contains("មិនមែនជាគេហទំព័រល្បី"));
        assert_eq!(khmer_digits(19), "១៩");
        let english = render(
            &[Check {
                subject: Subject::Link(LinkInfo {
                    host: "github.com".to_owned(),
                    redirected_to: None,
                    age_days: Some(365 * 19),
                    site: crate::analyzers::sites::identify("github.com"),
                    title: None,
                }),
                signals: vec![],
            }],
            Lang::En,
        );
        assert!(
            english.contains("• Owner: GitHub (code hosting site)") && english.contains("19 years")
        );
    }

    #[test]
    fn link_reply_defangs_domains() {
        let reply = render_km(&[link_check(vec![Signal::Lookalike("ABA")])]);
        assert!(reply.contains("bit[.]ly") && reply.contains("ababank-verify[.]com"));
        assert!(!reply.contains("ababank-verify.com"));
        assert!(reply.contains("ABA Bank Login"));
    }
}
