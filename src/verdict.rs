use khqr_core::{Currency, DecodedKhqr};

use crate::analyzers::file::{Detector, FileInfo, FileKind, Unread, VirusTotal};
use crate::analyzers::indicators::IndicatorKind;
use crate::analyzers::inside::Power;
use crate::analyzers::intent::Intent;
use crate::analyzers::link::{self, LinkInfo};
use crate::analyzers::llm::{MessageKind, ScamCategory};
use crate::analyzers::reputation::Threat;
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
    "សូមផ្ញើសារ តំណ (link) កូដ KHQR រូបថតអេក្រង់ ឬឯកសារ ដែលអ្នកសង្ស័យ មកទីនេះ។ ខ្ញុំនឹងប្រាប់ថា QR បង់ប្រាក់ទៅអ្នកណា តំណនាំទៅគេហទំព័រណា ឯកសារនោះជាអ្វីពិតប្រាកដ និងសារនោះមានសញ្ញាបោកប្រាស់ឬអត់។\n\nបើអ្នកដឹងថាវាជាការបោកប្រាស់ ចុច 🚩 នៅក្រោមចម្លើយរបស់ខ្ញុំ។ ពេលមានអ្នក ៣ នាក់រាយការណ៍ CheckSen នឹងព្រមានអ្នកដទៃ។\n\nCheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។ ដើម្បីពិនិត្យ អត្ថបទ និងរូបភាពអាចត្រូវបានផ្ញើទៅសេវា AI របស់ក្រុមហ៊ុនខាងក្រៅ ដែលអាចយកទៅកែលម្អសេវារបស់គេ ហើយមនុស្សអាចមើលឃើញ។ សូមបិទលេខគណនី និងព័ត៌មានផ្ទាល់ខ្លួនសិន មុនផ្ញើ។",
    "Send me a message, link, KHQR code, screenshot or file you're unsure about. I'll tell you who a QR really pays, where a link goes, what a file really is, and whether a message has scam signs.\n\nIf you know it's a scam, tap 🚩 under my reply. Once 3 people report it, CheckSen warns others.\n\nCheckSen doesn't keep your messages or images. To check them, text and images may be sent to an outside company's AI service, which may use them to improve its service and let people see them. Please hide account numbers and personal details before sending.",
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
pub const NOTHING_IN_PHOTO: Text = text(
    "រូបនេះមិនមាន QR កូដ ឬអក្សរសារ ដែលខ្ញុំអាចពិនិត្យបានទេ។ បើជារូប QR សូមថតឱ្យច្បាស់ ឱ្យឃើញ QR ទាំងមូល។ បើជាសារ សូមផ្ញើរូបថតអេក្រង់សារនោះ ឬចម្លងអក្សរមក។",
    "This photo has no QR code or message text for me to check. If it's a QR, take a clear photo of the whole code. If it's a message, send a screenshot of it or paste the text.",
);
/// For messages forwarded from Telegram's own service account, which nobody else can send as.
pub const FROM_TELEGRAM: Text = text(
    "ℹ️ សារនេះពិតជាមកពីគណនីផ្លូវការរបស់ Telegram មែន។\n👉 កុំឱ្យលេខកូដក្នុងសារនេះទៅនរណាម្នាក់ឡើយ សូម្បីតែអ្នកដែលអះអាងថាមកពី Telegram ក៏ដោយ។ បើអ្នកមិនបានសុំលេខកូដនេះទេ មានគេកំពុងព្យាយាមចូលគណនីរបស់អ្នក៖ សូមបើក Two-Step Verification ក្នុង Settings → Privacy and Security។",
    "ℹ️ This message really is from Telegram's official account.\n👉 Never give the code in it to anyone, even someone who says they're from Telegram. If you didn't ask for this code, someone is trying to get into your account: turn on Two-Step Verification in Settings → Privacy and Security.",
);
pub const TOO_SHORT: Text = text(
    "ខ្ញុំមិនអាចពិនិត្យពាក្យខ្លីៗបែបនេះបានទេ។ សូមផ្ញើសារទាំងមូល Link ឬ KHQR ដែលអ្នកបានទទួល មកខ្ញុំពិនិត្យ។",
    "I can't check this on its own. Forward me the whole message, link or KHQR you got.",
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
    "ដើម្បីរាយការណ៍៖\n• បើអ្នកបានបាត់លុយ ឬប្រាប់លេខកូដ សូមតេទៅធនាគាររបស់អ្នកមុនគេ តាមលេខក្នុងកម្មវិធី។\n• ក្នុង Telegram សូមបើកគណនី ឬឆានែលនោះ ចុច ⋮ ហើយជ្រើស Report។\n• ចុច 🚩 នៅក្រោមចម្លើយរបស់ CheckSen ដើម្បីឱ្យវាព្រមានអ្នកដទៃអំពីលេខ គណនី ឬគេហទំព័រនោះ។\n• អ្នកក៏អាចរាយការណ៍ទៅប៉ូលិសផងដែរ។",
    "To report a scam:\n• If you lost money or shared a code, call your bank first, on the number in its app.\n• In Telegram, open that account or channel, tap ⋮ and choose Report.\n• Tap 🚩 under a CheckSen reply so it warns others about that number, account or site.\n• You can also report it to the police.",
);
const PRIVACY: Text = text(
    "CheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។ ដើម្បីពិនិត្យ អត្ថបទ និងរូបភាពអាចត្រូវបានផ្ញើទៅសេវា AI របស់ក្រុមហ៊ុនខាងក្រៅ ដែលអាចយកទៅកែលម្អសេវារបស់គេ ហើយមនុស្សអាចមើលឃើញ។ សូមបិទលេខគណនី និងព័ត៌មានផ្ទាល់ខ្លួនសិន មុនផ្ញើ។ តំណភ្ជាប់ត្រូវបានពិនិត្យជាមួយបញ្ជីគេហទំព័រគ្រោះថ្នាក់របស់ Google និង URLhaus។ ឯកសារត្រូវបានពិនិត្យក្នុងអង្គចងចាំ ហើយលុបចោលភ្លាម។ មានតែលេខសម្គាល់ឯកសារ (hash) ប៉ុណ្ណោះ ដែលត្រូវផ្ញើទៅ VirusTotal និង MalwareBazaar មិនមែនឯកសារខ្លួនឯងទេ។ បើអ្នករាយការណ៍ការបោកប្រាស់ CheckSen រក្សាទុកតែលេខទូរស័ព្ទ ឈ្មោះគណនី គេហទំព័រ ឬគណនី QR នោះ ជាមួយលេខ Telegram របស់អ្នកដែលបានបំប្លែងជាកូដ (hash)។ ចុច /forget ដើម្បីលុបការរាយការណ៍របស់អ្នក។",
    "CheckSen doesn't keep your messages or images. To check them, text and images may be sent to an outside company's AI service, which may use them to improve its service and let people see them. Please hide account numbers and personal details before sending. Links are checked against Google's and URLhaus's lists of dangerous sites. Files are checked in memory and deleted; only a file's fingerprint (hash) is sent to VirusTotal and MalwareBazaar, never the file itself. If you report a scam, CheckSen stores only that phone number, username, website or QR account, with your Telegram ID hashed. Tap /forget to delete your reports.",
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
    "ថ្ងៃនេះអ្នករាយការណ៍ច្រើនដងហើយ។ សូមរាយការណ៍ម្តងទៀតនៅថ្ងៃស្អែក ហើយកុំបង់ប្រាក់ ឬឆ្លើយតប ទាល់តែអ្នកប្រាកដ។",
    "You've reported a lot today. Please report again tomorrow, and don't pay or reply until you're sure.",
);
pub const REPORT_FAILED: Text = text(
    "ពេលនេះមិនអាចរាយការណ៍បានទេ។ សូមកុំបង់ប្រាក់ ឬឆ្លើយតប ទាល់តែអ្នកប្រាកដ។",
    "Reporting isn't working right now. Please don't pay or reply until you're sure.",
);
pub const FORGET_FAILED: Text = text(
    "ពេលនេះមិនអាចលុបការរាយការណ៍របស់អ្នកបានទេ។ សូមសាកម្តងទៀតពេលក្រោយ។",
    "Couldn't delete your reports right now. Please try again later.",
);
pub const REPLY_FAILED: Text = text(
    "ខ្ញុំមិនអាចបង្ហាញលទ្ធផលបានទេ។ សូមប្រយ័ត្ន ហើយកុំបើក ឬបង់ប្រាក់អ្វីទាំងអស់ ទាល់តែអ្នកប្រាកដ។",
    "I couldn't show the result. Be careful, and don't open or pay for anything until you're sure.",
);
pub const SCAM_REPORTED: Text = text(
    "អរគុណសម្រាប់ការរាយការណ៍។ បើមានអ្នកផ្សេងទៀតរាយការណ៍ដូចគ្នា CheckSen នឹងព្រមានអ្នកដទៃ។",
    "Thanks for reporting. If others report it too, CheckSen will warn people about it.",
);
pub const REPORT_BUTTON: Text = text("🚩 រាយការណ៍ថាជាការបោកប្រាស់", "🚩 Report as a scam");
pub const REPORT_EXPIRED: Text = text(
    "ប៊ូតុងនេះផុតកំណត់ហើយ។ សូមផ្ញើសារនោះមកម្តងទៀត ដើម្បីរាយការណ៍។",
    "This button has expired. Send the message again to report it.",
);
pub const RATE_LIMITED: Text = text(
    "អ្នកផ្ញើមកច្រើនពេកក្នុងពេលខ្លី។ សូមរង់ចាំបន្តិច ហើយសាកម្តងទៀត។",
    "You've sent a lot in a short time. Please wait a little and try again.",
);
const BANK_APP_ADVICE: Text = text(
    "⚠️ មុនពេលបង់ប្រាក់៖ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់នៅក្នុងកម្មវិធីធនាគាររបស់អ្នកឱ្យបានហ្មត់ចត់ជានិច្ច។",
    "⚠️ Before paying, always check the recipient's name and the amount in your bank app.",
);
const LINK_ADVICE: Text = text(
    "មិនត្រូវបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP តាមតំណភ្ជាប់ (Link) ណាមួយឡើយ។ បើចង់ពិនិត្យមើលគណនី សូមបើកចូលកម្មវិធីធនាគាររបស់អ្នកដោយផ្ទាល់។",
    "Never enter a password or OTP code through a link. To check your account, open your bank app yourself.",
);
const OPENED_FILE: Text = text(
    "🆘 បើអ្នកបានបើកវារួចហើយ៖\n1. ក្នុង Telegram ចូល Settings → Devices ហើយបិទឧបករណ៍ដែលអ្នកមិនស្គាល់។\n2. ប្តូរលេខសម្ងាត់ Two-Step Verification។\n3. ស្កេនកុំព្យូទ័រ ឬទូរស័ព្ទរកមេរោគ ហើយចាកចេញពីកម្មវិធីធនាគារ។\n4. បើគណនីរបស់អ្នកត្រូវគេយកទៅបោកអ្នកដទៃ សូមតេទៅប៉ូលិសជាតិ លេខ 117។",
    "🆘 If you already opened it:\n1. In Telegram, go to Settings → Devices and end any session you don't recognise.\n2. Change your Two-Step Verification password.\n3. Scan your computer or phone for viruses, and log out of your bank app.\n4. If your account was used to scam others, call the National Police on 117.",
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

    /// Files are checked for viruses and dangerous content, not for a scammer's words.
    fn label_for(self, subject: &Subject, lang: Lang) -> &'static str {
        match (self, subject) {
            (Self::NoKnownSignals, Subject::File(_)) => lang.pick(
                "⚪ មិនទាន់រកឃើញសញ្ញាគ្រោះថ្នាក់ទេ",
                "⚪ No signs of danger found yet",
            ),
            _ => self.label(lang),
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

pub fn no_qr_found(lang: Lang) -> String {
    format!(
        "{}\n{}\n\n{}",
        Level::CantTell.label(lang),
        NO_QR_FOUND.get(lang),
        BANK_APP_ADVICE.get(lang)
    )
}

/// A step of a slow check, listed in the status message while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Download,
    Scan,
    FindQr,
    ReadText,
    CheckLinks,
}

impl Step {
    fn name(self, lang: Lang) -> &'static str {
        match self {
            Self::Download => lang.pick("ទាញយកឯកសារ", "Download the file"),
            Self::Scan => lang.pick("ស្កេនរកមេរោគ", "Scan for viruses"),
            Self::FindQr => lang.pick("រក QR ក្នុងរូប", "Look for a QR code"),
            Self::ReadText => lang.pick("អានអក្សរក្នុងរូប", "Read the text in the image"),
            Self::CheckLinks => lang.pick("ពិនិត្យតំណក្នុងឯកសារ", "Check the links inside"),
        }
    }
}

/// Telegram HTML: the steps done so far, and the one running now.
pub fn progress(done: &[Step], current: Step, lang: Lang) -> String {
    let mut lines = vec![format!(
        "<b>{}</b>",
        lang.pick("🔍 កំពុងពិនិត្យ…", "🔍 Checking…")
    )];
    lines.extend(done.iter().map(|step| format!("✅ {}", step.name(lang))));
    lines.push(format!("⏳ {}…", current.name(lang)));
    lines.join("\n")
}

/// Who a forwarded message came from and what kind of message it is.
#[derive(Debug, Default, Clone, Copy)]
pub struct About<'a> {
    pub forwarded_from: Option<&'a str>,
    pub kind: Option<MessageKind>,
    /// The owner of the official channel it was forwarded from.
    pub official: Option<&'static str>,
}

/// Telegram HTML: the verdict, one line on what it is, one action, then the details folded away.
/// A file's name, type and scan results stay outside the fold.
pub fn render(checks: &[Check], about: About, lang: Lang) -> String {
    let Some(lead) = checks
        .iter()
        .min_by_key(|check| std::cmp::Reverse(severity(decide(check))))
    else {
        return escape(&no_qr_found(lang));
    };
    let level = decide(lead);
    let top = top_signal(lead, level);
    let summary = summary(lead, level, top, lang);
    let action = action(lead, level, about.kind, lang).filter(|action| {
        !summary
            .as_deref()
            .is_some_and(|summary| summary.contains(action.as_str()))
    });
    let about = about_line(about, lang);

    let mut lines = vec![format!(
        "<b>{}</b>",
        escape(level.label_for(&lead.subject, lang))
    )];
    let lead_file = match &lead.subject {
        Subject::File(file) => Some(file),
        _ => None,
    };
    if lead_file.is_none()
        && let Some(about) = &about
    {
        lines.push(escape(about));
    }
    // A link found inside a file isn't one the person can see, so say which it is.
    if let Subject::Link(link) = &lead.subject
        && link.in_file
    {
        lines.push(format!(
            "🔗 {} {}",
            escape(lang.pick("តំណក្នុងឯកសារ៖", "Link inside the file:")),
            escape(&defang(&link.host))
        ));
    }
    if let Some(summary) = &summary {
        lines.push(escape(summary));
    }
    if let Some(action) = &action {
        lines.push(format!("👉 {}", escape(action)));
    }
    if let Some(file) = lead_file {
        lines.push(String::new());
        lines.push(escape(&file_card(
            file,
            summary.as_deref(),
            about.as_deref(),
            lang,
        )));
    }
    let about_money = matches!(level, Level::HighRisk | Level::Suspicious)
        && !matches!(lead.subject, Subject::File(_))
        || checks
            .iter()
            .any(|check| matches!(check.subject, Subject::Khqr(_)));
    if about_money {
        lines.push(String::new());
        lines.push(escape(BANK_APP_ADVICE.get(lang)));
    }

    let mut details: Vec<String> = Vec::new();
    let lead_first =
        std::iter::once(lead).chain(checks.iter().filter(|check| !std::ptr::eq(*check, lead)));
    for check in lead_first {
        let is_lead = std::ptr::eq(check, lead);
        let section = detail_section(
            check,
            checks.len() > 1,
            is_lead.then_some(top).flatten(),
            is_lead,
            lang,
        );
        if !section.is_empty() && !details.contains(&section) {
            details.push(section);
        }
    }
    let link_advice = LINK_ADVICE.get(lang);
    let has_links = checks
        .iter()
        .any(|check| matches!(check.subject, Subject::Link(_)));
    if has_links && action.as_deref() != Some(link_advice) {
        details.push(link_advice.to_owned());
    }
    // Files have nothing to do with paying, so they get no bank-app reminder.
    let only_files = checks
        .iter()
        .all(|check| matches!(check.subject, Subject::File(_)));
    if !about_money && !only_files {
        // A fold holding only the reminder isn't worth a tap, so it is shown inline instead.
        if details.is_empty() {
            lines.push(String::new());
            lines.push(escape(BANK_APP_ADVICE.get(lang)));
        } else {
            details.push(BANK_APP_ADVICE.get(lang).to_owned());
        }
    }
    let mut fold = Vec::new();
    if !details.is_empty() {
        let heading = lang.pick("ℹ️ ព័ត៌មានលម្អិត", "ℹ️ Details");
        fold.push(format!("{heading}\n{}", details.join("\n\n")));
    }
    let risky_file = checks.iter().any(|check| {
        matches!(check.subject, Subject::File(_)) && decide(check) != Level::NoKnownSignals
    });
    if risky_file {
        fold.push(OPENED_FILE.get(lang).to_owned());
    }
    if !fold.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "<blockquote expandable>{}</blockquote>",
            escape(&fold.join("\n\n"))
        ));
    }
    lines.join("\n")
}

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn severity(level: Level) -> u8 {
    match level {
        Level::HighRisk => 3,
        Level::Suspicious => 2,
        Level::CantTell => 1,
        Level::NoKnownSignals => 0,
    }
}

/// Urgency alone is common in honest promotions, so it is only explained next to other signs.
fn shown_signals(check: &Check, level: Level) -> Vec<Signal> {
    check
        .signals
        .iter()
        .copied()
        .filter(|&signal| !(signal == Signal::Urgency && level == Level::NoKnownSignals))
        .collect()
}

fn top_signal(check: &Check, level: Level) -> Option<Signal> {
    let shown = shown_signals(check, level);
    let strongest = shown
        .iter()
        .copied()
        .filter(|signal| signal.weight() > 0.0)
        .reduce(|best, signal| {
            if signal.weight() > best.weight() {
                signal
            } else {
                best
            }
        });
    match level {
        Level::NoKnownSignals => None,
        Level::CantTell => strongest.or(shown.first().copied()),
        _ => strongest,
    }
}

/// `None` for a file with nothing found, since its card below says what it is.
fn summary(check: &Check, level: Level, top: Option<Signal>, lang: Lang) -> Option<String> {
    if let Some(signal) = top {
        return Some(reason(signal, lang));
    }
    Some(match &check.subject {
        Subject::Khqr(payee) => {
            let mut line = format!(
                "{} {}",
                lang.pick("QR នេះបង់ទៅ៖", "This QR pays:"),
                inert(&payee.merchant_name)
            );
            if let Some(amount) = amount(payee) {
                line.push_str(&format!(" · {amount}"));
            }
            line
        }
        Subject::Link(link) => link_summary(link, lang),
        Subject::File(_) => return None,
        Subject::Text if level == Level::NoKnownSignals => NO_TEXT_SIGNALS.get(lang).to_owned(),
        Subject::Text | Subject::Unreadable => Level::CantTell.label(lang).to_owned(),
    })
}

fn link_summary(link: &LinkInfo, lang: Lang) -> String {
    let host = defang(link.redirected_to.as_deref().unwrap_or(&link.host));
    let mut parts = match link.site {
        Some(site) if site.kind == Kind::Hosting => vec![
            host,
            format!("{} {}", lang.pick("បង្កើតលើ", "built on"), site.name),
        ],
        Some(site) if site.kind == Kind::Shortener => {
            vec![site.name.to_owned(), kind_name(site.kind, lang).to_owned()]
        }
        Some(site) if site.kind == Kind::Government => vec![
            host,
            lang.pick("គេហទំព័ររដ្ឋាភិបាលកម្ពុជា", "Cambodian government site")
                .to_owned(),
        ],
        Some(site) => vec![
            site_name(site, lang).to_owned(),
            lang.pick("គេហទំព័រផ្លូវការ", "official site").to_owned(),
        ],
        None => vec![
            host,
            lang.pick("មិនមែនជាគេហទំព័រល្បី", "not a well-known site")
                .to_owned(),
        ],
    };
    if let Some(age) = link.age_days.map(|days| age(days, lang)) {
        parts.push(age);
    }
    parts.join(" · ")
}

fn action(check: &Check, level: Level, kind: Option<MessageKind>, lang: Lang) -> Option<String> {
    let text = match (&check.subject, level) {
        (_, Level::CantTell) => return None,
        (Subject::File(_), Level::HighRisk) => lang.pick(
            "កុំបើក ឬដំឡើងឯកសារនេះ ហើយលុបវាចោល។",
            "Don't open or install this file. Delete it.",
        ),
        (Subject::File(_), Level::Suspicious) => lang.pick(
            "កុំបើកឯកសារនេះ ទាល់តែអ្នកស្គាល់អ្នកផ្ញើ ហើយបានសួរគេផ្ទាល់។",
            "Don't open it unless you know the sender and have asked them directly.",
        ),
        (Subject::File(_), Level::NoKnownSignals) => lang.pick(
            "បើកតែឯកសារពីអ្នកដែលអ្នកស្គាល់ និងទុកចិត្តប៉ុណ្ណោះ។",
            "Only open files from people you know and trust.",
        ),
        (Subject::Khqr(_) | Subject::Unreadable, Level::HighRisk) => {
            lang.pick("កុំបង់ប្រាក់តាម QR នេះ។", "Don't pay with this QR.")
        }
        (Subject::Link(_), Level::HighRisk) => lang.pick(
            "កុំបើកតំណនេះ ហើយកុំបញ្ចូលព័ត៌មានអ្វីទាំងអស់។",
            "Don't open this link or enter anything on it.",
        ),
        (_, Level::HighRisk) => lang.pick(
            "កុំឆ្លើយតប កុំប្រាប់លេខកូដ ហើយកុំផ្ទេរលុយ។",
            "Don't reply, don't share any code, and don't send money.",
        ),
        (Subject::Khqr(_) | Subject::Unreadable, Level::Suspicious) => lang.pick(
            "សូមសួរអ្នកលក់ឱ្យប្រាកដពីគណនីរបស់គេ មុនពេលបង់ប្រាក់។",
            "Ask the seller to confirm their account before you pay.",
        ),
        (Subject::Link(_), Level::Suspicious) => lang.pick(
            "កុំបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP លើគេហទំព័រនេះ។",
            "Don't enter a password or OTP code on this site.",
        ),
        (_, Level::Suspicious) => lang.pick(
            "សូមផ្ទៀងផ្ទាត់តាមលេខ ឬកម្មវិធីផ្លូវការសិន មុនពេលធ្វើតាមសារនេះ។",
            "Check through an official number or app before you do what it asks.",
        ),
        (Subject::Khqr(_), Level::NoKnownSignals) => lang.pick(
            "តើឈ្មោះនេះត្រូវនឹងហាង ឬអ្នកដែលអ្នកចង់បង់ឱ្យទេ? បើមិនត្រូវ កុំបង់។",
            "Does this name match the shop or person you mean to pay? If not, don't pay.",
        ),
        (Subject::Link(link), Level::NoKnownSignals) => {
            return link
                .site
                .and_then(|site| site_note(site, lang))
                .or_else(|| kind_tip(kind, lang).map(str::to_owned))
                .or_else(|| Some(LINK_ADVICE.get(lang).to_owned()));
        }
        (Subject::Text | Subject::Unreadable, Level::NoKnownSignals) => {
            return kind_tip(kind, lang).map(str::to_owned);
        }
    };
    Some(text.to_owned())
}

/// The one thing to remember for a kind of message that scammers often copy.
fn kind_tip(kind: Option<MessageKind>, lang: Lang) -> Option<&'static str> {
    let (km, en) = match kind? {
        MessageKind::JobAd => (
            "ការងារពិត មិនដែលឱ្យបង់ថ្លៃមុនទេ។ បើគេសុំលុយ ឬលិខិតឆ្លងដែនរបស់អ្នក សូមកុំធ្វើតាម។",
            "Real jobs never ask you to pay first. If they ask for money or your passport, don't go ahead.",
        ),
        MessageKind::LoanOffer => (
            "កម្ចីពិត មិនដែលឱ្យបង់ថ្លៃមុន ទើបបើកលុយឱ្យទេ។",
            "Real lenders never ask for a fee before they pay out the loan.",
        ),
        MessageKind::Prize => (
            "រង្វាន់ពិត មិនដែលឱ្យបង់ថ្លៃ ឬប្រាប់លេខកូដ ដើម្បីទទួលទេ។",
            "Real prizes never need a fee or a code to claim.",
        ),
        MessageKind::Investment => (
            "គ្មានការវិនិយោគណា អាចធានាថាចំណេញបានទេ។ សូមប្រយ័ត្ន មុនពេលដាក់លុយ។",
            "No real investment can promise a profit. Be careful before you put money in.",
        ),
        MessageKind::MoneyRequest => (
            "សូមតេទៅម្ចាស់ផ្ទាល់ ដើម្បីបញ្ជាក់ មុនពេលផ្ទេរលុយ។",
            "Call the person directly to confirm before you send any money.",
        ),
        MessageKind::ForSale => (
            "កុំបង់ប្រាក់កក់ ទាល់តែអ្នកប្រាកដថាអ្នកលក់ពិតប្រាកដ។",
            "Don't pay a deposit until you're sure the seller is real.",
        ),
        MessageKind::Promotion
        | MessageKind::News
        | MessageKind::Notice
        | MessageKind::Personal
        | MessageKind::Other => return None,
    };
    Some(lang.pick(km, en))
}

fn about_line(about: About, lang: Lang) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(kind) = about.kind.and_then(|kind| kind_label(kind, lang)) {
        parts.push(kind.to_owned());
    }
    if let Some(owner) = about.official {
        parts.push(match lang {
            Lang::Km => format!("បញ្ជូនបន្តពីឆានែលផ្លូវការរបស់ {owner}"),
            Lang::En => format!("forwarded from {owner}'s official channel"),
        });
    } else if let Some(name) = about
        .forwarded_from
        .map(inert)
        .filter(|name| !name.trim().is_empty())
    {
        parts.push(format!("{} {name}", lang.pick("បញ្ជូនបន្តពី", "forwarded from")));
    }
    if parts.is_empty() {
        return None;
    }
    let line = parts.join(" · ");
    let mut chars = line.chars();
    Some(match (lang, chars.next()) {
        (Lang::En, Some(first)) => first.to_uppercase().chain(chars).collect(),
        _ => line,
    })
}

fn kind_label(kind: MessageKind, lang: Lang) -> Option<&'static str> {
    let (km, en) = match kind {
        MessageKind::Promotion => (
            "ការផ្សព្វផ្សាយ ឬប្រូម៉ូសិនរបស់ហាង",
            "a promotion or ad from a business",
        ),
        MessageKind::News => ("ព័ត៌មាន ឬការព្រមាន", "news or a public warning"),
        MessageKind::Notice => ("សេចក្តីជូនដំណឹងពីធនាគារ ឬក្រុមហ៊ុន", "a notice from a bank or company"),
        MessageKind::Personal => ("សារធម្មតារវាងមនុស្ស", "a personal message"),
        MessageKind::JobAd => ("ការផ្សាយជ្រើសរើសការងារ", "a job ad"),
        MessageKind::LoanOffer => ("ការផ្តល់កម្ចី", "a loan offer"),
        MessageKind::ForSale => ("ការលក់ទំនិញ ឬសេវា", "something for sale"),
        MessageKind::Prize => ("ការប្រកាសរង្វាន់ ឬការចាប់រង្វាន់", "a prize or giveaway"),
        MessageKind::Investment => ("ការអញ្ជើញឱ្យវិនិយោគ", "an investment offer"),
        MessageKind::MoneyRequest => ("ការសុំឱ្យផ្ទេរប្រាក់", "a request for money"),
        MessageKind::Other => return None,
    };
    Some(lang.pick(km, en))
}

fn detail_section(
    check: &Check,
    labeled: bool,
    skip: Option<Signal>,
    is_lead: bool,
    lang: Lang,
) -> String {
    let level = decide(check);
    let mut lines = Vec::new();
    if labeled {
        lines.push(level.label_for(&check.subject, lang).to_owned());
    }
    // A file's card already shows its scan results and an app's powers, and its real type when it leads.
    let on_card = |signal: &Signal| match (&check.subject, signal) {
        (
            Subject::File(_),
            Signal::KnownMalware(_) | Signal::FlaggedByFewEngines(_) | Signal::AppPower(_),
        ) => true,
        (Subject::File(file), Signal::DangerousFile(kind)) => is_lead && file.real == Some(*kind),
        _ => false,
    };
    lines.extend(
        shown_signals(check, level)
            .into_iter()
            .filter(|&signal| Some(signal) != skip)
            .filter(|signal| !on_card(signal))
            .map(|signal| reason(signal, lang)),
    );
    match &check.subject {
        Subject::Khqr(payee) => lines.push(render_payee(payee, lang)),
        Subject::Link(link) => {
            let rendered = render_link(link, lang);
            // The link inside a file is already named at the top of the reply.
            match rendered.split_once('\n') {
                Some((_, rest)) if is_lead && link.in_file => lines.push(rest.to_owned()),
                None if is_lead && link.in_file => {}
                _ => lines.push(rendered),
            }
            if !is_lead && let Some(note) = link.site.and_then(|site| site_note(site, lang)) {
                lines.push(note);
            }
        }
        Subject::File(file) if !is_lead => lines.push(file_card(file, None, None, lang)),
        Subject::File(_) | Subject::Text | Subject::Unreadable => {}
    }
    if lines.len() == usize::from(labeled) {
        return String::new();
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
            "សារនេះមានការទាមទារលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនផ្លូវការ ដាច់ខាតមិនដែលសុំលេខទាំងនេះឡើយ។ សូមកុំប្រាប់ព័ត៌មាននេះទៅនរណាម្នាក់ឱ្យសោះ!",
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
        Signal::PayBeforeMeeting => (
            "សារនេះសុំឱ្យផ្ញើលុយមុនពេលខល ឬជួបគ្នា។ អ្នកបោកប្រាស់តាមការស្នេហា ឬសេវាផ្លូវភេទ តែងបាត់ខ្លួនក្រោយទទួលបានលុយ។",
            "This message asks for money before a call or a meeting. Romance and escort scammers disappear once they're paid.",
        ),
        Signal::GamblingBait => (
            "សារនេះផ្សាយល្បែងភ្នាល់ ឬកាស៊ីណូអនឡាញ។ ល្បែងស៊ីសងអនឡាញខុសច្បាប់នៅកម្ពុជា ហើយគេហទំព័របែបនេះច្រើនតែមិនឱ្យដកលុយវិញទេ។",
            "This message advertises online betting or a casino. Online gambling is illegal in Cambodia, and sites like this often won't let you withdraw your money.",
        ),
        Signal::DisguisedFile { shown, real } => {
            let (shown, real) = (file_kind_name(shown, lang), file_kind_name(real, lang));
            return match lang {
                Lang::Km => format!("ឯកសារនេះធ្វើពុតជា{shown} តែតាមពិតជា{real}។"),
                Lang::En => format!("This file pretends to be {shown}, but it's really {real}."),
            };
        }
        Signal::KnownBadSite(Threat::Phishing) => (
            "Google ស្គាល់គេហទំព័រនេះថាជាគេហទំព័របោកប្រាស់ ដែលលួចលេខសម្ងាត់ ឬព័ត៌មានរបស់អ្នក។",
            "Google lists this as a phishing site that steals passwords or personal details.",
        ),
        Signal::KnownBadSite(Threat::Malware) => (
            "Google ស្គាល់គេហទំព័រនេះថាចែកចាយមេរោគ។ កុំទាញយកអ្វីពីវា។",
            "Google lists this site for spreading malware. Don't download anything from it.",
        ),
        Signal::KnownBadSite(Threat::UnwantedSoftware) => (
            "Google ស្គាល់គេហទំព័រនេះថាដំឡើងកម្មវិធីដែលមិនចង់បាន ឬបង្កគ្រោះថ្នាក់។ កុំទាញយកអ្វីពីវា។",
            "Google lists this site for pushing unwanted or harmful apps. Don't download anything from it.",
        ),
        Signal::DangerousFile(kind) => {
            let kind = file_kind_name(kind, lang);
            return match lang {
                Lang::Km => format!("ឯកសារនេះជា{kind}។"),
                Lang::En => format!("This file is {kind}."),
            };
        }
        Signal::FakeBankApp(brand) => {
            return match lang {
                Lang::Km => format!(
                    "កម្មវិធីនេះប្រើឈ្មោះ {brand}។ ធនាគារមិនដែលផ្ញើកម្មវិធីតាម Telegram ទេ។ សូមដំឡើងតែពី Play Store ឬ App Store ប៉ុណ្ណោះ។"
                ),
                Lang::En => format!(
                    "This app uses the name {brand}. Banks never send apps over Telegram. Only install apps from the Play Store or App Store."
                ),
            };
        }
        Signal::ImpersonatedSender(brand) => {
            return match lang {
                Lang::Km => format!(
                    "សារនេះបញ្ជូនបន្តពីគណនីផ្ទាល់ខ្លួន ដែលដាក់ឈ្មោះដូច {brand}។ {brand} មិនដែលផ្ញើសារមកអ្នកពីគណនីផ្ទាល់ខ្លួនទេ។"
                ),
                Lang::En => format!(
                    "This was forwarded from a personal account named like {brand}. {brand} never messages people from personal accounts."
                ),
            };
        }
        Signal::HiddenFileName => (
            "ឈ្មោះឯកសារនេះមានអក្សរលាក់ ដែលបង្វែរឈ្មោះ ដើម្បីលាក់ប្រភេទពិតរបស់វា។",
            "This file's name has a hidden character that flips the text to hide its real type.",
        ),
        Signal::ProgramInArchive => (
            "ឯកសារនេះមានកម្មវិធីលាក់នៅខាងក្នុង។",
            "This file has a program hidden inside it.",
        ),
        Signal::AppPower(Power::ReadsSms) => (
            "កម្មវិធីនេះអាចអានសារ SMS របស់អ្នក រួមទាំងលេខកូដ OTP ពីធនាគារ។",
            "This app can read your text messages, including OTP codes from your bank.",
        ),
        Signal::AppPower(Power::ControlsScreen) => (
            "កម្មវិធីនេះសុំសិទ្ធិ Accessibility ដែលអាចមើលអេក្រង់ និងចុចជំនួសអ្នកបាន។",
            "This app asks for Accessibility access, which lets it see your screen and tap for you.",
        ),
        Signal::AppPower(Power::DrawsOverApps) => (
            "កម្មវិធីនេះអាចបង្ហាញផ្ទាំងពីលើកម្មវិធីផ្សេង ដូចជាផ្ទាំងចូលធនាគារក្លែងក្លាយ។",
            "This app can draw over other apps, for example a fake bank login screen.",
        ),
        Signal::AppPower(Power::DeviceAdmin) => (
            "កម្មវិធីនេះសុំសិទ្ធិគ្រប់គ្រងឧបករណ៍ ដែលធ្វើឱ្យពិបាកលុបវាចោល។",
            "This app asks to be a device admin, which makes it hard to remove.",
        ),
        Signal::AppPower(Power::InstallsApps) => (
            "កម្មវិធីនេះអាចដំឡើងកម្មវិធីផ្សេងទៀតដោយខ្លួនឯង។",
            "This app can install other apps by itself.",
        ),
        Signal::StealsCodes => (
            "កម្មវិធីនេះអាចអានសារ SMS និងគ្រប់គ្រងអេក្រង់របស់អ្នក ដូចកម្មវិធីដែលលួចលុយពីគណនីធនាគារ។",
            "This app can read your text messages and take over your screen, the way apps that steal from bank accounts work.",
        ),
        Signal::MacroDocument => (
            "ឯកសារនេះមាន macro ដែលអាចដំណើរការកូដ ពេលអ្នកចុច Enable Content។",
            "This document has macros, which can run code if you click Enable Content.",
        ),
        Signal::PdfLaunch => (
            "PDF នេះព្យាយាមបើកកម្មវិធីផ្សេង ពេលអ្នកបើកវា។",
            "This PDF tries to start a program when you open it.",
        ),
        Signal::PdfScript => (
            "PDF នេះមានកូដ JavaScript។ ទម្រង់បំពេញខ្លះប្រើវា តែវាក៏អាចត្រូវគេប្រើក្នុងគោលបំណងអាក្រក់ដែរ។",
            "This PDF contains JavaScript. Some forms use it, but it can also be misused.",
        ),
        Signal::SendsToAttacker => (
            "ទំព័រនេះផ្ញើអ្វីដែលអ្នកវាយបញ្ចូល ដូចជាលេខសម្ងាត់ ទៅឱ្យអ្នកផ្សេងដោយសម្ងាត់។",
            "This page secretly sends what you type, like your password, to someone else.",
        ),
        Signal::DownloadsProgram(kind) => {
            let kind = file_kind_name(kind, lang);
            return match lang {
                Lang::Km => format!("តំណនេះទាញយក{kind} ជំនួសឱ្យការបើកគេហទំព័រ។"),
                Lang::En => format!("This link downloads {kind} instead of opening a page."),
            };
        }
        Signal::LockedArchive => (
            "ឯកសារ zip នេះដាក់លេខសម្ងាត់ ដូច្នេះកម្មវិធីកំចាត់មេរោគមិនអាចមើលខាងក្នុងបានទេ។ ជនបោកប្រាស់តែងប្រើល្បិចនេះ។",
            "This archive is password-protected, so antivirus can't look inside. Scammers often do this.",
        ),
        Signal::KnownMalware(Detector::MalwareBazaar) => (
            "MalwareBazaar ដែលជាបញ្ជីមេរោគសាធារណៈ ស្គាល់ឯកសារនេះថាជាមេរោគ។",
            "MalwareBazaar, a public list of malware, knows this file as malware.",
        ),
        Signal::KnownMalwareLink => (
            "URLhaus ដែលជាបញ្ជីតំណចែកចាយមេរោគ មានតំណនេះក្នុងបញ្ជី។ កុំទាញយកអ្វីពីវា។",
            "URLhaus, a public list of links that spread malware, lists this link. Don't download anything from it.",
        ),
        Signal::KnownMalware(Detector::ClamAv) => (
            "កម្មវិធីកំចាត់មេរោគ ClamAV រកឃើញមេរោគក្នុងឯកសារនេះ។",
            "ClamAV antivirus found a virus in this file.",
        ),
        Signal::KnownMalware(Detector::VirusTotal(engines)) => {
            return match lang {
                Lang::Km => format!(
                    "កម្មវិធីកំចាត់មេរោគ {} ក្នុង VirusTotal ស្គាល់ឯកសារនេះថាជាមេរោគ។",
                    khmer_digits(engines.into())
                ),
                Lang::En => {
                    format!("{engines} antivirus engines on VirusTotal know this file as malware.")
                }
            };
        }
        Signal::FlaggedByFewEngines(engines) => {
            return match lang {
                Lang::Km => format!(
                    "កម្មវិធីកំចាត់មេរោគ {} ក្នុង VirusTotal សង្ស័យឯកសារនេះ។",
                    khmer_digits(engines.into())
                ),
                Lang::En => {
                    format!(
                        "{engines} antivirus engines on VirusTotal flag this file as suspicious."
                    )
                }
            };
        }
        Signal::Urgency => (
            "សារនេះមានចេតនាបង្ខំឱ្យអ្នកប្រញាប់ធ្វើសកម្មភាពភ្លាមៗ។",
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
        Signal::ReportedScam(kind, reporters) => {
            let (km, en) = match kind {
                IndicatorKind::Phone => ("លេខទូរស័ព្ទ", "phone number"),
                IndicatorKind::TelegramUsername => ("គណនី Telegram", "Telegram account"),
                IndicatorKind::Domain => ("គេហទំព័រ", "website"),
                IndicatorKind::KhqrAccount => ("គណនី", "account"),
            };
            return match lang {
                Lang::Km => format!(
                    "មានអ្នកប្រើ {} នាក់ បានរាយការណ៍ថា{km}ក្នុងសារនេះជាការបោកប្រាស់។",
                    khmer_digits(reporters.into())
                ),
                Lang::En => {
                    format!("{reporters} people reported the {en} in this message as a scam.")
                }
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

fn amount(payee: &DecodedKhqr) -> Option<String> {
    let amount = payee.transaction_amount.as_ref()?;
    let currency = match payee.currency() {
        Some(Currency::Khr) => "KHR",
        Some(Currency::Usd) => "USD",
        _ => payee.transaction_currency.as_str(),
    };
    Some(format!("{} {}", visible(amount), visible(currency)))
}

fn render_payee(payee: &DecodedKhqr, lang: Lang) -> String {
    let mut lines = vec![
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
    if let Some(amount) = amount(payee) {
        lines.push(format!(
            "{} {amount}",
            lang.pick("• ចំនួនទឹកប្រាក់៖", "• Amount:")
        ));
    }
    lines.push(format!(
        "{} {}",
        lang.pick("• ទីក្រុង៖", "• City:"),
        inert(&payee.merchant_city)
    ));
    lines.join("\n")
}

fn age(days: i64, lang: Lang) -> String {
    match (lang, days / 365) {
        (Lang::Km, 0) => format!("{}ថ្ងៃ", khmer_digits(days)),
        (Lang::Km, years) => format!("{}ឆ្នាំ", khmer_digits(years)),
        (Lang::En, 0) if days == 1 => "1 day".to_owned(),
        (Lang::En, 0) => format!("{days} days"),
        (Lang::En, 1) => "1 year".to_owned(),
        (Lang::En, years) => format!("{years} years"),
    }
}

fn render_link(link: &LinkInfo, lang: Lang) -> String {
    let label = match link.in_file {
        true => lang.pick("• តំណក្នុងឯកសារ៖", "• Link inside the file:"),
        false => lang.pick("• គេហទំព័រ៖", "• Site:"),
    };
    let mut lines = vec![format!("{label} {}", defang(&link.host))];
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
        lines.push(format!(
            "{} {}",
            lang.pick("• អាយុគេហទំព័រ៖", "• Site age:"),
            age(days, lang)
        ));
    }
    lines.join("\n")
}

fn file_kind_name(kind: FileKind, lang: Lang) -> &'static str {
    let (km, en) = match kind {
        FileKind::Pdf => ("ឯកសារ PDF", "a PDF"),
        FileKind::Image => ("រូបភាព", "a photo"),
        FileKind::Video => ("វីដេអូ", "a video"),
        FileKind::Audio => ("សំឡេង", "an audio file"),
        FileKind::Text => ("ឯកសារអក្សរ", "a text file"),
        FileKind::Document => ("ឯកសារ Word ឬ Excel", "a Word or Excel document"),
        FileKind::Archive => ("ឯកសារបង្ហាប់ (zip)", "an archive (zip)"),
        FileKind::WindowsProgram => ("កម្មវិធីកុំព្យូទ័រ (.exe)", "a Windows program (.exe)"),
        FileKind::AndroidApp => ("កម្មវិធីទូរស័ព្ទ Android (.apk)", "an Android app (.apk)"),
        FileKind::OtherProgram => ("កម្មវិធី", "a program"),
        FileKind::Script => ("ស្គ្រីប ដែលអាចដំណើរការកូដ", "a script that runs code"),
        FileKind::WebPage => (
            "ទំព័រវេប ដែលអាចបង្ហាញទំព័រចូលគណនីក្លែងក្លាយ",
            "a web page that can show a fake login",
        ),
        FileKind::Shortcut => ("ផ្លូវកាត់ ដែលអាចបើកកម្មវិធី", "a shortcut that can run programs"),
        FileKind::DiskImage => (
            "ឯកសារ disk image ដែលអាចមានកម្មវិធី",
            "a disk image that can hold programs",
        ),
    };
    lang.pick(km, en)
}

/// File endings like .zip are also web domains, so the dot is swapped for a look-alike that Telegram won't link.
fn file_name(name: &str) -> String {
    inert(name).replace("[.]", "\u{2024}")
}

/// The file's name and type (unless the summary already gave it), where it came from, and the scan results.
fn file_card(file: &FileInfo, summary: Option<&str>, about: Option<&str>, lang: Lang) -> String {
    let mut name = format!("📎 {}", file_name(&file.name));
    if let Some(real) = file
        .real
        .map(|real| file_kind_name(real, lang))
        .filter(|real| !summary.is_some_and(|summary| summary.contains(real)))
    {
        name.push_str(&format!(" · {real}"));
    }
    let mut lines = vec![name];
    if let Some(package) = &file.package {
        lines.push(format!("📦 {}", file_name(package)));
    }
    if !file.powers.is_empty() {
        let powers: Vec<&str> = file
            .powers
            .iter()
            .map(|&power| power_name(power, lang))
            .collect();
        lines.push(format!(
            "🔓 {} {}",
            lang.pick("អាច៖", "Can:"),
            powers.join(" · ")
        ));
    }
    if let Some(about) = about {
        lines.push(format!("↪️ {about}"));
    }
    match file.unread {
        Some(Unread::TooBig(limit)) => lines.push(match lang {
            Lang::Km => format!("⚠️ មិនអាចពិនិត្យខាងក្នុងបានទេ ព្រោះឯកសារធំជាង {limit} MB"),
            Lang::En => format!("⚠️ Couldn't look inside: the file is over {limit} MB"),
        }),
        Some(Unread::DownloadFailed) => lines.push(
            lang.pick(
                "⚠️ មិនអាចពិនិត្យខាងក្នុងបានទេ ព្រោះទាញយកមិនបាន",
                "⚠️ Couldn't look inside: the download failed",
            )
            .to_owned(),
        ),
        None => {}
    }
    if let Some(clean) = file.scans.clamav_clean {
        let result = match clean {
            true => lang.pick("មិនរកឃើញមេរោគ", "no virus found"),
            false => lang.pick("រកឃើញមេរោគ", "virus found"),
        };
        lines.push(format!("🛡️ ClamAV: {result}"));
    }
    if let Some(known) = file.scans.malwarebazaar {
        let result = match known {
            true => lang.pick("ស្គាល់ថាជាមេរោគ", "known malware"),
            false => lang.pick("មិនមានក្នុងបញ្ជីមេរោគ", "not on its malware list"),
        };
        lines.push(format!("🛡️ MalwareBazaar: {result}"));
    }
    match file.scans.virustotal {
        Some(VirusTotal::Unknown) => lines.push(format!(
            "🛡️ VirusTotal: {}",
            lang.pick(
                "មិនទាន់មានអ្នកណាស្កេនឯកសារនេះទេ",
                "nobody has scanned this file yet"
            )
        )),
        Some(VirusTotal::Seen { malicious, engines }) => lines.push(match lang {
            Lang::Km => format!(
                "🛡️ VirusTotal: {}/{} រកឃើញមេរោគ",
                khmer_digits(malicious.into()),
                khmer_digits(engines.into())
            ),
            Lang::En => format!("🛡️ VirusTotal: {malicious}/{engines} engines found malware"),
        }),
        None => {}
    }
    lines.join("\n")
}

fn power_name(power: Power, lang: Lang) -> &'static str {
    match power {
        Power::ReadsSms => lang.pick("អាន SMS", "read SMS"),
        Power::ControlsScreen => lang.pick("គ្រប់គ្រងអេក្រង់", "control the screen"),
        Power::DrawsOverApps => lang.pick("បង្ហាញពីលើកម្មវិធីផ្សេង", "draw over apps"),
        Power::DeviceAdmin => lang.pick("គ្រប់គ្រងឧបករណ៍", "act as device admin"),
        Power::InstallsApps => lang.pick("ដំឡើងកម្មវិធីផ្សេង", "install apps"),
    }
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
        (Kind::Government, "gov.kh") => lang.pick("ស្ថាប័នរដ្ឋកម្ពុជា", "a Cambodian government office"),
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
        (kind, _) if kind.anyone_can_post() => lang
            .pick(
                "អ្នកណាក៏អាចបង្កើតទំព័រនៅលើនេះបានដែរ។ សូមពិនិត្យមើលឱ្យច្បាស់ថាអ្នកណាជាអ្នកបង្ហោះ មុនពេលទុកចិត្ត។",
                "Anyone can post here. Check who posted it before you trust it.",
            )
            .to_owned(),
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
        Kind::Design => ("កម្មវិធីរចនា", "design tool"),
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
        render(checks, About::default(), Lang::Km)
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
                in_file: false,
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
            let render_km = |checks: &[Check]| render(checks, About::default(), lang);
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
                assert!(reply.contains(BANK_APP_ADVICE.get(lang)), "{reply}");
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
            for fixed in [
                FROM_TELEGRAM.get(lang),
                REPLY_FAILED.get(lang),
                TOO_SHORT.get(lang),
            ] {
                assert!(!fixed.contains("សុវត្ថិភាព") && !fixed.to_lowercase().contains("safe"));
            }
            // Shared by every kind of report, so none of them may assume a QR code.
            for shared in [REPORT_LIMIT, REPORT_FAILED, FORGET_FAILED] {
                assert!(!shared.get(lang).contains("QR"));
            }
            assert!(HELP.get(lang).contains("🚩") && HOW_TO_REPORT.get(lang).contains("🚩"));
        }
    }

    #[test]
    fn identical_sections_are_shown_once() {
        let urgent = || Check {
            subject: Subject::Text,
            signals: vec![Signal::Urgency],
        };
        let reply = render_km(&[urgent(), urgent()]);
        assert_eq!(reply.matches("មិនឃើញពាក្យ").count(), 1);
        assert!(!reply.contains("ប្រញាប់ធ្វើសកម្មភាព"));
        let urgent_fee = Check {
            subject: Subject::Text,
            signals: vec![Signal::UpfrontFee, Signal::Urgency],
        };
        assert!(render_km(&[urgent_fee]).contains("ប្រញាប់ធ្វើសកម្មភាព"));
    }

    #[test]
    fn about_line_names_the_kind_and_sender() {
        let about = About {
            forwarded_from: Some("NEO GAME OASIS"),
            kind: Some(MessageKind::Promotion),
            official: None,
        };
        assert_eq!(
            about_line(about, Lang::En).as_deref(),
            Some("A promotion or ad from a business · forwarded from NEO GAME OASIS")
        );
        let impostor = About {
            forwarded_from: Some("@ABA_Support"),
            kind: Some(MessageKind::Other),
            official: None,
        };
        assert_eq!(
            about_line(impostor, Lang::Km).as_deref(),
            Some("បញ្ជូនបន្តពី ＠ABA_Support")
        );
        assert_eq!(about_line(About::default(), Lang::Km), None);
    }

    #[test]
    fn reported_contacts_say_what_was_reported() {
        let check = Check {
            subject: Subject::Text,
            signals: vec![Signal::ReportedScam(IndicatorKind::Phone, 4)],
        };
        assert_eq!(decide(&check), Level::Suspicious);
        assert!(render_km(&[check]).contains("មានអ្នកប្រើ ៤ នាក់ បានរាយការណ៍ថាលេខទូរស័ព្ទ"));
    }

    #[test]
    fn official_channels_and_impostor_senders_are_named() {
        let about = About {
            forwarded_from: Some("Telegram News"),
            kind: None,
            official: Some("Telegram"),
        };
        assert_eq!(
            about_line(about, Lang::En).as_deref(),
            Some("Forwarded from Telegram's official channel")
        );
        let check = Check {
            subject: Subject::Text,
            signals: vec![Signal::ImpersonatedSender("ABA")],
        };
        assert_eq!(decide(&check), Level::Suspicious);
        assert!(
            render(&[check], About::default(), Lang::En)
                .contains("forwarded from a personal account named like ABA")
        );
    }

    #[test]
    fn reply_puts_verdict_summary_and_action_first() {
        let reply = render_km(&[khqr::check(INDIVIDUAL_KHR_500)]);
        let mut lines = reply.lines();
        assert_eq!(lines.next(), Some("<b>⚪ មិនទាន់រកឃើញសញ្ញាបោកប្រាស់ទេ</b>"));
        assert!(lines.next().unwrap().contains("500 KHR"));
        assert!(lines.next().unwrap().starts_with("👉 តើឈ្មោះនេះត្រូវនឹងហាង"));
        assert!(reply.contains("<blockquote expandable>ℹ️ ព័ត៌មានលម្អិត"));
        assert!(reply.ends_with("</blockquote>"));
        let edited = render_km(&[check_with(vec![Signal::ChecksumInvalid], false)]);
        assert!(!edited.contains("blockquote"));
        let plain = render_km(&[Check {
            subject: Subject::Text,
            signals: vec![],
        }]);
        assert!(!plain.contains("blockquote") && plain.contains(BANK_APP_ADVICE.km));
    }

    #[test]
    fn government_links_and_job_ads_get_plain_lines_and_a_tip() {
        let link = Check {
            subject: Subject::Link(LinkInfo {
                host: "go.gov.kh".to_owned(),
                redirected_to: None,
                age_days: None,
                site: crate::analyzers::sites::identify("go.gov.kh"),
                title: None,
                in_file: false,
            }),
            signals: vec![],
        };
        let about = About {
            forwarded_from: None,
            kind: Some(MessageKind::JobAd),
            official: None,
        };
        let reply = render(&[link], about, Lang::Km);
        assert!(reply.contains("go[.]gov[.]kh · គេហទំព័ររដ្ឋាភិបាលកម្ពុជា"));
        assert!(reply.contains("👉 ការងារពិត មិនដែលឱ្យបង់ថ្លៃមុនទេ"));
        assert!(!reply.contains(".gov.kh"));
    }

    #[test]
    fn file_replies_name_the_real_type_and_unread_files() {
        use crate::analyzers::file::{Content, Scans, inspect};
        let page = render_km(&[inspect(
            "statement.html",
            None,
            Content::Bytes(b"<html><form>"),
            Scans::default(),
        )]);
        assert!(page.contains("ទំព័រវេប ដែលអាចបង្ហាញទំព័រចូលគណនីក្លែងក្លាយ"));
        assert!(!page.contains(".apk ឬ .exe"));
        assert!(!page.contains(BANK_APP_ADVICE.km));
        let big = render(
            &[inspect(
                "movie.mp4",
                None,
                Content::Unread(Unread::TooBig(50)),
                Scans::default(),
            )],
            About::default(),
            Lang::En,
        );
        assert!(big.contains("Couldn't look inside: the file is over 50 MB"));
    }

    #[test]
    fn clean_files_say_no_danger_rather_than_no_scam() {
        use crate::analyzers::file::{Content, Scans, inspect};
        let file = || {
            inspect(
                "notes.pdf",
                None,
                Content::Bytes(b"%PDF-1.4"),
                Scans::default(),
            )
        };
        assert_eq!(decide(&file()), Level::NoKnownSignals);
        let km = render_km(&[file()]);
        assert!(km.starts_with("<b>⚪ មិនទាន់រកឃើញសញ្ញាគ្រោះថ្នាក់ទេ</b>"));
        let en = render(&[file()], About::default(), Lang::En);
        assert!(en.starts_with("<b>⚪ No signs of danger found yet</b>"));
        assert!(!en.contains("scam signs"));
    }

    #[test]
    fn antivirus_results_are_not_repeated_in_file_details() {
        use crate::analyzers::file::{Content, Scans, VirusTotal, inspect};
        let scans = Scans {
            clamav_clean: Some(false),
            virustotal: Some(VirusTotal::Seen {
                malicious: 66,
                engines: 68,
            }),
            malwarebazaar: Some(true),
        };
        let reply = render_km(&[inspect(
            "eicar.txt",
            None,
            Content::Bytes(b"X5O!"),
            scans.clone(),
        )]);
        assert_eq!(reply.matches("ClamAV").count(), 1);
        assert_eq!(reply.matches("VirusTotal").count(), 2);
        assert!(reply.contains("🛡️ ClamAV: រកឃើញមេរោគ"));

        let program = render(
            &[inspect("photo.exe", None, Content::Bytes(b"MZ"), scans)],
            About::default(),
            Lang::En,
        );
        assert_eq!(program.matches("Windows program").count(), 1);
        assert!(program.contains("<blockquote expandable>🆘 If you already opened it:"));
    }

    #[test]
    fn progress_ticks_off_finished_steps() {
        assert_eq!(
            progress(&[Step::Download], Step::Scan, Lang::En),
            "<b>🔍 Checking…</b>\n✅ Download the file\n⏳ Scan for viruses…"
        );
    }

    #[test]
    fn apps_that_steal_codes_are_high_risk_with_their_powers_on_the_card() {
        use crate::analyzers::file::{Content, Scans, inspect};
        use crate::analyzers::inside::tests::{manifest, zipped};
        let apk = zipped(&[(
            "AndroidManifest.xml",
            &manifest(
                "com.aba.update",
                &[
                    "android.permission.READ_SMS",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                ],
            ),
        )]);
        let check = inspect(
            "ABA Update.apk",
            None,
            Content::Bytes(&apk),
            Scans::default(),
        );
        assert_eq!(decide(&check), Level::HighRisk);
        let reply = render(&[check], About::default(), Lang::En);
        let (shown, folded) = reply.split_once("<blockquote").unwrap();
        assert!(shown.contains("📦 com․aba․update\n🔓 Can: read SMS · draw over apps"));
        assert!(!folded.contains("can read your text messages, including"));
        assert!(!reply.contains("com.aba.update"));
    }

    #[test]
    fn file_facts_stay_outside_the_fold() {
        use crate::analyzers::file::{Content, Scans, VirusTotal, inspect};
        let about = About {
            forwarded_from: Some("Dara"),
            kind: None,
            official: None,
        };
        let program = render(
            &[inspect(
                "photo.exe",
                None,
                Content::Unread(Unread::TooBig(20)),
                Scans::default(),
            )],
            about,
            Lang::En,
        );
        let (shown, folded) = program.split_once("<blockquote expandable>").unwrap();
        assert!(shown.contains("📎 photo․exe\n↪️ Forwarded from Dara\n⚠️ Couldn't look inside"));
        assert!(!shown.contains("Real type") && !shown.contains("Don't open or install it"));
        assert!(folded.starts_with("🆘 If you already opened it:"));

        let scans = Scans {
            clamav_clean: Some(true),
            virustotal: Some(VirusTotal::Unknown),
            malwarebazaar: Some(false),
        };
        let pdf = render(
            &[inspect(
                "bill.pdf",
                None,
                Content::Bytes(b"%PDF-1.7"),
                scans,
            )],
            About::default(),
            Lang::En,
        );
        assert!(!pdf.contains("blockquote"));
        assert!(pdf.ends_with("📎 bill․pdf · a PDF\n🛡️ ClamAV: no virus found\n🛡️ MalwareBazaar: not on its malware list\n🛡️ VirusTotal: nobody has scanned this file yet"));
    }

    #[test]
    fn attacker_text_cannot_inject_html() {
        let check = Check {
            subject: Subject::Link(LinkInfo {
                host: "evil.top".to_owned(),
                redirected_to: None,
                age_days: None,
                site: None,
                title: Some("<a href=x>ABA</a> & co".to_owned()),
                in_file: false,
            }),
            signals: vec![],
        };
        let reply = render_km(&[check]);
        assert!(reply.contains("&lt;a href=x&gt;ABA&lt;/a&gt; &amp; co"));
        assert!(!reply.contains("<a "));
    }

    #[test]
    fn known_bad_site_reasons_never_say_safe() {
        use crate::analyzers::reputation::Threat;
        for lang in [Lang::Km, Lang::En] {
            for threat in [Threat::Phishing, Threat::Malware, Threat::UnwantedSoftware] {
                let text = reason(Signal::KnownBadSite(threat), lang).to_lowercase();
                assert!(!text.contains("safe") && !text.contains("សុវត្ថិភាព"), "{text}");
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
                    in_file: false,
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
                    in_file: false,
                }),
                signals: vec![],
            }],
            About::default(),
            Lang::En,
        );
        assert!(
            english.contains("• Owner: GitHub (code hosting site)") && english.contains("19 years")
        );
    }

    #[test]
    fn a_bad_link_inside_a_file_is_named_up_top() {
        use crate::analyzers::file::{Content, Scans, inspect};
        let file = inspect(
            "receipt.pdf",
            None,
            Content::Bytes(b"%PDF-1.7"),
            Scans::default(),
        );
        let link = Check {
            subject: Subject::Link(LinkInfo {
                host: "aba-verify-login.top".to_owned(),
                redirected_to: None,
                age_days: None,
                site: None,
                title: None,
                in_file: true,
            }),
            signals: vec![Signal::Lookalike("ABA")],
        };
        let reply = render(&[file, link], About::default(), Lang::En);
        let mut lines = reply.lines();
        assert_eq!(lines.next(), Some("<b>🟠 Suspicious</b>"));
        assert_eq!(
            lines.next(),
            Some("🔗 Link inside the file: aba-verify-login[.]top")
        );
        assert_eq!(reply.matches("Link inside the file").count(), 1);
        assert!(
            reply
                .split_once("<blockquote expandable>")
                .unwrap()
                .1
                .contains("receipt")
        );
    }

    #[test]
    fn links_found_in_files_say_so() {
        let link = LinkInfo {
            host: "aba-verify.top".to_owned(),
            redirected_to: None,
            age_days: None,
            site: None,
            title: None,
            in_file: true,
        };
        assert!(
            render_link(&link, Lang::En).starts_with("• Link inside the file: aba-verify[.]top")
        );
    }

    #[test]
    fn link_reply_defangs_domains() {
        let reply = render_km(&[link_check(vec![Signal::Lookalike("ABA")])]);
        assert!(reply.contains("bit[.]ly") && reply.contains("ababank-verify[.]com"));
        assert!(!reply.contains("ababank-verify.com"));
        let two_links = render_km(&[link_check(vec![]), link_check(vec![])]);
        assert_eq!(two_links.matches(LINK_ADVICE.km).count(), 1);
        assert!(reply.contains("ABA Bank Login"));
    }
}
