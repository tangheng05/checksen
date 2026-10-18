use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use super::text::Normalized;

/// Questions longer than this are only answered when the model agrees, since forwarded scams ask questions too.
const RULES_QUESTION_MAX_CHARS: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Check,
    Greeting,
    Thanks,
    AlreadyScammed,
    AsksAboutContact,
    AsksAboutCodes,
    AsksHowToReport,
    AsksWhatBotDoes,
    AsksPrivacy,
    OtherQuestion,
}

impl Intent {
    pub const NAMES: [&'static str; 10] = [
        "check",
        "greeting",
        "thanks",
        "already_scammed",
        "asks_about_contact",
        "asks_about_codes",
        "asks_how_to_report",
        "asks_what_bot_does",
        "asks_privacy",
        "other_question",
    ];
}

fn compile(pattern: &str) -> Regex {
    Regex::new(&format!("(?s){pattern}")).expect("intent patterns are valid")
}

static GREETING: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"^(?:hi+|hello+|hey+|helo|yo|good (?:morning|afternoon|evening)|សួស្តី|ជំរាបសួរ|ហាយ|ហេឡូ)(?:\s*(?:bot|checksen|there|bro|បង|បាទ|ចាស))?$",
    )
});
static THANKS: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"^(?:thanks?(?: you)?(?: so much| a lot)?|thank u|thx|ty|tq|ok(?:ay)?(?: thanks?)?|okie|got it|អរគុណ(?:ច្រើន)?|ok អរគុណ|អូខេ|បាទ|ចាស|យល់ហើយ)(?:\s*(?:bot|bro|បង|ណា|បាទ|ចាស))?$",
    )
});
static VICTIM: LazyLock<Regex> = LazyLock::new(|| {
    compile(concat!(
        r"ខ្ញុំ.{0,30}(?:ត្រូវ(?:គេ|បាន)?បោក|ចាញ់បោក|បាត់(?:លុយ|ប្រាក់))",
        r"|(?:ខ្ញុំ|បាន)(?:ផ្ញើ|ប្រាប់|ឱ្យ|វាយ|បញ្ចូល)(?:លេខ)?(?:កូដ|otp|pin|លេខសម្ងាត់)",
        r"|ខ្ញុំ(?:បាន)?(?:ផ្ទេរ|បង់)(?:លុយ|ប្រាក់).{0,40}(?:ហើយ|រួច)",
        r"|(?:គណនី|telegram|facebook|fb).{0,20}(?:hack|ហែក|ត្រូវគេលួច)",
        r"|\b(?:i|we)\b.{0,15}\b(?:got|been|was|were|am|get) (?:scammed|hacked|cheated|tricked|robbed)\b",
        r"|\blost (?:all )?(?:my |the )?money\b|\bmy (?:\w+ )?account (?:was|got|has been|is) hacked",
        r"|\bi (?:already |just |accidentally )?(?:gave|sent|shared|told|entered|typed) (?:them |him |her |it |the |my )*(?:otp|code|pin|password)",
        r"|\bi (?:already |just )?(?:paid|transferred|sent (?:the |them )?money)\b.{0,60}\b(?:scam|fake|now what|what (?:do|should|can) i do|help)",
    ))
});
static MISTAKEN_TRANSFER: LazyLock<Regex> =
    LazyLock::new(|| compile(r"ច្រលំ|ដោយអចេតនា|by mistake|wrong (?:account|number)"));
static QUESTION: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"[?？]$|(?:^|[\s,.!?។])តើ|(?:ទេ|អត់|ឬទេ|ឬអត់|មែនទេ|ម៉េច|អី)$|^(?:how|what|why|who|where|when|is|are|can|could|does|do|did|should|will|would)\b",
    )
});
static WHAT_BOT_DOES: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"what (?:can|do) you do|how (?:do i|to|can i) use|who are you|what (?:is|are) (?:this bot|you|checksen)|ធ្វើអី(?:បាន|ខ្លះ)|អ្នក(?:ជា)?នរណា|ប្រើ(?:យ៉ាង)?ម៉េច|ប្រើដូចម្តេច|របៀបប្រើ",
    )
});
static PRIVACY: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"privacy|private|do you (?:save|store|keep|read)|(?:save|store|keep) my|ឯកជនភាព|រក្សាទុក|មើលសារ",
    )
});
static REPORT: LazyLock<Regex> = LazyLock::new(|| compile(r"report|រាយការណ៍|ប្តឹង"));
static CODES: LazyLock<Regex> =
    LazyLock::new(|| compile(r"otp|\bpin\b|password|passcode|លេខកូដ|លេខសម្ងាត់|\bcode\b"));
static CONTACT: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?:\+?855|\b0)\d[\d -]{6,11}\d|@\w{4,}|លេខទូរស័ព្ទ|លេខនេះ|គណនីនេះ|អ្នកនេះ|ផេកនេះ|\b(?:number|this (?:account|page|person|guy|seller|shop))\b",
    )
});

/// What rules alone can tell about why the person sent this.
pub fn detect(text: &str) -> Option<Intent> {
    let normalized = Normalized::new(text);
    let bare = normalized
        .spaced
        .trim_matches(|c: char| !(c.is_alphanumeric() || ('\u{1780}'..='\u{17FF}').contains(&c)));
    if GREETING.is_match(bare) {
        return Some(Intent::Greeting);
    }
    if THANKS.is_match(bare) {
        return Some(Intent::Thanks);
    }
    if normalized.matches(&VICTIM) && !normalized.matches(&MISTAKEN_TRANSFER) {
        return Some(Intent::AlreadyScammed);
    }
    if normalized.matches(&WHAT_BOT_DOES) {
        return Some(Intent::AsksWhatBotDoes);
    }
    if !QUESTION.is_match(normalized.spaced.trim()) {
        return None;
    }
    Some(if normalized.matches(&PRIVACY) {
        Intent::AsksPrivacy
    } else if normalized.matches(&REPORT) {
        Intent::AsksHowToReport
    } else if normalized.matches(&CODES) {
        Intent::AsksAboutCodes
    } else if normalized.matches(&CONTACT) {
        Intent::AsksAboutContact
    } else {
        Intent::OtherQuestion
    })
}

/// Either side can spot a victim; otherwise the model's reading wins over the rules'.
pub fn decide(rules: Option<Intent>, model: Option<Intent>, text: &str) -> Intent {
    if [rules, model].contains(&Some(Intent::AlreadyScammed)) {
        return Intent::AlreadyScammed;
    }
    model
        .or(rules.filter(|_| text.chars().count() <= RULES_QUESTION_MAX_CHARS))
        .unwrap_or(Intent::Check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greetings_and_thanks_are_only_whole_messages() {
        for text in ["hi", "Hello!", "សួស្តីបង", "ជំរាបសួរ 🙏", "hi bot"]
        {
            assert_eq!(detect(text), Some(Intent::Greeting), "{text}");
        }
        for text in ["Thanks!", "thank you so much", "អរគុណច្រើន", "ok", "អូខេ"]
        {
            assert_eq!(detect(text), Some(Intent::Thanks), "{text}");
        }
        assert_ne!(
            detect("Hi, I'm from ABA. Send me your OTP"),
            Some(Intent::Greeting)
        );
    }

    #[test]
    fn victims_are_recognised_in_both_languages() {
        for text in [
            "ខ្ញុំបានផ្ញើលេខ OTP ទៅគេហើយ",
            "ខ្ញុំត្រូវគេបោកហើយ",
            "ខ្ញុំផ្ទេរលុយ 100$ ទៅគេហើយ ធ្វើម៉េចឥឡូវ",
            "I think I got scammed",
            "I already gave them the OTP code",
            "my telegram account was hacked",
        ] {
            assert_eq!(detect(text), Some(Intent::AlreadyScammed), "{text}");
        }
        assert_ne!(
            detect("Sorry, I transferred money to your account by mistake, please send it back"),
            Some(Intent::AlreadyScammed)
        );
    }

    #[test]
    fn questions_get_a_topic() {
        let cases = [
            ("តើ ABA សុំលេខកូដ OTP តាមសារទេ?", Intent::AsksAboutCodes),
            ("Does a bank ever ask for my PIN?", Intent::AsksAboutCodes),
            ("តើលេខ 012 345 678 ជាអ្នកបោកទេ?", Intent::AsksAboutContact),
            ("is this number a scammer?", Intent::AsksAboutContact),
            ("How do I report a scam?", Intent::AsksHowToReport),
            ("do you save my messages?", Intent::AsksPrivacy),
            ("what can you do", Intent::AsksWhatBotDoes),
            ("តើថ្ងៃនេះភ្លៀងទេ?", Intent::OtherQuestion),
        ];
        for (text, intent) in cases {
            assert_eq!(detect(text), Some(intent), "{text}");
        }
        assert_eq!(detect("Your parcel is waiting. Pay the fee here."), None);
    }

    #[test]
    fn model_wins_except_for_victims_and_long_rule_guesses() {
        let question = Some(Intent::OtherQuestion);
        assert_eq!(decide(question, None, "is it real?"), Intent::OtherQuestion);
        assert_eq!(
            decide(question, Some(Intent::Check), "is it real?"),
            Intent::Check
        );
        assert_eq!(decide(question, None, &"a".repeat(200)), Intent::Check);
        assert_eq!(
            decide(Some(Intent::AlreadyScammed), Some(Intent::Check), "x"),
            Intent::AlreadyScammed
        );
        assert_eq!(decide(None, None, "x"), Intent::Check);
    }
}
