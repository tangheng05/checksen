use std::sync::LazyLock;

use regex::Regex;

use super::{Check, Signal, Subject};

pub const RULES_VERSION: u32 = 1;

const SECRET_CODE_KM: &str =
    r"(?:លេខកូដ(?:otp|pin|ផ្ទៀងផ្ទាត់|សម្ងាត់|\d+ខ្ទង់|ដែល(?:ទើបតែ)?(?:ទទួល|ផ្ញើ))|លេខសម្ងាត់|otp|pin)";
const SECRET_CODE_EN: &str = r"(?:otp|pin|password|passcode|one[- ]time (?:password|pin|code)|(?:verification|security|sms) code|\d[- ]digit code|code (?:we|i|you) (?:just )?(?:sent|received|got))\b";
const NEWS_OR_WARNING: &str = r"ព័ត៌មាន៖|ក្រើនរំលឹក|ជនសង្ស័យ|\bnews\b|\bwarns\b|\bnever (?:ask|charge)";

struct Rule {
    signal: Signal,
    all: Vec<Regex>,
    unless: Option<Regex>,
}

impl Rule {
    fn new(signal: Signal, all: &[&str], unless: Option<&str>) -> Self {
        Self {
            signal,
            all: all.iter().map(|pattern| compile(pattern)).collect(),
            unless: unless.map(compile),
        }
    }

    fn fires(&self, text: &Normalized) -> bool {
        self.all.iter().all(|group| text.matches(group))
            && !self
                .unless
                .as_ref()
                .is_some_and(|group| text.matches(group))
    }
}

fn compile(pattern: &str) -> Regex {
    Regex::new(&format!("(?s){pattern}")).expect("rule patterns are valid")
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule::new(
            Signal::OtpRequest,
            &[&format!(
                concat!(
                    r"(?:សូម|ជួយ)(?:ផ្ញើ|ប្រាប់|ផ្តល់).{{0,20}}{km}|{km}.{{0,80}}ជួយប្រាប់",
                    r"|\b(?:send|give|tell|share|forward|provide|reply with|type)\b.{{0,30}}\b{en}",
                    r"|\bcode\b.{{0,80}}\bsend (?:it|them) (?:back|to me)",
                ),
                km = SECRET_CODE_KM,
                en = SECRET_CODE_EN,
            )],
            Some(r"កុំ(?:ប្រាប់|ផ្ញើ|ចែករំលែក)|\b(?:do not|don't|never) (?:share|give|send|tell)"),
        ),
        Rule::new(
            Signal::UpfrontFee,
            &[
                r"កម្ចី|ការងារ|រង្វាន់|កញ្ចប់|ឥវ៉ាន់|ភារកិច្ច|\b(?:loan|job|hiring|prize|reward|parcel|package|task|won|winner)\b",
                concat!(
                    r"បង់.{0,30}មុន(?:សិន|ពេល(?:បើក|ទទួល))|ជាមុន|ថ្លៃសេវា|ថ្លៃរដ្ឋបាល|ថ្លៃពិនិត្យ|ថ្លៃដំណើរការ|ថ្លៃឯកសណ្ឋាន|ថ្លៃបណ្តុះបណ្តាល",
                    r"|ថ្លៃដឹកជញ្ជូន|បង់ពន្ធ|ប្រាក់កក់|ប្រាក់ធានា|ដាក់ប្រាក់",
                    r"|\b(?:processing|admin|administration|registration|insurance|delivery|redelivery|activation|unlock) fee",
                    r"|\bpay\b.{0,40}\bfirst (?:to|before)\b|\bfirst pay|\bupfront\b|\bdeposit\b",
                ),
            ],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::MoveMoneyOut,
            &[
                r"គណនី.{0,20}(?:ខូច|មានបញ្ហា)|គណនីបណ្តោះអាសន្ន|គណនីសុវត្ថិភាព|\bsafe account|\btemporary account|\baccount\b.{0,30}\b(?:compromised|damaged|at risk)",
                r"ផ្ទេរ|\btransfer|\bmove (?:your )?(?:money|funds|balance)",
            ],
            None,
        ),
        Rule::new(
            Signal::AccountRental,
            &[concat!(
                r"(?:ជួល|ទិញ|លក់)គណនី|ផ្ទេរបន្តទៅគណនី",
                r"|\b(?:rent|buy|sell)(?:ing)? (?:your |their |a |an |my )?(?:bank |verified )?accounts?\b|\b(?:open|create)\b.{0,20}\bbank account\b.{0,60}\b(?:let us|for us|use it)",
            )],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::AuthorityThreat,
            &[
                r"ប៉ូលិស|នគរបាល|តុលាការ|ពន្ធដារ|លាងលុយ|\b(?:police|court|customs|tax|money laundering|warrant)\b",
                r"ត្រូវចាប់ខ្លួន|នឹងត្រូវផាក|បង់ប្រាក់ពិន័យ|ផ្ទេរ|ផ្ញើលុយ|ដោះលែង|ទូទាត់|កុំប្រាប់នរណា|\b(?:arrest|fine|transfer|pay|don't tell anyone)\b",
            ],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::AccountThreat,
            &[
                r"គណនី|កាបូប|\b(?:account|wallet)",
                r"ផ្អាក|បិទ|លុប|ចាក់សោ|ដោះសោ|\b(?:suspend|locked|lock|closed|closure|delete|deactivat|blocked|terminat)",
                r"ផ្ទៀងផ្ទាត់|ចុច|តំណ|ឆ្លើយតប|\b(?:verify|click|kyc|link|reply)\b|https?://",
            ],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::FamilyImpersonation,
            &[
                r"លេខថ្មី|បាត់ទូរស័ព្ទ|ទូរស័ព្ទខូច|\b(?:new number|lost my phone|phone (?:is )?broken)\b",
                r"ផ្ញើលុយ|ផ្ទេរ|ខ្ចីលុយ|\b(?:send|transfer|lend)\b.{0,20}(?:\$|money|cash)",
            ],
            None,
        ),
        Rule::new(
            Signal::LoanBait,
            &[concat!(
                r"មិនត្រូវការអ្នកធានា|គ្មានអ្នកធានា|មិនចាំបាច់មាន(?:ប្លង់|អ្នកធានា)|អនុម័តលឿន|អនុម័តភ្លាម|មិនពិនិត្យប្រវត្តិ|ខ្ចីលុយងាយ|ការប្រាក់ទាប",
                r"|\bno (?:guarantor|collateral|credit check)|\binstant loan|\bfast approval|\bapprov\w* in \d+ minutes",
            )],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::JobBait,
            &[concat!(
                r"ចុចឡាយ|ចុចតែ|ការងារងាយស្រួល|ធ្វើការនៅផ្ទះ|ធ្វើពីផ្ទះ|វាយអក្សរ.{0,60}(?:ប្រាក់ខែ|រកបាន|\$|ដុល្លារ)|មិនត្រូវការបទពិសោធន៍|ភារកិច្ច.{0,20}(?:រកលុយ|កម្រៃ)",
                r"|រកបាន.{0,20}ក្នុងមួយថ្ងៃ",
                r"|\b(?:like and follow|follow and like|typing job|data entry|work from home|no experience needed|per task)\b",
                r"|\bearn \$?\d+ (?:per|a) (?:task|day|hour)",
            )],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::PrizeBait,
            &[concat!(
                r"ឈ្នះរង្វាន់|អ្នក(?:បាន)?ឈ្នះ|ប្រាក់រង្វាន់|ចាប់រង្វាន់|ថវិកាជំនួយ",
                r"|\blucky (?:draw|winner)|\byou (?:have )?won\b|\bclaim your (?:prize|reward)",
            )],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::InvestmentBait,
            &[concat!(
                r"ធានា(?:ប្រាក់)?ចំណេញ|មិនខាត|ចំណេញ.{0,15}%.{0,20}(?:ក្នុងមួយ|ប្រចាំ)(?:ថ្ងៃ|សប្តាហ៍)",
                r"|\bguaranteed (?:returns?|profits?)|\bprofit guaranteed|\d+% (?:daily|per day|a day|weekly)|\bdouble your money|\bno risk\b",
            )],
            Some(NEWS_OR_WARNING),
        ),
        Rule::new(
            Signal::Urgency,
            &[concat!(
                r"ភ្លាមៗ|ឥឡូវនេះ|បន្ទាន់|ក្នុងរយៈពេល\d+(?:ម៉ោង|នាទី)",
                r"|\b(?:immediately|urgent|act now|right now|today only|expires today|limited slots)\b|\bwithin \d+ (?:hours?|minutes?)",
            )],
            None,
        ),
    ]
});

pub fn check(text: &str) -> Check {
    let normalized = Normalized::new(text);
    Check {
        subject: Subject::Text,
        signals: RULES
            .iter()
            .filter(|rule| rule.fires(&normalized))
            .map(|rule| rule.signal)
            .collect(),
    }
}

struct Normalized {
    spaced: String,
    compact: String,
}

impl Normalized {
    fn new(text: &str) -> Self {
        let spaced: String = text
            .to_lowercase()
            .replace("ឲ្យ", "ឱ្យ")
            .replace("\u{17D2}\u{178A}", "\u{17D2}\u{178F}")
            .chars()
            .filter(|c| !matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'))
            .map(|c| match c {
                '០'..='៩' => char::from(b'0' + (c as u32 - '០' as u32) as u8),
                _ => c,
            })
            .collect();
        let compact = spaced.chars().filter(|c| !c.is_whitespace()).collect();
        Self { spaced, compact }
    }

    fn matches(&self, group: &Regex) -> bool {
        group.is_match(&self.spaced) || group.is_match(&self.compact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(text: &str) -> Vec<Signal> {
        check(text).signals
    }

    #[test]
    fn normalizes_zero_width_spaces_spelling_and_digits() {
        let normalized = Normalized::new("ផ្ដល់\u{200B}ឲ្យ ២៤ ម៉ោង");
        assert_eq!(normalized.spaced, "ផ្តល់ឱ្យ 24 ម៉ោង");
        assert_eq!(normalized.compact, "ផ្តល់ឱ្យ24ម៉ោង");
    }

    #[test]
    fn otp_requests_are_hard_signals() {
        assert!(signals("សូមផ្ញើលេខកូដ OTP មកខ្ញុំ").contains(&Signal::OtpRequest));
        assert!(
            signals("Please reply with the verification code we sent you")
                .contains(&Signal::OtpRequest)
        );
        assert!(Signal::OtpRequest.is_hard());
    }

    #[test]
    fn bank_otp_messages_are_not_otp_requests() {
        for text in [
            "ABA: 482913 is your OTP. Do not share this code with anyone.",
            "លេខកូដ OTP របស់អ្នកគឺ 738204។ កុំប្រាប់លេខកូដនេះទៅនរណាម្នាក់។",
            "Bro ខ្ញុំផ្ញើ code WiFi ឱ្យហើយ។ ប្រាប់ខ្ញុំបើភ្ជាប់មិនបាន។",
        ] {
            assert!(!signals(text).contains(&Signal::OtpRequest), "{text}");
        }
    }

    #[test]
    fn each_rule_fires_in_khmer_and_english() {
        let cases = [
            (Signal::UpfrontFee, "កម្ចីត្រូវបានអនុម័ត សូមបង់ថ្លៃសេវា $50"),
            (
                Signal::UpfrontFee,
                "Your loan is approved, pay the processing fee first",
            ),
            (Signal::MoveMoneyOut, "គណនីរបស់បងខូចហើយ ត្រូវផ្ទេរលុយទៅគណនីនេះ"),
            (
                Signal::MoveMoneyOut,
                "Transfer your balance to this safe account",
            ),
            (Signal::AccountRental, "ត្រូវការជួលគណនីធនាគារ ឱ្យ $150"),
            (
                Signal::AccountRental,
                "Rent your bank account to us for $200",
            ),
            (
                Signal::AuthorityThreat,
                "នេះជាប៉ូលិស អ្នកត្រូវផ្ទេរប្រាក់ ដើម្បីកុំឱ្យចាប់ខ្លួន",
            ),
            (
                Signal::AuthorityThreat,
                "Police: you must pay the fine or face arrest",
            ),
            (Signal::AccountThreat, "គណនីរបស់អ្នកនឹងត្រូវបិទ សូមចុចតំណ"),
            (Signal::AccountThreat, "Your account is locked, verify now"),
            (Signal::LoanBait, "កម្ចីអនឡាញ មិនត្រូវការអ្នកធានា"),
            (Signal::LoanBait, "Instant loan with no collateral"),
            (Signal::JobBait, "ការងារងាយស្រួល ចុចឡាយរកលុយ"),
            (
                Signal::JobBait,
                "Like and follow channels, earn $5 per task",
            ),
            (Signal::PrizeBait, "អ្នកបានឈ្នះរង្វាន់ម៉ូតូ"),
            (
                Signal::PrizeBait,
                "You have won an iPhone, claim your prize",
            ),
            (Signal::InvestmentBait, "វិនិយោគ ធានាចំណេញ ៣០%"),
            (Signal::InvestmentBait, "Guaranteed returns of 5% daily"),
            (
                Signal::AccountThreat,
                "Your Bakong wallet is blocked, click to verify",
            ),
            (
                Signal::AccountRental,
                "Looking for people to rent their bank accounts",
            ),
            (
                Signal::FamilyImpersonation,
                "ម៉ាក់ ខ្ញុំបាត់ទូរស័ព្ទ នេះជាលេខថ្មី ផ្ញើលុយ $200 មកខ្ញុំបន្តិច",
            ),
            (
                Signal::FamilyImpersonation,
                "Mom, I lost my phone. Can you send me $200?",
            ),
            (Signal::Urgency, "សូមធ្វើភ្លាមៗ"),
            (Signal::Urgency, "Act now, today only"),
        ];
        for (signal, text) in cases {
            assert!(signals(text).contains(&signal), "{signal:?}: {text}");
        }
    }

    #[test]
    fn asking_to_fill_in_information_is_not_mistaken_for_news() {
        let text = "គណនីរបស់អ្នកនឹងត្រូវបិទ សូមចុចតំណ ហើយបំពេញព័ត៌មាន";
        assert!(signals(text).contains(&Signal::AccountThreat));
    }

    #[test]
    fn everyday_messages_are_not_flagged() {
        for text in [
            "Please transfer the rent to my account by Friday, thanks!",
            "សូមផ្ទេរប្រាក់ថ្លៃទឹកភ្លើងខែនេះទៅគណនីម៉ាក់ផង",
            "Your Netflix account will be closed if payment fails. Update your card in the app.",
            "ខ្ញុំបានឈ្នះការប្រកួតបាល់ទាត់នៅសាលាថ្ងៃនេះ!",
            "We won the match today! Celebration dinner at 7pm",
            "Please send me the code for the door lock, I forgot it",
            "សូមផ្ញើលេខកូដកុម្ម៉ង់មកខ្ញុំ ដើម្បីតាមដានឥវ៉ាន់",
            "The police closed the road near the market because of the parade",
            "ប៉ូលិសចរាចរណ៍ផាកពិន័យអ្នកបើកបរដែលមិនពាក់មួកសុវត្ថិភាព",
            "My loan application was approved, I pay the first installment next month",
            "ពាក្យស្នើសុំកម្ចីត្រូវបានអនុម័ត សូមបង់ប្រាក់ដំបូងមុនថ្ងៃទី ៥",
            "យើងត្រូវការអ្នកជួយវាយអក្សរឯកសារប្រជុំថ្ងៃស្អែក",
            "Deposit $50 to reserve your table for New Year's Eve",
            "Delivery fee is $1.50 for orders under $10",
            "ABA: Your card ending 4411 was used for $12.00 at LUCKY MART. Not you? Call 023 225 333.",
            "ម៉ាក់ផ្ញើលុយ $50 ទៅគណនីកូនហើយ ទិញសៀវភៅណា",
            "Hi, is the apartment still for rent? What's the monthly price?",
            "ធនាគារនឹងបិទនៅថ្ងៃបុណ្យភ្ជុំបិណ្ឌ ចាប់ពីថ្ងៃទី ២០ ដល់ ២២។",
            "I got a new number, save it! Lunch tomorrow?",
        ] {
            assert!(signals(text).is_empty(), "{:?}: {text}", signals(text));
        }
    }

    #[test]
    fn news_about_scams_is_not_flagged() {
        let text = "ព័ត៌មាន៖ នគរបាលបានចាប់ខ្លួនជនសង្ស័យ ពាក់ព័ន្ធការឆបោកកម្ចី ដែលទាមទារឱ្យបង់ប្រាក់មុន";
        assert!(signals(text).is_empty(), "{:?}", signals(text));
    }
}
