use khqr_core::{Currency, DecodedKhqr};

use crate::analyzers::link::LinkInfo;
use crate::analyzers::llm::ScamCategory;
use crate::analyzers::{Check, Signal, Subject};

pub const HELP_KM: &str = "សូមផ្ញើរូបថត KHQR កូដ KHQR ឬតំណ (link) ដែលអ្នកសង្ស័យមកទីនេះ។ ខ្ញុំនឹងប្រាប់ថា QR នោះបង់ប្រាក់ទៅអ្នកណា ឬតំណនោះនាំទៅគេហទំព័រណាពិតប្រាកដ។\n\nសារ និងរូបភាពដែលអ្នកផ្ញើមក មិនត្រូវបានរក្សាទុកទេ។ ដើម្បីពិនិត្យ អត្ថបទអាចត្រូវបានផ្ញើទៅសេវា AI ដែលមិនប្រើវាសម្រាប់ហ្វឹកហាត់។";
pub const FORGET_KM: &str = "CheckSen មិនរក្សាទុកសារ រូបភាព ឬព័ត៌មានដែលភ្ជាប់នឹងអ្នកទេ ដូច្នេះគ្មានអ្វីត្រូវលុបទេ។";
pub const INTENDED_BUTTON_KM: &str = "✅ ត្រូវហើយ";
pub const NOT_INTENDED_BUTTON_KM: &str = "❌ មិនមែនទេ";
pub const INTENDED_KM: &str = "ល្អ។ សូមពិនិត្យឈ្មោះអ្នកទទួលម្តងទៀតក្នុងកម្មវិធីធនាគាររបស់អ្នក មុនពេលបង់ប្រាក់។";
pub const REPORTED_KM: &str =
    "អរគុណ។ យើងបានកត់ត្រាការរាយការណ៍របស់អ្នក។ កុំបង់ប្រាក់តាម QR នេះ ហើយសូមសួរអ្នកលក់ពីគណនីត្រឹមត្រូវ។";
pub const REPORT_LIMIT_KM: &str =
    "អ្នកបានរាយការណ៍ច្រើនពេកនៅថ្ងៃនេះ។ កុំបង់ប្រាក់តាម QR នេះ ហើយសូមព្យាយាមរាយការណ៍ម្តងទៀតនៅថ្ងៃស្អែក។";
pub const REPORT_FAILED_KM: &str = "មិនអាចកត់ត្រាការរាយការណ៍បានទេនៅពេលនេះ។ កុំបង់ប្រាក់តាម QR នេះ។";

pub fn forgotten_km(removed: u64) -> String {
    format!("បានលុបការរាយការណ៍ {removed} ដែលភ្ជាប់នឹងអ្នក។ CheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។")
}
pub const RATE_LIMITED_KM: &str = "អ្នកបានផ្ញើសារឱ្យពិនិត្យច្រើនពេកក្នុងរយៈពេលខ្លី។ សូមរង់ចាំបន្តិច រួចព្យាយាមម្តងទៀត។";
const BANK_APP_ADVICE_KM: &str =
    "⚠️ មុនបង់ប្រាក់ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់ក្នុងកម្មវិធីធនាគាររបស់អ្នកឱ្យបានច្បាស់។";
const LINK_ADVICE_KM: &str = "កុំបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP តាមរយៈតំណ។ បើចង់ពិនិត្យគណនី សូមបើកកម្មវិធីធនាគារដោយផ្ទាល់។";
const NO_TEXT_SIGNALS_KM: &str =
    "ខ្ញុំមិនឃើញពាក្យដែលអ្នកបោកប្រាស់ច្រើនប្រើទេ ប៉ុន្តែនេះមិនមានន័យថាសារនេះគ្មានបញ្ហានោះទេ។";
const NO_QR_FOUND_KM: &str = "រកមិនឃើញ QR ក្នុងរូបភាពនេះទេ។ សូមថតឱ្យច្បាស់ ហើយឱ្យឃើញ QR ទាំងមូល រួចផ្ញើម្តងទៀត។";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    HighRisk,
    Suspicious,
    NoKnownSignals,
    CantTell,
}

impl Level {
    fn label_km(self) -> &'static str {
        match self {
            Self::HighRisk => "🔴 ហានិភ័យខ្ពស់",
            Self::Suspicious => "🟠 គួរឱ្យសង្ស័យ",
            Self::NoKnownSignals => "⚪ មិនទាន់រកឃើញសញ្ញាគួរឱ្យសង្ស័យទេ",
            Self::CantTell => "❔ មិនអាចពិនិត្យបាន",
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

pub fn render_km(checks: &[Check]) -> String {
    let mut sections: Vec<String> = if checks.is_empty() {
        vec![format!("{}\n{NO_QR_FOUND_KM}", Level::CantTell.label_km())]
    } else {
        checks.iter().map(render_check).collect()
    };
    sections.push(BANK_APP_ADVICE_KM.to_owned());
    sections.join("\n\n")
}

fn render_check(check: &Check) -> String {
    let mut lines = vec![decide(check).label_km().to_owned()];
    lines.extend(check.signals.iter().map(|&signal| reason_km(signal)));
    match &check.subject {
        Subject::Khqr(payee) => lines.push(render_payee(payee)),
        Subject::Link(link) => lines.push(render_link(link)),
        Subject::Text if check.signals.iter().all(|signal| signal.weight() == 0.0) => {
            lines.push(NO_TEXT_SIGNALS_KM.to_owned())
        }
        Subject::Text | Subject::Unreadable => {}
    }
    lines.join("\n")
}

fn reason_km(signal: Signal) -> String {
    let reason = match signal {
        Signal::NotKhqr => "QR នេះមិនមែនជា KHQR ឬតំណទេ។ បច្ចុប្បន្ន ខ្ញុំពិនិត្យបានតែ KHQR និងតំណប៉ុណ្ណោះ។",
        Signal::ChecksumInvalid => {
            "QR នេះប្រហែលជាត្រូវបានគេកែប្រែ ឬខូច (លេខផ្ទៀងផ្ទាត់មិនត្រូវគ្នា)។ កុំបង់ប្រាក់តាម QR នេះ។"
        }
        Signal::DuplicateTag => "QR នេះមានព័ត៌មានស្ទួនគ្នា ដែលជាសញ្ញាថាអាចត្រូវបានគេកែប្រែ។ កុំបង់ប្រាក់តាម QR នេះ។",
        Signal::Malformed => "QR នេះមើលទៅដូច KHQR ប៉ុន្តែទម្រង់របស់វាមិនត្រឹមត្រូវ។",
        Signal::Expired => "QR នេះប្រើបានតែម្តង ហើយបានផុតសុពលភាពរួចហើយ។ សូមសុំ QR ថ្មីពីអ្នកលក់។",
        Signal::Lookalike(brand) => {
            return format!("ឈ្មោះគេហទំព័រនេះស្រដៀងនឹង {brand} ប៉ុន្តែមិនមែនជាគេហទំព័រផ្លូវការទេ។");
        }
        Signal::Punycode => "ឈ្មោះគេហទំព័រនេះប្រើអក្សរពិសេស ដែលអាចធ្វើឱ្យមើលទៅដូចគេហទំព័រផ្សេង។",
        Signal::NewDomain => "គេហទំព័រនេះទើបតែបង្កើតថ្មីៗ មិនទាន់ដល់ ៣០ ថ្ងៃផង។",
        Signal::OtpRequest => {
            "សារនេះសុំលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនពិតប្រាកដមិនដែលសុំលេខកូដទាំងនេះទេ។ កុំប្រាប់នរណាម្នាក់ឱ្យសោះ។"
        }
        Signal::UpfrontFee => "សារនេះសុំឱ្យបង់ប្រាក់មុន ដើម្បីទទួលបានកម្ចី ការងារ ឬរង្វាន់។",
        Signal::MoveMoneyOut => "សារនេះប្រាប់ឱ្យផ្ទេរប្រាក់ចេញពីគណនីរបស់អ្នក ទៅគណនីផ្សេង។",
        Signal::AccountRental => {
            "សារនេះសុំជួល ទិញ ឬប្រើគណនីធនាគាររបស់អ្នក។ គណនីបែបនេះអាចត្រូវគេប្រើដើម្បីលាងលុយ ហើយអ្នកអាចជាប់ពាក់ព័ន្ធផ្លូវច្បាប់។"
        }
        Signal::AuthorityThreat => {
            "សារនេះអះអាងថាមកពីប៉ូលិស តុលាការ ឬស្ថាប័នរដ្ឋ ហើយសុំប្រាក់ ឬគំរាម។ ស្ថាប័នពិតមិនសុំឱ្យផ្ទេរប្រាក់តាមសារទេ។"
        }
        Signal::FamilyImpersonation => {
            "សារនេះអះអាងថាជាសាច់ញាតិ ឬមិត្តភក្តិដែលប្តូរលេខថ្មី ហើយសុំលុយ។ សូមខលទៅលេខចាស់របស់គាត់ដើម្បីបញ្ជាក់សិន។"
        }
        Signal::AccountThreat => "សារនេះគំរាមថាគណនីរបស់អ្នកនឹងត្រូវបិទ ឬផ្អាក ហើយប្រាប់ឱ្យចុចតំណ ឬផ្ទៀងផ្ទាត់។",
        Signal::LoanBait => "សារនេះសន្យាផ្តល់កម្ចីងាយៗ ដោយមិនត្រូវការអ្នកធានា ឬពិនិត្យប្រវត្តិ។",
        Signal::JobBait => "សារនេះសន្យាការងារងាយៗ ដែលរកលុយបានច្រើនពេក ដូចជាចុចឡាយ ឬវាយអក្សរ។",
        Signal::PrizeBait => "សារនេះប្រាប់ថាអ្នកបានឈ្នះរង្វាន់ ឬទទួលបានប្រាក់ជំនួយ។",
        Signal::InvestmentBait => "សារនេះធានាប្រាក់ចំណេញខ្ពស់ ឬថាមិនខាត។ គ្មានការវិនិយោគណាអាចធានាបែបនេះបានទេ។",
        Signal::TelegramTakeover => {
            "សារនេះប្រាប់ឱ្យផ្ទៀងផ្ទាត់ ឬការពារគណនី Telegram តាមតំណ។ Telegram មិនផ្ញើសារបែបនេះទេ ហើយតំណនោះអាចលួចគណនីរបស់អ្នក។"
        }
        Signal::MalwareFile => {
            "ឯកសារនេះជាកម្មវិធី (ដូចជា .apk ឬ .exe) មិនមែនជាឯកសារធម្មតាទេ។ កុំបើក ឬដំឡើងវា ព្រោះវាអាចគ្រប់គ្រងទូរស័ព្ទរបស់អ្នក។"
        }
        Signal::Urgency => "សារនេះបង្ខំឱ្យធ្វើភ្លាមៗ។",
        Signal::Reported(reporters) => {
            return format!(
                "គណនីនេះត្រូវបានអ្នកប្រើប្រាស់ {reporters} នាក់រាយការណ៍ថា មិនមែនជាអ្នកទទួលដែលពួកគេរំពឹងទុកទេ។"
            );
        }
        Signal::Model { category, .. } => {
            return format!(
                "ការពិនិត្យដោយ AI យល់ឃើញថាសារនេះស្រដៀងនឹង{}។",
                category_km(category)
            );
        }
        Signal::ModelUnavailable => {
            "ការពិនិត្យដោយ AI មិនអាចប្រើបានបណ្តោះអាសន្ន ដូច្នេះលទ្ធផលនេះពឹងលើការពិនិត្យតាមច្បាប់តែប៉ុណ្ណោះ។"
        }
    };
    reason.to_owned()
}

fn category_km(category: ScamCategory) -> &'static str {
    match category {
        ScamCategory::Loan => "កម្ចីក្លែងក្លាយ",
        ScamCategory::Job => "ការងារក្លែងក្លាយ",
        ScamCategory::Otp => "ការសុំលេខកូដសម្ងាត់",
        ScamCategory::Prize => "រង្វាន់ក្លែងក្លាយ",
        ScamCategory::Account => "ការគំរាមបិទគណនី",
        ScamCategory::Authority => "ការក្លែងខ្លួនជាអាជ្ញាធរ",
        ScamCategory::Investment => "ការវិនិយោគក្លែងក្លាយ",
        ScamCategory::Mule => "ការជួល ឬទិញគណនីធនាគារ",
        ScamCategory::Family => "ការក្លែងខ្លួនជាសាច់ញាតិ ឬមិត្តភក្តិ",
        ScamCategory::Telegram => "ការលួចគណនី Telegram",
        ScamCategory::Malware => "កម្មវិធីព្យាបាទ",
        ScamCategory::Charity => "ការសុំបរិច្ចាគក្លែងក្លាយ",
        ScamCategory::Shop => "ការលក់ទំនិញក្លែងក្លាយ",
        ScamCategory::Gambling => "ល្បែងស៊ីសង ឬឆ្នោតខុសច្បាប់",
        ScamCategory::Extortion => "ការគំរាមយកលុយ",
        ScamCategory::Recruitment => "ការជ្រើសរើសបុគ្គលិកក្លែងក្លាយ",
        ScamCategory::OtherScam | ScamCategory::None => "ការបោកប្រាស់",
    }
}

fn render_payee(payee: &DecodedKhqr) -> String {
    let mut lines = vec![
        "QR នេះបង់ប្រាក់ទៅ៖".to_owned(),
        format!("• ឈ្មោះអ្នកទទួល៖ {}", inert(&payee.merchant_name)),
        format!("• គណនី៖ {}", inert(&payee.bakong_account_id)),
    ];
    if let Some(bank) = &payee.acquiring_bank {
        lines.push(format!("• ធនាគារ៖ {}", inert(bank)));
    }
    if let Some(amount) = &payee.transaction_amount {
        let currency = match payee.currency() {
            Some(Currency::Khr) => "KHR",
            Some(Currency::Usd) => "USD",
            _ => payee.transaction_currency.as_str(),
        };
        lines.push(format!(
            "• ចំនួនទឹកប្រាក់៖ {} {}",
            visible(amount),
            visible(currency)
        ));
    }
    lines.push(format!("• ទីក្រុង៖ {}", inert(&payee.merchant_city)));
    lines.push("តើឈ្មោះនេះត្រូវនឹងហាង ឬបុគ្គលដែលអ្នកចង់បង់ប្រាក់ឱ្យមែនទេ? បើមិនត្រូវ កុំបង់ប្រាក់។".to_owned());
    lines.join("\n")
}

fn render_link(link: &LinkInfo) -> String {
    let mut lines = vec![format!("• គេហទំព័រ៖ {}", defang(&link.host))];
    if let Some(destination) = &link.redirected_to {
        lines.push(format!("• បញ្ជូនបន្តទៅ៖ {}", defang(destination)));
    }
    if let Some(days) = link.age_days {
        let age = if days >= 365 {
            format!("{} ឆ្នាំ", days / 365)
        } else {
            format!("{days} ថ្ងៃ")
        };
        lines.push(format!("• អាយុគេហទំព័រ៖ {age}"));
    }
    lines.push(LINK_ADVICE_KM.to_owned());
    lines.join("\n")
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
        let replies = [
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
            assert!(reply.ends_with(BANK_APP_ADVICE_KM), "{reply}");
            assert!(!reply.contains("សុវត្ថិភាព") && !reply.to_lowercase().contains("safe"));
        }
    }

    #[test]
    fn valid_reply_shows_payee() {
        let reply = render_km(&[khqr::check(INDIVIDUAL_KHR_500)]);
        assert!(reply.contains("jonhsmith@nbcq") && reply.contains("500 KHR"));
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
    fn link_reply_defangs_domains() {
        let reply = render_km(&[link_check(vec![Signal::Lookalike("ABA")])]);
        assert!(reply.contains("bit[.]ly") && reply.contains("ababank-verify[.]com"));
        assert!(!reply.contains("ababank-verify.com"));
    }
}
