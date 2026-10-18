use khqr_core::{Currency, DecodedKhqr};

use crate::analyzers::link::LinkInfo;
use crate::analyzers::llm::ScamCategory;
use crate::analyzers::{Check, Signal, Subject};

pub const HELP_KM: &str = "សូមផ្ញើសារ តំណ (link) កូដ KHQR ឬរូបថតអេក្រង់ ដែលអ្នកសង្ស័យ មកទីនេះ។ ខ្ញុំនឹងប្រាប់ថា QR បង់ប្រាក់ទៅអ្នកណា តំណនាំទៅគេហទំព័រណា និងសារនោះមានសញ្ញាបោកប្រាស់ឬអត់។\n\nCheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។ ដើម្បីពិនិត្យ អត្ថបទ និងរូបភាពអាចត្រូវបានផ្ញើទៅសេវា AI របស់ក្រុមហ៊ុនខាងក្រៅ ដែលអាចយកទៅកែលម្អសេវារបស់គេ ហើយមនុស្សអាចមើលឃើញ។ សូមបិទលេខគណនី និងព័ត៌មានផ្ទាល់ខ្លួនសិន មុនផ្ញើ។";
pub const FORGET_KM: &str = "CheckSen មិនបានរក្សាទុកព័ត៌មានអ្វីរបស់អ្នកទេ ដូច្នេះគ្មានអ្វីត្រូវលុបទេ។";
pub const INTENDED_BUTTON_KM: &str = "✅ ត្រូវ";
pub const NOT_INTENDED_BUTTON_KM: &str = "❌ មិនត្រូវ";
pub const INTENDED_KM: &str = "ល្អណាស់។ សូមពិនិត្យឈ្មោះអ្នកទទួលក្នុងកម្មវិធីធនាគារម្តងទៀត មុនចុចបង់ប្រាក់។";
pub const REPORTED_KM: &str = "អរគុណសម្រាប់ការរាយការណ៍។ កុំបង់ប្រាក់តាម QR នេះ ហើយសូមសួរអ្នកលក់ឱ្យប្រាកដពីគណនីរបស់គេ។";
pub const REPORT_LIMIT_KM: &str =
    "ថ្ងៃនេះអ្នករាយការណ៍ច្រើនដងហើយ។ សូមកុំបង់ប្រាក់តាម QR នេះ ហើយរាយការណ៍ម្តងទៀតនៅថ្ងៃស្អែក។";
pub const REPORT_FAILED_KM: &str = "ពេលនេះមិនអាចរាយការណ៍បានទេ។ សូមកុំបង់ប្រាក់តាម QR នេះ។";

pub fn forgotten_km(removed: u64) -> String {
    format!("បានលុបការរាយការណ៍របស់អ្នកចំនួន {removed} រួចហើយ។ CheckSen មិនរក្សាទុកសារ ឬរូបភាពរបស់អ្នកទេ។")
}
pub const RATE_LIMITED_KM: &str = "អ្នកផ្ញើមកច្រើនពេកក្នុងពេលខ្លី។ សូមរង់ចាំបន្តិច ហើយសាកម្តងទៀត។";
const BANK_APP_ADVICE_KM: &str = "⚠️ មុនបង់ប្រាក់ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់ ក្នុងកម្មវិធីធនាគាររបស់អ្នកជានិច្ច។";
const LINK_ADVICE_KM: &str =
    "កុំបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP តាមតំណណាមួយ។ បើចង់ពិនិត្យគណនី សូមបើកកម្មវិធីធនាគារដោយខ្លួនឯង។";
const NO_TEXT_SIGNALS_KM: &str = "មិនឃើញពាក្យដែលអ្នកបោកប្រាស់តែងប្រើទេ តែសូមនៅតែប្រយ័ត្ន។";
const NO_QR_FOUND_KM: &str = "រកមិនឃើញ QR ក្នុងរូបនេះទេ។ សូមថតឱ្យច្បាស់ ឱ្យឃើញ QR ទាំងមូល ហើយផ្ញើម្តងទៀត។";
const SCREENSHOT_UNREAD_KM: &str =
    "ពេលនេះមិនអាចអានអក្សរក្នុងរូបនេះបានទេ។ សូមសាកម្តងទៀតបន្តិចទៀត ឬចម្លងសារនោះ ហើយផ្ញើមកជាអក្សរ។";

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
            Self::NoKnownSignals => "⚪ មិនទាន់ឃើញសញ្ញាបោកប្រាស់ទេ",
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

pub fn screenshot_unread_km() -> String {
    format!(
        "{}\n{SCREENSHOT_UNREAD_KM}\n\n{BANK_APP_ADVICE_KM}",
        Level::CantTell.label_km()
    )
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
        Signal::NotKhqr => "QR នេះមិនមែន KHQR ឬតំណទេ។ ពេលនេះ CheckSen ពិនិត្យបានតែ KHQR និងតំណប៉ុណ្ណោះ។",
        Signal::ChecksumInvalid => "QR នេះអាចត្រូវគេកែ ឬខូច (លេខផ្ទៀងផ្ទាត់មិនត្រូវ)។ កុំបង់ប្រាក់តាម QR នេះ។",
        Signal::DuplicateTag => "QR នេះមានព័ត៌មានជាន់គ្នា ដែលអាចមកពីការកែបន្លំ។ កុំបង់ប្រាក់តាម QR នេះ។",
        Signal::Malformed => "QR នេះមើលទៅដូច KHQR តែទម្រង់មិនត្រឹមត្រូវ។",
        Signal::Expired => "QR នេះប្រើបានតែម្តង ហើយផុតកំណត់ហើយ។ សូមសុំ QR ថ្មីពីអ្នកលក់។",
        Signal::Lookalike(brand) => {
            return format!("ឈ្មោះគេហទំព័រនេះស្រដៀង {brand} តែមិនមែនគេហទំព័រផ្លូវការទេ។");
        }
        Signal::Punycode => "ឈ្មោះគេហទំព័រនេះប្រើអក្សរចម្លែក ដើម្បីឱ្យមើលទៅដូចគេហទំព័រផ្សេង។",
        Signal::NewDomain => "គេហទំព័រនេះទើបបង្កើតថ្មី មិនទាន់បាន ៣០ ថ្ងៃផង។",
        Signal::OtpRequest => {
            "សារនេះសុំលេខកូដ OTP ឬលេខសម្ងាត់។ ធនាគារ និងក្រុមហ៊ុនពិតៗ មិនដែលសុំលេខទាំងនេះទេ។ កុំប្រាប់នរណាម្នាក់ឡើយ។"
        }
        Signal::UpfrontFee => "សារនេះឱ្យបង់លុយមុន ទើបទទួលបានកម្ចី ការងារ ឬរង្វាន់។",
        Signal::MoveMoneyOut => "សារនេះប្រាប់ឱ្យផ្ទេរលុយចេញពីគណនីរបស់អ្នក ទៅគណនីផ្សេង។",
        Signal::AccountRental => {
            "សារនេះសុំជួល ទិញ ឬខ្ចីគណនីធនាគាររបស់អ្នក។ គណនីបែបនេះតែងត្រូវគេប្រើលាងលុយ ហើយអ្នកអាចជាប់ទោសតាមច្បាប់។"
        }
        Signal::AuthorityThreat => {
            "សារនេះអះអាងថាមកពីប៉ូលិស តុលាការ ឬស្ថាប័នរដ្ឋ ហើយគំរាម ឬសុំលុយ។ ស្ថាប័នពិតមិនសុំឱ្យផ្ទេរលុយតាមសារទេ។"
        }
        Signal::FamilyImpersonation => {
            "សារនេះអះអាងថាជាសាច់ញាតិ ឬមិត្តភក្តិដែលប្តូរលេខថ្មី ហើយសុំលុយ។ សូមតេទៅលេខចាស់របស់គាត់ ដើម្បីបញ្ជាក់សិន។"
        }
        Signal::AccountThreat => "សារនេះគំរាមថានឹងបិទ ឬផ្អាកគណនីរបស់អ្នក ហើយឱ្យចុចតំណ ឬផ្ទៀងផ្ទាត់។",
        Signal::LoanBait => "សារនេះសន្យាឱ្យខ្ចីលុយងាយៗ មិនបាច់មានអ្នកធានា ឬទ្រព្យធានា។",
        Signal::JobBait => "សារនេះសន្យាការងារស្រួលៗ តែបានលុយច្រើនពេក ដូចជាចុចឡាយ ឬវាយអក្សរ។",
        Signal::PrizeBait => "សារនេះប្រាប់ថាអ្នកឈ្នះរង្វាន់ ឬបានលុយជំនួយ។",
        Signal::InvestmentBait => "សារនេះធានាថាចំណេញខ្ពស់ ឬមិនខាត។ គ្មានការវិនិយោគណាអាចធានាបែបនេះបានទេ។",
        Signal::TelegramTakeover => {
            "សារនេះឱ្យផ្ទៀងផ្ទាត់ ឬការពារគណនី Telegram តាមតំណ។ Telegram មិនផ្ញើសារបែបនេះទេ ហើយតំណនោះអាចលួចគណនីរបស់អ្នក។"
        }
        Signal::DonationRequest => {
            "សារនេះសុំឱ្យបរិច្ចាគលុយចូលគណនីមួយ។ ជនបោកប្រាស់ច្រើនតែយករឿងទាហាន ឬកុមារឈឺមកបញ្ឆោត។ សូមបរិច្ចាគតែតាមអង្គការដែលអ្នកស្គាល់ច្បាស់។"
        }
        Signal::Extortion => "សារនេះគំរាមថានឹងផុសរូប ឬប្រាប់អ្នកដទៃ បើអ្នកមិនផ្ញើលុយ។ កុំផ្ញើលុយ ហើយទុកសារនេះជាភស្តុតាង។",
        Signal::PaymentRedirect => {
            "សារនេះឱ្យបង់ថ្លៃភ្លើង ថ្លៃសេវា ឬពន្ធ តាមភ្នាក់ងារ ឬគណនីផ្សេង មិនមែនតាមវិធីផ្លូវការទេ។ សូមបង់តាមកម្មវិធីផ្លូវការ ឬតេទៅស្ថាប័ននោះផ្ទាល់។"
        }
        Signal::RecruitmentBait => {
            "សារនេះផ្សាយការងារវាយអក្សរ ឆាត ឬ call center ប្រាក់ខែខ្ពស់ ដែលតែងជាការបោកទៅធ្វើការក្នុងទីតាំងបោកប្រាស់។ គេអាចដកលិខិតឆ្លងដែនរបស់អ្នក ហើយបង្ខំឱ្យធ្វើការ។"
        }
        Signal::MalwareFile => {
            "ឯកសារនេះជាកម្មវិធី (ដូចជា .apk ឬ .exe) មិនមែនឯកសារធម្មតាទេ។ កុំបើក ឬដំឡើង ព្រោះវាអាចចូលគ្រប់គ្រងទូរស័ព្ទរបស់អ្នក។"
        }
        Signal::Urgency => "សារនេះប្រញាប់ឱ្យអ្នកធ្វើភ្លាមៗ។",
        Signal::Reported(reporters) => {
            return format!("មានអ្នកប្រើ {reporters} នាក់ រាយការណ៍ថាគណនីនេះមិនមែនជាអ្នកទទួលដែលពួកគេចង់បង់ឱ្យទេ។");
        }
        Signal::Model { category, .. } => {
            return format!("AI យល់ថាសារនេះស្រដៀងនឹង{}។", category_km(category));
        }
        Signal::ModelUnavailable => "ពេលនេះ AI មិនអាចពិនិត្យបាន ដូច្នេះលទ្ធផលនេះមកពីការពិនិត្យស្វ័យប្រវត្តិតែប៉ុណ្ណោះ។",
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
    lines.push("តើឈ្មោះនេះត្រូវនឹងហាង ឬអ្នកដែលអ្នកចង់បង់ឱ្យទេ? បើមិនត្រូវ កុំបង់។".to_owned());
    lines.join("\n")
}

fn render_link(link: &LinkInfo) -> String {
    let mut lines = vec![format!("• គេហទំព័រ៖ {}", defang(&link.host))];
    if let Some(destination) = &link.redirected_to {
        lines.push(format!("• នាំបន្តទៅ៖ {}", defang(destination)));
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
            screenshot_unread_km(),
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
