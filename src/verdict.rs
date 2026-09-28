use khqr_core::{Currency, DecodedKhqr};

use crate::analyzers::link::LinkInfo;
use crate::analyzers::{Check, Signal, Subject};

pub const HELP_KM: &str = "សូមផ្ញើរូបថត KHQR កូដ KHQR ឬតំណ (link) ដែលអ្នកសង្ស័យមកទីនេះ។ ខ្ញុំនឹងប្រាប់ថា QR នោះបង់ប្រាក់ទៅអ្នកណា ឬតំណនោះនាំទៅគេហទំព័រណាពិតប្រាកដ។";
const BANK_APP_ADVICE_KM: &str =
    "⚠️ មុនបង់ប្រាក់ សូមពិនិត្យឈ្មោះអ្នកទទួល និងចំនួនទឹកប្រាក់ក្នុងកម្មវិធីធនាគាររបស់អ្នកឱ្យបានច្បាស់។";
const LINK_ADVICE_KM: &str = "កុំបញ្ចូលលេខសម្ងាត់ ឬលេខកូដ OTP តាមរយៈតំណ។ បើចង់ពិនិត្យគណនី សូមបើកកម្មវិធីធនាគារដោយផ្ទាល់។";
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
    if check.signals.iter().any(|signal| signal.is_hard()) || score > 0.8 {
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
        Subject::Unreadable => {}
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
    };
    reason.to_owned()
}

fn render_payee(payee: &DecodedKhqr) -> String {
    let mut lines = vec![
        "QR នេះបង់ប្រាក់ទៅ៖".to_owned(),
        format!("• ឈ្មោះអ្នកទទួល៖ {}", payee.merchant_name),
        format!("• គណនី៖ {}", payee.bakong_account_id),
    ];
    if let Some(bank) = &payee.acquiring_bank {
        lines.push(format!("• ធនាគារ៖ {bank}"));
    }
    if let Some(amount) = &payee.transaction_amount {
        let currency = match payee.currency() {
            Some(Currency::Khr) => "KHR",
            Some(Currency::Usd) => "USD",
            _ => payee.transaction_currency.as_str(),
        };
        lines.push(format!("• ចំនួនទឹកប្រាក់៖ {amount} {currency}"));
    }
    lines.push(format!("• ទីក្រុង៖ {}", payee.merchant_city));
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
    fn link_reply_defangs_domains() {
        let reply = render_km(&[link_check(vec![Signal::Lookalike("ABA")])]);
        assert!(reply.contains("bit[.]ly") && reply.contains("ababank-verify[.]com"));
        assert!(!reply.contains("ababank-verify.com"));
    }
}
