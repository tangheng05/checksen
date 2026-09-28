use khqr_core::{Currency, DecodedKhqr};

use crate::analyzers::Signal;
use crate::analyzers::khqr::KhqrCheck;

pub const HELP_KM: &str = "សូមផ្ញើរូបថត KHQR ឬកូដ KHQR មកខ្ញុំ។ ខ្ញុំនឹងប្រាប់អ្នកថា QR នោះបង់ប្រាក់ទៅឱ្យអ្នកណាពិតប្រាកដ។";
const BANK_APP_ADVICE_KM: &str = "សូមពិនិត្យឈ្មោះអ្នកទទួលក្នុងកម្មវិធីធនាគាររបស់អ្នក មុនពេលបង់ប្រាក់។";
const NO_QR_FOUND_KM: &str = "រកមិនឃើញ QR នៅក្នុងរូបភាពនេះទេ។ សូមផ្ញើរូបថតច្បាស់ៗ ដែលឃើញ QR ទាំងមូល។";

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
            Self::NoKnownSignals => "⚪ មិនឃើញសញ្ញាហានិភ័យដែលគេស្គាល់",
            Self::CantTell => "❔ មិនអាចសន្និដ្ឋានបាន",
        }
    }
}

pub fn decide(check: &KhqrCheck) -> Level {
    let score: f32 = check.signals.iter().map(|signal| signal.weight()).sum();
    if check.signals.iter().any(|signal| signal.is_hard()) || score > 0.8 {
        Level::HighRisk
    } else if score >= 0.4 {
        Level::Suspicious
    } else if check.payee.is_none() {
        Level::CantTell
    } else {
        Level::NoKnownSignals
    }
}

pub fn render_km(checks: &[KhqrCheck]) -> String {
    let mut sections: Vec<String> = if checks.is_empty() {
        vec![format!("{}\n{NO_QR_FOUND_KM}", Level::CantTell.label_km())]
    } else {
        checks.iter().map(render_check).collect()
    };
    sections.push(BANK_APP_ADVICE_KM.to_owned());
    sections.join("\n\n")
}

fn render_check(check: &KhqrCheck) -> String {
    let mut lines = vec![decide(check).label_km().to_owned()];
    lines.extend(
        check
            .signals
            .iter()
            .map(|&signal| reason_km(signal).to_owned()),
    );
    if let Some(payee) = &check.payee {
        lines.push(render_payee(payee));
    }
    lines.join("\n")
}

fn reason_km(signal: Signal) -> &'static str {
    match signal {
        Signal::NotKhqr => "QR នេះមិនមែនជា KHQR សម្រាប់ទូទាត់ប្រាក់ទេ។",
        Signal::ChecksumInvalid => "លេខផ្ទៀងផ្ទាត់របស់ KHQR នេះមិនត្រឹមត្រូវ។ QR អាចត្រូវបានកែប្រែ ឬខូច។",
        Signal::DuplicateTag => "KHQR នេះមានព័ត៌មានដដែលៗ ដែលជាលក្ខណៈនៃ QR ដែលត្រូវបានកែប្រែ។",
        Signal::Malformed => "QR នេះមើលទៅដូចជា KHQR ប៉ុន្តែទម្រង់របស់វាមិនត្រឹមត្រូវ។",
        Signal::Expired => "QR សម្រាប់ទូទាត់តែម្តងនេះបានផុតកំណត់ហើយ។",
    }
}

fn render_payee(payee: &DecodedKhqr) -> String {
    let mut lines = vec![
        "ប្រាក់នឹងទៅកាន់៖".to_owned(),
        format!("• ឈ្មោះ៖ {}", payee.merchant_name),
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
    lines.push("តើនេះជាអ្នកដែលអ្នកចង់បង់ប្រាក់ឱ្យមែនទេ?".to_owned());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::khqr::{self, tests::INDIVIDUAL_KHR_500};

    fn check_with(signals: Vec<Signal>, valid: bool) -> KhqrCheck {
        KhqrCheck {
            payee: valid.then(|| khqr_core::decode(INDIVIDUAL_KHR_500).unwrap()),
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
    }

    #[test]
    fn every_reply_sends_user_to_bank_app_and_never_says_safe() {
        let replies = [
            render_km(&[]),
            render_km(&[khqr::check(INDIVIDUAL_KHR_500)]),
            render_km(&[check_with(vec![Signal::ChecksumInvalid], false)]),
            render_km(&[check_with(vec![Signal::Expired], true)]),
            render_km(&[check_with(vec![Signal::NotKhqr], false)]),
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
}
