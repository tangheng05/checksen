pub mod khqr;
pub mod link;
pub mod llm;
pub mod text;

use khqr_core::DecodedKhqr;

use link::{LinkChecker, LinkInfo};
use llm::ScamCategory;

#[derive(Debug)]
pub struct Check {
    pub subject: Subject,
    pub signals: Vec<Signal>,
}

#[derive(Debug)]
pub enum Subject {
    Unreadable,
    Text,
    Khqr(Box<DecodedKhqr>),
    Link(LinkInfo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    NotKhqr,
    ChecksumInvalid,
    DuplicateTag,
    Malformed,
    Expired,
    Lookalike(&'static str),
    Punycode,
    NewDomain,
    Reported(u32),
    OtpRequest,
    UpfrontFee,
    MoveMoneyOut,
    AccountRental,
    AuthorityThreat,
    FamilyImpersonation,
    AccountThreat,
    LoanBait,
    JobBait,
    PrizeBait,
    InvestmentBait,
    TelegramTakeover,
    MalwareFile,
    Urgency,
    Model { category: ScamCategory, cited: bool },
    ModelUnavailable,
}

impl Signal {
    pub fn is_hard(self) -> bool {
        matches!(
            self,
            Self::ChecksumInvalid | Self::DuplicateTag | Self::OtpRequest
        )
    }

    pub fn weight(self) -> f32 {
        match self {
            Self::NotKhqr | Self::ModelUnavailable => 0.0,
            Self::Urgency => 0.2,
            Self::Punycode
            | Self::AccountThreat
            | Self::LoanBait
            | Self::JobBait
            | Self::PrizeBait
            | Self::InvestmentBait => 0.4,
            Self::Malformed
            | Self::Expired
            | Self::NewDomain
            | Self::AuthorityThreat
            | Self::FamilyImpersonation
            | Self::Model { .. } => 0.5,
            Self::Lookalike(_)
            | Self::Reported(_)
            | Self::UpfrontFee
            | Self::MoveMoneyOut
            | Self::AccountRental
            | Self::TelegramTakeover
            | Self::MalwareFile => 0.6,
            Self::ChecksumInvalid | Self::DuplicateTag | Self::OtpRequest => 1.0,
        }
    }
}

const TEXT_RULE_SIGNALS: [(Signal, &str); 14] = [
    (Signal::OtpRequest, "otp_request"),
    (Signal::UpfrontFee, "upfront_fee"),
    (Signal::MoveMoneyOut, "move_money_out"),
    (Signal::AccountRental, "account_rental"),
    (Signal::AuthorityThreat, "authority_threat"),
    (Signal::FamilyImpersonation, "family_impersonation"),
    (Signal::AccountThreat, "account_threat"),
    (Signal::LoanBait, "loan_bait"),
    (Signal::JobBait, "job_bait"),
    (Signal::PrizeBait, "prize_bait"),
    (Signal::InvestmentBait, "investment_bait"),
    (Signal::TelegramTakeover, "telegram_takeover"),
    (Signal::MalwareFile, "malware_file"),
    (Signal::Urgency, "urgency"),
];

impl Signal {
    pub fn rule_name(self) -> Option<&'static str> {
        TEXT_RULE_SIGNALS
            .iter()
            .find(|(signal, _)| *signal == self)
            .map(|(_, name)| *name)
    }

    pub fn from_rule_name(name: &str) -> Option<Self> {
        TEXT_RULE_SIGNALS
            .iter()
            .find(|(_, rule)| *rule == name)
            .map(|(signal, _)| *signal)
    }

    pub fn rule_names() -> impl Iterator<Item = &'static str> {
        TEXT_RULE_SIGNALS.iter().map(|(_, name)| *name)
    }
}

pub async fn check_qr_payload(payload: &str, links: &LinkChecker) -> Check {
    match link::parse_http_url(payload) {
        Some(url) => links.check(url).await,
        None => khqr::check(payload),
    }
}
