pub mod khqr;
pub mod link;
pub mod text;

use khqr_core::DecodedKhqr;

use link::{LinkChecker, LinkInfo};

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
            Self::NotKhqr => 0.0,
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
            | Self::FamilyImpersonation => 0.5,
            Self::Lookalike(_)
            | Self::UpfrontFee
            | Self::MoveMoneyOut
            | Self::AccountRental
            | Self::TelegramTakeover
            | Self::MalwareFile => 0.6,
            Self::ChecksumInvalid | Self::DuplicateTag | Self::OtpRequest => 1.0,
        }
    }
}

pub async fn check_qr_payload(payload: &str, links: &LinkChecker) -> Check {
    match link::parse_http_url(payload) {
        Some(url) => links.check(url).await,
        None => khqr::check(payload),
    }
}
