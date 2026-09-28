pub mod khqr;
pub mod link;

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
}

impl Signal {
    pub fn is_hard(self) -> bool {
        matches!(self, Self::ChecksumInvalid | Self::DuplicateTag)
    }

    pub fn weight(self) -> f32 {
        match self {
            Self::NotKhqr => 0.0,
            Self::Punycode => 0.4,
            Self::Malformed | Self::Expired | Self::NewDomain => 0.5,
            Self::Lookalike(_) => 0.6,
            Self::ChecksumInvalid | Self::DuplicateTag => 1.0,
        }
    }
}

pub async fn check_qr_payload(payload: &str, links: &LinkChecker) -> Check {
    match link::parse_http_url(payload) {
        Some(url) => links.check(url).await,
        None => khqr::check(payload),
    }
}
