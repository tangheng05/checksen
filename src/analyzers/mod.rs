pub mod abusech;
pub mod file;
pub mod indicators;
pub mod inside;
pub mod intent;
pub mod khqr;
pub mod link;
pub mod llm;
pub mod reputation;
pub mod scan;
pub mod senders;
pub mod sites;
pub mod text;

use khqr_core::DecodedKhqr;

use file::{Detector, FileInfo, FileKind};
use indicators::IndicatorKind;
use inside::Power;
use reputation::Threat;

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
    File(Box<FileInfo>),
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
    ReportedScam(IndicatorKind, u32),
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
    DonationRequest,
    Extortion,
    PaymentRedirect,
    RecruitmentBait,
    MalwareFile,
    GamblingBait,
    PayBeforeMeeting,
    Urgency,
    BrandClaim(&'static str),
    PasswordPage,
    ImpersonatedAccount(&'static str),
    ImpersonatedSender(&'static str),
    DisguisedFile { shown: FileKind, real: FileKind },
    HiddenFileName,
    FakeBankApp(&'static str),
    DangerousFile(FileKind),
    KnownBadSite(Threat),
    KnownMalwareLink,
    ProgramInArchive,
    LockedArchive,
    KnownMalware(Detector),
    FlaggedByFewEngines(u16),
    AppPower(Power),
    StealsCodes,
    MacroDocument,
    PdfLaunch,
    PdfScript,
    SendsToAttacker,
    DownloadsProgram(FileKind),
    Model { category: ScamCategory, cited: bool },
    ModelUnavailable,
}

impl Signal {
    pub fn is_hard(self) -> bool {
        matches!(
            self,
            Self::ChecksumInvalid
                | Self::DuplicateTag
                | Self::OtpRequest
                | Self::DisguisedFile { .. }
                | Self::HiddenFileName
                | Self::FakeBankApp(_)
                | Self::KnownMalware(_)
                | Self::KnownBadSite(_)
                | Self::KnownMalwareLink
                | Self::StealsCodes
                | Self::SendsToAttacker
        )
    }

    pub fn weight(self) -> f32 {
        match self {
            Self::NotKhqr | Self::ModelUnavailable => 0.0,
            Self::Urgency
            | Self::PasswordPage
            | Self::ImpersonatedAccount(_)
            | Self::LockedArchive
            | Self::PdfScript
            | Self::AppPower(Power::DrawsOverApps | Power::DeviceAdmin | Power::InstallsApps) => {
                0.2
            }
            Self::Punycode
            | Self::AccountThreat
            | Self::LoanBait
            | Self::JobBait
            | Self::PrizeBait
            | Self::InvestmentBait
            | Self::DonationRequest
            | Self::RecruitmentBait
            | Self::GamblingBait
            | Self::FlaggedByFewEngines(_)
            | Self::AppPower(Power::ReadsSms | Power::ControlsScreen) => 0.4,
            Self::Malformed
            | Self::Expired
            | Self::NewDomain
            | Self::AuthorityThreat
            | Self::FamilyImpersonation
            | Self::PaymentRedirect
            | Self::Model { .. } => 0.5,
            Self::Lookalike(_)
            | Self::BrandClaim(_)
            | Self::ImpersonatedSender(_)
            | Self::Reported(_)
            | Self::ReportedScam(..)
            | Self::UpfrontFee
            | Self::MoveMoneyOut
            | Self::AccountRental
            | Self::TelegramTakeover
            | Self::Extortion
            | Self::PayBeforeMeeting
            | Self::MalwareFile
            | Self::DangerousFile(_)
            | Self::ProgramInArchive
            | Self::MacroDocument
            | Self::PdfLaunch
            | Self::DownloadsProgram(_) => 0.6,
            Self::ChecksumInvalid
            | Self::DuplicateTag
            | Self::OtpRequest
            | Self::DisguisedFile { .. }
            | Self::HiddenFileName
            | Self::FakeBankApp(_)
            | Self::KnownMalware(_)
            | Self::KnownBadSite(_)
            | Self::KnownMalwareLink
            | Self::StealsCodes
            | Self::SendsToAttacker => 1.0,
        }
    }
}

const TEXT_RULE_SIGNALS: [(Signal, &str); 20] = [
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
    (Signal::DonationRequest, "donation_request"),
    (Signal::Extortion, "extortion"),
    (Signal::PaymentRedirect, "payment_redirect"),
    (Signal::RecruitmentBait, "recruitment_bait"),
    (Signal::MalwareFile, "malware_file"),
    (Signal::GamblingBait, "gambling_bait"),
    (Signal::PayBeforeMeeting, "pay_before_meeting"),
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
