pub mod khqr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    NotKhqr,
    ChecksumInvalid,
    DuplicateTag,
    Malformed,
    Expired,
}

impl Signal {
    pub fn is_hard(self) -> bool {
        matches!(self, Self::ChecksumInvalid | Self::DuplicateTag)
    }

    pub fn weight(self) -> f32 {
        match self {
            Self::NotKhqr => 0.0,
            Self::Malformed | Self::Expired => 0.5,
            Self::ChecksumInvalid | Self::DuplicateTag => 1.0,
        }
    }
}
