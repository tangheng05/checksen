use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use khqr_core::KhqrError;
use rxing::{BarcodeFormat, DecodeHints};

use super::{Check, Signal, Subject};

const MAX_QRS_PER_IMAGE: usize = 3;
const EMV_HEADER: &str = "000201";

pub fn looks_like_khqr(text: &str) -> bool {
    text.trim().starts_with(EMV_HEADER)
}

pub fn payloads_from_image(bytes: &[u8]) -> Vec<String> {
    let mut hints = DecodeHints {
        PossibleFormats: Some(HashSet::from([BarcodeFormat::QR_CODE])),
        ..Default::default()
    };
    let Ok(results) = rxing::helpers::detect_multiple_in_buffer_with_hints(bytes, &mut hints)
    else {
        return Vec::new();
    };

    let mut payloads: Vec<String> = Vec::new();
    for result in results {
        let text = result.getText().to_owned();
        if !payloads.contains(&text) {
            payloads.push(text);
        }
    }
    payloads.truncate(MAX_QRS_PER_IMAGE);
    payloads
}

pub fn check(payload: &str) -> Check {
    let payload = payload.trim();
    if !looks_like_khqr(payload) {
        return Check {
            subject: Subject::Unreadable,
            signals: vec![Signal::NotKhqr],
        };
    }

    match khqr_core::decode(payload) {
        Ok(decoded) => {
            let signals = if decoded.is_expired(now_ms()) {
                vec![Signal::Expired]
            } else {
                Vec::new()
            };
            Check {
                subject: Subject::Khqr(Box::new(decoded)),
                signals,
            }
        }
        Err(error) => {
            let signal = match error {
                KhqrError::ChecksumMismatch { .. } => Signal::ChecksumInvalid,
                KhqrError::DuplicateTag { .. } => Signal::DuplicateTag,
                _ => Signal::Malformed,
            };
            Check {
                subject: Subject::Unreadable,
                signals: vec![signal],
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const INDIVIDUAL_KHR_500: &str = "00020101021229180014jonhsmith@nbcq52045999530311654035005802KH5910Jonh Smith6010PHNOM PENH99170013173949577872263046894";
    pub const ABA_MERCHANT: &str = "00020101021230510016abaakhppxxx@abaa01151250212145328460208ABA Bank52045987530311654031005802KH5925OLD ME 25 CHAR WINNER IP26010Phnom Penh62570115MC-REF-KH-1500068340010PAYWAY@ABA0208104514230604A2279934001317598053453370113175980552533763049FBD";

    #[test]
    fn valid_payload_has_no_signals() {
        let check = check(INDIVIDUAL_KHR_500);
        assert!(check.signals.is_empty(), "{:?}", check.signals);
        assert!(matches!(check.subject, Subject::Khqr(_)));
    }

    #[test]
    fn expired_dynamic_payload_is_flagged() {
        let check = check(ABA_MERCHANT);
        assert_eq!(check.signals, [Signal::Expired]);
        assert!(matches!(check.subject, Subject::Khqr(_)));
    }

    #[test]
    fn edited_payload_fails_checksum() {
        let tampered = INDIVIDUAL_KHR_500.replace("Jonh Smith", "Jonh Smiti");
        assert_eq!(check(&tampered).signals, [Signal::ChecksumInvalid]);
    }

    #[test]
    fn link_is_not_khqr() {
        assert_eq!(check("https://example.com/pay").signals, [Signal::NotKhqr]);
    }

    #[test]
    fn reads_payload_from_png() {
        let png = khqr_core::to_png(ABA_MERCHANT, 400).unwrap();
        assert_eq!(payloads_from_image(&png), [ABA_MERCHANT]);
    }

    #[test]
    fn blank_image_has_no_payloads() {
        let mut png = Vec::new();
        image::GrayImage::from_pixel(200, 200, image::Luma([255]))
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert!(payloads_from_image(&png).is_empty());
    }
}
