use std::io::Cursor;

use super::{Check, Signal, Subject};

const MAX_ARCHIVE_ENTRIES: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    Pdf,
    Image,
    Video,
    Audio,
    Text,
    Document,
    Archive,
    WindowsProgram,
    AndroidApp,
    OtherProgram,
    Script,
    WebPage,
    Shortcut,
    DiskImage,
}

impl FileKind {
    /// Opening it runs code, or (for web pages) can show a fake login.
    pub fn is_dangerous(self) -> bool {
        matches!(
            self,
            Self::WindowsProgram
                | Self::AndroidApp
                | Self::OtherProgram
                | Self::Script
                | Self::WebPage
                | Self::Shortcut
                | Self::DiskImage
        )
    }

    /// What scammers pretend a dangerous file is.
    fn is_harmless_looking(self) -> bool {
        matches!(
            self,
            Self::Pdf | Self::Image | Self::Video | Self::Audio | Self::Text | Self::Document
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    ClamAv,
    VirusTotal(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub name: String,
    pub real: Option<FileKind>,
    pub scans: Scans,
    pub unread: Option<Unread>,
}

/// What the bot got of the file's bytes.
#[derive(Debug, Clone, Copy)]
pub enum Content<'a> {
    Bytes(&'a [u8]),
    Unread(Unread),
}

/// Why the inside of a file couldn't be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    /// Over the download limit, in MB.
    TooBig(u32),
    DownloadFailed,
}

/// What the antivirus checks said; `None` means that check didn't run.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scans {
    pub clamav_clean: Option<bool>,
    pub virustotal: Option<VirusTotal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirusTotal {
    Unknown,
    Seen { malicious: u16, engines: u16 },
}

pub fn kind_from_name(name: &str) -> Option<FileKind> {
    let extension = name.rsplit_once('.')?.1.trim().to_ascii_lowercase();
    kind_from_extension(&extension)
}

fn kind_from_extension(extension: &str) -> Option<FileKind> {
    Some(match extension {
        "pdf" => FileKind::Pdf,
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "bmp" => FileKind::Image,
        "mp4" | "mov" | "avi" | "mkv" | "3gp" | "webm" => FileKind::Video,
        "mp3" | "m4a" | "wav" | "ogg" | "aac" => FileKind::Audio,
        "txt" | "csv" | "log" => FileKind::Text,
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf" | "odt" => FileKind::Document,
        "docm" | "xlsm" | "pptm" => FileKind::Script,
        "zip" | "rar" | "7z" | "tar" | "gz" => FileKind::Archive,
        "exe" | "scr" | "msi" | "com" | "pif" | "cpl" | "dll" => FileKind::WindowsProgram,
        "apk" | "xapk" | "apks" | "aab" => FileKind::AndroidApp,
        "jar" | "dmg" | "pkg" | "app" | "deb" | "elf" => FileKind::OtherProgram,
        "bat" | "cmd" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "ps1" | "sh" | "hta" | "py" => {
            FileKind::Script
        }
        "html" | "htm" | "shtml" | "svg" => FileKind::WebPage,
        "lnk" | "url" => FileKind::Shortcut,
        "iso" | "img" | "vhd" => FileKind::DiskImage,
        _ => return None,
    })
}

pub fn kind_from_mime(mime: &str) -> Option<FileKind> {
    Some(match mime {
        "application/vnd.android.package-archive" => FileKind::AndroidApp,
        "application/x-msdownload"
        | "application/x-dosexec"
        | "application/vnd.microsoft.portable-executable"
        | "application/x-msi" => FileKind::WindowsProgram,
        "application/pdf" => FileKind::Pdf,
        "text/html" => FileKind::WebPage,
        _ if mime.starts_with("image/") => FileKind::Image,
        _ if mime.starts_with("video/") => FileKind::Video,
        _ => return None,
    })
}

/// The real type, read from the first bytes, whatever the name says.
pub fn kind_from_bytes(bytes: &[u8]) -> Option<FileKind> {
    let starts = |magic: &[u8]| bytes.starts_with(magic);
    if starts(b"MZ") {
        return Some(FileKind::WindowsProgram);
    }
    if starts(b"\x7fELF") || starts(b"\xca\xfe\xba\xbe") || starts(b"\xcf\xfa\xed\xfe") {
        return Some(FileKind::OtherProgram);
    }
    if starts(b"PK\x03\x04") {
        return Some(zip_kind(bytes));
    }
    if starts(b"%PDF") {
        return Some(FileKind::Pdf);
    }
    if starts(b"\xff\xd8\xff") || starts(b"\x89PNG") || starts(b"GIF8") {
        return Some(FileKind::Image);
    }
    if starts(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        return Some(FileKind::Image);
    }
    if bytes.get(4..8) == Some(b"ftyp") {
        return Some(FileKind::Video);
    }
    if starts(b"Rar!") || starts(b"7z\xbc\xaf") || starts(b"\x1f\x8b") {
        return Some(FileKind::Archive);
    }
    if starts(b"\x4c\x00\x00\x00\x01\x14\x02\x00") {
        return Some(FileKind::Shortcut);
    }
    if bytes.get(0x8001..0x8006) == Some(b"CD001") {
        return Some(FileKind::DiskImage);
    }
    if starts(b"#!") {
        return Some(FileKind::Script);
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_ascii_lowercase();
    let head = head.trim_start_matches('\u{feff}').trim_start();
    if head.starts_with("<!doctype html")
        || head.starts_with("<html")
        || head.starts_with("<script")
    {
        return Some(FileKind::WebPage);
    }
    None
}

fn zip_kind(bytes: &[u8]) -> FileKind {
    let names = archive_entries(bytes).map(|entries| entries.names);
    let has = |wanted: &str| {
        names
            .as_ref()
            .is_some_and(|names| names.iter().any(|name| name == wanted))
    };
    if has("AndroidManifest.xml") {
        FileKind::AndroidApp
    } else if has("[Content_Types].xml") {
        FileKind::Document
    } else if has("META-INF/MANIFEST.MF") {
        FileKind::OtherProgram
    } else {
        FileKind::Archive
    }
}

struct Entries {
    names: Vec<String>,
    encrypted: bool,
}

fn archive_entries(bytes: &[u8]) -> Option<Entries> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let count = archive.len().min(MAX_ARCHIVE_ENTRIES);
    let mut names = Vec::with_capacity(count);
    let mut encrypted = false;
    for index in 0..count {
        let Ok(entry) = archive.by_index_raw(index) else {
            continue;
        };
        encrypted |= entry.encrypted();
        if let Ok(name) = entry.name() {
            names.push(name.into_owned());
        }
    }
    Some(Entries { names, encrypted })
}

/// Name tricks, the real type behind the name, and what's packed inside a zip.
pub fn inspect(name: &str, mime: Option<&str>, content: Content, scans: Scans) -> Check {
    let (bytes, unread) = match content {
        Content::Bytes(bytes) => (Some(bytes), None),
        Content::Unread(why) => (None, Some(why)),
    };
    let mut signals = Vec::new();
    if name.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')) {
        signals.push(Signal::HiddenFileName);
    }

    let named = kind_from_name(name);
    // An .apk or .jar is a zip inside, so a dangerous name wins over a plain archive.
    let real = match (bytes.and_then(kind_from_bytes), named) {
        (Some(FileKind::Archive), Some(named)) if named.is_dangerous() => Some(named),
        (Some(real), _) => Some(real),
        (None, _) => mime.and_then(kind_from_mime).or(named),
    };
    let decoy = decoy_extension(name).or(named.filter(|kind| kind.is_harmless_looking()));
    match (decoy, real) {
        (Some(shown), Some(real)) if shown != real && real.is_dangerous() => {
            signals.push(Signal::DisguisedFile { shown, real });
        }
        (_, Some(real)) if real.is_dangerous() => signals.push(Signal::DangerousFile(real)),
        _ => {}
    }

    match (real, super::link::app_brand(name)) {
        (Some(FileKind::AndroidApp | FileKind::WindowsProgram), Some(brand)) => {
            signals.push(Signal::FakeBankApp(brand));
        }
        (Some(FileKind::WebPage), Some(brand)) => signals.push(Signal::BrandClaim(brand)),
        _ => {}
    }

    if real == Some(FileKind::Archive)
        && let Some(entries) = bytes.and_then(archive_entries)
    {
        if entries
            .names
            .iter()
            .any(|entry| kind_from_name(entry).is_some_and(FileKind::is_dangerous))
        {
            signals.push(Signal::ProgramInArchive);
        }
        if entries.encrypted {
            signals.push(Signal::LockedArchive);
        }
    }

    match scans.virustotal {
        Some(VirusTotal::Seen { malicious, .. }) if malicious >= 3 => {
            signals.push(Signal::KnownMalware(Detector::VirusTotal(malicious)));
        }
        Some(VirusTotal::Seen { malicious, .. }) if malicious > 0 => {
            signals.push(Signal::FlaggedByFewEngines(malicious));
        }
        _ => {}
    }
    if scans.clamav_clean == Some(false) {
        signals.push(Signal::KnownMalware(Detector::ClamAv));
    }

    Check {
        subject: Subject::File(Box::new(FileInfo {
            name: name.to_owned(),
            real,
            scans,
            unread,
        })),
        signals,
    }
}

/// The harmless-looking extension in front of the real one, as in "photo.jpg.exe".
fn decoy_extension(name: &str) -> Option<FileKind> {
    let mut parts = name.rsplit('.');
    let last = parts.next()?;
    let before = parts.next()?;
    parts.next()?;
    let real = kind_from_extension(&last.trim().to_ascii_lowercase())?;
    let shown = kind_from_extension(&before.trim().to_ascii_lowercase())?;
    (real.is_dangerous() && shown.is_harmless_looking()).then_some(shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(name: &str, bytes: &[u8]) -> Vec<Signal> {
        inspect(name, None, Content::Bytes(bytes), Scans::default()).signals
    }

    fn zip_with(entries: &[(&str, bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, encrypted) in entries {
            let offset = out.len() as u32;
            let flags: u16 = if *encrypted { 1 } else { 0 };
            let header = |signature: &[u8], central: bool| {
                let mut h = signature.to_vec();
                if central {
                    h.extend_from_slice(&20u16.to_le_bytes());
                }
                h.extend_from_slice(&20u16.to_le_bytes());
                h.extend_from_slice(&flags.to_le_bytes());
                h.extend_from_slice(&[0; 2 + 4 + 4 + 4 + 4]);
                h.extend_from_slice(&(name.len() as u16).to_le_bytes());
                h.extend_from_slice(&0u16.to_le_bytes());
                if central {
                    h.extend_from_slice(&[0; 2 + 2 + 2 + 4]);
                    h.extend_from_slice(&offset.to_le_bytes());
                }
                h.extend_from_slice(name.as_bytes());
                h
            };
            out.extend(header(b"PK\x03\x04", false));
            central.extend(header(b"PK\x01\x02", true));
        }
        let start = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        let count = entries.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn content_reveals_the_real_type() {
        assert_eq!(
            kind_from_bytes(b"MZ\x90\x00"),
            Some(FileKind::WindowsProgram)
        );
        assert_eq!(kind_from_bytes(b"%PDF-1.7"), Some(FileKind::Pdf));
        assert_eq!(kind_from_bytes(b"\xff\xd8\xff\xe0"), Some(FileKind::Image));
        assert_eq!(
            kind_from_bytes(b"  <!DOCTYPE html><title>x"),
            Some(FileKind::WebPage)
        );
        assert_eq!(
            kind_from_bytes(&zip_with(&[("AndroidManifest.xml", false)])),
            Some(FileKind::AndroidApp)
        );
        assert_eq!(kind_from_bytes(b"hello"), None);
    }

    #[test]
    fn programs_dressed_as_documents_are_disguised() {
        let disguised = |shown, real| Signal::DisguisedFile { shown, real };
        assert_eq!(
            signals("invoice.pdf", b"MZ\x90\x00"),
            [disguised(FileKind::Pdf, FileKind::WindowsProgram)]
        );
        assert_eq!(
            signals("photo.jpg.exe", b"MZ\x90\x00"),
            [disguised(FileKind::Image, FileKind::WindowsProgram)]
        );
        assert_eq!(
            signals("ឯកសារ.pdf      .scr", b"MZ"),
            [disguised(FileKind::Pdf, FileKind::WindowsProgram)]
        );
        assert_eq!(
            signals("statement.pdf.htm", b"<html><form>"),
            [disguised(FileKind::Pdf, FileKind::WebPage)]
        );
        assert_eq!(
            signals("setup.exe", b"MZ"),
            [Signal::DangerousFile(FileKind::WindowsProgram)]
        );
        assert_eq!(
            signals("login.html", b"<html><form>"),
            [Signal::DangerousFile(FileKind::WebPage)]
        );
        assert_eq!(
            signals("ABA statement.htm", b"<html><form>"),
            [
                Signal::DangerousFile(FileKind::WebPage),
                Signal::BrandClaim("ABA")
            ]
        );
        assert_eq!(kind_from_name("notes.txt"), Some(FileKind::Text));
        assert_eq!(
            signals("game.apk", b"PK\x03\x04"),
            [Signal::DangerousFile(FileKind::AndroidApp)]
        );
        assert_eq!(
            signals("ABA Mobile.apk", b"PK\x03\x04"),
            [
                Signal::DangerousFile(FileKind::AndroidApp),
                Signal::FakeBankApp("ABA")
            ]
        );
    }

    #[test]
    fn unread_files_fall_back_to_name_and_type() {
        let check = inspect(
            "big.apk",
            None,
            Content::Unread(Unread::TooBig(20)),
            Scans::default(),
        );
        assert_eq!(check.signals, [Signal::DangerousFile(FileKind::AndroidApp)]);
        let Subject::File(info) = check.subject else {
            panic!("expected a file");
        };
        assert_eq!(info.unread, Some(Unread::TooBig(20)));
    }

    #[test]
    fn reversed_names_are_flagged() {
        let name = "photo\u{202E}gpj.exe";
        assert!(signals(name, b"MZ").contains(&Signal::HiddenFileName));
    }

    #[test]
    fn real_documents_have_no_signals() {
        assert!(signals("report.pdf", b"%PDF-1.4").is_empty());
        assert!(signals("photo.jpg", b"\xff\xd8\xff\xe0").is_empty());
        assert!(signals("notes.docx", &zip_with(&[("[Content_Types].xml", false)])).is_empty());
        assert!(
            signals(
                "photos.zip",
                &zip_with(&[("a.jpg", false), ("b.png", false)])
            )
            .is_empty()
        );
    }

    #[test]
    fn programs_and_passwords_inside_zips_are_flagged() {
        assert_eq!(
            signals(
                "documents.zip",
                &zip_with(&[("readme.txt", false), ("invoice.pdf.exe", false)])
            ),
            [Signal::ProgramInArchive]
        );
        assert_eq!(
            signals("locked.zip", &zip_with(&[("data.bin", true)])),
            [Signal::LockedArchive]
        );
    }

    #[test]
    fn antivirus_results_become_signals() {
        let scanned = |scans| inspect("file.pdf", None, Content::Bytes(b"%PDF"), scans).signals;
        let seen = |malicious| Scans {
            virustotal: Some(VirusTotal::Seen {
                malicious,
                engines: 70,
            }),
            ..Scans::default()
        };
        assert_eq!(
            scanned(seen(12)),
            [Signal::KnownMalware(Detector::VirusTotal(12))]
        );
        assert_eq!(scanned(seen(1)), [Signal::FlaggedByFewEngines(1)]);
        assert!(scanned(seen(0)).is_empty());
        let clamav = Scans {
            clamav_clean: Some(false),
            ..Scans::default()
        };
        assert_eq!(scanned(clamav), [Signal::KnownMalware(Detector::ClamAv)]);
    }
}
