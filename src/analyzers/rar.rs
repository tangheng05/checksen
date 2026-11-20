use super::file::Entries;

const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// Names of the files in a RAR, read from its headers without unpacking anything.
pub(super) fn entries(bytes: &[u8], max: usize) -> Option<Entries> {
    let mut entries = Entries {
        names: Vec::new(),
        encrypted: false,
    };
    if bytes.starts_with(RAR5) {
        rar5(bytes, max, &mut entries);
    } else if bytes.starts_with(RAR4) {
        rar4(bytes, max, &mut entries);
    } else {
        return None;
    }
    Some(entries)
}

fn rar5(bytes: &[u8], max: usize, entries: &mut Entries) {
    let mut at = RAR5.len();
    while entries.names.len() < max {
        let Some(next) = rar5_block(bytes, at, entries) else {
            return;
        };
        at = next;
    }
}

/// Reads one block and returns where the next one starts, or `None` at the end.
fn rar5_block(bytes: &[u8], at: usize, entries: &mut Entries) -> Option<usize> {
    let mut reader = Reader {
        bytes,
        at: at.checked_add(4)?,
    };
    let size = reader.size()?;
    let end = reader.at.checked_add(size)?;
    let header = bytes.get(..end)?;
    let kind = reader.vint()?;
    let flags = reader.vint()?;
    let extra = if flags & 0x01 != 0 { reader.size()? } else { 0 };
    let data = if flags & 0x02 != 0 { reader.size()? } else { 0 };
    match kind {
        2 => {
            let file_flags = reader.vint()?;
            reader.vint()?;
            reader.vint()?;
            if file_flags & 0x02 != 0 {
                reader.skip(4)?;
            }
            if file_flags & 0x04 != 0 {
                reader.skip(4)?;
            }
            reader.vint()?;
            reader.vint()?;
            let length = reader.size()?;
            let name = header.get(reader.at..reader.at.checked_add(length)?)?;
            if file_flags & 0x01 == 0 {
                entries
                    .names
                    .push(String::from_utf8_lossy(name).into_owned());
            }
            let extra = header.get(end.checked_sub(extra)?..)?;
            entries.encrypted |= rar5_encrypted(extra);
        }
        4 => {
            entries.encrypted = true;
            return None;
        }
        5 => return None,
        _ => {}
    }
    end.checked_add(data)
}

fn rar5_encrypted(extra: &[u8]) -> bool {
    let mut reader = Reader {
        bytes: extra,
        at: 0,
    };
    while let Some(size) = reader.size() {
        let start = reader.at;
        if reader.vint() == Some(0x01) {
            return true;
        }
        let Some(next) = start.checked_add(size) else {
            return false;
        };
        reader.at = next;
    }
    false
}

fn rar4(bytes: &[u8], max: usize, entries: &mut Entries) {
    let mut at = RAR4.len();
    while entries.names.len() < max {
        let Some(next) = rar4_block(bytes, at, entries) else {
            return;
        };
        at = next;
    }
}

fn rar4_block(bytes: &[u8], at: usize, entries: &mut Entries) -> Option<usize> {
    let u16_at = |header: &[u8], offset: usize| {
        Some(u16::from_le_bytes(
            header.get(offset..offset + 2)?.try_into().ok()?,
        ))
    };
    let u32_at = |header: &[u8], offset: usize| {
        Some(u32::from_le_bytes(
            header.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let start = bytes.get(at..)?;
    let kind = *start.get(2)?;
    let flags = u16_at(start, 3)?;
    let size = usize::from(u16_at(start, 5)?);
    if size < 7 {
        return None;
    }
    let header = start.get(..size)?;
    let mut data = if flags & 0x8000 != 0 {
        u64::from(u32_at(header, 7)?)
    } else {
        0
    };
    match kind {
        0x73 if flags & 0x0080 != 0 => {
            entries.encrypted = true;
            return None;
        }
        0x74 => {
            entries.encrypted |= flags & 0x0004 != 0;
            let large = flags & 0x0100 != 0;
            if large {
                data |= u64::from(u32_at(header, 32)?) << 32;
            }
            let name_at = if large { 40 } else { 32 };
            let length = usize::from(u16_at(header, 26)?);
            let mut name = header.get(name_at..name_at + length)?;
            // Unicode names put a plain copy first, then a zero byte and the encoded name.
            if flags & 0x0200 != 0
                && let Some(zero) = name.iter().position(|&byte| byte == 0)
            {
                name = &name[..zero];
            }
            if flags & 0x00e0 != 0x00e0 {
                entries
                    .names
                    .push(String::from_utf8_lossy(name).into_owned());
            }
        }
        0x7b => return None,
        _ => {}
    }
    at.checked_add(size)?
        .checked_add(usize::try_from(data).ok()?)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn vint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = *self.bytes.get(self.at)?;
            self.at += 1;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn size(&mut self) -> Option<usize> {
        usize::try_from(self.vint()?).ok()
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        self.at = self.at.checked_add(count)?;
        Some(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn vint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn crc(bytes: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        crc.sum()
    }

    fn rar5_block(kind: u64, flags: u64, fields: &[u8], extra: &[u8], data: &[u8]) -> Vec<u8> {
        let mut body = vint(kind);
        body.extend(vint(
            flags
                | if extra.is_empty() { 0 } else { 0x01 }
                | if data.is_empty() { 0 } else { 0x02 },
        ));
        if !extra.is_empty() {
            body.extend(vint(extra.len() as u64));
        }
        if !data.is_empty() {
            body.extend(vint(data.len() as u64));
        }
        body.extend(fields);
        body.extend(extra);
        let mut header = vint(body.len() as u64);
        header.extend(body);
        let mut block = crc(&header).to_le_bytes().to_vec();
        block.extend(header);
        block.extend(data);
        block
    }

    /// A stored RAR5 holding the given (name, contents, locked) files.
    pub(crate) fn rar5_with(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut archive = RAR5.to_vec();
        archive.extend(rar5_block(1, 0, &vint(0), &[], &[]));
        for (name, contents, locked) in files {
            let mut fields = vint(0x04);
            fields.extend(vint(contents.len() as u64));
            fields.extend(vint(0x20));
            fields.extend(crc(contents).to_le_bytes());
            fields.extend(vint(0));
            fields.extend(vint(0));
            fields.extend(vint(name.len() as u64));
            fields.extend(name.as_bytes());
            let extra = if *locked {
                let mut record = vint(0x01);
                record.extend([0u8; 48]);
                let mut extra = vint(record.len() as u64);
                extra.extend(record);
                extra
            } else {
                Vec::new()
            };
            archive.extend(rar5_block(2, 0, &fields, &extra, contents));
        }
        archive.extend(rar5_block(5, 0, &vint(0), &[], &[]));
        archive
    }

    fn rar4_block(kind: u8, flags: u16, fields: &[u8]) -> Vec<u8> {
        let size = (7 + fields.len()) as u16;
        let mut header = vec![kind];
        header.extend(flags.to_le_bytes());
        header.extend(size.to_le_bytes());
        header.extend(fields);
        let mut block = ((crc(&header) & 0xffff) as u16).to_le_bytes().to_vec();
        block.extend(header);
        block
    }

    /// A stored RAR4 holding the given (name, contents) files.
    pub(crate) fn rar4_with(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = RAR4.to_vec();
        archive.extend(rar4_block(0x73, 0, &[0; 6]));
        for (name, contents) in files {
            let mut fields = Vec::new();
            fields.extend((contents.len() as u32).to_le_bytes());
            fields.extend((contents.len() as u32).to_le_bytes());
            fields.push(2);
            fields.extend(crc(contents).to_le_bytes());
            fields.extend(0u32.to_le_bytes());
            fields.extend([29, 0x30]);
            fields.extend((name.len() as u16).to_le_bytes());
            fields.extend(0x20u32.to_le_bytes());
            fields.extend(name.as_bytes());
            archive.extend(rar4_block(0x74, 0x8000, &fields));
            archive.extend(*contents);
        }
        archive.extend(rar4_block(0x7b, 0x4000, &[]));
        archive
    }

    #[test]
    fn lists_names_in_both_formats() {
        let names = ["វគ្គសិក្សា.pdf.exe", "readme.txt"];
        let rar5 = rar5_with(&[(names[0], b"MZ", false), (names[1], b"hi", false)]);
        let listed = entries(&rar5, 100).unwrap();
        assert_eq!(listed.names, names);
        assert!(!listed.encrypted);

        let rar4 = rar4_with(&[("invoice.pdf.lnk", b"L"), ("a.txt", b"")]);
        assert_eq!(
            entries(&rar4, 100).unwrap().names,
            ["invoice.pdf.lnk", "a.txt"]
        );
    }

    #[test]
    fn locked_files_and_broken_archives() {
        assert!(
            entries(&rar5_with(&[("a.exe", b"x", true)]), 100)
                .unwrap()
                .encrypted
        );
        let rar5 = rar5_with(&[("a.exe", b"x", false), ("b.exe", b"y", false)]);
        assert_eq!(entries(&rar5, 1).unwrap().names.len(), 1);
        for cut in 0..rar5.len() {
            entries(&rar5[..cut], 100);
        }
        assert!(entries(b"PK\x03\x04", 100).is_none());
    }

    #[test]
    fn a_block_claiming_endless_data_ends_the_list() {
        let mut archive = RAR5.to_vec();
        let mut body = vint(1);
        body.extend(vint(0x02));
        let end = RAR5.len() + 4 + 1 + 13;
        body.extend(vint((usize::MAX - end - 2) as u64));
        body.extend(vint(0));
        archive.extend([0; 4]);
        archive.extend(vint(body.len() as u64));
        archive.extend(body);
        assert_eq!(archive.len(), end);
        assert!(entries(&archive, 100).unwrap().names.is_empty());
    }
}
