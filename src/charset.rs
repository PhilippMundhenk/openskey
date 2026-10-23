//! Text decoding for the device's string objects.
//!
//! SNMP `DisplayString`s are bytes; which character set they are in is up to
//! the agent. Brother devices keep the panel text in **HP Roman-8**, the
//! printer character set of the PCL era, and declare it through the Printer
//! MIB's `prtLocalizationCharacterSet` (`1.3.6.1.2.1.43.7.1.1.4.1.1`, an IANA
//! charset number; `hp-roman8` is 2004). A German MFC-L2700DW whose panel
//! shows `Scan:   drück` sends `64 72 CF 63 6B` for `drück`: `0xCF` is `ü` in
//! Roman-8. It would be `Ï` in Latin-1, and it is not valid UTF-8 at all,
//! which is how the line used to reach a dashboard as `dr\u{FFFD}ck`.
//!
//! Decoding: valid UTF-8 is taken as is (plain ASCII included, and devices
//! that send UTF-8 while declaring something else). Everything else is
//! decoded with the declared set, Roman-8 when the device declares none or
//! one this crate does not know.

/// A character set of the device's text objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Charset {
    /// UTF-8 (IANA 106).
    Utf8,
    /// ISO 8859-1 (IANA 4): one byte per character.
    Latin1,
    /// HP Roman-8 (IANA 2004): what Brother devices use.
    #[default]
    Roman8,
}

impl Charset {
    /// The set an agent declares in `prtLocalizationCharacterSet`, an IANA
    /// charset number. Numbers this crate does not know decode as Roman-8.
    #[must_use]
    pub const fn from_iana(code: i64) -> Self {
        match code {
            106 => Self::Utf8,
            4 => Self::Latin1,
            _ => Self::Roman8,
        }
    }

    /// The IANA name of the set.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Latin1 => "iso-8859-1",
            Self::Roman8 => "hp-roman8",
        }
    }

    /// Decode `bytes` to text. Valid UTF-8 passes through unchanged; a byte
    /// without a character in the set becomes U+FFFD.
    #[must_use]
    pub fn decode(self, bytes: &[u8]) -> String {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return text.to_string();
        }
        match self {
            Self::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Self::Latin1 => bytes.iter().map(|&b| char::from(b)).collect(),
            Self::Roman8 => bytes.iter().map(|&b| roman8_char(b)).collect(),
        }
    }
}

/// One HP Roman-8 byte as a character: ASCII below 0x80, the Roman-8 table
/// from 0xA0 to 0xFE, U+FFFD for the positions the set leaves undefined
/// (0x80 to 0x9F and 0xFF).
#[must_use]
pub fn roman8_char(byte: u8) -> char {
    match byte {
        0x00..=0x7F => char::from(byte),
        0xA0..=0xFE => ROMAN8_HIGH[usize::from(byte - 0xA0)],
        _ => '\u{FFFD}',
    }
}

/// HP Roman-8, bytes 0xA0 to 0xFE (the 1985 table), 16 per line from 0xA0.
#[rustfmt::skip]
const ROMAN8_HIGH: [char; 95] = [
    '\u{A0}', 'À', 'Â', 'È', 'Ê', 'Ë', 'Î', 'Ï', '´', '\u{2CB}', '\u{2C6}', '¨', '\u{2DC}', 'Ù', 'Û', '₤',
    '¯', 'Ý', 'ý', '°', 'Ç', 'ç', 'Ñ', 'ñ', '¡', '¿', '¤', '£', '¥', '§', 'ƒ', '¢',
    'â', 'ê', 'ô', 'û', 'á', 'é', 'ó', 'ú', 'à', 'è', 'ò', 'ù', 'ä', 'ë', 'ö', 'ü',
    'Å', 'î', 'Ø', 'Æ', 'å', 'í', 'ø', 'æ', 'Ä', 'ì', 'Ö', 'Ü', 'É', 'ï', 'ß', 'Ô',
    'Á', 'Ã', 'ã', 'Ð', 'ð', 'Í', 'Ì', 'Ó', 'Ò', 'Õ', 'õ', 'Š', 'š', 'Ú', 'Ÿ', 'ÿ',
    'Þ', 'þ', '·', 'µ', '¶', '¾', '\u{AD}', '¼', '½', 'ª', 'º', '«', '■', '»', '±',
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_utf8_passes_through_whatever_the_declared_set() {
        for set in [Charset::Utf8, Charset::Latin1, Charset::Roman8] {
            assert_eq!(set.decode("Scan:   drück".as_bytes()), "Scan:   drück");
            assert_eq!(set.decode(b"Ready"), "Ready");
            assert_eq!(set.decode(b""), "");
        }
    }

    #[test]
    fn the_real_l2700dw_display_bytes_decode_as_roman8() {
        // "Scan:   drück   " as the device sends it: 0xCF is ü in Roman-8
        let line = b"Scan:   dr\xCFck   ";
        assert_eq!(Charset::Roman8.decode(line), "Scan:   drück   ");
        assert_eq!(Charset::default().decode(line), "Scan:   drück   ");
        assert_eq!(
            Charset::Roman8.decode(b"\xCC\xCE\xCF\xD8\xDA\xDB\xDE"),
            "äöüÄÖÜß"
        );
    }

    #[test]
    fn latin1_is_one_byte_per_character() {
        assert_eq!(Charset::Latin1.decode(b"dr\xFCck"), "drück");
        // the same byte means something else in Latin-1 than in Roman-8
        assert_eq!(Charset::Latin1.decode(b"\xCF"), "Ï");
    }

    #[test]
    fn invalid_utf8_declared_as_utf8_is_replaced_not_dropped() {
        assert_eq!(Charset::Utf8.decode(b"dr\xFFck"), "dr\u{FFFD}ck");
    }

    #[test]
    fn roman8_leaves_its_undefined_positions_as_replacement_characters() {
        for byte in 0x80..=0x9F {
            assert_eq!(roman8_char(byte), '\u{FFFD}');
        }
        assert_eq!(roman8_char(0xFF), '\u{FFFD}');
        assert_eq!(roman8_char(0xA0), '\u{A0}');
        assert_eq!(roman8_char(0xFE), '±');
        assert_eq!(roman8_char(b'A'), 'A');
        // every defined position is a distinct character
        let mut seen = std::collections::BTreeSet::new();
        for byte in 0xA0..=0xFE {
            assert!(seen.insert(roman8_char(byte)), "{byte:#x} duplicated");
        }
    }

    #[test]
    fn iana_numbers_map_to_the_sets_brother_devices_declare() {
        assert_eq!(Charset::from_iana(2004), Charset::Roman8);
        assert_eq!(Charset::from_iana(106), Charset::Utf8);
        assert_eq!(Charset::from_iana(4), Charset::Latin1);
        for unknown in [0, 3, 5, 12, 2252, -1, i64::MAX] {
            assert_eq!(Charset::from_iana(unknown), Charset::Roman8);
        }
        assert_eq!(Charset::Roman8.name(), "hp-roman8");
        assert_eq!(Charset::Utf8.name(), "utf-8");
        assert_eq!(Charset::Latin1.name(), "iso-8859-1");
    }
}
