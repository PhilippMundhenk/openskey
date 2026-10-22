//! Parsing the button-press event the device sends to UDP port 54925.
//!
//! The datagram is a short binary header followed by an ASCII token string in
//! the same `TYPE=BR;...;USER="...";FUNC=...;APPNUM=...;` shape as the
//! registration. We locate the `TYPE=` marker (so we are robust to the exact
//! header bytes) and read the fields we care about. See PROTOCOL.md.

use crate::config::Function;

#[derive(Debug, PartialEq, Eq)]
pub struct ButtonEvent {
    pub type_field: String,
    pub user: String,
    pub func: Option<Function>,
    pub appnum: Option<u32>,
    /// The scan parameters the device included (everything after FUNC), passed
    /// through to the scan command, mirroring how brscan-skey hands them on.
    pub raw: String,
}

/// Parse a raw 54925 datagram. Returns None if it does not contain a token
/// string we recognise.
pub fn parse(datagram: &[u8]) -> Option<ButtonEvent> {
    let text = String::from_utf8_lossy(datagram);
    let start = text.find("TYPE=")?;
    let body = &text[start..];
    // Trim at the first NUL or control run, keep the printable token string.
    let body: String = body.chars().take_while(|c| *c != '\0').collect();

    let mut type_field = String::new();
    let mut user = String::new();
    let mut func = None;
    let mut appnum = None;

    for token in body.split(';') {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "TYPE" => type_field = value.to_string(),
            "USER" => user = value.to_string(),
            "FUNC" => func = Function::from_name(value),
            "APPNUM" => appnum = value.parse().ok(),
            _ => {}
        }
    }

    if type_field.is_empty() {
        return None;
    }
    Some(ButtonEvent {
        type_field,
        user,
        func,
        appnum,
        raw: body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_file_button_event() {
        // 4-byte header then the token string, as the device sends it.
        let mut dg = vec![0x00, 0x1b, 0x00, 0x71];
        dg.extend_from_slice(
            b"TYPE=BR;BUTTON=SCAN;USER=\"NAS\";FUNC=FILE;HOST=10.0.30.10:54925;APPNUM=5;DURATION=360;BRID=;",
        );
        let ev = parse(&dg).expect("should parse");
        assert_eq!(ev.type_field, "BR");
        assert_eq!(ev.user, "NAS");
        assert_eq!(ev.func, Some(Function::File));
        assert_eq!(ev.appnum, Some(5));
    }

    #[test]
    fn parses_image_with_scan_parameters() {
        let dg = b"\x00\x00\x00\x00TYPE=BR;USER=\"Scanner\";FUNC=IMAGE;APPNUM=1;R=300;M=CGRAY";
        let ev = parse(dg).expect("should parse");
        assert_eq!(ev.func, Some(Function::Image));
        assert!(ev.raw.contains("R=300"));
    }

    #[test]
    fn rejects_noise() {
        assert!(parse(b"\x01\x02\x03nonsense").is_none());
    }
}
