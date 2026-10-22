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
    /// `REGID` from the event: a registration id the device assigns, distinct
    /// per function.
    pub regid: Option<u64>,
    /// `SEQ` from the event: a per-press sequence number. The device sends each
    /// press more than once with the same SEQ, so it is the deduplication key.
    pub seq: Option<u64>,
    /// The full token string (incl. P1..P4 scan options), passed through to the
    /// scan command, mirroring how brscan-skey hands the parameters on.
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
    let mut regid = None;
    let mut seq = None;

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
            "REGID" => regid = value.parse().ok(),
            "SEQ" => seq = value.parse().ok(),
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
        regid,
        seq,
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
    fn parses_real_capture_from_a_scanner() {
        // Exact bytes captured from an MFC's "Scan to File" button (header
        // 02 00 7c 30 then the token string, including P1..P4/REGID/SEQ).
        let hex = "02007c30545950453d42523b425554544f4e3d5343414e3b555345523d226f70656e736b6579223b46554e433d46494c453b484f53543d3139322e3136382e34342e35383a35343932353b4150504e554d3d353b50313d303b50323d303b50333d303b50343d303b52454749443d36303631343b5345513d35363b";
        let dg: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let ev = parse(&dg).expect("should parse");
        assert_eq!(ev.type_field, "BR");
        assert_eq!(ev.user, "openskey");
        assert_eq!(ev.func, Some(Function::File));
        assert_eq!(ev.appnum, Some(5));
        assert_eq!(ev.regid, Some(60614));
        assert_eq!(ev.seq, Some(56));
    }

    #[test]
    fn rejects_noise() {
        assert!(parse(b"\x01\x02\x03nonsense").is_none());
    }
}
