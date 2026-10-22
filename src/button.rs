//! Parsing the button-press event the device sends to UDP port 54925.
//!
//! The datagram is a short binary header followed by an ASCII token string in
//! the same `TYPE=BR;...;USER="...";FUNC=...;APPNUM=...;` shape as the
//! registration. We locate the `TYPE=` marker (so we are robust to the exact
//! header bytes) and read the fields we care about. See PROTOCOL.md.

use crate::config::Function;
use crate::status::json_string;

/// One button press as the device reported it.
#[derive(Debug, PartialEq, Eq)]
pub struct ButtonEvent {
    /// `TYPE`, always `BR`.
    pub type_field: String,
    /// `USER`: the registered PC name the press was for.
    pub user: String,
    /// `FUNC`: the Scan-to-PC function pressed, when it is one we know.
    pub func: Option<Function>,
    /// `APPNUM`: the function's number as the device sent it.
    pub appnum: Option<u32>,
    /// `P1`..`P4`: the per-press option fields; `0` is "default".
    ///
    /// The device fills them from the shortcut that was pressed. An
    /// MFC-L2700DW sends all zeros (the stock daemon never decodes them
    /// either; the panel scan options a model may offer are read by the scan
    /// backend over TCP 54921). They are passed through so a script can use
    /// them if a model populates them.
    pub params: [Option<u32>; 4],
    /// `REGID` from the event: a registration id the device assigns, distinct
    /// per function.
    pub regid: Option<u64>,
    /// `SEQ` from the event: a per-press sequence number. The device sends each
    /// press more than once with the same SEQ, so it is the deduplication key.
    pub seq: Option<u64>,
    /// `CLIENT`: the address of the registered host as the device sees it;
    /// present in the stock daemon's own sample event, not in every capture.
    pub client: Option<String>,
    /// The full token string, passed through to the scan command, mirroring
    /// how brscan-skey hands the parameters on.
    pub raw: String,
}

impl ButtonEvent {
    /// The event as a JSON object, for scripts (`SKEY_EVENT`) and logs.
    #[must_use]
    pub fn to_json(&self) -> String {
        fn opt_u<T: ToString>(v: Option<&T>) -> String {
            v.map_or_else(|| "null".into(), std::string::ToString::to_string)
        }
        format!(
            concat!(
                "{{\"type\":{},\"user\":{},\"func\":{},\"appnum\":{},",
                "\"p1\":{},\"p2\":{},\"p3\":{},\"p4\":{},",
                "\"regid\":{},\"seq\":{},\"client\":{},\"raw\":{}}}"
            ),
            json_string(&self.type_field),
            json_string(&self.user),
            self.func
                .map_or_else(|| "null".into(), |f| json_string(f.name())),
            opt_u(self.appnum.as_ref()),
            opt_u(self.params[0].as_ref()),
            opt_u(self.params[1].as_ref()),
            opt_u(self.params[2].as_ref()),
            opt_u(self.params[3].as_ref()),
            opt_u(self.regid.as_ref()),
            opt_u(self.seq.as_ref()),
            self.client
                .as_ref()
                .map_or_else(|| "null".into(), |c| json_string(c)),
            json_string(&self.raw),
        )
    }
}

/// Parse a raw 54925 datagram. Returns None if it does not contain a token
/// string we recognise.
#[must_use]
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
    let mut params = [None; 4];
    let mut regid = None;
    let mut seq = None;
    let mut client = None;

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
            "P1" => params[0] = value.parse().ok(),
            "P2" => params[1] = value.parse().ok(),
            "P3" => params[2] = value.parse().ok(),
            "P4" => params[3] = value.parse().ok(),
            "REGID" => regid = value.parse().ok(),
            "SEQ" => seq = value.parse().ok(),
            "CLIENT" => client = Some(value.to_string()).filter(|v| !v.is_empty()),
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
        params,
        regid,
        seq,
        client,
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
        assert_eq!(ev.params, [None; 4]);
        assert_eq!(ev.client, None);
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
        assert_eq!(ev.params, [Some(0), Some(0), Some(0), Some(0)]);
        assert_eq!(ev.regid, Some(60614));
        assert_eq!(ev.seq, Some(56));
    }

    #[test]
    fn parses_the_stock_daemons_sample_event_with_client() {
        // The sample event embedded in Brother's own brscan-skey binary: it
        // ends in an empty token (";;") and a CLIENT field.
        let dg = b"t0TYPE=BR;BUTTON=SCAN;USER=\"idevd101\";FUNC=IMAGE;HOST=10.136.150.6:54925;APPNUM=1;P1=0;P2=0;P3=0;P4=0;REGID=756;SEQ=1;;CLIENT=10.136.41.234";
        let ev = parse(dg).expect("should parse");
        assert_eq!(ev.user, "idevd101");
        assert_eq!(ev.func, Some(Function::Image));
        assert_eq!(ev.regid, Some(756));
        assert_eq!(ev.seq, Some(1));
        assert_eq!(ev.client.as_deref(), Some("10.136.41.234"));
    }

    #[test]
    fn parses_non_default_params() {
        let dg = b"\x02\x00\x50\x30TYPE=BR;USER=\"x\";FUNC=OCR;APPNUM=3;P1=3;P2=1;P3=0;P4=2;REGID=1;SEQ=9;";
        let ev = parse(dg).expect("should parse");
        assert_eq!(ev.params, [Some(3), Some(1), Some(0), Some(2)]);
        let json = ev.to_json();
        assert!(json.contains("\"func\":\"OCR\""));
        assert!(json.contains("\"p1\":3,\"p2\":1,\"p3\":0,\"p4\":2"));
        assert!(json.contains("\"regid\":1,\"seq\":9,\"client\":null"));
        assert!(json.contains("\"user\":\"x\""));
    }

    #[test]
    fn rejects_noise() {
        assert!(parse(b"\x01\x02\x03nonsense").is_none());
    }
}
