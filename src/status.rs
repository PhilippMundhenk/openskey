//! Scanner status over SNMP: the Scan-to-PC registration self-test, device
//! identity, the panel display line and the scanner capability flags.
//!
//! None of this exists in the stock `brscan-skey`. It reads Brother's private
//! MIB (enterprise arc `1.3.6.1.4.1.2435`), **scanner objects only**: this is
//! a scanner tool, so printer objects (toner, drum, page counters) are out of
//! scope on purpose. The objects were taken from a full walk of a live
//! MFC-L2700DW and named with the published BROTHER-MIB:
//!
//! - `brRegisterKeyInfo` (`...2.3.9.2.11.1.1.0`): the object the registration
//!   writes; reads back `TRUE` while the device lists a Scan-to-PC host.
//! - `mcsNetScanner` (`...2.3.9.2.101.3.11`): network scanning supported (.1)
//!   and enabled (.2).
//! - `mcsNetSKy` (`...2.3.9.2.101.3.12`): the network Scan Key, i.e. the
//!   Scan-to-PC button, supported (.1) and enabled (.2). This is the capability
//!   the stock daemon probes on every registration (and leaks a socket doing).
//!
//! Every field is optional: a model that lacks an object leaves it `null`.
//! Each query opens one UDP socket that is dropped when the query returns, so
//! a periodic poll cannot leak descriptors.

use crate::config::Config;
use crate::registration::REG_OID;
use crate::snmp::{self, Value};
use std::io;
use std::net::UdpSocket;
use std::time::Duration;

/// MIB-II sysDescr; a Brother device reports its model family here.
pub const OID_SYS_DESCR: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 1, 0];
/// Serial number (`brInfoSerialNumber`).
pub const OID_SERIAL: [u32; 17] = [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 4, 2, 1, 5, 5, 1, 0];
/// Firmware version.
pub const OID_FIRMWARE: [u32; 17] = [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 4, 2, 1, 5, 5, 17, 0];
/// The first line of the front-panel display.
pub const OID_DISPLAY: [u32; 16] = [1, 3, 6, 1, 4, 1, 2435, 2, 4, 3, 1240, 3, 2, 1, 5, 1];
/// `mcsNetScanner`: network scanning supported / enabled.
pub const OID_NET_SCANNER_SUPPORTED: [u32; 15] =
    [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 101, 3, 11, 1];
pub const OID_NET_SCANNER_ENABLED: [u32; 15] = [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 101, 3, 11, 2];
/// `mcsNetSKy`: the network Scan Key (Scan-to-PC button) supported / enabled.
pub const OID_SCAN_KEY_SUPPORTED: [u32; 15] = [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 101, 3, 12, 1];
pub const OID_SCAN_KEY_ENABLED: [u32; 15] = [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 101, 3, 12, 2];

/// Everything `openskey status` reports. Fields the device does not expose
/// stay `None` and serialise as `null`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub device_ip: String,
    /// The device answered at least one SNMP query.
    pub reachable: bool,
    /// Self-test: the registration object reads back `TRUE`, i.e. the device
    /// currently lists a Scan-to-PC host.
    pub registered: Option<bool>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    /// First line of the panel display, trimmed.
    pub display: Option<String>,
    pub net_scanner_supported: Option<bool>,
    pub net_scanner_enabled: Option<bool>,
    pub scan_key_supported: Option<bool>,
    pub scan_key_enabled: Option<bool>,
}

impl Status {
    /// Serialise as a JSON object (no dependencies, so hand-rolled).
    pub fn to_json(&self) -> String {
        fn s(v: &Option<String>) -> String {
            v.as_ref().map(|t| json_string(t)).unwrap_or("null".into())
        }
        fn b(v: &Option<bool>) -> String {
            v.map(|x| x.to_string()).unwrap_or("null".into())
        }
        format!(
            concat!(
                "{{",
                "\"device_ip\":{},",
                "\"reachable\":{},",
                "\"registered\":{},",
                "\"model\":{},",
                "\"serial\":{},",
                "\"firmware\":{},",
                "\"display\":{},",
                "\"net_scanner_supported\":{},",
                "\"net_scanner_enabled\":{},",
                "\"scan_key_supported\":{},",
                "\"scan_key_enabled\":{}",
                "}}"
            ),
            json_string(&self.device_ip),
            self.reachable,
            b(&self.registered),
            s(&self.model),
            s(&self.serial),
            s(&self.firmware),
            s(&self.display),
            b(&self.net_scanner_supported),
            b(&self.net_scanner_enabled),
            b(&self.scan_key_supported),
            b(&self.scan_key_enabled),
        )
    }
}

/// JSON string literal with the escapes JSON requires.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A reusable SNMP client bound to one socket for the duration of a query.
struct Client {
    socket: UdpSocket,
    target: (String, u16),
    community: String,
    next_id: i64,
}

impl Client {
    fn connect(cfg: &Config) -> io::Result<Client> {
        if cfg.device_ip.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPADDRESS is not set",
            ));
        }
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(1500)))?;
        Ok(Client {
            socket,
            target: (cfg.device_ip.clone(), cfg.device_port),
            community: cfg.community.clone(),
            next_id: 1000,
        })
    }

    /// GET one object. Each OID goes in its own request because SNMPv1 fails
    /// the whole request (noSuchName) when any one object is missing, and the
    /// set of objects a given model exposes varies.
    fn get(&mut self, oid: &[u32]) -> Option<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let pkt = snmp::get_request(&self.community, id, &[oid]);
        self.socket
            .send_to(&pkt, (self.target.0.as_str(), self.target.1))
            .ok()?;
        let mut buf = [0u8; 4096];
        // Skip stray datagrams that are not the answer to this request.
        for _ in 0..4 {
            let (n, _) = self.socket.recv_from(&mut buf).ok()?;
            let Some(msg) = snmp::decode_message(&buf[..n]) else {
                continue;
            };
            if msg.pdu_tag != snmp::TAG_GET_RESPONSE || msg.request_id != id {
                continue;
            }
            if msg.error_status != 0 {
                return None;
            }
            return msg
                .varbinds
                .into_iter()
                .find(|(o, _)| o == oid)
                .map(|(_, v)| v)
                .filter(|v| !matches!(v, Value::Null));
        }
        None
    }

    fn get_text(&mut self, oid: &[u32]) -> Option<String> {
        self.get(oid)
            .and_then(|v| v.as_text())
            .map(|t| {
                t.trim_matches(|c: char| c == '\0' || c.is_whitespace())
                    .to_string()
            })
            .filter(|t| !t.is_empty())
    }

    /// A capability flag: INTEGER 1 = yes, 0 = no.
    fn get_flag(&mut self, oid: &[u32]) -> Option<bool> {
        self.get(oid).and_then(|v| v.as_int()).map(|i| i != 0)
    }
}

/// Self-test: does the device currently report a Scan-to-PC registration?
/// Reads the same object the registration writes; a registered device answers
/// `TRUE`. `Ok(None)` means the device did not answer.
pub fn registered(cfg: &Config) -> io::Result<Option<bool>> {
    let mut client = Client::connect(cfg)?;
    Ok(client.get_text(&REG_OID).map(|t| is_true(&t)))
}

/// Query the full status. Never fails on a missing object; `reachable` is
/// false only if the device answered nothing at all.
pub fn query(cfg: &Config) -> io::Result<Status> {
    let mut client = Client::connect(cfg)?;
    let mut st = Status {
        device_ip: cfg.device_ip.clone(),
        ..Status::default()
    };
    st.registered = client.get_text(&REG_OID).map(|t| is_true(&t));
    st.model = client
        .get_text(&OID_SYS_DESCR)
        .map(|t| model_from_sys_descr(&t));
    st.serial = client.get_text(&OID_SERIAL);
    st.firmware = client.get_text(&OID_FIRMWARE);
    st.display = client.get_text(&OID_DISPLAY);
    st.net_scanner_supported = client.get_flag(&OID_NET_SCANNER_SUPPORTED);
    st.net_scanner_enabled = client.get_flag(&OID_NET_SCANNER_ENABLED);
    st.scan_key_supported = client.get_flag(&OID_SCAN_KEY_SUPPORTED);
    st.scan_key_enabled = client.get_flag(&OID_SCAN_KEY_ENABLED);
    st.reachable = st.registered.is_some()
        || st.model.is_some()
        || st.serial.is_some()
        || st.firmware.is_some()
        || st.display.is_some()
        || st.net_scanner_supported.is_some()
        || st.scan_key_supported.is_some();
    Ok(st)
}

/// The registration object's value, `TRUE` / `FALSE` (also accepts `1`/`0`).
pub fn is_true(text: &str) -> bool {
    let t = text.trim();
    t.eq_ignore_ascii_case("TRUE") || t == "1"
}

/// `"Brother MFC-L2700DW series"` -> `"MFC-L2700DW"`. Keeps the text as-is
/// when it does not look like that.
pub fn model_from_sys_descr(descr: &str) -> String {
    let t = descr.trim();
    let t = t.strip_prefix("Brother ").unwrap_or(t);
    let t = t.strip_suffix(" series").unwrap_or(t);
    t.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_is_extracted_from_sys_descr() {
        assert_eq!(
            model_from_sys_descr("Brother MFC-L2700DW series"),
            "MFC-L2700DW"
        );
        assert_eq!(model_from_sys_descr("Something else"), "Something else");
    }

    #[test]
    fn registration_flag_values() {
        assert!(is_true("TRUE"));
        assert!(is_true(" true "));
        assert!(is_true("1"));
        assert!(!is_true("FALSE"));
        assert!(!is_true(""));
    }

    #[test]
    fn json_has_every_field_and_escapes_strings() {
        let st = Status {
            device_ip: "10.0.0.5".into(),
            reachable: true,
            registered: Some(true),
            model: Some("MFC-L2700DW".into()),
            display: Some("Scan: \"drück\"".into()),
            scan_key_supported: Some(true),
            scan_key_enabled: Some(false),
            ..Status::default()
        };
        let j = st.to_json();
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains("\"device_ip\":\"10.0.0.5\""));
        assert!(j.contains("\"reachable\":true"));
        assert!(j.contains("\"registered\":true"));
        assert!(j.contains("\"display\":\"Scan: \\\"drück\\\"\""));
        assert!(j.contains("\"serial\":null"));
        assert!(j.contains("\"net_scanner_supported\":null"));
        assert!(j.contains("\"scan_key_supported\":true"));
        assert!(j.contains("\"scan_key_enabled\":false"));
        // no printer objects: this is a scanner tool
        assert!(!j.contains("toner") && !j.contains("drum") && !j.contains("page"));
    }

    #[test]
    fn json_string_escapes_control_characters() {
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
        assert_eq!(json_string("x\\y"), "\"x\\\\y\"");
    }

    #[test]
    fn capability_oids_are_under_mfp_capability_scanner() {
        let prefix = [1u32, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 101, 3];
        for oid in [
            &OID_NET_SCANNER_SUPPORTED,
            &OID_NET_SCANNER_ENABLED,
            &OID_SCAN_KEY_SUPPORTED,
            &OID_SCAN_KEY_ENABLED,
        ] {
            assert_eq!(&oid[..13], &prefix[..]);
        }
        assert_eq!(OID_NET_SCANNER_SUPPORTED[13..], [11, 1]);
        assert_eq!(OID_SCAN_KEY_ENABLED[13..], [12, 2]);
    }
}
