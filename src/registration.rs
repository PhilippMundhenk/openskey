//! Building and sending the Scan-to-PC registration.
//!
//! The device keeps a PC in its "Scan to PC" menu for `DURATION` seconds after
//! an SNMPv1 set-request writes the registration string into OID
//! `1.3.6.1.4.1.2435.2.3.9.2.11.1.1.0` (one binding per function). We re-send
//! it before the lease expires. Each send uses a fresh UDP socket that is
//! dropped (closed) immediately, so there is no descriptor leak.

use crate::config::{Config, Function};
use crate::snmp;
use std::io;
use std::net::UdpSocket;
use std::time::Duration;

/// OID the registration strings are written to.
pub const REG_OID: [u32; 15] = [1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 11, 1, 1, 0];

/// Brother uses a constant request-id of 201; the device echoes it.
pub const REQUEST_ID: i64 = 201;

/// The registration value string for one function, e.g.
/// `TYPE=BR;BUTTON=SCAN;USER="Scanner";FUNC=IMAGE;HOST=10.0.30.10:54925;APPNUM=1;DURATION=360;BRID=;`
pub fn registration_string(cfg: &Config, func: Function) -> String {
    format!(
        "TYPE=BR;BUTTON=SCAN;USER=\"{user}\";FUNC={func};HOST={host}:{port};APPNUM={appnum};DURATION={duration};BRID=;",
        user = cfg.name,
        func = func.name(),
        host = cfg.host_ip,
        port = cfg.listen_port,
        appnum = func.appnum(),
        duration = cfg.duration,
    )
}

/// The full SNMPv1 set-request packet that registers all four functions.
pub fn build_registration(cfg: &Config) -> Vec<u8> {
    let varbinds: Vec<Vec<u8>> = Function::all()
        .iter()
        .map(|&f| {
            let value = snmp::octet_string(registration_string(cfg, f).as_bytes());
            snmp::varbind(&REG_OID, &value)
        })
        .collect();
    snmp::message(&cfg.community, snmp::TAG_SET_REQUEST, REQUEST_ID, &varbinds)
}

/// Send the registration once to `device_ip:161`. The socket is created and
/// dropped within this function; nothing is leaked even if the device never
/// answers.
pub fn register_once(cfg: &Config) -> io::Result<()> {
    if cfg.device_ip.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPADDRESS is not set",
        ));
    }
    if cfg.host_ip.is_empty() {
        // The device would get HOST=:54925 and have nowhere to send button
        // events (the silent-buttons case in issue #10). Refuse loudly.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HOST_IPADDRESS is not set; the device could not reach us",
        ));
    }
    let packet = build_registration(cfg);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.send_to(&packet, (cfg.device_ip.as_str(), cfg.device_port))?;
    // Read and discard the get-response if it comes; ignore a timeout.
    let mut buf = [0u8; 2048];
    let _ = socket.recv_from(&mut buf);
    Ok(())
    // `socket` is dropped here -> closed. No accumulation across calls.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::collections::BTreeMap;

    fn cfg() -> Config {
        Config {
            name: "NAS".into(),
            device_ip: "10.0.30.10".into(),
            device_port: 161,
            host_ip: "10.0.30.10".into(),
            community: "internal".into(),
            duration: 360,
            keepalive_interval: 120,
            listen_port: 54925,
            commands: BTreeMap::new(),
        }
    }

    #[test]
    fn registration_string_matches_capture() {
        let c = cfg();
        assert_eq!(
            registration_string(&c, Function::Image),
            "TYPE=BR;BUTTON=SCAN;USER=\"NAS\";FUNC=IMAGE;HOST=10.0.30.10:54925;APPNUM=1;DURATION=360;BRID=;"
        );
        assert_eq!(
            registration_string(&c, Function::File),
            "TYPE=BR;BUTTON=SCAN;USER=\"NAS\";FUNC=FILE;HOST=10.0.30.10:54925;APPNUM=5;DURATION=360;BRID=;"
        );
    }

    #[test]
    fn packet_decodes_to_four_bindings() {
        let c = cfg();
        let packet = build_registration(&c);
        let vbs = snmp::extract_string_varbinds(&packet);
        assert_eq!(vbs.len(), 4);
        for (oid, _) in &vbs {
            assert_eq!(oid, &REG_OID);
        }
        let funcs: Vec<&str> = vbs
            .iter()
            .map(|(_, s)| {
                let start = s.find("FUNC=").unwrap() + 5;
                let end = s[start..].find(';').unwrap() + start;
                &s[start..end]
            })
            .collect();
        assert_eq!(funcs, vec!["IMAGE", "EMAIL", "OCR", "FILE"]);
    }

    #[test]
    fn register_once_refuses_missing_addresses() {
        let mut c = cfg();
        c.device_ip.clear();
        let err = register_once(&c).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("IPADDRESS"));
        let mut c = cfg();
        c.host_ip.clear();
        let err = register_once(&c).unwrap_err();
        assert!(err.to_string().contains("HOST_IPADDRESS"));
    }

    #[test]
    fn register_once_reaches_the_mock_device() {
        let server = crate::mock::MockServer::start(false);
        let mut c = cfg();
        c.device_ip = "127.0.0.1".into();
        c.device_port = server.port;
        register_once(&c).unwrap();
        let state = server.stop();
        assert!(state.registered);
        assert_eq!(state.requests, 1);
    }

    #[test]
    fn register_once_without_an_answer_is_not_an_error() {
        let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let mut c = cfg();
        c.device_ip = "127.0.0.1".into();
        c.device_port = port;
        register_once(&c).unwrap();
    }
}
