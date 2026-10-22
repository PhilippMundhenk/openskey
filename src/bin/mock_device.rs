//! mock-device: a stand-in Brother scanner for testing the daemon without
//! hardware, and for differential testing against the real `brscan-skey`.
//!
//! Default mode: bind UDP :161 (or `--port N`) as an SNMP agent that behaves
//! like an MFC-L2700DW:
//!
//! - a registration set-request is decoded and printed (the four function
//!   bindings), answered with a get-response, and flips the device into the
//!   "registered" state;
//! - get-requests are answered from a canned table of the status objects
//!   `openskey status` reads (identity, panel line, the packed `brInfo*`
//!   blobs). The registration object answers `TRUE` only once a registration
//!   was received, so `openskey selftest` is meaningful against the mock;
//! - an unknown object gets SNMPv1 `noSuchName`, like a real agent.
//!
//! `--button FUNC [--host IP:PORT]`: send a synthetic button-press datagram to a
//! listening daemon (default 127.0.0.1:54925), to exercise its event handling.
//! `--registered`: start in the registered state.

use openskey::config::Function;
use openskey::registration::REG_OID;
use openskey::snmp::{self, Value};
use openskey::status;
use std::net::UdpSocket;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--button") {
        let func = args.get(pos + 1).map(String::as_str).unwrap_or("FILE");
        let host = args
            .iter()
            .position(|a| a == "--host")
            .and_then(|p| args.get(p + 1))
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:54925".to_string());
        // --params P1,P2,P3,P4: the per-press option fields (default all 0,
        // which is what an MFC-L2700DW sends).
        let params: Vec<u32> = args
            .iter()
            .position(|a| a == "--params")
            .and_then(|p| args.get(p + 1))
            .map(|s| s.split(',').filter_map(|v| v.trim().parse().ok()).collect())
            .unwrap_or_default();
        let mut p = [0u32; 4];
        for (i, v) in params.iter().take(4).enumerate() {
            p[i] = *v;
        }
        send_button(func, &host, p);
        return;
    }
    let port: u16 = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|p| args.get(p + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let registered = args.iter().any(|a| a == "--registered");
    agent(port, registered);
}

/// Mirror of a real MFC-L2700DW's status objects, including the packed
/// record format and the three-byte `FF FF FF` separators a device inserts.
pub fn canned(oid: &[u32], registered: bool) -> Option<Value> {
    let text = |s: &str| Some(Value::OctetString(s.as_bytes().to_vec()));
    if oid == REG_OID {
        return text(if registered { "TRUE" } else { "FALSE" });
    }
    if oid == status::OID_SYS_DESCR {
        return text("Brother MFC-L2700DW series");
    }
    if oid == status::OID_SERIAL {
        return text("E73941F6N621420");
    }
    if oid == status::OID_FIRMWARE {
        return text("Y2309112149");
    }
    if oid == status::OID_DISPLAY {
        return text("Scan:   drück   ");
    }
    // Capability flags exactly as the live MFC-L2700DW answers them: network
    // scanning and the network Scan Key both supported (.1) and enabled (.2).
    if oid == status::OID_NET_SCANNER_SUPPORTED
        || oid == status::OID_NET_SCANNER_ENABLED
        || oid == status::OID_SCAN_KEY_SUPPORTED
        || oid == status::OID_SCAN_KEY_ENABLED
    {
        return Some(Value::Int(1));
    }
    None
}

fn oid_string(oid: &[u32]) -> String {
    oid.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn agent(port: u16, mut registered: bool) {
    let socket = UdpSocket::bind(("0.0.0.0", port)).expect("bind SNMP port");
    println!("mock-device: SNMP agent on :{port} (Ctrl-C to stop)");
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = socket.recv_from(&mut buf).expect("recv");
        let Some(msg) = snmp::decode_message(&buf[..n]) else {
            println!("mock-device: {n} bytes from {from}, not an SNMP message");
            continue;
        };
        let response = match msg.pdu_tag {
            snmp::TAG_SET_REQUEST => {
                let strings: Vec<(&Vec<u32>, String)> = msg
                    .varbinds
                    .iter()
                    .filter_map(|(o, v)| v.as_text().map(|s| (o, s)))
                    .collect();
                if strings.is_empty() {
                    println!("mock-device: {n} bytes from {from}, not a string set-request");
                    continue;
                }
                println!("mock-device: registration from {from}:");
                for (oid, value) in &strings {
                    println!("    {} = {value}", oid_string(oid));
                }
                registered = true;
                // Echo a get-response with the same bindings so the client sees an ACK.
                let varbinds: Vec<Vec<u8>> = msg
                    .varbinds
                    .iter()
                    .map(|(o, v)| snmp::varbind(o, &snmp::encode_value(v)))
                    .collect();
                snmp::message(
                    &msg.community,
                    snmp::TAG_GET_RESPONSE,
                    msg.request_id,
                    &varbinds,
                )
            }
            snmp::TAG_GET_REQUEST => {
                let mut varbinds = Vec::new();
                let mut missing: Option<usize> = None;
                for (i, (oid, _)) in msg.varbinds.iter().enumerate() {
                    match canned(oid, registered) {
                        Some(v) => varbinds.push(snmp::varbind(oid, &snmp::encode_value(&v))),
                        None => {
                            println!("mock-device: get {} -> noSuchName", oid_string(oid));
                            missing.get_or_insert(i + 1);
                            varbinds.push(snmp::varbind(oid, &snmp::null()));
                        }
                    }
                }
                match missing {
                    Some(index) => snmp::message_with_error(
                        &msg.community,
                        snmp::TAG_GET_RESPONSE,
                        msg.request_id,
                        snmp::ERR_NO_SUCH_NAME,
                        index as i64,
                        &varbinds,
                    ),
                    None => {
                        for (oid, _) in &msg.varbinds {
                            println!("mock-device: get {} -> ok", oid_string(oid));
                        }
                        snmp::message(
                            &msg.community,
                            snmp::TAG_GET_RESPONSE,
                            msg.request_id,
                            &varbinds,
                        )
                    }
                }
            }
            other => {
                println!("mock-device: PDU 0x{other:02x} from {from} not supported");
                continue;
            }
        };
        let _ = socket.send_to(&response, from);
    }
}

fn send_button(func: &str, host: &str, p: [u32; 4]) {
    let func = Function::from_name(func).unwrap_or(Function::File);
    let body = format!(
        "TYPE=BR;BUTTON=SCAN;USER=\"Scanner\";FUNC={};HOST=127.0.0.1:54925;APPNUM={};P1={};P2={};P3={};P4={};REGID=60614;SEQ=56;",
        func.name(),
        func.appnum(),
        p[0],
        p[1],
        p[2],
        p[3]
    );
    // 4-byte header `02 00 LL 30`, LL = datagram length + 1, as a real device sends.
    let ll = (4 + body.len() + 1) as u8;
    let mut datagram = vec![0x02, 0x00, ll, 0x30];
    datagram.extend_from_slice(body.as_bytes());

    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
    // The device resends the same SEQ; send twice so dedup is exercised.
    for _ in 0..2 {
        socket.send_to(&datagram, host).expect("send button");
    }
    println!(
        "mock-device: sent {} button to {host} (twice, same SEQ)",
        func.name()
    );
}
