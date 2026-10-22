//! mock-device: a stand-in Brother scanner for testing the daemon without
//! hardware, and for differential testing against the real `brscan-skey`.
//!
//! Default mode: bind UDP :161 as an SNMP agent, decode each registration
//! set-request, print the four function bindings, and echo a get-response. Run
//! the real `brscan-skey` or `openskey` against 127.0.0.1 and compare the output.
//!
//! `--button FUNC [--host IP:PORT]`: send a synthetic button-press datagram to a
//! listening daemon (default 127.0.0.1:54925), to exercise its event handling.

use openskey::config::Function;
use openskey::snmp;
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
        send_button(func, &host);
        return;
    }
    let port: u16 = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|p| args.get(p + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    agent(port);
}

fn agent(port: u16) {
    let socket = UdpSocket::bind(("0.0.0.0", port)).expect("bind SNMP port");
    println!("mock-device: SNMP agent on :{port} (Ctrl-C to stop)");
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = socket.recv_from(&mut buf).expect("recv");
        let bindings = snmp::extract_string_varbinds(&buf[..n]);
        if bindings.is_empty() {
            println!("mock-device: {n} bytes from {from}, not a string set-request");
            continue;
        }
        println!("mock-device: registration from {from}:");
        for (oid, value) in &bindings {
            let oid_s = oid.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".");
            println!("    {oid_s} = {value}");
        }
        // Echo a get-response with the same bindings so the client sees an ACK.
        let varbinds: Vec<Vec<u8>> = bindings
            .iter()
            .map(|(oid, value)| snmp::varbind(oid, &snmp::octet_string(value.as_bytes())))
            .collect();
        let response = snmp::message("internal", snmp::TAG_GET_RESPONSE, 201, &varbinds);
        let _ = socket.send_to(&response, from);
    }
}

fn send_button(func: &str, host: &str) {
    let func = Function::from_name(func).unwrap_or(Function::File);
    let mut datagram = vec![0x00, 0x1b, 0x00, 0x71]; // placeholder 4-byte header
    let body = format!(
        "TYPE=BR;BUTTON=SCAN;USER=\"Scanner\";FUNC={};HOST=127.0.0.1:54925;APPNUM={};DURATION=360;BRID=;",
        func.name(),
        func.appnum()
    );
    datagram.extend_from_slice(body.as_bytes());
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
    socket.send_to(&datagram, host).expect("send button");
    println!("mock-device: sent {} button to {host}", func.name());
}
