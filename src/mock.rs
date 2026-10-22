//! The mock device: a stand-in Brother scanner that answers the SNMP
//! registration and the status objects like a real MFC-L2700DW and can send
//! button events. Used by the `mock-device` binary, the tests of this crate,
//! and the container's end-to-end tests.

use crate::config::Function;
use crate::registration::REG_OID;
use crate::snmp::{self, Value};
use crate::status;
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What the mock device remembers between requests.
#[derive(Debug, Clone, Default)]
pub struct MockState {
    /// A registration set-request was received, so the registration object
    /// answers `TRUE` (what `openskey selftest` reads).
    pub registered: bool,
    pub requests: usize,
}

/// What one datagram turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    /// A registration set-request with these (OID, string) bindings.
    Registration(Vec<(Vec<u32>, String)>),
    /// A get-request: how many objects were known and how many missing.
    Get { known: usize, missing: usize },
    /// A set-request without string bindings (not a registration).
    NotAStringSet,
    /// Some other PDU type.
    Unsupported(u8),
    /// Not an SNMP message at all.
    NotSnmp,
}

/// Mirror of a real MFC-L2700DW's status objects.
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
    // Capability flags exactly as the live device answers them: network
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

/// Handle one datagram: classify it, update the state, and build the
/// response (None when nothing is sent back).
pub fn handle(datagram: &[u8], state: &mut MockState) -> (Handled, Option<Vec<u8>>) {
    state.requests += 1;
    let Some(msg) = snmp::decode_message(datagram) else {
        return (Handled::NotSnmp, None);
    };
    match msg.pdu_tag {
        snmp::TAG_SET_REQUEST => {
            let strings: Vec<(Vec<u32>, String)> = msg
                .varbinds
                .iter()
                .filter_map(|(o, v)| v.as_text().map(|s| (o.clone(), s)))
                .collect();
            if strings.is_empty() {
                return (Handled::NotAStringSet, None);
            }
            state.registered = true;
            // Echo a get-response with the same bindings, as a device does.
            let varbinds: Vec<Vec<u8>> = msg
                .varbinds
                .iter()
                .map(|(o, v)| snmp::varbind(o, &snmp::encode_value(v)))
                .collect();
            let response = snmp::message(
                &msg.community,
                snmp::TAG_GET_RESPONSE,
                msg.request_id,
                &varbinds,
            );
            (Handled::Registration(strings), Some(response))
        }
        snmp::TAG_GET_REQUEST => {
            let mut varbinds = Vec::new();
            let mut known = 0;
            let mut first_missing: Option<usize> = None;
            for (i, (oid, _)) in msg.varbinds.iter().enumerate() {
                match canned(oid, state.registered) {
                    Some(v) => {
                        known += 1;
                        varbinds.push(snmp::varbind(oid, &snmp::encode_value(&v)));
                    }
                    None => {
                        first_missing.get_or_insert(i + 1);
                        varbinds.push(snmp::varbind(oid, &snmp::null()));
                    }
                }
            }
            let missing = msg.varbinds.len() - known;
            let response = match first_missing {
                // SNMPv1: any missing object fails the whole request.
                Some(index) => snmp::message_with_error(
                    &msg.community,
                    snmp::TAG_GET_RESPONSE,
                    msg.request_id,
                    snmp::ERR_NO_SUCH_NAME,
                    index as i64,
                    &varbinds,
                ),
                None => snmp::message(
                    &msg.community,
                    snmp::TAG_GET_RESPONSE,
                    msg.request_id,
                    &varbinds,
                ),
            };
            (Handled::Get { known, missing }, Some(response))
        }
        other => (Handled::Unsupported(other), None),
    }
}

/// A line of log output for one handled datagram.
pub fn describe(handled: &Handled, from: &str, bytes: usize) -> String {
    match handled {
        Handled::Registration(bindings) => {
            let mut out = format!("mock-device: registration from {from}:");
            for (oid, value) in bindings {
                let oid_s = oid
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(".");
                out.push_str(&format!("\n    {oid_s} = {value}"));
            }
            out
        }
        Handled::Get { known, missing } => {
            format!("mock-device: get from {from}: {known} known, {missing} missing (noSuchName)")
        }
        Handled::NotAStringSet => {
            format!("mock-device: {bytes} bytes from {from}, not a string set-request")
        }
        Handled::Unsupported(tag) => {
            format!("mock-device: PDU 0x{tag:02x} from {from} not supported")
        }
        Handled::NotSnmp => format!("mock-device: {bytes} bytes from {from}, not an SNMP message"),
    }
}

/// Serve as an SNMP agent on `socket` until `stop` is set or `deadline`
/// passes (None: forever). Every handled datagram is reported through `log`.
pub fn serve(
    socket: &UdpSocket,
    state: &mut MockState,
    stop: &AtomicBool,
    deadline: Option<Instant>,
    log: &mut dyn FnMut(String),
) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) || deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(());
        }
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let (handled, response) = handle(&buf[..n], state);
        log(describe(&handled, &from.to_string(), n));
        if let Some(bytes) = response {
            let _ = socket.send_to(&bytes, from);
        }
    }
}

/// A button-press datagram as a real device sends it: the 4-byte header
/// `02 00 LL 30` (LL = datagram length + 1) and the token string.
pub fn button_datagram(func: Function, params: [u32; 4]) -> Vec<u8> {
    let body = format!(
        "TYPE=BR;BUTTON=SCAN;USER=\"Scanner\";FUNC={};HOST=127.0.0.1:54925;APPNUM={};P1={};P2={};P3={};P4={};REGID=60614;SEQ=56;",
        func.name(),
        func.appnum(),
        params[0],
        params[1],
        params[2],
        params[3]
    );
    let ll = (4 + body.len() + 1) as u8;
    let mut datagram = vec![0x02, 0x00, ll, 0x30];
    datagram.extend_from_slice(body.as_bytes());
    datagram
}

/// Send a button press to a listening daemon, twice with the same SEQ like a
/// real device (which always resends once, about two seconds later), then
/// listen briefly. A real device expects **nothing** back (Brother's daemon
/// sends nothing, PROTOCOL.md), so the result says whether the daemon wrongly
/// answered: `Ok(true)` means something came back.
pub fn send_button(func: Function, host: &str, params: [u32; 4]) -> io::Result<bool> {
    let datagram = button_datagram(func, params);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    for _ in 0..2 {
        socket.send_to(&datagram, host)?;
    }
    socket.set_read_timeout(Some(Duration::from_millis(400)))?;
    let mut buf = [0u8; 2048];
    Ok(socket.recv_from(&mut buf).is_ok())
}

/// A mock device serving on an ephemeral localhost port in a thread, for
/// tests. Stops and joins when dropped.
pub struct MockServer {
    pub port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<MockState>>,
}

impl MockServer {
    pub fn start(registered: bool) -> MockServer {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = socket.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut state = MockState {
                registered,
                requests: 0,
            };
            let _ = serve(&socket, &mut state, &stop_thread, None, &mut |_| {});
            state
        });
        MockServer {
            port,
            stop,
            thread: Some(thread),
        }
    }

    /// Stop serving and return the final state.
    pub fn stop(mut self) -> MockState {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::button;
    use crate::config::Config;
    use crate::registration;

    #[test]
    fn registration_flips_the_state_and_is_echoed() {
        let cfg = Config::from_lookup(|k| match k {
            "IPADDRESS" => Some("127.0.0.1".into()),
            "HOST_IPADDRESS" => Some("10.0.0.2".into()),
            _ => None,
        });
        let packet = registration::build_registration(&cfg);
        let mut state = MockState::default();
        let (handled, response) = handle(&packet, &mut state);
        assert!(state.registered);
        assert_eq!(state.requests, 1);
        let Handled::Registration(bindings) = &handled else {
            panic!("not a registration: {handled:?}");
        };
        assert_eq!(bindings.len(), 4);
        assert!(bindings[0].1.contains("FUNC=IMAGE"));
        let echoed = snmp::decode_message(&response.unwrap()).unwrap();
        assert_eq!(echoed.pdu_tag, snmp::TAG_GET_RESPONSE);
        assert_eq!(echoed.request_id, registration::REQUEST_ID);
        assert_eq!(echoed.varbinds.len(), 4);
        assert!(describe(&handled, "1.2.3.4:5", packet.len()).contains("FUNC=FILE"));
    }

    #[test]
    fn get_answers_known_objects_and_no_such_name_for_unknown() {
        let mut state = MockState::default();
        let known = snmp::get_request("internal", 5, &[&status::OID_SYS_DESCR, &REG_OID]);
        let (handled, response) = handle(&known, &mut state);
        assert_eq!(
            handled,
            Handled::Get {
                known: 2,
                missing: 0
            }
        );
        let msg = snmp::decode_message(&response.unwrap()).unwrap();
        assert_eq!(msg.error_status, 0);
        assert_eq!(msg.varbinds[1].1.as_text().as_deref(), Some("FALSE"));
        state.registered = true;
        let (_, response) = handle(&known, &mut state);
        let msg = snmp::decode_message(&response.unwrap()).unwrap();
        assert_eq!(msg.varbinds[1].1.as_text().as_deref(), Some("TRUE"));

        let unknown: &[u32] = &[1, 3, 6, 1, 4, 1, 2435, 9, 9, 9];
        let mixed = snmp::get_request("internal", 6, &[&status::OID_SERIAL, unknown]);
        let (handled, response) = handle(&mixed, &mut state);
        assert_eq!(
            handled,
            Handled::Get {
                known: 1,
                missing: 1
            }
        );
        let msg = snmp::decode_message(&response.unwrap()).unwrap();
        assert_eq!(msg.error_status, snmp::ERR_NO_SUCH_NAME);
        assert!(describe(&handled, "x", 0).contains("1 missing"));
    }

    #[test]
    fn other_input_is_classified_without_a_response() {
        let mut state = MockState::default();
        assert_eq!(
            handle(b"\x01\x02junk", &mut state),
            (Handled::NotSnmp, None)
        );
        let next = snmp::message("internal", 0xA1, 1, &[]);
        assert_eq!(
            handle(&next, &mut state),
            (Handled::Unsupported(0xA1), None)
        );
        let set_int = snmp::message(
            "internal",
            snmp::TAG_SET_REQUEST,
            1,
            &[snmp::varbind(&REG_OID, &snmp::integer(1))],
        );
        assert_eq!(handle(&set_int, &mut state), (Handled::NotAStringSet, None));
        assert!(!state.registered);
        assert_eq!(state.requests, 3);
        assert!(describe(&Handled::NotSnmp, "a", 4).contains("not an SNMP"));
        assert!(describe(&Handled::Unsupported(0xA1), "a", 4).contains("0xa1"));
        assert!(describe(&Handled::NotAStringSet, "a", 4).contains("string set"));
    }

    #[test]
    fn button_datagram_has_the_device_header_and_parses() {
        let dg = button_datagram(Function::Ocr, [3, 1, 0, 2]);
        assert_eq!(&dg[..2], &[0x02, 0x00]);
        assert_eq!(dg[3], 0x30);
        assert_eq!(dg[2] as usize, dg.len() + 1);
        let ev = button::parse(&dg).unwrap();
        assert_eq!(ev.func, Some(Function::Ocr));
        assert_eq!(ev.params, [Some(3), Some(1), Some(0), Some(2)]);
        assert_eq!(ev.seq, Some(56));
    }

    #[test]
    fn send_button_delivers_the_datagram_twice() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let host = listener.local_addr().unwrap().to_string();
        // a correct daemon answers nothing: delivered twice, nothing came back
        assert!(!send_button(Function::File, &host, [0; 4]).unwrap());
        let mut buf = [0u8; 512];
        let (n1, _) = listener.recv_from(&mut buf).unwrap();
        let first = buf[..n1].to_vec();
        let (n2, _) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(first, buf[..n2]);
        assert!(button::parse(&first).is_some());
    }

    #[test]
    fn send_button_reports_a_daemon_that_wrongly_answers() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let host = listener.local_addr().unwrap().to_string();
        // a daemon that echoes the event back: not what a device expects
        let echo = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = listener.recv_from(&mut buf).unwrap();
            listener.send_to(&buf[..n], from).unwrap();
        });
        assert!(send_button(Function::Ocr, &host, [0; 4]).unwrap());
        echo.join().unwrap();
    }

    #[test]
    fn server_answers_over_udp_and_reports_its_state() {
        let server = MockServer::start(false);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let req = snmp::get_request("internal", 9, &[&status::OID_FIRMWARE]);
        socket.send_to(&req, ("127.0.0.1", server.port)).unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = socket.recv_from(&mut buf).unwrap();
        let msg = snmp::decode_message(&buf[..n]).unwrap();
        assert_eq!(msg.varbinds[0].1.as_text().as_deref(), Some("Y2309112149"));
        let state = server.stop();
        assert_eq!(state.requests, 1);
        assert!(!state.registered);
    }

    #[test]
    fn serve_stops_at_the_deadline_and_logs() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(b"junk", ("127.0.0.1", port)).unwrap();
        let mut lines = Vec::new();
        let stop = AtomicBool::new(false);
        let mut state = MockState::default();
        let deadline = Instant::now() + Duration::from_millis(600);
        serve(&socket, &mut state, &stop, Some(deadline), &mut |l| {
            lines.push(l)
        })
        .unwrap();
        assert!(Instant::now() >= deadline);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("not an SNMP message"));
    }
}
