//! mock-device: a stand-in Brother scanner for testing the daemon without
//! hardware, and for differential testing against the real `brscan-skey`.
//!
//! Default mode: bind UDP :161 (or `--port N`) as an SNMP agent that behaves
//! like an MFC-L2700DW: a registration set-request is decoded, printed and
//! answered, and flips the device into the "registered" state; get-requests
//! are answered from a canned table of the status objects `openskey status`
//! reads (the registration object answers `TRUE` only once a registration
//! was received, so `openskey selftest` is meaningful); an unknown object gets
//! SNMPv1 `noSuchName`, like a real agent. `--registered` starts registered,
//! `--run-seconds N` stops after N seconds.
//!
//! `--button FUNC [--host IP:PORT] [--params P1,P2,P3,P4]`: send a synthetic
//! button-press datagram (twice, same SEQ, like a real device) to a listening
//! daemon (default 127.0.0.1:54925).
//!
//! The logic is in the library (`mock.rs`); this file parses the arguments.

use openskey::config::Function;
use openskey::mock::{self, MockState};
use std::net::UdpSocket;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const USAGE: &str = "usage: mock-device [--port N] [--registered] [--run-seconds N]
       mock-device --button FUNC [--host IP:PORT] [--params P1,P2,P3,P4]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|p| args.get(p + 1))
}

fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }
    if let Some(func) = arg_value(args, "--button") {
        let func = Function::from_name(func).unwrap_or(Function::File);
        let host = arg_value(args, "--host")
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:54925".to_string());
        // --params P1,P2,P3,P4: the per-press option fields (default all 0,
        // which is what an MFC-L2700DW sends).
        let mut params = [0u32; 4];
        if let Some(list) = arg_value(args, "--params") {
            for (slot, value) in params.iter_mut().zip(list.split(',')) {
                *slot = value.trim().parse().unwrap_or(0);
            }
        }
        return match mock::send_button(func, &host, params) {
            Ok(()) => {
                println!(
                    "mock-device: sent {} button to {host} (twice, same SEQ)",
                    func.name()
                );
                0
            }
            Err(e) => {
                eprintln!("mock-device: cannot send the button to {host}: {e}");
                1
            }
        };
    }

    let port: u16 = match arg_value(args, "--port") {
        Some(value) => match value.parse() {
            Ok(port) => port,
            Err(_) => {
                eprintln!("mock-device: --port needs a port number, not {value:?}\n{USAGE}");
                return 2;
            }
        },
        None => 161,
    };
    let registered = args.iter().any(|a| a == "--registered");
    let run_seconds: Option<u64> = arg_value(args, "--run-seconds").and_then(|s| s.parse().ok());

    let socket = match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("mock-device: cannot bind UDP :{port}: {e}");
            return 1;
        }
    };
    println!("mock-device: SNMP agent on :{port} (Ctrl-C to stop)");
    let stop = AtomicBool::new(false);
    let deadline = run_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let mut state = MockState {
        registered,
        requests: 0,
    };
    if let Err(e) = mock::serve(&socket, &mut state, &stop, deadline, &mut |line| {
        println!("{line}")
    }) {
        eprintln!("mock-device: {e}");
        return 1;
    }
    println!("mock-device: done after {} request(s)", state.requests);
    0
}
