//! openskey: an open, leak-free reimplementation of Brother's `brscan-skey`
//! Scan-to-PC key daemon.
//!
//! It registers this host with the scanner so the device shows the Scan-to-PC
//! menu, refreshes that registration before its lease expires (without the
//! socket leak of the original, see BrotherScannerDocker #179/#186), verifies
//! the registration by reading it back, listens for button presses on UDP
//! 54925, and runs the configured scan command.
//!
//! Beyond the original it also exposes the device's status (`openskey status`)
//! and a registration self-test (`openskey selftest`), see `status.rs`.
//!
//! Threads are independent: the keepalive never blocks on a scan, and each scan
//! runs in its own thread, so a long scan cannot delay re-registration.

use openskey::button;
use openskey::config::Config;
use openskey::registration;
use openskey::status;
use std::collections::VecDeque;
use std::net::UdpSocket;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

/// The device resends each button press (same SEQ) until the scan starts; drop
/// a repeat of the same (REGID, SEQ) seen within this window so it scans once.
const DEDUP_WINDOW: Duration = Duration::from_secs(20);

const USAGE: &str = "usage: openskey [status|selftest|help]

  (no command)  run the Scan-to-PC daemon
  status        print the device status as JSON and exit
                (exit 0 if the device answered, 2 if not)
  selftest      check the device reports a Scan-to-PC registration
                (exit 0 registered, 1 not registered, 2 no answer)

Configuration is taken from the environment: NAME, IPADDRESS, HOST_IPADDRESS,
KEEPALIVE_INTERVAL, SKEY_DEVICE_PORT, SKEY_COMMUNITY, SKEY_SELFTEST,
SKEY_IMAGE / SKEY_EMAIL / SKEY_OCR / SKEY_FILE (scan commands).";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => run_daemon(),
        Some("status") => run_status(),
        Some("selftest") => run_selftest(),
        Some("help") | Some("--help") | Some("-h") => println!("{USAGE}"),
        Some(other) => {
            eprintln!("openskey: unknown command {other:?}\n{USAGE}");
            std::process::exit(2);
        }
    }
}

fn run_status() {
    let cfg = Config::from_env();
    match status::query(&cfg) {
        Ok(st) => {
            println!("{}", st.to_json());
            if !st.reachable {
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("openskey: status failed: {e}");
            std::process::exit(2);
        }
    }
}

fn run_selftest() {
    let cfg = Config::from_env();
    match status::registered(&cfg) {
        Ok(Some(true)) => {
            println!("openskey: selftest OK, device reports a Scan-to-PC registration")
        }
        Ok(Some(false)) => {
            println!("openskey: selftest FAILED, device reports no Scan-to-PC registration");
            std::process::exit(1);
        }
        Ok(None) => {
            eprintln!("openskey: selftest: no answer from {}", cfg.device_ip);
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("openskey: selftest failed: {e}");
            std::process::exit(2);
        }
    }
}

fn run_daemon() {
    let cfg = Config::from_env();
    println!(
        "openskey starting: name={:?} device={} host={} listen=:{} keepalive={}s duration={}s",
        cfg.name, cfg.device_ip, cfg.host_ip, cfg.listen_port, cfg.keepalive_interval, cfg.duration
    );

    // Keepalive thread: register now, then re-register before each lease lapses.
    {
        let cfg = cfg.clone();
        thread::spawn(move || keepalive_loop(cfg));
    }

    // Button listener on 54925.
    match UdpSocket::bind(("0.0.0.0", cfg.listen_port)) {
        Ok(socket) => listen_loop(&cfg, socket),
        Err(e) => {
            eprintln!("openskey: cannot bind UDP :{}: {e}", cfg.listen_port);
            std::process::exit(1);
        }
    }
}

fn selftest_enabled() -> bool {
    std::env::var("SKEY_SELFTEST")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

fn keepalive_loop(cfg: Config) {
    let verify = selftest_enabled();
    loop {
        match registration::register_once(&cfg) {
            Ok(()) => {
                println!("openskey: registered Scan-to-PC for {:?}", cfg.name);
                // Self-test: read the registration object back. A device that
                // accepted us answers TRUE; anything else means the panel will
                // not show the Scan-to-PC entry, and we say so loudly.
                if verify {
                    match status::registered(&cfg) {
                        Ok(Some(true)) => println!("openskey: registration verified"),
                        Ok(Some(false)) => {
                            eprintln!("openskey: WARNING: device reports no registration after we registered")
                        }
                        Ok(None) => eprintln!("openskey: registration not verifiable (no answer)"),
                        Err(e) => eprintln!("openskey: registration check failed: {e}"),
                    }
                }
            }
            Err(e) => eprintln!("openskey: registration failed: {e}"),
        }
        thread::sleep(Duration::from_secs(cfg.keepalive_interval.max(1) as u64));
    }
}

fn listen_loop(cfg: &Config, socket: UdpSocket) {
    println!(
        "openskey: listening for button events on :{}",
        cfg.listen_port
    );
    let mut buf = [0u8; 2048];
    let mut recent: VecDeque<((u64, u64), Instant)> = VecDeque::new();
    loop {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("openskey: recv error: {e}");
                continue;
            }
        };
        let datagram = &buf[..n];
        let header: Vec<String> = datagram[..n.min(4)]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // Full-datagram capture: always for unrecognised packets, and for every
        // packet when SKEY_DEBUG is set. Paste these when characterising a real
        // scanner's button events (see README "Capturing from a real scanner").
        let debug = std::env::var("SKEY_DEBUG")
            .map(|v| v != "0" && !v.is_empty())
            .unwrap_or(false);
        match button::parse(datagram) {
            Some(ev) => {
                println!(
                    "openskey: button from {from}: header[{}] FUNC={:?} APPNUM={:?}",
                    header.join(" "),
                    ev.func,
                    ev.appnum
                );
                if debug {
                    println!(
                        "openskey: CAPTURE {n} bytes from {from}: {}",
                        hex_dump(datagram)
                    );
                }
                // Deduplicate the device's resends by (REGID, SEQ).
                if let Some(seq) = ev.seq {
                    let key = (ev.regid.unwrap_or(0), seq);
                    let now = Instant::now();
                    while recent.front().is_some_and(|&(_, t)| now - t > DEDUP_WINDOW) {
                        recent.pop_front();
                    }
                    if recent.iter().any(|&(k, _)| k == key) {
                        println!("openskey: duplicate event (SEQ={seq}) ignored");
                        continue;
                    }
                    recent.push_back((key, now));
                }
                dispatch(cfg, ev);
            }
            None => {
                eprintln!("openskey: unrecognised datagram from {from} ({n} bytes)");
                eprintln!(
                    "openskey: CAPTURE {n} bytes from {from}: {}",
                    hex_dump(datagram)
                );
            }
        }
    }
}

/// Render a datagram as contiguous hex plus a printable-ASCII view, for
/// capturing a real device's button events.
fn hex_dump(data: &[u8]) -> String {
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    let ascii: String = data
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{hex} | {ascii}")
}

fn dispatch(cfg: &Config, ev: button::ButtonEvent) {
    let Some(func) = ev.func else {
        eprintln!("openskey: event without a known FUNC, ignored");
        return;
    };
    let Some(command) = cfg.commands.get(func.name()).cloned() else {
        eprintln!("openskey: no command configured for {}", func.name());
        return;
    };
    let device = "brother4:net1;dev0".to_string(); // the SANE device name scanimage uses
    let name = cfg.name.clone();
    let func_name = func.name().to_string();
    let appnum = ev.appnum.unwrap_or(func.appnum());
    let event_json = ev.to_json();

    // Run each scan in its own thread and wait on the child there, so the
    // listener keeps serving and no zombie is left behind. Everything the
    // device sent is handed to the script in the environment: the raw token
    // string (SKEY_PARAMS), the per-press option fields P1..P4 (SKEY_P1..4),
    // REGID/SEQ/CLIENT, and the whole event as JSON (SKEY_EVENT).
    thread::spawn(move || {
        println!("openskey: running {} for {}", command, func_name);
        let mut child = Command::new("sh");
        child
            .arg("-c")
            .arg(&command)
            .arg("--") // sh positional params start after this
            .arg(&device)
            .arg(&name)
            .env("SKEY_FUNC", &func_name)
            .env("SKEY_APPNUM", appnum.to_string())
            .env("SKEY_PARAMS", &ev.raw)
            .env("SKEY_EVENT", &event_json);
        for (i, p) in ev.params.iter().enumerate() {
            if let Some(v) = p {
                child.env(format!("SKEY_P{}", i + 1), v.to_string());
            }
        }
        if let Some(r) = ev.regid {
            child.env("SKEY_REGID", r.to_string());
        }
        if let Some(s) = ev.seq {
            child.env("SKEY_SEQ", s.to_string());
        }
        if let Some(c) = &ev.client {
            child.env("SKEY_CLIENT", c);
        }
        let status = child.status();
        match status {
            Ok(s) => println!("openskey: {} finished ({s})", func_name),
            Err(e) => eprintln!("openskey: failed to run {}: {e}", func_name),
        }
    });
}
