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
//! The logic lives in the library (`daemon.rs`); this file is the loops:
//! threads are independent, the keepalive never blocks on a scan, and each
//! scan runs in its own thread, so a long scan cannot delay re-registration.

use openskey::button::ButtonEvent;
use openskey::config::Config;
use openskey::daemon::{self, Decision, Dedup, Keepalive};
use openskey::hold;
use std::io;
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

const USAGE: &str = "usage: openskey [status|selftest|help]

  (no command)  run the Scan-to-PC daemon
  status        print the device status as JSON and exit
                (exit 0 if the device answered, 2 if not)
  selftest      check the device reports a Scan-to-PC registration
                (exit 0 registered, 1 not registered, 2 no answer)

Configuration is taken from the environment: NAME, IPADDRESS, HOST_IPADDRESS,
KEEPALIVE_INTERVAL, SKEY_DEVICE_PORT, SKEY_LISTEN_PORT, SKEY_COMMUNITY,
SKEY_SELFTEST, SKEY_HOLD_FILES, SKEY_DEBUG, SKEY_RUN_SECONDS,
SKEY_IMAGE / SKEY_EMAIL / SKEY_OCR / SKEY_FILE (scan commands).";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        None => run_daemon(),
        Some("status") => {
            let (out, code) = daemon::status_report(&Config::from_env());
            println!("{out}");
            code
        }
        Some("selftest") => {
            let (out, code) = daemon::selftest_report(&Config::from_env());
            println!("{out}");
            code
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{USAGE}");
            0
        }
        Some(other) => {
            eprintln!("openskey: unknown command {other:?}\n{USAGE}");
            2
        }
    };
    std::process::exit(code);
}

fn run_daemon() -> i32 {
    let cfg = Config::from_env();
    let run_seconds = daemon::run_seconds_from(std::env::var("SKEY_RUN_SECONDS").ok());
    let debug = daemon::debug_enabled_from(std::env::var("SKEY_DEBUG").ok());
    println!(
        "openskey starting: name={:?} device={}:{} host={} listen=:{} keepalive={}s duration={}s",
        cfg.name,
        cfg.device_ip,
        cfg.device_port,
        cfg.host_ip,
        cfg.listen_port,
        cfg.keepalive_interval,
        cfg.duration
    );
    if let Some(seconds) = run_seconds {
        println!("openskey: will exit after {seconds}s (SKEY_RUN_SECONDS)");
    }

    // Bind the button port first: a taken port is a configuration error that
    // should fail before anything is registered.
    let socket = match UdpSocket::bind(("0.0.0.0", cfg.listen_port)) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("openskey: cannot bind UDP :{}: {e}", cfg.listen_port);
            return 1;
        }
    };

    // Keepalive thread: register now, then re-register before each lease lapses.
    {
        let cfg = cfg.clone();
        thread::spawn(move || keepalive_loop(cfg));
    }

    let deadline = run_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    listen_loop(&cfg, socket, debug, deadline);
    println!(
        "openskey: run time of {}s is over, exiting",
        run_seconds.unwrap_or(0)
    );
    0
}

fn keepalive_loop(cfg: Config) {
    let verify = daemon::selftest_enabled_from(std::env::var("SKEY_SELFTEST").ok());
    let holds = hold::hold_files_from_env();
    if !holds.is_empty() {
        println!(
            "openskey: registration refresh is held back while any of these is fresh: {}",
            holds
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    loop {
        let outcome = daemon::keepalive_once(&cfg, verify, &holds);
        let line = daemon::describe_keepalive(&cfg, &outcome);
        match outcome {
            Keepalive::Failed(_) | Keepalive::Registered(Some(false)) => eprintln!("{line}"),
            _ => println!("{line}"),
        }
        thread::sleep(Duration::from_secs(cfg.keepalive_interval.max(1) as u64));
    }
}

fn listen_loop(cfg: &Config, socket: UdpSocket, debug: bool, deadline: Option<Instant>) {
    println!(
        "openskey: listening for button events on :{}",
        cfg.listen_port
    );
    if deadline.is_some() {
        let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
    }
    let scan_delay = daemon::scan_delay_from(std::env::var("SKEY_SCAN_DELAY_MS").ok());
    let mut buf = [0u8; 2048];
    let mut dedup = Dedup::default();
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return;
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
            Err(e) => {
                eprintln!("openskey: recv error: {e}");
                continue;
            }
        };
        let datagram = &buf[..n];
        match daemon::classify(&mut dedup, datagram) {
            // Nothing is sent back to the device: Brother's daemon does not
            // acknowledge events either (it only runs the script), and the
            // device resends the event once regardless (PROTOCOL.md).
            Decision::Dispatch(ev) => {
                log_button(&ev, datagram, from.to_string(), debug);
                dispatch(cfg, ev, scan_delay);
            }
            Decision::Duplicate(ev) => {
                log_button(&ev, datagram, from.to_string(), debug);
                println!(
                    "openskey: duplicate event (SEQ={}) ignored",
                    ev.seq.unwrap_or(0)
                );
            }
            Decision::Unrecognised => {
                // Always captured in full: this is how another model's event
                // gets characterised (see README "Capturing from a real scanner").
                eprintln!("openskey: unrecognised datagram from {from} ({n} bytes)");
                eprintln!(
                    "openskey: CAPTURE {n} bytes from {from}: {}",
                    daemon::hex_dump(datagram)
                );
            }
        }
    }
}

fn log_button(ev: &ButtonEvent, datagram: &[u8], from: String, debug: bool) {
    println!(
        "openskey: button from {from}: header[{}] FUNC={:?} APPNUM={:?} P={:?} SEQ={:?}",
        daemon::header_hex(datagram),
        ev.func,
        ev.appnum,
        ev.params,
        ev.seq
    );
    if debug {
        println!(
            "openskey: CAPTURE {} bytes from {from}: {}",
            datagram.len(),
            daemon::hex_dump(datagram)
        );
    }
}

/// Run the scan command in its own thread and wait on it there, so the
/// listener keeps serving and no zombie is left behind. `delay` is the pause
/// between the event and the command (SKEY_SCAN_DELAY_MS; the stock daemon
/// waits 100 ms).
fn dispatch(cfg: &Config, ev: ButtonEvent, delay: Duration) {
    let cfg = cfg.clone();
    thread::spawn(move || {
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let func = ev.func.map(|f| f.name()).unwrap_or("?");
        let command = cfg.commands.get(func).cloned().unwrap_or_default();
        println!("openskey: running {command} for {func}");
        match daemon::run_command(&cfg, &ev) {
            Ok((name, status)) => println!("openskey: {name} finished ({status})"),
            Err(e) => eprintln!("openskey: {e}"),
        }
    });
}
