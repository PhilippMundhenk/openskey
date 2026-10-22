//! openskey: an open, leak-free reimplementation of Brother's `brscan-skey`
//! Scan-to-PC key daemon.
//!
//! It registers this host with the scanner so the device shows the Scan-to-PC
//! menu, refreshes that registration before its lease expires (without the
//! socket leak of the original, see BrotherScannerDocker #179/#186), listens
//! for button presses on UDP 54925, and runs the configured scan command.
//!
//! Threads are independent: the keepalive never blocks on a scan, and each scan
//! runs in its own thread, so a long scan cannot delay re-registration.

use openskey::button;
use openskey::config::Config;
use openskey::registration;
use std::net::UdpSocket;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
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

fn keepalive_loop(cfg: Config) {
    loop {
        match registration::register_once(&cfg) {
            Ok(()) => println!("openskey: registered Scan-to-PC for {:?}", cfg.name),
            Err(e) => eprintln!("openskey: registration failed: {e}"),
        }
        thread::sleep(Duration::from_secs(cfg.keepalive_interval.max(1) as u64));
    }
}

fn listen_loop(cfg: &Config, socket: UdpSocket) {
    println!("openskey: listening for button events on :{}", cfg.listen_port);
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("openskey: recv error: {e}");
                continue;
            }
        };
        let header: Vec<String> = buf[..n.min(4)].iter().map(|b| format!("{b:02x}")).collect();
        match button::parse(&buf[..n]) {
            Some(ev) => {
                println!(
                    "openskey: button from {from}: header[{}] FUNC={:?} APPNUM={:?}",
                    header.join(" "),
                    ev.func,
                    ev.appnum
                );
                dispatch(cfg, ev);
            }
            None => eprintln!("openskey: unrecognised datagram from {from} ({n} bytes)"),
        }
    }
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
    let raw = ev.raw.clone();
    let func_name = func.name().to_string();
    let appnum = ev.appnum.unwrap_or(func.appnum());

    // Run each scan in its own thread and wait on the child there, so the
    // listener keeps serving and no zombie is left behind.
    thread::spawn(move || {
        println!("openskey: running {} for {}", command, func_name);
        let status = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .arg("--") // sh positional params start after this
            .arg(&device)
            .arg(&name)
            .env("SKEY_FUNC", &func_name)
            .env("SKEY_APPNUM", appnum.to_string())
            .env("SKEY_PARAMS", &raw)
            .status();
        match status {
            Ok(s) => println!("openskey: {} finished ({s})", func_name),
            Err(e) => eprintln!("openskey: failed to run {}: {e}", func_name),
        }
    });
}
