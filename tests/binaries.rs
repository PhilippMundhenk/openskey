//! Drives the real `openskey` and `mock-device` binaries end to end, the way
//! the container and the CI shell job use them: mock device up, self-test
//! negative, daemon registers and verifies, hold file skips a refresh,
//! self-test positive, status JSON, a button press (sent twice) runs the
//! command once with the event in its environment. Both binaries run with a
//! time limit so they exit normally.

use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const OPENSKEY: &str = env!("CARGO_BIN_EXE_openskey");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-device");

fn free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("openskey-bin-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn openskey(args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let out = Command::new(OPENSKEY)
        .args(args)
        .envs(env.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

fn wait_for(log: &PathBuf, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let text = fs::read_to_string(log).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "{needle:?} not in log within {timeout:?}:\n{text}"
        );
        sleep(Duration::from_millis(100));
    }
}

#[test]
fn full_flow_against_the_mock_device() {
    let dir = work_dir("flow");
    let device_port = free_udp_port().to_string();
    let listen_port = free_udp_port().to_string();
    let mock_log = fs::File::create(dir.join("mock.log")).unwrap();
    let mut mock = Command::new(MOCK)
        .args(["--port", &device_port, "--run-seconds", "12"])
        .stdout(Stdio::from(mock_log.try_clone().unwrap()))
        .stderr(Stdio::from(mock_log))
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(300));
    let base = [
        ("IPADDRESS", "127.0.0.1"),
        ("SKEY_DEVICE_PORT", device_port.as_str()),
    ];

    // nothing registered yet
    let (code, text) = openskey(&["selftest"], &base);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("selftest FAILED"));

    let hold = dir.join("STATUS_SCAN");
    let hold_files = hold.to_string_lossy().to_string();
    let log_path = dir.join("skey.log");
    let log = fs::File::create(&log_path).unwrap();
    let mut daemon = Command::new(OPENSKEY)
        .envs(base.iter().map(|(k, v)| (k.to_string(), v.to_string())))
        .env("HOST_IPADDRESS", "127.0.0.1")
        .env("NAME", "bintest")
        .env("KEEPALIVE_INTERVAL", "1")
        .env("SKEY_LISTEN_PORT", &listen_port)
        .env("SKEY_HOLD_FILES", &hold_files)
        .env("SKEY_DEBUG", "1")
        .env("SKEY_RUN_SECONDS", "7")
        .env(
            "SKEY_FILE",
            "echo DISPATCHED P1=$SKEY_P1 P4=$SKEY_P4 SEQ=$SKEY_SEQ FUNC=$SKEY_FUNC",
        )
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    wait_for(&log_path, "registration verified", Duration::from_secs(5));

    // a scan in progress holds the refresh back
    fs::write(&hold, b"").unwrap();
    wait_for(&log_path, "scan in progress", Duration::from_secs(4));
    fs::remove_file(&hold).unwrap();

    let (code, text) = openskey(&["selftest"], &base);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("selftest OK"));

    let (code, json) = openskey(&["status"], &base);
    assert_eq!(code, 0, "{json}");
    for needle in [
        "\"reachable\":true",
        "\"registered\":true",
        "\"model\":\"MFC-L2700DW\"",
        "\"serial\":\"E73941F6N621420\"",
        "\"scan_key_enabled\":true",
    ] {
        assert!(json.contains(needle), "{needle} missing in {json}");
    }
    assert!(!json.to_lowercase().contains("toner"));

    // a button press, sent twice, runs the command once
    let host = format!("127.0.0.1:{listen_port}");
    let pressed = Command::new(MOCK)
        .args(["--button", "FILE", "--host", &host, "--params", "3,1,0,2"])
        .output()
        .unwrap();
    let pressed_text = String::from_utf8_lossy(&pressed.stdout).to_string();
    assert!(pressed.status.success(), "{pressed_text}");
    // the daemon must not answer the event: a real device expects nothing
    assert!(pressed_text.contains("nothing came back"), "{pressed_text}");
    let text = wait_for(&log_path, "FILE finished", Duration::from_secs(5));
    assert!(!text.contains("acknowledg"), "{text}");
    assert!(
        text.contains("DISPATCHED P1=3 P4=2 SEQ=56 FUNC=FILE"),
        "{text}"
    );
    assert!(text.contains("duplicate event (SEQ=56) ignored"), "{text}");
    assert!(text.contains("CAPTURE"), "{text}");
    assert_eq!(text.matches("FILE finished").count(), 1, "{text}");

    // unrecognised datagrams are logged with a capture
    let noise = UdpSocket::bind("127.0.0.1:0").unwrap();
    noise.send_to(b"\x01\x02noise", &host).unwrap();
    wait_for(&log_path, "unrecognised datagram", Duration::from_secs(3));

    // the time limit ends both processes normally
    let daemon_exit = daemon.wait().unwrap();
    assert!(daemon_exit.success(), "{daemon_exit}");
    let text = fs::read_to_string(&log_path).unwrap();
    assert!(text.contains("run time of 7s is over"), "{text}");
    let mock_exit = mock.wait().unwrap();
    assert!(mock_exit.success(), "{mock_exit}");
    let mock_text = fs::read_to_string(dir.join("mock.log")).unwrap();
    assert!(mock_text.contains("registration from"), "{mock_text}");
    assert!(mock_text.contains("FUNC=IMAGE"), "{mock_text}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn help_unknown_command_and_unreachable_device() {
    let (code, text) = openskey(&["help"], &[]);
    assert_eq!(code, 0);
    assert!(text.contains("usage: openskey"));
    let (code, text) = openskey(&["--help"], &[]);
    assert_eq!(code, 0);
    assert!(text.contains("usage"));
    let (code, text) = openskey(&["bogus"], &[]);
    assert_eq!(code, 2);
    assert!(text.contains("unknown command"));

    let port = free_udp_port().to_string();
    let env = [
        ("IPADDRESS", "127.0.0.1"),
        ("SKEY_DEVICE_PORT", port.as_str()),
    ];
    let (code, text) = openskey(&["status"], &env);
    assert_eq!(code, 2);
    assert!(text.contains("\"reachable\":false"));
    let (code, text) = openskey(&["selftest"], &env);
    assert_eq!(code, 2);
    assert!(text.contains("no answer"));

    // no device configured at all
    let (code, text) = openskey(&["status"], &[("IPADDRESS", "")]);
    assert_eq!(code, 2);
    assert!(text.contains("IPADDRESS"));
    let (code, _) = openskey(&["selftest"], &[("IPADDRESS", "")]);
    assert_eq!(code, 2);
}

#[test]
fn daemon_without_a_host_address_keeps_running_and_says_why() {
    let listen_port = free_udp_port().to_string();
    let (code, text) = openskey(
        &[],
        &[
            ("IPADDRESS", "127.0.0.1"),
            ("HOST_IPADDRESS", ""),
            ("SKEY_LISTEN_PORT", listen_port.as_str()),
            ("SKEY_RUN_SECONDS", "1"),
            ("KEEPALIVE_INTERVAL", "1"),
        ],
    );
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("registration failed"), "{text}");
    assert!(text.contains("HOST_IPADDRESS"), "{text}");
}

#[test]
fn daemon_refuses_a_taken_button_port() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let (code, text) = openskey(
        &[],
        &[
            ("IPADDRESS", "127.0.0.1"),
            ("HOST_IPADDRESS", "127.0.0.1"),
            ("SKEY_LISTEN_PORT", port.as_str()),
            ("SKEY_RUN_SECONDS", "1"),
        ],
    );
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("cannot bind"), "{text}");
}

#[test]
fn mock_device_usage_errors() {
    let out = Command::new(MOCK)
        .args(["--port", "notaport"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--port"));
    let out = Command::new(MOCK).args(["--help"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("usage"));
}
