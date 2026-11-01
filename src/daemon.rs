//! The daemon's logic, one step at a time.
//!
//! The `openskey` binary is only the loops around it. The steps are:
//! deduplicating and classifying button events, running
//! the scan command with the event in its environment, one keepalive cycle
//! (hold check, registration, self-test), and the `status` / `selftest`
//! reports.

use crate::button::{self, ButtonEvent};
use crate::config::Config;
use crate::hold;
use crate::registration;
use crate::status;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// The device resends each button press (same SEQ) about two seconds later;
/// a repeat of the same (REGID, SEQ) within this window is dropped.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(20);

/// The most (REGID, SEQ) pairs remembered at once, so a flood of distinct
/// events cannot grow the table without bound.
pub const DEDUP_CAPACITY: usize = 1024;

/// Remembers recent (REGID, SEQ) pairs.
pub struct Dedup {
    window: Duration,
    recent: VecDeque<((u64, u64), Instant)>,
}

impl Dedup {
    /// An empty table that forgets a pair after `window`.
    #[must_use]
    pub const fn new(window: Duration) -> Self {
        Self {
            window,
            recent: VecDeque::new(),
        }
    }

    /// True when this (REGID, SEQ) was seen within the window; an event
    /// without a SEQ is never a duplicate.
    pub fn is_duplicate(&mut self, regid: Option<u64>, seq: Option<u64>) -> bool {
        let Some(seq) = seq else {
            return false;
        };
        let key = (regid.unwrap_or(0), seq);
        let now = Instant::now();
        while self
            .recent
            .front()
            .is_some_and(|&(_, t)| now.duration_since(t) > self.window)
        {
            self.recent.pop_front();
        }
        if self.recent.iter().any(|&(k, _)| k == key) {
            return true;
        }
        if self.recent.len() >= DEDUP_CAPACITY {
            self.recent.pop_front();
        }
        self.recent.push_back((key, now));
        false
    }
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new(DEDUP_WINDOW)
    }
}

/// What to do with a datagram received on the button port.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// A new button press: run its scan command.
    Dispatch(ButtonEvent),
    /// The device's resend of a press already dispatched: ignore it.
    Duplicate(ButtonEvent),
    /// Not a button event (logged in full so a new model can be characterised).
    Unrecognised,
}

/// Parse a datagram and decide what to do with it.
pub fn classify(dedup: &mut Dedup, datagram: &[u8]) -> Decision {
    match button::parse(datagram) {
        Some(ev) => {
            if dedup.is_duplicate(ev.regid, ev.seq) {
                Decision::Duplicate(ev)
            } else {
                Decision::Dispatch(ev)
            }
        }
        None => Decision::Unrecognised,
    }
}

/// The first four bytes as hex, for the log line.
#[must_use]
pub fn header_hex(datagram: &[u8]) -> String {
    datagram[..datagram.len().min(4)]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A datagram as contiguous hex plus a printable-ASCII view, for capturing a
/// real device's button events.
#[must_use]
pub fn hex_dump(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(data.len() * 2);
    for b in data {
        // writing to a String cannot fail
        let _ = write!(hex, "{b:02x}");
    }
    let ascii: String = data
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    format!("{hex} | {ascii}")
}

/// The environment the scan command gets: everything the device sent.
#[must_use]
pub fn event_env(ev: &ButtonEvent) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(func) = ev.func {
        env.push(("SKEY_FUNC".into(), func.name().into()));
        env.push((
            "SKEY_APPNUM".into(),
            ev.appnum.unwrap_or_else(|| func.appnum()).to_string(),
        ));
    }
    env.push(("SKEY_PARAMS".into(), ev.raw.clone()));
    env.push(("SKEY_EVENT".into(), ev.to_json()));
    for (i, p) in ev.params.iter().enumerate() {
        if let Some(v) = p {
            env.push((format!("SKEY_P{}", i + 1), v.to_string()));
        }
    }
    if let Some(r) = ev.regid {
        env.push(("SKEY_REGID".into(), r.to_string()));
    }
    if let Some(s) = ev.seq {
        env.push(("SKEY_SEQ".into(), s.to_string()));
    }
    if let Some(c) = &ev.client {
        env.push(("SKEY_CLIENT".into(), c.clone()));
    }
    env
}

/// The SANE device name the stock daemon passes as the script's first
/// argument.
pub const DEVICE_ARG: &str = "brother4:net1;dev0";

/// Run the configured command for the event and wait for it.
///
/// The command runs as `sh -c <command> -- <device> <name>` with the event in
/// the environment (see [`event_env`]). Returns the function name and the
/// exit status.
///
/// # Errors
///
/// The event names no known function, no command is configured for it, or
/// the command could not be started; the message says which.
pub fn run_command(cfg: &Config, ev: &ButtonEvent) -> Result<(String, ExitStatus), String> {
    let func = ev.func.ok_or("event without a known FUNC, ignored")?;
    let command = cfg
        .commands
        .get(func.name())
        .ok_or_else(|| format!("no command configured for {}", func.name()))?;
    let mut child = Command::new("sh");
    child
        .arg("-c")
        .arg(command)
        .arg("--")
        .arg(DEVICE_ARG)
        .arg(&cfg.name);
    for (k, v) in event_env(ev) {
        child.env(k, v);
    }
    let status = child
        .status()
        .map_err(|e| format!("failed to run {}: {e}", func.name()))?;
    Ok((func.name().to_string(), status))
}

/// How often the keepalive looks again while a hold file is fresh.
///
/// Instead of waiting a whole `KEEPALIVE_INTERVAL`, so the refresh follows
/// the scan at once (issue #14: consecutive jobs chain their holds, and a
/// refresh that waits a full interval after the last one leaves the panel
/// without the Scan-to-PC entry for up to that long).
pub const HOLD_RECHECK: Duration = Duration::from_secs(10);

/// A hold is overridden when less than this is left of the lease: a scan must
/// never cost the registration, and the device drops the entry `DURATION`
/// seconds after the last refresh (PROTOCOL.md).
pub const LEASE_GRACE: Duration = Duration::from_secs(60);

/// Why a refresh went out although a hold file is fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Override {
    /// The lease would run out before the next look, or nothing has been
    /// registered since the daemon started.
    LeaseEnding,
    /// The device no longer lists the registration (a read-only self-test
    /// said so), whatever the reason: without a refresh the key is dead.
    NotListed,
}

impl Override {
    const fn text(self) -> &'static str {
        match self {
            Self::LeaseEnding => "the lease is about to run out",
            Self::NotListed => "the device no longer lists the registration",
        }
    }
}

/// One keepalive cycle's outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum Keepalive {
    /// A hold file is fresh: a scan is in progress, nothing was sent.
    Held(PathBuf),
    /// Registered; the self-test result when it ran (Some(true) = the device
    /// lists us, Some(false) = it does not, None = no answer or not run).
    Registered(Option<bool>),
    /// Registered although the hold file is fresh, for the given reason; the
    /// self-test result as in `Registered`.
    Forced(PathBuf, Override, Option<bool>),
    /// The registration could not be sent.
    Failed(String),
}

impl Keepalive {
    /// A registration was sent (the lease starts over).
    #[must_use]
    pub const fn sent(&self) -> bool {
        matches!(self, Self::Registered(_) | Self::Forced(..))
    }

    /// A scan is in progress: look again after [`HOLD_RECHECK`], not after a
    /// whole interval.
    #[must_use]
    pub const fn under_hold(&self) -> bool {
        matches!(self, Self::Held(_) | Self::Forced(..))
    }

    /// Something is wrong: the registration could not be sent, or the device
    /// says it does not list us right after it was sent.
    #[must_use]
    pub const fn is_warning(&self) -> bool {
        matches!(
            self,
            Self::Failed(_) | Self::Registered(Some(false)) | Self::Forced(_, _, Some(false))
        )
    }
}

/// One keepalive cycle: hold check, registration, optional self-test.
///
/// `registered_ago` is the time since the last registration was sent (`None`:
/// none yet). A fresh hold file holds the refresh back, except when the lease
/// is about to run out or, with `verify`, when the device no longer lists the
/// registration: then it goes out anyway. The read during a hold is a plain
/// SNMP get, which the device answers without side effects (the container's
/// status poll does the same while scans run).
#[must_use]
pub fn keepalive_once(
    cfg: &Config,
    verify: bool,
    holds: &[PathBuf],
    registered_ago: Option<Duration>,
) -> Keepalive {
    let Some(file) = hold::holding(holds) else {
        return refresh(cfg, verify, None);
    };
    let lease = Duration::from_secs(u64::from(cfg.duration));
    let ending = registered_ago.map_or(true, |ago| ago + LEASE_GRACE >= lease);
    if ending {
        return refresh(cfg, verify, Some((file.clone(), Override::LeaseEnding)));
    }
    if verify && status::registered(cfg).ok().flatten() == Some(false) {
        return refresh(cfg, verify, Some((file.clone(), Override::NotListed)));
    }
    Keepalive::Held(file.clone())
}

/// Send the registration and, with `verify`, read it back.
fn refresh(cfg: &Config, verify: bool, forced: Option<(PathBuf, Override)>) -> Keepalive {
    if let Err(e) = registration::register_once(cfg) {
        return Keepalive::Failed(e.to_string());
    }
    let verified = if verify {
        status::registered(cfg).ok().flatten()
    } else {
        None
    };
    match forced {
        Some((file, why)) => Keepalive::Forced(file, why, verified),
        None => Keepalive::Registered(verified),
    }
}

/// "registered Scan-to-PC for ..., <how the self-test went>".
fn registered_text(cfg: &Config, verified: Option<bool>) -> String {
    let name = &cfg.name;
    match verified {
        Some(true) => format!("registered Scan-to-PC for {name:?}, registration verified"),
        Some(false) => {
            format!("registered Scan-to-PC for {name:?}, WARNING: device reports no registration")
        }
        None => {
            format!("registered Scan-to-PC for {name:?} (not verified: no answer from the device)")
        }
    }
}

/// The log line for a keepalive outcome.
#[must_use]
pub fn describe_keepalive(cfg: &Config, outcome: &Keepalive) -> String {
    match outcome {
        Keepalive::Held(file) => format!(
            "openskey: scan in progress ({}), registration refresh held back",
            file.display()
        ),
        Keepalive::Registered(verified) => {
            format!("openskey: {}", registered_text(cfg, *verified))
        }
        Keepalive::Forced(file, why, verified) => format!(
            "openskey: scan in progress ({}) but {}: {}",
            file.display(),
            why.text(),
            registered_text(cfg, *verified)
        ),
        Keepalive::Failed(e) => format!("openskey: registration failed: {e}"),
    }
}

/// `SKEY_SELFTEST`: on unless "0" / "false".
#[must_use]
pub fn selftest_enabled_from(value: Option<&str>) -> bool {
    value.map_or(true, |v| v != "0" && !v.eq_ignore_ascii_case("false"))
}

/// `SKEY_DEBUG`: full-datagram capture logging when set to anything but "0".
#[must_use]
pub fn debug_enabled_from(value: Option<&str>) -> bool {
    value.is_some_and(|v| v != "0" && !v.is_empty())
}

/// `SKEY_RUN_SECONDS`: run the daemon (or the mock) for this long and then
/// exit normally; for captures and tests. `None`: run forever.
#[must_use]
pub fn run_seconds_from(value: Option<&str>) -> Option<u64> {
    value.and_then(|v| v.trim().parse().ok()).filter(|&s| s > 0)
}

/// The default of `SKEY_SCAN_DELAY_MS`: Brother's daemon waits 100 ms
/// (`usleep(100000)` before `system()`).
pub const DEFAULT_SCAN_DELAY_MS: u64 = 100;

/// `SKEY_SCAN_DELAY_MS`: the pause between a button event and starting the
/// scan command.
#[must_use]
pub fn scan_delay_from(value: Option<&str>) -> Duration {
    Duration::from_millis(
        value
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(DEFAULT_SCAN_DELAY_MS),
    )
}

/// `openskey status`: the JSON report and the exit code (0 when the device
/// answered, 2 when it did not or the configuration is unusable).
#[must_use]
pub fn status_report(cfg: &Config) -> (String, i32) {
    match status::query(cfg) {
        Ok(st) => {
            let code = if st.reachable { 0 } else { 2 };
            (st.to_json(), code)
        }
        Err(e) => (format!("openskey: status failed: {e}"), 2),
    }
}

/// `openskey selftest`: the message and the exit code (0 registered, 1 not
/// registered, 2 no answer).
#[must_use]
pub fn selftest_report(cfg: &Config) -> (String, i32) {
    match status::registered(cfg) {
        Ok(Some(true)) => (
            "openskey: selftest OK, device reports a Scan-to-PC registration".into(),
            0,
        ),
        Ok(Some(false)) => (
            "openskey: selftest FAILED, device reports no Scan-to-PC registration".into(),
            1,
        ),
        Ok(None) => (
            format!("openskey: selftest: no answer from {}", cfg.device_ip),
            2,
        ),
        Err(e) => (format!("openskey: selftest failed: {e}"), 2),
    }
}

/// Touch (create or empty) a hold file.
///
/// # Errors
///
/// The file could not be written.
pub fn touch(path: &Path) -> std::io::Result<()> {
    std::fs::write(path, b"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Function;
    use crate::mock::{button_datagram, MockServer};

    fn cfg_for(port: u16, host_ip: &str) -> Config {
        let port = port.to_string();
        let host_ip = host_ip.to_string();
        Config::from_lookup(move |k| match k {
            "IPADDRESS" => Some("127.0.0.1".into()),
            "SKEY_DEVICE_PORT" => Some(port.clone()),
            "HOST_IPADDRESS" => Some(host_ip.clone()),
            "NAME" => Some("tester".into()),
            _ => None,
        })
    }

    #[test]
    fn dedup_drops_repeats_within_the_window_only() {
        let mut d = Dedup::new(Duration::from_millis(300));
        assert!(!d.is_duplicate(Some(1), Some(7)));
        assert!(d.is_duplicate(Some(1), Some(7)));
        assert!(!d.is_duplicate(Some(2), Some(7)), "another REGID");
        assert!(!d.is_duplicate(None, None), "no SEQ: never a duplicate");
        assert!(!d.is_duplicate(None, None));
        std::thread::sleep(Duration::from_millis(400));
        assert!(!d.is_duplicate(Some(1), Some(7)), "window passed");
        assert!(Dedup::default().recent.is_empty());
    }

    #[test]
    fn classify_dispatches_once_then_reports_duplicates_and_noise() {
        let mut d = Dedup::default();
        let dg = button_datagram(Function::File, [0; 4]);
        assert!(matches!(classify(&mut d, &dg), Decision::Dispatch(ev) if ev.seq == Some(56)));
        assert!(matches!(classify(&mut d, &dg), Decision::Duplicate(_)));
        assert_eq!(classify(&mut d, b"\x01\x02junk"), Decision::Unrecognised);
        assert_eq!(header_hex(&dg), "02 00 77 30");
        assert_eq!(header_hex(&[0x7f]), "7f");
        let dump = hex_dump(b"\x02A\n");
        assert_eq!(dump, "02410a | .A.");
    }

    #[test]
    fn event_env_carries_every_field() {
        let ev = button::parse(&button_datagram(Function::Image, [3, 1, 0, 2])).unwrap();
        let env = event_env(&ev);
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(get("SKEY_FUNC").as_deref(), Some("IMAGE"));
        assert_eq!(get("SKEY_APPNUM").as_deref(), Some("1"));
        assert_eq!(get("SKEY_P1").as_deref(), Some("3"));
        assert_eq!(get("SKEY_P4").as_deref(), Some("2"));
        assert_eq!(get("SKEY_SEQ").as_deref(), Some("56"));
        assert_eq!(get("SKEY_REGID").as_deref(), Some("60614"));
        assert!(get("SKEY_CLIENT").is_none());
        assert!(get("SKEY_EVENT").unwrap().starts_with('{'));
        assert!(get("SKEY_PARAMS").unwrap().starts_with("TYPE=BR"));

        let minimal = button::parse(b"TYPE=BR;USER=\"x\";CLIENT=10.0.0.9;").unwrap();
        let env = event_env(&minimal);
        assert!(!env.iter().any(|(k, _)| k == "SKEY_FUNC"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SKEY_CLIENT" && v == "10.0.0.9"));
    }

    #[test]
    fn run_command_passes_arguments_and_environment() {
        let out = std::env::temp_dir().join(format!("openskey-run-{}", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let command = format!(
            "printf '%s|%s|%s|%s|%s' \"$1\" \"$2\" \"$SKEY_FUNC\" \"$SKEY_P1\" \"$SKEY_SEQ\" > {}",
            out.display()
        );
        let cfg = Config::from_lookup(move |k| match k {
            "SKEY_OCR" => Some(command.clone()),
            "NAME" => Some("tester".into()),
            _ => None,
        });
        let ev = button::parse(&button_datagram(Function::Ocr, [4, 0, 0, 0])).unwrap();
        let (func, status) = run_command(&cfg, &ev).unwrap();
        assert_eq!(func, "OCR");
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            format!("{DEVICE_ARG}|tester|OCR|4|56")
        );
        let _ = std::fs::remove_file(&out);

        // a failing command reports its status, not an error
        let cfg = Config::from_lookup(|k| match k {
            "SKEY_OCR" => Some("exit 3".into()),
            _ => None,
        });
        let (_, status) = run_command(&cfg, &ev).unwrap();
        assert_eq!(status.code(), Some(3));
    }

    #[test]
    fn run_command_refuses_unknown_function_or_missing_command() {
        let cfg = Config::from_lookup(|_| None);
        let no_func = button::parse(b"TYPE=BR;USER=\"x\";SEQ=1;").unwrap();
        assert!(run_command(&cfg, &no_func).unwrap_err().contains("FUNC"));
        let mut cfg = cfg;
        cfg.commands.remove("FILE");
        let ev = button::parse(&button_datagram(Function::File, [0; 4])).unwrap();
        assert_eq!(
            run_command(&cfg, &ev).unwrap_err(),
            "no command configured for FILE"
        );
    }

    #[test]
    fn keepalive_holds_registers_and_verifies() {
        // the device lists us already, the lease is fresh
        let server = MockServer::start(true).unwrap();
        let cfg = cfg_for(server.port, "127.0.0.1");
        let hold = std::env::temp_dir().join(format!("openskey-hold-{}", std::process::id()));
        touch(&hold).unwrap();
        let holds = vec![hold.clone()];
        let fresh = Some(Duration::from_secs(1));
        assert_eq!(
            keepalive_once(&cfg, true, &holds, fresh),
            Keepalive::Held(hold.clone())
        );
        assert_eq!(
            keepalive_once(&cfg, false, &holds, fresh),
            Keepalive::Held(hold.clone())
        );
        let outcome = Keepalive::Held(hold.clone());
        assert!(describe_keepalive(&cfg, &outcome).contains("held back"));
        assert!(outcome.under_hold() && !outcome.sent() && !outcome.is_warning());
        std::fs::remove_file(&hold).unwrap();

        assert_eq!(
            keepalive_once(&cfg, false, &holds, None),
            Keepalive::Registered(None)
        );
        assert_eq!(
            keepalive_once(&cfg, true, &holds, fresh),
            Keepalive::Registered(Some(true))
        );
        let ok = Keepalive::Registered(Some(true));
        assert!(describe_keepalive(&cfg, &ok).contains("registration verified"));
        assert!(ok.sent() && !ok.under_hold() && !ok.is_warning());
        let bad = Keepalive::Registered(Some(false));
        assert!(describe_keepalive(&cfg, &bad).contains("WARNING"));
        assert!(bad.sent() && bad.is_warning());
        let unverified = Keepalive::Registered(None);
        assert!(describe_keepalive(&cfg, &unverified).contains("not verified: no answer"));
        assert!(unverified.sent() && !unverified.is_warning());
        let state = server.stop();
        assert!(state.registered);
        assert!(state.requests >= 3);
    }

    #[test]
    fn a_hold_is_overridden_when_the_lease_ends_or_the_device_dropped_us() {
        let hold =
            std::env::temp_dir().join(format!("openskey-hold-override-{}", std::process::id()));
        touch(&hold).unwrap();
        let holds = vec![hold.clone()];

        // nothing registered since the start (e.g. the daemon was restarted
        // during a scan): the hold does not stop the first registration
        let server = MockServer::start(false).unwrap();
        let cfg = cfg_for(server.port, "127.0.0.1");
        let outcome = keepalive_once(&cfg, true, &holds, None);
        assert_eq!(
            outcome,
            Keepalive::Forced(hold.clone(), Override::LeaseEnding, Some(true))
        );
        assert!(outcome.sent() && outcome.under_hold() && !outcome.is_warning());
        let line = describe_keepalive(&cfg, &outcome);
        assert!(line.contains("scan in progress"), "{line}");
        assert!(line.contains("lease is about to run out"), "{line}");
        assert!(line.contains("registration verified"), "{line}");

        // the lease is nearly over: refreshed despite the hold
        let lease = Duration::from_secs(u64::from(cfg.duration));
        let ending = lease.saturating_sub(LEASE_GRACE);
        assert_eq!(
            keepalive_once(&cfg, false, &holds, Some(ending)),
            Keepalive::Forced(hold.clone(), Override::LeaseEnding, None)
        );
        // plenty of lease left and the device lists us: held
        let plenty = ending.saturating_sub(Duration::from_secs(1));
        assert_eq!(
            keepalive_once(&cfg, true, &holds, Some(plenty)),
            Keepalive::Held(hold.clone())
        );
        assert!(server.stop().registered);

        // the device dropped the entry while a scan runs (fresh lease or not):
        // the self-test notices and the refresh goes out anyway
        let server = MockServer::start(false).unwrap();
        let cfg = cfg_for(server.port, "127.0.0.1");
        let outcome = keepalive_once(&cfg, true, &holds, Some(Duration::from_secs(5)));
        assert_eq!(
            outcome,
            Keepalive::Forced(hold.clone(), Override::NotListed, Some(true))
        );
        assert!(describe_keepalive(&cfg, &outcome).contains("no longer lists"));
        // without the self-test the daemon cannot know, so it holds
        let server2 = MockServer::start(false).unwrap();
        let cfg2 = cfg_for(server2.port, "127.0.0.1");
        assert_eq!(
            keepalive_once(&cfg2, false, &holds, Some(Duration::from_secs(5))),
            Keepalive::Held(hold.clone())
        );
        assert!(!server2.stop().registered);
        assert!(server.stop().registered);

        let warning = Keepalive::Forced(hold.clone(), Override::NotListed, Some(false));
        assert!(warning.is_warning());
        assert!(describe_keepalive(&cfg, &warning).contains("WARNING"));
        std::fs::remove_file(&hold).unwrap();
    }

    #[test]
    fn keepalive_reports_a_registration_that_cannot_be_sent() {
        let cfg = cfg_for(1, "");
        let outcome = keepalive_once(&cfg, true, &[], None);
        let Keepalive::Failed(reason) = &outcome else {
            panic!("expected a failure: {outcome:?}");
        };
        assert!(reason.contains("HOST_IPADDRESS"));
        assert!(describe_keepalive(&cfg, &outcome).contains("registration failed"));
        assert!(outcome.is_warning() && !outcome.sent() && !outcome.under_hold());
        // the same under a hold whose lease is ending
        let hold =
            std::env::temp_dir().join(format!("openskey-hold-failed-{}", std::process::id()));
        touch(&hold).unwrap();
        assert!(matches!(
            keepalive_once(&cfg, true, std::slice::from_ref(&hold), None),
            Keepalive::Failed(_)
        ));
        std::fs::remove_file(&hold).unwrap();
    }

    #[test]
    fn keepalive_without_an_answer_is_registered_but_unverified() {
        // nothing listens on this port: the set-request goes out, the
        // self-test gets no answer
        let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let cfg = cfg_for(port, "127.0.0.1");
        assert_eq!(
            keepalive_once(&cfg, true, &[], None),
            Keepalive::Registered(None)
        );
        // no answer during a hold is not "not listed": the hold holds
        let hold =
            std::env::temp_dir().join(format!("openskey-hold-silent-{}", std::process::id()));
        touch(&hold).unwrap();
        assert_eq!(
            keepalive_once(
                &cfg,
                true,
                std::slice::from_ref(&hold),
                Some(Duration::from_secs(5))
            ),
            Keepalive::Held(hold.clone())
        );
        std::fs::remove_file(&hold).unwrap();
    }

    #[test]
    fn reports_against_the_mock_and_against_nothing() {
        let server = MockServer::start(false).unwrap();
        let cfg = cfg_for(server.port, "127.0.0.1");
        let (msg, code) = selftest_report(&cfg);
        assert_eq!(code, 1);
        assert!(msg.contains("FAILED"));
        registration::register_once(&cfg).unwrap();
        let (msg, code) = selftest_report(&cfg);
        assert_eq!(code, 0);
        assert!(msg.contains("selftest OK"));
        let (json, code) = status_report(&cfg);
        assert_eq!(code, 0);
        assert!(json.contains("\"registered\":true"));
        assert!(json.contains("\"model\":\"MFC-L2700DW\""));
        drop(server);

        let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let cfg = cfg_for(port, "127.0.0.1");
        let (msg, code) = selftest_report(&cfg);
        assert_eq!(code, 2);
        assert!(msg.contains("no answer"));
        let (json, code) = status_report(&cfg);
        assert_eq!(code, 2);
        assert!(json.contains("\"reachable\":false"));

        let unusable = Config::from_lookup(|_| None);
        assert_eq!(selftest_report(&unusable).1, 2);
        assert!(status_report(&unusable).0.contains("IPADDRESS"));
    }

    #[test]
    fn environment_switches() {
        assert!(selftest_enabled_from(None));
        assert!(selftest_enabled_from(Some("1")));
        assert!(!selftest_enabled_from(Some("0")));
        assert!(!selftest_enabled_from(Some("False")));
        assert!(!debug_enabled_from(None));
        assert!(!debug_enabled_from(Some("")));
        assert!(!debug_enabled_from(Some("0")));
        assert!(debug_enabled_from(Some("1")));
        assert_eq!(run_seconds_from(None), None);
        assert_eq!(run_seconds_from(Some("0")), None);
        assert_eq!(run_seconds_from(Some("abc")), None);
        assert_eq!(run_seconds_from(Some(" 15 ")), Some(15));
        assert_eq!(scan_delay_from(None), Duration::from_millis(100));
        assert_eq!(scan_delay_from(Some("x")), Duration::from_millis(100));
        assert_eq!(scan_delay_from(Some("0")), Duration::ZERO);
        assert_eq!(scan_delay_from(Some(" 250 ")), Duration::from_millis(250));
    }
}
