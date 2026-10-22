//! Holding the keepalive back while a scan is in progress.
//!
//! A re-registration while the device is busy with a scan can stall its
//! feeder, and it must not coincide with paper in the ADF (observed with the
//! stock daemon, `BrotherScannerDocker` #107/#117).
//!
//! The host marks a scan in progress by touching one or more files
//! (`SKEY_HOLD_FILES`, colon-separated paths; the container uses its
//! `STATUS_SCAN` / `STATUS_WAITING` files). While any of them exists and is
//! younger than [`HOLD_MAX_AGE`], the keepalive skips the refresh. An older
//! file was left behind by a crash and is ignored.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// A hold file older than this is stale (left behind) and does not hold.
pub const HOLD_MAX_AGE: Duration = Duration::from_secs(600);

/// Parse `SKEY_HOLD_FILES` (`/tmp/STATUS_SCAN:/tmp/STATUS_WAITING`).
pub fn parse_hold_files(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// The hold files from the environment.
#[must_use]
pub fn hold_files_from_env() -> Vec<PathBuf> {
    std::env::var("SKEY_HOLD_FILES")
        .map(|v| parse_hold_files(&v))
        .unwrap_or_default()
}

/// True when `path` exists and was modified less than `max_age` ago.
#[must_use]
pub fn is_fresh(path: &Path, max_age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < max_age)
}

/// The first hold file that currently holds, if any.
#[must_use]
pub fn holding(files: &[PathBuf]) -> Option<&PathBuf> {
    files.iter().find(|p| is_fresh(p, HOLD_MAX_AGE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("openskey-hold-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_colon_separated_paths_and_ignores_empties() {
        assert_eq!(
            parse_hold_files("/tmp/STATUS_SCAN:/tmp/STATUS_WAITING"),
            vec![
                PathBuf::from("/tmp/STATUS_SCAN"),
                PathBuf::from("/tmp/STATUS_WAITING")
            ]
        );
        assert_eq!(parse_hold_files(" : /a : "), vec![PathBuf::from("/a")]);
        assert_eq!(parse_hold_files(""), [] as [std::path::PathBuf; 0]);
    }

    #[test]
    fn a_fresh_file_holds_a_missing_or_stale_one_does_not() {
        let dir = temp_dir("fresh");
        let fresh = dir.join("STATUS_SCAN");
        let stale = dir.join("STATUS_WAITING");
        let missing = dir.join("nope");
        std::fs::write(&fresh, b"scan").unwrap();
        std::fs::write(&stale, b"waiting").unwrap();
        let old = SystemTime::now() - Duration::from_secs(20 * 60);
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();

        assert!(is_fresh(&fresh, HOLD_MAX_AGE));
        assert!(!is_fresh(&stale, HOLD_MAX_AGE));
        assert!(!is_fresh(&missing, HOLD_MAX_AGE));

        let files = vec![missing.clone(), stale.clone(), fresh.clone()];
        assert_eq!(holding(&files), Some(&fresh));
        let files = vec![missing, stale];
        assert_eq!(holding(&files), None);
        assert_eq!(holding(&[]), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
