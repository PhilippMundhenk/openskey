//! Daemon configuration, from environment variables (compatible with the names
//! used by the `BrotherScannerDocker` container).

use std::collections::BTreeMap;

/// The four Scan-to-PC functions a Brother device offers, with the APPNUM the
/// device expects for each (observed in the registration captures, issue #10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Function {
    /// Scan to Image (`APPNUM=1`).
    Image,
    /// Scan to E-mail (`APPNUM=2`).
    Email,
    /// Scan to OCR (`APPNUM=3`).
    Ocr,
    /// Scan to File (`APPNUM=5`).
    File,
}

impl Function {
    /// The name as it appears on the wire (`FUNC=...`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Image => "IMAGE",
            Self::Email => "EMAIL",
            Self::Ocr => "OCR",
            Self::File => "FILE",
        }
    }

    /// The number the device expects for the function (`APPNUM=...`).
    #[must_use]
    pub const fn appnum(self) -> u32 {
        match self {
            Self::Image => 1,
            Self::Email => 2,
            Self::Ocr => 3,
            Self::File => 5,
        }
    }

    /// The four functions in the order the stock daemon registers them
    /// (IMAGE, OCR, EMAIL, FILE: issue #10 capture and the binary's own
    /// registration strings).
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Image, Self::Ocr, Self::Email, Self::File]
    }

    /// The function for a wire name (`IMAGE`, `EMAIL`, `OCR`, `FILE`; any
    /// case, surrounding whitespace ignored).
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "IMAGE" => Some(Self::Image),
            "EMAIL" => Some(Self::Email),
            "OCR" => Some(Self::Ocr),
            "FILE" => Some(Self::File),
            _ => None,
        }
    }
}

/// Default listen port for button events; the device sends to `HOST=<ip>:54925`.
pub const DEFAULT_LISTEN_PORT: u16 = 54925;
/// Device-side registration lease in seconds (`DURATION=...`), hardcoded 360
/// by Brother; we refresh well before it.
pub const DURATION: u32 = 360;

/// The daemon's configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// PC name shown on the device panel (`USER=...` in the registration).
    pub name: String,
    /// The scanner's IP address (where the SNMP registration is sent).
    pub device_ip: String,
    /// The scanner's SNMP port (always 161 for a real device; configurable so
    /// tests can use an unprivileged port with the mock device).
    pub device_port: u16,
    /// The host IP the device should send button events to
    /// (`HOST=<ip>:<port>`). Must be reachable from the scanner; an empty
    /// value is why buttons stay silent in issue #10.
    pub host_ip: String,
    /// SNMP community (always "internal" on these devices).
    pub community: String,
    /// Device-side registration lease in seconds (`DURATION=...`).
    pub duration: u32,
    /// Seconds between re-registrations; kept below `duration`.
    pub keepalive_interval: u32,
    /// UDP port we listen on for button events (54925 unless `SKEY_LISTEN_PORT`
    /// says otherwise, for tests).
    pub listen_port: u16,
    /// Command to run for each enabled function (shell command line).
    pub commands: BTreeMap<&'static str, String>,
}

impl Config {
    /// From the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// From any lookup of the variable names (the environment, or a map in
    /// tests). Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let env_or = |key: &str, default: &str| {
            get(key)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let device_port: u16 = env_or("SKEY_DEVICE_PORT", "161").parse().unwrap_or(161);
        let listen_port: u16 = env_or("SKEY_LISTEN_PORT", "54925")
            .parse()
            .unwrap_or(DEFAULT_LISTEN_PORT);
        let keepalive_interval: u32 = env_or("KEEPALIVE_INTERVAL", "120").parse().unwrap_or(120);

        // Per-function commands. Defaults match the container's script layout.
        let base = "python3 /opt/brother/scanner/brscan-skey/script";
        let mut commands = BTreeMap::new();
        commands.insert(
            "IMAGE",
            env_or("SKEY_IMAGE", &format!("{base}/scantoimage.py")),
        );
        commands.insert("OCR", env_or("SKEY_OCR", &format!("{base}/scantoocr.py")));
        commands.insert(
            "EMAIL",
            env_or("SKEY_EMAIL", &format!("{base}/scantoemail.py")),
        );
        commands.insert(
            "FILE",
            env_or("SKEY_FILE", &format!("{base}/scantofile.py")),
        );

        Self {
            name: env_or("NAME", "Scanner"),
            device_ip: env_or("IPADDRESS", ""),
            device_port,
            host_ip: env_or("HOST_IPADDRESS", ""),
            community: env_or("SKEY_COMMUNITY", "internal"),
            duration: DURATION,
            keepalive_interval: keepalive_interval.min(DURATION.saturating_sub(1)),
            listen_port,
            commands,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functions_have_the_device_numbers_and_names() {
        assert_eq!(Function::Image.appnum(), 1);
        assert_eq!(Function::Email.appnum(), 2);
        assert_eq!(Function::Ocr.appnum(), 3);
        assert_eq!(Function::File.appnum(), 5);
        assert_eq!(
            Function::all().map(Function::name),
            ["IMAGE", "OCR", "EMAIL", "FILE"]
        );
        assert_eq!(Function::from_name(" file "), Some(Function::File));
        assert_eq!(Function::from_name("ocr"), Some(Function::Ocr));
        assert_eq!(Function::from_name("Email"), Some(Function::Email));
        assert_eq!(Function::from_name("image"), Some(Function::Image));
        assert_eq!(Function::from_name("fax"), None);
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let cfg = Config::from_lookup(|_| None);
        assert_eq!(cfg.name, "Scanner");
        assert_eq!(cfg.device_ip, "");
        assert_eq!(cfg.device_port, 161);
        assert_eq!(cfg.host_ip, "");
        assert_eq!(cfg.community, "internal");
        assert_eq!(cfg.duration, 360);
        assert_eq!(cfg.keepalive_interval, 120);
        assert_eq!(cfg.listen_port, 54925);
        assert_eq!(cfg.commands.len(), 4);
        assert!(cfg.commands["FILE"].ends_with("scantofile.py"));
        assert!(cfg.commands["OCR"].ends_with("scantoocr.py"));
    }

    #[test]
    fn values_from_the_lookup_win_and_empty_counts_as_unset() {
        let cfg = Config::from_lookup(|k| {
            Some(
                match k {
                    "NAME" => "NAS",
                    "IPADDRESS" => "10.0.30.10",
                    "SKEY_DEVICE_PORT" => "1161",
                    "HOST_IPADDRESS" => "10.0.30.2",
                    "SKEY_COMMUNITY" => "other",
                    "KEEPALIVE_INTERVAL" => "30",
                    "SKEY_LISTEN_PORT" => "15925",
                    "SKEY_FILE" => "echo file",
                    "SKEY_IMAGE" => "",
                    _ => return None,
                }
                .to_string(),
            )
        });
        assert_eq!(cfg.name, "NAS");
        assert_eq!(cfg.device_ip, "10.0.30.10");
        assert_eq!(cfg.device_port, 1161);
        assert_eq!(cfg.host_ip, "10.0.30.2");
        assert_eq!(cfg.community, "other");
        assert_eq!(cfg.keepalive_interval, 30);
        assert_eq!(cfg.listen_port, 15925);
        assert_eq!(cfg.commands["FILE"], "echo file");
        assert!(cfg.commands["IMAGE"].ends_with("scantoimage.py"));
    }

    #[test]
    fn bad_numbers_fall_back_and_the_keepalive_stays_below_the_lease() {
        let cfg = Config::from_lookup(|k| {
            Some(
                match k {
                    "SKEY_DEVICE_PORT" => "port",
                    "SKEY_LISTEN_PORT" => "99999",
                    "KEEPALIVE_INTERVAL" => "x",
                    _ => return None,
                }
                .to_string(),
            )
        });
        assert_eq!(cfg.device_port, 161);
        assert_eq!(cfg.listen_port, 54925);
        assert_eq!(cfg.keepalive_interval, 120);
        let cfg = Config::from_lookup(|k| (k == "KEEPALIVE_INTERVAL").then(|| "900".to_string()));
        assert_eq!(cfg.keepalive_interval, 359);
    }

    #[test]
    fn from_env_reads_the_process_environment() {
        // only a variable no other test touches, so parallel tests cannot race
        let cfg = Config::from_env();
        assert_eq!(cfg.duration, 360);
        assert!(!cfg.commands.is_empty());
    }
}
