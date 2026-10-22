//! Daemon configuration, from environment variables (compatible with the names
//! used by the BrotherScannerDocker container).

use std::collections::BTreeMap;

/// The four Scan-to-PC functions a Brother device offers, with the APPNUM the
/// device expects for each (observed in the registration captures, issue #10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Function {
    Image,
    Email,
    Ocr,
    File,
}

impl Function {
    pub fn name(self) -> &'static str {
        match self {
            Function::Image => "IMAGE",
            Function::Email => "EMAIL",
            Function::Ocr => "OCR",
            Function::File => "FILE",
        }
    }

    pub fn appnum(self) -> u32 {
        match self {
            Function::Image => 1,
            Function::Email => 2,
            Function::Ocr => 3,
            Function::File => 5,
        }
    }

    pub fn all() -> [Function; 4] {
        [
            Function::Image,
            Function::Email,
            Function::Ocr,
            Function::File,
        ]
    }

    pub fn from_name(s: &str) -> Option<Function> {
        match s.trim().to_ascii_uppercase().as_str() {
            "IMAGE" => Some(Function::Image),
            "EMAIL" => Some(Function::Email),
            "OCR" => Some(Function::Ocr),
            "FILE" => Some(Function::File),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// PC name shown on the device panel (USER=... in the registration).
    pub name: String,
    /// The scanner's IP address (where the SNMP registration is sent, port 161).
    pub device_ip: String,
    /// The host IP the device should send button events to (HOST=<ip>:54925).
    /// Must be reachable from the scanner; an empty value is why buttons stay
    /// silent in issue #10.
    pub host_ip: String,
    /// SNMP community (always "internal" on these devices).
    pub community: String,
    /// Device-side registration lease in seconds (DURATION=...), hardcoded 360
    /// by Brother; we refresh well before it.
    pub duration: u32,
    /// Seconds between re-registrations; must stay below `duration`.
    pub keepalive_interval: u32,
    /// UDP port we listen on for button events (always 54925).
    pub listen_port: u16,
    /// Command to run for each enabled function (argv-less shell command line).
    pub commands: BTreeMap<&'static str, String>,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

impl Config {
    pub fn from_env() -> Config {
        let name = env_or("NAME", "Scanner");
        let device_ip = env_or("IPADDRESS", "");
        let host_ip = env_or("HOST_IPADDRESS", "");
        let keepalive_interval: u32 = env_or("KEEPALIVE_INTERVAL", "120").parse().unwrap_or(120);
        let duration: u32 = 360;

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

        Config {
            name,
            device_ip,
            host_ip,
            community: env_or("SKEY_COMMUNITY", "internal"),
            duration,
            keepalive_interval: keepalive_interval.min(duration.saturating_sub(1)),
            listen_port: 54925,
            commands,
        }
    }
}
