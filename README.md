# openskey

An open, leak-free reimplementation of Brother's `brscan-skey` **Scan-to-PC key
daemon**, in Rust.

It makes a Brother multifunction device show the front-panel *Scan to PC* menu,
keeps that registration alive, listens for button presses, and runs a scan
command — the same job as Brother's closed-source `brscan-skey`, but without its
socket leak and with a documented, testable protocol.

> **Independent and unofficial.** Not affiliated with, authorised by, or
> endorsed by Brother Industries, Ltd. "Brother" and product names are
> trademarks of their respective owners. This is a clean reimplementation of a
> network protocol for interoperability; it contains no Brother code. Brother's
> Linux driver license explicitly permits derivative works. See
> [PROTOCOL.md](PROTOCOL.md) for how the protocol was documented.

## Why

**Brother does not support its Linux drivers.** They are shipped as
closed-source, binary-only packages, and when asked about a defect in
`brscan-skey`, Brother referred to not supporting its Linux drivers. The
driver license does, however, explicitly allow modifying and preparing
derivative works. This project takes Brother up on that: an open, documented,
maintainable implementation of the Scan-to-PC protocol that anyone can inspect,
test and fix, because the vendor will not.

The immediate trigger was a concrete bug the closed daemon cannot shed. The
stock `brscan-skey` daemon leaks one UDP socket on every registration cycle
(its firmware probe never closes it). With a keepalive re-registering every two
minutes it reaches its open-file limit in a few days, then logs `Too many open
files` and silently stops handling buttons and re-registering, so the Scan-to-PC
entry vanishes. This is tracked in
[BrotherScannerDocker](https://github.com/PhilippMundhenk/BrotherScannerDocker)
issues #179 and #186, and the leak is inside Brother's binary. `openskey`
re-sends the registration from a socket that is dropped immediately, so there is
nothing to accumulate, and each scan runs on its own thread so a long scan can
never delay re-registration.

## Status

Working and tested, against a live MFC-L2700DW and in CI against the mock:

- SNMPv1/BER encoder and the exact registration set-request (verified against
  the issue #10 captures and a live device).
- Keepalive loop, leak-free by construction, with a **self-test** after every
  registration: the registration object is read back and must say `TRUE`.
- Button-event (UDP 54925) parsing: `TYPE`/`USER`/`FUNC`/`APPNUM`,
  `P1..P4`, `REGID`/`SEQ` (deduplicates the device's resends) and `CLIENT`.
- Dispatch to a per-function command, with every event field in the script's
  environment (`SKEY_FUNC`, `SKEY_P1..P4`, `SKEY_SEQ`, `SKEY_EVENT` JSON, ...).
- `openskey status`: the scanner's state over SNMP as JSON (see below).
- A `mock-device` SNMP agent + button injector that mirrors a real
  MFC-L2700DW, for testing without hardware.

Scope: this is a **scanner** tool. Printer objects (toner, drum, page counters)
are deliberately not exposed.

## Commands

| Command             | Does                                                                     | Exit code                              |
| ------------------- | ------------------------------------------------------------------------ | -------------------------------------- |
| `openskey`          | run the Scan-to-PC daemon                                                |                                        |
| `openskey selftest` | ask the device whether it currently lists a Scan-to-PC host              | 0 yes, 1 no, 2 no answer               |
| `openskey status`   | print the scanner status as one JSON object                              | 0 device answered, 2 not               |

`openskey status` reports, each `null` when the model lacks the object:

```json
{"device_ip":"192.168.1.50","reachable":true,"registered":true,
 "model":"MFC-L2700DW","serial":"E73941F6N621420","firmware":"Y2309112149",
 "display":"Scan:   drück",
 "net_scanner_supported":true,"net_scanner_enabled":true,
 "scan_key_supported":true,"scan_key_enabled":true}
```

`registered` is the self-test; `scan_key_*` says whether the device supports
and has enabled the network Scan-to-PC key at all. Text objects are decoded
with the character set the device declares (Printer MIB
`prtLocalizationCharacterSet`); Brother panels use HP Roman-8, so a German
`drück` arrives as `64 72 CF 63 6B` and is reported as `drück`, not as a
replacement character. The objects are listed in
[PROTOCOL.md](PROTOCOL.md), section 5. Each query opens one socket and closes
it, so polling cannot leak.

## Build and test

Rust (stable) and Cargo. No third-party crates.

```sh
cargo build --release
cargo test
```

`cargo test` runs the unit tests (every module against an in-process mock
device) and `tests/binaries.rs`, which drives the real `openskey` and
`mock-device` binaries through the whole flow. CI also measures line coverage
with [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) and fails
below 95 %:

```sh
cargo llvm-cov --workspace --all-targets --fail-under-lines 95
```

## Code quality

Every one of these is a CI gate, not a convention:

- **No `unsafe`** (`#![forbid(unsafe_code)]` via `Cargo.toml`), no dependencies.
- **Clippy pedantic and nursery** are enabled in `Cargo.toml` and run with
  warnings as errors; `cargo fmt --check`.
- **Every public item is documented** (`missing_docs`) and `cargo doc` runs
  with warnings as errors.
- **MSRV: Rust 1.75**, declared in `Cargo.toml` and tested in CI.
- **Security audit**: `cargo audit` (RustSec advisories) and `cargo deny`
  (advisories, licenses, duplicate versions, unknown sources; `deny.toml`).
- **Robustness**: `tests/robustness.rs` feeds thousands of random and
  mutated datagrams through every parser and the mock's handler; nothing may
  panic. The BER decoder checks every length and addition, the OID encoder
  never panics on decoded input, and the duplicate table is bounded.
- **Coverage above 95 %** of lines (`cargo llvm-cov`).
- Dependabot keeps the GitHub Actions current.

## Run

Configuration is by environment variable, compatible with the container:

| Var                 | Meaning                                              | Default   |
| ------------------- | ---------------------------------------------------- | --------- |
| `NAME`              | PC name shown on the panel                           | `Scanner` |
| `IPADDRESS`         | the scanner's IP (registration target)               | required  |
| `HOST_IPADDRESS`    | this host's IP the device sends button events to     | required  |
| `KEEPALIVE_INTERVAL`| seconds between re-registrations (< 360)              | `120`     |
| `SKEY_SELFTEST`     | read the registration back after each refresh        | `true`    |
| `SKEY_HOLD_FILES`   | colon-separated files; while one exists and is younger than 10 minutes (a scan in progress), the refresh is skipped | none |
| `SKEY_LISTEN_PORT`  | the button-event port (the device sends to 54925; tests use another) | `54925` |
| `SKEY_DEBUG`        | log every button datagram in full (hex + ASCII)      | off       |
| `SKEY_RUN_SECONDS`  | exit normally after this many seconds (captures, tests) | forever |
| `SKEY_SCAN_DELAY_MS`| pause between a button event and starting the scan command (the stock daemon waits 100 ms) | `100` |
| `SKEY_DEVICE_PORT`  | the device's SNMP port (tests use the mock on 1161)  | `161`     |
| `SKEY_IMAGE` / `SKEY_OCR` / `SKEY_EMAIL` / `SKEY_FILE` | command per function   | container script paths |

The command runs as `sh -c "<command>" -- <device> <name>` (the two positional
arguments the stock daemon passes) with the event in its environment:
`SKEY_FUNC`, `SKEY_APPNUM`, `SKEY_P1`..`SKEY_P4`, `SKEY_REGID`, `SKEY_SEQ`,
`SKEY_CLIENT`, the raw token string `SKEY_PARAMS` and the JSON `SKEY_EVENT`.

```sh
IPADDRESS=192.168.1.50 HOST_IPADDRESS=192.168.1.10 NAME=Scanner ./target/release/openskey
```

## Testing without a scanner

In one terminal, run the mock device as an SNMP agent on an unprivileged port:

```sh
./target/release/mock-device --port 1161
```

In another, point the daemon at it and watch it register:

```sh
IPADDRESS=127.0.0.1 SKEY_DEVICE_PORT=1161 HOST_IPADDRESS=127.0.0.1 ./target/release/openskey
```

Then inject a button press and watch the daemon dispatch it (optionally with
non-default `P1..P4`), and read the status the mock answers with:

```sh
./target/release/mock-device --button FILE --params 3,1,0,2
IPADDRESS=127.0.0.1 SKEY_DEVICE_PORT=1161 ./target/release/openskey selftest
IPADDRESS=127.0.0.1 SKEY_DEVICE_PORT=1161 ./target/release/openskey status
```

The mock answers the registration object with `TRUE` only after it received a
registration, so `selftest` is meaningful against it (`--registered` starts it
registered, `--run-seconds N` stops it after N seconds).

The same `mock-device` agent can decode what the **real** `brscan-skey` sends
(point it at `127.0.0.1`), for differential testing against this implementation.

## Capturing from a real scanner

The button event has been decoded from a live MFC-L2700DW. To check another
model (or see what it puts into `P1..P4`), run `openskey` against it with
`SKEY_DEBUG=1` and press each Scan-to-PC button; it prints the full datagram as
hex:

```sh
# Stop any other daemon bound to UDP 54925 first (e.g. the container's
# brscan-skey), otherwise the port is taken.
SKEY_DEBUG=1 NAME=Scanner IPADDRESS=<scanner-ip> HOST_IPADDRESS=<this-host-ip> \
  ./target/release/openskey
```

`HOST_IPADDRESS` must be an address the scanner can reach back on. On WSL2 this
needs mirrored networking (`networkingMode=mirrored` in `.wslconfig`) or a
forwarded UDP 54925, so the inbound event reaches the WSL instance. Press *Scan
to File*, then *Image*, *Email*, *OCR* in turn; each prints a line like
`openskey: CAPTURE 114 bytes from <ip>: <hex> | <ascii>`. Share those lines (one
per button) to complete the parser.

Alternatively, capture passively with `tcpdump` while the existing, working
container is registered (no port conflict, works through NAT):

```sh
sudo tcpdump -i any -s0 -w skey.pcap 'udp port 54925 or udp port 161'
# press the buttons, then Ctrl-C and share skey.pcap, or:
tcpdump -r skey.pcap -X -nn 'udp port 54925'
```

## License

MIT. See [LICENSE](LICENSE).
