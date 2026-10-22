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
closed-source, binary-only packages, and when asked for help with a defect in
`brscan-skey`, Brother's support declined and advised fixing it yourself. The
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

Early. Working and tested so far:

- SNMPv1/BER encoder and the exact registration set-request (verified against
  the issue #10 captures).
- Keepalive loop, leak-free by construction.
- Button-event (UDP 54925) parsing of `TYPE`/`USER`/`FUNC`/`APPNUM`.
- Dispatch to a per-function command.
- A `mock-device` SNMP agent + button injector for testing without hardware.

Next: pin down the exact button-event header and scan-parameter fields from a
live capture, validate the scan-command argument contract against the container
scripts, and package it as a drop-in for the container.

## Build and test

Rust (stable) and Cargo. No third-party crates.

```sh
cargo build --release
cargo test
```

## Run

Configuration is by environment variable, compatible with the container:

| Var                 | Meaning                                              | Default   |
| ------------------- | ---------------------------------------------------- | --------- |
| `NAME`              | PC name shown on the panel                           | `Scanner` |
| `IPADDRESS`         | the scanner's IP (registration target)               | required  |
| `HOST_IPADDRESS`    | this host's IP the device sends button events to     | required  |
| `KEEPALIVE_INTERVAL`| seconds between re-registrations (< 360)              | `120`     |
| `SKEY_IMAGE` / `SKEY_OCR` / `SKEY_EMAIL` / `SKEY_FILE` | command per function   | container script paths |

```sh
IPADDRESS=192.168.1.50 HOST_IPADDRESS=192.168.1.10 NAME=Scanner ./target/release/openskey
```

## Testing without a scanner

In one terminal, run the mock device (SNMP agent on port 161):

```sh
sudo ./target/release/mock-device          # or --port 1161 to avoid root
```

In another, point the daemon at it and watch it register:

```sh
IPADDRESS=127.0.0.1 HOST_IPADDRESS=127.0.0.1 ./target/release/openskey
```

Then inject a button press and watch the daemon dispatch it:

```sh
./target/release/mock-device --button FILE
```

The same `mock-device` agent can decode what the **real** `brscan-skey` sends
(point it at `127.0.0.1`), for differential testing against this implementation.

## License

MIT. See [LICENSE](LICENSE).
