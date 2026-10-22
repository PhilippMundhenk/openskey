# Brother Scan-to-PC key protocol

This documents the network protocol a Brother multifunction device uses to offer
the front-panel **Scan to PC** function to a host, as implemented by Brother's
`brscan-skey` tool. It was reverse-engineered for interoperability from:

- packet captures contributed to BrotherScannerDocker issue #10 (SNMP
  registration fully decoded; button event observed on the wire), and
- the format strings and parsing routines inside the stock `brscan-skey-exe`
  binary (strings and disassembly only; **no Brother code is reused**).

Brother's Linux driver license explicitly permits modifying, translating and
preparing derivative works. This file records the wire format only.

## Roles and ports

| Party  | Role                                                        |
| ------ | ----------------------------------------------------------- |
| Host   | The PC (this daemon). Registers itself, listens for events. |
| Device | The scanner/MFC.                                            |

| Port         | Dir            | Use                                             |
| ------------ | -------------- | ----------------------------------------------- |
| UDP 161      | host -> device | SNMP registration (set-request) and queries     |
| UDP 54925    | device -> host | Button-press event                              |
| TCP 54921    | host -> device | The scan itself (SANE / `scanimage`), unchanged |

## 1. Registration (host -> device, SNMPv1 set-request to UDP 161)

- SNMP **version-1**, community `internal`.
- A single `set-request`, request-id **201** (constant; the device echoes it).
- Four variable-bindings, all writing OID
  **`1.3.6.1.4.1.2435.2.3.9.2.11.1.1.0`** (`2435` is Brother's enterprise arc),
  each an `OCTET STRING`:

```
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=IMAGE;HOST=<host-ip>:54925;APPNUM=1;DURATION=360;BRID=;
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=EMAIL;HOST=<host-ip>:54925;APPNUM=2;DURATION=360;BRID=;
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=OCR;HOST=<host-ip>:54925;APPNUM=3;DURATION=360;BRID=;
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=FILE;HOST=<host-ip>:54925;APPNUM=5;DURATION=360;BRID=;
```

Fields:

- `USER` — the PC name shown on the panel (quoted).
- `FUNC` / `APPNUM` — the four functions and their numbers: IMAGE=1, EMAIL=2,
  OCR=3, FILE=5 (4 is unused).
- `HOST` — the IP the device will send button events to, plus `:54925`. **It
  must be an address the device can reach back on.** An empty value
  (`HOST=:54925`) is why the panel appears to do nothing: the device has nowhere
  to send the event (BrotherScannerDocker issue #10).
- `DURATION` — the lease in seconds the device keeps the registration, **360**.
  The registration must be re-sent before it expires or the entry disappears.
- `BRID` — empty in all observed captures.

The device replies with an SNMP `get-response` echoing the bindings.

### Keeping it alive

The device does **not** renew on its own and `brscan-skey` only re-registers on
daemon start, a button press or power-on, so the entry lapses `DURATION` seconds
after the last event. A periodic re-send (well under 360 s) keeps it present.

> Note: in the stock binary every re-registration runs a firmware-probe that
> opens a UDP socket and never closes it, leaking one descriptor per cycle until
> the daemon hits its open-file limit and stops registering (BrotherScannerDocker
> #179/#186). `openskey` re-sends from a socket that is closed immediately, so
> there is nothing to leak.

## 2. Device identification (optional, host -> device, SNMP get)

`brscan-skey` also reads standard MIB-II objects once:

- `1.3.6.1.2.1.1.1.0` — `sysDescr`
- `1.3.6.1.2.1.2.2.1.6.1` — `ifPhysAddress.1` (the device MAC)

These are not required to register; they identify the device.

## 3. Button event (device -> host, UDP to port 54925)

When the user selects a Scan-to-PC function on the panel, the device sends a
single UDP datagram (~113–114 bytes observed) to `HOST:54925`. It is a short
binary header followed by an ASCII token string in the same shape as the
registration. `brscan-skey` parses it with `TYPE=`, `USER=`, `HOST=`, `CLIENT=`,
`FUNC=` / `APPNUM=` markers, and:

- checks `TYPE` is `BR`,
- checks `USER` matches the registered PC user,
- checks `HOST` resolves to this host's address (`decode_key_data IP mismatch`
  otherwise),
- dispatches on `FUNC` / `APPNUM` to the matching command, passing the scan
  parameters through.

`openskey` locates the `TYPE=` marker (tolerating the exact header bytes, which
are not yet fully characterised) and reads `TYPE`, `USER`, `FUNC`, `APPNUM`. The
precise header and the full set of scan parameters in the event are the next
item to pin down, by capturing a real event against the `mock-device` or a live
device (see README).

## 4. The scan

Dispatch runs the configured command (the same `scantofile.py` etc. the
container already ships), which invokes `scanimage` against the device over TCP
54921. That part is unchanged by this project.
