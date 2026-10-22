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
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=OCR;HOST=<host-ip>:54925;APPNUM=3;DURATION=360;BRID=;
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=EMAIL;HOST=<host-ip>:54925;APPNUM=2;DURATION=360;BRID=;
TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=FILE;HOST=<host-ip>:54925;APPNUM=5;DURATION=360;BRID=;
```

(in this order: IMAGE, OCR, EMAIL, FILE, as the stock daemon sends them.)

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

When the user selects a Scan-to-PC function on the panel, the device sends a UDP
datagram (~122–124 bytes) to `HOST:54925`. Confirmed against a live MFC. It is a
4-byte header followed by an ASCII token string:

```
02 00 LL 30  TYPE=BR;BUTTON=SCAN;USER="<name>";FUNC=FILE;HOST=<host-ip>:54925;APPNUM=5;P1=0;P2=0;P3=0;P4=0;REGID=60614;SEQ=56;
```

Header: bytes 0, 1, 3 are constant `02 00 .. 30`; byte 2 (`LL`) is the datagram
length + 1 (e.g. a 123-byte datagram has `LL = 0x7c = 124`).

Token string fields (the first four match the registration):

- `TYPE=BR`, `BUTTON=SCAN`, `USER` (the registered PC name), `FUNC` / `APPNUM`
  (which function was pressed), `HOST` (echoes our registered host).
- `P1..P4` — four numeric per-press option fields; `0` means default. An
  MFC-L2700DW sends `0;0;0;0` for every button, with and without paper in the
  ADF, so they are **not** device state. The stock daemon carries the string
  through to the scan script without decoding these fields (its binary holds
  no parser for them). The scan options a model may let the user pick on the
  panel ("set at device": file type, colour, resolution) are not in this
  datagram at all: the scan client reads them from the device over TCP 54921
  (`ESC GKP`), which is the SANE backend's job, not the button daemon's.
  `openskey` parses `P1..P4` and hands them to the script as `SKEY_P1..P4`.
- `REGID` — a registration id the device assigns, distinct per function.
- `SEQ` — a sequence number, one per press.
- `CLIENT` — the registered host's address as the device sees it. Seen in the
  sample event embedded in the stock binary (after an empty `;;` token), not
  in every capture; optional.

The stock `brscan-skey` additionally checks `USER` matches the registered user
and `HOST` resolves to this host (`decode_key_data IP mismatch` otherwise)
before dispatching on `FUNC` / `APPNUM`.

**The device sends each press more than once** (observed: twice, ~2 s apart, same
`SEQ`) until the scan starts, so the receiver must deduplicate by `(REGID, SEQ)`
or it will scan twice. `openskey` does this.

`openskey` locates the `TYPE=` marker (so the exact header bytes do not matter to
parsing) and reads `TYPE`, `USER`, `FUNC`, `APPNUM`, `P1..P4`, `REGID`, `SEQ`,
`CLIENT`.

### No acknowledgement

The host sends **nothing** back to the device. Established from two sources:

- Brother's daemon, disassembled (the binary ships with symbols): the UDP
  thread (`udp_agent`) classifies the datagram (`check_udp_data`: byte 0 =
  `0x02` and byte 3 = `0x30` is a key event), appends `;CLIENT=<sender ip>`
  to the string itself, and hands it to the main loop, which validates it
  (`decode_key_data`: `USER` must be the login user, `HOST` this host's
  address), sleeps 100 ms and runs the script with `system()`. Its
  `udp_sent` function is not an acknowledgement: it sends to
  `localhost:54925` and carries the command-line tool's internal commands
  (`Add device`, `Del device`, `Refresh Device List`, `List Device`,
  `Terminate`, header byte 0 = `0x01`/`0x80`, byte 3 = `0x80`..`0x84`).
- The issue #10 capture of a working setup: after the two event datagrams
  (device -> host, 2 s apart) the next packets are the scan session on TCP
  54921; no UDP goes from the host to the device.

So the device resends the event once, about two seconds later, whatever the
host does. Duplicates must be dropped: the stock daemon skips an identical
command within 4 s (and is blocked in `system()` while the scan runs),
`openskey` drops a repeat of `(REGID, SEQ)` within 20 s. The `CLIENT=` field
some logs show is added by the stock daemon locally; it is not on the wire.
The stock daemon also keeps 54925 open with `SO_REUSEADDR` because its own
command-line tool talks to it on that port; `openskey` has no such tool and
logs any such datagram as unrecognised.

## 4. The scan

Dispatch runs the configured command (the same `scantofile.py` etc. the
container already ships), which invokes `scanimage` against the device over TCP
54921. That part is unchanged by this project.

`openskey` passes everything the device sent to the script, in its
environment: `SKEY_FUNC`, `SKEY_APPNUM`, `SKEY_P1`..`SKEY_P4`, `SKEY_REGID`,
`SKEY_SEQ`, `SKEY_CLIENT` (when present), the raw token string `SKEY_PARAMS`
and the whole event as JSON in `SKEY_EVENT`.

## 5. Status objects (openskey only; not in the stock daemon)

Beyond the original, `openskey status` and `openskey selftest` read a few
objects from Brother's private MIB with ordinary SNMPv1 get-requests
(community `internal`, one object per request, because SNMPv1 fails the whole
request when any object is missing). **Scanner objects only** — this is a
scanner tool; printer objects (toner, drum, page counters) are deliberately
out of scope. Taken from a full walk of a live MFC-L2700DW, named with the
published BROTHER-MIB:

| Object | OID | Meaning |
| ------ | --- | ------- |
| `brRegisterKeyInfo` | `1.3.6.1.4.1.2435.2.3.9.2.11.1.1.0` | The registration object (section 1). Reads back `TRUE` while the device lists a Scan-to-PC host: the **self-test**. |
| `sysDescr` | `1.3.6.1.2.1.1.1.0` | `Brother MFC-L2700DW series` → model |
| serial number | `1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.1.0` | device serial |
| firmware | `1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.17.0` | firmware version |
| panel display | `1.3.6.1.4.1.2435.2.4.3.1240.3.2.1.5.1` | first line of the LCD |
| `mcsNetScanner` | `1.3.6.1.4.1.2435.2.3.9.2.101.3.11.{1,2}` | network scanning supported (.1) / enabled (.2), INTEGER 1/0 |
| `mcsNetSKy` | `1.3.6.1.4.1.2435.2.3.9.2.101.3.12.{1,2}` | the network Scan Key (Scan-to-PC button) supported / enabled |

The capability objects are what the stock daemon probes on every registration
(its `brPhoenixAllCapability` query, the step that leaks a socket). Whether
paper is in the ADF is **not** available this way: a walk with an empty and
with a loaded feeder differs only in a session nonce under the security
branch (`...2.4.3.2435.5.100`).
