//! Untrusted input never panics.
//!
//! Everything the daemon reads from the network (SNMP responses, button
//! datagrams) and everything the mock device handles goes through these
//! parsers. Random bytes, mutated real messages and deliberately absurd
//! lengths must all come back as `None` / `Unrecognised`, never as a panic:
//! a crafted datagram must not be able to stop the daemon.

use openskey::config::Function;
use openskey::{button, daemon, hold, mock, snmp, status};

/// A small deterministic generator (xorshift64*), so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

/// Everything that parses a datagram, on one input.
fn exercise(bytes: &[u8]) {
    let _ = snmp::read_tlv(bytes, 0);
    let _ = snmp::decode_oid(bytes);
    let _ = snmp::extract_string_varbinds(bytes);
    if let Some(msg) = snmp::decode_message(bytes) {
        // what the mock echoes back: every decoded value must re-encode
        for (oid, value) in &msg.varbinds {
            let _ = snmp::varbind(oid, &snmp::encode_value(value));
        }
    }
    let _ = button::parse(bytes);
    let mut dedup = daemon::Dedup::default();
    let _ = daemon::classify(&mut dedup, bytes);
    let _ = daemon::hex_dump(bytes);
    let _ = daemon::header_hex(bytes);
    let mut state = mock::MockState::default();
    let (_, response) = mock::handle(bytes, &mut state);
    if let Some(r) = response {
        let _ = snmp::decode_message(&r);
    }
    let text = String::from_utf8_lossy(bytes);
    let _ = hold::parse_hold_files(&text);
    let _ = status::json_string(&text);
    let _ = status::model_from_sys_descr(&text);
}

#[test]
fn random_datagrams_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..5000 {
        let len = rng.below(300);
        exercise(&rng.bytes(len));
    }
}

#[test]
fn mutated_real_messages_never_panic() {
    let cfg = openskey::config::Config::from_lookup(|k| match k {
        "IPADDRESS" => Some("127.0.0.1".into()),
        "HOST_IPADDRESS" => Some("10.0.0.2".into()),
        _ => None,
    });
    let originals = [
        openskey::registration::build_registration(&cfg),
        mock::button_datagram(Function::File, [3, 1, 0, 2]),
        snmp::get_request(
            "internal",
            7,
            &[&status::OID_SYS_DESCR, &status::OID_SERIAL],
        ),
    ];
    let mut rng = Rng(42);
    for original in &originals {
        exercise(original);
        for _ in 0..2000 {
            let mut bytes = original.clone();
            match rng.below(4) {
                // flip some bytes
                0 => {
                    for _ in 0..=rng.below(4) {
                        let i = rng.below(bytes.len());
                        bytes[i] = (rng.next() & 0xff) as u8;
                    }
                }
                // truncate
                1 => bytes.truncate(rng.below(bytes.len())),
                // extend with noise
                2 => {
                    let n = rng.below(64);
                    bytes.extend(rng.bytes(n));
                }
                // overwrite a length byte with an extreme value
                _ => {
                    let i = rng.below(bytes.len());
                    bytes[i] = if rng.next() & 1 == 0 { 0xff } else { 0x84 };
                }
            }
            exercise(&bytes);
        }
    }
}

#[test]
fn absurd_lengths_and_shapes_are_rejected_not_panicked() {
    // long form claiming more length bytes than a usize has
    let nine = [
        0x04, 0x89, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    assert!(snmp::read_tlv(&nine, 0).is_none());
    // a length that would overflow start + len
    let max = [0x04, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(snmp::read_tlv(&max, 0).is_none());
    // indefinite length, truncated length field, position past the end
    assert!(snmp::read_tlv(&[0x04, 0x80], 0).is_none());
    assert!(snmp::read_tlv(&[0x04, 0x82, 0x01], 0).is_none());
    assert!(snmp::read_tlv(&[0x04], 5).is_none());
    assert!(snmp::read_tlv(&[], usize::MAX).is_none());

    // OIDs that cannot be valid still encode without panicking
    assert_eq!(snmp::oid(&[]), snmp::tlv(snmp::TAG_OID, &[]));
    assert_eq!(snmp::oid(&[1]), snmp::tlv(snmp::TAG_OID, &[]));
    let huge = snmp::oid(&[u32::MAX, u32::MAX, u32::MAX]);
    assert_eq!(huge[0], snmp::TAG_OID);
    let (_, body, _) = snmp::read_tlv(&huge, 0).unwrap();
    assert_eq!(body[0], u8::MAX);

    // the longest length the encoder produces round-trips
    let big = vec![0u8; 70_000];
    let encoded = snmp::octet_string(&big);
    let (tag, value, end) = snmp::read_tlv(&encoded, 0).unwrap();
    assert_eq!(
        (tag, value.len(), end),
        (snmp::TAG_OCTET_STRING, 70_000, encoded.len())
    );

    // the dedup table stays bounded under a flood of distinct events
    let mut dedup = daemon::Dedup::default();
    for seq in 0..(daemon::DEDUP_CAPACITY as u64 * 3) {
        assert!(!dedup.is_duplicate(Some(1), Some(seq)));
    }
    assert!(dedup.is_duplicate(Some(1), Some(daemon::DEDUP_CAPACITY as u64 * 3 - 1)));
    assert!(
        !dedup.is_duplicate(Some(1), Some(0)),
        "the oldest entries were dropped"
    );
}
