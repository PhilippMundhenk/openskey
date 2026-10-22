//! Minimal `SNMPv1` / BER encoder and decoder.
//!
//! Just enough for the Brother Scan-to-PC registration (an `SNMPv1`
//! set-request with OCTET STRING bindings) and for reading the device's
//! status objects (get-request / get-response).
//!
//! Reverse-engineered from packet captures (`BrotherScannerDocker` issue #10) and
//! the `brscan-skey` binary's strings; no Brother code is used here. See
//! PROTOCOL.md for the wire format.

// --- BER tags ---------------------------------------------------------------
/// BER tag of an INTEGER.
pub const TAG_INTEGER: u8 = 0x02;
/// BER tag of an OCTET STRING.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// BER tag of NULL (the value of a get-request binding).
pub const TAG_NULL: u8 = 0x05;
/// BER tag of an OBJECT IDENTIFIER.
pub const TAG_OID: u8 = 0x06;
/// BER tag of a SEQUENCE.
pub const TAG_SEQUENCE: u8 = 0x30;
/// SNMP PDU tag of a get-request.
pub const TAG_GET_REQUEST: u8 = 0xA0;
/// SNMP PDU tag of a get-response.
pub const TAG_GET_RESPONSE: u8 = 0xA2;
/// SNMP PDU tag of a set-request.
pub const TAG_SET_REQUEST: u8 = 0xA3;
// Application types a device may return in a get-response.
/// SNMP application type `IpAddress`.
pub const TAG_IP_ADDRESS: u8 = 0x40;
/// SNMP application type `Counter32`.
pub const TAG_COUNTER32: u8 = 0x41;
/// SNMP application type `Gauge32`.
pub const TAG_GAUGE32: u8 = 0x42;
/// SNMP application type `TimeTicks`.
pub const TAG_TIMETICKS: u8 = 0x43;

/// The longest BER length the decoder accepts, in bytes of the length field:
/// a `usize` can hold no more, and no SNMP datagram comes anywhere near it.
const MAX_LENGTH_BYTES: usize = std::mem::size_of::<usize>();

/// A decoded variable-binding value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// INTEGER, and the unsigned application integers (`Counter32`,
    /// `Gauge32`, `TimeTicks`).
    Int(i64),
    /// OCTET STRING, and `IpAddress` (four raw bytes).
    OctetString(Vec<u8>),
    /// OBJECT IDENTIFIER, as its arcs.
    Oid(Vec<u32>),
    /// NULL (a get-request binding's placeholder).
    Null,
    /// Any other tag, kept as raw bytes so nothing is silently lost.
    Other(u8, Vec<u8>),
}

impl Value {
    /// The value as UTF-8 text, for OCTET STRING objects (lossy).
    #[must_use]
    pub fn as_text(&self) -> Option<String> {
        match self {
            Self::OctetString(b) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    }

    /// The value as raw bytes, for OCTET STRING objects (e.g. the packed
    /// Brother `brInfo*` blobs).
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::OctetString(b) | Self::Other(_, b) => Some(b),
            _ => None,
        }
    }

    /// The value as an integer, for INTEGER / Counter32 / Gauge32 / `TimeTicks`.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }
}

/// A decoded SNMP message.
#[derive(Debug, Clone)]
pub struct Message {
    /// The community string (`internal` on Brother devices).
    pub community: String,
    /// The PDU type: one of the `TAG_*_REQUEST` / `TAG_GET_RESPONSE` tags.
    pub pdu_tag: u8,
    /// The request id the other side echoes back.
    pub request_id: i64,
    /// The error status, 0 when the request succeeded.
    pub error_status: i64,
    /// The variable bindings, as (OID arcs, value) pairs.
    pub varbinds: Vec<(Vec<u32>, Value)>,
}

/// BER definite length encoding.
#[must_use]
pub fn encode_len(len: usize) -> Vec<u8> {
    // Short form: one byte below 0x80.
    if let Ok(short) = u8::try_from(len) {
        if short < 0x80 {
            return vec![short];
        }
    }
    // Long form: 0x80 | number of length bytes, then the length big-endian
    // without leading zeros (at most `size_of::<usize>()` bytes, so the count
    // always fits the 7 bits).
    let bytes: Vec<u8> = len
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect();
    let count = u8::try_from(bytes.len()).unwrap_or(0x7f);
    let mut out = vec![0x80 | count];
    out.extend_from_slice(&bytes);
    out
}

/// A tag-length-value element.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode an INTEGER.
#[must_use]
pub fn integer(value: i64) -> Vec<u8> {
    // Minimal two's-complement big-endian, keeping a leading sign byte correct.
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    tlv(TAG_INTEGER, &bytes)
}

/// Encode an OCTET STRING.
#[must_use]
pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, value)
}

/// Encode NULL.
#[must_use]
pub fn null() -> Vec<u8> {
    tlv(TAG_NULL, &[])
}

/// Encode a decoded [`Value`] back to BER, for building get-responses.
#[must_use]
pub fn encode_value(value: &Value) -> Vec<u8> {
    match value {
        Value::Int(v) => integer(*v),
        Value::OctetString(b) => octet_string(b),
        Value::Oid(arcs) => oid(arcs),
        Value::Null => null(),
        Value::Other(tag, b) => tlv(*tag, b),
    }
}

/// Encode an object identifier (e.g. `[1,3,6,1,4,1,2435,...]`).
///
/// Never panics: fewer than two arcs give an empty (invalid but harmless)
/// OID body, and a first pair that does not fit one byte is saturated, so a
/// value decoded from an untrusted packet can always be re-encoded.
#[must_use]
pub fn oid(arcs: &[u32]) -> Vec<u8> {
    let [first, second, rest @ ..] = arcs else {
        return tlv(TAG_OID, &[]);
    };
    let head = first.saturating_mul(40).saturating_add(*second);
    let mut body = vec![u8::try_from(head).unwrap_or(u8::MAX)];
    for &arc in rest {
        body.extend_from_slice(&base128(arc));
    }
    tlv(TAG_OID, &body)
}

/// Base-128, big-endian, continuation bit on every byte but the last.
fn base128(mut v: u32) -> Vec<u8> {
    // Every byte is masked to seven bits before the narrowing, so nothing is
    // lost.
    #[allow(clippy::cast_possible_truncation)]
    let low = |v: u32| (v & 0x7f) as u8;
    let mut bytes = vec![low(v)];
    v >>= 7;
    while v > 0 {
        bytes.insert(0, low(v) | 0x80);
        v >>= 7;
    }
    bytes
}

/// Encode a SEQUENCE around already-encoded content.
#[must_use]
pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, content)
}

/// One `VarBind`: SEQUENCE { OID, value }.
#[must_use]
pub fn varbind(oid_arcs: &[u32], value: &[u8]) -> Vec<u8> {
    let mut inner = oid(oid_arcs);
    inner.extend_from_slice(value);
    sequence(&inner)
}

/// `SNMPv1` error-status `noSuchName`: the requested object does not exist.
pub const ERR_NO_SUCH_NAME: i64 = 2;

/// Assemble a full `SNMPv1` message.
/// `pdu_tag` is e.g. `TAG_SET_REQUEST`; `varbinds` are already-encoded `VarBind` elements.
#[must_use]
pub fn message(community: &str, pdu_tag: u8, request_id: i64, varbinds: &[Vec<u8>]) -> Vec<u8> {
    message_with_error(community, pdu_tag, request_id, 0, 0, varbinds)
}

/// Like [`message`], with an explicit error-status / error-index (used by the
/// mock device to answer `noSuchName` like a real agent does).
#[must_use]
pub fn message_with_error(
    community: &str,
    pdu_tag: u8,
    request_id: i64,
    error_status: i64,
    error_index: i64,
    varbinds: &[Vec<u8>],
) -> Vec<u8> {
    let mut vb_list = Vec::new();
    for vb in varbinds {
        vb_list.extend_from_slice(vb);
    }
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&integer(request_id)); // request-id
    pdu.extend_from_slice(&integer(error_status)); // error-status
    pdu.extend_from_slice(&integer(error_index)); // error-index
    pdu.extend_from_slice(&sequence(&vb_list)); // variable-bindings
    let pdu = tlv(pdu_tag, &pdu);

    let mut body = Vec::new();
    body.extend_from_slice(&integer(0)); // version: SNMPv1 (0)
    body.extend_from_slice(&octet_string(community.as_bytes()));
    body.extend_from_slice(&pdu);
    sequence(&body)
}

/// Build an `SNMPv1` get-request for one or more OIDs (values are NULL).
#[must_use]
pub fn get_request(community: &str, request_id: i64, oids: &[&[u32]]) -> Vec<u8> {
    let varbinds: Vec<Vec<u8>> = oids.iter().map(|o| varbind(o, &null())).collect();
    message(community, TAG_GET_REQUEST, request_id, &varbinds)
}

// --- Decoder ----------------------------------------------------------------

/// Read one TLV at `data[pos]`. Returns (tag, `value_slice`, `next_pos`).
///
/// Every length is checked against the buffer and every addition is
/// checked, so a crafted datagram can only make this return `None`.
#[must_use]
pub fn read_tlv(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *data.get(pos)?;
    let first = *data.get(pos.checked_add(1)?)?;
    let (len, len_bytes) = if first < 0x80 {
        (usize::from(first), 1usize)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > MAX_LENGTH_BYTES {
            // indefinite length (not used by SNMP) or absurdly long
            return None;
        }
        let first_len_byte = pos.checked_add(2)?;
        let bytes = data.get(first_len_byte..first_len_byte.checked_add(n)?)?;
        let len = bytes.iter().fold(0usize, |l, &b| (l << 8) | usize::from(b));
        (len, n.checked_add(1)?)
    };
    let start = pos.checked_add(1)?.checked_add(len_bytes)?;
    let end = start.checked_add(len)?;
    let value = data.get(start..end)?;
    Some((tag, value, end))
}

/// Decode an OID value (the content of an OID TLV) back to its arcs.
#[must_use]
pub fn decode_oid(body: &[u8]) -> Vec<u32> {
    let mut arcs = Vec::new();
    if body.is_empty() {
        return arcs;
    }
    arcs.push(u32::from(body[0]) / 40);
    arcs.push(u32::from(body[0]) % 40);
    let mut v = 0u32;
    for &b in &body[1..] {
        v = (v << 7) | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(v);
            v = 0;
        }
    }
    arcs
}

/// Decode a signed big-endian integer (INTEGER); also used for the unsigned
/// application integers (Counter32/Gauge32/TimeTicks) where the sign never
/// matters for the values we read.
fn decode_int(body: &[u8]) -> i64 {
    if body.is_empty() {
        return 0;
    }
    let mut v = if body[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in body {
        v = (v << 8) | i64::from(b);
    }
    v
}

fn decode_value(tag: u8, body: &[u8]) -> Value {
    match tag {
        TAG_INTEGER | TAG_COUNTER32 | TAG_GAUGE32 | TAG_TIMETICKS => Value::Int(decode_int(body)),
        TAG_OCTET_STRING | TAG_IP_ADDRESS => Value::OctetString(body.to_vec()),
        TAG_OID => Value::Oid(decode_oid(body)),
        TAG_NULL => Value::Null,
        other => Value::Other(other, body.to_vec()),
    }
}

/// Fully decode an SNMP message into its community, PDU type, ids and the list
/// of (OID, value) bindings. Returns None if the structure is not as expected.
#[must_use]
pub fn decode_message(data: &[u8]) -> Option<Message> {
    let (TAG_SEQUENCE, msg, _) = read_tlv(data, 0)? else {
        return None;
    };
    // version INTEGER
    let (_, _, p1) = read_tlv(msg, 0)?;
    // community OCTET STRING
    let (_, community_b, p2) = read_tlv(msg, p1)?;
    // pdu (context tag)
    let (pdu_tag, pdu, _) = read_tlv(msg, p2)?;
    // request-id, error-status, error-index, then varbind-list SEQUENCE
    let (_, reqid_b, q1) = read_tlv(pdu, 0)?;
    let (_, errstat_b, q2) = read_tlv(pdu, q1)?;
    let (_, _errindex_b, q3) = read_tlv(pdu, q2)?;
    let (TAG_SEQUENCE, vblist, _) = read_tlv(pdu, q3)? else {
        return None;
    };

    let mut varbinds = Vec::new();
    let mut pos = 0;
    while let Some((TAG_SEQUENCE, vb, next)) = read_tlv(vblist, pos) {
        pos = next;
        if let Some((TAG_OID, oid_body, after_oid)) = read_tlv(vb, 0) {
            if let Some((vtag, vbody, _)) = read_tlv(vb, after_oid) {
                varbinds.push((decode_oid(oid_body), decode_value(vtag, vbody)));
            }
        }
    }

    Some(Message {
        community: String::from_utf8_lossy(community_b).into_owned(),
        pdu_tag,
        request_id: decode_int(reqid_b),
        error_status: decode_int(errstat_b),
        varbinds,
    })
}

/// Extract the (OID, OCTET STRING value) pairs from an SNMP message, for tests
/// and the mock device. Returns an empty vector if the structure is unexpected.
#[must_use]
pub fn extract_string_varbinds(data: &[u8]) -> Vec<(Vec<u32>, String)> {
    let Some(msg) = decode_message(data) else {
        return Vec::new();
    };
    msg.varbinds
        .into_iter()
        .filter_map(|(oid, value)| value.as_text().map(|s| (oid, s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_encoding() {
        assert_eq!(encode_len(5), vec![5]);
        assert_eq!(encode_len(0x80), vec![0x81, 0x80]);
        assert_eq!(encode_len(0x1ff), vec![0x82, 0x01, 0xff]);
    }

    #[test]
    fn brother_oid_roundtrips() {
        let arcs = [1u32, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 11, 1, 1, 0];
        let encoded = oid(&arcs);
        assert_eq!(encoded[0], TAG_OID);
        // 2435 must be the two-byte base-128 sequence 0x93 0x03
        let body = &encoded[2..];
        assert_eq!(&body[0..6], &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x93]);
        assert_eq!(body[6], 0x03);
        let (_, oid_body, _) = read_tlv(&encoded, 0).unwrap();
        assert_eq!(decode_oid(oid_body), arcs);
    }

    #[test]
    fn integer_is_minimal() {
        assert_eq!(integer(0), vec![TAG_INTEGER, 1, 0]);
        assert_eq!(integer(201), vec![TAG_INTEGER, 2, 0, 201]);
        assert_eq!(integer(127), vec![TAG_INTEGER, 1, 127]);
    }

    #[test]
    fn get_request_decodes_back_to_its_oids() {
        let a: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        let b: &[u32] = &[1, 3, 6, 1, 4, 1, 2435, 2, 3, 9, 2, 11, 1, 1, 0];
        let pkt = get_request("internal", 7, &[a, b]);
        let msg = decode_message(&pkt).expect("decodes");
        assert_eq!(msg.pdu_tag, TAG_GET_REQUEST);
        assert_eq!(msg.request_id, 7);
        assert_eq!(msg.community, "internal");
        assert_eq!(msg.varbinds.len(), 2);
        assert_eq!(msg.varbinds[0].0, a.to_vec());
        assert_eq!(msg.varbinds[1].0, b.to_vec());
        assert_eq!(msg.varbinds[0].1, Value::Null);
    }

    #[test]
    fn decodes_typed_response_values() {
        let oid_s: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        let oid_i: &[u32] = &[1, 3, 6, 1, 4, 1, 2435, 9, 9];
        let varbinds = vec![
            varbind(oid_s, &octet_string(b"Brother MFC-L2700DW series")),
            varbind(oid_i, &tlv(TAG_COUNTER32, &[0x00, 0x5a, 0xa5])),
        ];
        let pkt = message("internal", TAG_GET_RESPONSE, 7, &varbinds);
        let msg = decode_message(&pkt).expect("decodes");
        assert_eq!(msg.pdu_tag, TAG_GET_RESPONSE);
        assert_eq!(
            msg.varbinds[0].1.as_text().as_deref(),
            Some("Brother MFC-L2700DW series")
        );
        assert_eq!(msg.varbinds[1].1.as_int(), Some(23205));
    }

    #[test]
    fn long_lengths_and_negative_integers_roundtrip() {
        let big = vec![0x41u8; 300];
        let pkt = message(
            "internal",
            TAG_GET_RESPONSE,
            1,
            &[varbind(&[1, 3, 6, 1], &octet_string(&big))],
        );
        let msg = decode_message(&pkt).unwrap();
        assert_eq!(msg.varbinds[0].1.as_bytes().unwrap().len(), 300);
        for value in [-1i64, -129, 255, 65536, i64::MIN / 2] {
            let encoded = integer(value);
            let (tag, body, _) = read_tlv(&encoded, 0).unwrap();
            assert_eq!(tag, TAG_INTEGER);
            assert_eq!(decode_value(tag, body), Value::Int(value), "{value}");
        }
        assert_eq!(decode_value(TAG_INTEGER, &[]), Value::Int(0));
    }

    #[test]
    fn value_accessors_and_other_tags() {
        let other = Value::Other(0x47, vec![1, 2]);
        assert_eq!(other.as_bytes(), Some(&[1u8, 2][..]));
        assert_eq!(other.as_text(), None);
        assert_eq!(other.as_int(), None);
        assert_eq!(Value::Null.as_bytes(), None);
        assert_eq!(encode_value(&Value::Null), null());
        assert_eq!(encode_value(&Value::Oid(vec![1, 3, 6])), oid(&[1, 3, 6]));
        assert_eq!(encode_value(&other), tlv(0x47, &[1, 2]));
        assert_eq!(decode_value(0x47, &[9]), Value::Other(0x47, vec![9]));
        assert_eq!(
            decode_value(TAG_OID, &[0x2b, 0x06]),
            Value::Oid(vec![1, 3, 6])
        );
        assert_eq!(
            decode_value(TAG_IP_ADDRESS, &[10, 0, 0, 1])
                .as_bytes()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(decode_oid(&[]), [] as [u32; 0]);
    }

    #[test]
    fn malformed_input_decodes_to_nothing() {
        assert!(decode_message(b"").is_none());
        assert!(decode_message(b"\x30").is_none());
        assert!(decode_message(b"\x04\x01x").is_none(), "not a SEQUENCE");
        assert!(decode_message(b"\x30\x02\x02\x01").is_none(), "truncated");
        // a message whose PDU lacks the varbind list
        let pdu = tlv(
            TAG_GET_REQUEST,
            &[integer(1), integer(0), integer(0)].concat(),
        );
        let msg = sequence(&[integer(0), octet_string(b"c"), pdu].concat());
        assert!(decode_message(&msg).is_none());
        // long-form length that claims more than there is
        assert!(read_tlv(&[0x04, 0x82, 0x01, 0x00, 0x41], 0).is_none());
        assert!(read_tlv(&[0x04, 0x82], 0).is_none());
        assert_eq!(
            extract_string_varbinds(b"junk"),
            [] as [(std::vec::Vec<u32>, std::string::String); 0]
        );
    }
}
