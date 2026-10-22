//! Minimal SNMPv1 / BER encoder and decoder, just enough for the Brother
//! Scan-to-PC registration (an SNMPv1 set-request with OCTET STRING bindings).
//!
//! Reverse-engineered from packet captures (BrotherScannerDocker issue #10) and
//! the `brscan-skey` binary's strings; no Brother code is used here. See
//! PROTOCOL.md for the wire format.

// --- BER tags ---------------------------------------------------------------
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_GET_REQUEST: u8 = 0xA0;
pub const TAG_GET_RESPONSE: u8 = 0xA2;
pub const TAG_SET_REQUEST: u8 = 0xA3;

/// BER definite length encoding.
pub fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// A tag-length-value element.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

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

pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, value)
}

pub fn null() -> Vec<u8> {
    tlv(TAG_NULL, &[])
}

/// Encode an object identifier (e.g. `[1,3,6,1,4,1,2435,...]`).
pub fn oid(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "OID needs at least two arcs");
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        body.extend_from_slice(&base128(arc));
    }
    tlv(TAG_OID, &body)
}

/// Base-128, big-endian, continuation bit on every byte but the last.
fn base128(mut v: u32) -> Vec<u8> {
    let mut bytes = vec![(v & 0x7f) as u8];
    v >>= 7;
    while v > 0 {
        bytes.insert(0, ((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    bytes
}

pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, content)
}

/// One `VarBind`: SEQUENCE { OID, value }.
pub fn varbind(oid_arcs: &[u32], value: &[u8]) -> Vec<u8> {
    let mut inner = oid(oid_arcs);
    inner.extend_from_slice(value);
    sequence(&inner)
}

/// Assemble a full SNMPv1 message.
/// `pdu_tag` is e.g. `TAG_SET_REQUEST`; `varbinds` are already-encoded VarBind elements.
pub fn message(community: &str, pdu_tag: u8, request_id: i64, varbinds: &[Vec<u8>]) -> Vec<u8> {
    let mut vb_list = Vec::new();
    for vb in varbinds {
        vb_list.extend_from_slice(vb);
    }
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&integer(request_id)); // request-id
    pdu.extend_from_slice(&integer(0)); // error-status
    pdu.extend_from_slice(&integer(0)); // error-index
    pdu.extend_from_slice(&sequence(&vb_list)); // variable-bindings
    let pdu = tlv(pdu_tag, &pdu);

    let mut body = Vec::new();
    body.extend_from_slice(&integer(0)); // version: SNMPv1 (0)
    body.extend_from_slice(&octet_string(community.as_bytes()));
    body.extend_from_slice(&pdu);
    sequence(&body)
}

// --- Minimal decoder (used by the mock device and tests) --------------------

/// Read one TLV at `data[pos]`. Returns (tag, value_slice, next_pos).
pub fn read_tlv(data: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    if pos + 2 > data.len() {
        return None;
    }
    let tag = data[pos];
    let first = data[pos + 1];
    let (len, len_bytes) = if first < 0x80 {
        (first as usize, 1usize)
    } else {
        let n = (first & 0x7f) as usize;
        if pos + 2 + n > data.len() {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | data[pos + 2 + i] as usize;
        }
        (l, 1 + n)
    };
    let start = pos + 1 + len_bytes;
    let end = start + len;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[start..end], end))
}

/// Decode an OID value (the content of an OID TLV) back to its arcs.
pub fn decode_oid(body: &[u8]) -> Vec<u32> {
    let mut arcs = Vec::new();
    if body.is_empty() {
        return arcs;
    }
    arcs.push(body[0] as u32 / 40);
    arcs.push(body[0] as u32 % 40);
    let mut v = 0u32;
    for &b in &body[1..] {
        v = (v << 7) | (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            arcs.push(v);
            v = 0;
        }
    }
    arcs
}

/// Extract the (OID, OCTET STRING value) pairs from an SNMP message, for tests
/// and the mock device. Returns an empty vector if the structure is unexpected.
pub fn extract_string_varbinds(data: &[u8]) -> Vec<(Vec<u32>, String)> {
    let mut out = Vec::new();
    // message SEQUENCE
    let Some((TAG_SEQUENCE, msg, _)) = read_tlv(data, 0) else {
        return out;
    };
    // version INTEGER
    let Some((_, _, p1)) = read_tlv(msg, 0) else {
        return out;
    };
    // community OCTET STRING
    let Some((_, _, p2)) = read_tlv(msg, p1) else {
        return out;
    };
    // pdu (context tag)
    let Some((_pdu_tag, pdu, _)) = read_tlv(msg, p2) else {
        return out;
    };
    // request-id, error-status, error-index, then varbind-list SEQUENCE
    let Some((_, _, q1)) = read_tlv(pdu, 0) else {
        return out;
    };
    let Some((_, _, q2)) = read_tlv(pdu, q1) else {
        return out;
    };
    let Some((_, _, q3)) = read_tlv(pdu, q2) else {
        return out;
    };
    let Some((TAG_SEQUENCE, vblist, _)) = read_tlv(pdu, q3) else {
        return out;
    };
    let mut pos = 0;
    while let Some((TAG_SEQUENCE, vb, next)) = read_tlv(vblist, pos) {
        pos = next;
        if let Some((TAG_OID, oid_body, after_oid)) = read_tlv(vb, 0) {
            if let Some((TAG_OCTET_STRING, val, _)) = read_tlv(vb, after_oid) {
                out.push((
                    decode_oid(oid_body),
                    String::from_utf8_lossy(val).into_owned(),
                ));
            }
        }
    }
    out
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
}
