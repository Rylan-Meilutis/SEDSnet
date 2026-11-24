//! Side-transport chunk frames (kind 0x61) for integration tests:
//! `0x61 | transfer u16 LE | ULEB128 position | bytes | CRC32 LE`, where
//! position = total * (total - 1) / 2 + index.
#![allow(dead_code)]

/// A chunk frame; `transfer` is truncated to its 16-bit wire form.
pub fn chunk_frame(transfer: u32, index: u16, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x61];
    out.extend_from_slice(&(transfer as u16).to_le_bytes());
    let mut position = u64::from(total) * (u64::from(total) - 1) / 2 + u64::from(index);
    loop {
        let byte = (position & 0x7f) as u8;
        position >>= 7;
        if position == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32fast::hash(&out).to_le_bytes());
    out
}

/// `(transfer, index, total, payload)` of a chunk frame.
pub fn parse_chunk(frame: &[u8]) -> Option<(u32, u16, u16, &[u8])> {
    if frame.first() != Some(&0x61) || frame.len() < 9 {
        return None;
    }
    let body = &frame[1..frame.len() - 4];
    let transfer = u32::from(u16::from_le_bytes([body[0], body[1]]));
    let (mut position, mut shift, mut off) = (0u64, 0, 2);
    loop {
        let byte = *body.get(off)?;
        off += 1;
        position |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    let mut total = 1u64;
    while total * (total + 1) / 2 <= position {
        total += 1;
    }
    let index = position - total * (total - 1) / 2;
    Some((transfer, index as u16, total as u16, &body[off..]))
}
