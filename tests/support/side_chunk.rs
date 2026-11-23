//! Side-transport chunk frames (kind 0x03) for integration tests:
//! `"SDT" 0x03 | transfer u16 LE | ULEB128 position | bytes | CRC32 LE`, where
//! position = total * (total - 1) / 2 + index.
#![allow(dead_code)]

/// A chunk frame; `transfer` is truncated to its 16-bit wire form.
pub fn chunk_frame(transfer: u32, index: u16, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = b"SDT\x03".to_vec();
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
    if !frame.starts_with(b"SDT\x03") || frame.len() < 11 {
        return None;
    }
    let body = &frame[4..frame.len() - 4];
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

/// Re-wrap frames captured with the former chunk header (transfer u32, index
/// u16, total u16: 16 bytes of overhead) in the current one: each complete
/// legacy transfer is re-split for `max_frame_bytes` as a current sender
/// would. Other frames pass through unchanged.
pub fn rechunk_legacy(frames: &[Vec<u8>], max_frame_bytes: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pending: Vec<(u32, u16, Vec<u8>)> = Vec::new();
    for frame in frames {
        if !frame.starts_with(b"SDT\x03") {
            out.push(frame.clone());
            continue;
        }
        let body = &frame[4..frame.len() - 4];
        let transfer = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let total = u16::from_le_bytes([body[6], body[7]]);
        pending.push((transfer, total, body[8..].to_vec()));
        let parts: Vec<_> = pending.iter().filter(|p| p.0 == transfer).collect();
        if parts.len() == usize::from(total) {
            let whole: Vec<u8> = parts.iter().flat_map(|p| p.2.clone()).collect();
            pending.retain(|p| p.0 != transfer);
            let (budget, total) = layout(whole.len(), max_frame_bytes);
            for (index, part) in whole.chunks(budget).enumerate() {
                out.push(chunk_frame(transfer, index as u16, total, part));
            }
        }
    }
    out
}

fn layout(len: usize, max_frame_bytes: usize) -> (usize, u16) {
    for position_bytes in 1..=5u32 {
        let budget = max_frame_bytes - 10 - position_bytes as usize;
        let total = len.div_ceil(budget) as u64;
        let position = total * (total - 1) / 2 + total - 1;
        if position < 1u64 << (7 * position_bytes) {
            return (budget, total as u16);
        }
    }
    panic!("too many chunks")
}
