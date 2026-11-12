//! Compact bundle (CB1): several canonical frames in one side frame.
//!
//! A bundle is negotiated per link (see
//! [`crate::discovery::LINK_CAPABILITY_COMPACT_BUNDLE`]) and is stateless: every
//! record decodes from the bundle alone, so no dictionary can be lost or go
//! stale. The receiver rebuilds each canonical frame byte for byte (CRC
//! included), so packet ids, routing, hop and end-to-end reliability and
//! forwarding are unchanged.
//!
//! ```text
//! bundle = MARKER | base_ts ULEB128 | record+ | CRC32-LE(MARKER .. last record)
//! record = len ULEB128 | flags | elide | [nep] | [type ULEB128] | [source u32 LE]
//!        | ts zigzag ULEB128 (delta from the previous record, the first from base_ts)
//!        | [nonce: ULEB128, or zigzag delta from the previous record's nonce]
//!        | [endpoints] | [contract: ULEB128 len | bytes] | [reliable header]
//!        | [logical size ULEB128, only when the payload is compressed] | payload
//! ```
//! `flags` is the canonical flags byte. `elide` bits drop a field that equals
//! the previous record's. `MARKER` sets both the endpoint-bitmap and the
//! endpoint-list flag bits, which no canonical frame can carry, and is not the
//! side-transport magic, so a receiver tells a bundle apart from every other
//! frame by its first byte. One CRC32 covers the whole bundle.
//!
//! The writer bundles only frames that are already waiting, in its priority
//! order, and never an urgent frame (Abort and other turn-bypass traffic go
//! standalone in the legacy format). End-to-end sealed frames are not bundled.

use crate::side_transport::{crc32_bytes, read_uleb128_local, write_uleb128_local};
use crate::{TelemetryError, TelemetryResult};
use alloc::vec::Vec;

/// First byte of a compact bundle.
pub const BUNDLE_MARKER: u8 = 0xA1;
/// Upper bound on records accepted from one bundle.
pub const MAX_BUNDLE_RECORDS: usize = 64;

const F_COMPRESSED: u8 = 0x01;
const F_RELIABLE: u8 = 0x02;
const F_CONTRACT: u8 = 0x04;
const F_NONCE: u8 = 0x08;
const F_E2E: u8 = 0x10;
const F_EP_BITMAP: u8 = 0x20;
const F_COMPACT_RELIABLE: u8 = 0x40;
const F_EP_LIST: u8 = 0x80;
const EP_BITMAP_BYTES: usize = 32;

const E_TYPE: u8 = 0x01;
const E_SOURCE: u8 = 0x02;
const E_CONTRACT: u8 = 0x04;
const E_NONCE_DELTA: u8 = 0x08;
const E_NEP: u8 = 0x10;
const E_ENDPOINTS: u8 = 0x20;
const E_KNOWN: u8 = 0x3F;

const MIN_BUNDLE: usize = 1 + 1 + 1 + 4;

/// Is `bytes` a compact bundle (by its first byte)?
#[inline]
pub fn is_bundle(bytes: &[u8]) -> bool {
    bytes.first() == Some(&BUNDLE_MARKER)
}

#[derive(Clone, Copy)]
struct Canon<'a> {
    flags: u8,
    nep: u8,
    ty: u64,
    size: u64,
    ts: u64,
    nonce: u64,
    src: u32,
    eps: &'a [u8],
    contract: &'a [u8],
    rel: &'a [u8],
    payload: &'a [u8],
}

fn take<'a>(buf: &'a [u8], off: &mut usize, n: usize) -> TelemetryResult<&'a [u8]> {
    let end = off
        .checked_add(n)
        .filter(|end| *end <= buf.len())
        .ok_or(TelemetryError::Unpack("bundle short read"))?;
    let out = &buf[*off..end];
    *off = end;
    Ok(out)
}

fn uleb(buf: &[u8], off: &mut usize) -> TelemetryResult<u64> {
    read_uleb128_local(buf, off)
}

fn span_endpoints<'a>(buf: &'a [u8], off: &mut usize, flags: u8, nep: u8) -> TelemetryResult<&'a [u8]> {
    let start = *off;
    if flags & F_EP_LIST != 0 {
        for _ in 0..nep {
            uleb(buf, off)?;
        }
    } else if flags & F_EP_BITMAP != 0 {
        take(buf, off, EP_BITMAP_BYTES)?;
    }
    Ok(&buf[start..*off])
}

fn span_reliable<'a>(buf: &'a [u8], off: &mut usize, flags: u8) -> TelemetryResult<&'a [u8]> {
    let start = *off;
    if flags & F_RELIABLE != 0 {
        if flags & F_COMPACT_RELIABLE != 0 {
            let wire = take(buf, off, 1)?[0];
            if wire & 0x04 != 0 {
                uleb(buf, off)?;
            }
            if wire & 0x08 != 0 {
                uleb(buf, off)?;
            }
        } else {
            take(buf, off, 9)?;
        }
    }
    Ok(&buf[start..*off])
}

fn parse_canonical(frame: &[u8]) -> TelemetryResult<Canon<'_>> {
    if frame.len() < 4 + 4 {
        return Err(TelemetryError::Unpack("bundle frame too short"));
    }
    let data_len = frame.len() - 4;
    let crc = u32::from_le_bytes(frame[data_len..].try_into().expect("4-byte crc"));
    let data = &frame[..data_len];
    if crc32_bytes(data) != crc {
        return Err(TelemetryError::Unpack("bundle frame crc"));
    }
    let mut off = 0usize;
    let flags = take(data, &mut off, 1)?[0];
    if flags & F_E2E != 0 || flags & (F_EP_BITMAP | F_EP_LIST) == (F_EP_BITMAP | F_EP_LIST) {
        return Err(TelemetryError::Unpack("frame not bundleable"));
    }
    let nep = take(data, &mut off, 1)?[0];
    let ty = uleb(data, &mut off)?;
    let size = uleb(data, &mut off)?;
    let ts = uleb(data, &mut off)?;
    let nonce = if flags & F_NONCE != 0 { uleb(data, &mut off)? } else { 0 };
    let src = u32::try_from(uleb(data, &mut off)?)
        .map_err(|_| TelemetryError::Unpack("frame not bundleable"))?;
    let eps = span_endpoints(data, &mut off, flags, nep)?;
    let contract = if flags & F_CONTRACT != 0 {
        let n = usize::try_from(uleb(data, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("bundle contract length"))?;
        take(data, &mut off, n)?
    } else {
        &[]
    };
    let rel = span_reliable(data, &mut off, flags)?;
    let payload = &data[off..];
    if flags & F_COMPRESSED == 0 && size != payload.len() as u64 {
        return Err(TelemetryError::Unpack("frame not bundleable"));
    }
    Ok(Canon { flags, nep, ty, size, ts, nonce, src, eps, contract, rel, payload })
}

/// Whether `frame` can travel inside a bundle: a canonical (not side-wrapped),
/// CRC-valid, unsealed frame. Urgency is the writer's decision: it keeps
/// urgent frames out before asking.
pub fn frame_bundleable(frame: &[u8]) -> bool {
    !frame.starts_with(b"SDT") && parse_canonical(frame).is_ok()
}

#[inline]
fn zigzag(delta: i64) -> u64 {
    ((delta << 1) ^ (delta >> 63)) as u64
}

#[inline]
fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

fn encode_record(c: &Canon<'_>, prev: Option<&Canon<'_>>, prev_ts: u64, out: &mut Vec<u8>) {
    let mut elide = 0u8;
    if let Some(p) = prev {
        if p.ty == c.ty {
            elide |= E_TYPE;
        }
        if p.src == c.src {
            elide |= E_SOURCE;
            if c.flags & F_NONCE != 0 && p.flags & F_NONCE != 0 {
                elide |= E_NONCE_DELTA;
            }
        }
        if c.flags & F_CONTRACT != 0 && p.flags & F_CONTRACT != 0 && p.contract == c.contract {
            elide |= E_CONTRACT;
        }
        if p.nep == c.nep {
            elide |= E_NEP;
        }
        if c.flags & (F_EP_BITMAP | F_EP_LIST) != 0
            && p.nep == c.nep
            && p.flags & (F_EP_BITMAP | F_EP_LIST) == c.flags & (F_EP_BITMAP | F_EP_LIST)
            && p.eps == c.eps
        {
            elide |= E_ENDPOINTS;
        }
    }
    out.push(c.flags);
    out.push(elide);
    if elide & E_NEP == 0 {
        out.push(c.nep);
    }
    if elide & E_TYPE == 0 {
        write_uleb128_local(c.ty, out);
    }
    if elide & E_SOURCE == 0 {
        out.extend_from_slice(&c.src.to_le_bytes());
    }
    write_uleb128_local(zigzag(c.ts.wrapping_sub(prev_ts) as i64), out);
    if c.flags & F_NONCE != 0 {
        if elide & E_NONCE_DELTA != 0 {
            let p = prev.expect("delta needs a previous record");
            write_uleb128_local(zigzag(c.nonce.wrapping_sub(p.nonce) as i64), out);
        } else {
            write_uleb128_local(c.nonce, out);
        }
    }
    if elide & E_ENDPOINTS == 0 {
        out.extend_from_slice(c.eps);
    }
    if c.flags & F_CONTRACT != 0 && elide & E_CONTRACT == 0 {
        write_uleb128_local(c.contract.len() as u64, out);
        out.extend_from_slice(c.contract);
    }
    out.extend_from_slice(c.rel);
    if c.flags & F_COMPRESSED != 0 {
        write_uleb128_local(c.size, out);
    }
    out.extend_from_slice(c.payload);
}

/// Pack canonical frames, in the given order, into one bundle.
///
/// Fails with `TelemetryError::BadArg` when `frames` is empty or holds more
/// than [`MAX_BUNDLE_RECORDS`], and with `Unpack("frame not bundleable")` (or a
/// CRC error) when a frame is not a valid canonical frame; the writer then
/// sends that frame on its own.
pub fn pack_bundle(frames: &[&[u8]]) -> TelemetryResult<Vec<u8>> {
    if frames.is_empty() || frames.len() > MAX_BUNDLE_RECORDS {
        return Err(TelemetryError::BadArg);
    }
    let mut canon = Vec::with_capacity(frames.len());
    let mut total = 0usize;
    for frame in frames {
        if frame.starts_with(b"SDT") {
            return Err(TelemetryError::Unpack("frame not bundleable"));
        }
        canon.push(parse_canonical(frame)?);
        total += frame.len();
    }
    let mut out = Vec::with_capacity(total + 16);
    out.push(BUNDLE_MARKER);
    let base = canon[0].ts;
    write_uleb128_local(base, &mut out);
    let mut record = Vec::with_capacity(64);
    let mut prev_ts = base;
    for (i, c) in canon.iter().enumerate() {
        record.clear();
        encode_record(c, i.checked_sub(1).map(|p| &canon[p]), prev_ts, &mut record);
        prev_ts = c.ts;
        write_uleb128_local(record.len() as u64, &mut out);
        out.extend_from_slice(&record);
    }
    let crc = crc32_bytes(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

#[derive(Clone, Copy, Default)]
struct Prev<'a> {
    ty: u64,
    src: u32,
    nonce: u64,
    has_nonce: bool,
    contract: Option<&'a [u8]>,
    nep: u8,
    eps: &'a [u8],
    ep_flags: u8,
}

fn rebuild_record<'a>(
    rec: &'a [u8],
    prev: Option<&Prev<'a>>,
    prev_ts: u64,
    out: &mut Vec<u8>,
) -> TelemetryResult<(Prev<'a>, u64)> {
    let mut off = 0usize;
    let flags = take(rec, &mut off, 1)?[0];
    let elide = take(rec, &mut off, 1)?[0];
    if elide & !E_KNOWN != 0 || (prev.is_none() && elide != 0) {
        return Err(TelemetryError::Unpack("bundle elide bits"));
    }
    if flags & F_E2E != 0 || flags & (F_EP_BITMAP | F_EP_LIST) == (F_EP_BITMAP | F_EP_LIST) {
        return Err(TelemetryError::Unpack("bundle record flags"));
    }
    let p = prev.copied().unwrap_or_default();
    let nep = if elide & E_NEP != 0 { p.nep } else { take(rec, &mut off, 1)?[0] };
    let ty = if elide & E_TYPE != 0 { p.ty } else { uleb(rec, &mut off)? };
    let src = if elide & E_SOURCE != 0 {
        p.src
    } else {
        u32::from_le_bytes(take(rec, &mut off, 4)?.try_into().expect("4-byte source"))
    };
    let ts = prev_ts.wrapping_add(unzigzag(uleb(rec, &mut off)?) as u64);
    let nonce = if flags & F_NONCE != 0 {
        let v = uleb(rec, &mut off)?;
        if elide & E_NONCE_DELTA != 0 {
            if !p.has_nonce || elide & E_SOURCE == 0 {
                return Err(TelemetryError::Unpack("bundle nonce delta"));
            }
            p.nonce.wrapping_add(unzigzag(v) as u64)
        } else {
            v
        }
    } else if elide & E_NONCE_DELTA != 0 {
        return Err(TelemetryError::Unpack("bundle nonce delta"));
    } else {
        0
    };
    if flags & F_NONCE != 0 && nonce > u64::from(u16::MAX) {
        return Err(TelemetryError::Unpack("bundle nonce"));
    }
    let ep_flags = flags & (F_EP_BITMAP | F_EP_LIST);
    let eps = if elide & E_ENDPOINTS != 0 {
        if ep_flags == 0 || p.ep_flags != ep_flags || nep != p.nep {
            return Err(TelemetryError::Unpack("bundle endpoints"));
        }
        p.eps
    } else {
        span_endpoints(rec, &mut off, flags, nep)?
    };
    let contract = if flags & F_CONTRACT != 0 {
        if elide & E_CONTRACT != 0 {
            p.contract.ok_or(TelemetryError::Unpack("bundle contract"))?
        } else {
            let n = usize::try_from(uleb(rec, &mut off)?)
                .map_err(|_| TelemetryError::Unpack("bundle contract length"))?;
            take(rec, &mut off, n)?
        }
    } else if elide & E_CONTRACT != 0 {
        return Err(TelemetryError::Unpack("bundle contract"));
    } else {
        &[]
    };
    let rel = span_reliable(rec, &mut off, flags)?;
    let size = if flags & F_COMPRESSED != 0 { Some(uleb(rec, &mut off)?) } else { None };
    let payload = &rec[off..];
    let size = size.unwrap_or(payload.len() as u64);

    out.clear();
    out.push(flags);
    out.push(nep);
    write_uleb128_local(ty, out);
    write_uleb128_local(size, out);
    write_uleb128_local(ts, out);
    if flags & F_NONCE != 0 {
        write_uleb128_local(nonce, out);
    }
    write_uleb128_local(u64::from(src), out);
    out.extend_from_slice(eps);
    if flags & F_CONTRACT != 0 {
        write_uleb128_local(contract.len() as u64, out);
        out.extend_from_slice(contract);
    }
    out.extend_from_slice(rel);
    out.extend_from_slice(payload);
    let crc = crc32_bytes(out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok((
        Prev {
            ty,
            src,
            nonce,
            has_nonce: flags & F_NONCE != 0,
            contract: (flags & F_CONTRACT != 0).then_some(contract),
            nep,
            eps,
            ep_flags,
        },
        ts,
    ))
}

/// Verify a bundle and hand each rebuilt canonical frame to `each`, in order.
///
/// The whole bundle is checked (CRC and every record) before the first frame
/// is delivered, so a damaged bundle delivers nothing. Returns the number of
/// frames delivered.
pub fn unpack_bundle(
    bytes: &[u8],
    mut each: impl FnMut(&[u8]) -> TelemetryResult<()>,
) -> TelemetryResult<usize> {
    let frames = unpack_bundle_frames(bytes)?;
    for frame in &frames {
        each(frame)?;
    }
    Ok(frames.len())
}

/// Verify a bundle and return its rebuilt canonical frames.
pub fn unpack_bundle_frames(bytes: &[u8]) -> TelemetryResult<Vec<Vec<u8>>> {
    if bytes.len() < MIN_BUNDLE || !is_bundle(bytes) {
        return Err(TelemetryError::Unpack("short bundle"));
    }
    let data_len = bytes.len() - 4;
    let crc = u32::from_le_bytes(bytes[data_len..].try_into().expect("4-byte crc"));
    let data = &bytes[..data_len];
    if crc32_bytes(data) != crc {
        return Err(TelemetryError::Unpack("bundle crc32 mismatch"));
    }
    let mut off = 1usize;
    let mut prev_ts = uleb(data, &mut off)?;
    let mut prev: Option<Prev<'_>> = None;
    let mut frames = Vec::new();
    while off < data.len() {
        if frames.len() == MAX_BUNDLE_RECORDS {
            return Err(TelemetryError::Unpack("bundle has too many records"));
        }
        let n = usize::try_from(uleb(data, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("bundle record length"))?;
        let rec = take(data, &mut off, n)?;
        let mut out = Vec::with_capacity(n + 16);
        let (p, ts) = rebuild_record(rec, prev.as_ref(), prev_ts, &mut out)?;
        prev = Some(p);
        prev_ts = ts;
        frames.push(out);
    }
    if frames.is_empty() {
        return Err(TelemetryError::Unpack("empty bundle"));
    }
    Ok(frames)
}
