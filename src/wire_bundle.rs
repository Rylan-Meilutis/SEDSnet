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
//! record = len ULEB128 | flags | elide | [nep] | [type ULEB128]
//!        | [logical size ULEB128, only when the payload is compressed]
//!        | ts zigzag ULEB128 (delta from the previous record, the first from base_ts)
//!        | [nonce: ULEB128, or zigzag delta from the previous record's nonce]
//!        | [source ULEB128] | [endpoints] | [contract: ULEB128 len | bytes]
//!        | [reliable header] | payload
//! ```
//! Fields are in canonical order, so one reader and one writer serve both
//! forms (the canonical frame has no `elide`, always a size, an absolute
//! timestamp and nonce, and its own CRC32).
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

// Out-of-line writers: inlined Vec growth at every field cost the RF image
// about a kilobyte.
#[inline(never)]
fn put_uleb(out: &mut Vec<u8>, v: u64) {
    write_uleb128_local(v, out);
}
#[inline(never)]
fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}
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
const F_EPS: u8 = F_EP_BITMAP | F_EP_LIST;
const EP_BITMAP_BYTES: usize = 32;

const E_TYPE: u8 = 0x01;
const E_SOURCE: u8 = 0x02;
const E_CONTRACT: u8 = 0x04;
const E_NONCE_DELTA: u8 = 0x08;
const E_NEP: u8 = 0x10;
const E_ENDPOINTS: u8 = 0x20;
const E_KNOWN: u8 = 0x3F;

// One error for every malformed bundle or unbundleable frame keeps the
// embedded image small; the cause is never acted on differently.
const BAD: TelemetryError = TelemetryError::Unpack("bad compact bundle");

/// Is `bytes` a compact bundle (by its first byte)?
#[inline]
pub fn is_bundle(bytes: &[u8]) -> bool {
    bytes.first() == Some(&BUNDLE_MARKER)
}

/// Header fields of one frame, shared by the canonical and record forms.
#[derive(Clone, Copy, Default)]
struct Fields<'a> {
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

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> TelemetryResult<&'a [u8]> {
        let end = self.off.checked_add(n).filter(|end| *end <= self.buf.len()).ok_or(BAD)?;
        let out = &self.buf[self.off..end];
        self.off = end;
        Ok(out)
    }
    fn byte(&mut self) -> TelemetryResult<u8> {
        Ok(self.take(1)?[0])
    }
    fn uleb(&mut self) -> TelemetryResult<u64> {
        read_uleb128_local(self.buf, &mut self.off).map_err(|_| BAD)
    }
    fn len(&mut self) -> TelemetryResult<usize> {
        usize::try_from(self.uleb()?).map_err(|_| BAD)
    }
    fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.off..];
        self.off = self.buf.len();
        out
    }
    /// Endpoint bytes as the canonical flags describe them.
    fn endpoints(&mut self, flags: u8, nep: u8) -> TelemetryResult<&'a [u8]> {
        let start = self.off;
        if flags & F_EP_LIST != 0 {
            for _ in 0..nep {
                self.uleb()?;
            }
        } else if flags & F_EP_BITMAP != 0 {
            self.take(EP_BITMAP_BYTES)?;
        }
        Ok(&self.buf[start..self.off])
    }
    /// Reliable header bytes as the canonical flags describe them.
    fn reliable(&mut self, flags: u8) -> TelemetryResult<&'a [u8]> {
        let start = self.off;
        if flags & F_RELIABLE != 0 {
            if flags & F_COMPACT_RELIABLE != 0 {
                let wire = self.byte()?;
                if wire & 0x04 != 0 {
                    self.uleb()?;
                }
                if wire & 0x08 != 0 {
                    self.uleb()?;
                }
            } else {
                self.take(9)?;
            }
        }
        Ok(&self.buf[start..self.off])
    }
}

/// Split `bytes` into data and its trailing CRC32-LE, checking it.
fn checked(bytes: &[u8]) -> TelemetryResult<&[u8]> {
    let n = bytes.len().checked_sub(4).ok_or(BAD)?;
    let (data, crc) = bytes.split_at(n);
    if crc32_bytes(data).to_le_bytes() != crc {
        return Err(BAD);
    }
    Ok(data)
}

fn usable_flags(flags: u8) -> TelemetryResult<u8> {
    if flags & F_E2E != 0 || flags & F_EPS == F_EPS {
        return Err(BAD);
    }
    Ok(flags)
}

/// Read one frame's fields: the canonical form (`prev` None, `rec` false) or
/// a bundle record relative to the previous record.
fn read_fields<'a>(buf: &'a [u8], rec: bool, p: Option<&Fields<'a>>, prev_ts: u64) -> TelemetryResult<Fields<'a>> {
    let mut r = Reader { buf, off: 0 };
    let flags = usable_flags(r.byte()?)?;
    let elide = if rec { r.byte()? } else { 0 };
    let has_prev = p.is_some();
    let p = p.copied().unwrap_or_default();
    // Elision needs a previous record and the field it refers to.
    if elide & !E_KNOWN != 0
        || (!has_prev && elide != 0)
        || (elide & E_NONCE_DELTA != 0 && (elide & E_SOURCE == 0 || flags & p.flags & F_NONCE == 0))
        || (elide & E_CONTRACT != 0 && flags & p.flags & F_CONTRACT == 0)
        || (elide & E_ENDPOINTS != 0
            && (elide & E_NEP == 0 || flags & F_EPS == 0 || p.flags & F_EPS != flags & F_EPS))
    {
        return Err(BAD);
    }
    let nep = if elide & E_NEP != 0 { p.nep } else { r.byte()? };
    let ty = if elide & E_TYPE != 0 { p.ty } else { r.uleb()? };
    let size = if !rec || flags & F_COMPRESSED != 0 { Some(r.uleb()?) } else { None };
    let ts = if rec { prev_ts.wrapping_add(unzigzag(r.uleb()?)) } else { r.uleb()? };
    let nonce = if flags & F_NONCE != 0 {
        let v = r.uleb()?;
        let n = if elide & E_NONCE_DELTA != 0 { p.nonce.wrapping_add(unzigzag(v)) } else { v };
        if n > u64::from(u16::MAX) {
            return Err(BAD);
        }
        n
    } else {
        0
    };
    let src = if elide & E_SOURCE != 0 { p.src } else { u32::try_from(r.uleb()?).map_err(|_| BAD)? };
    let eps = if elide & E_ENDPOINTS != 0 { p.eps } else { r.endpoints(flags, nep)? };
    let contract = if flags & F_CONTRACT == 0 {
        &[][..]
    } else if elide & E_CONTRACT != 0 {
        p.contract
    } else {
        let n = r.len()?;
        r.take(n)?
    };
    let rel = r.reliable(flags)?;
    let payload = r.rest();
    let size = size.unwrap_or(payload.len() as u64);
    if flags & F_COMPRESSED == 0 && size != payload.len() as u64 {
        return Err(BAD);
    }
    Ok(Fields { flags, nep, ty, size, ts, nonce, src, eps, contract, rel, payload })
}

fn parse_canonical(frame: &[u8]) -> TelemetryResult<Fields<'_>> {
    if frame.starts_with(b"SDT") {
        return Err(BAD);
    }
    read_fields(checked(frame)?, false, None, 0)
}

/// Whether `frame` can travel inside a bundle: a canonical (not side-wrapped),
/// CRC-valid, unsealed frame. Urgency is the writer's decision: it keeps
/// urgent frames out before asking.
pub fn frame_bundleable(frame: &[u8]) -> bool {
    parse_canonical(frame).is_ok()
}

#[inline]
fn zigzag(delta: u64) -> u64 {
    let delta = delta as i64;
    ((delta << 1) ^ (delta >> 63)) as u64
}

#[inline]
fn unzigzag(v: u64) -> u64 {
    (((v >> 1) as i64) ^ -((v & 1) as i64)) as u64
}

/// Write one frame's fields: a bundle record relative to `p` (`rec`), or
/// the canonical frame with its CRC32.
fn write_fields(c: &Fields<'_>, rec: bool, p: Option<&Fields<'_>>, out: &mut Vec<u8>) {
    let mut elide = 0u8;
    let prev_ts = p.map_or(c.ts, |p| p.ts);
    if let (true, Some(p)) = (rec, p) {
        if p.ty == c.ty {
            elide |= E_TYPE;
        }
        if p.src == c.src {
            elide |= E_SOURCE;
            if c.flags & p.flags & F_NONCE != 0 {
                elide |= E_NONCE_DELTA;
            }
        }
        if c.flags & p.flags & F_CONTRACT != 0 && p.contract == c.contract {
            elide |= E_CONTRACT;
        }
        if p.nep == c.nep {
            elide |= E_NEP;
            if c.flags & F_EPS != 0 && p.flags & F_EPS == c.flags & F_EPS && p.eps == c.eps {
                elide |= E_ENDPOINTS;
            }
        }
    }
    out.clear();
    put(out, &[c.flags]);
    if rec {
        put(out, &[elide]);
    }
    if elide & E_NEP == 0 {
        put(out, &[c.nep]);
    }
    if elide & E_TYPE == 0 {
        put_uleb(out, c.ty);
    }
    if !rec || c.flags & F_COMPRESSED != 0 {
        put_uleb(out, c.size);
    }
    put_uleb(out, if rec { zigzag(c.ts.wrapping_sub(prev_ts)) } else { c.ts });
    if c.flags & F_NONCE != 0 {
        let delta = elide & E_NONCE_DELTA != 0;
        let v = c.nonce.wrapping_sub(if delta { p.map_or(0, |p| p.nonce) } else { 0 });
        put_uleb(out, if delta { zigzag(v) } else { v });
    }
    if elide & E_SOURCE == 0 {
        put_uleb(out, u64::from(c.src));
    }
    if elide & E_ENDPOINTS == 0 {
        put(out, c.eps);
    }
    if c.flags & F_CONTRACT != 0 && elide & E_CONTRACT == 0 {
        put_uleb(out, c.contract.len() as u64);
        put(out, c.contract);
    }
    put(out, c.rel);
    put(out, c.payload);
    if !rec {
        let crc = crc32_bytes(out);
        put(out, &crc.to_le_bytes());
    }
}

/// Pack canonical frames, in the given order, into one bundle.
///
/// Fails when `frames` is empty, holds more than [`MAX_BUNDLE_RECORDS`], or
/// holds a frame that is not a valid canonical frame; the writer then sends
/// such a frame on its own.
pub fn pack_bundle(frames: &[&[u8]]) -> TelemetryResult<Vec<u8>> {
    if frames.is_empty() || frames.len() > MAX_BUNDLE_RECORDS {
        return Err(BAD);
    }
    let total: usize = frames.iter().map(|f| f.len()).sum();
    let mut out = Vec::with_capacity(total + 16);
    let mut record = Vec::with_capacity(64);
    let mut prev: Option<Fields<'_>> = None;
    put(&mut out, &[BUNDLE_MARKER]);
    for frame in frames {
        let c = parse_canonical(frame)?;
        if prev.is_none() {
            put_uleb(&mut out, c.ts);
        }
        write_fields(&c, true, prev.as_ref(), &mut record);
        put_uleb(&mut out, record.len() as u64);
        put(&mut out, &record);
        prev = Some(c);
    }
    let crc = crc32_bytes(&out);
    put(&mut out, &crc.to_le_bytes());
    Ok(out)
}

/// Walk every record; with `each`, hand over each rebuilt canonical frame.
fn walk(bytes: &[u8], mut each: Option<&mut dyn FnMut(&[u8]) -> TelemetryResult<()>>) -> TelemetryResult<usize> {
    if !is_bundle(bytes) {
        return Err(BAD);
    }
    let mut r = Reader { buf: checked(bytes)?, off: 1 };
    let mut prev_ts = r.uleb()?;
    let mut prev: Option<Fields<'_>> = None;
    let mut count = 0usize;
    let mut canonical = Vec::new();
    while r.off < r.buf.len() {
        if count == MAX_BUNDLE_RECORDS {
            return Err(BAD);
        }
        let n = r.len()?;
        let rec = r.take(n)?;
        let c = read_fields(rec, true, prev.as_ref(), prev_ts)?;
        if let Some(each) = each.as_mut() {
            write_fields(&c, false, None, &mut canonical);
            each(&canonical)?;
        }
        prev_ts = c.ts;
        prev = Some(c);
        count += 1;
    }
    if count == 0 {
        return Err(BAD);
    }
    Ok(count)
}

/// Verify a bundle completely (CRC and every record), then hand each rebuilt
/// canonical frame to `each`, in order. A damaged bundle delivers nothing.
/// Returns the number of frames delivered.
pub fn unpack_bundle(
    bytes: &[u8],
    each: &mut dyn FnMut(&[u8]) -> TelemetryResult<()>,
) -> TelemetryResult<usize> {
    walk(bytes, None)?;
    walk(bytes, Some(each))
}

/// Verify a bundle and return its rebuilt canonical frames.
pub fn unpack_bundle_frames(bytes: &[u8]) -> TelemetryResult<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    unpack_bundle(bytes, &mut |frame| {
        frames.push(frame.to_vec());
        Ok(())
    })?;
    Ok(frames)
}
