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
    ty: u32,
    size: u32,
    ts: u64,
    nonce: u16,
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
    #[inline(never)]
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.off.checked_add(n).filter(|end| *end <= self.buf.len())?;
        let out = &self.buf[self.off..end];
        self.off = end;
        Some(out)
    }
    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    #[inline(never)]
    fn uleb(&mut self) -> Option<u64> {
        read_uleb128_local(self.buf, &mut self.off).ok()
    }
    /// A ULEB128 field that must fit 32 bits (type, size, source, lengths).
    #[inline(never)]
    fn u32(&mut self) -> Option<u32> {
        u32::try_from(self.uleb()?).ok()
    }
    fn len(&mut self) -> Option<usize> {
        Some(self.u32()? as usize)
    }
    fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.off..];
        self.off = self.buf.len();
        out
    }
    /// Endpoint bytes as the canonical flags describe them.
    fn endpoints(&mut self, flags: u8, nep: u8) -> Option<&'a [u8]> {
        let start = self.off;
        if flags & F_EP_LIST != 0 {
            for _ in 0..nep {
                self.uleb()?;
            }
        } else if flags & F_EP_BITMAP != 0 {
            self.take(EP_BITMAP_BYTES)?;
        }
        Some(&self.buf[start..self.off])
    }
    /// Reliable header bytes as the canonical flags describe them.
    fn reliable(&mut self, flags: u8) -> Option<&'a [u8]> {
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
        Some(&self.buf[start..self.off])
    }
}

/// Split `bytes` into data and its trailing CRC32-LE, checking it.
fn checked(bytes: &[u8]) -> Option<&[u8]> {
    let n = bytes.len().checked_sub(4)?;
    let (data, crc) = bytes.split_at(n);
    if crc32_bytes(data).to_le_bytes() != crc {
        return None;
    }
    Some(data)
}

fn usable_flags(flags: u8) -> Option<u8> {
    if flags & F_E2E != 0 || flags & F_EPS == F_EPS {
        return None;
    }
    Some(flags)
}

/// Read one frame's fields into `p`: the canonical form (`rec` false), or a
/// bundle record relative to the previous record already in `p` (`first`
/// when there is none; `p.ts` is then the bundle's base timestamp).
fn read_fields<'a>(buf: &'a [u8], rec: bool, first: bool, p: &mut Fields<'a>) -> Option<()> {
    let mut r = Reader { buf, off: 0 };
    let flags = usable_flags(r.byte()?)?;
    let elide = if rec { r.byte()? } else { 0 };
    // Elision needs a previous record and the field it refers to.
    if elide & !E_KNOWN != 0
        || (first && elide != 0)
        || (elide & E_NONCE_DELTA != 0 && (elide & E_SOURCE == 0 || flags & p.flags & F_NONCE == 0))
        || (elide & E_CONTRACT != 0 && flags & p.flags & F_CONTRACT == 0)
        || (elide & E_ENDPOINTS != 0
            && (elide & E_NEP == 0 || flags & F_EPS == 0 || p.flags & F_EPS != flags & F_EPS))
    {
        return None;
    }
    if elide & E_NEP == 0 {
        p.nep = r.byte()?;
    }
    if elide & E_TYPE == 0 {
        p.ty = r.u32()?;
    }
    let size = if !rec || flags & F_COMPRESSED != 0 { Some(r.u32()?) } else { None };
    let ts = r.uleb()?;
    p.ts = if rec { p.ts.wrapping_add(unzigzag(ts)) } else { ts };
    if flags & F_NONCE != 0 {
        let v = r.u32()?;
        let n = if elide & E_NONCE_DELTA != 0 { u32::from(p.nonce).wrapping_add(unzigzag32(v)) } else { v };
        p.nonce = u16::try_from(n).ok()?;
    } else {
        p.nonce = 0;
    }
    if elide & E_SOURCE == 0 {
        p.src = r.u32()?;
    }
    if elide & E_ENDPOINTS == 0 {
        p.eps = r.endpoints(flags, p.nep)?;
    }
    if flags & F_CONTRACT == 0 {
        p.contract = &[];
    } else if elide & E_CONTRACT == 0 {
        let n = r.len()?;
        p.contract = r.take(n)?;
    }
    p.rel = r.reliable(flags)?;
    p.payload = r.rest();
    let plen = u32::try_from(p.payload.len()).ok()?;
    p.size = size.unwrap_or(plen);
    if flags & F_COMPRESSED == 0 && p.size != plen {
        return None;
    }
    p.flags = flags;
    Some(())
}

fn parse_canonical(frame: &[u8]) -> Option<Fields<'_>> {
    if frame.starts_with(b"SDT") {
        return None;
    }
    let mut f = Fields::default();
    read_fields(checked(frame)?, false, true, &mut f)?;
    Some(f)
}

/// Whether `frame` can travel inside a bundle: a canonical (not side-wrapped),
/// CRC-valid, unsealed frame. Urgency is the writer's decision: it keeps
/// urgent frames out before asking.
pub fn frame_bundleable(frame: &[u8]) -> bool {
    parse_canonical(frame).is_some()
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

#[inline]
fn zigzag32(delta: u32) -> u32 {
    let delta = delta as i32;
    ((delta << 1) ^ (delta >> 31)) as u32
}

#[inline]
fn unzigzag32(v: u32) -> u32 {
    (((v >> 1) as i32) ^ -((v & 1) as i32)) as u32
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
        put_uleb(out, u64::from(c.ty));
    }
    if !rec || c.flags & F_COMPRESSED != 0 {
        put_uleb(out, u64::from(c.size));
    }
    put_uleb(out, if rec { zigzag(c.ts.wrapping_sub(prev_ts)) } else { c.ts });
    if c.flags & F_NONCE != 0 {
        let v = if elide & E_NONCE_DELTA != 0 {
            zigzag32(u32::from(c.nonce).wrapping_sub(u32::from(p.map_or(0, |p| p.nonce))))
        } else {
            u32::from(c.nonce)
        };
        put_uleb(out, u64::from(v));
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
    pack_bundle_with(frames.len(), &|i| frames[i])
}

/// [`pack_bundle`] over `count` frames that `frame(i)` returns.
pub fn pack_bundle_with<'a>(count: usize, frame: &dyn Fn(usize) -> &'a [u8]) -> TelemetryResult<Vec<u8>> {
    if count == 0 || count > MAX_BUNDLE_RECORDS {
        return Err(BAD);
    }
    let mut out = Vec::new();
    let mut record = Vec::new();
    let mut prev: Option<Fields<'_>> = None;
    put(&mut out, &[BUNDLE_MARKER]);
    for i in 0..count {
        let c = parse_canonical(frame(i)).ok_or(BAD)?;
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

/// Walk every record, handing each rebuilt canonical frame to `each`.
fn walk(bytes: &[u8], each: &mut dyn FnMut(&[u8]) -> TelemetryResult<()>) -> TelemetryResult<usize> {
    let mut r = Reader { buf: checked(bytes).filter(|_| is_bundle(bytes)).ok_or(BAD)?, off: 1 };
    let mut cur = Fields { ts: r.uleb().ok_or(BAD)?, ..Fields::default() };
    let mut count = 0usize;
    let mut canonical = Vec::new();
    while r.off < r.buf.len() {
        let rec = r.len().and_then(|n| r.take(n)).ok_or(BAD)?;
        if count == MAX_BUNDLE_RECORDS || read_fields(rec, true, count == 0, &mut cur).is_none() {
            return Err(BAD);
        }
        write_fields(&cur, false, None, &mut canonical);
        each(&canonical)?;
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
    walk(bytes, &mut |_| Ok(()))?;
    walk(bytes, each)
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
