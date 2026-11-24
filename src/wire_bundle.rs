//! Compact bundles: several canonical frames in one side frame.
//!
//! A side uses bundles when it is opened with
//! [`crate::routing_config::SideOptions::compact_bundle`], or a link layer
//! packs the canonical frames a side emits with [`BundleWriter`] (for example
//! one bundle per radio turn). Every node on such a link runs a
//! bundle-capable build (no negotiation, no legacy fallback). A bundle needs
//! no dictionary that could be lost or go stale: every record decodes from
//! the bundle plus the static node table below. The receiver rebuilds each
//! canonical frame byte for byte (CRC included), so packet ids, routing, hop
//! and end-to-end reliability and forwarding are unchanged.
//!
//! Node table: every node is built with the same ordered list of node names
//! ([`set_node_table`]). A record then names a source address, or a frozen
//! target hash, by its 1-byte position in that list instead of 4-5 or 8 bytes.
//! A bundle that uses the table carries a 16-bit check of the table; a
//! receiver whose table differs (or that has none) drops such records rather
//! than guess. Urgent frames (ABORT) never travel in a bundle: they stay
//! self-contained canonical frames that decode with no prior state.
//!
//! ```text
//! bundle = MARKER | [table check u16 LE, MARKER_TABLE bit] | base_ts ULEB128
//!          | record+ | CRC32-LE(MARKER .. last record)
//! record = len ULEB128 | elide | [flags] | [type ULEB128]
//!        | [source: ULEB128, or 1-byte node index]
//!        | [epoch | endpoints | contract, unless elided; contract targets as
//!           1-byte node indices when elide bit E_TARGET_INDEX is set]
//!        | ts zigzag ULEB128 (delta from the previous record, the first from base_ts)
//!        | [logical size ULEB128, compressed or sealed payloads]
//!        | [nonce: ULEB128, or zigzag delta from the previous record's nonce]
//!        | [reliable header] | payload
//!        | [CRC32-LE of the rebuilt canonical frame, MARKER_RECORD_CRC only]
//! ```
//!
//! Fields are in canonical order (the static header, then the per-packet
//! fields). `flags` is the canonical flags byte. `elide` bits drop a field
//! that equals the previous record's. Every marker sets both endpoint-encoding
//! bits (`0x60`), which no canonical frame can carry, so a receiver tells a
//! bundle apart from every other frame by its first byte.
//!
//! Integrity: one CRC32 ends the bundle and covers all of it, like every
//! SEDSnet side frame, so a link or relay can check it alone; a damaged
//! bundle delivers nothing. With [`BUNDLE_MARKER_RECORD_CRC`] every record
//! also carries the CRC32 of the canonical frame it rebuilds: when the bundle
//! check fails (a transport that passes damaged frames up), each record that
//! still passes its own check is delivered and the others are dropped (a
//! record that elides fields of a damaged one fails its own check too).
//!
//! The writer bundles only frames that are already waiting, in its priority
//! order (see [`frame_priority`]), and never an urgent frame (Abort and other
//! turn-bypass traffic go standalone). End-to-end sealed frames are not bundled.

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
use crate::packet::hash_bytes_u64;
use crate::{TelemetryError, TelemetryResult};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// First byte of a compact bundle without node-table references.
pub const BUNDLE_MARKER: u8 = 0x62;
/// Marker bit: the bundle's records may use the node table; a 16-bit table
/// check follows the marker.
pub const BUNDLE_MARKER_TABLE: u8 = 0x63;
/// Marker bit: every record also carries its own CRC32.
pub const BUNDLE_MARKER_RECORD_CRC: u8 = 0x04;
/// Upper bound on records accepted from one bundle.
pub const MAX_BUNDLE_RECORDS: usize = 64;

const F_COMPRESSED: u8 = 0x01;
const F_RELIABLE: u8 = 0x02;
const F_CONTRACT: u8 = 0x04;
const F_NONCE: u8 = 0x08;
const F_E2E: u8 = 0x10;
const F_EPS: u8 = 0x60;
const F_EP_ONE: u8 = 0x20;
const F_EP_LIST: u8 = 0x40;
const F_EPOCH: u8 = 0x80;
const F_SIZED: u8 = F_COMPRESSED | F_E2E;
/// Flags that shape the static header after the source.
const F_STATIC: u8 = F_CONTRACT | F_EPS | F_EPOCH;

const E_FLAGS: u8 = 0x01;
const E_TYPE: u8 = 0x02;
const E_SOURCE: u8 = 0x04;
const E_SOURCE_INDEX: u8 = 0x08;
const E_STATIC: u8 = 0x10;
const E_TARGET_INDEX: u8 = 0x20;
const E_NONCE_DELTA: u8 = 0x40;
const E_ALL: u8 = 0x7F;
const CONTRACT_TARGETS: u8 = 0x01;
const CONTRACT_SHAPE: u8 = 0x02;

// One error for every malformed bundle or unbundleable frame keeps the
// embedded image small; the cause is never acted on differently.
const BAD: TelemetryError = TelemetryError::Unpack("bad compact bundle");

/// Is `bytes` a compact bundle (by its first byte)?
#[inline]
pub fn is_bundle(bytes: &[u8]) -> bool {
    const VARYING: u8 = (BUNDLE_MARKER_TABLE ^ BUNDLE_MARKER) | BUNDLE_MARKER_RECORD_CRC;
    bytes.first().is_some_and(|m| m & !VARYING == BUNDLE_MARKER)
}

// ---------------------------------------------------------------- node table

static NODE_PTR: AtomicUsize = AtomicUsize::new(0);
static NODE_LEN: AtomicUsize = AtomicUsize::new(0);
const ACK_PREFIX: &[u8] = b"E2EACK:";

/// Set the ordered node-name table every node on bundle links shares (at
/// most 64 names). Position `i` names `names[i]`'s source address and frozen
/// target hash; `64 + i` names the source address of its end-to-end ACKs.
/// Set it once at start-up, before any bundle is packed or received.
pub fn set_node_table(names: &'static [&'static str]) {
    let names = &names[..names.len().min(64)];
    NODE_LEN.store(0, Ordering::Release);
    NODE_PTR.store(names.as_ptr() as usize, Ordering::Release);
    NODE_LEN.store(names.len(), Ordering::Release);
}

fn nodes() -> &'static [&'static str] {
    let len = NODE_LEN.load(Ordering::Acquire);
    if len == 0 {
        return &[];
    }
    // SAFETY: set_node_table stored a 'static slice of exactly `len` names.
    unsafe { core::slice::from_raw_parts(NODE_PTR.load(Ordering::Acquire) as *const &'static str, len) }
}

fn source_of(i: usize) -> Option<u32> {
    let names = nodes();
    let name = names.get(i % 64)?.as_bytes();
    if i >= 64 {
        let h = hash_bytes_u64(hash_bytes_u64(0xA6D3_8C21_4B7F_19E5, ACK_PREFIX), name) as u32;
        return Some(h.max(1));
    }
    Some(crate::packet::sender_address_u32(names[i]))
}

fn target_of(i: usize) -> Option<u64> {
    Some(hash_bytes_u64(0x517C_C1B7_2722_0A95, nodes().get(i)?.as_bytes()))
}

#[inline(never)]
fn source_index(src: u32) -> Option<u8> {
    (0..nodes().len()).chain(64..64 + nodes().len()).find(|&i| source_of(i) == Some(src)).map(|i| i as u8)
}

#[inline(never)]
fn target_index(hash: u64) -> Option<u8> {
    (0..nodes().len()).find(|&i| target_of(i) == Some(hash)).map(|i| i as u8)
}

/// 16-bit check of the node table carried by MARKER_TABLE bundles.
fn table_check() -> [u8; 2] {
    let h = nodes().iter().fold(0x6B1D_3C4F_u64, |h, name| hash_bytes_u64(h ^ 0xFF, name.as_bytes()));
    ((h ^ (h >> 16) ^ (h >> 32) ^ (h >> 48)) as u16).to_le_bytes()
}

/// Header fields of one frame, shared by the canonical and record forms.
#[derive(Clone, Copy, Default)]
struct Fields<'a> {
    flags: u8,
    ty: u32,
    src: u32,
    /// Epoch, endpoint and contract bytes of the static header, as the
    /// canonical frame encodes them (`targets_indexed`: as the record does).
    rest: &'a [u8],
    /// The contract holds 1-byte node indices for its targets (record form).
    targets_indexed: bool,
    ts: u64,
    size: u32,
    nonce: u16,
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
    /// The epoch, endpoint and contract fields the canonical flags describe;
    /// `indexed`: contract targets are 1-byte node indices.
    fn static_rest(&mut self, flags: u8, indexed: bool) -> Option<&'a [u8]> {
        let start = self.off;
        if flags & F_EPOCH != 0 {
            self.uleb()?;
        }
        let count = match flags & F_EPS {
            F_EP_ONE => 1,
            F_EP_LIST => self.len()?,
            _ => 0,
        };
        for _ in 0..count {
            self.uleb()?;
        }
        if flags & F_CONTRACT != 0 {
            let n = self.len()?;
            let mut c = Reader { buf: self.take(n)?, off: 0 };
            let contract_flags = c.byte()?;
            if contract_flags & CONTRACT_SHAPE != 0 && c.byte()? & 0x40 != 0 {
                c.uleb()?;
            }
            let targets = if contract_flags & CONTRACT_TARGETS != 0 { c.len()? } else { 0 };
            let list = c.take(targets.checked_mul(if indexed { 1 } else { 8 })?)?;
            if c.off != c.buf.len() || (indexed && list.iter().any(|&i| target_of(usize::from(i)).is_none())) {
                return None;
            }
        }
        Some(&self.buf[start..self.off])
    }
    /// Reliable header bytes as the canonical flags describe them. A
    /// contract declaring a reliable header without flag 0x02 is not
    /// bundleable (the record reader would not know to read it).
    fn reliable(&mut self, flags: u8) -> Option<&'a [u8]> {
        let start = self.off;
        if flags & F_RELIABLE != 0 {
            let wire = self.byte()?;
            if wire & 0x04 != 0 {
                self.uleb()?;
            }
            if wire & 0x08 != 0 {
                self.uleb()?;
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

/// The contract inside `rest` (after the epoch and endpoints), as a slice.
fn contract_span(rest: &[u8], flags: u8) -> Option<(usize, usize)> {
    if flags & F_CONTRACT == 0 {
        return None;
    }
    let mut r = Reader { buf: rest, off: 0 };
    if flags & F_EPOCH != 0 {
        r.uleb()?;
    }
    let count = match flags & F_EPS {
        F_EP_ONE => 1,
        F_EP_LIST => r.len()?,
        _ => 0,
    };
    for _ in 0..count {
        r.uleb()?;
    }
    Some((r.off, rest.len()))
}

/// Read one frame's fields into `p`: the canonical form (`rec` false), or a
/// bundle record relative to the previous record already in `p` (`first`
/// when there is none; `p.ts` is then the bundle's base timestamp).
fn read_fields<'a>(buf: &'a [u8], rec: bool, first: bool, table: bool, p: &mut Fields<'a>) -> Option<()> {
    let mut r = Reader { buf, off: 0 };
    let elide = if rec { r.byte()? } else { 0 };
    let flags = if elide & E_FLAGS != 0 { p.flags } else { r.byte()? };
    // Not canonical, sealed, or a reliable header the flags do not announce.
    if flags & F_EPS == F_EPS || flags & F_E2E != 0 {
        return None;
    }
    // Elision needs a previous record and the field it refers to; node
    // indices need a bundle that carried a matching table check.
    if elide & !E_ALL != 0
        || (first && elide & !(E_SOURCE_INDEX | E_TARGET_INDEX) != 0)
        || (!table && elide & (E_SOURCE_INDEX | E_TARGET_INDEX) != 0)
        || (elide & E_SOURCE != 0 && elide & E_SOURCE_INDEX != 0)
        || (elide & E_TARGET_INDEX != 0 && (flags & F_CONTRACT == 0 || elide & E_STATIC != 0))
        || (elide & E_NONCE_DELTA != 0 && (elide & E_SOURCE == 0 || flags & p.flags & F_NONCE == 0))
        || (elide & E_STATIC != 0 && flags & F_STATIC != p.flags & F_STATIC)
    {
        return None;
    }
    if elide & E_TYPE == 0 {
        p.ty = r.u32()?;
    }
    if elide & E_SOURCE_INDEX != 0 {
        p.src = source_of(usize::from(r.byte()?))?;
    } else if elide & E_SOURCE == 0 {
        p.src = r.u32()?;
    }
    if elide & E_STATIC == 0 {
        p.targets_indexed = elide & E_TARGET_INDEX != 0;
        p.rest = r.static_rest(flags, p.targets_indexed)?;
    }
    let ts = r.uleb()?;
    p.ts = if rec { p.ts.wrapping_add(unzigzag(ts)) } else { ts };
    let size = if flags & F_SIZED != 0 { Some(r.u32()?) } else { None };
    if flags & F_NONCE != 0 {
        let v = r.u32()?;
        let n = if elide & E_NONCE_DELTA != 0 { u32::from(p.nonce).wrapping_add(unzigzag32(v)) } else { v };
        p.nonce = u16::try_from(n).ok()?;
    } else {
        p.nonce = 0;
    }
    if flags & F_RELIABLE == 0 && contract_declares_reliable(p.rest, flags) {
        return None;
    }
    p.rel = r.reliable(flags)?;
    p.payload = r.rest();
    let plen = u32::try_from(p.payload.len()).ok()?;
    p.size = size.unwrap_or(plen);
    p.flags = flags;
    Some(())
}

/// Whether the contract in `rest` declares a reliable header.
fn contract_declares_reliable(rest: &[u8], flags: u8) -> bool {
    contract_span(rest, flags).is_some_and(|(start, _)| {
        let mut r = Reader { buf: rest, off: start };
        r.len().and_then(|_| r.byte()).is_some_and(|contract_flags| contract_flags & 0x04 != 0)
    })
}

fn parse_canonical(frame: &[u8]) -> Option<Fields<'_>> {
    if frame.first().is_none_or(|first| crate::wire_format::is_marker_byte(*first)) {
        return None;
    }
    let mut f = Fields::default();
    read_fields(checked(frame)?, false, true, false, &mut f)?;
    Some(f)
}

/// Whether `frame` can travel inside a bundle: a canonical (not side-wrapped),
/// CRC-valid, unsealed frame. Urgency is the writer's decision: it keeps
/// urgent frames out before asking.
pub fn frame_bundleable(frame: &[u8]) -> bool {
    parse_canonical(frame).is_some()
}

/// The transport priority of a canonical frame (higher is more urgent), for
/// a writer that orders waiting frames before bundling them; `None` when the
/// frame is not canonical.
pub fn frame_priority(frame: &[u8]) -> Option<u8> {
    let ty = crate::wire_format::scheduling_type(frame)?;
    crate::config::try_get_message_meta(ty).map(|_| crate::transport_priority(ty))
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

/// `rest` with each 8-byte contract target swapped for its node index (or
/// the reverse); `None` when a target is not in the table.
fn put_rest(out: &mut Vec<u8>, rest: &[u8], flags: u8, from_index: bool, to_index: bool) -> Option<()> {
    let Some((start, _)) = contract_span(rest, flags) else {
        put(out, rest);
        return Some(());
    };
    put(out, &rest[..start]);
    let mut r = Reader { buf: rest, off: start };
    let len = r.len()?;
    let contract = r.take(len)?;
    let mut c = Reader { buf: contract, off: 0 };
    let contract_flags = c.byte()?;
    if contract_flags & CONTRACT_SHAPE != 0 && c.byte()? & 0x40 != 0 {
        c.uleb()?;
    }
    let targets = if contract_flags & CONTRACT_TARGETS != 0 { c.len()? } else { 0 };
    let head = &contract[..c.off];
    let width = if from_index { 1 } else { 8 };
    let list = c.take(targets.checked_mul(width)?)?;
    put_uleb(out, (head.len() + targets * if to_index { 1 } else { 8 }) as u64);
    put(out, head);
    for target in list.chunks_exact(width) {
        let hash = if from_index {
            target_of(usize::from(target[0]))?
        } else {
            u64::from_le_bytes(target.try_into().ok()?)
        };
        if to_index {
            put(out, &[target_index(hash)?]);
        } else {
            put(out, &hash.to_le_bytes());
        }
    }
    Some(())
}

/// Write one frame's fields: a bundle record relative to `p` (`rec`), or
/// the canonical frame with its CRC32.
fn write_fields(c: &Fields<'_>, rec: bool, p: Option<&Fields<'_>>, out: &mut Vec<u8>) {
    let mut elide = 0u8;
    let prev_ts = p.map_or(c.ts, |p| p.ts);
    if let (true, Some(p)) = (rec, p) {
        if p.flags == c.flags {
            elide |= E_FLAGS;
        }
        if p.ty == c.ty {
            elide |= E_TYPE;
        }
        if p.src == c.src {
            elide |= E_SOURCE;
            if c.flags & p.flags & F_NONCE != 0 {
                elide |= E_NONCE_DELTA;
            }
        }
        if c.flags & F_STATIC == p.flags & F_STATIC && p.rest == c.rest && p.targets_indexed == c.targets_indexed {
            elide |= E_STATIC;
        }
    }
    // Node indices, when this node has a table (records only).
    let source = if rec && elide & E_SOURCE == 0 { source_index(c.src) } else { None };
    if source.is_some() {
        elide |= E_SOURCE_INDEX;
    }
    let mut rest = Vec::new();
    if elide & E_STATIC == 0 {
        let indexed = rec
            && c.flags & F_CONTRACT != 0
            && !nodes().is_empty()
            && put_rest(&mut rest, c.rest, c.flags, c.targets_indexed, true).is_some()
            && rest != c.rest;
        if indexed {
            elide |= E_TARGET_INDEX;
        } else {
            rest.clear();
            let _ = put_rest(&mut rest, c.rest, c.flags, c.targets_indexed, false);
        }
    }
    out.clear();
    if rec {
        put(out, &[elide]);
    }
    if elide & E_FLAGS == 0 {
        put(out, &[c.flags]);
    }
    if elide & E_TYPE == 0 {
        put_uleb(out, u64::from(c.ty));
    }
    if let Some(index) = source {
        put(out, &[index]);
    } else if elide & E_SOURCE == 0 {
        put_uleb(out, u64::from(c.src));
    }
    put(out, &rest);
    put_uleb(out, if rec { zigzag(c.ts.wrapping_sub(prev_ts)) } else { c.ts });
    if c.flags & F_SIZED != 0 {
        put_uleb(out, u64::from(c.size));
    }
    if c.flags & F_NONCE != 0 {
        let v = if elide & E_NONCE_DELTA != 0 {
            zigzag32(u32::from(c.nonce).wrapping_sub(u32::from(p.map_or(0, |p| p.nonce))))
        } else {
            u32::from(c.nonce)
        };
        put_uleb(out, u64::from(v));
    }
    put(out, c.rel);
    put(out, c.payload);
    if !rec {
        let crc = crc32_bytes(out);
        put(out, &crc.to_le_bytes());
    }
}

/// Builds one bundle from canonical frames, in the order they are pushed,
/// within a byte budget (a link MTU or a turn's budget).
///
/// ```ignore
/// let mut writer = BundleWriter::new(mtu, false);
/// for frame in waiting_frames_in_priority_order {
///     if !writer.try_push(frame)? { break; } // full: send the rest next time
/// }
/// if let Some(bundle) = writer.finish() { send(&bundle); }
/// ```
///
/// A frame that cannot join a bundle (side-transport frames, sealed frames,
/// damaged frames) is an error; a frame that does not fit is refused with
/// `Ok(false)` and the bundle is unchanged. A bundle of one record is
/// larger than the frame itself: send a lone frame standalone instead.
pub struct BundleWriter {
    out: Vec<u8>,
    record: Vec<u8>,
    previous: Vec<u8>,
    count: usize,
    budget: usize,
    record_crc: bool,
}

impl BundleWriter {
    /// A writer whose finished bundle is at most `budget` bytes. With
    /// `record_crc` every record also carries its own CRC32, so a damaged
    /// bundle still delivers its intact records.
    pub fn new(budget: usize, record_crc: bool) -> Self {
        let mut out = Vec::new();
        let marker = if nodes().is_empty() { BUNDLE_MARKER } else { BUNDLE_MARKER_TABLE }
            | if record_crc { BUNDLE_MARKER_RECORD_CRC } else { 0 };
        put(&mut out, &[marker]);
        if !nodes().is_empty() {
            put(&mut out, &table_check());
        }
        Self {
            out,
            record: Vec::new(),
            previous: Vec::new(),
            count: 0,
            budget,
            record_crc,
        }
    }

    /// Records in the bundle so far.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Bytes the bundle would have if finished now.
    pub fn len(&self) -> usize {
        self.out.len() + 4
    }

    /// Whether no record was pushed yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Bytes `frame` would add to the bundle; `Err` when it cannot join one.
    pub fn cost(&mut self, frame: &[u8]) -> TelemetryResult<usize> {
        Ok(self.encode(frame)?.0)
    }

    fn encode(&mut self, frame: &[u8]) -> TelemetryResult<(usize, u64)> {
        let c = parse_canonical(frame).ok_or(BAD)?;
        let prev = if self.count == 0 {
            None
        } else {
            Some(parse_canonical(&self.previous).ok_or(BAD)?)
        };
        // The first record's timestamp is the bundle's base: its delta is 0.
        let mut record = core::mem::take(&mut self.record);
        write_fields(&c, true, prev.as_ref(), &mut record);
        if self.record_crc {
            put(&mut record, &frame[frame.len() - 4..]);
        }
        let head = if self.count == 0 { uleb_len(c.ts) } else { 0 };
        let cost = head + uleb_len(record.len() as u64) + record.len();
        self.record = record;
        Ok((cost, c.ts))
    }

    /// Append `frame` when it fits the budget: `Ok(true)` when added,
    /// `Ok(false)` when it would not fit (or the bundle holds
    /// [`MAX_BUNDLE_RECORDS`]).
    pub fn try_push(&mut self, frame: &[u8]) -> TelemetryResult<bool> {
        let (cost, base) = self.encode(frame)?;
        if self.count == MAX_BUNDLE_RECORDS || self.len() + cost > self.budget {
            return Ok(false);
        }
        if self.count == 0 {
            put_uleb(&mut self.out, base);
        }
        put_uleb(&mut self.out, self.record.len() as u64);
        let record = core::mem::take(&mut self.record);
        put(&mut self.out, &record);
        self.record = record;
        self.previous.clear();
        self.previous.extend_from_slice(frame);
        self.count += 1;
        Ok(true)
    }

    /// The finished bundle, or `None` when nothing was pushed.
    pub fn finish(mut self) -> Option<Vec<u8>> {
        if self.count == 0 {
            return None;
        }
        let crc = crc32_bytes(&self.out);
        put(&mut self.out, &crc.to_le_bytes());
        Some(self.out)
    }
}

fn uleb_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Pack canonical frames, in the given order, into one bundle (one CRC32).
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
    let mut writer = BundleWriter::new(usize::MAX, false);
    for i in 0..count {
        if !writer.try_push(frame(i))? {
            return Err(BAD);
        }
    }
    writer.finish().ok_or(BAD)
}

/// Visitor that receives each rebuilt canonical frame.
type FrameVisitor<'a> = &'a mut dyn FnMut(&[u8]) -> TelemetryResult<()>;

/// Walk every record, handing each rebuilt canonical frame to `each`.
/// `check_crc` false is only for bytes a previous walk verified. Returns
/// (records read, records delivered).
fn walk(bytes: &[u8], check_crc: bool, mut each: Option<FrameVisitor<'_>>) -> TelemetryResult<(usize, usize)> {
    let marker = *bytes.first().filter(|_| is_bundle(bytes)).ok_or(BAD)?;
    // Per-record checks are used only when the bundle's own check failed.
    let record_crc = marker & BUNDLE_MARKER_RECORD_CRC != 0;
    let intact = !check_crc || checked(bytes).is_some();
    if !intact && !record_crc {
        return Err(BAD);
    }
    let check_records = record_crc && !intact;
    let data = bytes.get(..bytes.len().wrapping_sub(4));
    let mut r = Reader { buf: data.ok_or(BAD)?, off: 1 };
    // A table bundle decodes only against the same node table, never a guess.
    let table = marker & (BUNDLE_MARKER_TABLE ^ BUNDLE_MARKER) != 0;
    if table && (nodes().is_empty() || r.take(2) != Some(&table_check()[..])) {
        return Err(BAD);
    }
    let mut cur = Fields { ts: r.uleb().ok_or(BAD)?, ..Fields::default() };
    let mut count = 0usize;
    let mut delivered = 0usize;
    let mut canonical = Vec::new();
    while r.off < r.buf.len() {
        let rec = r.len().and_then(|n| r.take(n)).ok_or(BAD)?;
        if count == MAX_BUNDLE_RECORDS {
            return Err(BAD);
        }
        let (rec, carried) = if record_crc {
            let n = rec.len().checked_sub(4).ok_or(BAD)?;
            (&rec[..n], check_records.then_some(&rec[n..]))
        } else {
            (rec, None)
        };
        let parsed = read_fields(rec, true, count == 0, table, &mut cur);
        count += 1;
        if parsed.is_none() {
            // An intact bundle holds what its sender wrote, so it is
            // malformed. A damaged one with per-record checks drops this
            // record alone (the next one that elides its fields fails its
            // own check).
            if check_records {
                continue;
            }
            return Err(BAD);
        }
        if let Some(each) = each.as_mut() {
            write_fields(&cur, false, None, &mut canonical);
            if carried.is_some_and(|crc| canonical[canonical.len() - 4..] != *crc) {
                continue;
            }
            // A frame the visitor refuses does not stop the others.
            if each(&canonical).is_ok() {
                delivered += 1;
            }
        }
    }
    if count == 0 {
        return Err(BAD);
    }
    Ok((count, delivered))
}

/// Verify a bundle and hand each rebuilt canonical frame to `each`, in order.
/// With one bundle CRC a damaged bundle delivers nothing; with per-record
/// CRCs only damaged records are dropped. A frame `each` refuses does not
/// stop the rest. Returns the number of frames `each` accepted.
pub fn unpack_bundle(
    bytes: &[u8],
    each: &mut dyn FnMut(&[u8]) -> TelemetryResult<()>,
) -> TelemetryResult<usize> {
    if checked(bytes).is_none() {
        // A damaged bundle: only per-record checks can still deliver.
        return Ok(walk(bytes, true, Some(each))?.1);
    }
    // The first pass parses every record; the second rebuilds the frames
    // from the bytes the CRC check already verified.
    walk(bytes, false, None)?;
    Ok(walk(bytes, false, Some(each))?.1)
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
