//! Shared wire codec for router and relay side transports.
//!
//! A side frame is either a canonical frame or a side-transport frame. The
//! first byte tells them apart: a canonical frame never has both
//! endpoint-encoding bits (`0x60`) set in its flags byte, so every first byte
//! with those bits set is a side-transport kind:
//!
//! ```text
//! 0x60          FULL     template id+generation | base delta | canonical data | CRC32
//! 0x61          CHUNK    transfer id u16 LE | position | chunk bytes | CRC32
//! 0x62/63/66/67 BUNDLE   see `wire_bundle`
//! 0x70..=0x73   COMPACT  template id+generation | ts delta | [size] | [nonce] | payload | CRC32
//! ```
//!
//! Integrity: every frame a side emits ends in a CRC32 of all its own prior
//! bytes, so any hop (including a relay that keeps no SEDSnet state) can
//! check it, and SEDSnet checks it before using any byte. A COMPACT frame
//! also names its template's generation (three bits beside the template id):
//! a FULL frame that redefines an id, or moves its base timestamp, starts a
//! new generation, so a receiver holding a stale template or base (a lost
//! FULL frame) drops the compact frame instead of misreading it. A chunk's
//! CRC32 covers the chunk, and the reassembled frame is checked again.
//! First bytes `0xE0..=0xFF` are never used by SEDSnet (link layers may use
//! them as their own markers).

use crate::{DataType, TelemetryError, TelemetryResult, packet::hash_bytes_u64, wire_format};
use crate::OrdMap;
use alloc::{sync::Arc, vec::Vec};
use crate::crc32::Crc32 as Crc32Hasher;

const SIDE_TX_PROGRESS_TIMEOUT_MS: u64 = 2000;
/// Template definition: a canonical frame plus its template id.
pub(crate) const SIDE_TRANSPORT_KIND_FULL: u8 = 0x60;
/// Fragment of a larger side frame.
pub(crate) const SIDE_TRANSPORT_KIND_CHUNK: u8 = 0x61;
/// Compact frame base value; bits 0x01 (compressed) and 0x02 (nonce) vary.
pub(crate) const SIDE_TRANSPORT_KIND_COMPACT: u8 = 0x70;
pub(crate) const SIDE_TRANSPORT_COMPACT_COMPRESSED: u8 = 0x01;
pub(crate) const SIDE_TRANSPORT_COMPACT_NONCE: u8 = 0x02;
pub(crate) const SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED: u8 = 0x01;
pub(crate) const SIDE_TRANSPORT_FLAG_PACKET_NONCE: u8 = 0x08;
/// Canonical flags carrying an explicit logical payload size.
const SIDE_TRANSPORT_FLAGS_SIZED: u8 = 0x11;
/// Chunk bytes besides the ULEB128 position: kind, a 16-bit transfer id and
/// the chunk's CRC32.
pub(crate) const SIDE_TRANSPORT_CHUNK_FIXED_BYTES: usize = 1 + 2 + wire_format::CRC32_BYTES;
/// Smallest chunk overhead (a one-byte position, up to 15 chunks).
pub(crate) const SIDE_TRANSPORT_CHUNK_OVERHEAD: usize = SIDE_TRANSPORT_CHUNK_FIXED_BYTES + 1;
/// A template's base timestamp moves (with a FULL frame) once a compact
/// delta would no longer fit three ULEB128 bytes (about 17 minutes).
pub(crate) const SIDE_TRANSPORT_MAX_TS_DELTA: u64 = (1 << 21) - 1;
/// Bits of the template generation beside the template id.
pub(crate) const TEMPLATE_GEN_BITS: u32 = 3;
pub(crate) const TEMPLATE_GEN_MASK: u8 = (1 << TEMPLATE_GEN_BITS) - 1;

/// A template's base timestamp and generation, as the side state keeps them.
#[inline]
pub(crate) fn pack_template_base(base: u64, generation: u8) -> u64 {
    (base << TEMPLATE_GEN_BITS) | u64::from(generation & TEMPLATE_GEN_MASK)
}

#[inline]
pub(crate) fn unpack_template_base(packed: u64) -> (u64, u8) {
    (packed >> TEMPLATE_GEN_BITS, (packed as u8) & TEMPLATE_GEN_MASK)
}

/// The kind of a side frame's first byte: a side-transport kind, or `None`
/// for a canonical frame.
#[inline]
pub(crate) fn side_frame_kind(bytes: &[u8]) -> Option<u8> {
    let first = *bytes.first()?;
    if !wire_format::is_marker_byte(first) {
        return None;
    }
    Some(if first & 0xFC == SIDE_TRANSPORT_KIND_COMPACT { SIDE_TRANSPORT_KIND_COMPACT } else { first })
}

#[inline]
pub(crate) fn zigzag(delta: i64) -> u64 {
    ((delta << 1) ^ (delta >> 63)) as u64
}

#[inline]
pub(crate) fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

#[inline]
fn chunk_triangle(n: u64) -> u64 {
    n * (n + 1) / 2
}

/// One ULEB128 value names both a chunk's index and the transfer's chunk
/// count: `total * (total - 1) / 2 + index`. Up to 15 chunks fit one byte;
/// below 23171 chunks the value is never longer than two separate ULEB128
/// fields would be.
#[inline]
pub(crate) fn chunk_position(index: u16, total: u16) -> u64 {
    chunk_triangle(u64::from(total) - 1) + u64::from(index)
}

/// Inverse of [`chunk_position`]: `(index, total)`, or `None` when the value
/// names more than 65535 chunks.
pub(crate) fn decode_chunk_position(position: u64) -> Option<(u16, u16)> {
    // Largest n with T(n) <= position, n + 1 being the chunk count.
    let (mut lo, mut hi) = (0u64, u64::from(u16::MAX) - 1);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if chunk_triangle(mid) <= position {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let index = position - chunk_triangle(lo);
    let total = lo + 1;
    (index < total).then_some((index as u16, total as u16))
}

/// `(transfer id, index, total, header bytes)` of a chunk body (the kind
/// byte and CRC32 already removed and checked).
pub(crate) fn parse_chunk_header(body: &[u8]) -> TelemetryResult<(u32, u16, u16, usize)> {
    const SHORT: TelemetryError = TelemetryError::Unpack("short side chunk frame");
    if body.len() < 4 {
        return Err(SHORT);
    }
    let transfer = u32::from(u16::from_le_bytes([body[0], body[1]]));
    let mut off = 2;
    let position = read_uleb128_local(body, &mut off).map_err(|_| SHORT)?;
    let (index, total) = decode_chunk_position(position)
        .ok_or(TelemetryError::Unpack("invalid side chunk index"))?;
    if off == body.len() {
        return Err(TelemetryError::Unpack("invalid side chunk index"));
    }
    Ok((transfer, index, total, off))
}

/// The body of a chunk frame (after its kind byte, before its CRC32), when
/// its CRC32 is intact.
pub(crate) fn checked_chunk_body(frame: &[u8]) -> TelemetryResult<&[u8]> {
    if frame.first() != Some(&SIDE_TRANSPORT_KIND_CHUNK) || frame.len() < 1 + wire_format::CRC32_BYTES + 4 {
        return Err(TelemetryError::Unpack("short side chunk frame"));
    }
    let data_len = frame.len() - wire_format::CRC32_BYTES;
    if crc32_bytes(&frame[..data_len]).to_le_bytes() != frame[data_len..] {
        return Err(TelemetryError::Unpack("side chunk crc32 mismatch"));
    }
    Ok(&frame[1..data_len])
}

/// Payload bytes per chunk and chunk count for a `len`-byte frame split into
/// frames of at most `max_frame_bytes`.
pub(crate) fn chunk_layout(len: usize, max_frame_bytes: usize) -> TelemetryResult<(usize, u16)> {
    for position_bytes in 1..=5 {
        let overhead = SIDE_TRANSPORT_CHUNK_FIXED_BYTES + position_bytes;
        if max_frame_bytes <= overhead {
            return Err(TelemetryError::BadArg);
        }
        let budget = max_frame_bytes - overhead;
        let total = u16::try_from(len.div_ceil(budget).max(1))
            .map_err(|_| TelemetryError::PacketTooLarge("too many chunks"))?;
        if uleb128_len(chunk_position(total - 1, total)) <= position_bytes {
            return Ok((budget, total));
        }
    }
    Err(TelemetryError::PacketTooLarge("too many chunks"))
}

/// Bytes the chunk headers of a `total`-chunk transfer add on the wire.
pub(crate) fn chunk_wire_overhead(total: u16) -> usize {
    (0..total)
        .map(|index| SIDE_TRANSPORT_CHUNK_FIXED_BYTES + uleb128_len(chunk_position(index, total)))
        .sum()
}

#[inline]
fn uleb128_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

/// A chunk frame (tests build fragments by hand).
#[cfg(test)]
pub(crate) fn test_chunk_frame(transfer: u32, index: u16, total: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![SIDE_TRANSPORT_KIND_CHUNK];
    frame.extend_from_slice(&(transfer as u16).to_le_bytes());
    write_uleb128_local(chunk_position(index, total), &mut frame);
    frame.extend_from_slice(payload);
    let crc = crc32_bytes(&frame);
    frame.extend_from_slice(&crc.to_le_bytes());
    frame
}

/// Tests that wrapped frames by hand: a whole canonical frame stays bare (a
/// side without templates sends it so); otherwise the body is a one-byte
/// template id followed by a frame, built as a FULL frame.
#[cfg(test)]
pub(crate) fn wrap_side_transport_frame(kind: u8, body: &[u8]) -> crate::SharedBytes {
    assert_eq!(kind, SIDE_TRANSPORT_KIND_FULL, "only FULL frames are built from a body");
    if wire_format::verify_frame_crc(body).is_ok() && !wire_format::is_marker_byte(body[0]) {
        return crate::shared_bytes::convert(Arc::<[u8]>::from(body));
    }
    encode_full_frame(&body[1..], u32::from(body[0]), 0, 0)
}

/// A COMPACT frame for canonical `raw` under template `id` with base `base`.
#[cfg(test)]
pub(crate) fn test_compact_frame(raw: &[u8], id: u32, base: u64) -> crate::SharedBytes {
    let parts = extract_side_header_template_view(raw).expect("templated frame");
    let head = compact_frame_head(&parts, id, 0, base);
    crate::shared_bytes::convert(frame_with_crc_from_parts(&[head.as_slice(), parts.payload]))
}

/// `(transfer, index, total, payload)` of a chunk frame.
#[cfg(test)]
pub(crate) fn test_parse_chunk_frame(frame: &[u8]) -> Option<(u32, u16, u16, &[u8])> {
    if frame.first() != Some(&SIDE_TRANSPORT_KIND_CHUNK) {
        return None;
    }
    let body = &frame[1..frame.len() - wire_format::CRC32_BYTES];
    let (transfer, index, total, header) = parse_chunk_header(body).ok()?;
    Some((transfer, index, total, &body[header..]))
}

/// The 16-bit transfer id of a chunked frame: a stable content id, including
/// the sender, never zero.
fn chunk_transfer_id(hash: u64) -> [u8; 2] {
    let folded = (hash >> 48) ^ (hash >> 32) ^ (hash >> 16) ^ hash;
    (folded as u16).max(1).to_le_bytes()
}

/// An outgoing frame or lazily encoded chunks. Retains the source plus at most
/// the current chunk instead of allocating every fragment before the first TX.
#[derive(Clone, Debug)]
pub(crate) struct SideTransportFrames {
    frame: crate::SharedBytes,
    payload_budget: usize,
    transfer_id: [u8; 2],
    index: usize,
    total: usize,
}
impl SideTransportFrames {
    pub fn single(frame: crate::SharedBytes) -> Self {
        Self {
            frame,
            payload_budget: 0,
            transfer_id: [0; 2],
            index: 0,
            total: 1,
        }
    }
    pub fn split(
        frame: crate::SharedBytes,
        max_frame_bytes: usize,
        sender: &[u8],
    ) -> TelemetryResult<Self> {
        let (payload_budget, total) = chunk_layout(frame.len(), max_frame_bytes)?;
        // Stable content ID, including sender; CRC(frame || CRC) is constant.
        let seed = hash_bytes_u64(0x517C_C1B7_2722_0A95, sender);
        let transfer_id = chunk_transfer_id(hash_bytes_u64(seed, &frame));
        Ok(Self {
            frame,
            payload_budget,
            transfer_id,
            index: 0,
            total: usize::from(total),
        })
    }
    pub(crate) fn bootstraps_template(&self) -> bool {
        self.frame.first() == Some(&SIDE_TRANSPORT_KIND_FULL)
    }
    // Canonical chunks do not mutate the side dictionary. Full or compact
    // frames must retain their encoding-history serialization barrier.
    pub(crate) fn history_dependent(&self) -> bool {
        matches!(
            side_frame_kind(&self.frame),
            Some(SIDE_TRANSPORT_KIND_FULL | SIDE_TRANSPORT_KIND_COMPACT)
        )
    }
    pub(crate) fn progress_key(&self) -> u64 {
        hash_bytes_u64(
            hash_bytes_u64(0xB618_6A85_7329_4811, &self.payload_budget.to_le_bytes()),
            &self.frame,
        )
    }
    pub(crate) fn send_resuming(
        &mut self,
        next: &mut usize,
        mut send: impl FnMut(&[u8]) -> TelemetryResult<()>,
    ) -> TelemetryResult<()> {
        if *next > self.total {
            return Err(TelemetryError::BadArg);
        }
        self.index = *next;
        loop {
            if !self.admits_next() {
                return Err(TelemetryError::Io("memory pressure"));
            }
            let Some(frame) = self.next() else { break };
            send(frame.as_ref())?;
            *next = self.index;
        }
        Ok(())
    }
    // Keep one non-generic allocation boundary shared by router and relay
    // handlers, instead of duplicating this preflight in every TX callback.
    #[inline(never)]
    fn admits_next(&self) -> bool {
        if self.index < self.total && self.payload_budget != 0 {
            // A TX callback may retain its chunk and exhaust contiguous space.
            // Retry must leave the next index unchanged when admission fails.
            let remaining = self.frame.len() - self.index * self.payload_budget;
            let bytes = remaining
                .min(self.payload_budget)
                .saturating_add(SIDE_TRANSPORT_CHUNK_FIXED_BYTES)
                .saturating_add(uleb128_len(chunk_position(
                    self.index as u16,
                    self.total as u16,
                )));
            return crate::memory_admission::check(
                bytes.saturating_add(256),
                bytes.saturating_add(32),
            )
            .is_ok();
        }
        true
    }
    pub fn wire_len(&self) -> usize {
        self.frame.len()
            + if self.payload_budget == 0 {
                0
            } else {
                chunk_wire_overhead(self.total as u16)
            }
    }
}
impl Iterator for SideTransportFrames {
    type Item = crate::SharedBytes;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.total {
            return None;
        }
        let index = self.index;
        self.index += 1;
        if self.payload_budget == 0 {
            return Some(self.frame.clone());
        }
        let start = index * self.payload_budget;
        let end = (start + self.payload_budget).min(self.frame.len());
        let mut header = SideHeaderBytes::default();
        header.push(SIDE_TRANSPORT_KIND_CHUNK);
        header.push(self.transfer_id[0]);
        header.push(self.transfer_id[1]);
        header.uleb128(chunk_position(index as u16, self.total as u16));
        Some(crate::shared_bytes::convert(frame_with_crc_from_parts(&[
            header.as_slice(),
            &self.frame[start..end],
        ])))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.index;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for SideTransportFrames {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SideHeaderTemplate {
    pub(crate) hash: u64,
    /// Canonical flags without the per-packet bits (compressed, nonce).
    pub(crate) base_flags: u8,
    // Tiny immutable codec metadata never enters the movable packet arena.
    /// The canonical static header after the flags byte: type, source,
    /// epoch, endpoints and contract.
    header: Arc<[u8]>,
}

impl SideHeaderTemplate {
    pub(crate) fn header(&self) -> &[u8] {
        &self.header
    }

    /// Sender identity belongs to the retained, validated full header. Reading
    /// it requires no payload expansion, new cached fields or CRC pass.
    pub(crate) fn source_address(&self) -> Option<u32> {
        let mut off = 0;
        read_uleb128_local(&self.header, &mut off).ok()?;
        u32::try_from(read_uleb128_local(&self.header, &mut off).ok()?).ok()
    }

    /// The retained header froze explicit destination holders (contract
    /// targets). A contract that only carries a shape does not freeze
    /// delivery.
    #[cfg(any(feature = "std", feature = "fair-admission"))]
    pub(crate) fn has_target_contract(&self) -> bool {
        let mut frame = Vec::with_capacity(1 + self.header.len() + 1);
        frame.push(self.base_flags);
        frame.extend_from_slice(&self.header);
        frame.push(0); // timestamp
        wire_format::parse_frame_header(&frame).map_or(true, |header| {
            header
                .contract
                .and_then(|contract| contract.first())
                .is_some_and(|flags| flags & 0x01 != 0)
        })
    }

    pub(crate) fn data_type(&self) -> Option<DataType> {
        let mut off = 0;
        let id = u32::try_from(read_uleb128_local(&self.header, &mut off).ok()?).ok()?;
        DataType::try_from_u32(id)
    }

    /// Templates never carry a reliable header; an ACK is known by its type.
    pub(crate) fn is_ack(&self) -> bool {
        let mut off = 0;
        read_uleb128_local(&self.header, &mut off)
            .ok()
            .is_some_and(|ty| {
                ty == u64::from(DataType::ReliableAck.as_u32())
                    || ty == u64::from(DataType::ReliablePartialAck.as_u32())
            })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SideHeaderTemplateView<'a> {
    pub(crate) hash: u64,
    pub(crate) base_flags: u8,
    pub(crate) header: &'a [u8],
}
impl SideHeaderTemplateView<'_> {
    pub(crate) fn into_owned(self) -> SideHeaderTemplate {
        SideHeaderTemplate {
            hash: self.hash,
            base_flags: self.base_flags,
            header: Arc::from(self.header),
        }
    }
}

/// A canonical frame split into its template and per-packet fields.
#[derive(Clone, Copy)]
pub(crate) struct SideFrameParts<'a> {
    pub(crate) template: SideHeaderTemplateView<'a>,
    pub(crate) ty: DataType,
    pub(crate) flags: u8,
    pub(crate) timestamp: u64,
    pub(crate) size: Option<usize>,
    pub(crate) nonce: u16,
    pub(crate) payload: &'a [u8],
}

pub(crate) struct SideFramePartsOwned<'a> {
    pub(crate) template: SideHeaderTemplate,
    pub(crate) timestamp: u64,
    #[allow(dead_code)]
    pub(crate) parts: SideFrameParts<'a>,
}

#[inline]
pub(crate) fn crc32_bytes(data: &[u8]) -> u32 {
    crate::crc32::crc32(data)
}

pub(crate) fn read_uleb128_local(buf: &[u8], off: &mut usize) -> TelemetryResult<u64> {
    crate::varint::read_u64(buf, off)
}

pub(crate) fn write_uleb128_local(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// The variable header of a side frame, built on the stack: a kind byte and
/// at most six ULEB128 fields.
pub(crate) struct SideHeaderBytes {
    bytes: [u8; 64],
    pub(crate) len: usize,
}

impl Default for SideHeaderBytes {
    fn default() -> Self {
        Self { bytes: [0; 64], len: 0 }
    }
}

impl SideHeaderBytes {
    #[inline(always)]
    pub(crate) fn push(&mut self, byte: u8) {
        self.bytes[self.len] = byte;
        self.len += 1;
    }
    /// Same encoding as `write_uleb128_local`.
    #[inline(always)]
    pub(crate) fn uleb128(&mut self, mut value: u64) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.push(byte);
            if value == 0 {
                break;
            }
        }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// One allocation holding `parts` back to back, followed by the little-endian
/// CRC-32 of all of them.
pub(crate) fn frame_with_crc_from_parts(parts: &[&[u8]]) -> Arc<[u8]> {
    let body_len: usize = parts.iter().map(|part| part.len()).sum();
    let mut frame = Arc::<[u8]>::new_uninit_slice(body_len + wire_format::CRC32_BYTES);
    let bytes = Arc::get_mut(&mut frame).expect("new frame is exclusively owned");
    let mut off = 0;
    for part in parts {
        let dst = &mut bytes[off..off + part.len()];
        // SAFETY: `dst` and `part` have the same length and cannot overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(part.as_ptr(), dst.as_mut_ptr().cast::<u8>(), part.len());
        }
        off += part.len();
    }
    // One CRC pass over the assembled body rather than one per part.
    // SAFETY: the first `body_len` bytes were all written above.
    let body = unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), body_len) };
    let mut hasher = Crc32Hasher::new();
    hasher.update(body);
    let crc = hasher.finalize().to_le_bytes();
    for (slot, byte) in bytes[body_len..].iter_mut().zip(crc) {
        slot.write(byte);
    }
    // SAFETY: the parts and the CRC fill the entire allocation.
    unsafe { frame.assume_init() }
}

/// A side-transport frame's kind and the bytes after its kind byte, or `None`
/// for a canonical frame. Nothing is verified here: each kind carries its
/// own check (see the module documentation).
pub(crate) fn parse_side_transport_wrapper(bytes: &[u8]) -> TelemetryResult<Option<(u8, &[u8])>> {
    match side_frame_kind(bytes) {
        None => Ok(None),
        Some(kind) => Ok(Some((kind, &bytes[1..]))),
    }
}

/// Prefix of a FULL frame: kind, template id and generation, and the zigzag
/// delta from the frame's timestamp to the template's base timestamp.
pub(crate) fn full_frame_prefix(template_id: u32, generation: u8, base_delta: i64) -> SideHeaderBytes {
    let mut prefix = SideHeaderBytes::default();
    prefix.push(SIDE_TRANSPORT_KIND_FULL);
    prefix.uleb128((u64::from(template_id) << TEMPLATE_GEN_BITS) | u64::from(generation & TEMPLATE_GEN_MASK));
    prefix.uleb128(zigzag(base_delta));
    prefix
}

/// A FULL frame for canonical `raw`: its prefix and the canonical data, then
/// the CRC32 of the whole frame.
pub(crate) fn encode_full_frame(raw: &[u8], template_id: u32, generation: u8, base_delta: i64) -> crate::SharedBytes {
    let prefix = full_frame_prefix(template_id, generation, base_delta);
    let data_len = raw.len() - wire_format::CRC32_BYTES;
    crate::shared_bytes::convert(frame_with_crc_from_parts(&[prefix.as_slice(), &raw[..data_len]]))
}

/// The CRC32 trailer of a side frame matches all its prior bytes.
pub(crate) fn check_frame_crc(bytes: &[u8]) -> TelemetryResult<()> {
    let data_len = bytes
        .len()
        .checked_sub(wire_format::CRC32_BYTES)
        .ok_or(TelemetryError::Unpack("short side frame"))?;
    if crc32_bytes(&bytes[..data_len]).to_le_bytes() != bytes[data_len..] {
        return Err(TelemetryError::Unpack("side frame crc32 mismatch"));
    }
    Ok(())
}

/// Template id and generation of a FULL or COMPACT frame, and the offset
/// after them.
pub(crate) fn template_id_and_gen(bytes: &[u8]) -> TelemetryResult<(u32, u8, usize)> {
    let mut off = 1;
    let field = read_uleb128_local(bytes, &mut off)?;
    let id = u32::try_from(field >> TEMPLATE_GEN_BITS)
        .map_err(|_| TelemetryError::Unpack("side template id too large"))?;
    Ok((id, (field as u8) & TEMPLATE_GEN_MASK, off))
}

/// A decoded FULL frame (its CRC32 checked here): template id, generation,
/// base delta and the canonical frame with its own CRC32.
pub(crate) fn decode_full_frame(bytes: &[u8]) -> TelemetryResult<(u32, u8, i64, Arc<[u8]>)> {
    let (template_id, generation, base_delta, view) = decode_full_frame_view(bytes)?;
    Ok((template_id, generation, base_delta, canonical_from_full_view(view)))
}

/// A FULL frame's template id, generation and base delta, and a borrowed
/// view of the canonical frame it carries: the canonical bytes followed by
/// the FULL frame's own CRC32 in place of the canonical CRC. The FULL CRC is
/// checked here, so the view is verified data for unchecked readers (type,
/// discovery and admission peeks) without allocating;
/// [`canonical_from_full_view`] builds the canonical frame itself.
pub(crate) fn decode_full_frame_view(bytes: &[u8]) -> TelemetryResult<(u32, u8, i64, &[u8])> {
    const SHORT: TelemetryError = TelemetryError::Unpack("short side full frame");
    if bytes.first() != Some(&SIDE_TRANSPORT_KIND_FULL) {
        return Err(SHORT);
    }
    check_frame_crc(bytes)?;
    let (template_id, generation, mut off) = template_id_and_gen(bytes)?;
    let base_delta = unzigzag(read_uleb128_local(bytes, &mut off)?);
    if template_id == 0 || bytes.len() < off + 1 + wire_format::CRC32_BYTES {
        return Err(SHORT);
    }
    Ok((template_id, generation, base_delta, &bytes[off..]))
}

/// The canonical frame (with its own CRC32) of a [`decode_full_frame_view`] view.
pub(crate) fn canonical_from_full_view(view: &[u8]) -> Arc<[u8]> {
    frame_with_crc_from_parts(&[&view[..view.len() - wire_format::CRC32_BYTES]])
}

pub(crate) fn extract_side_header_template(bytes: &[u8]) -> TelemetryResult<SideFramePartsOwned<'_>> {
    let parts = extract_side_header_template_view(bytes)?;
    Ok(SideFramePartsOwned {
        template: parts.template.into_owned(),
        timestamp: parts.timestamp,
        parts,
    })
}

/// Split an admitted canonical frame (CRC included, not re-verified) into its
/// template and per-packet fields. Frames with a reliable header have no
/// template.
pub(crate) fn extract_side_header_template_view(bytes: &[u8]) -> TelemetryResult<SideFrameParts<'_>> {
    if bytes.len() < wire_format::CRC32_BYTES + 3 {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let data_len = bytes.len() - wire_format::CRC32_BYTES;
    let data = &bytes[..data_len];
    let header = wire_format::parse_frame_header(data)?;
    if header.reliable.is_some() {
        return Err(TelemetryError::Unpack("reliable frames have no side template"));
    }
    let flags = header.flags;
    let base_flags =
        flags & !(SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED | SIDE_TRANSPORT_FLAG_PACKET_NONCE);
    let static_header = &data[1..header.static_end];
    let mut hash = 0xD1B5_4A32_9C7E_01F3u64;
    hash = hash_bytes_u64(hash, &[base_flags]);
    hash = hash_bytes_u64(hash, static_header);
    Ok(SideFrameParts {
        template: SideHeaderTemplateView {
            hash,
            base_flags,
            header: static_header,
        },
        ty: DataType(header.ty),
        flags,
        timestamp: header.timestamp_ms,
        size: header.size,
        nonce: header.nonce,
        payload: &data[header.payload_off..],
    })
}

/// The per-packet head of a COMPACT frame (kind, template id and
/// generation, timestamp delta, size, nonce); the payload and the frame's
/// CRC32 follow it.
pub(crate) fn compact_frame_head(
    parts: &SideFrameParts<'_>,
    template_id: u32,
    generation: u8,
    base: u64,
) -> SideHeaderBytes {
    let mut head = SideHeaderBytes::default();
    let mut kind = SIDE_TRANSPORT_KIND_COMPACT;
    if parts.flags & SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED != 0 {
        kind |= SIDE_TRANSPORT_COMPACT_COMPRESSED;
    }
    if parts.flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE != 0 {
        kind |= SIDE_TRANSPORT_COMPACT_NONCE;
    }
    head.push(kind);
    head.uleb128((u64::from(template_id) << TEMPLATE_GEN_BITS) | u64::from(generation & TEMPLATE_GEN_MASK));
    head.uleb128(zigzag(parts.timestamp.wrapping_sub(base) as i64));
    if let Some(size) = parts.size {
        head.uleb128(size as u64);
    }
    if parts.flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE != 0 {
        head.uleb128(u64::from(parts.nonce));
    }
    head
}

/// Per-packet fields of a COMPACT frame as the canonical frame encodes them:
/// (canonical flags, timestamp/size/nonce bytes, payload offset).
fn compact_fields(
    template: &SideHeaderTemplate,
    bytes: &[u8],
    off: usize,
    base: u64,
) -> TelemetryResult<(u8, SideHeaderBytes, usize)> {
    let kind = *bytes.first().ok_or(TelemetryError::Unpack("short side compact frame"))?;
    let mut off = off;
    let delta = unzigzag(read_uleb128_local(bytes, &mut off)?);
    let timestamp = base.wrapping_add(delta as u64);
    let mut flags = template.base_flags;
    if kind & SIDE_TRANSPORT_COMPACT_COMPRESSED != 0 {
        flags |= SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED;
    }
    if kind & SIDE_TRANSPORT_COMPACT_NONCE != 0 {
        flags |= SIDE_TRANSPORT_FLAG_PACKET_NONCE;
    }
    let mut fields = SideHeaderBytes::default();
    fields.uleb128(timestamp);
    if flags & SIDE_TRANSPORT_FLAGS_SIZED != 0 {
        fields.uleb128(read_uleb128_local(bytes, &mut off)?);
    }
    if flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE != 0 {
        fields.uleb128(read_uleb128_local(bytes, &mut off)?);
    }
    if bytes.len() < off + wire_format::CRC32_BYTES {
        return Err(TelemetryError::Unpack("short side compact frame"));
    }
    Ok((flags, fields, off))
}

/// Rebuild the canonical frame a COMPACT frame (CRC32 already checked)
/// stands for. `off` is the offset after the template id; `base` the
/// template's base timestamp.
pub(crate) fn reconstruct_side_compact_frame(
    template: &SideHeaderTemplate,
    bytes: &[u8],
    off: usize,
    base: u64,
) -> TelemetryResult<crate::SharedBytes> {
    let (flags, fields, off) = compact_fields(template, bytes, off, base)?;
    let crc_at = bytes.len() - wire_format::CRC32_BYTES;
    Ok(crate::shared_bytes::convert(frame_with_crc_from_parts(&[
        &[flags],
        template.header(),
        fields.as_slice(),
        &bytes[off..crc_at],
    ])))
}

pub(crate) fn canonical_packet_progress_key(packet_id: u64, max_frame_bytes: usize) -> u64 {
    hash_bytes_u64(packet_id, &max_frame_bytes.to_le_bytes())
}

#[derive(Clone, Copy, Debug)]
struct SideTxCursor {
    #[cfg(feature = "latest-value-egress")]
    history_dependent: bool,
    #[cfg(feature = "latest-value-egress")]
    latest_owner: bool,
    key: u64,
    next: usize,
    last_progress_ms: u64,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct SideTxProgress {
    slots: [Option<SideTxCursor>; 4],
}
// Keep this optional classification inside the old cursor allocation on every
// target. Comparing actual structs avoids assumptions about tuple/niche layout.
#[cfg(feature = "latest-value-egress")]
const _: () = {
    struct PreviousCursor {
        key: u64,
        next: usize,
        last_progress_ms: u64,
    }
    let previous = PreviousCursor {
        key: 0,
        next: 0,
        last_progress_ms: 0,
    };
    let _ = (previous.key, previous.next, previous.last_progress_ms);
    assert!(
        core::mem::size_of::<SideTxProgress>()
            <= core::mem::size_of::<[Option<PreviousCursor>; 4]>()
    );
};

impl SideTxProgress {
    #[cfg(feature = "latest-value-egress")]
    pub(crate) fn clear_latest_owner(&mut self) {
        for cursor in self.slots.iter_mut().flatten() {
            cursor.latest_owner = false;
        }
    }

    #[cfg(feature = "latest-value-egress")]
    pub(crate) fn has_live_latest_owner(&self, now: u64) -> bool {
        self.slots.iter().flatten().any(|cursor| {
            cursor.latest_owner
                && now.saturating_sub(cursor.last_progress_ms) <= SIDE_TX_PROGRESS_TIMEOUT_MS
        })
    }
    #[cfg(feature = "latest-value-egress")]
    pub(crate) fn has_available_slot(&self, now: u64) -> bool {
        self.slots.iter().any(|slot| {
            slot.is_none_or(|cursor| {
                now.saturating_sub(cursor.last_progress_ms) > SIDE_TX_PROGRESS_TIMEOUT_MS
            })
        })
    }

    #[cfg(feature = "latest-value-egress")]
    pub(crate) fn available_slots(&self, now: u64) -> usize {
        self.slots
            .iter()
            .filter(|slot| {
                slot.is_none_or(|cursor| {
                    now.saturating_sub(cursor.last_progress_ms) > SIDE_TX_PROGRESS_TIMEOUT_MS
                })
            })
            .count()
    }

    #[cfg(feature = "latest-value-egress")]
    pub(crate) fn has_live_key(&self, key: u64, now: u64) -> bool {
        self.slots.iter().flatten().any(|cursor| {
            cursor.key == key
                && now.saturating_sub(cursor.last_progress_ms) <= SIDE_TX_PROGRESS_TIMEOUT_MS
        })
    }

    #[cfg(all(test, feature = "latest-value-egress"))]
    pub(crate) fn is_idle(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    #[cfg(feature = "latest-value-egress")]
    pub(crate) fn blocks_latest(&self) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|cursor| cursor.history_dependent)
    }

    #[cfg(any(test, not(feature = "latest-value-egress")))]
    pub(crate) fn begin(
        &mut self,
        key: u64,
        now: u64,
        _history_dependent: bool,
    ) -> TelemetryResult<usize> {
        self.begin_classified(key, now, _history_dependent, false)
    }

    pub(crate) fn begin_classified(
        &mut self,
        key: u64,
        now: u64,
        _history_dependent: bool,
        _latest_owner: bool,
    ) -> TelemetryResult<usize> {
        for slot in &mut self.slots {
            // Match the receiver's assembly timeout. After a genuine pause,
            // the peer requires a fresh transfer, rather than a missing suffix.
            if slot.is_some_and(|entry| {
                now.saturating_sub(entry.last_progress_ms) > SIDE_TX_PROGRESS_TIMEOUT_MS
            }) {
                *slot = None;
            }
        }
        if let Some(entry) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.key == key)
        {
            #[cfg(feature = "latest-value-egress")]
            {
                entry.history_dependent |= _history_dependent;
                entry.latest_owner |= _latest_owner;
            }
            return Ok(entry.next);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(TelemetryError::Io("side chunk progress saturated"))?;
        *slot = Some(SideTxCursor {
            #[cfg(feature = "latest-value-egress")]
            history_dependent: _history_dependent,
            #[cfg(feature = "latest-value-egress")]
            latest_owner: _latest_owner,
            key,
            next: 0,
            last_progress_ms: now,
        });
        Ok(0)
    }
    pub(crate) fn finish<T>(
        &mut self,
        key: u64,
        next: usize,
        now: u64,
        result: &TelemetryResult<T>,
    ) {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|entry| entry.key == key))
        {
            if result.is_ok() || next == 0 || !matches!(result, Err(TelemetryError::Io(_))) {
                *slot = None;
            } else if let Some(entry) = slot {
                if next > entry.next {
                    entry.last_progress_ms = now;
                }
                entry.next = next;
            }
        }
    }
}

/// Send a large plaintext packet as canonical chunks without assembling an
/// additional full wire frame. Callback errors stop transmission immediately.
pub(crate) fn send_packet_chunks(
    packet: &crate::packet::Packet,
    max_frame_bytes: usize,
    sender: &[u8],
    next_chunk: &mut usize,
    mut send: impl FnMut(&[u8]) -> TelemetryResult<()>,
) -> TelemetryResult<(usize, usize, usize)> {
    if max_frame_bytes <= SIDE_TRANSPORT_CHUNK_OVERHEAD {
        return Err(TelemetryError::BadArg);
    }
    wire_format::with_plain_packet_parts(packet, |header, payload| {
        let mut crc = Crc32Hasher::new();
        crc.update(header);
        crc.update(payload);
        let crc = crc.finalize().to_le_bytes();
        let parts = [header, payload, &crc];
        let len = header.len() + payload.len() + crc.len();
        let (budget, total_u16) = chunk_layout(len, max_frame_bytes)?;
        let total = usize::from(total_u16);
        let mut hash = hash_bytes_u64(0x517C_C1B7_2722_0A95, sender);
        for part in parts {
            hash = hash_bytes_u64(hash, part);
        }
        let transfer = chunk_transfer_id(hash);
        if *next_chunk > total {
            return Err(TelemetryError::BadArg);
        }
        for index in *next_chunk..total {
            let start = index * budget;
            let end = (start + budget).min(len);
            let mut chunk_header = SideHeaderBytes::default();
            chunk_header.push(SIDE_TRANSPORT_KIND_CHUNK);
            chunk_header.push(transfer[0]);
            chunk_header.push(transfer[1]);
            chunk_header.uleb128(chunk_position(index as u16, total_u16));
            let mut slices: [&[u8]; 4] = [chunk_header.as_slice(), &[], &[], &[]];
            let mut offset = 0;
            for (i, part) in parts.iter().enumerate() {
                let low = start.saturating_sub(offset).min(part.len());
                let high = end.saturating_sub(offset).min(part.len());
                slices[i + 1] = &part[low..high];
                offset += part.len();
            }
            crate::memory_admission::check(
                max_frame_bytes.saturating_add(256),
                max_frame_bytes.saturating_add(32),
            )?;
            let chunk = frame_with_crc_from_parts(&slices);
            send(&chunk)?;
            *next_chunk = index + 1;
        }
        Ok((len, len + chunk_wire_overhead(total_u16), total))
    })
}

#[cfg(test)]
mod streamed_chunk_tests {
    use super::*;
    #[test]
    #[cfg(feature = "latest-value-egress")]
    fn cursor_history_classification_never_weakens_a_retained_owner() {
        let mut progress = SideTxProgress::default();
        assert_eq!(progress.begin(1, 0, false).unwrap(), 0);
        progress.finish(1, 1, 0, &Err::<(), _>(TelemetryError::Io("busy")));
        assert!(!progress.blocks_latest());
        assert_eq!(progress.begin(1, 1, true).unwrap(), 1);
        assert!(progress.blocks_latest());
        assert_eq!(progress.begin(1, 2, false).unwrap(), 1);
        assert!(
            progress.blocks_latest(),
            "matching keys cannot weaken history protection"
        );
        progress.finish(1, 2, 2, &Ok(()));
        assert!(!progress.blocks_latest());
    }

    #[test]
    fn lazy_chunks_recheck_fragmentation_and_resume_without_skipping() {
        use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        static ALLOW: AtomicBool = AtomicBool::new(true);
        static LARGEST: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn probe(_: usize, largest: usize) -> bool {
            LARGEST.store(largest, Ordering::Relaxed);
            ALLOW.load(Ordering::Relaxed)
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                crate::memory_admission::set_probe(None);
            }
        }
        let source: crate::SharedBytes =
            crate::shared_bytes::convert(Arc::<[u8]>::from(vec![0x55; 3000]));
        let expected = SideTransportFrames::split(source.clone(), 1024, b"GB")
            .unwrap()
            .collect::<Vec<_>>();
        let mut frames = SideTransportFrames::split(source, 1024, b"GB").unwrap();
        let mut actual = Vec::new();
        let mut next = 0;
        ALLOW.store(true, Ordering::Relaxed);
        crate::memory_admission::set_probe(Some(probe));
        let _reset = Reset;
        let result = frames.send_resuming(&mut next, |bytes| {
            actual.push(Arc::<[u8]>::from(bytes));
            // Retained TX data leaves only small holes before the next chunk.
            ALLOW.store(false, Ordering::Relaxed);
            Ok(())
        });
        assert!(matches!(result, Err(TelemetryError::Io("memory pressure"))));
        assert_eq!(next, 1);
        assert_eq!(actual.len(), 1);
        assert_eq!(LARGEST.load(Ordering::Relaxed), 1056);
        ALLOW.store(true, Ordering::Relaxed);
        frames
            .send_resuming(&mut next, |bytes| {
                actual.push(Arc::<[u8]>::from(bytes));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            actual.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            expected.iter().map(|b| b.as_ref()).collect::<Vec<_>>()
        );
        assert_eq!(next, expected.len());
    }

    #[test]
    fn chunk_position_round_trips_and_stays_as_short_as_two_fields() {
        let uleb = |v: u64| uleb128_len(v);
        for total in (1u16..=300).chain([1000, 16384, 40000, u16::MAX]) {
            for index in (0..total).filter(|i| *i < 4 || u32::from(*i) + 4 > u32::from(total) || i % 97 == 0) {
                let position = chunk_position(index, total);
                assert_eq!(decode_chunk_position(position), Some((index, total)));
                // At most one byte longer than separate fields, and never
                // longer below 23171 chunks.
                let separate = uleb(index.into()) + uleb(total.into());
                assert!(uleb(position) <= separate + usize::from(total > 23170));
            }
        }
        assert_eq!(uleb(chunk_position(14, 15)), 1);
        assert_eq!(decode_chunk_position(chunk_position(u16::MAX - 1, u16::MAX) + 1), None);
        // Every chunk fits the frame, including multi-byte positions.
        for (len, max) in [(1, 12), (3000, 1024), (2000, 64), (100_000, 64), (1053, 192)] {
            let (budget, total) = chunk_layout(len, max).unwrap();
            let longest = SIDE_TRANSPORT_CHUNK_FIXED_BYTES + uleb(chunk_position(total - 1, total));
            assert!(budget + longest <= max, "{len} {max}");
            assert_eq!(usize::from(total), len.div_ceil(budget));
        }
        assert_eq!(chunk_layout(1053, 192).unwrap(), (184, 6));
        assert!(chunk_layout(10, SIDE_TRANSPORT_CHUNK_OVERHEAD).is_err());
    }

    #[test]
    fn streamed_chunks_match_canonical_frame_and_stop_on_callback_error() {
        let packet = crate::packet::Packet::new(
            DataType::DiscoverySchema,
            &[crate::DataEndpoint::Discovery],
            "GB",
            u64::MAX,
            Arc::from((0..3600).map(|i| (i % 251) as u8).collect::<Vec<_>>()),
        )
        .unwrap();
        let raw = wire_format::pack_packet(&packet);
        for max_bytes in [32, 128, 1024, 4096] {
            let expected = SideTransportFrames::split(
                crate::shared_bytes::convert(raw.clone()),
                max_bytes,
                b"GB",
            )
            .unwrap()
            .collect::<Vec<_>>();
            let mut actual = Vec::new();
            send_packet_chunks(&packet, max_bytes, b"GB", &mut 0, |chunk| {
                actual.push(Arc::<[u8]>::from(chunk));
                Ok(())
            })
            .unwrap();
            assert_eq!(
                actual.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
                expected.iter().map(|b| b.as_ref()).collect::<Vec<_>>()
            );
        }
        let mut calls = 0;
        let result = send_packet_chunks(&packet, 32, b"GB", &mut 0, |_| {
            calls += 1;
            Err(TelemetryError::Io("test stop"))
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SideChunkAssembly {
    pub(crate) last_seen_ms: u64,
    pub(crate) total: u16,
    // One bounded descriptor allocation replaces repeated B-tree node growth.
    // Payloads remain shared slices; completed frames still use the store.
    pub(crate) received: Vec<Option<Arc<[u8]>>>,
    pub(crate) received_count: u16,
}

impl SideChunkAssembly {
    /// Unique admitted fragments already own the bounded progress clock.
    /// A duplicate cannot extend it; missing first chunks prove no peer/type.
    pub(crate) fn schema_progress_for(&self, address: u32, now: u64) -> bool {
        now.saturating_sub(self.last_seen_ms) <= 2000
            && self
                .received
                .first()
                .and_then(|chunk| chunk.as_ref())
                .and_then(|prefix| wire_format::chunked_schema_source(prefix))
                == Some(address)
    }

    // Arc/allocator bookkeeping and padding, excluding the separately charged
    // descriptor vector. The former 64-byte estimate included B-tree entries.
    const FRAGMENT_OVERHEAD: usize = 48;
    #[inline(never)]
    pub(crate) fn oldest(chunks: &OrdMap<u32, Self>, keep: Option<u32>) -> Option<(u32, u64)> {
        let mut victim = None;
        let mut time = u64::MAX;
        // B-tree iteration already breaks equal-time ties by transfer ID.
        for (&id, assembly) in chunks {
            if keep != Some(id) && (victim.is_none() || assembly.last_seen_ms < time) {
                victim = Some(id);
                time = assembly.last_seen_ms;
            }
        }
        victim.map(|id| (id, time))
    }
    fn descriptor_bytes(total: u16) -> usize {
        usize::from(total).saturating_mul(core::mem::size_of::<Option<Arc<[u8]>>>())
    }
    pub(crate) fn received_len(&self) -> usize {
        usize::from(self.received_count)
    }
    pub(crate) fn contains_index(&self, index: u16) -> bool {
        self.received
            .get(usize::from(index))
            .is_some_and(Option::is_some)
    }
    /// Include allocated descriptors even before the last fragment arrives.
    pub(crate) fn byte_cost(&self) -> usize {
        self.received
            .iter()
            .flatten()
            .map(|p| p.len())
            .sum::<usize>()
            .saturating_add(self.received_len().saturating_mul(Self::FRAGMENT_OVERHEAD))
            .saturating_add(
                self.received
                    .capacity()
                    .saturating_mul(core::mem::size_of::<Option<Arc<[u8]>>>()),
            )
    }
    pub(crate) fn insert_with(
        &mut self,
        index: u16,
        now_ms: u64,
        make: impl FnOnce() -> Arc<[u8]>,
    ) -> TelemetryResult<usize> {
        if index >= self.total {
            return Err(TelemetryError::Unpack("invalid side chunk index"));
        }
        if !self.received.is_empty() && self.received.len() != usize::from(self.total) {
            return Err(TelemetryError::Unpack("side chunk total changed"));
        }
        if self.contains_index(index) {
            return Ok(0);
        }
        let mut descriptor_cost = 0;
        if self.received.is_empty() {
            descriptor_cost = Self::descriptor_bytes(self.total);
            crate::memory_admission::check(
                descriptor_cost.saturating_add(128),
                descriptor_cost.saturating_add(32),
            )?;
            self.received
                .try_reserve_exact(usize::from(self.total))
                .map_err(|_| TelemetryError::Unpack("side chunk descriptors allocation failed"))?;
            self.received.resize_with(usize::from(self.total), || None);
        }
        let bytes = make();
        let cost = bytes
            .len()
            .saturating_add(Self::FRAGMENT_OVERHEAD)
            .saturating_add(descriptor_cost);
        self.received[usize::from(index)] = Some(bytes);
        self.received_count += 1;
        // Only newly retained data extends assembly lifetime. Refused or replayed
        // fragments must not keep incomplete transfers alive indefinitely.
        self.last_seen_ms = now_ms;
        Ok(cost)
    }
    #[cfg(test)]
    pub(crate) fn insert(&mut self, index: u16, bytes: crate::SharedBytes) {
        self.insert_with(index, self.last_seen_ms, || {
            crate::shared_bytes::convert(bytes)
        })
        .unwrap();
    }
    #[inline(never)]
    pub(crate) fn remove(
        chunks: &mut OrdMap<u32, Self>,
        buffered: &mut usize,
        id: u32,
    ) -> Option<Self> {
        let value = chunks.remove(&id)?;
        *buffered = buffered.saturating_sub(value.byte_cost());
        Some(value)
    }
    #[inline(never)]
    pub(crate) fn expire(chunks: &mut OrdMap<u32, Self>, buffered: &mut usize, now: u64) -> u32 {
        let mut reclaimed = 0u32;
        // Each link admits at most four assemblies. Reuse ordinary removal
        // rather than linking a second B-tree deletion/retention iterator.
        while let Some(id) = chunks.iter().find_map(|(&id, assembly)| {
            (now.saturating_sub(assembly.last_seen_ms) > 2000).then_some(id)
        }) {
            Self::remove(chunks, buffered, id);
            reclaimed = reclaimed.saturating_add(1);
        }
        reclaimed
    }
    pub(crate) fn make_room(
        chunks: &mut OrdMap<u32, Self>,
        buffered: &mut usize,
        transfer_id: u32,
        index: u16,
        total: u16,
        payload_len: usize,
        budget: usize,
    ) -> TelemetryResult<usize> {
        debug_assert_eq!(
            *buffered,
            chunks.values().map(Self::byte_cost).sum::<usize>()
        );
        let descriptor_cost = if chunks
            .get(&transfer_id)
            .is_none_or(|a| a.received.is_empty())
        {
            Self::descriptor_bytes(total)
        } else {
            0
        };
        let cost = payload_len
            .saturating_add(Self::FRAGMENT_OVERHEAD)
            .saturating_add(descriptor_cost);
        if usize::from(total) > budget / 64 || cost > budget {
            Self::remove(chunks, buffered, transfer_id);
            return Err(TelemetryError::PacketTooLarge("side chunk receive budget"));
        }
        if chunks
            .get(&transfer_id)
            .is_some_and(|a| a.contains_index(index))
        {
            return Ok(0);
        }
        while buffered.saturating_add(cost) > budget {
            let Some((victim, _)) = Self::oldest(chunks, Some(transfer_id)) else {
                Self::remove(chunks, buffered, transfer_id);
                return Err(TelemetryError::PacketTooLarge("side chunk receive budget"));
            };
            Self::remove(chunks, buffered, victim);
        }
        Ok(cost)
    }

    pub(crate) fn assemble(self) -> TelemetryResult<Vec<u8>> {
        if self.received_len() != usize::from(self.total) {
            return Err(TelemetryError::Unpack("side chunk gap"));
        }
        let len = self
            .received
            .iter()
            .flatten()
            .try_fold(0usize, |n, chunk| {
                n.checked_add(chunk.len())
                    .ok_or(TelemetryError::PacketTooLarge("side chunk size overflow"))
            })?;
        // Prefer one allocation when the full scratch fits. Under pressure,
        // retaining all fragments while reserving a second full frame can
        // prevent a bounded schema from ever completing. Grow in at most eight
        // exact steps instead, releasing consumed fragment storage as we copy.
        // Each allocation still passes the original headroom/contiguous guard;
        // no extra reserve or decoder permission is granted by this fallback.
        let eager =
            match crate::memory_admission::check(len.saturating_add(512), len.saturating_add(32)) {
                Ok(()) => true,
                Err(TelemetryError::Io("memory pressure")) => false,
                Err(error) => return Err(error),
            };
        let step = len.div_ceil(8).max(128);
        let mut out = Vec::new();
        if eager {
            out.try_reserve_exact(len)
                .map_err(|_| TelemetryError::Unpack("side chunk assembly allocation failed"))?;
        }
        // A fixed tail lets the descriptor allocation go before the final
        // buffer growth. Otherwise keeping Vec's full descriptor capacity
        // alive regresses fragmented assembly's existing headroom bound.
        // This is 128 bytes of metadata on 32-bit targets, independent of total.
        let mut fragments = self.received.into_iter();
        let tail_count = fragments.len().min(16);
        let mut tail: [Option<Arc<[u8]>>; 16] = core::array::from_fn(|_| None);
        for slot in tail[..tail_count].iter_mut().rev() {
            *slot = fragments.next_back().flatten();
        }
        // Chain drops its exhausted first iterator before requesting the tail.
        let mut fragments = fragments
            .chain(tail.into_iter().take(tail_count))
            .peekable();
        let mut scratch = [0u8; 256];
        let mut append = |bytes: &[u8]| -> TelemetryResult<()> {
            let end = out.len().saturating_add(bytes.len());
            if end > out.capacity() {
                let target = end.div_ceil(step).saturating_mul(step).min(len);
                crate::memory_admission::check(
                    target.saturating_add(128).max(1024),
                    target.saturating_add(32),
                )?;
                out.try_reserve_exact(target - out.len())
                    .map_err(|_| TelemetryError::Unpack("side chunk assembly allocation failed"))?;
            }
            out.extend_from_slice(bytes);
            Ok(())
        };
        while let Some(chunk) = fragments.next() {
            let chunk = chunk.ok_or(TelemetryError::Unpack("side chunk gap"))?;
            if chunk.len() <= scratch.len() {
                let mut used = chunk.len();
                scratch[..used].copy_from_slice(&chunk);
                drop(chunk);
                // Release up to two small payload allocations before growing
                // the output, rather than holding them beside both Vec buffers.
                if fragments.peek().is_some_and(|next| {
                    next.as_ref()
                        .is_some_and(|p| p.len() <= scratch.len() - used)
                }) {
                    let next = fragments
                        .next()
                        .flatten()
                        .ok_or(TelemetryError::Unpack("side chunk gap"))?;
                    scratch[used..used + next.len()].copy_from_slice(&next);
                    used += next.len();
                    drop(next);
                }
                append(&scratch[..used])?;
            } else {
                append(&chunk)?;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod template_storage_tests {
    use super::*;
    #[test]
    fn immutable_template_metadata_stays_small_in_both_packet_store_modes() {
        assert!(size_of::<SideHeaderTemplate>() <= size_of::<Arc<[u8]>>() + 24);
    }
    #[test]
    fn clones_share_the_header() {
        let view = SideHeaderTemplateView {
            hash: 77,
            base_flags: 5,
            header: &[1, 2, 3, 9, 8],
        };
        let owned = view.into_owned();
        let clone = owned.clone();
        assert!(Arc::ptr_eq(&owned.header, &clone.header));
        drop(owned);
        assert_eq!(clone.header(), &[1, 2, 3, 9, 8]);
        assert_eq!((clone.hash, clone.base_flags), (77, 5));
    }
}

#[cfg(all(test, feature = "std"))]
mod template_codec_tests {
    use super::*;
    use crate::packet::Packet;

    fn frame(ts: u64, nonce: u16, payload: &[u8]) -> Arc<[u8]> {
        let ep = crate::message_meta(DataType::TimeSyncAnnounce).endpoints_ref()[0];
        let pkt = Packet::new(DataType::TimeSyncAnnounce, &[ep], "CODEC", ts, Arc::from(payload))
            .unwrap()
            .with_nonce(nonce)
            .with_time_epoch(2);
        wire_format::pack_packet(&pkt)
    }

    fn compact(raw: &[u8], id: u32, generation: u8, base: u64) -> Vec<u8> {
        let parts = extract_side_header_template_view(raw).unwrap();
        let head = compact_frame_head(&parts, id, generation, base);
        frame_with_crc_from_parts(&[head.as_slice(), parts.payload]).to_vec()
    }

    fn rebuild(template: &SideHeaderTemplate, bytes: &[u8], base: u64) -> TelemetryResult<Vec<u8>> {
        check_frame_crc(bytes)?;
        let (_, _, off) = template_id_and_gen(bytes)?;
        Ok(reconstruct_side_compact_frame(template, bytes, off, base)?.to_vec())
    }

    #[test]
    fn full_frames_round_trip_and_every_byte_is_checked() {
        let raw = frame(1_795_000_000_000, 300, &[7; 16]);
        let full = encode_full_frame(&raw, 3, 5, -40).to_vec();
        assert_eq!(full.len(), raw.len() + 3, "kind, one-byte id/generation, one-byte base delta");
        // Any hop can check the frame alone.
        check_frame_crc(&full).unwrap();
        let (id, generation, delta, back) = decode_full_frame(&full).unwrap();
        assert_eq!((id, generation, delta, back.as_ref()), (3, 5, -40, raw.as_ref()));
        for at in 0..full.len() {
            for bit in 0..8 {
                let mut bad = full.clone();
                bad[at] ^= 1 << bit;
                assert!(decode_full_frame(&bad).is_err(), "corruption at {at}.{bit} accepted");
            }
        }
    }

    #[test]
    fn compact_frames_rebuild_exactly_and_damage_is_detected() {
        let base = 1_795_000_000_000;
        let first = frame(base, 300, &[7; 16]);
        let template = extract_side_header_template(&first).unwrap().template;
        for (ts, nonce, payload) in [(base + 100, 301, [8u8; 16]), (base - 5, 302, [9; 16]), (base, 1, [0; 16])] {
            let raw = frame(ts, nonce, &payload);
            let bytes = compact(&raw, 1, 6, base);
            assert!(bytes.len() <= 1 + 1 + 3 + 3 + 16 + 4);
            assert_eq!(side_frame_kind(&bytes), Some(SIDE_TRANSPORT_KIND_COMPACT));
            assert_eq!(template_id_and_gen(&bytes).unwrap(), (1, 6, 2));
            assert_eq!(rebuild(&template, &bytes, base).unwrap(), raw.to_vec());
            for at in 0..bytes.len() {
                for bit in 0..8 {
                    let mut bad = bytes.clone();
                    bad[at] ^= 1 << bit;
                    assert!(check_frame_crc(&bad).is_err(), "corruption at {at}.{bit} accepted");
                }
            }
        }
        // Ids above 15 or generations wrap within the field.
        let raw = frame(base, 7, &[1; 16]);
        let bytes = compact(&raw, 300, 7, base);
        assert_eq!(template_id_and_gen(&bytes).unwrap().0, 300);
        assert_eq!(template_id_and_gen(&bytes).unwrap().1, 7);
        assert_eq!(unpack_template_base(pack_template_base(base, 5)), (base, 5));
    }
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<SideChunkAssembly>() == 24);

#[cfg(all(test, feature = "std"))]
mod incremental_chunk_cache_tests {
    use super::*;
    #[test]
    fn large_assemblies_keep_exact_cost_after_small_cache_saturates() {
        let mut assembly = SideChunkAssembly {
            total: 2,
            ..Default::default()
        };
        let left = vec![3u8; 60000];
        let right = vec![7u8; 20000];
        assert_eq!(
            assembly
                .insert_with(0, 0, || crate::shared_bytes::convert(Arc::<[u8]>::from(
                    left
                )))
                .unwrap(),
            60048 + SideChunkAssembly::descriptor_bytes(2)
        );
        assert_eq!(
            assembly
                .insert_with(1, 0, || crate::shared_bytes::convert(Arc::<[u8]>::from(
                    right
                )))
                .unwrap(),
            20048
        );
        assert_eq!(assembly.received_len(), 2);
        assert_eq!(
            assembly.byte_cost(),
            80096 + SideChunkAssembly::descriptor_bytes(2)
        );
        let out = assembly.assemble().unwrap();
        assert_eq!(out.len(), 80000);
        assert!(out[..60000].iter().all(|b| *b == 3));
        assert!(out[60000..].iter().all(|b| *b == 7));
    }
    #[test]
    fn duplicate_does_not_allocate_or_change_cached_cost() {
        let mut assembly = SideChunkAssembly {
            total: 2,
            ..Default::default()
        };
        assembly
            .insert_with(0, 0, || {
                crate::shared_bytes::convert(Arc::<[u8]>::from([9u8; 112]))
            })
            .unwrap();
        assert_eq!(
            assembly
                .insert_with(0, 0, || panic!("duplicate called payload factory"))
                .unwrap(),
            0
        );
        assert_eq!(
            assembly.byte_cost(),
            160 + SideChunkAssembly::descriptor_bytes(2)
        );
    }
}

#[cfg(test)]
mod expiry_chunk_cache_tests {
    use super::*;

    fn fixture(entries: &[(u32, u64, usize)]) -> (OrdMap<u32, SideChunkAssembly>, usize) {
        let mut chunks = OrdMap::new();
        let mut buffered = 0usize;
        for &(id, last_seen_ms, length) in entries {
            let mut assembly = SideChunkAssembly {
                total: 2,
                last_seen_ms,
                ..Default::default()
            };
            buffered += assembly
                .insert_with(0, last_seen_ms, || {
                    crate::shared_bytes::convert(Arc::<[u8]>::from(vec![id as u8; length]))
                })
                .unwrap();
            chunks.insert(id, assembly);
        }
        (chunks, buffered)
    }

    #[test]
    fn chunk_expiry_keeps_exact_boundary_and_future_clock_entries() {
        let (mut chunks, mut buffered) =
            fixture(&[(1, 0, 3), (2, 2000, 4), (3, u64::MAX, 5), (4, 1, 1)]);
        let original = buffered;
        assert_eq!(
            SideChunkAssembly::expire(&mut chunks, &mut buffered, 2000),
            0
        );
        assert_eq!(buffered, original);
        assert_eq!(
            SideChunkAssembly::expire(&mut chunks, &mut buffered, 2001),
            1
        );
        assert_eq!(
            buffered,
            original - 51 - SideChunkAssembly::descriptor_bytes(2)
        );
        assert!(!chunks.contains_key(&1));
        assert_eq!(
            SideChunkAssembly::expire(&mut chunks, &mut buffered, 2001),
            0
        );
        assert_eq!(SideChunkAssembly::expire(&mut chunks, &mut buffered, 0), 0);
        assert_eq!(
            SideChunkAssembly::expire(&mut chunks, &mut buffered, 4001),
            2
        );
        assert_eq!(chunks.keys().copied().collect::<Vec<_>>(), vec![3]);
        assert_eq!(buffered, 53 + SideChunkAssembly::descriptor_bytes(2));
    }

    #[test]
    fn chunk_expiry_matches_retention_model_for_every_four_entry_subset() {
        for expired_mask in 0u32..16 {
            let entries = [0, 1, 7, u32::MAX]
                .into_iter()
                .enumerate()
                .map(|(index, id)| {
                    (
                        id,
                        if expired_mask & (1 << index) != 0 {
                            0
                        } else {
                            1001
                        },
                        1 + index * 112,
                    )
                })
                .collect::<Vec<_>>();
            let (mut chunks, mut buffered) = fixture(&entries);
            let mut expected = chunks.clone();
            expected.retain(|_, assembly| 3001u64.saturating_sub(assembly.last_seen_ms) <= 2000);
            let expected_bytes = expected
                .values()
                .map(SideChunkAssembly::byte_cost)
                .sum::<usize>();
            assert_eq!(
                SideChunkAssembly::expire(&mut chunks, &mut buffered, 3001),
                expired_mask.count_ones()
            );
            assert_eq!(chunks, expected);
            assert_eq!(buffered, expected_bytes);
        }
    }

    #[test]
    fn chunk_expiry_releases_full_cost_after_small_payload_cache_saturates() {
        let (mut chunks, mut buffered) = fixture(&[(1, 0, 80000), (2, 2001, 20)]);
        assert_eq!(chunks[&1].received_len(), 1);
        assert_eq!(
            buffered,
            80048 + 68 + 2 * SideChunkAssembly::descriptor_bytes(2)
        );
        assert_eq!(
            SideChunkAssembly::expire(&mut chunks, &mut buffered, 2001),
            1
        );
        assert_eq!(buffered, 68 + SideChunkAssembly::descriptor_bytes(2));
        assert_eq!(chunks.keys().copied().collect::<Vec<_>>(), vec![2]);
    }
}

#[cfg(all(test, feature = "std"))]
mod chunk_slot_tests {
    use super::*;
    #[test]
    fn forty_reordered_fragments_reuse_one_bounded_descriptor_buffer() {
        let mut assembly = SideChunkAssembly {
            last_seen_ms: 42,
            total: 40,
            ..Default::default()
        };
        let mut cost = 0;
        for index in (0u16..40).rev() {
            cost += assembly
                .insert_with(index, 0, || Arc::<[u8]>::from([index as u8; 84]))
                .unwrap();
            assert_eq!(assembly.received.capacity(), 40);
            assert_eq!(assembly.byte_cost(), cost);
            assert_eq!(
                assembly
                    .insert_with(index, 0, || panic!("duplicate allocated"))
                    .unwrap(),
                0
            );
        }
        assert_eq!(assembly.received_len(), 40);
        let bytes = assembly.assemble().unwrap();
        assert_eq!(bytes.len(), 40 * 84);
        for (index, chunk) in bytes.as_chunks::<84>().0.iter().enumerate() {
            assert!(chunk.iter().all(|b| usize::from(*b) == index));
        }
    }
    #[test]
    fn only_newly_accepted_fragments_extend_assembly_lifetime() {
        let mut assembly = SideChunkAssembly {
            total: 2,
            last_seen_ms: 10,
            ..Default::default()
        };
        assembly
            .insert_with(0, 100, || Arc::<[u8]>::from([1]))
            .unwrap();
        assert_eq!(assembly.last_seen_ms, 100);
        assert_eq!(
            assembly
                .insert_with(0, 1800, || panic!("duplicate allocated"))
                .unwrap(),
            0
        );
        assert!(
            assembly
                .insert_with(2, 1900, || panic!("invalid allocated"))
                .is_err()
        );
        assert_eq!(assembly.last_seen_ms, 100);
        let mut chunks = OrdMap::from([(1, assembly)]);
        let mut buffered = chunks[&1].byte_cost();
        // A repeated fragment cannot extend the original two-second expiry.
        SideChunkAssembly::expire(&mut chunks, &mut buffered, 2101);
        assert!(chunks.is_empty());
        assert_eq!(buffered, 0);
    }
    #[test]
    fn descriptor_admission_precedes_payload_allocation_and_invalid_indices_are_rejected() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                crate::memory_admission::set_probe(None);
            }
        }
        let mut assembly = SideChunkAssembly {
            last_seen_ms: 42,
            total: 40,
            ..Default::default()
        };
        let _reset = Reset;
        extern "C" fn deny(_: usize, _: usize) -> bool {
            false
        }
        crate::memory_admission::set_probe(Some(deny));
        assert!(
            assembly
                .insert_with(0, 1000, || panic!(
                    "unadmitted descriptors allocated payload"
                ))
                .is_err()
        );
        assert!(assembly.received.is_empty());
        assert_eq!(assembly.received_len(), 0);
        assert_eq!(assembly.last_seen_ms, 42);
        assert!(
            assembly
                .insert_with(40, 0, || panic!("invalid index allocated payload"))
                .is_err()
        );
    }
}
