//! Shared wire codec for router and relay side transports.

use crate::{DataType, TelemetryError, TelemetryResult, packet::hash_bytes_u64, wire_format};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use crc32fast::Hasher as Crc32Hasher;

pub(crate) const SIDE_TRANSPORT_MAGIC: &[u8; 3] = b"SDT";
pub(crate) const SIDE_TRANSPORT_KIND_FULL: u8 = 0x01;
pub(crate) const SIDE_TRANSPORT_KIND_COMPACT: u8 = 0x02;
pub(crate) const SIDE_TRANSPORT_KIND_CHUNK: u8 = 0x03;
pub(crate) const SIDE_TRANSPORT_KIND_COMPACT_DELTA: u8 = 0x04;
pub(crate) const SIDE_TRANSPORT_KIND_COMPACT_SAME_TIMESTAMP: u8 = 0x05;
pub(crate) const SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED: u8 = 0x01;
pub(crate) const SIDE_TRANSPORT_FLAG_WIRE_CONTRACT: u8 = 0x04;
pub(crate) const SIDE_TRANSPORT_FLAG_PACKET_NONCE: u8 = 0x08;
pub(crate) const SIDE_TRANSPORT_FLAG_ENDPOINT_BITMAP_PRESENT: u8 = 0x20;
pub(crate) const SIDE_TRANSPORT_FLAG_ENDPOINT_LIST_PRESENT: u8 = 0x80;
pub(crate) const SIDE_TRANSPORT_FLAG_COMPACT_RELIABLE_HEADER: u8 = 0x40;
pub(crate) const SIDE_TRANSPORT_CHUNK_OVERHEAD: usize =
    3 + 1 + 4 + 2 + 2 + wire_format::CRC32_BYTES;
pub(crate) const SIDE_TRANSPORT_EP_BITMAP_BITS: usize =
    (crate::MAX_VALUE_DATA_ENDPOINT as usize) + 1;
pub(crate) const SIDE_TRANSPORT_EP_BITMAP_BYTES: usize = SIDE_TRANSPORT_EP_BITMAP_BITS.div_ceil(8);

/// An outgoing frame or lazily encoded chunks. Retains the source plus at most
/// the current chunk instead of allocating every fragment before the first TX.
#[derive(Clone, Debug)]
pub(crate) struct SideTransportFrames {
    frame: crate::SharedBytes,
    payload_budget: usize,
    transfer_id: u32,
    index: usize,
    total: usize,
}
impl SideTransportFrames {
    pub fn single(frame: crate::SharedBytes) -> Self {
        Self {
            frame,
            payload_budget: 0,
            transfer_id: 0,
            index: 0,
            total: 1,
        }
    }
    pub fn split(
        frame: crate::SharedBytes,
        max_frame_bytes: usize,
        sender: &[u8],
    ) -> TelemetryResult<Self> {
        if max_frame_bytes <= SIDE_TRANSPORT_CHUNK_OVERHEAD {
            return Err(TelemetryError::BadArg);
        }
        let payload_budget = max_frame_bytes - SIDE_TRANSPORT_CHUNK_OVERHEAD;
        let total = frame.len().div_ceil(payload_budget);
        u16::try_from(total).map_err(|_| TelemetryError::PacketTooLarge("too many chunks"))?;
        // Stable content ID, including sender; CRC(frame || CRC) is constant.
        let seed = hash_bytes_u64(0x517C_C1B7_2722_0A95, sender);
        let hash = hash_bytes_u64(seed, &frame);
        let transfer_id = ((hash >> 32) as u32 ^ hash as u32).max(1);
        Ok(Self {
            frame,
            payload_budget,
            transfer_id,
            index: 0,
            total,
        })
    }
    pub(crate) fn bootstraps_template(&self) -> bool {
        self.frame.starts_with(SIDE_TRANSPORT_MAGIC)
            && self.frame.get(3) == Some(&SIDE_TRANSPORT_KIND_FULL)
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
                .saturating_add(SIDE_TRANSPORT_CHUNK_OVERHEAD);
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
                self.total * SIDE_TRANSPORT_CHUNK_OVERHEAD
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
        Some(wrap_side_transport_frame_parts(
            SIDE_TRANSPORT_KIND_CHUNK,
            &[
                &self.transfer_id.to_le_bytes(),
                &(index as u16).to_le_bytes(),
                &(self.total as u16).to_le_bytes(),
                &self.frame[start..end],
            ],
        ))
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
    pub(crate) base_flags: u8,
    // Tiny immutable codec metadata never enters the movable packet arena.
    // Keep both ranges in one shared allocation rather than two wide handles.
    header: Arc<[u8]>,
    prefix_len: usize,
    pub(crate) reliable_flags: Option<u8>,
    pub(crate) reliable_compact: bool,
}

impl SideHeaderTemplate {
    pub(crate) fn prefix(&self) -> &[u8] {
        &self.header[..self.prefix_len]
    }
    pub(crate) fn between(&self) -> &[u8] {
        &self.header[self.prefix_len..]
    }

    /// Sender identity belongs to the retained, validated full header. Reading
    /// it requires no payload expansion, new cached fields or CRC pass.
    #[cfg(any(feature = "discovery", feature = "std", feature = "fair-admission"))]
    pub(crate) fn source_address(&self) -> Option<u32> {
        let mut off = 0;
        u32::try_from(read_uleb128_local(self.between(), &mut off).ok()?).ok()
    }

    pub(crate) fn data_type(&self) -> Option<DataType> {
        // The retained prefix begins with endpoint count, then type ULEB128.
        let mut off = 1;
        let id = u32::try_from(read_uleb128_local(self.prefix(), &mut off).ok()?).ok()?;
        DataType::try_from_u32(id)
    }

    pub(crate) fn is_ack(&self) -> bool {
        if self
            .reliable_flags
            .is_some_and(|flags| flags & wire_format::RELIABLE_FLAG_ACK_ONLY != 0)
        {
            return true;
        }
        // Prefix is endpoint count followed by the canonical type ULEB128.
        let mut off = 1;
        read_uleb128_local(self.prefix(), &mut off)
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
    pub(crate) prefix: &'a [u8],
    pub(crate) between: &'a [u8],
    pub(crate) reliable_flags: Option<u8>,
    pub(crate) reliable_compact: bool,
}
impl SideHeaderTemplateView<'_> {
    pub(crate) fn into_owned(self) -> SideHeaderTemplate {
        SideHeaderTemplate {
            hash: self.hash,
            base_flags: self.base_flags,
            // The exact-size slice iterator builds the Arc directly; no
            // concatenation buffer doubles peak header scratch storage.
            header: self
                .prefix
                .iter()
                .chain(self.between.iter())
                .copied()
                .collect(),
            prefix_len: self.prefix.len(),
            reliable_flags: self.reliable_flags,
            reliable_compact: self.reliable_compact,
        }
    }
}
type SideTemplateViewExtract<'a> = (
    SideHeaderTemplateView<'a>,
    DataType,
    u8,
    u64,
    u64,
    u16,
    Option<(u32, u32)>,
    &'a [u8],
);

type SideTemplateExtract<'a> = (
    SideHeaderTemplate,
    DataType,
    u8,
    u64,
    u64,
    u16,
    Option<(u32, u32)>,
    &'a [u8],
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SideCompactTimestampMode {
    Absolute,
    Delta,
    Omitted,
}

#[inline]
pub(crate) fn crc32_bytes(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    hasher.finalize()
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

pub(crate) fn wrap_side_transport_frame(kind: u8, body: &[u8]) -> crate::SharedBytes {
    wrap_side_transport_frame_parts(kind, &[body])
}

// Write body segments directly into the final allocation. This also lets a
// chunk header stay on the stack instead of copying its payload into a Vec.
pub(crate) fn wrap_side_transport_frame_parts(kind: u8, parts: &[&[u8]]) -> crate::SharedBytes {
    let header = [b'S', b'D', b'T', kind];
    let mut hasher = Crc32Hasher::new();
    hasher.update(&header);
    for part in parts {
        hasher.update(part);
    }
    let crc = hasher.finalize().to_le_bytes();
    let body_len: usize = parts.iter().map(|part| part.len()).sum();
    let mut frame = Arc::<[u8]>::new_uninit_slice(header.len() + body_len + crc.len());
    let bytes = Arc::get_mut(&mut frame).expect("new frame is exclusively owned");
    for (slot, value) in bytes.iter_mut().zip(
        header
            .iter()
            .chain(parts.iter().flat_map(|part| part.iter()))
            .chain(&crc),
    ) {
        slot.write(*value);
    }
    // SAFETY: header, all body segments and CRC fill the entire allocation.
    unsafe { crate::shared_bytes::convert(frame.assume_init()) }
}

pub(crate) fn parse_side_transport_wrapper(bytes: &[u8]) -> TelemetryResult<Option<(u8, &[u8])>> {
    if bytes.len() < SIDE_TRANSPORT_MAGIC.len() + 1 + wire_format::CRC32_BYTES {
        return Ok(None);
    }
    if &bytes[..SIDE_TRANSPORT_MAGIC.len()] != SIDE_TRANSPORT_MAGIC {
        return Ok(None);
    }
    let data_len = bytes.len() - wire_format::CRC32_BYTES;
    let expected = u32::from_le_bytes([
        bytes[data_len],
        bytes[data_len + 1],
        bytes[data_len + 2],
        bytes[data_len + 3],
    ]);
    let data = &bytes[..data_len];
    if crc32_bytes(data) != expected {
        return Err(TelemetryError::Unpack("side transport crc32 mismatch"));
    }
    let kind = data[SIDE_TRANSPORT_MAGIC.len()];
    Ok(Some((kind, &data[SIDE_TRANSPORT_MAGIC.len() + 1..])))
}

pub(crate) fn extract_side_header_template(
    bytes: &[u8],
) -> TelemetryResult<SideTemplateExtract<'_>> {
    let (view, ty, flags, size, timestamp, nonce, reliable, payload) =
        extract_side_header_template_view(bytes)?;
    Ok((
        view.into_owned(),
        ty,
        flags,
        size,
        timestamp,
        nonce,
        reliable,
        payload,
    ))
}
pub(crate) fn extract_side_header_template_view(
    bytes: &[u8],
) -> TelemetryResult<SideTemplateViewExtract<'_>> {
    if bytes.len() < wire_format::CRC32_BYTES + 4 {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let data_len = bytes.len() - wire_format::CRC32_BYTES;
    let data = &bytes[..data_len];
    let mut off = 0usize;
    let flags = *data
        .get(off)
        .ok_or(TelemetryError::Unpack("short prelude"))?;
    off += 1;
    let nep = *data
        .get(off)
        .ok_or(TelemetryError::Unpack("short prelude"))? as usize;
    off += 1; // NEP
    let ty_u64 = read_uleb128_local(data, &mut off)?;
    let ty_u32 = u32::try_from(ty_u64).map_err(|_| TelemetryError::Unpack("bad data type"))?;
    let ty = DataType(ty_u32);
    let data_size_off = off;
    let data_size = read_uleb128_local(data, &mut off)?;
    let timestamp = read_uleb128_local(data, &mut off)?;
    let nonce = if (flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE) != 0 {
        u16::try_from(read_uleb128_local(data, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("packet nonce too large"))?
    } else {
        0
    };
    let between_start = off;
    let _source_address = u32::try_from(read_uleb128_local(data, &mut off)?)
        .map_err(|_| TelemetryError::Unpack("source address too large"))?;
    let endpoint_bitmap_bytes = if (flags & SIDE_TRANSPORT_FLAG_ENDPOINT_BITMAP_PRESENT) != 0 {
        SIDE_TRANSPORT_EP_BITMAP_BYTES
    } else {
        0
    };
    if data.len() < off + endpoint_bitmap_bytes {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    off += endpoint_bitmap_bytes;
    if flags & SIDE_TRANSPORT_FLAG_ENDPOINT_LIST_PRESENT != 0 {
        if endpoint_bitmap_bytes != 0 {
            return Err(TelemetryError::Unpack("ambiguous endpoint encoding"));
        }
        let mut previous = None;
        for _ in 0..nep {
            let id = u32::try_from(read_uleb128_local(data, &mut off)?)
                .map_err(|_| TelemetryError::Unpack("endpoint too large"))?;
            if previous.is_some_and(|previous| id <= previous) {
                return Err(TelemetryError::Unpack(
                    "endpoint list is not unique and sorted",
                ));
            }
            previous = Some(id);
        }
    }
    if (flags & SIDE_TRANSPORT_FLAG_WIRE_CONTRACT) != 0 {
        let contract_len = usize::try_from(read_uleb128_local(data, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("wire contract length"))?;
        if data.len() < off + contract_len {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        off += contract_len;
    }
    let reliable_span = wire_format::reliable_header_span(bytes)?;
    let (reliable_flags, reliable_seq_ack, reliable_compact, payload_off) =
        if let Some((rel_off, rel_len, hdr)) = reliable_span {
            if data.len() < rel_off + rel_len {
                return Err(TelemetryError::Unpack("short buffer"));
            }
            (
                Some(hdr.flags),
                Some((hdr.seq, hdr.ack)),
                (flags & SIDE_TRANSPORT_FLAG_COMPACT_RELIABLE_HEADER) != 0,
                rel_off + rel_len,
            )
        } else {
            (None, None, false, off)
        };
    if payload_off > data.len() {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let payload = &data[payload_off..];
    let prefix = &data[1..data_size_off];
    let between_end = reliable_span
        .map(|(rel_off, _, _)| rel_off)
        .unwrap_or(payload_off);
    let between = &data[between_start..between_end];
    let base_flags =
        flags & !(SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED | SIDE_TRANSPORT_FLAG_PACKET_NONCE);
    let mut hash = 0xD1B5_4A32_9C7E_01F3u64;
    hash = hash_bytes_u64(hash, &[base_flags]);
    hash = hash_bytes_u64(hash, prefix);
    hash = hash_bytes_u64(hash, between);
    if let Some(rel_flags) = reliable_flags {
        hash = hash_bytes_u64(hash, &[rel_flags]);
    }
    let template = SideHeaderTemplateView {
        hash,
        base_flags,
        prefix,
        between,
        reliable_flags,
        reliable_compact,
    };
    Ok((
        template,
        ty,
        flags,
        data_size,
        timestamp,
        nonce,
        reliable_seq_ack,
        payload,
    ))
}

pub(crate) fn reconstruct_side_compact_frame(
    template: &SideHeaderTemplate,
    flags: u8,
    body: &[u8],
    timestamp_mode: SideCompactTimestampMode,
    timestamp_base: Option<u64>,
) -> TelemetryResult<(crate::SharedBytes, u64)> {
    if body.is_empty() {
        return Err(TelemetryError::Unpack("short side compact frame"));
    }
    let mut off = 0usize;
    if (flags & !(SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED | SIDE_TRANSPORT_FLAG_PACKET_NONCE))
        != template.base_flags
    {
        return Err(TelemetryError::Unpack("side compact flags mismatch"));
    }
    let data_size = read_uleb128_local(body, &mut off)?;
    let timestamp = match timestamp_mode {
        SideCompactTimestampMode::Absolute => read_uleb128_local(body, &mut off)?,
        SideCompactTimestampMode::Delta => {
            let timestamp_field = read_uleb128_local(body, &mut off)?;
            let base = timestamp_base.ok_or(TelemetryError::Unpack(
                "missing side compact timestamp context",
            ))?;
            base.checked_add(timestamp_field)
                .ok_or(TelemetryError::Unpack(
                    "side compact timestamp delta overflow",
                ))?
        }
        SideCompactTimestampMode::Omitted => timestamp_base.ok_or(TelemetryError::Unpack(
            "missing side compact timestamp context",
        ))?,
    };
    let nonce = if (flags & SIDE_TRANSPORT_FLAG_PACKET_NONCE) != 0 {
        Some(read_uleb128_local(body, &mut off)?)
    } else {
        None
    };
    let reliable_seq_ack = if template.reliable_flags.is_some() {
        let seq = u32::try_from(read_uleb128_local(body, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("side compact reliable seq too large"))?;
        let ack = u32::try_from(read_uleb128_local(body, &mut off)?)
            .map_err(|_| TelemetryError::Unpack("side compact reliable ack too large"))?;
        Some((seq, ack))
    } else {
        None
    };
    let payload = &body[off..];
    let mut raw = Vec::with_capacity(
        1 + template.prefix().len() + template.between().len() + payload.len() + 32,
    );
    raw.push(flags);
    raw.extend_from_slice(template.prefix());
    write_uleb128_local(data_size, &mut raw);
    write_uleb128_local(timestamp, &mut raw);
    if let Some(nonce) = nonce {
        write_uleb128_local(nonce, &mut raw);
    }
    raw.extend_from_slice(template.between());
    if let Some(rel_flags) = template.reliable_flags {
        let (seq, ack) =
            reliable_seq_ack.ok_or(TelemetryError::Unpack("missing side compact reliable"))?;
        wire_format::write_reliable_header_encoded(
            wire_format::ReliableHeader {
                flags: rel_flags,
                seq,
                ack,
            },
            template.reliable_compact,
            &mut raw,
        );
    }
    raw.extend_from_slice(payload);
    let crc = crc32_bytes(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    Ok((
        crate::shared_bytes::convert(Arc::<[u8]>::from(raw)),
        timestamp,
    ))
}

#[derive(Clone, Copy, Debug)]
struct SideTxCursor {
    key: u64,
    next: usize,
    last_progress_ms: u64,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct SideTxProgress {
    slots: [Option<SideTxCursor>; 4],
}
impl SideTxProgress {
    pub(crate) fn begin(&mut self, key: u64, now: u64) -> TelemetryResult<usize> {
        for slot in &mut self.slots {
            // Match the receiver's assembly timeout. After a genuine pause,
            // the peer requires a fresh transfer, rather than a missing suffix.
            if slot.is_some_and(|entry| now.saturating_sub(entry.last_progress_ms) > 2000) {
                *slot = None;
            }
        }
        if let Some(entry) = self.slots.iter().flatten().find(|entry| entry.key == key) {
            return Ok(entry.next);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(TelemetryError::Io("side chunk progress saturated"))?;
        *slot = Some(SideTxCursor {
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
        let budget = max_frame_bytes - SIDE_TRANSPORT_CHUNK_OVERHEAD;
        let total = len.div_ceil(budget);
        let total_u16 =
            u16::try_from(total).map_err(|_| TelemetryError::PacketTooLarge("too many chunks"))?;
        let mut hash = hash_bytes_u64(0x517C_C1B7_2722_0A95, sender);
        for part in parts {
            hash = hash_bytes_u64(hash, part);
        }
        let transfer = ((hash >> 32) as u32 ^ hash as u32).max(1).to_le_bytes();
        if *next_chunk > total {
            return Err(TelemetryError::BadArg);
        }
        for index in *next_chunk..total {
            let start = index * budget;
            let end = (start + budget).min(len);
            let index_bytes = (index as u16).to_le_bytes();
            let total_bytes = total_u16.to_le_bytes();
            let mut slices: [&[u8]; 6] = [&transfer, &index_bytes, &total_bytes, &[], &[], &[]];
            let mut offset = 0;
            for (i, part) in parts.iter().enumerate() {
                let low = start.saturating_sub(offset).min(part.len());
                let high = end.saturating_sub(offset).min(part.len());
                slices[i + 3] = &part[low..high];
                offset += part.len();
            }
            crate::memory_admission::check(
                max_frame_bytes.saturating_add(256),
                max_frame_bytes.saturating_add(32),
            )?;
            let chunk = wrap_side_transport_frame_parts(SIDE_TRANSPORT_KIND_CHUNK, &slices);
            send(&chunk)?;
            *next_chunk = index + 1;
        }
        Ok((len, len + total * SIDE_TRANSPORT_CHUNK_OVERHEAD, total))
    })
}

#[cfg(test)]
mod streamed_chunk_tests {
    use super::*;
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
    #[cfg(feature = "discovery")]
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
    pub(crate) fn oldest(chunks: &BTreeMap<u32, Self>, keep: Option<u32>) -> Option<(u32, u64)> {
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
        chunks: &mut BTreeMap<u32, Self>,
        buffered: &mut usize,
        id: u32,
    ) -> Option<Self> {
        let value = chunks.remove(&id)?;
        *buffered = buffered.saturating_sub(value.byte_cost());
        Some(value)
    }
    #[inline(never)]
    pub(crate) fn expire(chunks: &mut BTreeMap<u32, Self>, buffered: &mut usize, now: u64) -> u32 {
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
        chunks: &mut BTreeMap<u32, Self>,
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
    fn one_shared_buffer_preserves_both_ranges_and_clone_lifetime() {
        for (prefix, between) in [
            (&[][..], &[][..]),
            (&[1, 2, 3][..], &[9, 8, 7, 6][..]),
            (&[][..], &[42][..]),
        ] {
            let view = SideHeaderTemplateView {
                hash: 77,
                base_flags: 5,
                prefix,
                between,
                reliable_flags: Some(1),
                reliable_compact: true,
            };
            let owned = view.into_owned();
            let clone = owned.clone();
            assert!(Arc::ptr_eq(&owned.header, &clone.header));
            assert_eq!(owned.header.len(), prefix.len() + between.len());
            drop(owned);
            assert_eq!(clone.prefix(), prefix);
            assert_eq!(clone.between(), between);
            assert_eq!(clone.hash, 77);
            assert_eq!(clone.base_flags, 5);
            assert_eq!(clone.reliable_flags, Some(1));
            assert!(clone.reliable_compact);
        }
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

    fn fixture(entries: &[(u32, u64, usize)]) -> (BTreeMap<u32, SideChunkAssembly>, usize) {
        let mut chunks = BTreeMap::new();
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
        let mut chunks = BTreeMap::from([(1, assembly)]);
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
