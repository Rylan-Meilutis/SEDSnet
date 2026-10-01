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
pub(crate) const SIDE_TRANSPORT_FLAG_COMPACT_RELIABLE_HEADER: u8 = 0x40;
pub(crate) const SIDE_TRANSPORT_CHUNK_OVERHEAD: usize =
    3 + 1 + 4 + 2 + 2 + wire_format::CRC32_BYTES;
pub(crate) const SIDE_TRANSPORT_EP_BITMAP_BITS: usize =
    (crate::MAX_VALUE_DATA_ENDPOINT as usize) + 1;
pub(crate) const SIDE_TRANSPORT_EP_BITMAP_BYTES: usize = SIDE_TRANSPORT_EP_BITMAP_BITS.div_ceil(8);

/// An outgoing frame or lazily encoded chunks. Retains the source plus at most
/// the current chunk instead of allocating every fragment before the first TX.
pub(crate) struct SideTransportFrames {
    frame: Arc<[u8]>,
    payload_budget: usize,
    transfer_id: u32,
    index: usize,
    total: usize,
}
impl SideTransportFrames {
    pub fn single(frame: Arc<[u8]>) -> Self {
        Self {
            frame,
            payload_budget: 0,
            transfer_id: 0,
            index: 0,
            total: 1,
        }
    }
    pub fn split(frame: Arc<[u8]>, max_frame_bytes: usize, sender: &[u8]) -> TelemetryResult<Self> {
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
    type Item = Arc<[u8]>;
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
    pub(crate) prefix: Arc<[u8]>,
    pub(crate) between: Arc<[u8]>,
    pub(crate) reliable_flags: Option<u8>,
    pub(crate) reliable_compact: bool,
}

impl SideHeaderTemplate {
    pub(crate) fn is_ack(&self) -> bool {
        if self
            .reliable_flags
            .is_some_and(|flags| flags & wire_format::RELIABLE_FLAG_ACK_ONLY != 0)
        {
            return true;
        }
        // Prefix is endpoint count followed by the canonical type ULEB128.
        let mut off = 1;
        read_uleb128_local(&self.prefix, &mut off)
            .ok()
            .is_some_and(|ty| {
                ty == u64::from(DataType::ReliableAck.as_u32())
                    || ty == u64::from(DataType::ReliablePartialAck.as_u32())
            })
    }
}

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
    let mut result = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *buf.get(*off).ok_or(TelemetryError::Unpack("short read"))?;
        *off += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(TelemetryError::Unpack("uleb128 too long"))
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

pub(crate) fn wrap_side_transport_frame(kind: u8, body: &[u8]) -> Arc<[u8]> {
    wrap_side_transport_frame_parts(kind, &[body])
}

// Write body segments directly into the final allocation. This also lets a
// chunk header stay on the stack instead of copying its payload into a Vec.
pub(crate) fn wrap_side_transport_frame_parts(kind: u8, parts: &[&[u8]]) -> Arc<[u8]> {
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
    unsafe { frame.assume_init() }
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
    off += 1; // NEP
    let ty_u64 = read_uleb128_local(data, &mut off)?;
    let ty_u32 = u32::try_from(ty_u64).map_err(|_| TelemetryError::Unpack("bad data type"))?;
    if ty_u32 > crate::MAX_VALUE_DATA_TYPE {
        return Err(TelemetryError::Unpack("bad data type"));
    }
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
    let prefix = Arc::<[u8]>::from(&data[1..data_size_off]);
    let between_end = reliable_span
        .map(|(rel_off, _, _)| rel_off)
        .unwrap_or(payload_off);
    let between = Arc::<[u8]>::from(&data[between_start..between_end]);
    let base_flags =
        flags & !(SIDE_TRANSPORT_FLAG_PAYLOAD_COMPRESSED | SIDE_TRANSPORT_FLAG_PACKET_NONCE);
    let mut hash = 0xD1B5_4A32_9C7E_01F3u64;
    hash = hash_bytes_u64(hash, &[base_flags]);
    hash = hash_bytes_u64(hash, &prefix);
    hash = hash_bytes_u64(hash, &between);
    if let Some(rel_flags) = reliable_flags {
        hash = hash_bytes_u64(hash, &[rel_flags]);
    }
    let template = SideHeaderTemplate {
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
    body: &[u8],
    timestamp_mode: SideCompactTimestampMode,
    timestamp_base: Option<u64>,
) -> TelemetryResult<(Arc<[u8]>, u64)> {
    if body.is_empty() {
        return Err(TelemetryError::Unpack("short side compact frame"));
    }
    let mut off = 0usize;
    let flags = body[off];
    off += 1;
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
    let mut raw =
        Vec::with_capacity(1 + template.prefix.len() + template.between.len() + payload.len() + 32);
    raw.push(flags);
    raw.extend_from_slice(&template.prefix);
    write_uleb128_local(data_size, &mut raw);
    write_uleb128_local(timestamp, &mut raw);
    if let Some(nonce) = nonce {
        write_uleb128_local(nonce, &mut raw);
    }
    raw.extend_from_slice(&template.between);
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
    Ok((Arc::from(raw), timestamp))
}

/// Send a large plaintext packet as canonical chunks without assembling an
/// additional full wire frame. Callback errors stop transmission immediately.
pub(crate) fn send_packet_chunks(
    packet: &crate::packet::Packet,
    max_frame_bytes: usize,
    sender: &[u8],
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
        for index in 0..total {
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
        }
        Ok((len, len + total * SIDE_TRANSPORT_CHUNK_OVERHEAD, total))
    })
}

#[cfg(test)]
mod streamed_chunk_tests {
    use super::*;
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
            let expected = SideTransportFrames::split(raw.clone(), max_bytes, b"GB")
                .unwrap()
                .collect::<Vec<_>>();
            let mut actual = Vec::new();
            send_packet_chunks(&packet, max_bytes, b"GB", |chunk| {
                actual.push(Arc::<[u8]>::from(chunk));
                Ok(())
            })
            .unwrap();
            assert_eq!(actual, expected);
        }
        let mut calls = 0;
        let result = send_packet_chunks(&packet, 32, b"GB", |_| {
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
    pub(crate) received: BTreeMap<u16, Arc<[u8]>>,
}

impl SideChunkAssembly {
    pub(crate) fn assemble(self) -> TelemetryResult<Vec<u8>> {
        if self.received.len() != usize::from(self.total) {
            return Err(TelemetryError::Unpack("side chunk gap"));
        }
        let len = self.received.values().try_fold(0usize, |n, chunk| {
            n.checked_add(chunk.len())
                .ok_or(TelemetryError::PacketTooLarge("side chunk size overflow"))
        })?;
        // Repeated extend growth can double a ~3.6 KiB discovery packet to
        // 7 KiB while retaining the old buffer and every received fragment.
        // Reserve once, report exhaustion instead of panicking, and consume
        // fragments as we copy. Decoding accepts the Vec directly: no extra Arc.
        crate::memory_admission::check(len.saturating_add(512), len.saturating_add(32))?;
        let mut out = Vec::new();
        out.try_reserve_exact(len)
            .map_err(|_| TelemetryError::Unpack("side chunk assembly allocation failed"))?;
        for (expected, (index, chunk)) in self.received.into_iter().enumerate() {
            if usize::from(index) != expected {
                return Err(TelemetryError::Unpack("side chunk gap"));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}
