//! Wire-format packing and unpacking of telemetry packets.
//!
//! This module defines the compact v2 wire format used to send and receive
//! [`Packet`]s, along with:
//! - [`pack_packet`] / [`unpack_packet`] for full packets.
//! - [`peek_envelope`] for header-only inspection without touching the payload.
//! - Size helpers like [`header_size_bytes`] and [`packet_wire_size`].
//!
//! The core public type here is [`TelemetryEnvelope`], a lightweight view of
//! the header fields used by `peek_envelope`.

use crate::MessageElement;
use crate::{
    DataEndpoint, TelemetryError, TelemetryResult, config::DataType, is_reliable_type,
    message_meta, packet::Packet,
};

use crate::config::StandardSmallPayload;
use crate::packet::{hash_bytes_u64, sender_address_u32};
#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
use alloc::{sync::Arc, vec, vec::Vec};
use crc32fast::Hasher as Crc32Hasher;
#[cfg(feature = "std")]
use std::sync::{Mutex, OnceLock};

/// Lightweight header-only view of a packed [`Packet`].
///
/// Produced by [`peek_envelope`] without allocating or copying the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelemetryEnvelope {
    /// Telemetry [`DataType`] discriminant.
    pub ty: DataType,
    /// All endpoints this packet is destined for (set bits in the bitmap).
    pub endpoints: Arc<[DataEndpoint]>,
    /// Sender identity resolved from discovery/config address state.
    pub sender: Arc<str>,
    /// Compact source address carried by the packet header.
    pub source_address: u32,
    /// Timestamp in milliseconds (as stored on the wire).
    pub timestamp_ms: u64,
    /// Inline wire-format payload shape, if present.
    pub wire_shape: Option<MessageElement>,
    /// Frozen destination sender hashes, if present.
    pub target_senders: Arc<[u64]>,
}

/// Reliable header included for data types marked `reliable` in the schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReliableHeader {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
}

/// Reliable header flag: frame is ACK-only control (no payload).
pub const RELIABLE_FLAG_ACK_ONLY: u8 = 0x01;

/// Reliable header flag: frame is reliable but unordered (ACK/retransmit without ordering).
pub const RELIABLE_FLAG_UNORDERED: u8 = 0x02;

/// Reliable header flag: frame is unsequenced best-effort (no ordering/ack).
pub const RELIABLE_FLAG_UNSEQUENCED: u8 = 0x80;

/// Fixed size of the reliable header on the wire.
pub const RELIABLE_HEADER_BYTES: usize = 1 + 4 + 4;
/// Fixed size of the CRC32 trailer on the wire.
pub const CRC32_BYTES: usize = 4;

// packet Layout:
//
//   [FLAGS: u8]
//       Bit 0: payload compressed flag (1 = compressed)
//       Bit 1: reliable header present
//       Bit 7: explicit endpoint ID list present (mutually exclusive with bit5)
//       Bit 5: endpoint bitmap present (0 = derive endpoints from data type metadata)
//       Bit 6: compact reliable header present (if a reliable header exists)
//
//   [NEP: u8]
//       Number of selected endpoints.
//
//   VARINT(ty: u32 as u64)           -- ULEB128
//   VARINT(data_size: u64)           -- ULEB128   (LOGICAL payload size, uncompressed)
//   VARINT(timestamp: u64)           -- ULEB128
//   [VARINT(nonce: u16 as u64)]      -- ULEB128   (ONLY if bit3 set)
//   VARINT(src_addr: u32 as u64)     -- ULEB128
//
//   [ENDPOINTS_BITMAP]               -- ONLY if bit5 set; 1 bit per possible endpoint
//   [ENDPOINT_ID_LIST]               -- NEP sorted unique ULEB128 IDs if bit7 set
//   [RELIABLE HEADER]                -- declared by bit1 or the wire contract
//       [REL_FLAGS: u8]
//       [SEQ: u32 LE]
//       [ACK: u32 LE]
//   PAYLOAD BYTES                    -- raw or compressed payload bytes
//   [CRC32: u32 LE]                  -- checksum of all prior bytes

// ===========================================================================
// ULEB128 (varint) encoding helpers
// ===========================================================================
const FLAG_COMPRESSED_PAYLOAD: u8 = 0x01;
const FLAG_RELIABLE_HEADER_PRESENT: u8 = 0x02;
const FLAG_WIRE_CONTRACT: u8 = 0x04;
const FLAG_PACKET_NONCE: u8 = 0x08;
#[cfg(feature = "cryptography")]
const FLAG_E2E_ENCRYPTED_PAYLOAD: u8 = 0x10;
const FLAG_ENDPOINT_BITMAP_PRESENT: u8 = 0x20;
const FLAG_ENDPOINT_LIST_PRESENT: u8 = 0x80;
const FLAG_COMPACT_RELIABLE_HEADER: u8 = 0x40;
const CONTRACT_FLAG_TARGETS: u8 = 0x01;
const CONTRACT_FLAG_SHAPE: u8 = 0x02;
const CONTRACT_FLAG_RELIABLE_HEADER: u8 = 0x04;
const RELIABLE_WIRE_FLAG_SEQ_PRESENT: u8 = 0x04;
const RELIABLE_WIRE_FLAG_ACK_PRESENT: u8 = 0x08;
const RELIABLE_PUBLIC_FLAGS_MASK: u8 =
    RELIABLE_FLAG_ACK_ONLY | RELIABLE_FLAG_UNORDERED | RELIABLE_FLAG_UNSEQUENCED;
#[cfg(feature = "cryptography")]
const E2E_NONCE_LEN: usize = 12;
#[cfg(feature = "cryptography")]
const E2E_TAG_CAP: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
struct WireContract {
    shape: Option<MessageElement>,
    target_senders: Option<Arc<[u64]>>,
    has_reliable_header: bool,
}

/// Encode a `u64` as ULEB128 and append it to `out`.
#[inline]
fn write_uleb128<T>(mut v: u64, out: &mut Vec<T>)
where
    T: From<u8>,
{
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(T::from(byte));
        if v == 0 {
            break;
        }
    }
}

/// Decode a ULEB128-encoded `u64` from the given reader.
#[inline]
fn read_uleb128(r: &mut ByteReader) -> Result<u64, TelemetryError> {
    crate::varint::read_u64(r.buf, &mut r.off)
}

/// Compute the encoded length (in bytes) of a ULEB128-encoded `u64`.
#[inline]
fn uleb128_size(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Count the total number of bits set across all bytes of the bitmap.
#[inline]
fn bitmap_popcount(bm: &[u8]) -> usize {
    bm.iter().map(|b| b.count_ones() as usize).sum()
}

// ===========================================================================
// ByteReader: tiny cursor over a byte slice
// ===========================================================================

#[derive(Clone, Copy)]
struct ByteReader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> ByteReader<'a> {
    /// Create a new reader over the given buffer starting at offset 0.
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    /// Remaining bytes that can still be read.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    /// Read exactly `n` bytes, advancing the internal offset.
    #[inline(always)]
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], TelemetryError> {
        if self.remaining() < n {
            return Err(TelemetryError::Unpack("short read"));
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }
}

#[inline]
fn write_u32_le(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn read_u32_le(r: &mut ByteReader) -> Result<u32, TelemetryError> {
    let b = r.read_bytes(4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
fn write_wire_shape(shape: MessageElement, out: &mut Vec<u8>) -> Result<(), TelemetryError> {
    let dt = crate::config::message_data_type_code(shape.data_type());
    let class = crate::config::message_class_code(shape.message_type());
    let mut packed = dt | (class << 4);
    if matches!(shape, MessageElement::Static(_, _, _)) {
        packed |= 1 << 6;
    }
    out.push(packed);
    if let MessageElement::Static(count, _, _) = shape {
        let count = u64::try_from(count).map_err(|_| TelemetryError::Pack("wire shape count"))?;
        write_uleb128(count, out);
    }
    Ok(())
}

#[inline]
fn decode_wire_shape(r: &mut ByteReader) -> Result<MessageElement, TelemetryError> {
    let packed = r.read_bytes(1)?[0];
    let dt = crate::config::message_data_type_from_code(packed & 0x0F)
        .ok_or(TelemetryError::Unpack("wire shape type"))?;
    let class = crate::config::message_class_from_code((packed >> 4) & 0x03)
        .ok_or(TelemetryError::Unpack("wire shape class"))?;
    if (packed & (1 << 6)) != 0 {
        let count = usize::try_from(read_uleb128(r)?)
            .map_err(|_| TelemetryError::Unpack("wire shape count"))?;
        Ok(MessageElement::Static(count, dt, class))
    } else {
        Ok(MessageElement::Dynamic(dt, class))
    }
}

#[inline]
fn write_wire_contract(
    shape: Option<MessageElement>,
    target_senders: &[u64],
    has_reliable_header: bool,
    out: &mut Vec<u8>,
) -> Result<(), TelemetryError> {
    // Keep the contract self-contained and compact. It exists only to preserve
    // delivery/decode intent for packets that are already in flight while
    // schema or topology updates are still converging.
    let mut flags = 0u8;
    if !target_senders.is_empty() {
        flags |= CONTRACT_FLAG_TARGETS;
    }
    if shape.is_some() {
        flags |= CONTRACT_FLAG_SHAPE;
    }
    if has_reliable_header {
        flags |= CONTRACT_FLAG_RELIABLE_HEADER;
    }
    out.push(flags);
    if let Some(shape) = shape {
        write_wire_shape(shape, out)?;
    }
    if !target_senders.is_empty() {
        write_uleb128(target_senders.len() as u64, out);
        for hash in target_senders {
            out.extend_from_slice(&hash.to_le_bytes());
        }
    }
    Ok(())
}

/// Size the frozen contract without constructing temporary shape/target buffers.
fn wire_contract_size(shape: Option<MessageElement>, target_senders: &[u64]) -> usize {
    1 + shape.map_or(0, |shape| match shape {
        MessageElement::Static(count, _, _) => 1 + uleb128_size(count as u64),
        _ => 1,
    }) + if target_senders.is_empty() {
        0
    } else {
        uleb128_size(target_senders.len() as u64) + target_senders.len() * 8
    }
}

#[inline]
fn decode_wire_contract(
    r: &mut ByteReader,
    has_contract: bool,
) -> Result<WireContract, TelemetryError> {
    if !has_contract {
        return Ok(WireContract {
            shape: None,
            target_senders: None,
            has_reliable_header: false,
        });
    }
    let contract_len = usize::try_from(read_uleb128(r)?)
        .map_err(|_| TelemetryError::Unpack("wire contract length"))?;
    let contract_bytes = r.read_bytes(contract_len)?;
    let mut cr = ByteReader::new(contract_bytes);
    // Parsing through a bounded sub-reader lets us reject trailing garbage in
    // the contract cleanly instead of accidentally treating it as payload or
    // reliable-header bytes.
    let flags = cr.read_bytes(1)?[0];
    let shape = if (flags & CONTRACT_FLAG_SHAPE) != 0 {
        Some(decode_wire_shape(&mut cr)?)
    } else {
        None
    };
    let target_senders: Option<Arc<[u64]>> = if (flags & CONTRACT_FLAG_TARGETS) != 0 {
        let count = usize::try_from(read_uleb128(&mut cr)?)
            .map_err(|_| TelemetryError::Unpack("wire contract target count"))?;
        if count > cr.remaining() / 8 {
            return Err(TelemetryError::Unpack("wire contract target count"));
        }
        if count == 0 {
            None
        } else {
            let mut targets = Arc::<[u64]>::new_uninit_slice(count);
            for slot in Arc::get_mut(&mut targets).expect("new target storage is unique") {
                let bytes = cr.read_bytes(8)?;
                slot.write(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]));
            }
            // The bounded target count guarantees every slot was initialized.
            Some(unsafe { targets.assume_init() })
        }
    } else {
        None
    };
    if cr.remaining() != 0 {
        return Err(TelemetryError::Unpack("wire contract trailing bytes"));
    }
    Ok(WireContract {
        shape,
        target_senders,
        has_reliable_header: (flags & CONTRACT_FLAG_RELIABLE_HEADER) != 0,
    })
}

#[inline]
fn crc32_bytes(data: &[u8]) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

#[inline]
fn append_crc32(out: &mut Vec<u8>) {
    let crc = crc32_bytes(out);
    out.extend_from_slice(&crc.to_le_bytes());
}

// Initialize every byte before publishing the shared frame. Keeping the
// payload separate avoids a second full-size allocation during Arc creation.
fn join_frame_with_crc(header: &[u8], payload: &[u8]) -> Arc<[u8]> {
    let mut hasher = Crc32Hasher::new();
    hasher.update(header);
    hasher.update(payload);
    let crc = hasher.finalize().to_le_bytes();
    let mut frame = Arc::<[u8]>::new_uninit_slice(header.len() + payload.len() + crc.len());
    let bytes = Arc::get_mut(&mut frame).unwrap();
    for (slot, value) in bytes
        .iter_mut()
        .zip(header.iter().chain(payload).chain(&crc))
    {
        slot.write(*value);
    }
    // SAFETY: the iterator above writes exactly header + payload + CRC bytes,
    // which is the full allocation length. No uninitialized byte escapes.
    unsafe { frame.assume_init() }
}

#[inline]
fn split_crc32(buf: &[u8]) -> Result<(&[u8], u32), TelemetryError> {
    if buf.len() < CRC32_BYTES {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let data_len = buf.len() - CRC32_BYTES;
    let crc = u32::from_le_bytes([
        buf[data_len],
        buf[data_len + 1],
        buf[data_len + 2],
        buf[data_len + 3],
    ]);
    Ok((&buf[..data_len], crc))
}

#[inline]
fn verify_crc32(buf: &[u8]) -> Result<&[u8], TelemetryError> {
    let (data, expected) = split_crc32(buf)?;
    let actual = crc32_bytes(data);
    if actual != expected {
        return Err(TelemetryError::Unpack("crc32 mismatch"));
    }
    Ok(data)
}

#[cfg(feature = "cryptography")]
#[inline]
fn e2e_nonce_for_packet(pkt: &Packet) -> [u8; E2E_NONCE_LEN] {
    let mut nonce = [0u8; E2E_NONCE_LEN];
    nonce[..4].copy_from_slice(&pkt.data_type().as_u32().to_le_bytes());
    nonce[4..10].copy_from_slice(&(pkt.timestamp() & 0x0000_FFFF_FFFF_FFFF).to_le_bytes()[..6]);
    nonce[10..].copy_from_slice(&pkt.nonce().to_le_bytes());
    nonce
}

#[cfg(feature = "cryptography")]
fn write_encrypted_payload(
    pkt: &Packet,
    key_id: u32,
    plaintext_wire_payload: &[u8],
    out: &mut Vec<u8>,
) -> TelemetryResult<()> {
    let aad_end = out.len();
    let nonce = e2e_nonce_for_packet(pkt);
    let mut ciphertext = vec![0u8; plaintext_wire_payload.len()];
    let mut tag = [0u8; E2E_TAG_CAP];
    let (ciphertext_len, tag_len) = crate::crypto::seal_with_registered_crypto(
        key_id,
        &nonce,
        &out[..aad_end],
        plaintext_wire_payload,
        &mut ciphertext,
        &mut tag,
    )?;
    if ciphertext_len > ciphertext.len() || tag_len > tag.len() {
        return Err(TelemetryError::SizeMismatchError);
    }
    write_uleb128(u64::from(key_id), out);
    write_uleb128(plaintext_wire_payload.len() as u64, out);
    write_uleb128(nonce.len() as u64, out);
    out.extend_from_slice(&nonce);
    write_uleb128(tag_len as u64, out);
    out.extend_from_slice(&tag[..tag_len]);
    out.extend_from_slice(&ciphertext[..ciphertext_len]);
    Ok(())
}

#[cfg(feature = "cryptography")]
fn read_encrypted_payload(
    r: &mut ByteReader,
    aad: &[u8],
    plaintext_len: usize,
) -> TelemetryResult<Vec<u8>> {
    let key_id = u32::try_from(read_uleb128(r)?)
        .map_err(|_| TelemetryError::Unpack("e2e key id too large"))?;
    let wire_payload_len = usize::try_from(read_uleb128(r)?)
        .map_err(|_| TelemetryError::Unpack("e2e payload length"))?;
    if wire_payload_len > plaintext_len {
        return Err(TelemetryError::Unpack("bad e2e payload length"));
    }
    let nonce_len = usize::try_from(read_uleb128(r)?)
        .map_err(|_| TelemetryError::Unpack("e2e nonce length"))?;
    if nonce_len == 0 || nonce_len > 64 {
        return Err(TelemetryError::Unpack("bad e2e nonce length"));
    }
    let nonce = r.read_bytes(nonce_len)?;
    let tag_len =
        usize::try_from(read_uleb128(r)?).map_err(|_| TelemetryError::Unpack("e2e tag length"))?;
    if tag_len == 0 || tag_len > E2E_TAG_CAP {
        return Err(TelemetryError::Unpack("bad e2e tag length"));
    }
    let tag = r.read_bytes(tag_len)?;
    let ciphertext_len = r.remaining();
    let ciphertext = r.read_bytes(ciphertext_len)?;
    let mut plaintext = vec![0u8; wire_payload_len];
    let opened_len = crate::crypto::open_with_registered_crypto(
        key_id,
        nonce,
        aad,
        ciphertext,
        tag,
        &mut plaintext,
    )?;
    if opened_len != wire_payload_len {
        return Err(TelemetryError::SizeMismatchError);
    }
    Ok(plaintext)
}

#[inline]
fn write_reliable_header(h: ReliableHeader, out: &mut Vec<u8>) {
    out.push(h.flags);
    write_u32_le(h.seq, out);
    write_u32_le(h.ack, out);
}

#[inline]
fn reliable_compact_size(h: ReliableHeader) -> usize {
    let seq_present = (h.flags & RELIABLE_FLAG_ACK_ONLY) == 0 || h.seq != 0;
    let ack_present = h.ack != 0 || (h.flags & RELIABLE_FLAG_ACK_ONLY) != 0;
    1 + if seq_present {
        uleb128_size(h.seq as u64)
    } else {
        0
    } + if ack_present {
        uleb128_size(h.ack as u64)
    } else {
        0
    }
}

#[inline]
fn should_compact_reliable_header(h: ReliableHeader) -> bool {
    reliable_compact_size(h) < RELIABLE_HEADER_BYTES
}

#[inline]
fn reliable_wire_size(h: ReliableHeader, compact: bool) -> usize {
    if compact {
        reliable_compact_size(h)
    } else {
        RELIABLE_HEADER_BYTES
    }
}

pub(crate) fn write_reliable_header_encoded(h: ReliableHeader, compact: bool, out: &mut Vec<u8>) {
    if !compact {
        write_reliable_header(h, out);
        return;
    }

    let seq_present = (h.flags & RELIABLE_FLAG_ACK_ONLY) == 0 || h.seq != 0;
    let ack_present = h.ack != 0 || (h.flags & RELIABLE_FLAG_ACK_ONLY) != 0;
    let mut wire_flags = h.flags & RELIABLE_PUBLIC_FLAGS_MASK;
    if seq_present {
        wire_flags |= RELIABLE_WIRE_FLAG_SEQ_PRESENT;
    }
    if ack_present {
        wire_flags |= RELIABLE_WIRE_FLAG_ACK_PRESENT;
    }
    out.push(wire_flags);
    if seq_present {
        write_uleb128(h.seq as u64, out);
    }
    if ack_present {
        write_uleb128(h.ack as u64, out);
    }
}

#[inline]
fn read_reliable_header(r: &mut ByteReader) -> Result<ReliableHeader, TelemetryError> {
    let flags = r.read_bytes(1)?[0];
    let seq = read_u32_le(r)?;
    let ack = read_u32_le(r)?;
    Ok(ReliableHeader { flags, seq, ack })
}

fn read_reliable_header_compact(r: &mut ByteReader) -> Result<ReliableHeader, TelemetryError> {
    let wire_flags = r.read_bytes(1)?[0];
    let seq = if (wire_flags & RELIABLE_WIRE_FLAG_SEQ_PRESENT) != 0 {
        u32::try_from(read_uleb128(r)?)
            .map_err(|_| TelemetryError::Unpack("reliable seq too large"))?
    } else {
        0
    };
    let ack = if (wire_flags & RELIABLE_WIRE_FLAG_ACK_PRESENT) != 0 {
        u32::try_from(read_uleb128(r)?)
            .map_err(|_| TelemetryError::Unpack("reliable ack too large"))?
    } else {
        0
    };
    Ok(ReliableHeader {
        flags: wire_flags & RELIABLE_PUBLIC_FLAGS_MASK,
        seq,
        ack,
    })
}

#[inline]
fn read_reliable_header_encoded(
    r: &mut ByteReader,
    compact: bool,
) -> Result<ReliableHeader, TelemetryError> {
    if compact {
        read_reliable_header_compact(r)
    } else {
        read_reliable_header(r)
    }
}

#[cfg(feature = "std")]
static ADDRESS_BOOK: OnceLock<Mutex<BTreeMap<u32, Arc<str>>>> = OnceLock::new();

#[cfg(feature = "std")]
fn address_book() -> &'static Mutex<BTreeMap<u32, Arc<str>>> {
    ADDRESS_BOOK.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[inline]
pub(crate) fn source_address_for_sender(sender: &str) -> u32 {
    let addr = sender_address_u32(sender);
    remember_source_address(addr, sender);
    addr
}

#[cfg(feature = "std")]
pub(crate) fn remember_source_address(addr: u32, sender: &str) {
    address_book()
        .lock()
        .expect("wire address book poisoned")
        .entry(addr)
        .or_insert_with(|| Arc::<str>::from(sender));
}

#[cfg(not(feature = "std"))]
pub(crate) fn remember_source_address(_addr: u32, _sender: &str) {}

#[cfg(feature = "std")]
fn sender_name_for_address(addr: u32) -> Arc<str> {
    address_book()
        .lock()
        .expect("wire address book poisoned")
        .get(&addr)
        .cloned()
        .unwrap_or_else(|| format_sender_address(addr))
}

#[cfg(not(feature = "std"))]
fn sender_name_for_address(addr: u32) -> Arc<str> {
    format_sender_address(addr)
}

fn format_sender_address(addr: u32) -> Arc<str> {
    // Format the numeric alias on the stack; only the retained Arc allocates.
    let mut bytes = [0u8; 16];
    let mut start = bytes.len();
    let mut remaining = addr;
    loop {
        start -= 1;
        bytes[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    start -= 6;
    bytes[start..start + 6].copy_from_slice(b"@addr:");
    Arc::from(core::str::from_utf8(&bytes[start..]).expect("numeric alias is ASCII"))
}

// ===========================================================================
// Endpoint bitmap constants and helpers
// ===========================================================================

/// Number of bits needed to cover all possible `DataEndpoint` discriminants.
const EP_BITMAP_BITS: usize = 256;
#[cfg(test)]
use crate::MAX_VALUE_DATA_ENDPOINT;

/// Number of bytes required to store [`EP_BITMAP_BITS`] bits.
const EP_BITMAP_BYTES: usize = EP_BITMAP_BITS.div_ceil(8);

/// Build a compact endpoint bitmap from the provided list of endpoints.
///
/// Each endpoint `ep` sets the bit at position `ep.as_u32()` in the bitmap.
/// Bits are packed LSB-first within each byte.
#[inline]
fn build_endpoint_bitmap(eps: &[DataEndpoint]) -> [u8; EP_BITMAP_BYTES] {
    let mut bm = [0u8; EP_BITMAP_BYTES];
    for &ep in eps {
        let idx = ep.as_u32() as usize;
        debug_assert!(idx < EP_BITMAP_BITS, "endpoint discriminant out of range");
        if idx < EP_BITMAP_BITS {
            let byte = idx / 8;
            let bit = idx % 8;
            bm[byte] |= 1u8 << bit;
        }
    }
    bm
}

/// Expand a bitmap into registered endpoints in ascending discriminant order.
fn expand_endpoint_bitmap(bm: &[u8]) -> TelemetryResult<Arc<[DataEndpoint]>> {
    if bm.len() != EP_BITMAP_BYTES {
        return Err(TelemetryError::Unpack("bad endpoint bitmap size"));
    }
    // Only visit set bits. Sparse telemetry destinations should not initialize
    // and copy a 256-element endpoint array on every header inspection.
    let count = bitmap_popcount(bm);
    let mut endpoints = Arc::<[DataEndpoint]>::new_uninit_slice(count);
    let slots = Arc::get_mut(&mut endpoints).expect("new endpoint storage is unique");
    let mut written = 0;
    for (byte_index, &byte) in bm.iter().enumerate() {
        let mut bits = byte;
        while bits != 0 {
            let idx = byte_index * 8 + bits.trailing_zeros() as usize;
            slots[written].write(
                DataEndpoint::try_from_u32(idx as u32)
                    .ok_or(TelemetryError::Unpack("bad endpoint bit set"))?,
            );
            written += 1;
            bits &= bits - 1;
        }
    }
    // Every set bit initializes exactly one slot; errors drop uninitialized storage.
    debug_assert_eq!(written, count);
    Ok(unsafe { endpoints.assume_init() })
}

pub(crate) fn unique_sorted_endpoints(
    endpoints: &[DataEndpoint],
) -> impl Iterator<Item = DataEndpoint> + '_ {
    let mut previous = None;
    core::iter::from_fn(move || {
        let next = endpoints
            .iter()
            .copied()
            .filter(|endpoint| previous.is_none_or(|previous| *endpoint > previous))
            .min();
        // Retain the last maximum after exhaustion; subsequent calls remain
        // exhausted without a separate state field or restarting the sequence.
        previous = next.or(previous);
        next
    })
}

fn endpoint_arc_from_iter(
    count: usize,
    endpoints: impl Iterator<Item = DataEndpoint>,
) -> TelemetryResult<Arc<[DataEndpoint]>> {
    let mut output = Arc::<[DataEndpoint]>::new_uninit_slice(count);
    let slots = Arc::get_mut(&mut output).unwrap();
    let mut written = 0;
    for endpoint in endpoints {
        if written == count {
            return Err(TelemetryError::Unpack("endpoint count mismatch"));
        }
        slots[written].write(endpoint);
        written += 1;
    }
    if written != count {
        return Err(TelemetryError::Unpack("endpoint count mismatch"));
    }
    // SAFETY: every slot was initialized exactly once above.
    Ok(unsafe { output.assume_init() })
}
fn endpoint_list_size(eps: &[DataEndpoint]) -> usize {
    unique_sorted_endpoints(eps)
        .map(|ep| uleb128_size(u64::from(ep.0)))
        .sum()
}
fn explicit_endpoint_list(eps: &[DataEndpoint]) -> bool {
    eps.iter().any(|ep| ep.0 >= EP_BITMAP_BITS as u32) || endpoint_list_size(eps) < EP_BITMAP_BYTES
}
fn endpoints_match_schema(ty: DataType, eps: &[DataEndpoint]) -> bool {
    let meta = message_meta(ty);
    unique_sorted_endpoints(eps).eq(unique_sorted_endpoints(meta.endpoints_ref()))
}
fn read_endpoint_list<'a>(r: &mut ByteReader<'a>, count: usize) -> TelemetryResult<&'a [u8]> {
    let start = r.off;
    let mut previous = None;
    for _ in 0..count {
        let id = u32::try_from(read_uleb128(r)?)
            .map_err(|_| TelemetryError::Unpack("endpoint too large"))?;
        if previous.is_some_and(|previous| id <= previous) {
            return Err(TelemetryError::Unpack(
                "endpoint list is not unique and sorted",
            ));
        }
        previous = Some(id);
    }
    Ok(&r.buf[start..r.off])
}
fn endpoint_list_iter(bytes: &[u8]) -> impl Iterator<Item = DataEndpoint> + '_ {
    let mut r = ByteReader::new(bytes);
    core::iter::from_fn(move || {
        if r.remaining() == 0 {
            return None;
        }
        read_uleb128(&mut r)
            .ok()
            .and_then(|id| u32::try_from(id).ok())
            .map(DataEndpoint)
    })
}

#[inline]
fn schema_endpoints_from_type(ty: DataType, nep: usize) -> TelemetryResult<Arc<[DataEndpoint]>> {
    // Match bitmap ordering and duplicate removal without expanding all 256
    // possible destinations for the usual one-endpoint schema.
    let meta = message_meta(ty);
    let schema = meta.endpoints_ref();
    if schema.len() == nep
        && schema
            .windows(2)
            .all(|pair| pair[0].as_u32() < pair[1].as_u32())
        && schema
            .iter()
            .all(|ep| DataEndpoint::try_from_u32(ep.as_u32()).is_some())
    {
        // Compiled/registered metadata already owns sorted endpoints on hosts;
        // embedded metadata is static. Avoid a temporary Vec in either case.
        #[cfg(feature = "std")]
        return Ok(meta.endpoints);
        #[cfg(not(feature = "std"))]
        return Ok(Arc::from(schema));
    }
    endpoint_arc_from_iter(nep, unique_sorted_endpoints(schema))
}

#[inline]
fn endpoints_from_wire_or_schema(
    r: &mut ByteReader<'_>,
    bitmap_present: bool,
    list_present: bool,
    ty: Option<DataType>,
    nep: usize,
) -> TelemetryResult<Arc<[DataEndpoint]>> {
    if list_present {
        if bitmap_present {
            return Err(TelemetryError::Unpack("ambiguous endpoint encoding"));
        }
        let bytes = read_endpoint_list(r, nep)?;
        #[cfg(feature = "std")]
        if let Some(meta) = ty.and_then(crate::config::try_get_message_meta)
            && endpoint_list_iter(bytes).eq(meta.endpoints.iter().copied())
        {
            return Ok(meta.endpoints);
        }
        return endpoint_arc_from_iter(nep, endpoint_list_iter(bytes));
    }
    if bitmap_present {
        let bm = r.read_bytes(EP_BITMAP_BYTES)?;
        let endpoints = expand_endpoint_bitmap(bm)?;
        if endpoints.len() != nep {
            return Err(TelemetryError::Unpack("endpoint count mismatch"));
        }
        Ok(endpoints)
    } else {
        let ty = ty.ok_or(TelemetryError::InvalidType)?;
        schema_endpoints_from_type(ty, nep)
    }
}

#[inline]
fn data_type_id_from_wire(ty_v: u64) -> TelemetryResult<u32> {
    let ty_u32 = u32::try_from(ty_v).map_err(|_| TelemetryError::Unpack("type too large"))?;
    Ok(ty_u32)
}

// ===========================================================================
// Packing
// ===========================================================================

/// Pack a [`Packet`] into the compact v2 wire format.
///
/// The returned `Arc<[u8]>` owns the packed bytes and can be shared cheaply.
/// # Arguments
/// - `pkt`: Telemetry packet to pack.
///
/// # Returns
/// - `Arc<[u8]>`: Packed packet in compact v2 wire format.
pub fn pack_packet(pkt: &Packet) -> Arc<[u8]> {
    if is_reliable_type(pkt.data_type()) {
        // Default to an unsequenced reliable header to keep the wire format consistent.
        // Use `pack_packet_with_reliable` for ordered/retransmitted delivery.
        let hdr = ReliableHeader {
            flags: RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        };
        return pack_packet_with_reliable(pkt, hdr);
    }
    pack_packet_inner(pkt, None)
}

/// Pack a [`Packet`] with an explicit reliable header.
///
/// This should be used for data types configured as `reliable` in the schema.
pub fn pack_packet_with_reliable(pkt: &Packet, header: ReliableHeader) -> Arc<[u8]> {
    pack_packet_inner(pkt, Some(header))
}

/// Pack a reliable ACK-only control frame for the given data type.
///
/// The resulting bytes are not a valid `Packet` and should be handled
/// by the router's reliable layer.
pub fn pack_reliable_ack(sender: &str, ty: DataType, timestamp_ms: u64, ack: u32) -> Arc<[u8]> {
    let source_address = source_address_for_sender(sender);

    // No payload for ACK-only control frames.
    let mut out = Vec::with_capacity(32 + EP_BITMAP_BYTES + CRC32_BYTES);

    let flags: u8 = FLAG_ENDPOINT_LIST_PRESENT | FLAG_RELIABLE_HEADER_PRESENT;
    out.push(flags);
    out.push(0u8); // NEP = 0

    write_uleb128(ty.as_u32() as u64, &mut out);
    write_uleb128(0u64, &mut out); // payload size
    write_uleb128(timestamp_ms, &mut out);
    write_uleb128(source_address as u64, &mut out);

    let reliable = ReliableHeader {
        flags: RELIABLE_FLAG_ACK_ONLY,
        seq: 0,
        ack,
    };
    if should_compact_reliable_header(reliable) {
        out[0] |= FLAG_COMPACT_RELIABLE_HEADER;
        write_reliable_header_encoded(reliable, true, &mut out);
    } else {
        write_reliable_header_encoded(reliable, false, &mut out);
    }
    append_crc32(&mut out);

    Arc::<[u8]>::from(out)
}

fn pack_packet_inner(pkt: &Packet, reliable: Option<ReliableHeader>) -> Arc<[u8]> {
    pack_packet_inner_with_contract(
        pkt,
        reliable,
        pkt.wire_shape(),
        pkt.wire_target_senders(),
        None,
    )
    .expect("plaintext packet packing failed")
}

/// Pack `pkt` while explicitly controlling the wire-contract metadata.
///
/// Router and relay forwarding paths use this helper when they need to attach
/// or preserve a migration-safe contract instead of simply serializing the
/// packet against the current runtime schema/topology view.
///
/// # Parameters
/// - `pkt`: Logical packet to pack.
/// - `reliable`: Optional hop-level reliable header to append after the
///   contract.
/// - `shape`: Optional inline payload shape to encode into the contract so
///   downstream unpackers can validate/decode the payload against the
///   original shape.
/// - `target_senders`: Frozen destination-holder sender hashes that keep
///   in-flight routing bound to the intended holders.
///
/// # Returns
/// - `Ok(Arc<[u8]>)` containing the packed frame bytes.
/// - `Err(TelemetryError)` if contract encoding fails.
pub(crate) fn pack_packet_with_wire_contract(
    pkt: &Packet,
    reliable: Option<ReliableHeader>,
    shape: Option<MessageElement>,
    target_senders: &[u64],
) -> TelemetryResult<Arc<[u8]>> {
    pack_packet_inner_with_contract(pkt, reliable, shape, target_senders, None)
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "cryptography"), allow(dead_code))]
pub(crate) struct E2eSealConfig {
    pub key_id: u32,
}

#[cfg(feature = "cryptography")]
pub(crate) fn pack_packet_with_wire_contract_e2e(
    pkt: &Packet,
    reliable: Option<ReliableHeader>,
    shape: Option<MessageElement>,
    target_senders: &[u64],
    e2e: E2eSealConfig,
) -> TelemetryResult<Arc<[u8]>> {
    pack_packet_inner_with_contract(pkt, reliable, shape, target_senders, Some(e2e))
}

fn pack_packet_inner_with_contract(
    pkt: &Packet,
    reliable: Option<ReliableHeader>,
    shape: Option<MessageElement>,
    target_senders: &[u64],
    e2e: Option<E2eSealConfig>,
) -> TelemetryResult<Arc<[u8]>> {
    with_packet_frame_parts(
        pkt,
        reliable,
        shape,
        target_senders,
        e2e,
        |header, payload| Ok(join_frame_with_crc(header, payload)),
    )
}

/// Serialize the normal plaintext header while retaining the existing payload.
/// Used by chunked internal discovery to avoid a second schema-sized buffer.
pub(crate) fn with_plain_packet_parts<T>(
    pkt: &Packet,
    consume: impl FnOnce(&[u8], &[u8]) -> TelemetryResult<T>,
) -> TelemetryResult<T> {
    let reliable = is_reliable_type(pkt.data_type()).then_some(ReliableHeader {
        flags: RELIABLE_FLAG_UNSEQUENCED,
        seq: 0,
        ack: 0,
    });
    with_packet_frame_parts(
        pkt,
        reliable,
        pkt.wire_shape(),
        pkt.wire_target_senders(),
        None,
        consume,
    )
}

fn packet_endpoint_bitmap_present(
    pkt: &Packet,
    shape: Option<MessageElement>,
    target_senders: &[u64],
) -> bool {
    let carries_wire_contract = shape.is_some() || !target_senders.is_empty();
    let endpoints_are_schema_default = endpoints_match_schema(pkt.data_type(), pkt.endpoints());
    // Reliability controls have a protocol-defined endpoint on every peer;
    // their receipt contract does not require a second, 32-byte copy of it.
    // Runtime application types retain explicit endpoints with a frozen
    // contract, since their schemas may differ during discovery/rejoin.
    let fixed_control_endpoints = matches!(
        pkt.data_type(),
        DataType::ReliableAck | DataType::ReliablePartialAck | DataType::ReliablePacketRequest
    );
    // Application catalogs may be complementary or still converging. A short
    // explicit list preserves this packet's actual destinations in that case.
    pkt.data_type().0 > DataType::P2pMessage.0
        || !endpoints_are_schema_default
        || (carries_wire_contract && !fixed_control_endpoints)
}

fn with_packet_frame_parts<T>(
    pkt: &Packet,
    reliable: Option<ReliableHeader>,
    shape: Option<MessageElement>,
    target_senders: &[u64],
    #[cfg_attr(not(feature = "cryptography"), allow(unused_variables))] e2e: Option<E2eSealConfig>,
    consume: impl FnOnce(&[u8], &[u8]) -> TelemetryResult<T>,
) -> TelemetryResult<T> {
    let carries_wire_contract = shape.is_some() || !target_senders.is_empty();
    let endpoint_bitmap_present = packet_endpoint_bitmap_present(pkt, shape, target_senders);
    let endpoint_list_present = endpoint_bitmap_present && explicit_endpoint_list(pkt.endpoints());
    let nep_unique = unique_sorted_endpoints(pkt.endpoints()).count();
    let endpoint_bytes = if endpoint_list_present {
        endpoint_list_size(pkt.endpoints())
    } else if endpoint_bitmap_present {
        EP_BITMAP_BYTES
    } else {
        0
    };

    let source_address = source_address_for_sender(pkt.sender());

    // Decide whether to compress the payload.
    let payload = pkt.payload();
    let (payload_compressed, payload_wire) = payload_compression::compress_if_beneficial(payload);

    // Size the variable-length prefix exactly. A 16-byte estimate can be
    // too small for real timestamps/nonces, doubling a multi-KiB schema
    // buffer while its payload and the old allocation are still retained.
    let reliable_is_compact = reliable.is_some_and(should_compact_reliable_header);
    let reliable_len = if let Some(hdr) = reliable {
        reliable_wire_size(hdr, reliable_is_compact)
    } else {
        0
    };
    let contract_bytes = wire_contract_size(shape, target_senders);
    let contract_len = if carries_wire_contract {
        uleb128_size(contract_bytes as u64) + contract_bytes
    } else {
        0
    };
    let capacity = header_size_bytes(pkt)
        + endpoint_bytes
        + contract_len
        + reliable_len
        + payload_wire.len()
        + CRC32_BYTES;
    #[cfg(feature = "cryptography")]
    let capacity = capacity
        + e2e.map_or(0, |seal| {
            uleb128_size(u64::from(seal.key_id))
                + uleb128_size(payload_wire.len() as u64)
                + uleb128_size(E2E_NONCE_LEN as u64)
                + E2E_NONCE_LEN
                + uleb128_size(E2E_TAG_CAP as u64)
                + E2E_TAG_CAP
        });
    // Plain frames need only a small header scratch buffer. Construct the
    // final Arc directly: Vec -> Arc otherwise retains two frame-sized
    // allocations alongside the schema payload on embedded routers.
    #[cfg(feature = "cryptography")]
    let encrypted = e2e.is_some();
    #[cfg(not(feature = "cryptography"))]
    let encrypted = false;
    let scratch_capacity = if encrypted {
        capacity
    } else {
        capacity - payload_wire.len() - CRC32_BYTES
    };
    let mut out = Vec::with_capacity(scratch_capacity);
    #[cfg(debug_assertions)]
    let initial_capacity = out.capacity();

    // FLAGS byte
    let mut flags: u8 = 0;
    if payload_compressed {
        flags |= FLAG_COMPRESSED_PAYLOAD;
    }
    if carries_wire_contract {
        flags |= FLAG_WIRE_CONTRACT;
    }
    if pkt.nonce() != 0 {
        flags |= FLAG_PACKET_NONCE;
    }
    if endpoint_list_present {
        flags |= FLAG_ENDPOINT_LIST_PRESENT;
    } else if endpoint_bitmap_present {
        flags |= FLAG_ENDPOINT_BITMAP_PRESENT;
    }
    if reliable.is_some() {
        flags |= FLAG_RELIABLE_HEADER_PRESENT;
    }
    if reliable_is_compact {
        flags |= FLAG_COMPACT_RELIABLE_HEADER;
    }
    #[cfg(feature = "cryptography")]
    if e2e.is_some() {
        flags |= FLAG_E2E_ENCRYPTED_PAYLOAD;
    }
    out.push(flags);

    assert!(
        nep_unique <= u8::MAX as usize,
        "too many endpoints selected to fit in NEP u8"
    );
    out.push(nep_unique as u8);

    // NOTE: data_size is the *logical* (uncompressed) payload size.
    write_uleb128(pkt.data_type().as_u32() as u64, &mut out);
    write_uleb128(pkt.data_size() as u64, &mut out);
    write_uleb128(pkt.timestamp(), &mut out);
    if pkt.nonce() != 0 {
        write_uleb128(pkt.nonce() as u64, &mut out);
    }

    write_uleb128(source_address as u64, &mut out);

    if endpoint_list_present {
        for endpoint in unique_sorted_endpoints(pkt.endpoints()) {
            write_uleb128(u64::from(endpoint.0), &mut out);
        }
    } else if endpoint_bitmap_present {
        out.extend_from_slice(&build_endpoint_bitmap(pkt.endpoints()));
    }
    if (flags & FLAG_WIRE_CONTRACT) != 0 {
        // The contract must appear before the reliable header because it may
        // carry the "reliable header present" bit for packets whose current
        // runtime schema lookup no longer reflects the original wire semantics.
        write_uleb128(contract_bytes as u64, &mut out);
        write_wire_contract(shape, target_senders, reliable.is_some(), &mut out)?;
    }
    if let Some(hdr) = reliable {
        write_reliable_header_encoded(hdr, reliable_is_compact, &mut out);
    }
    #[cfg(feature = "cryptography")]
    if let Some(e2e) = e2e {
        write_encrypted_payload(pkt, e2e.key_id, &payload_wire, &mut out)?;
        return consume(&out, &[]);
    }
    #[cfg(debug_assertions)]
    debug_assert_eq!(
        out.capacity(),
        initial_capacity,
        "packet header grew its buffer"
    );
    consume(&out, &payload_wire)
}

// ===========================================================================
// Unpacking (full packet)
// ===========================================================================

/// Unpack a full [`Packet`] from a packed v2 wire frame.
///
/// This validates the frame CRC, resolves the endpoint set, decodes the
/// optional migration-safe wire contract, parses the optional reliable header,
/// and reconstructs the logical `Packet`. When the frame carries an inline wire
/// shape, the returned packet preserves that shape so payload validation and
/// formatting remain stable even if the local runtime schema has changed since
/// the packet was originally packed.
///
/// # Parameters
/// - `buf`: Complete packed frame bytes, including the CRC32 trailer.
///
/// # Returns
/// - `Ok(Packet)` when the frame is well-formed and contains a payload-bearing
///   telemetry packet.
///
/// # Errors
/// - [`TelemetryError::Unpack`] if the frame is malformed, truncated, or
///   fails CRC validation.
/// - [`TelemetryError::InvalidType`] if the type ID is not valid and the frame
///   does not carry enough inline shape information to keep decoding it.
pub fn unpack_packet(buf: &[u8]) -> Result<Packet, TelemetryError> {
    let data = verify_crc32(buf)?;
    if data.is_empty() {
        return Err(TelemetryError::Unpack("short prelude"));
    }
    let mut r = ByteReader::new(data);

    let flags = r.read_bytes(1)?[0];
    let payload_is_compressed = (flags & FLAG_COMPRESSED_PAYLOAD) != 0;
    let endpoint_bitmap_present = (flags & FLAG_ENDPOINT_BITMAP_PRESENT) != 0;
    let compact_reliable_header = (flags & FLAG_COMPACT_RELIABLE_HEADER) != 0;
    #[cfg(feature = "cryptography")]
    let payload_is_encrypted = (flags & FLAG_E2E_ENCRYPTED_PAYLOAD) != 0;
    #[cfg(not(feature = "cryptography"))]
    if (flags & 0x10) != 0 {
        return Err(TelemetryError::Unpack("e2e crypto unsupported"));
    }

    let nep = r.read_bytes(1)?[0] as usize;

    let ty_v = read_uleb128(&mut r)?;
    let dsz = read_uleb128(&mut r)? as usize; // logical (uncompressed) payload size
    let ts_v = read_uleb128(&mut r)?;
    let nonce = if (flags & FLAG_PACKET_NONCE) != 0 {
        u16::try_from(read_uleb128(&mut r)?)
            .map_err(|_| TelemetryError::Unpack("packet nonce too large"))?
    } else {
        0
    };
    let source_address = u32::try_from(read_uleb128(&mut r)?)
        .map_err(|_| TelemetryError::Unpack("source address too large"))?;
    let sender_str = sender_name_for_address(source_address);
    let ty_u32 = data_type_id_from_wire(ty_v)?;
    let known_ty = DataType::try_from_u32(ty_u32);
    let endpoint_bytes = if endpoint_bitmap_present {
        EP_BITMAP_BYTES
    } else {
        0
    };

    // For uncompressed payload: bitmap + [contract] + [reliable] + payload(dsz)
    // For compressed payload: bitmap + [contract] + [reliable] + at least 1 byte.
    if !payload_is_compressed {
        if r.remaining() < endpoint_bytes + dsz {
            return Err(TelemetryError::Unpack("short buffer"));
        }
    } else if r.remaining() < endpoint_bytes + 1 {
        return Err(TelemetryError::Unpack("short buffer"));
    }

    let eps = endpoints_from_wire_or_schema(
        &mut r,
        endpoint_bitmap_present,
        flags & FLAG_ENDPOINT_LIST_PRESENT != 0,
        known_ty,
        nep,
    )?;

    let contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty = known_ty
        .or_else(|| contract.shape.map(|_| DataType(ty_u32)))
        .ok_or(TelemetryError::InvalidType)?;

    // ----- Reliable header (optional) -----
    let mut reliable_hdr: Option<ReliableHeader> = None;
    if flags & FLAG_RELIABLE_HEADER_PRESENT != 0 || contract.has_reliable_header {
        let hdr = read_reliable_header_encoded(&mut r, compact_reliable_header)?;
        if (hdr.flags & RELIABLE_FLAG_ACK_ONLY) != 0 {
            return Err(TelemetryError::Unpack("reliable control frame"));
        }
        reliable_hdr = Some(hdr);
    }

    // Reassembled side frames bypass the small-fragment ingress estimate.
    // Check again immediately before allocating their logical payload, including
    // decompression/decryption scratch when enabled.
    let payload_copies = if payload_is_compressed { 3 } else { 1 };
    #[cfg(feature = "cryptography")]
    let payload_copies = payload_copies + usize::from(payload_is_encrypted);
    let small_ack = matches!(ty, DataType::ReliableAck | DataType::ReliablePartialAck)
        && dsz <= 32
        && payload_copies == 1;
    crate::memory_admission::check(
        if small_ack {
            512
        } else {
            dsz.saturating_mul(payload_copies).saturating_add(512)
        },
        dsz.saturating_add(32),
    )?;
    // ----- Payload handling -----
    let payload: StandardSmallPayload = {
        #[cfg(feature = "cryptography")]
        let payload_wire_owned;
        #[cfg(feature = "cryptography")]
        let payload_wire: &[u8] = if payload_is_encrypted {
            let aad_end = r.off;
            payload_wire_owned = read_encrypted_payload(&mut r, &data[..aad_end], dsz)?;
            &payload_wire_owned
        } else if !payload_is_compressed {
            r.read_bytes(dsz)?
        } else {
            let comp_len = r.remaining();
            r.read_bytes(comp_len)?
        };

        #[cfg(not(feature = "cryptography"))]
        let payload_wire: &[u8] = if !payload_is_compressed {
            r.read_bytes(dsz)?
        } else {
            let comp_len = r.remaining();
            r.read_bytes(comp_len)?
        };

        if payload_is_compressed {
            let decompressed = payload_compression::decompress(payload_wire, dsz)?;
            crate::memory_admission::check(dsz.saturating_add(512), dsz.saturating_add(32))?;
            StandardSmallPayload::new(&decompressed)
        } else {
            if payload_wire.len() != dsz {
                return Err(TelemetryError::Unpack("payload length mismatch"));
            }
            StandardSmallPayload::new(payload_wire)
        }
    };

    // `Packet` preserves logical payload data plus wire-contract metadata, but
    // not hop-level reliable transport state. The router/relay reliable layer
    // consumes that header before handing the logical packet onward.
    let _ = reliable_hdr;
    Packet::new_with_owned_wire_contract(
        ty,
        eps,
        sender_str,
        ts_v,
        nonce,
        payload,
        contract.shape,
        contract.target_senders,
    )
}

// ===========================================================================
// Peek / envelope-only decode
// ===========================================================================

/// Decode only the routing-relevant envelope of a packed packet.
///
/// This reads enough of the frame to expose type, endpoints, sender, timestamp,
/// and any migration-safe contract metadata without touching payload bytes.
/// That makes it the fast path for routing and other header-only inspection.
///
/// # Parameters
/// - `buf`: Complete packed frame bytes, including the CRC32 trailer.
///
/// # Returns
/// - `Ok(TelemetryEnvelope)` containing the logical packet envelope plus any
///   inline wire-shape and target-sender metadata.
///
/// # Errors
/// - [`TelemetryError::Unpack`] if the frame is malformed or fails CRC.
/// - [`TelemetryError::InvalidType`] if the type ID cannot be resolved.
pub fn peek_envelope(buf: &[u8]) -> TelemetryResult<TelemetryEnvelope> {
    Ok(peek_routing_envelope(buf)?.into_owned())
}

/// Validated routing metadata without owned strings or heap-backed arrays.
/// The fixed bitmap is normalized against the current schema on every parse;
/// nothing is cached across schema updates or packet lifetimes.
#[derive(Clone, Debug)]
pub(crate) struct RoutingEnvelope<'a> {
    pub ty: DataType,
    bitmap: [u64; EP_BITMAP_BYTES / 8],
    endpoint_list: Option<&'a [u8]>,
    schema_endpoints: Option<crate::MessageMeta>,
    pub source_address: u32,
    pub timestamp_ms: u64,
    pub wire_shape: Option<MessageElement>,
    pub is_reliable: bool,
    targets: &'a [u8],
    has_reliable_header: bool,
}
pub(crate) struct RoutingEndpointIter<'a> {
    envelope: &'a RoutingEnvelope<'a>,
    word: usize,
    bits: u64,
    list_offset: usize,
    previous: Option<DataEndpoint>,
    finished: bool,
}
impl Iterator for RoutingEndpointIter<'_> {
    type Item = DataEndpoint;
    #[inline(never)]
    fn next(&mut self) -> Option<DataEndpoint> {
        if self.finished {
            return None;
        }
        if let Some(bytes) = self.envelope.endpoint_list {
            let mut reader = ByteReader {
                buf: bytes,
                off: self.list_offset,
            };
            if reader.remaining() == 0 {
                self.finished = true;
                return None;
            }
            let endpoint = read_uleb128(&mut reader)
                .ok()
                .and_then(|id| u32::try_from(id).ok())
                .map(DataEndpoint);
            self.list_offset = reader.off;
            return endpoint;
        }
        if let Some(meta) = &self.envelope.schema_endpoints {
            let next = meta
                .endpoints_ref()
                .iter()
                .copied()
                .filter(|ep| self.previous.is_none_or(|previous| *ep > previous))
                .min();
            self.previous = next;
            self.finished = next.is_none();
            return next;
        }
        while self.bits == 0 {
            self.word += 1;
            if self.word == self.envelope.bitmap.len() {
                self.finished = true;
                return None;
            }
            self.bits = self.envelope.bitmap[self.word];
        }
        let bit = self.bits.trailing_zeros();
        self.bits &= self.bits - 1;
        Some(DataEndpoint((self.word * 64 + bit as usize) as u32))
    }
}

impl RoutingEnvelope<'_> {
    pub fn endpoints(&self) -> RoutingEndpointIter<'_> {
        RoutingEndpointIter {
            envelope: self,
            word: 0,
            bits: self.bitmap[0],
            list_offset: 0,
            previous: None,
            finished: false,
        }
    }
    pub fn target_senders(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.targets
            .as_chunks::<8>()
            .0
            .iter()
            .map(|bytes| u64::from_le_bytes(*bytes))
    }
    fn into_owned(self) -> TelemetryEnvelope {
        TelemetryEnvelope {
            ty: self.ty,
            endpoints: self.endpoints().collect::<Arc<[_]>>(),
            sender: sender_name_for_address(self.source_address),
            source_address: self.source_address,
            timestamp_ms: self.timestamp_ms,
            wire_shape: self.wire_shape,
            target_senders: self.target_senders().collect::<Arc<[_]>>(),
        }
    }
}

fn read_routing_envelope<'a>(r: &mut ByteReader<'a>) -> TelemetryResult<RoutingEnvelope<'a>> {
    let flags = r.read_bytes(1)?[0];
    let nep = r.read_bytes(1)?[0] as usize;
    let ty_v = read_uleb128(r)?;
    let _data_size = read_uleb128(r)?;
    let timestamp_ms = read_uleb128(r)?;
    if flags & FLAG_PACKET_NONCE != 0 {
        let _ = read_uleb128(r)?;
    }
    let source_address = u32::try_from(read_uleb128(r)?)
        .map_err(|_| TelemetryError::Unpack("source address too large"))?;
    let ty_u32 = data_type_id_from_wire(ty_v)?;
    let metadata = crate::config::try_get_message_meta(DataType(ty_u32));
    let known_ty = metadata.as_ref().map(|_| DataType(ty_u32));
    let is_reliable = flags & FLAG_RELIABLE_HEADER_PRESENT != 0;
    // Word-sized bitmaps avoid repeatedly scanning 32 individual bytes for
    // the usual one-destination telemetry frame on size-optimized MCUs.
    let mut bitmap = [0u64; EP_BITMAP_BYTES / 8];
    let mut endpoint_list = None;
    let mut schema_endpoints = None;
    if flags & FLAG_ENDPOINT_LIST_PRESENT != 0 {
        if flags & FLAG_ENDPOINT_BITMAP_PRESENT != 0 {
            return Err(TelemetryError::Unpack("ambiguous endpoint encoding"));
        }
        let bytes = read_endpoint_list(r, nep)?;
        endpoint_list = Some(bytes);
    } else if flags & FLAG_ENDPOINT_BITMAP_PRESENT != 0 {
        let bytes = r.read_bytes(EP_BITMAP_BYTES)?;
        for (word, chunk) in bitmap.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        if bitmap
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum::<usize>()
            != nep
        {
            return Err(TelemetryError::Unpack("endpoint count mismatch"));
        }
        for (index, &word) in bitmap.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let id = index * 64 + bits.trailing_zeros() as usize;
                if !crate::config::endpoint_exists(DataEndpoint(id as u32)) {
                    return Err(TelemetryError::Unpack("bad endpoint bit set"));
                }
                bits &= bits - 1;
            }
        }
    } else {
        let meta = metadata.ok_or(TelemetryError::InvalidType)?;
        if unique_sorted_endpoints(meta.endpoints_ref()).count() != nep {
            return Err(TelemetryError::Unpack("endpoint count mismatch"));
        }
        schema_endpoints = Some(meta);
    }
    let mut shape = None;
    let mut targets: &'a [u8] = &[];
    let mut has_reliable_header = false;
    if flags & FLAG_WIRE_CONTRACT != 0 {
        let len = usize::try_from(read_uleb128(r)?)
            .map_err(|_| TelemetryError::Unpack("wire contract length"))?;
        let mut cr = ByteReader::new(r.read_bytes(len)?);
        let contract_flags = cr.read_bytes(1)?[0];
        if contract_flags & CONTRACT_FLAG_SHAPE != 0 {
            shape = Some(decode_wire_shape(&mut cr)?);
        }
        if contract_flags & CONTRACT_FLAG_TARGETS != 0 {
            let count = usize::try_from(read_uleb128(&mut cr)?)
                .map_err(|_| TelemetryError::Unpack("wire contract target count"))?;
            let bytes = count
                .checked_mul(8)
                .ok_or(TelemetryError::Unpack("wire contract target count"))?;
            targets = cr.read_bytes(bytes)?;
        }
        if cr.remaining() != 0 {
            return Err(TelemetryError::Unpack("wire contract trailing bytes"));
        }
        has_reliable_header = contract_flags & CONTRACT_FLAG_RELIABLE_HEADER != 0;
    }
    if nep == 0 {
        if !is_reliable && !has_reliable_header {
            return Err(TelemetryError::EmptyEndpoints);
        }
        let mut header = ByteReader {
            buf: r.buf,
            off: r.off,
        };
        let reliable =
            read_reliable_header_encoded(&mut header, flags & FLAG_COMPACT_RELIABLE_HEADER != 0)?;
        if reliable.flags & RELIABLE_FLAG_ACK_ONLY == 0 {
            return Err(TelemetryError::EmptyEndpoints);
        }
    }
    let ty = known_ty.unwrap_or(DataType(ty_u32));
    Ok(RoutingEnvelope {
        ty,
        bitmap,
        endpoint_list,
        schema_endpoints,
        source_address,
        timestamp_ms,
        wire_shape: shape,
        is_reliable,
        targets,
        has_reliable_header,
    })
}

/// Read only the bounded type prefix for queue scheduling. This is deliberately
/// not frame validation: dispatch must still verify CRC and the full envelope.
/// Scanning an RX queue must not checksum every retained payload on each pass.
pub(crate) fn scheduling_type(buf: &[u8]) -> Option<DataType> {
    let mut reader = ByteReader::new(buf.get(..buf.len().min(12))?);
    reader.read_bytes(2).ok()?;
    let id = data_type_id_from_wire(read_uleb128(&mut reader).ok()?).ok()?;
    DataType::try_from_u32(id)
}

pub(crate) fn peek_routing_envelope(buf: &[u8]) -> TelemetryResult<RoutingEnvelope<'_>> {
    let data = verify_crc32(buf)?;
    read_routing_envelope(&mut ByteReader::new(data))
}

/// Decode the header/envelope and optional reliable header without touching the payload.
pub struct TelemetryFrameInfo {
    pub envelope: TelemetryEnvelope,
    pub reliable: Option<ReliableHeader>,
}

impl TelemetryFrameInfo {
    #[inline]
    /// Returns `true` when the frame carries only a reliable-delivery acknowledgment.
    pub fn ack_only(&self) -> bool {
        self.reliable
            .map(|h| (h.flags & RELIABLE_FLAG_ACK_ONLY) != 0)
            .unwrap_or(false)
    }
}

pub(crate) struct RoutingFrameInfo<'a> {
    pub envelope: RoutingEnvelope<'a>,
    pub reliable: Option<ReliableHeader>,
}
impl RoutingFrameInfo<'_> {
    pub fn ack_only(&self) -> bool {
        self.reliable
            .is_some_and(|header| header.flags & RELIABLE_FLAG_ACK_ONLY != 0)
    }
}
/// Borrow a complete, uncompressed schema without allocating its envelope or payload.
/// Other packet kinds retain the ordinary decode and reliable-delivery path.
#[cfg(all(feature = "discovery", not(feature = "std")))]
pub(crate) fn peek_plain_schema_payload(buf: &[u8]) -> TelemetryResult<Option<(u32, &[u8])>> {
    // Avoid a second CRC pass for ordinary telemetry. Its existing receive
    // and decode path remains responsible for complete frame validation.
    let mut prelude = ByteReader::new(buf);
    prelude.read_bytes(2)?;
    if data_type_id_from_wire(read_uleb128(&mut prelude)?)? != DataType::DiscoverySchema.as_u32() {
        return Ok(None);
    }
    let data = verify_crc32(buf)?;
    let mut reader = ByteReader::new(data);
    let envelope = read_routing_envelope(&mut reader)?;
    if envelope.ty != DataType::DiscoverySchema
        || data[0] & (FLAG_COMPRESSED_PAYLOAD | 0x10) != 0
        || envelope.target_senders().len() != 0
        || envelope
            .wire_shape
            .is_some_and(|shape| shape != crate::message_meta(DataType::DiscoverySchema).element)
    {
        return Ok(None);
    }
    if envelope.is_reliable || envelope.has_reliable_header {
        let reliable =
            read_reliable_header_encoded(&mut reader, data[0] & FLAG_COMPACT_RELIABLE_HEADER != 0)?;
        // Only the normal unsequenced broadcast snapshot is a no-op. A
        // sequenced snapshot or piggyback ACK still needs reliable processing.
        if reliable.flags != RELIABLE_FLAG_UNSEQUENCED || reliable.seq != 0 || reliable.ack != 0 {
            return Ok(None);
        }
    }
    // The routing parser already validated endpoints and any inline contract.
    // Recover the logical size from the short prelude without owning arrays.
    let mut prelude = ByteReader::new(data);
    prelude.read_bytes(2)?;
    read_uleb128(&mut prelude)?;
    let size = usize::try_from(read_uleb128(&mut prelude)?)
        .map_err(|_| TelemetryError::Unpack("schema payload too large"))?;
    if reader.remaining() != size {
        return Err(TelemetryError::Unpack("schema payload length mismatch"));
    }
    Ok(Some((envelope.source_address, reader.read_bytes(size)?)))
}

pub(crate) fn peek_routing_frame_info(buf: &[u8]) -> TelemetryResult<RoutingFrameInfo<'_>> {
    let data = verify_crc32(buf)?;
    let mut reader = ByteReader::new(data);
    let envelope = read_routing_envelope(&mut reader)?;
    let reliable = if envelope.is_reliable || envelope.has_reliable_header {
        Some(read_reliable_header_encoded(
            &mut reader,
            data[0] & FLAG_COMPACT_RELIABLE_HEADER != 0,
        )?)
    } else {
        None
    };
    Ok(RoutingFrameInfo { envelope, reliable })
}

fn peek_frame_info_inner(buf: &[u8]) -> TelemetryResult<TelemetryFrameInfo> {
    let mut r = ByteReader::new(buf);
    let header = read_routing_envelope(&mut r)?;
    let reliable = if header.is_reliable || header.has_reliable_header {
        Some(read_reliable_header_encoded(
            &mut r,
            buf[0] & FLAG_COMPACT_RELIABLE_HEADER != 0,
        )?)
    } else {
        None
    };
    Ok(TelemetryFrameInfo {
        envelope: header.into_owned(),
        reliable,
    })
}

/// Peek the envelope plus reliable header (if present) without decoding payload bytes.
///
/// This is the primary router/relay fast path for reliable-layer decisions on
/// packed traffic. It still validates the frame CRC before exposing any
/// information.
pub fn peek_frame_info(buf: &[u8]) -> TelemetryResult<TelemetryFrameInfo> {
    let data = verify_crc32(buf)?;
    peek_frame_info_inner(data)
}

/// Peek the envelope plus reliable header (if present) without validating CRC32.
///
/// This is intended only for internal call sites that have already validated
/// frame integrity or intentionally want best-effort inspection of partially
/// trusted bytes.
pub fn peek_frame_info_unchecked(buf: &[u8]) -> TelemetryResult<TelemetryFrameInfo> {
    let (data, _crc) = split_crc32(buf)?;
    peek_frame_info_inner(data)
}

/// Locate the reliable-header byte offset within a packed frame.
///
/// The offset is computed after walking the source address and optional wire
/// contract. This matters because the contract can explicitly state that a
/// reliable header is present even if the current runtime schema no longer
/// marks the type as reliable.
///
/// # Parameters
/// - `buf`: Packed frame bytes, including the CRC32 trailer.
///
/// # Returns
/// - `Ok(Some(offset))` when a reliable header is present.
/// - `Ok(None)` when the frame carries no reliable header.
/// - `Err(TelemetryError)` when the frame is malformed.
pub fn reliable_header_offset(buf: &[u8]) -> TelemetryResult<Option<usize>> {
    Ok(reliable_header_span(buf)?.map(|(off, _, _)| off))
}

pub(crate) fn reliable_header_span(
    buf: &[u8],
) -> TelemetryResult<Option<(usize, usize, ReliableHeader)>> {
    if buf.len() < CRC32_BYTES + 1 {
        return Err(TelemetryError::Unpack("short prelude"));
    }
    let data_len = buf.len().saturating_sub(CRC32_BYTES);
    let mut r = ByteReader::new(&buf[..data_len]);

    let flags = r.read_bytes(1)?[0];
    let endpoint_bitmap_present = (flags & FLAG_ENDPOINT_BITMAP_PRESENT) != 0;
    let compact_reliable_header = (flags & FLAG_COMPACT_RELIABLE_HEADER) != 0;

    let nep = r.read_bytes(1)?[0] as usize;

    let ty_v = read_uleb128(&mut r)?;
    let _dsz = read_uleb128(&mut r)? as usize;
    let _ts_v = read_uleb128(&mut r)?;
    if (flags & FLAG_PACKET_NONCE) != 0 {
        let _ = read_uleb128(&mut r)?;
    }
    let _source_address = u32::try_from(read_uleb128(&mut r)?)
        .map_err(|_| TelemetryError::Unpack("source address too large"))?;
    let endpoint_bytes = if endpoint_bitmap_present {
        EP_BITMAP_BYTES
    } else {
        0
    };

    if r.remaining() < endpoint_bytes {
        return Err(TelemetryError::Unpack("short buffer"));
    }

    if flags & FLAG_ENDPOINT_LIST_PRESENT != 0 {
        if endpoint_bitmap_present {
            return Err(TelemetryError::Unpack("ambiguous endpoint encoding"));
        }
        read_endpoint_list(&mut r, nep)?;
    } else if endpoint_bitmap_present {
        r.read_bytes(EP_BITMAP_BYTES)?;
    }
    let contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty_u32 = data_type_id_from_wire(ty_v)?;
    let _ty = DataType(ty_u32);
    if flags & FLAG_RELIABLE_HEADER_PRESENT == 0 && !contract.has_reliable_header {
        return Ok(None);
    }

    let off = r.off;
    let hdr = read_reliable_header_encoded(&mut r, compact_reliable_header)?;
    Ok(Some((off, r.off - off, hdr)))
}

/// Rewrite the reliable header in-place and refresh the frame CRC32.
///
/// This avoids reserializing the entire packet when reliable transport code
/// only needs to change sequence/ACK state in an already-built frame.
///
/// # Parameters
/// - `buf`: Mutable packed frame bytes.
/// - `flags`: Replacement reliable-header flags byte.
/// - `seq`: Replacement sequence number.
/// - `ack`: Replacement cumulative ACK value.
///
/// # Returns
/// - `Ok(true)` if the frame carried a reliable header and it was rewritten.
/// - `Ok(false)` if no reliable header is present.
/// - `Err(TelemetryError)` if the frame is malformed.
pub fn rewrite_reliable_header(
    buf: &mut [u8],
    flags: u8,
    seq: u32,
    ack: u32,
) -> TelemetryResult<bool> {
    let Some((off, old_len, _)) = reliable_header_span(buf)? else {
        return Ok(false);
    };
    let hdr = ReliableHeader { flags, seq, ack };
    let compact = should_compact_reliable_header(hdr);
    if reliable_wire_size(hdr, compact) != old_len {
        return Err(TelemetryError::Unpack(
            "reliable header rewrite changes wire size",
        ));
    }
    let data_len = buf.len().saturating_sub(CRC32_BYTES);
    if data_len.saturating_sub(off) < old_len {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    if compact {
        buf[0] |= FLAG_COMPACT_RELIABLE_HEADER;
    } else {
        buf[0] &= !FLAG_COMPACT_RELIABLE_HEADER;
    }
    let mut encoded = Vec::with_capacity(old_len);
    write_reliable_header_encoded(hdr, compact, &mut encoded);
    buf[off..off + old_len].copy_from_slice(&encoded);
    if buf.len() < CRC32_BYTES {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let crc = crc32_bytes(&buf[..data_len]);
    buf[data_len..data_len + CRC32_BYTES].copy_from_slice(&crc.to_le_bytes());
    Ok(true)
}

pub(crate) fn rewrite_reliable_header_owned(
    buf: &[u8],
    flags: u8,
    seq: u32,
    ack: u32,
) -> TelemetryResult<Option<Arc<[u8]>>> {
    let Some((off, old_len, _)) = reliable_header_span(buf)? else {
        return Ok(None);
    };
    let data_len = buf.len().saturating_sub(CRC32_BYTES);
    if data_len < off + old_len {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let hdr = ReliableHeader { flags, seq, ack };
    let compact = should_compact_reliable_header(hdr);
    let mut encoded = Vec::with_capacity(reliable_wire_size(hdr, compact));
    write_reliable_header_encoded(hdr, compact, &mut encoded);

    let mut out = Vec::with_capacity(data_len - old_len + encoded.len() + CRC32_BYTES);
    out.extend_from_slice(&buf[..off]);
    if compact {
        out[0] |= FLAG_COMPACT_RELIABLE_HEADER;
    } else {
        out[0] &= !FLAG_COMPACT_RELIABLE_HEADER;
    }
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&buf[off + old_len..data_len]);
    let crc = crc32_bytes(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(Some(Arc::from(out)))
}

// ===========================================================================
// Size helpers
// ===========================================================================

/// Compute the encoded metadata-prefix size for `pkt`.
///
/// This includes the fixed prelude and top-level varints, but excludes the
/// optional endpoint bitmap, optional wire contract, optional reliable header,
/// payload bytes, and CRC32 trailer.
///
/// # Parameters
/// - `pkt`: Packet to size.
///
/// # Returns
/// - Byte count of the packed metadata prefix.
pub fn header_size_bytes(pkt: &Packet) -> usize {
    let prelude = 2; // FLAGS (u8) + NEP (u8)

    let source_address = sender_address_u32(pkt.sender());

    prelude
        + uleb128_size(pkt.data_type().as_u32() as u64)
        + uleb128_size(pkt.data_size() as u64)
        + uleb128_size(pkt.timestamp())
        + if pkt.nonce() != 0 {
            uleb128_size(pkt.nonce() as u64)
        } else {
            0
        }
        + uleb128_size(source_address as u64)
}

/// Compute the full packed wire size for `pkt`.
///
/// This applies the same sender/payload compression heuristics as normal
/// packing, then sums the metadata prefix, optional endpoint bitmap and frozen
/// wire contract, payload bytes, and CRC32 trailer. It matches [`pack_packet`];
/// its default unsequenced reliable header is included.
///
/// # Parameters
/// - `pkt`: Packet to size.
///
/// # Returns
/// - Total encoded frame size in bytes.
pub fn packet_wire_size(pkt: &Packet) -> usize {
    let shape = pkt.wire_shape();
    let targets = pkt.wire_target_senders();
    let contract_bytes = wire_contract_size(shape, targets);
    let contract_len = if shape.is_some() || !targets.is_empty() {
        uleb128_size(contract_bytes as u64) + contract_bytes
    } else {
        0
    };
    let endpoint_len = if packet_endpoint_bitmap_present(pkt, shape, targets) {
        if explicit_endpoint_list(pkt.endpoints()) {
            endpoint_list_size(pkt.endpoints())
        } else {
            EP_BITMAP_BYTES
        }
    } else {
        0
    };
    let (_, payload_wire) = payload_compression::compress_if_beneficial(pkt.payload());
    let reliable_len = if is_reliable_type(pkt.data_type()) {
        let header = ReliableHeader {
            flags: RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        };
        reliable_wire_size(header, should_compact_reliable_header(header))
    } else {
        0
    };
    // Match pack_packet, including its default unsequenced reliable header.
    // No frame/header allocation, payload copy or CRC scan is needed for sizing.
    header_size_bytes(pkt)
        + endpoint_len
        + contract_len
        + reliable_len
        + payload_wire.len()
        + CRC32_BYTES
}

#[inline]
/// Computes the same packet ID as [`Packet::packet_id`] directly from a packed wire frame.
pub fn packet_id_from_wire(buf: &[u8]) -> Result<u64, TelemetryError> {
    let data = verify_crc32(buf)?;
    if data.len() < 2 {
        return Err(TelemetryError::Unpack("short prelude"));
    }

    let mut r = ByteReader::new(data);

    let flags = r.read_bytes(1)?[0];
    let payload_is_compressed = (flags & FLAG_COMPRESSED_PAYLOAD) != 0;
    let compact_reliable_header = (flags & FLAG_COMPACT_RELIABLE_HEADER) != 0;
    #[cfg(feature = "cryptography")]
    let payload_is_encrypted = (flags & FLAG_E2E_ENCRYPTED_PAYLOAD) != 0;
    #[cfg(not(feature = "cryptography"))]
    if (flags & 0x10) != 0 {
        return Err(TelemetryError::Unpack("e2e crypto unsupported"));
    }

    let _nep = r.read_bytes(1)?[0] as usize;

    let _ = read_uleb128(&mut r)?;
    let dsz = read_uleb128(&mut r)? as usize; // logical payload size (uncompressed)
    let ts_v = read_uleb128(&mut r)?;
    let nonce = if (flags & FLAG_PACKET_NONCE) != 0 {
        u16::try_from(read_uleb128(&mut r)?)
            .map_err(|_| TelemetryError::Unpack("packet nonce too large"))?
    } else {
        0
    };
    let source_address = u32::try_from(read_uleb128(&mut r)?)
        .map_err(|_| TelemetryError::Unpack("source address too large"))?;
    // Reuse the validated borrowed envelope. Computing an ID must not build
    // owned endpoint/target arrays merely to hash or inspect their contents.
    let mut envelope_reader = ByteReader::new(data);
    let envelope = read_routing_envelope(&mut envelope_reader)?;
    r = envelope_reader;
    let ty = envelope.ty;

    // ---- reliable header (optional) ----
    if envelope.is_reliable || envelope.has_reliable_header {
        let hdr = read_reliable_header_encoded(&mut r, compact_reliable_header)?;
        if (hdr.flags & RELIABLE_FLAG_ACK_ONLY) != 0 {
            return Err(TelemetryError::Unpack("reliable control frame"));
        }
    }

    // ---- payload bytes (must hash *logical* payload bytes) ----
    #[cfg(feature = "cryptography")]
    let payload_wire_owned;
    #[cfg(feature = "cryptography")]
    let payload_wire: &[u8] = if payload_is_encrypted {
        let aad_end = r.off;
        payload_wire_owned =
            read_encrypted_payload(&mut r, data.get(..aad_end).unwrap_or(&[]), dsz)?;
        &payload_wire_owned
    } else if !payload_is_compressed {
        if r.remaining() < dsz {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        r.read_bytes(dsz)?
    } else {
        let comp_len = r.remaining();
        if comp_len < 1 {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        r.read_bytes(comp_len)?
    };
    #[cfg(not(feature = "cryptography"))]
    let payload_wire: &[u8] = if !payload_is_compressed {
        if r.remaining() < dsz {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        r.read_bytes(dsz)?
    } else {
        let comp_len = r.remaining();
        if comp_len < 1 {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        r.read_bytes(comp_len)?
    };
    let payload_decompressed;
    let payload_bytes: &[u8] = if payload_is_compressed {
        payload_decompressed = payload_compression::decompress(payload_wire, dsz)?;
        &payload_decompressed
    } else {
        if payload_wire.len() != dsz {
            return Err(TelemetryError::Unpack("payload length mismatch"));
        }
        payload_wire
    };

    // ---- hash exactly like Packet::packet_id() ----
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15;

    // Compact source address.
    h = hash_bytes_u64(h, &source_address.to_le_bytes());

    // Stable numeric identity is independent of when schema names are learned.
    h = hash_bytes_u64(h, &ty.0.to_le_bytes());

    // Endpoints as string bytes, in ascending discriminant order.
    for ep in envelope.endpoints() {
        h = hash_bytes_u64(h, &ep.0.to_le_bytes());
    }

    // Timestamp + data_size as bytes
    h = hash_bytes_u64(h, &ts_v.to_le_bytes());
    h = hash_bytes_u64(h, &nonce.to_le_bytes());
    h = hash_bytes_u64(h, &(dsz as u64).to_le_bytes());

    // Payload bytes (logical payload)
    h = hash_bytes_u64(h, payload_bytes);
    Ok(h)
}

mod payload_compression {
    use crate::TelemetryError;
    use alloc::borrow::Cow;
    #[cfg(feature = "compression")]
    use alloc::vec;
    use alloc::vec::Vec;

    #[cfg(feature = "compression")]
    use crate::config::runtime_payload_compress_threshold;
    #[cfg(feature = "compression")]
    use zstd_safe::CompressionLevel;

    /// Compress the given payload if it is beneficial to do so.
    /// # Arguments
    /// - `payload`: Original uncompressed payload bytes.
    /// # Returns
    /// - `(bool, Cow<[u8]>)`: Tuple where the first element indicates whether
    ///   compression was applied, and the second element is the resulting
    ///   payload bytes (compressed or original).
    #[cfg(feature = "compression")]
    pub fn compress_if_beneficial(payload: &'_ [u8]) -> (bool, Cow<'_, [u8]>) {
        if payload.len() < runtime_payload_compress_threshold() {
            return (false, Cow::Borrowed(payload));
        }

        // Bound output and avoid growth beyond useful threshold.
        let Some(compressed) = compress_to_vec_bounded(payload, payload.len().saturating_sub(2))
        else {
            return (false, Cow::Borrowed(payload));
        };

        // Only use compressed form if it actually saves space.
        if compressed.len() + 1 >= payload.len() {
            (false, Cow::Borrowed(payload))
        } else {
            (true, Cow::Owned(compressed))
        }
    }

    #[cfg(feature = "compression")]
    fn compress_to_vec_bounded(input: &[u8], max_output: usize) -> Option<Vec<u8>> {
        if input.is_empty() || max_output == 0 {
            return None;
        }

        let mut out = vec![0u8; max_output];
        // Use default-level behavior for better compression ratio on typical telemetry payloads.
        let level: CompressionLevel = 1;
        let written = zstd_safe::compress(&mut out[..], input, level).ok()?;
        out.truncate(written);
        Some(out)
    }

    /// Decompress the given compressed payload.
    /// # Arguments
    /// - `compressed`: Compressed payload bytes.
    /// - `expected_len`: Expected length of the decompressed payload.
    /// # Returns
    /// - `Vec<u8>`: Decompressed payload bytes.
    /// # Errors
    /// - `TelemetryError::Unpack` if decompression fails or the size
    ///   does not match `expected_len`.
    #[cfg(feature = "compression")]
    pub fn decompress(compressed: &[u8], expected_len: usize) -> Result<Vec<u8>, TelemetryError> {
        let mut out = vec![0u8; expected_len];
        let written = zstd_safe::decompress(&mut out[..], compressed)
            .map_err(|_| TelemetryError::Unpack("decompression failed"))?;
        if written != expected_len {
            return Err(TelemetryError::Unpack("decompressed size mismatch"));
        }
        Ok(out)
    }

    // Stub when compression is disabled (never actually produces compressed payloads).
    #[cfg(not(feature = "compression"))]
    /// Returns the original payload unchanged when compression support is disabled.
    pub fn compress_if_beneficial<'a>(payload: &'a [u8]) -> (bool, Cow<'a, [u8]>) {
        (false, Cow::Borrowed(payload))
    }

    #[cfg(not(feature = "compression"))]
    /// Reports that compressed payloads cannot be decoded when compression support is disabled.
    pub fn decompress(_compressed: &[u8], _expected_len: usize) -> Result<Vec<u8>, TelemetryError> {
        Err(TelemetryError::Unpack(
            "compressed payloads not supported (compression feature disabled)",
        ))
    }
}

#[cfg(test)]
mod endpoint_decode_tests {
    use super::*;

    #[test]
    fn numeric_sender_alias_keeps_packet_wire_and_receipt_identity() {
        let ty = DataType::ReliableAck;
        let make = |sender: &str| {
            Packet::new_with_wire_contract(
                ty,
                message_meta(ty).endpoints_ref(),
                sender,
                200,
                9,
                Arc::from(42u64.to_le_bytes()),
                Some(MessageElement::Static(
                    2,
                    crate::MessageDataType::UInt32,
                    crate::MessageClass::Data,
                )),
                Arc::from([123u64]),
            )
            .unwrap()
        };
        let named = make("FC");
        let alias = alloc::format!("@addr:{}", sender_address_u32("FC"));
        let unresolved = make(&alias);
        assert_eq!(unresolved.packet_id(), named.packet_id());
        let named_wire = pack_packet(&named);
        let alias_wire = pack_packet(&unresolved);
        assert_eq!(alias_wire, named_wire);
        assert_eq!(packet_id_from_wire(&alias_wire).unwrap(), named.packet_id());
        assert_eq!(
            unpack_packet(&alias_wire).unwrap().packet_id(),
            named.packet_id()
        );
    }

    #[test]
    fn scheduling_type_is_bounded_and_never_replaces_frame_validation() {
        let pkt = Packet::new_with_wire_contract(
            DataType::ReliableAck,
            message_meta(DataType::ReliableAck).endpoints_ref(),
            "E2EACK:GS",
            100,
            1,
            Arc::from(42u64.to_le_bytes()),
            Some(MessageElement::Static(
                2,
                crate::MessageDataType::UInt32,
                crate::MessageClass::Data,
            )),
            Arc::from([123u64]),
        )
        .unwrap();
        let mut bytes = pack_packet(&pkt).to_vec();
        assert_eq!(scheduling_type(&bytes), Some(DataType::ReliableAck));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(scheduling_type(&bytes), Some(DataType::ReliableAck));
        assert!(peek_routing_envelope(&bytes).is_err());
        assert!(unpack_packet(&bytes).is_err());
        assert_eq!(scheduling_type(&[0, 0, 0x80]), None);
        assert_eq!(scheduling_type(&[0xff; 1024]), None);
        assert_eq!(scheduling_type(&[]), None);
    }

    #[test]
    fn receipt_contract_omits_redundant_builtin_endpoint_bitmap() {
        for ty in [
            DataType::ReliableAck,
            DataType::ReliablePartialAck,
            DataType::ReliablePacketRequest,
        ] {
            let shape = Some(MessageElement::Static(
                2,
                crate::MessageDataType::UInt32,
                crate::MessageClass::Data,
            ));
            let targets: Arc<[u64]> = Arc::from([0xa7fcbb129e92435f, 0x41426f62de53eb28]);
            let payload: Arc<[u8]> = Arc::from(0x9c2a63d6d7d44100u64.to_le_bytes());
            let make = |eps: &[DataEndpoint]| {
                Packet::new_with_wire_contract(
                    ty,
                    eps,
                    "E2EACK:GS",
                    1791737696510,
                    1234,
                    payload.clone(),
                    shape,
                    targets.clone(),
                )
                .unwrap()
            };
            let packet = make(message_meta(ty).endpoints_ref());
            let packed = pack_packet(&packet);
            assert_eq!(packed[0] & FLAG_ENDPOINT_BITMAP_PRESENT, 0);
            assert_ne!(packed[0] & FLAG_WIRE_CONTRACT, 0);
            let routing = peek_routing_envelope(&packed).unwrap();
            assert_eq!(routing.endpoints().collect::<Vec<_>>(), packet.endpoints());
            assert_eq!(
                routing.target_senders().collect::<Vec<_>>(),
                targets.as_ref()
            );
            let decoded = unpack_packet(&packed).unwrap();
            assert_eq!(decoded.packet_id(), packet.packet_id());
            assert_eq!(decoded.payload(), packet.payload());
            assert_eq!(decoded.wire_target_senders(), targets.as_ref());
            // Sparse explicit endpoints use a short sorted list.
            let explicit = pack_packet(&make(&[DataEndpoint::Discovery]));
            assert_ne!(explicit[0] & FLAG_ENDPOINT_LIST_PRESENT, 0);
            assert_eq!(
                explicit.len(),
                packed.len() + uleb128_size(u64::from(DataEndpoint::Discovery.0))
            );
            assert_eq!(
                unpack_packet(&explicit).unwrap().endpoints(),
                &[DataEndpoint::Discovery]
            );
        }
    }

    #[test]
    fn borrowed_routing_header_preserves_targets_and_validates_truncated_contracts() {
        let targets: Arc<[u64]> = Arc::from([1, u64::MAX, 42]);
        let packet = Packet::new_with_wire_contract(
            DataType::DiscoverySchema,
            &[DataEndpoint::Discovery],
            "PEER",
            1234,
            7,
            Arc::from([1u8, 2, 3]),
            Some(MessageElement::Dynamic(
                crate::MessageDataType::Binary,
                crate::MessageClass::Data,
            )),
            targets.clone(),
        )
        .unwrap();
        let packed = pack_packet(&packet);
        let routing = peek_routing_envelope(&packed).unwrap();
        let full = unpack_packet(&packed).unwrap();
        assert_eq!(routing.ty, full.data_type());
        assert_eq!(routing.endpoints().collect::<Vec<_>>(), full.endpoints());
        assert_eq!(
            routing.target_senders().collect::<Vec<_>>(),
            targets.as_ref()
        );
        assert_eq!(routing.timestamp_ms, full.timestamp());
        // Cut through the header, recomputing CRC so truncation validation runs.
        let data = verify_crc32(&packed).unwrap();
        let mut reader = ByteReader::new(data);
        read_routing_envelope(&mut reader).unwrap();
        for end in 0..reader.off {
            let mut truncated = data[..end].to_vec();
            append_crc32(&mut truncated);
            assert!(
                peek_routing_envelope(&truncated).is_err(),
                "accepted cut at {end}"
            );
        }
    }

    #[test]
    fn large_packet_with_long_prefix_does_not_grow_packing_buffer() {
        let payload: Vec<u8> = (0..3500)
            .map(|i| ((i * 73 + i / 251) % 256) as u8)
            .collect();
        let packet = Packet::new(
            DataType::DiscoverySchema,
            &[DataEndpoint::Discovery],
            "LONG_PREFIX_SENDER",
            u64::MAX,
            payload.into(),
        )
        .unwrap()
        .with_nonce(u16::MAX);
        assert!(header_size_bytes(&packet) > 16);
        let packed = pack_packet(&packet);
        let unpacked = unpack_packet(&packed).unwrap();
        assert_eq!(unpacked.payload(), packet.payload());
        assert_eq!(unpacked.timestamp(), u64::MAX);
        assert_eq!(unpacked.nonce(), u16::MAX);
    }

    #[test]
    fn bitmap_decode_preserves_sorted_unique_destinations() {
        let input = [
            DataEndpoint::TelemetryError,
            DataEndpoint::TimeSync,
            DataEndpoint::Discovery,
            DataEndpoint::TimeSync,
        ];
        let decoded = expand_endpoint_bitmap(&build_endpoint_bitmap(&input)).unwrap();
        assert_eq!(
            &*decoded,
            &[
                DataEndpoint::TimeSync,
                DataEndpoint::Discovery,
                DataEndpoint::TelemetryError
            ]
        );
        assert!(
            expand_endpoint_bitmap(&[0; EP_BITMAP_BYTES])
                .unwrap()
                .is_empty()
        );
        assert!(expand_endpoint_bitmap(&[0; EP_BITMAP_BYTES - 1]).is_err());
    }

    #[test]
    fn bitmap_decode_rejects_unregistered_endpoint_bits() {
        if let Some(id) =
            (0..=MAX_VALUE_DATA_ENDPOINT).find(|id| DataEndpoint::try_from_u32(*id).is_none())
        {
            let mut bitmap = [0; EP_BITMAP_BYTES];
            bitmap[id as usize / 8] = 1 << (id % 8);
            assert!(expand_endpoint_bitmap(&bitmap).is_err());
        }
    }
}
