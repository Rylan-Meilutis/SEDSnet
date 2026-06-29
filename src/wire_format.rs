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
    DataEndpoint, TelemetryError, TelemetryResult, get_message_name, is_reliable_type,
    message_meta,
    packet::Packet,
    {MAX_VALUE_DATA_ENDPOINT, MAX_VALUE_DATA_TYPE, config::DataType},
};

use crate::packet::{hash_bytes_u64, sender_address_u32};
#[cfg(feature = "std")]
use alloc::borrow::ToOwned;
#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
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
//   [RELIABLE HEADER]                -- present if type is configured `reliable`
//       [REL_FLAGS: u8]
//       [SEQ: u32 LE]
//       [ACK: u32 LE]
//   PAYLOAD BYTES                    -- raw or compressed payload bytes
//   [CRC32: u32 LE]                  -- checksum of all prior bytes

// ===========================================================================
// ULEB128 (varint) encoding helpers
// ===========================================================================
const FLAG_COMPRESSED_PAYLOAD: u8 = 0x01;
const FLAG_WIRE_CONTRACT: u8 = 0x04;
const FLAG_PACKET_NONCE: u8 = 0x08;
#[cfg(feature = "cryptography")]
const FLAG_E2E_ENCRYPTED_PAYLOAD: u8 = 0x10;
const FLAG_ENDPOINT_BITMAP_PRESENT: u8 = 0x20;
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
    target_senders: Arc<[u64]>,
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
    let mut result: u64 = 0;
    let mut shift = 0u32;
    // u64 fits in at most 10 ULEB128 bytes.
    for _ in 0..10 {
        let b = r.read_bytes(1)?[0];
        result |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(TelemetryError::Unpack("uleb128 too long"))
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
fn encode_wire_shape(shape: MessageElement) -> Result<Vec<u8>, TelemetryError> {
    let dt = crate::config::message_data_type_code(shape.data_type());
    let class = crate::config::message_class_code(shape.message_type());
    let mut out = Vec::with_capacity(6);
    let mut packed = dt | (class << 4);
    if matches!(shape, MessageElement::Static(_, _, _)) {
        packed |= 1 << 6;
    }
    out.push(packed);
    if let MessageElement::Static(count, _, _) = shape {
        let count = u64::try_from(count).map_err(|_| TelemetryError::Pack("wire shape count"))?;
        write_uleb128(count, &mut out);
    }
    Ok(out)
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
fn encode_wire_contract(
    shape: Option<MessageElement>,
    target_senders: &[u64],
    has_reliable_header: bool,
) -> Result<Vec<u8>, TelemetryError> {
    // Keep the contract self-contained and compact. It exists only to preserve
    // delivery/decode intent for packets that are already in flight while
    // schema or topology updates are still converging.
    let mut out = Vec::new();
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
        out.extend_from_slice(&encode_wire_shape(shape)?);
    }
    if !target_senders.is_empty() {
        write_uleb128(target_senders.len() as u64, &mut out);
        for hash in target_senders {
            out.extend_from_slice(&hash.to_le_bytes());
        }
    }
    Ok(out)
}

#[inline]
fn decode_wire_contract(
    r: &mut ByteReader,
    has_contract: bool,
) -> Result<WireContract, TelemetryError> {
    if !has_contract {
        return Ok(WireContract {
            shape: None,
            target_senders: Arc::<[u64]>::from([]),
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
    let target_senders: Arc<[u64]> = if (flags & CONTRACT_FLAG_TARGETS) != 0 {
        let count = usize::try_from(read_uleb128(&mut cr)?)
            .map_err(|_| TelemetryError::Unpack("wire contract target count"))?;
        let mut targets = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = cr.read_bytes(8)?;
            targets.push(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]));
        }
        Arc::from(targets)
    } else {
        Arc::<[u64]>::from([])
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
fn sender_name_for_address(addr: u32) -> String {
    address_book()
        .lock()
        .expect("wire address book poisoned")
        .get(&addr)
        .map(|sender| sender.as_ref().to_owned())
        .unwrap_or_else(|| format!("@addr:{addr}"))
}

#[cfg(not(feature = "std"))]
fn sender_name_for_address(addr: u32) -> String {
    format!("@addr:{addr}")
}

// ===========================================================================
// Endpoint bitmap constants and helpers
// ===========================================================================

/// Number of bits needed to cover all possible `DataEndpoint` discriminants.
const EP_BITMAP_BITS: usize = (MAX_VALUE_DATA_ENDPOINT as usize) + 1;

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

/// Expand a bitmap of endpoints into a dense array and its logical length.
///
/// Returns `(array, len)` where:
/// - `array[0..len]` are the active endpoints in ascending discriminant order.
/// - `array[len..]` is filled with a dummy `DataEndpoint` and should be ignored.
fn expand_endpoint_bitmap(
    bm: &[u8],
) -> Result<([DataEndpoint; EP_BITMAP_BITS], usize), TelemetryError> {
    if bm.len() != EP_BITMAP_BYTES {
        return Err(TelemetryError::Unpack("bad endpoint bitmap size"));
    }

    // Pick *any* valid endpoint as filler/dummy for the array.
    let dummy = DataEndpoint::TelemetryError;

    // Entire array is initialized to a valid value ⇒ fully safe.
    let mut arr = [dummy; EP_BITMAP_BITS];

    let mut len = 0usize;
    for idx in 0..EP_BITMAP_BITS {
        let byte = idx / 8;
        let bit = idx % 8;
        if (bm[byte] >> bit) & 1 != 0 {
            let v = idx as u32;
            let ep = DataEndpoint::try_from_u32(v)
                .ok_or(TelemetryError::Unpack("bad endpoint bit set"))?;
            arr[len] = ep;
            len += 1;
        }
    }

    Ok((arr, len))
}

#[inline]
fn endpoint_bitmap_and_count(eps: &[DataEndpoint]) -> ([u8; EP_BITMAP_BYTES], usize) {
    let bm = build_endpoint_bitmap(eps);
    let count = bitmap_popcount(&bm);
    (bm, count)
}

#[inline]
fn endpoints_match_schema(ty: DataType, eps: &[DataEndpoint]) -> bool {
    let (packet_bm, packet_count) = endpoint_bitmap_and_count(eps);
    let (schema_bm, schema_count) = endpoint_bitmap_and_count(message_meta(ty).endpoints);
    packet_count == schema_count && packet_bm == schema_bm
}

#[inline]
fn schema_endpoints_from_type(ty: DataType, nep: usize) -> TelemetryResult<Arc<[DataEndpoint]>> {
    let (bm, count) = endpoint_bitmap_and_count(message_meta(ty).endpoints);
    let (ep_buf, ep_len) = expand_endpoint_bitmap(&bm)?;
    if count != nep || ep_len != nep {
        return Err(TelemetryError::Unpack("endpoint count mismatch"));
    }
    Ok(Arc::from(&ep_buf[..ep_len]))
}

#[inline]
fn endpoints_from_wire_or_schema(
    r: &mut ByteReader<'_>,
    bitmap_present: bool,
    ty: Option<DataType>,
    nep: usize,
) -> TelemetryResult<Arc<[DataEndpoint]>> {
    if bitmap_present {
        let bm = r.read_bytes(EP_BITMAP_BYTES)?;
        let (ep_buf, ep_len) = expand_endpoint_bitmap(bm)?;
        if ep_len != nep {
            return Err(TelemetryError::Unpack("endpoint count mismatch"));
        }
        Ok(Arc::from(&ep_buf[..ep_len]))
    } else {
        let ty = ty.ok_or(TelemetryError::InvalidType)?;
        schema_endpoints_from_type(ty, nep)
    }
}

#[inline]
fn data_type_id_from_wire(ty_v: u64) -> TelemetryResult<u32> {
    let ty_u32 = u32::try_from(ty_v).map_err(|_| TelemetryError::Unpack("type too large"))?;
    if ty_u32 > MAX_VALUE_DATA_TYPE {
        return Err(TelemetryError::InvalidType);
    }
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
    let bm = [0u8; EP_BITMAP_BYTES];
    let source_address = source_address_for_sender(sender);

    // No payload for ACK-only control frames.
    let mut out = Vec::with_capacity(32 + EP_BITMAP_BYTES + CRC32_BYTES);

    let flags: u8 = FLAG_ENDPOINT_BITMAP_PRESENT;
    out.push(flags);
    out.push(0u8); // NEP = 0

    write_uleb128(ty.as_u32() as u64, &mut out);
    write_uleb128(0u64, &mut out); // payload size
    write_uleb128(timestamp_ms, &mut out);
    write_uleb128(source_address as u64, &mut out);

    out.extend_from_slice(&bm);
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
    #[cfg_attr(not(feature = "cryptography"), allow(unused_variables))] e2e: Option<E2eSealConfig>,
) -> TelemetryResult<Arc<[u8]>> {
    let carries_wire_contract = shape.is_some() || !target_senders.is_empty();
    let endpoints_are_schema_default = endpoints_match_schema(pkt.data_type(), pkt.endpoints());
    let endpoint_bitmap_present = carries_wire_contract || !endpoints_are_schema_default;
    let (bm, nep_unique) = endpoint_bitmap_and_count(pkt.endpoints());
    let endpoint_bytes = if endpoint_bitmap_present {
        EP_BITMAP_BYTES
    } else {
        0
    };

    let source_address = source_address_for_sender(pkt.sender());

    // Decide whether to compress the payload.
    let payload = pkt.payload();
    let (payload_compressed, payload_wire) = payload_compression::compress_if_beneficial(payload);

    // Heuristic capacity: fixed prelude + bitmap + reliable + payload_wire.
    let reliable_is_compact = reliable.is_some_and(should_compact_reliable_header);
    let reliable_len = if let Some(hdr) = reliable {
        reliable_wire_size(hdr, reliable_is_compact)
    } else {
        0
    };
    let contract = encode_wire_contract(shape, target_senders, reliable.is_some())
        .unwrap_or_else(|_| vec![0u8]);
    let contract_len = if carries_wire_contract {
        uleb128_size(contract.len() as u64) + contract.len()
    } else {
        0
    };
    let mut out = Vec::with_capacity(
        16 + endpoint_bytes + contract_len + reliable_len + payload_wire.len() + CRC32_BYTES,
    );

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
    if endpoint_bitmap_present {
        flags |= FLAG_ENDPOINT_BITMAP_PRESENT;
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

    if endpoint_bitmap_present {
        out.extend_from_slice(&bm);
    }
    if (flags & FLAG_WIRE_CONTRACT) != 0 {
        // The contract must appear before the reliable header because it may
        // carry the "reliable header present" bit for packets whose current
        // runtime schema lookup no longer reflects the original wire semantics.
        write_uleb128(contract.len() as u64, &mut out);
        out.extend_from_slice(&contract);
    }
    if let Some(hdr) = reliable {
        write_reliable_header_encoded(hdr, reliable_is_compact, &mut out);
    }
    #[cfg(feature = "cryptography")]
    if let Some(e2e) = e2e {
        write_encrypted_payload(pkt, e2e.key_id, &payload_wire, &mut out)?;
    } else {
        out.extend_from_slice(&payload_wire);
    }
    #[cfg(not(feature = "cryptography"))]
    {
        out.extend_from_slice(&payload_wire);
    }
    append_crc32(&mut out);

    Ok(Arc::<[u8]>::from(out))
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

    let eps = endpoints_from_wire_or_schema(&mut r, endpoint_bitmap_present, known_ty, nep)?;

    let contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty = known_ty
        .or_else(|| contract.shape.map(|_| DataType(ty_u32)))
        .ok_or(TelemetryError::InvalidType)?;

    // ----- Reliable header (optional) -----
    let mut reliable_hdr: Option<ReliableHeader> = None;
    if is_reliable_type(ty) || contract.has_reliable_header {
        let hdr = read_reliable_header_encoded(&mut r, compact_reliable_header)?;
        if (hdr.flags & RELIABLE_FLAG_ACK_ONLY) != 0 {
            return Err(TelemetryError::Unpack("reliable control frame"));
        }
        reliable_hdr = Some(hdr);
    }

    // ----- Payload handling -----
    let payload_arc: Arc<[u8]> = {
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
            Arc::<[u8]>::from(decompressed)
        } else {
            if payload_wire.len() != dsz {
                return Err(TelemetryError::Unpack("payload length mismatch"));
            }
            Arc::<[u8]>::from(payload_wire)
        }
    };

    // `Packet` preserves logical payload data plus wire-contract metadata, but
    // not hop-level reliable transport state. The router/relay reliable layer
    // consumes that header before handing the logical packet onward.
    let _ = reliable_hdr;
    Packet::new_with_wire_contract(
        ty,
        &eps,
        &sender_str,
        ts_v,
        nonce,
        payload_arc,
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
    let data = verify_crc32(buf)?;
    if data.is_empty() {
        return Err(TelemetryError::Unpack("short prelude"));
    }
    let mut r = ByteReader::new(data);

    let flags = r.read_bytes(1)?[0];
    let endpoint_bitmap_present = (flags & FLAG_ENDPOINT_BITMAP_PRESENT) != 0;
    // We don't care about payload compression here.
    let _payload_is_compressed = (flags & FLAG_COMPRESSED_PAYLOAD) != 0;

    let nep = r.read_bytes(1)?[0] as usize;

    let ty_v = read_uleb128(&mut r)?;
    let _dsz = read_uleb128(&mut r)? as usize;
    let ts_v = read_uleb128(&mut r)?;
    if (flags & FLAG_PACKET_NONCE) != 0 {
        let _ = read_uleb128(&mut r)?;
    }
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

    if r.remaining() < endpoint_bytes {
        return Err(TelemetryError::Unpack("short buffer"));
    }

    let eps = endpoints_from_wire_or_schema(&mut r, endpoint_bitmap_present, known_ty, nep)?;

    let contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty = known_ty
        .or_else(|| contract.shape.map(|_| DataType(ty_u32)))
        .ok_or(TelemetryError::InvalidType)?;

    Ok(TelemetryEnvelope {
        ty,
        endpoints: eps,
        sender: Arc::<str>::from(sender_str),
        source_address,
        timestamp_ms: ts_v,
        wire_shape: contract.shape,
        target_senders: contract.target_senders,
    })
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

fn peek_frame_info_inner(buf: &[u8]) -> TelemetryResult<TelemetryFrameInfo> {
    if buf.is_empty() {
        return Err(TelemetryError::Unpack("short prelude"));
    }
    let mut r = ByteReader::new(buf);

    let flags = r.read_bytes(1)?[0];
    let endpoint_bitmap_present = (flags & FLAG_ENDPOINT_BITMAP_PRESENT) != 0;
    let compact_reliable_header = (flags & FLAG_COMPACT_RELIABLE_HEADER) != 0;
    let _payload_is_compressed = (flags & FLAG_COMPRESSED_PAYLOAD) != 0;

    let nep = r.read_bytes(1)?[0] as usize;

    let ty_v = read_uleb128(&mut r)?;
    let _dsz = read_uleb128(&mut r)? as usize;
    let ts_v = read_uleb128(&mut r)?;
    if (flags & FLAG_PACKET_NONCE) != 0 {
        let _ = read_uleb128(&mut r)?;
    }
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

    if r.remaining() < endpoint_bytes {
        return Err(TelemetryError::Unpack("short buffer"));
    }

    let eps = endpoints_from_wire_or_schema(&mut r, endpoint_bitmap_present, known_ty, nep)?;

    let contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty = known_ty
        .or_else(|| contract.shape.map(|_| DataType(ty_u32)))
        .ok_or(TelemetryError::InvalidType)?;

    let reliable = if is_reliable_type(ty) || contract.has_reliable_header {
        if r.remaining() < 1 {
            return Err(TelemetryError::Unpack("short buffer"));
        }
        Some(read_reliable_header_encoded(
            &mut r,
            compact_reliable_header,
        )?)
    } else {
        None
    };

    Ok(TelemetryFrameInfo {
        envelope: TelemetryEnvelope {
            ty,
            endpoints: eps,
            sender: Arc::<str>::from(sender_str),
            source_address,
            timestamp_ms: ts_v,
            wire_shape: contract.shape,
            target_senders: contract.target_senders,
        },
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

    let _nep = r.read_bytes(1)?[0] as usize;

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

    if endpoint_bitmap_present {
        r.read_bytes(EP_BITMAP_BYTES)?;
    }
    let contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty_u32 = data_type_id_from_wire(ty_v)?;
    let ty = DataType::try_from_u32(ty_u32)
        .or_else(|| contract.shape.map(|_| DataType(ty_u32)))
        .ok_or(TelemetryError::InvalidType)?;
    if !is_reliable_type(ty) && !contract.has_reliable_header {
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
/// packing, then sums the metadata prefix, optional endpoint bitmap, optional
/// reliable header, payload bytes, and CRC32 trailer.
///
/// # Parameters
/// - `pkt`: Packet to size.
///
/// # Returns
/// - Total encoded frame size in bytes.
pub fn packet_wire_size(pkt: &Packet) -> usize {
    let header = header_size_bytes(pkt);

    let payload = pkt.payload();
    let (_payload_compressed, payload_wire) = payload_compression::compress_if_beneficial(payload);

    let reliable_len = if is_reliable_type(pkt.data_type()) {
        let hdr = ReliableHeader {
            flags: 0,
            seq: 0,
            ack: 0,
        };
        reliable_wire_size(hdr, should_compact_reliable_header(hdr))
    } else {
        0
    };
    let endpoint_len = if endpoints_match_schema(pkt.data_type(), pkt.endpoints()) {
        0
    } else {
        EP_BITMAP_BYTES
    };

    header + endpoint_len + reliable_len + payload_wire.len() + CRC32_BYTES
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
    let endpoint_bitmap_present = (flags & FLAG_ENDPOINT_BITMAP_PRESENT) != 0;
    let compact_reliable_header = (flags & FLAG_COMPACT_RELIABLE_HEADER) != 0;
    #[cfg(feature = "cryptography")]
    let payload_is_encrypted = (flags & FLAG_E2E_ENCRYPTED_PAYLOAD) != 0;
    #[cfg(not(feature = "cryptography"))]
    if (flags & 0x10) != 0 {
        return Err(TelemetryError::Unpack("e2e crypto unsupported"));
    }

    let _nep = r.read_bytes(1)?[0] as usize;

    let ty_v = read_uleb128(&mut r)?;
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
    let ty_u32 = data_type_id_from_wire(ty_v)?;
    let known_ty = DataType::try_from_u32(ty_u32);
    let endpoint_bytes = if endpoint_bitmap_present {
        EP_BITMAP_BYTES
    } else {
        0
    };

    if r.remaining() < endpoint_bytes {
        return Err(TelemetryError::Unpack("short buffer"));
    }

    let endpoints = endpoints_from_wire_or_schema(&mut r, endpoint_bitmap_present, known_ty, _nep)?;

    let _contract = decode_wire_contract(&mut r, (flags & FLAG_WIRE_CONTRACT) != 0)?;
    let ty = known_ty
        .or_else(|| _contract.shape.map(|_| DataType(ty_u32)))
        .ok_or(TelemetryError::InvalidType)?;

    // ---- reliable header (optional) ----
    if is_reliable_type(ty) || _contract.has_reliable_header {
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

    // Logical type as string bytes
    h = hash_bytes_u64(h, get_message_name(ty).as_bytes());

    // Endpoints as string bytes, in ascending discriminant order.
    for ep in endpoints.iter() {
        h = hash_bytes_u64(h, ep.as_str().as_bytes());
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
