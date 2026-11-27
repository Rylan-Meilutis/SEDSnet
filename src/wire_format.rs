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
use alloc::vec;
use alloc::{sync::Arc, vec::Vec};
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
    /// Network time-base epoch of the timestamp (0 when not carried).
    pub time_epoch: u16,
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

/// Size of the legacy fixed-form reliable header (flags, u32 seq, u32 ack).
///
/// SEDSnet 7 always writes the compact form (a flags byte plus the ULEB128
/// sequence and ACK when nonzero); this constant remains for API
/// compatibility and bounds that form for sequence/ACK values below 2^28.
pub const RELIABLE_HEADER_BYTES: usize = 1 + 4 + 4;
/// Fixed size of the CRC32 trailer on the wire.
pub const CRC32_BYTES: usize = 4;

// Canonical frame layout (SEDSnet 7):
//
//   [FLAGS: u8]
//       0x01 payload compressed            (logical size field present)
//       0x02 reliable header present
//       0x04 wire contract present         (inline shape / frozen targets)
//       0x08 packet nonce present
//       0x10 E2E-sealed payload            (logical size field present)
//       0x60 endpoint encoding:
//            0x00 schema default, 0x20 exactly one ID, 0x40 counted list;
//            0x60 never starts a canonical frame (side-transport markers)
//       0x80 time-base epoch present
//   VARINT(type)
//   VARINT(source address)
//   [VARINT(time epoch)]                   1..=65534, flag 0x80
//   [VARINT(endpoint count)]               encoding 0x40
//   [VARINT(endpoint ID)...]               encodings 0x20 / 0x40, sorted, unique
//   [VARINT(contract length), CONTRACT]    flag 0x04
//   VARINT(timestamp ms)
//   [VARINT(logical payload size)]         flags 0x01 / 0x10
//   [VARINT(nonce)]                        flag 0x08
//   [RELIABLE HEADER]                      flag 0x02 or the contract declares it
//   PAYLOAD                                runs to the CRC
//   CRC32 (LE)                             over every prior byte
//
// Everything before the timestamp is the frame's static header: it is equal
// for every packet of one stream, which side-transport templates and bundles
// rely on. The timestamp and the fields after it change per packet.
const FLAG_COMPRESSED_PAYLOAD: u8 = 0x01;
const FLAG_RELIABLE_HEADER_PRESENT: u8 = 0x02;
const FLAG_WIRE_CONTRACT: u8 = 0x04;
const FLAG_PACKET_NONCE: u8 = 0x08;
const FLAG_E2E_ENCRYPTED_PAYLOAD: u8 = 0x10;
const FLAG_ENDPOINTS_MASK: u8 = 0x60;
const ENDPOINTS_ONE: u8 = 0x20;
const ENDPOINTS_LIST: u8 = 0x40;
const FLAG_TIME_EPOCH: u8 = 0x80;
/// Flags whose payload is preceded by an explicit logical size.
const FLAGS_SIZED_PAYLOAD: u8 = FLAG_COMPRESSED_PAYLOAD | FLAG_E2E_ENCRYPTED_PAYLOAD;
/// A first byte with both endpoint-encoding bits set is never a canonical
/// frame; side transports use these values for their own frame kinds.
pub(crate) const NON_CANONICAL_MARKER: u8 = 0x60;
/// Whether `first` (a frame's first byte) marks a side-transport frame.
#[inline]
pub(crate) fn is_marker_byte(first: u8) -> bool {
    first & NON_CANONICAL_MARKER == NON_CANONICAL_MARKER
}
const CONTRACT_FLAG_TARGETS: u8 = 0x01;
const CONTRACT_FLAG_SHAPE: u8 = 0x02;
const CONTRACT_FLAG_RELIABLE_HEADER: u8 = 0x04;
const RELIABLE_WIRE_FLAG_SEQ_PRESENT: u8 = 0x04;
const RELIABLE_WIRE_FLAG_ACK_PRESENT: u8 = 0x08;
const RELIABLE_PUBLIC_FLAGS_MASK: u8 =
    RELIABLE_FLAG_ACK_ONLY | RELIABLE_FLAG_UNORDERED | RELIABLE_FLAG_UNSEQUENCED;
const E2E_NONCE_LEN: usize = 12;
const E2E_TAG_CAP: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
struct WireContract {
    shape: Option<MessageElement>,
    target_senders: Option<Arc<[u64]>>,
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

/// Bytes of the contract field (length included).
#[inline]
fn contract_field_size(shape: Option<MessageElement>, targets: &[u64]) -> usize {
    let body = wire_contract_size(shape, targets);
    uleb128_size(body as u64) + body
}

/// Decode a contract body (the bytes after its length).
fn decode_wire_contract(contract: Option<&[u8]>) -> Result<WireContract, TelemetryError> {
    let Some(contract_bytes) = contract else {
        return Ok(WireContract {
            shape: None,
            target_senders: None,
        });
    };
    let (shape, targets) = split_contract(contract_bytes)?;
    let target_senders: Option<Arc<[u64]>> = if targets.is_empty() {
        None
    } else {
        Some(
            targets
                .as_chunks::<8>()
                .0
                .iter()
                .map(|bytes| u64::from_le_bytes(*bytes))
                .collect(),
        )
    };
    Ok(WireContract {
        shape,
        target_senders,
    })
}

/// Parse a contract body into its shape and encoded target hashes, rejecting
/// trailing bytes.
fn split_contract(body: &[u8]) -> Result<(Option<MessageElement>, &[u8]), TelemetryError> {
    let mut cr = ByteReader::new(body);
    // Parsing through a bounded sub-reader lets us reject trailing garbage in
    // the contract cleanly instead of accidentally treating it as payload or
    // reliable-header bytes.
    let flags = cr.read_bytes(1)?[0];
    if flags & !(CONTRACT_FLAG_TARGETS | CONTRACT_FLAG_SHAPE | CONTRACT_FLAG_RELIABLE_HEADER) != 0 {
        return Err(TelemetryError::Unpack("wire contract flags"));
    }
    let shape = if (flags & CONTRACT_FLAG_SHAPE) != 0 {
        Some(decode_wire_shape(&mut cr)?)
    } else {
        None
    };
    let mut targets: &[u8] = &[];
    if (flags & CONTRACT_FLAG_TARGETS) != 0 {
        let count = usize::try_from(read_uleb128(&mut cr)?)
            .map_err(|_| TelemetryError::Unpack("wire contract target count"))?;
        if count == 0 || count > cr.remaining() / 8 {
            return Err(TelemetryError::Unpack("wire contract target count"));
        }
        targets = cr.read_bytes(count * 8)?;
    }
    if cr.remaining() != 0 {
        return Err(TelemetryError::Unpack("wire contract trailing bytes"));
    }
    Ok((shape, targets))
}

#[inline]
fn crc32_bytes(data: &[u8]) -> u32 {
    crate::crc32::crc32(data)
}

#[inline]
fn append_crc32(out: &mut Vec<u8>) {
    let crc = crc32_bytes(out);
    out.extend_from_slice(&crc.to_le_bytes());
}

// Initialize every byte before publishing the shared frame. Keeping the
// payload separate avoids a second full-size allocation during Arc creation.
fn join_frame_with_crc(header: &[u8], payload: &[u8]) -> Arc<[u8]> {
    let mut hasher = crate::crc32::Crc32::new();
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

#[cfg(all(test, feature = "std"))]
std::thread_local! {
    static CRC_VERIFICATIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}
#[cfg(all(test, feature = "std"))]
pub(crate) fn crc_verification_count() -> usize {
    CRC_VERIFICATIONS.with(core::cell::Cell::get)
}

#[inline]
fn verify_crc32(buf: &[u8]) -> Result<&[u8], TelemetryError> {
    #[cfg(all(test, feature = "std"))]
    CRC_VERIFICATIONS.with(|count| count.set(count.get().wrapping_add(1)));
    let (data, expected) = split_crc32(buf)?;
    let actual = crc32_bytes(data);
    if actual != expected {
        return Err(TelemetryError::Unpack("crc32 mismatch"));
    }
    Ok(data)
}

/// Data bytes of an admitted frame without re-hashing them.
///
/// Router-held frames are immutable and their CRC was verified once where
/// they entered the router (or computed when the router built them); see
/// [`verify_frame_crc`]. Internal lookups on such frames still parse and
/// bound-check every field, they only skip the checksum.
#[inline]
fn admitted_data(buf: &[u8]) -> Result<&[u8], TelemetryError> {
    split_crc32(buf).map(|(data, _)| data)
}

#[inline]
fn frame_data(buf: &[u8], verify: bool) -> Result<&[u8], TelemetryError> {
    if verify { verify_crc32(buf) } else { admitted_data(buf) }
}

/// Verify a canonical frame's CRC32 trailer. The router calls this once where
/// bytes enter it; everything it later does with the frame uses the
/// `_unchecked` peeks.
#[inline]
pub(crate) fn verify_frame_crc(buf: &[u8]) -> TelemetryResult<()> {
    verify_crc32(buf).map(|_| ())
}

#[inline]
fn e2e_nonce_for_packet(pkt: &Packet) -> [u8; E2E_NONCE_LEN] {
    // Type and source address, the 48-bit timestamp and the packet nonce: a
    // process never repeats (timestamp, nonce) for one type, and the source
    // address keeps senders that share a group key apart.
    let mut nonce = [0u8; E2E_NONCE_LEN];
    let source = sender_address_u32(pkt.sender());
    nonce[..4].copy_from_slice(&(pkt.data_type().as_u32() ^ source.rotate_left(16)).to_le_bytes());
    nonce[4..10].copy_from_slice(&(pkt.timestamp() & 0x0000_FFFF_FFFF_FFFF).to_le_bytes()[..6]);
    nonce[10..].copy_from_slice(&pkt.nonce().to_le_bytes());
    nonce
}

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

/// Encoded size of a reliable header: a flags byte, then the ULEB128 sequence
/// and ACK when present. A zero sequence (unsequenced wrappers, ACK-only
/// frames) is implied; an ACK-only frame always carries its ACK.
#[inline]
fn reliable_wire_size(h: ReliableHeader) -> usize {
    let seq_present = h.seq != 0;
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

pub(crate) fn write_reliable_header_encoded(h: ReliableHeader, out: &mut Vec<u8>) {
    let seq_present = h.seq != 0;
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

fn read_reliable_header_encoded(r: &mut ByteReader) -> Result<ReliableHeader, TelemetryError> {
    let wire_flags = r.read_bytes(1)?[0];
    if wire_flags
        & !(RELIABLE_PUBLIC_FLAGS_MASK | RELIABLE_WIRE_FLAG_SEQ_PRESENT | RELIABLE_WIRE_FLAG_ACK_PRESENT)
        != 0
    {
        return Err(TelemetryError::Unpack("reliable header flags"));
    }
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
// Endpoint helpers
// ===========================================================================

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
fn schema_endpoints_from_type(ty: DataType) -> TelemetryResult<Arc<[DataEndpoint]>> {
    let meta = crate::config::try_get_message_meta(ty).ok_or(TelemetryError::InvalidType)?;
    let schema = meta.endpoints_ref();
    if schema.windows(2).all(|pair| pair[0].as_u32() < pair[1].as_u32()) {
        // Compiled/registered metadata already owns sorted endpoints on hosts;
        // embedded metadata is static. Avoid a temporary Vec in either case.
        #[cfg(feature = "std")]
        return Ok(meta.endpoints);
        #[cfg(not(feature = "std"))]
        return Ok(Arc::from(schema));
    }
    endpoint_arc_from_iter(
        unique_sorted_endpoints(schema).count(),
        unique_sorted_endpoints(schema),
    )
}

/// The endpoint set of a parsed header: its explicit IDs, or the schema
/// default of its type.
fn endpoints_of_header(header: &FrameHeader<'_>, ty: Option<DataType>) -> TelemetryResult<Arc<[DataEndpoint]>> {
    match header.endpoint_list {
        Some(bytes) => {
            #[cfg(feature = "std")]
            if let Some(meta) = ty.and_then(crate::config::try_get_message_meta)
                && endpoint_list_iter(bytes).eq(meta.endpoints.iter().copied())
            {
                return Ok(meta.endpoints);
            }
            endpoint_arc_from_iter(header.endpoint_count, endpoint_list_iter(bytes))
        }
        None => schema_endpoints_from_type(ty.ok_or(TelemetryError::InvalidType)?),
    }
}

// ===========================================================================
// Frame header parse
// ===========================================================================

/// Every header field of a canonical frame, borrowed from its bytes. One
/// parser serves unpacking, peeks, packet IDs and side transports.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameHeader<'a> {
    pub flags: u8,
    pub ty: u32,
    pub source_address: u32,
    pub time_epoch: u16,
    /// Explicit endpoint IDs (ULEB128, sorted, unique); `None` for the schema
    /// default of the type.
    pub endpoint_list: Option<&'a [u8]>,
    pub endpoint_count: usize,
    /// Contract body (after its length).
    pub contract: Option<&'a [u8]>,
    /// Offset of the timestamp: the end of the static header.
    pub static_end: usize,
    pub timestamp_ms: u64,
    /// Explicit logical payload size (compressed or sealed payloads).
    pub size: Option<usize>,
    pub nonce: u16,
    /// Offset of the reliable header, when present.
    pub reliable_off: usize,
    pub reliable: Option<ReliableHeader>,
    /// Offset of the payload; it runs to the end of the frame data.
    pub payload_off: usize,
}

impl FrameHeader<'_> {
    /// Whether a reliable header follows the nonce.
    #[inline]
    fn contract_declares_reliable(&self) -> bool {
        self.contract
            .and_then(|c| c.first())
            .is_some_and(|flags| flags & CONTRACT_FLAG_RELIABLE_HEADER != 0)
    }
}

/// Parse the header of a canonical frame's data (CRC removed).
pub(crate) fn parse_frame_header(data: &[u8]) -> TelemetryResult<FrameHeader<'_>> {
    let mut r = ByteReader::new(data);
    let flags = r.read_bytes(1)?[0];
    if is_marker_byte(flags) {
        return Err(TelemetryError::Unpack("not a canonical frame"));
    }
    let ty = data_type_id_from_wire(read_uleb128(&mut r)?)?;
    let source_address = u32::try_from(read_uleb128(&mut r)?)
        .map_err(|_| TelemetryError::Unpack("source address too large"))?;
    let time_epoch = if flags & FLAG_TIME_EPOCH != 0 {
        match u16::try_from(read_uleb128(&mut r)?) {
            Ok(epoch) if epoch != 0 && epoch <= crate::packet::MAX_TIME_EPOCH => epoch,
            _ => return Err(TelemetryError::Unpack("time epoch")),
        }
    } else {
        0
    };
    let (endpoint_list, endpoint_count) = match flags & FLAG_ENDPOINTS_MASK {
        ENDPOINTS_ONE => (Some(read_endpoint_list(&mut r, 1)?), 1),
        ENDPOINTS_LIST => {
            // One ID has its own encoding (0x20); a list never holds just one.
            let count = usize::try_from(read_uleb128(&mut r)?)
                .ok()
                .filter(|count| *count <= u8::MAX as usize && *count != 1)
                .ok_or(TelemetryError::Unpack("endpoint count"))?;
            (Some(read_endpoint_list(&mut r, count)?), count)
        }
        _ => (None, 0),
    };
    let contract = if flags & FLAG_WIRE_CONTRACT != 0 {
        let len = usize::try_from(read_uleb128(&mut r)?)
            .map_err(|_| TelemetryError::Unpack("wire contract length"))?;
        if len == 0 {
            return Err(TelemetryError::Unpack("wire contract length"));
        }
        Some(r.read_bytes(len)?)
    } else {
        None
    };
    let static_end = r.off;
    let timestamp_ms = read_uleb128(&mut r)?;
    let size = if flags & FLAGS_SIZED_PAYLOAD != 0 {
        Some(
            usize::try_from(read_uleb128(&mut r)?)
                .map_err(|_| TelemetryError::Unpack("payload too large"))?,
        )
    } else {
        None
    };
    let nonce = if flags & FLAG_PACKET_NONCE != 0 {
        u16::try_from(read_uleb128(&mut r)?)
            .map_err(|_| TelemetryError::Unpack("packet nonce too large"))?
    } else {
        0
    };
    let mut header = FrameHeader {
        flags,
        ty,
        source_address,
        time_epoch,
        endpoint_list,
        endpoint_count,
        contract,
        static_end,
        timestamp_ms,
        size,
        nonce,
        reliable_off: r.off,
        reliable: None,
        payload_off: r.off,
    };
    if flags & FLAG_RELIABLE_HEADER_PRESENT != 0 || header.contract_declares_reliable() {
        header.reliable = Some(read_reliable_header_encoded(&mut r)?);
        header.payload_off = r.off;
    }
    if endpoint_count == 0
        && endpoint_list.is_some()
        && header
            .reliable
            .is_none_or(|reliable| reliable.flags & RELIABLE_FLAG_ACK_ONLY == 0)
    {
        return Err(TelemetryError::EmptyEndpoints);
    }
    Ok(header)
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

    // No payload and no endpoints for ACK-only control frames.
    let mut out = Vec::with_capacity(32);
    out.push(ENDPOINTS_LIST | FLAG_RELIABLE_HEADER_PRESENT);
    write_uleb128(ty.as_u32() as u64, &mut out);
    write_uleb128(source_address as u64, &mut out);
    write_uleb128(0, &mut out); // endpoint count
    write_uleb128(timestamp_ms, &mut out);
    write_reliable_header_encoded(
        ReliableHeader {
            flags: RELIABLE_FLAG_ACK_ONLY,
            seq: 0,
            ack,
        },
        &mut out,
    );
    append_crc32(&mut out);

    Arc::<[u8]>::from(out)
}

// Discovery must bootstrap across peers before optional codec support is known.
// A host with compression enabled must still seed an empty no-compression MCU.
fn payload_for_wire(pkt: &Packet) -> (bool, alloc::borrow::Cow<'_, [u8]>) {
    payload_for_encoding(pkt, true)
}

fn payload_for_encoding(
    pkt: &Packet,
    compression_allowed: bool,
) -> (bool, alloc::borrow::Cow<'_, [u8]>) {
    if !compression_allowed {
        return (false, alloc::borrow::Cow::Borrowed(pkt.payload()));
    }
    if crate::discovery::is_discovery_type(pkt.data_type()) {
        return (false, alloc::borrow::Cow::Borrowed(pkt.payload()));
    }
    payload_compression::compress_if_beneficial(pkt.payload())
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
#[cfg(test)]
pub(crate) fn pack_packet_with_wire_contract(
    pkt: &Packet,
    reliable: Option<ReliableHeader>,
    shape: Option<MessageElement>,
    target_senders: &[u64],
) -> TelemetryResult<Arc<[u8]>> {
    pack_packet_inner_with_contract(pkt, reliable, shape, target_senders, None)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct E2eSealConfig {
    pub key_id: u32,
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
        true,
        |header, payload| Ok(join_frame_with_crc(header, payload)),
    )
}

/// Router/relay replay basis is independent of the current outgoing peer set.
/// Sealed packets also keep their inner payload codec-free: transit nodes cannot
/// rewrite authenticated ciphertext without the recipient's key.
pub(crate) fn pack_routed_packet(
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
        false,
        |header, payload| Ok(join_frame_with_crc(header, payload)),
    )
}

/// Re-encode only an ordinary plaintext payload, preserving its complete header,
/// frozen delivery contract, nonce and reliable sequence. No schema registration
/// or application decoding is needed. `None` retains the existing shared frame.
pub(crate) fn payload_encoding_for_side(
    raw: &[u8],
    allowed: bool,
    max_decoded_bytes: usize,
) -> TelemetryResult<Option<Arc<[u8]>>> {
    let flags = *raw.first().ok_or(TelemetryError::Unpack("short prelude"))?;
    let compressed = flags & FLAG_COMPRESSED_PAYLOAD != 0;
    if flags & FLAG_E2E_ENCRYPTED_PAYLOAD != 0 {
        if compressed && !allowed {
            return Err(TelemetryError::Io(
                "opaque compressed payload requires codec-capable peers",
            ));
        }
        return Ok(None);
    }
    if !compressed && !allowed {
        return Ok(None);
    }
    // Small plaintext samples need neither a second CRC pass nor codec scratch.
    // This is an optional transformation; ordinary ingress validation remains
    // authoritative when the original shared bytes are retained unchanged.
    if !compressed && raw.len() < crate::config::runtime_payload_compress_threshold() {
        return Ok(None);
    }
    // Only router-held (admitted) frames are re-encoded for a side.
    let data = admitted_data(raw)?;
    let (envelope, header) = routing_parts(data)?;
    let allowed = allowed && !crate::discovery::is_discovery_type(envelope.ty);
    let payload = &data[header.payload_off..];
    if compressed == allowed {
        return Ok(None);
    }
    let logical = header.size.unwrap_or(payload.len());
    if !compressed && logical < crate::config::runtime_payload_compress_threshold() {
        return Ok(None);
    }
    let header_len = header.payload_off;
    if logical > max_decoded_bytes || logical > isize::MAX as usize - header_len - CRC32_BYTES - 10 {
        if !compressed {
            return Ok(None);
        }
        return Err(TelemetryError::Io("payload exceeds routing memory budget"));
    }
    let bytes = logical
        .saturating_mul(2)
        .saturating_add(header_len.saturating_mul(2))
        .saturating_add(64);
    let largest = logical
        .saturating_add(header_len)
        .saturating_add(CRC32_BYTES)
        .saturating_add(32);
    if let Err(error) = crate::memory_admission::check(bytes, largest) {
        // Compression is optional; required decompression must retain ownership
        // and backpressure rather than emitting an undecodable frame.
        if !compressed {
            return Ok(None);
        }
        return Err(error);
    }
    let (new_flags, new_payload) = if compressed {
        (
            flags & !FLAG_COMPRESSED_PAYLOAD,
            alloc::borrow::Cow::Owned(payload_compression::decompress(payload, logical)?),
        )
    } else {
        let (beneficial, value) = payload_compression::compress_if_beneficial(payload);
        if !beneficial {
            return Ok(None);
        }
        (flags | FLAG_COMPRESSED_PAYLOAD, value)
    };
    // The logical size field follows the timestamp exactly when the payload
    // is compressed: rebuild the per-packet fields around it.
    let mut prefix = Vec::with_capacity(header_len + 10);
    prefix.push(new_flags);
    prefix.extend_from_slice(&data[1..header.static_end]);
    write_uleb128(header.timestamp_ms, &mut prefix);
    if new_flags & FLAGS_SIZED_PAYLOAD != 0 {
        write_uleb128(logical as u64, &mut prefix);
    }
    if header.nonce != 0 {
        write_uleb128(u64::from(header.nonce), &mut prefix);
    }
    prefix.extend_from_slice(&data[header.reliable_off..header.payload_off]);
    Ok(Some(join_frame_with_crc(&prefix, &new_payload)))
}

/// Conservative size credit before retaining a compressed-to-raw conversion.
/// Includes the complete original header/CRC and the logical payload, so the
/// bounded queue reservation never depends on optimistic compression ratios.
pub(crate) fn decoded_frame_upper_bound(raw: &[u8]) -> TelemetryResult<usize> {
    let header = parse_frame_header(admitted_data(raw)?)?;
    let logical = header.size.unwrap_or(0);
    raw.len()
        .checked_add(logical)
        .ok_or(TelemetryError::Io("memory pressure"))
}

/// Keep replay ownership independent of a transient side codec choice. Sealed
/// frames cannot be rewritten without their key; their side compatibility is
/// checked before dispatch instead.
pub(crate) fn payload_encoding_for_retention(
    raw: &[u8],
    budget: usize,
) -> TelemetryResult<Option<Arc<[u8]>>> {
    if raw.first().is_some_and(|flags| flags & 0x10 != 0) {
        return Ok(None);
    }
    payload_encoding_for_side(raw, false, budget)
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
        true,
        consume,
    )
}

/// Whether the frame carries its endpoint IDs rather than the schema default.
fn packet_endpoints_explicit(
    pkt: &Packet,
    shape: Option<MessageElement>,
    target_senders: &[u64],
) -> bool {
    let carries_wire_contract = shape.is_some() || !target_senders.is_empty();
    let endpoints_are_schema_default = endpoints_match_schema(pkt.data_type(), pkt.endpoints());
    // Reliability controls and P2P messages have a protocol-defined endpoint
    // on every peer; their delivery contract does not require a copy of it.
    // Runtime application types retain explicit endpoints with a frozen
    // contract, since their schemas may differ during discovery/rejoin.
    let fixed_control_endpoints = matches!(
        pkt.data_type(),
        DataType::ReliableAck
            | DataType::ReliablePartialAck
            | DataType::ReliablePacketRequest
            | DataType::P2pMessage
    );
    // Application catalogs may be complementary or still converging. A short
    // explicit list preserves this packet's actual destinations in that case.
    pkt.data_type().0 > DataType::P2pMessage.0
        || !endpoints_are_schema_default
        || (carries_wire_contract && !fixed_control_endpoints)
}

/// Encoded size of the endpoint field (count and IDs) for `eps`.
fn endpoint_field_size(eps: &[DataEndpoint]) -> usize {
    let count = unique_sorted_endpoints(eps).count();
    endpoint_list_size(eps) + if count == 1 { 0 } else { uleb128_size(count as u64) }
}

fn with_packet_frame_parts<T>(
    pkt: &Packet,
    reliable: Option<ReliableHeader>,
    shape: Option<MessageElement>,
    target_senders: &[u64],
    e2e: Option<E2eSealConfig>,
    compression_allowed: bool,
    consume: impl FnOnce(&[u8], &[u8]) -> TelemetryResult<T>,
) -> TelemetryResult<T> {
    // Time sync packets are never sealed end to end: their nonce comes from a
    // short counter (see the router's time sync packets), which must never
    // feed an AEAD nonce.
    if e2e.is_some()
        && matches!(
            pkt.data_type(),
            DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
        )
    {
        return Err(TelemetryError::BadArg);
    }
    let carries_wire_contract = shape.is_some() || !target_senders.is_empty();
    let endpoints_explicit = packet_endpoints_explicit(pkt, shape, target_senders);
    let nep_unique = unique_sorted_endpoints(pkt.endpoints()).count();
    assert!(
        nep_unique <= u8::MAX as usize,
        "too many endpoints selected to fit the endpoint count"
    );
    let endpoint_bytes = if endpoints_explicit {
        endpoint_field_size(pkt.endpoints())
    } else {
        0
    };

    let source_address = source_address_for_sender(pkt.sender());

    // Decide whether to compress the payload.
    let (payload_compressed, payload_wire) = payload_for_encoding(pkt, compression_allowed);
    let encrypted = e2e.is_some();
    let sized = payload_compressed || encrypted;

    // Size the variable-length prefix exactly. A 16-byte estimate can be
    // too small for real timestamps/nonces, doubling a multi-KiB schema
    // buffer while its payload and the old allocation are still retained.
    let reliable_len = reliable.map_or(0, reliable_wire_size);
    let contract_len = if carries_wire_contract {
        contract_field_size(shape, target_senders)
    } else {
        0
    };
    let capacity = header_size_bytes(pkt)
        + endpoint_bytes
        + contract_len
        + reliable_len
        + if sized { uleb128_size(pkt.data_size() as u64) } else { 0 }
        + payload_wire.len()
        + CRC32_BYTES;
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
    if endpoints_explicit {
        flags |= if nep_unique == 1 { ENDPOINTS_ONE } else { ENDPOINTS_LIST };
    }
    if reliable.is_some() {
        flags |= FLAG_RELIABLE_HEADER_PRESENT;
    }
    if encrypted {
        flags |= FLAG_E2E_ENCRYPTED_PAYLOAD;
    }
    if pkt.time_epoch() != 0 {
        flags |= FLAG_TIME_EPOCH;
    }
    out.push(flags);

    // Static header: equal for every packet of one stream.
    write_uleb128(pkt.data_type().as_u32() as u64, &mut out);
    write_uleb128(source_address as u64, &mut out);
    if pkt.time_epoch() != 0 {
        write_uleb128(u64::from(pkt.time_epoch()), &mut out);
    }
    if endpoints_explicit {
        if nep_unique != 1 {
            write_uleb128(nep_unique as u64, &mut out);
        }
        for endpoint in unique_sorted_endpoints(pkt.endpoints()) {
            write_uleb128(u64::from(endpoint.0), &mut out);
        }
    }
    if carries_wire_contract {
        // The contract precedes the reliable header because it may carry the
        // "reliable header present" bit for packets whose current runtime
        // schema lookup no longer reflects the original wire semantics.
        write_uleb128(wire_contract_size(shape, target_senders) as u64, &mut out);
        write_wire_contract(shape, target_senders, reliable.is_some(), &mut out)?;
    }
    // Per-packet fields. The logical size is written only when the payload
    // bytes do not state it (compressed or sealed).
    write_uleb128(pkt.timestamp(), &mut out);
    if sized {
        write_uleb128(pkt.data_size() as u64, &mut out);
    }
    if pkt.nonce() != 0 {
        write_uleb128(pkt.nonce() as u64, &mut out);
    }
    if let Some(hdr) = reliable {
        write_reliable_header_encoded(hdr, &mut out);
    }
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
    unpack_packet_with_role(buf, false)
}

pub(crate) fn unpack_packet_with_role(buf: &[u8], managed: bool) -> Result<Packet, TelemetryError> {
    unpack_packet_frame(buf, managed, true)
}

/// [`unpack_packet_with_role`] for an admitted frame (CRC already verified).
pub(crate) fn unpack_packet_with_role_unchecked(
    buf: &[u8],
    managed: bool,
) -> Result<Packet, TelemetryError> {
    unpack_packet_frame(buf, managed, false)
}

fn unpack_packet_frame(buf: &[u8], managed: bool, verify: bool) -> Result<Packet, TelemetryError> {
    let data = frame_data(buf, verify)?;
    if data.is_empty() {
        return Err(TelemetryError::Unpack("short prelude"));
    }
    let header = parse_frame_header(data)?;
    let flags = header.flags;
    let payload_is_compressed = (flags & FLAG_COMPRESSED_PAYLOAD) != 0;
    let payload_is_encrypted = (flags & FLAG_E2E_ENCRYPTED_PAYLOAD) != 0;
    if let Some(reliable) = header.reliable
        && (reliable.flags & RELIABLE_FLAG_ACK_ONLY) != 0
    {
        return Err(TelemetryError::Unpack("reliable control frame"));
    }
    let payload_region = &data[header.payload_off..];
    // Logical (uncompressed) payload size.
    let dsz = header.size.unwrap_or(payload_region.len());
    if payload_is_compressed && payload_region.is_empty() {
        return Err(TelemetryError::Unpack("short buffer"));
    }
    let sender_str = sender_name_for_address(header.source_address);
    let known_ty = DataType::try_from_u32(header.ty);
    let eps = endpoints_of_header(&header, known_ty)?;
    let nep = eps.len();

    let contract = decode_wire_contract(header.contract)?;
    let ty = known_ty
        .or_else(|| contract.shape.map(|_| DataType(header.ty)))
        .ok_or(TelemetryError::InvalidType)?;
    let reliable_hdr = header.reliable;

    // Reassembled side frames bypass the small-fragment ingress estimate.
    // Check again immediately before allocating their logical payload, including
    // decompression/decryption scratch when enabled.
    let payload_copies = if payload_is_compressed { 3 } else { 1 };
    let payload_copies = payload_copies + usize::from(payload_is_encrypted);
    let small_ack = matches!(ty, DataType::ReliableAck | DataType::ReliablePartialAck)
        && dsz <= 32
        && payload_copies == 1;
    if crate::memory_admission::supports_work_kinds()
        && !small_ack
        && buf.len() <= 128
        && flags & FLAGS_SIZED_PAYLOAD == 0
        && (crate::memory_admission::protected_discovery_request_shape(
            ty,
            dsz == 0,
            eps.as_ref() == [DataEndpoint::Discovery],
            contract
                .target_senders
                .as_ref()
                .map_or(0, |owners| owners.len()),
            contract.shape,
        ) || crate::memory_admission::protected_control_shape(
            ty,
            nep,
            contract
                .target_senders
                .as_ref()
                .map_or(0, |owners| owners.len()),
            contract.shape,
            reliable_hdr.is_some(),
            managed,
        ))
    {
        crate::memory_admission::check_small_protected_decode(buf.len())?;
    } else {
        crate::memory_admission::check(
            if small_ack {
                512
            } else {
                dsz.saturating_mul(payload_copies).saturating_add(512)
            },
            dsz.saturating_add(32),
        )?;
    }
    // ----- Payload handling -----
    let payload: StandardSmallPayload = {
        let payload_wire_owned;
        let payload_wire: &[u8] = if payload_is_encrypted {
            let mut r = ByteReader::new(data);
            r.off = header.payload_off;
            payload_wire_owned = read_encrypted_payload(&mut r, &data[..header.payload_off], dsz)?;
            &payload_wire_owned
        } else {
            payload_region
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
        header.timestamp_ms,
        header.nonce,
        payload,
        contract.shape,
        contract.target_senders,
    )
    .map(|pkt| pkt.with_time_epoch(header.time_epoch))
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

/// [`peek_envelope`] for an admitted frame (CRC already verified).
pub(crate) fn peek_envelope_unchecked(buf: &[u8]) -> TelemetryResult<TelemetryEnvelope> {
    Ok(peek_routing_envelope_unchecked(buf)?.into_owned())
}

/// Validated routing metadata without owned strings or heap-backed arrays.
/// The schema-derived parts of an envelope may be reused by [`envelope_memo`]
/// for byte-identical static headers, but never across a schema generation.
#[derive(Clone, Debug)]
pub(crate) struct RoutingEnvelope<'a> {
    pub ty: DataType,
    endpoint_list: Option<&'a [u8]>,
    #[cfg(feature = "std")]
    schema_endpoints: Option<Arc<[DataEndpoint]>>,
    #[cfg(not(feature = "std"))]
    schema_endpoints: Option<&'static [DataEndpoint]>,
    pub source_address: u32,
    pub timestamp_ms: u64,
    pub time_epoch: u16,
    pub wire_shape: Option<MessageElement>,
    pub is_reliable: bool,
    targets: &'a [u8],
    has_reliable_header: bool,
}
#[derive(Clone)]
pub(crate) struct RoutingEndpointIter<'a> {
    envelope: &'a RoutingEnvelope<'a>,
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
        let next = self.envelope.schema_endpoints.as_ref().and_then(|endpoints| {
            endpoints
                .iter()
                .copied()
                .filter(|ep| self.previous.is_none_or(|previous| *ep > previous))
                .min()
        });
        self.previous = next;
        self.finished = next.is_none();
        next
    }
}

impl RoutingEnvelope<'_> {
    /// The encoded endpoint list, when the frame carries one: equal bytes
    /// decode to equal endpoint sets.
    pub(crate) fn endpoint_list_bytes(&self) -> Option<&[u8]> {
        self.endpoint_list
    }
    pub fn endpoints(&self) -> RoutingEndpointIter<'_> {
        RoutingEndpointIter {
            envelope: self,
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
            time_epoch: self.time_epoch,
            wire_shape: self.wire_shape,
            target_senders: self.target_senders().collect::<Arc<[_]>>(),
        }
    }
}

/// The schema- and contract-derived part of an envelope: a function of the
/// static header bytes and the schema generation only.
#[derive(Clone)]
struct StaticEnvelope {
    #[cfg(feature = "std")]
    schema_endpoints: Option<Arc<[DataEndpoint]>>,
    #[cfg(not(feature = "std"))]
    schema_endpoints: Option<&'static [DataEndpoint]>,
    wire_shape: Option<MessageElement>,
    /// Target hashes as (offset, length) in the frame.
    targets: (usize, usize),
    has_reliable_header: bool,
}

fn static_envelope(data: &[u8], header: &FrameHeader<'_>) -> TelemetryResult<StaticEnvelope> {
    let schema_endpoints = if header.endpoint_list.is_none() {
        let meta = crate::config::try_get_message_meta(DataType(header.ty))
            .ok_or(TelemetryError::InvalidType)?;
        if meta.endpoints_ref().is_empty() {
            return Err(TelemetryError::EmptyEndpoints);
        }
        Some(meta.endpoints)
    } else {
        None
    };
    let (wire_shape, targets) = match header.contract {
        Some(contract) => {
            let (shape, targets) = split_contract(contract)?;
            let start = if targets.is_empty() {
                0
            } else {
                targets.as_ptr() as usize - data.as_ptr() as usize
            };
            (shape, (start, targets.len()))
        }
        None => (None, (0, 0)),
    };
    Ok(StaticEnvelope {
        schema_endpoints,
        wire_shape,
        targets,
        has_reliable_header: header.contract_declares_reliable(),
    })
}

/// Parse a frame's routing envelope and header.
///
/// One forwarded frame used to be parsed about twenty times on its way
/// through the router (scheduling, dedupe, routing, encoding). The header
/// itself is a handful of ULEB128 fields; its schema lookup and contract
/// decode are served from [`envelope_memo`] when the same static header was
/// parsed under the current schema generation.
fn routing_parts(data: &[u8]) -> TelemetryResult<(RoutingEnvelope<'_>, FrameHeader<'_>)> {
    let header = parse_frame_header(data)?;
    let generation = crate::config::schema_generation();
    let key = &data[..header.static_end];
    let derived = match envelope_memo::lookup(key, generation) {
        Some(derived) => derived,
        None => {
            let derived = static_envelope(data, &header)?;
            envelope_memo::store(key, &derived, generation);
            derived
        }
    };
    let (start, len) = derived.targets;
    let envelope = RoutingEnvelope {
        ty: DataType(header.ty),
        endpoint_list: header.endpoint_list,
        schema_endpoints: derived.schema_endpoints,
        source_address: header.source_address,
        timestamp_ms: header.timestamp_ms,
        time_epoch: header.time_epoch,
        wire_shape: derived.wire_shape,
        is_reliable: header.flags & FLAG_RELIABLE_HEADER_PRESENT != 0,
        targets: data.get(start..start + len).ok_or(TelemetryError::Unpack("short buffer"))?,
        has_reliable_header: derived.has_reliable_header,
    };
    Ok((envelope, header))
}

/// Small cache of schema-derived envelope parts, keyed by the exact static
/// header bytes (type, source, epoch, endpoints, contract).
///
/// That part of a parse reads only those bytes and the schema, so two frames
/// with the same static header under the same schema generation derive the
/// same parts; the key is the content, not the buffer's identity, and needs
/// no invalidation when buffers are freed or reused. Every packet of one
/// stream shares its static header, so consecutive frames hit. Headers longer
/// than the key capacity are not cached.
mod envelope_memo {
    use super::StaticEnvelope;

    const KEY_BYTES: usize = 40;
    const SLOTS: usize = 2;

    #[derive(Clone)]
    struct Entry {
        generation: u32,
        len: u8,
        key: [u8; KEY_BYTES],
        derived: StaticEnvelope,
    }

    #[derive(Default)]
    struct Memo {
        slots: [Option<Entry>; SLOTS],
        next: usize,
    }

    impl Memo {
        fn lookup(&self, key: &[u8], generation: u32) -> Option<StaticEnvelope> {
            self.slots
                .iter()
                .flatten()
                .find(|entry| {
                    entry.generation == generation && entry.key[..usize::from(entry.len)] == *key
                })
                .map(|entry| entry.derived.clone())
        }

        fn store(&mut self, key: &[u8], derived: &StaticEnvelope, generation: u32) {
            if key.len() > KEY_BYTES {
                return;
            }
            let mut bytes = [0u8; KEY_BYTES];
            bytes[..key.len()].copy_from_slice(key);
            self.slots[self.next] = Some(Entry {
                generation,
                len: key.len() as u8,
                key: bytes,
                derived: derived.clone(),
            });
            self.next = (self.next + 1) % SLOTS;
        }
    }

    #[cfg(feature = "std")]
    std::thread_local! {
        static MEMO: core::cell::RefCell<Memo> = core::cell::RefCell::new(Memo::default());
    }

    #[cfg(feature = "std")]
    pub(super) fn lookup(key: &[u8], generation: u32) -> Option<StaticEnvelope> {
        MEMO.try_with(|memo| memo.try_borrow().ok()?.lookup(key, generation))
            .ok()
            .flatten()
    }

    #[cfg(feature = "std")]
    pub(super) fn store(key: &[u8], derived: &StaticEnvelope, generation: u32) {
        let _ = MEMO.try_with(|memo| {
            if let Ok(mut memo) = memo.try_borrow_mut() {
                memo.store(key, derived, generation);
            }
        });
    }

    // Without std there is no thread-local storage. One shared memo is taken
    // with a try-lock; a parse that finds it busy (another thread, or an
    // interrupt preempting a holder) simply parses without it.
    #[cfg(all(not(feature = "std"), target_has_atomic = "8"))]
    mod shared {
        use super::Memo;
        use core::cell::UnsafeCell;
        use core::sync::atomic::{AtomicBool, Ordering};

        // Heap-allocated on first use (a few hundred bytes), so images with
        // no spare static RAM do not pay for it in .bss: the static is one
        // pointer and a flag. If that allocation fails the memo stays
        // disabled and every parse is a plain parse.
        struct Shared {
            busy: AtomicBool,
            memo: UnsafeCell<*mut Memo>,
        }
        // SAFETY: `memo` is only accessed while `busy` is held.
        unsafe impl Sync for Shared {}

        static SHARED: Shared = Shared {
            busy: AtomicBool::new(false),
            memo: UnsafeCell::new(core::ptr::null_mut()),
        };

        pub(super) fn with<R>(f: impl FnOnce(&mut Memo) -> R) -> Option<R> {
            SHARED
                .busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()?;
            // SAFETY: the try-lock above grants exclusive access.
            let slot = unsafe { &mut *SHARED.memo.get() };
            if slot.is_null() {
                let layout = core::alloc::Layout::new::<Memo>();
                // SAFETY: `Memo` is not zero-sized; a null result is handled.
                let raw = unsafe { alloc::alloc::alloc(layout) }.cast::<Memo>();
                if !raw.is_null() {
                    // SAFETY: `raw` is a fresh allocation for one `Memo`; it is
                    // never freed (one per process, like a static).
                    unsafe { raw.write(Memo::default()) };
                    *slot = raw;
                }
            }
            // SAFETY: a non-null slot points at the initialised memo, used
            // only under the try-lock.
            let result = (!slot.is_null()).then(|| f(unsafe { &mut **slot }));
            SHARED.busy.store(false, Ordering::Release);
            result
        }
    }

    #[cfg(all(not(feature = "std"), target_has_atomic = "8"))]
    pub(super) fn lookup(key: &[u8], generation: u32) -> Option<StaticEnvelope> {
        shared::with(|memo| memo.lookup(key, generation)).flatten()
    }

    #[cfg(all(not(feature = "std"), target_has_atomic = "8"))]
    pub(super) fn store(key: &[u8], derived: &StaticEnvelope, generation: u32) {
        let _ = shared::with(|memo| memo.store(key, derived, generation));
    }

    #[cfg(all(not(feature = "std"), not(target_has_atomic = "8")))]
    pub(super) fn lookup(_key: &[u8], _generation: u32) -> Option<StaticEnvelope> {
        None
    }

    #[cfg(all(not(feature = "std"), not(target_has_atomic = "8")))]
    pub(super) fn store(_key: &[u8], _derived: &StaticEnvelope, _generation: u32) {}
}

/// The packet ID of an admitted frame whose routing frame is parsed, as
/// `packet_id_from_wire_unchecked` computes it, for the common frame without
/// a reliable header, payload compression or encryption. `None` otherwise
/// (and for malformed bounds): use `packet_id_from_wire_unchecked`.
pub(crate) fn plain_packet_id(buf: &[u8], frame: &RoutingFrameInfo<'_>) -> Option<u64> {
    if frame.envelope.is_reliable || frame.envelope.has_reliable_header {
        return None;
    }
    packet_id_with_payload_at(buf, frame)
}

/// The packet ID from a parsed routing frame whose payload starts at its
/// `payload_offset`; `None` for compressed or encrypted payloads.
fn packet_id_with_payload_at(buf: &[u8], frame: &RoutingFrameInfo<'_>) -> Option<u64> {
    let data = admitted_data(buf).ok()?;
    if data.first()? & FLAGS_SIZED_PAYLOAD != 0 {
        return None;
    }
    let payload = data.get(frame.payload_offset..)?;
    Some(packet_identity_hash(
        &frame.envelope,
        frame.nonce,
        payload.len(),
        payload,
    ))
}

/// `plain_packet_id` for a frame that may carry a reliable header (not an
/// ACK-only one), as `packet_id_from_wire_unchecked` computes it.
pub(crate) fn framed_packet_id(buf: &[u8], frame: &RoutingFrameInfo<'_>) -> Option<u64> {
    if frame.ack_only() {
        return None;
    }
    packet_id_with_payload_at(buf, frame)
}

/// The packet ID hash: exactly as `Packet::packet_id()` computes it.
fn packet_identity_hash(envelope: &RoutingEnvelope<'_>, nonce: u16, dsz: usize, payload: &[u8]) -> u64 {
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15;

    // Compact source address.
    h = hash_bytes_u64(h, &envelope.source_address.to_le_bytes());

    // Stable numeric identity is independent of when schema names are learned.
    h = hash_bytes_u64(h, &envelope.ty.0.to_le_bytes());

    // Endpoints as string bytes, in ascending discriminant order.
    for ep in envelope.endpoints() {
        h = hash_bytes_u64(h, &ep.0.to_le_bytes());
    }

    // Timestamp + data_size as bytes
    h = hash_bytes_u64(h, &envelope.timestamp_ms.to_le_bytes());
    h = hash_bytes_u64(h, &nonce.to_le_bytes());
    h = hash_bytes_u64(h, &(dsz as u64).to_le_bytes());
    if envelope.time_epoch != 0 {
        h = hash_bytes_u64(h, &envelope.time_epoch.to_le_bytes());
    }

    // Payload bytes (logical payload)
    hash_bytes_u64(h, payload)
}

/// Type and source address from the first bytes of a frame, without
/// validating the rest of it.
fn prefix_type_and_source(buf: &[u8]) -> Option<(u32, u32)> {
    let mut reader = ByteReader::new(buf);
    if is_marker_byte(reader.read_bytes(1).ok()?[0]) {
        return None;
    }
    let ty = data_type_id_from_wire(read_uleb128(&mut reader).ok()?).ok()?;
    let source = u32::try_from(read_uleb128(&mut reader).ok()?).ok()?;
    Some((ty, source))
}

/// Read only the bounded type prefix for queue scheduling. This is deliberately
/// not frame validation: ingress verifies the CRC and dispatch the envelope.
/// Scanning an RX queue must not checksum every retained payload on each pass.
pub(crate) fn scheduling_type(buf: &[u8]) -> Option<DataType> {
    let mut reader = ByteReader::new(buf.get(..buf.len().min(12))?);
    if is_marker_byte(reader.read_bytes(1).ok()?[0]) {
        return None;
    }
    let id = data_type_id_from_wire(read_uleb128(&mut reader).ok()?).ok()?;
    // Scheduling reads identity, not registry membership. Dynamic/frozen wire
    // contracts may precede their schema, and authoritative parsing follows.
    // Avoid a redundant schema lookup for every retained queue item.
    Some(DataType(id))
}

/// Identify only a schema sender in a retained first chunk of a canonical
/// frame. This borrowed prefix inspection neither validates a complete
/// canonical CRC nor admits a packet, route, or schema.
pub(crate) fn chunked_schema_source(prefix: &[u8]) -> Option<u32> {
    let (ty, source) = prefix_type_and_source(prefix)?;
    (ty == DataType::DiscoverySchema.as_u32()).then_some(source)
}

pub(crate) fn peek_routing_envelope(buf: &[u8]) -> TelemetryResult<RoutingEnvelope<'_>> {
    Ok(routing_parts(verify_crc32(buf)?)?.0)
}

/// [`peek_routing_envelope`] for an admitted frame (CRC already verified).
pub(crate) fn peek_routing_envelope_unchecked(buf: &[u8]) -> TelemetryResult<RoutingEnvelope<'_>> {
    Ok(routing_parts(admitted_data(buf)?)?.0)
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

/// Borrow frozen target hashes from a Packet or its little-endian wire header.
/// Membership never allocates an owner array or changes the frozen cohort.
#[derive(Clone, Copy)]
pub(crate) enum TargetSenderSet<'a> {
    Hashes(&'a [u64]),
    Encoded(&'a [u8]),
}
impl<'a> TargetSenderSet<'a> {
    pub(crate) fn skip(self, count: usize) -> Self {
        match self {
            Self::Hashes(v) => Self::Hashes(v.get(count..).unwrap_or(&[])),
            Self::Encoded(v) => Self::Encoded(v.get(count.saturating_mul(8)..).unwrap_or(&[])),
        }
    }
    pub(crate) fn iter(self) -> impl Iterator<Item = u64> + 'a {
        let (hashes, encoded) = match self {
            Self::Hashes(v) => (v, &[][..]),
            Self::Encoded(v) => (&[][..], v),
        };
        hashes.iter().copied().chain(
            encoded
                .as_chunks::<8>()
                .0
                .iter()
                .map(|v| u64::from_le_bytes(*v)),
        )
    }
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            Self::Hashes(v) => v.is_empty(),
            Self::Encoded(v) => v.is_empty(),
        }
    }
    pub(crate) fn contains(&self, target: u64) -> bool {
        match self {
            Self::Hashes(v) => v.contains(&target),
            Self::Encoded(v) => v
                .as_chunks::<8>()
                .0
                .iter()
                .any(|bytes| u64::from_le_bytes(*bytes) == target),
        }
    }
}
impl<'a> RoutingEnvelope<'a> {
    pub(crate) fn target_sender_set(&self) -> TargetSenderSet<'a> {
        TargetSenderSet::Encoded(self.targets)
    }
}

pub(crate) struct RoutingFrameInfo<'a> {
    pub envelope: RoutingEnvelope<'a>,
    pub reliable: Option<ReliableHeader>,
    pub empty_payload: bool,
    /// Where the payload starts (after the envelope and any reliable header).
    payload_offset: usize,
    nonce: u16,
}
impl RoutingFrameInfo<'_> {
    pub fn ack_only(&self) -> bool {
        self.reliable
            .is_some_and(|header| header.flags & RELIABLE_FLAG_ACK_ONLY != 0)
    }
}

fn frame_info_from_parts<'a>(
    data: &'a [u8],
    envelope: RoutingEnvelope<'a>,
    header: &FrameHeader<'a>,
) -> RoutingFrameInfo<'a> {
    RoutingFrameInfo {
        envelope,
        reliable: header.reliable,
        empty_payload: header.size.unwrap_or(0) == 0 && data.len() == header.payload_off,
        payload_offset: header.payload_off,
        nonce: header.nonce,
    }
}

/// Borrow an uncompressed discovery payload without owning its envelope or bytes.
/// Sequenced, piggyback-ACK, compressed, targeted and encrypted frames retain normal processing.
/// The frame must be admitted: its CRC was verified at router ingress.
pub(crate) fn peek_plain_discovery_payload_unchecked(
    buf: &[u8],
    expected: DataType,
) -> TelemetryResult<Option<(u32, &[u8])>> {
    // Ordinary telemetry pays only this type peek. Its normal decode path
    // remains responsible for complete frame validation.
    if prefix_type_and_source(buf).is_none_or(|(ty, _)| ty != expected.as_u32()) {
        return Ok(None);
    }
    let data = admitted_data(buf)?;
    let (envelope, header) = routing_parts(data)?;
    if envelope.ty != expected
        || header.flags & FLAGS_SIZED_PAYLOAD != 0
        || envelope.target_senders().len() != 0
        || envelope
            .wire_shape
            .is_some_and(|shape| shape != crate::message_meta(expected).element)
    {
        return Ok(None);
    }
    if let Some(reliable) = header.reliable {
        // Only the normal unsequenced broadcast snapshot is a no-op. A
        // sequenced snapshot or piggyback ACK still needs reliable processing.
        if reliable.flags != RELIABLE_FLAG_UNSEQUENCED || reliable.seq != 0 || reliable.ack != 0 {
            return Ok(None);
        }
    }
    Ok(Some((envelope.source_address, &data[header.payload_off..])))
}

/// Fully validate a replaceable plaintext sample without owning its payload.
/// Contract/codec/reliable frames never enter freshness coalescing.
#[cfg(feature = "latest-value-egress")]
/// Latest-value candidates are router-held frames, verified at ingress.
pub(crate) fn peek_latest_plain_frame_info(buf: &[u8]) -> TelemetryResult<RoutingFrameInfo<'_>> {
    if buf.first().is_none_or(|flags| {
        flags & (FLAGS_SIZED_PAYLOAD | FLAG_RELIABLE_HEADER_PRESENT) != 0 || is_marker_byte(*flags)
    }) {
        return Err(TelemetryError::BadArg);
    }
    let data = admitted_data(buf)?;
    let (envelope, header) = routing_parts(data)?;
    // A shape or frozen targets are delivery obligations.
    if envelope.has_reliable_header
        || envelope.wire_shape.is_some()
        || !envelope.targets.is_empty()
        || envelope.endpoints().next().is_none()
    {
        return Err(TelemetryError::BadArg);
    }
    let meta =
        crate::config::try_get_message_meta(envelope.ty).ok_or(TelemetryError::InvalidType)?;
    Packet::validate_payload_against_element(meta.element, &data[header.payload_off..])?;
    Ok(frame_info_from_parts(data, envelope, &header))
}

/// Verifying variant, for tests that inspect raw frames. The router itself
/// verifies at ingress and then uses [`peek_routing_frame_info_unchecked`].
#[cfg(test)]
pub(crate) fn peek_routing_frame_info(buf: &[u8]) -> TelemetryResult<RoutingFrameInfo<'_>> {
    routing_frame_info(verify_crc32(buf)?)
}

/// [`peek_routing_frame_info`] for an admitted frame (CRC already verified).
pub(crate) fn peek_routing_frame_info_unchecked(
    buf: &[u8],
) -> TelemetryResult<RoutingFrameInfo<'_>> {
    routing_frame_info(admitted_data(buf)?)
}

fn routing_frame_info(data: &[u8]) -> TelemetryResult<RoutingFrameInfo<'_>> {
    let (envelope, header) = routing_parts(data)?;
    Ok(frame_info_from_parts(data, envelope, &header))
}

pub(crate) fn peek_frame_info_inner(data: &[u8]) -> TelemetryResult<TelemetryFrameInfo> {
    let (envelope, header) = routing_parts(data)?;
    Ok(TelemetryFrameInfo {
        envelope: envelope.into_owned(),
        reliable: header.reliable,
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
/// The offset is computed after walking the static header and the per-packet
/// fields. This matters because the contract can explicitly state that a
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
#[cfg(feature = "std")]
pub fn reliable_header_offset(buf: &[u8]) -> TelemetryResult<Option<usize>> {
    Ok(reliable_header_span(buf)?.map(|(off, _, _)| off))
}

pub(crate) fn reliable_header_span(
    buf: &[u8],
) -> TelemetryResult<Option<(usize, usize, ReliableHeader)>> {
    if buf.len() < CRC32_BYTES + 1 {
        return Err(TelemetryError::Unpack("short prelude"));
    }
    let header = parse_frame_header(&buf[..buf.len() - CRC32_BYTES])?;
    Ok(header
        .reliable
        .map(|hdr| (header.reliable_off, header.payload_off - header.reliable_off, hdr)))
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
/// - `Err(TelemetryError)` if the frame is malformed or the new header has a
///   different encoded size (use an owned rewrite then).
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
    if reliable_wire_size(hdr) != old_len {
        return Err(TelemetryError::Unpack(
            "reliable header rewrite changes wire size",
        ));
    }
    let data_len = buf.len() - CRC32_BYTES;
    let mut encoded = Vec::with_capacity(old_len);
    write_reliable_header_encoded(hdr, &mut encoded);
    buf[off..off + old_len].copy_from_slice(&encoded);
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
    let data_len = buf.len() - CRC32_BYTES;
    let hdr = ReliableHeader { flags, seq, ack };
    let mut out = Vec::with_capacity(data_len - old_len + reliable_wire_size(hdr) + CRC32_BYTES);
    out.extend_from_slice(&buf[..off]);
    write_reliable_header_encoded(hdr, &mut out);
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
/// This includes the flags byte and the type, source, epoch, timestamp and
/// nonce fields, but excludes the endpoint IDs, wire contract, logical size
/// (only carried for compressed or sealed payloads), reliable header, payload
/// bytes and CRC32 trailer.
///
/// # Parameters
/// - `pkt`: Packet to size.
///
/// # Returns
/// - Byte count of the packed metadata prefix.
pub fn header_size_bytes(pkt: &Packet) -> usize {
    let source_address = sender_address_u32(pkt.sender());
    1 + uleb128_size(pkt.data_type().as_u32() as u64)
        + uleb128_size(source_address as u64)
        + if pkt.time_epoch() != 0 {
            uleb128_size(u64::from(pkt.time_epoch()))
        } else {
            0
        }
        + uleb128_size(pkt.timestamp())
        + if pkt.nonce() != 0 {
            uleb128_size(pkt.nonce() as u64)
        } else {
            0
        }
}

/// Compute the full packed wire size for `pkt`.
///
/// This applies the same sender/payload compression heuristics as normal
/// packing, then sums the metadata prefix, optional endpoint IDs and frozen
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
    let contract_len = if shape.is_some() || !targets.is_empty() {
        contract_field_size(shape, targets)
    } else {
        0
    };
    let endpoint_len = if packet_endpoints_explicit(pkt, shape, targets) {
        endpoint_field_size(pkt.endpoints())
    } else {
        0
    };
    let (compressed, payload_wire) = payload_for_wire(pkt);
    let reliable_len = if is_reliable_type(pkt.data_type()) {
        reliable_wire_size(ReliableHeader {
            flags: RELIABLE_FLAG_UNSEQUENCED,
            seq: 0,
            ack: 0,
        })
    } else {
        0
    };
    // Match pack_packet, including its default unsequenced reliable header.
    // No frame/header allocation, payload copy or CRC scan is needed for sizing.
    header_size_bytes(pkt)
        + endpoint_len
        + contract_len
        + reliable_len
        + if compressed { uleb128_size(pkt.data_size() as u64) } else { 0 }
        + payload_wire.len()
        + CRC32_BYTES
}

#[inline]
/// Computes the same packet ID as [`Packet::packet_id`] directly from a packed wire frame.
pub fn packet_id_from_wire(buf: &[u8]) -> Result<u64, TelemetryError> {
    packet_id_from_data(verify_crc32(buf)?)
}

/// [`packet_id_from_wire`] for an admitted frame (CRC already verified).
#[inline]
pub(crate) fn packet_id_from_wire_unchecked(buf: &[u8]) -> Result<u64, TelemetryError> {
    packet_id_from_data(admitted_data(buf)?)
}

fn packet_id_from_data(data: &[u8]) -> Result<u64, TelemetryError> {
    // Reuse the validated borrowed envelope. Computing an ID must not build
    // owned endpoint/target arrays merely to hash or inspect their contents.
    let (envelope, header) = routing_parts(data)?;
    let flags = header.flags;
    let payload_is_compressed = (flags & FLAG_COMPRESSED_PAYLOAD) != 0;
    if header
        .reliable
        .is_some_and(|hdr| (hdr.flags & RELIABLE_FLAG_ACK_ONLY) != 0)
    {
        return Err(TelemetryError::Unpack("reliable control frame"));
    }
    let region = &data[header.payload_off..];
    let dsz = header.size.unwrap_or(region.len());

    // ---- payload bytes (must hash *logical* payload bytes) ----
    let payload_wire_owned;
    let payload_wire: &[u8] = if (flags & FLAG_E2E_ENCRYPTED_PAYLOAD) != 0 {
        let mut r = ByteReader::new(data);
        r.off = header.payload_off;
        payload_wire_owned = read_encrypted_payload(&mut r, &data[..header.payload_off], dsz)?;
        &payload_wire_owned
    } else {
        region
    };
    if payload_is_compressed && payload_wire.is_empty() {
        return Err(TelemetryError::Unpack("short buffer"));
    }
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
    Ok(packet_identity_hash(&envelope, header.nonce, dsz, payload_bytes))
}

mod payload_compression {
    use crate::TelemetryError;
    use alloc::borrow::Cow;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::config::runtime_payload_compress_threshold;
    use zstd_safe::CompressionLevel;

    /// Compress the given payload if it is beneficial to do so.
    /// # Arguments
    /// - `payload`: Original uncompressed payload bytes.
    /// # Returns
    /// - `(bool, Cow<[u8]>)`: Tuple where the first element indicates whether
    ///   compression was applied, and the second element is the resulting
    ///   payload bytes (compressed or original).
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
    pub fn decompress(compressed: &[u8], expected_len: usize) -> Result<Vec<u8>, TelemetryError> {
        let mut out = vec![0u8; expected_len];
        let written = zstd_safe::decompress(&mut out[..], compressed)
            .map_err(|_| TelemetryError::Unpack("decompression failed"))?;
        if written != expected_len {
            return Err(TelemetryError::Unpack("decompressed size mismatch"));
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "std"))]
mod envelope_memo_tests {
    use super::*;
    use crate::config::{
        register_data_type_id_with_description, register_endpoint_with_description,
        remove_data_type,
    };


    fn endpoint(name: &str) -> DataEndpoint {
        DataEndpoint::try_named(name).unwrap_or_else(|| {
            register_endpoint_with_description(name, "memo test endpoint", false).unwrap()
        })
    }

    fn owned(bytes: &[u8]) -> TelemetryEnvelope {
        peek_routing_envelope_unchecked(bytes).unwrap().into_owned()
    }

    /// Repeated parses of one header are served by the memo, and match an
    /// uncached parse field for field, over any buffer holding those bytes.
    #[test]
    fn memoized_envelopes_match_uncached_parses() {
        crate::tests::ensure_common_test_schema();
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 2.0, 3.0],
            &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
            1_234,
        )
        .unwrap();
        let first = pack_packet(&pkt);
        let copy: Vec<u8> = first.to_vec();
        let uncached = {
            let data = admitted_data(&first).unwrap();
            let header = parse_frame_header(data).unwrap();
            let derived = static_envelope(data, &header).unwrap();
            assert!(derived.schema_endpoints.is_none() && derived.wire_shape.is_none());
            routing_parts(data).unwrap().0.into_owned()
        };
        assert_eq!(owned(&first), uncached);
        assert_eq!(owned(&first), uncached, "second parse is a memo hit");
        assert_eq!(owned(&copy), uncached, "content, not buffer identity, is the key");
        let info = peek_routing_frame_info_unchecked(&copy).unwrap();
        assert_eq!(info.envelope.into_owned(), uncached);
        assert_eq!(packet_id_from_wire(&copy).unwrap(), pkt.packet_id());
        // A different timestamp shares the static header (and its memo).
        let later = pack_packet(
            &Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[1.0, 2.0, 3.0],
                &[DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")],
                1_235,
            )
            .unwrap(),
        );
        assert_eq!(owned(&later).timestamp_ms, 1_235);
        assert_eq!(owned(&first).timestamp_ms, 1_234);
    }

    /// Any schema change retires memoized envelopes, even for byte-identical
    /// frames: parse results depend on schema lookups (schema-derived
    /// endpoints, bitmap validation).
    #[test]
    fn schema_changes_retire_memoized_envelopes() {
        crate::tests::ensure_common_test_schema();
        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[4.0, 5.0, 6.0],
            &[DataEndpoint::named("SD_CARD")],
            9_876,
        )
        .unwrap();
        let bytes = pack_packet(&pkt);
        let full = admitted_data(&bytes).unwrap();
        let data = &full[..parse_frame_header(full).unwrap().static_end];
        // Tests in other threads may change the schema concurrently; retry
        // until a parse and its lookup share one generation.
        let before = (0..1000)
            .find_map(|_| {
                let _ = owned(&bytes);
                let generation = crate::config::schema_generation();
                envelope_memo::lookup(data, generation).map(|_| generation)
            })
            .expect("parse was memoized");
        let id = DataType(0x7a11);
        let _ = remove_data_type(id);
        register_data_type_id_with_description(
            id,
            "MEMO_TEST_TYPE",
            "memo test type",
            MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
            &[endpoint("MEMO_TEST_ENDPOINT")],
            crate::ReliableMode::None,
            1,
        )
        .unwrap();
        let after = crate::config::schema_generation();
        assert!(after.wrapping_sub(before) >= 1, "registration advances the schema generation");
        assert!(envelope_memo::lookup(data, after).is_none(), "a stale entry was reused");
        assert_eq!(owned(&bytes).timestamp_ms, 9_876);
        let removed = crate::config::schema_generation();
        assert!(remove_data_type(id).unwrap());
        assert_ne!(crate::config::schema_generation(), removed, "removal advances it too");
    }
}

#[cfg(test)]
mod endpoint_decode_tests {
    use super::*;

    /// The time-base epoch is a flagged header field: absent for epoch 0,
    /// round-tripped with and without a delivery contract, folded into packet
    /// identity on both the decoded and the wire path, visible to envelope
    /// peeks, sized exactly, carried through compact bundles, and a present
    /// zero is malformed.
    #[test]
    fn time_epoch_round_trips_in_the_header() {
        let ep = message_meta(DataType::TimeSyncAnnounce).endpoints_ref()[0];
        let plain = Packet::new_with_nonce(
            DataType::TimeSyncAnnounce,
            &[ep],
            "GS",
            1_793_000_000_000,
            77,
            crate::router::encode_slice_le(&[5u64, 6]),
        )
        .unwrap();
        let bytes = pack_packet(&plain);
        assert_eq!(bytes[0] & FLAG_TIME_EPOCH, 0, "epoch 0 adds nothing");
        assert_eq!(unpack_packet(&bytes).unwrap().time_epoch(), 0);
        let mut ids = alloc::collections::BTreeSet::new();
        for epoch in [1u16, 127, 128, 300, crate::packet::MAX_TIME_EPOCH] {
            let pkt = plain.clone().with_time_epoch(epoch);
            let bytes = pack_packet(&pkt);
            assert_ne!(bytes[0] & FLAG_TIME_EPOCH, 0);
            assert_eq!(bytes[0] & FLAG_WIRE_CONTRACT, 0, "an epoch alone is no contract");
            assert_eq!(bytes.len(), packet_wire_size(&pkt));
            let back = unpack_packet(&bytes).unwrap();
            assert_eq!(back.time_epoch(), epoch);
            assert_eq!(back.timestamp(), pkt.timestamp());
            assert_eq!(back.packet_id(), pkt.packet_id());
            assert_eq!(packet_id_from_wire(&bytes).unwrap(), pkt.packet_id());
            assert_eq!(peek_envelope(&bytes).unwrap().time_epoch, epoch);
            assert!(peek_envelope(&bytes).unwrap().target_senders.is_empty());
            assert!(ids.insert(pkt.packet_id()), "epoch is part of identity");
        }
        assert!(!ids.contains(&plain.packet_id()));

        // With a frozen delivery contract (shape and targets).
        let frozen = Packet::new_with_wire_contract(
            DataType::ReliableAck,
            message_meta(DataType::ReliableAck).endpoints_ref(),
            "E2EACK:GS",
            100,
            1,
            Arc::from(42u64.to_le_bytes()),
            Some(MessageElement::Static(2, crate::MessageDataType::UInt32, crate::MessageClass::Data)),
            Arc::from([123u64, 456]),
        )
        .unwrap()
        .with_time_epoch(9);
        let bytes = pack_packet(&frozen);
        assert_eq!(bytes.len(), packet_wire_size(&frozen));
        let back = unpack_packet(&bytes).unwrap();
        assert_eq!(back.time_epoch(), 9);
        assert_eq!(back.wire_target_senders(), &[123, 456]);
        assert_eq!(back.packet_id(), frozen.packet_id());
        assert_eq!(packet_id_from_wire(&bytes).unwrap(), frozen.packet_id());

        // Compact bundles rebuild the canonical frames byte for byte.
        let a = pack_packet(&plain.clone().with_time_epoch(3));
        let b = pack_packet(&frozen);
        let c = pack_packet(&plain);
        let bundle = crate::wire_bundle::pack_bundle(&[&a, &b, &c]).unwrap();
        let frames = crate::wire_bundle::unpack_bundle_frames(&bundle).unwrap();
        assert_eq!(frames, vec![a.to_vec(), b.to_vec(), c.to_vec()]);
        // Consecutive epoch-only contracts (the second one elided), a
        // two-byte epoch, and a full contract between them.
        let a2 = pack_packet(&plain.clone().with_time_epoch(3).with_nonce(78));
        let d = pack_packet(&plain.clone().with_time_epoch(200));
        let bundle = crate::wire_bundle::pack_bundle(&[&a, &a2, &d, &b, &a]).unwrap();
        let frames = crate::wire_bundle::unpack_bundle_frames(&bundle).unwrap();
        assert_eq!(frames, vec![a.to_vec(), a2.to_vec(), d.to_vec(), b.to_vec(), a.to_vec()]);
        // The side transport reads past an epoch-only contract.
        for frame in [&a, &d] {
            assert!(crate::side_transport::extract_side_header_template(frame).is_ok());
        }

        // The epoch follows the type and source: one byte below epoch 128.
        let c = pack_packet(&plain);
        let one = pack_packet(&plain.clone().with_time_epoch(1));
        assert_eq!(one.len(), c.len() + 1, "a step costs one byte below epoch 128");
        assert_eq!(pack_packet(&plain.clone().with_time_epoch(128)).len(), c.len() + 2);
        let at = 1 + uleb128_size(u64::from(DataType::TimeSyncAnnounce.as_u32()))
            + uleb128_size(u64::from(sender_address_u32("GS")));
        assert_eq!(one[at], 1);
        // A present zero epoch is malformed.
        let mut zero = one[..one.len() - 4].to_vec();
        zero[at] = 0;
        append_crc32(&mut zero);
        assert!(unpack_packet(&zero).is_err());
        assert!(peek_envelope(&zero).is_err());
    }

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
        assert_eq!(scheduling_type(&[0, 0x80]), None);
        let mut overlong = [0xffu8; 1024];
        overlong[0] = 0x1f;
        assert_eq!(scheduling_type(&overlong), None);
        assert_eq!(scheduling_type(&[0x60, 1]), None, "side-transport kinds have no type");
        assert_eq!(scheduling_type(&[]), None);
        let unknown_prefix = [0, 0xff, 0xff, 0xff, 0xff, 0x0f];
        assert_eq!(scheduling_type(&unknown_prefix), Some(DataType(u32::MAX)));
        assert!(peek_routing_envelope(&unknown_prefix).is_err());
        assert!(unpack_packet(&unknown_prefix).is_err());
    }

    #[test]
    fn receipt_contract_omits_redundant_builtin_endpoints() {
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
            assert_eq!(packed[0] & FLAG_ENDPOINTS_MASK, 0);
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
            // An explicit endpoint is one ID with no count.
            let explicit = pack_packet(&make(&[DataEndpoint::Discovery]));
            assert_eq!(explicit[0] & FLAG_ENDPOINTS_MASK, ENDPOINTS_ONE);
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
        let header_end = parse_frame_header(data).unwrap().static_end;
        for end in 0..header_end {
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
    #[cfg(feature = "std")]
    fn endpoint_encodings_round_trip_and_reject_noncanonical_lists() {
        crate::tests::ensure_common_test_schema();
        let two = [DataEndpoint::named("SD_CARD"), DataEndpoint::named("RADIO")];
        for eps in [&two[..1], &two[..]] {
            let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], eps, 5).unwrap();
            let bytes = pack_packet(&pkt);
            assert_eq!(
                bytes[0] & FLAG_ENDPOINTS_MASK,
                if eps.len() == 1 { ENDPOINTS_ONE } else { ENDPOINTS_LIST }
            );
            assert_eq!(bytes.len(), packet_wire_size(&pkt));
            let back = unpack_packet(&bytes).unwrap();
            assert_eq!(back.packet_id(), pkt.packet_id());
            assert_eq!(packet_id_from_wire(&bytes).unwrap(), pkt.packet_id());
        }
        // A counted list of one ID is not canonical (0x20 encodes it).
        let pkt = Packet::from_f32_slice(DataType::named("GPS_DATA"), &[1.0, 2.0, 3.0], &two[..1], 5).unwrap();
        let bytes = pack_packet(&pkt);
        let data = &bytes[..bytes.len() - 4];
        let header = parse_frame_header(data).unwrap();
        let id_at = header.static_end - header.endpoint_list.unwrap().len();
        let mut listed = alloc::vec![(data[0] & !FLAG_ENDPOINTS_MASK) | ENDPOINTS_LIST];
        listed.extend_from_slice(&data[1..id_at]);
        listed.push(1);
        listed.extend_from_slice(&data[id_at..]);
        append_crc32(&mut listed);
        assert!(unpack_packet(&listed).is_err());
        // Both endpoint bits set is a side-transport marker, never a frame.
        let mut marker = data.to_vec();
        marker[0] |= FLAG_ENDPOINTS_MASK;
        append_crc32(&mut marker);
        assert!(unpack_packet(&marker).is_err());
        assert!(peek_envelope(&marker).is_err());
    }
}

#[cfg(test)]
mod bootstrap_compression_tests {
    use super::*;

    #[test]
    fn bootstrap_payloads_remain_decodable_without_optional_compression() {
        let payload: Arc<[u8]> = Arc::from(alloc::vec![b'A'; 4096]);
        assert!(payload_compression::compress_if_beneficial(&payload).0);
        for ty in [
            DataType::DiscoverySchema,
            DataType::DiscoveryTopology,
            DataType::ManagedVariableValue,
        ] {
            let packet =
                Packet::new(ty, &[DataEndpoint::Discovery], "HOST", 123, payload.clone()).unwrap();
            let wire = pack_packet(&packet);
            assert_eq!(wire[0] & FLAG_COMPRESSED_PAYLOAD, 0, "{ty:?}");
            assert_eq!(packet_wire_size(&packet), wire.len());
            assert_eq!(unpack_packet(&wire).unwrap().payload(), payload.as_ref());
        }
    }

    #[test]
    fn ordinary_data_keeps_optional_payload_compression() {
        let payload: Arc<[u8]> = Arc::from(alloc::vec![b'A'; 4096]);
        let packet = Packet::new(
            DataType::TelemetryError,
            &[DataEndpoint::TelemetryError],
            "HOST",
            123,
            payload.clone(),
        )
        .unwrap();
        let wire = pack_packet(&packet);
        assert_ne!(wire[0] & FLAG_COMPRESSED_PAYLOAD, 0);
        assert_eq!(packet_wire_size(&packet), wire.len());
        assert_eq!(unpack_packet(&wire).unwrap().payload(), payload.as_ref());
    }
}
