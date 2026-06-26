# Wire Format (Technical)

This page documents the compact v2 wire format implemented in
src/wire_format.rs ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/src/wire_format.rs)).

## Public API Names

The wire-format module is named `wire_format`; the former generic encoding module path is not part
of the API.

Rust callers use:

- `sedsnet::wire_format::pack_packet(...)`
- `sedsnet::wire_format::unpack_packet(...)`
- `sedsnet::wire_format::pack_packet_with_reliable(...)`
- `sedsnet::wire_format::pack_reliable_ack(...)`
- `sedsnet::wire_format::peek_envelope(...)`
- `sedsnet::wire_format::peek_frame_info(...)`
- `sedsnet::wire_format::packet_wire_size(...)`

Python callers use:

- `Packet.pack()`
- `unpack_packet_py(...)`
- `peek_header_py(...)`

C/C++ callers use the packed-wire names:

- `seds_pkt_pack_len(...)`
- `seds_pkt_pack(...)`
- `seds_pkt_unpack_owned(...)`
- `seds_pkt_unpack_header_owned(...)`
- `seds_pkt_validate_packed(...)`
- packed side APIs such as `seds_router_add_side_packed(...)`,
  `seds_router_rx_packed_packet_to_queue(...)`, and `seds_relay_rx_packed_from_side(...)`

These functions pack and unpack SEDSnet protocol frames.

## Frame layout

```text
[FLAGS: u8]
    bit0: payload compressed
    bit1: sender compressed
    bit2: wire contract present
    bit3: packet nonce present
    bit4: E2E encrypted payload wrapper present
    bit5: endpoint bitmap present
    bit6..7: reserved
[NEP: u8]                         // number of selected endpoints
VARINT(ty: u32 as u64)            // ULEB128
VARINT(data_size: u64)            // logical payload size after decompression
VARINT(timestamp_ms: u64)
[VARINT(nonce: u16 as u64)]       // only when bit3 is set
VARINT(sender_len: u64)           // logical sender length after decompression
[VARINT(sender_wire_len: u64)]    // only when sender is compressed
[ENDPOINT_BITMAP]                 // only when bit5 is set
SENDER_BYTES                      // raw or compressed
[VARINT(contract_len: u64)]       // only when bit2 is set
[WIRE_CONTRACT_BYTES]
[RELIABLE_HEADER]                 // present for reliable schema types or when contract says so
PAYLOAD_BYTES                     // raw/compressed, or E2E wrapper around those bytes
[CRC32: u32 LE]                   // checksum of every prior byte in the frame
```

## Flags

Top-level frame flags:

- `0x01`: payload compressed
- `0x02`: sender compressed
- `0x04`: wire contract present
- `0x08`: packet nonce present
- `0x10`: payload bytes are wrapped by the feature-gated E2E cryptography provider
- `0x20`: endpoint bitmap present

When `0x10` is set, routing metadata remains visible, but the payload region is:

```text
VARINT(key_id)
VARINT(plaintext_wire_payload_len)
VARINT(nonce_len)
NONCE_BYTES
VARINT(tag_len)
TAG_BYTES
CIPHERTEXT_BYTES
```

The authenticated data passed to the cryptography provider is the packed frame prefix through the optional
reliable header, excluding the payload wrapper and CRC. Unpackers built without `cryptography`
reject frames with `0x10` rather than exposing ciphertext as application data.

For multi-board endpoints, a sender can use an application-managed endpoint/group traffic key so
each listed board can decrypt the same payload. Any board that changes visible routing metadata or
ciphertext invalidates the AEAD tag for the other boards.

Reliable-header flags:

- `0x01`: ACK-only reliable control frame
- `0x02`: reliable but unordered
- `0x80`: unsequenced best-effort reliable wrapper

ACK-only reliable control frames are emitted by the router or relay reliable layer. They are not
valid application `Packet` values and are consumed before normal packet unpacking.

## Endpoint bitmap

`NEP` is the number of selected endpoints for the frame.

When flag `0x20` is clear, no endpoint bitmap bytes are present. The endpoint set is the default
endpoint set from the local data type metadata for `ty`, expanded in ascending endpoint-ID order,
and `NEP` must match that set size.

When flag `0x20` is set, a fixed-width endpoint bitmap follows the sender length fields and appears
before `SENDER_BYTES`. This form is used for custom endpoint sets, subsets, ACK-only reliable
control frames, wire-contract frames, and frames whose endpoints cannot be inferred from the data
type metadata.

- `EP_BITMAP_BITS = MAX_VALUE_DATA_ENDPOINT + 1`
- `EP_BITMAP_BYTES = ceil(EP_BITMAP_BITS / 8)`

Bitmap packing is LSB-first within each byte. `NEP` is the popcount of the bitmap and is used as a
sanity check during decode.

The bitmap width is stable for a given build. Adding or removing runtime schema entries does not
change the bitmap width.

## Wire contract

When `FLAG_WIRE_CONTRACT` is set, the frame carries a compact contract immediately after the sender
bytes.

```text
VARINT(contract_len)
[contract flags: u8]
[wire shape bytes]                // if contract flag 0x02 set
[target count: ULEB128]           // if contract flag 0x01 set
[target sender hash 0: u64 LE]
[target sender hash 1: u64 LE]
...
```

Contract flags:

- `0x01`: explicit frozen destination sender hashes are present
- `0x02`: inline payload shape is present
- `0x04`: a reliable header is present even if current schema lookup would no longer imply that

### Inline payload shape

The shape is packed compactly:

```text
[packed: u8]
    bits 0..3: MessageDataType code
    bits 4..5: MessageClass code
    bit 6: static-layout flag
[static_count: ULEB128]           // only when bit 6 is set
```

When present, the inline shape is used to construct the `Packet` instead of the current registry
definition.

### Frozen destination sender hashes

The target list contains `u64` sender hashes for destination holders. Routers and relays use this
list as an explicit destination set for the packed frame.

## Reliable header

The reliable header is a fixed 9-byte block:

```text
[REL_FLAGS: u8]
[SEQ: u32 LE]
[ACK: u32 LE]
```

For normal reliable data frames this header appears after the optional wire contract.

Reliable control traffic now primarily uses built-in internal packet types such as:

- `ReliableAck`
- `ReliablePartialAck`
- `ReliablePacketRequest`

Those are router/relay-owned control packets, not user endpoint traffic.

## Side Transport Wrappers

Routers and relays can add a side-local wrapper around packed frames for constrained links. This
wrapper is not part of the application `Packet`; it is consumed by `rx_packed_from_side(...)`
before normal unpacking.

```text
[magic: "SDT"]
[kind: u8]
[body bytes]
[CRC32: u32 LE]                   // checksum of magic + kind + body
```

Kinds:

- `0x01`: full packed frame plus a side-local ULEB template id
- `0x02`: compact frame using a previously learned side-local template id
- `0x03`: ordered chunk of a full or compact side-transport frame
- `0x04`: compact frame using a template id plus timestamp delta from the previous frame for that
  template
- `0x05`: compact frame using a template id and the unchanged previous timestamp for that template

Router packed sides support header-template reuse with
`Router::add_side_packed_small_packets(...)` or
`RouterSideOptions::with_small_packet_transport(...)`. The first stable header shape is sent as a
full `SDT` frame and assigns a compact side-local ULEB template id. Later packets with the same
static header shape can use kind `0x02`, replacing repeated type/endpoint/sender/contract bytes with
that template id plus the fields that still vary per packet. When the previous timestamp for that
template is known and the nonnegative delta is smaller than the full timestamp varint, the sender
uses kind `0x04` and carries the timestamp delta instead. When unchanged-timestamp omission is
enabled and the timestamp is identical to the previous frame for that template, the sender uses kind
`0x05` and omits the timestamp field entirely. Omission can be enabled side-wide, by the IPv4-like
profile, or for selected data types on a mixed link.

Python and C bindings expose the same profiles through `add_side_packed_profile(...)` and
`seds_*_add_side_packed_profile(...)`. `ipv6_like` uses a 40-byte compact-header profiling
target; `ipv4_like` uses a 20-byte target and enables unchanged-timestamp omission.

Router and relay packed sides both support bounded frame sizes. Relay small-packet sides use the
same side-local template id compaction when `max_frame_bytes` is non-zero. When the side-transport
frame is too large, the sender emits kind `0x03` chunks whose individual callback payloads do not
exceed the configured maximum. The receiver reassembles those chunks into the original
side-transport frame and then resumes normal packet processing.

## Compact Side Profiles

Routers and relays expose per-side compact-header profiles. `with_small_packet_transport` sets the
compact-header profile to `ipv6_like`; `with_ipv4_like_compact_header_target` sets it to
`ipv4_like`.

Each side also exports an effective side-transport profile:

- `canonical`: no side-transport wrapping is needed
- `template`: template reuse is enabled without an IPv4/IPv6-size target
- `ipv6_like`: compact follow-up frames are profiled against a 40-byte target
- `ipv4_like`: compact follow-up frames are profiled against a 20-byte target and omit unchanged
  compact timestamps

Runtime stats report:

- whether header templates are enabled on each side
- max fixed-frame size
- compact-header target bytes
- effective side-transport profile
- maximum retained side-local templates
- full, compact, timestamp-delta compact, unchanged-timestamp compact, and chunk side-transport
  frame counts
- raw canonical bytes, emitted side-transport bytes, and bytes saved
- minimum and maximum compact follow-up overhead bytes
- compact-header target misses
- active TX/RX template counts and template evictions

Side-local template dictionaries are bounded by `max_side_transport_templates`, which defaults to
64 entries per side. When the dictionary is full, the sender or receiver evicts a deterministic
entry and later refreshes that shape with a full template frame.

## Discovery Link Capabilities

Full discovery snapshots also send `SEDSNET_DISCOVERY_LINK_CAPABILITIES` on each side.

Payload:

```text
[version: u8]
[capability_flags: u32 LE]
[profile_code: u8]
[max_frame_bytes: u32 LE]
[compact_header_target_bytes: u32 LE]
[max_side_templates: u32 LE]
```

Capability flags advertise:

- header templates
- chunking
- hop reliability
- crypto support
- end-to-end reliability support
- unchanged compact timestamp omission

Profile codes:

- `0`: canonical
- `1`: template
- `2`: IPv6-like
- `3`: IPv4-like

## Varints

All integer metadata fields use unsigned LEB128.

This includes:

- type ID
- payload size
- timestamp
- sender lengths
- contract length
- target count
- static wire-shape count

`read_uleb128` rejects values that require more than 10 bytes.

## Compression

Sender and payload compression are evaluated independently.

- Compression is only used when it is actually smaller on the wire.
- The logical uncompressed length is still transmitted in the frame metadata.
- Decode validates the decompressed size against that logical length.

Compressed sender and payload bytes use the crate's `payload_compression` backend.

## Decode flow

High-level decode order:

1. Verify CRC32.
2. Parse the fixed prelude and varints.
3. Resolve endpoints from the fixed-width endpoint bitmap when flag `0x20` is set, otherwise from
   the default endpoint list in local data type metadata.
4. Decode sender bytes.
5. Decode the optional wire contract.
6. Decode the reliable header if current schema or contract says it is present.
7. Decode the payload bytes.
8. Construct `Packet::new_with_wire_contract(...)`.

The optional wire contract provides the inline shape and target sender hashes used during unpacking
and routing.

## Envelope peek

`peek_envelope(...)` parses only the envelope and returns:

- `ty`
- `endpoints`
- `sender`
- `timestamp_ms`
- `wire_shape`
- `target_senders`

`peek_frame_info(...)` extends that with the reliable header when present.

Routers and relays use these helpers for routing and reliable-layer decisions without fully decoding
payload data.

## Packet ID from wire

`packet_id_from_wire(...)` computes the same ID as `Packet::packet_id()` from a packed frame.
It hashes:

- sender bytes after decompression
- message name
- endpoint names in ascending bitmap order
- timestamp
- logical payload size
- payload bytes after decompression

The wire contract is not part of the packet ID.

## CRC32 trailer

Every frame ends with a 4-byte little-endian CRC32 computed over all preceding bytes.

On CRC failure the frame is rejected before normal decode. Recovery behavior after that depends on
whether the surrounding router/relay reliable layer is active for that hop.

## Common decode failures

- short prelude or short read
- CRC32 mismatch
- invalid endpoint bit set
- malformed or overlong ULEB128
- bad wire-shape type/class/count
- malformed wire-contract target list
- reliable control frame passed into full packet decode
- decompression failure or decompressed-size mismatch
- sender not valid UTF-8
