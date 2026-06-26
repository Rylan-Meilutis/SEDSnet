# Wire Format (Technical)

This page documents the compact v2 wire format implemented in
src/wire_format.rs ([source](https://github.com/Rylan-Meilutis/sedsnet/blob/main/src/wire_format.rs)).

## Goals

- Compact prelude with a fixed 2-byte start.
- ULEB128 integers for small-on-the-wire metadata.
- Endpoint bitmaps instead of repeated endpoint IDs.
- Optional sender and payload compression.
- CRC32 trailer for frame integrity.
- Defer stable context such as sender names, route owners, endpoint names, schema metadata, and
  link capabilities to discovery whenever it is safe to do so.
- A compact in-flight wire contract so packets already on the wire remain routable and decodable
  while topology and runtime-schema changes are still propagating.

## Frame layout

```text
[FLAGS: u8]
    bit0: payload compressed
    bit1: sender compressed
    bit2: wire contract present
    bit3: packet nonce present
    bit4: E2E encrypted payload wrapper present
    bit5..7: reserved
[NEP: u8]                         // number of set bits in the endpoint bitmap
VARINT(ty: u32 as u64)            // ULEB128
VARINT(data_size: u64)            // logical payload size after decompression
VARINT(timestamp_ms: u64)
[VARINT(nonce: u16 as u64)]       // only when bit3 is set
VARINT(sender_len: u64)           // logical sender length after decompression
[VARINT(sender_wire_len: u64)]    // only when sender is compressed
ENDPOINT_BITMAP                   // fixed width, 1 bit per possible endpoint ID
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
each intended board can decrypt the same payload. Any board that changes visible routing metadata or
ciphertext invalidates the AEAD tag for the other boards.

Reliable-header flags:

- `0x01`: ACK-only reliable control frame
- `0x02`: reliable but unordered
- `0x80`: unsequenced best-effort reliable wrapper

ACK-only reliable control frames are emitted by the router or relay reliable layer. They are not
valid application `Packet` values and are consumed before normal packet deserialization.

## Endpoint bitmap

The endpoint bitmap is fixed-width for the build, not sized from the currently registered runtime
schema.

- `EP_BITMAP_BITS = MAX_VALUE_DATA_ENDPOINT + 1`
- `EP_BITMAP_BYTES = ceil(EP_BITMAP_BITS / 8)`

Packing is LSB-first within each byte. `NEP` is the popcount of the bitmap and is used as a sanity
check during decode.

Important implications:

- The bitmap width is stable for a given build.
- Removing or adding runtime schema entries does not change bitmap width.
- New packets use the current endpoint IDs, but old packets still parse because the bitmap layout is
  fixed and the contract can carry extra delivery/decode metadata when needed.

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

This lets a packet remain decodable after runtime schema changes such as:

- the current type layout changing
- the type being removed from the local runtime registry

In those cases deserialization constructs the `Packet` against the inline wire shape instead of the
current registry definition.

### Frozen destination sender hashes

The target list contains `u64` sender hashes for the destination holders the source intended when
that packet was packed.

Routers and relays use that list to:

- keep in-flight packets pointed only at the intended holders
- avoid delivering a packet to the wrong board while discovery/topology updates are still
  converging
- allow new packets to immediately use the latest topology while old packets continue with the
  original delivery contract

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

Those are router/relay-owned control packets. Applications should not model them as user endpoint
traffic.

## Side Transport Wrappers

Routers and relays can add a side-local wrapper around packed frames for constrained links. This
wrapper is not part of the application `Packet`; it is consumed by `rx_packed_from_side(...)`
before normal deserialization.

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
side-transport frame and then resumes normal packet processing. This keeps CAN/I2C-style frame
limits transparent to endpoint handlers and packet-oriented APIs.

## Header Minimization

The current implementation reduces repeated overhead with ULEB metadata, fixed endpoint bitmaps,
sender IDs/hashes, side-local header templates, and fixed-size side splitting. The first packet on
a side remains self-describing enough to establish context; follow-up packets on constrained links
can replace repeated type/endpoint/sender/contract fields with a compact template ID.

The practical target is:

- **canonical full frame**: self-describing, migration-safe, and suitable for recovery after peer
  restart or lost side context
- **discovery-deferred steady-state frame**: carries only the critical per-packet fields that cannot
  be inferred from current discovery state, such as type ID, endpoint bitmap or compact route
  selector, timestamp/nonce when needed, reliability/crypto flags, payload length, payload bytes, and
  integrity/authentication data
- **compact side-transport follow-up frame**: IPv6-like overhead target by default, with an
  IPv4-like target available for stable tiny telemetry streams

Routers and relays expose this as a per-side compact-header target. `with_small_packet_transport`
sets the default target to 40 bytes, and `with_ipv4_like_compact_header_target` sets a 20-byte
profiling target. The target is not a hard parser rule; it is a deployment contract to validate
against runtime stats while preserving canonical packet reconstruction before normal routing,
dedupe, reliability, E2E ACK, and payload-decryption behavior.

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

For small stable telemetry such as a single template carrying changing timestamp/nonce/payload,
the compact follow-up path is expected to fit the IPv4-like 20-byte overhead target. Larger
contracts, reliable sequence/ACK fields, E2E wrappers, chunking, or changing header shapes can push
overhead toward the IPv6-like target or require a fresh full template frame.

Side-local template dictionaries are bounded by `max_side_transport_templates`, which defaults to
64 entries per side. When the dictionary is full, the sender or receiver evicts a deterministic
entry and later refreshes that shape with a full template frame. This keeps compact-link state
bounded and makes template memory visible through the same runtime stats used to tune queue,
reliability, discovery, and cache budgets.

The intended next protocol-level header-reduction path is to add discovered router addresses as a
canonical wire identity and treat the current sender string as a discovery hostname. In that model,
discovery owns the address-to-sender-name mapping, endpoint/schema names, route capabilities, and
stable link profile metadata. Steady-state packet headers should then carry a compact source address
and only the per-packet fields that are safety-critical to route, dedupe, decrypt, verify, and unpack
the payload. A peer that has lost discovery context can request or receive a full discovery/schema
refresh, and a sender can fall back to the canonical full frame or side-template refresh when
discovery state is stale.

That needs a wire-versioned migration because sender strings are currently part of packet identity,
discovery topology, reliable return-path learning, E2E ACK tracking, crypto authenticated header
data, and the C/Python API surface. Until that protocol version exists, side-local templates are the
supported way to replace repeated sender/type/endpoint header fields on constrained links.

Full discovery snapshots also send `SEDSNET_DISCOVERY_LINK_CAPABILITIES` on each side. Its payload
is fixed-width: version `u8`, capability flags `u32`, profile code `u8`, max frame bytes `u32`,
compact-header target bytes `u32`, and max side templates `u32`, all little-endian except the
single-byte fields. The flags advertise header templates, chunking, hop reliability, crypto support,
end-to-end reliability support, and unchanged compact timestamp omission. Profile codes are `0`
canonical, `1` template, `2` IPv6-like, and `3` IPv4-like.

Further compatible reductions should use negotiated per-side context rather than removing fields
globally:

- stream/context profiles that omit sender, endpoints, and type when unchanged
- single-endpoint route contracts that omit the endpoint bitmap on links where the route fixes it
- small-payload opcodes for common static shapes such as three `f32` values or one `u8` state
- grouped ACK/reliability metadata and optional aggregation of several tiny values into one
  authenticated frame on very low-bandwidth links
- E2E overhead amortization by sealing multiple tiny payloads under one AEAD tag when latency
  policy allows it

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
3. Expand the fixed-width endpoint bitmap.
4. Decode sender bytes.
5. Decode the optional wire contract.
6. Decode the reliable header if current schema or contract says it is present.
7. Decode the payload bytes.
8. Construct `Packet::new_with_wire_contract(...)`.

The contract is what keeps decode and delivery stable across runtime topology/schema churn.

## Envelope peek

`peek_envelope(...)` parses only the envelope and returns:

- `ty`
- `endpoints`
- `sender`
- `timestamp_ms`
- `wire_shape`
- `target_senders`

`peek_frame_info(...)` extends that with the reliable header when present.

These helpers are what the router and relay use to make routing and reliable-layer decisions without
fully decoding payload data.

## Packet ID from wire

`packet_id_from_wire(...)` computes the same ID as `Packet::packet_id()` from a packed frame.
It hashes:

- sender bytes after decompression
- message name
- endpoint names in ascending bitmap order
- timestamp
- logical payload size
- payload bytes after decompression

This makes dedupe stable across compressed and uncompressed links.

The wire contract is intentionally not part of the packet ID. It preserves delivery/decode intent
for in-flight packets without changing duplicate detection for the underlying telemetry payload.

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
