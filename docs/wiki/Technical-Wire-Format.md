# Wire Format (Technical)

This page documents the SEDSnet 7 wire format implemented in
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

SEDSnet 7 canonical frame (the end-to-end form every router stores and forwards):

```text
[FLAGS: u8]
    0x01: payload compressed            (logical size field present)
    0x02: reliable header present
    0x04: wire contract present         (inline shape and/or frozen targets)
    0x08: packet nonce present
    0x10: E2E-sealed payload            (logical size field present)
    0x60: endpoint encoding
          0x00 schema default, 0x20 exactly one ID, 0x40 counted list,
          0x60 never a canonical frame (side-transport kinds, see below)
    0x80: time-base epoch present
VARINT(type)
VARINT(source address)
[VARINT(time epoch)]                    // flag 0x80, 1..=65534
[VARINT(endpoint count)]                // encoding 0x40 (0 only for ACK-only frames, never 1)
[VARINT(endpoint ID) ...]               // encodings 0x20 / 0x40, sorted, unique
[VARINT(contract length) CONTRACT]      // flag 0x04
VARINT(timestamp ms)
[VARINT(logical payload size)]          // flags 0x01 / 0x10
[VARINT(nonce)]                         // flag 0x08
[RELIABLE HEADER]                       // flag 0x02, or the contract declares it
PAYLOAD                                 // runs to the CRC
[CRC32: u32 LE]                         // over every prior byte
```

Everything before the timestamp is the frame's *static header*: it is identical for every packet
of one stream (same type, source, epoch, endpoints and contract). The timestamp and the fields after
it change per packet. Side-transport templates and compact bundles rely on this split.

Changes from SEDSnet 6 (all breaking; every node updates together):

- The `NEP` byte is gone. A schema-default frame carries no count; one explicit endpoint is one
  ULEB128 ID (encoding `0x20`); a counted list (`0x40`) carries a ULEB128 count.
- The 32-byte endpoint bitmap encoding is gone (a sorted ULEB128 ID list is never larger for the
  endpoint sets SEDSnet produces).
- The logical payload size is written only for compressed or sealed payloads; otherwise the
  payload length is the size.
- The time-base epoch is a flagged header field (one byte below 128) instead of an epoch-only
  contract (two bytes).
- The reliable header always uses the compact form; the `0x40` "compact reliable header" flag is
  gone.
- Field order: static header first, then the per-packet fields.
- Packets created with a timestamp newer than every earlier packet of the process carry no nonce
  (see [Packet nonce](#packet-nonce)).

## Explicit destinations

Application types retain their destination set on the wire, including when it equals the sender's
current schema: a complementary schema merge must not redirect an already queued packet to new
destinations. One destination is encoding `0x20` (the ID alone); several are encoding `0x40`
(ULEB128 count, then the sorted unique IDs). A counted list of exactly one ID is malformed, so
every endpoint set has one encoding.

With encoding `0x00` destinations come from type metadata. This omission is restricted to internal
control types whose schema cannot acquire destinations through application schema merging; a
type whose schema has no endpoints cannot use it.

ACK-only reliable control frames are encoding `0x40` with a zero count. Other empty frames are
rejected.

## Wire contract

When flag `0x04` is set, the static header ends with a compact contract:

```text
VARINT(contract_len)
[contract flags: u8]
    0x01: frozen destination sender hashes present
    0x02: inline payload shape present
    0x04: a reliable header is present even if current schema lookup would no longer imply it
[wire shape bytes]                // flag 0x02
[target count: ULEB128, >= 1]     // flag 0x01
[target sender hash: u64 LE] ...
```

A contract is carried only for a shape or targets; other flag bits, a zero length, a zero target
count or trailing bytes are malformed.

### Time epoch

A frame whose timestamp was taken in network time-base epoch 0 (no step ever seen) carries no
epoch. Otherwise flag `0x80` is set and the ULEB128 epoch follows the source address (one byte
below epoch 128). The epoch is part of the packet ID (folded in after the payload size when
nonzero). A present zero, or a value above 65534, is malformed. See
[Time-Sync](Time-Sync#steps-slews-and-the-time-base-epoch-sedsnet-6).

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

## Packet nonce

The nonce keeps packets with the same timestamp and content distinct (packet IDs, receipts,
dedupe, AEAD nonces). A packet created with a timestamp newer than every earlier packet of the
process needs none: its timestamp already sets it apart, so it carries no nonce (flag `0x08`
clear). A packet stamped in the same millisecond as an earlier one, or with an older stamp, takes
the next value of a process-wide sequence 1..=16383 (two ULEB128 bytes at most; two packets get
the same nonce only 16383 packets apart). Time sync packets keep their own 128..=16383 counter.
SEDSnet 6 gave every packet a pseudo-random nonce (three bytes on the wire).

The E2E AEAD nonce is the type XOR the rotated source address, the 48-bit timestamp and the packet
nonce: senders that share a group key no longer depend on random nonces to stay apart.

## Reliable header

The reliable header follows the per-packet fields when frame flag `0x02` is set or the contract
declares it. Decoding does not infer header presence from receiver schema state.

```text
[REL_WIRE_FLAGS: u8]
    bit0: ACK-only reliable control frame
    bit1: reliable but unordered
    bit2: SEQ varint present
    bit3: ACK varint present
    bit7: unsequenced best-effort reliable wrapper
[VARINT(seq)]                    // only when bit2 is set
[VARINT(ack)]                    // only when bit3 is set
```

A zero sequence is never written (the decoder reads an absent field as zero), so an unsequenced
wrapper is the single byte `REL_WIRE_FLAGS`; an ACK-only frame always carries its ACK. Other bits
are malformed. `RELIABLE_HEADER_BYTES` (9) remains as the size of the former fixed form.

Reliable control traffic primarily uses built-in internal packet types such as:

- `ReliableAck`
- `ReliablePartialAck`
- `ReliablePacketRequest`
- `DiscoveryAddress`
- `P2pMessage`

Those are router/relay-owned control packets, not user endpoint traffic. Their payload layouts are
documented in [Technical-Discovery-and-Internal-Formats](Technical-Discovery-and-Internal-Formats).

## Side Transport Frames

Routers and relays can use side-local framing for constrained links. A side frame is a canonical
frame or a side-transport frame, told apart by the first byte: a canonical flags byte never has
both endpoint-encoding bits (`0x60`) set, so every first byte with those bits set is a
side-transport kind. There is no `SDT` magic (SEDSnet 6 spent three bytes on it).

| First byte | Kind | Layout |
|---|---|---|
| any with `0x60` clear in either bit | canonical frame | as above |
| `0x60` | FULL | template id and generation, base delta, canonical data, CRC32 |
| `0x61` | CHUNK | transfer id `u16` LE, ULEB128 position, chunk bytes, CRC32 |
| `0x62`, `0x63`, `0x66`, `0x67` | BUNDLE | see [Compact bundles](#compact-bundles) |
| `0x70`..`0x73` | COMPACT | template id and generation, timestamp delta, [size], [nonce], payload, CRC32 |

Other values are reserved and rejected. First bytes `0xE0`..`0xFF` are never used by any SEDSnet
frame: link layers may use them for their own markers (the RR mesh envelope does).

Every SEDSnet frame, of every kind, ends in the CRC32 (little endian) of all its own prior bytes.

### Header templates (FULL and COMPACT)

With `RouterSideOptions::with_small_packet_transport(...)`, `with_template_transport()` or an
`ipv4_like`/`ipv6_like` profile, a side replaces the static header of repeated streams with a small
template id. Frames with a reliable header (reliable types, hop sequencing, ACKs, frozen-owner
contracts) never use templates: they are sent canonical.

```text
FULL    = 0x60 | VARINT(template id << 3 | generation) | VARINT(zigzag(base - ts))
          | canonical data (without its CRC) | CRC32(all prior bytes)
COMPACT = 0x70 | 0x01 compressed | 0x02 nonce
          | VARINT(template id << 3 | generation) | VARINT(zigzag(ts - base))
          | [VARINT(logical size)] | [VARINT(nonce)] | payload | CRC32(all prior bytes)
```

- Template ids are small (the lowest id the side is not using; one byte, with the generation, for
  up to 15 templates).
- Each template has a base timestamp, set only by a FULL frame. A COMPACT frame carries its
  timestamp as a zigzag ULEB128 delta from that base (two or three bytes for deltas up to about
  17 minutes). The sender moves the base, with a FULL frame, only when a delta would not fit three
  bytes, so a lost FULL refresh rarely changes the base a receiver needs.
- After eight COMPACT frames for a template the sender sends a FULL refresh, so a receiver that
  missed the first FULL frame relearns it. Discovery frames always go FULL.
- Each template id has a 3-bit generation. A FULL frame that defines an id for a new template, or
  moves its base, starts the next generation; a refresh keeps it. A receiver accepts a COMPACT
  frame only when its id and generation match the template it holds, so a stale template or base
  (a lost FULL frame) drops the frame instead of misreading it, until the next FULL frame (sent
  first after any redefinition and then every ninth frame). The sender keeps an id's generation
  across eviction, so a reused id never repeats the previous generation.
- The receiver rebuilds the canonical frame byte for byte (same packet ID) with a fresh CRC32.

Templates are side-local, and a receiver cannot tell producers on a shared bus apart. A router
therefore uses templates on a side only while discovery shows exactly one live hop-local peer on
it, or the application declared the side point to point (`SideOptions::point_to_point`,
`with_point_to_point()`, `Router::set_side_point_to_point`, C
`seds_router_set_side_point_to_point`) and discovery has not heard a second peer. Otherwise frames
are canonical. Declaring a shared bus point to point is a configuration error: two producers'
templates under one id could be confused until discovery hears the second producer.

### Chunk frames (kind `0x61`)

```text
[0x61]
[transfer id: u16 LE]             // stable content id of the chunked frame
[position: ULEB128]               // total * (total - 1) / 2 + index
[chunk bytes]
[CRC32: u32 LE]                   // over the kind byte through the chunk bytes
```

One ULEB128 position names both the chunk index and the chunk count: `total` is the largest `t`
with `t * (t - 1) / 2 <= position`, and `index = position - total * (total - 1) / 2`. Up to 15
chunks the position is one byte, so a chunk costs 8 bytes of overhead (11 in SEDSnet 6.x, 16
before). A transfer has at most 65535 chunks. The sender sizes chunk bodies for the longest
position of the transfer, so no chunk exceeds `max_frame_bytes`.

Every chunk carries its CRC32, so noise never enters or evicts reassembly state, and the
reassembled frame (canonical, FULL, COMPACT or bundle) is checked again by its own check when it
re-enters. Two in-flight transfers on one side that share a 16-bit id, or a chunk whose total
disagrees with its transfer's, can only make that reassembly fail its check and be dropped
(end-to-end reliability resends it); the per-side reassembly bound and receive budget are
unchanged.

### Compact bundles

`wire_bundle` packs several canonical frames into one side frame. A writer (the router on a
`compact_bundle` side, or a link layer packing one radio turn) uses
`wire_bundle::BundleWriter::new(budget, record_crc)` and `try_push(frame)` in its priority order
(`wire_bundle::frame_priority(frame)` gives a frame's transport priority), then `finish()`. C:
`seds_compact_bundle_pack_budget(...)` and `seds_frame_priority(...)`.

```text
bundle = MARKER | [table check u16 LE] | VARINT(base ts) | record+ | CRC32
MARKER = 0x62 | 0x01 node table | 0x04 per-record CRC
record = VARINT(len) | elide | [flags] | [type] | [source or node index]
       | [epoch, endpoints, contract] | VARINT(zigzag ts delta) | [size]
       | [nonce or zigzag nonce delta] | [reliable header] | payload | [CRC32, per-record mode]
elide  = 0x01 flags | 0x02 type | 0x04 source | 0x08 source as node index
       | 0x10 epoch/endpoints/contract | 0x20 contract targets as node indices | 0x40 nonce delta
```

A record elides every static-header field equal to the previous record's, so a train of one
stream costs the length, the elide byte, a one- or two-byte timestamp delta and the payload per
packet. One CRC32 ends the bundle and covers all of it; a damaged bundle delivers nothing. With
`record_crc` every record also carries the CRC32 of the canonical frame it rebuilds: when the
bundle check fails (a transport that passes damaged frames up), each record that still passes its
own check is delivered (a record eliding fields of a damaged one fails its own check). A frame the
receiving router refuses does not stop the others. Urgent frames (ABORT)
stay standalone canonical frames; sealed frames are never bundled.

### Per-hop integrity for link layers

Every frame SEDSnet hands a side callback ends in a CRC32 of all its prior bytes, which the
receiving SEDSnet checks before using any of it, and which any hop can check alone (no SEDSnet
state needed):

| Frame | Trailing CRC32 covers | Also |
|---|---|---|
| canonical | the frame (set by the originator, kept end to end) | |
| FULL | the whole FULL frame | canonical CRC rebuilt by the receiver |
| COMPACT | the whole compact frame | template id + generation must match |
| CHUNK | the chunk | the reassembled frame is checked again |
| BUNDLE | the whole bundle | optional per-record CRC32 |

A link layer therefore needs no CRC of its own for integrity: it can check SEDSnet's trailer
instead (the RR mesh envelope's one-byte self-checked form relies on it). SEDSnet frames carry **no length and no sequence number**: the link layer must deliver
each frame's exact bytes (its own framing or length prefix), and SEDSnet tolerates loss,
duplication and reordering (dedupe by packet ID, hop and end-to-end reliability, template
refreshes, chunk reassembly by transfer id and position).

## Compact Side Profiles

Routers and relays expose per-side compact-header profiles. `with_small_packet_transport` sets the
compact-header profile to `ipv6_like`; `with_ipv4_like_compact_header_target` sets it to
`ipv4_like`.

Each side also exports an effective side-transport profile:

- `canonical`: no side-transport wrapping is needed
- `template`: template reuse is enabled without an IPv4/IPv6-size target
- `ipv6_like`: compact follow-up frames are profiled against a 40-byte target
- `ipv4_like`: compact follow-up frames are profiled against a 20-byte target

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
64 entries per side. Both sender and receiver evict the entry with the lowest template hash when
the dictionary is full; a FULL frame always (re)defines its id. Discovery link capabilities
advertise this limit; a router sender uses the smallest live peer limit on the side as its
effective transmit capacity. If a compact frame references a template the receiver does not know,
or a stale one, that frame is dropped (an unknown template without returning a transport error).
Delivery resumes when the sender's periodic full refresh arrives. The SEDSnet 6 timestamp-delta
and unchanged-timestamp compact kinds no longer exist; the omission options are accepted and
ignored.

## Discovery and Internal Payloads

Discovery, P2P, managed-variable, reliable-control, and time-sync packet payloads are documented in
[Technical-Discovery-and-Internal-Formats](Technical-Discovery-and-Internal-Formats).

## Varints

All integer metadata fields use unsigned LEB128.

This includes:

- type ID
- source address and time epoch
- endpoint count and IDs
- payload size (compressed or sealed payloads)
- timestamp and nonce
- contract length
- target count
- static wire-shape count

`read_uleb128` rejects values that require more than 10 bytes.

## Source Address

The canonical packet header does not carry the sender hostname. It carries `src_addr`, a compact
source address assigned or learned through network configuration and discovery. Hostnames, board
names, endpoint holders, and topology are discovery/config state rather than repeated packet-header
data.

Standalone pack/unpack helpers maintain a host-side address cache so decoded `Packet` values can
still expose `sender()` when the process has seen the corresponding sender name. If no mapping is
known, the decoded sender is represented as `@addr:<number>`.

## Compression

Payload compression is used only when it is actually smaller on the wire. A compressed frame
transmits the logical uncompressed payload length, and decode validates the decompressed size
against it.

## Decode flow

High-level decode order:

1. Verify CRC32 (or rebuild and check a side-transport frame, see above).
2. Parse the static header: type, source, epoch, endpoints, contract.
3. Resolve the explicit endpoint IDs (`0x20`, `0x40`). Frames with neither use the metadata
   default for protocol control traffic.
4. Resolve the source address to a sender name from discovery/config state.
5. Decode the optional wire contract.
6. Parse the per-packet fields: timestamp, logical size, nonce, and the reliable header when frame
   flag `0x02` or the wire contract declares it. Receiver schema changes cannot add or remove an
   in-flight reliable header.
7. Decode the payload bytes.
8. Construct `Packet::new_with_wire_contract(...)`.

The optional wire contract provides the inline shape and target sender hashes used during unpacking
and routing.

## Envelope peek

`peek_envelope(...)` parses only the envelope and returns:

- `ty`
- `endpoints`
- `sender`
- `source_address`
- `timestamp_ms`
- `wire_shape`
- `target_senders`

`peek_frame_info(...)` extends that with the reliable header when present.

Routers and relays use these helpers for routing and reliable-layer decisions without fully decoding
payload data.

## Packet ID from wire

`packet_id_from_wire(...)` computes the same ID as `Packet::packet_id()` from a packed frame.
It hashes:

- compact source address
- message name
- endpoint IDs in ascending order
- timestamp
- nonce
- logical payload size
- time epoch (when nonzero)
- payload bytes after decompression

The wire contract is not part of the packet ID.

## CRC32 trailer

Every frame ends with a 4-byte little-endian CRC32 computed over all preceding bytes.

On CRC failure the frame is rejected before normal decode. Recovery behavior after that depends on
whether the surrounding router/relay reliable layer is active for that hop.

## Common decode failures

- short prelude or short read
- CRC32 mismatch
- unsorted, duplicate or one-entry counted endpoint list
- a first byte with both endpoint-encoding bits set (a side-transport kind, not a canonical frame)
- malformed or overlong ULEB128
- bad wire-shape type/class/count
- malformed wire-contract target list
- reliable control frame passed into full packet decode
- decompression failure or decompressed-size mismatch
- sender not valid UTF-8
