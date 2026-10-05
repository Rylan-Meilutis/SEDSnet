# Compact packet storage (opt-in)

Experimental in 4.1.0; disabled by default. Enable only after checking the
application memory budget and worst-case compaction/codec latency.

`compact-packet-store` reserves a private payload arena and a fixed handle table.
ThreadX scheduling and its allocator are unchanged. The arena's startup allocations
still come from the application's allocator. This is not a software MMU for
arbitrary Rust allocations: references, RTOS objects, and DMA buffers are never
silently relocated.

Initialize `PacketStore::new(bytes, handles, movable_limit)` and install it with
`packet_store::set_default_store(Some(store.clone()))` before starting workers.
Heap-backed Packet payloads, packed wire frames, and replay queue bytes entering
router/relay queues are parked in the arena;
inline payloads remain inside queue slots. Growable queue metadata reserves its maximum configured
capacity at startup instead of reallocating while traffic is running. Deliberately
fixed queues (growth multiplier 1) keep their requested initial capacity. If the arena cannot
accept a payload, enqueue returns an error without evicting an existing handle.
Budget the startup queue slabs deliberately. Queue element and byte limits remain bounded.

Handles share ownership without allocating a separate control block per payload.
Compaction runs on allocation when no suitable gap exists, or explicitly through
`store.compact()`. It only moves unpinned allocations at/below `movable_limit`.
Pinned and larger allocations form barriers; compaction cannot guarantee a large
contiguous gap or free memory occupied by live payloads. Compaction traverses an ordered fixed
handle table and copies at most arena capacity bytes; benchmark its worst-case
latency before choosing embedded sizes.

`StoredBytes::pin()` returns an owned immutable view. Keep it alive for the entire
FFI/DMA operation. Drop it only after the external consumer is finished. Ordinary
`Packet::payload()` preserves the existing slice API by pinning until exclusive
queue parking or destruction. `Packet::read_payload_range` reads into caller
storage without retaining a view. External clones/readers can intentionally keep
shared bytes pinned. Embedded telemetry lock hooks must support nesting; do not
call arena APIs from an ISR unless those hooks are valid there.

## Optional indexed Zstd storage

`compact-packet-compression` adds `PacketCodec`, using the existing Zstd backend.
It stores independently compressed chunks with 8-byte raw/stored-length headers.
Compression is accepted only if the entire representation, including headers,
is smaller than the original. Otherwise it stores the original bytes. No wire
format change or second compression backend is introduced.

`PacketCodec::memory_requirements(chunk_bytes)` reports the fixed context reservation,
encoding scratch, decoding scratch and total memory for a `BoundedPacketCodec`.
Check this against your configured RAM budget before enabling compression.
`BoundedPacketCodec::new(chunk_bytes, total_memory_budget)` rejects an insufficient
budget before allocating, owns both reusable scratch buffers, and never grows them.
The total includes the codec object and buffers, excluding allocator bookkeeping,
packet arena capacity and caller-owned field output.

Both Zstd contexts use its static workspace API in aligned, fixed buffers. Zstd
cannot malloc or resize these contexts: insufficient workspace produces an error.
The existing Zstd dependency's experimental API is enabled only for this optional
feature; no additional compression library is introduced.

Encoding uses two passes: measure independent chunks, reserve exactly the smaller
representation in the arena, then write the encoded chunks directly into that slot.
Encoding scratch is only `ZSTD_compressBound(chunk_bytes)` bytes, regardless of
packet length. This trades extra encoding work for bounded RAM. If chunks plus
headers do not save space, or scratch is insufficient, store the original bytes.
Arena allocation failure returns an error. Writes are protected by the arena lock;
benchmark latency for your maximum payload size before embedded use.

`codec.store(&store, bytes)` creates an optionally compressed handle.
`codec.read_range(&handle, offset, field_output)` decodes only chunks intersecting
the requested field and skips unrelated chunks. Decoding scratch is one chunk;
a field crossing a boundary reuses it. No full decompressed packet is cached.
The caller supplies the field offset and length; this does not infer a schema.
Compressed handles reject `pin()` to prevent an implicit full-size copy.

`Packet::into_stored_bounded(&store, &mut codec)` consumes the original packet
payload and returns a `StoredPacket`. Use
`stored.read_payload_range_bounded(&mut codec, offset, field_output)` for field
reads. Header metadata remains available and the original payload is released.

The lower-level `PacketCodec::new(chunk_bytes, workspace_budget)` and its explicit
scratch APIs remain available for applications managing their own reusable buffers.
`workspace_bytes()` reports allocated context capacity. The constructor checks its
budget before allocating and no longer uses temporary priming buffers.

Ordinary queue parking still stores plain movable payloads to preserve full-slice
transport APIs. Compression is explicit through these codec APIs. Context and
scratch reservations are fixed startup costs; account for them separately from
the arena. This is not an allocator-wide OOM guarantee. Tiny telemetry is often
better left inline/uncompressed.

`store.stats()` reports reserved bytes (arena plus table), live bytes/handles,
pinned bytes, largest free gap, moves and rejected allocations. Reserved memory
is fixed; compression reduces occupied capacity, not the startup reservation.

Build with Cargo `--features compact-packet-store` (or
`compact-packet-compression`), build.py's matching tokens, or CMake
`SEDSNET_COMPACT_PACKET_STORE=ON` / `SEDSNET_COMPACT_PACKET_COMPRESSION=ON`.
C/C++ initialization uses `seds_packet_store_configure(bytes, handles, movable_limit)`.
Rust users constructing `RouterItem::Packed` or `RelayItem::Packed` explicitly
can pass `arc.into()` for compatibility with both representations; the existing
`Router::tx_packed` and `tx_packed_queue` methods still accept Arc buffers.
Defaults are OFF. This is a first-stage packet storage feature; schema structures,
reliability maps, and arbitrary application allocations remain outside the arena.

Development test results and remaining limits are recorded in
[compact packet validation](compact-packet-validation.md).
