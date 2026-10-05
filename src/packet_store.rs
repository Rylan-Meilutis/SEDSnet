//! A private, bounded packet arena. Live Rust objects are never relocated.
//! Buffers move through handles; a pinned view prevents movement until dropped.
//! Large buffers can be excluded from compaction. No allocation occurs in plain
//! store/read/pin/compact/drop operations after arena construction.
use crate::{TelemetryError, TelemetryResult, lock::RouterMutex};
use alloc::{sync::Arc, vec::Vec};
use core::{cell::UnsafeCell, fmt, ops::Deref, ptr};

fn pressure() -> TelemetryError {
    TelemetryError::Io("memory pressure")
}
#[derive(Clone, Copy, Default)]
struct Slot {
    offset: usize,
    len: usize,
    refs: usize,
    pins: usize,
    compressed: bool,
    next: Option<usize>,
    source: usize,
}
struct State {
    bytes: Vec<UnsafeCell<u8>>,
    slots: Vec<Slot>,
    movable_limit: usize,
    moves: usize,
    rejected: usize,
    head: Option<usize>,
}
/// Accounting includes the fixed arena and handle table, not just live payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct StoreStats {
    pub capacity: usize,
    pub live_bytes: usize,
    pub largest_gap: usize,
    pub live_handles: usize,
    pub pinned_bytes: usize,
    pub moves: usize,
    pub rejected: usize,
    pub reserved_bytes: usize,
}
/// Thread-safe, fixed-capacity arena. Configure it before starting network workers.
/// Embedded access uses SEDSnet's existing telemetry_lock/unlock hooks: they must
/// support nesting, including calls made while a router lock is held.
pub struct PacketStore {
    state: RouterMutex<State>,
}
// All metadata and byte writes are serialized. Only immutable pinned byte views
// escape the lock; the corresponding slots cannot move or be overwritten.

impl fmt::Debug for PacketStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.stats().fmt(f)
    }
}
impl State {
    fn reserve(&mut self, len: usize, compressed: bool, source: usize) -> TelemetryResult<usize> {
        let Some(slot) = self.slots.iter().position(|s| s.refs == 0) else {
            self.rejected = self.rejected.wrapping_add(1);
            return Err(pressure());
        };
        let mut offset = self.gap(len);
        if offset.is_none() {
            self.compact();
            offset = self.gap(len);
        }
        let Some(offset) = offset else {
            self.rejected = self.rejected.wrapping_add(1);
            return Err(pressure());
        };
        let mut previous = None;
        let mut next = self.head;
        while let Some(i) = next {
            if self.slots[i].offset > offset {
                break;
            }
            previous = Some(i);
            next = self.slots[i].next;
        }
        self.slots[slot] = Slot {
            offset,
            len,
            refs: 1,
            pins: 0,
            compressed,
            next,
            source,
        };
        if let Some(i) = previous {
            self.slots[i].next = Some(slot);
        } else {
            self.head = Some(slot);
        }
        Ok(slot)
    }
    fn gap(&self, need: usize) -> Option<usize> {
        let mut end = 0;
        let mut cursor = self.head;
        while let Some(i) = cursor {
            let slot = self.slots[i];
            if slot.offset - end >= need {
                return Some(end);
            }
            end = slot.offset + slot.len;
            cursor = slot.next;
        }
        (self.bytes.len() - end >= need).then_some(end)
    }

    fn compact(&mut self) {
        let mut cursor = self.head;
        let mut end = 0;
        while let Some(i) = cursor {
            let s = self.slots[i];
            cursor = s.next;
            if s.pins == 0 && s.len <= self.movable_limit && s.offset != end {
                // SAFETY: destination is a free gap or this slot's old bytes.
                // Ascending traversal never crosses a preceding pinned slot.
                // UnsafeCell allows disjoint writes while another slot is borrowed.
                unsafe {
                    ptr::copy(
                        self.bytes.as_ptr().cast::<u8>().add(s.offset),
                        self.bytes.as_ptr().cast::<u8>().add(end).cast_mut(),
                        s.len,
                    );
                }
                self.slots[i].offset = end;
                self.moves = self.moves.wrapping_add(1);
            } else {
                end = s.offset;
            }
            end += s.len;
        }
    }
}
impl PacketStore {
    /// Reserve payload bytes and a fixed handle table once. `movable_limit`
    /// excludes larger allocations from compaction (usize::MAX moves all sizes).
    /// The returned Arc/control block is a startup allocation, not a hot-path one.
    pub fn new(
        capacity: usize,
        handles: usize,
        movable_limit: usize,
    ) -> TelemetryResult<Arc<Self>> {
        if capacity == 0 || handles == 0 {
            return Err(pressure());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| pressure())?;
        bytes.resize_with(capacity, || UnsafeCell::new(0));
        let mut slots = Vec::new();
        slots.try_reserve_exact(handles).map_err(|_| pressure())?;
        slots.resize(handles, Slot::default());
        let store = Arc::new(Self {
            state: RouterMutex::new(State {
                bytes,
                slots,
                movable_limit,
                moves: 0,
                rejected: 0,
                head: None,
            }),
        });
        // Some host mutex implementations allocate on first lock. Pay that
        // cost at startup, before the allocation-free arena operations.
        #[cfg(feature = "std")]
        drop(store.state.lock());
        Ok(store)
    }
    /// Copy a payload into the arena; compact automatically only if a contiguous
    /// gap is missing. Exhaustion returns an error, never evicts another handle.
    pub fn store(self: &Arc<Self>, bytes: &[u8]) -> TelemetryResult<StoredBytes> {
        self.insert(bytes, bytes.len(), false, 0)
    }
    /// Coalesce parking of shared Arc owners into one arena handle. The address
    /// is a hint only: content is compared so allocator address reuse cannot
    /// alias unrelated payloads. No Weak is retained (it would retain Arc storage).
    pub fn store_shared(self: &Arc<Self>, bytes: &Arc<[u8]>) -> TelemetryResult<StoredBytes> {
        self.insert(
            bytes,
            bytes.len(),
            false,
            Arc::as_ptr(bytes) as *const u8 as usize,
        )
    }
    fn insert(
        self: &Arc<Self>,
        bytes: &[u8],
        logical: usize,
        compressed: bool,
        source: usize,
    ) -> TelemetryResult<StoredBytes> {
        if bytes.is_empty() {
            return Ok(StoredBytes {
                store: self.clone(),
                slot: None,
                len: logical,
            });
        }
        let mut st = self.state.lock();
        if source != 0 {
            if let Some(i) = st.slots.iter().position(|s| {
                s.refs != 0
                    && !s.compressed
                    && s.source == source
                    && s.len == bytes.len()
                    && unsafe {
                        core::slice::from_raw_parts(
                            st.bytes.as_ptr().cast::<u8>().add(s.offset),
                            s.len,
                        )
                    } == bytes
            }) {
                st.slots[i].refs = st.slots[i]
                    .refs
                    .checked_add(1)
                    .expect("packet handle overflow");
                return Ok(StoredBytes {
                    store: self.clone(),
                    slot: Some(i),
                    len: logical,
                });
            }
        }
        let slot = st.reserve(bytes.len(), compressed, source)?;
        let offset = st.slots[slot].offset;
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                st.bytes.as_ptr().cast::<u8>().add(offset).cast_mut(),
                bytes.len(),
            );
        }
        Ok(StoredBytes {
            store: self.clone(),
            slot: Some(slot),
            len: logical,
        })
    }
    pub fn compact(&self) {
        self.state.lock().compact();
    }
    pub fn stats(&self) -> StoreStats {
        let st = self.state.lock();
        let mut end = 0;
        let mut largest = 0;
        let mut cursor = st.head;
        while let Some(i) = cursor {
            let s = st.slots[i];
            largest = largest.max(s.offset - end);
            end = s.offset + s.len;
            cursor = s.next;
        }
        largest = largest.max(st.bytes.len() - end);
        StoreStats {
            capacity: st.bytes.len(),
            live_bytes: st.slots.iter().filter(|s| s.refs != 0).map(|s| s.len).sum(),
            live_handles: st.slots.iter().filter(|s| s.refs != 0).count(),
            pinned_bytes: st
                .slots
                .iter()
                .filter(|s| s.refs != 0 && s.pins != 0)
                .map(|s| s.len)
                .sum(),
            largest_gap: largest,
            moves: st.moves,
            rejected: st.rejected,
            reserved_bytes: st.bytes.capacity()
                + st.slots.capacity() * core::mem::size_of::<Slot>(),
        }
    }
}
/// Shared ownership of one arena slot. Cloning allocates no payload/control block.
pub struct StoredBytes {
    store: Arc<PacketStore>,
    slot: Option<usize>,
    len: usize,
}
impl Clone for StoredBytes {
    fn clone(&self) -> Self {
        if let Some(i) = self.slot {
            let mut st = self.store.state.lock();
            st.slots[i].refs = st.slots[i]
                .refs
                .checked_add(1)
                .expect("packet handle overflow");
        }
        Self {
            store: self.store.clone(),
            slot: self.slot,
            len: self.len,
        }
    }
}
impl Drop for StoredBytes {
    fn drop(&mut self) {
        if let Some(i) = self.slot {
            let mut st = self.store.state.lock();
            st.slots[i].refs -= 1;
            if st.slots[i].refs == 0 {
                debug_assert_eq!(st.slots[i].pins, 0);
                if st.head == Some(i) {
                    st.head = st.slots[i].next;
                } else {
                    let mut cursor = st.head;
                    while let Some(previous) = cursor {
                        if st.slots[previous].next == Some(i) {
                            st.slots[previous].next = st.slots[i].next;
                            break;
                        }
                        cursor = st.slots[previous].next;
                    }
                }
                st.slots[i] = Slot::default();
            }
        }
    }
}
impl fmt::Debug for StoredBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredBytes")
            .field("len", &self.len)
            .field("stored_len", &self.stored_len())
            .finish()
    }
}
impl StoredBytes {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn stored_len(&self) -> usize {
        self.slot
            .map_or(0, |i| self.store.state.lock().slots[i].len)
    }
    pub fn is_compressed(&self) -> bool {
        self.slot
            .is_some_and(|i| self.store.state.lock().slots[i].compressed)
    }
    /// A raw view is available only for plain payloads. Compressed field reads use
    /// read_range instead, so no second full-size decompressed buffer is retained.
    pub fn pin(&self) -> TelemetryResult<PinnedBytes> {
        if let Some(i) = self.slot {
            let mut st = self.store.state.lock();
            if st.slots[i].compressed {
                return Err(TelemetryError::Io(
                    "compressed payload requires range decoding",
                ));
            }
            st.slots[i].pins = st.slots[i]
                .pins
                .checked_add(1)
                .expect("packet pin overflow");
        }
        Ok(PinnedBytes {
            handle: self.clone(),
        })
    }
    #[cfg(feature = "compact-packet-compression")]
    fn pin_encoded(&self) -> PinnedBytes {
        if let Some(i) = self.slot {
            let mut st = self.store.state.lock();
            st.slots[i].pins = st.slots[i]
                .pins
                .checked_add(1)
                .expect("packet pin overflow");
        }
        PinnedBytes {
            handle: self.clone(),
        }
    }
    /// Read a plain byte range into caller storage, without allocating.
    pub fn read_range(&self, offset: usize, out: &mut [u8]) -> TelemetryResult<()> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(TelemetryError::Unpack("payload range out of bounds"));
        }
        let view = self.pin()?;
        out.copy_from_slice(&view[offset..offset + out.len()]);
        Ok(())
    }
}
/// Immutable view. Its allocation cannot move, be reused, or disappear until drop.
/// Owned views may be kept for synchronous FFI or asynchronous DMA, but the view
/// must outlive all raw-pointer consumers (and be dropped outside an ISR unless
/// the configured lock hooks permit it).
pub struct PinnedBytes {
    handle: StoredBytes,
}
impl Deref for PinnedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        let Some(i) = self.handle.slot else {
            return &[];
        };
        let st = self.handle.store.state.lock();
        let s = st.slots[i];
        unsafe { core::slice::from_raw_parts(st.bytes.as_ptr().cast::<u8>().add(s.offset), s.len) }
    }
}
impl Drop for PinnedBytes {
    fn drop(&mut self) {
        if let Some(i) = self.handle.slot {
            self.handle.store.state.lock().slots[i].pins -= 1;
        }
    }
}

// Optional process-wide arena for queue parking. Replacing it affects new
// parking only: old handles retain their original arena until dropped.
static DEFAULT_STORE: RouterMutex<Option<Arc<PacketStore>>> = RouterMutex::constant(None);
pub fn set_default_store(store: Option<Arc<PacketStore>>) {
    *DEFAULT_STORE.lock() = store;
}
pub(crate) fn default_store() -> Option<Arc<PacketStore>> {
    DEFAULT_STORE.lock().clone()
}

/// An ordinary slice API pins on first access. Exclusive queue parking releases
/// that pin. Concurrent readers can never invalidate each other's references.
pub struct ParkedPayload {
    handle: StoredBytes,
    view: RouterMutex<Option<PinnedBytes>>,
}
impl ParkedPayload {
    pub(crate) fn new(handle: StoredBytes) -> Self {
        assert!(!handle.is_compressed());
        Self {
            handle,
            view: RouterMutex::new(None),
        }
    }
    pub fn len(&self) -> usize {
        self.handle.len()
    }
    pub fn is_empty(&self) -> bool {
        self.handle.is_empty()
    }
    pub fn as_slice(&self) -> &[u8] {
        let mut view = self.view.lock();
        if view.is_none() {
            *view = Some(self.handle.pin().expect("plain parked payload"));
        }
        let bytes = view.as_ref().unwrap().deref();
        let pointer = bytes.as_ptr();
        let len = bytes.len();
        // Pin remains in self until an exclusive &mut self releases it or self is
        // dropped, so the returned borrow cannot overlap unpinning.
        unsafe { core::slice::from_raw_parts(pointer, len) }
    }
    pub fn park(&mut self) {
        *self.view.lock() = None;
    }
    pub fn read_range(&self, offset: usize, out: &mut [u8]) -> TelemetryResult<()> {
        self.handle.read_range(offset, out)
    }
}
impl Clone for ParkedPayload {
    fn clone(&self) -> Self {
        Self::new(self.handle.clone())
    }
}
impl fmt::Debug for ParkedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.handle.fmt(f)
    }
}

#[cfg(feature = "compact-packet-compression")]
mod compression {
    use super::*;
    use zstd_safe::zstd_sys as sys;

    fn zstd_result(n: usize) -> TelemetryResult<usize> {
        // SAFETY: error inspection has no pointer arguments.
        if unsafe { sys::ZSTD_isError(n) } != 0 {
            Err(TelemetryError::Io("fixed codec workspace exhausted"))
        } else {
            Ok(n)
        }
    }
    fn aligned_size(bytes: usize) -> TelemetryResult<usize> {
        bytes.checked_add(7).map(|n| n & !7).ok_or_else(pressure)
    }
    fn words(bytes: usize) -> TelemetryResult<Vec<u64>> {
        let mut v = Vec::new();
        let count = bytes / 8;
        v.try_reserve_exact(count).map_err(|_| pressure())?;
        v.resize(count, 0);
        Ok(v)
    }
    fn buffer(bytes: usize) -> TelemetryResult<Vec<u8>> {
        let mut v = Vec::new();
        v.try_reserve_exact(bytes).map_err(|_| pressure())?;
        v.resize(bytes, 0);
        Ok(v)
    }

    /// Preflight reservation for one bounded codec. Excludes packet arena bytes
    /// and caller field output; includes context buffers, scratch and this object.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CodecMemory {
        pub workspace_bytes: usize,
        pub encode_scratch_bytes: usize,
        pub decode_scratch_bytes: usize,
        pub total_bytes: usize,
    }

    /// Fixed Zstd contexts. Zstd cannot malloc or resize these static workspaces.
    /// Vec<u64> guarantees the required alignment; the allocation is never resized.
    /// Pointers are derived per call, so moving the Rust owner is safe. No Zstd
    /// free function is called for static contexts; Vec owns their lifetime.
    pub struct PacketCodec {
        encoder: Vec<u64>,
        decoder: Vec<u64>,
        chunk: usize,
        decoded_chunks: usize,
    }
    impl PacketCodec {
        fn sizes(chunk: usize) -> TelemetryResult<(usize, usize)> {
            if chunk == 0 || chunk > u32::MAX as usize {
                return Err(TelemetryError::Io("invalid compression chunk size"));
            }
            // SAFETY: Zstd's estimators take values only. Use exactly the same
            // compression parameters as the static context below, no dictionary.
            let params = unsafe { sys::ZSTD_getCParams(1, chunk as u64, 0) };
            let encoder = zstd_result(unsafe { sys::ZSTD_estimateCCtxSize_usingCParams(params) })?;
            let decoder = zstd_result(unsafe { sys::ZSTD_estimateDCtxSize() })?;
            Ok((aligned_size(encoder)?, aligned_size(decoder)?))
        }
        pub fn memory_requirements(chunk: usize) -> TelemetryResult<CodecMemory> {
            let (encoder, decoder) = Self::sizes(chunk)?;
            let workspace_bytes = encoder.checked_add(decoder).ok_or_else(pressure)?;
            let encode_scratch_bytes = zstd_safe::compress_bound(chunk);
            let decode_scratch_bytes = chunk;
            let total_bytes = workspace_bytes
                .checked_add(encode_scratch_bytes)
                .and_then(|n| n.checked_add(decode_scratch_bytes))
                .and_then(|n| n.checked_add(core::mem::size_of::<BoundedPacketCodec>()))
                .ok_or_else(pressure)?;
            Ok(CodecMemory {
                workspace_bytes,
                encode_scratch_bytes,
                decode_scratch_bytes,
                total_bytes,
            })
        }
        /// Reject oversized context reservations before allocating. All codec
        /// allocations happen here; subsequent operations never grow workspace.
        pub fn new(chunk: usize, workspace_budget: usize) -> TelemetryResult<Self> {
            let (enc, dec) = Self::sizes(chunk)?;
            let workspace = enc.checked_add(dec).ok_or_else(pressure)?;
            if workspace > workspace_budget {
                return Err(TelemetryError::Io("codec workspace exceeds budget"));
            }
            let mut encoder = words(enc)?;
            let mut decoder = words(dec)?;
            // SAFETY: both buffers are 8-byte aligned, correctly sized, and owned
            // until codec drop. Static initialization never allocates internally.
            let c = unsafe { sys::ZSTD_initStaticCCtx(encoder.as_mut_ptr().cast(), enc) };
            let d = unsafe { sys::ZSTD_initStaticDCtx(decoder.as_mut_ptr().cast(), dec) };
            if c.is_null() || d.is_null() {
                return Err(pressure());
            }
            let params = unsafe { sys::ZSTD_getCParams(1, chunk as u64, 0) };
            zstd_result(unsafe { sys::ZSTD_CCtx_setCParams(c, params) })?;
            let codec = Self {
                encoder,
                decoder,
                chunk,
                decoded_chunks: 0,
            };
            if codec.workspace_bytes() > workspace_budget {
                return Err(pressure());
            }
            Ok(codec)
        }
        /// The fixed allocated capacity, rather than an estimate of live Zstd use.
        pub fn workspace_bytes(&self) -> usize {
            (self.encoder.capacity() + self.decoder.capacity()) * 8
        }
        pub fn decoded_chunks(&self) -> usize {
            self.decoded_chunks
        }
        pub fn primed_workspace_bytes(&self) -> usize {
            self.workspace_bytes()
        }
        pub fn chunk_bytes(&self) -> usize {
            self.chunk
        }
        fn encode_chunk(&mut self, raw: &[u8], scratch: &mut [u8]) -> TelemetryResult<usize> {
            if scratch.len() < raw.len() {
                return Err(TelemetryError::Io("encode scratch too small"));
            }
            // SAFETY: initialized static context; input/output are disjoint valid
            // slices. &mut self serializes context use and the buffers never move.
            let n = unsafe {
                sys::ZSTD_compress2(
                    self.encoder.as_mut_ptr().cast(),
                    scratch.as_mut_ptr().cast(),
                    scratch.len(),
                    raw.as_ptr().cast(),
                    raw.len(),
                )
            };
            if let Ok(n) = zstd_result(n) {
                if n < raw.len() {
                    return Ok(n);
                }
            }
            scratch[..raw.len()].copy_from_slice(raw);
            Ok(raw.len())
        }
        /// Two-pass encoding uses only chunk-sized scratch. First measure the
        /// representation; then reserve exactly that many arena bytes and write
        /// directly into its private slot. No full encoded temporary is retained.
        /// Encoding errors or insufficient scratch fall back to plain storage.
        pub fn store(
            &mut self,
            store: &Arc<PacketStore>,
            data: &[u8],
            scratch: &mut [u8],
        ) -> TelemetryResult<StoredBytes> {
            if data.is_empty() || scratch.len() < self.chunk.min(data.len()) {
                return store.store(data);
            }
            let mut used = 0usize;
            for raw in data.chunks(self.chunk) {
                let n = self.encode_chunk(raw, scratch)?;
                used = match used.checked_add(8).and_then(|x| x.checked_add(n)) {
                    Some(n) if n < data.len() => n,
                    _ => return store.store(data),
                };
            }
            let slot = store.state.lock().reserve(used, true, 0)?;
            let handle = StoredBytes {
                store: store.clone(),
                slot: Some(slot),
                len: data.len(),
            };
            let result = (|| {
                let st = store.state.lock();
                let offset = st.slots[slot].offset;
                let mut cursor = 0usize;
                for raw in data.chunks(self.chunk) {
                    let n = self.encode_chunk(raw, scratch)?;
                    let end = cursor
                        .checked_add(8)
                        .and_then(|x| x.checked_add(n))
                        .filter(|&x| x <= used)
                        .ok_or(TelemetryError::Io("codec size changed"))?;
                    let raw_len = (raw.len() as u32).to_le_bytes();
                    let stored_len = (n as u32).to_le_bytes();
                    // SAFETY: this slot is private, unpinned and lock-protected;
                    // every write is checked within its exact reserved length.
                    unsafe {
                        let dst = st
                            .bytes
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + cursor)
                            .cast_mut();
                        ptr::copy_nonoverlapping(raw_len.as_ptr(), dst, 4);
                        ptr::copy_nonoverlapping(stored_len.as_ptr(), dst.add(4), 4);
                        ptr::copy_nonoverlapping(scratch.as_ptr(), dst.add(8), n);
                    }
                    cursor = end;
                }
                if cursor != used {
                    return Err(TelemetryError::Io("codec size changed"));
                }
                Ok(())
            })();
            // Drop/rollback happens only after the arena lock above is released.
            result?;
            Ok(handle)
        }
        /// Decode only chunks intersecting this field/range. Decoder scratch is
        /// at most chunk bytes; unrelated chunks are skipped without decoding.
        pub fn read_range(
            &mut self,
            handle: &StoredBytes,
            offset: usize,
            out: &mut [u8],
            scratch: &mut [u8],
        ) -> TelemetryResult<()> {
            let end = offset
                .checked_add(out.len())
                .filter(|&n| n <= handle.len())
                .ok_or(TelemetryError::Unpack("payload range out of bounds"))?;
            if !handle.is_compressed() {
                return handle.read_range(offset, out);
            }
            if out.is_empty() {
                return Ok(());
            }
            let view = handle.pin_encoded();
            let mut cursor = 0;
            let mut logical = 0;
            while logical < end {
                let header = view
                    .get(cursor..cursor + 8)
                    .ok_or(TelemetryError::Unpack("invalid stored chunk"))?;
                let raw = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
                let n = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
                cursor += 8;
                let bytes = view
                    .get(cursor..cursor + n)
                    .ok_or(TelemetryError::Unpack("invalid stored chunk"))?;
                if raw == 0 || raw > self.chunk || n > raw || n == 0 {
                    return Err(TelemetryError::Unpack("invalid stored chunk size"));
                }
                if logical + raw > offset {
                    let decoded = if n == raw {
                        bytes
                    } else {
                        if scratch.len() < raw {
                            return Err(TelemetryError::Io("field decode scratch too small"));
                        }
                        // SAFETY: fixed initialized decoder and valid disjoint slices.
                        let written = zstd_result(unsafe {
                            sys::ZSTD_decompressDCtx(
                                self.decoder.as_mut_ptr().cast(),
                                scratch.as_mut_ptr().cast(),
                                raw,
                                bytes.as_ptr().cast(),
                                bytes.len(),
                            )
                        })
                        .map_err(|_| TelemetryError::Unpack("stored chunk decode failed"))?;
                        if written != raw {
                            return Err(TelemetryError::Unpack("stored chunk size mismatch"));
                        }
                        self.decoded_chunks = self.decoded_chunks.wrapping_add(1);
                        &scratch[..raw]
                    };
                    let from = offset.max(logical);
                    let to = end.min(logical + raw);
                    out[from - offset..to - offset]
                        .copy_from_slice(&decoded[from - logical..to - logical]);
                }
                cursor += n;
                logical += raw;
            }
            Ok(())
        }
    }
    /// Owns both reusable scratch buffers and enforces one preflight RAM budget.
    /// The budget covers fixed buffers and object size, excluding allocator bookkeeping.
    pub struct BoundedPacketCodec {
        codec: PacketCodec,
        encode: Vec<u8>,
        decode: Vec<u8>,
    }
    impl BoundedPacketCodec {
        pub fn new(chunk: usize, memory_budget: usize) -> TelemetryResult<Self> {
            let required = PacketCodec::memory_requirements(chunk)?;
            if required.total_bytes > memory_budget {
                return Err(TelemetryError::Io("codec memory exceeds budget"));
            }
            let codec = PacketCodec::new(chunk, required.workspace_bytes)?;
            let encode = buffer(required.encode_scratch_bytes)?;
            let decode = buffer(required.decode_scratch_bytes)?;
            let result = Self {
                codec,
                encode,
                decode,
            };
            if result.reserved_bytes() > memory_budget {
                return Err(pressure());
            }
            Ok(result)
        }
        pub fn reserved_bytes(&self) -> usize {
            self.codec.workspace_bytes()
                + self.encode.capacity()
                + self.decode.capacity()
                + core::mem::size_of::<Self>()
        }
        pub fn decoded_chunks(&self) -> usize {
            self.codec.decoded_chunks()
        }
        pub fn store(
            &mut self,
            store: &Arc<PacketStore>,
            data: &[u8],
        ) -> TelemetryResult<StoredBytes> {
            self.codec.store(store, data, &mut self.encode)
        }
        pub fn read_range(
            &mut self,
            handle: &StoredBytes,
            offset: usize,
            out: &mut [u8],
        ) -> TelemetryResult<()> {
            self.codec.read_range(handle, offset, out, &mut self.decode)
        }
    }
}
#[cfg(feature = "compact-packet-compression")]
pub use compression::{BoundedPacketCodec, CodecMemory, PacketCodec};

/// Configure the default arena before worker startup. A zero capacity disables
/// parking for new items; existing handles retain their old arena safely.
/// Status matches SEDS_OK (0) / SEDS_IO (-14).
#[unsafe(no_mangle)]
pub extern "C" fn seds_packet_store_configure(
    capacity: usize,
    handles: usize,
    movable_limit: usize,
) -> i32 {
    if capacity == 0 {
        set_default_store(None);
        return 0;
    }
    match PacketStore::new(capacity, handles, movable_limit) {
        Ok(store) => {
            set_default_store(Some(store));
            0
        }
        Err(_) => crate::TelemetryErrorCode::Io as i32,
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn seds_packet_store_compact() {
    if let Some(store) = default_store() {
        store.compact();
    }
}

/// Copy statistics for the current default arena. No allocation.
/// # Safety
/// out must be valid and aligned for one writable StoreStats, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seds_packet_store_stats(out: *mut StoreStats) -> i32 {
    if out.is_null() {
        return crate::TelemetryErrorCode::BadArg as i32;
    }
    let Some(store) = default_store() else {
        return crate::TelemetryErrorCode::Io as i32;
    };
    unsafe {
        out.write(store.stats());
    }
    0
}

#[cfg(all(test, feature = "std"))]
mod shared_address_tests {
    use super::*;
    #[test]
    fn arena_pressure_does_not_prevent_retained_work_from_draining() {
        let store = PacketStore::new(16, 1, 16).unwrap();
        let queued = store.store(&[7; 16]).unwrap();
        // Background admission must yield to dispatch, not strand the only
        // handle that can free space for subsequent packets.
        let background = store.store(&[8; 16]).map(|_| ());
        assert!(background.is_err());
        crate::memory_admission::allow_drain(background).unwrap();
        assert_eq!(&*queued.pin().unwrap(), &[7; 16]);
        drop(queued);
        assert!(store.store(&[8; 16]).is_ok());
    }
    #[test]
    fn reused_source_address_cannot_alias_different_content() {
        let store = PacketStore::new(256, 8, 256).unwrap();
        let first: Arc<[u8]> = Arc::from([1; 80]);
        let a = store.store_shared(&first).unwrap();
        drop(first);
        let second: Arc<[u8]> = Arc::from([2; 80]);
        // Model allocator address reuse deterministically, rather than rely on
        // the host allocator to choose the same address during this test.
        store.state.lock().slots[a.slot.unwrap()].source =
            Arc::as_ptr(&second) as *const u8 as usize;
        let b = store.store_shared(&second).unwrap();
        assert_eq!(&*a.pin().unwrap(), &[1; 80]);
        assert_eq!(&*b.pin().unwrap(), &[2; 80]);
        assert_eq!(store.stats().live_handles, 2);
    }
}
