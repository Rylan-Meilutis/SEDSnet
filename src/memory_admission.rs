//! Optional allocator-headroom admission for constrained applications.
//!
//! Queue byte limits do not include schema snapshots, decoder scratch space or
//! allocator fragmentation. A board can register a non-allocating probe to reject
//! work before these allocations. This is admission control, not an allocator
//! guarantee: callers must still size pools for concurrent work and callbacks.
use crate::{TelemetryError, TelemetryResult};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

/// Must be nonblocking, allocation-free, thread/ISR-safe when those ingress APIs
/// are used, and must not call back into SEDSnet. Arguments are estimated total
/// additional bytes and the largest required contiguous allocation.
pub type MemoryAdmissionProbe = extern "C" fn(usize, usize) -> bool;
/// Extended probe distinguishes bounded cached transit from general work.
/// General work retains the conservative decoder/metadata scratch contract.
pub type MemoryAdmissionProbeV2 = extern "C" fn(usize, usize, u32) -> bool;
pub const WORK_GENERAL: u32 = 0;
pub const WORK_CACHED_TRANSIT: u32 = 1;
/// Small, CRC-validated, uncompressed reliable/managed traffic with known fixed byte shape
/// and protected queue priority. Estimates are unchanged; an application may
/// reserve less idle headroom for this work than for ordinary data/schema work.
pub const WORK_SMALL_PROTECTED: u32 = 2;
static PROBE_V2: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static PROBE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static REJECTED: AtomicUsize = AtomicUsize::new(0);

/// Install a process-wide admission probe, or `None` to disable it.
pub fn set_probe(probe: Option<MemoryAdmissionProbe>) {
    PROBE_V2.store(core::ptr::null_mut(), Ordering::Release);
    PROBE.store(
        probe.map_or(core::ptr::null_mut(), |f| f as *mut ()),
        Ordering::Release,
    );
}
/// Install an extended probe at startup, replacing the legacy probe.
pub fn set_probe_v2(probe: Option<MemoryAdmissionProbeV2>) {
    PROBE.store(core::ptr::null_mut(), Ordering::Release);
    PROBE_V2.store(
        probe.map_or(core::ptr::null_mut(), |f| f as *mut ()),
        Ordering::Release,
    );
}
pub(crate) fn supports_work_kinds() -> bool {
    !PROBE_V2.load(Ordering::Relaxed).is_null()
}
pub(crate) fn has_probe() -> bool {
    supports_work_kinds() || !PROBE.load(Ordering::Relaxed).is_null()
}
/// Number of operations rejected by the probe, wrapping at usize::MAX.
pub fn rejected_operations() -> usize {
    REJECTED.load(Ordering::Relaxed)
}

pub(crate) fn check(additional_bytes: usize, largest_allocation: usize) -> TelemetryResult<()> {
    check_work(additional_bytes, largest_allocation, WORK_GENERAL)
}
fn check_work(
    additional_bytes: usize,
    largest_allocation: usize,
    work: u32,
) -> TelemetryResult<()> {
    let extended = PROBE_V2.load(Ordering::Acquire);
    let allowed = if !extended.is_null() {
        // SAFETY: only this exact function-pointer signature is installed.
        let probe: MemoryAdmissionProbeV2 = unsafe { core::mem::transmute(extended) };
        probe(additional_bytes, largest_allocation, work)
    } else {
        let ptr = PROBE.load(Ordering::Acquire);
        if ptr.is_null() {
            return Ok(());
        }
        // SAFETY: legacy callbacks retain their original signature/contract.
        let probe: MemoryAdmissionProbe = unsafe { core::mem::transmute(ptr) };
        probe(additional_bytes, largest_allocation)
    };
    if allowed {
        return Ok(());
    }
    REJECTED.fetch_add(1, Ordering::Relaxed);
    Err(TelemetryError::Io("memory pressure"))
}
/// Only used after verifying cached routing, statistics and transport metadata.
pub(crate) fn check_cached_transit(len: usize) -> TelemetryResult<()> {
    // Snapshot the extended callback once. If a legacy probe replaces it
    // concurrently, never pass the smaller requirement to that legacy probe.
    let ptr = PROBE_V2.load(Ordering::Acquire);
    if ptr.is_null() {
        return check_frame(len, false);
    }
    // SAFETY: installed callbacks have this signature and remain valid while
    // in-flight admission checks complete, including across replacement.
    let probe: MemoryAdmissionProbeV2 = unsafe { core::mem::transmute(ptr) };
    if probe(
        1024usize.saturating_add(len.saturating_mul(2)),
        256,
        WORK_CACHED_TRANSIT,
    ) {
        return Ok(());
    }
    REJECTED.fetch_add(1, Ordering::Relaxed);
    Err(TelemetryError::Io("memory pressure"))
}

pub(crate) fn check_receive(bytes: &[u8]) -> TelemetryResult<()> {
    check_receive_with_role(bytes, false)
}

pub(crate) fn check_receive_with_role(bytes: &[u8], managed: bool) -> TelemetryResult<()> {
    if !has_probe() {
        return Ok(());
    }
    // Keep smaller admission for ACKs that release replay buffers and short
    // discovery keepalives that preserve the return path. Side wrappers are classified after their header is decoded.
    let frame = crate::wire_format::peek_routing_frame_info(bytes).ok();
    let ack = frame.as_ref().is_some_and(|frame| {
        frame.ack_only()
            || matches!(
                frame.envelope.ty,
                crate::DataType::ReliableAck
                    | crate::DataType::ReliablePartialAck
                    | crate::DataType::DiscoveryAnnounce
            )
    });
    if !ack
        && supports_work_kinds()
        && bytes.len() <= 128
        && bytes.first().is_some_and(|flags| flags & 0x11 == 0)
        && frame.as_ref().is_some_and(|frame| {
            protected_discovery_request_shape(
                frame.envelope.ty,
                frame.empty_payload,
                frame
                    .envelope
                    .endpoints()
                    .eq([crate::DataEndpoint::Discovery]),
                frame.envelope.target_senders().len(),
                frame.envelope.wire_shape,
            ) || protected_control_shape(
                frame.envelope.ty,
                bytes.get(1).copied().unwrap_or(u8::MAX) as usize,
                frame.envelope.target_senders().len(),
                frame.envelope.wire_shape,
                frame.reliable.is_some(),
                managed,
            )
        })
    {
        // Keep the complete conservative allocation estimate. This is a
        // scheduling classification, never permission to skip normal decoding.
        return check_frame_kind(bytes.len(), false, WORK_SMALL_PROTECTED);
    }
    check_frame(bytes.len(), ack)
}

/// Empty, untargeted discovery requests are bounded recovery controls even
/// though their established schema uses a dynamic byte element. The reply
/// still requires independent admission for its full graph/schema workspace.
pub(crate) fn protected_discovery_request_shape(
    ty: crate::DataType,
    empty: bool,
    discovery_only: bool,
    owners: usize,
    shape: Option<crate::MessageElement>,
) -> bool {
    empty
        && discovery_only
        && owners == 0
        && matches!(
            ty,
            crate::DataType::DiscoveryTopologyRequest | crate::DataType::DiscoverySchemaRequest
        )
        && shape.is_none_or(|value| value == crate::message_meta(ty).element)
}

/// Shared by ingress and the CRC-validated payload decoder. Keep the work
/// class through both stages without trusting caller supplied priority alone.
pub(crate) fn protected_control_shape(
    ty: crate::DataType,
    endpoints: usize,
    owners: usize,
    shape: Option<crate::MessageElement>,
    reliable: bool,
    managed: bool,
) -> bool {
    if endpoints > 3 || owners > 3 || (!reliable && owners == 0) {
        return false;
    }
    let Some(meta) = crate::config::try_get_message_meta(ty) else {
        return false;
    };
    (meta.priority >= 200 || managed || owners != 0)
        && matches!(
            meta.element,
            crate::MessageElement::Static(0..=16, crate::MessageDataType::UInt8, _)
        )
        && matches!(
            shape,
            None | Some(crate::MessageElement::Static(
                0..=16,
                crate::MessageDataType::UInt8,
                _
            ))
        )
}

/// Retain the complete ingress working estimate, including decoder/queue
/// objects, when allocating a previously admitted small control payload.
pub(crate) fn check_small_protected_decode(len: usize) -> TelemetryResult<()> {
    check_frame_kind(len, false, WORK_SMALL_PROTECTED)
}

/// A validated compact wrapper initially materializes only a byte vector and
/// its shared owned frame. Extended-probe users recheck full decoder/routing
/// work before queueing and again at dispatch in Router::rx_item / Relay::process_rx_queue_item.
/// Retain the legacy full estimate when that second check is not installed.
pub(crate) fn check_compact_reconstruction(len: usize, ack: bool) -> TelemetryResult<()> {
    if supports_work_kinds() && !ack && len <= 192 {
        // Two simultaneous byte buffers plus shared ownership, queue bookkeeping
        // and alignment. No schema, graph or payload decoder is created here.
        // This is ordinary work: the application's control reserve is unchanged.
        check(
            512usize.saturating_add(len.saturating_mul(2)),
            len.saturating_add(32),
        )
    } else {
        check_frame(len, ack)
    }
}

pub(crate) fn check_frame(len: usize, ack: bool) -> TelemetryResult<()> {
    check_frame_kind(len, ack, WORK_GENERAL)
}
#[inline(never)]
fn check_frame_kind(len: usize, ack: bool, work: u32) -> TelemetryResult<()> {
    // Only small control frames use reserved headroom. An oversized
    // or malformed control frame must not bypass ordinary allocation admission.
    if ack && len <= 128 {
        check(512, len.saturating_add(32))
    } else {
        check_work(
            len.saturating_mul(3).saturating_add(2048),
            len.saturating_add(32),
            work,
        )
    }
}

/// C ABI for [`set_probe`]. NULL disables admission checks.
#[unsafe(no_mangle)]
pub extern "C" fn seds_set_memory_admission_probe(probe: Option<MemoryAdmissionProbe>) {
    set_probe(probe);
}
/// C ABI for [`set_probe_v2`]. NULL disables both probe variants.
#[unsafe(no_mangle)]
pub extern "C" fn seds_set_memory_admission_probe_v2(probe: Option<MemoryAdmissionProbeV2>) {
    set_probe_v2(probe);
}
/// C ABI for [`rejected_operations`].
#[unsafe(no_mangle)]
pub extern "C" fn seds_memory_admission_rejected() -> usize {
    rejected_operations()
}

/// A refused background operation must not prevent dispatch of retained work.
pub(crate) fn allow_drain<T: Default>(result: TelemetryResult<T>) -> TelemetryResult<T> {
    match result {
        Err(TelemetryError::Io("memory pressure")) => Ok(T::default()),
        other => other,
    }
}
