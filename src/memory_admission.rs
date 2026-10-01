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
static PROBE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static REJECTED: AtomicUsize = AtomicUsize::new(0);

/// Install a process-wide admission probe, or `None` to disable it.
pub fn set_probe(probe: Option<MemoryAdmissionProbe>) {
    PROBE.store(
        probe.map_or(core::ptr::null_mut(), |f| f as *mut ()),
        Ordering::Release,
    );
}
/// Number of operations rejected by the probe, wrapping at usize::MAX.
pub fn rejected_operations() -> usize {
    REJECTED.load(Ordering::Relaxed)
}

pub(crate) fn check(additional_bytes: usize, largest_allocation: usize) -> TelemetryResult<()> {
    let ptr = PROBE.load(Ordering::Acquire);
    if ptr.is_null() {
        return Ok(());
    }
    // SAFETY: only function pointers of this exact signature are stored. Their
    // code remains valid even when a different probe is concurrently installed.
    let probe: MemoryAdmissionProbe = unsafe { core::mem::transmute(ptr) };
    if probe(additional_bytes, largest_allocation) {
        return Ok(());
    }
    REJECTED.fetch_add(1, Ordering::Relaxed);
    Err(TelemetryError::Io("memory pressure"))
}

pub(crate) fn check_receive(bytes: &[u8]) -> TelemetryResult<()> {
    if PROBE.load(Ordering::Relaxed).is_null() {
        return Ok(());
    }
    // Keep a smaller admission requirement for ACKs that can release retained
    // replay buffers. Side wrappers are classified after their header is decoded.
    let ack = crate::wire_format::peek_routing_frame_info(bytes)
        .ok()
        .is_some_and(|frame| {
            frame.ack_only()
                || matches!(
                    frame.envelope.ty,
                    crate::DataType::ReliableAck | crate::DataType::ReliablePartialAck
                )
        });
    check_frame(bytes.len(), ack)
}

pub(crate) fn check_frame(len: usize, ack: bool) -> TelemetryResult<()> {
    // Only small control frames use the reserved ACK headroom. An oversized
    // or malformed ACK must not bypass ordinary allocation admission.
    if ack && len <= 128 {
        check(512, len.saturating_add(32))
    } else {
        check(
            len.saturating_mul(3).saturating_add(2048),
            len.saturating_add(32),
        )
    }
}

/// C ABI for [`set_probe`]. NULL disables admission checks.
#[unsafe(no_mangle)]
pub extern "C" fn seds_set_memory_admission_probe(probe: Option<MemoryAdmissionProbe>) {
    set_probe(probe);
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
