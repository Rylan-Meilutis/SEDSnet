//! Frame CRC-32 with an optional application-provided implementation.
//!
//! Every SEDSnet frame, side-transport wrapper and compact bundle carries the
//! IEEE 802.3 CRC-32 (zlib/PNG/Ethernet): polynomial `0x04C11DB7` processed
//! reflected (`0xEDB88320`), initial value `0xFFFFFFFF`, reflected input and
//! output, final XOR `0xFFFFFFFF`. The check value of `b"123456789"` is
//! `0xCBF43926`.
//!
//! The default is the software `crc32fast` implementation. A board with a CRC
//! peripheral can install [`set_crc32_fn`] (C: `seds_set_crc32_fn`) once at
//! startup; SEDSnet then uses it for both computing and verifying every CRC.
//! Dispatch costs one atomic load and one indirect call per frame.
use core::sync::atomic::{AtomicPtr, Ordering};

/// zlib-compatible incremental CRC-32: `crc` is the CRC of the bytes already
/// processed (0 before the first byte) and the return value is the CRC of
/// those bytes followed by `len` bytes at `data`. The result must equal the
/// IEEE CRC-32 described in the module docs bit for bit.
///
/// The function is called from every thread (and ISR, when the ISR ingress
/// APIs are used) that touches a router, so it must be reentrant or
/// internally synchronized, nonblocking and must not call SEDSnet. `data` may
/// be dangling when `len == 0` and must not be read in that case.
pub type Crc32Fn = extern "C" fn(crc: u32, data: *const u8, len: usize) -> u32;

static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install a process-wide CRC-32 implementation, or `None` for the software
/// default. Install it before routers run; frames already in flight keep the
/// CRC they were built with, and any compliant implementation verifies them.
pub fn set_crc32_fn(f: Option<Crc32Fn>) {
    HOOK.store(f.map_or(core::ptr::null_mut(), |f| f as *mut ()), Ordering::Release);
}

/// The installed implementation, if any.
pub fn crc32_fn() -> Option<Crc32Fn> {
    let ptr = HOOK.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: only `Crc32Fn` values are ever stored in `HOOK`.
        Some(unsafe { core::mem::transmute::<*mut (), Crc32Fn>(ptr) })
    }
}

/// Software CRC-32 of `data` (the default implementation).
#[inline]
pub fn crc32_software(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// CRC-32 of `data` using the installed implementation.
#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    #[cfg(all(test, feature = "std"))]
    counters::note(data.len());
    match crc32_fn() {
        Some(f) => f(0, data.as_ptr(), data.len()),
        None => crc32_software(data),
    }
}

/// Incremental CRC-32 over several slices, using the installed implementation.
pub(crate) struct Crc32 {
    state: State,
}

enum State {
    Software(crc32fast::Hasher),
    Hook(Crc32Fn, u32),
}

impl Crc32 {
    #[inline]
    pub(crate) fn new() -> Self {
        #[cfg(all(test, feature = "std"))]
        counters::note(0);
        Self {
            state: match crc32_fn() {
                Some(f) => State::Hook(f, 0),
                None => State::Software(crc32fast::Hasher::new()),
            },
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        #[cfg(all(test, feature = "std"))]
        counters::note_bytes(data.len());
        match &mut self.state {
            State::Software(hasher) => hasher.update(data),
            State::Hook(f, crc) => *crc = f(*crc, data.as_ptr(), data.len()),
        }
    }

    #[inline]
    pub(crate) fn finalize(self) -> u32 {
        match self.state {
            State::Software(hasher) => hasher.finalize(),
            State::Hook(_, crc) => crc,
        }
    }
}

/// C ABI for [`set_crc32_fn`]. NULL restores the software default.
#[unsafe(no_mangle)]
pub extern "C" fn seds_set_crc32_fn(f: Option<Crc32Fn>) {
    set_crc32_fn(f);
}

/// Per-thread CRC work counters for host tests.
#[cfg(all(test, feature = "std"))]
pub(crate) mod counters {
    use core::cell::Cell;
    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static BYTES: Cell<usize> = const { Cell::new(0) };
    }
    pub(super) fn note(len: usize) {
        CALLS.with(|c| c.set(c.get() + 1));
        note_bytes(len);
    }
    pub(super) fn note_bytes(len: usize) {
        BYTES.with(|c| c.set(c.get() + len));
    }
    /// (CRC computations started, bytes hashed) on this thread so far.
    pub(crate) fn snapshot() -> (usize, usize) {
        (CALLS.with(Cell::get), BYTES.with(Cell::get))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // Reference bitwise IEEE CRC-32 with zlib continuation, independent of
    // crc32fast, fed through the hook exactly as a board would install it.
    fn reference(crc: u32, data: &[u8]) -> u32 {
        let mut state = !crc;
        for &byte in data {
            state ^= u32::from(byte);
            for _ in 0..8 {
                state = (state >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(state & 1));
            }
        }
        !state
    }
    extern "C" fn reference_hook(crc: u32, data: *const u8, len: usize) -> u32 {
        HOOK_CALLS.with(|c| c.set(c.get() + 1));
        let data = if len == 0 {
            &[][..]
        } else {
            // SAFETY: SEDSnet passes a valid slice of `len` bytes.
            unsafe { core::slice::from_raw_parts(data, len) }
        };
        reference(crc, data)
    }
    std::thread_local! {
        static HOOK_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    // The hook is process-wide; serialize the tests that install one.
    pub(crate) static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn buffers() -> Vec<Vec<u8>> {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        };
        let mut out = Vec::new();
        for len in (0..=8).chain([63, 64, 1500]) {
            out.push((0..len).map(|_| next()).collect());
        }
        for _ in 0..200 {
            let len = usize::from(next()) * 7 % 1600;
            out.push((0..len).map(|_| next()).collect());
        }
        out
    }

    #[test]
    fn crc32_parameters_match_ieee_check_value() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(crc32_software(b"123456789"), 0xCBF4_3926);
        assert_eq!(reference(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_software(b""), 0);
    }

    #[test]
    fn installed_reference_crc_matches_software_on_boundaries_and_random_buffers() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let buffers = buffers();
        let software: Vec<u32> = buffers.iter().map(|b| crc32_software(b)).collect();
        set_crc32_fn(Some(reference_hook));
        let before = HOOK_CALLS.with(core::cell::Cell::get);
        for (buf, expected) in buffers.iter().zip(&software) {
            assert_eq!(crc32(buf), *expected, "one-shot, len {}", buf.len());
            // Incremental: every split point of short buffers, and a few of
            // the longer ones, must give the same CRC.
            let splits: Vec<usize> = if buf.len() <= 16 {
                (0..=buf.len()).collect()
            } else {
                vec![0, 1, 3, buf.len() / 2, buf.len() - 1, buf.len()]
            };
            for split in splits {
                let mut crc = Crc32::new();
                crc.update(&buf[..split]);
                crc.update(&buf[split..]);
                assert_eq!(crc.finalize(), *expected, "split {split} of {}", buf.len());
            }
        }
        assert!(HOOK_CALLS.with(core::cell::Cell::get) > before, "hook was not used");
        set_crc32_fn(None);
        for (buf, expected) in buffers.iter().zip(&software) {
            assert_eq!(crc32(buf), *expected);
        }
    }

    #[test]
    fn frames_built_and_verified_through_the_hook_interoperate_with_software() {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::tests::ensure_common_test_schema();
        let ty = crate::DataType::try_named("BATTERY_STATUS").unwrap();
        let packet = crate::packet::Packet::new(
            ty,
            &[crate::DataEndpoint::try_named("SD_CARD").unwrap()],
            "VB",
            1234,
            alloc::sync::Arc::from([7u8; 8]),
        )
        .unwrap();
        let soft = crate::wire_format::pack_packet(&packet);
        set_crc32_fn(Some(reference_hook));
        let before = HOOK_CALLS.with(core::cell::Cell::get);
        let hooked = crate::wire_format::pack_packet(&packet);
        assert_eq!(soft, hooked);
        assert!(crate::wire_format::peek_frame_info(&soft).is_ok());
        let mut bad = soft.to_vec();
        bad[3] ^= 0x40;
        assert!(crate::wire_format::peek_frame_info(&bad).is_err());
        assert!(HOOK_CALLS.with(core::cell::Cell::get) >= before + 3);
        set_crc32_fn(None);
        assert!(crate::wire_format::peek_frame_info(&hooked).is_ok());
    }
}
