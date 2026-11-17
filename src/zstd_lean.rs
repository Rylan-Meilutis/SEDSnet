//! Opt-in `zstd-lean` flash reduction for size-constrained targets.
//!
//! SEDSnet calls zstd only through one-shot level-1 compression
//! (`ZSTD_compress`, or `ZSTD_compress2` with level-1 parameters in the packet
//! arena) and plain frame decompression. Those paths never enable zstd's
//! long-distance matcher (`zstd_ldm.c`: LDM is only auto-enabled for the
//! btopt-and-above strategies with a 128 MiB window, or by an explicit
//! parameter) and never set a target compressed-block size
//! (`zstd_compress_superblock.c`). The compressor still references both from
//! runtime branches, so a static link keeps their code and tables
//! (about 8.6 KB on Cortex-M).
//!
//! With this feature SEDSnet defines those internal entry points itself. The
//! linker resolves zstd's references here, never pulls the two library
//! objects, and every other zstd object is unchanged. Each definition behaves
//! exactly like zstd's for the disabled state SEDSnet always uses (no LDM,
//! empty external sequence store), so frames are byte-for-byte identical.
//! Reaching any other state means LDM, external sequences or a target block
//! size were requested, which this build cannot provide: that panics instead
//! of returning plausible but wrong data.
//!
//! The signatures are zstd's private ABI, so they are pinned to the verified
//! release below. A zstd update fails to compile here until it is re-checked.

use core::ffi::c_void;

// zstd_compress_internal.h / zstd_ldm.h, zstd 1.5.7.
const _: () = assert!(
    zstd_safe::zstd_sys::ZSTD_VERSION_NUMBER == 10507,
    "zstd-lean stubs are verified against zstd 1.5.7 internals; re-check them for this zstd"
);

/// `ZSTD_ps_enable` from `ZSTD_ParamSwitch_e`.
const ZSTD_PS_ENABLE: u32 = 1;

/// `ldmParams_t`, passed by value.
#[repr(C)]
#[allow(dead_code)] // Layout mirror; only `enable_ldm` is read.
#[derive(Clone, Copy)]
pub struct LdmParams {
    enable_ldm: u32,
    hash_log: u32,
    bucket_size_log: u32,
    min_match_length: u32,
    hash_rate_log: u32,
    window_log: u32,
}

/// `RawSeqStore_t`.
#[repr(C)]
#[allow(dead_code)] // Layout mirror; `seq` and `capacity` are never read.
pub struct RawSeqStore {
    seq: *mut c_void,
    pos: usize,
    pos_in_sequence: usize,
    size: usize,
    capacity: usize,
}

#[cold]
#[inline(never)]
fn excluded() -> ! {
    panic!("zstd long-distance matching/target block size excluded by zstd-lean")
}

/// Workspace for LDM tables: zero while LDM is disabled.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_ldm_getTableSize(params: LdmParams) -> usize {
    if params.enable_ldm == ZSTD_PS_ENABLE {
        excluded();
    }
    0
}

/// Maximum LDM sequences per chunk: zero while LDM is disabled.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_ldm_getMaxNbSeq(params: LdmParams, _max_chunk_size: usize) -> usize {
    if params.enable_ldm == ZSTD_PS_ENABLE {
        excluded();
    }
    0
}

/// Called by zstd only once LDM is enabled.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_ldm_adjustParameters(_params: *mut LdmParams, _c_params: *const c_void) {
    excluded()
}

/// Called by zstd only when loading a dictionary with LDM enabled.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_ldm_fillHashTable(
    _state: *mut c_void,
    _ip: *const u8,
    _iend: *const u8,
    _params: *const LdmParams,
) {
    excluded()
}

/// Called by zstd only with LDM enabled.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_ldm_generateSequences(
    _ldms: *mut c_void,
    _sequences: *mut RawSeqStore,
    _params: *const LdmParams,
    _src: *const c_void,
    _src_size: usize,
) -> usize {
    excluded()
}

/// Called by zstd only with LDM enabled or a non-empty external sequence store.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_ldm_blockCompress(
    _raw_seq_store: *mut RawSeqStore,
    _ms: *mut c_void,
    _seq_store: *mut c_void,
    _rep: *mut u32,
    _use_row_match_finder: u32,
    _src: *const c_void,
    _src_size: usize,
) -> usize {
    excluded()
}

/// Skips external sequences for a block too small to compress. zstd calls this
/// for every tiny block; with the empty store SEDSnet always has, zstd's own
/// loop does nothing.
///
/// # Safety
/// `raw_seq_store` must point to a valid `RawSeqStore_t`, as zstd guarantees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ZSTD_ldm_skipSequences(
    raw_seq_store: *mut RawSeqStore,
    src_size: usize,
    _min_match: u32,
) {
    // SAFETY: zstd passes its context's external sequence store.
    let store = unsafe { &*raw_seq_store };
    if src_size > 0 && store.pos < store.size {
        excluded();
    }
}

/// Byte-granular variant used by the optimal parsers; with an empty store
/// zstd only clears `posInSequence`.
///
/// # Safety
/// `raw_seq_store` must point to a valid `RawSeqStore_t`, as zstd guarantees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ZSTD_ldm_skipRawSeqStoreBytes(
    raw_seq_store: *mut RawSeqStore,
    nb_bytes: usize,
) {
    // SAFETY: zstd passes its context's external sequence store.
    let store = unsafe { &mut *raw_seq_store };
    let current = store.pos_in_sequence.wrapping_add(nb_bytes) as u32;
    if current != 0 && store.pos < store.size {
        excluded();
    }
    store.pos_in_sequence = 0;
}

/// Called by zstd only when a target compressed-block size is set.
#[unsafe(no_mangle)]
pub extern "C" fn ZSTD_compressSuperBlock(
    _zc: *mut c_void,
    _dst: *mut c_void,
    _dst_capacity: usize,
    _src: *const c_void,
    _src_size: usize,
    _last_block: u32,
) -> usize {
    excluded()
}
