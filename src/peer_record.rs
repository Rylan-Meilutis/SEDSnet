//! Pointer-sized peer index values keep B-tree rotations shared across metadata
//! types. Stage new allocations before changing authoritative peer state.
use crate::{TelemetryError, TelemetryResult};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;

// Pointer storage plus conservative allocator slack is charged separately from
// the pointee. Actual allocator headers/concurrent users can differ; admission
// remains an estimate and a null allocation still returns retryable pressure.
pub(crate) fn allocation_bytes<T>() -> usize {
    core::mem::size_of::<T>()
        .saturating_add(core::mem::size_of::<Box<T>>())
        .saturating_add(4 * core::mem::size_of::<usize>())
}

pub(crate) fn try_string(value: &str) -> TelemetryResult<String> {
    let mut out = String::new();
    out.try_reserve_exact(value.len())
        .map_err(|_| TelemetryError::Io("memory pressure"))?;
    out.push_str(value);
    Ok(out)
}

pub(crate) fn try_box<T>(value: T) -> TelemetryResult<Box<T>> {
    try_box_with(|| value)
}

pub(crate) fn try_box_with<T, F: FnOnce() -> T>(make: F) -> TelemetryResult<Box<T>> {
    let layout = core::alloc::Layout::new::<T>();
    if layout.size() == 0 {
        return Ok(Box::new(make()));
    }
    crate::memory_admission::check(allocation_bytes::<T>(), layout.size())?;
    // SAFETY: the allocation has exactly T's valid/nonzero layout. An owned
    // MaybeUninit box frees storage if make unwinds. Initialize once, then T's
    // ordinary Box owns destruction and deallocation through that same layout.
    let ptr = unsafe { alloc::alloc::alloc(layout).cast::<core::mem::MaybeUninit<T>>() };
    if ptr.is_null() {
        return Err(TelemetryError::Io("memory pressure"));
    }
    let mut out = unsafe { Box::from_raw(ptr) };
    out.write(make());
    Ok(unsafe { out.assume_init() })
}

pub(crate) enum Prepared<'a, T> {
    Existing { key: &'a str, value: T },
    New { key: String, value: Box<T> },
}

pub(crate) fn prepare<'a, T>(
    map: &BTreeMap<String, Box<T>>,
    key: &'a str,
    value: T,
) -> TelemetryResult<Prepared<'a, T>> {
    if map.contains_key(key) {
        return Ok(Prepared::Existing { key, value });
    }
    let value = try_box(value)?;
    let key = try_string(key)?;
    Ok(Prepared::New { key, value })
}

impl<T> Prepared<'_, T> {
    pub(crate) fn commit(self, map: &mut BTreeMap<String, Box<T>>) {
        match self {
            Self::Existing { key, value } => {
                // Preparation/commit stay inside the same caller-owned lock.
                **map.get_mut(key).expect("prepared peer remains present") = value;
            }
            Self::New { key, value } => {
                map.insert(key, value);
            }
        }
    }
}

#[cfg(feature = "discovery")]
pub(crate) fn try_clone_map<T: Clone>(
    map: &BTreeMap<String, Box<T>>,
) -> TelemetryResult<BTreeMap<String, Box<T>>> {
    let mut out = BTreeMap::new();
    for (name, value) in map {
        let record = try_box_with(|| value.as_ref().clone())?;
        out.insert(try_string(name)?, record);
    }
    Ok(out)
}
