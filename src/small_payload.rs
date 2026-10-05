//! Small, inline-optimized payload storage with configurable inline capacity.
//!
//! This module provides [`GenericSmallPayload`], a tiny enum that stores short
//! payloads inline on the stack and transparently spills to the heap when
//! they exceed the inline capacity `INLINE`.
//!
//! It derefs to `&[u8]`, so you can pass it anywhere a byte slice is expected.

use crate::queue::ByteCost;
use alloc::sync::Arc;
use core::{fmt, mem::MaybeUninit, ops::Deref, ptr};

/// Compact payload container with inline storage for small byte buffers.
///
/// - If `len <= INLINE`, the data is stored directly in the `Inline` variant.
/// - Otherwise, the data is stored in an `Arc<[u8]>` in the `Heap` variant.
///
/// Use [`SmallPayload::new`] to construct instances; prefer
/// [`SmallPayload::as_slice`] or `Deref` to treat it as `&[u8]`.
#[derive(Clone)]
pub enum SmallPayload<const INLINE: usize> {
    /// Inline storage for small payloads.
    ///
    /// - `len` is the number of valid bytes stored in `buf`.
    /// - `buf` has capacity `INLINE` bytes, but we only initialize the first `len`.
    Inline { len: u8, buf: InlineBuf<INLINE> },

    /// Heap-backed payload for larger data.
    ///
    /// Stores the bytes in a reference-counted slice.
    Heap(Arc<[u8]>),
    #[cfg(feature = "compact-packet-store")]
    Managed(crate::packet_store::ParkedPayload),
}

/// Helper type wrapping the uninitialized inline buffer.
#[derive(Clone)]
pub struct InlineBuf<const N: usize> {
    buf: [MaybeUninit<u8>; N],
    #[cfg(feature = "compact-packet-store")]
    initialized: u8,
}

impl<const N: usize> InlineBuf<N> {
    /// Create an inline buffer from a slice.
    ///
    /// # Panics
    /// Panics if `data.len() > N` or `data.len() > u8::MAX`.
    #[inline]
    pub fn from_slice(data: &[u8]) -> (Self, u8) {
        assert!(
            data.len() <= N,
            "InlineBuf capacity exceeded: data.len()={}, capacity={}",
            data.len(),
            N
        );
        assert!(
            data.len() <= u8::MAX as usize,
            "InlineBuf len does not fit in u8: {}",
            data.len()
        );

        // SAFETY: `[MaybeUninit<u8>; N]` is allowed to be left uninitialized.
        let mut buf: [MaybeUninit<u8>; N] = unsafe { MaybeUninit::uninit().assume_init() };

        if !data.is_empty() {
            // SAFETY:
            // - `data.as_ptr()` is valid for `data.len()` reads.
            // - `buf.as_mut_ptr()` is valid for `N` writes, and we only
            //   write `data.len()` bytes (≤ N).
            // - The regions do not overlap.
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), buf.as_mut_ptr() as *mut u8, data.len());
            }
        }

        (
            InlineBuf {
                buf,
                #[cfg(feature = "compact-packet-store")]
                initialized: data.len() as u8,
            },
            data.len() as u8,
        )
    }

    /// View the first `len` bytes as an initialized slice.
    ///
    /// # Safety
    /// This relies on the invariant that the first `len` bytes were
    /// initialized by `from_slice`.
    #[inline]
    pub fn as_slice(&self, len: u8) -> &[u8] {
        #[cfg(feature = "compact-packet-store")]
        assert!(
            len <= self.initialized,
            "inline slice exceeds initialized bytes"
        );
        let len = len as usize;
        // SAFETY:
        // - `self.buf.as_ptr()` points to `N` contiguous `MaybeUninit<u8>`.
        // - We guarantee the first `len` elements have been fully initialized.
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr() as *const u8, len) }
    }
}

// ===========================================================================
// Core API
// ===========================================================================

impl<const INLINE: usize> SmallPayload<INLINE> {
    /// Construct a new [`SmallPayload`] from a byte slice.
    ///
    /// - If `data.len() <= INLINE`, the bytes are copied into inline storage
    ///   without zeroing the entire buffer.
    /// - Otherwise, the bytes are stored in an `Arc<[u8]>`.
    #[inline]
    pub fn new(data: &[u8]) -> Self {
        if data.len() <= INLINE && data.len() <= u8::MAX as usize {
            let (buf, len) = InlineBuf::<INLINE>::from_slice(data);
            Self::Inline { len, buf }
        } else {
            Self::Heap(Arc::from(data))
        }
    }

    /// Consume an existing shared payload without copying its heap storage.
    ///
    /// Small values are still moved inline. Large values retain the supplied
    /// `Arc`, which avoids a second payload-sized allocation during packet
    /// construction. This is particularly important for discovery schemas on
    /// fragmented embedded heaps.
    #[inline]
    pub fn from_arc(data: Arc<[u8]>) -> Self {
        if data.len() <= INLINE && data.len() <= u8::MAX as usize {
            let (buf, len) = InlineBuf::<INLINE>::from_slice(&data);
            Self::Inline { len, buf }
        } else {
            Self::Heap(data)
        }
    }

    /// Byte cost of the payload (for use in byte-limited queues).
    #[inline]
    fn byte_cost(&self) -> usize {
        match self {
            SmallPayload::Inline { len, .. } => *len as usize,
            SmallPayload::Heap(a) => a.len() + size_of::<Arc<[u8]>>(),
            #[cfg(feature = "compact-packet-store")]
            SmallPayload::Managed(a) => a.len(),
        }
    }

    /// Return the payload as a borrowed byte slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            SmallPayload::Inline { len, buf } => buf.as_slice(*len),
            SmallPayload::Heap(arc) => arc,
            #[cfg(feature = "compact-packet-store")]
            SmallPayload::Managed(a) => a.as_slice(),
        }
    }

    /// Return the payload as an owned `Arc<[u8]>`.
    ///
    /// - For inline payloads this allocates a new `Arc<[u8]>`.
    /// - For heap-backed payloads this simply clones the existing `Arc`.
    #[inline]
    #[allow(dead_code)]
    pub fn to_arc(&self) -> Arc<[u8]> {
        match self {
            SmallPayload::Inline { len, buf } => {
                // We know only the first `len` bytes are initialized.
                Arc::from(buf.as_slice(*len))
            }
            SmallPayload::Heap(arc) => arc.clone(),
            #[cfg(feature = "compact-packet-store")]
            SmallPayload::Managed(a) => Arc::from(a.as_slice()),
        }
    }

    /// Length of the payload in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            SmallPayload::Inline { len, .. } => *len as usize,
            SmallPayload::Heap(a) => a.len(),
            #[cfg(feature = "compact-packet-store")]
            SmallPayload::Managed(a) => a.len(),
        }
    }

    #[cfg(feature = "compact-packet-store")]
    pub(crate) fn park_for_queue(&mut self) -> crate::TelemetryResult<()> {
        if let Self::Managed(payload) = self {
            payload.park();
            return Ok(());
        }
        if let Some(store) = crate::packet_store::default_store() {
            self.park_in_store(&store)?;
        }
        Ok(())
    }
    #[cfg(feature = "compact-packet-store")]
    pub(crate) fn park_in_store(
        &mut self,
        store: &Arc<crate::packet_store::PacketStore>,
    ) -> crate::TelemetryResult<()> {
        match self {
            Self::Managed(payload) => payload.park(),
            Self::Heap(bytes) => {
                let handle = store.store_shared(bytes)?;
                *self = Self::Managed(crate::packet_store::ParkedPayload::new(handle));
            }
            Self::Inline { .. } => {}
        }
        Ok(())
    }
    /// Copy a field/range into caller storage without permanently pinning it.
    pub fn read_range(&self, offset: usize, out: &mut [u8]) -> crate::TelemetryResult<()> {
        #[cfg(feature = "compact-packet-store")]
        if let Self::Managed(payload) = self {
            return payload.read_range(offset, out);
        }
        let end = offset
            .checked_add(out.len())
            .filter(|&n| n <= self.len())
            .ok_or(crate::TelemetryError::Unpack("payload range out of bounds"))?;
        out.copy_from_slice(&self.as_slice()[offset..end]);
        Ok(())
    }

    /// Returns `true` if the payload is stored inline on the stack.
    #[inline]
    #[allow(dead_code)]
    pub fn is_inline(&self) -> bool {
        matches!(self, SmallPayload::Inline { .. })
    }
}

// ===========================================================================
// Trait impls
// ===========================================================================

impl<const INLINE: usize> fmt::Debug for SmallPayload<INLINE> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline { len, .. } => {
                write!(f, "SmallPayload::Inline({} bytes)", len)
            }
            #[cfg(feature = "compact-packet-store")]
            Self::Managed(a) => a.fmt(f),
            Self::Heap(a) => {
                write!(f, "SmallPayload::Heap({} bytes)", a.len())
            }
        }
    }
}

impl<const INLINE: usize> Deref for SmallPayload<INLINE> {
    type Target = [u8];

    /// Deref to the underlying payload slice.
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const INLINE: usize> PartialEq for SmallPayload<INLINE> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const INLINE: usize> Eq for SmallPayload<INLINE> {}

impl<const INLINE: usize> PartialEq<[u8]> for SmallPayload<INLINE> {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl<const INLINE: usize> PartialEq<SmallPayload<INLINE>> for [u8] {
    #[inline]
    fn eq(&self, other: &SmallPayload<INLINE>) -> bool {
        self == other.as_slice()
    }
}

impl<const INLINE: usize> PartialEq<Arc<[u8]>> for SmallPayload<INLINE> {
    #[inline]
    fn eq(&self, other: &Arc<[u8]>) -> bool {
        self.as_slice() == other.as_ref()
    }
}

impl<const INLINE: usize> ByteCost for SmallPayload<INLINE> {
    #[inline]
    fn byte_cost(&self) -> usize {
        self.byte_cost()
    }
}

impl<const INLINE: usize> AsRef<[u8]> for SmallPayload<INLINE> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl<const INLINE: usize> From<Arc<[u8]>> for SmallPayload<INLINE> {
    fn from(bytes: Arc<[u8]>) -> Self {
        Self::from_arc(bytes)
    }
}
impl<const INLINE: usize> From<alloc::vec::Vec<u8>> for SmallPayload<INLINE> {
    fn from(bytes: alloc::vec::Vec<u8>) -> Self {
        Self::from_arc(Arc::from(bytes))
    }
}
impl<const INLINE: usize> From<&[u8]> for SmallPayload<INLINE> {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}
impl<const INLINE: usize, const N: usize> From<[u8; N]> for SmallPayload<INLINE> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(&bytes)
    }
}

impl<const INLINE: usize> From<SmallPayload<INLINE>> for Arc<[u8]> {
    fn from(bytes: SmallPayload<INLINE>) -> Self {
        bytes.to_arc()
    }
}

#[cfg(all(test, feature = "compact-packet-store"))]
mod inline_view_safety {
    use super::*;
    #[test]
    #[should_panic(expected = "inline slice exceeds initialized bytes")]
    fn altered_inline_length_cannot_expose_uninitialized_bytes() {
        let mut payload = SmallPayload::<64>::new(&[1]);
        if let SmallPayload::Inline { len, .. } = &mut payload {
            *len = 64;
        }
        let _ = payload.as_slice();
    }
    #[test]
    fn large_inline_configuration_spills_lengths_not_representable_by_u8() {
        let payload = SmallPayload::<512>::new(&[9; 256]);
        assert_eq!(payload.as_slice(), &[9; 256]);
        assert!(!payload.is_inline());
    }
}

#[cfg(test)]
mod tests {
    use super::SmallPayload;
    use alloc::sync::Arc;

    #[test]
    fn from_arc_reuses_large_payload_allocation() {
        let original: Arc<[u8]> = Arc::from([0x5a; 65]);
        let retained = original.clone();
        let payload = SmallPayload::<64>::from_arc(original);
        let SmallPayload::Heap(stored) = payload else {
            panic!("large payload must use heap storage");
        };
        assert!(Arc::ptr_eq(&stored, &retained));
    }

    #[test]
    fn from_arc_keeps_small_payload_inline() {
        let payload = SmallPayload::<64>::from_arc(Arc::from([1, 2, 3]));
        assert!(payload.is_inline());
        assert_eq!(payload.as_slice(), [1, 2, 3]);
    }
}
