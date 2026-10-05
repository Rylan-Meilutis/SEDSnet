//! Shared wire bytes. The optional arena keeps full-slice views pinned until
//! exclusive queue parking. Default builds retain the original Arc representation.
#[cfg(not(feature = "compact-packet-store"))]
pub type SharedBytes = alloc::sync::Arc<[u8]>;
#[cfg(feature = "compact-packet-store")]
pub type SharedBytes = crate::small_payload::SmallPayload<0>;

/// Convert between owned and arena-aware bytes using the destination type.
/// Keeping this generic supports both directions and the default Arc alias
/// without feature-dependent identity-conversion lints at each call site.
#[inline]
pub(crate) fn convert<T: Into<U>, U>(bytes: T) -> U {
    bytes.into()
}
