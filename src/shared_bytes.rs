//! Shared wire bytes. The optional arena keeps full-slice views pinned until
//! exclusive queue parking. Default builds retain the original Arc representation.
#[cfg(not(feature = "compact-packet-store"))]
pub type SharedBytes = alloc::sync::Arc<[u8]>;
#[cfg(feature = "compact-packet-store")]
pub type SharedBytes = crate::small_payload::SmallPayload<0>;
