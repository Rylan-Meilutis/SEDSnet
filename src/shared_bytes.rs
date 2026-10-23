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

/// Queue inspection must not retain a full-slice pin after classification.
pub(crate) fn with_slice<R>(
    bytes: &SharedBytes,
    read: impl FnOnce(&[u8]) -> R,
) -> crate::TelemetryResult<R> {
    #[cfg(feature = "compact-packet-store")]
    {
        bytes.with_slice(read)
    }
    #[cfg(not(feature = "compact-packet-store"))]
    {
        Ok(read(bytes))
    }
}

#[cfg(all(test, feature = "compact-packet-store", feature = "std"))]
mod scoped_inspection_tests {
    use super::*;
    #[test]
    fn queue_inspection_releases_its_pin_and_preserves_existing_consumer_pins() {
        let store = crate::packet_store::PacketStore::new(64, 4, usize::MAX).unwrap();
        let bytes = SharedBytes::Managed(crate::packet_store::ParkedPayload::new(
            store.store(&[7; 32]).unwrap(),
        ));
        assert_eq!(store.stats().pinned_bytes, 0);
        for _ in 0..32 {
            assert_eq!(
                with_slice(&bytes, |view| {
                    assert_eq!(store.stats().pinned_bytes, 32);
                    view[0]
                })
                .unwrap(),
                7
            );
            assert_eq!(store.stats().pinned_bytes, 0);
        }
        let consumer = bytes.as_ref();
        with_slice(&bytes, |view| assert_eq!(view, consumer)).unwrap();
        assert_eq!(store.stats().pinned_bytes, 32);
        assert_eq!(consumer, &[7; 32]);
    }
}
