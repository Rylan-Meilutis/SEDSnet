use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

fn schema(name: &str) -> (DataType, DataEndpoint) {
    let ep = crate::config::register_endpoint(name, false).unwrap();
    let ty = crate::config::register_data_type(
        name,
        MessageElement::Static(1, crate::MessageDataType::UInt8, crate::MessageClass::Data),
        &[ep],
        crate::ReliableMode::None,
        0,
    )
    .unwrap();
    (ty, ep)
}

#[test]
fn c_cache_retirement_validates_handles_and_optional_outputs() {
    let (ty, ep) = schema("C_CACHE_RETIREMENT");
    let bad = status_from_err(TelemetryError::BadArg);
    let mut removed = true;
    let mut count = 77;
    assert_eq!(
        seds_router_invalidate_network_variable_cache(ptr::null_mut(), ty, &mut removed),
        bad
    );
    assert_eq!(
        seds_router_clear_network_variable_caches(ptr::null_mut(), &mut count),
        bad
    );
    assert!(removed);
    assert_eq!(count, 77);
    let mut handle = SedsRouter {
        inner: Arc::new(Router::new(RouterConfig::new([]))),
    };
    assert_eq!(
        seds_router_enable_network_variable(&mut handle, ty, true, false),
        0
    );
    let value = Packet::new(ty, &[ep], "CACHE_WRITER", 41, Arc::from([1])).unwrap();
    let wire = pack_packet(&value);
    assert_eq!(
        seds_router_seed_managed_variable_packed(&mut handle, wire.as_ptr(), wire.len()),
        0
    );
    assert_eq!(
        seds_router_invalidate_network_variable_cache(&mut handle, ty, &mut removed),
        0
    );
    assert!(removed);
    assert_eq!(
        seds_router_cached_managed_variable_packed_len(&mut handle, ty),
        0
    );
    assert_eq!(
        seds_router_invalidate_network_variable_cache(&mut handle, ty, ptr::null_mut()),
        0
    );
    assert_eq!(
        seds_router_seed_managed_variable_packed(&mut handle, wire.as_ptr(), wire.len()),
        0
    );
    assert_eq!(
        seds_router_clear_network_variable_caches(&mut handle, &mut count),
        0
    );
    assert_eq!(count, 1);
    assert_eq!(
        seds_router_clear_network_variable_caches(&mut handle, ptr::null_mut()),
        0
    );
    assert_eq!(
        seds_router_set_network_variable_packed(&mut handle, wire.as_ptr(), wire.len()),
        status_from_err(TelemetryError::PermissionDenied)
    );
    let mut relay = SedsRouter {
        inner: Arc::new(Router::new(RouterConfig::relay())),
    };
    assert_eq!(
        seds_router_invalidate_network_variable_cache(&mut relay, ty, &mut removed),
        0
    );
    assert!(!removed);
    assert_eq!(
        seds_router_clear_network_variable_caches(&mut relay, &mut count),
        0
    );
    assert_eq!(count, 0);
    assert!(matches!(
        relay.inner.tx(value),
        Err(TelemetryError::PermissionDenied)
    ));
}

struct RetryState {
    router: *mut SedsRouter,
    ty: DataType,
    calls: AtomicUsize,
    retire: bool,
}
extern "C" fn reject_first(_packet: *const SedsPacketView, user: *mut c_void) -> i32 {
    let state = unsafe { &*(user as *const RetryState) };
    if state.calls.fetch_add(1, Ordering::Relaxed) == 0 {
        if state.retire {
            let mut removed = false;
            assert_eq!(
                seds_router_invalidate_network_variable_cache(state.router, state.ty, &mut removed),
                0
            );
            assert!(removed);
        }
        return status_from_err(TelemetryError::HandlerError("injected owner refusal"));
    }
    0
}

#[test]
fn c_callback_can_retire_rejected_packet_and_keep_exact_wire_retry() {
    for retire in [false, true] {
        let (ty, ep) = schema(if retire {
            "C_CACHE_RETRY_RETIRE"
        } else {
            "C_CACHE_RETRY_CONTROL"
        });
        let mut handle = SedsRouter {
            inner: Arc::new(Router::new(RouterConfig::new([
                EndpointHandler::new_packet_handler(ep, |_| Ok(())),
            ]))),
        };
        let mut state = RetryState {
            router: &mut handle,
            ty,
            calls: AtomicUsize::new(0),
            retire,
        };
        assert_eq!(
            seds_router_enable_network_variable(&mut handle, ty, true, false),
            0
        );
        assert_eq!(
            seds_router_on_network_variable_update(
                &mut handle,
                ty,
                Some(reject_first),
                (&mut state as *mut RetryState).cast()
            ),
            0
        );
        let side = handle.inner.add_side_packed("source", |_| Ok(()));
        let packet = Packet::new(ty, &[ep], "CACHE_WRITER", 42, Arc::from([2])).unwrap();
        let bytes = pack_packet(&packet);
        assert_ne!(
            seds_router_receive_packed_from_side(
                &mut handle,
                side as u32,
                bytes.as_ptr(),
                bytes.len()
            ),
            0
        );
        assert_eq!(state.calls.load(Ordering::Relaxed), 1);
        assert_eq!(handle.inner.cached_managed_variable(ty).is_none(), retire);
        assert_eq!(
            seds_router_receive_packed_from_side(
                &mut handle,
                side as u32,
                bytes.as_ptr(),
                bytes.len()
            ),
            0
        );
        assert_eq!(
            state.calls.load(Ordering::Relaxed),
            if retire { 2 } else { 1 },
            "negative control keeps the original poisoned-cache behavior; explicit retirement must allow its exact retry"
        );
    }
}
