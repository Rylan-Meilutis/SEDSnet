use super::*;

fn router() -> Router {
    crate::tests::ensure_common_test_schema();
    Router::new(RouterConfig::default())
}

#[test]
fn failover_min_matches_original_sort_exhaustive_and_preserves_allocation() {
    let router = router();
    let mut st = router.state.lock();
    let mut cases = 0;
    for src in [None, Some(99)] {
        st.source_route_modes
            .insert(src, RouteSelectionMode::Failover);
        for priorities in 0..64 {
            let mut encoded = priorities;
            for side in 0..3 {
                st.route_priorities.remove(&(src, side));
                match encoded % 4 {
                    0 => {}
                    1 => {
                        st.route_priorities.insert((src, side), 0);
                    }
                    2 => {
                        st.route_priorities.insert((src, side), 1);
                    }
                    _ => {
                        st.route_priorities.insert((src, side), u32::MAX);
                    }
                }
                encoded /= 4;
            }
            for len in 0..=6_u32 {
                for vector in 0..3_usize.pow(len) {
                    let mut input = Vec::with_capacity(len as usize + 7);
                    let mut encoded = vector;
                    for _ in 0..len {
                        input.push(encoded % 3);
                        encoded /= 3;
                    }
                    let pointer = input.as_ptr();
                    let capacity = input.capacity();
                    let mut expected = input.clone();
                    // The original implementation, including its <=1 early return.
                    if expected.len() > 1 {
                        expected.sort_by_key(|side| {
                            (
                                st.route_priorities.get(&(src, *side)).copied().unwrap_or(0),
                                *side,
                            )
                        });
                        expected.truncate(1);
                    }
                    let actual = router.apply_route_selection_locked(
                        &mut st,
                        src,
                        input,
                        RouteSelectionOrigin::Flood,
                    );
                    assert_eq!(
                        actual, expected,
                        "src={src:?} priorities={priorities} vector={vector} len={len}"
                    );
                    assert_eq!(actual.as_ptr(), pointer, "backing allocation changed");
                    assert_eq!(actual.capacity(), capacity, "capacity changed");
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 139_904);
}

#[test]
fn failover_min_public_policy_controls_keep_fanout_weighted_and_source_scopes() {
    let router = router();
    let a = router.add_side_packet("A", |_| Ok(()));
    let b = router.add_side_packet("B", |_| Ok(()));
    let ingress = router.add_side_packet("IN", |_| Ok(()));
    let select = |src, input| {
        let mut st = router.state.lock();
        router.apply_route_selection_locked(&mut st, src, input, RouteSelectionOrigin::Flood)
    };
    router
        .set_source_route_mode(None, RouteSelectionMode::Failover)
        .unwrap();
    router.set_route_priority(None, a, 2).unwrap();
    router.set_route_priority(None, b, 1).unwrap();
    assert_eq!(select(None, vec![a, b]), vec![b]);
    router.clear_route_priority(None, a).unwrap();
    assert_eq!(select(None, vec![b, a]), vec![a]); // Missing priority defaults to zero.
    router.set_route_priority(None, b, 0).unwrap();
    assert_eq!(select(None, vec![b, a, b]), vec![a.min(b)]); // Equal-key duplicates.
    router
        .set_source_route_mode(Some(ingress), RouteSelectionMode::Failover)
        .unwrap();
    router.set_route_priority(Some(ingress), a, 5).unwrap();
    assert_eq!(select(Some(ingress), vec![a, b]), vec![b]);
    router
        .set_source_route_mode(None, RouteSelectionMode::Fanout)
        .unwrap();
    assert_eq!(select(None, vec![b, a, b]), vec![b, a, b]);
    router
        .set_source_route_mode(None, RouteSelectionMode::Weighted)
        .unwrap();
    router.set_route_weight(None, a, 1).unwrap();
    router.set_route_weight(None, b, 1).unwrap();
    assert_eq!(select(None, vec![b, a]), vec![a.min(b)]);
    assert_eq!(select(None, vec![b, a]), vec![a.max(b)]);
    router.clear_source_route_mode(None).unwrap();
    assert_eq!(select(None, vec![b, a]), vec![b, a]);
}
