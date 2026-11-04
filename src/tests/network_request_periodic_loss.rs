//! Actual unreliable RFD/CAN-side periodic baseline repair; no hop-retry guarantee.
//! The reliable-side coupled loss failure is retained separately, not waived.
use super::*;
use std::collections::VecDeque;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

static CASE: Mutex<()> = Mutex::new(());
type Bus = Arc<Mutex<VecDeque<(usize, Vec<u8>)>>>;
#[derive(Default)]
struct Evidence {
    requests: [usize; 2],
    first_request_drops: [usize; 2],
    withheld_publications: [usize; 2],
    delivered_publications: [usize; 2],
    announce_delivered: bool,
    request_identities: Vec<(u32, u64, u64)>,
}
fn baseline_class(ty: DataType) -> Option<usize> {
    match ty {
        DataType::DiscoveryTopology => Some(0),
        DataType::DiscoverySchema => Some(1),
        _ => None,
    }
}
fn request_class(ty: DataType) -> Option<usize> {
    match ty {
        DataType::DiscoveryTopologyRequest => Some(0),
        DataType::DiscoverySchemaRequest => Some(1),
        _ => None,
    }
}
fn drain(nodes: &[Router], sides: &[RouterSideId], bus: &Bus) {
    // Same finite drain count as the existing bootstrap fixture. Clock reads
    // never advance the shared clock; each outer round advances it once.
    for _ in 0..8 {
        for node in nodes {
            node.process_all_queues().unwrap();
        }
        let queued = bus.lock().unwrap().drain(..).collect::<Vec<_>>();
        for (destination, bytes) in queued {
            nodes[destination]
                .rx_packed_from_side(&bytes, sides[destination])
                .unwrap();
        }
    }
}
#[test]
fn actual_unreliable_radio_side_periodic_baseline_reissues_lost_requests() {
    let _case = CASE.lock().unwrap_or_else(|error| error.into_inner());
    crate::tests::ensure_common_test_schema();
    let clock = Arc::new(AtomicU64::new(10_000));
    let bus: Bus = Arc::new(Mutex::new(VecDeque::new()));
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let mut nodes = Vec::new();
    let mut sides = Vec::new();
    for (index, name) in ["PERIODIC_READER", "PERIODIC_WRITER"]
        .into_iter()
        .enumerate()
    {
        let c = clock.clone();
        let node = Router::new_with_clock(
            RouterConfig::new([]).with_sender(name),
            Box::new(move || c.load(Ordering::SeqCst)),
        );
        let output = bus.clone();
        let observed = evidence.clone();
        let side = node.add_side_packed_with_options(
            "actual-baseline-link",
            move |bytes| {
                let frame = wire_format::peek_frame_info(bytes)?;
                let packet = wire_format::unpack_packet(bytes)?;
                let ty = packet.data_type();
                let mut state = observed.lock().unwrap();
                let mut drop = false;
                if index == 0 {
                    if let Some(class) = request_class(ty) {
                        state.requests[class] += 1;
                        let header = frame
                            .reliable
                            .expect("request retains explicit UNSEQUENCED envelope");
                        assert_eq!(header.flags, wire_format::RELIABLE_FLAG_UNSEQUENCED);
                        assert_eq!(header.seq, 0, "no Ordered sequence allocated for 11/12");
                        assert!(
                            state.request_identities.len() < 128,
                            "bounded request evidence"
                        );
                        state.request_identities.push((
                            ty.as_u32(),
                            packet.packet_id(),
                            packet.timestamp(),
                        ));
                        if state.requests[class] == 1 {
                            state.first_request_drops[class] += 1;
                            drop = true;
                        }
                    }
                } else if let Some(class) = baseline_class(ty) {
                    // Initial unsolicited baselines (and spontaneous replacements)
                    // cannot erase the missing-baseline premise before the actual
                    // periodic worker has reissued this class after first loss.
                    if state.requests[class] < 2 {
                        state.withheld_publications[class] += 1;
                        drop = true;
                    } else {
                        state.delivered_publications[class] += 1;
                    }
                } else if matches!(ty,DataType::DiscoveryAnnounce|DataType::DiscoveryAddress) {
                    state.announce_delivered = true;
                }
                core::mem::drop(state);
                if !drop {
                    let mut queue = output.lock().unwrap();
                    assert!(queue.len() < 4096, "bounded transport fixture");
                    queue.push_back((1 - index, bytes.to_vec()));
                }
                Ok(())
            },
            RouterSideOptions {
                // Matches actual configured RFD/CAN sides: periodic baseline repair,
                // not a guarantee that hop Schema can survive unlimited loss.
                reliable_enabled: false,
                link_local_enabled: true,
                ..Default::default()
            },
        );
        nodes.push(node);
        sides.push(side);
    }
    for node in &nodes {
        node.announce_discovery().unwrap();
    }
    drain(&nodes, &sides, &bus);
    {
        let state = nodes[0].state.lock();
        let peer = &state.discovery_routes[&sides[0]].announcers["PERIODIC_WRITER"];
        assert!(
            !peer.has_full_topology && !peer.has_schema,
            "real Announce must establish an actual missing baseline, not forced map state"
        );
    }
    assert!(evidence.lock().unwrap().announce_delivered);
    for _ in 0..30 {
        clock.fetch_add(1000, Ordering::SeqCst);
        drain(&nodes, &sides, &bus);
    }
    {
        let state = nodes[0].state.lock();
        let peer = &state.discovery_routes[&sides[0]].announcers["PERIODIC_WRITER"];
        assert!(
            peer.has_full_topology,
            "actual topology parser must complete the retained baseline"
        );
        assert!(
            peer.has_schema,
            "actual catalog parser must complete the retained baseline"
        );
    }
    let state = evidence.lock().unwrap();
    assert_eq!(state.first_request_drops, [1, 1]);
    for class in 0..2 {
        assert!(
            state.requests[class] >= 2,
            "actual periodic worker must reissue each lost request"
        );
        assert!(
            state.withheld_publications[class] > 0,
            "unsolicited baseline loss must be exercised"
        );
        assert!(
            state.delivered_publications[class] > 0,
            "actual reply/baseline must traverse transport"
        );
        let ty = if class == 0 {
            DataType::DiscoveryTopologyRequest
        } else {
            DataType::DiscoverySchemaRequest
        };
        let attempts = state
            .request_identities
            .iter()
            .filter(|(kind, _, _)| *kind == ty.as_u32())
            .collect::<Vec<_>>();
        assert_ne!(
            attempts[0].1, attempts[1].1,
            "periodic repair is a new request, not an Ordered retry"
        );
        assert!(
            attempts[1].2 > attempts[0].2,
            "original UTC of the later actual request must advance"
        );
    }
    println!(
        "PERIODIC_REQUEST_LOSS requests={:?} first_drops={:?} initial_withheld={:?} delivered={:?} ids={:?}",
        state.requests,
        state.first_request_drops,
        state.withheld_publications,
        state.delivered_publications,
        state.request_identities
    );
}
