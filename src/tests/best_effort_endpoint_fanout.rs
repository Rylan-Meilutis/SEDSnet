//! Actual C-ABI publications must retain independent endpoint roles while
//! selecting one path among redundant alternatives for the same role.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

type Capture = Arc<Mutex<Vec<(usize, u64, Vec<u8>)>>>;
struct Fixture {
    handle: SedsRouter,
    ty: DataType,
    endpoints: Vec<DataEndpoint>,
    sides: Vec<usize>,
    capture: Capture,
    blocked: Arc<Vec<AtomicBool>>,
    now: Arc<AtomicU64>,
}
impl Fixture {
    fn new(name: &str, coverage: &[&[usize]], reliable: crate::ReliableMode) -> Self {
        let names: Vec<String> = (0..3).map(|i| format!("{name}_ROLE_{i}")).collect();
        Self::with_endpoint_names(name, &names, coverage, reliable, None)
    }
    fn with_endpoint_names(
        name: &str,
        names: &[String],
        coverage: &[&[usize]],
        reliable: crate::ReliableMode,
        existing_type_id: Option<DataType>,
    ) -> Self {
        let endpoints: Vec<_> = names
            .iter()
            .map(|name| {
                if let Some(existing) = crate::config::endpoint_definition_by_name(name) {
                    assert!(!existing.link_local_only);
                    existing.id
                } else {
                    crate::config::register_endpoint(name, false).unwrap()
                }
            })
            .collect();
        let ty = crate::config::register_data_type_id_with_description(
            existing_type_id.unwrap_or_else(|| DataType::identity(name)),
            name,
            "",
            MessageElement::Static(
                3,
                crate::MessageDataType::Float32,
                crate::MessageClass::Data,
            ),
            &endpoints,
            reliable,
            255,
        )
        .unwrap();
        let now = Arc::new(AtomicU64::new(1000));
        let clock = now.clone();
        let router = Arc::new(Router::new_with_clock(
            RouterConfig::new([]).with_sender("RF"),
            Box::new(move || clock.load(Ordering::Relaxed)),
        ));
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let blocked = Arc::new(
            (0..coverage.len())
                .map(|_| AtomicBool::new(false))
                .collect::<Vec<_>>(),
        );
        let mut sides = Vec::new();
        for (index, roles) in coverage.iter().enumerate() {
            let sink = capture.clone();
            let busy = blocked.clone();
            let side = router.add_side_packed(format!("{name}_side_{index}"), move |bytes| {
                if crate::wire_format::peek_frame_info(bytes)
                    .is_ok_and(|frame| frame.envelope.ty == ty)
                {
                    if busy[index].load(Ordering::Relaxed) {
                        return Err(TelemetryError::Io("side tx busy"));
                    }
                    let packet = crate::wire_format::unpack_packet(bytes)?;
                    sink.lock().unwrap().push((
                        index,
                        packet.packet_id(),
                        packet.payload().to_vec(),
                    ));
                }
                Ok(())
            });
            let roles: Vec<_> = roles.iter().map(|index| endpoints[*index]).collect();
            router
                .rx_from_side(
                    &crate::discovery::build_discovery_announce(
                        &format!("{name}_peer_{index}"),
                        1,
                        &roles,
                    )
                    .unwrap(),
                    side,
                )
                .unwrap();
            sides.push(side);
        }
        router.process_all_queues_with_timeout(0).unwrap();
        capture.lock().unwrap().clear();
        Self {
            handle: SedsRouter { inner: router },
            ty,
            endpoints,
            sides,
            capture,
            blocked,
            now,
        }
    }
    fn publish(&mut self, value: f32) {
        self.now.fetch_add(1, Ordering::Relaxed);
        let values = [value, -78.0, 150.0];
        assert_eq!(
            seds_router_log_typed(
                &mut self.handle,
                self.ty.as_u32(),
                values.as_ptr().cast(),
                3,
                4,
                SEDS_EK_FLOAT
            ),
            0
        );
    }
    fn counts(&self) -> Vec<usize> {
        let captured = self.capture.lock().unwrap();
        (0..self.sides.len())
            .map(|side| captured.iter().filter(|row| row.0 == side).count())
            .collect()
    }
}

#[test]
fn actual_gps_c_abi_reaches_can_roles_and_ground_station_once() {
    const CHILD: &str = "SEDSNET_GPS_ROLE_FANOUT_CHILD";
    const NAME: &str = "c_api::best_effort_endpoint_fanout::actual_gps_c_abi_reaches_can_roles_and_ground_station_once";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let names: Vec<String> = ["GROUND_STATION", "SD_CARD", "FLIGHT_CONTROLLER"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // build.py seeds its generic GPS test definition (Ordered, SD+RADIO).
    // This isolated child instead exercises the actual RF contract while
    // retaining seeded canonical IDs and all endpoint metadata unchanged.
    let existing_card = crate::config::endpoint_definition_by_name("SD_CARD");
    let existing_type_id =
        crate::config::data_type_definition_by_name("GPS_DATA").map(|definition| {
            assert!(crate::config::remove_data_type(definition.id).unwrap());
            definition.id
        });
    let mut fixture = Fixture::with_endpoint_names(
        "GPS_DATA",
        &names,
        &[&[1, 2], &[0]],
        crate::ReliableMode::None,
        existing_type_id,
    );
    if let Some(expected) = existing_type_id {
        assert_eq!(fixture.ty, expected);
    }
    if let Some(existing) = existing_card {
        assert_eq!(fixture.endpoints[1], existing.id);
        let retained = crate::config::endpoint_definition(existing.id).unwrap();
        assert_eq!(retained.description, existing.description);
        assert_eq!(retained.link_local_only, existing.link_local_only);
    }
    fixture.publish(43.0);
    assert_eq!(fixture.counts(), [1, 1]);
    let capture = fixture.capture.lock().unwrap();
    assert_eq!(capture[0].1, capture[1].1);
    assert_eq!(capture[0].2, capture[1].2);
}

#[test]
fn identical_endpoint_coverage_keeps_one_adaptive_path_per_publication() {
    let mut fixture = Fixture::new(
        "ROLE_FANOUT_REDUNDANT",
        &[&[0, 1, 2], &[0, 1, 2]],
        crate::ReliableMode::None,
    );
    for value in 0..8 {
        fixture.publish(value as f32);
    }
    assert_eq!(fixture.counts().iter().sum::<usize>(), 8);
    let capture = fixture.capture.lock().unwrap();
    let unique: std::collections::BTreeSet<_> = capture.iter().map(|row| row.1).collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn partial_overlap_reuses_selected_side_and_deduplicates_physical_egress() {
    let mut fixture = Fixture::new(
        "ROLE_FANOUT_PARTIAL",
        &[&[0, 1], &[1, 2], &[0, 1]],
        crate::ReliableMode::None,
    );
    fixture.publish(43.0);
    let counts = fixture.counts();
    assert_eq!(counts[0] + counts[2], 1);
    assert_eq!(counts[1], 1);
}

#[test]
fn transient_backpressure_retries_only_unaccepted_role_with_original_identity() {
    let mut fixture = Fixture::new(
        "ROLE_FANOUT_BUSY",
        &[&[1, 2], &[0]],
        crate::ReliableMode::None,
    );
    fixture.blocked[1].store(true, Ordering::Relaxed);
    fixture.publish(43.0);
    assert_eq!(fixture.counts(), [1, 0]);
    fixture.blocked[1].store(false, Ordering::Relaxed);
    fixture.now.fetch_add(1000, Ordering::Relaxed);
    fixture
        .handle
        .inner
        .process_all_queues_with_timeout(0)
        .unwrap();
    assert_eq!(fixture.counts(), [1, 1]);
    fixture.now.fetch_add(1000, Ordering::Relaxed);
    fixture
        .handle
        .inner
        .process_all_queues_with_timeout(0)
        .unwrap();
    assert_eq!(fixture.counts(), [1, 1]);
    let capture = fixture.capture.lock().unwrap();
    assert_eq!(capture[0].1, capture[1].1);
    assert_eq!(capture[0].2, capture[1].2);
}

#[test]
fn explicit_weighted_policy_and_reliable_best_overlap_remain_unchanged() {
    let mut explicit = Fixture::new(
        "ROLE_FANOUT_EXPLICIT",
        &[&[1, 2], &[0]],
        crate::ReliableMode::None,
    );
    explicit
        .handle
        .inner
        .set_source_route_mode(None, RouteSelectionMode::Weighted)
        .unwrap();
    explicit.publish(43.0);
    assert_eq!(explicit.counts().iter().sum::<usize>(), 1);
    let mut reliable = Fixture::new(
        "ROLE_FANOUT_RELIABLE",
        &[&[1, 2], &[0]],
        crate::ReliableMode::Ordered,
    );
    reliable.publish(43.0);
    assert_eq!(reliable.counts(), [1, 0]);
}

#[test]
fn each_role_uses_its_shortest_path_without_reflected_radio_duplicates() {
    use crate::discovery::TopologyBoardNode;
    let name = "ROLE_FANOUT_SHORTEST";
    let mut fixture = Fixture::new(name, &[&[1, 2], &[0], &[0]], crate::ReliableMode::None);
    for index in 0..3 {
        let peer = format!("{name}_peer_{index}");
        let boards = if index < 2 {
            vec![TopologyBoardNode {
                sender_id: peer.clone(),
                reachable_endpoints: if index == 0 {
                    vec![fixture.endpoints[1], fixture.endpoints[2]]
                } else {
                    vec![fixture.endpoints[0]]
                },
                reachable_timesync_sources: Vec::new(),
                connections: Vec::new(),
            }]
        } else {
            vec![
                TopologyBoardNode {
                    sender_id: peer.clone(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["REFLECT_BRIDGE".into()],
                },
                TopologyBoardNode {
                    sender_id: "REFLECT_BRIDGE".into(),
                    reachable_endpoints: Vec::new(),
                    reachable_timesync_sources: Vec::new(),
                    connections: vec![peer.clone(), "REFLECT_GS".into()],
                },
                TopologyBoardNode {
                    sender_id: "REFLECT_GS".into(),
                    reachable_endpoints: vec![fixture.endpoints[0]],
                    reachable_timesync_sources: Vec::new(),
                    connections: vec!["REFLECT_BRIDGE".into()],
                },
            ]
        };
        fixture
            .handle
            .inner
            .rx_from_side(
                &crate::discovery::build_discovery_topology(&peer, 2, &boards).unwrap(),
                fixture.sides[index],
            )
            .unwrap();
    }
    fixture
        .handle
        .inner
        .process_all_queues_with_timeout(0)
        .unwrap();
    fixture.capture.lock().unwrap().clear();
    fixture.publish(43.0);
    assert_eq!(fixture.counts(), [1, 1, 0]);
}
