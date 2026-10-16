#![cfg(all(feature = "std", feature = "discovery"))]
use sedsnet::config::{
    register_data_type_with_description, register_endpoint_with_description, runtime_tuning_config,
    set_runtime_tuning_config,
};
use sedsnet::discovery::{TopologyBoardNode, build_discovery_topology};
use sedsnet::packet::Packet;
use sedsnet::router::{EndpointHandler, Router, RouterConfig, RouterSideOptions};
use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

#[derive(Clone)]
struct Frame {
    at: u64,
    node: usize,
    side: usize,
    bytes: Vec<u8>,
}

// A real application effect with one lost return receipt must not be invoked
// twice. Exercise GS -> RF -> FC and both return hops with finite wire delay.
#[test]
fn one_lost_radio_receipt_recovers_inside_the_configured_retry_window() {
    let saved = runtime_tuning_config();
    struct Restore(sedsnet::config::RuntimeTuningConfig);
    impl Drop for Restore {
        fn drop(&mut self) {
            set_runtime_tuning_config(self.0).unwrap();
        }
    }
    let _restore = Restore(saved);
    for mode in [ReliableMode::Ordered, ReliableMode::None] {
        let ep =
            register_endpoint_with_description(&format!("RECEIPT_LOSS_FC_{mode:?}"), "", false)
                .unwrap();
        let ty = register_data_type_with_description(
            &format!("RECEIPT_LOSS_BUZZER_{mode:?}"),
            "",
            MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
            &[ep],
            mode,
            16,
        )
        .unwrap();
        for bridge_reader in [false, true] {
            for drop_receipt in [false, true] {
                for retry_ms in [500, 250] {
                    for extra_child in [false, true] {
                        for extra_proxy in [false, true] {
                            receipt_loss_case(
                                saved,
                                ep,
                                ty,
                                Scenario {
                                    retry_ms,
                                    bridge_reader,
                                    drop_receipt,
                                    extra_child,
                                    extra_proxy,
                                },
                            );
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    retry_ms: u32,
    bridge_reader: bool,
    drop_receipt: bool,
    extra_child: bool,
    extra_proxy: bool,
}

fn receipt_loss_case(
    saved: sedsnet::config::RuntimeTuningConfig,
    ep: sedsnet::config::DataEndpoint,
    ty: sedsnet::config::DataType,
    case: Scenario,
) {
    let Scenario {
        retry_ms,
        bridge_reader,
        drop_receipt,
        extra_child,
        extra_proxy,
    } = case;
    let mut tuning = saved;
    tuning.reliable_retransmit_ms = retry_ms;
    tuning.reliable_max_retries = 17;
    tuning.reliable_max_return_routes = 2;
    set_runtime_tuning_config(tuning).unwrap();
    let now = Arc::new(AtomicU64::new(0));
    let frames = Arc::new(Mutex::new(Vec::<Frame>::new()));
    let effects = Arc::new(AtomicUsize::new(0));
    let mut peer_names = vec!["GS", "RF", "FC"];
    if extra_child {
        peer_names.push("PB");
    }
    let proxy = if extra_proxy {
        Some(peer_names.len())
    } else {
        None
    };
    if extra_proxy {
        peer_names.extend(["GW", "VB"]);
    }
    let noise_ep = register_endpoint_with_description("RECEIPT_ROUTE_CHURN", "", false).unwrap();
    let noise_ty = register_data_type_with_description(
        "RECEIPT_ROUTE_CHURN_DATA",
        "",
        MessageElement::Static(1, MessageDataType::UInt8, MessageClass::Data),
        &[noise_ep],
        ReliableMode::Ordered,
        0,
    )
    .unwrap();
    let nodes: Vec<_> = peer_names
        .iter()
        .copied()
        .enumerate()
        .map(|(i, name)| {
            let tick = now.clone();
            let handlers = if i == 1 {
                vec![EndpointHandler::new_packet_handler(noise_ep, |_| Ok(()))]
            } else {
                vec![]
            };
            Router::new_with_clock(
                RouterConfig::new(handlers).with_sender(name),
                Box::new(move || tick.load(Ordering::Relaxed)),
            )
        })
        .collect();
    for (index, node) in nodes.iter().enumerate() {
        if (index == 1 && !bridge_reader) || Some(index) == proxy {
            continue;
        }
        node.enable_network_variable(
            ty,
            sedsnet::router::NetworkVariablePermissions {
                read: true,
                write: index == 0,
            },
        )
        .unwrap();
    }
    let bridge_effects = Arc::new(AtomicUsize::new(0));
    if bridge_reader {
        let effects = bridge_effects.clone();
        nodes[1]
            .on_network_variable_update(ty, move |_| {
                effects.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .unwrap();
    }
    for (index, node) in nodes.iter().enumerate().skip(2) {
        if Some(index) == proxy {
            continue;
        }
        let effects = effects.clone();
        node.on_network_variable_update(ty, move |_| {
            effects.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
    }
    let lost = Arc::new(AtomicBool::new(false));
    let child_receipts = Arc::new(AtomicUsize::new(0));
    let mut links = vec![(0, 1, 0, 50), (1, 0, 0, 50), (1, 2, 0, 10), (2, 1, 1, 10)];
    if extra_child {
        links.push((3, 1, 1, 10));
    }
    if let Some(proxy) = proxy {
        links.extend([
            (0, proxy, 0, 50),
            (proxy, 0, 1, 50),
            (proxy, proxy + 1, 0, 10),
            (proxy + 1, proxy, 1, 10),
        ]);
    }
    for (from, to, side, delay) in links {
        let queue = frames.clone();
        let tick = now.clone();
        let lost = lost.clone();
        let child_receipts = child_receipts.clone();
        nodes[from].add_side_packed_with_options(
            "wire",
            move |bytes| {
                let kind = sedsnet::wire_format::peek_envelope(bytes)?.ty;
                // A downstream CAN reflection must not reapply the proxy's
                // own value or overwrite its retained upstream receipt route.
                if from == 1 && to == 2 && kind == ty {
                    queue.lock().unwrap().push(Frame {
                        at: tick.load(Ordering::Relaxed) + 5,
                        node: 1,
                        side: 1,
                        bytes: bytes.to_vec(),
                    });
                }
                // One RF CAN side broadcasts the same owned frame to both
                // readers. Drop only FC's copy; PB must not satisfy FC's ACK.
                if extra_child && from == 1 && to == 2 {
                    queue.lock().unwrap().push(Frame {
                        at: tick.load(Ordering::Relaxed) + delay,
                        node: 3,
                        side,
                        bytes: bytes.to_vec(),
                    });
                }
                if tick.load(Ordering::Relaxed) >= 1000
                    && ((drop_receipt
                        && from == 2
                        && kind == sedsnet::config::DataType::ReliableAck)
                        || (!drop_receipt && from == 1 && to == 2 && kind == ty))
                    && !lost.swap(true, Ordering::Relaxed)
                {
                    return Ok(());
                }
                if from >= 2
                    && Some(from) != proxy
                    && kind == sedsnet::config::DataType::ReliableAck
                    && tick.load(Ordering::Relaxed) >= 1000
                {
                    child_receipts.fetch_or(1 << (from - 2), Ordering::Relaxed);
                }
                queue.lock().unwrap().push(Frame {
                    at: tick.load(Ordering::Relaxed) + delay,
                    node: to,
                    side,
                    bytes: bytes.to_vec(),
                });
                Ok(())
            },
            RouterSideOptions {
                header_template_enabled: false,
                reliable_enabled: false,
                ..Default::default()
            },
        );
    }
    let topology = build_discovery_topology(
        "RF",
        0,
        &[
            TopologyBoardNode {
                sender_id: "RF".into(),
                reachable_endpoints: vec![],
                reachable_timesync_sources: vec![],
                connections: vec!["FC".into(), "GS".into()],
            },
            TopologyBoardNode {
                sender_id: "FC".into(),
                reachable_endpoints: vec![ep],
                reachable_timesync_sources: vec![],
                connections: vec!["RF".into()],
            },
        ],
    )
    .unwrap();
    nodes[0].rx_from_side(&topology, 0).unwrap();
    let topology = build_discovery_topology(
        "FC",
        0,
        &[TopologyBoardNode {
            sender_id: "FC".into(),
            reachable_endpoints: vec![ep],
            reachable_timesync_sources: vec![],
            connections: vec!["RF".into()],
        }],
    )
    .unwrap();
    nodes[1].rx_from_side(&topology, 1).unwrap();
    for node in &nodes {
        node.drain_queues_with_timeout(0).unwrap();
    }
    for node in &nodes {
        node.announce_discovery().unwrap();
    }
    for ms in (0..1000).step_by(10) {
        now.store(ms, Ordering::Relaxed);
        let mut due = Vec::new();
        frames.lock().unwrap().retain(|frame| {
            if frame.at <= ms {
                due.push(frame.clone());
                false
            } else {
                true
            }
        });
        for frame in due {
            nodes[frame.node]
                .rx_packed_queue_from_side(&frame.bytes, frame.side)
                .unwrap();
        }
        for (index, node) in nodes.iter().enumerate() {
            node.poll_discovery().unwrap();
            node.drain_queues_with_timeout(0).unwrap_or_else(|error| {
                panic!(
                    "{} at {}: {error:?}",
                    peer_names[index],
                    now.load(Ordering::Relaxed)
                )
            });
        }
    }
    now.store(1000, Ordering::Relaxed);
    assert!(
        nodes[0]
            .export_topology()
            .routes
            .iter()
            .any(|side| side.reachable_network_variables.contains(&ty)),
        "the real managed-variable owner must be discovered"
    );
    nodes[0]
        .set_network_variable(Packet::new(ty, &[ep], "GS", 1000, Arc::<[u8]>::from([1])).unwrap())
        .unwrap();
    if extra_proxy {
        assert_eq!(
            nodes[0].export_reliable_pending_stats()[0]
                .pending_destinations
                .len(),
            2,
            "the publisher must freeze both next-hop proxy owners"
        );
    }
    let expected_receipts =
        (if extra_child { 3 } else { 1 }) | proxy.map_or(0, |index| 1 << (index - 1));
    let expected_effects = (if extra_child { 2 } else { 1 }) + usize::from(extra_proxy);
    let mut completed = None;
    for ms in (0..=1500).step_by(10) {
        now.store(1000 + ms, Ordering::Relaxed);
        // Churn a two-entry return cache with unrelated reliable reports.
        // Active child aliases must survive, and queued parent ACKs retain
        // their chosen side even after this churn evicts the original entry.
        if (20..350).contains(&ms) {
            let noise = Packet::new(
                noise_ty,
                &[noise_ep],
                "GS",
                1000 + ms,
                Arc::<[u8]>::from([0]),
            )
            .unwrap();
            nodes[1]
                .rx_packed_queue_from_side(&sedsnet::wire_format::pack_packet(&noise), 0)
                .unwrap();
        }
        let mut due = Vec::new();
        frames.lock().unwrap().retain(|frame| {
            if frame.at <= 1000 + ms {
                due.push(frame.clone());
                false
            } else {
                true
            }
        });
        for frame in due {
            nodes[frame.node]
                .rx_packed_queue_from_side(&frame.bytes, frame.side)
                .unwrap();
        }
        for (index, node) in nodes.iter().enumerate() {
            node.poll_discovery().unwrap();
            node.drain_queues_with_timeout(0).unwrap_or_else(|error| {
                panic!(
                    "{} at {}: {error:?}",
                    peer_names[index],
                    now.load(Ordering::Relaxed)
                )
            });
        }
        if nodes[0].export_reliable_pending_stats().is_empty() {
            assert!(
                child_receipts.load(Ordering::Relaxed) == expected_receipts,
                "bridge acknowledged before downstream receipt: bridge_reader={bridge_reader} drop_receipt={drop_receipt}"
            );
            assert_eq!(effects.load(Ordering::Relaxed), expected_effects);

            completed = Some(ms);
            break;
        }
    }
    assert!(
        lost.load(Ordering::Relaxed),
        "effects={} pending={:?}",
        effects.load(Ordering::Relaxed),
        nodes[0].export_reliable_pending_stats()
    );
    assert_eq!(
        effects.load(Ordering::Relaxed),
        expected_effects,
        "receipt loss replayed the application effect"
    );
    assert_eq!(
        bridge_effects.load(Ordering::Relaxed),
        usize::from(bridge_reader),
        "a reflected child delivery reapplied the bridge value"
    );
    let completed = completed.expect("the routed receipt must eventually arrive");
    if retry_ms == 500 {
        assert!(
            completed > 500,
            "baseline must reproduce the missed 500 ms deadline"
        );
    } else {
        assert!(
            completed <= 500,
            "early retry must recover within the unchanged deadline: {completed}"
        );
    }
    println!(
        "routed recovery: bridge_reader={bridge_reader}, extra_proxy={extra_proxy}, drop_receipt={drop_receipt}, retry={retry_ms} ms, completed={completed} ms"
    );
}
