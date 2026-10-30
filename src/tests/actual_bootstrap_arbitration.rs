//! Diagnostic-only actual Router scheduler; the physical model is declared, not a modem emulator.
use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
fn diagnostic_turn_phase(state: &RouterInner) -> u8 {
    #[cfg(feature = "latest-value-egress")]
    {
        state.latest_turn_phase
    }
    #[cfg(not(feature = "latest-value-egress"))]
    {
        let _ = state;
        0
    }
}
fn diagnostic_turn_credit(state: &RouterInner) -> i32 {
    #[cfg(feature = "latest-value-egress")]
    {
        state.latest_turn_credit
    }
    #[cfg(not(feature = "latest-value-egress"))]
    {
        let _ = state;
        0
    }
}
struct PendingWrite {
    lease: PackedWriteLease,
    control: bool,
    admitted: u64,
}
#[derive(Default)]
struct Physical {
    queued: VecDeque<PendingWrite>,
    active: Option<(PendingWrite, u64)>,
    ordinary: usize,
    control: usize,
    high_ordinary: usize,
    high_control: usize,
    ready_ms: u64,
    accepted: usize,
    refused: usize,
    callback_events: Vec<serde_json::Value>,
    physical_events: Vec<serde_json::Value>,
}
fn identity(raw: &[u8]) -> serde_json::Value {
    if raw.starts_with(b"SDT\x03") && raw.len() >= 16 {
        serde_json::json!({"transfer":u32::from_le_bytes(raw[4..8].try_into().unwrap()),"index":u16::from_le_bytes(raw[8..10].try_into().unwrap())})
    } else {
        match wire_format::peek_frame_info(raw) {
            Ok(p) => {
                serde_json::json!({"type":p.envelope.ty.as_u32(),"source":p.envelope.source_address,"timestamp":p.envelope.timestamp_ms})
            }
            Err(e) => serde_json::json!({"opaque":true,"error":format!("{e:?}")}),
        }
    }
}
fn schema(name: &str, class: crate::MessageClass, priority: u8) -> (DataType, DataEndpoint) {
    let ep = crate::config::register_endpoint(name, false).unwrap();
    let ty = crate::config::register_data_type(
        name,
        MessageElement::Dynamic(crate::MessageDataType::UInt8, class),
        &[ep],
        crate::ReliableMode::None,
        priority,
    )
    .unwrap();
    (ty, ep)
}
fn model(period: u64, latest_enabled: bool) -> serde_json::Value {
    model_profile(period, latest_enabled, 0)
}
fn model_profile(period: u64, latest_enabled: bool, data_start: u64) -> serde_json::Value {
    let now = Arc::new(AtomicU64::new(0));
    let clock = now.clone();
    let router = Router::new_with_clock(
        RouterConfig::new([]).with_sender("GS"),
        Box::new(move || clock.load(Ordering::SeqCst)),
    );
    let physical = Arc::new(Mutex::new(Physical::default()));
    let pipe = physical.clone();
    let time = now.clone();
    let armed = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let enabled = armed.clone();
    let opts = RouterSideOptions::default().with_small_packet_transport(80);
    let (side,_tracker)=router.add_side_packed_leased_with_priority_and_options("radio",move|lease,priority|{
        if !enabled.load(Ordering::SeqCst){return Err(TelemetryError::Io("side tx busy"));}
        let raw=lease.bytes();let length=raw.len();let at=time.load(Ordering::SeqCst);
        let control=priority>=200&&priority!=254&&!raw.starts_with(b"SDT")&&!wire_format::peek_frame_info(raw).is_ok_and(|p|crate::discovery::is_discovery_type(p.envelope.ty));
        let mut p=pipe.lock().unwrap();let allowed=if control{p.control+length<=2048}else{p.ordinary+length<=256};
        let ordinary=p.ordinary;let controls=p.control;
        p.callback_events.push(serde_json::json!({"at_ms":at,"identity":identity(raw),"length":length,"priority":priority,"accepted":allowed,"pending_ordinary":ordinary,"pending_control":controls}));
        if !allowed{p.refused+=1;return Err(TelemetryError::Io("side tx busy"));}
        if control{p.control+=length;p.high_control=p.high_control.max(p.control);}else{p.ordinary+=length;p.high_ordinary=p.high_ordinary.max(p.ordinary);}
        p.accepted+=1;p.queued.push_back(PendingWrite{lease,control,admitted:at});p.queued.back().unwrap().lease.admit().unwrap();Ok(())
    },opts.clone(),RetryTrackerLimits::default()).unwrap();
    let fill = router.add_side_packed("fill-source", |_| Ok(()));
    // Configure shared-bus dictionary context before measurement, while the callback
    // refuses ALL output. No accepted physical bytes are cleared by this setup.
    for sender in ["RF", "PB", "FC"] {
        let announce =
            discovery::build_discovery_announce(sender, 0, &[DataEndpoint::TelemetryError])
                .unwrap();
        router
            .learn_discovery_packet(&announce, Some(side), true)
            .unwrap();
    }
    router.clear_tx_queue();
    assert_eq!(physical.lock().unwrap().accepted, 0);
    assert!(router.side_has_multiple_announcers_locked(&router.state.lock(), side, 0));
    #[cfg(feature = "latest-value-egress")]
    if latest_enabled {
        router.set_latest_value_side(Some(side)).unwrap();
    }
    #[cfg(not(feature = "latest-value-egress"))]
    assert!(!latest_enabled);
    armed.store(true, Ordering::SeqCst);
    let gs_raw = &include_bytes!("captured-local-gs.bin")[..];
    let gw_raw = &include_bytes!("gateway-catalog-original.bin")[..];
    let gs = wire_format::unpack_packet(gs_raw).unwrap();
    let gw = wire_format::unpack_packet(gw_raw).unwrap();
    assert_eq!(gs.packet_id(), 5077784926204178393);
    assert_eq!(gw.packet_id(), 17396325380979447247);
    assert_eq!(wire_format::pack_packet(&gs).as_ref(), gs_raw);
    assert_eq!(wire_format::pack_packet(&gw).as_ref(), gw_raw);
    let expected = [
        (gs.packet_id(), gs_raw.to_vec()),
        (gw.packet_id(), gw_raw.to_vec()),
    ];
    let flows = [
        schema("DIAG_BOOTSTRAP_FLOW_A", crate::MessageClass::Data, 0),
        schema("DIAG_BOOTSTRAP_FLOW_B", crate::MessageClass::Data, 0),
    ];
    let command = schema("DIAG_BOOTSTRAP_CONTROL", crate::MessageClass::Data, 255);
    let receiver_time = now.clone();
    let receiver = Router::new_with_clock(
        RouterConfig::new([]).with_sender("RECEIVER"),
        Box::new(move || receiver_time.load(Ordering::SeqCst)),
    );
    let input = receiver.add_side_packed_with_options("radio", |_| Ok(()), opts);
    let mut received_catalogs = Vec::new();
    let mut reports = [Vec::new(), Vec::new()];
    let mut controls = Vec::new();
    let mut control_offers = Vec::new();
    let mut source_offers = [0usize; 2];
    let mut progress_events = Vec::new();
    let mut max_idle_credit = 0;
    let mut last_progress = String::new();
    let mut last_codec_generation = u64::MAX;
    for ms in 0..=60_000u64 {
        now.store(ms, Ordering::SeqCst);
        if ms == 0 {
            router
                .emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side,
                        data: RouterItem::Packet(gs.clone()),
                    },
                    true,
                    true,
                )
                .unwrap();
        }
        if ms == 2287 {
            router
                .emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: Some(fill),
                        dst: side,
                        data: RouterItem::Packet(gw.clone()),
                    },
                    true,
                    true,
                )
                .unwrap();
        }
        if ms % 1000 == 0 {
            for sender in ["RF", "PB", "FC"] {
                let a = discovery::build_discovery_announce(sender, ms, &[]).unwrap();
                router.refresh_known_discovery_liveness(&a, side).unwrap();
            }
        }
        if ms >= data_start && ms % period == 0 {
            for (i, &(ty, ep)) in flows.iter().enumerate() {
                source_offers[i] += 1;
                let packet =
                    Packet::new(ty, &[ep], "FC", ms, Arc::from(vec![i as u8; [12, 24][i]]))
                        .unwrap();
                if latest_enabled {
                    #[cfg(feature = "latest-value-egress")]
                    router
                        .queue_latest_egress(side, Some(fill), &RouterItem::Packet(packet))
                        .unwrap();
                } else {
                    router
                        .emit_internal_tx(
                            RouterTxItem::ToSide {
                                src: Some(fill),
                                dst: side,
                                data: RouterItem::Packet(packet),
                            },
                            true,
                            true,
                        )
                        .unwrap();
                }
            }
        }
        if ms % 2000 == 0 {
            let packet =
                Packet::new(command.0, &[command.1], "GS", ms, Arc::from(vec![1u8])).unwrap();
            control_offers.push((ms, packet.packet_id()));
            router
                .emit_internal_tx(
                    RouterTxItem::ToSide {
                        src: None,
                        dst: side,
                        data: RouterItem::Packet(packet),
                    },
                    true,
                    true,
                )
                .unwrap();
        }
        router.dispatch_tx_queue_with_timeout(0).unwrap();
        let completed = {
            let mut p = physical.lock().unwrap();
            if p.active.as_ref().is_some_and(|(_, end)| ms >= *end) {
                let (w, end) = p.active.take().unwrap();
                let len = w.lease.bytes().len();
                w.lease.report_drained().unwrap();
                if w.control {
                    p.control -= len;
                } else {
                    p.ordinary -= len;
                }
                p.physical_events.push(serde_json::json!({"event":"drained","at_ms":end,"admitted_ms":w.admitted,"identity":identity(w.lease.bytes()),"length":len}));
                Some(w.lease.bytes().to_vec())
            } else {
                None
            }
        };
        if let Some(bytes) = completed
            && let Some(raw) = receiver.decode_side_transport_frame(input, &bytes).unwrap()
        {
            let packet = wire_format::unpack_packet(&raw).unwrap();
            if packet.data_type() == DataType::DiscoverySchema {
                received_catalogs.push((ms, packet.packet_id(), raw.to_vec()));
            }
            for (i, (ty, _)) in flows.iter().enumerate() {
                if packet.data_type() == *ty {
                    reports[i].push((ms, packet.timestamp()));
                }
            }
            if packet.data_type() == command.0 {
                controls.push((ms, packet.timestamp(), packet.packet_id()));
            }
        }
        {
            let mut p = physical.lock().unwrap();
            if p.active.is_none() && ms >= p.ready_ms && !p.queued.is_empty() {
                let index = p.queued.iter().position(|w| w.control).unwrap_or(0);
                let w = p.queued.remove(index).unwrap();
                assert_eq!(w.lease.try_start(), WriteStart::Ready);
                let len = w.lease.bytes().len();
                let uart_ms = ((len + 12) as u64 * 10_000).div_ceil(115_200).max(1);
                let charged = len as u64 + 28;
                let airtime = (charged * 1000).div_ceil(480);
                p.ready_ms = ms + airtime.max(55);
                let ready = p.ready_ms;
                p.physical_events.push(serde_json::json!({"event":"start","at_ms":ms,"identity":identity(w.lease.bytes()),"length":len,"charged":charged,"next_credit_ms":ready}));
                p.active = Some((w, ms + uart_ms));
            }
        }
        let st = router.state.lock();
        if ms < data_start {
            max_idle_credit = max_idle_credit.max(diagnostic_turn_credit(&st));
        }
        let current = format!(
            "{:?}",
            st.side_transport
                .get(&side)
                .and_then(|t| t.tx_chunk_progress.as_ref())
        );
        let generation = st.side_transport[&side].payload_codec.generation();
        if current != last_progress || generation != last_codec_generation {
            progress_events.push(serde_json::json!({"at_ms":ms,"cursors":current,"codec_generation":st.side_transport[&side].payload_codec.generation(),"phase":diagnostic_turn_phase(&st)}));
            last_progress = current;
            last_codec_generation = generation;
        }
    }
    let p = physical.lock().unwrap();
    assert!(p.high_ordinary <= 256 && p.high_control <= 2048);
    for (_, id, raw) in &received_catalogs {
        let original = expected
            .iter()
            .find(|(expected_id, _)| expected_id == id)
            .expect("no regenerated catalog");
        assert_eq!(&original.1, raw);
    }
    let max_age = reports
        .iter()
        .map(|r| r.iter().map(|(at, src)| at - src).max())
        .collect::<Vec<_>>();
    let gaps = reports
        .iter()
        .map(|r| r.windows(2).map(|w| w[1].0 - w[0].0).max())
        .collect::<Vec<_>>();
    let max_control = controls.iter().map(|(at, src, _)| at - src).max();
    let first_delay = reports
        .iter()
        .map(|r| r.first().map(|v| v.0))
        .collect::<Vec<_>>();
    let source_gate = reports.iter().all(|r| {
        !r.is_empty()
            && r.first().unwrap().0 - data_start <= 1500
            && r.iter().all(|(at, src)| at - src <= 1500)
            && r.windows(2).all(|w| w[1].0 - w[0].0 <= 1500)
            && r.last().is_some_and(|(at, src)| {
                60_000u64.checked_sub(*at).is_some_and(|age| age <= 1500)
                    && 60_000u64.checked_sub(*src).is_some_and(|age| age <= 1500)
            })
    });
    // The last60000ms offer has not reached its500ms deadline at the cutoff.
    // Every matured offer is checked by immutable PacketID, not just a count.
    let matured_controls: Vec<_> = control_offers
        .iter()
        .filter(|(at, _)| at + 500 <= 60_000)
        .collect();
    let control_gate = matured_controls.len() == 30
        && matured_controls.iter().all(|(due, id)| {
            let matches: Vec<_> = controls.iter().filter(|(_, _, seen)| seen == id).collect();
            matches.len() == 1 && matches[0].1 == *due && matches[0].0 - due <= 500
        })
        && max_control.is_some_and(|v| v <= 500);
    let catalogs_once = received_catalogs.len() == expected.len()
        && expected.iter().all(|(id, _)| {
            received_catalogs
                .iter()
                .filter(|(_, seen, _)| seen == id)
                .count()
                == 1
        });
    let source_end_age = reports
        .iter()
        .map(|r| {
            r.last()
                .and_then(|(_, source)| 60_000u64.checked_sub(*source))
        })
        .collect::<Vec<_>>();
    let result = serde_json::json!({"first_source_delay_ms":first_delay,"diagnostic_source_gate_1500ms":source_gate,"diagnostic_control_onehop_gate_500ms":control_gate,"both_original_catalogs_completed":catalogs_once,"matured_control_count":matured_controls.len(),"source_end_age_ms":source_end_age,"flow_type_ids":flows.iter().map(|(ty,_)|ty.as_u32()).collect::<Vec<_>>(),"sdk":env!("CARGO_PKG_VERSION"),"source_period_ms":period,"max_idle_credit":max_idle_credit,"data_start_ms":data_start,"latest_enabled":latest_enabled,"compiled_latest_feature":cfg!(feature="latest-value-egress"),"source_offers":source_offers,"source_received":reports.iter().map(Vec::len).collect::<Vec<_>>(),"source_max_age_ms":max_age,"source_max_gap_ms":gaps,"control_received":controls.len(),"control_max_onehop_ms":max_control,"catalog_completions":received_catalogs.iter().map(|(at,id,_)|(*at,*id)).collect::<Vec<_>>(),"callback_accepted":p.accepted,"callback_refused":p.refused,"high_ordinary_bytes":p.high_ordinary,"high_control_bytes":p.high_control,"callback_events":p.callback_events,"physical_events":p.physical_events,"progress_events":progress_events,"scope":"ActualRouter scheduling, declared singlehost12% rate+UARTdrain model; not matchedRFDmesh/no fakeAllownerACK. Unfinished60s tails retained."});
    if let Some(dir) = std::env::var_os("ROUTER_MODEL_TRACE_DIR") {
        let path = std::path::PathBuf::from(dir).join(format!(
            "router-{}-{}-{}ms-start{}ms.json",
            env!("CARGO_PKG_VERSION"),
            if latest_enabled {
                "optin-latest"
            } else {
                "host-fifo"
            },
            period,
            data_start
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("refuse to overwrite retained model evidence");
        serde_json::to_writer(std::io::BufWriter::new(file), &result).unwrap();
    }
    result
}
#[test]
#[cfg(feature = "latest-value-egress")]
fn actual_two_catalog_router_under_capacity() {
    let r = model(1000, true);
    eprintln!(
        "ROUTER_MODEL {}",
        serde_json::to_string(
            &r.as_object()
                .unwrap()
                .iter()
                .filter(|(k, _)| !k.ends_with("events"))
                .collect::<std::collections::BTreeMap<_, _>>()
        )
        .unwrap()
    );
}
#[test]
#[cfg(feature = "latest-value-egress")]
fn actual_two_catalog_router_five_hz_pressure() {
    let r = model(200, true);
    eprintln!(
        "ROUTER_MODEL {}",
        serde_json::to_string(
            &r.as_object()
                .unwrap()
                .iter()
                .filter(|(k, _)| !k.ends_with("events"))
                .collect::<std::collections::BTreeMap<_, _>>()
        )
        .unwrap()
    );
}

#[test]
fn actual_host_queue_two_catalog_router_under_capacity() {
    let r = model(1000, false);
    eprintln!(
        "ROUTER_MODEL {}",
        serde_json::to_string(
            &r.as_object()
                .unwrap()
                .iter()
                .filter(|(k, _)| !k.ends_with("events"))
                .collect::<std::collections::BTreeMap<_, _>>()
        )
        .unwrap()
    );
}

#[cfg(feature = "latest-value-egress")]
fn assert_multicatalog_service(period: u64) {
    let result = model(period, true);
    let summary: std::collections::BTreeMap<_, _> = result
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| !key.ends_with("events"))
        .collect();
    assert!(
        result["diagnostic_source_gate_1500ms"].as_bool().unwrap(),
        "independent latest source first-age/gap violated: {summary:?}"
    );
    assert!(
        result["diagnostic_control_onehop_gate_500ms"]
            .as_bool()
            .unwrap(),
        "control physical service violated: {summary:?}"
    );
    assert!(
        result["both_original_catalogs_completed"]
            .as_bool()
            .unwrap(),
        "original immutable catalog owner incomplete: {summary:?}"
    );
}
#[test]
#[cfg(feature = "latest-value-egress")]
fn required_multicatalog_service_one_hz() {
    assert_multicatalog_service(1000);
}
#[test]
#[cfg(feature = "latest-value-egress")]
fn required_multicatalog_service_five_hz_pressure() {
    assert_multicatalog_service(200);
}

#[test]
#[cfg(feature = "latest-value-egress")]
fn required_multicatalog_service_idle_credit_then_synchronous_five_hz() {
    let result = model_profile(200, true, 10_000);
    assert_eq!(
        result["max_idle_credit"],
        80 * u64::from(MAX_PRIORITY_BURST),
        "exercise actual saturated idle admission credit"
    );
    assert!(
        result["diagnostic_source_gate_1500ms"].as_bool().unwrap(),
        "idle-earned credit source first-age/intergap failure: ages={:?} gaps={:?}",
        result["source_max_age_ms"],
        result["source_max_gap_ms"]
    );
    assert!(
        result["diagnostic_control_onehop_gate_500ms"]
            .as_bool()
            .unwrap()
    );
    assert!(
        result["both_original_catalogs_completed"]
            .as_bool()
            .unwrap(),
        "idle-earned credits must preserve BOTH exact receiver owners"
    );
    for transfer in [3937645761u64, 1223421448] {
        let frames: Vec<_> = result["physical_events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| {
                event["event"] == "drained" && event["identity"]["transfer"] == transfer
            })
            .collect();
        assert!(
            frames
                .windows(2)
                .all(|pair| pair[0]["identity"]["index"].as_u64()
                    < pair[1]["identity"]["index"].as_u64()),
            "idle-credit burst caused avoidable 2s canonical assembly expiry/reset"
        );
    }
}

#[test]
#[cfg(feature = "latest-value-egress")]
fn required_multicatalog_idle_bulk_finishes_exactly_without_assembly_expiry() {
    let result = model_profile(1000, true, 60_001);
    assert_eq!(
        result["source_offers"],
        serde_json::json!([0, 0]),
        "this is explicitly a no-data bulk scene"
    );
    assert!(
        result["both_original_catalogs_completed"]
            .as_bool()
            .unwrap()
    );
    assert!(
        result["diagnostic_control_onehop_gate_500ms"]
            .as_bool()
            .unwrap()
    );
    for (transfer, count) in [(3937645761u64, 59u64), (1223421448, 60)] {
        let indexes: Vec<_> = result["physical_events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| {
                event["event"] == "drained" && event["identity"]["transfer"] == transfer
            })
            .map(|event| event["identity"]["index"].as_u64().unwrap())
            .collect();
        assert_eq!(
            indexes,
            (0..count).collect::<Vec<_>>(),
            "idle live catalogs must not restart/expire or lose accepted fragments"
        );
    }
}
