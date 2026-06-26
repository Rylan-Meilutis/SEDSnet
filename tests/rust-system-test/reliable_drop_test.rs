#[cfg(test)]
mod reliable_drop_tests {
    use sedsnet::TelemetryResult;
    use sedsnet::config::{
        DataEndpoint, DataType, RELIABLE_RETRANSMIT_MS, data_type_definition_by_name,
        endpoint_definition_by_name, register_data_type_with_description,
        register_endpoint_with_description,
    };
    use sedsnet::discovery::build_discovery_announce;
    use sedsnet::packet::Packet;
    use sedsnet::relay::{Relay, RelaySideOptions};
    use sedsnet::router::{
        Clock, EndpointHandler, NetworkVariablePermissions, Router, RouterConfig,
        RouterE2eEncryptionMode, RouterSideOptions,
    };
    use sedsnet::timesync::{TimeSyncConfig, TimeSyncRole};
    use sedsnet::wire_format;
    use sedsnet::{
        MessageClass, MessageDataType, MessageElement, ReliableMode, RouteSelectionMode,
    };

    use std::collections::{BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Once};

    type SharedBusFrameQueue = Arc<Mutex<VecDeque<(usize, Vec<u8>)>>>;

    fn shared_clock(now: Arc<AtomicU64>) -> Box<dyn Clock + Send + Sync> {
        Box::new(move || now.load(Ordering::SeqCst))
    }

    fn drain_queue(q: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut guard = q.lock().expect("queue lock poisoned");
        while let Some(frame) = guard.pop_front() {
            out.push(frame);
        }
        out
    }

    fn drain_queue_limited(q: &Arc<Mutex<VecDeque<Vec<u8>>>>, limit: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut guard = q.lock().expect("queue lock poisoned");
        for _ in 0..limit {
            let Some(frame) = guard.pop_front() else {
                break;
            };
            out.push(frame);
        }
        out
    }

    fn ensure_common_test_schema() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            if endpoint_definition_by_name("RADIO").is_none() {
                register_endpoint_with_description(
                    "RADIO",
                    "Radio or external link (telemetry uplink/downlink).",
                    false,
                )
                .unwrap();
            }
            if endpoint_definition_by_name("SD_CARD").is_none() {
                register_endpoint_with_description(
                    "SD_CARD",
                    "On-board storage (e.g. SD card / flash).",
                    false,
                )
                .unwrap();
            }
            if data_type_definition_by_name("GPS_DATA").is_none() {
                register_data_type_with_description(
                    "GPS_DATA",
                    "GPS data (typically 3x f32: latitude, longitude, altitude).",
                    MessageElement::Static(3, MessageDataType::Float32, MessageClass::Data),
                    &[DataEndpoint::named("RADIO"), DataEndpoint::named("SD_CARD")],
                    ReliableMode::Ordered,
                    80,
                )
                .unwrap();
            }
        });
    }

    #[allow(dead_code)]
    struct RocketTopology {
        now: Arc<AtomicU64>,
        gs: Router,
        gw: Relay,
        rf: Relay,
        actuator_hits: Arc<Mutex<Vec<u32>>>,
        gs_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        gw_gs_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        gs_rf_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        rf_gs_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        gw_ab_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        ab_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        gw_vb_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        vb_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        gw_daq_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        daq_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        rf_pb_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        pb_rf_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        rf_fc_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        fc_rf_tx: Arc<Mutex<VecDeque<Vec<u8>>>>,
        gs_gw_side: usize,
        gs_rf_side: usize,
        gw_gs_side: usize,
        gw_ab_side: usize,
        gw_vb_side: usize,
        gw_daq_side: usize,
        rf_gs_side: usize,
        rf_pb_side: usize,
        rf_fc_side: usize,
        actuator: Router,
        actuator_side: usize,
        valve: Router,
        valve_side: usize,
        daq: Router,
        daq_side: usize,
        power: Router,
        power_side: usize,
        flight: Router,
        flight_side: usize,
    }

    #[allow(dead_code)]
    impl RocketTopology {
        fn new() -> Self {
            ensure_common_test_schema();
            let now = Arc::new(AtomicU64::new(0));
            let gs = Router::new_with_clock(
                RouterConfig::default().with_sender("GS"),
                shared_clock(now.clone()),
            );
            let gw = Relay::new(shared_clock(now.clone()));
            let rf = Relay::new(shared_clock(now.clone()));

            let actuator_hits: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
            let actuator_handler_hits = actuator_hits.clone();
            let actuator = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("RADIO"),
                    move |pkt| {
                        let vals = pkt.data_as_f32()?;
                        if let Some(first) = vals.first() {
                            actuator_handler_hits.lock().unwrap().push(*first as u32);
                        }
                        Ok(())
                    },
                )])
                .with_sender("AB"),
                shared_clock(now.clone()),
            );
            let valve = Router::new_with_clock(
                RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                    DataEndpoint::named("SD_CARD"),
                    |_pkt| Ok(()),
                )])
                .with_sender("VB"),
                shared_clock(now.clone()),
            );
            let daq = Router::new_with_clock(
                RouterConfig::default().with_sender("DAQ"),
                shared_clock(now.clone()),
            );
            let power = Router::new_with_clock(
                RouterConfig::default().with_sender("PB"),
                shared_clock(now.clone()),
            );
            let flight = Router::new_with_clock(
                RouterConfig::default().with_sender("FC"),
                shared_clock(now.clone()),
            );

            let gs_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let gw_gs_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let gs_rf_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let rf_gs_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let gw_ab_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let ab_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let gw_vb_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let vb_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let gw_daq_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let daq_gw_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let rf_pb_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let pb_rf_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let rf_fc_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
            let fc_rf_tx: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

            let side_opts = RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            };
            let relay_side_opts = RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            };
            let leaf_side_opts = RouterSideOptions {
                reliable_enabled: false,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            };
            let leaf_relay_side_opts = RelaySideOptions {
                reliable_enabled: false,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            };
            let topology_side_opts = RouterSideOptions {
                reliable_enabled: false,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            };
            let topology_relay_side_opts = RelaySideOptions {
                reliable_enabled: false,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            };

            let gs_gw_side = gs.add_side_packed_with_options(
                "gw",
                {
                    let q = gs_gw_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                side_opts,
            );
            let gs_rf_side = gs.add_side_packed_with_options(
                "rf",
                {
                    let q = gs_rf_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                topology_side_opts,
            );

            let gw_gs_side = gw.add_side_packed_with_options(
                "gs",
                {
                    let q = gw_gs_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                relay_side_opts,
            );
            let gw_ab_side = gw.add_side_packed_with_options(
                "ab",
                {
                    let q = gw_ab_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                relay_side_opts,
            );
            let gw_vb_side = gw.add_side_packed_with_options(
                "vb",
                {
                    let q = gw_vb_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_relay_side_opts,
            );
            let gw_daq_side = gw.add_side_packed_with_options(
                "daq",
                {
                    let q = gw_daq_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_relay_side_opts,
            );

            let rf_gs_side = rf.add_side_packed_with_options(
                "gs",
                {
                    let q = rf_gs_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                topology_relay_side_opts,
            );
            let rf_pb_side = rf.add_side_packed_with_options(
                "pb",
                {
                    let q = rf_pb_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_relay_side_opts,
            );
            let rf_fc_side = rf.add_side_packed_with_options(
                "fc",
                {
                    let q = rf_fc_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_relay_side_opts,
            );

            let actuator_side = actuator.add_side_packed_with_options(
                "gw",
                {
                    let q = ab_gw_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                side_opts,
            );
            let valve_side = valve.add_side_packed_with_options(
                "gw",
                {
                    let q = vb_gw_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_side_opts,
            );
            let daq_side = daq.add_side_packed_with_options(
                "gw",
                {
                    let q = daq_gw_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_side_opts,
            );
            let power_side = power.add_side_packed_with_options(
                "rf",
                {
                    let q = pb_rf_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_side_opts,
            );
            let flight_side = flight.add_side_packed_with_options(
                "rf",
                {
                    let q = fc_rf_tx.clone();
                    move |bytes: &[u8]| -> TelemetryResult<()> {
                        q.lock().unwrap().push_back(bytes.to_vec());
                        Ok(())
                    }
                },
                leaf_side_opts,
            );

            Self {
                now,
                gs,
                gw,
                rf,
                actuator_hits,
                gs_gw_tx,
                gw_gs_tx,
                gs_rf_tx,
                rf_gs_tx,
                gw_ab_tx,
                ab_gw_tx,
                gw_vb_tx,
                vb_gw_tx,
                gw_daq_tx,
                daq_gw_tx,
                rf_pb_tx,
                pb_rf_tx,
                rf_fc_tx,
                fc_rf_tx,
                gs_gw_side,
                gs_rf_side,
                gw_gs_side,
                gw_ab_side,
                gw_vb_side,
                gw_daq_side,
                rf_gs_side,
                rf_pb_side,
                rf_fc_side,
                actuator,
                actuator_side,
                valve,
                valve_side,
                daq,
                daq_side,
                power,
                power_side,
                flight,
                flight_side,
            }
        }

        fn pump_once(&self) {
            self.gs.process_all_queues_with_timeout(0).unwrap();
            self.gw.process_all_queues_with_timeout(0).unwrap();
            self.rf.process_all_queues_with_timeout(0).unwrap();
            self.actuator.process_all_queues_with_timeout(0).unwrap();
            self.valve.process_all_queues_with_timeout(0).unwrap();
            self.daq.process_all_queues_with_timeout(0).unwrap();
            self.power.process_all_queues_with_timeout(0).unwrap();
            self.flight.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&self.gs_gw_tx) {
                self.gw
                    .rx_packed_from_side(self.gw_gs_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&self.gw_gs_tx) {
                self.gs
                    .rx_packed_queue_from_side(&frame, self.gs_gw_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.gs_rf_tx) {
                self.rf
                    .rx_packed_from_side(self.rf_gs_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&self.rf_gs_tx) {
                self.gs
                    .rx_packed_queue_from_side(&frame, self.gs_rf_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.gw_ab_tx) {
                self.actuator
                    .rx_packed_queue_from_side(&frame, self.actuator_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.ab_gw_tx) {
                self.gw
                    .rx_packed_from_side(self.gw_ab_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&self.gw_vb_tx) {
                self.valve
                    .rx_packed_queue_from_side(&frame, self.valve_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.vb_gw_tx) {
                self.gw
                    .rx_packed_from_side(self.gw_vb_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&self.gw_daq_tx) {
                self.daq
                    .rx_packed_queue_from_side(&frame, self.daq_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.daq_gw_tx) {
                self.gw
                    .rx_packed_from_side(self.gw_daq_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&self.rf_pb_tx) {
                self.power
                    .rx_packed_queue_from_side(&frame, self.power_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.pb_rf_tx) {
                self.rf
                    .rx_packed_from_side(self.rf_pb_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&self.rf_fc_tx) {
                self.flight
                    .rx_packed_queue_from_side(&frame, self.flight_side)
                    .unwrap();
            }
            for frame in drain_queue(&self.fc_rf_tx) {
                self.rf
                    .rx_packed_from_side(self.rf_fc_side, &frame)
                    .unwrap();
            }
        }

        fn advance(&self, delta_ms: u64) {
            self.now.fetch_add(delta_ms, Ordering::SeqCst);
        }

        fn settle(&self, rounds: usize) {
            for _ in 0..rounds {
                self.pump_once();
            }
        }
    }

    struct SharedBus {
        frames: SharedBusFrameQueue,
    }

    impl SharedBus {
        fn new() -> Self {
            Self {
                frames: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn tx_handler(
            &self,
            node_id: usize,
        ) -> impl Fn(&[u8]) -> TelemetryResult<()> + Send + Sync + 'static {
            let q = self.frames.clone();
            move |bytes: &[u8]| -> TelemetryResult<()> {
                q.lock().unwrap().push_back((node_id, bytes.to_vec()));
                Ok(())
            }
        }

        fn drain(&self) -> Vec<(usize, Vec<u8>)> {
            let mut out = Vec::new();
            let mut guard = self.frames.lock().unwrap();
            while let Some(frame) = guard.pop_front() {
                out.push(frame);
            }
            out
        }
    }

    #[test]
    fn reliable_link_recovers_from_dropped_frames() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));

        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let recv_sink = received.clone();
        let handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
                let vals = pkt.data_as_f32()?;
                if let Some(first) = vals.first() {
                    recv_sink
                        .lock()
                        .expect("received lock poisoned")
                        .push(*first as u32);
                }
                Ok(())
            });

        let router_a = Router::new_with_clock(RouterConfig::default(), shared_clock(now.clone()));
        let router_b =
            Router::new_with_clock(RouterConfig::new(vec![handler]), shared_clock(now.clone()));

        let a_to_b: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let a_to_b_tx = a_to_b.clone();
        let a_side = router_a.add_side_packed_with_options(
            "link",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                a_to_b_tx
                    .lock()
                    .expect("a_to_b lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let b_to_a_tx = b_to_a.clone();
        let b_side = router_b.add_side_packed_with_options(
            "link",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                b_to_a_tx
                    .lock()
                    .expect("b_to_a lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        const TOTAL: u32 = 6;
        for i in 0..TOTAL {
            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[i as f32, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                i as u64,
            )
            .expect("failed to build packet");
            router_a.tx(pkt).expect("tx failed");
        }

        let mut dropped_data_once = false;
        let mut dropped_control_once = false;

        for _ in 0..200 {
            router_a
                .process_all_queues_with_timeout(0)
                .expect("router_a process failed");
            router_b
                .process_all_queues_with_timeout(0)
                .expect("router_b process failed");

            for frame in drain_queue(&a_to_b) {
                let info = wire_format::peek_frame_info(&frame).expect("peek frame failed");
                if info.envelope.ty == DataType::named("GPS_DATA")
                    && !info.ack_only()
                    && let Some(hdr) = info.reliable
                    && hdr.seq == 1
                    && !dropped_data_once
                {
                    dropped_data_once = true;
                    continue; // drop first data frame for seq=1
                }
                router_b
                    .rx_packed_queue_from_side(&frame, b_side)
                    .expect("router_b rx failed");
            }

            for frame in drain_queue(&b_to_a) {
                let info = wire_format::peek_frame_info(&frame).expect("peek ack failed");
                if matches!(
                    info.envelope.ty,
                    DataType::ReliableAck | DataType::ReliablePacketRequest
                ) && !dropped_control_once
                {
                    let pkt = wire_format::unpack_packet(&frame).expect("decode control failed");
                    let vals = pkt.data_as_u32().expect("control payload decode failed");
                    if vals.first().copied() == Some(DataType::named("GPS_DATA").as_u32()) {
                        dropped_control_once = true;
                        continue; // drop first control packet for the reliable stream
                    }
                }
                router_a
                    .rx_packed_queue_from_side(&frame, a_side)
                    .expect("router_a rx failed");
            }

            router_a
                .process_all_queues_with_timeout(0)
                .expect("router_a process failed");
            router_b
                .process_all_queues_with_timeout(0)
                .expect("router_b process failed");

            if received.lock().expect("received lock poisoned").len() == TOTAL as usize {
                break;
            }

            now.fetch_add(RELIABLE_RETRANSMIT_MS, Ordering::SeqCst);
        }

        let got = received.lock().expect("received lock poisoned").clone();
        let expected: Vec<u32> = (0..TOTAL).collect();

        assert!(dropped_data_once, "test did not drop a data frame");
        assert!(
            dropped_control_once,
            "test did not drop a reliable control frame"
        );
        assert_eq!(got, expected, "reliable delivery should recover from drops");
    }

    #[test]
    fn reliable_ordered_delivers_in_order() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));

        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let recv_sink = received.clone();
        let handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
                let vals = pkt.data_as_f32()?;
                if let Some(first) = vals.first() {
                    recv_sink
                        .lock()
                        .expect("received lock poisoned")
                        .push(*first as u32);
                }
                Ok(())
            });

        let router =
            Router::new_with_clock(RouterConfig::new(vec![handler]), shared_clock(now.clone()));

        let side = router.add_side_packed_with_options(
            "SRC",
            |_b| Ok(()),
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0_f32, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            1,
        )
        .expect("failed to build packet");
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[2.0_f32, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            2,
        )
        .expect("failed to build packet");

        let seq1 = wire_format::pack_packet_with_reliable(
            &pkt1,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 1,
                ack: 0,
            },
        );
        let seq2 = wire_format::pack_packet_with_reliable(
            &pkt2,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 2,
                ack: 0,
            },
        );

        router
            .rx_packed_from_side(seq2.as_ref(), side)
            .expect("rx seq2 failed");
        router
            .rx_packed_from_side(seq1.as_ref(), side)
            .expect("rx seq1 failed");
        router
            .rx_packed_from_side(seq2.as_ref(), side)
            .expect("rx seq2 retransmit failed");

        let got = received.lock().expect("received lock poisoned").clone();
        assert_eq!(got, vec![1, 2], "ordered reliable delivery must reorder");
    }

    #[test]
    fn end_to_end_reliable_ack_routes_back_without_flooding() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));

        let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_c = delivered.clone();
        let handler =
            EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
                let vals = pkt.data_as_f32()?;
                if let Some(first) = vals.first() {
                    delivered_c
                        .lock()
                        .expect("delivered lock poisoned")
                        .push(*first as u32);
                }
                Ok(())
            });

        let source = Router::new_with_clock(RouterConfig::default(), shared_clock(now.clone()));
        let relay = Relay::new(shared_clock(now.clone()));
        let dest =
            Router::new_with_clock(RouterConfig::new(vec![handler]), shared_clock(now.clone()));

        let s_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_s: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_d: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let d_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_spur: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let s_to_r_tx = s_to_r.clone();
        let source_side = source.add_side_packed_with_options(
            "relay",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                s_to_r_tx
                    .lock()
                    .expect("s_to_r lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let r_to_s_tx = r_to_s.clone();
        let relay_source_side = relay.add_side_packed_with_options(
            "source",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                r_to_s_tx
                    .lock()
                    .expect("r_to_s lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        let r_to_d_tx = r_to_d.clone();
        let relay_dest_side = relay.add_side_packed_with_options(
            "dest",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                r_to_d_tx
                    .lock()
                    .expect("r_to_d lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );

        let d_to_r_tx = d_to_r.clone();
        let dest_side = dest.add_side_packed_with_options(
            "relay",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                d_to_r_tx
                    .lock()
                    .expect("d_to_r lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let r_to_spur_tx = r_to_spur.clone();
        relay.add_side_packed_with_options(
            "spur",
            move |bytes: &[u8]| -> TelemetryResult<()> {
                r_to_spur_tx
                    .lock()
                    .expect("r_to_spur lock poisoned")
                    .push_back(bytes.to_vec());
                Ok(())
            },
            RelaySideOptions::default(),
        );

        let discovery =
            build_discovery_announce("DEST", 0, &[DataEndpoint::named("RADIO")]).unwrap();
        relay.rx_from_side(relay_dest_side, discovery).unwrap();
        relay.process_all_queues().unwrap();
        let _ = drain_queue(&r_to_s);
        let _ = drain_queue(&r_to_spur);

        let pkt = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[42.0, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            42,
        )
        .expect("failed to build packet");
        source.tx(pkt).expect("source tx failed");

        let mut dropped_end_to_end_ack = false;
        let mut forwarded_data_frames = 0usize;
        let mut spur_ack_frames = 0usize;

        for _ in 0..200 {
            source.process_all_queues_with_timeout(0).unwrap();
            relay.process_all_queues().unwrap();
            dest.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&s_to_r) {
                let info = wire_format::peek_frame_info(&frame).expect("source->relay peek failed");
                if info.envelope.ty == DataType::named("GPS_DATA") && !info.ack_only() {
                    forwarded_data_frames += 1;
                }
                relay
                    .rx_packed_from_side(relay_source_side, &frame)
                    .unwrap();
            }

            for frame in drain_queue(&r_to_d) {
                dest.rx_packed_queue_from_side(&frame, dest_side).unwrap();
            }

            for frame in drain_queue(&d_to_r) {
                let info = wire_format::peek_frame_info(&frame).expect("dest->relay peek failed");
                if info.envelope.ty == DataType::ReliableAck {
                    let pkt = wire_format::unpack_packet(&frame).expect("decode ack failed");
                    if pkt.sender().starts_with("E2EACK:")
                        && pkt.payload().len() == 8
                        && !dropped_end_to_end_ack
                    {
                        dropped_end_to_end_ack = true;
                        continue;
                    }
                }
                relay.rx_packed_from_side(relay_dest_side, &frame).unwrap();
            }

            for frame in drain_queue(&r_to_s) {
                source
                    .rx_packed_queue_from_side(&frame, source_side)
                    .unwrap();
            }

            for frame in drain_queue(&r_to_spur) {
                let info = wire_format::peek_frame_info(&frame).expect("spur peek failed");
                if info.envelope.ty == DataType::ReliableAck {
                    spur_ack_frames += 1;
                }
            }

            source.process_all_queues_with_timeout(0).unwrap();
            relay.process_all_queues().unwrap();
            dest.process_all_queues_with_timeout(0).unwrap();

            if dropped_end_to_end_ack
                && forwarded_data_frames >= 2
                && delivered.lock().expect("delivered lock poisoned").len() == 1
            {
                break;
            }

            now.fetch_add(RELIABLE_RETRANSMIT_MS, Ordering::SeqCst);
        }

        assert!(
            dropped_end_to_end_ack,
            "test never dropped an end-to-end ACK"
        );
        assert!(
            forwarded_data_frames >= 2,
            "source should retransmit when the end-to-end ACK is lost"
        );
        assert_eq!(
            delivered
                .lock()
                .expect("delivered lock poisoned")
                .as_slice(),
            &[42],
            "destination should only consume the packet once"
        );
        assert_eq!(
            spur_ack_frames, 0,
            "reliable ACKs should not flood to unrelated sides"
        );
    }

    #[test]
    fn end_to_end_reliable_waits_for_all_discovered_holders() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let delivered_a: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_b: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

        let handler_a = {
            let delivered = delivered_a.clone();
            EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
                let vals = pkt.data_as_f32()?;
                if let Some(first) = vals.first() {
                    delivered.lock().unwrap().push(*first as u32);
                }
                Ok(())
            })
        };
        let handler_b = {
            let delivered = delivered_b.clone();
            EndpointHandler::new_packet_handler(DataEndpoint::named("RADIO"), move |pkt| {
                let vals = pkt.data_as_f32()?;
                if let Some(first) = vals.first() {
                    delivered.lock().unwrap().push(*first as u32);
                }
                Ok(())
            })
        };

        let source = Router::new_with_clock(
            RouterConfig::default().with_sender("SRC"),
            shared_clock(now.clone()),
        );
        let relay = Relay::new(shared_clock(now.clone()));
        let dest_a = Router::new_with_clock(
            RouterConfig::new(vec![handler_a]).with_sender("DEST_A"),
            shared_clock(now.clone()),
        );
        let dest_b = Router::new_with_clock(
            RouterConfig::new(vec![handler_b]).with_sender("DEST_B"),
            shared_clock(now.clone()),
        );

        let s_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_s: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_a: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let a_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_b: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let source_side = source.add_side_packed_with_options(
            "relay",
            {
                let q = s_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );
        let relay_source_side = relay.add_side_packed_with_options(
            "source",
            {
                let q = r_to_s.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let relay_a_side = relay.add_side_packed_with_options(
            "dest_a",
            {
                let q = r_to_a.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let dest_a_side = dest_a.add_side_packed_with_options(
            "relay",
            {
                let q = a_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );
        let relay_b_side = relay.add_side_packed_with_options(
            "dest_b",
            {
                let q = r_to_b.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let dest_b_side = dest_b.add_side_packed_with_options(
            "relay",
            {
                let q = b_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        relay
            .rx_from_side(
                relay_a_side,
                build_discovery_announce("DEST_A", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            )
            .unwrap();
        relay
            .rx_from_side(
                relay_b_side,
                build_discovery_announce("DEST_B", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            )
            .unwrap();
        for _ in 0..8 {
            relay.process_all_queues().unwrap();
            for frame in drain_queue(&r_to_s) {
                source
                    .rx_packed_queue_from_side(&frame, source_side)
                    .unwrap();
            }
            source.process_all_queues_with_timeout(0).unwrap();
        }

        source
            .tx(Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[7.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                7,
            )
            .unwrap())
            .unwrap();
        source.process_all_queues_with_timeout(0).unwrap();

        let mut dropped_b_first_delivery = false;
        let mut forwarded_b_frames = 0usize;
        for _ in 0..4 {
            relay.process_all_queues().unwrap();
            dest_a.process_all_queues_with_timeout(0).unwrap();
            dest_b.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&s_to_r) {
                relay
                    .rx_packed_from_side(relay_source_side, &frame)
                    .unwrap();
            }

            for frame in drain_queue(&r_to_a) {
                dest_a
                    .rx_packed_queue_from_side(&frame, dest_a_side)
                    .unwrap();
            }

            for frame in drain_queue(&r_to_b) {
                let info = wire_format::peek_frame_info(&frame).unwrap();
                if info.envelope.ty == DataType::named("GPS_DATA") && !info.ack_only() {
                    forwarded_b_frames += 1;
                    if !dropped_b_first_delivery {
                        dropped_b_first_delivery = true;
                        continue;
                    }
                }
                dest_b
                    .rx_packed_queue_from_side(&frame, dest_b_side)
                    .unwrap();
            }

            for frame in drain_queue(&a_to_r) {
                relay.rx_packed_from_side(relay_a_side, &frame).unwrap();
            }

            for frame in drain_queue(&b_to_r) {
                relay.rx_packed_from_side(relay_b_side, &frame).unwrap();
            }

            for frame in drain_queue(&r_to_s) {
                source
                    .rx_packed_queue_from_side(&frame, source_side)
                    .unwrap();
            }

            source.process_all_queues_with_timeout(0).unwrap();
            relay.process_all_queues().unwrap();
            dest_a.process_all_queues_with_timeout(0).unwrap();
            dest_b.process_all_queues_with_timeout(0).unwrap();

            if dropped_b_first_delivery
                && delivered_a.lock().unwrap().len() == 1
                && delivered_b.lock().unwrap().len() == 1
                && forwarded_b_frames >= 2
            {
                break;
            }

            now.fetch_add(RELIABLE_RETRANSMIT_MS, Ordering::SeqCst);
        }

        assert!(
            dropped_b_first_delivery,
            "test never dropped DEST_B's first delivery"
        );
        assert_eq!(delivered_a.lock().unwrap().as_slice(), &[7]);
        assert_eq!(delivered_b.lock().unwrap().as_slice(), &[7]);
        assert!(
            forwarded_b_frames >= 2,
            "unacknowledged destination should keep receiving end-to-end retransmits"
        );
    }

    #[test]
    fn reliable_rocket_topology_exports_missing_boards_and_reaches_actuator() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let gs = Router::new_with_clock(
            RouterConfig::default().with_sender("GS"),
            shared_clock(now.clone()),
        );
        let gw = Relay::new(shared_clock(now.clone()));

        let actuator_hits: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let actuator_seen = actuator_hits.clone();
        let actuator = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        actuator_seen.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );
        let daq = Router::new_with_clock(
            RouterConfig::default().with_sender("DAQ"),
            shared_clock(now.clone()),
        );
        let flight = Router::new_with_clock(
            RouterConfig::default().with_sender("FC"),
            shared_clock(now.clone()),
        );

        let gs_to_gw: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gw_to_gs: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gw_to_ab: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let ab_to_gw: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gw_to_daq: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let daq_to_gw: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gw_to_fc: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let fc_to_gw: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let reliable_side_opts = RouterSideOptions {
            reliable_enabled: false,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        };
        let reliable_relay_opts = RelaySideOptions {
            reliable_enabled: false,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        };
        let topo_side_opts = RouterSideOptions {
            reliable_enabled: false,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        };
        let topo_relay_opts = RelaySideOptions {
            reliable_enabled: false,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        };

        let gs_side = gs.add_side_packed_with_options(
            "gw",
            {
                let q = gs_to_gw.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            reliable_side_opts,
        );
        let gw_gs_side = gw.add_side_packed_with_options(
            "gs",
            {
                let q = gw_to_gs.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            reliable_relay_opts,
        );
        let gw_ab_side = gw.add_side_packed_with_options(
            "ab",
            {
                let q = gw_to_ab.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            reliable_relay_opts,
        );
        let ab_side = actuator.add_side_packed_with_options(
            "gw",
            {
                let q = ab_to_gw.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            reliable_side_opts,
        );
        let gw_daq_side = gw.add_side_packed_with_options(
            "daq",
            {
                let q = gw_to_daq.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            topo_relay_opts,
        );
        let daq_side = daq.add_side_packed_with_options(
            "gw",
            {
                let q = daq_to_gw.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            topo_side_opts,
        );
        let gw_fc_side = gw.add_side_packed_with_options(
            "fc",
            {
                let q = gw_to_fc.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            topo_relay_opts,
        );
        let fc_side = flight.add_side_packed_with_options(
            "gw",
            {
                let q = fc_to_gw.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            topo_side_opts,
        );

        let pump_once = || {
            gs.process_all_queues_with_timeout(0).unwrap();
            gw.process_all_queues_with_timeout(0).unwrap();
            actuator.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();
            flight.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&gs_to_gw) {
                gw.rx_packed_from_side(gw_gs_side, &frame).unwrap();
            }
            for frame in drain_queue(&gw_to_gs) {
                gs.rx_packed_queue_from_side(&frame, gs_side).unwrap();
            }
            for frame in drain_queue(&gw_to_ab) {
                actuator.rx_packed_queue_from_side(&frame, ab_side).unwrap();
            }
            for frame in drain_queue(&ab_to_gw) {
                gw.rx_packed_from_side(gw_ab_side, &frame).unwrap();
            }
            for frame in drain_queue(&gw_to_daq) {
                daq.rx_packed_queue_from_side(&frame, daq_side).unwrap();
            }
            for frame in drain_queue(&daq_to_gw) {
                gw.rx_packed_from_side(gw_daq_side, &frame).unwrap();
            }
            for frame in drain_queue(&gw_to_fc) {
                flight.rx_packed_queue_from_side(&frame, fc_side).unwrap();
            }
            for frame in drain_queue(&fc_to_gw) {
                gw.rx_packed_from_side(gw_fc_side, &frame).unwrap();
            }

            gs.process_all_queues_with_timeout(0).unwrap();
            actuator.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();
            flight.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&gs_to_gw) {
                gw.rx_packed_from_side(gw_gs_side, &frame).unwrap();
            }
            for frame in drain_queue(&ab_to_gw) {
                gw.rx_packed_from_side(gw_ab_side, &frame).unwrap();
            }
            for frame in drain_queue(&daq_to_gw) {
                gw.rx_packed_from_side(gw_daq_side, &frame).unwrap();
            }
            for frame in drain_queue(&fc_to_gw) {
                gw.rx_packed_from_side(gw_fc_side, &frame).unwrap();
            }
            for frame in drain_queue(&gw_to_gs) {
                gs.rx_packed_queue_from_side(&frame, gs_side).unwrap();
            }
        };

        gs.rx_from_side(
            &build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            gs_side,
        )
        .unwrap();
        gs.rx_from_side(&build_discovery_announce("DAQ", 0, &[]).unwrap(), gs_side)
            .unwrap();
        gs.rx_from_side(&build_discovery_announce("FC", 0, &[]).unwrap(), gs_side)
            .unwrap();

        gw.rx_from_side(
            gw_ab_side,
            build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
        )
        .unwrap();
        gw.rx_from_side(
            gw_daq_side,
            build_discovery_announce("DAQ", 0, &[]).unwrap(),
        )
        .unwrap();
        gw.rx_from_side(gw_fc_side, build_discovery_announce("FC", 0, &[]).unwrap())
            .unwrap();

        for _ in 0..4 {
            pump_once();
        }

        let gs_topology = gs.export_topology();
        assert!(
            gs_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "DAQ"),
            "DAQ should appear in GS topology export"
        );
        assert!(
            gs_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "FC"),
            "FC should appear in GS topology export"
        );
        assert!(
            gs_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "AB"),
            "AB should appear in GS topology export"
        );

        gs.tx(Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[42.0, 1.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            42,
        )
        .unwrap())
            .unwrap();

        for _ in 0..8 {
            pump_once();
            if actuator_hits.lock().unwrap().as_slice() == [42] {
                break;
            }
            now.fetch_add(10, Ordering::SeqCst);
        }

        assert_eq!(actuator_hits.lock().unwrap().as_slice(), &[42]);
    }

    #[test]
    fn reliable_multidrop_rocket_bus_reaches_actuator_and_exports_full_topology() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let trunk_bus = SharedBus::new();
        let gw_bus = SharedBus::new();
        let rf_bus = SharedBus::new();

        let actuator_hits: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let actuator_seen = actuator_hits.clone();

        let gs = Router::new_with_clock(
            RouterConfig::default().with_sender("GS"),
            shared_clock(now.clone()),
        );
        let gw = Relay::new(shared_clock(now.clone()));
        let rf = Relay::new(shared_clock(now.clone()));
        let actuator = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        actuator_seen.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );
        let valve = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                |_pkt| Ok(()),
            )])
            .with_sender("VB"),
            shared_clock(now.clone()),
        );
        let daq = Router::new_with_clock(
            RouterConfig::default().with_sender("DAQ"),
            shared_clock(now.clone()),
        );
        let power = Router::new_with_clock(
            RouterConfig::default().with_sender("PB"),
            shared_clock(now.clone()),
        );
        let flight = Router::new_with_clock(
            RouterConfig::default().with_sender("FC"),
            shared_clock(now.clone()),
        );

        let side_opts = RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        };
        let relay_side_opts = RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        };

        let gs_trunk = gs.add_side_packed_with_options("trunk", trunk_bus.tx_handler(0), side_opts);
        let gw_trunk =
            gw.add_side_packed_with_options("trunk", trunk_bus.tx_handler(1), relay_side_opts);
        let rf_trunk =
            rf.add_side_packed_with_options("trunk", trunk_bus.tx_handler(2), relay_side_opts);

        let gw_child =
            gw.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(0), relay_side_opts);
        let actuator_side =
            actuator.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(1), side_opts);
        let valve_side =
            valve.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(2), side_opts);
        let daq_side = daq.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(3), side_opts);

        let rf_child =
            rf.add_side_packed_with_options("rf_bus", rf_bus.tx_handler(0), relay_side_opts);
        let power_side =
            power.add_side_packed_with_options("rf_bus", rf_bus.tx_handler(1), side_opts);
        let flight_side =
            flight.add_side_packed_with_options("rf_bus", rf_bus.tx_handler(2), side_opts);

        gs.announce_discovery().unwrap();
        gw.announce_discovery().unwrap();
        rf.announce_discovery().unwrap();
        actuator.announce_discovery().unwrap();
        valve.announce_discovery().unwrap();
        daq.announce_discovery().unwrap();
        power.announce_discovery().unwrap();
        flight.announce_discovery().unwrap();

        for _ in 0..32 {
            gs.process_all_queues_with_timeout(0).unwrap();
            gw.process_all_queues_with_timeout(0).unwrap();
            rf.process_all_queues_with_timeout(0).unwrap();
            actuator.process_all_queues_with_timeout(0).unwrap();
            valve.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();
            power.process_all_queues_with_timeout(0).unwrap();
            flight.process_all_queues_with_timeout(0).unwrap();

            for (src, frame) in trunk_bus.drain() {
                if src != 0 {
                    gs.rx_packed_queue_from_side(&frame, gs_trunk).unwrap();
                }
                if src != 1 {
                    gw.rx_packed_from_side(gw_trunk, &frame).unwrap();
                }
                if src != 2 {
                    rf.rx_packed_from_side(rf_trunk, &frame).unwrap();
                }
            }

            for (src, frame) in gw_bus.drain() {
                if src != 0 {
                    gw.rx_packed_from_side(gw_child, &frame).unwrap();
                }
                if src != 1 {
                    actuator
                        .rx_packed_queue_from_side(&frame, actuator_side)
                        .unwrap();
                }
                if src != 2 {
                    valve.rx_packed_queue_from_side(&frame, valve_side).unwrap();
                }
                if src != 3 {
                    daq.rx_packed_queue_from_side(&frame, daq_side).unwrap();
                }
            }

            for (src, frame) in rf_bus.drain() {
                if src != 0 {
                    rf.rx_packed_from_side(rf_child, &frame).unwrap();
                }
                if src != 1 {
                    power.rx_packed_queue_from_side(&frame, power_side).unwrap();
                }
                if src != 2 {
                    flight
                        .rx_packed_queue_from_side(&frame, flight_side)
                        .unwrap();
                }
            }

            now.fetch_add(25, Ordering::SeqCst);
            gs.poll_discovery().unwrap();
            gw.poll_discovery().unwrap();
            rf.poll_discovery().unwrap();
            actuator.poll_discovery().unwrap();
            valve.poll_discovery().unwrap();
            daq.poll_discovery().unwrap();
            power.poll_discovery().unwrap();
            flight.poll_discovery().unwrap();
        }

        let gs_topology = gs.export_topology();
        assert!(
            gs_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "DAQ"),
            "DAQ should appear in GS topology export"
        );
        assert!(
            gs_topology
                .routers
                .iter()
                .any(|board| board.sender_id == "FC"),
            "FC should appear in GS topology export"
        );

        gs.tx(Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[99.0, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            99,
        )
        .unwrap())
            .unwrap();

        for _ in 0..96 {
            gs.process_all_queues_with_timeout(0).unwrap();
            gw.process_all_queues_with_timeout(0).unwrap();
            rf.process_all_queues_with_timeout(0).unwrap();
            actuator.process_all_queues_with_timeout(0).unwrap();
            valve.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();
            power.process_all_queues_with_timeout(0).unwrap();
            flight.process_all_queues_with_timeout(0).unwrap();

            for (src, frame) in trunk_bus.drain() {
                if src != 0 {
                    gs.rx_packed_queue_from_side(&frame, gs_trunk).unwrap();
                }
                if src != 1 {
                    gw.rx_packed_from_side(gw_trunk, &frame).unwrap();
                }
                if src != 2 {
                    rf.rx_packed_from_side(rf_trunk, &frame).unwrap();
                }
            }
            for (src, frame) in gw_bus.drain() {
                if src != 0 {
                    gw.rx_packed_from_side(gw_child, &frame).unwrap();
                }
                if src != 1 {
                    actuator
                        .rx_packed_queue_from_side(&frame, actuator_side)
                        .unwrap();
                }
                if src != 2 {
                    valve.rx_packed_queue_from_side(&frame, valve_side).unwrap();
                }
                if src != 3 {
                    daq.rx_packed_queue_from_side(&frame, daq_side).unwrap();
                }
            }
            for (src, frame) in rf_bus.drain() {
                if src != 0 {
                    rf.rx_packed_from_side(rf_child, &frame).unwrap();
                }
                if src != 1 {
                    power.rx_packed_queue_from_side(&frame, power_side).unwrap();
                }
                if src != 2 {
                    flight
                        .rx_packed_queue_from_side(&frame, flight_side)
                        .unwrap();
                }
            }

            if actuator_hits.lock().unwrap().as_slice() == [99] {
                break;
            }

            now.fetch_add(RELIABLE_RETRANSMIT_MS / 2, Ordering::SeqCst);
        }

        assert_eq!(actuator_hits.lock().unwrap().as_slice(), &[99]);
    }

    #[test]
    fn reliable_multidrop_bus_retries_until_missed_listener_receives_frame() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let gw_bus = SharedBus::new();
        let src_to_gw: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gw_to_src: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let actuator_hits: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let actuator_seen = actuator_hits.clone();

        let source = Router::new_with_clock(
            RouterConfig::default().with_sender("GS"),
            shared_clock(now.clone()),
        );
        let gateway = Relay::new(shared_clock(now.clone()));
        let actuator = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        actuator_seen.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );
        let valve = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                |_pkt| Ok(()),
            )])
            .with_sender("VB"),
            shared_clock(now.clone()),
        );
        let daq = Router::new_with_clock(
            RouterConfig::default().with_sender("DAQ"),
            shared_clock(now.clone()),
        );

        let relay_side_opts = RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        };
        let side_opts = RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        };

        let source_uplink = source.add_side_packed_with_options(
            "gw",
            {
                let q = src_to_gw.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            side_opts,
        );
        let uplink = gateway.add_side_packed_with_options(
            "uplink",
            {
                let q = gw_to_src.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            relay_side_opts,
        );
        let gw_child =
            gateway.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(0), relay_side_opts);
        let actuator_side =
            actuator.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(1), side_opts);
        let valve_side =
            valve.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(2), side_opts);
        let daq_side = daq.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(3), side_opts);

        gateway
            .rx_from_side(
                gw_child,
                build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            )
            .unwrap();
        gateway
            .rx_from_side(
                gw_child,
                build_discovery_announce("VB", 0, &[DataEndpoint::named("SD_CARD")]).unwrap(),
            )
            .unwrap();
        gateway
            .rx_from_side(gw_child, build_discovery_announce("DAQ", 0, &[]).unwrap())
            .unwrap();
        for _ in 0..4 {
            gateway.process_all_queues().unwrap();
            for frame in drain_queue(&gw_to_src) {
                source
                    .rx_packed_queue_from_side(&frame, source_uplink)
                    .unwrap();
            }
            source.process_all_queues_with_timeout(0).unwrap();
            if source
                .export_topology()
                .routers
                .iter()
                .any(|board| board.sender_id == "AB")
            {
                break;
            }
            now.fetch_add(25, Ordering::SeqCst);
        }
        assert!(
            source
                .export_topology()
                .routers
                .iter()
                .any(|board| board.sender_id == "AB"),
            "source should learn that AB is reachable behind GW before the command is sent"
        );

        source
            .tx(Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[7.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                7,
            )
            .unwrap())
            .unwrap();

        let mut dropped_actuator_first_delivery = false;
        let mut source_to_gateway_data_frames = 0usize;
        let mut gateway_to_bus_data_frames = 0usize;
        let mut source_to_gateway_seqs = BTreeSet::new();
        for _ in 0..12 {
            source.process_all_queues_with_timeout(0).unwrap();
            gateway.process_all_queues().unwrap();
            actuator.process_all_queues_with_timeout(0).unwrap();
            valve.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&src_to_gw) {
                let info = wire_format::peek_frame_info(&frame).unwrap();
                if info.envelope.ty == DataType::named("GPS_DATA") && !info.ack_only() {
                    source_to_gateway_data_frames += 1;
                    if let Some(hdr) = info.reliable {
                        source_to_gateway_seqs.insert(hdr.seq);
                    }
                }
                gateway.rx_packed_from_side(uplink, &frame).unwrap();
            }
            for frame in drain_queue(&gw_to_src) {
                source
                    .rx_packed_queue_from_side(&frame, source_uplink)
                    .unwrap();
            }

            for (src, frame) in gw_bus.drain() {
                let info = wire_format::peek_frame_info(&frame).unwrap();
                if src == 0 && info.envelope.ty == DataType::named("GPS_DATA") && !info.ack_only() {
                    gateway_to_bus_data_frames += 1;
                }
                if src != 0 {
                    gateway.rx_packed_from_side(gw_child, &frame).unwrap();
                }

                let drop_for_actuator = src == 0
                    && info.envelope.ty == DataType::named("GPS_DATA")
                    && !info.ack_only()
                    && !dropped_actuator_first_delivery;

                if src != 1 && !drop_for_actuator {
                    actuator
                        .rx_packed_queue_from_side(&frame, actuator_side)
                        .unwrap();
                }
                if src != 2 {
                    valve.rx_packed_queue_from_side(&frame, valve_side).unwrap();
                }
                if src != 3 {
                    daq.rx_packed_queue_from_side(&frame, daq_side).unwrap();
                }
                if drop_for_actuator {
                    dropped_actuator_first_delivery = true;
                }
            }

            actuator.process_all_queues_with_timeout(0).unwrap();
            valve.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();

            for (src, frame) in gw_bus.drain() {
                if src != 0 {
                    gateway.rx_packed_from_side(gw_child, &frame).unwrap();
                }
                if src != 1 {
                    actuator
                        .rx_packed_queue_from_side(&frame, actuator_side)
                        .unwrap();
                }
                if src != 2 {
                    valve.rx_packed_queue_from_side(&frame, valve_side).unwrap();
                }
                if src != 3 {
                    daq.rx_packed_queue_from_side(&frame, daq_side).unwrap();
                }
            }

            gateway.process_all_queues().unwrap();
            source.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&gw_to_src) {
                source
                    .rx_packed_queue_from_side(&frame, source_uplink)
                    .unwrap();
            }
            source.process_all_queues_with_timeout(0).unwrap();

            if actuator_hits.lock().unwrap().as_slice() == [7] {
                break;
            }

            now.fetch_add(RELIABLE_RETRANSMIT_MS, Ordering::SeqCst);
        }

        assert!(
            dropped_actuator_first_delivery,
            "test never dropped the first actuator-bound frame"
        );
        assert_eq!(
            actuator_hits.lock().unwrap().as_slice(),
            &[7],
            "shared-bus reliable forwarding should retry until the missed listener receives the frame; src->gw data frames={source_to_gateway_data_frames}, src->gw seqs={source_to_gateway_seqs:?}, gw->bus data frames={gateway_to_bus_data_frames}"
        );
    }

    #[test]
    fn reliable_multidrop_forwarding_disables_hop_reliable_on_shared_side() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let gw_bus = SharedBus::new();
        let src_to_gw: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let gw_to_src: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let actuator_hits: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let actuator_seen = actuator_hits.clone();

        let source = Router::new_with_clock(
            RouterConfig::default().with_sender("GS"),
            shared_clock(now.clone()),
        );
        let gateway = Relay::new(shared_clock(now.clone()));
        let actuator = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        actuator_seen.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );
        let valve = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                |_pkt| Ok(()),
            )])
            .with_sender("VB"),
            shared_clock(now.clone()),
        );
        let daq = Router::new_with_clock(
            RouterConfig::default().with_sender("DAQ"),
            shared_clock(now.clone()),
        );

        let relay_side_opts = RelaySideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RelaySideOptions::default()
        };
        let side_opts = RouterSideOptions {
            reliable_enabled: true,
            link_local_enabled: false,
            ..RouterSideOptions::default()
        };

        let source_uplink = source.add_side_packed_with_options(
            "gw",
            {
                let q = src_to_gw.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            side_opts,
        );
        let uplink = gateway.add_side_packed_with_options(
            "uplink",
            {
                let q = gw_to_src.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            relay_side_opts,
        );
        let gw_child =
            gateway.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(0), relay_side_opts);
        let actuator_side =
            actuator.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(1), side_opts);
        let valve_side =
            valve.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(2), side_opts);
        let daq_side = daq.add_side_packed_with_options("gw_bus", gw_bus.tx_handler(3), side_opts);

        gateway
            .rx_from_side(
                gw_child,
                build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            )
            .unwrap();
        gateway
            .rx_from_side(
                gw_child,
                build_discovery_announce("VB", 0, &[DataEndpoint::named("SD_CARD")]).unwrap(),
            )
            .unwrap();
        gateway
            .rx_from_side(gw_child, build_discovery_announce("DAQ", 0, &[]).unwrap())
            .unwrap();
        for _ in 0..6 {
            gateway.process_all_queues().unwrap();
            gateway.announce_discovery().unwrap();
            gateway.process_all_queues().unwrap();
            for frame in drain_queue(&gw_to_src) {
                source
                    .rx_packed_queue_from_side(&frame, source_uplink)
                    .unwrap();
            }
            source.process_all_queues_with_timeout(0).unwrap();
            now.fetch_add(25, Ordering::SeqCst);
        }
        assert!(
            source
                .export_topology()
                .routers
                .iter()
                .any(|board| board.sender_id == "AB"),
            "source should learn that AB is reachable behind GW before the command is sent"
        );

        source
            .tx(Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[11.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                11,
            )
            .unwrap())
            .unwrap();

        let mut saw_reliable_source_frame = false;
        let mut saw_shared_side_data_frame = false;
        let mut shared_side_frame_flags = None;
        let mut saw_shared_side_control_frame = false;
        for _ in 0..24 {
            source.process_all_queues_with_timeout(0).unwrap();
            gateway.process_all_queues().unwrap();
            actuator.process_all_queues_with_timeout(0).unwrap();
            valve.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&src_to_gw) {
                let info = wire_format::peek_frame_info(&frame).unwrap();
                if info.envelope.ty == DataType::named("GPS_DATA") && !info.ack_only() {
                    saw_reliable_source_frame = info.reliable.is_some();
                }
                gateway.rx_packed_from_side(uplink, &frame).unwrap();
            }

            for (src, frame) in gw_bus.drain() {
                let info = wire_format::peek_frame_info(&frame).unwrap();
                if src == 0
                    && matches!(
                        info.envelope.ty,
                        DataType::ReliableAck | DataType::ReliablePacketRequest
                    )
                {
                    saw_shared_side_control_frame = true;
                }
                if src == 0 && info.envelope.ty == DataType::named("GPS_DATA") && !info.ack_only() {
                    saw_shared_side_data_frame = true;
                    shared_side_frame_flags = info.reliable.map(|hdr| hdr.flags);
                }
                if src != 0 {
                    gateway.rx_packed_from_side(gw_child, &frame).unwrap();
                }
                if src != 1 {
                    actuator
                        .rx_packed_queue_from_side(&frame, actuator_side)
                        .unwrap();
                }
                if src != 2 {
                    valve.rx_packed_queue_from_side(&frame, valve_side).unwrap();
                }
                if src != 3 {
                    daq.rx_packed_queue_from_side(&frame, daq_side).unwrap();
                }
            }

            actuator.process_all_queues_with_timeout(0).unwrap();
            valve.process_all_queues_with_timeout(0).unwrap();
            daq.process_all_queues_with_timeout(0).unwrap();

            if actuator_hits.lock().unwrap().as_slice() == [11] {
                break;
            }

            now.fetch_add(RELIABLE_RETRANSMIT_MS / 2, Ordering::SeqCst);
        }

        assert!(
            saw_reliable_source_frame,
            "source->gateway hop should still use reliable framing"
        );
        assert!(
            saw_shared_side_data_frame,
            "gateway never forwarded the application packet onto the shared child side"
        );
        assert!(
            !saw_shared_side_control_frame,
            "gateway should not emit hop-level reliable control frames onto a shared packed side with multiple announcers"
        );
        assert_eq!(
            shared_side_frame_flags,
            Some(wire_format::RELIABLE_FLAG_UNSEQUENCED),
            "gateway should rewrite the forwarded shared-side application frame as unsequenced instead of using hop-level ACK sequencing"
        );
        assert_eq!(actuator_hits.lock().unwrap().as_slice(), &[11]);
    }

    #[test]
    fn mixed_first_hop_reliable_modes_still_reach_final_node() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_sink = delivered.clone();

        let source = Router::new_with_clock(
            RouterConfig::default().with_sender("GS"),
            shared_clock(now.clone()),
        );
        let relay = Relay::new(shared_clock(now.clone()));
        let dest = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        delivered_sink.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );

        let s_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_s: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_d: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let d_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let source_side = source.add_side_packed_with_options(
            "relay",
            {
                let q = s_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );
        let relay_source_side = relay.add_side_packed_with_options(
            "source_old_fw",
            {
                let q = r_to_s.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: false,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let relay_dest_side = relay.add_side_packed_with_options(
            "dest",
            {
                let q = r_to_d.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let dest_side = dest.add_side_packed_with_options(
            "relay",
            {
                let q = d_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        relay
            .rx_from_side(
                relay_dest_side,
                build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            )
            .unwrap();
        relay.announce_discovery().unwrap();
        relay.process_all_queues().unwrap();
        for frame in drain_queue(&r_to_s) {
            source
                .rx_packed_queue_from_side(&frame, source_side)
                .unwrap();
        }
        source.process_all_queues_with_timeout(0).unwrap();

        source
            .tx(Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[21.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                21,
            )
            .unwrap())
            .unwrap();

        for _ in 0..32 {
            source.process_all_queues_with_timeout(0).unwrap();
            relay.process_all_queues().unwrap();
            dest.process_all_queues_with_timeout(0).unwrap();

            for frame in drain_queue(&s_to_r) {
                relay
                    .rx_packed_from_side(relay_source_side, &frame)
                    .unwrap();
            }
            for frame in drain_queue(&r_to_d) {
                dest.rx_packed_queue_from_side(&frame, dest_side).unwrap();
            }
            for frame in drain_queue(&d_to_r) {
                relay.rx_packed_from_side(relay_dest_side, &frame).unwrap();
            }
            for frame in drain_queue(&r_to_s) {
                source
                    .rx_packed_queue_from_side(&frame, source_side)
                    .unwrap();
            }

            if delivered.lock().unwrap().as_slice() == [21] {
                break;
            }
            now.fetch_add(RELIABLE_RETRANSMIT_MS, Ordering::SeqCst);
        }

        assert_eq!(
            delivered.lock().unwrap().as_slice(),
            &[21],
            "mixed reliable/non-reliable first hop should still deliver the command"
        );
    }

    #[test]
    fn delayed_intermediate_rx_processing_only_delays_reliable_delivery() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let delivered: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_sink = delivered.clone();

        let source = Router::new_with_clock(
            RouterConfig::default().with_sender("GS"),
            shared_clock(now.clone()),
        );
        let relay = Relay::new(shared_clock(now.clone()));
        let dest = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        delivered_sink.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );

        let s_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_s: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let r_to_d: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let d_to_r: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let source_side = source.add_side_packed_with_options(
            "relay",
            {
                let q = s_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );
        let relay_source_side = relay.add_side_packed_with_options(
            "source",
            {
                let q = r_to_s.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let relay_dest_side = relay.add_side_packed_with_options(
            "dest",
            {
                let q = r_to_d.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RelaySideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        let dest_side = dest.add_side_packed_with_options(
            "relay",
            {
                let q = d_to_r.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        relay
            .rx_from_side(
                relay_dest_side,
                build_discovery_announce("AB", 0, &[DataEndpoint::named("RADIO")]).unwrap(),
            )
            .unwrap();
        relay.announce_discovery().unwrap();
        relay.process_all_queues().unwrap();
        for frame in drain_queue(&r_to_s) {
            source
                .rx_packed_queue_from_side(&frame, source_side)
                .unwrap();
        }
        source.process_all_queues_with_timeout(0).unwrap();

        source
            .tx(Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[33.0, 0.0, 0.0],
                &[DataEndpoint::named("RADIO")],
                33,
            )
            .unwrap())
            .unwrap();

        let mut delayed_first_hop_frames = Vec::new();
        for tick in 0..40 {
            source.process_all_queues_with_timeout(0).unwrap();
            relay.process_all_queues().unwrap();
            dest.process_all_queues_with_timeout(0).unwrap();

            delayed_first_hop_frames.extend(drain_queue(&s_to_r));

            if tick >= 4 {
                for frame in delayed_first_hop_frames.drain(..) {
                    relay
                        .rx_packed_from_side(relay_source_side, &frame)
                        .unwrap();
                }
            }

            for frame in drain_queue(&r_to_d) {
                dest.rx_packed_queue_from_side(&frame, dest_side).unwrap();
            }
            for frame in drain_queue(&d_to_r) {
                relay.rx_packed_from_side(relay_dest_side, &frame).unwrap();
            }
            for frame in drain_queue(&r_to_s) {
                source
                    .rx_packed_queue_from_side(&frame, source_side)
                    .unwrap();
            }

            if delivered.lock().unwrap().as_slice() == [33] {
                break;
            }
            now.fetch_add(RELIABLE_RETRANSMIT_MS, Ordering::SeqCst);
        }

        assert_eq!(
            delivered.lock().unwrap().as_slice(),
            &[33],
            "slow intermediate RX processing should delay but not prevent delivery"
        );
    }

    #[test]
    fn reflected_duplicate_ordered_frames_do_not_confuse_final_receiver() {
        ensure_common_test_schema();
        let now = Arc::new(AtomicU64::new(0));
        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let recv_sink = received.clone();

        let receiver = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        recv_sink.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("AB"),
            shared_clock(now.clone()),
        );
        let echoed_frames: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let side = receiver.add_side_packed_with_options(
            "echoed_bus",
            {
                let q = echoed_frames.clone();
                move |bytes: &[u8]| -> TelemetryResult<()> {
                    q.lock().unwrap().push_back(bytes.to_vec());
                    Ok(())
                }
            },
            RouterSideOptions {
                reliable_enabled: true,
                link_local_enabled: false,
                ..RouterSideOptions::default()
            },
        );

        let pkt1 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[1.0, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            1,
        )
        .unwrap();
        let pkt2 = Packet::from_f32_slice(
            DataType::named("GPS_DATA"),
            &[2.0, 0.0, 0.0],
            &[DataEndpoint::named("RADIO")],
            2,
        )
        .unwrap();
        let seq1 = wire_format::pack_packet_with_reliable(
            &pkt1,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 1,
                ack: 0,
            },
        );
        let seq2 = wire_format::pack_packet_with_reliable(
            &pkt2,
            wire_format::ReliableHeader {
                flags: 0,
                seq: 2,
                ack: 0,
            },
        );

        receiver.rx_packed_queue_from_side(&seq1, side).unwrap();
        receiver.process_all_queues_with_timeout(0).unwrap();
        receiver.rx_packed_queue_from_side(&seq1, side).unwrap();
        receiver.process_all_queues_with_timeout(0).unwrap();
        receiver.rx_packed_queue_from_side(&seq2, side).unwrap();
        receiver.process_all_queues_with_timeout(0).unwrap();
        receiver.rx_packed_queue_from_side(&seq1, side).unwrap();
        receiver.process_all_queues_with_timeout(0).unwrap();
        receiver.rx_packed_queue_from_side(&seq2, side).unwrap();
        receiver.process_all_queues_with_timeout(0).unwrap();

        assert_eq!(
            received.lock().unwrap().as_slice(),
            &[1, 2],
            "reflected duplicates should not break ordered reliable delivery"
        );
        assert!(
            !drain_queue(&echoed_frames).is_empty(),
            "receiver should still emit ACK/control traffic for the ordered stream"
        );
    }

    #[derive(Debug)]
    struct SoakLinkPolicy {
        rng: u64,
        down_until_tick: [usize; 14],
        delivered: usize,
        dropped: usize,
        random_disconnects: usize,
        planned_disconnects: usize,
    }

    impl SoakLinkPolicy {
        fn new() -> Self {
            Self {
                rng: 0x5ED5_2026_CAFE_BABE,
                down_until_tick: [0; 14],
                delivered: 0,
                dropped: 0,
                random_disconnects: 0,
                planned_disconnects: 0,
            }
        }

        fn next_u32(&mut self) -> u32 {
            self.rng = self
                .rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.rng >> 32) as u32
        }

        fn budget(&self, link: usize) -> usize {
            match link {
                0 | 1 => 12, // fast ground-station trunk
                2 | 3 => 3,  // slow RF backup
                4..=7 => 6,  // medium local buses
                _ => 4,
            }
        }

        fn maybe_churn(&mut self, tick: usize) {
            if tick == 90 {
                self.down_until_tick[0] = tick + 20;
                self.down_until_tick[1] = tick + 20;
                self.planned_disconnects += 1;
            }
            if tick == 180 {
                self.down_until_tick[4] = tick + 15;
                self.down_until_tick[5] = tick + 15;
                self.planned_disconnects += 1;
            }
            if tick == 320 {
                self.down_until_tick[2] = tick + 45;
                self.down_until_tick[3] = tick + 45;
                self.planned_disconnects += 1;
            }
            if tick.is_multiple_of(37) {
                let link = (self.next_u32() as usize) % self.down_until_tick.len();
                self.down_until_tick[link] = tick + 3 + ((self.next_u32() as usize) % 9);
                self.random_disconnects += 1;
            }
        }

        fn is_up(&self, link: usize, tick: usize) -> bool {
            tick >= self.down_until_tick[link]
        }

        fn should_drop(&mut self, link: usize, frame: &[u8]) -> bool {
            let divisor = match link {
                2 | 3 => 5,
                8..=13 => 11,
                _ => 29,
            };
            let control_bias = wire_format::peek_envelope(frame)
                .map(|env| {
                    matches!(
                        env.ty,
                        DataType::ReliableAck
                            | DataType::ReliablePacketRequest
                            | DataType::ReliablePartialAck
                    )
                })
                .unwrap_or(false);
            let threshold = if control_bias { divisor * 2 } else { divisor };
            self.next_u32().is_multiple_of(threshold)
        }

        fn account_delivered(&mut self) {
            self.delivered += 1;
        }

        fn account_dropped(&mut self) {
            self.dropped += 1;
        }
    }

    fn deliver_soak_link<F>(
        q: &Arc<Mutex<VecDeque<Vec<u8>>>>,
        link: usize,
        tick: usize,
        policy: &mut SoakLinkPolicy,
        mut deliver: F,
    ) where
        F: FnMut(Vec<u8>),
    {
        if !policy.is_up(link, tick) {
            return;
        }
        for frame in drain_queue_limited(q, policy.budget(link)) {
            if policy.should_drop(link, &frame) {
                policy.account_dropped();
                continue;
            }
            policy.account_delivered();
            deliver(frame);
        }
    }

    fn tolerate_soak_backpressure(result: TelemetryResult<()>) {
        match result {
            Ok(()) => {}
            Err(sedsnet::TelemetryError::PacketTooLarge(msg))
                if msg.contains("reliable history full") => {}
            Err(err) => panic!("unexpected soak processing error: {err:?}"),
        }
    }

    fn pump_soak_topology(topology: &RocketTopology, tick: usize, policy: &mut SoakLinkPolicy) {
        tolerate_soak_backpressure(topology.gs.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.gw.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.rf.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.actuator.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.valve.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.daq.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.power.process_all_queues_with_timeout(0));
        tolerate_soak_backpressure(topology.flight.process_all_queues_with_timeout(0));

        deliver_soak_link(&topology.gs_gw_tx, 0, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology.gw.rx_packed_from_side(topology.gw_gs_side, &frame),
            );
        });
        deliver_soak_link(&topology.gw_gs_tx, 1, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .gs
                    .rx_packed_queue_from_side(&frame, topology.gs_gw_side),
            );
        });
        deliver_soak_link(&topology.gs_rf_tx, 2, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology.rf.rx_packed_from_side(topology.rf_gs_side, &frame),
            );
        });
        deliver_soak_link(&topology.rf_gs_tx, 3, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .gs
                    .rx_packed_queue_from_side(&frame, topology.gs_rf_side),
            );
        });
        deliver_soak_link(&topology.gw_ab_tx, 4, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .actuator
                    .rx_packed_queue_from_side(&frame, topology.actuator_side),
            );
        });
        deliver_soak_link(&topology.ab_gw_tx, 5, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology.gw.rx_packed_from_side(topology.gw_ab_side, &frame),
            );
        });
        deliver_soak_link(&topology.gw_vb_tx, 6, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .valve
                    .rx_packed_queue_from_side(&frame, topology.valve_side),
            );
        });
        deliver_soak_link(&topology.vb_gw_tx, 7, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology.gw.rx_packed_from_side(topology.gw_vb_side, &frame),
            );
        });
        deliver_soak_link(&topology.gw_daq_tx, 8, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .daq
                    .rx_packed_queue_from_side(&frame, topology.daq_side),
            );
        });
        deliver_soak_link(&topology.daq_gw_tx, 9, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .gw
                    .rx_packed_from_side(topology.gw_daq_side, &frame),
            );
        });
        deliver_soak_link(&topology.rf_pb_tx, 10, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .power
                    .rx_packed_queue_from_side(&frame, topology.power_side),
            );
        });
        deliver_soak_link(&topology.pb_rf_tx, 11, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology.rf.rx_packed_from_side(topology.rf_pb_side, &frame),
            );
        });
        deliver_soak_link(&topology.rf_fc_tx, 12, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology
                    .flight
                    .rx_packed_queue_from_side(&frame, topology.flight_side),
            );
        });
        deliver_soak_link(&topology.fc_rf_tx, 13, tick, policy, |frame| {
            tolerate_soak_backpressure(
                topology.rf.rx_packed_from_side(topology.rf_fc_side, &frame),
            );
        });
    }

    fn exercise_compact_side_transport_in_soak(now: Arc<AtomicU64>) {
        let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let received_c = received.clone();
        let receiver = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("RADIO"),
                move |pkt| {
                    let vals = pkt.data_as_f32()?;
                    if let Some(first) = vals.first() {
                        received_c.lock().unwrap().push(*first as u32);
                    }
                    Ok(())
                },
            )])
            .with_sender("COMPACT_RX"),
            shared_clock(now.clone()),
        );

        let link: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let tx_link = link.clone();
        let sender = Router::new_with_clock(
            RouterConfig::default().with_sender("COMPACT_TX"),
            shared_clock(now),
        );
        let tx_side = sender.add_side_packed_with_options(
            "compact-can-fd",
            move |bytes| {
                tx_link.lock().unwrap().push_back(bytes.to_vec());
                Ok(())
            },
            RouterSideOptions {
                reliable_enabled: true,
                max_frame_bytes: 48,
                max_side_transport_templates: 4,
                ..RouterSideOptions::default()
                    .with_ipv4_like_compact_header_target()
                    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
            },
        );
        let rx_side = receiver.add_side_packed_with_options(
            "compact-can-fd",
            |_bytes| Ok(()),
            RouterSideOptions {
                reliable_enabled: true,
                max_frame_bytes: 48,
                max_side_transport_templates: 4,
                ..RouterSideOptions::default()
                    .with_ipv4_like_compact_header_target()
                    .with_omitted_unchanged_compact_timestamps_for_type(DataType::named("GPS_DATA"))
            },
        );
        sender
            .set_source_route_mode(None, RouteSelectionMode::Weighted)
            .unwrap();
        sender.set_route_weight(None, tx_side, 3).unwrap();
        sender.set_route_priority(None, tx_side, 1).unwrap();

        for seq in 0..12u32 {
            let pkt = Packet::from_f32_slice(
                DataType::named("GPS_DATA"),
                &[seq as f32, 1.0, 2.0],
                &[DataEndpoint::named("RADIO")],
                77_000,
            )
            .unwrap()
            .with_nonce(seq as u16 + 1);
            sender.tx(pkt).unwrap();
            sender.process_all_queues_with_timeout(0).unwrap();
            for frame in drain_queue(&link) {
                receiver.rx_packed_queue_from_side(&frame, rx_side).unwrap();
            }
            receiver.process_all_queues_with_timeout(0).unwrap();
        }

        let stats = sender.export_runtime_stats();
        let side = stats
            .sides
            .iter()
            .find(|side| side.side_name == "compact-can-fd")
            .expect("missing compact side stats");
        assert!(side.side_transport_compact_frames >= 8);
        assert!(side.side_transport_compact_omitted_timestamp_frames >= 8);
        assert!(side.side_transport_chunk_frames > 0);
        assert_eq!(received.lock().unwrap().len(), 12);
    }

    #[test]
    #[ignore = "multi-minute deterministic soak: run explicitly with cargo test --test reliable_drop_test comprehensive_multinode_churn_soak_exercises_stack_features -- --ignored --nocapture"]
    fn comprehensive_multinode_churn_soak_exercises_stack_features() {
        ensure_common_test_schema();
        let topology = RocketTopology::new();
        let tick_count = std::env::var("SEDSNET_SOAK_TICKS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1_440);
        let tick_ms = std::env::var("SEDSNET_SOAK_TICK_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(250);

        let var_ty = DataType(3_860);
        let bytes_ty = DataType(3_861);
        let _ = sedsnet::config::remove_data_type(var_ty);
        let _ = sedsnet::config::remove_data_type(bytes_ty);
        sedsnet::config::register_data_type_id_with_description(
            var_ty,
            "SOAK_NETWORK_VARIABLE",
            "Network-variable value exercised by the long churn soak.",
            MessageElement::Static(1, MessageDataType::UInt32, MessageClass::Data),
            &[DataEndpoint::named("SD_CARD")],
            ReliableMode::None,
            40,
        )
        .unwrap();
        sedsnet::config::register_data_type_id_with_description(
            bytes_ty,
            "SOAK_DYNAMIC_BYTES",
            "Large dynamic byte payload used to exercise compression and chunking paths.",
            MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            &[DataEndpoint::named("SD_CARD")],
            ReliableMode::None,
            30,
        )
        .unwrap();

        topology
            .gs
            .enable_network_variable(var_ty, NetworkVariablePermissions::READ_WRITE)
            .unwrap();
        topology
            .valve
            .enable_network_variable(var_ty, NetworkVariablePermissions::READ_WRITE)
            .unwrap();
        topology
            .actuator
            .enable_network_variable(var_ty, NetworkVariablePermissions::READ_ONLY)
            .unwrap();
        topology
            .gs
            .set_source_route_mode(None, RouteSelectionMode::Weighted)
            .unwrap();
        topology
            .gs
            .set_route_weight(None, topology.gs_gw_side, 4)
            .unwrap();
        topology
            .gs
            .set_route_weight(None, topology.gs_rf_side, 1)
            .unwrap();
        topology
            .gs
            .set_typed_route(None, DataType::named("GPS_DATA"), topology.gs_gw_side, true)
            .unwrap();
        topology
            .gs
            .set_typed_route(None, var_ty, topology.gs_gw_side, true)
            .unwrap();
        topology
            .gs
            .set_typed_route(None, bytes_ty, topology.gs_gw_side, true)
            .unwrap();
        topology
            .gw
            .set_source_route_mode(None, RouteSelectionMode::Failover)
            .unwrap();
        topology
            .rf
            .set_source_route_mode(None, RouteSelectionMode::Weighted)
            .unwrap();
        topology
            .gw
            .set_typed_route(None, DataType::named("GPS_DATA"), topology.gw_ab_side, true)
            .unwrap();
        topology
            .gw
            .set_route_priority(None, topology.gw_ab_side, 1)
            .unwrap();

        let temp_router_side = topology.daq.add_side_packed_with_options(
            "planned_temp_diag",
            |_bytes| Ok(()),
            RouterSideOptions {
                max_frame_bytes: 40,
                ..RouterSideOptions::default().with_ipv6_like_compact_header_target()
            },
        );
        topology.daq.remove_side(temp_router_side).unwrap();
        let temp_relay_side = topology.gw.add_side_packet_with_options(
            "planned_temp_ingress",
            |_pkt| Ok(()),
            RelaySideOptions {
                ingress_enabled: false,
                egress_enabled: false,
                ..RelaySideOptions::default()
            },
        );
        topology
            .gw
            .set_side_ingress_enabled(temp_relay_side, true)
            .unwrap();
        topology
            .gw
            .set_side_egress_enabled(temp_relay_side, true)
            .unwrap();
        topology.gw.remove_side(temp_relay_side).unwrap();

        topology.gs.set_timesync_config(Some(TimeSyncConfig {
            role: TimeSyncRole::Source,
            priority: 1,
            ..TimeSyncConfig::default()
        }));
        topology
            .gs
            .set_local_network_time(sedsnet::timesync::PartialNetworkTime {
                year: Some(2026),
                month: Some(6),
                day: Some(25),
                hour: Some(12),
                minute: Some(0),
                second: Some(0),
                nanosecond: Some(0),
            });
        topology
            .actuator
            .set_timesync_config(Some(TimeSyncConfig::default()));

        let mut policy = SoakLinkPolicy::new();
        let mut issued_reliable = 0u32;
        let mut issued_variables = 0u32;
        let mut issued_large_payloads = 0u32;

        topology.gs.announce_discovery().unwrap();
        topology.gw.announce_discovery().unwrap();
        topology.rf.announce_discovery().unwrap();
        topology.actuator.announce_discovery().unwrap();
        topology.valve.announce_discovery().unwrap();
        topology.daq.announce_discovery().unwrap();
        topology.power.announce_discovery().unwrap();
        topology.flight.announce_discovery().unwrap();

        for tick in 0..tick_count {
            policy.maybe_churn(tick);

            if tick == 120 {
                topology
                    .gs
                    .set_side_egress_enabled(topology.gs_rf_side, false)
                    .unwrap();
                policy.planned_disconnects += 1;
            }
            if tick == 155 {
                topology
                    .gs
                    .set_side_egress_enabled(topology.gs_rf_side, true)
                    .unwrap();
            }
            if tick == 260 {
                topology
                    .gw
                    .set_side_ingress_enabled(topology.gw_daq_side, false)
                    .unwrap();
                policy.planned_disconnects += 1;
            }
            if tick == 300 {
                topology
                    .gw
                    .set_side_ingress_enabled(topology.gw_daq_side, true)
                    .unwrap();
            }
            if tick == tick_count / 2 {
                topology
                    .gw
                    .clear_typed_route(None, DataType::named("GPS_DATA"), topology.gw_ab_side)
                    .unwrap();
                topology
                    .gs
                    .set_source_route_mode(None, RouteSelectionMode::Failover)
                    .unwrap();
            }

            if tick % 48 == 0 {
                let pkt = Packet::from_f32_slice(
                    DataType::named("GPS_DATA"),
                    &[issued_reliable as f32, 0.25, 0.5],
                    &[DataEndpoint::named("RADIO")],
                    topology.now.load(Ordering::SeqCst),
                )
                .unwrap()
                .with_nonce((issued_reliable & 0xFFFF) as u16);
                topology.gs.tx(pkt).unwrap();
                issued_reliable += 1;
            }

            if tick % 96 == 0 {
                let pkt = Packet::from_u32_slice(
                    var_ty,
                    &[issued_variables],
                    &[DataEndpoint::named("SD_CARD")],
                    topology.now.load(Ordering::SeqCst),
                )
                .unwrap();
                topology.gs.set_network_variable(pkt).unwrap();
                issued_variables += 1;
            }

            if tick % 144 == 0 {
                let payload = vec![(tick & 0xFF) as u8; 320];
                let pkt = Packet::new(
                    bytes_ty,
                    &[DataEndpoint::named("SD_CARD")],
                    "SOAK_GS",
                    topology.now.load(Ordering::SeqCst),
                    Arc::<[u8]>::from(payload),
                )
                .unwrap();
                topology.gs.tx(pkt).unwrap();
                issued_large_payloads += 1;
            }

            if tick % 50 == 0 {
                topology.gs.announce_discovery().unwrap();
                topology.gw.announce_discovery().unwrap();
                topology.rf.announce_discovery().unwrap();
                topology.actuator.announce_discovery().unwrap();
                topology.valve.announce_discovery().unwrap();
                topology.daq.announce_discovery().unwrap();
                topology.power.announce_discovery().unwrap();
                topology.flight.announce_discovery().unwrap();
                topology.gs.request_topology().unwrap();
                topology.gs.request_schema().unwrap();
            }

            if tick % 64 == 0 {
                let _ = topology.valve.get_network_variable(var_ty, Some(10));
                let _ = topology.actuator.get_network_variable(var_ty, Some(10));
            }

            tolerate_soak_backpressure(topology.gs.periodic(0));
            tolerate_soak_backpressure(topology.actuator.periodic(0));
            tolerate_soak_backpressure(topology.valve.periodic(0));
            tolerate_soak_backpressure(topology.daq.periodic(0));
            tolerate_soak_backpressure(topology.power.periodic(0));
            tolerate_soak_backpressure(topology.flight.periodic(0));
            tolerate_soak_backpressure(topology.gw.periodic(0));
            tolerate_soak_backpressure(topology.rf.periodic(0));
            pump_soak_topology(&topology, tick, &mut policy);
            topology.advance(tick_ms);
        }

        policy.down_until_tick.fill(0);
        for settle_tick in 0..800 {
            tolerate_soak_backpressure(topology.gs.periodic(0));
            tolerate_soak_backpressure(topology.actuator.periodic(0));
            tolerate_soak_backpressure(topology.valve.periodic(0));
            tolerate_soak_backpressure(topology.daq.periodic(0));
            tolerate_soak_backpressure(topology.power.periodic(0));
            tolerate_soak_backpressure(topology.flight.periodic(0));
            tolerate_soak_backpressure(topology.gw.periodic(0));
            tolerate_soak_backpressure(topology.rf.periodic(0));
            pump_soak_topology(&topology, tick_count + settle_tick, &mut policy);
            topology.advance(RELIABLE_RETRANSMIT_MS);
        }

        let actuator_hits = topology.actuator_hits.lock().unwrap().clone();
        assert!(
            actuator_hits.len() >= (issued_reliable as usize).saturating_add(1) / 2,
            "actuator should receive most reliable packets after churn recovery: got {}, issued {}",
            actuator_hits.len(),
            issued_reliable
        );
        assert!(
            policy.delivered > 100,
            "soak did not deliver enough frames: {policy:?}"
        );
        assert!(
            policy.dropped > 0,
            "soak did not drop any frames: {policy:?}"
        );
        assert!(
            policy.random_disconnects > 0 && policy.planned_disconnects >= 2,
            "disconnect/reconnect paths were not exercised: {policy:?}"
        );
        assert!(topology.gs.export_topology().routers.len() >= 2);
        assert!(topology.gw.export_topology().routers.len() >= 2);
        let gs_stats = topology.gs.export_runtime_stats();
        let gs_tx_packets: u64 = gs_stats.sides.iter().map(|side| side.tx_packets).sum();
        let gs_rx_packets: u64 = gs_stats.sides.iter().map(|side| side.rx_packets).sum();
        assert!(gs_tx_packets > 0);
        assert!(gs_rx_packets > 0);
        assert!(gs_stats.discovery.route_count > 0 || gs_stats.discovery.announcer_count > 0);
        let gw_stats = topology.gw.export_runtime_stats();
        let gw_tx_packets: u64 = gw_stats.sides.iter().map(|side| side.tx_packets).sum();
        let gw_rx_packets: u64 = gw_stats.sides.iter().map(|side| side.rx_packets).sum();
        assert!(gw_tx_packets > 0);
        assert!(gw_rx_packets > 0);
        assert!(
            topology
                .gs
                .export_memory_layout_json()
                .contains("network_variable_cache_bytes")
        );
        assert!(
            topology
                .valve
                .get_cached_network_variable(var_ty)
                .unwrap()
                .is_some()
        );
        assert!(topology.gs.network_time_ms().is_some());
        assert!(issued_large_payloads > 0);

        exercise_compact_side_transport_in_soak(topology.now.clone());

        #[cfg(feature = "cryptography")]
        {
            sedsnet::crypto::register_software_key(0xC0DE, b"0123456789abcdef0123456789abcdef")
                .unwrap();
            let encrypted_ty = DataType(3_862);
            let _ = sedsnet::config::remove_data_type(encrypted_ty);
            sedsnet::config::register_data_type_id_with_description_and_e2e_encryption(
                encrypted_ty,
                "SOAK_E2E_BYTES",
                "Encrypted byte payload used by the long churn soak.",
                MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
                &[DataEndpoint::named("RADIO")],
                ReliableMode::None,
                50,
                sedsnet::E2eEncryptionPolicy::PreferOn,
            )
            .unwrap();
            let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
            let captured_c = captured.clone();
            let crypto_router = Router::new_with_clock(
                RouterConfig::default()
                    .with_sender("SOAK_CRYPTO")
                    .with_e2e_encryption(RouterE2eEncryptionMode::Preferred)
                    .with_e2e_key_id(0xC0DE),
                shared_clock(topology.now.clone()),
            );
            crypto_router.add_side_packed("encrypted-link", move |bytes| {
                *captured_c.lock().unwrap() = bytes.to_vec();
                Ok(())
            });
            let payload = [9_u8, 8, 7, 6, 5, 4, 3, 2];
            crypto_router
                .tx(Packet::new(
                    encrypted_ty,
                    &[DataEndpoint::named("RADIO")],
                    "SOAK_CRYPTO",
                    topology.now.load(Ordering::SeqCst),
                    Arc::<[u8]>::from(&payload[..]),
                )
                .unwrap())
                .unwrap();
            let wire = captured.lock().unwrap().clone();
            assert!(!wire.windows(payload.len()).any(|window| window == payload));
            let decoded = wire_format::unpack_packet(&wire).unwrap();
            assert_eq!(decoded.data_type(), encrypted_ty);
            assert_eq!(decoded.payload(), payload);
        }

        let _ = sedsnet::config::remove_data_type(var_ty);
        let _ = sedsnet::config::remove_data_type(bytes_ty);
    }
}
