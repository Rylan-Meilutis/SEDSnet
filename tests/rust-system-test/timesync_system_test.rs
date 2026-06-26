#[cfg(feature = "timesync")]
mod timesync_system_test {
    use sedsnet::config::{
        DEVICE_IDENTIFIER, DataEndpoint, DataType, data_type_definition_by_name,
        endpoint_definition_by_name, register_data_type_with_description,
        register_endpoint_with_description,
    };
    use sedsnet::packet::Packet;
    use sedsnet::router::{Clock, EndpointHandler, Router, RouterConfig};
    use sedsnet::timesync::{
        PartialNetworkTime, TimeSyncConfig, TimeSyncRole, TimeSyncTracker,
        build_timesync_announce_with_sender, build_timesync_request, build_timesync_response,
        compute_offset_delay,
    };
    use sedsnet::wire_format;
    use sedsnet::{MessageClass, MessageDataType, MessageElement, ReliableMode};

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Once};
    use std::thread;

    struct StepClock {
        now_ns: AtomicU64,
        step_ns: u64,
    }

    impl Clock for StepClock {
        fn now_ms(&self) -> u64 {
            self.now_ns.fetch_add(self.step_ns, Ordering::SeqCst) / 1_000_000
        }

        fn now_ns(&self) -> u64 {
            self.now_ns.fetch_add(self.step_ns, Ordering::SeqCst)
        }
    }

    fn zero_clock() -> Box<dyn Clock + Send + Sync> {
        Box::new(|| 0u64)
    }

    fn shared_clock(now: Arc<AtomicU64>) -> Box<dyn Clock + Send + Sync> {
        Box::new(move || now.load(Ordering::SeqCst))
    }

    #[derive(Clone, Copy)]
    struct ScheduledLinkProfile {
        name: &'static str,
        source_to_consumer_latency_ms: u64,
        consumer_to_source_latency_ms: u64,
        jitter_ms: u64,
        slot_period_ms: Option<u64>,
        slot_offset_ms: u64,
        frames_per_tick: usize,
        duration_ms: u64,
        tick_ms: u64,
        max_error_ms: u64,
        max_timesync_frames: usize,
        max_slew_ppm: u32,
    }

    #[derive(Clone)]
    struct ScheduledPacket {
        due_ms: u64,
        seq: u64,
        pkt: Packet,
    }

    struct LinkScheduler {
        profile: ScheduledLinkProfile,
        one_way_latency_ms: u64,
        seq: u64,
        frames: VecDeque<ScheduledPacket>,
        timesync_frames: usize,
    }

    impl LinkScheduler {
        fn new(profile: ScheduledLinkProfile, one_way_latency_ms: u64) -> Self {
            Self {
                profile,
                one_way_latency_ms,
                seq: 0,
                frames: VecDeque::new(),
                timesync_frames: 0,
            }
        }

        fn enqueue(&mut self, now_ms: u64, pkt: Packet) {
            if matches!(
                pkt.data_type(),
                DataType::TimeSyncAnnounce | DataType::TimeSyncRequest | DataType::TimeSyncResponse
            ) {
                self.timesync_frames += 1;
            }

            let jitter = if self.profile.jitter_ms == 0 {
                0
            } else {
                self.seq.wrapping_mul(17) % (self.profile.jitter_ms + 1)
            };
            let mut due_ms = now_ms
                .saturating_add(self.one_way_latency_ms)
                .saturating_add(jitter);
            if let Some(period) = self.profile.slot_period_ms {
                let offset = self.profile.slot_offset_ms % period;
                if due_ms <= offset {
                    due_ms = offset;
                } else {
                    let elapsed = due_ms - offset;
                    let remainder = elapsed % period;
                    if remainder != 0 {
                        due_ms = due_ms.saturating_add(period - remainder);
                    }
                }
            }

            self.frames.push_back(ScheduledPacket {
                due_ms,
                seq: self.seq,
                pkt,
            });
            self.seq = self.seq.wrapping_add(1);
        }

        fn drain_due(&mut self, now_ms: u64) -> Vec<Packet> {
            let mut ready = Vec::new();
            let mut pending = VecDeque::new();
            while let Some(frame) = self.frames.pop_front() {
                if frame.due_ms <= now_ms && ready.len() < self.profile.frames_per_tick {
                    ready.push(frame);
                } else {
                    pending.push_back(frame);
                }
            }
            ready.sort_by_key(|frame| (frame.due_ms, frame.seq));
            self.frames = pending;
            ready.into_iter().map(|frame| frame.pkt).collect()
        }
    }

    fn ensure_compression_test_schema() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            if endpoint_definition_by_name("SD_CARD").is_none() {
                register_endpoint_with_description(
                    "SD_CARD",
                    "On-board storage endpoint used by system compression tests.",
                    false,
                )
                .expect("register SD_CARD");
            }
            if data_type_definition_by_name("MESSAGE_DATA").is_none() {
                register_data_type_with_description(
                    "MESSAGE_DATA",
                    "Dynamic bytes used by system compression tests.",
                    MessageElement::Dynamic(MessageDataType::Binary, MessageClass::Data),
                    &[DataEndpoint::named("SD_CARD")],
                    ReliableMode::None,
                    50,
                )
                .expect("register MESSAGE_DATA");
            }
        });
    }

    #[test]
    fn timesync_offset_delay_and_timestamp_update() {
        let req = build_timesync_request(1, 1_000).unwrap();
        let resp = build_timesync_response(1, 1_000, 1_010, 1_020).unwrap();
        let t4_ms = 1_030;
        let sample = compute_offset_delay(1_000, 1_010, 1_020, t4_ms);

        assert_eq!(sample.offset_ms, 0);
        assert_eq!(sample.delay_ms, 20);

        let captured = Arc::new(Mutex::new(None));
        let captured_c = captured.clone();
        let router = Router::new_with_clock(
            RouterConfig::new(vec![EndpointHandler::new_packet_handler(
                DataEndpoint::named("SD_CARD"),
                |_pkt| Ok(()),
            )]),
            zero_clock(),
        );
        router.add_side_packet("CAP", move |pkt| {
            *captured_c.lock().unwrap() = Some(pkt.timestamp());
            Ok(())
        });
        let offset_ts = (t4_ms as i64 + sample.offset_ms) as u64;
        router
            .log_ts(
                DataType::TimeSyncRequest,
                offset_ts,
                &req.data_as_u64().unwrap(),
            )
            .unwrap();

        let got = captured.lock().unwrap().expect("no timestamp captured");
        assert_eq!(got, offset_ts);

        let _ = resp;
    }

    #[test]
    fn timesync_failover_selects_next_source() {
        let mut tracker = TimeSyncTracker::new(TimeSyncConfig {
            role: TimeSyncRole::Auto,
            priority: 50,
            source_timeout_ms: 1_000,
            ..Default::default()
        });

        let pkt_a = build_timesync_announce_with_sender("SRC_A", 10, 5_000).unwrap();
        let pkt_b = build_timesync_announce_with_sender("SRC_B", 20, 5_000).unwrap();

        tracker.handle_announce(&pkt_a, 5_000).unwrap();
        tracker.handle_announce(&pkt_b, 5_000).unwrap();
        assert_eq!(tracker.current_source().unwrap().sender, "SRC_A");
        assert!(!tracker.should_announce(5_000, true));

        tracker.refresh(6_500);
        assert!(tracker.current_source().is_none());
        assert!(tracker.should_announce(6_500, true));

        let pkt_b_late = build_timesync_announce_with_sender("SRC_B", 20, 6_500).unwrap();
        tracker.handle_announce(&pkt_b_late, 6_500).unwrap();
        assert_eq!(tracker.current_source().unwrap().sender, "SRC_B");
        assert!(!tracker.should_announce(6_500, true));
    }

    #[test]
    fn timesync_equal_priority_failover_uses_standby_without_reannounce() {
        let mut tracker = TimeSyncTracker::new(TimeSyncConfig {
            role: TimeSyncRole::Consumer,
            priority: 50,
            source_timeout_ms: 1_000,
            ..Default::default()
        });

        let pkt_a = build_timesync_announce_with_sender("SRC_A", 10, 5_000).unwrap();
        let pkt_b = build_timesync_announce_with_sender("SRC_B", 10, 5_500).unwrap();

        tracker.handle_announce(&pkt_a, 5_000).unwrap();
        tracker.handle_announce(&pkt_b, 5_500).unwrap();
        assert_eq!(tracker.current_source().unwrap().sender, "SRC_A");

        assert!(matches!(
            tracker.refresh(6_050),
            sedsnet::timesync::TimeSyncUpdate::SourceChanged
        ));
        assert_eq!(tracker.current_source().unwrap().sender, "SRC_B");
        assert!(!tracker.should_announce(6_050, true));
    }

    #[test]
    fn source_role_participates_in_priority_election_and_follows_better_remote() {
        let mut tracker = TimeSyncTracker::new(TimeSyncConfig {
            role: TimeSyncRole::Source,
            priority: 20,
            source_timeout_ms: 1_000,
            ..Default::default()
        });

        assert!(tracker.should_announce(0, true));

        let pkt_better = build_timesync_announce_with_sender("SRC_A", 10, 5_000).unwrap();
        tracker.handle_announce(&pkt_better, 5_000).unwrap();

        assert_eq!(tracker.current_source().unwrap().sender, "SRC_A");
        assert!(!tracker.should_announce(5_000, true));
        assert_eq!(
            tracker.leader(5_000, true),
            Some(sedsnet::timesync::TimeSyncLeader::Remote(
                tracker.current_source().unwrap().clone()
            ))
        );
    }

    #[test]
    fn same_priority_leader_gets_boosted_priority() {
        let mut tracker = TimeSyncTracker::new(TimeSyncConfig {
            role: TimeSyncRole::Source,
            priority: 10,
            source_timeout_ms: 1_000,
            ..Default::default()
        });

        let remote = if DEVICE_IDENTIFIER < "ZZZ" {
            "ZZZ"
        } else {
            "zzzz"
        };
        let pkt_same = build_timesync_announce_with_sender(remote, 10, 5_000).unwrap();
        tracker.handle_announce(&pkt_same, 5_000).unwrap();

        assert_eq!(tracker.local_announce_priority(5_000, true), Some(9));
    }

    #[test]
    fn consumer_can_promote_when_no_remote_producer_and_has_time() {
        let tracker = TimeSyncTracker::new(TimeSyncConfig {
            role: TimeSyncRole::Consumer,
            priority: 40,
            source_timeout_ms: 1_000,
            consumer_promotion_enabled: true,
            ..Default::default()
        });

        assert!(tracker.should_announce(1_000, true));
    }

    #[test]
    fn consumer_promotion_can_be_disabled() {
        let tracker = TimeSyncTracker::new(TimeSyncConfig {
            role: TimeSyncRole::Consumer,
            priority: 40,
            source_timeout_ms: 1_000,
            consumer_promotion_enabled: false,
            ..Default::default()
        });

        assert!(!tracker.should_announce(1_000, true));
    }

    #[test]
    fn router_internal_timesync_endpoint_updates_network_time() {
        let now = Arc::new(AtomicU64::new(1_000));
        let router = Router::new_with_clock(
            RouterConfig::default().with_timesync(TimeSyncConfig::default()),
            shared_clock(now.clone()),
        );

        let announce = build_timesync_announce_with_sender("GM", 1, 1_700_000_000_000).unwrap();
        router.rx(&announce).unwrap();

        let first = router.network_time_ms().expect("network time unavailable");
        now.store(1_025, Ordering::SeqCst);
        let later = router.network_time_ms().expect("network time unavailable");
        assert!(
            later >= first + 25,
            "network time should advance with monotonic clock"
        );
    }

    #[test]
    fn router_failover_slews_without_jumping_backwards() {
        let now = Arc::new(AtomicU64::new(1_000));
        let router = Router::new_with_clock(
            RouterConfig::default().with_timesync(TimeSyncConfig {
                role: TimeSyncRole::Consumer,
                priority: 50,
                source_timeout_ms: 100,
                max_slew_ppm: 50_000,
                ..Default::default()
            }),
            shared_clock(now.clone()),
        );

        let leader_a = build_timesync_announce_with_sender("SRC_A", 10, 1_700_000_000_000).unwrap();
        let leader_b = build_timesync_announce_with_sender("SRC_B", 20, 1_699_999_990_000).unwrap();

        router.rx(&leader_a).unwrap();
        router.rx(&leader_b).unwrap();
        let before_failover = router.network_time_ms().expect("network time unavailable");

        now.store(1_200, Ordering::SeqCst);
        let after_timeout = router.network_time_ms().expect("network time unavailable");

        assert!(
            after_timeout >= before_failover,
            "failover must not jump backwards"
        );
    }

    #[test]
    fn router_clears_stale_pending_request_when_source_fails_over() {
        let now = Arc::new(AtomicU64::new(0));
        let request_seqs = Arc::new(Mutex::new(Vec::new()));
        let request_seqs_c = request_seqs.clone();
        let router = Router::new_with_clock(
            RouterConfig::default().with_timesync(TimeSyncConfig {
                role: TimeSyncRole::Consumer,
                priority: 50,
                source_timeout_ms: 1_000,
                request_interval_ms: 1_000,
                max_slew_ppm: 999_999,
                ..Default::default()
            }),
            shared_clock(now.clone()),
        );
        router.add_side_packet("CAP", move |pkt| {
            if pkt.data_type() == DataType::TimeSyncRequest {
                request_seqs_c
                    .lock()
                    .unwrap()
                    .push(pkt.data_as_u64().unwrap()[0]);
            }
            Ok(())
        });

        let leader_a = build_timesync_announce_with_sender("SRC_A", 1, 1_700_000_000_000).unwrap();
        router.rx(&leader_a).unwrap();
        router.process_tx_queue().unwrap();

        now.store(1_500, Ordering::SeqCst);
        let leader_b = build_timesync_announce_with_sender("SRC_B", 2, 1_700_000_001_500).unwrap();
        router.rx(&leader_b).unwrap();
        router.process_tx_queue().unwrap();

        let request_seqs = request_seqs.lock().unwrap().clone();
        assert_eq!(request_seqs, vec![1, 2]);

        let before_response = router.network_time_ms().expect("network time unavailable");
        let resp_b_wire =
            build_timesync_response(request_seqs[1], 1_500, 1_700_000_001_550, 1_700_000_001_550)
                .unwrap();
        let resp_b = Packet::new(
            DataType::TimeSyncResponse,
            &[DataEndpoint::TimeSync],
            "SRC_B",
            resp_b_wire.timestamp(),
            resp_b_wire.payload().into(),
        )
        .unwrap();
        router.rx(&resp_b).unwrap();

        now.store(1_600, Ordering::SeqCst);
        let after_response = router.network_time_ms().expect("network time unavailable");
        assert!(
            after_response >= before_response + 140,
            "failover response from replacement source should be accepted and influence the slewed clock: before={before_response}, after={after_response}"
        );
    }

    fn run_scheduled_timesync_profile(profile: ScheduledLinkProfile) {
        let now = Arc::new(AtomicU64::new(0));
        let epoch_ms = 1_700_000_000_000u64;

        let source_to_consumer = Arc::new(Mutex::new(LinkScheduler::new(
            profile,
            profile.source_to_consumer_latency_ms,
        )));
        let consumer_to_source = Arc::new(Mutex::new(LinkScheduler::new(
            profile,
            profile.consumer_to_source_latency_ms,
        )));

        let source = Router::new_with_clock(
            RouterConfig::default()
                .with_sender("TIME_SOURCE")
                .with_timesync(TimeSyncConfig {
                    role: TimeSyncRole::Source,
                    priority: 1,
                    announce_interval_ms: 2_000,
                    request_interval_ms: 1_500,
                    source_timeout_ms: 120_000,
                    max_slew_ppm: profile.max_slew_ppm,
                    ..Default::default()
                }),
            shared_clock(now.clone()),
        );
        source.set_local_network_time(PartialNetworkTime::from_unix_ms(epoch_ms));

        let consumer = Router::new_with_clock(
            RouterConfig::default()
                .with_sender(profile.name)
                .with_timesync(TimeSyncConfig {
                    role: TimeSyncRole::Consumer,
                    priority: 50,
                    announce_interval_ms: 2_000,
                    request_interval_ms: 1_500,
                    source_timeout_ms: 120_000,
                    max_slew_ppm: profile.max_slew_ppm,
                    ..Default::default()
                }),
            shared_clock(now.clone()),
        );

        let link_now = now.clone();
        let source_to_consumer_tx = source_to_consumer.clone();
        let source_side = source.add_side_packet("scheduled-downlink", move |pkt| {
            source_to_consumer_tx
                .lock()
                .unwrap()
                .enqueue(link_now.load(Ordering::SeqCst), pkt.clone());
            Ok(())
        });

        let link_now = now.clone();
        let consumer_to_source_tx = consumer_to_source.clone();
        let consumer_side = consumer.add_side_packet("scheduled-uplink", move |pkt| {
            consumer_to_source_tx
                .lock()
                .unwrap()
                .enqueue(link_now.load(Ordering::SeqCst), pkt.clone());
            Ok(())
        });

        let warmup_ms = profile.duration_ms / 3;
        let mut best_error_after_warmup = u64::MAX;
        let mut final_error_after_warmup = None;
        let mut readings_after_warmup = 0usize;

        while now.load(Ordering::SeqCst) <= profile.duration_ms {
            source.periodic(0).unwrap();
            consumer.periodic(0).unwrap();
            source.process_all_queues_with_timeout(0).unwrap();
            consumer.process_all_queues_with_timeout(0).unwrap();

            let now_ms = now.load(Ordering::SeqCst);
            for pkt in source_to_consumer.lock().unwrap().drain_due(now_ms) {
                consumer.rx_from_side(&pkt, consumer_side).unwrap();
            }
            for pkt in consumer_to_source.lock().unwrap().drain_due(now_ms) {
                source.rx_from_side(&pkt, source_side).unwrap();
            }

            source.process_all_queues_with_timeout(0).unwrap();
            consumer.process_all_queues_with_timeout(0).unwrap();

            let now_ms = now.load(Ordering::SeqCst);
            if now_ms >= warmup_ms
                && let Some(observed) = consumer.network_time_ms()
            {
                let expected = epoch_ms.saturating_add(now_ms);
                let error = observed.abs_diff(expected);
                best_error_after_warmup = best_error_after_warmup.min(error);
                final_error_after_warmup = Some(error);
                readings_after_warmup += 1;
            }
            now.fetch_add(profile.tick_ms, Ordering::SeqCst);
        }

        for _ in 0..80 {
            let now_ms = now.load(Ordering::SeqCst);
            for pkt in source_to_consumer.lock().unwrap().drain_due(now_ms) {
                consumer.rx_from_side(&pkt, consumer_side).unwrap();
            }
            for pkt in consumer_to_source.lock().unwrap().drain_due(now_ms) {
                source.rx_from_side(&pkt, source_side).unwrap();
            }
            source.process_all_queues_with_timeout(0).unwrap();
            consumer.process_all_queues_with_timeout(0).unwrap();
            now.fetch_add(profile.tick_ms, Ordering::SeqCst);
        }

        assert!(
            readings_after_warmup > 0,
            "{} board did not converge to a usable network time",
            profile.name
        );
        assert!(
            best_error_after_warmup <= profile.max_error_ms,
            "{} board never reached accurate time-sync after warmup: best_error={}, max={}",
            profile.name,
            best_error_after_warmup,
            profile.max_error_ms
        );
        let final_error_after_warmup =
            final_error_after_warmup.expect("readings_after_warmup checked above");
        assert!(
            final_error_after_warmup <= profile.max_error_ms,
            "{} board did not remain accurate at the end of active scheduling: final_error={}, max={}",
            profile.name,
            final_error_after_warmup,
            profile.max_error_ms
        );

        let downlink_frames = source_to_consumer.lock().unwrap().timesync_frames;
        let uplink_frames = consumer_to_source.lock().unwrap().timesync_frames;
        let total_timesync_frames = downlink_frames + uplink_frames;
        assert!(
            total_timesync_frames <= profile.max_timesync_frames,
            "{} emitted too many time-sync frames for a constrained scheduler: downlink={downlink_frames}, uplink={uplink_frames}, total={total_timesync_frames}, max={}",
            profile.name,
            profile.max_timesync_frames
        );
        assert!(
            downlink_frames > 0 && uplink_frames > 0,
            "{} should exercise announce, request, and response traffic",
            profile.name
        );
    }

    #[test]
    fn timesync_converges_without_monopolizing_realistic_link_schedulers() {
        let profiles = [
            ScheduledLinkProfile {
                name: "rfboard26_tdma",
                source_to_consumer_latency_ms: 260,
                consumer_to_source_latency_ms: 420,
                jitter_ms: 60,
                slot_period_ms: Some(512),
                slot_offset_ms: 128,
                frames_per_tick: 1,
                duration_ms: 36_000,
                tick_ms: 64,
                max_error_ms: 1_100,
                max_timesync_frames: 190,
                max_slew_ppm: 0,
            },
            ScheduledLinkProfile {
                name: "high_latency_fifo_radio",
                source_to_consumer_latency_ms: 1_600,
                consumer_to_source_latency_ms: 1_600,
                jitter_ms: 250,
                slot_period_ms: None,
                slot_offset_ms: 0,
                frames_per_tick: 2,
                duration_ms: 48_000,
                tick_ms: 100,
                max_error_ms: 1_900,
                max_timesync_frames: 220,
                max_slew_ppm: 0,
            },
            ScheduledLinkProfile {
                name: "bursty_shared_serial_bus",
                source_to_consumer_latency_ms: 120,
                consumer_to_source_latency_ms: 160,
                jitter_ms: 40,
                slot_period_ms: Some(1_000),
                slot_offset_ms: 0,
                frames_per_tick: 4,
                duration_ms: 30_000,
                tick_ms: 50,
                max_error_ms: 1_500,
                max_timesync_frames: 170,
                max_slew_ppm: 0,
            },
            ScheduledLinkProfile {
                name: "can_fd_priority_tick",
                source_to_consumer_latency_ms: 8,
                consumer_to_source_latency_ms: 8,
                jitter_ms: 4,
                slot_period_ms: Some(10),
                slot_offset_ms: 0,
                frames_per_tick: 8,
                duration_ms: 18_000,
                tick_ms: 10,
                max_error_ms: 80,
                max_timesync_frames: 130,
                max_slew_ppm: 0,
            },
        ];

        for profile in profiles {
            run_scheduled_timesync_profile(profile);
        }
    }

    #[test]
    fn router_merges_partial_network_time_sources() {
        let now = Arc::new(AtomicU64::new(2_000));
        let router = Router::new_with_clock(
            RouterConfig::default().with_timesync(TimeSyncConfig::default()),
            shared_clock(now.clone()),
        );

        router.update_network_time_source(
            "rtc_date",
            50,
            PartialNetworkTime {
                year: Some(2026),
                month: Some(3),
                day: Some(21),
                ..Default::default()
            },
            None,
        );
        router.update_network_time_source(
            "gps_tod",
            1,
            PartialNetworkTime {
                hour: Some(12),
                minute: Some(34),
                second: Some(56),
                ..Default::default()
            },
            None,
        );

        let merged = router.network_time().expect("network time unavailable");
        assert_eq!(merged.time.year, Some(2026));
        assert_eq!(merged.time.month, Some(3));
        assert_eq!(merged.time.day, Some(21));
        assert_eq!(merged.time.hour, Some(12));
        assert_eq!(merged.time.minute, Some(34));
        assert_eq!(merged.time.second, Some(56));
        assert!(
            merged.unix_time_ms.is_some(),
            "merged date/time should produce epoch ms"
        );

        now.store(3_500, Ordering::SeqCst);
        let advanced = router.network_time().expect("network time unavailable");
        assert_eq!(advanced.time.second, Some(57));
        assert_eq!(advanced.time.nanosecond, Some(500_000_000));
    }

    #[test]
    fn local_master_setters_merge_partial_fields_and_anchor_at_commit_time() {
        let router = Router::new_with_clock(
            RouterConfig::default().with_timesync(TimeSyncConfig {
                role: TimeSyncRole::Source,
                priority: 1,
                ..Default::default()
            }),
            Box::new(StepClock {
                now_ns: AtomicU64::new(0),
                step_ns: 25_000_000,
            }),
        );

        router.set_local_network_date(2026, 3, 21);
        router.set_local_network_time_hms_millis(12, 34, 56, 0);

        let reading = router.network_time().expect("network time unavailable");
        assert_eq!(reading.time.year, Some(2026));
        assert_eq!(reading.time.month, Some(3));
        assert_eq!(reading.time.day, Some(21));
        assert_eq!(reading.time.hour, Some(12));
        assert_eq!(reading.time.minute, Some(34));
        assert_eq!(reading.time.second, Some(56));
        assert!(
            reading.time.nanosecond.unwrap_or(0) >= 100_000_000,
            "setter should compensate for elapsed monotonic time during the call"
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compression_mixed_workload_threaded_system_stability() {
        ensure_compression_test_schema();

        let worker_count = 4usize;
        let iters_per_worker = 600usize;

        let mut joins = Vec::new();
        for tid in 0..worker_count {
            joins.push(thread::spawn(move || {
                for i in 0..iters_per_worker {
                    let ts = (tid as u64) * 10_000 + (i as u64);
                    let payload = if i % 2 == 0 {
                        vec![b'Q'; 224]
                    } else {
                        let mut v = Vec::with_capacity(224);
                        for j in 0..224u16 {
                            v.push(32u8 + (((i as u16 + j + tid as u16) as u8) % 95));
                        }
                        v
                    };

                    let pkt = Packet::new(
                        DataType::named("MESSAGE_DATA"),
                        &[DataEndpoint::named("SD_CARD")],
                        "SYS_COMP",
                        ts,
                        Arc::<[u8]>::from(payload.as_slice()),
                    )
                    .expect("packet build failed");

                    let wire = wire_format::pack_packet(&pkt);
                    let decoded = wire_format::unpack_packet(&wire).expect("unpack failed");
                    assert_eq!(decoded.payload(), payload.as_slice());
                }
            }));
        }

        for j in joins {
            j.join().expect("compression worker panicked");
        }
    }
}
