//! Victim selection from cached item classes (`queue::ItemTag`) and kept
//! bulk summaries (`queue::BulkSummary`) must choose exactly what classifying
//! every queued item on the spot chooses. Two identical routers run the same
//! randomized queue operations (admissions into a full budget, receive and
//! transmit pops, metadata updates, schema changes), one with the tagged
//! selection and one with on-the-spot classification, and must keep identical
//! queues and admission results; the tagged router's direct selection queries
//! are also compared with the on-the-spot ones after every step.

use super::{
    QueuedDelivery, RouterInner, RouterItem, RouterRxItem, RouterTxItem, TX_E2E_CHILD, TX_FRESH,
    TxQueued, fair_tag_test_switch,
};
use crate::config::{
    DataEndpoint, DataType, RuntimeMemoryConfig, register_data_type_with_description,
};
use crate::packet::Packet;
use crate::router::{Router, RouterConfig};
use crate::{MessageClass, MessageDataType, MessageElement, ReliableMode};
use alloc::sync::Arc;

const ENDPOINT: &str = "FAIR_DIFF_REMOTE";

fn endpoint() -> DataEndpoint {
    crate::tests::ensure_common_test_schema();
    DataEndpoint::try_named(ENDPOINT).unwrap_or_else(|| {
        crate::config::register_endpoint_with_description(ENDPOINT, "victim endpoint", false)
            .unwrap()
    })
}

fn data_type(name: &str, mode: ReliableMode, priority: u8) -> DataType {
    let ep = endpoint();
    DataType::try_named(name).unwrap_or_else(|| {
        register_data_type_with_description(
            name,
            "victim selection type",
            MessageElement::Dynamic(MessageDataType::UInt8, MessageClass::Data),
            &[ep],
            mode,
            priority,
        )
        .unwrap()
    })
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn router(budget: usize) -> Router {
    Router::new_with_clock(
        RouterConfig::new([])
            .with_sender("FAIR_DIFF")
            .with_memory_config(RuntimeMemoryConfig {
                max_queue_budget: budget,
                ..Default::default()
            })
            .unwrap(),
        Box::new(|| 1_000),
    )
}

enum Op {
    Rx(RouterRxItem),
    Tx(TxQueued),
    PopRx,
    RemoveTx(usize),
    FlagTx(usize),
    Schema,
}

fn random_op(rng: &mut Rng, types: &[(DataType, u8)], senders: u64, step: usize) -> Op {
    let item = |rng: &mut Rng| {
        // Mostly one stream, as a flooding sensor sends.
        let (ty, priority) = if rng.below(4) == 0 {
            types[rng.below(types.len() as u64) as usize]
        } else {
            types[0]
        };
        // One flooding source most of the time; others now and then.
        let sender = if rng.below(8) == 0 {
            ["FAIR_A", "FAIR_B", "FAIR_C"][rng.below(senders) as usize]
        } else {
            "FAIR_A"
        };
        let len = 1 + rng.below(40) as usize;
        let payload: Arc<[u8]> = (0..len).map(|i| (i as u64 ^ rng.next()) as u8).collect();
        let packet = Packet::new(ty, &[endpoint()], sender, 1_000 + step as u64, payload).unwrap();
        let data = if rng.below(4) == 0 {
            RouterItem::Packet(packet)
        } else {
            RouterItem::Packed(crate::shared_bytes::convert(crate::wire_format::pack_packet(&packet)))
        };
        (data, priority)
    };
    match rng.below(20) {
        0..=8 => {
            let (data, priority) = item(rng);
            Op::Rx(RouterRxItem { src: Some(0), data, priority })
        }
        9..=12 => {
            let (data, priority) = item(rng);
            Op::Tx(TxQueued {
                disposable: TX_FRESH,
                item: RouterTxItem::ToSide { src: Some(0), dst: 1, data },
                ignore_local: true,
                priority,
                delivery_state: QueuedDelivery::Untracked,
                accepted_type: 0,
                deferred_since_ms: 0,
                retry_after_ms: 0,
            })
        }
        13..=15 => Op::PopRx,
        16..=17 => Op::RemoveTx(rng.below(8) as usize),
        18 => Op::FlagTx(rng.below(8) as usize),
        _ => Op::Schema,
    }
}

fn apply(st: &mut RouterInner, op: &Op) -> String {
    match op {
        Op::Rx(item) => format!("{:?}", st.push_received(item.clone())),
        Op::Tx(item) => format!("{:?}", st.push_transmit(item.clone())),
        Op::PopRx => format!("{:?}", st.pop_received_fair().map(|item| item.priority)),
        Op::RemoveTx(index) => format!("{:?}", st.transmit_queue.remove_pos(*index).map(|item| item.priority)),
        Op::FlagTx(index) => {
            st.transmit_queue.update_metadata(*index, |item| item.disposable ^= TX_E2E_CHILD);
            String::new()
        }
        Op::Schema => String::new(),
    }
}

fn queues(st: &RouterInner) -> (Vec<RouterRxItem>, Vec<TxQueued>) {
    (st.received_queue.iter().cloned().collect(), st.transmit_queue.iter().cloned().collect())
}

#[test]
fn tagged_victim_selection_matches_on_the_spot_classification() {
    let types = [
        (data_type("FAIR_DIFF_BULK", ReliableMode::None, 20), 20),
        (data_type("FAIR_DIFF_BULK_HIGH", ReliableMode::None, 60), 60),
        (data_type("FAIR_DIFF_OTHER", ReliableMode::None, 20), 20),
        (data_type("FAIR_DIFF_RELIABLE", ReliableMode::Unordered, 20), 20),
    ];
    let mut compared = 0usize;
    for seed in 1..=6u64 {
        // A small budget (protected state takes part of it) keeps the queues
        // full, so most admissions select a victim.
        let tagged = router(12 * 1024);
        let general = router(12 * 1024);
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
        for step in 0..1500 {
            // Every third seed: one source and one bulk stream (plus
            // reliable traffic), the case the kept summaries serve.
            let flood = [types[0], types[3]];
            let op = if seed % 3 == 0 {
                random_op(&mut rng, &flood, 1, step)
            } else {
                random_op(&mut rng, &types, seed % 3 + 1, step)
            };
            if matches!(op, Op::Schema) {
                // Advances the schema generation: every tag is reclassified.
                let _ = data_type(&format!("FAIR_DIFF_LATE_{seed}_{step}"), ReliableMode::None, 10);
            }
            let tagged_result = apply(&mut tagged.state.lock(), &op);
            fair_tag_test_switch::set_disabled(true);
            let general_result = apply(&mut general.state.lock(), &op);
            fair_tag_test_switch::set_disabled(false);
            assert_eq!(tagged_result, general_result, "seed {seed} step {step}: admission differs");
            assert!(
                queues(&tagged.state.lock()) == queues(&general.state.lock()),
                "seed {seed} step {step}: queues differ"
            );

            // Direct queries on the tagged router against classification on
            // the spot over the very same queues.
            let mut st = tagged.state.lock();
            // Mostly the admission threshold of the dominant traffic, so the
            // kept summaries carry over from step to step.
            let threshold = if rng.below(10) == 0 {
                [10u8, 60, 199][rng.below(3) as usize]
            } else {
                20
            };
            for priority in [threshold] {
                let incoming = [None, Some(crate::wire_format::source_address_for_sender("FAIR_A"))]
                    [rng.below(2) as usize];
                let tagged_loads = st.bulk_loads(priority);
                let general_loads = st.bulk_loads_untagged(priority);
                assert!(tagged_loads == general_loads, "seed {seed} step {step}: loads differ");
                assert_eq!(
                    tagged_loads.queue_victim(incoming),
                    general_loads.queue_victim(incoming)
                );
                let (scan_loads, summaries) = st.bulk_loads_scan(priority);
                assert!(scan_loads == general_loads, "seed {seed} step {step}: scan loads differ");
                if let Some(owner) = general_loads.queue_victim(incoming) {
                    for stream in [None, Some(types[0].0.as_u32()), Some(types[2].0.as_u32())] {
                        let expected = st.bulk_victim_untagged(owner, priority, stream);
                        let fresh = st.bulk_victim(owner, priority, stream);
                        assert_eq!(fresh, expected, "seed {seed} step {step}: victim differs");
                        if let Some(summaries) = summaries.as_ref() {
                            let scan = super::summary_victim_scan(owner, summaries);
                            if let Some(stream) = RouterInner::single_owner_stream(&scan, stream)
                                && let Some([rx, tx]) = scan.positions(stream)
                            {
                                assert_eq!(
                                    RouterInner::pick_bulk_victim(rx, tx),
                                    expected,
                                    "seed {seed} step {step}: summary victim differs"
                                );
                                compared += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(compared > 100, "summaries were rarely usable ({compared})");
}
