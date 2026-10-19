//! Compact directional type counters. Transit normally uses only one direction per side;
//! allocate the remaining counters only when both directions, retries, or failures occur.
//! Counter widths and saturation match the public runtime statistics API.
use alloc::boxed::Box;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) tx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) relayed_tx_packets: u64,
    pub(crate) relayed_tx_bytes: u64,
    pub(crate) relayed_rx_packets: u64,
    pub(crate) relayed_rx_bytes: u64,
    pub(crate) tx_retries: u64,
    pub(crate) handler_failures: u64,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Direction {
    #[default]
    Empty,
    Tx,
    Rx,
}
#[derive(Debug, Clone, Default)]
pub(crate) struct TypeRuntimeStatsInner {
    values: [u64; 4],
    extra: Option<Box<[u64; 6]>>,
    direction: Direction,
}
impl TypeRuntimeStatsInner {
    pub(crate) fn heap_bytes(&self) -> usize {
        if self.extra.is_some() {
            core::mem::size_of::<[u64; 6]>()
        } else {
            0
        }
    }
    // The first observed direction remains inline. The first four overflow
    // words hold the opposite direction; the last two hold retries/failures.
    fn extra(&mut self) -> &mut [u64; 6] {
        self.extra.get_or_insert_with(|| Box::new([0; 6]))
    }
    pub(crate) fn counters(&self) -> Counters {
        let zero = [0; 6];
        let extra = self.extra.as_deref().unwrap_or(&zero);
        let (tx, rx): (&[u64], &[u64]) = if self.direction == Direction::Tx {
            (&self.values, extra)
        } else {
            (extra, &self.values)
        };
        Counters {
            tx_packets: tx[0],
            tx_bytes: tx[1],
            rx_packets: rx[0],
            rx_bytes: rx[1],
            relayed_tx_packets: tx[2],
            relayed_tx_bytes: tx[3],
            relayed_rx_packets: rx[2],
            relayed_rx_bytes: rx[3],
            tx_retries: extra[4],
            handler_failures: extra[5],
        }
    }
    fn note(values: &mut [u64], bytes: u64, relayed: bool) {
        values[0] = values[0].saturating_add(1);
        values[1] = values[1].saturating_add(bytes);
        if relayed {
            values[2] = values[2].saturating_add(1);
            values[3] = values[3].saturating_add(bytes);
        }
    }
    pub(crate) fn tx(&mut self, bytes: u64, relayed: bool, retries: u64) {
        if self.direction == Direction::Empty {
            self.direction = Direction::Tx;
        }
        if self.direction == Direction::Tx {
            Self::note(&mut self.values, bytes, relayed);
        } else {
            Self::note(self.extra(), bytes, relayed);
        }
        if retries != 0 {
            let extra = self.extra();
            extra[4] = extra[4].saturating_add(retries);
        }
    }
    pub(crate) fn rx(&mut self, bytes: u64, relayed: bool) {
        if self.direction == Direction::Empty {
            self.direction = Direction::Rx;
        }
        if self.direction == Direction::Rx {
            Self::note(&mut self.values, bytes, relayed);
        } else {
            Self::note(self.extra(), bytes, relayed);
        }
    }
    pub(crate) fn failure(&mut self, retries: u64) {
        let extra = self.extra();
        extra[5] = extra[5].saturating_add(1);
        extra[4] = extra[4].saturating_add(retries);
    }
}
#[cfg(test)]
#[test]
fn directional_size_and_full_width() {
    assert!(core::mem::size_of::<TypeRuntimeStatsInner>() <= 48);
    let mut a = TypeRuntimeStatsInner::default();
    a.tx(u64::MAX, false, 0);
    a.tx(1, true, 0);
    assert!(a.direction == Direction::Tx);
    assert_eq!(a.counters().tx_bytes, u64::MAX);
    a.rx(7, true);
    assert_eq!(a.counters().tx_bytes, u64::MAX);
    assert_eq!(a.counters().rx_bytes, 7);
    assert!(a.extra.is_some());
}
#[cfg(test)]
#[test]
fn matches_full_model_for_mixed_retries_failures_and_saturation() {
    let mut a = TypeRuntimeStatsInner::default();
    let mut b = Counters::default();
    let mut seed = 53u64;
    for i in 0..10000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let bytes = if i % 97 == 0 { u64::MAX } else { seed % 4097 };
        let relayed = seed & 8 != 0;
        let retries = seed % 5;
        match seed % 5 {
            0 | 1 => {
                a.tx(bytes, relayed, retries);
                b.tx_packets = b.tx_packets.saturating_add(1);
                b.tx_bytes = b.tx_bytes.saturating_add(bytes);
                b.tx_retries = b.tx_retries.saturating_add(retries);
                if relayed {
                    b.relayed_tx_packets = b.relayed_tx_packets.saturating_add(1);
                    b.relayed_tx_bytes = b.relayed_tx_bytes.saturating_add(bytes);
                }
            }
            2 | 3 => {
                a.rx(bytes, relayed);
                b.rx_packets = b.rx_packets.saturating_add(1);
                b.rx_bytes = b.rx_bytes.saturating_add(bytes);
                if relayed {
                    b.relayed_rx_packets = b.relayed_rx_packets.saturating_add(1);
                    b.relayed_rx_bytes = b.relayed_rx_bytes.saturating_add(bytes);
                }
            }
            _ => {
                a.failure(retries);
                b.handler_failures = b.handler_failures.saturating_add(1);
                b.tx_retries = b.tx_retries.saturating_add(retries);
            }
        }
        assert_eq!(a.counters(), b);
    }
}

#[cfg(test)]
#[test]
fn directional_updates_do_not_allocate_and_promotion_is_reused() {
    for transmit in [true, false] {
        let mut stats = TypeRuntimeStatsInner::default();
        for _ in 0..1000 {
            if transmit {
                stats.tx(42, true, 0);
            } else {
                stats.rx(42, true);
            }
        }
        assert_eq!(stats.heap_bytes(), 0);
        assert!(stats.extra.is_none());
        stats.failure(3);
        let address = stats.extra.as_deref().unwrap().as_ptr();
        assert_eq!(stats.heap_bytes(), 48);
        for _ in 0..1000 {
            stats.tx(1, false, 2);
            stats.rx(1, false);
            stats.failure(1);
        }
        assert_eq!(stats.extra.as_deref().unwrap().as_ptr(), address);
        assert_eq!(stats.counters().handler_failures, 1001);
    }
}

#[cfg(test)]
#[test]
fn failure_before_first_packet_preserves_direction_and_totals() {
    for transmit in [true, false] {
        let mut stats = TypeRuntimeStatsInner::default();
        stats.failure(7);
        assert_eq!(stats.counters().handler_failures, 1);
        if transmit {
            stats.tx(42, true, 0);
            stats.rx(13, false);
        } else {
            stats.rx(13, false);
            stats.tx(42, true, 0);
        }
        assert_eq!(
            stats.counters(),
            Counters {
                tx_packets: 1,
                tx_bytes: 42,
                rx_packets: 1,
                rx_bytes: 13,
                relayed_tx_packets: 1,
                relayed_tx_bytes: 42,
                tx_retries: 7,
                handler_failures: 1,
                ..Counters::default()
            }
        );
    }
}
