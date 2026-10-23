use crate::{TelemetryError, TelemetryResult};
use alloc::collections::VecDeque;

/// Items stored in the queue must report (approximately) how much memory they
/// account for.
pub trait ByteCost {
    /// Approximate heap+payload memory attributable to this queued item.
    fn byte_cost(&self) -> usize;
    #[cfg(feature = "compact-packet-store")]
    fn park_for_queue(&mut self) -> TelemetryResult<()> {
        Ok(())
    }
}

/// Convert float multiplier to ratio (num, den).
#[inline]
fn float_to_ratio(mult: f64) -> (usize, usize) {
    const DEN: usize = 1024;
    // Multiplication by 1024 changes only the binary exponent. Decode the
    // bounded positive range directly instead of linking software f64 math
    // on Cortex-M. Preserve the former clamp/truncation and NaN behavior.
    if mult.is_nan() {
        return (DEN + 1, DEN);
    }
    let bits = mult.to_bits();
    let num = if bits >> 63 != 0 || bits < 1.01f64.to_bits() {
        1034
    } else if bits >= 16.0f64.to_bits() {
        16 * DEN
    } else {
        let exponent = ((bits >> 52) & 0x7ff) as u32 - 1023;
        let significand = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
        (significand >> (42 - exponent)) as usize
    };
    (num, DEN)
}

/// A double-ended queue with a maximum byte budget.
///
/// Policy:
/// - Byte budget is enforced by evicting from the front until the new item fits.
/// - `max_elems` is a hard cap. Fixed queues keep their initial allocation;
///   dynamic queues grow fallibly and reuse a slot if growth is refused.
/// - When the ring is full, we evict one item from the front before pushing.
/// - `cur_bytes` is kept consistent for *all* removal paths.
#[derive(Debug)]
#[cfg_attr(not(feature = "compact-packet-store"), derive(Clone))]
pub struct BoundedDeque<T> {
    q: VecDeque<T>,
    max_bytes: usize,
    cur_bytes: usize,
    max_elems: usize,
    grow_num: usize,
    grow_den: usize,
    fixed_capacity: bool,
    // Rotate bounded service opportunities through waiting lower bands.
    fair_priority_cursor: u8,
}

#[cfg(feature = "compact-packet-store")]
impl<T: Clone> Clone for BoundedDeque<T> {
    fn clone(&self) -> Self {
        let mut q = VecDeque::with_capacity(self.q.capacity());
        q.extend(self.q.iter().cloned());
        Self {
            q,
            max_bytes: self.max_bytes,
            cur_bytes: self.cur_bytes,
            max_elems: self.max_elems,
            grow_num: self.grow_num,
            grow_den: self.grow_den,
            fixed_capacity: self.fixed_capacity,
            fair_priority_cursor: self.fair_priority_cursor,
        }
    }
}

// Admit queue storage before allocation. Fragmented board startup may fit a
// smaller fixed ring even when the requested full compact ring cannot fit.
#[inline(never)]
fn admitted_initial_capacity(mut capacity: usize, item_bytes: usize) -> usize {
    while capacity != 0 {
        // The constructor bounds capacity by max_bytes / item_bytes;
        // retry only halves it, so multiplication cannot overflow.
        let bytes = (capacity * item_bytes).saturating_add(64);
        if crate::memory_admission::check(bytes, bytes).is_ok() {
            return capacity;
        }
        capacity /= 2;
    }
    0
}

fn allocate_initial_ring<T>(mut capacity: usize, item_bytes: usize) -> VecDeque<T> {
    let mut ring = VecDeque::new();
    loop {
        capacity = admitted_initial_capacity(capacity, item_bytes);
        if capacity == 0 || ring.try_reserve_exact(capacity).is_ok() {
            break;
        }
        capacity /= 2;
    }
    ring
}

impl<T: ByteCost> BoundedDeque<T> {
    fn prepare_push_fifo(&mut self, cost: usize) -> TelemetryResult<()> {
        if self.q.capacity() == 0 {
            return Err(TelemetryError::Io("queue unavailable"));
        }
        if cost > self.max_bytes {
            return Err(TelemetryError::PacketTooLarge(
                "Item exceeds maximum byte budget",
            ));
        }

        while !self.q.is_empty() && self.cur_bytes + cost > self.max_bytes {
            let _ = self.pop_front();
        }

        if self.q.len() >= self.max_elems {
            let _ = self.pop_front();
        }

        if !self.ensure_room_for_one() {
            // Reuse existing storage when allocator headroom refuses growth.
            let _ = self.pop_front();
        }
        Ok(())
    }

    /// Create new bounded deque with byte budget and element cap.
    ///
    /// `starting_elems` controls the initial allocation but will be clamped
    /// to `max_elems`.
    ///
    /// Notes:
    /// - `max_elems` is derived conservatively from `size_of::<T>()` because
    ///   `ByteCost` is dynamic. This prevents runaway element counts even if
    ///   `byte_cost()` is small.
    pub fn new(max_bytes: usize, starting_bytes: usize, grow_mult: f64) -> Self {
        if starting_bytes > max_bytes {
            panic!(
                "starting_bytes ({}) must be less than max_bytes ({}) to avoid conflicts",
                starting_bytes, max_bytes
            );
        }
        if max_bytes == 0 {
            panic!("max_bytes must be greater than 0");
        }
        if grow_mult < 1.0 {
            panic!("grow_mult must be at least 1.0");
        }
        let min_cost = size_of::<T>().max(1);
        let max_elems = (max_bytes / min_cost).max(1);
        let starting_elems = starting_bytes / min_cost;
        let start_cap = if cfg!(feature = "compact-packet-store") && grow_mult > 1.0 {
            max_elems
        } else {
            starting_elems.clamp(1, max_elems)
        };

        let (grow_num, grow_den) = float_to_ratio(grow_mult);

        Self {
            q: allocate_initial_ring(start_cap, min_cost),
            max_bytes,
            cur_bytes: 0,
            max_elems,
            grow_num,
            grow_den,
            fixed_capacity: grow_mult == 1.0 || cfg!(feature = "compact-packet-store"),
            fair_priority_cursor: u8::MAX,
        }
    }

    /// Current length.
    #[inline]
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Check if empty.
    #[allow(dead_code)]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// Get iterator over items.
    #[allow(dead_code)]
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.q.iter()
    }

    /// Check if item is contained in the queue.
    #[inline]
    pub fn contains(&self, v: &T) -> bool
    where
        T: PartialEq,
    {
        self.q.contains(v)
    }

    /// Clear all items.
    #[inline]
    pub fn clear(&mut self) {
        self.q.clear();
        self.cur_bytes = 0;
        self.fair_priority_cursor = u8::MAX;
    }

    /// Current used bytes (according to `ByteCost`).
    #[allow(dead_code)]
    #[inline]
    pub fn bytes_used(&self) -> usize {
        self.cur_bytes
    }

    /// Maximum allowed bytes.
    #[allow(dead_code)]
    #[inline]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Maximum allowed elements (hard cap).
    #[allow(dead_code)]
    #[inline]
    pub fn max_elems(&self) -> usize {
        self.max_elems
    }

    /// Underlying `VecDeque` capacity, bounded by `max_elems`.
    #[allow(dead_code)]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.q.capacity()
    }

    /// Pop from front, updating byte count.
    pub fn pop_front(&mut self) -> Option<T> {
        let v = self.q.pop_front()?;
        self.cur_bytes = self.cur_bytes.saturating_sub(v.byte_cost());
        Some(v)
    }

    /// Pop in priority order while guaranteeing bounded service for an item
    /// already waiting at the lowest queued priority.
    #[cfg(test)]
    pub fn pop_front_fair<F>(
        &mut self,
        priority_burst: &mut u8,
        max_priority_burst: u8,
        priority_of: F,
    ) -> Option<T>
    where
        F: FnMut(&T) -> u8,
    {
        self.pop_front_fair_if(priority_burst, max_priority_burst, priority_of, |_| true)
    }

    /// Bounded fairness for a ready RX queue sorted by descending priority.
    /// Protected control never yields. The usual path checks only its ends;
    /// scan for the first low-priority item only once per bounded bulk burst.
    pub(crate) fn pop_front_bulk_fair<F>(
        &mut self,
        priority_burst: &mut u8,
        max_priority_burst: u8,
        priority_of: F,
    ) -> Option<T>
    where
        F: Fn(&T) -> u8,
    {
        let Some(front) = self.q.front().map(&priority_of) else {
            *priority_burst = 0;
            return None;
        };
        let lowest = self.q.back().map(&priority_of).unwrap_or(front);
        if front >= 200 || front == lowest {
            *priority_burst = 0;
            return self.pop_front();
        }
        if *priority_burst < max_priority_burst {
            *priority_burst += 1;
            return self.pop_front();
        }
        *priority_burst = 0;
        // Explicit indexing avoids a second generic iterator traversal on
        // small MCUs. The first match retains FIFO within the lowest priority.
        let mut index = 0;
        while self
            .q
            .get(index)
            .is_some_and(|item| priority_of(item) != lowest)
        {
            index += 1;
        }
        self.remove_pos(index)
    }

    /// Preserve priority fairness while leaving deferred work in owned storage.
    pub(crate) fn pop_front_fair_if<F, G>(
        &mut self,
        priority_burst: &mut u8,
        max_priority_burst: u8,
        mut priority_of: F,
        mut eligible: G,
    ) -> Option<T>
    where
        F: FnMut(&T) -> u8,
        G: FnMut(&T) -> bool,
    {
        let selected = {
            let mut ready = self.q.iter().enumerate().filter(|(_, item)| eligible(item));
            let (front, first) = ready.next()?;
            let front_priority = priority_of(first);
            let mut lower = front;
            let mut lower_priority = front_priority;
            let mut best_distance = u8::MAX;
            for (index, item) in ready {
                let priority = priority_of(item);
                if priority >= front_priority {
                    continue;
                }
                // Descend from the previous service band, then wrap. Equal
                // distances retain the first eligible item (FIFO in a band).
                let distance = self
                    .fair_priority_cursor
                    .wrapping_sub(priority)
                    .wrapping_sub(1);
                if lower == front || distance < best_distance {
                    lower = index;
                    lower_priority = priority;
                    best_distance = distance;
                }
            }
            if lower != front && *priority_burst >= max_priority_burst {
                *priority_burst = 0;
                self.fair_priority_cursor = lower_priority;
                lower
            } else {
                if lower != front {
                    *priority_burst = priority_burst.saturating_add(1);
                } else {
                    *priority_burst = 0;
                }
                front
            }
        };
        self.remove_pos(selected)
    }

    /// Pop from back, updating byte count.
    #[allow(dead_code)]
    pub fn pop_back(&mut self) -> Option<T> {
        let v = self.q.pop_back()?;
        self.cur_bytes = self.cur_bytes.saturating_sub(v.byte_cost());
        Some(v)
    }

    /// Remove the lowest-priority item from a deque populated with
    /// [`Self::push_back_prioritized`].
    pub(crate) fn pop_lowest_priority(&mut self) -> Option<T> {
        self.pop_back()
    }

    /// Return the priority of the lowest-priority queued item.
    ///
    /// Queues populated by [`Self::push_back_prioritized`] keep that item at
    /// the back, so shared-budget arbitration can compare queues without
    /// scanning or removing anything first.
    pub(crate) fn lowest_priority<F>(&self, mut priority_of: F) -> Option<u8>
    where
        F: FnMut(&T) -> u8,
    {
        self.q.back().map(&mut priority_of)
    }

    /// Remove item at position, updating byte count.
    pub fn remove_pos(&mut self, idx: usize) -> Option<T> {
        let v = self.q.remove(idx)?;
        self.cur_bytes = self.cur_bytes.saturating_sub(v.byte_cost());
        Some(v)
    }

    /// Remove first occurrence of value, updating byte count.
    pub fn remove_value(&mut self, needle: &T)
    where
        T: PartialEq,
    {
        if let Some(idx) = self.q.iter().position(|x| x == needle) {
            let _ = self.remove_pos(idx);
        }
    }

    /// Retain only the elements specified by the predicate, updating byte count.
    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.retain_observed(keep, core::mem::drop)
    }

    pub(crate) fn retain_observed<F, E>(&mut self, mut keep: F, mut evicted: E)
    where
        F: FnMut(&T) -> bool,
        E: FnMut(T),
    {
        let mut idx = 0;
        while idx < self.q.len() {
            let keep_item = self.q.get(idx).is_some_and(&mut keep);
            if keep_item {
                idx += 1;
            } else {
                if let Some(old) = self.remove_pos(idx) {
                    evicted(old);
                }
            }
        }
    }

    /// Ensure there is room for one more element *without* `push_back` triggering growth.
    ///
    /// Multiplicative growth: new_cap = ceil(cap * grow_num / grow_den), capped at max_elems.
    /// Always guarantees progress by forcing target_cap >= cap + 1 when growing.
    fn ensure_room_for_one(&mut self) -> bool {
        let len = self.q.len();
        let cap = self.q.capacity();

        if len < cap {
            return true;
        }

        // A multiplier of exactly 1.0 deliberately disables live queue
        // reallocations. The bounded queue retains its startup capacity and
        // applies the existing priority/FIFO eviction policy when full.
        if self.fixed_capacity {
            let _ = self.pop_front();
            return true;
        }

        // Hard length cap: ring eviction.
        if len >= self.max_elems {
            let _ = self.pop_front();
            return true;
        }

        // If we've reached the cap (or allocator rounded capacity above it), don't grow.
        if cap >= self.max_elems {
            let _ = self.pop_front();
            return true;
        }

        // ---- multiplicative growth ----
        // Example: 2x => grow_num=2, grow_den=1
        // Example: 1.5x => grow_num=3, grow_den=2
        let grow_num: usize = self.grow_num; // must be >= 1
        let grow_den: usize = self.grow_den; // must be >= 1

        // ceil(cap * grow_num / grow_den) without floats:
        // (cap*grow_num + grow_den - 1) / grow_den
        let scaled = cap.saturating_mul(grow_num).saturating_add(grow_den - 1);
        let mut target_cap = scaled / grow_den;

        // Ensure we actually grow (avoid target_cap == cap).
        target_cap = target_cap.max(cap + 1);

        // Cap growth at max_elems.
        target_cap = target_cap.min(self.max_elems);

        // Reserve exactly the delta from current capacity to requested capacity.
        let add = target_cap.saturating_sub(cap);
        if add > 0 {
            // Reallocation temporarily holds both old and new buffers. Probe
            // the complete new allocation before touching the allocator, then
            // use fallible reservation so fragmentation cannot trigger OOM.
            let bytes = target_cap.saturating_mul(size_of::<T>()).saturating_add(32);
            if crate::memory_admission::check(bytes, bytes).is_err()
                || self.q.try_reserve_exact(add).is_err()
            {
                return false;
            }
        } else {
            // Shouldn't happen due to max(cap+1), but keep it safe.
            let _ = self.pop_front();
        }

        debug_assert!(self.q.len() < self.q.capacity());
        true
    }

    /// Push to back, evicting from front as needed to stay within byte budget.
    ///
    /// Guarantees:
    /// - Never grows allocation beyond `max_elems`; refused growth reuses a slot.
    /// - Maintains `cur_bytes` consistency.
    #[allow(unused_mut)]
    pub fn push_back(&mut self, mut v: T) -> TelemetryResult<()> {
        #[cfg(feature = "compact-packet-store")]
        v.park_for_queue()?;
        let cost = v.byte_cost();
        self.prepare_push_fifo(cost)?;

        // The growth/eviction pass has already made a slot available.
        self.q.push_back(v);
        self.cur_bytes = self.cur_bytes.saturating_add(cost);
        Ok(())
    }

    /// Push while preserving descending priority order.
    ///
    /// `priority_of` must return a larger value for higher-priority items.
    /// Items with equal priority preserve FIFO order.
    pub fn push_back_prioritized<F>(&mut self, v: T, priority_of: F) -> TelemetryResult<()>
    where
        F: FnMut(&T) -> u8,
    {
        self.push_back_prioritized_observed(v, priority_of, core::mem::drop)
    }

    /// Observe removed entries so queue owners can release replay reservations.
    /// Refusing the incoming entry never reports it as an earlier eviction.
    pub(crate) fn push_back_prioritized_observed<F, E>(
        &mut self,
        v: T,
        mut priority_of: F,
        mut evicted: E,
    ) -> TelemetryResult<()>
    where
        F: FnMut(&T) -> u8,
        E: FnMut(T),
    {
        #[cfg(feature = "compact-packet-store")]
        let mut v = v;
        #[cfg(feature = "compact-packet-store")]
        v.park_for_queue()?;
        if self.q.capacity() == 0 {
            return Err(TelemetryError::Io("queue unavailable"));
        }
        let cost = v.byte_cost();
        if cost > self.max_bytes {
            return Err(TelemetryError::PacketTooLarge(
                "Item exceeds maximum byte budget",
            ));
        }

        let new_priority = priority_of(&v);
        // All admission limits share one eviction point. Besides avoiding
        // repeated priority checks, this guarantees every removed entry has
        // its reservation released exactly once.
        loop {
            let limit = self.cur_bytes.saturating_add(cost) > self.max_bytes
                || self.q.len() >= self.max_elems
                || (self.fixed_capacity && self.q.len() >= self.q.capacity());
            if !limit && self.ensure_room_for_one() {
                break;
            }
            let tail_priority = self.q.back().map(&mut priority_of).unwrap_or(0);
            if tail_priority > new_priority
                || (new_priority == 254 && tail_priority == new_priority)
            {
                return Err(TelemetryError::Io("priority queue saturated"));
            }
            let old = self
                .pop_back()
                .ok_or(TelemetryError::Io("queue unavailable"))?;
            evicted(old);
        }

        self.insert_prioritized_prepared(v, cost, new_priority, priority_of);
        Ok(())
    }

    // Call only after parking and all capacity/byte/element limits succeeded.
    // A selected victim must not be followed by a second admission pass that
    // can park again or choose a different entry to evict.
    fn insert_prioritized_prepared<F>(
        &mut self,
        v: T,
        cost: usize,
        new_priority: u8,
        mut priority_of: F,
    ) where
        F: FnMut(&T) -> u8,
    {
        // Priority insertion maintains descending order. Most sensor traffic
        // appends to its existing priority band; do not scan the whole backlog
        // just to discover that its insertion point is the tail.
        if self
            .q
            .back()
            .is_none_or(|tail| priority_of(tail) >= new_priority)
        {
            self.q.push_back(v);
        } else if self
            .q
            .front()
            .is_some_and(|head| priority_of(head) < new_priority)
        {
            self.q.push_front(v);
        } else {
            // Keep equal-priority FIFO order while locating a band boundary
            // in logarithmic work, including a wrapped backing ring.
            let index = self
                .q
                .partition_point(|existing| priority_of(existing) >= new_priority);
            self.q.insert(index, v);
        }
        self.cur_bytes = self.cur_bytes.saturating_add(cost);
    }
    /// Apply a bounded cold-path selector before normal priority insertion.
    /// Preparing all limits first prevents the insertion fallback from evicting
    /// a different peer. Builds without fairness keep the original insertion.
    pub(crate) fn push_back_prioritized_select<F, V, E>(
        &mut self,
        v: T,
        mut priority_of: F,
        mut victim: V,
        mut evicted: E,
    ) -> TelemetryResult<()>
    where
        F: FnMut(&T) -> u8,
        V: FnMut(&Self, &T) -> Option<usize>,
        E: FnMut(T),
    {
        #[cfg(feature = "compact-packet-store")]
        let mut v = v;
        #[cfg(feature = "compact-packet-store")]
        v.park_for_queue()?;
        if self.q.capacity() == 0 {
            return Err(TelemetryError::Io("queue unavailable"));
        }
        let cost = v.byte_cost();
        if cost > self.max_bytes {
            return Err(TelemetryError::PacketTooLarge(
                "Item exceeds maximum byte budget",
            ));
        }
        let new_priority = priority_of(&v);
        loop {
            let limit = self.cur_bytes.saturating_add(cost) > self.max_bytes
                || self.q.len() >= self.max_elems
                || (self.fixed_capacity && self.q.len() >= self.q.capacity());
            if !limit && self.ensure_room_for_one() {
                break;
            }
            let index = victim(self, &v).ok_or(TelemetryError::Io("priority queue saturated"))?;
            let old_priority = self
                .q
                .get(index)
                .map(&mut priority_of)
                .ok_or(TelemetryError::Io("priority queue saturated"))?;
            if old_priority > new_priority || (new_priority == 254 && old_priority == new_priority)
            {
                return Err(TelemetryError::Io("priority queue saturated"));
            }
            if let Some(old) = self.remove_pos(index) {
                evicted(old);
            }
        }
        self.insert_prioritized_prepared(v, cost, new_priority, priority_of);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Item {
        id: u8,
        cost: usize,
        priority: u8,
    }

    impl ByteCost for Item {
        fn byte_cost(&self) -> usize {
            self.cost
        }
    }

    #[cfg(feature = "compact-packet-store")]
    #[test]
    fn selected_admission_parks_a_compact_payload_only_once() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicUsize, Ordering};
        struct Counted(Arc<AtomicUsize>);
        impl ByteCost for Counted {
            fn byte_cost(&self) -> usize {
                8
            }
            fn park_for_queue(&mut self) -> TelemetryResult<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let mut queue = BoundedDeque::new(128, 16, 1.25);
        queue
            .push_back_prioritized_select(
                Counted(count.clone()),
                |_| 1,
                |_, _| None,
                core::mem::drop,
            )
            .unwrap();
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "prepared insertion must not park or admit an accepted payload a second time"
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.bytes_used(), 8);
    }

    #[test]
    fn equal_priority_append_classifies_constant_work_under_backlog() {
        let mut queue = BoundedDeque::new(16384, 16384, 1.25);
        for id in 0..=255 {
            queue
                .push_back(Item {
                    id,
                    cost: 1,
                    priority: 16,
                })
                .unwrap();
        }
        let mut classifications = 0;
        queue
            .push_back_prioritized(
                Item {
                    id: 0,
                    cost: 1,
                    priority: 16,
                },
                |item| {
                    classifications += 1;
                    item.priority
                },
            )
            .unwrap();
        assert!(
            classifications <= 3,
            "equal-priority append scanned a 256-entry backlog: {classifications} classifications"
        );
        assert_eq!(queue.len(), 257);
        for id in 0..=255 {
            assert_eq!(queue.pop_front().unwrap().id, id);
        }
        assert_eq!(queue.pop_front().unwrap().id, 0);
    }

    #[test]
    fn middle_priority_insertion_avoids_a_linear_backlog_scan() {
        let mut queue = BoundedDeque::new(16384, 16384, 1.25);
        for id in 0..=255 {
            queue
                .push_back(Item {
                    id,
                    cost: 1,
                    priority: 16,
                })
                .unwrap();
        }
        queue
            .push_back(Item {
                id: 0,
                cost: 1,
                priority: 0,
            })
            .unwrap();
        let mut classifications = 0;
        queue
            .push_back_prioritized(
                Item {
                    id: 99,
                    cost: 2,
                    priority: 16,
                },
                |item| {
                    classifications += 1;
                    item.priority
                },
            )
            .unwrap();
        assert!(
            classifications <= 16,
            "one low-priority peer restored a linear scan: {classifications} classifications"
        );
        for id in 0..=255 {
            let item = queue.pop_front().unwrap();
            assert_eq!((item.id, item.cost, item.priority), (id, 1, 16));
        }
        let new_item = queue.pop_front().unwrap();
        assert_eq!((new_item.id, new_item.cost, new_item.priority), (99, 2, 16));
        assert_eq!(queue.pop_front().unwrap().priority, 0);
    }

    #[test]
    fn priority_band_boundaries_preserve_fifo_after_ring_wrap() {
        let mut queue = BoundedDeque::new(4096, 32 * core::mem::size_of::<Item>(), 1.0);
        let mut expected = alloc::vec::Vec::new();
        let mut wrapped = false;
        for step in 0..1024usize {
            if queue.len() >= 24 {
                assert_eq!(queue.pop_front().unwrap(), expected.remove(0));
            } else {
                let item = Item {
                    id: step as u8,
                    cost: 1,
                    priority: (step * 37 % 7) as u8,
                };
                queue
                    .push_back_prioritized(item.clone(), |v| v.priority)
                    .unwrap();
                expected.push(item);
                expected.sort_by_key(|v| core::cmp::Reverse(v.priority));
            }
            wrapped |= !queue.q.as_slices().1.is_empty();
            assert_eq!(
                queue.iter().cloned().collect::<alloc::vec::Vec<_>>(),
                expected
            );
        }
        assert!(
            wrapped,
            "the regression must exercise the split backing ring"
        );
    }

    #[test]
    fn prioritized_queue_preserves_fifo_within_same_priority() {
        let mut q = BoundedDeque::new(64, 16, 2.0);
        q.push_back_prioritized(
            Item {
                id: 1,
                cost: 1,
                priority: 10,
            },
            |item| item.priority,
        )
        .unwrap();
        q.push_back_prioritized(
            Item {
                id: 2,
                cost: 1,
                priority: 10,
            },
            |item| item.priority,
        )
        .unwrap();
        q.push_back_prioritized(
            Item {
                id: 3,
                cost: 1,
                priority: 20,
            },
            |item| item.priority,
        )
        .unwrap();

        assert_eq!(q.pop_front().unwrap().id, 3);
        assert_eq!(q.pop_front().unwrap().id, 1);
        assert_eq!(q.pop_front().unwrap().id, 2);
    }

    #[test]
    fn prioritized_queue_evicts_the_lowest_priority_item() {
        let mut q = BoundedDeque::new(4096, 4096, 1.0);
        q.push_back_prioritized(
            Item {
                id: 1,
                cost: 1,
                priority: 10,
            },
            |item| item.priority,
        )
        .unwrap();
        q.push_back_prioritized(
            Item {
                id: 2,
                cost: 1,
                priority: 200,
            },
            |item| item.priority,
        )
        .unwrap();
        q.push_back_prioritized(
            Item {
                id: 3,
                cost: 1,
                priority: 100,
            },
            |item| item.priority,
        )
        .unwrap();

        assert_eq!(q.pop_lowest_priority().map(|item| item.id), Some(1));
        assert_eq!(q.pop_front().map(|item| item.id), Some(2));
        assert_eq!(q.pop_front().map(|item| item.id), Some(3));
    }

    #[test]
    fn every_lower_priority_band_gets_a_turn_before_rotation_wraps() {
        let mut q = BoundedDeque::new(8192, 8192, 1.0);
        for priority in 0..255 {
            q.push_back_prioritized(
                Item {
                    id: priority,
                    cost: 1,
                    priority,
                },
                |i| i.priority,
            )
            .unwrap();
        }
        let mut burst = 0;
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..9 * 256 {
            q.push_back_prioritized(
                Item {
                    id: 255,
                    cost: 1,
                    priority: 255,
                },
                |i| i.priority,
            )
            .unwrap();
            let item = q.pop_front_fair(&mut burst, 8, |i| i.priority).unwrap();
            if item.priority != 255 {
                seen.push(item.priority);
                q.push_back_prioritized(item, |i| i.priority).unwrap();
            }
        }
        let mut expected: alloc::vec::Vec<u8> = (0..255).rev().collect();
        expected.push(254);
        assert_eq!(seen, expected);
    }

    #[test]
    fn band_rotation_preserves_fifo_and_skips_deferred_items() {
        let mut q = BoundedDeque::new(4096, 4096, 1.0);
        for (id, priority) in [(1, 254), (2, 254), (3, 16)] {
            q.push_back_prioritized(
                Item {
                    id,
                    cost: 1,
                    priority,
                },
                |i| i.priority,
            )
            .unwrap();
        }
        let mut burst = 8;
        let first = q
            .pop_front_fair_if(&mut burst, 8, |i| i.priority, |i| i.id != 1 && i.id != 2)
            .unwrap();
        assert_eq!(first.id, 3);
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..27 {
            q.push_back_prioritized(
                Item {
                    id: 255,
                    cost: 1,
                    priority: 255,
                },
                |i| i.priority,
            )
            .unwrap();
            let item = q
                .pop_front_fair_if(&mut burst, 8, |i| i.priority, |_| true)
                .unwrap();
            if item.id != 255 {
                seen.push(item.id);
            }
        }
        assert_eq!(seen, alloc::vec![1, 2]);
        // The cursor occupies existing tail padding on the supported layouts.
        assert_eq!(
            core::mem::size_of::<BoundedDeque<Item>>(),
            10 * core::mem::size_of::<usize>()
        );
    }

    #[test]
    fn sustained_receipts_and_bulk_cannot_starve_managed_updates_between_them() {
        let mut q = BoundedDeque::new(4096, 4096, 1.0);
        for priority in [16, 254] {
            q.push_back_prioritized(
                Item {
                    id: priority,
                    cost: 1,
                    priority,
                },
                |i| i.priority,
            )
            .unwrap();
        }
        let mut burst = 0;
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..18 {
            // A live receipt stream keeps the highest band continuously ready.
            q.push_back_prioritized(
                Item {
                    id: 255,
                    cost: 1,
                    priority: 255,
                },
                |i| i.priority,
            )
            .unwrap();
            let item = q.pop_front_fair(&mut burst, 8, |i| i.priority).unwrap();
            if item.priority != 255 {
                seen.push(item.priority);
                q.push_back_prioritized(item, |i| i.priority).unwrap();
            }
        }
        assert_eq!(
            seen,
            alloc::vec![254, 16],
            "every waiting band needs a bounded service turn"
        );
    }

    #[test]
    fn prioritized_queue_eventually_services_waiting_low_priority_item() {
        let mut q = BoundedDeque::new(512, 128, 2.0);
        q.push_back_prioritized(
            Item {
                id: 1,
                cost: 1,
                priority: 1,
            },
            |item| item.priority,
        )
        .unwrap();
        for id in 2..=20 {
            q.push_back_prioritized(
                Item {
                    id,
                    cost: 1,
                    priority: 250,
                },
                |item| item.priority,
            )
            .unwrap();
        }

        let mut burst = 0;
        for _ in 0..8 {
            assert_ne!(
                q.pop_front_fair(&mut burst, 8, |item| item.priority)
                    .unwrap()
                    .id,
                1
            );
        }
        assert_eq!(
            q.pop_front_fair(&mut burst, 8, |item| item.priority)
                .unwrap()
                .id,
            1
        );
        assert_eq!(burst, 0);
    }

    #[test]
    fn one_x_growth_keeps_startup_capacity_and_evicts() {
        let item_size = size_of::<Item>();
        let mut q = BoundedDeque::new(item_size * 8, item_size * 2, 1.0);
        let startup_capacity = q.capacity();

        for id in 0..(startup_capacity + 4) {
            q.push_back(Item {
                id: id as u8,
                cost: 1,
                priority: 0,
            })
            .unwrap();
            assert_eq!(q.capacity(), startup_capacity);
        }

        assert_eq!(q.len(), startup_capacity);
        assert_eq!(q.pop_front().unwrap().id, 4);
    }

    #[test]
    fn prioritized_queue_drops_lower_priority_when_saturated() {
        let mut q = BoundedDeque::new(64, 32, 2.0);
        q.push_back_prioritized(
            Item {
                id: 1,
                cost: 32,
                priority: 20,
            },
            |item| item.priority,
        )
        .unwrap();
        q.push_back_prioritized(
            Item {
                id: 2,
                cost: 32,
                priority: 20,
            },
            |item| item.priority,
        )
        .unwrap();

        let err = q
            .push_back_prioritized(
                Item {
                    id: 3,
                    cost: 32,
                    priority: 10,
                },
                |item| item.priority,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            TelemetryError::Io("priority queue saturated")
        ));
        assert_eq!(q.pop_front().unwrap().id, 1);
        assert_eq!(q.pop_front().unwrap().id, 2);
    }

    #[test]
    fn saturated_control_queue_never_replaces_an_equal_priority_update() {
        let mut q = BoundedDeque::new(64, 64, 1.0);
        for id in [1, 2] {
            q.push_back_prioritized(
                Item {
                    id,
                    cost: 32,
                    priority: 254,
                },
                |item| item.priority,
            )
            .unwrap();
        }

        assert_eq!(
            q.push_back_prioritized(
                Item {
                    id: 3,
                    cost: 32,
                    priority: 254,
                },
                |item| item.priority,
            ),
            Err(TelemetryError::Io("priority queue saturated"))
        );
        assert_eq!(q.pop_front().unwrap().id, 1);
        assert_eq!(q.pop_front().unwrap().id, 2);
    }

    #[test]
    fn bounded_queue_never_exceeds_element_cap_or_capacity() {
        let mut q = BoundedDeque::new(256, 8, 2.0);
        let max_elems = q.max_elems();
        let max_bytes = q.max_bytes();

        for id in 0..(max_elems * 4) {
            q.push_back(Item {
                id: id as u8,
                cost: 1,
                priority: 0,
            })
            .unwrap();
            assert!(q.len() <= max_elems);
            assert!(q.capacity() <= max_elems);
            assert!(q.bytes_used() <= max_bytes);
        }

        assert_eq!(q.len(), max_elems);
    }

    #[test]
    fn bounded_queue_never_exceeds_byte_budget_under_eviction() {
        let mut q = BoundedDeque::new(48, 8, 2.0);
        let max_elems = q.max_elems();
        let max_bytes = q.max_bytes();

        for id in 0..32u8 {
            q.push_back(Item {
                id,
                cost: 17,
                priority: 0,
            })
            .unwrap();
            assert!(q.len() <= max_elems);
            assert!(q.capacity() <= max_elems);
            assert!(q.bytes_used() <= max_bytes);
        }

        let retained_bytes: usize = q.iter().map(ByteCost::byte_cost).sum();
        assert_eq!(q.bytes_used(), retained_bytes);
    }
}

#[cfg(all(test, feature = "compact-packet-store"))]
mod arena_queue_tests {
    use super::*;
    use crate::packet_store::PacketStore;
    use crate::small_payload::SmallPayload;
    impl ByteCost for TestPayload {
        fn byte_cost(&self) -> usize {
            self.0.len()
        }
        fn park_for_queue(&mut self) -> TelemetryResult<()> {
            self.0.park_in_store(&self.1)
        }
    }
    #[derive(Clone)]
    struct TestPayload(SmallPayload<4>, alloc::sync::Arc<PacketStore>);
    #[test]
    fn parking_releases_slice_pins_and_fixed_queue_clones_keep_capacity() {
        let store = PacketStore::new(256, 8, 256).unwrap();
        let mut q = BoundedDeque::new(256, 64, 2.0);
        q.push_back(TestPayload(SmallPayload::new(&[4; 24]), store.clone()))
            .unwrap();
        assert_eq!(q.iter().next().unwrap().0.as_slice(), &[4; 24]);
        assert_eq!(store.stats().pinned_bytes, 24);
        let value = q.pop_front().unwrap();
        q.push_back(value).unwrap();
        assert_eq!(store.stats().pinned_bytes, 0);
        let capacity = q.capacity();
        let mut clone = q.clone();
        for _ in 0..100 {
            clone
                .push_back(TestPayload(SmallPayload::new(&[5; 24]), store.clone()))
                .ok();
        }
        assert_eq!(clone.capacity(), capacity);
        drop(clone);
        drop(q);
        assert_eq!(store.stats().live_bytes, 0);
    }
}

#[cfg(all(test, not(feature = "compact-packet-store")))]
mod growth_tests {
    use super::*;
    struct Item {
        id: u8,
        cost: usize,
        priority: u8,
    }
    impl ByteCost for Item {
        fn byte_cost(&self) -> usize {
            self.cost
        }
    }
    extern "C" fn refuse_growth(_: usize, _: usize) -> bool {
        false
    }
    struct ProbeReset;
    impl Drop for ProbeReset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }
    #[test]
    fn refused_growth_reuses_storage_without_evicting_protected_acks() {
        let mut q = BoundedDeque::new(1024, size_of::<Item>(), 1.25);
        assert_eq!(q.q.capacity(), 1);
        q.push_back_prioritized(
            Item {
                id: 1,
                cost: 17,
                priority: 10,
            },
            |i| i.priority,
        )
        .unwrap();
        crate::memory_admission::set_probe(Some(refuse_growth));
        let _reset = ProbeReset;
        q.push_back_prioritized(
            Item {
                id: 2,
                cost: 19,
                priority: 254,
            },
            |i| i.priority,
        )
        .unwrap();
        assert_eq!(q.q.capacity(), 1);
        assert_eq!(q.bytes_used(), 19);
        assert_eq!(q.q.front().unwrap().id, 2);
        assert!(
            q.push_back_prioritized(
                Item {
                    id: 3,
                    cost: 23,
                    priority: 254
                },
                |i| i.priority
            )
            .is_err()
        );
        assert_eq!(q.bytes_used(), 19);
        assert_eq!(q.q.front().unwrap().id, 2);
        assert!(
            q.push_back_prioritized(
                Item {
                    id: 4,
                    cost: 23,
                    priority: 10
                },
                |i| i.priority
            )
            .is_err()
        );
        assert_eq!(q.q.front().unwrap().id, 2);
        crate::memory_admission::set_probe(None);
        q.push_back_prioritized(
            Item {
                id: 5,
                cost: 23,
                priority: 254,
            },
            |i| i.priority,
        )
        .unwrap();
        assert!(q.q.capacity() > 1);
        assert_eq!(q.bytes_used(), 42);
        assert_eq!(q.pop_front().unwrap().id, 2);
        assert_eq!(q.pop_front().unwrap().id, 5);
    }
    #[test]
    fn refused_fifo_growth_remains_bounded_and_recovers() {
        let mut q = BoundedDeque::new(1024, size_of::<Item>(), 1.25);
        q.push_back(Item {
            id: 1,
            cost: 17,
            priority: 10,
        })
        .unwrap();
        crate::memory_admission::set_probe(Some(refuse_growth));
        let _reset = ProbeReset;
        q.push_back(Item {
            id: 2,
            cost: 23,
            priority: 10,
        })
        .unwrap();
        assert_eq!(q.q.capacity(), 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes_used(), 23);
        assert_eq!(q.q.front().unwrap().id, 2);
        crate::memory_admission::set_probe(None);
        q.push_back(Item {
            id: 3,
            cost: 29,
            priority: 10,
        })
        .unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.bytes_used(), 52);
    }
}

#[cfg(test)]
mod startup_admission_tests {
    use super::*;

    #[cfg(feature = "compact-packet-store")]
    extern "C" fn fragmented_startup(additional: usize, largest: usize) -> bool {
        additional <= 8192 && largest <= 8192
    }
    extern "C" fn deny_storage(_: usize, _: usize) -> bool {
        false
    }
    struct ProbeReset;
    impl Drop for ProbeReset {
        fn drop(&mut self) {
            crate::memory_admission::set_probe(None);
        }
    }

    #[test]
    #[cfg(feature = "compact-packet-store")]
    fn compact_startup_ring_respects_fragmented_heap_admission() {
        crate::memory_admission::set_probe(Some(fragmented_startup));
        let _reset = ProbeReset;
        let mut queue = BoundedDeque::<u64>::new(12288, 1024, 1.25);
        assert!(queue.capacity() > 0);
        assert!(queue.capacity() * size_of::<u64>() + 64 <= 8192);
        let capacity = queue.capacity();
        crate::memory_admission::set_probe(Some(deny_storage));
        for value in 0..capacity * 2 {
            queue.push_back(value as u64).unwrap();
        }
        assert_eq!(queue.capacity(), capacity);
        assert_eq!(queue.len(), capacity);
        assert_eq!(queue.bytes_used(), capacity * size_of::<u64>());
    }

    #[test]
    fn denied_startup_storage_rejects_fifo_and_priority_without_growth() {
        crate::memory_admission::set_probe(Some(deny_storage));
        let _reset = ProbeReset;
        let mut queue = BoundedDeque::<u64>::new(4096, 512, 1.25);
        assert_eq!(queue.capacity(), 0);
        assert!(queue.push_back(1).is_err());
        assert!(queue.push_back_prioritized(2, |_| 254).is_err());
        assert!(queue.is_empty());
        assert_eq!(queue.bytes_used(), 0);
    }
}

#[cfg(test)]
mod growth_ratio_tests {
    #[test]
    fn integer_ratio_matches_float_clamp_and_truncation() {
        let check = |value: f64| {
            let previous = ((value.clamp(1.01, 16.0) * 1024.0) as usize).max(1025);
            assert_eq!(super::float_to_ratio(value), (previous, 1024), "{value:?}");
        };
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1.0,
            -0.0,
            0.0,
            1.0,
            1.01,
            1.25,
            2.0,
            16.0,
            17.0,
        ] {
            check(value);
        }
        for index in 0..10000 {
            check(index as f64 / 500.0);
        }
        for value in [1.01f64, 1.25, 2.0, 4.0, 8.0, 16.0] {
            for adjustment in [-1i64, 0, 1] {
                check(f64::from_bits(
                    value.to_bits().wrapping_add_signed(adjustment),
                ));
            }
        }
    }
}

#[cfg(test)]
mod fair_selector_tests {
    use super::*;
    struct Item {
        id: u8,
        cost: usize,
        priority: u8,
    }
    impl ByteCost for Item {
        fn byte_cost(&self) -> usize {
            self.cost
        }
    }
    #[test]
    fn custom_reclamation_cannot_override_priority_or_remove_invalid_indices() {
        for selected in [None, Some(0), Some(999)] {
            let mut queue = BoundedDeque::new(200, 200, 1.0);
            queue
                .push_back_prioritized(
                    Item {
                        id: 1,
                        cost: 100,
                        priority: 250,
                    },
                    |item| item.priority,
                )
                .unwrap();
            queue
                .push_back_prioritized(
                    Item {
                        id: 2,
                        cost: 100,
                        priority: 0,
                    },
                    |item| item.priority,
                )
                .unwrap();
            assert!(
                queue
                    .push_back_prioritized_select(
                        Item {
                            id: 3,
                            cost: 100,
                            priority: 0
                        },
                        |item| item.priority,
                        |_, _| selected,
                        core::mem::drop,
                    )
                    .is_err()
            );
            assert_eq!(queue.len(), 2);
            assert_eq!(queue.bytes_used(), 200);
            assert_eq!(
                queue
                    .iter()
                    .map(|item| item.id)
                    .collect::<alloc::vec::Vec<_>>(),
                [1, 2]
            );
        }
    }
}
