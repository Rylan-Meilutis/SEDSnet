//! Constant-scratch sorting for embedded routing identifiers.
//!
//! The standard numeric small-sort specializations trade flash for speed.
//! Route/recipient lists do not need those unrolled sorting networks. Heapsort
//! retains O(n log n) worst-case work, no recursion, and no heap allocation.

pub(crate) fn sort<T: Ord>(values: &mut [T]) {
    #[cfg(not(feature = "embedded"))]
    values.sort_unstable();
    #[cfg(feature = "embedded")]
    heap_sort(values);
}

/// Unstable sort by comparator; embedded builds use the same constant-scratch
/// heapsort instead of instantiating the standard pattern-defeating quicksort.
#[cfg(feature = "discovery")]
pub(crate) fn sort_by<T, F: FnMut(&T, &T) -> core::cmp::Ordering>(values: &mut [T], compare: F) {
    #[cfg(not(feature = "embedded"))]
    values.sort_unstable_by(compare);
    #[cfg(feature = "embedded")]
    heap_sort_by(values, compare);
}

#[cfg(any(feature = "embedded", test))]
fn heap_sort<T: Ord>(values: &mut [T]) {
    heap_sort_by(values, T::cmp);
}

#[cfg(any(feature = "embedded", test))]
fn heap_sort_by<T, F: FnMut(&T, &T) -> core::cmp::Ordering>(values: &mut [T], mut compare: F) {
    use core::cmp::Ordering::Less;
    fn sift<T, F: FnMut(&T, &T) -> core::cmp::Ordering>(
        values: &mut [T],
        mut root: usize,
        end: usize,
        compare: &mut F,
    ) {
        while root < end / 2 {
            let mut child = root * 2 + 1;
            if child + 1 < end && compare(&values[child], &values[child + 1]) == Less {
                child += 1;
            }
            if compare(&values[root], &values[child]) != Less {
                break;
            }
            values.swap(root, child);
            root = child;
        }
    }
    let len = values.len();
    for root in (0..len / 2).rev() {
        sift(values, root, len, &mut compare);
    }
    for end in (1..len).rev() {
        values.swap(0, end);
        sift(values, 0, end, &mut compare);
    }
}

#[cfg(test)]
mod tests {
    use super::heap_sort;
    #[test]
    fn comparator_sort_matches_standard_ordering() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut values: alloc::vec::Vec<(u8, u16)> = (0..300u16)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                ((seed % 9) as u8, i)
            })
            .collect();
        let mut expected = values.clone();
        expected.sort_unstable_by(|a, b| b.cmp(a));
        super::heap_sort_by(&mut values, |a, b| b.cmp(a));
        assert_eq!(values, expected);
    }
    #[test]
    fn embedded_sort_matches_standard_for_routing_lists() {
        for length in [0, 1, 2, 3, 7, 8, 13, 16, 31, 32, 255, 256, 1024] {
            for pattern in 0..5 {
                let mut seed = 0x123456789abcdefu64;
                let mut values: alloc::vec::Vec<u64> = (0..length)
                    .map(|i| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        match pattern {
                            0 => i as u64,
                            1 => (length - i) as u64,
                            2 => seed % 7,
                            3 => {
                                if i % 2 == 0 {
                                    u64::MAX
                                } else {
                                    0
                                }
                            }
                            _ => seed,
                        }
                    })
                    .collect();
                let mut expected = values.clone();
                expected.sort_unstable();
                heap_sort(&mut values);
                assert_eq!(values, expected, "length={length}, pattern={pattern}");
            }
        }
    }
}

#[cfg(test)]
mod string_heap_equivalence {
    use super::heap_sort;
    use alloc::{string::String,vec::Vec};
    fn samples(length:usize)->Vec<String> {
        let words=["", "a", "aa", "A", "é", "λ", "a\0b", "z", "same"];
        (0..length).map(|index|{
            let word=words[(index*7+length)%words.len()];
            let mut value=String::with_capacity(word.len()+if index%2==0{4096}else{0});value.push_str(word);value
        }).collect()
    }
    #[test]
    fn string_heap_sort_large_ties_empty_unicode_and_capacities_match_values() {
        for length in [0,1,2,3,7,8,16,64,255,1024] {
            let mut values=samples(length);let mut expected=values.clone();expected.sort_unstable();
            let mut allocations=values.iter().map(|s|(s.as_ptr()as usize,s.len(),s.capacity())).collect::<Vec<_>>();allocations.sort_unstable();
            heap_sort(&mut values);assert_eq!(values,expected);
            let mut after=values.iter().map(|s|(s.as_ptr()as usize,s.len(),s.capacity())).collect::<Vec<_>>();after.sort_unstable();
            assert_eq!(after,allocations,"sort moves owners without duplicating/dropping allocations");
            values.dedup();expected.dedup();assert_eq!(values,expected);
            // Equal-value allocation choice is intentionally not asserted.
        }
    }
    #[test]
    fn borrowed_string_heap_sort_matches_lexical_dedup_values() {
        for length in [0,1,2,7,16,255,1024] {
            let owners=samples(length);let mut values=owners.iter().map(String::as_str).collect::<Vec<_>>();
            let mut expected=values.clone();expected.sort_unstable();heap_sort(&mut values);assert_eq!(values,expected);
            values.dedup();expected.dedup();assert_eq!(values,expected);
        }
    }
}
