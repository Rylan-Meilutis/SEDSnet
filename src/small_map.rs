//! Compact ordered index for small embedded router tables.
//!
//! Binary search preserves B-tree key order and logarithmic lookups. Insertions
//! shift entries, so this is reserved for small side/transport/replay indexes;
//! unbounded schemas, peer addresses and per-type metadata keep B-trees. Empty
//! tables release their allocation rather than retaining a historical peak.
//! There is no entry cap and no unsafe code. Desktop production uses B-trees.
use alloc::vec::Vec;
use core::borrow::Borrow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SmallMap<K, V> {
    entries: Vec<(K, V)>,
}
impl<K, V> Default for SmallMap<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}
impl<K: Ord, V> SmallMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }
    fn position<Q: Ord + ?Sized>(&self, key: &Q) -> Result<usize, usize>
    where
        K: Borrow<Q>,
    {
        self.entries.binary_search_by(|(k, _)| k.borrow().cmp(key))
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn clear(&mut self) {
        self.entries = Vec::new()
    }
    pub fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.position(key).ok().map(|i| &self.entries[i].1)
    }
    pub fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        self.position(key).ok().map(|i| &mut self.entries[i].1)
    }
    pub fn contains_key<Q: Ord + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.position(key).is_ok()
    }
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.position(&key) {
            Ok(i) => Some(core::mem::replace(&mut self.entries[i].1, value)),
            Err(i) => {
                self.entries.insert(i, (key, value));
                None
            }
        }
    }
    pub fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        self.position(key).ok().map(|i| {
            let value = self.entries.remove(i).1;
            if self.entries.is_empty() {
                self.clear();
            }
            value
        })
    }
    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.entries.first().map(|(k, v)| (k, v))
    }
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        if self.entries.is_empty() {
            None
        } else {
            Some({
                let value = self.entries.remove(0);
                if self.entries.is_empty() {
                    self.clear();
                }
                value
            })
        }
    }
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, mut f: F) {
        self.entries.retain_mut(|(k, v)| f(k, v));
        if self.entries.is_empty() {
            self.clear();
        }
    }
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter(self.entries.iter())
    }
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut(self.entries.iter_mut())
    }
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &K> + ExactSizeIterator {
        self.entries.iter().map(|(k, _)| k)
    }
    pub fn values(&self) -> impl DoubleEndedIterator<Item = &V> + ExactSizeIterator + Clone {
        self.entries.iter().map(|(_, v)| v)
    }
    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut V> + ExactSizeIterator {
        self.entries.iter_mut().map(|(_, v)| v)
    }
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        let position = self.position(&key);
        Entry {
            map: self,
            key,
            position,
        }
    }
}
pub(crate) struct Entry<'a, K, V> {
    map: &'a mut SmallMap<K, V>,
    key: K,
    position: Result<usize, usize>,
}
impl<'a, K: Ord, V> Entry<'a, K, V> {
    #[cfg(test)]
    pub fn and_modify<F: FnOnce(&mut V)>(self, f: F) -> Self {
        if let Ok(i) = self.position {
            f(&mut self.map.entries[i].1);
        }
        self
    }
    pub fn or_insert(self, value: V) -> &'a mut V {
        self.or_insert_with(|| value)
    }
    pub fn or_insert_with<F: FnOnce() -> V>(self, f: F) -> &'a mut V {
        let i = match self.position {
            Ok(i) => i,
            Err(i) => {
                self.map.entries.insert(i, (self.key, f()));
                i
            }
        };
        &mut self.map.entries[i].1
    }
    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.or_insert_with(V::default)
    }
}
pub(crate) struct Iter<'a, K, V>(core::slice::Iter<'a, (K, V)>);
impl<K, V> Clone for Iter<'_, K, V> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (k, v))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}
impl<K, V> DoubleEndedIterator for Iter<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(|(k, v)| (k, v))
    }
}
impl<K, V> ExactSizeIterator for Iter<'_, K, V> {}
pub(crate) struct IterMut<'a, K, V>(core::slice::IterMut<'a, (K, V)>);
impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, v)| (&*k, v))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}
impl<K, V> DoubleEndedIterator for IterMut<'_, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(|(k, v)| (&*k, v))
    }
}
impl<K, V> ExactSizeIterator for IterMut<'_, K, V> {}
impl<K, V> IntoIterator for SmallMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
impl<'a, K: Ord, V> IntoIterator for &'a SmallMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<'a, K: Ord, V> IntoIterator for &'a mut SmallMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
impl<K: Ord, V> FromIterator<(K, V)> for SmallMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(it: T) -> Self {
        let mut map = Self::new();
        for (k, v) in it {
            map.insert(k, v);
        }
        map
    }
}
impl<K: Ord, V, const N: usize> From<[(K, V); N]> for SmallMap<K, V> {
    fn from(v: [(K, V); N]) -> Self {
        v.into_iter().collect()
    }
}
impl<K: Ord + Borrow<Q>, V, Q: Ord + ?Sized> core::ops::Index<&Q> for SmallMap<K, V> {
    type Output = V;
    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("no entry found for key")
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::SmallMap;
    use std::collections::BTreeMap;
    #[test]
    fn randomized_btree_equivalence() {
        let (mut a, mut b) = (SmallMap::new(), BTreeMap::new());
        let mut seed = 123456789u64;
        for step in 0..100000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let key = (seed % 1024) as u32;
            let value = step;
            match seed % 7 {
                0 => assert_eq!(a.insert(key, value), b.insert(key, value)),
                1 => assert_eq!(a.remove(&key), b.remove(&key)),
                2 => assert_eq!(a.get(&key), b.get(&key)),
                3 => {
                    *a.entry(key).or_default() += 1;
                    *b.entry(key).or_default() += 1
                }
                4 => {
                    a.entry(key).and_modify(|v| *v += 5).or_insert(value);
                    b.entry(key).and_modify(|v| *v += 5).or_insert(value);
                }
                5 => {
                    a.retain(|k, v| {
                        *v += 1;
                        *k % 5 != 0
                    });
                    b.retain(|k, v| {
                        *v += 1;
                        *k % 5 != 0
                    });
                }
                _ => assert_eq!(a.pop_first(), b.pop_first()),
            }
            assert_eq!(a.len(), b.len());
            assert!(a.iter().eq(b.iter()));
            assert!(a.iter().rev().eq(b.iter().rev()));
            assert_eq!(a.first_key_value(), b.first_key_value());
        }
        assert!(a.clone().into_iter().eq(b.clone()));
    }
    #[test]
    fn entry_laziness_key_retention_and_borrow() {
        let mut m = SmallMap::new();
        m.insert("hello".to_string(), 1);
        m.entry("hello".to_string())
            .or_insert_with(|| panic!("must not evaluate"));
        assert_eq!(m["hello"], 1);
        assert_eq!(
            m.get_mut("hello").map(|v| {
                *v += 1;
                *v
            }),
            Some(2)
        );
        let clone = m.iter().clone();
        assert!(clone.eq(m.iter()));
        assert_eq!(m.remove("hello"), Some(2));
        assert!(m.is_empty());
    }
    #[test]
    fn no_value_leaks() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Count(Arc<AtomicUsize>);
        impl Drop for Count {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let c = Arc::new(AtomicUsize::new(0));
        {
            let mut m = SmallMap::new();
            for i in 0..256 {
                m.insert(i, Count(c.clone()));
            }
            m.retain(|k, _| k % 2 == 0);
            assert_eq!(c.load(Ordering::SeqCst), 128);
            m.clear();
            assert_eq!(c.load(Ordering::SeqCst), 256);
        }
        assert_eq!(c.load(Ordering::SeqCst), 256);
    }
}
