//! Append-only replay index. Keys stay retained while values may be replaced.
//! Nodes live in one fallibly grown allocation;
//! AVL balance bounds lookup/insert depth even for adversarial ID order.
use alloc::vec::Vec;
use crate::{IdState, RecoveryError};
use crate::replay_budget::ReplayBudget;

const NONE: u32 = u32::MAX;

#[derive(Clone, Debug)]
struct Node<V, K> {
    key: K,
    value: V,
    left: u32,
    right: u32,
    height: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct ReplayIndex<V, K = u128> {
    nodes: Vec<Node<V, K>>,
    root: u32,
}

pub(crate) type ReplayIds = ReplayIndex<IdState>;

impl<V, K: Ord + Copy> ReplayIndex<V, K> {
    pub(crate) fn new() -> Self {
        Self { nodes: Vec::new(), root: NONE }
    }

    fn find(&self, key: &K) -> Option<usize> {
        let mut at = self.root;
        while at != NONE {
            let node = &self.nodes[at as usize];
            match key.cmp(&node.key) {
                core::cmp::Ordering::Less => at = node.left,
                core::cmp::Ordering::Greater => at = node.right,
                core::cmp::Ordering::Equal => return Some(at as usize),
            }
        }
        None
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.find(key).map(|at| &self.nodes[at].value)
    }

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.find(key).map(|at| &mut self.nodes[at].value)
    }

    pub(crate) fn len(&self) -> usize { self.nodes.len() }
    pub(crate) fn is_empty(&self) -> bool { self.nodes.is_empty() }

    // In insertion order, not key order. Public sorted output must sort itself.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.nodes.iter().map(|node| (&node.key, &node.value))
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, key: K, value: V, limit: usize) -> Result<Option<V>, RecoveryError> {
        if let Some(existing) = self.get_mut(&key) {
            return Ok(Some(core::mem::replace(existing, value)));
        }
        self.insert_absent(key, value, limit)?;
        Ok(None)
    }

    pub(crate) fn insert_budgeted(&mut self, key: K, value: V, budget: &mut ReplayBudget)
        -> Result<Option<V>, RecoveryError> {
        if let Some(existing) = self.get_mut(&key) {
            return Ok(Some(core::mem::replace(existing, value)));
        }
        self.insert_absent_budgeted(key, value, budget)?;
        Ok(None)
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        self.nodes.capacity() * core::mem::size_of::<Node<V, K>>()
    }

    #[cfg(test)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.nodes.iter().map(|node| &node.value)
    }

    #[cfg(test)]
    pub(crate) fn insert_absent(&mut self, key: K, value: V, limit: usize) -> Result<(), RecoveryError> {
        let mut budget = ReplayBudget::new(limit);
        budget.charge(self.allocated_bytes())?;
        self.insert_absent_budgeted(key, value, &mut budget)
    }

    // The shared budget already includes this index's retained allocation.
    // Reserve a replacement while the old capacity remains charged, then
    // release the old charge. All callers discard failed replay state.
    pub(crate) fn insert_absent_budgeted(
        &mut self, key: K, value: V, budget: &mut ReplayBudget,
    ) -> Result<(), RecoveryError> {
        if self.nodes.len() >= NONE as usize {
            return Err(RecoveryError::AllocationFailed);
        }
        if self.nodes.len() == self.nodes.capacity() {
            let size = core::mem::size_of::<Node<V, K>>();
            let old_bytes = self.allocated_bytes();
            let desired = self.nodes.len().checked_add((self.nodes.len() / 2).max(16))
                .ok_or(RecoveryError::AllocationFailed)?.min(NONE as usize);
            let admitted = (budget.remaining() / size).min(desired);
            if admitted <= self.nodes.len() { return Err(RecoveryError::AllocationFailed); }
            let reserved = admitted.checked_mul(size).ok_or(RecoveryError::AllocationFailed)?;
            budget.charge(reserved)?;
            if self.nodes.try_reserve_exact(admitted - self.nodes.len()).is_err() {
                budget.release(reserved);
                return Err(RecoveryError::AllocationFailed);
            }
            let actual = self.allocated_bytes();
            if actual > reserved { budget.charge(actual - reserved)?; }
            budget.release(old_bytes);
        }
        let added = self.nodes.len() as u32;
        self.nodes.push(Node { key, value, left: NONE, right: NONE, height: 1 });
        self.root = self.attach(self.root, added);
        Ok(())
    }

    fn height(&self, at: u32) -> u8 {
        if at == NONE { 0 } else { self.nodes[at as usize].height }
    }

    fn refresh(&mut self, at: u32) {
        let node = &self.nodes[at as usize];
        let height = 1 + self.height(node.left).max(self.height(node.right));
        self.nodes[at as usize].height = height;
    }

    fn rotate_left(&mut self, at: u32) -> u32 {
        let right = self.nodes[at as usize].right;
        self.nodes[at as usize].right = self.nodes[right as usize].left;
        self.nodes[right as usize].left = at;
        self.refresh(at);
        self.refresh(right);
        right
    }

    fn rotate_right(&mut self, at: u32) -> u32 {
        let left = self.nodes[at as usize].left;
        self.nodes[at as usize].left = self.nodes[left as usize].right;
        self.nodes[left as usize].right = at;
        self.refresh(at);
        self.refresh(left);
        left
    }

    fn attach(&mut self, at: u32, added: u32) -> u32 {
        if at == NONE { return added; }
        let key = self.nodes[added as usize].key;
        if key < self.nodes[at as usize].key {
            let child = self.attach(self.nodes[at as usize].left, added);
            self.nodes[at as usize].left = child;
        } else {
            debug_assert!(key != self.nodes[at as usize].key);
            let child = self.attach(self.nodes[at as usize].right, added);
            self.nodes[at as usize].right = child;
        }
        self.refresh(at);
        let left = self.nodes[at as usize].left;
        let right = self.nodes[at as usize].right;
        let balance = self.height(left) as i16 - self.height(right) as i16;
        if balance > 1 {
            if key > self.nodes[left as usize].key {
                let child = self.rotate_left(left);
                self.nodes[at as usize].left = child;
            }
            return self.rotate_right(at);
        }
        if balance < -1 {
            if key < self.nodes[right as usize].key {
                let child = self.rotate_right(right);
                self.nodes[at as usize].right = child;
            }
            return self.rotate_left(at);
        }
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdClass;
    fn state() -> IdState { IdState { class: IdClass::Object, consumed: false } }

    fn audit(tree: &ReplayIds, at: u32, min: Option<u128>, max: Option<u128>) -> (u8, usize) {
        if at == NONE { return (0, 0); }
        let n = &tree.nodes[at as usize];
        assert!(min.map_or(true, |v| v < n.key));
        assert!(max.map_or(true, |v| n.key < v));
        let (left, lc) = audit(tree, n.left, min, Some(n.key));
        let (right, rc) = audit(tree, n.right, Some(n.key), max);
        assert!((left as i16 - right as i16).abs() <= 1);
        assert_eq!(n.height, 1 + left.max(right));
        (n.height, 1 + lc + rc)
    }

    #[test]
    fn ordered_reverse_and_shuffled_insertions_remain_balanced() {
        for order in 0..3 {
            let mut tree = ReplayIds::new();
            let mut keys: Vec<u128> = (0..4096).map(|i| (i as u128) << 96 | i).collect();
            if order == 1 { keys.reverse(); }
            if order == 2 {
                let mut rng = 97u64;
                for i in (1..keys.len()).rev() {
                    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                    keys.swap(i, rng as usize % (i + 1));
                }
            }
            for (i, key) in keys.iter().enumerate() {
                assert!(tree.get_mut(key).is_none());
                tree.insert_absent(*key, state(), usize::MAX).unwrap();
                if i < 32 || i % 127 == 0 {
                    assert_eq!(audit(&tree, tree.root, None, None).1, i + 1);
                }
            }
            assert_eq!(audit(&tree, tree.root, None, None).1, keys.len());
            for key in &keys { tree.get_mut(key).unwrap().consumed = true; }
            let mut cloned = tree.clone();
            for key in keys { assert!(cloned.get_mut(&key).unwrap().consumed); }
            assert!(tree.get_mut(&u128::MAX).is_none());
        }
    }

    #[test]
    fn replacing_owned_state_needs_no_allocation_and_returns_old_value() {
        let mut tree = ReplayIndex::new();
        assert!(tree.insert(7, alloc::vec![1u8, 2, 3], usize::MAX).unwrap().is_none());
        let pointer = tree.nodes.as_ptr();
        let capacity = tree.nodes.capacity();
        // Existing entries can transition even with no growth allowance.
        assert_eq!(tree.insert(7, Vec::new(), 0).unwrap(), Some(alloc::vec![1, 2, 3]));
        assert_eq!(tree.nodes.as_ptr(), pointer);
        assert_eq!(tree.nodes.capacity(), capacity);
        assert_eq!(tree.nodes.len(), 1);
        assert!(tree.get_mut(&7).unwrap().is_empty());
    }

    #[test]
    fn shared_budget_includes_other_indexes_and_old_new_overlap() {
        let size = core::mem::size_of::<Node<IdState, u128>>();
        for limit in [49 * size - 1, 49 * size] {
            let mut budget = ReplayBudget::new(limit);
            let mut first = ReplayIds::new();
            let mut second = ReplayIds::new();
            for key in 0..16 {
                first.insert_absent_budgeted(key, state(), &mut budget).unwrap();
            }
            second.insert_absent_budgeted(90, state(), &mut budget).unwrap();
            assert_eq!(budget.used(), 32 * size);
            let result = first.insert_absent_budgeted(16, state(), &mut budget);
            if limit == 49 * size - 1 {
                assert_eq!(result, Err(RecoveryError::AllocationFailed));
                assert_eq!(first.len(), 16);
                assert_eq!(budget.used(), 32 * size);
                assert!(first.get(&16).is_none());
            } else {
                result.unwrap();
                assert_eq!(first.len(), 17);
                assert_eq!(budget.used(), 33 * size);
                assert_eq!(budget.peak(), 49 * size);
            }
            assert!(second.get(&90).is_some());
            budget.release(second.allocated_bytes());
            drop(second);
            assert_eq!(budget.used(), first.allocated_bytes());
            budget.release(first.allocated_bytes());
            drop(first);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn node_budget_accounts_for_growth_overlap_and_preserves_entries() {
        let size = core::mem::size_of::<Node<IdState, u128>>();
        let mut tree = ReplayIds::new();
        assert_eq!(tree.insert_absent(7, state(), size - 1), Err(RecoveryError::AllocationFailed));
        assert!(tree.nodes.is_empty());
        tree.insert_absent(7, state(), size).unwrap();
        assert_eq!(tree.nodes.capacity(), 1);
        assert_eq!(tree.insert_absent(3, state(), 3 * size - 1), Err(RecoveryError::AllocationFailed));
        assert_eq!(tree.nodes.len(), 1);
        assert_eq!(tree.nodes.capacity(), 1);
        assert!(tree.get_mut(&7).is_some());
        assert!(tree.get_mut(&3).is_none());
        tree.insert_absent(3, state(), 3 * size).unwrap();
        assert_eq!(tree.nodes.capacity(), 2);
        assert_eq!(audit(&tree, tree.root, None, None).1, 2);
    }
}
