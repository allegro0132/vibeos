//! Requested-capacity accounting, excluding allocator bookkeeping and stack.
use crate::RecoveryError;

#[derive(Clone, Debug)]
pub(crate) struct ReplayBudget {
    limit: usize,
    used: usize,
    peak: usize,
}
impl ReplayBudget {
    pub(crate) fn new(limit: usize) -> Self { Self { limit, used: 0, peak: 0 } }
    // A replay clone may have smaller Vec capacities than its source. Restore
    // accounting from actual retained capacities before the next operation.
    pub(crate) fn sync_retained(&mut self, bytes: usize) -> Result<(), RecoveryError> {
        if bytes > self.limit { return Err(RecoveryError::AllocationFailed); }
        self.used = bytes;
        self.peak = self.peak.max(bytes);
        Ok(())
    }
    pub(crate) fn remaining(&self) -> usize { self.limit - self.used }
    pub(crate) fn charge(&mut self, bytes: usize) -> Result<(), RecoveryError> {
        let used = self.used.checked_add(bytes).ok_or(RecoveryError::AllocationFailed)?;
        if used > self.limit { return Err(RecoveryError::AllocationFailed); }
        self.used = used;
        self.peak = self.peak.max(used);
        Ok(())
    }
    pub(crate) fn release(&mut self, bytes: usize) {
        self.used = self.used.checked_sub(bytes).expect("release charged replay storage");
    }
    pub(crate) fn used(&self) -> usize { self.used }
    pub(crate) fn peak(&self) -> usize { self.peak }
}

// The old vector is already charged. Reserve a replacement before releasing
// that charge; growth can be smaller than preferred when approaching the cap.
pub(crate) fn reserve_vec<T>(values: &mut alloc::vec::Vec<T>, additional: usize,
    budget: &mut ReplayBudget) -> Result<(), RecoveryError> {
    let required = values.len().checked_add(additional).ok_or(RecoveryError::AllocationFailed)?;
    if required <= values.capacity() { return Ok(()); }
    let size = core::mem::size_of::<T>();
    if size == 0 { return Ok(()); }
    let minimum = if size == 1 { 8 } else if size <= 1024 { 4 } else { 1 };
    let desired = values.capacity().checked_mul(2).ok_or(RecoveryError::AllocationFailed)?
        .max(required).max(minimum);
    let admitted = desired.min(budget.remaining() / size);
    if admitted < required { return Err(RecoveryError::AllocationFailed); }
    let old = values.capacity().checked_mul(size).ok_or(RecoveryError::AllocationFailed)?;
    let reserved = admitted.checked_mul(size).ok_or(RecoveryError::AllocationFailed)?;
    budget.charge(reserved)?;
    if values.try_reserve_exact(admitted - values.len()).is_err() {
        budget.release(reserved);
        return Err(RecoveryError::AllocationFailed);
    }
    let actual = values.capacity().checked_mul(size).ok_or(RecoveryError::AllocationFailed)?;
    if actual > reserved { budget.charge(actual - reserved)?; }
    budget.release(old);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vector_growth_counts_other_buffers_and_old_capacity() {
        for limit in [24, 25] {
            let mut budget = ReplayBudget::new(limit);
            let mut first = alloc::vec::Vec::<u8>::new();
            let mut second = alloc::vec::Vec::<u8>::new();
            reserve_vec(&mut first, 8, &mut budget).unwrap();
            first.extend_from_slice(&[7; 8]);
            reserve_vec(&mut second, 8, &mut budget).unwrap();
            assert_eq!(budget.used(), 16);
            let result = reserve_vec(&mut first, 1, &mut budget);
            if limit == 24 {
                assert_eq!(result, Err(RecoveryError::AllocationFailed));
                assert_eq!(budget.used(), 16);
            } else {
                result.unwrap();
                assert_eq!(budget.used(), 17);
                assert_eq!(budget.peak(), 25);
            }
            assert_eq!(first.as_slice(), &[7; 8]);
            budget.release(first.capacity() + second.capacity());
            drop((first, second));
            assert_eq!(budget.used(), 0);
        }
    }
}
