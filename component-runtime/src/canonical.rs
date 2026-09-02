//! Synchronous Canonical ABI call state, realloc, and cleanup rules.

use crate::memory::{
    checked_span, lift_u32_list, lift_utf8, lower_u32_list, AbiError, Allocation,
    AllocationJournal, GuestMemory,
};
use core::cell::Cell;
use vibeos_component_format::PROFILE_1_LIMITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Idle,
    Calling,
    Realloc,
    PostReturn,
    Poisoned,
}

#[derive(Debug)]
pub struct CallGate {
    state: Cell<EntryState>,
}

impl CallGate {
    fn new() -> Self {
        Self {
            state: Cell::new(EntryState::Idle),
        }
    }

    pub fn state(&self) -> EntryState {
        self.state.get()
    }

    /// Host imports are callable only while ordinary guest code is running.
    /// Realloc, post-return, and cleanup therefore cannot re-enter the host.
    pub fn host_entry_probe(&self) -> Result<(), AbiError> {
        match self.state.get() {
            EntryState::Calling => Ok(()),
            EntryState::Poisoned => Err(AbiError::Poisoned),
            EntryState::Idle | EntryState::Realloc | EntryState::PostReturn => {
                Err(AbiError::Reentry)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReallocRequest {
    pub old_pointer: u32,
    pub old_size: u32,
    pub alignment: u32,
    pub new_size: u32,
}

pub trait Reallocator<M: GuestMemory> {
    /// Runs guest `cabi_realloc` under the supplied invocation budget.
    ///
    /// Implementations backed by a Core engine must configure that engine from
    /// `budget.remaining()` and charge the exact consumed fuel before returning.
    /// An error is treated as having potentially mutated the guest allocator;
    /// the whole arena is discarded rather than attempting pointer cleanup.
    fn realloc(
        &mut self,
        memory: &mut M,
        gate: &CallGate,
        request: ReallocRequest,
        budget: &mut AbiBudget,
    ) -> Result<u32, AbiError>;

    /// Frees one previously validated, non-overlapping allocation under the
    /// supplied invocation budget.
    fn free(
        &mut self,
        memory: &mut M,
        gate: &CallGate,
        allocation: Allocation,
        budget: &mut AbiBudget,
    ) -> Result<(), AbiError>;

    /// Infallibly abandons all allocator state owned by this machine.
    ///
    /// This is a trusted host-side arena operation, never a guest callback. It
    /// is used after an uncertain realloc result, a guest trap, or failed
    /// cleanup. Implementations must not call guest code from this method.
    fn discard_arena(&mut self, memory: &mut M, gate: &CallGate);
}

pub const REALLOC_BASE_WORK: u64 = 12;
pub const FREE_BASE_WORK: u64 = 1;
pub const POST_RETURN_BASE_WORK: u64 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct AbiBudget {
    remaining_work: u64,
    allocations: u32,
}

impl AbiBudget {
    pub fn new(work: u64) -> Result<Self, AbiError> {
        if work == 0 || work > PROFILE_1_LIMITS.total_fuel {
            return Err(AbiError::WorkBudget);
        }
        Ok(Self {
            remaining_work: work,
            allocations: 0,
        })
    }

    pub fn charge(&mut self, work: u64) -> Result<(), AbiError> {
        if work > self.remaining_work {
            return Err(AbiError::WorkBudget);
        }
        self.remaining_work -= work;
        Ok(())
    }

    fn charge_allocation(&mut self) -> Result<(), AbiError> {
        let next = self
            .allocations
            .checked_add(1)
            .ok_or(AbiError::AllocationLimit)?;
        if next > PROFILE_1_LIMITS.max_abi_allocations {
            return Err(AbiError::AllocationLimit);
        }
        self.allocations = next;
        Ok(())
    }

    pub const fn remaining(&self) -> u64 {
        self.remaining_work
    }

    fn reset(&mut self, work: u64) {
        self.remaining_work = work;
        self.allocations = 0;
    }
}

pub struct CanonicalMachine<M: GuestMemory, R: Reallocator<M>> {
    memory: M,
    reallocator: R,
    gate: CallGate,
    journal: AllocationJournal,
    budget: AbiBudget,
    work_per_call: u64,
    arena_discarded: bool,
}

impl<M: GuestMemory, R: Reallocator<M>> CanonicalMachine<M, R> {
    pub fn new(memory: M, reallocator: R, work: u64) -> Result<Self, AbiError> {
        Ok(Self {
            memory,
            reallocator,
            gate: CallGate::new(),
            journal: AllocationJournal::default(),
            budget: AbiBudget::new(work)?,
            work_per_call: work,
            arena_discarded: false,
        })
    }

    /// Begins one independent synchronous invocation.
    ///
    /// ABI work and allocation counts are reset to the constructor's per-call
    /// allowance only after the previous call reached `Idle` with no live
    /// allocations. A poisoned machine is never reusable.
    pub fn begin_call(&mut self) -> Result<(), AbiError> {
        match self.gate.state.get() {
            EntryState::Idle if self.journal.is_empty() => {
                self.budget.reset(self.work_per_call);
                self.gate.state.set(EntryState::Calling);
                Ok(())
            }
            EntryState::Poisoned => Err(AbiError::Poisoned),
            _ => Err(AbiError::Reentry),
        }
    }

    pub fn state(&self) -> EntryState {
        self.gate.state()
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn reallocator(&self) -> &R {
        &self.reallocator
    }

    pub fn remaining_work(&self) -> u64 {
        self.budget.remaining()
    }

    fn allocate_region(&mut self, size: usize, alignment: u32) -> Result<u32, AbiError> {
        self.gate.host_entry_probe()?;
        if size > PROFILE_1_LIMITS.max_canonical_value_bytes {
            return self.fail(AbiError::LengthLimit);
        }
        if alignment == 0 || !alignment.is_power_of_two() || alignment > 8 {
            return self.fail(AbiError::Misaligned);
        }
        if size == 0 {
            self.budget.charge(1).or_else(|error| self.fail(error))?;
            return Ok(0);
        }
        if let Err(error) = self.journal.reserve_one() {
            return self.fail(error);
        }
        if let Err(error) = self.budget.charge_allocation() {
            return self.fail(error);
        }
        let work = u64::try_from(size)
            .map_err(|_| AbiError::LengthLimit)?
            .checked_add(REALLOC_BASE_WORK)
            .ok_or(AbiError::WorkBudget)?;
        if let Err(error) = self.budget.charge(work) {
            return self.fail(error);
        }
        let new_size = match u32::try_from(size) {
            Ok(size) => size,
            Err(_) => return self.fail(AbiError::LengthLimit),
        };
        self.gate.state.set(EntryState::Realloc);
        let request = ReallocRequest {
            old_pointer: 0,
            old_size: 0,
            alignment,
            new_size,
        };
        let pointer =
            match self
                .reallocator
                .realloc(&mut self.memory, &self.gate, request, &mut self.budget)
            {
                Ok(pointer) => pointer,
                Err(error) => return self.discard_and_poison(error),
            };
        self.gate.state.set(EntryState::Calling);
        let allocation = Allocation {
            pointer,
            size: new_size,
            alignment,
        };
        if pointer == 0 {
            return self.discard_and_poison(AbiError::BadRealloc);
        }
        if checked_span(
            pointer,
            size as u64,
            1,
            alignment,
            self.memory.len(),
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        )
        .is_err()
        {
            return self.discard_and_poison(AbiError::BadRealloc);
        }
        if self.journal.overlaps(allocation) {
            return self.discard_and_poison(AbiError::BadRealloc);
        }
        if self.journal.record_reserved(allocation).is_err() {
            return self.discard_and_poison(AbiError::CleanupLimit);
        }
        Ok(pointer)
    }

    pub fn lower_bytes(&mut self, bytes: &[u8], alignment: u32) -> Result<u32, AbiError> {
        let pointer = self.allocate_region(bytes.len(), alignment)?;
        if !bytes.is_empty() {
            if let Err(error) = self.memory.write_exact(pointer, bytes) {
                return self.fail(error);
            }
        }
        Ok(pointer)
    }

    pub fn lower_utf8(&mut self, value: &str) -> Result<(u32, u32), AbiError> {
        if value.len() > PROFILE_1_LIMITS.max_string_bytes {
            return self.fail_if_calling(AbiError::LengthLimit);
        }
        let pointer = self.lower_bytes(value.as_bytes(), 1)?;
        Ok((pointer, value.len() as u32))
    }

    pub fn lower_u32_list(&mut self, values: &[u32]) -> Result<(u32, u32), AbiError> {
        if values.len() > PROFILE_1_LIMITS.max_list_elements as usize {
            return self.fail_if_calling(AbiError::ElementLimit);
        }
        let bytes = match values.len().checked_mul(4) {
            Some(bytes) => bytes,
            None => return self.fail_if_calling(AbiError::Overflow),
        };
        let pointer = self.allocate_region(bytes, 4)?;
        if let Err(error) = lower_u32_list(&mut self.memory, pointer, values) {
            return self.fail(error);
        }
        Ok((pointer, values.len() as u32))
    }

    pub fn lift_utf8(
        &mut self,
        pointer: u32,
        length: u32,
    ) -> Result<alloc::string::String, AbiError> {
        self.gate.host_entry_probe()?;
        if length as usize > PROFILE_1_LIMITS.max_string_bytes
            || length as usize > PROFILE_1_LIMITS.max_canonical_value_bytes
        {
            return self.fail(AbiError::LengthLimit);
        }
        if let Err(error) = checked_span(
            pointer,
            u64::from(length),
            1,
            1,
            self.memory.len(),
            PROFILE_1_LIMITS.max_string_bytes as u64,
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        ) {
            return self.fail(error);
        }
        if let Err(error) = self.budget.charge(u64::from(length) + 2) {
            return self.fail(error);
        }
        match lift_utf8(&self.memory, pointer, length) {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }

    pub fn lift_u32_list(
        &mut self,
        pointer: u32,
        length: u32,
    ) -> Result<alloc::vec::Vec<u32>, AbiError> {
        self.gate.host_entry_probe()?;
        if length > PROFILE_1_LIMITS.max_list_elements {
            return self.fail(AbiError::ElementLimit);
        }
        if let Err(error) = checked_span(
            pointer,
            u64::from(length),
            4,
            4,
            self.memory.len(),
            PROFILE_1_LIMITS.max_list_elements as u64,
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        ) {
            return self.fail(error);
        }
        let work = u64::from(length)
            .checked_mul(4)
            .and_then(|work| work.checked_add(2))
            .ok_or(AbiError::WorkBudget)?;
        if let Err(error) = self.budget.charge(work) {
            return self.fail(error);
        }
        match lift_u32_list(&self.memory, pointer, length) {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }

    /// Runs canonical post-return and then releases host-lowered allocations.
    /// A Core-backed callback must set its engine fuel from the supplied
    /// budget and charge the exact fuel consumed before it returns.
    pub fn finish_success(
        &mut self,
        post_return: impl FnOnce(&mut M, &CallGate, &mut AbiBudget) -> Result<(), AbiError>,
    ) -> Result<(), AbiError> {
        self.gate.host_entry_probe()?;
        if let Err(error) = self.budget.charge(POST_RETURN_BASE_WORK) {
            return self.fail(error);
        }
        self.gate.state.set(EntryState::PostReturn);
        let post_result = post_return(&mut self.memory, &self.gate, &mut self.budget);
        if let Err(error) = post_result {
            return self.discard_and_poison(error);
        }
        let cleanup_failed = self.cleanup_allocations(EntryState::Idle);
        if cleanup_failed {
            Err(AbiError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    /// Tears down a live call.
    ///
    /// Each validated allocation is passed to `free` at most once. If a free
    /// traps or exhausts its budget, no further guest cleanup runs and the
    /// trusted host discards the entire arena exactly once.
    pub fn abort(&mut self) -> Result<(), AbiError> {
        match self.gate.state.get() {
            EntryState::Calling => {
                if self.cleanup_allocations(EntryState::Idle) {
                    Err(AbiError::CleanupFailed)
                } else {
                    Ok(())
                }
            }
            EntryState::Realloc | EntryState::PostReturn => {
                self.discard_and_poison(AbiError::CleanupFailed)
            }
            EntryState::Poisoned => Err(AbiError::Poisoned),
            EntryState::Idle => Err(AbiError::Reentry),
        }
    }

    fn fail_if_calling<T>(&mut self, error: AbiError) -> Result<T, AbiError> {
        self.gate.host_entry_probe()?;
        self.fail(error)
    }

    fn fail<T>(&mut self, error: AbiError) -> Result<T, AbiError> {
        let cleanup_failed = self.cleanup_allocations(EntryState::Poisoned);
        Err(if cleanup_failed {
            AbiError::CleanupFailed
        } else {
            error
        })
    }

    fn cleanup_allocations(&mut self, final_state: EntryState) -> bool {
        self.gate.state.set(EntryState::PostReturn);
        let mut failed = false;
        while let Some(allocation) = self.journal.pop() {
            if self.budget.charge(FREE_BASE_WORK).is_err() {
                failed = true;
                break;
            }
            if self
                .reallocator
                .free(&mut self.memory, &self.gate, allocation, &mut self.budget)
                .is_err()
            {
                failed = true;
                break;
            }
        }
        if failed {
            self.discard_owned_arena();
            self.gate.state.set(EntryState::Poisoned);
        } else {
            self.gate.state.set(final_state);
        }
        failed
    }

    fn discard_and_poison<T>(&mut self, error: AbiError) -> Result<T, AbiError> {
        self.discard_owned_arena();
        self.gate.state.set(EntryState::Poisoned);
        Err(error)
    }

    fn discard_owned_arena(&mut self) {
        self.journal.clear();
        if !self.arena_discarded {
            // Mark first so an unexpected teardown panic cannot make Drop
            // attempt the same arena operation a second time.
            self.arena_discarded = true;
            self.gate.state.set(EntryState::PostReturn);
            self.reallocator.discard_arena(&mut self.memory, &self.gate);
        }
    }
}

impl<M: GuestMemory, R: Reallocator<M>> Drop for CanonicalMachine<M, R> {
    fn drop(&mut self) {
        // Never enter guest cleanup from Drop: unwinding through guest code can
        // otherwise double-panic. The trusted owner arena is safe to discard.
        if !self.arena_discarded
            && (!self.journal.is_empty() || self.gate.state.get() != EntryState::Idle)
        {
            self.discard_owned_arena();
            self.gate.state.set(EntryState::Poisoned);
        }
    }
}
