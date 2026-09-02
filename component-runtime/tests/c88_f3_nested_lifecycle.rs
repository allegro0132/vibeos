#![cfg(feature = "c88-f3-acceptance")]

//! Codec-level allocation and cleanup-model evidence for C8.8-F3.
//!
//! The candidate remains deliberately disconnected from runtime execution in
//! F3. These tests capture its exact payload bytes and allocation requests,
//! then replay that trace through the existing `CanonicalMachine` realloc and
//! cleanup state machine. Direct candidate/runtime lifecycle wiring belongs to
//! the default-off admission work in F4.

use std::{cell::RefCell, rc::Rc};

use vibeos_component_runtime::{
    abi_value::float_candidate::{
        lower_results_into_prepared, lower_value, CodecError, LoweringJournal, PayloadAllocator,
    },
    canonical::{AbiBudget, CallGate, CanonicalMachine, EntryState, ReallocRequest, Reallocator},
    memory::{AbiError, Allocation, GuestMemory, VecMemory},
    value::{CanonicalF32, CanonicalF64, CanonicalValue, ValuePosition, ValueType},
};

#[derive(Default)]
struct CandidateAllocator {
    next: u32,
    requests: Vec<(u32, u32, u32)>,
    forced_pointer: Option<u32>,
}

impl CandidateAllocator {
    fn at(next: u32) -> Self {
        Self {
            next,
            ..Self::default()
        }
    }
}

impl PayloadAllocator<VecMemory> for CandidateAllocator {
    fn allocate(
        &mut self,
        memory: &mut VecMemory,
        size: u32,
        alignment: u32,
    ) -> Result<u32, CodecError> {
        let pointer = if let Some(pointer) = self.forced_pointer {
            pointer
        } else {
            let mask = alignment.checked_sub(1).ok_or(CodecError::Misaligned)?;
            self.next.checked_add(mask).ok_or(CodecError::Overflow)? & !mask
        };
        let end = pointer.checked_add(size).ok_or(CodecError::Overflow)?;
        if u64::from(end) > memory.len() {
            memory.grow_to(end as usize).map_err(CodecError::from)?;
        }
        self.next = end.max(pointer.saturating_add(1));
        self.requests.push((size, alignment, pointer));
        Ok(pointer)
    }
}

#[derive(Default)]
struct LifecycleStats {
    reallocs: Vec<(ReallocRequest, u32)>,
    frees: Vec<Allocation>,
    discards: u32,
    fail_realloc_at: Option<usize>,
    fail_free_at: Option<usize>,
}

struct LifecycleAllocator {
    next: u32,
    stats: Rc<RefCell<LifecycleStats>>,
}

impl Reallocator<VecMemory> for LifecycleAllocator {
    fn realloc(
        &mut self,
        memory: &mut VecMemory,
        gate: &CallGate,
        request: ReallocRequest,
        _budget: &mut AbiBudget,
    ) -> Result<u32, AbiError> {
        assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
        let call = self.stats.borrow().reallocs.len() + 1;
        if self.stats.borrow().fail_realloc_at == Some(call) {
            return Err(AbiError::BadRealloc);
        }
        let mask = request
            .alignment
            .checked_sub(1)
            .ok_or(AbiError::Misaligned)?;
        let pointer = self.next.checked_add(mask).ok_or(AbiError::Overflow)? & !mask;
        let end = pointer
            .checked_add(request.new_size)
            .ok_or(AbiError::Overflow)?;
        memory.grow_to(end as usize)?;
        self.next = end.max(pointer.saturating_add(1));
        self.stats.borrow_mut().reallocs.push((request, pointer));
        Ok(pointer)
    }

    fn free(
        &mut self,
        _memory: &mut VecMemory,
        gate: &CallGate,
        allocation: Allocation,
        _budget: &mut AbiBudget,
    ) -> Result<(), AbiError> {
        assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
        let mut stats = self.stats.borrow_mut();
        stats.frees.push(allocation);
        if stats.fail_free_at == Some(stats.frees.len()) {
            Err(AbiError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    fn discard_arena(&mut self, _memory: &mut VecMemory, gate: &CallGate) {
        assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
        self.stats.borrow_mut().discards += 1;
    }
}

fn f32v(bits: u32) -> CanonicalValue {
    CanonicalValue::F32(CanonicalF32::from_bits(bits))
}

fn f64v(bits: u64) -> CanonicalValue {
    CanonicalValue::F64(CanonicalF64::from_bits(bits))
}

fn nested_fixture() -> (ValueType, CanonicalValue) {
    let record = ValueType::Record(vec![ValueType::F64, ValueType::F32]);
    (
        ValueType::Record(vec![
            ValueType::List(Box::new(ValueType::F32)),
            ValueType::List(Box::new(record)),
            ValueType::Result {
                ok: Some(Box::new(ValueType::F64)),
                error: Some(Box::new(ValueType::F32)),
            },
        ]),
        CanonicalValue::Record(vec![
            CanonicalValue::List(vec![
                f32v(0xff80_0001),
                f32v(0x8000_0000),
                f32v(0x7f80_0000),
            ]),
            CanonicalValue::List(vec![
                CanonicalValue::Record(vec![f64v(0xfff0_0000_0000_0001), f32v(1)]),
                CanonicalValue::Record(vec![f64v(0x8000_0000_0000_0000), f32v(0x7fff_ffff)]),
            ]),
            CanonicalValue::Result(Ok(Some(Box::new(f64v(0x7ff0_0000_0000_0001))))),
        ]),
    )
}

fn candidate_payloads() -> (VecMemory, Vec<(u32, u32, u32)>) {
    let (ty, value) = nested_fixture();
    let mut memory = VecMemory::new(256, 128 * 1024).unwrap();
    let mut allocator = CandidateAllocator::at(4096);
    let usage = lower_value(
        &mut memory,
        &mut allocator,
        &ty,
        &value,
        64,
        ValuePosition::Result,
    )
    .unwrap();
    assert_eq!(usage.allocations, 2);
    assert_eq!(allocator.requests, vec![(12, 4, 4096), (32, 8, 4112)]);

    let mut f32_nan = [0; 4];
    memory.read_exact(4096, &mut f32_nan).unwrap();
    assert_eq!(u32::from_le_bytes(f32_nan), 0x7fc0_0000);
    let mut f64_nan = [0; 8];
    memory.read_exact(4112, &mut f64_nan).unwrap();
    assert_eq!(u64::from_le_bytes(f64_nan), 0x7ff8_0000_0000_0000);

    (memory, allocator.requests)
}

fn build_machine(
    stats: Rc<RefCell<LifecycleStats>>,
) -> CanonicalMachine<VecMemory, LifecycleAllocator> {
    CanonicalMachine::new(
        VecMemory::new(8, 128 * 1024).unwrap(),
        LifecycleAllocator { next: 128, stats },
        1_000_000,
    )
    .unwrap()
}

fn replay_payloads(
    machine: &mut CanonicalMachine<VecMemory, LifecycleAllocator>,
    source: &VecMemory,
    requests: &[(u32, u32, u32)],
) -> Vec<Allocation> {
    let mut allocations = Vec::new();
    for &(size, alignment, source_pointer) in requests {
        let mut bytes = vec![0; size as usize];
        source.read_exact(source_pointer, &mut bytes).unwrap();
        let pointer = machine.lower_bytes(&bytes, alignment).unwrap();
        let mut copied = vec![0; size as usize];
        machine.memory().read_exact(pointer, &mut copied).unwrap();
        assert_eq!(copied, bytes);
        allocations.push(Allocation {
            pointer,
            size,
            alignment,
        });
    }
    allocations
}

#[test]
fn nested_float_payload_trace_replays_through_existing_cleanup_once() {
    let (source, requests) = candidate_payloads();
    let stats = Rc::new(RefCell::new(LifecycleStats::default()));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    let allocations = replay_payloads(&mut machine, &source, &requests);
    assert_eq!(
        stats
            .borrow()
            .reallocs
            .iter()
            .map(|(request, _)| (request.new_size, request.alignment))
            .collect::<Vec<_>>(),
        vec![(12, 4), (32, 8)]
    );
    machine
        .finish_success(|_, gate, _| {
            assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
            Ok(())
        })
        .unwrap();
    assert_eq!(machine.state(), EntryState::Idle);
    assert_eq!(
        stats.borrow().frees,
        allocations.into_iter().rev().collect::<Vec<_>>()
    );
    assert_eq!(stats.borrow().discards, 0);

    machine.begin_call().unwrap();
    let aborted = replay_payloads(&mut machine, &source, &requests);
    machine.abort().unwrap();
    assert_eq!(machine.state(), EntryState::Idle);
    assert_eq!(
        &stats.borrow().frees[2..],
        aborted.into_iter().rev().collect::<Vec<_>>().as_slice()
    );
    assert_eq!(stats.borrow().discards, 0);
}

#[test]
fn candidate_journal_reserves_before_guest_allocation_and_rejects_aliases() {
    let mut flat_memory = VecMemory::new(256, 128 * 1024).unwrap();
    flat_memory.write_exact(64, &[0xa5; 8]).unwrap();
    let mut flat_allocator = CandidateAllocator::at(4096);
    let mut flat_journal = LoweringJournal::try_with_capacity(1).unwrap();
    assert_eq!(
        lower_results_into_prepared(
            &mut flat_memory,
            &mut flat_allocator,
            &[ValueType::F32],
            &[f32v(1)],
            64,
            &mut flat_journal,
        ),
        Err(CodecError::FlatLimit)
    );
    assert!(flat_allocator.requests.is_empty());
    let mut sentinel = [0; 8];
    flat_memory.read_exact(64, &mut sentinel).unwrap();
    assert_eq!(sentinel, [0xa5; 8]);

    let (ty, value) = nested_fixture();
    let mut memory = VecMemory::new(256, 128 * 1024).unwrap();
    let mut allocator = CandidateAllocator::at(4096);
    let mut one_slot = LoweringJournal::try_with_capacity(1).unwrap();
    assert_eq!(
        lower_results_into_prepared(
            &mut memory,
            &mut allocator,
            &[ty],
            &[value],
            64,
            &mut one_slot,
        ),
        Err(CodecError::AllocationLimit)
    );
    assert_eq!(allocator.requests.len(), 1);

    let mut hostile = CandidateAllocator {
        forced_pointer: Some(64),
        ..CandidateAllocator::at(4096)
    };
    let mut hostile_memory = VecMemory::new(256, 128 * 1024).unwrap();
    let (ty, value) = nested_fixture();
    let mut two_slots = LoweringJournal::try_with_capacity(2).unwrap();
    assert_eq!(
        lower_results_into_prepared(
            &mut hostile_memory,
            &mut hostile,
            &[ty],
            &[value],
            64,
            &mut two_slots,
        ),
        Err(CodecError::Allocation)
    );
    assert_eq!(hostile.requests, vec![(12, 4, 64)]);
}

#[test]
fn uncertain_realloc_and_cleanup_failures_discard_exactly_once() {
    let (source, requests) = candidate_payloads();
    let stats = Rc::new(RefCell::new(LifecycleStats {
        fail_realloc_at: Some(2),
        ..LifecycleStats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    let first = &requests[0];
    let mut bytes = vec![0; first.0 as usize];
    source.read_exact(first.2, &mut bytes).unwrap();
    machine.lower_bytes(&bytes, first.1).unwrap();
    let second = &requests[1];
    bytes.resize(second.0 as usize, 0);
    source.read_exact(second.2, &mut bytes).unwrap();
    assert_eq!(
        machine.lower_bytes(&bytes, second.1),
        Err(AbiError::BadRealloc)
    );
    assert_eq!(machine.state(), EntryState::Poisoned);
    assert_eq!(stats.borrow().frees.len(), 0);
    assert_eq!(stats.borrow().discards, 1);
    assert_eq!(machine.abort(), Err(AbiError::Poisoned));
    assert_eq!(stats.borrow().discards, 1);

    let stats = Rc::new(RefCell::new(LifecycleStats {
        fail_free_at: Some(1),
        ..LifecycleStats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    replay_payloads(&mut machine, &source, &requests);
    assert_eq!(
        machine.finish_success(|_, _, _| Ok(())),
        Err(AbiError::CleanupFailed)
    );
    assert_eq!(machine.state(), EntryState::Poisoned);
    assert_eq!(stats.borrow().frees.len(), 1);
    assert_eq!(stats.borrow().discards, 1);
    assert_eq!(machine.abort(), Err(AbiError::Poisoned));
    assert_eq!(stats.borrow().discards, 1);
}
