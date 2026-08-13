use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use vibeos_component_format::PROFILE_1_LIMITS;
use vibeos_component_runtime::{
    canonical::{
        AbiBudget, CallGate, CanonicalMachine, EntryState, ReallocRequest, Reallocator,
        FREE_BASE_WORK, POST_RETURN_BASE_WORK, REALLOC_BASE_WORK,
    },
    memory::{
        checked_span, lift_bool, lift_char, lift_discriminant, lift_s64, lift_u16, lower_s64,
        lower_u16, AbiError, Allocation, GuestMemory, VecMemory,
    },
};

#[derive(Default)]
struct Stats {
    realloc_calls: u32,
    free_calls: u32,
    discard_calls: u32,
    fail_realloc_at: Option<u32>,
    mutate_before_realloc_failure: bool,
    panic_realloc_at: Option<u32>,
    panic_free_at: Option<u32>,
    panic_discard: bool,
    fail_free: bool,
    realloc_work: u64,
    free_work: u64,
    force_pointer_at: Option<(u32, u32)>,
    skip_grow_at: Option<u32>,
    cleanup_reentry: Vec<Result<(), AbiError>>,
    discard_reentry: Vec<Result<(), AbiError>>,
}

struct TestReallocator {
    next: u32,
    stats: Rc<RefCell<Stats>>,
}

impl Reallocator<VecMemory> for TestReallocator {
    fn realloc(
        &mut self,
        memory: &mut VecMemory,
        gate: &CallGate,
        request: ReallocRequest,
        budget: &mut AbiBudget,
    ) -> Result<u32, AbiError> {
        let mut stats = self.stats.borrow_mut();
        stats.realloc_calls += 1;
        let call = stats.realloc_calls;
        if stats.panic_realloc_at == Some(call) {
            panic!("simulated guest engine panic");
        }
        if stats.fail_realloc_at == Some(call) {
            let mutate = stats.mutate_before_realloc_failure;
            drop(stats);
            if mutate {
                let grown = memory.len().checked_add(1).ok_or(AbiError::Overflow)?;
                memory.grow_to(usize::try_from(grown).map_err(|_| AbiError::Overflow)?)?;
            }
            return Err(AbiError::BadRealloc);
        }
        let forced_pointer = stats
            .force_pointer_at
            .and_then(|(at, pointer)| (at == call).then_some(pointer));
        let skip_grow = stats.skip_grow_at == Some(call);
        let work = stats.realloc_work;
        drop(stats);
        assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
        budget.charge(work)?;
        let mask = request.alignment - 1;
        let pointer = match forced_pointer {
            Some(pointer) => pointer,
            None => self.next.checked_add(mask).ok_or(AbiError::Overflow)? & !mask,
        };
        let end = pointer
            .checked_add(request.new_size)
            .ok_or(AbiError::Overflow)?;
        if !skip_grow {
            memory.grow_to(end as usize)?;
        }
        if forced_pointer.is_none() {
            self.next = end.max(pointer + 1);
        }
        Ok(pointer)
    }

    fn free(
        &mut self,
        _memory: &mut VecMemory,
        gate: &CallGate,
        _allocation: Allocation,
        budget: &mut AbiBudget,
    ) -> Result<(), AbiError> {
        let mut stats = self.stats.borrow_mut();
        stats.free_calls += 1;
        if stats.panic_free_at == Some(stats.free_calls) {
            panic!("simulated guest free panic");
        }
        stats.cleanup_reentry.push(gate.host_entry_probe());
        let work = stats.free_work;
        let fail = stats.fail_free;
        drop(stats);
        budget.charge(work)?;
        if fail {
            Err(AbiError::CleanupFailed)
        } else {
            Ok(())
        }
    }

    fn discard_arena(&mut self, _memory: &mut VecMemory, gate: &CallGate) {
        let mut stats = self.stats.borrow_mut();
        stats.discard_calls += 1;
        stats.discard_reentry.push(gate.host_entry_probe());
        if stats.panic_discard {
            panic!("simulated trusted arena teardown panic");
        }
    }
}

fn build_machine(stats: Rc<RefCell<Stats>>) -> CanonicalMachine<VecMemory, TestReallocator> {
    CanonicalMachine::new(
        VecMemory::new(8, 4 * 65_536).unwrap(),
        TestReallocator { next: 8, stats },
        1_000_000,
    )
    .unwrap()
}

#[test]
fn scalar_memory_is_little_endian_aligned_and_checked() {
    let mut memory = VecMemory::new(32, 64).unwrap();
    lower_u16(&mut memory, 2, 0x1234).unwrap();
    lower_s64(&mut memory, 8, -9).unwrap();
    assert_eq!(lift_u16(&memory, 2), Ok(0x1234));
    assert_eq!(lift_s64(&memory, 8), Ok(-9));
    assert_eq!(lift_u16(&memory, 1), Err(AbiError::Misaligned));
    assert_eq!(lift_bool(2), Err(AbiError::InvalidBool));
    assert_eq!(lift_char(0xd800), Err(AbiError::InvalidChar));
    assert_eq!(lift_discriminant(3, 3), Err(AbiError::InvalidDiscriminant));
    assert_eq!(memory.grow_to(16), Err(AbiError::NonMonotonicGrowth));
    assert_eq!(memory.len(), 32);
}

#[test]
fn span_checks_elements_and_total_bytes_independently() {
    assert_eq!(
        checked_span(
            0,
            PROFILE_1_LIMITS.max_list_elements as u64,
            24,
            8,
            1_000_000,
            PROFILE_1_LIMITS.max_list_elements as u64,
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        ),
        Err(AbiError::LengthLimit)
    );
    assert_eq!(
        checked_span(4, 1, 4, 8, 16, 1, 4),
        Err(AbiError::Misaligned)
    );
    assert_eq!(
        checked_span(u32::MAX, 2, 4, 1, u64::MAX, 2, 8),
        Err(AbiError::OutOfBounds)
    );
    assert_eq!(
        checked_span(u32::MAX, 1, 1, 1, u64::MAX, 1, 1),
        Ok(u32::MAX as usize..u32::MAX as usize + 1)
    );
    assert_eq!(checked_span(8, 4, 0, 1, 8, 4, 0), Ok(8..8));
}

#[test]
fn successful_call_round_trips_and_cleans_each_allocation_once() {
    let stats = Rc::new(RefCell::new(Stats::default()));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    let (text_pointer, text_length) = machine.lower_utf8("hello").unwrap();
    assert_eq!(
        machine.lift_utf8(text_pointer, text_length).unwrap(),
        "hello"
    );
    let (list_pointer, list_length) = machine.lower_u32_list(&[1, 2, 3]).unwrap();
    assert_eq!(
        machine.lift_u32_list(list_pointer, list_length).unwrap(),
        vec![1, 2, 3]
    );
    let post_called = Cell::new(false);
    machine
        .finish_success(|_, gate, budget| {
            post_called.set(true);
            assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
            budget.charge(3)?;
            Ok(())
        })
        .unwrap();
    assert!(post_called.get());
    assert_eq!(machine.state(), EntryState::Idle);
    assert_eq!(stats.borrow().realloc_calls, 2);
    assert_eq!(stats.borrow().free_calls, 2);
    assert!(stats
        .borrow()
        .cleanup_reentry
        .iter()
        .all(|result| *result == Err(AbiError::Reentry)));
}

#[test]
fn realloc_and_post_return_failures_still_clean_prior_allocations() {
    let stats = Rc::new(RefCell::new(Stats {
        fail_realloc_at: Some(2),
        ..Stats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    machine.lower_utf8("first").unwrap();
    assert_eq!(machine.lower_utf8("second"), Err(AbiError::BadRealloc));
    assert_eq!(machine.state(), EntryState::Poisoned);
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);
    assert_eq!(machine.abort(), Err(AbiError::Poisoned));
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats::default()));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    machine.lower_utf8("allocated").unwrap();
    assert_eq!(
        machine.finish_success(|_, _, _| Err(AbiError::InvalidDiscriminant)),
        Err(AbiError::InvalidDiscriminant)
    );
    assert_eq!(machine.state(), EntryState::Poisoned);
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);
}

#[test]
fn invalid_alignment_never_calls_guest_realloc() {
    for alignment in [0, 3, 16] {
        let stats = Rc::new(RefCell::new(Stats::default()));
        let mut machine = build_machine(stats.clone());
        machine.begin_call().unwrap();
        assert_eq!(
            machine.lower_bytes(&[1], alignment),
            Err(AbiError::Misaligned)
        );
        assert_eq!(machine.state(), EntryState::Poisoned);
        assert_eq!(stats.borrow().realloc_calls, 0);
        assert_eq!(stats.borrow().free_calls, 0);
    }
}

#[test]
fn cleanup_failure_stops_guest_callbacks_and_discards_once() {
    let stats = Rc::new(RefCell::new(Stats {
        fail_free: true,
        ..Stats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    machine.lower_utf8("one").unwrap();
    machine.lower_utf8("two").unwrap();
    assert_eq!(
        machine.finish_success(|_, _, _| Ok(())),
        Err(AbiError::CleanupFailed)
    );
    assert_eq!(stats.borrow().free_calls, 1);
    assert_eq!(stats.borrow().discard_calls, 1);
    assert_eq!(machine.state(), EntryState::Poisoned);
}

#[test]
fn uncertain_realloc_discards_the_arena_without_freeing_unknown_pointers() {
    let stats = Rc::new(RefCell::new(Stats {
        fail_realloc_at: Some(2),
        mutate_before_realloc_failure: true,
        ..Stats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    machine.lower_utf8("known").unwrap();
    let before = machine.memory().len();
    assert_eq!(machine.lower_utf8("uncertain"), Err(AbiError::BadRealloc));
    assert!(machine.memory().len() > before);
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);
    assert_eq!(stats.borrow().discard_reentry, vec![Err(AbiError::Reentry)]);
}

#[test]
fn bad_and_overlapping_realloc_results_are_never_passed_to_free() {
    let stats = Rc::new(RefCell::new(Stats {
        force_pointer_at: Some((1, 9)),
        ..Stats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    assert_eq!(
        machine.lower_bytes(&[1, 2, 3, 4], 4),
        Err(AbiError::BadRealloc)
    );
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats {
        force_pointer_at: Some((1, 64)),
        skip_grow_at: Some(1),
        ..Stats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    assert_eq!(machine.lower_bytes(&[1], 1), Err(AbiError::BadRealloc));
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats {
        force_pointer_at: Some((2, 8)),
        ..Stats::default()
    }));
    let mut machine = build_machine(stats.clone());
    machine.begin_call().unwrap();
    assert_eq!(machine.lower_bytes(&[1, 2, 3], 1), Ok(8));
    assert_eq!(
        machine.lower_bytes(&[4, 5, 6], 1),
        Err(AbiError::BadRealloc)
    );
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);
}

#[test]
fn guest_callbacks_charge_one_per_call_budget_and_it_resets() {
    let stats = Rc::new(RefCell::new(Stats {
        realloc_work: 7,
        free_work: 5,
        ..Stats::default()
    }));
    let mut machine = CanonicalMachine::new(
        VecMemory::new(8, 65_536).unwrap(),
        TestReallocator {
            next: 8,
            stats: stats.clone(),
        },
        100,
    )
    .unwrap();
    machine.begin_call().unwrap();
    machine.lower_bytes(&[1, 2, 3, 4], 1).unwrap();
    machine
        .finish_success(|_, gate, budget| {
            assert_eq!(gate.host_entry_probe(), Err(AbiError::Reentry));
            budget.charge(3)
        })
        .unwrap();
    assert_eq!(
        machine.remaining_work(),
        100 - 4 - REALLOC_BASE_WORK - 7 - POST_RETURN_BASE_WORK - 3 - FREE_BASE_WORK - 5
    );
    machine.begin_call().unwrap();
    assert_eq!(machine.remaining_work(), 100);
    machine.abort().unwrap();
}

#[test]
fn exhausted_guest_callback_budget_discards_instead_of_running_unbounded() {
    let stats = Rc::new(RefCell::new(Stats {
        realloc_work: 8,
        ..Stats::default()
    }));
    let mut machine = CanonicalMachine::new(
        VecMemory::new(8, 65_536).unwrap(),
        TestReallocator {
            next: 8,
            stats: stats.clone(),
        },
        20,
    )
    .unwrap();
    machine.begin_call().unwrap();
    assert_eq!(machine.lower_bytes(&[1], 1), Err(AbiError::WorkBudget));
    assert_eq!(stats.borrow().realloc_calls, 1);
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats {
        free_work: 2,
        ..Stats::default()
    }));
    let mut machine = CanonicalMachine::new(
        VecMemory::new(8, 65_536).unwrap(),
        TestReallocator {
            next: 8,
            stats: stats.clone(),
        },
        16,
    )
    .unwrap();
    machine.begin_call().unwrap();
    machine.lower_bytes(&[1], 1).unwrap();
    assert_eq!(
        machine.finish_success(|_, _, _| Ok(())),
        Err(AbiError::CleanupFailed)
    );
    assert_eq!(stats.borrow().free_calls, 1);
    assert_eq!(stats.borrow().discard_calls, 1);
}

#[test]
fn hostile_lift_lengths_fail_before_budget_precedence() {
    let stats = Rc::new(RefCell::new(Stats::default()));
    let mut machine = CanonicalMachine::new(
        VecMemory::new(8, 65_536).unwrap(),
        TestReallocator { next: 8, stats },
        1,
    )
    .unwrap();
    machine.begin_call().unwrap();
    assert_eq!(
        machine.lift_utf8(0, PROFILE_1_LIMITS.max_string_bytes as u32 + 1),
        Err(AbiError::LengthLimit)
    );

    let stats = Rc::new(RefCell::new(Stats::default()));
    let mut machine = CanonicalMachine::new(
        VecMemory::new(8, 65_536).unwrap(),
        TestReallocator { next: 8, stats },
        1,
    )
    .unwrap();
    machine.begin_call().unwrap();
    assert_eq!(
        machine.lift_u32_list(0, PROFILE_1_LIMITS.max_list_elements + 1),
        Err(AbiError::ElementLimit)
    );
}

#[test]
fn construction_caps_initial_memory_before_allocation() {
    let over_initial = PROFILE_1_LIMITS.max_initial_memory_pages as usize * 65_536 + 1;
    assert_eq!(
        VecMemory::new(over_initial, over_initial),
        Err(AbiError::LengthLimit)
    );
}

#[test]
fn drop_only_discards_the_host_arena_even_during_unwind() {
    let stats = Rc::new(RefCell::new(Stats::default()));
    {
        let mut machine = build_machine(stats.clone());
        machine.begin_call().unwrap();
        machine.lower_utf8("live").unwrap();
    }
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats {
        panic_realloc_at: Some(1),
        ..Stats::default()
    }));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let stats = stats.clone();
        move || {
            let mut machine = build_machine(stats);
            machine.begin_call().unwrap();
            let _ = machine.lower_utf8("panic");
        }
    }));
    assert!(unwind.is_err());
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats {
        panic_free_at: Some(1),
        ..Stats::default()
    }));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let stats = stats.clone();
        move || {
            let mut machine = build_machine(stats);
            machine.begin_call().unwrap();
            machine.lower_utf8("live").unwrap();
            let _ = machine.finish_success(|_, _, _| Ok(()));
        }
    }));
    assert!(unwind.is_err());
    assert_eq!(stats.borrow().free_calls, 1);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats::default()));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let stats = stats.clone();
        move || {
            let mut machine = build_machine(stats);
            machine.begin_call().unwrap();
            machine.lower_utf8("live").unwrap();
            let _ = machine.finish_success(|_, _, _| panic!("post-return panic"));
        }
    }));
    assert!(unwind.is_err());
    assert_eq!(stats.borrow().free_calls, 0);
    assert_eq!(stats.borrow().discard_calls, 1);

    let stats = Rc::new(RefCell::new(Stats {
        fail_realloc_at: Some(1),
        panic_discard: true,
        ..Stats::default()
    }));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
        let stats = stats.clone();
        move || {
            let mut machine = build_machine(stats);
            machine.begin_call().unwrap();
            let _ = machine.lower_utf8("discard panic");
        }
    }));
    assert!(unwind.is_err());
    assert_eq!(stats.borrow().discard_calls, 1);
}
