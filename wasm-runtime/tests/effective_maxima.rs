use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
    hint::black_box,
};

use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    inspect_core, AdmissionDetail, CoreComponentGroup, CoreValue, OwnerAllocationReservation,
    PollResult, ProfileEngine, ValidatedCore,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AllocationStats {
    calls: usize,
    total_bytes: usize,
    max_bytes: usize,
}

thread_local! {
    static ACTIVE_OWNER: Cell<usize> = const { Cell::new(0) };
    static OWNER_STATS: RefCell<[AllocationStats; 3]> = const {
        RefCell::new([AllocationStats {
            calls: 0,
            total_bytes: 0,
            max_bytes: 0,
        }; 3])
    };
}

struct OwnerTrackingAllocator;

#[global_allocator]
static ALLOCATOR: OwnerTrackingAllocator = OwnerTrackingAllocator;

unsafe impl GlobalAlloc for OwnerTrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Safety: delegation preserves the caller's exact layout contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Safety: delegation preserves the caller's exact layout contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // Safety: the pointer and layout came from this allocator's System
        // delegation and are returned unchanged.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Safety: delegation preserves the original allocation contract and
        // forwards the requested replacement size unchanged.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record_allocation(new_size);
        }
        replacement
    }
}

fn record_allocation(bytes: usize) {
    ACTIVE_OWNER.with(|active| {
        let owner = active.get();
        if owner == 0 {
            return;
        }
        OWNER_STATS.with(|all| {
            let mut all = all.borrow_mut();
            let stats = &mut all[owner];
            stats.calls = stats.calls.saturating_add(1);
            stats.total_bytes = stats.total_bytes.saturating_add(bytes);
            stats.max_bytes = stats.max_bytes.max(bytes);
        });
    });
}

fn track_owner<T>(owner: usize, operation: impl FnOnce() -> T) -> (T, [AllocationStats; 3]) {
    assert!(matches!(owner, 1 | 2));
    OWNER_STATS.with(|all| *all.borrow_mut() = [AllocationStats::default(); 3]);
    ACTIVE_OWNER.with(|active| {
        assert_eq!(active.replace(owner), 0, "nested owner allocation scope");
    });
    let result = operation();
    ACTIVE_OWNER.with(|active| assert_eq!(active.replace(0), owner));
    let stats = OWNER_STATS.with(|all| *all.borrow());
    (result, stats)
}

fn compile_in(engine: &ProfileEngine, source: &str) -> ValidatedCore {
    let bytes = wat::parse_str(source).unwrap();
    ValidatedCore::new_in(
        engine,
        &bytes,
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn poll_group_to_terminal(group: &mut CoreComponentGroup) -> PollResult {
    loop {
        match group.poll_call(0) {
            PollResult::Pending { .. } => {}
            terminal @ (PollResult::Ready(_) | PollResult::Trapped(_)) => return terminal,
            PollResult::HostCall(call) => panic!("unexpected host call: {call:?}"),
        }
    }
}

fn run_depth(instance: &mut vibeos_wasm_runtime::CoreInstance, depth: u32) -> PollResult {
    instance
        .start_call(
            "depth",
            &[CoreValue::I32(depth as i32)],
            PROFILE_1_LIMITS.total_fuel,
            PROFILE_1_LIMITS.poll_quantum,
        )
        .unwrap();
    loop {
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            terminal @ (PollResult::Ready(_) | PollResult::Trapped(_)) => return terminal,
            PollResult::HostCall(call) => panic!("unexpected host call: {call:?}"),
        }
    }
}

fn push_u32_leb(target: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        target.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn push_section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    push_u32_leb(module, payload.len().try_into().unwrap());
    module.extend_from_slice(payload);
}

fn compressed_locals_module(locals: u32) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    push_section(&mut module, 1, &[0x01, 0x60, 0x00, 0x00]);
    push_section(&mut module, 3, &[0x01, 0x00]);

    let mut body = vec![0x01];
    push_u32_leb(&mut body, locals);
    body.extend([0x7f, 0x0b]);
    let mut code = vec![0x01];
    push_u32_leb(&mut code, body.len().try_into().unwrap());
    code.extend(body);
    push_section(&mut module, 10, &code);
    module
}

#[test]
fn memory_and_table_growth_stop_at_the_effective_maximum() {
    let engine = ProfileEngine::new();
    let memory = compile_in(
        &engine,
        r#"(module
              (memory (export "memory") 1 4)
              (func (export "grow") (param i32) (result i32)
                local.get 0
                memory.grow))"#,
    );
    let mut group = CoreComponentGroup::new_with_memory_limit(&engine, 1, 2 * 65_536).unwrap();
    group.add_instance(&memory, &[]).unwrap();
    group.seal().unwrap();

    group
        .start_call(0, "grow", &[CoreValue::I32(1)], 100_000, 10_000)
        .unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
    assert_eq!(group.memory_size(0, "memory"), Ok(2 * 65_536));
    for _ in 0..2 {
        group
            .start_call(0, "grow", &[CoreValue::I32(1)], 100_000, 10_000)
            .unwrap();
        assert_eq!(
            poll_group_to_terminal(&mut group),
            PollResult::Trapped(TrapCode::LimitExceeded)
        );
        assert_eq!(group.memory_size(0, "memory"), Ok(2 * 65_536));
    }
    assert_eq!(
        group.grow_memory_to(0, "memory", 2 * 65_536 + 1),
        Err(TrapCode::LimitExceeded)
    );

    // A tighter module-declared maximum is a Core bounds failure rather than
    // a denial by the outer image policy.
    let declared_memory = compile_in(&engine, r#"(module (memory (export "memory") 1 1))"#);
    let mut declared_memory = declared_memory.instantiate().unwrap();
    assert_eq!(
        declared_memory.grow_memory_to("memory", 65_537),
        Err(TrapCode::MemoryOutOfBounds)
    );
    assert_eq!(declared_memory.memory_size("memory"), Ok(65_536));

    let table_source = format!(
        "(module (table (export \"table\") 1 {} funcref))",
        PROFILE_1_LIMITS.max_table_elements
    );
    let table = compile_in(&engine, &table_source);
    let mut table = table.instantiate().unwrap();
    assert_eq!(table.table_size("table"), Ok(1));
    table
        .grow_table_to("table", PROFILE_1_LIMITS.max_table_elements as usize)
        .unwrap();
    assert_eq!(
        table.table_size("table"),
        Ok(PROFILE_1_LIMITS.max_table_elements as usize)
    );
    for _ in 0..2 {
        assert_eq!(
            table.grow_table_to("table", PROFILE_1_LIMITS.max_table_elements as usize + 1,),
            Err(TrapCode::LimitExceeded)
        );
        assert_eq!(
            table.table_size("table"),
            Ok(PROFILE_1_LIMITS.max_table_elements as usize)
        );
    }
    assert_eq!(
        table.grow_table_to("table", usize::MAX),
        Err(TrapCode::LimitExceeded)
    );
    assert_eq!(
        table.table_size("table"),
        Ok(PROFILE_1_LIMITS.max_table_elements as usize)
    );

    let declared_table = compile_in(&engine, r#"(module (table (export "table") 1 1 funcref))"#);
    let mut declared_table = declared_table.instantiate().unwrap();
    assert_eq!(
        declared_table.grow_table_to("table", 2),
        Err(TrapCode::TableOutOfBounds)
    );
    assert_eq!(declared_table.table_size("table"), Ok(1));

    let disabled_table_grow = wat::parse_str(
        r#"(module
              (table 1 2 funcref)
              (func (export "grow") (param i32) (result i32)
                ref.null func
                local.get 0
                table.grow))"#,
    )
    .unwrap();
    assert_eq!(
        inspect_core(&disabled_table_grow).unwrap_err().detail,
        AdmissionDetail::UnsupportedFeature
    );
}

#[test]
fn call_depth_accepts_128_active_frames_and_rejects_the_129th() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func $depth (export "depth") (param i32) (result i32)
                local.get 0
                i32.eqz
                if (result i32)
                  i32.const 0
                else
                  local.get 0
                  i32.const 1
                  i32.sub
                  call $depth
                end))"#,
    );
    let mut instance = module.instantiate().unwrap();
    assert_eq!(
        run_depth(&mut instance, PROFILE_1_LIMITS.max_call_depth - 1),
        PollResult::Ready(vec![CoreValue::I32(0)])
    );
    for _ in 0..2 {
        assert_eq!(
            run_depth(&mut instance, PROFILE_1_LIMITS.max_call_depth),
            PollResult::Trapped(TrapCode::CallDepthExceeded)
        );
    }
    assert_eq!(
        run_depth(&mut instance, 0),
        PollResult::Ready(vec![CoreValue::I32(0)])
    );
}

#[test]
fn compile_policy_charge_rejects_before_engine_allocation_in_the_active_owner() {
    // One compact local group expands to one pointer-sized Wasmi locals-head
    // slot per local even though the complete module is only 27 bytes.
    let bytes = compressed_locals_module(PROFILE_1_LIMITS.max_locals_per_function);
    assert_eq!(bytes.len(), 27);
    let summary = inspect_core(&bytes).unwrap();
    assert_eq!(summary.max_locals, PROFILE_1_LIMITS.max_locals_per_function);
    let local_expansion_bytes = (summary.max_locals as usize) * size_of::<usize>();
    let charge = ValidatedCore::required_compile_bytes(&bytes).unwrap();
    assert!(charge >= bytes.len() * 32 + local_expansion_bytes);

    let (_, owner_probe) = track_owner(2, || {
        let probe = vec![black_box(1_u8)];
        black_box(probe.capacity())
    });
    assert!(owner_probe[2].calls > 0 && owner_probe[2].total_bytes > 0);
    assert_eq!(owner_probe[1], AllocationStats::default());

    let (_, inspect_stats) = track_owner(1, || inspect_core(&bytes).unwrap());
    let (error, rejected_stats) = track_owner(1, || {
        ValidatedCore::new(&bytes, OwnerAllocationReservation::new(charge - 1)).unwrap_err()
    });
    assert_eq!(error.trap, TrapCode::LimitExceeded);
    assert_eq!(error.detail, AdmissionDetail::AllocationReservation);
    assert_eq!(rejected_stats, inspect_stats);
    assert_eq!(rejected_stats[2], AllocationStats::default());

    let (reserved, accepted_stats) = track_owner(1, || {
        ValidatedCore::new(&bytes, OwnerAllocationReservation::new(charge))
            .unwrap()
            .reserved_compile_bytes()
    });
    assert_eq!(reserved, charge);
    assert!(accepted_stats[1].calls > inspect_stats[1].calls);
    assert!(accepted_stats[1].total_bytes > inspect_stats[1].total_bytes);
    assert!(accepted_stats[1].max_bytes >= local_expansion_bytes);
    assert!(charge >= accepted_stats[1].max_bytes);
    assert_eq!(accepted_stats[2], AllocationStats::default());
}
