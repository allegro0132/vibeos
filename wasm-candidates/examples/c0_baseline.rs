use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use dlr_wasm_interpreter::{
    decode_and_validate, FuncAddr, InstantiationOutcome, RunState, Store as DlrStore, Value,
};
use vibeos_component_runtime::{
    canonical::{AbiBudget, CallGate, CanonicalMachine, ReallocRequest, Reallocator},
    memory::{AbiError, Allocation, GuestMemory, VecMemory},
};
use vibeos_wasm_candidates::{
    baseline_contract::{
        CANONICAL_LIST_ELEMENTS, CANONICAL_OPERATIONS, CANONICAL_TEXT_BYTES, FRONTEND_OPERATIONS,
        FUEL_BUDGET, FUEL_INPUT, FUEL_OPERATIONS, STARTUP_INPUT, STARTUP_OPERATIONS,
        TIMING_SAMPLES,
    },
    configured_wasmi_engine, inspect_component, validate_wit_world,
};
use wasmi::{Engine, Linker, Module, Store, TypedFunc};

const EMPTY_CORE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/c0_empty.wasm"));
const FUEL_CORE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/c0_fuel.wasm"));
const COMPONENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/c0_typed_component.wasm"));
const WORLD: &str = include_str!("../../component-format/tests/corpus/wit/world.wit");

const CANONICAL_TEXT: &str = concat!(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
);
const CANONICAL_LIST: [u32; CANONICAL_LIST_ELEMENTS] = [0x0102_0304; CANONICAL_LIST_ELEMENTS];
const CANONICAL_RESULT: u64 = (CANONICAL_TEXT_BYTES + CANONICAL_LIST_ELEMENTS) as u64;
const _: () = assert!(CANONICAL_TEXT.len() == CANONICAL_TEXT_BYTES);

struct TrackingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

fn add_live(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::SeqCst);
}

fn subtract_live(bytes: usize) {
    let previous = LIVE_BYTES.fetch_sub(bytes, Ordering::SeqCst);
    assert!(previous >= bytes, "allocator live-byte counter underflow");
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            add_live(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc_zeroed(layout);
        if !pointer.is_null() {
            add_live(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
        subtract_live(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = System.realloc(pointer, layout, new_size);
        if !replacement.is_null() {
            if new_size >= layout.size() {
                add_live(new_size - layout.size());
            } else {
                subtract_live(layout.size() - new_size);
            }
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[derive(Clone, Copy)]
struct MemoryObservation {
    baseline_bytes: usize,
    peak_delta_bytes: usize,
    retained_bytes: usize,
    after_bytes: usize,
}

fn begin_memory_window() -> usize {
    let baseline = LIVE_BYTES.load(Ordering::SeqCst);
    PEAK_BYTES.store(baseline, Ordering::SeqCst);
    baseline
}

fn finish_memory_window(baseline: usize, retained: usize) -> MemoryObservation {
    let after = LIVE_BYTES.load(Ordering::SeqCst);
    let peak = PEAK_BYTES.load(Ordering::SeqCst);
    assert_eq!(
        after, baseline,
        "measurement did not return to its heap baseline"
    );
    MemoryObservation {
        baseline_bytes: baseline,
        peak_delta_bytes: peak
            .checked_sub(baseline)
            .expect("measurement peak fell below its baseline"),
        retained_bytes: retained,
        after_bytes: after,
    }
}

fn measure_transient(operation: impl FnOnce()) -> MemoryObservation {
    let baseline = begin_memory_window();
    operation();
    finish_memory_window(baseline, 0)
}

fn measure_retained<T>(operation: impl FnOnce() -> T) -> MemoryObservation {
    let baseline = begin_memory_window();
    let value = operation();
    black_box(&value);
    let retained = LIVE_BYTES
        .load(Ordering::SeqCst)
        .checked_sub(baseline)
        .expect("retained measurement fell below its baseline");
    drop(value);
    finish_memory_window(baseline, retained)
}

fn timing_samples(operations: u64, mut operation: impl FnMut() -> u64) -> (Vec<u128>, Vec<u64>) {
    black_box(operation());
    let mut elapsed = Vec::with_capacity(TIMING_SAMPLES);
    let mut results = Vec::with_capacity(TIMING_SAMPLES);
    for _ in 0..TIMING_SAMPLES {
        let started = Instant::now();
        let mut accumulator = 0_u64;
        for _ in 0..operations {
            accumulator = accumulator.wrapping_add(black_box(operation()));
        }
        elapsed.push(started.elapsed().as_nanos());
        results.push(accumulator);
    }
    (elapsed, results)
}

fn collect_fuel_samples(
    operations: u64,
    mut operation: impl FnMut() -> (u64, u64),
) -> (Vec<u128>, Vec<u64>, Vec<u64>, u64) {
    let (_, expected_fuel) = operation();
    assert!(expected_fuel > 0);
    let mut elapsed = Vec::with_capacity(TIMING_SAMPLES);
    let mut results = Vec::with_capacity(TIMING_SAMPLES);
    let mut fuel = Vec::with_capacity(TIMING_SAMPLES);
    for _ in 0..TIMING_SAMPLES {
        let started = Instant::now();
        let mut accumulator = 0_u64;
        let mut consumed = 0_u64;
        for _ in 0..operations {
            let (result, operation_fuel) = operation();
            assert_eq!(operation_fuel, expected_fuel, "fuel changed between calls");
            accumulator = accumulator.wrapping_add(black_box(result));
            consumed = consumed.checked_add(operation_fuel).unwrap();
        }
        elapsed.push(started.elapsed().as_nanos());
        results.push(accumulator);
        fuel.push(consumed);
    }
    (elapsed, results, fuel, expected_fuel)
}

fn wasmi_started(engine: &Engine, bytes: &[u8]) -> (Store<()>, TypedFunc<i32, i32>) {
    let module = Module::new(engine, bytes).unwrap();
    let mut store = Store::new(engine, ());
    store.set_fuel(FUEL_BUDGET).unwrap();
    let instance = Linker::new(engine)
        .instantiate_and_start(&mut store, &module)
        .unwrap();
    let burn = instance.get_typed_func::<i32, i32>(&store, "burn").unwrap();
    (store, burn)
}

fn dlr_started(bytes: &[u8]) -> (DlrStore<'_, ()>, FuncAddr) {
    let module = decode_and_validate(bytes, &mut ()).unwrap();
    let mut store = DlrStore::new(());
    // SAFETY: the decoded module is import-free and belongs to this store.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { store.module_instantiate(&module, Vec::new(), None) }.unwrap();
    // SAFETY: the instance address was returned by this store.
    let burn = unsafe { store.instance_export(module_addr, "burn") }
        .unwrap()
        .as_func()
        .unwrap();
    (store, burn)
}

fn run_dlr_fueled(store: &mut DlrStore<()>, burn: FuncAddr, input: i32) -> (u64, u64) {
    // SAFETY: the function belongs to this store and receives its exact i32 parameter.
    let state =
        unsafe { store.invoke(burn, vec![Value::I32(input as u32)], Some(FUEL_BUDGET)) }.unwrap();
    let RunState::Finished {
        values,
        maybe_remaining_fuel: Some(remaining),
    } = state
    else {
        panic!("DLR fuel workload did not finish")
    };
    let [Value::I32(result)] = values.as_slice() else {
        panic!("DLR fuel workload returned the wrong shape")
    };
    (u64::from(*result), FUEL_BUDGET - remaining)
}

#[derive(Default)]
struct ResettingBump {
    next: u32,
    live: u32,
}

impl ResettingBump {
    fn new() -> Self {
        Self { next: 64, live: 0 }
    }
}

impl Reallocator<VecMemory> for ResettingBump {
    fn realloc(
        &mut self,
        memory: &mut VecMemory,
        _gate: &CallGate,
        request: ReallocRequest,
        _budget: &mut AbiBudget,
    ) -> Result<u32, AbiError> {
        if request.old_pointer != 0 || request.old_size != 0 || request.new_size == 0 {
            return Err(AbiError::BadRealloc);
        }
        let aligned = self
            .next
            .checked_add(request.alignment - 1)
            .map(|value| value & !(request.alignment - 1))
            .ok_or(AbiError::Overflow)?;
        let end = aligned
            .checked_add(request.new_size)
            .ok_or(AbiError::Overflow)?;
        if memory.len() < u64::from(end) {
            memory.grow_to(end as usize)?;
        }
        self.next = end;
        self.live = self.live.checked_add(1).ok_or(AbiError::AllocationLimit)?;
        Ok(aligned)
    }

    fn free(
        &mut self,
        _memory: &mut VecMemory,
        _gate: &CallGate,
        _allocation: Allocation,
        _budget: &mut AbiBudget,
    ) -> Result<(), AbiError> {
        self.live = self.live.checked_sub(1).ok_or(AbiError::CleanupFailed)?;
        if self.live == 0 {
            self.next = 64;
        }
        Ok(())
    }

    fn discard_arena(&mut self, _memory: &mut VecMemory, _gate: &CallGate) {
        self.next = 64;
        self.live = 0;
    }
}

fn canonical_operation(machine: &mut CanonicalMachine<VecMemory, ResettingBump>) -> u64 {
    machine.begin_call().unwrap();
    let (text_pointer, text_length) = machine.lower_utf8(CANONICAL_TEXT).unwrap();
    let lifted_text = machine.lift_utf8(text_pointer, text_length).unwrap();
    let (list_pointer, list_length) = machine.lower_u32_list(&CANONICAL_LIST).unwrap();
    let lifted_list = machine.lift_u32_list(list_pointer, list_length).unwrap();
    assert_eq!(lifted_text, CANONICAL_TEXT);
    assert_eq!(lifted_list.as_slice(), CANONICAL_LIST);
    machine.finish_success(|_, _, _| Ok(())).unwrap();
    (lifted_text.len() + lifted_list.len()) as u64
}

enum Record {
    Memory {
        subject: &'static str,
        metric: &'static str,
        workload: &'static str,
        observation: MemoryObservation,
        result: u64,
    },
    Timing {
        subject: &'static str,
        metric: &'static str,
        workload: &'static str,
        operations: u64,
        samples_ns: Vec<u128>,
        results: Vec<u64>,
    },
    Fuel {
        subject: &'static str,
        workload: &'static str,
        operations: u64,
        samples_ns: Vec<u128>,
        results: Vec<u64>,
        fuel_samples: Vec<u64>,
        fuel_per_operation: u64,
    },
}

impl Record {
    fn emit(&self) {
        match self {
            Self::Memory {
                subject,
                metric,
                workload,
                observation,
                result,
            } => println!(
                "{{\"kind\":\"memory\",\"subject\":\"{subject}\",\"metric\":\"{metric}\",\"workload\":\"{workload}\",\"operations\":1,\"baseline_bytes\":{},\"peak_delta_bytes\":{},\"retained_bytes\":{},\"after_bytes\":{},\"result\":{result}}}",
                observation.baseline_bytes,
                observation.peak_delta_bytes,
                observation.retained_bytes,
                observation.after_bytes,
            ),
            Self::Timing {
                subject,
                metric,
                workload,
                operations,
                samples_ns,
                results,
            } => println!(
                "{{\"kind\":\"timing\",\"subject\":\"{subject}\",\"metric\":\"{metric}\",\"workload\":\"{workload}\",\"operations_per_sample\":{operations},\"samples_ns\":{samples_ns:?},\"results\":{results:?}}}"
            ),
            Self::Fuel {
                subject,
                workload,
                operations,
                samples_ns,
                results,
                fuel_samples,
                fuel_per_operation,
            } => println!(
                "{{\"kind\":\"fuel\",\"subject\":\"{subject}\",\"metric\":\"core-fuel-throughput\",\"workload\":\"{workload}\",\"operations_per_sample\":{operations},\"samples_ns\":{samples_ns:?},\"results\":{results:?},\"fuel_samples\":{fuel_samples:?},\"fuel_per_operation\":{fuel_per_operation}}}"
            ),
        }
    }
}

fn main() {
    let mut records = Vec::new();
    let malformed_core = &FUEL_CORE[..FUEL_CORE.len() - 1];
    let malformed_component = &COMPONENT[..COMPONENT.len() - 1];

    let wasmi_engine = configured_wasmi_engine();
    drop({
        let engine = configured_wasmi_engine();
        Module::new(&engine, FUEL_CORE).unwrap()
    });
    let observation = measure_transient(|| {
        let engine = configured_wasmi_engine();
        drop(Module::new(&engine, FUEL_CORE).unwrap());
    });
    records.push(Record::Memory {
        subject: "wasmi=1.1.0",
        metric: "validator-accepted-peak",
        workload: "fuel-core-v1",
        observation,
        result: 1,
    });
    assert!({
        let engine = configured_wasmi_engine();
        Module::new(&engine, malformed_core).is_err()
    });
    let observation = measure_transient(|| {
        let engine = configured_wasmi_engine();
        assert!(Module::new(&engine, malformed_core).is_err());
    });
    records.push(Record::Memory {
        subject: "wasmi=1.1.0",
        metric: "validator-rejected-peak",
        workload: "malformed-core-v1",
        observation,
        result: 1,
    });

    let empty_module = Module::new(&wasmi_engine, EMPTY_CORE).unwrap();
    drop({
        let mut store = Store::new(&wasmi_engine, ());
        let instance = Linker::new(&wasmi_engine)
            .instantiate_and_start(&mut store, &empty_module)
            .unwrap();
        black_box(instance);
        store
    });
    let observation = measure_retained(|| {
        let mut store = Store::new(&wasmi_engine, ());
        let instance = Linker::new(&wasmi_engine)
            .instantiate_and_start(&mut store, &empty_module)
            .unwrap();
        black_box(instance);
        store
    });
    records.push(Record::Memory {
        subject: "wasmi=1.1.0",
        metric: "empty-instance",
        workload: "empty-core-v1",
        observation,
        result: 1,
    });

    let (samples_ns, results) = timing_samples(STARTUP_OPERATIONS, || {
        let engine = configured_wasmi_engine();
        let (mut store, burn) = wasmi_started(&engine, FUEL_CORE);
        u64::try_from(burn.call(&mut store, STARTUP_INPUT).unwrap()).unwrap()
    });
    records.push(Record::Timing {
        subject: "wasmi=1.1.0",
        metric: "cold-startup",
        workload: "fuel-core-first-call-v1",
        operations: STARTUP_OPERATIONS,
        samples_ns,
        results,
    });

    let (mut wasmi_store, wasmi_burn) = wasmi_started(&wasmi_engine, FUEL_CORE);
    let (samples_ns, results, fuel_samples, fuel_per_operation) =
        collect_fuel_samples(FUEL_OPERATIONS, || {
            wasmi_store.set_fuel(FUEL_BUDGET).unwrap();
            let result = wasmi_burn.call(&mut wasmi_store, FUEL_INPUT).unwrap();
            let remaining = wasmi_store.get_fuel().unwrap();
            (u64::try_from(result).unwrap(), FUEL_BUDGET - remaining)
        });
    records.push(Record::Fuel {
        subject: "wasmi=1.1.0",
        workload: "burn-32768-v1",
        operations: FUEL_OPERATIONS,
        samples_ns,
        results,
        fuel_samples,
        fuel_per_operation,
    });

    drop(decode_and_validate(FUEL_CORE, &mut ()).unwrap());
    let observation = measure_transient(|| {
        drop(decode_and_validate(FUEL_CORE, &mut ()).unwrap());
    });
    records.push(Record::Memory {
        subject: "dlr-wasm-interpreter=0.2.0",
        metric: "validator-accepted-peak",
        workload: "fuel-core-v1",
        observation,
        result: 1,
    });
    assert!(decode_and_validate(malformed_core, &mut ()).is_err());
    let observation = measure_transient(|| {
        assert!(decode_and_validate(malformed_core, &mut ()).is_err());
    });
    records.push(Record::Memory {
        subject: "dlr-wasm-interpreter=0.2.0",
        metric: "validator-rejected-peak",
        workload: "malformed-core-v1",
        observation,
        result: 1,
    });

    let empty_dlr_module = decode_and_validate(EMPTY_CORE, &mut ()).unwrap();
    drop({
        let mut store = DlrStore::new(());
        // SAFETY: the decoded module is import-free and belongs to this store.
        let instance =
            unsafe { store.module_instantiate(&empty_dlr_module, Vec::new(), None) }.unwrap();
        black_box(instance.module_addr);
        store
    });
    let observation = measure_retained(|| {
        let mut store = DlrStore::new(());
        // SAFETY: the decoded module is import-free and belongs to this store.
        let instance =
            unsafe { store.module_instantiate(&empty_dlr_module, Vec::new(), None) }.unwrap();
        black_box(instance.module_addr);
        store
    });
    records.push(Record::Memory {
        subject: "dlr-wasm-interpreter=0.2.0",
        metric: "empty-instance",
        workload: "empty-core-v1",
        observation,
        result: 1,
    });

    let (samples_ns, results) = timing_samples(STARTUP_OPERATIONS, || {
        let (mut store, burn) = dlr_started(FUEL_CORE);
        run_dlr_fueled(&mut store, burn, 1).0
    });
    records.push(Record::Timing {
        subject: "dlr-wasm-interpreter=0.2.0",
        metric: "cold-startup",
        workload: "fuel-core-first-call-v1",
        operations: STARTUP_OPERATIONS,
        samples_ns,
        results,
    });

    let (mut dlr_store, dlr_burn) = dlr_started(FUEL_CORE);
    let (samples_ns, results, fuel_samples, fuel_per_operation) =
        collect_fuel_samples(FUEL_OPERATIONS, || {
            run_dlr_fueled(&mut dlr_store, dlr_burn, FUEL_INPUT)
        });
    records.push(Record::Fuel {
        subject: "dlr-wasm-interpreter=0.2.0",
        workload: "burn-32768-v1",
        operations: FUEL_OPERATIONS,
        samples_ns,
        results,
        fuel_samples,
        fuel_per_operation,
    });

    inspect_component(COMPONENT).unwrap();
    let observation = measure_transient(|| {
        black_box(inspect_component(COMPONENT).unwrap());
    });
    records.push(Record::Memory {
        subject: "component-frontend=0.255.0",
        metric: "component-validator-accepted-peak",
        workload: "typed-component-v1",
        observation,
        result: 1,
    });
    assert!(inspect_component(malformed_component).is_err());
    let observation = measure_transient(|| {
        assert!(inspect_component(malformed_component).is_err());
    });
    records.push(Record::Memory {
        subject: "component-frontend=0.255.0",
        metric: "component-validator-rejected-peak",
        workload: "malformed-component-v1",
        observation,
        result: 1,
    });
    validate_wit_world(WORLD, "typed-filter").unwrap();
    let observation = measure_transient(|| {
        validate_wit_world(WORLD, "typed-filter").unwrap();
    });
    records.push(Record::Memory {
        subject: "component-frontend=0.255.0",
        metric: "wit-validator-peak",
        workload: "typed-world-v1",
        observation,
        result: 1,
    });

    let (samples_ns, results) = timing_samples(FRONTEND_OPERATIONS, || {
        let summary = inspect_component(COMPONENT).unwrap();
        validate_wit_world(WORLD, "typed-filter").unwrap();
        u64::from(summary.embedded_modules + summary.exports)
    });
    records.push(Record::Timing {
        subject: "component-frontend=0.255.0",
        metric: "frontend-prepare",
        workload: "typed-component-world-v1",
        operations: FRONTEND_OPERATIONS,
        samples_ns,
        results,
    });

    let memory = VecMemory::new(65_536, 65_536).unwrap();
    let mut canonical = CanonicalMachine::new(memory, ResettingBump::new(), 100_000).unwrap();
    canonical_operation(&mut canonical);
    let observation = measure_transient(|| {
        assert_eq!(canonical_operation(&mut canonical), CANONICAL_RESULT);
    });
    records.push(Record::Memory {
        subject: "component-frontend=0.255.0",
        metric: "canonical-lift-lower-peak",
        workload: "canonical-256b-64u32-v1",
        observation,
        result: CANONICAL_RESULT,
    });
    let (samples_ns, results) =
        timing_samples(CANONICAL_OPERATIONS, || canonical_operation(&mut canonical));
    records.push(Record::Timing {
        subject: "component-frontend=0.255.0",
        metric: "canonical-lift-lower",
        workload: "canonical-256b-64u32-v1",
        operations: CANONICAL_OPERATIONS,
        samples_ns,
        results,
    });

    for record in &records {
        record.emit();
    }
}
