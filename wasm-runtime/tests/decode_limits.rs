use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
};

use vibeos_component_format::{LimitKind, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    inspect_core, AdmissionDetail, AdmissionError, OwnerAllocationReservation, ProfileEngine,
    ValidatedCore,
};

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
    static ALLOCATION_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_ALLOCATION_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct TestAllocator;

fn record_allocation(bytes: usize) {
    let tracked = TRACK_ALLOCATIONS.try_with(Cell::get).unwrap_or(false);
    if tracked {
        let _ = ALLOCATION_COUNT.try_with(|count| count.set(count.get().saturating_add(1)));
        let _ = ALLOCATION_BYTES.try_with(|total| total.set(total.get().saturating_add(bytes)));
        let _ = MAX_ALLOCATION_BYTES.try_with(|maximum| maximum.set(maximum.get().max(bytes)));
    }
}

unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size);
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

const MAX_STRUCTURAL_DIAGNOSTIC_CALLS: usize = 8;
const MAX_STRUCTURAL_DIAGNOSTIC_TOTAL_BYTES: usize = 1024;
const MAX_STRUCTURAL_DIAGNOSTIC_REQUEST_BYTES: usize = 512;

struct AllocationTrackingGuard;

impl Drop for AllocationTrackingGuard {
    fn drop(&mut self) {
        TRACK_ALLOCATIONS.with(|tracked| tracked.set(false));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocationStats {
    calls: usize,
    total_bytes: usize,
    max_bytes: usize,
}

fn track_allocations<T>(operation: impl FnOnce() -> T) -> (T, AllocationStats) {
    ALLOCATION_COUNT.with(|count| count.set(0));
    ALLOCATION_BYTES.with(|total| total.set(0));
    MAX_ALLOCATION_BYTES.with(|maximum| maximum.set(0));
    TRACK_ALLOCATIONS.with(|tracked| {
        assert!(!tracked.replace(true), "nested allocation tracking");
    });
    let guard = AllocationTrackingGuard;
    let result = operation();
    drop(guard);
    let stats = AllocationStats {
        calls: ALLOCATION_COUNT.with(Cell::get),
        total_bytes: ALLOCATION_BYTES.with(Cell::get),
        max_bytes: MAX_ALLOCATION_BYTES.with(Cell::get),
    };
    (result, stats)
}

fn u32_leb(mut value: u32) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn module_header() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

fn append_section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(u32_leb(payload.len().try_into().unwrap()));
    module.extend_from_slice(payload);
}

fn module_with_count_section(id: u8, count: u32) -> Vec<u8> {
    let mut module = module_header();
    append_section(&mut module, id, &u32_leb(count));
    module
}

fn module_with_one_function(body: &[u8]) -> Vec<u8> {
    let mut module = module_header();
    append_section(&mut module, 1, &[0x01, 0x60, 0x00, 0x00]);
    append_section(&mut module, 3, &[0x01, 0x00]);

    let mut code = vec![0x01];
    code.extend(u32_leb(body.len().try_into().unwrap()));
    code.extend_from_slice(body);
    append_section(&mut module, 10, &code);
    module
}

fn assert_predecode_rejection(
    label: &str,
    bytes: &[u8],
    expected: AdmissionDetail,
    engine: &ProfileEngine,
) -> AllocationStats {
    let expected = AdmissionError {
        trap: match expected {
            AdmissionDetail::Limit(_) => vibeos_component_format::TrapCode::LimitExceeded,
            AdmissionDetail::UnsupportedFeature => {
                vibeos_component_format::TrapCode::UnsupportedFeature
            }
            _ => vibeos_component_format::TrapCode::Validation,
        },
        detail: expected,
    };
    let (inspect_result, inspect_stats) = track_allocations(|| inspect_core(bytes).map(|_| ()));
    let (validated_result, validated_stats) = track_allocations(|| {
        ValidatedCore::new_in(engine, bytes, OwnerAllocationReservation::new(0)).map(|_| ())
    });
    assert_eq!(
        inspect_result,
        Err(expected),
        "wrong inspect_core rejection for {label}"
    );
    assert_eq!(
        validated_result,
        Err(expected),
        "wrong ValidatedCore::new_in rejection for {label}"
    );
    assert_eq!(
        validated_stats, inspect_stats,
        "{label} allocated after its structural admission rejection"
    );
    // Some wasmparser structural paths create small owned diagnostics while
    // probing a section reader. This fixed envelope is intentionally tiny and
    // independent of any declared count or length; most cases remain zero.
    assert!(
        inspect_stats.calls <= MAX_STRUCTURAL_DIAGNOSTIC_CALLS
            && inspect_stats.total_bytes <= MAX_STRUCTURAL_DIAGNOSTIC_TOTAL_BYTES
            && inspect_stats.max_bytes <= MAX_STRUCTURAL_DIAGNOSTIC_REQUEST_BYTES,
        "{label} exceeded the fixed structural-decoder envelope: {inspect_stats:?}"
    );
    inspect_stats
}

#[test]
fn hostile_lengths_counts_and_depth_do_not_amplify_predecode_allocation() {
    let engine = ProfileEngine::new();
    let (_, probe_allocations) = track_allocations(|| {
        let probe = vec![black_box(1_u8)];
        black_box(probe.capacity())
    });
    assert!(
        probe_allocations.calls != 0 && probe_allocations.total_bytes != 0,
        "the allocation probe is not armed"
    );

    let oversized = vec![0_u8; PROFILE_1_LIMITS.max_core_module_bytes + 1];
    assert_predecode_rejection(
        "module-length-limit-plus-one",
        &oversized,
        AdmissionDetail::Limit(LimitKind::CoreModuleBytes),
        &engine,
    );

    let malformed_length = |declared| {
        let mut module = module_header();
        module.push(1);
        module.extend(u32_leb(declared));
        module
    };
    let short_length = malformed_length(1);
    let huge_length = malformed_length(u32::MAX);
    let short_stats = assert_predecode_rejection(
        "short-malformed-section-length",
        &short_length,
        AdmissionDetail::Malformed,
        &engine,
    );
    let huge_stats = assert_predecode_rejection(
        "u32-max-malformed-section-length",
        &huge_length,
        AdmissionDetail::Malformed,
        &engine,
    );
    assert!(
        huge_stats.calls <= short_stats.calls
            && huge_stats.total_bytes <= short_stats.total_bytes
            && huge_stats.max_bytes <= short_stats.max_bytes,
        "a larger declared section length amplified allocation: short={short_stats:?}, huge={huge_stats:?}"
    );

    for (label, section, count, kind) in [
        (
            "type-count-limit-plus-one",
            1,
            PROFILE_1_LIMITS.max_types + 1,
            LimitKind::Types,
        ),
        (
            "function-count-limit-plus-one",
            3,
            PROFILE_1_LIMITS.max_functions + 1,
            LimitKind::Functions,
        ),
        (
            "import-count-limit-plus-one",
            2,
            PROFILE_1_LIMITS.max_imports + 1,
            LimitKind::Imports,
        ),
        (
            "global-count-limit-plus-one",
            6,
            PROFILE_1_LIMITS.max_globals + 1,
            LimitKind::Globals,
        ),
        (
            "export-count-limit-plus-one",
            7,
            PROFILE_1_LIMITS.max_exports + 1,
            LimitKind::Exports,
        ),
        (
            "table-count-limit-plus-one",
            4,
            PROFILE_1_LIMITS.max_tables + 1,
            LimitKind::Tables,
        ),
        (
            "memory-count-limit-plus-one",
            5,
            PROFILE_1_LIMITS.max_memories + 1,
            LimitKind::Memories,
        ),
        (
            "element-count-limit-plus-one",
            9,
            PROFILE_1_LIMITS.max_element_segments + 1,
            LimitKind::ElementSegments,
        ),
        (
            "data-count-limit-plus-one",
            11,
            PROFILE_1_LIMITS.max_data_segments + 1,
            LimitKind::DataSegments,
        ),
    ] {
        let module = module_with_count_section(section, count);
        assert_predecode_rejection(label, &module, AdmissionDetail::Limit(kind), &engine);
    }

    let append_single_import = |module: &mut Vec<u8>, descriptor: &[u8]| {
        let mut payload = vec![0x01, 0x01, b'm', 0x00];
        payload.extend_from_slice(descriptor);
        append_section(module, 2, &payload);
    };

    let mut aggregate_functions = module_header();
    append_section(&mut aggregate_functions, 1, &[0x01, 0x60, 0x00, 0x00]);
    append_single_import(&mut aggregate_functions, &[0x00, 0x00]);
    let mut defined_functions = u32_leb(PROFILE_1_LIMITS.max_functions);
    defined_functions.resize(
        defined_functions.len() + PROFILE_1_LIMITS.max_functions as usize,
        0x00,
    );
    append_section(&mut aggregate_functions, 3, &defined_functions);
    assert_predecode_rejection(
        "imported-plus-defined-functions-limit-plus-one",
        &aggregate_functions,
        AdmissionDetail::Limit(LimitKind::Functions),
        &engine,
    );

    let mut aggregate_globals = module_header();
    append_single_import(&mut aggregate_globals, &[0x03, 0x7f, 0x00]);
    let mut defined_globals = u32_leb(PROFILE_1_LIMITS.max_globals);
    for _ in 0..PROFILE_1_LIMITS.max_globals {
        defined_globals.extend([0x7f, 0x00, 0x41, 0x00, 0x0b]);
    }
    append_section(&mut aggregate_globals, 6, &defined_globals);
    assert_predecode_rejection(
        "imported-plus-defined-globals-limit-plus-one",
        &aggregate_globals,
        AdmissionDetail::Limit(LimitKind::Globals),
        &engine,
    );

    let mut aggregate_tables = module_header();
    append_single_import(&mut aggregate_tables, &[0x01, 0x70, 0x01, 0x00, 0x00]);
    append_section(&mut aggregate_tables, 4, &[0x01, 0x70, 0x01, 0x00, 0x00]);
    assert_predecode_rejection(
        "imported-plus-defined-tables-limit-plus-one",
        &aggregate_tables,
        AdmissionDetail::Limit(LimitKind::Tables),
        &engine,
    );

    let mut aggregate_memories = module_header();
    append_single_import(&mut aggregate_memories, &[0x02, 0x01, 0x00, 0x00]);
    append_section(&mut aggregate_memories, 5, &[0x01, 0x01, 0x00, 0x00]);
    assert_predecode_rejection(
        "imported-plus-defined-memories-limit-plus-one",
        &aggregate_memories,
        AdmissionDetail::Limit(LimitKind::Memories),
        &engine,
    );

    let mut oversized_imported_table = module_header();
    let mut imported_table_descriptor = vec![0x01, 0x70, 0x01];
    imported_table_descriptor.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements + 1));
    imported_table_descriptor.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements + 1));
    append_single_import(&mut oversized_imported_table, &imported_table_descriptor);
    assert_predecode_rejection(
        "imported-table-elements-limit-plus-one",
        &oversized_imported_table,
        AdmissionDetail::Limit(LimitKind::TableElements),
        &engine,
    );

    let mut oversized_imported_memory = module_header();
    let mut imported_memory_descriptor = vec![0x02, 0x01];
    imported_memory_descriptor.extend(u32_leb(PROFILE_1_LIMITS.max_initial_memory_pages + 1));
    imported_memory_descriptor.extend(u32_leb(PROFILE_1_LIMITS.max_initial_memory_pages + 1));
    append_single_import(&mut oversized_imported_memory, &imported_memory_descriptor);
    assert_predecode_rejection(
        "imported-initial-memory-pages-limit-plus-one",
        &oversized_imported_memory,
        AdmissionDetail::Limit(LimitKind::InitialMemoryPages),
        &engine,
    );

    let element_module = |item_counts: &[u32], complete_items: usize| {
        let mut module = module_header();
        append_section(&mut module, 1, &[0x01, 0x60, 0x00, 0x00]);
        append_section(&mut module, 3, &[0x01, 0x00]);
        let mut table = vec![0x01, 0x70, 0x01];
        table.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements));
        table.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements));
        append_section(&mut module, 4, &table);

        let mut elements = u32_leb(item_counts.len().try_into().unwrap());
        for (index, count) in item_counts.iter().enumerate() {
            elements.extend([0x00, 0x41, 0x00, 0x0b]);
            elements.extend(u32_leb(*count));
            if index < complete_items {
                elements.resize(elements.len() + *count as usize, 0x00);
            }
        }
        append_section(&mut module, 9, &elements);
        module
    };
    let element_items = element_module(&[PROFILE_1_LIMITS.max_table_elements + 1], 0);
    assert_predecode_rejection(
        "element-items-limit-plus-one",
        &element_items,
        AdmissionDetail::Limit(LimitKind::TableElements),
        &engine,
    );
    let aggregate_element_items = element_module(
        &[
            PROFILE_1_LIMITS.max_table_elements / 2,
            PROFILE_1_LIMITS.max_table_elements / 2 + 1,
        ],
        1,
    );
    assert_predecode_rejection(
        "aggregate-element-items-limit-plus-one",
        &aggregate_element_items,
        AdmissionDetail::Limit(LimitKind::TableElements),
        &engine,
    );
    let maximal_element_items = element_module(&[u32::MAX], 0);
    let maximal_element_stats = assert_predecode_rejection(
        "element-items-u32-max",
        &maximal_element_items,
        AdmissionDetail::Limit(LimitKind::TableElements),
        &engine,
    );
    let element_stats = assert_predecode_rejection(
        "element-items-limit-plus-one-repeat",
        &element_items,
        AdmissionDetail::Limit(LimitKind::TableElements),
        &engine,
    );
    assert_eq!(
        maximal_element_stats, element_stats,
        "declared element-item magnitude influenced allocation"
    );

    let mut malformed_element_flags = module_header();
    append_section(&mut malformed_element_flags, 9, &[0x01, 0x08]);
    assert_predecode_rejection(
        "element-flags-high-bit",
        &malformed_element_flags,
        AdmissionDetail::Malformed,
        &engine,
    );

    let explicit_rec_group = |inner_count| {
        let mut module = module_header();
        let mut type_payload = vec![0x01, 0x4e];
        type_payload.extend(u32_leb(inner_count));
        append_section(&mut module, 1, &type_payload);
        module
    };
    let shallow_rec_group = explicit_rec_group(1);
    let shallow_rec_group_stats = assert_predecode_rejection(
        "disabled-rec-group-one-type",
        &shallow_rec_group,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    let allocating_rec_group = explicit_rec_group(PROFILE_1_LIMITS.max_types + 1);
    let allocating_rec_group_stats = assert_predecode_rejection(
        "disabled-rec-group-profile-limit-plus-one-types",
        &allocating_rec_group,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    assert_eq!(
        allocating_rec_group_stats, shallow_rec_group_stats,
        "recursive-group type count influenced predecode allocation"
    );

    let mut parameters = module_header();
    let mut parameter_payload = vec![0x01, 0x60];
    parameter_payload.extend(u32_leb(PROFILE_1_LIMITS.max_params_per_function + 1));
    append_section(&mut parameters, 1, &parameter_payload);
    assert_predecode_rejection(
        "parameter-count-limit-plus-one",
        &parameters,
        AdmissionDetail::Limit(LimitKind::Parameters),
        &engine,
    );

    let mut results = module_header();
    let mut result_payload = vec![0x01, 0x60, 0x00];
    result_payload.extend(u32_leb(PROFILE_1_LIMITS.max_results_per_function + 1));
    append_section(&mut results, 1, &result_payload);
    assert_predecode_rejection(
        "result-count-limit-plus-one",
        &results,
        AdmissionDetail::Limit(LimitKind::Results),
        &engine,
    );

    let mut locals_body = vec![0x01];
    locals_body.extend(u32_leb(PROFILE_1_LIMITS.max_locals_per_function + 1));
    locals_body.extend([0x7f, 0x0b]);
    let locals = module_with_one_function(&locals_body);
    assert_predecode_rejection(
        "locals-limit-plus-one",
        &locals,
        AdmissionDetail::Limit(LimitKind::Locals),
        &engine,
    );

    let mut nesting_body = vec![0x00];
    for _ in 0..=PROFILE_1_LIMITS.max_core_nesting {
        nesting_body.extend([0x02, 0x40]);
    }
    nesting_body.extend(std::iter::repeat_n(
        0x0b,
        PROFILE_1_LIMITS.max_core_nesting as usize + 2,
    ));
    let nesting = module_with_one_function(&nesting_body);
    assert_predecode_rejection(
        "control-nesting-limit-plus-one",
        &nesting,
        AdmissionDetail::Limit(LimitKind::CoreNesting),
        &engine,
    );

    let typed_select_one = vec![0x00, 0x1c, 0x01, 0x7f, 0x0b];
    let typed_select_one = module_with_one_function(&typed_select_one);
    let typed_select_one_stats = assert_predecode_rejection(
        "disabled-typed-select-one-result",
        &typed_select_one,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    const WASMPARSER_SELECT_RESULT_CEILING: u32 = 10;
    let mut typed_select_many = vec![0x00, 0x1c];
    typed_select_many.extend(u32_leb(WASMPARSER_SELECT_RESULT_CEILING));
    typed_select_many.resize(
        typed_select_many.len() + WASMPARSER_SELECT_RESULT_CEILING as usize,
        0x7f,
    );
    typed_select_many.push(0x0b);
    let typed_select_many = module_with_one_function(&typed_select_many);
    let typed_select_many_stats = assert_predecode_rejection(
        "disabled-typed-select-upstream-max-results",
        &typed_select_many,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    assert_eq!(
        typed_select_many_stats, typed_select_one_stats,
        "typed-select result count influenced predecode allocation"
    );

    let try_table = |catch_count: u32| {
        let mut body = vec![0x00, 0x1f, 0x40];
        body.extend(u32_leb(catch_count));
        for _ in 0..catch_count {
            // catch_all label 0
            body.extend([0x02, 0x00]);
        }
        body.extend([0x0b, 0x0b]);
        module_with_one_function(&body)
    };
    let shallow_try_table = try_table(1);
    let shallow_try_table_stats = assert_predecode_rejection(
        "disabled-try-table-one-catch",
        &shallow_try_table,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    let allocating_try_table = try_table(64);
    let allocating_try_table_stats = assert_predecode_rejection(
        "disabled-try-table-64-catches",
        &allocating_try_table,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    assert_eq!(
        allocating_try_table_stats, shallow_try_table_stats,
        "try-table catch count influenced predecode allocation"
    );

    let resume_table = |handler_count: u32| {
        let mut body = vec![0x00, 0xe3, 0x00];
        body.extend(u32_leb(handler_count));
        for _ in 0..handler_count {
            // on-switch tag 0
            body.extend([0x01, 0x00]);
        }
        body.push(0x0b);
        module_with_one_function(&body)
    };
    let shallow_resume_table = resume_table(1);
    let shallow_resume_table_stats = assert_predecode_rejection(
        "disabled-resume-table-one-handler",
        &shallow_resume_table,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    let allocating_resume_table = resume_table(64);
    let allocating_resume_table_stats = assert_predecode_rejection(
        "disabled-resume-table-64-handlers",
        &allocating_resume_table,
        AdmissionDetail::UnsupportedFeature,
        &engine,
    );
    assert_eq!(
        allocating_resume_table_stats, shallow_resume_table_stats,
        "resume-table handler count influenced predecode allocation"
    );

    let nested_const_expr = |section: u8, prefix: &[u8], blocks: usize| {
        let mut module = module_header();
        let mut payload = prefix.to_vec();
        for _ in 0..blocks {
            payload.extend([0x02, 0x40]);
        }
        payload.resize(payload.len() + blocks + 1, 0x0b);
        append_section(&mut module, section, &payload);
        module
    };
    for (label, section, prefix) in [
        ("global-init", 6, &[0x01, 0x7f, 0x00][..]),
        ("table-init", 4, &[0x01, 0x40, 0x00][..]),
        ("data-offset", 11, &[0x01, 0x00][..]),
    ] {
        let shallow = nested_const_expr(section, prefix, 1);
        let deep = nested_const_expr(
            section,
            prefix,
            PROFILE_1_LIMITS.max_core_nesting as usize + 1,
        );
        let shallow_stats = assert_predecode_rejection(
            &format!("{label}-unsupported-const-expr"),
            &shallow,
            AdmissionDetail::UnsupportedFeature,
            &engine,
        );
        let deep_stats = assert_predecode_rejection(
            &format!("{label}-deep-unsupported-const-expr"),
            &deep,
            AdmissionDetail::UnsupportedFeature,
            &engine,
        );
        assert_eq!(
            deep_stats, shallow_stats,
            "{label} nesting influenced predecode allocation"
        );
    }

    let truncated_data = |length| {
        let mut module = module_header();
        let mut data = vec![0x01, 0x00, 0x41, 0x00, 0x0b];
        data.extend(u32_leb(length));
        append_section(&mut module, 11, &data);
        module
    };
    let short_data = truncated_data(1);
    let maximal_data = truncated_data(u32::MAX);
    let short_data_stats = assert_predecode_rejection(
        "data-byte-length-truncated",
        &short_data,
        AdmissionDetail::Malformed,
        &engine,
    );
    let maximal_data_stats = assert_predecode_rejection(
        "data-byte-length-u32-max",
        &maximal_data,
        AdmissionDetail::Malformed,
        &engine,
    );
    assert_eq!(
        maximal_data_stats, short_data_stats,
        "declared data length influenced allocation"
    );

    let mut table_payload = vec![0x01, 0x70, 0x01];
    table_payload.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements + 1));
    table_payload.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements + 1));
    let mut table_elements = module_header();
    append_section(&mut table_elements, 4, &table_payload);
    assert_predecode_rejection(
        "table-elements-limit-plus-one",
        &table_elements,
        AdmissionDetail::Limit(LimitKind::TableElements),
        &engine,
    );

    let mut truncated_table = module_header();
    append_section(&mut truncated_table, 4, &[0x01]);
    truncated_table.push(0x40);
    assert_predecode_rejection(
        "truncated-table-does-not-read-next-section-byte",
        &truncated_table,
        AdmissionDetail::Malformed,
        &engine,
    );

    let mut memory_payload = vec![0x01, 0x01];
    memory_payload.extend(u32_leb(PROFILE_1_LIMITS.max_initial_memory_pages + 1));
    memory_payload.extend(u32_leb(PROFILE_1_LIMITS.max_initial_memory_pages + 1));
    let mut memory_pages = module_header();
    append_section(&mut memory_pages, 5, &memory_payload);
    assert_predecode_rejection(
        "initial-memory-pages-limit-plus-one",
        &memory_pages,
        AdmissionDetail::Limit(LimitKind::InitialMemoryPages),
        &engine,
    );

    let mut maximum_memory_payload = vec![0x01, 0x01, 0x00];
    maximum_memory_payload.extend(u32_leb(PROFILE_1_LIMITS.max_memory_pages + 1));
    let mut maximum_memory_pages = module_header();
    append_section(&mut maximum_memory_pages, 5, &maximum_memory_payload);
    assert_predecode_rejection(
        "maximum-memory-pages-limit-plus-one",
        &maximum_memory_pages,
        AdmissionDetail::Limit(LimitKind::MemoryPages),
        &engine,
    );

    let data_count = module_with_count_section(12, PROFILE_1_LIMITS.max_data_segments + 1);
    assert_predecode_rejection(
        "declared-data-count-limit-plus-one",
        &data_count,
        AdmissionDetail::Limit(LimitKind::DataSegments),
        &engine,
    );

    let mut compact_imports = module_header();
    append_section(&mut compact_imports, 1, &[0x01, 0x60, 0x00, 0x00]);
    let mut compact_import_payload = vec![0x01, 0x01, b'm', 0x00, 0x7e, 0x00, 0x00];
    compact_import_payload.extend(u32_leb(PROFILE_1_LIMITS.max_imports + 1));
    compact_import_payload.resize(
        compact_import_payload.len() + PROFILE_1_LIMITS.max_imports as usize + 1,
        0x00,
    );
    append_section(&mut compact_imports, 2, &compact_import_payload);
    assert_predecode_rejection(
        "compact-import-flattened-count-limit-plus-one",
        &compact_imports,
        AdmissionDetail::Limit(LimitKind::Imports),
        &engine,
    );

    let mut custom_count = module_header();
    for _ in 0..=PROFILE_1_LIMITS.max_custom_sections {
        append_section(&mut custom_count, 0, &[0x00]);
    }
    assert_predecode_rejection(
        "custom-section-count-limit-plus-one",
        &custom_count,
        AdmissionDetail::Limit(LimitKind::CustomSections),
        &engine,
    );

    let mut custom_payload = Vec::with_capacity(PROFILE_1_LIMITS.max_custom_section_bytes + 2);
    custom_payload.push(0x00);
    custom_payload.resize(PROFILE_1_LIMITS.max_custom_section_bytes + 1, 0x00);
    let mut custom_bytes = module_header();
    append_section(&mut custom_bytes, 0, &custom_payload);
    assert_predecode_rejection(
        "custom-section-bytes-limit-plus-one",
        &custom_bytes,
        AdmissionDetail::Limit(LimitKind::CustomSectionBytes),
        &engine,
    );

    let mut oversized_custom_name_payload = u32_leb(
        (PROFILE_1_LIMITS.max_custom_section_bytes + 1)
            .try_into()
            .unwrap(),
    );
    oversized_custom_name_payload.resize(
        oversized_custom_name_payload.len() + PROFILE_1_LIMITS.max_custom_section_bytes + 1,
        b'n',
    );
    let mut oversized_custom_name = module_header();
    append_section(
        &mut oversized_custom_name,
        0,
        &oversized_custom_name_payload,
    );
    assert_predecode_rejection(
        "custom-section-name-limit-plus-one",
        &oversized_custom_name,
        AdmissionDetail::Limit(LimitKind::CustomSectionBytes),
        &engine,
    );

    let mut aggregate_custom_bytes = module_header();
    let first_custom = vec![0x00; PROFILE_1_LIMITS.max_custom_section_bytes / 2];
    let second_custom = vec![0x00; PROFILE_1_LIMITS.max_custom_section_bytes / 2 + 1];
    append_section(&mut aggregate_custom_bytes, 0, &first_custom);
    append_section(&mut aggregate_custom_bytes, 0, &second_custom);
    assert_predecode_rejection(
        "aggregate-custom-section-bytes-limit-plus-one",
        &aggregate_custom_bytes,
        AdmissionDetail::Limit(LimitKind::CustomSectionBytes),
        &engine,
    );
}

#[test]
fn disabled_multi_value_stays_closed_at_the_numeric_result_ceiling() {
    let mut results = module_header();
    let mut result_type = vec![0x01, 0x60, 0x00];
    result_type.extend(u32_leb(PROFILE_1_LIMITS.max_results_per_function));
    result_type.resize(
        result_type.len() + PROFILE_1_LIMITS.max_results_per_function as usize,
        0x7f,
    );
    append_section(&mut results, 1, &result_type);
    assert_eq!(
        inspect_core(&results).unwrap_err().detail,
        AdmissionDetail::UnsupportedFeature,
        "the numerical result ceiling must not enable multi-value"
    );
}

#[test]
fn enabled_profile_ceilings_are_admitted_and_reported() {
    let mut types = module_header();
    let mut type_payload = u32_leb(PROFILE_1_LIMITS.max_types);
    for _ in 0..PROFILE_1_LIMITS.max_types {
        type_payload.extend([0x60, 0x00, 0x00]);
    }
    append_section(&mut types, 1, &type_payload);
    assert_eq!(
        inspect_core(&types).unwrap().types,
        PROFILE_1_LIMITS.max_types
    );

    let mut parameters = module_header();
    let mut parameter_type = vec![0x01, 0x60];
    parameter_type.extend(u32_leb(PROFILE_1_LIMITS.max_params_per_function));
    parameter_type.resize(
        parameter_type.len() + PROFILE_1_LIMITS.max_params_per_function as usize,
        0x7f,
    );
    parameter_type.push(0x00);
    append_section(&mut parameters, 1, &parameter_type);
    assert_eq!(
        inspect_core(&parameters).unwrap().max_params,
        PROFILE_1_LIMITS.max_params_per_function
    );

    let mut imports = module_header();
    append_section(&mut imports, 1, &[0x01, 0x60, 0x00, 0x00]);
    let mut import_payload = u32_leb(PROFILE_1_LIMITS.max_imports);
    for _ in 0..PROFILE_1_LIMITS.max_imports {
        import_payload.extend([0x01, b'm', 0x00, 0x00, 0x00]);
    }
    append_section(&mut imports, 2, &import_payload);
    assert_eq!(
        inspect_core(&imports).unwrap().imports,
        PROFILE_1_LIMITS.max_imports
    );

    let mut functions = module_header();
    append_section(&mut functions, 1, &[0x01, 0x60, 0x00, 0x00]);
    let mut function_payload = u32_leb(PROFILE_1_LIMITS.max_functions);
    function_payload.resize(
        function_payload.len() + PROFILE_1_LIMITS.max_functions as usize,
        0,
    );
    append_section(&mut functions, 3, &function_payload);
    let mut code_payload = u32_leb(PROFILE_1_LIMITS.max_functions);
    for _ in 0..PROFILE_1_LIMITS.max_functions {
        code_payload.extend([0x02, 0x00, 0x0b]);
    }
    append_section(&mut functions, 10, &code_payload);
    assert_eq!(
        inspect_core(&functions).unwrap().functions,
        PROFILE_1_LIMITS.max_functions
    );

    let mut globals = module_header();
    let mut global_payload = u32_leb(PROFILE_1_LIMITS.max_globals);
    for _ in 0..PROFILE_1_LIMITS.max_globals {
        global_payload.extend([0x7f, 0x00, 0x41, 0x00, 0x0b]);
    }
    append_section(&mut globals, 6, &global_payload);
    assert_eq!(
        inspect_core(&globals).unwrap().globals,
        PROFILE_1_LIMITS.max_globals
    );

    let mut exports = module_header();
    append_section(&mut exports, 1, &[0x01, 0x60, 0x00, 0x00]);
    append_section(&mut exports, 3, &[0x01, 0x00]);
    let mut export_payload = u32_leb(PROFILE_1_LIMITS.max_exports);
    for index in 0..PROFILE_1_LIMITS.max_exports {
        let name = format!("export-{index}");
        export_payload.extend(u32_leb(name.len().try_into().unwrap()));
        export_payload.extend_from_slice(name.as_bytes());
        export_payload.extend([0x00, 0x00]);
    }
    append_section(&mut exports, 7, &export_payload);
    append_section(&mut exports, 10, &[0x01, 0x02, 0x00, 0x0b]);
    assert_eq!(
        inspect_core(&exports).unwrap().exports,
        PROFILE_1_LIMITS.max_exports
    );

    let mut locals_body = vec![0x01];
    locals_body.extend(u32_leb(PROFILE_1_LIMITS.max_locals_per_function));
    locals_body.extend([0x7f, 0x0b]);
    let locals = inspect_core(&module_with_one_function(&locals_body)).unwrap();
    assert_eq!(locals.locals, PROFILE_1_LIMITS.max_locals_per_function);

    let mut nesting_body = vec![0x00];
    for _ in 0..PROFILE_1_LIMITS.max_core_nesting {
        nesting_body.extend([0x02, 0x40]);
    }
    nesting_body.extend(std::iter::repeat_n(
        0x0b,
        PROFILE_1_LIMITS.max_core_nesting as usize + 1,
    ));
    let nesting = inspect_core(&module_with_one_function(&nesting_body)).unwrap();
    assert_eq!(nesting.max_control_depth, PROFILE_1_LIMITS.max_core_nesting);

    let mut table_module = module_header();
    let mut table_payload = vec![0x01, 0x70, 0x01];
    table_payload.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements));
    table_payload.extend(u32_leb(PROFILE_1_LIMITS.max_table_elements));
    append_section(&mut table_module, 4, &table_payload);
    let table = inspect_core(&table_module).unwrap();
    assert_eq!(table.tables, PROFILE_1_LIMITS.max_tables);

    let mut memory_module = module_header();
    let mut memory_payload = vec![0x01, 0x01];
    memory_payload.extend(u32_leb(PROFILE_1_LIMITS.max_initial_memory_pages));
    memory_payload.extend(u32_leb(PROFILE_1_LIMITS.max_memory_pages));
    append_section(&mut memory_module, 5, &memory_payload);
    let memory = inspect_core(&memory_module).unwrap();
    assert_eq!(memory.memories, PROFILE_1_LIMITS.max_memories);

    let mut data_module = memory_module.clone();
    let mut data_payload = u32_leb(PROFILE_1_LIMITS.max_data_segments);
    for _ in 0..PROFILE_1_LIMITS.max_data_segments {
        data_payload.extend([0x00, 0x41, 0x00, 0x0b, 0x00]);
    }
    append_section(&mut data_module, 11, &data_payload);
    assert_eq!(
        inspect_core(&data_module).unwrap().data_segments,
        PROFILE_1_LIMITS.max_data_segments
    );

    let mut element_module = module_header();
    append_section(&mut element_module, 1, &[0x01, 0x60, 0x00, 0x00]);
    append_section(&mut element_module, 3, &[0x01, 0x00]);
    append_section(&mut element_module, 4, &table_payload);
    let mut element_payload = u32_leb(PROFILE_1_LIMITS.max_element_segments);
    let items_per_segment =
        PROFILE_1_LIMITS.max_table_elements / PROFILE_1_LIMITS.max_element_segments;
    assert_eq!(
        items_per_segment * PROFILE_1_LIMITS.max_element_segments,
        PROFILE_1_LIMITS.max_table_elements
    );
    for _ in 0..PROFILE_1_LIMITS.max_element_segments {
        element_payload.extend([0x00, 0x41, 0x00, 0x0b]);
        element_payload.extend(u32_leb(items_per_segment));
        element_payload.resize(element_payload.len() + items_per_segment as usize, 0x00);
    }
    append_section(&mut element_module, 9, &element_payload);
    append_section(&mut element_module, 10, &[0x01, 0x02, 0x00, 0x0b]);
    let elements = inspect_core(&element_module).unwrap();
    assert_eq!(
        elements.element_segments,
        PROFILE_1_LIMITS.max_element_segments
    );
    assert_eq!(elements.element_items, PROFILE_1_LIMITS.max_table_elements);

    let mut custom = module_header();
    for _ in 1..PROFILE_1_LIMITS.max_custom_sections {
        append_section(&mut custom, 0, &[0x00]);
    }
    let final_custom_payload_bytes = PROFILE_1_LIMITS
        .max_custom_section_bytes
        .checked_sub(PROFILE_1_LIMITS.max_custom_sections as usize - 1)
        .unwrap();
    let final_custom = vec![0x00; final_custom_payload_bytes];
    append_section(&mut custom, 0, &final_custom);
    let custom_summary = inspect_core(&custom).unwrap();
    assert_eq!(
        custom_summary.custom_sections,
        PROFILE_1_LIMITS.max_custom_sections
    );
    assert_eq!(
        custom_summary.custom_section_bytes as usize,
        PROFILE_1_LIMITS.max_custom_section_bytes
    );

    let module_with_nops = |nops: usize| {
        let mut body = Vec::with_capacity(nops + 2);
        body.push(0x00);
        body.resize(nops + 1, 0x01);
        body.push(0x0b);
        module_with_one_function(&body)
    };
    let mut nops = PROFILE_1_LIMITS.max_core_module_bytes - 32;
    let exact_length = loop {
        let module = module_with_nops(nops);
        match module.len().cmp(&PROFILE_1_LIMITS.max_core_module_bytes) {
            std::cmp::Ordering::Equal => break module,
            std::cmp::Ordering::Less => {
                nops += PROFILE_1_LIMITS.max_core_module_bytes - module.len();
            }
            std::cmp::Ordering::Greater => {
                nops -= module.len() - PROFILE_1_LIMITS.max_core_module_bytes;
            }
        }
    };
    let exact_length_summary = inspect_core(&exact_length).unwrap();
    assert_eq!(
        exact_length_summary.bytes as usize,
        PROFILE_1_LIMITS.max_core_module_bytes
    );
}
