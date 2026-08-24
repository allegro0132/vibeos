use vibeos_c81_preview1_componentizer::{
    componentize_preview1, derive_output_pins, hex_sha256, sha256, OutputDirection, OutputKind,
    TransformError, ADAPTER_BYTES, ADAPTER_SHA256, CANONICAL_LOWERING_DOMAIN,
    FIXTURE_COMPONENT_BYTES, FIXTURE_COMPONENT_SHA256, FIXTURE_CORE_BYTES, FIXTURE_CORE_SHA256,
};

const CORE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policy/image/artifacts/c81-fd-write.core.wasm"
));
const ADAPTER: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policy/image/artifacts/c81-wasmtime-v48.0.0-preview1-command-adapter.wasm"
));
const COMPONENT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policy/image/artifacts/c81-fd-write.preview1-wrapped.component.wasm"
));

fn parse_core(extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (module
          (type $fd-write-type (func (param i32 i32 i32 i32) (result i32)))
          (type $start-type (func))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd-write (type $fd-write-type)))
          (memory $memory 1 16)
          (export "memory" (memory $memory))
          (func $_start (type $start-type)
            i32.const 1
            i32.const 0
            i32.const 0
            i32.const 0
            call $fd-write
            drop)
          (export "_start" (func $_start))
          {extra}
        )
        "#
    ))
    .expect("test WAT must compile")
}

fn parse_core_with_memory(memory: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (module
          (type $fd-write-type (func (param i32 i32 i32 i32) (result i32)))
          (type $start-type (func))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd-write (type $fd-write-type)))
          {memory}
          (export "memory" (memory 0))
          (func $_start (type $start-type))
          (export "_start" (func $_start))
        )
        "#
    ))
    .expect("test WAT must compile")
}

fn parse_core_instruction(instruction: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (module
          (type $fd-write-type (func (param i32 i32 i32 i32) (result i32)))
          (type $start-type (func))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd-write (type $fd-write-type)))
          (memory $memory 1 16)
          (export "memory" (memory $memory))
          (func $_start (type $start-type)
            {instruction})
          (export "_start" (func $_start))
        )
        "#
    ))
    .expect("test WAT must compile")
}

fn push_u32_leb(bytes: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn append_custom_section(module: &mut Vec<u8>, name: &str, data: &[u8]) {
    let name_len = u32::try_from(name.len()).expect("test custom name fits u32");
    let mut payload = Vec::new();
    push_u32_leb(&mut payload, name_len);
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(data);
    module.push(0);
    push_u32_leb(
        module,
        u32::try_from(payload.len()).expect("test custom payload fits u32"),
    );
    module.extend_from_slice(&payload);
}

#[test]
fn exact_fixture_is_deterministic_and_inert() {
    assert_eq!(CORE.len(), FIXTURE_CORE_BYTES);
    assert_eq!(sha256(CORE), FIXTURE_CORE_SHA256);
    assert_eq!(ADAPTER.len(), ADAPTER_BYTES);
    assert_eq!(sha256(ADAPTER), ADAPTER_SHA256);
    assert_eq!(COMPONENT.len(), FIXTURE_COMPONENT_BYTES);
    assert_eq!(sha256(COMPONENT), FIXTURE_COMPONENT_SHA256);

    let first = componentize_preview1(CORE, ADAPTER).expect("reviewed inputs must transform");
    let second = componentize_preview1(CORE, ADAPTER).expect("repeat must transform");
    assert_eq!(first.bytes(), COMPONENT);
    assert_eq!(second.bytes(), COMPONENT);
    assert_eq!(first.bytes(), second.bytes());

    let report = first.report();
    assert_eq!(report.outer_imports, 8);
    assert_eq!(report.outer_exports, 1);
    assert_eq!(report.embedded_core_modules, 4);
    assert_eq!(report.nested_components, 1);
    assert_eq!(report.canonical_lowers, 13);
    assert!(!report.runtime_ready);
    assert_eq!(report.guest_calls, 0);
}

#[test]
fn exact_outer_entries_and_lowering_fingerprint_are_derived_from_bytes() {
    assert_eq!(
        CANONICAL_LOWERING_DOMAIN,
        b"vibeos.preview1-wrapped.canonical-lowerings.v1\0"
    );
    let pins = derive_output_pins(COMPONENT).expect("reviewed component must inspect");
    let expected = [
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:cli/stderr@0.2.12",
            26,
            "6fc47ffb74b1b905a5b8fe1c467ea8199eb091ffb0e9e2874f7ac986a4a91a32",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:cli/stdin@0.2.12",
            25,
            "e5ff52618b9ebffbca4783de197eda34847f87c0a4351c0aea669cf7ba2db4a4",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:cli/stdout@0.2.12",
            26,
            "9f231e2d8ad27a675d433c795b154f0246ca22f8d600bda2ddc60e76c8aa9d25",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:clocks/wall-clock@0.2.12",
            33,
            "09d4e71704cfc40ffbd71d8481daab692c737df30fafc26d89e89a745f6116b7",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:filesystem/preopens@0.2.12",
            35,
            "cb5037f354e73e9b1ae3380e90d00371bdd943c720aa7d0e5727e9591c507a90",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:filesystem/types@0.2.12",
            32,
            "2fbf66c40479ed438de2ac00b156d8d88bbf38447c6b76449502be035d8849c5",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:io/error@0.2.12",
            24,
            "40fed392ca0fd40a1feff77e63776a6bdc059a2cf26cd60366f3f77d2b7cc344",
        ),
        (
            OutputDirection::Import,
            OutputKind::Instance,
            "wasi:io/streams@0.2.12",
            26,
            "9a16c9faac49b9dbf019eb4735259eb0d58ac3bc824867ab2aa374826ca95241",
        ),
        (
            OutputDirection::Export,
            OutputKind::Instance,
            "wasi:cli/run@0.2.12",
            24,
            "c2429760150a601023aa7883ffaf212116e2a304829b6aab11aaadb84e510478",
        ),
    ];
    assert_eq!(pins.entries.len(), expected.len());
    for (observed, expected) in pins.entries.iter().zip(expected) {
        assert_eq!(observed.direction, expected.0);
        assert_eq!(observed.kind, expected.1);
        assert_eq!(observed.name, expected.2);
        assert_eq!(observed.raw_bytes, expected.3);
        assert_eq!(hex_sha256(&observed.raw_sha256), expected.4);
    }
    let embedded = pins
        .embedded_core_modules
        .iter()
        .map(|module| {
            (
                module.ordinal,
                module.raw_bytes,
                hex_sha256(&module.raw_sha256),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        embedded,
        [
            (
                0,
                145,
                String::from("5ac1eb14874721c8355669fd91811f9a0165d96f1382ff82f08f3dfc0634bb0c")
            ),
            (
                1,
                9_581,
                String::from("96cbc60f3ef3ad13621236858694165e0b4dd02052ab38b875285e1aeafb4f66")
            ),
            (
                2,
                318,
                String::from("1e30d212a60962a6eefee3b6ba9249332aa0a430b7e3bacca792bf86ef89ae0e")
            ),
            (
                3,
                183,
                String::from("3c11674007ed6e8d74e99a1d2b52dc41cf1acd842f20ebd6e438593668d7d7ff")
            ),
        ]
    );
    assert_eq!(pins.canonical_lowers, 13);
    assert_eq!(
        hex_sha256(&pins.canonical_lowering_sha256),
        "a5f5d1b1b1a09d92718132121d367acef0aed6364b58b1aac3e70daef62701f8"
    );
}

#[test]
fn adapter_length_and_digest_are_both_pinned() {
    assert_eq!(
        componentize_preview1(CORE, &ADAPTER[..ADAPTER.len() - 1]),
        Err(TransformError::AdapterLength)
    );
    let mut changed = ADAPTER.to_vec();
    changed[ADAPTER.len() / 2] ^= 1;
    assert_eq!(
        componentize_preview1(CORE, &changed),
        Err(TransformError::AdapterDigest)
    );
}

#[test]
fn malformed_and_extra_import_guests_are_rejected() {
    let mut changed = CORE.to_vec();
    changed[0] ^= 1;
    assert_eq!(
        componentize_preview1(&changed, ADAPTER),
        Err(TransformError::MalformedCore)
    );

    let extra_import = wat::parse_str(
        r#"
        (module
          (type $fd (func (param i32 i32 i32 i32) (result i32)))
          (type $start (func))
          (import "wasi_snapshot_preview1" "fd_write" (func $fd-write (type $fd)))
          (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
          (memory (export "memory") 1 16)
          (func $_start (type $start))
          (export "_start" (func $_start))
        )
        "#,
    )
    .expect("test WAT must compile");
    assert_eq!(
        componentize_preview1(&extra_import, ADAPTER),
        Err(TransformError::GuestContract)
    );
}

#[test]
fn memory_must_be_single_bounded_wasm32_and_unshared() {
    for memory in [
        "(memory 1)",
        "(memory 1 300)",
        "(memory i64 1 16)",
        "(memory 1 16 shared)",
        "(memory 1 16) (memory 1 16)",
    ] {
        let core = parse_core_with_memory(memory);
        assert!(componentize_preview1(&core, ADAPTER).is_err(), "{memory}");
    }
}

#[test]
fn start_float_and_simd_extensions_are_rejected() {
    let explicit_start = parse_core("(start $_start)");
    assert_eq!(
        componentize_preview1(&explicit_start, ADAPTER),
        Err(TransformError::GuestContract)
    );

    for instruction in ["f32.const 0 drop", "v128.const i32x4 0 0 0 0 drop"] {
        let core = parse_core_instruction(instruction);
        assert_eq!(
            componentize_preview1(&core, ADAPTER),
            Err(TransformError::UnsupportedCoreFeature),
            "{instruction}"
        );
    }
}

#[test]
fn tables_globals_data_elements_and_extra_functions_are_rejected() {
    for extra in [
        "(table 1 1 funcref)",
        "(global i32 (i32.const 0))",
        r#"(data (i32.const 0) "x")"#,
        "(elem func $_start)",
        "(func $extra)",
    ] {
        let core = parse_core(extra);
        assert_eq!(
            componentize_preview1(&core, ADAPTER),
            Err(TransformError::GuestContract),
            "{extra}"
        );
    }
}

#[test]
fn only_one_bounded_name_custom_section_is_allowed() {
    let mut unexpected = CORE.to_vec();
    append_custom_section(&mut unexpected, "producers", b"x");
    assert_eq!(
        componentize_preview1(&unexpected, ADAPTER),
        Err(TransformError::GuestContract)
    );

    let mut duplicate_name = CORE.to_vec();
    append_custom_section(&mut duplicate_name, "name", &[]);
    assert_eq!(
        componentize_preview1(&duplicate_name, ADAPTER),
        Err(TransformError::GuestContract)
    );
}
