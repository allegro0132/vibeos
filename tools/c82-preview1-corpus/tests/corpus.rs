use std::{fs, process::Command, time::SystemTime};

use vibeos_c82_preview1_corpus::{
    componentize_corpus_core, sanitize_compiler_core, OutputDirection, OutputKind, TransformError,
};
use wasmparser::{Encoding, Parser, Payload, Validator, WasmFeatures};

const ADAPTER: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../policy/image/artifacts/c81-wasmtime-v48.0.0-preview1-command-adapter.wasm"
));

const TYPES: &str = r#"
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32 i32 i32 i32) (result i32)))
  (type (func (param i32)))
  (type (func))
"#;

const EXACT_IMPORTS: &str = r#"
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (type 0)))
  (import "wasi_snapshot_preview1" "args_get" (func (type 0)))
  (import "wasi_snapshot_preview1" "fd_read" (func (type 1)))
  (import "wasi_snapshot_preview1" "fd_write" (func (type 1)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (type 2)))
"#;

fn compiler_core(global: &str, body: &str, extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (module
          {TYPES}
          {EXACT_IMPORTS}
          (memory (export "memory") 2 16)
          {global}
          (func (export "_start") (type 3)
            {body})
          {extra}
        )
        "#
    ))
    .expect("test Core WAT must compile")
}

fn exact_compiler_core() -> Vec<u8> {
    compiler_core("(global (mut i32) (i32.const 65536))", "", "")
}

#[test]
fn compiler_core_input_is_bounded_before_parsing() {
    let oversized = vec![0; 512 * 1024 + 1];
    assert_eq!(
        sanitize_compiler_core(&oversized),
        Err(TransformError::CoreTooLarge)
    );
}

#[test]
fn declared_gc_groups_do_not_reach_the_allocating_validator() {
    let mut hostile = b"\0asm\x01\0\0\0".to_vec();
    // One rec-group claims u32::MAX inner types in a seven-byte type payload.
    hostile.extend_from_slice(&[1, 7, 1, 0x4e, 0xff, 0xff, 0xff, 0xff, 0x0f]);
    // One otherwise exact private mutable i32 stack pointer initialized to 65536.
    hostile.extend_from_slice(&[6, 8, 1, 0x7f, 1, 0x41, 0x80, 0x80, 0x04, 0x0b]);
    assert_eq!(
        sanitize_compiler_core(&hostile),
        Err(TransformError::RuntimeCoreRejection)
    );
}

fn has_global_section(bytes: &[u8]) -> bool {
    Parser::new(0)
        .parse_all(bytes)
        .any(|payload| matches!(payload, Ok(Payload::GlobalSection(_))))
}

fn append_custom_section(module: &mut Vec<u8>, name: &str, data: &[u8]) {
    fn push_u32_leb(bytes: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    let mut payload = Vec::new();
    push_u32_leb(&mut payload, name.len() as u32);
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(data);
    module.push(0);
    push_u32_leb(module, payload.len() as u32);
    module.extend_from_slice(&payload);
}

#[test]
fn unused_compiler_stack_pointer_is_removed_and_componentization_is_inert() {
    let compiler = exact_compiler_core();
    assert!(has_global_section(&compiler));

    let sanitized = sanitize_compiler_core(&compiler).expect("exact compiler Core must sanitize");
    assert!(!has_global_section(sanitized.bytes()));
    assert_eq!(
        sanitized.report().compiler_core_bytes - sanitized.report().sanitized_core_bytes,
        sanitized.report().removed_global_section_bytes
    );
    assert_eq!(sanitized.report().removed_global_section_bytes, 10);
    assert_eq!(sanitized.report().stack_pointer_value, 65_536);
    assert_eq!(sanitized.report().global_references, 0);
    assert_eq!(
        vibeos_wasm_runtime::inspect_core(sanitized.bytes())
            .unwrap()
            .globals,
        0
    );

    let first = componentize_corpus_core(&compiler, ADAPTER).expect("exact Core must wrap");
    let second = componentize_corpus_core(&compiler, ADAPTER).expect("repeat must wrap");
    assert_eq!(first.sanitized_core().bytes(), sanitized.bytes());
    assert_eq!(first.component_bytes(), second.component_bytes());
    assert_eq!(first.pins(), second.pins());
    let report = first.report();
    assert_eq!(report.outer_imports, 10);
    assert_eq!(report.outer_exports, 1);
    assert_eq!(report.embedded_core_modules, 4);
    assert_eq!(report.nested_components, 1);
    assert_eq!(report.canonical_lowers, 18);
    assert!(!report.runtime_ready);
    assert_eq!(report.guest_calls, 0);
    assert_eq!(
        first.pins().embedded_core_modules[0].raw_sha256,
        sanitized.report().sanitized_core_sha256
    );
    assert!(first.pins().entries.iter().all(|entry| {
        entry.kind == OutputKind::Instance
            && matches!(
                entry.direction,
                OutputDirection::Import | OutputDirection::Export
            )
    }));
}

#[test]
fn stack_pointer_shape_and_privacy_are_exact() {
    for global in [
        "",
        "(global i32 (i32.const 65536))",
        "(global (mut i64) (i64.const 65536))",
        "(global (mut i32) (i32.const 65535))",
        "(global (mut i32) (i32.const 65536)) (global i32 (i32.const 0))",
    ] {
        assert_eq!(
            sanitize_compiler_core(&compiler_core(global, "", "")),
            Err(TransformError::InvalidStackPointerProof),
            "{global}"
        );
    }

    let exported = compiler_core(
        "(global (export \"stack\") (mut i32) (i32.const 65536))",
        "",
        "",
    );
    assert_eq!(
        sanitize_compiler_core(&exported),
        Err(TransformError::InvalidStackPointerProof)
    );

    let imported = wat::parse_str(format!(
        r#"
        (module
          {TYPES}
          (import "private" "stack" (global i32))
          {EXACT_IMPORTS}
          (memory (export "memory") 2 16)
          (global (mut i32) (i32.const 65536))
          (func (export "_start") (type 3)))
        "#
    ))
    .expect("imported global mutation must compile");
    assert_eq!(
        sanitize_compiler_core(&imported),
        Err(TransformError::InvalidStackPointerProof)
    );
}

#[test]
fn every_code_and_const_expression_global_reference_is_rejected() {
    for body in ["global.get 0 drop", "i32.const 0 global.set 0"] {
        assert_eq!(
            sanitize_compiler_core(&compiler_core(
                "(global (mut i32) (i32.const 65536))",
                body,
                ""
            )),
            Err(TransformError::GlobalReference),
            "{body}"
        );
    }

    let imported_const_reference = wat::parse_str(format!(
        r#"
        (module
          {TYPES}
          (import "private" "offset" (global i32))
          {EXACT_IMPORTS}
          (memory (export "memory") 2 16)
          (global (mut i32) (i32.const 65536))
          (func (export "_start") (type 3))
          (data (global.get 0) "x"))
        "#
    ))
    .expect("imported immutable global is valid in an MVP const expression");
    assert_eq!(
        sanitize_compiler_core(&imported_const_reference),
        Err(TransformError::GlobalReference)
    );
}

#[test]
fn custom_sections_are_rejected_before_index_metadata_can_go_stale() {
    let mut compiler = exact_compiler_core();
    append_custom_section(&mut compiler, "name", b"\x02\x01\x00");
    assert_eq!(
        sanitize_compiler_core(&compiler),
        Err(TransformError::CustomSection)
    );
}

fn custom_guest(imports: &str, memory: &str, function: &str, extra: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"
        (module
          {TYPES}
          {imports}
          {memory}
          (global (mut i32) (i32.const 65536))
          {function}
          {extra})
        "#
    ))
    .expect("test mutation WAT must compile")
}

#[test]
fn only_the_exact_five_function_imports_are_accepted() {
    let mutations = [
        EXACT_IMPORTS.replace("wasi_snapshot_preview1", "wasi_unstable"),
        EXACT_IMPORTS.replace("args_get\" (func (type 0))", "environ_get\" (func (type 0))"),
        EXACT_IMPORTS.replace("args_get\" (func (type 0))", "args_get\" (func (type 2))"),
        format!(
            "{EXACT_IMPORTS}\n(import \"wasi_snapshot_preview1\" \"environ_sizes_get\" (func (type 0)))"
        ),
        format!(
            "{EXACT_IMPORTS}\n(import \"wasi_snapshot_preview1\" \"fd_write\" (func (type 1)))"
        ),
    ];
    for imports in mutations {
        let compiler = custom_guest(
            &imports,
            "(memory (export \"memory\") 2 16)",
            "(func (export \"_start\") (type 3))",
            "",
        );
        assert!(matches!(
            sanitize_compiler_core(&compiler),
            Err(TransformError::SanitizedGuestContract | TransformError::RuntimeCoreRejection)
        ));
    }
}

#[test]
fn memory_exports_start_and_tables_are_closed() {
    for memory in [
        "(memory (export \"memory\") 1 16)",
        "(memory (export \"memory\") 2 15)",
        "(memory (export \"memory\") 2)",
        "(memory (export \"memory\") 2 16) (memory 1 1)",
    ] {
        let compiler = custom_guest(
            EXACT_IMPORTS,
            memory,
            "(func (export \"_start\") (type 3))",
            "",
        );
        assert!(sanitize_compiler_core(&compiler).is_err(), "{memory}");
    }

    for (function, extra) in [
        ("(func (export \"run\") (type 3))", ""),
        ("(func (export \"_start\") (export \"extra\") (type 3))", ""),
        ("(func (export \"_start\") (type 3))", "(start 5)"),
        ("(func (export \"_start\") (type 3))", "(table 0 0 funcref)"),
    ] {
        let compiler = custom_guest(
            EXACT_IMPORTS,
            "(memory (export \"memory\") 2 16)",
            function,
            extra,
        );
        assert!(matches!(
            sanitize_compiler_core(&compiler),
            Err(TransformError::SanitizedGuestContract | TransformError::RuntimeCoreRejection)
        ));
    }
}

#[test]
fn adapter_length_digest_and_component_validation_are_fresh() {
    let compiler = exact_compiler_core();
    assert_eq!(
        componentize_corpus_core(&compiler, &ADAPTER[..ADAPTER.len() - 1]),
        Err(TransformError::AdapterLength)
    );
    let mut changed = ADAPTER.to_vec();
    let middle = changed.len() / 2;
    changed[middle] ^= 1;
    assert_eq!(
        componentize_corpus_core(&compiler, &changed),
        Err(TransformError::AdapterDigest)
    );
}

#[test]
fn cli_writes_both_outputs_and_prints_exact_pins() {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "vibeos-c82-preview1-corpus-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let core_path = directory.join("compiler.core.wasm");
    let adapter_path = directory.join("adapter.wasm");
    let sanitized_path = directory.join("sanitized.core.wasm");
    let component_path = directory.join("wrapped.component.wasm");
    let compiler = exact_compiler_core();
    fs::write(&core_path, &compiler).unwrap();
    fs::write(&adapter_path, ADAPTER).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_vibeos-c82-preview1-corpus"))
        .args([
            "--core",
            core_path.to_str().unwrap(),
            "--adapter",
            adapter_path.to_str().unwrap(),
            "--sanitized-core-output",
            sanitized_path.to_str().unwrap(),
            "--output",
            component_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for marker in [
        "removed_global_section_bytes=10",
        "stack_pointer_value=65536",
        "global_references=0",
        "outer_imports=10",
        "outer_exports=1",
        "embedded_core_modules=4",
        "nested_components=1",
        "canonical_lowers=18",
        "runtime_ready=false",
        "guest_calls=0",
        "name=wasi:cli/environment@0.2.12",
        "name=wasi:cli/exit@0.2.12",
        "name=wasi:cli/run@0.2.12",
    ] {
        assert!(stdout.contains(marker), "missing {marker}\n{stdout}");
    }

    let library = componentize_corpus_core(&compiler, ADAPTER).unwrap();
    assert_eq!(
        fs::read(&sanitized_path).unwrap(),
        library.sanitized_core().bytes()
    );
    assert_eq!(
        fs::read(&component_path).unwrap(),
        library.component_bytes()
    );
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(&fs::read(&component_path).unwrap())
        .unwrap();
    assert!(matches!(
        Parser::new(0)
            .parse_all(&fs::read(&component_path).unwrap())
            .next(),
        Some(Ok(Payload::Version {
            encoding: Encoding::Component,
            ..
        }))
    ));

    fs::remove_dir_all(directory).unwrap();
}
