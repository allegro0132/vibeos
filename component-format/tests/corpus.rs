const WORLD: &str = include_str!("corpus/wit/world.wit");
const RESOURCES: &str = include_str!("corpus/wit/resources.wit");
const CLOCK: &str = include_str!("corpus/wit/clock.wit");
const BLOB: &str = include_str!("corpus/wit/blob.wit");
const LOG: &str = include_str!("corpus/wit/log.wit");
const STREAM: &str = include_str!("corpus/wit/stream.wit");
const CANONICAL_VALUES: &str = include_str!("corpus/wit/canonical-values.wit");
const VALID_CORE: &str = include_str!("corpus/core/integer.wat");
const LIMIT_CORE: &str = include_str!("corpus/core/limits.wat");
const UNSUPPORTED_CORE: &str = include_str!("corpus/core/unsupported-float.wat");
const VALID_COMPONENT: &str = include_str!("corpus/component/typed.component.wat");
const ASYNC_COMPONENT: &str = include_str!("corpus/component/async-0.255.0.component.wat");
const ASYNC_WORLD: &str = include_str!("corpus/wit/async-world.wit");
const NATIVE_ASYNC_STREAM_COMPONENT: &str =
    include_str!("corpus/component/native-async-stream-0.255.0.component.wat");
const NATIVE_ASYNC_SMOKE_COMPONENT: &str =
    include_str!("corpus/component/native-async-smoke-0.255.0.component.wat");
const MALFORMED_COMPONENT: &str = include_str!("corpus/component/malformed.hex");
const RUST_GUEST: &str = include_str!("corpus/guests/typed_guest.rs");
const C_GUEST: &str = include_str!("corpus/guests/typed_guest.c");

#[test]
fn corpus_covers_the_profile_contract() {
    for marker in [
        "record request",
        "variant response",
        "resource random-source",
        "borrow<random-source>",
        "list<u8>",
        "result<",
    ] {
        assert!(
            WORLD.contains(marker) || RESOURCES.contains(marker),
            "{marker}"
        );
    }
    for marker in [
        "package vibe:clock@1.0.0",
        "now: func(clock: borrow<clock>) -> u64",
    ] {
        assert!(CLOCK.contains(marker), "{marker}");
    }
    for marker in [
        "package vibe:blob@1.0.0",
        "len: func(blob: borrow<blob>) -> u64",
        "read: func(blob: borrow<blob>, offset: u64, len: u32)",
        "enum blob-error { denied, invalid, failed }",
    ] {
        assert!(BLOB.contains(marker), "{marker}");
    }
    for marker in [
        "package vibe:log@1.0.0",
        "record event",
        "write: func(log: borrow<structured-log>, event: event)",
        "enum log-error { denied, invalid, failed }",
    ] {
        assert!(LOG.contains(marker), "{marker}");
    }
    for marker in [
        "package vibe:%stream@1.0.0",
        "resource reader",
        "resource writer",
        "enum close-reason",
        "read: func(input: borrow<reader>) -> list<u8>",
        "write: func(output: borrow<writer>, bytes: list<u8>)",
        "close-reader: func(input: borrow<reader>, reason: close-reason)",
        "close-writer: func(output: borrow<writer>, reason: close-reason)",
        "export run: func(input: borrow<reader>, output: borrow<writer>)",
        "record byte-stream",
        "type bytes = stream<u8>",
        "type closed = future<close-reason>",
        "bytes: bytes",
        "closed: closed",
        "export run: async func(input: byte-stream) -> byte-stream",
    ] {
        assert!(STREAM.contains(marker), "{marker}");
    }
    for reason in [
        "normal",
        "failure",
        "cancelled",
        "denied",
        "unavailable",
        "exhausted",
        "invalid",
        "backend-fault",
    ] {
        assert!(STREAM.contains(reason), "{reason}");
    }
    for marker in [
        "package vibe:fixture@1.0.0",
        "interface canonical-values",
        "flags attributes { urgent, audited, traced }",
        "enum error-code { denied, invalid, exhausted }",
        "record request",
        "truth: bool",
        "signed: s32",
        "wide: u64",
        "symbol: char",
        "label: string",
        "payload: list<u8>",
        "attributes: attributes",
        "maybe: option<u16>",
        "outcome: result<u32, u8>",
        "variant response",
        "accepted(tuple<request, error-code>)",
        "rejected(error-code)",
        "transform: func(value: request) -> response",
        "world canonical-language",
        "export canonical-values;",
    ] {
        assert!(CANONICAL_VALUES.contains(marker), "{marker}");
    }
    assert!(VALID_CORE.contains("i32.add"));
    assert!(LIMIT_CORE.contains("memory 1 256"));
    assert!(UNSUPPORTED_CORE.contains("f32.const"));
    assert!(VALID_COMPONENT.contains("canon lift"));
    assert!(VALID_COMPONENT.contains("canon lower"));
    for marker in ["func async", "future u32", "stream u8"] {
        assert!(ASYNC_COMPONENT.contains(marker), "{marker}");
    }
    for marker in ["async func", "future<u32>", "stream<u8>"] {
        assert!(ASYNC_WORLD.contains(marker), "{marker}");
    }
    for marker in [
        "type $byte-stream-private",
        "(stream u8)",
        "(future $close-reason)",
        "(func async",
        "(param \"input\" $byte-stream)",
        "(result $byte-stream)",
        "(param i32 i32 i32) (result i32)",
        "(callback (core func $callback))",
    ] {
        assert!(NATIVE_ASYNC_STREAM_COMPONENT.contains(marker), "{marker}");
    }
    for marker in [
        "(canon task.return)",
        "(canon stream.read $bytes async (memory $memory))",
        "(canon future.write $closed async (memory $memory))",
        "(canon waitable.join)",
        "(import \"vibe:async\" \"task-return\"",
        "call $task-return",
        "i32.const 1",
    ] {
        assert!(NATIVE_ASYNC_SMOKE_COMPONENT.contains(marker), "{marker}");
    }
    assert!(MALFORMED_COMPONENT.contains("truncated-section"));
    for marker in [
        "#![no_std]",
        "#![no_main]",
        "wasm32-wasip1",
        "static mut BUMP_POINTER: u32 = 69_632",
        "#[unsafe(no_mangle)]",
        "pub unsafe extern \"C\" fn cabi_realloc",
        "pub unsafe extern \"C\" fn transform",
        "maybe_discriminant: u32",
        "outcome_discriminant: u32",
        "const RESULT_POINTER: u32 = 1_024",
        "const LABEL_OUTPUT_POINTER: u32 = 16_384",
        "const PAYLOAD_OUTPUT_POINTER: u32 = 32_768",
        "pub extern \"C\" fn cabi_post_transform",
        "#[panic_handler]",
    ] {
        assert!(RUST_GUEST.contains(marker), "Rust guest marker: {marker}");
    }
    for marker in [
        "wasm32-wasip1 with wasi-sdk-33",
        "-ffreestanding, -fno-builtin",
        "-nostdlib",
        "static uint32_t bump_pointer = 69632u",
        "WASM_EXPORT(\"cabi_realloc\")",
        "WASM_EXPORT(\"transform\")",
        "uint32_t maybe_discriminant",
        "uint32_t outcome_discriminant",
        "RESULT_POINTER = 1024u",
        "LABEL_OUTPUT_POINTER = 16384u",
        "PAYLOAD_OUTPUT_POINTER = 32768u",
        "WASM_EXPORT(\"cabi_post_transform\")",
    ] {
        assert!(C_GUEST.contains(marker), "C guest marker: {marker}");
    }
    assert!(!RUST_GUEST.contains(" fn add("));
    assert!(!C_GUEST.contains(" add("));
}

#[test]
fn malformed_hex_fixture_is_intentionally_truncated() {
    let bytes: Vec<u8> = MALFORMED_COMPONENT
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect();
    assert_eq!(&bytes[..8], &[0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0]);
    assert_eq!(bytes.last(), Some(&0x80));
}
