const WORLD: &str = include_str!("corpus/wit/world.wit");
const RESOURCES: &str = include_str!("corpus/wit/resources.wit");
const CLOCK: &str = include_str!("corpus/wit/clock.wit");
const BLOB: &str = include_str!("corpus/wit/blob.wit");
const LOG: &str = include_str!("corpus/wit/log.wit");
const VALID_CORE: &str = include_str!("corpus/core/integer.wat");
const LIMIT_CORE: &str = include_str!("corpus/core/limits.wat");
const UNSUPPORTED_CORE: &str = include_str!("corpus/core/unsupported-float.wat");
const VALID_COMPONENT: &str = include_str!("corpus/component/typed.component.wat");
const ASYNC_COMPONENT: &str = include_str!("corpus/component/async-0.255.0.component.wat");
const ASYNC_WORLD: &str = include_str!("corpus/wit/async-world.wit");
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
    assert!(MALFORMED_COMPONENT.contains("truncated-section"));
    assert!(RUST_GUEST.contains("extern \"C\""));
    assert!(C_GUEST.contains("uint32_t"));
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
