const WORLD: &str = include_str!("corpus/wit/world.wit");
const RESOURCES: &str = include_str!("corpus/wit/resources.wit");
const VALID_CORE: &str = include_str!("corpus/core/integer.wat");
const LIMIT_CORE: &str = include_str!("corpus/core/limits.wat");
const UNSUPPORTED_CORE: &str = include_str!("corpus/core/unsupported-float.wat");
const VALID_COMPONENT: &str = include_str!("corpus/component/typed.component.wat");
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
    assert!(VALID_CORE.contains("i32.add"));
    assert!(LIMIT_CORE.contains("memory 1 256"));
    assert!(UNSUPPORTED_CORE.contains("f32.const"));
    assert!(VALID_COMPONENT.contains("canon lift"));
    assert!(VALID_COMPONENT.contains("canon lower"));
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
