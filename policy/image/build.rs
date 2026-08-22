use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const SOURCE: &str = include_str!("artifacts/c53-stream-filter.component.wat");
const NATIVE_ASYNC_SOURCE: &str = include_str!("artifacts/c53-native-async-filter.component.wat");
const C64_RESOURCE_PROVIDER_SOURCE: &str =
    include_str!("artifacts/c64-resource-provider.component.wat");
const C64_RESOURCE_CONSUMER_SOURCE: &str =
    include_str!("artifacts/c64-resource-consumer.component.wat");
const C64_RESOURCE_ROUTE_WIT: &str = include_str!("artifacts/c64-resource-route.wit");

// This is deliberately independent of the artifact bytes produced below.
// Updating the WAT source or pinned parser must fail the build until review
// explicitly updates this image identity.
const EXPECTED_SHA256: [u8; 32] = [
    0x18, 0x0e, 0xd4, 0x44, 0xde, 0x8b, 0x6c, 0x9e, 0xcd, 0x82, 0x8b, 0x36, 0x9d, 0x4c, 0x8b, 0x9f,
    0x78, 0x37, 0x58, 0xef, 0x22, 0xc0, 0xb1, 0x71, 0x70, 0x68, 0x2d, 0x71, 0xf2, 0xfd, 0x0e, 0x72,
];

// This is an independent validation-only identity. It must never reuse the
// executable synchronous C5.3/C4.8 pin above.
const NATIVE_ASYNC_EXPECTED_SHA256: [u8; 32] = [
    0x8c, 0xff, 0xb5, 0xbc, 0xce, 0x06, 0x22, 0xc6, 0x4a, 0xff, 0xec, 0xd8, 0xc1, 0xa1, 0xee, 0xcc,
    0x57, 0xf3, 0x06, 0xbe, 0x08, 0xc7, 0x6c, 0xc0, 0x46, 0x21, 0xd8, 0x2d, 0x67, 0x8b, 0x10, 0xf3,
];

const C64_RESOURCE_PROVIDER_EXPECTED_SHA256: [u8; 32] = [
    0x54, 0x8a, 0x11, 0x71, 0x94, 0xcb, 0xc4, 0xec, 0x6a, 0xfc, 0x28, 0xf8, 0x10, 0xba, 0x2f, 0x0a,
    0xde, 0x44, 0x0e, 0x8a, 0x8a, 0x0d, 0xb2, 0x3b, 0x0b, 0x74, 0xa1, 0x25, 0x85, 0xf0, 0x1c, 0x64,
];
const C64_RESOURCE_CONSUMER_EXPECTED_SHA256: [u8; 32] = [
    0x55, 0x80, 0xe7, 0x68, 0x73, 0x5e, 0x5f, 0x4d, 0x53, 0x90, 0x71, 0x2f, 0xcd, 0x2d, 0x47, 0x12,
    0x4b, 0xdd, 0x74, 0xf0, 0x47, 0x4d, 0x18, 0xeb, 0xe1, 0xbc, 0x16, 0x24, 0x05, 0x71, 0xcf, 0x41,
];
const C64_RESOURCE_ROUTE_WIT_EXPECTED_SHA256: [u8; 32] = [
    0x07, 0x16, 0xe0, 0x79, 0x84, 0x89, 0x6d, 0xf8, 0x3b, 0xc2, 0x6a, 0x82, 0x82, 0x23, 0x6e, 0x6d,
    0xfa, 0x70, 0x8b, 0xf6, 0x71, 0x92, 0x85, 0x3b, 0xd8, 0xcd, 0x84, 0x79, 0xcc, 0xec, 0x13, 0x41,
];

fn main() {
    println!("cargo:rerun-if-changed=artifacts/c53-stream-filter.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c53-native-async-filter.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c64-resource-provider.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c64-resource-consumer.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c64-resource-route.wit");

    let bytes = wat::parse_str(SOURCE).expect("pinned Component WAT must parse");
    let observed: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        observed, EXPECTED_SHA256,
        "pinned C5.3 Component digest changed: {observed:02x?}"
    );

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    fs::write(output.join("c53-stream-filter.component.wasm"), bytes)
        .expect("write pinned Component artifact");
    fs::write(
        output.join("c53-stream-filter.sha256.rs"),
        format!("{EXPECTED_SHA256:?}"),
    )
    .expect("write checked Component identity constant");

    if env::var_os("CARGO_FEATURE_C53_NATIVE_ASYNC_QEMU_ACCEPTANCE").is_some()
        || env::var_os("CARGO_FEATURE_C53_NATIVE_ASYNC_COMMAND_PROJECTION").is_some()
    {
        let bytes = wat::parse_str(NATIVE_ASYNC_SOURCE)
            .expect("pinned native async Component WAT must parse");
        let observed: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            observed, NATIVE_ASYNC_EXPECTED_SHA256,
            "pinned native async C5.3 Component digest changed: {observed:02x?}"
        );
        fs::write(output.join("c53-native-async-filter.component.wasm"), bytes)
            .expect("write pinned native async Component artifact");
        fs::write(
            output.join("c53-native-async-filter.sha256.rs"),
            format!("{NATIVE_ASYNC_EXPECTED_SHA256:?}"),
        )
        .expect("write checked native async Component identity constant");
    }

    if env::var_os("CARGO_FEATURE_C64_RESOURCE_ROUTE_QEMU_ACCEPTANCE").is_some() {
        let provider = wat::parse_str(C64_RESOURCE_PROVIDER_SOURCE)
            .expect("pinned C6.4 provider Component WAT must parse");
        let provider_observed: [u8; 32] = Sha256::digest(&provider).into();
        assert_eq!(
            provider_observed, C64_RESOURCE_PROVIDER_EXPECTED_SHA256,
            "pinned C6.4 provider Component digest changed: {provider_observed:02x?}"
        );
        let consumer = wat::parse_str(C64_RESOURCE_CONSUMER_SOURCE)
            .expect("pinned C6.4 consumer Component WAT must parse");
        let consumer_observed: [u8; 32] = Sha256::digest(&consumer).into();
        assert_eq!(
            consumer_observed, C64_RESOURCE_CONSUMER_EXPECTED_SHA256,
            "pinned C6.4 consumer Component digest changed: {consumer_observed:02x?}"
        );
        let wit_observed: [u8; 32] = Sha256::digest(C64_RESOURCE_ROUTE_WIT.as_bytes()).into();
        assert_eq!(
            wit_observed, C64_RESOURCE_ROUTE_WIT_EXPECTED_SHA256,
            "pinned C6.4 route WIT digest changed: {wit_observed:02x?}"
        );
        fs::write(
            output.join("c64-resource-provider.component.wasm"),
            provider,
        )
        .expect("write pinned C6.4 provider Component artifact");
        fs::write(
            output.join("c64-resource-consumer.component.wasm"),
            consumer,
        )
        .expect("write pinned C6.4 consumer Component artifact");
        fs::write(
            output.join("c64-resource-provider.sha256.rs"),
            format!("{C64_RESOURCE_PROVIDER_EXPECTED_SHA256:?}"),
        )
        .expect("write checked C6.4 provider Component identity constant");
        fs::write(
            output.join("c64-resource-consumer.sha256.rs"),
            format!("{C64_RESOURCE_CONSUMER_EXPECTED_SHA256:?}"),
        )
        .expect("write checked C6.4 consumer Component identity constant");
    }
}
