use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};
use vibeos_component_format::{
    ComponentArtifactAdapterV1, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactInterfaceDirection, ComponentArtifactInterfaceV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyV1, ComponentArtifactV1, ComponentArtifactWitPackageV1,
    ProfileIdentity, COMPONENT_ARTIFACT_FORMAT_VERSION, COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION,
};
use vibeos_component_runtime::decode::inspect_component;

const SOURCE: &str = include_str!("artifacts/c53-stream-filter.component.wat");
const NATIVE_ASYNC_SOURCE: &str = include_str!("artifacts/c53-native-async-filter.component.wat");
const C64_RESOURCE_PROVIDER_SOURCE: &str =
    include_str!("artifacts/c64-resource-provider.component.wat");
const C64_RESOURCE_CONSUMER_SOURCE: &str =
    include_str!("artifacts/c64-resource-consumer.component.wat");
const C64_RESOURCE_ROUTE_WIT: &str = include_str!("artifacts/c64-resource-route.wit");
const C65_ASYNC_SOURCE_SOURCE: &str = include_str!("artifacts/c65-async-source.component.wat");
const C65_ASYNC_RELAY_SOURCE: &str = include_str!("artifacts/c65-async-relay.component.wat");
const C65_ASYNC_SINK_SOURCE: &str = include_str!("artifacts/c65-async-sink.component.wat");
const C65_ASYNC_CHAIN_WIT: &str = include_str!("artifacts/c65-async-chain.wit");
const C66_ASYNC_RELAY_V2_SOURCE: &str = include_str!("artifacts/c66-async-relay-v2.component.wat");
const C73_COMPONENT_A_SOURCE: &str = include_str!("artifacts/c73-byte-filter-a.component.wat");
const C73_COMPONENT_B_SOURCE: &str = include_str!("artifacts/c73-byte-filter-b.component.wat");
const C73_WIT: &str = include_str!("artifacts/c73-byte-filter.wit");
const C73_VECTOR_SOURCE: &str = include_str!("artifacts/c73-authenticated-admission.vectors");

const C73_WORLD: &str = "vibe:bytes/filter@1.0.0";
const C73_POLICY_DOMAIN: &[u8] = b"vibeos.component-artifact.operator-policy.v1\0";
const C73_SIGNATURE_DOMAIN: &[u8; 48] = b"vibeos.component-artifact.operator-admission.v1\0";
const C73_OPERATOR_ROLE_DOMAIN: &[u8] = b"vibeos.c73.acceptance.operator-role.v1\0";
const C73_OPERATOR_POLICY_VERSION: u16 = 1;
const C73_TRUST_MODE_OPERATOR: u8 = 2;
const C73_STREAM_REQUIRED: u8 = 1;
const C73_STREAM_OPTIONAL: u8 = 2;
const C73_EVIDENCE_VERSION: u16 = 1;
const C73_ED25519_ALGORITHM: u16 = 1;
const C73_TRANSCRIPT_LEN: usize = 192;
const C73_VECTOR_MAGIC: &str = "VIBEOS-C73-AUTHENTICATED-ADMISSION-V1";

// C7.3-only deterministic acceptance public keys. They are derived by the
// offline fixture generator from role-specific seed domains and are distinct
// from every SSH test/provisioning signer. Only public verification material
// enters the image; the acceptance seeds are intentionally absent here.
const C73_ACTIVE_PUBLIC_KEY: [u8; 32] = [
    0x8d, 0x17, 0x8a, 0x30, 0xc5, 0xbe, 0x44, 0x3f, 0x7e, 0x94, 0x8f, 0x4d, 0xdf, 0xce, 0xc3, 0x75,
    0x61, 0xe8, 0x85, 0xb7, 0xde, 0x63, 0x1a, 0xdd, 0x2b, 0x63, 0x50, 0x2f, 0x75, 0x4c, 0xf1, 0x87,
];
const C73_REVOKED_PUBLIC_KEY: [u8; 32] = [
    0xea, 0x4c, 0x61, 0x1e, 0x93, 0x61, 0xcd, 0x8e, 0xad, 0x0f, 0x53, 0x3f, 0x82, 0x57, 0x69, 0xcb,
    0xbc, 0x7e, 0xbe, 0xda, 0xf1, 0xc3, 0x8e, 0x64, 0x9f, 0xe7, 0x89, 0x2f, 0x4d, 0x29, 0xe1, 0xac,
];
const C73_UNKNOWN_PUBLIC_KEY: [u8; 32] = [
    0xf9, 0xe1, 0x08, 0xc9, 0xbe, 0x89, 0x0b, 0x59, 0xe4, 0x03, 0xc5, 0x26, 0xba, 0xff, 0xa1, 0xdd,
    0x2b, 0x96, 0x5d, 0xc2, 0x80, 0xb7, 0x33, 0x02, 0x25, 0x66, 0x05, 0x4a, 0x91, 0x61, 0xdf, 0x25,
];

const C73_MEMORY_BYTES: u64 = 512 * 1024;
const C73_TOTAL_FUEL: u64 = 100_000;
const C73_POLL_QUANTUM: u64 = 100;
const C73_RESOURCES: u64 = 4;

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

const C65_ASYNC_SOURCE_EXPECTED_SHA256: [u8; 32] = [
    0x7f, 0x95, 0x59, 0xa1, 0x20, 0x77, 0x3a, 0x61, 0x43, 0x28, 0xf5, 0xb8, 0x58, 0x75, 0xe2, 0x39,
    0x53, 0xee, 0x5e, 0xbf, 0xf6, 0x86, 0x1c, 0xa4, 0x3b, 0xdb, 0xe1, 0x0c, 0x3c, 0xdf, 0x6c, 0x81,
];
const C65_ASYNC_RELAY_EXPECTED_SHA256: [u8; 32] = [
    0xc9, 0xa1, 0x4d, 0x5d, 0xf6, 0x3a, 0xf5, 0x3b, 0x33, 0x46, 0x75, 0x24, 0x2b, 0x63, 0x42, 0x72,
    0x59, 0x1d, 0xff, 0xd2, 0x6b, 0xea, 0x8a, 0xf5, 0xbc, 0xdb, 0x24, 0x0e, 0x59, 0xfd, 0x0f, 0xb1,
];
const C65_ASYNC_SINK_EXPECTED_SHA256: [u8; 32] = [
    0x28, 0x42, 0xca, 0xc9, 0xaf, 0x1a, 0x6b, 0xd0, 0x86, 0x4e, 0xff, 0xfe, 0xe6, 0x16, 0x50, 0xbe,
    0x5e, 0x56, 0x42, 0x39, 0xad, 0xa2, 0x9e, 0x97, 0x5f, 0xf2, 0x79, 0xcf, 0x7b, 0x3e, 0x5b, 0xa9,
];
const C65_ASYNC_CHAIN_WIT_EXPECTED_SHA256: [u8; 32] = [
    0x05, 0x3e, 0x44, 0x72, 0x9a, 0x38, 0x75, 0x45, 0xf5, 0xdc, 0x73, 0xba, 0xc2, 0x11, 0xd3, 0x07,
    0xde, 0x74, 0x6a, 0x4c, 0xf7, 0x58, 0xd1, 0x79, 0xc0, 0xfa, 0x3c, 0xf2, 0xb9, 0xe8, 0xc5, 0xbf,
];
const C66_ASYNC_RELAY_V2_EXPECTED_SHA256: [u8; 32] = [
    0x04, 0x26, 0xc2, 0x53, 0xbd, 0x80, 0x82, 0xf8, 0x9c, 0x9d, 0x1e, 0x95, 0x8f, 0x19, 0x70, 0xc3,
    0xa8, 0x48, 0x67, 0x5c, 0xdb, 0xc2, 0x5c, 0xd6, 0xee, 0x94, 0xc6, 0x4f, 0x2a, 0xee, 0x5e, 0xb8,
];

#[derive(Clone, Copy, Debug)]
enum C73ArtifactVariant {
    Exact,
    InterfaceManifest,
    CoreManifest,
    WitSource,
    Adapter,
    Limits,
    Profile,
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    push_u32(
        out,
        u32::try_from(value.len()).expect("C7.3 fixture text length fits u32"),
    );
    out.extend_from_slice(value.as_bytes());
}

fn c73_operator_role() -> [u8; 32] {
    Sha256::digest(C73_OPERATOR_ROLE_DOMAIN).into()
}

/// Independently encode the frozen C7.3 operator policy used by the target
/// fixture. This deliberately does not call the production admission policy
/// encoder: build-time equality with its digest is cross-implementation
/// evidence rather than circular self-confirmation.
fn c73_operator_policy_stream(generation: u64) -> Vec<u8> {
    let profile = ProfileIdentity::PROFILE_1_SYNC;
    let mut out = Vec::new();
    push_u16(&mut out, C73_OPERATOR_POLICY_VERSION);
    push_u64(&mut out, generation);
    out.extend_from_slice(&c73_operator_role());

    // Entries are strictly canonical by complete C7.3 public-key bytes; role
    // status is committed with each complete key and does not define order.
    let mut signers = [
        (C73_ACTIVE_PUBLIC_KEY, 1_u8),
        (C73_REVOKED_PUBLIC_KEY, 2_u8),
    ];
    signers.sort_by_key(|(key, _)| *key);
    push_u16(&mut out, signers.len() as u16);
    for (key, status) in signers {
        out.extend_from_slice(&key);
        out.push(status);
    }

    out.push(C73_TRUST_MODE_OPERATOR);
    push_u16(&mut out, profile.artifact_abi);
    push_u16(&mut out, profile.component_profile);
    push_u16(&mut out, profile.core_profile);
    push_u16(&mut out, profile.runtime_abi);
    push_u64(&mut out, profile.canonical_features);
    push_u16(&mut out, profile.stage as u16);
    for revision in [
        profile.core_revision,
        profile.component_revision,
        profile.canonical_abi_revision,
        profile.wasm_tools_revision,
        profile.wasi_revision,
    ] {
        push_text(&mut out, revision);
    }

    push_text(&mut out, "c73-filter");
    push_text(&mut out, "run");
    push_u64(&mut out, 0);
    push_u64(&mut out, 0);

    // Exact normalized `vibe:bytes/filter@1.0.0` world:
    // no imports and one sync `run(input: list<u8>) -> list<u8>` export.
    push_text(&mut out, C73_WORLD);
    push_u32(&mut out, 0); // imports
    push_u32(&mut out, 1); // exports
    push_text(&mut out, "run");
    out.push(0); // EntityShape::Function
    out.push(0); // FunctionEffect::Sync
    push_u32(&mut out, 1);
    push_text(&mut out, "input");
    out.push(11); // ValueShape::List
    out.push(1); // ValueShape::U8
    out.push(1); // Some(result)
    out.push(11); // ValueShape::List
    out.push(1); // ValueShape::U8

    push_u64(&mut out, C73_MEMORY_BYTES);
    push_u64(&mut out, C73_TOTAL_FUEL);
    push_u64(&mut out, C73_POLL_QUANTUM);
    push_u16(&mut out, C73_RESOURCES as u16);
    out.push(C73_STREAM_REQUIRED);
    out.push(C73_STREAM_REQUIRED);
    out.push(C73_STREAM_OPTIONAL);
    push_u16(&mut out, 0); // no interface ceilings/import authority

    // Exact authorized WIT source is independently bound in addition to the
    // normalized world shape.  Length framing is u64 because it is part of
    // the frozen C7.3 policy wire, not the canonical text helper above.
    push_u64(&mut out, C73_WIT.len() as u64);
    out.extend_from_slice(C73_WIT.as_bytes());
    out
}

fn c73_operator_policy_commitment(generation: u64) -> [u8; 32] {
    let stream = c73_operator_policy_stream(generation);
    let mut hasher = Sha256::new();
    hasher.update(C73_POLICY_DOMAIN);
    hasher.update(&stream);
    hasher.finalize().into()
}

fn c73_development_policy_commitment() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vibeos.c73.acceptance.development-image-policy.v1\0");
    hasher.update((C73_WIT.len() as u64).to_le_bytes());
    hasher.update(C73_WIT.as_bytes());
    hasher.finalize().into()
}

fn c73_artifact(
    component: &[u8],
    signer_policy: ComponentArtifactSignerPolicyV1,
    variant: C73ArtifactVariant,
) -> Vec<u8> {
    let wit_source = if matches!(variant, C73ArtifactVariant::WitSource) {
        "package vibe:bytes@1.0.0;\nworld filter { export run: func(input: list<u8>) -> list<u8>; }\n"
    } else {
        C73_WIT
    };
    let wit_packages = vec![
        ComponentArtifactWitPackageV1::new("vibe:bytes", "1.0.0", wit_source)
            .expect("C7.3 WIT package is canonical"),
    ];
    let diagnostic_shape = if matches!(variant, C73ArtifactVariant::InterfaceManifest) {
        "func(input:list<u8>)->u32"
    } else {
        "func(input:list<u8>)->list<u8>"
    };
    let interfaces = vec![ComponentArtifactInterfaceV1::new(
        ComponentArtifactInterfaceDirection::Export,
        ComponentArtifactEntityKind::Function,
        "run",
        diagnostic_shape,
    )
    .expect("C7.3 interface evidence is bounded")];
    let core_modules = if matches!(variant, C73ArtifactVariant::CoreManifest) {
        let wrong = wat::parse_str("(module (func))").expect("adjacent Core fixture parses");
        vec![ComponentArtifactCoreModuleV1::from_bytes(&wrong)
            .expect("adjacent Core fixture is bounded")]
    } else {
        inspect_component(component)
            .expect("C7.3 Component fixture inspects")
            .embedded_modules()
            .iter()
            .map(|module| {
                ComponentArtifactCoreModuleV1::from_bytes(module)
                    .expect("embedded C7.3 module is bounded")
            })
            .collect()
    };
    let adapters = if matches!(variant, C73ArtifactVariant::Adapter) {
        vec![
            ComponentArtifactAdapterV1::new(0, "c73-test-adapter-v1", b"descriptor")
                .expect("C7.3 adapter mutation is bounded"),
        ]
    } else {
        Vec::new()
    };
    let manifest = ComponentArtifactManifestV1::new(
        C73_WORLD,
        wit_packages,
        interfaces,
        core_modules,
        adapters,
    )
    .expect("C7.3 manifest is canonical");
    let memory = if matches!(variant, C73ArtifactVariant::Limits) {
        C73_MEMORY_BYTES / 2
    } else {
        C73_MEMORY_BYTES
    };
    let limits = ComponentArtifactInstanceLimitsV1::new(
        memory,
        C73_TOTAL_FUEL,
        C73_POLL_QUANTUM,
        C73_RESOURCES,
    )
    .expect("C7.3 instance limits are bounded");
    let profile = if matches!(variant, C73ArtifactVariant::Profile) {
        ProfileIdentity::PROFILE_1_ASYNC
    } else {
        ProfileIdentity::PROFILE_1_SYNC
    };
    ComponentArtifactV1::new(component, profile, limits, signer_policy, manifest)
        .expect("C7.3 canonical artifact builds")
        .encode()
        .expect("C7.3 canonical artifact encodes")
}

fn c73_signature_transcript(
    artifact_bytes: &[u8],
    policy_commitment: [u8; 32],
    policy_generation: u64,
    signer: [u8; 32],
) -> [u8; C73_TRANSCRIPT_LEN] {
    let artifact = ComponentArtifactV1::decode(artifact_bytes)
        .expect("C7.3 transcript input is a canonical artifact");
    assert_eq!(
        artifact.signer_policy().policy_digest().as_bytes(),
        &policy_commitment,
        "artifact and independent operator policy must remain exact"
    );
    let mut out = [0_u8; C73_TRANSCRIPT_LEN];
    out[0..48].copy_from_slice(C73_SIGNATURE_DOMAIN);
    out[48..50].copy_from_slice(&1_u16.to_le_bytes());
    out[50..52].copy_from_slice(&C73_EVIDENCE_VERSION.to_le_bytes());
    out[52..54].copy_from_slice(&C73_ED25519_ALGORITHM.to_le_bytes());
    out[54..56].copy_from_slice(&COMPONENT_ARTIFACT_FORMAT_VERSION.to_le_bytes());
    out[56..58].copy_from_slice(&COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION.to_le_bytes());
    out[58..60].copy_from_slice(&C73_OPERATOR_POLICY_VERSION.to_le_bytes());
    let profile = artifact.profile();
    out[60..62].copy_from_slice(&profile.artifact_abi.to_le_bytes());
    out[62..64].copy_from_slice(&profile.component_profile.to_le_bytes());
    out[64..66].copy_from_slice(&profile.core_profile.to_le_bytes());
    out[66..68].copy_from_slice(&profile.runtime_abi.to_le_bytes());
    out[68..70].copy_from_slice(&(profile.stage as u16).to_le_bytes());
    out[72..80].copy_from_slice(&profile.canonical_features.to_le_bytes());
    out[80..88].copy_from_slice(&(artifact_bytes.len() as u64).to_le_bytes());
    out[88..120].copy_from_slice(
        artifact
            .artifact_commitment()
            .expect("canonical artifact commitment exists")
            .as_bytes(),
    );
    out[120..152].copy_from_slice(&policy_commitment);
    out[152..184].copy_from_slice(&signer);
    out[184..192].copy_from_slice(&policy_generation.to_le_bytes());
    out
}

fn c73_decode_hex(name: &str, encoded: &str) -> Vec<u8> {
    assert!(
        !encoded.is_empty() && encoded.len().is_multiple_of(2),
        "C7.3 vector `{name}` has an empty or odd-length hex payload"
    );
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "C7.3 vector `{name}` is not canonical lowercase hex"
    );
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("C7.3 hex is ASCII");
            u8::from_str_radix(text, 16).expect("C7.3 hex pair is valid")
        })
        .collect()
}

fn c73_vectors() -> BTreeMap<&'static str, Vec<u8>> {
    let mut lines = C73_VECTOR_SOURCE.lines();
    assert_eq!(
        lines.next(),
        Some(C73_VECTOR_MAGIC),
        "C7.3 vector schema/magic changed"
    );
    let mut vectors = BTreeMap::new();
    for line in lines {
        assert!(!line.is_empty(), "C7.3 vector contains an empty line");
        let (name, encoded) = line
            .split_once('=')
            .expect("C7.3 vector line must contain exactly one assignment");
        assert!(
            !encoded.contains('='),
            "C7.3 vector line contains a second assignment"
        );
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "C7.3 vector name is outside the closed schema"
        );
        assert!(
            vectors
                .insert(name, c73_decode_hex(name, encoded))
                .is_none(),
            "duplicate C7.3 vector name `{name}`"
        );
    }

    let mut expected = vec![
        "policy_p1",
        "policy_p2",
        "development_artifact",
        "operator_a_p1_artifact",
        "operator_a_p1_evidence",
        "operator_b_p1_artifact",
        "operator_b_p1_evidence",
        "operator_a_p2_artifact",
        "operator_a_p2_evidence",
        "wrong_signer_evidence",
        "unknown_signer_evidence",
        "revoked_signer_evidence",
        "content_hash_only_evidence",
    ];
    for mutation in ["artifact", "module", "wit", "adapter", "limit", "profile"] {
        expected.push(match mutation {
            "artifact" => "mutation_artifact_artifact",
            "module" => "mutation_module_artifact",
            "wit" => "mutation_wit_artifact",
            "adapter" => "mutation_adapter_artifact",
            "limit" => "mutation_limit_artifact",
            "profile" => "mutation_profile_artifact",
            _ => unreachable!(),
        });
        expected.push(match mutation {
            "artifact" => "mutation_artifact_evidence",
            "module" => "mutation_module_evidence",
            "wit" => "mutation_wit_evidence",
            "adapter" => "mutation_adapter_evidence",
            "limit" => "mutation_limit_evidence",
            "profile" => "mutation_profile_evidence",
            _ => unreachable!(),
        });
    }
    expected.sort_unstable();
    assert_eq!(
        vectors.keys().copied().collect::<Vec<_>>(),
        expected,
        "C7.3 vector field set is not the closed acceptance schema"
    );
    vectors
}

fn c73_evidence_verifies(
    encoded: &[u8],
    transcript: &[u8; C73_TRANSCRIPT_LEN],
    expected_key: [u8; 32],
) -> bool {
    let evidence = ComponentArtifactAuthenticationEvidenceV1::decode(encoded)
        .expect("C7.3 detached evidence must use the exact 112-byte wire");
    assert_eq!(
        evidence.encode().as_slice(),
        encoded,
        "C7.3 evidence is not its canonical re-encoding"
    );
    assert!(
        !evidence.runtime_ready(),
        "detached evidence became executable"
    );
    assert_eq!(
        evidence.public_key().to_bytes(),
        expected_key,
        "C7.3 evidence selected an unexpected complete public key"
    );
    let verifying_key = VerifyingKey::from_bytes(&expected_key)
        .expect("pinned C7.3 operator public key must decode");
    let signature = Signature::from_bytes(evidence.signature().as_bytes());
    verifying_key.verify_strict(transcript, &signature).is_ok()
}

fn c73_verify_and_install_signed_vectors(output: &Path) {
    let vectors = c73_vectors();
    let vector = |name: &str| {
        vectors
            .get(name)
            .unwrap_or_else(|| panic!("missing checked C7.3 vector `{name}`"))
    };
    let generated = |name: &str, suffix: &str| {
        fs::read(output.join(format!("c73-{name}.{suffix}")))
            .unwrap_or_else(|_| panic!("missing generated C7.3 input `{name}.{suffix}`"))
    };

    assert_eq!(generated("policy-p1", "bin"), *vector("policy_p1"));
    assert_eq!(generated("policy-p2", "bin"), *vector("policy_p2"));
    assert_eq!(
        generated("development", "artifact"),
        *vector("development_artifact"),
        "development exact-byte image pin changed"
    );

    for (fixture, vector_prefix, policy_commitment, generation) in [
        (
            "operator-a-p1",
            "operator_a_p1",
            c73_operator_policy_commitment(1),
            1_u64,
        ),
        (
            "operator-b-p1",
            "operator_b_p1",
            c73_operator_policy_commitment(1),
            1_u64,
        ),
        (
            "operator-a-p2",
            "operator_a_p2",
            c73_operator_policy_commitment(2),
            2_u64,
        ),
    ] {
        let artifact_name = format!("{vector_prefix}_artifact");
        let evidence_name = format!("{vector_prefix}_evidence");
        let artifact = generated(fixture, "artifact");
        assert_eq!(
            artifact,
            *vector(&artifact_name),
            "signed artifact pin changed"
        );
        let transcript = c73_signature_transcript(
            &artifact,
            policy_commitment,
            generation,
            C73_ACTIVE_PUBLIC_KEY,
        );
        assert!(
            c73_evidence_verifies(vector(&evidence_name), &transcript, C73_ACTIVE_PUBLIC_KEY),
            "checked C7.3 operator signature `{fixture}` does not verify strictly"
        );
        fs::write(
            output.join(format!("c73-{fixture}.evidence")),
            vector(&evidence_name),
        )
        .expect("write checked C7.3 operator evidence");
    }

    let operator_a_p1 = generated("operator-a-p1", "artifact");
    let operator_b_p1 = generated("operator-b-p1", "artifact");
    let baseline_transcript = c73_signature_transcript(
        &operator_a_p1,
        c73_operator_policy_commitment(1),
        1,
        C73_ACTIVE_PUBLIC_KEY,
    );
    let replay_transcript = c73_signature_transcript(
        &operator_b_p1,
        c73_operator_policy_commitment(1),
        1,
        C73_ACTIVE_PUBLIC_KEY,
    );
    assert!(
        !c73_evidence_verifies(
            vector("operator_a_p1_evidence"),
            &replay_transcript,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        "artifact-scoped signature replay unexpectedly verified"
    );

    assert!(
        !c73_evidence_verifies(
            vector("wrong_signer_evidence"),
            &baseline_transcript,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        "wrong-key signature unexpectedly verified as the active signer"
    );
    for (name, key) in [
        ("unknown-signer", C73_UNKNOWN_PUBLIC_KEY),
        ("revoked-signer", C73_REVOKED_PUBLIC_KEY),
    ] {
        let transcript =
            c73_signature_transcript(&operator_a_p1, c73_operator_policy_commitment(1), 1, key);
        let evidence_name = format!("{}_evidence", name.replace('-', "_"));
        assert!(
            c73_evidence_verifies(vector(&evidence_name), &transcript, key),
            "{name} fixture must be cryptographically valid before policy rejection"
        );
        fs::write(
            output.join(format!("c73-{name}.evidence")),
            vector(&evidence_name),
        )
        .expect("write checked C7.3 negative signer evidence");
    }
    fs::write(
        output.join("c73-wrong-signer.evidence"),
        vector("wrong_signer_evidence"),
    )
    .expect("write checked C7.3 wrong-signer evidence");
    assert!(
        !c73_evidence_verifies(
            vector("content_hash_only_evidence"),
            &baseline_transcript,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        "an artifact content hash was accepted as an Ed25519 signature"
    );
    fs::write(
        output.join("c73-content-hash-only.evidence"),
        vector("content_hash_only_evidence"),
    )
    .expect("write checked C7.3 content-hash-only evidence");

    for mutation in ["artifact", "module", "wit", "adapter", "limit", "profile"] {
        let fixture = format!("mutation-{mutation}");
        let artifact_name = format!("mutation_{mutation}_artifact");
        let evidence_name = format!("mutation_{mutation}_evidence");
        let artifact = generated(&fixture, "artifact");
        assert_eq!(
            artifact,
            *vector(&artifact_name),
            "C7.3 `{mutation}` mutation bytes changed"
        );
        let transcript = c73_signature_transcript(
            &artifact,
            c73_operator_policy_commitment(1),
            1,
            C73_ACTIVE_PUBLIC_KEY,
        );
        assert!(
            !c73_evidence_verifies(
                vector("operator_a_p1_evidence"),
                &transcript,
                C73_ACTIVE_PUBLIC_KEY,
            ),
            "stale signature accepted the `{mutation}` mutation"
        );
        assert!(
            c73_evidence_verifies(vector(&evidence_name), &transcript, C73_ACTIVE_PUBLIC_KEY),
            "freshly signed `{mutation}` mutation is not a valid double-layer fixture"
        );
        fs::write(
            output.join(format!("c73-{fixture}.evidence")),
            vector(&evidence_name),
        )
        .expect("write checked C7.3 mutation evidence");
    }

    for (name, bytes) in [
        ("operator-role", c73_operator_role()),
        ("active-public-key", C73_ACTIVE_PUBLIC_KEY),
        ("revoked-public-key", C73_REVOKED_PUBLIC_KEY),
        (
            "development-policy-digest",
            c73_development_policy_commitment(),
        ),
    ] {
        fs::write(output.join(format!("c73-{name}.rs")), format!("{bytes:?}"))
            .expect("write verified C7.3 public policy input");
    }
}

fn write_c73_unsigned_fixture(output: &Path) {
    let component_a =
        wat::parse_str(C73_COMPONENT_A_SOURCE).expect("pinned C7.3 Component A WAT must parse");
    let component_b =
        wat::parse_str(C73_COMPONENT_B_SOURCE).expect("pinned C7.3 Component B WAT must parse");
    assert_ne!(component_a, component_b, "operator artifacts must differ");

    let policy_p1 = c73_operator_policy_stream(1);
    let policy_p2 = c73_operator_policy_stream(2);
    let commitment_p1 = c73_operator_policy_commitment(1);
    let commitment_p2 = c73_operator_policy_commitment(2);
    assert_ne!(
        commitment_p1, commitment_p2,
        "rotation must change policy commitment"
    );

    let dev = c73_artifact(
        &component_a,
        ComponentArtifactSignerPolicyV1::development_image_pin(c73_development_policy_commitment())
            .expect("development policy commitment is non-zero"),
        C73ArtifactVariant::Exact,
    );
    let operator = |component: &[u8], commitment, variant| {
        c73_artifact(
            component,
            ComponentArtifactSignerPolicyV1::operator_required(commitment)
                .expect("operator policy commitment is non-zero"),
            variant,
        )
    };
    let operator_a_p1 = operator(&component_a, commitment_p1, C73ArtifactVariant::Exact);
    let operator_b_p1 = operator(&component_b, commitment_p1, C73ArtifactVariant::Exact);
    let operator_a_p2 = operator(&component_a, commitment_p2, C73ArtifactVariant::Exact);

    fs::write(output.join("c73-development.artifact"), &dev)
        .expect("write C7.3 development artifact");
    fs::write(output.join("c73-operator-a-p1.artifact"), &operator_a_p1)
        .expect("write C7.3 operator A/P1 artifact");
    fs::write(output.join("c73-operator-b-p1.artifact"), &operator_b_p1)
        .expect("write C7.3 operator B/P1 artifact");
    fs::write(output.join("c73-operator-a-p2.artifact"), &operator_a_p2)
        .expect("write C7.3 operator A/P2 artifact");
    fs::write(output.join("c73-policy-p1.bin"), &policy_p1).expect("write C7.3 P1 policy");
    fs::write(output.join("c73-policy-p2.bin"), &policy_p2).expect("write C7.3 P2 policy");

    for (name, artifact, commitment, generation, signer) in [
        (
            "operator-a-p1",
            operator_a_p1.as_slice(),
            commitment_p1,
            1,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        (
            "operator-b-p1",
            operator_b_p1.as_slice(),
            commitment_p1,
            1,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        (
            "operator-a-p2",
            operator_a_p2.as_slice(),
            commitment_p2,
            2,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        (
            "wrong-signer",
            operator_a_p1.as_slice(),
            commitment_p1,
            1,
            C73_ACTIVE_PUBLIC_KEY,
        ),
        (
            "unknown-signer",
            operator_a_p1.as_slice(),
            commitment_p1,
            1,
            C73_UNKNOWN_PUBLIC_KEY,
        ),
        (
            "revoked-signer",
            operator_a_p1.as_slice(),
            commitment_p1,
            1,
            C73_REVOKED_PUBLIC_KEY,
        ),
    ] {
        fs::write(
            output.join(format!("c73-{name}.transcript")),
            c73_signature_transcript(artifact, commitment, generation, signer),
        )
        .expect("write C7.3 signature transcript");
    }

    for (name, variant) in [
        ("artifact", C73ArtifactVariant::InterfaceManifest),
        ("module", C73ArtifactVariant::CoreManifest),
        ("wit", C73ArtifactVariant::WitSource),
        ("adapter", C73ArtifactVariant::Adapter),
        ("limit", C73ArtifactVariant::Limits),
        ("profile", C73ArtifactVariant::Profile),
    ] {
        let artifact = operator(&component_a, commitment_p1, variant);
        fs::write(
            output.join(format!("c73-mutation-{name}.artifact")),
            &artifact,
        )
        .expect("write C7.3 mutation artifact");
        fs::write(
            output.join(format!("c73-mutation-{name}.transcript")),
            c73_signature_transcript(&artifact, commitment_p1, 1, C73_ACTIVE_PUBLIC_KEY),
        )
        .expect("write C7.3 mutation transcript");
    }

    c73_verify_and_install_signed_vectors(output);
}

fn main() {
    println!("cargo:rerun-if-changed=artifacts/c53-stream-filter.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c53-native-async-filter.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c64-resource-provider.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c64-resource-consumer.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c64-resource-route.wit");
    println!("cargo:rerun-if-changed=artifacts/c65-async-source.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c65-async-relay.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c65-async-sink.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c65-async-chain.wit");
    println!("cargo:rerun-if-changed=artifacts/c66-async-relay-v2.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c73-byte-filter-a.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c73-byte-filter-b.component.wat");
    println!("cargo:rerun-if-changed=artifacts/c73-byte-filter.wit");
    println!("cargo:rerun-if-changed=artifacts/c73-authenticated-admission.vectors");

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

    if env::var_os("CARGO_FEATURE_C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE").is_some() {
        write_c73_unsigned_fixture(&output);
    }

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

    if env::var_os("CARGO_FEATURE_C65_ASYNC_CHAIN_QEMU_ACCEPTANCE").is_some()
        || env::var_os("CARGO_FEATURE_C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE").is_some()
        || env::var_os("CARGO_FEATURE_C67_INFORMATION_FLOW_QEMU_ACCEPTANCE").is_some()
    {
        let source = wat::parse_str(C65_ASYNC_SOURCE_SOURCE)
            .expect("pinned C6.5 source Component WAT must parse");
        let source_observed: [u8; 32] = Sha256::digest(&source).into();
        assert_eq!(
            source_observed, C65_ASYNC_SOURCE_EXPECTED_SHA256,
            "pinned C6.5 source Component digest changed: {source_observed:02x?}"
        );
        let relay = wat::parse_str(C65_ASYNC_RELAY_SOURCE)
            .expect("pinned C6.5 relay Component WAT must parse");
        let relay_observed: [u8; 32] = Sha256::digest(&relay).into();
        assert_eq!(
            relay_observed, C65_ASYNC_RELAY_EXPECTED_SHA256,
            "pinned C6.5 relay Component digest changed: {relay_observed:02x?}"
        );
        let sink = wat::parse_str(C65_ASYNC_SINK_SOURCE)
            .expect("pinned C6.5 sink Component WAT must parse");
        let sink_observed: [u8; 32] = Sha256::digest(&sink).into();
        assert_eq!(
            sink_observed, C65_ASYNC_SINK_EXPECTED_SHA256,
            "pinned C6.5 sink Component digest changed: {sink_observed:02x?}"
        );
        assert!(
            source_observed != relay_observed
                && source_observed != sink_observed
                && relay_observed != sink_observed,
            "the three C6.5 Component artifacts must have distinct identities"
        );
        let wit_observed: [u8; 32] = Sha256::digest(C65_ASYNC_CHAIN_WIT.as_bytes()).into();
        assert_eq!(
            wit_observed, C65_ASYNC_CHAIN_WIT_EXPECTED_SHA256,
            "pinned C6.5 chain WIT digest changed: {wit_observed:02x?}"
        );

        fs::write(output.join("c65-async-source.component.wasm"), source)
            .expect("write pinned C6.5 source Component artifact");
        fs::write(output.join("c65-async-relay.component.wasm"), relay)
            .expect("write pinned C6.5 relay Component artifact");
        fs::write(output.join("c65-async-sink.component.wasm"), sink)
            .expect("write pinned C6.5 sink Component artifact");
        fs::write(
            output.join("c65-async-source.sha256.rs"),
            format!("{C65_ASYNC_SOURCE_EXPECTED_SHA256:?}"),
        )
        .expect("write checked C6.5 source Component identity constant");
        fs::write(
            output.join("c65-async-relay.sha256.rs"),
            format!("{C65_ASYNC_RELAY_EXPECTED_SHA256:?}"),
        )
        .expect("write checked C6.5 relay Component identity constant");
        fs::write(
            output.join("c65-async-sink.sha256.rs"),
            format!("{C65_ASYNC_SINK_EXPECTED_SHA256:?}"),
        )
        .expect("write checked C6.5 sink Component identity constant");
        fs::write(
            output.join("c65-async-chain-wit.sha256.rs"),
            format!("{C65_ASYNC_CHAIN_WIT_EXPECTED_SHA256:?}"),
        )
        .expect("write checked C6.5 chain WIT identity constant");

        if env::var_os("CARGO_FEATURE_C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE").is_some() {
            let relay_v2 = wat::parse_str(C66_ASYNC_RELAY_V2_SOURCE)
                .expect("pinned C6.6 replacement relay Component WAT must parse");
            let relay_v2_observed: [u8; 32] = Sha256::digest(&relay_v2).into();
            assert_eq!(
                relay_v2_observed, C66_ASYNC_RELAY_V2_EXPECTED_SHA256,
                "pinned C6.6 replacement relay Component digest changed: {relay_v2_observed:02x?}"
            );
            assert_ne!(
                relay_v2_observed, relay_observed,
                "the C6.6 old and replacement relay identities must be distinct"
            );
            assert!(
                relay_v2_observed != source_observed && relay_v2_observed != sink_observed,
                "the C6.6 replacement relay identity must be graph-node-local"
            );
            fs::write(output.join("c66-async-relay-v2.component.wasm"), relay_v2)
                .expect("write pinned C6.6 replacement relay Component artifact");
            fs::write(
                output.join("c66-async-relay-v2.sha256.rs"),
                format!("{C66_ASYNC_RELAY_V2_EXPECTED_SHA256:?}"),
            )
            .expect("write checked C6.6 replacement relay Component identity constant");
        }
    }
}
