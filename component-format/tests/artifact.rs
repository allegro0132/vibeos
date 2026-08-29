use std::ops::Range;

use sha2::{Digest, Sha256};
use vibeos_component_format::{
    CanonicalAbiFeature, ComponentArtifactAdapterV1, ComponentArtifactCoreModuleV1,
    ComponentArtifactEntityKind, ComponentArtifactError, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactInterfaceDirection, ComponentArtifactInterfaceV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyKind, ComponentArtifactSignerPolicyV1, ComponentArtifactV1,
    ComponentArtifactWitPackageV1, ProfileIdentity, ProfileStage,
    COMPONENT_ARTIFACT_FORMAT_VERSION, COMPONENT_ARTIFACT_HASH_SHA256,
    COMPONENT_ARTIFACT_HEADER_LEN, COMPONENT_ARTIFACT_MANIFEST_VERSION,
    COMPONENT_ARTIFACT_OBJECT_KIND_RAW, COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION,
    MAX_COMPONENT_ARTIFACT_ENCODED_BYTES, PROFILE_1_LIMITS, PROFILE_2_SYNC_FLOAT_PROFILE_CODE,
    PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE,
};

const COMPONENT_BYTES: &[u8] = b"\0asm\r\0\x01\0secret-component-body-c71";
const WIT_A: &str = "package alpha:api@1.0.0;\n\nworld alpha-world {\n  export run: func();\n}\n";
const WIT_Z: &str =
    "package zeta:api@2.3.0;\n\nworld zeta-world {\n  import log: func(value: string);\n}\n";
const ADAPTER_ZERO: &[u8] = b"canonical-lower-descriptor-zero";
const ADAPTER_ONE: &[u8] = b"canonical-lower-descriptor-one";
const CORE_ONE: &[u8] = b"\0asm\x01\0\0\0module-one";
const CORE_TWO: &[u8] = b"\0asm\x01\0\0\0module-two-is-distinct";
const POLICY_DIGEST: [u8; 32] = [0xa5; 32];
const GOLDEN_ARTIFACT_SHA256: [u8; 32] = [
    0xd2, 0x99, 0xf6, 0x99, 0x30, 0xd6, 0xcf, 0x01, 0x47, 0x67, 0x52, 0xf9, 0xbc, 0x02, 0xf3, 0x71,
    0x52, 0xe2, 0x39, 0x6d, 0xd7, 0x88, 0xf4, 0xfd, 0xfb, 0xab, 0x3c, 0xbb, 0x71, 0xf1, 0x55, 0x56,
];

const FLAGS_OFFSET: usize = 12;
const OBJECT_KIND_OFFSET: usize = 16;
const HASH_ALGORITHM_OFFSET: usize = 20;
const PROFILE_CODE_OFFSET: usize = 22;
const PROFILE_STAGE_OFFSET: usize = 24;
const MANIFEST_VERSION_OFFSET: usize = 26;
const SIGNER_KIND_OFFSET: usize = 28;
const SIGNER_VERSION_OFFSET: usize = 30;
const ARTIFACT_ABI_OFFSET: usize = 32;
const COMPONENT_PROFILE_OFFSET: usize = 34;
const CORE_PROFILE_OFFSET: usize = 36;
const RUNTIME_ABI_OFFSET: usize = 38;
const CANONICAL_FEATURES_OFFSET: usize = 40;
const CONTRACT_LEN_OFFSET: usize = 48;
const MANIFEST_LEN_OFFSET: usize = 56;
const COMPONENT_LEN_OFFSET: usize = 64;
const TOTAL_LEN_OFFSET: usize = 72;
const WIT_COUNT_OFFSET: usize = 80;
const INTERFACE_COUNT_OFFSET: usize = 84;
const MODULE_COUNT_OFFSET: usize = 88;
const ADAPTER_COUNT_OFFSET: usize = 92;
const PROFILE_LIMIT_COUNT_OFFSET: usize = 96;
const INSTANCE_LIMIT_COUNT_OFFSET: usize = 98;
const REVISION_COUNT_OFFSET: usize = 100;
const HEADER_RESERVED0_OFFSET: usize = 102;
const COMPONENT_HASH_OFFSET: usize = 104;
const CONTRACT_HASH_OFFSET: usize = 136;
const MANIFEST_HASH_OFFSET: usize = 168;
const BODY_HASH_OFFSET: usize = 200;
const SIGNER_POLICY_DIGEST_OFFSET: usize = 232;
const ARTIFACT_COMMITMENT_OFFSET: usize = 264;
const HEADER_RESERVED1_OFFSET: usize = 296;

const MANIFEST_HEADER_LEN: usize = 40;
const CONTRACT_HEADER_LEN: usize = 24;
const PROFILE_REVISION_FIELD_COUNT: usize = 5;
const PROFILE_LIMIT_FIELD_COUNT: usize = 44;

const BODY_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.body.v1\0";
const COMMITMENT_DOMAIN: &[u8] = b"vibeos.component-artifact.commitment.v1\0";
const COMPONENT_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.component.v1\0";
const CONTRACT_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.contract.v1\0";
const MANIFEST_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.manifest.v1\0";
const WIT_SOURCE_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.wit-source.v1\0";
const CORE_MODULE_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.core-module.v1\0";
const ADAPTER_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.adapter.v1\0";

fn package_a() -> ComponentArtifactWitPackageV1 {
    ComponentArtifactWitPackageV1::new("alpha:api", "1.0.0", WIT_A).unwrap()
}

fn package_z() -> ComponentArtifactWitPackageV1 {
    ComponentArtifactWitPackageV1::new("zeta:api", "2.3.0", WIT_Z).unwrap()
}

fn import_interface() -> ComponentArtifactInterfaceV1 {
    ComponentArtifactInterfaceV1::new(
        ComponentArtifactInterfaceDirection::Import,
        ComponentArtifactEntityKind::Interface,
        "alpha:api/logger",
        "instance{log:func(string)}",
    )
    .unwrap()
}

fn export_function() -> ComponentArtifactInterfaceV1 {
    ComponentArtifactInterfaceV1::new(
        ComponentArtifactInterfaceDirection::Export,
        ComponentArtifactEntityKind::Function,
        "zeta:api/run",
        "func(u32)->u32",
    )
    .unwrap()
}

fn many_interfaces(
    direction: ComponentArtifactInterfaceDirection,
    count: usize,
) -> Vec<ComponentArtifactInterfaceV1> {
    (0..count)
        .map(|index| {
            ComponentArtifactInterfaceV1::new(
                direction,
                ComponentArtifactEntityKind::Function,
                &format!("test:many/entity-{index}"),
                "func()",
            )
            .unwrap()
        })
        .collect()
}

fn module_one() -> ComponentArtifactCoreModuleV1 {
    ComponentArtifactCoreModuleV1::from_bytes(CORE_ONE).unwrap()
}

fn module_two() -> ComponentArtifactCoreModuleV1 {
    ComponentArtifactCoreModuleV1::from_bytes(CORE_TWO).unwrap()
}

fn adapter_zero() -> ComponentArtifactAdapterV1 {
    ComponentArtifactAdapterV1::new(0, "canonical-lower-v1", ADAPTER_ZERO).unwrap()
}

fn adapter_one() -> ComponentArtifactAdapterV1 {
    ComponentArtifactAdapterV1::new(1, "canonical-lower-v2", ADAPTER_ONE).unwrap()
}

fn manifest(reverse_canonical_inputs: bool) -> ComponentArtifactManifestV1 {
    let (packages, interfaces, adapters) = if reverse_canonical_inputs {
        (
            vec![package_z(), package_a()],
            vec![export_function(), import_interface()],
            vec![adapter_one(), adapter_zero()],
        )
    } else {
        (
            vec![package_a(), package_z()],
            vec![import_interface(), export_function()],
            vec![adapter_zero(), adapter_one()],
        )
    };
    ComponentArtifactManifestV1::new(
        "alpha:api/root",
        packages,
        interfaces,
        vec![module_one(), module_two()],
        adapters,
    )
    .unwrap()
}

fn limits() -> ComponentArtifactInstanceLimitsV1 {
    ComponentArtifactInstanceLimitsV1::new(8 * 65_536, 456_789, 1_000, 7).unwrap()
}

fn signer_policy() -> ComponentArtifactSignerPolicyV1 {
    ComponentArtifactSignerPolicyV1::operator_required(POLICY_DIGEST).unwrap()
}

fn artifact(profile: ProfileIdentity) -> ComponentArtifactV1 {
    ComponentArtifactV1::new(
        COMPONENT_BYTES,
        profile,
        limits(),
        signer_policy(),
        manifest(false),
    )
    .unwrap()
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn role_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(bytes.len()).unwrap().to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Clone, Copy)]
struct EnvelopeLayout {
    contract: RangeEnds,
    manifest: RangeEnds,
    component: RangeEnds,
}

#[derive(Clone, Copy)]
struct RangeEnds {
    start: usize,
    end: usize,
}

impl RangeEnds {
    fn range(self) -> Range<usize> {
        self.start..self.end
    }
}

fn envelope_layout(bytes: &[u8]) -> EnvelopeLayout {
    let contract_len = usize::try_from(read_u64(bytes, CONTRACT_LEN_OFFSET)).unwrap();
    let manifest_len = usize::try_from(read_u64(bytes, MANIFEST_LEN_OFFSET)).unwrap();
    let component_len = usize::try_from(read_u64(bytes, COMPONENT_LEN_OFFSET)).unwrap();
    let contract_start = COMPONENT_ARTIFACT_HEADER_LEN;
    let manifest_start = contract_start + contract_len;
    let component_start = manifest_start + manifest_len;
    assert_eq!(component_start + component_len, bytes.len());
    EnvelopeLayout {
        contract: RangeEnds {
            start: contract_start,
            end: manifest_start,
        },
        manifest: RangeEnds {
            start: manifest_start,
            end: component_start,
        },
        component: RangeEnds {
            start: component_start,
            end: bytes.len(),
        },
    }
}

fn body_hash(contract: &[u8], manifest: &[u8], component: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BODY_HASH_DOMAIN);
    hasher.update(u64::try_from(contract.len()).unwrap().to_le_bytes());
    hasher.update(contract);
    hasher.update(u64::try_from(manifest.len()).unwrap().to_le_bytes());
    hasher.update(manifest);
    hasher.update(u64::try_from(component.len()).unwrap().to_le_bytes());
    hasher.update(component);
    hasher.finalize().into()
}

fn commitment_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap().to_le_bytes());
    hasher.update(&bytes[..ARTIFACT_COMMITMENT_OFFSET]);
    hasher.update([0_u8; 32]);
    hasher.update(&bytes[ARTIFACT_COMMITMENT_OFFSET + 32..]);
    hasher.finalize().into()
}

/// Repair only the deliberately unkeyed outer checksums after a deep wire
/// mutation. This lets tests reach the canonical record decoder; it does not
/// model C7.3 signer authentication.
fn repair_outer_checksums(bytes: &mut [u8]) {
    let layout = envelope_layout(bytes);
    let component_hash = role_hash(COMPONENT_HASH_DOMAIN, &bytes[layout.component.range()]);
    let contract_hash = role_hash(CONTRACT_HASH_DOMAIN, &bytes[layout.contract.range()]);
    let manifest_hash = role_hash(MANIFEST_HASH_DOMAIN, &bytes[layout.manifest.range()]);
    let body_hash = body_hash(
        &bytes[layout.contract.range()],
        &bytes[layout.manifest.range()],
        &bytes[layout.component.range()],
    );
    bytes[COMPONENT_HASH_OFFSET..COMPONENT_HASH_OFFSET + 32].copy_from_slice(&component_hash);
    bytes[CONTRACT_HASH_OFFSET..CONTRACT_HASH_OFFSET + 32].copy_from_slice(&contract_hash);
    bytes[MANIFEST_HASH_OFFSET..MANIFEST_HASH_OFFSET + 32].copy_from_slice(&manifest_hash);
    bytes[BODY_HASH_OFFSET..BODY_HASH_OFFSET + 32].copy_from_slice(&body_hash);
    bytes[ARTIFACT_COMMITMENT_OFFSET..ARTIFACT_COMMITMENT_OFFSET + 32].fill(0);
    let commitment = commitment_hash(bytes);
    bytes[ARTIFACT_COMMITMENT_OFFSET..ARTIFACT_COMMITMENT_OFFSET + 32].copy_from_slice(&commitment);
}

#[derive(Debug)]
struct WitRecord {
    whole: Range<usize>,
    reserved: usize,
    source: Range<usize>,
    digest: usize,
}

#[derive(Debug)]
struct AdapterRecord {
    reserved0: usize,
    reserved1: usize,
    bytes: Range<usize>,
    digest: usize,
}

#[derive(Debug)]
struct ManifestPositions {
    start: usize,
    wit: Vec<WitRecord>,
    adapter: Vec<AdapterRecord>,
}

fn manifest_positions(bytes: &[u8]) -> ManifestPositions {
    let layout = envelope_layout(bytes);
    let start = layout.manifest.start;
    let world_len = usize::from(read_u16(bytes, start + 16));
    let wit_count = usize::try_from(read_u32(bytes, start + 20)).unwrap();
    let interface_count = usize::try_from(read_u32(bytes, start + 24)).unwrap();
    let module_count = usize::try_from(read_u32(bytes, start + 28)).unwrap();
    let adapter_count = usize::try_from(read_u32(bytes, start + 32)).unwrap();
    let mut offset = start + MANIFEST_HEADER_LEN + world_len;
    let mut wit = Vec::with_capacity(wit_count);
    for _ in 0..wit_count {
        let record_start = offset;
        let name_len = usize::from(read_u16(bytes, offset));
        let version_len = usize::from(read_u16(bytes, offset + 2));
        let source_len = usize::try_from(read_u32(bytes, offset + 4)).unwrap();
        let source_start = offset + 12 + name_len + version_len;
        let digest = source_start + source_len;
        offset = digest + 32;
        wit.push(WitRecord {
            whole: record_start..offset,
            reserved: record_start + 8,
            source: source_start..digest,
            digest,
        });
    }
    for _ in 0..interface_count {
        let name_len = usize::from(read_u16(bytes, offset + 4));
        let shape_len = usize::try_from(read_u32(bytes, offset + 8)).unwrap();
        offset += 12 + name_len + shape_len;
    }
    offset += module_count * 40;
    let mut adapter = Vec::with_capacity(adapter_count);
    for _ in 0..adapter_count {
        let record_start = offset;
        let revision_len = usize::from(read_u16(bytes, offset + 4));
        let adapter_len = usize::try_from(read_u32(bytes, offset + 8)).unwrap();
        let bytes_start = offset + 16 + revision_len;
        let digest = bytes_start + adapter_len;
        offset = digest + 32;
        adapter.push(AdapterRecord {
            reserved0: record_start + 6,
            reserved1: record_start + 12,
            bytes: bytes_start..digest,
            digest,
        });
    }
    assert_eq!(offset, layout.manifest.end);
    ManifestPositions {
        start,
        wit,
        adapter,
    }
}

fn contract_value_offsets(bytes: &[u8]) -> (Vec<Range<usize>>, Vec<usize>, Vec<usize>) {
    let layout = envelope_layout(bytes);
    let mut offset = layout.contract.start + CONTRACT_HEADER_LEN;
    let mut revisions = Vec::new();
    for _ in 0..PROFILE_REVISION_FIELD_COUNT {
        let len = usize::try_from(read_u32(bytes, offset)).unwrap();
        let start = offset + 4;
        revisions.push(start..start + len);
        offset = start + len;
    }
    let profile_limits = (0..PROFILE_LIMIT_FIELD_COUNT)
        .map(|_| {
            let result = offset;
            offset += 8;
            result
        })
        .collect();
    let instance_limits = (0..4)
        .map(|_| {
            let result = offset;
            offset += 8;
            result
        })
        .collect();
    assert_eq!(offset, layout.contract.end);
    (revisions, profile_limits, instance_limits)
}

#[test]
fn builder_canonicalizes_sets_and_roundtrips_exact_bytes() {
    let first = ComponentArtifactV1::new(
        COMPONENT_BYTES,
        ProfileIdentity::PROFILE_1_ASYNC,
        limits(),
        signer_policy(),
        manifest(false),
    )
    .unwrap();
    let reversed = ComponentArtifactV1::new(
        COMPONENT_BYTES,
        ProfileIdentity::PROFILE_1_ASYNC,
        limits(),
        signer_policy(),
        manifest(true),
    )
    .unwrap();

    let encoded = first.encode().unwrap();
    let encoded_sha256: [u8; 32] = Sha256::digest(&encoded).into();
    assert_eq!(encoded_sha256, GOLDEN_ARTIFACT_SHA256);
    assert_eq!(encoded, reversed.encode().unwrap());
    let decoded = ComponentArtifactV1::decode(&encoded).unwrap();
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(decoded, first);
    assert!(!decoded.runtime_ready());
    assert_eq!(decoded.component_bytes(), COMPONENT_BYTES);
    assert_eq!(
        decoded.component_commitment().as_bytes(),
        &role_hash(COMPONENT_HASH_DOMAIN, COMPONENT_BYTES)
    );
    assert_eq!(
        decoded.artifact_commitment().unwrap().as_bytes(),
        &encoded[ARTIFACT_COMMITMENT_OFFSET..ARTIFACT_COMMITMENT_OFFSET + 32]
    );
}

#[test]
fn exact_wit_sources_modules_and_independent_adapters_survive_roundtrip() {
    let decoded = ComponentArtifactV1::decode(
        &artifact(ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE)
            .encode()
            .unwrap(),
    )
    .unwrap();
    let manifest = decoded.manifest();

    assert_eq!(manifest.world(), "alpha:api/root");
    assert_eq!(manifest.wit_packages().len(), 2);
    assert_eq!(manifest.wit_packages()[0].name(), "alpha:api");
    assert_eq!(manifest.wit_packages()[0].source(), WIT_A);
    assert_eq!(
        manifest.wit_packages()[0].source_commitment().as_bytes(),
        &role_hash(WIT_SOURCE_HASH_DOMAIN, WIT_A.as_bytes())
    );
    assert_eq!(manifest.wit_packages()[1].name(), "zeta:api");
    assert_eq!(manifest.wit_packages()[1].source(), WIT_Z);

    assert_eq!(
        manifest.interfaces()[0].direction(),
        ComponentArtifactInterfaceDirection::Import
    );
    assert_eq!(manifest.interfaces()[0].name(), "alpha:api/logger");
    assert_eq!(
        manifest.interfaces()[0].diagnostic_shape(),
        "instance{log:func(string)}"
    );
    assert_eq!(
        manifest.interfaces()[1].direction(),
        ComponentArtifactInterfaceDirection::Export
    );
    assert_eq!(manifest.core_modules().len(), 2);
    assert_eq!(
        manifest.core_modules()[0].commitment().as_bytes(),
        &role_hash(CORE_MODULE_HASH_DOMAIN, CORE_ONE)
    );
    assert_eq!(
        manifest.core_modules()[1].commitment().as_bytes(),
        &role_hash(CORE_MODULE_HASH_DOMAIN, CORE_TWO)
    );
    assert_ne!(
        manifest.core_modules()[0].commitment(),
        manifest.core_modules()[1].commitment()
    );
    assert_eq!(manifest.adapters().len(), 2);
    assert_eq!(manifest.adapters()[0].ordinal(), 0);
    assert_eq!(manifest.adapters()[0].bytes(), ADAPTER_ZERO);
    assert_eq!(
        manifest.adapters()[0].commitment().as_bytes(),
        &role_hash(ADAPTER_HASH_DOMAIN, ADAPTER_ZERO)
    );
    assert_eq!(manifest.adapters()[1].ordinal(), 1);
    assert_eq!(manifest.adapters()[1].bytes(), ADAPTER_ONE);
    assert_eq!(
        manifest.adapters()[1].commitment().as_bytes(),
        &role_hash(ADAPTER_HASH_DOMAIN, ADAPTER_ONE)
    );
    assert_ne!(
        manifest.adapters()[0].commitment().as_bytes(),
        manifest.core_modules()[0].commitment().as_bytes()
    );
    assert_ne!(
        manifest.adapters()[1].commitment().as_bytes(),
        manifest.core_modules()[1].commitment().as_bytes()
    );
}

#[test]
fn every_frozen_profile_variant_is_exact_and_stays_inert() {
    for profile in [
        ProfileIdentity::PROFILE_1_SYNC,
        ProfileIdentity::PROFILE_1_ASYNC,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
        ProfileIdentity::PROFILE_2_SYNC_FLOAT,
    ] {
        let expected = artifact(profile);
        let encoded = expected.encode().unwrap();
        let decoded = ComponentArtifactV1::decode(&encoded).unwrap();
        assert_eq!(decoded.profile(), profile);
        assert_eq!(decoded.profile_limits(), PROFILE_1_LIMITS);
        assert_eq!(decoded.instance_limits(), limits());
        assert_eq!(
            decoded.signer_policy().kind(),
            ComponentArtifactSignerPolicyKind::OperatorRequired
        );
        assert!(!decoded.runtime_ready());
        assert_eq!(decoded.encode().unwrap(), encoded);
    }
}

#[test]
fn c81_preview1_wrapped_profile_code_roundtrips_and_adjacent_identities_fail_closed() {
    let profile = ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED;
    let encoded = artifact(profile).encode().unwrap();

    assert_eq!(read_u16(&encoded, PROFILE_CODE_OFFSET), 4);
    assert_eq!(read_u16(&encoded, PROFILE_STAGE_OFFSET), 2);
    assert_eq!(read_u16(&encoded, ARTIFACT_ABI_OFFSET), 4);
    assert_eq!(read_u16(&encoded, RUNTIME_ABI_OFFSET), 4);
    assert_eq!(
        read_u64(&encoded, CANONICAL_FEATURES_OFFSET),
        profile.canonical_features
    );
    let decoded = ComponentArtifactV1::decode(&encoded).unwrap();
    assert_eq!(decoded.profile(), profile);
    assert!(!decoded.runtime_ready());
    assert_eq!(decoded.encode().unwrap(), encoded);

    let mut unknown_code = encoded;
    write_u16(&mut unknown_code, PROFILE_CODE_OFFSET, u16::MAX);
    assert_eq!(
        ComponentArtifactV1::decode(&unknown_code),
        Err(ComponentArtifactError::Profile)
    );

    let adjacent = [
        {
            let mut adjacent = profile;
            adjacent.artifact_abi = adjacent.artifact_abi.wrapping_add(1);
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.component_profile = adjacent.component_profile.wrapping_add(1);
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.core_profile = adjacent.core_profile.wrapping_add(1);
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.runtime_abi = adjacent.runtime_abi.wrapping_add(1);
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.core_revision = "adjacent-core";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.component_revision = "adjacent-component";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.canonical_abi_revision = "adjacent-canonical";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.wasm_tools_revision = "adjacent-wasm-tools";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.wasi_revision = "adjacent-wasi";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.canonical_features ^= 1;
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.stage = ProfileStage::Executable;
            adjacent
        },
    ];
    for adjacent in adjacent {
        assert_eq!(
            ComponentArtifactV1::new(
                COMPONENT_BYTES,
                adjacent,
                limits(),
                signer_policy(),
                manifest(false),
            ),
            Err(ComponentArtifactError::Profile),
            "accepted adjacent profile: {adjacent:?}"
        );
    }
}

#[test]
fn c89_code6_roundtrips_without_reinterpreting_code5() {
    let artifact = artifact(ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE);
    let encoded = artifact.encode().unwrap();
    assert_eq!(
        u16::from_le_bytes(
            encoded[PROFILE_CODE_OFFSET..PROFILE_CODE_OFFSET + 2]
                .try_into()
                .unwrap()
        ),
        PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE
    );
    let decoded = ComponentArtifactV1::decode(&encoded).unwrap();
    assert_eq!(
        decoded.profile(),
        ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE
    );
    assert!(decoded.profile().execution_enabled());
    assert_eq!(PROFILE_2_SYNC_FLOAT_PROFILE_CODE, 5);
    assert!(!ProfileIdentity::PROFILE_2_SYNC_FLOAT.execution_enabled());
}

#[test]
fn c88_f1_sync_float_code5_roundtrips_but_stays_validation_only() {
    let profile = ProfileIdentity::PROFILE_2_SYNC_FLOAT;
    let encoded = artifact(profile).encode().unwrap();

    assert_eq!(PROFILE_2_SYNC_FLOAT_PROFILE_CODE, 5);
    assert_eq!(read_u16(&encoded, PROFILE_CODE_OFFSET), 5);
    assert_eq!(read_u16(&encoded, PROFILE_STAGE_OFFSET), 2);
    assert_eq!(read_u16(&encoded, ARTIFACT_ABI_OFFSET), 5);
    assert_eq!(read_u16(&encoded, COMPONENT_PROFILE_OFFSET), 2);
    assert_eq!(read_u16(&encoded, CORE_PROFILE_OFFSET), 2);
    assert_eq!(read_u16(&encoded, RUNTIME_ABI_OFFSET), 5);
    assert_eq!(
        read_u64(&encoded, CANONICAL_FEATURES_OFFSET),
        profile.canonical_features
    );
    assert_ne!(
        read_u64(&encoded, CANONICAL_FEATURES_OFFSET) & CanonicalAbiFeature::FloatValues.bit(),
        0
    );

    let decoded = ComponentArtifactV1::decode(&encoded).unwrap();
    assert_eq!(decoded.profile(), profile);
    assert_eq!(decoded.profile().stage, ProfileStage::ValidationOnly);
    assert!(!decoded.profile().execution_enabled());
    assert!(!decoded.runtime_ready());
    assert_eq!(decoded.encode().unwrap(), encoded);

    for (offset, adjacent) in [
        (PROFILE_CODE_OFFSET, 4),
        (PROFILE_CODE_OFFSET, 6),
        (PROFILE_STAGE_OFFSET, 1),
        (ARTIFACT_ABI_OFFSET, 4),
        (ARTIFACT_ABI_OFFSET, 6),
        (COMPONENT_PROFILE_OFFSET, 1),
        (COMPONENT_PROFILE_OFFSET, 3),
        (CORE_PROFILE_OFFSET, 1),
        (CORE_PROFILE_OFFSET, 3),
        (RUNTIME_ABI_OFFSET, 4),
        (RUNTIME_ABI_OFFSET, 6),
    ] {
        let mut mutated = encoded.clone();
        write_u16(&mut mutated, offset, adjacent);
        assert_eq!(
            ComponentArtifactV1::decode(&mutated),
            Err(ComponentArtifactError::Profile),
            "accepted offset {offset} value {adjacent}"
        );
    }

    let mut adjacent_features = encoded.clone();
    write_u64(
        &mut adjacent_features,
        CANONICAL_FEATURES_OFFSET,
        profile.canonical_features ^ CanonicalAbiFeature::FloatValues.bit(),
    );
    assert_eq!(
        ComponentArtifactV1::decode(&adjacent_features),
        Err(ComponentArtifactError::Profile)
    );

    let adjacent_identities = [
        {
            let mut adjacent = profile;
            adjacent.artifact_abi = 6;
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.component_profile = 3;
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.core_profile = 3;
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.runtime_abi = 6;
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.core_revision = "adjacent-core";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.component_revision = "adjacent-component";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.canonical_abi_revision = "adjacent-canonical";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.wasm_tools_revision = "adjacent-wasm-tools";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.wasi_revision = "adjacent-wasi";
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.canonical_features ^= CanonicalAbiFeature::FloatValues.bit();
            adjacent
        },
        {
            let mut adjacent = profile;
            adjacent.stage = ProfileStage::Executable;
            adjacent
        },
    ];
    for adjacent in adjacent_identities {
        assert_eq!(
            ComponentArtifactV1::new(
                COMPONENT_BYTES,
                adjacent,
                limits(),
                signer_policy(),
                manifest(false),
            ),
            Err(ComponentArtifactError::Profile),
            "accepted adjacent profile: {adjacent:?}"
        );
    }
}

#[test]
fn canonical_header_has_exact_versions_kind_counts_and_zero_reservations() {
    let artifact = artifact(ProfileIdentity::PROFILE_1_ASYNC);
    let bytes = artifact.encode().unwrap();
    assert_eq!(read_u16(&bytes, 8), COMPONENT_ARTIFACT_FORMAT_VERSION);
    assert_eq!(
        usize::from(read_u16(&bytes, 10)),
        COMPONENT_ARTIFACT_HEADER_LEN
    );
    assert_eq!(read_u32(&bytes, FLAGS_OFFSET), 0);
    assert_eq!(
        read_u32(&bytes, OBJECT_KIND_OFFSET),
        COMPONENT_ARTIFACT_OBJECT_KIND_RAW
    );
    assert_eq!(
        read_u16(&bytes, HASH_ALGORITHM_OFFSET),
        COMPONENT_ARTIFACT_HASH_SHA256
    );
    assert_eq!(
        read_u16(&bytes, MANIFEST_VERSION_OFFSET),
        COMPONENT_ARTIFACT_MANIFEST_VERSION
    );
    assert_eq!(
        read_u16(&bytes, SIGNER_VERSION_OFFSET),
        COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION
    );
    assert_eq!(read_u32(&bytes, WIT_COUNT_OFFSET), 2);
    assert_eq!(read_u32(&bytes, INTERFACE_COUNT_OFFSET), 2);
    assert_eq!(read_u32(&bytes, MODULE_COUNT_OFFSET), 2);
    assert_eq!(read_u32(&bytes, ADAPTER_COUNT_OFFSET), 2);
    assert_eq!(read_u16(&bytes, PROFILE_LIMIT_COUNT_OFFSET), 44);
    assert_eq!(read_u16(&bytes, INSTANCE_LIMIT_COUNT_OFFSET), 4);
    assert_eq!(read_u16(&bytes, REVISION_COUNT_OFFSET), 5);
    assert_eq!(read_u16(&bytes, HEADER_RESERVED0_OFFSET), 0);
    assert!(
        bytes[HEADER_RESERVED1_OFFSET..COMPONENT_ARTIFACT_HEADER_LEN]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(read_u64(&bytes, TOTAL_LEN_OFFSET) as usize, bytes.len());
    assert!(bytes.len() <= MAX_COMPONENT_ARTIFACT_ENCODED_BYTES);
}

#[test]
fn constructors_reject_invalid_limits_policy_text_payloads_and_duplicates() {
    let maximum_memory = u64::from(PROFILE_1_LIMITS.max_memory_pages) * 65_536;
    assert_eq!(
        ComponentArtifactInstanceLimitsV1::new(0, 1, 1, 1),
        Err(ComponentArtifactError::Limits)
    );
    assert_eq!(
        ComponentArtifactInstanceLimitsV1::new(maximum_memory + 1, 1, 1, 1),
        Err(ComponentArtifactError::Limits)
    );
    assert_eq!(
        ComponentArtifactInstanceLimitsV1::new(1, 0, 1, 1),
        Err(ComponentArtifactError::Limits)
    );
    assert_eq!(
        ComponentArtifactInstanceLimitsV1::new(1, 10, 11, 1),
        Err(ComponentArtifactError::Limits)
    );
    assert_eq!(
        ComponentArtifactInstanceLimitsV1::new(1, 10, 1, 0),
        Err(ComponentArtifactError::Limits)
    );
    assert_eq!(
        ComponentArtifactSignerPolicyV1::operator_required([0; 32]),
        Err(ComponentArtifactError::SignerPolicy)
    );
    assert_eq!(
        ComponentArtifactWitPackageV1::new("bad name", "1", WIT_A),
        Err(ComponentArtifactError::InvalidText)
    );
    assert_eq!(
        ComponentArtifactWitPackageV1::new("alpha:api", "1", ""),
        Err(ComponentArtifactError::InvalidText)
    );
    assert_eq!(
        ComponentArtifactWitPackageV1::new("alpha:api", "1", "a\0b"),
        Err(ComponentArtifactError::InvalidText)
    );
    assert_eq!(
        ComponentArtifactInterfaceV1::new(
            ComponentArtifactInterfaceDirection::Import,
            ComponentArtifactEntityKind::Function,
            "alpha:api/run",
            "shape with spaces",
        ),
        Err(ComponentArtifactError::InvalidText)
    );
    assert_eq!(
        ComponentArtifactCoreModuleV1::from_bytes(&[]),
        Err(ComponentArtifactError::Manifest)
    );
    assert_eq!(
        ComponentArtifactAdapterV1::new(0, "canonical-lower-v1", &[]),
        Err(ComponentArtifactError::Manifest)
    );
    assert_eq!(
        ComponentArtifactAdapterV1::new(0, "bad revision", b"x"),
        Err(ComponentArtifactError::InvalidText)
    );

    let duplicate_wit = ComponentArtifactManifestV1::new(
        "alpha:api/root",
        vec![
            package_a(),
            ComponentArtifactWitPackageV1::new("alpha:api", "1.0.0", WIT_Z).unwrap(),
        ],
        vec![],
        vec![],
        vec![],
    );
    assert_eq!(
        duplicate_wit,
        Err(ComponentArtifactError::DuplicateManifestEntry)
    );
    let duplicate_interface = ComponentArtifactManifestV1::new(
        "alpha:api/root",
        vec![package_a()],
        vec![
            import_interface(),
            ComponentArtifactInterfaceV1::new(
                ComponentArtifactInterfaceDirection::Import,
                ComponentArtifactEntityKind::Function,
                "alpha:api/logger",
                "func()",
            )
            .unwrap(),
        ],
        vec![],
        vec![],
    );
    assert_eq!(
        duplicate_interface,
        Err(ComponentArtifactError::DuplicateManifestEntry)
    );
    let duplicate_adapter = ComponentArtifactManifestV1::new(
        "alpha:api/root",
        vec![package_a()],
        vec![],
        vec![],
        vec![
            adapter_zero(),
            ComponentArtifactAdapterV1::new(0, "other-v1", b"other").unwrap(),
        ],
    );
    assert_eq!(
        duplicate_adapter,
        Err(ComponentArtifactError::DuplicateManifestEntry)
    );
    let adapter_gap = ComponentArtifactManifestV1::new(
        "alpha:api/root",
        vec![package_a()],
        vec![],
        vec![],
        vec![ComponentArtifactAdapterV1::new(1, "other-v1", b"other").unwrap()],
    );
    assert_eq!(adapter_gap, Err(ComponentArtifactError::Manifest));
    assert_eq!(
        ComponentArtifactManifestV1::new("alpha:api/root", vec![], vec![], vec![], vec![]),
        Err(ComponentArtifactError::Manifest)
    );

    assert_eq!(
        ComponentArtifactV1::new(
            &[],
            ProfileIdentity::PROFILE_1_SYNC,
            limits(),
            signer_policy(),
            manifest(false),
        ),
        Err(ComponentArtifactError::EmptyComponent)
    );
    let oversized = vec![0_u8; PROFILE_1_LIMITS.max_component_bytes + 1];
    assert_eq!(
        ComponentArtifactV1::new(
            &oversized,
            ProfileIdentity::PROFILE_1_SYNC,
            limits(),
            signer_policy(),
            manifest(false),
        ),
        Err(ComponentArtifactError::TooLarge)
    );

    let mut unsupported = ProfileIdentity::PROFILE_1_SYNC;
    unsupported.runtime_abi = unsupported.runtime_abi.wrapping_add(1);
    assert_eq!(
        ComponentArtifactV1::new(
            COMPONENT_BYTES,
            unsupported,
            limits(),
            signer_policy(),
            manifest(false),
        ),
        Err(ComponentArtifactError::Profile)
    );
}

#[test]
fn import_and_export_limits_are_enforced_independently() {
    for (direction, maximum) in [
        (
            ComponentArtifactInterfaceDirection::Import,
            usize::try_from(PROFILE_1_LIMITS.max_imports).unwrap(),
        ),
        (
            ComponentArtifactInterfaceDirection::Export,
            usize::try_from(PROFILE_1_LIMITS.max_exports).unwrap(),
        ),
    ] {
        let exact = ComponentArtifactManifestV1::new(
            "alpha:api/root",
            vec![package_a()],
            many_interfaces(direction, maximum),
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(exact.interfaces().len(), maximum);

        assert_eq!(
            ComponentArtifactManifestV1::new(
                "alpha:api/root",
                vec![package_a()],
                many_interfaces(direction, maximum + 1),
                vec![],
                vec![],
            ),
            Err(ComponentArtifactError::Manifest)
        );
    }
}

#[test]
fn every_strict_prefix_suffix_and_appended_byte_is_rejected() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    for end in 0..encoded.len() {
        assert!(
            ComponentArtifactV1::decode(&encoded[..end]).is_err(),
            "accepted strict prefix ending at {end}"
        );
    }
    for start in 1..=encoded.len() {
        assert!(
            ComponentArtifactV1::decode(&encoded[start..]).is_err(),
            "accepted strict suffix starting at {start}"
        );
    }
    let mut appended = encoded;
    appended.push(0);
    assert_eq!(
        ComponentArtifactV1::decode(&appended),
        Err(ComponentArtifactError::Length)
    );
}

#[test]
fn every_header_class_is_committed_and_mutations_are_rejected() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    let offsets = [
        0,
        8,
        10,
        FLAGS_OFFSET,
        OBJECT_KIND_OFFSET,
        HASH_ALGORITHM_OFFSET,
        PROFILE_CODE_OFFSET,
        PROFILE_STAGE_OFFSET,
        MANIFEST_VERSION_OFFSET,
        SIGNER_KIND_OFFSET,
        SIGNER_VERSION_OFFSET,
        ARTIFACT_ABI_OFFSET,
        COMPONENT_PROFILE_OFFSET,
        CORE_PROFILE_OFFSET,
        RUNTIME_ABI_OFFSET,
        CANONICAL_FEATURES_OFFSET,
        CONTRACT_LEN_OFFSET,
        MANIFEST_LEN_OFFSET,
        COMPONENT_LEN_OFFSET,
        TOTAL_LEN_OFFSET,
        WIT_COUNT_OFFSET,
        INTERFACE_COUNT_OFFSET,
        MODULE_COUNT_OFFSET,
        ADAPTER_COUNT_OFFSET,
        PROFILE_LIMIT_COUNT_OFFSET,
        INSTANCE_LIMIT_COUNT_OFFSET,
        REVISION_COUNT_OFFSET,
        HEADER_RESERVED0_OFFSET,
        COMPONENT_HASH_OFFSET,
        CONTRACT_HASH_OFFSET,
        MANIFEST_HASH_OFFSET,
        BODY_HASH_OFFSET,
        SIGNER_POLICY_DIGEST_OFFSET,
        ARTIFACT_COMMITMENT_OFFSET,
        HEADER_RESERVED1_OFFSET,
        COMPONENT_ARTIFACT_HEADER_LEN - 1,
    ];
    for offset in offsets {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert!(
            ComponentArtifactV1::decode(&mutated).is_err(),
            "accepted header mutation at {offset}"
        );
    }
    for offset in HEADER_RESERVED0_OFFSET..HEADER_RESERVED0_OFFSET + 2 {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert!(ComponentArtifactV1::decode(&mutated).is_err());
    }
    for offset in HEADER_RESERVED1_OFFSET..COMPONENT_ARTIFACT_HEADER_LEN {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert!(ComponentArtifactV1::decode(&mutated).is_err());
    }
}

#[test]
fn profile_header_fields_and_each_contract_revision_and_limit_are_exact() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    for offset in [
        PROFILE_CODE_OFFSET,
        PROFILE_STAGE_OFFSET,
        ARTIFACT_ABI_OFFSET,
        COMPONENT_PROFILE_OFFSET,
        CORE_PROFILE_OFFSET,
        RUNTIME_ABI_OFFSET,
        CANONICAL_FEATURES_OFFSET,
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 0x40;
        assert_eq!(
            ComponentArtifactV1::decode(&mutated),
            Err(ComponentArtifactError::Profile),
            "profile header offset {offset} was not checked before commitment"
        );
    }

    let (revisions, profile_limits, instance_limits) = contract_value_offsets(&encoded);
    assert_eq!(revisions.len(), 5);
    assert_eq!(profile_limits.len(), 44);
    assert_eq!(instance_limits.len(), 4);
    for (index, revision) in revisions.iter().enumerate() {
        let mut mutated = encoded.clone();
        mutated[revision.start] = if mutated[revision.start] == b'x' {
            b'y'
        } else {
            b'x'
        };
        repair_outer_checksums(&mut mutated);
        assert_eq!(
            ComponentArtifactV1::decode(&mutated),
            Err(ComponentArtifactError::Profile),
            "accepted revision field {index}"
        );
    }
    for (index, offset) in profile_limits.iter().copied().enumerate() {
        let mut mutated = encoded.clone();
        write_u64(&mut mutated, offset, read_u64(&encoded, offset) ^ 1);
        repair_outer_checksums(&mut mutated);
        assert_eq!(
            ComponentArtifactV1::decode(&mutated),
            Err(ComponentArtifactError::Limits),
            "accepted frozen profile limit {index}"
        );
    }
    for (index, offset) in instance_limits.iter().copied().enumerate() {
        let mut mutated = encoded.clone();
        write_u64(&mut mutated, offset, 0);
        repair_outer_checksums(&mut mutated);
        assert_eq!(
            ComponentArtifactV1::decode(&mutated),
            Err(ComponentArtifactError::Limits),
            "accepted invalid instance limit {index}"
        );
    }
}

#[test]
fn payload_and_each_outer_hash_layer_detect_mutation() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    let layout = envelope_layout(&encoded);

    let cases = [
        (
            COMPONENT_HASH_OFFSET,
            ComponentArtifactError::ComponentCommitment,
        ),
        (CONTRACT_HASH_OFFSET, ComponentArtifactError::ContractHash),
        (MANIFEST_HASH_OFFSET, ComponentArtifactError::ManifestHash),
        (BODY_HASH_OFFSET, ComponentArtifactError::BodyHash),
        (
            ARTIFACT_COMMITMENT_OFFSET,
            ComponentArtifactError::Commitment,
        ),
    ];
    for (offset, expected) in cases {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert_eq!(ComponentArtifactV1::decode(&mutated), Err(expected));
    }

    let mut component = encoded.clone();
    component[layout.component.start] ^= 1;
    assert_eq!(
        ComponentArtifactV1::decode(&component),
        Err(ComponentArtifactError::ComponentCommitment)
    );
    let mut contract = encoded.clone();
    contract[layout.contract.start] ^= 1;
    assert_eq!(
        ComponentArtifactV1::decode(&contract),
        Err(ComponentArtifactError::ContractHash)
    );
    let mut manifest = encoded;
    manifest[layout.manifest.start] ^= 1;
    assert_eq!(
        ComponentArtifactV1::decode(&manifest),
        Err(ComponentArtifactError::ManifestHash)
    );
}

#[test]
fn deep_wit_and_adapter_hashes_and_reserved_fields_are_revalidated() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    let positions = manifest_positions(&encoded);

    let mut wit_source = encoded.clone();
    wit_source[positions.wit[0].source.start] ^= 1;
    repair_outer_checksums(&mut wit_source);
    assert_eq!(
        ComponentArtifactV1::decode(&wit_source),
        Err(ComponentArtifactError::WitSourceCommitment)
    );
    let mut wit_digest = encoded.clone();
    wit_digest[positions.wit[0].digest] ^= 1;
    repair_outer_checksums(&mut wit_digest);
    assert_eq!(
        ComponentArtifactV1::decode(&wit_digest),
        Err(ComponentArtifactError::WitSourceCommitment)
    );
    let mut adapter_bytes = encoded.clone();
    adapter_bytes[positions.adapter[1].bytes.start] ^= 1;
    repair_outer_checksums(&mut adapter_bytes);
    assert_eq!(
        ComponentArtifactV1::decode(&adapter_bytes),
        Err(ComponentArtifactError::AdapterCommitment)
    );
    let mut adapter_digest = encoded.clone();
    adapter_digest[positions.adapter[1].digest] ^= 1;
    repair_outer_checksums(&mut adapter_digest);
    assert_eq!(
        ComponentArtifactV1::decode(&adapter_digest),
        Err(ComponentArtifactError::AdapterCommitment)
    );

    for offset in [
        positions.start + 12,
        positions.start + 18,
        positions.start + 36,
        positions.wit[0].reserved,
        positions.adapter[0].reserved0,
        positions.adapter[0].reserved1,
    ] {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        repair_outer_checksums(&mut mutated);
        assert_eq!(
            ComponentArtifactV1::decode(&mutated),
            Err(ComponentArtifactError::Reserved),
            "accepted manifest reserved field at {offset}"
        );
    }
}

#[test]
fn canonical_order_is_enforced_even_when_all_unkeyed_hashes_are_repaired() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    let positions = manifest_positions(&encoded);
    let first = positions.wit[0].whole.clone();
    let second = positions.wit[1].whole.clone();
    assert_eq!(first.end, second.start);
    let mut swapped_records = Vec::new();
    swapped_records.extend_from_slice(&encoded[second.clone()]);
    swapped_records.extend_from_slice(&encoded[first.clone()]);
    let mut mutated = encoded;
    mutated[first.start..second.end].copy_from_slice(&swapped_records);
    repair_outer_checksums(&mut mutated);
    assert_eq!(
        ComponentArtifactV1::decode(&mutated),
        Err(ComponentArtifactError::NonCanonical)
    );
}

#[test]
fn repaired_unkeyed_claim_is_still_inert_and_has_a_different_commitment() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    let original_commitment =
        encoded[ARTIFACT_COMMITMENT_OFFSET..ARTIFACT_COMMITMENT_OFFSET + 32].to_vec();
    let positions = manifest_positions(&encoded);
    let source = positions.wit[0].source.clone();
    let digest = positions.wit[0].digest;
    let mut mutated = encoded;
    let index = source.start + 8;
    mutated[index] = if mutated[index] == b'x' { b'y' } else { b'x' };
    let new_source_hash = role_hash(WIT_SOURCE_HASH_DOMAIN, &mutated[source]);
    mutated[digest..digest + 32].copy_from_slice(&new_source_hash);
    repair_outer_checksums(&mut mutated);

    let decoded = ComponentArtifactV1::decode(&mutated).unwrap();
    assert!(!decoded.runtime_ready());
    assert_ne!(
        &mutated[ARTIFACT_COMMITMENT_OFFSET..ARTIFACT_COMMITMENT_OFFSET + 32],
        original_commitment.as_slice()
    );
    assert_eq!(decoded.encode().unwrap(), mutated);
}

#[test]
fn hostile_outer_and_inner_lengths_and_counts_never_panic() {
    let encoded = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    for offset in [
        CONTRACT_LEN_OFFSET,
        MANIFEST_LEN_OFFSET,
        COMPONENT_LEN_OFFSET,
        TOTAL_LEN_OFFSET,
    ] {
        let mut mutated = encoded.clone();
        write_u64(&mut mutated, offset, u64::MAX);
        let result = std::panic::catch_unwind(|| ComponentArtifactV1::decode(&mutated));
        assert!(result.is_ok(), "panicked on hostile u64 at {offset}");
        assert!(result.unwrap().is_err());
    }
    for offset in [
        WIT_COUNT_OFFSET,
        INTERFACE_COUNT_OFFSET,
        MODULE_COUNT_OFFSET,
        ADAPTER_COUNT_OFFSET,
    ] {
        let mut mutated = encoded.clone();
        write_u32(&mut mutated, offset, u32::MAX);
        let result = std::panic::catch_unwind(|| ComponentArtifactV1::decode(&mutated));
        assert!(result.is_ok(), "panicked on hostile u32 at {offset}");
        assert!(result.unwrap().is_err());
    }

    let positions = manifest_positions(&encoded);
    let mut source_length = encoded.clone();
    write_u32(
        &mut source_length,
        positions.wit[0].whole.start + 4,
        u32::MAX,
    );
    repair_outer_checksums(&mut source_length);
    let result = std::panic::catch_unwind(|| ComponentArtifactV1::decode(&source_length));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());

    let mut adapter_length = encoded.clone();
    let adapter_length_offset = positions.adapter[0].reserved0 + 2;
    write_u32(&mut adapter_length, adapter_length_offset, u32::MAX);
    repair_outer_checksums(&mut adapter_length);
    let result = std::panic::catch_unwind(|| ComponentArtifactV1::decode(&adapter_length));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());

    let layout = envelope_layout(&encoded);
    let mut revision_length = encoded;
    write_u32(
        &mut revision_length,
        layout.contract.start + CONTRACT_HEADER_LEN,
        u32::MAX,
    );
    repair_outer_checksums(&mut revision_length);
    let result = std::panic::catch_unwind(|| ComponentArtifactV1::decode(&revision_length));
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
}

#[test]
fn deterministic_malformed_corpus_never_panics_or_accepts_noncanonical_bytes() {
    let canonical = artifact(ProfileIdentity::PROFILE_1_ASYNC).encode().unwrap();
    let mut state = 0x6f4f_2c19_d781_a53b_u64;
    for case in 0..1_024 {
        let mut candidate = canonical.clone();
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        match case % 4 {
            0 => {
                let length = usize::try_from(state).unwrap() % candidate.len();
                candidate.truncate(length);
            }
            1 => {
                candidate.push(state as u8);
            }
            _ => {
                for _ in 0..=case % 5 {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    let offset = usize::try_from(state).unwrap() % candidate.len();
                    candidate[offset] ^= ((state >> 32) as u8) | 1;
                }
            }
        }
        let result = std::panic::catch_unwind(|| ComponentArtifactV1::decode(&candidate));
        assert!(result.is_ok(), "decoder panicked for seeded case {case}");
        if let Ok(decoded) = result.unwrap() {
            assert_eq!(decoded.encode().unwrap(), candidate);
            assert!(!decoded.runtime_ready());
        }
    }
}

#[test]
fn debug_output_redacts_payloads_digests_and_policy_material() {
    let artifact = artifact(ProfileIdentity::PROFILE_1_ASYNC);
    let debug = format!("{artifact:?}");
    assert!(debug.contains("runtime_ready: false"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("secret-component-body-c71"));
    assert!(!debug.contains("package alpha:api"));
    assert!(!debug.contains("canonical-lower-descriptor"));
    assert!(!debug.contains("165, 165, 165"));

    let package_debug = format!("{:?}", package_a());
    assert!(package_debug.contains("source_bytes"));
    assert!(package_debug.contains("<redacted>"));
    assert!(!package_debug.contains("world alpha-world"));
    let adapter_debug = format!("{:?}", adapter_zero());
    assert!(adapter_debug.contains("<redacted>"));
    assert!(!adapter_debug.contains("canonical-lower-descriptor-zero"));
    assert_eq!(
        format!("{:?}", artifact.component_commitment()),
        "ComponentArtifactComponentCommitment(<redacted>)"
    );
}

#[test]
fn owned_artifact_graph_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ComponentArtifactV1>();
    assert_send_sync::<ComponentArtifactManifestV1>();
    assert_send_sync::<ComponentArtifactWitPackageV1>();
    assert_send_sync::<ComponentArtifactAdapterV1>();
    assert_send_sync::<ComponentArtifactCoreModuleV1>();
}
