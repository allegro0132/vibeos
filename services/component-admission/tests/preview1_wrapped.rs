#![cfg(feature = "preview1-wrapped-admission")]

use sha2::{Digest, Sha256};
use vibeos_component_admission::{
    admit_preview1_wrapped_candidate, AdmissionError, ComponentArtifact, Preview1CoreValueType,
    Preview1GuestFunctionImportPin, Preview1WrappedAdmissionPolicy, Preview1WrappedCoreModulePin,
    Preview1WrappedEntityDirection, Preview1WrappedEntityKind, Preview1WrappedTopLevelEntityPin,
};
use vibeos_component_format::{
    ComponentArtifactAdapterV1, ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind,
    ComponentArtifactInstanceLimitsV1, ComponentArtifactInterfaceDirection,
    ComponentArtifactInterfaceV1, ComponentArtifactManifestV1, ComponentArtifactSignerPolicyV1,
    ComponentArtifactV1, ComponentArtifactWitPackageV1, ProfileIdentity,
    PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN, PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256,
    PREVIEW1_WRAPPED_ADAPTER_REVISION,
};
use wasmparser::{Parser, Payload};

const COMPONENT: &[u8] =
    include_bytes!("../../../policy/image/artifacts/c81-fd-write.preview1-wrapped.component.wasm");
const GUEST: &[u8] = include_bytes!("../../../policy/image/artifacts/c81-fd-write.core.wasm");
const ADAPTER: &[u8] = include_bytes!(
    "../../../policy/image/artifacts/c81-wasmtime-v48.0.0-preview1-command-adapter.wasm"
);
const WIT: &str = include_str!("../../../policy/image/artifacts/c81-fd-write.component.wit");
const POLICY_BYTES: &[u8] =
    include_bytes!("../../../policy/image/artifacts/c81-preview1-wrapped-policy.json");

const POLICY_SHA256: &str = "577524109ce68e07fe33034cb4e6d8c8a5f016a93938f89598377b9d26b55646";
const ARTIFACT_COMMITMENT: &str =
    "c913a32e180e179fba8c52b20f50f47649d95838c5c9feeb3162ff58e7404f4c";
const LOWERING_SHA256: &str = "a5f5d1b1b1a09d92718132121d367acef0aed6364b58b1aac3e70daef62701f8";

const I32_X4: [Preview1CoreValueType; 4] = [Preview1CoreValueType::I32; 4];
const I32_X1: [Preview1CoreValueType; 1] = [Preview1CoreValueType::I32];

struct ReviewedPins {
    artifact_commitment: [u8; 32],
    external_policy_digest: [u8; 32],
    adapter_revision: &'static str,
    adapter_embedded_module_ordinal: u32,
    adapter_asset_byte_len: u32,
    adapter_asset_sha256: [u8; 32],
    guest_module_ordinal: u32,
    guest_module_byte_len: u32,
    guest_module_sha256: [u8; 32],
    modules: Vec<Preview1WrappedCoreModulePin>,
    guest_imports: [Preview1GuestFunctionImportPin<'static>; 1],
    entities: Vec<Preview1WrappedTopLevelEntityPin<'static>>,
    lowering_sha256: [u8; 32],
    lowering_count: u32,
    nested_components: u32,
}

impl ReviewedPins {
    fn reviewed() -> Self {
        Self {
            artifact_commitment: sha256(ARTIFACT_COMMITMENT),
            external_policy_digest: sha256(POLICY_SHA256),
            adapter_revision: PREVIEW1_WRAPPED_ADAPTER_REVISION,
            adapter_embedded_module_ordinal: 1,
            adapter_asset_byte_len: PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN as u32,
            adapter_asset_sha256: sha256(
                "316dfbf171591d69ae414efd13b85933ca13526af8d9e0a735ab88ae08fd85f0",
            ),
            guest_module_ordinal: 0,
            guest_module_byte_len: 145,
            guest_module_sha256: sha256(
                "5ac1eb14874721c8355669fd91811f9a0165d96f1382ff82f08f3dfc0634bb0c",
            ),
            modules: vec![
                module_pin(
                    145,
                    "5ac1eb14874721c8355669fd91811f9a0165d96f1382ff82f08f3dfc0634bb0c",
                ),
                module_pin(
                    9_581,
                    "96cbc60f3ef3ad13621236858694165e0b4dd02052ab38b875285e1aeafb4f66",
                ),
                module_pin(
                    318,
                    "1e30d212a60962a6eefee3b6ba9249332aa0a430b7e3bacca792bf86ef89ae0e",
                ),
                module_pin(
                    183,
                    "3c11674007ed6e8d74e99a1d2b52dc41cf1acd842f20ebd6e438593668d7d7ff",
                ),
            ],
            guest_imports: [Preview1GuestFunctionImportPin {
                module: "wasi_snapshot_preview1",
                name: "fd_write",
                params: &I32_X4,
                results: &I32_X1,
            }],
            entities: reviewed_entities(),
            lowering_sha256: sha256(LOWERING_SHA256),
            lowering_count: 13,
            nested_components: 1,
        }
    }

    fn policy(&self) -> Preview1WrappedAdmissionPolicy<'_> {
        Preview1WrappedAdmissionPolicy {
            artifact_commitment: self.artifact_commitment,
            external_policy_digest: self.external_policy_digest,
            adapter_revision: self.adapter_revision,
            adapter_embedded_module_ordinal: self.adapter_embedded_module_ordinal,
            adapter_asset_byte_len: self.adapter_asset_byte_len,
            adapter_asset_sha256: self.adapter_asset_sha256,
            guest_module_ordinal: self.guest_module_ordinal,
            guest_module_byte_len: self.guest_module_byte_len,
            guest_module_sha256: self.guest_module_sha256,
            embedded_modules: &self.modules,
            guest_function_imports: &self.guest_imports,
            top_level_entities: &self.entities,
            canonical_lowering_sha256: self.lowering_sha256,
            canonical_lowering_count: self.lowering_count,
            nested_component_count: self.nested_components,
        }
    }
}

fn module_pin(byte_len: u32, digest: &str) -> Preview1WrappedCoreModulePin {
    Preview1WrappedCoreModulePin {
        byte_len,
        sha256: sha256(digest),
    }
}

fn reviewed_entities() -> Vec<Preview1WrappedTopLevelEntityPin<'static>> {
    use Preview1WrappedEntityDirection::{Export, Import};
    use Preview1WrappedEntityKind::Instance;
    vec![
        entity(
            Import,
            Instance,
            "wasi:cli/stderr@0.2.12",
            "6fc47ffb74b1b905a5b8fe1c467ea8199eb091ffb0e9e2874f7ac986a4a91a32",
        ),
        entity(
            Import,
            Instance,
            "wasi:cli/stdin@0.2.12",
            "e5ff52618b9ebffbca4783de197eda34847f87c0a4351c0aea669cf7ba2db4a4",
        ),
        entity(
            Import,
            Instance,
            "wasi:cli/stdout@0.2.12",
            "9f231e2d8ad27a675d433c795b154f0246ca22f8d600bda2ddc60e76c8aa9d25",
        ),
        entity(
            Import,
            Instance,
            "wasi:clocks/wall-clock@0.2.12",
            "09d4e71704cfc40ffbd71d8481daab692c737df30fafc26d89e89a745f6116b7",
        ),
        entity(
            Import,
            Instance,
            "wasi:filesystem/preopens@0.2.12",
            "cb5037f354e73e9b1ae3380e90d00371bdd943c720aa7d0e5727e9591c507a90",
        ),
        entity(
            Import,
            Instance,
            "wasi:filesystem/types@0.2.12",
            "2fbf66c40479ed438de2ac00b156d8d88bbf38447c6b76449502be035d8849c5",
        ),
        entity(
            Import,
            Instance,
            "wasi:io/error@0.2.12",
            "40fed392ca0fd40a1feff77e63776a6bdc059a2cf26cd60366f3f77d2b7cc344",
        ),
        entity(
            Import,
            Instance,
            "wasi:io/streams@0.2.12",
            "9a16c9faac49b9dbf019eb4735259eb0d58ac3bc824867ab2aa374826ca95241",
        ),
        entity(
            Export,
            Instance,
            "wasi:cli/run@0.2.12",
            "c2429760150a601023aa7883ffaf212116e2a304829b6aab11aaadb84e510478",
        ),
    ]
}

fn entity(
    direction: Preview1WrappedEntityDirection,
    kind: Preview1WrappedEntityKind,
    name: &'static str,
    digest: &str,
) -> Preview1WrappedTopLevelEntityPin<'static> {
    Preview1WrappedTopLevelEntityPin {
        direction,
        kind,
        name,
        raw_entry_sha256: sha256(digest),
    }
}

fn sha256(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).unwrap();
    }
    result
}

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn raw_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn embedded_modules(component: &[u8]) -> Vec<&[u8]> {
    let mut modules = Vec::new();
    for payload in Parser::new(0).parse_all(component) {
        if let Payload::ModuleSection {
            unchecked_range, ..
        } = payload.unwrap()
        {
            modules.push(&component[unchecked_range]);
        }
    }
    modules
}

fn manifest(component: &[u8], adapter: &[u8]) -> ComponentArtifactManifestV1 {
    let modules = embedded_modules(component)
        .into_iter()
        .map(|module| ComponentArtifactCoreModuleV1::from_bytes(module).unwrap())
        .collect();
    let mut interfaces = Vec::new();
    for pin in reviewed_entities() {
        interfaces.push(
            ComponentArtifactInterfaceV1::new(
                match pin.direction {
                    Preview1WrappedEntityDirection::Import => {
                        ComponentArtifactInterfaceDirection::Import
                    }
                    Preview1WrappedEntityDirection::Export => {
                        ComponentArtifactInterfaceDirection::Export
                    }
                },
                ComponentArtifactEntityKind::Interface,
                pin.name,
                "instance(exact-wasi-0.2.12;host-mapping=none)",
            )
            .unwrap(),
        );
    }
    ComponentArtifactManifestV1::new(
        "root:component/root",
        vec![ComponentArtifactWitPackageV1::new("root:component", "0.0.0+c81", WIT).unwrap()],
        interfaces,
        modules,
        vec![
            ComponentArtifactAdapterV1::new(0, PREVIEW1_WRAPPED_ADAPTER_REVISION, adapter).unwrap(),
        ],
    )
    .unwrap()
}

fn artifact(
    component: &[u8],
    adapter: &[u8],
    profile: ProfileIdentity,
    operator_required: bool,
) -> ComponentArtifactV1 {
    let policy_digest = sha256(POLICY_SHA256);
    let signer = if operator_required {
        ComponentArtifactSignerPolicyV1::operator_required(policy_digest).unwrap()
    } else {
        ComponentArtifactSignerPolicyV1::development_image_pin(policy_digest).unwrap()
    };
    ComponentArtifactV1::new(
        component,
        profile,
        ComponentArtifactInstanceLimitsV1::new(1_048_576, 100_000, 100, 16).unwrap(),
        signer,
        manifest(component, adapter),
    )
    .unwrap()
}

fn reviewed_artifact() -> ComponentArtifactV1 {
    artifact(
        COMPONENT,
        ADAPTER,
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
        false,
    )
}

#[test]
fn reviewed_fixture_admits_as_inert_move_only_candidate_and_revalidates() {
    assert_eq!(COMPONENT.len(), 17_495);
    assert_eq!(
        raw_sha256(COMPONENT),
        sha256("b910b4428e9ff442649f36a59707373a34d73f50f11fc1ae1266cd9f19e9f48e")
    );
    assert_eq!(GUEST.len(), 145);
    assert_eq!(
        raw_sha256(GUEST),
        ReviewedPins::reviewed().guest_module_sha256
    );
    assert_eq!(ADAPTER.len(), PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN);
    assert_eq!(raw_sha256(ADAPTER), PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256);
    assert_eq!(raw_sha256(POLICY_BYTES), sha256(POLICY_SHA256));

    let artifact = reviewed_artifact();
    let observed_commitment = *artifact.artifact_commitment().unwrap().as_bytes();
    eprintln!("reviewed artifact commitment={}", hex(&observed_commitment));
    assert_eq!(observed_commitment, sha256(ARTIFACT_COMMITMENT));
    if let Ok(path) = std::env::var("C81_ARTIFACT_OUT") {
        std::fs::write(path, artifact.encode().unwrap()).unwrap();
    }

    let reviewed = ReviewedPins::reviewed();
    let candidate = admit_preview1_wrapped_candidate(artifact, &reviewed.policy()).unwrap();
    assert_eq!(
        candidate.profile(),
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED
    );
    assert!(!candidate.runtime_ready());
    assert_eq!(candidate.guest_calls(), 0);
    assert_eq!(candidate.diagnostics().embedded_module_count(), 4);
    assert_eq!(
        candidate.diagnostics().embedded_module_byte_len(0),
        Some(145)
    );
    assert_eq!(candidate.diagnostics().canonical_lowering_count(), 13);
    assert_eq!(candidate.diagnostics().nested_component_count(), 1);
    assert_eq!(candidate.diagnostics().top_level_entities().len(), 9);
    assert_eq!(candidate.diagnostics().guest_function_imports().len(), 1);
    candidate.revalidate().unwrap();
    candidate.revalidate().unwrap();

    let debug = format!("{candidate:?}");
    assert!(debug.contains("runtime_ready: false"));
    assert!(debug.contains("guest_calls: 0"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(ARTIFACT_COMMITMENT));
    assert!(!debug.contains(POLICY_SHA256));
    assert!(!debug.contains(LOWERING_SHA256));
}

#[test]
fn policy_pins_fail_closed_under_independent_mutations() {
    for mutation in 0..18 {
        let mut reviewed = ReviewedPins::reviewed();
        match mutation {
            0 => reviewed.artifact_commitment[0] ^= 1,
            1 => reviewed.external_policy_digest[0] ^= 1,
            2 => reviewed.adapter_revision = "wasmtime-v48.0.1/adjacent.wasm",
            3 => reviewed.adapter_asset_byte_len -= 1,
            4 => reviewed.adapter_asset_sha256[0] ^= 1,
            5 => reviewed.adapter_embedded_module_ordinal = 2,
            6 => reviewed.guest_module_byte_len -= 1,
            7 => reviewed.guest_module_sha256[0] ^= 1,
            8 => reviewed.modules[2].sha256[0] ^= 1,
            9 => reviewed.guest_imports[0].name = "path_open",
            10 => reviewed.entities[0].name = "wasi:cli/environment@0.2.12",
            11 => reviewed.entities[0].raw_entry_sha256[0] ^= 1,
            12 => reviewed.lowering_sha256[0] ^= 1,
            13 => reviewed.nested_components = 0,
            14 => reviewed.guest_imports[0].params = &I32_X1,
            15 => reviewed.guest_module_ordinal = 1,
            16 => reviewed.entities[0].kind = Preview1WrappedEntityKind::Function,
            17 => reviewed.modules.push(reviewed.modules[3]),
            _ => unreachable!(),
        }
        assert!(
            admit_preview1_wrapped_candidate(reviewed_artifact(), &reviewed.policy()).is_err(),
            "mutation {mutation} must fail closed"
        );
    }
}

#[test]
fn adjacent_envelopes_and_existing_admission_path_remain_closed() {
    let operator = artifact(
        COMPONENT,
        ADAPTER,
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
        true,
    );
    let mut reviewed = ReviewedPins::reviewed();
    reviewed.artifact_commitment = *operator.artifact_commitment().unwrap().as_bytes();
    assert!(matches!(
        admit_preview1_wrapped_candidate(operator, &reviewed.policy()),
        Err(AdmissionError::InvalidPolicy)
    ));

    let adjacent = artifact(COMPONENT, ADAPTER, ProfileIdentity::PROFILE_1_SYNC, false);
    let mut reviewed = ReviewedPins::reviewed();
    reviewed.artifact_commitment = *adjacent.artifact_commitment().unwrap().as_bytes();
    assert!(matches!(
        admit_preview1_wrapped_candidate(adjacent, &reviewed.policy()),
        Err(AdmissionError::InvalidPolicy)
    ));

    let raw_core = artifact(
        GUEST,
        ADAPTER,
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
        false,
    );
    let mut reviewed = ReviewedPins::reviewed();
    reviewed.artifact_commitment = *raw_core.artifact_commitment().unwrap().as_bytes();
    assert!(admit_preview1_wrapped_candidate(raw_core, &reviewed.policy()).is_err());

    let fake_adapter = b"not-the-pinned-preview1-adapter";
    let substituted = artifact(
        COMPONENT,
        fake_adapter,
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
        false,
    );
    let mut reviewed = ReviewedPins::reviewed();
    reviewed.artifact_commitment = *substituted.artifact_commitment().unwrap().as_bytes();
    assert!(admit_preview1_wrapped_candidate(substituted, &reviewed.policy()).is_err());

    let ordinary =
        ComponentArtifact::copy_from(COMPONENT, ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED)
            .unwrap();
    assert!(matches!(
        ordinary.inspect(),
        Err(AdmissionError::BadProfile)
    ));
}
