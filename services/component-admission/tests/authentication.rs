use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vibeos_component_admission::{
    admit_authenticated, authenticate_component_artifact, ArtifactAuthenticationError,
    AuthenticatedAdmissionError, CallerAuthority, CommandStreamMode, InstanceLimits,
    InterfaceCeiling, OperatorArtifactAdmissionPolicy, OperatorRoleIdentity, OperatorSignerStatus,
    OperatorSignerV1, COMPONENT_ARTIFACT_OPERATOR_POLICY_VERSION,
    COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN,
};
use vibeos_component_format::{
    ComponentArtifactAdapterV1, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactInterfaceDirection, ComponentArtifactInterfaceV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyV1, ComponentArtifactV1, ComponentArtifactWitPackageV1,
    ProfileIdentity,
};
use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::{decode::inspect_component, world::WorldContract};
use vibeos_core::cap::Rights;

const COMPONENT_A: &str =
    include_str!("../../../policy/image/artifacts/c73-byte-filter-a.component.wat");
const COMPONENT_B: &str =
    include_str!("../../../policy/image/artifacts/c73-byte-filter-b.component.wat");
const WIT: &str = include_str!("../../../policy/image/artifacts/c73-byte-filter.wit");
const WORLD: &str = "vibe:bytes/filter@1.0.0";

const ACTIVE_SEED: [u8; 32] = [
    0x20, 0xc4, 0x84, 0xcd, 0x66, 0x0d, 0xbe, 0x4f, 0xdc, 0xac, 0x63, 0xf8, 0x12, 0x6a, 0x5b, 0x70,
    0xfb, 0xee, 0xc3, 0x8a, 0x6a, 0x37, 0xc9, 0xa8, 0xbe, 0x06, 0x70, 0x59, 0x20, 0x36, 0xbd, 0x75,
];
const REVOKED_SEED: [u8; 32] = [
    0xc2, 0x78, 0xfe, 0xe1, 0x2f, 0xde, 0x92, 0x94, 0xf6, 0x7d, 0x9e, 0x81, 0x8c, 0xb0, 0x48, 0x64,
    0xc4, 0xd5, 0x07, 0x9c, 0xf2, 0x7a, 0x27, 0xc7, 0x50, 0x16, 0x3d, 0x1d, 0xcb, 0xb5, 0x25, 0x27,
];
const UNKNOWN_SEED: [u8; 32] = [
    0x97, 0xd2, 0xa9, 0x5e, 0x41, 0x4d, 0x8b, 0x93, 0x74, 0xc4, 0x19, 0xd8, 0xce, 0x6b, 0x26, 0x99,
    0xb1, 0x32, 0xb4, 0xfb, 0xa9, 0xab, 0x0f, 0x89, 0x56, 0xfe, 0xef, 0x7f, 0x8e, 0xe7, 0x0d, 0x85,
];

const MEMORY_BYTES: usize = 512 * 1024;
const TOTAL_FUEL: u64 = 100_000;
const POLL_QUANTUM: u64 = 100;
const RESOURCES: u16 = 4;

#[derive(Clone, Copy)]
enum ManifestVariant {
    Exact,
    Interface,
    Core,
    Adapter,
}

struct Fixture {
    world: WorldContract,
    role: OperatorRoleIdentity,
    signers: [OperatorSignerV1; 2],
}

impl Fixture {
    fn new() -> Self {
        let world = WorldContract::parse(WIT, WORLD).unwrap();
        let role = OperatorRoleIdentity::from_bytes(
            Sha256::digest(b"vibeos.c73.test.operator-role.v1\0").into(),
        )
        .unwrap();
        let active = OperatorSignerV1::new(active_public(), OperatorSignerStatus::Active).unwrap();
        let revoked =
            OperatorSignerV1::new(revoked_public(), OperatorSignerStatus::Revoked).unwrap();
        let mut signers = [active, revoked];
        signers.sort_by_key(|signer| *signer.public_key());
        Self {
            world,
            role,
            signers,
        }
    }

    fn policy(&self, generation: u64) -> OperatorArtifactAdmissionPolicy<'_> {
        self.policy_with_source(generation, WIT)
    }

    fn policy_with_source<'a>(
        &'a self,
        generation: u64,
        source: &'a str,
    ) -> OperatorArtifactAdmissionPolicy<'a> {
        OperatorArtifactAdmissionPolicy::new(
            self.role,
            generation,
            ProfileIdentity::PROFILE_1_SYNC,
            "c73-filter",
            "run",
            0,
            0,
            source,
            &self.world,
            limits(),
            CommandStreamMode::Required,
            CommandStreamMode::Required,
            CommandStreamMode::Optional,
            &[],
            &self.signers,
        )
        .unwrap()
    }

    fn artifact(
        &self,
        policy: &OperatorArtifactAdmissionPolicy<'_>,
        component_source: &str,
        variant: ManifestVariant,
    ) -> ComponentArtifactV1 {
        let component = wat::parse_str(component_source).unwrap();
        artifact_with(
            &component,
            policy.profile(),
            limits(),
            ComponentArtifactSignerPolicyV1::operator_required(
                *policy.commitment().unwrap().as_bytes(),
            )
            .unwrap(),
            WIT,
            variant,
        )
    }
}

fn active_signer() -> SigningKey {
    SigningKey::from_bytes(&ACTIVE_SEED)
}

fn revoked_signer() -> SigningKey {
    SigningKey::from_bytes(&REVOKED_SEED)
}

fn unknown_signer() -> SigningKey {
    SigningKey::from_bytes(&UNKNOWN_SEED)
}

fn active_public() -> [u8; 32] {
    active_signer().verifying_key().to_bytes()
}

fn revoked_public() -> [u8; 32] {
    revoked_signer().verifying_key().to_bytes()
}

fn limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: MEMORY_BYTES,
        total_fuel: TOTAL_FUEL,
        poll_quantum: POLL_QUANTUM,
        resources: RESOURCES,
    }
}

fn format_limits(limits: InstanceLimits) -> ComponentArtifactInstanceLimitsV1 {
    ComponentArtifactInstanceLimitsV1::new(
        limits.memory_bytes as u64,
        limits.total_fuel,
        limits.poll_quantum,
        u64::from(limits.resources),
    )
    .unwrap()
}

fn artifact_with(
    component: &[u8],
    profile: ProfileIdentity,
    limits: InstanceLimits,
    signer_policy: ComponentArtifactSignerPolicyV1,
    wit: &str,
    variant: ManifestVariant,
) -> ComponentArtifactV1 {
    let diagnostic_shape = if matches!(variant, ManifestVariant::Interface) {
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
    .unwrap()];
    let core_modules = if matches!(variant, ManifestVariant::Core) {
        vec![
            ComponentArtifactCoreModuleV1::from_bytes(&wat::parse_str("(module (func))").unwrap())
                .unwrap(),
        ]
    } else {
        inspect_component(component)
            .unwrap()
            .embedded_modules()
            .iter()
            .map(|module| ComponentArtifactCoreModuleV1::from_bytes(module).unwrap())
            .collect()
    };
    let adapters = if matches!(variant, ManifestVariant::Adapter) {
        vec![ComponentArtifactAdapterV1::new(0, "c73-test-adapter-v1", b"descriptor").unwrap()]
    } else {
        Vec::new()
    };
    let manifest = ComponentArtifactManifestV1::new(
        WORLD,
        vec![ComponentArtifactWitPackageV1::new("vibe:bytes", "1.0.0", wit).unwrap()],
        interfaces,
        core_modules,
        adapters,
    )
    .unwrap();
    ComponentArtifactV1::new(
        component,
        profile,
        format_limits(limits),
        signer_policy,
        manifest,
    )
    .unwrap()
}

fn evidence(
    policy: &OperatorArtifactAdmissionPolicy<'_>,
    artifact: &ComponentArtifactV1,
    signing_key: &SigningKey,
) -> ComponentArtifactAuthenticationEvidenceV1 {
    let public_key = signing_key.verifying_key().to_bytes();
    let transcript = policy.signature_transcript(artifact, public_key).unwrap();
    evidence_for_transcript(signing_key, &transcript, public_key)
}

fn evidence_for_transcript(
    signing_key: &SigningKey,
    transcript: &[u8; COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN],
    declared_public_key: [u8; 32],
) -> ComponentArtifactAuthenticationEvidenceV1 {
    ComponentArtifactAuthenticationEvidenceV1::new(
        declared_public_key,
        signing_key.sign(transcript).to_bytes(),
    )
    .unwrap()
}

#[test]
fn canonical_policy_transcript_authentication_and_admission_are_exact_and_inert() {
    let fixture = Fixture::new();
    let policy = fixture.policy(1);
    assert_eq!(
        policy.commitment().unwrap().as_bytes(),
        &independent_policy_commitment(&fixture, 1)
    );
    let artifact = fixture.artifact(&policy, COMPONENT_A, ManifestVariant::Exact);
    let transcript = policy
        .signature_transcript(&artifact, active_public())
        .unwrap();
    assert_eq!(transcript.len(), 192);
    assert_eq!(
        &transcript[..48],
        b"vibeos.component-artifact.operator-admission.v1\0"
    );
    assert_eq!(&transcript[70..72], &[0, 0]);
    assert_eq!(&transcript[152..184], &active_public());
    assert_eq!(
        u64::from_le_bytes(transcript[184..192].try_into().unwrap()),
        1
    );

    let detached = evidence(&policy, &artifact, &active_signer());
    let authenticated = authenticate_component_artifact(artifact, &detached, &policy).unwrap();
    assert!(!authenticated.runtime_ready());
    assert!(!authenticated.receipt().runtime_ready());
    assert_eq!(authenticated.receipt().generation(), 1);
    assert_eq!(
        authenticated.receipt().profile(),
        ProfileIdentity::PROFILE_1_SYNC
    );
    assert_eq!(
        authenticated.receipt().policy_commitment(),
        policy.commitment().unwrap()
    );

    let debug = format!("{authenticated:?} {policy:?} {:?}", fixture.signers[1]);
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&hex(&active_public())));
    assert!(!debug.contains(WIT));

    let identity = authenticated.receipt().component_identity();
    let admitted =
        admit_authenticated(authenticated, &policy, &CallerAuthority { offers: &[] }).unwrap();
    assert_eq!(admitted.identity(), identity);
    assert_eq!(admitted.command_manifest().name(), "c73-filter");
    assert_eq!(admitted.command_manifest().world(), WORLD);
    assert!(admitted.grants().is_empty());
    assert!(admitted.validated_plan().is_ok());
}

#[test]
fn weak_noncanonical_and_noncanonical_policy_keys_fail_before_use() {
    let mut weak = [0_u8; 32];
    weak[0] = 1;
    assert_eq!(
        OperatorSignerV1::new(weak, OperatorSignerStatus::Active).err(),
        Some(ArtifactAuthenticationError::WeakPublicKey)
    );

    // Non-canonical encoding of the same identity point: y = p + 1. ZIP-215
    // decoding accepts it, while explicit Edwards recompression must reject it.
    let mut noncanonical = [0xff_u8; 32];
    noncanonical[0] = 0xee;
    noncanonical[31] = 0x7f;
    assert_eq!(
        OperatorSignerV1::new(noncanonical, OperatorSignerStatus::Active).err(),
        Some(ArtifactAuthenticationError::NonCanonicalPublicKey)
    );

    let fixture = Fixture::new();
    let reversed = [fixture.signers[1], fixture.signers[0]];
    assert_eq!(
        policy_with_signers(&fixture, &reversed).err(),
        Some(ArtifactAuthenticationError::NonCanonicalSignerTable)
    );
    let duplicate = [fixture.signers[0], fixture.signers[0]];
    assert_eq!(
        policy_with_signers(&fixture, &duplicate).err(),
        Some(ArtifactAuthenticationError::NonCanonicalSignerTable)
    );
    let revoked_only = [
        OperatorSignerV1::new(active_public(), OperatorSignerStatus::Revoked).unwrap(),
        OperatorSignerV1::new(revoked_public(), OperatorSignerStatus::Revoked).unwrap(),
    ];
    let mut revoked_only = revoked_only;
    revoked_only.sort_by_key(|signer| *signer.public_key());
    assert_eq!(
        policy_with_signers(&fixture, &revoked_only).err(),
        Some(ArtifactAuthenticationError::NoActiveSigner)
    );

    let unsorted_interfaces = [
        InterfaceCeiling {
            label: "z-policy",
            interface: "vibe:test/z@1.0.0",
            kind: HostResourceKind::Clock,
            rights: Rights::READ,
        },
        InterfaceCeiling {
            label: "a-policy",
            interface: "vibe:test/a@1.0.0",
            kind: HostResourceKind::Random,
            rights: Rights::READ,
        },
    ];
    assert_eq!(
        OperatorArtifactAdmissionPolicy::new(
            fixture.role,
            1,
            ProfileIdentity::PROFILE_1_SYNC,
            "c73-filter",
            "run",
            0,
            0,
            WIT,
            &fixture.world,
            limits(),
            CommandStreamMode::Required,
            CommandStreamMode::Required,
            CommandStreamMode::Optional,
            &unsorted_interfaces,
            &fixture.signers,
        )
        .err(),
        Some(ArtifactAuthenticationError::NonCanonicalInterfaces)
    );
}

#[test]
fn authenticated_policy_constructor_blocks_direct_resource_shape_admission() {
    const RESOURCE_WIT: &str = r#"
        package vibe:resource-policy@1.0.0;
        interface handles {
            resource handle;
            inspect: func(value: option<borrow<handle>>);
        }
        world command {
            import handles;
            export run: func();
        }
    "#;
    const RESOURCE_WORLD: &str = "vibe:resource-policy/command@1.0.0";

    let fixture = Fixture::new();
    let world = WorldContract::parse(RESOURCE_WIT, RESOURCE_WORLD).unwrap();
    assert_eq!(
        OperatorArtifactAdmissionPolicy::new(
            fixture.role,
            1,
            ProfileIdentity::PROFILE_1_SYNC,
            "resource-command",
            "run",
            0,
            0,
            RESOURCE_WIT,
            &world,
            limits(),
            CommandStreamMode::Required,
            CommandStreamMode::Required,
            CommandStreamMode::Optional,
            &[],
            &fixture.signers,
        )
        .err(),
        Some(ArtifactAuthenticationError::UnsupportedResourceShape)
    );
}

#[test]
fn wrong_unknown_and_revoked_signers_fail_closed_without_receipts() {
    let fixture = Fixture::new();
    let policy = fixture.policy(1);

    let artifact = fixture.artifact(&policy, COMPONENT_A, ManifestVariant::Exact);
    let active_transcript = policy
        .signature_transcript(&artifact, active_public())
        .unwrap();
    let wrong = evidence_for_transcript(&revoked_signer(), &active_transcript, active_public());
    assert_eq!(
        authenticate_component_artifact(artifact, &wrong, &policy).err(),
        Some(ArtifactAuthenticationError::InvalidSignature)
    );

    for (key, signer, expected) in [
        (
            unknown_signer().verifying_key().to_bytes(),
            unknown_signer(),
            ArtifactAuthenticationError::UnknownSigner,
        ),
        (
            revoked_public(),
            revoked_signer(),
            ArtifactAuthenticationError::RevokedSigner,
        ),
    ] {
        let artifact = fixture.artifact(&policy, COMPONENT_A, ManifestVariant::Exact);
        let mut transcript = policy
            .signature_transcript(&artifact, active_public())
            .unwrap();
        transcript[152..184].copy_from_slice(&key);
        let detached = evidence_for_transcript(&signer, &transcript, key);
        assert!(VerifyingKey::from_bytes(&key)
            .unwrap()
            .verify_strict(
                &transcript,
                &ed25519_dalek::Signature::from_bytes(detached.signature().as_bytes())
            )
            .is_ok());
        assert_eq!(
            authenticate_component_artifact(artifact, &detached, &policy).err(),
            Some(expected)
        );
    }
}

#[test]
fn signatures_cannot_replay_across_artifact_policy_generation_or_wit_rules() {
    let fixture = Fixture::new();
    let policy_p1 = fixture.policy(1);
    let artifact_a = fixture.artifact(&policy_p1, COMPONENT_A, ManifestVariant::Exact);
    let detached_a = evidence(&policy_p1, &artifact_a, &active_signer());

    let artifact_b = fixture.artifact(&policy_p1, COMPONENT_B, ManifestVariant::Exact);
    assert_eq!(
        authenticate_component_artifact(artifact_b, &detached_a, &policy_p1).err(),
        Some(ArtifactAuthenticationError::InvalidSignature)
    );

    let policy_p2 = fixture.policy(2);
    let receipt_artifact = fixture.artifact(&policy_p1, COMPONENT_A, ManifestVariant::Exact);
    let receipt_evidence = evidence(&policy_p1, &receipt_artifact, &active_signer());
    let authenticated =
        authenticate_component_artifact(receipt_artifact, &receipt_evidence, &policy_p1).unwrap();
    assert_eq!(
        admit_authenticated(authenticated, &policy_p2, &CallerAuthority { offers: &[] }).err(),
        Some(AuthenticatedAdmissionError::Authentication(
            ArtifactAuthenticationError::ReceiptMismatch
        ))
    );

    let artifact_p2 = fixture.artifact(&policy_p2, COMPONENT_A, ManifestVariant::Exact);
    assert_eq!(
        authenticate_component_artifact(artifact_p2, &detached_a, &policy_p1).err(),
        Some(ArtifactAuthenticationError::PolicyDigestMismatch)
    );
    let artifact_p1 = fixture.artifact(&policy_p1, COMPONENT_A, ManifestVariant::Exact);
    assert_eq!(
        authenticate_component_artifact(artifact_p1, &detached_a, &policy_p2).err(),
        Some(ArtifactAuthenticationError::PolicyDigestMismatch)
    );

    let wit_with_exact_extra_bytes = format!("{WIT}\n// independently reviewed whitespace\n");
    let adjacent_policy = fixture.policy_with_source(1, &wit_with_exact_extra_bytes);
    assert_ne!(
        adjacent_policy.commitment().unwrap(),
        policy_p1.commitment().unwrap()
    );
    let artifact = fixture.artifact(&policy_p1, COMPONENT_A, ManifestVariant::Exact);
    assert_eq!(
        authenticate_component_artifact(artifact, &detached_a, &adjacent_policy).err(),
        Some(ArtifactAuthenticationError::PolicyDigestMismatch)
    );
}

#[test]
fn strict_verification_rejects_signature_malleability_and_content_hash_substitution() {
    let fixture = Fixture::new();
    let policy = fixture.policy(1);
    let artifact = fixture.artifact(&policy, COMPONENT_A, ManifestVariant::Exact);
    let transcript = policy
        .signature_transcript(&artifact, active_public())
        .unwrap();
    let valid = active_signer().sign(&transcript).to_bytes();

    let mut noncanonical_scalar = valid;
    noncanonical_scalar[32..].fill(0xff);
    let malleable =
        ComponentArtifactAuthenticationEvidenceV1::new(active_public(), noncanonical_scalar)
            .unwrap();
    assert_eq!(
        authenticate_component_artifact(artifact, &malleable, &policy).err(),
        Some(ArtifactAuthenticationError::InvalidSignature)
    );

    let artifact = fixture.artifact(&policy, COMPONENT_A, ManifestVariant::Exact);
    let mut hash_only = [0_u8; 64];
    hash_only[..32].copy_from_slice(artifact.artifact_commitment().unwrap().as_bytes());
    hash_only[32..].copy_from_slice(artifact.component_commitment().as_bytes());
    let content_hash =
        ComponentArtifactAuthenticationEvidenceV1::new(active_public(), hash_only).unwrap();
    assert_eq!(
        authenticate_component_artifact(artifact, &content_hash, &policy).err(),
        Some(ArtifactAuthenticationError::InvalidSignature)
    );
}

#[test]
fn development_artifacts_never_fallback_to_the_authenticated_path() {
    let fixture = Fixture::new();
    let policy = fixture.policy(1);
    let operator = fixture.artifact(&policy, COMPONENT_A, ManifestVariant::Exact);
    let detached = evidence(&policy, &operator, &active_signer());
    let component = wat::parse_str(COMPONENT_A).unwrap();
    let development = artifact_with(
        &component,
        ProfileIdentity::PROFILE_1_SYNC,
        limits(),
        ComponentArtifactSignerPolicyV1::development_image_pin([0x5a; 32]).unwrap(),
        WIT,
        ManifestVariant::Exact,
    );
    assert_eq!(
        authenticate_component_artifact(development, &detached, &policy).err(),
        Some(ArtifactAuthenticationError::SignerPolicyKind)
    );
}

#[test]
fn fresh_signatures_do_not_bypass_fresh_manifest_admission() {
    let fixture = Fixture::new();
    let policy = fixture.policy(1);
    for variant in [
        ManifestVariant::Interface,
        ManifestVariant::Core,
        ManifestVariant::Adapter,
    ] {
        let artifact = fixture.artifact(&policy, COMPONENT_A, variant);
        let detached = evidence(&policy, &artifact, &active_signer());
        let authenticated = authenticate_component_artifact(artifact, &detached, &policy).unwrap();
        assert_eq!(
            admit_authenticated(authenticated, &policy, &CallerAuthority { offers: &[] }).err(),
            Some(AuthenticatedAdmissionError::Authentication(
                ArtifactAuthenticationError::ArtifactConfiguration
            ))
        );
    }
}

fn policy_with_signers<'a>(
    fixture: &'a Fixture,
    signers: &'a [OperatorSignerV1],
) -> Result<OperatorArtifactAdmissionPolicy<'a>, ArtifactAuthenticationError> {
    OperatorArtifactAdmissionPolicy::new(
        fixture.role,
        1,
        ProfileIdentity::PROFILE_1_SYNC,
        "c73-filter",
        "run",
        0,
        0,
        WIT,
        &fixture.world,
        limits(),
        CommandStreamMode::Required,
        CommandStreamMode::Required,
        CommandStreamMode::Optional,
        &[],
        signers,
    )
}

fn independent_policy_commitment(fixture: &Fixture, generation: u64) -> [u8; 32] {
    let profile = ProfileIdentity::PROFILE_1_SYNC;
    let mut stream = Vec::new();
    push_u16(&mut stream, COMPONENT_ARTIFACT_OPERATOR_POLICY_VERSION);
    push_u64(&mut stream, generation);
    stream.extend_from_slice(fixture.role.as_bytes());
    push_u16(&mut stream, fixture.signers.len() as u16);
    for signer in &fixture.signers {
        stream.extend_from_slice(signer.public_key());
        stream.push(signer.status() as u8);
    }
    stream.push(2);
    push_u16(&mut stream, profile.artifact_abi);
    push_u16(&mut stream, profile.component_profile);
    push_u16(&mut stream, profile.core_profile);
    push_u16(&mut stream, profile.runtime_abi);
    push_u64(&mut stream, profile.canonical_features);
    push_u16(&mut stream, profile.stage as u16);
    for revision in [
        profile.core_revision,
        profile.component_revision,
        profile.canonical_abi_revision,
        profile.wasm_tools_revision,
        profile.wasi_revision,
    ] {
        push_text(&mut stream, revision);
    }
    push_text(&mut stream, "c73-filter");
    push_text(&mut stream, "run");
    push_u64(&mut stream, 0);
    push_u64(&mut stream, 0);
    push_text(&mut stream, WORLD);
    push_u32(&mut stream, 0);
    push_u32(&mut stream, 1);
    push_text(&mut stream, "run");
    stream.push(0);
    stream.push(0);
    push_u32(&mut stream, 1);
    push_text(&mut stream, "input");
    stream.extend_from_slice(&[11, 1, 1, 11, 1]);
    push_u64(&mut stream, MEMORY_BYTES as u64);
    push_u64(&mut stream, TOTAL_FUEL);
    push_u64(&mut stream, POLL_QUANTUM);
    push_u16(&mut stream, RESOURCES);
    stream.extend_from_slice(&[1, 1, 2]);
    push_u16(&mut stream, 0);
    push_u64(&mut stream, WIT.len() as u64);
    stream.extend_from_slice(WIT.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"vibeos.component-artifact.operator-policy.v1\0");
    hasher.update(stream);
    hasher.finalize().into()
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
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

fn hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}
