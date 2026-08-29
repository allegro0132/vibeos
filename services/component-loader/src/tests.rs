extern crate std;

use super::*;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::task::{Context, Poll, Waker};
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::sync::OnceLock;

use vibeos_component_admission::{
    AdmissionPolicy, ArtifactTrust, CommandStreamMode, ComponentArtifact, InstanceLimits,
    OperatorArtifactAdmissionPolicy, OperatorRoleIdentity, OperatorSignerStatus, OperatorSignerV1,
};
use vibeos_component_format::{
    ComponentArtifactAdapterV1, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactInterfaceDirection, ComponentArtifactInterfaceV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyV1, ComponentArtifactV1, ProfileIdentity,
    COMPONENT_ARTIFACT_OBJECT_KIND_RAW,
};
use vibeos_component_runtime::{decode::inspect_component, world::WorldContract};
use vibeos_core::cap::{CSpace, InvocationLease, Rights};
use vibeos_durable_format::{
    DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId, ObjectKind, RecoveredGrant,
    RecoveredObject, RecoveredSlot, RecoveredStore, ResourceKind, SlotIdentity, SpaceId, StoreId,
    TransactionId,
};
use vibeos_object_store::{
    BackendError, BackendFuture, BackendInfo, BackendMutationFuture, Platform, StoreError,
    StoreService,
};
use vibeos_storage_device::{DeviceId, DeviceSession, MutationFailure};
use vibeos_vsh::{ComponentCommandRunner, ComponentTerminal, Session};

const FILTER: &str =
    include_str!("../../component-command/tests/fixtures/byte-filter.component.wat");
const WORLD: &str = "vibe:bytes/filter@1.0.0";
const WIT: &str = r#"package vibe:bytes@1.0.0;

world filter {
    export run: func(input: list<u8>) -> list<u8>;
}
"#;
const ADJACENT_WIT: &str = r#"package vibe:bytes@1.0.0;
world filter { export run: func(input: list<u8>) -> list<u8>; }
"#;
const MALFORMED_WIT: &str = "package vibe:bytes@1.0.0; world filter {";
const RESOURCE_WIT: &str = r#"package vibe:bytes@1.0.0;

interface handles {
    resource handle;
}

world filter {
    use handles.{handle};
    export run: func(input: borrow<handle>) -> list<u8>;
}
"#;

const SIGNER_DIGEST: [u8; 32] = [0xa5; 32];
const ADJACENT_SIGNER_DIGEST: [u8; 32] = [0x5a; 32];
const MEMORY_BYTES: usize = 512 * 1024;
const TOTAL_FUEL: u64 = 100_000;
const POLL_QUANTUM: u64 = 100;
const RESOURCE_LIMIT: u16 = 4;
const OPERATOR_ROLE: [u8; 32] = [0x73; 32];
// C7.3-only deterministic acceptance key, distinct from every SSH fixture.
// This public test seed is absent from non-test builds.
const OPERATOR_TEST_SEED: [u8; 32] = [
    0x20, 0xc4, 0x84, 0xcd, 0x66, 0x0d, 0xbe, 0x4f, 0xdc, 0xac, 0x63, 0xf8, 0x12, 0x6a, 0x5b, 0x70,
    0xfb, 0xee, 0xc3, 0x8a, 0x6a, 0x37, 0xc9, 0xa8, 0xbe, 0x06, 0x70, 0x59, 0x20, 0x36, 0xbd, 0x75,
];

#[derive(Clone, Copy)]
enum SignerSpec {
    Development([u8; 32]),
    Operator([u8; 32]),
}

#[derive(Clone, Copy)]
enum WitSpec {
    Exact,
    Malformed,
    Resource,
    Multiple,
}

#[derive(Clone, Copy)]
enum InterfaceSpec {
    Exact,
    Missing,
    WrongKind,
    WrongShape,
}

#[derive(Clone, Copy)]
enum CoreSpec {
    Exact,
    WrongCommitment,
}

#[derive(Clone, Copy)]
struct ArtifactSpec {
    profile: ProfileIdentity,
    memory_bytes: u64,
    signer: SignerSpec,
    wit: WitSpec,
    interface: InterfaceSpec,
    core: CoreSpec,
    adapter: bool,
}

impl ArtifactSpec {
    const fn exact() -> Self {
        Self {
            profile: ProfileIdentity::PROFILE_1_SYNC,
            memory_bytes: MEMORY_BYTES as u64,
            signer: SignerSpec::Development(SIGNER_DIGEST),
            wit: WitSpec::Exact,
            interface: InterfaceSpec::Exact,
            core: CoreSpec::Exact,
            adapter: false,
        }
    }
}

fn component_bytes() -> Vec<u8> {
    wat::parse_str(FILTER).expect("the reviewed byte-filter fixture must remain valid")
}

fn admission_limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: MEMORY_BYTES,
        total_fuel: TOTAL_FUEL,
        poll_quantum: POLL_QUANTUM,
        resources: RESOURCE_LIMIT,
    }
}

fn artifact_bytes(spec: ArtifactSpec) -> Vec<u8> {
    let component = component_bytes();
    artifact_bytes_for_component(&component, spec)
}

fn artifact_bytes_for_component(component: &[u8], spec: ArtifactSpec) -> Vec<u8> {
    let wit_packages = match spec.wit {
        WitSpec::Exact => vec![vibeos_component_format::ComponentArtifactWitPackageV1::new(
            "vibe:bytes",
            "1.0.0",
            WIT,
        )
        .unwrap()],
        WitSpec::Malformed => vec![vibeos_component_format::ComponentArtifactWitPackageV1::new(
            "vibe:bytes",
            "1.0.0",
            MALFORMED_WIT,
        )
        .unwrap()],
        WitSpec::Resource => vec![vibeos_component_format::ComponentArtifactWitPackageV1::new(
            "vibe:bytes",
            "1.0.0",
            RESOURCE_WIT,
        )
        .unwrap()],
        WitSpec::Multiple => vec![
            vibeos_component_format::ComponentArtifactWitPackageV1::new("vibe:bytes", "1.0.0", WIT)
                .unwrap(),
            vibeos_component_format::ComponentArtifactWitPackageV1::new(
                "vibe:extra",
                "1.0.0",
                "package vibe:extra@1.0.0; world unused {}",
            )
            .unwrap(),
        ],
    };
    let interfaces = match spec.interface {
        InterfaceSpec::Exact => vec![ComponentArtifactInterfaceV1::new(
            ComponentArtifactInterfaceDirection::Export,
            ComponentArtifactEntityKind::Function,
            "run",
            "func(input:list<u8>)->list<u8>",
        )
        .unwrap()],
        InterfaceSpec::Missing => Vec::new(),
        InterfaceSpec::WrongKind => vec![ComponentArtifactInterfaceV1::new(
            ComponentArtifactInterfaceDirection::Export,
            ComponentArtifactEntityKind::Type,
            "run",
            "type",
        )
        .unwrap()],
        InterfaceSpec::WrongShape => vec![ComponentArtifactInterfaceV1::new(
            ComponentArtifactInterfaceDirection::Export,
            ComponentArtifactEntityKind::Function,
            "run",
            "func(input:list<u8>)->u32",
        )
        .unwrap()],
    };
    let core_modules = match spec.core {
        CoreSpec::Exact => inspect_component(component)
            .unwrap()
            .embedded_modules()
            .iter()
            .map(|module| ComponentArtifactCoreModuleV1::from_bytes(module).unwrap())
            .collect(),
        CoreSpec::WrongCommitment => {
            let adjacent = wat::parse_str("(module (func))").unwrap();
            vec![ComponentArtifactCoreModuleV1::from_bytes(&adjacent).unwrap()]
        }
    };
    let adapters = if spec.adapter {
        vec![ComponentArtifactAdapterV1::new(0, "test-adapter-v1", b"descriptor").unwrap()]
    } else {
        Vec::new()
    };
    let manifest =
        ComponentArtifactManifestV1::new(WORLD, wit_packages, interfaces, core_modules, adapters)
            .unwrap();
    let limits = ComponentArtifactInstanceLimitsV1::new(
        spec.memory_bytes,
        TOTAL_FUEL,
        POLL_QUANTUM,
        u64::from(RESOURCE_LIMIT),
    )
    .unwrap();
    let signer = match spec.signer {
        SignerSpec::Development(digest) => {
            ComponentArtifactSignerPolicyV1::development_image_pin(digest).unwrap()
        }
        SignerSpec::Operator(digest) => {
            ComponentArtifactSignerPolicyV1::operator_required(digest).unwrap()
        }
    };
    ComponentArtifactV1::new(component, spec.profile, limits, signer, manifest)
        .unwrap()
        .encode()
        .unwrap()
}

fn exact_world() -> WorldContract {
    WorldContract::parse(WIT, WORLD).expect("the WIT policy fixture must remain valid")
}

fn resource_world() -> WorldContract {
    WorldContract::parse(RESOURCE_WIT, WORLD).expect("the resource WIT fixture must remain valid")
}

fn admission_policy<'a>(
    component: &[u8],
    world: &'a WorldContract,
    limits: InstanceLimits,
    profile: ProfileIdentity,
) -> AdmissionPolicy<'a> {
    let identity = ComponentArtifact::copy_from(component, profile)
        .unwrap()
        .identity();
    AdmissionPolicy {
        command_name: "durable-filter",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: world,
        profile,
        trust: ArtifactTrust::ImagePinned(identity),
        limits,
        stdin: CommandStreamMode::Required,
        stdout: CommandStreamMode::Required,
        stderr: CommandStreamMode::Optional,
        interfaces: &[],
    }
}

fn operator_signer(status: OperatorSignerStatus) -> OperatorSignerV1 {
    let key = SigningKey::from_bytes(&OPERATOR_TEST_SEED)
        .verifying_key()
        .to_bytes();
    OperatorSignerV1::new(key, status)
        .expect("the C7.3-specific operator fixture is canonical and strong")
}

fn operator_policy<'a>(
    world: &'a WorldContract,
    signers: &'a [OperatorSignerV1],
    generation: u64,
) -> OperatorArtifactAdmissionPolicy<'a> {
    OperatorArtifactAdmissionPolicy::new(
        OperatorRoleIdentity::from_bytes(OPERATOR_ROLE).unwrap(),
        generation,
        ProfileIdentity::PROFILE_1_SYNC,
        "durable-filter",
        "run",
        0,
        0,
        WIT,
        world,
        admission_limits(),
        CommandStreamMode::Required,
        CommandStreamMode::Required,
        CommandStreamMode::Optional,
        &[],
        signers,
    )
    .expect("the operator test policy is exact and independently configured")
}

fn operator_artifact_bytes(
    component: &[u8],
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> Vec<u8> {
    let mut spec = ArtifactSpec::exact();
    spec.signer = SignerSpec::Operator(*policy.commitment().unwrap().as_bytes());
    artifact_bytes_for_component(component, spec)
}

fn operator_evidence(
    artifact_bytes: &[u8],
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> [u8; 112] {
    let signing_key = SigningKey::from_bytes(&OPERATOR_TEST_SEED);
    let artifact = ComponentArtifactV1::decode(artifact_bytes).unwrap();
    let transcript = policy
        .signature_transcript(&artifact, signing_key.verifying_key().to_bytes())
        .unwrap();
    let signature = signing_key.sign(&transcript).to_bytes();
    ComponentArtifactAuthenticationEvidenceV1::new(
        signing_key.verifying_key().to_bytes(),
        signature,
    )
    .unwrap()
    .encode()
}

fn stable<T>(value: u128, constructor: fn(u128) -> Option<T>) -> T {
    constructor(value).unwrap()
}

fn recovered_store(bytes: &[u8]) -> RecoveredStore {
    let space = stable(COMPONENT_ARTIFACT_SPACE_ID_RAW, SpaceId::new);
    let object_id = stable(0x7201, ObjectId::new);
    let derivation_id = stable(0x7202, DerivationId::new);
    let object = RecoveredObject {
        object_id,
        object_kind: ObjectKind::new(COMPONENT_ARTIFACT_OBJECT_KIND_RAW).unwrap(),
        bytes: bytes.to_vec(),
        byte_len: bytes.len() as u64,
        external_root: None,
        transaction_id: stable(0x7203, TransactionId::new),
        prepare_sequence: 1,
        commit_sequence: 2,
    };
    let grant = GrantRecord {
        derivation_id,
        parent_id: None,
        object_id,
        target: SlotIdentity {
            space,
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind: ResourceKind::new(0x5354_4f52).unwrap(),
        flags: GrantFlags::ROOT,
    };
    RecoveredStore {
        store_id: stable(0x7204, StoreId::new),
        id_high_water: 0x8000,
        grants: vec![RecoveredGrant {
            grant,
            transaction_id: stable(0x7205, TransactionId::new),
            prepare_sequence: 3,
            commit_sequence: 4,
        }],
        objects: vec![object],
        slots: vec![RecoveredSlot {
            space,
            slot: 0,
            max_generation: 0,
            live_derivation: Some(derivation_id),
        }],
        tombstones: Vec::new(),
        last_sequence: 4,
        last_crc32c: 0,
    }
}

fn artifact_read(bytes: &[u8]) -> ComponentArtifactPersistentRead {
    let recovered = recovered_store(bytes);
    let trusted = crate::root::authorize_recovered_for_test(&recovered)
        .unwrap()
        .expect("the exact fixed root must be present");
    let space = SpaceId::new(COMPONENT_ARTIFACT_SPACE_ID_RAW).unwrap();
    let mut cspace = CSpace::new_persistent("component-artifact-test", space);
    let incarnation = cspace.incarnation();
    trusted.install(&mut cspace, incarnation).unwrap()
}

struct OfflinePlatform;

impl Platform for OfflinePlatform {
    fn info(&self) -> Result<BackendInfo, BackendError> {
        Ok(BackendInfo {
            capacity_sectors: 1,
            read_only: true,
            supports_flush: false,
            session: DeviceSession::new(DeviceId::new(1).unwrap(), 1).unwrap(),
        })
    }

    fn read_sector(&self, _session: DeviceSession, _sector: u64) -> BackendFuture<'_, [u8; 512]> {
        Box::pin(async { Err(BackendError::Offline) })
    }

    fn write_sector_durable(
        &self,
        _session: DeviceSession,
        _sector: u64,
        _bytes: [u8; 512],
    ) -> BackendMutationFuture<'_, ()> {
        Box::pin(async { Err(MutationFailure::not_submitted(BackendError::ReadOnly)) })
    }

    fn has_working_headroom(&self, _required: usize) -> bool {
        false
    }
}

fn store_service() -> Arc<StoreService> {
    static STORE: OnceLock<Arc<StoreService>> = OnceLock::new();
    STORE
        .get_or_init(|| StoreService::new(Arc::new(OfflinePlatform)))
        .clone()
}

fn store_lease(rights: Rights) -> InvocationLease<StoreService> {
    let mut cspace = CSpace::new("component-loader-store-test");
    let cap = cspace.mint(store_service(), rights);
    cspace.lookup_lease(cap, Rights::NONE).unwrap()
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn load_from_bytes(
    stored: Vec<u8>,
    exact_image: &[u8],
    exact_wit_source: &str,
    signer_digest: [u8; 32],
    admission: &AdmissionPolicy<'_>,
    store_rights: Rights,
) -> Result<VolatileComponentCommand, ComponentLoadError> {
    let artifact_read = artifact_read(&stored);
    let policy = DevelopmentComponentLoadPolicy::new(
        exact_image,
        exact_wit_source,
        signer_digest,
        admission,
    );
    block_on(load_component_command_with(
        store_lease(store_rights),
        artifact_read,
        &policy,
        move |store, object| async move {
            assert!(store.authorizes(Rights::READ));
            assert!(object.authorizes(Rights::READ));
            Ok(stored)
        },
    ))
}

fn load_exact(
    encoded: Vec<u8>,
    exact_wit_source: &str,
    signer_digest: [u8; 32],
    admission: &AdmissionPolicy<'_>,
) -> Result<VolatileComponentCommand, ComponentLoadError> {
    let image = encoded.clone();
    load_from_bytes(
        encoded,
        &image,
        exact_wit_source,
        signer_digest,
        admission,
        Rights::READ,
    )
}

fn load_authenticated_exact(
    encoded: Vec<u8>,
    evidence: &[u8],
    operator: &OperatorArtifactAdmissionPolicy<'_>,
) -> Result<VolatileComponentCommand, ComponentLoadError> {
    let artifact_read = artifact_read(&encoded);
    let policy = DeployableComponentLoadPolicy::new(operator);
    block_on(load_authenticated_component_command_with(
        store_lease(Rights::READ),
        artifact_read,
        evidence,
        &policy,
        move |store, object| async move {
            assert!(store.authorizes(Rights::READ));
            assert!(object.authorizes(Rights::READ));
            Ok(encoded)
        },
    ))
}

#[test]
fn exact_read_root_loads_one_inert_boot_local_vsh_command() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let command = load_exact(
        artifact_bytes(ArtifactSpec::exact()),
        WIT,
        SIGNER_DIGEST,
        &admission,
    )
    .expect("the exact independent image and root policy must load");

    assert_eq!(command.manifest().name(), "durable-filter");
    assert_eq!(command.manifest().world(), WORLD);
    assert!(!command.runtime_ready());
    assert_eq!(command.guest_calls(), 0);
    assert_eq!(
        ComponentCommandRunner::preflight(&command, command.manifest()),
        Err(ComponentTerminal::Unavailable)
    );

    let command = Arc::new(command);
    let mut session = Session::new();
    session
        .install_component_command(command.clone())
        .expect("the fully revalidated runner is a real volatile VSH command");
    assert!(session
        .completion_candidates()
        .iter()
        .any(|candidate| candidate == "durable-filter"));
    assert!(!command.runtime_ready());
    assert_eq!(command.guest_calls(), 0);
}

#[test]
fn independent_boot_local_loads_repeat_every_gate_without_guest_activation() {
    let component = component_bytes();
    let encoded = artifact_bytes(ArtifactSpec::exact());
    for _boot in 0..2 {
        let world = exact_world();
        let admission = admission_policy(
            &component,
            &world,
            admission_limits(),
            ProfileIdentity::PROFILE_1_SYNC,
        );
        let command = load_exact(encoded.clone(), WIT, SIGNER_DIGEST, &admission).unwrap();
        assert!(!command.runtime_ready());
        assert_eq!(command.guest_calls(), 0);
        assert_eq!(
            ComponentCommandRunner::preflight(&command, command.manifest()),
            Err(ComponentTerminal::Unavailable)
        );
    }
}

#[test]
fn whole_image_and_independent_trust_pins_are_both_mandatory() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let exact = artifact_bytes(ArtifactSpec::exact());
    let mut adjacent_spec = ArtifactSpec::exact();
    adjacent_spec.signer = SignerSpec::Development(ADJACENT_SIGNER_DIGEST);
    let adjacent = artifact_bytes(adjacent_spec);
    assert_eq!(
        load_from_bytes(
            adjacent,
            &exact,
            WIT,
            SIGNER_DIGEST,
            &admission,
            Rights::READ,
        )
        .err(),
        Some(ComponentLoadError::ImagePinMismatch)
    );

    let foreign = wat::parse_str("(component)").unwrap();
    let foreign_identity = ComponentArtifact::copy_from(&foreign, ProfileIdentity::PROFILE_1_SYNC)
        .unwrap()
        .identity();
    let bad_admission = AdmissionPolicy {
        trust: ArtifactTrust::ImagePinned(foreign_identity),
        ..admission_policy(
            &component,
            &world,
            admission_limits(),
            ProfileIdentity::PROFILE_1_SYNC,
        )
    };
    assert_eq!(
        load_exact(exact, WIT, SIGNER_DIGEST, &bad_admission).err(),
        Some(ComponentLoadError::ImagePinMismatch)
    );
}

#[test]
fn signer_kind_and_digest_are_checked_against_independent_policy() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let exact = artifact_bytes(ArtifactSpec::exact());
    assert_eq!(
        load_exact(exact, WIT, ADJACENT_SIGNER_DIGEST, &admission).err(),
        Some(ComponentLoadError::SignerPolicy)
    );

    let mut operator_spec = ArtifactSpec::exact();
    operator_spec.signer = SignerSpec::Operator(SIGNER_DIGEST);
    assert_eq!(
        load_exact(
            artifact_bytes(operator_spec),
            WIT,
            SIGNER_DIGEST,
            &admission,
        )
        .err(),
        Some(ComponentLoadError::SignerPolicy)
    );
}

#[test]
fn profile_instance_limits_and_exact_wit_are_revalidated() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );

    let mut profile = ArtifactSpec::exact();
    profile.profile = ProfileIdentity::PROFILE_1_ASYNC;
    assert_eq!(
        load_exact(artifact_bytes(profile), WIT, SIGNER_DIGEST, &admission).err(),
        Some(ComponentLoadError::Profile)
    );

    // CMP1 intentionally preserves validation-only code 5 as inert artifact
    // metadata, but the durable production loader must reject it before a
    // publication candidate or command projection can be minted.
    let mut float_candidate = ArtifactSpec::exact();
    float_candidate.profile = ProfileIdentity::PROFILE_2_SYNC_FLOAT;
    assert_eq!(
        load_exact(
            artifact_bytes(float_candidate),
            WIT,
            SIGNER_DIGEST,
            &admission,
        )
        .err(),
        Some(ComponentLoadError::Profile)
    );

    // The executable code-6 identity is implemented only for the sealed,
    // volatile Float admission surface. S3 has not authorized durable
    // publication, so the production loader remains Profile-1-only.
    let mut float_executable = ArtifactSpec::exact();
    float_executable.profile = ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE;
    assert_eq!(
        load_exact(
            artifact_bytes(float_executable),
            WIT,
            SIGNER_DIGEST,
            &admission,
        )
        .err(),
        Some(ComponentLoadError::Profile)
    );

    let mut limits = ArtifactSpec::exact();
    limits.memory_bytes = 256 * 1024;
    assert_eq!(
        load_exact(artifact_bytes(limits), WIT, SIGNER_DIGEST, &admission).err(),
        Some(ComponentLoadError::Limits)
    );

    assert_eq!(
        load_exact(
            artifact_bytes(ArtifactSpec::exact()),
            ADJACENT_WIT,
            SIGNER_DIGEST,
            &admission,
        )
        .err(),
        Some(ComponentLoadError::WitPolicyMismatch)
    );
}

#[test]
fn malformed_or_ambiguous_wit_package_sets_fail_closed() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let mut malformed = ArtifactSpec::exact();
    malformed.wit = WitSpec::Malformed;
    assert!(matches!(
        load_exact(
            artifact_bytes(malformed),
            MALFORMED_WIT,
            SIGNER_DIGEST,
            &admission,
        ),
        Err(ComponentLoadError::Wit(_))
    ));

    let mut multiple = ArtifactSpec::exact();
    multiple.wit = WitSpec::Multiple;
    assert_eq!(
        load_exact(artifact_bytes(multiple), WIT, SIGNER_DIGEST, &admission).err(),
        Some(ComponentLoadError::UnsupportedWitPackageSet)
    );
}

#[test]
fn self_claimed_interface_core_and_adapter_evidence_cannot_authorize_loading() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );

    let mut missing_interface = ArtifactSpec::exact();
    missing_interface.interface = InterfaceSpec::Missing;
    assert_eq!(
        load_exact(
            artifact_bytes(missing_interface),
            WIT,
            SIGNER_DIGEST,
            &admission,
        )
        .err(),
        Some(ComponentLoadError::InterfaceManifest)
    );

    let mut wrong_kind = ArtifactSpec::exact();
    wrong_kind.interface = InterfaceSpec::WrongKind;
    assert_eq!(
        load_exact(artifact_bytes(wrong_kind), WIT, SIGNER_DIGEST, &admission,).err(),
        Some(ComponentLoadError::InterfaceManifest)
    );

    let mut wrong_shape = ArtifactSpec::exact();
    wrong_shape.interface = InterfaceSpec::WrongShape;
    assert_eq!(
        load_exact(artifact_bytes(wrong_shape), WIT, SIGNER_DIGEST, &admission,).err(),
        Some(ComponentLoadError::InterfaceManifest)
    );

    let mut wrong_core = ArtifactSpec::exact();
    wrong_core.core = CoreSpec::WrongCommitment;
    assert_eq!(
        load_exact(artifact_bytes(wrong_core), WIT, SIGNER_DIGEST, &admission,).err(),
        Some(ComponentLoadError::CoreManifest)
    );

    let mut adapter = ArtifactSpec::exact();
    adapter.adapter = true;
    assert_eq!(
        load_exact(artifact_bytes(adapter), WIT, SIGNER_DIGEST, &admission,).err(),
        Some(ComponentLoadError::UnsupportedAdapterEvidence)
    );
}

#[test]
fn nominal_resources_remain_outside_the_c72_loader_profile() {
    let component = component_bytes();
    let world = resource_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let mut resource = ArtifactSpec::exact();
    resource.wit = WitSpec::Resource;
    assert_eq!(
        load_exact(
            artifact_bytes(resource),
            RESOURCE_WIT,
            SIGNER_DIGEST,
            &admission,
        )
        .err(),
        Some(ComponentLoadError::UnsupportedResourceShape)
    );
}

#[test]
fn store_service_authority_must_be_exact_read() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let encoded = artifact_bytes(ArtifactSpec::exact());
    for rights in [
        Rights::NONE,
        Rights::READ.union(Rights::WRITE),
        Rights::READ.union(Rights::SEND),
        Rights::READ.union(Rights::RECV),
        Rights::READ.union(Rights::GRANT),
        Rights::READ.union(Rights::REVOKE),
        Rights::READ.union(Rights::INVOKE),
    ] {
        let image = encoded.clone();
        assert_eq!(
            load_from_bytes(
                encoded.clone(),
                &image,
                WIT,
                SIGNER_DIGEST,
                &admission,
                rights,
            )
            .err(),
            Some(ComponentLoadError::StoreAuthority),
            "store rights {rights:?} must not cross the exact-READ gate"
        );
    }
}

#[test]
fn rooted_length_and_capability_read_failures_do_not_fall_back() {
    let component = component_bytes();
    let world = exact_world();
    let admission = admission_policy(
        &component,
        &world,
        admission_limits(),
        ProfileIdentity::PROFILE_1_SYNC,
    );
    let encoded = artifact_bytes(ArtifactSpec::exact());
    let policy = DevelopmentComponentLoadPolicy::new(&encoded, WIT, SIGNER_DIGEST, &admission);

    let truncated = encoded[..encoded.len() - 1].to_vec();
    assert_eq!(
        block_on(load_component_command_with(
            store_lease(Rights::READ),
            artifact_read(&encoded),
            &policy,
            move |_, _| async move { Ok(truncated) },
        ))
        .err(),
        Some(ComponentLoadError::ReadLength)
    );

    assert_eq!(
        block_on(load_component_command_with(
            store_lease(Rights::READ),
            artifact_read(&encoded),
            &policy,
            |_, _| async { Err(StoreError::ObjectUnavailable) },
        ))
        .err(),
        Some(ComponentLoadError::Store(StoreError::ObjectUnavailable))
    );
}

#[test]
fn active_operator_policy_loads_two_distinct_signed_artifacts_without_an_image_pin() {
    let world = exact_world();
    let signers = [operator_signer(OperatorSignerStatus::Active)];
    let policy = operator_policy(&world, &signers, 1);
    let component_a = component_bytes();
    let component_b = wat::parse_str(FILTER.replace("i32.const 32", "i32.const 1"))
        .expect("the adjacent operator fixture must remain a valid Component");
    assert_ne!(component_a, component_b);

    for component in [&component_a, &component_b] {
        let encoded = operator_artifact_bytes(component, &policy);
        let evidence = operator_evidence(&encoded, &policy);
        let command = load_authenticated_exact(encoded, &evidence, &policy)
            .expect("one configured policy must authenticate distinct signed artifacts");
        assert_eq!(command.manifest().name(), "durable-filter");
        assert_eq!(command.manifest().world(), WORLD);
        assert!(!command.runtime_ready());
        assert_eq!(command.guest_calls(), 0);
        assert_eq!(
            ComponentCommandRunner::preflight(&command, command.manifest()),
            Err(ComponentTerminal::Unavailable)
        );
    }
}

#[test]
fn operator_authentication_has_no_development_or_content_hash_fallback() {
    let world = exact_world();
    let signers = [operator_signer(OperatorSignerStatus::Active)];
    let policy = operator_policy(&world, &signers, 1);
    let operator = operator_artifact_bytes(&component_bytes(), &policy);
    let valid_evidence = operator_evidence(&operator, &policy);

    let development = artifact_bytes(ArtifactSpec::exact());
    assert_eq!(
        load_authenticated_exact(development, &valid_evidence, &policy).err(),
        Some(ComponentLoadError::Authentication(
            ArtifactAuthenticationError::SignerPolicyKind
        ))
    );

    let mut hash_only = valid_evidence;
    let digest: [u8; 32] = sha2::Sha256::digest(&operator).into();
    hash_only[48..80].copy_from_slice(&digest);
    hash_only[80..112].copy_from_slice(&digest);
    assert_eq!(
        load_authenticated_exact(operator, &hash_only, &policy).err(),
        Some(ComponentLoadError::Authentication(
            ArtifactAuthenticationError::InvalidSignature
        ))
    );
}

#[test]
fn signatures_and_receipts_cannot_replay_across_artifacts_or_policy_rotation() {
    let world = exact_world();
    let signers = [operator_signer(OperatorSignerStatus::Active)];
    let policy_p1 = operator_policy(&world, &signers, 1);
    let artifact_a_p1 = operator_artifact_bytes(&component_bytes(), &policy_p1);
    let evidence_a_p1 = operator_evidence(&artifact_a_p1, &policy_p1);

    let component_b = wat::parse_str(FILTER.replace("i32.const 32", "i32.const 1")).unwrap();
    let artifact_b_p1 = operator_artifact_bytes(&component_b, &policy_p1);
    assert_eq!(
        load_authenticated_exact(artifact_b_p1, &evidence_a_p1, &policy_p1).err(),
        Some(ComponentLoadError::Authentication(
            ArtifactAuthenticationError::InvalidSignature
        ))
    );

    let policy_p2 = operator_policy(&world, &signers, 2);
    assert_ne!(
        policy_p1.commitment().unwrap(),
        policy_p2.commitment().unwrap()
    );
    assert_eq!(
        load_authenticated_exact(artifact_a_p1, &evidence_a_p1, &policy_p2).err(),
        Some(ComponentLoadError::Authentication(
            ArtifactAuthenticationError::PolicyDigestMismatch
        ))
    );

    let artifact_a_p2 = operator_artifact_bytes(&component_bytes(), &policy_p2);
    let evidence_a_p2 = operator_evidence(&artifact_a_p2, &policy_p2);
    assert!(load_authenticated_exact(artifact_a_p2, &evidence_a_p2, &policy_p2).is_ok());
}

#[test]
fn valid_operator_signature_cannot_bypass_fresh_manifest_validation() {
    let world = exact_world();
    let signers = [operator_signer(OperatorSignerStatus::Active)];
    let policy = operator_policy(&world, &signers, 1);
    let commitment = *policy.commitment().unwrap().as_bytes();

    for (mut spec, expected) in [
        {
            let mut spec = ArtifactSpec::exact();
            spec.interface = InterfaceSpec::WrongShape;
            (spec, ComponentLoadError::InterfaceManifest)
        },
        {
            let mut spec = ArtifactSpec::exact();
            spec.core = CoreSpec::WrongCommitment;
            (spec, ComponentLoadError::CoreManifest)
        },
        {
            let mut spec = ArtifactSpec::exact();
            spec.adapter = true;
            (spec, ComponentLoadError::UnsupportedAdapterEvidence)
        },
    ] {
        spec.signer = SignerSpec::Operator(commitment);
        let encoded = artifact_bytes(spec);
        let evidence = operator_evidence(&encoded, &policy);
        assert_eq!(
            load_authenticated_exact(encoded, &evidence, &policy).err(),
            Some(expected)
        );
    }
}

#[test]
fn authenticated_loader_rejects_noncanonical_evidence_and_over_righted_store_authority() {
    let world = exact_world();
    let signers = [operator_signer(OperatorSignerStatus::Active)];
    let operator = operator_policy(&world, &signers, 1);
    let encoded = operator_artifact_bytes(&component_bytes(), &operator);
    let evidence = operator_evidence(&encoded, &operator);
    let policy = DeployableComponentLoadPolicy::new(&operator);

    assert_eq!(
        load_authenticated_exact(encoded.clone(), &evidence[..111], &operator).err(),
        Some(ComponentLoadError::AuthenticationEvidence(
            ComponentArtifactAuthenticationError::EncodedLength { actual: 111 }
        ))
    );

    let artifact_read = artifact_read(&encoded);
    assert_eq!(
        block_on(load_authenticated_component_command_with(
            store_lease(Rights::READ.union(Rights::INVOKE)),
            artifact_read,
            &evidence,
            &policy,
            move |_, _| async move { Ok(encoded) },
        ))
        .err(),
        Some(ComponentLoadError::StoreAuthority)
    );
}
