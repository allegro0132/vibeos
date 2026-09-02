use sha2::{Digest, Sha256};
use vibeos_component_admission::{
    admit, AdmissionError, AdmissionPolicy, ArtifactTrust, CallerAuthority, CommandStreamMode,
    ComponentArtifact, ComponentIdentity, InstanceLimits,
};
use vibeos_component_command::{
    try_manifest_from_admitted, validate_admitted_stream_filter, RunnerBuildError,
};
use vibeos_component_runtime::{
    decode::inspect_component,
    host::{
        HostDispatch, HostDispatcher, HostError, HostOperationToken, HostPayloadAllocation,
        HostPrepared, HostRequest, HostResponse, HostWakeToken,
    },
    resource::{ResourceTable, ResourceTypeId},
    sync::{ProfileClock, SyncCallProfile, SynchronousComponent, TypedPoll},
    value::{CanonicalValue, ResourceOwnership, ValueType},
    world::{WorldContract, WorldError},
    HostImportInfo,
};
use vibeos_image_policy::{
    ComponentCommandPin, ComponentInstanceLimits, ComponentStreamMode, SSH_EXEC_COMPONENT,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const SOURCE: &str = include_str!("../artifacts/c53-stream-filter.component.wat");
const STREAM_INTERFACE: &str = "vibe:stream/streams@1.0.0";
const MAX_CHUNK: u32 = 1024;
// These product charges mirror the private RegistryStreamDispatcher constants
// in kernel/src/component_instances.rs. The C8.4 preflight selects them
// explicitly; existing LoopDispatcher tests retain their original synthetic
// 7/5/3 work model.
const PRODUCT_STREAM_READ_WORK: u64 = MAX_CHUNK as u64 + 4;
const PRODUCT_STREAM_WRITE_BASE_WORK: u64 = 4;
const PRODUCT_STREAM_CLOSE_WORK: u64 = 1;
const FROZEN_INPUT_LEN: usize = 12 * 1024 + 37;
const C84_ENGINEERING_INTERVAL_CAPACITY: u64 = 65_536;
const FROZEN_ARTIFACT_SHA256: &str =
    "180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72";
const FROZEN_INPUT_SHA256: &str =
    "6b6054d492e00e68a93bc9b657a69577c7c44f5a48f169adb4124df0a50f6b3c";
const FROZEN_OUTPUT_SHA256: &str =
    "791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27";

fn admission_mode(mode: ComponentStreamMode) -> CommandStreamMode {
    match mode {
        ComponentStreamMode::Required => CommandStreamMode::Required,
        ComponentStreamMode::Optional => CommandStreamMode::Optional,
        ComponentStreamMode::Closed => CommandStreamMode::Closed,
    }
}

fn admission_limits(limits: ComponentInstanceLimits) -> InstanceLimits {
    InstanceLimits {
        memory_bytes: limits.memory_bytes,
        total_fuel: limits.total_fuel,
        poll_quantum: limits.poll_quantum,
        resources: limits.resources,
    }
}

fn policy<'a>(
    pin: ComponentCommandPin,
    world: &'a WorldContract,
    identity: ComponentIdentity,
) -> AdmissionPolicy<'a> {
    AdmissionPolicy {
        command_name: pin.command_name(),
        entrypoint: pin.entrypoint(),
        min_args: pin.min_args(),
        max_args: pin.max_args(),
        exact_world: world,
        profile: pin.profile(),
        trust: ArtifactTrust::ImagePinned(identity),
        limits: admission_limits(pin.limits()),
        stdin: admission_mode(pin.stdin()),
        stdout: admission_mode(pin.stdout()),
        stderr: admission_mode(pin.stderr()),
        interfaces: &[],
    }
}

fn exact_world() -> WorldContract {
    WorldContract::parse(SSH_EXEC_COMPONENT.wit_source(), SSH_EXEC_COMPONENT.world()).unwrap()
}

fn admitted_source(source: &str) -> vibeos_component_admission::AdmittedComponent {
    let bytes = wat::parse_str(source).unwrap();
    let artifact = ComponentArtifact::copy_from(&bytes, SSH_EXEC_COMPONENT.profile()).unwrap();
    let identity = artifact.identity();
    let world = exact_world();
    admit(
        artifact,
        &policy(SSH_EXEC_COMPONENT, &world, identity),
        &CallerAuthority { offers: &[] },
    )
    .unwrap()
}

#[test]
fn pinned_stream_world_imports_signature_and_two_instance_topology_are_exact() {
    let artifact = ComponentArtifact::copy_from(
        SSH_EXEC_COMPONENT.artifact_bytes(),
        SSH_EXEC_COMPONENT.profile(),
    )
    .unwrap();
    let identity = artifact.identity();
    let world = exact_world();
    let admitted = admit(
        artifact,
        &policy(SSH_EXEC_COMPONENT, &world, identity),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();
    let manifest = try_manifest_from_admitted(&admitted).unwrap();
    validate_admitted_stream_filter(&admitted, &manifest).unwrap();

    let plan = admitted.validated_plan().unwrap();
    assert_eq!(plan.runtime_instance_count(), 2);
    let imports: Vec<_> = plan.host_imports().collect();
    assert_eq!(imports.len(), 4);
    assert!(imports
        .iter()
        .all(|import| import.interface == STREAM_INTERFACE));
    let functions: Vec<_> = imports
        .iter()
        .map(|import| import.function.as_str())
        .collect();
    assert_eq!(functions, ["read", "write", "close-reader", "close-writer"]);
    assert_eq!(plan.imports(), world.imports.as_slice());
    assert_eq!(plan.exports(), world.exports.as_slice());
    assert_eq!(manifest.min_args(), 0);
    assert_eq!(manifest.max_args(), 0);
    assert!(manifest.requirements().is_empty());
    assert!(admitted.grants().is_empty());
}

#[test]
fn wrong_hash_world_import_type_signature_mode_and_instance_count_fail_closed() {
    let pinned = ComponentArtifact::copy_from(
        SSH_EXEC_COMPONENT.artifact_bytes(),
        SSH_EXEC_COMPONENT.profile(),
    )
    .unwrap();
    let pinned_identity = pinned.identity();
    let mut corrupted = SSH_EXEC_COMPONENT.artifact_bytes().to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let corrupted = ComponentArtifact::copy_from(&corrupted, SSH_EXEC_COMPONENT.profile()).unwrap();
    let world = exact_world();
    assert_eq!(
        admit(
            corrupted,
            &policy(SSH_EXEC_COMPONENT, &world, pinned_identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::UntrustedArtifact)
    );

    let artifact = ComponentArtifact::copy_from(
        SSH_EXEC_COMPONENT.artifact_bytes(),
        SSH_EXEC_COMPONENT.profile(),
    )
    .unwrap();
    let identity = artifact.identity();
    let mut wrong_world = exact_world();
    wrong_world.identity = String::from("vibe:stream/adjacent@1.0.0");
    assert_eq!(
        admit(
            artifact,
            &policy(SSH_EXEC_COMPONENT, &wrong_world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let adjacent_import = SOURCE.replace("\"read\"", "\"read-adjacent\"");
    assert_ne!(adjacent_import, SOURCE);
    let bytes = wat::parse_str(&adjacent_import).unwrap();
    let artifact = ComponentArtifact::copy_from(&bytes, SSH_EXEC_COMPONENT.profile()).unwrap();
    let identity = artifact.identity();
    let world = exact_world();
    assert_eq!(
        admit(
            artifact,
            &policy(SSH_EXEC_COMPONENT, &world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::World(WorldError::TypeMismatch))
    );

    let adjacent_type = SOURCE.replacen("(result (list u8))))", "(result (list u16))))", 1);
    assert_ne!(adjacent_type, SOURCE);
    let bytes = wat::parse_str(&adjacent_type).unwrap();
    let artifact = ComponentArtifact::copy_from(&bytes, SSH_EXEC_COMPONENT.profile()).unwrap();
    let identity = artifact.identity();
    let world = exact_world();
    assert_eq!(
        admit(
            artifact,
            &policy(SSH_EXEC_COMPONENT, &world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::World(WorldError::TypeMismatch))
    );

    const RUN_PARAMETERS: &str = r#"      (param "input" $borrow-reader)
      (param "output" $borrow-writer)"#;
    let adjacent_signature = SOURCE.replacen(
        RUN_PARAMETERS,
        r#"      (param "source" $borrow-reader)
      (param "output" $borrow-writer)"#,
        1,
    );
    assert_ne!(adjacent_signature, SOURCE);
    let bytes = wat::parse_str(&adjacent_signature).unwrap();
    let artifact = ComponentArtifact::copy_from(&bytes, SSH_EXEC_COMPONENT.profile()).unwrap();
    let identity = artifact.identity();
    let world = exact_world();
    assert_eq!(
        admit(
            artifact,
            &policy(SSH_EXEC_COMPONENT, &world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::World(WorldError::TypeMismatch))
    );

    let artifact = ComponentArtifact::copy_from(
        SSH_EXEC_COMPONENT.artifact_bytes(),
        SSH_EXEC_COMPONENT.profile(),
    )
    .unwrap();
    let identity = artifact.identity();
    let world = exact_world();
    let mut wrong_mode = policy(SSH_EXEC_COMPONENT, &world, identity);
    wrong_mode.stdin = CommandStreamMode::Closed;
    assert_eq!(
        admit(artifact, &wrong_mode, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let extra_instance = SOURCE.replacen(
        "  (core instance $memory-instance (instantiate $memory-provider))",
        "  (core instance $unused-memory-instance (instantiate $memory-provider))\n  (core instance $memory-instance (instantiate $memory-provider))",
        1,
    );
    assert_ne!(extra_instance, SOURCE);
    let admitted = admitted_source(&extra_instance);
    assert_eq!(
        admitted.validated_plan().unwrap().runtime_instance_count(),
        3
    );
    let manifest = try_manifest_from_admitted(&admitted).unwrap();
    assert_eq!(
        validate_admitted_stream_filter(&admitted, &manifest),
        Err(RunnerBuildError::UnsupportedRuntimeInstances)
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endpoint {
    Reader,
    Writer,
}

#[derive(Clone, Copy)]
enum LoopWorkModel {
    Synthetic,
    FrozenProduct,
}

impl LoopWorkModel {
    const fn read(self) -> u64 {
        match self {
            Self::Synthetic => 7,
            Self::FrozenProduct => PRODUCT_STREAM_READ_WORK,
        }
    }

    fn write(self, bytes: usize) -> Result<u64, HostError> {
        match self {
            Self::Synthetic => Ok(5),
            Self::FrozenProduct => PRODUCT_STREAM_WRITE_BASE_WORK
                .checked_add(bytes as u64)
                .ok_or(HostError::Exhausted),
        }
    }

    const fn close(self) -> u64 {
        match self {
            Self::Synthetic => 3,
            Self::FrozenProduct => PRODUCT_STREAM_CLOSE_WORK,
        }
    }
}

struct LoopDispatcher {
    chunks: Vec<Vec<u8>>,
    next_read: usize,
    next_write: usize,
    next_generation: u64,
    active: Option<(HostOperationToken, usize)>,
    output: Vec<u8>,
    starts: usize,
    reads: usize,
    commits: usize,
    closes: usize,
    cancels: usize,
    work_model: LoopWorkModel,
}

impl LoopDispatcher {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self::with_work_model(chunks, LoopWorkModel::Synthetic)
    }

    fn frozen_product(chunks: Vec<Vec<u8>>) -> Self {
        Self::with_work_model(chunks, LoopWorkModel::FrozenProduct)
    }

    fn with_work_model(chunks: Vec<Vec<u8>>, work_model: LoopWorkModel) -> Self {
        Self {
            chunks,
            next_read: 0,
            next_write: 0,
            next_generation: 1,
            active: None,
            output: Vec::new(),
            starts: 0,
            reads: 0,
            commits: 0,
            closes: 0,
            cancels: 0,
            work_model,
        }
    }

    fn endpoint(request: &HostRequest<'_, Endpoint>, expected: Endpoint) -> Result<(), HostError> {
        let actual = request.with_borrow_argument(0, |endpoint| *endpoint)?;
        (actual == expected).then_some(()).ok_or(HostError::Denied)
    }

    fn bytes(value: &CanonicalValue) -> Result<Vec<u8>, HostError> {
        let CanonicalValue::List(values) = value else {
            return Err(HostError::InvalidArgument);
        };
        values
            .iter()
            .map(|value| match value {
                CanonicalValue::U8(byte) => Ok(*byte),
                _ => Err(HostError::InvalidArgument),
            })
            .collect()
    }
}

impl HostDispatcher<Endpoint> for LoopDispatcher {
    fn required_work(
        &self,
        import: &HostImportInfo,
        arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        match import.function.as_str() {
            "read" => match (self.work_model, arguments) {
                (LoopWorkModel::Synthetic, _) => Ok(self.work_model.read()),
                (LoopWorkModel::FrozenProduct, [CanonicalValue::Resource(_)]) => {
                    Ok(self.work_model.read())
                }
                (LoopWorkModel::FrozenProduct, _) => Err(HostError::InvalidArgument),
            },
            "write" => match (self.work_model, arguments) {
                (LoopWorkModel::Synthetic, _) => self.work_model.write(0),
                (
                    LoopWorkModel::FrozenProduct,
                    [CanonicalValue::Resource(_), CanonicalValue::List(bytes)],
                ) if !bytes.is_empty() && bytes.len() <= MAX_CHUNK as usize => {
                    self.work_model.write(bytes.len())
                }
                (LoopWorkModel::FrozenProduct, _) => Err(HostError::InvalidArgument),
            },
            "close-reader" | "close-writer" => Ok(self.work_model.close()),
            _ => Err(HostError::Denied),
        }
    }

    fn result_allocations(
        &self,
        import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<Vec<HostPayloadAllocation>, HostError> {
        Ok(if import.function == "read" {
            vec![HostPayloadAllocation {
                size: MAX_CHUNK,
                alignment: 1,
            }]
        } else {
            Vec::new()
        })
    }

    fn start(&mut self, request: HostRequest<'_, Endpoint>) -> Result<HostDispatch, HostError> {
        self.starts += 1;
        assert_eq!(request.import().interface, STREAM_INTERFACE);
        match request.import().function.as_str() {
            "read" => {
                Self::endpoint(&request, Endpoint::Reader)?;
                self.reads += 1;
                let Some(chunk) = self.chunks.get(self.next_read) else {
                    return Ok(HostDispatch::Ready(HostResponse::one(
                        CanonicalValue::List(Vec::new()),
                        self.work_model.read(),
                    )?));
                };
                let operation = HostOperationToken::from_generation(self.next_generation)
                    .ok_or(HostError::BackendFault)?;
                self.next_generation = self
                    .next_generation
                    .checked_add(1)
                    .ok_or(HostError::BackendFault)?;
                self.active = Some((operation, self.next_read));
                Ok(HostDispatch::Prepared(HostPrepared::new(
                    operation,
                    vec![HostPayloadAllocation {
                        size: u32::try_from(chunk.len()).map_err(|_| HostError::Exhausted)?,
                        alignment: 1,
                    }],
                )?))
            }
            "write" => {
                Self::endpoint(&request, Endpoint::Writer)?;
                let bytes = request
                    .arguments()
                    .get(1)
                    .ok_or(HostError::InvalidArgument)
                    .and_then(Self::bytes)?;
                let expected = self
                    .chunks
                    .get(self.next_write)
                    .ok_or(HostError::BackendFault)?;
                assert_eq!(
                    bytes,
                    expected.iter().map(|byte| byte ^ 0x20).collect::<Vec<_>>()
                );
                self.output.extend_from_slice(&bytes);
                self.next_write += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(
                    self.work_model.write(bytes.len())?,
                )?))
            }
            "close-reader" => {
                Self::endpoint(&request, Endpoint::Reader)?;
                assert_eq!(request.arguments().get(1), Some(&CanonicalValue::Enum(0)));
                self.closes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(
                    self.work_model.close(),
                )?))
            }
            "close-writer" => {
                Self::endpoint(&request, Endpoint::Writer)?;
                assert_eq!(request.arguments().get(1), Some(&CanonicalValue::Enum(0)));
                self.closes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(
                    self.work_model.close(),
                )?))
            }
            _ => Err(HostError::Denied),
        }
    }

    fn register_wake(
        &mut self,
        _operation: HostOperationToken,
        _wake: HostWakeToken,
    ) -> Result<(), HostError> {
        Err(HostError::InvalidArgument)
    }

    fn resume(
        &mut self,
        _operation: HostOperationToken,
        _request: HostRequest<'_, Endpoint>,
    ) -> Result<HostDispatch, HostError> {
        Err(HostError::InvalidArgument)
    }

    fn commit_prepared(
        &mut self,
        operation: HostOperationToken,
        request: HostRequest<'_, Endpoint>,
    ) -> Result<HostResponse, HostError> {
        Self::endpoint(&request, Endpoint::Reader)?;
        let Some((active, index)) = self.active else {
            return Err(HostError::InvalidArgument);
        };
        if active != operation || index != self.next_read {
            return Err(HostError::InvalidArgument);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.chunks[index].len())
            .map_err(|_| HostError::Exhausted)?;
        values.extend(self.chunks[index].iter().copied().map(CanonicalValue::U8));
        let response = HostResponse::reserve_one(self.work_model.read())?;

        // Everything which can allocate or fail precedes the simulated
        // destructive reservation commit.
        self.active = None;
        self.next_read += 1;
        self.commits += 1;
        response.commit(CanonicalValue::List(values))
    }

    fn cancel(&mut self, operation: HostOperationToken) -> Result<(), HostError> {
        if self.active.map(|(active, _)| active) != Some(operation) {
            return Err(HostError::InvalidArgument);
        }
        self.active = None;
        self.cancels += 1;
        Ok(())
    }
}

fn resource_types(component: &SynchronousComponent) -> (ResourceTypeId, ResourceTypeId) {
    let function = component
        .function_type(SSH_EXEC_COMPONENT.entrypoint())
        .unwrap();
    let resource = |index: usize| match function.parameters[index].value {
        ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        } => resource_type,
        ref other => panic!("unexpected stream resource type: {other:?}"),
    };
    let reader = resource(0);
    let writer = resource(1);
    assert_ne!(reader, writer, "reader and writer are nominally distinct");
    (reader, writer)
}

fn read_u32(component: &SynchronousComponent, offset: u32) -> u32 {
    let mut bytes = [0; 4];
    component
        .read_export_memory(SSH_EXEC_COMPONENT.entrypoint(), offset, &mut bytes)
        .unwrap();
    u32::from_le_bytes(bytes)
}

fn test_chunks(full_chunks: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::with_capacity(full_chunks + 1);
    for chunk_index in 0..full_chunks {
        chunks.push(
            (0..MAX_CHUNK as usize)
                .map(|offset| ((chunk_index * 17 + offset * 29) % 251) as u8)
                .collect(),
        );
    }
    chunks.push((0..37).map(|offset| (offset * 7 + 3) as u8).collect());
    chunks
}

fn frozen_case_filter_chunks() -> Vec<Vec<u8>> {
    let input: Vec<u8> = (0..FROZEN_INPUT_LEN)
        .map(|index| ((index * 17 + 3) % 251) as u8)
        .collect();
    input
        .chunks(MAX_CHUNK as usize)
        .map(<[u8]>::to_vec)
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Default)]
struct ProfileCounterClock(u64);

impl ProfileClock for ProfileCounterClock {
    fn ticks(&mut self) -> u64 {
        let tick = self.0;
        self.0 = self.0.wrapping_add(1);
        tick
    }
}

fn execute_chunks(chunks: Vec<Vec<u8>>, total_fuel: u64, poll_quantum: u64) {
    let plan = inspect_component(SSH_EXEC_COMPONENT.artifact_bytes()).unwrap();
    let mut component = SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap();
    let (reader_type, writer_type) = resource_types(&component);
    let mut resources = ResourceTable::new(0xc53, SSH_EXEC_COMPONENT.limits().resources).unwrap();
    let reader = resources
        .insert_owned(reader_type, Endpoint::Reader)
        .unwrap();
    let writer = resources
        .insert_owned(writer_type, Endpoint::Writer)
        .unwrap();
    let expected_output: Vec<u8> = chunks.iter().flatten().map(|byte| byte ^ 0x20).collect();
    let data_chunks = chunks.len();
    let short_chunks = chunks
        .iter()
        .filter(|chunk| chunk.len() < MAX_CHUNK as usize)
        .count();
    let mut dispatcher = LoopDispatcher::new(chunks);
    let mut call = component
        .start_typed_call_with_host(
            &mut resources,
            &mut dispatcher,
            SSH_EXEC_COMPONENT.entrypoint(),
            vec![
                CanonicalValue::Resource(reader),
                CanonicalValue::Resource(writer),
            ],
            total_fuel,
            poll_quantum,
        )
        .unwrap();
    let mut completed = false;
    for _ in 0..100_000 {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::Ready(value) => {
                assert_eq!(value, CanonicalValue::Tuple(Vec::new()));
                completed = true;
                break;
            }
            TypedPoll::HostPending(operation) => {
                panic!("immediate prepared dispatcher unexpectedly waited: {operation:?}")
            }
            TypedPoll::HostFailed(error) => panic!("stream host failed: {error:?}"),
            TypedPoll::Trapped(trap) => panic!("stream component trapped: {trap:?}"),
        }
    }
    assert!(completed, "stream component exceeded the bounded poll loop");
    drop(call);

    assert_eq!(dispatcher.output, expected_output);
    assert_eq!(dispatcher.next_read, data_chunks);
    assert_eq!(dispatcher.next_write, data_chunks);
    assert_eq!(dispatcher.reads, data_chunks + 1, "one final EOF read");
    assert_eq!(dispatcher.commits, data_chunks);
    assert_eq!(dispatcher.closes, 2);
    assert_eq!(dispatcher.cancels, 0);
    assert_eq!(read_u32(&component, 0), 4096, "allocation base is reusable");
    assert_eq!(
        read_u32(&component, 4),
        (data_chunks + 1) as u32,
        "every data read and the Ready EOF reserve one bounded max span"
    );
    assert_eq!(
        read_u32(&component, 8),
        short_chunks as u32,
        "only nonempty short chunks use max-to-exact shrink"
    );
    assert_eq!(
        read_u32(&component, 12),
        (data_chunks + 1) as u32,
        "guest frees every data chunk and runtime rolls back the EOF max span"
    );
    assert_eq!(read_u32(&component, 16), 0, "no allocator size mismatch");
    assert_eq!(read_u32(&component, 20), 0, "EOF leaves no live pointer");
    assert_eq!(read_u32(&component, 24), 0, "EOF leaves no live size");
    assert_eq!(read_u32(&component, 28), MAX_CHUNK);
    assert_eq!(read_u32(&component, 32), 0);
    assert_eq!(read_u32(&component, 36), 1);
    assert!(!component.is_poisoned());
}

#[test]
fn production_pin_streams_twelve_full_chunks_and_exact_final_37_bytes() {
    let limits = SSH_EXEC_COMPONENT.limits();
    execute_chunks(test_chunks(12), limits.total_fuel, limits.poll_quantum);
}

#[test]
fn frozen_case_filter_profile_preflight_proves_interval_capacity() {
    let pin = SSH_EXEC_COMPONENT;
    let limits = pin.limits();
    let chunks = frozen_case_filter_chunks();
    let input: Vec<u8> = chunks.iter().flatten().copied().collect();
    let expected_output: Vec<u8> = input.iter().map(|byte| byte ^ 0x20).collect();

    assert_eq!(pin.artifact_bytes().len(), 2012);
    assert_eq!(sha256_hex(pin.artifact_bytes()), FROZEN_ARTIFACT_SHA256);
    assert_eq!(input.len(), FROZEN_INPUT_LEN);
    assert_eq!(sha256_hex(&input), FROZEN_INPUT_SHA256);
    assert_eq!(expected_output.len(), FROZEN_INPUT_LEN);
    assert_eq!(sha256_hex(&expected_output), FROZEN_OUTPUT_SHA256);
    assert_eq!(chunks.len(), 13);
    assert_eq!(chunks.last().map(Vec::len), Some(37));

    let plan = inspect_component(pin.artifact_bytes()).unwrap();
    let mut component = SynchronousComponent::instantiate_with_memory_limit(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::new(limits.memory_bytes),
        limits.memory_bytes,
    )
    .unwrap();
    let (reader_type, writer_type) = resource_types(&component);
    let mut resources = ResourceTable::new(0xc84, limits.resources).unwrap();
    let reader = resources
        .insert_owned(reader_type, Endpoint::Reader)
        .unwrap();
    let writer = resources
        .insert_owned(writer_type, Endpoint::Writer)
        .unwrap();
    let mut dispatcher = LoopDispatcher::frozen_product(chunks);
    let mut call = component
        .start_typed_call_with_host(
            &mut resources,
            &mut dispatcher,
            pin.entrypoint(),
            vec![
                CanonicalValue::Resource(reader),
                CanonicalValue::Resource(writer),
            ],
            limits.total_fuel,
            limits.poll_quantum,
        )
        .unwrap();
    let planning_work = call.metrics().consumed_work;
    let mut clock = ProfileCounterClock::default();
    let mut profile = SyncCallProfile::default();
    let mut pending_polls = 0_u64;
    let mut completed = false;
    for _ in 0..100_000 {
        match call.poll_profiled(&mut clock, &mut profile) {
            TypedPoll::Pending(_) => pending_polls += 1,
            TypedPoll::Ready(value) => {
                assert_eq!(value, CanonicalValue::Tuple(Vec::new()));
                completed = true;
                break;
            }
            TypedPoll::HostPending(operation) => {
                panic!("frozen buffered dispatcher unexpectedly waited: {operation:?}")
            }
            TypedPoll::HostFailed(error) => panic!("frozen stream host failed: {error:?}"),
            TypedPoll::Trapped(trap) => panic!("frozen stream component trapped: {trap:?}"),
        }
    }
    assert!(completed, "frozen stream exceeded the bounded poll loop");
    let terminal_work = call.metrics().consumed_work;
    drop(call);

    assert_eq!(dispatcher.output, expected_output);
    assert_eq!(profile.typed_polls, 1251);
    assert_eq!(pending_polls, 1250);
    assert_eq!(profile.core_polls, 1165);
    assert_eq!(profile.consumed_work, 188_121);
    assert_eq!(planning_work, 2);
    assert_eq!(terminal_work, 188_123);
    assert_eq!(dispatcher.starts, 29);
    assert_eq!(dispatcher.commits, 13);
    let host_entries = dispatcher.starts + dispatcher.commits;
    assert_eq!(host_entries, 42);

    // Strict adjacent-same-phase merging leaves four fixed intervals
    // (validation, instantiation, initial ABI, cleanup), plus interpretation
    // then ABI for every Core poll and host then ABI for every dispatcher
    // entry. The managed runner additionally enters wait and resumes ABI after
    // every non-terminal quantum poll.
    let no_wait_intervals = 4_u64 + 2 * (profile.core_polls + host_entries as u64);
    let managed_minimum = no_wait_intervals + 2 * pending_polls;
    assert_eq!(no_wait_intervals, 2418);
    assert_eq!(managed_minimum, 4918);
    assert!(
        managed_minimum > 4096,
        "the retired schema cap was too small"
    );
    assert!(managed_minimum <= C84_ENGINEERING_INTERVAL_CAPACITY);
    assert_eq!(C84_ENGINEERING_INTERVAL_CAPACITY - managed_minimum, 60_618);
}

#[test]
fn reusable_allocator_survives_more_than_sixty_four_full_chunks() {
    // Use a larger invocation budget (still below Profile 1's frozen ceiling)
    // to isolate allocator lifetime from the production command's intentional
    // total-fuel bound. Sixty-five full reads would exhaust the old monotonic
    // bump allocator despite never having more than one live allocation.
    execute_chunks(test_chunks(65), 5_000_000, 1_000);
}
