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
    sync::{SynchronousComponent, TypedPoll},
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

struct LoopDispatcher {
    chunks: Vec<Vec<u8>>,
    next_read: usize,
    next_write: usize,
    next_generation: u64,
    active: Option<(HostOperationToken, usize)>,
    output: Vec<u8>,
    reads: usize,
    commits: usize,
    closes: usize,
    cancels: usize,
}

impl LoopDispatcher {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks,
            next_read: 0,
            next_write: 0,
            next_generation: 1,
            active: None,
            output: Vec::new(),
            reads: 0,
            commits: 0,
            closes: 0,
            cancels: 0,
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
        _arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        Ok(match import.function.as_str() {
            "read" => 7,
            "write" => 5,
            "close-reader" | "close-writer" => 3,
            _ => return Err(HostError::Denied),
        })
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
        assert_eq!(request.import().interface, STREAM_INTERFACE);
        match request.import().function.as_str() {
            "read" => {
                Self::endpoint(&request, Endpoint::Reader)?;
                self.reads += 1;
                let Some(chunk) = self.chunks.get(self.next_read) else {
                    return Ok(HostDispatch::Ready(HostResponse::one(
                        CanonicalValue::List(Vec::new()),
                        7,
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
                Ok(HostDispatch::Ready(HostResponse::unit(5)?))
            }
            "close-reader" => {
                Self::endpoint(&request, Endpoint::Reader)?;
                assert_eq!(request.arguments().get(1), Some(&CanonicalValue::Enum(0)));
                self.closes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(3)?))
            }
            "close-writer" => {
                Self::endpoint(&request, Endpoint::Writer)?;
                assert_eq!(request.arguments().get(1), Some(&CanonicalValue::Enum(0)));
                self.closes += 1;
                Ok(HostDispatch::Ready(HostResponse::unit(3)?))
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
        let response = HostResponse::reserve_one(7)?;

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
fn reusable_allocator_survives_more_than_sixty_four_full_chunks() {
    // Use a larger invocation budget (still below Profile 1's frozen ceiling)
    // to isolate allocator lifetime from the production command's intentional
    // total-fuel bound. Sixty-five full reads would exhaust the old monotonic
    // bump allocator despite never having more than one live allocation.
    execute_chunks(test_chunks(65), 5_000_000, 1_000);
}
