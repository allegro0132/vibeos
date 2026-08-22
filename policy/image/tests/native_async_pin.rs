#![cfg(feature = "c53-native-async-qemu-acceptance")]

use vibeos_component_admission::{
    admit, admit_native_async_acceptance_candidate, AdmissionError, AdmissionPolicy, ArtifactTrust,
    CallerAuthority, CommandStreamMode, ComponentArtifact, ComponentIdentity, InstanceLimits,
};
use vibeos_component_runtime::{
    native_async_acceptance::{
        Component as NativeAsyncComponent, HostRequest as NativeAsyncHostRequest,
        HostToken as NativeAsyncHostToken, Invocation as NativeAsyncInvocation,
        Poll as NativeAsyncPoll,
    },
    world::WorldContract,
};
use vibeos_image_policy::{
    ComponentInstanceLimits, ComponentStreamMode, NativeAsyncAcceptancePin,
    C53_NATIVE_ASYNC_QEMU_ACCEPTANCE,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

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
    pin: NativeAsyncAcceptancePin,
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

fn exact_world(pin: NativeAsyncAcceptancePin) -> WorldContract {
    WorldContract::parse(pin.wit_source(), pin.world()).unwrap()
}

#[test]
fn pinned_native_async_candidate_admits_only_through_the_isolated_path() {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    assert_eq!(pin.limits().resources, 8);
    assert_eq!(pin.limits().poll_quantum, 100);
    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    assert_eq!(identity.as_bytes(), &pin.expected_sha256());
    let world = exact_world(pin);
    let candidate = admit_native_async_acceptance_candidate(
        artifact,
        &policy(pin, &world, identity),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();

    assert_eq!(candidate.command_name(), "c53-native-filter");
    assert_eq!(candidate.world(), "vibe:stream/native-filter@1.0.0");
    assert_eq!(candidate.limits().resources, 8);
    let plan = candidate.validated_plan().unwrap();
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert_eq!(plan.embedded_modules().len(), 2);
    assert_eq!(plan.runtime_instance_count(), 2);
    assert_eq!(
        (
            plan.native_async_execution_plan()
                .unwrap()
                .canonical_plans()
                .len(),
            plan.native_async_execution_plan()
                .unwrap()
                .canonical_import_bridges()
                .len(),
            plan.native_async_execution_plan().unwrap().exports().len(),
        ),
        (15, 14, 1)
    );

    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    assert_eq!(
        admit(
            artifact,
            &policy(pin, &world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::BadProfile)
    );
}

fn runtime_component() -> NativeAsyncComponent {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    let world = exact_world(pin);
    let candidate = admit_native_async_acceptance_candidate(
        artifact,
        &policy(pin, &world, identity),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();
    let plan = candidate.validated_plan().unwrap();
    let component = NativeAsyncComponent::instantiate_validation_candidate_with_memory_limit(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
        candidate.limits().memory_bytes,
        u32::from(candidate.limits().resources),
    )
    .unwrap();
    assert_eq!(component.work_costs().handle_state, 65);
    assert_eq!(component.work_costs().buffer_bridge, 74);
    assert_eq!(component.work_costs().wait_state, 65);
    assert_eq!(component.storage_metrics().async_state.handles.limit, 8);
    assert_eq!(component.storage_metrics().async_state.pairs.limit, 8);
    assert_eq!(component.storage_metrics().buffers.limit, 8);
    component
}

#[derive(Debug)]
struct RuntimeAcceptance {
    output: Vec<u8>,
    output_close: u8,
    input_chunks: usize,
    output_chunks: usize,
    partial_output_chunks: usize,
    stable_host_pending_polls: usize,
    max_input_request: u32,
    max_output_request: u32,
}

fn prepared_host_token(
    progress: NativeAsyncPoll,
    expected: NativeAsyncHostRequest,
) -> NativeAsyncHostToken {
    match progress {
        NativeAsyncPoll::HostPending { token, request, .. } if request == expected => token,
        other => panic!("host prepare did not retain the exact request: {other:?}"),
    }
}

fn assert_bounded_invocation_api<T>(
    invocation: &mut NativeAsyncInvocation<'_>,
    poll_quantum: u64,
    operation: &'static str,
    invoke: impl FnOnce(&mut NativeAsyncInvocation<'_>) -> T,
) -> T {
    let before = invocation.metrics();
    let result = invoke(invocation);
    let after = invocation.metrics();
    let consumed = after
        .consumed_work
        .checked_sub(before.consumed_work)
        .unwrap_or_else(|| panic!("{operation} moved consumed work backward"));
    let remaining = before
        .remaining_work
        .checked_sub(after.remaining_work)
        .unwrap_or_else(|| panic!("{operation} increased remaining work"));
    assert_eq!(consumed, remaining, "{operation} split the work ledger");
    assert!(
        consumed <= poll_quantum,
        "{operation} spent {consumed} work in one public turn with quantum {poll_quantum}"
    );
    result
}

fn assert_stable_host_pending(
    invocation: &mut NativeAsyncInvocation<'_>,
    poll_quantum: u64,
    expected_token: NativeAsyncHostToken,
    expected_request: NativeAsyncHostRequest,
) {
    match assert_bounded_invocation_api(invocation, poll_quantum, "poll HostPending", |call| {
        call.poll()
    }) {
        NativeAsyncPoll::HostPending { token, request, .. } => {
            assert_eq!(token, expected_token);
            assert_eq!(request, expected_request);
        }
        other => panic!("delayed host operation changed without a driver action: {other:?}"),
    }
}

fn expected_stream_maximum(limits: ComponentInstanceLimits) -> u32 {
    assert_eq!(limits.resources, 8);
    assert_eq!(limits.poll_quantum, 100);
    let maximum = u32::try_from(limits.poll_quantum.checked_sub(1).unwrap()).unwrap();
    assert_eq!(maximum, 99);
    maximum
}

fn drive_runtime_filter(
    component: &mut NativeAsyncComponent,
    input: &[u8],
    close_reason: u8,
) -> RuntimeAcceptance {
    assert!(close_reason < 8);
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    let limits = pin.limits();
    let stream_maximum = expected_stream_maximum(limits);
    let mut invocation = component
        .start_filter(pin.entrypoint(), limits.total_fuel, limits.poll_quantum)
        .unwrap();
    let mut input_offset = 0_usize;
    let mut input_round = 0_usize;
    let mut output_round = 0_usize;
    let mut output = Vec::new();
    let mut observed_output_close = None;
    let mut input_chunks = 0_usize;
    let mut output_chunks = 0_usize;
    let mut partial_output_chunks = 0_usize;
    let mut stable_host_pending_polls = 0_usize;
    let mut max_input_request = 0_u32;
    let mut max_output_request = 0_u32;
    let mut transitions = 0_usize;

    loop {
        transitions += 1;
        assert!(
            transitions < 100_000,
            "native guest made no bounded progress"
        );
        let progress =
            assert_bounded_invocation_api(&mut invocation, limits.poll_quantum, "poll", |call| {
                call.poll()
            });
        match progress {
            // Core outcomes are deliberately deferred. Treat Pending as an
            // ordinary owner-visible turn and let the next loop poll handle it.
            NativeAsyncPoll::Pending(_) => {}
            NativeAsyncPoll::Resolved(_) | NativeAsyncPoll::Yielded(_) => {}
            NativeAsyncPoll::WaitPending { .. } => {
                panic!("guest parked without a corresponding host transition")
            }
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::InputStream { maximum },
                ..
            } => {
                assert!((1..=stream_maximum).contains(&maximum));
                max_input_request = max_input_request.max(maximum);
                assert_stable_host_pending(
                    &mut invocation,
                    limits.poll_quantum,
                    token,
                    NativeAsyncHostRequest::InputStream { maximum },
                );
                stable_host_pending_polls += 1;
                if input_offset == input.len() {
                    assert!(matches!(
                        assert_bounded_invocation_api(
                            &mut invocation,
                            limits.poll_quantum,
                            "drop_host_copy_peer",
                            |call| call.drop_host_copy_peer(token),
                        )
                        .unwrap(),
                        NativeAsyncPoll::Pending(_)
                    ));
                    continue;
                }
                let desired = [1024_usize, 257, 17, 701, 509][input_round % 5];
                input_round += 1;
                let progress = desired
                    .min(maximum as usize)
                    .min(input.len() - input_offset);
                assert!((1..=stream_maximum as usize).contains(&progress));
                let prepared = assert_bounded_invocation_api(
                    &mut invocation,
                    limits.poll_quantum,
                    "prepare_host_input_stream",
                    |call| call.prepare_host_input_stream(token, progress as u32),
                )
                .unwrap();
                let token =
                    prepared_host_token(prepared, NativeAsyncHostRequest::InputStream { maximum });
                let end = input_offset + progress;
                assert!(matches!(
                    assert_bounded_invocation_api(
                        &mut invocation,
                        limits.poll_quantum,
                        "commit_host_input_stream",
                        |call| call.commit_host_input_stream(token, &input[input_offset..end]),
                    )
                    .unwrap(),
                    NativeAsyncPoll::Pending(_)
                ));
                input_offset = end;
                input_chunks += 1;
            }
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::InputClosed,
                ..
            } => {
                assert_eq!(input_offset, input.len());
                let prepared = assert_bounded_invocation_api(
                    &mut invocation,
                    limits.poll_quantum,
                    "prepare_host_input_closed",
                    |call| call.prepare_host_input_closed(token),
                )
                .unwrap();
                let token = prepared_host_token(prepared, NativeAsyncHostRequest::InputClosed);
                assert!(matches!(
                    assert_bounded_invocation_api(
                        &mut invocation,
                        limits.poll_quantum,
                        "commit_host_input_closed",
                        |call| call.commit_host_input_closed(token, close_reason),
                    )
                    .unwrap(),
                    NativeAsyncPoll::Pending(_)
                ));
            }
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::OutputStream { maximum },
                ..
            } => {
                assert!((1..=stream_maximum).contains(&maximum));
                max_output_request = max_output_request.max(maximum);
                assert_stable_host_pending(
                    &mut invocation,
                    limits.poll_quantum,
                    token,
                    NativeAsyncHostRequest::OutputStream { maximum },
                );
                stable_host_pending_polls += 1;
                let desired = [1_usize, 31, 257, 509][output_round % 4];
                output_round += 1;
                let progress = desired.min(maximum as usize);
                if progress < maximum as usize {
                    partial_output_chunks += 1;
                }
                let start = output.len();
                output.resize(start + progress, 0);
                let prepared = assert_bounded_invocation_api(
                    &mut invocation,
                    limits.poll_quantum,
                    "prepare_host_output_stream",
                    |call| call.prepare_host_output_stream(token, &mut output[start..]),
                )
                .unwrap();
                let token =
                    prepared_host_token(prepared, NativeAsyncHostRequest::OutputStream { maximum });
                assert_stable_host_pending(
                    &mut invocation,
                    limits.poll_quantum,
                    token,
                    NativeAsyncHostRequest::OutputStream { maximum },
                );
                stable_host_pending_polls += 1;
                assert!(matches!(
                    assert_bounded_invocation_api(
                        &mut invocation,
                        limits.poll_quantum,
                        "commit_host_output stream",
                        |call| call.commit_host_output(token),
                    )
                    .unwrap(),
                    NativeAsyncPoll::Pending(_)
                ));
                output_chunks += 1;
            }
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::OutputClosed { value: None },
                ..
            } => {
                let prepared = assert_bounded_invocation_api(
                    &mut invocation,
                    limits.poll_quantum,
                    "prepare_host_output_closed",
                    |call| call.prepare_host_output_closed(token),
                )
                .unwrap();
                let prepared_request = NativeAsyncHostRequest::OutputClosed {
                    value: Some(close_reason),
                };
                let token = prepared_host_token(prepared, prepared_request);
                assert_stable_host_pending(
                    &mut invocation,
                    limits.poll_quantum,
                    token,
                    prepared_request,
                );
                stable_host_pending_polls += 1;
                observed_output_close = Some(close_reason);
                assert!(matches!(
                    assert_bounded_invocation_api(
                        &mut invocation,
                        limits.poll_quantum,
                        "commit_host_output closed",
                        |call| call.commit_host_output(token),
                    )
                    .unwrap(),
                    NativeAsyncPoll::Pending(_)
                ));
            }
            NativeAsyncPoll::HostPending { request, .. } => {
                panic!("unexpected prepared request surfaced to driver: {request:?}")
            }
            NativeAsyncPoll::Complete(_) => {
                assert_bounded_invocation_api(
                    &mut invocation,
                    limits.poll_quantum,
                    "finalize_transport",
                    |call| call.finalize_transport(),
                )
                .unwrap();
                break;
            }
            NativeAsyncPoll::CleanupPending { trap, .. } => {
                panic!("native artifact entered fail-stop cleanup: {trap:?}")
            }
            NativeAsyncPoll::Trapped(trap) => panic!("native artifact trapped: {trap:?}"),
        }
    }

    assert_eq!(input_offset, input.len());
    assert_eq!(observed_output_close, Some(close_reason));
    RuntimeAcceptance {
        output,
        output_close: observed_output_close.unwrap(),
        input_chunks,
        output_chunks,
        partial_output_chunks,
        stable_host_pending_polls,
        max_input_request,
        max_output_request,
    }
}

fn xor_0x20(input: &[u8]) -> Vec<u8> {
    input.iter().map(|byte| byte ^ 0x20).collect()
}

#[test]
fn pinned_artifact_executes_large_backpressured_xor_and_reuses_one_component() {
    let stream_maximum = expected_stream_maximum(C53_NATIVE_ASYNC_QEMU_ACCEPTANCE.limits());
    let mut component = runtime_component();
    let input: Vec<u8> = (0..(8 * 1024 + 333))
        .map(|index| ((index * 37 + 11) & 0xff) as u8)
        .collect();
    let first = drive_runtime_filter(&mut component, &input, 0);
    assert_eq!(first.output, xor_0x20(&input));
    assert_eq!(first.output_close, 0);
    assert_eq!(first.output.len(), input.len());
    assert!(first.input_chunks > input.len().div_ceil(stream_maximum as usize));
    assert!(first.output_chunks > first.input_chunks);
    assert!(first.partial_output_chunks > 8);
    assert!(first.stable_host_pending_polls > first.output_chunks);
    assert_eq!(first.max_input_request, stream_maximum);
    assert_eq!(first.max_output_request, stream_maximum);

    let second_input = b"second invocation crosses the same sealed runtime";
    let second = drive_runtime_filter(&mut component, second_input, 1);
    assert_eq!(second.output, xor_0x20(second_input));
    assert_eq!(second.output_close, 1);

    let storage = component.storage_metrics();
    assert_eq!(storage.async_state.handles.current, 0);
    assert_eq!(storage.async_state.pairs.current, 0);
    assert_eq!(storage.async_state.tasks.current, 0);
    assert_eq!(storage.async_state.joined_waitables.current, 0);
    assert_eq!(storage.async_state.wait_registrations.current, 0);
    assert_eq!(storage.buffers.current, 0);
    assert_eq!(storage.async_state.handles.peak, 7);
    assert_eq!(storage.async_state.pairs.peak, 4);
    assert_eq!(storage.async_state.tasks.peak, 1);
    assert_eq!(storage.async_state.joined_waitables.peak, 4);
    assert_eq!(storage.async_state.wait_registrations.peak, 0);
    assert_eq!(storage.buffers.peak, 1);
}

#[test]
fn pinned_artifact_propagates_all_eight_close_reasons_exactly() {
    let mut component = runtime_component();
    for reason in 0_u8..8 {
        let input = [reason, 0x00, 0x20, 0x7f, 0x80, 0xff];
        let result = drive_runtime_filter(&mut component, &input, reason);
        assert_eq!(result.output, xor_0x20(&input));
        assert_eq!(result.output_close, reason);
    }
}

#[test]
fn pinned_native_async_hash_and_independent_wit_fail_closed() {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    let pinned = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let pinned_identity = pinned.identity();
    let world = exact_world(pin);

    let mut corrupted = pin.artifact_bytes().to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let corrupted = ComponentArtifact::copy_from(&corrupted, pin.profile()).unwrap();
    assert_eq!(
        admit_native_async_acceptance_candidate(
            corrupted,
            &policy(pin, &world, pinned_identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::UntrustedArtifact)
    );

    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    let mut adjacent_world = exact_world(pin);
    adjacent_world.identity = String::from("vibe:stream/native-filter@1.0.1");
    assert_eq!(
        admit_native_async_acceptance_candidate(
            artifact,
            &policy(pin, &adjacent_world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    let mut wrong_contract = exact_world(pin);
    wrong_contract.exports.clear();
    assert!(matches!(
        admit_native_async_acceptance_candidate(
            artifact,
            &policy(pin, &wrong_contract, identity),
            &CallerAuthority { offers: &[] },
        ),
        Err(AdmissionError::World(_))
    ));
}
