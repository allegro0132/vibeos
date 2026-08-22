#![cfg(feature = "native-async-acceptance")]

use core::sync::atomic::{AtomicUsize, Ordering};
use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_format::{ProfileIdentity, TrapCode};
use vibeos_component_runtime::{
    decode::inspect_component_for_profile,
    host::HostWakeToken,
    native_async_acceptance::{
        CancelOutcome, Component, ControlError, Error, HostError, HostRequest, HostToken,
        Invocation, Metrics, Poll, WaitToken,
    },
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const C53_FILTER_WAT: &str =
    include_str!("../../policy/image/artifacts/c53-native-async-filter.component.wat");
const ENTRYPOINT: &str = "run";
const MEMORY_BYTES: usize = 64 * 1024;
const RESOURCE_LIMIT: u32 = 8;
const TOTAL_WORK: u64 = 500_000;
const POLL_QUANTUM: u64 = 100;
const PREFIX_LIMIT: usize = 512;
const SEEDED_STEPS: usize = 24;

fn component_from(source: &str) -> Component {
    let bytes = wat::parse_str(source).expect("native async component WAT");
    let plan = inspect_component_for_profile(
        &bytes,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    )
    .expect("native async validation plan");
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    Component::instantiate_validation_candidate_with_memory_limit(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
        MEMORY_BYTES,
        RESOURCE_LIMIT,
    )
    .expect("validation-candidate executor")
}

fn pinned_component() -> Component {
    component_from(C53_FILTER_WAT)
}

fn assert_storage_bounded(component: &Component, seed: u64, action: &str) {
    let storage = component.storage_metrics();
    let usages = [
        ("handles", storage.async_state.handles),
        ("pairs", storage.async_state.pairs),
        ("tasks", storage.async_state.tasks),
        ("joined_waitables", storage.async_state.joined_waitables),
        ("wait_registrations", storage.async_state.wait_registrations),
        ("buffers", storage.buffers),
        ("wait_wake_registrations", storage.wait_wake_registrations),
    ];
    for (name, usage) in usages {
        assert!(
            usage.current <= usage.peak && usage.peak <= usage.limit,
            "seed={seed:#018x} action={action}: {name} usage {usage:?} escaped its ceiling"
        );
    }
}

fn assert_storage_empty(component: &Component, seed: u64, action: &str) {
    assert_storage_bounded(component, seed, action);
    let storage = component.storage_metrics();
    assert_eq!(
        (
            storage.async_state.handles.current,
            storage.async_state.pairs.current,
            storage.async_state.tasks.current,
            storage.async_state.joined_waitables.current,
            storage.async_state.wait_registrations.current,
            storage.buffers.current,
            storage.wait_wake_registrations.current,
        ),
        (0, 0, 0, 0, 0, 0, 0),
        "seed={seed:#018x} action={action}: clean invocation leaked storage"
    );
}

fn panic_message(payload: Box<dyn core::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        String::from(*message)
    } else {
        String::from("non-string panic")
    }
}

fn turn<T>(
    invocation: &mut Invocation<'_>,
    seed: u64,
    step: &mut usize,
    action: &str,
    operation: impl FnOnce(&mut Invocation<'_>) -> T,
) -> T {
    let current_step = *step;
    let before = invocation.metrics();
    let result = catch_unwind(AssertUnwindSafe(|| operation(invocation))).unwrap_or_else(|panic| {
        panic!(
            "seed={seed:#018x} step={current_step} action={action}: runtime panicked: {}",
            panic_message(panic)
        )
    });
    let after = invocation.metrics();
    let consumed = after.consumed_work.checked_sub(before.consumed_work).unwrap_or_else(|| {
        panic!(
            "seed={seed:#018x} step={current_step} action={action}: consumed work moved backward: {before:?} -> {after:?}"
        )
    });
    let remaining = before.remaining_work.checked_sub(after.remaining_work).unwrap_or_else(|| {
        panic!(
            "seed={seed:#018x} step={current_step} action={action}: remaining work increased: {before:?} -> {after:?}"
        )
    });
    assert_eq!(
        consumed, remaining,
        "seed={seed:#018x} step={current_step} action={action}: split work ledger"
    );
    assert!(
        consumed <= POLL_QUANTUM,
        "seed={seed:#018x} step={current_step} action={action}: one turn consumed {consumed}, quantum is {POLL_QUANTUM}"
    );
    assert_eq!(
        after.consumed_work.checked_add(after.remaining_work),
        Some(TOTAL_WORK),
        "seed={seed:#018x} step={current_step} action={action}: total work changed"
    );
    *step += 1;
    result
}

fn poll_to_host(
    invocation: &mut Invocation<'_>,
    seed: u64,
    step: &mut usize,
    label: &str,
) -> (HostToken, HostRequest, Metrics) {
    for _ in 0..PREFIX_LIMIT {
        let action = format!("{label}/poll");
        match turn(invocation, seed, step, &action, |call| call.poll()) {
            Poll::Pending(_) | Poll::Resolved(_) | Poll::Yielded(_) => {}
            Poll::HostPending {
                token,
                request,
                metrics,
            } => return (token, request, metrics),
            other => panic!(
                "seed={seed:#018x} step={} action={label}: expected HostPending, got {other:?}",
                *step
            ),
        }
    }
    panic!(
        "seed={seed:#018x} step={} action={label}: exceeded {PREFIX_LIMIT} transitions",
        *step
    )
}

fn prepared_token(poll: Poll, expected: HostRequest, seed: u64, step: usize) -> HostToken {
    match poll {
        Poll::HostPending { token, request, .. } if request == expected => token,
        other => panic!(
            "seed={seed:#018x} step={step} action=prepare: expected stable prepared request {expected:?}, got {other:?}"
        ),
    }
}

/// Every seeded trace starts with this exact prefix. Besides making failures
/// replayable, it forces a run suspension, task-return resolution, an input
/// host copy, a guest callback which performs a nested stream-write call, and
/// both offered/prepared token generations before the generated tail begins.
fn mandatory_transition_prefix(
    invocation: &mut Invocation<'_>,
    seed: u64,
    step: &mut usize,
) -> (usize, Vec<u8>) {
    let input = [(seed as u8).wrapping_mul(37).wrapping_add(11)];
    let (offered, request, blocked) = poll_to_host(invocation, seed, step, "prefix/input");
    let HostRequest::InputStream { maximum } = request else {
        panic!(
            "seed={seed:#018x} step={} action=prefix/input: first host request was {request:?}",
            *step
        )
    };
    assert!(maximum > 0);

    let stable = turn(invocation, seed, step, "prefix/input/stable-poll", |call| {
        call.poll()
    });
    assert_eq!(
        stable,
        Poll::HostPending {
            token: offered,
            request,
            metrics: blocked,
        },
        "seed={seed:#018x} step={} action=prefix/input/stable-poll",
        *step - 1
    );
    let before_error = invocation.metrics();
    assert_eq!(
        turn(
            invocation,
            seed,
            step,
            "prefix/input/oversize-prepare",
            |call| call.prepare_host_input_stream(offered, maximum + 1),
        ),
        Err(HostError::InvalidProgress),
        "seed={seed:#018x} step={} action=prefix/input/oversize-prepare",
        *step - 1
    );
    assert_eq!(invocation.metrics(), before_error);

    let prepared = turn(invocation, seed, step, "prefix/input/prepare-one", |call| {
        call.prepare_host_input_stream(offered, 1)
    })
    .expect("valid input prepare");
    let prepared = prepared_token(prepared, request, seed, *step - 1);
    assert!(prepared.strictly_after(offered));
    assert_eq!(
        turn(
            invocation,
            seed,
            step,
            "prefix/input/replay-offered-token",
            |call| call.cancel_host_copy(offered),
        ),
        Err(HostError::InvalidToken),
        "seed={seed:#018x} step={} action=prefix/input/replay-offered-token",
        *step - 1
    );
    assert!(matches!(
        turn(invocation, seed, step, "prefix/input/commit-one", |call| {
            call.commit_host_input_stream(prepared, &input)
        },),
        Ok(Poll::Pending(_))
    ));

    let (offered, request, blocked) = poll_to_host(invocation, seed, step, "prefix/output");
    let HostRequest::OutputStream { maximum } = request else {
        panic!(
            "seed={seed:#018x} step={} action=prefix/output: nested callback request was {request:?}",
            *step
        )
    };
    assert!(maximum > 0);
    assert_eq!(
        turn(
            invocation,
            seed,
            step,
            "prefix/output/stable-poll",
            |call| call.poll()
        ),
        Poll::HostPending {
            token: offered,
            request,
            metrics: blocked,
        }
    );
    let mut oversize = vec![0; maximum as usize + 1];
    assert_eq!(
        turn(
            invocation,
            seed,
            step,
            "prefix/output/oversize-prepare",
            |call| call.prepare_host_output_stream(offered, &mut oversize),
        ),
        Err(HostError::InvalidProgress)
    );
    let mut output = vec![0];
    let prepared = turn(
        invocation,
        seed,
        step,
        "prefix/output/prepare-one",
        |call| call.prepare_host_output_stream(offered, &mut output),
    )
    .expect("valid output prepare");
    assert_eq!(output[0], input[0] ^ 0x20);
    let prepared = prepared_token(prepared, request, seed, *step - 1);
    assert!(prepared.strictly_after(offered));
    assert_eq!(
        turn(
            invocation,
            seed,
            step,
            "prefix/output/replay-offered-token",
            |call| call.commit_host_output(offered),
        ),
        Err(HostError::InvalidToken)
    );
    assert!(matches!(
        turn(invocation, seed, step, "prefix/output/commit-one", |call| {
            call.commit_host_output(prepared)
        },),
        Ok(Poll::Pending(_))
    ));
    (1, output)
}

fn clean_trace(seed: u64, input: &[u8], close_reason: u8) {
    let mut component = pinned_component();
    let mut step = 0;
    let mut invocation = component
        .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
        .expect("pinned filter start");
    let (mut input_offset, mut output) =
        mandatory_transition_prefix(&mut invocation, seed, &mut step);
    assert_eq!(input.first(), Some(&(output[0] ^ 0x20)));
    let mut finalized = false;

    for _ in 0..10_000 {
        let progress = turn(&mut invocation, seed, &mut step, "clean/poll", |call| {
            call.poll()
        });
        match progress {
            Poll::Pending(_) | Poll::Resolved(_) | Poll::Yielded(_) => {}
            Poll::HostPending {
                token,
                request: HostRequest::InputStream { maximum },
                ..
            } => {
                if input_offset == input.len() {
                    assert!(matches!(
                        turn(
                            &mut invocation,
                            seed,
                            &mut step,
                            "clean/input-eof",
                            |call| call.drop_host_copy_peer(token),
                        ),
                        Ok(Poll::Pending(_))
                    ));
                } else {
                    let desired = 1 + ((seed.rotate_left((input_offset % 63) as u32) as usize) % 17);
                    let amount = desired
                        .min(maximum as usize)
                        .min(input.len() - input_offset);
                    let prepared = turn(
                        &mut invocation,
                        seed,
                        &mut step,
                        "clean/input-prepare",
                        |call| call.prepare_host_input_stream(token, amount as u32),
                    )
                    .expect("input prepare");
                    let prepared = prepared_token(
                        prepared,
                        HostRequest::InputStream { maximum },
                        seed,
                        step - 1,
                    );
                    let end = input_offset + amount;
                    assert!(matches!(
                        turn(
                            &mut invocation,
                            seed,
                            &mut step,
                            "clean/input-commit",
                            |call| call.commit_host_input_stream(prepared, &input[input_offset..end]),
                        ),
                        Ok(Poll::Pending(_))
                    ));
                    input_offset = end;
                }
            }
            Poll::HostPending {
                token,
                request: HostRequest::InputClosed,
                ..
            } => {
                let prepared = turn(
                    &mut invocation,
                    seed,
                    &mut step,
                    "clean/input-close-prepare",
                    |call| call.prepare_host_input_closed(token),
                )
                .expect("input close prepare");
                let prepared =
                    prepared_token(prepared, HostRequest::InputClosed, seed, step - 1);
                assert!(matches!(
                    turn(
                        &mut invocation,
                        seed,
                        &mut step,
                        "clean/input-close-commit",
                        |call| call.commit_host_input_closed(prepared, close_reason),
                    ),
                    Ok(Poll::Pending(_))
                ));
            }
            Poll::HostPending {
                token,
                request: HostRequest::OutputStream { maximum },
                ..
            } => {
                let amount = 1 + ((seed.rotate_right((output.len() % 63) as u32) as usize) % 13);
                let amount = amount.min(maximum as usize);
                let start = output.len();
                output.resize(start + amount, 0);
                let prepared = turn(
                    &mut invocation,
                    seed,
                    &mut step,
                    "clean/output-prepare",
                    |call| call.prepare_host_output_stream(token, &mut output[start..]),
                )
                .expect("output prepare");
                let prepared = prepared_token(
                    prepared,
                    HostRequest::OutputStream { maximum },
                    seed,
                    step - 1,
                );
                assert!(matches!(
                    turn(
                        &mut invocation,
                        seed,
                        &mut step,
                        "clean/output-commit",
                        |call| call.commit_host_output(prepared),
                    ),
                    Ok(Poll::Pending(_))
                ));
            }
            Poll::HostPending {
                token,
                request: HostRequest::OutputClosed { value: None },
                ..
            } => {
                let prepared = turn(
                    &mut invocation,
                    seed,
                    &mut step,
                    "clean/output-close-prepare",
                    |call| call.prepare_host_output_closed(token),
                )
                .expect("output close prepare");
                let prepared = prepared_token(
                    prepared,
                    HostRequest::OutputClosed {
                        value: Some(close_reason),
                    },
                    seed,
                    step - 1,
                );
                assert!(matches!(
                    turn(
                        &mut invocation,
                        seed,
                        &mut step,
                        "clean/output-close-commit",
                        |call| call.commit_host_output(prepared),
                    ),
                    Ok(Poll::Pending(_))
                ));
            }
            Poll::HostPending { request, .. } => panic!(
                "seed={seed:#018x} step={step} action=clean: unexpected prepared request {request:?}"
            ),
            Poll::Complete(_) => {
                turn(
                    &mut invocation,
                    seed,
                    &mut step,
                    "clean/finalize",
                    |call| call.finalize_transport(),
                )
                .expect("clean transport finalization");
                finalized = true;
                break;
            }
            Poll::WaitPending { .. } => panic!(
                "seed={seed:#018x} step={step} action=clean: pinned filter unexpectedly parked"
            ),
            Poll::CleanupPending { trap, .. } | Poll::Trapped(trap) => panic!(
                "seed={seed:#018x} step={step} action=clean: pinned filter trapped: {trap:?}"
            ),
        }
    }
    assert!(
        finalized,
        "seed={seed:#018x} step={step} action=clean: transition bound exhausted before Complete/finalize"
    );
    assert_eq!(input_offset, input.len());
    assert_eq!(
        output,
        input.iter().map(|byte| byte ^ 0x20).collect::<Vec<_>>()
    );
    drop(invocation);
    assert_storage_empty(&component, seed, "clean/drop");
}

#[test]
fn pinned_filter_mandatory_prefix_and_clean_seeded_traces_are_bounded() {
    const SEEDS: [u64; 4] = [
        0x0000_0000_0000_0001,
        0x9e37_79b9_7f4a_7c15,
        0xd1b5_4a32_d192_ed03,
        0xffff_ffff_ffff_ffff,
    ];
    for seed in SEEDS {
        let mut input = vec![(seed as u8).wrapping_mul(37).wrapping_add(11)];
        input.extend((1..=47).map(|index| {
            (seed.rotate_left(index) as u8).wrapping_add((index as u8).wrapping_mul(29))
        }));
        clean_trace(seed, &input, (seed as u8) & 7);
    }
}

#[test]
fn pinned_filter_seeded_early_drop_is_poisoned_and_confined() {
    const SEEDS: [u64; 8] = [
        0x243f_6a88_85a3_08d3,
        0x1319_8a2e_0370_7344,
        0xa409_3822_299f_31d0,
        0x082e_fa98_ec4e_6c89,
        0x4528_21e6_38d0_1377,
        0xbe54_66cf_34e9_0c6c,
        0xc0ac_29b7_c97c_50dd,
        0x3f84_d5b5_b547_0917,
    ];
    for seed in SEEDS {
        let mut component = pinned_component();
        let mut step = 0;
        {
            let mut invocation = component
                .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
                .expect("pinned filter start");
            let _ = mandatory_transition_prefix(&mut invocation, seed, &mut step);
            let drop_after = 1 + (seed as usize % SEEDED_STEPS);
            for generated in 0..drop_after {
                let action = format!("seeded-tail/poll-{generated}");
                match turn(&mut invocation, seed, &mut step, &action, |call| {
                    call.poll()
                }) {
                    Poll::Pending(_) | Poll::Resolved(_) | Poll::Yielded(_) => {}
                    Poll::HostPending { token, .. } => {
                        if generated & 1 == 0 {
                            let before = invocation.metrics();
                            let stable = turn(
                                &mut invocation,
                                seed,
                                &mut step,
                                "seeded-tail/stable-host-poll",
                                |call| call.poll(),
                            );
                            assert!(
                                matches!(stable, Poll::HostPending { token: next, .. } if next == token)
                            );
                            assert_eq!(invocation.metrics(), before);
                        }
                    }
                    Poll::Complete(_) | Poll::WaitPending { .. } => break,
                    Poll::CleanupPending { .. } | Poll::Trapped(_) => break,
                }
            }
            // Dropping at a deterministic, seed-selected suspension boundary
            // is itself the generated action under test.
        }
        assert_eq!(
            component
                .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
                .err(),
            Some(Error::Poisoned),
            "seed={seed:#018x} step={step} action=drop-incomplete: component remained reusable"
        );
        assert_storage_bounded(&component, seed, "drop-incomplete");
        catch_unwind(AssertUnwindSafe(|| drop(component))).unwrap_or_else(|panic| {
            panic!(
                "seed={seed:#018x} step={step} action=drop-component: {}",
                panic_message(panic)
            )
        });
    }
}

#[test]
fn pinned_filter_invalid_close_traps_then_completes_bounded_cleanup() {
    let seed = 0x6a09_e667_f3bc_c909;
    let mut component = pinned_component();
    let mut step = 0;
    let trapped = {
        let mut invocation = component
            .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
            .expect("pinned filter start");
        let _ = mandatory_transition_prefix(&mut invocation, seed, &mut step);
        let mut trap = None;
        let mut terminal = false;
        for _ in 0..PREFIX_LIMIT {
            match turn(&mut invocation, seed, &mut step, "trap/poll", |call| {
                call.poll()
            }) {
                Poll::Pending(_) | Poll::Resolved(_) | Poll::Yielded(_) => {}
                Poll::HostPending {
                    token,
                    request: HostRequest::InputStream { .. },
                    ..
                } => {
                    assert!(matches!(
                        turn(&mut invocation, seed, &mut step, "trap/input-eof", |call| {
                            call.drop_host_copy_peer(token)
                        },),
                        Ok(Poll::Pending(_))
                    ));
                }
                Poll::HostPending {
                    token,
                    request: HostRequest::InputClosed,
                    ..
                } => {
                    let prepared = turn(
                        &mut invocation,
                        seed,
                        &mut step,
                        "trap/close-prepare",
                        |call| call.prepare_host_input_closed(token),
                    )
                    .expect("input close prepare");
                    let prepared =
                        prepared_token(prepared, HostRequest::InputClosed, seed, step - 1);
                    let pending = turn(
                        &mut invocation,
                        seed,
                        &mut step,
                        "trap/invalid-close-commit",
                        |call| call.commit_host_input_closed(prepared, 8),
                    )
                    .expect("invalid close is a guest-visible trap, not a driver error");
                    assert!(matches!(
                        pending,
                        Poll::CleanupPending {
                            trap: TrapCode::CanonicalAbi,
                            ..
                        }
                    ));
                    trap = Some(TrapCode::CanonicalAbi);
                }
                Poll::CleanupPending { trap: observed, .. } => trap = Some(observed),
                Poll::Trapped(observed) => {
                    assert_eq!(Some(observed), trap);
                    terminal = true;
                    break;
                }
                other => panic!(
                    "seed={seed:#018x} step={step} action=trap: unexpected transition {other:?}"
                ),
            }
        }
        assert!(
            terminal,
            "seed={seed:#018x} step={step} action=trap: cleanup did not reach Trapped within {PREFIX_LIMIT} transitions"
        );
        trap
    };
    assert_eq!(trapped, Some(TrapCode::CanonicalAbi));
    assert_eq!(
        component
            .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
            .err(),
        Some(Error::Poisoned)
    );
    assert_storage_bounded(&component, seed, "trap/cleanup-complete");
}

const PINNED_INPUT_READ: &str = r#"    (func $begin-input-read (result i32)
      i32.const 0
      call $load-state
      i32.const 1024
      i32.const 1024
      call $stream-read
      i32.const -1
      i32.ne
      if
        unreachable
      end
      call $wait-result)"#;
const WAIT_ONLY_INPUT_READ: &str = r#"    (func $begin-input-read (result i32)
      call $wait-result)"#;
const PINNED_TASK_RETURN: &str = r#"      i32.const 8
      call $load-state
      i32.const 16
      call $load-state
      call $task-return
      call $begin-input-read)"#;
const WAIT_ONLY_RETURN: &str = r#"      call $begin-input-read)"#;

fn wait_only_filter() -> String {
    assert_eq!(C53_FILTER_WAT.matches(PINNED_INPUT_READ).count(), 1);
    assert_eq!(C53_FILTER_WAT.matches(PINNED_TASK_RETURN).count(), 1);
    C53_FILTER_WAT
        .replacen(PINNED_INPUT_READ, WAIT_ONLY_INPUT_READ, 1)
        .replacen(PINNED_TASK_RETURN, WAIT_ONLY_RETURN, 1)
}

static WAIT_WAKES: AtomicUsize = AtomicUsize::new(0);

fn count_wait_wake(_: [usize; 4]) {
    WAIT_WAKES.fetch_add(1, Ordering::SeqCst);
}

fn poll_to_wait(invocation: &mut Invocation<'_>, seed: u64, step: &mut usize) -> WaitToken {
    for _ in 0..PREFIX_LIMIT {
        match turn(invocation, seed, step, "wait/poll", |call| call.poll()) {
            Poll::Pending(_) | Poll::Resolved(_) | Poll::Yielded(_) => {}
            Poll::WaitPending { token, .. } => return token,
            other => panic!(
                "seed={seed:#018x} step={} action=wait/poll: expected WaitPending, got {other:?}",
                *step
            ),
        }
    }
    panic!("seed={seed:#018x} action=wait/poll: transition bound exceeded")
}

#[test]
fn wait_tokens_cancel_and_stale_replay_are_exact_and_bounded() {
    let seed = 0xbb67_ae85_84ca_a73b;
    let source = wait_only_filter();
    let mut component = component_from(&source);
    let mut foreign_component = component_from(&source);
    let mut step = 0;
    WAIT_WAKES.store(0, Ordering::SeqCst);
    {
        let mut invocation = component
            .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
            .expect("wait-only filter start");
        let mut foreign = foreign_component
            .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
            .expect("foreign wait-only filter start");
        let token = poll_to_wait(&mut invocation, seed, &mut step);
        let foreign_token = poll_to_wait(&mut foreign, seed ^ 1, &mut step);
        let before = invocation.metrics();
        assert!(matches!(
            turn(
                &mut invocation,
                seed,
                &mut step,
                "wait/register-foreign-token",
                |call| {
                    call.register_wait_wake(
                        foreign_token,
                        HostWakeToken::new([0; 4], count_wait_wake),
                    )
                },
            ),
            Err(ControlError::InvalidWaitToken)
        ));
        assert_eq!(invocation.metrics(), before);
        let registration = turn(
            &mut invocation,
            seed,
            &mut step,
            "wait/register-exact-token",
            |call| call.register_wait_wake(token, HostWakeToken::new([0; 4], count_wait_wake)),
        )
        .expect("exact wait registration");
        assert_eq!(
            turn(
                &mut invocation,
                seed,
                &mut step,
                "wait/request-cancel",
                |call| call.request_cancel(),
            ),
            Ok(CancelOutcome::Requested)
        );
        assert_eq!(WAIT_WAKES.load(Ordering::SeqCst), 1);
        assert!(matches!(
            turn(
                &mut invocation,
                seed,
                &mut step,
                "wait/resume-cancel",
                |call| call.resume_wait(registration),
            ),
            Ok(Poll::Pending(_))
        ));
        assert!(matches!(
            turn(
                &mut invocation,
                seed,
                &mut step,
                "wait/replay-stale-token",
                |call| call.register_wait_wake(token, HostWakeToken::new([0; 4], count_wait_wake),),
            ),
            Err(ControlError::NotWaiting)
        ));

        let mut saw_cleanup = false;
        let mut terminal = false;
        for _ in 0..PREFIX_LIMIT {
            match turn(
                &mut invocation,
                seed,
                &mut step,
                "wait/cancel-callback",
                |call| call.poll(),
            ) {
                Poll::Pending(_) | Poll::Resolved(_) | Poll::Yielded(_) => {}
                Poll::CleanupPending { .. } => saw_cleanup = true,
                Poll::Trapped(_) => {
                    terminal = true;
                    break;
                }
                other => panic!(
                    "seed={seed:#018x} step={step} action=wait/cancel-callback: unexpected {other:?}"
                ),
            }
        }
        assert!(saw_cleanup);
        assert!(
            terminal,
            "seed={seed:#018x} step={step} action=wait/cancel-callback: cleanup did not reach Trapped within {PREFIX_LIMIT} transitions"
        );
        // `foreign` is deliberately dropped while blocked; both incomplete
        // components must remain sealed and safely reclaimable by whole drop.
    }
    assert_eq!(
        component
            .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
            .err(),
        Some(Error::Poisoned)
    );
    assert_eq!(
        foreign_component
            .start_filter(ENTRYPOINT, TOTAL_WORK, POLL_QUANTUM)
            .err(),
        Some(Error::Poisoned)
    );
    assert_storage_bounded(&component, seed, "wait/cancelled-drop");
    assert_storage_bounded(&foreign_component, seed ^ 1, "wait/blocked-drop");
}
