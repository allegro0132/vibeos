//! Kernel adapters for the separately compiled SSH component and acceptance
//! runner.
//!
//! This module is intentionally thin: it resolves capabilities against the
//! component CSpace and translates kernel-private devices, timers, logging, and
//! shutdown to platform-neutral interfaces. SSH protocol and acceptance policy
//! live in their own crates.

extern crate alloc;

use alloc::boxed::Box;
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use core::fmt;

use vibeos_core::cap::{Cap, Rights};
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use vibeos_core::chan::Endpoint;
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use vibeos_core::net::StampedPacket;
#[cfg(feature = "ssh-security-test")]
use vibeos_kernel_acceptance::ssh_security_test::{
    Platform as SecurityTestPlatform, PlatformFuture as SecurityPlatformFuture,
    SecretBytes as SecuritySecretBytes,
};
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use vibeos_net_api::{TcpConnectionToken, TcpIoResult, TcpListener, TcpListenerSnapshot};
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use vibeos_ssh_identity::SshEd25519PublicKey;
#[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample")]
use vibeos_sshd::SshExecProfileTerminal;
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use vibeos_sshd::{
    AuthorizedProfile, BindRetry, HostPublicKeySnapshot, HostSignatureResult, Ipv4Policy,
    Ipv4RuntimeStatus, NetworkBindError, NetworkInfo, Platform as SshdPlatform, PlatformFuture,
    SecretBytes, SshExecComponentSessionPolicy, SshServicePolicy, StaticIpv4Address,
};
#[cfg(feature = "wasm-c84-ssh-request-parent")]
use vibeos_sshd::{
    SshExecProfilePermit, SshExecProfilePermitBackend, SshExecProfilePrepareError,
    SshExecProfileRunBackend, SshExecProfileTarget,
};

#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
use crate::ssh_security::{AuthorizedKeyPolicyService, HostSigningService};
use crate::world::Space;

#[cfg(feature = "milkv-ssh")]
use crate::jitterentropy_random as ssh_rng;
#[cfg(feature = "qemu-virt")]
use crate::virtio_rng as ssh_rng;
use ssh_rng::RandomError;
#[cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]
use vibeos_kernel_acceptance::ssh_acceptance_rng as ssh_rng;

const ENTROPY_RETRY_BUDGET: usize = 5_000;

#[cfg(feature = "ssh-test")]
const SSH_SERVICE_POLICY: SshServicePolicy = SshServicePolicy {
    ethernet_address: [0x02, 0, 0, 0, 0, 1],
    listen_port: 2222,
    ipv4: Ipv4Policy::Static(
        StaticIpv4Address::new([10, 0, 2, 15], 24).with_default_gateway([10, 0, 2, 2]),
    ),
    require_carrier: false,
    bind_retry: BindRetry::Attempts(5_000),
    status_interval_ms: 0,
    listener_label: "ssh-test",
};

#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
fn ssh_service_policy() -> SshServicePolicy {
    SSH_SERVICE_POLICY
}

#[cfg(feature = "milkv-ssh-acceptance")]
const SSH_SERVICE_POLICY: SshServicePolicy = SshServicePolicy {
    ethernet_address: [0x02, 0, 0, 0, 0, 1],
    listen_port: 2222,
    ipv4: Ipv4Policy::Dhcp {
        bootstrap: StaticIpv4Address::new([192, 0, 2, 1], 24),
    },
    require_carrier: true,
    bind_retry: BindRetry::Forever,
    status_interval_ms: 30_000,
    listener_label: "milkv-ssh-acceptance",
};

#[cfg(feature = "milkv-ssh")]
const SSH_SERVICE_POLICY: SshServicePolicy = SshServicePolicy {
    ethernet_address: [0x02, 0, 0, 0, 0, 1],
    listen_port: 22,
    ipv4: Ipv4Policy::Dhcp {
        bootstrap: StaticIpv4Address::new([192, 0, 2, 1], 24),
    },
    require_carrier: true,
    bind_retry: BindRetry::Forever,
    status_interval_ms: 30_000,
    listener_label: "sshd",
};

#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
struct SshPlatform {
    space: &'static Space,
}

#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
impl SshPlatform {
    const fn new(space: &'static Space) -> Self {
        Self { space }
    }
}

/// Kernel-private request-parent owner retained inside one SSHD-allocated box.
///
/// `start` mutates this object from Reserved to Active before SSHD moves that
/// same box between its public typestates. The base owner remains cancel-only.
/// Its terminal successors either discard a newly verified stream, consume
/// its summary and every interval before explicit completion, or briefly seal
/// one opaque trusted sample before explicitly abandoning it. No
/// storage-bearing stream, terminal evidence, or publisher authority leaves
/// this synchronous adapter.
#[cfg(feature = "wasm-c84-ssh-request-parent")]
struct SshExecProfileOwner {
    policy: SshExecComponentSessionPolicy,
    state: SshExecProfileOwnerState,
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
enum SshExecProfileOwnerState {
    Reserved(crate::wasm_aot_profile_slot::StartPermit),
    Active(crate::wasm_aot_profile_slot::RunLease),
    Closed,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedStreamEvidence {
    ready_epoch: u64,
    total_ticks: u64,
    interval_count: usize,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample")]
struct TrustedSampleEvidence {
    ready_epoch: u64,
    #[cfg(any(
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
    ))]
    acceptance: crate::wasm_aot_profile_slot::TrustedSampleAcceptanceObservation,
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
    collector: crate::wasm_aot_profile_slot::CollectorTerminalReceipt,
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
impl SshExecProfileOwner {
    const fn reserved(
        policy: SshExecComponentSessionPolicy,
        permit: crate::wasm_aot_profile_slot::StartPermit,
    ) -> Self {
        Self {
            policy,
            state: SshExecProfileOwnerState::Reserved(permit),
        }
    }

    fn start(&mut self) -> Result<(), ()> {
        let previous = core::mem::replace(&mut self.state, SshExecProfileOwnerState::Closed);
        let SshExecProfileOwnerState::Reserved(permit) = previous else {
            self.state = previous;
            profile_request_failure("start-state", None);
            return Err(());
        };
        match permit.start() {
            Ok(run) => {
                let epoch = run.token().epoch();
                self.state = SshExecProfileOwnerState::Active(run);
                profile_request_start(epoch);
                Ok(())
            }
            Err(_) => {
                profile_request_failure("start", None);
                Err(())
            }
        }
    }

    fn response_boundary(
        &mut self,
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-trusted-sample"))] status: u32,
        #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample")]
        terminal_seal: SshExecProfileTerminal,
    ) -> Result<(), ()> {
        #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample")]
        let status = terminal_seal.exit_status();
        let previous = core::mem::replace(&mut self.state, SshExecProfileOwnerState::Closed);
        let SshExecProfileOwnerState::Active(run) = previous else {
            self.state = previous;
            profile_request_failure("response-state", None);
            return Err(());
        };
        let epoch = run.token().epoch();
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        let child_ready = crate::wasm_aot_profile_slot::managed_phase_response_ready(epoch).is_ok();
        #[cfg(all(
            feature = "wasm-c84-ssh-managed-child-core",
            not(feature = "wasm-c84-ssh-managed-child-phase-sidecar")
        ))]
        let child_ready = crate::wasm_aot_profile_slot::managed_child_response_ready(epoch).is_ok();
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-core"))]
        let child_ready = true;
        #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample")]
        let trusted_terminal_prerequisite = terminal_seal.component_terminal()
            == vibeos_vsh::ComponentTerminal::Success
            && !terminal_seal.timed_out();
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-trusted-sample"))]
        let trusted_terminal_prerequisite = true;
        #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify")]
        if status != 0
            || !trusted_terminal_prerequisite
            || !child_ready
            || !profile_policy_is_current(self.policy)
        {
            let recycled =
                cancel_and_ack_profile(run, crate::wasm_aot_profile_slot::SlotFaults::default());
            let stage = if recycled.is_ok() {
                "response-prerequisite"
            } else {
                "response-prerequisite-cancel"
            };
            profile_request_failure(stage, Some(epoch));
            return Err(());
        }
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        let phase_observation = crate::wasm_aot_profile_slot::managed_phase_observation(epoch);
        #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
        let child_observation =
            crate::wasm_aot_profile_slot::take_managed_child_response_observation(epoch);
        #[cfg(all(
            feature = "wasm-c84-ssh-managed-child-trusted-sample",
            not(feature = "wasm-c84-ssh-managed-child-single-boot-collector")
        ))]
        let terminal = finish_verify_trusted_discard_and_ack_profile(run, terminal_seal)
            .map(|evidence| (evidence.ready_epoch, evidence));
        #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
        let terminal = finish_verify_trusted_collect_profile(run, terminal_seal)
            .map(|evidence| (evidence.ready_epoch, evidence));
        #[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream")]
        let terminal = finish_verify_stream_and_complete_profile(run)
            .map(|evidence| (evidence.ready_epoch, evidence));
        #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify")]
        #[cfg(not(any(
            feature = "wasm-c84-ssh-managed-child-verified-stream",
            feature = "wasm-c84-ssh-managed-child-trusted-sample"
        )))]
        let terminal =
            finish_verify_discard_and_ack_profile(run).map(|ready_epoch| (ready_epoch, ()));
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-finish-verify"))]
        let terminal =
            cancel_and_ack_profile(run, crate::wasm_aot_profile_slot::SlotFaults::default())
                .map(|ready_epoch| (ready_epoch, ()));
        #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify")]
        let terminal_prerequisite_exact = true;
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-finish-verify"))]
        let terminal_prerequisite_exact = child_ready && profile_policy_is_current(self.policy);
        match terminal {
            Ok((ready_epoch, _terminal_evidence)) if terminal_prerequisite_exact => {
                #[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
                let irq_observation =
                    match crate::wasm_aot_profile_slot::managed_irq_acceptance_terminal_gate(
                        epoch,
                        ready_epoch,
                    ) {
                        Ok(observation) => observation,
                        Err(_) => {
                            profile_request_failure("irq-response-terminal", Some(epoch));
                            return Err(());
                        }
                    };
                #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
                profile_phase_response(
                    epoch,
                    status,
                    ready_epoch,
                    phase_observation,
                    child_observation,
                )?;
                #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
                match child_observation {
                    Ok(observation) => {
                        #[cfg(not(
                            feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance"
                        ))]
                        crate::println!(
                            "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 cancel=1 ack=1 ready_epoch={}",
                            epoch,
                            status,
                            observation.core_polls,
                            observation.core_pairs,
                            observation.typed_polls,
                            ready_epoch
                        );
                        #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
                        #[cfg(not(any(
                            feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
                            feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
                            feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
                        )))]
                        crate::println!(
                            "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 finish=1 verify=1 discard=stream_abandoned ack=1 ready_epoch={}",
                            epoch,
                            status,
                            observation.core_polls,
                            observation.core_pairs,
                            observation.typed_polls,
                            ready_epoch
                        );
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance"
                        )]
                        crate::println!(
                            "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1 ready_epoch={}",
                            epoch,
                            status,
                            observation.core_polls,
                            observation.core_pairs,
                            observation.typed_polls,
                            ready_epoch
                        );
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
                        )]
                        crate::println!(
                            "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 finish=1 verify=1 bundle=trusted collector=consumed ack=0 ready_epoch={}",
                            epoch,
                            status,
                            observation.core_polls,
                            observation.core_pairs,
                            observation.typed_polls,
                            ready_epoch
                        );
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance"
                        )]
                        crate::println!(
                            "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 finish=1 verify=1 stream=complete ack=0 ready_epoch={}",
                            epoch,
                            status,
                            observation.core_polls,
                            observation.core_pairs,
                            observation.typed_polls,
                            ready_epoch
                        );
                    }
                    Err(_) => {
                        profile_request_failure("managed-child-response-trace", Some(epoch));
                        return Err(());
                    }
                }
                profile_request_response(epoch, status, ready_epoch);
                #[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
                managed_irq_response(epoch, status, ready_epoch, irq_observation);
                #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
                finish_verify_response(epoch, status, ready_epoch);
                #[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
                verified_stream_response(epoch, _terminal_evidence);
                #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
                trusted_sample_response(epoch, _terminal_evidence)?;
                #[cfg(
                    feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
                )]
                collector_trusted_sample_response(epoch, &_terminal_evidence)?;
                #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
                crate::wasm_aot_profile_slot::collector_emit_success(_terminal_evidence.collector)
                    .map_err(|_| ())?;
                Ok(())
            }
            Ok(_) => {
                profile_request_failure("response-policy", Some(epoch));
                Err(())
            }
            Err(()) => {
                profile_request_failure("response", Some(epoch));
                Err(())
            }
        }
    }

    fn cancel(&mut self) {
        let previous = core::mem::replace(&mut self.state, SshExecProfileOwnerState::Closed);
        match previous {
            SshExecProfileOwnerState::Reserved(permit) => drop(permit),
            SshExecProfileOwnerState::Active(run) => {
                let epoch = run.token().epoch();
                #[cfg(feature = "wasm-c84-ssh-managed-child-core")]
                let drop_expectation =
                    crate::wasm_aot_profile_slot::managed_child_drop_faults(epoch);
                #[cfg(all(
                    feature = "wasm-c84-ssh-managed-child-core",
                    not(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")
                ))]
                let expectation_exact = drop_expectation.is_ok();
                #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
                let expectation_exact = drop_expectation.is_ok()
                    && crate::wasm_aot_profile_slot::managed_child_active_drop_ready(epoch).is_ok();
                #[cfg(feature = "wasm-c84-ssh-managed-child-core")]
                let expected_faults = drop_expectation.unwrap_or_default();
                #[cfg(not(feature = "wasm-c84-ssh-managed-child-core"))]
                let expected_faults = crate::wasm_aot_profile_slot::SlotFaults::default();
                #[cfg(not(feature = "wasm-c84-ssh-managed-child-core"))]
                let expectation_exact = true;
                #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
                let child_drop =
                    crate::wasm_aot_profile_slot::take_managed_child_drop_observation(epoch);
                #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
                let phase_observation =
                    crate::wasm_aot_profile_slot::managed_phase_observation(epoch);
                match cancel_and_ack_profile(run, expected_faults) {
                    Ok(ready_epoch) if expectation_exact => {
                        #[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
                        let irq_observation =
                            match crate::wasm_aot_profile_slot::managed_irq_acceptance_terminal_gate(
                                epoch,
                                ready_epoch,
                            ) {
                                Ok(observation) => observation,
                                Err(_) => {
                                    profile_request_failure("irq-drop-terminal", Some(epoch));
                                    return;
                                }
                            };
                        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
                        if profile_phase_drop(
                            epoch,
                            ready_epoch,
                            expected_faults,
                            phase_observation,
                            child_drop,
                        )
                        .is_err()
                        {
                            return;
                        }
                        #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
                        match child_drop {
                            Ok((core_pairs, crate::exec::TaskDetachReason::Exited)) => {
                                crate::println!(
                                    "WASM_C84_SSH_MANAGED_CHILD_CORE DROP epoch={} claim=1 release=0 detach=exited clean=0 child_faults=abandoned+detached observer_pairs={} observer_closed=1 cancel=1 ack=1 ready_epoch={}",
                                    epoch,
                                    core_pairs,
                                    ready_epoch
                                )
                            }
                            Ok(_) | Err(_) => {
                                profile_request_failure("managed-child-drop-trace", Some(epoch));
                                return;
                            }
                        }
                        profile_request_drop(epoch, ready_epoch);
                        #[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
                        managed_irq_drop(epoch, ready_epoch, irq_observation);
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance"
                        )]
                        finish_verify_drop(epoch, ready_epoch);
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance"
                        )]
                        verified_stream_drop(epoch, ready_epoch);
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance"
                        )]
                        trusted_sample_drop(epoch, ready_epoch);
                        #[cfg(
                            feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
                        )]
                        {
                            trusted_sample_drop(epoch, ready_epoch);
                            if crate::wasm_aot_profile_slot::collector_emit_failed_after_drop(
                                epoch,
                                ready_epoch,
                            )
                            .is_err()
                            {
                                profile_request_failure("collector-drop-observation", Some(epoch));
                                return;
                            }
                        }
                    }
                    Ok(_) => profile_request_failure("managed-child-drop-state", Some(epoch)),
                    Err(()) => profile_request_failure("drop", Some(epoch)),
                }
            }
            SshExecProfileOwnerState::Closed => {}
        }
    }
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
fn cancel_and_ack_profile(
    run: crate::wasm_aot_profile_slot::RunLease,
    expected_slot_faults: crate::wasm_aot_profile_slot::SlotFaults,
) -> Result<u64, ()> {
    use crate::wasm_aot_profile_slot::{
        acknowledge_rejection, rejection, RejectionCause, SlotStatus,
    };

    let epoch = run.token().epoch();
    let report = run.cancel().map_err(|_| ())?;
    let report_is_exact = report.epoch == epoch
        && report.cause == RejectionCause::LeaseCancelled
        && report.facade_faults.is_empty()
        && report.ledger_error.is_none()
        && report.slot_faults == expected_slot_faults
        && report.intervals_emitted == 0;
    let stored_rejection_is_exact = rejection() == Some(report);
    // A successful cancel has already installed one diagnostic rejection.
    // Attempt its exact acknowledgement once even when local validation finds
    // an unexpected returned or independently stored field; otherwise a
    // recoverable request would strand the global slot in Rejected. Cancel
    // failure is the only path with no known rejection to acknowledge.
    let acknowledged = acknowledge_rejection(epoch).map_err(|_| ())?;
    let acknowledgement_is_exact = acknowledged == report;
    let ready_epoch = epoch.checked_add(1).ok_or(())?;
    let ready_is_exact = crate::wasm_aot_profile_slot::status()
        == (SlotStatus::Ready {
            next_epoch: Some(ready_epoch),
        });
    if !report_is_exact
        || !stored_rejection_is_exact
        || !acknowledgement_is_exact
        || !ready_is_exact
    {
        return Err(());
    }
    Ok(ready_epoch)
}

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-finish-verify",
    not(feature = "wasm-c84-ssh-managed-child-trusted-sample")
))]
fn finish_verify_discard_and_ack_profile(
    run: crate::wasm_aot_profile_slot::RunLease,
) -> Result<u64, ()> {
    use crate::wasm_aot_profile_slot::{
        rejection, ProfileError, RejectionCause, SlotFaults, SlotStatus,
    };

    let epoch = run.token().epoch();
    let stream = match run.finish() {
        Ok(stream) => stream,
        Err(ProfileError::Rejected(report)) => {
            // finish/verify has already installed this exact rejection. Recycle
            // it even though the response itself must remain failed.
            let _ = acknowledge_finish_verify_rejection(epoch, report)?;
            return Err(());
        }
        Err(_) => {
            // A non-Rejected failure can still have triggered RunLease's
            // fail-closed cancellation Drop. If that installed this epoch's
            // report, acknowledge the known rejection before returning.
            if let Some(report) = rejection().filter(|report| report.epoch == epoch) {
                let _ = acknowledge_finish_verify_rejection(epoch, report);
            }
            return Err(());
        }
    };
    let verified_is_exact = stream.token().epoch() == epoch
        && matches!(
            crate::wasm_aot_profile_slot::status(),
            SlotStatus::Verified {
                epoch: verified_epoch,
                cursor: 0,
                ..
            } if verified_epoch == epoch
        );

    // Deliberately consume the lease explicitly without reading a summary or
    // interval and without ever constructing publication authority.
    let report = stream.discard().map_err(|_| ())?;
    let report_is_exact = report.epoch == epoch
        && report.cause == RejectionCause::StreamAbandoned
        && report.facade_faults.is_empty()
        && report.ledger_error.is_none()
        && report.slot_faults == SlotFaults::default()
        && report.intervals_emitted == 0;
    // A discard has already installed a rejection. Acknowledge it exactly once
    // even if a local invariant above is unexpectedly false, so the global
    // slot cannot remain stranded in Rejected.
    let ready_epoch = acknowledge_finish_verify_rejection(epoch, report)?;
    if !verified_is_exact || !report_is_exact {
        return Err(());
    }
    Ok(ready_epoch)
}

#[cfg(all(
    feature = "wasm-c84-ssh-managed-child-trusted-sample",
    not(feature = "wasm-c84-ssh-managed-child-single-boot-collector")
))]
fn finish_verify_trusted_discard_and_ack_profile(
    run: crate::wasm_aot_profile_slot::RunLease,
    terminal: SshExecProfileTerminal,
) -> Result<TrustedSampleEvidence, ()> {
    use crate::wasm_aot_profile_slot::{
        rejection, ProfileError, RejectionCause, SlotFaults, SlotStatus,
    };

    let epoch = run.token().epoch();
    let bundle = match run.finish_trusted(terminal) {
        Ok(bundle) => bundle,
        Err(ProfileError::Rejected(report)) => {
            // Finish or terminal validation has already installed this exact
            // rejection. Recycle it while preserving a failed SSH response.
            let _ = acknowledge_finish_verify_rejection(epoch, report)?;
            return Err(());
        }
        Err(_) => {
            // A failed transition can still have abandoned its temporary
            // zero-cursor stream. Only recycle an independently observable
            // report belonging to this request.
            if let Some(report) = rejection().filter(|report| report.epoch == epoch) {
                let _ = acknowledge_finish_verify_rejection(epoch, report);
            }
            return Err(());
        }
    };

    #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
    let acceptance = bundle.acceptance_observation();
    let report = bundle.discard().map_err(|_| ())?;
    let report_is_exact = report.epoch == epoch
        && report.cause == RejectionCause::TrustedSampleAbandoned
        && report.facade_faults.is_empty()
        && report.ledger_error.is_none()
        && report.slot_faults == SlotFaults::default()
        && report.intervals_emitted == 0;
    let stored_rejection_is_exact = rejection() == Some(report)
        && crate::wasm_aot_profile_slot::status() == SlotStatus::Rejected(report);
    // The bundle is already consumed and its rejection installed. Always
    // attempt the one exact acknowledgement so an unexpected local telemetry
    // mismatch cannot strand a recoverable global slot.
    let ready_epoch = acknowledge_finish_verify_rejection(epoch, report)?;
    if !report_is_exact || !stored_rejection_is_exact {
        return Err(());
    }

    Ok(TrustedSampleEvidence {
        ready_epoch,
        #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
        acceptance,
    })
}

#[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
fn finish_verify_trusted_collect_profile(
    run: crate::wasm_aot_profile_slot::RunLease,
    terminal: SshExecProfileTerminal,
) -> Result<TrustedSampleEvidence, ()> {
    use crate::wasm_aot_profile_slot::{rejection, ProfileError};

    let epoch = run.token().epoch();
    let bundle = match run.finish_trusted(terminal) {
        Ok(bundle) => bundle,
        Err(ProfileError::Rejected(report)) => {
            let _ = acknowledge_finish_verify_rejection(epoch, report)?;
            return Err(());
        }
        Err(_) => {
            if let Some(report) = rejection().filter(|report| report.epoch == epoch) {
                let _ = acknowledge_finish_verify_rejection(epoch, report);
            }
            return Err(());
        }
    };

    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
    let acceptance = bundle.acceptance_observation();
    let collector = crate::wasm_aot_profile_slot::collect_trusted_sample(bundle).map_err(|_| ())?;
    let ready_epoch = collector.ready_epoch();
    Ok(TrustedSampleEvidence {
        ready_epoch,
        #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
        acceptance,
        collector,
    })
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream")]
fn finish_verify_stream_and_complete_profile(
    run: crate::wasm_aot_profile_slot::RunLease,
) -> Result<VerifiedStreamEvidence, ()> {
    use crate::wasm_aot_profile_slot::{rejection, ProfileError, SlotStatus};
    use vibeos_wasm_aot_profile::{PhaseTicks, INTERVAL_CAPACITY};

    let epoch = run.token().epoch();
    let mut stream = match run.finish() {
        Ok(stream) => stream,
        Err(ProfileError::Rejected(report)) => {
            // finish/verify has already installed the rejection. Recycle it
            // before propagating the failed response.
            let _ = acknowledge_finish_verify_rejection(epoch, report)?;
            return Err(());
        }
        Err(_) => {
            // RunLease Drop may have installed a fail-closed cancellation.
            // Recycle only an independently observable report for this epoch.
            if let Some(report) = rejection().filter(|report| report.epoch == epoch) {
                let _ = acknowledge_finish_verify_rejection(epoch, report);
            }
            return Err(());
        }
    };

    if stream.token().epoch() != epoch {
        discard_and_ack_verified_stream(stream, epoch, 0)?;
        return Err(());
    }
    let initial_interval_count = match crate::wasm_aot_profile_slot::status() {
        SlotStatus::Verified {
            epoch: verified_epoch,
            cursor: 0,
            intervals,
        } if verified_epoch == epoch => intervals,
        _ => {
            discard_and_ack_verified_stream(stream, epoch, 0)?;
            return Err(());
        }
    };
    let summary = match stream.summary() {
        Ok(summary) => summary,
        Err(_) => {
            discard_and_ack_verified_stream(stream, epoch, 0)?;
            return Err(());
        }
    };
    let summary_phase_ticks = summary.phase_ticks();
    let summary_is_exact = summary.interval_capacity() == INTERVAL_CAPACITY
        && summary.intervals_complete()
        && summary.interval_count() != 0
        && summary.interval_count() <= summary.interval_capacity()
        && summary.interval_count() == initial_interval_count
        && summary.total_ticks() != 0
        && summary.end_tick().checked_sub(summary.start_tick()) == Some(summary.total_ticks())
        && summary_phase_ticks.checked_total() == Some(summary.total_ticks());
    if !summary_is_exact {
        discard_and_ack_verified_stream(stream, epoch, 0)?;
        return Err(());
    }

    let mut emitted = 0_usize;
    let mut previous_end = 0_u64;
    let mut previous_phase = None;
    let mut rescanned_phase_ticks = PhaseTicks::ZERO;
    loop {
        let interval = match stream.next_interval() {
            Ok(interval) => interval,
            Err(_) => {
                discard_and_ack_verified_stream(stream, epoch, emitted)?;
                return Err(());
            }
        };
        let Some(interval) = interval else {
            break;
        };
        let expected_sequence = emitted;
        let Some(next_emitted) = emitted.checked_add(1) else {
            discard_and_ack_verified_stream(stream, epoch, emitted)?;
            return Err(());
        };
        emitted = next_emitted;
        let duration = match interval
            .end_offset_ticks()
            .checked_sub(interval.start_offset_ticks())
        {
            Some(duration) if duration != 0 => duration,
            _ => {
                discard_and_ack_verified_stream(stream, epoch, emitted)?;
                return Err(());
            }
        };
        if emitted > summary.interval_count()
            || interval.sequence() != expected_sequence
            || interval.start_offset_ticks() != previous_end
            || previous_phase == Some(interval.phase())
            || !add_verified_stream_phase_ticks(
                &mut rescanned_phase_ticks,
                interval.phase(),
                duration,
            )
        {
            discard_and_ack_verified_stream(stream, epoch, emitted)?;
            return Err(());
        }
        previous_end = interval.end_offset_ticks();
        previous_phase = Some(interval.phase());
    }

    let final_cursor_is_exact = matches!(
        crate::wasm_aot_profile_slot::status(),
        SlotStatus::Verified {
            epoch: verified_epoch,
            cursor,
            intervals,
        } if verified_epoch == epoch
            && cursor == emitted
            && intervals == summary.interval_count()
    );
    if emitted != summary.interval_count()
        || previous_end != summary.total_ticks()
        || rescanned_phase_ticks != summary_phase_ticks
        || !final_cursor_is_exact
    {
        discard_and_ack_verified_stream(stream, epoch, emitted)?;
        return Err(());
    }

    if stream.complete().is_err() {
        acknowledge_consumed_stream_error(epoch, emitted)?;
        return Err(());
    }
    let ready_epoch = epoch.checked_add(1).ok_or(())?;
    let ready_is_exact = crate::wasm_aot_profile_slot::status()
        == (SlotStatus::Ready {
            next_epoch: Some(ready_epoch),
        });
    if !ready_is_exact || rejection().is_some() {
        return Err(());
    }
    Ok(VerifiedStreamEvidence {
        ready_epoch,
        total_ticks: summary.total_ticks(),
        interval_count: summary.interval_count(),
    })
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream")]
fn add_verified_stream_phase_ticks(
    phase_ticks: &mut vibeos_wasm_aot_profile::PhaseTicks,
    phase: vibeos_wasm_aot_profile::Phase,
    ticks: u64,
) -> bool {
    use vibeos_wasm_aot_profile::Phase;

    let phase_ticks = match phase {
        Phase::Validation => &mut phase_ticks.validation,
        Phase::Instantiation => &mut phase_ticks.instantiation,
        Phase::Abi => &mut phase_ticks.abi,
        Phase::Interpretation => &mut phase_ticks.interpretation,
        Phase::Host => &mut phase_ticks.host,
        Phase::Wait => &mut phase_ticks.wait,
        Phase::Cleanup => &mut phase_ticks.cleanup,
    };
    let Some(total) = (*phase_ticks).checked_add(ticks) else {
        return false;
    };
    if total == u64::MAX {
        return false;
    }
    *phase_ticks = total;
    true
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream")]
fn discard_and_ack_verified_stream(
    stream: crate::wasm_aot_profile_slot::StreamLease,
    epoch: u64,
    expected_emitted: usize,
) -> Result<(), ()> {
    use crate::wasm_aot_profile_slot::{RejectionCause, SlotFaults};

    let report = stream.discard().map_err(|_| ())?;
    let report_is_exact = report.epoch == epoch
        && report.cause == RejectionCause::StreamAbandoned
        && report.facade_faults.is_empty()
        && report.ledger_error.is_none()
        && report.slot_faults == SlotFaults::default()
        && report.intervals_emitted == expected_emitted;
    // Discard has installed a known rejection. Acknowledge it even if local
    // comparison fails, then report the response failure to the caller.
    let _ = acknowledge_finish_verify_rejection(epoch, report)?;
    if !report_is_exact {
        return Err(());
    }
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream")]
fn acknowledge_consumed_stream_error(epoch: u64, expected_emitted: usize) -> Result<(), ()> {
    use crate::wasm_aot_profile_slot::{rejection, RejectionCause, SlotFaults};

    // StreamLease::complete consumes the handle. On an error its Drop path may
    // have installed an abandonment report; only that independently visible,
    // same-epoch rejection is safe to acknowledge here.
    let report = rejection()
        .filter(|report| report.epoch == epoch)
        .ok_or(())?;
    let report_is_exact = report.cause == RejectionCause::StreamAbandoned
        && report.facade_faults.is_empty()
        && report.ledger_error.is_none()
        && report.slot_faults == SlotFaults::default()
        && report.intervals_emitted == expected_emitted;
    let _ = acknowledge_finish_verify_rejection(epoch, report)?;
    if !report_is_exact {
        return Err(());
    }
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify")]
fn acknowledge_finish_verify_rejection(
    expected_epoch: u64,
    report: crate::wasm_aot_profile_slot::RejectionReport,
) -> Result<u64, ()> {
    use crate::wasm_aot_profile_slot::{acknowledge_rejection, rejection, SlotStatus};

    let stored_rejection_is_exact = rejection() == Some(report);
    // Use the installed report's own epoch so validation disagreement cannot
    // prevent recycling a known rejection.
    let acknowledged = acknowledge_rejection(report.epoch).map_err(|_| ())?;
    let acknowledgement_is_exact = acknowledged == report;
    let ready_epoch = report.epoch.checked_add(1).ok_or(())?;
    let ready_is_exact = crate::wasm_aot_profile_slot::status()
        == (SlotStatus::Ready {
            next_epoch: Some(ready_epoch),
        });
    if report.epoch != expected_epoch
        || !stored_rejection_is_exact
        || !acknowledgement_is_exact
        || !ready_is_exact
    {
        return Err(());
    }
    Ok(ready_epoch)
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
fn profile_policy_is_current(accepted: SshExecComponentSessionPolicy) -> bool {
    crate::component_instances::select_ssh_exec_component_policy(accepted.profile(), "case-filter")
        == Some(accepted)
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
impl SshExecProfilePermitBackend for SshExecProfileOwner {
    fn start(&mut self) -> Result<(), ()> {
        SshExecProfileOwner::start(self)
    }

    fn into_run(self: Box<Self>) -> Box<dyn SshExecProfileRunBackend> {
        self
    }

    fn cancel(&mut self) {
        SshExecProfileOwner::cancel(self);
    }
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
impl SshExecProfileRunBackend for SshExecProfileOwner {
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    fn phase_host(&mut self) -> Result<(), ()> {
        let SshExecProfileOwnerState::Active(run) = &mut self.state else {
            profile_request_failure("host-phase-state", None);
            return Err(());
        };
        let epoch = run.token().epoch();
        run.managed_parent_host().map_err(|_| {
            profile_request_failure("host-phase", Some(run.token().epoch()));
        })?;
        #[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
        match crate::wasm_aot_profile_slot::managed_irq_acceptance_parent_host(epoch) {
            Ok(Some(observation)) => {
                // The Host transition and self-SSIP trap have both returned;
                // neither SLOT nor the trap stack is held while UART prints.
                crate::println!(
                    "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY PARENT_SSIP epoch={} causal=1 paired={} inactive={} active_epoch={}",
                    epoch,
                    observation.paired,
                    observation.inactive,
                    observation.active_epoch,
                );
            }
            Ok(None) => {}
            Err(_) => {
                profile_request_failure("irq-parent-host", Some(epoch));
                return Err(());
            }
        }
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance"))]
        let _ = epoch;
        Ok(())
    }

    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    fn phase_wait(&mut self) -> Result<(), ()> {
        let SshExecProfileOwnerState::Active(run) = &mut self.state else {
            profile_request_failure("wait-phase-state", None);
            return Err(());
        };
        run.managed_parent_wait().map_err(|_| {
            profile_request_failure("wait-phase", Some(run.token().epoch()));
        })
    }

    #[cfg(not(feature = "wasm-c84-ssh-managed-child-trusted-sample"))]
    fn response_boundary(&mut self, status: u32) -> Result<(), ()> {
        SshExecProfileOwner::response_boundary(self, status)
    }

    #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample")]
    fn response_boundary(&mut self, terminal: SshExecProfileTerminal) -> Result<(), ()> {
        SshExecProfileOwner::response_boundary(self, terminal)
    }

    fn cancel(&mut self) {
        SshExecProfileOwner::cancel(self);
    }
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
impl Drop for SshExecProfileOwner {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
fn profile_request_failure(stage: &'static str, epoch: Option<u64>) {
    #[cfg(feature = "wasm-c84-ssh-request-parent-qemu-acceptance")]
    match epoch {
        Some(epoch) => crate::println!(
            "WASM_C84_SSH_REQUEST_PARENT FAIL stage={} epoch={}",
            stage,
            epoch
        ),
        None => crate::println!(
            "WASM_C84_SSH_REQUEST_PARENT FAIL stage={} epoch=none",
            stage
        ),
    }
    #[cfg(not(feature = "wasm-c84-ssh-request-parent-qemu-acceptance"))]
    let _ = (stage, epoch);
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
fn profile_request_start(epoch: u64) {
    #[cfg(feature = "wasm-c84-ssh-request-parent-qemu-acceptance")]
    crate::println!("WASM_C84_SSH_REQUEST_PARENT START epoch={}", epoch);
    #[cfg(not(feature = "wasm-c84-ssh-request-parent-qemu-acceptance"))]
    let _ = epoch;
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
fn profile_request_response(epoch: u64, status: u32, ready_epoch: u64) {
    #[cfg(all(
        feature = "wasm-c84-ssh-request-parent-qemu-acceptance",
        not(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")
    ))]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} cancel=1 ack=1 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
    #[cfg(not(any(
        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
    )))]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} finish=1 verify=1 discard=stream_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} finish=1 verify=1 bundle=trusted collector=consumed ack=0 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} finish=1 verify=1 stream=complete ack=0 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(not(feature = "wasm-c84-ssh-request-parent-qemu-acceptance"))]
    let _ = (epoch, status, ready_epoch);
}

#[cfg(feature = "wasm-c84-ssh-request-parent")]
fn profile_request_drop(epoch: u64, ready_epoch: u64) {
    #[cfg(feature = "wasm-c84-ssh-request-parent-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT DROP epoch={} cancel=1 ack=1 ready_epoch={}",
        epoch,
        ready_epoch
    );
    #[cfg(not(feature = "wasm-c84-ssh-request-parent-qemu-acceptance"))]
    let _ = (epoch, ready_epoch);
}

#[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
fn managed_irq_response(
    epoch: u64,
    status: u32,
    ready_epoch: u64,
    observation: crate::wasm_aot_profile_slot::ManagedIrqObservation,
) {
    let causal_pair = u8::from(epoch == 1);
    #[cfg(not(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance"))]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={} status={} parent_pair={} child_pair={} terminal_inactive=1 paired={} inactive={} active_epoch={} cancel=1 ack=1 ready_epoch={}",
        epoch,
        status,
        causal_pair,
        causal_pair,
        observation.paired,
        observation.inactive,
        observation.active_epoch,
        ready_epoch,
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
    #[cfg(not(any(
        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
    )))]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={} status={} parent_pair={} child_pair={} terminal_inactive=1 paired={} inactive={} active_epoch={} finish=1 verify=1 discard=stream_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        causal_pair,
        causal_pair,
        observation.paired,
        observation.inactive,
        observation.active_epoch,
        ready_epoch,
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={} status={} parent_pair={} child_pair={} terminal_inactive=1 paired={} inactive={} active_epoch={} finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        causal_pair,
        causal_pair,
        observation.paired,
        observation.inactive,
        observation.active_epoch,
        ready_epoch,
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={} status={} parent_pair={} child_pair={} terminal_inactive=1 paired={} inactive={} active_epoch={} finish=1 verify=1 bundle=trusted collector=consumed ack=0 ready_epoch={}",
        epoch,
        status,
        causal_pair,
        causal_pair,
        observation.paired,
        observation.inactive,
        observation.active_epoch,
        ready_epoch,
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={} status={} parent_pair={} child_pair={} terminal_inactive=1 paired={} inactive={} active_epoch={} finish=1 verify=1 stream=complete ack=0 ready_epoch={}",
        epoch,
        status,
        causal_pair,
        causal_pair,
        observation.paired,
        observation.inactive,
        observation.active_epoch,
        ready_epoch,
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance")]
fn managed_irq_drop(
    epoch: u64,
    ready_epoch: u64,
    observation: crate::wasm_aot_profile_slot::ManagedIrqObservation,
) {
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY DROP epoch={} parent_pair=0 child_pair=0 terminal_inactive=1 paired={} inactive={} active_epoch={} cancel=1 ack=1 ready_epoch={}",
        epoch,
        observation.paired,
        observation.inactive,
        observation.active_epoch,
        ready_epoch,
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
fn profile_phase_response(
    epoch: u64,
    status: u32,
    ready_epoch: u64,
    phase: Result<
        crate::wasm_aot_profile_slot::ManagedPhaseObservation,
        crate::wasm_aot_profile_slot::ProfileError,
    >,
    child: Result<
        crate::wasm_aot_profile_slot::ManagedChildCoreObservation,
        crate::wasm_aot_profile_slot::ProfileError,
    >,
) -> Result<(), ()> {
    use crate::exec::TaskDetachReason;
    use vibeos_wasm_aot_profile::Phase;

    let (phase, child) = match (phase, child) {
        (Ok(phase), Ok(child)) => (phase, child),
        _ => {
            profile_request_failure("phase-response-observation", Some(epoch));
            return Err(());
        }
    };
    let exact = phase.parent_host_starts > 0
        && phase.parent_host_starts == phase.parent_host_finishes
        && phase.parent_wait_starts > 0
        && phase.parent_wait_starts == phase.parent_wait_finishes
        && phase.child_host_starts > 0
        && phase.child_host_starts == phase.child_host_finishes
        && phase.child_wait_starts > 0
        && phase.child_wait_starts == phase.child_wait_finishes
        && phase.cleanup_count == 1
        && phase.cleanup_latched
        && !phase.parent_wait_open
        && !phase.child_wait_open
        && !phase.child_host_open
        && phase.child_base == Phase::Cleanup
        && !phase.child_phase_fault
        && !phase.parent_phase_fault
        && !phase.child_attached
        && phase.child_detach == Some(TaskDetachReason::Exited)
        && phase.slot_faults == crate::wasm_aot_profile_slot::SlotFaults::default()
        && child.core_pairs > 0
        && child.core_pairs == child.core_polls;
    if !exact {
        profile_request_failure("phase-response-state", Some(epoch));
        return Err(());
    }
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR EXITED epoch={} detach=exited release=1",
        epoch
    );
    #[cfg(not(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance"))]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR RESPONSE epoch={} status={} child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} child_wait_open=0 parent_wait_open=0 late=0 clean=1 cancel=1 ack=1 ready_epoch={}",
        epoch,
        status,
        child.core_pairs,
        child.core_pairs,
        phase.child_host_starts,
        phase.child_host_finishes,
        phase.child_wait_starts,
        phase.child_wait_finishes,
        phase.cleanup_count,
        phase.parent_host_starts,
        phase.parent_host_finishes,
        phase.parent_wait_starts,
        phase.parent_wait_finishes,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
    #[cfg(not(any(
        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
    )))]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR RESPONSE epoch={} status={} child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} child_wait_open=0 parent_wait_open=0 late=0 clean=1 finish=1 verify=1 discard=stream_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        child.core_pairs,
        child.core_pairs,
        phase.child_host_starts,
        phase.child_host_finishes,
        phase.child_wait_starts,
        phase.child_wait_finishes,
        phase.cleanup_count,
        phase.parent_host_starts,
        phase.parent_host_finishes,
        phase.parent_wait_starts,
        phase.parent_wait_finishes,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR RESPONSE epoch={} status={} child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} child_wait_open=0 parent_wait_open=0 late=0 clean=1 finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        child.core_pairs,
        child.core_pairs,
        phase.child_host_starts,
        phase.child_host_finishes,
        phase.child_wait_starts,
        phase.child_wait_finishes,
        phase.cleanup_count,
        phase.parent_host_starts,
        phase.parent_host_finishes,
        phase.parent_wait_starts,
        phase.parent_wait_finishes,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR RESPONSE epoch={} status={} child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} child_wait_open=0 parent_wait_open=0 late=0 clean=1 finish=1 verify=1 bundle=trusted collector=consumed ack=0 ready_epoch={}",
        epoch,
        status,
        child.core_pairs,
        child.core_pairs,
        phase.child_host_starts,
        phase.child_host_finishes,
        phase.child_wait_starts,
        phase.child_wait_finishes,
        phase.cleanup_count,
        phase.parent_host_starts,
        phase.parent_host_finishes,
        phase.parent_wait_starts,
        phase.parent_wait_finishes,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR RESPONSE epoch={} status={} child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} child_wait_open=0 parent_wait_open=0 late=0 clean=1 finish=1 verify=1 stream=complete ack=0 ready_epoch={}",
        epoch,
        status,
        child.core_pairs,
        child.core_pairs,
        phase.child_host_starts,
        phase.child_host_finishes,
        phase.child_wait_starts,
        phase.child_wait_finishes,
        phase.cleanup_count,
        phase.parent_host_starts,
        phase.parent_host_finishes,
        phase.parent_wait_starts,
        phase.parent_wait_finishes,
        ready_epoch
    );
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
fn finish_verify_response(epoch: u64, status: u32, ready_epoch: u64) {
    #[cfg(not(any(
        feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
    )))]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY RESPONSE epoch={} status={} finish=1 verify=1 cursor=0 discard=stream_abandoned emitted=0 stored=1 ack=1 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY RESPONSE epoch={} status={} finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY RESPONSE epoch={} status={} finish=1 verify=1 bundle=trusted collector=consumed ack=0 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
    #[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY RESPONSE epoch={} status={} finish=1 verify=1 stream=complete ack=0 ready_epoch={}",
        epoch,
        status,
        ready_epoch
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-finish-verify-qemu-acceptance")]
fn finish_verify_drop(epoch: u64, ready_epoch: u64) {
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY DROP epoch={} cancel=lease_cancelled finish=0 verify=0 stream=0 emitted=0 stored=1 ack=1 ready_epoch={}",
        epoch,
        ready_epoch
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
fn verified_stream_response(epoch: u64, evidence: VerifiedStreamEvidence) {
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM RESPONSE epoch={} status=0 finish=1 verify=1 summary=1 initial_cursor=0 total_ticks={} interval_capacity=65536 interval_count={} intervals_complete=1 emitted={} cursor={} sequence=exact contiguous=1 nonempty=1 adjacent_distinct=1 phase_sum=total_ticks phase_rescan=summary final_end=total_ticks stream=complete stored=0 ack=0 ready_epoch={}",
        epoch,
        evidence.total_ticks,
        evidence.interval_count,
        evidence.interval_count,
        evidence.interval_count,
        evidence.ready_epoch
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-verified-stream-qemu-acceptance")]
fn verified_stream_drop(epoch: u64, ready_epoch: u64) {
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM DROP epoch={} cancel=lease_cancelled finish=0 verify=0 summary=0 stream=0 emitted=0 stored=1 ack=1 ready_epoch={}",
        epoch,
        ready_epoch
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance")]
fn trusted_sample_response(epoch: u64, evidence: TrustedSampleEvidence) -> Result<(), ()> {
    use vibeos_wasm_aot_profile::{
        FORMAL_READ_CHUNKS, FORMAL_STDOUT_BYTES, FORMAL_STDOUT_SHA256, FORMAL_WRITE_CHUNKS,
    };

    let observation = evidence.acceptance;
    let exact = observation.epoch == epoch
        && observation.terminal == vibeos_vsh::ComponentTerminal::Success
        && observation.status == 0
        && !observation.timed_out
        && observation.read_chunks == FORMAL_READ_CHUNKS
        && observation.write_chunks == FORMAL_WRITE_CHUNKS
        && observation.stdout_bytes == FORMAL_STDOUT_BYTES
        && observation.stdout_digest == FORMAL_STDOUT_SHA256
        && observation.fuel_consumed != 0
        && observation.fuel_consumed <= vibeos_wasm_aot_profile::MAX_FORMAL_FUEL
        && observation.poll_quanta != 0
        && observation.poll_quanta != u64::MAX
        && observation.poll_exact
        && observation.logical_live_after == 0
        && observation.full_drain;
    if !exact {
        profile_request_failure("trusted-sample-observation", Some(epoch));
        return Err(());
    }
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE RESPONSE epoch={} status=0 exact_success=1 full_drain=1 read_chunks={} write_chunks={} stdout_bytes={} stdout_sha256=791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27 fuel_consumed={} poll_quanta={} poll_exact=1 logical_live_after=0 timed_out=0 bundle=trusted finish=1 verify=1 discard=trusted_sample_abandoned emitted=0 stored=1 ack=1 ready_epoch={}",
        epoch,
        observation.read_chunks,
        observation.write_chunks,
        observation.stdout_bytes,
        observation.fuel_consumed,
        observation.poll_quanta,
        evidence.ready_epoch
    );
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance")]
fn collector_trusted_sample_response(
    epoch: u64,
    evidence: &TrustedSampleEvidence,
) -> Result<(), ()> {
    use vibeos_wasm_aot_profile::{
        FORMAL_READ_CHUNKS, FORMAL_STDOUT_BYTES, FORMAL_STDOUT_SHA256, FORMAL_WRITE_CHUNKS,
    };

    let observation = evidence.acceptance;
    let exact = observation.epoch == epoch
        && observation.terminal == vibeos_vsh::ComponentTerminal::Success
        && observation.status == 0
        && !observation.timed_out
        && observation.read_chunks == FORMAL_READ_CHUNKS
        && observation.write_chunks == FORMAL_WRITE_CHUNKS
        && observation.stdout_bytes == FORMAL_STDOUT_BYTES
        && observation.stdout_digest == FORMAL_STDOUT_SHA256
        && observation.fuel_consumed != 0
        && observation.fuel_consumed <= vibeos_wasm_aot_profile::MAX_FORMAL_FUEL
        && observation.poll_quanta != 0
        && observation.poll_quanta != u64::MAX
        && observation.poll_exact
        && observation.logical_live_after == 0
        && observation.full_drain;
    if !exact {
        profile_request_failure("trusted-sample-observation", Some(epoch));
        return Err(());
    }
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE RESPONSE epoch={} status=0 exact_success=1 full_drain=1 read_chunks={} write_chunks={} stdout_bytes={} stdout_sha256=791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27 fuel_consumed={} poll_quanta={} poll_exact=1 logical_live_after=0 timed_out=0 bundle=trusted finish=1 verify=1 collector=consumed ack=0 ready_epoch={}",
        epoch,
        observation.read_chunks,
        observation.write_chunks,
        observation.stdout_bytes,
        observation.fuel_consumed,
        observation.poll_quanta,
        evidence.ready_epoch
    );
    Ok(())
}

#[cfg(any(
    feature = "wasm-c84-ssh-managed-child-trusted-sample-qemu-acceptance",
    feature = "wasm-c84-ssh-managed-child-single-boot-collector-qemu-acceptance"
))]
fn trusted_sample_drop(epoch: u64, ready_epoch: u64) {
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE DROP epoch={} cancel=lease_cancelled bundle=0 finish=0 verify=0 discard=0 emitted=0 stored=1 ack=1 ready_epoch={}",
        epoch,
        ready_epoch
    );
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
fn profile_phase_drop(
    epoch: u64,
    ready_epoch: u64,
    expected_faults: crate::wasm_aot_profile_slot::SlotFaults,
    phase: Result<
        crate::wasm_aot_profile_slot::ManagedPhaseObservation,
        crate::wasm_aot_profile_slot::ProfileError,
    >,
    child: Result<(u64, crate::exec::TaskDetachReason), crate::wasm_aot_profile_slot::ProfileError>,
) -> Result<(), ()> {
    use crate::exec::TaskDetachReason;
    use vibeos_wasm_aot_profile::Phase;

    let (phase, (core_pairs, detach)) = match (phase, child) {
        (Ok(phase), Ok(child)) => (phase, child),
        _ => {
            profile_request_failure("phase-drop-observation", Some(epoch));
            return Err(());
        }
    };
    let parent_open = u64::from(phase.parent_wait_open);
    let cleanup_exact = match phase.cleanup_count {
        0 => !phase.cleanup_latched && phase.child_base != Phase::Cleanup,
        1 => phase.cleanup_latched && phase.child_base == Phase::Cleanup,
        _ => false,
    };
    let exact = phase.parent_host_starts > 0
        && phase.parent_host_starts == phase.parent_host_finishes
        && phase.parent_wait_starts > 0
        && phase.parent_wait_starts == phase.parent_wait_finishes.saturating_add(parent_open)
        && phase.child_host_starts == phase.child_host_finishes
        && phase.child_wait_starts > 0
        && phase.child_wait_starts == phase.child_wait_finishes.saturating_add(1)
        && phase.child_wait_open
        && !phase.child_host_open
        && cleanup_exact
        && !phase.child_phase_fault
        && !phase.parent_phase_fault
        && !phase.child_attached
        && phase.child_detach == Some(TaskDetachReason::Exited)
        && phase.slot_faults == expected_faults
        && detach == TaskDetachReason::Exited
        && core_pairs > 0;
    if !exact {
        profile_request_failure("phase-drop-state", Some(epoch));
        return Err(());
    }
    crate::println!(
        "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR DROP epoch={} release=0 detach=exited clean=0 child_faults=abandoned+detached child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} child_wait_open_at_cancel=1 parent_wait_open_at_cancel={} late=0 cancel=1 ack=1 ready_epoch={}",
        epoch,
        core_pairs,
        core_pairs,
        phase.child_host_starts,
        phase.child_host_finishes,
        phase.child_wait_starts,
        phase.child_wait_finishes,
        phase.cleanup_count,
        phase.parent_host_starts,
        phase.parent_host_finishes,
        phase.parent_wait_starts,
        phase.parent_wait_finishes,
        parent_open,
        ready_epoch
    );
    Ok(())
}

#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
impl SshdPlatform for SshPlatform {
    fn packet_endpoints(
        &self,
        outbound: Cap,
        inbound: Cap,
    ) -> Option<(
        vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
        vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
    )> {
        let cspace = self.space.0.lock();
        let outbound = cspace
            .lookup_revocable::<Endpoint<StampedPacket>>(outbound, Rights::SEND)
            .ok()?;
        let inbound = cspace
            .lookup_revocable::<Endpoint<StampedPacket>>(inbound, Rights::RECV)
            .ok()?;
        Some((outbound, inbound))
    }

    fn bind_stack(&self, control: Cap) -> Result<vibeos_core::net::PacketStamp, NetworkBindError> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<crate::net_device::NetDevice>(control, Rights::INVOKE)
            .map_err(|_| NetworkBindError::Denied)?;
        crate::net_device::bind_stack_with(&lease).map_err(|error| match error {
            crate::net_device::NetError::Offline => NetworkBindError::Offline,
            crate::net_device::NetError::SessionBusy => NetworkBindError::SessionBusy,
            crate::net_device::NetError::AuthorityRevoked
            | crate::net_device::NetError::PermissionDenied => NetworkBindError::Denied,
            _ => NetworkBindError::Failed,
        })
    }

    fn network_info(&self, control: Cap) -> Option<NetworkInfo> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<crate::net_device::NetDevice>(control, Rights::READ)
            .ok()?;
        let info = crate::net_device::info_with(&lease).ok()?;
        let phy_link_up = crate::net_device::carrier_up(&info);
        Some(NetworkInfo {
            online: info.online,
            quarantined: info.quarantined,
            session_epoch: info.session_epoch,
            phy_link_up,
        })
    }

    fn tcp_listener_snapshot(&self, listener: Cap) -> Option<TcpListenerSnapshot> {
        let listener = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::READ)
            .ok()?;
        listener.try_with(TcpListener::snapshot).ok()
    }

    fn tcp_accept(&self, listener: Cap) -> Result<Option<TcpConnectionToken>, ()> {
        let listener = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::RECV)
            .map_err(|_| ())?;
        listener.try_with(TcpListener::try_accept).map_err(|_| ())
    }

    fn tcp_recv(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        output: &mut [u8],
    ) -> Result<TcpIoResult, ()> {
        let listener = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::READ)
            .map_err(|_| ())?;
        listener
            .try_with(|listener| listener.try_recv(connection, output))
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    fn tcp_send(
        &self,
        listener: Cap,
        connection: TcpConnectionToken,
        input: &[u8],
    ) -> Result<TcpIoResult, ()> {
        let listener = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::WRITE)
            .map_err(|_| ())?;
        listener
            .try_with(|listener| listener.try_send(connection, input))
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    fn tcp_close(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), ()> {
        let listener = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::INVOKE)
            .map_err(|_| ())?;
        listener
            .try_with(|listener| listener.request_close(connection))
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    fn tcp_reset(&self, listener: Cap, connection: TcpConnectionToken) -> Result<(), ()> {
        let listener = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::INVOKE)
            .map_err(|_| ())?;
        listener
            .try_with(|listener| listener.request_reset(connection))
            .map_err(|_| ())?
            .map_err(|_| ())
    }

    fn network_ipv4_status(&self, listener: Cap) -> Option<Ipv4RuntimeStatus> {
        let listener_authority = self
            .space
            .0
            .lock()
            .lookup_revocable::<TcpListener>(listener, Rights::READ)
            .ok()?;
        let listener_id = listener_authority.try_with(TcpListener::id).ok()?.get();
        vibeos_netstack::config::runtime_status_for_listener(listener_id)
    }

    fn entropy<'a>(
        &'a self,
        random: Cap,
        length: usize,
    ) -> PlatformFuture<'a, Result<SecretBytes, ()>> {
        Box::pin(async move {
            for _ in 0..ENTROPY_RETRY_BUDGET {
                let lease = self
                    .space
                    .0
                    .lock()
                    .lookup_lease::<ssh_rng::RandomSource>(random, Rights::READ)
                    .map_err(|_| ())?;
                match ssh_rng::bytes_with(lease, length).await {
                    Ok(bytes) => return SecretBytes::try_from_slice(bytes.as_slice()),
                    Err(
                        RandomError::Offline | RandomError::Busy | RandomError::DriverRestarted,
                    ) => {
                        crate::exec::sleep_ms(1).await;
                    }
                    Err(_) => return Err(()),
                }
            }
            Err(())
        })
    }

    fn host_public_key(&self, read: Cap) -> Result<HostPublicKeySnapshot, ()> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<HostSigningService>(read, Rights::READ)
            .map_err(|_| ())?;
        let snapshot = crate::ssh_security::public_key_with(&lease).map_err(|_| ())?;
        Ok(HostPublicKeySnapshot {
            generation: snapshot.generation.get(),
            public_key: snapshot.public_key,
        })
    }

    fn sign_exchange_hash(
        &self,
        invoke: Cap,
        exchange_hash: &[u8; 32],
    ) -> Result<HostSignatureResult, ()> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<HostSigningService>(invoke, Rights::INVOKE)
            .map_err(|_| ())?;
        let signed = crate::ssh_security::sign_with(&lease, exchange_hash).map_err(|_| ())?;
        Ok(HostSignatureResult {
            generation: signed.generation.get(),
            signature: signed.signature.to_bytes(),
        })
    }

    fn authorized_profile(
        &self,
        policy: Cap,
        key: &SshEd25519PublicKey,
    ) -> Result<Option<AuthorizedProfile>, ()> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<AuthorizedKeyPolicyService>(policy, Rights::READ)
            .map_err(|_| ())?;
        let profile = crate::ssh_security::profile_for_with(&lease, key).map_err(|_| ())?;
        Ok(profile
            .filter(|profile| {
                #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
                {
                    profile.profile.get()
                        == vibeos_kernel_acceptance::ssh_test_fixture::TEST_PROFILE
                }
                #[cfg(feature = "milkv-ssh")]
                {
                    profile.profile.get() == crate::ssh_provisioning::PROFILE
                }
            })
            .map(|profile| AuthorizedProfile {
                generation: profile.generation.get(),
                profile: profile.profile,
            }))
    }

    fn onboarding_password_profile(
        &self,
        username: &str,
        password: &str,
    ) -> Option<AuthorizedProfile> {
        #[cfg(feature = "milkv-ssh")]
        {
            crate::ssh_provisioning::onboarding_password_profile(username, password)
        }
        #[cfg(not(feature = "milkv-ssh"))]
        {
            let _ = (username, password);
            None
        }
    }

    fn onboarding_profile(&self) -> Option<AuthorizedProfile> {
        #[cfg(feature = "milkv-ssh")]
        {
            crate::ssh_provisioning::onboarding_profile()
        }
        #[cfg(not(feature = "milkv-ssh"))]
        {
            None
        }
    }

    fn security_policy_changed(&self) -> bool {
        #[cfg(feature = "milkv-ssh")]
        {
            crate::ssh_provisioning::policy_changed()
        }
        #[cfg(not(feature = "milkv-ssh"))]
        {
            false
        }
    }

    fn install_vsh_commands(&self, session: &mut vibeos_vsh::Session, onboarding: bool) {
        if onboarding {
            #[cfg(feature = "milkv-ssh")]
            crate::vsh_platform::install_ssh_onboarding_commands(session);
        } else {
            crate::vsh_platform::install_remote_commands(session);
        }
    }

    fn install_ssh_exec_component_commands(
        &self,
        session: &mut vibeos_vsh::Session,
        policy: SshExecComponentSessionPolicy,
        io: vibeos_vsh::SshExecComponentIoInstall,
    ) -> Result<(), vibeos_vsh::Diagnostic> {
        crate::component_instances::install_ssh_exec_component(session, policy, io)
    }

    fn ssh_exec_component_policy(
        &self,
        profile: AuthorizedProfile,
    ) -> Option<SshExecComponentSessionPolicy> {
        crate::component_instances::ssh_exec_policy(profile)
    }

    fn select_ssh_exec_component_policy(
        &self,
        profile: AuthorizedProfile,
        source: &str,
    ) -> Option<SshExecComponentSessionPolicy> {
        crate::component_instances::select_ssh_exec_component_policy(profile, source)
    }

    #[cfg(feature = "wasm-c84-ssh-request-parent")]
    fn prepare_ssh_exec_profile(
        &self,
        target: SshExecProfileTarget<'_>,
    ) -> Result<Option<SshExecProfilePermit>, SshExecProfilePrepareError> {
        let source = target.source();
        if source != "case-filter" {
            return Ok(None);
        }

        let accepted = target.policy();
        let Some(current) = crate::component_instances::select_ssh_exec_component_policy(
            accepted.profile(),
            source,
        ) else {
            profile_request_failure("policy-missing", None);
            return Err(SshExecProfilePrepareError::Failed);
        };
        if accepted.command_name() != "case-filter"
            || current.profile() != accepted.profile()
            || current.command_name() != accepted.command_name()
            || current.incarnation() != accepted.incarnation()
            || current.artifact_sha256() != accepted.artifact_sha256()
        {
            profile_request_failure("policy-mismatch", None);
            return Err(SshExecProfilePrepareError::Failed);
        }

        let permit = match crate::wasm_aot_profile_slot::prepare_current() {
            Ok(permit) => permit,
            #[cfg(feature = "wasm-c84-ssh-managed-child-single-boot-collector")]
            Err(error) if crate::wasm_aot_profile_slot::collector_terminal_reject(error) => {
                return Err(SshExecProfilePrepareError::Reject);
            }
            Err(_) => {
                profile_request_failure("prepare", None);
                return Err(SshExecProfilePrepareError::Failed);
            }
        };
        Ok(Some(SshExecProfilePermit::new(
            SshExecProfileOwner::reserved(accepted, permit),
        )))
    }

    #[cfg(any(
        feature = "ssh-native-async-qemu-acceptance",
        feature = "ssh-native-async-revoke-qemu-acceptance"
    ))]
    fn ssh_exec_component_completed(&self, policy: SshExecComponentSessionPolicy, status: u32) {
        #[cfg(feature = "ssh-native-async-qemu-acceptance")]
        crate::component_instances::ssh_exec_component_completed(policy, status);
        #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
        crate::component_instances::ssh_exec_component_revoke_completed(policy, status);
    }

    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    fn ssh_exec_component_stdout_drain_permitted(
        &self,
        policy: SshExecComponentSessionPolicy,
    ) -> bool {
        crate::component_instances::ssh_exec_component_stdout_drain_permitted(policy)
    }

    #[cfg(feature = "ssh-native-async-revoke-qemu-acceptance")]
    fn ssh_exec_component_stdin_chunk_limit(
        &self,
        policy: SshExecComponentSessionPolicy,
        accepted_bytes: usize,
    ) -> Result<usize, &'static str> {
        crate::component_instances::ssh_exec_component_stdin_chunk_limit(policy, accepted_bytes)
    }

    #[cfg(feature = "milkv-jitterentropy-ssh-probe")]
    fn accepts_streaming_exec(&self, command: &str) -> bool {
        crate::jitterentropy_probe::accepts_ssh_stream(command)
    }

    #[cfg(feature = "milkv-jitterentropy-ssh-probe")]
    fn open_streaming_exec(
        &self,
        command: &str,
    ) -> Option<Result<vibeos_sshd::StreamingExecBox, u32>> {
        crate::jitterentropy_probe::open_ssh_stream(command)
    }

    fn log(&self, args: fmt::Arguments<'_>) {
        crate::uart::_print(format_args!("{args}\n"));
    }
}

#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
pub async fn capability_task(
    space: &'static Space,
    listener: Cap,
    random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
) {
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if !crate::component_instances::run_qemu_acceptance().await {
        crate::sbi::shutdown(true);
    }

    let platform = SshPlatform::new(space);
    #[cfg(feature = "milkv-ssh-acceptance")]
    crate::uart::_print(format_args!(
        "WARNING milkv-ssh-acceptance: deterministic entropy and fixed test keys; isolated bring-up only\n"
    ));
    #[cfg(feature = "milkv-jitterentropy-ssh-probe")]
    crate::uart::_print(format_args!(
        "WARNING milkv-jitterentropy-ssh-probe: fixed SSH fixtures; raw deltas are qualification evidence only\n"
    ));
    vibeos_sshd::capability_task(
        &platform,
        ssh_service_policy(),
        listener,
        random,
        signer_read,
        signer_invoke,
        policy,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
#[cfg(any(
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
pub async fn task(
    space: &'static Space,
    outbound: Cap,
    inbound: Cap,
    control: Cap,
    random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
) {
    let platform = SshPlatform::new(space);
    #[cfg(feature = "milkv-ssh-acceptance")]
    crate::uart::_print(format_args!(
        "WARNING milkv-ssh-acceptance: deterministic entropy and fixed test keys; isolated bring-up only\n"
    ));
    #[cfg(feature = "milkv-jitterentropy-ssh-probe")]
    crate::uart::_print(format_args!(
        "WARNING milkv-jitterentropy-ssh-probe: fixed SSH fixtures; raw deltas are qualification evidence only\n"
    ));
    vibeos_sshd::task(
        &platform,
        ssh_service_policy(),
        outbound,
        inbound,
        control,
        random,
        signer_read,
        signer_invoke,
        policy,
    )
    .await;
}

#[cfg(feature = "milkv-ssh")]
pub async fn provisioned_task(space: &'static Space, listener: Cap, random: Cap) {
    let mut provisioning_failure_reported = false;
    loop {
        match crate::ssh_provisioning::ensure_host_key().await {
            Ok(config) => {
                provisioning_failure_reported = false;
                if config.complete() {
                    crate::uart::_print(format_args!("SSH public-key authentication active\n"));
                } else {
                    crate::uart::_print(format_args!(
                        "SSH first login: user vibe, password vibeos; authorize an Ed25519 key immediately\n"
                    ));
                }
                match crate::ssh_provisioning::install_services(space, config) {
                    Ok((read, invoke, policy)) => {
                        crate::uart::_print(format_args!(
                            "SSH host identity verified; starting DHCP SSH on port 22\n"
                        ));
                        capability_task(space, listener, random, read, invoke, policy).await;
                    }
                    Err(()) => crate::uart::_print(format_args!(
                        "SSH configuration invalid; refusing to listen\n"
                    )),
                }
            }
            Err(error) => {
                if !provisioning_failure_reported {
                    crate::uart::_print(format_args!(
                        "SSH provisioning unavailable ({error:?}); retrying\n"
                    ));
                    provisioning_failure_reported = true;
                }
            }
        }
        crate::exec::sleep_ms(1000).await;
    }
}

#[cfg(feature = "ssh-security-test")]
struct SecurityPlatform {
    space: &'static Space,
    random: Cap,
}

#[cfg(feature = "ssh-security-test")]
impl SecurityPlatform {
    const fn new(space: &'static Space, random: Cap) -> Self {
        Self { space, random }
    }
}

#[cfg(feature = "ssh-security-test")]
impl SecurityTestPlatform for SecurityPlatform {
    fn entropy<'a>(
        &'a self,
        length: usize,
    ) -> SecurityPlatformFuture<'a, Result<SecuritySecretBytes, ()>> {
        Box::pin(async move {
            for _ in 0..ENTROPY_RETRY_BUDGET {
                let lease = self
                    .space
                    .0
                    .lock()
                    .lookup_lease::<ssh_rng::RandomSource>(self.random, Rights::READ)
                    .map_err(|_| ())?;
                match ssh_rng::bytes_with(lease, length).await {
                    Ok(bytes) => return SecuritySecretBytes::try_from_slice(bytes.as_slice()),
                    Err(
                        RandomError::Offline | RandomError::Busy | RandomError::DriverRestarted,
                    ) => crate::exec::sleep_ms(1).await,
                    Err(_) => return Err(()),
                }
            }
            Err(())
        })
    }

    fn log(&self, args: core::fmt::Arguments<'_>) {
        crate::uart::_print(format_args!("{args}\n"));
    }
}

#[cfg(feature = "ssh-security-test")]
pub async fn security_test_task(
    space: &'static Space,
    random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
) {
    let platform = SecurityPlatform::new(space, random);
    let passed = vibeos_kernel_acceptance::ssh_security_test::run_and_report(
        &platform,
        space.0.as_ref(),
        signer_read,
        signer_invoke,
        policy,
    )
    .await;
    crate::sbi::shutdown(!passed)
}
