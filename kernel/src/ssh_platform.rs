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
    SshExecProfilePermit, SshExecProfilePermitBackend, SshExecProfileRunBackend,
    SshExecProfileTarget,
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
/// same box between its public typestates. Every terminal path is deliberately
/// diagnostic-only: Active can only cancel the sample, validate the exact
/// rejection, and acknowledge it once. There is no finish or stream method in
/// this adapter.
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

    fn response_boundary(&mut self, status: u32) -> Result<(), ()> {
        let previous = core::mem::replace(&mut self.state, SshExecProfileOwnerState::Closed);
        let SshExecProfileOwnerState::Active(run) = previous else {
            self.state = previous;
            profile_request_failure("response-state", None);
            return Err(());
        };
        let epoch = run.token().epoch();
        #[cfg(feature = "wasm-c84-ssh-managed-child-core")]
        let child_ready = crate::wasm_aot_profile_slot::managed_child_response_ready(epoch).is_ok();
        #[cfg(not(feature = "wasm-c84-ssh-managed-child-core"))]
        let child_ready = true;
        #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
        let child_observation =
            crate::wasm_aot_profile_slot::take_managed_child_response_observation(epoch);
        match cancel_and_ack_profile(run, crate::wasm_aot_profile_slot::SlotFaults::default()) {
            Ok(ready_epoch) if child_ready && profile_policy_is_current(self.policy) => {
                #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
                match child_observation {
                    Ok(observation) => crate::println!(
                        "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 cancel=1 ack=1 ready_epoch={}",
                        epoch,
                        status,
                        observation.core_polls,
                        observation.core_pairs,
                        observation.typed_polls,
                        ready_epoch
                    ),
                    Err(_) => {
                        profile_request_failure("managed-child-response-trace", Some(epoch));
                        return Err(());
                    }
                }
                profile_request_response(epoch, status, ready_epoch);
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
                match cancel_and_ack_profile(run, expected_faults) {
                    Ok(ready_epoch) if expectation_exact => {
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
                        profile_request_drop(epoch, ready_epoch)
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
    fn response_boundary(&mut self, status: u32) -> Result<(), ()> {
        SshExecProfileOwner::response_boundary(self, status)
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
    #[cfg(feature = "wasm-c84-ssh-request-parent-qemu-acceptance")]
    crate::println!(
        "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} cancel=1 ack=1 ready_epoch={}",
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
    ) -> Result<Option<SshExecProfilePermit>, ()> {
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
            return Err(());
        };
        if accepted.command_name() != "case-filter"
            || current.profile() != accepted.profile()
            || current.command_name() != accepted.command_name()
            || current.incarnation() != accepted.incarnation()
            || current.artifact_sha256() != accepted.artifact_sha256()
        {
            profile_request_failure("policy-mismatch", None);
            return Err(());
        }

        let permit = crate::wasm_aot_profile_slot::prepare_current().map_err(|_| {
            profile_request_failure("prepare", None);
        })?;
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
