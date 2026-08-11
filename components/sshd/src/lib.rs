//! Capability-confined SSH server component: one connection at a time.
//!
//! The transport owns no ambient authority. Packet I/O, entropy, host-key
//! signing, and authorization are all reached through separately attenuated
//! capabilities. Each accepted TCP connection gets fresh caller-provided
//! randomness and at most one authenticated session channel and one accepted
//! start request: either bounded `exec` or an isolated PTY-backed VSH shell.
//!
//! Image-specific addressing, carrier, and retry choices are supplied through
//! [`SshServicePolicy`]. Entropy and identity provisioning remain kernel-image
//! responsibilities behind explicit capabilities.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use sunset::{
    ChanData, ChanFail, ChanHandle, Ed25519HostSigner, Event, PubKey, Runner, ServEvent, Server,
    TerminalSize,
};
use vibeos_core::cap::{CSpace, Cap, Revocable};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{PacketStamp, StampedPacket};
use vibeos_core::sync::SpinLock;
pub use vibeos_net_protocol::StaticIpv4Address;
use vibeos_net_protocol::{
    Ipv4RuntimeStatus, StaticIpv4Config, StaticIpv4TcpStack, TcpIoResult, TcpStreamState,
};
use vibeos_random::{ChaCha20Random, EntropySource, RandomDomain, RandomLimits, SEED_BYTES};
use vibeos_ssh_identity::{CapabilityProfileId, SshEd25519PublicKey};
use vibeos_vsh::terminal::{
    FrontendError, TerminalEvent, TerminalFrontend, MAX_EMIT_TEXT_BYTES,
    MAX_INPUT_BYTES as MAX_TERMINAL_INPUT_BYTES,
};

/// Boxed kernel-service operation used at the narrow component/platform seam.
pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(feature = "qualification-stream")]
pub trait StreamingExec: Send {
    /// Produce one bounded stdout chunk, or `None` with the SSH exit status.
    /// A producer may return `Pending` to let the SSH transport and TCP stack
    /// make progress between hardware acquisition steps.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Option<Vec<u8>>, u32>>;
}

#[cfg(feature = "qualification-stream")]
pub type StreamingExecBox = Pin<Box<dyn StreamingExec>>;

/// Platform-neutral status needed to supervise one TCP stack binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkInfo {
    pub online: bool,
    pub quarantined: bool,
    pub session_epoch: u64,
    pub phy_link_up: bool,
}

/// Stable error classes exposed by the network control capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBindError {
    Offline,
    SessionBusy,
    Denied,
    Failed,
}

/// How the SSH image obtains its service address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4Policy {
    Static(StaticIpv4Address),
    Dhcp { bootstrap: StaticIpv4Address },
}

impl Ipv4Policy {
    const fn initial_address(self) -> StaticIpv4Address {
        match self {
            Self::Static(address) => address,
            Self::Dhcp { bootstrap } => bootstrap,
        }
    }
}

/// Limit applied while waiting to bind the packet service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindRetry {
    Attempts(usize),
    Forever,
}

/// Image-selected network policy for one SSH service instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshServicePolicy {
    pub ethernet_address: [u8; 6],
    pub listen_port: u16,
    pub ipv4: Ipv4Policy,
    pub require_carrier: bool,
    pub bind_retry: BindRetry,
    pub status_interval_ms: u64,
    pub listener_label: &'static str,
}

/// Public half of one provisioned host-signing service incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPublicKeySnapshot {
    pub generation: u64,
    pub public_key: SshEd25519PublicKey,
}

/// Result of invoking the opaque host signer for one exchange hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSignatureResult {
    pub generation: u64,
    pub signature: [u8; 64],
}

/// Authorization decision retained and revalidated across SSH state changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizedProfile {
    pub generation: u64,
    pub profile: CapabilityProfileId,
}

/// Owned entropy which is scrubbed before its component allocation is freed.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ()> {
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| ())?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// All privileged services consumed by the SSH component.
///
/// The implementation lives in the kernel image and resolves each operation
/// through the exact capability supplied to this component. Protocol and
/// session code cannot name a device, key, policy, or console directly.
pub trait Platform: Sync {
    fn packet_endpoints(
        &self,
        outbound: Cap,
        inbound: Cap,
    ) -> Option<(
        Revocable<Endpoint<StampedPacket>>,
        Revocable<Endpoint<StampedPacket>>,
    )>;
    fn bind_stack(&self, control: Cap) -> Result<PacketStamp, NetworkBindError>;
    fn network_info(&self, control: Cap) -> Option<NetworkInfo>;
    fn entropy<'a>(
        &'a self,
        random: Cap,
        length: usize,
    ) -> PlatformFuture<'a, Result<SecretBytes, ()>>;
    fn host_public_key(&self, read: Cap) -> Result<HostPublicKeySnapshot, ()>;
    fn sign_exchange_hash(
        &self,
        invoke: Cap,
        exchange_hash: &[u8; 32],
    ) -> Result<HostSignatureResult, ()>;
    fn authorized_profile(
        &self,
        policy: Cap,
        key: &SshEd25519PublicKey,
    ) -> Result<Option<AuthorizedProfile>, ()>;
    fn onboarding_password_profile(
        &self,
        _username: &str,
        _password: &str,
    ) -> Option<AuthorizedProfile> {
        None
    }
    fn onboarding_profile(&self) -> Option<AuthorizedProfile> {
        None
    }
    fn security_policy_changed(&self) -> bool {
        false
    }
    fn install_vsh_commands(&self, session: &mut vibeos_vsh::Session, onboarding: bool);
    #[cfg(feature = "qualification-stream")]
    fn accepts_streaming_exec(&self, _command: &str) -> bool {
        false
    }
    #[cfg(feature = "qualification-stream")]
    fn open_streaming_exec(&self, _command: &str) -> Option<Result<StreamingExecBox, u32>> {
        None
    }
    fn log(&self, args: fmt::Arguments<'_>);
}

type Space = dyn Platform;

macro_rules! component_log {
    ($platform:expr, $($arg:tt)*) => {
        $platform.log(format_args!($($arg)*))
    };
}

const SSH_RANDOM_DOMAIN: u64 = 0x5353_4803;

const CONNECTION_TIMEOUT_MS: u64 = 60_000;
const EXEC_TIMEOUT_MS: u64 = 10_000;
const CANCEL_GRACE_MS: u64 = 1_000;
const CLOSE_TIMEOUT_MS: u64 = 5_000;
const IDLE_POLL_CEILING_MS: u64 = 10;
const MAX_SSH_PROGRESS_PER_TURN: usize = 32;
const MAX_WIRE_IO_PER_TURN: usize = 8;
const MAX_CHANNEL_DISCARDS_PER_TURN: usize = 4;
#[cfg(not(feature = "qualification-stream"))]
const MAX_WIRE_BYTES_PER_DIRECTION: usize = 512 * 1024;
#[cfg(feature = "qualification-stream")]
const MAX_WIRE_BYTES_PER_DIRECTION: usize = 64 * 1024 * 1024;
const MAX_EXEC_OUTPUT_BYTES: usize = 64 * 1024;
const WIRE_CHUNK_BYTES: usize = 1_024;
const SHELL_PROMPT: &str = "vsh> ";
const SHELL_OUTPUT_LIMIT_DIAGNOSTIC: &str = "  vsh: command output exceeded SSH shell limit\n";
const SHELL_INPUT_CHUNK_BYTES: usize = 64;
const MAX_SHELL_INPUT_ACTIONS_PER_TURN: usize = 64;

struct OneSeed(Option<[u8; SEED_BYTES]>);

impl EntropySource for OneSeed {
    type Error = ();

    fn try_fill_seed(&mut self, seed: &mut [u8; SEED_BYTES]) -> Result<(), Self::Error> {
        let mut next = self.0.take().ok_or(())?;
        seed.copy_from_slice(&next);
        wipe(&mut next);
        Ok(())
    }
}

struct SunsetRandom {
    inner: ChaCha20Random<OneSeed>,
}

impl sunset::RandomSource for SunsetRandom {
    fn fill_random(&mut self, output: &mut [u8]) -> sunset::Result<()> {
        self.inner
            .try_fill_bytes(output)
            .map_err(|_| sunset::Error::Random)
    }
}

/// Sunset-facing signer which never owns or observes the host private key.
///
/// The public-key capability establishes the connection generation. Every
/// signing invocation is checked against that same generation, so replacing
/// only one half of the authority fails the key exchange closed.
struct CapabilityHostSigner<'a> {
    space: &'a Space,
    read: Cap,
    invoke: Cap,
    generation: Cell<Option<u64>>,
}

impl<'a> CapabilityHostSigner<'a> {
    fn new(space: &'a Space, read: Cap, invoke: Cap) -> Self {
        Self {
            space,
            read,
            invoke,
            generation: Cell::new(None),
        }
    }

    fn snapshot(&self) -> Result<HostPublicKeySnapshot, &'static str> {
        let snapshot = self
            .space
            .host_public_key(self.read)
            .map_err(|_| "host public-key authority was revoked")?;
        match self.generation.get() {
            Some(generation) if generation != snapshot.generation => {
                Err("host signer generation changed")
            }
            Some(_) => Ok(snapshot),
            None => {
                self.generation.set(Some(snapshot.generation));
                Ok(snapshot)
            }
        }
    }
}

impl Ed25519HostSigner for CapabilityHostSigner<'_> {
    fn public_key(&self) -> sunset::Result<[u8; 32]> {
        self.snapshot()
            .map(|snapshot| snapshot.public_key.to_bytes())
            .map_err(|_| sunset::Error::BadKey)
    }

    fn sign_exchange_hash(&mut self, exchange_hash: &[u8; 32]) -> sunset::Result<[u8; 64]> {
        let public = self.snapshot().map_err(|_| sunset::Error::BadSig)?;
        let signed = self
            .space
            .sign_exchange_hash(self.invoke, exchange_hash)
            .map_err(|_| sunset::Error::BadSig)?;
        if signed.generation != public.generation {
            return Err(sunset::Error::BadSig);
        }
        Ok(signed.signature)
    }
}

#[derive(Clone, Copy)]
enum AuthCredential {
    PublicKey(SshEd25519PublicKey),
    OnboardingPassword,
}

#[derive(Clone, Copy)]
struct AuthCandidate {
    credential: AuthCredential,
    profile: AuthorizedProfile,
}

#[derive(Default)]
struct ProtocolState {
    candidate: Option<AuthCandidate>,
    committed: Option<AuthCandidate>,
    authenticated: bool,
    channel: Option<ChanHandle>,
    channel_seen: bool,
    pty: Option<TerminalSize>,
    start_seen: bool,
}

enum ProtocolSignal {
    Idle,
    Progressed,
    Exec(String),
    Shell,
    Interrupt,
    Defunct,
}

enum SessionStart {
    Exec(String),
    Shell,
}

struct PendingInput {
    bytes: VecDeque<u8>,
    signal_interrupt: bool,
}

impl PendingInput {
    fn new() -> Result<Self, &'static str> {
        let mut bytes = VecDeque::new();
        bytes
            .try_reserve_exact(MAX_TERMINAL_INPUT_BYTES)
            .map_err(|_| "SSH shell input allocation failed")?;
        Ok(Self {
            bytes,
            signal_interrupt: false,
        })
    }

    fn remaining_capacity(&self) -> usize {
        MAX_TERMINAL_INPUT_BYTES - self.bytes.len()
    }
}

#[derive(Clone, Copy)]
struct WireTurn {
    ended: bool,
    worked: bool,
    next_poll_delay_ms: Option<u64>,
}

struct WireBridge {
    inbound: [u8; WIRE_CHUNK_BYTES],
    inbound_start: usize,
    inbound_end: usize,
    input_closed: bool,
    received: usize,
    sent: usize,
}

impl WireBridge {
    fn new() -> Self {
        Self {
            inbound: [0; WIRE_CHUNK_BYTES],
            inbound_start: 0,
            inbound_end: 0,
            input_closed: false,
            received: 0,
            sent: 0,
        }
    }

    fn drive(
        &mut self,
        runner: &mut Runner<'_, Server>,
        stack: &mut StaticIpv4TcpStack,
        now_ms: u64,
    ) -> Result<WireTurn, &'static str> {
        let network = stack
            .poll_network(now_ms)
            .map_err(|_| "network stack poll failed")?;
        if network.connection_ended {
            if !self.input_closed {
                runner.close_input();
                self.input_closed = true;
            }
            return Ok(WireTurn {
                ended: true,
                worked: true,
                next_poll_delay_ms: network.next_poll_delay_ms,
            });
        }

        let mut worked = network.more_work || network.ingress_frames != 0;

        // Sunset may deliberately stop accepting input while key-exchange
        // output drains. Always service its outbound half first.
        for _ in 0..MAX_WIRE_IO_PER_TURN {
            let result = {
                let output = runner.output_buf();
                if output.is_empty() {
                    break;
                }
                stack
                    .try_send(output)
                    .map_err(|_| "TCP send authority failed")?
            };
            match result {
                TcpIoResult::Progress(0) | TcpIoResult::WouldBlock => break,
                TcpIoResult::Progress(length) => {
                    self.sent = self
                        .sent
                        .checked_add(length)
                        .ok_or("SSH transmit byte budget overflowed")?;
                    if self.sent > MAX_WIRE_BYTES_PER_DIRECTION {
                        return Err("SSH transmit byte budget exceeded");
                    }
                    runner.consume_output(length);
                    worked = true;
                }
                TcpIoResult::Closed => {
                    return Ok(WireTurn {
                        ended: true,
                        worked: true,
                        next_poll_delay_ms: network.next_poll_delay_ms,
                    });
                }
            }
        }

        for _ in 0..MAX_WIRE_IO_PER_TURN {
            if self.inbound_start != self.inbound_end {
                if !runner.is_input_ready() {
                    break;
                }
                let consumed = runner
                    .input(&self.inbound[self.inbound_start..self.inbound_end])
                    .map_err(|_| "SSH input processing failed")?;
                if consumed == 0 {
                    break;
                }
                self.inbound_start += consumed;
                worked = true;
                if self.inbound_start != self.inbound_end {
                    continue;
                }
                self.inbound_start = 0;
                self.inbound_end = 0;
            }

            match stack
                .try_recv(&mut self.inbound)
                .map_err(|_| "TCP receive authority failed")?
            {
                TcpIoResult::Progress(0) | TcpIoResult::WouldBlock => break,
                TcpIoResult::Progress(length) => {
                    self.received = self
                        .received
                        .checked_add(length)
                        .ok_or("SSH receive byte budget overflowed")?;
                    if self.received > MAX_WIRE_BYTES_PER_DIRECTION {
                        return Err("SSH receive byte budget exceeded");
                    }
                    self.inbound_end = length;
                    worked = true;
                }
                TcpIoResult::Closed => {
                    if !self.input_closed {
                        runner.close_input();
                        self.input_closed = true;
                        worked = true;
                    }
                    break;
                }
            }
        }

        let status = stack.stream_status();
        if !self.input_closed
            && self.inbound_start == self.inbound_end
            && status.readable_bytes == 0
            && matches!(
                status.state,
                TcpStreamState::PeerClosed
                    | TcpStreamState::Closing
                    | TcpStreamState::Reset
                    | TcpStreamState::Closed
            )
        {
            runner.close_input();
            self.input_closed = true;
            worked = true;
        }

        Ok(WireTurn {
            ended: false,
            worked,
            next_poll_delay_ms: network.next_poll_delay_ms,
        })
    }
}

enum ConnectionEnd {
    ExecComplete(u32),
    ShellComplete(u32),
    Reset(&'static str),
    Rebind(&'static str),
}

enum ExecutionEnd {
    Complete {
        reports: Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
        timed_out: bool,
    },
    Reset(&'static str),
    Rebind(&'static str),
}

#[derive(Clone, Copy)]
enum ExecutionCancellation {
    Timeout,
    Reset(&'static str),
    Rebind(&'static str),
}

/// Serve an explicit acceptance endpoint with one active TCP/SSH peer at a time.
pub async fn task(
    space: &Space,
    service_policy: SshServicePolicy,
    outbound: Cap,
    inbound: Cap,
    control: Cap,
    random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    authorization_policy: Cap,
) {
    let (outbound_endpoint, inbound_endpoint) = match space.packet_endpoints(outbound, inbound) {
        Some(endpoints) => endpoints,
        None => {
            component_log!(space, "FAIL ssh-test: packet authority unavailable");
            return;
        }
    };

    let initial_entropy = match fetch_entropy(space, random, SEED_BYTES + 8).await {
        Ok(entropy) => entropy,
        Err(_) => {
            component_log!(space, "FAIL ssh-test: SSH random source unavailable");
            return;
        }
    };
    let mut connection_seed = [0u8; SEED_BYTES];
    connection_seed.copy_from_slice(&initial_entropy.as_slice()[..SEED_BYTES]);
    if connection_seed.iter().all(|byte| *byte == 0) {
        wipe(&mut connection_seed);
        component_log!(
            space,
            "FAIL ssh-test: SSH random source returned an all-zero seed"
        );
        return;
    }
    let mut tcp_seed_bytes = [0u8; 8];
    tcp_seed_bytes.copy_from_slice(&initial_entropy.as_slice()[SEED_BYTES..]);
    let tcp_seed = u64::from_le_bytes(tcp_seed_bytes);
    wipe(&mut tcp_seed_bytes);
    drop(initial_entropy);

    let mut stack = match build_stack(
        space,
        control,
        tcp_seed,
        inbound_endpoint,
        outbound_endpoint,
        service_policy,
    )
    .await
    {
        Ok(stack) => stack,
        Err(reason) => {
            wipe(&mut connection_seed);
            component_log!(space, "FAIL ssh-test: {reason}");
            return;
        }
    };
    let mut bound_epoch = match device_info(space, control) {
        Some(info) => info.session_epoch,
        None => {
            wipe(&mut connection_seed);
            component_log!(
                space,
                "FAIL ssh-test: network control authority unavailable"
            );
            return;
        }
    };
    let mut announced_ipv4 = None;
    let mut announce_required = true;

    loop {
        let wait_result = if announce_required {
            match announce_listener(
                space,
                control,
                bound_epoch,
                &mut stack,
                &mut announced_ipv4,
                service_policy,
            )
            .await
            {
                Ok(()) => {
                    announce_required = false;
                    wait_for_connection(
                        space,
                        control,
                        bound_epoch,
                        &mut stack,
                        &mut announced_ipv4,
                        service_policy,
                    )
                    .await
                }
                Err(reason) => Err(reason),
            }
        } else {
            wait_for_connection(
                space,
                control,
                bound_epoch,
                &mut stack,
                &mut announced_ipv4,
                service_policy,
            )
            .await
        };
        let outcome = match wait_result {
            Ok(()) => {
                let seed = core::mem::replace(&mut connection_seed, [0; SEED_BYTES]);
                serve_connection(
                    space,
                    control,
                    bound_epoch,
                    signer_read,
                    signer_invoke,
                    authorization_policy,
                    &mut stack,
                    seed,
                    service_policy.require_carrier,
                )
                .await
            }
            Err(reason) => ConnectionEnd::Rebind(reason),
        };

        let mut rebind_reason = None;
        match outcome {
            ConnectionEnd::ExecComplete(status) => {
                component_log!(space, "ssh-test exec complete: status {status}");
            }
            ConnectionEnd::ShellComplete(status) => {
                component_log!(space, "ssh-test shell complete: status {status}");
            }
            ConnectionEnd::Reset(reason) => {
                let _ = stack.reset();
                component_log!(space, "ssh-test connection reset: {reason}");
            }
            ConnectionEnd::Rebind(reason) => {
                let _ = stack.reset();
                component_log!(space, "ssh-test connection reset: {reason}");
                rebind_reason = Some(reason);
            }
        }

        if space.security_policy_changed() {
            wipe(&mut connection_seed);
            component_log!(space, "SSH security policy changed; restarting listener");
            return;
        }

        if rebind_reason.is_none() {
            if let Err(reason) = rearm_listener(&mut stack).await {
                let _ = stack.reset();
                component_log!(space, "ssh-test connection reset: {reason}");
                rebind_reason = Some(reason);
            }
        }

        if rebind_reason.is_some() {
            wipe(&mut connection_seed);
            announced_ipv4 = None;
            announce_required = true;
            let next_entropy = match fetch_entropy(space, random, SEED_BYTES + 8).await {
                Ok(entropy) => entropy,
                Err(_) => {
                    component_log!(
                        space,
                        "FAIL ssh-test: SSH random source unavailable during rebind"
                    );
                    return;
                }
            };
            connection_seed.copy_from_slice(&next_entropy.as_slice()[..SEED_BYTES]);
            let mut next_tcp_seed = [0u8; 8];
            next_tcp_seed.copy_from_slice(&next_entropy.as_slice()[SEED_BYTES..]);
            let next_tcp_seed_value = u64::from_le_bytes(next_tcp_seed);
            wipe(&mut next_tcp_seed);
            drop(next_entropy);
            if connection_seed.iter().all(|byte| *byte == 0) {
                wipe(&mut connection_seed);
                component_log!(
                    space,
                    "FAIL ssh-test: SSH random source returned an all-zero seed"
                );
                return;
            }
            let Some((next_outbound, next_inbound)) = stack_endpoints(space, outbound, inbound)
            else {
                wipe(&mut connection_seed);
                component_log!(
                    space,
                    "FAIL ssh-test: packet authority unavailable while rebinding"
                );
                return;
            };
            stack = match build_stack(
                space,
                control,
                next_tcp_seed_value,
                next_inbound,
                next_outbound,
                service_policy,
            )
            .await
            {
                Ok(stack) => stack,
                Err(reason) => {
                    wipe(&mut connection_seed);
                    component_log!(space, "FAIL ssh-test: {reason}");
                    return;
                }
            };
            bound_epoch = match device_info(space, control) {
                Some(info) => info.session_epoch,
                None => {
                    wipe(&mut connection_seed);
                    component_log!(
                        space,
                        "FAIL ssh-test: network control authority unavailable"
                    );
                    return;
                }
            };
            continue;
        }

        // Prepare fresh connection-local randomness only after the old TCP
        // tuple has definitely returned to the passive listener.
        let entropy = match fetch_entropy(space, random, SEED_BYTES).await {
            Ok(entropy) => entropy,
            Err(_) => {
                component_log!(
                    space,
                    "FAIL ssh-test: SSH random source unavailable for next connection"
                );
                return;
            }
        };
        connection_seed.copy_from_slice(entropy.as_slice());
        drop(entropy);
        if connection_seed.iter().all(|byte| *byte == 0) {
            wipe(&mut connection_seed);
            component_log!(
                space,
                "FAIL ssh-test: SSH random source returned an all-zero seed"
            );
            return;
        }
    }
}

fn stack_endpoints(
    space: &Space,
    outbound: Cap,
    inbound: Cap,
) -> Option<(
    Revocable<Endpoint<StampedPacket>>,
    Revocable<Endpoint<StampedPacket>>,
)> {
    space.packet_endpoints(outbound, inbound)
}

async fn build_stack(
    space: &Space,
    control: Cap,
    tcp_seed: u64,
    inbound: Revocable<Endpoint<StampedPacket>>,
    outbound: Revocable<Endpoint<StampedPacket>>,
    policy: SshServicePolicy,
) -> Result<StaticIpv4TcpStack, &'static str> {
    let mut attempts = 0usize;
    loop {
        if matches!(policy.bind_retry, BindRetry::Attempts(limit) if attempts >= limit) {
            return Err("network stack bind timed out");
        }
        attempts = attempts.saturating_add(1);
        let info = device_info(space, control).ok_or("network control authority unavailable")?;
        if info.quarantined {
            return Err("network device is quarantined");
        }
        if !info.online {
            vibeos_core::exec::sleep_ms(1).await;
            continue;
        }
        if policy.require_carrier && !info.phy_link_up {
            vibeos_core::exec::sleep_ms(1).await;
            continue;
        }
        match bind_stack(space, control) {
            Ok(stamp) => {
                let address = policy.ipv4.initial_address();
                let mut config = StaticIpv4Config::new(
                    policy.ethernet_address,
                    address.address,
                    address.prefix_len,
                    policy.listen_port,
                    tcp_seed ^ stamp.device_epoch(),
                );
                if let Some(gateway) = address.default_gateway {
                    config = config.with_default_gateway(gateway);
                }
                let mut stack = StaticIpv4TcpStack::new(config, stamp, inbound, outbound)
                    .map_err(|_| "IPv4/TCP stack construction failed")?;
                if matches!(policy.ipv4, Ipv4Policy::Dhcp { .. }) {
                    stack
                        .start_dhcp()
                        .map_err(|_| "DHCP client initialization failed")?;
                }
                return Ok(stack);
            }
            Err(NetworkBindError::Offline | NetworkBindError::SessionBusy) => {
                vibeos_core::exec::sleep_ms(1).await;
            }
            Err(_) => return Err("network stack bind failed"),
        }
    }
}

async fn announce_listener(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    stack: &mut StaticIpv4TcpStack,
    announced_ipv4: &mut Option<[u8; 4]>,
    policy: SshServicePolicy,
) -> Result<(), &'static str> {
    if matches!(policy.ipv4, Ipv4Policy::Static(_)) {
        update_listener_announcement(space, stack, announced_ipv4, policy);
        return Ok(());
    }

    let mut last_status = monotonic_ms();
    loop {
        validate_network_authority(space, control, bound_epoch, policy.require_carrier)?;
        let report = stack
            .poll_network(monotonic_ms())
            .map_err(|_| "DHCP/network listener poll failed")?;
        if update_listener_announcement(space, stack, announced_ipv4, policy) {
            return Ok(());
        }
        let now = monotonic_ms();
        if policy.status_interval_ms != 0
            && now.saturating_sub(last_status) >= policy.status_interval_ms
        {
            component_log!(space, "{} waiting for a DHCP lease", policy.listener_label);
            last_status = now;
        }
        cooperate(
            report.more_work || report.ingress_frames != 0,
            report.next_poll_delay_ms,
        )
        .await;
    }
}

async fn wait_for_connection(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    stack: &mut StaticIpv4TcpStack,
    announced_ipv4: &mut Option<[u8; 4]>,
    policy: SshServicePolicy,
) -> Result<(), &'static str> {
    loop {
        validate_network_authority(space, control, bound_epoch, policy.require_carrier)?;
        let report = stack
            .poll_network(monotonic_ms())
            .map_err(|_| "network listener poll failed")?;
        update_listener_announcement(space, stack, announced_ipv4, policy);
        // smoltcp considers SYN-RECEIVED an active connection, but its byte
        // stream API cannot accept Sunset's server banner until the final ACK
        // moves the socket to ESTABLISHED. Entering the bridge on the earlier
        // `connection_started` edge would misread that temporary send state as
        // a closed stream and reset every real OpenSSH connection.
        if matches!(
            stack.stream_status().state,
            TcpStreamState::Established | TcpStreamState::PeerClosed
        ) {
            return Ok(());
        }
        cooperate(
            report.more_work || report.ingress_frames != 0,
            report.next_poll_delay_ms,
        )
        .await;
    }
}

async fn rearm_listener(stack: &mut StaticIpv4TcpStack) -> Result<(), &'static str> {
    let started = monotonic_ms();
    loop {
        // A successfully completed connection may already have rearmed the
        // passive socket. Do not poll in that state: an immediately queued SYN
        // belongs to the next fresh SSH Runner and connection entropy.
        if stack.is_listening() {
            return Ok(());
        }
        let now = monotonic_ms();
        let report = stack
            .poll_network(now)
            .map_err(|_| "network listener rearm poll failed")?;
        if stack.is_listening() {
            return Ok(());
        }
        if now.saturating_sub(started) > CLOSE_TIMEOUT_MS {
            stack
                .reset()
                .map_err(|_| "TCP listener fallback reset failed")?;
            stack
                .poll_network(now)
                .map_err(|_| "TCP listener fallback reset poll failed")?;
            return if stack.is_listening() {
                Ok(())
            } else {
                Err("TCP listener did not rearm after fallback reset")
            };
        }
        cooperate(
            report.more_work || report.ingress_frames != 0,
            report.next_poll_delay_ms,
        )
        .await;
    }
}

fn update_listener_announcement(
    space: &Space,
    stack: &StaticIpv4TcpStack,
    announced_ipv4: &mut Option<[u8; 4]>,
    policy: SshServicePolicy,
) -> bool {
    let address = match policy.ipv4 {
        Ipv4Policy::Static(address) => Some(address.address),
        Ipv4Policy::Dhcp { .. } => match stack.ipv4_status() {
            Ipv4RuntimeStatus::DhcpBound(address) => Some(address.address),
            _ => None,
        },
    };
    match address {
        Some(address) => {
            if *announced_ipv4 != Some(address) {
                let [a, b, c, d] = address;
                component_log!(
                    space,
                    "{} listening on {a}.{b}.{c}.{d}:{}",
                    policy.listener_label,
                    policy.listen_port
                );
                *announced_ipv4 = Some(address);
            }
            true
        }
        None => {
            if announced_ipv4.take().is_some() {
                component_log!(
                    space,
                    "{} DHCP lease lost; listener unavailable",
                    policy.listener_label
                );
            }
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    mut seed: [u8; SEED_BYTES],
    require_carrier: bool,
) -> ConnectionEnd {
    let limits =
        RandomLimits::new(4 * 1024, 1024 * 1024).expect("SSH random limits are within hard bounds");
    let source = OneSeed(Some(seed));
    wipe(&mut seed);
    let inner = match ChaCha20Random::new(
        source,
        RandomDomain::new(SSH_RANDOM_DOMAIN).expect("SSH random domain is non-zero"),
        limits,
    ) {
        Ok(random) => random,
        Err(_) => return ConnectionEnd::Reset("connection random source initialization failed"),
    };
    let mut random = SunsetRandom { inner };
    let mut runner = Runner::<Server>::new_server_owned(&mut random);
    let mut signer = CapabilityHostSigner::new(space, signer_read, signer_invoke);
    let mut protocol = ProtocolState::default();
    let mut bridge = WireBridge::new();
    let mut pending_input = match PendingInput::new() {
        Ok(input) => input,
        Err(reason) => return ConnectionEnd::Reset(reason),
    };
    let started = monotonic_ms();

    let start = loop {
        let now = monotonic_ms();
        if now.saturating_sub(started) > CONNECTION_TIMEOUT_MS {
            return reset_connection(stack, "SSH connection timed out");
        }
        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            return ConnectionEnd::Rebind(reason);
        }
        let wire = match bridge.drive(&mut runner, stack, now) {
            Ok(turn) => turn,
            Err(reason) => return reset_connection(stack, reason),
        };
        if wire.ended {
            return ConnectionEnd::Reset("peer disconnected before exec completed");
        }
        let signal = match progress_protocol(&mut runner, &mut signer, space, policy, &mut protocol)
        {
            Ok(signal) => signal,
            Err(reason) => return reset_connection(stack, reason),
        };
        match signal {
            ProtocolSignal::Exec(command) => break SessionStart::Exec(command),
            ProtocolSignal::Shell => break SessionStart::Shell,
            ProtocolSignal::Interrupt => pending_input.signal_interrupt = true,
            ProtocolSignal::Defunct => {
                return ConnectionEnd::Reset("SSH peer disconnected before session start")
            }
            ProtocolSignal::Idle | ProtocolSignal::Progressed => {}
        }
        let input_work = if protocol.pty.is_some() {
            match read_shell_channel_input(&mut runner, &protocol, &mut pending_input) {
                Ok(worked) => worked,
                Err(reason) => return reset_connection(stack, reason),
            }
        } else {
            match discard_channel_input(&mut runner, &protocol) {
                Ok(worked) => worked,
                Err(reason) => return reset_connection(stack, reason),
            }
        };
        if protocol
            .channel
            .as_ref()
            .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            return ConnectionEnd::Reset("session channel closed before session start");
        }
        cooperate(
            wire.worked || input_work || matches!(signal, ProtocolSignal::Progressed),
            wire.next_poll_delay_ms,
        )
        .await;
    };

    match start {
        SessionStart::Exec(command) => {
            #[cfg(feature = "qualification-stream")]
            if let Some(opened) = space.open_streaming_exec(&command) {
                let status = match opened {
                    Ok(stream) => match execute_stream_with_network(
                        stream,
                        &mut runner,
                        &mut signer,
                        space,
                        control,
                        bound_epoch,
                        policy,
                        stack,
                        &mut bridge,
                        &mut protocol,
                        require_carrier,
                    )
                    .await
                    {
                        Ok(status) => status,
                        Err(ConnectionEnd::Reset(reason)) => {
                            return reset_connection(stack, reason)
                        }
                        Err(other) => return other,
                    },
                    Err(status) => status,
                };
                return match finish_exec(
                    &mut runner,
                    &mut signer,
                    space,
                    control,
                    bound_epoch,
                    policy,
                    stack,
                    &mut bridge,
                    &mut protocol,
                    &[],
                    status,
                    require_carrier,
                )
                .await
                {
                    Ok(()) => ConnectionEnd::ExecComplete(status),
                    Err(ConnectionEnd::Reset(reason)) => reset_connection(stack, reason),
                    Err(other) => other,
                };
            }
            let execution = execute_with_network(
                &command,
                &mut runner,
                &mut signer,
                space,
                control,
                bound_epoch,
                policy,
                stack,
                &mut bridge,
                &mut protocol,
                require_carrier,
            )
            .await;
            let (reports, timed_out) = match execution {
                ExecutionEnd::Complete { reports, timed_out } => (reports, timed_out),
                ExecutionEnd::Reset(reason) => return reset_connection(stack, reason),
                ExecutionEnd::Rebind(reason) => return ConnectionEnd::Rebind(reason),
            };
            let (output, status) = collect_execution(reports, timed_out);
            match finish_exec(
                &mut runner,
                &mut signer,
                space,
                control,
                bound_epoch,
                policy,
                stack,
                &mut bridge,
                &mut protocol,
                &output,
                status,
                require_carrier,
            )
            .await
            {
                Ok(()) => ConnectionEnd::ExecComplete(status),
                Err(ConnectionEnd::Reset(reason)) => reset_connection(stack, reason),
                Err(other) => other,
            }
        }
        SessionStart::Shell => {
            let status = match serve_interactive_shell(
                &mut runner,
                &mut signer,
                space,
                control,
                bound_epoch,
                policy,
                stack,
                &mut bridge,
                &mut protocol,
                &mut pending_input,
                require_carrier,
            )
            .await
            {
                Ok(status) => status,
                Err(ConnectionEnd::Reset(reason)) => return reset_connection(stack, reason),
                Err(other) => return other,
            };
            ConnectionEnd::ShellComplete(status)
        }
    }
}

#[cfg(feature = "qualification-stream")]
#[allow(clippy::too_many_arguments)]
async fn execute_stream_with_network(
    mut stream: StreamingExecBox,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    require_carrier: bool,
) -> Result<u32, ConnectionEnd> {
    let mut pending = Vec::new();
    let mut offset = 0usize;

    loop {
        let now = monotonic_ms();
        validate_network_authority(space, control, bound_epoch, require_carrier)
            .map_err(ConnectionEnd::Rebind)?;
        let wire = bridge
            .drive(runner, stack, now)
            .map_err(ConnectionEnd::Reset)?;
        if wire.ended {
            return Err(ConnectionEnd::Reset(
                "peer disconnected during streaming exec",
            ));
        }
        let signal = progress_protocol(runner, signer, space, policy, protocol)
            .map_err(ConnectionEnd::Reset)?;
        if matches!(signal, ProtocolSignal::Defunct)
            || protocol
                .channel
                .as_ref()
                .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            return Err(ConnectionEnd::Reset(
                "SSH channel closed during streaming exec",
            ));
        }
        discard_channel_input(runner, protocol).map_err(ConnectionEnd::Reset)?;

        let mut application_work = false;
        if offset < pending.len() {
            let channel = protocol
                .channel
                .as_ref()
                .ok_or(ConnectionEnd::Reset("streaming exec lost its channel"))?;
            match runner.write_channel(channel, ChanData::Normal, &pending[offset..]) {
                Ok(0) => {}
                Ok(written) => {
                    offset += written;
                    application_work = true;
                }
                Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => {}
                Err(_) => return Err(ConnectionEnd::Reset("streaming SSH stdout closed")),
            }
            if offset == pending.len() {
                pending.clear();
                offset = 0;
            }
        } else {
            let mut context = Context::from_waker(Waker::noop());
            match stream.as_mut().poll_next(&mut context) {
                Poll::Ready(Ok(Some(chunk))) => {
                    if chunk.is_empty() || chunk.len() > 64 * 1024 {
                        return Err(ConnectionEnd::Reset(
                            "streaming exec produced an invalid chunk",
                        ));
                    }
                    pending = chunk;
                    application_work = true;
                }
                Poll::Ready(Ok(None)) => return Ok(0),
                Poll::Ready(Err(status)) => return Ok(status),
                Poll::Pending => application_work = true,
            }
        }

        cooperate(
            wire.worked || application_work || matches!(signal, ProtocolSignal::Progressed),
            wire.next_poll_delay_ms,
        )
        .await;
    }
}

fn progress_protocol(
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    policy_cap: Cap,
    state: &mut ProtocolState,
) -> Result<ProtocolSignal, &'static str> {
    let mut progressed = false;
    for _ in 0..MAX_SSH_PROGRESS_PER_TURN {
        let event = match runner.progress() {
            Ok(event) => event,
            Err(error) => {
                // This image carries only public test identities. Retaining the
                // Sunset error category in its serial transcript makes an
                // interoperability failure actionable without exposing key or
                // packet contents.
                component_log!(space, "ssh-test Sunset protocol error: {error:?}");
                return Err("SSH protocol state failed");
            }
        };
        match event {
            Event::None => break,
            Event::Progressed => progressed = true,
            Event::Cli(_) => return Err("server runner emitted a client event"),
            Event::Serv(ServEvent::PollAgain) => progressed = true,
            Event::Serv(ServEvent::Defunct) => return Ok(ProtocolSignal::Defunct),
            Event::Serv(ServEvent::Hostkeys(event)) => {
                event
                    .hostkey_ed25519(signer)
                    .map_err(|_| "host-key signing failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::FirstAuth(event)) => {
                state.candidate = None;
                let mut event = event;
                let onboarding = space.onboarding_profile().is_some();
                event
                    .set_auth_methods(onboarding, !onboarding)
                    .map_err(|_| "authentication-method configuration failed")?;
                event.reject().map_err(|_| "first-auth rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::PasswordAuth(event)) => {
                state.candidate = None;
                let profile = match (event.username(), event.password()) {
                    (Ok(username), Ok(password)) => {
                        space.onboarding_password_profile(username, password)
                    }
                    _ => None,
                };
                state.candidate = profile.map(|profile| AuthCandidate {
                    credential: AuthCredential::OnboardingPassword,
                    profile,
                });
                if profile.is_some() {
                    event.allow().map_err(|_| "password-auth allow failed")?;
                } else {
                    event
                        .reject()
                        .map_err(|_| "password-auth rejection failed")?;
                }
                progressed = true;
            }
            Event::Serv(ServEvent::PubkeyAuth(event)) => {
                // Parse and copy the exact key before consuming the event.
                let _username = event
                    .username()
                    .map_err(|_| "authentication username was invalid")?;
                let key = match event
                    .pubkey()
                    .map_err(|_| "authentication public key was invalid")?
                {
                    PubKey::Ed25519(key) => SshEd25519PublicKey::from_bytes(key.key.0).ok(),
                    _ => None,
                };
                let candidate = match key {
                    Some(key) => authorize(space, policy_cap, signer, key)?,
                    None => None,
                };
                state.candidate = candidate;
                if candidate.is_some() {
                    event
                        .allow()
                        .map_err(|_| "public-key authorization response failed")?;
                } else {
                    event.reject().map_err(|_| "public-key rejection failed")?;
                }
                progressed = true;
            }
            Event::Serv(ServEvent::Authenticated) => {
                if state.authenticated {
                    return Err("duplicate authenticated transition");
                }
                let candidate = state
                    .candidate
                    .take()
                    .ok_or("authentication completed without an authorized profile")?;
                if !revalidate_candidate(space, policy_cap, signer, candidate)? {
                    return Err("authorized profile changed before authentication commit");
                }
                state.committed = Some(candidate);
                state.authenticated = true;
                progressed = true;
            }
            Event::Serv(ServEvent::OpenSession(event)) => {
                if state.authenticated && state.committed.is_some() && !state.channel_seen {
                    let channel = event
                        .accept()
                        .map_err(|_| "session-channel acceptance failed")?;
                    state.channel = Some(channel);
                    state.channel_seen = true;
                } else {
                    event
                        .reject(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
                        .map_err(|_| "session-channel rejection failed")?;
                }
                progressed = true;
            }
            Event::Serv(ServEvent::SessionExec(event)) => {
                let ours = state
                    .channel
                    .as_ref()
                    .is_some_and(|channel| channel.num() == event.channel());
                let mut command = None;
                if ours && state.authenticated && !state.start_seen {
                    state.start_seen = true;
                    let candidate = state
                        .committed
                        .ok_or("exec arrived without a committed profile")?;
                    if state.pty.is_none()
                        && !revalidate_candidate(space, policy_cap, signer, candidate)?
                    {
                        return Err("authorized profile changed before exec");
                    }
                    if state.pty.is_none() {
                        let value = event
                            .command()
                            .map_err(|_| "exec command was not valid UTF-8")?
                            .to_string();
                        if vibeos_vsh::validate_ssh_exec(&value).is_ok() || {
                            #[cfg(feature = "qualification-stream")]
                            {
                                space.accepts_streaming_exec(&value)
                            }
                            #[cfg(not(feature = "qualification-stream"))]
                            {
                                false
                            }
                        } {
                            command = Some(value);
                        }
                    }
                }
                if let Some(command) = command {
                    event
                        .succeed()
                        .map_err(|_| "exec acceptance response failed")?;
                    return Ok(ProtocolSignal::Exec(command));
                }
                event.fail().map_err(|_| "exec rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionShell(event)) => {
                let ours = state
                    .channel
                    .as_ref()
                    .is_some_and(|channel| channel.num() == event.channel());
                let mut accept = false;
                if ours && state.authenticated && !state.start_seen {
                    state.start_seen = true;
                    let candidate = state
                        .committed
                        .ok_or("shell arrived without a committed profile")?;
                    if state.pty.is_some()
                        && !revalidate_candidate(space, policy_cap, signer, candidate)?
                    {
                        return Err("authorized profile changed before shell");
                    }
                    accept = state.pty.is_some();
                }
                if accept {
                    event
                        .succeed()
                        .map_err(|_| "shell acceptance response failed")?;
                    return Ok(ProtocolSignal::Shell);
                }
                event.fail().map_err(|_| "shell rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionSubsystem(event)) => {
                let ours = state
                    .channel
                    .as_ref()
                    .is_some_and(|channel| channel.num() == event.channel());
                if ours && !state.start_seen {
                    state.start_seen = true;
                }
                event.fail().map_err(|_| "subsystem rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionPty(event)) => {
                let ours = state
                    .channel
                    .as_ref()
                    .is_some_and(|channel| channel.num() == event.channel());
                if ours && state.authenticated && !state.start_seen && state.pty.is_none() {
                    // Dimensions are metadata only. Never turn peer-provided
                    // rows, columns, or pixels into allocation sizes.
                    let size = event
                        .metadata()
                        .map_err(|_| "PTY metadata was invalid")?
                        .size;
                    event
                        .succeed()
                        .map_err(|_| "PTY acceptance response failed")?;
                    state.pty = Some(size);
                    progressed = true;
                    continue;
                }
                event.fail().map_err(|_| "PTY rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionWindowChange(event)) => {
                let ours = state
                    .channel
                    .as_ref()
                    .is_some_and(|channel| channel.num() == event.channel());
                if !ours || state.pty.is_none() {
                    return Err("window change arrived without an accepted PTY");
                }
                let size = event.size().map_err(|_| "window change was invalid")?;
                state.pty = Some(size);
                progressed = true;
            }
            Event::Serv(ServEvent::SessionSignal(event)) => {
                let ours = state
                    .channel
                    .as_ref()
                    .is_some_and(|channel| channel.num() == event.channel());
                if !ours || !state.start_seen {
                    return Err("signal arrived without an active session command");
                }
                if event.signal_name().map_err(|_| "signal name was invalid")? == "INT" {
                    return Ok(ProtocolSignal::Interrupt);
                }
                progressed = true;
            }
            Event::Serv(ServEvent::SessionBreak(event)) => {
                event.fail().map_err(|_| "BREAK rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionEnv(event)) => {
                event.fail().map_err(|_| "environment rejection failed")?;
                progressed = true;
            }
        }
    }
    Ok(if progressed {
        ProtocolSignal::Progressed
    } else {
        ProtocolSignal::Idle
    })
}

fn authorize(
    space: &Space,
    policy_cap: Cap,
    signer: &CapabilityHostSigner<'_>,
    key: SshEd25519PublicKey,
) -> Result<Option<AuthCandidate>, &'static str> {
    let host = signer.snapshot()?;
    let profile = space
        .authorized_profile(policy_cap, &key)
        .map_err(|_| "authorized-key policy lookup failed")?;
    let Some(profile) = profile else {
        return Ok(None);
    };
    if profile.generation != host.generation {
        return Ok(None);
    }
    Ok(Some(AuthCandidate {
        credential: AuthCredential::PublicKey(key),
        profile,
    }))
}

fn revalidate_candidate(
    space: &Space,
    policy_cap: Cap,
    signer: &CapabilityHostSigner<'_>,
    expected: AuthCandidate,
) -> Result<bool, &'static str> {
    match expected.credential {
        AuthCredential::PublicKey(key) => Ok(authorize(space, policy_cap, signer, key)?
            .is_some_and(|candidate| candidate.profile == expected.profile)),
        AuthCredential::OnboardingPassword => {
            Ok(space.onboarding_profile() == Some(expected.profile))
        }
    }
}

fn discard_channel_input(
    runner: &mut Runner<'_, Server>,
    state: &ProtocolState,
) -> Result<bool, &'static str> {
    let mut discarded = false;
    for _ in 0..MAX_CHANNEL_DISCARDS_PER_TURN {
        let Some((number, _, _)) = runner.read_channel_ready() else {
            break;
        };
        let channel = state
            .channel
            .as_ref()
            .ok_or("data arrived without an accepted session channel")?;
        if channel.num() != number {
            return Err("data arrived on an unowned session channel");
        }
        runner
            .discard_read_channel(channel)
            .map_err(|_| "failed to discard closed SSH stdin")?;
        discarded = true;
    }
    Ok(discarded)
}

fn read_shell_channel_input(
    runner: &mut Runner<'_, Server>,
    state: &ProtocolState,
    input: &mut PendingInput,
) -> Result<bool, &'static str> {
    let mut worked = false;
    let mut chunk = [0u8; SHELL_INPUT_CHUNK_BYTES];
    for _ in 0..MAX_CHANNEL_DISCARDS_PER_TURN {
        let Some((number, data, ready)) = runner.read_channel_ready() else {
            break;
        };
        let channel = state
            .channel
            .as_ref()
            .ok_or("data arrived without an accepted session channel")?;
        if channel.num() != number {
            return Err("data arrived on an unowned session channel");
        }
        if data != ChanData::Normal {
            return Err("extended data is not valid SSH shell input");
        }
        let remaining = input.remaining_capacity();
        if ready > remaining {
            // Leaving a partially consumed Sunset channel-data packet behind
            // would stop protocol progress, so fail this bounded session
            // instead of waiting forever for queue capacity that a running
            // foreground command cannot release.
            return Err("SSH shell input exceeded its fixed bound");
        }
        let length = ready.min(chunk.len());
        let read = runner
            .read_channel(channel, ChanData::Normal, &mut chunk[..length])
            .map_err(|_| "failed to read SSH shell input")?;
        if read == 0 {
            break;
        }
        input.bytes.extend(&chunk[..read]);
        worked = true;
    }
    Ok(worked)
}

fn flush_terminal_output(
    runner: &mut Runner<'_, Server>,
    state: &ProtocolState,
    frontend: &mut TerminalFrontend,
) -> Result<bool, &'static str> {
    if frontend.pending_output().is_empty() {
        return Ok(false);
    }
    let channel = state
        .channel
        .as_ref()
        .ok_or("SSH shell lost its session channel")?;
    match runner.write_channel(channel, ChanData::Normal, frontend.pending_output()) {
        Ok(0) => Ok(false),
        Ok(written) => {
            // Acknowledge only the prefix Sunset actually accepted. A zero or
            // failed write leaves the frontend queue byte-for-byte intact.
            frontend
                .consume_output(written)
                .map_err(|_| "terminal output accounting failed")?;
            Ok(true)
        }
        Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => Ok(false),
        Err(_) => Err("SSH shell output channel closed"),
    }
}

struct ShellTurn {
    worked: bool,
    next_poll_delay_ms: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
fn drive_shell_turn(
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<ShellTurn, ConnectionEnd> {
    validate_network_authority(space, control, bound_epoch, require_carrier)
        .map_err(ConnectionEnd::Rebind)?;
    let wire = bridge
        .drive(runner, stack, monotonic_ms())
        .map_err(ConnectionEnd::Reset)?;
    if wire.ended {
        return Err(ConnectionEnd::Reset("peer disconnected during SSH shell"));
    }

    let signal =
        progress_protocol(runner, signer, space, policy, protocol).map_err(ConnectionEnd::Reset)?;
    match signal {
        ProtocolSignal::Interrupt => input.signal_interrupt = true,
        ProtocolSignal::Defunct => {
            return Err(ConnectionEnd::Reset("SSH shell became defunct"));
        }
        ProtocolSignal::Exec(_) | ProtocolSignal::Shell => {
            return Err(ConnectionEnd::Reset(
                "duplicate SSH session start was accepted",
            ));
        }
        ProtocolSignal::Idle | ProtocolSignal::Progressed => {}
    }

    let output_work =
        flush_terminal_output(runner, protocol, frontend).map_err(ConnectionEnd::Reset)?;
    let input_work =
        read_shell_channel_input(runner, protocol, input).map_err(ConnectionEnd::Reset)?;
    if protocol
        .channel
        .as_ref()
        .is_some_and(|channel| runner.is_channel_closed(channel))
    {
        return Err(ConnectionEnd::Reset(
            "SSH shell channel closed unexpectedly",
        ));
    }

    Ok(ShellTurn {
        worked: wire.worked
            || output_work
            || input_work
            || matches!(
                signal,
                ProtocolSignal::Progressed | ProtocolSignal::Interrupt
            ),
        next_poll_delay_ms: wire.next_poll_delay_ms,
    })
}

fn terminal_error(error: FrontendError) -> &'static str {
    match error {
        FrontendError::Backpressure => "terminal output remained backpressured",
        FrontendError::OutputTooLarge => "terminal output exceeded its fixed bound",
        FrontendError::PromptTooLong => "terminal prompt exceeded its fixed bound",
        FrontendError::AllocationFailed => "terminal allocation failed",
        FrontendError::InvalidConsume => "terminal output accounting failed",
        FrontendError::PromptInactive => "terminal prompt was unexpectedly inactive",
        FrontendError::PromptActive => "terminal prompt was unexpectedly active",
        FrontendError::OutputInProgress => "terminal output transaction was already active",
        FrontendError::NoOutputInProgress => "terminal output transaction was not active",
    }
}

#[allow(clippy::too_many_arguments)]
async fn next_shell_event(
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<TerminalEvent, ConnectionEnd> {
    loop {
        let transport_eof = input.bytes.is_empty()
            && protocol
                .channel
                .as_ref()
                .is_some_and(|channel| runner.is_channel_eof(channel));
        if transport_eof {
            return Ok(frontend.transport_eof());
        }

        let mut application_work = false;
        if !frontend.is_at_prompt() {
            match frontend.show_prompt(SHELL_PROMPT) {
                Ok(()) => application_work = true,
                Err(FrontendError::Backpressure) => {}
                Err(error) => return Err(ConnectionEnd::Reset(terminal_error(error))),
            }
        }

        if frontend.is_at_prompt() && input.signal_interrupt {
            match frontend.interrupt() {
                Ok(event) => {
                    input.signal_interrupt = false;
                    return Ok(event);
                }
                Err(FrontendError::Backpressure) => {}
                Err(error) => return Err(ConnectionEnd::Reset(terminal_error(error))),
            }
        }

        if frontend.is_at_prompt() && !input.signal_interrupt {
            for _ in 0..MAX_SHELL_INPUT_ACTIONS_PER_TURN {
                let Some(byte) = input.bytes.front().copied() else {
                    break;
                };
                match frontend.input_byte(byte) {
                    Ok(event) => {
                        input.bytes.pop_front();
                        application_work = true;
                        if let Some(event) = event {
                            return Ok(event);
                        }
                    }
                    Err(FrontendError::Backpressure) => break,
                    Err(error) => return Err(ConnectionEnd::Reset(terminal_error(error))),
                }
            }
        }

        let turn = drive_shell_turn(
            runner,
            signer,
            space,
            control,
            bound_epoch,
            policy,
            stack,
            bridge,
            protocol,
            input,
            frontend,
            require_carrier,
        )?;
        cooperate(application_work || turn.worked, turn.next_poll_delay_ms).await;
    }
}

fn mark_running_interrupts(
    frontend: &mut TerminalFrontend,
    input: &mut PendingInput,
    cancel: &AtomicBool,
) -> Result<bool, &'static str> {
    if input.signal_interrupt {
        cancel.store(true, Ordering::Release);
        match frontend.interrupt() {
            Ok(_) => {
                input.signal_interrupt = false;
                return Ok(!input.bytes.iter().any(|byte| *byte == 0x03));
            }
            Err(FrontendError::Backpressure) => return Ok(false),
            Err(error) => return Err(terminal_error(error)),
        }
    }

    let Some(position) = input
        .bytes
        .iter()
        .enumerate()
        .find_map(|(position, byte)| (*byte == 0x03).then_some(position))
    else {
        return Ok(true);
    };
    cancel.store(true, Ordering::Release);
    match frontend.interrupt() {
        Ok(_) => {
            input.bytes.remove(position);
            Ok(!input.bytes.iter().any(|byte| *byte == 0x03))
        }
        Err(FrontendError::Backpressure) => Ok(false),
        Err(error) => Err(terminal_error(error)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_shell_command(
    command: &str,
    session: &mut vibeos_vsh::Session,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>, ConnectionEnd> {
    let cancel = Arc::new(AtomicBool::new(false));
    // Ordinary bytes queued after Enter remain typeahead for the next prompt.
    // Ctrl-C is different: SSH byte ordering proves every queued byte follows
    // the submitted line, so it must interrupt the command even when both
    // arrived in one channel-data packet.
    let mut execution = Box::pin(session.execute_cancellable(command, cancel.clone()));
    let mut cancellation: Option<(ExecutionCancellation, u64)> = None;
    let mut transport_eof_deadline = None;

    loop {
        if let Some((kind, deadline)) = cancellation {
            if let Poll::Ready(_reports) = poll_once(execution.as_mut()) {
                return match kind {
                    ExecutionCancellation::Reset(reason) => Err(ConnectionEnd::Reset(reason)),
                    ExecutionCancellation::Rebind(reason) => Err(ConnectionEnd::Rebind(reason)),
                    ExecutionCancellation::Timeout => {
                        Err(ConnectionEnd::Reset("unexpected shell execution timeout"))
                    }
                };
            }
            if monotonic_ms() >= deadline {
                return Err(match kind {
                    ExecutionCancellation::Reset(reason) => ConnectionEnd::Reset(reason),
                    ExecutionCancellation::Rebind(reason) => ConnectionEnd::Rebind(reason),
                    ExecutionCancellation::Timeout => {
                        ConnectionEnd::Reset("unexpected shell execution timeout")
                    }
                });
            }
            vibeos_core::exec::yield_now().await;
            continue;
        }

        let controls_rendered = mark_running_interrupts(frontend, input, cancel.as_ref())
            .map_err(ConnectionEnd::Reset)?;
        if controls_rendered {
            if let Poll::Ready(reports) = poll_once(execution.as_mut()) {
                return Ok(reports);
            }
        }

        let now = monotonic_ms();
        if transport_eof_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(ConnectionEnd::Reset(
                "VSH shell transport EOF cancellation timed out",
            ));
        }
        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            cancel.store(true, Ordering::Release);
            cancellation = Some((ExecutionCancellation::Rebind(reason), now + CANCEL_GRACE_MS));
            continue;
        }
        let wire = match bridge.drive(runner, stack, now) {
            Ok(turn) => turn,
            Err(reason) => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if wire.ended {
            cancel.store(true, Ordering::Release);
            cancellation = Some((
                ExecutionCancellation::Reset("peer disconnected during SSH shell command"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        let signal = match progress_protocol(runner, signer, space, policy, protocol) {
            Ok(signal) => signal,
            Err(reason) => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        match signal {
            ProtocolSignal::Interrupt => {
                input.signal_interrupt = true;
                cancel.store(true, Ordering::Release);
            }
            ProtocolSignal::Defunct => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((
                    ExecutionCancellation::Reset("SSH shell became defunct during command"),
                    now + CANCEL_GRACE_MS,
                ));
                continue;
            }
            ProtocolSignal::Exec(_) | ProtocolSignal::Shell => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((
                    ExecutionCancellation::Reset("duplicate SSH session start during command"),
                    now + CANCEL_GRACE_MS,
                ));
                continue;
            }
            ProtocolSignal::Idle | ProtocolSignal::Progressed => {}
        }
        if protocol
            .channel
            .as_ref()
            .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            cancel.store(true, Ordering::Release);
            cancellation = Some((
                ExecutionCancellation::Reset("SSH shell channel closed during command"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        let output_work = match flush_terminal_output(runner, protocol, frontend) {
            Ok(worked) => worked,
            Err(reason) => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        let input_work = match read_shell_channel_input(runner, protocol, input) {
            Ok(worked) => worked,
            Err(reason) => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if protocol
            .channel
            .as_ref()
            .is_some_and(|channel| runner.is_channel_eof(channel))
        {
            // Once transport EOF is observed, no later control byte can
            // arrive. Always bound foreground teardown even when earlier
            // typeahead remains queued. With no earlier bytes to preserve,
            // request cancellation immediately; otherwise give a finite job
            // the grace interval to complete without misreading piped input.
            transport_eof_deadline.get_or_insert(now + CANCEL_GRACE_MS);
            if input.bytes.is_empty() {
                cancel.store(true, Ordering::Release);
            }
        }
        if input.signal_interrupt || input.bytes.iter().any(|byte| *byte == 0x03) {
            cancel.store(true, Ordering::Release);
        }
        cooperate(
            wire.worked
                || output_work
                || input_work
                || matches!(
                    signal,
                    ProtocolSignal::Progressed | ProtocolSignal::Interrupt
                ),
            wire.next_poll_delay_ms,
        )
        .await;
    }
}

fn utf8_chunk_end(text: &str) -> usize {
    let mut end = text.len().min(MAX_EMIT_TEXT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[allow(clippy::too_many_arguments)]
async fn emit_shell_text(
    mut text: &str,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<(), ConnectionEnd> {
    while !text.is_empty() {
        let end = utf8_chunk_end(text);
        match frontend.emit_text(&text[..end]) {
            Ok(()) => {
                text = &text[end..];
                continue;
            }
            Err(FrontendError::Backpressure) => {}
            Err(error) => return Err(ConnectionEnd::Reset(terminal_error(error))),
        }
        let turn = drive_shell_turn(
            runner,
            signer,
            space,
            control,
            bound_epoch,
            policy,
            stack,
            bridge,
            protocol,
            input,
            frontend,
            require_carrier,
        )?;
        cooperate(turn.worked, turn.next_poll_delay_ms).await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn render_shell_execution(
    result: &Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<u32, ConnectionEnd> {
    match result {
        Ok(reports) => {
            let total = reports.iter().try_fold(0usize, |total, report| {
                let total = total.checked_add(report.output.len())?;
                if report.status == vibeos_vsh::Status::Success {
                    Some(total)
                } else {
                    total.checked_add(
                        alloc::format!("  vsh job %{}: {:?}\n", report.id, report.status).len(),
                    )
                }
            });
            if total.is_none_or(|total| total > MAX_EXEC_OUTPUT_BYTES) {
                emit_shell_text(
                    SHELL_OUTPUT_LIMIT_DIAGNOSTIC,
                    runner,
                    signer,
                    space,
                    control,
                    bound_epoch,
                    policy,
                    stack,
                    bridge,
                    protocol,
                    input,
                    frontend,
                    require_carrier,
                )
                .await?;
                return Ok(124);
            }
            for report in reports {
                emit_shell_text(
                    &report.output,
                    runner,
                    signer,
                    space,
                    control,
                    bound_epoch,
                    policy,
                    stack,
                    bridge,
                    protocol,
                    input,
                    frontend,
                    require_carrier,
                )
                .await?;
                if report.status != vibeos_vsh::Status::Success {
                    let diagnostic =
                        alloc::format!("  vsh job %{}: {:?}\n", report.id, report.status);
                    emit_shell_text(
                        &diagnostic,
                        runner,
                        signer,
                        space,
                        control,
                        bound_epoch,
                        policy,
                        stack,
                        bridge,
                        protocol,
                        input,
                        frontend,
                        require_carrier,
                    )
                    .await?;
                }
            }
            Ok(reports
                .last()
                .map_or(0, |report| ssh_exit_status(report.status)))
        }
        Err(error) => {
            let diagnostic = alloc::format!(
                "  vsh: {} at bytes {}..{}\n",
                error.message,
                error.span.start,
                error.span.end
            );
            emit_shell_text(
                &diagnostic,
                runner,
                signer,
                space,
                control,
                bound_epoch,
                policy,
                stack,
                bridge,
                protocol,
                input,
                frontend,
                require_carrier,
            )
            .await?;
            Ok(2)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_shell_repl(
    session: &mut vibeos_vsh::Session,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<u32, ConnectionEnd> {
    let mut status = 0;
    loop {
        match next_shell_event(
            runner,
            signer,
            space,
            control,
            bound_epoch,
            policy,
            stack,
            bridge,
            protocol,
            input,
            frontend,
            require_carrier,
        )
        .await?
        {
            TerminalEvent::Line(command) => {
                let command = command.trim();
                if command.is_empty() {
                    continue;
                }
                if matches!(command, "exit" | "logout") {
                    return Ok(0);
                }
                // VSH captures bounded command output internally. Rendering
                // starts only after execute_cancellable has actually finished;
                // this transport does not claim to provide live command I/O.
                let result = execute_shell_command(
                    command,
                    session,
                    runner,
                    signer,
                    space,
                    control,
                    bound_epoch,
                    policy,
                    stack,
                    bridge,
                    protocol,
                    input,
                    frontend,
                    require_carrier,
                )
                .await?;
                status = render_shell_execution(
                    &result,
                    runner,
                    signer,
                    space,
                    control,
                    bound_epoch,
                    policy,
                    stack,
                    bridge,
                    protocol,
                    input,
                    frontend,
                    require_carrier,
                )
                .await?;
            }
            TerminalEvent::Interrupt => status = 130,
            TerminalEvent::Eof => return Ok(status),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_interactive_shell(
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    require_carrier: bool,
) -> Result<u32, ConnectionEnd> {
    let _terminal_size = protocol
        .pty
        .ok_or(ConnectionEnd::Reset("SSH shell started without a PTY"))?;
    let cspace = Arc::new(SpinLock::new(CSpace::new("ssh-vsh-session")));
    let mut session = vibeos_vsh::Session::with_cspace(cspace);
    let onboarding = matches!(
        protocol.committed.map(|candidate| candidate.credential),
        Some(AuthCredential::OnboardingPassword)
    );
    space.install_vsh_commands(&mut session, onboarding);
    let mut frontend = TerminalFrontend::new();

    let repl = run_shell_repl(
        &mut session,
        runner,
        signer,
        space,
        control,
        bound_epoch,
        policy,
        stack,
        bridge,
        protocol,
        input,
        &mut frontend,
        require_carrier,
    )
    .await;
    // Join all foreground/background stages before the connection-local CSpace
    // or transport is released, including every network/error exit.
    session.shutdown().await;
    let status = repl?;

    while !frontend.pending_output().is_empty() {
        let turn = drive_shell_turn(
            runner,
            signer,
            space,
            control,
            bound_epoch,
            policy,
            stack,
            bridge,
            protocol,
            input,
            &mut frontend,
            require_carrier,
        )?;
        cooperate(turn.worked, turn.next_poll_delay_ms).await;
    }

    // Frontend bytes are fully drained before the common completion path sends
    // exit-status, EOF, CLOSE, waits for peer CLOSE, and releases the channel.
    finish_exec(
        runner,
        signer,
        space,
        control,
        bound_epoch,
        policy,
        stack,
        bridge,
        protocol,
        &[],
        status,
        require_carrier,
    )
    .await?;
    Ok(status)
}

#[allow(clippy::too_many_arguments)]
async fn execute_with_network(
    command: &str,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    require_carrier: bool,
) -> ExecutionEnd {
    let cancel = Arc::new(AtomicBool::new(false));
    let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
    let onboarding = matches!(
        protocol.committed.map(|candidate| candidate.credential),
        Some(AuthCredential::OnboardingPassword)
    );
    space.install_vsh_commands(&mut session, onboarding);
    let mut execution = Box::pin(session.execute_ssh_cancellable(command, cancel.clone()));
    let started = monotonic_ms();
    let mut cancellation: Option<(ExecutionCancellation, u64)> = None;

    let outcome = loop {
        if let Poll::Ready(reports) = poll_once(execution.as_mut()) {
            break match cancellation.map(|(kind, _)| kind) {
                Some(ExecutionCancellation::Timeout) => ExecutionEnd::Complete {
                    reports,
                    timed_out: true,
                },
                Some(ExecutionCancellation::Reset(reason)) => ExecutionEnd::Reset(reason),
                Some(ExecutionCancellation::Rebind(reason)) => ExecutionEnd::Rebind(reason),
                None => ExecutionEnd::Complete {
                    reports,
                    timed_out: false,
                },
            };
        }

        let now = monotonic_ms();
        if let Some((kind, deadline)) = cancellation {
            if now >= deadline {
                break match kind {
                    ExecutionCancellation::Timeout => {
                        ExecutionEnd::Reset("VSH exec cancellation timed out")
                    }
                    ExecutionCancellation::Reset(reason) => ExecutionEnd::Reset(reason),
                    ExecutionCancellation::Rebind(reason) => ExecutionEnd::Rebind(reason),
                };
            }
            vibeos_core::exec::yield_now().await;
            continue;
        }
        if now.saturating_sub(started) > EXEC_TIMEOUT_MS {
            cancel.store(true, Ordering::Release);
            cancellation = Some((ExecutionCancellation::Timeout, now + CANCEL_GRACE_MS));
            continue;
        }

        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            cancel.store(true, Ordering::Release);
            cancellation = Some((ExecutionCancellation::Rebind(reason), now + CANCEL_GRACE_MS));
            continue;
        }
        let wire = match bridge.drive(runner, stack, now) {
            Ok(turn) => turn,
            Err(reason) => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if wire.ended {
            cancel.store(true, Ordering::Release);
            cancellation = Some((
                ExecutionCancellation::Reset("peer disconnected during exec"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        let signal = match progress_protocol(runner, signer, space, policy, protocol) {
            Ok(signal) => signal,
            Err(reason) => {
                cancel.store(true, Ordering::Release);
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if matches!(signal, ProtocolSignal::Interrupt) {
            cancel.store(true, Ordering::Release);
        }
        if matches!(signal, ProtocolSignal::Defunct)
            || protocol
                .channel
                .as_ref()
                .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            cancel.store(true, Ordering::Release);
            cancellation = Some((
                ExecutionCancellation::Reset("SSH channel closed during exec"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        if let Err(reason) = discard_channel_input(runner, protocol) {
            cancel.store(true, Ordering::Release);
            cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
            continue;
        }
        cooperate(
            wire.worked
                || matches!(
                    signal,
                    ProtocolSignal::Progressed | ProtocolSignal::Interrupt
                ),
            wire.next_poll_delay_ms,
        )
        .await;
    };
    drop(execution);
    session.shutdown().await;
    outcome
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    future.poll(&mut context)
}

fn collect_execution(
    reports: Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
    timed_out: bool,
) -> (Vec<u8>, u32) {
    if timed_out {
        return (Vec::new(), 124);
    }
    let Ok(reports) = reports else {
        return (Vec::new(), 2);
    };
    let status = reports
        .last()
        .map_or(0, |report| ssh_exit_status(report.status));
    let total = reports.iter().try_fold(0usize, |total, report| {
        total.checked_add(report.output.len())
    });
    let Some(total) = total.filter(|total| *total <= MAX_EXEC_OUTPUT_BYTES) else {
        return (Vec::new(), 124);
    };
    let mut output = Vec::with_capacity(total);
    for report in reports {
        output.extend_from_slice(report.output.as_bytes());
    }
    (output, status)
}

fn ssh_exit_status(status: vibeos_vsh::Status) -> u32 {
    match status {
        vibeos_vsh::Status::Success => 0,
        vibeos_vsh::Status::Returned(status) => status.into(),
        vibeos_vsh::Status::Usage => 2,
        vibeos_vsh::Status::Unavailable => 127,
        vibeos_vsh::Status::Denied => 126,
        vibeos_vsh::Status::BudgetExceeded => 124,
        vibeos_vsh::Status::Faulted => 125,
        vibeos_vsh::Status::Cancelled => 130,
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_exec(
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    output: &[u8],
    status: u32,
    require_carrier: bool,
) -> Result<(), ConnectionEnd> {
    let started = monotonic_ms();
    let mut offset = 0usize;
    let mut exit_sent = false;
    let mut eof_sent = false;
    let mut close_sent = false;

    loop {
        let now = monotonic_ms();
        if now.saturating_sub(started) > CLOSE_TIMEOUT_MS {
            return Err(ConnectionEnd::Reset("SSH completion drain timed out"));
        }
        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            return Err(ConnectionEnd::Rebind(reason));
        }
        let wire = bridge
            .drive(runner, stack, now)
            .map_err(ConnectionEnd::Reset)?;
        if wire.ended {
            return Err(ConnectionEnd::Reset(
                "peer disconnected before SSH completion was acknowledged",
            ));
        }

        let completion_confirmed_before_progress =
            close_sent && protocol.channel.is_none() && runner.is_output_drained();
        let signal = progress_protocol(runner, signer, space, policy, protocol)
            .map_err(ConnectionEnd::Reset)?;
        if matches!(signal, ProtocolSignal::Defunct) {
            // `Defunct` also makes Sunset's convenience closed predicate true.
            // It also discards any still-buffered output. Only state observed
            // before processing that event can therefore prove both the peer's
            // CHANNEL_CLOSE acknowledgement and a complete output drain.
            if completion_confirmed_before_progress {
                return finish_tcp_after_ssh(
                    space,
                    control,
                    bound_epoch,
                    stack,
                    started,
                    require_carrier,
                )
                .await;
            }
            return Err(ConnectionEnd::Reset(
                "SSH peer became defunct before completion was acknowledged",
            ));
        }
        discard_channel_input(runner, protocol).map_err(ConnectionEnd::Reset)?;

        let mut application_work = false;
        if close_sent
            && protocol
                .channel
                .as_ref()
                .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            let channel = protocol
                .channel
                .take()
                .ok_or(ConnectionEnd::Reset("SSH channel ownership was lost"))?;
            runner
                .channel_done(channel)
                .map_err(|_| ConnectionEnd::Reset("SSH channel release failed"))?;
            application_work = true;
        }

        if !close_sent {
            let channel = protocol
                .channel
                .as_ref()
                .ok_or(ConnectionEnd::Reset("accepted session lost its channel"))?;
            if offset < output.len() {
                match runner.write_channel(channel, ChanData::Normal, &output[offset..]) {
                    Ok(0) => {}
                    Ok(written) => {
                        offset += written;
                        application_work = true;
                    }
                    Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => {}
                    Err(_) => return Err(ConnectionEnd::Reset("SSH stdout channel closed")),
                }
            } else if !exit_sent {
                match runner.send_exit_status(channel, status) {
                    Ok(()) => {
                        exit_sent = true;
                        application_work = true;
                    }
                    Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => {}
                    Err(_) => return Err(ConnectionEnd::Reset("SSH exit-status send failed")),
                }
            } else if !eof_sent {
                match runner.send_channel_eof(channel) {
                    Ok(()) => {
                        eof_sent = true;
                        application_work = true;
                    }
                    Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => {}
                    Err(_) => return Err(ConnectionEnd::Reset("SSH EOF send failed")),
                }
            } else {
                match runner.close_channel(channel) {
                    Ok(()) => {
                        close_sent = true;
                        application_work = true;
                    }
                    Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => {}
                    Err(_) => return Err(ConnectionEnd::Reset("SSH channel close send failed")),
                }
            }
        }

        if close_sent && protocol.channel.is_none() && runner.is_output_drained() {
            return finish_tcp_after_ssh(
                space,
                control,
                bound_epoch,
                stack,
                started,
                require_carrier,
            )
            .await;
        }

        cooperate(
            wire.worked || application_work || matches!(signal, ProtocolSignal::Progressed),
            wire.next_poll_delay_ms,
        )
        .await;
    }
}

async fn finish_tcp_after_ssh(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    stack: &mut StaticIpv4TcpStack,
    started: u64,
    require_carrier: bool,
) -> Result<(), ConnectionEnd> {
    let mut discard = [0u8; WIRE_CHUNK_BYTES];
    let mut close_requested = false;

    loop {
        let now = monotonic_ms();
        if now.saturating_sub(started) > CLOSE_TIMEOUT_MS {
            return Err(ConnectionEnd::Reset("SSH completion drain timed out"));
        }
        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            return Err(ConnectionEnd::Rebind(reason));
        }
        let network = stack
            .poll_network(now)
            .map_err(|_| ConnectionEnd::Reset("network stack poll failed during TCP close"))?;
        if stack.is_listening() {
            return Ok(());
        }

        // OpenSSH sends a final encrypted disconnect record before FIN. Once
        // SSH completion is acknowledged that record has no application
        // meaning. Drain it to release bounded receive capacity while TCP
        // retains the old tuple long enough to acknowledge every byte.
        let mut worked = network.more_work || network.ingress_frames != 0;
        for _ in 0..MAX_WIRE_IO_PER_TURN {
            match stack
                .try_recv(&mut discard)
                .map_err(|_| ConnectionEnd::Reset("TCP close receive authority failed"))?
            {
                TcpIoResult::Progress(0) | TcpIoResult::WouldBlock => break,
                TcpIoResult::Progress(_) => worked = true,
                TcpIoResult::Closed => break,
            }
        }

        // Let the peer close first. CLOSE-WAIT -> LAST-ACK -> CLOSED avoids
        // server-side TIME-WAIT and permits the single passive socket to rearm
        // immediately without discarding a delayed ACK for payload+FIN.
        if !close_requested && stack.stream_status().state == TcpStreamState::PeerClosed {
            stack
                .close()
                .map_err(|_| ConnectionEnd::Reset("TCP close failed"))?;
            close_requested = true;
            worked = true;
        }

        cooperate(worked, network.next_poll_delay_ms).await;
    }
}

fn reset_connection(stack: &mut StaticIpv4TcpStack, reason: &'static str) -> ConnectionEnd {
    let _ = stack.reset();
    ConnectionEnd::Reset(reason)
}

fn validate_network_authority(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    require_carrier: bool,
) -> Result<(), &'static str> {
    if space.security_policy_changed() {
        return Err("SSH security policy changed");
    }
    let info = device_info(space, control).ok_or("network control authority was revoked")?;
    if info.quarantined {
        return Err("network device was quarantined");
    }
    if !info.online {
        return Err("network device went offline");
    }
    if require_carrier && !info.phy_link_up {
        return Err("network carrier went down");
    }
    if info.session_epoch != bound_epoch {
        return Err("network device session changed");
    }
    Ok(())
}

fn bind_stack(space: &Space, control: Cap) -> Result<PacketStamp, NetworkBindError> {
    space.bind_stack(control)
}

fn device_info(space: &Space, control: Cap) -> Option<NetworkInfo> {
    space.network_info(control)
}

async fn fetch_entropy(space: &Space, random: Cap, length: usize) -> Result<SecretBytes, ()> {
    space.entropy(random, length).await
}

async fn cooperate(worked: bool, next_poll_delay_ms: Option<u64>) {
    if worked {
        vibeos_core::exec::yield_now().await;
    } else {
        let delay = next_poll_delay_ms
            .unwrap_or(IDLE_POLL_CEILING_MS)
            .clamp(1, IDLE_POLL_CEILING_MS);
        vibeos_core::exec::sleep_ms(delay).await;
    }
}

fn monotonic_ms() -> u64 {
    let hz = vibeos_core::exec::timebase_hz();
    vibeos_core::arch::time().saturating_mul(1_000) / hz
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // Secret cleanup is best-effort on ordinary task teardown; the kernel
        // arena additionally zeroes memory before cross-domain reuse.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}
