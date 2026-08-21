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
use core::future::{poll_fn, Future};
use core::num::NonZeroU64;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::Poll;
#[cfg(any(test, feature = "qualification-stream"))]
use core::task::{Context, Waker};

use sunset::{
    ChanData, ChanFail, ChanHandle, Ed25519HostSigner, Event, PubKey, Runner, ServEvent, Server,
    TerminalSize,
};
use vibeos_component_host::{
    ByteStreamReader, ByteStreamWriter, StreamCloseOutcome, StreamCloseReason, StreamError,
    StreamPreparedReceive, StreamReceiveCommit, StreamReceiveDispatch, StreamSendDispatch,
    MAX_STREAM_CHUNK_BYTES,
};
use vibeos_component_runtime::host::HostOperationToken;
use vibeos_core::cap::{CSpace, Cap, Revocable};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{PacketStamp, StampedPacket};
use vibeos_core::sync::SpinLock;
use vibeos_net_api::{TcpConnectionToken, TcpListenerSnapshot};
pub use vibeos_net_protocol::{
    command::{
        parse_dhclient_command, parse_ip_command, DhclientCommand, IpCommand, Ipv4Method,
        NetworkConfiguration, PRIMARY_INTERFACE,
    },
    Ipv4RuntimeStatus, StaticIpv4Address,
};
use vibeos_net_protocol::{
    StaticIpv4Config, StaticIpv4TcpStack, TcpIoResult, TcpPollReport, TcpStreamState,
    TcpStreamStatus,
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
    fn tcp_listener_snapshot(&self, _listener: Cap) -> Option<TcpListenerSnapshot> {
        None
    }
    fn tcp_accept(&self, _listener: Cap) -> Result<Option<TcpConnectionToken>, ()> {
        Err(())
    }
    fn tcp_recv(
        &self,
        _listener: Cap,
        _connection: TcpConnectionToken,
        _output: &mut [u8],
    ) -> Result<TcpIoResult, ()> {
        Err(())
    }
    fn tcp_send(
        &self,
        _listener: Cap,
        _connection: TcpConnectionToken,
        _input: &[u8],
    ) -> Result<TcpIoResult, ()> {
        Err(())
    }
    fn tcp_close(&self, _listener: Cap, _connection: TcpConnectionToken) -> Result<(), ()> {
        Err(())
    }
    fn tcp_reset(&self, _listener: Cap, _connection: TcpConnectionToken) -> Result<(), ()> {
        Err(())
    }
    fn network_ipv4_status(&self, _listener: Cap) -> Option<Ipv4RuntimeStatus> {
        None
    }
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
    fn ipv4_configuration(&self, fallback: Ipv4Policy) -> (u64, NetworkConfiguration) {
        let method = match fallback {
            Ipv4Policy::Static(address) => Ipv4Method::Static(address),
            Ipv4Policy::Dhcp { .. } => Ipv4Method::Dhcp,
        };
        (
            0,
            NetworkConfiguration {
                link_up: true,
                method,
            },
        )
    }
    fn acknowledge_ipv4_configuration(&self, _revision: u64, _status: Ipv4RuntimeStatus) {}
    fn publish_ipv4_status(&self, _status: Ipv4RuntimeStatus) {}
    fn ipv4_configuration_changed(&self) -> bool {
        false
    }
    fn install_vsh_commands(&self, session: &mut vibeos_vsh::Session, onboarding: bool);
    /// Explicit per-connection hook for image-policy-pinned Component commands
    /// admitted to the restricted SSH exec profile. The default installs
    /// nothing; it is never called for onboarding credentials or interactive
    /// PTY sessions. An implementation must re-read its policy atomically and
    /// match this complete captured descriptor immediately before installing
    /// anything; the runner pin alone is not authentication authority. A
    /// rotation between the protocol's check and this hook must fail closed.
    /// `io` is the non-cloneable component-facing half created only for this
    /// accepted request. A managed installer must consume it in
    /// `Session::install_ssh_exec_managed_component_io` during the same exact
    /// policy transaction; it must never retain or expose it elsewhere.
    fn install_ssh_exec_component_commands(
        &self,
        _session: &mut vibeos_vsh::Session,
        _policy: SshExecComponentSessionPolicy,
        _io: vibeos_vsh::SshExecComponentIoInstall,
    ) -> Result<(), vibeos_vsh::Diagnostic> {
        Ok(())
    }
    /// Return the exact image/session-policy Component descriptor admitted for
    /// this already committed profile. The default exposes nothing. The
    /// protocol copies it into the accepted exec request, then compares all
    /// fields again before invoking the independent installation hook.
    fn ssh_exec_component_policy(
        &self,
        _profile: AuthorizedProfile,
    ) -> Option<SshExecComponentSessionPolicy> {
        None
    }
    /// Select one exact Component descriptor for this raw exec request.
    /// Platforms with multiple independently pinned commands override this
    /// method; the compatibility default preserves the original single-slot
    /// policy and still applies the exact VSH grammar/name gate.
    fn select_ssh_exec_component_policy(
        &self,
        profile: AuthorizedProfile,
        source: &str,
    ) -> Option<SshExecComponentSessionPolicy> {
        self.ssh_exec_component_policy(profile).filter(|policy| {
            vibeos_vsh::validate_ssh_exec_with_component_name(source, policy.command_name())
                == Ok(true)
        })
    }
    /// Observe one exact policy-selected Component only after VSH shutdown and
    /// the SSH exit-status/EOF/CLOSE exchange have fully drained. Production
    /// platforms need no completion observer; target gates can correlate this
    /// descriptor and status with private lifecycle evidence.
    fn ssh_exec_component_completed(&self, _policy: SshExecComponentSessionPolicy, _status: u32) {}
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

/// One image-selected Component command bound to an exact authorized SSH
/// profile incarnation. Both exec-request acknowledgement and session-local
/// installation consume this same descriptor so the two gates cannot select
/// different names, artifacts, profile generations, or policy incarnations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SshExecComponentSessionPolicy {
    profile: AuthorizedProfile,
    incarnation: NonZeroU64,
    command_name: &'static str,
    artifact_sha256: [u8; 32],
}

impl SshExecComponentSessionPolicy {
    pub const fn new(
        profile: AuthorizedProfile,
        incarnation: NonZeroU64,
        command_name: &'static str,
        artifact_sha256: [u8; 32],
    ) -> Self {
        Self {
            profile,
            incarnation,
            command_name,
            artifact_sha256,
        }
    }

    pub const fn profile(self) -> AuthorizedProfile {
        self.profile
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn incarnation(self) -> NonZeroU64 {
        self.incarnation
    }

    pub const fn artifact_sha256(self) -> [u8; 32] {
        self.artifact_sha256
    }

    fn matches(self, profile: AuthorizedProfile) -> bool {
        self.profile == profile
    }
}

impl fmt::Debug for SshExecComponentSessionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshExecComponentSessionPolicy")
            .field("profile", &self.profile)
            .field("incarnation", &self.incarnation)
            .field("command_name", &self.command_name)
            .field("artifact_sha256", &"<redacted>")
            .finish()
    }
}

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
    Exec(String, Option<SshExecComponentSessionPolicy>),
    Shell,
    Interrupt,
    Defunct,
}

enum SessionStart {
    Exec(String, Option<SshExecComponentSessionPolicy>),
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

trait TcpTransport: Send {
    fn poll_network(&mut self, now_ms: u64) -> Result<TcpPollReport, ()>;
    fn stream_status(&self) -> TcpStreamStatus;
    fn try_recv(&mut self, output: &mut [u8]) -> Result<TcpIoResult, ()>;
    fn try_send(&mut self, input: &[u8]) -> Result<TcpIoResult, ()>;
    fn close(&mut self) -> Result<TcpStreamState, ()>;
    fn reset(&mut self) -> Result<TcpStreamState, ()>;
    fn is_listening(&self) -> bool;
    fn ipv4_status(&self) -> Ipv4RuntimeStatus;
}

impl TcpTransport for StaticIpv4TcpStack {
    fn poll_network(&mut self, now_ms: u64) -> Result<TcpPollReport, ()> {
        StaticIpv4TcpStack::poll_network(self, now_ms).map_err(|_| ())
    }

    fn stream_status(&self) -> TcpStreamStatus {
        StaticIpv4TcpStack::stream_status(self)
    }

    fn try_recv(&mut self, output: &mut [u8]) -> Result<TcpIoResult, ()> {
        StaticIpv4TcpStack::try_recv(self, output).map_err(|_| ())
    }

    fn try_send(&mut self, input: &[u8]) -> Result<TcpIoResult, ()> {
        StaticIpv4TcpStack::try_send(self, input).map_err(|_| ())
    }

    fn close(&mut self) -> Result<TcpStreamState, ()> {
        StaticIpv4TcpStack::close(self).map_err(|_| ())
    }

    fn reset(&mut self) -> Result<TcpStreamState, ()> {
        StaticIpv4TcpStack::reset(self).map_err(|_| ())
    }

    fn is_listening(&self) -> bool {
        StaticIpv4TcpStack::is_listening(self)
    }

    fn ipv4_status(&self) -> Ipv4RuntimeStatus {
        StaticIpv4TcpStack::ipv4_status(self)
    }
}

struct CapabilityTcpTransport<'a> {
    space: &'a Space,
    listener: Cap,
    connection: Option<TcpConnectionToken>,
    ipv4_status: Ipv4RuntimeStatus,
}

impl<'a> CapabilityTcpTransport<'a> {
    fn new(space: &'a Space, listener: Cap, ipv4_status: Ipv4RuntimeStatus) -> Result<Self, ()> {
        let _snapshot = space.tcp_listener_snapshot(listener).ok_or(())?;
        Ok(Self {
            space,
            listener,
            connection: None,
            ipv4_status,
        })
    }

    fn snapshot(&self) -> Option<TcpListenerSnapshot> {
        self.space.tcp_listener_snapshot(self.listener)
    }
}

impl TcpTransport for CapabilityTcpTransport<'_> {
    fn poll_network(&mut self, _now_ms: u64) -> Result<TcpPollReport, ()> {
        let mut snapshot = self.snapshot().ok_or(())?;
        let mut connection_started = false;
        if self.connection.is_none()
            && matches!(
                snapshot.state,
                TcpStreamState::Established | TcpStreamState::PeerClosed
            )
        {
            self.connection = self.space.tcp_accept(self.listener)?;
            connection_started = self.connection.is_some();
            snapshot = self.snapshot().ok_or(())?;
        }
        let connection_ended = self.connection.is_some()
            && matches!(
                snapshot.state,
                TcpStreamState::Listening | TcpStreamState::Reset | TcpStreamState::Closed
            );
        if connection_ended {
            self.connection = None;
        }
        Ok(TcpPollReport {
            ingress_frames: 0,
            connection_started,
            connection_ended,
            more_work: snapshot.readable_bytes != 0
                || (snapshot.queued_send_bytes != 0 && snapshot.writable_bytes != 0),
            next_poll_delay_ms: Some(IDLE_POLL_CEILING_MS),
        })
    }

    fn stream_status(&self) -> TcpStreamStatus {
        self.snapshot().map_or(
            TcpStreamStatus {
                state: TcpStreamState::Closed,
                readable_bytes: 0,
                queued_send_bytes: 0,
                writable_bytes: 0,
            },
            |snapshot| TcpStreamStatus {
                state: snapshot.state,
                readable_bytes: snapshot.readable_bytes,
                queued_send_bytes: snapshot.queued_send_bytes,
                writable_bytes: snapshot.writable_bytes,
            },
        )
    }

    fn try_recv(&mut self, output: &mut [u8]) -> Result<TcpIoResult, ()> {
        let connection = self.connection.ok_or(())?;
        self.space.tcp_recv(self.listener, connection, output)
    }

    fn try_send(&mut self, input: &[u8]) -> Result<TcpIoResult, ()> {
        let connection = self.connection.ok_or(())?;
        self.space.tcp_send(self.listener, connection, input)
    }

    fn close(&mut self) -> Result<TcpStreamState, ()> {
        if let Some(connection) = self.connection {
            self.space.tcp_close(self.listener, connection)?;
        }
        Ok(TcpStreamState::Closing)
    }

    fn reset(&mut self) -> Result<TcpStreamState, ()> {
        if let Some(connection) = self.connection {
            self.space.tcp_reset(self.listener, connection)?;
        }
        Ok(TcpStreamState::Reset)
    }

    fn is_listening(&self) -> bool {
        self.snapshot()
            .is_some_and(|snapshot| snapshot.state == TcpStreamState::Listening)
    }

    fn ipv4_status(&self) -> Ipv4RuntimeStatus {
        self.space
            .network_ipv4_status(self.listener)
            .unwrap_or(self.ipv4_status)
    }
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
        stack: &mut dyn TcpTransport,
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

impl ExecutionCancellation {
    fn after_managed_completion(self) -> ExecutionEnd {
        match self {
            Self::Reset(reason) => ExecutionEnd::Reset(reason),
            Self::Rebind(reason) => ExecutionEnd::Rebind(reason),
            Self::Timeout => ExecutionEnd::Reset(
                "SSH Component cancellation state survived immutable completion",
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct PendingComponentInput {
    operation: HostOperationToken,
    bytes: [u8; MAX_STREAM_CHUNK_BYTES],
    length: usize,
}

struct PendingComponentOutput {
    bytes: [u8; MAX_STREAM_CHUNK_BYTES],
    length: usize,
    offset: usize,
}

/// The SSH-owned half of one admitted Component transport.
///
/// This object deliberately retains only the pump endpoints. It never owns a
/// supervisor, component-facing endpoint, CSpace, or registry handle. A full
/// stdin queue leaves exactly one copied chunk here and stops Sunset reads.
/// A partially written stdout chunk likewise remains here until Sunset has
/// accepted every byte; no later stream receive is started in the meantime.
struct ComponentStreamPump {
    stdin: Arc<ByteStreamWriter>,
    stdout: Arc<ByteStreamReader>,
    stdin_pending: Option<PendingComponentInput>,
    stdin_source_closed: bool,
    stdout_waiting: Option<HostOperationToken>,
    stdout_pending: Option<PendingComponentOutput>,
    stdout_terminal: Option<StreamCloseReason>,
}

impl ComponentStreamPump {
    fn new(io: vibeos_vsh::SshExecComponentIoPump) -> Self {
        Self::from_endpoints(io.stdin().clone(), io.stdout().clone())
    }

    fn from_endpoints(stdin: Arc<ByteStreamWriter>, stdout: Arc<ByteStreamReader>) -> Self {
        Self {
            stdin,
            stdout,
            stdin_pending: None,
            stdin_source_closed: false,
            stdout_waiting: None,
            stdout_pending: None,
            stdout_terminal: None,
        }
    }

    fn has_pending_stdin(&self) -> bool {
        self.stdin_pending.is_some()
    }

    fn stdin_source_closed(&self) -> bool {
        self.stdin_source_closed
    }

    fn send_stdin(&mut self, bytes: &[u8]) -> Result<bool, &'static str> {
        if self.stdin_source_closed {
            return Err("SSH Component stdin was already closed");
        }
        if self.stdin_pending.is_some() {
            return Err("SSH Component stdin backpressure state was overwritten");
        }
        if bytes.is_empty() || bytes.len() > MAX_STREAM_CHUNK_BYTES {
            return Err("SSH Component stdin chunk was invalid");
        }
        let mut retained = [0u8; MAX_STREAM_CHUNK_BYTES];
        retained[..bytes.len()].copy_from_slice(bytes);
        match self.stdin.start(bytes).map_err(component_stream_error)? {
            StreamSendDispatch::Sent => Ok(true),
            StreamSendDispatch::Waiting(operation) => {
                self.stdin_pending = Some(PendingComponentInput {
                    operation,
                    bytes: retained,
                    length: bytes.len(),
                });
                Ok(false)
            }
            StreamSendDispatch::Closed(_) => {
                self.stdin_source_closed = true;
                Ok(true)
            }
        }
    }

    /// Retry one exact waiting send. The stream returns a fresh opaque token
    /// when it remains full. SSHD has no safe way to manufacture the kernel's
    /// four-word continuation wake, so the enclosing task calls this only
    /// after its existing bounded network/deadline wait (at most 10ms), never
    /// in a spin loop.
    fn retry_stdin(&mut self) -> Result<bool, &'static str> {
        let Some(pending) = self.stdin_pending else {
            return Ok(false);
        };
        match self
            .stdin
            .resume(pending.operation, &pending.bytes[..pending.length])
            .map_err(component_stream_error)?
        {
            StreamSendDispatch::Sent => {
                self.stdin_pending = None;
                Ok(true)
            }
            StreamSendDispatch::Waiting(operation) => {
                self.stdin_pending = Some(PendingComponentInput {
                    operation,
                    ..pending
                });
                Ok(false)
            }
            StreamSendDispatch::Closed(_) => {
                self.stdin_pending = None;
                self.stdin_source_closed = true;
                Ok(true)
            }
        }
    }

    fn close_stdin_normal(&mut self) -> Result<bool, &'static str> {
        if self.stdin_source_closed {
            return Ok(false);
        }
        if self.stdin_pending.is_some() {
            return Err("SSH Component stdin EOF raced a retained chunk");
        }
        match self.stdin.close(StreamCloseReason::Normal) {
            StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished => {
                self.stdin_source_closed = true;
                Ok(true)
            }
            StreamCloseOutcome::Conflict => Err("SSH Component stdin close conflicted"),
        }
    }

    fn poll_stdout(&mut self) -> Result<bool, &'static str> {
        if self.stdout_pending.is_some() || self.stdout_terminal.is_some() {
            return Ok(false);
        }
        let dispatch = match self.stdout_waiting.take() {
            Some(operation) => self
                .stdout
                .resume(operation)
                .map_err(component_stream_error)?,
            None => self.stdout.start().map_err(component_stream_error)?,
        };
        match dispatch {
            StreamReceiveDispatch::Waiting(operation) => {
                self.stdout_waiting = Some(operation);
                Ok(false)
            }
            StreamReceiveDispatch::Prepared(prepared) => self.commit_stdout(prepared),
            StreamReceiveDispatch::Closed(reason) => {
                self.stdout_terminal = Some(reason);
                Ok(true)
            }
        }
    }

    fn commit_stdout(&mut self, prepared: StreamPreparedReceive) -> Result<bool, &'static str> {
        let length = prepared.length();
        if length == 0 || length > MAX_STREAM_CHUNK_BYTES {
            let _ = self.stdout.cancel(prepared.operation());
            return Err("SSH Component stdout prepared an invalid chunk");
        }
        let mut bytes = [0u8; MAX_STREAM_CHUNK_BYTES];
        match self
            .stdout
            .commit(prepared.operation(), &mut bytes[..length])
            .map_err(component_stream_error)?
        {
            StreamReceiveCommit::Received(received) if received == length => {
                self.stdout_pending = Some(PendingComponentOutput {
                    bytes,
                    length,
                    offset: 0,
                });
                Ok(true)
            }
            StreamReceiveCommit::Received(_) => Err("SSH Component stdout commit length changed"),
            StreamReceiveCommit::Closed(reason) => {
                // A non-normal supervisor terminal invalidates the prepared
                // reservation but deliberately leaves its exact operation
                // installed until the consumer cancels it. Consume that
                // operation before publishing the terminal to the pump so a
                // retained reader can never remain permanently Busy.
                self.stdout
                    .cancel(prepared.operation())
                    .map_err(component_stream_error)?;
                self.stdout_terminal = Some(reason);
                Ok(true)
            }
        }
    }

    fn pending_stdout(&self) -> &[u8] {
        self.stdout_pending.as_ref().map_or(&[], |pending| {
            &pending.bytes[pending.offset..pending.length]
        })
    }

    fn consume_stdout(&mut self, length: usize) -> Result<bool, &'static str> {
        let Some(pending) = self.stdout_pending.as_mut() else {
            return Err("SSH Component stdout accounting had no pending chunk");
        };
        let remaining = pending.length - pending.offset;
        if length == 0 || length > remaining {
            return Err("SSH Component stdout accounting exceeded its chunk");
        }
        pending.offset += length;
        if pending.offset == pending.length {
            self.stdout_pending = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn stdout_terminal(&self) -> Option<StreamCloseReason> {
        self.stdout_terminal
    }

    /// Detach transport-local operations after the SYSTEM lifecycle has
    /// already published the exact terminal.
    ///
    /// Stdin is source-owned and may have reached immutable Normal EOF before
    /// the component later returned or faulted. Do not overwrite that valid
    /// directional close with the component's stdout terminal reason.
    fn finish_after_lifecycle(&mut self, reason: StreamCloseReason) -> Result<(), &'static str> {
        if let Some(pending) = self.stdin_pending.take() {
            let _ = self.stdin.cancel(pending.operation);
        }
        if let Some(operation) = self.stdout_waiting.take() {
            let _ = self.stdout.cancel(operation);
        }
        self.stdout_pending = None;
        self.stdin_source_closed = true;
        if matches!(self.stdout.close(reason), StreamCloseOutcome::Conflict) {
            return Err("SSH Component stdout terminal reason conflicted");
        }
        self.stdout_terminal = Some(reason);
        Ok(())
    }
}

fn component_stream_error(error: StreamError) -> &'static str {
    match error {
        StreamError::InvalidChunk => "SSH Component stream rejected a chunk",
        StreamError::Busy => "SSH Component stream operation overlapped",
        StreamError::TokenMismatch => "SSH Component stream token changed",
        StreamError::WakeAlreadyRegistered => "SSH Component stream wake was duplicated",
        StreamError::InvalidCommitLength => "SSH Component stream commit length was invalid",
        StreamError::EndpointClosed => "SSH Component stream endpoint closed unexpectedly",
        StreamError::TokenExhausted => "SSH Component stream token space was exhausted",
        StreamError::FailStopped => "SSH Component stream fail-stopped",
    }
}

/// Signal cancellation without guessing which terminal wins the race.
///
/// The managed instance may already have committed Success, Returned, or a
/// fault on another hart. Freezing the pump streams to Cancelled here would
/// conflict with that immutable terminal. The cancellation wait therefore
/// stops driving transport, observes the lifecycle's exact report, and only
/// then calls [`reconcile_managed_component_cancel`].
fn request_managed_component_cancel(cancel: &vibeos_vsh::CancellationSignal) {
    cancel.cancel();
}

/// Arm cancellation only while the nested execution can still make progress.
///
/// Once the exact lifecycle report has been stored, the execution future is
/// fused by ownership rather than by its implementation: it must never be
/// polled again. Transport failures during the bounded stdout drain therefore
/// end the connection directly and leave the immutable component terminal
/// untouched.
fn arm_managed_component_cancellation(
    completion_ready: bool,
    cancel: &vibeos_vsh::CancellationSignal,
    cancellation: &mut Option<(ExecutionCancellation, u64)>,
    kind: ExecutionCancellation,
    deadline: u64,
) -> Option<ExecutionEnd> {
    if completion_ready {
        return Some(kind.after_managed_completion());
    }
    request_managed_component_cancel(cancel);
    *cancellation = Some((kind, deadline));
    None
}

fn reconcile_managed_component_cancel(
    pump: &mut ComponentStreamPump,
    reports: &Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
) -> Result<vibeos_vsh::ComponentTerminal, &'static str> {
    let terminal = managed_component_terminal(reports)
        .ok_or("SSH Component cancellation published no exact terminal")?;
    let reason = terminal.stream_close_reason();
    pump.finish_after_lifecycle(reason)?;
    if pump.stdout_terminal() != Some(reason) {
        return Err("SSH Component cancellation terminal was not stable");
    }
    Ok(terminal)
}

enum ManagedComponentCancelCompletion {
    End(ExecutionEnd),
    Drain {
        reports: Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
        terminal: vibeos_vsh::ComponentTerminal,
    },
}

fn complete_managed_component_cancel(
    kind: ExecutionCancellation,
    reports: Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
    pump: &mut ComponentStreamPump,
) -> ManagedComponentCancelCompletion {
    let Some(terminal) = managed_component_terminal(&reports) else {
        return ManagedComponentCancelCompletion::End(ExecutionEnd::Reset(
            "SSH Component cancellation published no exact terminal",
        ));
    };
    if matches!(kind, ExecutionCancellation::Timeout)
        && terminal != vibeos_vsh::ComponentTerminal::Cancelled
    {
        // The immutable completion won at the deadline boundary. Resume the
        // ordinary stdout drain instead of silently dropping its final bytes.
        return ManagedComponentCancelCompletion::Drain { reports, terminal };
    }
    if let Err(reason) = reconcile_managed_component_cancel(pump, &reports) {
        return ManagedComponentCancelCompletion::End(ExecutionEnd::Reset(reason));
    }
    ManagedComponentCancelCompletion::End(match kind {
        ExecutionCancellation::Timeout => ExecutionEnd::Complete {
            reports,
            timed_out: true,
        },
        ExecutionCancellation::Reset(reason) => ExecutionEnd::Reset(reason),
        ExecutionCancellation::Rebind(reason) => ExecutionEnd::Rebind(reason),
    })
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

/// Serve SSH through a pre-authorized TCP listener owned by the independent
/// netstack component. This entry point receives no packet endpoint, device
/// control capability, address configuration authority, or TCP seed.
pub async fn capability_task(
    space: &Space,
    service_policy: SshServicePolicy,
    listener: Cap,
    random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    authorization_policy: Cap,
) {
    let ipv4_status = match service_policy.ipv4 {
        Ipv4Policy::Static(address) => Ipv4RuntimeStatus::Static(address),
        Ipv4Policy::Dhcp { .. } => Ipv4RuntimeStatus::DhcpDiscovering,
    };
    let mut stack = match CapabilityTcpTransport::new(space, listener, ipv4_status) {
        Ok(stack) => stack,
        Err(()) => {
            component_log!(space, "FAIL ssh-test: TCP listener authority unavailable");
            return;
        }
    };
    let mut announced_ipv4 = None;
    if let Err(reason) = announce_listener(
        space,
        listener,
        0,
        &mut stack,
        &mut announced_ipv4,
        service_policy,
    )
    .await
    {
        component_log!(space, "FAIL ssh-test: {reason}");
        return;
    }

    loop {
        let entropy = match fetch_entropy(space, random, SEED_BYTES).await {
            Ok(entropy) => entropy,
            Err(_) => {
                component_log!(space, "FAIL ssh-test: SSH random source unavailable");
                return;
            }
        };
        let mut connection_seed = [0u8; SEED_BYTES];
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

        if let Err(reason) = wait_for_connection(
            space,
            listener,
            0,
            &mut stack,
            &mut announced_ipv4,
            service_policy,
        )
        .await
        {
            wipe(&mut connection_seed);
            component_log!(space, "ssh-test listener unavailable: {reason}");
            return;
        }

        let outcome = serve_connection(
            space,
            listener,
            0,
            signer_read,
            signer_invoke,
            authorization_policy,
            &mut stack,
            connection_seed,
            false,
        )
        .await;
        match outcome {
            ConnectionEnd::ExecComplete(status) => {
                component_log!(space, "ssh-test exec complete: status {status}");
            }
            ConnectionEnd::ShellComplete(status) => {
                component_log!(space, "ssh-test shell complete: status {status}");
            }
            ConnectionEnd::Reset(reason) | ConnectionEnd::Rebind(reason) => {
                let _ = stack.reset();
                component_log!(space, "ssh-test connection reset: {reason}");
            }
        }

        if space.security_policy_changed() {
            component_log!(space, "SSH security policy changed; restarting listener");
            return;
        }
        if let Err(reason) = rearm_listener(&mut stack).await {
            component_log!(space, "ssh-test listener rearm failed: {reason}");
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
                let (revision, desired) = space.ipv4_configuration(policy.ipv4);
                let address = match desired.method {
                    Ipv4Method::Static(address) => address,
                    Ipv4Method::None | Ipv4Method::Dhcp => policy.ipv4.initial_address(),
                };
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
                if !desired.link_up {
                    stack
                        .clear_ipv4()
                        .map_err(|_| "IPv4 link-down setup failed")?;
                } else {
                    match desired.method {
                        Ipv4Method::None => stack
                            .clear_ipv4()
                            .map_err(|_| "IPv4 unconfigured setup failed")?,
                        Ipv4Method::Static(address) => stack
                            .configure_static_ipv4(address)
                            .map_err(|_| "static IPv4 setup failed")?,
                        Ipv4Method::Dhcp => stack
                            .start_dhcp()
                            .map_err(|_| "DHCP client initialization failed")?,
                    }
                }
                space.acknowledge_ipv4_configuration(revision, stack.ipv4_status());
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
    stack: &mut dyn TcpTransport,
    announced_ipv4: &mut Option<[u8; 4]>,
    policy: SshServicePolicy,
) -> Result<(), &'static str> {
    if update_listener_announcement(space, stack, announced_ipv4, policy) {
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
    stack: &mut dyn TcpTransport,
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

async fn rearm_listener(stack: &mut dyn TcpTransport) -> Result<(), &'static str> {
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
    stack: &dyn TcpTransport,
    announced_ipv4: &mut Option<[u8; 4]>,
    policy: SshServicePolicy,
) -> bool {
    let status = stack.ipv4_status();
    space.publish_ipv4_status(status);
    let address = match status {
        Ipv4RuntimeStatus::Static(address) | Ipv4RuntimeStatus::DhcpBound(address) => {
            Some(address.address)
        }
        Ipv4RuntimeStatus::Unconfigured | Ipv4RuntimeStatus::DhcpDiscovering => None,
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
    stack: &mut dyn TcpTransport,
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
            ProtocolSignal::Exec(command, component) => {
                break SessionStart::Exec(command, component);
            }
            ProtocolSignal::Shell => break SessionStart::Shell,
            ProtocolSignal::Interrupt => pending_input.signal_interrupt = true,
            ProtocolSignal::Defunct => {
                return ConnectionEnd::Reset("SSH peer disconnected before session start");
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
        SessionStart::Exec(command, accepted_component) => {
            #[cfg(feature = "qualification-stream")]
            if let Some(opened) = accepted_component
                .is_none()
                .then(|| space.open_streaming_exec(&command))
                .flatten()
            {
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
                            return reset_connection(stack, reason);
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
                accepted_component,
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
                Ok(()) => {
                    if let Some(component) = accepted_component {
                        space.ssh_exec_component_completed(component, status);
                    }
                    ConnectionEnd::ExecComplete(status)
                }
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
    stack: &mut dyn TcpTransport,
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
                        let accepted_component = accepted_ssh_component_policy(
                            space,
                            candidate.profile,
                            matches!(candidate.credential, AuthCredential::PublicKey(_)),
                            &value,
                        );
                        if vibeos_vsh::validate_ssh_exec(&value).is_ok()
                            || accepted_component.is_some()
                            || {
                                #[cfg(feature = "qualification-stream")]
                                {
                                    space.accepts_streaming_exec(&value)
                                }
                                #[cfg(not(feature = "qualification-stream"))]
                                {
                                    false
                                }
                            }
                        {
                            command = Some((value, accepted_component));
                        }
                    }
                }
                if let Some((command, accepted_component)) = command {
                    event
                        .succeed()
                        .map_err(|_| "exec acceptance response failed")?;
                    return Ok(ProtocolSignal::Exec(command, accepted_component));
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

fn accepted_ssh_component_policy(
    space: &Space,
    profile: AuthorizedProfile,
    public_key_credential: bool,
    source: &str,
) -> Option<SshExecComponentSessionPolicy> {
    if !public_key_credential {
        return None;
    }
    space
        .select_ssh_exec_component_policy(profile, source)
        .filter(|policy| policy.matches(profile))
        .filter(|policy| {
            vibeos_vsh::validate_ssh_exec_with_component_name(source, policy.command_name())
                == Ok(true)
        })
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

fn pump_component_stdin_turn(
    pump: &mut ComponentStreamPump,
    runner: &mut Runner<'_, Server>,
    state: &ProtocolState,
) -> Result<bool, &'static str> {
    if pump.stdin_source_closed() {
        return Ok(false);
    }
    let mut worked = false;
    if pump.has_pending_stdin() {
        if !pump.retry_stdin()? {
            // This is a readiness retry, not useful work. The enclosing loop
            // will take its bounded network/deadline sleep before trying the
            // fresh exact operation token returned by the stream.
            return Ok(false);
        }
        worked = true;
        if pump.stdin_source_closed() {
            // The component may terminalize while the ninth chunk is waiting
            // behind a full ring. `resume` then consumes the exact wait token
            // as Closed, not as a successful send. Stop before asking Sunset
            // for another channel-data slice so a legitimate Failure or
            // Cancelled terminal cannot be downgraded to a transport reset.
            return Ok(true);
        }
    }

    let mut chunk = [0u8; MAX_STREAM_CHUNK_BYTES];
    for _ in 0..MAX_CHANNEL_DISCARDS_PER_TURN {
        let Some((number, data, ready)) = runner.read_channel_ready() else {
            break;
        };
        let channel = state
            .channel
            .as_ref()
            .ok_or("data arrived without an accepted Component channel")?;
        if channel.num() != number {
            return Err("data arrived on an unowned Component channel");
        }
        if data != ChanData::Normal {
            return Err("extended data is not valid Component stdin");
        }
        let length = ready.min(chunk.len());
        let read = runner
            .read_channel(channel, ChanData::Normal, &mut chunk[..length])
            .map_err(|_| "failed to read SSH Component stdin")?;
        if read == 0 {
            break;
        }
        worked = true;
        if !pump.send_stdin(&chunk[..read])? || pump.stdin_source_closed() {
            // At most the chunk which discovered a full ring is retained.
            // Do not consume another Sunset channel-data byte until it is
            // accepted by the exact stream operation.
            break;
        }
    }

    if !pump.stdin_source_closed() && !pump.has_pending_stdin() {
        let channel = state
            .channel
            .as_ref()
            .ok_or("accepted Component session lost its channel")?;
        if runner.read_channel_ready().is_none() && runner.is_channel_eof(channel) {
            // Normal is intentionally only provisional here. The stable
            // lifecycle owns the supervisors and, after its exact CSpace
            // revalidation, promotes drained stdin to immutable Normal and
            // wakes the guest's current read operation.
            worked |= pump.close_stdin_normal()?;
        }
    }
    Ok(worked)
}

fn pump_component_stdout_turn(
    pump: &mut ComponentStreamPump,
    runner: &mut Runner<'_, Server>,
    state: &ProtocolState,
) -> Result<bool, &'static str> {
    let mut worked = false;
    if !pump.pending_stdout().is_empty() {
        let channel = state
            .channel
            .as_ref()
            .ok_or("accepted Component session lost its channel")?;
        match runner.write_channel(channel, ChanData::Normal, pump.pending_stdout()) {
            Ok(0) => {}
            Ok(written) => {
                pump.consume_stdout(written)?;
                worked = true;
            }
            Err(sunset::Error::NoRoom { .. } | sunset::Error::BusySend { .. }) => {}
            Err(_) => return Err("SSH Component stdout channel closed"),
        }
    }
    if pump.pending_stdout().is_empty() && pump.stdout_terminal().is_none() {
        worked |= pump.poll_stdout()?;
    }
    Ok(worked)
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
    stack: &mut dyn TcpTransport,
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
        ProtocolSignal::Exec(_, _) | ProtocolSignal::Shell => {
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
    stack: &mut dyn TcpTransport,
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
    cancel: &vibeos_vsh::CancellationSignal,
) -> Result<bool, &'static str> {
    if input.signal_interrupt {
        cancel.cancel();
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
    cancel.cancel();
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
    stack: &mut dyn TcpTransport,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>, ConnectionEnd> {
    let cancel = Arc::new(vibeos_vsh::CancellationSignal::new());
    // Ordinary bytes queued after Enter remain typeahead for the next prompt.
    // Ctrl-C is different: SSH byte ordering proves every queued byte follows
    // the submitted line, so it must interrupt the command even when both
    // arrived in one channel-data packet.
    let mut execution = Box::pin(session.execute_cancellable(command, cancel.clone()));
    let mut cancellation: Option<(ExecutionCancellation, u64)> = None;
    let mut transport_eof_deadline = None;
    let mut completed = None;

    loop {
        if let Some((kind, deadline)) = cancellation {
            if completed.is_none() {
                match wait_for_execution_or(
                    execution.as_mut(),
                    vibeos_core::exec::sleep_ms(deadline.saturating_sub(monotonic_ms())),
                )
                .await
                {
                    ExecutionWait::Complete(_reports) => {
                        return match kind {
                            ExecutionCancellation::Reset(reason) => {
                                Err(ConnectionEnd::Reset(reason))
                            }
                            ExecutionCancellation::Rebind(reason) => {
                                Err(ConnectionEnd::Rebind(reason))
                            }
                            ExecutionCancellation::Timeout => {
                                Err(ConnectionEnd::Reset("unexpected shell execution timeout"))
                            }
                        };
                    }
                    ExecutionWait::DelayElapsed => {
                        return Err(match kind {
                            ExecutionCancellation::Reset(reason) => ConnectionEnd::Reset(reason),
                            ExecutionCancellation::Rebind(reason) => ConnectionEnd::Rebind(reason),
                            ExecutionCancellation::Timeout => {
                                ConnectionEnd::Reset("unexpected shell execution timeout")
                            }
                        });
                    }
                }
            }
            if completed.is_some() {
                return Err(match kind {
                    ExecutionCancellation::Reset(reason) => ConnectionEnd::Reset(reason),
                    ExecutionCancellation::Rebind(reason) => ConnectionEnd::Rebind(reason),
                    ExecutionCancellation::Timeout => {
                        ConnectionEnd::Reset("unexpected shell execution timeout")
                    }
                });
            }
            continue;
        }

        let controls_rendered = mark_running_interrupts(frontend, input, cancel.as_ref())
            .map_err(ConnectionEnd::Reset)?;
        if controls_rendered {
            if let Some(reports) = completed.take() {
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
            cancel.cancel();
            cancellation = Some((ExecutionCancellation::Rebind(reason), now + CANCEL_GRACE_MS));
            continue;
        }
        let wire = match bridge.drive(runner, stack, now) {
            Ok(turn) => turn,
            Err(reason) => {
                cancel.cancel();
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if wire.ended {
            cancel.cancel();
            cancellation = Some((
                ExecutionCancellation::Reset("peer disconnected during SSH shell command"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        let signal = match progress_protocol(runner, signer, space, policy, protocol) {
            Ok(signal) => signal,
            Err(reason) => {
                cancel.cancel();
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        match signal {
            ProtocolSignal::Interrupt => {
                input.signal_interrupt = true;
                cancel.cancel();
            }
            ProtocolSignal::Defunct => {
                cancel.cancel();
                cancellation = Some((
                    ExecutionCancellation::Reset("SSH shell became defunct during command"),
                    now + CANCEL_GRACE_MS,
                ));
                continue;
            }
            ProtocolSignal::Exec(_, _) | ProtocolSignal::Shell => {
                cancel.cancel();
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
            cancel.cancel();
            cancellation = Some((
                ExecutionCancellation::Reset("SSH shell channel closed during command"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        let output_work = match flush_terminal_output(runner, protocol, frontend) {
            Ok(worked) => worked,
            Err(reason) => {
                cancel.cancel();
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        let input_work = match read_shell_channel_input(runner, protocol, input) {
            Ok(worked) => worked,
            Err(reason) => {
                cancel.cancel();
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
                cancel.cancel();
            }
        }
        if input.signal_interrupt || input.bytes.iter().any(|byte| *byte == 0x03) {
            cancel.cancel();
        }
        let worked = wire.worked
            || output_work
            || input_work
            || matches!(
                signal,
                ProtocolSignal::Progressed | ProtocolSignal::Interrupt
            );
        if completed.is_some() {
            cooperate(worked, wire.next_poll_delay_ms).await;
        } else if let Some(reports) = wait_for_execution_turn(
            execution.as_mut(),
            worked,
            wire.next_poll_delay_ms,
            transport_eof_deadline,
        )
        .await
        {
            if controls_rendered {
                return Ok(reports);
            }
            completed = Some(reports);
        }
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
    stack: &mut dyn TcpTransport,
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
    stack: &mut dyn TcpTransport,
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
    stack: &mut dyn TcpTransport,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    input: &mut PendingInput,
    frontend: &mut TerminalFrontend,
    require_carrier: bool,
) -> Result<u32, ConnectionEnd> {
    let mut status = 0;
    loop {
        frontend.set_completion_candidates(&session.completion_candidates());
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
    stack: &mut dyn TcpTransport,
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
    stack: &mut dyn TcpTransport,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    require_carrier: bool,
    accepted_component: Option<SshExecComponentSessionPolicy>,
) -> ExecutionEnd {
    let cancel = Arc::new(vibeos_vsh::CancellationSignal::new());
    let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
    let Some(candidate) = protocol.committed else {
        return ExecutionEnd::Reset("SSH exec session has no committed profile");
    };
    let onboarding = matches!(candidate.credential, AuthCredential::OnboardingPassword);
    let profile = candidate.profile;
    space.install_vsh_commands(&mut session, onboarding);
    match revalidate_candidate(space, policy, signer, candidate) {
        Ok(true) => {}
        Ok(false) => {
            return ExecutionEnd::Reset(
                "authorized profile changed before SSH exec command installation",
            );
        }
        Err(reason) => return ExecutionEnd::Reset(reason),
    }
    let component_pump = match install_accepted_ssh_component(
        space,
        &mut session,
        profile,
        onboarding,
        command,
        accepted_component,
    ) {
        Ok(pump) => pump,
        Err(error) => {
            return match error {
                AcceptedComponentInstallError::PolicyChanged => {
                    ExecutionEnd::Reset("SSH Component policy changed after exec acceptance")
                }
                AcceptedComponentInstallError::Install(error) => ExecutionEnd::Complete {
                    reports: Err(error),
                    timed_out: false,
                },
            };
        }
    };
    if let Some(pump) = component_pump {
        return execute_managed_component_with_network(
            &mut session,
            command,
            cancel,
            pump,
            runner,
            signer,
            space,
            control,
            bound_epoch,
            policy,
            stack,
            bridge,
            protocol,
            require_carrier,
        )
        .await;
    }
    let mut execution = Box::pin(session.execute_ssh_cancellable(command, cancel.clone()));
    let started = monotonic_ms();
    let execution_deadline = started.saturating_add(EXEC_TIMEOUT_MS);
    let mut cancellation: Option<(ExecutionCancellation, u64)> = None;

    let outcome = loop {
        let now = monotonic_ms();
        if let Some((kind, deadline)) = cancellation {
            match wait_for_execution_or(
                execution.as_mut(),
                vibeos_core::exec::sleep_ms(deadline.saturating_sub(now)),
            )
            .await
            {
                ExecutionWait::Complete(reports) => {
                    break match kind {
                        ExecutionCancellation::Timeout => ExecutionEnd::Complete {
                            reports,
                            timed_out: true,
                        },
                        ExecutionCancellation::Reset(reason) => ExecutionEnd::Reset(reason),
                        ExecutionCancellation::Rebind(reason) => ExecutionEnd::Rebind(reason),
                    };
                }
                ExecutionWait::DelayElapsed => {
                    break match kind {
                        ExecutionCancellation::Timeout => {
                            ExecutionEnd::Reset("VSH exec cancellation timed out")
                        }
                        ExecutionCancellation::Reset(reason) => ExecutionEnd::Reset(reason),
                        ExecutionCancellation::Rebind(reason) => ExecutionEnd::Rebind(reason),
                    }
                }
            }
        }
        if now >= execution_deadline {
            cancel.cancel();
            cancellation = Some((ExecutionCancellation::Timeout, now + CANCEL_GRACE_MS));
            continue;
        }

        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            cancel.cancel();
            cancellation = Some((ExecutionCancellation::Rebind(reason), now + CANCEL_GRACE_MS));
            continue;
        }
        let wire = match bridge.drive(runner, stack, now) {
            Ok(turn) => turn,
            Err(reason) => {
                cancel.cancel();
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if wire.ended {
            cancel.cancel();
            cancellation = Some((
                ExecutionCancellation::Reset("peer disconnected during exec"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        let signal = match progress_protocol(runner, signer, space, policy, protocol) {
            Ok(signal) => signal,
            Err(reason) => {
                cancel.cancel();
                cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
                continue;
            }
        };
        if matches!(signal, ProtocolSignal::Interrupt) {
            cancel.cancel();
        }
        if matches!(signal, ProtocolSignal::Defunct)
            || protocol
                .channel
                .as_ref()
                .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            cancel.cancel();
            cancellation = Some((
                ExecutionCancellation::Reset("SSH channel closed during exec"),
                now + CANCEL_GRACE_MS,
            ));
            continue;
        }
        if let Err(reason) = discard_channel_input(runner, protocol) {
            cancel.cancel();
            cancellation = Some((ExecutionCancellation::Reset(reason), now + CANCEL_GRACE_MS));
            continue;
        }
        if let Some(reports) = wait_for_execution_turn(
            execution.as_mut(),
            wire.worked
                || matches!(
                    signal,
                    ProtocolSignal::Progressed | ProtocolSignal::Interrupt
                ),
            wire.next_poll_delay_ms,
            Some(execution_deadline),
        )
        .await
        {
            break ExecutionEnd::Complete {
                reports,
                timed_out: false,
            };
        }
    };
    drop(execution);
    session.shutdown().await;
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn execute_managed_component_with_network(
    session: &mut vibeos_vsh::Session,
    command: &str,
    cancel: Arc<vibeos_vsh::CancellationSignal>,
    io: vibeos_vsh::SshExecComponentIoPump,
    runner: &mut Runner<'_, Server>,
    signer: &mut CapabilityHostSigner<'_>,
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    policy: Cap,
    stack: &mut dyn TcpTransport,
    bridge: &mut WireBridge,
    protocol: &mut ProtocolState,
    require_carrier: bool,
) -> ExecutionEnd {
    let mut pump = ComponentStreamPump::new(io);
    let mut execution = Box::pin(session.execute_ssh_cancellable(command, cancel.clone()));
    let started = monotonic_ms();
    let execution_deadline = started.saturating_add(EXEC_TIMEOUT_MS);
    let mut cancellation: Option<(ExecutionCancellation, u64)> = None;
    let mut interrupt_deadline = None;
    let mut completed = None;
    let mut expected_terminal = None;
    let mut drain_deadline = None;

    let outcome = loop {
        let now = monotonic_ms();
        if let Some((kind, deadline)) = cancellation {
            if completed.is_some() {
                break kind.after_managed_completion();
            }
            match wait_for_execution_or(
                execution.as_mut(),
                vibeos_core::exec::sleep_ms(deadline.saturating_sub(now)),
            )
            .await
            {
                ExecutionWait::Complete(reports) => {
                    match complete_managed_component_cancel(kind, reports, &mut pump) {
                        ManagedComponentCancelCompletion::End(end) => break end,
                        ManagedComponentCancelCompletion::Drain { reports, terminal } => {
                            cancellation = None;
                            expected_terminal = Some(terminal.stream_close_reason());
                            drain_deadline = Some(monotonic_ms().saturating_add(CLOSE_TIMEOUT_MS));
                            completed = Some(reports);
                            continue;
                        }
                    }
                }
                ExecutionWait::DelayElapsed => {
                    break match kind {
                        ExecutionCancellation::Timeout => {
                            ExecutionEnd::Reset("SSH Component cancellation timed out")
                        }
                        ExecutionCancellation::Reset(reason) => ExecutionEnd::Reset(reason),
                        ExecutionCancellation::Rebind(reason) => ExecutionEnd::Rebind(reason),
                    };
                }
            }
        }

        if completed.is_none() && now >= execution_deadline {
            request_managed_component_cancel(&cancel);
            cancellation = Some((ExecutionCancellation::Timeout, now + CANCEL_GRACE_MS));
            continue;
        }
        if completed.is_none() && interrupt_deadline.is_some_and(|deadline| now >= deadline) {
            cancellation = Some((
                ExecutionCancellation::Reset("SSH Component interrupt cancellation timed out"),
                now,
            ));
            continue;
        }
        if completed.is_some() && drain_deadline.is_some_and(|deadline| now >= deadline) {
            break ExecutionEnd::Reset("SSH Component terminal stream drain timed out");
        }

        if let Err(reason) =
            validate_network_authority(space, control, bound_epoch, require_carrier)
        {
            if let Some(end) = arm_managed_component_cancellation(
                completed.is_some(),
                &cancel,
                &mut cancellation,
                ExecutionCancellation::Rebind(reason),
                now + CANCEL_GRACE_MS,
            ) {
                break end;
            }
            continue;
        }
        let wire = match bridge.drive(runner, stack, now) {
            Ok(turn) => turn,
            Err(reason) => {
                if let Some(end) = arm_managed_component_cancellation(
                    completed.is_some(),
                    &cancel,
                    &mut cancellation,
                    ExecutionCancellation::Reset(reason),
                    now + CANCEL_GRACE_MS,
                ) {
                    break end;
                }
                continue;
            }
        };
        if wire.ended {
            if let Some(end) = arm_managed_component_cancellation(
                completed.is_some(),
                &cancel,
                &mut cancellation,
                ExecutionCancellation::Reset("peer disconnected during Component exec"),
                now + CANCEL_GRACE_MS,
            ) {
                break end;
            }
            continue;
        }
        let signal = match progress_protocol(runner, signer, space, policy, protocol) {
            Ok(signal) => signal,
            Err(reason) => {
                if let Some(end) = arm_managed_component_cancellation(
                    completed.is_some(),
                    &cancel,
                    &mut cancellation,
                    ExecutionCancellation::Reset(reason),
                    now + CANCEL_GRACE_MS,
                ) {
                    break end;
                }
                continue;
            }
        };
        if matches!(signal, ProtocolSignal::Interrupt) && completed.is_none() {
            request_managed_component_cancel(&cancel);
            interrupt_deadline.get_or_insert(now + CANCEL_GRACE_MS);
        }
        if matches!(signal, ProtocolSignal::Defunct)
            || protocol
                .channel
                .as_ref()
                .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            if let Some(end) = arm_managed_component_cancellation(
                completed.is_some(),
                &cancel,
                &mut cancellation,
                ExecutionCancellation::Reset("SSH channel closed during Component exec"),
                now + CANCEL_GRACE_MS,
            ) {
                break end;
            }
            continue;
        }

        let input_work = match pump_component_stdin_turn(&mut pump, runner, protocol) {
            Ok(worked) => worked,
            Err(reason) => {
                if let Some(end) = arm_managed_component_cancellation(
                    completed.is_some(),
                    &cancel,
                    &mut cancellation,
                    ExecutionCancellation::Reset(reason),
                    now + CANCEL_GRACE_MS,
                ) {
                    break end;
                }
                continue;
            }
        };
        let output_work = match pump_component_stdout_turn(&mut pump, runner, protocol) {
            Ok(worked) => worked,
            Err(reason) => {
                if let Some(end) = arm_managed_component_cancellation(
                    completed.is_some(),
                    &cancel,
                    &mut cancellation,
                    ExecutionCancellation::Reset(reason),
                    now + CANCEL_GRACE_MS,
                ) {
                    break end;
                }
                continue;
            }
        };

        if let (Some(expected), Some(observed)) = (expected_terminal, pump.stdout_terminal()) {
            if expected != observed {
                break ExecutionEnd::Reset(
                    "SSH Component lifecycle and stdout terminal reasons diverged",
                );
            }
            if pump.pending_stdout().is_empty() {
                break ExecutionEnd::Complete {
                    reports: completed
                        .take()
                        .expect("managed Component completion disappeared"),
                    timed_out: false,
                };
            }
        }

        let worked = wire.worked
            || input_work
            || output_work
            || matches!(
                signal,
                ProtocolSignal::Progressed | ProtocolSignal::Interrupt
            );
        if completed.is_none() {
            if let Some(reports) = wait_for_execution_turn(
                execution.as_mut(),
                worked,
                wire.next_poll_delay_ms,
                Some(execution_deadline),
            )
            .await
            {
                let terminal = match validated_managed_component_terminal(&reports) {
                    Ok(terminal) => terminal,
                    Err(reason) => break ExecutionEnd::Reset(reason),
                };
                expected_terminal = Some(terminal.stream_close_reason());
                drain_deadline = Some(monotonic_ms().saturating_add(CLOSE_TIMEOUT_MS));
                completed = Some(reports);
            }
        } else {
            cooperate(worked, wire.next_poll_delay_ms).await;
        }
    };
    drop(execution);
    session.shutdown().await;
    outcome
}

fn managed_component_terminal(
    reports: &Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
) -> Option<vibeos_vsh::ComponentTerminal> {
    let reports = reports.as_ref().ok()?;
    if reports.len() != 1 || !reports[0].output.is_empty() || reports[0].stages.len() != 1 {
        return None;
    }
    let report = &reports[0];
    let stage = &report.stages[0];
    let vibeos_vsh::TerminalDetail::Component(terminal) = &stage.detail else {
        return None;
    };
    (report.status == terminal.status() && stage.status == terminal.status()).then_some(*terminal)
}

/// Validate the immutable VSH completion without inventing a stream reason.
///
/// The SYSTEM lifecycle has already finalized both streams before VSH can
/// publish this report. A malformed envelope is therefore a local protocol
/// reset only: closing either endpoint with a guessed `BackendFault` could
/// conflict with the exact terminal and fail-stop an otherwise healthy stream.
fn validated_managed_component_terminal(
    reports: &Result<Vec<vibeos_vsh::JobReport>, vibeos_vsh::Diagnostic>,
) -> Result<vibeos_vsh::ComponentTerminal, &'static str> {
    managed_component_terminal(reports).ok_or("SSH Component execution published no exact terminal")
}

#[derive(Debug)]
enum AcceptedComponentInstallError {
    PolicyChanged,
    Install(vibeos_vsh::Diagnostic),
}

fn install_accepted_ssh_component(
    space: &Space,
    session: &mut vibeos_vsh::Session,
    profile: AuthorizedProfile,
    onboarding: bool,
    command: &str,
    accepted: Option<SshExecComponentSessionPolicy>,
) -> Result<Option<vibeos_vsh::SshExecComponentIoPump>, AcceptedComponentInstallError> {
    let Some(accepted) = accepted else {
        return Ok(None);
    };
    let selected =
        vibeos_vsh::validate_ssh_exec_with_component_name(command, accepted.command_name());
    if onboarding
        || !accepted.matches(profile)
        || selected != Ok(true)
        || space.select_ssh_exec_component_policy(profile, command) != Some(accepted)
    {
        return Err(AcceptedComponentInstallError::PolicyChanged);
    }
    let (install, pump) = vibeos_vsh::new_ssh_exec_component_io();
    space
        .install_ssh_exec_component_commands(session, accepted, install)
        .map_err(AcceptedComponentInstallError::Install)?;
    Ok(Some(pump))
}

enum ExecutionWait<T> {
    Complete(T),
    DelayElapsed,
}

/// Poll a nested VSH execution with the SSH task's real waker while also
/// registering the network/deadline wait which bounds the next transport turn.
/// A Component lifecycle wake can therefore resume this task immediately; it
/// does not have to wait for periodic network polling to notice completion.
async fn wait_for_execution_or<F, D>(
    mut execution: Pin<&mut F>,
    delay: D,
) -> ExecutionWait<F::Output>
where
    F: Future + ?Sized,
    D: Future<Output = ()>,
{
    let mut delay = core::pin::pin!(delay);
    poll_fn(|cx| {
        if let Poll::Ready(output) = execution.as_mut().poll(cx) {
            return Poll::Ready(ExecutionWait::Complete(output));
        }
        if delay.as_mut().poll(cx).is_ready() {
            return Poll::Ready(ExecutionWait::DelayElapsed);
        }
        Poll::Pending
    })
    .await
}

async fn wait_for_execution_turn<F: Future + ?Sized>(
    execution: Pin<&mut F>,
    worked: bool,
    next_poll_delay_ms: Option<u64>,
    deadline: Option<u64>,
) -> Option<F::Output> {
    let event = if worked {
        wait_for_execution_or(execution, vibeos_core::exec::yield_now()).await
    } else {
        let mut delay = next_poll_delay_ms
            .unwrap_or(IDLE_POLL_CEILING_MS)
            .clamp(1, IDLE_POLL_CEILING_MS);
        if let Some(deadline) = deadline {
            delay = delay.min(deadline.saturating_sub(monotonic_ms()));
        }
        wait_for_execution_or(execution, vibeos_core::exec::sleep_ms(delay)).await
    };
    match event {
        ExecutionWait::Complete(output) => Some(output),
        ExecutionWait::DelayElapsed => None,
    }
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
        vibeos_vsh::Status::BackendFault => 125,
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
    stack: &mut dyn TcpTransport,
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
    stack: &mut dyn TcpTransport,
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

fn reset_connection(stack: &mut dyn TcpTransport, reason: &'static str) -> ConnectionEnd {
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
    if space.ipv4_configuration_changed() {
        return Err("SSH IPv4 configuration changed");
    }
    if space.tcp_listener_snapshot(control).is_some() {
        return Ok(());
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, task::Wake, vec};
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
    use vibeos_component_admission::{
        admit, AdmissionPolicy, ArtifactTrust, CallerAuthority, CommandStreamMode,
        ComponentArtifact, InstanceLimits,
    };
    use vibeos_component_command::try_manifest_from_admitted;
    use vibeos_component_host::ByteStream;
    use vibeos_component_runtime::world::WorldContract;
    use vibeos_image_policy::{ComponentCommandPin, ComponentStreamMode, SSH_EXEC_COMPONENT};
    use vibeos_vsh::{
        ComponentTerminal, JobReport, ManagedComponentAcknowledge, ManagedComponentCancel,
        ManagedComponentLifecycle, ManagedComponentStartLease, ManagedComponentState,
        ManagedComponentStateFuture, ManagedComponentToken, StageReport, Status, TerminalDetail,
    };

    fn receive_stream_chunk(reader: &ByteStreamReader, output: &mut Vec<u8>) {
        let StreamReceiveDispatch::Prepared(prepared) = reader.start().unwrap() else {
            panic!("queued stream chunk was not prepared");
        };
        let start = output.len();
        output.resize(start + prepared.length(), 0);
        assert_eq!(
            reader.commit(prepared.operation(), &mut output[start..]),
            Ok(StreamReceiveCommit::Received(prepared.length()))
        );
    }

    #[test]
    fn component_pump_preserves_depth_eight_backpressure_partial_writes_and_final_37() {
        let stdin_stream = ByteStream::new();
        let stdout_stream = ByteStream::new();
        let guest_stdin = stdin_stream.reader();
        let guest_stdout = stdout_stream.writer();
        let stdin_supervisor = stdin_stream.supervisor();
        let stdout_supervisor = stdout_stream.supervisor();
        let mut pump =
            ComponentStreamPump::from_endpoints(stdin_stream.writer(), stdout_stream.reader());

        let length = 12 * MAX_STREAM_CHUNK_BYTES + 37;
        let input: Vec<u8> = (0..length)
            .map(|index| ((index * 17 + 3) % 251) as u8)
            .collect();
        let chunks: Vec<&[u8]> = input.chunks(MAX_STREAM_CHUNK_BYTES).collect();
        assert_eq!(chunks.len(), 13);
        assert_eq!(chunks.last().unwrap().len(), 37);

        for chunk in &chunks[..8] {
            assert!(pump.send_stdin(chunk).unwrap());
        }
        assert_eq!(stdin_stream.depth(), 8);
        assert_eq!(stdin_stream.peak_depth(), 8);
        assert!(!pump.send_stdin(chunks[8]).unwrap());
        assert!(pump.has_pending_stdin());
        // A bounded readiness retry consumes the old opaque operation and
        // obtains a fresh one without spinning or mutating FIFO contents.
        assert!(!pump.retry_stdin().unwrap());
        assert!(!pump.retry_stdin().unwrap());
        assert_eq!(stdin_stream.depth(), 8);

        let mut guest_input = Vec::new();
        receive_stream_chunk(&guest_stdin, &mut guest_input);
        assert!(pump.retry_stdin().unwrap());
        assert_eq!(stdin_stream.depth(), 8);
        for chunk in &chunks[9..] {
            receive_stream_chunk(&guest_stdin, &mut guest_input);
            assert!(pump.send_stdin(chunk).unwrap());
        }
        while stdin_stream.depth() != 0 {
            receive_stream_chunk(&guest_stdin, &mut guest_input);
        }
        assert_eq!(guest_input, input);
        assert!(pump.close_stdin_normal().unwrap());
        assert!(stdin_stream.is_normal_provisional());
        assert_eq!(stdin_stream.final_reason(), None);
        assert!(matches!(
            stdin_supervisor.finalize(StreamCloseReason::Normal),
            StreamCloseOutcome::Published
        ));
        assert_eq!(
            guest_stdin.start(),
            Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Normal))
        );

        let transformed: Vec<u8> = input.iter().map(|byte| byte ^ 0x20).collect();
        let transformed_chunks: Vec<&[u8]> = transformed.chunks(MAX_STREAM_CHUNK_BYTES).collect();
        for chunk in &transformed_chunks[..8] {
            assert_eq!(guest_stdout.start(chunk), Ok(StreamSendDispatch::Sent));
        }
        let StreamSendDispatch::Waiting(ninth) = guest_stdout.start(transformed_chunks[8]).unwrap()
        else {
            panic!("ninth output chunk did not observe depth-eight backpressure");
        };
        assert_eq!(stdout_stream.depth(), 8);
        assert!(pump.poll_stdout().unwrap());
        assert_eq!(stdout_stream.depth(), 7);
        assert_eq!(
            guest_stdout.resume(ninth, transformed_chunks[8]),
            Ok(StreamSendDispatch::Sent)
        );
        assert_eq!(stdout_stream.depth(), 8);
        assert!(!pump.poll_stdout().unwrap());

        let mut ssh_output = Vec::new();
        ssh_output.extend_from_slice(&pump.pending_stdout()[..17]);
        assert!(!pump.consume_stdout(17).unwrap());
        assert_eq!(stdout_stream.depth(), 8);
        ssh_output.extend_from_slice(pump.pending_stdout());
        let remaining = pump.pending_stdout().len();
        assert!(pump.consume_stdout(remaining).unwrap());

        let mut next_component_chunk = 9usize;
        while next_component_chunk < transformed_chunks.len() || stdout_stream.depth() != 0 {
            if pump.pending_stdout().is_empty() {
                assert!(pump.poll_stdout().unwrap());
            }
            if next_component_chunk < transformed_chunks.len() {
                assert_eq!(
                    guest_stdout.start(transformed_chunks[next_component_chunk]),
                    Ok(StreamSendDispatch::Sent)
                );
                next_component_chunk += 1;
            }
            ssh_output.extend_from_slice(pump.pending_stdout());
            let pending = pump.pending_stdout().len();
            assert!(pump.consume_stdout(pending).unwrap());
        }
        assert_eq!(ssh_output, transformed);
        assert_eq!(&ssh_output[ssh_output.len() - 37..], transformed_chunks[12]);
        assert_eq!(stdout_stream.peak_depth(), 8);

        assert!(matches!(
            guest_stdout.close(StreamCloseReason::Normal),
            StreamCloseOutcome::Published
        ));
        assert!(matches!(
            stdout_supervisor.finalize(StreamCloseReason::Normal),
            StreamCloseOutcome::Published
        ));
        assert!(pump.poll_stdout().unwrap());
        assert_eq!(pump.stdout_terminal(), Some(StreamCloseReason::Normal));
    }

    #[test]
    fn component_pump_cancels_prepared_stdout_when_terminal_wins_commit() {
        let stdin_stream = ByteStream::new();
        let stdout_stream = ByteStream::new();
        let component_output = stdout_stream.writer();
        let retained_reader = stdout_stream.reader();
        let stdout_supervisor = stdout_stream.supervisor();
        let mut pump =
            ComponentStreamPump::from_endpoints(stdin_stream.writer(), retained_reader.clone());

        assert_eq!(
            component_output.start(&[0x53, 0x37]),
            Ok(StreamSendDispatch::Sent)
        );
        let StreamReceiveDispatch::Prepared(prepared) = retained_reader.start().unwrap() else {
            panic!("component output was not prepared");
        };
        assert_eq!(
            stdout_supervisor.finalize(StreamCloseReason::Failure),
            StreamCloseOutcome::Published
        );

        assert!(pump.commit_stdout(prepared).unwrap());
        assert_eq!(pump.stdout_terminal(), Some(StreamCloseReason::Failure));
        assert_eq!(
            retained_reader.start(),
            Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Failure))
        );
    }

    #[test]
    fn terminal_close_while_ninth_stdin_chunk_waits_stops_further_input() {
        for reason in [StreamCloseReason::Failure, StreamCloseReason::Cancelled] {
            let stdin_stream = ByteStream::new();
            let stdout_stream = ByteStream::new();
            let stdin_supervisor = stdin_stream.supervisor();
            let mut pump =
                ComponentStreamPump::from_endpoints(stdin_stream.writer(), stdout_stream.reader());
            let chunk = [0x5au8; MAX_STREAM_CHUNK_BYTES];

            for _ in 0..8 {
                assert!(pump.send_stdin(&chunk).unwrap());
            }
            assert!(!pump.send_stdin(&chunk).unwrap());
            assert!(pump.has_pending_stdin());
            assert_eq!(stdin_stream.depth(), 8);

            assert_eq!(
                stdin_supervisor.finalize(reason),
                StreamCloseOutcome::Published
            );
            assert!(pump.retry_stdin().unwrap());
            assert!(pump.stdin_source_closed());
            assert!(!pump.has_pending_stdin());
            assert_eq!(stdin_stream.depth(), 0);
            assert_eq!(stdin_stream.final_reason(), Some(reason));

            // This is the exact guard used by `pump_component_stdin_turn`
            // before its first `read_channel_ready` call after a retry.
            assert!(pump.stdin_source_closed());
        }
    }

    #[test]
    fn completion_winning_cancellation_keeps_the_exact_managed_terminal() {
        for terminal in [
            ComponentTerminal::Success,
            ComponentTerminal::Returned(37),
            ComponentTerminal::BackendFault,
            ComponentTerminal::Cancelled,
        ] {
            let stdin_stream = ByteStream::new();
            let stdout_stream = ByteStream::new();
            let component_output = stdout_stream.writer();
            let stdin_supervisor = stdin_stream.supervisor();
            let stdout_supervisor = stdout_stream.supervisor();
            let mut pump =
                ComponentStreamPump::from_endpoints(stdin_stream.writer(), stdout_stream.reader());
            let cancel = vibeos_vsh::CancellationSignal::new();
            let reason = terminal.stream_close_reason();
            let final_bytes = [0x25, 0x53, 0x37];

            assert_eq!(
                component_output.start(&final_bytes),
                Ok(StreamSendDispatch::Sent)
            );
            assert!(pump.poll_stdout().unwrap());
            assert_eq!(pump.pending_stdout(), final_bytes);

            // Model another hart committing the managed terminal immediately
            // before VSH observes the boolean cancellation edge. Stdin may
            // already have immutable normal EOF even when stdout later faults.
            assert_eq!(
                stdin_supervisor.finalize(StreamCloseReason::Normal),
                StreamCloseOutcome::Published
            );
            assert_eq!(
                stdout_supervisor.finalize(reason),
                StreamCloseOutcome::Published
            );
            let reports = Ok(vec![JobReport {
                id: 1,
                status: terminal.status(),
                stages: vec![StageReport {
                    stage: 0,
                    status: terminal.status(),
                    detail: TerminalDetail::Component(terminal),
                }],
                output: String::new(),
                peak_pipe_depth: 0,
            }]);

            request_managed_component_cancel(&cancel);
            assert!(cancel.is_cancelled(), "{terminal:?}");
            assert_eq!(
                stdin_stream.final_reason(),
                Some(StreamCloseReason::Normal),
                "{terminal:?}"
            );
            assert_eq!(stdout_stream.final_reason(), Some(reason), "{terminal:?}");
            let resolution = complete_managed_component_cancel(
                ExecutionCancellation::Timeout,
                reports,
                &mut pump,
            );
            if terminal == ComponentTerminal::Cancelled {
                let ManagedComponentCancelCompletion::End(ExecutionEnd::Complete {
                    reports: observed,
                    timed_out: true,
                }) = resolution
                else {
                    panic!("won cancellation was not reported as timeout: {terminal:?}");
                };
                assert_eq!(managed_component_terminal(&observed), Some(terminal));
                assert!(pump.pending_stdout().is_empty());
            } else {
                let ManagedComponentCancelCompletion::Drain {
                    reports: observed,
                    terminal: observed_terminal,
                } = resolution
                else {
                    panic!("completion winner did not resume stdout drain: {terminal:?}");
                };
                assert_eq!(managed_component_terminal(&observed), Some(terminal));
                assert_eq!(observed_terminal, terminal);
                assert_eq!(pump.pending_stdout(), final_bytes);
                assert!(pump.consume_stdout(final_bytes.len()).unwrap());
                assert!(pump.poll_stdout().unwrap());
            }
            assert_eq!(pump.stdout_terminal(), Some(reason), "{terminal:?}");
        }
    }

    #[test]
    fn malformed_completed_report_never_rewrites_an_immutable_stream_terminal() {
        for reason in [
            StreamCloseReason::Normal,
            StreamCloseReason::Failure,
            StreamCloseReason::Cancelled,
            StreamCloseReason::Invalid,
        ] {
            let stdin_stream = ByteStream::new();
            let stdout_stream = ByteStream::new();
            let stdin_supervisor = stdin_stream.supervisor();
            let stdout_supervisor = stdout_stream.supervisor();
            let mut pump =
                ComponentStreamPump::from_endpoints(stdin_stream.writer(), stdout_stream.reader());

            assert_eq!(
                stdin_supervisor.finalize(reason),
                StreamCloseOutcome::Published
            );
            assert_eq!(
                stdout_supervisor.finalize(reason),
                StreamCloseOutcome::Published
            );

            // An empty report vector models a completed but malformed VSH
            // envelope. The production branch now returns Reset directly and
            // never guesses a replacement terminal through `pump.abort`.
            let malformed = Ok(vec![]);
            assert_eq!(
                validated_managed_component_terminal(&malformed),
                Err("SSH Component execution published no exact terminal")
            );
            assert_eq!(stdin_stream.final_reason(), Some(reason));
            assert_eq!(stdout_stream.final_reason(), Some(reason));
            assert!(!stdin_stream.is_fail_stopped());
            assert!(!stdout_stream.is_fail_stopped());

            assert!(pump.poll_stdout().unwrap());
            assert_eq!(pump.stdout_terminal(), Some(reason));
        }
    }

    struct WakeDrivenState {
        ready: AtomicBool,
        polls: AtomicUsize,
        waker: SpinLock<Option<Waker>>,
    }

    struct WakeDrivenExecution {
        state: Arc<WakeDrivenState>,
    }

    impl Future for WakeDrivenExecution {
        type Output = u32;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.state.polls.fetch_add(1, AtomicOrdering::SeqCst);
            if self.state.ready.load(AtomicOrdering::SeqCst) {
                Poll::Ready(37)
            } else {
                *self.state.waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    struct PassiveDelay(Arc<AtomicUsize>);

    impl Future for PassiveDelay {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
            Poll::Pending
        }
    }

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
        }
    }

    struct ReadyOnlyOnceExecution {
        polls: Arc<AtomicUsize>,
    }

    impl Future for ReadyOnlyOnceExecution {
        type Output = u32;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            assert_eq!(
                self.polls.fetch_add(1, AtomicOrdering::SeqCst),
                0,
                "completed execution future was polled twice"
            );
            Poll::Ready(37)
        }
    }

    #[test]
    fn nested_execution_wait_registers_the_current_task_without_self_waking() {
        let state = Arc::new(WakeDrivenState {
            ready: AtomicBool::new(false),
            polls: AtomicUsize::new(0),
            waker: SpinLock::new(None),
        });
        let delay_polls = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(wake_count.clone());
        let mut context = Context::from_waker(&waker);
        let mut execution = WakeDrivenExecution {
            state: state.clone(),
        };
        let mut wait = Box::pin(wait_for_execution_or(
            Pin::new(&mut execution),
            PassiveDelay(delay_polls.clone()),
        ));

        assert!(wait.as_mut().poll(&mut context).is_pending());
        assert_eq!(state.polls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(delay_polls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(wake_count.0.load(AtomicOrdering::SeqCst), 0);

        state.ready.store(true, AtomicOrdering::SeqCst);
        state.waker.lock().take().unwrap().wake();
        assert_eq!(wake_count.0.load(AtomicOrdering::SeqCst), 1);
        assert!(matches!(
            wait.as_mut().poll(&mut context),
            Poll::Ready(ExecutionWait::Complete(37))
        ));
        assert_eq!(state.polls.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(delay_polls.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn completed_component_transport_failure_never_repolls_execution() {
        let polls = Arc::new(AtomicUsize::new(0));
        let delay_polls = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(wake_count);
        let mut context = Context::from_waker(&waker);
        let mut execution = ReadyOnlyOnceExecution {
            polls: polls.clone(),
        };
        let mut wait = Box::pin(wait_for_execution_or(
            Pin::new(&mut execution),
            PassiveDelay(delay_polls.clone()),
        ));

        assert!(matches!(
            wait.as_mut().poll(&mut context),
            Poll::Ready(ExecutionWait::Complete(37))
        ));
        drop(wait);
        assert_eq!(polls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(delay_polls.load(AtomicOrdering::SeqCst), 0);

        for kind in [
            ExecutionCancellation::Reset("drain transport failed"),
            ExecutionCancellation::Rebind("drain authority changed"),
        ] {
            let cancel = vibeos_vsh::CancellationSignal::new();
            let mut cancellation = None;
            let end =
                arm_managed_component_cancellation(true, &cancel, &mut cancellation, kind, 37)
                    .expect("completed drain failure must end without cancellation");
            assert!(matches!(
                end,
                ExecutionEnd::Reset("drain transport failed")
                    | ExecutionEnd::Rebind("drain authority changed")
            ));
            assert!(cancellation.is_none());
            assert!(!cancel.is_cancelled());
            assert_eq!(polls.load(AtomicOrdering::SeqCst), 1);
        }
    }

    struct TestManagedLifecycle {
        manifest: vibeos_vsh::ComponentCommandManifest,
        next_token: AtomicU64,
        current_token: AtomicU64,
        starts: AtomicUsize,
    }

    impl TestManagedLifecycle {
        fn new() -> &'static Self {
            let admitted = admit_image_component(SSH_EXEC_COMPONENT);
            let manifest = try_manifest_from_admitted(&admitted).unwrap();
            Box::leak(Box::new(Self {
                manifest,
                next_token: AtomicU64::new(1),
                current_token: AtomicU64::new(0),
                starts: AtomicUsize::new(0),
            }))
        }

        fn started_invocations(&self) -> usize {
            self.starts.load(AtomicOrdering::SeqCst)
        }

        fn exact_token(&self, token: ManagedComponentToken) -> bool {
            let raw = unsafe { token.trusted_raw() }.get();
            raw != 0 && self.current_token.load(AtomicOrdering::SeqCst) == raw
        }
    }

    // SAFETY: this test-only lifecycle is leaked for the process lifetime,
    // issues monotonic opaque tokens, consumes the sealed IO envelope, and
    // publishes both terminal supervisors before reporting immutable Success.
    // It never enters production or the target acceptance image.
    unsafe impl ManagedComponentLifecycle for TestManagedLifecycle {
        fn manifest(&self) -> &vibeos_vsh::ComponentCommandManifest {
            &self.manifest
        }

        fn start(
            &self,
            cleanup: ManagedComponentStartLease,
        ) -> Result<ManagedComponentToken, ComponentTerminal> {
            let raw = self.next_token.fetch_add(1, AtomicOrdering::SeqCst);
            let Some(raw) = NonZeroU64::new(raw) else {
                let _ = cleanup.abort_before_child_publication(ComponentTerminal::RunnerFault);
                return Err(ComponentTerminal::RunnerFault);
            };
            let token = unsafe { ManagedComponentToken::from_trusted_raw(raw) };
            if !cleanup.bind_before_child_publication(token) {
                cleanup.quarantine_partial_start();
                return Err(ComponentTerminal::RunnerFault);
            }
            let Some(io) = cleanup.claim_bound_io(token) else {
                cleanup.quarantine_partial_start();
                return Err(ComponentTerminal::RunnerFault);
            };
            let (stdin, stdout, stdin_supervisor, stdout_supervisor) = io.into_parts();
            let normal = StreamCloseReason::Normal;
            let input_closed = stdin.close(normal);
            let output_closed = stdout.close(normal);
            let input_final = stdin_supervisor.finalize(normal);
            let output_final = stdout_supervisor.finalize(normal);
            if [input_closed, output_closed, input_final, output_final]
                .iter()
                .any(|outcome| matches!(outcome, StreamCloseOutcome::Conflict))
                || stdin_supervisor.final_reason() != Some(normal)
                || stdout_supervisor.final_reason() != Some(normal)
            {
                cleanup.quarantine_partial_start();
                return Err(ComponentTerminal::BackendFault);
            }
            self.current_token.store(raw.get(), AtomicOrdering::SeqCst);
            self.starts.fetch_add(1, AtomicOrdering::SeqCst);
            cleanup
                .commit_child_publication(token)
                .expect("test lifecycle commits its bound child")
                .dispatch();
            cleanup
                .notify_state_change()
                .expect("test lifecycle publishes its immediate terminal")
                .dispatch();
            Ok(token)
        }

        fn state(&self, token: ManagedComponentToken) -> ManagedComponentState {
            if self.exact_token(token) {
                ManagedComponentState::Complete(ComponentTerminal::Success)
            } else {
                ManagedComponentState::Lost
            }
        }

        fn wait_state<'a>(
            &'a self,
            token: ManagedComponentToken,
        ) -> ManagedComponentStateFuture<'a> {
            Box::pin(async move { self.state(token) })
        }

        fn request_cancel(
            &self,
            token: ManagedComponentToken,
            _terminal: ComponentTerminal,
        ) -> ManagedComponentCancel {
            if self.exact_token(token) {
                ManagedComponentCancel::AlreadyComplete
            } else {
                ManagedComponentCancel::Lost
            }
        }

        fn acknowledge_complete(
            &self,
            token: ManagedComponentToken,
        ) -> ManagedComponentAcknowledge {
            if self.exact_token(token) {
                ManagedComponentAcknowledge::Acknowledged
            } else {
                ManagedComponentAcknowledge::Lost
            }
        }
    }

    struct TestPolicyPlatform {
        component_policy: Option<SshExecComponentSessionPolicy>,
        secondary_component_policy: Option<SshExecComponentSessionPolicy>,
        component_lifecycle: Option<&'static TestManagedLifecycle>,
    }

    fn component_policy(
        profile: AuthorizedProfile,
        incarnation: u64,
        artifact_sha256: [u8; 32],
    ) -> SshExecComponentSessionPolicy {
        SshExecComponentSessionPolicy::new(
            profile,
            NonZeroU64::new(incarnation).unwrap(),
            "case-filter",
            artifact_sha256,
        )
    }

    impl Platform for TestPolicyPlatform {
        fn packet_endpoints(
            &self,
            _outbound: Cap,
            _inbound: Cap,
        ) -> Option<(
            Revocable<Endpoint<StampedPacket>>,
            Revocable<Endpoint<StampedPacket>>,
        )> {
            None
        }

        fn bind_stack(&self, _control: Cap) -> Result<PacketStamp, NetworkBindError> {
            Err(NetworkBindError::Denied)
        }

        fn network_info(&self, _control: Cap) -> Option<NetworkInfo> {
            None
        }

        fn entropy<'a>(
            &'a self,
            _random: Cap,
            _length: usize,
        ) -> PlatformFuture<'a, Result<SecretBytes, ()>> {
            Box::pin(async { Err(()) })
        }

        fn host_public_key(&self, _read: Cap) -> Result<HostPublicKeySnapshot, ()> {
            Err(())
        }

        fn sign_exchange_hash(
            &self,
            _invoke: Cap,
            _exchange_hash: &[u8; 32],
        ) -> Result<HostSignatureResult, ()> {
            Err(())
        }

        fn authorized_profile(
            &self,
            _policy: Cap,
            _key: &SshEd25519PublicKey,
        ) -> Result<Option<AuthorizedProfile>, ()> {
            Ok(None)
        }

        fn install_vsh_commands(&self, _session: &mut vibeos_vsh::Session, _onboarding: bool) {}

        fn install_ssh_exec_component_commands(
            &self,
            session: &mut vibeos_vsh::Session,
            policy: SshExecComponentSessionPolicy,
            io: vibeos_vsh::SshExecComponentIoInstall,
        ) -> Result<(), vibeos_vsh::Diagnostic> {
            let Some(lifecycle) = self.component_lifecycle else {
                return Ok(());
            };
            if self.component_policy != Some(policy)
                || policy.command_name() != SSH_EXEC_COMPONENT.command_name()
                || policy.artifact_sha256() != SSH_EXEC_COMPONENT.expected_sha256()
            {
                return vibeos_vsh::validate_ssh_exec(policy.command_name());
            }
            let image_policy = ssh_component_policy(SSH_EXEC_COMPONENT)?;
            // SAFETY: the test lifecycle is process-stable and the immediately
            // preceding checks independently bind the accepted session policy
            // to the immutable image pin before consuming this exact IO half.
            unsafe { session.install_ssh_exec_managed_component_io(&image_policy, lifecycle, io) }
        }

        fn ssh_exec_component_policy(
            &self,
            profile: AuthorizedProfile,
        ) -> Option<SshExecComponentSessionPolicy> {
            self.component_policy
                .filter(|policy| policy.matches(profile))
        }

        fn select_ssh_exec_component_policy(
            &self,
            profile: AuthorizedProfile,
            source: &str,
        ) -> Option<SshExecComponentSessionPolicy> {
            let select = |policy: SshExecComponentSessionPolicy| {
                policy.matches(profile)
                    && vibeos_vsh::validate_ssh_exec_with_component_name(
                        source,
                        policy.command_name(),
                    ) == Ok(true)
            };
            let primary = self.component_policy.filter(|policy| select(*policy));
            let secondary = self
                .secondary_component_policy
                .filter(|policy| select(*policy));
            match (primary, secondary) {
                (Some(policy), None) | (None, Some(policy)) => Some(policy),
                (None, None) | (Some(_), Some(_)) => None,
            }
        }

        fn log(&self, _args: fmt::Arguments<'_>) {}
    }

    #[test]
    fn default_platform_policy_installs_no_ssh_component_command() {
        let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
        let profile = AuthorizedProfile {
            generation: 1,
            profile: CapabilityProfileId::new(1).unwrap(),
        };
        let (install, _pump) = vibeos_vsh::new_ssh_exec_component_io();
        TestPolicyPlatform {
            component_policy: None,
            secondary_component_policy: None,
            component_lifecycle: None,
        }
        .install_ssh_exec_component_commands(
            &mut session,
            component_policy(profile, 1, [0x11; 32]),
            install,
        )
        .unwrap();

        assert_eq!(
            vibeos_vsh::validate_ssh_exec("case-filter")
                .unwrap_err()
                .message,
            "command is outside the SSH exec profile"
        );
        assert!(!session
            .completion_candidates()
            .iter()
            .any(|name| name == "case-filter"));
    }

    #[test]
    fn ssh_component_session_policy_binds_profile_and_generation_exactly() {
        let admitted = AuthorizedProfile {
            generation: 7,
            profile: CapabilityProfileId::new(3).unwrap(),
        };
        let policy = component_policy(admitted, 7, [0x33; 32]);
        assert!(policy.matches(admitted));
        assert!(!policy.matches(AuthorizedProfile {
            generation: 8,
            profile: admitted.profile,
        }));
        assert!(!policy.matches(AuthorizedProfile {
            generation: admitted.generation,
            profile: CapabilityProfileId::new(4).unwrap(),
        }));
        assert_eq!(policy.profile(), admitted);
        assert_eq!(policy.incarnation(), NonZeroU64::new(7).unwrap());
        assert_eq!(policy.command_name(), "case-filter");
        assert_eq!(policy.artifact_sha256(), [0x33; 32]);
    }

    #[test]
    fn ssh_component_request_requires_exact_profile_public_key_and_simple_syntax() {
        let admitted = AuthorizedProfile {
            generation: 7,
            profile: CapabilityProfileId::new(3).unwrap(),
        };
        let platform = TestPolicyPlatform {
            component_policy: Some(component_policy(admitted, 7, [0x33; 32])),
            secondary_component_policy: None,
            component_lifecycle: None,
        };
        assert!(accepted_ssh_component_policy(&platform, admitted, true, "case-filter").is_some());
        assert!(accepted_ssh_component_policy(&platform, admitted, false, "case-filter").is_none());
        assert!(accepted_ssh_component_policy(
            &platform,
            AuthorizedProfile {
                generation: 8,
                profile: admitted.profile,
            },
            true,
            "case-filter"
        )
        .is_none());
        assert!(accepted_ssh_component_policy(
            &platform,
            AuthorizedProfile {
                generation: admitted.generation,
                profile: CapabilityProfileId::new(4).unwrap(),
            },
            true,
            "case-filter"
        )
        .is_none());
        for source in [
            "case-filter | true",
            "case-filter > @console",
            "case-filter $(true)",
            "$case-filter",
        ] {
            assert!(accepted_ssh_component_policy(&platform, admitted, true, source).is_none());
        }
    }

    #[test]
    fn ssh_component_selector_keeps_two_exact_routes_and_rechecks_before_install() {
        let profile = AuthorizedProfile {
            generation: 17,
            profile: CapabilityProfileId::new(3).unwrap(),
        };
        let sync = component_policy(profile, 21, [0x31; 32]);
        let native = SshExecComponentSessionPolicy::new(
            profile,
            NonZeroU64::new(22).unwrap(),
            "native-case-filter",
            [0x53; 32],
        );
        let platform = TestPolicyPlatform {
            component_policy: Some(sync),
            secondary_component_policy: Some(native),
            component_lifecycle: None,
        };
        assert_eq!(
            accepted_ssh_component_policy(&platform, profile, true, "case-filter"),
            Some(sync)
        );
        assert_eq!(
            accepted_ssh_component_policy(&platform, profile, true, "native-case-filter"),
            Some(native)
        );
        for source in [
            "native-case-filter | true",
            "native-case-filter > @console",
            "native-case-filter $(true)",
        ] {
            assert!(accepted_ssh_component_policy(&platform, profile, true, source).is_none());
        }

        let rotated = TestPolicyPlatform {
            component_policy: Some(sync),
            secondary_component_policy: Some(SshExecComponentSessionPolicy::new(
                profile,
                NonZeroU64::new(23).unwrap(),
                "native-case-filter",
                [0x53; 32],
            )),
            component_lifecycle: None,
        };
        let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
        assert!(matches!(
            install_accepted_ssh_component(
                &rotated,
                &mut session,
                profile,
                false,
                "native-case-filter",
                Some(native),
            ),
            Err(AcceptedComponentInstallError::PolicyChanged)
        ));
        assert!(!session
            .completion_candidates()
            .iter()
            .any(|name| name == "native-case-filter"));
    }

    #[test]
    fn accepted_component_policy_fails_closed_across_rotation_and_revocation() {
        let profile = AuthorizedProfile {
            generation: 7,
            profile: CapabilityProfileId::new(3).unwrap(),
        };
        let accepted = component_policy(profile, 10, [0x33; 32]);
        let gate = TestPolicyPlatform {
            component_policy: Some(accepted),
            secondary_component_policy: None,
            component_lifecycle: None,
        };
        assert_eq!(
            accepted_ssh_component_policy(&gate, profile, true, "case-filter"),
            Some(accepted)
        );

        let changed = [
            None,
            Some(component_policy(profile, 11, [0x33; 32])),
            Some(component_policy(profile, 10, [0x44; 32])),
            Some(component_policy(
                AuthorizedProfile {
                    generation: 8,
                    profile: profile.profile,
                },
                10,
                [0x33; 32],
            )),
            Some(component_policy(
                AuthorizedProfile {
                    generation: profile.generation,
                    profile: CapabilityProfileId::new(4).unwrap(),
                },
                10,
                [0x33; 32],
            )),
        ];
        for current in changed {
            let platform = TestPolicyPlatform {
                component_policy: current,
                secondary_component_policy: None,
                component_lifecycle: None,
            };
            let mut session =
                vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
            assert!(matches!(
                install_accepted_ssh_component(
                    &platform,
                    &mut session,
                    profile,
                    false,
                    "case-filter",
                    Some(accepted),
                ),
                Err(AcceptedComponentInstallError::PolicyChanged)
            ));
            assert!(!session
                .completion_candidates()
                .iter()
                .any(|name| name == "case-filter"));
        }
    }

    #[test]
    fn stable_policy_for_a_different_artifact_is_not_installed() {
        let lifecycle = TestManagedLifecycle::new();
        let profile = AuthorizedProfile {
            generation: 7,
            profile: CapabilityProfileId::new(3).unwrap(),
        };
        let wrong_artifact = component_policy(profile, 10, [0x44; 32]);
        let platform = TestPolicyPlatform {
            component_policy: Some(wrong_artifact),
            secondary_component_policy: None,
            component_lifecycle: Some(lifecycle),
        };
        assert_eq!(
            accepted_ssh_component_policy(&platform, profile, true, "case-filter"),
            Some(wrong_artifact)
        );

        let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
        assert!(matches!(
            install_accepted_ssh_component(
                &platform,
                &mut session,
                profile,
                false,
                "case-filter",
                Some(wrong_artifact),
            ),
            Err(AcceptedComponentInstallError::Install(_))
        ));
        assert!(!session
            .completion_candidates()
            .iter()
            .any(|name| name == "case-filter"));
        assert_eq!(lifecycle.started_invocations(), 0);
    }

    #[test]
    fn builtin_exec_carries_no_component_descriptor_or_installation() {
        let profile = AuthorizedProfile {
            generation: 7,
            profile: CapabilityProfileId::new(3).unwrap(),
        };
        let platform = TestPolicyPlatform {
            component_policy: Some(component_policy(profile, 10, [0x33; 32])),
            secondary_component_policy: None,
            component_lifecycle: None,
        };
        let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
        assert!(install_accepted_ssh_component(
            &platform,
            &mut session,
            profile,
            false,
            "true",
            None
        )
        .unwrap()
        .is_none());
        assert!(!session
            .completion_candidates()
            .iter()
            .any(|name| name == "case-filter"));
    }

    #[test]
    fn component_backend_fault_is_preserved_as_ssh_exit_125() {
        let reports = vec![JobReport {
            id: 1,
            status: Status::BackendFault,
            stages: vec![StageReport {
                stage: 0,
                status: Status::BackendFault,
                detail: TerminalDetail::Component(ComponentTerminal::BackendFault),
            }],
            output: String::new(),
            peak_pipe_depth: 0,
        }];

        let (output, status) = collect_execution(Ok(reports), false);
        assert!(output.is_empty());
        assert_eq!(status, 125);
    }

    fn admission_stream(mode: ComponentStreamMode) -> CommandStreamMode {
        match mode {
            ComponentStreamMode::Required => CommandStreamMode::Required,
            ComponentStreamMode::Optional => CommandStreamMode::Optional,
            ComponentStreamMode::Closed => CommandStreamMode::Closed,
        }
    }

    fn vsh_stream(mode: ComponentStreamMode) -> vibeos_vsh::StreamMode {
        match mode {
            ComponentStreamMode::Required => vibeos_vsh::StreamMode::Required,
            ComponentStreamMode::Optional => vibeos_vsh::StreamMode::Optional,
            ComponentStreamMode::Closed => vibeos_vsh::StreamMode::Closed,
        }
    }

    fn admit_image_component(
        pin: ComponentCommandPin,
    ) -> Arc<vibeos_component_admission::AdmittedComponent> {
        // Parse the separately pinned WIT policy instead of reflecting the
        // artifact's decoded shape back as its own expected contract.
        let world = WorldContract::parse(pin.wit_source(), pin.world()).unwrap();
        let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
        let identity = artifact.identity();
        assert_eq!(identity.as_bytes(), &pin.expected_sha256());
        let limits = pin.limits();
        Arc::new(
            admit(
                artifact,
                &AdmissionPolicy {
                    command_name: pin.command_name(),
                    entrypoint: pin.entrypoint(),
                    min_args: pin.min_args(),
                    max_args: pin.max_args(),
                    exact_world: &world,
                    profile: pin.profile(),
                    trust: ArtifactTrust::ImagePinned(identity),
                    limits: InstanceLimits {
                        memory_bytes: limits.memory_bytes,
                        total_fuel: limits.total_fuel,
                        poll_quantum: limits.poll_quantum,
                        resources: limits.resources,
                    },
                    stdin: admission_stream(pin.stdin()),
                    stdout: admission_stream(pin.stdout()),
                    stderr: admission_stream(pin.stderr()),
                    interfaces: &[],
                },
                &CallerAuthority { offers: &[] },
            )
            .unwrap(),
        )
    }

    fn ssh_component_policy(
        pin: ComponentCommandPin,
    ) -> Result<vibeos_vsh::SshExecComponentPolicy, vibeos_vsh::Diagnostic> {
        let limits = pin.limits();
        vibeos_vsh::SshExecComponentPolicy::from_image_pin(
            pin.command_name(),
            pin.abi(),
            vibeos_vsh::ComponentArtifactIdentity::new(pin.expected_sha256()),
            pin.world(),
            pin.entrypoint(),
            pin.min_args(),
            pin.max_args(),
            vsh_stream(pin.stdin()),
            vsh_stream(pin.stdout()),
            vsh_stream(pin.stderr()),
            limits.memory_bytes,
            limits.total_fuel,
            limits.poll_quantum,
            limits.resources,
            Vec::new(),
        )
    }

    fn execute_ssh(
        mut session: vibeos_vsh::Session,
        source: &'static str,
    ) -> Result<Vec<JobReport>, vibeos_vsh::Diagnostic> {
        let result = Arc::new(SpinLock::new(None));
        let published = result.clone();
        let task = vibeos_core::exec::spawn_tracked("ssh-component-e2e", async move {
            let report = session
                .execute_ssh_cancellable(source, Arc::new(vibeos_vsh::CancellationSignal::new()))
                .await;
            *published.lock() = Some(report);
        });
        vibeos_core::exec::run_until_idle(100_000);
        assert!(
            task.try_exit().is_some(),
            "SSH Component exec did not finish"
        );
        let report = result.lock().take().unwrap();
        report
    }

    #[test]
    fn image_pin_requires_explicit_ssh_policy_then_executes_stream_filter() {
        let lifecycle = TestManagedLifecycle::new();
        assert_eq!(
            lifecycle.manifest().stdin(),
            vibeos_vsh::StreamMode::Required
        );
        let profile = AuthorizedProfile {
            generation: 41,
            profile: CapabilityProfileId::new(9).unwrap(),
        };

        let no_policy = TestPolicyPlatform {
            component_policy: None,
            secondary_component_policy: None,
            component_lifecycle: Some(lifecycle),
        };
        assert!(accepted_ssh_component_policy(&no_policy, profile, true, "case-filter").is_none());
        let rejected = execute_ssh(
            vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec),
            "case-filter",
        )
        .unwrap_err();
        assert_eq!(rejected.message, "command is outside the SSH exec profile");
        assert_eq!(lifecycle.started_invocations(), 0);

        let platform = TestPolicyPlatform {
            component_policy: Some(component_policy(
                profile,
                41,
                SSH_EXEC_COMPONENT.expected_sha256(),
            )),
            secondary_component_policy: None,
            component_lifecycle: Some(lifecycle),
        };
        let accepted =
            accepted_ssh_component_policy(&platform, profile, true, "case-filter").unwrap();
        let mut session = vibeos_vsh::Session::with_profile(vibeos_vsh::SessionProfile::SshExec);
        let pump = install_accepted_ssh_component(
            &platform,
            &mut session,
            profile,
            false,
            "case-filter",
            Some(accepted),
        )
        .unwrap();
        assert!(pump.is_some());
        let reports = execute_ssh(session, "case-filter").unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].status, Status::Success);
        assert!(reports[0].output.is_empty());
        assert_eq!(
            reports[0].stages[0].detail,
            TerminalDetail::Component(ComponentTerminal::Success)
        );
        assert_eq!(lifecycle.started_invocations(), 1);
    }
}
