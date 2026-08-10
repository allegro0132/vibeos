//! QEMU-only N4 acceptance server: one bounded SSH connection at a time.
//!
//! The transport owns no ambient authority. Packet I/O, entropy, host-key
//! signing, and authorization are all reached through separately attenuated
//! capabilities. Each accepted TCP connection gets fresh caller-provided
//! randomness and at most one authenticated session channel and one `exec`.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use sunset::{
    ChanData, ChanFail, ChanHandle, Ed25519HostSigner, Event, PubKey, Runner, ServEvent, Server,
};
use vibeos_core::cap::{Cap, Rights};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{PacketStamp, StampedPacket};
use vibeos_core::net_stack::{StaticIpv4Config, StaticIpv4TcpStack, TcpIoResult, TcpStreamState};
use vibeos_core::random::{ChaCha20Random, EntropySource, RandomDomain, RandomLimits, SEED_BYTES};
use vibeos_core::ssh_identity::SshEd25519PublicKey;

use crate::ssh_security::{
    self, AuthorizedKeyPolicyService, AuthorizedProfile, HostPublicKeySnapshot, HostSigningService,
    SecurityGeneration,
};
use crate::virtio_rng::{self, RandomBytes, RandomError};
use crate::world::Space;

const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const GUEST_IPV4: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IPV4: [u8; 4] = [10, 0, 2, 2];
const PREFIX_LEN: u8 = 24;
const LISTEN_PORT: u16 = 2222;
const SSH_RANDOM_DOMAIN: u64 = 0x5353_4803;

const ENTROPY_RETRY_BUDGET: usize = 5_000;
const NETWORK_RETRY_BUDGET: usize = 5_000;
const CONNECTION_TIMEOUT_MS: u64 = 60_000;
const EXEC_TIMEOUT_MS: u64 = 10_000;
const CANCEL_GRACE_MS: u64 = 1_000;
const CLOSE_TIMEOUT_MS: u64 = 5_000;
const IDLE_POLL_CEILING_MS: u64 = 10;
const MAX_SSH_PROGRESS_PER_TURN: usize = 32;
const MAX_WIRE_IO_PER_TURN: usize = 8;
const MAX_CHANNEL_DISCARDS_PER_TURN: usize = 4;
const MAX_WIRE_BYTES_PER_DIRECTION: usize = 512 * 1024;
const MAX_EXEC_OUTPUT_BYTES: usize = 64 * 1024;
const WIRE_CHUNK_BYTES: usize = 1_024;

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
    generation: Cell<Option<SecurityGeneration>>,
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
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<HostSigningService>(self.read, Rights::READ)
            .map_err(|_| "host public-key authority was revoked")?;
        let snapshot =
            ssh_security::public_key_with(&lease).map_err(|_| "host public-key read was denied")?;
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
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<HostSigningService>(self.invoke, Rights::INVOKE)
            .map_err(|_| sunset::Error::BadSig)?;
        let signed =
            ssh_security::sign_with(&lease, exchange_hash).map_err(|_| sunset::Error::BadSig)?;
        if signed.generation != public.generation {
            return Err(sunset::Error::BadSig);
        }
        Ok(signed.signature.to_bytes())
    }
}

#[derive(Clone, Copy)]
struct AuthCandidate {
    key: SshEd25519PublicKey,
    profile: AuthorizedProfile,
}

#[derive(Default)]
struct ProtocolState {
    candidate: Option<AuthCandidate>,
    committed: Option<AuthCandidate>,
    authenticated: bool,
    channel: Option<ChanHandle>,
    channel_seen: bool,
    exec_seen: bool,
}

enum ProtocolSignal {
    Idle,
    Progressed,
    Exec(String),
    Defunct,
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
    Complete(u32),
    Reset(&'static str),
    Rebind(&'static str),
}

enum ExecutionEnd {
    Complete {
        reports: Result<Vec<crate::vsh::JobReport>, crate::vsh::Diagnostic>,
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

/// Serve the QEMU acceptance endpoint with one active TCP/SSH peer at a time.
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
    let (outbound_endpoint, inbound_endpoint) = {
        let cspace = space.0.lock();
        let Ok(outbound_endpoint) =
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(outbound, Rights::SEND)
        else {
            crate::println!("FAIL ssh-test: outbound packet authority unavailable");
            return;
        };
        let Ok(inbound_endpoint) =
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(inbound, Rights::RECV)
        else {
            crate::println!("FAIL ssh-test: inbound packet authority unavailable");
            return;
        };
        (outbound_endpoint, inbound_endpoint)
    };

    let initial_entropy = match fetch_entropy(space, random, SEED_BYTES + 8).await {
        Ok(entropy) => entropy,
        Err(_) => {
            crate::println!("FAIL ssh-test: trusted entropy unavailable");
            return;
        }
    };
    let mut connection_seed = [0u8; SEED_BYTES];
    connection_seed.copy_from_slice(&initial_entropy.as_slice()[..SEED_BYTES]);
    if connection_seed.iter().all(|byte| *byte == 0) {
        wipe(&mut connection_seed);
        crate::println!("FAIL ssh-test: trusted entropy returned an all-zero seed");
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
    )
    .await
    {
        Ok(stack) => stack,
        Err(reason) => {
            wipe(&mut connection_seed);
            crate::println!("FAIL ssh-test: {reason}");
            return;
        }
    };
    let mut bound_epoch = match device_info(space, control) {
        Some(info) => info.session_epoch,
        None => {
            wipe(&mut connection_seed);
            crate::println!("FAIL ssh-test: network control authority unavailable");
            return;
        }
    };
    crate::println!("ssh-test listening on 10.0.2.15:2222");

    loop {
        match wait_for_connection(space, control, bound_epoch, &mut stack).await {
            Ok(()) => {}
            Err(reason) => {
                wipe(&mut connection_seed);
                crate::println!("FAIL ssh-test: {reason}");
                return;
            }
        }

        let seed = core::mem::replace(&mut connection_seed, [0; SEED_BYTES]);
        let outcome = serve_connection(
            space,
            control,
            bound_epoch,
            random,
            signer_read,
            signer_invoke,
            policy,
            &mut stack,
            seed,
        )
        .await;

        match outcome {
            ConnectionEnd::Complete(status) => {
                crate::println!("ssh-test exec complete: status {status}");
            }
            ConnectionEnd::Reset(reason) => {
                let _ = stack.reset();
                crate::println!("ssh-test connection reset: {reason}");
            }
            ConnectionEnd::Rebind(reason) => {
                let _ = stack.reset();
                crate::println!("ssh-test connection reset: {reason}");
                let next_entropy = match fetch_entropy(space, random, SEED_BYTES + 8).await {
                    Ok(entropy) => entropy,
                    Err(_) => {
                        crate::println!("FAIL ssh-test: trusted entropy unavailable during rebind");
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
                    crate::println!("FAIL ssh-test: trusted entropy returned an all-zero seed");
                    return;
                }
                let Some((next_outbound, next_inbound)) = stack_endpoints(space, outbound, inbound)
                else {
                    wipe(&mut connection_seed);
                    crate::println!("FAIL ssh-test: packet authority unavailable while rebinding");
                    return;
                };
                stack = match build_stack(
                    space,
                    control,
                    next_tcp_seed_value,
                    next_inbound,
                    next_outbound,
                )
                .await
                {
                    Ok(stack) => stack,
                    Err(reason) => {
                        wipe(&mut connection_seed);
                        crate::println!("FAIL ssh-test: {reason}");
                        return;
                    }
                };
                bound_epoch = match device_info(space, control) {
                    Some(info) => info.session_epoch,
                    None => {
                        wipe(&mut connection_seed);
                        crate::println!("FAIL ssh-test: network control authority unavailable");
                        return;
                    }
                };
                crate::println!("ssh-test listening on 10.0.2.15:2222");
                continue;
            }
        }

        // Rearm the reusable listener and prepare fresh connection-local
        // randomness before admitting another peer.
        for _ in 0..MAX_WIRE_IO_PER_TURN {
            let _ = stack.poll_network(monotonic_ms());
            if stack.is_listening() {
                break;
            }
            crate::exec::yield_now().await;
        }
        let entropy = match fetch_entropy(space, random, SEED_BYTES).await {
            Ok(entropy) => entropy,
            Err(_) => {
                crate::println!("FAIL ssh-test: trusted entropy unavailable for next connection");
                return;
            }
        };
        connection_seed.copy_from_slice(entropy.as_slice());
        drop(entropy);
        if connection_seed.iter().all(|byte| *byte == 0) {
            wipe(&mut connection_seed);
            crate::println!("FAIL ssh-test: trusted entropy returned an all-zero seed");
            return;
        }
    }
}

fn stack_endpoints(
    space: &Space,
    outbound: Cap,
    inbound: Cap,
) -> Option<(
    vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
    vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
)> {
    let cspace = space.0.lock();
    let outbound = cspace
        .lookup_revocable::<Endpoint<StampedPacket>>(outbound, Rights::SEND)
        .ok()?;
    let inbound = cspace
        .lookup_revocable::<Endpoint<StampedPacket>>(inbound, Rights::RECV)
        .ok()?;
    Some((outbound, inbound))
}

async fn build_stack(
    space: &Space,
    control: Cap,
    tcp_seed: u64,
    inbound: vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
    outbound: vibeos_core::cap::Revocable<Endpoint<StampedPacket>>,
) -> Result<StaticIpv4TcpStack, &'static str> {
    for _ in 0..NETWORK_RETRY_BUDGET {
        let info = device_info(space, control).ok_or("network control authority unavailable")?;
        if info.quarantined {
            return Err("network device is quarantined");
        }
        if !info.online {
            crate::exec::sleep_ms(1).await;
            continue;
        }
        match bind_stack(space, control) {
            Ok(stamp) => {
                let config = StaticIpv4Config::new(
                    GUEST_MAC,
                    GUEST_IPV4,
                    PREFIX_LEN,
                    LISTEN_PORT,
                    tcp_seed ^ stamp.device_epoch(),
                )
                .with_default_gateway(GATEWAY_IPV4);
                return StaticIpv4TcpStack::new(config, stamp, inbound, outbound)
                    .map_err(|_| "static IPv4/TCP stack construction failed");
            }
            Err(
                crate::virtio_net::NetError::Offline | crate::virtio_net::NetError::SessionBusy,
            ) => {
                crate::exec::sleep_ms(1).await;
            }
            Err(_) => return Err("network stack bind failed"),
        }
    }
    Err("network stack bind timed out")
}

async fn wait_for_connection(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    stack: &mut StaticIpv4TcpStack,
) -> Result<(), &'static str> {
    loop {
        validate_network_authority(space, control, bound_epoch)?;
        let report = stack
            .poll_network(monotonic_ms())
            .map_err(|_| "network listener poll failed")?;
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

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    space: &Space,
    control: Cap,
    bound_epoch: u64,
    _random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
    stack: &mut StaticIpv4TcpStack,
    mut seed: [u8; SEED_BYTES],
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
    let started = monotonic_ms();

    let command = loop {
        let now = monotonic_ms();
        if now.saturating_sub(started) > CONNECTION_TIMEOUT_MS {
            return reset_connection(stack, "SSH connection timed out");
        }
        if let Err(reason) = validate_network_authority(space, control, bound_epoch) {
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
        if let Err(reason) = discard_channel_input(&mut runner, &protocol) {
            return reset_connection(stack, reason);
        }
        match signal {
            ProtocolSignal::Exec(command) => break command,
            ProtocolSignal::Defunct => {
                return ConnectionEnd::Reset("SSH peer disconnected before exec")
            }
            ProtocolSignal::Idle | ProtocolSignal::Progressed => {}
        }
        if protocol
            .channel
            .as_ref()
            .is_some_and(|channel| runner.is_channel_closed(channel))
        {
            return ConnectionEnd::Reset("session channel closed before exec");
        }
        cooperate(
            wire.worked || matches!(signal, ProtocolSignal::Progressed),
            wire.next_poll_delay_ms,
        )
        .await;
    };

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
    )
    .await
    {
        Ok(()) => ConnectionEnd::Complete(status),
        Err(ConnectionEnd::Reset(reason)) => reset_connection(stack, reason),
        Err(other) => other,
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
                crate::println!("ssh-test Sunset protocol error: {error:?}");
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
                event.reject().map_err(|_| "first-auth rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::PasswordAuth(event)) => {
                state.candidate = None;
                event
                    .reject()
                    .map_err(|_| "password-auth rejection failed")?;
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
                if ours && state.authenticated && !state.exec_seen {
                    state.exec_seen = true;
                    let candidate = state
                        .committed
                        .ok_or("exec arrived without a committed profile")?;
                    if !revalidate_candidate(space, policy_cap, signer, candidate)? {
                        return Err("authorized profile changed before exec");
                    }
                    let value = event
                        .command()
                        .map_err(|_| "exec command was not valid UTF-8")?
                        .to_string();
                    if crate::vsh::validate_ssh_exec(&value).is_ok() {
                        command = Some(value);
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
                event.fail().map_err(|_| "shell rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionSubsystem(event)) => {
                event.fail().map_err(|_| "subsystem rejection failed")?;
                progressed = true;
            }
            Event::Serv(ServEvent::SessionPty(event)) => {
                event.fail().map_err(|_| "PTY rejection failed")?;
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
    let lease = space
        .0
        .lock()
        .lookup_lease::<AuthorizedKeyPolicyService>(policy_cap, Rights::READ)
        .map_err(|_| "authorized-key policy authority was revoked")?;
    let profile = ssh_security::profile_for_with(&lease, &key)
        .map_err(|_| "authorized-key policy lookup failed")?;
    let Some(profile) = profile else {
        return Ok(None);
    };
    if profile.generation != host.generation
        || profile.profile.get() != crate::ssh_test_fixture::TEST_PROFILE
    {
        return Ok(None);
    }
    Ok(Some(AuthCandidate { key, profile }))
}

fn revalidate_candidate(
    space: &Space,
    policy_cap: Cap,
    signer: &CapabilityHostSigner<'_>,
    expected: AuthCandidate,
) -> Result<bool, &'static str> {
    Ok(authorize(space, policy_cap, signer, expected.key)?
        .is_some_and(|candidate| candidate.profile == expected.profile))
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
) -> ExecutionEnd {
    let cancel = Arc::new(AtomicBool::new(false));
    let mut session = crate::vsh::Session::with_profile(crate::vsh::SessionProfile::SshExec);
    let mut execution = Box::pin(session.execute_ssh_cancellable(command, cancel.clone()));
    let started = monotonic_ms();
    let mut cancellation: Option<(ExecutionCancellation, u64)> = None;

    loop {
        if let Poll::Ready(reports) = poll_once(execution.as_mut()) {
            return match cancellation.map(|(kind, _)| kind) {
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
                return match kind {
                    ExecutionCancellation::Timeout => {
                        ExecutionEnd::Reset("VSH exec cancellation timed out")
                    }
                    ExecutionCancellation::Reset(reason) => ExecutionEnd::Reset(reason),
                    ExecutionCancellation::Rebind(reason) => ExecutionEnd::Rebind(reason),
                };
            }
            crate::exec::yield_now().await;
            continue;
        }
        if now.saturating_sub(started) > EXEC_TIMEOUT_MS {
            cancel.store(true, Ordering::Release);
            cancellation = Some((ExecutionCancellation::Timeout, now + CANCEL_GRACE_MS));
            continue;
        }

        if let Err(reason) = validate_network_authority(space, control, bound_epoch) {
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
            wire.worked || matches!(signal, ProtocolSignal::Progressed),
            wire.next_poll_delay_ms,
        )
        .await;
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    future.poll(&mut context)
}

fn collect_execution(
    reports: Result<Vec<crate::vsh::JobReport>, crate::vsh::Diagnostic>,
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

fn ssh_exit_status(status: crate::vsh::Status) -> u32 {
    match status {
        crate::vsh::Status::Success => 0,
        crate::vsh::Status::Returned(status) => status.into(),
        crate::vsh::Status::Usage => 2,
        crate::vsh::Status::Unavailable => 127,
        crate::vsh::Status::Denied => 126,
        crate::vsh::Status::BudgetExceeded => 124,
        crate::vsh::Status::Faulted => 125,
        crate::vsh::Status::Cancelled => 130,
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
) -> Result<(), ConnectionEnd> {
    let started = monotonic_ms();
    let mut offset = 0usize;
    let mut exit_sent = false;
    let mut eof_sent = false;
    let mut close_sent = false;
    let mut tcp_close_requested = false;

    loop {
        let now = monotonic_ms();
        if now.saturating_sub(started) > CLOSE_TIMEOUT_MS {
            return Err(ConnectionEnd::Reset("SSH completion drain timed out"));
        }
        if let Err(reason) = validate_network_authority(space, control, bound_epoch) {
            return Err(ConnectionEnd::Rebind(reason));
        }
        let wire = bridge
            .drive(runner, stack, now)
            .map_err(ConnectionEnd::Reset)?;
        if wire.ended {
            return if tcp_close_requested {
                Ok(())
            } else {
                Err(ConnectionEnd::Reset(
                    "peer disconnected before SSH completion was acknowledged",
                ))
            };
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
                stack
                    .close()
                    .map_err(|_| ConnectionEnd::Reset("TCP close failed"))?;
                return Ok(());
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
                .ok_or(ConnectionEnd::Reset("accepted exec lost its channel"))?;
            if offset < output.len() {
                match runner.write_channel(channel, ChanData::Normal, &output[offset..]) {
                    Ok(0) => {}
                    Ok(written) => {
                        offset += written;
                        application_work = true;
                    }
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

        if close_sent
            && protocol.channel.is_none()
            && !tcp_close_requested
            && runner.is_output_drained()
        {
            stack
                .close()
                .map_err(|_| ConnectionEnd::Reset("TCP close failed"))?;
            tcp_close_requested = true;
            application_work = true;
        }
        if tcp_close_requested && !stack.connection_active() {
            return Ok(());
        }

        cooperate(
            wire.worked || application_work || matches!(signal, ProtocolSignal::Progressed),
            wire.next_poll_delay_ms,
        )
        .await;
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
) -> Result<(), &'static str> {
    let info = device_info(space, control).ok_or("network control authority was revoked")?;
    if info.quarantined {
        return Err("network device was quarantined");
    }
    if !info.online {
        return Err("network device went offline");
    }
    if info.session_epoch != bound_epoch {
        return Err("network device session changed");
    }
    Ok(())
}

fn bind_stack(space: &Space, control: Cap) -> Result<PacketStamp, crate::virtio_net::NetError> {
    let lease = space
        .0
        .lock()
        .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::INVOKE)
        .map_err(|_| crate::virtio_net::NetError::AuthorityRevoked)?;
    crate::virtio_net::bind_stack_with(&lease)
}

fn device_info(space: &Space, control: Cap) -> Option<crate::virtio_net::NetInfo> {
    let lease = space
        .0
        .lock()
        .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::READ)
        .ok()?;
    crate::virtio_net::info_with(&lease).ok()
}

async fn fetch_entropy(
    space: &Space,
    random: Cap,
    length: usize,
) -> Result<RandomBytes, RandomError> {
    for _ in 0..ENTROPY_RETRY_BUDGET {
        let lease = space
            .0
            .lock()
            .lookup_lease::<virtio_rng::RandomSource>(random, Rights::READ)
            .map_err(|_| RandomError::AuthorityRevoked)?;
        match virtio_rng::bytes_with(lease, length).await {
            Ok(bytes) => return Ok(bytes),
            Err(RandomError::Offline | RandomError::Busy | RandomError::DriverRestarted) => {
                crate::exec::sleep_ms(1).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(RandomError::TimedOut)
}

async fn cooperate(worked: bool, next_poll_delay_ms: Option<u64>) {
    if worked {
        crate::exec::yield_now().await;
    } else {
        let delay = next_poll_delay_ms
            .unwrap_or(IDLE_POLL_CEILING_MS)
            .clamp(1, IDLE_POLL_CEILING_MS);
        crate::exec::sleep_ms(delay).await;
    }
}

fn monotonic_ms() -> u64 {
    let hz = crate::exec::timebase_hz();
    crate::sbi::time().saturating_mul(1_000) / hz
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // Secret cleanup is best-effort on ordinary task teardown; the kernel
        // arena additionally zeroes memory before cross-domain reuse.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}
