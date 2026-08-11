//! Capability-confined configurable IPv4 stack and bounded TCP echo service.
//!
//! QEMU compiles it for the dedicated `tcp-echo` acceptance image. Milk-V Duo
//! compiles the same capability-confined stack for its production `net-shell`
//! image, starting in DHCP mode.

#![no_std]

extern crate alloc;

#[cfg(feature = "tcp-echo-recovery-test")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use vibeos_core::cap::{Cap, Revocable};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{PacketStamp, StampedPacket};
use vibeos_core::net_stack::{StackError, StaticIpv4Config, StaticIpv4EchoStack};

pub mod config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkInfo {
    pub online: bool,
    pub quarantined: bool,
    pub session_epoch: u64,
    pub phy_link_up: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBindError {
    Offline,
    SessionBusy,
    Denied,
    Failed,
}

/// Privileged packet and network-control operations consumed by this component.
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
}

type Space = dyn Platform;

const GUEST_MAC: [u8; 6] = config::DEFAULT_MAC;
const GUEST_IPV4: [u8; 4] = config::DEFAULT_IPV4;
const GATEWAY_IPV4: [u8; 4] = config::DEFAULT_GATEWAY;
const PREFIX_LEN: u8 = config::DEFAULT_PREFIX_LEN;
const LISTEN_PORT: u16 = 2222;
const TCP_TEST_SEED: u64 = 0x5649_4245_4f53_4e31;
const IDLE_POLL_CEILING_MS: u64 = 10;

#[cfg(feature = "tcp-echo")]
pub const COMPONENT_NAME: &str = "tcp-echo";
#[cfg(feature = "net-shell")]
pub const COMPONENT_NAME: &str = "net-stack";

#[cfg(feature = "tcp-echo-recovery-test")]
static FAULT_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "tcp-echo-recovery-test")]
static REJECTED_DEVICE_EPOCH_INGRESS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "tcp-echo-recovery-test")]
static REJECTED_STACK_GENERATION_INGRESS: AtomicU64 = AtomicU64::new(0);

/// Request one component-local injected fault after the kernel has staged the
/// recovery fixture. This symbol does not exist in production images.
#[cfg(feature = "tcp-echo-recovery-test")]
pub fn request_fault_for_test() {
    FAULT_REQUESTED.store(true, Ordering::Release);
}

/// Return the component-side stale-ingress rejection counters used by N2.
#[cfg(feature = "tcp-echo-recovery-test")]
pub fn rejected_ingress_for_test() -> (u64, u64) {
    (
        REJECTED_DEVICE_EPOCH_INGRESS.load(Ordering::Acquire),
        REJECTED_STACK_GENERATION_INGRESS.load(Ordering::Acquire),
    )
}

/// Run the feature-gated transport proof with SEND/RECV plus control READ and
/// the narrow INVOKE operation required to mint a fresh packet-session stamp.
pub async fn task(space: &Space, outbound_cap: Cap, inbound_cap: Cap, control_cap: Cap) {
    let (outbound, inbound) = match space.packet_endpoints(outbound_cap, inbound_cap) {
        Some(endpoints) => endpoints,
        None => return,
    };

    let mut observed_epoch = None;
    let mut observed_config_revision = 0;
    let mut stack = None;
    loop {
        #[cfg(feature = "tcp-echo-recovery-test")]
        if FAULT_REQUESTED.swap(false, Ordering::AcqRel) {
            panic!("injected TCP stack fault");
        }

        let Some(info) = device_info(space, control_cap) else {
            return;
        };
        #[cfg(feature = "qemu-virt")]
        config::publish_carrier(info.online);
        #[cfg(feature = "milkv-duo")]
        config::publish_carrier(info.online && info.phy_link_up);
        if info.quarantined {
            return;
        }
        if !info.online {
            vibeos_core::exec::sleep_ms(1).await;
            continue;
        }

        if observed_epoch != Some(info.session_epoch) {
            let stamp = match bind_stack(space, control_cap) {
                Ok(stamp) => stamp,
                Err(NetworkBindError::SessionBusy | NetworkBindError::Offline) => {
                    vibeos_core::exec::sleep_ms(1).await;
                    continue;
                }
                Err(_) => return,
            };
            let config = StaticIpv4Config::new(
                GUEST_MAC,
                GUEST_IPV4,
                PREFIX_LEN,
                LISTEN_PORT,
                TCP_TEST_SEED ^ stamp.device_epoch(),
            )
            .with_default_gateway(GATEWAY_IPV4);
            let next =
                match StaticIpv4EchoStack::new(config, stamp, inbound.clone(), outbound.clone()) {
                    Ok(stack) => stack,
                    Err(_) => return,
                };
            stack = Some(next);
            observed_epoch = Some(stamp.device_epoch());
            observed_config_revision = 0;
        }

        let active_stack = stack
            .as_mut()
            .expect("an observed network epoch has a protocol stack");
        if config::reconcile(active_stack, &mut observed_config_revision).is_err() {
            return;
        }
        let now_ms = monotonic_ms();
        let report = match active_stack.poll(now_ms) {
            Ok(report) => report,
            Err(StackError::AuthorityRevoked) => return,
            Err(_) => return,
        };
        config::publish_stack_status(observed_config_revision, active_stack.ipv4_status());
        #[cfg(feature = "tcp-echo-recovery-test")]
        {
            let device_stats = stack
                .as_ref()
                .expect("a polled network epoch has a protocol stack")
                .device_stats();
            REJECTED_DEVICE_EPOCH_INGRESS
                .store(device_stats.rejected_device_epoch_frames, Ordering::Release);
            REJECTED_STACK_GENERATION_INGRESS.store(
                device_stats.rejected_stack_generation_frames,
                Ordering::Release,
            );
        }

        if report.more_work {
            vibeos_core::exec::yield_now().await;
        } else {
            let delay = report
                .next_poll_delay_ms
                .unwrap_or(IDLE_POLL_CEILING_MS)
                .clamp(1, IDLE_POLL_CEILING_MS);
            vibeos_core::exec::sleep_ms(delay).await;
        }
    }
}

fn bind_stack(space: &Space, control_cap: Cap) -> Result<PacketStamp, NetworkBindError> {
    space.bind_stack(control_cap)
}

fn device_info(space: &Space, control_cap: Cap) -> Option<NetworkInfo> {
    space.network_info(control_cap)
}

fn monotonic_ms() -> u64 {
    let hz = vibeos_core::exec::timebase_hz();
    vibeos_core::arch::time().saturating_mul(1_000) / hz
}
