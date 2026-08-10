//! N1 acceptance service: one static IPv4 interface and one TCP echo socket.
//!
//! This module is compiled only for the dedicated `tcp-echo` image. It keeps
//! the protocol stack behind attenuated packet/control capabilities and is not
//! part of the eventual SSH security boundary.

use crate::cap::{Cap, Revocable, Rights};
use crate::chan::Endpoint;
use crate::net::Packet;
use crate::world::Space;
use vibeos_core::net_stack::{StackError, StaticIpv4Config, StaticIpv4EchoStack};

const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const GUEST_IPV4: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IPV4: [u8; 4] = [10, 0, 2, 2];
const PREFIX_LEN: u8 = 24;
const LISTEN_PORT: u16 = 2222;
const TCP_TEST_SEED: u64 = 0x5649_4245_4f53_4e31;
const IDLE_POLL_CEILING_MS: u64 = 10;

/// Run the feature-gated transport proof with only SEND/RECV/READ authority.
pub async fn task(space: &'static Space, outbound_cap: Cap, inbound_cap: Cap, control_cap: Cap) {
    let (outbound, inbound) = {
        let cspace = space.0.lock();
        let Ok(outbound) = cspace.lookup_revocable::<Endpoint<Packet>>(outbound_cap, Rights::SEND)
        else {
            return;
        };
        let Ok(inbound) = cspace.lookup_revocable::<Endpoint<Packet>>(inbound_cap, Rights::RECV)
        else {
            return;
        };
        (outbound, inbound)
    };

    let mut observed_epoch = None;
    let mut stack = None;
    loop {
        let Some(info) = device_info(space, control_cap) else {
            return;
        };
        if info.quarantined {
            return;
        }
        if !info.online {
            crate::exec::sleep_ms(1).await;
            continue;
        }

        if observed_epoch != Some(info.session_epoch) {
            if drain_stale_ingress(&inbound).is_err() {
                return;
            }
            let config = StaticIpv4Config::new(
                GUEST_MAC,
                GUEST_IPV4,
                PREFIX_LEN,
                LISTEN_PORT,
                TCP_TEST_SEED ^ info.session_epoch,
            )
            .with_default_gateway(GATEWAY_IPV4);
            let next = match StaticIpv4EchoStack::new(config, inbound.clone(), outbound.clone()) {
                Ok(stack) => stack,
                Err(_) => return,
            };
            stack = Some(next);
            observed_epoch = Some(info.session_epoch);
        }

        let now_ms = monotonic_ms();
        let report = match stack
            .as_mut()
            .expect("an observed network epoch has a protocol stack")
            .poll(now_ms)
        {
            Ok(report) => report,
            Err(StackError::AuthorityRevoked) => return,
            Err(_) => return,
        };

        if report.more_work {
            crate::exec::yield_now().await;
        } else {
            let delay = report
                .next_poll_delay_ms
                .unwrap_or(IDLE_POLL_CEILING_MS)
                .clamp(1, IDLE_POLL_CEILING_MS);
            crate::exec::sleep_ms(delay).await;
        }
    }
}

fn device_info(space: &Space, control_cap: Cap) -> Option<crate::virtio_net::NetInfo> {
    let lease = space
        .0
        .lock()
        .lookup_lease::<crate::virtio_net::NetDevice>(control_cap, Rights::READ)
        .ok()?;
    crate::virtio_net::info_with(&lease).ok()
}

/// Drop exactly the frames queued before the newly observed device epoch.
fn drain_stale_ingress(inbound: &Revocable<Endpoint<Packet>>) -> Result<usize, StackError> {
    inbound
        .try_with(|endpoint| {
            let depth = endpoint.stats().2;
            for _ in 0..depth {
                let _ = endpoint.try_recv();
            }
            depth
        })
        .map_err(|_| StackError::AuthorityRevoked)
}

fn monotonic_ms() -> u64 {
    let hz = crate::exec::timebase_hz();
    crate::sbi::time().saturating_mul(1_000) / hz
}
