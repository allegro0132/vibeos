//! Kernel adapters for the separately compiled SSH component.
//!
//! This module is intentionally thin: it resolves capabilities against the
//! component CSpace and translates kernel-private device/security services to
//! the platform-neutral interface implemented by `vibeos-sshd`.

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;

use vibeos_core::cap::{Cap, Rights};
use vibeos_core::chan::Endpoint;
use vibeos_core::net::StampedPacket;
use vibeos_core::ssh_identity::SshEd25519PublicKey;
use vibeos_sshd::{
    AuthorizedProfile, HostPublicKeySnapshot, HostSignatureResult, NetworkBindError, NetworkInfo,
    Platform, PlatformFuture, SecretBytes,
};

use crate::ssh_security::{AuthorizedKeyPolicyService, HostSigningService};
use crate::world::Space;

#[cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]
use crate::ssh_acceptance_rng as ssh_rng;
#[cfg(feature = "qemu-virt")]
use crate::virtio_rng as ssh_rng;
use ssh_rng::RandomError;

const ENTROPY_RETRY_BUDGET: usize = 5_000;

struct SshPlatform {
    space: &'static Space,
}

impl SshPlatform {
    const fn new(space: &'static Space) -> Self {
        Self { space }
    }
}

impl Platform for SshPlatform {
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
            .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::INVOKE)
            .map_err(|_| NetworkBindError::Denied)?;
        crate::virtio_net::bind_stack_with(&lease).map_err(|error| match error {
            crate::virtio_net::NetError::Offline => NetworkBindError::Offline,
            crate::virtio_net::NetError::SessionBusy => NetworkBindError::SessionBusy,
            crate::virtio_net::NetError::AuthorityRevoked
            | crate::virtio_net::NetError::PermissionDenied => NetworkBindError::Denied,
            _ => NetworkBindError::Failed,
        })
    }

    fn network_info(&self, control: Cap) -> Option<NetworkInfo> {
        let lease = self
            .space
            .0
            .lock()
            .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::READ)
            .ok()?;
        let info = crate::virtio_net::info_with(&lease).ok()?;
        Some(NetworkInfo {
            online: info.online,
            quarantined: info.quarantined,
            session_epoch: info.session_epoch,
            #[cfg(feature = "qemu-virt")]
            phy_link_up: true,
            #[cfg(feature = "milkv-ssh-acceptance")]
            phy_link_up: info.phy_link_up,
        })
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
            .filter(|profile| profile.profile.get() == crate::ssh_test_fixture::TEST_PROFILE)
            .map(|profile| AuthorizedProfile {
                generation: profile.generation.get(),
                profile: profile.profile,
            }))
    }

    fn install_standard_vsh_commands(&self, session: &mut vibeos_core::vsh::Session) {
        crate::vsh_platform::install_standard_commands(session);
    }

    fn log(&self, args: fmt::Arguments<'_>) {
        crate::uart::_print(format_args!("{args}\n"));
    }
}

#[allow(clippy::too_many_arguments)]
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
    vibeos_sshd::task(
        &platform,
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
