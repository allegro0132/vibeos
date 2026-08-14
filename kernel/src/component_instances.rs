//! SYSTEM-owned lifecycle registry for managed WASM component invocations.
//!
//! Production command admission is intentionally not installed yet.  Keeping
//! the fixed registry and fault dispatcher live before VSH integration makes
//! the safety boundary fail closed: a witness carrying a managed token can
//! never fall through to the older World/domain-only recovery path.

use crate::exec::ReclaimableFaultWitness;
use crate::instance::{FaultGateOutcome, InstanceRegistry};
use crate::HEAP;

static INSTANCES: InstanceRegistry = InstanceRegistry::new();

pub(crate) fn registry() -> &'static InstanceRegistry {
    &INSTANCES
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultRoute {
    Legacy,
    ManagedReclaimed,
    Quarantined,
}

/// Classify a detached fault before any legacy recovery hook can mutate
/// stable state.  The registry performs the complete generation/task/status/
/// owner/arena/hart/Space/CSpace gate; only that success authorizes raw arena
/// reclamation.  It never resets the CSpace here.
///
/// # Safety
///
/// `witness` is supplied only by the executor after permanent detach and its
/// all-hart quiescence proof.  The exact registry domain, if any, must still be
/// active in `HEAP`.
pub(crate) unsafe fn reclaim_faulted(witness: ReclaimableFaultWitness) -> FaultRoute {
    let task = witness.task_id();
    match unsafe {
        registry().fault_reclaim(witness, |domain| {
            // Managed exact-task cleanup is deliberately delayed until after
            // the registry's complete identity/CSpace gate.  The executor
            // skips its legacy pre-reclaimer cleanup for token-bearing
            // witnesses, so a mismatch cannot mutate stable task state.
            crate::cleanup_faulted_task(task, domain);
            // Recover only shared service state which is keyed by this exact
            // allocation domain.  The legacy World hook is intentionally not
            // reused: this registry, rather than World, owns the managed
            // instance's Space/CSpace lifecycle and reset authority.
            crate::block_device::recover_faulted_domain(domain);
            crate::net_device::recover_faulted_domain(domain);
            #[cfg(feature = "qemu-virt")]
            crate::virtio_rng::recover_faulted_domain(domain);
            crate::code_pool::recover_faulted_domain(domain);
            HEAP.reclaim_faulted_domain(domain)
                .expect("registry-authorized managed arena must reclaim atomically");
            true
        })
    } {
        FaultGateOutcome::NotManaged => FaultRoute::Legacy,
        FaultGateOutcome::ManagedReclaimed => FaultRoute::ManagedReclaimed,
        FaultGateOutcome::Quarantined => FaultRoute::Quarantined,
    }
}
