//! C7.7 exact-final-G1, graph-only cold-boot gate.
//!
//! The gate consumes C7.6's sealed journal and accepts only a complete
//! two-version G1 history whose *entire* logical namespace consists of the
//! fixed graph objects, grants, and slot.  It then performs one independent
//! physical readback and repeats that exact namespace check before releasing
//! the already-final graph bytes.  No durable write transition survives.

use super::{
    c76::{c77_recover_exact_final_g1, c77_take_exact_final_g1, C77BootProofRevocation},
    C76AuthorityJournal, C76FinalGraph, C76PendingPhysicalReadback,
};
use core::fmt;

/// Redacted failures for the terminal C7.7 storage gate.  The variants carry
/// no object, grant, slot, checkpoint, stable identity, or recovered bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C77ExactFinalG1Error {
    Recovery,
    NotExactFinalG1,
    PhysicalReadback,
}

impl fmt::Display for C77ExactFinalG1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Recovery => "C7.7 sealed V3 recovery failed",
            Self::NotExactFinalG1 => "C7.7 requires an exact graph-only final G1 namespace",
            Self::PhysicalReadback => "C7.7 independent physical readback failed",
        })
    }
}

/// Move-only terminal checkpoint awaiting its one independent physical
/// readback.  It exposes no candidate, append, generic lookup, snapshot, or
/// raw durable identity operation.
///
/// ```compile_fail
/// use vibeos_object_store::C77PendingFinalG1Readback;
/// fn require_clone<T: Clone>() {}
/// fn cannot_duplicate() { require_clone::<C77PendingFinalG1Readback>(); }
/// ```
///
/// ```compile_fail
/// use vibeos_object_store::C77PendingFinalG1Readback;
/// async fn cannot_replay(pending: C77PendingFinalG1Readback) {
///     let _ = pending.recover_final().await;
///     let _ = pending.recover_final().await;
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_object_store::C77PendingFinalG1Readback;
/// async fn no_write_or_lookup(pending: C77PendingFinalG1Readback) {
///     let _ = pending.append(&[]).await;
///     let _ = pending.install_initial(()).await;
///     let _ = pending.replace(()).await;
///     let _ = pending.snapshot();
///     let _ = pending.object_id();
/// }
/// ```
#[must_use = "the exact-final C7.7 checkpoint must be physically read or discarded"]
pub struct C77PendingFinalG1Readback {
    pending: Option<C76PendingPhysicalReadback>,
    _terminal_revocation: C77BootProofRevocation,
}

/// Consume a C7.6 boot journal and classify its first recovered checkpoint as
/// the exact terminal graph-only namespace.  Vacant, G0, persistent/program
/// history (including tombstoned history), and any extra record fail closed.
pub fn begin_c77_exact_final_g1(
    journal: C76AuthorityJournal,
) -> impl core::future::Future<Output = Result<C77PendingFinalG1Readback, C77ExactFinalG1Error>> {
    // This must happen outside the async body: dropping an unpolled future is
    // itself a terminal C7.7 exit and must revoke the boot proof.
    let terminal_revocation = journal.c77_terminal_revocation();
    async move {
        let state = journal
            .recover_exact_v3()
            .await
            .map_err(|_| C77ExactFinalG1Error::Recovery)?;
        let pending =
            c77_take_exact_final_g1(state).map_err(|_| C77ExactFinalG1Error::NotExactFinalG1)?;
        Ok(C77PendingFinalG1Readback {
            pending: Some(pending),
            _terminal_revocation: terminal_revocation,
        })
    }
}

impl C77PendingFinalG1Readback {
    /// Consume the pending gate, perform exactly one independent physical
    /// namespace/readback validation, and return an already-final G1 graph.
    /// The result has no append or replacement transition.
    pub async fn recover_final(mut self) -> Result<C76FinalGraph, C77ExactFinalG1Error> {
        let pending = self
            .pending
            .take()
            .ok_or(C77ExactFinalG1Error::PhysicalReadback)?;
        let result = c77_recover_exact_final_g1(pending)
            .await
            .map_err(|_| C77ExactFinalG1Error::PhysicalReadback);
        // Keep the cancellation guard alive through the physical await.  Its
        // drop is the terminal transition for both success and failure.
        drop(self);
        result
    }
}
