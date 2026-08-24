//! C7.7 graph-only ephemeral boot typestate.
//!
//! This path can only consume the object store's exact-final-G1 gate.  After
//! its independent physical readback, both durable graph versions are freshly
//! decoded, authenticated, and admitted under current image policy.  The sole
//! output is an opaque boot-local projection of the already-final successor;
//! no durable write authority, predecessor bytes, candidate, runtime object,
//! task, CSpace, memory, resource, fuel, or pending-call state is exposed.

use core::fmt;

use vibeos_component_admission::{CallerAuthority, OperatorComponentGraphAdmissionPolicy};
use vibeos_object_store::{
    begin_c77_exact_final_g1, C76AuthorityJournal, C76FinalGraph, C77ExactFinalG1Error,
    C77PendingFinalG1Readback,
};

use super::graph_publication::revalidate_c76_final_g1_to_current;
use super::{C76GraphInstallProtocolError, C76SupervisorCurrentGraph};

/// Redacted C7.7 cold-boot failures.  Neither variant exposes recovered bytes,
/// durable identity, policy internals, or boot-local execution state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C77EphemeralBootError {
    Storage(C77ExactFinalG1Error),
    Revalidation(C76GraphInstallProtocolError),
}

impl fmt::Display for C77EphemeralBootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "C7.7 exact-final physical graph recovery failed",
            Self::Revalidation(_) => "C7.7 current-policy graph revalidation failed",
        })
    }
}

impl From<C77ExactFinalG1Error> for C77EphemeralBootError {
    fn from(error: C77ExactFinalG1Error) -> Self {
        Self::Storage(error)
    }
}

impl From<C76GraphInstallProtocolError> for C77EphemeralBootError {
    fn from(error: C76GraphInstallProtocolError) -> Self {
        Self::Revalidation(error)
    }
}

/// First C7.7 typestate: a graph-only final G1 namespace has passed sealed
/// logical recovery and awaits its one independent physical readback.
///
/// ```compile_fail
/// use vibeos_component_loader::C77PendingGraphReadback;
/// fn require_clone<T: Clone>() {}
/// fn cannot_duplicate() { require_clone::<C77PendingGraphReadback>(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C77PendingGraphReadback;
/// async fn cannot_replay(pending: C77PendingGraphReadback) {
///     let _ = pending.recover_graph().await;
///     let _ = pending.recover_graph().await;
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C77PendingGraphReadback;
/// async fn no_write_lookup_or_storage_escape(pending: C77PendingGraphReadback) {
///     let _ = pending.install_initial(()).await;
///     let _ = pending.replace(()).await;
///     let _ = pending.append(&[]).await;
///     let _ = pending.snapshot();
///     let _ = pending.object_id();
///     let _ = pending.recover_final().await;
/// }
/// ```
#[must_use = "C7.7 pending graph readback must be consumed or discarded"]
pub struct C77PendingGraphReadback {
    pending: C77PendingFinalG1Readback,
}

/// Second C7.7 typestate: exact physical final-G1 bytes awaiting one current
/// policy/current-engine revalidation.  Its byte-bearing graph is private.
///
/// ```compile_fail
/// use vibeos_component_loader::C77RecoveredFinalGraph;
/// fn require_clone<T: Clone>() {}
/// fn cannot_duplicate() { require_clone::<C77RecoveredFinalGraph>(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C77RecoveredFinalGraph;
/// fn no_bytes_ids_or_replacement(graph: C77RecoveredFinalGraph) {
///     let _ = graph.predecessor();
///     let _ = graph.successor();
///     let _ = graph.descriptor_bytes();
///     let _ = graph.object_id();
///     let _ = graph.replace(());
///     let _ = graph.take_current_supervisor();
/// }
/// ```
#[must_use = "C7.7 recovered final graph must be freshly revalidated or discarded"]
pub struct C77RecoveredFinalGraph {
    graph: C76FinalGraph,
}

/// Begin the C7.7 cold-boot path from the sealed C7.6 authority journal.  This
/// performs no write and accepts neither vacant/G0 media nor a namespace with
/// persistent/program or other extra history.
pub fn begin_c77_ephemeral_boot(
    journal: C76AuthorityJournal,
) -> impl core::future::Future<Output = Result<C77PendingGraphReadback, C77EphemeralBootError>> {
    // Construct the storage future synchronously.  That call mints its
    // revoke-on-drop guard before this loader future can be left unpolled.
    let storage_recovery = begin_c77_exact_final_g1(journal);
    async move {
        let pending = storage_recovery.await?;
        Ok(C77PendingGraphReadback { pending })
    }
}

impl C77PendingGraphReadback {
    /// Consume the first typestate and perform the one independent physical
    /// graph-only readback.  No policy claim is made until the next state.
    pub async fn recover_graph(self) -> Result<C77RecoveredFinalGraph, C77EphemeralBootError> {
        let graph = self.pending.recover_final().await?;
        Ok(C77RecoveredFinalGraph { graph })
    }
}

impl C77RecoveredFinalGraph {
    /// Freshly revalidate predecessor and successor as the exact authorized
    /// PolicyCancel replacement, then release only the opaque successor
    /// current graph.  The returned template remains `runtime_ready=false`.
    pub fn revalidate_current_on_boot(
        self,
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<C76SupervisorCurrentGraph, C77EphemeralBootError> {
        Ok(revalidate_c76_final_g1_to_current(
            self.graph, policy, caller,
        )?)
    }
}
