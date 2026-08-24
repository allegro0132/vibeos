//! C7.6 durable graph-version replacement and scoped supervisor handoff.
//!
//! Candidate validation is persistence hygiene only. It is destroyed before
//! append. A supervisor handoff can be minted only from an independently
//! physically read G1 checkpoint containing exact G0 and G1 bytes; both
//! complete bundles then repeat graph and leaf signatures, current policy,
//! current engines, atomic graph admission, version linkage, and C6.6
//! single-target replacement admission.

use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use vibeos_component_admission::{
    admit_authenticated_component_graph_replacement, admit_authenticated_component_graph_version,
    authenticate_component_graph_version, CallerAuthority, ComponentGraphAuthenticationError,
    ComponentGraphReplacementEdgePolicy, ComponentGraphReplacementNodeAction,
    OperatorComponentGraphAdmissionPolicy,
};
use vibeos_component_command::{
    ComponentGraphNodeReplacementTemplate, ComponentGraphNodeReplacementTemplateError,
    ComponentGraphPrincipalTemplate, ComponentGraphPrincipalTemplateError,
};
use vibeos_component_format::{
    ComponentArtifactAuthenticationError, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactError, ComponentArtifactV1, ComponentGraphVersionAuthenticationError,
    ComponentGraphVersionAuthenticationEvidenceV1, ComponentGraphVersionBundleV1,
    ComponentGraphVersionError, ComponentGraphVersionV1,
    COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN,
    COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN,
};
use vibeos_object_store::{
    C76AuthorityJournal, C76FinalGraph, C76GraphVersionBytes, C76GraphVersionInput,
    C76PendingPhysicalReadback, C76RecoveredGraphState, C76RecoveredState, C76ReplaceableGraph,
    C76StorageV2Error, C76VacantHead, StoreError, C76_GRAPH_COMPONENT_COUNT,
};

/// Redacted failures for the fixed C7.6 protocol.  No variant contains a
/// durable object, root, slot, checkpoint, capability, or recovered bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C76GraphInstallProtocolError {
    Storage(C76StorageV2Error),
    PhysicalReadback(StoreError),
    Descriptor(ComponentGraphVersionError),
    Artifact(ComponentArtifactError),
    ArtifactEvidence(ComponentArtifactAuthenticationError),
    GraphEvidence(ComponentGraphVersionAuthenticationError),
    Authentication(ComponentGraphAuthenticationError),
    PrincipalProjection(ComponentGraphPrincipalTemplateError),
    ReplacementProjection(ComponentGraphNodeReplacementTemplateError),
    WrongVersion,
    PolicyCancelRequired,
    Allocation,
}

impl fmt::Display for C76GraphInstallProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Storage(_) => "C7.6 durable graph transition failed",
            Self::PhysicalReadback(_) => "C7.6 physical graph readback failed",
            Self::Descriptor(_) => "C7.6 graph descriptor is invalid",
            Self::Artifact(_) => "one C7.6 component artifact is invalid",
            Self::ArtifactEvidence(_) => "one C7.6 component evidence value is invalid",
            Self::GraphEvidence(_) => "C7.6 graph evidence is invalid",
            Self::Authentication(_) => "C7.6 current-policy graph admission failed",
            Self::PrincipalProjection(_) => "C7.6 current graph projection failed",
            Self::ReplacementProjection(_) => "C7.6 replacement projection failed",
            Self::WrongVersion => "C7.6 graph ordinal or predecessor is invalid",
            Self::PolicyCancelRequired => "C7.6 replacement is not explicit PolicyCancel",
            Self::Allocation => "C7.6 graph protocol allocation failed",
        })
    }
}

/// Canonical authority-free bytes retained by an image installation candidate.
/// Fresh admission values are always destroyed before this value is returned.
struct C76CanonicalGraphVersion {
    descriptor: Vec<u8>,
    artifacts: [Vec<u8>; C76_GRAPH_COMPONENT_COUNT],
    artifact_evidence:
        [[u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN]; C76_GRAPH_COMPONENT_COUNT],
    graph_evidence: [u8; COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN],
}

impl C76CanonicalGraphVersion {
    fn storage_input(&self) -> C76GraphVersionInput<'_> {
        C76GraphVersionInput {
            descriptor_bytes: &self.descriptor,
            component_artifact_bytes: [&self.artifacts[0], &self.artifacts[1], &self.artifacts[2]],
            component_evidence_bytes: [
                &self.artifact_evidence[0],
                &self.artifact_evidence[1],
                &self.artifact_evidence[2],
            ],
            graph_evidence_bytes: &self.graph_evidence,
        }
    }
}

/// Private, move-only G0 installation bytes. This type contains no admitted
/// graph, supervisor template, runtime object, or durable authority. It can be
/// constructed only while consuming a classified vacant V3 head.
struct C76InitialGraphInstallCandidate {
    canonical: C76CanonicalGraphVersion,
}

/// Private, move-only G1 installation bytes. It can be constructed only while
/// consuming a successor-admission gate minted from physically read and
/// freshly validated G0.
struct C76SuccessorGraphInstallCandidate {
    canonical: C76CanonicalGraphVersion,
}

impl C76InitialGraphInstallCandidate {
    fn admit(
        _vacant: &C76VacantGraphInstall,
        descriptor_bytes: &[u8],
        component_artifact_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        component_evidence_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        graph_evidence_bytes: &[u8],
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<Self, C76GraphInstallProtocolError> {
        let canonical = canonical_candidate(
            descriptor_bytes,
            component_artifact_bytes,
            component_evidence_bytes,
            graph_evidence_bytes,
        )?;
        let fresh = fresh_version(&canonical, policy, caller)?;
        if fresh.descriptor().ordinal() != 0 || fresh.descriptor().predecessor().is_some() {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        drop(fresh);
        Ok(Self { canonical })
    }
}

impl C76SuccessorGraphInstallCandidate {
    fn admit(
        _gate: &C76SuccessorGraphAdmissionGate,
        descriptor_bytes: &[u8],
        component_artifact_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        component_evidence_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        graph_evidence_bytes: &[u8],
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<Self, C76GraphInstallProtocolError> {
        let canonical = canonical_candidate(
            descriptor_bytes,
            component_artifact_bytes,
            component_evidence_bytes,
            graph_evidence_bytes,
        )?;
        let fresh = fresh_version(&canonical, policy, caller)?;
        if fresh.descriptor().ordinal() != 1 || fresh.descriptor().predecessor().is_none() {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        drop(fresh);
        Ok(Self { canonical })
    }
}

fn canonical_candidate(
    descriptor_bytes: &[u8],
    component_artifact_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
    component_evidence_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
    graph_evidence_bytes: &[u8],
) -> Result<C76CanonicalGraphVersion, C76GraphInstallProtocolError> {
    let descriptor = ComponentGraphVersionV1::decode(descriptor_bytes)
        .map_err(C76GraphInstallProtocolError::Descriptor)?;
    let canonical_descriptor = descriptor
        .encode()
        .map_err(C76GraphInstallProtocolError::Descriptor)?;
    if canonical_descriptor.as_slice() != descriptor_bytes {
        return Err(C76GraphInstallProtocolError::WrongVersion);
    }

    let mut artifacts = Vec::new();
    artifacts
        .try_reserve_exact(C76_GRAPH_COMPONENT_COUNT)
        .map_err(|_| C76GraphInstallProtocolError::Allocation)?;
    for bytes in component_artifact_bytes {
        let artifact =
            ComponentArtifactV1::decode(bytes).map_err(C76GraphInstallProtocolError::Artifact)?;
        let canonical = artifact
            .encode()
            .map_err(C76GraphInstallProtocolError::Artifact)?;
        if canonical.as_slice() != bytes {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        artifacts.push(canonical);
    }

    let mut evidence = Vec::new();
    evidence
        .try_reserve_exact(C76_GRAPH_COMPONENT_COUNT)
        .map_err(|_| C76GraphInstallProtocolError::Allocation)?;
    for bytes in component_evidence_bytes {
        let decoded = ComponentArtifactAuthenticationEvidenceV1::decode(bytes)
            .map_err(C76GraphInstallProtocolError::ArtifactEvidence)?;
        let canonical = decoded.encode();
        if canonical.as_slice() != bytes {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        evidence.push(canonical);
    }
    let graph_evidence =
        ComponentGraphVersionAuthenticationEvidenceV1::decode(graph_evidence_bytes)
            .map_err(C76GraphInstallProtocolError::GraphEvidence)?
            .encode();
    if graph_evidence.as_slice() != graph_evidence_bytes {
        return Err(C76GraphInstallProtocolError::WrongVersion);
    }

    Ok(C76CanonicalGraphVersion {
        descriptor: canonical_descriptor,
        artifacts: artifacts
            .try_into()
            .map_err(|_| C76GraphInstallProtocolError::Allocation)?,
        artifact_evidence: evidence
            .try_into()
            .map_err(|_| C76GraphInstallProtocolError::Allocation)?,
        graph_evidence,
    })
}

fn canonical_from_physical(
    bytes: &C76GraphVersionBytes,
) -> Result<C76CanonicalGraphVersion, C76GraphInstallProtocolError> {
    canonical_candidate(
        bytes.descriptor_bytes(),
        [
            bytes
                .component_artifact_bytes(0)
                .ok_or(C76GraphInstallProtocolError::WrongVersion)?,
            bytes
                .component_artifact_bytes(1)
                .ok_or(C76GraphInstallProtocolError::WrongVersion)?,
            bytes
                .component_artifact_bytes(2)
                .ok_or(C76GraphInstallProtocolError::WrongVersion)?,
        ],
        [
            bytes
                .component_evidence_bytes(0)
                .ok_or(C76GraphInstallProtocolError::WrongVersion)?,
            bytes
                .component_evidence_bytes(1)
                .ok_or(C76GraphInstallProtocolError::WrongVersion)?,
            bytes
                .component_evidence_bytes(2)
                .ok_or(C76GraphInstallProtocolError::WrongVersion)?,
        ],
        bytes.graph_evidence_bytes(),
    )
}

fn decoded_bundle(
    canonical: &C76CanonicalGraphVersion,
) -> Result<ComponentGraphVersionBundleV1, C76GraphInstallProtocolError> {
    let descriptor = ComponentGraphVersionV1::decode(&canonical.descriptor)
        .map_err(C76GraphInstallProtocolError::Descriptor)?;
    let mut artifacts = Vec::new();
    let mut evidence = Vec::new();
    artifacts
        .try_reserve_exact(C76_GRAPH_COMPONENT_COUNT)
        .map_err(|_| C76GraphInstallProtocolError::Allocation)?;
    evidence
        .try_reserve_exact(C76_GRAPH_COMPONENT_COUNT)
        .map_err(|_| C76GraphInstallProtocolError::Allocation)?;
    for bytes in &canonical.artifacts {
        artifacts.push(
            ComponentArtifactV1::decode(bytes).map_err(C76GraphInstallProtocolError::Artifact)?,
        );
    }
    for bytes in &canonical.artifact_evidence {
        evidence.push(
            ComponentArtifactAuthenticationEvidenceV1::decode(bytes)
                .map_err(C76GraphInstallProtocolError::ArtifactEvidence)?,
        );
    }
    let graph_evidence =
        ComponentGraphVersionAuthenticationEvidenceV1::decode(&canonical.graph_evidence)
            .map_err(C76GraphInstallProtocolError::GraphEvidence)?;
    ComponentGraphVersionBundleV1::new(descriptor, artifacts, evidence, graph_evidence)
        .map_err(C76GraphInstallProtocolError::Descriptor)
}

fn fresh_version(
    canonical: &C76CanonicalGraphVersion,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<
    vibeos_component_admission::FreshAuthenticatedComponentGraphVersion,
    C76GraphInstallProtocolError,
> {
    let authenticated = authenticate_component_graph_version(decoded_bundle(canonical)?, policy)
        .map_err(C76GraphInstallProtocolError::Authentication)?;
    let fresh = admit_authenticated_component_graph_version(authenticated, policy, caller)
        .map_err(C76GraphInstallProtocolError::Authentication)?;
    if fresh.runtime_ready() || fresh.descriptor().profile().execution_enabled() {
        return Err(C76GraphInstallProtocolError::WrongVersion);
    }
    Ok(fresh)
}

/// State returned after classifying the exact V3 namespace.  Neither variant
/// exposes candidate bytes or a generic journal operation.
#[must_use = "C7.6 durable state must be installed or physically recovered"]
pub enum C76GraphBootState {
    Vacant(C76VacantGraphInstall),
    Existing(C76PendingGraphReadback),
}

/// A classified vacant head is the only entry point that may validate or
/// persist initial G0 image bytes.
///
/// Candidate admission is deliberately not exported as an ambient/free API:
///
/// ```compile_fail
/// use vibeos_component_loader::admit_c76_initial_graph_install;
/// ```
///
/// The private candidate type cannot be named or constructed by callers:
///
/// ```compile_fail
/// use vibeos_component_loader::C76InitialGraphInstallCandidate;
/// ```
#[must_use = "a vacant C7.6 graph head must be initialized or discarded"]
pub struct C76VacantGraphInstall {
    head: C76VacantHead,
}

#[must_use = "a C7.6 graph checkpoint must be physically recovered or discarded"]
pub struct C76PendingGraphReadback {
    pending: C76PendingPhysicalReadback,
}

pub async fn begin_c76_graph_boot(
    journal: C76AuthorityJournal,
) -> Result<C76GraphBootState, C76GraphInstallProtocolError> {
    match journal
        .recover_exact_v3()
        .await
        .map_err(C76GraphInstallProtocolError::Storage)?
    {
        C76RecoveredState::Vacant(head) => {
            Ok(C76GraphBootState::Vacant(C76VacantGraphInstall { head }))
        }
        C76RecoveredState::Existing(pending) => {
            Ok(C76GraphBootState::Existing(C76PendingGraphReadback {
                pending,
            }))
        }
    }
}

impl C76VacantGraphInstall {
    /// Consume the classified vacant head, freshly validate exact G0, and
    /// immediately install only its canonical authority-free bytes.
    pub async fn admit_and_install_initial(
        self,
        descriptor_bytes: &[u8],
        component_artifact_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        component_evidence_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        graph_evidence_bytes: &[u8],
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<C76PendingGraphReadback, C76GraphInstallProtocolError> {
        let candidate = C76InitialGraphInstallCandidate::admit(
            &self,
            descriptor_bytes,
            component_artifact_bytes,
            component_evidence_bytes,
            graph_evidence_bytes,
            policy,
            caller,
        )?;
        let input = candidate.canonical.storage_input();
        let pending = self
            .head
            .install_initial(input)
            .await
            .map_err(C76GraphInstallProtocolError::Storage)?;
        Ok(C76PendingGraphReadback { pending })
    }
}

/// Only exact physically read G0 or G1 histories can be represented here.
#[must_use = "a physically recovered graph must be freshly admitted"]
pub enum C76RecoveredDurableGraph {
    G0(C76RecoveredReplaceableGraph),
    G1(C76RecoveredFinalGraph),
}

pub struct C76RecoveredReplaceableGraph {
    graph: C76ReplaceableGraph,
}

/// Physically recovered final G1. It exposes fresh pair validation only: no
/// successor admission gate and no durable write operation can be obtained.
///
/// ```compile_fail
/// use vibeos_component_loader::C76RecoveredFinalGraph;
///
/// fn no_candidate(graph: C76RecoveredFinalGraph) {
///     let _ = graph.take_current_supervisor();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C76RecoveredFinalGraph;
///
/// fn no_write(graph: C76RecoveredFinalGraph) {
///     let _ = graph.replace(());
/// }
/// ```
pub struct C76RecoveredFinalGraph {
    graph: C76FinalGraph,
}

impl C76PendingGraphReadback {
    pub async fn recover_graph(
        self,
    ) -> Result<C76RecoveredDurableGraph, C76GraphInstallProtocolError> {
        match self
            .pending
            .recover_payload()
            .await
            .map_err(C76GraphInstallProtocolError::PhysicalReadback)?
        {
            C76RecoveredGraphState::G0(graph) => {
                Ok(C76RecoveredDurableGraph::G0(C76RecoveredReplaceableGraph {
                    graph,
                }))
            }
            C76RecoveredGraphState::G1(graph) => {
                Ok(C76RecoveredDurableGraph::G1(C76RecoveredFinalGraph {
                    graph,
                }))
            }
        }
    }
}

/// Physically sourced, freshly validated G0 plus its one-shot durable append
/// authority.  The current-only supervisor proof can be consumed once; the
/// storage handle remains private for the later replacement append.
///
/// ```compile_fail
/// use vibeos_component_loader::C76FreshReplaceableGraph;
///
/// fn replay(graph: &C76FreshReplaceableGraph) {
///     let _: C76FreshReplaceableGraph = graph.clone();
/// }
/// ```
#[must_use = "fresh G0 must stage its current graph, replace it, or be discarded"]
pub struct C76FreshReplaceableGraph {
    graph: C76ReplaceableGraph,
    current_supervisor: C76SupervisorCurrentGraph,
}

impl C76RecoveredReplaceableGraph {
    pub fn revalidate_current_on_boot(
        self,
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<C76FreshReplaceableGraph, C76GraphInstallProtocolError> {
        let canonical = canonical_from_physical(self.graph.current())?;
        let fresh = fresh_version(&canonical, policy, caller)?;
        if fresh.descriptor().ordinal() != 0 || fresh.descriptor().predecessor().is_some() {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        let admitted = fresh.into_admitted_graph();
        let template = ComponentGraphPrincipalTemplate::new(admitted)
            .map_err(C76GraphInstallProtocolError::PrincipalProjection)?;
        if template.runtime_ready() {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        Ok(C76FreshReplaceableGraph {
            graph: self.graph,
            current_supervisor: C76SupervisorCurrentGraph { template },
        })
    }
}

impl C76FreshReplaceableGraph {
    /// Consume freshly validated G0 and split it exactly once into a current
    /// supervisor proof and a move-only successor-admission gate. The proof
    /// names no successor; the gate contains no admitted successor.
    pub fn take_current_supervisor(
        self,
    ) -> (C76SupervisorCurrentGraph, C76SuccessorGraphAdmissionGate) {
        (
            self.current_supervisor,
            C76SuccessorGraphAdmissionGate { graph: self.graph },
        )
    }
}

/// Move-only authority to validate and append G1. Only physical G0 readback
/// followed by current-policy/current-engine fresh validation can mint it.
/// Existing G1 recovery exposes neither this gate nor a write method.
///
/// ```compile_fail
/// use vibeos_component_loader::C76SuccessorGraphAdmissionGate;
///
/// fn replay(gate: &C76SuccessorGraphAdmissionGate) {
///     let _: C76SuccessorGraphAdmissionGate = gate.clone();
/// }
/// ```
///
/// Successor candidate admission is deliberately not exported as an
/// ambient/free API:
///
/// ```compile_fail
/// use vibeos_component_loader::admit_c76_successor_graph_install;
/// ```
#[must_use = "fresh G0 successor admission must be consumed or fail closed"]
pub struct C76SuccessorGraphAdmissionGate {
    graph: C76ReplaceableGraph,
}

impl C76SuccessorGraphAdmissionGate {
    /// Revalidate physical G0 and image G1 as one exact replacement, destroy
    /// that volatile proof, and only then append canonical bytes.  The return
    /// value still requires an independent physical G1 readback.
    pub async fn admit_and_replace(
        self,
        descriptor_bytes: &[u8],
        component_artifact_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        component_evidence_bytes: [&[u8]; C76_GRAPH_COMPONENT_COUNT],
        graph_evidence_bytes: &[u8],
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<C76PendingGraphReadback, C76GraphInstallProtocolError> {
        let candidate = C76SuccessorGraphInstallCandidate::admit(
            &self,
            descriptor_bytes,
            component_artifact_bytes,
            component_evidence_bytes,
            graph_evidence_bytes,
            policy,
            caller,
        )?;
        let current = fresh_version(
            &canonical_from_physical(self.graph.current())?,
            policy,
            caller,
        )?;
        let successor = fresh_version(&candidate.canonical, policy, caller)?;
        let preappend = admit_authenticated_component_graph_replacement(current, successor, policy)
            .map_err(C76GraphInstallProtocolError::Authentication)?;
        if preappend.admitted_replacement().manifest().node_action()
            != ComponentGraphReplacementNodeAction::PolicyCancel
        {
            return Err(C76GraphInstallProtocolError::PolicyCancelRequired);
        }
        // Persistence hygiene only: no pre-append graph proof crosses this
        // explicit destruction boundary.
        drop(preappend);
        let input = candidate.canonical.storage_input();
        let pending = self
            .graph
            .replace(input)
            .await
            .map_err(C76GraphInstallProtocolError::Storage)?;
        Ok(C76PendingGraphReadback { pending })
    }
}

/// Complete fresh G0/G1 proof minted only after one physical G1 readback.
///
/// ```compile_fail
/// use vibeos_component_loader::C76FreshDurableGraphReplacement;
///
/// fn replay(replacement: &C76FreshDurableGraphReplacement) {
///     let _: C76FreshDurableGraphReplacement = replacement.clone();
/// }
/// ```
#[must_use = "a fresh durable replacement must be handed to a supervisor or discarded"]
pub struct C76FreshDurableGraphReplacement {
    template: Arc<ComponentGraphNodeReplacementTemplate>,
}

impl C76RecoveredFinalGraph {
    pub fn revalidate_on_boot(
        self,
        policy: &OperatorComponentGraphAdmissionPolicy<'_>,
        caller: &CallerAuthority<'_>,
    ) -> Result<C76FreshDurableGraphReplacement, C76GraphInstallProtocolError> {
        let current = fresh_version(
            &canonical_from_physical(self.graph.predecessor())?,
            policy,
            caller,
        )?;
        let successor = fresh_version(
            &canonical_from_physical(self.graph.successor())?,
            policy,
            caller,
        )?;
        let replacement =
            admit_authenticated_component_graph_replacement(current, successor, policy)
                .map_err(C76GraphInstallProtocolError::Authentication)?;
        if replacement.admitted_replacement().manifest().node_action()
            != ComponentGraphReplacementNodeAction::PolicyCancel
        {
            return Err(C76GraphInstallProtocolError::PolicyCancelRequired);
        }
        let template = ComponentGraphNodeReplacementTemplate::new(Arc::new(
            replacement.into_admitted_replacement(),
        ))
        .map_err(C76GraphInstallProtocolError::ReplacementProjection)?;
        if template.runtime_ready() {
            return Err(C76GraphInstallProtocolError::WrongVersion);
        }
        Ok(C76FreshDurableGraphReplacement {
            template: Arc::new(template),
        })
    }
}

impl C76FreshDurableGraphReplacement {
    pub fn into_supervisor_replacement(self) -> C76SupervisorGraphReplacement {
        C76SupervisorGraphReplacement {
            template: self.template,
            cancel: C76PolicyCancelPermit { consumed: false },
        }
    }

    /// Cold G1 recovery needs no replacement candidate and performs no
    /// cancellation.  It may project only the already-committed successor as
    /// the boot-local current graph.
    pub fn into_successor_supervisor_graph(
        self,
    ) -> Result<C76SupervisorCurrentGraph, C76GraphInstallProtocolError> {
        let admitted = Arc::clone(self.template.admitted_replacement().candidate_graph_arc());
        let template = ComponentGraphPrincipalTemplate::new(admitted)
            .map_err(C76GraphInstallProtocolError::PrincipalProjection)?;
        Ok(C76SupervisorCurrentGraph { template })
    }
}

/// Opaque current-only handoff.  Its borrowed view cannot escape `consume`.
///
/// ```compile_fail
/// use vibeos_component_command::ComponentGraphPrincipalTemplate;
/// use vibeos_component_loader::C76SupervisorCurrentGraph;
///
/// fn leak<'a>(graph: C76SupervisorCurrentGraph) -> &'a ComponentGraphPrincipalTemplate {
///     graph.consume(|view| view.current_graph())
/// }
/// ```
pub struct C76SupervisorCurrentGraph {
    template: ComponentGraphPrincipalTemplate,
}

pub struct C76SupervisorCurrentGraphView<'a> {
    current: &'a ComponentGraphPrincipalTemplate,
}

impl C76SupervisorCurrentGraph {
    pub fn consume<R>(
        self,
        consume: impl for<'a> FnOnce(C76SupervisorCurrentGraphView<'a>) -> R,
    ) -> R {
        consume(C76SupervisorCurrentGraphView {
            current: &self.template,
        })
    }
}

impl<'a> C76SupervisorCurrentGraphView<'a> {
    pub const fn current_graph(&self) -> &'a ComponentGraphPrincipalTemplate {
        self.current
    }
}

/// Opaque post-readback replacement handoff.  The view and cancellation
/// permit exist only for the duration of one consuming supervisor callback.
///
/// ```compile_fail
/// use vibeos_component_loader::C76SupervisorGraphReplacement;
///
/// fn replay(replacement: &C76SupervisorGraphReplacement) {
///     let _: C76SupervisorGraphReplacement = replacement.clone();
/// }
/// ```
pub struct C76SupervisorGraphReplacement {
    template: Arc<ComponentGraphNodeReplacementTemplate>,
    cancel: C76PolicyCancelPermit,
}

pub struct C76SupervisorReplacementView<'a> {
    replacement: &'a ComponentGraphNodeReplacementTemplate,
}

impl C76SupervisorGraphReplacement {
    pub fn consume<R>(
        self,
        consume: impl for<'a> FnOnce(C76SupervisorReplacementView<'a>, C76PolicyCancelPermit) -> R,
    ) -> R {
        consume(
            C76SupervisorReplacementView {
                replacement: &self.template,
            },
            self.cancel,
        )
    }
}

impl<'a> C76SupervisorReplacementView<'a> {
    pub const fn current_graph(&self) -> &'a ComponentGraphPrincipalTemplate {
        self.replacement.current_graph()
    }

    pub const fn successor_graph(&self) -> &'a ComponentGraphPrincipalTemplate {
        self.replacement.candidate_graph()
    }

    pub const fn node_action(&self) -> ComponentGraphReplacementNodeAction {
        self.replacement.node_action()
    }

    pub const fn max_replacements(&self) -> u16 {
        self.replacement.max_replacements()
    }

    pub fn incident_edges(&self) -> &'a [ComponentGraphReplacementEdgePolicy] {
        self.replacement.incident_edges()
    }
}

/// Move-only authority for the one explicit old-target PolicyCancel action.
/// It is not a capability and contains no target identity.  Only the loader's
/// physical G1 postflight can create it.
///
/// ```compile_fail
/// use vibeos_component_loader::C76PolicyCancelPermit;
///
/// fn replay(permit: &C76PolicyCancelPermit) {
///     let _: C76PolicyCancelPermit = permit.clone();
/// }
/// ```
#[must_use = "the C7.6 supervisor must consume PolicyCancel at old-target retirement"]
pub struct C76PolicyCancelPermit {
    consumed: bool,
}

impl C76PolicyCancelPermit {
    pub fn consume(mut self) {
        self.consumed = true;
    }
}

impl Drop for C76PolicyCancelPermit {
    fn drop(&mut self) {
        // The kernel's sticky visibility ledger treats a dropped, unconsumed
        // permit as failure.  This type deliberately has no ambient callback
        // or automatic cancellation side effect.
        let _ = self.consumed;
    }
}
