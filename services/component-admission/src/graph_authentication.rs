//! Operator authentication and fresh semantic admission for durable graph versions.
//!
//! A signed CGV1 descriptor is not admission authority. This module first
//! authenticates the complete descriptor and every attached CMP1/CME1 leaf,
//! then consumes those move-only receipts through the current Component/Core/
//! WIT engines and ordinary atomic graph admission. Replacement admission is
//! a second consuming gate which fixes the only supported history to G0 -> G1
//! and reuses the exact C6.6 single-target relation.

use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use vibeos_component_format::{
    ComponentGraphVersionAuthenticationAlgorithm, ComponentGraphVersionAuthenticationEvidenceV1,
    ComponentGraphVersionBundleV1, ComponentGraphVersionCommitment,
    ComponentGraphVersionCyclePolicyV1, ComponentGraphVersionEdgeV1,
    ComponentGraphVersionEndpointV1, ComponentGraphVersionIncidentEdgeActionV1,
    ComponentGraphVersionNodeNestingV1, ComponentGraphVersionRetirementActionV1,
    ComponentGraphVersionV1, ProfileIdentity, ProfileStage, C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT,
    C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT, C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS,
    C76_COMPONENT_GRAPH_VERSION_NODE_COUNT, C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT,
    C76_COMPONENT_GRAPH_VERSION_TARGET, COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION,
    COMPONENT_GRAPH_VERSION_FORMAT_VERSION, COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION,
};
use vibeos_component_runtime::graph::{
    ComponentGraphEdgeSpec, ComponentGraphExportEndpoint, ComponentGraphExternalImportSpec,
    ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
    ComponentGraphPublishedExportSpec,
};

use crate::{
    admit_component_graph_replacement, admit_component_graph_with_resource_policy,
    authenticate_component_artifact, operator_verifying_key,
    revalidate_authenticated_graph_artifact, AdmittedComponentGraph,
    AdmittedComponentGraphReplacement, ArtifactAuthenticationError, ArtifactTrust,
    AuthenticatedAdmissionError, AuthenticatedComponentArtifact, CallerAuthority,
    ComponentGraphAdmissionError, ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy,
    ComponentGraphNodeAdmissionPolicy, ComponentGraphNodeReplacementPolicy,
    ComponentGraphReplacementAdmissionError, ComponentGraphReplacementEdgeAction,
    ComponentGraphReplacementEdgePolicy, ComponentGraphReplacementNodeAction,
    ComponentGraphResourceEdgePolicy, ComponentGraphResourceMode, OperatorArtifactAdmissionPolicy,
    OperatorRoleIdentity, OperatorSignerStatus, OperatorSignerV1,
    MAX_COMPONENT_ARTIFACT_OPERATOR_SIGNERS,
};

/// Frozen canonical operator graph-policy format.
pub const COMPONENT_GRAPH_OPERATOR_POLICY_VERSION: u16 = 1;
/// Frozen graph signature transcript format.
pub const COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_VERSION: u16 = 1;
/// Fixed-width transcript. Reserved bytes are always zero.
pub const COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_LEN: usize = 256;

const GRAPH_POLICY_DOMAIN: &[u8] = b"vibeos.component-graph.operator-policy.v1\0";
const GRAPH_SIGNATURE_DOMAIN: &[u8; 48] = b"vibeos.component-graph.operator-admission.v1.c7\0";
const GRAPH_TRANSCRIPT_ED25519_ALGORITHM: u16 = 1;

/// Trusted leaf policy for one graph-local principal.
///
/// The embedded artifact policy is independent of durable bytes. Its exact
/// WIT world, limits, policy generation, complete signer table, and policy
/// commitment are reused for leaf authentication; `label` and `nesting` are
/// graph policy, not component-controlled metadata.
#[derive(Clone, Copy, Debug)]
pub struct OperatorComponentGraphNodeAdmissionPolicy<'a> {
    pub label: &'a str,
    pub nesting: ComponentGraphNesting,
    pub artifact: &'a OperatorArtifactAdmissionPolicy<'a>,
}

/// SHA-256 commitment to every independently configured graph policy field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OperatorComponentGraphPolicyCommitment([u8; 32]);

impl OperatorComponentGraphPolicyCommitment {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OperatorComponentGraphPolicyCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorComponentGraphPolicyCommitment(<redacted>)")
    }
}

/// Complete current operator policy for the fixed C7.6 graph boundary.
///
/// No field is reflected from a CGV1 object. The topology, exact per-node
/// semantic policy, explicit resource-edge modes, and single replacement
/// action are configured before a descriptor can be authenticated.
pub struct OperatorComponentGraphAdmissionPolicy<'a> {
    role: OperatorRoleIdentity,
    generation: u64,
    name: &'a str,
    profile: ProfileIdentity,
    nodes: &'a [OperatorComponentGraphNodeAdmissionPolicy<'a>],
    edges: &'a [ComponentGraphEdgeSpec],
    resource_edges: &'a [ComponentGraphResourceEdgePolicy],
    external_imports: &'a [ComponentGraphExternalImportSpec],
    published_exports: &'a [ComponentGraphPublishedExportSpec],
    replacement: ComponentGraphNodeReplacementPolicy<'a>,
    signers: &'a [OperatorSignerV1],
}

impl<'a> OperatorComponentGraphAdmissionPolicy<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: OperatorRoleIdentity,
        generation: u64,
        name: &'a str,
        profile: ProfileIdentity,
        nodes: &'a [OperatorComponentGraphNodeAdmissionPolicy<'a>],
        edges: &'a [ComponentGraphEdgeSpec],
        resource_edges: &'a [ComponentGraphResourceEdgePolicy],
        external_imports: &'a [ComponentGraphExternalImportSpec],
        published_exports: &'a [ComponentGraphPublishedExportSpec],
        replacement: ComponentGraphNodeReplacementPolicy<'a>,
        signers: &'a [OperatorSignerV1],
    ) -> Result<Self, ComponentGraphAuthenticationError> {
        let policy = Self {
            role,
            generation,
            name,
            profile,
            nodes,
            edges,
            resource_edges,
            external_imports,
            published_exports,
            replacement,
            signers,
        };
        policy.validate()?;
        let _ = policy.commitment()?;
        Ok(policy)
    }

    pub const fn role(&self) -> OperatorRoleIdentity {
        self.role
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn name(&self) -> &str {
        self.name
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn nodes(&self) -> &[OperatorComponentGraphNodeAdmissionPolicy<'a>] {
        self.nodes
    }

    pub const fn edges(&self) -> &[ComponentGraphEdgeSpec] {
        self.edges
    }

    pub const fn resource_edges(&self) -> &[ComponentGraphResourceEdgePolicy] {
        self.resource_edges
    }

    pub const fn external_imports(&self) -> &[ComponentGraphExternalImportSpec] {
        self.external_imports
    }

    pub const fn published_exports(&self) -> &[ComponentGraphPublishedExportSpec] {
        self.published_exports
    }

    pub const fn replacement(&self) -> ComponentGraphNodeReplacementPolicy<'a> {
        self.replacement
    }

    pub const fn signers(&self) -> &[OperatorSignerV1] {
        self.signers
    }

    pub fn commitment(
        &self,
    ) -> Result<OperatorComponentGraphPolicyCommitment, ComponentGraphAuthenticationError> {
        canonical_graph_policy_commitment(self)
    }

    /// Produce the complete offline-signing transcript. Descriptor ordinal
    /// and predecessor are both explicit and also transitively covered by the
    /// version commitment.
    pub fn signature_transcript(
        &self,
        descriptor: &ComponentGraphVersionV1,
        signer_public_key: [u8; 32],
    ) -> Result<[u8; COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_LEN], ComponentGraphAuthenticationError>
    {
        let signer = self.signer(signer_public_key)?;
        let policy_commitment = self.commitment()?;
        validate_descriptor_policy(descriptor, self, policy_commitment)?;
        let encoded = descriptor
            .encode()
            .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
        let version_commitment = descriptor
            .version_commitment()
            .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
        Ok(graph_signature_transcript_bytes(
            descriptor,
            encoded_len,
            version_commitment,
            policy_commitment,
            *signer.public_key(),
            self.generation,
        ))
    }

    fn validate(&self) -> Result<(), ComponentGraphAuthenticationError> {
        if self.generation == 0
            || !valid_graph_text(self.name, 64)
            || self.profile != ProfileIdentity::PROFILE_1_ASYNC
            || self.profile.execution_enabled()
            || self.nodes.len() != C76_COMPONENT_GRAPH_VERSION_NODE_COUNT
            || self.edges.len() != C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT
            || !self.resource_edges.is_empty()
            || !self.external_imports.is_empty()
            || self.published_exports.len() != C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT
            || self.replacement.target.index() != C76_COMPONENT_GRAPH_VERSION_TARGET
            || self.replacement.max_replacements != C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS
            || self.replacement.node_action != ComponentGraphReplacementNodeAction::PolicyCancel
            || self.replacement.incident_edges.len()
                != C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT
        {
            return Err(ComponentGraphAuthenticationError::InvalidPolicy);
        }
        for (index, node) in self.nodes.iter().enumerate() {
            if !valid_graph_text(node.label, 128)
                || node.artifact.profile() != self.profile
                || node.artifact.profile().execution_enabled()
                || self.nodes[..index]
                    .iter()
                    .any(|earlier| earlier.label == node.label)
            {
                return Err(ComponentGraphAuthenticationError::InvalidPolicy);
            }
            node.artifact
                .commitment()
                .map_err(ComponentGraphAuthenticationError::LeafPolicy)?;
        }
        if !strictly_sorted_edges(self.edges)
            || !strictly_sorted_external_imports(self.external_imports)
            || !strictly_sorted_published_exports(self.published_exports)
            || !strictly_sorted_incident_edges(self.replacement.incident_edges)
            || self.replacement.incident_edges.iter().any(|incident| {
                incident.action != ComponentGraphReplacementEdgeAction::RecreateFresh
                    || !self.edges.contains(&incident.edge)
                    || !edge_touches(incident.edge, self.replacement.target)
            })
            || self
                .edges
                .iter()
                .filter(|edge| edge_touches(**edge, self.replacement.target))
                .count()
                != self.replacement.incident_edges.len()
        {
            return Err(ComponentGraphAuthenticationError::InvalidPolicy);
        }
        for edge in self.edges {
            if usize::from(edge.source().node().index()) >= self.nodes.len()
                || usize::from(edge.target().node().index()) >= self.nodes.len()
            {
                return Err(ComponentGraphAuthenticationError::InvalidPolicy);
            }
        }
        if self.signers.is_empty() || self.signers.len() > MAX_COMPONENT_ARTIFACT_OPERATOR_SIGNERS {
            return Err(ComponentGraphAuthenticationError::SignerLimit);
        }
        let mut active = false;
        for (index, signer) in self.signers.iter().enumerate() {
            operator_verifying_key(*signer.public_key())
                .map_err(ComponentGraphAuthenticationError::LeafPolicy)?;
            if index != 0 && self.signers[index - 1].public_key() >= signer.public_key() {
                return Err(ComponentGraphAuthenticationError::NonCanonicalSignerTable);
            }
            active |= signer.status() == OperatorSignerStatus::Active;
        }
        if !active {
            return Err(ComponentGraphAuthenticationError::NoActiveSigner);
        }
        Ok(())
    }

    fn signer(
        &self,
        public_key: [u8; 32],
    ) -> Result<&OperatorSignerV1, ComponentGraphAuthenticationError> {
        operator_verifying_key(public_key)
            .map_err(ComponentGraphAuthenticationError::LeafPolicy)?;
        let mut found = None;
        for signer in self.signers {
            if *signer.public_key() == public_key {
                found = Some(signer);
            }
        }
        let signer = found.ok_or(ComponentGraphAuthenticationError::UnknownSigner)?;
        if signer.status() != OperatorSignerStatus::Active {
            return Err(ComponentGraphAuthenticationError::RevokedSigner);
        }
        Ok(signer)
    }
}

impl fmt::Debug for OperatorComponentGraphAdmissionPolicy<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorComponentGraphAdmissionPolicy")
            .field("role", &self.role)
            .field("generation", &self.generation)
            .field("name", &self.name)
            .field("profile", &self.profile)
            .field("nodes", &self.nodes.len())
            .field("edges", &self.edges.len())
            .field("resource_edges", &self.resource_edges.len())
            .field("external_imports", &self.external_imports.len())
            .field("published_exports", &self.published_exports.len())
            .field("replacement", &"<redacted>")
            .field("signers", &self.signers.len())
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Stable graph authentication/admission failures. No signature, key, raw
/// object identity, durable slot, or recovered byte string is formatted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphAuthenticationError {
    InvalidPolicy,
    SignerLimit,
    NonCanonicalSignerTable,
    NoActiveSigner,
    UnknownSigner,
    RevokedSigner,
    LeafPolicy(ArtifactAuthenticationError),
    DescriptorEncoding,
    DescriptorPolicyMismatch,
    InvalidSignature,
    LeafAuthentication {
        node: ComponentGraphNodeId,
        error: ArtifactAuthenticationError,
    },
    LeafFreshAdmission {
        node: ComponentGraphNodeId,
        error: AuthenticatedAdmissionError,
    },
    GraphAdmission(ComponentGraphAdmissionError),
    ReplacementAdmission(ComponentGraphReplacementAdmissionError),
    VersionRelation,
    DescriptorAdmissionMismatch,
    ReceiptMismatch,
    Allocation,
}

impl fmt::Display for ComponentGraphAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "operator graph admission policy is invalid",
            Self::SignerLimit => "operator graph signer table exceeds its bound",
            Self::NonCanonicalSignerTable => "operator graph signer table is not canonical",
            Self::NoActiveSigner => "operator graph policy has no active signer",
            Self::UnknownSigner => "graph evidence signer is not configured",
            Self::RevokedSigner => "graph evidence signer is revoked",
            Self::LeafPolicy(_) => "one graph leaf policy is invalid",
            Self::DescriptorEncoding => "canonical graph descriptor could not be reproduced",
            Self::DescriptorPolicyMismatch => {
                "graph descriptor differs from current operator policy"
            }
            Self::InvalidSignature => "detached graph signature is invalid",
            Self::LeafAuthentication { .. } => "one graph leaf failed operator authentication",
            Self::LeafFreshAdmission { .. } => {
                "one graph leaf failed current-policy or current-engine validation"
            }
            Self::GraphAdmission(_) => "complete graph failed fresh atomic admission",
            Self::ReplacementAdmission(_) => {
                "graph versions failed exact single-target replacement admission"
            }
            Self::VersionRelation => "graph predecessor or ordinal relation is invalid",
            Self::DescriptorAdmissionMismatch => {
                "signed graph descriptor differs from fresh graph admission"
            }
            Self::ReceiptMismatch => "graph authentication receipt no longer matches exact inputs",
            Self::Allocation => "graph authentication allocation failed",
        })
    }
}

/// Move-only result of verifying a complete graph signature and all leaf
/// signatures. This state has no admitted graph or publication operation.
///
/// ```compile_fail
/// use vibeos_component_admission::AuthenticatedComponentGraphVersion;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<AuthenticatedComponentGraphVersion>();
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AuthenticatedComponentGraphVersion;
/// fn signature_only_cannot_publish(value: AuthenticatedComponentGraphVersion) {
///     value.publish();
/// }
/// ```
pub struct AuthenticatedComponentGraphVersion {
    descriptor: ComponentGraphVersionV1,
    leaves: Vec<AuthenticatedComponentArtifact>,
    graph_evidence: ComponentGraphVersionAuthenticationEvidenceV1,
    receipt: ComponentGraphAuthenticationReceipt,
}

impl AuthenticatedComponentGraphVersion {
    pub const fn descriptor(&self) -> &ComponentGraphVersionV1 {
        &self.descriptor
    }

    pub const fn receipt(&self) -> &ComponentGraphAuthenticationReceipt {
        &self.receipt
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }
}

impl fmt::Debug for AuthenticatedComponentGraphVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedComponentGraphVersion")
            .field("descriptor", &"<redacted>")
            .field("leaves", &self.leaves.len())
            .field("receipt", &self.receipt)
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Fresh current-engine admission of one authenticated graph version. This is
/// still a volatile pre-durability proof; loaders must destroy it before an
/// append and reconstruct it from physical readback bytes afterwards.
pub struct FreshAuthenticatedComponentGraphVersion {
    descriptor: ComponentGraphVersionV1,
    admitted: Arc<AdmittedComponentGraph>,
    receipt: ComponentGraphAuthenticationReceipt,
}

impl FreshAuthenticatedComponentGraphVersion {
    pub const fn descriptor(&self) -> &ComponentGraphVersionV1 {
        &self.descriptor
    }

    pub fn admitted_graph(&self) -> &AdmittedComponentGraph {
        &self.admitted
    }

    pub const fn receipt(&self) -> &ComponentGraphAuthenticationReceipt {
        &self.receipt
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Consume one fresh semantic result for immediate inert command-layer
    /// projection. This value is not durability proof and carries no runtime
    /// principal, CSpace, resource, task, route, or raw durable identity.
    pub fn into_admitted_graph(self) -> Arc<AdmittedComponentGraph> {
        self.admitted
    }
}

impl fmt::Debug for FreshAuthenticatedComponentGraphVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshAuthenticatedComponentGraphVersion")
            .field("descriptor", &"<redacted>")
            .field("admitted", &"<redacted>")
            .field("receipt", &self.receipt)
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Fresh, move-only proof of the exact G0 -> G1, single-target C6.6 relation.
/// It is not durable proof; only the C7.6 loader may combine it with physical
/// postflight provenance.
pub struct FreshAuthenticatedComponentGraphReplacement {
    replacement: AdmittedComponentGraphReplacement,
    current_receipt: ComponentGraphAuthenticationReceipt,
    successor_receipt: ComponentGraphAuthenticationReceipt,
}

impl FreshAuthenticatedComponentGraphReplacement {
    pub const fn admitted_replacement(&self) -> &AdmittedComponentGraphReplacement {
        &self.replacement
    }

    pub const fn current_receipt(&self) -> &ComponentGraphAuthenticationReceipt {
        &self.current_receipt
    }

    pub const fn successor_receipt(&self) -> &ComponentGraphAuthenticationReceipt {
        &self.successor_receipt
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Consume the volatile relation proof for immediate inert command-layer
    /// projection. This does not imply durability and exposes no raw ID.
    pub fn into_admitted_replacement(self) -> AdmittedComponentGraphReplacement {
        self.replacement
    }
}

impl fmt::Debug for FreshAuthenticatedComponentGraphReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshAuthenticatedComponentGraphReplacement")
            .field("replacement", &"<redacted>")
            .field("current_receipt", &self.current_receipt)
            .field("successor_receipt", &self.successor_receipt)
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Authenticate the complete signed bundle without admitting or publishing
/// it. A graph signature cannot substitute for any leaf signature, and a leaf
/// signature cannot substitute for the graph signature.
pub fn authenticate_component_graph_version(
    bundle: ComponentGraphVersionBundleV1,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Result<AuthenticatedComponentGraphVersion, ComponentGraphAuthenticationError> {
    policy.validate()?;
    let (descriptor, artifacts, evidence, graph_evidence) = bundle.into_parts();
    if graph_evidence.algorithm() != ComponentGraphVersionAuthenticationAlgorithm::Ed25519 {
        return Err(ComponentGraphAuthenticationError::InvalidSignature);
    }
    let signer_public_key = graph_evidence.public_key().to_bytes();
    let transcript = policy.signature_transcript(&descriptor, signer_public_key)?;
    let verifying_key = operator_verifying_key(signer_public_key)
        .map_err(ComponentGraphAuthenticationError::LeafPolicy)?;
    let signature = Signature::from_bytes(graph_evidence.signature().as_bytes());
    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| ComponentGraphAuthenticationError::InvalidSignature)?;

    if artifacts.len() != policy.nodes.len() || evidence.len() != policy.nodes.len() {
        return Err(ComponentGraphAuthenticationError::DescriptorPolicyMismatch);
    }
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(artifacts.len())
        .map_err(|_| ComponentGraphAuthenticationError::Allocation)?;
    for (index, ((artifact, evidence), node)) in artifacts
        .into_iter()
        .zip(&evidence)
        .zip(policy.nodes)
        .enumerate()
    {
        let authenticated = authenticate_component_artifact(artifact, evidence, node.artifact)
            .map_err(
                |error| ComponentGraphAuthenticationError::LeafAuthentication {
                    node: ComponentGraphNodeId::new(index as u16),
                    error,
                },
            )?;
        leaves.push(authenticated);
    }
    let encoded_len = u64::try_from(
        descriptor
            .encode()
            .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?
            .len(),
    )
    .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
    let version_commitment = descriptor
        .version_commitment()
        .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
    let receipt = ComponentGraphAuthenticationReceipt {
        version_commitment,
        policy_commitment: policy.commitment()?,
        ordinal: descriptor.ordinal(),
        predecessor: descriptor.predecessor(),
        encoded_len,
        generation: policy.generation,
        signer_public_key,
    };
    Ok(AuthenticatedComponentGraphVersion {
        descriptor,
        leaves,
        graph_evidence,
        receipt,
    })
}

/// Consume graph and leaf signature proofs through every current semantic
/// gate, then perform one ordinary complete graph admission transaction.
pub fn admit_authenticated_component_graph_version(
    authenticated: AuthenticatedComponentGraphVersion,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<FreshAuthenticatedComponentGraphVersion, ComponentGraphAuthenticationError> {
    revalidate_graph_authentication_receipt(&authenticated, policy)?;
    let AuthenticatedComponentGraphVersion {
        descriptor,
        leaves,
        graph_evidence: _,
        receipt,
    } = authenticated;

    let mut artifacts = Vec::new();
    artifacts
        .try_reserve_exact(leaves.len())
        .map_err(|_| ComponentGraphAuthenticationError::Allocation)?;
    for (index, (leaf, node)) in leaves.into_iter().zip(policy.nodes).enumerate() {
        artifacts.push(
            revalidate_authenticated_graph_artifact(leaf, node.artifact).map_err(|error| {
                ComponentGraphAuthenticationError::LeafFreshAdmission {
                    node: ComponentGraphNodeId::new(index as u16),
                    error,
                }
            })?,
        );
    }

    let mut node_policies = Vec::new();
    node_policies
        .try_reserve_exact(policy.nodes.len())
        .map_err(|_| ComponentGraphAuthenticationError::Allocation)?;
    for (artifact, node) in artifacts.iter().zip(policy.nodes) {
        node_policies.push(ComponentGraphNodeAdmissionPolicy {
            label: node.label,
            nesting: node.nesting,
            exact_world: node.artifact.exact_world(),
            trust: ArtifactTrust::ImagePinned(artifact.identity()),
            limits: node.artifact.limits(),
            interfaces: node.artifact.interfaces(),
        });
    }
    let graph_policy = ComponentGraphAdmissionPolicy {
        name: policy.name,
        profile: policy.profile,
        nodes: &node_policies,
        edges: policy.edges,
        external_imports: policy.external_imports,
        published_exports: policy.published_exports,
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    let admitted = admit_component_graph_with_resource_policy(
        artifacts,
        &graph_policy,
        policy.resource_edges,
        caller,
    )
    .map_err(ComponentGraphAuthenticationError::GraphAdmission)?;
    validate_descriptor_admission(&descriptor, &admitted, policy)?;
    Ok(FreshAuthenticatedComponentGraphVersion {
        descriptor,
        admitted: Arc::new(admitted),
        receipt,
    })
}

/// Consume two complete fresh graph admissions and prove the sole supported
/// durable history relation: G0 has no predecessor, G1 is ordinal one and
/// names G0's exact signed version commitment, all non-target descriptor
/// nodes are byte-for-byte stable, and C6.6 admits only the target change.
pub fn admit_authenticated_component_graph_replacement(
    current: FreshAuthenticatedComponentGraphVersion,
    successor: FreshAuthenticatedComponentGraphVersion,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Result<FreshAuthenticatedComponentGraphReplacement, ComponentGraphAuthenticationError> {
    let current_policy_commitment = policy.commitment()?;
    if current.receipt.policy_commitment != current_policy_commitment
        || successor.receipt.policy_commitment != current_policy_commitment
        || current.receipt.generation != policy.generation
        || successor.receipt.generation != policy.generation
        || current.receipt.ordinal != 0
        || current.receipt.predecessor.is_some()
        || successor.receipt.ordinal != 1
        || successor.receipt.predecessor != Some(current.receipt.version_commitment)
        || current.descriptor.ordinal() != 0
        || current.descriptor.predecessor().is_some()
        || successor.descriptor.ordinal() != 1
        || successor.descriptor.predecessor() != Some(current.receipt.version_commitment)
    {
        return Err(ComponentGraphAuthenticationError::VersionRelation);
    }
    validate_descriptor_version_pair(&current.descriptor, &successor.descriptor, policy)?;
    current
        .admitted
        .revalidate()
        .map_err(ComponentGraphAuthenticationError::GraphAdmission)?;
    successor
        .admitted
        .revalidate()
        .map_err(ComponentGraphAuthenticationError::GraphAdmission)?;
    let replacement = admit_component_graph_replacement(
        current.admitted,
        successor.admitted,
        &policy.replacement,
    )
    .map_err(ComponentGraphAuthenticationError::ReplacementAdmission)?;
    if replacement.manifest().node_action() != ComponentGraphReplacementNodeAction::PolicyCancel
        || replacement.manifest().max_replacements() != 1
        || replacement
            .manifest()
            .incident_edges()
            .iter()
            .any(|edge| edge.action != ComponentGraphReplacementEdgeAction::RecreateFresh)
        || replacement.runtime_ready()
    {
        return Err(ComponentGraphAuthenticationError::DescriptorAdmissionMismatch);
    }
    Ok(FreshAuthenticatedComponentGraphReplacement {
        replacement,
        current_receipt: current.receipt,
        successor_receipt: successor.receipt,
    })
}

fn revalidate_graph_authentication_receipt(
    authenticated: &AuthenticatedComponentGraphVersion,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Result<(), ComponentGraphAuthenticationError> {
    let commitment = policy.commitment()?;
    let descriptor = &authenticated.descriptor;
    validate_descriptor_policy(descriptor, policy, commitment)?;
    let encoded_len = u64::try_from(
        descriptor
            .encode()
            .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?
            .len(),
    )
    .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
    let version_commitment = descriptor
        .version_commitment()
        .map_err(|_| ComponentGraphAuthenticationError::DescriptorEncoding)?;
    let receipt = &authenticated.receipt;
    if receipt.version_commitment != version_commitment
        || receipt.policy_commitment != commitment
        || receipt.ordinal != descriptor.ordinal()
        || receipt.predecessor != descriptor.predecessor()
        || receipt.encoded_len != encoded_len
        || receipt.generation != policy.generation
        || receipt.signer_public_key != authenticated.graph_evidence.public_key().to_bytes()
        || authenticated.leaves.len() != policy.nodes.len()
    {
        return Err(ComponentGraphAuthenticationError::ReceiptMismatch);
    }
    policy.signer(receipt.signer_public_key)?;
    let transcript = policy.signature_transcript(descriptor, receipt.signer_public_key)?;
    let verifying_key: VerifyingKey = operator_verifying_key(receipt.signer_public_key)
        .map_err(ComponentGraphAuthenticationError::LeafPolicy)?;
    let signature = Signature::from_bytes(authenticated.graph_evidence.signature().as_bytes());
    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| ComponentGraphAuthenticationError::InvalidSignature)
}

/// Complete graph-version authentication receipt. It is boot-local,
/// move-only, and contains comparison metadata only.
pub struct ComponentGraphAuthenticationReceipt {
    version_commitment: ComponentGraphVersionCommitment,
    policy_commitment: OperatorComponentGraphPolicyCommitment,
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    encoded_len: u64,
    generation: u64,
    signer_public_key: [u8; 32],
}

impl ComponentGraphAuthenticationReceipt {
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn predecessor(&self) -> Option<ComponentGraphVersionCommitment> {
        self.predecessor
    }

    pub const fn policy_commitment(&self) -> OperatorComponentGraphPolicyCommitment {
        self.policy_commitment
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }
}

impl fmt::Debug for ComponentGraphAuthenticationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphAuthenticationReceipt")
            .field("version_commitment", &"<redacted>")
            .field("policy_commitment", &self.policy_commitment)
            .field("ordinal", &self.ordinal)
            .field("predecessor", &self.predecessor.map(|_| "<redacted>"))
            .field("generation", &self.generation)
            .field("runtime_ready", &false)
            .finish()
    }
}

fn canonical_graph_policy_commitment(
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Result<OperatorComponentGraphPolicyCommitment, ComponentGraphAuthenticationError> {
    policy.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(GRAPH_POLICY_DOMAIN);
    hash_u16(&mut hasher, COMPONENT_GRAPH_OPERATOR_POLICY_VERSION);
    hash_u64(&mut hasher, policy.generation);
    hasher.update(policy.role.as_bytes());
    hash_u16(&mut hasher, bounded_u16(policy.signers.len())?);
    for signer in policy.signers {
        hasher.update(signer.public_key());
        hash_u8(&mut hasher, signer.status() as u8);
    }
    hash_profile(&mut hasher, policy.profile)?;
    hash_text(&mut hasher, policy.name)?;
    hash_u16(&mut hasher, bounded_u16(policy.nodes.len())?);
    for node in policy.nodes {
        hash_text(&mut hasher, node.label)?;
        hash_nesting(&mut hasher, node.nesting);
        hasher.update(
            node.artifact
                .commitment()
                .map_err(ComponentGraphAuthenticationError::LeafPolicy)?
                .as_bytes(),
        );
    }
    hash_u16(&mut hasher, bounded_u16(policy.edges.len())?);
    for edge in policy.edges {
        hash_edge(&mut hasher, *edge);
    }
    hash_u16(&mut hasher, bounded_u16(policy.resource_edges.len())?);
    for resource in policy.resource_edges {
        hash_edge(&mut hasher, resource.edge);
        hash_u8(
            &mut hasher,
            match resource.mode {
                ComponentGraphResourceMode::Borrow => 1,
                ComponentGraphResourceMode::Own => 2,
                ComponentGraphResourceMode::OwnAndBorrow => 3,
            },
        );
    }
    hash_u16(&mut hasher, bounded_u16(policy.external_imports.len())?);
    for external in policy.external_imports {
        hash_import_endpoint(&mut hasher, external.target());
    }
    hash_u16(&mut hasher, bounded_u16(policy.published_exports.len())?);
    for published in policy.published_exports {
        hash_export_endpoint(&mut hasher, published.source());
    }
    hash_u16(&mut hasher, policy.replacement.target.index());
    hash_u16(&mut hasher, policy.replacement.max_replacements);
    hash_u8(&mut hasher, 1); // PolicyCancel
    hash_u16(
        &mut hasher,
        bounded_u16(policy.replacement.incident_edges.len())?,
    );
    for incident in policy.replacement.incident_edges {
        hash_edge(&mut hasher, incident.edge);
        hash_u8(&mut hasher, 1); // RecreateFresh
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(ComponentGraphAuthenticationError::InvalidPolicy);
    }
    Ok(OperatorComponentGraphPolicyCommitment(digest))
}

fn graph_signature_transcript_bytes(
    descriptor: &ComponentGraphVersionV1,
    encoded_len: u64,
    version_commitment: ComponentGraphVersionCommitment,
    policy_commitment: OperatorComponentGraphPolicyCommitment,
    signer_public_key: [u8; 32],
    policy_generation: u64,
) -> [u8; COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_LEN] {
    let mut out = [0_u8; COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_LEN];
    out[0..48].copy_from_slice(GRAPH_SIGNATURE_DOMAIN);
    out[48..50].copy_from_slice(&COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_VERSION.to_le_bytes());
    out[50..52].copy_from_slice(&COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION.to_le_bytes());
    out[52..54].copy_from_slice(&GRAPH_TRANSCRIPT_ED25519_ALGORITHM.to_le_bytes());
    out[54..56].copy_from_slice(&COMPONENT_GRAPH_VERSION_FORMAT_VERSION.to_le_bytes());
    out[56..58].copy_from_slice(&COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION.to_le_bytes());
    out[58..60].copy_from_slice(&COMPONENT_GRAPH_OPERATOR_POLICY_VERSION.to_le_bytes());
    let profile = descriptor.profile();
    out[60..62].copy_from_slice(&profile.artifact_abi.to_le_bytes());
    out[62..64].copy_from_slice(&profile.component_profile.to_le_bytes());
    out[64..66].copy_from_slice(&profile.core_profile.to_le_bytes());
    out[66..68].copy_from_slice(&profile.runtime_abi.to_le_bytes());
    out[68..70].copy_from_slice(&profile_stage_raw(profile.stage).to_le_bytes());
    // 70..72 is a frozen zero reservation.
    out[72..80].copy_from_slice(&profile.canonical_features.to_le_bytes());
    out[80..88].copy_from_slice(&encoded_len.to_le_bytes());
    out[88..120].copy_from_slice(version_commitment.as_bytes());
    out[120..152].copy_from_slice(policy_commitment.as_bytes());
    out[152..184].copy_from_slice(&signer_public_key);
    out[184..192].copy_from_slice(&policy_generation.to_le_bytes());
    out[192..200].copy_from_slice(&descriptor.ordinal().to_le_bytes());
    if let Some(predecessor) = descriptor.predecessor() {
        out[200..232].copy_from_slice(predecessor.as_bytes());
        out[232] = 1;
    }
    // 233..256 is a frozen zero reservation.
    out
}

fn valid_graph_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.as_bytes().contains(&0)
}

fn bounded_u16(value: usize) -> Result<u16, ComponentGraphAuthenticationError> {
    u16::try_from(value).map_err(|_| ComponentGraphAuthenticationError::InvalidPolicy)
}

fn profile_stage_raw(stage: ProfileStage) -> u16 {
    match stage {
        ProfileStage::Executable => 1,
        ProfileStage::ValidationOnly => 2,
    }
}

fn hash_profile(
    hasher: &mut Sha256,
    profile: ProfileIdentity,
) -> Result<(), ComponentGraphAuthenticationError> {
    hash_u16(hasher, profile.artifact_abi);
    hash_u16(hasher, profile.component_profile);
    hash_u16(hasher, profile.core_profile);
    hash_u16(hasher, profile.runtime_abi);
    hash_u16(hasher, profile_stage_raw(profile.stage));
    hash_u64(hasher, profile.canonical_features);
    hash_text(hasher, profile.core_revision)?;
    hash_text(hasher, profile.component_revision)?;
    hash_text(hasher, profile.canonical_abi_revision)?;
    hash_text(hasher, profile.wasm_tools_revision)?;
    hash_text(hasher, profile.wasi_revision)
}

fn hash_nesting(hasher: &mut Sha256, nesting: ComponentGraphNesting) {
    match nesting {
        ComponentGraphNesting::Root => {
            hash_u8(hasher, 0);
            hash_u16(hasher, 0);
        }
        ComponentGraphNesting::Nested { parent } => {
            hash_u8(hasher, 1);
            hash_u16(hasher, parent.index());
        }
    }
}

fn hash_edge(hasher: &mut Sha256, edge: ComponentGraphEdgeSpec) {
    hash_export_endpoint(hasher, edge.source());
    hash_import_endpoint(hasher, edge.target());
}

fn hash_export_endpoint(hasher: &mut Sha256, endpoint: ComponentGraphExportEndpoint) {
    hash_u16(hasher, endpoint.node().index());
    hash_u16(hasher, endpoint.export().index());
}

fn hash_import_endpoint(hasher: &mut Sha256, endpoint: ComponentGraphImportEndpoint) {
    hash_u16(hasher, endpoint.node().index());
    hash_u16(hasher, endpoint.import().index());
}

fn hash_text(hasher: &mut Sha256, value: &str) -> Result<(), ComponentGraphAuthenticationError> {
    hash_u32(
        hasher,
        u32::try_from(value.len()).map_err(|_| ComponentGraphAuthenticationError::InvalidPolicy)?,
    );
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn hash_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_le_bytes());
}

fn hash_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn edge_key(edge: ComponentGraphEdgeSpec) -> (u16, u16, u16, u16) {
    (
        edge.source().node().index(),
        edge.source().export().index(),
        edge.target().node().index(),
        edge.target().import().index(),
    )
}

fn strictly_sorted_edges(edges: &[ComponentGraphEdgeSpec]) -> bool {
    edges
        .windows(2)
        .all(|pair| edge_key(pair[0]) < edge_key(pair[1]))
}

fn strictly_sorted_incident_edges(edges: &[ComponentGraphReplacementEdgePolicy]) -> bool {
    edges
        .windows(2)
        .all(|pair| edge_key(pair[0].edge) < edge_key(pair[1].edge))
}

fn import_key(endpoint: ComponentGraphImportEndpoint) -> (u16, u16) {
    (endpoint.node().index(), endpoint.import().index())
}

fn export_key(endpoint: ComponentGraphExportEndpoint) -> (u16, u16) {
    (endpoint.node().index(), endpoint.export().index())
}

fn strictly_sorted_external_imports(edges: &[ComponentGraphExternalImportSpec]) -> bool {
    edges
        .windows(2)
        .all(|pair| import_key(pair[0].target()) < import_key(pair[1].target()))
}

fn strictly_sorted_published_exports(edges: &[ComponentGraphPublishedExportSpec]) -> bool {
    edges
        .windows(2)
        .all(|pair| export_key(pair[0].source()) < export_key(pair[1].source()))
}

fn edge_touches(edge: ComponentGraphEdgeSpec, target: ComponentGraphNodeId) -> bool {
    edge.source().node() == target || edge.target().node() == target
}

fn format_edge(runtime: ComponentGraphEdgeSpec) -> ComponentGraphVersionEdgeV1 {
    ComponentGraphVersionEdgeV1::new(
        ComponentGraphVersionEndpointV1::new(
            runtime.source().node().index(),
            runtime.source().export().index(),
        ),
        ComponentGraphVersionEndpointV1::new(
            runtime.target().node().index(),
            runtime.target().import().index(),
        ),
    )
}

fn format_nesting(runtime: ComponentGraphNesting) -> ComponentGraphVersionNodeNestingV1 {
    match runtime {
        ComponentGraphNesting::Root => ComponentGraphVersionNodeNestingV1::Root,
        ComponentGraphNesting::Nested { parent } => ComponentGraphVersionNodeNestingV1::Nested {
            parent: parent.index(),
        },
    }
}

fn validate_descriptor_policy(
    descriptor: &ComponentGraphVersionV1,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
    policy_commitment: OperatorComponentGraphPolicyCommitment,
) -> Result<(), ComponentGraphAuthenticationError> {
    descriptor
        .validate_c76_shape()
        .map_err(|_| ComponentGraphAuthenticationError::DescriptorPolicyMismatch)?;
    if descriptor.runtime_ready()
        || descriptor.name() != policy.name
        || descriptor.profile() != policy.profile
        || descriptor.policy_digest().as_bytes() != policy_commitment.as_bytes()
        || descriptor.cycle_policy() != ComponentGraphVersionCyclePolicyV1::AcyclicOnly
        || descriptor.ordinal() > 1
        || (descriptor.ordinal() == 0) != descriptor.predecessor().is_none()
        || descriptor.nodes().len() != policy.nodes.len()
        || descriptor.edges().len() != policy.edges.len()
        || descriptor.external_imports().len() != policy.external_imports.len()
        || descriptor.published_exports().len() != policy.published_exports.len()
    {
        return Err(ComponentGraphAuthenticationError::DescriptorPolicyMismatch);
    }
    for (index, (node, expected)) in descriptor.nodes().iter().zip(policy.nodes).enumerate() {
        let artifact_policy = expected
            .artifact
            .commitment()
            .map_err(ComponentGraphAuthenticationError::LeafPolicy)?;
        let limits = node.instance_limits();
        let expected_limits = expected.artifact.limits();
        if usize::from(node.ordinal()) != index
            || node.label() != expected.label
            || node.world() != expected.artifact.exact_world().identity
            || node.nesting() != format_nesting(expected.nesting)
            || node.artifact_policy_digest().as_bytes() != artifact_policy.as_bytes()
            || limits.memory_bytes() != expected_limits.memory_bytes as u64
            || limits.total_fuel() != expected_limits.total_fuel
            || limits.poll_quantum() != expected_limits.poll_quantum
            || limits.resources() != u64::from(expected_limits.resources)
        {
            return Err(ComponentGraphAuthenticationError::DescriptorPolicyMismatch);
        }
    }
    if descriptor
        .edges()
        .iter()
        .zip(policy.edges)
        .any(|(observed, expected)| *observed != format_edge(*expected))
        || descriptor
            .external_imports()
            .iter()
            .zip(policy.external_imports)
            .any(|(observed, expected)| {
                observed.target().node() != expected.target().node().index()
                    || observed.target().entity() != expected.target().import().index()
            })
        || descriptor
            .published_exports()
            .iter()
            .zip(policy.published_exports)
            .any(|(observed, expected)| {
                observed.source().node() != expected.source().node().index()
                    || observed.source().entity() != expected.source().export().index()
            })
    {
        return Err(ComponentGraphAuthenticationError::DescriptorPolicyMismatch);
    }
    let replacement = descriptor.replacement();
    if replacement.target() != policy.replacement.target.index()
        || replacement.max_replacements() != policy.replacement.max_replacements
        || replacement.retirement_action() != ComponentGraphVersionRetirementActionV1::PolicyCancel
        || replacement.incident_edges().len() != policy.replacement.incident_edges.len()
        || replacement
            .incident_edges()
            .iter()
            .zip(policy.replacement.incident_edges)
            .any(|(observed, expected)| {
                observed.edge() != format_edge(expected.edge)
                    || observed.action() != ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh
                    || expected.action != ComponentGraphReplacementEdgeAction::RecreateFresh
            })
    {
        return Err(ComponentGraphAuthenticationError::DescriptorPolicyMismatch);
    }
    Ok(())
}

fn validate_descriptor_admission(
    descriptor: &ComponentGraphVersionV1,
    admitted: &AdmittedComponentGraph,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Result<(), ComponentGraphAuthenticationError> {
    let manifest = admitted.manifest();
    if admitted.runtime_ready()
        || manifest.name() != descriptor.name()
        || manifest.profile() != descriptor.profile()
        || manifest.cycle_policy() != ComponentGraphCyclePolicy::AcyclicOnly
        || descriptor.cycle_policy() != ComponentGraphVersionCyclePolicyV1::AcyclicOnly
        || manifest.account() != descriptor.account()
        || manifest.nodes().len() != descriptor.nodes().len()
        || manifest.edges().len() != descriptor.edges().len()
        || manifest.async_edges().len() != descriptor.async_edges().len()
        || manifest.resource_edges().len() != policy.resource_edges.len()
        || !manifest.resource_edges().is_empty()
        || manifest.external_imports().len() != descriptor.external_imports().len()
        || manifest.published_exports().len() != descriptor.published_exports().len()
        || !admitted.grants().is_empty()
    {
        return Err(ComponentGraphAuthenticationError::DescriptorAdmissionMismatch);
    }
    for (observed, expected) in manifest.nodes().iter().zip(descriptor.nodes()) {
        let limits = expected.instance_limits();
        if observed.id().index() != expected.ordinal()
            || observed.label() != expected.label()
            || observed.profile() != descriptor.profile()
            || observed.world() != expected.world()
            || format_nesting(observed.nesting()) != expected.nesting()
            || observed.artifact().as_bytes() != expected.component_identity().as_bytes()
            || &observed.world_contract_commitment()
                != expected.world_contract_commitment().as_bytes()
            || observed.limits().memory_bytes as u64 != limits.memory_bytes()
            || observed.limits().total_fuel != limits.total_fuel()
            || observed.limits().poll_quantum != limits.poll_quantum()
            || u64::from(observed.limits().resources) != limits.resources()
            || observed.budget() != expected.budget()
        {
            return Err(ComponentGraphAuthenticationError::DescriptorAdmissionMismatch);
        }
    }
    if manifest
        .edges()
        .iter()
        .zip(descriptor.edges())
        .any(|(observed, expected)| format_edge(*observed) != *expected)
        || manifest
            .async_edges()
            .iter()
            .zip(descriptor.async_edges())
            .any(|(observed, expected)| {
                format_edge(observed.edge()) != expected.edge()
                    || observed.async_functions() != expected.async_functions()
                    || observed.streams() != expected.streams()
                    || observed.futures() != expected.futures()
            })
        || manifest
            .external_imports()
            .iter()
            .zip(descriptor.external_imports())
            .any(|(observed, expected)| {
                observed.target().node().index() != expected.target().node()
                    || observed.target().import().index() != expected.target().entity()
            })
        || manifest
            .published_exports()
            .iter()
            .zip(descriptor.published_exports())
            .any(|(observed, expected)| {
                observed.source().node().index() != expected.source().node()
                    || observed.source().export().index() != expected.source().entity()
            })
    {
        return Err(ComponentGraphAuthenticationError::DescriptorAdmissionMismatch);
    }
    validate_descriptor_policy(descriptor, policy, policy.commitment()?)
        .map_err(|_| ComponentGraphAuthenticationError::DescriptorAdmissionMismatch)
}

fn validate_descriptor_version_pair(
    current: &ComponentGraphVersionV1,
    successor: &ComponentGraphVersionV1,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Result<(), ComponentGraphAuthenticationError> {
    if current.name() != successor.name()
        || current.profile() != successor.profile()
        || current.policy_digest() != successor.policy_digest()
        || current.cycle_policy() != successor.cycle_policy()
        || current.edges() != successor.edges()
        || current.async_edges() != successor.async_edges()
        || current.external_imports() != successor.external_imports()
        || current.published_exports() != successor.published_exports()
        || current.replacement() != successor.replacement()
        || current.nodes().len() != successor.nodes().len()
    {
        return Err(ComponentGraphAuthenticationError::VersionRelation);
    }
    let target = usize::from(policy.replacement.target.index());
    for (index, (left, right)) in current.nodes().iter().zip(successor.nodes()).enumerate() {
        if index != target {
            if left != right {
                return Err(ComponentGraphAuthenticationError::VersionRelation);
            }
        } else if left.ordinal() != right.ordinal()
            || left.label() != right.label()
            || left.world() != right.world()
            || left.nesting() != right.nesting()
            || left.artifact_policy_digest() != right.artifact_policy_digest()
            || left.world_contract_commitment() != right.world_contract_commitment()
            || left.instance_limits() != right.instance_limits()
        {
            return Err(ComponentGraphAuthenticationError::VersionRelation);
        }
    }
    Ok(())
}
