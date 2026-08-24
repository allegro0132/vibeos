//! Canonical, inert descriptor for one durable Component graph version.
//!
//! A CGV1 object contains the complete semantic manifest and commitments for
//! an ordered set of separately stored CMP1/CME1 attachments. It deliberately
//! contains no ObjectId, SpaceId, transaction, derivation, slot, capability,
//! runtime identity, or lookup key. Storage binds attachments by an external
//! exact root-relative layout; [`ComponentGraphVersionBundleV1`] then checks
//! their bytes against this descriptor before admission may authenticate or
//! inspect anything.

use alloc::{string::String, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};

use crate::{
    artifact::{profile_code, profile_from_code, profile_stage_raw},
    ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactCommitment,
    ComponentArtifactInstanceLimitsV1, ComponentArtifactPolicyDigest,
    ComponentArtifactSignerPolicyKind, ComponentArtifactV1, ComponentGraphAccount,
    ComponentGraphNodeBudget, ProfileIdentity, PROFILE_1_COMPONENT_GRAPH_LIMITS, PROFILE_1_LIMITS,
};

use crate::ComponentGraphVersionAuthenticationEvidenceV1;

pub const COMPONENT_GRAPH_VERSION_MAGIC: [u8; 8] = *b"VIBECGV\0";
pub const COMPONENT_GRAPH_VERSION_FORMAT_VERSION: u16 = 1;
pub const COMPONENT_GRAPH_VERSION_MANIFEST_VERSION: u16 = 1;
pub const COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION: u16 = 1;
pub const COMPONENT_GRAPH_VERSION_HASH_SHA256: u16 = 1;
pub const COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW: u32 = 0x4347_5631;
pub const COMPONENT_GRAPH_VERSION_HEADER_LEN: usize = 256;
pub const MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES: usize = 64 * 1024;
pub const MAX_COMPONENT_GRAPH_VERSION_NAME_BYTES: usize = 64;
pub const MAX_COMPONENT_GRAPH_VERSION_LABEL_BYTES: usize = 128;
pub const MAX_COMPONENT_GRAPH_VERSION_WORLD_BYTES: usize = 256;

pub const C76_COMPONENT_GRAPH_VERSION_NODE_COUNT: usize = 3;
pub const C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT: usize = 2;
pub const C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT: usize = 1;
pub const C76_COMPONENT_GRAPH_VERSION_TARGET: u16 = 1;
pub const C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS: u16 = 1;
pub const C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT: usize = 2;

const FLAGS_OFFSET: usize = 12;
const OBJECT_KIND_OFFSET: usize = 16;
const HASH_ALGORITHM_OFFSET: usize = 20;
const MANIFEST_VERSION_OFFSET: usize = 22;
const SIGNER_POLICY_VERSION_OFFSET: usize = 24;
const PROFILE_CODE_OFFSET: usize = 26;
const PROFILE_STAGE_OFFSET: usize = 28;
const CYCLE_POLICY_OFFSET: usize = 30;
const ARTIFACT_ABI_OFFSET: usize = 32;
const COMPONENT_PROFILE_OFFSET: usize = 34;
const CORE_PROFILE_OFFSET: usize = 36;
const RUNTIME_ABI_OFFSET: usize = 38;
const CANONICAL_FEATURES_OFFSET: usize = 40;
const ORDINAL_OFFSET: usize = 48;
const TOTAL_LEN_OFFSET: usize = 56;
const BODY_LEN_OFFSET: usize = 64;
const NODE_COUNT_OFFSET: usize = 72;
const EDGE_COUNT_OFFSET: usize = 74;
const ASYNC_EDGE_COUNT_OFFSET: usize = 76;
const EXTERNAL_IMPORT_COUNT_OFFSET: usize = 78;
const PUBLISHED_EXPORT_COUNT_OFFSET: usize = 80;
const RESOURCE_EDGE_COUNT_OFFSET: usize = 82;
const GRANT_COUNT_OFFSET: usize = 84;
const INCIDENT_EDGE_COUNT_OFFSET: usize = 86;
const REPLACEMENT_TARGET_OFFSET: usize = 88;
const MAX_REPLACEMENTS_OFFSET: usize = 90;
const RETIREMENT_ACTION_OFFSET: usize = 92;
const HEADER_RESERVED0_OFFSET: usize = 94;
const PREDECESSOR_COMMITMENT_OFFSET: usize = 96;
const POLICY_DIGEST_OFFSET: usize = 128;
const MANIFEST_HASH_OFFSET: usize = 160;
const VERSION_COMMITMENT_OFFSET: usize = 192;
const HEADER_RESERVED1_OFFSET: usize = 224;

const NODE_FIXED_LEN: usize = 280;
const EDGE_ENCODED_LEN: usize = 8;
const ASYNC_EDGE_ENCODED_LEN: usize = 24;
const ENDPOINT_ENCODED_LEN: usize = 4;
const ACCOUNT_FIELD_COUNT: usize = 13;

const MANIFEST_HASH_DOMAIN: &[u8] = b"vibeos.component-graph-version.manifest.v1\0";
const VERSION_COMMITMENT_DOMAIN: &[u8] = b"vibeos.component-graph-version.commitment.v1\0";
const ARTIFACT_EVIDENCE_COMMITMENT_DOMAIN: &[u8] =
    b"vibeos.component-artifact.authentication-evidence.v1\0";

macro_rules! redacted_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ComponentGraphVersionError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    Err(ComponentGraphVersionError::ZeroDigest)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

redacted_digest!(ComponentGraphVersionCommitment);
redacted_digest!(ComponentGraphVersionPolicyDigest);
redacted_digest!(ComponentGraphVersionWorldContractCommitment);
redacted_digest!(ComponentGraphVersionComponentIdentity);
redacted_digest!(ComponentArtifactAuthenticationEvidenceCommitment);

impl ComponentGraphVersionComponentIdentity {
    pub fn from_component_bytes(bytes: &[u8]) -> Result<Self, ComponentGraphVersionError> {
        Self::from_bytes(Sha256::digest(bytes).into())
    }
}

impl ComponentArtifactAuthenticationEvidenceCommitment {
    pub fn from_evidence(
        evidence: &ComponentArtifactAuthenticationEvidenceV1,
    ) -> Result<Self, ComponentGraphVersionError> {
        let encoded = evidence.encode();
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_EVIDENCE_COMMITMENT_DOMAIN);
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(encoded);
        Self::from_bytes(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentGraphVersionCyclePolicyV1 {
    AcyclicOnly = 1,
}

impl ComponentGraphVersionCyclePolicyV1 {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::AcyclicOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphVersionNodeNestingV1 {
    Root,
    Nested { parent: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentGraphVersionEndpointV1 {
    node: u16,
    entity: u16,
}

impl ComponentGraphVersionEndpointV1 {
    pub const fn new(node: u16, entity: u16) -> Self {
        Self { node, entity }
    }

    pub const fn node(self) -> u16 {
        self.node
    }

    pub const fn entity(self) -> u16 {
        self.entity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentGraphVersionEdgeV1 {
    source: ComponentGraphVersionEndpointV1,
    target: ComponentGraphVersionEndpointV1,
}

impl ComponentGraphVersionEdgeV1 {
    pub const fn new(
        source: ComponentGraphVersionEndpointV1,
        target: ComponentGraphVersionEndpointV1,
    ) -> Self {
        Self { source, target }
    }

    pub const fn source(self) -> ComponentGraphVersionEndpointV1 {
        self.source
    }

    pub const fn target(self) -> ComponentGraphVersionEndpointV1 {
        self.target
    }

    fn key(self) -> (u16, u16, u16, u16) {
        (
            self.source.node,
            self.source.entity,
            self.target.node,
            self.target.entity,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphVersionAsyncEdgeV1 {
    edge: ComponentGraphVersionEdgeV1,
    async_functions: u32,
    streams: u32,
    futures: u32,
}

impl ComponentGraphVersionAsyncEdgeV1 {
    pub fn new(
        edge: ComponentGraphVersionEdgeV1,
        async_functions: u32,
        streams: u32,
        futures: u32,
    ) -> Result<Self, ComponentGraphVersionError> {
        if async_functions == 0
            || async_functions > PROFILE_1_LIMITS.max_async_functions
            || streams > PROFILE_1_LIMITS.max_component_definitions
            || futures > PROFILE_1_LIMITS.max_component_definitions
        {
            return Err(ComponentGraphVersionError::AsyncEdge);
        }
        Ok(Self {
            edge,
            async_functions,
            streams,
            futures,
        })
    }

    pub const fn edge(&self) -> ComponentGraphVersionEdgeV1 {
        self.edge
    }

    pub const fn async_functions(&self) -> u32 {
        self.async_functions
    }

    pub const fn streams(&self) -> u32 {
        self.streams
    }

    pub const fn futures(&self) -> u32 {
        self.futures
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentGraphVersionExternalImportV1 {
    target: ComponentGraphVersionEndpointV1,
}

impl ComponentGraphVersionExternalImportV1 {
    pub const fn new(target: ComponentGraphVersionEndpointV1) -> Self {
        Self { target }
    }

    pub const fn target(self) -> ComponentGraphVersionEndpointV1 {
        self.target
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentGraphVersionPublishedExportV1 {
    source: ComponentGraphVersionEndpointV1,
}

impl ComponentGraphVersionPublishedExportV1 {
    pub const fn new(source: ComponentGraphVersionEndpointV1) -> Self {
        Self { source }
    }

    pub const fn source(self) -> ComponentGraphVersionEndpointV1 {
        self.source
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentGraphVersionRetirementActionV1 {
    PolicyCancel = 1,
}

impl ComponentGraphVersionRetirementActionV1 {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::PolicyCancel),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentGraphVersionIncidentEdgeActionV1 {
    RecreateFresh = 1,
}

impl ComponentGraphVersionIncidentEdgeActionV1 {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::RecreateFresh),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphVersionIncidentEdgeV1 {
    edge: ComponentGraphVersionEdgeV1,
    action: ComponentGraphVersionIncidentEdgeActionV1,
}

impl ComponentGraphVersionIncidentEdgeV1 {
    pub const fn new(
        edge: ComponentGraphVersionEdgeV1,
        action: ComponentGraphVersionIncidentEdgeActionV1,
    ) -> Self {
        Self { edge, action }
    }

    pub const fn edge(self) -> ComponentGraphVersionEdgeV1 {
        self.edge
    }

    pub const fn action(self) -> ComponentGraphVersionIncidentEdgeActionV1 {
        self.action
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ComponentGraphVersionReplacementV1 {
    target: u16,
    max_replacements: u16,
    retirement_action: ComponentGraphVersionRetirementActionV1,
    incident_edges: Vec<ComponentGraphVersionIncidentEdgeV1>,
}

impl ComponentGraphVersionReplacementV1 {
    pub fn new(
        target: u16,
        max_replacements: u16,
        retirement_action: ComponentGraphVersionRetirementActionV1,
        mut incident_edges: Vec<ComponentGraphVersionIncidentEdgeV1>,
    ) -> Result<Self, ComponentGraphVersionError> {
        if max_replacements != C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS
            || incident_edges.is_empty()
            || incident_edges.len() > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize
        {
            return Err(ComponentGraphVersionError::Replacement);
        }
        incident_edges.sort_unstable_by_key(|incident| incident.edge.key());
        if incident_edges.windows(2).any(|pair| pair[0] == pair[1])
            || incident_edges.iter().any(|incident| {
                incident.action != ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh
            })
        {
            return Err(ComponentGraphVersionError::Replacement);
        }
        Ok(Self {
            target,
            max_replacements,
            retirement_action,
            incident_edges,
        })
    }

    pub const fn target(&self) -> u16 {
        self.target
    }

    pub const fn max_replacements(&self) -> u16 {
        self.max_replacements
    }

    pub const fn retirement_action(&self) -> ComponentGraphVersionRetirementActionV1 {
        self.retirement_action
    }

    pub fn incident_edges(&self) -> &[ComponentGraphVersionIncidentEdgeV1] {
        &self.incident_edges
    }
}

#[derive(PartialEq, Eq)]
pub struct ComponentGraphVersionNodeV1 {
    ordinal: u16,
    label: String,
    world: String,
    nesting: ComponentGraphVersionNodeNestingV1,
    artifact_encoded_len: u64,
    artifact_commitment: ComponentArtifactCommitment,
    artifact_evidence_commitment: ComponentArtifactAuthenticationEvidenceCommitment,
    artifact_policy_digest: ComponentArtifactPolicyDigest,
    component_identity: ComponentGraphVersionComponentIdentity,
    world_contract_commitment: ComponentGraphVersionWorldContractCommitment,
    instance_limits: ComponentArtifactInstanceLimitsV1,
    budget: ComponentGraphNodeBudget,
}

impl ComponentGraphVersionNodeV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ordinal: u16,
        label: &str,
        world: &str,
        nesting: ComponentGraphVersionNodeNestingV1,
        artifact_encoded_len: u64,
        artifact_commitment: ComponentArtifactCommitment,
        artifact_evidence_commitment: ComponentArtifactAuthenticationEvidenceCommitment,
        artifact_policy_digest: ComponentArtifactPolicyDigest,
        component_identity: ComponentGraphVersionComponentIdentity,
        world_contract_commitment: ComponentGraphVersionWorldContractCommitment,
        instance_limits: ComponentArtifactInstanceLimitsV1,
        budget: ComponentGraphNodeBudget,
    ) -> Result<Self, ComponentGraphVersionError> {
        if artifact_encoded_len == 0
            || artifact_encoded_len > crate::MAX_COMPONENT_ARTIFACT_ENCODED_BYTES as u64
        {
            return Err(ComponentGraphVersionError::AttachmentLength);
        }
        let label = copied_text(label, MAX_COMPONENT_GRAPH_VERSION_LABEL_BYTES)?;
        let world = copied_text(world, MAX_COMPONENT_GRAPH_VERSION_WORLD_BYTES)?;
        if !valid_world(&world) {
            return Err(ComponentGraphVersionError::Text);
        }
        ComponentArtifactInstanceLimitsV1::new(
            instance_limits.memory_bytes(),
            instance_limits.total_fuel(),
            instance_limits.poll_quantum(),
            instance_limits.resources(),
        )
        .map_err(|_| ComponentGraphVersionError::Limits)?;
        Ok(Self {
            ordinal,
            label,
            world,
            nesting,
            artifact_encoded_len,
            artifact_commitment,
            artifact_evidence_commitment,
            artifact_policy_digest,
            component_identity,
            world_contract_commitment,
            instance_limits,
            budget,
        })
    }

    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub const fn nesting(&self) -> ComponentGraphVersionNodeNestingV1 {
        self.nesting
    }

    pub const fn artifact_encoded_len(&self) -> u64 {
        self.artifact_encoded_len
    }

    pub const fn artifact_commitment(&self) -> ComponentArtifactCommitment {
        self.artifact_commitment
    }

    pub const fn artifact_evidence_commitment(
        &self,
    ) -> ComponentArtifactAuthenticationEvidenceCommitment {
        self.artifact_evidence_commitment
    }

    pub const fn artifact_policy_digest(&self) -> ComponentArtifactPolicyDigest {
        self.artifact_policy_digest
    }

    pub const fn component_identity(&self) -> ComponentGraphVersionComponentIdentity {
        self.component_identity
    }

    pub const fn world_contract_commitment(&self) -> ComponentGraphVersionWorldContractCommitment {
        self.world_contract_commitment
    }

    pub const fn instance_limits(&self) -> ComponentArtifactInstanceLimitsV1 {
        self.instance_limits
    }

    pub const fn budget(&self) -> ComponentGraphNodeBudget {
        self.budget
    }
}

impl fmt::Debug for ComponentGraphVersionNodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphVersionNodeV1")
            .field("ordinal", &self.ordinal)
            .field("label", &self.label)
            .field("world", &self.world)
            .field("nesting", &self.nesting)
            .field("artifact_encoded_len", &self.artifact_encoded_len)
            .field("artifact_commitment", &self.artifact_commitment)
            .field(
                "artifact_evidence_commitment",
                &self.artifact_evidence_commitment,
            )
            .field("artifact_policy_digest", &self.artifact_policy_digest)
            .field("component_identity", &self.component_identity)
            .field("world_contract_commitment", &self.world_contract_commitment)
            .field("instance_limits", &self.instance_limits)
            .field("budget", &self.budget)
            .finish()
    }
}

/// One canonical graph-version descriptor. Hashes and graph-local ordinals are
/// inert metadata, never durable lookup authority.
///
/// ```compile_fail
/// use vibeos_component_format::ComponentGraphVersionV1;
/// fn no_raw_durable_id(value: &ComponentGraphVersionV1) { let _ = value.object_id(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_format::ComponentGraphVersionV1;
/// fn no_ambient_lookup(value: &ComponentGraphVersionV1) { value.lookup("node-1"); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_format::ComponentGraphVersionV1;
/// fn no_guest_execution(value: &ComponentGraphVersionV1) { value.invoke(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_format::ComponentGraphVersionV1;
/// fn no_direct_grant_move(value: &ComponentGraphVersionV1) { value.grant(); }
/// ```
#[derive(PartialEq, Eq)]
pub struct ComponentGraphVersionV1 {
    name: String,
    profile: ProfileIdentity,
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    policy_digest: ComponentGraphVersionPolicyDigest,
    cycle_policy: ComponentGraphVersionCyclePolicyV1,
    account: ComponentGraphAccount,
    nodes: Vec<ComponentGraphVersionNodeV1>,
    edges: Vec<ComponentGraphVersionEdgeV1>,
    async_edges: Vec<ComponentGraphVersionAsyncEdgeV1>,
    external_imports: Vec<ComponentGraphVersionExternalImportV1>,
    published_exports: Vec<ComponentGraphVersionPublishedExportV1>,
    replacement: ComponentGraphVersionReplacementV1,
}

impl ComponentGraphVersionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        profile: ProfileIdentity,
        ordinal: u64,
        predecessor: Option<ComponentGraphVersionCommitment>,
        policy_digest: ComponentGraphVersionPolicyDigest,
        account: ComponentGraphAccount,
        mut nodes: Vec<ComponentGraphVersionNodeV1>,
        mut edges: Vec<ComponentGraphVersionEdgeV1>,
        mut async_edges: Vec<ComponentGraphVersionAsyncEdgeV1>,
        mut external_imports: Vec<ComponentGraphVersionExternalImportV1>,
        mut published_exports: Vec<ComponentGraphVersionPublishedExportV1>,
        replacement: ComponentGraphVersionReplacementV1,
    ) -> Result<Self, ComponentGraphVersionError> {
        if profile_code(profile).is_none() {
            return Err(ComponentGraphVersionError::Profile);
        }
        if ordinal > u64::from(replacement.max_replacements)
            || (ordinal == 0) != predecessor.is_none()
        {
            return Err(ComponentGraphVersionError::VersionRelation);
        }
        if nodes.is_empty()
            || nodes.len() > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes as usize
            || edges.len() > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize
            || async_edges.len() > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize
            || external_imports.len()
                > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_external_imports as usize
            || published_exports.len()
                > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_published_exports as usize
        {
            return Err(ComponentGraphVersionError::Count);
        }

        let name = copied_graph_name(name)?;
        nodes.sort_unstable_by_key(|node| node.ordinal);
        for (index, node) in nodes.iter().enumerate() {
            if usize::from(node.ordinal) != index
                || nodes[..index]
                    .iter()
                    .any(|earlier| earlier.label == node.label)
            {
                return Err(ComponentGraphVersionError::NodeOrder);
            }
        }

        edges.sort_unstable_by_key(|edge| edge.key());
        if edges.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ComponentGraphVersionError::EdgeOrder);
        }
        async_edges.sort_unstable_by_key(|edge| edge.edge.key());
        if async_edges
            .windows(2)
            .any(|pair| pair[0].edge == pair[1].edge)
        {
            return Err(ComponentGraphVersionError::AsyncEdge);
        }
        external_imports.sort_unstable();
        if external_imports.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ComponentGraphVersionError::ExternalImport);
        }
        published_exports.sort_unstable();
        if published_exports.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ComponentGraphVersionError::PublishedExport);
        }

        let node_count = nodes.len();
        for edge in &edges {
            validate_edge(*edge, node_count)?;
        }
        validate_acyclic(&edges, node_count)?;
        if edges.iter().enumerate().any(|(index, edge)| {
            edges[..index]
                .iter()
                .any(|earlier| earlier.target == edge.target)
        }) {
            return Err(ComponentGraphVersionError::EdgeOrder);
        }
        for async_edge in &async_edges {
            if edges.binary_search(&async_edge.edge).is_err() {
                return Err(ComponentGraphVersionError::AsyncEdge);
            }
        }
        for external in &external_imports {
            validate_endpoint(external.target, node_count)?;
            if edges.iter().any(|edge| edge.target == external.target) {
                return Err(ComponentGraphVersionError::ExternalImport);
            }
        }
        for published in &published_exports {
            validate_endpoint(published.source, node_count)?;
        }

        let target_index = usize::from(replacement.target);
        if target_index >= node_count
            || nodes[target_index].nesting != ComponentGraphVersionNodeNestingV1::Root
            || nodes.iter().any(|node| {
                matches!(
                    node.nesting,
                    ComponentGraphVersionNodeNestingV1::Nested { parent }
                        if parent == replacement.target
                )
            })
            || external_imports
                .iter()
                .any(|external| external.target.node == replacement.target)
            || published_exports
                .iter()
                .any(|published| published.source.node == replacement.target)
        {
            return Err(ComponentGraphVersionError::ReplacementSurface);
        }
        let incident: Vec<_> = edges
            .iter()
            .copied()
            .filter(|edge| {
                edge.source.node == replacement.target || edge.target.node == replacement.target
            })
            .collect();
        if incident.len() != replacement.incident_edges.len()
            || incident
                .iter()
                .zip(&replacement.incident_edges)
                .any(|(edge, expected)| *edge != expected.edge)
        {
            return Err(ComponentGraphVersionError::IncidentEdges);
        }

        let observed_account = derive_account(
            &nodes,
            edges.len(),
            external_imports.len(),
            published_exports.len(),
        )?;
        if account != observed_account {
            return Err(ComponentGraphVersionError::Account);
        }

        let graph = Self {
            name,
            profile,
            ordinal,
            predecessor,
            policy_digest,
            cycle_policy: ComponentGraphVersionCyclePolicyV1::AcyclicOnly,
            account,
            nodes,
            edges,
            async_edges,
            external_imports,
            published_exports,
            replacement,
        };
        let _ = graph.encode()?;
        Ok(graph)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn predecessor(&self) -> Option<ComponentGraphVersionCommitment> {
        self.predecessor
    }

    pub const fn policy_digest(&self) -> ComponentGraphVersionPolicyDigest {
        self.policy_digest
    }

    pub const fn cycle_policy(&self) -> ComponentGraphVersionCyclePolicyV1 {
        self.cycle_policy
    }

    pub const fn account(&self) -> ComponentGraphAccount {
        self.account
    }

    pub fn nodes(&self) -> &[ComponentGraphVersionNodeV1] {
        &self.nodes
    }

    pub fn edges(&self) -> &[ComponentGraphVersionEdgeV1] {
        &self.edges
    }

    pub fn async_edges(&self) -> &[ComponentGraphVersionAsyncEdgeV1] {
        &self.async_edges
    }

    pub fn external_imports(&self) -> &[ComponentGraphVersionExternalImportV1] {
        &self.external_imports
    }

    pub fn published_exports(&self) -> &[ComponentGraphVersionPublishedExportV1] {
        &self.published_exports
    }

    pub const fn replacement(&self) -> &ComponentGraphVersionReplacementV1 {
        &self.replacement
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Enforce the exact C7.6 acceptance fixture on top of the bounded CGV1
    /// codec. Production decoders may retain the generalized bounded format;
    /// the C7.6 admission root must call this gate before authentication.
    pub fn validate_c76_shape(&self) -> Result<(), ComponentGraphVersionError> {
        if self.profile != ProfileIdentity::PROFILE_1_ASYNC
            || self.profile.execution_enabled()
            || self.nodes.len() != C76_COMPONENT_GRAPH_VERSION_NODE_COUNT
            || self.edges.len() != C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT
            || self.async_edges.len() != C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT
            || !self.external_imports.is_empty()
            || self.published_exports.len() != C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT
            || self.replacement.target != C76_COMPONENT_GRAPH_VERSION_TARGET
            || self.replacement.max_replacements != C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS
            || self.replacement.retirement_action
                != ComponentGraphVersionRetirementActionV1::PolicyCancel
            || self.replacement.incident_edges.len()
                != C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT
            || self.replacement.incident_edges.iter().any(|incident| {
                incident.action != ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh
            })
        {
            return Err(ComponentGraphVersionError::C76Shape);
        }
        Ok(())
    }

    pub fn version_commitment(
        &self,
    ) -> Result<ComponentGraphVersionCommitment, ComponentGraphVersionError> {
        let encoded = self.encode()?;
        ComponentGraphVersionCommitment::from_bytes(read_digest(
            &encoded,
            VERSION_COMMITMENT_OFFSET,
        )?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ComponentGraphVersionError> {
        let body = self.encode_body()?;
        let total = COMPONENT_GRAPH_VERSION_HEADER_LEN
            .checked_add(body.len())
            .ok_or(ComponentGraphVersionError::Length)?;
        if total > MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES {
            return Err(ComponentGraphVersionError::TooLarge);
        }
        let mut out = zeroed(total)?;
        out[..8].copy_from_slice(&COMPONENT_GRAPH_VERSION_MAGIC);
        put_u16(&mut out, 8, COMPONENT_GRAPH_VERSION_FORMAT_VERSION)?;
        put_u16(
            &mut out,
            10,
            u16::try_from(COMPONENT_GRAPH_VERSION_HEADER_LEN)
                .map_err(|_| ComponentGraphVersionError::Length)?,
        )?;
        put_u32(&mut out, FLAGS_OFFSET, 0)?;
        put_u32(
            &mut out,
            OBJECT_KIND_OFFSET,
            COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW,
        )?;
        put_u16(
            &mut out,
            HASH_ALGORITHM_OFFSET,
            COMPONENT_GRAPH_VERSION_HASH_SHA256,
        )?;
        put_u16(
            &mut out,
            MANIFEST_VERSION_OFFSET,
            COMPONENT_GRAPH_VERSION_MANIFEST_VERSION,
        )?;
        put_u16(
            &mut out,
            SIGNER_POLICY_VERSION_OFFSET,
            COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION,
        )?;
        put_u16(
            &mut out,
            PROFILE_CODE_OFFSET,
            profile_code(self.profile).ok_or(ComponentGraphVersionError::Profile)?,
        )?;
        put_u16(
            &mut out,
            PROFILE_STAGE_OFFSET,
            profile_stage_raw(self.profile.stage),
        )?;
        put_u16(&mut out, CYCLE_POLICY_OFFSET, self.cycle_policy as u16)?;
        put_u16(&mut out, ARTIFACT_ABI_OFFSET, self.profile.artifact_abi)?;
        put_u16(
            &mut out,
            COMPONENT_PROFILE_OFFSET,
            self.profile.component_profile,
        )?;
        put_u16(&mut out, CORE_PROFILE_OFFSET, self.profile.core_profile)?;
        put_u16(&mut out, RUNTIME_ABI_OFFSET, self.profile.runtime_abi)?;
        put_u64(
            &mut out,
            CANONICAL_FEATURES_OFFSET,
            self.profile.canonical_features,
        )?;
        put_u64(&mut out, ORDINAL_OFFSET, self.ordinal)?;
        put_u64(&mut out, TOTAL_LEN_OFFSET, usize_u64(total)?)?;
        put_u64(&mut out, BODY_LEN_OFFSET, usize_u64(body.len())?)?;
        put_u16(&mut out, NODE_COUNT_OFFSET, usize_u16(self.nodes.len())?)?;
        put_u16(&mut out, EDGE_COUNT_OFFSET, usize_u16(self.edges.len())?)?;
        put_u16(
            &mut out,
            ASYNC_EDGE_COUNT_OFFSET,
            usize_u16(self.async_edges.len())?,
        )?;
        put_u16(
            &mut out,
            EXTERNAL_IMPORT_COUNT_OFFSET,
            usize_u16(self.external_imports.len())?,
        )?;
        put_u16(
            &mut out,
            PUBLISHED_EXPORT_COUNT_OFFSET,
            usize_u16(self.published_exports.len())?,
        )?;
        put_u16(&mut out, RESOURCE_EDGE_COUNT_OFFSET, 0)?;
        put_u16(&mut out, GRANT_COUNT_OFFSET, 0)?;
        put_u16(
            &mut out,
            INCIDENT_EDGE_COUNT_OFFSET,
            usize_u16(self.replacement.incident_edges.len())?,
        )?;
        put_u16(&mut out, REPLACEMENT_TARGET_OFFSET, self.replacement.target)?;
        put_u16(
            &mut out,
            MAX_REPLACEMENTS_OFFSET,
            self.replacement.max_replacements,
        )?;
        put_u16(
            &mut out,
            RETIREMENT_ACTION_OFFSET,
            self.replacement.retirement_action as u16,
        )?;
        if let Some(predecessor) = self.predecessor {
            out[PREDECESSOR_COMMITMENT_OFFSET..PREDECESSOR_COMMITMENT_OFFSET + 32]
                .copy_from_slice(predecessor.as_bytes());
        }
        out[POLICY_DIGEST_OFFSET..POLICY_DIGEST_OFFSET + 32]
            .copy_from_slice(self.policy_digest.as_bytes());
        out[COMPONENT_GRAPH_VERSION_HEADER_LEN..].copy_from_slice(&body);

        let manifest_hash = hash_framed(MANIFEST_HASH_DOMAIN, &body);
        out[MANIFEST_HASH_OFFSET..MANIFEST_HASH_OFFSET + 32].copy_from_slice(&manifest_hash);
        let commitment = hash_version_commitment(&out)?;
        out[VERSION_COMMITMENT_OFFSET..VERSION_COMMITMENT_OFFSET + 32].copy_from_slice(&commitment);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComponentGraphVersionError> {
        if bytes.len() < COMPONENT_GRAPH_VERSION_HEADER_LEN {
            return Err(ComponentGraphVersionError::Truncated);
        }
        if bytes.len() > MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES {
            return Err(ComponentGraphVersionError::TooLarge);
        }
        if bytes[..8] != COMPONENT_GRAPH_VERSION_MAGIC {
            return Err(ComponentGraphVersionError::Magic);
        }
        if get_u16(bytes, 8)? != COMPONENT_GRAPH_VERSION_FORMAT_VERSION {
            return Err(ComponentGraphVersionError::Version);
        }
        if usize::from(get_u16(bytes, 10)?) != COMPONENT_GRAPH_VERSION_HEADER_LEN
            || get_u32(bytes, FLAGS_OFFSET)? != 0
        {
            return Err(ComponentGraphVersionError::Header);
        }
        if get_u32(bytes, OBJECT_KIND_OFFSET)? != COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW {
            return Err(ComponentGraphVersionError::ObjectKind);
        }
        if get_u16(bytes, HASH_ALGORITHM_OFFSET)? != COMPONENT_GRAPH_VERSION_HASH_SHA256 {
            return Err(ComponentGraphVersionError::HashAlgorithm);
        }
        if get_u16(bytes, MANIFEST_VERSION_OFFSET)? != COMPONENT_GRAPH_VERSION_MANIFEST_VERSION
            || get_u16(bytes, SIGNER_POLICY_VERSION_OFFSET)?
                != COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION
        {
            return Err(ComponentGraphVersionError::Version);
        }
        if get_u16(bytes, HEADER_RESERVED0_OFFSET)? != 0
            || bytes[42..48].iter().any(|byte| *byte != 0)
            || bytes[HEADER_RESERVED1_OFFSET..COMPONENT_GRAPH_VERSION_HEADER_LEN]
                .iter()
                .any(|byte| *byte != 0)
            || get_u16(bytes, RESOURCE_EDGE_COUNT_OFFSET)? != 0
            || get_u16(bytes, GRANT_COUNT_OFFSET)? != 0
        {
            return Err(ComponentGraphVersionError::Reserved);
        }

        let profile = profile_from_code(get_u16(bytes, PROFILE_CODE_OFFSET)?)
            .ok_or(ComponentGraphVersionError::Profile)?;
        if get_u16(bytes, PROFILE_STAGE_OFFSET)? != profile_stage_raw(profile.stage)
            || get_u16(bytes, ARTIFACT_ABI_OFFSET)? != profile.artifact_abi
            || get_u16(bytes, COMPONENT_PROFILE_OFFSET)? != profile.component_profile
            || get_u16(bytes, CORE_PROFILE_OFFSET)? != profile.core_profile
            || get_u16(bytes, RUNTIME_ABI_OFFSET)? != profile.runtime_abi
            || get_u64(bytes, CANONICAL_FEATURES_OFFSET)? != profile.canonical_features
        {
            return Err(ComponentGraphVersionError::Profile);
        }
        let cycle_policy =
            ComponentGraphVersionCyclePolicyV1::from_raw(get_u16(bytes, CYCLE_POLICY_OFFSET)?)
                .ok_or(ComponentGraphVersionError::CyclePolicy)?;
        if cycle_policy != ComponentGraphVersionCyclePolicyV1::AcyclicOnly {
            return Err(ComponentGraphVersionError::CyclePolicy);
        }

        let total = u64_usize(get_u64(bytes, TOTAL_LEN_OFFSET)?)?;
        let body_len = u64_usize(get_u64(bytes, BODY_LEN_OFFSET)?)?;
        if total != bytes.len()
            || COMPONENT_GRAPH_VERSION_HEADER_LEN
                .checked_add(body_len)
                .ok_or(ComponentGraphVersionError::Length)?
                != total
        {
            return Err(ComponentGraphVersionError::Length);
        }
        let body = &bytes[COMPONENT_GRAPH_VERSION_HEADER_LEN..];
        if read_digest(bytes, MANIFEST_HASH_OFFSET)? != hash_framed(MANIFEST_HASH_DOMAIN, body) {
            return Err(ComponentGraphVersionError::ManifestHash);
        }
        if read_digest(bytes, VERSION_COMMITMENT_OFFSET)? != hash_version_commitment(bytes)? {
            return Err(ComponentGraphVersionError::Commitment);
        }

        let ordinal = get_u64(bytes, ORDINAL_OFFSET)?;
        let predecessor_raw = read_digest(bytes, PREDECESSOR_COMMITMENT_OFFSET)?;
        let predecessor = if predecessor_raw == [0; 32] {
            None
        } else {
            Some(ComponentGraphVersionCommitment::from_bytes(
                predecessor_raw,
            )?)
        };
        let policy_digest = ComponentGraphVersionPolicyDigest::from_bytes(read_digest(
            bytes,
            POLICY_DIGEST_OFFSET,
        )?)?;
        let node_count = usize::from(get_u16(bytes, NODE_COUNT_OFFSET)?);
        let edge_count = usize::from(get_u16(bytes, EDGE_COUNT_OFFSET)?);
        let async_count = usize::from(get_u16(bytes, ASYNC_EDGE_COUNT_OFFSET)?);
        let external_count = usize::from(get_u16(bytes, EXTERNAL_IMPORT_COUNT_OFFSET)?);
        let published_count = usize::from(get_u16(bytes, PUBLISHED_EXPORT_COUNT_OFFSET)?);
        let incident_count = usize::from(get_u16(bytes, INCIDENT_EDGE_COUNT_OFFSET)?);
        if node_count == 0
            || node_count > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes as usize
            || edge_count > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize
            || async_count > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize
            || external_count > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_external_imports as usize
            || published_count > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_published_exports as usize
            || incident_count > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize
        {
            return Err(ComponentGraphVersionError::Count);
        }

        let mut cursor = Cursor::new(body);
        let account = decode_account(&mut cursor)?;
        let name = cursor.text_u16(MAX_COMPONENT_GRAPH_VERSION_NAME_BYTES)?;
        let mut nodes = reserved_vec(node_count)?;
        for _ in 0..node_count {
            nodes.push(decode_node(&mut cursor)?);
        }
        let mut edges = reserved_vec(edge_count)?;
        for _ in 0..edge_count {
            edges.push(decode_edge(&mut cursor)?);
        }
        let mut async_edges = reserved_vec(async_count)?;
        for _ in 0..async_count {
            async_edges.push(decode_async_edge(&mut cursor)?);
        }
        let mut external_imports = reserved_vec(external_count)?;
        for _ in 0..external_count {
            external_imports.push(ComponentGraphVersionExternalImportV1::new(decode_endpoint(
                &mut cursor,
            )?));
        }
        let mut published_exports = reserved_vec(published_count)?;
        for _ in 0..published_count {
            published_exports.push(ComponentGraphVersionPublishedExportV1::new(
                decode_endpoint(&mut cursor)?,
            ));
        }
        let mut incidents = reserved_vec(incident_count)?;
        for _ in 0..incident_count {
            let edge = decode_edge(&mut cursor)?;
            let action = ComponentGraphVersionIncidentEdgeActionV1::from_raw(cursor.u16()?)
                .ok_or(ComponentGraphVersionError::Replacement)?;
            if cursor.u16()? != 0 {
                return Err(ComponentGraphVersionError::Reserved);
            }
            incidents.push(ComponentGraphVersionIncidentEdgeV1::new(edge, action));
        }
        cursor.finish()?;
        let retirement_action = ComponentGraphVersionRetirementActionV1::from_raw(get_u16(
            bytes,
            RETIREMENT_ACTION_OFFSET,
        )?)
        .ok_or(ComponentGraphVersionError::Replacement)?;
        let replacement = ComponentGraphVersionReplacementV1::new(
            get_u16(bytes, REPLACEMENT_TARGET_OFFSET)?,
            get_u16(bytes, MAX_REPLACEMENTS_OFFSET)?,
            retirement_action,
            incidents,
        )?;
        let decoded = Self::new(
            &name,
            profile,
            ordinal,
            predecessor,
            policy_digest,
            account,
            nodes,
            edges,
            async_edges,
            external_imports,
            published_exports,
            replacement,
        )?;
        if decoded.encode()?.as_slice() != bytes {
            return Err(ComponentGraphVersionError::NonCanonical);
        }
        Ok(decoded)
    }

    fn encode_body(&self) -> Result<Vec<u8>, ComponentGraphVersionError> {
        let mut body = Vec::new();
        body.try_reserve_exact(4096)
            .map_err(|_| ComponentGraphVersionError::Allocation)?;
        encode_account(&mut body, self.account)?;
        push_text_u16(&mut body, &self.name)?;
        for node in &self.nodes {
            encode_node(&mut body, node)?;
        }
        for edge in &self.edges {
            encode_edge(&mut body, *edge)?;
        }
        for async_edge in &self.async_edges {
            encode_edge(&mut body, async_edge.edge)?;
            push_u32(&mut body, async_edge.async_functions)?;
            push_u32(&mut body, async_edge.streams)?;
            push_u32(&mut body, async_edge.futures)?;
            push_u32(&mut body, 0)?;
        }
        for external in &self.external_imports {
            encode_endpoint(&mut body, external.target)?;
        }
        for published in &self.published_exports {
            encode_endpoint(&mut body, published.source)?;
        }
        for incident in &self.replacement.incident_edges {
            encode_edge(&mut body, incident.edge)?;
            push_u16(&mut body, incident.action as u16)?;
            push_u16(&mut body, 0)?;
        }
        if COMPONENT_GRAPH_VERSION_HEADER_LEN + body.len()
            > MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES
        {
            return Err(ComponentGraphVersionError::TooLarge);
        }
        Ok(body)
    }
}

impl fmt::Debug for ComponentGraphVersionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphVersionV1")
            .field("name", &self.name)
            .field("profile", &self.profile)
            .field("ordinal", &self.ordinal)
            .field("predecessor", &self.predecessor)
            .field("policy_digest", &self.policy_digest)
            .field("cycle_policy", &self.cycle_policy)
            .field("account", &self.account)
            .field("nodes", &self.nodes)
            .field("edges", &self.edges)
            .field("async_edges", &self.async_edges)
            .field("external_imports", &self.external_imports)
            .field("published_exports", &self.published_exports)
            .field("replacement", &self.replacement)
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Complete in-memory logical bundle assembled from one CGV1 descriptor, its
/// ordered CMP1/CME1 attachments, and one detached CGE1 signature. The bundle
/// deliberately carries values rather than durable identifiers.
pub struct ComponentGraphVersionBundleV1 {
    descriptor: ComponentGraphVersionV1,
    artifacts: Vec<ComponentArtifactV1>,
    artifact_evidence: Vec<ComponentArtifactAuthenticationEvidenceV1>,
    graph_evidence: ComponentGraphVersionAuthenticationEvidenceV1,
}

impl ComponentGraphVersionBundleV1 {
    pub fn new(
        descriptor: ComponentGraphVersionV1,
        artifacts: Vec<ComponentArtifactV1>,
        artifact_evidence: Vec<ComponentArtifactAuthenticationEvidenceV1>,
        graph_evidence: ComponentGraphVersionAuthenticationEvidenceV1,
    ) -> Result<Self, ComponentGraphVersionError> {
        if artifacts.len() != descriptor.nodes.len()
            || artifact_evidence.len() != descriptor.nodes.len()
        {
            return Err(ComponentGraphVersionError::AttachmentCount);
        }

        for (index, ((node, artifact), evidence)) in descriptor
            .nodes
            .iter()
            .zip(&artifacts)
            .zip(&artifact_evidence)
            .enumerate()
        {
            if usize::from(node.ordinal) != index
                || artifact.profile() != descriptor.profile
                || artifact.instance_limits() != node.instance_limits
                || artifact.signer_policy().kind()
                    != ComponentArtifactSignerPolicyKind::OperatorRequired
                || artifact.signer_policy().policy_digest() != node.artifact_policy_digest
                || artifact.manifest().world() != node.world
                || artifact.runtime_ready()
                || evidence.runtime_ready()
            {
                return Err(ComponentGraphVersionError::AttachmentMismatch);
            }
            let encoded = artifact
                .encode()
                .map_err(|_| ComponentGraphVersionError::AttachmentMismatch)?;
            if usize_u64(encoded.len())? != node.artifact_encoded_len
                || artifact
                    .artifact_commitment()
                    .map_err(|_| ComponentGraphVersionError::AttachmentMismatch)?
                    != node.artifact_commitment
                || ComponentGraphVersionComponentIdentity::from_component_bytes(
                    artifact.component_bytes(),
                )? != node.component_identity
                || ComponentArtifactAuthenticationEvidenceCommitment::from_evidence(evidence)?
                    != node.artifact_evidence_commitment
                || usize_u64(artifact.component_bytes().len())? != node.budget.component_bytes
                || usize_u64(artifact.manifest().adapters().len())? != node.budget.adapters
                || node.budget.resource_slots != node.instance_limits.resources()
                || node.budget.memory_bytes != node.instance_limits.memory_bytes()
                || node.budget.total_fuel != node.instance_limits.total_fuel()
                || node.budget.poll_quantum != node.instance_limits.poll_quantum()
            {
                return Err(ComponentGraphVersionError::AttachmentMismatch);
            }
        }
        if descriptor.runtime_ready() || graph_evidence.runtime_ready() {
            return Err(ComponentGraphVersionError::AttachmentMismatch);
        }
        Ok(Self {
            descriptor,
            artifacts,
            artifact_evidence,
            graph_evidence,
        })
    }

    pub const fn descriptor(&self) -> &ComponentGraphVersionV1 {
        &self.descriptor
    }

    pub const fn graph_version(&self) -> &ComponentGraphVersionV1 {
        &self.descriptor
    }

    pub fn artifacts(&self) -> &[ComponentArtifactV1] {
        &self.artifacts
    }

    pub fn artifact_evidence(&self) -> &[ComponentArtifactAuthenticationEvidenceV1] {
        &self.artifact_evidence
    }

    pub const fn graph_evidence(&self) -> &ComponentGraphVersionAuthenticationEvidenceV1 {
        &self.graph_evidence
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Return values in root-relative logical order: CGV1, ordered CMP1,
    /// ordered CME1, then detached CGE1.
    pub fn into_parts(
        self,
    ) -> (
        ComponentGraphVersionV1,
        Vec<ComponentArtifactV1>,
        Vec<ComponentArtifactAuthenticationEvidenceV1>,
        ComponentGraphVersionAuthenticationEvidenceV1,
    ) {
        (
            self.descriptor,
            self.artifacts,
            self.artifact_evidence,
            self.graph_evidence,
        )
    }
}

impl fmt::Debug for ComponentGraphVersionBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphVersionBundleV1")
            .field("descriptor", &self.descriptor)
            .field("artifact_count", &self.artifacts.len())
            .field("artifact_evidence_count", &self.artifact_evidence.len())
            .field("graph_evidence", &self.graph_evidence)
            .field("runtime_ready", &false)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphVersionError {
    ZeroDigest,
    Allocation,
    TooLarge,
    Truncated,
    Magic,
    Version,
    VersionRelation,
    Header,
    ObjectKind,
    HashAlgorithm,
    Reserved,
    Profile,
    CyclePolicy,
    Length,
    Count,
    Text,
    Limits,
    AttachmentLength,
    NodeOrder,
    EdgeOrder,
    GraphCycle,
    AsyncEdge,
    ExternalImport,
    PublishedExport,
    Replacement,
    ReplacementSurface,
    IncidentEdges,
    Account,
    ManifestHash,
    Commitment,
    NonCanonical,
    AttachmentCount,
    AttachmentMismatch,
    C76Shape,
}

impl fmt::Display for ComponentGraphVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroDigest => "component graph digest is the zero sentinel",
            Self::Allocation => "component graph allocation failed",
            Self::TooLarge => "component graph descriptor exceeds its encoded bound",
            Self::Truncated => "component graph descriptor is truncated",
            Self::Magic => "component graph descriptor magic is invalid",
            Self::Version => "component graph descriptor version is unsupported",
            Self::VersionRelation => "component graph ordinal/predecessor relation is invalid",
            Self::Header => "component graph descriptor header is invalid",
            Self::ObjectKind => "component graph descriptor object kind is invalid",
            Self::HashAlgorithm => "component graph descriptor hash algorithm is unsupported",
            Self::Reserved => "component graph descriptor reserved field is non-zero",
            Self::Profile => "component graph descriptor profile is invalid",
            Self::CyclePolicy => "component graph cycle policy is invalid",
            Self::Length => "component graph descriptor length is invalid",
            Self::Count => "component graph descriptor count exceeds its bound",
            Self::Text => "component graph descriptor text is invalid",
            Self::Limits => "component graph node limits are invalid",
            Self::AttachmentLength => "component graph attachment length is invalid",
            Self::NodeOrder => "component graph nodes are not a canonical ordered set",
            Self::EdgeOrder => "component graph edges are invalid or ambiguous",
            Self::GraphCycle => "component graph violates the acyclic-only policy",
            Self::AsyncEdge => "component graph async edge metadata is invalid",
            Self::ExternalImport => "component graph external import is invalid",
            Self::PublishedExport => "component graph published export is invalid",
            Self::Replacement => "component graph replacement policy is invalid",
            Self::ReplacementSurface => "component graph replacement target is not isolated",
            Self::IncidentEdges => "component graph incident-edge policy is incomplete",
            Self::Account => "component graph aggregate account does not match its manifest",
            Self::ManifestHash => "component graph manifest hash does not match",
            Self::Commitment => "component graph version commitment does not match",
            Self::NonCanonical => "component graph descriptor is not canonical",
            Self::AttachmentCount => "component graph bundle attachment count does not match",
            Self::AttachmentMismatch => "component graph bundle attachment does not match its node",
            Self::C76Shape => "component graph does not match the fixed C7.6 shape",
        };
        formatter.write_str(message)
    }
}

fn copied_graph_name(value: &str) -> Result<String, ComponentGraphVersionError> {
    let copied = copied_text(value, MAX_COMPONENT_GRAPH_VERSION_NAME_BYTES)?;
    if !valid_graph_text(&copied) {
        return Err(ComponentGraphVersionError::Text);
    }
    Ok(copied)
}

fn copied_text(value: &str, maximum: usize) -> Result<String, ComponentGraphVersionError> {
    if value.is_empty() || value.len() > maximum || !valid_graph_text(value) {
        return Err(ComponentGraphVersionError::Text);
    }
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| ComponentGraphVersionError::Allocation)?;
    copied.push_str(value);
    Ok(copied)
}

fn valid_graph_text(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
    })
}

fn valid_world(value: &str) -> bool {
    valid_graph_text(value) && value.contains(':')
}

fn validate_endpoint(
    endpoint: ComponentGraphVersionEndpointV1,
    node_count: usize,
) -> Result<(), ComponentGraphVersionError> {
    if usize::from(endpoint.node) >= node_count {
        Err(ComponentGraphVersionError::EdgeOrder)
    } else {
        Ok(())
    }
}

fn validate_edge(
    edge: ComponentGraphVersionEdgeV1,
    node_count: usize,
) -> Result<(), ComponentGraphVersionError> {
    validate_endpoint(edge.source, node_count)?;
    validate_endpoint(edge.target, node_count)?;
    if edge.source == edge.target {
        return Err(ComponentGraphVersionError::GraphCycle);
    }
    Ok(())
}

fn validate_acyclic(
    edges: &[ComponentGraphVersionEdgeV1],
    node_count: usize,
) -> Result<(), ComponentGraphVersionError> {
    let mut state = [0_u8; PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes as usize];
    for node in 0..node_count {
        visit_node(node, edges, &mut state)?;
    }
    Ok(())
}

fn visit_node(
    node: usize,
    edges: &[ComponentGraphVersionEdgeV1],
    state: &mut [u8; PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes as usize],
) -> Result<(), ComponentGraphVersionError> {
    match state[node] {
        1 => return Err(ComponentGraphVersionError::GraphCycle),
        2 => return Ok(()),
        _ => {}
    }
    state[node] = 1;
    for edge in edges
        .iter()
        .filter(|edge| usize::from(edge.source.node) == node)
    {
        visit_node(usize::from(edge.target.node), edges, state)?;
    }
    state[node] = 2;
    Ok(())
}

fn derive_account(
    nodes: &[ComponentGraphVersionNodeV1],
    edge_count: usize,
    external_count: usize,
    published_count: usize,
) -> Result<ComponentGraphAccount, ComponentGraphVersionError> {
    let mut account = ComponentGraphAccount::default();
    for (index, node) in nodes.iter().enumerate() {
        let depth = match node.nesting {
            // Runtime graph accounting defines the root itself as nesting
            // depth one; descendants add one for every containment edge.
            ComponentGraphVersionNodeNestingV1::Root => 1,
            ComponentGraphVersionNodeNestingV1::Nested { parent } => {
                if usize::from(parent) >= index {
                    return Err(ComponentGraphVersionError::NodeOrder);
                }
                let mut depth = 2_u64;
                let mut cursor = usize::from(parent);
                loop {
                    match nodes[cursor].nesting {
                        ComponentGraphVersionNodeNestingV1::Root => break,
                        ComponentGraphVersionNodeNestingV1::Nested { parent } => {
                            if usize::from(parent) >= cursor {
                                return Err(ComponentGraphVersionError::NodeOrder);
                            }
                            cursor = usize::from(parent);
                            depth = depth
                                .checked_add(1)
                                .ok_or(ComponentGraphVersionError::Account)?;
                        }
                    }
                }
                depth
            }
        };
        account
            .charge_node(node.budget)
            .map_err(|_| ComponentGraphVersionError::Account)?;
        account
            .observe_nesting(depth)
            .map_err(|_| ComponentGraphVersionError::Account)?;
    }
    account
        .charge_edges(usize_u64(edge_count)?)
        .map_err(|_| ComponentGraphVersionError::Account)?;
    account
        .charge_external_imports(usize_u64(external_count)?)
        .map_err(|_| ComponentGraphVersionError::Account)?;
    account
        .charge_published_exports(usize_u64(published_count)?)
        .map_err(|_| ComponentGraphVersionError::Account)?;
    Ok(account)
}

fn encode_account(
    out: &mut Vec<u8>,
    account: ComponentGraphAccount,
) -> Result<(), ComponentGraphVersionError> {
    for value in [
        account.nodes,
        account.edges,
        account.maximum_nesting,
        account.external_imports,
        account.published_exports,
        account.component_bytes,
        account.core_instances,
        account.adapters,
        account.resource_types,
        account.resource_slots,
        account.memory_bytes,
        account.total_fuel,
        account.maximum_poll_quantum,
    ] {
        push_u64(out, value)?;
    }
    Ok(())
}

fn decode_account(
    cursor: &mut Cursor<'_>,
) -> Result<ComponentGraphAccount, ComponentGraphVersionError> {
    let mut fields = [0_u64; ACCOUNT_FIELD_COUNT];
    for field in &mut fields {
        *field = cursor.u64()?;
    }
    Ok(ComponentGraphAccount {
        nodes: fields[0],
        edges: fields[1],
        maximum_nesting: fields[2],
        external_imports: fields[3],
        published_exports: fields[4],
        component_bytes: fields[5],
        core_instances: fields[6],
        adapters: fields[7],
        resource_types: fields[8],
        resource_slots: fields[9],
        memory_bytes: fields[10],
        total_fuel: fields[11],
        maximum_poll_quantum: fields[12],
    })
}

fn encode_node(
    out: &mut Vec<u8>,
    node: &ComponentGraphVersionNodeV1,
) -> Result<(), ComponentGraphVersionError> {
    push_u16(out, node.ordinal)?;
    match node.nesting {
        ComponentGraphVersionNodeNestingV1::Root => {
            push_u16(out, 0)?;
            push_u16(out, 0)?;
        }
        ComponentGraphVersionNodeNestingV1::Nested { parent } => {
            push_u16(out, 1)?;
            push_u16(out, parent)?;
        }
    }
    push_u16(out, 0)?;
    push_u64(out, node.artifact_encoded_len)?;
    push_bytes(out, node.artifact_commitment.as_bytes())?;
    push_bytes(out, node.artifact_evidence_commitment.as_bytes())?;
    push_bytes(out, node.artifact_policy_digest.as_bytes())?;
    push_bytes(out, node.component_identity.as_bytes())?;
    push_bytes(out, node.world_contract_commitment.as_bytes())?;
    for value in [
        node.instance_limits.memory_bytes(),
        node.instance_limits.total_fuel(),
        node.instance_limits.poll_quantum(),
        node.instance_limits.resources(),
        node.budget.component_bytes,
        node.budget.core_instances,
        node.budget.adapters,
        node.budget.resource_types,
        node.budget.resource_slots,
        node.budget.memory_bytes,
        node.budget.total_fuel,
        node.budget.poll_quantum,
    ] {
        push_u64(out, value)?;
    }
    push_u16(out, usize_u16(node.label.len())?)?;
    push_u16(out, usize_u16(node.world.len())?)?;
    push_u32(out, 0)?;
    push_bytes(out, node.label.as_bytes())?;
    push_bytes(out, node.world.as_bytes())?;
    Ok(())
}

fn decode_node(
    cursor: &mut Cursor<'_>,
) -> Result<ComponentGraphVersionNodeV1, ComponentGraphVersionError> {
    cursor.require(NODE_FIXED_LEN)?;
    let ordinal = cursor.u16()?;
    let nesting_raw = cursor.u16()?;
    let parent = cursor.u16()?;
    if cursor.u16()? != 0 {
        return Err(ComponentGraphVersionError::Reserved);
    }
    let nesting = match nesting_raw {
        0 if parent == 0 => ComponentGraphVersionNodeNestingV1::Root,
        1 => ComponentGraphVersionNodeNestingV1::Nested { parent },
        _ => return Err(ComponentGraphVersionError::NodeOrder),
    };
    let artifact_encoded_len = cursor.u64()?;
    let artifact_commitment = ComponentArtifactCommitment::checked(cursor.digest()?)
        .map_err(|_| ComponentGraphVersionError::ZeroDigest)?;
    let artifact_evidence_commitment =
        ComponentArtifactAuthenticationEvidenceCommitment::from_bytes(cursor.digest()?)?;
    let artifact_policy_digest = ComponentArtifactPolicyDigest::checked(cursor.digest()?)
        .map_err(|_| ComponentGraphVersionError::ZeroDigest)?;
    let component_identity = ComponentGraphVersionComponentIdentity::from_bytes(cursor.digest()?)?;
    let world_contract_commitment =
        ComponentGraphVersionWorldContractCommitment::from_bytes(cursor.digest()?)?;
    let instance_limits = ComponentArtifactInstanceLimitsV1::new(
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
        cursor.u64()?,
    )
    .map_err(|_| ComponentGraphVersionError::Limits)?;
    let budget = ComponentGraphNodeBudget {
        component_bytes: cursor.u64()?,
        core_instances: cursor.u64()?,
        adapters: cursor.u64()?,
        resource_types: cursor.u64()?,
        resource_slots: cursor.u64()?,
        memory_bytes: cursor.u64()?,
        total_fuel: cursor.u64()?,
        poll_quantum: cursor.u64()?,
    };
    let label_len = usize::from(cursor.u16()?);
    let world_len = usize::from(cursor.u16()?);
    if cursor.u32()? != 0 {
        return Err(ComponentGraphVersionError::Reserved);
    }
    let label = cursor.text(label_len, MAX_COMPONENT_GRAPH_VERSION_LABEL_BYTES)?;
    let world = cursor.text(world_len, MAX_COMPONENT_GRAPH_VERSION_WORLD_BYTES)?;
    ComponentGraphVersionNodeV1::new(
        ordinal,
        &label,
        &world,
        nesting,
        artifact_encoded_len,
        artifact_commitment,
        artifact_evidence_commitment,
        artifact_policy_digest,
        component_identity,
        world_contract_commitment,
        instance_limits,
        budget,
    )
}

fn encode_endpoint(
    out: &mut Vec<u8>,
    endpoint: ComponentGraphVersionEndpointV1,
) -> Result<(), ComponentGraphVersionError> {
    push_u16(out, endpoint.node)?;
    push_u16(out, endpoint.entity)
}

fn decode_endpoint(
    cursor: &mut Cursor<'_>,
) -> Result<ComponentGraphVersionEndpointV1, ComponentGraphVersionError> {
    cursor.require(ENDPOINT_ENCODED_LEN)?;
    Ok(ComponentGraphVersionEndpointV1::new(
        cursor.u16()?,
        cursor.u16()?,
    ))
}

fn encode_edge(
    out: &mut Vec<u8>,
    edge: ComponentGraphVersionEdgeV1,
) -> Result<(), ComponentGraphVersionError> {
    encode_endpoint(out, edge.source)?;
    encode_endpoint(out, edge.target)
}

fn decode_edge(
    cursor: &mut Cursor<'_>,
) -> Result<ComponentGraphVersionEdgeV1, ComponentGraphVersionError> {
    cursor.require(EDGE_ENCODED_LEN)?;
    Ok(ComponentGraphVersionEdgeV1::new(
        decode_endpoint(cursor)?,
        decode_endpoint(cursor)?,
    ))
}

fn decode_async_edge(
    cursor: &mut Cursor<'_>,
) -> Result<ComponentGraphVersionAsyncEdgeV1, ComponentGraphVersionError> {
    cursor.require(ASYNC_EDGE_ENCODED_LEN)?;
    let edge = decode_edge(cursor)?;
    let async_functions = cursor.u32()?;
    let streams = cursor.u32()?;
    let futures = cursor.u32()?;
    if cursor.u32()? != 0 {
        return Err(ComponentGraphVersionError::Reserved);
    }
    ComponentGraphVersionAsyncEdgeV1::new(edge, async_functions, streams, futures)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn require(&self, length: usize) -> Result<(), ComponentGraphVersionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ComponentGraphVersionError::Length)?;
        if end > self.bytes.len() {
            Err(ComponentGraphVersionError::Truncated)
        } else {
            Ok(())
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ComponentGraphVersionError> {
        self.require(length)?;
        let start = self.offset;
        self.offset += length;
        Ok(&self.bytes[start..self.offset])
    }

    fn u16(&mut self) -> Result<u16, ComponentGraphVersionError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ComponentGraphVersionError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, ComponentGraphVersionError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ComponentGraphVersionError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ComponentGraphVersionError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ComponentGraphVersionError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], ComponentGraphVersionError> {
        self.take(32)?
            .try_into()
            .map_err(|_| ComponentGraphVersionError::Truncated)
    }

    fn text(
        &mut self,
        length: usize,
        maximum: usize,
    ) -> Result<String, ComponentGraphVersionError> {
        if length == 0 || length > maximum {
            return Err(ComponentGraphVersionError::Text);
        }
        let value = core::str::from_utf8(self.take(length)?)
            .map_err(|_| ComponentGraphVersionError::Text)?;
        copied_text(value, maximum)
    }

    fn text_u16(&mut self, maximum: usize) -> Result<String, ComponentGraphVersionError> {
        let length = usize::from(self.u16()?);
        self.text(length, maximum)
    }

    fn finish(self) -> Result<(), ComponentGraphVersionError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ComponentGraphVersionError::Length)
        }
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ComponentGraphVersionError> {
    out.try_reserve(bytes.len())
        .map_err(|_| ComponentGraphVersionError::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_u16(out: &mut Vec<u8>, value: u16) -> Result<(), ComponentGraphVersionError> {
    push_bytes(out, &value.to_le_bytes())
}

fn push_u32(out: &mut Vec<u8>, value: u32) -> Result<(), ComponentGraphVersionError> {
    push_bytes(out, &value.to_le_bytes())
}

fn push_u64(out: &mut Vec<u8>, value: u64) -> Result<(), ComponentGraphVersionError> {
    push_bytes(out, &value.to_le_bytes())
}

fn push_text_u16(out: &mut Vec<u8>, value: &str) -> Result<(), ComponentGraphVersionError> {
    push_u16(out, usize_u16(value.len())?)?;
    push_bytes(out, value.as_bytes())
}

fn zeroed(length: usize) -> Result<Vec<u8>, ComponentGraphVersionError> {
    let mut out = Vec::new();
    out.try_reserve_exact(length)
        .map_err(|_| ComponentGraphVersionError::Allocation)?;
    out.resize(length, 0);
    Ok(out)
}

fn reserved_vec<T>(length: usize) -> Result<Vec<T>, ComponentGraphVersionError> {
    let mut out = Vec::new();
    out.try_reserve_exact(length)
        .map_err(|_| ComponentGraphVersionError::Allocation)?;
    Ok(out)
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) -> Result<(), ComponentGraphVersionError> {
    put_bytes(out, offset, &value.to_le_bytes())
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) -> Result<(), ComponentGraphVersionError> {
    put_bytes(out, offset, &value.to_le_bytes())
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) -> Result<(), ComponentGraphVersionError> {
    put_bytes(out, offset, &value.to_le_bytes())
}

fn put_bytes(
    out: &mut [u8],
    offset: usize,
    value: &[u8],
) -> Result<(), ComponentGraphVersionError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(ComponentGraphVersionError::Length)?;
    out.get_mut(offset..end)
        .ok_or(ComponentGraphVersionError::Length)?
        .copy_from_slice(value);
    Ok(())
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, ComponentGraphVersionError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(ComponentGraphVersionError::Truncated)?
            .try_into()
            .map_err(|_| ComponentGraphVersionError::Truncated)?,
    ))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, ComponentGraphVersionError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(ComponentGraphVersionError::Truncated)?
            .try_into()
            .map_err(|_| ComponentGraphVersionError::Truncated)?,
    ))
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, ComponentGraphVersionError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(ComponentGraphVersionError::Truncated)?
            .try_into()
            .map_err(|_| ComponentGraphVersionError::Truncated)?,
    ))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<[u8; 32], ComponentGraphVersionError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(ComponentGraphVersionError::Truncated)?
        .try_into()
        .map_err(|_| ComponentGraphVersionError::Truncated)
}

fn usize_u16(value: usize) -> Result<u16, ComponentGraphVersionError> {
    u16::try_from(value).map_err(|_| ComponentGraphVersionError::Length)
}

fn usize_u64(value: usize) -> Result<u64, ComponentGraphVersionError> {
    u64::try_from(value).map_err(|_| ComponentGraphVersionError::Length)
}

fn u64_usize(value: u64) -> Result<usize, ComponentGraphVersionError> {
    usize::try_from(value).map_err(|_| ComponentGraphVersionError::Length)
}

fn hash_framed(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_version_commitment(bytes: &[u8]) -> Result<[u8; 32], ComponentGraphVersionError> {
    if bytes.len() < COMPONENT_GRAPH_VERSION_HEADER_LEN {
        return Err(ComponentGraphVersionError::Truncated);
    }
    let suffix_offset = VERSION_COMMITMENT_OFFSET
        .checked_add(32)
        .ok_or(ComponentGraphVersionError::Length)?;
    let prefix = bytes
        .get(..VERSION_COMMITMENT_OFFSET)
        .ok_or(ComponentGraphVersionError::Truncated)?;
    let suffix = bytes
        .get(suffix_offset..)
        .ok_or(ComponentGraphVersionError::Truncated)?;
    let mut hasher = Sha256::new();
    hasher.update(VERSION_COMMITMENT_DOMAIN);
    hasher.update(usize_u64(bytes.len())?.to_le_bytes());
    hasher.update(prefix);
    hasher.update([0_u8; 32]);
    hasher.update(suffix);
    Ok(hasher.finalize().into())
}
