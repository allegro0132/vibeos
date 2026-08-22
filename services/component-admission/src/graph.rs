//! Atomic, capability-free admission for a complete typed Component graph.
//!
//! A successful value owns only immutable artifacts and inert policy metadata.
//! It never stores a borrowed runtime graph, a live capability, or an
//! executable entry point.

use alloc::{string::String, vec::Vec};
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_component_format::{
    ComponentGraphAccount, ComponentGraphInstanceBudget, ComponentGraphNodeBudget,
    PROFILE_1_COMPONENT_GRAPH_LIMITS, PROFILE_1_LIMITS,
};
use vibeos_component_host::{HostManifestError, HostResourceKind, VibeHostManifest};
use vibeos_component_runtime::{
    graph::{
        plan_component_graph, ComponentGraph, ComponentGraphEdgeSpec, ComponentGraphExportEndpoint,
        ComponentGraphExternalImportSpec, ComponentGraphImportEndpoint, ComponentGraphNesting,
        ComponentGraphNodeId, ComponentGraphNodeSpec, ComponentGraphPublishedExportSpec,
        ComponentGraphResourceProvenance, ComponentGraphResourceStatus,
    },
    world::{
        EntityShape, FunctionShape, NamedCaseShape, NamedEntityShape, NamedValueShape, TypeShape,
        ValueShape, WorldContract,
    },
};
use vibeos_core::cap::Rights;

use crate::{
    private, AdmissionError, ArtifactTrust, AuthorityOffer, CallerAuthority, ComponentArtifact,
    ComponentIdentity, InspectedComponent, InspectionSummary, InstanceLimits, InterfaceCeiling,
    ProfileIdentity,
};

/// The only dependency-cycle policy admitted by C6.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphCyclePolicy {
    AcyclicOnly,
}

/// Trusted policy for one independently admitted graph principal.
#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphNodeAdmissionPolicy<'a> {
    pub label: &'a str,
    pub nesting: ComponentGraphNesting,
    pub exact_world: &'a WorldContract,
    pub trust: ArtifactTrust,
    pub limits: InstanceLimits,
    pub interfaces: &'a [InterfaceCeiling<'a>],
}

/// Trusted topology and policy for one all-or-nothing graph admission.
#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphAdmissionPolicy<'a> {
    pub name: &'a str,
    pub profile: ProfileIdentity,
    pub nodes: &'a [ComponentGraphNodeAdmissionPolicy<'a>],
    pub edges: &'a [ComponentGraphEdgeSpec],
    pub external_imports: &'a [ComponentGraphExternalImportSpec],
    pub published_exports: &'a [ComponentGraphPublishedExportSpec],
    pub cycle_policy: ComponentGraphCyclePolicy,
}

/// Exact ownership modes authorized for one immutable internal resource edge.
///
/// This is inert admission metadata. It is not a capability, does not grant
/// kernel authority, and cannot make an admitted graph executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphResourceMode {
    Borrow,
    Own,
    OwnAndBorrow,
}

/// Trusted authorization for the exact pair of graph endpoints in `edge`.
///
/// The mode must equal, rather than merely contain, the ownership modes found
/// in the validator-proven interface. One policy therefore cannot reserve
/// dormant authority for a future or different interface shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphResourceEdgePolicy {
    pub edge: ComponentGraphEdgeSpec,
    pub mode: ComponentGraphResourceMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphBindingMismatch {
    InterfaceVersion,
    EntityKind,
    Type,
    Effect,
    Ownership,
    ResourceIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphAdmissionError {
    Graph(vibeos_component_runtime::graph::ComponentGraphError),
    InvalidPolicy,
    Node {
        node: ComponentGraphNodeId,
        error: AdmissionError,
    },
    MissingBinding {
        target: ComponentGraphImportEndpoint,
    },
    DuplicateBinding {
        target: ComponentGraphImportEndpoint,
    },
    DuplicateResourceBinding {
        target: ComponentGraphImportEndpoint,
    },
    DuplicateResourceSource {
        source: ComponentGraphExportEndpoint,
    },
    DuplicatePublishedExport {
        source: ComponentGraphExportEndpoint,
    },
    UnsupportedBindingSurface {
        edge: u16,
    },
    UnsupportedResourceBinding {
        edge: u16,
    },
    UnauthorizedResourceBinding {
        edge: u16,
    },
    BindingMismatch {
        edge: u16,
        kind: ComponentGraphBindingMismatch,
    },
    DependencyCycle {
        node: ComponentGraphNodeId,
    },
    ExternalHostManifest {
        node: ComponentGraphNodeId,
        error: HostManifestError,
    },
    MissingImageCeiling {
        target: ComponentGraphImportEndpoint,
    },
    MissingCallerAuthority {
        target: ComponentGraphImportEndpoint,
    },
    AuthorityAmplification {
        target: ComponentGraphImportEndpoint,
    },
    DuplicateAuthoritySource {
        target: ComponentGraphImportEndpoint,
    },
    Allocation,
    RevalidationMismatch,
}

impl From<vibeos_component_runtime::graph::ComponentGraphError> for ComponentGraphAdmissionError {
    fn from(error: vibeos_component_runtime::graph::ComponentGraphError) -> Self {
        Self::Graph(error)
    }
}

impl fmt::Display for ComponentGraphAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Graph(_) => "component graph structure or aggregate budget is invalid",
            Self::InvalidPolicy => "component graph policy is ambiguous or invalid",
            Self::Node { .. } => "component graph node admission failed",
            Self::MissingBinding { .. } => "component graph import has no binding",
            Self::DuplicateBinding { .. } => "component graph import has multiple bindings",
            Self::DuplicateResourceBinding { .. } => {
                "component graph resource import has multiple bindings"
            }
            Self::DuplicateResourceSource { .. } => {
                "component graph resource export has multiple consumers"
            }
            Self::DuplicatePublishedExport { .. } => {
                "component graph export is published more than once"
            }
            Self::UnsupportedBindingSurface { .. } => {
                "component graph edge is not a versioned interface binding"
            }
            Self::UnsupportedResourceBinding { .. } => {
                "component graph resource edge lacks nominal provenance"
            }
            Self::UnauthorizedResourceBinding { .. } => {
                "component graph resource edge lacks exact trusted policy"
            }
            Self::BindingMismatch { .. } => "component graph edge types do not match exactly",
            Self::DependencyCycle { .. } => "component graph dependency cycle is forbidden",
            Self::ExternalHostManifest { .. } => {
                "component graph external import manifest is invalid"
            }
            Self::MissingImageCeiling { .. } => {
                "component graph external import has no image-policy ceiling"
            }
            Self::MissingCallerAuthority { .. } => {
                "component graph external import has no caller authority"
            }
            Self::AuthorityAmplification { .. } => {
                "component graph admission would amplify authority"
            }
            Self::DuplicateAuthoritySource { .. } => {
                "component graph reuses one authority source implicitly"
            }
            Self::Allocation => "component graph admission allocation failed",
            Self::RevalidationMismatch => {
                "component graph revalidation differs from its admitted manifest"
            }
        })
    }
}

/// Owned immutable metadata for one admitted graph principal.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentGraphNodeManifest {
    id: ComponentGraphNodeId,
    label: String,
    artifact: ComponentIdentity,
    profile: ProfileIdentity,
    world: String,
    world_contract: WorldContractCommitment,
    nesting: ComponentGraphNesting,
    limits: InstanceLimits,
    budget: ComponentGraphNodeBudget,
    interfaces: Vec<ComponentGraphInterfaceCeiling>,
}

impl ComponentGraphNodeManifest {
    pub const fn id(&self) -> ComponentGraphNodeId {
        self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn artifact(&self) -> ComponentIdentity {
        self.artifact
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub const fn nesting(&self) -> ComponentGraphNesting {
        self.nesting
    }

    pub const fn limits(&self) -> InstanceLimits {
        self.limits
    }

    pub const fn budget(&self) -> ComponentGraphNodeBudget {
        self.budget
    }

    pub fn interfaces(&self) -> &[ComponentGraphInterfaceCeiling] {
        &self.interfaces
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct WorldContractCommitment([u8; 32]);

impl fmt::Debug for WorldContractCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorldContractCommitment(<redacted>)")
    }
}

/// Owned image-policy ceiling retained so inert revalidation can prove the
/// semantic grant route selected at admission. It is policy metadata, not a
/// capability or a live delegation.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentGraphInterfaceCeiling {
    label: String,
    interface: String,
    kind: HostResourceKind,
    rights: Rights,
}

impl ComponentGraphInterfaceCeiling {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub const fn kind(&self) -> HostResourceKind {
        self.kind
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

/// Capability-free evidence and authorization retained for one resource edge.
///
/// Resource names are direct interface declaration names derived from fresh
/// validator evidence and stored in canonical order. They are never runtime
/// handles, validator-local IDs, or authority lookup keys.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentGraphResourceEdgeManifest {
    edge: ComponentGraphEdgeSpec,
    mode: ComponentGraphResourceMode,
    resources: Vec<String>,
}

impl ComponentGraphResourceEdgeManifest {
    pub const fn edge(&self) -> ComponentGraphEdgeSpec {
        self.edge
    }

    pub const fn mode(&self) -> ComponentGraphResourceMode {
        self.mode
    }

    pub fn resources(&self) -> &[String] {
        &self.resources
    }
}

/// Capability-free graph manifest. Endpoint values are graph-local ordinals,
/// never runtime handles or authority tokens.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentGraphManifest {
    name: String,
    profile: ProfileIdentity,
    cycle_policy: ComponentGraphCyclePolicy,
    account: ComponentGraphAccount,
    nodes: Vec<ComponentGraphNodeManifest>,
    edges: Vec<ComponentGraphEdgeSpec>,
    resource_edges: Vec<ComponentGraphResourceEdgeManifest>,
    external_imports: Vec<ComponentGraphExternalImportSpec>,
    published_exports: Vec<ComponentGraphPublishedExportSpec>,
}

impl ComponentGraphManifest {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn cycle_policy(&self) -> ComponentGraphCyclePolicy {
        self.cycle_policy
    }

    pub const fn account(&self) -> ComponentGraphAccount {
        self.account
    }

    pub fn nodes(&self) -> &[ComponentGraphNodeManifest] {
        &self.nodes
    }

    pub fn edges(&self) -> &[ComponentGraphEdgeSpec] {
        &self.edges
    }

    pub fn resource_edges(&self) -> &[ComponentGraphResourceEdgeManifest] {
        &self.resource_edges
    }

    pub fn external_imports(&self) -> &[ComponentGraphExternalImportSpec] {
        &self.external_imports
    }

    pub fn published_exports(&self) -> &[ComponentGraphPublishedExportSpec] {
        &self.published_exports
    }
}

/// One exact semantic authority route selected during atomic graph admission.
/// A future lifecycle must resolve `source_label` again and recheck live
/// delegation authority; this value deliberately stores no offer ordinal.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentGraphAuthorityGrant {
    target: ComponentGraphImportEndpoint,
    source_label: String,
    interface: &'static str,
    resource: &'static str,
    kind: HostResourceKind,
    rights: Rights,
}

impl ComponentGraphAuthorityGrant {
    pub const fn target(&self) -> ComponentGraphImportEndpoint {
        self.target
    }

    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    pub const fn interface(&self) -> &'static str {
        self.interface
    }

    pub const fn resource(&self) -> &'static str {
        self.resource
    }

    pub const fn kind(&self) -> HostResourceKind {
        self.kind
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

/// Sealed result of complete graph admission.
///
/// It has no `run`, `instantiate`, `plan`, or conversion into an executable
/// single-component admission result.
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedComponentGraph;
/// fn run(graph: &AdmittedComponentGraph) { graph.run(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedComponentGraph;
/// fn plan(graph: &AdmittedComponentGraph) { let _ = graph.plan(); }
/// ```
pub struct AdmittedComponentGraph {
    artifacts: Vec<ComponentArtifact>,
    inspections: Vec<InspectionSummary>,
    manifest: ComponentGraphManifest,
    grants: Vec<ComponentGraphAuthorityGrant>,
    _sealed: private::Seal,
}

impl AdmittedComponentGraph {
    pub fn manifest(&self) -> &ComponentGraphManifest {
        &self.manifest
    }

    pub fn node_inspections(&self) -> &[InspectionSummary] {
        &self.inspections
    }

    pub fn grants(&self) -> &[ComponentGraphAuthorityGrant] {
        &self.grants
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Re-decode every immutable artifact and reconstruct the complete inert
    /// graph before accepting the stored manifest again.
    pub fn revalidate(&self) -> Result<(), ComponentGraphAdmissionError> {
        revalidate_component_graph(self)
    }
}

fn node_id(index: usize) -> Result<ComponentGraphNodeId, ComponentGraphAdmissionError> {
    u16::try_from(index)
        .map(ComponentGraphNodeId::new)
        .map_err(|_| ComponentGraphAdmissionError::InvalidPolicy)
}

fn edge_index(index: usize) -> Result<u16, ComponentGraphAdmissionError> {
    u16::try_from(index).map_err(|_| ComponentGraphAdmissionError::InvalidPolicy)
}

fn instance_budget(limits: InstanceLimits) -> ComponentGraphInstanceBudget {
    ComponentGraphInstanceBudget {
        resource_slots: u64::from(limits.resources),
        memory_bytes: u64::try_from(limits.memory_bytes).unwrap_or(u64::MAX),
        total_fuel: limits.total_fuel,
        poll_quantum: limits.poll_quantum,
    }
}

fn copied(value: &str) -> Result<String, ComponentGraphAdmissionError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn hash_length(hasher: &mut Sha256, length: usize) {
    hasher.update(u64::try_from(length).unwrap_or(u64::MAX).to_le_bytes());
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_length(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_named_values(hasher: &mut Sha256, values: &[NamedValueShape]) {
    hash_length(hasher, values.len());
    for value in values {
        hash_text(hasher, &value.name);
        hash_value(hasher, &value.value);
    }
}

fn hash_optional_value(hasher: &mut Sha256, value: Option<&ValueShape>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_value(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_value(hasher: &mut Sha256, value: &ValueShape) {
    use ValueShape::*;
    match value {
        Bool => hasher.update([0]),
        U8 => hasher.update([1]),
        U16 => hasher.update([2]),
        U32 => hasher.update([3]),
        U64 => hasher.update([4]),
        S8 => hasher.update([5]),
        S16 => hasher.update([6]),
        S32 => hasher.update([7]),
        S64 => hasher.update([8]),
        Char => hasher.update([9]),
        String => hasher.update([10]),
        List(value) => {
            hasher.update([11]);
            hash_value(hasher, value);
        }
        Tuple(values) => {
            hasher.update([12]);
            hash_length(hasher, values.len());
            for value in values {
                hash_value(hasher, value);
            }
        }
        Record(values) => {
            hasher.update([13]);
            hash_named_values(hasher, values);
        }
        Flags(names) => {
            hasher.update([14]);
            hash_length(hasher, names.len());
            for name in names {
                hash_text(hasher, name);
            }
        }
        Enum(names) => {
            hasher.update([15]);
            hash_length(hasher, names.len());
            for name in names {
                hash_text(hasher, name);
            }
        }
        Option(value) => {
            hasher.update([16]);
            hash_value(hasher, value);
        }
        Result { ok, error } => {
            hasher.update([17]);
            hash_optional_value(hasher, ok.as_deref());
            hash_optional_value(hasher, error.as_deref());
        }
        Variant(cases) => {
            hasher.update([18]);
            hash_length(hasher, cases.len());
            for case in cases {
                hash_text(hasher, &case.name);
                hash_optional_value(hasher, case.value.as_ref());
            }
        }
        Future(value) => {
            hasher.update([19]);
            hash_optional_value(hasher, value.as_deref());
        }
        Stream(value) => {
            hasher.update([20]);
            hash_optional_value(hasher, value.as_deref());
        }
        Own(resource) => {
            hasher.update([21]);
            hash_text(hasher, resource);
        }
        Borrow(resource) => {
            hasher.update([22]);
            hash_text(hasher, resource);
        }
    }
}

fn hash_entity(hasher: &mut Sha256, entity: &EntityShape) {
    match entity {
        EntityShape::Function(function) => {
            hasher.update([0]);
            hasher.update([match function.effect {
                vibeos_component_runtime::world::FunctionEffect::Sync => 0,
                vibeos_component_runtime::world::FunctionEffect::Async => 1,
            }]);
            hash_named_values(hasher, &function.parameters);
            hash_optional_value(hasher, function.result.as_ref());
        }
        EntityShape::Interface(members) => {
            hasher.update([1]);
            hash_entities(hasher, members);
        }
        EntityShape::Type(TypeShape::Resource) => hasher.update([2]),
        EntityShape::Type(TypeShape::Value(value)) => {
            hasher.update([3]);
            hash_value(hasher, value);
        }
    }
}

fn hash_entities(hasher: &mut Sha256, entities: &[NamedEntityShape]) {
    hash_length(hasher, entities.len());
    for entity in entities {
        hash_text(hasher, &entity.name);
        hash_entity(hasher, &entity.entity);
    }
}

fn hash_top_level_entities(hasher: &mut Sha256, entities: &[NamedEntityShape]) {
    hash_length(hasher, entities.len());
    let mut previous: Option<&str> = None;
    for _ in 0..entities.len() {
        let next = entities
            .iter()
            .filter(|entity| previous.is_none_or(|previous| entity.name.as_str() > previous))
            .min_by(|left, right| left.name.cmp(&right.name));
        let Some(entity) = next else {
            // Policy validation and the Component validator both reject
            // duplicate top-level names. Keep this total even if corrupted
            // in-memory metadata reaches the commitment helper.
            hasher.update([0xff]);
            return;
        };
        hash_text(hasher, &entity.name);
        hash_entity(hasher, &entity.entity);
        previous = Some(&entity.name);
    }
}

fn unique_top_level_names(entities: &[NamedEntityShape]) -> bool {
    entities.iter().enumerate().all(|(index, entity)| {
        !entities[..index]
            .iter()
            .any(|earlier| earlier.name == entity.name)
    })
}

fn world_contract_commitment_parts(
    identity: &str,
    imports: &[NamedEntityShape],
    exports: &[NamedEntityShape],
) -> WorldContractCommitment {
    let mut hasher = Sha256::new();
    hasher.update(b"vibeos.component-graph.world-contract.v1\0");
    hash_text(&mut hasher, identity);
    hasher.update([0]);
    hash_top_level_entities(&mut hasher, imports);
    hasher.update([1]);
    hash_top_level_entities(&mut hasher, exports);
    WorldContractCommitment(hasher.finalize().into())
}

fn world_contract_commitment(world: &WorldContract) -> WorldContractCommitment {
    world_contract_commitment_parts(&world.identity, &world.imports, &world.exports)
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_graph_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
}

fn valid_world_identity(value: &str) -> bool {
    valid_text(value, 256)
        && value.contains(':')
        && value.contains('/')
        && value
            .rsplit_once('@')
            .is_some_and(|(name, version)| !name.is_empty() && !version.is_empty())
}

fn valid_versioned_interface(value: &str) -> bool {
    valid_world_identity(value)
}

const fn operation_rights(kind: HostResourceKind) -> Rights {
    match kind {
        HostResourceKind::Clock | HostResourceKind::Random | HostResourceKind::Blob => Rights::READ,
        HostResourceKind::StructuredLog => Rights::WRITE,
        HostResourceKind::ByteStreamReader => Rights::RECV,
        HostResourceKind::ByteStreamWriter => Rights::SEND,
    }
}

fn validate_node_ceilings(
    ceilings: &[InterfaceCeiling<'_>],
) -> Result<(), ComponentGraphAdmissionError> {
    if ceilings.len() > PROFILE_1_LIMITS.max_imports as usize {
        return Err(ComponentGraphAdmissionError::InvalidPolicy);
    }
    for (index, ceiling) in ceilings.iter().enumerate() {
        if !valid_text(ceiling.label, 128)
            || !valid_versioned_interface(ceiling.interface)
            || !operation_rights(ceiling.kind).contains(ceiling.rights)
            || ceilings[..index].iter().any(|earlier| {
                earlier.interface == ceiling.interface && earlier.kind == ceiling.kind
            })
        {
            return Err(ComponentGraphAdmissionError::InvalidPolicy);
        }
    }
    Ok(())
}

fn copy_ceilings(
    ceilings: &[InterfaceCeiling<'_>],
) -> Result<Vec<ComponentGraphInterfaceCeiling>, ComponentGraphAdmissionError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(ceilings.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for ceiling in ceilings {
        owned.push(ComponentGraphInterfaceCeiling {
            label: copied(ceiling.label)?,
            interface: copied(ceiling.interface)?,
            kind: ceiling.kind,
            rights: ceiling.rights,
        });
    }
    Ok(owned)
}

fn validate_owned_ceilings(
    ceilings: &[ComponentGraphInterfaceCeiling],
) -> Result<(), ComponentGraphAdmissionError> {
    if ceilings.len() > PROFILE_1_LIMITS.max_imports as usize {
        return Err(ComponentGraphAdmissionError::RevalidationMismatch);
    }
    for (index, ceiling) in ceilings.iter().enumerate() {
        if !valid_text(&ceiling.label, 128)
            || !valid_versioned_interface(&ceiling.interface)
            || !operation_rights(ceiling.kind).contains(ceiling.rights)
            || ceilings[..index].iter().any(|earlier| {
                earlier.interface == ceiling.interface && earlier.kind == ceiling.kind
            })
        {
            return Err(ComponentGraphAdmissionError::RevalidationMismatch);
        }
    }
    Ok(())
}

fn validate_offers(offers: &[AuthorityOffer<'_>]) -> Result<(), ComponentGraphAdmissionError> {
    if offers.len() > PROFILE_1_LIMITS.max_imports as usize {
        return Err(ComponentGraphAdmissionError::InvalidPolicy);
    }
    for (index, offer) in offers.iter().enumerate() {
        if !valid_text(offer.label, 128)
            || !operation_rights(offer.kind).contains(offer.grantable)
            || offers[..index]
                .iter()
                .any(|earlier| earlier.label == offer.label && earlier.kind == offer.kind)
        {
            return Err(ComponentGraphAdmissionError::InvalidPolicy);
        }
    }
    Ok(())
}

fn validate_policy(
    artifacts: &[ComponentArtifact],
    policy: &ComponentGraphAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<(), ComponentGraphAdmissionError> {
    if !valid_graph_name(policy.name)
        || artifacts.is_empty()
        || artifacts.len() != policy.nodes.len()
        || artifacts.len() > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes as usize
        || (policy.profile != ProfileIdentity::PROFILE_1
            && policy.profile != ProfileIdentity::PROFILE_1_ASYNC)
        || policy.cycle_policy != ComponentGraphCyclePolicy::AcyclicOnly
    {
        return Err(ComponentGraphAdmissionError::InvalidPolicy);
    }
    validate_offers(caller.offers)?;
    for (index, node) in policy.nodes.iter().enumerate() {
        let id = node_id(index)?;
        if !valid_text(node.label, 128)
            || !valid_world_identity(&node.exact_world.identity)
            || !unique_top_level_names(&node.exact_world.imports)
            || !unique_top_level_names(&node.exact_world.exports)
            || policy.nodes[..index]
                .iter()
                .any(|earlier| earlier.label == node.label)
        {
            return Err(ComponentGraphAdmissionError::InvalidPolicy);
        }
        node.limits
            .validate()
            .map_err(|error| ComponentGraphAdmissionError::Node { node: id, error })?;
        validate_node_ceilings(node.interfaces)?;
        if artifacts[index].profile() != policy.profile {
            return Err(ComponentGraphAdmissionError::Node {
                node: id,
                error: AdmissionError::BadProfile,
            });
        }
        if node.trust != ArtifactTrust::ImagePinned(artifacts[index].identity()) {
            return Err(ComponentGraphAdmissionError::Node {
                node: id,
                error: AdmissionError::UntrustedArtifact,
            });
        }
    }
    Ok(())
}

fn contains_resource_entity(entity: &EntityShape) -> bool {
    match entity {
        EntityShape::Function(function) => contains_resource_function(function),
        EntityShape::Interface(members) => members
            .iter()
            .any(|member| contains_resource_entity(&member.entity)),
        EntityShape::Type(TypeShape::Resource) => true,
        EntityShape::Type(TypeShape::Value(value)) => contains_resource_value(value),
    }
}

fn contains_resource_function(function: &FunctionShape) -> bool {
    function
        .parameters
        .iter()
        .any(|parameter| contains_resource_value(&parameter.value))
        || function
            .result
            .as_ref()
            .is_some_and(contains_resource_value)
}

fn contains_resource_value(value: &ValueShape) -> bool {
    match value {
        ValueShape::Own(_) | ValueShape::Borrow(_) => true,
        ValueShape::List(value) | ValueShape::Option(value) => contains_resource_value(value),
        ValueShape::Tuple(values) => values.iter().any(contains_resource_value),
        ValueShape::Record(values) => values
            .iter()
            .any(|value| contains_resource_value(&value.value)),
        ValueShape::Result { ok, error } => {
            ok.as_deref().is_some_and(contains_resource_value)
                || error.as_deref().is_some_and(contains_resource_value)
        }
        ValueShape::Variant(cases) => cases
            .iter()
            .any(|case| case.value.as_ref().is_some_and(contains_resource_value)),
        ValueShape::Future(value) | ValueShape::Stream(value) => {
            value.as_deref().is_some_and(contains_resource_value)
        }
        ValueShape::Bool
        | ValueShape::U8
        | ValueShape::U16
        | ValueShape::U32
        | ValueShape::U64
        | ValueShape::S8
        | ValueShape::S16
        | ValueShape::S32
        | ValueShape::S64
        | ValueShape::Char
        | ValueShape::String
        | ValueShape::Flags(_)
        | ValueShape::Enum(_) => false,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ResourceModeSet {
    own: bool,
    borrow: bool,
}

impl ResourceModeSet {
    fn include(&mut self, other: Self) {
        self.own |= other.own;
        self.borrow |= other.borrow;
    }

    const fn exact_mode(self) -> Option<ComponentGraphResourceMode> {
        match (self.own, self.borrow) {
            (false, false) => None,
            (false, true) => Some(ComponentGraphResourceMode::Borrow),
            (true, false) => Some(ComponentGraphResourceMode::Own),
            (true, true) => Some(ComponentGraphResourceMode::OwnAndBorrow),
        }
    }
}

fn declared_resource(resources: &[String], name: &str) -> bool {
    resources.iter().any(|resource| resource == name)
}

fn collect_value_resource_modes(
    value: &ValueShape,
    resources: &[String],
) -> Option<ResourceModeSet> {
    use ValueShape::*;
    let mut modes = ResourceModeSet::default();
    match value {
        Own(resource) => {
            if !declared_resource(resources, resource) {
                return None;
            }
            modes.own = true;
        }
        Borrow(resource) => {
            if !declared_resource(resources, resource) {
                return None;
            }
            modes.borrow = true;
        }
        List(value) | Option(value) => {
            modes.include(collect_value_resource_modes(value, resources)?);
        }
        Tuple(values) => {
            for value in values {
                modes.include(collect_value_resource_modes(value, resources)?);
            }
        }
        Record(values) => {
            for value in values {
                modes.include(collect_value_resource_modes(&value.value, resources)?);
            }
        }
        Result { ok, error } => {
            if let Some(value) = ok {
                modes.include(collect_value_resource_modes(value, resources)?);
            }
            if let Some(value) = error {
                modes.include(collect_value_resource_modes(value, resources)?);
            }
        }
        Variant(cases) => {
            for case in cases {
                if let Some(value) = &case.value {
                    modes.include(collect_value_resource_modes(value, resources)?);
                }
            }
        }
        Future(value) | Stream(value) => {
            if let Some(value) = value {
                modes.include(collect_value_resource_modes(value, resources)?);
            }
        }
        Bool | U8 | U16 | U32 | U64 | S8 | S16 | S32 | S64 | Char | String | Flags(_) | Enum(_) => {
        }
    }
    Some(modes)
}

fn collect_entity_resource_modes(
    entity: &EntityShape,
    resources: &[String],
) -> Option<ResourceModeSet> {
    let mut modes = ResourceModeSet::default();
    match entity {
        EntityShape::Function(function) => {
            for parameter in &function.parameters {
                modes.include(collect_value_resource_modes(&parameter.value, resources)?);
            }
            if let Some(result) = &function.result {
                modes.include(collect_value_resource_modes(result, resources)?);
            }
        }
        EntityShape::Interface(members) => {
            for member in members {
                modes.include(collect_entity_resource_modes(&member.entity, resources)?);
            }
        }
        // Exact graph provenance permits resource declarations only as direct
        // members of the bound top-level interface. A nested declaration is
        // therefore an internal inconsistency and fails closed.
        EntityShape::Type(TypeShape::Resource) => return None,
        EntityShape::Type(TypeShape::Value(value)) => {
            modes.include(collect_value_resource_modes(value, resources)?);
        }
    }
    Some(modes)
}

fn collect_interface_resource_mode(
    members: &[NamedEntityShape],
    resources: &[String],
) -> Option<ComponentGraphResourceMode> {
    let mut modes = ResourceModeSet::default();
    for member in members {
        if declared_resource(resources, &member.name) {
            if !matches!(member.entity, EntityShape::Type(TypeShape::Resource)) {
                return None;
            }
            continue;
        }
        modes.include(collect_entity_resource_modes(&member.entity, resources)?);
    }
    modes.exact_mode()
}

fn exact_resource_names(
    members: &[NamedEntityShape],
    evidence: &vibeos_component_runtime::graph::ComponentGraphEntityResourceProvenance,
    edge: u16,
) -> Result<Vec<String>, ComponentGraphAdmissionError> {
    if evidence.status() != ComponentGraphResourceStatus::ExactInterface
        || evidence.declarations().is_empty()
    {
        return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding { edge });
    }
    let mut resources = Vec::new();
    resources
        .try_reserve_exact(evidence.declarations().len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for declaration in evidence.declarations() {
        let Some(member) = members.get(usize::from(declaration.member().index())) else {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding { edge });
        };
        if !matches!(member.entity, EntityShape::Type(TypeShape::Resource)) {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding { edge });
        }
        resources.push(copied(&member.name)?);
    }
    resources.sort_unstable();
    if resources.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding { edge });
    }
    Ok(resources)
}

fn compare_named_values(
    left: &[NamedValueShape],
    right: &[NamedValueShape],
) -> Option<ComponentGraphBindingMismatch> {
    if left.len() != right.len() {
        return Some(ComponentGraphBindingMismatch::Type);
    }
    for (left, right) in left.iter().zip(right) {
        if left.name != right.name {
            return Some(ComponentGraphBindingMismatch::Type);
        }
        if let Some(mismatch) = compare_values(&left.value, &right.value) {
            return Some(mismatch);
        }
    }
    None
}

fn compare_cases(
    left: &[NamedCaseShape],
    right: &[NamedCaseShape],
) -> Option<ComponentGraphBindingMismatch> {
    if left.len() != right.len() {
        return Some(ComponentGraphBindingMismatch::Type);
    }
    for (left, right) in left.iter().zip(right) {
        if left.name != right.name {
            return Some(ComponentGraphBindingMismatch::Type);
        }
        match (&left.value, &right.value) {
            (Some(left), Some(right)) => {
                if let Some(mismatch) = compare_values(left, right) {
                    return Some(mismatch);
                }
            }
            (None, None) => {}
            _ => return Some(ComponentGraphBindingMismatch::Type),
        }
    }
    None
}

fn compare_values(left: &ValueShape, right: &ValueShape) -> Option<ComponentGraphBindingMismatch> {
    use ValueShape::*;
    match (left, right) {
        (Own(left), Own(right)) | (Borrow(left), Borrow(right)) => {
            (left != right).then_some(ComponentGraphBindingMismatch::ResourceIdentity)
        }
        (Own(_), Borrow(_)) | (Borrow(_), Own(_)) => Some(ComponentGraphBindingMismatch::Ownership),
        (List(left), List(right)) | (Option(left), Option(right)) => compare_values(left, right),
        (Tuple(left), Tuple(right)) => {
            if left.len() != right.len() {
                return Some(ComponentGraphBindingMismatch::Type);
            }
            left.iter()
                .zip(right)
                .find_map(|(left, right)| compare_values(left, right))
        }
        (Record(left), Record(right)) => compare_named_values(left, right),
        (Flags(left), Flags(right)) | (Enum(left), Enum(right)) => {
            (left != right).then_some(ComponentGraphBindingMismatch::Type)
        }
        (
            Result {
                ok: left_ok,
                error: left_error,
            },
            Result {
                ok: right_ok,
                error: right_error,
            },
        ) => compare_optional_values(left_ok.as_deref(), right_ok.as_deref())
            .or_else(|| compare_optional_values(left_error.as_deref(), right_error.as_deref())),
        (Variant(left), Variant(right)) => compare_cases(left, right),
        (Future(left), Future(right)) | (Stream(left), Stream(right)) => {
            compare_optional_values(left.as_deref(), right.as_deref())
        }
        (Bool, Bool)
        | (U8, U8)
        | (U16, U16)
        | (U32, U32)
        | (U64, U64)
        | (S8, S8)
        | (S16, S16)
        | (S32, S32)
        | (S64, S64)
        | (Char, Char)
        | (String, String) => None,
        _ => Some(ComponentGraphBindingMismatch::Type),
    }
}

fn compare_optional_values(
    left: Option<&ValueShape>,
    right: Option<&ValueShape>,
) -> Option<ComponentGraphBindingMismatch> {
    match (left, right) {
        (Some(left), Some(right)) => compare_values(left, right),
        (None, None) => None,
        _ => Some(ComponentGraphBindingMismatch::Type),
    }
}

fn compare_functions(
    left: &FunctionShape,
    right: &FunctionShape,
) -> Option<ComponentGraphBindingMismatch> {
    if left.effect != right.effect {
        return Some(ComponentGraphBindingMismatch::Effect);
    }
    compare_named_values(&left.parameters, &right.parameters)
        .or_else(|| compare_optional_values(left.result.as_ref(), right.result.as_ref()))
}

fn compare_entities(
    left: &EntityShape,
    right: &EntityShape,
) -> Option<ComponentGraphBindingMismatch> {
    match (left, right) {
        (EntityShape::Function(left), EntityShape::Function(right)) => {
            compare_functions(left, right)
        }
        (EntityShape::Interface(left), EntityShape::Interface(right)) => {
            compare_interfaces(left, right)
        }
        (EntityShape::Type(left), EntityShape::Type(right)) => match (left, right) {
            (TypeShape::Resource, TypeShape::Resource) => None,
            (TypeShape::Value(left), TypeShape::Value(right)) => compare_values(left, right),
            _ => Some(ComponentGraphBindingMismatch::EntityKind),
        },
        _ => Some(ComponentGraphBindingMismatch::EntityKind),
    }
}

fn compare_interfaces(
    left: &[NamedEntityShape],
    right: &[NamedEntityShape],
) -> Option<ComponentGraphBindingMismatch> {
    if left.len() != right.len() {
        return Some(ComponentGraphBindingMismatch::Type);
    }
    for (index, left_entity) in left.iter().enumerate() {
        if left[..index]
            .iter()
            .any(|earlier| earlier.name == left_entity.name)
        {
            return Some(ComponentGraphBindingMismatch::Type);
        }
        let mut matches = right.iter().filter(|right| right.name == left_entity.name);
        let Some(right) = matches.next() else {
            let kind = if matches!(left_entity.entity, EntityShape::Type(TypeShape::Resource)) {
                ComponentGraphBindingMismatch::ResourceIdentity
            } else {
                ComponentGraphBindingMismatch::Type
            };
            return Some(kind);
        };
        if matches.next().is_some() {
            return Some(ComponentGraphBindingMismatch::Type);
        }
        if let Some(mismatch) = compare_entities(&left_entity.entity, &right.entity) {
            return Some(mismatch);
        }
    }
    None
}

fn check_complete_bindings(graph: &ComponentGraph<'_>) -> Result<(), ComponentGraphAdmissionError> {
    for node in graph.nodes() {
        for import_index in 0..node.imports().len() {
            let endpoint = ComponentGraphImportEndpoint::new(
                node.id(),
                vibeos_component_runtime::graph::ComponentGraphEntityIndex::new(
                    u16::try_from(import_index)
                        .map_err(|_| ComponentGraphAdmissionError::InvalidPolicy)?,
                ),
            );
            let internal = graph
                .edges()
                .iter()
                .filter(|edge| edge.target() == endpoint)
                .count();
            let external = graph
                .external_imports()
                .iter()
                .filter(|item| item.target() == endpoint)
                .count();
            let count = internal
                .checked_add(external)
                .ok_or(ComponentGraphAdmissionError::InvalidPolicy)?;
            if count == 0 {
                return Err(ComponentGraphAdmissionError::MissingBinding { target: endpoint });
            }
            if count > 1 {
                let resource = contains_resource_entity(&node.imports()[import_index].entity);
                return Err(if resource {
                    ComponentGraphAdmissionError::DuplicateResourceBinding { target: endpoint }
                } else {
                    ComponentGraphAdmissionError::DuplicateBinding { target: endpoint }
                });
            }
        }
    }
    for (index, published) in graph.published_exports().iter().enumerate() {
        if graph.published_exports()[..index]
            .iter()
            .any(|earlier| earlier.source() == published.source())
        {
            return Err(ComponentGraphAdmissionError::DuplicatePublishedExport {
                source: published.source(),
            });
        }
        if contains_resource_entity(&published.shape().entity) {
            return Err(ComponentGraphAdmissionError::InvalidPolicy);
        }
    }
    for (index, edge) in graph.edges().iter().enumerate() {
        if contains_resource_entity(&edge.source_shape().entity)
            && graph.edges()[..index]
                .iter()
                .any(|earlier| earlier.source() == edge.source())
        {
            return Err(ComponentGraphAdmissionError::DuplicateResourceSource {
                source: edge.source(),
            });
        }
    }
    Ok(())
}

fn check_typed_edges(graph: &ComponentGraph<'_>) -> Result<(), ComponentGraphAdmissionError> {
    for (index, edge) in graph.edges().iter().enumerate() {
        let edge_index = edge_index(index)?;
        let (EntityShape::Interface(source), EntityShape::Interface(target)) =
            (&edge.source_shape().entity, &edge.target_shape().entity)
        else {
            return Err(ComponentGraphAdmissionError::UnsupportedBindingSurface {
                edge: edge_index,
            });
        };
        if !valid_versioned_interface(&edge.source_shape().name)
            || !valid_versioned_interface(&edge.target_shape().name)
        {
            return Err(ComponentGraphAdmissionError::UnsupportedBindingSurface {
                edge: edge_index,
            });
        }
        if edge.source_shape().name != edge.target_shape().name {
            return Err(ComponentGraphAdmissionError::BindingMismatch {
                edge: edge_index,
                kind: ComponentGraphBindingMismatch::InterfaceVersion,
            });
        }
        if let Some(kind) = compare_interfaces(source, target) {
            return Err(ComponentGraphAdmissionError::BindingMismatch {
                edge: edge_index,
                kind,
            });
        }
    }
    Ok(())
}

fn derive_resource_edges(
    graph: &ComponentGraph<'_>,
    provenances: &[ComponentGraphResourceProvenance],
) -> Result<Vec<ComponentGraphResourceEdgeManifest>, ComponentGraphAdmissionError> {
    let mut routes = Vec::new();
    routes
        .try_reserve_exact(graph.edges().len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for (index, edge) in graph.edges().iter().enumerate() {
        let edge_index = edge_index(index)?;
        let (EntityShape::Interface(source), EntityShape::Interface(target)) =
            (&edge.source_shape().entity, &edge.target_shape().entity)
        else {
            // `check_typed_edges` must run before this helper.
            return Err(ComponentGraphAdmissionError::UnsupportedBindingSurface {
                edge: edge_index,
            });
        };
        let resource_bearing = source
            .iter()
            .any(|member| contains_resource_entity(&member.entity))
            || target
                .iter()
                .any(|member| contains_resource_entity(&member.entity));
        if !resource_bearing {
            continue;
        }

        let Some(source_evidence) = provenances
            .get(usize::from(edge.source().node().index()))
            .and_then(|resources| resources.export(edge.source().export()))
        else {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding {
                edge: edge_index,
            });
        };
        let Some(target_evidence) = provenances
            .get(usize::from(edge.target().node().index()))
            .and_then(|resources| resources.import(edge.target().import()))
        else {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding {
                edge: edge_index,
            });
        };
        let source_resources = exact_resource_names(source, source_evidence, edge_index)?;
        let target_resources = exact_resource_names(target, target_evidence, edge_index)?;
        if source_resources != target_resources {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding {
                edge: edge_index,
            });
        }
        let Some(source_mode) = collect_interface_resource_mode(source, &source_resources) else {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding {
                edge: edge_index,
            });
        };
        let Some(target_mode) = collect_interface_resource_mode(target, &target_resources) else {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding {
                edge: edge_index,
            });
        };
        if source_mode != target_mode {
            return Err(ComponentGraphAdmissionError::UnsupportedResourceBinding {
                edge: edge_index,
            });
        }
        routes.push(ComponentGraphResourceEdgeManifest {
            edge: ComponentGraphEdgeSpec::new(edge.source(), edge.target()),
            mode: source_mode,
            resources: source_resources,
        });
    }
    Ok(routes)
}

fn authorize_resource_edges(
    graph: &ComponentGraph<'_>,
    observed: &[ComponentGraphResourceEdgeManifest],
    policy: &[ComponentGraphResourceEdgePolicy],
) -> Result<(), ComponentGraphAdmissionError> {
    // Structural policy ambiguity is rejected only after topology, complete
    // bindings, exact edge types, and nominal evidence have been checked, so
    // the established error precedence is preserved.
    for (index, route) in policy.iter().enumerate() {
        if policy[..index]
            .iter()
            .any(|earlier| earlier.edge == route.edge)
            || !graph.edges().iter().any(|edge| {
                edge.source() == route.edge.source() && edge.target() == route.edge.target()
            })
        {
            return Err(ComponentGraphAdmissionError::InvalidPolicy);
        }
    }

    for route in observed {
        let index = graph
            .edges()
            .iter()
            .position(|edge| {
                edge.source() == route.edge.source() && edge.target() == route.edge.target()
            })
            .ok_or(ComponentGraphAdmissionError::InvalidPolicy)?;
        let Some(authorized) = policy.iter().find(|policy| policy.edge == route.edge) else {
            return Err(ComponentGraphAdmissionError::UnauthorizedResourceBinding {
                edge: edge_index(index)?,
            });
        };
        if authorized.mode != route.mode {
            return Err(ComponentGraphAdmissionError::UnauthorizedResourceBinding {
                edge: edge_index(index)?,
            });
        }
    }

    for authorized in policy {
        if observed.iter().all(|route| route.edge != authorized.edge) {
            let index = graph
                .edges()
                .iter()
                .position(|edge| {
                    edge.source() == authorized.edge.source()
                        && edge.target() == authorized.edge.target()
                })
                .ok_or(ComponentGraphAdmissionError::InvalidPolicy)?;
            return Err(ComponentGraphAdmissionError::UnauthorizedResourceBinding {
                edge: edge_index(index)?,
            });
        }
    }
    Ok(())
}

fn check_acyclic(graph: &ComponentGraph<'_>) -> Result<(), ComponentGraphAdmissionError> {
    let count = graph.nodes().len();
    if count > 16 {
        return Err(ComponentGraphAdmissionError::InvalidPolicy);
    }
    let mut indegree = [0_u16; 16];
    for edge in graph.edges() {
        let target = usize::from(edge.target().node().index());
        indegree[target] = indegree[target]
            .checked_add(1)
            .ok_or(ComponentGraphAdmissionError::InvalidPolicy)?;
    }
    let mut removed = [false; 16];
    let mut visited = 0_usize;
    loop {
        let mut next = None;
        for index in 0..count {
            if !removed[index] && indegree[index] == 0 {
                next = Some(index);
                break;
            }
        }
        let Some(index) = next else {
            break;
        };
        removed[index] = true;
        visited += 1;
        for edge in graph
            .edges()
            .iter()
            .filter(|edge| usize::from(edge.source().node().index()) == index)
        {
            let target = usize::from(edge.target().node().index());
            indegree[target] = indegree[target]
                .checked_sub(1)
                .ok_or(ComponentGraphAdmissionError::InvalidPolicy)?;
        }
    }
    if visited != count {
        let index = (0..count)
            .find(|index| !removed[*index])
            .ok_or(ComponentGraphAdmissionError::InvalidPolicy)?;
        return Err(ComponentGraphAdmissionError::DependencyCycle {
            node: node_id(index)?,
        });
    }
    Ok(())
}

fn check_graph_bindings(graph: &ComponentGraph<'_>) -> Result<(), ComponentGraphAdmissionError> {
    check_complete_bindings(graph)?;
    check_typed_edges(graph)
}

fn copy_specs<T: Copy>(source: &[T]) -> Result<Vec<T>, ComponentGraphAdmissionError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(source.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    result.extend_from_slice(source);
    Ok(result)
}

fn external_target_for_interface(
    graph: &ComponentGraph<'_>,
    node: ComponentGraphNodeId,
    interface: &str,
) -> Result<ComponentGraphImportEndpoint, ComponentGraphAdmissionError> {
    let mut found = None;
    for external in graph
        .external_imports()
        .iter()
        .filter(|external| external.target().node() == node && external.shape().name == interface)
    {
        if found.is_some() {
            return Err(ComponentGraphAdmissionError::DuplicateResourceBinding {
                target: external.target(),
            });
        }
        found = Some(external.target());
    }
    found.ok_or(ComponentGraphAdmissionError::InvalidPolicy)
}

fn select_external_imports(
    graph: &ComponentGraph<'_>,
    node: ComponentGraphNodeId,
) -> Result<Vec<u16>, ComponentGraphAdmissionError> {
    let count = graph
        .external_imports()
        .iter()
        .filter(|external| external.target().node() == node)
        .count();
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(count)
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for external in graph
        .external_imports()
        .iter()
        .filter(|external| external.target().node() == node)
    {
        selected.push(external.target().import().index());
    }
    Ok(selected)
}

fn build_grants(
    inspections: &[InspectedComponent<'_>],
    graph: &ComponentGraph<'_>,
    policy: &ComponentGraphAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<Vec<ComponentGraphAuthorityGrant>, ComponentGraphAdmissionError> {
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(graph.external_imports().len().saturating_mul(2))
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    let mut used_offers = Vec::new();
    used_offers
        .try_reserve_exact(caller.offers.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    used_offers.resize(caller.offers.len(), false);

    for (node_index, inspection) in inspections.iter().enumerate() {
        let node = node_id(node_index)?;
        let selected = select_external_imports(graph, node)?;
        if selected.is_empty() {
            continue;
        }
        let manifest = VibeHostManifest::from_selected_imports(inspection.plan(), &selected)
            .map_err(|error| ComponentGraphAdmissionError::ExternalHostManifest { node, error })?;
        for requirement in manifest.requirements() {
            let target = external_target_for_interface(graph, node, requirement.interface())?;
            let mut ceiling = None;
            for candidate in policy.nodes[node_index].interfaces {
                if candidate.interface == requirement.interface()
                    && candidate.kind == requirement.kind()
                {
                    if ceiling.is_some() {
                        return Err(ComponentGraphAdmissionError::InvalidPolicy);
                    }
                    ceiling = Some(candidate);
                }
            }
            let ceiling =
                ceiling.ok_or(ComponentGraphAdmissionError::MissingImageCeiling { target })?;
            let mut offer = None;
            for (index, candidate) in caller.offers.iter().enumerate() {
                if candidate.label == ceiling.label && candidate.kind == requirement.kind() {
                    if offer.is_some() {
                        return Err(ComponentGraphAdmissionError::InvalidPolicy);
                    }
                    offer = Some((index, candidate));
                }
            }
            let (offer_index, offer) =
                offer.ok_or(ComponentGraphAdmissionError::MissingCallerAuthority { target })?;
            if !ceiling.rights.contains(requirement.rights())
                || !offer.grantable.contains(requirement.rights())
            {
                return Err(ComponentGraphAdmissionError::AuthorityAmplification { target });
            }
            if used_offers[offer_index] {
                return Err(ComponentGraphAdmissionError::DuplicateAuthoritySource { target });
            }
            used_offers[offer_index] = true;
            grants.push(ComponentGraphAuthorityGrant {
                target,
                source_label: copied(offer.label)?,
                interface: requirement.interface(),
                resource: requirement.resource(),
                kind: requirement.kind(),
                rights: requirement.rights(),
            });
        }
    }
    Ok(grants)
}

/// Inspect and admit every node and edge as one transaction. This function has
/// no execution, kernel, CSpace, or host-dispatch input, so no rejected graph
/// can start a node or publish a capability.
pub fn admit_component_graph(
    artifacts: Vec<ComponentArtifact>,
    policy: &ComponentGraphAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    admit_component_graph_with_resource_policy(artifacts, policy, &[], caller)
}

/// Inspect and admit a complete graph with explicit, exact authorization for
/// its internal resource edges.
///
/// This remains a capability-free validation operation. In particular, the
/// resource policy does not contain or produce a live handle, Cap, CSpace
/// identity, supervisor operation, or executable route.
pub fn admit_component_graph_with_resource_policy(
    artifacts: Vec<ComponentArtifact>,
    policy: &ComponentGraphAdmissionPolicy<'_>,
    resource_policy: &[ComponentGraphResourceEdgePolicy],
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    validate_policy(&artifacts, policy, caller)?;
    if resource_policy.len() > PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges as usize {
        return Err(ComponentGraphAdmissionError::InvalidPolicy);
    }

    let mut inspected = Vec::new();
    inspected
        .try_reserve_exact(artifacts.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    let mut provenances = Vec::new();
    provenances
        .try_reserve_exact(artifacts.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for (index, artifact) in artifacts.iter().enumerate() {
        let (inspection, provenance) =
            artifact
                .inspect_graph()
                .map_err(|error| ComponentGraphAdmissionError::Node {
                    node: ComponentGraphNodeId::new(index as u16),
                    error,
                })?;
        inspected.push(inspection);
        provenances.push(provenance);
    }

    for (index, inspection) in inspected.iter().enumerate() {
        inspection
            .plan()
            .check_world(policy.nodes[index].exact_world)
            .map_err(|error| ComponentGraphAdmissionError::Node {
                node: ComponentGraphNodeId::new(index as u16),
                error: AdmissionError::World(error),
            })?;
    }

    let mut node_specs = Vec::new();
    node_specs
        .try_reserve_exact(inspected.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for (inspection, node) in inspected.iter().zip(policy.nodes) {
        node_specs.push(ComponentGraphNodeSpec::from_plan(
            node.label,
            &node.exact_world.identity,
            node.nesting,
            inspection.plan(),
            instance_budget(node.limits),
        ));
    }
    let graph = plan_component_graph(
        &node_specs,
        policy.edges,
        policy.external_imports,
        policy.published_exports,
    )?;
    check_graph_bindings(&graph)?;
    let resource_edges = derive_resource_edges(&graph, &provenances)?;
    authorize_resource_edges(&graph, &resource_edges, resource_policy)?;
    check_acyclic(&graph)?;
    let grants = build_grants(&inspected, &graph, policy, caller)?;

    let name = copied(policy.name)?;
    let edges = copy_specs(policy.edges)?;
    let external_imports = copy_specs(policy.external_imports)?;
    let published_exports = copy_specs(policy.published_exports)?;
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(graph.nodes().len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for ((node, policy_node), artifact) in graph.nodes().iter().zip(policy.nodes).zip(&artifacts) {
        nodes.push(ComponentGraphNodeManifest {
            id: node.id(),
            label: copied(policy_node.label)?,
            artifact: artifact.identity(),
            profile: policy.profile,
            world: copied(&policy_node.exact_world.identity)?,
            world_contract: world_contract_commitment(policy_node.exact_world),
            nesting: policy_node.nesting,
            limits: policy_node.limits,
            budget: node.budget(),
            interfaces: copy_ceilings(policy_node.interfaces)?,
        });
    }
    let account = graph.account();
    drop(graph);
    drop(node_specs);

    let mut inspections = Vec::new();
    inspections
        .try_reserve_exact(inspected.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for (inspection, policy_node) in inspected.into_iter().zip(policy.nodes) {
        let InspectedComponent { plan, modules, .. } = inspection;
        let component = plan.summary();
        let (imports, exports) = plan.into_world_shapes();
        inspections.push(InspectionSummary {
            profile: policy.profile,
            world: copied(&policy_node.exact_world.identity)?,
            component,
            modules,
            imports,
            exports,
        });
    }

    Ok(AdmittedComponentGraph {
        artifacts,
        inspections,
        manifest: ComponentGraphManifest {
            name,
            profile: policy.profile,
            cycle_policy: policy.cycle_policy,
            account,
            nodes,
            edges,
            resource_edges,
            external_imports,
            published_exports,
        },
        grants,
        _sealed: private::Seal,
    })
}

fn revalidate_component_graph(
    admitted: &AdmittedComponentGraph,
) -> Result<(), ComponentGraphAdmissionError> {
    if !valid_graph_name(&admitted.manifest.name)
        || admitted.manifest.profile != ProfileIdentity::PROFILE_1
            && admitted.manifest.profile != ProfileIdentity::PROFILE_1_ASYNC
        || admitted.manifest.cycle_policy != ComponentGraphCyclePolicy::AcyclicOnly
        || admitted.artifacts.len() != admitted.manifest.nodes.len()
        || admitted.inspections.len() != admitted.manifest.nodes.len()
    {
        return Err(ComponentGraphAdmissionError::RevalidationMismatch);
    }

    let mut inspected = Vec::new();
    inspected
        .try_reserve_exact(admitted.artifacts.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    let mut provenances = Vec::new();
    provenances
        .try_reserve_exact(admitted.artifacts.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for (index, artifact) in admitted.artifacts.iter().enumerate() {
        let expected_node = &admitted.manifest.nodes[index];
        let expected = &admitted.inspections[index];
        let observed_identity = ComponentIdentity(Sha256::digest(artifact.bytes()).into());
        if observed_identity != artifact.identity()
            || artifact.identity() != expected_node.artifact
            || artifact.profile() != expected_node.profile
            || artifact.profile() != admitted.manifest.profile
            || expected.profile != expected_node.profile
            || expected.world != expected_node.world
            || !valid_text(&expected_node.label, 128)
            || !valid_world_identity(&expected_node.world)
            || expected_node.limits.validate().is_err()
            || expected_node.id != node_id(index)?
            || admitted.manifest.nodes[..index]
                .iter()
                .any(|earlier| earlier.label == expected_node.label)
        {
            return Err(ComponentGraphAdmissionError::RevalidationMismatch);
        }
        validate_owned_ceilings(&expected_node.interfaces)?;
        let (observed, provenance) =
            artifact
                .inspect_graph()
                .map_err(|error| ComponentGraphAdmissionError::Node {
                    node: expected_node.id,
                    error,
                })?;
        if observed.profile() != expected.profile
            || observed.summary() != expected.component
            || !unique_top_level_names(observed.imports())
            || !unique_top_level_names(observed.exports())
            || observed.imports() != expected.imports
            || observed.exports() != expected.exports
            || observed.embedded_modules() != expected.modules
        {
            return Err(ComponentGraphAdmissionError::RevalidationMismatch);
        }
        if world_contract_commitment_parts(
            &expected_node.world,
            observed.imports(),
            observed.exports(),
        ) != expected_node.world_contract
        {
            return Err(ComponentGraphAdmissionError::RevalidationMismatch);
        }
        inspected.push(observed);
        provenances.push(provenance);
    }

    let mut node_specs = Vec::new();
    node_specs
        .try_reserve_exact(inspected.len())
        .map_err(|_| ComponentGraphAdmissionError::Allocation)?;
    for (inspection, node) in inspected.iter().zip(&admitted.manifest.nodes) {
        node_specs.push(ComponentGraphNodeSpec::from_plan(
            &node.label,
            &node.world,
            node.nesting,
            inspection.plan(),
            instance_budget(node.limits),
        ));
    }
    let graph = plan_component_graph(
        &node_specs,
        &admitted.manifest.edges,
        &admitted.manifest.external_imports,
        &admitted.manifest.published_exports,
    )?;
    check_graph_bindings(&graph)?;
    let observed_resource_edges = derive_resource_edges(&graph, &provenances)?;
    if observed_resource_edges != admitted.manifest.resource_edges {
        return Err(ComponentGraphAdmissionError::RevalidationMismatch);
    }
    check_acyclic(&graph)?;
    if graph.account() != admitted.manifest.account
        || graph
            .nodes()
            .iter()
            .zip(&admitted.manifest.nodes)
            .any(|(observed, expected)| observed.budget() != expected.budget)
    {
        return Err(ComponentGraphAdmissionError::RevalidationMismatch);
    }

    let mut observed_grants = 0_usize;
    for (node_index, inspection) in inspected.iter().enumerate() {
        let node = node_id(node_index)?;
        let selected = select_external_imports(&graph, node)?;
        if selected.is_empty() {
            continue;
        }
        let host = VibeHostManifest::from_selected_imports(inspection.plan(), &selected)
            .map_err(|error| ComponentGraphAdmissionError::ExternalHostManifest { node, error })?;
        for requirement in host.requirements() {
            let target = external_target_for_interface(&graph, node, requirement.interface())?;
            let grant = admitted
                .grants
                .get(observed_grants)
                .ok_or(ComponentGraphAdmissionError::RevalidationMismatch)?;
            let mut ceiling = None;
            for candidate in &admitted.manifest.nodes[node_index].interfaces {
                if candidate.interface == requirement.interface()
                    && candidate.kind == requirement.kind()
                {
                    if ceiling.is_some() {
                        return Err(ComponentGraphAdmissionError::RevalidationMismatch);
                    }
                    ceiling = Some(candidate);
                }
            }
            let ceiling = ceiling.ok_or(ComponentGraphAdmissionError::RevalidationMismatch)?;
            if grant.target != target
                || !valid_text(&grant.source_label, 128)
                || grant.source_label != ceiling.label
                || grant.interface != requirement.interface()
                || grant.resource != requirement.resource()
                || grant.kind != requirement.kind()
                || grant.rights != requirement.rights()
                || !ceiling.rights.contains(requirement.rights())
                || admitted.grants[..observed_grants].iter().any(|earlier| {
                    earlier.source_label == grant.source_label && earlier.kind == grant.kind
                })
            {
                return Err(ComponentGraphAdmissionError::RevalidationMismatch);
            }
            observed_grants += 1;
        }
    }
    if observed_grants != admitted.grants.len() {
        return Err(ComponentGraphAdmissionError::RevalidationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(name: &str) -> NamedEntityShape {
        NamedEntityShape {
            name: String::from(name),
            entity: EntityShape::Type(TypeShape::Value(ValueShape::U32)),
        }
    }

    #[test]
    fn world_commitment_canonicalizes_only_name_keyed_top_level_sides() {
        let left = alloc::vec![scalar("alpha"), scalar("beta")];
        let right = alloc::vec![scalar("beta"), scalar("alpha")];
        assert_eq!(
            world_contract_commitment_parts("test:c62/world@1.0.0", &left, &[]),
            world_contract_commitment_parts("test:c62/world@1.0.0", &right, &[]),
        );

        let nested_left = alloc::vec![NamedEntityShape {
            name: String::from("test:c62/pipe@1.0.0"),
            entity: EntityShape::Interface(left),
        }];
        let nested_right = alloc::vec![NamedEntityShape {
            name: String::from("test:c62/pipe@1.0.0"),
            entity: EntityShape::Interface(right),
        }];
        assert_ne!(
            world_contract_commitment_parts("test:c62/world@1.0.0", &nested_left, &[]),
            world_contract_commitment_parts("test:c62/world@1.0.0", &nested_right, &[]),
        );
    }

    #[test]
    fn exact_matcher_distinguishes_function_effects() {
        let sync = EntityShape::Function(FunctionShape {
            effect: vibeos_component_runtime::world::FunctionEffect::Sync,
            parameters: Vec::new(),
            result: None,
        });
        let asynchronous = EntityShape::Function(FunctionShape {
            effect: vibeos_component_runtime::world::FunctionEffect::Async,
            parameters: Vec::new(),
            result: None,
        });
        assert_eq!(
            compare_entities(&sync, &asynchronous),
            Some(ComponentGraphBindingMismatch::Effect)
        );
    }
}
