//! Allocation-bounded, permanently inert Component graph planning.
//!
//! C6.1 establishes only structural provenance, containment, and absolute
//! aggregate ceilings. It deliberately does not decide whether imports and
//! exports match, whether a data-flow cycle is allowed, or whether an edge
//! carries authority. Those admission decisions belong to C6.2.
//!
//! The plan has no execution entry point:
//!
//! ```compile_fail
//! use vibeos_component_runtime::graph::ComponentGraph;
//!
//! fn cannot_start(graph: &ComponentGraph<'_>) {
//!     graph.instantiate();
//! }
//! ```

use crate::{
    decode::{ComponentPlan, ComponentSummary},
    world::NamedEntityShape,
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{
    ComponentGraphAccount, ComponentGraphInstanceBudget, ComponentGraphNodeBudget, LimitError,
    LimitKind, ProfileIdentity, PROFILE_1_COMPONENT_GRAPH_LIMITS, PROFILE_1_LIMITS,
};
use wasmparser::{
    component_types::{
        AliasableResourceId, ComponentAnyTypeId, ComponentDefinedType, ComponentDefinedTypeId,
        ComponentEntityType, ComponentValType,
    },
    types::Types,
};

/// Dense, graph-local node address. It is neither durable identity nor
/// execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ComponentGraphNodeId(u16);

impl ComponentGraphNodeId {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u16 {
        self.0
    }
}

/// Direction-neutral index into one node's import or export shape slice.
/// Directional endpoint wrappers prevent source and target confusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ComponentGraphEntityIndex(u16);

impl ComponentGraphEntityIndex {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u16 {
        self.0
    }
}

/// The graph-only classification of one top-level Component entity's
/// resource surface.
///
/// `ExactInterface` is intentionally narrow: every resource is declared as a
/// direct member of that interface, every `own`/`borrow` refers to exactly one
/// such declaration, and no second top-level resource-bearing entity exists.
/// This last rule conservatively excludes cross-entity aliases without
/// retaining validator IDs. Everything else fails closed as `Unsupported`
/// for graph resource routing without changing ordinary Component inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphResourceStatus {
    ResourceFree,
    ExactInterface,
    Unsupported,
}

/// A semantic resource declaration in an exact top-level interface.
///
/// Only the stable member position is retained. Validator-local nominal IDs
/// are deliberately discarded before this value is constructed and can
/// therefore never be logged, persisted, or compared across inspections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphResourceDeclaration {
    member: ComponentGraphEntityIndex,
}

impl ComponentGraphResourceDeclaration {
    pub const fn member(&self) -> ComponentGraphEntityIndex {
        self.member
    }
}

/// Resource provenance for one normalized top-level import or export.
#[derive(Debug)]
pub struct ComponentGraphEntityResourceProvenance {
    status: ComponentGraphResourceStatus,
    declarations: Vec<ComponentGraphResourceDeclaration>,
}

impl ComponentGraphEntityResourceProvenance {
    pub const fn status(&self) -> ComponentGraphResourceStatus {
        self.status
    }

    pub fn declarations(&self) -> &[ComponentGraphResourceDeclaration] {
        &self.declarations
    }
}

/// Graph-only nominal-resource evidence captured during validation.
///
/// Entries are positionally aligned with [`ComponentPlan::imports`] and
/// [`ComponentPlan::exports`]. The sidecar is owned but contains no validator
/// IDs, so a durable manifest must save entity/member names and obtain fresh
/// evidence by re-inspecting the original bytes.
#[derive(Debug)]
pub struct ComponentGraphResourceProvenance {
    imports: Vec<ComponentGraphEntityResourceProvenance>,
    exports: Vec<ComponentGraphEntityResourceProvenance>,
}

impl ComponentGraphResourceProvenance {
    pub fn imports(&self) -> &[ComponentGraphEntityResourceProvenance] {
        &self.imports
    }

    pub fn exports(&self) -> &[ComponentGraphEntityResourceProvenance] {
        &self.exports
    }

    pub fn import(
        &self,
        index: ComponentGraphEntityIndex,
    ) -> Option<&ComponentGraphEntityResourceProvenance> {
        self.imports.get(usize::from(index.index()))
    }

    pub fn export(
        &self,
        index: ComponentGraphEntityIndex,
    ) -> Option<&ComponentGraphEntityResourceProvenance> {
        self.exports.get(usize::from(index.index()))
    }
}

/// An inspected Component plus opt-in graph resource evidence.
///
/// The plan borrows only the original Component bytes. The evidence owns its
/// semantic indices and never borrows validator internals, avoiding a
/// self-referential `Types`/plan object.
pub struct ComponentGraphInspection<'a> {
    plan: ComponentPlan<'a>,
    resources: ComponentGraphResourceProvenance,
}

impl<'a> ComponentGraphInspection<'a> {
    pub(crate) const fn new(
        plan: ComponentPlan<'a>,
        resources: ComponentGraphResourceProvenance,
    ) -> Self {
        Self { plan, resources }
    }

    pub const fn plan(&self) -> &ComponentPlan<'a> {
        &self.plan
    }

    pub const fn resources(&self) -> &ComponentGraphResourceProvenance {
        &self.resources
    }

    pub fn into_parts(self) -> (ComponentPlan<'a>, ComponentGraphResourceProvenance) {
        (self.plan, self.resources)
    }
}

pub(crate) fn build_component_graph_resource_provenance(
    types: &Types,
    import_names: &[String],
    export_names: &[String],
) -> Result<ComponentGraphResourceProvenance, ComponentGraphProvenanceBuildError> {
    let mut imports = collect_raw_resource_entities(types, import_names, true)?;
    let mut exports = collect_raw_resource_entities(types, export_names, false)?;
    reject_cross_entity_resource_ambiguity(&mut imports, &mut exports);
    Ok(ComponentGraphResourceProvenance {
        imports: finish_resource_entities(imports)?,
        exports: finish_resource_entities(exports)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComponentGraphProvenanceBuildError {
    Allocation,
    InvalidWiring,
}

#[derive(Clone, Copy)]
struct RawResourceDeclaration {
    member: ComponentGraphEntityIndex,
    resource: AliasableResourceId,
}

struct RawResourceEntity {
    has_resources: bool,
    exact: bool,
    declarations: Vec<RawResourceDeclaration>,
}

#[derive(Clone, Copy)]
struct ResourceScan {
    has_resources: bool,
    exact: bool,
}

impl ResourceScan {
    const FREE: Self = Self {
        has_resources: false,
        exact: true,
    };

    const fn resource(exact: bool) -> Self {
        Self {
            has_resources: true,
            exact,
        }
    }

    fn include(&mut self, other: Self) {
        self.has_resources |= other.has_resources;
        self.exact &= other.exact;
    }
}

fn collect_raw_resource_entities(
    types: &Types,
    names: &[String],
    imports: bool,
) -> Result<Vec<RawResourceEntity>, ComponentGraphProvenanceBuildError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(names.len())
        .map_err(|_| ComponentGraphProvenanceBuildError::Allocation)?;
    for name in names {
        let item = if imports {
            types.component_item_for_import(name)
        } else {
            types.component_item_for_export(name)
        }
        .ok_or(ComponentGraphProvenanceBuildError::InvalidWiring)?;
        result.push(collect_raw_resource_entity(types, item.ty)?);
    }
    Ok(result)
}

fn collect_raw_resource_entity(
    types: &Types,
    entity: ComponentEntityType,
) -> Result<RawResourceEntity, ComponentGraphProvenanceBuildError> {
    let ComponentEntityType::Instance(instance_id) = entity else {
        let scan = scan_resource_entity(types, entity, &[], 1);
        return Ok(RawResourceEntity {
            has_resources: scan.has_resources,
            exact: !scan.has_resources,
            declarations: Vec::new(),
        });
    };

    let instance = &types[instance_id];
    let mut declarations = Vec::new();
    declarations
        .try_reserve_exact(instance.exports.len())
        .map_err(|_| ComponentGraphProvenanceBuildError::Allocation)?;
    let mut exact = true;
    for (member_index, (_, member)) in instance.exports.iter().enumerate() {
        let ComponentEntityType::Type {
            referenced: ComponentAnyTypeId::Resource(resource),
            ..
        } = member.ty
        else {
            continue;
        };
        let Ok(member_index) = u16::try_from(member_index) else {
            exact = false;
            continue;
        };
        if declarations
            .iter()
            .any(|existing: &RawResourceDeclaration| {
                existing.resource == resource || existing.resource.resource() == resource.resource()
            })
        {
            exact = false;
        }
        declarations.push(RawResourceDeclaration {
            member: ComponentGraphEntityIndex::new(member_index),
            resource,
        });
    }

    let mut scan = ResourceScan::FREE;
    for (_, member) in instance.exports.iter() {
        if matches!(
            member.ty,
            ComponentEntityType::Type {
                referenced: ComponentAnyTypeId::Resource(_),
                ..
            }
        ) {
            continue;
        }
        scan.include(scan_resource_entity(types, member.ty, &declarations, 1));
    }
    exact &= scan.exact;
    Ok(RawResourceEntity {
        has_resources: !declarations.is_empty() || scan.has_resources,
        exact,
        declarations,
    })
}

fn scan_resource_entity(
    types: &Types,
    entity: ComponentEntityType,
    declarations: &[RawResourceDeclaration],
    depth: u32,
) -> ResourceScan {
    if depth > PROFILE_1_LIMITS.max_canonical_nesting {
        return ResourceScan::resource(false);
    }
    match entity {
        ComponentEntityType::Func(id) => {
            let function = &types[id];
            let mut scan = ResourceScan::FREE;
            for (_, value) in function.params.iter() {
                scan.include(scan_resource_value(types, *value, declarations, depth + 1));
            }
            if let Some(value) = function.result {
                scan.include(scan_resource_value(types, value, declarations, depth + 1));
            }
            scan
        }
        ComponentEntityType::Instance(id) => {
            let mut scan = ResourceScan::FREE;
            for (_, member) in types[id].exports.iter() {
                scan.include(scan_resource_entity(
                    types,
                    member.ty,
                    declarations,
                    depth + 1,
                ));
            }
            if scan.has_resources {
                scan.exact = false;
            }
            scan
        }
        ComponentEntityType::Type { referenced, .. } => match referenced {
            ComponentAnyTypeId::Resource(_) => ResourceScan::resource(false),
            ComponentAnyTypeId::Defined(id) => {
                scan_resource_defined(types, id, declarations, depth + 1)
            }
            _ => ResourceScan::FREE,
        },
        ComponentEntityType::Value(value) => {
            scan_resource_value(types, value, declarations, depth + 1)
        }
        ComponentEntityType::Module(_) | ComponentEntityType::Component(_) => ResourceScan::FREE,
    }
}

fn scan_resource_value(
    types: &Types,
    value: ComponentValType,
    declarations: &[RawResourceDeclaration],
    depth: u32,
) -> ResourceScan {
    match value {
        ComponentValType::Primitive(_) => ResourceScan::FREE,
        ComponentValType::Type(id) => {
            scan_resource_defined(types, id, declarations, depth.saturating_add(1))
        }
    }
}

fn scan_resource_defined(
    types: &Types,
    id: ComponentDefinedTypeId,
    declarations: &[RawResourceDeclaration],
    depth: u32,
) -> ResourceScan {
    if depth > PROFILE_1_LIMITS.max_canonical_nesting {
        return ResourceScan::resource(false);
    }
    let scan_values = |values: &[ComponentValType]| {
        let mut scan = ResourceScan::FREE;
        for value in values {
            scan.include(scan_resource_value(types, *value, declarations, depth + 1));
        }
        scan
    };
    match &types[id] {
        ComponentDefinedType::Primitive(_)
        | ComponentDefinedType::Flags(_)
        | ComponentDefinedType::Enum(_) => ResourceScan::FREE,
        ComponentDefinedType::Record(record) => {
            let mut scan = ResourceScan::FREE;
            for (_, value) in record.fields.iter() {
                scan.include(scan_resource_value(types, *value, declarations, depth + 1));
            }
            scan
        }
        ComponentDefinedType::Variant(variant) => {
            let mut scan = ResourceScan::FREE;
            for (_, case) in variant.cases.iter() {
                if let Some(value) = case.ty {
                    scan.include(scan_resource_value(types, value, declarations, depth + 1));
                }
            }
            scan
        }
        ComponentDefinedType::List { element, .. }
        | ComponentDefinedType::Option { ty: element, .. }
        | ComponentDefinedType::FixedLengthList { element, .. } => {
            scan_resource_value(types, *element, declarations, depth + 1)
        }
        ComponentDefinedType::Map { key, value, .. } => scan_values(&[*key, *value]),
        ComponentDefinedType::Tuple(tuple) => scan_values(&tuple.types),
        ComponentDefinedType::Result { ok, err, .. } => {
            let mut scan = ResourceScan::FREE;
            if let Some(value) = ok {
                scan.include(scan_resource_value(types, *value, declarations, depth + 1));
            }
            if let Some(value) = err {
                scan.include(scan_resource_value(types, *value, declarations, depth + 1));
            }
            scan
        }
        ComponentDefinedType::Own(resource) | ComponentDefinedType::Borrow(resource) => {
            ResourceScan::resource(
                declarations
                    .iter()
                    .any(|declaration| declaration.resource == *resource),
            )
        }
        ComponentDefinedType::Future { ty, .. } | ComponentDefinedType::Stream { ty, .. } => ty
            .map_or(ResourceScan::FREE, |value| {
                scan_resource_value(types, value, declarations, depth + 1)
            }),
    }
}

fn reject_cross_entity_resource_ambiguity(
    imports: &mut [RawResourceEntity],
    exports: &mut [RawResourceEntity],
) {
    // This intentionally conservative graph profile does not retain raw IDs
    // or allocate a global reference map. If resources occur in more than one
    // top-level entity, a handle in one entity may alias a declaration in
    // another. Mark every resource-bearing entity unsupported rather than
    // accidentally granting a cross-entity nominal route.
    let resource_entities = imports
        .iter()
        .chain(exports.iter())
        .filter(|entity| entity.has_resources)
        .count();
    if resource_entities > 1 {
        for entity in imports.iter_mut().chain(exports.iter_mut()) {
            if entity.has_resources {
                entity.exact = false;
            }
        }
    }
}

fn finish_resource_entities(
    raw: Vec<RawResourceEntity>,
) -> Result<Vec<ComponentGraphEntityResourceProvenance>, ComponentGraphProvenanceBuildError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(raw.len())
        .map_err(|_| ComponentGraphProvenanceBuildError::Allocation)?;
    for entity in raw {
        let status = if !entity.has_resources {
            ComponentGraphResourceStatus::ResourceFree
        } else if entity.exact {
            ComponentGraphResourceStatus::ExactInterface
        } else {
            ComponentGraphResourceStatus::Unsupported
        };
        let mut declarations = Vec::new();
        if status == ComponentGraphResourceStatus::ExactInterface {
            declarations
                .try_reserve_exact(entity.declarations.len())
                .map_err(|_| ComponentGraphProvenanceBuildError::Allocation)?;
            for declaration in entity.declarations {
                declarations.push(ComponentGraphResourceDeclaration {
                    member: declaration.member,
                });
            }
        }
        result.push(ComponentGraphEntityResourceProvenance {
            status,
            declarations,
        });
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ComponentGraphExportEndpoint {
    node: ComponentGraphNodeId,
    export: ComponentGraphEntityIndex,
}

impl ComponentGraphExportEndpoint {
    pub const fn new(node: ComponentGraphNodeId, export: ComponentGraphEntityIndex) -> Self {
        Self { node, export }
    }

    pub const fn node(self) -> ComponentGraphNodeId {
        self.node
    }

    pub const fn export(self) -> ComponentGraphEntityIndex {
        self.export
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ComponentGraphImportEndpoint {
    node: ComponentGraphNodeId,
    import: ComponentGraphEntityIndex,
}

impl ComponentGraphImportEndpoint {
    pub const fn new(node: ComponentGraphNodeId, import: ComponentGraphEntityIndex) -> Self {
        Self { node, import }
    }

    pub const fn node(self) -> ComponentGraphNodeId {
        self.node
    }

    pub const fn import(self) -> ComponentGraphEntityIndex {
        self.import
    }
}

/// Structural data-flow declaration. C6.1 resolves both endpoints but does not
/// claim that their shapes, effects, versions, or ownership modes match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphEdgeSpec {
    source: ComponentGraphExportEndpoint,
    target: ComponentGraphImportEndpoint,
}

impl ComponentGraphEdgeSpec {
    pub const fn new(
        source: ComponentGraphExportEndpoint,
        target: ComponentGraphImportEndpoint,
    ) -> Self {
        Self { source, target }
    }

    pub const fn source(self) -> ComponentGraphExportEndpoint {
        self.source
    }

    pub const fn target(self) -> ComponentGraphImportEndpoint {
        self.target
    }
}

/// Marks an import endpoint for later C6.2 policy binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphExternalImportSpec {
    target: ComponentGraphImportEndpoint,
}

impl ComponentGraphExternalImportSpec {
    pub const fn new(target: ComponentGraphImportEndpoint) -> Self {
        Self { target }
    }

    pub const fn target(self) -> ComponentGraphImportEndpoint {
        self.target
    }
}

/// Marks an export endpoint for later C6.2 policy publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphPublishedExportSpec {
    source: ComponentGraphExportEndpoint,
}

impl ComponentGraphPublishedExportSpec {
    pub const fn new(source: ComponentGraphExportEndpoint) -> Self {
        Self { source }
    }

    pub const fn source(self) -> ComponentGraphExportEndpoint {
        self.source
    }
}

/// Principal-containment relation, distinct from data-flow edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphNesting {
    Root,
    Nested { parent: ComponentGraphNodeId },
}

/// Borrowed input for one node. Component-derived fields are captured from an
/// inspected [`ComponentPlan`], while volatile capacity remains an untrusted
/// request until C6.2 binds it to admission policy.
#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphNodeSpec<'a> {
    label: &'a str,
    world: &'a str,
    nesting: ComponentGraphNesting,
    profile: ProfileIdentity,
    summary: ComponentSummary,
    imports: &'a [NamedEntityShape],
    exports: &'a [NamedEntityShape],
    budget: ComponentGraphNodeBudget,
}

impl<'a> ComponentGraphNodeSpec<'a> {
    pub fn from_plan(
        label: &'a str,
        world: &'a str,
        nesting: ComponentGraphNesting,
        plan: &'a ComponentPlan<'_>,
        requested: ComponentGraphInstanceBudget,
    ) -> Self {
        let summary = plan.summary();
        // Validation-only profiles deliberately have no execution plan. The
        // validator summary is the profile-independent structural count and
        // therefore the only sound aggregate-accounting source here.
        let core_instances = u64::from(summary.core_instances);
        Self {
            label,
            world,
            nesting,
            profile: plan.profile(),
            summary,
            imports: plan.imports(),
            exports: plan.exports(),
            budget: ComponentGraphNodeBudget {
                component_bytes: u64::from(summary.bytes),
                core_instances,
                adapters: u64::from(summary.adapters),
                resource_types: u64::from(summary.resources),
                resource_slots: requested.resource_slots,
                memory_bytes: requested.memory_bytes,
                total_fuel: requested.total_fuel,
                poll_quantum: requested.poll_quantum,
            },
        }
    }

    pub const fn label(&self) -> &'a str {
        self.label
    }

    pub const fn world(&self) -> &'a str {
        self.world
    }

    pub const fn nesting(&self) -> ComponentGraphNesting {
        self.nesting
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn summary(&self) -> ComponentSummary {
        self.summary
    }

    pub const fn imports(&self) -> &'a [NamedEntityShape] {
        self.imports
    }

    pub const fn exports(&self) -> &'a [NamedEntityShape] {
        self.exports
    }

    pub const fn budget(&self) -> ComponentGraphNodeBudget {
        self.budget
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphNodeBudgetError {
    ZeroResourceSlots,
    ZeroMemoryBytes,
    ZeroTotalFuel,
    ZeroPollQuantum,
    ResourceTypesExceedSlots,
    PollQuantumExceedsFuel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphError {
    EmptyGraph,
    Limit(LimitError),
    InvalidNodeBudget {
        node: ComponentGraphNodeId,
        reason: ComponentGraphNodeBudgetError,
    },
    InvalidParent {
        node: ComponentGraphNodeId,
        parent: ComponentGraphNodeId,
    },
    ContainmentCycle {
        node: ComponentGraphNodeId,
    },
    InvalidExportNode {
        node: ComponentGraphNodeId,
    },
    InvalidImportNode {
        node: ComponentGraphNodeId,
    },
    InvalidExportIndex {
        endpoint: ComponentGraphExportEndpoint,
    },
    InvalidImportIndex {
        endpoint: ComponentGraphImportEndpoint,
    },
    Allocation,
}

impl From<LimitError> for ComponentGraphError {
    fn from(error: LimitError) -> Self {
        Self::Limit(error)
    }
}

/// Successful allocation-free validation result.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphPreflight {
    account: ComponentGraphAccount,
}

impl ComponentGraphPreflight {
    pub const fn account(&self) -> ComponentGraphAccount {
        self.account
    }
}

/// One structurally planned node. Labels and world names are diagnostic input,
/// not lookup authority.
#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphNode<'a> {
    id: ComponentGraphNodeId,
    label: &'a str,
    world: &'a str,
    nesting: ComponentGraphNesting,
    profile: ProfileIdentity,
    summary: ComponentSummary,
    imports: &'a [NamedEntityShape],
    exports: &'a [NamedEntityShape],
    budget: ComponentGraphNodeBudget,
}

impl<'a> ComponentGraphNode<'a> {
    pub const fn id(&self) -> ComponentGraphNodeId {
        self.id
    }

    pub const fn label(&self) -> &'a str {
        self.label
    }

    pub const fn world(&self) -> &'a str {
        self.world
    }

    pub const fn nesting(&self) -> ComponentGraphNesting {
        self.nesting
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn summary(&self) -> ComponentSummary {
        self.summary
    }

    pub const fn imports(&self) -> &'a [NamedEntityShape] {
        self.imports
    }

    pub const fn exports(&self) -> &'a [NamedEntityShape] {
        self.exports
    }

    pub const fn budget(&self) -> ComponentGraphNodeBudget {
        self.budget
    }
}

/// Structurally resolved but deliberately untyped data-flow edge.
#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphEdge<'a> {
    source: ComponentGraphExportEndpoint,
    target: ComponentGraphImportEndpoint,
    source_shape: &'a NamedEntityShape,
    target_shape: &'a NamedEntityShape,
}

impl<'a> ComponentGraphEdge<'a> {
    pub const fn source(&self) -> ComponentGraphExportEndpoint {
        self.source
    }

    pub const fn target(&self) -> ComponentGraphImportEndpoint {
        self.target
    }

    pub const fn source_shape(&self) -> &'a NamedEntityShape {
        self.source_shape
    }

    pub const fn target_shape(&self) -> &'a NamedEntityShape {
        self.target_shape
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphExternalImport<'a> {
    target: ComponentGraphImportEndpoint,
    shape: &'a NamedEntityShape,
}

impl<'a> ComponentGraphExternalImport<'a> {
    pub const fn target(&self) -> ComponentGraphImportEndpoint {
        self.target
    }

    pub const fn shape(&self) -> &'a NamedEntityShape {
        self.shape
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ComponentGraphPublishedExport<'a> {
    source: ComponentGraphExportEndpoint,
    shape: &'a NamedEntityShape,
}

impl<'a> ComponentGraphPublishedExport<'a> {
    pub const fn source(&self) -> ComponentGraphExportEndpoint {
        self.source
    }

    pub const fn shape(&self) -> &'a NamedEntityShape {
        self.shape
    }
}

/// Flat, bounded and permanently inert C6.1 composition plan.
#[derive(Debug)]
pub struct ComponentGraph<'a> {
    account: ComponentGraphAccount,
    nodes: Vec<ComponentGraphNode<'a>>,
    edges: Vec<ComponentGraphEdge<'a>>,
    external_imports: Vec<ComponentGraphExternalImport<'a>>,
    published_exports: Vec<ComponentGraphPublishedExport<'a>>,
}

impl<'a> ComponentGraph<'a> {
    pub const fn account(&self) -> ComponentGraphAccount {
        self.account
    }

    pub fn nodes(&self) -> &[ComponentGraphNode<'a>] {
        &self.nodes
    }

    pub fn edges(&self) -> &[ComponentGraphEdge<'a>] {
        &self.edges
    }

    pub fn external_imports(&self) -> &[ComponentGraphExternalImport<'a>] {
        &self.external_imports
    }

    pub fn published_exports(&self) -> &[ComponentGraphPublishedExport<'a>] {
        &self.published_exports
    }

    /// C6.1 never produces execution authority.
    pub const fn runtime_ready(&self) -> bool {
        false
    }
}

fn count(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn node_id(index: usize) -> Result<ComponentGraphNodeId, ComponentGraphError> {
    match u16::try_from(index) {
        Ok(index) => Ok(ComponentGraphNodeId::new(index)),
        Err(_) => Err(ComponentGraphError::Limit(LimitError {
            kind: LimitKind::GraphNodes,
            attempted: u64::MAX,
            maximum: PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes,
        })),
    }
}

fn check_count(attempted: u64, maximum: u64, kind: LimitKind) -> Result<(), ComponentGraphError> {
    if attempted > maximum {
        return Err(ComponentGraphError::Limit(LimitError {
            kind,
            attempted,
            maximum,
        }));
    }
    Ok(())
}

fn check_node_budget(
    node: ComponentGraphNodeId,
    budget: ComponentGraphNodeBudget,
) -> Result<(), ComponentGraphError> {
    let reason = if budget.resource_slots == 0 {
        Some(ComponentGraphNodeBudgetError::ZeroResourceSlots)
    } else if budget.memory_bytes == 0 {
        Some(ComponentGraphNodeBudgetError::ZeroMemoryBytes)
    } else if budget.total_fuel == 0 {
        Some(ComponentGraphNodeBudgetError::ZeroTotalFuel)
    } else if budget.poll_quantum == 0 {
        Some(ComponentGraphNodeBudgetError::ZeroPollQuantum)
    } else if budget.resource_types > budget.resource_slots {
        Some(ComponentGraphNodeBudgetError::ResourceTypesExceedSlots)
    } else if budget.poll_quantum > budget.total_fuel {
        Some(ComponentGraphNodeBudgetError::PollQuantumExceedsFuel)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(ComponentGraphError::InvalidNodeBudget { node, reason });
    }
    Ok(())
}

fn export_shape<'a>(
    nodes: &[ComponentGraphNodeSpec<'a>],
    endpoint: ComponentGraphExportEndpoint,
) -> Result<&'a NamedEntityShape, ComponentGraphError> {
    let node = nodes.get(usize::from(endpoint.node().index())).ok_or(
        ComponentGraphError::InvalidExportNode {
            node: endpoint.node(),
        },
    )?;
    node.exports()
        .get(usize::from(endpoint.export().index()))
        .ok_or(ComponentGraphError::InvalidExportIndex { endpoint })
}

fn import_shape<'a>(
    nodes: &[ComponentGraphNodeSpec<'a>],
    endpoint: ComponentGraphImportEndpoint,
) -> Result<&'a NamedEntityShape, ComponentGraphError> {
    let node = nodes.get(usize::from(endpoint.node().index())).ok_or(
        ComponentGraphError::InvalidImportNode {
            node: endpoint.node(),
        },
    )?;
    node.imports()
        .get(usize::from(endpoint.import().index()))
        .ok_or(ComponentGraphError::InvalidImportIndex { endpoint })
}

/// Checks the complete graph without allocating graph-plan storage.
pub fn preflight_component_graph<'a>(
    nodes: &[ComponentGraphNodeSpec<'a>],
    edges: &[ComponentGraphEdgeSpec],
    external_imports: &[ComponentGraphExternalImportSpec],
    published_exports: &[ComponentGraphPublishedExportSpec],
) -> Result<ComponentGraphPreflight, ComponentGraphError> {
    if nodes.is_empty() {
        return Err(ComponentGraphError::EmptyGraph);
    }

    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    check_count(count(nodes.len()), limits.max_nodes, LimitKind::GraphNodes)?;
    check_count(count(edges.len()), limits.max_edges, LimitKind::GraphEdges)?;
    check_count(
        count(external_imports.len()),
        limits.max_external_imports,
        LimitKind::GraphExternalImports,
    )?;
    check_count(
        count(published_exports.len()),
        limits.max_published_exports,
        LimitKind::GraphPublishedExports,
    )?;

    let mut account = ComponentGraphAccount::default();
    account.charge_edges(count(edges.len()))?;
    account.charge_external_imports(count(external_imports.len()))?;
    account.charge_published_exports(count(published_exports.len()))?;

    for (index, node) in nodes.iter().enumerate() {
        let id = node_id(index)?;
        check_count(
            count(node.imports().len()),
            u64::from(PROFILE_1_LIMITS.max_imports),
            LimitKind::Imports,
        )?;
        check_count(
            count(node.exports().len()),
            u64::from(PROFILE_1_LIMITS.max_exports),
            LimitKind::Exports,
        )?;
        check_node_budget(id, node.budget())?;
        account.charge_node(node.budget())?;
    }

    // Follow at most `nodes.len()` parents. Reaching a root proves acyclicity;
    // taking that many non-root steps proves a containment cycle. Depth is
    // observed only after reaching a root so cycles are never misreported as
    // mere nesting-limit failures.
    for index in 0..nodes.len() {
        let origin = node_id(index)?;
        let mut cursor = origin;
        let mut depth = 0_u64;
        let mut reached_root = false;
        for _ in 0..nodes.len() {
            let node = &nodes[usize::from(cursor.index())];
            depth = depth
                .checked_add(1)
                .ok_or(ComponentGraphError::Limit(LimitError {
                    kind: LimitKind::GraphNesting,
                    attempted: u64::MAX,
                    maximum: limits.max_nesting,
                }))?;
            match node.nesting() {
                ComponentGraphNesting::Root => {
                    reached_root = true;
                    break;
                }
                ComponentGraphNesting::Nested { parent } => {
                    if nodes.get(usize::from(parent.index())).is_none() {
                        return Err(ComponentGraphError::InvalidParent {
                            node: cursor,
                            parent,
                        });
                    }
                    cursor = parent;
                }
            }
        }
        if !reached_root {
            return Err(ComponentGraphError::ContainmentCycle { node: origin });
        }
        account.observe_nesting(depth)?;
    }

    for edge in edges {
        export_shape(nodes, edge.source())?;
        import_shape(nodes, edge.target())?;
    }
    for external in external_imports {
        import_shape(nodes, external.target())?;
    }
    for published in published_exports {
        export_shape(nodes, published.source())?;
    }

    Ok(ComponentGraphPreflight { account })
}

/// Materializes a flat inert plan only after the complete semantic-free
/// preflight has succeeded.
pub fn plan_component_graph<'a>(
    node_specs: &[ComponentGraphNodeSpec<'a>],
    edge_specs: &[ComponentGraphEdgeSpec],
    external_import_specs: &[ComponentGraphExternalImportSpec],
    published_export_specs: &[ComponentGraphPublishedExportSpec],
) -> Result<ComponentGraph<'a>, ComponentGraphError> {
    let preflight = preflight_component_graph(
        node_specs,
        edge_specs,
        external_import_specs,
        published_export_specs,
    )?;

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut external_imports = Vec::new();
    let mut published_exports = Vec::new();
    nodes
        .try_reserve_exact(node_specs.len())
        .map_err(|_| ComponentGraphError::Allocation)?;
    edges
        .try_reserve_exact(edge_specs.len())
        .map_err(|_| ComponentGraphError::Allocation)?;
    external_imports
        .try_reserve_exact(external_import_specs.len())
        .map_err(|_| ComponentGraphError::Allocation)?;
    published_exports
        .try_reserve_exact(published_export_specs.len())
        .map_err(|_| ComponentGraphError::Allocation)?;

    for (index, spec) in node_specs.iter().enumerate() {
        nodes.push(ComponentGraphNode {
            id: node_id(index)?,
            label: spec.label(),
            world: spec.world(),
            nesting: spec.nesting(),
            profile: spec.profile(),
            summary: spec.summary(),
            imports: spec.imports(),
            exports: spec.exports(),
            budget: spec.budget(),
        });
    }
    for spec in edge_specs {
        edges.push(ComponentGraphEdge {
            source: spec.source(),
            target: spec.target(),
            source_shape: export_shape(node_specs, spec.source())?,
            target_shape: import_shape(node_specs, spec.target())?,
        });
    }
    for spec in external_import_specs {
        external_imports.push(ComponentGraphExternalImport {
            target: spec.target(),
            shape: import_shape(node_specs, spec.target())?,
        });
    }
    for spec in published_export_specs {
        published_exports.push(ComponentGraphPublishedExport {
            source: spec.source(),
            shape: export_shape(node_specs, spec.source())?,
        });
    }

    Ok(ComponentGraph {
        account: preflight.account(),
        nodes,
        edges,
        external_imports,
        published_exports,
    })
}
