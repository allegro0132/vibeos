//! Closed, semantic-only diagnostics for an admitted Component graph.
//!
//! This module is intentionally separate from the graph manifest's ordinary
//! Rust `Debug` surface. Endpoint ordinals are used only as local indices while
//! constructing an owned report and are discarded before the report escapes.

use alloc::{string::String, vec::Vec};
use core::{cmp::Ordering, fmt};

use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::{
    graph::{ComponentGraphExportEndpoint, ComponentGraphImportEndpoint, ComponentGraphNesting},
    world::{
        EntityShape, FunctionEffect, FunctionShape, NamedCaseShape, NamedEntityShape,
        NamedValueShape, TypeShape, ValueShape,
    },
};
use vibeos_core::cap::Rights;

use crate::{
    AdmittedComponentGraph, ComponentGraphAsyncEdgeManifest, ComponentGraphResourceEdgeManifest,
    ComponentGraphResourceMode,
};

/// Stable failure for the closed information-flow diagnostic projection.
///
/// No variant retains or formats the underlying admission error, graph-local
/// coordinate, artifact identity, or allocation identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ComponentGraphInformationFlowError {
    RevalidationFailed,
    Allocation,
    ProjectionMismatch,
}

impl fmt::Display for ComponentGraphInformationFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RevalidationFailed => "component graph information-flow revalidation failed",
            Self::Allocation => "component graph information-flow allocation failed",
            Self::ProjectionMismatch => {
                "component graph information-flow semantic projection failed"
            }
        })
    }
}

impl fmt::Debug for ComponentGraphInformationFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Owned, sealed, semantic-only view of one freshly revalidated graph.
///
/// The report has no artifact identity, graph coordinate, resource index,
/// capability, Task, CSpace, pointer, durable object identity, lookup hook, or
/// execution entry point. Its handwritten [`Display`](fmt::Display) and
/// [`Debug`](fmt::Debug) implementations are the only diagnostic schema.
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_artifact(report: &ComponentGraphInformationFlow) { report.artifact(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_node_id(report: &ComponentGraphInformationFlow) { report.node_id(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_entity_index(report: &ComponentGraphInformationFlow) { report.entity_index(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_resource_index(report: &ComponentGraphInformationFlow) { report.resource_index(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_capability(report: &ComponentGraphInformationFlow) { report.cap(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_pointer(report: &ComponentGraphInformationFlow) { report.pointer(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_object_id(report: &ComponentGraphInformationFlow) { report.object_id(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_lookup(report: &ComponentGraphInformationFlow) { report.lookup("ambient"); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ComponentGraphInformationFlow;
/// fn no_execution(report: &ComponentGraphInformationFlow) { report.instantiate(); }
/// ```
pub struct ComponentGraphInformationFlow {
    graph_policy_label: String,
    nodes: Vec<ComponentGraphInformationFlowNode>,
    internal_flows: Vec<ComponentGraphInformationFlowInternal>,
    external_flows: Vec<ComponentGraphInformationFlowExternal>,
    published_flows: Vec<ComponentGraphInformationFlowPublished>,
}

impl ComponentGraphInformationFlow {
    pub fn graph_policy_label(&self) -> &str {
        &self.graph_policy_label
    }

    pub fn nodes(&self) -> &[ComponentGraphInformationFlowNode] {
        &self.nodes
    }

    pub fn internal_flows(&self) -> &[ComponentGraphInformationFlowInternal] {
        &self.internal_flows
    }

    pub fn external_flows(&self) -> &[ComponentGraphInformationFlowExternal] {
        &self.external_flows
    }

    pub fn published_flows(&self) -> &[ComponentGraphInformationFlowPublished] {
        &self.published_flows
    }

    pub fn authority_policy_count(&self) -> usize {
        self.external_flows
            .iter()
            .map(|flow| flow.authority_policies.len())
            .sum()
    }

    /// Information-flow inspection never creates execution authority.
    pub const fn runtime_ready(&self) -> bool {
        false
    }
}

/// One principal identified only by trusted policy label and exact WIT world.
pub struct ComponentGraphInformationFlowNode {
    policy_label: String,
    world: String,
    parent_policy_label: Option<String>,
}

impl ComponentGraphInformationFlowNode {
    pub fn policy_label(&self) -> &str {
        &self.policy_label
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub fn parent_policy_label(&self) -> Option<&str> {
        self.parent_policy_label.as_deref()
    }
}

/// One endpoint resolved to policy/WIT names and a canonical semantic shape.
pub struct ComponentGraphInformationFlowEndpoint {
    principal_policy_label: String,
    entity_name: String,
    entity_shape: String,
}

impl ComponentGraphInformationFlowEndpoint {
    pub fn principal_policy_label(&self) -> &str {
        &self.principal_policy_label
    }

    pub fn entity_name(&self) -> &str {
        &self.entity_name
    }

    pub fn entity_shape(&self) -> &str {
        &self.entity_shape
    }
}

/// Exact resource authorization attached to an internal typed edge.
pub struct ComponentGraphInformationFlowResourcePolicy {
    mode: ComponentGraphResourceMode,
    resources: Vec<String>,
}

impl ComponentGraphInformationFlowResourcePolicy {
    pub const fn mode(&self) -> ComponentGraphResourceMode {
        self.mode
    }

    pub fn resources(&self) -> &[String] {
        &self.resources
    }
}

/// Validator-derived async shape evidence attached to an internal edge.
pub struct ComponentGraphInformationFlowAsyncPolicy {
    async_functions: u32,
    streams: u32,
    futures: u32,
}

impl ComponentGraphInformationFlowAsyncPolicy {
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

/// One exact internal typed flow, with optional resource and async policy.
pub struct ComponentGraphInformationFlowInternal {
    source: ComponentGraphInformationFlowEndpoint,
    target: ComponentGraphInformationFlowEndpoint,
    resource_policy: Option<ComponentGraphInformationFlowResourcePolicy>,
    async_policy: Option<ComponentGraphInformationFlowAsyncPolicy>,
}

impl ComponentGraphInformationFlowInternal {
    pub const fn source(&self) -> &ComponentGraphInformationFlowEndpoint {
        &self.source
    }

    pub const fn target(&self) -> &ComponentGraphInformationFlowEndpoint {
        &self.target
    }

    pub const fn resource_policy(&self) -> Option<&ComponentGraphInformationFlowResourcePolicy> {
        self.resource_policy.as_ref()
    }

    pub const fn async_policy(&self) -> Option<&ComponentGraphInformationFlowAsyncPolicy> {
        self.async_policy.as_ref()
    }
}

/// One exact external authority policy selected during graph admission.
pub struct ComponentGraphInformationFlowAuthorityPolicy {
    source_policy_label: String,
    interface: String,
    resource: String,
    kind: HostResourceKind,
    rights: Rights,
}

impl ComponentGraphInformationFlowAuthorityPolicy {
    pub fn source_policy_label(&self) -> &str {
        &self.source_policy_label
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub const fn kind(&self) -> HostResourceKind {
        self.kind
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

/// One declared external boundary and all exact selected policy labels.
pub struct ComponentGraphInformationFlowExternal {
    target: ComponentGraphInformationFlowEndpoint,
    authority_policies: Vec<ComponentGraphInformationFlowAuthorityPolicy>,
}

impl ComponentGraphInformationFlowExternal {
    pub const fn target(&self) -> &ComponentGraphInformationFlowEndpoint {
        &self.target
    }

    pub fn authority_policies(&self) -> &[ComponentGraphInformationFlowAuthorityPolicy] {
        &self.authority_policies
    }
}

/// One graph export published across the outer policy boundary.
pub struct ComponentGraphInformationFlowPublished {
    source: ComponentGraphInformationFlowEndpoint,
}

impl ComponentGraphInformationFlowPublished {
    pub const fn source(&self) -> &ComponentGraphInformationFlowEndpoint {
        &self.source
    }
}

impl AdmittedComponentGraph {
    /// Freshly verify immutable artifact provenance and build a detached,
    /// semantic-only information-flow report.
    pub fn information_flow(
        &self,
    ) -> Result<ComponentGraphInformationFlow, ComponentGraphInformationFlowError> {
        self.revalidate()
            .map_err(|_| ComponentGraphInformationFlowError::RevalidationFailed)?;

        let manifest = self.manifest();
        let mut nodes = reserved(manifest.nodes().len())?;
        for node in manifest.nodes() {
            let parent_policy_label = match node.nesting() {
                ComponentGraphNesting::Root => None,
                ComponentGraphNesting::Nested { parent } => Some(copied(
                    manifest
                        .nodes()
                        .get(usize::from(parent.index()))
                        .ok_or(ComponentGraphInformationFlowError::ProjectionMismatch)?
                        .label(),
                )?),
            };
            nodes.push(ComponentGraphInformationFlowNode {
                policy_label: copied(node.label())?,
                world: copied(node.world())?,
                parent_policy_label,
            });
        }
        nodes.sort_unstable_by(|left, right| left.policy_label.cmp(&right.policy_label));
        reject_adjacent_duplicates(&nodes, |node| node.policy_label.as_str())?;

        let mut internal_flows = reserved(manifest.edges().len())?;
        for edge in manifest.edges() {
            let source = export_endpoint(self, edge.source())?;
            let target = import_endpoint(self, edge.target())?;
            if source.entity_shape != target.entity_shape {
                return Err(ComponentGraphInformationFlowError::ProjectionMismatch);
            }
            let resource_policy = manifest
                .resource_edges()
                .iter()
                .find(|policy| policy.edge() == *edge)
                .map(copy_resource_policy)
                .transpose()?;
            let async_policy = manifest
                .async_edges()
                .iter()
                .find(|policy| policy.edge() == *edge)
                .map(copy_async_policy);
            internal_flows.push(ComponentGraphInformationFlowInternal {
                source,
                target,
                resource_policy,
                async_policy,
            });
        }
        internal_flows.sort_unstable_by(compare_internal_flows);
        if internal_flows
            .windows(2)
            .any(|pair| compare_internal_flows(&pair[0], &pair[1]) == Ordering::Equal)
            || internal_flows
                .iter()
                .filter(|flow| flow.resource_policy.is_some())
                .count()
                != manifest.resource_edges().len()
            || internal_flows
                .iter()
                .filter(|flow| flow.async_policy.is_some())
                .count()
                != manifest.async_edges().len()
        {
            return Err(ComponentGraphInformationFlowError::ProjectionMismatch);
        }

        let mut external_flows = reserved(manifest.external_imports().len())?;
        for external in manifest.external_imports() {
            let target = import_endpoint(self, external.target())?;
            let matching_grants = self
                .grants()
                .iter()
                .filter(|grant| grant.target() == external.target())
                .count();
            let mut authority_policies = reserved(matching_grants)?;
            for grant in self
                .grants()
                .iter()
                .filter(|grant| grant.target() == external.target())
            {
                authority_policies.push(ComponentGraphInformationFlowAuthorityPolicy {
                    source_policy_label: copied(grant.source_label())?,
                    interface: copied(grant.interface())?,
                    resource: copied(grant.resource())?,
                    kind: grant.kind(),
                    rights: grant.rights(),
                });
            }
            authority_policies.sort_unstable_by(compare_authority_policies);
            if authority_policies
                .windows(2)
                .any(|pair| compare_authority_policies(&pair[0], &pair[1]) == Ordering::Equal)
            {
                return Err(ComponentGraphInformationFlowError::ProjectionMismatch);
            }
            external_flows.push(ComponentGraphInformationFlowExternal {
                target,
                authority_policies,
            });
        }
        external_flows
            .sort_unstable_by(|left, right| compare_endpoints(&left.target, &right.target));
        if external_flows
            .windows(2)
            .any(|pair| compare_endpoints(&pair[0].target, &pair[1].target) == Ordering::Equal)
        {
            return Err(ComponentGraphInformationFlowError::ProjectionMismatch);
        }

        let mut published_flows = reserved(manifest.published_exports().len())?;
        for published in manifest.published_exports() {
            published_flows.push(ComponentGraphInformationFlowPublished {
                source: export_endpoint(self, published.source())?,
            });
        }
        published_flows
            .sort_unstable_by(|left, right| compare_endpoints(&left.source, &right.source));
        if published_flows
            .windows(2)
            .any(|pair| compare_endpoints(&pair[0].source, &pair[1].source) == Ordering::Equal)
        {
            return Err(ComponentGraphInformationFlowError::ProjectionMismatch);
        }

        let report = ComponentGraphInformationFlow {
            graph_policy_label: copied(manifest.name())?,
            nodes,
            internal_flows,
            external_flows,
            published_flows,
        };
        if report.authority_policy_count() != self.grants().len() || report.runtime_ready() {
            return Err(ComponentGraphInformationFlowError::ProjectionMismatch);
        }
        Ok(report)
    }
}

fn reserved<T>(length: usize) -> Result<Vec<T>, ComponentGraphInformationFlowError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| ComponentGraphInformationFlowError::Allocation)?;
    Ok(values)
}

fn copied(value: &str) -> Result<String, ComponentGraphInformationFlowError> {
    let mut owned = String::new();
    append(&mut owned, value)?;
    Ok(owned)
}

fn append(output: &mut String, value: &str) -> Result<(), ComponentGraphInformationFlowError> {
    output
        .try_reserve_exact(value.len())
        .map_err(|_| ComponentGraphInformationFlowError::Allocation)?;
    output.push_str(value);
    Ok(())
}

fn reject_adjacent_duplicates<T>(
    values: &[T],
    key: impl Fn(&T) -> &str,
) -> Result<(), ComponentGraphInformationFlowError> {
    if values.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
        Err(ComponentGraphInformationFlowError::ProjectionMismatch)
    } else {
        Ok(())
    }
}

fn export_endpoint(
    graph: &AdmittedComponentGraph,
    endpoint: ComponentGraphExportEndpoint,
) -> Result<ComponentGraphInformationFlowEndpoint, ComponentGraphInformationFlowError> {
    let node_index = usize::from(endpoint.node().index());
    let node = graph
        .manifest()
        .nodes()
        .get(node_index)
        .ok_or(ComponentGraphInformationFlowError::ProjectionMismatch)?;
    let entity = graph
        .node_inspections()
        .get(node_index)
        .and_then(|inspection| {
            inspection
                .exports()
                .get(usize::from(endpoint.export().index()))
        })
        .ok_or(ComponentGraphInformationFlowError::ProjectionMismatch)?;
    semantic_endpoint(node.label(), entity)
}

fn import_endpoint(
    graph: &AdmittedComponentGraph,
    endpoint: ComponentGraphImportEndpoint,
) -> Result<ComponentGraphInformationFlowEndpoint, ComponentGraphInformationFlowError> {
    let node_index = usize::from(endpoint.node().index());
    let node = graph
        .manifest()
        .nodes()
        .get(node_index)
        .ok_or(ComponentGraphInformationFlowError::ProjectionMismatch)?;
    let entity = graph
        .node_inspections()
        .get(node_index)
        .and_then(|inspection| {
            inspection
                .imports()
                .get(usize::from(endpoint.import().index()))
        })
        .ok_or(ComponentGraphInformationFlowError::ProjectionMismatch)?;
    semantic_endpoint(node.label(), entity)
}

fn semantic_endpoint(
    policy_label: &str,
    entity: &NamedEntityShape,
) -> Result<ComponentGraphInformationFlowEndpoint, ComponentGraphInformationFlowError> {
    Ok(ComponentGraphInformationFlowEndpoint {
        principal_policy_label: copied(policy_label)?,
        entity_name: copied(&entity.name)?,
        entity_shape: canonical_entity_shape_text_v1(&entity.entity)?,
    })
}

fn copy_resource_policy(
    policy: &ComponentGraphResourceEdgeManifest,
) -> Result<ComponentGraphInformationFlowResourcePolicy, ComponentGraphInformationFlowError> {
    let mut resources = reserved(policy.resources().len())?;
    for resource in policy.resources() {
        resources.push(copied(resource)?);
    }
    Ok(ComponentGraphInformationFlowResourcePolicy {
        mode: policy.mode(),
        resources,
    })
}

fn copy_async_policy(
    policy: &ComponentGraphAsyncEdgeManifest,
) -> ComponentGraphInformationFlowAsyncPolicy {
    ComponentGraphInformationFlowAsyncPolicy {
        async_functions: policy.async_functions(),
        streams: policy.streams(),
        futures: policy.futures(),
    }
}

fn compare_endpoints(
    left: &ComponentGraphInformationFlowEndpoint,
    right: &ComponentGraphInformationFlowEndpoint,
) -> Ordering {
    left.principal_policy_label
        .cmp(&right.principal_policy_label)
        .then_with(|| left.entity_name.cmp(&right.entity_name))
        .then_with(|| left.entity_shape.cmp(&right.entity_shape))
}

fn compare_internal_flows(
    left: &ComponentGraphInformationFlowInternal,
    right: &ComponentGraphInformationFlowInternal,
) -> Ordering {
    compare_endpoints(&left.source, &right.source)
        .then_with(|| compare_endpoints(&left.target, &right.target))
}

fn host_kind_rank(kind: HostResourceKind) -> u8 {
    match kind {
        HostResourceKind::Clock => 0,
        HostResourceKind::Random => 1,
        HostResourceKind::Blob => 2,
        HostResourceKind::StructuredLog => 3,
        HostResourceKind::ByteStreamReader => 4,
        HostResourceKind::ByteStreamWriter => 5,
    }
}

fn host_kind_name(kind: HostResourceKind) -> &'static str {
    match kind {
        HostResourceKind::Clock => "clock",
        HostResourceKind::Random => "random",
        HostResourceKind::Blob => "blob",
        HostResourceKind::StructuredLog => "structured-log",
        HostResourceKind::ByteStreamReader => "byte-stream-reader",
        HostResourceKind::ByteStreamWriter => "byte-stream-writer",
    }
}

fn compare_authority_policies(
    left: &ComponentGraphInformationFlowAuthorityPolicy,
    right: &ComponentGraphInformationFlowAuthorityPolicy,
) -> Ordering {
    left.source_policy_label
        .cmp(&right.source_policy_label)
        .then_with(|| left.interface.cmp(&right.interface))
        .then_with(|| left.resource.cmp(&right.resource))
        .then_with(|| host_kind_rank(left.kind).cmp(&host_kind_rank(right.kind)))
        .then_with(|| left.rights.bits().cmp(&right.rights.bits()))
}

/// Render the bounded canonical v1 diagnostic text for a freshly normalized
/// entity shape.
///
/// This projection is suitable for checking that an inert manifest remains
/// self-consistent. It is not nominal-resource identity or admission
/// authority; trust boundaries must still compare fresh typed validator and
/// WIT evidence.
pub fn canonical_entity_shape_text_v1(
    entity: &EntityShape,
) -> Result<String, ComponentGraphInformationFlowError> {
    let mut output = String::new();
    append_entity_shape(&mut output, entity)?;
    Ok(output)
}

fn append_entity_shape(
    output: &mut String,
    entity: &EntityShape,
) -> Result<(), ComponentGraphInformationFlowError> {
    match entity {
        EntityShape::Function(function) => append_function_shape(output, function),
        EntityShape::Interface(members) => {
            append(output, "interface{")?;
            append_sorted_entities(output, members)?;
            append(output, "}")
        }
        EntityShape::Type(TypeShape::Resource) => append(output, "resource"),
        EntityShape::Type(TypeShape::Value(value)) => {
            append(output, "type=")?;
            append_value_shape(output, value)
        }
    }
}

fn append_sorted_entities(
    output: &mut String,
    entities: &[NamedEntityShape],
) -> Result<(), ComponentGraphInformationFlowError> {
    let mut previous: Option<&str> = None;
    for emitted in 0..entities.len() {
        let entity = entities
            .iter()
            .filter(|entity| previous.is_none_or(|previous| entity.name.as_str() > previous))
            .min_by(|left, right| left.name.cmp(&right.name))
            .ok_or(ComponentGraphInformationFlowError::ProjectionMismatch)?;
        if emitted != 0 {
            append(output, ";")?;
        }
        append(output, &entity.name)?;
        append(output, ":")?;
        append_entity_shape(output, &entity.entity)?;
        previous = Some(&entity.name);
    }
    Ok(())
}

fn append_function_shape(
    output: &mut String,
    function: &FunctionShape,
) -> Result<(), ComponentGraphInformationFlowError> {
    append(
        output,
        match function.effect {
            FunctionEffect::Sync => "func(",
            FunctionEffect::Async => "async-func(",
        },
    )?;
    append_named_values(output, &function.parameters)?;
    append(output, ")->")?;
    append_optional_value(output, function.result.as_ref())
}

fn append_named_values(
    output: &mut String,
    values: &[NamedValueShape],
) -> Result<(), ComponentGraphInformationFlowError> {
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            append(output, ",")?;
        }
        append(output, &value.name)?;
        append(output, ":")?;
        append_value_shape(output, &value.value)?;
    }
    Ok(())
}

fn append_optional_value(
    output: &mut String,
    value: Option<&ValueShape>,
) -> Result<(), ComponentGraphInformationFlowError> {
    match value {
        Some(value) => append_value_shape(output, value),
        None => append(output, "unit"),
    }
}

fn append_cases(
    output: &mut String,
    cases: &[NamedCaseShape],
) -> Result<(), ComponentGraphInformationFlowError> {
    for (index, case) in cases.iter().enumerate() {
        if index != 0 {
            append(output, ",")?;
        }
        append(output, &case.name)?;
        if let Some(value) = &case.value {
            append(output, ":")?;
            append_value_shape(output, value)?;
        }
    }
    Ok(())
}

fn append_names(
    output: &mut String,
    names: &[String],
) -> Result<(), ComponentGraphInformationFlowError> {
    for (index, name) in names.iter().enumerate() {
        if index != 0 {
            append(output, ",")?;
        }
        append(output, name)?;
    }
    Ok(())
}

fn append_value_shape(
    output: &mut String,
    value: &ValueShape,
) -> Result<(), ComponentGraphInformationFlowError> {
    use ValueShape::*;
    match value {
        #[cfg(feature = "c88-f4-acceptance")]
        F32 | F64 => Err(ComponentGraphInformationFlowError::ProjectionMismatch),
        Bool => append(output, "bool"),
        U8 => append(output, "u8"),
        U16 => append(output, "u16"),
        U32 => append(output, "u32"),
        U64 => append(output, "u64"),
        S8 => append(output, "s8"),
        S16 => append(output, "s16"),
        S32 => append(output, "s32"),
        S64 => append(output, "s64"),
        Char => append(output, "char"),
        String => append(output, "string"),
        List(value) => append_unary(output, "list<", value, ">"),
        Tuple(values) => {
            append(output, "tuple<")?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    append(output, ",")?;
                }
                append_value_shape(output, value)?;
            }
            append(output, ">")
        }
        Record(values) => {
            append(output, "record{")?;
            append_named_values(output, values)?;
            append(output, "}")
        }
        Flags(names) => {
            append(output, "flags{")?;
            append_names(output, names)?;
            append(output, "}")
        }
        Enum(names) => {
            append(output, "enum{")?;
            append_names(output, names)?;
            append(output, "}")
        }
        Option(value) => append_unary(output, "option<", value, ">"),
        Result { ok, error } => {
            append(output, "result<")?;
            append_optional_value(output, ok.as_deref())?;
            append(output, ",")?;
            append_optional_value(output, error.as_deref())?;
            append(output, ">")
        }
        Variant(cases) => {
            append(output, "variant{")?;
            append_cases(output, cases)?;
            append(output, "}")
        }
        Future(value) => {
            append(output, "future<")?;
            append_optional_value(output, value.as_deref())?;
            append(output, ">")
        }
        Stream(value) => {
            append(output, "stream<")?;
            append_optional_value(output, value.as_deref())?;
            append(output, ">")
        }
        Own(resource) => {
            append(output, "own<")?;
            append(output, resource)?;
            append(output, ">")
        }
        Borrow(resource) => {
            append(output, "borrow<")?;
            append(output, resource)?;
            append(output, ">")
        }
    }
}

fn append_unary(
    output: &mut String,
    prefix: &str,
    value: &ValueShape,
    suffix: &str,
) -> Result<(), ComponentGraphInformationFlowError> {
    append(output, prefix)?;
    append_value_shape(output, value)?;
    append(output, suffix)
}

fn resource_mode_name(mode: ComponentGraphResourceMode) -> &'static str {
    match mode {
        ComponentGraphResourceMode::Borrow => "borrow",
        ComponentGraphResourceMode::Own => "own",
        ComponentGraphResourceMode::OwnAndBorrow => "own-and-borrow",
    }
}

struct QuotedResources<'a>(&'a [String]);

impl fmt::Display for QuotedResources<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[")?;
        for (index, resource) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{resource:?}")?;
        }
        formatter.write_str("]")
    }
}

impl fmt::Display for ComponentGraphInformationFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "graph policy={:?} runtime_ready=false nodes={} internal={} external={} authorities={} published={}",
            self.graph_policy_label,
            self.nodes.len(),
            self.internal_flows.len(),
            self.external_flows.len(),
            self.authority_policy_count(),
            self.published_flows.len()
        )?;
        for node in &self.nodes {
            write!(formatter, "\n{node}")?;
        }
        for flow in &self.internal_flows {
            write!(formatter, "\n{flow}")?;
        }
        for flow in &self.external_flows {
            write!(formatter, "\n{flow}")?;
            for policy in &flow.authority_policies {
                write!(
                    formatter,
                    "\nauthority target_policy={:?} target_entity={:?} {policy}",
                    flow.target.principal_policy_label, flow.target.entity_name
                )?;
            }
        }
        for flow in &self.published_flows {
            write!(formatter, "\n{flow}")?;
        }
        Ok(())
    }
}

impl fmt::Display for ComponentGraphInformationFlowNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "node policy={:?} world={:?} parent=",
            self.policy_label, self.world
        )?;
        match &self.parent_policy_label {
            Some(parent) => write!(formatter, "{parent:?}"),
            None => formatter.write_str("root"),
        }
    }
}

impl fmt::Display for ComponentGraphInformationFlowEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "policy={:?} entity={:?} shape={:?}",
            self.principal_policy_label, self.entity_name, self.entity_shape
        )
    }
}

impl fmt::Display for ComponentGraphInformationFlowResourcePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "resource_mode={} resources={}",
            resource_mode_name(self.mode),
            QuotedResources(&self.resources)
        )
    }
}

impl fmt::Display for ComponentGraphInformationFlowAsyncPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "async_functions={} streams={} futures={}",
            self.async_functions, self.streams, self.futures
        )
    }
}

impl fmt::Display for ComponentGraphInformationFlowInternal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "internal source_policy={:?} source_entity={:?} target_policy={:?} target_entity={:?} shape={:?} exact_type=true ",
            self.source.principal_policy_label,
            self.source.entity_name,
            self.target.principal_policy_label,
            self.target.entity_name,
            self.source.entity_shape
        )?;
        match &self.resource_policy {
            Some(policy) => write!(formatter, "{policy} ")?,
            None => formatter.write_str("resource_mode=none resources=[] ")?,
        }
        match &self.async_policy {
            Some(policy) => write!(formatter, "{policy}"),
            None => formatter.write_str("async_functions=0 streams=0 futures=0"),
        }
    }
}

impl fmt::Display for ComponentGraphInformationFlowAuthorityPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "source_policy={:?} interface={:?} resource={:?} kind={} rights={}",
            self.source_policy_label,
            self.interface,
            self.resource,
            host_kind_name(self.kind),
            self.rights
        )
    }
}

impl fmt::Display for ComponentGraphInformationFlowExternal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "external target_policy={:?} target_entity={:?} shape={:?} authority_count={}",
            self.target.principal_policy_label,
            self.target.entity_name,
            self.target.entity_shape,
            self.authority_policies.len()
        )
    }
}

impl fmt::Display for ComponentGraphInformationFlowPublished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "published source_policy={:?} source_entity={:?} shape={:?}",
            self.source.principal_policy_label, self.source.entity_name, self.source.entity_shape
        )
    }
}

macro_rules! debug_via_display {
    ($($ty:ty),+ $(,)?) => {$ (
        impl fmt::Debug for $ty {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }
    )+ };
}

debug_via_display!(
    ComponentGraphInformationFlow,
    ComponentGraphInformationFlowNode,
    ComponentGraphInformationFlowEndpoint,
    ComponentGraphInformationFlowResourcePolicy,
    ComponentGraphInformationFlowAsyncPolicy,
    ComponentGraphInformationFlowInternal,
    ComponentGraphInformationFlowAuthorityPolicy,
    ComponentGraphInformationFlowExternal,
    ComponentGraphInformationFlowPublished,
);
