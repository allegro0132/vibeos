//! Portable, inert lifecycle envelopes for an admitted Component graph.
//!
//! This layer projects one immutable principal template per admitted node. It
//! deliberately carries only semantic policy and budget data: component
//! generations, Tasks, arenas, CSpaces, Caps, resource handles, and raw
//! generations belong to a future kernel lifecycle adapter and are never
//! retained here.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::fmt;

use vibeos_component_admission::{
    AdmittedComponentGraph, AdmittedComponentGraphReplacement, ComponentGraphAdmissionError,
    ComponentGraphAsyncEdgeManifest, ComponentGraphAuthorityGrant, ComponentGraphInformationFlow,
    ComponentGraphInformationFlowError, ComponentGraphManifest,
    ComponentGraphReplacementAdmissionError, ComponentGraphReplacementEdgePolicy,
    ComponentGraphResourceEdgeManifest, ComponentIdentity, InstanceLimits, ProfileIdentity,
};
use vibeos_component_format::{
    ComponentGraphAccount, ComponentGraphNodeBudget, TrapCode, PROFILE_1_LIMITS,
};
use vibeos_component_runtime::graph::{ComponentGraphNesting, ComponentGraphNodeId};

/// Failure while deriving or revalidating an inert principal template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphPrincipalTemplateError {
    Admission(ComponentGraphAdmissionError),
    Allocation,
    ProjectionMismatch,
}

impl fmt::Display for ComponentGraphPrincipalTemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Admission(_) => "component graph revalidation failed",
            Self::Allocation => "component graph principal projection allocation failed",
            Self::ProjectionMismatch => {
                "component graph principal projection differs from its admitted manifest"
            }
        })
    }
}

impl From<ComponentGraphAdmissionError> for ComponentGraphPrincipalTemplateError {
    fn from(error: ComponentGraphAdmissionError) -> Self {
        Self::Admission(error)
    }
}

/// Failure while deriving or revalidating an inert replacement template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphNodeReplacementTemplateError {
    Admission(ComponentGraphReplacementAdmissionError),
    Principal(ComponentGraphPrincipalTemplateError),
    Allocation,
    ProjectionMismatch,
}

impl fmt::Display for ComponentGraphNodeReplacementTemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Admission(_) => "component graph replacement revalidation failed",
            Self::Principal(_) => "component graph principal revalidation failed",
            Self::Allocation => "component graph replacement projection allocation failed",
            Self::ProjectionMismatch => {
                "component graph replacement projection differs from admission"
            }
        })
    }
}

impl From<ComponentGraphReplacementAdmissionError> for ComponentGraphNodeReplacementTemplateError {
    fn from(error: ComponentGraphReplacementAdmissionError) -> Self {
        Self::Admission(error)
    }
}

impl From<ComponentGraphPrincipalTemplateError> for ComponentGraphNodeReplacementTemplateError {
    fn from(error: ComponentGraphPrincipalTemplateError) -> Self {
        Self::Principal(error)
    }
}

/// Required isolation for every graph node.
///
/// A lifecycle adapter interpreting this value must allocate a fresh component
/// incarnation, CSpace, Task, and arena for the node. This enum is a semantic
/// requirement, not any of those boot-local identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphPrincipalIsolation {
    FreshPerNode,
}

/// Exact immutable lifecycle inputs for one separately admitted node.
pub struct ComponentGraphNodePrincipalTemplate {
    id: ComponentGraphNodeId,
    label: String,
    artifact: ComponentIdentity,
    profile: ProfileIdentity,
    world: String,
    nesting: ComponentGraphNesting,
    limits: InstanceLimits,
    budget: ComponentGraphNodeBudget,
}

impl ComponentGraphNodePrincipalTemplate {
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

    pub const fn isolation(&self) -> ComponentGraphPrincipalIsolation {
        ComponentGraphPrincipalIsolation::FreshPerNode
    }

    pub const fn memory_bytes(&self) -> u64 {
        self.budget.memory_bytes
    }

    pub const fn fuel_limit(&self) -> u64 {
        self.budget.total_fuel
    }

    pub const fn poll_quantum(&self) -> u64 {
        self.budget.poll_quantum
    }

    pub const fn resource_slot_limit(&self) -> u64 {
        self.budget.resource_slots
    }
}

impl fmt::Debug for ComponentGraphNodePrincipalTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphNodePrincipalTemplate")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("artifact", &self.artifact)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("nesting", &self.nesting)
            .field("limits", &self.limits)
            .field("budget", &self.budget)
            .field("isolation", &self.isolation())
            .finish()
    }
}

/// Immutable command-layer envelope around one atomically admitted graph.
///
/// Construction and [`Self::revalidate`] re-decode every artifact through the
/// sealed admission record. The template never becomes executable in C6.3.
///
/// ```compile_fail
/// use vibeos_component_command::ComponentGraphPrincipalTemplate;
/// fn cannot_run(template: &ComponentGraphPrincipalTemplate) { template.run(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_command::ComponentGraphPrincipalTemplate;
/// fn cannot_plan(template: &ComponentGraphPrincipalTemplate) { let _ = template.plan(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_command::ComponentGraphPrincipalTemplate;
/// fn cannot_instantiate(template: &ComponentGraphPrincipalTemplate) {
///     template.instantiate();
/// }
/// ```
pub struct ComponentGraphPrincipalTemplate {
    admitted: Arc<AdmittedComponentGraph>,
    profile: ProfileIdentity,
    account: ComponentGraphAccount,
    principals: Vec<ComponentGraphNodePrincipalTemplate>,
}

impl ComponentGraphPrincipalTemplate {
    /// Revalidate the complete admitted graph before projecting any lifecycle
    /// metadata. No runtime allocation or principal identity is created.
    pub fn new(
        admitted: Arc<AdmittedComponentGraph>,
    ) -> Result<Self, ComponentGraphPrincipalTemplateError> {
        admitted.revalidate()?;
        let manifest = admitted.manifest();
        let mut principals = Vec::new();
        principals
            .try_reserve_exact(manifest.nodes().len())
            .map_err(|_| ComponentGraphPrincipalTemplateError::Allocation)?;
        for node in manifest.nodes() {
            principals.push(ComponentGraphNodePrincipalTemplate {
                id: node.id(),
                label: copied(node.label())?,
                artifact: node.artifact(),
                profile: node.profile(),
                world: copied(node.world())?,
                nesting: node.nesting(),
                limits: node.limits(),
                budget: node.budget(),
            });
        }
        let profile = manifest.profile();
        let account = manifest.account();
        let template = Self {
            admitted,
            profile,
            account,
            principals,
        };
        template.ensure_exact_projection()?;
        Ok(template)
    }

    pub fn admitted_graph(&self) -> &AdmittedComponentGraph {
        &self.admitted
    }

    pub fn manifest(&self) -> &ComponentGraphManifest {
        self.admitted.manifest()
    }

    pub fn grants(&self) -> &[ComponentGraphAuthorityGrant] {
        self.admitted.grants()
    }

    /// Validator-derived, capability-free resource edges sealed by graph
    /// admission. Construction and [`Self::revalidate`] prove these values
    /// again from fresh nominal provenance before exposing them here.
    pub fn resource_edges(&self) -> &[ComponentGraphResourceEdgeManifest] {
        self.admitted.manifest().resource_edges()
    }

    /// Freshly revalidated, capability-free async evidence for internal graph
    /// edges. These records contain only graph-local endpoints and bounded
    /// exact shape counts; they are not wake or execution authority.
    pub fn async_edges(&self) -> &[ComponentGraphAsyncEdgeManifest] {
        self.admitted.manifest().async_edges()
    }

    /// Build the closed C6.7 semantic information-flow diagnostic after
    /// freshly revalidating both the admission record and this command-layer
    /// projection. The returned owned report retains neither graph ordinals
    /// nor the admitted graph and remains permanently non-executable.
    pub fn information_flow(
        &self,
    ) -> Result<ComponentGraphInformationFlow, ComponentGraphInformationFlowError> {
        self.revalidate()
            .map_err(|_| ComponentGraphInformationFlowError::RevalidationFailed)?;
        self.admitted.information_flow()
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn account(&self) -> ComponentGraphAccount {
        self.account
    }

    pub fn principals(&self) -> &[ComponentGraphNodePrincipalTemplate] {
        &self.principals
    }

    pub fn principal(
        &self,
        node: ComponentGraphNodeId,
    ) -> Option<&ComponentGraphNodePrincipalTemplate> {
        self.principals
            .get(usize::from(node.index()))
            .filter(|principal| principal.id == node)
    }

    /// C6.3 preserves guest execution as ValidationOnly. A kernel adapter may
    /// allocate and supervise the fresh per-node lifecycle envelopes required
    /// by [`ComponentGraphPrincipalIsolation`], but it must not decode for
    /// execution, instantiate, or call guest code from this template.
    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Revalidate immutable bytes and prove this cached command-layer
    /// projection still matches the complete admitted manifest exactly.
    pub fn revalidate(&self) -> Result<(), ComponentGraphPrincipalTemplateError> {
        self.admitted.revalidate()?;
        self.ensure_exact_projection()
    }

    /// Build a checked semantic RuntimeUnavailable report for the current
    /// inert template. This does not publish or authorize a terminal event: a
    /// kernel lifecycle adapter may publish the value only after it owns the
    /// matching node's teardown receipt. Since no guest runtime started, fuel
    /// and resource usage are zero.
    pub fn runtime_unavailable_report(
        &self,
        node: ComponentGraphNodeId,
    ) -> Result<ComponentGraphNodeTerminalReport, ComponentGraphNodeReportError> {
        self.try_terminal_report(
            node,
            ComponentGraphNodeTerminal::RuntimeUnavailable,
            0,
            0,
            0,
        )
    }

    /// Build a deterministic RuntimeUnavailable report after a kernel
    /// supervisor has pre-established an admitted resource route and then
    /// torn down every live resource slot without starting guest execution.
    ///
    /// `peak_resource_slots` must be the supervisor's measured, positive peak;
    /// declaration counts are not substituted for live-slot observations. The
    /// node must be an endpoint of a sealed resource edge and the observation
    /// must fit its exact manifest ceiling. This builder neither proves the
    /// supervisor operation nor authorizes publication: a kernel adapter must
    /// retain the matching route and teardown receipts. Fuel and live slots
    /// remain fixed at zero, and [`Self::runtime_ready`] remains false.
    ///
    /// The ordinary [`Self::runtime_unavailable_report`] path remains stricter
    /// and continues requiring a zero peak.
    pub fn supervisor_prepared_resource_unavailable_report(
        &self,
        node: ComponentGraphNodeId,
        peak_resource_slots: u64,
    ) -> Result<ComponentGraphNodeTerminalReport, ComponentGraphNodeReportError> {
        let principal = self
            .principal(node)
            .ok_or(ComponentGraphNodeReportError::UnknownNode { node })?;
        if !self.resource_edges().iter().any(|route| {
            route.edge().source().node() == node || route.edge().target().node() == node
        }) {
            return Err(ComponentGraphNodeReportError::ResourceEdgeRequired { node });
        }
        if peak_resource_slots == 0 {
            return Err(ComponentGraphNodeReportError::SupervisorPreparedPeakRequired);
        }
        if peak_resource_slots > principal.resource_slot_limit() {
            return Err(ComponentGraphNodeReportError::ResourceLimitExceeded);
        }
        Ok(ComponentGraphNodeTerminalReport {
            node,
            terminal: ComponentGraphNodeTerminal::RuntimeUnavailable,
            fuel: ComponentGraphNodeFuelAccount {
                limit: principal.fuel_limit(),
                consumed: 0,
            },
            resources: ComponentGraphNodeResourceAccount {
                declared_types: principal.budget.resource_types,
                slot_limit: principal.resource_slot_limit(),
                peak_slots: peak_resource_slots,
                live_slots: 0,
            },
        })
    }

    /// Build a deterministic RuntimeUnavailable report after a supervisor has
    /// prepared and torn down bounded state for an admitted async edge without
    /// starting guest execution.
    ///
    /// Only an endpoint of a freshly sealed async edge may report a positive
    /// observed resource-slot peak. Fuel and live slots remain zero, and this
    /// method never changes [`Self::runtime_ready`].
    pub fn supervisor_prepared_async_unavailable_report(
        &self,
        node: ComponentGraphNodeId,
        peak_resource_slots: u64,
    ) -> Result<ComponentGraphNodeTerminalReport, ComponentGraphNodeReportError> {
        let principal = self
            .principal(node)
            .ok_or(ComponentGraphNodeReportError::UnknownNode { node })?;
        if !self.async_edges().iter().any(|route| {
            route.edge().source().node() == node || route.edge().target().node() == node
        }) {
            return Err(ComponentGraphNodeReportError::AsyncEdgeRequired { node });
        }
        if peak_resource_slots == 0 {
            return Err(ComponentGraphNodeReportError::SupervisorPreparedPeakRequired);
        }
        if peak_resource_slots > principal.resource_slot_limit() {
            return Err(ComponentGraphNodeReportError::ResourceLimitExceeded);
        }
        Ok(ComponentGraphNodeTerminalReport {
            node,
            terminal: ComponentGraphNodeTerminal::RuntimeUnavailable,
            fuel: ComponentGraphNodeFuelAccount {
                limit: principal.fuel_limit(),
                consumed: 0,
            },
            resources: ComponentGraphNodeResourceAccount {
                declared_types: principal.budget.resource_types,
                slot_limit: principal.resource_slot_limit(),
                peak_slots: peak_resource_slots,
                live_slots: 0,
            },
        })
    }

    fn try_terminal_report(
        &self,
        node: ComponentGraphNodeId,
        terminal: ComponentGraphNodeTerminal,
        fuel_consumed: u64,
        peak_resource_slots: u64,
        live_resource_slots: u64,
    ) -> Result<ComponentGraphNodeTerminalReport, ComponentGraphNodeReportError> {
        let principal = self
            .principal(node)
            .ok_or(ComponentGraphNodeReportError::UnknownNode { node })?;
        if fuel_consumed > principal.fuel_limit() {
            return Err(ComponentGraphNodeReportError::FuelLimitExceeded);
        }
        if peak_resource_slots > principal.resource_slot_limit() {
            return Err(ComponentGraphNodeReportError::ResourceLimitExceeded);
        }
        if live_resource_slots > peak_resource_slots {
            return Err(ComponentGraphNodeReportError::InvalidResourceAccount);
        }
        if !self.runtime_ready()
            && (terminal != ComponentGraphNodeTerminal::RuntimeUnavailable
                || fuel_consumed != 0
                || peak_resource_slots != 0
                || live_resource_slots != 0)
        {
            return Err(ComponentGraphNodeReportError::RuntimeUnavailableRequired);
        }
        Ok(ComponentGraphNodeTerminalReport {
            node,
            terminal,
            fuel: ComponentGraphNodeFuelAccount {
                limit: principal.fuel_limit(),
                consumed: fuel_consumed,
            },
            resources: ComponentGraphNodeResourceAccount {
                declared_types: principal.budget.resource_types,
                slot_limit: principal.resource_slot_limit(),
                peak_slots: peak_resource_slots,
                live_slots: live_resource_slots,
            },
        })
    }

    fn ensure_exact_projection(&self) -> Result<(), ComponentGraphPrincipalTemplateError> {
        let manifest = self.admitted.manifest();
        if self.profile != manifest.profile()
            || self.account != manifest.account()
            || self.principals.len() != manifest.nodes().len()
            || self
                .principals
                .iter()
                .zip(manifest.nodes())
                .any(|(principal, node)| {
                    principal.id != node.id()
                        || principal.label != node.label()
                        || principal.artifact != node.artifact()
                        || principal.profile != node.profile()
                        || principal.world != node.world()
                        || principal.nesting != node.nesting()
                        || principal.limits != node.limits()
                        || principal.budget != node.budget()
                })
            || manifest
                .async_edges()
                .iter()
                .enumerate()
                .any(|(index, route)| {
                    (route.async_functions() == 0 && route.streams() == 0 && route.futures() == 0)
                        || route.async_functions() > PROFILE_1_LIMITS.max_component_definitions
                        || route.streams() > PROFILE_1_LIMITS.max_component_definitions
                        || route.futures() > PROFILE_1_LIMITS.max_component_definitions
                        || manifest.async_edges()[..index]
                            .iter()
                            .any(|earlier| earlier.edge() == route.edge())
                        || !manifest.edges().contains(&route.edge())
                        || self.principal(route.edge().source().node()).is_none()
                        || self.principal(route.edge().target().node()).is_none()
                })
            || manifest
                .resource_edges()
                .iter()
                .enumerate()
                .any(|(index, route)| {
                    route.resources().is_empty()
                        || manifest.resource_edges()[..index]
                            .iter()
                            .any(|earlier| earlier.edge() == route.edge())
                        || !manifest.edges().contains(&route.edge())
                        || self.principal(route.edge().source().node()).is_none()
                        || self.principal(route.edge().target().node()).is_none()
                        || route.resources().windows(2).any(|pair| pair[0] >= pair[1])
                })
        {
            return Err(ComponentGraphPrincipalTemplateError::ProjectionMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ComponentGraphPrincipalTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphPrincipalTemplate")
            .field("admitted_graph", &"<redacted>")
            .field("profile", &self.profile)
            .field("account", &self.account)
            .field("principals", &self.principals)
            .field("async_edges", &self.async_edges())
            .field("runtime_ready", &self.runtime_ready())
            .finish()
    }
}

/// Immutable command-layer envelope for one sealed C6.6 node replacement.
///
/// The two graph projections and every incident-edge action remain inert.
/// Construction and [`Self::revalidate`] freshly prove the underlying graph
/// admission records; only a kernel supervisor holding the exact live
/// lifecycle identities may interpret `RecreateFresh`. This type has no
/// ambient lookup, capability transfer, guest execution, or publication API.
///
/// ```compile_fail
/// use vibeos_component_command::ComponentGraphNodeReplacementTemplate;
/// fn cannot_run(template: &ComponentGraphNodeReplacementTemplate) { template.run(); }
/// ```
///
/// ```compile_fail
/// use vibeos_component_command::ComponentGraphNodeReplacementTemplate;
/// fn cannot_instantiate(template: &ComponentGraphNodeReplacementTemplate) {
///     template.instantiate();
/// }
/// ```
pub struct ComponentGraphNodeReplacementTemplate {
    admitted: Arc<AdmittedComponentGraphReplacement>,
    current: ComponentGraphPrincipalTemplate,
    candidate: ComponentGraphPrincipalTemplate,
    target: ComponentGraphNodeId,
    max_replacements: u16,
    incident_edges: Vec<ComponentGraphReplacementEdgePolicy>,
    transient_account: ComponentGraphAccount,
}

impl ComponentGraphNodeReplacementTemplate {
    /// Revalidate both complete graphs and the sealed replacement relation
    /// before projecting any lifecycle metadata.
    pub fn new(
        admitted: Arc<AdmittedComponentGraphReplacement>,
    ) -> Result<Self, ComponentGraphNodeReplacementTemplateError> {
        admitted.revalidate()?;
        let current =
            ComponentGraphPrincipalTemplate::new(Arc::clone(admitted.current_graph_arc()))?;
        let candidate =
            ComponentGraphPrincipalTemplate::new(Arc::clone(admitted.candidate_graph_arc()))?;
        let manifest = admitted.manifest();
        let mut incident_edges = Vec::new();
        incident_edges
            .try_reserve_exact(manifest.incident_edges().len())
            .map_err(|_| ComponentGraphNodeReplacementTemplateError::Allocation)?;
        incident_edges.extend_from_slice(manifest.incident_edges());
        let template = Self {
            target: manifest.target(),
            max_replacements: manifest.max_replacements(),
            transient_account: manifest.transient_account(),
            admitted,
            current,
            candidate,
            incident_edges,
        };
        template.ensure_exact_projection()?;
        Ok(template)
    }

    pub fn admitted_replacement(&self) -> &AdmittedComponentGraphReplacement {
        &self.admitted
    }

    pub const fn target(&self) -> ComponentGraphNodeId {
        self.target
    }

    pub const fn max_replacements(&self) -> u16 {
        self.max_replacements
    }

    pub fn incident_edges(&self) -> &[ComponentGraphReplacementEdgePolicy] {
        &self.incident_edges
    }

    pub const fn transient_account(&self) -> ComponentGraphAccount {
        self.transient_account
    }

    pub const fn current_graph(&self) -> &ComponentGraphPrincipalTemplate {
        &self.current
    }

    pub const fn candidate_graph(&self) -> &ComponentGraphPrincipalTemplate {
        &self.candidate
    }

    pub fn current_principal(&self) -> Option<&ComponentGraphNodePrincipalTemplate> {
        self.current.principal(self.target)
    }

    pub fn candidate_principal(&self) -> Option<&ComponentGraphNodePrincipalTemplate> {
        self.candidate.principal(self.target)
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Freshly revalidate both graph bytes and prove the cached command-layer
    /// replacement projection remains exact.
    pub fn revalidate(&self) -> Result<(), ComponentGraphNodeReplacementTemplateError> {
        self.admitted.revalidate()?;
        self.current.revalidate()?;
        self.candidate.revalidate()?;
        self.ensure_exact_projection()
    }

    fn ensure_exact_projection(&self) -> Result<(), ComponentGraphNodeReplacementTemplateError> {
        let manifest = self.admitted.manifest();
        if self.target != manifest.target()
            || self.max_replacements != 1
            || self.max_replacements != manifest.max_replacements()
            || self.incident_edges != manifest.incident_edges()
            || self.transient_account != manifest.transient_account()
            || !Arc::ptr_eq(&self.current.admitted, self.admitted.current_graph_arc())
            || !Arc::ptr_eq(
                &self.candidate.admitted,
                self.admitted.candidate_graph_arc(),
            )
            || self.current.principal(self.target).is_none()
            || self.candidate.principal(self.target).is_none()
            || self.admitted.runtime_ready()
            || self.current.runtime_ready()
            || self.candidate.runtime_ready()
            || self.runtime_ready()
        {
            return Err(ComponentGraphNodeReplacementTemplateError::ProjectionMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ComponentGraphNodeReplacementTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphNodeReplacementTemplate")
            .field("admitted_replacement", &"<redacted>")
            .field("current_graph", &"<redacted>")
            .field("candidate_graph", &"<redacted>")
            .field("target", &self.target)
            .field("max_replacements", &self.max_replacements)
            .field("incident_edges", &self.incident_edges)
            .field("transient_account", &self.transient_account)
            .field("runtime_ready", &self.runtime_ready())
            .finish()
    }
}

/// Stable semantic terminal for one graph node.
///
/// No variant carries a Task, generation, capability, resource handle, arena,
/// pointer, or backend-specific object identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphNodeTerminal {
    Success,
    Returned(u8),
    Usage,
    Denied,
    RuntimeUnavailable,
    BackendFault,
    BudgetExceeded,
    Cancelled,
    RunnerFault,
    Trapped(TrapCode),
}

/// Checked fuel counters for one node's terminal report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphNodeFuelAccount {
    limit: u64,
    consumed: u64,
}

impl ComponentGraphNodeFuelAccount {
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    pub const fn consumed(&self) -> u64 {
        self.consumed
    }
}

/// Checked resource-table counters for one node's terminal report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphNodeResourceAccount {
    declared_types: u64,
    slot_limit: u64,
    peak_slots: u64,
    live_slots: u64,
}

impl ComponentGraphNodeResourceAccount {
    pub const fn declared_types(&self) -> u64 {
        self.declared_types
    }

    pub const fn slot_limit(&self) -> u64 {
        self.slot_limit
    }

    pub const fn peak_slots(&self) -> u64 {
        self.peak_slots
    }

    pub const fn live_slots(&self) -> u64 {
        self.live_slots
    }
}

/// Bounded, semantic terminal report for one exact graph-local node.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentGraphNodeTerminalReport {
    node: ComponentGraphNodeId,
    terminal: ComponentGraphNodeTerminal,
    fuel: ComponentGraphNodeFuelAccount,
    resources: ComponentGraphNodeResourceAccount,
}

impl ComponentGraphNodeTerminalReport {
    pub const fn node(&self) -> ComponentGraphNodeId {
        self.node
    }

    pub const fn terminal(&self) -> ComponentGraphNodeTerminal {
        self.terminal
    }

    pub const fn fuel(&self) -> ComponentGraphNodeFuelAccount {
        self.fuel
    }

    pub const fn resources(&self) -> ComponentGraphNodeResourceAccount {
        self.resources
    }
}

impl fmt::Debug for ComponentGraphNodeTerminalReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphNodeTerminalReport")
            .field("node", &self.node)
            .field("terminal", &self.terminal)
            .field("fuel", &self.fuel)
            .field("resources", &self.resources)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphNodeReportError {
    UnknownNode { node: ComponentGraphNodeId },
    AsyncEdgeRequired { node: ComponentGraphNodeId },
    ResourceEdgeRequired { node: ComponentGraphNodeId },
    SupervisorPreparedPeakRequired,
    FuelLimitExceeded,
    ResourceLimitExceeded,
    InvalidResourceAccount,
    RuntimeUnavailableRequired,
}

fn copied(value: &str) -> Result<String, ComponentGraphPrincipalTemplateError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| ComponentGraphPrincipalTemplateError::Allocation)?;
    result.push_str(value);
    Ok(result)
}
