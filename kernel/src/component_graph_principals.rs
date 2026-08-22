//! Fresh, separately supervised kernel principals for one admitted Component graph.
//!
//! C6.3 deliberately stops at the lifecycle boundary. Every node receives a
//! distinct owner, tracked arena, registry generation, CSpace, task, resource
//! table, and fuel envelope, but its payload never decodes, instantiates, or
//! calls guest code. The only successful terminal is therefore the semantic
//! `RuntimeUnavailable` report supplied by the sealed command template.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use vibeos_component_command::{
    ComponentGraphNodeTerminal, ComponentGraphNodeTerminalReport, ComponentGraphPrincipalIsolation,
    ComponentGraphPrincipalTemplate,
};
use vibeos_component_runtime::graph::ComponentGraphNodeId;
use vibeos_component_runtime::resource::ResourceTable;
#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
use vibeos_component_runtime::{graph::ComponentGraphNesting, world::WorldContract};

#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
use vibeos_component_admission::{
    admit_component_graph, ArtifactTrust, CallerAuthority, ComponentArtifact,
    ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy, ComponentGraphNodeAdmissionPolicy,
    InstanceLimits, ProfileIdentity,
};

use crate::exec::{PreparedTaskBatch, TaskHandle, TaskState};
use crate::heap::{AllocationDomain, FreshDomainBatchError, OwnerId};
use crate::instance::{
    InstancePayload, InstanceSpace, InstanceToken, TerminalRetireKind, MAX_COMPONENT_INSTANCES,
};
use crate::sync::SpinLock;
use crate::HEAP;

/// Audited non-guest storage allowance for one C6.3 node lifecycle.
///
/// This frozen 64-KiB charge covers the managed task future, registry payload,
/// empty resource table, and bounded lifecycle bookkeeping allocated in the
/// node's tracked arena. It is added with `checked_add` to the owner quota. The
/// admitted guest-memory ceiling remains a separate field in the payload and
/// is never enlarged by this allowance.
pub const COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES: usize = 64 * 1024;

const PRINCIPAL_CSPACE_NAME: &str = "wasm-graph-principal";
const PRINCIPAL_TASK_NAME: &str = "wasm-graph-principal";
const RUNTIME_UNAVAILABLE_COMPLETION: u64 = 0x5649_4245_4336_0300;
const INVALID_ENVELOPE_COMPLETION: u64 = 0x5649_4245_4336_FFFF;

static NEXT_RESOURCE_GENERATION: AtomicU64 = AtomicU64::new(1);

/// A public lifecycle failure contains only a semantic graph-local node and a
/// bounded classification. It never formats a TaskId, owner, arena, registry
/// token, CSpace identity/incarnation, resource handle/generation, or Cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphPrincipalLifecycleError {
    Revalidation,
    AuthorityBearingGraph,
    ExecutableTemplate,
    InvalidPrincipalSet,
    BudgetOverflow { node: ComponentGraphNodeId },
    ResourceGenerationExhausted,
    ResourceTableUnavailable { node: ComponentGraphNodeId },
    Allocation,
    DomainBatchUnavailable,
    RegistryReservation,
    SchedulerReservation,
    PayloadInstall { node: ComponentGraphNodeId },
    RegistryBinding,
    AtomicPublication,
    SupervisorUnavailable,
    TaskTerminal { node: ComponentGraphNodeId },
    TerminalTeardown { node: ComponentGraphNodeId },
    SemanticReport { node: ComponentGraphNodeId },
    UnpublishedCleanup,
}

impl fmt::Display for ComponentGraphPrincipalLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Revalidation => "component graph principal revalidation failed",
            Self::AuthorityBearingGraph => {
                "C6.3 cannot materialize a graph with unresolved live authority grants"
            }
            Self::ExecutableTemplate => "C6.3 accepts only a validation-only graph template",
            Self::InvalidPrincipalSet => "component graph principal set is invalid",
            Self::BudgetOverflow { .. } => "component graph principal budget overflowed",
            Self::ResourceGenerationExhausted => {
                "component graph resource generation space is exhausted"
            }
            Self::ResourceTableUnavailable { .. } => {
                "component graph resource table could not be created"
            }
            Self::Allocation => "component graph lifecycle metadata allocation failed",
            Self::DomainBatchUnavailable => {
                "component graph allocation domains could not be created atomically"
            }
            Self::RegistryReservation => {
                "component graph registry slots could not be reserved atomically"
            }
            Self::SchedulerReservation => {
                "component graph scheduler publication could not be reserved atomically"
            }
            Self::PayloadInstall { .. } => "component graph payload installation failed",
            Self::RegistryBinding => "component graph task binding failed",
            Self::AtomicPublication => "component graph task publication failed",
            Self::SupervisorUnavailable => "component graph supervisor did not terminate exactly",
            Self::TaskTerminal { .. } => "component graph node did not terminate exactly",
            Self::TerminalTeardown { .. } => "component graph node teardown failed",
            Self::SemanticReport { .. } => "component graph semantic report is invalid",
            Self::UnpublishedCleanup => "component graph unpublished cleanup failed",
        })
    }
}

/// Immutable semantic results published only after every node has completed
/// exact registry finalization and allocator retirement.
pub struct ComponentGraphPrincipalReports {
    reports: Vec<ComponentGraphNodeTerminalReport>,
}

struct PrincipalCompletion {
    result: SpinLock<
        Option<Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError>>,
    >,
}

impl PrincipalCompletion {
    const fn new() -> Self {
        Self {
            result: SpinLock::new(None),
        }
    }

    fn publish(
        &self,
        result: Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError>,
    ) {
        let mut slot = self.result.lock();
        assert!(slot.is_none(), "graph principal result published twice");
        *slot = Some(result);
    }

    fn take(
        &self,
    ) -> Option<Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError>> {
        self.result.lock().take()
    }
}

/// Non-authoritative observation handle for one atomically published graph.
///
/// Dropping this handle never cancels a node or its SYSTEM supervisor. The
/// scheduler-owned supervisor retains the only node TaskHandles and completes
/// exact teardown even when the caller loses interest in the result.
pub struct ComponentGraphPrincipalRun {
    supervisor: TaskHandle,
    completion: Arc<PrincipalCompletion>,
}

impl ComponentGraphPrincipalRun {
    pub async fn wait(
        self,
    ) -> Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError> {
        let exit = self.supervisor.join().await;
        if exit.state() != TaskState::Exited {
            return Err(ComponentGraphPrincipalLifecycleError::SupervisorUnavailable);
        }
        self.completion.take().unwrap_or(Err(
            ComponentGraphPrincipalLifecycleError::SupervisorUnavailable,
        ))
    }
}

impl fmt::Debug for ComponentGraphPrincipalRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphPrincipalRun")
            .field("supervisor_state", &self.supervisor.state())
            .finish_non_exhaustive()
    }
}

impl ComponentGraphPrincipalReports {
    pub fn nodes(&self) -> &[ComponentGraphNodeTerminalReport] {
        &self.reports
    }

    pub fn node(&self, node: ComponentGraphNodeId) -> Option<&ComponentGraphNodeTerminalReport> {
        self.reports.iter().find(|report| report.node() == node)
    }
}

impl fmt::Debug for ComponentGraphPrincipalReports {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphPrincipalReports")
            .field("nodes", &self.reports)
            .finish()
    }
}

#[derive(Clone, Copy)]
struct PrincipalPlan {
    node: ComponentGraphNodeId,
    owner_quota: usize,
    guest_memory_limit: usize,
    fuel_limit: u64,
    poll_quantum: u64,
    resource_types: u64,
    resource_slots: u16,
    resource_generation: u64,
}

struct PrincipalSupervisor {
    plans: Vec<PrincipalPlan>,
    tokens: Vec<InstanceToken>,
    handles: Vec<TaskHandle>,
    states: Vec<TaskState>,
    teardown: Vec<PrincipalTeardownReceipt>,
    reports: Vec<ComponentGraphNodeTerminalReport>,
    completion: Arc<PrincipalCompletion>,
}

#[derive(Clone, Copy)]
struct PrincipalTeardownReceipt {
    node: ComponentGraphNodeId,
}

impl PrincipalSupervisor {
    async fn run(mut self) {
        for handle in &self.handles {
            self.states.push(handle.join().await.state());
        }
        let result = finalize_all(
            &self.plans,
            &self.tokens,
            &self.handles,
            &self.states,
            &mut self.teardown,
        )
        .and_then(|()| {
            publish_semantic_reports(
                &self.plans,
                &self.teardown,
                core::mem::take(&mut self.reports),
            )
        });
        self.completion.publish(result);
    }
}

struct PrincipalPayload {
    resources: ResourceTable<()>,
    fuel: PrincipalFuelEnvelope,
    guest_memory_limit: usize,
    completed: bool,
}

#[derive(Clone, Copy)]
struct PrincipalFuelEnvelope {
    limit: u64,
    poll_quantum: u64,
    consumed: u64,
}

impl PrincipalPayload {
    fn new(plan: PrincipalPlan, resources: ResourceTable<()>) -> Self {
        Self {
            resources,
            fuel: PrincipalFuelEnvelope {
                limit: plan.fuel_limit,
                poll_quantum: plan.poll_quantum,
                consumed: 0,
            },
            guest_memory_limit: plan.guest_memory_limit,
            completed: false,
        }
    }

    fn runtime_unavailable_completion(&mut self) -> u64 {
        let pristine = !self.completed
            && self.resources.is_empty()
            && self.fuel.consumed == 0
            && self.fuel.limit != 0
            && self.fuel.poll_quantum != 0
            && self.fuel.poll_quantum <= self.fuel.limit
            && self.guest_memory_limit != 0;
        if !pristine {
            return INVALID_ENVELOPE_COMPLETION;
        }
        self.completed = true;
        RUNTIME_UNAVAILABLE_COMPLETION
    }
}

impl Drop for PrincipalPayload {
    fn drop(&mut self) {
        debug_assert!(self.resources.is_empty());
        debug_assert_eq!(self.fuel.consumed, 0);
    }
}

// SAFETY: the payload owns all of its arena-local state. It retains no Space,
// CSpace guard, capability, pointer, reference, waker, external registration,
// or other ownership across a quantum. Its only quantum inspects bounded local
// counters and returns immediately; Drop is bounded and non-reentrant.
unsafe impl InstancePayload for PrincipalPayload {
    fn poll_quantum(&mut self, _space: &InstanceSpace, _context: &mut Context<'_>) -> Poll<u64> {
        Poll::Ready(self.runtime_unavailable_completion())
    }
}

struct PrincipalTask {
    token: InstanceToken,
}

impl Future for PrincipalTask {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            let _ = super::component_instances::registry().quarantine(self.token);
            return Poll::Ready(());
        };
        if witness.instance_token() != Some(self.token) {
            let _ = super::component_instances::registry().quarantine(self.token);
            return Poll::Ready(());
        }
        match unsafe { super::component_instances::registry().poll_payload(witness, context) } {
            Ok(Poll::Ready(_)) => Poll::Ready(()),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => {
                let _ = super::component_instances::registry().quarantine(self.token);
                Poll::Ready(())
            }
        }
    }
}

const _: () = assert!(core::mem::size_of::<PrincipalTask>() <= 32);

fn revalidate_template(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let result = template
        .revalidate()
        .map_err(|_| ComponentGraphPrincipalLifecycleError::Revalidation);
    system.restore();
    result?;
    if !template.grants().is_empty() {
        return Err(ComponentGraphPrincipalLifecycleError::AuthorityBearingGraph);
    }
    if template.runtime_ready() {
        return Err(ComponentGraphPrincipalLifecycleError::ExecutableTemplate);
    }
    Ok(())
}

fn checked_owner_quota(guest_memory_limit: usize) -> Option<usize> {
    guest_memory_limit.checked_add(COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES)
}

fn reserve_resource_generations(
    count: usize,
) -> Result<u64, ComponentGraphPrincipalLifecycleError> {
    let count = u64::try_from(count)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;
    NEXT_RESOURCE_GENERATION
        .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            next.checked_add(count)
        })
        .map_err(|_| ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)
}

fn checked_plan(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<Vec<PrincipalPlan>, ComponentGraphPrincipalLifecycleError> {
    let principals = template.principals();
    if principals.is_empty() || principals.len() > MAX_COMPONENT_INSTANCES {
        return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
    }
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut plans = Vec::new();
    if plans.try_reserve_exact(principals.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for (index, principal) in principals.iter().enumerate() {
        let expected = u16::try_from(index).ok().map(ComponentGraphNodeId::new);
        if expected != Some(principal.id())
            || principal.isolation() != ComponentGraphPrincipalIsolation::FreshPerNode
        {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
        }
        let guest_memory_limit = match usize::try_from(principal.memory_bytes()) {
            Ok(limit) if limit != 0 => limit,
            _ => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                    node: principal.id(),
                });
            }
        };
        let Some(owner_quota) = checked_owner_quota(guest_memory_limit) else {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                node: principal.id(),
            });
        };
        let resource_slots = match u16::try_from(principal.resource_slot_limit()) {
            Ok(slots) if slots != 0 => slots,
            _ => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                    node: principal.id(),
                });
            }
        };
        if principal.fuel_limit() == 0
            || principal.poll_quantum() == 0
            || principal.poll_quantum() > principal.fuel_limit()
        {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                node: principal.id(),
            });
        }
        plans.push(PrincipalPlan {
            node: principal.id(),
            owner_quota,
            guest_memory_limit,
            fuel_limit: principal.fuel_limit(),
            poll_quantum: principal.poll_quantum(),
            resource_types: principal.budget().resource_types,
            resource_slots,
            resource_generation: 0,
        });
    }
    system.restore();
    Ok(plans)
}

fn assign_resource_generations(
    plans: &mut [PrincipalPlan],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let generation = reserve_resource_generations(plans.len())?;
    for (index, plan) in plans.iter_mut().enumerate() {
        plan.resource_generation = generation
            .checked_add(index as u64)
            .ok_or(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;
    }
    Ok(())
}

fn prepare_resource_tables(
    plans: &[PrincipalPlan],
) -> Result<Vec<Option<ResourceTable<()>>>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut tables = Vec::new();
    if tables.try_reserve_exact(plans.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for plan in plans {
        let table = match ResourceTable::new(plan.resource_generation, plan.resource_slots) {
            Ok(table) => table,
            Err(_) => {
                system.restore();
                return Err(
                    ComponentGraphPrincipalLifecycleError::ResourceTableUnavailable {
                        node: plan.node,
                    },
                );
            }
        };
        tables.push(Some(table));
    }
    system.restore();
    Ok(tables)
}

fn release_empty_domain(domain: AllocationDomain) -> bool {
    HEAP.retire_empty_domains_batch(core::slice::from_ref(&domain))
        .is_ok_and(|outcome| outcome.retired_count() == 1)
}

fn release_empty_domains(domains: &[AllocationDomain]) -> bool {
    HEAP.retire_empty_domains_batch(domains)
        .is_ok_and(|outcome| outcome.retired_count() == domains.len())
}

fn create_domains(
    plans: &[PrincipalPlan],
) -> Result<Vec<AllocationDomain>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut quotas = Vec::new();
    if quotas.try_reserve_exact(plans.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for plan in plans {
        quotas.push(plan.owner_quota);
    }
    let domains = HEAP
        .create_fresh_domains_batch(&quotas)
        .map_err(|error| match error {
            FreshDomainBatchError::Allocation => ComponentGraphPrincipalLifecycleError::Allocation,
            _ => ComponentGraphPrincipalLifecycleError::DomainBatchUnavailable,
        });
    system.restore();
    domains
}

fn retire_domain(domain: AllocationDomain, kind: TerminalRetireKind) -> bool {
    match kind {
        TerminalRetireKind::Normal => release_empty_domain(domain),
        TerminalRetireKind::FaultReclaimed => HEAP.unregister_owner(domain.owner).is_ok(),
    }
}

fn abort_pristine_registry_batch(
    tokens: &[InstanceToken],
    domains: &[AllocationDomain],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    // Preserve the still-Reserved registry identities if the allocator cannot
    // prove that the whole fresh domain batch is exactly empty. The exclusive
    // fresh-domain contract keeps that proof stable across the registry's
    // allocation-free abort and the all-or-none retirement commit below.
    HEAP.preflight_retire_empty_domains_batch(domains)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::UnpublishedCleanup)?;
    let aborted = super::component_instances::registry()
        .abort_reserved_batch(tokens)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::UnpublishedCleanup)?;
    if aborted.aborted_instances() != tokens.len() || !release_empty_domains(domains) {
        return Err(ComponentGraphPrincipalLifecycleError::UnpublishedCleanup);
    }
    Ok(())
}

fn reserve_registry_batch(
    domains: &[AllocationDomain],
) -> Result<Vec<InstanceToken>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut inputs = Vec::new();
    if inputs.try_reserve_exact(domains.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for domain in domains {
        inputs.push((*domain, PRINCIPAL_CSPACE_NAME));
    }
    let result = super::component_instances::registry()
        .reserve_named_batch(&inputs)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::RegistryReservation);
    system.restore();
    result
}

fn prepare_supervisor(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    reports: Vec<ComponentGraphNodeTerminalReport>,
) -> Result<
    (
        PrincipalSupervisor,
        Vec<TaskHandle>,
        Arc<PrincipalCompletion>,
    ),
    ComponentGraphPrincipalLifecycleError,
> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let completion = Arc::new(PrincipalCompletion::new());
    let mut supervisor_plans = Vec::new();
    let mut supervisor_tokens = Vec::new();
    let mut handles = Vec::new();
    let mut verification_handles = Vec::new();
    let mut states = Vec::new();
    let mut teardown = Vec::new();
    let reserved = supervisor_plans.try_reserve_exact(plans.len()).is_ok()
        && supervisor_tokens.try_reserve_exact(tokens.len()).is_ok()
        && handles.try_reserve_exact(plans.len()).is_ok()
        && verification_handles.try_reserve_exact(plans.len()).is_ok()
        && states.try_reserve_exact(plans.len()).is_ok()
        && teardown.try_reserve_exact(plans.len()).is_ok();
    if !reserved {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    supervisor_plans.extend_from_slice(plans);
    supervisor_tokens.extend_from_slice(tokens);
    let supervisor = PrincipalSupervisor {
        plans: supervisor_plans,
        tokens: supervisor_tokens,
        handles,
        states,
        teardown,
        reports,
        completion: completion.clone(),
    };
    system.restore();
    Ok((supervisor, verification_handles, completion))
}

fn publication_pairs(
    tokens: &[InstanceToken],
    domains: &[AllocationDomain],
) -> Result<Vec<(InstanceToken, AllocationDomain)>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut pairs = Vec::new();
    if pairs.try_reserve_exact(tokens.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    pairs.extend(tokens.iter().copied().zip(domains.iter().copied()));
    system.restore();
    Ok(pairs)
}

fn quarantine_all(tokens: &[InstanceToken]) {
    for token in tokens {
        let _ = super::component_instances::registry().quarantine(*token);
    }
}

fn lifecycle_invariant_failed(tokens: &[InstanceToken], message: &'static str) -> ! {
    quarantine_all(tokens);
    panic!("{message}")
}

fn install_payloads(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    tables: &mut [Option<ResourceTable<()>>],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    for ((plan, token), table) in plans.iter().zip(tokens).zip(tables) {
        let Some(resources) = table.take() else {
            let _ = super::component_instances::registry().quarantine(*token);
            return Err(ComponentGraphPrincipalLifecycleError::PayloadInstall { node: plan.node });
        };
        if unsafe {
            super::component_instances::registry()
                .install_payload(*token, || PrincipalPayload::new(*plan, resources))
        }
        .is_err()
        {
            return Err(ComponentGraphPrincipalLifecycleError::PayloadInstall { node: plan.node });
        }
    }
    Ok(())
}

fn bind_prepared_tasks(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    batch: &PreparedTaskBatch,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let handles = batch.prepared_handles();
    let bindings = batch.prepared_reclaimable_bindings();
    if handles.len() != plans.len() + 1 || bindings.len() != plans.len() {
        return Err(ComponentGraphPrincipalLifecycleError::AtomicPublication);
    }
    super::component_instances::registry()
        .bind_batch(tokens, bindings, &handles[..plans.len()])
        .map_err(|_| ComponentGraphPrincipalLifecycleError::RegistryBinding)
}

fn finalize_all(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    handles: &[TaskHandle],
    states: &[TaskState],
    teardown: &mut Vec<PrincipalTeardownReceipt>,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let mut first_error = None;
    for index in 0..plans.len() {
        let expected =
            (states[index] == TaskState::Exited).then_some(RUNTIME_UNAVAILABLE_COMPLETION);
        let finalized = unsafe {
            super::component_instances::registry().finalize_with_space_expect_completion(
                tokens[index],
                &handles[index],
                expected,
                |_space, _kind| true,
                retire_domain,
            )
        };
        let teardown_exact = finalized.as_ref().is_ok_and(|outcome| {
            outcome.revoked_capabilities == 0 && outcome.detached_completion == expected
        });
        if states[index] != TaskState::Exited || !teardown_exact {
            first_error.get_or_insert(if !teardown_exact {
                ComponentGraphPrincipalLifecycleError::TerminalTeardown {
                    node: plans[index].node,
                }
            } else {
                ComponentGraphPrincipalLifecycleError::TaskTerminal {
                    node: plans[index].node,
                }
            });
        } else {
            teardown.push(PrincipalTeardownReceipt {
                node: plans[index].node,
            });
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn semantic_report_matches_plan(
    report: &ComponentGraphNodeTerminalReport,
    plan: &PrincipalPlan,
) -> bool {
    report.node() == plan.node
        && report.terminal() == ComponentGraphNodeTerminal::RuntimeUnavailable
        && report.fuel().limit() == plan.fuel_limit
        && report.fuel().consumed() == 0
        && report.resources().declared_types() == plan.resource_types
        && report.resources().slot_limit() == u64::from(plan.resource_slots)
        && report.resources().peak_slots() == 0
        && report.resources().live_slots() == 0
}

fn precompute_semantic_reports(
    template: &ComponentGraphPrincipalTemplate,
    plans: &[PrincipalPlan],
) -> Result<Vec<ComponentGraphNodeTerminalReport>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut reports = Vec::new();
    if reports.try_reserve_exact(plans.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for plan in plans {
        let report = match template.runtime_unavailable_report(plan.node) {
            Ok(report) => report,
            Err(_) => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::SemanticReport {
                    node: plan.node,
                });
            }
        };
        if !semantic_report_matches_plan(&report, plan) {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::SemanticReport { node: plan.node });
        }
        reports.push(report);
    }
    system.restore();
    Ok(reports)
}

fn publish_semantic_reports(
    plans: &[PrincipalPlan],
    teardown: &[PrincipalTeardownReceipt],
    reports: Vec<ComponentGraphNodeTerminalReport>,
) -> Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError> {
    if teardown.len() != plans.len()
        || reports.len() != plans.len()
        || teardown
            .iter()
            .zip(plans)
            .zip(&reports)
            .any(|((receipt, plan), report)| {
                receipt.node != plan.node || !semantic_report_matches_plan(report, plan)
            })
    {
        return Err(ComponentGraphPrincipalLifecycleError::SemanticReport {
            node: plans[0].node,
        });
    }
    Ok(ComponentGraphPrincipalReports { reports })
}

/// Allocate and publish one fresh kernel principal per admitted graph node.
///
/// Revalidation and the zero-grant gate run before any owner, arena, registry
/// slot, task, or CSpace is created. The executor reservation is established
/// while the registry batch is still pristine and abortable. After the first
/// tracked future is prepared, every remaining fallible identity operation is
/// an internal invariant gate and fail-stops rather than pretending the arena
/// can be rolled back safely.
pub fn start_component_graph_principals(
    template: Arc<ComponentGraphPrincipalTemplate>,
) -> Result<ComponentGraphPrincipalRun, ComponentGraphPrincipalLifecycleError> {
    revalidate_template(&template)?;
    let mut plans = checked_plan(&template)?;
    // Freeze the only terminal values C6.3 can publish while the caller still
    // owns the template. The report buffer is SYSTEM-owned and every element is
    // copy-only semantic data. Dropping the caller Arc here ensures no admitted
    // graph, String, Vec, or other caller-arena allocation can escape into the
    // independently supervised lifecycle below.
    let reports = precompute_semantic_reports(&template, &plans)?;
    drop(template);

    // The batch remains empty and ordinarily droppable through all
    // registry/scheduler reservation failures below. Its reservation method
    // preallocates every task/handle/binding vector before publishing hidden
    // scheduler credits.
    let mut batch = PreparedTaskBatch::new();
    assign_resource_generations(&mut plans)?;
    let mut tables = prepare_resource_tables(&plans)?;
    let domains = create_domains(&plans)?;
    let tokens = match reserve_registry_batch(&domains) {
        Ok(tokens) => tokens,
        Err(error) => {
            return Err(if release_empty_domains(&domains) {
                error
            } else {
                ComponentGraphPrincipalLifecycleError::UnpublishedCleanup
            });
        }
    };
    let (mut supervisor, mut verification_handles, completion) =
        match prepare_supervisor(&plans, &tokens, reports) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(error);
            }
        };
    let pairs = match publication_pairs(&tokens, &domains) {
        Ok(pairs) => pairs,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    if batch.reserve_managed_publication(&pairs, 1).is_err() {
        drop(batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::SchedulerReservation);
    }

    for index in 0..plans.len() {
        unsafe {
            batch.prepare_managed_instance_owned(
                tokens[index],
                domains[index],
                PRINCIPAL_TASK_NAME,
                PrincipalTask {
                    token: tokens[index],
                },
            );
        }
    }
    let prepared_managed = &batch.prepared_handles()[..plans.len()];
    supervisor.handles.extend(prepared_managed.iter().cloned());
    verification_handles.extend(prepared_managed.iter().cloned());
    let completion_for_run = completion.clone();
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    batch.prepare("wasm-graph-supervisor", async move {
        supervisor.run().await;
    });
    system.restore();

    let supervisor_index = plans.len();
    if !batch.try_reserve_prepared_task_registrations(supervisor_index, 1) {
        lifecycle_invariant_failed(
            &tokens,
            "graph principal supervisor registration reservation failed",
        );
    }
    if install_payloads(&plans, &tokens, &mut tables).is_err() {
        lifecycle_invariant_failed(&tokens, "graph principal payload installation failed");
    }
    if bind_prepared_tasks(&plans, &tokens, &batch).is_err() {
        lifecycle_invariant_failed(&tokens, "graph principal atomic binding failed");
    }

    let prepared_supervisor = batch.prepared_handles()[supervisor_index].clone();
    let mut published = match unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            super::component_instances::registry().activate_batch(bindings)
        })
    } {
        Ok(handles) => handles,
        Err(_) => lifecycle_invariant_failed(
            &tokens,
            "reserved graph principal publication failed after atomic binding",
        ),
    };
    let exact = published.len() == plans.len() + 1
        && published.iter().all(TaskHandle::is_published)
        && published[..plans.len()]
            .iter()
            .zip(&verification_handles)
            .all(|(published, prepared)| {
                published.id() == prepared.id()
                    && published.allocation_domain() == prepared.allocation_domain()
                    && published.shares_status_with(prepared)
            })
        && published[supervisor_index].id() == prepared_supervisor.id()
        && published[supervisor_index].shares_status_with(&prepared_supervisor);
    if !exact {
        lifecycle_invariant_failed(&tokens, "published graph principal identities changed");
    }
    let supervisor = published
        .pop()
        .expect("validated graph publication contains its SYSTEM supervisor");
    drop(published);
    Ok(ComponentGraphPrincipalRun {
        supervisor,
        completion: completion_for_run,
    })
}

/// Convenience wrapper which observes a graph run to completion. Dropping the
/// returned future after publication drops only the observation handle; the
/// scheduler-owned SYSTEM supervisor still tears every node down.
pub async fn supervise_component_graph_principals(
    template: Arc<ComponentGraphPrincipalTemplate>,
) -> Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError> {
    start_component_graph_principals(template)?.wait().await
}

/// Allocation-free checks for the feature-gated architecture-neutral model.
/// The real registry/scheduler path is exercised by
/// [`run_qemu_acceptance`]; this early sanity helper remains directly callable
/// despite the kernel archive's `test = false` setting.
#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
pub(crate) fn run_host_model_selftest() -> bool {
    if checked_owner_quota(1) != Some(1 + COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES)
        || checked_owner_quota(usize::MAX).is_some()
    {
        return false;
    }
    let Ok(resources) = ResourceTable::new(1, 1) else {
        return false;
    };
    let mut payload = PrincipalPayload::new(
        PrincipalPlan {
            node: ComponentGraphNodeId::new(0),
            owner_quota: 1 + COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES,
            guest_memory_limit: 1,
            fuel_limit: 1,
            poll_quantum: 1,
            resource_types: 0,
            resource_slots: 1,
            resource_generation: 1,
        },
        resources,
    );
    payload.runtime_unavailable_completion() == RUNTIME_UNAVAILABLE_COMPLETION
        && payload.resources.is_empty()
        && payload.fuel.consumed == 0
        && payload.runtime_unavailable_completion() == INVALID_ENVELOPE_COMPLETION
}

#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
fn qemu_acceptance_template() -> Option<(Arc<ComponentGraphPrincipalTemplate>, AllocationDomain)> {
    const EMPTY_COMPONENT: &[u8] = b"\0asm\r\0\x01\0";
    const EMPTY_WORLD_WIT: &str = r#"
        package test:c63@1.0.0;

        world empty {}
    "#;
    const EMPTY_WORLD: &str = "test:c63/empty@1.0.0";

    let caller_quota = 2usize.checked_mul(1024)?.checked_mul(1024)?;
    let caller_domains = HEAP.create_fresh_domains_batch(&[caller_quota]).ok()?;
    let [caller_domain] = caller_domains.as_slice() else {
        let _ = release_empty_domains(&caller_domains);
        return None;
    };
    let caller_domain = *caller_domain;
    drop(caller_domains);

    // SAFETY: this acceptance task exclusively owns the unpublished fresh
    // domain. Construction and every failure-path destructor run synchronously
    // in this scope. The sole successful escape is the template under test; the
    // same non-yielding SYSTEM task immediately consumes it through `start` and
    // proves the domain empty before its first await, so no raw reclaimer can
    // race this temporary ownership proof.
    let mut caller = unsafe { crate::heap::enter_domain(caller_domain) };
    let template = (|| {
        let profile = ProfileIdentity::PROFILE_1_ASYNC;
        let root = ComponentArtifact::copy_from(EMPTY_COMPONENT, profile).ok()?;
        let child = ComponentArtifact::copy_from(EMPTY_COMPONENT, profile).ok()?;
        let exact_world = WorldContract::parse(EMPTY_WORLD_WIT, EMPTY_WORLD).ok()?;
        let nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "root-principal",
                nesting: ComponentGraphNesting::Root,
                exact_world: &exact_world,
                trust: ArtifactTrust::ImagePinned(root.identity()),
                limits: InstanceLimits {
                    memory_bytes: 64 * 1024,
                    total_fuel: 1_000,
                    poll_quantum: 100,
                    resources: 3,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "child-principal",
                nesting: ComponentGraphNesting::Nested {
                    parent: ComponentGraphNodeId::new(0),
                },
                exact_world: &exact_world,
                trust: ArtifactTrust::ImagePinned(child.identity()),
                limits: InstanceLimits {
                    memory_bytes: 128 * 1024,
                    total_fuel: 2_000,
                    poll_quantum: 200,
                    resources: 5,
                },
                interfaces: &[],
            },
        ];
        let policy = ComponentGraphAdmissionPolicy {
            name: "c63-qemu-principals",
            profile,
            nodes: &nodes,
            edges: &[],
            external_imports: &[],
            published_exports: &[],
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let admitted = admit_component_graph(
            Vec::from([root, child]),
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .ok()?;
        ComponentGraphPrincipalTemplate::new(Arc::new(admitted))
            .ok()
            .map(Arc::new)
    })();
    caller.restore();
    match template {
        Some(template) => Some((template, caller_domain)),
        None => {
            let _ = release_empty_domain(caller_domain);
            None
        }
    }
}

/// Exercise the real registry, scheduler, payload, supervisor, and teardown
/// path with a two-node, zero-edge, zero-grant admitted graph.
#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
pub(crate) async fn run_qemu_acceptance() -> bool {
    let before = super::component_instances::registry().occupancy_stats();
    if before.occupied != 0 || before.header_mismatches != 0 {
        return false;
    }
    let Some((template, caller_domain)) = qemu_acceptance_template() else {
        return false;
    };
    if !template.grants().is_empty() {
        drop(template);
        let _ = release_empty_domain(caller_domain);
        return false;
    }
    let run = match start_component_graph_principals(template) {
        Ok(run) => run,
        Err(_) => {
            let _ = release_empty_domain(caller_domain);
            return false;
        }
    };
    // This retirement precedes the first await. It proves the published SYSTEM
    // supervisor retained no Arc or transitive projection allocation from the
    // tracked caller template.
    if !release_empty_domain(caller_domain) {
        return false;
    }
    let Ok(reports) = run.wait().await else {
        return false;
    };
    if reports.nodes().len() != 2 {
        return false;
    }
    for (index, (fuel_limit, resource_slots)) in [(1_000, 3), (2_000, 5)].iter().enumerate() {
        let Some(report) = reports.node(ComponentGraphNodeId::new(index as u16)) else {
            return false;
        };
        if report.terminal() != ComponentGraphNodeTerminal::RuntimeUnavailable
            || report.fuel().limit() != *fuel_limit
            || report.fuel().consumed() != 0
            || report.resources().declared_types() != 0
            || report.resources().slot_limit() != *resource_slots
            || report.resources().peak_slots() != 0
            || report.resources().live_slots() != 0
        {
            return false;
        }
    }
    let after = super::component_instances::registry().occupancy_stats();
    after.occupied == 0 && after.header_mismatches == 0
}
