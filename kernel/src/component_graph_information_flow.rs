//! C6.7 target gate for semantic-only Component graph inspection.
//!
//! The report is constructed and rendered before any graph Task, CSpace,
//! resource table, instance, or guest execution lifecycle exists. The pinned
//! Components are validator inputs only and use the execution-disabled async
//! profile.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Write};

use vibeos_component_admission::{
    admit_component_graph, ArtifactTrust, CallerAuthority, ComponentArtifact,
    ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy, ComponentGraphInformationFlow,
    ComponentGraphNodeAdmissionPolicy, InstanceLimits, ProfileIdentity,
};
use vibeos_component_runtime::{
    graph::{
        ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
        ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
        ComponentGraphPublishedExportSpec,
    },
    world::WorldContract,
};
use vibeos_image_policy::C67_INFORMATION_FLOW_QEMU_ACCEPTANCE;

use crate::heap::AllocationDomain;
use crate::HEAP;

const C67_CALLER_QUOTA_BYTES: usize = 6 * 1024 * 1024;
const C67_RENDER_BYTES: usize = 8 * 1024;
const C67_ASYNC_CHAIN_WIT_SHA256: [u8; 32] = [
    0x05, 0x3e, 0x44, 0x72, 0x9a, 0x38, 0x75, 0x45, 0xf5, 0xdc, 0x73, 0xba, 0xc2, 0x11, 0xd3, 0x07,
    0xde, 0x74, 0x6a, 0x4c, 0xf7, 0x58, 0xd1, 0x79, 0xc0, 0xfa, 0x3c, 0xf2, 0xb9, 0xe8, 0xc5, 0xbf,
];

struct BoundedText<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> BoundedText<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.bytes[..self.len]).ok()
    }
}

impl<const N: usize> fmt::Write for BoundedText<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn edge(source: u16, target: u16) -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(source),
            ComponentGraphEntityIndex::new(0),
        ),
        ComponentGraphImportEndpoint::new(
            ComponentGraphNodeId::new(target),
            ComponentGraphEntityIndex::new(0),
        ),
    )
}

fn release_empty_domain(domain: AllocationDomain) -> bool {
    HEAP.retire_empty_domains_batch(core::slice::from_ref(&domain))
        .is_ok_and(|outcome| outcome.retired_count() == 1)
}

fn build_report() -> Option<(ComponentGraphInformationFlow, AllocationDomain)> {
    let domains = HEAP
        .create_fresh_domains_batch(&[C67_CALLER_QUOTA_BYTES])
        .ok()?;
    let [domain] = domains.as_slice() else {
        let _ = HEAP.retire_empty_domains_batch(&domains);
        return None;
    };
    let domain = *domain;
    drop(domains);

    // SAFETY: the acceptance task exclusively owns this unpublished fresh
    // domain. Construction is synchronous and the only successful escape is
    // the owned semantic report. The admitted graph and every artifact are
    // dropped before this scope is restored; the caller drops the report and
    // proves the domain empty before returning.
    let mut caller = unsafe { crate::heap::enter_domain(domain) };
    let report = (|| {
        let pin = C67_INFORMATION_FLOW_QEMU_ACCEPTANCE;
        if pin.profile() != ProfileIdentity::PROFILE_1_ASYNC
            || pin.profile().execution_enabled()
            || pin.wit_sha256() != C67_ASYNC_CHAIN_WIT_SHA256
            || pin.interface() != "test:c65-chain/pipe@1.0.0"
        {
            return None;
        }

        let source = ComponentArtifact::copy_from(pin.source_bytes(), pin.profile()).ok()?;
        let relay = ComponentArtifact::copy_from(pin.relay_bytes(), pin.profile()).ok()?;
        let sink = ComponentArtifact::copy_from(pin.sink_bytes(), pin.profile()).ok()?;
        if source.identity().as_bytes() != &pin.source_sha256()
            || relay.identity().as_bytes() != &pin.relay_sha256()
            || sink.identity().as_bytes() != &pin.sink_sha256()
            || source.identity() == relay.identity()
            || source.identity() == sink.identity()
            || relay.identity() == sink.identity()
        {
            return None;
        }

        let source_world = WorldContract::parse(pin.wit_source(), pin.source_world()).ok()?;
        let relay_world = WorldContract::parse(pin.wit_source(), pin.relay_world()).ok()?;
        let sink_world = WorldContract::parse(pin.wit_source(), pin.sink_world()).ok()?;
        let limits = pin.limits();
        let limits = InstanceLimits {
            memory_bytes: limits.memory_bytes,
            total_fuel: limits.total_fuel,
            poll_quantum: limits.poll_quantum,
            resources: limits.resources,
        };
        let nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "input.untrusted",
                nesting: ComponentGraphNesting::Root,
                exact_world: &source_world,
                trust: ArtifactTrust::ImagePinned(source.identity()),
                limits,
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "transform.filtered",
                nesting: ComponentGraphNesting::Root,
                exact_world: &relay_world,
                trust: ArtifactTrust::ImagePinned(relay.identity()),
                limits,
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "output.approved",
                nesting: ComponentGraphNesting::Root,
                exact_world: &sink_world,
                trust: ArtifactTrust::ImagePinned(sink.identity()),
                limits,
                interfaces: &[],
            },
        ];
        let edges = [edge(0, 1), edge(1, 2)];
        let published = [ComponentGraphPublishedExportSpec::new(
            ComponentGraphExportEndpoint::new(
                ComponentGraphNodeId::new(2),
                ComponentGraphEntityIndex::new(0),
            ),
        )];
        let policy = ComponentGraphAdmissionPolicy {
            name: "c67-information-flow",
            profile: pin.profile(),
            nodes: &nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &published,
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let mut artifacts = Vec::new();
        artifacts.try_reserve_exact(3).ok()?;
        artifacts.push(source);
        artifacts.push(relay);
        artifacts.push(sink);
        let admitted =
            admit_component_graph(artifacts, &policy, &CallerAuthority { offers: &[] }).ok()?;
        if admitted.runtime_ready()
            || !admitted.grants().is_empty()
            || !admitted.manifest().resource_edges().is_empty()
            || admitted.manifest().async_edges().len() != 2
        {
            return None;
        }
        for async_edge in admitted.manifest().async_edges() {
            if async_edge.async_functions() != 1
                || async_edge.streams() != 4
                || async_edge.futures() != 4
            {
                return None;
            }
        }
        admitted.information_flow().ok()
    })();
    caller.restore();
    match report {
        Some(report) => Some((report, domain)),
        None => {
            let _ = release_empty_domain(domain);
            None
        }
    }
}

fn has_hex_run(value: &str, minimum: usize) -> bool {
    let mut run = 0usize;
    for byte in value.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= minimum {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn semantic_diagnostic_only(value: &str) -> bool {
    const FORBIDDEN: [&str; 30] = [
        "resource_index",
        "guest_index",
        "ResourceToken",
        "ResourceTypeId",
        "ComponentGraphNodeId",
        "ComponentGraphEntityIndex",
        "cap:",
        "Cap {",
        "slot=",
        "generation",
        "pointer",
        "address",
        "0x",
        "ObjectId",
        "SpaceId",
        "DerivationId",
        "durable",
        "artifact",
        "digest",
        "sha256",
        "ComponentIdentity",
        "TaskId",
        "CSpace",
        "OwnerId",
        "ArenaId",
        "AllocationDomain",
        "InstanceToken",
        "HostOperationToken",
        "incarnation",
        "runtime_abi",
    ];
    !FORBIDDEN.iter().any(|forbidden| value.contains(forbidden)) && !has_hex_run(value, 16)
}

fn exact_report_shape(report: &ComponentGraphInformationFlow) -> bool {
    let [input, output, transform] = report.nodes() else {
        return false;
    };
    if report.graph_policy_label() != "c67-information-flow"
        || report.runtime_ready()
        || input.policy_label() != "input.untrusted"
        || output.policy_label() != "output.approved"
        || transform.policy_label() != "transform.filtered"
        || input.parent_policy_label().is_some()
        || output.parent_policy_label().is_some()
        || transform.parent_policy_label().is_some()
        || report.internal_flows().len() != 2
        || !report.external_flows().is_empty()
        || report.authority_policy_count() != 0
        || report.published_flows().len() != 1
    {
        return false;
    }
    let [first, second] = report.internal_flows() else {
        return false;
    };
    for (flow, source, target) in [
        (first, "input.untrusted", "transform.filtered"),
        (second, "transform.filtered", "output.approved"),
    ] {
        let Some(policy) = flow.async_policy() else {
            return false;
        };
        if flow.source().principal_policy_label() != source
            || flow.target().principal_policy_label() != target
            || flow.source().entity_name() != "test:c65-chain/pipe@1.0.0"
            || flow.target().entity_name() != "test:c65-chain/pipe@1.0.0"
            || flow.source().entity_shape() != flow.target().entity_shape()
            || flow.resource_policy().is_some()
            || policy.async_functions() != 1
            || policy.streams() != 4
            || policy.futures() != 4
        {
            return false;
        }
    }
    let published = &report.published_flows()[0];
    published.source().principal_policy_label() == "output.approved"
        && published.source().entity_name() == "test:c65-chain/pipe@1.0.0"
}

/// Four-hart, inspection-only target proof. The one UART block is emitted
/// only after fresh provenance, exact semantic shape, bounded rendering, and
/// all five synthetic forbidden-class rejections have succeeded.
pub(crate) fn run_qemu_acceptance() -> bool {
    if crate::online_hart_count() != 4 || crate::online_hart_mask() & 0x0f != 0x0f {
        return false;
    }
    let before = crate::component_instances::registry().occupancy_stats();
    if before.occupied != 0 || before.header_mismatches != 0 {
        return false;
    }
    let Some((report, domain)) = build_report() else {
        return false;
    };
    if !exact_report_shape(&report) {
        drop(report);
        let _ = release_empty_domain(domain);
        return false;
    }

    let mut rendered = BoundedText::<C67_RENDER_BYTES>::new();
    if write!(&mut rendered, "{report}").is_err() {
        drop(report);
        let _ = release_empty_domain(domain);
        return false;
    }
    let Some(text) = rendered.as_str() else {
        drop(report);
        let _ = release_empty_domain(domain);
        return false;
    };
    if !semantic_diagnostic_only(text)
        || [
            "resource_index=7",
            "cap:3.9 slot=3 generation=9",
            "pointer=0x1234",
            "ObjectId=11 durable artifact digest",
            "TaskId=5 CSpace OwnerId ArenaId",
        ]
        .iter()
        .any(|tainted| semantic_diagnostic_only(tainted))
    {
        drop(report);
        let _ = release_empty_domain(domain);
        return false;
    }

    crate::println!(
        "WASM_C67_INFORMATION_FLOW BEGIN\n{}\nWASM_C67_INFORMATION_FLOW END",
        text
    );
    drop(report);
    if !release_empty_domain(domain) {
        return false;
    }
    let after = crate::component_instances::registry().occupancy_stats();
    after.occupied == 0 && after.header_mismatches == 0
}
