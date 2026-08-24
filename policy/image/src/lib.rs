#![no_std]

//! Compile-time logical resource and storage-layout policy selected by final
//! firmware images. Physical hardware descriptions remain in the BSP/HAL.

use vibeos_component_format::ProfileIdentity;

#[cfg(any(
    feature = "c73-authenticated-admission-qemu-acceptance",
    feature = "c76-graph-version-replacement-qemu-acceptance"
))]
use vibeos_component_admission::{
    ArtifactAuthenticationError, CommandStreamMode as AdmissionStreamMode, InstanceLimits,
    OperatorRoleIdentity, OperatorSignerStatus, OperatorSignerV1,
};
#[cfg(any(
    feature = "c73-authenticated-admission-qemu-acceptance",
    feature = "c76-graph-version-replacement-qemu-acceptance"
))]
use vibeos_component_format::{
    ComponentArtifactAuthenticationError, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactError, ComponentArtifactV1,
};
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
use vibeos_component_format::{ComponentArtifactPolicyDigest, ComponentArtifactSignerPolicyV1};
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
use vibeos_component_format::{
    ComponentGraphVersionAuthenticationError, ComponentGraphVersionAuthenticationEvidenceV1,
    ComponentGraphVersionError, ComponentGraphVersionV1,
};

#[cfg(all(feature = "qemu-default", feature = "milkv-duo-sd"))]
compile_error!("image policies `qemu-default` and `milkv-duo-sd` are mutually exclusive");

#[cfg(not(any(feature = "qemu-default", feature = "milkv-duo-sd")))]
compile_error!("exactly one image policy must be selected");

#[cfg(all(
    feature = "c53-native-async-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c53-native-async-qemu-acceptance` requires `qemu-default`");

#[cfg(all(
    feature = "c64-resource-route-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c64-resource-route-qemu-acceptance` requires `qemu-default`");

#[cfg(all(
    feature = "c65-async-chain-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c65-async-chain-qemu-acceptance` requires `qemu-default`");

#[cfg(all(
    feature = "c66-node-replacement-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c66-node-replacement-qemu-acceptance` requires `qemu-default`");

#[cfg(all(
    feature = "c67-information-flow-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c67-information-flow-qemu-acceptance` requires `qemu-default`");

#[cfg(all(
    feature = "c73-authenticated-admission-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c73-authenticated-admission-qemu-acceptance` requires `qemu-default`");

#[cfg(all(
    feature = "c76-graph-version-replacement-qemu-acceptance",
    not(feature = "qemu-default")
))]
compile_error!("feature `c76-graph-version-replacement-qemu-acceptance` requires `qemu-default`");

/// A logical block-device view carved out of a packaged storage image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSlice {
    pub first_sector: u64,
    pub sector_count: u64,
}

impl BlockSlice {
    pub const fn end_sector(self) -> Option<u64> {
        self.first_sector.checked_add(self.sector_count)
    }
}

/// Resource policy for stable packet frontends shared by network backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkFrontendPolicy {
    pub queue_depth: usize,
}

/// Bounded capacity of each stable packet endpoint. This is independent of a
/// device backend's descriptor-ring size.
pub const NETWORK_FRONTEND: NetworkFrontendPolicy = NetworkFrontendPolicy { queue_depth: 64 };

/// Stream contract pinned for an image-provided Component command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStreamMode {
    Required,
    Optional,
    Closed,
}

/// Exact per-instance ceilings selected by the image independently of the
/// artifact's own declarations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentInstanceLimits {
    pub memory_bytes: usize,
    pub total_fuel: u64,
    pub poll_quantum: u64,
    pub resources: u16,
}

/// Exact negative authentication case embedded in the C7.3 acceptance image.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C73RejectedEvidenceKind {
    WrongSignature,
    UnknownSigner,
    RevokedSigner,
    ContentHashOnly,
}

/// Exact double-layer mutation selected by the C7.3 acceptance image.
///
/// Each artifact is paired with a fresh, valid signature. Admission must first
/// reject the baseline signature over changed bytes, then still reject the
/// freshly signed artifact at the named semantic revalidation gate.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C73ArtifactMutationKind {
    ArtifactManifest,
    CoreModuleManifest,
    ExactWitSource,
    AdapterManifest,
    InstanceLimits,
    ProfileIdentity,
}

/// Image-pinned development artifact. Its exact encoded bytes are encapsulated,
/// build-verified, and exposed only through the explicit development projector
/// input below; operator pins deliberately have no equivalent byte getter.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C73DevelopmentArtifactPin {
    artifact_bytes: &'static [u8],
    signer_policy_digest: [u8; 32],
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl C73DevelopmentArtifactPin {
    /// Exact canonical envelope owned by this development image.
    ///
    /// This is an input only to the development image-pin projector. It is not
    /// deployable operator evidence, a content-addressed lookup key, or a
    /// substitute for [`C73OperatorArtifactPin::authentication_evidence`].
    pub const fn canonical_artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    /// Independently generated development signer policy for the exact image
    /// descriptor. The digest is never copied out as a raw identifier.
    pub fn signer_policy(self) -> Result<ComponentArtifactSignerPolicyV1, ComponentArtifactError> {
        ComponentArtifactSignerPolicyV1::development_image_pin(self.signer_policy_digest)
    }

    pub fn signer_policy_digest(
        self,
    ) -> Result<ComponentArtifactPolicyDigest, ComponentArtifactError> {
        self.signer_policy().map(|policy| policy.policy_digest())
    }

    pub fn artifact(self) -> Result<ComponentArtifactV1, ComponentArtifactError> {
        ComponentArtifactV1::decode(self.artifact_bytes)
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl core::fmt::Debug for C73DevelopmentArtifactPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C73DevelopmentArtifactPin")
            .field("artifact", &"<redacted>")
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// One deployable operator-signed artifact with detached canonical evidence.
/// Encoded bytes remain private; callers receive only decoded format types.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C73OperatorArtifactPin {
    artifact_bytes: &'static [u8],
    evidence_bytes: &'static [u8],
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl C73OperatorArtifactPin {
    pub fn artifact(self) -> Result<ComponentArtifactV1, ComponentArtifactError> {
        ComponentArtifactV1::decode(self.artifact_bytes)
    }

    pub fn authentication_evidence(
        self,
    ) -> Result<ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactAuthenticationError>
    {
        ComponentArtifactAuthenticationEvidenceV1::decode(self.evidence_bytes)
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl core::fmt::Debug for C73OperatorArtifactPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C73OperatorArtifactPin")
            .field("artifact", &"<redacted>")
            .field("authentication_evidence", &"<redacted>")
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// One structurally canonical but deliberately rejected detached evidence.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C73RejectedEvidencePin {
    kind: C73RejectedEvidenceKind,
    evidence_bytes: &'static [u8],
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl C73RejectedEvidencePin {
    pub const fn kind(self) -> C73RejectedEvidenceKind {
        self.kind
    }

    pub fn authentication_evidence(
        self,
    ) -> Result<ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactAuthenticationError>
    {
        ComponentArtifactAuthenticationEvidenceV1::decode(self.evidence_bytes)
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl core::fmt::Debug for C73RejectedEvidencePin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C73RejectedEvidencePin")
            .field("kind", &self.kind)
            .field("authentication_evidence", &"<redacted>")
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// One freshly signed semantic mutation fixture. Both byte arrays are private
/// so the image cannot turn a diagnostic fixture into ambient lookup material.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C73ArtifactMutationPin {
    kind: C73ArtifactMutationKind,
    artifact_bytes: &'static [u8],
    evidence_bytes: &'static [u8],
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl C73ArtifactMutationPin {
    pub const fn kind(self) -> C73ArtifactMutationKind {
        self.kind
    }

    pub fn artifact(self) -> Result<ComponentArtifactV1, ComponentArtifactError> {
        ComponentArtifactV1::decode(self.artifact_bytes)
    }

    pub fn authentication_evidence(
        self,
    ) -> Result<ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactAuthenticationError>
    {
        ComponentArtifactAuthenticationEvidenceV1::decode(self.evidence_bytes)
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl core::fmt::Debug for C73ArtifactMutationPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C73ArtifactMutationPin")
            .field("kind", &self.kind)
            .field("artifact", &"<redacted>")
            .field("authentication_evidence", &"<redacted>")
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// Private, redacted typed inputs for one canonical operator-policy generation.
///
/// The raw key and role storage remains private. Fallible typed accessors
/// construct the production admission values, rechecking curve points and
/// fail-closing if the checked fixture ever drifts.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C73OperatorPolicyPin {
    generation: u64,
    operator_role: [u8; 32],
    active_signer: [u8; 32],
    revoked_signer: [u8; 32],
    exact_wit_source: &'static str,
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl C73OperatorPolicyPin {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub fn operator_role(self) -> Result<OperatorRoleIdentity, ArtifactAuthenticationError> {
        OperatorRoleIdentity::from_bytes(self.operator_role)
    }

    /// Return the complete canonical signer table, ordered by public-key bytes.
    pub fn signers(self) -> Result<[OperatorSignerV1; 2], ArtifactAuthenticationError> {
        let revoked = OperatorSignerV1::new(self.revoked_signer, OperatorSignerStatus::Revoked)?;
        let active = OperatorSignerV1::new(self.active_signer, OperatorSignerStatus::Active)?;
        let mut signers = [revoked, active];
        signers.sort_by_key(|signer| *signer.public_key());
        if signers[0].public_key() >= signers[1].public_key() {
            return Err(ArtifactAuthenticationError::NonCanonicalSignerTable);
        }
        Ok(signers)
    }

    pub const fn profile(self) -> ProfileIdentity {
        ProfileIdentity::PROFILE_1_SYNC
    }

    pub const fn command_name(self) -> &'static str {
        "c73-filter"
    }

    pub const fn entrypoint(self) -> &'static str {
        "run"
    }

    pub const fn min_args(self) -> usize {
        0
    }

    pub const fn max_args(self) -> usize {
        0
    }

    pub const fn exact_wit_source(self) -> &'static str {
        self.exact_wit_source
    }

    pub const fn exact_world(self) -> &'static str {
        "vibe:bytes/filter@1.0.0"
    }

    pub const fn limits(self) -> InstanceLimits {
        InstanceLimits {
            memory_bytes: 512 * 1024,
            total_fuel: 100_000,
            poll_quantum: 100,
            resources: 4,
        }
    }

    pub const fn stdin(self) -> AdmissionStreamMode {
        AdmissionStreamMode::Required
    }

    pub const fn stdout(self) -> AdmissionStreamMode {
        AdmissionStreamMode::Required
    }

    pub const fn stderr(self) -> AdmissionStreamMode {
        AdmissionStreamMode::Optional
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl core::fmt::Debug for C73OperatorPolicyPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C73OperatorPolicyPin")
            .field("generation", &self.generation)
            .field("operator_role", &"<redacted>")
            .field("signers", &"<redacted>")
            .field("exact_wit_source", &"<redacted>")
            .field("profile", &ProfileIdentity::PROFILE_1_SYNC)
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// Closed C7.3 acceptance-image policy root.
///
/// It contains only canonical artifact bytes, detached public evidence, exact
/// WIT, and typed signer-policy inputs. It contains no private signing seed,
/// capability, durable identity, lookup handle, invocation token, or guest
/// execution authority.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C73AuthenticatedAdmissionPin {
    development: C73DevelopmentArtifactPin,
    policy_p1: C73OperatorPolicyPin,
    policy_p2: C73OperatorPolicyPin,
    operator_p1: [C73OperatorArtifactPin; 2],
    operator_p2: C73OperatorArtifactPin,
    rejected_evidence: [C73RejectedEvidencePin; 4],
    mutations: [C73ArtifactMutationPin; 6],
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl C73AuthenticatedAdmissionPin {
    pub const fn development(self) -> C73DevelopmentArtifactPin {
        self.development
    }

    pub const fn policy_p1(self) -> C73OperatorPolicyPin {
        self.policy_p1
    }

    pub const fn policy_p2(self) -> C73OperatorPolicyPin {
        self.policy_p2
    }

    pub const fn operator_p1(self) -> [C73OperatorArtifactPin; 2] {
        self.operator_p1
    }

    pub const fn operator_p2(self) -> C73OperatorArtifactPin {
        self.operator_p2
    }

    pub const fn rejected_evidence(self) -> [C73RejectedEvidencePin; 4] {
        self.rejected_evidence
    }

    pub const fn mutations(self) -> [C73ArtifactMutationPin; 6] {
        self.mutations
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
impl core::fmt::Debug for C73AuthenticatedAdmissionPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C73AuthenticatedAdmissionPin")
            .field("development", &"<redacted>")
            .field("operator_p1", &"<redacted:2>")
            .field("operator_p2", &"<redacted>")
            .field("policies", &"<redacted:2>")
            .field("rejected_evidence", &"<redacted:4>")
            .field("mutations", &"<redacted:6>")
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// Exact retirement action authorized by the fixed C7.6 graph policy.
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C76GraphRetirementAction {
    PolicyCancel,
}

/// Private, typed inputs for the current C7.6 operator policy.
///
/// The complete public key is carried directly and never selected by a key
/// identifier or ambient lookup. No signing seed, durable object identity,
/// capability, runtime principal, or guest entry authority exists here.
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C76GraphOperatorPolicyPin {
    generation: u64,
    operator_role: [u8; 32],
    active_signer: [u8; 32],
    exact_wit_source: &'static str,
}

#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
impl C76GraphOperatorPolicyPin {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn profile(self) -> ProfileIdentity {
        ProfileIdentity::PROFILE_1_ASYNC
    }

    pub const fn graph_name(self) -> &'static str {
        "c76-chain"
    }

    pub const fn node_command_name(self) -> &'static str {
        "c76-node"
    }

    pub const fn node_entrypoint(self) -> &'static str {
        "run"
    }

    pub const fn node_argument_limits(self) -> (usize, usize) {
        (0, 0)
    }

    pub const fn node_interface_ceiling_count(self) -> u16 {
        0
    }

    pub const fn exact_wit_source(self) -> &'static str {
        self.exact_wit_source
    }

    pub const fn node_labels(self) -> [&'static str; 3] {
        ["source", "relay", "sink"]
    }

    pub const fn node_worlds(self) -> [&'static str; 3] {
        [
            "test:c65-chain/source@1.0.0",
            "test:c65-chain/relay@1.0.0",
            "test:c65-chain/sink@1.0.0",
        ]
    }

    pub const fn node_limits(self) -> InstanceLimits {
        InstanceLimits {
            memory_bytes: 64 * 1024,
            total_fuel: 1_000,
            poll_quantum: 100,
            resources: 8,
        }
    }

    pub const fn node_streams(
        self,
    ) -> (
        AdmissionStreamMode,
        AdmissionStreamMode,
        AdmissionStreamMode,
    ) {
        (
            AdmissionStreamMode::Closed,
            AdmissionStreamMode::Closed,
            AdmissionStreamMode::Closed,
        )
    }

    pub fn operator_role(self) -> Result<OperatorRoleIdentity, ArtifactAuthenticationError> {
        OperatorRoleIdentity::from_bytes(self.operator_role)
    }

    pub fn active_signer(self) -> Result<OperatorSignerV1, ArtifactAuthenticationError> {
        OperatorSignerV1::new(self.active_signer, OperatorSignerStatus::Active)
    }

    /// The complete canonical leaf signer table. It contains no key ID.
    pub fn leaf_signers(self) -> Result<[OperatorSignerV1; 1], ArtifactAuthenticationError> {
        Ok([self.active_signer()?])
    }

    /// The complete canonical graph signer table. C7.6 intentionally uses the
    /// same current operator role as every leaf while retaining distinct
    /// artifact and graph signature domains.
    pub fn graph_signers(self) -> Result<[OperatorSignerV1; 1], ArtifactAuthenticationError> {
        Ok([self.active_signer()?])
    }

    pub const fn active_public_key_bytes(self) -> [u8; 32] {
        self.active_signer
    }

    pub const fn node_count(self) -> u16 {
        3
    }

    pub const fn all_nodes_are_roots(self) -> bool {
        true
    }

    pub const fn graph_edges(self) -> [ComponentGraphReplacementEdgePin; 2] {
        [
            ComponentGraphReplacementEdgePin::new(
                0,
                0,
                1,
                0,
                ComponentGraphReplacementPinAction::RecreateFresh,
            ),
            ComponentGraphReplacementEdgePin::new(
                1,
                0,
                2,
                0,
                ComponentGraphReplacementPinAction::RecreateFresh,
            ),
        ]
    }

    pub const fn published_export(self) -> (u16, u16) {
        (2, 0)
    }

    pub const fn replacement_node(self) -> u16 {
        1
    }

    pub const fn retirement_action(self) -> C76GraphRetirementAction {
        C76GraphRetirementAction::PolicyCancel
    }

    pub const fn incident_edges(self) -> [ComponentGraphReplacementEdgePin; 2] {
        self.graph_edges()
    }

    pub const fn max_replacements(self) -> u16 {
        1
    }

    pub const fn resource_edge_count(self) -> u16 {
        0
    }

    pub const fn external_import_count(self) -> u16 {
        0
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
impl core::fmt::Debug for C76GraphOperatorPolicyPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C76GraphOperatorPolicyPin")
            .field("generation", &self.generation)
            .field("operator_role", &"<redacted>")
            .field("active_signer", &"<redacted>")
            .field("profile", &ProfileIdentity::PROFILE_1_ASYNC)
            .field("nodes", &3)
            .field("edges", &2)
            .field("replacement_node", &1)
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// One complete, inert C7.6 graph-version bundle pinned by canonical bytes.
///
/// The byte accessors are explicit installation inputs for the exact
/// root-relative storage layout. They are content bytes, never durable IDs or
/// lookup authority, and every typed accessor reparses the canonical format.
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct C76GraphVersionPin {
    ordinal: u64,
    descriptor_bytes: &'static [u8],
    artifact_bytes: [&'static [u8]; 3],
    artifact_evidence_bytes: [&'static [u8]; 3],
    graph_evidence_bytes: &'static [u8],
}

#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
impl C76GraphVersionPin {
    pub const fn ordinal(self) -> u64 {
        self.ordinal
    }

    pub const fn canonical_descriptor_bytes(self) -> &'static [u8] {
        self.descriptor_bytes
    }

    pub const fn canonical_artifact_bytes(self) -> [&'static [u8]; 3] {
        self.artifact_bytes
    }

    pub const fn canonical_artifact_evidence_bytes(self) -> [&'static [u8]; 3] {
        self.artifact_evidence_bytes
    }

    pub const fn canonical_graph_evidence_bytes(self) -> &'static [u8] {
        self.graph_evidence_bytes
    }

    pub fn descriptor(self) -> Result<ComponentGraphVersionV1, ComponentGraphVersionError> {
        ComponentGraphVersionV1::decode(self.descriptor_bytes)
    }

    pub fn artifacts(self) -> Result<[ComponentArtifactV1; 3], ComponentArtifactError> {
        Ok([
            ComponentArtifactV1::decode(self.artifact_bytes[0])?,
            ComponentArtifactV1::decode(self.artifact_bytes[1])?,
            ComponentArtifactV1::decode(self.artifact_bytes[2])?,
        ])
    }

    pub fn artifact_evidence(
        self,
    ) -> Result<[ComponentArtifactAuthenticationEvidenceV1; 3], ComponentArtifactAuthenticationError>
    {
        Ok([
            ComponentArtifactAuthenticationEvidenceV1::decode(self.artifact_evidence_bytes[0])?,
            ComponentArtifactAuthenticationEvidenceV1::decode(self.artifact_evidence_bytes[1])?,
            ComponentArtifactAuthenticationEvidenceV1::decode(self.artifact_evidence_bytes[2])?,
        ])
    }

    pub fn graph_evidence(
        self,
    ) -> Result<
        ComponentGraphVersionAuthenticationEvidenceV1,
        ComponentGraphVersionAuthenticationError,
    > {
        ComponentGraphVersionAuthenticationEvidenceV1::decode(self.graph_evidence_bytes)
    }

    pub const fn attachment_counts(self) -> (u16, u16, u16) {
        (3, 3, 1)
    }

    pub const fn runtime_ready(self) -> bool {
        false
    }

    pub const fn guest_calls(self) -> u64 {
        0
    }
}

#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
impl core::fmt::Debug for C76GraphVersionPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("C76GraphVersionPin")
            .field("ordinal", &self.ordinal)
            .field("descriptor", &"<redacted>")
            .field("artifacts", &"<redacted:3>")
            .field("artifact_evidence", &"<redacted:3>")
            .field("graph_evidence", &"<redacted>")
            .field("runtime_ready", &false)
            .field("guest_calls", &0)
            .finish()
    }
}

/// Immutable, validation-only two-node artifact pair for the C6.4 resource
/// route acceptance image.
///
/// The pin supplies bytes and independent WIT policy only. It carries no Cap,
/// resource handle, CSpace identity, durable object identity, or execution
/// entry point, and its profile can never authorize guest execution.
#[cfg(feature = "c64-resource-route-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct ComponentGraphResourceRoutePin {
    provider_bytes: &'static [u8],
    provider_sha256: [u8; 32],
    consumer_bytes: &'static [u8],
    consumer_sha256: [u8; 32],
    wit_source: &'static str,
    wit_sha256: [u8; 32],
    provider_world: &'static str,
    consumer_world: &'static str,
    interface: &'static str,
    profile: ProfileIdentity,
    limits: ComponentInstanceLimits,
}

#[cfg(feature = "c64-resource-route-qemu-acceptance")]
impl ComponentGraphResourceRoutePin {
    pub const fn provider_bytes(self) -> &'static [u8] {
        self.provider_bytes
    }

    pub const fn provider_sha256(self) -> [u8; 32] {
        self.provider_sha256
    }

    pub const fn consumer_bytes(self) -> &'static [u8] {
        self.consumer_bytes
    }

    pub const fn consumer_sha256(self) -> [u8; 32] {
        self.consumer_sha256
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn wit_sha256(self) -> [u8; 32] {
        self.wit_sha256
    }

    pub const fn provider_world(self) -> &'static str {
        self.provider_world
    }

    pub const fn consumer_world(self) -> &'static str {
        self.consumer_world
    }

    pub const fn interface(self) -> &'static str {
        self.interface
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

#[cfg(feature = "c64-resource-route-qemu-acceptance")]
impl core::fmt::Debug for ComponentGraphResourceRoutePin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ComponentGraphResourceRoutePin")
            .field("artifacts", &"<redacted>")
            .field("provider_world", &self.provider_world)
            .field("consumer_world", &self.consumer_world)
            .field("interface", &self.interface)
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Immutable validation-only three-node artifact set for the C6.5 async-chain
/// acceptance image.
///
/// This root contains only independently hashed Component bytes, exact WIT
/// policy, and bounded accounting inputs. It contains no guest execution
/// authority, ambient lookup key, durable object identity, capability, or
/// graph wiring authority. The kernel must still construct the exact
/// source-to-relay-to-sink graph and explicitly publish the sink export.
#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
#[derive(Clone, Copy)]
pub struct ComponentGraphAsyncChainPin {
    source_bytes: &'static [u8],
    source_sha256: [u8; 32],
    relay_bytes: &'static [u8],
    relay_sha256: [u8; 32],
    sink_bytes: &'static [u8],
    sink_sha256: [u8; 32],
    wit_source: &'static str,
    wit_sha256: [u8; 32],
    source_world: &'static str,
    relay_world: &'static str,
    sink_world: &'static str,
    interface: &'static str,
    profile: ProfileIdentity,
    limits: ComponentInstanceLimits,
}

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
impl ComponentGraphAsyncChainPin {
    pub const fn source_bytes(self) -> &'static [u8] {
        self.source_bytes
    }

    pub const fn source_sha256(self) -> [u8; 32] {
        self.source_sha256
    }

    pub const fn relay_bytes(self) -> &'static [u8] {
        self.relay_bytes
    }

    pub const fn relay_sha256(self) -> [u8; 32] {
        self.relay_sha256
    }

    pub const fn sink_bytes(self) -> &'static [u8] {
        self.sink_bytes
    }

    pub const fn sink_sha256(self) -> [u8; 32] {
        self.sink_sha256
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn wit_sha256(self) -> [u8; 32] {
        self.wit_sha256
    }

    pub const fn source_world(self) -> &'static str {
        self.source_world
    }

    pub const fn relay_world(self) -> &'static str {
        self.relay_world
    }

    pub const fn sink_world(self) -> &'static str {
        self.sink_world
    }

    pub const fn interface(self) -> &'static str {
        self.interface
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
impl core::fmt::Debug for ComponentGraphAsyncChainPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ComponentGraphAsyncChainPin")
            .field("artifacts", &"<redacted>")
            .field("wit_source", &"<redacted>")
            .field("source_world", &self.source_world)
            .field("relay_world", &self.relay_world)
            .field("sink_world", &self.sink_world)
            .field("interface", &self.interface)
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Exact authority-preserving action selected for one incident graph edge
/// while replacing a node.
///
/// Disconnect-only teardown is intentionally not representable: the C6.6
/// image requires the supervisor to create a fresh edge incarnation from the
/// admitted policy before publishing the replacement.
#[cfg(any(
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c76-graph-version-replacement-qemu-acceptance"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentGraphReplacementPinAction {
    RecreateFresh,
}

/// One graph-local incident edge covered by the C6.6 replacement policy.
///
/// Node and entity numbers are inert bounded graph coordinates, never Task,
/// CSpace, capability, resource, live route, or durable object identities.
#[cfg(any(
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c76-graph-version-replacement-qemu-acceptance"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentGraphReplacementEdgePin {
    source_node: u16,
    source_export: u16,
    target_node: u16,
    target_import: u16,
    action: ComponentGraphReplacementPinAction,
}

#[cfg(any(
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c76-graph-version-replacement-qemu-acceptance"
))]
impl ComponentGraphReplacementEdgePin {
    const fn new(
        source_node: u16,
        source_export: u16,
        target_node: u16,
        target_import: u16,
        action: ComponentGraphReplacementPinAction,
    ) -> Self {
        Self {
            source_node,
            source_export,
            target_node,
            target_import,
            action,
        }
    }

    pub const fn source_node(self) -> u16 {
        self.source_node
    }

    pub const fn source_export(self) -> u16 {
        self.source_export
    }

    pub const fn target_node(self) -> u16 {
        self.target_node
    }

    pub const fn target_import(self) -> u16 {
        self.target_import
    }

    pub const fn action(self) -> ComponentGraphReplacementPinAction {
        self.action
    }
}

/// Immutable validation-only C6.6 node-replacement policy root.
///
/// Source, sink, old relay, and WIT bytes are the exact C6.5 pins. The new
/// relay has a distinct independently checked artifact identity but the same
/// exact relay world and interface. The fixed incident-edge array admits only
/// one replacement of graph-local node 1 and requires both adjacent routes to
/// be recreated fresh. No field is execution authority, a live route, a raw
/// runtime identity, an ambient lookup key, or a durable object identity.
#[cfg(feature = "c66-node-replacement-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct ComponentGraphNodeReplacementPin {
    source_bytes: &'static [u8],
    source_sha256: [u8; 32],
    old_relay_bytes: &'static [u8],
    old_relay_sha256: [u8; 32],
    new_relay_bytes: &'static [u8],
    new_relay_sha256: [u8; 32],
    sink_bytes: &'static [u8],
    sink_sha256: [u8; 32],
    wit_source: &'static str,
    wit_sha256: [u8; 32],
    source_world: &'static str,
    relay_world: &'static str,
    sink_world: &'static str,
    interface: &'static str,
    profile: ProfileIdentity,
    limits: ComponentInstanceLimits,
    node_count: u16,
    replacement_node: u16,
    incident_edges: [ComponentGraphReplacementEdgePin; 2],
    max_replacements: u16,
}

#[cfg(feature = "c66-node-replacement-qemu-acceptance")]
impl ComponentGraphNodeReplacementPin {
    pub const fn source_bytes(self) -> &'static [u8] {
        self.source_bytes
    }

    pub const fn source_sha256(self) -> [u8; 32] {
        self.source_sha256
    }

    pub const fn old_relay_bytes(self) -> &'static [u8] {
        self.old_relay_bytes
    }

    pub const fn old_relay_sha256(self) -> [u8; 32] {
        self.old_relay_sha256
    }

    pub const fn new_relay_bytes(self) -> &'static [u8] {
        self.new_relay_bytes
    }

    pub const fn new_relay_sha256(self) -> [u8; 32] {
        self.new_relay_sha256
    }

    pub const fn sink_bytes(self) -> &'static [u8] {
        self.sink_bytes
    }

    pub const fn sink_sha256(self) -> [u8; 32] {
        self.sink_sha256
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn wit_sha256(self) -> [u8; 32] {
        self.wit_sha256
    }

    pub const fn source_world(self) -> &'static str {
        self.source_world
    }

    pub const fn relay_world(self) -> &'static str {
        self.relay_world
    }

    pub const fn sink_world(self) -> &'static str {
        self.sink_world
    }

    pub const fn interface(self) -> &'static str {
        self.interface
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }

    pub const fn node_count(self) -> u16 {
        self.node_count
    }

    pub const fn replacement_node(self) -> u16 {
        self.replacement_node
    }

    pub const fn incident_edges(self) -> [ComponentGraphReplacementEdgePin; 2] {
        self.incident_edges
    }

    pub const fn max_replacements(self) -> u16 {
        self.max_replacements
    }
}

#[cfg(feature = "c66-node-replacement-qemu-acceptance")]
impl core::fmt::Debug for ComponentGraphNodeReplacementPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ComponentGraphNodeReplacementPin")
            .field("artifacts", &"<redacted>")
            .field("wit_source", &"<redacted>")
            .field("source_world", &self.source_world)
            .field("relay_world", &self.relay_world)
            .field("sink_world", &self.sink_world)
            .field("interface", &self.interface)
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .field("node_count", &self.node_count)
            .field("replacement_node", &self.replacement_node)
            .field("incident_edges", &self.incident_edges)
            .field("max_replacements", &self.max_replacements)
            .finish()
    }
}

/// Immutable image-policy root for one admitted Component command.
///
/// Fields are private so consumers can inspect the selected policy but cannot
/// fabricate or mutate a pin. `artifact_bytes` are produced from the audited
/// in-tree WAT by a version-pinned build tool; the build independently checks
/// them against `expected_sha256` before this crate is compiled. The WIT source
/// is also pinned rather than inferred from the decoded artifact.
#[derive(Clone, Copy)]
pub struct ComponentCommandPin {
    artifact_bytes: &'static [u8],
    expected_sha256: [u8; 32],
    command_name: &'static str,
    profile: ProfileIdentity,
    wit_source: &'static str,
    world: &'static str,
    entrypoint: &'static str,
    min_args: usize,
    max_args: usize,
    stdin: ComponentStreamMode,
    stdout: ComponentStreamMode,
    stderr: ComponentStreamMode,
    limits: ComponentInstanceLimits,
}

impl ComponentCommandPin {
    pub const fn artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    pub const fn expected_sha256(self) -> [u8; 32] {
        self.expected_sha256
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn abi(self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn world(self) -> &'static str {
        self.world
    }

    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    pub const fn min_args(self) -> usize {
        self.min_args
    }

    pub const fn max_args(self) -> usize {
        self.max_args
    }

    pub const fn stdin(self) -> ComponentStreamMode {
        self.stdin
    }

    pub const fn stdout(self) -> ComponentStreamMode {
        self.stdout
    }

    pub const fn stderr(self) -> ComponentStreamMode {
        self.stderr
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

impl core::fmt::Debug for ComponentCommandPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ComponentCommandPin")
            .field("artifact", &"<redacted>")
            .field("command_name", &self.command_name)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("entrypoint", &self.entrypoint)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Isolated image-policy root for C5.3 native async runtime acceptance.
///
/// This type is intentionally not [`ComponentCommandPin`]. It cannot enter the
/// synchronous command runner or the existing SSH C4.8 policy gate. Enabling
/// its feature makes one immutable executable guest available only to the
/// feature-gated runtime acceptance driver. Kernel installation, SSH routing,
/// and QEMU execution remain separately reviewed boundaries.
#[cfg(feature = "c53-native-async-qemu-acceptance")]
#[derive(Clone, Copy)]
pub struct NativeAsyncAcceptancePin {
    artifact_bytes: &'static [u8],
    expected_sha256: [u8; 32],
    command_name: &'static str,
    profile: ProfileIdentity,
    wit_source: &'static str,
    world: &'static str,
    entrypoint: &'static str,
    min_args: usize,
    max_args: usize,
    stdin: ComponentStreamMode,
    stdout: ComponentStreamMode,
    stderr: ComponentStreamMode,
    limits: ComponentInstanceLimits,
}

#[cfg(feature = "c53-native-async-qemu-acceptance")]
impl NativeAsyncAcceptancePin {
    pub const fn artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    pub const fn expected_sha256(self) -> [u8; 32] {
        self.expected_sha256
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn abi(self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn world(self) -> &'static str {
        self.world
    }

    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    pub const fn min_args(self) -> usize {
        self.min_args
    }

    pub const fn max_args(self) -> usize {
        self.max_args
    }

    pub const fn stdin(self) -> ComponentStreamMode {
        self.stdin
    }

    pub const fn stdout(self) -> ComponentStreamMode {
        self.stdout
    }

    pub const fn stderr(self) -> ComponentStreamMode {
        self.stderr
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

#[cfg(feature = "c53-native-async-qemu-acceptance")]
impl core::fmt::Debug for NativeAsyncAcceptancePin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeAsyncAcceptancePin")
            .field("artifact", &"<redacted>")
            .field("command_name", &self.command_name)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("entrypoint", &self.entrypoint)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Image-policy authority for projecting the pinned native async artifact into
/// an inert VSH command manifest.
///
/// This is a separate policy upgrade from `NativeAsyncAcceptancePin`. There
/// is deliberately no `From`/`Into` implementation between the two roots, even
/// though both may bind the same immutable artifact and validation-only
/// profile. The command projection adapter accepts only this type.
///
/// ```compile_fail
/// # use vibeos_image_policy::{
/// #     NativeAsyncAcceptancePin, C53_NATIVE_ASYNC_COMMAND,
/// # };
/// let _: NativeAsyncAcceptancePin = C53_NATIVE_ASYNC_COMMAND.into();
/// ```
#[cfg(feature = "c53-native-async-command-projection")]
#[derive(Clone, Copy)]
pub struct NativeAsyncCommandPin {
    artifact_bytes: &'static [u8],
    expected_sha256: [u8; 32],
    command_name: &'static str,
    profile: ProfileIdentity,
    wit_source: &'static str,
    world: &'static str,
    entrypoint: &'static str,
    min_args: usize,
    max_args: usize,
    stdin: ComponentStreamMode,
    stdout: ComponentStreamMode,
    stderr: ComponentStreamMode,
    limits: ComponentInstanceLimits,
}

#[cfg(feature = "c53-native-async-command-projection")]
impl NativeAsyncCommandPin {
    pub const fn artifact_bytes(self) -> &'static [u8] {
        self.artifact_bytes
    }

    pub const fn expected_sha256(self) -> [u8; 32] {
        self.expected_sha256
    }

    pub const fn command_name(self) -> &'static str {
        self.command_name
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn abi(self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn wit_source(self) -> &'static str {
        self.wit_source
    }

    pub const fn world(self) -> &'static str {
        self.world
    }

    pub const fn entrypoint(self) -> &'static str {
        self.entrypoint
    }

    pub const fn min_args(self) -> usize {
        self.min_args
    }

    pub const fn max_args(self) -> usize {
        self.max_args
    }

    pub const fn stdin(self) -> ComponentStreamMode {
        self.stdin
    }

    pub const fn stdout(self) -> ComponentStreamMode {
        self.stdout
    }

    pub const fn stderr(self) -> ComponentStreamMode {
        self.stderr
    }

    pub const fn limits(self) -> ComponentInstanceLimits {
        self.limits
    }
}

#[cfg(feature = "c53-native-async-command-projection")]
impl core::fmt::Debug for NativeAsyncCommandPin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeAsyncCommandPin")
            .field("artifact", &"<redacted>")
            .field("command_name", &self.command_name)
            .field("profile", &self.profile)
            .field("world", &self.world)
            .field("entrypoint", &self.entrypoint)
            .field("min_args", &self.min_args)
            .field("max_args", &self.max_args)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("limits", &self.limits)
            .finish()
    }
}

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_DEVELOPMENT_ARTIFACT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-development.artifact"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_A_P1_ARTIFACT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-operator-a-p1.artifact"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_A_P1_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-operator-a-p1.evidence"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_B_P1_ARTIFACT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-operator-b-p1.artifact"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_B_P1_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-operator-b-p1.evidence"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_A_P2_ARTIFACT_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-operator-a-p2.artifact"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_A_P2_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-operator-a-p2.evidence"));

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_WRONG_SIGNER_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-wrong-signer.evidence"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_UNKNOWN_SIGNER_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-unknown-signer.evidence"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_REVOKED_SIGNER_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-revoked-signer.evidence"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_CONTENT_HASH_ONLY_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c73-content-hash-only.evidence"));

macro_rules! c73_mutation_bytes {
    ($artifact:ident, $evidence:ident, $name:literal) => {
        #[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
        const $artifact: &[u8] = include_bytes!(concat!(
            env!("OUT_DIR"),
            "/c73-mutation-",
            $name,
            ".artifact"
        ));
        #[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
        const $evidence: &[u8] = include_bytes!(concat!(
            env!("OUT_DIR"),
            "/c73-mutation-",
            $name,
            ".evidence"
        ));
    };
}

c73_mutation_bytes!(
    C73_MUTATION_ARTIFACT_ARTIFACT_BYTES,
    C73_MUTATION_ARTIFACT_EVIDENCE_BYTES,
    "artifact"
);
c73_mutation_bytes!(
    C73_MUTATION_MODULE_ARTIFACT_BYTES,
    C73_MUTATION_MODULE_EVIDENCE_BYTES,
    "module"
);
c73_mutation_bytes!(
    C73_MUTATION_WIT_ARTIFACT_BYTES,
    C73_MUTATION_WIT_EVIDENCE_BYTES,
    "wit"
);
c73_mutation_bytes!(
    C73_MUTATION_ADAPTER_ARTIFACT_BYTES,
    C73_MUTATION_ADAPTER_EVIDENCE_BYTES,
    "adapter"
);
c73_mutation_bytes!(
    C73_MUTATION_LIMIT_ARTIFACT_BYTES,
    C73_MUTATION_LIMIT_EVIDENCE_BYTES,
    "limit"
);
c73_mutation_bytes!(
    C73_MUTATION_PROFILE_ARTIFACT_BYTES,
    C73_MUTATION_PROFILE_EVIDENCE_BYTES,
    "profile"
);

#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_OPERATOR_ROLE_BYTES: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c73-operator-role.rs"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_ACTIVE_PUBLIC_KEY_BYTES: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c73-active-public-key.rs"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_REVOKED_PUBLIC_KEY_BYTES: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c73-revoked-public-key.rs"));
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
const C73_DEVELOPMENT_POLICY_DIGEST_BYTES: [u8; 32] = include!(concat!(
    env!("OUT_DIR"),
    "/c73-development-policy-digest.rs"
));

#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
const C76_OPERATOR_ROLE_BYTES: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c76-operator-role.rs"));
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
// Hand-reviewed C7.6 trust root. Generated fixture output cannot replace this
// key; build_c76 independently requires the public vector to match it exactly.
const C76_ACTIVE_PUBLIC_KEY_BYTES: [u8; 32] = [
    0x1d, 0xfa, 0xeb, 0x2e, 0x9d, 0x9f, 0xf3, 0xd5, 0xc4, 0xeb, 0x7f, 0x81, 0xa1, 0x19, 0x7d, 0xd0,
    0x9f, 0x8a, 0x30, 0x1a, 0x5a, 0x31, 0xb6, 0xed, 0x15, 0x92, 0x1e, 0x93, 0x95, 0x74, 0x15, 0x4f,
];
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
const C76_G0_DESCRIPTOR_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c76-g0.descriptor"));
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
const C76_G1_DESCRIPTOR_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c76-g1.descriptor"));
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
const C76_G0_GRAPH_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c76-g0-graph.evidence"));
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
const C76_G1_GRAPH_EVIDENCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c76-g1-graph.evidence"));

macro_rules! c76_attachment_bytes {
    ($artifact:ident, $evidence:ident, $version:literal, $index:literal) => {
        #[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
        const $artifact: &[u8] = include_bytes!(concat!(
            env!("OUT_DIR"),
            "/c76-",
            $version,
            "-artifact-",
            $index,
            ".artifact"
        ));
        #[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
        const $evidence: &[u8] = include_bytes!(concat!(
            env!("OUT_DIR"),
            "/c76-",
            $version,
            "-evidence-",
            $index,
            ".evidence"
        ));
    };
}

c76_attachment_bytes!(C76_G0_ARTIFACT_0_BYTES, C76_G0_EVIDENCE_0_BYTES, "g0", "0");
c76_attachment_bytes!(C76_G0_ARTIFACT_1_BYTES, C76_G0_EVIDENCE_1_BYTES, "g0", "1");
c76_attachment_bytes!(C76_G0_ARTIFACT_2_BYTES, C76_G0_EVIDENCE_2_BYTES, "g0", "2");
c76_attachment_bytes!(C76_G1_ARTIFACT_0_BYTES, C76_G1_EVIDENCE_0_BYTES, "g1", "0");
c76_attachment_bytes!(C76_G1_ARTIFACT_1_BYTES, C76_G1_EVIDENCE_1_BYTES, "g1", "1");
c76_attachment_bytes!(C76_G1_ARTIFACT_2_BYTES, C76_G1_EVIDENCE_2_BYTES, "g1", "2");

const C53_STREAM_FILTER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c53-stream-filter.component.wasm"
));

const C53_STREAM_FILTER_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c53-stream-filter.sha256.rs"));

#[cfg(feature = "c64-resource-route-qemu-acceptance")]
const C64_RESOURCE_PROVIDER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c64-resource-provider.component.wasm"
));

#[cfg(feature = "c64-resource-route-qemu-acceptance")]
const C64_RESOURCE_PROVIDER_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c64-resource-provider.sha256.rs"));

#[cfg(feature = "c64-resource-route-qemu-acceptance")]
const C64_RESOURCE_CONSUMER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c64-resource-consumer.component.wasm"
));

#[cfg(feature = "c64-resource-route-qemu-acceptance")]
const C64_RESOURCE_CONSUMER_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c64-resource-consumer.sha256.rs"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_SOURCE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c65-async-source.component.wasm"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_SOURCE_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c65-async-source.sha256.rs"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_RELAY_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c65-async-relay.component.wasm"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_RELAY_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c65-async-relay.sha256.rs"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_SINK_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/c65-async-sink.component.wasm"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_SINK_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c65-async-sink.sha256.rs"));

#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c66-node-replacement-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
const C65_ASYNC_CHAIN_WIT_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c65-async-chain-wit.sha256.rs"));

#[cfg(feature = "c66-node-replacement-qemu-acceptance")]
const C66_ASYNC_RELAY_V2_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c66-async-relay-v2.component.wasm"
));

#[cfg(feature = "c66-node-replacement-qemu-acceptance")]
const C66_ASYNC_RELAY_V2_SHA256: [u8; 32] =
    include!(concat!(env!("OUT_DIR"), "/c66-async-relay-v2.sha256.rs"));

#[cfg(any(
    feature = "c53-native-async-qemu-acceptance",
    feature = "c53-native-async-command-projection"
))]
const C53_NATIVE_ASYNC_FILTER_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/c53-native-async-filter.component.wasm"
));

#[cfg(any(
    feature = "c53-native-async-qemu-acceptance",
    feature = "c53-native-async-command-projection"
))]
const C53_NATIVE_ASYNC_FILTER_SHA256: [u8; 32] = include!(concat!(
    env!("OUT_DIR"),
    "/c53-native-async-filter.sha256.rs"
));

const C53_STREAM_FILTER_WIT: &str = r#"
package vibe:%stream@1.0.0;

interface streams {
    resource reader;
    resource writer;

    enum close-reason {
        normal,
        failure,
        cancelled,
        denied,
        unavailable,
        exhausted,
        invalid,
        backend-fault,
    }

    read: func(input: borrow<reader>) -> list<u8>;
    write: func(output: borrow<writer>, bytes: list<u8>);
    close-reader: func(input: borrow<reader>, reason: close-reason);
    close-writer: func(output: borrow<writer>, reason: close-reason);
}

world filter {
    use streams.{reader, writer};
    import streams;
    export run: func(input: borrow<reader>, output: borrow<writer>);
}
"#;

#[cfg(any(
    feature = "c53-native-async-qemu-acceptance",
    feature = "c53-native-async-command-projection"
))]
const C53_NATIVE_ASYNC_FILTER_WIT: &str = r#"
package vibe:%stream@1.0.0;

world native-filter {
    enum close-reason {
        normal,
        failure,
        cancelled,
        denied,
        unavailable,
        exhausted,
        invalid,
        backend-fault,
    }

    type bytes = stream<u8>;
    type closed = future<close-reason>;

    record byte-stream {
        bytes: bytes,
        closed: closed,
    }

    export run: async func(input: byte-stream) -> byte-stream;
}
"#;

/// The one streaming Component made available to trusted SSH session setup by
/// the current QEMU and Duo image policies. Merely linking these bytes does not
/// install a command: exact admission and an explicit per-session policy
/// witness are still required. The two stream resources are lifecycle-owned
/// transport, never ambient authority or shell value arguments.
pub const SSH_EXEC_COMPONENT: ComponentCommandPin = ComponentCommandPin {
    artifact_bytes: C53_STREAM_FILTER_BYTES,
    expected_sha256: C53_STREAM_FILTER_SHA256,
    command_name: "case-filter",
    profile: ProfileIdentity::PROFILE_1,
    wit_source: C53_STREAM_FILTER_WIT,
    world: "vibe:stream/filter@1.0.0",
    entrypoint: "run",
    min_args: 0,
    max_args: 0,
    stdin: ComponentStreamMode::Required,
    stdout: ComponentStreamMode::Required,
    stderr: ComponentStreamMode::Optional,
    limits: ComponentInstanceLimits {
        memory_bytes: 512 * 1024,
        total_fuel: 500_000,
        poll_quantum: 100,
        resources: 4,
    },
};

/// Immutable executable guest for C5.3 native async runtime acceptance.
///
/// The checked-in artifact performs real bounded byte-stream reads and writes,
/// XORs each byte by `0x20`, and propagates all eight terminal reasons through
/// the close futures. This remains a validation-only runtime acceptance input,
/// not a production, kernel, SSH, or QEMU end-to-end activation claim.
#[cfg(feature = "c53-native-async-qemu-acceptance")]
pub const C53_NATIVE_ASYNC_QEMU_ACCEPTANCE: NativeAsyncAcceptancePin = NativeAsyncAcceptancePin {
    artifact_bytes: C53_NATIVE_ASYNC_FILTER_BYTES,
    expected_sha256: C53_NATIVE_ASYNC_FILTER_SHA256,
    command_name: "c53-native-filter",
    profile: ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    wit_source: C53_NATIVE_ASYNC_FILTER_WIT,
    world: "vibe:stream/native-filter@1.0.0",
    entrypoint: "run",
    min_args: 0,
    max_args: 0,
    stdin: ComponentStreamMode::Required,
    stdout: ComponentStreamMode::Required,
    stderr: ComponentStreamMode::Optional,
    limits: ComponentInstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 500_000,
        poll_quantum: 100,
        resources: 8,
    },
};

/// Explicit image-policy upgrade that lets the sealed adapter derive the
/// trusted native async projection, which carries an inert VSH manifest.
///
/// This does not activate the profile, install a VSH command, select an SSH
/// route, or authorize the native runtime. Those remain later trusted
/// lifecycle boundaries.
#[cfg(feature = "c53-native-async-command-projection")]
pub const C53_NATIVE_ASYNC_COMMAND: NativeAsyncCommandPin = NativeAsyncCommandPin {
    artifact_bytes: C53_NATIVE_ASYNC_FILTER_BYTES,
    expected_sha256: C53_NATIVE_ASYNC_FILTER_SHA256,
    command_name: "native-case-filter",
    profile: ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    wit_source: C53_NATIVE_ASYNC_FILTER_WIT,
    world: "vibe:stream/native-filter@1.0.0",
    entrypoint: "run",
    min_args: 0,
    max_args: 0,
    stdin: ComponentStreamMode::Required,
    stdout: ComponentStreamMode::Required,
    stderr: ComponentStreamMode::Optional,
    limits: ComponentInstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 500_000,
        poll_quantum: 100,
        resources: 8,
    },
};

/// Closed C7.3 development and deployable operator-authentication fixture.
///
/// Build-time checks independently regenerate every canonical artifact and
/// policy commitment, strictly verify every checked signature, and require
/// exact equality with the public vector file. No signing seed is linked into
/// this image. All artifacts and evidence remain inert (`runtime_ready=false`,
/// `guest_calls=0`) until later authenticated admission and execution gates.
#[cfg(feature = "c73-authenticated-admission-qemu-acceptance")]
pub const C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE: C73AuthenticatedAdmissionPin =
    C73AuthenticatedAdmissionPin {
        development: C73DevelopmentArtifactPin {
            artifact_bytes: C73_DEVELOPMENT_ARTIFACT_BYTES,
            signer_policy_digest: C73_DEVELOPMENT_POLICY_DIGEST_BYTES,
        },
        policy_p1: C73OperatorPolicyPin {
            generation: 1,
            operator_role: C73_OPERATOR_ROLE_BYTES,
            active_signer: C73_ACTIVE_PUBLIC_KEY_BYTES,
            revoked_signer: C73_REVOKED_PUBLIC_KEY_BYTES,
            exact_wit_source: include_str!("../artifacts/c73-byte-filter.wit"),
        },
        policy_p2: C73OperatorPolicyPin {
            generation: 2,
            operator_role: C73_OPERATOR_ROLE_BYTES,
            active_signer: C73_ACTIVE_PUBLIC_KEY_BYTES,
            revoked_signer: C73_REVOKED_PUBLIC_KEY_BYTES,
            exact_wit_source: include_str!("../artifacts/c73-byte-filter.wit"),
        },
        operator_p1: [
            C73OperatorArtifactPin {
                artifact_bytes: C73_OPERATOR_A_P1_ARTIFACT_BYTES,
                evidence_bytes: C73_OPERATOR_A_P1_EVIDENCE_BYTES,
            },
            C73OperatorArtifactPin {
                artifact_bytes: C73_OPERATOR_B_P1_ARTIFACT_BYTES,
                evidence_bytes: C73_OPERATOR_B_P1_EVIDENCE_BYTES,
            },
        ],
        operator_p2: C73OperatorArtifactPin {
            artifact_bytes: C73_OPERATOR_A_P2_ARTIFACT_BYTES,
            evidence_bytes: C73_OPERATOR_A_P2_EVIDENCE_BYTES,
        },
        rejected_evidence: [
            C73RejectedEvidencePin {
                kind: C73RejectedEvidenceKind::WrongSignature,
                evidence_bytes: C73_WRONG_SIGNER_EVIDENCE_BYTES,
            },
            C73RejectedEvidencePin {
                kind: C73RejectedEvidenceKind::UnknownSigner,
                evidence_bytes: C73_UNKNOWN_SIGNER_EVIDENCE_BYTES,
            },
            C73RejectedEvidencePin {
                kind: C73RejectedEvidenceKind::RevokedSigner,
                evidence_bytes: C73_REVOKED_SIGNER_EVIDENCE_BYTES,
            },
            C73RejectedEvidencePin {
                kind: C73RejectedEvidenceKind::ContentHashOnly,
                evidence_bytes: C73_CONTENT_HASH_ONLY_EVIDENCE_BYTES,
            },
        ],
        mutations: [
            C73ArtifactMutationPin {
                kind: C73ArtifactMutationKind::ArtifactManifest,
                artifact_bytes: C73_MUTATION_ARTIFACT_ARTIFACT_BYTES,
                evidence_bytes: C73_MUTATION_ARTIFACT_EVIDENCE_BYTES,
            },
            C73ArtifactMutationPin {
                kind: C73ArtifactMutationKind::CoreModuleManifest,
                artifact_bytes: C73_MUTATION_MODULE_ARTIFACT_BYTES,
                evidence_bytes: C73_MUTATION_MODULE_EVIDENCE_BYTES,
            },
            C73ArtifactMutationPin {
                kind: C73ArtifactMutationKind::ExactWitSource,
                artifact_bytes: C73_MUTATION_WIT_ARTIFACT_BYTES,
                evidence_bytes: C73_MUTATION_WIT_EVIDENCE_BYTES,
            },
            C73ArtifactMutationPin {
                kind: C73ArtifactMutationKind::AdapterManifest,
                artifact_bytes: C73_MUTATION_ADAPTER_ARTIFACT_BYTES,
                evidence_bytes: C73_MUTATION_ADAPTER_EVIDENCE_BYTES,
            },
            C73ArtifactMutationPin {
                kind: C73ArtifactMutationKind::InstanceLimits,
                artifact_bytes: C73_MUTATION_LIMIT_ARTIFACT_BYTES,
                evidence_bytes: C73_MUTATION_LIMIT_EVIDENCE_BYTES,
            },
            C73ArtifactMutationPin {
                kind: C73ArtifactMutationKind::ProfileIdentity,
                artifact_bytes: C73_MUTATION_PROFILE_ARTIFACT_BYTES,
                evidence_bytes: C73_MUTATION_PROFILE_EVIDENCE_BYTES,
            },
        ],
    };

/// Independent current C7.6 operator policy.  It is intentionally a separate
/// constant from both image candidates so boot recovery can construct the
/// current validation policy without touching either candidate bundle.
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
pub const C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE: C76GraphOperatorPolicyPin =
    C76GraphOperatorPolicyPin {
        generation: 1,
        operator_role: C76_OPERATOR_ROLE_BYTES,
        active_signer: C76_ACTIVE_PUBLIC_KEY_BYTES,
        exact_wit_source: include_str!("../artifacts/c65-async-chain.wit"),
    };

/// Initial graph image candidate, named only by the classified vacant branch.
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
pub const C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE: C76GraphVersionPin = C76GraphVersionPin {
    ordinal: 0,
    descriptor_bytes: C76_G0_DESCRIPTOR_BYTES,
    artifact_bytes: [
        C76_G0_ARTIFACT_0_BYTES,
        C76_G0_ARTIFACT_1_BYTES,
        C76_G0_ARTIFACT_2_BYTES,
    ],
    artifact_evidence_bytes: [
        C76_G0_EVIDENCE_0_BYTES,
        C76_G0_EVIDENCE_1_BYTES,
        C76_G0_EVIDENCE_2_BYTES,
    ],
    graph_evidence_bytes: C76_G0_GRAPH_EVIDENCE_BYTES,
};

/// Successor graph image candidate, named only after physical G0 recovery and
/// fresh current-policy/current-engine validation release its one-shot gate.
#[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
pub const C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE: C76GraphVersionPin = C76GraphVersionPin {
    ordinal: 1,
    descriptor_bytes: C76_G1_DESCRIPTOR_BYTES,
    artifact_bytes: [
        C76_G1_ARTIFACT_0_BYTES,
        C76_G1_ARTIFACT_1_BYTES,
        C76_G1_ARTIFACT_2_BYTES,
    ],
    artifact_evidence_bytes: [
        C76_G1_EVIDENCE_0_BYTES,
        C76_G1_EVIDENCE_1_BYTES,
        C76_G1_EVIDENCE_2_BYTES,
    ],
    graph_evidence_bytes: C76_G1_GRAPH_EVIDENCE_BYTES,
};

/// Exact validation-only graph policy root used by the C6.4 QEMU lifecycle
/// proof. Resource authority is created later by the explicit kernel
/// supervisor transaction; these artifacts and names are never lookup
/// authority.
#[cfg(feature = "c64-resource-route-qemu-acceptance")]
pub const C64_RESOURCE_ROUTE_QEMU_ACCEPTANCE: ComponentGraphResourceRoutePin =
    ComponentGraphResourceRoutePin {
        provider_bytes: C64_RESOURCE_PROVIDER_BYTES,
        provider_sha256: C64_RESOURCE_PROVIDER_SHA256,
        consumer_bytes: C64_RESOURCE_CONSUMER_BYTES,
        consumer_sha256: C64_RESOURCE_CONSUMER_SHA256,
        wit_source: include_str!("../artifacts/c64-resource-route.wit"),
        wit_sha256: [
            0x07, 0x16, 0xe0, 0x79, 0x84, 0x89, 0x6d, 0xf8, 0x3b, 0xc2, 0x6a, 0x82, 0x82, 0x23,
            0x6e, 0x6d, 0xfa, 0x70, 0x8b, 0xf6, 0x71, 0x92, 0x85, 0x3b, 0xd8, 0xcd, 0x84, 0x79,
            0xcc, 0xec, 0x13, 0x41,
        ],
        provider_world: "test:c64-resource/provider@1.0.0",
        consumer_world: "test:c64-resource/consumer@1.0.0",
        interface: "test:c64-resource/route@1.0.0",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        limits: ComponentInstanceLimits {
            memory_bytes: 64 * 1024,
            total_fuel: 1_000,
            poll_quantum: 100,
            resources: 2,
        },
    };

/// Exact image-policy root for a validation-only three-node async chain.
///
/// The source exports the pinned pipe interface, relay and sink each import
/// and export it, and only the sink export may be published by the separately
/// reviewed kernel graph policy. `PROFILE_1_ASYNC` deliberately keeps every
/// embedded canonical lift inert.
#[cfg(any(
    feature = "c65-async-chain-qemu-acceptance",
    feature = "c67-information-flow-qemu-acceptance"
))]
pub const C65_ASYNC_CHAIN_QEMU_ACCEPTANCE: ComponentGraphAsyncChainPin =
    ComponentGraphAsyncChainPin {
        source_bytes: C65_ASYNC_SOURCE_BYTES,
        source_sha256: C65_ASYNC_SOURCE_SHA256,
        relay_bytes: C65_ASYNC_RELAY_BYTES,
        relay_sha256: C65_ASYNC_RELAY_SHA256,
        sink_bytes: C65_ASYNC_SINK_BYTES,
        sink_sha256: C65_ASYNC_SINK_SHA256,
        wit_source: include_str!("../artifacts/c65-async-chain.wit"),
        wit_sha256: C65_ASYNC_CHAIN_WIT_SHA256,
        source_world: "test:c65-chain/source@1.0.0",
        relay_world: "test:c65-chain/relay@1.0.0",
        sink_world: "test:c65-chain/sink@1.0.0",
        interface: "test:c65-chain/pipe@1.0.0",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        limits: ComponentInstanceLimits {
            memory_bytes: 64 * 1024,
            total_fuel: 1_000,
            poll_quantum: 100,
            resources: 8,
        },
    };

/// C6.7 deliberately reuses the exact validation-only C6.5 artifact set. The
/// new policy root authorizes semantic inspection only; graph wiring and
/// policy labels are still supplied explicitly by the kernel acceptance gate.
#[cfg(feature = "c67-information-flow-qemu-acceptance")]
pub const C67_INFORMATION_FLOW_QEMU_ACCEPTANCE: ComponentGraphAsyncChainPin =
    C65_ASYNC_CHAIN_QEMU_ACCEPTANCE;

/// Exact validation-only policy root for replacing the middle C6.5 relay.
///
/// This reuses the C6.5 source, old relay, sink, WIT, worlds, profile, and
/// ceilings without changing the C6.5 pin. Only the relay artifact identity is
/// updated. Both incident edges must be recreated under fresh local runtime
/// identities, and the bounded image authorizes exactly one such replacement.
#[cfg(feature = "c66-node-replacement-qemu-acceptance")]
pub const C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE: ComponentGraphNodeReplacementPin =
    ComponentGraphNodeReplacementPin {
        source_bytes: C65_ASYNC_SOURCE_BYTES,
        source_sha256: C65_ASYNC_SOURCE_SHA256,
        old_relay_bytes: C65_ASYNC_RELAY_BYTES,
        old_relay_sha256: C65_ASYNC_RELAY_SHA256,
        new_relay_bytes: C66_ASYNC_RELAY_V2_BYTES,
        new_relay_sha256: C66_ASYNC_RELAY_V2_SHA256,
        sink_bytes: C65_ASYNC_SINK_BYTES,
        sink_sha256: C65_ASYNC_SINK_SHA256,
        wit_source: include_str!("../artifacts/c65-async-chain.wit"),
        wit_sha256: C65_ASYNC_CHAIN_WIT_SHA256,
        source_world: "test:c65-chain/source@1.0.0",
        relay_world: "test:c65-chain/relay@1.0.0",
        sink_world: "test:c65-chain/sink@1.0.0",
        interface: "test:c65-chain/pipe@1.0.0",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        limits: ComponentInstanceLimits {
            memory_bytes: 64 * 1024,
            total_fuel: 1_000,
            poll_quantum: 100,
            resources: 8,
        },
        node_count: 3,
        replacement_node: 1,
        incident_edges: [
            ComponentGraphReplacementEdgePin::new(
                0,
                0,
                1,
                0,
                ComponentGraphReplacementPinAction::RecreateFresh,
            ),
            ComponentGraphReplacementEdgePin::new(
                1,
                0,
                2,
                0,
                ComponentGraphReplacementPinAction::RecreateFresh,
            ),
        ],
        max_replacements: 1,
    };

/// The default QEMU image admits a bounded managed slice. Storage V2 initially
/// formats only its policy range within this slice; unused suffix capacity is
/// not ambient store capacity and may be admitted only by explicit growth.
#[cfg(all(feature = "qemu-default", feature = "storage-bench"))]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    // The benchmark harness always provisions a 1 GiB data disk; admit all of
    // it so large-file workloads exercise real growth instead of an
    // artificially small window. The raw-block benchmark range parks in the
    // final 64 MiB.
    sector_count: 2_097_152,
});

#[cfg(all(
    feature = "qemu-default",
    not(feature = "storage-bench"),
    not(feature = "file-tree")
))]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    sector_count: 131_072,
});

/// The capability-rooted file-tree acceptance image uses a dedicated 128 MiB
/// managed slice. The initial V2 ABI remains the same 8-segment window; the
/// aligned suffix becomes usable only through the maintenance growth protocol.
#[cfg(all(
    feature = "qemu-default",
    feature = "file-tree",
    not(feature = "storage-bench")
))]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    sector_count: 262_144,
});

/// The packaged Duo image places raw service data immediately after its
/// 128 MiB FAT boot partition. The slice is 512 MiB: Storage V2's segment
/// granule is 4 MiB and its foreground free-segment policy needs dozens of
/// segments of headroom, so the previous 64 MiB (sixteen segments) forced a
/// full garbage-collection walk on nearly every commit.
#[cfg(feature = "milkv-duo-sd")]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 262_145,
    sector_count: 1_048_576,
});

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use sha2::{Digest, Sha256};

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn frontend_queue_is_bounded() {
        assert!(NETWORK_FRONTEND.queue_depth > 0);
    }

    #[test]
    fn ssh_component_policy_pins_every_admission_field() {
        let pin = SSH_EXEC_COMPONENT;
        assert!(!pin.artifact_bytes().is_empty());
        assert_eq!(pin.expected_sha256(), C53_STREAM_FILTER_SHA256);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.artifact_bytes())),
            pin.expected_sha256()
        );
        assert_eq!(pin.command_name(), "case-filter");
        assert_eq!(pin.profile(), ProfileIdentity::PROFILE_1);
        assert_eq!(pin.abi(), ProfileIdentity::PROFILE_1.runtime_abi);
        assert_eq!(pin.world(), "vibe:stream/filter@1.0.0");
        assert_eq!(pin.entrypoint(), "run");
        assert_eq!((pin.min_args(), pin.max_args()), (0, 0));
        assert_eq!(pin.stdin(), ComponentStreamMode::Required);
        assert_eq!(pin.stdout(), ComponentStreamMode::Required);
        assert_eq!(pin.stderr(), ComponentStreamMode::Optional);
        assert_eq!(
            pin.limits(),
            ComponentInstanceLimits {
                memory_bytes: 512 * 1024,
                total_fuel: 500_000,
                poll_quantum: 100,
                resources: 4,
            }
        );
        assert!(pin.wit_source().contains("import streams;"));
        assert!(pin
            .wit_source()
            .contains("export run: func(input: borrow<reader>, output: borrow<writer>);"));
    }

    #[cfg(feature = "c53-native-async-qemu-acceptance")]
    #[test]
    fn native_async_candidate_has_an_independent_validation_only_identity() {
        let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
        assert_ne!(pin.artifact_bytes(), SSH_EXEC_COMPONENT.artifact_bytes());
        assert_ne!(pin.expected_sha256(), SSH_EXEC_COMPONENT.expected_sha256());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.artifact_bytes())),
            pin.expected_sha256()
        );
        assert_eq!(pin.command_name(), "c53-native-filter");
        assert_eq!(
            pin.profile(),
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        );
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.abi(), 3);
        assert_eq!(pin.world(), "vibe:stream/native-filter@1.0.0");
        assert_eq!(pin.entrypoint(), "run");
        assert_eq!((pin.min_args(), pin.max_args()), (0, 0));
        assert_eq!(pin.stdin(), ComponentStreamMode::Required);
        assert_eq!(pin.stdout(), ComponentStreamMode::Required);
        assert_eq!(pin.stderr(), ComponentStreamMode::Optional);
        assert_eq!(pin.limits().resources, 8);
        assert!(pin.wit_source().contains("type bytes = stream<u8>;"));
        assert!(pin
            .wit_source()
            .contains("export run: async func(input: byte-stream) -> byte-stream;"));
    }

    #[cfg(feature = "c64-resource-route-qemu-acceptance")]
    #[test]
    fn c64_resource_route_pair_is_exact_and_validation_only() {
        let pin = C64_RESOURCE_ROUTE_QEMU_ACCEPTANCE;
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.provider_bytes())),
            pin.provider_sha256()
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.consumer_bytes())),
            pin.consumer_sha256()
        );
        assert_ne!(pin.provider_sha256(), pin.consumer_sha256());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.wit_source().as_bytes())),
            pin.wit_sha256()
        );
        assert_eq!(pin.profile(), ProfileIdentity::PROFILE_1_ASYNC);
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.interface(), "test:c64-resource/route@1.0.0");
        assert!(pin.wit_source().contains("borrow<handle>"));
        assert!(pin.wit_source().contains("own<handle>"));
        assert_eq!(pin.limits().resources, 2);
    }

    #[cfg(any(
        feature = "c65-async-chain-qemu-acceptance",
        feature = "c67-information-flow-qemu-acceptance"
    ))]
    #[test]
    fn c65_async_chain_is_exact_resource_free_and_validation_only() {
        use vibeos_component_runtime::{
            decode::inspect_component_for_profile, world::WorldContract,
        };

        let pin = C65_ASYNC_CHAIN_QEMU_ACCEPTANCE;
        for (bytes, expected) in [
            (pin.source_bytes(), pin.source_sha256()),
            (pin.relay_bytes(), pin.relay_sha256()),
            (pin.sink_bytes(), pin.sink_sha256()),
        ] {
            assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), expected);
        }
        assert_ne!(pin.source_sha256(), pin.relay_sha256());
        assert_ne!(pin.source_sha256(), pin.sink_sha256());
        assert_ne!(pin.relay_sha256(), pin.sink_sha256());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.wit_source().as_bytes())),
            pin.wit_sha256()
        );
        assert_eq!(pin.profile(), ProfileIdentity::PROFILE_1_ASYNC);
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.source_world(), "test:c65-chain/source@1.0.0");
        assert_eq!(pin.relay_world(), "test:c65-chain/relay@1.0.0");
        assert_eq!(pin.sink_world(), "test:c65-chain/sink@1.0.0");
        assert_eq!(pin.interface(), "test:c65-chain/pipe@1.0.0");
        assert_eq!(
            pin.limits(),
            ComponentInstanceLimits {
                memory_bytes: 64 * 1024,
                total_fuel: 1_000,
                poll_quantum: 100,
                resources: 8,
            }
        );
        assert!(pin.wit_source().contains("type bytes = stream<u8>;"));
        assert!(pin
            .wit_source()
            .contains("type closed = future<close-reason>;"));
        assert!(pin
            .wit_source()
            .contains("run: async func(input: byte-stream) -> byte-stream;"));
        assert!(!pin.wit_source().contains("resource "));
        assert!(!pin.wit_source().contains("borrow<"));
        assert!(!pin.wit_source().contains("own<"));

        for (bytes, world_name, imports, exports) in [
            (pin.source_bytes(), pin.source_world(), 0, 1),
            (pin.relay_bytes(), pin.relay_world(), 1, 1),
            (pin.sink_bytes(), pin.sink_world(), 1, 1),
        ] {
            let plan = inspect_component_for_profile(bytes, pin.profile())
                .expect("pinned C6.5 Component must inspect under Profile 1 async");
            let world = WorldContract::parse(pin.wit_source(), world_name)
                .expect("pinned C6.5 world must parse");
            plan.check_world(&world)
                .expect("pinned C6.5 Component must match its exact world");
            assert_eq!(plan.imports().len(), imports);
            assert_eq!(plan.exports().len(), exports);
            assert_eq!(plan.exports()[0].name, pin.interface());
            if imports == 1 {
                assert_eq!(plan.imports()[0].name, pin.interface());
            }
            assert_eq!(plan.summary().resources, 0);
            assert!(plan.summary().async_abi.async_function_types > 0);
            assert!(plan.summary().async_abi.stream_types > 0);
            assert!(plan.summary().async_abi.future_types > 0);
            assert!(!plan.runtime_ready());
            assert!(!plan.native_async_runtime_ready());
            assert_eq!(plan.executable_exports().count(), 0);
        }
    }

    #[cfg(feature = "c66-node-replacement-qemu-acceptance")]
    #[test]
    fn c66_node_replacement_pin_is_exact_bounded_and_redacted() {
        let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
        for (bytes, expected) in [
            (pin.source_bytes(), pin.source_sha256()),
            (pin.old_relay_bytes(), pin.old_relay_sha256()),
            (pin.new_relay_bytes(), pin.new_relay_sha256()),
            (pin.sink_bytes(), pin.sink_sha256()),
        ] {
            assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), expected);
        }
        assert_eq!(pin.source_sha256(), C65_ASYNC_SOURCE_SHA256);
        assert_eq!(pin.old_relay_sha256(), C65_ASYNC_RELAY_SHA256);
        assert_eq!(pin.sink_sha256(), C65_ASYNC_SINK_SHA256);
        assert_ne!(pin.old_relay_sha256(), pin.new_relay_sha256());
        assert_ne!(pin.source_sha256(), pin.new_relay_sha256());
        assert_ne!(pin.sink_sha256(), pin.new_relay_sha256());
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.wit_source().as_bytes())),
            pin.wit_sha256()
        );
        assert_eq!(pin.wit_sha256(), C65_ASYNC_CHAIN_WIT_SHA256);
        assert_eq!(pin.profile(), ProfileIdentity::PROFILE_1_ASYNC);
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.source_world(), "test:c65-chain/source@1.0.0");
        assert_eq!(pin.relay_world(), "test:c65-chain/relay@1.0.0");
        assert_eq!(pin.sink_world(), "test:c65-chain/sink@1.0.0");
        assert_eq!(pin.interface(), "test:c65-chain/pipe@1.0.0");
        assert_eq!(
            pin.limits(),
            ComponentInstanceLimits {
                memory_bytes: 64 * 1024,
                total_fuel: 1_000,
                poll_quantum: 100,
                resources: 8,
            }
        );
        assert_eq!(pin.node_count(), 3);
        assert_eq!(pin.replacement_node(), 1);
        assert_eq!(pin.max_replacements(), 1);
        assert_eq!(
            pin.incident_edges(),
            [
                ComponentGraphReplacementEdgePin::new(
                    0,
                    0,
                    1,
                    0,
                    ComponentGraphReplacementPinAction::RecreateFresh,
                ),
                ComponentGraphReplacementEdgePin::new(
                    1,
                    0,
                    2,
                    0,
                    ComponentGraphReplacementPinAction::RecreateFresh,
                ),
            ]
        );
        for edge in pin.incident_edges() {
            assert!(
                edge.source_node() == pin.replacement_node()
                    || edge.target_node() == pin.replacement_node()
            );
            assert_eq!(edge.source_export(), 0);
            assert_eq!(edge.target_import(), 0);
            assert_eq!(
                edge.action(),
                ComponentGraphReplacementPinAction::RecreateFresh
            );
        }

        let debug = std::format!("{pin:?}");
        assert!(debug.contains("artifacts: \"<redacted>\""));
        assert!(debug.contains("wit_source: \"<redacted>\""));
        assert!(!debug.contains(&std::format!("{:?}", pin.old_relay_sha256())));
        assert!(!debug.contains(&std::format!("{:?}", pin.new_relay_sha256())));
        assert!(!debug.contains("(component"));
    }

    #[cfg(feature = "c66-node-replacement-qemu-acceptance")]
    #[test]
    fn c66_relay_update_changes_identity_but_preserves_the_exact_world() {
        use vibeos_component_runtime::{
            decode::inspect_component_for_profile, world::WorldContract,
        };

        let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
        let world = WorldContract::parse(pin.wit_source(), pin.relay_world())
            .expect("pinned C6.6 relay world must parse");
        let old = inspect_component_for_profile(pin.old_relay_bytes(), pin.profile())
            .expect("pinned C6.6 old relay must inspect under Profile 1 async");
        let new = inspect_component_for_profile(pin.new_relay_bytes(), pin.profile())
            .expect("pinned C6.6 new relay must inspect under Profile 1 async");

        old.check_world(&world)
            .expect("pinned C6.6 old relay must match the exact relay world");
        new.check_world(&world)
            .expect("pinned C6.6 new relay must match the exact relay world");
        assert_eq!(old.imports(), new.imports());
        assert_eq!(old.exports(), new.exports());
        assert_eq!(old.imports().len(), 1);
        assert_eq!(old.exports().len(), 1);
        assert_eq!(old.imports()[0].name, pin.interface());
        assert_eq!(old.exports()[0].name, pin.interface());
        assert_eq!(old.summary().resources, 0);
        assert_eq!(new.summary().resources, 0);
        assert_eq!(old.summary().async_abi, new.summary().async_abi);
        assert!(!old.runtime_ready());
        assert!(!new.runtime_ready());
        assert!(!old.native_async_runtime_ready());
        assert!(!new.native_async_runtime_ready());
        assert_eq!(old.executable_exports().count(), 0);
        assert_eq!(new.executable_exports().count(), 0);
        assert_ne!(pin.old_relay_bytes(), pin.new_relay_bytes());
        assert_ne!(pin.old_relay_sha256(), pin.new_relay_sha256());
    }

    #[cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]
    #[test]
    fn c76_every_evidence_value_uses_the_handwritten_active_signer() {
        let policy = C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE;
        assert_eq!(
            policy.active_public_key_bytes(),
            C76_ACTIVE_PUBLIC_KEY_BYTES
        );
        for version in [
            C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE,
            C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE,
        ] {
            for evidence in version
                .artifact_evidence()
                .expect("C7.6 leaf evidence must remain canonical")
            {
                assert_eq!(
                    evidence.public_key().as_bytes(),
                    &C76_ACTIVE_PUBLIC_KEY_BYTES
                );
            }
            assert_eq!(
                version
                    .graph_evidence()
                    .expect("C7.6 graph evidence must remain canonical")
                    .public_key()
                    .as_bytes(),
                &C76_ACTIVE_PUBLIC_KEY_BYTES
            );
        }
    }

    #[cfg(feature = "c53-native-async-command-projection")]
    #[test]
    fn native_async_command_projection_requires_its_own_exact_pin() {
        let pin = C53_NATIVE_ASYNC_COMMAND;
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(pin.artifact_bytes())),
            pin.expected_sha256()
        );
        assert_eq!(pin.command_name(), "native-case-filter");
        assert_eq!(
            pin.profile(),
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        );
        assert!(!pin.profile().execution_enabled());
        assert_eq!(pin.abi(), 3);
        assert_eq!(pin.world(), "vibe:stream/native-filter@1.0.0");
        assert_eq!(pin.entrypoint(), "run");
        assert_eq!((pin.min_args(), pin.max_args()), (0, 0));
        assert_eq!(pin.stdin(), ComponentStreamMode::Required);
        assert_eq!(pin.stdout(), ComponentStreamMode::Required);
        assert_eq!(pin.stderr(), ComponentStreamMode::Optional);
        assert_eq!(pin.limits().resources, 8);
    }

    #[cfg(all(
        feature = "c53-native-async-qemu-acceptance",
        feature = "c53-native-async-command-projection"
    ))]
    #[test]
    fn native_async_policy_roots_are_distinct_types_over_the_same_artifact() {
        assert_ne!(
            core::any::type_name::<NativeAsyncAcceptancePin>(),
            core::any::type_name::<NativeAsyncCommandPin>()
        );
        assert_eq!(
            C53_NATIVE_ASYNC_QEMU_ACCEPTANCE.expected_sha256(),
            C53_NATIVE_ASYNC_COMMAND.expected_sha256()
        );
        assert_eq!(
            C53_NATIVE_ASYNC_QEMU_ACCEPTANCE.artifact_bytes(),
            C53_NATIVE_ASYNC_COMMAND.artifact_bytes()
        );
    }

    #[cfg(feature = "qemu-default")]
    #[test]
    fn qemu_data_slice_is_exact_and_checked() {
        assert_eq!(
            BLOCK_DATA_SLICE.unwrap().end_sector(),
            Some(if cfg!(feature = "storage-bench") {
                2_097_152
            } else if cfg!(feature = "file-tree") {
                262_144
            } else {
                131_072
            })
        );
    }

    #[cfg(feature = "milkv-duo-sd")]
    #[test]
    fn duo_data_slice_does_not_overflow() {
        assert_eq!(BLOCK_DATA_SLICE.unwrap().end_sector(), Some(1_310_721));
    }
}
