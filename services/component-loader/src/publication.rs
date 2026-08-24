//! C7.5 cold-boot Component revalidation and inert publication.
//!
//! The production surface never exposes stable IDs, record bytes, a journal
//! checkpoint, or a recovered snapshot. Every boot consumes one boot-proved
//! Storage V2 head, discovers the fixed root without caller-supplied expected
//! bytes, performs an independent physical readback, and only then validates
//! the recovered artifact and evidence against current policy and the current
//! validation engine. No pre-append admission value can cross that boundary.

use alloc::vec::Vec;
use core::fmt;

use vibeos_component_admission::AdmittedComponent;
use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactSignerPolicyKind,
    ComponentArtifactV1, COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN,
};
use vibeos_object_store::{
    C75PendingPhysicalReadback, C75RecoveredDevelopmentPayload, C75RecoveredOperatorPayload,
    C75RecoveredPublicationPayload, C75RecoveredState, C75StorageV2Error, C75VacantHead,
    StorageV2RecoveredAuthorityHead, StoreError,
};

use crate::{
    admit_development_component_bytes, authenticate_and_admit_component_bytes,
    project_admitted_component, ComponentLoadError, DeployableComponentLoadPolicy,
    DevelopmentComponentLoadPolicy, VolatileComponentCommand,
};

/// Move-only preinstallation candidate. Validation prevents writing already
/// invalid development bytes, but its admission result is destroyed before
/// this value is returned and conveys no postflight publication authority.
#[must_use = "a prevalidated development install candidate must be installed or discarded"]
pub struct DevelopmentComponentInstallCandidate {
    artifact_bytes: Vec<u8>,
}

/// Move-only preinstallation candidate for canonical operator bytes/evidence.
/// It contains no `AdmittedComponent`, command, or reusable validator receipt.
///
/// ```compile_fail
/// use vibeos_component_loader::OperatorComponentInstallCandidate;
/// fn preappend_proof_cannot_publish(candidate: OperatorComponentInstallCandidate) {
///     let _ = candidate.seal_inert_publication();
/// }
/// ```
#[must_use = "a prevalidated operator install candidate must be installed or discarded"]
pub struct OperatorComponentInstallCandidate {
    artifact_bytes: Vec<u8>,
    evidence_bytes: [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN],
}

/// Perform the development persistence-hygiene gate and retain only bytes.
pub fn admit_development_component_install(
    bytes: &[u8],
    policy: &DevelopmentComponentLoadPolicy<'_>,
) -> Result<DevelopmentComponentInstallCandidate, ComponentLoadError> {
    let artifact = ComponentArtifactV1::decode(bytes).map_err(ComponentLoadError::Artifact)?;
    if artifact.signer_policy().kind() != ComponentArtifactSignerPolicyKind::DevelopmentImagePin {
        return Err(ComponentLoadError::SignerPolicy);
    }
    let canonical = artifact.encode().map_err(ComponentLoadError::Artifact)?;
    if canonical.as_slice() != bytes {
        return Err(ComponentLoadError::ImagePinMismatch);
    }
    // This check prevents persisting bytes which are already invalid, but the
    // admitted value is deliberately destroyed here. It can never authorize
    // post-append publication; C7.5 repeats the complete gate over physical
    // readback bytes on every boot.
    drop(admit_development_component_bytes(bytes, policy)?);
    Ok(DevelopmentComponentInstallCandidate {
        artifact_bytes: canonical,
    })
}

/// Perform the deployable gate and retain the canonical 112-byte evidence
/// beside canonical artifact bytes. The admission result is discarded and
/// failure cannot fall back to development trust.
pub fn admit_operator_component_install(
    bytes: &[u8],
    evidence_bytes: &[u8],
    policy: &DeployableComponentLoadPolicy<'_>,
) -> Result<OperatorComponentInstallCandidate, ComponentLoadError> {
    let evidence = ComponentArtifactAuthenticationEvidenceV1::decode(evidence_bytes)
        .map_err(ComponentLoadError::AuthenticationEvidence)?;
    let artifact = ComponentArtifactV1::decode(bytes).map_err(ComponentLoadError::Artifact)?;
    if artifact.signer_policy().kind() != ComponentArtifactSignerPolicyKind::OperatorRequired {
        return Err(ComponentLoadError::SignerPolicy);
    }
    let canonical = artifact.encode().map_err(ComponentLoadError::Artifact)?;
    if canonical.as_slice() != bytes {
        return Err(ComponentLoadError::Authentication(
            vibeos_component_admission::ArtifactAuthenticationError::ArtifactEncoding,
        ));
    }
    let evidence_bytes = evidence.encode();
    // As above, this is a persistence hygiene check only. The operator
    // admission proof must not survive the durable boundary.
    drop(authenticate_and_admit_component_bytes(
        bytes,
        &evidence_bytes,
        policy,
    )?);
    Ok(OperatorComponentInstallCandidate {
        artifact_bytes: canonical,
        evidence_bytes,
    })
}

/// Start one C7.5 cold-boot probe. The object store privately enforces the
/// fixed Storage V2 policy and root-relative layout; this crate receives only
/// an opaque vacant head or an existing value which still requires physical
/// readback.
///
/// ```compile_fail
/// use vibeos_component_loader::begin_c75_component_boot;
/// use vibeos_object_store::AuthoritySnapshot;
/// fn cannot_begin_from_snapshot(snapshot: AuthoritySnapshot) {
///     let _ = begin_c75_component_boot(snapshot);
/// }
/// ```
pub async fn begin_c75_component_boot(
    head: StorageV2RecoveredAuthorityHead,
) -> Result<C75ComponentBootState, ComponentInstallProtocolError> {
    match head
        .recover_c75_state()
        .await
        .map_err(map_c75_storage_v2_error)?
    {
        C75RecoveredState::Vacant(head) => {
            Ok(C75ComponentBootState::Vacant(C75VacantComponentInstall {
                head,
            }))
        }
        C75RecoveredState::Existing(pending) => Ok(C75ComponentBootState::Existing(
            C75PendingComponentReadback { pending },
        )),
    }
}

/// Canonical C7.4 Storage V2 external-root policy image. Kernel policy and the
/// installer hash/compare this same frozen byte string; callers cannot reflect
/// a journal-provided digest back into the gate.
#[cfg(test)]
const C74_STORAGE_V2_EXTERNAL_POLICY: &[u8] = b"vibeos.storage-v2.external-policy.v2\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0component-space=0x564942454f532d434f4d504f4e454e54,slot=0,generation=0,rights=r,kind=0x434d5031\0component-evidence=exact-root-relative,kind=0x434d4531,len=112,inline=1,ungranted=1\0sealed-singleton-optional=0x53534801";

/// SHA-256 of the private canonical C7.4 Storage V2 policy image. Comparison
/// metadata only: this is not authority, an object name, or a caller-selected
/// policy digest.
///
/// ```compile_fail
/// use vibeos_component_loader::C74_STORAGE_V2_EXTERNAL_POLICY;
/// fn raw_policy_image_is_private() {
///     let _ = C74_STORAGE_V2_EXTERNAL_POLICY;
/// }
/// ```
pub const C74_STORAGE_V2_EXTERNAL_POLICY_SHA256: [u8; 32] = [
    0x85, 0x6f, 0x31, 0x4c, 0xfb, 0xd8, 0x21, 0xec, 0x0f, 0x87, 0x30, 0x90, 0x39, 0x48, 0xa8, 0xc1,
    0x65, 0xbf, 0x5c, 0xe8, 0x6b, 0xf4, 0x16, 0xda, 0x2b, 0x21, 0x7b, 0xf6, 0xc3, 0x49, 0x2a, 0xa3,
];

pub const fn c74_storage_v2_policy_commitment_sha256() -> [u8; 32] {
    C74_STORAGE_V2_EXTERNAL_POLICY_SHA256
}

/// The only outcomes of the fixed-root cold-boot probe. Existing media never
/// needs (or accepts) artifact/evidence bytes from the caller.
#[must_use = "the C7.5 boot state must be physically recovered or initialized"]
pub enum C75ComponentBootState {
    Vacant(C75VacantComponentInstall),
    Existing(C75PendingComponentReadback),
}

/// The sole state from which an initial Component bundle can be appended.
/// There is no command, admission receipt, root ID, or generic journal handle.
#[must_use = "a vacant C7.5 head must be initialized or discarded"]
pub struct C75VacantComponentInstall {
    head: C75VacantHead,
}

/// An append acknowledgement or exact-existing discovery which still cannot
/// be validated or published until independent physical readback succeeds.
///
/// ```compile_fail
/// use vibeos_component_loader::C75PendingComponentReadback;
/// fn pending_has_no_bytes_or_publication(pending: C75PendingComponentReadback) {
///     let _ = pending.artifact_bytes();
///     let _ = pending.seal_inert_publication();
/// }
/// ```
#[must_use = "a C7.5 durable successor must be physically read back"]
pub struct C75PendingComponentReadback {
    pending: C75PendingPhysicalReadback,
}

/// Durable trust mode selected by the exact physical layout. In particular,
/// operator evidence cannot be discarded in order to enter development trust.
#[must_use = "physical Component bytes must pass the matching boot validator"]
pub enum C75RecoveredComponentInstall {
    Development(C75RecoveredDevelopmentComponentInstall),
    Operator(C75RecoveredOperatorComponentInstall),
}

/// Untrusted development artifact bytes obtained only after exact physical
/// root recovery. This type has no byte, ID, capability, or command accessor.
#[must_use = "recovered development bytes must be freshly validated"]
pub struct C75RecoveredDevelopmentComponentInstall {
    payload: C75RecoveredDevelopmentPayload,
    roots: ComponentInstallRootPresence,
}

/// Untrusted operator artifact/evidence bytes obtained only after exact
/// physical root recovery. Evidence remains inert data and cannot be granted.
///
/// ```compile_fail
/// use vibeos_component_loader::C75RecoveredOperatorComponentInstall;
/// fn unvalidated_bytes_cannot_publish(recovered: C75RecoveredOperatorComponentInstall) {
///     let _ = recovered.seal_inert_publication();
///     let _ = recovered.object_id();
/// }
/// ```
#[must_use = "recovered operator bytes must be freshly authenticated and validated"]
pub struct C75RecoveredOperatorComponentInstall {
    payload: C75RecoveredOperatorPayload,
    roots: ComponentInstallRootPresence,
}

/// Move-only boot-local proof that physical development bytes passed every
/// current validation gate. Only this state can seal an inert publication.
#[must_use = "a fresh development admission must be sealed or discarded"]
pub struct C75FreshDevelopmentAdmission {
    admitted: AdmittedComponent,
    roots: ComponentInstallRootPresence,
}

/// Move-only boot-local proof that physical operator bytes passed current
/// signature policy and every current semantic/engine gate.
///
/// ```compile_fail
/// use vibeos_component_loader::C75FreshOperatorAdmission;
/// fn requires_clone<T: Clone>() {}
/// fn fresh_proof_is_linear() { requires_clone::<C75FreshOperatorAdmission>(); }
/// ```
#[must_use = "a fresh operator admission must be sealed or discarded"]
pub struct C75FreshOperatorAdmission {
    admitted: AdmittedComponent,
    roots: ComponentInstallRootPresence,
}

/// Snapshot-derived presence of the three fixed global root partitions used
/// by C7.4. Only booleans escape; no SpaceId, root ID, or snapshot does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentInstallRootPresence {
    persistent: bool,
    program: bool,
    component: bool,
}

impl ComponentInstallRootPresence {
    pub const fn persistent(self) -> bool {
        self.persistent
    }

    pub const fn program(self) -> bool {
        self.program
    }

    pub const fn component(self) -> bool {
        self.component
    }
}

/// One boot-local command sealed for the C7.5 supervisor ledger.
///
/// This wrapper is intentionally move-only and has no public accessor. In
/// particular it is not a VSH runner and cannot be installed into a CSpace.
/// Only the kernel supervisor needs to retain the value; all validation and
/// command construction happened before this type was minted.
///
/// ```compile_fail
/// use vibeos_component_loader::C75SealedVolatileComponentPublication;
/// use vibeos_vsh::ComponentCommandRunner;
/// fn require_runner<T: ComponentCommandRunner>() {}
/// fn cannot_run_or_publish() {
///     require_runner::<C75SealedVolatileComponentPublication>();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C75SealedVolatileComponentPublication;
/// use vibeos_core::cap::Resource;
/// fn require_resource<T: Resource>() {}
/// fn cannot_be_installed_as_a_cspace_resource() {
///     require_resource::<C75SealedVolatileComponentPublication>();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C75SealedVolatileComponentPublication;
/// fn no_generic_install_surface() {
///     let _ = C75SealedVolatileComponentPublication::install;
/// }
/// ```
#[must_use = "a sealed C7.5 publication must be moved into the supervisor ledger or discarded"]
pub struct C75SealedVolatileComponentPublication {
    _command: VolatileComponentCommand,
}

impl C75SealedVolatileComponentPublication {
    fn from_admitted(admitted: AdmittedComponent) -> Result<Self, ComponentInstallProtocolError> {
        let command =
            project_admitted_component(admitted).map_err(ComponentInstallProtocolError::Command)?;
        // These are structural properties of VolatileComponentCommand today,
        // but retain the explicit C7.5 minting gate so a later runtime change
        // cannot silently make an already-sealed publication executable.
        if command.runtime_ready()
            || command.guest_calls() != 0
            || vibeos_vsh::ComponentCommandRunner::preflight(&command, command.manifest())
                != Err(vibeos_vsh::ComponentTerminal::Unavailable)
        {
            return Err(ComponentInstallProtocolError::Command(
                ComponentLoadError::RevalidationMismatch,
            ));
        }
        Ok(Self { _command: command })
    }
}

/// Compatibility name for the older C7.4 supervisor storage slot. The alias
/// does not restore any pre-C7.5 constructor: only a fresh postflight proof can
/// create the underlying value.
pub type C74SealedVolatileComponentPublication = C75SealedVolatileComponentPublication;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentInstallProtocolError {
    Unformatted,
    ExternalPolicyMismatch,
    ExistingComponentHistory,
    IdExhausted,
    Encode,
    Append(StoreError),
    Recovery(StoreError),
    PostflightMismatch,
    Command(ComponentLoadError),
}

impl fmt::Display for ComponentInstallProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unformatted => "component install requires a formatted authority journal",
            Self::ExternalPolicyMismatch => {
                "component install external root policy commitment differs"
            }
            Self::ExistingComponentHistory => {
                "component initial install found non-identical durable Component history"
            }
            Self::IdExhausted => "component install stable ID reservation exhausted",
            Self::Encode => "component install record encoding failed",
            Self::Append(_) => "component install durable append failed",
            Self::Recovery(_) => "component install physical recovery failed",
            Self::PostflightMismatch => {
                "component install physical successor differs from its sealed candidate"
            }
            Self::Command(_) => {
                "component fresh validation or inert projection failed after durable postflight"
            }
        })
    }
}

impl C75VacantComponentInstall {
    /// Append the private four-ID development batch. Existing media can never
    /// reach this state and therefore cannot be compared to caller bytes.
    pub async fn install_development(
        self,
        candidate: DevelopmentComponentInstallCandidate,
    ) -> Result<C75PendingComponentReadback, ComponentInstallProtocolError> {
        let Self { head } = self;
        let DevelopmentComponentInstallCandidate { artifact_bytes } = candidate;
        let pending = head
            .install_development(&artifact_bytes)
            .await
            .map_err(map_c75_storage_v2_error)?;
        Ok(C75PendingComponentReadback { pending })
    }

    /// Append the sole private six-ID evidence/artifact/root batch. The
    /// preinstall admission value was already destroyed by candidate creation.
    pub async fn install_operator(
        self,
        candidate: OperatorComponentInstallCandidate,
    ) -> Result<C75PendingComponentReadback, ComponentInstallProtocolError> {
        let Self { head } = self;
        let OperatorComponentInstallCandidate {
            artifact_bytes,
            evidence_bytes,
        } = candidate;
        let pending = head
            .install_operator(&artifact_bytes, &evidence_bytes)
            .await
            .map_err(map_c75_storage_v2_error)?;
        Ok(C75PendingComponentReadback { pending })
    }
}

fn map_c75_storage_v2_error(error: C75StorageV2Error) -> ComponentInstallProtocolError {
    match error {
        C75StorageV2Error::Unformatted => ComponentInstallProtocolError::Unformatted,
        C75StorageV2Error::ExternalPolicyMismatch => {
            ComponentInstallProtocolError::ExternalPolicyMismatch
        }
        C75StorageV2Error::ExistingComponentHistory => {
            ComponentInstallProtocolError::ExistingComponentHistory
        }
        C75StorageV2Error::IdExhausted => ComponentInstallProtocolError::IdExhausted,
        C75StorageV2Error::Encode => ComponentInstallProtocolError::Encode,
        C75StorageV2Error::Append(error) => ComponentInstallProtocolError::Append(error),
        C75StorageV2Error::PostflightMismatch => ComponentInstallProtocolError::PostflightMismatch,
    }
}

impl C75PendingComponentReadback {
    /// Perform independent physical readback and consume this linear pending
    /// value. A storage/postflight error also revokes the backend boot proof,
    /// so only cold recovery may retry that failed path.
    pub async fn recover_payload(
        self,
    ) -> Result<C75RecoveredComponentInstall, ComponentInstallProtocolError> {
        let payload = self
            .pending
            .recover_payload()
            .await
            .map_err(ComponentInstallProtocolError::Recovery)?;
        let roots = ComponentInstallRootPresence {
            persistent: payload.persistent_root_present(),
            program: payload.program_root_present(),
            component: payload.component_root_present(),
        };
        // Persistent/program partitions are optional and their exact
        // presence/absence was already bound by the private complete union.
        // The Component root itself is the sole mandatory publication root.
        if !roots.component {
            return Err(ComponentInstallProtocolError::PostflightMismatch);
        }
        Ok(match payload {
            C75RecoveredPublicationPayload::Development(payload) => {
                C75RecoveredComponentInstall::Development(C75RecoveredDevelopmentComponentInstall {
                    payload,
                    roots,
                })
            }
            C75RecoveredPublicationPayload::Operator(payload) => {
                C75RecoveredComponentInstall::Operator(C75RecoveredOperatorComponentInstall {
                    payload,
                    roots,
                })
            }
        })
    }
}

impl C75RecoveredDevelopmentComponentInstall {
    /// Consume the real physical artifact bytes and repeat canonical decoding,
    /// Component/Core inspection, WIT/manifest/adapter/limit checks, current
    /// engine validation, and image-pin admission. No command or resource is
    /// allocated before this returns successfully.
    pub fn revalidate_on_boot(
        self,
        policy: &DevelopmentComponentLoadPolicy<'_>,
    ) -> Result<C75FreshDevelopmentAdmission, ComponentInstallProtocolError> {
        let admitted = admit_development_component_bytes(self.payload.artifact_bytes(), policy)
            .map_err(ComponentInstallProtocolError::Command)?;
        Ok(C75FreshDevelopmentAdmission {
            admitted,
            roots: self.roots,
        })
    }
}

impl C75RecoveredOperatorComponentInstall {
    /// Consume the real physical artifact and retained-only evidence. The
    /// supplied policy is re-read before and after validation, binding the
    /// fresh proof to one current immutable generation and commitment.
    pub fn revalidate_on_boot(
        self,
        policy: &DeployableComponentLoadPolicy<'_>,
    ) -> Result<C75FreshOperatorAdmission, ComponentInstallProtocolError> {
        let generation = policy.operator_policy().generation();
        let commitment = policy
            .operator_policy()
            .commitment()
            .map_err(ComponentLoadError::Authentication)
            .map_err(ComponentInstallProtocolError::Command)?;
        let admitted = authenticate_and_admit_component_bytes(
            self.payload.artifact_bytes(),
            self.payload.evidence_bytes(),
            policy,
        )
        .map_err(ComponentInstallProtocolError::Command)?;
        let current_commitment = policy
            .operator_policy()
            .commitment()
            .map_err(ComponentLoadError::Authentication)
            .map_err(ComponentInstallProtocolError::Command)?;
        if policy.operator_policy().generation() != generation || current_commitment != commitment {
            return Err(ComponentInstallProtocolError::Command(
                ComponentLoadError::RevalidationMismatch,
            ));
        }
        Ok(C75FreshOperatorAdmission {
            admitted,
            roots: self.roots,
        })
    }
}

impl C75FreshDevelopmentAdmission {
    pub const fn root_presence(&self) -> ComponentInstallRootPresence {
        self.roots
    }

    pub fn seal_inert_publication(
        self,
    ) -> Result<C75SealedVolatileComponentPublication, ComponentInstallProtocolError> {
        C75SealedVolatileComponentPublication::from_admitted(self.admitted)
    }
}

impl C75FreshOperatorAdmission {
    pub const fn root_presence(&self) -> ComponentInstallRootPresence {
        self.roots
    }

    pub fn seal_inert_publication(
        self,
    ) -> Result<C75SealedVolatileComponentPublication, ComponentInstallProtocolError> {
        C75SealedVolatileComponentPublication::from_admitted(self.admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn frozen_policy_commitment_matches_canonical_policy_bytes() {
        let digest: [u8; 32] = Sha256::digest(C74_STORAGE_V2_EXTERNAL_POLICY).into();
        assert_eq!(digest, C74_STORAGE_V2_EXTERNAL_POLICY_SHA256);
        assert_eq!(digest, c74_storage_v2_policy_commitment_sha256());
    }

    #[test]
    fn redacted_root_presence_exposes_only_three_booleans() {
        let presence = ComponentInstallRootPresence {
            persistent: true,
            program: false,
            component: true,
        };
        assert!(presence.persistent());
        assert!(!presence.program());
        assert!(presence.component());
    }

    #[test]
    fn object_store_install_errors_remain_redacted() {
        assert_eq!(
            map_c75_storage_v2_error(C75StorageV2Error::ExternalPolicyMismatch),
            ComponentInstallProtocolError::ExternalPolicyMismatch
        );
        assert_eq!(
            map_c75_storage_v2_error(C75StorageV2Error::ExistingComponentHistory),
            ComponentInstallProtocolError::ExistingComponentHistory
        );
        assert_eq!(
            map_c75_storage_v2_error(C75StorageV2Error::Append(StoreError::Corrupt)),
            ComponentInstallProtocolError::Append(StoreError::Corrupt)
        );
    }
}
