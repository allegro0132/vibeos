//! Canonical C7.4 initial Component installation.
//!
//! The production surface never exposes stable IDs, record bytes, a journal
//! checkpoint, or a recovered snapshot. An installer consumes one
//! boot-selected Storage V2 journal handle, appends one private canonical
//! batch (or recognizes its exact already-committed successor), and can
//! release only an opaque root observation after an independent physical bound
//! recovery under the private fixed complete C7.4 root-policy union. The
//! observation can mint only an accessor-free, non-runner publication value.

use alloc::vec::Vec;
use core::fmt;

use vibeos_component_admission::AdmittedComponent;
use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactSignerPolicyKind,
    ComponentArtifactV1, COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN,
};
use vibeos_object_store::{
    C74CommittedStorageV2Install, C74StorageV2InstallError, StorageV2RecoveredAuthorityHead,
    StoreError,
};

use crate::{
    admit_development_component_bytes, authenticate_and_admit_component_bytes,
    project_admitted_component, ComponentLoadError, DeployableComponentLoadPolicy,
    DevelopmentComponentLoadPolicy, VolatileComponentCommand,
};

/// Move-only proof that development bytes passed the complete independent
/// image-pin and semantic admission gate without constructing a command.
#[must_use = "an admitted development install candidate must be installed or discarded"]
pub struct DevelopmentComponentInstallCandidate {
    artifact_bytes: Vec<u8>,
    admitted: AdmittedComponent,
}

/// Move-only proof that operator bytes and exact detached evidence passed the
/// complete authenticated semantic admission gate without constructing a
/// command.
#[must_use = "an admitted operator install candidate must be installed or discarded"]
pub struct OperatorComponentInstallCandidate {
    artifact_bytes: Vec<u8>,
    evidence_bytes: [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN],
    admitted: AdmittedComponent,
}

/// Perform the development gate and retain only its sealed, non-command result.
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
    let admitted = admit_development_component_bytes(bytes, policy)?;
    Ok(DevelopmentComponentInstallCandidate {
        artifact_bytes: canonical,
        admitted,
    })
}

/// Perform the deployable gate and retain the canonical 112-byte evidence
/// beside its sealed, non-command admission result. Failure cannot fall back to
/// development trust.
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
    let admitted = authenticate_and_admit_component_bytes(bytes, &evidence_bytes, policy)?;
    Ok(OperatorComponentInstallCandidate {
        artifact_bytes: canonical,
        evidence_bytes,
        admitted,
    })
}

/// Linear initial-install session. It contains one indivisible object-store
/// recovered head and exposes neither its journal nor its snapshot.
#[must_use = "a Component install session must be consumed"]
pub struct ComponentInstallSession {
    head: StorageV2RecoveredAuthorityHead,
}

/// Consume the sealed head returned by
/// `AuthorityJournal::recover_storage_v2_only` only after comparing its
/// external-policy commitment to the fixed C7.4 policy. No snapshot or
/// checkpoint crosses this API.
///
/// ```compile_fail
/// use vibeos_component_loader::begin_component_install;
/// use vibeos_object_store::AuthoritySnapshot;
/// fn cannot_begin_from_snapshot(snapshot: AuthoritySnapshot) {
///     let _ = begin_component_install(snapshot);
/// }
/// ```
pub fn begin_component_install(
    head: StorageV2RecoveredAuthorityHead,
) -> Result<ComponentInstallSession, ComponentInstallProtocolError> {
    validate_storage_v2_policy_commitment(head.external_root_policy_sha256())?;
    Ok(ComponentInstallSession { head })
}

fn validate_storage_v2_policy_commitment(
    actual: [u8; 32],
) -> Result<(), ComponentInstallProtocolError> {
    if actual != c74_storage_v2_policy_commitment_sha256() {
        return Err(ComponentInstallProtocolError::ExternalPolicyMismatch);
    }
    Ok(())
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

/// Opaque acknowledged development successor. No root authority or command
/// exists until consuming physical bound recovery succeeds.
#[must_use = "a committed development install must be physically recovered"]
pub struct CommittedDevelopmentComponentInstall {
    storage: C74CommittedStorageV2Install,
    admitted: AdmittedComponent,
}

/// Opaque acknowledged operator successor. Evidence remains inert and the
/// pre-append admission receipt remains sealed until physical postflight.
///
/// ```compile_fail
/// use vibeos_component_loader::CommittedOperatorComponentInstall;
/// fn no_raw_plan(committed: &CommittedOperatorComponentInstall) {
///     let _ = committed.records();
///     let _ = committed.expected_checkpoint();
///     let _ = committed.snapshot();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::CommittedOperatorComponentInstall;
/// fn no_command_before_physical_postflight(committed: CommittedOperatorComponentInstall) {
///     let _ = committed.command();
/// }
/// ```
#[must_use = "a committed operator install must be physically recovered"]
pub struct CommittedOperatorComponentInstall {
    storage: C74CommittedStorageV2Install,
    admitted: AdmittedComponent,
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

/// Opaque proof that the exact development root was observed by physical
/// postflight.
///
/// The root capability witness has already been consumed and is not retained
/// here. This type exposes neither the root nor a command; its sole consuming
/// transition produces an opaque C7.4 publication value which implements no
/// runner or CSpace-install interface.
///
/// ```compile_fail
/// use vibeos_component_loader::RecoveredDevelopmentComponentInstall;
/// fn cannot_extract_root_or_command(observed: RecoveredDevelopmentComponentInstall) {
///     let _ = observed.into_parts();
/// }
/// ```
#[must_use = "a recovered development root observation must be sealed or discarded"]
pub struct RecoveredDevelopmentComponentInstall {
    admitted: AdmittedComponent,
}

impl RecoveredDevelopmentComponentInstall {
    /// Consume the root observation and construct one opaque inert publication.
    /// The returned value deliberately implements neither
    /// [`vibeos_vsh::ComponentCommandRunner`] nor a command getter.
    pub fn seal_inert_publication(
        self,
    ) -> Result<C74SealedVolatileComponentPublication, ComponentInstallProtocolError> {
        C74SealedVolatileComponentPublication::from_admitted(self.admitted)
    }
}

/// Opaque proof that the exact operator root and its inert evidence attachment
/// were observed by physical postflight. Neither root/evidence authority nor a
/// command can be extracted from this value.
///
/// ```compile_fail
/// use vibeos_component_loader::RecoveredOperatorComponentInstall;
/// fn cannot_install_or_extract(observed: RecoveredOperatorComponentInstall) {
///     let (bundle, command) = observed.into_parts();
///     let _ = (bundle, command);
/// }
/// ```
#[must_use = "a recovered operator root observation must be sealed or discarded"]
pub struct RecoveredOperatorComponentInstall {
    admitted: AdmittedComponent,
}

impl RecoveredOperatorComponentInstall {
    /// Consume the root observation and construct one opaque inert publication.
    pub fn seal_inert_publication(
        self,
    ) -> Result<C74SealedVolatileComponentPublication, ComponentInstallProtocolError> {
        C74SealedVolatileComponentPublication::from_admitted(self.admitted)
    }
}

/// One boot-local command sealed for the C7.4 supervisor ledger.
///
/// This wrapper is intentionally move-only and has no public accessor. In
/// particular it is not a VSH runner and cannot be installed into a CSpace.
/// Only the kernel supervisor needs to retain the value; all validation and
/// command construction happened before this type was minted.
///
/// ```compile_fail
/// use vibeos_component_loader::C74SealedVolatileComponentPublication;
/// use vibeos_vsh::ComponentCommandRunner;
/// fn require_runner<T: ComponentCommandRunner>() {}
/// fn cannot_run_or_publish() {
///     require_runner::<C74SealedVolatileComponentPublication>();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C74SealedVolatileComponentPublication;
/// use vibeos_core::cap::Resource;
/// fn require_resource<T: Resource>() {}
/// fn cannot_be_installed_as_a_cspace_resource() {
///     require_resource::<C74SealedVolatileComponentPublication>();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::C74SealedVolatileComponentPublication;
/// fn no_generic_install_surface() {
///     let _ = C74SealedVolatileComponentPublication::install;
/// }
/// ```
#[must_use = "a sealed C7.4 publication must be moved into the supervisor ledger or discarded"]
pub struct C74SealedVolatileComponentPublication {
    _command: VolatileComponentCommand,
}

impl C74SealedVolatileComponentPublication {
    fn from_admitted(admitted: AdmittedComponent) -> Result<Self, ComponentInstallProtocolError> {
        let command =
            project_admitted_component(admitted).map_err(ComponentInstallProtocolError::Command)?;
        // These are structural properties of VolatileComponentCommand today,
        // but retain the explicit C7.4 minting gate so a later runtime change
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
            Self::Command(_) => "component command construction failed after durable postflight",
        })
    }
}

impl ComponentInstallSession {
    /// Append the private four-ID development batch, or recognize the exact
    /// same already-committed successor without appending any record.
    pub async fn install_development(
        self,
        candidate: DevelopmentComponentInstallCandidate,
    ) -> Result<CommittedDevelopmentComponentInstall, ComponentInstallProtocolError> {
        let Self { head } = self;
        let DevelopmentComponentInstallCandidate {
            artifact_bytes,
            admitted,
        } = candidate;
        let storage = head
            .install_c74_development(&artifact_bytes)
            .await
            .map_err(map_storage_v2_install_error)?;
        Ok(CommittedDevelopmentComponentInstall { storage, admitted })
    }

    /// Append the sole private six-ID evidence/artifact/root batch, or
    /// recognize its exact already-committed successor without appending.
    pub async fn install_operator(
        self,
        candidate: OperatorComponentInstallCandidate,
    ) -> Result<CommittedOperatorComponentInstall, ComponentInstallProtocolError> {
        let Self { head } = self;
        let OperatorComponentInstallCandidate {
            artifact_bytes,
            evidence_bytes,
            admitted,
        } = candidate;
        let storage = head
            .install_c74_operator(&artifact_bytes, &evidence_bytes)
            .await
            .map_err(map_storage_v2_install_error)?;
        Ok(CommittedOperatorComponentInstall { storage, admitted })
    }
}

fn map_storage_v2_install_error(error: C74StorageV2InstallError) -> ComponentInstallProtocolError {
    match error {
        C74StorageV2InstallError::Unformatted => ComponentInstallProtocolError::Unformatted,
        C74StorageV2InstallError::ExternalPolicyMismatch => {
            ComponentInstallProtocolError::ExternalPolicyMismatch
        }
        C74StorageV2InstallError::ExistingComponentHistory => {
            ComponentInstallProtocolError::ExistingComponentHistory
        }
        C74StorageV2InstallError::IdExhausted => ComponentInstallProtocolError::IdExhausted,
        C74StorageV2InstallError::Encode => ComponentInstallProtocolError::Encode,
        C74StorageV2InstallError::Append(error) => ComponentInstallProtocolError::Append(error),
        C74StorageV2InstallError::PostflightMismatch => {
            ComponentInstallProtocolError::PostflightMismatch
        }
    }
}

impl CommittedDevelopmentComponentInstall {
    pub fn root_presence(&self) -> ComponentInstallRootPresence {
        ComponentInstallRootPresence {
            persistent: self.storage.persistent_root_present(),
            program: self.storage.program_root_present(),
            component: self.storage.component_root_present(),
        }
    }

    /// Physical readback under the private fixed complete C7.4 root-policy
    /// union must succeed before an opaque root observation is released. Root
    /// authority and commands do not escape this transition.
    pub async fn recover_bound(
        self,
    ) -> Result<RecoveredDevelopmentComponentInstall, ComponentInstallProtocolError> {
        let Self { storage, admitted } = self;
        storage
            .recover_bound()
            .await
            .map_err(ComponentInstallProtocolError::Recovery)?;
        Ok(RecoveredDevelopmentComponentInstall { admitted })
    }
}

impl CommittedOperatorComponentInstall {
    pub fn root_presence(&self) -> ComponentInstallRootPresence {
        ComponentInstallRootPresence {
            persistent: self.storage.persistent_root_present(),
            program: self.storage.program_root_present(),
            component: self.storage.component_root_present(),
        }
    }

    /// Physical readback under the private fixed complete C7.4 root-policy
    /// union must succeed before an opaque root observation is released.
    /// Root/evidence authority and commands do not escape this transition.
    ///
    /// ```compile_fail
    /// use vibeos_component_loader::CommittedOperatorComponentInstall;
    /// use vibeos_durable_format::RootPolicyPartition;
    /// fn cannot_supply_raw_policy(
    ///     committed: CommittedOperatorComponentInstall,
    ///     partitions: &[RootPolicyPartition<'_>],
    /// ) {
    ///     let _ = committed.recover_bound(partitions);
    /// }
    /// ```
    pub async fn recover_bound(
        self,
    ) -> Result<RecoveredOperatorComponentInstall, ComponentInstallProtocolError> {
        let Self { storage, admitted } = self;
        storage
            .recover_bound()
            .await
            .map_err(ComponentInstallProtocolError::Recovery)?;
        Ok(RecoveredOperatorComponentInstall { admitted })
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
            map_storage_v2_install_error(C74StorageV2InstallError::ExternalPolicyMismatch),
            ComponentInstallProtocolError::ExternalPolicyMismatch
        );
        assert_eq!(
            map_storage_v2_install_error(C74StorageV2InstallError::ExistingComponentHistory),
            ComponentInstallProtocolError::ExistingComponentHistory
        );
        assert_eq!(
            map_storage_v2_install_error(C74StorageV2InstallError::Append(StoreError::Corrupt)),
            ComponentInstallProtocolError::Append(StoreError::Corrupt)
        );
    }
}
