//! Sealed C7.4 supervisor ledger for one postflight Component command.
//!
//! The ledger is deliberately not a command registry. It accepts only a
//! loader-owned recovered install outcome, consumes the root authority, and
//! moves the resulting boot-local command into one private slot. There is no
//! command getter, name lookup, `Cap`, `INVOKE`, `GRANT`, VSH publication, or
//! guest call on this path.

use vibeos_component_loader::{
    C74SealedVolatileComponentPublication, CommittedDevelopmentComponentInstall,
    CommittedOperatorComponentInstall, ComponentInstallProtocolError,
};

use crate::sync::SpinLock;

/// The only three representable supervisor states for C7.4 publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum C74PublicationLedgerState {
    /// No exact physical Component postflight has been consumed this boot.
    NoRootNoCommand = 0,
    /// Exact root postflight succeeded, but its command failed the inert
    /// predicate. This state is intentionally retryable only through another
    /// exact recovered install outcome.
    ExactRootNoCommand = 1,
    /// The sole private slot owns one unavailable boot-local command.
    ExactRootOneInertCommand = 2,
}

enum SealedComponentPublicationLedger<T> {
    NoRootNoCommand,
    ExactRootNoCommand,
    ExactRootOneInertCommand(T),
}

impl<T> SealedComponentPublicationLedger<T> {
    const fn new() -> Self {
        Self::NoRootNoCommand
    }

    const fn state(&self) -> C74PublicationLedgerState {
        match self {
            Self::NoRootNoCommand => C74PublicationLedgerState::NoRootNoCommand,
            Self::ExactRootNoCommand => C74PublicationLedgerState::ExactRootNoCommand,
            Self::ExactRootOneInertCommand(_) => {
                C74PublicationLedgerState::ExactRootOneInertCommand
            }
        }
    }

    const fn len(&self) -> usize {
        match self {
            Self::ExactRootOneInertCommand(_) => 1,
            Self::NoRootNoCommand | Self::ExactRootNoCommand => 0,
        }
    }

    /// Publish the physical root observation before any command projection is
    /// attempted. Re-observing the exact root is harmless while the command
    /// slot is still empty; a populated singleton cannot be replaced.
    fn observe_exact_root(&mut self) -> Result<(), C74PublicationError> {
        match self {
            Self::NoRootNoCommand => {
                *self = Self::ExactRootNoCommand;
                Ok(())
            }
            Self::ExactRootNoCommand => Ok(()),
            Self::ExactRootOneInertCommand(_) => Err(C74PublicationError::AlreadyPublished),
        }
    }

    /// Move one loader-sealed publication into the sole slot. The opaque input
    /// has no runner or getter, so this transition cannot publish into VSH or a
    /// CSpace as a side effect.
    fn publish(&mut self, publication: T) -> Result<(), C74PublicationError> {
        match self {
            Self::NoRootNoCommand => Err(C74PublicationError::RootNotObserved),
            Self::ExactRootNoCommand => {
                *self = Self::ExactRootOneInertCommand(publication);
                Ok(())
            }
            Self::ExactRootOneInertCommand(_) => Err(C74PublicationError::AlreadyPublished),
        }
    }
}

static C74_COMPONENT_PUBLICATION: SpinLock<
    SealedComponentPublicationLedger<C74SealedVolatileComponentPublication>,
> = SpinLock::new(SealedComponentPublicationLedger::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C74PublicationError {
    RootNotObserved,
    AlreadyPublished,
}

#[derive(Debug)]
pub(crate) enum C74RecoverAndPublishError {
    Install(ComponentInstallProtocolError),
    Publication(C74PublicationError),
}

/// Redacted state only. No command, manifest, name, capability, or durable
/// identity can be recovered from this observation.
pub(crate) fn c74_publication_ledger_state() -> C74PublicationLedgerState {
    C74_COMPONENT_PUBLICATION.lock().state()
}

/// Whether the sealed command slot is empty. Both pre-postflight and
/// root-only fail-closed states contain zero commands.
pub(crate) fn c74_publication_ledger_is_empty() -> bool {
    c74_publication_ledger_len() == 0
}

/// The ledger is a singleton by construction, so this can return only 0 or 1.
pub(crate) fn c74_publication_ledger_len() -> usize {
    C74_COMPONENT_PUBLICATION.lock().len()
}

/// Fixed redacted marker for target acceptance after `len() == 1`.
pub(crate) const C74_INERT_SINGLETON_MARKER: &str =
    "c74 root=exact command=volatile-singleton runtime_ready=false guest_calls=0";

fn observe_exact_postflight_root() -> Result<(), C74PublicationError> {
    C74_COMPONENT_PUBLICATION.lock().observe_exact_root()
}

fn publish_sealed_postflight_command(
    publication: C74SealedVolatileComponentPublication,
) -> Result<(), C74PublicationError> {
    C74_COMPONENT_PUBLICATION.lock().publish(publication)
}

/// Consume the loader's acknowledged development successor, perform physical
/// recovery against the complete successor root union, then seal its command.
pub(crate) async fn recover_and_publish_development(
    committed: CommittedDevelopmentComponentInstall,
) -> Result<(), C74RecoverAndPublishError> {
    let recovered = committed
        .recover_bound()
        .await
        .map_err(C74RecoverAndPublishError::Install)?;
    // This transition must precede the fallible command projection. If
    // projection fails (including allocation failure), the ledger truthfully
    // remains ExactRootNoCommand.
    observe_exact_postflight_root().map_err(C74RecoverAndPublishError::Publication)?;
    let publication = recovered
        .seal_inert_publication()
        .map_err(C74RecoverAndPublishError::Install)?;
    publish_sealed_postflight_command(publication)
        .map_err(C74RecoverAndPublishError::Publication)?;
    Ok(())
}

/// Operator analogue of [`recover_and_publish_development`]. Exact detached
/// evidence is consumed by the loader and never retained by the ledger.
pub(crate) async fn recover_and_publish_operator(
    committed: CommittedOperatorComponentInstall,
) -> Result<(), C74RecoverAndPublishError> {
    let recovered = committed
        .recover_bound()
        .await
        .map_err(C74RecoverAndPublishError::Install)?;
    observe_exact_postflight_root().map_err(C74RecoverAndPublishError::Publication)?;
    let publication = recovered
        .seal_inert_publication()
        .map_err(C74RecoverAndPublishError::Install)?;
    publish_sealed_postflight_command(publication)
        .map_err(C74RecoverAndPublishError::Publication)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_observation_precedes_projection_and_failed_projection_keeps_root_only_state() {
        let mut ledger = SealedComponentPublicationLedger::<()>::new();
        assert_eq!(ledger.state(), C74PublicationLedgerState::NoRootNoCommand);
        assert_eq!(ledger.len(), 0);
        assert_eq!(
            ledger.publish(()),
            Err(C74PublicationError::RootNotObserved)
        );

        ledger.observe_exact_root().unwrap();
        // Simulate any fallible projection returning without a sealed value.
        assert_eq!(
            ledger.state(),
            C74PublicationLedgerState::ExactRootNoCommand
        );
        assert_eq!(ledger.len(), 0);

        // An exact cold retry may observe the same root again, but publication
        // remains a singleton and can never replace the first command.
        ledger.observe_exact_root().unwrap();
        ledger.publish(()).unwrap();
        assert_eq!(
            ledger.state(),
            C74PublicationLedgerState::ExactRootOneInertCommand
        );
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.observe_exact_root(),
            Err(C74PublicationError::AlreadyPublished)
        );
        assert_eq!(
            ledger.publish(()),
            Err(C74PublicationError::AlreadyPublished)
        );
    }
}
