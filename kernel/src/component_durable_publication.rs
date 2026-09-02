//! Sealed C7.4 supervisor ledger for one postflight Component command.
//!
//! The ledger is deliberately not a command registry. It accepts only a
//! loader-owned recovered install outcome, consumes the root authority, and
//! moves the resulting boot-local command into one private slot. There is no
//! command getter, name lookup, `Cap`, `INVOKE`, `GRANT`, VSH publication, or
//! guest call on this path.

use vibeos_component_loader::{
    C74SealedVolatileComponentPublication, C75FreshDevelopmentAdmission, C75FreshOperatorAdmission,
    C75SealedVolatileComponentPublication, ComponentInstallProtocolError,
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

/// Compatibility-preserved C7.4 ledger transition fed by the stronger C7.5
/// proof. Physical readback and every fresh boot validation already succeeded;
/// observing the root before the still-fallible inert projection retains the
/// original crash-safe ledger ordering without accepting preappend admission.
pub(crate) fn recover_and_publish_development(
    fresh: C75FreshDevelopmentAdmission,
) -> Result<(), C74RecoverAndPublishError> {
    observe_exact_postflight_root().map_err(C74RecoverAndPublishError::Publication)?;
    let publication = fresh
        .seal_inert_publication()
        .map_err(C74RecoverAndPublishError::Install)?;
    publish_sealed_postflight_command(publication)
        .map_err(C74RecoverAndPublishError::Publication)?;
    Ok(())
}

/// Operator analogue of [`recover_and_publish_development`]. The input can be
/// minted only by authenticating physical retained-only evidence and artifact
/// bytes under the current boot policy and engine.
pub(crate) fn recover_and_publish_operator(
    fresh: C75FreshOperatorAdmission,
) -> Result<(), C74RecoverAndPublishError> {
    observe_exact_postflight_root().map_err(C74RecoverAndPublishError::Publication)?;
    let publication = fresh
        .seal_inert_publication()
        .map_err(C74RecoverAndPublishError::Install)?;
    publish_sealed_postflight_command(publication)
        .map_err(C74RecoverAndPublishError::Publication)?;
    Ok(())
}

/// C7.5 is intentionally a separate ledger from the compatibility-preserved
/// C7.4 path above. It has no root-only state: physical recovery, current-
/// policy/current-engine validation, and inert projection must all succeed
/// before the one mutation below is possible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum C75PublicationLedgerState {
    NoRootNoCommand = 0,
    ExactRootOneFreshValidatedInertCommand = 1,
}

enum FreshValidatedPublicationLedger<T> {
    NoRootNoCommand,
    ExactRootOneFreshValidatedInertCommand(T),
}

impl<T> FreshValidatedPublicationLedger<T> {
    const fn new() -> Self {
        Self::NoRootNoCommand
    }

    const fn state(&self) -> C75PublicationLedgerState {
        match self {
            Self::NoRootNoCommand => C75PublicationLedgerState::NoRootNoCommand,
            Self::ExactRootOneFreshValidatedInertCommand(_) => {
                C75PublicationLedgerState::ExactRootOneFreshValidatedInertCommand
            }
        }
    }

    const fn len(&self) -> usize {
        match self {
            Self::NoRootNoCommand => 0,
            Self::ExactRootOneFreshValidatedInertCommand(_) => 1,
        }
    }

    fn publish(&mut self, publication: T) -> Result<(), C75PublicationError> {
        match self {
            Self::NoRootNoCommand => {
                *self = Self::ExactRootOneFreshValidatedInertCommand(publication);
                Ok(())
            }
            Self::ExactRootOneFreshValidatedInertCommand(_) => {
                Err(C75PublicationError::AlreadyPublished)
            }
        }
    }
}

static C75_COMPONENT_PUBLICATION: SpinLock<
    FreshValidatedPublicationLedger<C75SealedVolatileComponentPublication>,
> = SpinLock::new(FreshValidatedPublicationLedger::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C75PublicationError {
    AlreadyPublished,
}

pub(crate) fn c75_publication_ledger_state() -> C75PublicationLedgerState {
    C75_COMPONENT_PUBLICATION.lock().state()
}

pub(crate) fn c75_publication_ledger_is_empty() -> bool {
    c75_publication_ledger_len() == 0
}

pub(crate) fn c75_publication_ledger_len() -> usize {
    C75_COMPONENT_PUBLICATION.lock().len()
}

/// Only the loader's move-only postflight fresh proof can enter this slot.
/// There is deliberately no transition for a root observation or unvalidated
/// durable payload.
pub(crate) fn publish_c75_fresh_validated(
    publication: C75SealedVolatileComponentPublication,
) -> Result<(), C75PublicationError> {
    C75_COMPONENT_PUBLICATION.lock().publish(publication)
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

    #[test]
    fn c75_has_no_intermediate_root_state_and_publishes_once() {
        let mut ledger = FreshValidatedPublicationLedger::<()>::new();
        assert_eq!(ledger.state(), C75PublicationLedgerState::NoRootNoCommand);
        assert_eq!(ledger.len(), 0);

        // Failed gates produce no sealed input, hence no mutation at all.
        assert_eq!(ledger.state(), C75PublicationLedgerState::NoRootNoCommand);
        assert_eq!(ledger.len(), 0);

        ledger.publish(()).unwrap();
        assert_eq!(
            ledger.state(),
            C75PublicationLedgerState::ExactRootOneFreshValidatedInertCommand
        );
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.publish(()),
            Err(C75PublicationError::AlreadyPublished)
        );
    }
}
