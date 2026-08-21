//! Allocation-free state machine for one SYSTEM-owned native transport slot.
//!
//! This file deliberately has no kernel dependencies. The production adapter
//! supplies opaque copy-only CONTROL/instance/CSpace/token identities, while
//! the same source can be compiled directly with `rustc --test` on the host.

pub(crate) const DRIVER_CHUNK_BYTES: usize = 1024;

/// Bytes already popped from the backend but not yet committed to the guest.
/// Input and output intentionally never alias the same fixed storage.
pub(crate) struct InputSpill {
    bytes: [u8; DRIVER_CHUNK_BYTES],
    cursor: u16,
    length: u16,
}

impl InputSpill {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; DRIVER_CHUNK_BYTES],
            cursor: 0,
            length: 0,
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.cursor == self.length
    }

    pub(crate) fn receive_target(&mut self, length: usize) -> Option<&mut [u8]> {
        if !self.is_empty() || length == 0 || length > DRIVER_CHUNK_BYTES {
            return None;
        }
        self.cursor = 0;
        self.length = length as u16;
        Some(&mut self.bytes[..length])
    }

    pub(crate) fn remaining_prefix(&self, maximum: usize) -> &[u8] {
        let start = usize::from(self.cursor);
        let available = usize::from(self.length) - start;
        &self.bytes[start..start + available.min(maximum)]
    }

    pub(crate) fn consume(&mut self, length: usize) -> bool {
        let remaining = usize::from(self.length) - usize::from(self.cursor);
        if length > remaining {
            return false;
        }
        self.cursor += length as u16;
        if self.cursor == self.length {
            self.cursor = 0;
            self.length = 0;
        }
        true
    }

    pub(crate) fn abort_receive(&mut self) {
        self.cursor = 0;
        self.length = 0;
    }
}

pub(crate) struct OutputStaging {
    bytes: [u8; DRIVER_CHUNK_BYTES],
    length: u16,
}

impl OutputStaging {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; DRIVER_CHUNK_BYTES],
            length: 0,
        }
    }

    pub(crate) fn prepare(&mut self, maximum: usize) -> &mut [u8] {
        let length = maximum.min(DRIVER_CHUNK_BYTES);
        self.length = length as u16;
        &mut self.bytes[..length]
    }

    pub(crate) fn prepared(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub(crate) fn clear(&mut self) {
        self.length = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingKind {
    ReadWaiting,
    ReadPrepared,
    WriteWaiting,
    TerminalWaiting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingIdentity<I, B> {
    pub(crate) control_generation: u64,
    pub(crate) instance: I,
    pub(crate) bindings: B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingSnapshot<I, B, O> {
    pub(crate) identity: PendingIdentity<I, B>,
    pub(crate) kind: PendingKind,
    pub(crate) operation: O,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingShadowError {
    Busy,
    Vacant,
    StaleGeneration,
    IdentityMismatch,
    OperationMismatch,
    TokenDidNotRotate,
    Quarantined,
}

/// One fixed slot with a monotonic CONTROL-generation watermark.
///
/// Clearing an operation retains the exact identity until `retire`, allowing
/// successive operations in one live CONTROL generation while preventing a
/// stale generation from being installed after slot reuse. Every structural
/// mismatch sticky-quarantines the slot; callers translate that transition
/// into the global lifecycle fail-stop before touching a CSpace again.
pub(crate) struct PendingShadow<I, B, O> {
    watermark: u64,
    identity: Option<PendingIdentity<I, B>>,
    operation: Option<(PendingKind, O)>,
    quarantined: bool,
}

impl<I: Copy + Eq, B: Copy + Eq, O: Copy + Eq> PendingShadow<I, B, O> {
    pub(crate) const fn new() -> Self {
        Self {
            watermark: 0,
            identity: None,
            operation: None,
            quarantined: false,
        }
    }

    /// Binds one exact live CONTROL generation before its child can poll.
    /// A retired generation can never be rebound, even when every other copy
    /// field is identical; a newer generation must carry a wholly exact new
    /// identity.
    pub(crate) fn bind(
        &mut self,
        identity: PendingIdentity<I, B>,
    ) -> Result<(), PendingShadowError> {
        self.check_live()?;
        if identity.control_generation == 0 || identity.control_generation <= self.watermark {
            return self.reject(PendingShadowError::StaleGeneration);
        }
        if self.identity.is_some() || self.operation.is_some() {
            return self.reject(PendingShadowError::Busy);
        }
        self.watermark = identity.control_generation;
        self.identity = Some(identity);
        Ok(())
    }

    pub(crate) fn install(
        &mut self,
        identity: PendingIdentity<I, B>,
        kind: PendingKind,
        operation: O,
    ) -> Result<PendingSnapshot<I, B, O>, PendingShadowError> {
        self.check_live()?;
        if identity.control_generation < self.watermark {
            return self.reject(PendingShadowError::StaleGeneration);
        }
        if self.operation.is_some() {
            return self.reject(PendingShadowError::Busy);
        }
        if self.identity != Some(identity) || identity.control_generation != self.watermark {
            return self.reject(PendingShadowError::IdentityMismatch);
        }
        self.operation = Some((kind, operation));
        Ok(PendingSnapshot {
            identity,
            kind,
            operation,
        })
    }

    pub(crate) fn replace(
        &mut self,
        previous: PendingSnapshot<I, B, O>,
        kind: PendingKind,
        operation: O,
    ) -> Result<PendingSnapshot<I, B, O>, PendingShadowError> {
        self.check_live()?;
        self.require_exact(previous)?;
        if operation == previous.operation {
            return self.reject(PendingShadowError::TokenDidNotRotate);
        }
        self.operation = Some((kind, operation));
        Ok(PendingSnapshot {
            identity: previous.identity,
            kind,
            operation,
        })
    }

    pub(crate) fn snapshot(
        &mut self,
        identity: PendingIdentity<I, B>,
    ) -> Result<Option<PendingSnapshot<I, B, O>>, PendingShadowError> {
        self.check_live()?;
        if identity.control_generation < self.watermark {
            return self.reject(PendingShadowError::StaleGeneration);
        }
        if self.identity != Some(identity) {
            return self.reject(PendingShadowError::IdentityMismatch);
        }
        Ok(self.operation.map(|(kind, operation)| PendingSnapshot {
            identity,
            kind,
            operation,
        }))
    }

    /// Acceptance-only observation which may wait before the first operation
    /// is installed. Once an identity exists, every mismatch retains the same
    /// sticky-quarantine behavior as an exact production snapshot.
    pub(crate) fn observe_kind_if_installed(
        &mut self,
        identity: PendingIdentity<I, B>,
    ) -> Result<Option<PendingKind>, PendingShadowError> {
        self.check_live()?;
        if identity.control_generation < self.watermark {
            return self.reject(PendingShadowError::StaleGeneration);
        }
        match self.identity {
            None => Ok(None),
            Some(current) if current == identity => {
                Ok(self.operation.map(|(kind, _operation)| kind))
            }
            Some(_) => self.reject(PendingShadowError::IdentityMismatch),
        }
    }

    pub(crate) fn clear(
        &mut self,
        expected: PendingSnapshot<I, B, O>,
    ) -> Result<(), PendingShadowError> {
        self.check_live()?;
        self.require_exact(expected)?;
        self.operation = None;
        Ok(())
    }

    pub(crate) fn retire(
        &mut self,
        identity: PendingIdentity<I, B>,
    ) -> Result<(), PendingShadowError> {
        self.check_live()?;
        if self.identity != Some(identity) {
            return self.reject(PendingShadowError::IdentityMismatch);
        }
        if self.operation.is_some() {
            return self.reject(PendingShadowError::Busy);
        }
        self.identity = None;
        Ok(())
    }

    pub(crate) fn quarantine(&mut self) {
        self.quarantined = true;
    }

    pub(crate) const fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    /// A retired slot retains only its monotonic generation watermark. No
    /// exact invocation identity or backend operation remains reachable.
    pub(crate) const fn is_retired(&self) -> bool {
        !self.quarantined && self.identity.is_none() && self.operation.is_none()
    }

    fn check_live(&self) -> Result<(), PendingShadowError> {
        if self.quarantined {
            Err(PendingShadowError::Quarantined)
        } else {
            Ok(())
        }
    }

    fn require_exact(
        &mut self,
        expected: PendingSnapshot<I, B, O>,
    ) -> Result<(), PendingShadowError> {
        if self.identity != Some(expected.identity) {
            return self.reject(PendingShadowError::IdentityMismatch);
        }
        match self.operation {
            Some((kind, operation)) if kind == expected.kind && operation == expected.operation => {
                Ok(())
            }
            None => self.reject(PendingShadowError::Vacant),
            Some(_) => self.reject(PendingShadowError::OperationMismatch),
        }
    }

    fn reject<T>(&mut self, error: PendingShadowError) -> Result<T, PendingShadowError> {
        self.quarantined = true;
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(generation: u64, instance: u64, bindings: u64) -> PendingIdentity<u64, u64> {
        PendingIdentity {
            control_generation: generation,
            instance,
            bindings,
        }
    }

    #[test]
    fn all_pending_kinds_install_clear_and_rotate_in_one_generation() {
        let mut shadow = PendingShadow::new();
        let exact = identity(7, 11, 13);
        let kinds = [
            PendingKind::ReadWaiting,
            PendingKind::ReadPrepared,
            PendingKind::WriteWaiting,
            PendingKind::TerminalWaiting,
        ];
        shadow.bind(exact).unwrap();
        for (index, kind) in kinds.into_iter().enumerate() {
            let token = 100 + index as u64;
            let installed = shadow.install(exact, kind, token).unwrap();
            assert_eq!(shadow.snapshot(exact).unwrap(), Some(installed));
            let rotated = shadow.replace(installed, kind, token + 10).unwrap();
            assert_eq!(shadow.snapshot(exact).unwrap(), Some(rotated));
            shadow.clear(rotated).unwrap();
            assert_eq!(shadow.snapshot(exact).unwrap(), None);
        }
        shadow.retire(exact).unwrap();
        assert!(!shadow.is_quarantined());
        assert!(shadow.is_retired());
    }

    #[test]
    fn stale_generation_cannot_cross_retirement_aba() {
        let mut shadow = PendingShadow::new();
        let old = identity(3, 10, 20);
        shadow.bind(old).unwrap();
        let operation = shadow.install(old, PendingKind::ReadWaiting, 30).unwrap();
        shadow.clear(operation).unwrap();
        shadow.retire(old).unwrap();
        let new = identity(4, 11, 21);
        shadow.bind(new).unwrap();
        let _current = shadow.install(new, PendingKind::WriteWaiting, 31).unwrap();

        assert_eq!(
            shadow.snapshot(old),
            Err(PendingShadowError::StaleGeneration)
        );
        assert!(shadow.is_quarantined());
    }

    #[test]
    fn cap_incarnation_or_token_mismatch_is_sticky_quarantine() {
        for mismatch in 0..3 {
            let mut shadow = PendingShadow::new();
            let exact = identity(9, 41, 51);
            shadow.bind(exact).unwrap();
            let installed = shadow
                .install(exact, PendingKind::ReadPrepared, 61)
                .unwrap();
            let result = match mismatch {
                0 => shadow.snapshot(identity(9, 41, 52)).map(|_| ()),
                1 => shadow.clear(PendingSnapshot {
                    operation: 62,
                    ..installed
                }),
                _ => shadow
                    .replace(installed, PendingKind::ReadWaiting, 61)
                    .map(|_| ()),
            };
            assert!(result.is_err());
            assert!(shadow.is_quarantined());
            assert_eq!(shadow.snapshot(exact), Err(PendingShadowError::Quarantined));
        }
    }

    #[test]
    fn reset_preflight_rejects_a_live_operation() {
        let mut shadow = PendingShadow::new();
        let exact = identity(12, 71, 81);
        shadow.bind(exact).unwrap();
        let _installed = shadow
            .install(exact, PendingKind::TerminalWaiting, 91)
            .unwrap();
        assert_eq!(shadow.retire(exact), Err(PendingShadowError::Busy));
        assert!(shadow.is_quarantined());
    }

    #[test]
    fn bound_generation_without_an_operation_snapshots_and_retires() {
        let mut shadow: PendingShadow<u64, u64, u64> = PendingShadow::new();
        let exact = identity(15, 101, 111);
        shadow.bind(exact).unwrap();
        assert!(!shadow.is_retired());
        assert_eq!(shadow.snapshot(exact), Ok(None));
        shadow.retire(exact).unwrap();
        assert!(!shadow.is_quarantined());
        assert!(shadow.is_retired());
    }

    #[test]
    fn same_or_older_generation_cannot_rebind_after_retirement() {
        for generation in [20, 19] {
            let mut shadow: PendingShadow<u64, u64, u64> = PendingShadow::new();
            let exact = identity(20, 121, 131);
            shadow.bind(exact).unwrap();
            shadow.retire(exact).unwrap();
            assert_eq!(
                shadow.bind(identity(generation, 122, 132)),
                Err(PendingShadowError::StaleGeneration)
            );
            assert!(shadow.is_quarantined());
        }
    }

    #[test]
    fn input_spill_and_output_staging_are_independent_and_bounded() {
        let mut input = InputSpill::new();
        let mut output = OutputStaging::new();
        assert!(input.is_empty());
        assert!(output.is_empty());
        let target = input.receive_target(DRIVER_CHUNK_BYTES).unwrap();
        target[0] = 0x11;
        target[DRIVER_CHUNK_BYTES - 1] = 0x22;
        let staged = output.prepare(DRIVER_CHUNK_BYTES + 1);
        staged[0] = 0xaa;
        staged[DRIVER_CHUNK_BYTES - 1] = 0xbb;

        assert_eq!(input.remaining_prefix(1), &[0x11]);
        assert_eq!(output.prepared()[0], 0xaa);
        assert_eq!(output.prepared()[DRIVER_CHUNK_BYTES - 1], 0xbb);
        assert!(input.consume(1));
        assert_eq!(input.remaining_prefix(DRIVER_CHUNK_BYTES).len(), 1023);
        assert!(input.consume(1023));
        assert!(input.is_empty());
        output.clear();
        assert!(output.is_empty());
        assert!(output.prepared().is_empty());
        assert!(input.receive_target(0).is_none());
        assert!(input.receive_target(DRIVER_CHUNK_BYTES + 1).is_none());
    }
}
