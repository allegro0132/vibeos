//! Portable, allocation-free target-session facade for the C8.4 ledger.
//!
//! This layer binds every active hook to one opaque non-zero sample token in a
//! continuously recycled [`TargetReady`] lineage and to the one-hart context
//! supplied by a trusted kernel adapter. It does not read hardware topology or
//! expose the underlying ledger's `Active`, `Finished`, `Verified`, or
//! `Rejected` handles. A kernel slot must create exactly one lineage and then
//! preserve it only through the provided recycle transitions: constructing a
//! second [`TargetReady`] starts another epoch namespace and is not a valid way
//! to replace that slot. This is the portable boundary that a later kernel slot
//! can place behind a `SpinLock`, tombstone, and executor-owned RAII lease; it
//! is not evidence that trap, executor, kernel, or SSH wiring exists.
//!
//! Target-session handles may move to one exclusive owner, but cannot be
//! shared. The witnesses below pin both sides of that contract.
//!
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::TargetReady<'static>>();
//! require_send::<vibeos_wasm_aot_profile::TargetActive<'static>>();
//! require_send::<vibeos_wasm_aot_profile::TargetFinished<'static>>();
//! require_send::<vibeos_wasm_aot_profile::TargetVerified<'static>>();
//! require_send::<vibeos_wasm_aot_profile::TargetRejected<'static>>();
//! require_send::<vibeos_wasm_aot_profile::TargetStartFailure<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::TargetReady<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::TargetActive<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::TargetFinished<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::TargetVerified<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::TargetRejected<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::TargetStartFailure<'static>>();
//! ```
//! A rejected target sample has diagnostics and a recycle path, but no
//! publication surface:
//!
//! ```compile_fail
//! fn publish(rejected: vibeos_wasm_aot_profile::TargetRejected<'_>) {
//!     let _ = rejected.summary();
//!     let _ = rejected.intervals();
//! }
//! ```

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroU64;

use crate::{
    Active, Finished, Intervals, Phase, Rejected, Storage, Summary, VerificationError, Verified,
};

/// Target identity declaration supplied by a trusted kernel adapter to every
/// formal C8.4 session hook.
///
/// The portable facade validates the values but cannot observe hardware hart
/// identity or the online topology itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetContext {
    online_mask: u64,
    logical_hart: usize,
    physical_hart: usize,
}

impl TargetContext {
    /// The only context accepted for a formal target sample.
    pub const CANONICAL: Self = Self {
        online_mask: 1,
        logical_hart: 0,
        physical_hart: 0,
    };

    pub const fn new(online_mask: u64, logical_hart: usize, physical_hart: usize) -> Self {
        Self {
            online_mask,
            logical_hart,
            physical_hart,
        }
    }

    pub const fn online_mask(self) -> u64 {
        self.online_mask
    }

    pub const fn logical_hart(self) -> usize {
        self.logical_hart
    }

    pub const fn physical_hart(self) -> usize {
        self.physical_hart
    }
}

/// Opaque identity for exactly one armed target sample within one continuously
/// recycled [`TargetReady`] lineage.
///
/// Tokens can only be obtained from a successful [`TargetReady::start`]. They
/// are not globally unique across independently constructed lineages.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SampleToken(NonZeroU64);

impl SampleToken {
    /// Non-zero monotonic epoch, exposed only for diagnostics and evidence.
    pub const fn epoch(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for SampleToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SampleToken")
            .field(&self.epoch())
            .finish()
    }
}

/// Sticky failures enforced by the portable target facade rather than by the
/// interval ledger itself.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct FacadeFaults(u8);

impl FacadeFaults {
    pub const NONE: Self = Self(0);
    pub const WRONG_TOKEN: Self = Self(1 << 0);
    pub const WRONG_ONLINE_MASK: Self = Self(1 << 1);
    pub const WRONG_LOGICAL_HART: Self = Self(1 << 2);
    pub const WRONG_PHYSICAL_HART: Self = Self(1 << 3);
    pub const STALE_IRQ_COOKIE: Self = Self(1 << 4);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn insert(&mut self, fault: Self) {
        self.0 |= fault.0;
    }

    fn for_context(context: TargetContext) -> Self {
        let mut faults = Self::NONE;
        if context.online_mask != TargetContext::CANONICAL.online_mask {
            faults.insert(Self::WRONG_ONLINE_MASK);
        }
        if context.logical_hart != TargetContext::CANONICAL.logical_hart {
            faults.insert(Self::WRONG_LOGICAL_HART);
        }
        if context.physical_hart != TargetContext::CANONICAL.physical_hart {
            faults.insert(Self::WRONG_PHYSICAL_HART);
        }
        faults
    }
}

impl fmt::Debug for FacadeFaults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FacadeFaults")
            .field("bits", &self.bits())
            .field("wrong_token", &self.contains(Self::WRONG_TOKEN))
            .field("wrong_online_mask", &self.contains(Self::WRONG_ONLINE_MASK))
            .field(
                "wrong_logical_hart",
                &self.contains(Self::WRONG_LOGICAL_HART),
            )
            .field(
                "wrong_physical_hart",
                &self.contains(Self::WRONG_PHYSICAL_HART),
            )
            .field("stale_irq_cookie", &self.contains(Self::STALE_IRQ_COOKIE))
            .finish()
    }
}

/// An interrupt overlay capability returned at the matching entry boundary.
///
/// The public inactive value lets trap plumbing use one unconditional exit
/// path. An inactive exit is always a no-op, including after another sample is
/// armed and when observed from a non-canonical hart.
///
/// Active cookies are linear capabilities and cannot be copied:
///
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<vibeos_wasm_aot_profile::IrqCookie>();
/// ```
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<vibeos_wasm_aot_profile::IrqCookie>();
/// ```
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct IrqCookie {
    token: Option<SampleToken>,
}

impl IrqCookie {
    pub const fn inactive() -> Self {
        Self { token: None }
    }

    pub const fn is_active(&self) -> bool {
        self.token.is_some()
    }
}

/// Why a target session could not be armed. The failure retains the ready
/// storage and does not consume an epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetStartError {
    Exhausted,
    InvalidTickSentinel,
    InvalidContext(FacadeFaults),
}

/// Caller-owned buffers ready to arm one target sample.
///
/// Every target-session handle is `Send` so one exclusive owner may move it,
/// including in a pinned kernel future. None of the handles is `Sync`:
///
/// ```
/// fn require_send<T: Send>() {}
/// require_send::<vibeos_wasm_aot_profile::TargetReady<'static>>();
/// require_send::<vibeos_wasm_aot_profile::TargetActive<'static>>();
/// require_send::<vibeos_wasm_aot_profile::TargetFinished<'static>>();
/// require_send::<vibeos_wasm_aot_profile::TargetVerified<'static>>();
/// require_send::<vibeos_wasm_aot_profile::TargetRejected<'static>>();
/// require_send::<vibeos_wasm_aot_profile::TargetStartFailure<'static>>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<vibeos_wasm_aot_profile::TargetReady<'static>>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<vibeos_wasm_aot_profile::TargetActive<'static>>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<vibeos_wasm_aot_profile::TargetFinished<'static>>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<vibeos_wasm_aot_profile::TargetVerified<'static>>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<vibeos_wasm_aot_profile::TargetRejected<'static>>();
/// ```
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<vibeos_wasm_aot_profile::TargetStartFailure<'static>>();
/// ```
pub struct TargetReady<'a> {
    storage: Storage<'a>,
    next_epoch: Option<NonZeroU64>,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> TargetReady<'a> {
    /// Creates a new epoch lineage whose first successful sample uses epoch 1.
    ///
    /// A kernel-owned slot must call this exactly once and retain that lineage
    /// exclusively through the target typestates' recycle transitions.
    pub fn new(storage: Storage<'a>) -> Self {
        Self::from_parts(storage, NonZeroU64::new(1))
    }

    fn from_parts(storage: Storage<'a>, next_epoch: Option<NonZeroU64>) -> Self {
        Self {
            storage,
            next_epoch,
            not_sync: PhantomData,
        }
    }

    pub const fn next_epoch(&self) -> Option<u64> {
        match self.next_epoch {
            Some(epoch) => Some(epoch.get()),
            None => None,
        }
    }

    pub const fn is_exhausted(&self) -> bool {
        self.next_epoch.is_none()
    }

    /// Arms one sample without allocation. Invalid starts retain this exact
    /// ready state inside [`TargetStartFailure`].
    pub fn start(
        self,
        context: TargetContext,
        start_tick: u64,
    ) -> Result<TargetActive<'a>, TargetStartFailure<'a>> {
        let Some(epoch) = self.next_epoch else {
            return Err(TargetStartFailure::new(self, TargetStartError::Exhausted));
        };
        let context_faults = FacadeFaults::for_context(context);
        if !context_faults.is_empty() {
            return Err(TargetStartFailure::new(
                self,
                TargetStartError::InvalidContext(context_faults),
            ));
        }
        if start_tick == u64::MAX {
            return Err(TargetStartFailure::new(
                self,
                TargetStartError::InvalidTickSentinel,
            ));
        }

        let token = SampleToken(epoch);
        let next_epoch = epoch.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(TargetActive {
            ledger: self.storage.start(start_tick),
            token,
            next_epoch,
            facade_faults: FacadeFaults::NONE,
            not_sync: PhantomData,
        })
    }
}

/// Failed arm attempt with the unchanged ready state still owned by it.
pub struct TargetStartFailure<'a> {
    ready: TargetReady<'a>,
    error: TargetStartError,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> TargetStartFailure<'a> {
    fn new(ready: TargetReady<'a>, error: TargetStartError) -> Self {
        Self {
            ready,
            error,
            not_sync: PhantomData,
        }
    }

    pub const fn error(&self) -> TargetStartError {
        self.error
    }

    pub fn into_ready(self) -> TargetReady<'a> {
        self.ready
    }
}

/// Armed target sample. Every mutating entry point requires the exact token
/// and canonical dynamic target context.
pub struct TargetActive<'a> {
    ledger: Active<'a>,
    token: SampleToken,
    next_epoch: Option<NonZeroU64>,
    facade_faults: FacadeFaults,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> TargetActive<'a> {
    pub const fn token(&self) -> SampleToken {
        self.token
    }

    pub const fn facade_faults(&self) -> FacadeFaults {
        self.facade_faults
    }

    fn validate_call(&mut self, token: SampleToken, context: TargetContext) -> bool {
        if token != self.token {
            self.facade_faults.insert(FacadeFaults::WRONG_TOKEN);
        }
        self.facade_faults.0 |= FacadeFaults::for_context(context).0;
        self.facade_faults.is_empty()
    }

    pub fn set_phase(
        &mut self,
        token: SampleToken,
        context: TargetContext,
        tick: u64,
        phase: Phase,
    ) {
        if self.validate_call(token, context) {
            self.ledger.set_phase(tick, phase);
        }
    }

    pub fn begin_cleanup(&mut self, token: SampleToken, context: TargetContext, tick: u64) {
        if self.validate_call(token, context) {
            self.ledger.begin_cleanup(tick);
        }
    }

    pub fn interrupt_enter(
        &mut self,
        token: SampleToken,
        context: TargetContext,
        tick: u64,
    ) -> IrqCookie {
        if !self.validate_call(token, context) {
            return IrqCookie::inactive();
        }
        self.ledger.interrupt_enter(tick);
        IrqCookie { token: Some(token) }
    }

    pub fn interrupt_exit(&mut self, cookie: IrqCookie, context: TargetContext, tick: u64) {
        let Some(cookie_token) = cookie.token else {
            return;
        };
        let mut valid = self.validate_call(cookie_token, context);
        if cookie_token != self.token {
            self.facade_faults.insert(FacadeFaults::STALE_IRQ_COOKIE);
            valid = false;
        }
        if valid {
            self.ledger.interrupt_exit(tick);
        }
    }

    /// Closes a facade-clean sample. A poisoned facade aborts and clears the
    /// ledger immediately, producing diagnostic-only rejection instead.
    pub fn finish(
        mut self,
        token: SampleToken,
        context: TargetContext,
        end_tick: u64,
    ) -> Result<TargetFinished<'a>, TargetRejected<'a>> {
        if !self.validate_call(token, context) {
            let faults = self.facade_faults;
            let storage = self.ledger.abort();
            return Err(TargetRejected::aborted(
                storage,
                self.token,
                self.next_epoch,
                faults,
                false,
            ));
        }
        Ok(TargetFinished {
            ledger: self.ledger.finish(end_tick),
            token: self.token,
            next_epoch: self.next_epoch,
            not_sync: PhantomData,
        })
    }

    /// Cancels and clears an active sample. Cancellation can never create a
    /// finished or publishable handle.
    pub fn cancel(mut self, token: SampleToken, context: TargetContext) -> TargetRejected<'a> {
        self.validate_call(token, context);
        let faults = self.facade_faults;
        let storage = self.ledger.abort();
        TargetRejected::aborted(storage, self.token, self.next_epoch, faults, true)
    }
}

/// Closed target sample that has not yet undergone the independent full
/// ledger rescan.
pub struct TargetFinished<'a> {
    ledger: Finished<'a>,
    token: SampleToken,
    next_epoch: Option<NonZeroU64>,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> TargetFinished<'a> {
    pub const fn token(&self) -> SampleToken {
        self.token
    }

    /// Runs the underlying independent verifier as a distinct typestate step.
    pub fn verify(self) -> Result<TargetVerified<'a>, TargetRejected<'a>> {
        match self.ledger.verify() {
            Ok(ledger) => Ok(TargetVerified {
                ledger,
                token: self.token,
                next_epoch: self.next_epoch,
                not_sync: PhantomData,
            }),
            Err(ledger) => Err(TargetRejected::ledger(ledger, self.token, self.next_epoch)),
        }
    }
}

/// The only target typestate that exposes formal summary and interval data.
pub struct TargetVerified<'a> {
    ledger: Verified<'a>,
    token: SampleToken,
    next_epoch: Option<NonZeroU64>,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> TargetVerified<'a> {
    pub const fn token(&self) -> SampleToken {
        self.token
    }

    pub const fn summary(&self) -> Summary {
        self.ledger.summary()
    }

    pub fn intervals(&self) -> Intervals<'_> {
        self.ledger.intervals()
    }

    pub fn recycle(self) -> TargetReady<'a> {
        TargetReady::from_parts(self.ledger.recycle(), self.next_epoch)
    }
}

enum RejectedStorage<'a> {
    Aborted(Storage<'a>),
    Ledger(Rejected<'a>),
}

/// Diagnostic-only target rejection. It intentionally has no summary or
/// interval methods.
///
/// ```compile_fail
/// fn publish(rejected: vibeos_wasm_aot_profile::TargetRejected<'_>) {
///     let _ = rejected.summary();
///     let _ = rejected.intervals();
/// }
/// ```
pub struct TargetRejected<'a> {
    storage: RejectedStorage<'a>,
    token: SampleToken,
    next_epoch: Option<NonZeroU64>,
    facade_faults: FacadeFaults,
    ledger_error: Option<VerificationError>,
    cancelled: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> TargetRejected<'a> {
    fn aborted(
        storage: Storage<'a>,
        token: SampleToken,
        next_epoch: Option<NonZeroU64>,
        facade_faults: FacadeFaults,
        cancelled: bool,
    ) -> Self {
        Self {
            storage: RejectedStorage::Aborted(storage),
            token,
            next_epoch,
            facade_faults,
            ledger_error: None,
            cancelled,
            not_sync: PhantomData,
        }
    }

    fn ledger(ledger: Rejected<'a>, token: SampleToken, next_epoch: Option<NonZeroU64>) -> Self {
        let ledger_error = ledger.error();
        Self {
            storage: RejectedStorage::Ledger(ledger),
            token,
            next_epoch,
            facade_faults: FacadeFaults::NONE,
            ledger_error: Some(ledger_error),
            cancelled: false,
            not_sync: PhantomData,
        }
    }

    pub const fn token(&self) -> SampleToken {
        self.token
    }

    pub const fn facade_faults(&self) -> FacadeFaults {
        self.facade_faults
    }

    pub const fn ledger_error(&self) -> Option<VerificationError> {
        self.ledger_error
    }

    pub const fn was_cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn recycle(self) -> TargetReady<'a> {
        let storage = match self.storage {
            RejectedStorage::Aborted(storage) => storage,
            RejectedStorage::Ledger(ledger) => ledger.recycle(),
        };
        TargetReady::from_parts(storage, self.next_epoch)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{Faults, PhaseTicks, INTERVAL_CAPACITY};
    use std::vec;
    use std::vec::Vec;

    fn heap_storage() -> (Vec<u64>, Vec<u8>) {
        (
            vec![u64::MAX; INTERVAL_CAPACITY],
            vec![u8::MAX; INTERVAL_CAPACITY],
        )
    }

    fn ready<'a>(endpoints: &'a mut [u64], phases: &'a mut [u8]) -> TargetReady<'a> {
        TargetReady::new(Storage::new(endpoints, phases).unwrap())
    }

    fn require_send<T: Send>() {}

    fn finish_valid<'a>(mut active: TargetActive<'a>, end_tick: u64) -> TargetVerified<'a> {
        let token = active.token();
        active.begin_cleanup(token, TargetContext::CANONICAL, end_tick - 10);
        let finished = match active.finish(token, TargetContext::CANONICAL, end_tick) {
            Ok(finished) => finished,
            Err(_) => panic!("facade-clean sample was rejected before verification"),
        };
        match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("valid ledger sample did not verify"),
        }
    }

    fn rejection_error(rejected: &TargetRejected<'_>) -> VerificationError {
        match rejected.ledger_error() {
            Some(error) => error,
            None => panic!("expected a ledger verification error"),
        }
    }

    fn assert_pristine_ledger(active: &TargetActive<'_>, start_tick: u64) {
        let core = &active.ledger.core;
        assert_eq!(core.start_tick, start_tick);
        assert_eq!(core.last_observed_tick, start_tick);
        assert_eq!(core.interval_start_tick, start_tick);
        assert_eq!(core.current_phase, Phase::Validation);
        assert_eq!(core.base_phase, Phase::Validation);
        assert!(!core.cleanup_latched);
        assert!(!core.interrupt_active);
        assert_eq!(core.stored_count, 0);
        assert_eq!(core.required_intervals, 0);
        assert_eq!(core.logical_last_phase, None);
        assert_eq!(core.collected_phase_ticks, PhaseTicks::ZERO);
        assert!(core.faults.is_empty());
        assert!(!core.storage_frozen);
        assert!(core.buffers.endpoints.iter().all(|value| *value == 0));
        assert!(core.buffers.phases.iter().all(|value| *value == 0));
    }

    #[test]
    fn target_handles_are_send_and_epoch_starts_at_one() {
        require_send::<TargetReady<'static>>();
        require_send::<TargetActive<'static>>();
        require_send::<TargetFinished<'static>>();
        require_send::<TargetVerified<'static>>();
        require_send::<TargetRejected<'static>>();
        require_send::<TargetStartFailure<'static>>();

        let (mut endpoints, mut phases) = heap_storage();
        let ready = ready(&mut endpoints, &mut phases);
        assert_eq!(ready.next_epoch(), Some(1));
    }

    #[test]
    fn happy_path_covers_all_seven_phases_and_recycles_to_a_new_epoch() {
        let (mut endpoints, mut phases) = heap_storage();
        let active = match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
            Ok(active) => active,
            Err(_) => panic!("canonical start failed"),
        };
        assert_eq!(active.token().epoch(), 1);
        let mut active = active;
        let token = active.token();
        active.set_phase(token, TargetContext::CANONICAL, 110, Phase::Instantiation);
        active.set_phase(token, TargetContext::CANONICAL, 120, Phase::Abi);
        active.set_phase(token, TargetContext::CANONICAL, 130, Phase::Interpretation);
        active.set_phase(token, TargetContext::CANONICAL, 140, Phase::Host);
        active.set_phase(token, TargetContext::CANONICAL, 150, Phase::Wait);
        active.begin_cleanup(token, TargetContext::CANONICAL, 160);
        let finished = match active.finish(token, TargetContext::CANONICAL, 170) {
            Ok(finished) => finished,
            Err(_) => panic!("clean target facade rejected the sample"),
        };
        assert_eq!(finished.token(), token);
        let verified = match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("seven-phase sample did not verify"),
        };
        assert_eq!(
            verified.summary().phase_ticks(),
            PhaseTicks {
                validation: 10,
                instantiation: 10,
                abi: 10,
                interpretation: 10,
                host: 10,
                wait: 10,
                cleanup: 10,
            }
        );
        assert_eq!(verified.intervals().count(), 7);

        let ready = verified.recycle();
        assert_eq!(ready.next_epoch(), Some(2));
        let active = match ready.start(TargetContext::CANONICAL, 200) {
            Ok(active) => active,
            Err(_) => panic!("second epoch did not arm"),
        };
        assert_eq!(active.token().epoch(), 2);
        let token = active.token();
        let verified = finish_valid(active, 220);
        assert_eq!(verified.token(), token);
    }

    #[derive(Clone, Copy, Debug)]
    enum ActiveEntry {
        Phase,
        Cleanup,
        IrqEnter,
        IrqExit,
        Finish,
        Cancel,
    }

    const ACTIVE_ENTRIES: [ActiveEntry; 6] = [
        ActiveEntry::Phase,
        ActiveEntry::Cleanup,
        ActiveEntry::IrqEnter,
        ActiveEntry::IrqExit,
        ActiveEntry::Finish,
        ActiveEntry::Cancel,
    ];

    #[derive(Clone, Copy, Debug)]
    enum BadIdentity {
        Token,
        OnlineMask,
        LogicalHart,
        PhysicalHart,
    }

    const BAD_IDENTITIES: [(BadIdentity, FacadeFaults); 4] = [
        (BadIdentity::Token, FacadeFaults::WRONG_TOKEN),
        (BadIdentity::OnlineMask, FacadeFaults::WRONG_ONLINE_MASK),
        (BadIdentity::LogicalHart, FacadeFaults::WRONG_LOGICAL_HART),
        (BadIdentity::PhysicalHart, FacadeFaults::WRONG_PHYSICAL_HART),
    ];

    fn bad_token(token: SampleToken) -> SampleToken {
        let epoch = if token.epoch() == 1 { 2 } else { 1 };
        SampleToken(NonZeroU64::new(epoch).unwrap())
    }

    fn bad_context(identity: BadIdentity) -> TargetContext {
        match identity {
            BadIdentity::Token => TargetContext::CANONICAL,
            BadIdentity::OnlineMask => TargetContext::new(3, 0, 0),
            BadIdentity::LogicalHart => TargetContext::new(1, 1, 0),
            BadIdentity::PhysicalHart => TargetContext::new(1, 0, 1),
        }
    }

    fn invoke_bad_identity<'a>(
        mut active: TargetActive<'a>,
        entry: ActiveEntry,
        identity: BadIdentity,
    ) -> TargetRejected<'a> {
        let current = active.token();
        let supplied = if matches!(identity, BadIdentity::Token) {
            bad_token(current)
        } else {
            current
        };
        let context = bad_context(identity);

        match entry {
            ActiveEntry::Phase => {
                active.set_phase(supplied, context, 110, Phase::Host);
            }
            ActiveEntry::Cleanup => {
                active.begin_cleanup(supplied, context, 110);
            }
            ActiveEntry::IrqEnter => {
                let _ = active.interrupt_enter(supplied, context, 110);
            }
            ActiveEntry::IrqExit => {
                let cookie = if matches!(identity, BadIdentity::Token) {
                    IrqCookie {
                        token: Some(supplied),
                    }
                } else {
                    active.interrupt_enter(current, TargetContext::CANONICAL, 105)
                };
                active.interrupt_exit(cookie, context, 110);
            }
            ActiveEntry::Finish => {
                return match active.finish(supplied, context, 110) {
                    Ok(_) => panic!("bad finish identity was accepted"),
                    Err(rejected) => rejected,
                };
            }
            ActiveEntry::Cancel => {
                return active.cancel(supplied, context);
            }
        }

        match active.finish(current, TargetContext::CANONICAL, 120) {
            Ok(_) => panic!("sticky facade fault did not reject finish"),
            Err(rejected) => rejected,
        }
    }

    #[test]
    fn every_active_entry_stickily_checks_token_and_full_context() {
        for entry in ACTIVE_ENTRIES {
            for (identity, expected) in BAD_IDENTITIES {
                let (mut endpoints, mut phases) = heap_storage();
                let active =
                    match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                        Ok(active) => active,
                        Err(_) => panic!("test start failed"),
                    };
                let rejected = invoke_bad_identity(active, entry, identity);
                assert!(
                    rejected.facade_faults().contains(expected),
                    "entry {entry:?} accepted bad identity {identity:?}: {:?}",
                    rejected.facade_faults()
                );
                assert!(rejected.ledger_error().is_none());
            }
        }
    }

    #[test]
    fn start_failures_retain_ready_storage_and_do_not_consume_epoch() {
        let (mut endpoints, mut phases) = heap_storage();
        let ready = ready(&mut endpoints, &mut phases);
        let failure = match ready.start(TargetContext::new(3, 1, 2), 100) {
            Ok(_) => panic!("invalid context armed a target sample"),
            Err(failure) => failure,
        };
        let faults = match failure.error() {
            TargetStartError::InvalidContext(faults) => faults,
            error => panic!("wrong start error: {error:?}"),
        };
        assert!(faults.contains(FacadeFaults::WRONG_ONLINE_MASK));
        assert!(faults.contains(FacadeFaults::WRONG_LOGICAL_HART));
        assert!(faults.contains(FacadeFaults::WRONG_PHYSICAL_HART));
        let ready = failure.into_ready();
        assert_eq!(ready.next_epoch(), Some(1));

        let failure = match ready.start(TargetContext::CANONICAL, u64::MAX) {
            Ok(_) => panic!("sentinel start tick armed a target sample"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), TargetStartError::InvalidTickSentinel);
        assert_eq!(failure.into_ready().next_epoch(), Some(1));
    }

    #[test]
    fn an_old_epoch_cannot_mutate_a_new_sample() {
        let (mut endpoints, mut phases) = heap_storage();
        let first = match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
            Ok(active) => active,
            Err(_) => panic!("first start failed"),
        };
        let old_token = first.token();
        let ready = first.cancel(old_token, TargetContext::CANONICAL).recycle();
        let mut second = match ready.start(TargetContext::CANONICAL, 200) {
            Ok(active) => active,
            Err(_) => panic!("second start failed"),
        };
        let current = second.token();
        second.set_phase(old_token, TargetContext::CANONICAL, 210, Phase::Host);
        assert_pristine_ledger(&second, 200);

        // Once any identity check fails, even a later canonical hook must not
        // mutate the ledger behind the already-poisoned facade.
        second.set_phase(current, TargetContext::CANONICAL, 215, Phase::Abi);
        assert_pristine_ledger(&second, 200);

        let rejected = match second.finish(current, TargetContext::CANONICAL, 220) {
            Ok(_) => panic!("old epoch did not poison the new sample"),
            Err(rejected) => rejected,
        };
        assert!(rejected.facade_faults().contains(FacadeFaults::WRONG_TOKEN));
    }

    #[test]
    fn inactive_irq_cookie_is_an_absolute_noop_across_arm() {
        let inactive = IrqCookie::inactive();
        assert!(!inactive.is_active());
        let (mut endpoints, mut phases) = heap_storage();
        let mut active =
            match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                Ok(active) => active,
                Err(_) => panic!("start failed"),
            };
        active.interrupt_exit(inactive, TargetContext::new(u64::MAX, 9, 9), u64::MAX);
        assert!(active.facade_faults().is_empty());
        let verified = finish_valid(active, 120);
        assert_eq!(verified.summary().total_ticks(), 20);
    }

    #[test]
    fn canonical_active_irq_cookie_restores_the_ledger_and_verifies() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active =
            match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                Ok(active) => active,
                Err(_) => panic!("start failed"),
            };
        let token = active.token();
        active.set_phase(token, TargetContext::CANONICAL, 105, Phase::Host);
        let cookie = active.interrupt_enter(token, TargetContext::CANONICAL, 110);
        assert!(cookie.is_active());
        active.interrupt_exit(cookie, TargetContext::CANONICAL, 120);
        active.begin_cleanup(token, TargetContext::CANONICAL, 130);
        let finished = match active.finish(token, TargetContext::CANONICAL, 140) {
            Ok(finished) => finished,
            Err(_) => panic!("canonical IRQ round trip poisoned the facade"),
        };
        let verified = match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("canonical IRQ round trip did not verify"),
        };
        assert_eq!(verified.summary().phase_ticks().wait, 10);
        assert!(verified.intervals().any(|interval| {
            interval.phase() == Phase::Wait
                && interval.start_offset_ticks() == 10
                && interval.end_offset_ticks() == 20
        }));
    }

    #[test]
    fn stale_active_irq_cookie_poisoning_is_epoch_bound() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut first =
            match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                Ok(active) => active,
                Err(_) => panic!("first start failed"),
            };
        let first_token = first.token();
        let stale = first.interrupt_enter(first_token, TargetContext::CANONICAL, 105);
        let ready = first
            .cancel(first_token, TargetContext::CANONICAL)
            .recycle();
        let mut second = match ready.start(TargetContext::CANONICAL, 200) {
            Ok(active) => active,
            Err(_) => panic!("second start failed"),
        };
        let current = second.token();
        second.interrupt_exit(stale, TargetContext::CANONICAL, 205);
        let rejected = match second.finish(current, TargetContext::CANONICAL, 210) {
            Ok(_) => panic!("stale IRQ cookie did not poison the new epoch"),
            Err(rejected) => rejected,
        };
        assert!(rejected
            .facade_faults()
            .contains(FacadeFaults::STALE_IRQ_COOKIE));
        assert!(rejected.facade_faults().contains(FacadeFaults::WRONG_TOKEN));
    }

    #[test]
    fn nested_and_missing_irq_exit_are_rejected_by_the_ledger() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active =
            match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                Ok(active) => active,
                Err(_) => panic!("nested test start failed"),
            };
        let token = active.token();
        let first = active.interrupt_enter(token, TargetContext::CANONICAL, 105);
        let _nested = active.interrupt_enter(token, TargetContext::CANONICAL, 106);
        active.interrupt_exit(first, TargetContext::CANONICAL, 107);
        let finished = match active.finish(token, TargetContext::CANONICAL, 110) {
            Ok(finished) => finished,
            Err(_) => panic!("ledger fault incorrectly became a facade rejection"),
        };
        let rejected = match finished.verify() {
            Ok(_) => panic!("nested interrupt verified"),
            Err(rejected) => rejected,
        };
        assert!(matches!(
            rejection_error(&rejected),
            VerificationError::CollectionFaults(faults)
                if faults.contains(Faults::NESTED_INTERRUPT)
        ));

        let (mut endpoints, mut phases) = heap_storage();
        let mut active =
            match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                Ok(active) => active,
                Err(_) => panic!("missing-exit test start failed"),
            };
        let token = active.token();
        let _cookie = active.interrupt_enter(token, TargetContext::CANONICAL, 105);
        let finished = match active.finish(token, TargetContext::CANONICAL, 110) {
            Ok(finished) => finished,
            Err(_) => panic!("ledger fault incorrectly became a facade rejection"),
        };
        let rejected = match finished.verify() {
            Ok(_) => panic!("open interrupt verified"),
            Err(rejected) => rejected,
        };
        assert!(matches!(
            rejection_error(&rejected),
            VerificationError::CollectionFaults(faults)
                if faults.contains(Faults::FINISH_DURING_INTERRUPT)
        ));
    }

    #[derive(Clone, Copy, Debug)]
    enum TickEntry {
        Phase,
        Cleanup,
        IrqEnter,
        IrqExit,
        Finish,
    }

    const TICK_ENTRIES: [TickEntry; 5] = [
        TickEntry::Phase,
        TickEntry::Cleanup,
        TickEntry::IrqEnter,
        TickEntry::IrqExit,
        TickEntry::Finish,
    ];

    fn invoke_bad_tick(entry: TickEntry, tick: u64) -> VerificationError {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active =
            match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                Ok(active) => active,
                Err(_) => panic!("tick test start failed"),
            };
        let token = active.token();
        let finished = match entry {
            TickEntry::Phase => {
                active.set_phase(token, TargetContext::CANONICAL, tick, Phase::Host);
                match active.finish(token, TargetContext::CANONICAL, 120) {
                    Ok(finished) => finished,
                    Err(_) => panic!("tick fault became facade rejection"),
                }
            }
            TickEntry::Cleanup => {
                active.begin_cleanup(token, TargetContext::CANONICAL, tick);
                match active.finish(token, TargetContext::CANONICAL, 120) {
                    Ok(finished) => finished,
                    Err(_) => panic!("tick fault became facade rejection"),
                }
            }
            TickEntry::IrqEnter => {
                let _ = active.interrupt_enter(token, TargetContext::CANONICAL, tick);
                match active.finish(token, TargetContext::CANONICAL, 120) {
                    Ok(finished) => finished,
                    Err(_) => panic!("tick fault became facade rejection"),
                }
            }
            TickEntry::IrqExit => {
                let cookie = active.interrupt_enter(token, TargetContext::CANONICAL, 105);
                active.interrupt_exit(cookie, TargetContext::CANONICAL, tick);
                match active.finish(token, TargetContext::CANONICAL, 120) {
                    Ok(finished) => finished,
                    Err(_) => panic!("tick fault became facade rejection"),
                }
            }
            TickEntry::Finish => match active.finish(token, TargetContext::CANONICAL, tick) {
                Ok(finished) => finished,
                Err(_) => panic!("tick fault became facade rejection"),
            },
        };
        let rejected = match finished.verify() {
            Ok(_) => panic!("bad tick at {entry:?} verified"),
            Err(rejected) => rejected,
        };
        rejection_error(&rejected)
    }

    #[test]
    fn max_and_regressing_ticks_fail_at_every_timestamped_entry() {
        for entry in TICK_ENTRIES {
            assert!(matches!(
                invoke_bad_tick(entry, u64::MAX),
                VerificationError::CollectionFaults(faults)
                    if faults.contains(Faults::INVALID_TICK_SENTINEL)
            ));
            let regression_tick = if matches!(entry, TickEntry::IrqExit) {
                104
            } else {
                99
            };
            assert!(matches!(
                invoke_bad_tick(entry, regression_tick),
                VerificationError::CollectionFaults(faults)
                    if faults.contains(Faults::CLOCK_REGRESSION)
            ));
        }
    }

    #[test]
    fn max_epoch_is_used_once_then_exhaustion_is_permanent() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut ready = ready(&mut endpoints, &mut phases);
        ready.next_epoch = NonZeroU64::new(u64::MAX - 1);

        let active = match ready.start(TargetContext::CANONICAL, 100) {
            Ok(active) => active,
            Err(_) => panic!("MAX-1 epoch failed"),
        };
        assert_eq!(active.token().epoch(), u64::MAX - 1);
        let token = active.token();
        let ready = active.cancel(token, TargetContext::CANONICAL).recycle();
        assert_eq!(ready.next_epoch(), Some(u64::MAX));

        let active = match ready.start(TargetContext::CANONICAL, 200) {
            Ok(active) => active,
            Err(_) => panic!("MAX epoch failed"),
        };
        assert_eq!(active.token().epoch(), u64::MAX);
        let token = active.token();
        let ready = active.cancel(token, TargetContext::CANONICAL).recycle();
        assert!(ready.is_exhausted());
        assert_eq!(ready.next_epoch(), None);

        let failure = match ready.start(TargetContext::new(7, 8, 9), u64::MAX) {
            Ok(_) => panic!("exhausted ready state wrapped its epoch"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), TargetStartError::Exhausted);
        let ready = failure.into_ready();
        assert!(ready.is_exhausted());
        let failure = match ready.start(TargetContext::CANONICAL, 300) {
            Ok(_) => panic!("exhaustion was not permanent"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error(), TargetStartError::Exhausted);
    }

    #[test]
    fn active_abort_and_target_cancel_clear_complete_storage() {
        let (mut endpoints, mut phases) = heap_storage();
        {
            let mut active = Storage::new(&mut endpoints, &mut phases)
                .unwrap()
                .start(100);
            active.set_phase(110, Phase::Host);
            let storage = active.abort();
            assert!(storage.buffers.endpoints.iter().all(|value| *value == 0));
            assert!(storage.buffers.phases.iter().all(|value| *value == 0));
            drop(storage);
        }
        assert!(endpoints.iter().all(|value| *value == 0));
        assert!(phases.iter().all(|value| *value == 0));

        endpoints.fill(u64::MAX);
        phases.fill(u8::MAX);
        {
            let mut active =
                match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 100) {
                    Ok(active) => active,
                    Err(_) => panic!("cancel clear start failed"),
                };
            let token = active.token();
            active.set_phase(token, TargetContext::CANONICAL, 110, Phase::Host);
            let rejected = active.cancel(token, TargetContext::CANONICAL);
            assert!(rejected.was_cancelled());
            assert!(rejected.facade_faults().is_empty());
            match &rejected.storage {
                RejectedStorage::Aborted(storage) => {
                    assert!(storage.buffers.endpoints.iter().all(|value| *value == 0));
                    assert!(storage.buffers.phases.iter().all(|value| *value == 0));
                }
                RejectedStorage::Ledger(_) => panic!("cancel produced a ledger rejection"),
            }
            drop(rejected);
        }
        assert!(endpoints.iter().all(|value| *value == 0));
        assert!(phases.iter().all(|value| *value == 0));
    }
}
