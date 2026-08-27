//! Allocation-free, target-clocked interval collection for the frozen C8.4
//! WebAssembly AOT decision workload.
//!
//! The collector borrows exactly one caller-owned endpoint array and one
//! caller-owned phase array. Handles move linearly from [`Storage`] through
//! [`Active`] and [`Finished`]. Only an independently rescanned [`Verified`]
//! handle exposes a publishable summary or interval iterator. Rejected and
//! unverified samples can only be inspected as diagnostics and recycled.
//! These raw ledger primitives do not establish target identity or topology.
//! The allocation-free [`ProfilePublisher`] implemented here accepts only
//! [`TargetVerified`], which is obtainable only through the target-session
//! facade. This boundary validates one SAMPLE's shape; it does not itself
//! establish live provenance. [`BootCollector`] privately chains that
//! primitive into one build-bound physical-Duo transcript containing one META,
//! 24 ordered SAMPLE records, and one END. The target adapter must still prove
//! live provenance, one physical cold boot, and exclusive ownership of the
//! target lineage supplied to the collector.
//!
//! Every handle is linearly owned. It may move with one exclusive `Send`
//! future, but cannot be shared through `Sync`; moving ownership does not
//! duplicate the active sample or permit concurrent hooks. A formal target
//! collector must still pin that future to hart 0 and dynamically reject any
//! hook observed on another hart. The following checks pin both halves of that
//! type contract:
//!
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::Storage<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::Storage<'static>>();
//! ```
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::Active<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::Active<'static>>();
//! ```
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::Finished<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::Finished<'static>>();
//! ```
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::Verified<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::Verified<'static>>();
//! ```
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::Rejected<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::Rejected<'static>>();
//! ```
//! ```
//! fn require_send<T: Send>() {}
//! require_send::<vibeos_wasm_aot_profile::Intervals<'static>>();
//! ```
//! ```compile_fail
//! fn require_sync<T: Sync>() {}
//! require_sync::<vibeos_wasm_aot_profile::Intervals<'static>>();
//! ```

#![no_std]

mod collector;
mod publisher;
mod target;

pub use collector::{
    BootCollector, BootReceipt, Campaign, CampaignError, CollectionFailure, CollectionProgress,
    CollectorAbort, CollectorFault, CollectorReady, CompletedTranscript, PoisonedTranscript,
    ProfileRecordSinkFactory, RecordStage, BOOT_RETAINED, BOOT_SAMPLES, BOOT_WARMUPS,
};

pub use publisher::{
    BindingError, Challenge, EligibleTerminalEvidence, PoisonedPublisher, PreflightError,
    PreflightFailure, ProfilePublisher, ProfileRecordSink, PublishFailure, Published, RunId,
    SinkFailure, TerminalEvidenceError, TerminalObservation, TranscriptBinding, FORMAL_READ_CHUNKS,
    FORMAL_STDOUT_BYTES, FORMAL_STDOUT_SHA256, FORMAL_WRITE_CHUNKS, MAX_FORMAL_FUEL,
};

pub use target::{
    FacadeFaults, IrqCookie, SampleToken, TargetActive, TargetContext, TargetFinished, TargetReady,
    TargetRejected, TargetStartError, TargetStartFailure, TargetVerified,
};

use core::cell::Cell;
use core::fmt;
use core::iter::FusedIterator;
use core::marker::PhantomData;

/// Frozen engineering capacity for one C8.4 sample.
pub const INTERVAL_CAPACITY: usize = 65_536;
/// Exact caller-owned packed storage, excluding the small live handle.
pub const PACKED_STORAGE_BYTES: usize =
    INTERVAL_CAPACITY * (core::mem::size_of::<u64>() + core::mem::size_of::<u8>());

const PHASE_COUNT: usize = 7;

/// The seven mutually exclusive C8.4 reporting phases, in schema order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Validation = 1,
    Instantiation = 2,
    Abi = 3,
    Interpretation = 4,
    Host = 5,
    Wait = 6,
    Cleanup = 7,
}

impl Phase {
    pub const ALL: [Self; PHASE_COUNT] = [
        Self::Validation,
        Self::Instantiation,
        Self::Abi,
        Self::Interpretation,
        Self::Host,
        Self::Wait,
        Self::Cleanup,
    ];

    /// Stable packed representation stored in the caller-owned phase array.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Exact spelling used by the frozen C8.4 JSON schema.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Instantiation => "instantiation",
            Self::Abi => "abi",
            Self::Interpretation => "interpretation",
            Self::Host => "host",
            Self::Wait => "wait",
            Self::Cleanup => "cleanup",
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Validation),
            2 => Some(Self::Instantiation),
            3 => Some(Self::Abi),
            4 => Some(Self::Interpretation),
            5 => Some(Self::Host),
            6 => Some(Self::Wait),
            7 => Some(Self::Cleanup),
            _ => None,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Per-phase tick totals with field names matching `phase_ticks` in schema v1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PhaseTicks {
    pub validation: u64,
    pub instantiation: u64,
    pub abi: u64,
    pub interpretation: u64,
    pub host: u64,
    pub wait: u64,
    pub cleanup: u64,
}

impl PhaseTicks {
    pub const ZERO: Self = Self {
        validation: 0,
        instantiation: 0,
        abi: 0,
        interpretation: 0,
        host: 0,
        wait: 0,
        cleanup: 0,
    };

    pub const fn get(self, phase: Phase) -> u64 {
        match phase {
            Phase::Validation => self.validation,
            Phase::Instantiation => self.instantiation,
            Phase::Abi => self.abi,
            Phase::Interpretation => self.interpretation,
            Phase::Host => self.host,
            Phase::Wait => self.wait,
            Phase::Cleanup => self.cleanup,
        }
    }

    /// Returns `None` if a corrupted set of totals cannot be added in `u64`.
    pub const fn checked_total(self) -> Option<u64> {
        let Some(total) = self.validation.checked_add(self.instantiation) else {
            return None;
        };
        let Some(total) = total.checked_add(self.abi) else {
            return None;
        };
        let Some(total) = total.checked_add(self.interpretation) else {
            return None;
        };
        let Some(total) = total.checked_add(self.host) else {
            return None;
        };
        let Some(total) = total.checked_add(self.wait) else {
            return None;
        };
        match total.checked_add(self.cleanup) {
            Some(u64::MAX) | None => None,
            total => total,
        }
    }

    fn checked_add(&mut self, phase: Phase, ticks: u64) -> bool {
        let slot = match phase {
            Phase::Validation => &mut self.validation,
            Phase::Instantiation => &mut self.instantiation,
            Phase::Abi => &mut self.abi,
            Phase::Interpretation => &mut self.interpretation,
            Phase::Host => &mut self.host,
            Phase::Wait => &mut self.wait,
            Phase::Cleanup => &mut self.cleanup,
        };
        let Some(total) = slot.checked_add(ticks) else {
            return false;
        };
        if total == u64::MAX {
            return false;
        }
        *slot = total;
        true
    }
}

/// Sticky collection failures. Any non-empty set permanently prevents
/// publication, even if later timestamps look valid.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Faults(u16);

impl Faults {
    pub const NONE: Self = Self(0);
    pub const CLOCK_REGRESSION: Self = Self(1 << 0);
    pub const CAPACITY_EXHAUSTED: Self = Self(1 << 1);
    pub const REQUIRED_INTERVALS_OVERFLOW: Self = Self(1 << 2);
    pub const PHASE_TOTAL_OVERFLOW: Self = Self(1 << 3);
    pub const NESTED_INTERRUPT: Self = Self(1 << 4);
    pub const INTERRUPT_EXIT_WITHOUT_ENTRY: Self = Self(1 << 5);
    pub const PHASE_CHANGE_DURING_INTERRUPT: Self = Self(1 << 6);
    pub const FINISH_DURING_INTERRUPT: Self = Self(1 << 7);
    pub const FINISH_WITHOUT_CLEANUP: Self = Self(1 << 8);
    pub const INVALID_TICK_SENTINEL: Self = Self(1 << 9);

    const NON_CONTINUABLE_BITS: u16 = Self::CLOCK_REGRESSION.0
        | Self::REQUIRED_INTERVALS_OVERFLOW.0
        | Self::PHASE_TOTAL_OVERFLOW.0
        | Self::NESTED_INTERRUPT.0
        | Self::INTERRUPT_EXIT_WITHOUT_ENTRY.0
        | Self::PHASE_CHANGE_DURING_INTERRUPT.0
        | Self::FINISH_DURING_INTERRUPT.0
        | Self::INVALID_TICK_SENTINEL.0;

    pub const fn bits(self) -> u16 {
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

    const fn can_continue_capacity_accounting(self) -> bool {
        self.0 & Self::NON_CONTINUABLE_BITS == 0
    }
}

impl fmt::Debug for Faults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Faults")
            .field("bits", &self.0)
            .field("clock_regression", &self.contains(Self::CLOCK_REGRESSION))
            .field(
                "capacity_exhausted",
                &self.contains(Self::CAPACITY_EXHAUSTED),
            )
            .field(
                "required_intervals_overflow",
                &self.contains(Self::REQUIRED_INTERVALS_OVERFLOW),
            )
            .field(
                "phase_total_overflow",
                &self.contains(Self::PHASE_TOTAL_OVERFLOW),
            )
            .field("nested_interrupt", &self.contains(Self::NESTED_INTERRUPT))
            .field(
                "interrupt_exit_without_entry",
                &self.contains(Self::INTERRUPT_EXIT_WITHOUT_ENTRY),
            )
            .field(
                "phase_change_during_interrupt",
                &self.contains(Self::PHASE_CHANGE_DURING_INTERRUPT),
            )
            .field(
                "finish_during_interrupt",
                &self.contains(Self::FINISH_DURING_INTERRUPT),
            )
            .field(
                "finish_without_cleanup",
                &self.contains(Self::FINISH_WITHOUT_CLEANUP),
            )
            .field(
                "invalid_tick_sentinel",
                &self.contains(Self::INVALID_TICK_SENTINEL),
            )
            .finish()
    }
}

/// Construction fails unless both caller-owned arrays have the frozen size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    EndpointCapacity { actual: usize },
    PhaseCapacity { actual: usize },
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointCapacity { actual } => write!(
                formatter,
                "endpoint capacity must be {INTERVAL_CAPACITY}, got {actual}"
            ),
            Self::PhaseCapacity { actual } => write!(
                formatter,
                "phase capacity must be {INTERVAL_CAPACITY}, got {actual}"
            ),
        }
    }
}

struct Buffers<'a> {
    endpoints: &'a mut [u64],
    phases: &'a mut [u8],
}

impl Buffers<'_> {
    fn clear(&mut self) {
        self.endpoints.fill(0);
        self.phases.fill(0);
    }
}

impl Drop for Buffers<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Caller-owned, cleared storage ready to start exactly one sample.
pub struct Storage<'a> {
    buffers: Buffers<'a>,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> Storage<'a> {
    /// Borrows and clears exact-capacity endpoint and phase slices.
    pub fn new(endpoints: &'a mut [u64], phases: &'a mut [u8]) -> Result<Self, StorageError> {
        if endpoints.len() != INTERVAL_CAPACITY {
            return Err(StorageError::EndpointCapacity {
                actual: endpoints.len(),
            });
        }
        if phases.len() != INTERVAL_CAPACITY {
            return Err(StorageError::PhaseCapacity {
                actual: phases.len(),
            });
        }
        let mut buffers = Buffers { endpoints, phases };
        buffers.clear();
        Ok(Self {
            buffers,
            not_sync: PhantomData,
        })
    }

    /// Starts the response interval in the mandatory validation phase.
    pub fn start(self, start_tick: u64) -> Active<'a> {
        let (faults, storage_frozen) = if start_tick == u64::MAX {
            (Faults::INVALID_TICK_SENTINEL, true)
        } else {
            (Faults::NONE, false)
        };
        Active {
            core: LedgerCore {
                buffers: self.buffers,
                start_tick,
                last_observed_tick: start_tick,
                interval_start_tick: start_tick,
                current_phase: Phase::Validation,
                base_phase: Phase::Validation,
                cleanup_latched: false,
                interrupt_active: false,
                stored_count: 0,
                required_intervals: 0,
                logical_last_phase: None,
                collected_phase_ticks: PhaseTicks::ZERO,
                faults,
                storage_frozen,
            },
            not_sync: PhantomData,
        }
    }
}

struct LedgerCore<'a> {
    buffers: Buffers<'a>,
    start_tick: u64,
    last_observed_tick: u64,
    interval_start_tick: u64,
    current_phase: Phase,
    base_phase: Phase,
    cleanup_latched: bool,
    interrupt_active: bool,
    stored_count: usize,
    required_intervals: u64,
    logical_last_phase: Option<Phase>,
    collected_phase_ticks: PhaseTicks,
    faults: Faults,
    storage_frozen: bool,
}

impl<'a> LedgerCore<'a> {
    fn observe_tick(&mut self, tick: u64) -> bool {
        if !self.faults.can_continue_capacity_accounting() {
            return false;
        }
        if tick == u64::MAX {
            self.faults.insert(Faults::INVALID_TICK_SENTINEL);
            self.storage_frozen = true;
            return false;
        }
        if tick < self.last_observed_tick {
            self.faults.insert(Faults::CLOCK_REGRESSION);
            self.storage_frozen = true;
            return false;
        }
        self.last_observed_tick = tick;
        true
    }

    fn switch_effective_phase(&mut self, tick: u64, next: Phase) {
        if self.current_phase == next {
            return;
        }
        self.close_current_interval(tick);
        self.current_phase = next;
        self.interval_start_tick = tick;
    }

    fn close_current_interval(&mut self, tick: u64) {
        let duration = tick - self.interval_start_tick;
        if duration == 0 {
            return;
        }

        if !self
            .collected_phase_ticks
            .checked_add(self.current_phase, duration)
        {
            self.faults.insert(Faults::PHASE_TOTAL_OVERFLOW);
            self.storage_frozen = true;
            return;
        }

        let end_offset = tick - self.start_tick;
        if self.logical_last_phase == Some(self.current_phase) {
            if !self.storage_frozen {
                debug_assert!(self.stored_count != 0);
                self.buffers.endpoints[self.stored_count - 1] = end_offset;
            }
            self.interval_start_tick = tick;
            return;
        }

        let Some(required) = self.required_intervals.checked_add(1) else {
            self.faults.insert(Faults::REQUIRED_INTERVALS_OVERFLOW);
            self.storage_frozen = true;
            return;
        };
        self.required_intervals = required;
        self.logical_last_phase = Some(self.current_phase);

        if self.storage_frozen {
            self.interval_start_tick = tick;
            return;
        }
        if self.stored_count == INTERVAL_CAPACITY {
            self.faults.insert(Faults::CAPACITY_EXHAUSTED);
            self.storage_frozen = true;
            self.interval_start_tick = tick;
            return;
        }

        self.buffers.endpoints[self.stored_count] = end_offset;
        self.buffers.phases[self.stored_count] = self.current_phase.code();
        self.stored_count += 1;
        self.interval_start_tick = tick;
    }

    fn recycle(mut self) -> Storage<'a> {
        self.buffers.clear();
        Storage {
            buffers: self.buffers,
            not_sync: PhantomData,
        }
    }
}

/// The only mutable collection state. A mutable reference is required for
/// every hook so target code can serialize the one-active-sample invariant.
pub struct Active<'a> {
    core: LedgerCore<'a>,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> Active<'a> {
    /// Abandons an in-progress sample, clears the complete caller-owned
    /// buffers, and returns them as fresh storage. No closed or publishable
    /// handle is created by this recovery path.
    pub fn abort(self) -> Storage<'a> {
        self.core.recycle()
    }

    /// Changes the base phase at `tick`.
    ///
    /// `Cleanup` is a latch: after it is requested, later base-phase hooks are
    /// observed for clock monotonicity but cannot leave cleanup. A base-phase
    /// change while an interrupt overlay is open is a sticky failure; callers
    /// must first supply the target-owned interrupt-exit timestamp.
    pub fn set_phase(&mut self, tick: u64, requested: Phase) {
        if !self.core.observe_tick(tick) {
            return;
        }
        if self.core.interrupt_active {
            self.core
                .faults
                .insert(Faults::PHASE_CHANGE_DURING_INTERRUPT);
            self.core.storage_frozen = true;
            return;
        }

        let next = if self.core.cleanup_latched || requested == Phase::Cleanup {
            self.core.cleanup_latched = true;
            Phase::Cleanup
        } else {
            requested
        };
        self.core.base_phase = next;
        self.core.switch_effective_phase(tick, next);
    }

    /// Explicit spelling for the irreversible cleanup latch.
    pub fn begin_cleanup(&mut self, tick: u64) {
        self.set_phase(tick, Phase::Cleanup);
    }

    /// Overlays `wait` at the earliest target trap-entry timestamp.
    pub fn interrupt_enter(&mut self, tick: u64) {
        if !self.core.observe_tick(tick) {
            return;
        }
        if self.core.interrupt_active {
            self.core.faults.insert(Faults::NESTED_INTERRUPT);
            self.core.storage_frozen = true;
            return;
        }
        self.core.interrupt_active = true;
        self.core.switch_effective_phase(tick, Phase::Wait);
    }

    /// Closes the interrupt overlay and restores the base phase. A cleanup
    /// latch established before entry therefore restores cleanup and cannot be
    /// bypassed by an interrupt round trip.
    pub fn interrupt_exit(&mut self, tick: u64) {
        if !self.core.observe_tick(tick) {
            return;
        }
        if !self.core.interrupt_active {
            self.core
                .faults
                .insert(Faults::INTERRUPT_EXIT_WITHOUT_ENTRY);
            self.core.storage_frozen = true;
            return;
        }
        self.core.interrupt_active = false;
        let restore = if self.core.cleanup_latched {
            Phase::Cleanup
        } else {
            self.core.base_phase
        };
        self.core.switch_effective_phase(tick, restore);
    }

    /// Closes collection. The returned handle still cannot publish anything;
    /// it must pass [`Finished::verify`] first.
    pub fn finish(mut self, end_tick: u64) -> Finished<'a> {
        if self.core.observe_tick(end_tick) {
            if self.core.interrupt_active {
                self.core.faults.insert(Faults::FINISH_DURING_INTERRUPT);
                self.core.storage_frozen = true;
            } else {
                self.core.close_current_interval(end_tick);
                if !self.core.cleanup_latched {
                    self.core.faults.insert(Faults::FINISH_WITHOUT_CLEANUP);
                }
            }
        }
        Finished {
            core: self.core,
            end_tick,
            not_sync: PhantomData,
        }
    }
}

/// A closed but untrusted sample. It exposes diagnostics only.
pub struct Finished<'a> {
    core: LedgerCore<'a>,
    end_tick: u64,
    not_sync: PhantomData<Cell<()>>,
}

impl<'a> Finished<'a> {
    pub const fn faults(&self) -> Faults {
        self.core.faults
    }

    pub const fn stored_interval_count(&self) -> usize {
        self.core.stored_count
    }

    pub const fn required_interval_count(&self) -> u64 {
        self.core.required_intervals
    }

    pub const fn storage_frozen(&self) -> bool {
        self.core.storage_frozen
    }

    /// Independently decodes and rescans every stored interval before creating
    /// the only publishable handle.
    pub fn verify(self) -> Result<Verified<'a>, Rejected<'a>> {
        let verification = verify_core(&self.core, self.end_tick);
        match verification {
            Ok(summary) => Ok(Verified {
                core: self.core,
                summary,
                not_sync: PhantomData,
            }),
            Err(error) => Err(Rejected {
                core: self.core,
                end_tick: self.end_tick,
                error,
                not_sync: PhantomData,
            }),
        }
    }

    /// Discards an unverified sample and clears all caller-owned storage.
    pub fn recycle(self) -> Storage<'a> {
        self.core.recycle()
    }
}

/// Independent verification failure. Collection faults are kept as a single
/// variant so callers cannot accidentally reinterpret an incomplete sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    CollectionFaults(Faults),
    CapacityInvariant {
        stored: usize,
        required: u64,
    },
    FinishBeforeStart {
        start_tick: u64,
        end_tick: u64,
    },
    InvalidTickSentinel,
    FinishTickNotLastObserved {
        end_tick: u64,
        last_observed_tick: u64,
    },
    CleanupNotLatched,
    InterruptStillActive,
    StorageFrozen,
    FinalPhaseNotCleanup {
        current: Phase,
        base: Phase,
    },
    OpenIntervalAtFinish {
        interval_start_tick: u64,
        end_tick: u64,
    },
    Empty,
    RequiredCountNotRepresentable {
        required: u64,
    },
    CountMismatch {
        stored: usize,
        required: usize,
    },
    InvalidPhaseCode {
        sequence: usize,
        code: u8,
    },
    NonIncreasingEndpoint {
        sequence: usize,
        previous: u64,
        endpoint: u64,
    },
    EndpointPastFinish {
        sequence: usize,
        endpoint: u64,
        total_ticks: u64,
    },
    AdjacentEqualPhase {
        sequence: usize,
        phase: Phase,
    },
    LogicalLastPhaseMismatch {
        collected: Option<Phase>,
        rescanned: Option<Phase>,
    },
    PhaseTotalOverflow,
    FinalEndpointMismatch {
        endpoint: u64,
        total_ticks: u64,
    },
    PhaseTotalsMismatch {
        collected: PhaseTicks,
        rescanned: PhaseTicks,
    },
    TotalMismatch {
        phase_total: u64,
        total_ticks: u64,
    },
}

fn verify_core(core: &LedgerCore<'_>, end_tick: u64) -> Result<Summary, VerificationError> {
    if !core.faults.is_empty() {
        return Err(VerificationError::CollectionFaults(core.faults));
    }
    if core.stored_count > INTERVAL_CAPACITY || core.required_intervals > INTERVAL_CAPACITY as u64 {
        return Err(VerificationError::CapacityInvariant {
            stored: core.stored_count,
            required: core.required_intervals,
        });
    }
    if core.start_tick == u64::MAX
        || end_tick == u64::MAX
        || core.last_observed_tick == u64::MAX
        || core.interval_start_tick == u64::MAX
    {
        return Err(VerificationError::InvalidTickSentinel);
    }
    if end_tick < core.start_tick {
        return Err(VerificationError::FinishBeforeStart {
            start_tick: core.start_tick,
            end_tick,
        });
    }
    if core.last_observed_tick != end_tick {
        return Err(VerificationError::FinishTickNotLastObserved {
            end_tick,
            last_observed_tick: core.last_observed_tick,
        });
    }
    if !core.cleanup_latched {
        return Err(VerificationError::CleanupNotLatched);
    }
    if core.interrupt_active {
        return Err(VerificationError::InterruptStillActive);
    }
    if core.storage_frozen {
        return Err(VerificationError::StorageFrozen);
    }
    if core.current_phase != Phase::Cleanup || core.base_phase != Phase::Cleanup {
        return Err(VerificationError::FinalPhaseNotCleanup {
            current: core.current_phase,
            base: core.base_phase,
        });
    }
    if core.interval_start_tick != end_tick {
        return Err(VerificationError::OpenIntervalAtFinish {
            interval_start_tick: core.interval_start_tick,
            end_tick,
        });
    }
    let Ok(required) = usize::try_from(core.required_intervals) else {
        return Err(VerificationError::RequiredCountNotRepresentable {
            required: core.required_intervals,
        });
    };
    if core.stored_count != required {
        return Err(VerificationError::CountMismatch {
            stored: core.stored_count,
            required,
        });
    }
    if required == 0 {
        return Err(VerificationError::Empty);
    }

    let total_ticks = end_tick - core.start_tick;
    let mut previous_endpoint = 0;
    let mut previous_phase = None;
    let mut rescanned = PhaseTicks::ZERO;
    for sequence in 0..required {
        let code = core.buffers.phases[sequence];
        let Some(phase) = Phase::from_code(code) else {
            return Err(VerificationError::InvalidPhaseCode { sequence, code });
        };
        let endpoint = core.buffers.endpoints[sequence];
        if endpoint <= previous_endpoint {
            return Err(VerificationError::NonIncreasingEndpoint {
                sequence,
                previous: previous_endpoint,
                endpoint,
            });
        }
        if endpoint > total_ticks {
            return Err(VerificationError::EndpointPastFinish {
                sequence,
                endpoint,
                total_ticks,
            });
        }
        if previous_phase == Some(phase) {
            return Err(VerificationError::AdjacentEqualPhase { sequence, phase });
        }
        if !rescanned.checked_add(phase, endpoint - previous_endpoint) {
            return Err(VerificationError::PhaseTotalOverflow);
        }
        previous_endpoint = endpoint;
        previous_phase = Some(phase);
    }

    if previous_endpoint != total_ticks {
        return Err(VerificationError::FinalEndpointMismatch {
            endpoint: previous_endpoint,
            total_ticks,
        });
    }
    if core.logical_last_phase != previous_phase {
        return Err(VerificationError::LogicalLastPhaseMismatch {
            collected: core.logical_last_phase,
            rescanned: previous_phase,
        });
    }
    if rescanned != core.collected_phase_ticks {
        return Err(VerificationError::PhaseTotalsMismatch {
            collected: core.collected_phase_ticks,
            rescanned,
        });
    }
    let Some(phase_total) = rescanned.checked_total() else {
        return Err(VerificationError::PhaseTotalOverflow);
    };
    if phase_total != total_ticks {
        return Err(VerificationError::TotalMismatch {
            phase_total,
            total_ticks,
        });
    }

    Ok(Summary {
        start_tick: core.start_tick,
        end_tick,
        total_ticks,
        phase_ticks: rescanned,
        interval_capacity: INTERVAL_CAPACITY,
        interval_count: required,
        intervals_complete: true,
    })
}

/// Closed diagnostic state. It deliberately has no summary or interval
/// iterator, so rejected bytes cannot be mistaken for formal evidence.
pub struct Rejected<'a> {
    core: LedgerCore<'a>,
    end_tick: u64,
    error: VerificationError,
    not_sync: PhantomData<Cell<()>>,
}

impl fmt::Debug for Rejected<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Rejected")
            .field("start_tick", &self.core.start_tick)
            .field("end_tick", &self.end_tick)
            .field("stored_interval_count", &self.core.stored_count)
            .field("required_interval_count", &self.core.required_intervals)
            .field("error", &self.error)
            .finish()
    }
}

impl<'a> Rejected<'a> {
    pub const fn error(&self) -> VerificationError {
        self.error
    }

    pub const fn faults(&self) -> Faults {
        self.core.faults
    }

    pub const fn start_tick(&self) -> u64 {
        self.core.start_tick
    }

    pub const fn end_tick(&self) -> u64 {
        self.end_tick
    }

    pub const fn stored_interval_count(&self) -> usize {
        self.core.stored_count
    }

    pub const fn required_interval_count(&self) -> u64 {
        self.core.required_intervals
    }

    pub fn recycle(self) -> Storage<'a> {
        self.core.recycle()
    }
}

/// Schema-shaped summary available only after independent verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    start_tick: u64,
    end_tick: u64,
    total_ticks: u64,
    phase_ticks: PhaseTicks,
    interval_capacity: usize,
    interval_count: usize,
    intervals_complete: bool,
}

impl Summary {
    pub const fn start_tick(self) -> u64 {
        self.start_tick
    }

    pub const fn end_tick(self) -> u64 {
        self.end_tick
    }

    pub const fn total_ticks(self) -> u64 {
        self.total_ticks
    }

    pub const fn phase_ticks(self) -> PhaseTicks {
        self.phase_ticks
    }

    pub const fn interval_capacity(self) -> usize {
        self.interval_capacity
    }

    pub const fn interval_count(self) -> usize {
        self.interval_count
    }

    pub const fn intervals_complete(self) -> bool {
        self.intervals_complete
    }
}

/// One exact schema-v1 interval reconstructed from packed endpoint storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interval {
    sequence: usize,
    phase: Phase,
    start_offset_ticks: u64,
    end_offset_ticks: u64,
}

impl Interval {
    pub const fn sequence(self) -> usize {
        self.sequence
    }

    pub const fn phase(self) -> Phase {
        self.phase
    }

    pub const fn start_offset_ticks(self) -> u64 {
        self.start_offset_ticks
    }

    pub const fn end_offset_ticks(self) -> u64 {
        self.end_offset_ticks
    }
}

/// The only state that exposes publishable interval data.
pub struct Verified<'a> {
    core: LedgerCore<'a>,
    summary: Summary,
    not_sync: PhantomData<Cell<()>>,
}

impl fmt::Debug for Verified<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Verified")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl<'a> Verified<'a> {
    pub const fn summary(&self) -> Summary {
        self.summary
    }

    /// Copies one verified interval in constant time.
    ///
    /// This indexed surface lets a kernel-owned streaming slot retain the
    /// storage-bearing verified handle globally while an async publisher owns
    /// only a cursor. Out-of-range indices return `None`.
    pub fn interval(&self, sequence: usize) -> Option<Interval> {
        if sequence >= self.summary.interval_count {
            return None;
        }
        let start_offset_ticks = if sequence == 0 {
            0
        } else {
            self.core.buffers.endpoints[sequence - 1]
        };
        Some(Interval {
            sequence,
            // Verified construction already decoded every byte.
            phase: Phase::from_code(self.core.buffers.phases[sequence])?,
            start_offset_ticks,
            end_offset_ticks: self.core.buffers.endpoints[sequence],
        })
    }

    pub fn intervals(&self) -> Intervals<'_> {
        Intervals {
            endpoints: &self.core.buffers.endpoints[..self.summary.interval_count],
            phases: &self.core.buffers.phases[..self.summary.interval_count],
            front: 0,
            not_sync: PhantomData,
        }
    }

    pub fn recycle(self) -> Storage<'a> {
        self.core.recycle()
    }
}

/// Exact-size forward iterator over a verified sample.
pub struct Intervals<'a> {
    endpoints: &'a [u64],
    phases: &'a [u8],
    front: usize,
    not_sync: PhantomData<Cell<()>>,
}

impl Iterator for Intervals<'_> {
    type Item = Interval;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.endpoints.len() {
            return None;
        }
        let sequence = self.front;
        let start_offset_ticks = if sequence == 0 {
            0
        } else {
            self.endpoints[sequence - 1]
        };
        let interval = Interval {
            sequence,
            // Verified construction already decoded every byte.
            phase: Phase::from_code(self.phases[sequence])?,
            start_offset_ticks,
            end_offset_ticks: self.endpoints[sequence],
        };
        self.front += 1;
        Some(interval)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.endpoints.len() - self.front;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Intervals<'_> {}
impl FusedIterator for Intervals<'_> {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::future::Future;
    use core::pin::Pin;
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;

    fn heap_storage() -> (Vec<u64>, Vec<u8>) {
        (
            vec![u64::MAX; INTERVAL_CAPACITY],
            vec![u8::MAX; INTERVAL_CAPACITY],
        )
    }

    fn require_send<T: Send>() {}

    fn active_kernel_driver(active: Active<'static>) -> Pin<Box<dyn Future<Output = u64> + Send>> {
        Box::pin(async move {
            core::future::pending::<()>().await;
            drop(active);
            0
        })
    }

    fn verified_kernel_driver(
        verified: Verified<'static>,
    ) -> Pin<Box<dyn Future<Output = u64> + Send>> {
        Box::pin(async move {
            core::future::pending::<()>().await;
            drop(verified);
            0
        })
    }

    #[test]
    fn linear_handles_fit_the_pinned_send_future_contract() {
        require_send::<Storage<'static>>();
        require_send::<Active<'static>>();
        require_send::<Finished<'static>>();
        require_send::<Verified<'static>>();
        require_send::<Rejected<'static>>();
        require_send::<Intervals<'static>>();

        // These function-pointer witnesses force the same erased future type
        // used by the kernel driver. Their async bodies retain the handle
        // after an await, but no permanently-pending future is constructed or
        // polled by this test.
        let _: fn(Active<'static>) -> Pin<Box<dyn Future<Output = u64> + Send>> =
            active_kernel_driver;
        let _: fn(Verified<'static>) -> Pin<Box<dyn Future<Output = u64> + Send>> =
            verified_kernel_driver;
    }

    #[test]
    fn frozen_schema_literals_are_exact() {
        assert_eq!(INTERVAL_CAPACITY, 65_536);
        assert_eq!(PACKED_STORAGE_BYTES, 589_824);
        assert_eq!(
            Phase::ALL.map(|phase| (phase.code(), phase.as_str())),
            [
                (1, "validation"),
                (2, "instantiation"),
                (3, "abi"),
                (4, "interpretation"),
                (5, "host"),
                (6, "wait"),
                (7, "cleanup"),
            ]
        );
    }

    fn valid_finished<'a>(endpoints: &'a mut [u64], phases: &'a mut [u8]) -> Finished<'a> {
        let mut active = Storage::new(endpoints, phases).unwrap().start(100);
        active.set_phase(110, Phase::Instantiation);
        active.set_phase(120, Phase::Abi);
        active.set_phase(130, Phase::Interpretation);
        active.set_phase(140, Phase::Host);
        active.set_phase(150, Phase::Wait);
        active.begin_cleanup(160);
        active.finish(170)
    }

    #[test]
    fn verified_summary_and_iterator_map_losslessly_to_schema() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases)
            .unwrap()
            .start(1_000);
        active.set_phase(1_002, Phase::Validation);
        active.set_phase(1_010, Phase::Instantiation);
        active.set_phase(1_020, Phase::Abi);
        active.set_phase(1_030, Phase::Interpretation);
        active.interrupt_enter(1_035);
        active.interrupt_exit(1_040);
        active.set_phase(1_050, Phase::Host);
        active.set_phase(1_060, Phase::Wait);
        active.set_phase(1_060, Phase::Host);
        active.set_phase(1_070, Phase::Abi);
        active.begin_cleanup(1_080);
        active.set_phase(1_085, Phase::Host);
        active.interrupt_enter(1_090);
        active.interrupt_exit(1_095);
        let verified = active.finish(1_100).verify().unwrap();

        let summary = verified.summary();
        assert_eq!(summary.start_tick(), 1_000);
        assert_eq!(summary.end_tick(), 1_100);
        assert_eq!(summary.total_ticks(), 100);
        assert_eq!(summary.interval_capacity(), INTERVAL_CAPACITY);
        assert_eq!(summary.phase_ticks().checked_total(), Some(100));
        assert!(summary.intervals_complete());

        let mut intervals = verified.intervals();
        assert_eq!(intervals.len(), summary.interval_count());
        let mut expected_sequence = 0;
        let mut previous_end = 0;
        let mut previous_phase = None;
        while let Some(interval) = intervals.next() {
            assert_eq!(interval.sequence(), expected_sequence);
            assert_eq!(verified.interval(expected_sequence), Some(interval));
            assert_eq!(interval.start_offset_ticks(), previous_end);
            assert!(interval.end_offset_ticks() > interval.start_offset_ticks());
            assert_ne!(previous_phase, Some(interval.phase()));
            expected_sequence += 1;
            previous_end = interval.end_offset_ticks();
            previous_phase = Some(interval.phase());
            assert_eq!(
                intervals.len(),
                summary.interval_count() - expected_sequence
            );
        }
        assert_eq!(expected_sequence, summary.interval_count());
        assert_eq!(previous_end, summary.total_ticks());
        assert_eq!(verified.interval(summary.interval_count()), None);
        assert_eq!(verified.interval(usize::MAX), None);
    }

    #[test]
    fn zero_duration_changes_are_suppressed_and_neighbors_merge() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        active.set_phase(10, Phase::Host);
        active.set_phase(20, Phase::Wait);
        active.set_phase(20, Phase::Host);
        active.set_phase(30, Phase::Validation);
        active.begin_cleanup(40);
        let verified = active.finish(50).verify().unwrap();
        let intervals: Vec<_> = verified.intervals().collect();
        assert_eq!(intervals.len(), 4);
        assert_eq!(intervals[0].phase, Phase::Validation);
        assert_eq!(intervals[0].start_offset_ticks, 0);
        assert_eq!(intervals[0].end_offset_ticks, 10);
        assert_eq!(intervals[1].phase, Phase::Host);
        assert_eq!(intervals[1].start_offset_ticks, 10);
        assert_eq!(intervals[1].end_offset_ticks, 30);
        assert_eq!(intervals[2].phase, Phase::Validation);
        assert_eq!(intervals[3].phase, Phase::Cleanup);
    }

    #[test]
    fn cleanup_latch_wins_over_interrupt_restore_and_later_hooks() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        active.set_phase(10, Phase::Host);
        active.begin_cleanup(20);
        active.interrupt_enter(25);
        active.interrupt_exit(30);
        active.set_phase(40, Phase::Interpretation);
        let verified = active.finish(50).verify().unwrap();
        let intervals: Vec<_> = verified.intervals().collect();
        assert_eq!(intervals.len(), 5);
        assert_eq!(intervals[0].phase, Phase::Validation);
        assert_eq!(intervals[1].phase, Phase::Host);
        assert_eq!(intervals[2].phase, Phase::Cleanup);
        assert_eq!(intervals[2].start_offset_ticks, 20);
        assert_eq!(intervals[2].end_offset_ticks, 25);
        assert_eq!(intervals[3].phase, Phase::Wait);
        assert_eq!(intervals[3].start_offset_ticks, 25);
        assert_eq!(intervals[3].end_offset_ticks, 30);
        assert_eq!(intervals[4].phase, Phase::Cleanup);
        assert_eq!(intervals[4].start_offset_ticks, 30);
        assert_eq!(intervals[4].end_offset_ticks, 50);
    }

    #[test]
    fn interrupt_overlay_restores_every_base_phase() {
        for base in Phase::ALL {
            let (mut endpoints, mut phases) = heap_storage();
            let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
            active.set_phase(10, base);
            active.interrupt_enter(20);
            active.interrupt_exit(30);
            active.begin_cleanup(40);
            let verified = active.finish(50).verify().unwrap();
            let intervals: Vec<_> = verified.intervals().collect();

            let at_20 = intervals
                .iter()
                .find(|interval| {
                    interval.start_offset_ticks <= 20 && interval.end_offset_ticks >= 30
                })
                .unwrap();
            if base == Phase::Wait {
                assert_eq!(at_20.phase, Phase::Wait);
            } else {
                assert!(intervals.iter().any(|interval| {
                    interval.phase == Phase::Wait
                        && interval.start_offset_ticks == 20
                        && interval.end_offset_ticks == 30
                }));
                assert!(intervals.iter().any(|interval| {
                    interval.phase == base
                        && interval.start_offset_ticks == 30
                        && interval.end_offset_ticks >= 40
                }));
            }
        }
    }

    #[test]
    fn clock_and_interrupt_protocol_faults_are_sticky_and_unpublishable() {
        let fault_cases = [
            Faults::CLOCK_REGRESSION,
            Faults::NESTED_INTERRUPT,
            Faults::INTERRUPT_EXIT_WITHOUT_ENTRY,
            Faults::PHASE_CHANGE_DURING_INTERRUPT,
            Faults::FINISH_DURING_INTERRUPT,
            Faults::FINISH_WITHOUT_CLEANUP,
            Faults::INVALID_TICK_SENTINEL,
        ];

        for expected in fault_cases {
            let (mut endpoints, mut phases) = heap_storage();
            let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(10);
            match expected {
                Faults::CLOCK_REGRESSION => active.set_phase(9, Phase::Host),
                Faults::NESTED_INTERRUPT => {
                    active.interrupt_enter(11);
                    active.interrupt_enter(12);
                }
                Faults::INTERRUPT_EXIT_WITHOUT_ENTRY => active.interrupt_exit(11),
                Faults::PHASE_CHANGE_DURING_INTERRUPT => {
                    active.interrupt_enter(11);
                    active.set_phase(12, Phase::Host);
                }
                Faults::FINISH_DURING_INTERRUPT => active.interrupt_enter(11),
                Faults::FINISH_WITHOUT_CLEANUP => active.set_phase(11, Phase::Host),
                Faults::INVALID_TICK_SENTINEL => active.set_phase(u64::MAX, Phase::Host),
                _ => unreachable!(),
            }
            if expected != Faults::FINISH_WITHOUT_CLEANUP
                && expected != Faults::FINISH_DURING_INTERRUPT
            {
                active.begin_cleanup(20);
            }
            let rejected = active.finish(30).verify().unwrap_err();
            assert!(rejected.faults().contains(expected));
            assert!(matches!(
                rejected.error(),
                VerificationError::CollectionFaults(_)
            ));
        }
    }

    #[test]
    fn capacity_exhaustion_freezes_bytes_but_counts_later_intervals() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        let extra = 97_u64;
        for tick in 1..=(INTERVAL_CAPACITY as u64 + extra) {
            let phase = if tick & 1 == 0 {
                Phase::Host
            } else {
                Phase::Abi
            };
            active.set_phase(tick, phase);
        }
        active.begin_cleanup(INTERVAL_CAPACITY as u64 + extra + 1);
        let finished = active.finish(INTERVAL_CAPACITY as u64 + extra + 2);
        assert!(finished.faults().contains(Faults::CAPACITY_EXHAUSTED));
        assert!(finished.storage_frozen());
        assert_eq!(finished.stored_interval_count(), INTERVAL_CAPACITY);
        assert!(finished.required_interval_count() > INTERVAL_CAPACITY as u64 + 1);
        assert_eq!(finished.core.buffers.endpoints[0], 1);
        assert_eq!(finished.core.buffers.phases[0], Phase::Validation.code());
        assert_eq!(
            finished.core.buffers.endpoints[INTERVAL_CAPACITY - 1],
            INTERVAL_CAPACITY as u64
        );
        assert_eq!(
            finished.core.buffers.phases[INTERVAL_CAPACITY - 1],
            Phase::Abi.code()
        );
        let rejected = finished.verify().unwrap_err();
        assert_eq!(rejected.stored_interval_count(), INTERVAL_CAPACITY);
        assert!(rejected.required_interval_count() > INTERVAL_CAPACITY as u64 + 1);
    }

    #[test]
    fn exactly_full_capacity_remains_complete_and_publishable() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        for tick in 1..=(INTERVAL_CAPACITY as u64 - 2) {
            active.set_phase(
                tick,
                if tick & 1 == 0 {
                    Phase::Abi
                } else {
                    Phase::Host
                },
            );
        }
        active.begin_cleanup(INTERVAL_CAPACITY as u64 - 1);
        let verified = active.finish(INTERVAL_CAPACITY as u64).verify().unwrap();
        assert_eq!(verified.summary().interval_count(), INTERVAL_CAPACITY);
        assert_eq!(verified.intervals().len(), INTERVAL_CAPACITY);
        assert!(verified.summary().intervals_complete());
    }

    #[test]
    fn empty_and_same_tick_finish_cannot_publish() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(42);
        active.begin_cleanup(42);
        assert_eq!(
            active.finish(42).verify().unwrap_err().error(),
            VerificationError::Empty
        );

        let (mut endpoints, mut phases) = heap_storage();
        let active = Storage::new(&mut endpoints, &mut phases).unwrap().start(42);
        let rejected = active.finish(42).verify().unwrap_err();
        assert!(rejected.faults().contains(Faults::FINISH_WITHOUT_CLEANUP));
    }

    #[test]
    fn exact_storage_lengths_are_mandatory() {
        let mut short_endpoints = vec![0; INTERVAL_CAPACITY - 1];
        let mut exact_phases = vec![0; INTERVAL_CAPACITY];
        assert_eq!(
            Storage::new(&mut short_endpoints, &mut exact_phases).err(),
            Some(StorageError::EndpointCapacity {
                actual: INTERVAL_CAPACITY - 1
            })
        );

        let mut exact_endpoints = vec![0; INTERVAL_CAPACITY];
        let mut short_phases = vec![0; INTERVAL_CAPACITY - 1];
        assert_eq!(
            Storage::new(&mut exact_endpoints, &mut short_phases).err(),
            Some(StorageError::PhaseCapacity {
                actual: INTERVAL_CAPACITY - 1
            })
        );
    }

    #[test]
    fn independent_rescan_rejects_endpoint_phase_and_total_corruption() {
        let (mut endpoints, mut phases) = heap_storage();
        let finished = valid_finished(&mut endpoints, &mut phases);
        finished.core.buffers.endpoints[1] = finished.core.buffers.endpoints[0];
        assert!(matches!(
            finished.verify().unwrap_err().error(),
            VerificationError::NonIncreasingEndpoint { sequence: 1, .. }
        ));

        let (mut endpoints, mut phases) = heap_storage();
        let finished = valid_finished(&mut endpoints, &mut phases);
        finished.core.buffers.phases[2] = 0;
        assert_eq!(
            finished.verify().unwrap_err().error(),
            VerificationError::InvalidPhaseCode {
                sequence: 2,
                code: 0
            }
        );

        let (mut endpoints, mut phases) = heap_storage();
        let mut finished = valid_finished(&mut endpoints, &mut phases);
        finished.core.collected_phase_ticks.validation += 1;
        assert!(matches!(
            finished.verify().unwrap_err().error(),
            VerificationError::PhaseTotalsMismatch { .. }
        ));
    }

    #[test]
    fn independent_rescan_checks_closed_state_before_indexing() {
        fn corrupted_error(mutate: fn(&mut Finished<'_>)) -> VerificationError {
            let (mut endpoints, mut phases) = heap_storage();
            let mut finished = valid_finished(&mut endpoints, &mut phases);
            mutate(&mut finished);
            let error = finished.verify().unwrap_err().error();
            error
        }

        assert!(matches!(
            corrupted_error(|finished| finished.core.stored_count = INTERVAL_CAPACITY + 1),
            VerificationError::CapacityInvariant { .. }
        ));
        assert!(matches!(
            corrupted_error(|finished| {
                finished.core.required_intervals = INTERVAL_CAPACITY as u64 + 1
            }),
            VerificationError::CapacityInvariant { .. }
        ));
        assert!(matches!(
            corrupted_error(|finished| finished.core.required_intervals -= 1),
            VerificationError::CountMismatch { .. }
        ));
        assert!(matches!(
            corrupted_error(|finished| finished.end_tick = finished.core.start_tick - 1),
            VerificationError::FinishBeforeStart { .. }
        ));
        assert_eq!(
            corrupted_error(|finished| finished.core.start_tick = u64::MAX),
            VerificationError::InvalidTickSentinel
        );
        assert_eq!(
            corrupted_error(|finished| finished.end_tick = u64::MAX),
            VerificationError::InvalidTickSentinel
        );
        assert_eq!(
            corrupted_error(|finished| finished.core.last_observed_tick = u64::MAX),
            VerificationError::InvalidTickSentinel
        );
        assert_eq!(
            corrupted_error(|finished| finished.core.interval_start_tick = u64::MAX),
            VerificationError::InvalidTickSentinel
        );
        assert!(matches!(
            corrupted_error(|finished| finished.core.last_observed_tick -= 1),
            VerificationError::FinishTickNotLastObserved { .. }
        ));
        assert_eq!(
            corrupted_error(|finished| finished.core.cleanup_latched = false),
            VerificationError::CleanupNotLatched
        );
        assert_eq!(
            corrupted_error(|finished| finished.core.interrupt_active = true),
            VerificationError::InterruptStillActive
        );
        assert_eq!(
            corrupted_error(|finished| finished.core.storage_frozen = true),
            VerificationError::StorageFrozen
        );
        assert!(matches!(
            corrupted_error(|finished| finished.core.current_phase = Phase::Host),
            VerificationError::FinalPhaseNotCleanup { .. }
        ));
        assert!(matches!(
            corrupted_error(|finished| finished.core.interval_start_tick -= 1),
            VerificationError::OpenIntervalAtFinish { .. }
        ));
        assert!(matches!(
            corrupted_error(|finished| finished.core.logical_last_phase = Some(Phase::Host)),
            VerificationError::LogicalLastPhaseMismatch { .. }
        ));
        assert!(matches!(
            corrupted_error(|finished| {
                let last = finished.core.stored_count - 1;
                finished.core.buffers.endpoints[last] -= 1;
            }),
            VerificationError::FinalEndpointMismatch { .. }
        ));
    }

    #[test]
    fn cleanup_hook_during_interrupt_is_rejected() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        active.interrupt_enter(10);
        active.begin_cleanup(20);
        let rejected = active.finish(30).verify().unwrap_err();
        assert!(rejected
            .faults()
            .contains(Faults::PHASE_CHANGE_DURING_INTERRUPT));
    }

    #[test]
    fn max_tick_is_an_invalid_sentinel_at_start_and_at_finish() {
        let (mut endpoints, mut phases) = heap_storage();
        let active = Storage::new(&mut endpoints, &mut phases)
            .unwrap()
            .start(u64::MAX);
        assert!(active
            .finish(u64::MAX)
            .verify()
            .unwrap_err()
            .faults()
            .contains(Faults::INVALID_TICK_SENTINEL));

        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        active.begin_cleanup(1);
        assert!(active
            .finish(u64::MAX)
            .verify()
            .unwrap_err()
            .faults()
            .contains(Faults::INVALID_TICK_SENTINEL));
    }

    #[test]
    fn checked_required_interval_overflow_is_sticky() {
        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        active.core.required_intervals = u64::MAX;
        active.set_phase(1, Phase::Host);
        let finished = active.finish(2);
        assert!(finished
            .faults()
            .contains(Faults::REQUIRED_INTERVALS_OVERFLOW));
        assert!(finished.verify().is_err());
    }

    #[test]
    fn max_phase_total_sentinel_is_sticky() {
        assert_eq!(
            PhaseTicks {
                validation: u64::MAX,
                ..PhaseTicks::ZERO
            }
            .checked_total(),
            None
        );

        let (mut endpoints, mut phases) = heap_storage();
        let mut active = Storage::new(&mut endpoints, &mut phases).unwrap().start(0);
        active.core.collected_phase_ticks.validation = u64::MAX - 1;
        active.set_phase(1, Phase::Host);
        assert!(active
            .finish(2)
            .verify()
            .unwrap_err()
            .faults()
            .contains(Faults::PHASE_TOTAL_OVERFLOW));
    }

    #[test]
    fn recycle_and_drop_clear_used_entries_and_the_tail() {
        let (mut endpoints, mut phases) = heap_storage();
        {
            let verified = valid_finished(&mut endpoints, &mut phases)
                .verify()
                .unwrap();
            let storage = verified.recycle();
            assert!(storage.buffers.endpoints.iter().all(|value| *value == 0));
            assert!(storage.buffers.phases.iter().all(|value| *value == 0));
        }
        assert!(endpoints.iter().all(|value| *value == 0));
        assert!(phases.iter().all(|value| *value == 0));

        {
            let verified = valid_finished(&mut endpoints, &mut phases)
                .verify()
                .unwrap();
            assert!(verified.summary().interval_count() > 0);
        }
        assert!(endpoints.iter().all(|value| *value == 0));
        assert!(phases.iter().all(|value| *value == 0));
    }
}
