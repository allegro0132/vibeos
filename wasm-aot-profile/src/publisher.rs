//! Allocation-free serialization of one independently verified C8.4 sample.
//!
//! This module is deliberately a single-record primitive. It does not publish
//! `META` or `END`, own a 24-sample transcript, prove that a cold boot occurred,
//! or authenticate the caller that supplied terminal observations. A later
//! trusted target adapter and collector must provide those provenance and
//! transcript-closure guarantees without weakening the authority boundary here.

use core::mem::ManuallyDrop;

use crate::{Interval, Phase, PhaseTicks, Summary, TargetReady, TargetVerified, INTERVAL_CAPACITY};

pub const FORMAL_READ_CHUNKS: u64 = 13;
pub const FORMAL_WRITE_CHUNKS: u64 = 13;
pub const MAX_FORMAL_FUEL: u64 = 500_000;
pub const FORMAL_STDOUT_BYTES: u64 = 12_325;
pub const FORMAL_STDOUT_SHA256: [u8; 32] = [
    0x79, 0x1f, 0x3f, 0xe1, 0x33, 0x99, 0x84, 0xe8, 0xa8, 0x48, 0x9c, 0x12, 0xea, 0x5f, 0xf4, 0x79,
    0xac, 0x7c, 0xaa, 0x07, 0xc8, 0x7b, 0xe4, 0x51, 0x13, 0x4d, 0x3a, 0xf0, 0xf5, 0x26, 0xbb, 0x27,
];

const SAMPLE_PREFIX: &[u8] = b"VIBE_WASM_AOT_SAMPLE ";
const SAMPLE_DOMAIN_WORD: u64 = 4_843_678_931_419_484_236;
const INTERVAL_DOMAIN_WORD: u64 = 4_843_678_888_688_374_358;
const MAX_SAMPLE_INDEX: u8 = 23;
const WARMUP_SAMPLES: u8 = 3;

/// A sink whose writes either accept the complete byte slice or report an
/// error. Implementations must never report success after a short write.
/// An error may follow an arbitrary written prefix, so the publisher treats
/// every failed call as an irrecoverably partial record and quarantines the
/// sink.
///
/// [`ProfileRecordSink::commit_record`] is a commit/flush boundary only. It
/// must not append, rewrite, or otherwise alter payload bytes. The publisher
/// itself writes the record's unique line-feed byte immediately before commit.
pub trait ProfileRecordSink {
    type Error;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    fn commit_record(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    ZeroRunId,
    ZeroChallenge,
}

/// Branded 32-byte run identity. Branding prevents accidentally swapping it
/// with a challenge when constructing [`TranscriptBinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunId([u8; 32]);

impl RunId {
    pub fn new(bytes: [u8; 32]) -> Result<Self, BindingError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(BindingError::ZeroRunId)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Branded 32-byte capture challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge([u8; 32]);

impl Challenge {
    pub fn new(bytes: [u8; 32]) -> Result<Self, BindingError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(BindingError::ZeroChallenge)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Campaign fields repeated by one SAMPLE record.
///
/// This binds bytes inside the record; it does not prove that a matching META
/// record was committed or prevent a caller from forking two single-record
/// publishers with the same prior accumulator. A later collector must keep the
/// transcript chain private and linear.
///
/// The branded arguments cannot be silently transposed:
///
/// ```compile_fail
/// fn swap(
///     run_id: vibeos_wasm_aot_profile::RunId,
///     challenge: vibeos_wasm_aot_profile::Challenge,
/// ) {
///     let _ = vibeos_wasm_aot_profile::TranscriptBinding::new(challenge, run_id);
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranscriptBinding {
    run_id: RunId,
    challenge: Challenge,
}

impl TranscriptBinding {
    pub const fn new(run_id: RunId, challenge: Challenge) -> Self {
        Self { run_id, challenge }
    }

    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    pub const fn challenge(self) -> Challenge {
        self.challenge
    }
}

/// Raw terminal claims supplied to the portable eligibility validator.
///
/// Successful validation proves only that these values satisfy the frozen
/// SAMPLE shape. It does not prove their provenance. In particular,
/// `poll_quanta_exact` is a caller assertion here. A later trusted live adapter
/// must derive it from a checked non-saturated counter; it must never label a
/// saturated `SyncCallProfile` value exact merely to pass this validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalObservation {
    pub read_chunks: u64,
    pub write_chunks: u64,
    pub fuel_consumed: u64,
    pub poll_quanta: u64,
    pub poll_quanta_exact: bool,
    pub succeeded: bool,
    pub logical_live_after: u64,
    pub timed_out: bool,
    pub timeout_phase: Option<Phase>,
    pub exit_status: u32,
    pub stdout_bytes: u64,
    pub stdout_sha256: [u8; 32],
    pub stderr_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalEvidenceError {
    ReadChunks,
    WriteChunks,
    FuelOutOfRange,
    PollQuantaZero,
    PollQuantaNotExact,
    NotSuccessful,
    LogicalStateLive,
    TimedOut,
    TimeoutPhase,
    ExitStatus,
    StdoutLength,
    StdoutDigest,
    StderrNotEmpty,
}

/// Structurally eligible terminal evidence for one SAMPLE.
///
/// The fields remain private and the value is neither `Clone` nor `Copy`. The
/// publisher consumes it, and both serialization and accumulation use the
/// retained observed values rather than substituting fixed literals.
///
/// ```compile_fail
/// fn duplicate(evidence: vibeos_wasm_aot_profile::EligibleTerminalEvidence) {
///     let _ = evidence.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<vibeos_wasm_aot_profile::EligibleTerminalEvidence>();
/// ```
///
/// ```compile_fail
/// let _ = vibeos_wasm_aot_profile::EligibleTerminalEvidence::default();
/// ```
///
/// ```compile_fail
/// let _ = vibeos_wasm_aot_profile::EligibleTerminalEvidence {
///     read_chunks: 13,
/// };
/// ```
///
/// ```compile_fail
/// fn move_twice(evidence: vibeos_wasm_aot_profile::EligibleTerminalEvidence) {
///     let first = evidence;
///     let second = evidence;
///     drop((first, second));
/// }
/// ```
pub struct EligibleTerminalEvidence {
    read_chunks: u64,
    write_chunks: u64,
    fuel_consumed: u64,
    poll_quanta: u64,
    poll_quanta_exact: bool,
    succeeded: bool,
    logical_live_after: u64,
    timed_out: bool,
    timeout_phase: Option<Phase>,
    exit_status: u32,
    stdout_bytes: u64,
    stdout_sha256: [u8; 32],
    stderr_bytes: u64,
}

impl EligibleTerminalEvidence {
    pub fn validate(observation: TerminalObservation) -> Result<Self, TerminalEvidenceError> {
        if observation.read_chunks != FORMAL_READ_CHUNKS {
            return Err(TerminalEvidenceError::ReadChunks);
        }
        if observation.write_chunks != FORMAL_WRITE_CHUNKS {
            return Err(TerminalEvidenceError::WriteChunks);
        }
        if !(1..=MAX_FORMAL_FUEL).contains(&observation.fuel_consumed) {
            return Err(TerminalEvidenceError::FuelOutOfRange);
        }
        if observation.poll_quanta == 0 {
            return Err(TerminalEvidenceError::PollQuantaZero);
        }
        if !observation.poll_quanta_exact {
            return Err(TerminalEvidenceError::PollQuantaNotExact);
        }
        if !observation.succeeded {
            return Err(TerminalEvidenceError::NotSuccessful);
        }
        if observation.logical_live_after != 0 {
            return Err(TerminalEvidenceError::LogicalStateLive);
        }
        if observation.timed_out {
            return Err(TerminalEvidenceError::TimedOut);
        }
        if observation.timeout_phase.is_some() {
            return Err(TerminalEvidenceError::TimeoutPhase);
        }
        if observation.exit_status != 0 {
            return Err(TerminalEvidenceError::ExitStatus);
        }
        if observation.stdout_bytes != FORMAL_STDOUT_BYTES {
            return Err(TerminalEvidenceError::StdoutLength);
        }
        if observation.stdout_sha256 != FORMAL_STDOUT_SHA256 {
            return Err(TerminalEvidenceError::StdoutDigest);
        }
        if observation.stderr_bytes != 0 {
            return Err(TerminalEvidenceError::StderrNotEmpty);
        }

        Ok(Self {
            read_chunks: observation.read_chunks,
            write_chunks: observation.write_chunks,
            fuel_consumed: observation.fuel_consumed,
            poll_quanta: observation.poll_quanta,
            poll_quanta_exact: observation.poll_quanta_exact,
            succeeded: observation.succeeded,
            logical_live_after: observation.logical_live_after,
            timed_out: observation.timed_out,
            timeout_phase: observation.timeout_phase,
            exit_status: observation.exit_status,
            stdout_bytes: observation.stdout_bytes,
            stdout_sha256: observation.stdout_sha256,
            stderr_bytes: observation.stderr_bytes,
        })
    }

    pub const fn fuel_consumed(&self) -> u64 {
        self.fuel_consumed
    }

    pub const fn poll_quanta(&self) -> u64 {
        self.poll_quanta
    }

    pub const fn poll_quanta_is_exact(&self) -> bool {
        self.poll_quanta_exact
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightError {
    SampleIndexOutOfRange {
        actual: u8,
    },
    ZeroTotalTicks,
    IntervalCapacity {
        actual: usize,
    },
    IntervalsIncomplete,
    IntervalCountOutOfRange {
        actual: usize,
    },
    IntervalCountExceedsTotal {
        count: usize,
        total_ticks: u64,
    },
    SummaryPhaseTotalOverflow,
    SummaryPhaseTotalMismatch {
        phase_total: u64,
        total_ticks: u64,
    },
    IntervalSequence {
        expected: usize,
        actual: usize,
    },
    IntervalNotContiguous {
        sequence: usize,
        expected_start: u64,
        actual_start: u64,
    },
    IntervalNotIncreasing {
        sequence: usize,
        start: u64,
        end: u64,
    },
    IntervalPastTotal {
        sequence: usize,
        end: u64,
        total_ticks: u64,
    },
    AdjacentPhase {
        sequence: usize,
        phase: Phase,
    },
    PhaseRescanOverflow {
        sequence: usize,
        phase: Phase,
    },
    IntervalCountMismatch {
        declared: usize,
        observed: usize,
    },
    UnexpectedInterval {
        sequence: usize,
    },
    FinalEndpointMismatch {
        endpoint: u64,
        total_ticks: u64,
    },
    PhaseRescanMismatch,
}

/// One retryable, single-SAMPLE publisher.
///
/// This type is intentionally neither `Clone` nor `Copy`. Its public
/// constructor accepts a raw prior accumulator because transcript ownership is
/// outside this foundation; that does not prove META/END closure or prevent a
/// caller from forking a chain.
///
/// ```compile_fail
/// fn clone_publisher<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
/// ) {
///     let _ = publisher.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn move_twice<S>(publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>) {
///     let first = publisher;
///     let second = publisher;
///     drop((first, second));
/// }
/// ```
pub struct ProfilePublisher<S> {
    sink: S,
    binding: TranscriptBinding,
    prior_accumulator: u64,
}

impl<S> ProfilePublisher<S> {
    pub const fn new(sink: S, binding: TranscriptBinding, prior_accumulator: u64) -> Self {
        Self {
            sink,
            binding,
            prior_accumulator,
        }
    }

    pub const fn binding(&self) -> TranscriptBinding {
        self.binding
    }

    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }
}

impl<S: ProfileRecordSink> ProfilePublisher<S> {
    /// Publishes exactly one canonical SAMPLE and consumes the storage-bearing
    /// target authority by value.
    ///
    /// A preflight error occurs before the first sink call and returns both the
    /// recycled target lineage and this retryable publisher. Once any sink call
    /// occurs, an error permanently quarantines the sink in
    /// [`PoisonedPublisher`]. Every non-panicking result recycles the target
    /// authority exactly once. Panic or process abort is deliberately fail-stop.
    ///
    /// Raw ledger authority is rejected by the type signature:
    ///
    /// ```compile_fail
    /// fn publish_raw<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
    ///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
    ///     raw: vibeos_wasm_aot_profile::Verified<'_>,
    ///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
    /// ) {
    ///     let _ = publisher.publish_profile(raw, 0, terminal);
    /// }
    /// ```
    ///
    /// Summaries and intervals cannot substitute for target authority:
    ///
    /// ```compile_fail
    /// fn publish_summary<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
    ///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
    ///     summary: vibeos_wasm_aot_profile::Summary,
    ///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
    /// ) {
    ///     let _ = publisher.publish_profile(summary, 0, terminal);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// fn publish_interval<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
    ///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
    ///     interval: vibeos_wasm_aot_profile::Interval,
    ///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
    /// ) {
    ///     let _ = publisher.publish_profile(interval, 0, terminal);
    /// }
    /// ```
    ///
    /// Finished target state is not independently verified:
    ///
    /// ```compile_fail
    /// fn publish_finished<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
    ///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
    ///     finished: vibeos_wasm_aot_profile::TargetFinished<'_>,
    ///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
    /// ) {
    ///     let _ = publisher.publish_profile(finished, 0, terminal);
    /// }
    /// ```
    ///
    /// A shared borrow cannot preserve authority for a second publication:
    ///
    /// ```compile_fail
    /// fn publish_borrowed<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
    ///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
    ///     verified: &vibeos_wasm_aot_profile::TargetVerified<'_>,
    ///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
    /// ) {
    ///     let _ = publisher.publish_profile(verified, 0, terminal);
    /// }
    /// ```
    ///
    /// Rejected target state has no publication path:
    ///
    /// ```compile_fail
    /// fn publish_rejected<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
    ///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
    ///     rejected: vibeos_wasm_aot_profile::TargetRejected<'_>,
    ///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
    /// ) {
    ///     let _ = publisher.publish_profile(rejected, 0, terminal);
    /// }
    /// ```
    pub fn publish_profile<'a>(
        self,
        verified: TargetVerified<'a>,
        sample_index: u8,
        terminal: EligibleTerminalEvidence,
    ) -> Result<Published<'a, S>, PublishFailure<'a, S>> {
        let candidate =
            match preflight_profile(&verified, sample_index, &terminal, self.prior_accumulator) {
                Ok(candidate) => candidate,
                Err(error) => {
                    let ready = verified.recycle();
                    return Err(PublishFailure::Preflight(PreflightFailure {
                        ready,
                        publisher: self,
                        error,
                    }));
                }
            };

        // Quarantine the sink before the first potentially panicking sink call.
        // Unwinding therefore cannot run a sink destructor that flushes or
        // appends to a partial formal record.
        let ProfilePublisher {
            sink,
            binding,
            prior_accumulator,
        } = self;
        let mut sink = ManuallyDrop::new(sink);
        let write_result = write_sample(
            &mut *sink,
            binding,
            sample_index,
            &terminal,
            candidate.summary,
            &verified,
        );
        match write_result {
            Ok(()) => {
                let ready = verified.recycle();
                let sink = ManuallyDrop::into_inner(sink);
                Ok(Published {
                    ready,
                    sink,
                    binding,
                    accumulator: candidate.accumulator,
                })
            }
            Err(error) => {
                let ready = verified.recycle();
                Err(PublishFailure::Sink(SinkFailure {
                    ready,
                    publisher: PoisonedPublisher {
                        _sink: sink,
                        failed_sample_index: sample_index,
                        prior_accumulator,
                    },
                    error,
                }))
            }
        }
    }
}

/// Successful single-record publication. This value is neither `Clone` nor
/// `Copy`; consuming it returns the recycled target lineage, sink, binding, and
/// candidate accumulator to a later private collector.
///
/// ```compile_fail
/// fn duplicate<'a, S>(published: vibeos_wasm_aot_profile::Published<'a, S>) {
///     let _ = published.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn require_copy<T: Copy>() {}
/// require_copy::<vibeos_wasm_aot_profile::Published<'static, ()>>();
/// ```
///
/// ```compile_fail
/// fn forge<'a, S>(
///     ready: vibeos_wasm_aot_profile::TargetReady<'a>,
///     sink: S,
///     binding: vibeos_wasm_aot_profile::TranscriptBinding,
/// ) -> vibeos_wasm_aot_profile::Published<'a, S> {
///     vibeos_wasm_aot_profile::Published {
///         ready,
///         sink,
///         binding,
///         accumulator: 0,
///     }
/// }
/// ```
pub struct Published<'a, S> {
    ready: TargetReady<'a>,
    sink: S,
    binding: TranscriptBinding,
    accumulator: u64,
}

impl<'a, S> Published<'a, S> {
    pub const fn accumulator(&self) -> u64 {
        self.accumulator
    }

    pub const fn binding(&self) -> TranscriptBinding {
        self.binding
    }

    pub fn into_parts(self) -> (TargetReady<'a>, S, TranscriptBinding, u64) {
        (self.ready, self.sink, self.binding, self.accumulator)
    }
}

/// Permanently quarantined sink after a possibly partial record.
///
/// The sink is held in [`ManuallyDrop`] and this type exposes no recovery or
/// republish API. Dropping the poison state intentionally retains the resource
/// rather than running `S::drop`, because a sink destructor could flush or
/// append bytes to an already invalid transcript.
///
/// ```compile_fail
/// fn cannot_republish<S: vibeos_wasm_aot_profile::ProfileRecordSink>(
///     poisoned: vibeos_wasm_aot_profile::PoisonedPublisher<S>,
///     verified: vibeos_wasm_aot_profile::TargetVerified<'_>,
///     terminal: vibeos_wasm_aot_profile::EligibleTerminalEvidence,
/// ) {
///     let _ = poisoned.publish_profile(verified, 0, terminal);
/// }
/// ```
///
/// ```compile_fail
/// fn recover_sink<S>(poisoned: &vibeos_wasm_aot_profile::PoisonedPublisher<S>) {
///     let _ = poisoned.sink();
/// }
/// ```
///
/// ```compile_fail
/// fn forge<S>(sink: S) -> vibeos_wasm_aot_profile::PoisonedPublisher<S> {
///     vibeos_wasm_aot_profile::PoisonedPublisher {
///         _sink: core::mem::ManuallyDrop::new(sink),
///         failed_sample_index: 0,
///         prior_accumulator: 0,
///     }
/// }
/// ```
pub struct PoisonedPublisher<S> {
    _sink: ManuallyDrop<S>,
    failed_sample_index: u8,
    prior_accumulator: u64,
}

impl<S> PoisonedPublisher<S> {
    pub const fn failed_sample_index(&self) -> u8 {
        self.failed_sample_index
    }

    pub const fn prior_accumulator(&self) -> u64 {
        self.prior_accumulator
    }
}

/// Non-forgeable zero-write preflight failure.
///
/// External code cannot construct this wrapper because all fields are private;
/// it can only consume a value returned by [`ProfilePublisher::publish_profile`].
///
/// ```compile_fail
/// fn forge<'a, S: vibeos_wasm_aot_profile::ProfileRecordSink>(
///     ready: vibeos_wasm_aot_profile::TargetReady<'a>,
///     publisher: vibeos_wasm_aot_profile::ProfilePublisher<S>,
///     error: vibeos_wasm_aot_profile::PreflightError,
/// ) {
///     let _ = vibeos_wasm_aot_profile::PreflightFailure {
///         ready,
///         publisher,
///         error,
///     };
/// }
/// ```
pub struct PreflightFailure<'a, S> {
    ready: TargetReady<'a>,
    publisher: ProfilePublisher<S>,
    error: PreflightError,
}

impl<'a, S> PreflightFailure<'a, S> {
    pub const fn error(&self) -> PreflightError {
        self.error
    }

    pub const fn ready_next_epoch(&self) -> Option<u64> {
        self.ready.next_epoch()
    }

    pub const fn prior_accumulator(&self) -> u64 {
        self.publisher.prior_accumulator()
    }

    pub fn into_retry(self) -> (TargetReady<'a>, ProfilePublisher<S>, PreflightError) {
        (self.ready, self.publisher, self.error)
    }
}

/// Non-forgeable sink failure carrying the recycled target lineage and the
/// permanently quarantined sink owner.
///
/// ```compile_fail
/// fn forge<'a, S: vibeos_wasm_aot_profile::ProfileRecordSink>(
///     ready: vibeos_wasm_aot_profile::TargetReady<'a>,
///     publisher: vibeos_wasm_aot_profile::PoisonedPublisher<S>,
///     error: S::Error,
/// ) -> vibeos_wasm_aot_profile::SinkFailure<'a, S> {
///     vibeos_wasm_aot_profile::SinkFailure {
///         ready,
///         publisher,
///         error,
///     }
/// }
/// ```
pub struct SinkFailure<'a, S>
where
    S: ProfileRecordSink,
{
    ready: TargetReady<'a>,
    publisher: PoisonedPublisher<S>,
    error: S::Error,
}

impl<'a, S: ProfileRecordSink> SinkFailure<'a, S> {
    pub const fn ready_next_epoch(&self) -> Option<u64> {
        self.ready.next_epoch()
    }

    pub const fn prior_accumulator(&self) -> u64 {
        self.publisher.prior_accumulator()
    }

    pub const fn failed_sample_index(&self) -> u8 {
        self.publisher.failed_sample_index()
    }

    pub fn error(&self) -> &S::Error {
        &self.error
    }

    pub fn into_parts(self) -> (TargetReady<'a>, PoisonedPublisher<S>, S::Error) {
        (self.ready, self.publisher, self.error)
    }
}

pub enum PublishFailure<'a, S>
where
    S: ProfileRecordSink,
{
    Preflight(PreflightFailure<'a, S>),
    Sink(SinkFailure<'a, S>),
}

#[derive(Clone, Copy)]
struct Candidate {
    summary: Summary,
    accumulator: u64,
}

trait ProfileAccess {
    fn profile_summary(&self) -> Summary;
    fn profile_interval(&self, sequence: usize) -> Option<Interval>;
}

impl ProfileAccess for TargetVerified<'_> {
    fn profile_summary(&self) -> Summary {
        self.summary()
    }

    fn profile_interval(&self, sequence: usize) -> Option<Interval> {
        self.interval(sequence)
    }
}

fn preflight_profile<P: ProfileAccess>(
    verified: &P,
    sample_index: u8,
    terminal: &EligibleTerminalEvidence,
    prior_accumulator: u64,
) -> Result<Candidate, PreflightError> {
    if sample_index > MAX_SAMPLE_INDEX {
        return Err(PreflightError::SampleIndexOutOfRange {
            actual: sample_index,
        });
    }

    let summary = verified.profile_summary();
    let total_ticks = summary.total_ticks();
    if total_ticks == 0 {
        return Err(PreflightError::ZeroTotalTicks);
    }
    if summary.interval_capacity() != INTERVAL_CAPACITY {
        return Err(PreflightError::IntervalCapacity {
            actual: summary.interval_capacity(),
        });
    }
    if !summary.intervals_complete() {
        return Err(PreflightError::IntervalsIncomplete);
    }
    let interval_count = summary.interval_count();
    if !(1..=INTERVAL_CAPACITY).contains(&interval_count) {
        return Err(PreflightError::IntervalCountOutOfRange {
            actual: interval_count,
        });
    }
    if interval_count as u64 > total_ticks {
        return Err(PreflightError::IntervalCountExceedsTotal {
            count: interval_count,
            total_ticks,
        });
    }

    let declared_phase_ticks = summary.phase_ticks();
    let Some(declared_total) = declared_phase_ticks.checked_total() else {
        return Err(PreflightError::SummaryPhaseTotalOverflow);
    };
    if declared_total != total_ticks {
        return Err(PreflightError::SummaryPhaseTotalMismatch {
            phase_total: declared_total,
            total_ticks,
        });
    }

    let warmup = sample_index < WARMUP_SAMPLES;
    let mut accumulator = prior_accumulator;
    for word in [
        SAMPLE_DOMAIN_WORD,
        u64::from(sample_index),
        u64::from(sample_index),
        bool_word(warmup),
        total_ticks,
    ] {
        accumulator = fold_word(accumulator, word);
    }
    for phase in Phase::ALL {
        accumulator = fold_word(accumulator, declared_phase_ticks.get(phase));
    }
    for word in [
        summary.interval_capacity() as u64,
        interval_count as u64,
        bool_word(summary.intervals_complete()),
    ] {
        accumulator = fold_word(accumulator, word);
    }

    let mut rescanned = [0_u64; 7];
    let mut previous_end = 0_u64;
    let mut previous_phase = None;
    for sequence in 0..interval_count {
        let Some(interval) = verified.profile_interval(sequence) else {
            return Err(PreflightError::IntervalCountMismatch {
                declared: interval_count,
                observed: sequence,
            });
        };
        if interval.sequence() != sequence {
            return Err(PreflightError::IntervalSequence {
                expected: sequence,
                actual: interval.sequence(),
            });
        }
        if interval.start_offset_ticks() != previous_end {
            return Err(PreflightError::IntervalNotContiguous {
                sequence,
                expected_start: previous_end,
                actual_start: interval.start_offset_ticks(),
            });
        }
        if interval.end_offset_ticks() <= interval.start_offset_ticks() {
            return Err(PreflightError::IntervalNotIncreasing {
                sequence,
                start: interval.start_offset_ticks(),
                end: interval.end_offset_ticks(),
            });
        }
        if interval.end_offset_ticks() > total_ticks {
            return Err(PreflightError::IntervalPastTotal {
                sequence,
                end: interval.end_offset_ticks(),
                total_ticks,
            });
        }
        if previous_phase == Some(interval.phase()) {
            return Err(PreflightError::AdjacentPhase {
                sequence,
                phase: interval.phase(),
            });
        }
        let phase_index = usize::from(interval.phase().code() - 1);
        let duration = interval.end_offset_ticks() - interval.start_offset_ticks();
        let Some(phase_total) = rescanned[phase_index].checked_add(duration) else {
            return Err(PreflightError::PhaseRescanOverflow {
                sequence,
                phase: interval.phase(),
            });
        };
        rescanned[phase_index] = phase_total;

        for word in [
            INTERVAL_DOMAIN_WORD,
            interval.sequence() as u64,
            u64::from(interval.phase().code()),
            interval.start_offset_ticks(),
            interval.end_offset_ticks(),
        ] {
            accumulator = fold_word(accumulator, word);
        }

        previous_end = interval.end_offset_ticks();
        previous_phase = Some(interval.phase());
    }
    if verified.profile_interval(interval_count).is_some() {
        return Err(PreflightError::UnexpectedInterval {
            sequence: interval_count,
        });
    }
    if previous_end != total_ticks {
        return Err(PreflightError::FinalEndpointMismatch {
            endpoint: previous_end,
            total_ticks,
        });
    }
    let rescanned = PhaseTicks {
        validation: rescanned[0],
        instantiation: rescanned[1],
        abi: rescanned[2],
        interpretation: rescanned[3],
        host: rescanned[4],
        wait: rescanned[5],
        cleanup: rescanned[6],
    };
    if rescanned != declared_phase_ticks {
        return Err(PreflightError::PhaseRescanMismatch);
    }

    for word in [
        terminal.read_chunks,
        terminal.write_chunks,
        terminal.fuel_consumed,
        terminal.poll_quanta,
        bool_word(terminal.succeeded),
        terminal.logical_live_after,
        bool_word(terminal.timed_out),
        timeout_phase_word(terminal.timeout_phase),
        u64::from(terminal.exit_status),
        terminal.stdout_bytes,
    ] {
        accumulator = fold_word(accumulator, word);
    }
    for chunk in terminal.stdout_sha256.chunks_exact(8) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        accumulator = fold_word(accumulator, u64::from_be_bytes(bytes));
    }
    accumulator = fold_word(accumulator, terminal.stderr_bytes);

    Ok(Candidate {
        summary,
        accumulator,
    })
}

fn fold_word(accumulator: u64, word: u64) -> u64 {
    accumulator.rotate_left(7).wrapping_add(word)
}

const fn bool_word(value: bool) -> u64 {
    if value {
        1
    } else {
        0
    }
}

const fn timeout_phase_word(phase: Option<Phase>) -> u64 {
    match phase {
        Some(phase) => phase.code() as u64,
        None => 0,
    }
}

fn write_sample<S: ProfileRecordSink>(
    sink: &mut S,
    binding: TranscriptBinding,
    sample_index: u8,
    terminal: &EligibleTerminalEvidence,
    summary: Summary,
    verified: &TargetVerified<'_>,
) -> Result<(), S::Error> {
    sink.write_all(SAMPLE_PREFIX)?;
    sink.write_all(b"{\"challenge\":\"")?;
    write_hex(sink, &binding.challenge().bytes())?;
    sink.write_all(b"\",\"exit_status\":")?;
    write_u64(sink, u64::from(terminal.exit_status))?;
    sink.write_all(b",\"fuel_consumed\":")?;
    write_u64(sink, terminal.fuel_consumed)?;
    sink.write_all(b",\"interval_capacity\":")?;
    write_u64(sink, summary.interval_capacity() as u64)?;
    sink.write_all(b",\"interval_count\":")?;
    write_u64(sink, summary.interval_count() as u64)?;
    sink.write_all(b",\"intervals\":[")?;
    for (position, interval) in verified.intervals().enumerate() {
        if position != 0 {
            sink.write_all(b",")?;
        }
        sink.write_all(b"{\"end_offset_ticks\":")?;
        write_u64(sink, interval.end_offset_ticks())?;
        sink.write_all(b",\"phase\":\"")?;
        sink.write_all(interval.phase().as_str().as_bytes())?;
        sink.write_all(b"\",\"sequence\":")?;
        write_u64(sink, interval.sequence() as u64)?;
        sink.write_all(b",\"start_offset_ticks\":")?;
        write_u64(sink, interval.start_offset_ticks())?;
        sink.write_all(b"}")?;
    }
    sink.write_all(b"],\"intervals_complete\":")?;
    write_bool(sink, summary.intervals_complete())?;
    sink.write_all(b",\"logical_live_after\":")?;
    write_u64(sink, terminal.logical_live_after)?;
    sink.write_all(b",\"phase_ticks\":{\"abi\":")?;
    let phase_ticks = summary.phase_ticks();
    write_u64(sink, phase_ticks.abi)?;
    sink.write_all(b",\"cleanup\":")?;
    write_u64(sink, phase_ticks.cleanup)?;
    sink.write_all(b",\"host\":")?;
    write_u64(sink, phase_ticks.host)?;
    sink.write_all(b",\"instantiation\":")?;
    write_u64(sink, phase_ticks.instantiation)?;
    sink.write_all(b",\"interpretation\":")?;
    write_u64(sink, phase_ticks.interpretation)?;
    sink.write_all(b",\"validation\":")?;
    write_u64(sink, phase_ticks.validation)?;
    sink.write_all(b",\"wait\":")?;
    write_u64(sink, phase_ticks.wait)?;
    sink.write_all(b"},\"poll_quanta\":")?;
    write_u64(sink, terminal.poll_quanta)?;
    sink.write_all(b",\"read_chunks\":")?;
    write_u64(sink, terminal.read_chunks)?;
    sink.write_all(b",\"run_id\":\"")?;
    write_hex(sink, &binding.run_id().bytes())?;
    sink.write_all(b"\",\"sample_index\":")?;
    write_u64(sink, u64::from(sample_index))?;
    sink.write_all(b",\"schema\":\"vibeos.wasm-aot-decision.sample\",\"sequence\":")?;
    write_u64(sink, u64::from(sample_index))?;
    sink.write_all(b",\"stderr_bytes\":")?;
    write_u64(sink, terminal.stderr_bytes)?;
    sink.write_all(b",\"stdout_bytes\":")?;
    write_u64(sink, terminal.stdout_bytes)?;
    sink.write_all(b",\"stdout_sha256\":\"")?;
    write_hex(sink, &terminal.stdout_sha256)?;
    sink.write_all(b"\",\"terminal\":\"")?;
    sink.write_all(if terminal.succeeded {
        b"success"
    } else {
        b"failure"
    })?;
    sink.write_all(b"\",\"timed_out\":")?;
    write_bool(sink, terminal.timed_out)?;
    sink.write_all(b",\"timeout_phase\":\"")?;
    match terminal.timeout_phase {
        Some(phase) => sink.write_all(phase.as_str().as_bytes())?,
        None => sink.write_all(b"none")?,
    }
    sink.write_all(b"\",\"total_ticks\":")?;
    write_u64(sink, summary.total_ticks())?;
    sink.write_all(b",\"version\":1,\"warmup\":")?;
    write_bool(sink, sample_index < WARMUP_SAMPLES)?;
    sink.write_all(b",\"workload_id\":\"ssh-case-filter-12k-v1\",\"write_chunks\":")?;
    write_u64(sink, terminal.write_chunks)?;
    sink.write_all(b"}")?;
    sink.write_all(b"\n")?;
    sink.commit_record()
}

fn write_bool<S: ProfileRecordSink>(sink: &mut S, value: bool) -> Result<(), S::Error> {
    sink.write_all(if value { b"true" } else { b"false" })
}

fn write_hex<S: ProfileRecordSink>(sink: &mut S, bytes: &[u8; 32]) -> Result<(), S::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in bytes.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    sink.write_all(&encoded)
}

fn write_u64<S: ProfileRecordSink>(sink: &mut S, mut value: u64) -> Result<(), S::Error> {
    let mut encoded = [0_u8; 20];
    let mut cursor = encoded.len();
    loop {
        cursor -= 1;
        encoded[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    sink.write_all(&encoded[cursor..])
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{Storage, TargetContext};
    use std::cell::{Cell, RefCell};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;
    use std::vec;
    use std::vec::Vec;

    const KAT_PRIOR_ACCUMULATOR: u64 = 0x0123_4567_89ab_cdef;
    const KAT_PRIOR_RESULT: u64 = 0x0ce2_4a87_0336_63a1;
    const KAT_ZERO_RESULT: u64 = 0x7b3f_96c2_1d6f_6c20;

    fn storage() -> (Vec<u64>, Vec<u8>) {
        (
            vec![u64::MAX; INTERVAL_CAPACITY],
            vec![u8::MAX; INTERVAL_CAPACITY],
        )
    }

    fn ready<'a>(endpoints: &'a mut [u64], phases: &'a mut [u8]) -> TargetReady<'a> {
        TargetReady::new(Storage::new(endpoints, phases).unwrap())
    }

    fn kat_verified_from_ready<'a>(ready: TargetReady<'a>, base: u64) -> TargetVerified<'a> {
        let mut active = match ready.start(TargetContext::CANONICAL, base) {
            Ok(active) => active,
            Err(_) => panic!("KAT target start failed"),
        };
        let token = active.token();
        active.set_phase(
            token,
            TargetContext::CANONICAL,
            base + 1,
            Phase::Instantiation,
        );
        active.set_phase(token, TargetContext::CANONICAL, base + 3, Phase::Abi);
        active.set_phase(
            token,
            TargetContext::CANONICAL,
            base + 6,
            Phase::Interpretation,
        );
        active.set_phase(token, TargetContext::CANONICAL, base + 10, Phase::Host);
        active.set_phase(token, TargetContext::CANONICAL, base + 15, Phase::Wait);
        active.begin_cleanup(token, TargetContext::CANONICAL, base + 21);
        let finished = match active.finish(token, TargetContext::CANONICAL, base + 28) {
            Ok(finished) => finished,
            Err(_) => panic!("KAT facade rejected a clean sample"),
        };
        match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("KAT ledger failed independent verification"),
        }
    }

    fn kat_verified<'a>(endpoints: &'a mut [u64], phases: &'a mut [u8]) -> TargetVerified<'a> {
        kat_verified_from_ready(ready(endpoints, phases), 100)
    }

    fn kat_binding() -> TranscriptBinding {
        let mut run_id = [0_u8; 32];
        let mut challenge = [0_u8; 32];
        for index in 0..32 {
            run_id[index] = index as u8;
            challenge[index] = index as u8 + 32;
        }
        TranscriptBinding::new(
            RunId::new(run_id).unwrap(),
            Challenge::new(challenge).unwrap(),
        )
    }

    fn kat_observation() -> TerminalObservation {
        TerminalObservation {
            read_chunks: FORMAL_READ_CHUNKS,
            write_chunks: FORMAL_WRITE_CHUNKS,
            fuel_consumed: MAX_FORMAL_FUEL,
            poll_quanta: u64::MAX,
            poll_quanta_exact: true,
            succeeded: true,
            logical_live_after: 0,
            timed_out: false,
            timeout_phase: None,
            exit_status: 0,
            stdout_bytes: FORMAL_STDOUT_BYTES,
            stdout_sha256: FORMAL_STDOUT_SHA256,
            stderr_bytes: 0,
        }
    }

    fn kat_evidence() -> EligibleTerminalEvidence {
        EligibleTerminalEvidence::validate(kat_observation()).unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestSinkError {
        Injected(usize),
    }

    struct TestSink {
        bytes: Vec<u8>,
        calls: usize,
        commits: usize,
        fail_at: Option<usize>,
        drops: Rc<Cell<usize>>,
    }

    impl TestSink {
        fn new(fail_at: Option<usize>, drops: Rc<Cell<usize>>) -> Self {
            Self {
                bytes: Vec::new(),
                calls: 0,
                commits: 0,
                fail_at,
                drops,
            }
        }

        fn enter(&mut self) -> Result<(), TestSinkError> {
            let call = self.calls;
            self.calls += 1;
            if self.fail_at == Some(call) {
                Err(TestSinkError::Injected(call))
            } else {
                Ok(())
            }
        }
    }

    impl ProfileRecordSink for TestSink {
        type Error = TestSinkError;

        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.enter()?;
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn commit_record(&mut self) -> Result<(), Self::Error> {
            self.enter()?;
            self.commits += 1;
            Ok(())
        }
    }

    impl Drop for TestSink {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    #[test]
    fn branded_binding_rejects_only_the_respective_zero_identity() {
        assert_eq!(RunId::new([0; 32]), Err(BindingError::ZeroRunId));
        assert_eq!(Challenge::new([0; 32]), Err(BindingError::ZeroChallenge));

        let mut run_id = [0_u8; 32];
        run_id[31] = 1;
        let mut challenge = [0_u8; 32];
        challenge[0] = 1;
        let binding = TranscriptBinding::new(
            RunId::new(run_id).unwrap(),
            Challenge::new(challenge).unwrap(),
        );
        assert_eq!(binding.run_id().bytes(), run_id);
        assert_eq!(binding.challenge().bytes(), challenge);
    }

    #[test]
    fn terminal_evidence_rejects_every_ineligible_field() {
        macro_rules! rejects {
            ($field:ident, $value:expr, $error:expr) => {{
                let mut observation = kat_observation();
                observation.$field = $value;
                assert_eq!(
                    EligibleTerminalEvidence::validate(observation).err(),
                    Some($error)
                );
            }};
        }

        rejects!(read_chunks, 12, TerminalEvidenceError::ReadChunks);
        rejects!(write_chunks, 12, TerminalEvidenceError::WriteChunks);
        rejects!(fuel_consumed, 0, TerminalEvidenceError::FuelOutOfRange);
        rejects!(
            fuel_consumed,
            MAX_FORMAL_FUEL + 1,
            TerminalEvidenceError::FuelOutOfRange
        );
        rejects!(poll_quanta, 0, TerminalEvidenceError::PollQuantaZero);
        rejects!(
            poll_quanta_exact,
            false,
            TerminalEvidenceError::PollQuantaNotExact
        );
        rejects!(succeeded, false, TerminalEvidenceError::NotSuccessful);
        rejects!(
            logical_live_after,
            1,
            TerminalEvidenceError::LogicalStateLive
        );
        rejects!(timed_out, true, TerminalEvidenceError::TimedOut);
        rejects!(
            timeout_phase,
            Some(Phase::Host),
            TerminalEvidenceError::TimeoutPhase
        );
        rejects!(exit_status, 1, TerminalEvidenceError::ExitStatus);
        rejects!(
            stdout_bytes,
            FORMAL_STDOUT_BYTES - 1,
            TerminalEvidenceError::StdoutLength
        );
        let mut observation = kat_observation();
        observation.stdout_sha256[31] ^= 1;
        assert_eq!(
            EligibleTerminalEvidence::validate(observation).err(),
            Some(TerminalEvidenceError::StdoutDigest)
        );
        rejects!(stderr_bytes, 1, TerminalEvidenceError::StderrNotEmpty);

        let evidence = kat_evidence();
        assert_eq!(evidence.fuel_consumed(), MAX_FORMAL_FUEL);
        assert_eq!(evidence.poll_quanta(), u64::MAX);
        assert!(evidence.poll_quanta_is_exact());
    }

    #[test]
    fn exact_accumulator_kat_binds_all_sixty_five_words() {
        let (mut endpoints, mut phases) = storage();
        let verified = kat_verified(&mut endpoints, &mut phases);
        let evidence = kat_evidence();
        assert_eq!(15 + 7 * 5 + 15, 65);
        assert_eq!(
            preflight_profile(&verified, 3, &evidence, KAT_PRIOR_ACCUMULATOR)
                .unwrap()
                .accumulator,
            KAT_PRIOR_RESULT
        );
        assert_eq!(
            preflight_profile(&verified, 3, &evidence, 0)
                .unwrap()
                .accumulator,
            KAT_ZERO_RESULT
        );
    }

    #[test]
    fn every_sink_boundary_fails_closed_without_running_sink_drop() {
        let successful_drops = Rc::new(Cell::new(0));
        let (mut endpoints, mut phases) = storage();
        let published = ProfilePublisher::new(
            TestSink::new(None, successful_drops.clone()),
            kat_binding(),
            KAT_PRIOR_ACCUMULATOR,
        )
        .publish_profile(kat_verified(&mut endpoints, &mut phases), 3, kat_evidence())
        .unwrap_or_else(|_| panic!("counting publication failed"));
        let (_, successful_sink, _, _) = published.into_parts();
        let call_count = successful_sink.calls;
        assert!(call_count > 1);
        drop(successful_sink);
        assert_eq!(successful_drops.get(), 1);

        for fail_at in 0..call_count {
            let drops = Rc::new(Cell::new(0));
            let (mut endpoints, mut phases) = storage();
            let failure = ProfilePublisher::new(
                TestSink::new(Some(fail_at), drops.clone()),
                kat_binding(),
                KAT_PRIOR_ACCUMULATOR,
            )
            .publish_profile(
                kat_verified(&mut endpoints, &mut phases),
                3,
                kat_evidence(),
            );
            let PublishFailure::Sink(failure) = (match failure {
                Ok(_) => panic!("sink boundary {fail_at} unexpectedly succeeded"),
                Err(failure) => failure,
            }) else {
                panic!("sink boundary {fail_at} became a preflight error");
            };
            assert_eq!(failure.ready_next_epoch(), Some(2));
            assert_eq!(failure.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);
            assert_eq!(failure.failed_sample_index(), 3);
            assert_eq!(*failure.error(), TestSinkError::Injected(fail_at));
            let (ready, poisoned, error) = failure.into_parts();
            assert_eq!(ready.next_epoch(), Some(2));
            assert_eq!(poisoned.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);
            assert_eq!(error, TestSinkError::Injected(fail_at));
            drop(poisoned);
            drop(ready);
            assert_eq!(drops.get(), 0, "sink Drop ran at boundary {fail_at}");
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum QuotaError {
        Partial,
        Commit,
    }

    struct ByteQuotaSink {
        bytes: Vec<u8>,
        quota: usize,
        commit_calls: usize,
        fail_commit: bool,
        drops: Rc<Cell<usize>>,
    }

    impl ProfileRecordSink for ByteQuotaSink {
        type Error = QuotaError;

        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            let remaining = self.quota.saturating_sub(self.bytes.len());
            if remaining < bytes.len() {
                self.bytes.extend_from_slice(&bytes[..remaining]);
                return Err(QuotaError::Partial);
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn commit_record(&mut self) -> Result<(), Self::Error> {
            self.commit_calls += 1;
            if self.fail_commit {
                Err(QuotaError::Commit)
            } else {
                Ok(())
            }
        }
    }

    impl Drop for ByteQuotaSink {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    #[test]
    fn every_partial_byte_prefix_and_post_lf_commit_error_are_quarantined() {
        const RECORD_BYTES: usize = 1_392;
        let drops = Rc::new(Cell::new(0));
        let (mut endpoints, mut phases) = storage();
        let mut next_ready = ready(&mut endpoints, &mut phases);

        for quota in 0..RECORD_BYTES {
            let expected_ready_epoch = next_ready.next_epoch().unwrap() + 1;
            let result = ProfilePublisher::new(
                ByteQuotaSink {
                    bytes: Vec::new(),
                    quota,
                    commit_calls: 0,
                    fail_commit: false,
                    drops: drops.clone(),
                },
                kat_binding(),
                KAT_PRIOR_ACCUMULATOR,
            )
            .publish_profile(
                kat_verified_from_ready(next_ready, 1_000 + quota as u64 * 100),
                3,
                kat_evidence(),
            );
            let PublishFailure::Sink(failure) = (match result {
                Ok(_) => panic!("byte quota {quota} unexpectedly published"),
                Err(failure) => failure,
            }) else {
                panic!("byte quota {quota} became a preflight failure");
            };
            assert_eq!(failure.ready_next_epoch(), Some(expected_ready_epoch));
            assert_eq!(failure.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);
            assert_eq!(*failure.error(), QuotaError::Partial);
            assert_eq!(failure.publisher._sink.bytes.len(), quota);
            assert_eq!(failure.publisher._sink.commit_calls, 0);
            let (ready, poisoned, _) = failure.into_parts();
            drop(poisoned);
            assert_eq!(drops.get(), 0, "partial sink Drop ran at byte {quota}");
            next_ready = ready;
        }

        let expected_ready_epoch = next_ready.next_epoch().unwrap() + 1;
        let result = ProfilePublisher::new(
            ByteQuotaSink {
                bytes: Vec::new(),
                quota: RECORD_BYTES,
                commit_calls: 0,
                fail_commit: true,
                drops: drops.clone(),
            },
            kat_binding(),
            KAT_PRIOR_ACCUMULATOR,
        )
        .publish_profile(
            kat_verified_from_ready(next_ready, 200_000),
            3,
            kat_evidence(),
        );
        let PublishFailure::Sink(failure) = (match result {
            Ok(_) => panic!("commit failure unexpectedly published"),
            Err(failure) => failure,
        }) else {
            panic!("commit failure became a preflight failure");
        };
        assert_eq!(failure.ready_next_epoch(), Some(expected_ready_epoch));
        assert_eq!(failure.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);
        assert_eq!(*failure.error(), QuotaError::Commit);
        assert_eq!(failure.publisher._sink.bytes.len(), RECORD_BYTES);
        assert_eq!(failure.publisher._sink.bytes.last(), Some(&b'\n'));
        assert_eq!(failure.publisher._sink.commit_calls, 1);
        let (ready, poisoned, _) = failure.into_parts();
        drop(poisoned);
        drop(ready);
        assert_eq!(drops.get(), 0);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AuditMode {
        PartialError,
        CommitError,
        WritePanic,
        CommitPanic,
    }

    #[derive(Default)]
    struct SinkAudit {
        bytes: RefCell<Vec<u8>>,
        write_calls: Cell<usize>,
        commit_calls: Cell<usize>,
        drops: Cell<usize>,
    }

    struct AuditedSink {
        audit: Rc<SinkAudit>,
        mode: AuditMode,
    }

    impl ProfileRecordSink for AuditedSink {
        type Error = QuotaError;

        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.audit.write_calls.set(self.audit.write_calls.get() + 1);
            match self.mode {
                AuditMode::PartialError => {
                    self.audit.bytes.borrow_mut().push(bytes[0]);
                    Err(QuotaError::Partial)
                }
                AuditMode::WritePanic => {
                    self.audit.bytes.borrow_mut().push(bytes[0]);
                    panic!("injected write panic after a one-byte side effect")
                }
                AuditMode::CommitError | AuditMode::CommitPanic => {
                    self.audit.bytes.borrow_mut().extend_from_slice(bytes);
                    Ok(())
                }
            }
        }

        fn commit_record(&mut self) -> Result<(), Self::Error> {
            self.audit
                .commit_calls
                .set(self.audit.commit_calls.get() + 1);
            match self.mode {
                AuditMode::CommitError => Err(QuotaError::Commit),
                AuditMode::CommitPanic => {
                    panic!("injected commit panic after the complete record")
                }
                AuditMode::PartialError | AuditMode::WritePanic => {
                    panic!("commit reached after a failed write")
                }
            }
        }
    }

    impl Drop for AuditedSink {
        fn drop(&mut self) {
            self.audit.drops.set(self.audit.drops.get() + 1);
        }
    }

    #[test]
    fn shared_audit_observes_partial_error_and_stops_before_commit() {
        let audit = Rc::new(SinkAudit::default());
        let (mut endpoints, mut phases) = storage();
        let failure = ProfilePublisher::new(
            AuditedSink {
                audit: audit.clone(),
                mode: AuditMode::PartialError,
            },
            kat_binding(),
            KAT_PRIOR_ACCUMULATOR,
        )
        .publish_profile(kat_verified(&mut endpoints, &mut phases), 3, kat_evidence());
        let PublishFailure::Sink(failure) = (match failure {
            Ok(_) => panic!("partial sink error unexpectedly published"),
            Err(failure) => failure,
        }) else {
            panic!("partial sink error became a preflight failure");
        };
        assert_eq!(failure.ready_next_epoch(), Some(2));
        assert_eq!(failure.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);
        assert_eq!(*failure.error(), QuotaError::Partial);
        assert_eq!(audit.bytes.borrow().as_slice(), b"V");
        assert_eq!(audit.write_calls.get(), 1);
        assert_eq!(audit.commit_calls.get(), 0);
        let (ready, poisoned, _) = failure.into_parts();
        drop(poisoned);
        drop(ready);
        assert_eq!(audit.drops.get(), 0);
    }

    #[test]
    fn shared_audit_observes_full_record_before_commit_error() {
        const KAT_RECORD: &[u8] = include_bytes!("../tests/fixtures/publisher-sample-v1.jsonl");
        let audit = Rc::new(SinkAudit::default());
        let (mut endpoints, mut phases) = storage();
        let failure = ProfilePublisher::new(
            AuditedSink {
                audit: audit.clone(),
                mode: AuditMode::CommitError,
            },
            kat_binding(),
            KAT_PRIOR_ACCUMULATOR,
        )
        .publish_profile(kat_verified(&mut endpoints, &mut phases), 3, kat_evidence());
        let PublishFailure::Sink(failure) = (match failure {
            Ok(_) => panic!("commit error unexpectedly published"),
            Err(failure) => failure,
        }) else {
            panic!("commit error became a preflight failure");
        };
        assert_eq!(failure.ready_next_epoch(), Some(2));
        assert_eq!(failure.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);
        assert_eq!(*failure.error(), QuotaError::Commit);
        assert_eq!(audit.bytes.borrow().as_slice(), KAT_RECORD);
        assert!(audit.write_calls.get() > 1);
        assert_eq!(audit.commit_calls.get(), 1);
        let (ready, poisoned, _) = failure.into_parts();
        drop(poisoned);
        drop(ready);
        assert_eq!(audit.drops.get(), 0);
    }

    #[test]
    fn sink_write_and_commit_panics_retain_the_quarantined_resource() {
        const KAT_RECORD: &[u8] = include_bytes!("../tests/fixtures/publisher-sample-v1.jsonl");

        let write_audit = Rc::new(SinkAudit::default());
        let (mut endpoints, mut phases) = storage();
        let write_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = ProfilePublisher::new(
                AuditedSink {
                    audit: write_audit.clone(),
                    mode: AuditMode::WritePanic,
                },
                kat_binding(),
                KAT_PRIOR_ACCUMULATOR,
            )
            .publish_profile(
                kat_verified(&mut endpoints, &mut phases),
                3,
                kat_evidence(),
            );
        }));
        assert!(write_result.is_err());
        assert_eq!(write_audit.bytes.borrow().as_slice(), b"V");
        assert_eq!(write_audit.write_calls.get(), 1);
        assert_eq!(write_audit.commit_calls.get(), 0);
        assert_eq!(write_audit.drops.get(), 0);
        assert!(endpoints.iter().all(|value| *value == 0));
        assert!(phases.iter().all(|value| *value == 0));

        let commit_audit = Rc::new(SinkAudit::default());
        let (mut endpoints, mut phases) = storage();
        let commit_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = ProfilePublisher::new(
                AuditedSink {
                    audit: commit_audit.clone(),
                    mode: AuditMode::CommitPanic,
                },
                kat_binding(),
                KAT_PRIOR_ACCUMULATOR,
            )
            .publish_profile(
                kat_verified(&mut endpoints, &mut phases),
                3,
                kat_evidence(),
            );
        }));
        assert!(commit_result.is_err());
        assert_eq!(commit_audit.bytes.borrow().as_slice(), KAT_RECORD);
        assert!(commit_audit.write_calls.get() > 1);
        assert_eq!(commit_audit.commit_calls.get(), 1);
        assert_eq!(commit_audit.drops.get(), 0);
        assert!(endpoints.iter().all(|value| *value == 0));
        assert!(phases.iter().all(|value| *value == 0));
    }

    #[test]
    fn sample_index_preflight_is_zero_write_and_retryable() {
        let drops = Rc::new(Cell::new(0));
        let (mut endpoints, mut phases) = storage();
        let result = ProfilePublisher::new(
            TestSink::new(None, drops.clone()),
            kat_binding(),
            KAT_PRIOR_ACCUMULATOR,
        )
        .publish_profile(
            kat_verified(&mut endpoints, &mut phases),
            24,
            kat_evidence(),
        );
        let PublishFailure::Preflight(failure) = (match result {
            Ok(_) => panic!("out-of-range sample index published"),
            Err(failure) => failure,
        }) else {
            panic!("out-of-range sample index touched the sink");
        };
        assert_eq!(
            failure.error(),
            PreflightError::SampleIndexOutOfRange { actual: 24 }
        );
        assert_eq!(failure.ready_next_epoch(), Some(2));
        let (ready, publisher, _) = failure.into_retry();
        assert_eq!(publisher.sink.calls, 0);
        assert_eq!(publisher.prior_accumulator(), KAT_PRIOR_ACCUMULATOR);

        let published = publisher
            .publish_profile(kat_verified_from_ready(ready, 200), 3, kat_evidence())
            .unwrap_or_else(|_| panic!("retry after zero-write preflight failed"));
        let (ready, sink, _, accumulator) = published.into_parts();
        assert_eq!(ready.next_epoch(), Some(3));
        assert_eq!(accumulator, KAT_PRIOR_RESULT);
        assert_eq!(sink.commits, 1);
        drop(sink);
        drop(ready);
        assert_eq!(drops.get(), 1);
    }

    struct FakeProfile {
        summary: Summary,
        intervals: Vec<Interval>,
    }

    impl ProfileAccess for FakeProfile {
        fn profile_summary(&self) -> Summary {
            self.summary
        }

        fn profile_interval(&self, sequence: usize) -> Option<Interval> {
            self.intervals.get(sequence).copied()
        }
    }

    fn valid_fake_profile() -> FakeProfile {
        let phases = Phase::ALL;
        let mut intervals = Vec::new();
        let mut start = 0_u64;
        for (sequence, phase) in phases.into_iter().enumerate() {
            let end = start + sequence as u64 + 1;
            intervals.push(Interval {
                sequence,
                phase,
                start_offset_ticks: start,
                end_offset_ticks: end,
            });
            start = end;
        }
        FakeProfile {
            summary: Summary {
                start_tick: 100,
                end_tick: 128,
                total_ticks: 28,
                phase_ticks: PhaseTicks {
                    validation: 1,
                    instantiation: 2,
                    abi: 3,
                    interpretation: 4,
                    host: 5,
                    wait: 6,
                    cleanup: 7,
                },
                interval_capacity: INTERVAL_CAPACITY,
                interval_count: 7,
                intervals_complete: true,
            },
            intervals,
        }
    }

    fn fake_error(profile: &FakeProfile) -> PreflightError {
        match preflight_profile(profile, 3, &kat_evidence(), KAT_PRIOR_ACCUMULATOR) {
            Ok(_) => panic!("mutated fake profile passed preflight"),
            Err(error) => error,
        }
    }

    #[test]
    fn preflight_rejects_relational_profile_mutations_before_serialization() {
        let mut profile = valid_fake_profile();
        profile.summary.total_ticks = 0;
        assert_eq!(fake_error(&profile), PreflightError::ZeroTotalTicks);

        let mut profile = valid_fake_profile();
        profile.summary.interval_capacity -= 1;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalCapacity { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.summary.intervals_complete = false;
        assert_eq!(fake_error(&profile), PreflightError::IntervalsIncomplete);

        let mut profile = valid_fake_profile();
        profile.summary.interval_count = 0;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalCountOutOfRange { actual: 0 }
        ));

        let mut profile = valid_fake_profile();
        profile.summary.interval_count = INTERVAL_CAPACITY + 1;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalCountOutOfRange { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.summary.total_ticks = 6;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalCountExceedsTotal { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.summary.phase_ticks.validation = u64::MAX;
        assert_eq!(
            fake_error(&profile),
            PreflightError::SummaryPhaseTotalOverflow
        );

        let mut profile = valid_fake_profile();
        profile.summary.phase_ticks.validation = 2;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::SummaryPhaseTotalMismatch { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals.pop();
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalCountMismatch {
                declared: 7,
                observed: 6
            }
        ));

        let mut profile = valid_fake_profile();
        profile.summary.interval_count = 6;
        assert_eq!(
            fake_error(&profile),
            PreflightError::UnexpectedInterval { sequence: 6 }
        );

        let mut profile = valid_fake_profile();
        profile.intervals[1].sequence = 2;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalSequence { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals[1].start_offset_ticks = 2;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalNotContiguous { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals[1].end_offset_ticks = 1;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalNotIncreasing { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals[6].end_offset_ticks = 29;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::IntervalPastTotal { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals[1].phase = Phase::Validation;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::AdjacentPhase { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals[6].end_offset_ticks = 27;
        assert!(matches!(
            fake_error(&profile),
            PreflightError::FinalEndpointMismatch { .. }
        ));

        let mut profile = valid_fake_profile();
        profile.intervals[0].phase = Phase::Host;
        assert_eq!(fake_error(&profile), PreflightError::PhaseRescanMismatch);
    }

    #[test]
    fn publisher_does_not_require_all_phases_or_freeze_first_and_last_interval() {
        let (mut endpoints, mut phases) = storage();
        let ready = ready(&mut endpoints, &mut phases);
        let mut active = match ready.start(TargetContext::CANONICAL, 100) {
            Ok(active) => active,
            Err(_) => panic!("minimal target start failed"),
        };
        let token = active.token();
        active.set_phase(token, TargetContext::CANONICAL, 100, Phase::Host);
        active.begin_cleanup(token, TargetContext::CANONICAL, 110);
        let finished = match active.finish(token, TargetContext::CANONICAL, 110) {
            Ok(finished) => finished,
            Err(_) => panic!("minimal facade sample rejected"),
        };
        let verified = match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("minimal ledger sample rejected"),
        };
        assert_eq!(verified.summary().interval_count(), 1);
        assert_eq!(verified.interval(0).unwrap().phase(), Phase::Host);

        let drops = Rc::new(Cell::new(0));
        let published = ProfilePublisher::new(TestSink::new(None, drops.clone()), kat_binding(), 0)
            .publish_profile(verified, 0, kat_evidence())
            .unwrap_or_else(|_| panic!("minimal valid profile failed publication"));
        let (_, sink, _, _) = published.into_parts();
        let text = std::str::from_utf8(&sink.bytes).unwrap();
        assert!(text.contains("\"interval_count\":1"));
        assert!(text.contains("\"phase\":\"host\""));
        assert!(text.contains("\"warmup\":true"));
    }

    struct CountingSink {
        bytes: u64,
        commits: usize,
    }

    impl ProfileRecordSink for CountingSink {
        type Error = ();

        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.bytes = self.bytes.checked_add(bytes.len() as u64).ok_or(())?;
            Ok(())
        }

        fn commit_record(&mut self) -> Result<(), Self::Error> {
            self.commits += 1;
            Ok(())
        }
    }

    #[test]
    fn full_capacity_profile_scans_twice_and_streams_without_record_storage() {
        let (mut endpoints, mut phases) = storage();
        let mut active = match ready(&mut endpoints, &mut phases).start(TargetContext::CANONICAL, 0)
        {
            Ok(active) => active,
            Err(_) => panic!("full-capacity target start failed"),
        };
        let token = active.token();
        for tick in 1..=(INTERVAL_CAPACITY as u64 - 2) {
            active.set_phase(
                token,
                TargetContext::CANONICAL,
                tick,
                if tick & 1 == 0 {
                    Phase::Abi
                } else {
                    Phase::Host
                },
            );
        }
        active.begin_cleanup(
            token,
            TargetContext::CANONICAL,
            INTERVAL_CAPACITY as u64 - 1,
        );
        let finished =
            match active.finish(token, TargetContext::CANONICAL, INTERVAL_CAPACITY as u64) {
                Ok(finished) => finished,
                Err(_) => panic!("full-capacity facade sample failed"),
            };
        let verified = match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("full-capacity ledger verification failed"),
        };
        assert_eq!(verified.summary().interval_count(), INTERVAL_CAPACITY);

        let published = ProfilePublisher::new(
            CountingSink {
                bytes: 0,
                commits: 0,
            },
            kat_binding(),
            0,
        )
        .publish_profile(verified, 0, kat_evidence())
        .unwrap_or_else(|_| panic!("full-capacity profile failed publication"));
        let (ready, sink, _, accumulator) = published.into_parts();
        assert_eq!(ready.next_epoch(), Some(2));
        assert_eq!(sink.commits, 1);
        assert_eq!(sink.bytes, 5_570_866);
        assert_eq!(accumulator, 0x14a2_4874_780b_11d9);
    }
}
