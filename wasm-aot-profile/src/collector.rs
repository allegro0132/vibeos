//! Private, allocation-free closure of one frozen physical-Duo C8.4 boot.
//!
//! This module deliberately serializes only the decision-eligible physical
//! schema. A QEMU adapter may drive the same state machine through an absorbing
//! audit factory, but must never forward these formal bytes to its UART.

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;

use sha2::{Digest, Sha256};

use crate::{
    BindingError, Challenge, EligibleTerminalEvidence, PreflightError, ProfilePublisher,
    ProfileRecordSink, PublishFailure, RunId, TargetReady, TargetVerified, TranscriptBinding,
};

/// Exact number of formal samples in one cold-boot transcript.
pub const BOOT_SAMPLES: u8 = 24;
/// Exact discarded prefix in one cold-boot transcript.
pub const BOOT_WARMUPS: u8 = 3;
/// Exact retained population in one cold-boot transcript.
pub const BOOT_RETAINED: usize = 21;

const META_PREFIX: &[u8] = b"VIBE_WASM_AOT_META ";
const END_PREFIX: &[u8] = b"VIBE_WASM_AOT_END ";
const RUN_ID_DOMAIN: &[u8] = b"vibeos.c84.aot-decision.run-id.v1";
const MANIFEST_SHA256: &str = "87026895f2207d85a04f5c04f11420530f1c8f922391f71915f173b18dcfd9d8";
const TRANSCRIPT_SCHEMA_SHA256: &str =
    "b608aa3de46aac1a73fb321babdcd4ad18ec43c60b54760f53b9e5e8d317bf3a";
const ARTIFACT_SHA256: &str = "180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72";
const INPUT_SHA256: &str = "6b6054d492e00e68a93bc9b657a69577c7c44f5a48f169adb4124df0a50f6b3c";
const OUTPUT_SHA256: &str = "791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27";

/// Factory for one exclusive, initially empty formal-record sink.
///
/// A record is deliberately an owned associated type rather than a borrow of
/// the factory. This lets the collector permanently leak a possibly partial
/// record without creating a self-referential poison value. A successful
/// `commit_record` must release every transient resource needed for record
/// atomicity and make forgetting the record safe. The collector never runs a
/// record destructor, even after success, because a destructor must not append
/// bytes beyond the unique line feed written by the serializer.
pub trait ProfileRecordSinkFactory {
    type Error;
    type Record: ProfileRecordSink<Error = Self::Error>;

    fn begin_record(&mut self) -> Result<Self::Record, Self::Error>;
}

/// Failure to bind the frozen campaign to canonical build inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CampaignError {
    MissingSourceCommit,
    MissingChallenge,
    InvalidSourceCommit,
    InvalidChallenge,
    ZeroSourceCommit,
    ZeroChallenge,
    ZeroRunId,
}

/// Build-bound identity shared by the three later physical cold boots.
///
/// The only public constructor reads `VIBEOS_C84_SOURCE_COMMIT` and
/// `VIBEOS_C84_CHALLENGE` through `option_env!`. It independently derives the
/// frozen run id and provides no raw identity constructor. This value binds
/// record bytes; it does not attest a board or prove that a power cycle
/// occurred.
///
/// ```compile_fail
/// let _ = vibeos_wasm_aot_profile::Campaign::new([0; 20], [0; 32]);
/// ```
pub struct Campaign {
    source_commit: [u8; 20],
    binding: TranscriptBinding,
}

impl Campaign {
    /// Loads and validates the identities compiled into this crate.
    pub fn from_bound_build() -> Result<Self, CampaignError> {
        let source_commit =
            option_env!("VIBEOS_C84_SOURCE_COMMIT").ok_or(CampaignError::MissingSourceCommit)?;
        let challenge =
            option_env!("VIBEOS_C84_CHALLENGE").ok_or(CampaignError::MissingChallenge)?;
        Self::from_values(source_commit, challenge)
    }

    fn from_values(source_commit: &str, challenge_text: &str) -> Result<Self, CampaignError> {
        let source_commit_bytes =
            decode_hex::<20>(source_commit).ok_or(CampaignError::InvalidSourceCommit)?;
        if source_commit_bytes.iter().all(|byte| *byte == 0) {
            return Err(CampaignError::ZeroSourceCommit);
        }
        let challenge_bytes =
            decode_hex::<32>(challenge_text).ok_or(CampaignError::InvalidChallenge)?;
        let challenge = Challenge::new(challenge_bytes).map_err(|error| match error {
            BindingError::ZeroChallenge => CampaignError::ZeroChallenge,
            BindingError::ZeroRunId => CampaignError::InvalidChallenge,
        })?;

        let mut run_id = Sha256::new();
        run_id.update(RUN_ID_DOMAIN);
        for field in [
            source_commit,
            challenge_text,
            ARTIFACT_SHA256,
            INPUT_SHA256,
            OUTPUT_SHA256,
            MANIFEST_SHA256,
            TRANSCRIPT_SCHEMA_SHA256,
        ] {
            run_id.update(b"\0");
            run_id.update(field.as_bytes());
        }
        let run_id = RunId::new(run_id.finalize().into()).map_err(|error| match error {
            BindingError::ZeroRunId => CampaignError::ZeroRunId,
            BindingError::ZeroChallenge => CampaignError::InvalidChallenge,
        })?;

        Ok(Self {
            source_commit: source_commit_bytes,
            binding: TranscriptBinding::new(run_id, challenge),
        })
    }

    /// Commits the unique META record and seals the factory into a private
    /// 24-sample chain.
    pub fn begin<'a, F: ProfileRecordSinkFactory>(
        self,
        factory: F,
        ready: TargetReady<'a>,
    ) -> Result<CollectorReady<'a, F>, PoisonedTranscript<'a, F>> {
        let mut factory = ManuallyDrop::new(factory);
        let Some(first_epoch) = ready.next_epoch() else {
            return Err(PoisonedTranscript::new(
                ready,
                factory,
                RecordStage::Meta,
                0,
                CollectionFailure::Fault(CollectorFault::EpochUnavailable),
            ));
        };
        let last_epoch_delta = u64::from(BOOT_SAMPLES - 1);
        if first_epoch > u64::MAX - last_epoch_delta {
            return Err(PoisonedTranscript::new(
                ready,
                factory,
                RecordStage::Meta,
                0,
                CollectionFailure::Fault(CollectorFault::EpochBudget { first_epoch }),
            ));
        }

        let record = match (&mut *factory).begin_record() {
            Ok(record) => record,
            Err(error) => {
                return Err(PoisonedTranscript::new(
                    ready,
                    factory,
                    RecordStage::Meta,
                    0,
                    CollectionFailure::Record(error),
                ));
            }
        };
        let mut record = ManuallyDrop::new(record);
        let result = write_meta(&mut *record, &self).and_then(|()| record.commit_record());
        if let Err(error) = result {
            return Err(PoisonedTranscript::new(
                ready,
                factory,
                RecordStage::Meta,
                0,
                CollectionFailure::Record(error),
            ));
        }

        Ok(CollectorReady {
            ready: Some(ready),
            collector: Some(BootCollector {
                factory,
                campaign: self,
                next_sample: 0,
                expected_epoch: first_epoch,
                accumulator: 0,
                retained_ticks: [0; BOOT_RETAINED],
                retained_count: 0,
                not_sync: PhantomData,
            }),
        })
    }
}

/// Stage whose formal record could not be completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordStage {
    Meta,
    Sample(u8),
    End,
}

/// Explicit non-sink reason for permanently ending one boot campaign.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorAbort {
    TerminalRejected,
    TargetRejected,
    OwnerMismatch,
}

/// Fail-closed collector invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorFault {
    EpochUnavailable,
    EpochBudget {
        first_epoch: u64,
    },
    EpochMismatch {
        expected: u64,
        actual: u64,
    },
    RecycledEpochMismatch {
        expected: Option<u64>,
        actual: Option<u64>,
    },
    PublisherPreflight(PreflightError),
    TerminalRejected,
    TargetRejected,
    OwnerMismatch,
    RetainedCount {
        actual: u8,
    },
    Stability {
        p50: u64,
        p95: u64,
    },
    InternalInvariant,
}

/// Diagnostic cause retained without returning the record factory.
#[derive(Debug, Eq, PartialEq)]
pub enum CollectionFailure<E> {
    Fault(CollectorFault),
    Record(E),
}

/// Private, linear state after META and before END.
///
/// The collector is neither `Clone` nor `Copy`. It is `Send` when its factory
/// is `Send`, allowing a kernel slot to retain it between separately spawned
/// SSH requests, but the `Cell` marker makes it unconditionally non-`Sync`.
/// It exposes no sample-index, accumulator, factory, or early-finish setter.
///
/// ```compile_fail
/// use vibeos_wasm_aot_profile::{BootCollector, ProfileRecordSink, ProfileRecordSinkFactory};
/// struct Record;
/// impl ProfileRecordSink for Record {
///     type Error = ();
///     fn write_all(&mut self, _: &[u8]) -> Result<(), ()> { Ok(()) }
///     fn commit_record(&mut self) -> Result<(), ()> { Ok(()) }
/// }
/// struct Factory;
/// impl ProfileRecordSinkFactory for Factory {
///     type Error = ();
///     type Record = Record;
///     fn begin_record(&mut self) -> Result<Record, ()> { Ok(Record) }
/// }
/// fn require_sync<T: Sync>() {}
/// require_sync::<BootCollector<Factory>>();
/// ```
///
/// ```compile_fail
/// fn duplicate<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     collector: vibeos_wasm_aot_profile::BootCollector<F>,
/// ) {
///     let _ = collector.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn recover<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     collector: vibeos_wasm_aot_profile::BootCollector<F>,
/// ) {
///     let _ = collector.sink();
/// }
/// ```
///
/// ```compile_fail
/// fn close_early<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     collector: vibeos_wasm_aot_profile::BootCollector<F>,
/// ) {
///     collector.finish();
/// }
/// ```
///
/// ```compile_fail
/// fn rewrite_index<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     collector: &mut vibeos_wasm_aot_profile::BootCollector<F>,
/// ) {
///     collector.set_sample_index(23);
/// }
/// ```
///
/// ```compile_fail
/// fn rewrite_accumulator<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     collector: &mut vibeos_wasm_aot_profile::BootCollector<F>,
/// ) {
///     collector.set_accumulator(0);
/// }
/// ```
#[must_use = "dropping a live collector permanently leaves the transcript without END"]
pub struct BootCollector<F: ProfileRecordSinkFactory> {
    factory: ManuallyDrop<F>,
    campaign: Campaign,
    next_sample: u8,
    expected_epoch: u64,
    accumulator: u64,
    retained_ticks: [u64; BOOT_RETAINED],
    retained_count: u8,
    not_sync: PhantomData<Cell<()>>,
}

impl<F: ProfileRecordSinkFactory> BootCollector<F> {
    /// Publishes the next internally numbered SAMPLE. Sample 23 immediately
    /// checks retained stability and, only on success, commits END.
    pub fn collect<'a>(
        mut self,
        verified: TargetVerified<'a>,
        terminal: EligibleTerminalEvidence,
    ) -> Result<CollectionProgress<'a, F>, PoisonedTranscript<'a, F>> {
        let sample_index = self.next_sample;
        let committed_before = 1 + sample_index;
        let committed_after = committed_before + 1;
        if self.next_sample >= BOOT_SAMPLES {
            let ready = verified.recycle();
            let stage = RecordStage::End;
            return Err(self.poison(
                ready,
                stage,
                committed_before,
                CollectionFailure::Fault(CollectorFault::InternalInvariant),
            ));
        }

        let actual_epoch = verified.token().epoch();
        if actual_epoch != self.expected_epoch {
            let ready = verified.recycle();
            let expected = self.expected_epoch;
            let stage = RecordStage::Sample(sample_index);
            return Err(self.poison(
                ready,
                stage,
                committed_before,
                CollectionFailure::Fault(CollectorFault::EpochMismatch {
                    expected,
                    actual: actual_epoch,
                }),
            ));
        }

        let total_ticks = verified.summary().total_ticks();
        let record = match (&mut *self.factory).begin_record() {
            Ok(record) => record,
            Err(error) => {
                let ready = verified.recycle();
                let stage = RecordStage::Sample(sample_index);
                return Err(self.poison(
                    ready,
                    stage,
                    committed_before,
                    CollectionFailure::Record(error),
                ));
            }
        };
        let publisher = ProfilePublisher::new(record, self.campaign.binding, self.accumulator);
        let published = publisher.publish_profile(verified, self.next_sample, terminal);
        let (ready, binding, accumulator) = match published {
            Ok(published) => {
                let (ready, record, binding, accumulator) = published.into_parts();
                // commit_record already ended the atomic record. Never run a
                // destructor that could append bytes after its sole LF.
                let _record = ManuallyDrop::new(record);
                (ready, binding, accumulator)
            }
            Err(PublishFailure::Preflight(failure)) => {
                let (ready, publisher, error) = failure.into_retry();
                // Preflight performed no sink calls, but META and earlier
                // samples already committed. The acquired record and factory
                // are therefore still permanently quarantined.
                let _publisher = ManuallyDrop::new(publisher);
                let stage = RecordStage::Sample(sample_index);
                return Err(self.poison(
                    ready,
                    stage,
                    committed_before,
                    CollectionFailure::Fault(CollectorFault::PublisherPreflight(error)),
                ));
            }
            Err(PublishFailure::Sink(failure)) => {
                let (ready, poisoned, error) = failure.into_parts();
                // PoisonedPublisher already owns its record in ManuallyDrop.
                drop(poisoned);
                let stage = RecordStage::Sample(sample_index);
                return Err(self.poison(
                    ready,
                    stage,
                    committed_before,
                    CollectionFailure::Record(error),
                ));
            }
        };

        let expected_next_epoch = self.expected_epoch.checked_add(1);
        if ready.next_epoch() != expected_next_epoch || binding != self.campaign.binding {
            let actual = ready.next_epoch();
            let stage = RecordStage::Sample(sample_index);
            return Err(self.poison(
                ready,
                stage,
                committed_after,
                CollectionFailure::Fault(CollectorFault::RecycledEpochMismatch {
                    expected: expected_next_epoch,
                    actual,
                }),
            ));
        }

        if self.next_sample >= BOOT_WARMUPS {
            let retained_index = usize::from(self.retained_count);
            if retained_index >= BOOT_RETAINED {
                let actual = self.retained_count;
                let stage = RecordStage::Sample(sample_index);
                return Err(self.poison(
                    ready,
                    stage,
                    committed_after,
                    CollectionFailure::Fault(CollectorFault::RetainedCount { actual }),
                ));
            }
            self.retained_ticks[retained_index] = total_ticks;
            self.retained_count += 1;
        }
        self.accumulator = accumulator;
        self.next_sample += 1;
        self.expected_epoch = expected_next_epoch.unwrap_or(u64::MAX);

        if self.next_sample < BOOT_SAMPLES {
            return Ok(CollectionProgress::More(CollectorReady {
                ready: Some(ready),
                collector: Some(self),
            }));
        }

        if usize::from(self.retained_count) != BOOT_RETAINED {
            let actual = self.retained_count;
            return Err(self.poison(
                ready,
                RecordStage::End,
                committed_after,
                CollectionFailure::Fault(CollectorFault::RetainedCount { actual }),
            ));
        }
        let (p50, p95) = retained_percentiles(self.retained_ticks);
        if u128::from(p95) * 100 > u128::from(p50) * 150 {
            return Err(self.poison(
                ready,
                RecordStage::End,
                committed_after,
                CollectionFailure::Fault(CollectorFault::Stability { p50, p95 }),
            ));
        }

        let end_record = match (&mut *self.factory).begin_record() {
            Ok(record) => record,
            Err(error) => {
                return Err(self.poison(
                    ready,
                    RecordStage::End,
                    committed_after,
                    CollectionFailure::Record(error),
                ));
            }
        };
        let mut end_record = ManuallyDrop::new(end_record);
        let result = write_end(&mut *end_record, self.campaign.binding, self.accumulator)
            .and_then(|()| end_record.commit_record());
        if let Err(error) = result {
            return Err(self.poison(
                ready,
                RecordStage::End,
                committed_after,
                CollectionFailure::Record(error),
            ));
        }

        let receipt = BootReceipt {
            samples: BOOT_SAMPLES,
            warmups: BOOT_WARMUPS,
            retained: BOOT_RETAINED as u8,
            accumulator: self.accumulator,
            retained_p50: p50,
            retained_p95: p95,
        };
        Ok(CollectionProgress::Complete(CompletedTranscript {
            ready: Some(ready),
            factory: self.factory,
            receipt,
        }))
    }

    /// Permanently terminates a campaign after the target attempt was already
    /// consumed and recycled without producing eligible terminal evidence.
    pub fn quarantine_attempt<'a>(
        self,
        ready: TargetReady<'a>,
        reason: CollectorAbort,
    ) -> PoisonedTranscript<'a, F> {
        let expected = self.expected_epoch.checked_add(1);
        let actual = ready.next_epoch();
        let fault = if actual != expected {
            CollectorFault::RecycledEpochMismatch { expected, actual }
        } else {
            match reason {
                CollectorAbort::TerminalRejected => CollectorFault::TerminalRejected,
                CollectorAbort::TargetRejected => CollectorFault::TargetRejected,
                CollectorAbort::OwnerMismatch => CollectorFault::OwnerMismatch,
            }
        };
        let stage = RecordStage::Sample(self.next_sample);
        let committed_records = 1 + self.next_sample;
        self.poison(
            ready,
            stage,
            committed_records,
            CollectionFailure::Fault(fault),
        )
    }

    fn poison<'a>(
        self,
        ready: TargetReady<'a>,
        stage: RecordStage,
        committed_records: u8,
        failure: CollectionFailure<F::Error>,
    ) -> PoisonedTranscript<'a, F> {
        PoisonedTranscript::new(ready, self.factory, stage, committed_records, failure)
    }
}

/// Transient pair returned after META or SAMPLE commit.
#[must_use = "the target Ready and collector must be installed exactly once"]
pub struct CollectorReady<'a, F: ProfileRecordSinkFactory> {
    ready: Option<TargetReady<'a>>,
    collector: Option<BootCollector<F>>,
}

impl<'a, F: ProfileRecordSinkFactory> CollectorReady<'a, F> {
    pub const fn ready_next_epoch(&self) -> Option<u64> {
        match &self.ready {
            Some(ready) => ready.next_epoch(),
            None => None,
        }
    }

    /// Returns only the target lineage and opaque collector. The factory,
    /// index, and accumulator remain sealed inside the latter.
    pub fn into_next(mut self) -> (TargetReady<'a>, BootCollector<F>) {
        let ready = self.ready.take().expect("collector Ready consumed once");
        let collector = self
            .collector
            .take()
            .expect("collector state consumed once");
        (ready, collector)
    }
}

/// Result of one successful SAMPLE publication.
pub enum CollectionProgress<'a, F: ProfileRecordSinkFactory> {
    More(CollectorReady<'a, F>),
    Complete(CompletedTranscript<'a, F>),
}

/// Copy-only diagnostic receipt for a closed single-boot transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootReceipt {
    samples: u8,
    warmups: u8,
    retained: u8,
    accumulator: u64,
    retained_p50: u64,
    retained_p95: u64,
}

impl BootReceipt {
    pub const fn samples(self) -> u8 {
        self.samples
    }

    pub const fn warmups(self) -> u8 {
        self.warmups
    }

    pub const fn retained(self) -> u8 {
        self.retained
    }

    pub const fn accumulator(self) -> u64 {
        self.accumulator
    }

    pub const fn retained_p50(self) -> u64 {
        self.retained_p50
    }

    pub const fn retained_p95(self) -> u64 {
        self.retained_p95
    }
}

/// Closed transcript. The factory remains permanently inaccessible so no
/// caller can append a second END or a 25th SAMPLE.
#[must_use = "the recycled target Ready must be installed exactly once"]
pub struct CompletedTranscript<'a, F: ProfileRecordSinkFactory> {
    ready: Option<TargetReady<'a>>,
    factory: ManuallyDrop<F>,
    receipt: BootReceipt,
}

/// A closed transcript cannot return its factory for another record.
///
/// ```compile_fail
/// fn append<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     completed: vibeos_wasm_aot_profile::CompletedTranscript<'_, F>,
/// ) {
///     let _ = completed.into_factory();
/// }
/// ```
impl<'a, F: ProfileRecordSinkFactory> CompletedTranscript<'a, F> {
    pub const fn ready_next_epoch(&self) -> Option<u64> {
        match &self.ready {
            Some(ready) => ready.next_epoch(),
            None => None,
        }
    }

    pub const fn receipt(&self) -> BootReceipt {
        self.receipt
    }

    /// Recycles the target lineage while intentionally retaining the closed
    /// factory in `ManuallyDrop`.
    pub fn into_ready(mut self) -> TargetReady<'a> {
        let ready = self.ready.take().expect("completed Ready consumed once");
        let _factory = self.factory;
        ready
    }
}

/// Permanently failed transcript. It has no retry, collector, END, or factory
/// recovery surface.
#[must_use = "the recycled target Ready must be installed even after campaign failure"]
pub struct PoisonedTranscript<'a, F: ProfileRecordSinkFactory> {
    ready: Option<TargetReady<'a>>,
    factory: ManuallyDrop<F>,
    stage: RecordStage,
    committed_records: u8,
    failure: CollectionFailure<F::Error>,
}

/// Poison is terminal: neither retry nor factory recovery is exposed.
///
/// ```compile_fail
/// fn retry<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     poisoned: vibeos_wasm_aot_profile::PoisonedTranscript<'_, F>,
/// ) {
///     let _ = poisoned.retry();
/// }
/// ```
///
/// ```compile_fail
/// fn recover_factory<F: vibeos_wasm_aot_profile::ProfileRecordSinkFactory>(
///     poisoned: vibeos_wasm_aot_profile::PoisonedTranscript<'_, F>,
/// ) {
///     let _ = poisoned.into_factory();
/// }
/// ```
impl<'a, F: ProfileRecordSinkFactory> PoisonedTranscript<'a, F> {
    fn new(
        ready: TargetReady<'a>,
        factory: ManuallyDrop<F>,
        stage: RecordStage,
        committed_records: u8,
        failure: CollectionFailure<F::Error>,
    ) -> Self {
        Self {
            ready: Some(ready),
            factory,
            stage,
            committed_records,
            failure,
        }
    }

    pub const fn stage(&self) -> RecordStage {
        self.stage
    }

    pub const fn committed_records(&self) -> u8 {
        self.committed_records
    }

    pub const fn failure(&self) -> &CollectionFailure<F::Error> {
        &self.failure
    }

    pub const fn ready_next_epoch(&self) -> Option<u64> {
        match &self.ready {
            Some(ready) => ready.next_epoch(),
            None => None,
        }
    }

    /// Returns the sole recycled target lineage while leaving the factory
    /// permanently quarantined.
    pub fn into_ready(mut self) -> TargetReady<'a> {
        let ready = self.ready.take().expect("poisoned Ready consumed once");
        let _factory = self.factory;
        ready
    }
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut decoded = [0_u8; N];
    let mut index = 0;
    while index < N {
        let upper = hex_nibble(bytes[index * 2])?;
        let lower = hex_nibble(bytes[index * 2 + 1])?;
        decoded[index] = (upper << 4) | lower;
        index += 1;
    }
    Some(decoded)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn retained_percentiles(mut ticks: [u64; BOOT_RETAINED]) -> (u64, u64) {
    let mut index = 1;
    while index < ticks.len() {
        let value = ticks[index];
        let mut cursor = index;
        while cursor != 0 && ticks[cursor - 1] > value {
            ticks[cursor] = ticks[cursor - 1];
            cursor -= 1;
        }
        ticks[cursor] = value;
        index += 1;
    }
    // nearest-rank ceil(0.50 * 21) - 1 and ceil(0.95 * 21) - 1.
    (ticks[10], ticks[19])
}

fn write_meta<S: ProfileRecordSink>(sink: &mut S, campaign: &Campaign) -> Result<(), S::Error> {
    sink.write_all(META_PREFIX)?;
    sink.write_all(b"{\"artifact_bytes\":2012,\"artifact_sha256\":\"")?;
    sink.write_all(ARTIFACT_SHA256.as_bytes())?;
    sink.write_all(b"\",\"budget_ticks\":2500000,\"challenge\":\"")?;
    write_hex(sink, &campaign.binding.challenge().bytes())?;
    sink.write_all(b"\",\"clock\":\"riscv.rdtime\",\"decision_eligible\":true,\"hart_count\":1,\"hart_id\":0,\"input_bytes\":12325,\"input_sha256\":\"")?;
    sink.write_all(INPUT_SHA256.as_bytes())?;
    sink.write_all(b"\",\"manifest_sha256\":\"")?;
    sink.write_all(MANIFEST_SHA256.as_bytes())?;
    sink.write_all(b"\",\"output_bytes\":12325,\"output_sha256\":\"")?;
    sink.write_all(OUTPUT_SHA256.as_bytes())?;
    sink.write_all(b"\",\"platform\":\"milkv-duo-cv1800b\",\"required_cold_boots\":3,\"retained_per_boot\":21,\"run_id\":\"")?;
    write_hex(sink, &campaign.binding.run_id().bytes())?;
    sink.write_all(b"\",\"samples_per_boot\":24,\"schema\":\"vibeos.wasm-aot-decision.meta\",\"source_commit\":\"")?;
    write_hex(sink, &campaign.source_commit)?;
    sink.write_all(b"\",\"suite_id\":\"vibeos.c84.aot-decision\",\"timebase_hz\":25000000,\"transcript_schema_sha256\":\"")?;
    sink.write_all(TRANSCRIPT_SCHEMA_SHA256.as_bytes())?;
    sink.write_all(b"\",\"transcript_scope\":\"single-cold-boot\",\"version\":1,\"warmup_per_boot\":3,\"workload_id\":\"ssh-case-filter-12k-v1\",\"workload_revision\":1}\n")
}

fn write_end<S: ProfileRecordSink>(
    sink: &mut S,
    binding: TranscriptBinding,
    accumulator: u64,
) -> Result<(), S::Error> {
    sink.write_all(END_PREFIX)?;
    sink.write_all(b"{\"accumulator\":")?;
    write_u64(sink, accumulator)?;
    sink.write_all(b",\"challenge\":\"")?;
    write_hex(sink, &binding.challenge().bytes())?;
    sink.write_all(b"\",\"retained\":21,\"run_id\":\"")?;
    write_hex(sink, &binding.run_id().bytes())?;
    sink.write_all(b"\",\"samples\":24,\"schema\":\"vibeos.wasm-aot-decision.end\",\"version\":1,\"warmups\":3}\n")
}

fn write_hex<S: ProfileRecordSink>(sink: &mut S, bytes: &[u8]) -> Result<(), S::Error> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    if bytes.len() > encoded.len() / 2 {
        unreachable!("formal identity exceeds fixed hex scratch");
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    sink.write_all(&encoded[..bytes.len() * 2])
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
    use crate::{Phase, Storage, TargetContext, FORMAL_STDOUT_BYTES, FORMAL_STDOUT_SHA256};
    use std::cell::RefCell;
    use std::format;
    use std::rc::Rc;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    const TEST_SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_CHALLENGE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TEST_RUN_ID: &str = "89be700330cb0f73f57ea5a18a8924b4ae356b7733e45c2335dbca7a80d6601a";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Injected,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailurePlan {
        None,
        Acquire {
            record: usize,
        },
        Write {
            record: usize,
            call: usize,
            prefix: usize,
        },
        Commit {
            record: usize,
        },
        PanicAcquire {
            record: usize,
        },
        PanicWrite {
            record: usize,
            call: usize,
            prefix: usize,
        },
        PanicCommit {
            record: usize,
        },
    }

    #[derive(Default)]
    struct Audit {
        bytes: Vec<u8>,
        begin_calls: usize,
        commits: usize,
        record_drops: usize,
        factory_drops: usize,
    }

    struct TestFactory {
        audit: Rc<RefCell<Audit>>,
        plan: FailurePlan,
    }

    impl TestFactory {
        fn new(plan: FailurePlan) -> (Self, Rc<RefCell<Audit>>) {
            let audit = Rc::new(RefCell::new(Audit::default()));
            (
                Self {
                    audit: audit.clone(),
                    plan,
                },
                audit,
            )
        }
    }

    impl Drop for TestFactory {
        fn drop(&mut self) {
            self.audit.borrow_mut().factory_drops += 1;
        }
    }

    struct TestRecord {
        audit: Rc<RefCell<Audit>>,
        plan: FailurePlan,
        record: usize,
        write_calls: usize,
    }

    impl Drop for TestRecord {
        fn drop(&mut self) {
            self.audit.borrow_mut().record_drops += 1;
        }
    }

    impl ProfileRecordSink for TestRecord {
        type Error = TestError;

        fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            let call = self.write_calls;
            self.write_calls += 1;
            if let FailurePlan::PanicWrite {
                record,
                call: failed_call,
                prefix,
            } = self.plan
            {
                if record == self.record && failed_call == call {
                    let accepted = prefix.min(bytes.len());
                    self.audit
                        .borrow_mut()
                        .bytes
                        .extend_from_slice(&bytes[..accepted]);
                    panic!("injected write panic");
                }
            }
            if let FailurePlan::Write {
                record,
                call: failed_call,
                prefix,
            } = self.plan
            {
                if record == self.record && failed_call == call {
                    let accepted = prefix.min(bytes.len());
                    self.audit
                        .borrow_mut()
                        .bytes
                        .extend_from_slice(&bytes[..accepted]);
                    return Err(TestError::Injected);
                }
            }
            self.audit.borrow_mut().bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn commit_record(&mut self) -> Result<(), Self::Error> {
            if self.plan
                == (FailurePlan::PanicCommit {
                    record: self.record,
                })
            {
                panic!("injected commit panic");
            }
            if self.plan
                == (FailurePlan::Commit {
                    record: self.record,
                })
            {
                return Err(TestError::Injected);
            }
            self.audit.borrow_mut().commits += 1;
            Ok(())
        }
    }

    impl ProfileRecordSinkFactory for TestFactory {
        type Error = TestError;
        type Record = TestRecord;

        fn begin_record(&mut self) -> Result<Self::Record, Self::Error> {
            let record = self.audit.borrow().begin_calls;
            self.audit.borrow_mut().begin_calls += 1;
            if self.plan == (FailurePlan::PanicAcquire { record }) {
                panic!("injected acquire panic");
            }
            if self.plan == (FailurePlan::Acquire { record }) {
                return Err(TestError::Injected);
            }
            Ok(TestRecord {
                audit: self.audit.clone(),
                plan: self.plan,
                record,
                write_calls: 0,
            })
        }
    }

    struct SendRecord;

    impl ProfileRecordSink for SendRecord {
        type Error = ();

        fn write_all(&mut self, _bytes: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn commit_record(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct SendFactory;

    impl ProfileRecordSinkFactory for SendFactory {
        type Error = ();
        type Record = SendRecord;

        fn begin_record(&mut self) -> Result<Self::Record, Self::Error> {
            Ok(SendRecord)
        }
    }

    fn require_send<T: Send>() {}

    fn campaign() -> Campaign {
        Campaign::from_values(TEST_SOURCE, TEST_CHALLENGE)
            .unwrap_or_else(|_| panic!("test campaign must bind"))
    }

    fn storage() -> (Vec<u64>, Vec<u8>) {
        (
            vec![u64::MAX; crate::INTERVAL_CAPACITY],
            vec![u8::MAX; crate::INTERVAL_CAPACITY],
        )
    }

    fn ready<'a>(endpoints: &'a mut [u64], phases: &'a mut [u8]) -> TargetReady<'a> {
        TargetReady::new(
            Storage::new(endpoints, phases)
                .unwrap_or_else(|_| panic!("exact test storage must bind")),
        )
    }

    fn verified_with_total<'a>(ready: TargetReady<'a>, total_ticks: u64) -> TargetVerified<'a> {
        assert!(total_ticks >= 7);
        let start = 0;
        let mut active = match ready.start(TargetContext::CANONICAL, start) {
            Ok(active) => active,
            Err(_) => panic!("test target start failed"),
        };
        let token = active.token();
        active.set_phase(
            token,
            TargetContext::CANONICAL,
            start + 1,
            Phase::Instantiation,
        );
        active.set_phase(token, TargetContext::CANONICAL, start + 2, Phase::Abi);
        active.set_phase(
            token,
            TargetContext::CANONICAL,
            start + 3,
            Phase::Interpretation,
        );
        active.set_phase(token, TargetContext::CANONICAL, start + 4, Phase::Host);
        active.set_phase(token, TargetContext::CANONICAL, start + 5, Phase::Wait);
        active.begin_cleanup(token, TargetContext::CANONICAL, start + 6);
        let finished = match active.finish(token, TargetContext::CANONICAL, start + total_ticks) {
            Ok(finished) => finished,
            Err(_) => panic!("test facade finish failed"),
        };
        match finished.verify() {
            Ok(verified) => verified,
            Err(_) => panic!("test ledger verification failed"),
        }
    }

    fn terminal(sample_index: u8) -> EligibleTerminalEvidence {
        EligibleTerminalEvidence::validate(crate::TerminalObservation {
            read_chunks: crate::FORMAL_READ_CHUNKS,
            write_chunks: crate::FORMAL_WRITE_CHUNKS,
            fuel_consumed: 1_000 + u64::from(sample_index),
            poll_quanta: 2_000 + u64::from(sample_index),
            poll_quanta_exact: true,
            succeeded: true,
            logical_live_after: 0,
            timed_out: false,
            timeout_phase: None,
            exit_status: 0,
            stdout_bytes: FORMAL_STDOUT_BYTES,
            stdout_sha256: FORMAL_STDOUT_SHA256,
            stderr_bytes: 0,
        })
        .unwrap_or_else(|_| panic!("test terminal must be eligible"))
    }

    fn begin_boot<'a>(
        ready: TargetReady<'a>,
        factory: TestFactory,
    ) -> (TargetReady<'a>, BootCollector<TestFactory>) {
        let started = match campaign().begin(factory, ready) {
            Ok(started) => started,
            Err(_) => panic!("test META must commit"),
        };
        let (ready, collector) = started.into_next();
        assert_eq!(collector.next_sample, 0);
        (ready, collector)
    }

    fn run_boot<'a>(
        ready: TargetReady<'a>,
        factory: TestFactory,
        totals: [u64; BOOT_SAMPLES as usize],
    ) -> Result<CompletedTranscript<'a, TestFactory>, PoisonedTranscript<'a, TestFactory>> {
        let (mut ready, mut collector) = begin_boot(ready, factory);
        for (index, total_ticks) in totals.into_iter().enumerate() {
            let result = collector.collect(
                verified_with_total(ready, total_ticks),
                terminal(index as u8),
            );
            match result {
                Ok(CollectionProgress::More(next)) if index + 1 < usize::from(BOOT_SAMPLES) => {
                    (ready, collector) = next.into_next();
                    assert_eq!(collector.next_sample, index as u8 + 1);
                }
                Ok(CollectionProgress::Complete(completed))
                    if index + 1 == usize::from(BOOT_SAMPLES) =>
                {
                    return Ok(completed);
                }
                Ok(_) => panic!("collector completed at the wrong sample"),
                Err(poisoned) => return Err(poisoned),
            }
        }
        panic!("24 samples did not close the transcript")
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::new();
        for byte in bytes {
            text.push(HEX[usize::from(byte >> 4)] as char);
            text.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        text
    }

    #[test]
    fn campaign_validation_and_run_id_are_exact() {
        assert_eq!(
            Campaign::from_values("a", TEST_CHALLENGE).err(),
            Some(CampaignError::InvalidSourceCommit)
        );
        assert_eq!(
            Campaign::from_values(&"0".repeat(40), TEST_CHALLENGE).err(),
            Some(CampaignError::ZeroSourceCommit)
        );
        assert_eq!(
            Campaign::from_values(TEST_SOURCE, &"0".repeat(64)).err(),
            Some(CampaignError::ZeroChallenge)
        );
        assert_eq!(
            Campaign::from_values(TEST_SOURCE, &"B".repeat(64)).err(),
            Some(CampaignError::InvalidChallenge)
        );
        let campaign = campaign();
        assert_eq!(lower_hex(&campaign.source_commit), TEST_SOURCE);
        assert_eq!(
            lower_hex(&campaign.binding.challenge().bytes()),
            TEST_CHALLENGE
        );
        assert_eq!(lower_hex(&campaign.binding.run_id().bytes()), TEST_RUN_ID);

        match (
            option_env!("VIBEOS_C84_SOURCE_COMMIT"),
            option_env!("VIBEOS_C84_CHALLENGE"),
        ) {
            (None, _) => assert!(matches!(
                Campaign::from_bound_build(),
                Err(CampaignError::MissingSourceCommit)
            )),
            (Some(_), None) => assert!(matches!(
                Campaign::from_bound_build(),
                Err(CampaignError::MissingChallenge)
            )),
            (Some(source), Some(challenge)) => {
                let bound = Campaign::from_bound_build()
                    .unwrap_or_else(|_| panic!("valid build identity must bind"));
                let expected = Campaign::from_values(source, challenge)
                    .unwrap_or_else(|_| panic!("valid build identity must bind"));
                assert_eq!(bound.source_commit, expected.source_commit);
                assert_eq!(bound.binding, expected.binding);
            }
        }
        require_send::<BootCollector<SendFactory>>();
    }

    #[test]
    fn complete_boot_emits_one_meta_twenty_four_samples_and_one_end() {
        let (mut endpoints, mut phases) = storage();
        let (factory, audit) = TestFactory::new(FailurePlan::None);
        let completed = match run_boot(
            ready(&mut endpoints, &mut phases),
            factory,
            [100; BOOT_SAMPLES as usize],
        ) {
            Ok(completed) => completed,
            Err(_) => panic!("stable test boot was poisoned"),
        };
        assert_eq!(completed.ready_next_epoch(), Some(25));
        let receipt = completed.receipt();
        assert_eq!(receipt.samples(), BOOT_SAMPLES);
        assert_eq!(receipt.warmups(), BOOT_WARMUPS);
        assert_eq!(usize::from(receipt.retained()), BOOT_RETAINED);
        assert_eq!(receipt.retained_p50(), 100);
        assert_eq!(receipt.retained_p95(), 100);

        let observed = audit.borrow();
        assert_eq!(observed.begin_calls, 26);
        assert_eq!(observed.commits, 26);
        assert_eq!(observed.record_drops, 0);
        assert_eq!(observed.factory_drops, 0);
        assert!(!observed.bytes.contains(&b'\r'));
        assert_eq!(observed.bytes.last(), Some(&b'\n'));
        let transcript_sha256: [u8; 32] = Sha256::digest(&observed.bytes).into();
        assert_eq!(
            (observed.bytes.len(), lower_hex(&transcript_sha256)),
            (
                34_386,
                String::from("10df3a084b5817ee998c11e3eab0326fc2f16bdeba6644ce7e29e57c7bbc9da2",),
            ),
        );
        let text = String::from_utf8(observed.bytes.clone())
            .unwrap_or_else(|_| panic!("formal transcript must be UTF-8"));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 26);
        let expected_meta = format!(
            "VIBE_WASM_AOT_META {{\"artifact_bytes\":2012,\"artifact_sha256\":\"{}\",\"budget_ticks\":2500000,\"challenge\":\"{}\",\"clock\":\"riscv.rdtime\",\"decision_eligible\":true,\"hart_count\":1,\"hart_id\":0,\"input_bytes\":12325,\"input_sha256\":\"{}\",\"manifest_sha256\":\"{}\",\"output_bytes\":12325,\"output_sha256\":\"{}\",\"platform\":\"milkv-duo-cv1800b\",\"required_cold_boots\":3,\"retained_per_boot\":21,\"run_id\":\"{}\",\"samples_per_boot\":24,\"schema\":\"vibeos.wasm-aot-decision.meta\",\"source_commit\":\"{}\",\"suite_id\":\"vibeos.c84.aot-decision\",\"timebase_hz\":25000000,\"transcript_schema_sha256\":\"{}\",\"transcript_scope\":\"single-cold-boot\",\"version\":1,\"warmup_per_boot\":3,\"workload_id\":\"ssh-case-filter-12k-v1\",\"workload_revision\":1}}",
            ARTIFACT_SHA256,
            TEST_CHALLENGE,
            INPUT_SHA256,
            MANIFEST_SHA256,
            OUTPUT_SHA256,
            TEST_RUN_ID,
            TEST_SOURCE,
            TRANSCRIPT_SCHEMA_SHA256,
        );
        assert_eq!(lines[0], expected_meta);
        for index in 0..usize::from(BOOT_SAMPLES) {
            let line = lines[index + 1];
            assert!(line.starts_with("VIBE_WASM_AOT_SAMPLE "));
            assert!(line.contains(&format!("\"sample_index\":{index}")));
            assert!(line.contains(&format!("\"sequence\":{index},\"stderr_bytes\"")));
            assert!(line.contains(if index < usize::from(BOOT_WARMUPS) {
                "\"warmup\":true"
            } else {
                "\"warmup\":false"
            }));
        }
        let expected_end = format!(
            "VIBE_WASM_AOT_END {{\"accumulator\":{},\"challenge\":\"{}\",\"retained\":21,\"run_id\":\"{}\",\"samples\":24,\"schema\":\"vibeos.wasm-aot-decision.end\",\"version\":1,\"warmups\":3}}",
            receipt.accumulator(),
            TEST_CHALLENGE,
            TEST_RUN_ID,
        );
        assert_eq!(lines[25], expected_end);
        drop(observed);

        let recycled = completed.into_ready();
        assert_eq!(recycled.next_epoch(), Some(25));
        assert_eq!(audit.borrow().factory_drops, 0);
    }

    #[test]
    fn stability_uses_only_twenty_one_retained_nearest_rank_samples() {
        let mut passing = [100_u64; BOOT_SAMPLES as usize];
        passing[..usize::from(BOOT_WARMUPS)].fill(u64::MAX - 1);
        passing[22] = 150;
        passing[23] = 1_000;
        let (mut endpoints, mut phases) = storage();
        let (factory, _) = TestFactory::new(FailurePlan::None);
        let completed = match run_boot(ready(&mut endpoints, &mut phases), factory, passing) {
            Ok(completed) => completed,
            Err(_) => panic!("exact 1.50 stability boundary failed"),
        };
        assert_eq!(completed.receipt().retained_p50(), 100);
        assert_eq!(completed.receipt().retained_p95(), 150);
        drop(completed.into_ready());

        let mut failing = [100_u64; BOOT_SAMPLES as usize];
        failing[22] = 151;
        failing[23] = 1_000;
        let (mut endpoints, mut phases) = storage();
        let (factory, audit) = TestFactory::new(FailurePlan::None);
        let poisoned = match run_boot(ready(&mut endpoints, &mut phases), factory, failing) {
            Ok(_) => panic!("unstable boot emitted END"),
            Err(poisoned) => poisoned,
        };
        assert_eq!(poisoned.stage(), RecordStage::End);
        assert_eq!(poisoned.committed_records(), 25);
        assert_eq!(
            poisoned.failure(),
            &CollectionFailure::Fault(CollectorFault::Stability { p50: 100, p95: 151 })
        );
        assert_eq!(poisoned.ready_next_epoch(), Some(25));
        let audit = audit.borrow();
        assert_eq!(audit.begin_calls, 25);
        assert_eq!(audit.commits, 25);
        assert!(!audit
            .bytes
            .windows(END_PREFIX.len())
            .any(|w| w == END_PREFIX));
        assert_eq!(audit.record_drops, 0);
        assert_eq!(audit.factory_drops, 0);
        drop(audit);
        drop(poisoned.into_ready());
    }

    #[test]
    fn meta_acquire_write_and_commit_failures_quarantine_without_drop() {
        let plans = [
            FailurePlan::Acquire { record: 0 },
            FailurePlan::Write {
                record: 0,
                call: 0,
                prefix: 3,
            },
            FailurePlan::Commit { record: 0 },
        ];
        for plan in plans {
            let (mut endpoints, mut phases) = storage();
            let (factory, audit) = TestFactory::new(plan);
            let poisoned = match campaign().begin(factory, ready(&mut endpoints, &mut phases)) {
                Ok(_) => panic!("injected META failure committed"),
                Err(poisoned) => poisoned,
            };
            assert_eq!(poisoned.stage(), RecordStage::Meta);
            assert_eq!(poisoned.committed_records(), 0);
            assert_eq!(
                poisoned.failure(),
                &CollectionFailure::Record(TestError::Injected)
            );
            assert_eq!(poisoned.ready_next_epoch(), Some(1));
            assert_eq!(audit.borrow().begin_calls, 1);
            assert_eq!(audit.borrow().commits, 0);
            assert_eq!(audit.borrow().record_drops, 0);
            assert_eq!(audit.borrow().factory_drops, 0);
            drop(poisoned.into_ready());
            assert_eq!(audit.borrow().factory_drops, 0);
        }
    }

    #[test]
    fn sample_and_end_failures_never_retry_or_run_destructors() {
        let cases = [
            (
                FailurePlan::Acquire { record: 1 },
                RecordStage::Sample(0),
                1,
            ),
            (
                FailurePlan::Write {
                    record: 1,
                    call: 0,
                    prefix: 5,
                },
                RecordStage::Sample(0),
                1,
            ),
            (FailurePlan::Commit { record: 1 }, RecordStage::Sample(0), 1),
            (FailurePlan::Acquire { record: 25 }, RecordStage::End, 25),
            (
                FailurePlan::Write {
                    record: 25,
                    call: 0,
                    prefix: 5,
                },
                RecordStage::End,
                25,
            ),
            (FailurePlan::Commit { record: 25 }, RecordStage::End, 25),
        ];
        for (plan, expected_stage, committed_records) in cases {
            let (mut endpoints, mut phases) = storage();
            let (factory, audit) = TestFactory::new(plan);
            let poisoned = match run_boot(
                ready(&mut endpoints, &mut phases),
                factory,
                [100; BOOT_SAMPLES as usize],
            ) {
                Ok(_) => panic!("injected record failure closed a transcript"),
                Err(poisoned) => poisoned,
            };
            assert_eq!(poisoned.stage(), expected_stage);
            assert_eq!(poisoned.committed_records(), committed_records);
            assert_eq!(
                poisoned.failure(),
                &CollectionFailure::Record(TestError::Injected)
            );
            let observed = audit.borrow();
            assert_eq!(observed.commits, usize::from(committed_records));
            assert_eq!(observed.record_drops, 0);
            assert_eq!(observed.factory_drops, 0);
            if expected_stage != RecordStage::End {
                assert!(!observed
                    .bytes
                    .windows(END_PREFIX.len())
                    .any(|w| w == END_PREFIX));
            }
            drop(observed);
            drop(poisoned.into_ready());
            assert_eq!(audit.borrow().factory_drops, 0);
        }
    }

    #[test]
    fn epoch_mismatch_and_terminal_abort_touch_no_sample_record() {
        let (mut endpoints_a, mut phases_a) = storage();
        let (factory, audit) = TestFactory::new(FailurePlan::None);
        let (ready_a, collector) = begin_boot(ready(&mut endpoints_a, &mut phases_a), factory);

        let (mut endpoints_b, mut phases_b) = storage();
        let foreign_ready =
            verified_with_total(ready(&mut endpoints_b, &mut phases_b), 100).recycle();
        let foreign = verified_with_total(foreign_ready, 100);
        let poisoned = match collector.collect(foreign, terminal(0)) {
            Ok(_) => panic!("wrong epoch entered the transcript"),
            Err(poisoned) => poisoned,
        };
        assert_eq!(poisoned.stage(), RecordStage::Sample(0));
        assert_eq!(poisoned.committed_records(), 1);
        assert_eq!(
            poisoned.failure(),
            &CollectionFailure::Fault(CollectorFault::EpochMismatch {
                expected: 1,
                actual: 2,
            })
        );
        assert_eq!(poisoned.ready_next_epoch(), Some(3));
        assert_eq!(audit.borrow().begin_calls, 1);
        drop(poisoned.into_ready());
        drop(ready_a);

        let (mut endpoints, mut phases) = storage();
        let (factory, audit) = TestFactory::new(FailurePlan::None);
        let (ready, collector) = begin_boot(ready(&mut endpoints, &mut phases), factory);
        let recycled = verified_with_total(ready, 100).recycle();
        let poisoned = collector.quarantine_attempt(recycled, CollectorAbort::TerminalRejected);
        assert_eq!(poisoned.stage(), RecordStage::Sample(0));
        assert_eq!(poisoned.committed_records(), 1);
        assert_eq!(
            poisoned.failure(),
            &CollectionFailure::Fault(CollectorFault::TerminalRejected)
        );
        assert_eq!(poisoned.ready_next_epoch(), Some(2));
        assert_eq!(audit.borrow().begin_calls, 1);
        assert_eq!(audit.borrow().commits, 1);
        drop(poisoned.into_ready());
    }

    #[test]
    fn dropping_live_collector_leaves_meta_only_and_never_drops_factory() {
        let (mut endpoints, mut phases) = storage();
        let (factory, audit) = TestFactory::new(FailurePlan::None);
        let started = match campaign().begin(factory, ready(&mut endpoints, &mut phases)) {
            Ok(started) => started,
            Err(_) => panic!("test META failed"),
        };
        let (ready, collector) = started.into_next();
        drop(collector);
        drop(ready);
        let audit = audit.borrow();
        assert_eq!(audit.begin_calls, 1);
        assert_eq!(audit.commits, 1);
        assert_eq!(audit.record_drops, 0);
        assert_eq!(audit.factory_drops, 0);
        assert!(audit.bytes.starts_with(META_PREFIX));
        assert!(!audit
            .bytes
            .windows(END_PREFIX.len())
            .any(|w| w == END_PREFIX));
    }

    #[test]
    fn panics_fail_stop_without_running_factory_or_record_destructors() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let plans = [
            FailurePlan::PanicAcquire { record: 0 },
            FailurePlan::PanicWrite {
                record: 0,
                call: 0,
                prefix: 3,
            },
            FailurePlan::PanicCommit { record: 0 },
            FailurePlan::PanicWrite {
                record: 1,
                call: 0,
                prefix: 3,
            },
            FailurePlan::PanicWrite {
                record: 25,
                call: 0,
                prefix: 3,
            },
            FailurePlan::PanicCommit { record: 25 },
        ];
        for plan in plans {
            let (mut endpoints, mut phases) = storage();
            let (factory, audit) = TestFactory::new(plan);
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = run_boot(
                    ready(&mut endpoints, &mut phases),
                    factory,
                    [100; BOOT_SAMPLES as usize],
                );
            }));
            assert!(result.is_err());
            assert_eq!(audit.borrow().record_drops, 0);
            assert_eq!(audit.borrow().factory_drops, 0);
        }
    }
}
