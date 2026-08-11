//! Milk-V Duo qualification harness for jitterentropy-rs.
//!
//! This module is deliberately available only in the dedicated probe image.
//! Raw deltas are qualification evidence, never random bytes.

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
use alloc::{boxed::Box, format, vec::Vec};
use core::cell::UnsafeCell;
#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
use core::task::{Context, Poll};

use jitterentropy::{
    EntropyCollector, EntropyCollectorBuilder, Flags, InitError, ReadError, Timer, version,
};

use crate::{println, sbi};

const OSR: u32 = 3;
const MEMORY_SIZE: usize = 256 * 1024;
const FLAGS: Flags = Flags(
    Flags::DISABLE_INTERNAL_TIMER.bits() | Flags::FORCE_FIPS.bits() | (9 << Flags::MEMSIZE_SHIFT),
);
const SEED_BYTES: usize = 32;
const RAW_BLOCK_DELTAS: usize = 128;
#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
const SSH_STREAM_DELTAS: usize = 4 * 1024;
pub const MAX_RAW_SAMPLES: usize = 1_000_000;

static JENT_IN_USE: AtomicBool = AtomicBool::new(false);

struct RawBuffer(UnsafeCell<[u64; MAX_RAW_SAMPLES]>);

// The dedicated qualification image is single-core and `UseGuard` serializes
// all access before a mutable reference is created.
unsafe impl Sync for RawBuffer {}

static RAW_BUFFER: RawBuffer = RawBuffer(UnsafeCell::new([0; MAX_RAW_SAMPLES]));

#[derive(Clone, Copy, Debug)]
struct SbiTimer;

impl Timer for SbiTimer {
    #[inline(always)]
    fn now(&mut self) -> Option<u64> {
        Some(sbi::time())
    }
}

struct UseGuard;

impl UseGuard {
    fn acquire() -> Option<Self> {
        JENT_IN_USE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for UseGuard {
    fn drop(&mut self) {
        JENT_IN_USE.store(false, Ordering::Release);
    }
}

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn init_error_name(error: InitError) -> &'static str {
    match error {
        InitError::TimerUnavailable => "no-timer",
        InitError::TimerTooCoarse => "coarse-timer",
        InitError::TimerNotMonotonic => "non-monotonic-timer",
        InitError::MinimalVariation => "timer-min-variation",
        InitError::VariationOfVariationMissing => "timer-variation-of-variation",
        InitError::MinimalVariationOfVariation => "timer-min-variation-of-variation",
        InitError::ProgrammingError => "programming-error",
        InitError::Stuck => "timer-stuck",
        InitError::Health => "health-test",
        InitError::Rct => "rct-health-test",
        InitError::Hash => "hash-self-test",
        InitError::Memory => "memory",
        InitError::Gcd => "gcd-self-test",
    }
}

fn read_code(result: Result<(), ReadError>, expected: usize) -> isize {
    match result {
        Ok(()) => expected as isize,
        Err(error) => error.c_code(),
    }
}

fn build_collector() -> Result<EntropyCollector<SbiTimer>, InitError> {
    EntropyCollectorBuilder::new()
        .osr(OSR)
        .flags(FLAGS)
        .memory_size(MEMORY_SIZE)
        .build_with_timer(SbiTimer)
}

pub fn smoke() {
    let Some(_guard) = UseGuard::acquire() else {
        println!("VIBE_JENT_SMOKE FAIL reason=busy");
        return;
    };
    let version = version();
    let started = sbi::time();
    let mut collector = match build_collector() {
        Ok(collector) => collector,
        Err(error) => {
            let init_ticks = sbi::time().wrapping_sub(started);
            println!(
                "VIBE_JENT_SMOKE FAIL version={} init={} reason={} ticks={}",
                version,
                error as i32,
                init_error_name(error),
                init_ticks
            );
            return;
        }
    };
    let init_ticks = sbi::time().wrapping_sub(started);

    let mut first = [0u8; SEED_BYTES];
    let mut second = [0u8; SEED_BYTES];
    let first_read = read_code(collector.fill_bytes(&mut first), first.len());
    let second_read = read_code(collector.fill_bytes(&mut second), second.len());
    let distinct = first != second;
    let pass = first_read == SEED_BYTES as isize && second_read == SEED_BYTES as isize && distinct;
    zeroize(&mut first);
    zeroize(&mut second);
    println!(
        "VIBE_JENT_SMOKE {} source=jitterentropy-rs version={} init=0 read1={} read2={} distinct={} osr={} fips=forced timer=sbi-rdtime ticks={}",
        if pass { "PASS" } else { "FAIL" },
        version,
        first_read,
        second_read,
        distinct,
        OSR,
        init_ticks
    );
}

pub fn raw(samples: usize) {
    let Some(_guard) = UseGuard::acquire() else {
        println!("VIBE_JENT_END FAIL samples=0 stuck=not-exposed health=0x0 reason=busy");
        return;
    };
    println!(
        "VIBE_JENT_BEGIN source=jitterentropy-rs version={} mode=raw-timer-delta samples={} osr={} timer=sbi-rdtime",
        version(),
        samples,
        OSR
    );

    // SAFETY: `UseGuard` provides exclusive access, and this probe image has
    // only the Milk-V Duo's single application hart.
    let values = unsafe { &mut *RAW_BUFFER.0.get() };
    let mut captured = 0usize;
    let mut collector = match build_collector() {
        Ok(collector) => collector,
        Err(error) => {
            println!(
                "VIBE_JENT_END FAIL samples=0 stuck=not-exposed health=0x0 reason={} init={}",
                init_error_name(error),
                error as i32
            );
            return;
        }
    };
    let mut raw_block = [0u64; RAW_BLOCK_DELTAS];
    let mut read_error = None;
    while captured < samples {
        match collector.raw_block(&mut raw_block) {
            Ok(count) => {
                let copied = core::cmp::min(count, samples - captured);
                values[captured..captured + copied].copy_from_slice(&raw_block[..copied]);
                captured += copied;
            }
            Err(error) => {
                read_error = Some(error);
                break;
            }
        }
    }
    let health = collector.status().last_health_failure;
    drop(collector);

    for (index, delta) in values[..captured].iter().enumerate() {
        println!("VIBE_JENT_RAW {} {:016x}", index, delta);
    }
    match read_error {
        None if captured == samples && health == 0 => println!(
            "VIBE_JENT_END COMPLETE samples={} stuck=not-exposed health={:#x}",
            captured, health
        ),
        Some(error) => println!(
            "VIBE_JENT_END HEALTH-FAIL samples={} stuck=not-exposed health={:#x} read={}",
            captured,
            health,
            error.c_code()
        ),
        None => println!(
            "VIBE_JENT_END FAIL samples={} stuck=not-exposed health={:#x} reason=incomplete",
            captured, health
        ),
    }
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
enum StreamPhase {
    Capture,
    Header,
    Data,
    Trailer,
    Done,
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
struct SshRawStream {
    _guard: Option<UseGuard>,
    collector: Option<EntropyCollector<SbiTimer>>,
    requested: usize,
    captured: usize,
    output_offset: usize,
    health: u32,
    read_error: Option<i32>,
    phase: StreamPhase,
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
impl SshRawStream {
    fn new(samples: usize) -> Result<Self, u32> {
        let guard = UseGuard::acquire().ok_or(75u32)?;
        let collector = build_collector().map_err(|_| 70u32)?;
        Ok(Self {
            _guard: Some(guard),
            collector: Some(collector),
            requested: samples,
            captured: 0,
            output_offset: 0,
            health: 0,
            read_error: None,
            phase: StreamPhase::Capture,
        })
    }

    fn capture_one_block(&mut self) {
        let mut raw_block = [0u64; RAW_BLOCK_DELTAS];
        let collector = self
            .collector
            .as_mut()
            .expect("capture phase retains the collector");
        match collector.raw_block(&mut raw_block) {
            Ok(count) => {
                let copied = core::cmp::min(count, self.requested - self.captured);
                // SAFETY: the stream owns `UseGuard`, the image runs only the
                // Duo application hart, and bounds are checked above.
                let values = unsafe { &mut *RAW_BUFFER.0.get() };
                values[self.captured..self.captured + copied].copy_from_slice(&raw_block[..copied]);
                self.captured += copied;
            }
            Err(error) => self.read_error = Some(error.c_code() as i32),
        }
        if self.captured == self.requested || self.read_error.is_some() {
            self.health = collector.status().last_health_failure;
            self.collector = None;
            self.phase = StreamPhase::Header;
        }
    }

    fn complete(&self) -> bool {
        self.captured == self.requested && self.read_error.is_none() && self.health == 0
    }
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
impl vibeos_sshd::StreamingExec for SshRawStream {
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Vec<u8>>, u32>> {
        loop {
            match self.phase {
                StreamPhase::Capture => {
                    self.capture_one_block();
                    if matches!(self.phase, StreamPhase::Capture) {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                StreamPhase::Header => {
                    self.phase = StreamPhase::Data;
                    return Poll::Ready(Ok(Some(
                        format!(
                            "VIBE_JENT_STREAM_V1 requested={} captured={} encoding=u64le osr={} version={} stuck=not-exposed health={:#x} read={}\n",
                            self.requested,
                            self.captured,
                            OSR,
                            version(),
                            self.health,
                            self.read_error.map_or(0, |code| code),
                        )
                        .into_bytes(),
                    )));
                }
                StreamPhase::Data => {
                    if self.output_offset < self.captured {
                        let end =
                            core::cmp::min(self.output_offset + SSH_STREAM_DELTAS, self.captured);
                        let mut chunk = Vec::with_capacity((end - self.output_offset) * 8);
                        // SAFETY: `UseGuard` remains owned until stream
                        // completion, and the range is within captured data.
                        let values = unsafe { &*RAW_BUFFER.0.get() };
                        for delta in &values[self.output_offset..end] {
                            chunk.extend_from_slice(&delta.to_le_bytes());
                        }
                        self.output_offset = end;
                        return Poll::Ready(Ok(Some(chunk)));
                    }
                    self.phase = StreamPhase::Trailer;
                }
                StreamPhase::Trailer => {
                    let status = if self.complete() {
                        "COMPLETE"
                    } else {
                        "HEALTH-FAIL"
                    };
                    self.phase = StreamPhase::Done;
                    return Poll::Ready(Ok(Some(
                        format!(
                            "\nVIBE_JENT_END {} samples={} stuck=not-exposed health={:#x} read={}\n",
                            status,
                            self.captured,
                            self.health,
                            self.read_error.map_or(0, |code| code),
                        )
                        .into_bytes(),
                    )));
                }
                StreamPhase::Done => {
                    self._guard = None;
                    return if self.complete() {
                        Poll::Ready(Ok(None))
                    } else {
                        Poll::Ready(Err(1))
                    };
                }
            }
        }
    }
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
fn ssh_stream_samples(command: &str) -> Option<usize> {
    let mut words = command.split_ascii_whitespace();
    if words.next() != Some("jent") || words.next() != Some("raw") {
        return None;
    }
    let count = words.next()?;
    if words.next().is_some() {
        return None;
    }
    let samples = count.parse::<usize>().ok()?;
    if !(1..=MAX_RAW_SAMPLES).contains(&samples) {
        return None;
    }
    Some(samples)
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
pub fn accepts_ssh_stream(command: &str) -> bool {
    ssh_stream_samples(command).is_some()
}

#[cfg(feature = "milkv-jitterentropy-ssh-probe")]
pub fn open_ssh_stream(command: &str) -> Option<Result<vibeos_sshd::StreamingExecBox, u32>> {
    let samples = ssh_stream_samples(command)?;
    Some(SshRawStream::new(samples).map(|stream| Box::pin(stream) as _))
}
