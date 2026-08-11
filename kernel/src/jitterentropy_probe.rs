//! Milk-V Duo qualification harness for jitterentropy-rs.
//!
//! This module is deliberately available only in the dedicated probe image.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use jitterentropy::{
    version, EntropyCollector, EntropyCollectorBuilder, Flags, InitError, ReadError, Timer,
};

use crate::{println, sbi};

const OSR: u32 = 3;
const MEMORY_SIZE: usize = 256 * 1024;
const FLAGS: Flags = Flags(
    Flags::DISABLE_INTERNAL_TIMER.bits() | Flags::FORCE_FIPS.bits() | (9 << Flags::MEMSIZE_SHIFT),
);
const SEED_BYTES: usize = 32;

static JENT_IN_USE: AtomicBool = AtomicBool::new(false);

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
