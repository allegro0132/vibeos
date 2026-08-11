//! Milk-V Duo qualification harness for upstream jitterentropy-library.
//!
//! This module is deliberately available only in the dedicated probe image.
//! Raw deltas are evidence, not random bytes, and must never be consumed by a
//! cryptographic protocol.

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{println, sbi};

const OSR: u32 = 3;
const JENT_DISABLE_INTERNAL_TIMER: u32 = 1 << 4;
const JENT_FORCE_FIPS: u32 = 1 << 5;
const JENT_MAX_MEMSIZE_256_KIB: u32 = 9 << 27;
const FLAGS: u32 = JENT_DISABLE_INTERNAL_TIMER | JENT_FORCE_FIPS | JENT_MAX_MEMSIZE_256_KIB;
const SEED_BYTES: usize = 32;
pub const MAX_RAW_SAMPLES: usize = 1_000_000;

static JENT_IN_USE: AtomicBool = AtomicBool::new(false);

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

#[repr(C)]
struct RandData {
    _private: [u8; 0],
}

extern "C" {
    fn jent_version() -> u32;
    fn jent_entropy_init_ex(osr: u32, flags: u32) -> i32;
    fn jent_entropy_collector_alloc(osr: u32, flags: u32) -> *mut RandData;
    fn jent_entropy_collector_free(collector: *mut RandData);
    fn jent_read_entropy(collector: *mut RandData, output: *mut u8, len: usize) -> isize;

    fn vibeos_jent_raw_alloc(osr: u32, flags: u32) -> *mut RandData;
    fn vibeos_jent_raw_next(collector: *mut RandData, delta: *mut u64) -> u32;
    fn vibeos_jent_raw_health(collector: *mut RandData) -> u32;
}

struct Collector(*mut RandData);

impl Drop for Collector {
    fn drop(&mut self) {
        unsafe { jent_entropy_collector_free(self.0) };
    }
}

#[no_mangle]
pub extern "C" fn vibeos_jent_zalloc(len: usize) -> *mut u8 {
    let Ok(layout) = Layout::from_size_align(len, 64) else {
        return ptr::null_mut();
    };
    unsafe { alloc_zeroed(layout) }
}

#[no_mangle]
pub extern "C" fn vibeos_jent_zfree(allocation: *mut u8, len: usize) {
    if allocation.is_null() {
        return;
    }
    let Ok(layout) = Layout::from_size_align(len, 64) else {
        return;
    };
    unsafe { dealloc(allocation, layout) };
}

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn init_error_name(code: i32) -> &'static str {
    match code {
        0 => "ok",
        1 => "no-timer",
        2 => "coarse-timer",
        3 => "non-monotonic-timer",
        4 => "timer-min-variation",
        5 => "timer-variation-of-variation",
        6 => "timer-min-variation-of-variation",
        7 => "programming-error",
        8 => "timer-stuck",
        9 => "health-test",
        10 => "rct-health-test",
        11 => "hash-self-test",
        12 => "memory",
        13 => "gcd-self-test",
        _ => "unknown",
    }
}

pub fn smoke() {
    let Some(_guard) = UseGuard::acquire() else {
        println!("VIBE_JENT_SMOKE FAIL reason=busy");
        return;
    };
    let version = unsafe { jent_version() };
    let started = sbi::time();
    let init = unsafe { jent_entropy_init_ex(OSR, FLAGS) };
    let init_ticks = sbi::time().wrapping_sub(started);
    if init != 0 {
        println!(
            "VIBE_JENT_SMOKE FAIL version={} init={} reason={} ticks={}",
            version,
            init,
            init_error_name(init),
            init_ticks
        );
        return;
    }

    let collector = unsafe { jent_entropy_collector_alloc(OSR, FLAGS) };
    if collector.is_null() {
        println!(
            "VIBE_JENT_SMOKE FAIL version={} init=0 reason=collector-allocation ticks={}",
            version, init_ticks
        );
        return;
    }
    let collector = Collector(collector);
    let mut first = [0u8; SEED_BYTES];
    let mut second = [0u8; SEED_BYTES];
    let first_read = unsafe { jent_read_entropy(collector.0, first.as_mut_ptr(), first.len()) };
    let second_read = unsafe { jent_read_entropy(collector.0, second.as_mut_ptr(), second.len()) };
    let distinct = first != second;
    let pass = first_read == SEED_BYTES as isize && second_read == SEED_BYTES as isize && distinct;
    zeroize(&mut first);
    zeroize(&mut second);
    println!(
        "VIBE_JENT_SMOKE {} version={} init=0 read1={} read2={} distinct={} osr={} fips=forced internal_timer=disabled ticks={}",
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
        println!("VIBE_JENT_END FAIL samples=0 stuck=0 health=0x0 reason=busy");
        return;
    };
    let version = unsafe { jent_version() };
    println!(
        "VIBE_JENT_BEGIN version={} mode=raw-evidence samples={} osr={} internal_timer=disabled",
        version, samples, OSR
    );
    let mut deltas = Vec::new();
    if deltas.try_reserve_exact(samples).is_err() {
        println!("VIBE_JENT_END FAIL samples=0 stuck=0 health=0x0 reason=raw-buffer-allocation");
        return;
    }
    deltas.resize(samples, 0);
    let collector = unsafe { vibeos_jent_raw_alloc(OSR, FLAGS) };
    if collector.is_null() {
        println!("VIBE_JENT_END FAIL samples=0 stuck=0 health=0x0 reason=collector-allocation");
        return;
    }
    let collector = Collector(collector);
    let mut stuck = 0usize;
    for delta in &mut deltas {
        stuck += unsafe { vibeos_jent_raw_next(collector.0, delta) } as usize;
    }
    let health = unsafe { vibeos_jent_raw_health(collector.0) };
    drop(collector);
    for (index, delta) in deltas.iter().enumerate() {
        println!("VIBE_JENT_RAW {} {:016x}", index, delta);
    }
    println!(
        "VIBE_JENT_END {} samples={} stuck={} health={:#x}",
        if health == 0 {
            "COMPLETE"
        } else {
            "HEALTH-FAIL"
        },
        samples,
        stuck,
        health
    );
}
