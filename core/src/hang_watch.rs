//! Optional cross-hart timer-stall evidence. No scheduler, allocator or TTY locks.
//! Snapshots are best-effort independent atomic fields, not stopped-hart dumps.
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct Hart {
    timer: AtomicU64,
    trap: AtomicU64,
    pc: AtomicUsize,
    cause: AtomicUsize,
    stage: AtomicUsize,
    irq: AtomicUsize,
    reported: AtomicU64,
}
impl Hart {
    const fn new() -> Self {
        Self {
            timer: AtomicU64::new(0),
            trap: AtomicU64::new(0),
            pc: AtomicUsize::new(0),
            cause: AtomicUsize::new(0),
            stage: AtomicUsize::new(0),
            irq: AtomicUsize::new(0),
            reported: AtomicU64::new(0),
        }
    }
    fn claim_report(&self, now: u64, threshold: u64) -> Option<u64> {
        let last = self.timer.load(Ordering::Acquire);
        if last == 0 || now.saturating_sub(last) < threshold.max(1) {
            return None;
        }
        let old = self.reported.load(Ordering::Relaxed);
        if old == last {
            return None;
        }
        self.reported
            .compare_exchange(old, last, Ordering::AcqRel, Ordering::Relaxed)
            .ok()?;
        Some(last)
    }
}
static HARTS: [Hart; crate::exec::MAX_HARTS] = [const { Hart::new() }; crate::exec::MAX_HARTS];

/// Stage: 1 trap entry, 2 timer, 3 PLIC claim loop, 4 IRQ callback,
/// 5 trap return, 6 synchronous exception. PC is the LAST interrupted PC,
/// never claimed to be the target hart's current stopped instruction.
pub fn enter(hart: usize, now: u64, cause: usize, pc: usize) {
    let Some(slot) = HARTS.get(hart) else {
        return;
    };
    slot.pc.store(pc, Ordering::Relaxed);
    slot.cause.store(cause, Ordering::Relaxed);
    slot.irq.store(0, Ordering::Relaxed);
    slot.stage.store(1, Ordering::Relaxed);
    slot.trap.store(now, Ordering::Release);
}
pub fn stage(hart: usize, value: usize, irq: usize) {
    if let Some(slot) = HARTS.get(hart) {
        slot.irq.store(irq, Ordering::Relaxed);
        slot.stage.store(value, Ordering::Release);
    }
}

/// Call before the timer handler takes ANY registry/scheduler lock. A healthy
/// idle hart has a 10-second timer backstop. Allow three periods before reporting.
/// Requires some other hart and SBI console to remain functional. A silent log
/// does not prove liveness; this never resets or unlocks the target.
pub fn timer(hart: usize, now: u64) {
    let Some(own) = HARTS.get(hart) else {
        return;
    };
    own.timer.store(now, Ordering::Release);
    let threshold = crate::exec::timebase_hz().saturating_mul(30);
    for (target, slot) in HARTS.iter().enumerate() {
        if target == hart {
            continue;
        }
        if let Some(last) = slot.claim_report(now, threshold) {
            text(b"\r\nHART_STALL observer_logical=");
            hex(hart as u64);
            text(b" target_logical=");
            hex(target as u64);
            text(b" timer_age_ticks=");
            hex(now.saturating_sub(last));
            text(b" last_trap_ticks=");
            hex(slot.trap.load(Ordering::Acquire));
            text(b" last_pc=");
            hex(slot.pc.load(Ordering::Relaxed) as u64);
            text(b" last_cause=");
            hex(slot.cause.load(Ordering::Relaxed) as u64);
            text(b" stage=");
            hex(slot.stage.load(Ordering::Acquire) as u64);
            text(b" irq=");
            hex(slot.irq.load(Ordering::Relaxed) as u64);
            text(b"\r\n");
        }
    }
    #[cfg(all(
        feature = "hang-watchdog-selftest",
        target_arch = "riscv64",
        target_os = "none"
    ))]
    selftest_pause(hart, now);
}

/// Separate diagnostic image only. Stall logical hart 1 once, before taking
/// any timer/scheduler lock, so live peers can validate the reporting path.
/// This tests one stalled hart, NOT the all-hart/global-lock blind spot.
#[cfg(all(
    feature = "hang-watchdog-selftest",
    target_arch = "riscv64",
    target_os = "none"
))]
fn selftest_pause(hart: usize, now: u64) {
    static FIRST_TIMER: AtomicU64 = AtomicU64::new(0);
    static STARTED: AtomicUsize = AtomicUsize::new(0);
    if hart != 1 {
        return;
    }
    let hz = crate::exec::timebase_hz();
    if hz == 0 || now == 0 {
        return;
    }
    let first = match FIRST_TIMER.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => return,
        Err(first) => first,
    };
    if now.saturating_sub(first) < hz.saturating_mul(60)
        || STARTED
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    text(b"\r\nHART_SELFTEST_BEGIN target_logical=");
    hex(hart as u64);
    text(b" timer_ticks=");
    hex(now);
    text(b"\r\n");
    // Trap entry has SIE clear. No registry lock, allocation, reset or shared
    // state mutation is held across this bounded delay. Keep other harts live.
    let start = crate::arch::time();
    while crate::arch::time().wrapping_sub(start) < hz.saturating_mul(45) {
        core::hint::spin_loop();
    }
    text(b"\r\nHART_SELFTEST_END target_logical=");
    hex(hart as u64);
    text(b" elapsed_ticks=");
    hex(crate::arch::time().wrapping_sub(start));
    text(b"\r\n");
}
fn byte(value: u8) {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    crate::arch::legacy_putchar(value);
    #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
    let _ = value;
}

/// Preserve the otherwise silent ready-notification failure before shutdown.
/// Uses only SBI byte output; like stall reports this can itself block in SBI.
/// No retry, reset-policy change, allocation or ordinary console lock.
pub fn ipi_failure(target: usize, physical: Option<usize>, error: crate::arch::IpiError) {
    struct Console;
    impl core::fmt::Write for Console {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            text(s.as_bytes());
            Ok(())
        }
    }
    let _ = format_ipi_failure(&mut Console, target, physical, error);
}

fn format_ipi_failure(
    out: &mut impl core::fmt::Write,
    target: usize,
    physical: Option<usize>,
    error: crate::arch::IpiError,
) -> core::fmt::Result {
    write!(out, "\r\nIPI_SEND_FAILED target_logical={target} target_physical={physical:?} error={error:?}\r\n")
}
fn text(value: &[u8]) {
    for &b in value {
        byte(b);
    }
}
fn hex(value: u64) {
    text(b"0x");
    for shift in (0..16).rev() {
        byte(b"0123456789abcdef"[((value >> (shift * 4)) & 15) as usize]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipi_failure_preserves_target_mapping_and_unknown_error() {
        extern crate std;
        let mut output = std::string::String::new();
        format_ipi_failure(&mut output, 2, Some(4), crate::arch::IpiError::Unknown(-37)).unwrap();
        assert_eq!(output, "\r\nIPI_SEND_FAILED target_logical=2 target_physical=Some(4) error=Unknown(-37)\r\n");
    }
    #[test]
    fn uninitialized_future_and_recent_harts_do_not_report() {
        let h = Hart::new();
        assert_eq!(h.claim_report(100, 30), None);
        h.timer.store(101, Ordering::Release);
        assert_eq!(h.claim_report(100, 30), None);
        assert_eq!(h.claim_report(130, 30), None);
        assert_eq!(h.claim_report(131, 30), Some(101));
    }
    #[test]
    fn one_report_per_heartbeat_and_recovery_rearms() {
        let h = Hart::new();
        h.timer.store(10, Ordering::Release);
        assert_eq!(h.claim_report(40, 30), Some(10));
        assert_eq!(h.claim_report(80, 30), None);
        h.timer.store(81, Ordering::Release);
        assert_eq!(h.claim_report(82, 30), None);
        assert_eq!(h.claim_report(111, 30), Some(81));
    }
    #[test]
    fn concurrent_observers_report_a_stall_once() {
        extern crate std;
        let h = std::sync::Arc::new(Hart::new());
        h.timer.store(10, Ordering::Release);
        let threads: std::vec::Vec<_> = (0..8)
            .map(|_| {
                let h = h.clone();
                std::thread::spawn(move || h.claim_report(40, 30).is_some())
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().unwrap().then_some(()))
                .count(),
            1
        );
    }
}
