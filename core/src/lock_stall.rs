//! Opt-in deadlock evidence. Never unlocks, panics, allocates or enters the
//! scheduler/TTY. SBI output itself may still block if machine firmware is stuck.

pub(crate) struct Probe {
    started: Option<u64>,
    spins: u32,
    reported: bool,
}
impl Probe {
    pub(crate) const fn new() -> Self {
        Self { started: None, spins: 0, reported: false }
    }
    // Called only after failed acquisition. Sample the clock sparsely while
    // contending; uncontended acquisitions never read it or write output.
    pub(crate) fn check(&mut self) -> Option<u64> {
        if self.reported { return None; }
        self.spins = self.spins.wrapping_add(1);
        if self.started.is_some() && self.spins & 4095 != 0 { return None; }
        self.observe(crate::arch::time(), crate::exec::timebase_hz().saturating_mul(2))
    }
    fn observe(&mut self, now: u64, threshold: u64) -> Option<u64> {
        if self.reported { return None; }
        let start = *self.started.get_or_insert(now);
        let elapsed = now.wrapping_sub(start);
        if elapsed < threshold.max(1) { return None; }
        self.reported = true;
        Some(elapsed)
    }
}

fn byte(value: u8) {
    #[cfg(all(target_arch = "riscv64", target_os = "none"))]
    crate::arch::legacy_putchar(value);
    #[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
    let _ = value; // Host tests exercise detection, not target SBI output.
}
fn text(bytes: &[u8]) {
    for &value in bytes { byte(value); }
}
fn hex(value: u64) {
    text(b"0x");
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 15) as usize;
        byte(b"0123456789abcdef"[nibble]);
    }
}

/// Diagnostic sites whose loops run with supervisor interrupts masked.
#[derive(Clone, Copy)]
pub enum LoopStallKind {
    ExternalInterrupt,
    UartReceive,
}

/// Best-effort evidence only: does not mask a source, release a lock or reset
/// hardware. Like the lock probe, SBI output can itself block. It cannot see
/// a single MMIO access or callback that never returns.
pub struct LoopStallProbe {
    probe: Probe,
    kind: LoopStallKind,
    iterations: u64,
}

impl LoopStallProbe {
    pub const fn new(kind: LoopStallKind) -> Self {
        Self { probe: Probe::new(), kind, iterations: 0 }
    }

    /// Call once per iteration. `detail` is the interrupt source number;
    /// counts include successful iterations, not just failed operations.
    pub fn observe(&mut self, detail: u64) {
        self.iterations = self.iterations.saturating_add(1);
        if let Some(elapsed) = self.probe.check() {
            text(b"\r\nLOOP_STALL kind=");
            text(match self.kind {
                LoopStallKind::ExternalInterrupt => b"external_irq",
                LoopStallKind::UartReceive => b"uart_rx",
            });
            text(b" hart="); hex(crate::arch::current_hart_id() as u64);
            text(b" elapsed_ticks="); hex(elapsed);
            text(b" iterations="); hex(self.iterations);
            text(b" detail="); hex(detail);
            text(b"\r\n");
        }
    }
}
/// Best-effort independent atomic snapshots, not a transactional owner record.
/// Owner/key/state apply only to recoverable locks. Concurrent hart records may
/// interleave because acquiring an output lock would hide the deadlock.
pub(crate) fn report(lock: usize, elapsed: u64, recoverable: bool, state: u64, owner: u64, key: u64) {
    text(b"\r\nLOCK_STALL hart="); hex(crate::arch::current_hart_id() as u64);
    text(b" lock="); hex(lock as u64);
    text(b" elapsed_ticks="); hex(elapsed);
    text(b" recoverable="); hex(recoverable as u64);
    text(b" state="); hex(state);
    text(b" owner="); hex(owner);
    text(b" recovery_key="); hex(key);
    text(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::Probe;
    #[test]
    fn reports_only_after_threshold_and_once_per_acquisition() {
        let mut p = Probe::new();
        assert_eq!(p.observe(100, 20), None);
        assert_eq!(p.observe(119, 20), None);
        assert_eq!(p.observe(120, 20), Some(20));
        assert_eq!(p.observe(200, 20), None);
        let mut fresh = Probe::new();
        assert_eq!(fresh.observe(200, 20), None);
    }
    #[test]
    fn elapsed_handles_timer_wrap_and_zero_threshold_is_not_immediate() {
        let mut p = Probe::new();
        assert_eq!(p.observe(u64::MAX - 4, 10), None);
        assert_eq!(p.observe(4, 10), None);
        assert_eq!(p.observe(5, 10), Some(10));
        let mut zero = Probe::new();
        assert_eq!(zero.observe(0, 0), None);
        assert_eq!(zero.observe(1, 0), Some(1));
    }
}
