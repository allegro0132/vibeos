//! Opt-in public application receive-call diagnostics. No payload is inspected.
//! Calls to the explicit-owner integration API alone are not counted. Timer
//! samples include interrupts and notifications: elapsed ticks, not CPU cycles.
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use crate::{TcpFrontendError, TcpIoResult, MAX_TCP_IO_BYTES_PER_CALL};

pub const INTERVAL: u64 = 127;
pub const FIELDS: usize = 11;
#[repr(align(128))]
struct Counters([AtomicU64; FIELDS]);
pub struct Recorder { paths: [Counters; 2] }
pub static RECORDER: Recorder = Recorder::new();
impl Recorder {
    const fn new() -> Self {
        Self { paths: [const { Counters([const { AtomicU64::new(0) }; FIELDS]) }; 2] }
    }
    pub fn begin(&self, exchanged: bool) -> Sample<'_> {
        let row = &self.paths[usize::from(exchanged)].0;
        let selected = row[0].fetch_add(1, Relaxed) % INTERVAL == 0;
        Sample { row, start: selected.then(vibeos_core::arch::time) }
    }
    pub fn snapshot(&self, exchanged: bool) -> [u64; FIELDS] {
        core::array::from_fn(|i| self.paths[usize::from(exchanged)].0[i].load(Relaxed))
    }
}
pub struct Sample<'a> { row: &'a [AtomicU64; FIELDS], start: Option<u64> }
impl Sample<'_> {
    pub fn finish(self, result: &Result<TcpIoResult, TcpFrontendError>, requested: usize) {
        // End the timing window before the diagnostic result accounting.
        let elapsed = self.start.map(|start| vibeos_core::arch::time().wrapping_sub(start));
        let field = match result {
            Ok(TcpIoResult::Progress(0)) => 4,
            Ok(TcpIoResult::Progress(length)) => {
                self.row[2].fetch_add(*length as u64, Relaxed);
                if *length < requested.min(MAX_TCP_IO_BYTES_PER_CALL) {
                    self.row[3].fetch_add(1, Relaxed);
                }
                1
            }
            Ok(TcpIoResult::WouldBlock) => 5,
            Ok(TcpIoResult::Closed) => 6,
            Err(_) => 7,
        };
        self.row[field].fetch_add(1, Relaxed);
        if let Some(ticks) = elapsed {
            self.row[8].fetch_add(1, Relaxed);
            self.row[9].fetch_add(ticks, Relaxed);
            self.row[10].fetch_max(ticks, Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn records_actual_bytes_and_distinguishes_short_and_nonprogress_reads() {
        let recorder = Recorder::new();
        for result in [Ok(TcpIoResult::Progress(32768)), Ok(TcpIoResult::Progress(17)),
            Ok(TcpIoResult::Progress(0)), Ok(TcpIoResult::WouldBlock),
            Ok(TcpIoResult::Closed), Err(TcpFrontendError::StaleConnection)] {
            recorder.begin(true).finish(&result, 65536);
        }
        let row = recorder.snapshot(true);
        assert_eq!(&row[..9], &[6, 2, 32785, 1, 1, 1, 1, 1, 1]);
        assert_eq!(recorder.snapshot(false), [0; FIELDS]);
    }
}
