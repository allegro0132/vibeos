//! Bounded boot-output prefix. Allocation-free writers never acquire a lock.
//! A stalled writer leaves an unpublished slot; readers return the preceding
//! prefix rather than spin. Reservation order defines concurrent output order.
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};

pub struct BootLog<const N: usize> {
    reserved: AtomicUsize,
    truncated: AtomicBool,
    bytes: [AtomicU16; N],
}
impl<const N: usize> BootLog<N> {
    pub const fn new() -> Self {
        Self { reserved: AtomicUsize::new(0), truncated: AtomicBool::new(false),
            bytes: [const { AtomicU16::new(0) }; N] }
    }
    pub fn append(&self, data: &[u8]) {
        if data.is_empty() { return; }
        let start = match self.reserved.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |start| (start < N).then(|| start + data.len().min(N - start))) {
            Ok(start) => start,
            Err(_) => { self.truncated.store(true, Ordering::Relaxed); return; }
        };
        let count = data.len().min(N - start);
        if count < data.len() { self.truncated.store(true, Ordering::Relaxed); }
        // Publish the first byte last: observing it also observes the complete
        // reserved fragment. The high bit distinguishes an actual NUL from a gap.
        for i in (0..count).rev() {
            self.bytes[start+i].store(0x100 | u16::from(data[i]), Ordering::Release);
        }
    }
    pub fn truncated(&self) -> bool { self.truncated.load(Ordering::Relaxed) }
    /// Copy a committed prefix, bounded by both caller storage and reservation.
    /// Does not consume or reset the log; later reads can include more output.
    pub fn copy_into(&self, output: &mut [u8]) -> usize {
        let end = self.reserved.load(Ordering::Relaxed).min(output.len());
        for i in 0..end {
            let value = self.bytes[i].load(Ordering::Acquire);
            if value & 0x100 == 0 { return i; }
            output[i] = value as u8;
        }
        end
    }
}
impl<const N: usize> Default for BootLog<N> { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retains_prefix_and_reports_truncation_without_overwriting() {
        let log = BootLog::<5>::new(); let mut out = [0; 8];
        log.append(b"ab\0"); assert_eq!(log.copy_into(&mut out),3);
        assert!(!log.truncated()); log.append(b"cdef");log.append(b"later");
        assert_eq!(log.copy_into(&mut out),5);assert_eq!(&out[..5],b"ab\0cd");
        assert!(log.truncated());
        assert_eq!(log.copy_into(&mut [0;2]),2);
    }
    #[test]
    fn unpublished_writer_never_blocks_reader_or_exposes_later_fragment() {
        let log = BootLog::<8>::new(); let mut out = [0;8];
        log.append(b"ab");log.reserved.store(4,Ordering::Relaxed);
        log.append(b"ef"); assert_eq!(log.copy_into(&mut out),2);
        log.bytes[3].store(0x100|b'd' as u16,Ordering::Release);
        log.bytes[2].store(0x100|b'c' as u16,Ordering::Release);
        assert_eq!(log.copy_into(&mut out),6);assert_eq!(&out[..6],b"abcdef");
    }
    #[test]
    fn concurrent_fragments_are_complete_and_reads_are_repeatable() {
        let log = BootLog::<2048>::new();
        std::thread::scope(|scope| {
            for byte in [b'a',b'b',b'c',b'd'] {
                let log = &log;
                scope.spawn(move || { for _ in 0..64 { log.append(&[byte;8]); } });
            }
        });
        let mut out = [0;2048];assert_eq!(log.copy_into(&mut out),2048);
        for chunk in out.chunks_exact(8) { assert!(chunk.iter().all(|b|*b==chunk[0])); }
        for byte in [b'a',b'b',b'c',b'd'] {assert_eq!(out.iter().filter(|b|**b==byte).count(),512);}
        assert!(!log.truncated());let mut again=[0;2048];log.copy_into(&mut again);assert_eq!(again,out);
        let empty=BootLog::<0>::new();empty.append(b"x");assert!(empty.truncated());
    }
}
