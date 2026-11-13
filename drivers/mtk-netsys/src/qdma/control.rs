//! Terminal QDMA TX lifecycle. Stop never releases or reinitializes storage.
use super::Io;
use crate::Error;
const CONFIG: usize = 0x4604;
const MASK: usize = 0x461c;
const ENABLE: u32 = 0x45;
const BUSY: u32 = 0xa;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Prepared,
    Running,
    Closed,
}
pub struct Control {
    state: State,
}
impl Control {
    /// Hardware and permanent storage must have passed stopped preparation.
    pub fn prepared() -> Self {
        Self {
            state: State::Prepared,
        }
    }
    pub fn used(&self) -> bool {
        self.state != State::Prepared
    }
    pub fn running(&self) -> bool {
        self.state == State::Running
    }
    pub fn start(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.state != State::Prepared
            || io.reg(0x6a04) & 1 != 0
            || io.reg(CONFIG) & (ENABLE | BUSY) != 0
        {
            return Err(Error::Busy);
        }
        // NETSYS v3 flags (Linux v6.12 mtk_start_dma). QDMA RX remains off.
        let flags = (1 << 28)
            | (1 << 26)
            | (1 << 24)
            | (0x40 << 16)
            | (4 << 12)
            | (1 << 11)
            | (1 << 10)
            | (3 << 4)
            | 0x41;
        io.barrier();
        io.set_reg(CONFIG, (io.reg(CONFIG) & !ENABLE) | flags);
        io.barrier();
        self.state = State::Running;
        if io.reg(CONFIG) & ENABLE != 0x41 {
            self.close(io);
            return Err(Error::Malformed);
        }
        Ok(())
    }
    /// Close software admission first; disable IRQs and both DMA directions.
    /// This is only a shutdown request, not evidence that hardware is idle.
    pub fn close(&mut self, io: &mut impl Io) {
        self.state = State::Closed;
        io.set_reg(MASK, 0);
        io.set_reg(CONFIG, io.reg(CONFIG) & !ENABLE);
        io.barrier();
    }
    /// Wait boundedly for disabled/idle readback. Pending packets may be
    /// abandoned; this is not lossless drain or physical-wire completion.
    /// Success AND failure are terminal: retain all buffers/descriptors.
    pub fn stop(
        &mut self,
        io: &mut impl Io,
        timeout: u64,
        mut now: impl FnMut() -> u64,
    ) -> Result<(), Error> {
        self.close(io);
        let start = now();
        loop {
            let config = io.reg(CONFIG);
            if config & ENABLE != 0 || io.reg(MASK) != 0 {
                return Err(Error::Malformed);
            }
            if config & BUSY == 0 {
                io.barrier();
                return Ok(());
            }
            if now().wrapping_sub(start) >= timeout {
                return Err(Error::Timeout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    struct Mock {
        config: u32,
        mask: u32,
        pdma: u32,
        busy: Cell<usize>,
        ignore_disable: bool,
        writes: usize,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                config: 0x55404530,
                mask: 0,
                pdma: 4,
                busy: Cell::new(0),
                ignore_disable: false,
                writes: 0,
            }
        }
    }
    impl Io for Mock {
        fn read(&self, _: usize, _: usize) -> u32 {
            panic!("lifecycle must not inspect descriptors")
        }
        fn write(&mut self, _: usize, _: usize, _: u32) {
            panic!("lifecycle must retain descriptors")
        }
        fn reg(&self, o: usize) -> u32 {
            match o {
                CONFIG => {
                    let busy = self.busy.get();
                    self.busy.set(busy.saturating_sub(1));
                    self.config | if busy > 0 { BUSY } else { 0 }
                }
                MASK => self.mask,
                0x6a04 => self.pdma,
                _ => panic!("unexpected register"),
            }
        }
        fn set_reg(&mut self, o: usize, v: u32) {
            self.writes += 1;
            match o {
                CONFIG => {
                    if !self.ignore_disable || v & ENABLE != 0 {
                        self.config = v & !BUSY;
                    }
                }
                MASK => self.mask = v,
                _ => panic!("unexpected write"),
            }
        }
        fn barrier(&self) {}
    }
    #[test]
    fn stop_after_busy_clears_is_terminal_and_never_reinitializes_memory() {
        let mut io = Mock::new();
        let mut c = Control::prepared();
        c.start(&mut io).unwrap();
        io.busy.set(4);
        let mut tick = u64::MAX - 2;
        assert_eq!(
            c.stop(&mut io, 10, || {
                tick = tick.wrapping_add(1);
                tick
            }),
            Ok(())
        );
        assert!(!c.running());
        assert!(c.used());
        assert_eq!(io.config & ENABLE, 0);
        let writes = io.writes;
        assert_eq!(c.start(&mut io), Err(Error::Busy));
        assert_eq!(io.writes, writes);
    }
    #[test]
    fn timeout_and_ignored_disable_never_report_quiescence() {
        let mut io = Mock::new();
        let mut c = Control::prepared();
        c.start(&mut io).unwrap();
        io.busy.set(100);
        let mut tick = u64::MAX - 2;
        assert_eq!(
            c.stop(&mut io, 5, || {
                tick = tick.wrapping_add(1);
                tick
            }),
            Err(Error::Timeout)
        );
        assert!(!c.running());
        assert_eq!(io.config & ENABLE, 0);
        assert!(tick < 10);
        io.busy.set(0);
        assert_eq!(c.start(&mut io), Err(Error::Busy));
        let mut io = Mock::new();
        let mut c = Control::prepared();
        c.start(&mut io).unwrap();
        io.ignore_disable = true;
        assert_eq!(c.stop(&mut io, 5, || 0), Err(Error::Malformed));
        assert!(!c.running());
    }
    #[test]
    fn close_without_wait_never_reopens_and_live_pdma_prevents_start() {
        let mut io = Mock::new();
        let mut c = Control::prepared();
        io.pdma = 0x45;
        assert_eq!(c.start(&mut io), Err(Error::Busy));
        assert_eq!(io.writes, 0);
        io.pdma = 4;
        c.start(&mut io).unwrap();
        c.close(&mut io);
        assert!(!c.running());
        assert_eq!(c.start(&mut io), Err(Error::Busy));
    }
}
