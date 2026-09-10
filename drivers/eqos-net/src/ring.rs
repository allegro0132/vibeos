//! Serialized EQoS ring lifecycle. Hardware/cache operations are supplied by an
//! exclusively borrowed, permanently allocated backend, not by kernel policy.
use crate::descriptor::{self, OWN};

pub const STRIDE: usize = 64;
pub const BUFFER: usize = 1536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub tx_descriptors: u64,
    pub rx_descriptors: u64,
    pub tx_buffers: u64,
    pub rx_buffers: u64,
    pub count: usize,
    pub axi_bytes: usize,
}
impl Layout {
    pub fn validate(self) -> Result<(), Error> {
        if !(2..=1024).contains(&self.count)
            || descriptor::skip_length(STRIDE, self.axi_bytes).is_err()
        {
            return Err(Error::Layout);
        }
        let regions = [
            (self.tx_descriptors, self.count * STRIDE),
            (self.rx_descriptors, self.count * STRIDE),
            (self.tx_buffers, self.count * BUFFER),
            (self.rx_buffers, self.count * BUFFER),
        ];
        for (i, &(start, bytes)) in regions.iter().enumerate() {
            if start % STRIDE as u64 != 0
                || start
                    .checked_add(bytes as u64)
                    .is_none_or(|end| end > 1 << 32)
            {
                return Err(Error::Layout);
            }
            for &(other, size) in &regions[..i] {
                if start < other + size as u64 && other < start + bytes as u64 {
                    return Err(Error::Layout);
                }
            }
        }
        Ok(())
    }
    fn desc(self, rx: bool, index: usize) -> u64 {
        (if rx {
            self.rx_descriptors
        } else {
            self.tx_descriptors
        }) + (index * STRIDE) as u64
    }
    fn buffer(self, rx: bool, index: usize) -> u64 {
        (if rx { self.rx_buffers } else { self.tx_buffers }) + (index * BUFFER) as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Layout,
    Offline,
    Full,
    Packet,
    OutputTooSmall,
    Controller,
    Descriptor(descriptor::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ToDevice,
    FromDevice,
    Bidirectional,
}

/// # Safety
/// All admitted layout regions must refer to dedicated, permanently allocated,
/// CPU-accessible DMA memory. No other CPU may access or reuse that storage or
/// controller, even if the Ring is dropped while running/quarantined. Dropping
/// the borrowed handle never frees that memory. Descriptor accesses are volatile
/// little-endian words; buffer copies access exactly the requested bytes.
/// Caller packet/output slices are never retained after a copy returns.
/// Synchronization covers every cache level and the whole isolated region.
/// The backend must support independently synchronized 64-byte descriptor slots;
/// a larger cache-maintenance granule requires rejecting this layout profile.
/// Polling a descriptor may observe OWN but must not modify DMA-owned memory.
/// `barrier` orders memory/cache operations and MMIO tail publication.
/// `reset` and `stop` return true only after proving DMA cannot access any old
/// buffer/descriptor. Both must be bounded. `configure` does not start DMA;
/// it must reject layouts outside the backend's actual dedicated pool before
/// returning true. Arithmetic validation alone never authorizes a DMA address.
/// `start` uses the prepared rings with FCS retention and checksum/TSO disabled.
/// Errors may leave DMA active and must not release storage. Tail pointers use
/// the same 32-bit address domain as Layout; RX tail names the last returned slot.
pub unsafe trait Backend {
    fn reset(&mut self) -> bool;
    fn configure(&mut self, layout: Layout) -> bool;
    fn start(&mut self) -> bool;
    fn stop(&mut self) -> bool;
    fn read_word(&mut self, address: u64, word: usize) -> u32;
    fn write_word(&mut self, address: u64, word: usize, value: u32);
    fn copy_tx(&mut self, address: u64, packet: &[u8]);
    fn copy_rx(&mut self, address: u64, output: &mut [u8]);
    fn for_device(&mut self, address: u64, bytes: usize, direction: Direction);
    fn for_cpu(&mut self, address: u64, bytes: usize, direction: Direction);
    fn barrier(&mut self);
    fn tail(&mut self, rx: bool, address: u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Offline,
    Running,
    Quarantined,
}

pub struct Ring<B: Backend + 'static> {
    backend: &'static mut B,
    layout: Layout,
    state: State,
    producer: usize,
    consumer: usize,
    pending: usize,
    receive: usize,
}

impl<B: Backend> Ring<B> {
    /// No hardware access occurs until initialization. The Backend's unsafe
    /// contract, not physical-address arithmetic alone, establishes pool ownership.
    pub fn new(backend: &'static mut B, layout: Layout) -> Result<Self, Error> {
        layout.validate()?;
        Ok(Self {
            backend,
            layout,
            state: State::Offline,
            producer: 0,
            consumer: 0,
            pending: 0,
            receive: 0,
        })
    }
    /// Release the backend only before first DMA start or after a successful
    /// shutdown. A running/quarantined ring retains exclusive pool ownership.
    pub fn into_stopped_backend(self) -> Result<&'static mut B, Self> {
        if self.state == State::Offline {
            Ok(self.backend)
        } else {
            Err(self)
        }
    }
    pub(crate) fn stopped_backend(&mut self) -> Option<&mut B> {
        if self.state == State::Offline {
            Some(self.backend)
        } else {
            None
        }
    }
    pub fn initialize(&mut self) -> Result<(), Error> {
        if self.state == State::Running {
            return Err(Error::Controller);
        }
        self.state = State::Quarantined;
        if !self.backend.reset() || !self.backend.configure(self.layout) {
            return Err(Error::Controller);
        }
        self.producer = 0;
        self.consumer = 0;
        self.pending = 0;
        self.receive = 0;
        for i in 0..self.layout.count {
            let tx = self.layout.desc(false, i);
            for word in 0..4 {
                self.backend.write_word(tx, word, 0);
            }
            self.backend
                .for_device(tx, STRIDE, Direction::Bidirectional);
            self.arm_rx(i);
        }
        self.backend.barrier();
        self.backend.tail(false, self.layout.tx_descriptors);
        self.backend
            .tail(true, self.layout.desc(true, self.layout.count - 1));
        if !self.backend.start() {
            return Err(Error::Controller);
        }
        self.state = State::Running;
        Ok(())
    }
    fn publish(&mut self, address: u64, words: [u32; 4]) {
        for (index, value) in words.into_iter().enumerate() {
            self.backend.write_word(address, index, value);
        }
        self.backend
            .for_device(address, STRIDE, Direction::Bidirectional);
        self.backend.barrier();
        self.backend.write_word(address, 3, words[3] | OWN);
        self.backend
            .for_device(address, STRIDE, Direction::Bidirectional);
        self.backend.barrier();
    }
    fn arm_rx(&mut self, index: usize) {
        let buffer = self.layout.buffer(true, index);
        self.backend
            .for_device(buffer, BUFFER, Direction::FromDevice);
        self.publish(
            self.layout.desc(true, index),
            descriptor::rx(buffer, BUFFER).unwrap(),
        );
    }
    fn snapshot(&mut self, rx: bool, index: usize) -> [u32; 4] {
        let address = self.layout.desc(rx, index);
        self.backend
            .for_cpu(address, STRIDE, Direction::Bidirectional);
        self.backend.barrier();
        let status = self.backend.read_word(address, 3);
        // Only word 3 is needed by the codec. RX write-back words 0/1 must never
        // replace the private buffer mapping with device-controlled addresses.
        [0, 0, 0, status]
    }
    fn running(&self) -> Result<(), Error> {
        if self.state == State::Running {
            Ok(())
        } else {
            Err(Error::Offline)
        }
    }
    pub fn pending(&self) -> usize {
        self.pending
    }
    pub fn quarantined(&self) -> bool {
        self.state == State::Quarantined
    }
    pub fn reap(&mut self) -> Result<usize, Error> {
        self.running()?;
        let mut completed = 0;
        while self.pending != 0 {
            let words = self.snapshot(false, self.consumer);
            match descriptor::tx_complete(words) {
                Ok(false) => break,
                Err(error) => {
                    self.state = State::Quarantined;
                    return Err(Error::Descriptor(error));
                }
                Ok(true) => {
                    self.backend.for_cpu(
                        self.layout.buffer(false, self.consumer),
                        BUFFER,
                        Direction::ToDevice,
                    );
                    self.pending -= 1;
                    self.consumer = (self.consumer + 1) % self.layout.count;
                    completed += 1;
                }
            }
        }
        Ok(completed)
    }
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.running()?;
        // Validate the whole packet before any DMA or controller operation.
        let buffer = self.layout.buffer(false, self.producer);
        let words = descriptor::tx(buffer, packet.len()).map_err(|_| Error::Packet)?;
        self.reap()?;
        // Reserve one slot so an exclusive TX tail never aliases the DMA head
        // merely because software filled an otherwise empty circular ring.
        if self.pending == self.layout.count - 1 {
            return Err(Error::Full);
        }
        self.backend.copy_tx(buffer, packet);
        self.backend.for_device(buffer, BUFFER, Direction::ToDevice);
        self.publish(self.layout.desc(false, self.producer), words);
        self.pending += 1;
        self.producer = (self.producer + 1) % self.layout.count;
        self.backend
            .tail(false, self.layout.desc(false, self.producer));
        Ok(())
    }
    /// At most one descriptor is consumed per call, including malformed frames.
    /// A small output drops that frame and returns its slot to DMA without a copy.
    pub fn receive(&mut self, output: &mut [u8]) -> Result<Option<usize>, Error> {
        self.running()?;
        let words = self.snapshot(true, self.receive);
        let result = descriptor::rx_complete(words, BUFFER);
        if result == Ok(None) {
            return Ok(None);
        }
        let buffer = self.layout.buffer(true, self.receive);
        self.backend.for_cpu(buffer, BUFFER, Direction::FromDevice);
        let result = match result {
            Ok(Some(bytes)) if bytes <= output.len() => {
                self.backend.copy_rx(buffer, &mut output[..bytes]);
                Ok(Some(bytes))
            }
            Ok(Some(_)) => Err(Error::OutputTooSmall),
            Err(error) => Err(Error::Descriptor(error)),
            Ok(None) => unreachable!(),
        };
        self.arm_rx(self.receive);
        self.backend
            .tail(true, self.layout.desc(true, self.receive));
        self.receive = (self.receive + 1) % self.layout.count;
        result
    }
    /// Explicit fault notification (including an external TX deadline). No
    /// descriptor or packet is retried/reused until reset has proved quiescence.
    pub fn fault(&mut self) {
        self.state = State::Quarantined;
    }
    pub fn shutdown(&mut self) -> bool {
        if self.state == State::Offline {
            return true;
        }
        if self.backend.stop() {
            self.state = State::Offline;
            self.pending = 0;
            true
        } else {
            self.state = State::Quarantined;
            false
        }
    }
}
