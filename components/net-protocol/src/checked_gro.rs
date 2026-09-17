//! Stable bounded DMA loan slots. Select and validate a prefix only while the
//! synchronous token callback borrows its original bytes; never extend a borrow
//! across a slot mutation or move a validated packet into a different owner.
use smoltcp::phy::{ChecksumCapabilities, TcpGroBuilder, TcpGroReject, TcpGroRx};
use vibeos_core::net_receive::{Loan, ReleaseBatch};
use crate::gro::{self, MAX_SEGMENTS};

pub struct Window {
    slots: [Option<Loan>; MAX_SEGMENTS],
    head: usize,
    len: usize,
    consumed: usize,
}

impl Window {
    pub fn new() -> Self {
        Self { slots: core::array::from_fn(|_| None), head: 0, len: 0, consumed: 0 }
    }
    pub fn len(&self) -> usize { self.len }
    pub fn has_pending(&self) -> bool { self.len > self.consumed }
    pub fn push(&mut self, loan: Loan) {
        assert!(self.len < MAX_SEGMENTS);
        let slot = (self.head + self.len) % MAX_SEGMENTS;
        debug_assert!(self.slots[slot].is_none());
        self.slots[slot] = Some(loan);
        self.len += 1;
    }
    pub fn retire(&mut self) {
        let mut batch = ReleaseBatch::<MAX_SEGMENTS>::new();
        for _ in 0..self.consumed {
            let loan = self.slots[self.head].take().expect("admitted loan");
            if let Err(loan) = batch.push(loan) { drop(loan); }
            self.head = (self.head + 1) % MAX_SEGMENTS;
            self.len -= 1;
        }
        self.consumed = 0;
    }
    pub fn clear(&mut self) { self.consumed = self.len; self.retire(); }
}

impl Drop for Window {
    fn drop(&mut self) { self.clear(); }
}

pub struct Token<'a> {
    pub window: &'a mut Window,
    pub stats: &'a mut gro::Buffer,
    pub caps: ChecksumCapabilities,
    #[cfg(feature = "gro-end-profile")]
    pub no_input: gro::NoInput,
}

impl Token<'_> {
    pub fn consume<R>(self, caps: &ChecksumCapabilities,
        f: impl FnOnce(TcpGroRx<'_>, &[&[u8]]) -> R) -> R
    {
        let mut frames = [&[][..]; MAX_SEGMENTS];
        for (i, frame) in frames[..self.window.len].iter_mut().enumerate() {
            *frame = self.window.slots[(self.window.head + i) % MAX_SEGMENTS]
                .as_ref().expect("admitted loan").as_bytes();
        }
        let first = frames[0];
        let Some(mut builder) = TcpGroBuilder::new(first, caps) else {
            self.window.consumed = 1;
            self.stats.record_checked(0, 0);
            return f(TcpGroRx::Frame(first), &frames[..1]);
        };
        let mut reason = if first[47] & 8 != 0 { 1 } else { 7 };
        for frame in &frames[1..self.window.len] {
            if builder.is_finished() { break; }
            match builder.push(frame) {
                Ok(()) => {
                    reason = if frame[47] & 8 != 0 { 1 }
                        else if frame[16..18] != first[16..18] { 2 } else { 7 };
                }
                Err(error) => {
                    reason = match error {
                        TcpGroReject::Ineligible => 4,
                        TcpGroReject::Incompatible => 5,
                        TcpGroReject::Capacity | TcpGroReject::Finished => 7,
                    };
                    break;
                }
            }
        }
        let count = builder.segment_count();
        if !builder.is_finished() && count == self.window.len {
            reason = 3;
            #[cfg(feature = "gro-end-profile")]
            self.stats.profile_no_input(self.no_input);
        }
        self.window.consumed = count;
        self.stats.record_checked(count, reason);
        let received = match builder.finish() {
            Some(group) => TcpGroRx::Group(group),
            None => TcpGroRx::Frame(first),
        };
        f(received, &frames[..count])
    }
}

impl Drop for Token<'_> {
    fn drop(&mut self) {
        // A consumer may discard a token. Advance one frame rather than retry
        // it forever; the remaining prefetched frames retain their order.
        if self.window.consumed == 0 { self.window.consumed = 1; }
    }
}
