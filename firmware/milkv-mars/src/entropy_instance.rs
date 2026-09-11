//! Firmware-owned PIO request lifecycle. This does not approve the source or
//! publish capabilities. The shared SEC owner remains retained after failures.
use vibeos_hal::entropy::{Error, Pending, Submission, MAX_RANDOM_BYTES};
use vibeos_platform_jh7110::security::{Domain, Registers as DomainRegisters};
use vibeos_starfive_trng::{Registers, Trng};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State { New, Ready, Faulted, Stopped }

pub struct Instance<D, R> {
    domain: Domain<D>,
    trng: Trng<R>,
    state: State,
    epoch: u64,
    pending: Pending<usize>,
    output: [u8; MAX_RANDOM_BYTES],
}
impl<D: DomainRegisters, R: Registers> Instance<D, R> {
    /// # Safety
    /// These are the sole owners of this SEC domain and its TRNG. All other
    /// SEC clients are relinquished, PLIC is masked, parents stay stable, and
    /// CRG access is serialized for the full lifetime, including quarantine.
    /// Retain this instance until shutdown confirms stop; do not drop a failed
    /// owner or construct a second view to recover it.
    pub unsafe fn new(domain: Domain<D>, trng: Trng<R>) -> Self {
        Self { domain, trng, state: State::New, epoch: 0,
            pending: Pending::new(), output: [0; MAX_RANDOM_BYTES] }
    }
    fn wipe(&mut self) {
        for byte in &mut self.output {
            unsafe { core::ptr::write_volatile(byte, 0); }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
    pub fn prepare(&mut self, epoch: u64) -> Result<(), Error> {
        if !matches!(self.state, State::New | State::Stopped) {
            return Err(Error::Quarantined);
        }
        if epoch == 0 || epoch <= self.epoch { return Err(Error::IdentityExhausted); }
        self.epoch = epoch;
        self.state = State::Faulted;
        self.domain.prepare().map_err(|_| Error::Quarantined)?;
        // Domain::prepare confirmed assertion and release. Reuse the same
        // child register owner and preserve its cross-reset output history.
        unsafe { self.trng.reset_observed(); }
        self.trng.initialize().map_err(|_| Error::Protocol)?;
        self.state = State::Ready;
        Ok(())
    }
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn operational(&self) -> bool { self.state == State::Ready }
    pub fn submit(&mut self, bytes: usize) -> Result<Submission, Error> {
        if !self.operational() { return Err(Error::DriverRestarted); }
        if bytes == 0 || bytes > MAX_RANDOM_BYTES { return Err(Error::InvalidLength); }
        let token = self.pending.reserve(self.epoch)?;
        // PIO commands are individually bounded by the driver's timer and poll
        // budget. At most two complete blocks; no caller buffer reaches hardware.
        for offset in (0..bytes).step_by(32) {
            match self.trng.read_block() {
                Ok(block) => {
                    let count = (bytes - offset).min(32);
                    self.output[offset..offset + count].copy_from_slice(&block[..count]);
                }
                Err(_) => {
                    self.wipe();
                    self.state = State::Faulted;
                    return Err(Error::Protocol);
                }
            }
        }
        self.pending.publish(token, bytes);
        Ok(token)
    }
    pub fn completion(&self, token: Submission) -> bool {
        self.operational() && self.pending.get(token).is_some()
    }
    pub fn finish(&mut self, token: Submission, out: &mut [u8]) -> Result<usize, Error> {
        if !self.operational() { return Err(Error::DriverRestarted); }
        let bytes = self.pending.get(token).ok_or(Error::DriverRestarted)?;
        if out.len() < bytes { return Err(Error::InvalidLength); }
        out[..bytes].copy_from_slice(&self.output[..bytes]);
        self.wipe();
        self.pending.clear();
        Ok(bytes)
    }
    pub fn require_reset(&mut self) { self.state = State::Faulted; }
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.state = State::Faulted;
        // &mut self excludes child calls; failed stop retains both owners and
        // pending state. No Drop path claims that hardware has stopped.
        unsafe { self.domain.stop() }.map_err(|_| Error::Quarantined)?;
        self.pending.clear();
        self.wipe();
        self.state = State::Stopped;
        Ok(())
    }
    pub fn reset_and_prepare(&mut self, epoch: u64) -> Result<(), Error> {
        if epoch == 0 || epoch <= self.epoch { return Err(Error::IdentityExhausted); }
        self.shutdown()?;
        self.prepare(epoch)
    }
}
