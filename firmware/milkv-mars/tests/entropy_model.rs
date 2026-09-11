//! Shared host/RV64 lifecycle model. No noise or physical reset proof.
use core::cell::Cell;
use vibeos_firmware_milkv_mars::entropy_instance::Instance;
use vibeos_hal::entropy::Error;
use vibeos_platform_jh7110::security;
use vibeos_starfive_trng::{Registers, Trng};
struct Model {
    words: [Cell<u32>; 26],
    gates: [Cell<u32>; 2],
    reset: Cell<u32>,
    stop_fails: Cell<bool>,
    repeat: Cell<bool>,
    generated: Cell<u32>,
    fail_at: Cell<u32>,
}
impl Model {
    const fn new() -> Self {
        Self { words: [const { Cell::new(0) }; 26], gates: [const { Cell::new(0) }; 2],
            reset: Cell::new(0), stop_fails: Cell::new(false), repeat: Cell::new(false),
            generated: Cell::new(0), fail_at: Cell::new(u32::MAX) }
    }
    fn instance(&self) -> Instance<Crg<'_>, Rng<'_>> {
        unsafe { Instance::new(security::Domain::new_exclusive(Crg(self), 4000).unwrap(),
            Trng::new(Rng(self), 4000, 8).unwrap()) }
    }
}
struct Crg<'a>(&'a Model);
impl security::Registers for Crg<'_> {
    fn read(&mut self, o: usize) -> u32 {
        match o { 0x3c => self.0.gates[0].get(), 0x40 => self.0.gates[1].get(),
            0x74 => self.0.reset.get(), 0x78 => if self.0.stop_fails.get() { 8 } else { !self.0.reset.get() },
            _ => panic!("CRG read") }
    }
    fn write(&mut self, o: usize, v: u32) {
        match o { 0x3c => self.0.gates[0].set(v), 0x40 => self.0.gates[1].set(v),
            0x74 => {
                self.0.reset.set(v);
                if v & 8 != 0 && !self.0.stop_fails.get() {
                    for w in &self.0.words { w.set(0); }
                    self.0.words[1].set(256); self.0.words[3].set(256);
                }
            }, _ => panic!("CRG write") }
    }
    fn ticks(&mut self) -> u64 { 0 } // frozen timer must still respect poll cap
}
struct Rng<'a>(&'a Model);
impl Registers for Rng<'_> {
    fn read(&mut self, o: usize) -> u32 { self.0.words[o / 4].get() }
    fn write(&mut self, o: usize, v: u32) {
        let m = self.0;
        match o {
            8 => { m.words[2].set(v); m.words[1].set(m.words[1].get() | (v & 8)); },
            20 => m.words[5].set(m.words[5].get() & !v),
            0 => {
                assert_eq!(m.words[5].get(), 0);
                m.words[1].set(m.words[1].get() | 512); m.words[5].set(v);
                if v == 1 {
                    let n = m.generated.get() + 1; m.generated.set(n);
                    if n == m.fail_at.get() { m.words[5].set(16); }
                    for w in &m.words[8..16] { w.set(if m.repeat.get() { 0x1020304 } else { n }); }
                }
            }, _ => m.words[o / 4].set(v),
        }
    }
    fn ticks(&mut self) -> u64 { 0 }
}

pub fn run() {
    table_model();
    let m = Model::new(); let mut i = m.instance();
    assert_eq!(i.prepare(0), Err(Error::IdentityExhausted));
    i.prepare(1).unwrap(); assert!(i.operational()); assert_eq!(i.epoch(), 1);
    assert_eq!(i.submit(0), Err(Error::InvalidLength));
    assert_eq!(i.submit(65), Err(Error::InvalidLength));
    let a = i.submit(64).unwrap(); assert!(i.completion(a));
    assert_eq!(i.submit(1), Err(Error::Busy));
    let mut out = [0xaa; 65];
    assert_eq!(i.finish(a, &mut out[..63]), Err(Error::InvalidLength));
    assert_eq!(out, [0xaa; 65]); assert!(i.completion(a));
    assert_eq!(i.finish(a, &mut out), Ok(64)); assert_eq!(out[64], 0xaa);
    assert_eq!(&out[..4], &[1, 0, 0, 0]); assert_eq!(&out[32..36], &[2, 0, 0, 0]);
    assert!(!i.completion(a)); assert_eq!(i.finish(a, &mut out), Err(Error::DriverRestarted));
    let old = i.submit(1).unwrap();
    i.reset_and_prepare(2).unwrap(); assert!(!i.completion(old));
    let new = i.submit(1).unwrap(); assert!(new.serial > old.serial); assert_eq!(new.epoch, 2);
    assert_eq!(i.finish(old, &mut out), Err(Error::DriverRestarted));
    i.finish(new, &mut out).unwrap();
    assert_eq!(i.reset_and_prepare(2), Err(Error::IdentityExhausted));
    assert!(i.operational());
    let pending = i.submit(1).unwrap(); i.require_reset(); assert!(!i.completion(pending));
    m.stop_fails.set(true);
    assert_eq!(i.reset_and_prepare(3), Err(Error::Quarantined));
    assert!(!i.operational()); assert_eq!(i.epoch(), 2);
    assert_eq!(i.prepare(3), Err(Error::Quarantined));
    assert_eq!(i.submit(1), Err(Error::DriverRestarted));
    m.stop_fails.set(false); i.reset_and_prepare(3).unwrap();
    assert!(!i.completion(pending)); i.shutdown().unwrap();

    // Failure in the second block must publish neither a completion nor a prefix.
    let m = Model::new(); m.fail_at.set(2); let mut i = m.instance(); i.prepare(1).unwrap();
    assert_eq!(i.submit(64), Err(Error::Protocol)); assert!(!i.operational());
    assert_eq!(i.prepare(2), Err(Error::Quarantined)); i.shutdown().unwrap();
    i.prepare(2).unwrap(); let t = i.submit(1).unwrap(); assert_eq!(t.serial, 2);
    i.shutdown().unwrap();

    // Hardware reset cannot erase repeated-output history in the software owner.
    let m = Model::new(); m.repeat.set(true); let mut i = m.instance(); i.prepare(1).unwrap();
    let t = i.submit(32).unwrap(); i.finish(t, &mut [0; 32]).unwrap();
    i.reset_and_prepare(2).unwrap(); assert_eq!(i.submit(32), Err(Error::Protocol));
    i.shutdown().unwrap();
}
#[test]
fn native_request_lifecycle() { run(); }

// Execute the exact production table with the same Instance and modeled IO.
// Only this test invocation accesses the static owner; IRQ/quiesce do not.
#[path = "../src/entropy.rs"]
mod provider;
pub const ENTROPY_DEVICE: vibeos_hal::entropy::EntropyDevice = provider::DEVICE;
type NativeEntropyInstance = Instance<Crg<'static>, Rng<'static>>;
fn entropy_description() -> Option<vibeos_hal::device_transport::Descriptor> {
    Some(vibeos_hal::device_transport::Descriptor {
        kind: vibeos_hal::device_transport::Kind::Entropy,
        slot: 0, base: 0x1600c000, irq: 30, vendor_id: 0,
    })
}
struct StaticModel(core::cell::UnsafeCell<Model>);
unsafe impl Sync for StaticModel {}
static TABLE_MODEL: StaticModel = StaticModel(core::cell::UnsafeCell::new(Model::new()));
fn table_model() { unsafe {
    use vibeos_hal::entropy::{Backing, CompletionMode, Events, SourceApproval};
    let table = &ENTROPY_DEVICE;
    let source = (table.discover)().unwrap();
    assert_eq!(source.approval, SourceApproval::DiagnosticOnly);
    assert_eq!(source.endpoint, entropy_description().unwrap());
    assert!(matches!(table.backing, Backing::DriverOwned));
    assert_eq!(table.completion_mode, CompletionMode::Polling);
    assert_eq!(table.queue_size, 1);
    assert!(!(table.operational)());
    assert_eq!((table.prepare)(0, 0x1600c000, 1, provider::POLL_BUDGET), Err(Error::Unsupported));
    let m = &*TABLE_MODEL.0.get();
    provider::install(m.instance());
    assert_eq!((table.epoch)(), 0);
    assert!(!(table.operational)());
    assert_eq!(m.generated.get(), 0);
    assert_eq!(m.reset.get(), 0);
    assert_eq!(m.gates[0].get(), 0);
    assert_eq!(m.gates[1].get(), 0);
    assert_eq!((table.prepare)(1, 0x1600c000, 1, provider::POLL_BUDGET), Err(Error::Unsupported));
    assert_eq!((table.prepare)(0, 0x1600d000, 1, provider::POLL_BUDGET), Err(Error::Unsupported));
    assert_eq!((table.prepare)(0, 0x1600c000, 1, 0), Err(Error::Unsupported));
    assert_eq!(m.reset.get(), 0); // invalid resources/budget performed no reset
    (table.prepare)(0, 0x1600c000, 1, provider::POLL_BUDGET).unwrap();
    (table.start)().unwrap(); assert_eq!((table.epoch)(), 1);
    assert_eq!((table.accepted_features)(), 0);
    let first = (table.submit)(64).unwrap(); assert!((table.completion)(first));
    assert!(!(table.quiesce)(source.endpoint, provider::POLL_BUDGET));
    assert_eq!((table.acknowledge)(source.endpoint.base), Events::default());
    assert!((table.completion)(first)); // neither callback changed pending state
    let mut out = [0; 64]; assert_eq!((table.finish)(first, &mut out), Ok(64));
    assert_eq!(&out[..4], &[1, 0, 0, 0]); assert_eq!(&out[32..36], &[2, 0, 0, 0]);
    let old = (table.submit)(1).unwrap(); (table.require_reset)();
    assert!(!(table.completion)(old));
    m.stop_fails.set(true);
    assert!(!(table.confirmed_reset)(0, 0x1600c000, provider::POLL_BUDGET));
    assert_eq!((table.start)(), Err(Error::DriverRestarted));
    m.stop_fails.set(false);
    assert!(!(table.confirmed_reset)(1, 0x1600c000, provider::POLL_BUDGET));
    assert!((table.confirmed_reset)(0, 0x1600c000, provider::POLL_BUDGET));
    (table.prepare)(0, 0x1600c000, 2, provider::POLL_BUDGET).unwrap();
    let new = (table.submit)(1).unwrap(); assert!(new.serial > old.serial);
    assert!(!(table.completion)(old));
    assert_eq!((table.finish)(old, &mut out), Err(Error::DriverRestarted));
    (table.finish)(new, &mut out).unwrap();
    (table.reset_and_prepare)(3, provider::POLL_BUDGET).unwrap();
    assert_eq!((table.epoch)(), 3);
    (table.shutdown)(provider::POLL_BUDGET).unwrap(); assert!(!(table.operational)());
    assert_eq!((table.discover)().unwrap().approval, SourceApproval::DiagnosticOnly);
} }
