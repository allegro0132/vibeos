//! Exercise the actual kernel USB adapter and IRQ-install rollback on the host.
use std::sync::{Mutex,atomic::{AtomicBool,AtomicUsize,Ordering::SeqCst}};
use vibeos_hal::{usb::*,AddressRange};
mod sync{pub struct SpinLock<T>(std::sync::Mutex<T>);impl<T> SpinLock<T>{pub const fn new(v:T)->Self{Self(std::sync::Mutex::new(v))}pub fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}}
static WAIT_REGISTERED:AtomicBool=AtomicBool::new(false);
static WAKES:AtomicUsize=AtomicUsize::new(0);
mod exec{pub struct WaitQueue;impl WaitQueue{pub const fn new()->Self{Self}pub fn wait(&self)->core::future::Pending<()>{super::WAIT_REGISTERED.store(true,super::SeqCst);core::future::pending()}pub fn wake_all(&self){super::WAKES.fetch_add(1,super::SeqCst);}}}
static INPUT:Mutex<Vec<u8>>=Mutex::new(Vec::new());
mod uart{pub fn inject_usb_input(byte:u8){super::INPUT.lock().unwrap().push(byte);}}
mod platform{pub struct Pci{pub mmio:vibeos_hal::AddressRange}pub fn pci()->Pci{Pci{mmio:vibeos_hal::AddressRange::new(0x1000,0x2000)}}}
mod pci{
    pub use vibeos_hal::pci::Bar;
    pub fn find_xhci()->Option<vibeos_hal::pci::Function>{Some(vibeos_hal::pci::Function{
        address:vibeos_hal::pci::Address{bus:0,device:1,function:0},vendor_id:1,device_id:2,class:12,subclass:3,programming_interface:0x30,revision:0,header_type:0,interrupt_pin:1,interrupt_line:Some(5),
        bars:[Bar::Memory32{address:0x1000,size:0x1000,prefetchable:false},Bar::None,Bar::None,Bar::None,Bar::None,Bar::None]})}
    pub fn enable_bus_mastering(_:vibeos_hal::pci::Function)->Result<(),()>{Ok(())}
}
static FAIL_REGISTER:AtomicBool=AtomicBool::new(true);
static FAIL_ENABLE:AtomicBool=AtomicBool::new(true);
static HANDLER:Mutex<Option<(fn(usize,u64),usize)>>=Mutex::new(None);
mod plic{
    pub fn register(irq:u32,h:fn(usize,u64),context:usize)->Result<(),()>{assert_eq!(irq,5);if super::FAIL_REGISTER.swap(false,super::SeqCst){return Err(());}*super::HANDLER.lock().unwrap()=Some((h,context));Ok(())}
    pub fn enable(_:u32)->Result<(),()>{if super::FAIL_ENABLE.swap(false,super::SeqCst){Err(())}else{Ok(())}}
    pub fn unregister(_:u32){*super::HANDLER.lock().unwrap()=None;}
}
#[path="../../kernel/src/xhci.rs"]mod adapter;
static ENABLED:AtomicBool=AtomicBool::new(false);
static DISABLED:AtomicUsize=AtomicUsize::new(0);
static INITIALIZES:AtomicUsize=AtomicUsize::new(0);
fn info()->Info{Info{version:0x110,mmio_base:0x1000,max_slots:8,max_ports:4,connected_ports:1,addressed_devices:1,irq:5}}
#[no_mangle]
static VIBEOS_USB_HOST:Host=Host{
    initialize:|mmio,irq|{assert_eq!((mmio.base(),mmio.length(),irq),(0x1000,0x1000,5));INITIALIZES.fetch_add(1,SeqCst);Ok(info())},info,
    devices:|_|{},interrupt_context:||0xabcd,enable_interrupts:||{ENABLED.store(true,SeqCst);},disable_interrupts:||{ENABLED.store(false,SeqCst);DISABLED.fetch_add(1,SeqCst);},
    acknowledge:|context|{assert_eq!(context,0xabcd);true},read_sector:|sector|{assert_eq!(sector,7);Ok([42;512])},
    write_sector:|sector,bytes|{assert_eq!(sector,8);assert_eq!(bytes,&[17;512]);Ok(())},
    service:||{assert!(WAIT_REGISTERED.load(SeqCst));let mut batch=HidInputBatch::new();batch.push(b'x');batch.push(b'\n');batch},
};
#[test]
fn irq_failures_remain_unpublished_and_retry_preserves_input_and_storage(){
    assert_eq!(adapter::info(),None);assert!(adapter::devices().is_empty());
    assert_eq!(adapter::read_sector(7),Err(adapter::Error::Driver(Error::NoMassStorage)));
    assert_eq!(adapter::init(),Err(adapter::Error::InterruptRoute));assert_eq!(DISABLED.load(SeqCst),1);assert_eq!(adapter::info(),None);
    assert_eq!(adapter::init(),Err(adapter::Error::InterruptRoute));assert_eq!(DISABLED.load(SeqCst),2);assert!(!ENABLED.load(SeqCst));assert!(HANDLER.lock().unwrap().is_none());
    assert_eq!(adapter::init(),Ok(Some(info())));assert!(ENABLED.load(SeqCst));assert_eq!(adapter::info(),Some(info()));
    assert_eq!(adapter::init(),Ok(Some(info())));assert_eq!(INITIALIZES.load(SeqCst),3);
    assert_eq!(adapter::read_sector(7),Ok([42;512]));adapter::write_sector(8,&[17;512]).unwrap();
    use core::{future::Future,task::{Context,Waker,Poll}};
    let mut service=std::pin::pin!(adapter::service_task());
    assert!(matches!(service.as_mut().poll(&mut Context::from_waker(Waker::noop())),Poll::Pending));
    assert_eq!(&*INPUT.lock().unwrap(),b"x\n");
    let(h,context)=HANDLER.lock().unwrap().unwrap();h(context,0);assert_eq!(WAKES.load(SeqCst),1);
}
