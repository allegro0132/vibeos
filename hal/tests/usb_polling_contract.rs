//! Runs the actual kernel polling adapter with a scripted host. This cannot
//! validate CV1800B MMIO, cache maintenance, DMA, or physical USB timing.
#![allow(dead_code, unused_imports)]
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    Mutex,
};
use vibeos_hal::usb_polling::*;
mod sync {
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {
        pub const fn new(v: T) -> Self {
            Self(std::sync::Mutex::new(v))
        }
        pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
            self.0.lock().unwrap()
        }
    }
}
#[macro_export]
macro_rules! println { ($($t:tt)*) => { std::println!($($t)*) }; }
mod platform {
    pub fn timebase_hz() -> u64 {
        4_000_000
    }
}
mod sbi {
    pub fn time() -> u64 {
        123
    }
}
mod exec {
    pub async fn sleep_ms(ms: u64) {
        super::SLEEPS.lock().unwrap().push(ms);
        core::future::pending::<()>().await;
    }
}
mod uart {
    pub fn inject_usb_input(b: u8) {
        super::INPUT.lock().unwrap().push(b);
    }
}
#[path = "../../kernel/src/dwc2_host.rs"]
mod adapter;
static INITIALIZES: AtomicUsize = AtomicUsize::new(0);
static CONNECTED: AtomicBool = AtomicBool::new(true);
static ENUMERATED: AtomicBool = AtomicBool::new(false);
static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static INPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static SLEEPS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
fn info() -> Info {
    Info {
        core_id: 0x4f54280a,
        release: 0x280a,
        irq: 30,
        host_channels: 8,
        dynamic_fifo: true,
        dma_architecture: 2,
        fifo_depth_words: 1024,
        dedicated_fifos: false,
    }
}
fn device() -> Option<DeviceInfo> {
    if ENUMERATED.load(SeqCst) {
        Some(DeviceInfo {
            address: 1,
            speed: Speed::High,
            usb_version: 0x200,
            device_class: 0,
            vendor_id: 1,
            product_id: 2,
            max_packet_size_0: 64,
            configuration_count: 1,
        })
    } else {
        None
    }
}
fn keyboard() -> Option<HidKeyboardInfo> {
    device().map(|_| HidKeyboardInfo {
        interface: 0,
        endpoint_in: 0x81,
        max_packet_size: 8,
        interval_ms: 10,
        protocol: HidKeyboardProtocol::Boot,
    })
}
fn telemetry() -> Telemetry {
    Telemetry {
        clock_enable_1: 0,
        clock_enable_2: 0,
        role_override: 0,
        gusbcfg: 0,
        hprt0: 0,
        phy_utmi_control: 0,
    }
}
#[no_mangle]
static VIBEOS_POLLING_USB_HOST: Host = Host {
    initialize: |hz, time| {
        assert_eq!((hz, time()), (4_000_000, 123));
        if INITIALIZES.fetch_add(1, SeqCst) == 0 {
            Err(Error::CoreResetTimedOut)
        } else {
            Ok(info())
        }
    },
    connected: || CONNECTED.load(SeqCst),
    info,
    device,
    keyboard,
    telemetry,
    network_bus_path: || {
        Some(UsbBusPath {
            ports: [1, 0, 0, 0, 0],
            depth: 1,
        })
    },
    snapshot: || Snapshot {
        info: info(),
        connected: CONNECTED.load(SeqCst),
        device: device(),
        child: None,
        children: [None; MAX_HUB_CHILDREN],
        hub: None,
        hubs: [None; MAX_HUB_CHILDREN],
        configuration: None,
        configurations: [None; MAX_DEVICE_CONFIGURATIONS],
        configuration_device_address: None,
        report_descriptor: None,
        keyboard: keyboard(),
        keyboard_device_address: None,
        mass_storage: None,
        storage_device_address: None,
        cdc_ecm: None,
        cdc_ecm_device_address: None,
        telemetry: telemetry(),
    },
    enumerate_device: || {
        EVENTS.lock().unwrap().push("enumerate");
        ENUMERATED.store(CONNECTED.load(SeqCst), SeqCst);
        Ok(device())
    },
    configure_hid_keyboard: || {
        EVENTS.lock().unwrap().push("hid");
        Ok(keyboard())
    },
    configure_mass_storage: || {
        EVENTS.lock().unwrap().push("storage");
        Ok(None)
    },
    switch_rtl8151_install_mode: || {
        EVENTS.lock().unwrap().push("switch");
        Ok(false)
    },
    configure_cdc_ecm: || {
        EVENTS.lock().unwrap().push("ecm");
        Ok(None)
    },
    receive_cdc_ecm: |out| {
        out[..3].copy_from_slice(b"net");
        Ok(3)
    },
    transmit_cdc_ecm: |frame| {
        assert_eq!(frame, b"frame");
        Err(Error::Nak)
    },
    poll_cdc_ecm_carrier: || {
        Ok(CdcCarrierStatus {
            link_up: Some(true),
            rtl815x_phystatus: None,
        })
    },
    read_sector: |sector| {
        assert_eq!(sector, 9);
        Ok([42; 512])
    },
    write_sector: |sector, bytes| {
        assert_eq!(sector, 9);
        assert_eq!(bytes, &[42; 512]);
        Ok(())
    },
    hub_topology_changed: || Ok(false),
    poll_keyboard: || {
        let mut b = HidInputBatch::new();
        b.push(b'x');
        Ok(b)
    },
};
#[test]
fn initialization_publication_and_class_policy_survive_composition() {
    assert_eq!(adapter::info(), None);
    assert_eq!(adapter::read_sector(9), Err(Error::NoDevice));
    assert_eq!(adapter::init(), Err(Error::CoreResetTimedOut));
    assert_eq!(adapter::info(), None);
    assert_eq!(adapter::init(), Ok(info()));
    assert_eq!(adapter::init(), Ok(info()));
    assert_eq!(INITIALIZES.load(SeqCst), 2);
    let mut service = Box::pin(adapter::service_task());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(service.as_mut(), &mut context).is_pending());
    assert_eq!(
        *EVENTS.lock().unwrap(),
        ["enumerate", "hid", "switch", "ecm", "storage"]
    );
    assert_eq!(*INPUT.lock().unwrap(), b"x");
    assert_eq!(*SLEEPS.lock().unwrap(), [10]);
    assert_eq!(adapter::snapshot().unwrap().device, device());
    assert_eq!(adapter::network_bus_path().unwrap().ports[0], 1);
    let bytes = adapter::read_sector(9).unwrap();
    adapter::write_sector(9, &bytes).unwrap();
    let mut frame = [0; 3];
    assert_eq!(adapter::receive_cdc_ecm(&mut frame), Ok(3));
    assert_eq!(&frame, b"net");
    assert_eq!(adapter::transmit_cdc_ecm(b"frame"), Err(Error::Nak));
    assert_eq!(adapter::poll_cdc_ecm_carrier().unwrap().link_up, Some(true));
}
#[test]
fn descriptor_lengths_and_input_batch_are_bounded() {
    assert_eq!(
        HidReportDescriptor::new(0, 256, [0; 256], 257),
        Err(Error::InvalidDescriptor)
    );
    assert_eq!(
        HidReportDescriptor::new(0, 256, [42; 256], 256)
            .unwrap()
            .as_slice(),
        &[42; 256]
    );
    let mut batch = HidInputBatch::new();
    for i in 0..30 {
        batch.push(i);
    }
    assert_eq!(batch.as_slice(), &(0..18).collect::<Vec<_>>());
}
