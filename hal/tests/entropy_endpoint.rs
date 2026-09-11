//! Execute the real kernel endpoint/engine adapter with an independently owned
//! entropy provider. Deliberately no VIBEOS_DEVICE_TRANSPORT symbol is defined.
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use vibeos_hal::{device_transport::{Descriptor, Kind}, entropy::*};
#[path = "../../kernel/src/entropy_device.rs"]
mod adapter;
static DISCOVERY: AtomicUsize = AtomicUsize::new(0);
static PREPARED: AtomicUsize = AtomicUsize::new(0);
fn description() -> Descriptor {
    Descriptor { kind: Kind::Entropy, slot: 2, base: 0x1600c000, irq: 30, vendor_id: 7 }
}
#[no_mangle]
static VIBEOS_ENTROPY_DEVICE: EntropyDevice = EntropyDevice {
    discover: || match DISCOVERY.load(SeqCst) {
        0 => Some(description()),
        1 => Some(Descriptor { kind: Kind::Block, ..description() }),
        _ => None,
    },
    resource_kind: "test-native-entropy",
    transport_name: "test native instance",
    quiesce: |d, budget| {
        assert_eq!(d, description());
        // Hardware-only quiesce does not change the software owner marker.
        budget > 0
    },
    completion_mode: CompletionMode::Polling,
    queue_size: 1,
    backing: Backing::DriverOwned,
    prepare: |slot, base, epoch, budget| {
        assert_eq!((slot, base, epoch, budget), (2, 0x1600c000, 3, 10));
        PREPARED.store(1, SeqCst);
        Ok(())
    },
    start: || Ok(()),
    epoch: || 3,
    accepted_features: || 0,
    operational: || true,
    submit: |_| Err(Error::Unsupported),
    completion: |_| false,
    finish: |_, _| Err(Error::Unsupported),
    require_reset: || {},
    reset_and_prepare: |_, _| Err(Error::Unsupported),
    shutdown: |_| Err(Error::Unsupported),
    confirmed_reset: |_, _, _| { PREPARED.store(0, SeqCst); true },
    acknowledge: |base| {
        assert_eq!(base, 0x1600c000);
        Events { completion: true, state_changed: false }
    },
};

#[test]
fn native_endpoint_needs_no_shared_transport_and_preserves_owner_on_quiesce() {
    assert!(matches!(adapter::backing(), Backing::DriverOwned));
    let endpoint = unsafe { adapter::Endpoint::discover() }.unwrap();
    assert_eq!((endpoint.slot(), endpoint.base(), endpoint.irq(), endpoint.vendor_id()), (2, 0x1600c000, 30, 7));
    let engine = unsafe { adapter::Engine::prepare(endpoint, 3, 10) }.unwrap();
    assert!(engine.start().is_ok());
    assert_eq!(engine.epoch(), 3);
    assert!(!endpoint.quiesce(0));
    assert!(endpoint.quiesce(10));
    assert_eq!(PREPARED.load(SeqCst), 1);
    assert!(endpoint.acknowledge_interrupt().completion);
    assert_eq!(PREPARED.load(SeqCst), 1);
    unsafe { assert!(adapter::confirmed_reset(endpoint, 10)); }
    assert_eq!(PREPARED.load(SeqCst), 0);
    DISCOVERY.store(1, SeqCst);
    assert!(unsafe { adapter::Endpoint::discover() }.is_none());
    DISCOVERY.store(2, SeqCst);
    assert!(unsafe { adapter::Endpoint::discover() }.is_none());
}
