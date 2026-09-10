//! DWMAC composition with static DMA ownership and state-free telemetry.
use super::Board;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use vibeos_driver_dwmac_net::{self as driver, DmaStorage, Engine, InstanceState};
use vibeos_hal::{
    network::{Device, Error},
    Board as _,
};
#[cfg_attr(target_arch = "riscv64", link_section = ".dma")]
static DMA: DmaStorage = DmaStorage::new();
static INSTANCE: InstanceState = InstanceState::new();
struct EngineStorage(UnsafeCell<Option<Engine>>);
// SAFETY: operations require the kernel's exclusive incarnation. Claim and
// release additionally fence access to the firmware's instance slot.
unsafe impl Sync for EngineStorage {}
static ENGINE: EngineStorage = EngineStorage(UnsafeCell::new(None));
static CLAIMED: AtomicBool = AtomicBool::new(false);
unsafe fn engine() -> &'static mut Engine {
    (*ENGINE.0.get()).as_mut().expect("claimed packet device")
}
const DESC: vibeos_hal::DwmacDescription = Board::INFO.dwmac.unwrap();
#[no_mangle]
pub static VIBEOS_PACKET_DEVICE: Device = Device {
    present: true,
    registers: DESC.registers,
    irq: DESC.irq,
    rx_queue_size: driver::RX_RING_SIZE,
    dma_base: || driver::dma_region_base(&DMA),
    telemetry: || unsafe { driver::telemetry(DESC, &INSTANCE, &PLATFORM) },
    claim: |mac, time, hz| unsafe {
        CLAIMED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        match Engine::claim(DESC, &PLATFORM, &DMA, &INSTANCE, mac, time, hz) {
            Ok(e) => {
                *ENGINE.0.get() = Some(e);
                Ok(())
            }
            Err(e) => {
                CLAIMED.store(false, Ordering::Release);
                Err(e)
            }
        }
    },
    tx_owned: || unsafe { engine().tx_owned() },
    transmit: |packet| unsafe { engine().transmit(packet) },
    receive: |output| unsafe { engine().receive(output) },
    poll_link: || unsafe { engine().poll_link() },
    shutdown: || unsafe {
        let reset = (*ENGINE.0.get()).take().is_some_and(Engine::shutdown);
        if reset {
            CLAIMED.store(false, Ordering::Release);
        }
        reset
    },
    recover: || unsafe {
        // A faulted instance must never run Drop: it could reset hardware
        // after a replacement claims it. Recovery owns quiescence instead.
        vibeos_hal::devices::abandon_faulted_instance(&mut *ENGINE.0.get());
        let reset = driver::recover_faulted(DESC, &INSTANCE);
        if reset {
            *ENGINE.0.get() = None;
            CLAIMED.store(false, Ordering::Release);
        }
        reset
    },
};

unsafe fn ethernet(
    time: fn() -> u64,
    hz: u64,
) -> Result<
    vibeos_platform_cv1800b::ethernet::Ethernet<vibeos_platform_cv1800b::ethernet::Mmio>,
    Error,
> {
    use vibeos_bsp_milkv_duo::{
        EFUSE_BASE, EFUSE_MMIO_END, SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END,
    };
    use vibeos_hal::AddressRange;
    Ok(vibeos_platform_cv1800b::ethernet::Ethernet(
        vibeos_platform_cv1800b::ethernet::Mmio::new(
            AddressRange::new(SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
            AddressRange::new(EFUSE_BASE, EFUSE_MMIO_END),
            hz,
            time,
        )?,
    ))
}
static PLATFORM: vibeos_hal::network::Platform = vibeos_hal::network::Platform {
    prepare: |time, hz| unsafe {
        ethernet(time, hz)?.prepare();
        Ok(())
    },
    telemetry: || unsafe {
        ethernet(|| 0, Board::INFO.timebase_hz)
            .expect("valid Ethernet platform wiring")
            .telemetry()
    },
    dma: &vibeos_platform_cv1800b::cache::DMA,
};
