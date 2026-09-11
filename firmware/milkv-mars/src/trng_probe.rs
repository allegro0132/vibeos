//! One-shot, boot-hart-only hardware diagnostic. Never publishes entropy.
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use vibeos_driver_plic::{Mmio as PlicMmio, Registers as PlicRegisters};
use vibeos_platform_jh7110::{clock, security};
use vibeos_starfive_trng::{Mmio, Trng};

static CLAIMED: AtomicBool = AtomicBool::new(false);
struct Output(fn(&str));
impl fmt::Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        (self.0)(text);
        Ok(())
    }
}
fn print(write: fn(&str), args: fmt::Arguments<'_>) {
    let _ = fmt::write(&mut Output(write), args);
}
fn halt(write: fn(&str), args: fmt::Arguments<'_>) -> ! {
    print(write, args);
    vibeos_runtime_riscv::shutdown(true)
}
fn fence() {
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
}

/// # Safety
/// Called once after device mappings, before secondary harts/services. Boot
/// firmware must have relinquished ALL SEC clients and their DMA/interrupts.
/// This composition owns the entire shared domain; no crypto/security-DMA
/// driver is present. Shared root clocks remain stable through final stop.
pub unsafe fn run(write: fn(&str)) {
    if CLAIMED.swap(true, Ordering::AcqRel) {
        halt(
            write,
            format_args!("MARS_TRNG_PROBE FAIL duplicate invocation\n"),
        );
    }
    let boot = super::admission();
    let resources = boot.trng.expect("TRNG DTB admission");
    // Priority zero suppresses this source for every PLIC context, including
    // bootloader enable bits left in inactive contexts. No other IRQ is changed.
    let plic = PlicMmio::new(vibeos_bsp_milkv_mars::PLIC);
    fence();
    plic.write(resources.irq as usize * 4, 0);
    fence();
    if plic.read(resources.irq as usize * 4) != 0 {
        halt(write, format_args!("MARS_TRNG_PROBE FAIL interrupt mask\n"));
    }
    let hz = clock::stg_axiahb_hz(|bank, offset| {
        let range = match bank {
            clock::Bank::SysCrg => resources.sys_crg,
            clock::Bank::Syscon => boot.resources.syscon,
        };
        assert!(offset % 4 == 0 && offset <= range.len() - 4);
        fence();
        let value = ((range.start + offset) as *const u32).read_volatile();
        fence();
        value
    })
    .unwrap_or_else(|error| {
        halt(
            write,
            format_args!("MARS_TRNG_PROBE FAIL parent={error:?}\n"),
        )
    });
    let timebase = super::timebase_hz();
    let mut domain = security::Domain::new_exclusive(
        security::Mmio::new(resources.stg_crg, vibeos_runtime_riscv::time).unwrap(),
        timebase,
    )
    .unwrap();
    // Retain both owners on this stack until a confirmed stop, or SBI shutdown
    // on failure. There is no retry, dynamic registration or fallback source.
    let mut trng = Trng::new(
        Mmio::new(
            resources.registers.start,
            resources.registers.len(),
            vibeos_runtime_riscv::time,
        )
        .unwrap(),
        timebase,
        100_000,
    )
    .unwrap();
    let prepared = domain.prepare();
    let mut blocks = 0;
    let result = if prepared.is_ok() {
        trng.initialize().and_then(|()| {
            for _ in 0..2 {
                let _ = trng.read_block()?;
                blocks += 1;
            }
            Ok(())
        })
    } else {
        Err(vibeos_starfive_trng::Error::NotReady)
    };
    // No child can be invoked after this point. Even a prepare/protocol failure
    // requires explicit reset acknowledgement before child clocks are gated.
    let stopped = domain.stop();
    if prepared.is_err() || result.is_err() || stopped.is_err() {
        halt(write, format_args!("MARS_TRNG_PROBE FAIL parent_hz={hz} prepare={prepared:?} read={result:?} stop={stopped:?} blocks={blocks}\n"));
    }
    print(write, format_args!("MARS_TRNG_PROBE protocol-observed parent_hz={hz} blocks={blocks} stopped=true entropy=unqualified\n"));
}
