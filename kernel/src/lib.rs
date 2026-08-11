//! VibeOS — a capability-secure, single-address-space, async-first kernel.
//!
//! Three bets, all visible in this ~1800-line v0.1:
//!
//!   1. Authority is a *capability*, never a name. No paths, no uids, no root.
//!   2. Isolation is a *type system*, not a page table. Components share one
//!      address space; the compiler, not the MMU, is the enforcement boundary.
//!   3. Concurrency is a *future*, not a thread. Nothing blocks, nothing gets
//!      preempted, and an interrupt costs a queue push instead of a context
//!      switch.

#![no_std]
#![feature(alloc_error_handler)]
#![cfg_attr(not(feature = "legacy-shell"), allow(dead_code))]

#[cfg(all(feature = "tcp-echo", not(feature = "qemu-virt")))]
compile_error!("feature `tcp-echo` is the QEMU-only N1 acceptance image");
#[cfg(all(feature = "net-shell", not(feature = "milkv-duo")))]
compile_error!("feature `net-shell` is the Milk-V Duo production IPv4 image");
#[cfg(all(feature = "net-shell", feature = "tcp-echo"))]
compile_error!("features `net-shell` and `tcp-echo` are mutually exclusive IPv4 images");
#[cfg(all(feature = "ssh-security-test", not(feature = "qemu-virt")))]
compile_error!("feature `ssh-security-test` is the QEMU-only N3 acceptance image");
#[cfg(all(feature = "ssh-test", not(feature = "qemu-virt")))]
compile_error!("feature `ssh-test` is the QEMU-only N4 acceptance image");
#[cfg(all(feature = "milkv-ssh-acceptance", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-ssh-acceptance` is the Milk-V Duo hardware acceptance image");
#[cfg(all(feature = "milkv-ssh", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-ssh` is the Milk-V Duo production SSH image");
#[cfg(all(
    feature = "milkv-ssh",
    any(
        feature = "net-shell",
        feature = "milkv-ssh-acceptance",
        feature = "tcp-echo",
        feature = "ssh-test"
    )
))]
compile_error!("feature `milkv-ssh` must exclusively own the IPv4 stack");
#[cfg(all(feature = "milkv-jitterentropy-probe", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-jitterentropy-probe` is the Milk-V Duo hardware probe image");
#[cfg(all(feature = "milkv-jitterentropy-ssh-probe", not(feature = "milkv-duo")))]
compile_error!("feature `milkv-jitterentropy-ssh-probe` is a Milk-V Duo qualification image");
#[cfg(all(feature = "ssh-test", feature = "tcp-echo"))]
compile_error!("features `ssh-test` and `tcp-echo` are mutually exclusive acceptance images");
#[cfg(all(feature = "ssh-test", feature = "ssh-security-test"))]
compile_error!(
    "features `ssh-test` and `ssh-security-test` are mutually exclusive acceptance images"
);
#[cfg(all(
    feature = "milkv-ssh-acceptance",
    any(
        feature = "net-shell",
        feature = "tcp-echo",
        feature = "ssh-test",
        feature = "ssh-security-test"
    )
))]
compile_error!(
    "feature `milkv-ssh-acceptance` must exclusively own the IPv4 stack and SSH test policy"
);
#[cfg(all(
    feature = "milkv-jitterentropy-probe",
    any(
        feature = "net-shell",
        feature = "tcp-echo",
        feature = "ssh-test",
        feature = "ssh-security-test",
        feature = "milkv-ssh-acceptance"
    )
))]
compile_error!("feature `milkv-jitterentropy-probe` is an isolated UART qualification image");

extern crate alloc;

// Portable kernel logic lives in `vibeos-core`; the bare SBI seam lives in the
// RISC-V runtime. Re-export both under the names the rest of the tree uses.
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub use vibeos_core::arch as sbi;
pub use vibeos_core::net;
pub use vibeos_core::{cap, chan, exec, heap, interrupt, ipi, sync};
#[cfg(feature = "qemu-virt")]
pub use vibeos_driver_virtio_core as virtio;
pub use vibeos_durable_format as durable;
pub use vibeos_program_store as program;
pub use vibeos_random as random;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use vibeos_runtime_riscv as sbi;
pub use vibeos_vsh as vsh;
pub use vibeos_vsh::terminal;

mod bench_platform;
#[cfg(feature = "milkv-duo")]
mod board_led;
mod cap_table_pool;
mod code_pool;
mod dev;
#[path = "authority_store_platform.rs"]
mod durable_cspace;
#[cfg(any(
    feature = "milkv-jitterentropy-probe",
    feature = "milkv-jitterentropy-ssh-probe"
))]
mod jitterentropy_probe;
#[cfg(feature = "milkv-ssh")]
mod jitterentropy_random;
#[cfg(feature = "legacy-shell")]
mod legacy_shell;
mod mmu;
#[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
mod netstack_platform;
#[cfg(feature = "qemu-virt")]
mod pci;
mod platform;
mod plic;
mod rustc;
#[path = "program_store_platform.rs"]
mod saved_program;
#[path = "selftest_platform.rs"]
mod selftest;
#[cfg(any(
    feature = "ssh-security-test",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
mod ssh_platform;
#[cfg(feature = "milkv-ssh")]
mod ssh_provisioning;
pub use vibeos_object_store as store;
#[cfg(any(
    feature = "ssh-security-test",
    feature = "ssh-test",
    feature = "milkv-ssh-acceptance",
    feature = "milkv-ssh"
))]
pub use vibeos_ssh_identity as ssh_security;
mod block_device;
#[cfg(feature = "milkv-duo")]
mod dwmac_net;
#[cfg(feature = "milkv-duo")]
mod dwc2_host;
mod net_device;
#[cfg(feature = "milkv-duo")]
mod sdhci_blk;
mod store_platform;
mod trampoline;
mod trap;
mod tty;
mod uart;
#[cfg(feature = "qemu-virt")]
mod virtio_blk;
#[cfg(feature = "qemu-virt")]
use vibeos_driver_virtio_mmio as virtio_mmio;
#[cfg(feature = "qemu-virt")]
mod virtio_net;
#[cfg(feature = "qemu-virt")]
mod virtio_rng;
mod vsh_platform;
mod world;
#[cfg(feature = "qemu-virt")]
mod xhci;

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const KERNEL_STACK_STRIDE: usize = 256 * 1024;
const STACK_ABORT_RESERVE: usize = 8192;
const BOOT_HART_BIT: usize = 1;

// Release/acquire publication makes the boot hart's heap, hooks, and mapping
// reservations visible before a secondary touches shared kernel state.
static SECONDARY_BOOT_RELEASED: AtomicBool = AtomicBool::new(false);
// A bit is published only after the hart has a private stack, logical token,
// local trap vector, and timer. This is the real HSM completion barrier.
static KERNEL_READY_HARTS: AtomicUsize = AtomicUsize::new(0);

global_asm!(
    r#"
.option norvc
.section .text.boot
.global vibeos_kernel_start
vibeos_kernel_start:
    csrw sie, zero
    csrw sip, zero
    // Zero is the fail-closed "no logical hart" encoding. `mark_online`
    // installs logical_index + 1 after validating the firmware hartid.
    csrw sscratch, zero

    // OpenSBI passes the hart id in a0. S-mode cannot read mhartid, so retain
    // it in tp for IRQ routing now and hart-local state from M5.4 onward.
    mv tp, a0

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // OpenSBI chooses the coldboot hart dynamically. Firmware retains every
    // other hart in HSM STOPPED, so whichever physical id arrives here owns
    // logical slot 0 and performs the one global initialization pass.
    la sp, __stack_top

    // Zero .bss before any Rust runs.
    la t0, __bss_start
    la t1, __bss_end
.Lbss:
    bgeu t0, t1, .Ldone
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lbss
.Ldone:
    j kmain

.align 4
.global _secondary_start
_secondary_start:
    csrw sie, zero
    csrw sip, zero
    csrw sscratch, zero

    // HSM supplies the physical hartid in a0 and our logical index in a1.
    // Keep the physical id in tp and select the corresponding private stack
    // before making any Rust call.
    mv tp, a0

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    beqz a1, .Lsecondary_park
    li t0, 4
    bgeu a1, t0, .Lsecondary_park
    la t0, __stacks_bottom
    slli t1, a1, 18
    add sp, t0, t1
    li t1, 1
    slli t1, t1, 18
    add sp, sp, t1
    j secondary_kmain

.Lsecondary_park:
    wfi
    j .Lsecondary_park
"#
);

extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
    static __stack_bottom: u8;
    fn _secondary_start();
}

/// Lowest address a compiled program's current-hart stack may reach.
///
/// `__stack_bottom` is the first byte above logical hart 0's guard. Selecting
/// the fixed slot stride keeps generated-code probes inside the same private
/// mapped stack chosen by `_secondary_start`, with 8 KiB of mapped abort room
/// still below the returned floor.
pub fn stack_floor() -> usize {
    // Leave a band so the abort path itself has room to run.
    let hart =
        ipi::current_logical_hart().expect("compiled program stack requires a mapped logical hart");
    core::ptr::addr_of!(__stack_bottom) as usize
        + hart.index() * KERNEL_STACK_STRIDE
        + STACK_ABORT_RESERVE
}

/// Harts which have completed the complete VibeOS-local startup handshake.
pub fn online_hart_mask() -> usize {
    KERNEL_READY_HARTS.load(Ordering::Acquire)
}

pub fn online_hart_count() -> usize {
    online_hart_mask().count_ones() as usize
}

#[global_allocator]
pub static HEAP: heap::Heap = heap::Heap::new();

const BANNER: &str = r#"
   __   __ __  _           ____  ____
   \ \ / /(_)| |__   ___  / __ \/ ___|
    \ V / | || '_ \ / _ \| |  | \___ \
     \_/  |_||_.__/ \___/ \____/|____/   v0.1
"#;

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    uart::early_write("\r\n[VibeOS] entry\r\n");
    exec::configure_timebase(platform::TIMEBASE_HZ);
    let boot_time = sbi::time();
    #[cfg(not(feature = "legacy-shell"))]
    let _ = boot_time;
    let boot_physical_hart = sbi::current_hart_id();

    mmu::init_boot(boot_physical_hart);
    uart::early_write("[VibeOS] page tables ready\r\n");
    mmu::enable(exec::HartId::BOOT.index());
    uart::early_write("[VibeOS] Sv39 enabled\r\n");

    #[cfg(feature = "milkv-duo")]
    let blue_led = board_led::init();
    #[cfg(feature = "milkv-duo")]
    uart::early_write(if blue_led.on() {
        "[VibeOS] blue status LED on\r\n"
    } else {
        "[VibeOS] blue status LED readback failed\r\n"
    });

    uart::init();
    println!("{}", BANNER);
    println!(
        "  platform  {} ({} MHz timebase)",
        platform::NAME,
        platform::TIMEBASE_HZ / 1_000_000
    );
    #[cfg(feature = "milkv-duo")]
    println!(
        "  led       blue GPIOC24 {} (pinmux {:#x}, dir {:#010x}, data {:#010x}, input {:#010x})",
        if blue_led.on() { "on" } else { "FAILED" },
        blue_led.pinmux,
        blue_led.direction,
        blue_led.data,
        blue_led.external,
    );

    let (hs, he) = (
        core::ptr::addr_of!(__heap_start) as usize,
        core::ptr::addr_of!(__heap_end) as usize,
    );
    unsafe { HEAP.init(hs, he) };
    println!(
        "  heap      {:#x}..{:#x}  ({} KiB)",
        hs,
        he,
        (he - hs) / 1024
    );

    ipi::mark_online(exec::HartId::BOOT, boot_physical_hart)
        .expect("boot physical hart must have one logical scheduler identity");
    // Install the logical identity before any trap-local state can be used.
    trap::init_boot();
    KERNEL_READY_HARTS.store(BOOT_HART_BIT, Ordering::Release);
    exec::set_ready_notify_hook(ipi::notify_ready);
    println!(
        "  traps     stvec armed, PLIC ctx S/hart{}, IRQ {} enabled",
        boot_physical_hart,
        uart::UART_IRQ
    );

    // Install the complete fault boundary before World admits any reclaimable
    // component task. A tracked arena must never run without both hooks.
    exec::set_fault_guard(trampoline::guard_task);
    exec::set_fault_cleanup(cleanup_faulted_task);
    exec::set_fault_reclaimer(reclaim_faulted_component);

    let online = start_secondary_harts();
    println!("  smp       {} hart(s) online", online);
    assert_eq!(
        mmu::enabled_hart_mask(),
        online_hart_mask(),
        "every online hart must publish Sv39 readback"
    );
    println!(
        "  mmu       Sv39 single address space, hart mask {:#x}",
        mmu::enabled_hart_mask()
    );
    #[cfg(feature = "qemu-virt")]
    {
        let functions = pci::init().expect("QEMU PCI resource assignment must succeed");
        println!(
            "  pci       {} function(s), ECAM {:#x}, MMIO {:#x}..{:#x}",
            functions,
            platform::PCI_ECAM_START,
            platform::PCI_MMIO_START,
            platform::PCI_MMIO_END,
        );
        if let Some(info) = xhci::init().expect("QEMU XHCI initialization must succeed") {
            println!(
                "  usb       XHCI {:#06x} @ {:#x}, {} slot(s), {} port(s), {} device(s)",
                info.version,
                info.mmio_base,
                info.max_slots,
                info.max_ports,
                info.addressed_devices,
            );
        }
    }
    #[cfg(feature = "milkv-duo")]
    match dwc2_host::init() {
        Ok(info) => println!(
            "  usb       DWC2 {:#06x} @ {:#x}, IRQ {}, {} channel(s), port {}",
            info.release,
            platform::USB_BASE,
            info.irq,
            info.host_channels,
            if dwc2_host::connected() {
                "connected"
            } else {
                "powered/waiting"
            },
        ),
        Err(error) => println!("  usb       DWC2 bring-up FAILED: {:?}", error),
    }
    #[cfg(feature = "milkv-duo")]
    if let Some(usb) = dwc2_host::telemetry() {
        println!(
            "  usb regs  clocks {:#010x}/{:#010x}, role {:#010x}, GUSBCFG {:#010x}, HPRT {:#010x}, PHY14 {:#010x}",
            usb.clock_enable_1,
            usb.clock_enable_2,
            usb.role_override,
            usb.gusbcfg,
            usb.hprt0,
            usb.phy_utmi_control,
        );
    }
    assert!(
        mmu::wx_remote_fence_ready(),
        "multicore W^X requires the SBI RFENCE extension"
    );
    // Safety: cap_table_pool owns one page-exclusive region for the kernel
    // lifetime; its hooks validate exact live runs, synchronously perform the
    // all-hart PTE/TLB transition, and release only retired writable runs.
    cap::set_capability_table_backend(unsafe {
        cap::CapabilityTableBackend::new(
            cap_table_pool::allocate_pages,
            cap_table_pool::set_read_only,
            cap_table_pool::release_pages,
        )
    });
    let (code_start, code_end) = mmu::code_pool_range();
    println!(
        "  W^X       {} KiB code pool {:#x}..{:#x}, MXR clear, RFENCE ready",
        (code_end - code_start) / 1024,
        code_start,
        code_end
    );
    let (rodata_start, rodata_end) = mmu::rodata_range();
    println!(
        "  read-only {} KiB .rodata {:#x}..{:#x}; {} KiB COW capability-table pool",
        (rodata_end - rodata_start) / 1024,
        rodata_start,
        rodata_end,
        cap_table_pool::CAP_TABLE_POOL_BYTES / 1024,
    );

    world::build();

    let world = world::world();
    world::start_block_supervisor();
    world::start_net_supervisor();
    #[cfg(feature = "qemu-virt")]
    world::start_rng_supervisor();
    #[cfg(feature = "qemu-virt")]
    if xhci::info().is_some() {
        exec::spawn("usb-host", xhci::service_task());
    }
    #[cfg(any(feature = "tcp-echo", feature = "net-shell"))]
    world::start_ipv4_stack_supervisor();
    #[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]
    world::start_ssh_test_supervisor();
    #[cfg(feature = "legacy-shell")]
    world.spawn_component(
        "shell",
        world.spaces["init"].clone(),
        world::SHELL_MEMORY_BUDGET,
        legacy_shell::shell_task(boot_time),
    );
    #[cfg(not(feature = "legacy-shell"))]
    {
        let space = world.spaces["vsh"].clone();
        let mut session = vsh::Session::with_cspace(space.0.clone());
        vsh_platform::install_standard_commands(&mut session);
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command("tcp-fault", 0, 0, netstack_platform::vsh_inject_fault);
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command(
            "tcp-device-fault",
            0,
            0,
            netstack_platform::vsh_inject_driver_fault,
        );
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command("tcp-release", 0, 0, netstack_platform::vsh_release_stale);
        #[cfg(feature = "tcp-echo-recovery-test")]
        session.install_host_command("tcp-session", 0, 0, netstack_platform::vsh_session_info);
        world.spawn_component(
            "vsh",
            space.clone(),
            world::SHELL_MEMORY_BUDGET,
            vsh_platform::task(space, world.vsh_console, session),
        );
    }
    let typed_channels = if world.net_outbound.is_some() {
        "3 typed channels"
    } else {
        "1 typed channel"
    };
    println!(
        "  world     {} capability spaces, {}, {} components",
        world.spaces.len(),
        typed_channels,
        world.components().len()
    );
    println!("  sched     async executor, no threads, no preemption");

    trap::enable_interrupts();
    uart::early_write("[VibeOS] interrupts enabled\r\n");
    let (busy, phantom_timeout) = uart::dw_irq_recoveries();
    if busy != 0 || phantom_timeout != 0 {
        println!(
            "  uart      recovered {} DW busy, {} phantom timeout IRQ(s)",
            busy, phantom_timeout
        );
    }
    exec::run()
}

/// Discover the other physical harts, assign dense logical identities, ask
/// HSM to start them, and wait for their VibeOS-local ready publication.
fn start_secondary_harts() -> usize {
    let boot_physical_hart = sbi::current_hart_id();
    let mut expected = BOOT_HART_BIT;
    let mut physical_for_logical = [usize::MAX; exec::MAX_HARTS];
    physical_for_logical[exec::HartId::BOOT.index()] = boot_physical_hart;
    let mut next_logical_index = 1;
    assert!(
        platform::HART_IDS.contains(&boot_physical_hart),
        "firmware boot hart is absent from the selected platform topology"
    );
    for &physical_hart in platform::HART_IDS {
        if physical_hart == boot_physical_hart {
            continue;
        }
        match sbi::hart_status(physical_hart) {
            Ok(sbi::HartState::Stopped) => {
                let logical = exec::HartId::new(next_logical_index)
                    .expect("secondary logical hart index is in range");
                ipi::prepare_start(logical, physical_hart)
                    .expect("secondary logical-to-physical mapping must be unique");
                physical_for_logical[logical.index()] = physical_hart;
                expected |= 1usize << logical.index();
                next_logical_index += 1;
            }
            Err(sbi::IpiError::InvalidParam) => {
                // A smaller machine is valid: deterministic benchmarks retain
                // their existing `-smp 1` boundary.
            }
            Ok(state) => panic!(
                "secondary physical hart {} is not stopped before HSM start: {:?}",
                physical_hart, state
            ),
            Err(error) => panic!(
                "could not discover secondary physical hart {} through SBI HSM: {:?}",
                physical_hart, error
            ),
        }
    }

    // The acquire side in secondary_kmain publishes every preceding boot-hart
    // initialization before a newly started CPU touches shared state.
    SECONDARY_BOOT_RELEASED.store(true, Ordering::Release);
    let entry = _secondary_start as *const () as usize;
    for (logical_index, physical_hart) in physical_for_logical.iter().copied().enumerate().skip(1) {
        if physical_hart == usize::MAX {
            break;
        }
        sbi::hart_start(physical_hart, entry, logical_index)
            .expect("SBI HSM must accept every discovered stopped hart");
    }

    let started_at = sbi::time();
    loop {
        let ready = online_hart_mask();
        if ready & expected == expected {
            break;
        }
        if sbi::time().wrapping_sub(started_at) >= exec::timebase_hz() * 5 {
            panic!(
                "secondary startup timed out: expected mask {:#x}, ready mask {:#x}",
                expected, ready
            );
        }
        core::hint::spin_loop();
    }

    for index in 0..exec::MAX_HARTS {
        if expected & (1usize << index) != 0 {
            let hart = exec::HartId::new(index).expect("ready hart index is in range");
            assert!(
                ipi::is_online(hart),
                "kernel-ready hart {} did not publish its executor identity",
                index
            );
        }
    }
    (online_hart_mask() & expected).count_ones() as usize
}

/// Rust destination for the SBI HSM secondary entry. The assembly path has
/// already installed `tp`, `gp`, and this logical hart's private stack.
#[no_mangle]
pub extern "C" fn secondary_kmain(physical_hart: usize, logical_index: usize) -> ! {
    while !SECONDARY_BOOT_RELEASED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let Some(logical) = exec::HartId::new(logical_index) else {
        sbi::shutdown(true);
    };
    if sbi::current_hart_id() != physical_hart || logical == exec::HartId::BOOT {
        sbi::shutdown(true);
    }

    // SBI HSM starts every secondary with satp=0. Install the boot-published
    // shared root while all addresses are still valid physical identities,
    // before trap state or ONLINE publication can expose this hart.
    mmu::enable(logical.index());

    // Install stvec and the local interrupt-enable mask before ONLINE can let
    // another hart send SSIP here. Global SIE remains clear throughout.
    trap::prepare_secondary();
    if ipi::mark_online(logical, physical_hart).is_err() {
        sbi::shutdown(true);
    }
    // Timer initialization uses hart-local allocation/recovery context and
    // therefore follows self-registration.
    trap::finish_secondary();

    KERNEL_READY_HARTS.fetch_or(1usize << logical.index(), Ordering::Release);
    trap::enable_interrupts();
    exec::run()
}

/// Executor callback after every task and external registration in a tracked
/// incarnation has been detached. The sealed World templates prove that no
/// arena-backed pointer escaped, so raw reclamation is sound and runs no Drop.
unsafe fn reclaim_faulted_component(domain: heap::AllocationDomain) {
    unsafe {
        // Repair component-stable synchronization state while the exact
        // faulting incarnation is still identifiable and before Faulted is
        // visible to safe lifecycle callers.
        block_device::recover_faulted_domain(domain);
        net_device::recover_faulted_domain(domain);
        #[cfg(feature = "qemu-virt")]
        virtio_rng::recover_faulted_domain(domain);
        world::world().recover_faulted_domain(domain);
        code_pool::recover_faulted_domain(domain);
        HEAP.reclaim_faulted_arena(domain.arena)
            .expect("a faulted audited arena must reclaim atomically");
    }
}

/// Repair exact-task stable state for both conservative untracked faults and
/// audited arena faults. The executor has detached the task permanently before
/// entering this non-allocating hook.
unsafe fn cleanup_faulted_task(task: exec::TaskId, domain: heap::AllocationDomain) {
    unsafe {
        store::recover_faulted_task(task, domain);
        // Durable boot recovery installs and fail-closes the saved-program
        // target. Repair all saved-program locks first so durable quarantine
        // cannot spin on a guard abandoned by this same faulted task. Both
        // hooks are idempotent and retain exact claims until isolation ends.
        saved_program::recover_faulted_task(task, domain);
        durable_cspace::recover_faulted_task(task, domain);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Deliberately bypasses the UART driver: a panic may already hold its lock.
    let mut w = SbiWriter;
    let _ = core::fmt::write(&mut w, format_args!("\n[!] panic: {}\n", info));

    // An IRQ may preempt a guarded task, but its panic belongs to the kernel.
    // Longjmp from here would skip the saved trap frame and corrupt interrupt
    // state, so interrupt faults are deliberately fatal.
    if trap::in_interrupt() {
        let _ = core::fmt::write(&mut w, format_args!("[!] panic in interrupt; halting\n"));
        sbi::shutdown(true);
    }

    // If a compiled program is running, or a task is being polled behind the
    // fault guard, unwind to that landing pad instead of taking the machine
    // down. Innermost first.
    rustc::unwind_running_program();
    trampoline::unwind_faulted_task();

    let _ = core::fmt::write(&mut w, format_args!("[!] no landing pad; halting\n"));
    sbi::shutdown(true);
}

struct SbiWriter;
impl core::fmt::Write for SbiWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                sbi::legacy_putchar(b'\r');
            }
            sbi::legacy_putchar(b);
        }
        Ok(())
    }
}

#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    match HEAP.take_last_failure() {
        Some(heap::AllocationFailure::QuotaExceeded { owner, .. })
            if owner != heap::OwnerId::SYSTEM =>
        {
            // Keep the panic text deterministic; the account snapshot carries
            // exact live/peak/request evidence for diagnostics and tests.
            panic!("component allocation quota exceeded")
        }
        failure => {
            // A global allocator failure is kernel state, even if it happened
            // while a task guard was armed. Bypass panic/longjmp so it cannot be
            // misattributed to the interrupted component.
            let mut w = SbiWriter;
            let _ = core::fmt::write(
                &mut w,
                format_args!(
                    "\n[!] fatal allocator failure: {:?}, layout {:?}\n",
                    failure, layout
                ),
            );
            sbi::shutdown(true)
        }
    }
}
