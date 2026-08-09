//! An interactive shell — itself just another async task holding capabilities.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::cap::{CSpace, Cap, CapError, Resource, Rights};
use crate::chan::Endpoint;
use crate::dev::ConsoleDev;
use crate::net::Packet;
use crate::world::{world, Reading, Space};
use crate::HEAP;
use crate::{exec, ipi, mmu, println, sbi, sync::SpinLock, tty, uart};

struct ReadOnlyCapProbe(u64);

impl Resource for ReadOnlyCapProbe {
    fn kind(&self) -> &'static str {
        "read-only-cap-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub async fn shell_task(boot_time: u64) {
    println!("\nVibeOS shell ready -- type `help` for commands, `quiet` to mute components.\n");
    loop {
        tty::prompt("vibe> ");
        if let Some(line) = read_line().await {
            if !line.is_empty() {
                run(&line, boot_time).await;
            }
        }
    }
}

/// Read one line at the active prompt. `None` means the user hit Ctrl-C.
///
/// Nothing here echoes directly: the tty owns the line, so a component printing
/// mid-keystroke redraws the prompt and whatever has been typed so far.
async fn read_line() -> Option<String> {
    loop {
        let b = uart::read_byte().await;
        match b {
            b'\r' | b'\n' => return Some(tty::submit()),
            0x7f | 0x08 => tty::backspace(),
            0x03 => {
                tty::cancel();
                return None;
            }
            b if (0x20..0x7f).contains(&b) => tty::type_char(b as char),
            _ => {}
        }
    }
}

async fn run(line: &str, boot_time: u64) {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else { return };
    let rest: Vec<&str> = parts.collect();

    match cmd {
        "help" => {
            println!("  ps              component identities, lifecycle, and poll counts");
            println!("  spaces          capability spaces in the system");
            println!("  caps <space>    component owner and capability table");
            println!("  probe           attempt four illegal operations, show the refusals");
            println!("  revoke <space>  pull a component's authority at runtime");
            println!("  cancel <name>   cooperatively stop a component (shell is protected)");
            println!("  restart <name>  start a fresh terminal component incarnation");
            println!("  rustc hello     compile and run a Rust hello world, natively");
            println!("  rustc demo      compile and run a larger sample (fib, gcd, loops)");
            println!("  rustc conform   compile and run the language conformance program");
            println!("  rustc lease     revoke during a run, then retry without new grants");
            println!("  rustc edit      type your own program; end it with a lone `.`");
            println!("  rustc save hello  durably publish source + canonical VIBEEXE + authority");
            println!("  run hello       run the recovered artifact through its persisted cap");
            println!("  chan            telemetry channel depth and totals");
            println!("  bench           emit the versioned machine-readable benchmark suite");
            println!("  durable         recover a sealed capability log and tombstone");
            println!("  blk info|test   inspect or exercise the supervised block device");
            println!("  net info|test|fault  inspect, handshake, or recover virtio-net");
            println!("  store info|test|fault  exercise capability-addressed persistence");
            println!("  pcspace test    exercise three-boot persistent authority recovery");
            println!("  smp queues      prove four physical executors and cross-hart wakeups");
            println!("  smp scale       compare equal serial and four-hart parallel work");
            println!("  mmu             inspect the shared Sv39 integrity map");
            println!("  mmu guard fault prove a stack guard with a real page fault");
            println!("  mmu wx          prove seal, cross-hart execute, and cleared reuse");
            println!("  mmu wx fault execute|read|write  run expected-fatal W^X probes");
            println!("  mmu ro          prove read-only rodata and COW capability tables");
            println!("  mmu ro fault rodata|captab  run expected-fatal write probes");
            println!("  selftest        run the in-kernel test suite");
            println!("  quiet           mute background components (`verbose` restores)");
            println!("  mem             kernel heap usage");
            println!("  uptime          seconds since boot");
            println!("  echo <text>     write via init's console capability");
            println!("  halt            shut the machine down");
        }

        "ps" => {
            println!(
                "  {:<12} {:<8} {:<10} {:<8} {:<9} {:<9} {:>8} {:>10}",
                "COMPONENT", "TASK", "NAME", "CSPACE", "STATE", "REASON", "POLLS", "BUDGET"
            );
            for component in world().components() {
                let c = component.snapshot();
                let component_id = alloc::format!("{}", c.id);
                let task_id = alloc::format!("{}", c.task_id);
                let state = alloc::format!("{}", c.state);
                println!(
                    "  {:<12} {:<8} {:<10} {:<8} {:<9} {:<9} {:>8} {:>8} B",
                    component_id,
                    task_id,
                    c.name,
                    c.cspace,
                    state,
                    c.terminal_reason.unwrap_or("-"),
                    c.polls,
                    c.memory.budget_bytes
                );
            }
            println!(
                "  executor totals (including untracked tasks): {} exited, {} faulted, {} cancelled",
                exec::completed_count(),
                exec::faulted_count(),
                exec::cancelled_count()
            );
            println!("  component allocation quotas are enforced; `mem` shows live and peak use");
            if tty::is_quiet() {
                println!("  background output is muted; poll counts still rising");
            }
        }

        "spaces" => {
            let w = world();
            for (name, space) in &w.spaces {
                let n = space.0.lock().list().len();
                println!("  {:<8} {} caps", name, n);
            }
        }

        "caps" => {
            let w = world();
            let name = rest.first().copied().unwrap_or("init");
            let Some(space) = w.spaces.get(name) else {
                println!("  no such space: {}", name);
                return;
            };
            let owner_state = match w.component_for_space(space) {
                Some(component) => {
                    let c = component.snapshot();
                    println!(
                        "  owner {}  task {}  name {}  state {}  reason {}",
                        c.id,
                        c.task_id,
                        c.name,
                        c.state,
                        c.terminal_reason.unwrap_or("-")
                    );
                    println!(
                        "  memory owner {}  budget {} B  quota denials {}",
                        c.memory.owner, c.memory.budget_bytes, c.memory.denials
                    );
                    Some(c.state)
                }
                None => {
                    println!(
                        "  owner unbound (generated code executes synchronously in the shell task)"
                    );
                    None
                }
            };
            if owner_state == Some(exec::TaskState::Faulted) {
                println!(
                    "  capability table unavailable: a fault may have abandoned its CSpace lock"
                );
                return;
            }
            println!(
                "  {:<12} {:<9} {:<8} {}",
                "HANDLE", "KIND", "RIGHTS", "OBJECT"
            );
            for (cap, kind, rights, desc) in space.0.lock().list() {
                println!(
                    "  {:<12} {:<9} {:<8} {}",
                    alloc::format!("{}", cap),
                    kind,
                    alloc::format!("{}", rights),
                    desc
                );
            }
            println!("  rights: r=read w=write s=send v=recv g=grant x=revoke");
        }

        "probe" => probe().await,

        "revoke" => {
            let w = world();
            let Some(target) = rest.first().copied() else {
                println!("  usage: revoke <space>");
                return;
            };
            let handle = match target {
                "guest" => w.guest_space,
                "prog" => w.prog_space,
                _ => {
                    println!("  init holds REVOKE caps on `guest` and `prog` only");
                    return;
                }
            };
            // Authority to do this comes from init's cap on the target *space*.
            let init = w.spaces["init"].clone();
            let space_res = init.0.lock().lookup_as::<Space>(handle, Rights::REVOKE);
            match space_res {
                Ok(space) => {
                    let killed = space.0.lock().revoke_all();
                    println!("  revoked {} cap(s) in `{}`", killed, target);
                    match target {
                        "guest" => println!(
                            "  (authority is gone; cancel then restart to install fresh grants)"
                        ),
                        _ => println!("  (already-compiled machine code will now print nothing)"),
                    }
                }
                Err(e) => println!("  refused: {}", e),
            }
        }

        "cancel" => {
            let Some(name) = rest.first().copied() else {
                println!("  usage: cancel <component>");
                return;
            };
            if name == "shell" {
                println!("  refused: the active shell supervisor cannot cancel itself");
                return;
            }
            let w = world();
            let Some(component) = w.component_named(name) else {
                println!("  no such component: {}", name);
                return;
            };
            match component.cancel() {
                exec::CancelOutcome::Requested => {
                    let c = component.snapshot();
                    match c.state {
                        exec::TaskState::Cancelled => println!(
                            "  cancelled {}  task {} after {} poll(s)",
                            c.id, c.task_id, c.polls
                        ),
                        exec::TaskState::Running => println!(
                            "  cancellation requested for {}  task {}; waiting for a poll boundary",
                            c.id, c.task_id
                        ),
                        exec::TaskState::Exited | exec::TaskState::Faulted => println!(
                            "  cancellation completed as {} ({}) for {}  task {} after {} poll(s)",
                            c.state,
                            c.terminal_reason.unwrap_or("-"),
                            c.id,
                            c.task_id,
                            c.polls
                        ),
                    }
                }
                exec::CancelOutcome::AlreadyTerminal(exit) => println!(
                    "  {} already {}  task {} after {} poll(s)",
                    component.snapshot().id,
                    exit.state(),
                    exit.id(),
                    exit.polls()
                ),
                exec::CancelOutcome::TooLate(state) => println!(
                    "  cancellation was too late; task completion is already committed as {}",
                    state
                ),
            }
        }

        "restart" => {
            let Some(name) = rest.first().copied() else {
                println!("  usage: restart <component>");
                return;
            };
            match world().restart_component(name) {
                Ok(report) => {
                    println!(
                        "  restarted {}  generation {} -> {}",
                        report.component, report.old_generation, report.new_generation
                    );
                    println!(
                        "  task {} -> {}; retired {} old cap(s), fresh grants installed",
                        report.old_task, report.new_task, report.retired_caps
                    );
                }
                Err(crate::world::RestartError::NotFound) => {
                    println!("  no such component: {}", name)
                }
                Err(e) => println!("  refused: {}", e),
            }
        }

        "rustc" => {
            if rest.first().copied() == Some("save") {
                if rest.get(1).copied() != Some(crate::program::PROGRAM_ALIAS)
                    || rest.len() != 2
                {
                    println!("  usage: rustc save hello");
                    return;
                }
                save_hello().await;
                return;
            }
            if rest.first().copied() == Some("lease") {
                run_lease_demo().await;
                return;
            }
            let src = match rest.first().copied() {
                Some("hello") | None => String::from(crate::rustc::HELLO_SRC),
                Some("demo") => String::from(crate::rustc::DEMO_SRC),
                Some("conform") => String::from(crate::rustc::CONFORM_SRC),
                Some("edit") => match read_source().await {
                    Some(s) => s,
                    None => {
                        println!("  aborted");
                        return;
                    }
                },
                Some(other) => {
                    println!(
                        "  usage: rustc [hello|demo|conform|lease|edit|save hello] (got `{}`)",
                        other
                    );
                    return;
                }
            };
            compile_and_run(&src).await;
        }

        "run" => {
            if rest.as_slice() != [crate::program::PROGRAM_ALIAS] {
                println!("  usage: run hello");
                return;
            }
            run_saved_hello().await;
        }

        "chan" => {
            let w = world();
            let init = w.spaces["init"].clone();
            let ep = init
                .0
                .lock()
                .lookup_as::<Endpoint<Reading>>(w.telemetry, Rights::READ);
            match ep {
                Ok(ep) => {
                    let (sent, recv, depth) = ep.stats();
                    println!("  telemetry  sent={} recv={} queued={}", sent, recv, depth);
                }
                Err(e) => println!("  refused: {}", e),
            }
        }

        "bench" => crate::bench::run().await,

        "durable" => durable_demo(),

        "blk" => block_command(&rest).await,

        "net" => net_command(&rest).await,

        "store" => store_command(&rest).await,

        "pcspace" => persistent_cspace_command(&rest).await,

        "smp" => {
            match rest.as_slice() {
                ["queues"] => smp_queue_demo().await,
                ["scale"] => smp_scale_demo().await,
                _ => println!("  usage: smp queues|scale"),
            }
        }

        "mmu" => match rest.as_slice() {
            [] => mmu_status(),
            ["guard", "fault"] => mmu_guard_fault(),
            ["wx"] => mmu_wx_demo().await,
            ["wx", "fault", "execute"] => crate::code_pool::execute_writable_probe(),
            ["wx", "fault", "read"] => crate::rustc::sealed_access_probe(false),
            ["wx", "fault", "write"] => crate::rustc::sealed_access_probe(true),
            ["ro"] => mmu_ro_demo().await,
            ["ro", "fault", "rodata"] => mmu_rodata_write_probe(),
            ["ro", "fault", "captab"] => mmu_capability_table_write_probe(),
            _ => println!(
                "  usage: mmu [guard fault|wx [fault execute|read|write]|ro [fault rodata|captab]]"
            ),
        },

        "selftest" => {
            let r = crate::selftest::run().await;
            // CI greps for this line, so keep the wording stable.
            if r.failed == 0 {
                println!("  SELFTEST OK ({} checks)", r.passed);
            } else {
                println!(
                    "  SELFTEST FAILED ({} of {})",
                    r.failed,
                    r.passed + r.failed
                );
            }
        }

        "quiet" | "verbose" => {
            let quiet = cmd == "quiet";
            tty::set_quiet(quiet);
            if quiet {
                println!("  background components muted; they keep running (`ps` proves it)");
            } else {
                println!("  background components audible again");
            }
        }

        "mem" => {
            let (live, peak, free) = HEAP.stats();
            println!(
                "  heap   live {:>7} B  peak {:>7} B  bump remaining {:>9} B",
                live, peak, free
            );
            let w = world();
            let init = w.spaces["init"].clone();
            let region = init
                .0
                .lock()
                .lookup_as::<crate::dev::MemoryRegion>(w.region, Rights::READ);
            match region {
                Ok(r) => println!("  region {} x i64 granted to `prog`", r.len()),
                Err(_) => println!("  region not reachable from init"),
            }
            println!(
                "  {:<10} {:>9} {:>9} {:>9} {:>7}",
                "COMPONENT", "LIVE", "PEAK", "BUDGET", "DENIED"
            );
            for component in w.components() {
                let c = component.snapshot();
                println!(
                    "  {:<10} {:>7} B {:>7} B {:>7} B {:>7}",
                    c.name,
                    c.memory.live_bytes,
                    c.memory.peak_bytes,
                    c.memory.budget_bytes,
                    c.memory.denials
                );
            }
        }

        "uptime" => {
            let ticks = sbi::time() - boot_time;
            let ms = ticks / (exec::TIMEBASE_HZ / 1000);
            println!("  up {}.{:03} s", ms / 1000, ms % 1000);
        }

        "echo" => {
            let w = world();
            let init = w.spaces["init"].clone();
            let con = init
                .0
                .lock()
                .lookup_as::<ConsoleDev>(w.console, Rights::WRITE);
            match con {
                Ok(c) => c.write(&alloc::format!("  {}\n", rest.join(" "))),
                Err(e) => println!("  refused: {}", e),
            }
        }

        "halt" => {
            println!("  powering off.");
            sbi::shutdown(false);
        }

        other => println!("  unknown command: {} (try `help`)", other),
    }
}

fn mmu_status() {
    let text = mmu::mapping(mmu_status as *const () as usize)
        .expect("the running shell text must be mapped");
    let plic = mmu::mapping(mmu::PLIC_START).expect("the PLIC must be mapped");
    let uart = mmu::mapping(mmu::UART_VIRTIO_START).expect("UART/virtio must be mapped");
    let online = crate::online_hart_mask();
    let enabled = mmu::enabled_hart_mask();
    println!(
        "  mode: Sv39, ASID 0, one shared root at {:#x}",
        mmu::root_physical()
    );
    println!(
        "  harts: satp read back on mask {:#x} ({}/{} online), MXR clear mask {:#x}",
        enabled,
        (enabled & online).count_ones(),
        online.count_ones(),
        mmu::mxr_cleared_hart_mask(),
    );
    println!(
        "  kernel RAM: {:#x}..{:#x}, identity, {} KiB leaves, strict W^X",
        mmu::KERNEL_RAM_START,
        mmu::KERNEL_RAM_END,
        text.page_size / 1024,
    );
    println!(
        "  text: {}, writable RAM: rw-, no writable-executable leaf",
        permission_text(text.permissions)
    );
    let rodata = mmu::mapping(mmu::rodata_range().0).expect("rodata mapping exists");
    println!(
        "  rodata: {}, capability tables: COW published r--",
        permission_text(rodata.permissions)
    );
    println!(
        "  MMIO: PLIC {} KiB leaves {}, UART/virtio {} KiB leaves {}",
        plic.page_size / 1024,
        permission_text(plic.permissions),
        uart.page_size / 1024,
        permission_text(uart.permissions)
    );
    let stack = mmu::mapping(
        mmu::stack_usable_start(exec::HartId::BOOT.index())
            .expect("the boot stack slot must exist"),
    )
    .expect("the boot stack must be mapped above its guard");
    println!(
        "  stacks: {} x {} KiB usable, {} KiB guards invalid, {}",
        exec::MAX_HARTS,
        (mmu::STACK_SLOT_STRIDE - mmu::STACK_GUARD_SIZE) / 1024,
        mmu::STACK_GUARD_SIZE / 1024,
        permission_text(stack.permissions)
    );
    let pool = crate::code_pool::stats();
    println!(
        "  code pool: {} KiB, {} live/{} sealed pages, free/write rw-, sealed --x",
        crate::code_pool::CODE_POOL_BYTES / 1024,
        pool.live_pages,
        pool.sealed_pages,
    );
    let cap_pool = crate::cap_table_pool::stats();
    println!(
        "  cap-table pool: {} KiB, live pages {}",
        crate::cap_table_pool::CAP_TABLE_POOL_BYTES / 1024,
        if cap_pool.live_pages == cap_pool.read_only_pages {
            "all read-only"
        } else {
            "FAILED writable candidate"
        },
    );
    println!("  unmapped: firmware prefix, null page, and unused physical space");
}

async fn mmu_wx_demo() {
    use vibeos_core::mmu::PagePermissions;

    let Some(remote_hart) = exec::HartId::new(1) else {
        println!("  W^X: FAILED no remote logical hart");
        return;
    };
    if !ipi::is_online(remote_hart) {
        println!("  W^X: FAILED remote hart offline");
        return;
    }

    let before = mmu::wx_sync_stats();
    let zeroed = crate::code_pool::reuse_zero_probe();
    let first = match crate::rustc::compile("fn main() -> i64 { 41 }") {
        Ok(compiled) => Arc::new(compiled),
        Err(error) => {
            println!("  W^X: FAILED first compile ({})", error);
            return;
        }
    };
    let first_start = first.code_start();
    let first_mapping = mmu::mapping(first_start);
    let local_first = crate::rustc::run(first.as_ref());
    let remote_first = run_generated_on(remote_hart, first.clone()).await;
    let first_pages = first.code_pages();
    drop(first);

    let second = match crate::rustc::compile("fn main() -> i64 { 42 }") {
        Ok(compiled) => Arc::new(compiled),
        Err(error) => {
            println!("  W^X: FAILED second compile ({})", error);
            return;
        }
    };
    let same_address = second.code_start() == first_start;
    let second_mapping = mmu::mapping(second.code_start());
    let remote_second = run_generated_on(remote_hart, second.clone()).await;
    let after = mmu::wx_sync_stats();

    let sealed = [first_mapping, second_mapping].into_iter().all(|mapping| {
        mapping.is_some_and(|mapping| {
            mapping.page_size == vibeos_core::mmu::PAGE_SIZE
                && mapping.permissions == PagePermissions::EXECUTE
        })
    });
    let no_wx = mmu::first_writable_executable_ram_page().is_none();
    let local_ok = local_first.aborted.is_none() && local_first.value == 41;
    let remote_ok = remote_first == Some(41) && remote_second == Some(42);
    println!(
        "  W^X: {} KiB pool, free/write rw-, sealed --x, MXR mask {:#x}",
        crate::code_pool::CODE_POOL_BYTES / 1024,
        mmu::mxr_cleared_hart_mask(),
    );
    println!(
        "  sealed: {} page(s) at {:#x}, boot=41 {}, hart1=41 {}",
        first_pages,
        first_start,
        if sealed && no_wx { "ok" } else { "FAILED" },
        if local_ok && remote_first == Some(41) {
            "ok"
        } else {
            "FAILED"
        },
    );
    println!(
        "  reuse: zeroed {}, same-address {}, hart1=42 {}",
        if zeroed { "yes" } else { "NO" },
        if same_address { "yes" } else { "NO" },
        if remote_second == Some(42) { "ok" } else { "FAILED" },
    );
    println!(
        "  shootdown: {} transitions, {} remote sfence, {} remote fence.i",
        after.transitions.saturating_sub(before.transitions),
        after.remote_sfences.saturating_sub(before.remote_sfences),
        after.remote_fence_i.saturating_sub(before.remote_fence_i),
    );
    if !zeroed || !same_address || !sealed || !no_wx || !local_ok || !remote_ok {
        println!("  W^X: FAILED acceptance invariant");
    }
}

async fn run_generated_on(
    hart: exec::HartId,
    compiled: Arc<crate::rustc::Compiled>,
) -> Option<i64> {
    let value = Arc::new(AtomicU64::new(u64::MAX));
    let aborted = Arc::new(AtomicBool::new(false));
    let observed_hart = Arc::new(AtomicUsize::new(usize::MAX));
    let task_value = value.clone();
    let task_aborted = aborted.clone();
    let task_hart = observed_hart.clone();
    let handle = exec::spawn_pinned_on(hart, "wx-generated", async move {
        task_hart.store(
            ipi::current_logical_hart().map_or(usize::MAX, exec::HartId::index),
            Ordering::Release,
        );
        let outcome = crate::rustc::run(compiled.as_ref());
        task_aborted.store(outcome.aborted.is_some(), Ordering::Release);
        task_value.store(outcome.value as u64, Ordering::Release);
    });
    let exit = handle.join().await;
    (exit.state() == exec::TaskState::Exited
        && observed_hart.load(Ordering::Acquire) == hart.index()
        && !aborted.load(Ordering::Acquire)
        && value.load(Ordering::Acquire) != u64::MAX)
        .then(|| value.load(Ordering::Acquire) as i64)
}

async fn mmu_ro_demo() {
    use vibeos_core::mmu::{PagePermissions, PAGE_SIZE};

    let (rodata_start, rodata_end) = mmu::rodata_range();
    let rodata_read_only = [rodata_start, rodata_end - PAGE_SIZE]
        .into_iter()
        .all(|address| {
            mmu::mapping(address).is_some_and(|mapping| {
                mapping.physical == address
                    && mapping.page_size == PAGE_SIZE
                    && mapping.permissions == PagePermissions::READ
            })
        });

    let before_transitions = mmu::capability_table_transitions();
    let before_fences = mmu::wx_sync_stats().remote_sfences;
    let table = Arc::new(SpinLock::new(CSpace::new("mmu-ro-probe")));
    let (root, first_range, first_read_only, child, second_read_only) = {
        let mut cspace = table.lock();
        let root = cspace.mint(Arc::new(ReadOnlyCapProbe(64)), Rights::ALL);
        let first_range = cspace
            .capability_table_range()
            .expect("mint must publish a capability table");
        let first_read_only = capability_table_range_is_read_only(first_range);
        let child = cspace
            .derive(root, Rights::READ)
            .expect("fixed read-only probe must derive");
        let second_range = cspace
            .capability_table_range()
            .expect("derive must publish a capability table");
        let second_read_only = capability_table_range_is_read_only(second_range);
        (root, first_range, first_read_only, child, second_read_only)
    };

    let remote_hart = exec::HartId::new(1).expect("logical hart 1 exists");
    let remote_value = run_cap_lookup_on(remote_hart, table.clone(), child).await;
    let (removed, stale_denied, third_range, third_read_only) = {
        let mut cspace = table.lock();
        let removed = cspace
            .revoke(root)
            .expect("fixed read-only probe root is revocable");
        let stale_denied = cspace
            .lookup_as::<ReadOnlyCapProbe>(child, Rights::READ)
            .is_err();
        let range = cspace
            .capability_table_range()
            .expect("revocation retains generation slots");
        let read_only = capability_table_range_is_read_only(range);
        (removed, stale_denied, range, read_only)
    };

    let ranges_read_only = first_read_only && second_read_only && third_read_only;
    let same_address_reuse = first_range.start == third_range.start;
    let pool = crate::cap_table_pool::stats();
    let transitions = mmu::capability_table_transitions().saturating_sub(before_transitions);
    let remote_sfences = mmu::wx_sync_stats()
        .remote_sfences
        .saturating_sub(before_fences);
    let pool_fully_published = pool.live_pages == pool.read_only_pages;
    println!(
        "  .rodata: {} KiB at {:#x}..{:#x}, first/last page {}",
        (rodata_end - rodata_start) / 1024,
        rodata_start,
        rodata_end,
        if rodata_read_only { "r--" } else { "FAILED" },
    );
    println!(
        "  capability tables: {} KiB pool, COW publish r--, live pages {}",
        crate::cap_table_pool::CAP_TABLE_POOL_BYTES / 1024,
        if pool_fully_published {
            "all read-only"
        } else {
            "FAILED writable candidate"
        },
    );
    println!(
        "  mutation: mint {}, derive {}, revoke {}, same-address reuse {}",
        if first_read_only { "r--" } else { "FAILED" },
        if second_read_only { "r--" } else { "FAILED" },
        if third_read_only { "r--" } else { "FAILED" },
        if same_address_reuse { "yes" } else { "NO" },
    );
    println!(
        "  hart1: derived lookup={} {}, revoke removed {} and stale lookup {}",
        remote_value.unwrap_or(u64::MAX),
        if remote_value == Some(64) {
            "ok"
        } else {
            "FAILED"
        },
        removed,
        if stale_denied { "denied" } else { "FAILED" },
    );
    println!(
        "  shootdown: {} table transitions, {} remote sfence, authoritative pages {}",
        transitions,
        remote_sfences,
        if ranges_read_only && pool_fully_published {
            "r--"
        } else {
            "FAILED"
        },
    );
    if !rodata_read_only
        || !ranges_read_only
        || !same_address_reuse
        || remote_value != Some(64)
        || removed != 2
        || !stale_denied
        || transitions < 5
        || remote_sfences < 10
        || !pool_fully_published
    {
        println!("  read-only: FAILED acceptance invariant");
    }
}

fn capability_table_range_is_read_only(range: crate::cap::CapabilityTableRange) -> bool {
    use vibeos_core::mmu::{PagePermissions, PAGE_SIZE};

    range.start % PAGE_SIZE == 0
        && range.page_count != 0
        && (0..range.page_count).all(|page| {
            let address = range.start + page * PAGE_SIZE;
            crate::cap_table_pool::contains(address)
                && mmu::mapping(address).is_some_and(|mapping| {
                    mapping.physical == address
                        && mapping.page_size == PAGE_SIZE
                        && mapping.permissions == PagePermissions::READ
                })
        })
}

async fn run_cap_lookup_on(
    hart: exec::HartId,
    table: Arc<SpinLock<CSpace>>,
    capability: Cap,
) -> Option<u64> {
    let value = Arc::new(AtomicU64::new(u64::MAX));
    let observed_hart = Arc::new(AtomicUsize::new(usize::MAX));
    let task_value = value.clone();
    let task_hart = observed_hart.clone();
    let handle = exec::spawn_pinned_on(hart, "ro-cap-lookup", async move {
        task_hart.store(
            ipi::current_logical_hart().map_or(usize::MAX, exec::HartId::index),
            Ordering::Release,
        );
        let observed = table
            .lock()
            .lookup_as::<ReadOnlyCapProbe>(capability, Rights::READ)
            .map_or(u64::MAX, |probe| probe.0);
        task_value.store(observed, Ordering::Release);
    });
    let exit = handle.join().await;
    (exit.state() == exec::TaskState::Exited
        && observed_hart.load(Ordering::Acquire) == hart.index()
        && value.load(Ordering::Acquire) != u64::MAX)
        .then(|| value.load(Ordering::Acquire))
}

fn mmu_rodata_write_probe() -> ! {
    let address = mmu::rodata_range().0;
    println!("  read-only probe: write rodata {:#x}", address);
    // Safety: this expected-fatal acceptance case deliberately stores to an
    // R-- linker page and must take a store page fault at this exact address.
    unsafe { (address as *mut u8).write_volatile(0x5a) };
    panic!("read-only .rodata accepted a store")
}

fn mmu_capability_table_write_probe() -> ! {
    let mut cspace = CSpace::new("read-only-fault-probe");
    cspace.mint(Arc::new(ReadOnlyCapProbe(64)), Rights::ALL);
    let range = cspace
        .capability_table_range()
        .expect("mint must publish a read-only table");
    assert!(capability_table_range_is_read_only(range));
    let address = range.start;
    println!("  read-only probe: write capability table {:#x}", address);
    // Safety: `cspace` keeps this authoritative table live and R--. The store
    // must fault before it can alter the first Slot.
    unsafe { (address as *mut u8).write_volatile(0x5a) };
    panic!("read-only capability table accepted a store")
}

fn mmu_guard_fault() {
    let hart = ipi::current_logical_hart().expect("guard probe requires a registered hart");
    let guard = mmu::stack_guard_page(hart.index()).expect("current hart guard must exist");
    println!(
        "  guard probe: hart{} store into {:#x}",
        hart.index(),
        guard
    );
    // Safety: this command is an explicit fatal acceptance probe. The address
    // is the current hart's statically reserved guard page, never heap or
    // device memory. A successful return is itself an integrity failure.
    unsafe { (guard as *mut u8).write_volatile(0x5a) };
    panic!("stack guard accepted a store")
}

fn permission_text(permissions: vibeos_core::mmu::PagePermissions) -> &'static str {
    use vibeos_core::mmu::PagePermissions;

    match (
        permissions.contains(PagePermissions::READ),
        permissions.contains(PagePermissions::WRITE),
        permissions.contains(PagePermissions::EXECUTE),
    ) {
        (true, true, true) => "rwx",
        (true, true, false) => "rw-",
        (true, false, true) => "r-x",
        (true, false, false) => "r--",
        (false, false, true) => "--x",
        _ => "invalid",
    }
}

/// M5.5 physical-hart and cross-hart wake acceptance probe.
async fn smp_queue_demo() {
    let scheduler_lock_before = exec::scheduler_lock_stats();
    let boot_initiator = ipi::current_logical_hart() == Some(exec::HartId::BOOT);
    let all_online = (0..exec::MAX_HARTS).all(|index| {
        ipi::is_online(exec::HartId::new(index).expect("logical scheduler hart is valid"))
    });
    let physical_ids: Vec<_> = (0..exec::MAX_HARTS)
        .map(|index| {
            ipi::stats(exec::HartId::new(index).expect("logical scheduler hart is valid"))
                .physical_hart_id
        })
        .collect();
    let unique_physical = physical_ids.iter().enumerate().all(|(index, physical)| {
        physical.is_some() && physical_ids[..index].iter().all(|other| other != physical)
    });

    let mut gates = Vec::new();
    let mut started = Vec::new();
    let mut resumed = Vec::new();
    let mut handles = Vec::new();
    for index in 1..exec::MAX_HARTS {
        let hart = exec::HartId::new(index).expect("logical scheduler hart is valid");
        let gate = Arc::new(exec::WaitQueue::new());
        let start = Arc::new(AtomicU64::new(0));
        let resume = Arc::new(AtomicU64::new(0));
        let task_gate = gate.clone();
        let task_start = start.clone();
        let task_resume = resume.clone();
        let handle = exec::spawn_pinned_on(hart, "smp-physical-wake-probe", async move {
            task_start.store(
                ipi::current_logical_hart().map_or(0, |current| current.index() as u64 + 1),
                Ordering::SeqCst,
            );
            task_gate.wait().await;
            task_resume.store(
                ipi::current_logical_hart().map_or(0, |current| current.index() as u64 + 1),
                Ordering::SeqCst,
            );
        });
        gates.push(gate);
        started.push(start);
        resumed.push(resume);
        handles.push(handle);
    }

    // Wait until every exact-hart task has returned Pending with its waiter
    // registered. Waking below therefore crosses from the boot hart into each
    // remote ready queue and must ring an SBI doorbell.
    let mut waiters_parked = false;
    for _ in 0..10_000 {
        if gates.iter().all(|gate| gate.waiter_count() == 1) {
            waiters_parked = true;
            break;
        }
        exec::yield_now().await;
    }
    if !waiters_parked {
        for handle in &handles {
            let _ = handle.cancel();
        }
        println!("  smp queues: FAILED remote waiters did not park");
        return;
    }
    // Drain each spawn-time doorbell before taking the wake baseline. This
    // makes the increment below belong uniquely to `wake_all`, not to initial
    // placement of the probe.
    let mut mailboxes_drained = false;
    for _ in 0..10_000 {
        if (1..exec::MAX_HARTS).all(|index| {
            ipi::stats(exec::HartId::new(index).expect("logical scheduler hart is valid"))
                .pending_reasons
                == 0
        }) {
            mailboxes_drained = true;
            break;
        }
        exec::yield_now().await;
    }
    if !mailboxes_drained {
        for handle in &handles {
            let _ = handle.cancel();
        }
        println!("  smp queues: FAILED spawn doorbells did not drain");
        return;
    }
    let before_ipi: Vec<_> = (1..exec::MAX_HARTS)
        .map(|index| {
            ipi::stats(exec::HartId::new(index).expect("logical scheduler hart is valid"))
        })
        .collect();
    for gate in &gates {
        gate.wake_all();
    }

    let mut exits_twice = true;
    for handle in &handles {
        let exit = handle.join().await;
        exits_twice &= exit.state() == exec::TaskState::Exited && exit.polls() == 2;
    }
    // Give a stale SSIP (possible when the idle gate consumed the reason first)
    // one executor turn to reach the trap acknowledgement path.
    for _ in 0..8 {
        exec::yield_now().await;
    }
    let after_ipi: Vec<_> = (1..exec::MAX_HARTS)
        .map(|index| {
            ipi::stats(exec::HartId::new(index).expect("logical scheduler hart is valid"))
        })
        .collect();
    let exact_harts = started.iter().zip(&resumed).enumerate().all(
        |(offset, (start, resume))| {
            let encoded = (offset + 2) as u64;
            start.load(Ordering::SeqCst) == encoded && resume.load(Ordering::SeqCst) == encoded
        },
    );
    let ipis_observed = before_ipi.iter().zip(&after_ipi).all(|(before, after)| {
        after.doorbells == before.doorbells + 1
            && after.send_failures == before.send_failures
            && (after.acknowledged + after.stale > before.acknowledged + before.stale
                || after.idle_consumed > before.idle_consumed)
    });

    // Force a short four-way sample of the retained scheduler lock. M5.3
    // deferred physical contention evidence until secondaries were real; a
    // nonzero delta here proves the counter is observing overlapping harts,
    // rather than merely printing an always-zero field.
    let contention_ready = Arc::new(AtomicUsize::new(0));
    let contention_release = Arc::new(AtomicBool::new(false));
    let mut contention_handles = Vec::new();
    for index in 1..exec::MAX_HARTS {
        let hart = exec::HartId::new(index).expect("logical scheduler hart is valid");
        let task_ready = contention_ready.clone();
        let task_release = contention_release.clone();
        contention_handles.push(exec::spawn_pinned_on(
            hart,
            "smp-scheduler-contention",
            async move {
                task_ready.fetch_add(1, Ordering::AcqRel);
                while !task_release.load(Ordering::Acquire) {
                    core::hint::spin_loop();
                }
                for _ in 0..512 {
                    core::hint::black_box(exec::scheduler_stats());
                }
            },
        ));
    }
    let contention_preflight = sbi::time();
    while contention_ready.load(Ordering::Acquire) != exec::MAX_HARTS - 1
        && sbi::time().wrapping_sub(contention_preflight) < exec::TIMEBASE_HZ
    {
        exec::yield_now().await;
    }
    let contention_started = contention_ready.load(Ordering::Acquire) == exec::MAX_HARTS - 1;
    contention_release.store(true, Ordering::Release);
    if !contention_started {
        for handle in &contention_handles {
            let _ = handle.cancel();
        }
        println!("  smp queues: FAILED scheduler contention preflight");
        return;
    }
    for _ in 0..512 {
        core::hint::black_box(exec::scheduler_stats());
    }
    let mut contention_workers_ok = true;
    for handle in &contention_handles {
        let exit = handle.join().await;
        contention_workers_ok &= exit.state() == exec::TaskState::Exited && exit.polls() == 1;
    }

    let scheduler_lock_after = exec::scheduler_lock_stats();
    let scheduler_acquisitions = scheduler_lock_after
        .acquisitions
        .saturating_sub(scheduler_lock_before.acquisitions);
    let scheduler_contention = scheduler_lock_after
        .contended_acquisitions
        .saturating_sub(scheduler_lock_before.contended_acquisitions);
    if boot_initiator
        && all_online
        && unique_physical
        && exits_twice
        && exact_harts
        && ipis_observed
        && contention_workers_ok
        && scheduler_acquisitions > 0
        && scheduler_contention > 0
        && scheduler_contention <= scheduler_acquisitions
    {
        println!("  smp boot: four logical harts own four physical executors");
        println!("  smp queues: pinned hart1..hart3 tasks parked and resumed in place");
        println!("  smp ipi: boot-hart wakes reached all three remote executors");
        println!("  smp locks: PLIC/UART RX/virtio IRQ data handoff is lock-free");
        println!(
            "  smp locks: scheduler acquisitions delta={} contention delta={}",
            scheduler_acquisitions, scheduler_contention
        );
    } else {
        println!("  smp queues: FAILED physical SMP acceptance invariant");
    }
}

// Long enough that a sample spans tens of milliseconds under QEMU TCG. Short
// millisecond-scale probes let host scheduling jitter dominate the result.
const SMP_SCALE_ROUNDS: usize = 12_000_000;

#[inline(never)]
fn smp_work_segment(worker: usize) -> u64 {
    let mut value = 0x9e37_79b9_7f4a_7c15u64 ^ worker as u64;
    for iteration in 0..SMP_SCALE_ROUNDS {
        value ^= (iteration as u64).wrapping_add(0xa076_1d64_78bd_642f);
        value = value.rotate_left(17).wrapping_mul(0xe703_7ed1_a0b4_28db);
        core::hint::black_box(value);
    }
    value
}

/// Compare equal work executed sequentially and on four exact logical harts.
async fn smp_scale_demo() {
    if ipi::current_logical_hart() != Some(exec::HartId::BOOT)
        || !(0..exec::MAX_HARTS).all(|index| {
        ipi::is_online(exec::HartId::new(index).expect("logical scheduler hart is valid"))
    })
    {
        println!("VIBE_SMP_SCALE_FAILED harts_offline");
        return;
    }

    let serial_started = sbi::time();
    let mut serial_checksum = 0u64;
    for worker in 0..exec::MAX_HARTS {
        serial_checksum ^= smp_work_segment(worker);
    }
    let serial_ticks = sbi::time().saturating_sub(serial_started).max(1);

    let remote_ready = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicBool::new(false));
    let start_tick = Arc::new(AtomicU64::new(0));
    let finish_tick = Arc::new(AtomicU64::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let checksum = Arc::new(AtomicU64::new(0));
    let observed = Arc::new([const { AtomicU64::new(0) }; exec::MAX_HARTS]);
    let mut handles = Vec::new();

    // Start only the three remote workers first. The boot-hart shell remains
    // schedulable and can report a bounded preflight failure instead of
    // entering a four-way spin barrier before a remote executor ever ran.
    for index in 1..exec::MAX_HARTS {
        let hart = exec::HartId::new(index).expect("logical scheduler hart is valid");
        let task_ready = remote_ready.clone();
        let task_released = released.clone();
        let task_finish = finish_tick.clone();
        let task_finished = finished.clone();
        let task_checksum = checksum.clone();
        let task_observed = observed.clone();
        handles.push(exec::spawn_pinned_on(hart, "smp-scale-worker", async move {
            task_observed[index].store(
                ipi::current_logical_hart().map_or(0, |current| current.index() as u64 + 1),
                Ordering::SeqCst,
            );
            task_ready.fetch_add(1, Ordering::AcqRel);
            while !task_released.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }

            let result = smp_work_segment(index);
            task_checksum.fetch_xor(result, Ordering::AcqRel);
            if task_finished.fetch_add(1, Ordering::AcqRel) + 1 == exec::MAX_HARTS {
                task_finish.store(sbi::time(), Ordering::Release);
            }
        }));
    }

    let mut remotes_started = false;
    let preflight_started = sbi::time();
    while sbi::time().wrapping_sub(preflight_started) < exec::TIMEBASE_HZ {
        if remote_ready.load(Ordering::Acquire) == exec::MAX_HARTS - 1 {
            remotes_started = true;
            break;
        }
        exec::yield_now().await;
    }
    if !remotes_started {
        // Release any subset which reached the spin gate so no physical hart
        // remains permanently occupied after the diagnostic is printed.
        released.store(true, Ordering::Release);
        for handle in &handles {
            let _ = handle.cancel();
        }
        println!("VIBE_SMP_SCALE_FAILED remote_preflight");
        return;
    }

    observed[exec::HartId::BOOT.index()].store(1, Ordering::SeqCst);
    start_tick.store(sbi::time(), Ordering::Release);
    released.store(true, Ordering::Release);
    let boot_result = smp_work_segment(exec::HartId::BOOT.index());
    checksum.fetch_xor(boot_result, Ordering::AcqRel);
    if finished.fetch_add(1, Ordering::AcqRel) + 1 == exec::MAX_HARTS {
        finish_tick.store(sbi::time(), Ordering::Release);
    }

    let mut workers_ok = true;
    for handle in &handles {
        let exit = handle.join().await;
        workers_ok &= exit.state() == exec::TaskState::Exited && exit.polls() == 1;
    }
    let parallel_ticks = finish_tick
        .load(Ordering::Acquire)
        .saturating_sub(start_tick.load(Ordering::Acquire))
        .max(1);
    let exact_harts = observed.iter().enumerate().all(|(index, seen)| {
        seen.load(Ordering::SeqCst) == index as u64 + 1
    });
    let parallel_checksum = checksum.load(Ordering::Acquire);
    if !workers_ok || !exact_harts || parallel_checksum != serial_checksum {
        println!("VIBE_SMP_SCALE_FAILED worker_invariant");
        return;
    }
    let speedup_milli = serial_ticks.saturating_mul(1_000) / parallel_ticks;
    println!(
        "VIBE_SMP_SCALE {{\"schema\":\"vibeos.smp-scale\",\"version\":1,\"workers\":{},\"serial_ticks\":{},\"parallel_ticks\":{},\"speedup_milli\":{},\"checksum\":{}}}",
        exec::MAX_HARTS,
        serial_ticks,
        parallel_ticks,
        speedup_milli,
        parallel_checksum,
    );
}

/// Read a program from the console, terminated by a line containing only `.`.
async fn read_source() -> Option<String> {
    println!("  enter your program; finish with a single `.` on its own line");
    let mut src = String::new();
    loop {
        tty::prompt("  | ");
        let line = read_line().await?;
        if line == "." {
            return Some(src);
        }
        src.push_str(&line);
        src.push('\n');
    }
}

async fn compile_and_run(src: &str) {
    let t0 = sbi::time();
    let compiled = match crate::rustc::compile(src) {
        Ok(c) => c,
        Err(e) => {
            println!("  error: {}", e);
            return;
        }
    };
    let compile_us = (sbi::time() - t0) / (exec::TIMEBASE_HZ / 1_000_000);
    println!(
        "  compiled {} fn -> {} B of RV64 + {} B of data in {} us",
        compiled.funcs, compiled.bytes, compiled.data_bytes, compile_us
    );
    println!("  --- running natively ---");

    let out = crate::rustc::run(&compiled);
    report_run(&out);
}

async fn save_hello() {
    let w = world();
    let Some(service_cap) = w.saved_program else {
        println!("  saved program: offline (no writable block backend)");
        return;
    };
    let init = w.spaces["init"].clone();
    let lease = init
        .0
        .lock()
        .lookup_lease::<crate::saved_program::SavedProgramService>(service_cap, Rights::WRITE);
    let report = match lease {
        Ok(lease) => crate::saved_program::save_with(lease, crate::rustc::HELLO_SRC).await,
        Err(_) => Err(crate::saved_program::SavedProgramError::PermissionDenied),
    };
    match report {
        Ok(report) => {
            println!(
                "  saved `hello`: {} B source + {} B canonical VIBEEXE",
                report.source_bytes, report.executable_bytes
            );
            println!(
                "  durable artifact cap: slot {} generation {}, rights r",
                report.identity.slot(), report.identity.generation()
            );
            println!("  authority manifest: console=w memory=rw; Store WRITE absent");
        }
        Err(crate::saved_program::SavedProgramError::AlreadySaved) => {
            println!("  saved `hello`: already present; no object or grant appended");
        }
        Err(error) => println!("  saved `hello`: failed ({})", error),
    }
}

async fn run_saved_hello() {
    let w = world();
    let Some(service_cap) = w.saved_program else {
        println!("  saved program: offline (no readable block backend)");
        return;
    };
    let init = w.spaces["init"].clone();
    let lease = init
        .0
        .lock()
        .lookup_lease::<crate::saved_program::SavedProgramService>(service_cap, Rights::READ);
    let report = match lease {
        Ok(lease) => crate::saved_program::run_with(lease).await,
        Err(_) => Err(crate::saved_program::SavedProgramError::PermissionDenied),
    };
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            println!("  run `hello`: refused ({})", error);
            return;
        }
    };
    println!(
        "  recovered `hello`: cap slot {} generation {}, {} B source + {} B VIBEEXE",
        report.identity.slot(),
        report.identity.generation(),
        report.source_bytes,
        report.executable_bytes
    );
    println!(
        "  verified current compiler match; linked {} fn -> {} B RV64 + {} B data",
        report.funcs, report.compiled_bytes, report.data_bytes
    );
    println!("  authority: console=w memory=rw; Store WRITE absent");
    println!("  --- running recovered program ---");
    report_run(&report.outcome);
}

fn report_run(out: &crate::rustc::RunOutcome) {
    match out.aborted {
        Some(reason) => println!("  --- aborted: {} (after {} us) ---", reason, out.micros),
        None => println!("  --- exited with {} in {} us ---", out.value, out.micros),
    }
    if out.denied {
        println!("  note: output was suppressed -- `prog` console authority is absent or revoked");
    }
}

async fn run_lease_demo() {
    let t0 = sbi::time();
    let compiled = match crate::rustc::compile(crate::rustc::LEASE_SRC) {
        Ok(c) => c,
        Err(e) => {
            println!("  error: {}", e);
            return;
        }
    };
    let compile_us = (sbi::time() - t0) / (exec::TIMEBASE_HZ / 1_000_000);
    println!(
        "  compiled {} fn -> {} B of RV64 + {} B of data in {} us",
        compiled.funcs, compiled.bytes, compiled.data_bytes, compile_us
    );

    println!("  --- lease run 1: revoke before console operation 2 ---");
    if !crate::rustc::arm_console_revoke_hook(2) {
        println!("  refused: the console revocation hook is already armed");
        return;
    }
    let first = crate::rustc::run(&compiled);
    report_run(&first);
    if first.aborted.is_none() && first.value == 42 && first.revoked_caps > 0 {
        println!(
            "  note: hook revoked {} cap(s); the active memory lease completed",
            first.revoked_caps
        );
    } else {
        println!("  note: this demo requires fresh `prog` console and memory authority");
        return;
    }

    println!("  --- lease run 2: cold launch after revocation ---");
    let second = crate::rustc::run(&compiled);
    report_run(&second);
    println!("  note: no grant or hook was installed between runs");
}

/// Four operations a conventional OS would let you attempt and fail at runtime,
/// or would not model at all. Here each one is refused at the capability check.
async fn probe() {
    let w = world();

    // 1. The sensor holds SEND on telemetry. Ask it for RECV.
    let sensor: Arc<Space> = w.spaces["sensor"].clone();
    let sensor_cap = sensor.0.lock().list()[0].0;
    report(
        "sensor tries to RECV on the channel it publishes to",
        sensor
            .0
            .lock()
            .lookup_as::<Endpoint<Reading>>(sensor_cap, Rights::RECV)
            .map(|_| ()),
    );

    // 2. The logger holds RECV. Ask it for SEND, i.e. forge a reading.
    let logger = w.spaces["logger"].clone();
    let logger_cap = logger.0.lock().list()[0].0;
    report(
        "logger tries to SEND a forged reading",
        logger
            .0
            .lock()
            .lookup_as::<Endpoint<Reading>>(logger_cap, Rights::SEND)
            .map(|_| ()),
    );

    // 3. The logger's console cap is WRITE-only, with no GRANT. Try to pass it on.
    let mut scratch = crate::cap::CSpace::new("scratch");
    let logger_con = logger.0.lock().list()[1].0;
    report(
        "logger tries to hand its console cap to a third party",
        crate::cap::grant(&logger.0.lock(), logger_con, Rights::WRITE, &mut scratch).map(|_| ()),
    );

    // 4. Ask a WRITE-only cap to be re-derived with more rights than it has.
    let init = w.spaces["init"].clone();
    let weak = {
        let mut cs = init.0.lock();
        cs.derive(w.console, Rights::WRITE.union(Rights::GRANT))
            .unwrap()
    };
    report(
        "a WRITE|GRANT console cap tries to derive REVOKE for itself",
        init.0.lock().derive(weak, Rights::REVOKE).map(|_| ()),
    );

    exec::yield_now().await;
}

fn report(what: &str, outcome: Result<(), CapError>) {
    match outcome {
        Ok(()) => println!("  ALLOWED  {}   <-- this is a bug", what),
        Err(e) => println!("  REFUSED  {}\n           reason: {}", what, e),
    }
}

fn durable_demo() {
    use crate::durable::{
        recover, DecodeStatus, DerivationId, DurableRights, GrantFlags, GrantRecord,
        LogRecord, ObjectId, RecordBody, RecordChain, RecoveryPolicy, ResourceKind,
        RootPolicy, SlotIdentity, SpaceId, StoreId, TransactionId,
    };

    let store = StoreId::new(1).unwrap();
    let root = GrantRecord {
        derivation_id: DerivationId::new(10).unwrap(),
        parent_id: None,
        object_id: ObjectId::new(11).unwrap(),
        target: SlotIdentity {
            space: SpaceId::new(12).unwrap(),
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ.union(DurableRights::GRANT),
        resource_kind: ResourceKind::new(1).unwrap(),
        flags: GrantFlags::ROOT,
    };
    let transaction = TransactionId::new(20).unwrap();
    let mut chain = RecordChain::new(store);
    let mut sectors = Vec::new();
    sectors.push(chain.append(None, RecordBody::Format).unwrap());
    sectors.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end: 100 })
            .unwrap(),
    );
    let prepare = chain
        .append(Some(transaction), RecordBody::GrantPrepare(root.clone()))
        .unwrap();
    let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepare).unwrap() else {
        unreachable!()
    };
    sectors.push(prepare);
    sectors.push(
        chain
            .append(
                Some(transaction),
                RecordBody::GrantCommit {
                    prepare_sequence: decoded.record.sequence,
                    prepare_crc32c: decoded.crc32c,
                    derivation_id: root.derivation_id,
                },
            )
            .unwrap(),
    );
    let roots = [RootPolicy { grant: root.clone() }];
    let before = recover(&sectors, RecoveryPolicy { store_id: store, roots: &roots }).unwrap();

    sectors.push(
        chain
            .append(
                Some(TransactionId::new(21).unwrap()),
                RecordBody::RevokeTombstone { derivation_id: root.derivation_id },
            )
            .unwrap(),
    );
    let after = recover(&sectors, RecoveryPolicy { store_id: store, roots: &roots }).unwrap();

    println!("  durable-cap v1: 512-byte LE records, CRC32C + sealed chain");
    println!(
        "  committed grant: {} live root at sequence {}",
        before.grants.len(), before.last_sequence
    );
    println!(
        "  tombstone recovery: {} live grants, {} retained tombstone at sequence {}",
        after.grants.len(),
        after.tombstones.len(),
        after.last_sequence
    );
    println!("  authority result: stable IDs only; no path or object pointer was persisted");
}

const NET_COMMAND_TIMEOUT_MS: usize = 2_000;

async fn net_command(args: &[&str]) {
    let w = world();
    let (Some(outbound), Some(inbound), Some(control)) =
        (w.net_outbound, w.net_inbound, w.net_control)
    else {
        println!("  virtio-net: offline (no modern network transport discovered)");
        return;
    };
    let init = w.spaces["init"].clone();

    match args.first().copied().unwrap_or("info") {
        "info" => match net_info(&init, control) {
            Ok(info) if info.quarantined => {
                println!("  virtio-net: quarantined (reset was not confirmed)")
            }
            Ok(info) if info.online => println!(
                "  virtio-net: ready, queues rx=0/tx=1 size {}, header {}, features VERSION_1",
                info.queue_size, info.header_size
            ),
            Ok(_) => println!("  virtio-net: offline (driver component not attached)"),
            Err(error) => println!("  refused: {}", error),
        },
        "test" => match net_handshake(&init, outbound, inbound, control).await {
            Ok((before, after)) => {
                println!("  raw L2 HELLO -> CHALLENGE -> ACK: ok");
                println!(
                    "  dual-queue completion: ok (IRQ observed; rx +{}, tx +{})",
                    after.rx_packets.saturating_sub(before.rx_packets),
                    after.tx_packets.saturating_sub(before.tx_packets)
                );
            }
            Err(error) => println!("  raw L2 handshake: failed ({})", error),
        },
        "fault" => {
            let Some(component) = w.component_named("virtio-net") else {
                println!("  network fault recovery: driver component absent");
                return;
            };
            let generation_before = component.snapshot().generation;
            let epoch_before = match net_info(&init, control) {
                Ok(info) => info.session_epoch,
                Err(error) => {
                    println!("  network fault recovery: refused ({})", error);
                    return;
                }
            };
            let inject = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::WRITE);
            if inject
                .as_ref()
                .map_err(|_| crate::virtio_net::NetError::AuthorityRevoked)
                .and_then(crate::virtio_net::inject_fault_with)
                .is_err()
            {
                println!("  network fault recovery: control authority denied");
                return;
            }
            if let Err(error) = net_send(&init, outbound, crate::virtio_net::hello_packet()).await {
                println!("  network fault recovery: trigger failed ({})", error);
                return;
            }

            let mut restarted = None;
            for _ in 0..NET_COMMAND_TIMEOUT_MS {
                let snapshot = component.snapshot();
                let ready = snapshot.generation > generation_before
                    && snapshot.state == exec::TaskState::Running
                    && net_info(&init, control).is_ok_and(|info| {
                        info.online && info.session_epoch > epoch_before && !info.quarantined
                    });
                if ready {
                    restarted = Some(snapshot.generation);
                    break;
                }
                exec::sleep_ms(1).await;
            }
            let Some(generation_after) = restarted else {
                println!("  network fault recovery: supervisor did not restore the driver");
                return;
            };

            match net_handshake(&init, outbound, inbound, control).await {
                Ok(_) => println!(
                    "  network fault recovery: reset confirmed, generation {} -> {}, handshake ok",
                    generation_before, generation_after
                ),
                Err(error) => println!(
                    "  network fault recovery: restarted handshake failed ({})",
                    error
                ),
            }
        }
        other => println!(
            "  usage: net [info|test|fault] (got `{}`)",
            other
        ),
    }
}

fn net_info(
    init: &Arc<Space>,
    control: crate::cap::Cap,
) -> Result<crate::virtio_net::NetInfo, crate::virtio_net::NetError> {
    let lease = init
        .0
        .lock()
        .lookup_lease::<crate::virtio_net::NetDevice>(control, Rights::READ)
        .map_err(|_| crate::virtio_net::NetError::AuthorityRevoked)?;
    crate::virtio_net::info_with(&lease)
}

async fn net_send(
    init: &Arc<Space>,
    outbound: crate::cap::Cap,
    packet: Packet,
) -> Result<(), crate::virtio_net::NetError> {
    let mut pending = packet;
    for _ in 0..NET_COMMAND_TIMEOUT_MS {
        let lease = init
            .0
            .lock()
            .lookup_lease::<Endpoint<Packet>>(outbound, Rights::SEND)
            .map_err(|_| crate::virtio_net::NetError::AuthorityRevoked)?;
        match lease.with(|endpoint| endpoint.try_send(pending)) {
            Ok(()) => return Ok(()),
            Err(packet) => pending = packet,
        }
        exec::sleep_ms(1).await;
    }
    Err(crate::virtio_net::NetError::QueueFull)
}

async fn net_receive(
    init: &Arc<Space>,
    inbound: crate::cap::Cap,
) -> Result<Packet, crate::virtio_net::NetError> {
    for _ in 0..NET_COMMAND_TIMEOUT_MS {
        let lease = init
            .0
            .lock()
            .lookup_lease::<Endpoint<Packet>>(inbound, Rights::RECV)
            .map_err(|_| crate::virtio_net::NetError::AuthorityRevoked)?;
        if let Some(packet) = lease.with(Endpoint::try_recv) {
            return Ok(packet);
        }
        exec::sleep_ms(1).await;
    }
    Err(crate::virtio_net::NetError::TimedOut)
}

async fn net_handshake(
    init: &Arc<Space>,
    outbound: crate::cap::Cap,
    inbound: crate::cap::Cap,
    control: crate::cap::Cap,
) -> Result<
    (crate::virtio_net::NetInfo, crate::virtio_net::NetInfo),
    crate::virtio_net::NetError,
> {
    let before = net_info(init, control)?;
    if !before.online || before.quarantined {
        return Err(crate::virtio_net::NetError::Offline);
    }
    net_send(init, outbound, crate::virtio_net::hello_packet()).await?;
    let challenge = net_receive(init, inbound).await?;
    if !crate::virtio_net::is_challenge(&challenge) {
        return Err(crate::virtio_net::NetError::Protocol);
    }
    net_send(init, outbound, crate::virtio_net::ack_packet()).await?;

    let tx_target = before.tx_packets.saturating_add(2);
    for _ in 0..NET_COMMAND_TIMEOUT_MS {
        let after = net_info(init, control)?;
        if after.tx_packets >= tx_target
            && after.rx_packets > before.rx_packets
            && after.used_interrupts > before.used_interrupts
        {
            return Ok((before, after));
        }
        exec::sleep_ms(1).await;
    }
    Err(crate::virtio_net::NetError::TimedOut)
}

async fn block_command(args: &[&str]) {
    const SEED: &[u8] = b"VIBEOS-BLK-SECTOR-7-SEED-v1";
    const WRITTEN: &[u8] = b"VIBEOS-BLK-SECTOR-8-WRITE-v1";

    let w = world();
    let Some(block_cap) = w.block else {
        println!("  virtio-blk: offline (no modern block transport discovered)");
        return;
    };
    let init = w.spaces["init"].clone();
    match args.first().copied().unwrap_or("info") {
        "info" => {
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            match lease {
                Ok(lease) => {
                    let Ok(info) = crate::virtio_blk::info_with(&lease) else {
                        println!("  refused: block capability lacks read authority");
                        return;
                    };
                    if info.quarantined {
                        println!("  virtio-blk: quarantined (reset was not confirmed)");
                    } else if info.online {
                        println!(
                            "  virtio-blk: ready, capacity {} sectors, queue size {}",
                            info.capacity_sectors, info.queue_size
                        );
                    } else {
                        println!("  virtio-blk: offline (driver component not attached)");
                    }
                }
                Err(e) => println!("  refused: {}", e),
            }
        }
        "test" => {
            let irq_before = {
                let lease = init
                    .0
                    .lock()
                    .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
                lease
                    .as_ref()
                    .ok()
                    .and_then(|lease| crate::virtio_blk::info_with(lease).ok())
                    .map_or(0, |info| info.used_interrupts)
            };
            let read = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let sector = match read {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            match sector {
                Ok(sector)
                    if sector.starts_with(SEED)
                        && sector[SEED.len()..].iter().all(|byte| *byte == 0) =>
                {
                    println!("  sector 7 seed: ok")
                }
                Ok(_) => {
                    println!("  sector 7 seed: mismatch");
                    return;
                }
                Err(e) => {
                    println!("  sector 7 seed: failed ({})", e);
                    return;
                }
            }

            let mut data = [0u8; 512];
            data[..WRITTEN.len()].copy_from_slice(WRITTEN);
            let write = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(
                    block_cap,
                    Rights::WRITE,
                );
            let write = match write {
                Ok(lease) => crate::virtio_blk::write_with(lease, 8, data).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if let Err(e) = write {
                println!("  sector 8 write + flush: failed ({})", e);
                return;
            }
            let flush = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(
                    block_cap,
                    Rights::WRITE,
                );
            let flushed = match flush {
                Ok(lease) => crate::virtio_blk::flush_with(lease).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if let Err(e) = flushed {
                println!("  sector 8 write + flush: failed ({})", e);
                return;
            }
            let verify = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let verified = match verify {
                Ok(lease) => crate::virtio_blk::read_with(lease, 8).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            let irq_after = {
                let lease = init
                    .0
                    .lock()
                    .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
                lease
                    .as_ref()
                    .ok()
                    .and_then(|lease| crate::virtio_blk::info_with(lease).ok())
                    .map_or(irq_before, |info| info.used_interrupts)
            };
            match verified {
                Ok(observed) if observed == data && irq_after > irq_before => {
                    println!("  sector 8 write + flush: ok");
                    println!("  used-buffer IRQ delivery: ok");
                }
                Ok(observed) if observed == data => {
                    println!("  sector 8 write + flush: IRQ was not observed")
                }
                Ok(_) => println!("  sector 8 write + flush: readback mismatch"),
                Err(e) => println!("  sector 8 write + flush: failed ({})", e),
            }
        }
        "fault" => {
            crate::virtio_blk::inject_fault_after_publish();
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let result = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            match result {
                Err(crate::virtio_blk::BlockError::DriverFault) => {
                    println!("  injected fault: device reset confirmed, DMA released")
                }
                Err(e) => println!("  injected fault returned: {}", e),
                Ok(_) => println!("  injected fault was not observed"),
            }
        }
        "recover" => {
            let before = w
                .component_named("virtio-blk")
                .map(|component| component.snapshot().generation)
                .unwrap_or(0);
            crate::virtio_blk::inject_fault_after_publish();
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let fault = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if fault != Err(crate::virtio_blk::BlockError::DriverFault) {
                println!("  fault recovery: unexpected request result");
                return;
            }
            let mut restarted = false;
            for _ in 0..200 {
                let ready = w.component_named("virtio-blk").is_some_and(|component| {
                    let snapshot = component.snapshot();
                    snapshot.generation > before
                        && snapshot.state == exec::TaskState::Running
                        && crate::virtio_blk::is_online()
                });
                if ready {
                    restarted = true;
                    break;
                }
                exec::sleep_ms(1).await;
            }
            if !restarted {
                println!("  fault recovery: supervisor did not restart the driver");
                return;
            }
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let after = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if after.is_ok_and(|sector| {
                sector.starts_with(SEED)
                    && sector[SEED.len()..].iter().all(|byte| *byte == 0)
            }) {
                println!("  fault recovery: reset confirmed, fresh generation online");
            } else {
                println!("  fault recovery: restarted driver could not read");
            }
        }
        "timeout" => {
            let before = crate::virtio_blk::debug_waiter_counts();
            crate::virtio_blk::inject_timeout();
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let timed_out = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let retry = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            let after = crate::virtio_blk::debug_waiter_counts();
            let retry_matches_seed = retry.is_ok_and(|sector| {
                sector.starts_with(SEED)
                    && sector[SEED.len()..].iter().all(|byte| *byte == 0)
            });
            if timed_out == Err(crate::virtio_blk::BlockError::TimedOut)
                && retry_matches_seed
                && before == after
            {
                println!("  timeout recovery: reset-before-reuse, retry ok, waiters bounded");
            } else {
                println!("  timeout recovery: invariant failed");
            }
        }
        "cancel" => {
            let Some(component) = w.component_named("virtio-blk") else {
                println!("  cancellation recovery: driver component absent");
                return;
            };
            let _ = component.cancel();
            let mut cancelled = false;
            for _ in 0..100 {
                if component.snapshot().state == exec::TaskState::Cancelled {
                    cancelled = true;
                    break;
                }
                exec::yield_now().await;
            }
            if !cancelled || w.restart_component("virtio-blk").is_err() {
                println!("  cancellation recovery: lifecycle transition failed");
                return;
            }
            for _ in 0..200 {
                if crate::virtio_blk::is_online() {
                    break;
                }
                exec::sleep_ms(1).await;
            }
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let retry = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if retry.is_ok_and(|sector| {
                sector.starts_with(SEED)
                    && sector[SEED.len()..].iter().all(|byte| *byte == 0)
            }) {
                println!("  cancellation recovery: reset confirmed, explicit restart online");
            } else {
                println!("  cancellation recovery: restarted driver could not read");
            }
        }
        "revoke" => {
            let Some(space_cap) = w.block_space else {
                println!("  authority revocation: driver CSpace absent");
                return;
            };
            let target = init
                .0
                .lock()
                .lookup_as::<Space>(space_cap, Rights::REVOKE);
            let Ok(target) = target else {
                println!("  authority revocation: supervisor cap denied");
                return;
            };
            target.0.lock().revoke_all();
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let denied = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if denied != Err(crate::virtio_blk::BlockError::AuthorityRevoked)
                || w.restart_component("virtio-blk").is_err()
            {
                println!("  authority revocation: next operation was not denied");
                return;
            }
            for _ in 0..200 {
                if crate::virtio_blk::is_online() {
                    break;
                }
                exec::sleep_ms(1).await;
            }
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::virtio_blk::BlockDevice>(block_cap, Rights::READ);
            let retry = match lease {
                Ok(lease) => crate::virtio_blk::read_with(lease, 7).await,
                Err(_) => Err(crate::virtio_blk::BlockError::AuthorityRevoked),
            };
            if retry.is_ok_and(|sector| {
                sector.starts_with(SEED)
                    && sector[SEED.len()..].iter().all(|byte| *byte == 0)
            }) {
                println!("  authority revocation: next request denied, fresh grants online");
            } else {
                println!("  authority revocation: explicit restart failed");
            }
        }
        other => println!(
            "  usage: blk [info|test|fault|recover|timeout|cancel|revoke] (got `{}`)",
            other
        ),
    }
}

async fn store_command(args: &[&str]) {
    const OBJECT_KIND: u32 = 1;
    const MARKER: &[u8] = b"VIBEOS-STORE-OBJECT-v1";

    let w = world();
    let Some(store_cap) = w.store else {
        println!("  object store: offline (no writable block backend)");
        return;
    };
    let init = w.spaces["init"].clone();
    match args.first().copied().unwrap_or("info") {
        "info" => {
            let lease = init
                .0
                .lock()
                .lookup_lease::<crate::store::StoreService>(store_cap, Rights::READ);
            match lease.and_then(|lease| {
                crate::store::info_with(&lease).map_err(|_| CapError::InsufficientRights)
            }) {
                Ok(info) => println!(
                    "  object store: {}, {} object(s), {} of {} journal sectors used",
                    if info.ready {
                        "ready"
                    } else {
                        "recovery pending"
                    },
                    info.recovered_objects,
                    info.used_sectors,
                    crate::store::STORE_LOG_SECTORS
                ),
                Err(error) => println!("  refused: {}", error),
            }
        }
        "fault" => store_fault_recovery().await,
        "test" => {
            let mut payload: Vec<u8> = (0..900)
                .map(|index| ((index * 17 + 3) % 251) as u8)
                .collect();
            payload[..MARKER.len()].copy_from_slice(MARKER);
            let object_kind = crate::store::journal_object_kind(OBJECT_KIND)
                .expect("the acceptance object kind is non-zero");

            let read_only = {
                let mut cspace = init.0.lock();
                cspace.derive(store_cap, Rights::READ)
            };
            let denied = match read_only {
                Ok(read_only) => {
                    let lease = init
                        .0
                        .lock()
                        .lookup_lease::<crate::store::StoreService>(read_only, Rights::NONE);
                    match lease {
                        Ok(lease) => {
                            crate::store::put_with(lease, init.clone(), object_kind, &payload).await
                        }
                        Err(_) => Err(crate::store::StoreError::PermissionDenied),
                    }
                }
                Err(_) => Err(crate::store::StoreError::PermissionDenied),
            };
            if denied != Err(crate::store::StoreError::PermissionDenied) {
                println!("  read-only store put: invariant failed");
                return;
            }
            println!("  read-only store put: refused");

            let write = init
                .0
                .lock()
                .lookup_lease::<crate::store::StoreService>(store_cap, Rights::NONE);
            let object_cap = match write {
                Ok(lease) => {
                    match crate::store::put_with(lease, init.clone(), object_kind, &payload).await {
                        Ok(cap) => cap,
                        Err(error) => {
                            println!("  900-byte object commit: failed ({})", error);
                            return;
                        }
                    }
                }
                Err(error) => {
                    println!("  900-byte object commit: refused ({})", error);
                    return;
                }
            };

            let service = init
                .0
                .lock()
                .lookup_lease::<crate::store::StoreService>(store_cap, Rights::READ);
            let object = init
                .0
                .lock()
                .lookup_lease::<crate::store::StoredObject>(object_cap, Rights::READ);
            let read_back = match (service, object) {
                (Ok(service), Ok(object)) => crate::store::get_with(service, object).await,
                _ => Err(crate::store::StoreError::ObjectUnavailable),
            };
            if read_back.as_deref() != Ok(payload.as_slice()) {
                println!("  900-byte object commit + disk readback: mismatch");
                return;
            }
            println!("  900-byte object commit + disk readback: ok");

            let retired = init.0.lock().revoke(object_cap).unwrap_or(0);
            let denied_after_revoke = init
                .0
                .lock()
                .lookup_lease::<crate::store::StoredObject>(object_cap, Rights::READ)
                .is_err();
            if retired == 0 || !denied_after_revoke {
                println!("  object-cap revocation: invariant failed");
                return;
            }
            println!("  object-cap revocation: next read refused");
            println!("  namespace check: capability only; no path or ObjectId lookup");
        }
        other => println!("  usage: store [info|test|fault] (got `{}`)", other),
    }
}

async fn persistent_cspace_command(args: &[&str]) {
    let w = world();
    let Some(service_cap) = w.durable_cspace else {
        println!("  durable CSpace: offline (no writable block backend)");
        return;
    };
    if args.first().copied().unwrap_or("test") != "test" {
        println!("  usage: pcspace test");
        return;
    }
    let init = w.spaces["init"].clone();
    let lease = init
        .0
        .lock()
        .lookup_lease::<crate::durable_cspace::DurableCSpaceService>(
            service_cap,
            Rights::WRITE,
        );
    let report = match lease {
        Ok(lease) => crate::durable_cspace::test_with(lease).await,
        Err(_) => Err(crate::durable_cspace::DurableCSpaceError::PermissionDenied),
    };
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            println!("  durable CSpace test: failed ({})", error);
            return;
        }
    };
    println!(
        "  durable CSpace gate: ready, dependent {}",
        if report.dependent_started {
            "started"
        } else {
            "blocked"
        }
    );
    match report.phase {
        crate::durable_cspace::PersistentTestPhase::Boot1Created => {
            println!(
                "  boot1 root: slot {} generation {}, rights r---gx",
                report.root_slot, report.root_generation
            );
            println!(
                "  boot1 child: slot {} generation {} (descendant readback {})",
                report.child_slot,
                report.child_generation,
                if report.read_ok { "ok" } else { "mismatch" }
            );
        }
        crate::durable_cspace::PersistentTestPhase::Boot2Revoked => {
            println!(
                "  boot2 restored child: slot {} generation {}, readback {}",
                report.child_slot,
                report.old_child_generation,
                if report.read_ok { "ok" } else { "mismatch" }
            );
            println!(
                "  tombstone-first ancestor revoke: child {}, descendant {}",
                if report.old_child_absent { "absent" } else { "live" },
                if report.descendant_absent {
                    "absent"
                } else {
                    "live"
                }
            );
        }
        crate::durable_cspace::PersistentTestPhase::Boot3Reused => {
            println!(
                "  boot3 tombstoned child: slot {} generation {} absent",
                report.child_slot, report.old_child_generation
            );
            println!(
                "  slot reuse: slot {} generation {} (higher), readback {}",
                report.child_slot,
                report.child_generation,
                if report.read_ok { "ok" } else { "mismatch" }
            );
        }
        crate::durable_cspace::PersistentTestPhase::AlreadyComplete => {
            println!(
                "  persistent child already live: slot {} generation {}, readback {}",
                report.child_slot,
                report.child_generation,
                if report.read_ok { "ok" } else { "mismatch" }
            );
        }
    }
    println!(
        "  persistent-test Store WRITE: {}",
        if report.no_store_write {
            "absent"
        } else {
            "invariant failed"
        }
    );
}

async fn store_fault_recovery() {
    const CYCLES: usize = 4;
    const PROBE_BUDGET: usize = crate::store::STORE_CLIENT_MEMORY_BUDGET;

    let w = world();
    let Some(store_cap) = w.store else {
        println!("  store fault recovery: skipped (store offline)");
        return;
    };
    let Some(probe) = w.spawn_store_fault_probe("store-fault-probe", PROBE_BUDGET) else {
        println!("  store fault recovery: probe could not be created");
        return;
    };
    let owner = probe.memory_owner();
    let mut warm_remaining = None;
    let mut warm_live = None;
    let mut healthy = true;

    for cycle in 0..CYCLES {
        let reached_before = crate::store::fault_reached_count();
        let (_, join) = probe.join_current();
        let exit = join.await;
        let snapshot = probe.snapshot();
        let init = w.spaces["init"].clone();
        let store_busy = init
            .0
            .lock()
            .lookup_lease::<crate::store::StoreService>(store_cap, Rights::READ)
            .ok()
            .and_then(|lease| crate::store::info_with(&lease).ok())
            .is_some_and(|info| info.busy);
        healthy &= exit.state() == exec::TaskState::Faulted
            && crate::store::fault_reached_count() == reached_before + 1
            && snapshot.memory.live_bytes == 0
            && HEAP.arena_stats(snapshot.arena).is_none()
            && !store_busy;

        let (live, _, remaining) = HEAP.stats();
        if cycle == 1 {
            warm_live = Some(live);
            warm_remaining = Some(remaining);
        } else if cycle > 1 {
            healthy &= Some(remaining) == warm_remaining;
            healthy &= warm_live.is_some_and(|baseline| live <= baseline);
        }

        if cycle + 1 != CYCLES {
            healthy &= w.restart_component("store-fault-probe").is_ok();
        }
    }

    healthy &= w.remove_terminal_component(probe.snapshot().id);
    drop(probe);
    healthy &= HEAP.account_stats(owner).is_none();
    if healthy {
        println!(
            "  store fault recovery: {} raw faults, claim cleared, heap plateau",
            CYCLES
        );
    } else {
        println!("  store fault recovery: invariant failed");
    }
}
