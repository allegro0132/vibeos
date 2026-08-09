//! An interactive shell — itself just another async task holding capabilities.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::cap::{CapError, Rights};
use crate::chan::Endpoint;
use crate::dev::ConsoleDev;
use crate::world::{world, Reading, Space};
use crate::HEAP;
use crate::{exec, println, sbi, tty, uart};

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
            println!("  chan            telemetry channel depth and totals");
            println!("  bench           emit the versioned machine-readable benchmark suite");
            println!("  durable         recover a sealed capability log and tombstone");
            println!("  blk info|test   inspect or exercise the supervised block device");
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
                        "  usage: rustc [hello|demo|conform|lease|edit] (got `{}`)",
                        other
                    );
                    return;
                }
            };
            compile_and_run(&src).await;
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
