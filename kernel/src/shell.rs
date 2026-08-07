//! An interactive shell — itself just another async task holding capabilities.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::cap::{CapError, Rights};
use crate::chan::Endpoint;
use crate::dev::ConsoleDev;
use crate::heap::HEAP;
use crate::world::{world, Reading, Space};
use crate::{exec, println, print, sbi, uart};

pub async fn shell_task(boot_time: u64) {
    println!("\ntype `help` for commands.\n");
    let mut line = String::new();
    loop {
        print!("vibe> ");
        line.clear();
        loop {
            let b = uart::read_byte().await;
            match b {
                b'\r' | b'\n' => {
                    println!();
                    break;
                }
                0x7f | 0x08 => {
                    if line.pop().is_some() {
                        print!("\x08 \x08");
                    }
                }
                0x03 => {
                    println!("^C");
                    line.clear();
                    break;
                }
                b if (0x20..0x7f).contains(&b) => {
                    line.push(b as char);
                    print!("{}", b as char);
                }
                _ => {}
            }
        }
        if !line.is_empty() {
            run(&line, boot_time).await;
        }
    }
}

async fn run(line: &str, boot_time: u64) {
    let mut parts = line.split_whitespace();
    let Some(cmd) = parts.next() else { return };
    let rest: Vec<&str> = parts.collect();

    match cmd {
        "help" => {
            println!("  ps              live tasks and how many times each was polled");
            println!("  spaces          capability spaces in the system");
            println!("  caps <space>    dump a space's capability table");
            println!("  probe           attempt four illegal operations, show the refusals");
            println!("  revoke <space>  pull a component's authority at runtime");
            println!("  chan            telemetry channel depth and totals");
            println!("  mem             kernel heap usage");
            println!("  uptime          seconds since boot");
            println!("  echo <text>     write via init's console capability");
            println!("  halt            shut the machine down");
        }

        "ps" => {
            println!("  {:<10} {:>8}", "TASK", "POLLS");
            for (name, polls) in exec::task_report() {
                println!("  {:<10} {:>8}", name, polls);
            }
            println!("  ({} tasks exited)", exec::completed_count());
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
            println!("  {:<12} {:<9} {:<8} {}", "HANDLE", "KIND", "RIGHTS", "OBJECT");
            for (cap, kind, rights, desc) in space.0.lock().list() {
                println!("  {:<12} {:<9} {:<8} {}", alloc::format!("{}", cap), kind, alloc::format!("{}", rights), desc);
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
            if target != "guest" {
                println!("  init holds a REVOKE cap on `guest` only; nothing to revoke on `{}`", target);
                return;
            }
            // Authority to do this comes from init's cap on the guest *space*.
            let init = w.spaces["init"].clone();
            let space_res = {
                let cs = init.0.lock();
                cs.lookup_as::<Space>(w.guest_space, Rights::REVOKE)
            };
            match space_res {
                Ok(guest) => {
                    let killed = guest.0.lock().revoke_slot(0);
                    println!("  revoked {} cap(s) in `guest`", killed);
                    println!("  (its next heartbeat will fail -- no restart, no signal)");
                }
                Err(e) => println!("  refused: {}", e),
            }
        }

        "chan" => {
            let w = world();
            let init = w.spaces["init"].clone();
            let ep = init.0.lock().lookup_as::<Endpoint<Reading>>(w.telemetry, Rights::READ);
            match ep {
                Ok(ep) => {
                    let (sent, recv, depth) = ep.stats();
                    println!("  telemetry  sent={} recv={} queued={}", sent, recv, depth);
                }
                Err(e) => println!("  refused: {}", e),
            }
        }

        "mem" => {
            let (live, peak, free) = HEAP.stats();
            println!("  live {:>7} B   peak {:>7} B   bump remaining {:>9} B", live, peak, free);
        }

        "uptime" => {
            let ticks = sbi::time() - boot_time;
            let ms = ticks / (exec::TIMEBASE_HZ / 1000);
            println!("  up {}.{:03} s", ms / 1000, ms % 1000);
        }

        "echo" => {
            let w = world();
            let init = w.spaces["init"].clone();
            let con = init.0.lock().lookup_as::<ConsoleDev>(w.console, Rights::WRITE);
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

/// Four operations a conventional OS would let you attempt and fail at runtime,
/// or would not model at all. Here each one is refused at the capability check.
async fn probe() {
    let w = world();

    // 1. The sensor holds SEND on telemetry. Ask it for RECV.
    let sensor: Arc<Space> = w.spaces["sensor"].clone();
    let sensor_cap = sensor.0.lock().list()[0].0;
    report(
        "sensor tries to RECV on the channel it publishes to",
        sensor.0.lock().lookup_as::<Endpoint<Reading>>(sensor_cap, Rights::RECV).map(|_| ()),
    );

    // 2. The logger holds RECV. Ask it for SEND, i.e. forge a reading.
    let logger = w.spaces["logger"].clone();
    let logger_cap = logger.0.lock().list()[0].0;
    report(
        "logger tries to SEND a forged reading",
        logger.0.lock().lookup_as::<Endpoint<Reading>>(logger_cap, Rights::SEND).map(|_| ()),
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
        cs.derive(w.console, Rights::WRITE.union(Rights::GRANT)).unwrap()
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
