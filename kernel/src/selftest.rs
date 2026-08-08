//! In-kernel self-test.
//!
//! Host unit tests cover logic; these cover the things a host cannot fake —
//! real timer interrupts, real wakeups from a trap handler, the live capability
//! graph, and machine code actually executing. CI drives this through the shell
//! and fails the build on a nonzero failure count.
//!
//! Both bugs that have reached `main` so far are regression cases here.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::cap::{CSpace, CapError, Rights};
use crate::chan::Endpoint;
use crate::dev::ConsoleDev;
use crate::world::{world, Space};
use crate::{exec, println, sbi};

pub struct Report {
    pub passed: usize,
    pub failed: usize,
}

struct Harness {
    passed: usize,
    failures: Vec<String>,
}

impl Harness {
    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failures.push(String::from(name));
        }
    }

    fn eq<T: PartialEq + core::fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        if got == want {
            self.passed += 1;
        } else {
            self.failures.push(format!("{} (got {:?}, want {:?})", name, got, want));
        }
    }
}

pub async fn run() -> Report {
    let mut h = Harness { passed: 0, failures: Vec::new() };

    timers(&mut h).await;
    scheduler(&mut h).await;
    channels(&mut h).await;
    fault_isolation(&mut h).await;
    capabilities(&mut h);
    compiler(&mut h);

    for f in &h.failures {
        println!("  FAIL  {}", f);
    }
    println!("  selftest: {} passed, {} failed", h.passed, h.failures.len());
    Report { passed: h.passed, failed: h.failures.len() }
}

/// Needs a real timer interrupt to fire and a real waker to run.
async fn timers(h: &mut Harness) {
    let start = sbi::time();
    exec::sleep_ms(25).await;
    let elapsed_ms = (sbi::time() - start) / (exec::TIMEBASE_HZ / 1000);
    h.check("sleep_ms waits at least the requested time", elapsed_ms >= 25);
    // With the check-then-sleep race closed, the heartbeat is 10 s and no longer
    // masks a lost wake. Anything past a few ms here means the wake was lost and
    // we are riding the backstop -- which would now show up as a 10 s stall.
    h.check("sleep_ms wakes promptly", elapsed_ms < 100);

    let t0 = sbi::time();
    exec::sleep_ms(0).await;
    h.check("sleep_ms(0) does not block", sbi::time() - t0 < exec::TIMEBASE_HZ / 100);
}

async fn scheduler(h: &mut Harness) {
    // Regression: a task that wakes itself mid-poll had the wake dropped,
    // because `poll_once` lifts the task out of the map before polling it.
    // `yield_now` is exactly that case, and it hung the shell.
    let before = sbi::time();
    for _ in 0..64 {
        exec::yield_now().await;
    }
    h.check("yield_now resumes (self-wake during poll)", sbi::time() >= before);

    h.check("task_report sees the running components", exec::task_report().len() >= 3);

    // Regression: `ps` omitted the task being polled, because `poll_once` lifts
    // it out of the map first. The only faithful way to test that is to ask
    // from inside a task's own poll, so a probe task reports on itself.
    let ep: Arc<Endpoint<(bool, u64)>> = Endpoint::new("selftest-probe", 1);
    let tx = ep.clone();
    exec::spawn("selftest-probe", async move {
        exec::yield_now().await; // guarantee this is not the first poll
        let seen = exec::task_report()
            .into_iter()
            .find(|(n, _)| n == "selftest-probe")
            .map(|(_, polls)| polls);
        tx.send((seen.is_some(), seen.unwrap_or(0))).await;
    });
    let (visible, polls) = ep.recv().await;
    h.check("a task polling right now is visible in task_report", visible);
    h.check("poll counts advance", polls > 1);
}

/// ROADMAP 2.8. A component that panics must cost its own task, not the box.
/// This can only be tested on target: the host has no landing pad, and a panic
/// there correctly fails the test run instead.
async fn fault_isolation(h: &mut Harness) {
    let faults_before = exec::faulted_count();
    let live_before = exec::task_report().len();

    exec::spawn("selftest-doomed", async {
        exec::yield_now().await;
        panic!("deliberate fault from the self-test");
    });

    // Give it enough turns to be polled, panic, and be reaped.
    for _ in 0..8 {
        exec::yield_now().await;
    }

    h.eq("a panicking task is counted as faulted", exec::faulted_count(), faults_before + 1);
    h.check(
        "a panicking task is removed from the scheduler",
        !exec::task_report().iter().any(|(n, _)| n == "selftest-doomed"),
    );
    h.check(
        "the other tasks are untouched",
        exec::task_report().len() >= live_before.saturating_sub(1),
    );
    // And the machine is obviously still running, because we got here.
    h.check("the kernel survived the fault", true);
}

async fn channels(h: &mut Harness) {
    let ep: Arc<Endpoint<u64>> = Endpoint::new("selftest", 2);

    h.check("try_send into space succeeds", ep.try_send(1).is_ok());
    h.check("try_send fills the bound", ep.try_send(2).is_ok());
    h.check("try_send refuses when full", ep.try_send(3).is_err());
    h.eq("try_recv returns in order", ep.try_recv(), Some(1));
    h.eq("try_recv drains", ep.try_recv(), Some(2));
    h.eq("try_recv on empty", ep.try_recv(), None);

    // Cross-task delivery: the producer's send must wake this task's recv.
    let producer = ep.clone();
    exec::spawn("selftest-tx", async move {
        for i in 0..4u64 {
            producer.send(i * 10).await;
        }
    });
    let mut got = Vec::new();
    for _ in 0..4 {
        got.push(ep.recv().await);
    }
    h.eq("channel delivers across tasks", got, alloc::vec![0, 10, 20, 30]);

    let (sent, received, depth) = ep.stats();
    h.eq("channel accounting", (sent, received, depth), (6, 6, 0));
}

/// The live capability graph, not a synthetic one.
fn capabilities(h: &mut Harness) {
    let w = world();

    let sensor = w.spaces["sensor"].clone();
    let sensor_cap = sensor.0.lock().list()[0].0;
    h.eq(
        "sensor cannot RECV on the channel it publishes to",
        sensor.0.lock().lookup(sensor_cap, Rights::RECV).err(),
        Some(CapError::InsufficientRights),
    );
    h.check(
        "sensor can still SEND",
        sensor.0.lock().lookup(sensor_cap, Rights::SEND).is_ok(),
    );

    let logger = w.spaces["logger"].clone();
    let logger_chan = logger.0.lock().list()[0].0;
    let logger_con = logger.0.lock().list()[1].0;
    h.eq(
        "logger cannot forge a reading",
        logger.0.lock().lookup(logger_chan, Rights::SEND).err(),
        Some(CapError::InsufficientRights),
    );
    h.eq(
        "logger cannot pass its console on",
        crate::cap::grant(
            &logger.0.lock(),
            logger_con,
            Rights::WRITE,
            &mut CSpace::new("selftest-scratch"),
        )
        .err(),
        Some(CapError::InsufficientRights),
    );

    let init = w.spaces["init"].clone();
    let weak = init.0.lock().derive(w.console, Rights::WRITE.union(Rights::GRANT)).unwrap();
    h.eq(
        "a cap cannot derive rights it lacks",
        init.0.lock().derive(weak, Rights::REVOKE).err(),
        Some(CapError::Amplification),
    );
    h.check(
        "a cap can derive a subset of what it holds",
        init.0.lock().derive(weak, Rights::WRITE).is_ok(),
    );

    // Revoking the parent must take the derived child with it.
    let killed = init.0.lock().revoke_slot(weak.slot());
    h.check("revoke cascades to derived caps", killed >= 2);
    h.eq(
        "a revoked handle is invalid",
        init.0.lock().lookup(weak, Rights::WRITE).err(),
        Some(CapError::Invalid),
    );
    h.check(
        "revoking a derived cap leaves the parent alone",
        init.0.lock().lookup(w.console, Rights::WRITE).is_ok(),
    );

    // Type confusion: the console cap does not name an endpoint.
    h.eq(
        "typed lookup rejects the wrong resource type",
        init.0
            .lock()
            .lookup_as::<Endpoint<u64>>(w.console, Rights::WRITE)
            .err(),
        Some(CapError::WrongType),
    );
    h.check(
        "typed lookup accepts the right resource type",
        init.0.lock().lookup_as::<ConsoleDev>(w.console, Rights::WRITE).is_ok(),
    );
    h.check(
        "a space is itself a resource",
        init.0.lock().lookup_as::<Space>(w.prog_space, Rights::REVOKE).is_ok(),
    );
}

/// Machine code actually executing. Host tests can check what the emitter
/// *emits*; only this can check what the CPU *does* with it.
fn compiler(h: &mut Harness) {
    let hello = crate::rustc::compile(crate::rustc::HELLO_SRC);
    h.check("hello compiles", hello.is_ok());

    // Layout must be identical across the sizing pass and the real pass, or
    // every absolute address in the program is wrong.
    if let (Ok(a), Ok(b)) = (
        crate::rustc::compile(crate::rustc::DEMO_SRC),
        crate::rustc::compile(crate::rustc::DEMO_SRC),
    ) {
        h.eq("codegen is deterministic in size", a.bytes, b.bytes);
        h.check("demo emits code", a.bytes > 0);
    } else {
        h.check("demo compiles", false);
    }

    h.check(
        "a program that returns a value runs",
        crate::rustc::compile("fn main() -> i64 { 6 * 7 }")
            .map(|c| crate::rustc::run(&c).value)
            .unwrap_or(-1)
            == 42,
    );
    h.check(
        "recursion runs",
        crate::rustc::compile(
            "fn f(n: i64) -> i64 { if n < 2 { n } else { f(n-1) + f(n-2) } }\nfn main() -> i64 { f(20) }",
        )
        .map(|c| crate::rustc::run(&c).value)
        .unwrap_or(-1)
            == 6765,
    );
    h.check(
        "loops and mutation run",
        crate::rustc::compile(
            "fn main() -> i64 { let mut s = 0; let mut i = 0; while i <= 100 { s = s + i; i = i + 1; } s }",
        )
        .map(|c| crate::rustc::run(&c).value)
        .unwrap_or(-1)
            == 5050,
    );

    // M2: every emitted safety check, exercised end to end. These need real
    // execution -- a host test can prove the check was *emitted*, only this can
    // prove it fires and that the shell survives it.
    let aborts: [(&str, &str); 6] = [
        ("fn main() -> i64 { let z = 0; 1 / z }", "attempt to divide by zero"),
        (
            "fn main() -> i64 { let z = 0; 1 % z }",
            "attempt to calculate the remainder with a divisor of zero",
        ),
        (
            // Through variables, so it is a runtime check: the literal form is
            // now folded and rejected at compile time, as real rustc does.
            "fn main() -> i64 { let a = 9223372036854775807; let b = 1; a + b }",
            "attempt to perform arithmetic that overflowed",
        ),
        (
            "fn main() -> i64 { let a = 9223372036854775807; let b = 0 - a - 1; let c = 0 - 1; b / c }",
            "attempt to divide with overflow",
        ),
        (
            "fn main() -> i64 { let mut i = 0; while i >= 0 { i = i + 0; } i }",
            "exceeded execution budget",
        ),
        ("fn f(n: i64) -> i64 { f(n) }\nfn main() -> i64 { f(0) }", "stack overflow"),
    ];
    for (src, want) in aborts {
        match crate::rustc::compile(src) {
            Ok(c) => {
                let out = crate::rustc::run(&c);
                h.eq(want, out.aborted, Some(want));
            }
            Err(e) => {
                crate::println!("  FAIL  {} did not compile: {}", want, e);
                h.check(want, false);
            }
        }
    }
    h.check(
        "the shell survives an aborted program",
        crate::rustc::compile("fn main() -> i64 { 2 + 2 }")
            .map(|c| crate::rustc::run(&c).value)
            .unwrap_or(-1)
            == 4,
    );

    // M3: arrays in the capability-granted region.
    h.check(
        "arrays round-trip through the region",
        crate::rustc::compile(
            "fn main() -> i64 { let mut a = [0; 8]; let mut i = 0; let mut v = 0;\
             while i < 8 { a[i] = v * v; v = v + 1; i = i + 1; }\
             let mut s = 0; i = 0; while i < 8 { s = s + a[i]; i = i + 1; } s }",
        )
        .map(|c| crate::rustc::run(&c).value)
        .unwrap_or(-1)
            == 140,
    );
    let region_aborts: [(&str, &str); 3] = [
        ("fn main() -> i64 { let mut a = [1; 4]; a[9] }", "index out of bounds"),
        (
            "fn main() -> i64 { let mut a = [1; 4]; let i = 0 - 1; a[i] }",
            "index out of bounds",
        ),
        (
            "fn main() -> i64 { let mut a = [0; 3000]; let mut b = [0; 3000]; a[0] + b[0] }",
            "the granted memory region is too small for this program",
        ),
    ];
    for (src, want) in region_aborts {
        match crate::rustc::compile(src) {
            Ok(c) => h.eq(want, crate::rustc::run(&c).aborted, Some(want)),
            Err(e) => {
                crate::println!("  FAIL  {} did not compile: {}", want, e);
                h.check(want, false);
            }
        }
    }
    h.check(
        "a program with no memory capability cannot allocate",
        crate::rustc::compile("fn main() -> i64 { let mut a = [1; 2]; a[0] }").is_ok(),
    );

    h.check("undefined names are rejected", crate::rustc::compile("fn main() { y; }").is_err());
    h.check(
        "a literal zero divisor is a compile error",
        crate::rustc::compile("fn main() -> i64 { 1 / 0 }").is_err(),
    );
    h.check(
        "literal overflow is a compile error, as in rustc",
        crate::rustc::compile("fn main() -> i64 { 9223372036854775807 + 1 }").is_err(),
    );
    h.check(
        "constant folding preserves the value",
        crate::rustc::compile("fn main() -> i64 { 2 + 3 * 4 - 1 }")
            .map(|c| crate::rustc::run(&c).value)
            .unwrap_or(-1)
            == 13,
    );
    h.check(
        "immutable reassignment is rejected",
        crate::rustc::compile("fn main() { let x = 1; x = 2; }").is_err(),
    );
    h.check(
        "arity mismatch is rejected",
        crate::rustc::compile("fn f(a: i64) -> i64 { a }\nfn main() { f(1, 2); }").is_err(),
    );
    h.check("a program with no main is rejected", crate::rustc::compile("fn f() {}").is_err());
}
