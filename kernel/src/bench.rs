//! Versioned, machine-readable measurements from the real guest kernel.
//!
//! The host runner owns environment metadata (QEMU version/CPU/commit) and
//! regression policy. This module owns only observations that must happen in
//! the guest: every duration is read from the architectural `rdtime` clock and
//! emitted in raw ticks so consumers never lose resolution to unit rounding.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::cap::{CSpace, Resource, Rights};
use crate::chan::Endpoint;
use crate::{exec, println, sbi, HEAP};

const SCHEMA_VERSION: u32 = 1;

const IPC_WARMUP: usize = 32;
const IPC_SAMPLES: usize = 257;
const IRQ_WARMUP: usize = 16;
const IRQ_SAMPLES: usize = 129;
const CAP_WARMUP: usize = 3;
const CAP_SAMPLES: usize = 41;
const CAP_BATCH: usize = 4096;
const COMPILE_WARMUP: usize = 3;
const COMPILE_SAMPLES: usize = 21;
const RUN_WARMUP: usize = 5;
const RUN_SAMPLES: usize = 41;
const BENCH_RESULT: i64 = 731_462_992;

#[derive(Clone, Copy)]
enum Direction {
    Lower,
    Higher,
}

impl Direction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lower => "lower",
            Self::Higher => "higher",
        }
    }
}

fn emit(name: &str, unit: &str, direction: Direction, warmup: usize, values: &mut [u64]) {
    let summary = vibeos_core::bench::summarize(values)
        .expect("a benchmark metric always has at least one sample");
    println!(
        "VIBE_BENCH {{\"schema\":\"vibeos.bench.metric\",\"version\":{},\"name\":\"{}\",\"unit\":\"{}\",\"direction\":\"{}\",\"warmup\":{},\"samples\":{},\"min\":{},\"p50\":{},\"p95\":{},\"max\":{},\"mean\":{}}}",
        SCHEMA_VERSION,
        name,
        unit,
        direction.as_str(),
        warmup,
        summary.count,
        summary.min,
        summary.p50,
        summary.p95,
        summary.max,
        summary.mean,
    );
}

/// Run the complete guest-owned benchmark suite.
pub async fn run() {
    let heap_start = HEAP.snapshot();
    println!(
        "VIBE_BENCH_META {{\"schema\":\"vibeos.bench.meta\",\"version\":{},\"clock\":\"riscv.rdtime\",\"timebase_hz\":{},\"target\":\"riscv64gc-unknown-none-elf\",\"profile\":\"release\",\"heap_start_live_bytes\":{}}}",
        SCHEMA_VERSION,
        exec::TIMEBASE_HZ,
        heap_start.live_bytes,
    );

    ipc_round_trip().await;
    irq_to_poll().await;
    capability_lookup();
    compiler_and_generated_code();

    let mut heap = [HEAP.snapshot().peak_live_bytes as u64];
    emit("heap_peak_bytes", "bytes", Direction::Lower, 0, &mut heap);

    println!(
        "VIBE_BENCH_END {{\"schema\":\"vibeos.bench\",\"version\":{},\"metrics\":{}}}",
        SCHEMA_VERSION, 14,
    );
}

async fn ipc_round_trip() {
    let requests: Arc<Endpoint<u64>> = Endpoint::new("bench-requests", 1);
    let replies: Arc<Endpoint<u64>> = Endpoint::new("bench-replies", 1);
    let responder_requests = requests.clone();
    let responder_replies = replies.clone();
    let total = IPC_WARMUP + IPC_SAMPLES;
    let responder = exec::spawn_tracked("bench-ipc-responder", async move {
        for _ in 0..total {
            let sequence = responder_requests.recv().await;
            responder_replies.send(sequence).await;
        }
    });

    let mut samples = Vec::with_capacity(IPC_SAMPLES);
    for sequence in 0..total {
        let started = sbi::time();
        requests.send(sequence as u64).await;
        let reply = replies.recv().await;
        let elapsed = sbi::time().saturating_sub(started).max(1);
        assert_eq!(reply, sequence as u64, "IPC benchmark reply order changed");
        if sequence >= IPC_WARMUP {
            samples.push(elapsed);
        }
    }
    let exit = responder.join().await;
    assert_eq!(
        exit.state(),
        exec::TaskState::Exited,
        "IPC responder did not exit"
    );
    emit(
        "ipc_roundtrip_ticks",
        "ticks",
        Direction::Lower,
        IPC_WARMUP,
        &mut samples,
    );
}

async fn irq_to_poll() {
    let mut samples = Vec::with_capacity(IRQ_SAMPLES);
    for iteration in 0..(IRQ_WARMUP + IRQ_SAMPLES) {
        // The probe records time at timer IRQ dispatch and finishes on the
        // first subsequent poll of this task, excluding the programmed sleep
        // itself. It lives in `core::exec` so `timer_tick` can stamp the exact
        // interrupt-side boundary.
        let probe = exec::arm_irq_poll_probe()
            .unwrap_or_else(|_| panic!("IRQ-to-poll benchmark probe could not be armed"));
        exec::sleep_ms(1).await;
        let elapsed = probe
            .finish()
            .expect("IRQ-to-poll benchmark timer IRQ was not observed")
            .max(1);
        if iteration >= IRQ_WARMUP {
            samples.push(elapsed);
        }
    }
    emit(
        "irq_to_poll_ticks",
        "ticks",
        Direction::Lower,
        IRQ_WARMUP,
        &mut samples,
    );
}

struct BenchResource;

impl Resource for BenchResource {
    fn kind(&self) -> &'static str {
        "bench"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn capability_lookup() {
    const DEPTHS: [usize; 7] = [0, 1, 2, 4, 8, 16, 32];

    let resource = Arc::new(BenchResource);
    let mut cspace = CSpace::new("bench-capability-depth");
    let mut cap = cspace.mint(resource, Rights::READ.union(Rights::GRANT));
    let mut depth = 0;
    for wanted in DEPTHS {
        while depth < wanted {
            cap = cspace
                .derive(cap, Rights::READ.union(Rights::GRANT))
                .expect("benchmark derivation stays within parent rights");
            depth += 1;
        }

        let mut samples = Vec::with_capacity(CAP_SAMPLES);
        for iteration in 0..(CAP_WARMUP + CAP_SAMPLES) {
            let started = sbi::time();
            for _ in 0..CAP_BATCH {
                let object = cspace
                    .lookup_as::<BenchResource>(cap, Rights::READ)
                    .expect("benchmark capability remains live");
                core::hint::black_box(object);
            }
            let total = sbi::time().saturating_sub(started);
            let per_lookup = total.div_ceil(CAP_BATCH as u64).max(1);
            if iteration >= CAP_WARMUP {
                samples.push(per_lookup);
            }
        }
        let name = alloc::format!("cap_lookup_depth_{}_ticks", wanted);
        emit(
            &name,
            "ticks_per_lookup",
            Direction::Lower,
            CAP_WARMUP,
            &mut samples,
        );
    }
}

fn compiler_and_generated_code() {
    for _ in 0..COMPILE_WARMUP {
        let compiled = crate::rustc::compile(crate::rustc::BENCH_SRC)
            .expect("fixed benchmark source must compile");
        core::hint::black_box(compiled.bytes);
    }

    let mut throughput = Vec::with_capacity(COMPILE_SAMPLES);
    for _ in 0..COMPILE_SAMPLES {
        let started = sbi::time();
        let compiled = crate::rustc::compile(crate::rustc::BENCH_SRC)
            .expect("fixed benchmark source must compile");
        let elapsed = sbi::time().saturating_sub(started).max(1);
        let bytes_per_second =
            (crate::rustc::BENCH_SRC.len() as u64).saturating_mul(exec::TIMEBASE_HZ) / elapsed;
        core::hint::black_box(compiled.bytes);
        throughput.push(bytes_per_second);
    }
    emit(
        "compile_bytes_per_second",
        "source_bytes_per_second",
        Direction::Higher,
        COMPILE_WARMUP,
        &mut throughput,
    );

    let compiled = crate::rustc::compile(crate::rustc::BENCH_SRC)
        .expect("fixed benchmark source must compile");
    let mut code_size = [compiled.bytes as u64];
    emit(
        "generated_code_bytes",
        "bytes",
        Direction::Lower,
        0,
        &mut code_size,
    );
    let mut data_size = [compiled.data_bytes as u64];
    emit(
        "generated_data_bytes",
        "bytes",
        Direction::Lower,
        0,
        &mut data_size,
    );

    for _ in 0..RUN_WARMUP {
        let outcome = crate::rustc::run(&compiled);
        assert!(outcome.aborted.is_none(), "benchmark program aborted");
        assert_eq!(
            outcome.value, BENCH_RESULT,
            "benchmark program returned a wrong value"
        );
        core::hint::black_box(outcome.value);
    }
    let mut runtime = Vec::with_capacity(RUN_SAMPLES);
    for _ in 0..RUN_SAMPLES {
        let outcome = crate::rustc::run(&compiled);
        assert!(outcome.aborted.is_none(), "benchmark program aborted");
        assert_eq!(
            outcome.value, BENCH_RESULT,
            "benchmark program returned a wrong value"
        );
        core::hint::black_box(outcome.value);
        runtime.push(outcome.ticks.max(1));
    }
    emit(
        "generated_runtime_ticks",
        "ticks",
        Direction::Lower,
        RUN_WARMUP,
        &mut runtime,
    );
}
