//! Versioned, machine-readable measurements run by the real guest kernel.
//!
//! The benchmark policy and scenarios live here; the kernel supplies only the
//! clock, heap, compiler/executor, and logging capabilities through `Platform`.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Arguments;

use vibeos_core::cap::{CSpace, Resource, Rights};
use vibeos_core::chan::Endpoint;
use vibeos_core::exec;
use vibeos_core::heap::HeapSnapshot;

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

pub struct Compiled<P> {
    pub program: P,
    pub code_bytes: usize,
    pub data_bytes: usize,
}

pub struct RunOutcome {
    pub value: i64,
    pub ticks: u64,
    pub aborted: bool,
}

/// Capabilities required from the kernel to execute the portable suite.
pub trait Platform {
    type Program;

    fn time(&self) -> u64;
    fn timebase_hz(&self) -> u64;
    fn heap_snapshot(&self) -> HeapSnapshot;
    fn compile(&self, source: &str) -> Result<Compiled<Self::Program>, String>;
    fn run(&self, program: &Self::Program) -> RunOutcome;
    fn log(&self, arguments: Arguments<'_>);
}

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

fn emit<P: Platform>(
    platform: &P,
    name: &str,
    unit: &str,
    direction: Direction,
    warmup: usize,
    values: &mut [u64],
) {
    let summary = vibeos_core::bench::summarize(values)
        .expect("a benchmark metric always has at least one sample");
    platform.log(format_args!(
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
    ));
}

/// Run the complete guest-owned benchmark suite.
pub async fn run<P: Platform>(platform: &P) {
    let heap_start = platform.heap_snapshot();
    platform.log(format_args!(
        "VIBE_BENCH_META {{\"schema\":\"vibeos.bench.meta\",\"version\":{},\"clock\":\"riscv.rdtime\",\"timebase_hz\":{},\"target\":\"riscv64imac-unknown-none-elf\",\"profile\":\"release\",\"heap_start_live_bytes\":{}}}",
        SCHEMA_VERSION,
        platform.timebase_hz(),
        heap_start.live_bytes,
    ));

    ipc_round_trip(platform).await;
    irq_to_poll(platform).await;
    capability_lookup(platform);
    compiler_and_generated_code(platform);

    let mut heap = [platform.heap_snapshot().peak_live_bytes as u64];
    emit(
        platform,
        "heap_peak_bytes",
        "bytes",
        Direction::Lower,
        0,
        &mut heap,
    );

    platform.log(format_args!(
        "VIBE_BENCH_END {{\"schema\":\"vibeos.bench\",\"version\":{},\"metrics\":{}}}",
        SCHEMA_VERSION, 14,
    ));
}

async fn ipc_round_trip<P: Platform>(platform: &P) {
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
        let started = platform.time();
        requests.send(sequence as u64).await;
        let reply = replies.recv().await;
        let elapsed = platform.time().saturating_sub(started).max(1);
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
        platform,
        "ipc_roundtrip_ticks",
        "ticks",
        Direction::Lower,
        IPC_WARMUP,
        &mut samples,
    );
}

async fn irq_to_poll<P: Platform>(platform: &P) {
    let mut samples = Vec::with_capacity(IRQ_SAMPLES);
    for iteration in 0..(IRQ_WARMUP + IRQ_SAMPLES) {
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
        platform,
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

fn capability_lookup<P: Platform>(platform: &P) {
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
            let started = platform.time();
            for _ in 0..CAP_BATCH {
                let object = cspace
                    .lookup_as::<BenchResource>(cap, Rights::READ)
                    .expect("benchmark capability remains live");
                core::hint::black_box(object);
            }
            let total = platform.time().saturating_sub(started);
            let per_lookup = total.div_ceil(CAP_BATCH as u64).max(1);
            if iteration >= CAP_WARMUP {
                samples.push(per_lookup);
            }
        }
        let name = alloc::format!("cap_lookup_depth_{}_ticks", wanted);
        emit(
            platform,
            &name,
            "ticks_per_lookup",
            Direction::Lower,
            CAP_WARMUP,
            &mut samples,
        );
    }
}

fn compiler_and_generated_code<P: Platform>(platform: &P) {
    let source = vibeos_rustc::samples::BENCHMARK;
    for _ in 0..COMPILE_WARMUP {
        let compiled = platform
            .compile(source)
            .expect("fixed benchmark source must compile");
        core::hint::black_box(compiled.code_bytes);
    }

    let mut throughput = Vec::with_capacity(COMPILE_SAMPLES);
    for _ in 0..COMPILE_SAMPLES {
        let started = platform.time();
        let compiled = platform
            .compile(source)
            .expect("fixed benchmark source must compile");
        let elapsed = platform.time().saturating_sub(started).max(1);
        let bytes_per_second =
            (source.len() as u64).saturating_mul(platform.timebase_hz()) / elapsed;
        core::hint::black_box(compiled.code_bytes);
        throughput.push(bytes_per_second);
    }
    emit(
        platform,
        "compile_bytes_per_second",
        "source_bytes_per_second",
        Direction::Higher,
        COMPILE_WARMUP,
        &mut throughput,
    );

    let compiled = platform
        .compile(source)
        .expect("fixed benchmark source must compile");
    let mut code_size = [compiled.code_bytes as u64];
    emit(
        platform,
        "generated_code_bytes",
        "bytes",
        Direction::Lower,
        0,
        &mut code_size,
    );
    let mut data_size = [compiled.data_bytes as u64];
    emit(
        platform,
        "generated_data_bytes",
        "bytes",
        Direction::Lower,
        0,
        &mut data_size,
    );

    for _ in 0..RUN_WARMUP {
        let outcome = platform.run(&compiled.program);
        assert!(!outcome.aborted, "benchmark program aborted");
        assert_eq!(
            outcome.value, BENCH_RESULT,
            "benchmark program returned a wrong value"
        );
        core::hint::black_box(outcome.value);
    }
    let mut runtime = Vec::with_capacity(RUN_SAMPLES);
    for _ in 0..RUN_SAMPLES {
        let outcome = platform.run(&compiled.program);
        assert!(!outcome.aborted, "benchmark program aborted");
        assert_eq!(
            outcome.value, BENCH_RESULT,
            "benchmark program returned a wrong value"
        );
        core::hint::black_box(outcome.value);
        runtime.push(outcome.ticks.max(1));
    }
    emit(
        platform,
        "generated_runtime_ticks",
        "ticks",
        Direction::Lower,
        RUN_WARMUP,
        &mut runtime,
    );
}
