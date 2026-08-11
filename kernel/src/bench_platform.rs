//! Kernel capabilities supplied to the acceptance benchmark suite.

use core::fmt::Arguments;

use vibeos_kernel_acceptance::bench::{Compiled, Platform, RunOutcome};

struct KernelPlatform;

impl Platform for KernelPlatform {
    type Program = crate::rustc::Compiled;

    fn time(&self) -> u64 {
        crate::sbi::time()
    }

    fn timebase_hz(&self) -> u64 {
        crate::exec::timebase_hz()
    }

    fn heap_snapshot(&self) -> vibeos_core::heap::HeapSnapshot {
        crate::HEAP.snapshot()
    }

    fn compile(&self, source: &str) -> Result<Compiled<Self::Program>, alloc::string::String> {
        crate::rustc::compile(source).map(|program| Compiled {
            code_bytes: program.bytes,
            data_bytes: program.data_bytes,
            program,
        })
    }

    fn run(&self, program: &Self::Program) -> RunOutcome {
        let outcome = crate::rustc::run(program);
        RunOutcome {
            value: outcome.value,
            ticks: outcome.ticks,
            aborted: outcome.aborted.is_some(),
        }
    }

    fn log(&self, arguments: Arguments<'_>) {
        crate::uart::_print(format_args!("{arguments}\n"));
    }
}

pub async fn run() {
    vibeos_kernel_acceptance::bench::run(&KernelPlatform).await;
}
