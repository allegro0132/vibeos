//! Board adapter for the dedicated C8.3 raw runtime-cost image.

use core::fmt::Arguments;

use vibeos_wasm_runtime_costs::{HeapWindow, HeapWindowObservation, Platform, RuntimeCostError};

struct KernelPlatform;

struct KernelHeapWindow(vibeos_core::heap::HeapLiveWindow<'static>);

impl HeapWindow for KernelHeapWindow {
    fn finish(self) -> HeapWindowObservation {
        let observation = self.0.finish();
        HeapWindowObservation {
            live_before: observation.live_before,
            peak_live_bytes: observation.peak_live_bytes,
            live_after: observation.live_after,
        }
    }
}

impl Platform for KernelPlatform {
    type HeapWindow<'a> = KernelHeapWindow;

    fn platform_id(&self) -> &'static str {
        if cfg!(feature = "qemu-virt") {
            "qemu-virt"
        } else {
            "milkv-duo-cv1800b"
        }
    }

    fn time(&self) -> u64 {
        crate::sbi::time()
    }

    fn timebase_hz(&self) -> u64 {
        crate::exec::timebase_hz()
    }

    fn begin_heap_window(&self) -> Option<Self::HeapWindow<'_>> {
        crate::HEAP.begin_live_window().ok().map(KernelHeapWindow)
    }

    fn log(&self, arguments: Arguments<'_>) {
        crate::uart::_print(format_args!("{arguments}\n"));
    }
}

pub async fn run() {
    let result = if crate::online_hart_count() == 1 {
        vibeos_wasm_runtime_costs::run(&KernelPlatform)
    } else {
        Err(RuntimeCostError::PlatformContract)
    };

    if let Err(error) = result {
        crate::println!(
            "VIBE_WASM_COST_FAILED {{\"schema\":\"vibeos.wasm-runtime-cost.failure\",\"version\":1,\"code\":{}}}",
            error.code(),
        );
        crate::sbi::shutdown(true);
    }
}
