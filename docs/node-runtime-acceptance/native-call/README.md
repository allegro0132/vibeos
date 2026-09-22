# Normal-return native stack prerequisite

Built with nightly-2026-08-01, target `riscv64gc-unknown-none-elf`, firmware
features `wasi-ssh-upload,native-runtime-probe,native-call-probe`.

The QEMU test calls a Rust C-ABI function four times on a 256 KiB RW/NX alias,
checks unmapped adjacent guards, performs floating-point arithmetic, changes
FCSR, returns normally and verifies the original TLS pointer and FCSR. Each
stack is unmapped and freed after return. All four harts and a VSH echo pass.
The results bind the kernel and modified source hashes.

This is not a V8 execution, C++ destructor, suspend/resume, infinite-loop
cancellation or 100-invocation acceptance test. It does not inject a stack
fault or prove preservation of every FP register. No forced jump or arena
recovery is used by this call path.
