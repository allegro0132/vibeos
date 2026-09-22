# Fatal native-image exit

A dedicated `native-exit-probe` image completes prior native fixtures, then
enters the protected native stack and calls the Rust fatal-exit C ABI with 42.
It records the native status and requests SBI shutdown with SYSTEM_FAILURE.
No stack jump, destructor drain, isolate cleanup or arena reclamation is used.

Run 1 failed the initial assumption that QEMU would return host exit 1. The
actual QEMU 11.0.3/OpenSBI process exits 0, while the serial log records native
status 42. Run 2 repeats the same frozen kernel and passes the corrected
shutdown contract: terminal QEMU process, native fatal marker, prior normal
return marker, no returned fatal call and no panic. Host status propagation
remains false and is explicitly recorded. This is not an invocation exit-code
test and must not be used to claim Node process.exit semantics.

C++ `_exit` delegates to this fatal backend; `_kill` returns ENOTSUP because
v1 provides no POSIX signal delivery. Target libbase compilation and mock host
signal-error tests pass. The fatal QEMU fixture calls the Rust C ABI directly;
actual newlib abort/exit, V8 fatal errors and OOM remain unqualified.

Reproduce with native-exit-probe firmware:
`python3 scripts/test-native-exit-qemu.py --work target/native-exit-repeat --kernel target/riscv64gc-unknown-none-elf/release/vibeos-qemu-virt`
