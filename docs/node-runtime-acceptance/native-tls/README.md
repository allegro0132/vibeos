# Native TLS identity prerequisite

This is a four-hart, 128 MiB QEMU identity probe, not the V8/Node acceptance gate.
The firmware was built with pinned nightly-2026-08-01 and features
`wasi-ssh-upload,native-runtime-probe`. `results.json` records the kernel and
source hashes, QEMU version and observed physical/logical pairs. Physical and
logical indices differ in this run; all four probes and the VSH echo pass.

`host-tests.log` records 101 core and 2 RISC-V mapping library tests. The RISC-V
bare-metal identity path itself is exercised by QEMU, not these host tests.
No C++ TLS destructor, native stack/FPU, V8 or Node claim follows from this test.
