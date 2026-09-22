# Native standard-stream prerequisite

QEMU RV64GC/LP64D, four harts, 128 MiB: PASS. The admitted native context
uses the same bounded CommandIo transport as WASI, without running a WASI guest.
The transport grant is explicit in NativeTls; there is no ambient console.

The fixture verifies no-grant denial, nine ordered stdout writes into an
eight-chunk queue, a registered blocked writer before a same-hart peer drains,
stdin delivery and EOF, bad descriptor rejection, a registered blocked reader
before explicit grant denial wakes it, unchanged read buffer on denial, and
zero pending waiters after completion. All previous native probes also pass.
Read/write copies are bounded to IO_CHUNK (1024 bytes); short IO is intentional.
No RefCell or kernel lock remains held while the native stack is suspended.

Target C++ compilation of newlib _read/_write adapters passes, and mock host
contracts cover errno mappings and short IO. This QEMU fixture calls the Rust
C ABI directly: it does NOT yet run actual newlib stdio, V8 or Node.

The grant currently comes from trusted probe admission, not the VSH/CSpace
launcher. Explicit CommandIo denial is tested; arbitrary CSpace revocation,
per-descriptor close/fstat/isatty, file descriptors beyond stdio, and cooperative
V8 cancellation remain pending. These prerequisites do not complete M1.
