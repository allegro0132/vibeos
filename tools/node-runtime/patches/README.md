# Native V8 port patches (M1 in progress)

Apply in filename order to the exact Node archive in `sources.lock.json`, using
`scripts/build-v8.py prepare`. These patches are not a completed Node platform.

- `0001`: distinct VibeOS target, host/target compiler separation, Darwin host
  linking, V8 OS detection, and native synchronization/clock bridge calls.
- `0002`: compile the pinned RISC-V backend without WebAssembly and fix Abseil's
  non-mmap poison-pointer branch referencing a branch-local variable.
- `0003`: Abseil task identity, native predicate waits and timed waiter, and
  monotonic timeout calculations. Compiler C++ TLS replaces pthread identity;
  the pinned bare-metal GCC emits emutls calls. Per-context allocation is being
  qualified separately, including dynamic initialization and normal-exit
  destructors; full static C/C++ runtime integration remains open.
- `0004`: Abseil realtime clock and suspendable timed sleep bridge.
- `0005`: disable unavailable ELF loader/signal-stack diagnostics on VibeOS,
  exclude the POSIX failure-signal handler, and use a native predicate-wait
  mutex for the process-lifetime cctz timezone cache.
- `0006`: read the pinned newlib timezone rules instead of nonstandard `tm`
  fields. Offsets use the opposite sign to POSIX seconds-west; UTC remains
  zero and DST uses its own rule rather than assuming a one-hour adjustment.
- `0007`: do not request GCC's `libatomic` for the Darwin x64 host generator;
  retain the target's atomic-library requirement.
- `0008`: regenerate GYP through its own driver, not through Node configure
  with GYP arguments. The latter silently resets configure choices. A forced
  regeneration must preserve `config.gypi` and generated host/target flags
  byte-for-byte. The regeneration command retains `-fmake-vibeos`; config OS
  alone does not select the generator flavor.
- `0009`: compile the VibeOS V8 memory adapter for the target only. Heap data
  mappings reject executable permissions; shared mappings and large address
  reservations report unsupported. Real page operations remain unresolved
  Rust bridge calls until the kernel implementation is supplied. The static
  flag block has a separate read-only image-data registration contract.

- `0010`: permit inactive sampler construction without OS signal handles;
  sampling activation and direct sampling fail explicitly. CPU profiling must
  be rejected by the launcher before reaching these fatal internal APIs.

- `0011`: register target-only V8 clock/sleep/task-identity methods. Wall time
  uses the existing granted clock adapter; positive sleep intervals wait on a
  never-ready predicate until the native scheduler deadline. Clock failures,
  failed waits and invalid task identities cannot silently succeed.

- `0012`: route RISC-V instruction-cache flushing to the native local/SBI
  all-hart fence instead of Linux syscall headers. The kernel bridge fails
  fatally if synchronization cannot complete; it never grants executable data.

- `0013`: provide V8 stack-position and stack-start queries from the current
  admitted native stack. Frame addresses may equal the exclusive upper bound;
  actual storage and the kernel sp must remain inside it.

- `0014`: supply V8 thread object lifecycle for the single-threaded platform.
  Background starts return false/ENOTSUP and release any synchronous-start
  semaphore; joining an unstarted unsupported thread is fatal. Key-based TLS
  APIs and general native worker creation are not provided by this adapter.

- `0015`: provide buffer formatting and bounded-copy methods using the pinned
  C runtime, including upstream truncation/termination semantics. Negative
  formatting lengths are rejected before conversion to an unsigned size.

- `0016`: enable Abseil LowLevelAlloc via a separate TCB page-allocation ABI,
  retaining the upstream arena algorithm and enabling dependent identity,
  semaphore and graph-cycle implementations. Async signal safety remains
  unsupported. TCB pages need process-lifetime ownership/accounting and actual
  reclamation. The Rust backend passes its direct C ABI QEMU probe; actual
  Abseil arena integration remains unqualified.

The newlib offset convention is visible in its upstream
[localtime implementation](https://sourceware.org/pipermail/newlib/2014/011730.html)
and the pinned toolchain's `sys/_tz_structs.h`. This adaptation still requires
invocation-scoped environment/TZ setup and lifecycle validation; compilation
does not establish timezone isolation across invocations.

The files retain upstream behavior for existing targets. VibeOS bridge functions
are declarations only at this stage: no substitute implementation, fake clock,
busy-loop wait or successful no-op is supplied. The target must fail to link
until the actual runtime implements these calls.

The host generator and target engine remain separate artifacts. A successful
`base` build is a library compilation check; neither that result nor a successful
host snapshot build proves V8 executes in VibeOS. The required QEMU expression,
exception and GC gate is still open.

- `0017`: provide V8 stdio diagnostic formatting and Unix-style directory
  separator methods. Output uses the pinned newlib streams and still requires
  the invocation-aware `_write` bridge. No direct UART fallback or filesystem
  access is introduced. Standalone target compilation passes; a diagnostic
  link with this object reduces unresolved symbols from 62 to 54. This object
  has not yet been integrated into the active engine build or run in QEMU.

- `0018`: supply the non-ICU timezone cache against pinned newlib rules.
  Standard offsets convert seconds west into milliseconds east; DST uses
  the actual difference between standard/daylight rules. Invalid/nonfinite
  dates are rejected before integer conversion. Compilation and diagnostic
  linking pass for this object, but TZ isolation and target execution remain
  unqualified. The launcher must install/reset each invocation's TZ environment.

- `0019`: supply static-image V8 initialization, RV64 ABI frame alignment,
  shared-library enumeration (none), and upstream abort/exit behavior through
  newlib. The executor owns scheduling; external profiling is unsupported.
  The unused default Linux profiler filename is never opened. `_exit` remains
  a required kernel backend, not an isolate-cleanup mechanism. Diagnostic
  linking resolves eight OS methods; fatal target execution is unqualified.

- `0020`: provide V8 stack diagnostics using a bounded RV64 frame-pointer
  walk and raw-address output for offline symbolization. Unix signal stack
  dumping is explicitly unsupported. Each frame is checked for alignment,
  stack bounds and increasing address before reading its two-word record.
  Target compilation passes; the standalone diagnostic link has 40 unresolved
  symbols (down from 45), with no new missing symbols.

- `0021`: place the real V8 flag object in a dedicated `.vibeos_v8_flags`
  section for exact linker-bound admission. The QEMU script keeps whole pages
  in that section; the native bridge freezes only the full range to RO/NX.
  A separate probe page passes QEMU protection checks. Real V8 flag execution
  remains unqualified; production builds must omit the probe page.

- `0022`: restore upstream Unix C++ defaults for the bare-metal target without
  inheriting pthread/linker assumptions. V8 engine/support targets now disable
  C++ exceptions and RTTI and strict aliasing, while GYP's explicit exception
  overrides (e.g. Torque) remain effective. This fixes a demonstrated omission
  in the target configuration; the full firmware relocation issue must still
  be rechecked after rebuilding all affected objects. JS exceptions remain
  an independent required execution check.

- `0023`: provide V8 regular-file and temporary-file wrappers over newlib, plus
  the single-threaded invocation's virtual process identity. The syscall layer
  must enforce root/permission boundaries; these wrappers are not authorization.
  Integrated compilation passes, and the firmware link has 16 missing runtime
  symbols after resolving the final three missing V8 OS methods.
