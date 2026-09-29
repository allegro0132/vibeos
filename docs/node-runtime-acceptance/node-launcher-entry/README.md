# Launcher-facing native Node invocation ABI

`vibeos_node_run(argc, argv, eval, eval_length)` now owns per-invocation
environment/isolate/loop setup and normal cleanup independently of the test
script and its assertions. It uses the reusable Node process, the caller's
admitted native context, and upstream LoadEnvironment startup dispatch.
Arguments exclude launcher --root; the trusted caller owns all input buffers
until return. Limits are 128 argv items, 64 KiB argument content and 1 MiB eval.

The file gate passes argv for /main.cjs. The eval gate passes source through
invocation-owned Node EnvironmentOptions and execArgv -e; pinned Node copies
those options for each environment. Real eval checks require and argv before
running the same complete project fixture. Both QEMU runs pass module/file/
stream/async work, subtree isolation and normal exit 0 with zero waiters.

The file run precedes a small admission-order correction: the ABI initializes
C/C++ process state before building std::string arguments. The eval run includes
that correction and bounds each argument before copying it.

The launcher file entry also passes explicit `process.exit(7)`: native return 7,
normal teardown, no fatal error and zero waiters (`explicit-exit/`).

The loop uses UV_RUN_ONCE to return to the supervisor's cancellation boundary.
CommandIo now registers an owned native-domain cancellation observer, wakes it
on cancellation, and releases it on completion. Libuv readiness observes the
cancelled grant and returns after a cleanup iteration, including UV_RUN_DEFAULT.
Generic semaphore waits retain their existing synchronization semantics.

`idle-cancel/` runs upstream eval with a 60-second timer through the launcher
ABI. A test hook arms the same-hart cancellation peer only once native waiting
actually receives a timeout above one second. The observed timeout is 60000000
microseconds; cancellation, normal cleanup and native return 130 finish in
114 ms, below the 10-second acceptance bound, with zero waiters and the outside
file unchanged. Eight CommandIo host tests pass, including observer registration
before/after cancellation and release on completion. Link 56 preceded a Waker
destructor lock-scope adjustment and was not run; link 57 includes the final
source and is the accepted image.

No VSH command is registered yet. Uncaught exceptions through the new ABI still need dedicated acceptance;
prior such evidence exercises the older embedding gate. CPU-loop cancellation
now passes through the launcher ABI after patch 0057; see `cpu-cancel/` for the
initial fatal exit and successful retest.

The final cancellation implementation also passes ordinary main-file startup
regression (`idle-cancel-regression/`, link 58): CJS/ESM, files, stdin, timers,
Promise, zlib, directory authority and exit 0 all pass with zero waiters.

The launcher ABI also passes 100 serial main-file invocations (`repeat-100/`),
including the new callback-stop patch, exit 0 and zero waiters every time.
