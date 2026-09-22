# Native platform adapter tests

These are host unit tests for adapters, not V8/Node target acceptance.
After verifying/unpacking the pinned Node archive:

```sh
clang++ -std=c++20 -pthread \
  -I tools/node-runtime/platform \
  -I target/node-runtime/unpacked/node/node-v24.14.0/deps/v8/third_party/abseil-cpp \
  tools/node-runtime/tests/native-mutex-test.cc \
  target/node-runtime/unpacked/node/node-v24.14.0/deps/v8/third_party/abseil-cpp/absl/base/internal/raw_logging.cc \
  target/node-runtime/unpacked/node/node-v24.14.0/deps/v8/third_party/abseil-cpp/absl/base/log_severity.cc \
  -o target/node-runtime/native-mutex-test
./target/node-runtime/native-mutex-test
```

The test uses a real host condition variable to implement the declared blocking
bridge contract. It forces four simultaneous parked contenders, checks mutual
exclusion across 40,000 increments, verifies that all waiters return, and reuses
the same mutex after those callers exit. Do not compile with `NDEBUG`.
The Rust implementation must separately prove this contract on VibeOS.

`v8-smoke.cc` is a separate target-only, one-shot V8 execution gate. The
`scripts/build-v8.py smoke` phase compiles it using the configured target
library's generated flags and records `runtime_acceptance=NOT_RUN`. It must be
linked to real V8 and called by the kernel on a protected native stack with
working TLS, FP state, memory, clocks, entropy and suspendable wait bridges.
It requests jitless/single-threaded mode, checks an expression and exception,
allocates JS objects, requires a full-GC callback and disposes V8 normally.
It supplies no host execution path. Passing compilation is not acceptance;
the QEMU serial log must show all checks and a successful return to the kernel.
Because this gate disposes process-global V8, it is not the later reusable
Node invocation service or the 100-cycle lifecycle test.
