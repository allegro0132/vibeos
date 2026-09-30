# Final native toolchain regression (M5 qualified)

The production image includes the M4 lifetime fixes and omits audit,
allocation-trace and fatal-probe features. It links the locked-source archives
from the [complete M4 rebuild](../lifecycle-audit/fresh-build/) with the final
runtime and Rust kernel. No host JavaScript execution substitutes for guest
checking, transformation or execution.

Production ELF SHA-256:
`108d02239d3f1d154712c5ba4b4dbe5a0b6836d46d6f75446c0daa8835e9faae`.
Probe ELF SHA-256:
`b78df3c166b2c85ef3c4110e0603b6b59e81a5fb041d2768fb0060b76fcdadb4`.
Links take 48.12 s and 48.09 s. `production-link/` and `js-probe-link/`
record archive/member, source, toolkit and compiler identities.
`version-manifest.json` collects the source/toolchain/toolkit locks.

## Final target qualification

All Node/toolkit cases use 1 GiB, four-hart QEMU. The tool-authorized esbuild
fixture command exists only in the separate probe image. Each result binds its
ELF and source hashes; `local-suite-results.json` records local suite ordering
and verifies that the production ELF did not change between tests.

| Suite | Host wall time | Evidence |
|---|---:|---|
| Official tsc: project/noEmit, JS/declarations, emitted JS, type diagnostics | 79.79 s | [tsc](tsc/results.json) |
| tsx: CJS/ESM, dynamic/offline imports, TSX/custom factory, mapped errors | 146.26 s | [tsx](tsx/results.json) |
| Node/VSH: files/streams/modules/exit, CPU and idle cancellation | 16.30 s | [node](node/results.json) |
| Project/tool directory and descriptor boundaries | 37.62 s | [boundary](boundary/results.json) |
| Cancellation during real WASI transform and restart | 31.71 s | [tsx-cancel](tsx-cancel/results.json) |
| Output backpressure and drain | 9.96 s | [backpressure](backpressure/results.json) |
| Separate unrecoverable V8 OOM | 4.02 s | [oom](oom/results.json) |
| 100 production invocations | 98.01 s | [cycles](cycles/results.json) |
| Authorized OpenSSH PTY Node/tsc/tsx | 52.08 s | [ssh](ssh/results.json) |
| Native esbuild sync/Promise/exit cleanup | 137.23 s | [esbuild-node](esbuild-node/results.json) |
| Adapted official esbuild JS API | 72.32 s | [esbuild-api](esbuild-api/results.json) |
| Explicit unsupported-feature errors and restart | 11.25 s | [exclusions](exclusions/results.json) |

The production cycle test's last three rounded whole-system heap observations
are 143.1 MiB live and 401.5 MiB peak; the first is 143.0 MiB live and 400.8 MiB
peak. These rounded observations are not exact per-job leak counts. The M4
audit separately checks exact allocator, handle, grant and owner reclamation.
WASI transforms report 96,523,904-byte owner peaks and complete reclamation.

`ssh/` retains the actual PTY transcript. The original 2-second keepalive and
one missed response limit remain unchanged. Single-hart long-transform SSH
responsiveness is outside this four-hart qualification.

## Shared subsystem regressions

- `file-tree/`: three-boot default-profile persistent tree test, hard links,
  symlinks, recursive removal, GC pressure, cold recovery and powered-off checks.
- `default-shell/`: default legacy-shell MMU and VSH golden-output tests pass.
- `wasi/`: default Wasmi QEMU + OpenSSH gate passes standard Rust/C commands,
  arguments/binary input/stderr/exit, rejected keys, upload integrity/containment,
  disconnect recovery, local pipes, post-boot compilation, 100 reclaimed
  invocations and restart/persistence. Original 2-second SSH keepalive retained.
- `host/pinned-components.log`: file-store, VSH and WASI-command tests pass
  (150 test results, five existing opt-in I/O/batch cases ignored).
- `host/runtime-core-net.log`: core, WASI runtime and network tests pass
  (465 passing results including an isolated child-process check; two existing
  opt-in/doctest cases ignored). Genuine Rust/C standard-library execution is
  additionally covered by the target WASI gate.

The expanded Python suite has **83 passes and one pre-existing failure**:
`test_kernel_client_adapters_have_no_board_selection` rejects existing
storage-bench board conditions. `host/preexisting-frontend-check.json` proves
the offending pattern existed before this port; `host/scripts.log.gz` retains
the failure. This broader suite is not reported green. The affected component
suites and required target regressions pass.

## Retained investigation records

`initial-tsc-input-race/` records sending a command before the preceding native
invocation relinquished stdin. The tsc/tsx drivers now require result text and
the subsequent prompt before sending another command. No runtime behavior or
timeout threshold was weakened. The final tsc and tsx runs use that correction.

`initial-addon-expectation/` expected the lower-level `ERR_DLOPEN_FAILED`, but
Node's explicit `kNoNativeAddons` boundary rejects earlier with
`ERR_DLOPEN_DISABLED`. `initial-watch-expectation/` expected the JS wrapper error,
but the VSH launcher rejects earlier with `Unavailable` and an explanatory
message. The final exclusion test verifies these actual boundaries plus
worker, sync/async child-process, TCP/UDP, signal, watch/poll and WebAssembly
exclusions, followed by successful Node restart.

`default-shell/wrong-file-profile.log` retains an initial MMU run with a
file-tree image missing its required disk. The default shell image passes.
`wasi/m5-wasi-build.log` retains an initial compiler-path mismatch; the successful
build explicitly selects the locked nightly RUSTC/RUSTDOC, as in existing
repository scripts. No toolchain version was changed.

See [requirements audit](requirements.md) for the original plan's coverage.
