# Complete toolkit cross-build qualification

The qualified M3 production image is recorded under `final/`, with ELF SHA-256
`c50dd05c6fe479aabff7ea63c8708c37595eae9e4889ea609f5fcc2912167364`.
It includes bounded native file reads and worker-hart esbuild admission, with
temporary diagnostic logging removed. Its SSH, tsc, tsx and Node/VSH tests
pass. The remaining local suites and the matching probe image's esbuild API
regressions also pass. All final result manifests match the current source
hashes. This closes M3; precise resource inventories, complete final authority
revocation coverage, and the M5 WASI/MMU regressions remain separate work.
The earlier images and failures below explain the corrections and do not
substitute for this image's checks.

| Final target suite | Host wall time | Result |
| --- | ---: | --- |
| Official tsc project/noEmit/JS/declarations/diagnostics | 78.44 s | Pass |
| tsx CJS/ESM/TSX/offline import/source maps/relaunch | 148.82 s | Pass |
| Node/VSH files, streams, exit and cancellation | 16.33 s | Pass |
| Tool/project boundaries and multi-chunk reads | 37.31 s | Pass |
| tsx cancellation during WASI transform | 32.22 s | Pass |
| Output backpressure | 8.02 s | Pass |
| Separate fatal V8 OOM | 3.70 s | Pass: whole-image shutdown |
| 100 production Node invocations | 97.32 s | Pass |
| Authenticated OpenSSH PTY Node/tsc/tsx | 52.10 s | Pass |
| Native esbuild JS binding/Promise/exit cleanup | 128.89 s | Pass |
| Adapted official esbuild JS API | 67.00 s | Pass |

The production cycle test's final three rounded heap samples are all 143.1 MiB
live and 401.5 MiB peak. These are whole-system observations, not exact per-job
leak counts. WASI transforms report 96,523,904-byte owner peaks and audited
reclamation with zero capabilities/waiters. Source/version/compiler manifests
are retained alongside each test and link. The probe ELF is separately bound
by `final/js-probe-link/`; its tool-authorized fixture command is absent from
the production image.

This qualification uses 1 GiB, four-hart QEMU. Worker-hart WASI admission keeps
the boot hart responsive during synchronous module validation/instantiation.
Single-hart execution falls back to the boot hart; its long-transform SSH
responsiveness is not qualified here. User workers remain unsupported.

The `m3-clean-2` work directory was prepared from the pinned official Node
24.14.0 archive. Preparation and configuration succeeded, followed by complete
V8 engine, libuv, Node dependency and Node builds. Every recorded phase exits
zero and binds its port inputs, source archive, compiler and configuration.
The libuv input includes the bounded async regular-file read accumulation fix.

`driver.log` records phase ordering. Raw phase stdout/stderr are retained as
gzip files; `compressed-logs.json` records their uncompressed hashes and sizes.
`prepared.json` binds all 93 port inputs at preparation time. Later build
phases validate those inputs before proceeding.

Reproduce in a fresh work directory with:

```sh
python3 scripts/build-v8.py prepare --work target/FRESH_BUILD --jobs 4
python3 scripts/build-v8.py configure --work target/FRESH_BUILD --jobs 4
python3 scripts/build-v8.py engine --work target/FRESH_BUILD --jobs 4
python3 scripts/build-v8.py uv --work target/FRESH_BUILD --jobs 4
python3 scripts/build-v8.py node-deps --work target/FRESH_BUILD --jobs 4
python3 scripts/build-v8.py node --work target/FRESH_BUILD --jobs 4
```

Production toolkit linking passes; `shell-link/` retains the complete archive
and runtime compilation inputs. The production ELF SHA-256 is
`4b79857539b11aee70573ac8a04cb79b6cf0daeb0f8e3fedd7152576987db279`.
No preceding incremental Node/V8 archive was reused by this fresh build.

`tsc/` passes official TypeScript 5.9.3 version, project/noEmit checking,
JS/declaration emission, guest execution of emitted JS (result 43), and
`bad.ts(1,14)` TS2322 diagnostics with nonzero exit. The guest performs all
checking and compilation. Source inputs remain unchanged during execution.

`tsx/` also passes on the same ELF: cross-file CJS/ESM, dynamic import,
offline dependency, TSX with a custom factory, source-mapped exceptions and
successful relaunch. Exactly ten WASI transforms are started and reclaimed,
each with zero capabilities and waiters. Source inputs remain unchanged.

All eight local suites pass on that ELF; `local-suite-results.json` records
their ordering, elapsed times and unchanged kernel hash. In addition to tsc
and tsx, these cover Node/VSH, tool/project boundaries, transform cancellation,
stdout backpressure, fatal OOM and 100 production Node invocations. The cycle
heap observations retain the rounded-statistics limitation described in the
dedicated cycle evidence.

SSH qualification exposed an outstanding first-use responsiveness problem:
`ssh/run-1/` failed because its fixture tried a VSH `write` command unavailable
in this SSH session; `ssh/run-2/` correctly prepared files through Node, then
OpenSSH's existing 2-second, one-missed-response keepalive policy disconnected
during the first `tsc --version`. The roughly 40 MiB tool pack was initialized
synchronously on the event-loop hart. The initializer now yields after each
64 KiB write and scopes SYSTEM allocation to individual future polls, but
`ssh/run-3/` still times out under the unchanged keepalive policy. Initialization
alone is therefore not an established explanation; file loading and native
compilation still need investigation. These local passes do not establish that
the SSH issue is fixed.
That initial image did not close M3; final qualification is recorded above.

Further diagnostics distinguish two long native turns. `ssh/stage-diagnostic/`
places the first timeout inside `node::LoadEnvironment`; tool initialization
takes only about 88 ms. `ssh/file-read-diagnostic/` shows the large TypeScript
file begins reading but never closes before timeout. Native reads were copying
all preceding chunks again for each 1 KiB request. The new reader skips volatile
prefix metadata without copying it, and native reads yield before completion.
`ssh/bounded-read-diagnostic/` then passes tsc version, project/declaration emit,
and emitted-JS execution through SSH, but times out at tsx startup.

`ssh/wasi-start-diagnostic/` isolates that second timeout to synchronous
`WasiInvocation::new`; the esbuild module load itself takes about 17 ms. A
worker-hart admission path corrects this. It creates the reclaimable WASI
domain on that worker instead of migrating an admitted domain, retaining the
existing reaper and complete-before-release contract. `ssh/worker-diagnostic/`
passes Node, tsc version/project/declaration emission, emitted-JS execution and
tsx through the real OpenSSH PTY, with the original 2-second keepalive policy
unchanged. The WASI instance reports complete reclamation. Temporary stage
logging was then removed for the final production qualification above.
These diagnostic images are not the final production qualification.
