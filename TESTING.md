# Testing VibeOS

Four layers, cheapest first. Run them all before pushing.

```sh
cargo test --workspace --exclude vibeos-sshd # VibeOS portable tests, no QEMU
cargo test --manifest-path vendor/sunset/Cargo.toml -p sunset \
  --no-default-features --features alloc # audited Sunset fork tests
cargo test --locked --offline -p vibeos-wasm-runtime \
  --test decode_limits -- --test-threads=1 # C1.2 no attacker-scaled decode allocation
cargo test --locked --offline -p vibeos-wasm-runtime \
  --test effective_maxima -- --test-threads=1 # C1.3 adjacent execution/allocation maxima
cargo test --locked --offline -p vibeos-wasm-runtime --test core_spec # C1.6 pinned official integer semantics
cargo test --locked --offline -p vibeos-wasm-runtime --test core_robustness # C1.7 deterministic bounded corpus
cargo test --locked --offline -p vibeos-component-runtime \
  --test canonical_language_fixtures # C2.3 Rust/C rich-value round-trip
C2_WASI_SDK_PATH=/path/to/wasi-sdk-33.0-arm64-macos \
  ./scripts/rebuild-c2-language-fixtures.sh # C2.3 exact source/Core gate
cargo test --locked --offline -p vibeos-component-runtime \
  --test c27_component_reference # C2.7 pinned Component reference differential
cargo test --locked --offline -p vibeos-component-runtime \
  --test c27_component_bytes # C2.7 bounded Component-byte corpus
cargo test --locked --offline -p vibeos-component-runtime \
  --test c27_canonical_values # C2.7 bounded Canonical-value corpus
cargo check -p vibeos-sshd --features qemu-virt
cargo check -p vibeos-sshd --features milkv-ssh-acceptance
cargo test -p vibeos-driver-dwc2-host -p vibeos-bsp-milkv-duo
./scripts/differential.sh      # verify committed output with pinned real rustc
./scripts/qemu-test.sh         # golden cases plus the differential oracle
./scripts/qemu-usb-test.sh     # PCI/XHCI HID, BOT/SCSI, INTx, and hotplug
./scripts/qemu-tcp-test.sh     # N1 static/DHCP IPv4 and TCP echo over QEMU hostfwd
./scripts/qemu-tcp-test.sh recovery # N2 stack/driver generation-recovery gate
./scripts/qemu-iperf3-test.sh # iperf3 control/data interoperability in both directions
./scripts/qemu-ssh-security-test.sh # N3 QEMU entropy/identity boundary gate
./scripts/qemu-ssh-test.sh     # N4/N5 real OpenSSH exec and rejection gate
./scripts/bench.py             # fixed QEMU/TCG run checked against the baseline
./scripts/bench.py --smp-scaling # equal-work four-hart throughput acceptance
./scripts/status.sh            # derive current test/corpus counts on the host
C82_WASI_SDK_PATH=/path/to/wasi-sdk-33.0-arm64-macos \
  ./scripts/test-c82-preview1-corpus.sh # C8.2 source-to-execution gate
python3 -B scripts/verify-c83-runtime-costs.py --selftest --check-manifest
python3 -B scripts/qemu-c83-runtime-costs.py --allow-dirty-smoke
python3 -B scripts/capture-c83-duo-runtime-costs.py --selftest
python3 -B scripts/verify-c83-evidence.py --selftest
python3 -B scripts/verify-c84-aot-decision.py --selftest --check-manifest
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source
bash -n scripts/build-milkv-duo.sh scripts/package-milkv-duo-sdk.sh \
  scripts/verify-milkv-duo-image.sh
python3 -B scripts/c84-source-materialization.py --selftest --check-source
python3 -B scripts/c84-docker-runtime.py --selftest
./scripts/verify-milkv-duo-image.sh --selftest
python3 -B scripts/capture-c84-duo-aot-decision.py --selftest
python3 -B scripts/verify-c84-evidence.py --selftest
cargo test --locked -p vibeos-component-runtime --no-default-features \
  --features c84-profile-hooks --test c84_profile
cargo test --locked -p vibeos-wasm-aot-profile
cargo check --locked -p vibeos-wasm-aot-profile \
  --target riscv64imac-unknown-none-elf
./scripts/qemu-c84-profile-slot-test.sh # C8.4 slot ownership/topology gate
./scripts/qemu-c84-core-poll-test.sh # C8.4 real Core observer/slot gate
./scripts/qemu-c84-profile-irq-overlay-test.sh # C8.4 real self-SSIP overlay gate
./scripts/qemu-c84-profile-child-delegation-test.sh # C8.4 prepared-child lineage gate
python3 -B scripts/verify-c84-ssh-profile-request-parent.py --selftest --check-source
./scripts/qemu-c84-ssh-request-parent-test.sh # C8.4 authenticated request-parent/reuse gate
python3 -B scripts/verify-c84-ssh-managed-child-core.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-core-test.sh # C8.4 real managed-child/ordinary-Core SSH gate
python3 -B scripts/verify-c84-ssh-managed-child-phase-sidecar.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-phase-sidecar-test.sh # C8.4 parent/child phase sidecar gate
python3 -B scripts/verify-c84-ssh-managed-child-irq-overlay.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-irq-overlay-test.sh # C8.4 parent/child causal self-SSIP gate
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-finish-verify-test.sh # C8.4 response finish/verify/discard gate
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-verified-stream-test.sh # C8.4 verified summary/stream completion gate
python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-trusted-sample-test.sh # C8.4 live terminal evidence/opaque bundle gate
python3 -B scripts/verify-c84-ssh-managed-child-single-boot-collector.py --selftest --check-source
python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py --selftest
./scripts/qemu-c84-ssh-managed-child-single-boot-collector-test.sh # C8.4 private single-boot collector/audit gate
cargo test --locked -p vibeos-image-policy --no-default-features \
  --features milkv-duo-sd --test stream_pin \
  frozen_case_filter_profile_preflight_proves_interval_capacity -- --exact
```

`wasm-runtime/tests/decode_limits.rs` is the C1.2 Core decode-account gate. It
builds raw modules locally at every applicable enabled Profile-1 ceiling and at
the adjacent limit-plus-one mutation. The hostile matrix covers raw and
declared lengths, bounded and imported-plus-defined counts, compact-import
expansion, materialization-capable disabled type/operator vectors, signature
arities, compressed locals, structured-control depth, table and memory maxima,
data lengths/segments, element segments/items, and aggregate encoded custom
names plus data. Enabled exact ceilings must be admitted; fields modeled by
`CoreSummary` must also report the exact count. Disabled multi-value remains
rejected even when its numeric result arity is within the configured ceiling.

The test installs a thread-local-enabled wrapper around the host `System`
allocator. Inputs are constructed outside the measured interval. Inside it,
the test records allocation-call count, cumulative requested bytes, and largest
single request for the current test thread; these are request-envelope metrics,
not live/high-water memory or kernel-owner attribution. Every hostile rejection
runs through both `inspect_core` and `ValidatedCore::new_in` with one prebuilt
engine and a zero compile reservation. The stable error and request envelope
must match, proving that the production entrypoint does not reach Wasmi
compilation. Both absolute small bounds and shallow-versus-materialization-size
comparisons prevent a hostile declaration from amplifying predecode allocation.

`CoreSummary` plus the checked counters is the Core decoder's structural
account. Type, table, global, data and MVP element framing is predecoded before
attacker-sized vectors can be materialized, and function control frames use a
fixed Profile-1 stack. This host gate does not measure Component decoding,
successful Wasmi compilation, instantiation, growth, call-depth enforcement,
kernel allocator ownership, QEMU or Duo allocation, or exhaustive fuzzing;
those have separate gates or later roadmap nodes.

`wasm-runtime/tests/effective_maxima.rs` is the portable C1.3 adjacent-boundary
gate. An image-selected two-page store ceiling admits the first guest
`memory.grow`, then repeatedly returns exact `LimitExceeded` without changing
the two-page memory; a smaller module-declared maximum remains the distinct Core
`MemoryOutOfBounds` path for host-directed growth. The production host table
seam grows an MVP function table to exactly 4,096 elements, then rejects 4,097
twice with `LimitExceeded` and an unchanged size. Guest `table.grow` remains an
`UnsupportedFeature`; the gate does not enable reference types.

The recursive countdown pins Wasmi's configured call-stack interpretation:
argument 127 succeeds with 128 active frames, while argument 128 attempts the
129th frame and repeatedly returns `CallDepthExceeded`; a shallow call succeeds
afterward. The compile-reservation case pins the calculator-reported policy
charge and charge-minus-one behavior. Its 27-byte raw module declares 4,096
locals in one compact group; `CoreSummary::max_locals` records that count, and
the policy charge includes the corresponding pointer-sized per-function
expansion. A short reservation through `ValidatedCore::new` must have the same
allocation-request fingerprint as `inspect_core`, proving rejection occurs
before engine creation and `Module::new`.

That allocation probe labels two synthetic caller-selected owner scopes and
records calls, cumulative requested bytes, and largest requests for the current
test thread. It proves the portable runtime does not switch a rejected or
accepted compilation into the other label and observes, during selected-scope
compilation, an allocation request at least as large as the compressed-locals
expansion. `OwnerAllocationReservation` is a caller-provided per-compilation
policy-ceiling assertion, not an owner credential or ledger debit. The
deterministic policy charge is not an upper bound on Wasmi's allocation-request
total or live/high-water memory.
Live/high-water/denial accounting, an unforgeable kernel owner, aggregate memory
across a multi-module Component principal, and lifecycle reclamation remain
C4.2/C6 evidence. The gate performs no QEMU or Duo work.

The C1.6 specification gate is deliberately offline and byte-pinned. It vendors
the complete official [`test/core/fac.wast`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/test/core/fac.wast)
from the WebAssembly/spec `wg-1.0` commit
`977f97014c962f7bd1291fcc6d28b41a924882bf` at
`wasm-runtime/tests/spec/core-wg-1.0/fac.wast`: 2,602 bytes with SHA-256
`7bf27b090f6533865acc79a37e0331b27fa11d7a3ab27b02e32e2efddfb405e7`.
The adjacent `LICENSE` is also pinned at 11,358 bytes and SHA-256
`c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08`;
[`PROVENANCE.md`](wasm-runtime/tests/spec/core-wg-1.0/PROVENANCE.md) records the
repository, tag, immutable commit, source path, download URL, sizes, and
digests. The test performs no network fetch and fails if either vendored byte
sequence changes.

`wasm-runtime/tests/core_spec.rs` consumes the whole script, not selected
hand-transcribed cases. It requires exactly one anonymous module, five
`assert_return` directives, and one `assert_exhaustion`, and rejects every
unknown directive. Each factorial return is compared three ways: the official
WAST result, the Vibe Profile-1 runtime, and pinned
`dlr-wasm-interpreter` 0.2.0. The exhaustion action must map to Vibe's stable
`CallDepthExceeded` trap and DLR's `StackExhaustion`. This closes the selected
Profile-1 integer baseline for indexed and named calls, recursion, locals,
blocks, loops, branches, the fixture's non-negative factorial comparisons,
and wrapping `i64` arithmetic
under Vibe's configured bounds. It is not full WebAssembly Core 2.0
conformance and does not enable any disabled Profile-1 feature. C1.6 does not
itself supply C1.7 robustness evidence; that separate gate is described below.

`wasm-runtime/tests/core_robustness.rs` is the C1.7 deterministic bounded CI
corpus. Its in-process xorshift64* generator uses the fixed seed
`0x6a09_e667_f3bc_c909`; the test pins exactly 679 inputs, 575,262 aggregate
input bytes, and the length-and-tag-bound FNV-1a digest
`0xbe6b2c8ae635595a`. The corpus contains raw inputs at every length from 0
through 192, the same tail lengths after an exact Core magic/version prefix,
and 96 valid generated Profile-1 modules plus one truncation and one bit flip
of each. The valid modules cover integer arithmetic, direct calls, `if`, loops,
bounded memory, and `unreachable`. Dedicated cases additionally cover a
disabled float signature, a validated but unlinked import, fuel-bounded
nontermination, call-depth exhaustion, the exact 524,289-byte module-size
limit-plus-one input, and a compile reservation one byte below the measured
requirement. Every ordinary structured input is at most 4,096 bytes.

Each pipeline exercise is enclosed by `catch_unwind`, checks every admitted
summary and compile reservation against Profile 1, then drives any runnable
module with exactly 50,000 total fuel and a 10,000-fuel quantum. At most six
polls may occur. The 96 unmodified generated modules and the dedicated spin
and recursion cases require exact `Ready`, `Unreachable`, `FuelExhausted`, and
`CallDepthExceeded` outcomes. Mutated or arbitrary inputs may reject at any
earlier stage or terminate with another bounded result, but they may not panic,
reach a host call, exceed the poll bound, or leave an active call after a
terminal result. This closes the selected deterministic C1.7 evidence for
decode, validation, instantiation, and execution under configured bounds. It
is a reproducible bounded CI corpus, not coverage-guided or exhaustive fuzzing,
and does not claim enumeration of all byte sequences.

`component-runtime/tests/canonical_language_fixtures.rs` is the C2.3
cross-language execution gate. The same exact
`vibe:fixture/canonical-language@1.0.0` WIT world is implemented by
freestanding Rust and C guests compiled for `wasm32-wasip1`. Their import-free
Core modules are checked into
`component-runtime/tests/fixtures/language/`, inspected under Vibe Profile 1,
and embedded in deterministic import-free Components. The test pins the Rust
Core/Component at 557/950 bytes and SHA-256
`79e1eb3f2043c4ae224da6057279f80f32ec171106ad2112e8f7d2bf62e96f52` /
`1826aef365bbc0c1061bd8f23eaea5883ed052220f711243cd7c29c335975cfe`,
and the C Core/Component at 1,030/1,423 bytes and SHA-256
`20e26c154f2fc3d0892a2175dd85912ea2df77ff43e22200864eba7e6d3f7e8e` /
`2ee8f6154c6069d46d726e922a1d07979982d022dd8c02e035dcd244a9248b78`.

Both Components execute the same four-case typed corpus covering booleans,
signed and wide integers, Unicode scalar values, UTF-8 strings, byte lists,
flags, enums, options, results, records, tuples, and both variant arms. The
corpus pins 276 aggregate dynamic bytes and FNV-1a64
`0x5a3e5d03338a9be3`. Each call has 1,000,000 total work, a 10,000-work poll
quantum, and a 101-poll hard bound; host suspension, host failure, traps,
poisoning, or a retained continuation fail the test. The adjacent provenance
records exact compiler binaries and digests. The offline rebuild gate first
reproduces both compiler outputs, then uses a digest-allowlisted structural
sanitizer to remove only each linker's private, unreferenced mutable stack
global before requiring byte-identical Profile-1 fixtures. This closes C2.3
for the selected Rust/C language evidence; it neither claims every compiler
nor supplies the separate C2.7 differential/fuzz evidence.

The three C2.7 gates keep reference execution, Component bytes, and Canonical
values as separate evidence. `c27_component_reference.rs` first requires Vibe
Profile-1 admission, zero imports, and the exact C2.3 WIT world, then executes
the byte-pinned Rust and C Components through both Vibe and Wasmtime 48.0.0.
An empty Wasmtime linker supplies no ambient host authority. Each engine runs
the same four cases for both fixtures; all 16 engine/case executions are
compared with a neutral named representation as well as with each other. The
test also retains the C2.3 pins of 276 aggregate dynamic bytes and corpus FNV
`0x5a3e5d03338a9be3`, gives each reference call finite fuel, and proves that
fuel was consumed without exhaustion. Wasmtime is an exact dev dependency with
default features disabled and is used only by host tests; it is neither linked
into the VibeOS target nor used as an admission oracle. Its release commit,
crates.io digest, direct features, license, and Rust-version declaration are
recorded in the adjacent
[`PROVENANCE.md`](component-runtime/tests/reference/PROVENANCE.md).

`c27_component_bytes.rs` uses seed `0x243f6a8885a308d3` and pins 4,323 inputs,
4,604,005 aggregate bytes, maximum length 1,048,577, and corpus FNV
`0x9edc2bd8460d97a4`. The cases comprise 512 arbitrary byte strings, 512 exact
Component-header-prefixed strings, two admitted fixture originals, all 1,648
proper-prefix truncations of those fixtures, one deterministic single-bit
mutation at each of their 1,648 byte positions, and one limit-plus-one input.
Every inspection is panic-contained. The gate pins all public decoder outcomes:
863 accepted, 520 non-Components, 2,528 malformed, 134 unsupported, 10 limit
failures, 267 invalid embedded Core modules, and one invalid wiring result,
with zero allocation, duplicate-name, type-graph, or callback-signature
failures for this exact corpus.

`c27_canonical_values.rs` independently uses the same numeric seed for 512
valid generated values spanning all 19 non-resource value families. Every
case validates its generated type and value, lowers to bounded memory32, lifts
it back under alternating parameter/result rules, and requires the exact value,
usage accounting, allocation count, and encoded-memory digest inside a panic
boundary. The pins are 799 type nodes, 772 value nodes, 1,026 dynamic bytes,
88 list elements, 65 lower allocations, type/value depth 6/5, and corpus FNV
`0xbf10e036e7750d0b`. A separate mutation pass requires exactly 512
`TypeMismatch` results with digest `0x4cc0bcd2afdc82bc`; 32 named invalid
type/value/memory cases pin digest `0x974017feed8c1e42` and the exact bool,
character, UTF-8, bounds, alignment, limit, flags, discriminant, shape, and
nesting errors. This is deterministic bounded CI fuzz evidence, not exhaustive
coverage-guided fuzzing. Resource, stream, and future handles remain outside
this corpus and resource/Canonical-ABI state fuzzing remains C3.6.

The C8.2 gate is intentionally pinned to the reviewed
`aarch64-apple-darwin` Rust distribution and wasi-sdk 33 macOS arm64 release.
It fails closed when either toolchain is absent or has a different digest. The
gate recompiles the checked-in Rust and C filters, verifies the exact compiler
Core hashes, reproduces the sanitized Core modules and Components byte for
byte, independently checks the CMP1 artifacts and named mutations, executes
both filters through the bounded acceptance broker, and checks the feature-off,
loader-isolation, and RISC-V `no_std` paths. It does not enable the Preview1
profile for ordinary loader, graph, VSH, or durable registration.

The C8.3 runtime-cost preparation and physical publication flow is documented
in [docs/WASM_RUNTIME_COSTS.md](docs/WASM_RUNTIME_COSTS.md). Its dedicated image
emits target-owned raw `rdtime` samples for validation, startup, Canonical ABI,
native-async primitives, validation-only composition, host calls, memory, fuel,
cancellation, and revocation. The independent host verifier owns the closed
schema and all derived statistics. A dirty QEMU smoke run is useful integration
evidence but cannot export a baseline; C8.3 remains open until one fixed QEMU
boot and three real cold Duo boots from the same clean preparation commit are
published. Physical capture also requires the canonical `package-envelope.json`
and image-verifier audit emitted by the pinned Linux/amd64 SDK packaging flow;
the C8.3 record's container digest is an operator assertion, not hardware
attestation.

The C8.4 AOT-decision preparation contract is documented in
[docs/WASM_AOT_DECISION.md](docs/WASM_AOT_DECISION.md). It freezes the exact
authorized SSH `case-filter` product workload, its physical-Duo response
budget, the mutually exclusive profiling phases, and the fail-closed decision
rule before any profiling result exists. The independent verifier checks the
checked-in workload/schema bytes against the executable image pin and OpenSSH
fixture. This preparation gate neither completes C8.3 nor authorizes AOT;
fixed-QEMU runs are integration evidence only, and a final decision requires
the documented physical-Duo sample set.

The image-policy command above enables `c84-profile-hooks` only through its
dev-dependency and replays the exact 12,325-byte frozen input. It locks the
1,251 typed polls, 1,165 Core polls, work ledger, dispatcher entries, 2,418
no-wait intervals, and 4,918 managed-runner minimum which disproved the old
4,096 cap. The verifier independently binds its 1,028/read, `4 + bytes`/write,
and 1/close declarations, `required_work` branches, and ready/commit response
sites to the kernel dispatcher and shared 1,024-byte component-host maximum.
It pins the whole kernel component dispatcher file's reviewed byte identity,
including attribute literal values, before scope extraction, rejecting module
binding, `cfg` feature selection, alias, dead-code, and macro drift. It then
strips comments and literals, and a second digest pins the seven balanced method
scopes for localized review without accepting decoy text.
The revised 65,536 capacity is an engineering bound for one packed active
target sample, not a mathematical worst case.
Formal samples must be complete and self-consistent; overflow or truncation is
diagnostic-only.

The C8.4 single-boot verifier self-test also closes one synthetic raw
cold-boot transcript at a time:
one metadata record, three warmups, 21 retained samples, and one end record. It
rejects malformed JSON, wrong coordinates or campaign identity, incomplete or
unmerged phase intervals, invalid fuel/poll counters, unstable retained data,
and a stale ordered accumulator. Its host-file tests cover bounded stable reads,
symlink and hardlink alias rejection, no-clobber summary creation, explicit
overwrite, exact reread, and protected verifier inputs. A passing single-boot
check reports physical and cold-boot provenance as unverified.

The C8.4 software-side closure now also has independent immutable source
materialization, content-addressed build/package envelopes, host-observed
Docker runtime custody, a full-SD-image verifier, a deliberately read-only
three-boot UART capture program, and a final evidence verifier. The CI-safe
commands listed above exercise source/config/path replacement attacks, runtime
inspect/namespace mutations, shell syntax, raw-image parser mutations, capture
stream/tree/no-clobber mutations, exact three-boot aggregation, and final
evidence closure using synthetic host files. The source and runtime self-tests
use only local fixtures, and `capture-c84-duo-aot-decision.py --selftest` never
opens a serial device; no listed self-test invokes Docker, downloads an SDK,
flashes media, resets a board, or claims a physical boot.

The source proof deliberately separates namespaces: host materialization and
offline verification bind the exact device/inode sets, while the fixed
`/home/vibeos` read-only container mount rechecks content, Git administration,
permissions, single-link counts, and clone disjointness after its runtime
attestation is validated. Package preflight validates the package-mode
attestation; the independent image verifier validates its own verify-mode
attestation and separately runs the complete package-mode verifier because its
image report still binds the package attestation. This accommodates Docker
Desktop inode remapping without weakening the host-side independence proof.

The final evidence gate binds three distinct boot indexes, revalidates the
independently frozen C8.4 source and offline container-runtime closure, reruns
the complete C8.3 evidence verifier from that explicit full preparation
commit, and independently derives nearest-rank p50/p95 from all 63 retained
samples. A C8.4 result cannot exist unless that committed C8.3 tree is complete
and byte-identical. Current execution status (2026-08-27): Milk-V Duo physical
testing is paused at operator request, so C8.3 and C8.4 remain open; there is no
complete three-cold-boot physical capture set and no workload-specific AOT
decision. Source immutability and Docker runtime custody are closed in the
software pipeline, but the runtime record remains local software evidence, not
hardware, TPM, remote-attestation, or physical-cold-boot proof.
See [docs/WASM_AOT_DECISION.md](docs/WASM_AOT_DECISION.md) for the deferred
formal build, package, image-verification, capture, and publication commands.

The portable C8.4 hook gate above exercises the default-off, caller-clocked
boundary around the real synchronous Core poll. It proves ordinary and
profiled typed-call results stay identical and locks the exact observer/tick
ordering: the start observer returns its post-observer sample, while the finish
observer owns one end sample, atomically closes interpretation with that same
sample, and returns it to the runtime aggregate. The gate also covers inclusive
outer totals, wrapping subtraction, and saturating counters. It is only the
interpreter-boundary primitive: connecting that Core hook to the kernel slot,
interrupt attribution, and SSH integration remain separate gates.

The standalone `vibeos-wasm-aot-profile` gate covers the target-side ledger
state machine without connecting it to kernel, trap, executor, or SSH code. It
borrows one exact 65,536-entry endpoint array and one packed phase array,
for exactly 589,824 bytes (576 KiB) of caller storage, suppresses zero-duration
intervals, merges only adjacent equal phases, latches cleanup, overlays
interrupt time as wait, and freezes stored bytes after a sticky failure. Only a
finished sample that passes an independent full rescan can expose the
schema-shaped summary and exact-size interval iterator; rejected or
capacity-overflow samples remain diagnostic-only. Its linear handles are
`Send` but not `Sync`: this permits exclusive ownership to move inside the
kernel's required `Send` future, including across suspension, without allowing
the active sample or its hooks to be shared. `Send` is not a measurement-hart
claim. Every formal target sample must still keep that future pinned to hart 0,
and later target wiring must dynamically reject a hook observed on any other
hart. The RISC-V check proves that this foundation stays dependency-free and
`no_std`; target hook, pinning, and dynamic-hart verification remain later
gates.

The same crate's portable target-session facade is the next allocation-free,
`no_std`, and `unsafe`-free boundary above that ledger. Within one continuously
recycled `TargetReady` lineage, it gives each armed sample a private non-zero
checked epoch, rejects any active hook whose token or trusted-kernel-supplied
single-hart online mask, logical hart, or physical hart is wrong, and binds IRQ
exit to the epoch captured by its entry cookie. Epochs are not globally unique
across separately constructed lineages, so the kernel slot initializes
exactly one lineage and preserves it only through recycle transitions. Only a
facade-clean closed sample may proceed to the explicit independent ledger
rescan; the formal target publisher must accept `TargetVerified`, not the raw
ledger's `Verified`. Cancellation, facade faults, ledger faults, and epoch
exhaustion remain diagnostic-only and clear storage before reuse. This facade
intentionally contains no lock, callback, allocator, target clock access, or
hardware topology reader.

The default-off `wasm-c84-profile-slot` boundary allocates one exact 576 KiB
backing store once before secondary-hart release and preserves that one
`TargetReady` lineage behind the IRQ-masking kernel `SpinLock`. Storage-bearing
active and verified states remain global; task-bound run and stream leases carry
only exact epoch/task/domain identity across suspension. Task-detach capacity is
reserved and the callback is armed before the start tick. Normal reuse requires
complete indexed streaming and explicit recycle. An active or verified task
detach, explicit cancellation, or an abandoned stream instead creates a
diagnostic rejection which must be acknowledged before reuse. Full
verification, clearing, and recycling run outside the slot lock.

`scripts/qemu-c84-profile-slot-test.sh` builds one isolated image and boots it
with `-smp 1` and `-smp 2`. The single-hart case intentionally forgets an active
lease and a partially streamed verified lease in normally exiting pinned tasks,
requires exact detach recovery for epochs 1 and 2, then streams all seven
synthetic intervals and explicitly completes epoch 3 back to ready epoch 4. The
two-hart case requires start-time rejection of online mask `0x3` without
consuming epoch 1. This is ownership, detach, recycle, and topology integration
evidence only. It does not connect the Core observer, trap/IRQ entry and exit,
SSH timing boundary, schema publisher, collector, or physical-Duo path, and it
does not inject the executor raw-fault or cancellation detach reasons.

The separate default-off `wasm-c84-core-poll-observer` feature adapts one
caller-supplied `poll_profiled` invocation to the exact current `RunLease`.
The clock is lexical, sticky-latches its first slot error, requires each Core
start/end pair to close before the next poll, and returns the same single end
tick that changes the target ledger from Interpretation back to ABI. Ordinary
`TypedCall::poll` is unchanged; this feature does not create an ambient hook or
weaken task ownership.

`scripts/qemu-c84-core-poll-test.sh` runs the exact image-pinned `case-filter`
artifact through a real wasmi Core poll in one boot-hart-pinned task. The
single-hart transcript must verify the exact phase sequence Validation,
Instantiation, ABI, Interpretation, ABI, Cleanup; the external Interpretation
total must contain the portable Core aggregate; streaming must complete back
to ready epoch 2. The two-hart boot must reject topology before Core entry.
This proves only the explicit Core-observer adapter. The frozen SSH runner
still calls ordinary `poll` when the managed-child composition feature is off.
The default-off composition gate below now connects this adapter to the exact
SSH target child; IRQ overlays, complete SSH phase timing, publication,
collection, and physical-Duo evidence remain separate work.

The separate default-off `wasm-c84-profile-irq-overlay` feature gives a trap
preempting the exact active slot owner one linear entry/exit cookie. The trap
briefly borrows the slot at each boundary but never holds it across the handler;
an inactive slot or a different current task remains observationally inert.
The entry endpoint is the trap assembly's early timestamp, and the paired exit
restores the interrupted base phase after accounting the intervening time as
Wait.

`scripts/qemu-c84-profile-irq-overlay-test.sh` builds the isolated
`wasm-c84-profile-irq-overlay-qemu-acceptance` image and uses the parameterized
profile-slot harness for both `-smp 1` and `-smp 2`. The single-hart worker
forces four real boot-hart self-IPIs through OpenSBI and the SSIP early-return
path. An acceptance-only SSIP counter proves exactly one active-owner
entry/exit pair and causally distinguishes it from timer traffic. While the
sample owner is suspended, the current non-owner task must remain inert;
explicit cancellation, ordinary `RunLease` Drop, and exact task-detach recovery
must each clear the active fast gate before the next epoch. The publishable
sample requires a paired non-zero Wait overlay with the base phase restored and
completes back to ready epoch 5; real SSIPs before and after Active must remain
inert. Finally, an
acceptance-only mismatch injection must preserve the first poison, clear the
fast gate, and prevent re-arming. The two-hart boot must reject topology before
arming the sample.
This gate is evidence for that deliberate self-SSIP only; it does not establish
targeted timer or PLIC handling, SSH timing, publication/collection, or
physical Milk-V Duo behaviour.

The default-off `wasm-c84-profile-child-delegation` seam lets an exact
request-owned `RunLease` bind at most one still-hidden `PreparedTaskBatch`
member before scheduler publication. The executor returns a copy-only seal for
the child's already-armed detach callback; it grants no handle, wake, poll,
cancel, disarm, or recycle authority. The child must claim from its exact first
poll and may change phases only while claimed. IRQ overlays accept the exact
child while claimed or while explicitly released and awaiting final detach.
Release deliberately does not disarm the callback: only the executor's later
`Exited` reason is clean. Early exit, ordinary lease Drop, post-release
cancellation or fault, and parent finish with a live child become request-local
diagnostic rejections. The parent remains the sole owner of finish,
cancellation, target storage, streaming, and recycle.
The `vibeos-core` compile-fail doctests independently enforce that the public
prepared seal has neither wake nor disarm methods.

`scripts/qemu-c84-profile-child-delegation-test.sh` proves bind-before-publish,
one exact prepared-child identity, first-poll-only claim, duplicate and
wrong-task inertia, an exact child-owned Core observer pair, a real child-owned
self-SSIP, clean `release + Exited`, parent-cancel-first stale callback
behavior, forgotten and dropped child rejection, `release + Cancelled`,
fail-closed parent finish, and rejection of a claim attempted after a first-poll
yield. A silent destructor fault proves that `release + Faulted` stays
diagnostic. The successful Core epoch compares the exact ledger end tick with
the tick returned to the portable observer by reconstructing that boundary
from the final streamed interval. Seven additional epochs independently prove
finish-without-start, observer Drop, open-child release, direct phase mutation
and replacement rejection, simultaneous observer/child `forget`, and
request-parent mutation rejection while child Core is open. A final
parent-observer/RunLease double-`forget` epoch proves that raw owner detach
preserves the global observer fault. The request-wide Core owner lives in the
slot, so neither forgotten parent nor child adapters can overlap a later
observer or produce verified evidence. The generic serial gate still rejects
every panic. The single-hart boot completes fifteen epochs and returns to ready
epoch 16; the two-hart boot rejects before epoch 1 starts. This is an isolated
ownership seam only. By itself it does not modify the frozen ordinary component
runner, connect the OpenSSH acceptance/response boundary, prove real wasmi Core
attribution, publish the schema, collect physical Duo samples, or make an AOT
decision. The managed-child/Core composition below closes the first three gaps
for the exact diagnostic SSH target without changing the isolated gate's claim.

The default-off `wasm-c84-ssh-request-parent` seam closes the authenticated
request-parent ownership boundary without claiming a profile result. Only the
public-key-authenticated, current-policy, exact-grammar `case-filter` descriptor
can reserve the kernel slot. `PreparedExec` owns that reservation before the
SSH success response; `PreparedExec::accept` sends success first and only then
starts the slot lease, so a failed response drops the unstarted reservation.
The resulting `AcceptedExec` keeps the run in `serve_connection`, outside the
managed child. Every post-start, pre-response execution/reset/rebind failure
therefore reaches the same linear Drop cleanup. A complete response instead
consumes the run through the explicit response boundary, only after exit
status, EOF, peer CLOSE acknowledgement, and Sunset output drain, before the
next protocol event or TCP teardown.

The kernel adapter deliberately cancels rather than finishes. It compares the
cancel report with the independently stored rejection, acknowledges that exact
epoch once, and requires `Ready(next_epoch)` before reporting RESPONSE or DROP.
It has no finish, stream, publisher, or evidence surface. The independent
source verifier mutation-checks the admission/order/ownership boundary and the
exact cancel/rejection/acknowledge/reuse closure.

`scripts/qemu-c84-ssh-request-parent-test.sh` boots the isolated OpenSSH image
with one canonical hart. Builtin, unavailable native, parameterized target,
and rejected-key probes must emit no profile marker. Two exact `case-filter`
requests must close epochs 1 and 2; a third request is killed after its START
marker and must emit one DROP cleanup marker; epoch 4 must then succeed, proving
post-Drop slot reuse. The authenticated readiness probe starts immediately
after DROP: the capability TCP adapter must retire the old connection
generation in one poll, accept a queued replacement only on the next poll, and
hand it to a fresh SSH Runner rather than resetting or reading it through the
old parent. The exact epoch-4 request follows that successful readiness probe.
The host accepts only the frozen ordered UART sequence.
This request-parent-only gate remains QEMU integration evidence for request
ownership: its managed child uses unprofiled wasmi polling, no sample is
finished or streamed, and no physical-Duo profiling evidence is produced. The
separate composition gate below closes the ordinary-child/Core connection.

The default-off `wasm-c84-ssh-managed-child-core` feature composes the
authenticated request parent, prepared-child delegation, and portable Core
observer on the real ordinary Component path. During the exact synchronous
`case-filter` start, child index 0 reserves its third prepared-task registration
slot and is attached while the `PreparedTaskBatch` is still unpublished. Only
its copy-only epoch enters the arena-owned payload; the parent `RunLease`
remains private.
The outer `ManagedChildFuture` claims that lineage in its first executor poll,
before `child_start_gate`. A target driver constructs a fresh lexical
`ManagedChildSlotCorePollClock` around every `poll_profiled`, then rejects an
observer error or non-Closed Core owner before any later poll or `.await`.
Non-target and feature-off drivers continue to call ordinary `call.poll()`.

The driver sets its completion bit only after an exact successful guest result.
The outer future releases only when that bit is true and the registry payload's
final word is still exact Success; the armed executor detach callback then
accepts only `CompletedPendingDetach + Exited` as clean. A cooperative
cancellation cannot turn its later `Ready` envelope into a release: the
future's destructor instead records abandonment before detach. Normal SSH
response therefore requires no attached child, exact `Exited`, an empty fault
set, and a Closed observer. Active request Drop accepts only the frozen
detached/abandoned fault lattice. In both cases the request parent still
cancels the sample, compares the rejection, acknowledges it once, and proves
`Ready(next_epoch)`; it never finishes or streams the sample.

The independent source verifier and isolated one-hart OpenSSH gate are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-core.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-core-test.sh
```

The standalone gate preserves its original 19-marker managed-child/Core
sequence and field contract. For identical successful requests at epochs 1, 2,
and 4, it
freezes 1,167 real Core polls, 1,167 observer pairs, and 1,241 typed polls.
These are QEMU control-flow counts, distinct from the preparation preflight
above and not timing evidence. Epoch 3 is killed only after the first ordinary
Core pair;
the actual executor detach is `Exited` after a canonical positive-u64 count of
closed pairs (14 in the run that exposed the latent scheduling variation),
with no release and exact `abandoned + detached` faults. That partial-run count
is not frozen. The parent then performs the same cancel/ack closure, an
immediate readiness probe succeeds, and epoch 4 proves post-Drop reuse. QEMU
acceptance adds only guarded transition telemetry. This node deliberately does
not add Host/Wait/Cleanup sidecars, combine the IRQ overlay, call `finish`,
expose a verified stream or publisher, or produce schema, collector, physical
Milk-V Duo, or AOT-decision evidence.

The default-off `wasm-c84-ssh-managed-child-phase-sidecar` feature extends that
same exact target with diagnostic Host, Wait, and Cleanup ownership. The parent
records each real managed SSH pump/transport turn as Host and each execution,
cooperation, cancellation, response-drain, or shutdown suspension as Wait. The
child independently records Validation, Instantiation, and ABI; synchronous
stream-dispatch methods use an explicit non-`Send` Host guard, while each real
continuation await opens a copy-epoch Wait and revalidates the prepared task
before restoring ABI or Cleanup. Parent and child Wait bits are independent.

The portable runtime's default-no-op `cleanup_started` callback fires at most
once per typed call. The managed clock latches Cleanup before canonical cleanup
work, and a normal release requires closed child Wait/Host/Core plus that latch.
Response additionally requires clean `Exited` and a closed parent Wait. Request
Drop may preserve an open Wait as diagnostic state, but cannot acquire an extra
phase fault; forgotten Host, stale successful Wait, missing Cleanup, or a late
phase transition fails closed. The parent still cancels and acknowledges rather
than finishing or streaming the sample.

Run the source and live integration gates with:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-phase-sidecar.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-phase-sidecar-test.sh
```

The combined one-hart OpenSSH gate still strictly parses exactly 19 ordered
managed-child/Core-family markers. Epochs 1 and 4 retain the standalone normal
counts of 1,167 Core polls, 1,167 observer pairs, and 1,241 typed polls. Epoch 2
writes only the first 257 stdin bytes before waiting for the real HostPending
marker, so its frozen combined-image counts are exactly 1,171 Core polls,
1,171 observer pairs, and 1,251 typed polls: Core increases by 4 and typed polls
by 10. This combined workload does not change the standalone gate's transcript.
The gate kills epoch 3 while the post-Core child Wait is open, immediately
probes readiness, and reuses epoch 4. Successful epochs require ordered child
phases, exactly one Cleanup, paired child Host/Core/Wait observations,
relationally paired nonzero parent Host/Wait observations, clean detach, and
response closure. On Drop, the canonical positive-u64 child Core start/finish
count must exactly match the dynamically parsed Core-family closed-observer
count. Dynamic partial-run and parent counts are not timing evidence. This node
adds no IRQ composition, `finish`, verified stream, publisher, collector,
physical Milk-V Duo sample, or AOT decision.

The next default-off
`wasm-c84-ssh-managed-child-irq-overlay` feature composes that same silent
phase seam with the production IRQ overlay. It does not select the standalone
IRQ acceptance worker. Its QEMU-only acceptance hooks force exactly two active
boot-hart self-SSIPs, both in epoch 1: the first only after a real parent Host
transition has returned and released `SLOT`, and the second only after the real
managed child has opened its first lexical Core boundary. The child marker is
withheld until that Core boundary has closed successfully. No active SSIP is
forced in epochs 2--4.

Every response or active Drop still performs the request parent's exact
`cancel -> rejection -> acknowledge once -> Ready(next_epoch)` closure. Only
after `Ready` and `ACTIVE_EPOCH == 0` are established does the acceptance hook
force one inactive self-SSIP. Thus the cumulative `(paired, inactive,
active_epoch)` observations are `(2, 1, 0)`, `(2, 2, 0)`, `(2, 3, 0)`, and
`(2, 4, 0)` at epochs 1--4. The successful UART family is exactly six lines:
epoch-1 `PARENT_SSIP` and `CHILD_SSIP`, then `RESPONSE` for epochs 1, 2, and 4
and `DROP` for epoch 3. Epoch 1 alone reports `parent_pair=1 child_pair=1`;
epochs 2--4 report both as zero. Each terminal reports
`terminal_inactive=1`, `active_epoch=0`, `cancel=1`, `ack=1`, and the exact
next ready epoch.

Run the incremental source and live integration gates with:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-irq-overlay.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-irq-overlay-test.sh
```

The peer reuses the phase-sidecar's real four-request OpenSSH driver and strict
27/28 phase-marker plus 19 Core-marker parser, and also imports the exact
eight-marker request-parent parser. It then freezes the six IRQ markers and
their cross-family order: request start precedes parent SSIP; child ABI and
Core claim precede child SSIP; child SSIP precedes the original first-Core and
Wait markers; and each phase, Core, and request terminal precedes the IRQ
terminal before the next epoch starts. The old standalone IRQ and phase gates
and their transcripts remain unchanged.

The reusable base feature is UART-silent and is exposed to the Milk-V build
only as a compile-time seam. This single-hart QEMU result is causal integration
evidence, not timer/PLIC coverage, target timing, physical-Duo evidence, a
verified profile, or an AOT decision. The parent still cancels: this node adds
no `finish`, verified stream, schema publisher, or collector.

The next default-off
`wasm-c84-ssh-managed-child-finish-verify` successor changes only the terminal
policy of successful profiled responses. After the existing child Cleanup,
release, and exact Exited detach checks, epochs 1, 2, and 4 consume the parent
`RunLease` with `finish`. The slot closes the target, runs the independent
`TargetFinished::verify` rescan, and installs `TargetVerified` at cursor zero.
The SSH adapter then explicitly discards that `StreamLease` without calling
`summary`, `next_interval`, or `complete`; it checks the exact
`StreamAbandoned` report with `intervals_emitted=0`, compares the independently
stored rejection, acknowledges it once, and proves `Ready(next_epoch)`.

Epoch 3 deliberately retains the predecessor active-Drop contract: kill after
the real child Wait-open edge, observe abandoned+detached with Exited, cancel
with `LeaseCancelled`, acknowledge once, prove `Ready(4)`, and reuse epoch 4.
Nonzero status, an unready child, or stale policy is cancelled and recycled
before finish; a target finish/verify rejection is also acknowledged before
the response fails so the global slot is not stranded.

Run the incremental source and live integration gates with:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-finish-verify-test.sh
```

The live peer reuses the exact four-request OpenSSH workload, including the
epoch-2 257-byte delayed-stdin `HostPending` edge, epoch-3 active kill,
immediate readiness probe, and epoch-4 replacement. In the successor image the
normal RESPONSE suffix of the phase, Core, request, and IRQ families becomes
`finish=1 verify=1 discard=stream_abandoned ack=1`; their nonterminal markers,
epoch-3 DROP field/order contracts, family marker counts (27/28 phase, 19 Core,
eight request, six IRQ), and cross-family order remain frozen. The
scheduler-dependent phase/Core Drop observer count is parsed dynamically and
must match across those two families. The new family contributes exactly four
last-in-chain terminals: RESPONSE for epochs 1, 2, and 4 and DROP for epoch 3.
The separately built predecessor IRQ gate remains byte-for-byte cancel-only
and runs first in CI.

This proves only the target finish/independent-verify transition and deliberate
zero-cursor discard/recycle on one QEMU hart. It does not consume or validate a
profile stream, publish a summary or schema, retain evidence, run a collector,
produce physical Milk-V Duo evidence, or make the AOT decision.

The next default-off
`wasm-c84-ssh-managed-child-verified-stream` successor retains the same
authenticated request, managed child, phase/Core, IRQ, and finish/verify
boundaries while changing only successful verified-stream termination. Instead
of abandoning the cursor-zero `StreamLease`, the kernel-private SSH adapter
reads its `Summary`, consumes every indexed `Interval`, and calls
`StreamLease::complete` only after the complete stream has passed the frozen
schema-v1 partition semantics.

For successful epochs 1, 2, and 4, `total_ticks` must be a positive u64,
`interval_capacity` must be 65,536, `intervals_complete` must be true, and the
dynamic `interval_count` must be in `1..=min(65_536, total_ticks)`: the
`interval_count <= total_ticks` bound follows from positive interval lengths
and contiguous coverage. The phase totals must add without overflow to
`total_ticks`. The streamed intervals must have exact
zero-based sequence numbers, positive lengths, gap-free contiguous endpoints,
and distinct adjacent phases; a checked per-phase rescan must equal the summary
and the final endpoint must equal `total_ticks`. The gate deliberately does not
require every phase to be nonzero, freeze a phase order, or freeze the
scheduler-dependent interval count. Completion requires
`interval_count == emitted == final cursor` and exact `Ready(next_epoch)`.

A locally detected summary or interval mismatch while the lease is still owned
is explicitly discarded and must produce the exact same-epoch
`StreamAbandoned` report, emitted cursor, stored comparison, acknowledgement,
and Ready reuse before the SSH response fails. An error returned from
`complete(self)` has already consumed the caller's handle, so the adapter may
only inspect and acknowledge an installed same-epoch rejection; poison,
ownership, or state mismatch without such a rejection remains fail-closed and
is not claimed recoverable. Epoch 3 remains the active-Drop path and never
finishes, verifies, summarizes, or streams a sample.

Run the incremental gates with:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-verified-stream-test.sh
```

The successor leaves the five predecessor families' nonterminal and epoch-3
DROP bytes/field contracts untouched and retains their exact family counts:
27/28 phase, 19 Core, eight request, six IRQ, and four finish/verify. In the
successor image only their successful RESPONSE suffix changes to
`finish=1 verify=1 stream=complete ack=0 ready_epoch=...`; no predecessor
success marker carries the dynamic interval count. The new family contributes
exactly four last-in-chain terminals. Its successful marker is:

```text
WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM RESPONSE epoch=E status=0 finish=1 verify=1 summary=1 initial_cursor=0 total_ticks=T interval_capacity=65536 interval_count=N intervals_complete=1 emitted=N cursor=N sequence=exact contiguous=1 nonempty=1 adjacent_distinct=1 phase_sum=total_ticks phase_rescan=summary final_end=total_ticks stream=complete stored=0 ack=0 ready_epoch=R
```

Here `T` is a positive u64, `1 <= N <= min(65536, T)`, and `R = E + 1`; the
`N <= T` bound is derived from positive-length contiguous coverage, and `N` is
parsed semantically rather than frozen. Its epoch-3 terminal is:

```text
WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM DROP epoch=E cancel=lease_cancelled finish=0 verify=0 summary=0 stream=0 emitted=0 stored=1 ack=1 ready_epoch=R
```

Normal and Drop terminal order is phase, Core, request, IRQ, finish/verify, then
verified-stream, and the last terminal must precede the next request START. The
separately built finish/verify predecessor remains discard-only and runs first
in CI. The compact verified-stream markers are diagnostic integration results,
not serialized schema records. The storage-bearing lease never leaves the
kernel adapter, and this node introduces no `ProfilePublisher`, schema
publication, collector, retained evidence, physical Milk-V Duo evidence, or AOT
decision; a later formal publisher must still accept `TargetVerified` rather
than copied summary data or a UART success flag.

The portable `vibeos-wasm-aot-profile` successor now provides that narrow
single-record boundary. `ProfilePublisher::publish_profile` consumes one
storage-bearing `TargetVerified` by value, rescans the complete profile and
computes the chained accumulator before the first sink call, then streams one
recursively ASCII-key-sorted, compact `VIBE_WASM_AOT_SAMPLE` JSON record without
allocation. `RunId` and `Challenge` are distinct non-zero branded values;
terminal observations must first become non-copyable eligible fields. That
validation proves the frozen field values only, not live provenance.

Zero-write preflight failures return the recycled `TargetReady` lineage and a
retryable publisher with the original accumulator. Any possibly partial write
or commit failure also recycles the lineage but permanently quarantines the
sink in `ManuallyDrop`, including across unwinding, so its destructor cannot
flush a truncated record. Only a committed record returns the sink, binding,
recycled lineage, and derived accumulator. The checked-in golden is exactly one
SAMPLE line; it intentionally contains no META or END.

```sh
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source
cargo test --locked -p vibeos-wasm-aot-profile
cargo check --locked -p vibeos-wasm-aot-profile \
  --target riscv64imac-unknown-none-elf
```

This is still a portable serialization and ownership primitive. Its public
terminal input can assert exactness but cannot prove where a counter came from;
the exact-`u64::MAX` case is a serializer KAT, not permission to relabel a
saturated live counter. The node adds no trusted SSH evidence producer,
24-sample ordering, META/END closure, rollback resistance, physical-Duo
capture, retained dataset, or AOT decision. Those remain collector/live nodes.

The default-off `wasm-c84-ssh-managed-child-trusted-sample` live producer is a
sibling successor of finish/verify, not a child of verified-stream. The two
base features are mutually exclusive: verified-stream consumes and completes
the storage-bearing authority, while trusted-sample must retain the unstreamed
`TargetVerified` long enough to combine it with validated terminal evidence.
The trusted base directly inherits finish/verify and the SSHD
`c84-profile-trusted-sample` seam; its QEMU feature pairs only with the matching
finish/verify QEMU predecessor. Milk-V forwards the silent base only.

SSHD seals a non-copyable `SshExecProfileTerminal` only after the managed
Component has published its exact terminal, all Component stdout has been
drained into the SSH response buffer, and Component session shutdown has
completed. It retains that seal inside the request run and delivers it to the
kernel only at the later response boundary, after peer channel-close
acknowledgement and complete Sunset output drain. `ComponentTerminal::Success`
is required independently of numeric status zero, so `Returned(0)` is
ineligible; any observed timeout, nonempty stderr, incomplete drain, or later
cancellation fails closed. SSHD coalesces arbitrary Sunset channel-data slices
into exactly twelve 1,024-byte Component sends plus the 37-byte EOF tail; the
trusted feature fixes that staging limit even if the target-only native-revoke
feature is also present. The exact Component host dispatcher counts a read only
after the matching `Received(length)` commit and a write only after the
immediate or resumed operation reaches its final `Sent`. It verifies all 13
input and 13 output chunk boundaries and every byte of the frozen 12,325-byte
transform with checked counters. Waiting, retry, EOF, and prepared-only edges
never count.

The terminal call's fuel metrics are copied before the call is dropped. The
private producer rejects zero or over-budget fuel, a saturated fuel field, any
of the five saturated `SyncCallProfile` fields, inconsistent Core/outer work,
an empty or saturated poll count, or a non-exact poll derivation. Only then may
the slot validate `TerminalObservation` into non-copyable
`EligibleTerminalEvidence` and atomically move the matching `TargetVerified`
into `TrustedVerifiedSample`. That kernel-private, non-`Send`, non-`Sync`
bundle has private fields, no public constructor or `into_parts`, and keeps the
sample and evidence inseparable. Public `TerminalObservation::validate` alone
still proves eligibility values, not this live provenance.

This node deliberately does not connect the bundle to `ProfilePublisher`.
Epochs 1, 2, and 4 form exactly one bundle, take only a copy-only QEMU
acceptance observation, explicitly discard the bundle with
`TrustedSampleAbandoned`, compare the installed empty-fault/zero-cursor
rejection, acknowledge it once, and prove `Ready(E + 1)`. Epoch 3 follows the
existing active-Drop path and must form no bundle. Run the portable publisher,
finish, verified-stream sibling, and trusted gates with:

```sh
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-trusted-sample-test.sh
```

The trusted image preserves every predecessor marker format and field contract,
retaining 27/28 phase, 19 Core, eight request, six IRQ, and four finish/verify
markers. The epoch-3 phase/Core observer count remains dynamically parsed and
must agree across both families; it is not claimed byte-identical to a separate
predecessor run. The three predecessor success lines per family end in
`finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1
ready_epoch=...`. The new family is last in the terminal chain and emits:

```text
WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE RESPONSE epoch=E status=0 exact_success=1 full_drain=1 read_chunks=13 write_chunks=13 stdout_bytes=12325 stdout_sha256=791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27 fuel_consumed=F poll_quanta=P poll_exact=1 logical_live_after=0 timed_out=0 bundle=trusted finish=1 verify=1 discard=trusted_sample_abandoned emitted=0 stored=1 ack=1 ready_epoch=R
WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE DROP epoch=E cancel=lease_cancelled bundle=0 finish=0 verify=0 discard=0 emitted=0 stored=1 ack=1 ready_epoch=R
```

The peer accepts canonical decimal values only, with `1 <= F <= 500000`,
`1 <= P < u64::MAX`, and `R = E + 1`; neither live count is frozen. It also
requires each trusted `P` to equal the same epoch's dynamically parsed Core
`typed_polls`, and requires phase/Core counts to agree. Normal and Drop order is
phase, Core, request, IRQ, finish/verify, trusted-sample, followed by the next
request START. These are log-only single-hart integration facts, not a SAMPLE
record. No `ProfilePublisher`, META/SAMPLE/END transcript, collector ordering,
retained dataset, physical Milk-V Duo capture, physical cold-boot provenance,
or AOT decision is created or claimed.

The default-off
`wasm-c84-ssh-managed-child-single-boot-collector` successor consumes that
opaque trusted bundle inside the kernel. A build-bound portable campaign owns
the factory, sequence, accumulator, and 24-sample chain; after one META it
accepts epochs 1 through 24, discards three warmups, retains 21 samples, checks
nearest-rank p50/p95 stability, and commits END before Ready epoch 25 becomes
visible. Complete/Failed states (diagnostic `closed`/`failed`) reject before
target start, and every failure after META is absorbing. The physical Milk-V
sink holds TTY then TX across each
raw-LF formal record. Framing, write, commit, panic, or allocator failure keeps
the record fail-stopped; only a fully drained commit releases TX then TTY.
For a terminal collector state, SSHD accepts the exec request only far enough
to drain empty stdout plus exit status 126, EOF, and CLOSE; the rejection owns
no command, Component, profile permit, or target-start path.

The QEMU acceptance uses the same collector and serializer with an absorbing
SHA-256/byte-count audit sink. It performs one failed boot and one successful
24-request boot, but writes no formal record bytes to UART and marks every
diagnostic line `decision_eligible=0 formal_uart=0`. The host parser freezes
both logs, validates all predecessor/collector counts and order, and rejects
formal prefixes or schema payloads anywhere in the raw logs. Run the static,
parser, and two-boot gates with:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-single-boot-collector.py \
  --selftest --check-source
python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py \
  --selftest
./scripts/qemu-c84-ssh-managed-child-single-boot-collector-test.sh
```

CI also cross-compiles and links the physical Milk-V collector with a freshly
generated challenge from an independently materialized and verified frozen
source tree. The build runs in a sanitized `env -i` envelope with an isolated
Cargo home, the pinned Rust tools, a fixed `ld.lld`, commit-derived
`SOURCE_DATE_EPOCH`, and isolated objcopy. CI injects hostile ambient wrapper,
profile, and rustflag values; the build must ignore all three. It neither runs
nor retains that artifact. A decision-eligible capture additionally requires
that same frozen-source materialization and host-observed runtime closure, a
real physical cold boot, and the documented three-boot/63-retained-sample
verification flow; none is supplied by this compile gate.

Normal `run.sh`/`qrun.sh` builds boot the separately compiled, least-authority
`components/vsh` frontend through `kernel/src/vsh_platform.rs`. The
golden and benchmark runners explicitly build the kernel with
`--features legacy-shell`; production/default images therefore do not expose
the broad diagnostic command dispatcher.

`status.sh` lists runnable and ignored host tests separately and derives corpus
and transcript counts from the tree. Target checks are not guessed from source:
`./scripts/qemu-test.sh selftest` reports the count observed in that QEMU run.

| Layer | What it covers | Where |
|---|---|---|
| Host unit tests | Sv39 PTE/satp encoding and invalid-leaf rejection; SBI RFENCE request/error handling, local fence/MXR state, and exact online physical-hart masks; capability algebra including page-aligned COW table replacement and exact backend callback ordering, cross-space revocation, explicit leases, persistent witnesses, atomic recovered-graph installation, and tombstoned slot generations; unified authority/object journal decoding, partitioned global root selection, exhaustive prefix/flush recovery, canonical ProgramArtifact/VIBEEXE decoding and no-write-on-error in-place relocation, cross-kind ID/transaction collisions, and allocation-amplification inputs; modern virtio block/net feature negotiation, descriptor direction, RX length/header validation, exact tokens, multi-flight queue wrap, device-wide reset/quarantine, and reset-before-reuse; non-zero packet-session coordinates, fail-closed identity exhaustion, in-flight-TX rebind refusal, stale device/stack stamp rejection, fresh traffic after stale ingress, and rebound-driver rejection of stamped egress; fixed-point scheduler lifecycle, four-queue ownership, per-hart running/current-task/domain state, and IPI lost-wakeup models; work stealing, wake/remote-cancel/fault boundaries and cross-hart fault survival; reason coalescing, stale SSIP, offline/online handoff, physical hart mapping, and send-failure retry; atomic IRQ publication, SPSC byte ordering, SpinLock contention/generation recovery/hart ownership; fault arenas; wait/timer registration ownership; per-hart heap provenance and OOM diagnostics; typed channels; bounded vsh parsing, Jobs, scripting, substitutions, and exact script manifests; and the compiler | `core/tests/`, `compiler/tests/` |
| In-kernel self-test | Live Sv39 identity/permission walks plus all-hart `satp` and MXR readback; R-X kernel text, R-- `.rodata` endpoints, RW-NX free code/capability-pool pages, execute-only compiled pages, every non-empty published capability table and all live table-pool pages R--, and a full RAM scan excluding writable-executable leaves; invalid per-hart stack guards, endpoint RW-NX stack mappings, fixed slot stride, and the 8 KiB generated-code abort reserve; zeroed same-address code and capability-table reuse; real timer interrupts and wakeups, cancellation cleanup, sixteen fault/restart cycles with bounded heap and code-pool use and no interrupted Drop, normal/abort release of exclusive generated-memory claims, component allocation isolation/reclaim, `ComponentId`/`TaskId`/CSpace binding, retained fault state, the live capability graph, and machine code actually executing | harness/report in `acceptance/kernel-tests`; hardware cases in `kernel/src/selftest_platform.rs`, via `selftest` in the shell |
| Golden transcripts | End-to-end shell behaviour, including arrow-key history and mid-line editing; the live shared page-table, stack-guard, strict W^X, and read-only data/table reports; sealed local/cross-hart execution, COW capability mutation, cross-hart lookup/revoke, and zeroed same-address reuse; expected-fatal real guard-page, W^X instruction/load/store, `.rodata` store, and capability-table store faults; retained cancelled state, revoke-during-invocation lease boundaries, durable-log recovery, real virtio-blk read/write/flush, virtio-net raw-L2 exchange and fault recovery, timeout reset, cancellation/fault restart, capability-addressed object commit/read/revoke, three boots of one persistent CSpace, and two boots of a saved source/VIBEEXE artifact against the same disk | `tests/cases/`, `tests/golden/` |
| PCI/XHCI acceptance | Real QEMU ECAM discovery, 64-bit BAR sizing/assignment, PCI INTx through PLIC, XHCI command/event/transfer rings, USB descriptor enumeration, HID keyboard input into the shell, keyboard unplug/replug recovery, BOT/SCSI capacity and sector I/O, and host-side verification of the complete written sector | `scripts/qemu-usb-test.sh` |
| Differential vs real rustc | Whether generated code computes the *right answer* | `tests/programs/`, `scripts/differential.sh` |
| Fuzzing | Whether the front end can be made to panic | `compiler/tests/fuzz.rs` |
| Mutation checks | Whether the above actually catch anything | ad hoc; see below |

The `block` QEMU case is intentionally stronger than a transcript: every case
gets a fresh raw disk, sector 7 is seeded by the host, and after `blk test` exits
the host compares all 512 bytes of sector 8. `block_recovery` suppresses one real
QueueNotify to exercise the timer/reset path, injects a component fault after DMA
publication, and separately verifies cancellation plus explicit restart.

The `store` case is likewise stronger than its transcript. The host first seeds
506 valid records containing a 180,720-byte object, leaving exactly six journal
slots. Four injected raw component faults must each reach the task/domain-bound
pre-write hook after this dense recovery, clear the exact store claim, reclaim
each arena, and reach a stable heap plateau. Store calls require 4 MiB of free
caller headroom before claiming the writer; the shell and probe each have an 8 MiB
quota. The next command commits and reads a
deterministic 900-byte object, filling all 512 slots. After shutdown,
`store-image.py` independently checks the fixed sectors 64--575, platform StoreId,
canonical kinds 1--8, shared ID/transaction classes, chain/CRC/commit binding,
and both exact payloads. Its positive interleaving and negative parity fixtures
run before the real backing image is accepted.

The `persistent_cspace` case reboots three times against one unchanged raw disk.
Boot 1 persists and installs a `root -> child -> grandchild` object-capability
graph; boot 2 reads it, flushes a tombstone for the child ancestor, and proves
both child and grandchild absent; boot 3 keeps that tombstone effective and
reuses child slot 1 only at generation 1. Every boot also checks that the target
`persistent-test` CSpace has no Store `WRITE` authority and that its first dependent
observation occurs only after recovery reaches `Ready`. After the third shutdown,
`persistent-cspace-image.py` independently parses the raw journal. Its host-side
self-test applies all 512 strict byte-prefix cuts to each of 19 canonical fixture
records (9,728 cuts) and requires every cut to recover exactly the preceding
flushed boundary before checking malformed graph and root-policy fixtures.
Core tests additionally prove that persistent quarantine denies generic lookups,
invalidates `Revocable` tokens, preserves an already acquired invocation lease,
and retains resource entries without running `Drop`. The service's stable
task/domain/token ledger lets raw-fault cleanup clear only the exact abandoned
reservation without touching another caller.

The `program_persistence` case reboots twice against one unchanged raw disk.
Boot 1 publishes the fixed `hello` source plus canonical relocatable VIBEEXE as
one read-only ProgramArtifact root and runs it. Boot 2 proves a repeat save
appends nothing, recovers the exact slot-0/generation-0 capability, recompiles the
source with the current trusted compiler, requires byte-identical VIBEEXE, and
runs using only reconstructed console `WRITE` and memory `READ|WRITE` authority.
After shutdown, `program-image.py` independently validates the journal, artifact,
hashes, relocation table, stable imports, publication order, authority manifest,
and strict 512-byte prefix cuts. See `docs/PROGRAM_PERSISTENCE.md`.

The `net` and `net_recovery` cases are also stronger than their transcripts.
Only those cases add a modern virtio-net device. Before QEMU starts, the harness
launches `scripts/net-peer.py` on an ephemeral localhost TCP port and connects
QEMU's socket netdev to it. The peer parses the four-byte big-endian QEMU frame
length and compares every byte of the 60-byte raw Ethernet messages. `net`
requires HELLO, CHALLENGE, and ACK in order. `net_recovery` first observes the
HELLO exposed before an injected component fault, withholds its response, and
then requires a second HELLO plus the complete exchange after the shared device
epoch advances. A canonical evidence file is checked separately from the guest
golden; TAP, root privileges, and host network access are never used.

`qemu-tcp-test.sh` is the separate QEMU protocol-stack harness. Its default N1
mode builds only the `tcp-echo` image, attaches QEMU user networking, binds host
forwarding to an ephemeral `127.0.0.1` port, and targets static guest
`10.0.2.15:2222`. Before opening the TCP peer, the harness exercises the
Linux-style vsh command layer, verifies the initial static address, switches
`net0` to DHCP, and requires QEMU's `10.0.2.15/24` dynamic lease. The peer then
sends a deterministic binary payload containing
NUL, control, and high-bit bytes, tolerates fragmented TCP reads, and accepts
only an exact echo. Portable tests separately drive two smoltcp interfaces
through capability-addressed packet endpoints to cover ARP, a 3,000-byte TCP
exchange, endpoint pressure, and operation-time revocation.

The `recovery` mode defines the N2 acceptance gate in that same harness. It
keeps a live TCP stream while first faulting the stack and then faulting the
virtio-net driver. After the stack fault it requires the same device epoch and
a greater stack generation; after the driver fault it requires both coordinates
to advance. At each transition the retired stream must not echo a post-fault
nonce, a fresh stream must echo exact bytes, and packets staged with that
transition's retired coordinate must increment separate stale-ingress and
stale-egress rejection counts. Silence, EOF, or reset is sufficient for the
retired-stream assertion; the gate does not require a clean TCP close or RST.

The fault, session-reporting, and stale-packet controls are compiled only by
the `tcp-echo-recovery-test` feature. They are ambient vsh commands in that
acceptance image and are absent from normal `tcp-echo`, default, and future SSH
images. The injected stale frames enter the typed endpoints after replacement
binding; they are deterministic evidence for the stack-ingress and
driver-egress checks, not an emulation of a delayed DMA completion or late IRQ.
The harness is QEMU/virtio-only and provides no Milk-V Duo DWMAC hardware
evidence. This document describes the gate and its blind spots; it does not
assert that the current run passed, nor does it test an entropy source, host
key, or SSH protocol.

`qemu-iperf3-test.sh` builds the isolated `iperf3-server` image, forwards an
ephemeral loopback port to guest TCP `5201`, and runs the host's real iperf3
client twice: first normal TCP and then `-R`. Both commands must complete and
report non-zero received bytes. Portable tests separately verify that only an
explicit shared-port group can own two simultaneous sockets. This is a TCP
single-stream compatibility gate; it does not cover UDP, parallel streams,
IPv6, authentication, bidirectional mode, or physical NIC performance.

`qemu-ssh-security-test.sh` is the separate N3 security-boundary gate. It boots
the explicitly marked test-identity image twice with QEMU's `/dev/urandom`-
backed modern virtio-rng device. Each boot must complete one bounded capability
request, separate equal seed material into distinct ChaCha20 stream domains,
enforce independent READ and INVOKE signer grants, accept one exact binary
client key, and reject another. The host key must remain stable while a signed
transport-sample marker must differ between boots. That marker is a freshness
smoke test for the wired QEMU transport, not an entropy-quality proof. The
fixed identities and generation are test-only; this gate does not provide
per-device provisioning, authenticated persistence, rollback resistance, a
Milk-V hardware source, or an SSH wire protocol.

`qemu-ssh-test.sh` is the separate N4/N5 wire-level gate. It builds only the
QEMU `ssh-test` image, forwards a dynamically selected localhost port to the
fixed guest listener at `10.0.2.15:2222`. Readiness is not an open-port check:
the peer preloads the exact test host key and retries an authenticated `true`
exec through the real OpenSSH client. It validates the verbose transcript's
exact host fingerprint (`SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8`)
and negotiated profile. An explicit `SSH_HOST_PORT` override is available. The
peer forces `curve25519-sha256`, `ssh-ed25519`, and
`chacha20-poly1305@openssh.com` with an empty host ssh config (`-F /dev/null`).
It requires exact `echo` output, exit status 0 from `true`, exit status 1 from
`false`, denial of the deterministic rejected key, and explicit rejection of
shell, PTY, and subsystem requests. A second complete QEMU boot must pass the
same strict authenticated probe with the same exact host key.
`scripts/openssh-test-key.py` creates both client fixtures with mode 0600 and
never prints their private material.

The serial side is an independent assertion: a successful boot must print
`ssh-test listening on 10.0.2.15:2222`; completed authorized commands print
`ssh-test exec complete: status <n>`; and `FAIL ssh-test:` is fatal. A
`ssh-test connection reset: <reason>` line is connection-local diagnostic
output and is expected for hostile or deliberately rejected probes. The gate
uses QEMU user networking with `restrict=on`, IPv6 disabled, and an
`/dev/urandom`-backed virtio-rng device. Its fixed identities are public test
vectors, not production provisioning or Milk-V Duo evidence. It also does not
replace the malformed-packet fuzzing, resource-exhaustion, deadline, reset, and
disconnect-race work listed for the complete N5 milestone.

The QEMU harness now defaults every integration case to four multithreaded TCG
vCPUs and requires the boot-time `4 hart(s) online` barrier, shared Sv39
activation marker, W^X/MXR/RFENCE marker, and `.rodata`/4 MiB COW capability-table
marker before accepting a shell transcript.
`smp_queues` places non-stealable waiters on logical harts 1--3,
proves each parks and resumes on its exact executor, drains the placement
doorbells, then wakes all three from the boot-pinned shell. It requires one new
successful SBI doorbell per target and receiver-side acknowledgement/idle evidence.
The same case runs a synchronized four-hart scheduler-lock sample and requires a
coherent, nonzero contention delta; the final full-suite run observed 1,688
contended acquisitions out of 2,170. Numeric telemetry is normalized only for the
golden diff and is separately parsed from the raw serial log. M5.4's nested host
model still checks running/current-task/domain isolation, remote cancellation, and
cross-hart fault survival without pretending host threads reproduce target IRQs.

`guard_page` is the deliberate exception to the usual clean-shell-exit shape. The
boot-pinned shell prints hart 0's invalid 4 KiB guard address and stores to it. The
raw-log validator requires exception cause 15 (`store page fault`), requires the
reported `stval` to equal the printed probe address exactly, and requires the
hart-specific guard marker. This proves that hardware blocked the store whose
address landed in the guard; it does not simulate a corrupted `sp` or a jump over
the single-page guard. A real bad-`sp` overflow may fault recursively while trap
entry saves registers on the same stack, so M6.2 claims guard-page enforcement,
not complete stack-clash protection, reliable recovery, or diagnostics.

`wx` is the non-fatal W^X lifecycle case. The boot-pinned shell links code into
an RW-NX page, seals it execute-only, and obtains 41 on both the boot hart and a
task pinned to logical hart 1. It then drops the image, requires the complete
same-address page to have been cleared, links code returning 42 there, and executes
the new image on hart 1 without a per-run `fence.i`. The transcript reports the
actual PTE state and the transition/remote-fence deltas; the in-kernel RAM scan
must find no writable-executable leaf.

The three `wx_*_fault` cases are separate expected-fatal boots because each proves
one hardware denial: instruction fetch from writable RW-NX storage (cause 12), load
from sealed execute-only storage with MXR clear (cause 13), and store to sealed
storage (cause 15). For each, the raw-log validator requires the printed probe
address to equal `stval` and requires the W^X-specific trap marker. A normalized
golden alone is insufficient because it deliberately hides addresses.

`ro` is the non-fatal M6.4 lifecycle case. It requires both `.rodata` endpoint
pages to be R--, then performs capability mint, derive, hart-1 lookup, revoke, and
stale lookup denial while every published replacement remains R--. It also requires
the first-fit pool to reuse the same address after the retired table has returned to
RW-NX, dropped its slots, and been completely cleared, and checks the expected
all-hart TLB-shootdown deltas.

`rodata_write_fault` and `cap_table_write_fault` are separate expected-fatal boots.
Each performs a real store and must report cause 15 (`store page fault`); the raw-log
validator requires `stval` to equal the printed `.rodata` or published-table address
exactly and requires the matching read-only marker. The normalized transcript is
necessary but not sufficient because it hides those addresses.

The protection is intentionally narrower than complete capability-graph
immutability. It covers the published `Slot` snapshot—generation, rights, object
pointer, and derivation pointer—while CSpace lifecycle scalars and
`Derivation.alive` remain RW supervisor metadata. Candidate construction and commit
are synchronous and use SYSTEM allocation; ordinary errors leave the old table
authoritative, while an exceptional candidate allocation/protection failure may be
conservatively leaked rather than rolled back across a non-local exit.

The sixteen audited fault/restart cycles now abandon a sealed code allocation as
well as heap data and a held CSpace lock. After all-hart task quiescence, raw
recovery must unseal, zero, and release exactly that allocation domain without
running the interrupted future's destructor; live code-pool pages must return to
their pre-probe baseline every cycle.

## Performance baseline

The shell's `bench` command measures two-endpoint IPC round trips, timer-IRQ to
task-poll latency, capability lookup at derivation depths 0 through 32, global
heap high-water, compiler throughput, and generated code/data size and runtime.
Every timing distribution reports warmup/sample counts plus min, p50, p95, max,
and integer mean in raw `rdtime` ticks.

`scripts/bench.py` boots the release kernel with `virt`, `rv64`, one hart,
single-threaded TCG, and deterministic `icount`; it rejects missing, duplicate,
or schema-changed metrics before comparing the checked-in
`benchmarks/qemu-tcg-rv64.json`. Latency/size regressions are upper-bounded and
throughput is lower-bounded. Relative budgets are combined with small absolute
allowances for timer quantisation; heap and generated buffers use the documented
larger byte allowances.

```sh
./scripts/bench.py                 # collect and check; never rewrites truth
./scripts/bench.py --update        # intentional baseline replacement
./scripts/bench.py --input log.txt # validate/recheck a saved transcript
./scripts/bench.py --smp-scaling   # four exact-hart workers; require >=1.25x
./scripts/bench.py --selftest      # positive and fail-closed SMP parser fixtures
```

Replacing the one-hart baseline is an architecture-epoch operation, not a way
to waive a red comparison. Start from an otherwise clean source tree, use the
pinned compiler, record the exact QEMU revision used, and rebuild once. Then
repeat the exact binary with at least three `--no-build` runs. Review every
metric and the policy-derived limits before committing the JSON. The
2026-08-25 epoch followed that procedure on QEMU 11.0.3 after a source bisection
attributed the old IPC/IRQ crossings to reclaimable-dispatch and generational
instance safety. Its IPC/IRQ ratios were tightened so the larger coordinate
retains approximately the old absolute regression headroom.

The scaling mode intentionally does not share the deterministic one-hart
baseline. It boots `-smp 4` with multithreaded TCG, waits for all three remote
workers before releasing the boot hart, and compares identical integer work run
serially and in parallel. Each measurement spans tens of milliseconds rather
than a scheduler quantum. The final M5.5 run measured 773,610 serial ticks and
275,290 parallel ticks (`2.810x`); CI enforces only the conservative `1.25x`
floor so host noise cannot turn the observation into an overfit baseline.

The guest IPC number is a repeatable VibeOS trend measurement, not yet a claim
against a Linux pipe: a host pipe measured on another ISA/runtime would not be a
controlled comparison.

## Why four layers

Each layer catches what the one above it structurally cannot.

Host tests cannot reproduce interrupt ordering, because the host arch shim makes
interrupts a no-op — so timer and wakeup behaviour belongs to the in-kernel
self-test. Neither host tests nor the self-test can check the *semantics* of
emitted machine code as thoroughly as running a program whose every output value
is known, which is what the `conform` golden transcript is for.

This is not hypothetical. Changing one frame offset in the code generator:

```rust
-  self.emit(ld(T0, S0, off));
+  self.emit(ld(T0, S0, off + 8));
```

passes **every host test**, including the confinement audit — the instruction is
still a structurally valid load through the frame pointer. The QEMU conformance
run catches it immediately:

```
-call 42 3628800
+call 2149628476 8634481114540408832
```

`2149628476` is `0x8020xxxx`: a kernel address, read off the stack by a compiled
program. That is the privilege-escalation class this project's design rests on
preventing, and only the integration layer sees it.

## Differential testing against real rustc

Every program in `tests/programs/` is valid Rust *and* valid in the VibeOS
subset, so `rustc` is a free oracle for the code generator — the strongest check
available for something this security-critical.

`scripts/differential.sh` compiles each with the exact real `rustc` pinned in
`rust-toolchain.toml`, runs it, and verifies the committed output byte-for-byte.
It is read-only unless passed `--update`; a missing expectation fails instead of
silently becoming truth. The QEMU `differential` case feeds the same source
through `rustc edit` inside VibeOS and requires identical bytes. The case file is
regenerated from the corpus on every run, so the two cannot drift.

Keeping the corpus inside the intersection of the two languages is a real
constraint, and getting it wrong is caught immediately — rustc rejected the
first draft because bare integer literals infer as `i32` while the subset is
`i64`-only. See `tests/programs/README.md` for the rules.

## Updating goldens

```sh
./scripts/differential.sh --update  # real-rustc corpus expectations
./scripts/qemu-test.sh --update      # all cases
./scripts/qemu-test.sh conform       # run one case
./scripts/qemu-test.sh net           # raw L2 exchange plus host evidence
./scripts/qemu-test.sh net_recovery  # post-publish fault and fresh-epoch retry
./scripts/qemu-tcp-test.sh           # independent N1 hostfwd byte-stream gate
./scripts/qemu-tcp-test.sh recovery  # independent N2 stack/driver recovery gate
./scripts/qemu-ssh-security-test.sh  # independent N3 entropy/identity gate
./scripts/qemu-ssh-test.sh           # independent N4/N5 OpenSSH wire gate
./scripts/qemu-test.sh program_persistence # two boots plus raw artifact evidence
python3 -B scripts/storage-v2-image.py --selftest # independent Storage V2 format/parser gate
cargo test -p vibeos-segment-store # exhaustive Storage V2 write/flush fault boundaries
./scripts/qemu-test.sh smp_queues   # logical queues + boot-hart SBI/SSIP, one CPU
./scripts/qemu-test.sh guard_page   # expected-fatal store-page-fault + exact stval
./scripts/qemu-test.sh wx           # seal, cross-hart execute, clear, same-address reuse
./scripts/qemu-test.sh wx_execute_fault # expected-fatal instruction-page-fault + exact stval
./scripts/qemu-test.sh wx_read_fault    # expected-fatal load-page-fault + exact stval
./scripts/qemu-test.sh wx_write_fault   # expected-fatal store-page-fault + exact stval
./scripts/qemu-test.sh ro           # .rodata + COW table lifecycle across harts
./scripts/qemu-test.sh rodata_write_fault # expected-fatal `.rodata` store + exact stval
./scripts/qemu-test.sh cap_table_write_fault # expected-fatal table store + exact stval
```

Read the diff before updating. The `--update` flag is the only thing standing
between a deliberate behaviour change and a silent regression.

## Adding a test

- **A bug that reached `main` gets a regression test in the same commit as its
  fix.** Both bugs found so far are in the suite: the dropped self-wake
  (`core/tests/runtime.rs`) and the invisible running task (both there and in
  `kernel/src/selftest_platform.rs`).
- **Diagnostics are asserted verbatim.** Error messages are a UI; a silently
  reworded error is a regression a user notices first.
- **New compiler syntax gets a line in `samples::CONFORMANCE`** with a printable,
  hand-checkable value — not just a "does it compile" test.

## Checking that a test can fail

A test that cannot fail is worse than no test, because it looks like coverage.
To check one, break the code it covers and confirm it goes red:

```sh
# in core/src/cap.rs, temporarily:
-  if !e.rights.contains(need) {
+  if false {
cargo test -p vibeos-core --test cap     # must FAIL
```

Mutations verified to be caught: dropped self-wake, bypassed rights check,
non-cascading revoke, unbumped generation, permitted amplification, memory access
through a non-frame register, dropped `li64` chunk, wrong store opcode, corrupted
precedence table, dropped heap free-list entry.

Mutations **not** caught by host tests, caught only under QEMU: wrong frame
offset. That gap is the reason the golden transcripts are not optional.
