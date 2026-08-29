# C8.4 AOT decision contracts

The independent fixed-QEMU v1 campaign published on 2026-08-28 formally
completes C8.4 for `ssh-case-filter-12k-v1`. C1 through C8.2 remain accepted
complete by historical-evidence policy; none is reopened, rerun, or
individually rewalked. C8.3 remains accepted as complete by the project's
historical-evidence policy. Milk-V Duo execution remains paused at operator
request and was not a prerequisite for this decision. The
published QEMU result is explicitly emulator-scoped: it cannot claim, imply,
or be renamed into physical-Duo performance evidence.

The published bundle is
[`benchmarks/wasm-aot-decision/qemu-v1/`](../benchmarks/wasm-aot-decision/qemu-v1/).
It binds source commit
`e950a2facb6a6c230e67becb186bddf34a5924bb`, run ID
`a22f28ef7aab11de5c4858e9a4e4c5b5b4e6e763c43a126ad84d4ac80b9f500f`,
and outcome `aot-not-justified-on-fixed-qemu`. C8.5 through C8.7 were not
entered for this workload and remain globally deferred. Its immutable
historical next-node value is `C8.8-skip-or-defer-C8.5-C8.7`; the live roadmap
position is now `c811-s3-qualified-sealed-simd-runtime-released`. The separately
allocated C8.9 Float successor does not rewrite the C8.4 decision. The result
does not authorize AOT or accept native component bytes.

The immutable historical C8.4 `next_node` value is
`C8.8-skip-or-defer-C8.5-C8.7`; it is not the repository's current position.
The C8.9 closure position is `c89-s3-qualified-sealed-float-runtime-released`.
C8.9-S1 allocates the independent Float successor design, C8.9-S2 implements
its interpreter path, and C8.9-S3 qualifies and releases only the sealed Float
runtime on fixed QEMU. AOT remains unauthorized.
The current roadmap position is
`c811-s3-qualified-sealed-simd-runtime-released`; C8.11-S3 releases only the
sealed SIMD runtime and does not authorize AOT.

The later non-numbered fixed-QEMU target/release policy checkpoint applies
prospectively to generic WASM target/release gates. It does not widen the
historical C8.4 replacement scope, alter the stored next-node value, or permit
this campaign to be reused as fresh evidence for another node.

The decision-bearing machine-readable contracts are
[`benchmarks/wasm-aot-decision/workloads-qemu-v1.json`](../benchmarks/wasm-aot-decision/workloads-qemu-v1.json)
and
[`benchmarks/wasm-aot-decision/schema-qemu-v1.json`](../benchmarks/wasm-aot-decision/schema-qemu-v1.json).
The strict summary, environment, and final-decision envelopes are defined by
[`benchmarks/wasm-aot-decision/evidence-schema-qemu-v1.json`](../benchmarks/wasm-aot-decision/evidence-schema-qemu-v1.json);
that evidence schema is deliberately not part of the target transcript run ID.
The earlier physical contract is retained, unchanged and non-blocking, in
[`benchmarks/wasm-aot-decision/workloads-v1.json`](../benchmarks/wasm-aot-decision/workloads-v1.json).

## Fixed-QEMU decision envelope

The platform ID is `qemu-virt-rv64-tcg-icount-v1`: `virt`, RV64, one hart,
128 MiB, `tcg,thread=single`, and
`-icount shift=0,align=off,sleep=off`. The runner must name an explicit
`opensbi-riscv64-generic-fw_dynamic.bin`; `-bios default` is forbidden. QEMU,
OpenSBI, OpenSSH, kernel, toolchain, the complete QEMU argv, and every Python
helper reachable from the runner/peer chain are recorded in the evidence
envelope. The canonical SSH host public key and fingerprint are embedded
rather than referring to a deleted temporary file. For formal verification,
QEMU is frozen to version `11.0.3`, SHA-256
`ef5c714232320c22561daa0998546b73672e21a2801404714dfbd4982ac7b3c0`
and 13,511,488 bytes; OpenSBI is frozen to SHA-256
`49bdf7b939bda11321132d1042bf99d7324fb190f1feef423171fed3573f8705`
and 273,048 bytes. QEMU, BIOS, and the private kernel are re-hashed, copied into
one randomized private directory, sealed to `0500`/`0400` with a `0500`
directory, and executed only from those byte-identical copies.

The runner constructs the absolute, custody-bearing QEMU argv once as an
immutable tuple. That same tuple is passed directly to the sole `Popen` call
and to the evidence writer; no second command reconstruction is allowed. The
evidence retains both the actual argv and its path/port-normalized form. The
independent verifier starts from the actual argv, validates the three shared
custody paths and unique host-forward port, independently performs the only
permitted normalization, and requires the result to equal the frozen semantic
argv contract.

The formal build has a separate closed input envelope. It audits the 189
crates.io packages in the exact project `Cargo.lock` and the 30 in pinned
rust-src `library/Cargo.lock`, rejects a same-name/version checksum conflict,
and materializes their deterministic 213-package union. Project packages are
checksum-verified safe extractions from the fixed launcher cache; the 24
rust-src-only packages are copied from pinned `library/vendor` only after its
checksum inventory, file types, paths, bytes, and modes are independently
verified. Cargo is then invoked by its absolute toolchain path from cwd `/`,
with an absolute manifest and a `0700` private `CARGO_HOME` containing exactly
one immutable generated `config.toml`; the reviewed
`firmware/.cargo/config.toml` bytes are preserved and fixed cache-GC plus
private source-replacement sections are appended. This prevents an ancestor
such as `/tmp/.cargo` from participating. Before any Rust tool is
executed, the fixed RUSTUP_HOME/channel/host triple is used to derive and hash
the complete nightly toolchain and rust-src trees without executing rustup.
Those trees, the private crate tree and Cargo home, root-config absence, and
the recursive non-system `ld.lld` Mach-O closure are checked again after build
and by both independent-verifier passes. The build PATH is exactly
`/opt/homebrew/bin:/usr/bin:/bin`; `cargo`, `rustc`, and `rustdoc` must be the
exact files under the manifest-pinned toolchain root's `bin/` directory.
`SOURCE_DATE_EPOCH` is the decimal timestamp read from the attested source
commit, not a caller-supplied epoch. The private crate-archive directory is
also recorded as a canonical direct path with no leaf symlink, alongside the
separately extracted private crate-source tree.

Pinned Cargo 1.99 necessarily creates runtime cache metadata even for this
directory source. The formal environment fixes only Cargo's cache last-use
clock (`__CARGO_TEST_LAST_USE_NOW=1234567890`), disables automatic cache GC,
and launches Cargo with umask `0077`. The private home must start config-only;
after a successful full build its complete additional set must be exactly the
pinned 57,344-byte `.global-cache`, the empty `.package-cache` and
`.package-cache-mutate` locks, and `registry/CACHEDIR.TAG`. Their types, modes,
link counts, bytes, SQLite header and hashes are verified and recorded before
they are removed and the directory is fsynced; the final home must again be
exactly config-only. No unknown entry is removed or ignored.

The firmware-search probe, QEMU `--version` probe, and sole live QEMU process
receive the same single explicit deny-by-default environment. Its complete
allowlist is `HOME`,
`LANG`, `LC_ALL`, `PATH`, `TMPDIR`, `TZ`, and `XDG_CONFIG_HOME`; the four fixed
values are `LANG=C`, `LC_ALL=C`, `PATH=/usr/bin:/bin`, and `TZ=UTC`. `HOME`,
`TMPDIR`, and `XDG_CONFIG_HOME` name fresh `0700` directories beneath the
private campaign root. The runner does not copy the ambient environment, so
`DYLD_*`, `QEMU_*`, additional locale variables, and host user configuration
cannot enter either process. The manifest freezes this normalized policy and
the evidence records it under `environment.qemu.environment`; the independent
verifier also closes the runner source edges that feed the one created mapping
to all three subprocesses.

The source QEMU binary and its byte-identical execution-custody copy each have
a recursive non-system Mach-O load-command closure recorded before capture,
after QEMU exits, and immediately before evidence creation. All three records
must remain identical within a role, and the source/custody normalized graph
hashes must match. Non-system edges must resolve inside the Homebrew Cellar;
only install names under `/System/Library/` or `/usr/lib/` are classified as
system edges. Those system edges are bound to the sealed, read-only APFS root
record and the exact host tuple macOS 26.5.2, build `25F84`, Darwin `25.5.0`.
The contract also forbids `-plugin`, omits `QEMU_MODULE_DIR`, and requires all
four frozen QEMU module-search locations under the Cellar/Homebrew prefix to be
absent. This closes QEMU's module/plugin search, but does not claim arbitrary
library-internal `dlopen` behavior beyond the recursive Mach-O load-command
graph.

The only formal entry point is `scripts/run-c84-qemu-aot-decision.sh`. It
resolves the reviewed CPython 3.14.6 Cellar executable and verifies its exact
52,448-byte identity plus the Framework binary and the 51,392-byte
`Python.app/Contents/MacOS/Python` executable before using `-I -B -S -X
pycache_prefix=/var/empty/vibeos-c84-python-pyc` under an empty-then-exact
environment. The runner removes the normally absent zip entry from effective
`sys.path`, excludes unreachable `site-packages` and `__pycache__`, inventories
the full reachable stdlib/lib-dynload tree, and rechecks it at closure. The
non-system Mach-O closure also pins `_hashlib`, `_lzma`, and `_zstd`, their
exact extension modules, the resolved Homebrew libcrypto/liblzma/libzstd
bytes, and the xz/zstd symlink chains. `OPENSSL_CONF=/dev/null` and
`OPENSSL_MODULES=/var/empty` are part of the exact launch environment; the
configuration device, empty provider directory, and an OpenSSL-backed SHA-256
known-answer test are verified. System dylibs remain covered by the Darwin
sealed-system policy. Maintained dynamic helpers are never loaded through importlib or
bytecode: each stable UTF-8 source snapshot is compiled directly, tagged with
its executed hash/length, merged through the nested peer chain, and compared
to the evidence helper identities for both live and frozen verification.

OpenSSH uses a separate Darwin sealed-system-volume custody rule because a
byte-identical copy of an Apple platform binary can be killed when executed off
the sealed system volume. The only accepted path is `/usr/bin/ssh`, version
`OpenSSH_10.2p1, LibreSSL 3.3.6`, SHA-256
`470f812f6e71ee4ca1b49c79f9c2982c054493e22502d4648bd010feb4b2a9b2`, and
1,555,472 bytes. Before and after capture, and again at both independent
verification boundaries, the tools require a root-owned `0755` regular
non-symlink with one link, `SF_RESTRICTED`, the same device as `/`, a read-only
filesystem flag, and an APFS root mount marked both `sealed` and `read-only`.
They execute that original path in place; no ad-hoc signing transformation or
`PATH` lookup is permitted. Pinned byte identity binds the reviewed Apple
binary while avoiding a host-dependent `codesign --verify` trust-chain result.

Local QEMU/BIOS/kernel paths and the fixed OpenSSH host path remain custody
provenance and are excluded from the guest platform identity. This software
custody closes ordinary path swap-and-restore races, but does not claim
isolation from a privileged attacker able to alter or remount the sealed system
volume. The accepted host-side limit is explicit: the operator must provide
same-UID host exclusivity for the campaign, because pre/post/final identity
checks cannot exclude a same-UID swap-and-restore while QEMU is live. The
contract also makes no broader `dlopen` claim beyond the recorded QEMU
load-command graph and explicitly frozen CPython runtime inputs.

One fresh QEMU process executes three discarded warmups and 21 retained
samples. The guest clock is `riscv.rdtime` at 10 MHz. The pre-frozen 100 ms
budget is therefore 1,000,000 ticks; this is a unit conversion fixed before
measurement, not post-result calibration. Retained stability requires
nearest-rank `p95(total_ticks) / p50(total_ticks) <= 1.10`; for 21 sorted
samples p50 is index 10 and p95 is index 19. The independent verifier closes
the source path from profile `live_tick()` through `sbi::time()` to `rdtime`,
and the QEMU board's exact 10 MHz constant, so metadata alone cannot relabel a
different tick source or scale.

Transcript parsing also has a generic fail-closed sentinel: any occurrence
matching `WASM_[A-Z0-9_]+ FAIL`, including a previously unknown failure marker,
invalidates the capture before the finite expected success-marker checks. It
cannot be ignored merely because it is not named by the workload schema.

Both predicates must hold to produce
`aot-eligible-for-c85-design-review-on-fixed-qemu`:

1. `p95(total_ticks) > 1_000_000`;
2. `p95(total_ticks - interpretation_ticks) <= 1_000_000`.

Otherwise the result is `aot-not-justified-on-fixed-qemu`, conditional C8.5
through C8.7 are skipped or deferred, and the historical decision records
`C8.8-skip-or-defer-C8.5-C8.7` as its next node. In either case
`aot_authorized=false`, `native_code_accepted=false`,
`platform_class=emulator`, and `physical_provenance=not-claimed`. A malformed,
incomplete, incorrect, or unstable run produces no decision at all.

## Published fixed-QEMU result

The formal campaign used one QEMU process, discarded three warmups, and
retained 21 samples. Its nearest-rank statistics are:

| Distribution | p50 ticks | p95 ticks | p50 ms | p95 ms |
|---|---:|---:|---:|---:|
| Total | 2,899,765 | 2,901,632 | 289.9765 | 290.1632 |
| Interpretation | 97,260 | 97,318 | 9.7260 | 9.7318 |
| Non-interpretation | 2,802,541 | 2,804,417 | 280.2541 | 280.4417 |

Stability passed because
`2,901,632 * 100 = 290,163,200 <= 2,899,765 * 110 = 318,974,150`.
The total p95 exceeds the 1,000,000-tick budget, so `budget_miss=true`.
However, the independently sorted non-interpretation p95 also exceeds that
budget, so `interpretation_attribution=false`. The evidence therefore records
`candidate_for_c85_design_review=false`, `aot_authorized=false`,
`native_code_accepted=false`, and next node
`C8.8-skip-or-defer-C8.5-C8.7`. Non-interpretation percentiles are derived by
subtracting interpretation from total per sample and then sorting; they are
not differences between independently selected percentiles.

The neutral
[`qemu-v1-publication-integrity-contract.json`](../benchmarks/wasm-aot-decision/qemu-v1-publication-integrity-contract.json)
is policy, not evidence. The current CI-safe publication-integrity and
transport checks do not boot QEMU:

```sh
python3 -B scripts/verify-c84-qemu-published-evidence.py --check-published
python3 -O -B scripts/verify-c84-qemu-published-evidence.py --check-published
python3 -B scripts/verify-c84-qemu-published-evidence.py --selftest
python3 -O -B scripts/verify-c84-qemu-published-evidence.py --selftest
python3 -B scripts/c84-qemu-aot-decision-peer.py --selftest
./scripts/run-c84-qemu-aot-decision.sh --selftest
```

The publication auditor verifies the exact four checked-in evidence files at
publication commit `cbb1d0f`, the full recorded source tree at `e950a2f`, and
the historical Git membership of the capture-time QEMU verifier, physical
helper, policy source, and three decision contracts. It also rechecks the
stored emulator-only/no-AOT/no-native-code outcome and zero physical inputs.
This is structure/hash integrity only: it does not replay the QEMU process,
publisher execution, or ephemeral host custody and does not establish physical
provenance. The old capture-time verifiers remain byte-frozen historical
members rather than current-tree gates; later policy files must never be
substituted for the `e950a2f` members they reviewed.

A development run may use `--allow-dirty-smoke`, but that mode selects a
compile-time smoke-only feature. Its META records
`capture_mode=dirty-smoke-not-publication`, `decision_eligible=false`, and a
smoke-only run-ID domain. It is therefore wire-distinct and is categorically
rejected by `--publication`. Its recorded Cargo command names
`<dirty-worktree>/firmware/qemu-virt/Cargo.toml`, never the formal
`<materialized-source>` provenance. Smoke mode still requires the configured
fetch and push origin to be exactly the frozen repository origin, although it
does not perform the formal live remote-advertisement proof. The formal feature instead records
`capture_mode=formal-publication`, `decision_eligible=true`, and the formal-only
run-ID domain. The published campaign used this formal no-clobber command:

```sh
./scripts/run-c84-qemu-aot-decision.sh \
  --evidence-dir benchmarks/wasm-aot-decision/qemu-v1
```

It wrote `uart.log`, `summary.json`, `environment.json`, and `DECISION.json`
only after the independent verifier accepted both the transcript and the
source/tool/platform envelope. Formal verification also requires live branch
`codex/wasm`, a clean HEAD equal to the bound source, local and tracking refs at
that commit, no assume-unchanged, skip-worktree, or fsmonitor-valid index state,
and a direct sanitized query proving that
`https://github.com/allegro0132/vibeos.git` advertises the same
`refs/heads/codex/wasm`. The build does not consume the current working tree or
its ignored `target/`: it inventories the exact superproject commit and the
exact `vendor/jitterentropy-rs` and `vendor/sunset` gitlink commits with
`ls-tree`, then exports each already-verified blob through raw `git cat-file
--batch` bytes. It recomputes every Git blob object ID and materializes only
reviewed `0644`/`0755` modes; checkout, clean/smudge filters, and working-tree
conversion never participate. Every Git subprocess uses
`GIT_NO_LAZY_FETCH=1`, replacement objects disabled, no system/global config,
and a fixed sanitized PATH. The superproject and both submodule local config
files are read explicitly with `--no-includes`, byte-identified before and
after, and parsed through a default-deny key/value allowlist. Filter drivers,
URL rewrite rules, includes, and any other unreviewed local key therefore fail
closed. Fixed-remote queries run from `/`, where `/.git` must be absent, so
repository-local discovery cannot alter the URL. The build uses a new private
`CARGO_TARGET_DIR`. Publication verifies all bytes before one atomic
no-replace directory rename; the final directory and files are read-only. A
failure to fsync the parent after that commit point is reported explicitly as
complete verified bytes with uncertain crash durability, not as a retryable
absence.

## Frozen product workload

`ssh-case-filter-12k-v1` is one authenticated OpenSSH exec of the image-pinned
`case-filter` command. Timing begins immediately after the authenticated
`SessionExec("case-filter")` request is accepted and ends after status `0` is
published and the exact stdout is drained. The request has no arguments,
stderr is empty, and stdin/stdout use the existing bounded SSH stream path.

| Item | Frozen value |
|---|---|
| Command/world/entrypoint | `case-filter` / `vibe:stream/filter@1.0.0` / `run` |
| Compiled component | 2,012 bytes; SHA-256 `180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72` |
| WAT source | `policy/image/artifacts/c53-stream-filter.component.wat`; SHA-256 `6db36b58350c4de22077fba4dd9dd1166f0808e2adc8488ba086d91c6f659cc1` |
| Input | 12,325 bytes, byte `i = (i * 17 + 3) % 251`; SHA-256 `6b6054d492e00e68a93bc9b657a69577c7c44f5a48f169adb4124df0a50f6b3c` |
| Expected output | Each input byte XOR `0x20`; SHA-256 `791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27` |

The exact executable `ProfileIdentity` has artifact, component-profile,
core-profile, and runtime ABI version `1`; Core revision
`webassembly-core-2.0-integer-v1`; Component revision
`wasmparser-component-model-0.255.0`; Canonical ABI revision
`component-model-0.255.0-sync`; wasm-tools revision
`wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380`;
WASI revision `wasi-not-selected-sync`; canonical feature mask `7`; and stage
`executable`. Input and output are each transferred as twelve full 1,024-byte
chunks followed by one 37-byte chunk: 13 reads and 13 writes.

The artifact and SSH fixture identities are checked independently against
`policy/image/build.rs`, `policy/image/src/lib.rs`, and
`scripts/openssh-peer.py`; a similarly behaving replacement is not the frozen
workload.

## Deferred legacy physical platform, sampling, and budget

This section documents the retained Duo-v1 contract for historical audit and
possible future qualification. It no longer blocks C8.4 and is not mixed with
the fixed-QEMU decision population.

The decision platform is a Milk-V Duo CV1800B/C906B running hart 0 only. The
clock is `riscv.rdtime` at 25 MHz. Collection requires three separate physical
cold boots. Each boot runs three discarded warmups followed by 21 retained
samples, for 63 retained samples in total.

The frozen response budget is 2,500,000 ticks, exactly 100 ms at 25 MHz. The
decision statistic is nearest-rank p95 over all 63 retained physical samples:
index `ceil(0.95 * n) - 1` after ascending sort. A budget miss is strictly
`p95(total_ticks) > 2_500_000`.

The 100 ms threshold is a product-response requirement selected before any
C8.4 profiling result exists. It is not inferred from C8.3 observations and
must not be moved to make a later result pass.

Under this retained physical contract, the older diagnostic QEMU gate remains
integration-only. Its ticks must not be converted, combined with Duo ticks, or
used to meet or miss the 25 MHz Duo budget. The separate QEMU-v1 contract above
uses its own 10 MHz population and never mixes the two datasets.

Only complete success samples enter the formal dataset: each records 13 reads,
13 writes, fuel consumption in the inclusive range 1 through 500,000, positive
poll quanta, terminal `success`, zero logical live state after cleanup,
`timed_out = false`, timeout phase `none`, and a complete interval transcript
with capacity 65,536 and an exact declared count. A timeout, trap, failed
status, truncated stream or interval ledger, wrong output, leak, or interval
overflow is diagnostic evidence outside the decision population and can never
authorize AOT.

## Deferred physical single-cold-boot transcript closure

Each cold boot has its own raw serial transcript, capped at 268,435,456 bytes.
One raw contains exactly one `VIBE_WASM_AOT_META` record, 24 ordered
`VIBE_WASM_AOT_SAMPLE` records with sequence and sample index 0 through 23,
and one `VIBE_WASM_AOT_END` record. Samples 0 through 2 are warmups and samples
3 through 23 are retained. Target records deliberately contain no boot index:
only host evidence assigns indexes 0 through 2 after each raw has passed
independent verification. The final evidence verifier must prove all three
indexes occur once and share one campaign identity.

The shared `run_id` is SHA-256 over the ASCII campaign domain followed by the
source commit, challenge, artifact/input/output hashes, manifest hash, and
schema hash as NUL-separated fields with no trailing NUL. It binds those
values but does not prove that a board was power-cycled. The `END` record's
64-bit rotate-and-add accumulator folds every ordered sample and interval word,
including the stdout digest. It helps detect accidental ordering, truncation,
and corruption; it is not authentication and has no collision-resistance
claim.

The host verifier accepts only a non-empty stable regular file, rejects
symlinks and special files, parses strict UTF-8 JSON without duplicate members
or oversized integers, requires record markers at column zero, and enforces the
complete per-sample semantics: identity, coordinates, successful output,
fuel/poll bounds, exact interval count, non-empty gap-free phase partition,
adjacent-phase merging, phase sums, accumulator, and per-boot stability. It
derives a deterministic single-boot summary that carries the raw byte hash and
explicitly has scope
`single-boot-transcript-semantics-only-no-aot-decision`; the artifact also
records both physical and cold-boot provenance as `unverified`.

```sh
python3 -B scripts/verify-c84-aot-decision.py \
  --transcript evidence/wasm-aot-decision/duo/boot-0/uart.log \
  --expect-source "$PREPARATION_COMMIT" \
  --expect-challenge "$CAMPAIGN_CHALLENGE" \
  --boot-index 0 \
  --summary-out evidence/wasm-aot-decision/duo/boot-0/summary.json
```

Summary creation is no-clobber by default; `--overwrite` is explicit and only
replaces an existing regular output after all input checks pass. The verifier
then rereads the summary and revalidates every preparation input. A passing
command verifies transcript bytes only: physical provenance and the cold-boot
operation remain unverified until a separate capture/evidence closure exists.
One raw or one derived summary cannot satisfy the three-boot publication gate,
complete C8.3, decide C8.4, or authorize AOT.

## Exclusive phase ledger

Every elapsed tick in the response interval belongs to exactly one interval
label. Intervals may repeat or interleave, but they may not overlap or leave a
gap, and each retained sample must satisfy
`total_ticks == sum(phase_ticks)` for these seven phases:

1. `validation`: after accepted `SessionExec` through exact credential,
   policy, manifest, image-root, and plan revalidation, including validator or
   compiler work and excluding Core/adapter instruction execution.
2. `instantiation`: owner, arena, CSpace, task envelope, `ProfileEngine`,
   `SynchronousComponent`, `ResourceTable`, and typed-call construction.
3. `abi`: Canonical lower/lift, realloc, resource-token, return-pointer, and
   value encoding/decoding work.
4. `interpretation`: only wasmi Core or adapter instruction execution; no
   validation or compilation.
5. `host`: runnable stream read/write/close plus SSH pump and protocol
   transport work.
6. `wait`: yield, `HostPending`, backpressure, scheduler, and network waiting.
7. `cleanup`: after guest `Ready` or trap through terminal/stream finalization,
   CSpace/registry/arena/owner reclaim, VSH reaper acknowledgement, and stdout
   drain.

The order above is the canonical reporting order, not a claim that each phase
is one contiguous interval. Only `interpretation` is AOT-attributable.

## Interval capacity and collection completeness

During preparation, before any decision-bearing C8.4 capture may be produced,
a dev-only `c84-profile-hooks` preflight ran the exact frozen artifact and
12,325-byte input through the buffered product work model. It locked these
complete-call counts:

| Counter | Frozen preflight |
|---|---:|
| Typed polls / pending polls | 1,251 / 1,250 |
| Core polls | 1,165 |
| Profiled-poll work / typed-call planning / terminal work | 188,121 / 2 / 188,123 |
| Dispatcher start / prepared commit / total host entries | 29 / 13 / 42 |

The preparation verifier independently parses the real kernel dispatcher's
declarations, `required_work` branches, and every ready/commit response charge.
Read must remain `MAX_STREAM_CHUNK_BYTES + 4`, write `4 + bytes`, and close `1`.
The kernel must also import the same 1,024-byte component-host maximum used by
the fixture. Before any scope extraction, the verifier pins the reviewed byte
identity of the entire `kernel/src/component_instances.rs`, including attribute
literal values. This makes module binding, `cfg` feature selection, alias,
executable dead-code, and macro drift fail closed. It separately removes nested
comments and Rust literal forms, extracts the seven reviewed dispatcher methods
with balanced braces, and pins their combined canonical source digest for
localized review; decoy text cannot satisfy the semantic checks.

With strict adjacent-same-phase merging and no wait or interrupt episodes, the
audited interval count is exactly
`4 + 2 * (1,165 Core polls + 42 host entries) = 2,418`. The managed runner
yields one executor turn after each of the 1,250 pending polls, so even the
buffered no-`HostPending`, no-IRQ path requires at least
`2,418 + 2 * 1,250 = 4,918` intervals. The former schema capacity of 4,096 was
therefore impossible for the frozen successful path.

The corrected v1 engineering capacity is 65,536 intervals. Each formal sample
must contain `interval_capacity = 65536`, `interval_count == len(intervals)`,
and `intervals_complete = true`. The collector must keep one active sample in
packed target storage and stream it before starting another; a conservative
17-byte phase/start/end encoding occupies 1,114,112 bytes, about 1.77% of the
Duo's 60 MiB RAM. Capacity exhaustion, a missing interval, or any truncation
makes the attempt diagnostic-only and ineligible for publication. The
collector must never ring-overwrite intervals or merge non-adjacent phases.

The 65,536 value is not a mathematical worst-case upper bound: the frozen
contract does not bound the number of `HostPending`, network/backpressure, or
interrupt episodes. It is an engineering cap with fail-closed overflow
semantics. Because no evidence existed when this feasibility error was found,
the schema remains version 1 and the workload remains revision 1; artifact,
input, budget, sampling, phases, and decision predicates are unchanged.

## Prepared-child ownership seam

The default-off kernel profile slot can bind at most one exact member of a
still-hidden `PreparedTaskBatch` to its request parent before scheduler
publication. The executor installs the child's final-reason callback first and
returns only a copy-only identity seal; the request parent keeps exclusive
finish, cancel, storage, stream, and recycle authority. The seal itself has no
wake or disarm operation. A child can claim only from its exact first poll;
yielding before claim is permanently too late. Explicit release leaves the
callback armed across the remainder of the future and its destructor, so only
`release + Exited` is clean. `Cancelled`, `Faulted`, exit without release,
child-lease abandonment, or parent finish while the child is live is
diagnostic-only and cannot produce verified evidence. The isolated gate drives
the executor's real guarded destructor-fault path without emitting or allowing
a serial panic.

The isolated QEMU gate proves this bind/claim/release/detach state machine,
including an exact child-owned Core start/end observer pair whose returned end
tick is independently matched against the final streamed ledger boundary. Its
request-wide slot owner rejects parent/child Core overlap, parent phase
mutation during child Core, malformed pairing, open release, adapter Drop, and
single or double `forget`, including raw owner-task detach after both a parent
observer and its RunLease are forgotten. The gate also proves a real
child-owned self-SSIP and a multi-hart start rejection. By itself it does not
edit the frozen `kernel/src/component_instances.rs`, connect the real managed
component child or ordinary wasmi `poll()` path, prove the authenticated SSH
boundary, publish schema output, collect cold boots, or establish physical
timing eligibility. The managed-child/Core composition below now closes the
child, ordinary-Core, and authenticated-response gaps for one exact diagnostic
target.

Before that seam can be attached to the production managed batch, the executor
also guarantees one exact pre-staging rollback edge. Dropping a hidden
raw-reclaimable task while it is still held by the batch-local `Prepared`
envelope drains its SYSTEM-owned detach ledger with reason `Cancelled` while
the arena bytes are intact, then abandons the future without running its
destructor. A profile child bound before staging therefore cannot remain
silently `Attached` after a later pre-staging setup failure. Once staging
succeeds, the activated batch must instead be published or explicitly
quarantined; this rollback makes no broader promise. The default-off
composition below consumes this prerequisite on the real ordinary managed-child
path without enabling it in default images.

## Authenticated SSH request-parent seam

The next default-off seam binds the exact authenticated OpenSSH request parent
to the kernel slot without finishing a sample. The only arming route is a
public-key-authenticated `SessionExec` whose current Component descriptor and
raw command are the exact, unparameterized `case-filter` target. Builtins,
onboarding credentials, `native-case-filter`, parameterized commands, revoked
or rotated descriptors, and feature-off builds remain inert.

After credential, current-policy, and grammar revalidation, `PreparedExec`
owns the slot reservation. Its acceptance transition calls Sunset's exec
success response first and starts the lease immediately afterward, before
returning `ProtocolSignal::Exec(AcceptedExec)`. Failure to send success drops
the still-unstarted permit. `serve_connection` retains the resulting run as
request-parent state; it is not passed into the managed child. Pre-response
execution, network, reset, rebind, timeout, and disconnect failures therefore
cancel through the same linear Drop path; normal completion uses the explicit
response boundary below.

On the normal path, the response boundary is the predicate that exit status,
EOF, server CLOSE, peer CLOSE acknowledgement, and all encoded output have
drained. The run is consumed once at that predicate before processing a
potentially destructive next protocol event and before TCP teardown. The
kernel then performs `RunLease::cancel`, compares the returned report with the
independently stored rejection, acknowledges that exact epoch once, and
requires `Ready(next_epoch)`. This diagnostic adapter intentionally exposes no
`finish`, verified stream, schema publisher, collector, or evidence API.

The static verifier and isolated single-hart OpenSSH gate are:

```sh
python3 -B scripts/verify-c84-ssh-profile-request-parent.py --selftest --check-source
./scripts/qemu-c84-ssh-request-parent-test.sh
```

The QEMU gate requires two consecutive exact responses and one connection
killed after START with exact DROP cleanup. It immediately starts an
authenticated readiness probe after DROP, then requires a fourth successful
request reusing the slot. The capability transport closes the old TCP
generation in one poll and accepts a queued replacement only on a later poll,
so each connection receives fresh entropy and a fresh SSH Runner.
Non-target probes must emit no request-parent marker. This proves the request
boundary and diagnostic recycling only. In this request-parent-only image the
real managed child is not attached to the lease and ordinary wasmi Core polls
remain unprofiled. The separate composition below closes those two gaps without
finishing or streaming a ledger, publishing a C8.4 sample, or establishing
physical Milk-V Duo evidence.

## Managed-child ordinary-Core composition seam

The default-off `wasm-c84-ssh-managed-child-core` feature composes the exact
authenticated request parent, prepared-child delegation, and ordinary Core
observer. The only target is the synchronous, unparameterized `case-filter`
managed child. Before scheduler publication, child index 0 reserves three
prepared-task registration slots and attaches to the current request; only its
copy-only epoch is stored in the arena-owned payload. The complete parent seal
and `RunLease` never enter the child.

On the outer future's first executor poll, the child claims before
`child_start_gate`, preserving the executor's sealed first-poll predicate even
when activation is not yet visible. Each target driver poll constructs one
lexical `ManagedChildSlotCorePollClock` and calls the ordinary runtime's
`poll_profiled`; that portable path brackets the real wasmi `poll_call`. The
driver checks both the clock's sticky error and globally stored Closed state
before the next poll or any `.await`. A zero epoch and every feature-off path
still call `call.poll()`.

An exact successful guest result alone sets `driver_completed`. The outer
future requires both that bit and the registry payload's exact final Success
word before release, leaves the detach callback armed, and accepts only the
later `CompletedPendingDetach + Exited` callback as clean. If registry
cancellation drops the driver or overrides its completion word, its later
outer `Ready` cannot wash cancellation into a release:
`ManagedChildFuture::drop` records abandonment and the callback records the
exact detach fault. Normal response requires `child = None`, `Exited`, no slot
faults, and a Closed Core owner. Request Drop accepts only the enumerated
detached/abandoned fault sets. Both boundaries retain the diagnostic parent's
`cancel -> exact rejection -> one acknowledgement -> Ready(next_epoch)`
closure.

The static source gate and isolated single-hart OpenSSH integration gate are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-core.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-core-test.sh
```

The standalone gate preserves its original 19-marker managed-child/Core
sequence and field contract. Successful epochs 1, 2, and 4 each freeze exactly
1,167 real Core polls, 1,167 observer pairs, and 1,241 typed polls. Those are
control-flow counts from the isolated QEMU image, not target timing or formal
profile evidence; they do not replace the distinct frozen preparation preflight.
Epoch 3 is killed after its first ordinary Core pair. Its real executor
callback reports `Exited` after a canonical positive-u64 count of closed
observer pairs (the run that exposed the latent scheduling variation reported
14). That partial-run count is deliberately not frozen. The missing
successful-driver bit keeps release false and produces exact
`CHILD_ABANDONED + CHILD_DETACHED` faults.
The parent still cancels and acknowledges the epoch, an immediate readiness
probe succeeds, and epoch 4 proves post-Drop reuse.

This closes the previously explicit gap between the real managed child and the
ordinary Core observer for the exact SSH target. The reusable base feature is
default-off; this predecessor's diagnostic QEMU acceptance contributes only
guarded transition telemetry and is integration evidence. There is still no
Host/Wait/Cleanup sidecar, IRQ
composition, `finish`, verified stream, schema publisher, collector, physical
Milk-V Duo sample, or AOT decision.

## Managed-child and SSH phase sidecar seam

The default-off `wasm-c84-ssh-managed-child-phase-sidecar` feature adds the
next diagnostic layer without changing the request parent's terminal authority.
At the exact current-policy, authenticated, synchronous, unparameterized
`case-filter` route, the parent first records Instantiation during preparation,
then the real child records Validation, Instantiation, and ABI. Ordinary Core
polls remain lexical Interpretation overlays. The child dispatcher opens a
non-`Send` Host guard around each synchronous start, wake registration, resume,
prepared commit, and explicit cancellation; every guard must close before the
caller can suspend. Destructor cleanup deliberately does not fabricate Host
while a request cancellation is snapshotting a legal open Wait.

Child Wait is independent of its resumable base phase. Immediately before each
real continuation `.await`, the driver stores only its copyable epoch and opens
Wait. A successful resume first revalidates the current prepared-task seal and
restores ABI or Cleanup before doing more work. An active request cancellation
may retain an open Wait as diagnostic state; a successful completion may not.
The parent has a separate Wait bit: `sshd` marks each managed transport, bridge,
protocol, stdin, stdout, and response-drain turn as Host, and marks real
execution, cancellation, cooperation, and shutdown suspension points as Wait.
Both owners may therefore be waiting at once without borrowing either lease
across an await.

`ProfileClock::cleanup_started` is a default no-op portable hook and is stored
once per typed call only when the C8.4 runtime hooks are selected. On a normal
call it fires after the next outer-poll start tick and before canonical cleanup
work; a preconstructed terminal or direct trap receives the same exactly-once
diagnostic edge before resource closure or the outer finish sample. The managed
clock irreversibly latches Cleanup. Release requires Cleanup, closed child
Wait/Host/Core, and the exact successful driver word. The SSH response further
requires the clean `Exited` detach and a closed parent Wait. It still consumes
the parent only through `cancel -> exact rejection -> acknowledge once ->
Ready(next_epoch)`; no result is finished or retained.

The independent source and single-hart OpenSSH gates are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-phase-sidecar.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-phase-sidecar-test.sh
```

The composed QEMU image still strictly parses exactly 19 ordered
managed-child/Core-family markers. Normal epochs 1 and 4 retain the standalone
counts of 1,167 Core polls, 1,167 observer pairs, and 1,241 typed polls. Epoch 2
writes only the first 257 stdin bytes before waiting for the real guest
HostPending marker, so its frozen combined-image counts are exactly 1,171 Core
polls, 1,171 observer pairs, and 1,251 typed polls: Core increases by 4 and
typed polls by 10. The standalone gate and its transcript remain unchanged.
Epoch 3 is killed at a child Wait that follows the first ordinary Core pair;
the open Wait is accepted only on the diagnostic Drop path, with no release and
the exact abandoned/detached faults. Its canonical positive-u64 child Core
start/finish count must equal the dynamically parsed Core-family closed-observer
count. Normal epochs require ordered Validation -> Instantiation -> ABI -> Cleanup, paired child Host/Core/Wait edges, paired
nonzero parent Host/Wait observations, clean detach, response, and post-Drop
epoch reuse. Parent transport counts are scheduler/network dependent and are
checked relationally, not frozen as target timing evidence.

This closes only the roadmap's real Host/Wait/Cleanup composition gap. The base
feature is silent and remains available to the Milk-V build as a compile-time
seam, not physical evidence. IRQ composition, `finish`, verified streaming,
schema publication, collection, physical-Duo sampling, and the AOT decision
remain later nodes.

## Managed-child parent/child IRQ-overlay composition

The default-off `wasm-c84-ssh-managed-child-irq-overlay` successor composes the
same authenticated request parent, real managed child, ordinary Core observer,
and phase sidecar with the production profile IRQ overlay. The base feature is
silent, contains no acceptance worker, and is exposed to Milk-V only as a
compile-time seam. The separate diagnostic IRQ-overlay QEMU-acceptance feature
retains the phase, Core, and request predecessor telemetry and adds one narrow
causal self-SSIP state machine; it does not enable the standalone profile-IRQ
acceptance image.

Epoch 1 forces the only two active self-SSIPs. The parent injection occurs only
after `managed_parent_host` has returned, so `SLOT` is no longer held and the
current request parent is the active owner. The child injection occurs only
after `begin_child_core_phase` has returned for the exact current prepared-task
seal. Its observation stays in the lexical managed-child clock until
`end_child_core_phase` has succeeded and Core is Closed; only then may the
`CHILD_SSIP` marker be printed. The start tick is sampled after the injected
interrupt, so acceptance work is not charged to the portable Core aggregate.
No active self-SSIP is forced in epochs 2--4.

The response and active-Drop paths retain the existing terminal authority and
order. They first cancel the parent, compare the exact rejection, acknowledge
it once, and prove `Ready(next_epoch)`. With `ACTIVE_EPOCH == 0`, the acceptance
state machine then forces exactly one inactive self-SSIP and confirms that the
slot status and active epoch did not change. Existing phase, Core, and request
terminals remain in their original order; the new terminal marker is printed
last and must precede the next request start. The cumulative observations at
the four terminals are respectively `(paired, inactive, active_epoch) =`
`(2, 1, 0)`, `(2, 2, 0)`, `(2, 3, 0)`, and `(2, 4, 0)`.

The source and live gates are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-irq-overlay.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-irq-overlay-test.sh
```

The frozen UART contract has exactly six
`WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY` lines: epoch-1 `PARENT_SSIP` and
`CHILD_SSIP`; normal `RESPONSE` terminals for epochs 1, 2, and 4; and the epoch-3
`DROP` terminal. Only epoch 1 reports `parent_pair=1 child_pair=1`; every later
epoch reports zero active pairs. All four terminals report one causal inactive
self-SSIP, `active_epoch=0`, exact cumulative counters, cancel/ack, and the next
ready epoch. The peer independently preserves the phase-sidecar's exact 27/28
markers, the managed-child/Core 19-marker transcript, and the request parent's
eight markers, including the delayed-stdin epoch and active-Drop reuse.

This closes only the parent/child SSIP composition gap on one QEMU hart. It is
not timer or PLIC coverage, target timing evidence, a physical Milk-V Duo
sample, a verified stream, schema publication, collection, or an AOT decision.
The parent continues to cancel; there is still no `finish` or publisher.

## Managed-child finish and independent verification closure

The default-off `wasm-c84-ssh-managed-child-finish-verify` successor retains
the authenticated request parent, real managed child, phase/Core accounting,
and IRQ-overlay topology while changing only successful response termination.
After child Cleanup, release, and exact Exited detach are proven, epochs 1, 2,
and 4 consume `RunLease::finish`. The slot closes the target, performs the
independent `TargetFinished::verify` rescan, and installs `TargetVerified` with
cursor zero. The kernel-private SSH adapter observes that typestate and then
explicitly calls `StreamLease::discard`; it does not call `summary`,
`next_interval`, or `complete` and does not let the storage-bearing lease escape.

The returned rejection must have cause `StreamAbandoned`, empty facade and
slot faults, no ledger error, and `intervals_emitted=0`. The adapter separately
compares the stored rejection, acknowledges it once, compares the acknowledged
report, and proves `Ready(next_epoch)`. A nonzero response status, unready child,
or stale policy is instead cancelled and recycled before finish. A target
finish/verify rejection is also acknowledged before returning the response
failure, preventing a global Rejected slot from being stranded.

Epoch 3 intentionally remains the existing active-Drop proof. The peer kills
the connection after the exact child Wait-open marker; the child is abandoned,
detaches as Exited, and the parent records `LeaseCancelled`, acknowledges it
once, proves `Ready(4)`, forces the terminal inactive SSIP, and admits epoch 4.
Thus Drop never creates a finished or verified stream.

The source and live gates are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-finish-verify-test.sh
```

The successor UART family has exactly four lines:
`WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY RESPONSE` for epochs 1, 2, and 4,
and `DROP` for epoch 3. Normal lines freeze `finish=1 verify=1 cursor=0`, exact
`discard=stream_abandoned emitted=0`, stored comparison, one acknowledgement,
and the next Ready epoch. The Drop line freezes `cancel=lease_cancelled`,
`finish=0 verify=0 stream=0`, zero emitted intervals, stored comparison, one
acknowledgement, and `ready_epoch=4`.

The four predecessor families retain their nonterminal bytes and epoch-3 DROP
field/order contracts. Successful counts remain frozen; the scheduler-dependent
phase/Core Drop observer count is parsed dynamically as a canonical positive
u64 and must match across both families. Their successful RESPONSE suffix truthfully changes from
`cancel=1` to
`finish=1 verify=1 discard=stream_abandoned ack=1`; terminal order is phase,
Core, request, IRQ, then finish/verify, and each last terminal precedes the next
request START. The predecessor image remains separately selectable and its IRQ
gate runs first in CI, preserving the exact cancel-only six IRQ, 27/28 phase,
19 Core, and eight request transcript.

This is diagnostic single-hart integration evidence only. Deliberately
abandoning a verified stream proves neither interval enumeration nor profile
content. This node adds no summary validation, schema, publisher, collector,
retained evidence, physical Milk-V Duo sample, or AOT decision.

## Managed-child verified-stream completion closure

The default-off `wasm-c84-ssh-managed-child-verified-stream` successor retains
the authenticated request parent, real managed child, phase/Core accounting,
IRQ topology, and independent finish/verify boundary. It changes only the
successful handling of the kernel-private `StreamLease`: instead of discarding
it at cursor zero, the SSH adapter reads the verified `Summary`, consumes every
indexed `Interval`, and calls `StreamLease::complete` only after validating the
complete schema-v1 phase partition. Neither `TargetVerified` nor the
storage-bearing stream authority leaves the adapter.

For successful epochs 1, 2, and 4, the adapter requires positive
`total_ticks`, exact `interval_capacity=65536`, `intervals_complete=true`, and a
dynamic `interval_count` in `1..=min(65536, total_ticks)`. The
`interval_count <= total_ticks` bound follows from positive interval lengths
and contiguous coverage. The seven summary phase totals must add without
overflow to `total_ticks`. Interval sequence numbers must be exactly
zero-based; every interval must be nonempty; starts must equal the preceding
end; adjacent phases must differ; checked per-phase accumulation must exactly
reproduce the summary; and the final end must equal `total_ticks`. Only after
`interval_count == emitted == cursor` and the next read returns `None` may the
lease be completed and the slot compared with `Ready(next_epoch)`. This is a
semantic contract, not a frozen control-flow count: it does not require all
seven phases to be nonzero, prescribe the first or last emitted phase, freeze a
phase sequence, or freeze the scheduler-dependent interval count.

A local summary or interval invariant failure detected before completion keeps
the lease in hand. That path explicitly discards it, requires the exact
same-epoch `StreamAbandoned` report with empty facade/slot faults, no ledger
error, and `intervals_emitted` equal to the current cursor, then compares the
stored rejection, acknowledges it once, and proves Ready reuse before returning
response failure. By contrast, `StreamLease::complete(self)` consumes the
handle. If it returns an error, the handle's Drop may attempt the abandonment;
the caller can only inspect and acknowledge an installed rejection for that
epoch and cannot call `discard` again. Poison, `OwnerNotCurrent`, or
`StateMismatch` without a confirmable rejection remains fail-closed; this node
does not promise recovery from those paths. The normal path proves full cursor
coverage before calling `complete` and never relies on Drop.

Epoch 3 remains the existing active-Drop proof. All five predecessor DROP bytes
and field contracts are unchanged, including the dynamically parsed equal
phase/Core observer count. The new family mirrors that terminal without
creating a verified lease:

```text
WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM DROP epoch=E cancel=lease_cancelled finish=0 verify=0 summary=0 stream=0 emitted=0 stored=1 ack=1 ready_epoch=R
```

The source and live gates are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-verified-stream-test.sh
```

In the successor image, the successful RESPONSE suffix of each of the five
predecessor families is exactly
`finish=1 verify=1 stream=complete ack=0 ready_epoch=...`. Those predecessor
markers do not repeat or freeze the interval count, and retain exact family
counts of 27/28 phase, 19 Core, eight request, six IRQ, and four finish/verify.
The new UART family has exactly four lines, with RESPONSE for epochs 1, 2, and
4 and DROP for epoch 3. Its successful line is:

```text
WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM RESPONSE epoch=E status=0 finish=1 verify=1 summary=1 initial_cursor=0 total_ticks=T interval_capacity=65536 interval_count=N intervals_complete=1 emitted=N cursor=N sequence=exact contiguous=1 nonempty=1 adjacent_distinct=1 phase_sum=total_ticks phase_rescan=summary final_end=total_ticks stream=complete stored=0 ack=0 ready_epoch=R
```

The peer accepts only a canonical positive-u64 `T`,
`1 <= N <= min(65536, T)`, `N == emitted == cursor`, and `R == E + 1`. The
`N <= T` bound is derived from positive-length contiguous coverage; it does not
freeze `T` or `N` as timing evidence. Normal and Drop terminal order is phase,
Core, request, IRQ, finish/verify, then verified-stream, and every last terminal
precedes the next request START. The separately built finish/verify predecessor
remains discard-only and runs first in CI.

This remains one-hart diagnostic integration evidence. The compact UART flags
are not JSON or a published schema record, and the gate emits no per-interval
evidence stream. It introduces no `ProfilePublisher`, `publish_profile`,
collector, retained sample, physical Milk-V Duo evidence, or AOT decision. A
later formal publisher must still accept the storage-bearing `TargetVerified`
authority, not copied `Summary`/`Interval` values or this success marker.

## Portable single-SAMPLE publisher foundation

The allocation-free `vibeos-wasm-aot-profile` crate now contains the narrow
formal publisher that the verified-stream node deliberately lacked.
`ProfilePublisher::publish_profile` consumes a storage-bearing
`TargetVerified` authority by value. Before its first sink call it independently
checks positive total ticks, the exact 65,536 interval capacity, completeness,
the dynamic `1 <= N <= min(65536, T)` bound, checked phase totals, exact
zero-based interval sequence, contiguous nonempty coverage, distinct adjacent
phases, a full checked phase rescan, the final endpoint, and the absence of an
interval after `N`. It computes the complete candidate rotate-and-add
accumulator during that same zero-write preflight.

The publisher then streams exactly one LF-terminated
`VIBE_WASM_AOT_SAMPLE` record using recursively ASCII-sorted object keys,
compact JSON separators, lowercase hexadecimal identities and digest, and
strict decimal u64 encoding. It uses fixed scratch storage and has no allocator
or serialization dependency. `RunId` and `Challenge` are separate branded
non-zero types. A public `TerminalObservation` must validate into private,
non-copyable eligible fields before publication; both the serializer and
accumulator consume the retained validated values. This validation establishes
schema eligibility only. It does not authenticate the caller or prove live
terminal provenance.

Preflight rejection makes zero sink calls and returns the same publisher,
original accumulator, and recycled target lineage. After the first sink call,
any write or commit error is treated as possibly partial: the target lineage is
still recycled, the original accumulator remains diagnostic-only, and the sink
is permanently held in `ManuallyDrop` with no recovery or republish surface.
The sink is quarantined before the first call, so unwinding cannot run a
destructor that flushes a partial record. The publisher itself writes the sole
line feed; `commit_record` is a commit/flush boundary and may not append bytes.

The known-answer record uses run-id bytes `00..1f`, challenge bytes `20..3f`,
sample index 3, phase durations 1 through 7, exact maximum-u64 poll quanta, and
prior accumulator `0x0123456789abcdef`. Its 1,392 bytes have SHA-256
`dc0aafe23554862c3941a06440ff404aebf19aaf2ce5358694625beb0bdf8955`
and derive accumulator `0x0ce24a87033663a1`. The independent gate validates
that golden against the frozen manifest/schema and attacks the Rust authority,
preflight, field source, ordering, poison, and accumulator paths:

```sh
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source
cargo test --locked -p vibeos-wasm-aot-profile
cargo check --locked -p vibeos-wasm-aot-profile \
  --target riscv64imac-unknown-none-elf
```

This node is deliberately not a collector. The raw prior accumulator and
successful sink can still be forked by a caller; no META or END is emitted; no
24-sample order, rollback protection, trusted checked-counter producer,
physical-Duo provenance, retained dataset, or AOT decision is claimed. In
particular, the exact-`u64::MAX` poll vector proves decimal and accumulator
handling only. A later live adapter must mint exactness from a private checked
counter and must reject the existing saturating profile value at its sentinel.

## Trusted live terminal and opaque-sample closure

The default-off `wasm-c84-ssh-managed-child-trusted-sample` feature is the
live-producer sibling of verified-stream. Both directly succeed
finish/verify, and they are mutually exclusive: verified-stream consumes the
cursor to completion, whereas the trusted producer must preserve the
storage-bearing `TargetVerified` while attaching live terminal evidence. The
base also selects SSHD's private `c84-profile-trusted-sample` seam. Its QEMU
acceptance pairs with the finish/verify predecessor, never with the separate
verified-stream transcript; Milk-V exposes only the UART-silent base seam.

SSHD constructs a linear `SshExecProfileTerminal` only after the exact managed
Component terminal agrees with lifecycle shutdown, pending Component stdout is
empty, and Component session shutdown has returned. It retains the seal inside
the live SSH request and transfers it to the kernel only at the later response
boundary, after peer channel-close acknowledgement and complete Sunset output
drain. The kernel requires the terminal enum itself to be `Success`, numeric
status zero, no timeout, zero stderr, and exactly 12,325 forwarded stdout bytes;
`ComponentTerminal::Returned(0)` is not an alias for success. The terminal
seal's constructor and fields remain private and the token is neither Clone nor
Copy.

SSHD coalesces arbitrary Sunset channel-data slices into exactly twelve
1,024-byte Component sends plus the 37-byte EOF tail. The trusted feature fixes
that staging limit even if the target-only native-revoke feature is also
present, so transport packetization cannot alter the formal input transcript.

The call-local dispatcher maintains a sticky-invalid checked audit of actual
host transfers. A read advances only after the exact prepared token commits a
`Received(length)` result; a write advances only on immediate `Sent` or the
final resumed `Sent`. Waiting, retries, EOF, and prepared-only work contribute
nothing. It verifies the frozen 12 full 1,024-byte chunks plus one 37-byte
chunk, the input formula, and every XOR-transformed output byte before binding
the frozen stdout SHA-256. Fuel is sampled from the still-live terminal call
before `drop(call)`. The private metrics validator rejects zero or over-budget
fuel, inconsistent remaining work, all five `SyncCallProfile` sentinels,
cross-counter mismatches, and empty or saturated poll quanta; exactness is
derived from those checked facts rather than a public boolean assertion.

After independent ledger verification, the slot validates the complete live
observation into `EligibleTerminalEvidence` and atomically removes the matching
cursor-zero `TargetVerified`. Both authorities are held in one kernel-private
`TrustedVerifiedSample` with private fields and an owner seal. It is non-copyable,
has no constructor or `into_parts`, and a raw-pointer marker makes it neither
`Send` nor `Sync`; the SSH platform cannot publish or separately retain either
half. This closes provenance only for the exact live route. The portable public
validator by itself continues to prove field eligibility, not origin.

Epochs 1, 2, and 4 form one opaque bundle and then intentionally discard it in
this foundation node. The discard must install `TrustedSampleAbandoned` with
empty facade/ledger/slot faults and zero emitted intervals; the adapter compares
that stored rejection, acknowledges it once, and proves `Ready(E + 1)`. Epoch 3
uses the unchanged active-Drop closure and must never form a bundle. The source
gate attacks status-only success, `Returned(0)`, public seals, counter placement
and saturation, after-drop metrics, profile deltas and sentinels, forged exact
flags, split authority, `into_parts`, Send/Sync widening, missing validation,
discard/ack bypasses, marker decoys, cfg pairing, and CI bypasses.

```sh
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-trusted-sample-test.sh
```

All five predecessor families preserve their marker formats and field
contracts, with the exact 27/28 phase, 19 Core, eight request, six IRQ, and four
finish/verify counts. The epoch-3 phase/Core observer count is parsed
dynamically and must agree across those two families; no byte identity with a
separate predecessor run is claimed. Each predecessor success RESPONSE ends in
`finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned ack=1
ready_epoch=...`. The trusted family follows finish/verify last and has exactly
three success records plus one Drop:

```text
WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE RESPONSE epoch=E status=0 exact_success=1 full_drain=1 read_chunks=13 write_chunks=13 stdout_bytes=12325 stdout_sha256=791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27 fuel_consumed=F poll_quanta=P poll_exact=1 logical_live_after=0 timed_out=0 bundle=trusted finish=1 verify=1 discard=trusted_sample_abandoned emitted=0 stored=1 ack=1 ready_epoch=R
WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE DROP epoch=E cancel=lease_cancelled bundle=0 finish=0 verify=0 discard=0 emitted=0 stored=1 ack=1 ready_epoch=R
```

The peer requires canonical decimal `1 <= F <= 500000`,
`1 <= P < u64::MAX`, and `R = E + 1`; it does not freeze scheduler-dependent
values. Each trusted `P` must equal the same epoch's dynamically parsed Core
`typed_polls`, and phase/Core counts must agree. Terminal order is phase, Core,
request, IRQ, finish/verify, then trusted-sample, before the next START. The
family is diagnostic log evidence, not serialized JSON. This node calls no
`ProfilePublisher`, emits no META/SAMPLE/END, stores no dataset, establishes no
24-sample collector chain, performs no physical Milk-V Duo capture or cold
boot, and makes no AOT decision.

## Private single-transcript collector closure

The default-off
`wasm-c84-ssh-managed-child-single-boot-collector` successor now consumes the
opaque trusted bundle inside the kernel profile slot. It never exposes the
verified target, terminal evidence, record factory, sample index, or prior
accumulator to the SSH adapter. A build-bound `Campaign` reads only the
compile-time `VIBEOS_C84_SOURCE_COMMIT` and `VIBEOS_C84_CHALLENGE`, validates
their canonical lowercase hexadecimal encodings, and derives the frozen
run-id with pinned no-std SHA-256. Kernel initialization commits META once and
then splits the portable `CollectorReady`: the storage-bearing `TargetReady`
returns to `SLOT`, while the opaque `BootCollector` remains in a second private
slot. Their only lock order is target slot then collector slot.

Each accepted target is bound to the exact task/allocation/epoch `OwnerSeal`.
After finish, independent ledger verification, live terminal validation, and
opaque-bundle creation, the adapter installs matching Publishing tombstones in
both slots. It then releases both locks, proves the exact owner is still
current, and disarms the detach callback before acquiring any record sink. The
portable collector supplies its own private checked sequence and accumulator;
the kernel cannot skip, repeat, roll back, or substitute either value. The
target Ready lineage is reinstalled after each SAMPLE commit, but the collector
simultaneously enters `PendingAcceptance` (or `PendingTerminal` after SAMPLE
23). Those states make every new prepare return Busy until the request adapter
has passed the remaining fallible tail gates.

One successful process or boot transcript commits exactly 26 records:

- one META;
- SAMPLE sequence/index 0 through 23, with 0 through 2 marked warmup and 3
  through 23 retained; and
- one END as the next wire record after SAMPLE 23, with no intervening record.

The collector retains only the 21 total-tick values needed for its transcript
guard. After SAMPLE 23 commits, it computes nearest-rank p50 at sorted index 10
and p95 at index 19. The default retained Duo-v1 contract accepts stability at
the checked `u128` boundary `p95 * 100 <= p50 * 150`; its portable known-answer
transcript is 34,386 bytes with SHA-256
`10df3a084b5817ee998c11e3eab0326fc2f16bdeba6644ce7e29e57c7bbc9da2`.
The disjoint `qemu-decision-v1` contract instead requires
`p95 * 100 <= p50 * 110`; its formal known-answer transcript is 34,532 bytes
with SHA-256
`ee94947964ea80cdbfd4df6abdcaac1bcfe65a6e397348e6728bddada64d3cdd`,
while the wire-distinct ineligible smoke transcript is 34,542 bytes with
SHA-256
`6f5dee3156f8950defd10e17a163a7919afbe90ec0249bfac17e74b498b33b69`.
After SAMPLE 23 and the selected stability guard pass, the portable collector
splits out `TargetReady` epoch 25 and the sole `PendingEnd` authority. The
kernel stores them as Ready plus `PendingTerminal`, so Ready25 exists for
ownership closure but cannot start. Only after every remaining fallible
request-tail gate succeeds does `collector_emit_success` enter
`FinalizingTerminal` and acquire, write, and commit END. Any abandonment or END
acquire/write/commit failure is absorbing, emits no later record, and never
retries; success moves the campaign to Complete, where Ready25 is retained only
for closed-rejection lineage. There is no public early-finish or 25th-sample
surface.

The platform-neutral formal UART sink acquires the console renderer and UART
transmitter only in TTY-to-TX order. It is used by both the retained physical
image and the disjoint fixed-QEMU decision image; provenance comes from the
surrounding platform and host-evidence contract, never from this sink. A
temporary non-Send record holds both guards over every
`write_all`, writes raw LF without CRLF translation, requires the record to
begin at column zero and contain one final LF, and releases TX then TTY only
after a successful commit observes the transmitter fully empty. A write,
framing, commit, or panic failure retains the guards through `ManuallyDrop` so
a partial formal record cannot be followed by ordinary UART output. The
persistent factory is Send but not Sync and stores no guard.

Every failure after META is absorbing. Registration, reservation, start,
owner, terminal, target, cancellation, sink, stability, state, and concurrent
attempt failures permanently move the campaign to Failed. The sole recycled
Ready remains in the target slot for ownership closure, but Failed and Closed
are checked before detach registration or target start. They admit no reset,
retry, second META, later SAMPLE, or END and do not consume another epoch.
SSHD accepts such a rejected exec request only to drain empty stdout, status
126, EOF, and CLOSE. Its rejection variant carries no command, Component,
profile permit, or execution path, so neither VSH nor the target can start.

The older diagnostic QEMU acceptance feature deliberately selects a different
absorbing audit sink. It runs the identical campaign, serializer, 24 SSH calls, and collector
state machine, but keeps only each committed record's byte count and SHA-256;
formal bytes are never buffered, recovered, or written to UART. Every audit
marker consumes a private post-commit token and ends with
`decision_eligible=0 formal_uart=0`. One boot commits META and then loses its
active epoch-1 target, proving an absorbing Failed state with one audit commit
and a pre-start rejection at Ready epoch 2. A fresh boot commits META, 24
SAMPLE records, and END, then rejects attempt 25 at Ready epoch 25. The runner
freezes two independent UART logs and OpenSSH fixtures, checks all predecessor
families and terminal order, and scans the complete raw logs for zero
occurrences of `VIBE_WASM_AOT_META`, `VIBE_WASM_AOT_SAMPLE`,
`VIBE_WASM_AOT_END`, or any formal schema payload. These legacy audit logs are
integration evidence only: they can enter neither the retained physical
dataset nor the new fixed-QEMU decision dataset.

The source, parser, and live gates are:

```sh
python3 -B scripts/verify-c84-ssh-managed-child-single-boot-collector.py \
  --selftest --check-source
python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py \
  --selftest
./scripts/qemu-c84-ssh-managed-child-single-boot-collector-test.sh
```

### Deferred physical build, package, and image verification

A formal collector image starts in an independently materialized and frozen
source tree with a fresh non-zero challenge. The full 40-hex preparation commit
must contain the four C8.4 preparation contracts and the complete checked-in
C8.3 evidence tree; an abbreviated, dirty, replacement-object, QEMU-sentinel,
or all-zero identity is ineligible. Cargo dependencies must already be cached
before the locked, offline build starts.

The materializer creates local bundles for the superproject and both exact
gitlinks, clones them into a random sibling staging directory without network
access, applies the one reviewed `jitterentropy-rs` patch, removes remotes and
ordinary refs, closes Git configuration and administration, proves no regular
file inode is shared with the operator source, freezes everything outside
`target/`, and publishes with a no-replace rename. Its canonical envelope is
recomputed at every later software boundary. The operator source remains only
an input to the materialization step. Both submodules must already be
initialized, clean, and at their fixed gitlinks; `frozen_parent` must be outside
the operator source tree:

```sh
set -eu
umask 077
operator_source=$(pwd -P)
prep=$(git rev-parse HEAD)
challenge=$(openssl rand -hex 32)
frozen_parent=/absolute/private/path/to/c84-frozen-sources
frozen="$frozen_parent/c84-$prep-$challenge"

cargo fetch --locked
mkdir -m 0700 "$frozen_parent"
python3 -B scripts/c84-source-materialization.py materialize \
  --source "$operator_source" \
  --destination "$frozen" \
  --source-commit "$prep" \
  --challenge "$challenge"

python3 -B "$frozen/scripts/c84-source-materialization.py" verify \
  --destination "$frozen" \
  --source-commit "$prep" \
  --challenge "$challenge" \
  --operator-source "$operator_source"

cd "$frozen"
artifact_root="$frozen/target/milkv-duo-wasm-aot-profile"
VIBEOS_C84_SOURCE_COMMIT="$prep" \
VIBEOS_C84_CHALLENGE="$challenge" \
  ./scripts/build-milkv-duo.sh --wasm-aot-profile
```

The build runs inside a sanitized `env -i` envelope with an isolated Cargo
home, pinned Rust tools, fixed `ld.lld`, commit-derived `SOURCE_DATE_EPOCH`, and
isolated objcopy. It publishes the ELF, raw kernel binary, and a
content-addressed `build-envelope.json` under
`target/milkv-duo-wasm-aot-profile` without replacing an existing campaign.

The full host verifier binds the materialization's exact device/inode sets.
Docker Desktop bind filesystems may legitimately remap those numbers, so the
two guests use the restricted `--container-mounted-read-only` verifier at the
fixed `/home/vibeos` path only after validating the attestation for the guest
that is currently running: `container-runtime-attestation.json` in `package`
mode for package preflight, and
`container-runtime-verifier-attestation.json` in `verify` mode for the
independent image verifier. The image audit and package provenance continue to
bind the package attestation, so every image gate also runs its complete
package-mode verifier; the normal independent pass therefore fully verifies
both distinct attestations. That guest pass repeats the byte, Git-admin, fsck,
permission,
single-link, file-count, and clone/clone-disjoint checks in its own inode
namespace; it retains rather than rewrites the host inode proof. The launcher
performs the full host verification before either container starts, and the
offline runtime/final evidence verifiers perform it again from the host path.

Packaging and image verification run as two distinct containers created by the
host custody launcher. The launcher requires the already-present pinned
Linux/amd64 image and the clean official Duo SDK at commit
`23eb84fecb29585dbb5728d6b7e2475ff273baac`; it never pulls and disables the
network. This example uses a pre-existing Docker volume. The launcher accepts
only the local driver and local scope with empty options and labels, then
requires `/home/work` to be that exact clean SDK Git root. The Docker caller
must have a non-root UID/GID, and Docker Desktop must permit a read-only bind of
the frozen absolute path:

```sh
sdk_volume=${C84_SDK_VOLUME:?name the existing pinned SDK volume}
python3 -B scripts/c84-docker-runtime.py launch-package \
  --source "$frozen" \
  --source-commit "$prep" \
  --challenge "$challenge" \
  --sdk-volume "$sdk_volume"

python3 -B scripts/c84-docker-runtime.py verify \
  --closure "$artifact_root/container-runtime-closure.json" \
  --source-commit "$prep" \
  --challenge "$challenge"
```

Before starting either container, the launcher records the host image inspect,
container configuration, mount source type, and read-only flags. Each guest
then records its own UID/GID, environment, mountinfo, route table, and network
interfaces before `exec`. The host records the exited state and proves the two
container IDs are distinct. The source and SDK mounts are read-only; only the
nested source `target/` mount is writable. Packaging reconstructs FIT and
full-card images and publishes the package envelope and its runtime
attestation. The second container independently verifies the image. Only after
both exits pass does the host publish `container-runtime-closure.json`; its
offline verifier rereads all bound artifacts and records.

This is host-observed local Docker software custody, not a TPM measurement,
remote attestation, hardware identity, board boot, or physical cold-boot proof.
The independent image verifier still parses the MBR directly, extracts the FAT
boot partition, FIP, FIT kernel and DTB payloads, checks raw-data geometry and
seed/zero regions, and compares those bytes with the selected artifact root and
pinned SDK.

Every challenge is single-attempt. If build, package, image verification, or
runtime closure fails after publishing any no-clobber output, retain that tree
for diagnosis and restart from a new challenge and new materialization; never
delete outputs and retry the same campaign identity. Superproject ignored
caches are excluded from the local bundle, but either submodule must contain no
ignored or untracked files in addition to being at its fixed clean gitlink.

CI does not package an SDK image or contact a board. Its software-only gate is:

```sh
bash -n scripts/build-milkv-duo.sh
bash -n scripts/package-milkv-duo-sdk.sh
bash -n scripts/verify-milkv-duo-image.sh
python3 -B scripts/c84-source-materialization.py --selftest --check-source
python3 -B scripts/c84-docker-runtime.py --selftest
./scripts/verify-milkv-duo-image.sh --selftest
python3 -B scripts/capture-c84-duo-aot-decision.py --selftest
python3 -B scripts/verify-c84-evidence.py --selftest
```

These self-tests use local synthetic repositories, records, streams, and
temporary files. They never open a UART; the commands also require no SDK,
Docker, network, flash, reset, or physical cold boot and produce no
decision-eligible evidence.

### Deferred physical capture and final evidence publication

Physical execution is intentionally paused at operator request. The following
commands document the frozen resumption procedure; they are not a report that
the procedure has run. First create an evidence root outside the frozen source
tree and copy the exact committed preparation files into it. The capture
program will publish its `duo` child atomically and no-clobber:

```sh
set -eu
umask 077
evidence_root=/absolute/path/to/c84-evidence
test ! -e "$evidence_root"
mkdir -m 0700 "$evidence_root"
cp benchmarks/wasm-aot-decision/README.md "$evidence_root/"
cp benchmarks/wasm-aot-decision/schema-v1.json "$evidence_root/"
cp benchmarks/wasm-aot-decision/workloads-v1.json "$evidence_root/"
cp benchmarks/wasm-aot-decision/evidence-schema-v2.json "$evidence_root/"

c83_source=${C83_SOURCE_COMMIT:?set the full 40-hex C8.3 source commit}
c83_challenge=${C83_CHALLENGE:?set the 64-hex C8.3 challenge}
c83_root="$frozen/benchmarks/wasm-runtime"
duo_uart=${DUO_UART:?set the explicit absolute Duo UART path}

python3 -B scripts/capture-c84-duo-aot-decision.py \
  --port "$duo_uart" \
  --output-dir "$evidence_root/duo" \
  --source-commit "$prep" \
  --challenge "$challenge" \
  --expect-c83-source "$c83_source" \
  --expect-c83-challenge "$c83_challenge" \
  --c83-evidence-root "$c83_root" \
  --kernel "$artifact_root/vibeos-milkv-duo.bin" \
  --fit "$artifact_root/boot.sd" \
  --image "$artifact_root/vibeos-milkv-duo-wasm-aot-profile-sd.img" \
  --package-envelope "$artifact_root/package-envelope.json"
```

The collector requires an explicit absolute character-device path, refuses any
requested or resolved `usbmodem` monitor/control path, opens the UART read-only,
and has no flash, reset, auto-discovery, or serial-write operation. It requires
the operator to perform and acknowledge `COLD BOOT 1`, `COLD BOOT 2`, and
`COLD BOOT 3`; each raw is closed by the independent single-boot verifier
before the next boot can begin. The published `duo` tree also takes exact
custody of the source-materialization envelope, package and verifier runtime
attestations, runtime closure, build envelope, package envelope, and package
image-verifier audit. The capture envelope embeds the complete source and
runtime provenance roots rather than accepting filenames alone.

Only after that capture exists may the final verifier revalidate the exact
frozen source envelope and offline runtime closure, prove the C8.3 tree
byte-for-byte against the preparation commit, and rerun that source's complete
C8.3 evidence verifier. It then independently rechecks the package closure and
all three raw transcripts, pools exactly 63 retained samples, and computes
nearest-rank p50 at sorted index 31 and p95 at index 59. Non-interpretation time
is computed per sample as `N = T - I` before sorting; it is never percentile
subtraction. First publication and subsequent no-write verification are:

Both final-verifier invocations run from the original frozen source path. They
invoke that source's materialization verifier first, invoke the runtime
closure's offline verifier, and bind the captured copies to the still-live
artifact tree. They do not launch another container or require a live SDK; the
two host-observed package/image-verifier containers are already closed by the
runtime record. First publication writes only `DECISION.json`; the second call
performs the same reconstruction without a write request:

```sh
python3 -B "$frozen/scripts/verify-c84-evidence.py" \
  --source-root "$frozen" \
  --evidence-root "$evidence_root" \
  --c83-evidence-root "$c83_root" \
  --artifact-root "$artifact_root" \
  --expect-c84-source "$prep" \
  --expect-c84-challenge "$challenge" \
  --expect-c83-source "$c83_source" \
  --expect-c83-challenge "$c83_challenge" \
  --write-decision

python3 -B "$frozen/scripts/verify-c84-evidence.py" \
  --source-root "$frozen" \
  --evidence-root "$evidence_root" \
  --c83-evidence-root "$c83_root" \
  --artifact-root "$artifact_root" \
  --expect-c84-source "$prep" \
  --expect-c84-challenge "$challenge" \
  --expect-c83-source "$c83_source" \
  --expect-c83-challenge "$c83_challenge"
```

`DECISION.json` is no-clobber. A malformed or incomplete C8.3/C8.4 input
prevents its creation; failure is never relabelled `aot-not-justified`. A
passing dual-threshold result may say only
`aot-eligible-for-c85-design-review`. Every outcome keeps
`aot_authorized=false` and `native_code_accepted=false`.

## Deferred physical-Duo decision rule

Let `T` be each retained sample's `total_ticks`, `I` its `interpretation`
ticks, and `B = 2_500_000`. A dataset is eligible only after C8.3 is complete
and every identity, completeness, correctness, phase-partition, cold-boot, and
stability gate in the manifest passes.

AOT becomes only a candidate for the C8.5 design review when both conditions
hold:

1. `p95(T) > B`; and
2. `p95(T - I) <= B`.

The second condition is the frozen counterfactual attribution test: removing
only interpretation must eliminate the miss. If the budget is met, or if the
non-interpretation path still misses it, AOT is not justified. Even a candidate
result does not admit external native bytes, add a JIT/RWX path, or bypass the
authoritative component, profile, WIT, CSpace, and admission policy. Those
remain separate C8.5--C8.7 work.

## Retained physical-toolchain preparation verification

```sh
cargo test --locked -p vibeos-image-policy --no-default-features \
  --features milkv-duo-sd --test stream_pin \
  frozen_case_filter_profile_preflight_proves_interval_capacity -- --exact
python3 -B scripts/verify-c84-profile-publisher.py --selftest --check-source
python3 -B scripts/verify-c84-ssh-profile-request-parent.py --selftest --check-source
./scripts/qemu-c84-ssh-request-parent-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-core.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-core-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-phase-sidecar.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-phase-sidecar-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-irq-overlay.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-irq-overlay-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-finish-verify.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-finish-verify-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-verified-stream.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-verified-stream-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-trusted-sample-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-single-boot-collector.py --selftest --check-source
python3 -B scripts/c84-ssh-managed-child-single-boot-collector-peer.py --selftest
./scripts/qemu-c84-ssh-managed-child-single-boot-collector-test.sh
bash -n scripts/build-milkv-duo.sh scripts/package-milkv-duo-sdk.sh \
  scripts/verify-milkv-duo-image.sh
./scripts/verify-milkv-duo-image.sh --selftest
python3 -B scripts/capture-c84-duo-aot-decision.py --selftest
python3 -B scripts/verify-c84-evidence.py --selftest
```

The capture-time physical transcript verifier is source-bound to `e950a2f`.
Its reviewed bytes and historical policy inputs are checked by the current
fixed-QEMU publication auditor above; it is retained for historical inspection
and future separately authorized qualification, not run against later live
policy files and not required by the C8.4 gate.

These checks validate the retained physical preparation contract, portable
single-SAMPLE ownership/serialization, trusted producer, private single-boot collector, and
single-hart QEMU integration transcript semantics, plus the software-side
package/capture/evidence failure boundaries. They cannot manufacture physical
C8.3 or C8.4 evidence; those optional legacy datasets remain absent and do not
block the fixed-QEMU C8.4 path. The paused hardware commands above remain
deliberately unexecuted.
