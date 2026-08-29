# C8.4 AOT-decision contracts

`workloads-qemu-v1.json`, `schema-qemu-v1.json`, and
`evidence-schema-qemu-v1.json` are the authoritative
decision-bearing C8.4 contract. They freeze one fresh
`qemu-virt-rv64-tcg-icount-v1` process, 3 warmups plus 21 retained samples, a
10 MHz `riscv.rdtime` clock, a pre-frozen 1,000,000-tick/100 ms budget, and a
retained `p95/p50 <= 1.10` stability gate. The evidence is emulator-scoped and
must say `physical_provenance=not-claimed`.

`workloads-v1.json` retains the one product workload and physical-Duo budget,
seven-phase attribution ledger, and fail-closed decision rule. `schema-v1.json`
defines the records for exactly one future physical cold-boot transcript, and
`evidence-schema-v2.json` closes the three-boot capture and final decision
envelopes, including the independently materialized source and host-observed
container-runtime custody roots. A raw transcript contains one metadata record,
24 samples, and one end record; the host, not the target, later assigns its
boot index.

These contract files contain no result and do not authorize AOT. The published
formal result is in [`qemu-v1/`](qemu-v1/). It binds source commit
`e950a2facb6a6c230e67becb186bddf34a5924bb` and run ID
`a22f28ef7aab11de5c4858e9a4e4c5b5b4e6e763c43a126ad84d4ac80b9f500f`.
Total p50/p95 are 2,899,765/2,901,632 ticks, interpretation p50/p95 are
97,260/97,318, and per-sample-derived non-interpretation p50/p95 are
2,802,541/2,804,417. Stability passed; `budget_miss=true` but
`interpretation_attribution=false`, so the outcome is
`aot-not-justified-on-fixed-qemu` and the next node is
`C8.8-skip-or-defer-C8.5-C8.7`. It records `platform_class=emulator`,
`physical_provenance=not-claimed`, `aot_authorized=false`, and
`native_code_accepted=false`.

C1 through C8.3 are accepted complete by historical-evidence policy. C8.4 is
complete for the selected workload; C8.5 through C8.7 were not entered for it
and remain globally deferred. The retained Duo-v1 tooling is non-blocking and
physical execution stays paused. See
[`docs/WASM_AOT_DECISION.md`](../../docs/WASM_AOT_DECISION.md).

The neutral machine contract is
[`qemu-v1-publication-integrity-contract.json`](qemu-v1-publication-integrity-contract.json).
The current QEMU-v1 publication-integrity gates are:

```sh
python3 -B scripts/verify-c84-qemu-published-evidence.py --check-published
python3 -O -B scripts/verify-c84-qemu-published-evidence.py --check-published
python3 -B scripts/verify-c84-qemu-published-evidence.py --selftest
python3 -O -B scripts/verify-c84-qemu-published-evidence.py --selftest
python3 -B scripts/c84-qemu-aot-decision-peer.py --selftest
./scripts/run-c84-qemu-aot-decision.sh --selftest
```

The first four commands bind the exact published files to publication commit
`cbb1d0f`, bind the recorded source and capture-time verifier bytes to source
commit `e950a2f`, and recheck the stored emulator-only/no-AOT decision. They are
historical structure/hash checks only: they do not boot QEMU, replay the
publisher or its host custody, or claim physical provenance. The capture-time
verifiers remain frozen at `e950a2f`; later policy additions are not substituted
for those historical source members.

The published formal clean-tree campaign used
`./scripts/run-c84-qemu-aot-decision.sh --evidence-dir benchmarks/wasm-aot-decision/qemu-v1`.
It created `uart.log`, `summary.json`, `environment.json`, and `DECISION.json`
with strict no-clobber semantics. Formal publication requires a clean
`codex/wasm` branch whose local and tracking refs equal the bound source commit,
whose index contains no assume-unchanged, skip-worktree, or fsmonitor-valid
entries, and whose fixed GitHub remote directly advertises that commit. The
formal build inventories the exact commit plus both exact gitlinks, then
exports their already-verified blobs as raw `git cat-file --batch` bytes. It
recomputes every blob OID and never invokes checkout or clean/smudge filters.
All Git commands set `GIT_NO_LAZY_FETCH=1`, disable replacement objects and
system/global configuration, and use a fixed PATH. The superproject and both
submodule local configs are byte-identified and parsed with `--no-includes`
through a default-deny safe-key/value allowlist, so filter drivers, URL rewrite
rules, includes, and other unreviewed keys fail closed. The fixed-remote query
runs from `/` with `/.git` absent. The build uses a fresh private Cargo target
and runs byte-identical private custody copies of the pinned QEMU 11.0.3
binary, pinned OpenSBI image, and private kernel.
Its project `Cargo.lock` (189 registry packages) and pinned rust-src
`library/Cargo.lock` (30) are jointly audited into a conflict-free 213-package
union. Project packages are copied from the launcher-fixed cache only after
checksum verification; the 24 rust-src-only packages come from the pinned
rust-src vendor tree after independent checksum-inventory and safe-tree
validation. The resulting read-only private directory source is inventoried
before and after Cargo. Cargo runs from `/`
with an absolute manifest and a private `CARGO_HOME` containing exactly the
materialized firmware config plus that source replacement; `/tmp/.cargo` and
other source-ancestor configs are therefore outside discovery. The complete
nightly toolchain tree, rust-src subtree, and recursive non-system `ld.lld`
Mach-O closure are manifest-pinned and independently re-inventoried pre/post.
The build PATH is exactly `/opt/homebrew/bin:/usr/bin:/bin`; `cargo`, `rustc`,
and `rustdoc` must reside under the pinned toolchain root, and
`SOURCE_DATE_EPOCH` must equal the attested commit timestamp. The private crate
archive path is canonical, direct, and separately bound from the extracted
crate-source tree. Cargo's cache last-use clock, cache-GC policy, and child
umask are fixed, making its required `.global-cache`, two empty package locks,
and cache-directory tag deterministic. The exact fresh output set is recorded,
validated, removed, and fsynced before the private home is re-attested as
config-only; unknown entries fail closed. The firmware search, QEMU version probe, and live process
share one manifest-frozen,
deny-by-default environment: exact `PATH`, `LANG`, `LC_ALL`, and `TZ` values
plus private campaign-local `HOME`, `TMPDIR`, and `XDG_CONFIG_HOME`. No ambient
`DYLD_*`, `QEMU_*`, locale, or user-config variable is inherited, and the
normalized allowlist and values are recorded in `environment.json`.

The runner creates one immutable actual QEMU argv and passes that same value to
the only process launch and the evidence writer. The verifier independently
validates and normalizes its custody paths and unique host-forward port before
comparing it with the frozen argv. Source and execution-custody QEMU binaries
each have identical pre/post/final recursive non-system Mach-O closures;
non-system edges must resolve inside the Homebrew Cellar, while system edges
are restricted to `/System/Library/` and `/usr/lib/` and bind the sealed APFS
root plus macOS 26.5.2/build `25F84`/Darwin `25.5.0`. Plugin argv and
`QEMU_MODULE_DIR` are absent, as are the frozen QEMU module-search directories.
The accepted limit is explicit: same-UID host exclusivity is required because
identity snapshots cannot exclude a live swap-and-restore, and generic
library-internal `dlopen` is not claimed beyond the recursive load-command
graph.

The formal peer sends exactly 24 sequential `case-filter` requests. Other SSH
exec commands are not covered by a collector-wide admission gate, so the
decision also requires the recorded exclusive QEMU/SSH host envelope: no
same-UID process may inject a concurrent loopback SSH request or swap a
snapshotted input. This emulator-scoped result can open design review only and
cannot authorize AOT or native execution.

The launcher additionally pins CPython 3.14.6 and `-I -B -S`, keeps the
pycache sink absent under `/var/empty`, hashes the reachable stdlib and
lib-dynload tree, and binds the Framework, Python.app executable,
`_hashlib`/libcrypto, `_lzma`/liblzma, `_zstd`/libzstd, and xz/zstd symlink
chains. Its exact environment includes `OPENSSL_CONF=/dev/null` and
`OPENSSL_MODULES=/var/empty`; the null device, empty provider directory, and a
SHA-256 known-answer test are checked.
Nested maintained Python helpers are compiled from stable UTF-8 source bytes;
the live and frozen peers report those executed hashes for exact comparison
with the helper identities, so ignored `.pyc` files cannot enter the decision.
OpenSSH is never copied: the runner names only `/usr/bin/ssh`, pins its exact
version/hash/length, and executes it in place after attesting root ownership,
mode/link count, `SF_RESTRICTED`, same-device placement, and a sealed read-only
APFS root on Darwin. The independent verifier repeats the source, remote, clock,
both custody forms, and complete Python helper-chain checks. OpenSSH is never
resolved through `PATH`. `--allow-dirty-smoke` instead selects a
build-time smoke marker with an ineligible META value and a disjoint run-ID
domain. Its Cargo provenance is `<dirty-worktree>/firmware/qemu-virt/Cargo.toml`,
never `<materialized-source>`, and it still requires the fixed configured
origin even though it omits the formal remote-advertisement query. It uses a
fresh private target and the same custody policy, but cannot be promoted into
formal evidence. Finally, either parser rejects any matching
`WASM_[A-Z0-9_]+ FAIL` occurrence, including an unknown future failure marker,
before accepting the finite expected marker set.

## Retained/deferred physical-Duo toolchain

The retained physical single-boot verifier semantically closes one raw
transcript and derives one deterministic boot summary. It checks the cross-field
`interval_count == len(intervals)` relation which JSON Schema cannot express,
the complete gap-free phase partition, ordered 64-bit accumulator, exact sample
coordinates, output and fuel/poll bounds, and per-boot stability. Timeout,
trap, failure, truncation, wrong-output, and leak attempts are diagnostic and
cannot enter the decision population or authorize AOT.

The retained physical software-side chain includes an independently cloned and frozen source
tree, content-addressed build and package envelopes, host-observed Docker
runtime custody, an independent full-SD-image verifier, a read-only
three-cold-boot UART collector, and a final evidence verifier. The final
verifier starts by revalidating the frozen source envelope and the offline
runtime closure, proves the complete checked-in C8.3 evidence tree
byte-for-byte against that source, reruns its verifier, and only then pools the
63 retained C8.4 samples. It computes nearest-rank p50/p95 after sorting the 63
values and computes non-interpretation time per sample as `N = T - I` before
sorting. Neither a failed precondition nor malformed evidence is converted
into a negative AOT decision.

Host verification binds exact source/admin inodes. Because Docker Desktop may
remap inode numbers across a bind mount, the attested read-only guest verifier
retains that host proof and independently rechecks bytes, Git closure,
permissions, single links, file counts, and clone/clone disjointness in the
container namespace. Package preflight and the independent image verifier each
validate their own mode-specific runtime attestation before that check; the
independent verifier also completely validates the package attestation that
its image report continues to bind. The final offline verifier repeats the
full host check.

The retained physical single-boot verifier alone still does not attest physical provenance or a
power cycle, aggregate three boots, prove the C8.3 precondition, or produce an
AOT decision. Its raw input is a stable non-empty regular file capped at
268,435,456 bytes; derived summary creation is no-clobber unless `--overwrite`
is supplied explicitly.

Historical C8.4 decision status (published 2026-08-28): C1 through C8.2 remain
accepted complete by historical-evidence policy; none is reopened, rerun, or
individually rewalked. The fixed-QEMU formal
result completes C8.4 for the selected workload with outcome
`aot-not-justified-on-fixed-qemu`; C8.5 through C8.7 are skipped for that
workload and remain globally deferred. The stored next-node value remains
`C8.8-skip-or-defer-C8.5-C8.7`; the C8.11 closure position was
`c811-s3-qualified-sealed-simd-runtime-released`, while the live position is
`c813-e2-reference-executable-implemented-pre-qemu`, neither of which rewrites this
historical decision.
Milk-V Duo physical testing is paused and the retained physical toolchain
remains available for future qualification. Its runtime evidence is software
custody from the local Docker daemon plus an in-container namespace witness;
it is not a TPM, remote-attestation, hardware, or physical-cold-boot proof.

The immutable historical C8.4 `next_node` value is
`C8.8-skip-or-defer-C8.5-C8.7`; it is not the repository's current position.
The C8.9 closure position is `c89-s3-qualified-sealed-float-runtime-released`.
C8.9-S1 through C8.9-S3 allocate, implement, and qualify the independent code 6
Float successor. Its fixed-QEMU release authority is limited to sealed,
authority-free Float admission; code 5 remains permanently inert and Milk-V Duo
observations remain optional and non-gating.
The current roadmap position is
`c813-e2-reference-executable-implemented-pre-qemu`;
C8.11-S3 released the sealed SIMD successor and C8.12-R2 implements only a
Reference Types validation candidate. Neither authorizes AOT.

These CI-safe commands do not open a UART, invoke Docker, access the network,
flash media, reset a board, or require an SDK:

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

The separate non-numbered fixed-QEMU target/release policy is prospective. It
does not broaden C8.4, alter its stored next-node value, or allow this evidence
bundle to satisfy a future node's fresh source-bound campaign.

The deferred Duo-v1 physical build/package/image/capture/publication commands
are documented in
[`docs/WASM_AOT_DECISION.md`](../../docs/WASM_AOT_DECISION.md). In particular,
the capture command accepts only an explicitly named read-only UART, refuses
`usbmodem` monitor/control paths, performs no serial writes, reset,
auto-discovery, or flash, and requires an interactive `COLD BOOT N`
acknowledgement for each of three boots. Those commands are intentionally not
being run while physical testing is paused.

During preparation, before any decision-bearing capture may be produced, the
exact frozen workload's portable profile preflight proved that the former
4,096-interval limit could not hold
even the managed runner's 4,918-interval minimum. The corrected engineering
capacity is 65,536 intervals. Every formal sample self-describes that capacity,
reports `interval_count == len(intervals)`, and sets `intervals_complete` true.
The target collector must keep only one active sample in packed storage;
overflow or truncation remains diagnostic-only and fails closed. This
feasibility fix does not change the Duo-v1 workload, budget, sampling, or
decision rule, and 65,536 is not claimed as a mathematical worst-case bound.

The verifier also parses the kernel's real stream dispatcher instead of
trusting a copied test constant: declarations, `required_work`, and every
ready/commit response must charge `MAX_STREAM_CHUNK_BYTES + 4` for read,
`4 + bytes` for write, and `1` for close, using the same component-host
1,024-byte maximum as the fixture. Before extracting those scopes, the verifier
pins the reviewed byte identity of all of `kernel/src/component_instances.rs`,
including attribute literal values; module binding, `cfg` feature selection,
alias, dead-code, and macro drift therefore fail closed. It separately strips
comments and literals before balanced extraction and pins the seven reviewed
dispatcher method scopes for localized review, so decoy text cannot satisfy
the semantic checks.

```sh
cargo test --locked -p vibeos-image-policy --no-default-features \
  --features milkv-duo-sd --test stream_pin \
  frozen_case_filter_profile_preflight_proves_interval_capacity -- --exact
```

The capture-time physical verifier is source-bound to `e950a2f` and remains a
retained historical member, not a current-tree gate. Its reviewed bytes and
the two policy source members it inspected are covered by the fixed-QEMU
publication-integrity auditor above. No retained physical command is required
to complete or preserve C8.4.
