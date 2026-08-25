# C8.4 AOT decision preparation contract

This document freezes the workload, measurement boundary, physical budget, and
decision rule for C8.4. It is **preparation only**: no C8.4 result has been
collected, C8.3 is still incomplete until its three physical-Duo cold boots are
published, and this contract does not authorize AOT or native component bytes.

The machine-readable contract is
[`benchmarks/wasm-aot-decision/workloads-v1.json`](../benchmarks/wasm-aot-decision/workloads-v1.json).

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

## Physical platform, sampling, and budget

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

Fixed-QEMU measurements may test instrumentation and integration. QEMU ticks
must not be converted, combined with Duo ticks, or used to meet or miss this
budget.

Only complete success samples enter the formal dataset: each records 13 reads,
13 writes, fuel, poll quanta, terminal `success`, zero logical live state after
cleanup, `timed_out = false`, timeout phase `none`, and a complete interval
transcript with capacity 65,536 and an exact declared count. A timeout, trap,
failed status, truncated stream or interval ledger, wrong output, leak, or
interval overflow is diagnostic evidence outside the decision population and
can never authorize AOT.

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

Before any C8.4 evidence was produced, a dev-only `c84-profile-hooks`
preflight ran the exact frozen artifact and 12,325-byte input through the
buffered product work model. It locked these complete-call counts:

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

## Decision rule

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

## Preparation verification

```sh
cargo test --locked -p vibeos-image-policy --no-default-features \
  --features milkv-duo-sd --test stream_pin \
  frozen_case_filter_profile_preflight_proves_interval_capacity -- --exact
python3 -B scripts/verify-c84-aot-decision.py --selftest --check-manifest
```

This check validates the preparation contract only; it cannot manufacture the
missing physical C8.3 or C8.4 evidence.
