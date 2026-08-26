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
13 writes, fuel consumption in the inclusive range 1 through 500,000, positive
poll quanta, terminal `success`, zero logical live state after cleanup,
`timed_out = false`, timeout phase `none`, and a complete interval transcript
with capacity 65,536 and an exact declared count. A timeout, trap, failed
status, truncated stream or interval ledger, wrong output, leak, or interval
overflow is diagnostic evidence outside the decision population and can never
authorize AOT.

## Single-cold-boot transcript closure

Each cold boot has its own raw serial transcript, capped at 268,435,456 bytes.
One raw contains exactly one `VIBE_WASM_AOT_META` record, 24 ordered
`VIBE_WASM_AOT_SAMPLE` records with sequence and sample index 0 through 23,
and one `VIBE_WASM_AOT_END` record. Samples 0 through 2 are warmups and samples
3 through 23 are retained. Target records deliberately contain no boot index:
only host evidence assigns indexes 0 through 2 after each raw has passed
independent verification. A later evidence verifier must prove all three
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

The standalone gate preserves its original exact 19-marker managed-child/Core
transcript. Successful epochs 1, 2, and 4 each freeze exactly 1,167 real Core
polls, 1,167 observer pairs, and 1,241 typed polls. Those are control-flow
counts from the isolated QEMU image, not target timing or formal profile
evidence; they do not replace the distinct frozen preparation preflight.
Epoch 3 is killed after its first ordinary Core pair. Its real executor
callback reports `Exited` after 29 closed observer pairs, while the missing
successful-driver bit keeps release false and produces exact
`CHILD_ABANDONED + CHILD_DETACHED` faults.
The parent still cancels and acknowledges the epoch, an immediate readiness
probe succeeds, and epoch 4 proves post-Drop reuse.

This closes the previously explicit gap between the real managed child and the
ordinary Core observer for the exact SSH target. The reusable base feature is
default-off; QEMU acceptance contributes only guarded transition telemetry and
is integration evidence. There is still no Host/Wait/Cleanup sidecar, IRQ
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
the exact abandoned/detached faults. Normal epochs require ordered Validation
-> Instantiation -> ABI -> Cleanup, paired child Host/Core/Wait edges, paired
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
compile-time seam. The separate QEMU acceptance feature retains the phase,
Core, and request predecessor telemetry and adds one narrow causal self-SSIP
state machine; it does not enable the standalone profile-IRQ acceptance image.

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
python3 -B scripts/verify-c84-ssh-profile-request-parent.py --selftest --check-source
./scripts/qemu-c84-ssh-request-parent-test.sh
python3 -B scripts/verify-c84-ssh-managed-child-core.py --selftest --check-source
./scripts/qemu-c84-ssh-managed-child-core-test.sh
```

These checks validate the preparation contract, diagnostic ownership, and
single-hart QEMU integration transcript semantics only; they cannot manufacture
the missing physical C8.3 or C8.4 evidence.
