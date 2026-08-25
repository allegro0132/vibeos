# WebAssembly runtime costs (C8.3)

This document defines the reproducible collection and publication contract for
C8.3 of the [Component Model roadmap](WASM_ROADMAP.md). The target-side harness,
closed manifest/schema, independent verifier, and dedicated QEMU/Duo images are
the preparation stage. **C8.3 is not complete until results from one fixed QEMU
boot and three real, cold Milk-V Duo boots are checked in and independently
verified against the same clean preparation commit.** A host model, a dirty
QEMU smoke run, or an old Duo image is never physical evidence.

## Measured surface

The workload identity is
`benchmarks/wasm-runtime/workloads-v1.json`. Its exact bytes, the transcript
schema, the source commit, a fresh challenge, and all three compiled Wasm
fixtures are bound into the target `run_id`. Changing any of them requires an
explicit reviewed identity update; an ordinary test cannot rewrite a baseline.

| Category | Workload | Timed operations per sample | Scope |
|---|---|---:|---|
| validation | accepted rich Component decode/validation/plan | 4 | executable synchronous Profile 1 |
| startup | cold Component instantiation | 4 | includes a fresh engine and embedded Core validation/compilation |
| lift/lower | 256-byte string plus 64-element `u32` list round trip | 256 | synchronous Canonical ABI |
| async | wait registration, pending resume, and exact cancellation cleanup | 1,024 | native-async state primitive, not guest async throughput |
| composition | eight-node, seven-edge graph plan | 256 | validation-only over an already-decoded `ComponentPlan`; decode bytes and byte throughput are excluded; `runtime_ready` stays false |
| host call | suspended Core host call and resume | 256 | executable Core Profile 1 |
| memory | allocate and hold sixteen 64 KiB linear memories | 16 | reports the exact scoped allocator live-heap peak and teardown return |
| fuel | deterministic 32,768-iteration integer loop | 32,768 | exact consumed fuel and poll quanta |
| cancellation | task cancellation to terminal cleanup | 2,048 | native-async state primitive |
| revocation | depth-eight capability revoke to stale-token denial | 512 | exact CSpace operation |

The target emits raw integer `rdtime` observations only: one
`VIBE_WASM_COST_META`, the exact ordered sample matrix, and one
`VIBE_WASM_COST_END`. The host verifier rejects missing, duplicate, reordered,
extra, malformed, unbound, leaking, non-deterministic, or truncated records and
derives every statistic from retained samples. Warmups are retained in the raw
log but excluded from summaries. Percentiles use nearest rank and means use an
unbounded integer sum followed by floor division.

Every workload sample owns an exclusive, resettable allocator window. The
allocator records the exact maximum live-byte gauge on every successful
allocation, including allocations freed before the next snapshot, then closes
the window only after workload cleanup. This global window is attributable to
the workload because the dedicated C8.3 image runs one hart and disables
background services. `heap_peak_delta_bytes` is that scoped peak minus the
sample baseline; it is not the kernel-lifetime heap high-water mark.

The async and composition numbers deliberately describe the implemented
validation-candidate primitives. They are not claims of production guest-async
or cross-component execution. Adapted Preview1 artifacts remain validation-only
and are excluded from runtime throughput.

## Fixed platforms and publication gates

| Platform | Fixed contract | Fresh boots |
|---|---|---:|
| QEMU | `virt`, `rv64`, one hart, 128 MiB, `tcg,thread=single`, `icount shift=0,align=off,sleep=off`, explicit OpenSBI `fw_dynamic` BIOS, 10 MHz guest timebase; exact QEMU/BIOS bytes, version, and arguments recorded in the envelope | 1 |
| Milk-V Duo | CV1800B/C906B, hart 0 only, 60 MiB VibeOS RAM, 25 MHz `rdtime`, UART 115200 8N1, SDK commit fixed by the manifest, and the exact operator-declared SDK container digest recorded in the package envelope | 3 separate cold boots |

Every timed batch must span at least 1 ms of its platform clock. Each retained
distribution must have `p95/p50 <= 1.10` on fixed QEMU and `<= 1.50` on Duo.
Every sample must return live heap to its pre-sample value and logical live state
to zero. Host-call and fuel counts must be deterministic. These are publication
completeness/stability gates, not product performance budgets. C8.3 freezes
observations; C8.4 must name a product workload and frozen budget before it can
justify AOT.

QEMU `icount` ticks and physical 25 MHz ticks are published in separate columns.
They must not be divided to claim a hardware speed ratio.

## Preparation checks

Run these before making the preparation commit:

```sh
python3 -B scripts/verify-c83-runtime-costs.py --selftest --check-manifest
cargo test -p vibeos-wasm-runtime-costs

VIBEOS_C83_SOURCE_COMMIT=1111111111111111111111111111111111111111 \
VIBEOS_C83_CHALLENGE=2222222222222222222222222222222222222222222222222222222222222222 \
  cargo test -p vibeos-wasm-runtime-costs \
    bound_build_runs_every_workload_and_closes_once -- --nocapture

python3 -B scripts/qemu-c83-runtime-costs.py --allow-dirty-smoke
python3 -B scripts/capture-c83-duo-runtime-costs.py --selftest
python3 -B scripts/verify-c83-evidence.py --selftest
```

The all-ones/all-twos identity above is a test binding only. It must never be
published as evidence. The dirty QEMU mode cannot export files and disables the
publication gates by construction.

## Evidence collection

Evidence uses two commits so that the measured source does not refer to a commit
that contains its own measurement:

1. Verify, commit, and push the harness/tooling preparation commit.
2. With that exact commit checked out in a separate clean checkout/worktree and
   its recursive submodules initialized, create one fresh 256-bit challenge.
   Build and collect both platforms into directories outside the repository.
   The formal tools require the root and every submodule to be clean; they do
   not honor `.gitmodules` `ignore` settings for this check.
3. Copy only verified raw logs, summaries, envelopes, and the derived results
   document into `benchmarks/wasm-runtime/`; verify them again; then make the
   separate evidence commit. C8.3 completes only at this step.

One challenge may bind both platform captures:

```sh
prep=$(git rev-parse HEAD)
challenge=$(openssl rand -hex 32)
evidence_root=/absolute/path/outside/the/repository/c83

test -z "$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"
cargo fetch --locked

python3 -B scripts/qemu-c83-runtime-costs.py \
  --source-commit "$prep" --challenge "$challenge" \
  --transcript-out "$evidence_root/qemu/uart.log" \
  --summary-out "$evidence_root/qemu/summary.json" \
  --envelope-out "$evidence_root/qemu/evidence.json"
```

For Duo, first build the dedicated kernel with the same identity from that clean
preparation checkout. Like the QEMU collector, the closed build uses only the
Cargo cache populated above:

```sh
VIBEOS_C83_SOURCE_COMMIT="$prep" VIBEOS_C83_CHALLENGE="$challenge" \
  ./scripts/build-milkv-duo.sh --runtime-costs
```

Package only in the pinned Linux/amd64 SDK environment. The SDK checkout must
be clean at commit `23eb84fecb29585dbb5728d6b7e2475ff273baac` and must already
contain its stock `milkv-duo-sd` build. On macOS/Apple Silicon, the canonical
cross-host invocation is:

```sh
SDK=/absolute/path/to/duo-buildroot-sdk
VIBEOS=$(pwd -P)
DUO_DIGEST=sha256:63d71ea6fb2c2fb23ee34b68892ace67ed8a0c66954ed47b5cb793443fead679
DUO_IMAGE="milkvtech/milkv-duo@$DUO_DIGEST"

docker pull --platform linux/amd64 "$DUO_IMAGE"
docker run --rm --platform linux/amd64 \
  -e VIBEOS_C83_SOURCE_COMMIT="$prep" \
  -e VIBEOS_C83_CHALLENGE="$challenge" \
  -e VIBEOS_C83_SDK_CONTAINER_DIGEST="$DUO_DIGEST" \
  -v "$SDK:/home/work:ro" \
  -v "$VIBEOS:/home/vibeos" \
  "$DUO_IMAGE" \
  /home/vibeos/scripts/package-milkv-duo-sdk.sh \
    --runtime-costs /home/work
```

The package command independently verifies the image before publishing
`boot.sd`, the full SD image, `image-verifier-audit.log`, and
`package-envelope.json` under `target/milkv-duo-runtime-costs/`. The digest
environment variable is an operator assertion checked against the manifest;
the script cannot infer the OCI image identity from inside an arbitrary
container. The pinned image reference above, package envelope, exact SDK/tool
hashes, and verifier audit form the reviewable packaging record.

After independently verifying the image, flash it using the documented manual
Milk-V procedure. The capture tool never flashes, resets, writes to, or guesses
a device. It requires an explicit UART and pauses for the operator to cold boot
the board three times:

```sh
python3 -B scripts/capture-c83-duo-runtime-costs.py \
  --port /dev/cu.EXPLICIT_DUO_UART \
  --output-dir "$evidence_root/duo" \
  --source-commit "$prep" --challenge "$challenge" \
  --kernel target/milkv-duo-runtime-costs/vibeos-milkv-duo.bin \
  --fit target/milkv-duo-runtime-costs/boot.sd \
  --image target/milkv-duo-runtime-costs/vibeos-milkv-duo-runtime-costs-sd.img \
  --package-envelope target/milkv-duo-runtime-costs/package-envelope.json
```

Do not use the monitor-control `/dev/cu.usbmodem*` device as a substitute for a
Duo UART. The operator must verify the adapter and the flashed card before
capture. Known Duo warm-reboot behavior is why each retained boot is a physical
power cycle.

After both collectors pass, assemble the exact Stage-B evidence tree and derive
`RESULTS.md` only through the offline closure verifier:

```sh
mkdir -p benchmarks/wasm-runtime/qemu benchmarks/wasm-runtime/duo
cp "$evidence_root/qemu/uart.log" \
  "$evidence_root/qemu/summary.json" \
  "$evidence_root/qemu/evidence.json" \
  benchmarks/wasm-runtime/qemu/
cp "$evidence_root"/duo/* benchmarks/wasm-runtime/duo/

python3 -B scripts/verify-c83-evidence.py --selftest
python3 -B scripts/verify-c83-evidence.py \
  --evidence-root benchmarks/wasm-runtime \
  --expect-source "$prep" --expect-challenge "$challenge" \
  --write-results
python3 -B scripts/verify-c83-evidence.py \
  --evidence-root benchmarks/wasm-runtime \
  --expect-source "$prep" --expect-challenge "$challenge"
```

The verifier rejects extra, missing, non-regular, or symlinked evidence members;
reruns the raw publication verifier for QEMU and all three Duo boots; checks all
summary and envelope hashes; recomputes the cross-boot gate from raw batch ticks;
and requires the checked `RESULTS.md` to equal its deterministic rendering.

## Evidence boundary

The QEMU envelope binds the clean Git state, exact command/version, pinned Rust
toolchain, kernel ELF, raw transcript, derived summary, UTC interval, and runner
hash. The Duo envelope additionally binds the kernel binary, FIT, full-card
image, fixed SDK commit, operator-declared container digest, package/build
envelopes and verifier audit, UART path/contract, three raw transcript hashes,
and three derived summaries.

The fresh challenge prevents accidental replay of an old log. It is not hardware
attestation. The Duo operator statement and artifact hashes establish an
auditable collection record, but VibeOS currently has no trusted unique board
identity or hardware signing root. FIT and FAT construction also contains
timestamps, so publication binds the produced hashes rather than claiming
byte-for-byte reproducible full images.
