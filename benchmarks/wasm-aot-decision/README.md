# C8.4 AOT-decision preparation

`workloads-v1.json` freezes the one product workload, physical-Duo budget,
seven-phase attribution ledger, and fail-closed decision rule. `schema-v1.json`
defines the records for exactly one future physical cold-boot transcript, and
`evidence-schema-v1.json` closes the three-boot capture and final decision
envelopes. A raw transcript contains one metadata record, 24 samples, and one
end record; the host, not the target, later assigns its boot index.

These files contain no result. They neither complete C8.3 nor authorize AOT.
QEMU is integration-only and cannot contribute to the 25 MHz physical-Duo
budget decision. See
[`docs/WASM_AOT_DECISION.md`](../../docs/WASM_AOT_DECISION.md).

The preparation verifier now semantically closes one raw transcript and derives
one deterministic boot summary. It checks the cross-field
`interval_count == len(intervals)` relation which JSON Schema cannot express,
the complete gap-free phase partition, ordered 64-bit accumulator, exact sample
coordinates, output and fuel/poll bounds, and per-boot stability. Timeout,
trap, failure, truncation, wrong-output, and leak attempts are diagnostic and
cannot enter the decision population or authorize AOT.

The software-side chain now includes content-addressed build and package
envelopes, an independent full-SD-image verifier, a read-only three-cold-boot
UART collector, and a final evidence verifier. The final verifier resolves the
full C8.4 preparation commit with replacement objects disabled, materializes
an immutable snapshot, proves the complete checked-in C8.3 evidence tree
byte-for-byte, reruns its verifier, and only then pools the 63 retained C8.4
samples. It computes nearest-rank p50/p95 after sorting the 63 values and
computes non-interpretation time per sample as `N = T - I` before sorting.
Neither a failed precondition nor malformed evidence is converted into a
negative AOT decision.

The single-boot verifier alone still does not attest physical provenance or a
power cycle, aggregate three boots, prove the C8.3 precondition, or produce an
AOT decision. Its raw input is a stable non-empty regular file capped at
268,435,456 bytes; derived summary creation is no-clobber unless `--overwrite`
is supplied explicitly.

Current execution status (2026-08-27): Milk-V Duo physical testing is paused
at operator request. The software tooling and host-only synthetic gates are
ready, but no C8.3/C8.4 physical capture or C8.4 decision is claimed and both
roadmap nodes remain open. The current build is attested from a clean checkout,
not an independent immutable local clone, and the packaging container identity
is operator-declared rather than host-runtime-attested. Those provenance gaps
must close before decision-eligible physical publication. These CI-safe
commands do not open a UART, invoke Docker, access the network, flash media,
reset a board, or require an SDK:

```sh
bash -n scripts/build-milkv-duo.sh
bash -n scripts/package-milkv-duo-sdk.sh
bash -n scripts/verify-milkv-duo-image.sh
./scripts/verify-milkv-duo-image.sh --selftest
python3 -B scripts/capture-c84-duo-aot-decision.py --selftest
python3 -B scripts/verify-c84-evidence.py --selftest
```

The formal build/package/image/capture/publication commands are documented in
[`docs/WASM_AOT_DECISION.md`](../../docs/WASM_AOT_DECISION.md). In particular,
the capture command accepts only an explicitly named read-only UART, refuses
`usbmodem` monitor/control paths, performs no serial writes, reset,
auto-discovery, or flash, and requires an interactive `COLD BOOT N`
acknowledgement for each of three boots. Those commands are intentionally not
being run while the physical gate is paused.

Before the first evidence was collected, the exact frozen workload's portable
profile preflight proved that the former 4,096-interval limit could not hold
even the managed runner's 4,918-interval minimum. The corrected engineering
capacity is 65,536 intervals. Every formal sample self-describes that capacity,
reports `interval_count == len(intervals)`, and sets `intervals_complete` true.
The target collector must keep only one active sample in packed storage;
overflow or truncation remains diagnostic-only and fails closed. This
feasibility fix does not change the v1 workload, budget, sampling, or decision
rule, and 65,536 is not claimed as a mathematical worst-case bound.

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
python3 -B scripts/verify-c84-aot-decision.py --selftest --check-manifest
```
