# C8.4 AOT-decision preparation

`workloads-v1.json` freezes the one product workload, physical-Duo budget,
seven-phase attribution ledger, and fail-closed decision rule. `schema-v1.json`
defines the records for exactly one future physical cold-boot transcript. A
raw transcript contains one metadata record, 24 samples, and one end record;
the host, not the target, later assigns its boot index.

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

This verifier does not attest physical provenance or a power cycle, aggregate
three boots, prove the C8.3 precondition, or produce an AOT decision. Those
remain responsibilities of a later capture and evidence verifier. Its raw
input is a stable non-empty regular file capped at 268,435,456 bytes; derived
summary creation is no-clobber unless `--overwrite` is supplied explicitly.

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
