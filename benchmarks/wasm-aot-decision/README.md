# C8.4 AOT-decision preparation

`workloads-v1.json` freezes the one product workload, physical-Duo budget,
seven-phase attribution ledger, and fail-closed decision rule. `schema-v1.json`
defines the future physical decision transcript.

These files contain no result. They neither complete C8.3 nor authorize AOT.
QEMU is integration-only and cannot contribute to the 25 MHz physical-Duo
budget decision. See
[`docs/WASM_AOT_DECISION.md`](../../docs/WASM_AOT_DECISION.md).

The formal schema accepts complete successful physical samples only. Timeout,
trap, failure, truncation, wrong-output, and leak attempts are diagnostic and
cannot enter the decision population or authorize AOT.
