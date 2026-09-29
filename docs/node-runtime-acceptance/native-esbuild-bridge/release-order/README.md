# Transform handle release ordering

The QEMU native bridge probe passes with two enforced lifetime invariants:

- Invocation TLS destruction requires no active esbuild handle.
- `release` returns busy while a transform lacks a terminal result; it cannot
  drop an unpolled or suspended transform future as a substitute for joining it.

The probe attempts early release immediately after admission and after each
pending async poll, verifies refusal, then still completes or cancels the same
handle and releases it successfully. The three WASI instances report audited
reclamation, zero capabilities and zero waiters. Normal native return and QEMU
shutdown are required. Source inputs remain unchanged during execution.

`link/` retains the incremental image's archive and compilation evidence.
Fresh cross-build and production Node/tsx qualification of this additional
release guard remain pending. Earlier production teardown/cancellation checks
are recorded in `../../tsx-cancel/` and `../../tsx-qemu/cleanup-guard/`.
