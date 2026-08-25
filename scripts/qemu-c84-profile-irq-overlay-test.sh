#!/bin/sh
# C8.4 real self-SSIP -> exact kernel profile IRQ-overlay acceptance.
set -eu

cd "$(dirname "$0")/.."

export C84_ACCEPTANCE_FEATURE=wasm-c84-profile-irq-overlay-qemu-acceptance
export C84_TEST_LABEL=qemu-c84-profile-irq-overlay-test
export C84_PASS_MARKER='WASM_C84_PROFILE_IRQ_OVERLAY PASS inactive_before=1 forced_ssip=4 causal_ssip_pair=1 non_owner_inert=1 cleared_cancel=1 cleared_drop=1 cleared_detach=1 wait_nonzero=1 restored=1 paired=1 complete=1 ready_epoch=5 inactive_after=1 poison_fail_closed=1'
export C84_TOPOLOGY_MARKER='WASM_C84_PROFILE_IRQ_OVERLAY TOPOLOGY_REJECT mask=0x3 logical=0 physical=0 epoch=1'
export C84_FAIL_MARKER='WASM_C84_PROFILE_IRQ_OVERLAY FAIL'
export C84_FAMILY_MARKER='WASM_C84_PROFILE_IRQ_OVERLAY'

exec ./scripts/qemu-c84-profile-slot-test.sh
