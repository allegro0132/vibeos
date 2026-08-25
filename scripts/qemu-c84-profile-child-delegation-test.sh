#!/bin/sh
# C8.4 exact prepared-child delegation and terminal-reason acceptance.
set -eu

cd "$(dirname "$0")/.."

export C84_ACCEPTANCE_FEATURE=wasm-c84-profile-child-delegation-qemu-acceptance
export C84_TEST_LABEL=qemu-c84-profile-child-delegation-test
export C84_PASS_MARKER='WASM_C84_PROFILE_CHILD_DELEGATION PASS bind_before_publish=1 exact_prepared=1 first_poll_only=1 duplicate_inert=1 wrong_task_inert=1 child_irq_pair=1 clean_detach=1 complete=1 cancel_stale_inert=1 forget_rejected=1 abandoned_rejected=1 release_cancelled=1 finish_attached_rejected=1 late_claim_rejected=1 release_faulted=1 gate_cleared=1 epochs=1,2,3,4,5,6,7,8 ready_epoch=9'
export C84_TOPOLOGY_MARKER='WASM_C84_PROFILE_CHILD_DELEGATION TOPOLOGY_REJECT mask=0x3 logical=0 physical=0 epoch=1'
export C84_FAIL_MARKER='WASM_C84_PROFILE_CHILD_DELEGATION FAIL'
export C84_FAMILY_MARKER='WASM_C84_PROFILE_CHILD_DELEGATION'

exec ./scripts/qemu-c84-profile-slot-test.sh
