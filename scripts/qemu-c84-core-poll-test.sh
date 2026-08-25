#!/bin/sh
# C8.4 real Core-poll observer -> exact kernel profile-slot acceptance.
set -eu

cd "$(dirname "$0")/.."

export C84_ACCEPTANCE_FEATURE=wasm-c84-core-poll-qemu-acceptance
export C84_TEST_LABEL=qemu-c84-core-poll-test
export C84_PASS_MARKER='WASM_C84_CORE_POLL PASS exact_artifact=1 real_core=1 observer_paired=1 interpretation_nonzero=1 complete=1 ready_epoch=2'
export C84_TOPOLOGY_MARKER='WASM_C84_CORE_POLL TOPOLOGY_REJECT mask=0x3 logical=0 physical=0 epoch=1'
export C84_FAIL_MARKER='WASM_C84_CORE_POLL FAIL'
export C84_FAMILY_MARKER='WASM_C84_CORE_POLL'

exec ./scripts/qemu-c84-profile-slot-test.sh
