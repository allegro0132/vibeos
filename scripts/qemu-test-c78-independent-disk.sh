#!/bin/sh
# C7.8 host-owned disk, corruption, and exhaustive crash-prefix evidence.
set -eu

cd "$(dirname "$0")/.."

C78_POLICY=policy/image/artifacts/c78-independent-disk-policy.json
C78_TRUST_ANCHOR=1dfaeb2e9d9ff3d5c4eb7f81a1197dd09f8a301a5a31b6ed15921e939574154f
TEST_TMP=$(mktemp -d)
QEMU_EVIDENCE="$TEST_TMP/qemu"
CRASH_EVIDENCE="$TEST_TMP/crash-corpus"
MANIFEST="$CRASH_EVIDENCE/manifest.jsonl"
EVIDENCE="$TEST_TMP/c78-evidence.json"
RESULT_REPORTED=0

# shellcheck disable=SC2329  # Invoked by the EXIT/signal trap.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "${KEEP_C78_EVIDENCE:-0}" = 1 ]; then
    echo "C7.8 evidence retained at $TEST_TMP" >&2
  else
    rm -rf -- "$TEST_TMP"
  fi
  if [ "$status" -ne 0 ] && [ "$RESULT_REPORTED" -eq 0 ]; then
    echo 'FAIL qemu-test-c78-independent-disk: test aborted unexpectedly' >&2
  fi
  exit "$status"
}

fail() {
  RESULT_REPORTED=1
  echo "FAIL qemu-test-c78-independent-disk: $*" >&2
  if [ -s "$EVIDENCE" ]; then
    echo '--- C7.8 verifier output ---' >&2
    tail -80 "$EVIDENCE" >&2 || true
  fi
  exit 1
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "${KEEP_C78_EVIDENCE:-0}" in
  0|1) ;;
  *) fail 'KEEP_C78_EVIDENCE must be 0 or 1' ;;
esac

[ -r "$C78_POLICY" ] || fail "frozen C7.8 policy is absent: $C78_POLICY"
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
command -v rustup >/dev/null 2>&1 || fail 'rustup is required'

echo 'C7.8: independent parser corruption/selftest corpus' >&2
python3 -B scripts/verify-c78-independent-disk.py --selftest || \
  fail 'independent parser selftest failed'

toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
[ -n "$toolchain" ] || fail 'rust-toolchain.toml has no pinned channel'
mkdir -p "$QEMU_EVIDENCE" "$CRASH_EVIDENCE"

echo 'C7.8: exporting complete production-path crash corpus' >&2
C78_RAW_DISK_FIXTURE_DIR="$CRASH_EVIDENCE" \
  rustup run "$toolchain" cargo test --locked --offline \
    -p vibeos-segment-store --test c78_raw_disk_fixtures \
    c78_exports_complete_raw_fault_disk_corpus_when_requested -- --exact --nocapture || \
  fail 'raw fault-disk exporter failed'
[ -s "$MANIFEST" ] || fail 'raw fault-disk exporter produced no manifest'

# Reuse the exact C7.7 path rather than maintaining a second copy: C7.6 creates
# G0/G1 and performs one cold no-write recovery, then C7.7 performs two more
# cold no-write boots with fresh ephemeral runtime identities. The optional
# evidence directory changes only where that existing gate stores snapshots.
echo 'C7.8: collecting five real four-hart QEMU powered-off snapshots' >&2
C77_EVIDENCE_DIR="$QEMU_EVIDENCE" C77_CAPTURE_ONLY=1 KEEP_C77_EVIDENCE=1 \
  ./scripts/qemu-test-c77-ephemeral-runtime.sh || \
  fail 'C7.7 five-boot QEMU evidence collection failed'

echo 'C7.8: independently parsing raw disks and every manifest event' >&2
python3 -B scripts/verify-c78-independent-disk.py \
  --manifest "$MANIFEST" \
  --policy "$C78_POLICY" \
  --trust-anchor-hex "$C78_TRUST_ANCHOR" \
  --g0-image "$QEMU_EVIDENCE/c76-post-g0.raw" \
  --g1-image "$QEMU_EVIDENCE/c76-post-g1.raw" \
  --c76-cold-image "$QEMU_EVIDENCE/c76-post-cold-g1.raw" \
  --c77-cold1-image "$QEMU_EVIDENCE/c77-post-cold1.raw" \
  --final-image "$QEMU_EVIDENCE/c77-storage-v3.raw" \
  --c76-boot1-log "$QEMU_EVIDENCE/c76-boot1.log" \
  --c76-boot2-log "$QEMU_EVIDENCE/c76-boot2.log" \
  --c76-boot3-log "$QEMU_EVIDENCE/c76-boot3.log" \
  --c77-boot1-log "$QEMU_EVIDENCE/c77-boot1.log" \
  --c77-boot2-log "$QEMU_EVIDENCE/c77-boot2.log" >"$EVIDENCE" || \
  fail 'independent C7.8 disk verification failed'

if ! python3 - "$EVIDENCE" <<'PY'
import json
import sys


def exact_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate verifier JSON member: {key}")
        value[key] = item
    return value


with open(sys.argv[1], "r", encoding="utf-8") as handle:
    result = json.load(
        handle,
        object_pairs_hook=exact_object,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite verifier JSON number: {token}")
        ),
    )
expected = {
    "status": "ok",
    "scope": "frozen-c7-v1-policy-v3-component-graph",
    "fixture_bytes_as_authority": False,
    "guest_marker_is_storage_authority": False,
    "c78_independent_disk_scope": True,
    "runtime_ready": False,
    "profile_runtime_ready": False,
    "guest_calls": 0,
    "guest_execution": False,
    "ambient_lookup": 0,
    "raw_durable_ids": 0,
    "no_grant_direct_move": 0,
}
if not isinstance(result, dict):
    raise SystemExit("verifier output is not one JSON object")
for key, expected_value in expected.items():
    observed = result.get(key)
    if type(observed) is not type(expected_value) or observed != expected_value:
        raise SystemExit(f"verifier boundary differs: {key}")
PY
then
  fail 'verifier JSON did not preserve the exact C7.8 success boundary'
fi

mkdir -p target
cp "$EVIDENCE" target/c78-independent-disk-verifier.json
RESULT_REPORTED=1
echo 'PASS qemu-test-c78-independent-disk: data-driven G0/G1 disks, five cold-boot snapshots, semantic corruption, and every documented logical/physical crash prefix independently verified'
