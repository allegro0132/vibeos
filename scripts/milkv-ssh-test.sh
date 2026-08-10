#!/bin/sh
# Run the complete OpenSSH/VSH gate against an already-booted Milk-V Duo.
set -eu

cd "$(dirname "$0")/.."

SSH_READY_TIMEOUT=${SSH_READY_TIMEOUT:-45}
SSH_COMMAND_TIMEOUT=${SSH_COMMAND_TIMEOUT:-15}
SSH_BIND_ADDRESS=${SSH_BIND_ADDRESS:-}

TEST_TMP=""
ACCEPTED_KEY=""
REJECTED_KEY=""
KNOWN_HOSTS=""
HOST_KEY=""

usage() {
  cat <<'EOF'
Usage: ./scripts/milkv-ssh-test.sh TARGET_IPV4 [PORT]

Run the complete real-OpenSSH acceptance gate against an already-booted
Milk-V Duo SSH acceptance image. PORT defaults to 2222.

A PASS proves the addressed endpoint. Physical-board evidence additionally
requires the matching UART insecurity warning and DHCP listener announcement
from the same boot.

The gate pins the exact test host key and forces Ed25519,
curve25519-sha256, and chacha20-poly1305@openssh.com. It exercises exec exit
statuses, an interactive PTY-backed VSH, authorized/rejected client keys, and
unsupported-request rejection.

Environment:
  SSH_READY_TIMEOUT    Readiness deadline in seconds (default: 45)
  SSH_COMMAND_TIMEOUT  Per-command deadline in seconds (default: 15)
  SSH_BIND_ADDRESS     Optional local IPv4 source address for a direct link
EOF
}

usage_error() {
  echo "error: $*" >&2
  usage >&2
  exit 2
}

fail() {
  echo "FAIL milkv-ssh-test: $*" >&2
  exit 1
}

# shellcheck disable=SC2329  # Invoked by the EXIT trap.
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$TEST_TMP" ] && [ -d "$TEST_TMP" ]; then
    rm -rf "$TEST_TMP"
  fi
  exit "$status"
}

if [ "$#" -eq 1 ] && { [ "$1" = "-h" ] || [ "$1" = "--help" ]; }; then
  usage
  exit 0
fi
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage_error "expected TARGET_IPV4 and optional PORT"
fi

SSH_HOST=$1
SSH_PORT=${2:-2222}

for command in python3 ssh ssh-keygen; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "required command not found: $command"
done

python3 -B -c '
import ipaddress
import sys

try:
    address = ipaddress.IPv4Address(sys.argv[1])
except ipaddress.AddressValueError:
    raise SystemExit(1)
if (
    address.is_loopback
    or address.is_unspecified
    or address.is_multicast
    or address.is_reserved
    or address == ipaddress.IPv4Address("255.255.255.255")
):
    raise SystemExit(1)
' "$SSH_HOST" || usage_error "TARGET_IPV4 must be a non-loopback unicast IPv4 address"

if [ -n "$SSH_BIND_ADDRESS" ]; then
  python3 -B -c '
import ipaddress
import sys

try:
    address = ipaddress.IPv4Address(sys.argv[1])
except ipaddress.AddressValueError:
    raise SystemExit(1)
if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_reserved:
    raise SystemExit(1)
' "$SSH_BIND_ADDRESS" \
    || usage_error "SSH_BIND_ADDRESS must be a non-loopback unicast IPv4 address"
fi

python3 -B -c '
import sys

try:
    port = int(sys.argv[1], 10)
except ValueError:
    raise SystemExit(1)
if not 1 <= port <= 65535 or str(port) != sys.argv[1]:
    raise SystemExit(1)
' "$SSH_PORT" || usage_error "PORT must be an integer in the range 1..65535"

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

python3 -B scripts/openssh-test-key.py --selftest >/dev/null \
  || fail "OpenSSH key fixture self-test failed"
python3 -B scripts/openssh-peer.py --selftest >/dev/null \
  || fail "OpenSSH peer self-test failed"

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/vibeos-milkv-ssh-test.XXXXXX") \
  || fail "cannot create temporary directory"
ACCEPTED_KEY="$TEST_TMP/id_ed25519_accepted"
REJECTED_KEY="$TEST_TMP/id_ed25519_rejected"
KNOWN_HOSTS="$TEST_TMP/known_hosts"
HOST_KEY="$TEST_TMP/host_key"

python3 -B scripts/openssh-test-key.py \
  --fixture accepted \
  --comment vibeos-milkv-accepted-test-only \
  --output "$ACCEPTED_KEY" \
  >/dev/null || fail "cannot generate the accepted OpenSSH fixture"
python3 -B scripts/openssh-test-key.py \
  --fixture rejected \
  --comment vibeos-milkv-rejected-test-only \
  --output "$REJECTED_KEY" \
  >/dev/null || fail "cannot generate the rejected OpenSSH fixture"

echo "WARNING milkv-ssh-test: fixed identities and deterministic guest random data; isolated bring-up only" >&2
echo "milkv-ssh-test: probing $SSH_HOST:$SSH_PORT with the pinned test identity"
set -- python3 -B scripts/openssh-peer.py \
  --host "$SSH_HOST" \
  --port "$SSH_PORT" \
  --accepted-key "$ACCEPTED_KEY" \
  --rejected-key "$REJECTED_KEY" \
  --known-hosts "$KNOWN_HOSTS" \
  --host-key-output "$HOST_KEY" \
  --ready-timeout "$SSH_READY_TIMEOUT" \
  --command-timeout "$SSH_COMMAND_TIMEOUT"
if [ -n "$SSH_BIND_ADDRESS" ]; then
  set -- "$@" --bind-address "$SSH_BIND_ADDRESS"
fi
"$@" \
  || fail "OpenSSH peer gate failed for $SSH_HOST:$SSH_PORT"

echo "PASS milkv-ssh-test: OpenSSH/VSH endpoint gate passed on $SSH_HOST:$SSH_PORT"
echo "milkv-ssh-test: physical evidence also requires this boot's matching UART warning and listener address"
