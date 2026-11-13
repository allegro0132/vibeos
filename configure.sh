#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
exec cargo run --quiet -p vibeos-config --features tui -- "$@"
