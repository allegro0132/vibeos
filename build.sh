#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
if [ "$#" -eq 0 ] && [ ! -f vibeos.toml ]; then
  if [ ! -t 0 ] || [ ! -t 1 ]; then
    echo 'No configuration: run ./configure.sh --preset default --non-interactive, or supply --config FILE.' >&2
    exit 2
  fi
  "$root/configure.sh"
fi
exec cargo run --quiet -p vibeos-config -- build "$@"
