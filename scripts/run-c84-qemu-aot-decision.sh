#!/bin/sh
# Start the C8.4 runner under the one reviewed CPython/runtime envelope.

set -eu
umask 077
IFS=$(printf '\040\011\012_')
IFS=${IFS%_}
CDPATH=
export CDPATH

python=/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/bin/python3.14
python_sha256=b502cb4c5b46b8d4192ec6bcb600ce8922f1afc396fcf646e8765c6eba74a0bf
python_bytes=52448
framework=/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Python
framework_sha256=696ffa2cf9562522c387f7c2b3a990ef67e574df2d921822fe310ea35587cce0
framework_bytes=5454512
python_app=/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python
python_app_sha256=0c9a985712bb1235d8fe474a6a99810dc118bcae0dfb429a237aac0c907fa3af
python_app_bytes=51392
stdlib_zip=/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/lib/python314.zip
pycache_prefix=/var/empty/vibeos-c84-python-pyc

if [ ! -f "$python" ] || [ -L "$python" ] || [ ! -x "$python" ]; then
    echo "FAIL C8.4 Python launcher: fixed interpreter path is unsafe" >&2
    exit 1
fi
if [ ! -f "$framework" ] || [ -L "$framework" ] || [ ! -x "$framework" ]; then
    echo "FAIL C8.4 Python launcher: fixed framework path is unsafe" >&2
    exit 1
fi
if [ ! -f "$python_app" ] || [ -L "$python_app" ] || [ ! -x "$python_app" ]; then
    echo "FAIL C8.4 Python launcher: fixed app executable path is unsafe" >&2
    exit 1
fi
if [ -e "$stdlib_zip" ] || [ -L "$stdlib_zip" ]; then
    echo "FAIL C8.4 Python launcher: normally absent stdlib zip appeared" >&2
    exit 1
fi
if [ -e "$pycache_prefix" ] || [ -L "$pycache_prefix" ]; then
    echo "FAIL C8.4 Python launcher: private pycache sink appeared" >&2
    exit 1
fi
if [ "$(/usr/bin/stat -f '%Sp:%Su:%Sg' /var/empty)" != 'drwxr-xr-x:root:sys' ]; then
    echo "FAIL C8.4 Python launcher: /var/empty custody differs" >&2
    exit 1
fi
if [ -n "$(/bin/ls -A /var/empty)" ]; then
    echo "FAIL C8.4 Python launcher: OpenSSL module directory is not empty" >&2
    exit 1
fi
if [ "$(/usr/bin/stat -f '%HT:%Sp:%Su:%Sg' /dev/null)" != 'Character Device:crw-rw-rw-:root:wheel' ]; then
    echo "FAIL C8.4 Python launcher: OpenSSL configuration sink differs" >&2
    exit 1
fi

python_hash_line=$(/usr/bin/shasum -a 256 "$python")
python_hash=${python_hash_line%% *}
if [ "$python_hash" != "$python_sha256" ] || \
   [ "$(/usr/bin/stat -f '%z' "$python")" != "$python_bytes" ]; then
    echo "FAIL C8.4 Python launcher: fixed interpreter identity differs" >&2
    exit 1
fi
framework_hash_line=$(/usr/bin/shasum -a 256 "$framework")
framework_hash=${framework_hash_line%% *}
if [ "$framework_hash" != "$framework_sha256" ] || \
   [ "$(/usr/bin/stat -f '%z' "$framework")" != "$framework_bytes" ]; then
    echo "FAIL C8.4 Python launcher: fixed framework identity differs" >&2
    exit 1
fi
python_app_hash_line=$(/usr/bin/shasum -a 256 "$python_app")
python_app_hash=${python_app_hash_line%% *}
if [ "$python_app_hash" != "$python_app_sha256" ] || \
   [ "$(/usr/bin/stat -f '%z' "$python_app")" != "$python_app_bytes" ]; then
    echo "FAIL C8.4 Python launcher: fixed app executable identity differs" >&2
    exit 1
fi

script_dir=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
launcher=$script_dir/run-c84-qemu-aot-decision.sh
runner=$script_dir/qemu-c84-aot-decision.py
if [ ! -f "$launcher" ] || [ -L "$launcher" ] || [ ! -f "$runner" ] || [ -L "$runner" ]; then
    echo "FAIL C8.4 Python launcher: launcher/runner source path is unsafe" >&2
    exit 1
fi

exec /usr/bin/env -i \
    CARGO_HOME=/Users/ziangwang/.cargo \
    HOME=/var/empty \
    LANG=C \
    LC_ALL=C \
    OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES=/var/empty \
    PATH=/opt/homebrew/bin:/usr/bin:/bin \
    RUSTUP_HOME=/Users/ziangwang/.rustup \
    TMPDIR=/tmp \
    TZ=UTC \
    VIBEOS_C84_PYTHON_LAUNCHER="$launcher" \
    XDG_CONFIG_HOME=/var/empty \
    __CF_USER_TEXT_ENCODING=0x1F5:0x0:0x0 \
    "$python" -I -B -S -X "pycache_prefix=$pycache_prefix" "$runner" "$@"
