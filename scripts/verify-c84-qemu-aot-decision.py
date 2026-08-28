#!/usr/bin/env python3
"""Verify the frozen C8.4 fixed-QEMU AOT-decision contract and evidence.

The tool is intentionally independent of the collector and runner.  It reuses
only the already-reviewed, platform-neutral transcript sample, accumulator,
and distribution helpers from ``verify-c84-aot-decision.py``.  Physical-Duo
metadata and the older diagnostic ``AUDIT_`` stream are rejected.

Typical use is two-phase::

    verify-c84-qemu-aot-decision.py --check-manifest --selftest
    verify-c84-qemu-aot-decision.py --transcript uart.log \
        --expect-source "$SOURCE" --expect-challenge "$CHALLENGE" \
        --expect-capture-mode formal-publication \
        --summary-out summary.json
    verify-c84-qemu-aot-decision.py --publication --transcript uart.log \
        --expect-source "$SOURCE" --expect-challenge "$CHALLENGE" \
        --expect-capture-mode formal-publication \
        --summary-in summary.json --environment-in environment.json \
        --qemu-bin /path/to/qemu-system-riscv64 \
        --bios-bin /path/to/fw_dynamic.bin --kernel-bin /private/target/kernel \
        --openssh-bin /usr/bin/ssh --materialized-source /private/source \
        --execution-qemu-bin /private/custody/qemu-system-riscv64 \
        --execution-bios-bin /private/custody/fw_dynamic.bin \
        --execution-kernel-bin /private/custody/vibeos-qemu-virt \
        --decision-out DECISION.json

No result produced here authorizes AOT or accepts native code.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import datetime
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import types
from dataclasses import dataclass
from typing import Any, Callable


SCRIPT_PATH = pathlib.Path(__file__).resolve()
ROOT = SCRIPT_PATH.parent.parent
MANIFEST_PATH = ROOT / "benchmarks/wasm-aot-decision/workloads-qemu-v1.json"
SCHEMA_PATH = ROOT / "benchmarks/wasm-aot-decision/schema-qemu-v1.json"
EVIDENCE_SCHEMA_PATH = (
    ROOT / "benchmarks/wasm-aot-decision/evidence-schema-qemu-v1.json"
)
PHYSICAL_VERIFIER_PATH = ROOT / "scripts/verify-c84-aot-decision.py"
RUNNER_PATH = ROOT / "scripts/qemu-c84-aot-decision.py"
BASE_RUNNER_PATH = ROOT / "scripts/qemu-c83-runtime-costs.py"
LAUNCHER_PATH = ROOT / "scripts/run-c84-qemu-aot-decision.sh"

CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
PINNED_CARGO_LOCK_SHA256 = (
    "ca1ed8424b4e21ba8844a7f426077e811097760a2d59c21c5c711d4927c2ec9d"
)
PINNED_CARGO_LOCK_BYTES = 56_970
PINNED_CARGO_PACKAGES = 189
PINNED_CARGO_PACKAGE_SET_SHA256 = (
    "a327b577ce3f0b4591afa2451f6ad0ea3c8900e3b64677fae98581dc4f2be190"
)
PINNED_RUST_SRC_CARGO_PACKAGES = 30
PINNED_RUST_SRC_CARGO_PACKAGE_SET_SHA256 = (
    "c13441213110ae29eb2f814ca77627f2f3a43501b7e7d3d6e9337567a1572c8f"
)
PINNED_CARGO_UNION_PACKAGES = 213
PINNED_CARGO_UNION_EXACT_OVERLAP = 6
PINNED_CARGO_UNION_PROJECT_ONLY = 183
PINNED_CARGO_UNION_RUST_SRC_ONLY = 24
PINNED_CARGO_UNION_PACKAGE_SET_SHA256 = (
    "395c4f3063d7d5c0db59ffa15cb1e58e48272837ac97386616a40e8bf3f9c5b2"
)
PINNED_PRIVATE_CRATE_TREE = {
    "policy": "strict-tree-content-mode-v1",
    "sha256": "4c147b68347c1183847aae453c1a625a08bcca6409f6036c2eaf2a85ace3a33b",
    "files": 11_604,
    "directories": 2_518,
    "bytes": 138_693_206,
}
PINNED_PRIVATE_CRATE_ARCHIVE_TREE = {
    "policy": "strict-tree-content-mode-v1",
    "sha256": "d0b61dc97e2c4e3dda7a57c5034cf51a58c300254c571d1fe2f264a19bb48ad0",
    "files": 189,
    "directories": 1,
    "bytes": 23_706_909,
}
PINNED_TOOLCHAIN_TREE = {
    "policy": "strict-tree-content-mode-v1",
    "sha256": "5927a8a6986e0478afcafd0d61151a503436225fdaceb0f087f7d46aad968f92",
    "files": 3_916,
    "directories": 972,
    "bytes": 853_137_324,
}
PINNED_RUST_SRC_TREE = {
    "policy": "strict-tree-content-mode-v1",
    "sha256": "6dc205c0cc725423857e3fe34a0f7394a3247846bf71a25a087321281df5e182",
    "files": 3_603,
    "directories": 933,
    "bytes": 71_790_604,
}
PINNED_RUST_SRC_CARGO_TOML = {
    "sha256": "b346ae33bd9648949894510a2bcc1d1f8b78c7301c3110e4a98b68bacd3b4584",
    "bytes": 3_070,
}
PINNED_RUST_SRC_CARGO_LOCK = {
    "sha256": "0cd31e4d5c49d7cfbfc479e5cb63001a60c8fdca365677e8ee92137a2b5aaeeb",
    "bytes": 9_835,
}
PINNED_LLD_RUNTIME_SHA256 = (
    "9b5885317dd8ea18a789427356d4258352222f0c218422f5d224f387e9888cb8"
)
PINNED_LLD_INVOCATION = pathlib.Path("/opt/homebrew/bin/ld.lld")

PINNED_PYTHON = pathlib.Path(
    "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/"
    "Python.framework/Versions/3.14/bin/python3.14"
)
PINNED_PYTHON_SHA256 = (
    "b502cb4c5b46b8d4192ec6bcb600ce8922f1afc396fcf646e8765c6eba74a0bf"
)
PINNED_PYTHON_BYTES = 52_448
PINNED_PYTHON_VERSION = "3.14.6"
PINNED_PYTHON_CELLAR = pathlib.Path(
    "/opt/homebrew/Cellar/python@3.14/3.14.6"
)
PINNED_PYTHON_PREFIX = pathlib.Path(
    "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/"
    "Python.framework/Versions/3.14"
)
PINNED_PYTHON_FRAMEWORK = PINNED_PYTHON_PREFIX / "Python"
PINNED_PYTHON_FRAMEWORK_SHA256 = (
    "696ffa2cf9562522c387f7c2b3a990ef67e574df2d921822fe310ea35587cce0"
)
PINNED_PYTHON_FRAMEWORK_BYTES = 5_454_512
PINNED_PYTHON_APP = (
    PINNED_PYTHON_PREFIX / "Resources/Python.app/Contents/MacOS/Python"
)
PINNED_PYTHON_APP_SHA256 = (
    "0c9a985712bb1235d8fe474a6a99810dc118bcae0dfb429a237aac0c907fa3af"
)
PINNED_PYTHON_APP_BYTES = 51_392
PINNED_PYTHON_STDLIB = PINNED_PYTHON_PREFIX / "lib/python3.14"
PINNED_PYTHON_LIB_DYNLOAD = PINNED_PYTHON_STDLIB / "lib-dynload"
PINNED_PYTHON_ZIP = PINNED_PYTHON_PREFIX / "lib/python314.zip"
PINNED_PYTHON_PYCACHE_PREFIX = pathlib.Path(
    "/var/empty/vibeos-c84-python-pyc"
)
PINNED_HASHLIB_EXTENSION = (
    PINNED_PYTHON_LIB_DYNLOAD / "_hashlib.cpython-314-darwin.so"
)
PINNED_LIBCRYPTO_LINK = pathlib.Path(
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
)
PINNED_LIBCRYPTO = pathlib.Path(
    "/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib"
)
PINNED_LZMA_EXTENSION = PINNED_PYTHON_LIB_DYNLOAD / "_lzma.cpython-314-darwin.so"
PINNED_LIBLZMA_LINK = pathlib.Path("/opt/homebrew/opt/xz/lib/liblzma.5.dylib")
PINNED_LIBLZMA = pathlib.Path("/opt/homebrew/Cellar/xz/5.8.3/lib/liblzma.5.dylib")
PINNED_ZSTD_EXTENSION = PINNED_PYTHON_LIB_DYNLOAD / "_zstd.cpython-314-darwin.so"
PINNED_LIBZSTD_LINK = pathlib.Path("/opt/homebrew/opt/zstd/lib/libzstd.1.dylib")
PINNED_LIBZSTD = pathlib.Path(
    "/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.5.7.dylib"
)
PINNED_PYTHON_ARGV_PREFIX = [
    str(PINNED_PYTHON),
    "-I",
    "-B",
    "-S",
    "-X",
    f"pycache_prefix={PINNED_PYTHON_PYCACHE_PREFIX}",
]
PINNED_PYTHON_STARTUP_SYS_PATH = [
    str(PINNED_PYTHON_ZIP),
    str(PINNED_PYTHON_STDLIB),
    str(PINNED_PYTHON_LIB_DYNLOAD),
]
PINNED_PYTHON_EFFECTIVE_SYS_PATH = [
    str(PINNED_PYTHON_STDLIB),
    str(PINNED_PYTHON_LIB_DYNLOAD),
]
PINNED_PYTHON_FLAGS = {
    "isolated": 1,
    "dont_write_bytecode": 1,
    "no_site": 1,
    "ignore_environment": 1,
    "no_user_site": 1,
    "safe_path": True,
    "optimize": 0,
    "hash_randomization": 1,
    "utf8_mode": 1,
}
PINNED_PYTHON_LAUNCH_ENVIRONMENT = {
    "CARGO_HOME": "/Users/ziangwang/.cargo",
    "HOME": "/var/empty",
    "LANG": "C",
    "LC_ALL": "C",
    "OPENSSL_CONF": "/dev/null",
    "OPENSSL_MODULES": "/var/empty",
    "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
    "RUSTUP_HOME": "/Users/ziangwang/.rustup",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
    "VIBEOS_C84_PYTHON_LAUNCHER": str(LAUNCHER_PATH),
    "XDG_CONFIG_HOME": "/var/empty",
    "__CF_USER_TEXT_ENCODING": "0x1F5:0x0:0x0",
}
PINNED_PYTHON_STDLIB_INVENTORY = {
    "policy": "reachable-stdlib-tree-v1-exclude-site-packages-and-pycache",
    "root": str(PINNED_PYTHON_STDLIB),
    "sha256": "59bb25e3cf5c4483dfdd8d152f41dafef62ab2f905717bcfd5f800c1a61c641a",
    "entries": 2_703,
    "files": 2_498,
    "directories": 203,
    "symlinks": 2,
    "bytes": 57_153_940,
}
PINNED_LAUNCHER_SHA256 = (
    "a379d1531d67a19931563a47477467b4010046b922b22c0af40a9a2a1ba25c71"
)
PINNED_LAUNCHER_BYTES = 4_060
PINNED_HASHLIB_EXTENSION_SHA256 = (
    "7218f3babc5db5b091249955dbba6c2260a0dddd25560bc17d83c7da87a3e95c"
)
PINNED_HASHLIB_EXTENSION_BYTES = 97_968
PINNED_LIBCRYPTO_SHA256 = (
    "34bc039f5c725691e757ef42d26f1709830b18046c3ad6d93985153c83d0bbbc"
)
PINNED_LIBCRYPTO_BYTES = 4_846_032
PINNED_LZMA_EXTENSION_SHA256 = (
    "90f3612615d66f3cc7ebced3851f2c24ed91a142ddb5428b1ad9253d2a7fbb19"
)
PINNED_LZMA_EXTENSION_BYTES = 92_256
PINNED_LIBLZMA_SHA256 = (
    "3d5bfa2f097c31463642b1daab5e662b44368bb4da368f85e412e7f9adcbaa10"
)
PINNED_LIBLZMA_BYTES = 184_512
PINNED_ZSTD_EXTENSION_SHA256 = (
    "4ee39ca9e3102ca37938cd578bb8e0c1c82106be7001f329ded33a0720cbee5e"
)
PINNED_ZSTD_EXTENSION_BYTES = 114_176
PINNED_LIBZSTD_SHA256 = (
    "e2847c4613b386683c234913ae3b7b04299254096caf7616e3b3cd9bb97a39ab"
)
PINNED_LIBZSTD_BYTES = 649_648


def load_source_module(name: str, path: pathlib.Path) -> types.ModuleType:
    """Compile one stable UTF-8 source snapshot without consulting ``.pyc``."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise RuntimeError(f"source helper is not one regular file: {path}")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 16 * 1024 * 1024:
                    raise RuntimeError(f"source helper exceeds 16 MiB: {path}")
                chunks.append(chunk)
            closed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        current = path.lstat()
    except OSError as error:
        raise RuntimeError(f"cannot read source helper {path}: {error}") from error

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    if identity(opened) != identity(closed) or identity(closed) != identity(current):
        raise RuntimeError(f"source helper changed while reading: {path}")
    raw = b"".join(chunks)
    if len(raw) != opened.st_size:
        raise RuntimeError(f"source helper byte length changed: {path}")
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"source helper is not strict UTF-8: {path}") from error
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition(".")[0]
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        code = compile(source, str(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    executed_identity = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    executed_closure: dict[str, dict[str, object]] = {str(path): executed_identity}
    for value in tuple(module.__dict__.values()):
        nested = getattr(value, "__vibeos_executed_source_closure__", None)
        if not isinstance(nested, dict):
            continue
        for nested_path, nested_identity in nested.items():
            prior = executed_closure.get(nested_path)
            if prior is not None and prior != nested_identity:
                raise RuntimeError(f"conflicting executed source identity: {nested_path}")
            executed_closure[nested_path] = nested_identity
    module.__vibeos_executed_source_identity__ = executed_identity
    module.__vibeos_executed_source_closure__ = executed_closure
    return module


def load_physical_helpers() -> Any:
    return load_source_module(
        "vibeos_c84_physical_verifier_helpers", PHYSICAL_VERIFIER_PATH
    )


BASE = load_physical_helpers()
VerificationError = BASE.VerificationError
require = BASE.require
strict_json_bytes = BASE.strict_json_bytes
exact_keys = BASE.exact_keys
exact_literal = BASE.exact_literal
exact_int = BASE.exact_int
exact_bool = BASE.exact_bool
exact_text = BASE.exact_text
exact_sha256 = BASE.exact_sha256
exact_commit = BASE.exact_commit
parse_record = BASE.parse_record
verify_transcript_sample = BASE.verify_transcript_sample
transcript_accumulator = BASE.transcript_accumulator
distribution = BASE.distribution
serialize_transcript = BASE.serialize_transcript

U64_MAX = BASE.U64_MAX
PHASE_IDS = BASE.PHASE_IDS
META_PREFIX = BASE.META_PREFIX
SAMPLE_PREFIX = BASE.SAMPLE_PREFIX
END_PREFIX = BASE.END_PREFIX
SAMPLE_KEYS = BASE.SAMPLE_KEYS
END_KEYS = BASE.END_KEYS
INTERVAL_CAPACITY = BASE.INTERVAL_CAPACITY
SAMPLES = 24
WARMUPS = 3
RETAINED = 21
P50_SORTED_INDEX = 10
P95_SORTED_INDEX = 19
BUDGET_TICKS = 1_000_000
TIMEBASE_HZ = 10_000_000
PLATFORM = "qemu-virt-rv64-tcg-icount-v1"
SUITE = "vibeos.c84.qemu-aot-decision"
FORMAL_CAPTURE_MODE = "formal-publication"
SMOKE_CAPTURE_MODE = "dirty-smoke-not-publication"
CAPTURE_MODES = (FORMAL_CAPTURE_MODE, SMOKE_CAPTURE_MODE)
RUN_ID_DOMAINS = {
    FORMAL_CAPTURE_MODE: "vibeos.c84.qemu-aot-decision.run-id.v1",
    SMOKE_CAPTURE_MODE: "vibeos.c84.qemu-aot-decision.smoke.run-id.v1",
}
TRANSCRIPT_SCOPE = "one-fresh-fixed-qemu-process-no-physical-claim"
PLATFORM_CLASS = "emulator"
PHYSICAL_PROVENANCE = "not-claimed"
ELIGIBLE_OUTCOME = "aot-eligible-for-c85-design-review-on-fixed-qemu"
OTHERWISE_OUTCOME = "aot-not-justified-on-fixed-qemu"
MAX_CONTRACT_BYTES = 1_048_576
MAX_TRANSCRIPT_BYTES = 268_435_456
MAX_JSON_BYTES = 16_777_216
FORBIDDEN_AUDIT_PREFIX = "WASM_C84_SSH_MANAGED_CHILD_SINGLE_BOOT_COLLECTOR AUDIT_"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GENERIC_WASM_FAILURE = re.compile(r"\bWASM_[A-Z0-9_]+ FAIL\b")
RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z"
)
EVIDENCE_SCHEMA_SHA256 = (
    "6239f8fb2e71a0195d8efccb445badbd8f6cad04a755440be93c08131e7cd22e"
)
FORMAL_BRANCH = "codex/wasm"
FORMAL_LOCAL_REF = "refs/heads/codex/wasm"
FORMAL_ORIGIN_REF = "refs/remotes/origin/codex/wasm"
FORMAL_CONFIGURED_ORIGIN = "git@github.com:allegro0132/vibeos.git"
FORMAL_REMOTE_URL = "https://github.com/allegro0132/vibeos.git"
FORMAL_REMOTE_REF = "refs/heads/codex/wasm"
PINNED_QEMU_VERSION = "QEMU emulator version 11.0.3"
PINNED_QEMU_SHA256 = "ef5c714232320c22561daa0998546b73672e21a2801404714dfbd4982ac7b3c0"
PINNED_QEMU_BYTES = 13_511_488
PINNED_QEMU_RUNTIME_GRAPH_SHA256 = (
    "4b410b796467f972fdf4f55113dad8c6edbe964cb921ff1271faf2439a737855"
)
PINNED_QEMU_RUNTIME_COUNTS = {
    "nodes": 29,
    "load_edges": 147,
    "pinned_homebrew_edges": 68,
    "sealed_system_edges": 79,
}
PINNED_QEMU_PREFIX = pathlib.Path("/opt/homebrew/Cellar/qemu/11.0.3")
PINNED_BIOS_SHA256 = "49bdf7b939bda11321132d1042bf99d7324fb190f1feef423171fed3573f8705"
PINNED_BIOS_BYTES = 273_048
PINNED_OPENSSH_VERSION = "OpenSSH_10.2p1, LibreSSL 3.3.6"
PINNED_OPENSSH_SHA256 = (
    "470f812f6e71ee4ca1b49c79f9c2982c054493e22502d4648bd010feb4b2a9b2"
)
PINNED_OPENSSH_BYTES = 1_555_472
DARWIN_SYSTEM_OPENSSH = pathlib.Path("/usr/bin/ssh")
DARWIN_MOUNT = pathlib.Path("/sbin/mount")
DARWIN_SF_RESTRICTED = 0x00080000
DARWIN_OPENSSH_METHOD = "darwin-sealed-system-volume-v1"
PINNED_DARWIN_HOST_BUILD = {
    "product_name": "macOS",
    "product_version": "26.5.2",
    "build_version": "25F84",
    "darwin_release": "25.5.0",
}
PINNED_OTOOL_INVOCATION = pathlib.Path(
    "/Library/Developer/CommandLineTools/usr/bin/otool"
)
PINNED_OTOOL_RESOLVED = pathlib.Path(
    "/Library/Developer/CommandLineTools/usr/bin/llvm-otool"
)
PINNED_OTOOL_SHA256 = "61ff2c63cf68eeeadf9c4700dadb8271740ff4960f98500f30db82b31521c0de"
PINNED_OTOOL_BYTES = 138_208
PINNED_CLT_PACKAGE_ID = "com.apple.pkg.CLTools_Executables"
PINNED_CLT_VERSION = "26.6.0.0.1781586589"
OTOOL_CUSTODY_POLICY = "direct-command-line-tools-symlink-and-identity-v1"
CUSTODY_SCHEME = "private-qemu-bios-kernel-plus-darwin-system-openssh-v1"
CUSTODY_DIRECTORY_MODE = 0o500
CUSTODY_ROLES = {
    "qemu": ("qemu-system-riscv64", 0o500),
    "bios": ("opensbi-riscv64-generic-fw_dynamic.bin", 0o400),
    "kernel_elf": ("vibeos-qemu-virt", 0o400),
}
QEMU_ENVIRONMENT_POLICY = "deny-by-default-private-campaign-v1"
QEMU_ENVIRONMENT_APPLIES_TO = [
    "firmware-search-probe",
    "version-probe",
    "live-campaign",
]
QEMU_ENVIRONMENT_DIRECTORY_MODE = "0700"
QEMU_DATA_DIRECTORY_MODE = "0500"
QEMU_PROCESS_CWD = "/"
QEMU_ENVIRONMENT_ALLOWED_NAMES = [
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "TMPDIR",
    "TZ",
    "XDG_CONFIG_HOME",
]
QEMU_ENVIRONMENT_NORMALIZED_VALUES = {
    "HOME": "<campaign-root>/qemu-environment/home",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TMPDIR": "<campaign-root>/qemu-environment/tmp",
    "TZ": "UTC",
    "XDG_CONFIG_HOME": "<campaign-root>/qemu-environment/xdg-config",
}
EXPECTED_QEMU_ENVIRONMENT = {
    "policy": QEMU_ENVIRONMENT_POLICY,
    "applies_to": QEMU_ENVIRONMENT_APPLIES_TO,
    "private_directory_mode": QEMU_ENVIRONMENT_DIRECTORY_MODE,
    "private_directories_must_remain_empty": True,
    "allowed_names": QEMU_ENVIRONMENT_ALLOWED_NAMES,
    "normalized_values": QEMU_ENVIRONMENT_NORMALIZED_VALUES,
    "live_data_directory": {
        "path": "<campaign-root>/qemu-environment/data",
        "mode": QEMU_DATA_DIRECTORY_MODE,
        "must_remain_empty": True,
    },
}
QEMU_RUNTIME_CLOSURE_POLICY = "darwin-qemu-recursive-nonsystem-macho-closure-v1"
QEMU_RUNTIME_SYSTEM_PREFIXES = ["/System/Library/", "/usr/lib/"]
QEMU_RUNTIME_HOST_LIMIT = (
    "same-uid-host-exclusivity-required; pre/post/final identity checks cannot "
    "exclude a same-UID swap-and-restore during a live process"
)
EXPECTED_SUBMODULES = {
    "vendor/jitterentropy-rs": ".git/modules/vendor/jitterentropy-rs",
    "vendor/sunset": ".git/modules/vendor/sunset",
}
EXPECTED_HOST_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAICnlgzqRWmQppOOnlIR1wzjvQ264K+ickvBZcEQD251V"
)
EXPECTED_HOST_FINGERPRINT = "SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8"
EXPECTED_HOST_KEY_RAW = (EXPECTED_HOST_PUBLIC_KEY + "\n").encode("ascii")
HELPER_PATHS = {
    "qemu_c83_base_runner": "scripts/qemu-c83-runtime-costs.py",
    "qemu_peer": "scripts/c84-qemu-aot-decision-peer.py",
    "collector_peer": "scripts/c84-ssh-managed-child-single-boot-collector-peer.py",
    "trusted_sample_peer": "scripts/c84-ssh-managed-child-trusted-sample-peer.py",
    "finish_verify_peer": "scripts/c84-ssh-managed-child-finish-verify-peer.py",
    "irq_overlay_peer": "scripts/c84-ssh-managed-child-irq-overlay-peer.py",
    "phase_sidecar_peer": "scripts/c84-ssh-managed-child-phase-sidecar-peer.py",
    "core_peer": "scripts/c84-ssh-managed-child-core-peer.py",
    "openssh_peer_port_helper": "scripts/openssh-peer.py",
    "request_parent_verifier": "scripts/verify-c84-ssh-profile-request-parent.py",
    "physical_contract_verifier": "scripts/verify-c84-aot-decision.py",
    "openssh_test_key": "scripts/openssh-test-key.py",
}
PEER_SOURCE_CLOSURE_KEYS = (
    "qemu_peer",
    "collector_peer",
    "trusted_sample_peer",
    "finish_verify_peer",
    "irq_overlay_peer",
    "phase_sidecar_peer",
    "core_peer",
    "openssh_peer_port_helper",
    "request_parent_verifier",
)
EXECUTED_SOURCE_EVIDENCE_KEYS = (
    "qemu_c83_base_runner",
    *PEER_SOURCE_CLOSURE_KEYS,
)

NORMALIZED_QEMU_ARGV = [
    "qemu-system-riscv64",
    "-no-user-config",
    "-L",
    "<qemu-data>",
    "-machine",
    "virt",
    "-cpu",
    "rv64",
    "-smp",
    "1",
    "-m",
    "128M",
    "-accel",
    "tcg,thread=single",
    "-icount",
    "shift=0,align=off,sleep=off",
    "-nographic",
    "-bios",
    "<opensbi>",
    "-kernel",
    "<kernel>",
    "-object",
    "rng-random,id=vibeos-c84-aot-decision-rng,filename=/dev/urandom",
    "-device",
    "virtio-rng-device,rng=vibeos-c84-aot-decision-rng,bus=virtio-mmio-bus.1",
    "-netdev",
    "user,id=vibeos-c84-aot-decision-net,net=10.0.2.0/24,host=10.0.2.2,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:<host-port>-10.0.2.15:2222",
    "-device",
    "virtio-net-device,netdev=vibeos-c84-aot-decision-net,bus=virtio-mmio-bus.0,mac=02:00:00:00:00:01",
    "-global",
    "virtio-mmio.force-legacy=false",
]
GIT_STATUS_COMMAND = [
    "git",
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=all",
    "--ignore-submodules=none",
]
GIT_DIFF_COMMAND = [
    "git",
    "diff",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    "--ignore-submodules=none",
    "HEAD",
    "--",
]
GIT_INDEX_FLAGS_COMMAND = ["git", "ls-files", "-v", "-z", "--full-name"]
GIT_FSMONITOR_FLAGS_COMMAND = ["git", "ls-files", "-f", "-z", "--full-name"]
GIT_REMOTE_QUERY_COMMAND = [
    "git",
    "ls-remote",
    "--exit-code",
    "--refs",
    FORMAL_REMOTE_URL,
    FORMAL_REMOTE_REF,
]
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SANITIZED_GIT_PATH = os.pathsep.join(
    ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin")
)
GIT_LOCAL_CONFIG_POLICY = "raw-identity-safe-key-allowlist-v1"
GIT_LOCAL_CONFIG_PATHS = {
    ".": ".git/config",
    **{
        path: f"{git_directory}/config"
        for path, git_directory in EXPECTED_SUBMODULES.items()
    },
}

META_KEYS = {
    "schema",
    "version",
    "suite_id",
    "workload_revision",
    "source_commit",
    "challenge",
    "run_id",
    "manifest_sha256",
    "transcript_schema_sha256",
    "platform",
    "platform_class",
    "physical_provenance",
    "capture_mode",
    "decision_eligible",
    "clock",
    "timebase_hz",
    "hart_id",
    "hart_count",
    "transcript_scope",
    "required_qemu_boots",
    "samples_per_boot",
    "warmup_per_boot",
    "retained_per_boot",
    "workload_id",
    "artifact_sha256",
    "artifact_bytes",
    "input_sha256",
    "input_bytes",
    "output_sha256",
    "output_bytes",
    "budget_ticks",
}

EXPECTED_FIXTURE = {
    "id": "ssh-case-filter-12k-v1",
    "product_path": "authenticated OpenSSH SessionExec of the image-pinned case-filter command",
    "transport": "authenticated-openssh-exec",
    "command": "case-filter",
    "world": "vibe:stream/filter@1.0.0",
    "entrypoint": "run",
    "artifact": {
        "wat_path": "policy/image/artifacts/c53-stream-filter.component.wat",
        "byte_len": 2012,
        "sha256": "180ed444de8b6c9ecd828b369d4c8b9f783758ef22c0b17170682d71f2fd0e72",
    },
    "input": {
        "generator": "bytes((index * 17 + 3) % 251 for index in range(12 * 1024 + 37))",
        "byte_len": 12325,
        "sha256": "6b6054d492e00e68a93bc9b657a69577c7c44f5a48f169adb4124df0a50f6b3c",
    },
    "output": {
        "transform": "bytes(byte ^ 0x20 for byte in input)",
        "byte_len": 12325,
        "sha256": "791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27",
        "exit_status": 0,
        "stderr_bytes": 0,
    },
    "chunking": {"maximum_chunk_bytes": 1024, "read_chunks": 13, "write_chunks": 13},
    "limits": {
        "memory_bytes": 524288,
        "total_fuel": 500000,
        "poll_quantum": 100,
        "resources": 4,
    },
}

EXPECTED_SCOPE = {
    "roadmap_item": "C8.4",
    "state": "qemu-decision-contract-frozen",
    "c83_status": "accepted-complete-by-historical-evidence-policy",
    "platform_class": PLATFORM_CLASS,
    "physical_provenance": PHYSICAL_PROVENANCE,
    "aot_authorized": False,
    "native_code_accepted": False,
}
EXPECTED_CAPTURE_MODES = {
    FORMAL_CAPTURE_MODE: {
        "decision_eligible": True,
        "publication_eligible": True,
    },
    SMOKE_CAPTURE_MODE: {
        "decision_eligible": False,
        "publication_eligible": False,
    },
}

EXPECTED_PYTHON_RUNTIME = {
    "policy": "pinned-cpython-3.14-runtime-closure-v1",
    "launcher": {
        "path": "scripts/run-c84-qemu-aot-decision.sh",
        "sha256": PINNED_LAUNCHER_SHA256,
        "bytes": PINNED_LAUNCHER_BYTES,
    },
    "argv_prefix": PINNED_PYTHON_ARGV_PREFIX,
    "executable": {
        "path": str(PINNED_PYTHON),
        "sha256": PINNED_PYTHON_SHA256,
        "bytes": PINNED_PYTHON_BYTES,
    },
    "version": PINNED_PYTHON_VERSION,
    "prefix": str(PINNED_PYTHON_PREFIX),
    "framework": {
        "path": str(PINNED_PYTHON_FRAMEWORK),
        "sha256": PINNED_PYTHON_FRAMEWORK_SHA256,
        "bytes": PINNED_PYTHON_FRAMEWORK_BYTES,
    },
    "app_executable": {
        "path": str(PINNED_PYTHON_APP),
        "sha256": PINNED_PYTHON_APP_SHA256,
        "bytes": PINNED_PYTHON_APP_BYTES,
    },
    "stdlib_inventory": PINNED_PYTHON_STDLIB_INVENTORY,
    "runtime_dynamic_closure": {
        "hashlib_extension": {
            "path": str(PINNED_HASHLIB_EXTENSION),
            "sha256": PINNED_HASHLIB_EXTENSION_SHA256,
            "bytes": PINNED_HASHLIB_EXTENSION_BYTES,
        },
        "libcrypto": {
            "path": str(PINNED_LIBCRYPTO),
            "sha256": PINNED_LIBCRYPTO_SHA256,
            "bytes": PINNED_LIBCRYPTO_BYTES,
        },
        "lzma_extension": {
            "path": str(PINNED_LZMA_EXTENSION),
            "sha256": PINNED_LZMA_EXTENSION_SHA256,
            "bytes": PINNED_LZMA_EXTENSION_BYTES,
        },
        "liblzma": {
            "path": str(PINNED_LIBLZMA),
            "sha256": PINNED_LIBLZMA_SHA256,
            "bytes": PINNED_LIBLZMA_BYTES,
        },
        "zstd_extension": {
            "path": str(PINNED_ZSTD_EXTENSION),
            "sha256": PINNED_ZSTD_EXTENSION_SHA256,
            "bytes": PINNED_ZSTD_EXTENSION_BYTES,
        },
        "libzstd": {
            "path": str(PINNED_LIBZSTD),
            "sha256": PINNED_LIBZSTD_SHA256,
            "bytes": PINNED_LIBZSTD_BYTES,
        },
        "openssl_configuration": {
            "conf": "/dev/null",
            "modules": "/var/empty",
            "modules_empty": True,
        },
        "system_policy": "darwin-sealed-system-volume",
    },
}

EXPECTED_PLATFORM = {
    "id": PLATFORM,
    "class": PLATFORM_CLASS,
    "physical_provenance": PHYSICAL_PROVENANCE,
    "decision_eligible": True,
    "machine": "virt",
    "cpu": "rv64",
    "hart_count": 1,
    "memory_mib": 128,
    "accelerator": "tcg,thread=single",
    "icount": "shift=0,align=off,sleep=off",
    "bios": "explicit-opensbi-riscv64-generic-fw_dynamic.bin",
    "bios_default_forbidden": True,
    "clock": "riscv.rdtime",
    "timebase_hz": TIMEBASE_HZ,
    "qemu_version_policy": "frozen-exact-v1",
    "qemu_version": PINNED_QEMU_VERSION,
    "qemu_binary_policy": "frozen-sha256-and-byte-length-v1",
    "qemu_binary": {"sha256": PINNED_QEMU_SHA256, "bytes": PINNED_QEMU_BYTES},
    "qemu_environment": EXPECTED_QEMU_ENVIRONMENT,
    "qemu_process_cwd": QEMU_PROCESS_CWD,
    "python_runtime": EXPECTED_PYTHON_RUNTIME,
    "bios_policy": "frozen-sha256-and-byte-length-v1",
    "bios_identity": {"sha256": PINNED_BIOS_SHA256, "bytes": PINNED_BIOS_BYTES},
    "host_os": "darwin",
    "openssh_policy": "frozen-darwin-system-volume-v1",
    "openssh_execution_path": "/usr/bin/ssh",
    "openssh_version": PINNED_OPENSSH_VERSION,
    "openssh_identity": {
        "sha256": PINNED_OPENSSH_SHA256,
        "bytes": PINNED_OPENSSH_BYTES,
    },
    "kernel_policy": "sha256-and-byte-length-recorded-per-evidence",
    "qemu_argv_policy": "single-generated-actual-plus-independent-normalization-v1",
    "qemu_normalized_argv": NORMALIZED_QEMU_ARGV,
    "qemu_runtime_policy": QEMU_RUNTIME_CLOSURE_POLICY,
    "qemu_runtime_graph_sha256": PINNED_QEMU_RUNTIME_GRAPH_SHA256,
    "qemu_runtime_counts": PINNED_QEMU_RUNTIME_COUNTS,
    "qemu_runtime_phase_policy": "source-and-execution-custody-pre-post-final-v1",
    "qemu_runtime_system_dependency_prefixes": QEMU_RUNTIME_SYSTEM_PREFIXES,
    "qemu_runtime_host_os_build": PINNED_DARWIN_HOST_BUILD,
    "qemu_module_search_policy": "no-plugin-argv-and-absent-qemu-module-directories-v1",
    "qemu_live_data_policy": "private-empty-directory-v1",
    "qemu_otool_custody": {
        "policy": OTOOL_CUSTODY_POLICY,
        "invocation_path": str(PINNED_OTOOL_INVOCATION),
        "resolved_path": str(PINNED_OTOOL_RESOLVED),
        "sha256": PINNED_OTOOL_SHA256,
        "bytes": PINNED_OTOOL_BYTES,
        "package_id": PINNED_CLT_PACKAGE_ID,
        "package_version": PINNED_CLT_VERSION,
    },
    "qemu_runtime_host_exclusivity_limit": QEMU_RUNTIME_HOST_LIMIT,
    "source_materialization_policy": "exact-commit-raw-blob-export-v1",
    "repository_local_config_policy": GIT_LOCAL_CONFIG_POLICY,
    "cargo_dependency_policy": (
        "project-and-rust-src-lock-union-checksum-verified-private-directory-source-v1"
    ),
    "cargo_registry_source": CRATES_IO_SOURCE,
    "cargo_project_lock_identity": {
        "sha256": PINNED_CARGO_LOCK_SHA256,
        "bytes": PINNED_CARGO_LOCK_BYTES,
        "packages": PINNED_CARGO_PACKAGES,
        "package_set_sha256": PINNED_CARGO_PACKAGE_SET_SHA256,
    },
    "cargo_rust_src_lock_identity": {
        "sha256": PINNED_RUST_SRC_CARGO_LOCK["sha256"],
        "bytes": PINNED_RUST_SRC_CARGO_LOCK["bytes"],
        "packages": PINNED_RUST_SRC_CARGO_PACKAGES,
        "package_set_sha256": PINNED_RUST_SRC_CARGO_PACKAGE_SET_SHA256,
    },
    "cargo_lock_union_identity": {
        "packages": PINNED_CARGO_UNION_PACKAGES,
        "exact_overlap": PINNED_CARGO_UNION_EXACT_OVERLAP,
        "project_only": PINNED_CARGO_UNION_PROJECT_ONLY,
        "rust_src_only": PINNED_CARGO_UNION_RUST_SRC_ONLY,
        "package_set_sha256": PINNED_CARGO_UNION_PACKAGE_SET_SHA256,
    },
    "private_crate_source_identity": PINNED_PRIVATE_CRATE_TREE,
    "private_crate_archive_identity": PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
    "cargo_configuration_policy": (
        "cwd-root-private-home-exact-config-deterministic-transients-v1"
    ),
    "cargo_cache_last_use_clock": "1234567890",
    "cargo_transient_output_set": [
        ".global-cache",
        ".package-cache",
        ".package-cache-mutate",
        "registry/CACHEDIR.TAG",
    ],
    "cargo_global_cache_identity": {
        "sha256": "66d946720de0afd44c2d5748698b700ce812830bd8a3dedaa589831610948d9d",
        "bytes": 57_344,
    },
    "cargo_cache_directory_tag_identity": {
        "sha256": "6d9d1d216e0f83abc5e5662ca62c92b4f23009466b54fa27321a69acdb778bb2",
        "bytes": 177,
    },
    "formal_cargo_cwd": "/",
    "build_environment_path": "/opt/homebrew/bin:/usr/bin:/bin",
    "rust_toolchain_resolution_policy": (
        "fixed-rustup-home-channel-host-no-rustup-execution-v1"
    ),
    "rust_toolchain_root": (
        "/Users/ziangwang/.rustup/toolchains/"
        "nightly-2026-08-01-aarch64-apple-darwin"
    ),
    "rust_toolchain_tree_identity": PINNED_TOOLCHAIN_TREE,
    "rust_src_identity": PINNED_RUST_SRC_TREE,
    "rust_src_cargo_toml_identity": PINNED_RUST_SRC_CARGO_TOML,
    "rust_src_cargo_lock_identity": PINNED_RUST_SRC_CARGO_LOCK,
    "linker_runtime_policy": "darwin-recursive-nonsystem-macho-closure-v1",
    "linker_runtime_sha256": PINNED_LLD_RUNTIME_SHA256,
    "execution_custody_policy": CUSTODY_SCHEME,
    "guest_platform_identity_excludes_host_paths": True,
}

EXPECTED_SAMPLING = {
    "fresh_qemu_processes": 1,
    "warmup_per_process": WARMUPS,
    "retained_per_process": RETAINED,
    "samples_per_process": SAMPLES,
    "retained_total": RETAINED,
    "order": "three discarded warmups followed by twenty-one retained samples in one fresh fixed-QEMU process",
    "statistics": {
        "p50": "nearest-rank index ceil(0.50*n)-1 after ascending sort",
        "p95": "nearest-rank index ceil(0.95*n)-1 after ascending sort",
        "p50_sorted_index": P50_SORTED_INDEX,
        "p95_sorted_index": P95_SORTED_INDEX,
        "decision_population": "the 21 retained samples from the one fresh fixed-QEMU process",
        "timer_overhead_subtracted": False,
        "stability": "p95(total_ticks) / p50(total_ticks) <= 1.10",
    },
}

EXPECTED_BUDGET = {
    "metric": "retained end-to-end response p95",
    "clock": "riscv.rdtime",
    "timebase_hz": TIMEBASE_HZ,
    "ticks": BUDGET_TICKS,
    "milliseconds": 100,
    "derivation": "the pre-frozen 100 ms workload budget multiplied by the fixed 10 MHz guest timebase",
    "calibrated_after_measurement": False,
    "comparison": "miss iff p95(total_ticks) > 1000000",
    "eligible_platform": PLATFORM,
}

EXPECTED_PHASES = [
    {"id": phase, "order": index + 1, "aot_attributable": phase == "interpretation"}
    for index, phase in enumerate(PHASE_IDS)
]

EXPECTED_TRANSCRIPT = {
    "framing": {
        "raw_scope": "one fresh fixed-QEMU process with no physical claim",
        "required_raw_transcripts": 1,
        "meta_records_per_raw": 1,
        "sample_records_per_raw": SAMPLES,
        "end_records_per_raw": 1,
        "warmups_per_raw": WARMUPS,
        "retained_per_raw": RETAINED,
        "maximum_raw_bytes": MAX_TRANSCRIPT_BYTES,
        "record_order": "META, SAMPLE sequence 0 through 23, END",
        "prefixes": {"meta": META_PREFIX, "sample": SAMPLE_PREFIX, "end": END_PREFIX},
        "forbidden_prefix": FORBIDDEN_AUDIT_PREFIX,
    },
    "run_id": {
        "domains": RUN_ID_DOMAINS,
        "algorithm": "sha256",
        "encoding": "domain followed by fields as NUL-separated ASCII values with no trailing NUL",
        "fields": [
            "source_commit",
            "challenge",
            "artifact_sha256",
            "input_sha256",
            "output_sha256",
            "manifest_sha256",
            "transcript_schema_sha256",
        ],
        "meaning": "identity of one source-bound QEMU campaign; it makes no cold-boot or physical-hardware claim",
    },
    "accumulator": {
        "width_bits": 64,
        "initial": 0,
        "update": "acc = rotl64(acc, 7).wrapping_add(word)",
        "sample_domain_word": BASE.SAMPLE_DOMAIN_WORD,
        "interval_domain_word": BASE.INTERVAL_DOMAIN_WORD,
        "phase_order": list(PHASE_IDS),
        "phase_codes": BASE.PHASE_CODES,
        "purpose": "ordered truncation and corruption check, not authentication",
    },
}

EXPECTED_DECISION_RULE = {
    "preconditions": "C1-C8.3 are accepted complete by historical-evidence policy and every QEMU-v1 C8.4 publication gate passes",
    "budget_miss": "p95(total_ticks) > 1000000",
    "interpretation_attribution": "p95(total_ticks - phase_ticks.interpretation) <= 1000000",
    "eligible_outcome": ELIGIBLE_OUTCOME,
    "otherwise_outcome": OTHERWISE_OUTCOME,
    "eligible_next_node": "C8.5 design review only",
    "otherwise_next_node": "skip or defer conditional C8.5-C8.7 and continue C8.8",
    "aot_authorized": False,
    "native_code_accepted": False,
}

EXPECTED_PUBLICATION_GATES = {
    "preparation_commit": "the contract, runner, verifier, and feature isolation are committed and the fixed remote directly advertises that commit before and after capture",
    "source": "the formal capture uses an exact raw-blob commit-and-gitlink export with frozen safe local Git configuration, a fresh private Cargo target, and binds the source commit and its timestamp into every build",
    "smoke_exclusion": "dirty smoke records dirty-worktree build provenance while retaining the fixed-origin policy, uses a distinct build feature, capture mode, ineligible META value, and run-id domain, and cannot be promoted into formal publication",
    "platform": "the frozen CPython launcher, executable, app executable, stdlib and dynamic runtime closure, QEMU and OpenSBI bytes, deny-by-default probe and process environments, actual and independently normalized QEMU argv, QEMU source/custody runtime closures and host-build-bound sealed-system edges, OpenSSH, private kernel, toolchain, executed Python source closure, and byte-identical execution custody are recorded and independently verified",
    "completeness": "one fresh QEMU transcript contains one META, exactly 24 ordered SAMPLE records, and one END",
    "correctness": "every sample exits zero, emits the exact output hash, emits empty stderr, and satisfies the frozen resource limits",
    "phase_partition": "intervals are ordered, gap-free, non-overlapping, complete, and sum exactly to total_ticks and phase_ticks",
    "stability": "the retained p95/p50 ratio is at most 1.10",
    "physical_exclusion": "the evidence and outcome explicitly claim no physical provenance and cannot be accepted by the Duo contract",
    "authorization": "neither outcome authorizes AOT, JIT, RWX, external native bytes, or bypass of authoritative component bytes and policy",
}


@dataclass(frozen=True)
class Contracts:
    manifest: dict[str, Any]
    schema: dict[str, Any]
    evidence_schema: dict[str, Any]
    manifest_raw: bytes
    schema_raw: bytes
    evidence_schema_raw: bytes

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.manifest_raw).hexdigest()

    @property
    def schema_sha256(self) -> str:
        return hashlib.sha256(self.schema_raw).hexdigest()

    @property
    def evidence_schema_sha256(self) -> str:
        return hashlib.sha256(self.evidence_schema_raw).hexdigest()


@dataclass(frozen=True)
class VerifiedTranscript:
    meta: dict[str, Any]
    samples: list[dict[str, Any]]
    ending: dict[str, Any]
    raw: bytes


def read_regular(path: pathlib.Path, label: str, maximum: int) -> bytes:
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        path_before = path.lstat()
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and not stat.S_ISLNK(path_before.st_mode)
            and before.st_nlink == 1,
            f"{label} must be one direct regular file",
        )
        require(
            0 < before.st_size <= maximum,
            f"{label} byte length is outside [1, {maximum}]",
        )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            require(bool(chunk), f"{label} became truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(os.read(descriptor, 1) == b"", f"{label} grew while reading")
        after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot read {label} {path}: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raw = b"".join(chunks)

    def signature(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    require(
        signature(path_before)
        == signature(before)
        == signature(after)
        == signature(path_after),
        f"{label} changed while reading",
    )
    require(len(raw) == before.st_size, f"{label} byte length changed while reading")
    return raw


def load_contracts() -> Contracts:
    manifest_raw = read_regular(MANIFEST_PATH, "QEMU manifest", MAX_CONTRACT_BYTES)
    schema_raw = read_regular(SCHEMA_PATH, "QEMU transcript schema", MAX_CONTRACT_BYTES)
    evidence_schema_raw = read_regular(
        EVIDENCE_SCHEMA_PATH, "QEMU evidence schema", MAX_CONTRACT_BYTES
    )
    validate_evidence_schema_raw(evidence_schema_raw)
    manifest = strict_json_bytes(manifest_raw, "QEMU manifest")
    schema = strict_json_bytes(schema_raw, "QEMU transcript schema")
    evidence_schema = strict_json_bytes(evidence_schema_raw, "QEMU evidence schema")
    require(
        type(manifest) is dict
        and type(schema) is dict
        and type(evidence_schema) is dict,
        "contract roots must be objects",
    )
    contracts = Contracts(
        manifest,
        schema,
        evidence_schema,
        manifest_raw,
        schema_raw,
        evidence_schema_raw,
    )
    validate_manifest(contracts.manifest)
    validate_schema(contracts.schema)
    validate_evidence_schema(contracts.evidence_schema)
    # These checks close the named product artifact and the exact OpenSSH
    # fixture against their reviewed source implementations. Merely repeating
    # their frozen hashes in this verifier would not establish that identity.
    BASE.image_identity()
    BASE.openssh_fixture_identity()
    validate_clock_source_closure()
    validate_base_build_stdin_source_closure()
    validate_runner_qemu_environment_source_closure()
    validate_private_checksum_encoder_source_closure()
    return contracts


def rust_character_literal_end(source: str, start: int) -> int | None:
    """Return the end of one Rust character literal, but not a lifetime."""

    require(source[start] == "'", "Rust character scanner did not start at a quote")
    cursor = start + 1
    if cursor >= len(source) or source[cursor] in "'\r\n":
        return None
    if source[cursor] == "\\":
        cursor += 1
        if cursor >= len(source):
            return None
        if source[cursor] == "x":
            cursor += 3
        elif source[cursor] == "u" and source.startswith("u{", cursor):
            closing = source.find("}", cursor + 2)
            if closing < 0:
                return None
            cursor = closing + 1
        else:
            cursor += 1
    else:
        cursor += 1
    if cursor < len(source) and source[cursor] == "'":
        return cursor + 1
    return None


def rust_lexical_mask(raw: bytes, label: str, *, mask_literals: bool = True) -> str:
    """Mask Rust comments and literals while preserving offsets and newlines."""

    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not strict UTF-8: {error}") from error
    output = list(source)
    index = 0
    block_depth = 0
    state = "code"
    raw_hashes = 0

    def blank(start: int, end: int) -> None:
        for cursor in range(start, end):
            if output[cursor] not in "\r\n":
                output[cursor] = " "

    while index < len(source):
        if state == "line-comment":
            if source[index] in "\r\n":
                state = "code"
            else:
                blank(index, index + 1)
            index += 1
            continue
        if state == "block-comment":
            if source.startswith("/*", index):
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index, index + 2)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                blank(index, index + 1)
                index += 1
            continue
        if state == "string":
            if source[index] == "\\":
                if mask_literals:
                    blank(index, min(index + 2, len(source)))
                index += 2
            elif source[index] == '"':
                if mask_literals:
                    blank(index, index + 1)
                index += 1
                state = "code"
            else:
                if mask_literals:
                    blank(index, index + 1)
                index += 1
            continue
        if state == "raw-string":
            ending = '"' + "#" * raw_hashes
            if source.startswith(ending, index):
                if mask_literals:
                    blank(index, index + len(ending))
                index += len(ending)
                state = "code"
            else:
                if mask_literals:
                    blank(index, index + 1)
                index += 1
            continue

        if source.startswith("//", index):
            blank(index, index + 2)
            index += 2
            state = "line-comment"
            continue
        if source.startswith("/*", index):
            blank(index, index + 2)
            index += 2
            block_depth = 1
            state = "block-comment"
            continue
        raw_match = re.match(r"(?:br|cr|r)(?P<hashes>#{0,255})\"", source[index:])
        if raw_match is not None:
            raw_hashes = len(raw_match.group("hashes"))
            ending = index + raw_match.end()
            if mask_literals:
                blank(index, ending)
            index = ending
            state = "raw-string"
            continue
        string_match = re.match(r'(?:b|c)?"', source[index:])
        if string_match is not None:
            ending = index + string_match.end()
            if mask_literals:
                blank(index, ending)
            index = ending
            state = "string"
            continue
        character_start = index + 1 if source.startswith("b'", index) else index
        if source[character_start : character_start + 1] == "'":
            character_end = rust_character_literal_end(source, character_start)
            if character_end is not None:
                if mask_literals:
                    blank(index, character_end)
                index = character_end
                continue
        index += 1

    require(
        state not in {"block-comment", "string", "raw-string"},
        f"{label} has an unterminated Rust lexical item",
    )
    return "".join(output)


def rust_item_scope(
    source: str, masked: str, declaration: str, label: str
) -> tuple[re.Match[str], str]:
    matches = list(re.finditer(declaration, masked, re.MULTILINE))
    require(len(matches) == 1, f"{label} declaration count differs: {len(matches)}")
    match = matches[0]
    depth = 0
    for character in masked[: match.start()]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        require(depth >= 0, f"{label} source has an unbalanced prefix")
    require(depth == 0, f"{label} is not a top-level Rust item")
    opening = masked.find("{", match.end())
    require(opening >= 0, f"{label} has no body")
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return match, source[match.start() : cursor + 1]
        require(depth >= 0, f"{label} body is unbalanced")
    raise VerificationError(f"{label} body is unterminated")


def adjacent_rust_attributes(source: str, masked: str, offset: int) -> list[str]:
    cursor = offset
    attributes: list[str] = []
    while True:
        while cursor > 0 and masked[cursor - 1].isspace():
            cursor -= 1
        if cursor == 0 or masked[cursor - 1] != "]":
            break
        depth = 0
        opening = -1
        for index in range(cursor - 1, -1, -1):
            if masked[index] == "]":
                depth += 1
            elif masked[index] == "[":
                depth -= 1
                if depth == 0:
                    opening = index
                    break
        if opening <= 0 or masked[opening - 1] != "#":
            break
        attributes.append(source[opening - 1 : cursor])
        cursor = opening - 1
    return list(reversed(attributes))


def compact_rust(value: str) -> str:
    return re.sub(r"\s+", "", value)


def validate_clock_source_bytes(
    slot: bytes, kernel_root: bytes, bare: bytes, board: bytes
) -> None:
    slot_source = slot.decode("utf-8", errors="strict")
    slot_masked = rust_lexical_mask(slot, "QEMU live-tick source")
    require(
        len(re.findall(r"\bfn\s+live_tick\s*\(", slot_masked)) == 1,
        "QEMU clock closure must contain one live_tick declaration",
    )
    slot_match, slot_item = rust_item_scope(
        slot_source,
        slot_masked,
        r"\bfn\s+live_tick\s*\(\s*\)\s*->\s*u64\s*",
        "QEMU live_tick",
    )
    require(
        adjacent_rust_attributes(slot_source, slot_masked, slot_match.start()) == [],
        "QEMU live_tick must be an unconditional item",
    )
    require(
        re.fullmatch(
            r"fn\s+live_tick\s*\(\s*\)\s*->\s*u64\s*"
            r"\{\s*crate::sbi::time\s*\(\s*\)\s*\}",
            slot_item,
        )
        is not None,
        "QEMU clock closure must contain one live_tick -> crate::sbi::time edge",
    )

    kernel_source = kernel_root.decode("utf-8", errors="strict")
    kernel_masked = rust_lexical_mask(kernel_root, "QEMU kernel root source")
    reexports = list(
        re.finditer(r"\bpub\s+use\s+vibeos_runtime_riscv\s+as\s+sbi\s*;", kernel_masked)
    )
    require(
        len(reexports) == 1,
        "QEMU clock closure must contain one runtime-riscv -> crate::sbi re-export",
    )
    reexport = reexports[0]
    depth = 0
    for character in kernel_masked[: reexport.start()]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        require(depth >= 0, "QEMU kernel root has an unbalanced prefix")
    require(depth == 0, "QEMU runtime-riscv re-export is not top-level")
    reexport_attributes = adjacent_rust_attributes(
        kernel_source, kernel_masked, reexport.start()
    )
    require(
        [compact_rust(value) for value in reexport_attributes]
        == ['#[cfg(all(target_arch="riscv64",target_os="none"))]'],
        "QEMU runtime-riscv re-export target guard differs",
    )

    bare_source = bare.decode("utf-8", errors="strict")
    bare_masked = rust_lexical_mask(bare, "RISC-V rdtime source")
    require(
        len(re.findall(r"\bpub\s+fn\s+time\s*\(", bare_masked)) == 1,
        "QEMU clock closure must contain one runtime time declaration",
    )
    time_match, time_item = rust_item_scope(
        bare_source,
        bare_masked,
        r"\bpub\s+fn\s+time\s*\(\s*\)\s*->\s*u64\s*",
        "RISC-V time",
    )
    require(
        [
            compact_rust(value)
            for value in adjacent_rust_attributes(
                bare_source, bare_masked, time_match.start()
            )
        ]
        == ["#[inline]"],
        "RISC-V time attributes differ",
    )
    require(
        re.fullmatch(
            r"pub\s+fn\s+time\s*\(\s*\)\s*->\s*u64\s*\{\s*"
            r"let\s+t\s*:\s*u64\s*;\s*unsafe\s*\{\s*"
            r"asm!\s*\(\s*\"rdtime \{\}\"\s*,\s*out\s*\(\s*reg\s*\)\s+t\s*\)\s*"
            r"\}\s*;\s*t\s*\}",
            time_item,
        )
        is not None,
        "QEMU clock closure must contain one crate::sbi::time -> rdtime edge",
    )

    board_source = board.decode("utf-8", errors="strict")
    board_masked = rust_lexical_mask(board, "QEMU board timebase source")
    declarations = list(re.finditer(r"\bpub\s+const\s+TIMEBASE_HZ\b", board_masked))
    require(
        len(declarations) == 1,
        "QEMU clock closure must contain one TIMEBASE_HZ declaration",
    )
    declaration = declarations[0]
    depth = 0
    for character in board_masked[: declaration.start()]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        require(depth >= 0, "QEMU board source has an unbalanced prefix")
    require(depth == 0, "QEMU TIMEBASE_HZ declaration is not top-level")
    require(
        adjacent_rust_attributes(board_source, board_masked, declaration.start()) == [],
        "QEMU TIMEBASE_HZ must be an unconditional item",
    )
    board_items = list(
        re.finditer(
            r"\bpub\s+const\s+TIMEBASE_HZ\s*:\s*u64\s*=\s*10_000_000\s*;",
            board_masked,
        )
    )
    require(
        len(board_items) == 1 and board_items[0].start() == declaration.start(),
        "QEMU clock closure must contain one 10 MHz board constant",
    )


def validate_clock_source_closure() -> None:
    slot = read_regular(
        ROOT / "kernel/src/wasm_aot_profile_slot.rs",
        "QEMU live-tick source",
        MAX_JSON_BYTES,
    )
    kernel_root = read_regular(
        ROOT / "kernel/src/lib.rs", "QEMU kernel root source", MAX_JSON_BYTES
    )
    bare = read_regular(
        ROOT / "runtime/riscv/src/bare.rs", "RISC-V rdtime source", MAX_JSON_BYTES
    )
    board = read_regular(
        ROOT / "boards/qemu-virt/src/lib.rs",
        "QEMU board timebase source",
        MAX_JSON_BYTES,
    )
    validate_clock_source_bytes(slot, kernel_root, bare, board)


def ast_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = ast_dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def ast_unique_function(module: ast.Module, name: str) -> ast.FunctionDef:
    functions = [
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    require(len(functions) == 1, f"QEMU runner {name} function count differs")
    return functions[0]


def ast_unique_call(function: ast.FunctionDef, name: str) -> ast.Call:
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and ast_dotted_name(node.func) == name
    ]
    require(
        len(calls) == 1,
        f"QEMU runner {function.name} {name} call count differs",
    )
    return calls[0]


def ast_keyword_name(call: ast.Call, keyword: str, label: str) -> str:
    values = [item.value for item in call.keywords if item.arg == keyword]
    require(len(values) == 1, f"{label} {keyword} keyword count differs")
    require(isinstance(values[0], ast.Name), f"{label} {keyword} is not one name")
    return values[0].id


def validate_private_checksum_encoder_source_bytes(raw: bytes) -> None:
    try:
        source = raw.decode("utf-8", errors="strict")
        module = ast.parse(
            source, filename="scripts/verify-c84-qemu-aot-decision.py"
        )
    except (UnicodeDecodeError, SyntaxError) as error:
        raise VerificationError(
            f"cannot parse QEMU verifier checksum source: {error}"
        ) from error

    encoder = ast_unique_function(module, "canonical_compact_json")
    expected_encoder = ast.parse(
        """def canonical_compact_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(\",\", \":\"), ensure_ascii=True)
        + \"\\n\"
    ).encode(\"ascii\")
"""
    ).body[0]
    require(
        ast.dump(encoder, include_attributes=False)
        == ast.dump(expected_encoder, include_attributes=False),
        "QEMU verifier compact Cargo checksum encoder differs",
    )

    verifier = ast_unique_function(module, "verify_private_crates")
    expected_call = ast.parse(
        'canonical_compact_json({"files": dict(sorted(checksums.items())), '
        '"package": package["checksum"]})',
        mode="eval",
    ).body
    observed: dict[str, ast.Call] = {}
    for node in ast.walk(verifier):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and ast_dotted_name(node.value.func) == "canonical_compact_json"
        ):
            name = node.targets[0].id
            require(name not in observed, "QEMU verifier checksum encoder repeats")
            observed[name] = node.value
    require(
        set(observed) == {"installed_checksum", "checksum_raw"},
        "QEMU verifier must use the compact checksum encoder in both source branches",
    )
    for name, call in observed.items():
        require(
            ast.dump(call, include_attributes=False)
            == ast.dump(expected_call, include_attributes=False),
            f"QEMU verifier {name} compact checksum payload differs",
        )

    local_configs = ast_unique_function(module, "live_local_config_records")
    expected_local_config_hash = ast.parse(
        "hashlib.sha256(canonical_compact_json(parsed)).hexdigest()",
        mode="eval",
    ).body
    local_config_hashes = [
        node
        for node in ast.walk(local_configs)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "hexdigest"
    ]
    require(
        len(local_config_hashes) == 1
        and ast.dump(local_config_hashes[0], include_attributes=False)
        == ast.dump(expected_local_config_hash, include_attributes=False),
        "QEMU verifier local Git config must use the compact evidence encoder",
    )


def validate_private_checksum_encoder_source_closure() -> None:
    raw = read_regular(
        pathlib.Path(__file__).resolve(),
        "QEMU verifier checksum source",
        MAX_JSON_BYTES,
    )
    validate_private_checksum_encoder_source_bytes(raw)


def validate_base_build_stdin_source_bytes(raw: bytes) -> None:
    try:
        source = raw.decode("utf-8", errors="strict")
        module = ast.parse(source, filename="scripts/qemu-c83-runtime-costs.py")
    except (UnicodeDecodeError, SyntaxError) as error:
        raise VerificationError(f"cannot parse QEMU base runner source: {error}") from error

    build = ast_unique_function(module, "build_kernel")
    build_keyword_parameters = {
        argument.arg for argument in build.args.kwonlyargs
    }
    require(
        "private_crate_archives" in build_keyword_parameters,
        "QEMU base runner build contract omits private crate archives",
    )
    cargo_runs = [
        node
        for node in ast.walk(build)
        if isinstance(node, ast.Call)
        and ast_dotted_name(node.func) == "subprocess.run"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "command"
    ]
    require(
        len(cargo_runs) == 2,
        "QEMU base runner Cargo subprocess count differs",
    )
    for call in cargo_runs:
        stdin_values = [item.value for item in call.keywords if item.arg == "stdin"]
        require(
            len(stdin_values) == 1
            and ast_dotted_name(stdin_values[0]) == "subprocess.DEVNULL",
            "QEMU base runner Cargo subprocess inherits ambient stdin",
        )
    formal_runs = [
        call
        for call in cargo_runs
        if any(
            item.arg == "cwd"
            and isinstance(item.value, ast.Constant)
            and item.value.value == "/"
            for item in call.keywords
        )
    ]
    require(len(formal_runs) == 1, "QEMU base runner formal Cargo cwd differs")
    umask_values = [
        item.value for item in formal_runs[0].keywords if item.arg == "umask"
    ]
    require(
        len(umask_values) == 1
        and isinstance(umask_values[0], ast.Constant)
        and umask_values[0].value == 0o077,
        "QEMU base runner formal Cargo umask differs",
    )
    ast_unique_function(module, "remove_private_cargo_transient_outputs")
    for literal, label in (
        ('"__CARGO_TEST_LAST_USE_NOW": "1234567890"', "cache last-use clock"),
        ('auto-clean-frequency = "never"', "cache auto-clean policy"),
        (
            "66d946720de0afd44c2d5748698b700ce812830bd8a3dedaa589831610948d9d",
            "global cache identity",
        ),
        ('".package-cache-mutate"', "package-cache-mutate output"),
    ):
        require(literal in source, f"QEMU base runner {label} closure differs")


def validate_base_build_stdin_source_closure() -> None:
    raw = read_regular(
        BASE_RUNNER_PATH, "QEMU base runner source", MAX_JSON_BYTES
    )
    validate_base_build_stdin_source_bytes(raw)


def validate_runner_qemu_environment_source_bytes(raw: bytes) -> None:
    try:
        source = raw.decode("utf-8", errors="strict")
        module = ast.parse(source, filename="scripts/qemu-c84-aot-decision.py")
    except (UnicodeDecodeError, SyntaxError) as error:
        raise VerificationError(f"cannot parse QEMU runner source: {error}") from error

    factory = ast_unique_function(module, "create_qemu_environment")
    firmware_probe = ast_unique_function(module, "resolve_bios")
    probe = ast_unique_function(module, "run_qemu_version")
    capture = ast_unique_function(module, "capture_qemu")
    exporter = ast_unique_function(module, "export_git_tree")
    build_wrapper = ast_unique_function(module, "build_kernel")
    main = ast_unique_function(module, "main")
    base_build_call = ast_unique_call(build_wrapper, "BASE.build_kernel")
    require(
        ast_keyword_name(
            base_build_call,
            "private_crate_archives",
            "QEMU runner base build archive closure",
        )
        == "private_crate_archives",
        "QEMU runner does not pass private crate archives to its base build",
    )
    for function in (firmware_probe, probe, capture):
        parameters = {
            argument.arg
            for argument in (*function.args.args, *function.args.kwonlyargs)
        }
        require(
            "qemu_environment" in parameters,
            f"QEMU runner {function.name} does not accept the shared environment",
        )
        validations = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and ast_dotted_name(node.func) == "validate_qemu_environment"
        ]
        expected_validations = 2 if function in (firmware_probe, probe) else 1
        require(
            len(validations) == expected_validations
            and all(
                len(validation.args) == 1
                and isinstance(validation.args[0], ast.Name)
                and validation.args[0].id == "qemu_environment"
                and not validation.keywords
                for validation in validations
            ),
            f"QEMU runner {function.name} does not validate its explicit environment before/after use",
        )

    factory_returns = [
        node for node in ast.walk(factory) if isinstance(node, ast.Return)
    ]
    require(
        len(factory_returns) == 1
        and isinstance(factory_returns[0].value, ast.Tuple)
        and [
            element.id if isinstance(element, ast.Name) else None
            for element in factory_returns[0].value.elts
        ]
        == ["environment", "record"],
        "QEMU environment factory return binding differs",
    )

    probe_run = ast_unique_call(probe, "subprocess.run")
    probe_env = ast_keyword_name(probe_run, "env", "QEMU version probe")
    require(
        probe_env == "qemu_environment",
        "QEMU version probe does not use its explicit environment",
    )
    require(
        len(probe_run.args) == 1
        and isinstance(probe_run.args[0], ast.List)
        and len(probe_run.args[0].elts) == 3
        and isinstance(probe_run.args[0].elts[0], ast.Name)
        and probe_run.args[0].elts[0].id == "qemu"
        and isinstance(probe_run.args[0].elts[1], ast.Constant)
        and probe_run.args[0].elts[1].value == "-no-user-config"
        and isinstance(probe_run.args[0].elts[2], ast.Constant)
        and probe_run.args[0].elts[2].value == "--version",
        "QEMU version probe argv differs",
    )
    firmware_run = ast_unique_call(firmware_probe, "subprocess.run")
    require(
        ast_keyword_name(firmware_run, "env", "QEMU firmware probe")
        == "qemu_environment",
        "QEMU firmware probe does not use its explicit environment",
    )
    require(
        len(firmware_run.args) == 1
        and isinstance(firmware_run.args[0], ast.List)
        and [
            element.id if isinstance(element, ast.Name) else element.value
            if isinstance(element, ast.Constant)
            else None
            for element in firmware_run.args[0].elts
        ]
        == ["qemu", "-no-user-config", "-L", "help"],
        "QEMU firmware probe argv differs",
    )

    live_popen = ast_unique_call(capture, "subprocess.Popen")
    live_env = ast_keyword_name(live_popen, "env", "live QEMU process")
    require(
        live_env == "qemu_environment",
        "live QEMU process does not use its explicit environment",
    )
    live_cwd = [item.value for item in live_popen.keywords if item.arg == "cwd"]
    require(
        len(live_cwd) == 1
        and isinstance(live_cwd[0], ast.Call)
        and ast_dotted_name(live_cwd[0].func) == "pathlib.Path"
        and len(live_cwd[0].args) == 1
        and isinstance(live_cwd[0].args[0], ast.Constant)
        and live_cwd[0].args[0].value == QEMU_PROCESS_CWD
        and not live_cwd[0].keywords,
        "live QEMU process cwd is not filesystem root",
    )
    require(
        len(live_popen.args) == 1
        and isinstance(live_popen.args[0], ast.Name)
        and live_popen.args[0].id == "qemu_argv",
        "live QEMU process does not use the immutable actual argv",
    )
    all_popen = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and ast_dotted_name(node.func) == "subprocess.Popen"
    ]
    exporter_popen = ast_unique_call(exporter, "subprocess.Popen")
    require(
        len(all_popen) == 2
        and live_popen in all_popen
        and exporter_popen in all_popen
        and len(exporter_popen.args) == 1
        and isinstance(exporter_popen.args[0], ast.Name)
        and exporter_popen.args[0].id == "command"
        and ast_keyword_name(exporter_popen, "env", "raw Git exporter")
        == "environment",
        "QEMU runner contains an unclosed process launch",
    )

    factory_calls = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and ast_dotted_name(node.value.func) == "create_qemu_environment"
    ]
    require(len(factory_calls) == 1, "QEMU environment factory call count differs")
    assignment = factory_calls[0]
    require(
        len(assignment.targets) == 1
        and isinstance(assignment.targets[0], ast.Tuple)
        and [
            element.id if isinstance(element, ast.Name) else None
            for element in assignment.targets[0].elts
        ]
        == ["qemu_process_environment", "qemu_environment_record"],
        "QEMU environment factory assignment differs",
    )
    main_probe = ast_unique_call(main, "run_qemu_version")
    main_firmware_probe = ast_unique_call(main, "resolve_bios")
    main_capture = ast_unique_call(main, "capture_qemu")
    main_module_searches = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Call)
        and ast_dotted_name(node.func) == "qemu_module_search_record"
    ]
    require(
        len(main_module_searches) == 2,
        "main QEMU module-search closure call count differs",
    )
    for module_search in main_module_searches:
        require(
            len(module_search.args) == 1
            and isinstance(module_search.args[0], ast.Name)
            and module_search.args[0].id == "qemu_path"
            and ast_keyword_name(
                module_search, "qemu_environment", "main QEMU module search"
            )
            == "qemu_process_environment"
            and ast_keyword_name(module_search, "qemu_argv", "main QEMU module search")
            == "actual_qemu_argv"
            and ast_keyword_name(
                module_search, "data_directory", "main QEMU module search"
            )
            == "qemu_data_directory",
            "main QEMU module-search closure wiring differs",
        )
    require(
        assignment.lineno < main_firmware_probe.lineno,
        "QEMU environment is created after the firmware probe",
    )
    kernel_identity_assignments = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "kernel_identity"
    ]
    require(
        len(kernel_identity_assignments) == 1
        and kernel_identity_assignments[0].lineno < main_firmware_probe.lineno,
        "kernel identity is not frozen before the firmware probe",
    )
    require(
        ast_keyword_name(
            main_firmware_probe, "qemu_environment", "main QEMU firmware probe"
        )
        == "qemu_process_environment",
        "main does not pass the created environment to the firmware probe",
    )
    require(
        ast_keyword_name(main_probe, "qemu_environment", "main QEMU version probe")
        == "qemu_process_environment",
        "main does not pass the created environment to the QEMU version probe",
    )
    require(
        ast_keyword_name(main_capture, "qemu_environment", "main live QEMU process")
        == "qemu_process_environment",
        "main does not pass the same environment to the live QEMU process",
    )
    require(
        ast_keyword_name(main_capture, "qemu_argv", "main live QEMU argv")
        == "actual_qemu_argv",
        "main does not pass the recorded actual argv to QEMU",
    )
    write_environment = ast_unique_call(main, "write_environment")
    require(
        ast_keyword_name(
            write_environment, "qemu_environment", "QEMU evidence writer"
        )
        == "qemu_environment_record",
        "main does not record the normalized QEMU environment",
    )
    require(
        ast_keyword_name(write_environment, "qemu_actual_argv", "QEMU evidence argv")
        == "actual_qemu_argv",
        "main does not record the exact argv passed to QEMU",
    )


def validate_runner_qemu_environment_source_closure() -> None:
    raw = read_regular(RUNNER_PATH, "QEMU runner source", MAX_JSON_BYTES)
    validate_runner_qemu_environment_source_bytes(raw)


def validate_evidence_schema_raw(raw: bytes) -> None:
    require(
        hashlib.sha256(raw).hexdigest() == EVIDENCE_SCHEMA_SHA256,
        "QEMU evidence schema raw byte identity differs",
    )


def validate_manifest(value: dict[str, Any]) -> None:
    exact_keys(
        value,
        {
            "schema",
            "version",
            "suite_id",
            "workload_revision",
            "scope",
            "capture_modes",
            "fixture",
            "platform",
            "sampling",
            "budget",
            "phases",
            "transcript",
            "decision_rule",
            "publication_gates",
        },
        "QEMU manifest",
    )
    exact_literal(
        value["schema"], "vibeos.wasm-aot-decision.manifest", "manifest.schema"
    )
    exact_literal(value["version"], 1, "manifest.version")
    exact_literal(value["suite_id"], SUITE, "manifest.suite_id")
    exact_literal(value["workload_revision"], 1, "manifest.workload_revision")
    exact_literal(value["scope"], EXPECTED_SCOPE, "manifest.scope")
    exact_literal(
        value["capture_modes"], EXPECTED_CAPTURE_MODES, "manifest.capture_modes"
    )
    exact_literal(value["fixture"], EXPECTED_FIXTURE, "manifest.fixture")
    exact_literal(value["platform"], EXPECTED_PLATFORM, "manifest.platform")
    exact_literal(value["sampling"], EXPECTED_SAMPLING, "manifest.sampling")
    exact_literal(value["budget"], EXPECTED_BUDGET, "manifest.budget")
    exact_literal(value["phases"], EXPECTED_PHASES, "manifest.phases")
    exact_literal(value["transcript"], EXPECTED_TRANSCRIPT, "manifest.transcript")
    exact_literal(
        value["decision_rule"], EXPECTED_DECISION_RULE, "manifest.decision_rule"
    )
    exact_literal(
        value["publication_gates"],
        EXPECTED_PUBLICATION_GATES,
        "manifest.publication_gates",
    )
    require(BUDGET_TICKS * 1000 == 100 * TIMEBASE_HZ, "budget conversion differs")
    require(
        RETAINED == 21 and P95_SORTED_INDEX == 19, "nearest-rank population differs"
    )


def expected_schema() -> dict[str, Any]:
    def closed(properties: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": list(properties),
        }

    phase_ticks = {phase: {"$ref": "#/$defs/u64"} for phase in PHASE_IDS}
    interval = {
        "sequence": {"type": "integer", "minimum": 0, "maximum": 65_535},
        "phase": {"$ref": "#/$defs/phase"},
        "start_offset_ticks": {"$ref": "#/$defs/u64"},
        "end_offset_ticks": {"$ref": "#/$defs/positiveU64"},
    }
    meta = {
        "schema": {"const": "vibeos.wasm-aot-decision.meta"},
        "version": {"const": 1},
        "suite_id": {"const": SUITE},
        "workload_revision": {"const": 1},
        "source_commit": {"$ref": "#/$defs/hex40"},
        "challenge": {"$ref": "#/$defs/hex64"},
        "run_id": {"$ref": "#/$defs/hex64"},
        "manifest_sha256": {"$ref": "#/$defs/hex64"},
        "transcript_schema_sha256": {"$ref": "#/$defs/hex64"},
        "platform": {"const": PLATFORM},
        "platform_class": {"const": PLATFORM_CLASS},
        "physical_provenance": {"const": PHYSICAL_PROVENANCE},
        "capture_mode": {"enum": list(CAPTURE_MODES)},
        "decision_eligible": {"type": "boolean"},
        "clock": {"const": "riscv.rdtime"},
        "timebase_hz": {"const": TIMEBASE_HZ},
        "hart_id": {"const": 0},
        "hart_count": {"const": 1},
        "transcript_scope": {"const": TRANSCRIPT_SCOPE},
        "required_qemu_boots": {"const": 1},
        "samples_per_boot": {"const": SAMPLES},
        "warmup_per_boot": {"const": WARMUPS},
        "retained_per_boot": {"const": RETAINED},
        "workload_id": {"const": EXPECTED_FIXTURE["id"]},
        "artifact_sha256": {"const": EXPECTED_FIXTURE["artifact"]["sha256"]},
        "artifact_bytes": {"const": EXPECTED_FIXTURE["artifact"]["byte_len"]},
        "input_sha256": {"const": EXPECTED_FIXTURE["input"]["sha256"]},
        "input_bytes": {"const": EXPECTED_FIXTURE["input"]["byte_len"]},
        "output_sha256": {"const": EXPECTED_FIXTURE["output"]["sha256"]},
        "output_bytes": {"const": EXPECTED_FIXTURE["output"]["byte_len"]},
        "budget_ticks": {"const": BUDGET_TICKS},
    }
    sample = {
        "schema": {"const": "vibeos.wasm-aot-decision.sample"},
        "version": {"const": 1},
        "run_id": {"$ref": "#/$defs/hex64"},
        "challenge": {"$ref": "#/$defs/hex64"},
        "sequence": {"type": "integer", "minimum": 0, "maximum": 23},
        "sample_index": {"type": "integer", "minimum": 0, "maximum": 23},
        "warmup": {"type": "boolean"},
        "workload_id": {"const": EXPECTED_FIXTURE["id"]},
        "total_ticks": {"$ref": "#/$defs/positiveU64"},
        "phase_ticks": {"$ref": "#/$defs/phaseTicks"},
        "interval_capacity": {"const": INTERVAL_CAPACITY},
        "interval_count": {
            "type": "integer",
            "minimum": 1,
            "maximum": INTERVAL_CAPACITY,
        },
        "intervals_complete": {"const": True},
        "intervals": {
            "type": "array",
            "minItems": 1,
            "maxItems": INTERVAL_CAPACITY,
            "items": {"$ref": "#/$defs/interval"},
        },
        "read_chunks": {"const": 13},
        "write_chunks": {"const": 13},
        "fuel_consumed": {"type": "integer", "minimum": 1, "maximum": 500_000},
        "poll_quanta": {"$ref": "#/$defs/positiveU64"},
        "terminal": {"const": "success"},
        "logical_live_after": {"const": 0},
        "timed_out": {"const": False},
        "timeout_phase": {"const": "none"},
        "exit_status": {"const": 0},
        "stdout_bytes": {"const": 12325},
        "stdout_sha256": {"const": EXPECTED_FIXTURE["output"]["sha256"]},
        "stderr_bytes": {"const": 0},
    }
    meta_schema = closed(meta)
    meta_schema["oneOf"] = [
        {
            "properties": {
                "capture_mode": {"const": FORMAL_CAPTURE_MODE},
                "decision_eligible": {"const": True},
            },
            "required": ["capture_mode", "decision_eligible"],
        },
        {
            "properties": {
                "capture_mode": {"const": SMOKE_CAPTURE_MODE},
                "decision_eligible": {"const": False},
            },
            "required": ["capture_mode", "decision_eligible"],
        },
    ]
    ending = {
        "schema": {"const": "vibeos.wasm-aot-decision.end"},
        "version": {"const": 1},
        "run_id": {"$ref": "#/$defs/hex64"},
        "challenge": {"$ref": "#/$defs/hex64"},
        "samples": {"const": SAMPLES},
        "warmups": {"const": WARMUPS},
        "retained": {"const": RETAINED},
        "accumulator": {"$ref": "#/$defs/u64"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://vibeos.invalid/schemas/wasm-aot-decision-qemu-v1.json",
        "title": "VibeOS C8.4 fixed-QEMU AOT-decision transcript records",
        "oneOf": [
            {"$ref": "#/$defs/meta"},
            {"$ref": "#/$defs/sample"},
            {"$ref": "#/$defs/end"},
        ],
        "$defs": {
            "hex40": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "hex64": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "u64": {"type": "integer", "minimum": 0, "maximum": U64_MAX},
            "positiveU64": {"type": "integer", "minimum": 1, "maximum": U64_MAX},
            "phase": {"type": "string", "enum": list(PHASE_IDS)},
            "phaseTicks": closed(phase_ticks),
            "interval": closed(interval),
            "meta": meta_schema,
            "sample": closed(sample),
            "end": closed(ending),
        },
    }


def validate_schema(value: dict[str, Any]) -> None:
    exact_literal(value, expected_schema(), "QEMU transcript schema")


def validate_evidence_schema(value: dict[str, Any]) -> None:
    exact_keys(
        value, {"$schema", "$id", "title", "oneOf", "$defs"}, "QEMU evidence schema"
    )
    exact_literal(
        value["$schema"],
        "https://json-schema.org/draft/2020-12/schema",
        "evidence schema.$schema",
    )
    exact_literal(
        value["$id"],
        "https://vibeos.invalid/schemas/wasm-aot-decision-qemu-evidence-v1.json",
        "evidence schema.$id",
    )
    exact_literal(
        value["title"],
        "VibeOS C8.4 fixed-QEMU AOT-decision summary, environment, and decision evidence",
        "evidence schema.title",
    )
    exact_literal(
        value["oneOf"],
        [
            {"$ref": "#/$defs/summary"},
            {"$ref": "#/$defs/environment"},
            {"$ref": "#/$defs/decisionEnvelope"},
        ],
        "evidence schema.oneOf",
    )
    definitions = exact_keys(
        value["$defs"],
        {
            "hex40",
            "hex64",
            "positiveInteger",
            "identity",
            "pathIdentity",
            "distribution",
            "statistics",
            "derivedDecision",
            "retainedSample",
            "summary",
            "repository",
            "localGitConfig",
            "inventoryRecord",
            "submoduleInventory",
            "sourceMaterialization",
            "custodyIdentity",
            "darwinRootVolume",
            "darwinHostBuild",
            "darwinSystemOpenSsh",
            "executionCustody",
            "helpers",
            "hostKeyEvidence",
            "linkerIdentity",
            "treeIdentity",
            "privateCargoHome",
            "rootCargoConfigAbsence",
            "machoSymlink",
            "machoDependency",
            "machoNode",
            "otoolCustody",
            "linkerRuntimeClosure",
            "qemuMachoNode",
            "qemuRuntimeClosure",
            "qemuRuntimePhaseSet",
            "qemuModuleSearch",
            "qemuRuntimeClosures",
            "buildInputClosure",
            "buildEnvironment",
            "qemuEnvironment",
            "toolchain",
            "environment",
            "contractIdentity",
            "decisionEnvelope",
        },
        "evidence schema.$defs",
    )
    exact_literal(
        definitions["hex40"],
        {"type": "string", "pattern": "^[0-9a-f]{40}$"},
        "evidence schema.hex40",
    )
    exact_literal(
        definitions["hex64"],
        {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "evidence schema.hex64",
    )
    exact_literal(
        definitions["positiveInteger"],
        {"type": "integer", "minimum": 1},
        "evidence schema.positiveInteger",
    )
    exact_literal(
        definitions["darwinRootVolume"]["properties"],
        {
            "filesystem": {"const": "apfs"},
            "sealed": {"const": True},
            "read_only": {"const": True},
        },
        "evidence schema Darwin root volume",
    )
    exact_literal(
        definitions["darwinSystemOpenSsh"]["properties"],
        {
            "method": {"const": DARWIN_OPENSSH_METHOD},
            "path": {"const": str(DARWIN_SYSTEM_OPENSSH)},
            "mode": {"const": "0755"},
            "uid": {"const": 0},
            "gid": {"const": 0},
            "nlink": {"const": 1},
            "sf_restricted": {"const": True},
            "same_device_as_root": {"const": True},
            "root_volume": {"$ref": "#/$defs/darwinRootVolume"},
            "version": {"const": PINNED_OPENSSH_VERSION},
            "sha256": {"const": PINNED_OPENSSH_SHA256},
            "bytes": {"const": PINNED_OPENSSH_BYTES},
        },
        "evidence schema Darwin system OpenSSH",
    )
    exact_literal(
        definitions["executionCustody"]["properties"],
        {
            "scheme": {"const": CUSTODY_SCHEME},
            "private_directory_mode": {"const": f"{CUSTODY_DIRECTORY_MODE:04o}"},
            "qemu": {"$ref": "#/$defs/custodyIdentity"},
            "bios": {"$ref": "#/$defs/custodyIdentity"},
            "kernel_elf": {"$ref": "#/$defs/custodyIdentity"},
            "openssh": {"$ref": "#/$defs/darwinSystemOpenSsh"},
        },
        "evidence schema execution custody",
    )
    exact_literal(
        definitions["qemuEnvironment"]["properties"],
        {
            "policy": {"const": QEMU_ENVIRONMENT_POLICY},
            "applies_to": {"const": QEMU_ENVIRONMENT_APPLIES_TO},
            "private_directory_mode": {
                "const": QEMU_ENVIRONMENT_DIRECTORY_MODE
            },
            "private_directories_must_remain_empty": {"const": True},
            "allowed_names": {"const": QEMU_ENVIRONMENT_ALLOWED_NAMES},
            "normalized_values": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    name: {"const": value}
                    for name, value in QEMU_ENVIRONMENT_NORMALIZED_VALUES.items()
                },
                "required": QEMU_ENVIRONMENT_ALLOWED_NAMES,
            },
            "live_data_directory": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "path": {"const": "<campaign-root>/qemu-environment/data"},
                    "mode": {"const": QEMU_DATA_DIRECTORY_MODE},
                    "must_remain_empty": {"const": True},
                },
                "required": ["path", "mode", "must_remain_empty"],
            },
        },
        "evidence schema QEMU environment",
    )
    exact_literal(
        definitions["qemuRuntimeClosure"]["properties"]["graph_sha256"],
        {"const": PINNED_QEMU_RUNTIME_GRAPH_SHA256},
        "evidence schema QEMU runtime preparation graph",
    )
    exact_literal(
        {
            "nodes": definitions["qemuRuntimeClosure"]["properties"][
                "node_count"
            ],
            "load_edges": definitions["qemuRuntimeClosure"]["properties"][
                "load_edge_count"
            ],
            "pinned_homebrew_edges": definitions["qemuRuntimeClosure"][
                "properties"
            ]["pinned_homebrew_edge_count"],
            "sealed_system_edges": definitions["qemuRuntimeClosure"]["properties"][
                "sealed_system_edge_count"
            ],
        },
        {name: {"const": count} for name, count in PINNED_QEMU_RUNTIME_COUNTS.items()},
        "evidence schema QEMU runtime preparation counts",
    )

    def require_closed_objects(node: Any, label: str) -> None:
        if type(node) is list:
            for index, child in enumerate(node):
                require_closed_objects(child, f"{label}[{index}]")
            return
        if type(node) is not dict:
            return
        if node.get("type") == "object":
            require(node.get("additionalProperties") is False, f"{label} is not closed")
            properties = node.get("properties")
            required = node.get("required")
            require(
                type(properties) is dict and type(required) is list,
                f"{label} shape differs",
            )
            require(
                len(required) == len(set(required))
                and set(required) == set(properties),
                f"{label} required fields do not close its properties",
            )
        reference = node.get("$ref")
        if reference is not None:
            require(
                type(reference) is str
                and reference.startswith("#/$defs/")
                and reference.removeprefix("#/$defs/") in definitions,
                f"{label} contains an unknown reference",
            )
        for key, child in node.items():
            require_closed_objects(child, f"{label}.{key}")

    require_closed_objects(definitions, "evidence schema.$defs")
    expected_property_sets = {
        "summary": {
            "schema",
            "version",
            "suite_id",
            "scope",
            "platform",
            "platform_class",
            "physical_provenance",
            "capture_mode",
            "source_commit",
            "challenge",
            "run_id",
            "manifest_sha256",
            "transcript_schema_sha256",
            "fresh_qemu_processes",
            "warmups",
            "retained",
            "timebase_hz",
            "raw_transcript_sha256",
            "raw_transcript_bytes",
            "end_accumulator",
            "retained_samples",
            "statistics",
            "decision",
        },
        "environment": {
            "schema",
            "version",
            "suite_id",
            "mode",
            "platform",
            "platform_class",
            "physical_provenance",
            "source_commit",
            "challenge",
            "run_id",
            "started_at_utc",
            "ended_at_utc",
            "repository",
            "source_materialization",
            "contract",
            "runner",
            "verifier",
            "helpers",
            "executed_peer_sources",
            "python_runtime",
            "toolchain",
            "kernel_elf",
            "qemu",
            "bios",
            "openssh",
            "execution_custody",
            "host_key_evidence",
            "transcript",
            "summary",
        },
        "decisionEnvelope": {
            "schema",
            "version",
            "suite_id",
            "mode",
            "scope",
            "platform",
            "platform_class",
            "physical_provenance",
            "source_commit",
            "challenge",
            "run_id",
            "contract",
            "evidence",
            "environment_identity",
            "population",
            "statistics",
            "decision",
            "next_node",
            "limitations",
        },
    }
    for name, expected in expected_property_sets.items():
        properties = definitions[name]["properties"]
        require(
            set(properties) == expected, f"evidence schema {name} properties differ"
        )
    critical = {
        "summary": "vibeos.c84.qemu-aot-decision.summary",
        "environment": "vibeos.c84.qemu-aot-decision.environment",
        "decisionEnvelope": "vibeos.c84.qemu-aot-decision.evidence",
    }
    for name, schema_id in critical.items():
        properties = definitions[name]["properties"]
        exact_literal(
            properties["schema"], {"const": schema_id}, f"evidence schema {name}.schema"
        )
        exact_literal(
            properties["version"], {"const": 1}, f"evidence schema {name}.version"
        )
        exact_literal(
            properties["platform"],
            {"const": PLATFORM},
            f"evidence schema {name}.platform",
        )
        exact_literal(
            properties["physical_provenance"],
            {"const": PHYSICAL_PROVENANCE},
            f"evidence schema {name}.physical_provenance",
        )
    exact_literal(
        definitions["derivedDecision"]["properties"]["outcome"],
        {"enum": [ELIGIBLE_OUTCOME, OTHERWISE_OUTCOME]},
        "evidence schema decision outcomes",
    )
    exact_literal(
        definitions["derivedDecision"]["properties"]["aot_authorized"],
        {"const": False},
        "evidence schema AOT authorization",
    )
    exact_literal(
        definitions["derivedDecision"]["properties"]["native_code_accepted"],
        {"const": False},
        "evidence schema native-code acceptance",
    )
    exact_literal(
        definitions["statistics"]["properties"]["nearest_rank_sorted_indices"][
            "properties"
        ],
        {"population": {"const": 21}, "p50": {"const": 10}, "p95": {"const": 19}},
        "evidence schema nearest-rank indices",
    )
    exact_literal(
        definitions["statistics"]["properties"]["stability"]["properties"],
        {
            "criterion": {"const": "p95(total_ticks) * 100 <= p50(total_ticks) * 110"},
            "passed": {"const": True},
        },
        "evidence schema stability",
    )


def expected_run_id(meta: dict[str, Any], contracts: Contracts) -> str:
    fields = contracts.manifest["transcript"]["run_id"]["fields"]
    capture_mode = exact_text(meta["capture_mode"], "QEMU metadata.capture_mode")
    require(capture_mode in CAPTURE_MODES, "QEMU metadata.capture_mode differs")
    domain = contracts.manifest["transcript"]["run_id"]["domains"][capture_mode]
    exact_literal(domain, RUN_ID_DOMAINS[capture_mode], "QEMU run-id domain")
    values = [domain, *(meta[field] for field in fields)]
    require(
        all(type(value) is str and "\0" not in value for value in values),
        "run-id fields must be NUL-free strings",
    )
    try:
        payload = "\0".join(values).encode("ascii")
    except UnicodeEncodeError as error:
        raise VerificationError("run-id fields must be ASCII") from error
    return hashlib.sha256(payload).hexdigest()


def verify_meta(
    meta: dict[str, Any],
    *,
    contracts: Contracts,
    expected_source: str,
    expected_challenge: str,
    expected_capture_mode: str,
) -> None:
    exact_keys(meta, META_KEYS, "QEMU metadata")
    fixed = {
        "schema": "vibeos.wasm-aot-decision.meta",
        "version": 1,
        "suite_id": SUITE,
        "workload_revision": 1,
        "manifest_sha256": contracts.manifest_sha256,
        "transcript_schema_sha256": contracts.schema_sha256,
        "platform": PLATFORM,
        "platform_class": PLATFORM_CLASS,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "capture_mode": expected_capture_mode,
        "decision_eligible": expected_capture_mode == FORMAL_CAPTURE_MODE,
        "clock": "riscv.rdtime",
        "timebase_hz": TIMEBASE_HZ,
        "hart_id": 0,
        "hart_count": 1,
        "transcript_scope": TRANSCRIPT_SCOPE,
        "required_qemu_boots": 1,
        "samples_per_boot": SAMPLES,
        "warmup_per_boot": WARMUPS,
        "retained_per_boot": RETAINED,
        "workload_id": EXPECTED_FIXTURE["id"],
        "artifact_sha256": EXPECTED_FIXTURE["artifact"]["sha256"],
        "artifact_bytes": EXPECTED_FIXTURE["artifact"]["byte_len"],
        "input_sha256": EXPECTED_FIXTURE["input"]["sha256"],
        "input_bytes": EXPECTED_FIXTURE["input"]["byte_len"],
        "output_sha256": EXPECTED_FIXTURE["output"]["sha256"],
        "output_bytes": EXPECTED_FIXTURE["output"]["byte_len"],
        "budget_ticks": BUDGET_TICKS,
    }
    for field, expected in fixed.items():
        exact_literal(meta[field], expected, f"QEMU metadata.{field}")
    require(
        expected_capture_mode in CAPTURE_MODES,
        "expected QEMU capture mode is not frozen",
    )
    source = exact_commit(meta["source_commit"], "QEMU metadata.source_commit")
    challenge = exact_sha256(meta["challenge"], "QEMU metadata.challenge")
    exact_literal(
        source,
        exact_commit(expected_source, "expected source commit"),
        "QEMU metadata.source_commit",
    )
    exact_literal(
        challenge,
        exact_sha256(expected_challenge, "expected challenge"),
        "QEMU metadata.challenge",
    )
    run_id = exact_sha256(meta["run_id"], "QEMU metadata.run_id")
    require(
        run_id == expected_run_id(meta, contracts),
        "QEMU run id does not bind the campaign",
    )


def verify_end(
    ending: dict[str, Any], *, samples: list[dict[str, Any]], meta: dict[str, Any]
) -> None:
    exact_keys(ending, END_KEYS, "QEMU end")
    fixed = {
        "schema": "vibeos.wasm-aot-decision.end",
        "version": 1,
        "samples": SAMPLES,
        "warmups": WARMUPS,
        "retained": RETAINED,
    }
    for field, expected in fixed.items():
        exact_literal(ending[field], expected, f"QEMU end.{field}")
    exact_literal(
        exact_sha256(ending["run_id"], "QEMU end.run_id"),
        meta["run_id"],
        "QEMU end.run_id",
    )
    exact_literal(
        exact_sha256(ending["challenge"], "QEMU end.challenge"),
        meta["challenge"],
        "QEMU end.challenge",
    )
    observed = exact_int(ending["accumulator"], "QEMU end.accumulator")
    require(observed == transcript_accumulator(samples), "QEMU END accumulator differs")


def retained_statistics(samples: list[dict[str, Any]]) -> dict[str, Any]:
    retained = [sample for sample in samples if not sample["warmup"]]
    require(len(retained) == RETAINED, "retained QEMU population is not exactly 21")
    require(
        [sample["sample_index"] for sample in retained]
        == list(range(WARMUPS, SAMPLES)),
        "retained QEMU sample coordinates differ",
    )
    totals = [sample["total_ticks"] for sample in retained]
    interpretation = [sample["phase_ticks"]["interpretation"] for sample in retained]
    non_interpretation = [
        sample["total_ticks"] - sample["phase_ticks"]["interpretation"]
        for sample in retained
    ]
    require(
        all(value >= 0 for value in non_interpretation),
        "interpretation exceeds total ticks",
    )
    total_ordered = sorted(totals)
    require(
        len(total_ordered) == 21, "nearest-rank contract requires 21 retained samples"
    )
    total_stats = distribution(totals)
    require(
        total_stats["p50"] == total_ordered[P50_SORTED_INDEX]
        and total_stats["p95"] == total_ordered[P95_SORTED_INDEX],
        "nearest-rank p50/p95 indices differ from fixed indexes 10/19",
    )
    stable = total_stats["p95"] * 100 <= total_stats["p50"] * 110
    require(stable, "fixed-QEMU retained stability exceeds p95/p50 <= 1.10")
    non_interpretation_stats = distribution(non_interpretation)
    budget_miss = total_stats["p95"] > BUDGET_TICKS
    attribution = non_interpretation_stats["p95"] <= BUDGET_TICKS
    candidate = budget_miss and attribution
    return {
        "retained_samples": [
            {
                "sample_index": sample["sample_index"],
                "total_ticks": sample["total_ticks"],
                "interpretation_ticks": sample["phase_ticks"]["interpretation"],
                "non_interpretation_ticks": sample["total_ticks"]
                - sample["phase_ticks"]["interpretation"],
            }
            for sample in retained
        ],
        "statistics": {
            "total_ticks": total_stats,
            "interpretation_ticks": distribution(interpretation),
            "non_interpretation_ticks": non_interpretation_stats,
            "nearest_rank_sorted_indices": {
                "population": RETAINED,
                "p50": P50_SORTED_INDEX,
                "p95": P95_SORTED_INDEX,
            },
            "stability": {
                "criterion": "p95(total_ticks) * 100 <= p50(total_ticks) * 110",
                "passed": stable,
            },
        },
        "decision": {
            "budget_ticks": BUDGET_TICKS,
            "budget_miss": budget_miss,
            "interpretation_attribution": attribution,
            "candidate_for_c85_design_review": candidate,
            "outcome": ELIGIBLE_OUTCOME if candidate else OTHERWISE_OUTCOME,
            "aot_authorized": False,
            "native_code_accepted": False,
        },
    }


def verify_transcript(
    raw: bytes,
    *,
    contracts: Contracts,
    expected_source: str,
    expected_challenge: str,
    expected_capture_mode: str,
) -> VerifiedTranscript:
    require(
        0 < len(raw) <= MAX_TRANSCRIPT_BYTES,
        "QEMU transcript byte length is out of range",
    )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(
            f"QEMU transcript is not strict UTF-8: {error}"
        ) from error
    lowered = text.lower()
    require(
        GENERIC_WASM_FAILURE.search(text) is None,
        "QEMU UART contains a generic WASM failure marker",
    )
    for marker in BASE.FAILURE_MARKERS:
        require(
            marker.lower() not in lowered,
            f"QEMU transcript contains failure marker {marker!r}",
        )
    require(FORBIDDEN_AUDIT_PREFIX not in text, "old C8.4 AUDIT stream is forbidden")
    require(
        "AUDIT_" not in text,
        "diagnostic AUDIT records are forbidden in formal QEMU evidence",
    )
    require(
        "VIBE_WASM_AOT_AUDIT" not in text,
        "legacy VIBE_WASM_AOT_AUDIT records are forbidden",
    )

    records: list[tuple[str, dict[str, Any]]] = []
    for line in text.splitlines():
        matches = 0
        for kind, prefix in (
            ("meta", META_PREFIX),
            ("sample", SAMPLE_PREFIX),
            ("end", END_PREFIX),
        ):
            record = parse_record(line, prefix, f"QEMU {kind}")
            if record is not None:
                records.append((kind, record))
                matches += 1
        require(
            matches <= 1, "one UART line contains multiple transcript record markers"
        )
    expected_order = ["meta", *(["sample"] * SAMPLES), "end"]
    require(
        [kind for kind, _ in records] == expected_order,
        "QEMU record count or order differs",
    )
    meta = records[0][1]
    samples = [record for kind, record in records if kind == "sample"]
    ending = records[-1][1]
    verify_meta(
        meta,
        contracts=contracts,
        expected_source=expected_source,
        expected_challenge=expected_challenge,
        expected_capture_mode=expected_capture_mode,
    )
    for position, sample in enumerate(samples):
        # This function is platform-neutral: the QEMU-specific identity and
        # population are closed above and below this call.
        verify_transcript_sample(sample, position=position, meta=meta)
    retained_statistics(samples)
    verify_end(ending, samples=samples, meta=meta)
    return VerifiedTranscript(meta=meta, samples=samples, ending=ending, raw=raw)


def derive_summary(verified: VerifiedTranscript) -> dict[str, Any]:
    measured = retained_statistics(verified.samples)
    return {
        "schema": "vibeos.c84.qemu-aot-decision.summary",
        "version": 1,
        "suite_id": SUITE,
        "scope": TRANSCRIPT_SCOPE,
        "platform": PLATFORM,
        "platform_class": PLATFORM_CLASS,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "capture_mode": verified.meta["capture_mode"],
        "source_commit": verified.meta["source_commit"],
        "challenge": verified.meta["challenge"],
        "run_id": verified.meta["run_id"],
        "manifest_sha256": verified.meta["manifest_sha256"],
        "transcript_schema_sha256": verified.meta["transcript_schema_sha256"],
        "fresh_qemu_processes": 1,
        "warmups": WARMUPS,
        "retained": RETAINED,
        "timebase_hz": TIMEBASE_HZ,
        "raw_transcript_sha256": hashlib.sha256(verified.raw).hexdigest(),
        "raw_transcript_bytes": len(verified.raw),
        "end_accumulator": verified.ending["accumulator"],
        **measured,
    }


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def canonical_compact_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def write_json(path: pathlib.Path, value: Any, *, overwrite: bool) -> bytes:
    rendered = canonical_json(value)
    try:
        parent = path.parent.resolve(strict=True)
        require(parent.is_dir(), f"output parent is not a directory: {parent}")
        destination = parent / path.name
        require(
            not destination.is_symlink(), "output destination must not be a symlink"
        )
        if destination.exists() and not overwrite:
            raise VerificationError(f"output already exists: {destination}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=parent
        )
        temporary = pathlib.Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(rendered)
                output.flush()
                os.fsync(output.fileno())
            if overwrite:
                os.replace(temporary, destination)
            else:
                try:
                    os.link(temporary, destination)
                except FileExistsError as error:
                    raise VerificationError(
                        f"output appeared concurrently: {destination}"
                    ) from error
                temporary.unlink()
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except OSError as error:
        raise VerificationError(f"cannot write output {path}: {error}") from error
    observed = read_regular(destination, "written output", MAX_JSON_BYTES)
    require(observed == rendered, "written output differs from rendered JSON")
    return rendered


def identity(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(value, {"sha256", "bytes"}, label)
    exact_sha256(record["sha256"], f"{label}.sha256")
    exact_int(record["bytes"], f"{label}.bytes", minimum=1)
    return record


def identity_for(raw: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def stable_runtime_identity(path: pathlib.Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
        try:
            before_fd = os.fstat(descriptor)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after_fd = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot hash Python runtime file {path}: {error}") from error

    def signature(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    require(
        stat.S_ISREG(before_fd.st_mode)
        and signature(before_path) == signature(before_fd) == signature(after_fd)
        and signature(after_fd) == signature(after_path),
        f"Python runtime file changed while hashing: {path}",
    )
    raw = b"".join(chunks)
    require(len(raw) == after_fd.st_size, f"Python runtime file size changed: {path}")
    return identity_for(raw)


def live_python_stdlib_inventory() -> dict[str, Any]:
    root = PINNED_PYTHON_STDLIB
    try:
        root_status = root.lstat()
    except OSError as error:
        raise VerificationError(f"cannot inspect fixed Python stdlib: {error}") from error
    require(
        stat.S_ISDIR(root_status.st_mode) and not root.is_symlink(),
        "fixed Python stdlib is not one real directory",
    )
    entries: list[dict[str, Any]] = []
    files = 0
    directories = 0
    symlinks = 0
    byte_total = 0
    stack = [(root, ".")]
    while stack:
        directory, relative_directory = stack.pop()
        status = directory.lstat()
        entries.append(
            {
                "path": relative_directory,
                "kind": "directory",
                "mode": f"{stat.S_IMODE(status.st_mode):04o}",
            }
        )
        directories += 1
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise VerificationError(
                f"cannot enumerate Python runtime directory {directory}: {error}"
            ) from error
        descend: list[tuple[pathlib.Path, str]] = []
        for child in children:
            if child.name in {"__pycache__", "site-packages"}:
                continue
            child_path = pathlib.Path(child.path)
            relative = (
                child.name
                if relative_directory == "."
                else f"{relative_directory}/{child.name}"
            )
            child_status = child_path.lstat()
            mode = f"{stat.S_IMODE(child_status.st_mode):04o}"
            if stat.S_ISDIR(child_status.st_mode):
                descend.append((child_path, relative))
            elif stat.S_ISREG(child_status.st_mode):
                observed = stable_runtime_identity(child_path)
                entries.append(
                    {"path": relative, "kind": "file", "mode": mode, **observed}
                )
                files += 1
                byte_total += observed["bytes"]
            elif stat.S_ISLNK(child_status.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "kind": "symlink",
                        "mode": mode,
                        "target": os.readlink(child_path),
                    }
                )
                symlinks += 1
            else:
                raise VerificationError(
                    f"unsupported Python runtime entry type: {child_path}"
                )
        stack.extend(reversed(descend))
    entries.sort(key=lambda entry: str(entry["path"]))
    encoded = json.dumps(
        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "policy": "reachable-stdlib-tree-v1-exclude-site-packages-and-pycache",
        "root": str(root),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "entries": len(entries),
        "files": files,
        "directories": directories,
        "symlinks": symlinks,
        "bytes": byte_total,
    }


def expected_python_runtime_environment() -> dict[str, Any]:
    return {
        "policy": "pinned-cpython-3.14-runtime-closure-v1",
        "launcher": EXPECTED_PYTHON_RUNTIME["launcher"],
        "argv_prefix": PINNED_PYTHON_ARGV_PREFIX,
        "environment": {
            "policy": "empty-then-exact-values-v1",
            "values": PINNED_PYTHON_LAUNCH_ENVIRONMENT,
        },
        "executable": EXPECTED_PYTHON_RUNTIME["executable"],
        "version": PINNED_PYTHON_VERSION,
        "implementation": "cpython",
        "cache_tag": "cpython-314",
        "prefix": str(PINNED_PYTHON_PREFIX),
        "framework": EXPECTED_PYTHON_RUNTIME["framework"],
        "app_executable": EXPECTED_PYTHON_RUNTIME["app_executable"],
        "startup_sys_path": PINNED_PYTHON_STARTUP_SYS_PATH,
        "effective_sys_path": PINNED_PYTHON_EFFECTIVE_SYS_PATH,
        "flags": PINNED_PYTHON_FLAGS,
        "xoptions": {"pycache_prefix": str(PINNED_PYTHON_PYCACHE_PREFIX)},
        "stdlib_inventory": PINNED_PYTHON_STDLIB_INVENTORY,
        "runtime_dynamic_closure": {
            "policy": "exact-non-system-python-macho-closure-v1",
            "python_opt_prefix": {
                "path": "/opt/homebrew/opt/python@3.14",
                "resolves_to": str(PINNED_PYTHON_CELLAR),
            },
            "hashlib_extension": EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["hashlib_extension"],
            "libcrypto": {
                "link_path": str(PINNED_LIBCRYPTO_LINK),
                **EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["libcrypto"],
            },
            "lzma_extension": EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["lzma_extension"],
            "liblzma": {
                "link_path": str(PINNED_LIBLZMA_LINK),
                **EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["liblzma"],
                "symlinks": [
                    {
                        "path": "/opt/homebrew/opt/xz",
                        "target": "../Cellar/xz/5.8.3",
                    }
                ],
            },
            "zstd_extension": EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["zstd_extension"],
            "libzstd": {
                "link_path": str(PINNED_LIBZSTD_LINK),
                **EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["libzstd"],
                "symlinks": [
                    {
                        "path": "/opt/homebrew/opt/zstd",
                        "target": "../Cellar/zstd/1.5.7_1",
                    },
                    {
                        "path": "/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.dylib",
                        "target": "libzstd.1.5.7.dylib",
                    },
                ],
            },
            "openssl_configuration": EXPECTED_PYTHON_RUNTIME["runtime_dynamic_closure"]["openssl_configuration"],
            "system_dependencies": {
                "policy": "darwin-sealed-system-volume",
                "paths": [
                    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                    "/usr/lib/libSystem.B.dylib",
                ],
            },
        },
        "pycache_custody": {
            "path": str(PINNED_PYTHON_PYCACHE_PREFIX),
            "must_remain_absent": True,
            "parent": "/var/empty",
            "parent_mode": "0755",
            "parent_uid": 0,
            "parent_gid": 3,
        },
    }


def validate_python_runtime(value: Any, *, verify_live: bool) -> dict[str, Any]:
    expected = expected_python_runtime_environment()
    exact_literal(value, expected, "environment.python_runtime")
    if not verify_live:
        return expected
    exact_literal(sys.executable, str(PINNED_PYTHON), "live Python executable")
    exact_literal(tuple(sys.version_info[:3]), (3, 14, 6), "live Python version")
    exact_literal(sys.prefix, str(PINNED_PYTHON_PREFIX), "live Python prefix")
    exact_literal(
        {name: getattr(sys.flags, name) for name in PINNED_PYTHON_FLAGS},
        PINNED_PYTHON_FLAGS,
        "live Python flags",
    )
    exact_literal(
        sys.pycache_prefix,
        str(PINNED_PYTHON_PYCACHE_PREFIX),
        "live Python pycache prefix",
    )
    require(
        sys.path in (PINNED_PYTHON_STARTUP_SYS_PATH, PINNED_PYTHON_EFFECTIVE_SYS_PATH),
        "live Python sys.path differs",
    )
    require(not os.path.lexists(PINNED_PYTHON_ZIP), "absent Python stdlib zip appeared")
    require(
        not os.path.lexists(PINNED_PYTHON_PYCACHE_PREFIX),
        "Python pycache sink appeared",
    )
    require(
        not tuple(pathlib.Path("/var/empty").iterdir()),
        "Python OpenSSL module directory is not empty",
    )
    openssl_conf = pathlib.Path("/dev/null").lstat()
    require(
        stat.S_ISCHR(openssl_conf.st_mode)
        and stat.S_IMODE(openssl_conf.st_mode) == 0o666
        and openssl_conf.st_uid == 0
        and openssl_conf.st_gid == 0,
        "Python OpenSSL configuration sink differs",
    )
    exact_literal(
        hashlib.sha256(b"").hexdigest(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "Python SHA-256 KAT",
    )
    exact_literal(dict(os.environ), PINNED_PYTHON_LAUNCH_ENVIRONMENT, "live Python environment")
    exact_literal(
        stable_runtime_identity(PINNED_PYTHON),
        {"sha256": PINNED_PYTHON_SHA256, "bytes": PINNED_PYTHON_BYTES},
        "live Python executable identity",
    )
    exact_literal(
        stable_runtime_identity(PINNED_PYTHON_FRAMEWORK),
        {"sha256": PINNED_PYTHON_FRAMEWORK_SHA256, "bytes": PINNED_PYTHON_FRAMEWORK_BYTES},
        "live Python framework identity",
    )
    exact_literal(
        stable_runtime_identity(PINNED_PYTHON_APP),
        {"sha256": PINNED_PYTHON_APP_SHA256, "bytes": PINNED_PYTHON_APP_BYTES},
        "live Python app executable identity",
    )
    exact_literal(live_python_stdlib_inventory(), PINNED_PYTHON_STDLIB_INVENTORY, "live Python stdlib inventory")
    exact_literal(
        stable_runtime_identity(PINNED_HASHLIB_EXTENSION),
        {"sha256": PINNED_HASHLIB_EXTENSION_SHA256, "bytes": PINNED_HASHLIB_EXTENSION_BYTES},
        "live Python _hashlib identity",
    )
    exact_literal(
        PINNED_LIBCRYPTO_LINK.resolve(strict=True),
        PINNED_LIBCRYPTO,
        "live Python libcrypto link",
    )
    exact_literal(
        stable_runtime_identity(PINNED_LIBCRYPTO),
        {"sha256": PINNED_LIBCRYPTO_SHA256, "bytes": PINNED_LIBCRYPTO_BYTES},
        "live Python libcrypto identity",
    )
    for module_name, extension, extension_identity in (
        (
            "_lzma",
            PINNED_LZMA_EXTENSION,
            {"sha256": PINNED_LZMA_EXTENSION_SHA256, "bytes": PINNED_LZMA_EXTENSION_BYTES},
        ),
        (
            "_zstd",
            PINNED_ZSTD_EXTENSION,
            {"sha256": PINNED_ZSTD_EXTENSION_SHA256, "bytes": PINNED_ZSTD_EXTENSION_BYTES},
        ),
    ):
        require(sys.modules.get(module_name) is not None, f"live Python omitted {module_name}")
        exact_literal(
            getattr(sys.modules[module_name], "__file__", None),
            str(extension),
            f"live Python {module_name} path",
        )
        exact_literal(
            stable_runtime_identity(extension),
            extension_identity,
            f"live Python {module_name} identity",
        )
    lzma_resolved, lzma_links = resolve_symlinks(PINNED_LIBLZMA_LINK)
    zstd_resolved, zstd_links = resolve_symlinks(PINNED_LIBZSTD_LINK)
    exact_literal(lzma_resolved, PINNED_LIBLZMA, "live Python liblzma link")
    exact_literal(
        lzma_links,
        expected["runtime_dynamic_closure"]["liblzma"]["symlinks"],
        "live Python liblzma symlinks",
    )
    exact_literal(
        stable_runtime_identity(PINNED_LIBLZMA),
        {"sha256": PINNED_LIBLZMA_SHA256, "bytes": PINNED_LIBLZMA_BYTES},
        "live Python liblzma identity",
    )
    exact_literal(zstd_resolved, PINNED_LIBZSTD, "live Python libzstd link")
    exact_literal(
        zstd_links,
        expected["runtime_dynamic_closure"]["libzstd"]["symlinks"],
        "live Python libzstd symlinks",
    )
    exact_literal(
        stable_runtime_identity(PINNED_LIBZSTD),
        {"sha256": PINNED_LIBZSTD_SHA256, "bytes": PINNED_LIBZSTD_BYTES},
        "live Python libzstd identity",
    )
    return expected


def path_identity(value: Any, expected_path: str, label: str) -> dict[str, Any]:
    record = exact_keys(value, {"path", "sha256", "bytes"}, label)
    exact_literal(record["path"], expected_path, f"{label}.path")
    identity({"sha256": record["sha256"], "bytes": record["bytes"]}, label)
    return record


def verify_local_identity(
    record: dict[str, Any], path: pathlib.Path, label: str
) -> None:
    raw = read_regular(path, label, 1 << 31)
    exact_literal(
        identity_for(raw), {"sha256": record["sha256"], "bytes": record["bytes"]}, label
    )


def validate_repository(
    value: Any, source: str, label: str, *, require_clean: bool
) -> dict[str, Any]:
    record = exact_keys(
        value,
        {
            "head",
            "commit_timestamp",
            "clean",
            "branch",
            "local_codex_wasm_head",
            "local_tracking_codex_wasm_head",
            "configured_fetch_url",
            "configured_push_url",
            "remote_query_url",
            "remote_ref",
            "advertised_remote_head",
            "status_command",
            "diff_command",
            "index_flags_command",
            "fsmonitor_flags_command",
            "remote_query_command",
            "status_porcelain_v1_z_sha256",
            "tracked_diff_head_binary_sha256",
            "index_flags_sha256",
            "fsmonitor_flags_sha256",
            "index_entries",
            "index_flags_all_h",
            "fsmonitor_flags_all_h",
            "remote_response_sha256",
            "local_configs",
        },
        label,
    )
    exact_literal(
        exact_commit(record["head"], f"{label}.head"), source, f"{label}.head"
    )
    commit_timestamp = exact_text(
        record["commit_timestamp"], f"{label}.commit_timestamp"
    )
    require(
        commit_timestamp.isdigit() and int(commit_timestamp) > 0,
        f"{label}.commit_timestamp differs",
    )
    branch_value = record["branch"]
    branch = (
        None
        if branch_value is None
        else exact_text(branch_value, f"{label}.branch", maximum=1024)
    )

    def nullable_commit(field: str) -> str | None:
        observed = record[field]
        if observed is None:
            return None
        return exact_commit(observed, f"{label}.{field}")

    local_head = nullable_commit("local_codex_wasm_head")
    tracking_head = nullable_commit("local_tracking_codex_wasm_head")
    advertised_head = nullable_commit("advertised_remote_head")
    clean = exact_bool(record["clean"], f"{label}.clean")
    exact_literal(
        record["configured_fetch_url"],
        FORMAL_CONFIGURED_ORIGIN,
        f"{label}.configured_fetch_url",
    )
    exact_literal(
        record["configured_push_url"],
        FORMAL_CONFIGURED_ORIGIN,
        f"{label}.configured_push_url",
    )
    exact_literal(record["remote_query_url"], FORMAL_REMOTE_URL, f"{label}.query URL")
    exact_literal(record["remote_ref"], FORMAL_REMOTE_REF, f"{label}.remote ref")
    exact_literal(
        record["status_command"], GIT_STATUS_COMMAND, f"{label}.status_command"
    )
    exact_literal(record["diff_command"], GIT_DIFF_COMMAND, f"{label}.diff_command")
    exact_literal(
        record["index_flags_command"],
        GIT_INDEX_FLAGS_COMMAND,
        f"{label}.index_flags_command",
    )
    exact_literal(
        record["fsmonitor_flags_command"],
        GIT_FSMONITOR_FLAGS_COMMAND,
        f"{label}.fsmonitor_flags_command",
    )
    exact_literal(
        record["remote_query_command"],
        GIT_REMOTE_QUERY_COMMAND,
        f"{label}.remote_query_command",
    )
    status_hash = exact_sha256(
        record["status_porcelain_v1_z_sha256"], f"{label}.status hash"
    )
    diff_hash = exact_sha256(
        record["tracked_diff_head_binary_sha256"], f"{label}.diff hash"
    )
    exact_sha256(record["index_flags_sha256"], f"{label}.index flags hash")
    exact_sha256(record["fsmonitor_flags_sha256"], f"{label}.fsmonitor flags hash")
    remote_hash = exact_sha256(
        record["remote_response_sha256"], f"{label}.remote response hash"
    )
    index_entries = exact_int(record["index_entries"], f"{label}.index_entries")
    require(index_entries > 0, f"{label}.index_entries must be positive")
    index_all_h = exact_bool(record["index_flags_all_h"], f"{label}.index all-H")
    fsmonitor_all_h = exact_bool(
        record["fsmonitor_flags_all_h"], f"{label}.fsmonitor all-H"
    )
    require(
        clean
        == (
            status_hash == EMPTY_SHA256
            and diff_hash == EMPTY_SHA256
            and index_all_h
            and fsmonitor_all_h
        ),
        f"{label}.clean disagrees with its repository closure",
    )
    configs = record["local_configs"]
    require(type(configs) is list and len(configs) == 3, f"{label}.local configs differ")
    expected_repositories = [".", *sorted(EXPECTED_SUBMODULES)]
    for item, repository in zip(configs, expected_repositories, strict=True):
        config = exact_keys(
            item,
            {
                "repository",
                "path",
                "policy",
                "sha256",
                "bytes",
                "entries",
                "parsed_sha256",
            },
            f"{label}.local config {repository}",
        )
        exact_literal(config["repository"], repository, f"{label}.config repository")
        exact_literal(
            config["path"], GIT_LOCAL_CONFIG_PATHS[repository], f"{label}.config path"
        )
        exact_literal(
            config["policy"], GIT_LOCAL_CONFIG_POLICY, f"{label}.config policy"
        )
        identity(
            {"sha256": config["sha256"], "bytes": config["bytes"]},
            f"{label}.config identity",
        )
        require(
            exact_int(config["entries"], f"{label}.config entries") > 0,
            f"{label}.config entries must be positive",
        )
        exact_sha256(config["parsed_sha256"], f"{label}.config parsed hash")
    if require_clean:
        require(clean, f"{label} must attest a clean repository")
        exact_literal(branch, FORMAL_BRANCH, f"{label}.branch")
        exact_literal(local_head, source, f"{label}.local_codex_wasm_head")
        exact_literal(tracking_head, source, f"{label}.local_tracking_codex_wasm_head")
        exact_literal(advertised_head, source, f"{label}.advertised_remote_head")
        exact_literal(status_hash, EMPTY_SHA256, f"{label}.status hash")
        exact_literal(diff_hash, EMPTY_SHA256, f"{label}.diff hash")
        exact_literal(
            remote_hash,
            hashlib.sha256(
                f"{source}\t{FORMAL_REMOTE_REF}\n".encode("ascii")
            ).hexdigest(),
            f"{label}.remote response hash",
        )
    else:
        exact_literal(advertised_head, None, f"{label}.smoke advertised head")
        exact_literal(remote_hash, EMPTY_SHA256, f"{label}.smoke remote response hash")
    return record


def git_output(arguments: list[str], label: str, *, cwd: pathlib.Path = ROOT) -> bytes:
    executable = shutil.which("git", path=SANITIZED_GIT_PATH)
    require(executable is not None, "Git executable is unavailable")
    try:
        executable = str(pathlib.Path(executable).resolve(strict=True))
    except OSError as error:
        raise VerificationError(
            f"cannot resolve sanitized Git executable: {error}"
        ) from error
    environment = {
        "HOME": "/nonexistent-vibeos-c84-qemu-verifier",
        "XDG_CONFIG_HOME": "/nonexistent-vibeos-c84-qemu-verifier",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": SANITIZED_GIT_PATH,
    }
    command = [
        executable,
        "--no-pager",
        "-c",
        "color.ui=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "status.aheadBehind=false",
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise VerificationError(
            f"cannot run sanitized Git for {label}: {error}"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(f"sanitized Git {label} failed: {detail}")
    return completed.stdout


def git_line(arguments: list[str], label: str) -> str:
    raw = git_output(arguments, label)
    require(
        raw.endswith(b"\n") and raw.count(b"\n") == 1, f"Git {label} output differs"
    )
    try:
        return raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(f"Git {label} output is not ASCII") from error


def parse_remote_advertisement(raw: bytes, source: str) -> None:
    exact_literal(
        raw,
        f"{source}\t{FORMAL_REMOTE_REF}\n".encode("ascii"),
        "fixed remote advertisement",
    )


def parse_index_flags(raw: bytes, label: str) -> tuple[int, bool]:
    require(raw.endswith(b"\0"), f"{label} is not NUL terminated")
    records = raw[:-1].split(b"\0") if raw else []
    require(bool(records), f"{label} has no tracked entries")
    require(all(len(record) >= 3 for record in records), f"{label} record is truncated")
    return len(records), all(record.startswith(b"H ") for record in records)


def combined_live_index_flags(
    arguments: list[str], label: str
) -> tuple[bytes, int, bool]:
    pieces: list[bytes] = []
    count = 0
    all_h = True
    for path in (".", *sorted(EXPECTED_SUBMODULES)):
        cwd = ROOT if path == "." else ROOT / path
        raw = git_output(arguments, f"{label} {path}", cwd=cwd)
        entries, observed_all_h = parse_index_flags(raw, f"{label} {path}")
        encoded_path = path.encode("utf-8")
        pieces.append(len(encoded_path).to_bytes(4, "big") + encoded_path + raw)
        count += entries
        all_h = all_h and observed_all_h
    return b"".join(pieces), count, all_h


def validate_local_config_entry(repository: str, key: str, value: str) -> None:
    core_values = {
        "core.repositoryformatversion": "0",
        "core.filemode": "true",
        "core.bare": "false",
        "core.logallrefupdates": "true",
        "core.ignorecase": "true",
        "core.precomposeunicode": "true",
    }
    if key in core_values:
        exact_literal(value, core_values[key], f"unsafe local Git config {key}")
        return
    if key == "core.worktree":
        require(repository in EXPECTED_SUBMODULES, "superproject has core.worktree")
        exact_literal(
            value,
            f"../../../../{repository}",
            f"submodule core.worktree {repository}",
        )
        return
    expected_urls = {
        ".": FORMAL_CONFIGURED_ORIGIN,
        "vendor/jitterentropy-rs": "https://github.com/qnfm/jitterentropy-rs.git",
        "vendor/sunset": "git@github.com:allegro0132/sunset.git",
    }
    if key == "remote.origin.url":
        exact_literal(value, expected_urls[repository], f"origin URL {repository}")
        return
    if key == "remote.origin.fetch":
        exact_literal(
            value,
            "+refs/heads/*:refs/remotes/origin/*",
            f"origin fetch refspec {repository}",
        )
        return
    branch = re.fullmatch(r"branch\.(.+)\.(remote|merge|vscode-merge-base)", key)
    if branch is not None:
        field = branch.group(2)
        require(
            (field == "remote" and value == "origin")
            or (field == "merge" and value.startswith("refs/heads/"))
            or (field == "vscode-merge-base" and value.startswith("origin/")),
            f"unsafe local branch config value: {key}",
        )
        return
    submodule = re.fullmatch(r"submodule\.(.+)\.(active|url)", key)
    if submodule is not None and repository == ".":
        name, field = submodule.groups()
        require(name in EXPECTED_SUBMODULES, f"unknown configured submodule: {name}")
        expected = "true" if field == "active" else expected_urls[name]
        exact_literal(value, expected, f"local submodule config {key}")
        return
    raise VerificationError(f"unsafe local Git config key: {key}")


def live_local_config_records() -> list[dict[str, Any]]:
    require(
        not os.path.lexists("/.git"),
        "root directory unexpectedly exposes repository-local Git config",
    )
    records: list[dict[str, Any]] = []
    for repository in (".", *sorted(EXPECTED_SUBMODULES)):
        relative = GIT_LOCAL_CONFIG_PATHS[repository]
        path = ROOT / relative
        before_raw = read_regular(path, f"local config {repository}", MAX_JSON_BYTES)
        raw = git_output(
            [
                "config",
                f"--file={path}",
                "--null",
                "--list",
                "--no-includes",
            ],
            f"local config {repository}",
            cwd=pathlib.Path("/"),
        )
        require(raw.endswith(b"\0"), f"local config is not NUL terminated: {repository}")
        parsed: list[tuple[str, str]] = []
        for item in raw[:-1].split(b"\0"):
            encoded_key, separator, encoded_value = item.partition(b"\n")
            require(separator == b"\n", f"local config entry differs: {repository}")
            try:
                key = encoded_key.decode("utf-8", errors="strict")
                value = encoded_value.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise VerificationError(
                    f"local config is not strict UTF-8: {repository}"
                ) from error
            require(key == key.lower(), f"local config key is not canonical: {key}")
            validate_local_config_entry(repository, key, value)
            parsed.append((key, value))
        require(bool(parsed), f"local config is empty: {repository}")
        require(
            len(parsed) == len(set(parsed)),
            f"local config repeats an exact entry: {repository}",
        )
        after_raw = read_regular(path, f"local config {repository}", MAX_JSON_BYTES)
        exact_literal(after_raw, before_raw, f"local config changed: {repository}")
        records.append(
            {
                "repository": repository,
                "path": relative,
                "policy": GIT_LOCAL_CONFIG_POLICY,
                **identity_for(before_raw),
                "entries": len(parsed),
                "parsed_sha256": hashlib.sha256(
                    canonical_compact_json(parsed)
                ).hexdigest(),
            }
        )
    return records


def validate_live_repository(source: str) -> dict[str, Any]:
    source = exact_commit(source, "live repository source commit")
    top_level = pathlib.Path(
        git_line(["rev-parse", "--show-toplevel"], "repository top level")
    ).resolve(strict=True)
    exact_literal(top_level, ROOT.resolve(strict=True), "live repository top level")
    branch = git_line(["symbolic-ref", "--quiet", "--short", "HEAD"], "branch")
    exact_literal(branch, FORMAL_BRANCH, "live repository branch")
    revisions: dict[str, str] = {}
    for key, label, revision in (
        ("head", "HEAD", "HEAD^{commit}"),
        ("local", "local codex/wasm", f"{FORMAL_LOCAL_REF}^{{commit}}"),
        (
            "tracking",
            "local origin/codex/wasm tracking",
            f"{FORMAL_ORIGIN_REF}^{{commit}}",
        ),
    ):
        observed = exact_commit(
            git_line(["rev-parse", "--verify", revision], label),
            f"live repository {label}",
        )
        exact_literal(observed, source, f"live repository {label}")
        revisions[key] = observed
    commit_timestamp = git_line(
        ["show", "-s", "--format=%ct", source], "source commit timestamp"
    )
    require(
        commit_timestamp.isdigit() and int(commit_timestamp) > 0,
        "live source commit timestamp differs",
    )
    status_raw = git_output(GIT_STATUS_COMMAND[1:], "status")
    diff_raw = git_output(GIT_DIFF_COMMAND[1:], "tracked diff")
    index_raw, index_entries, index_all_h = combined_live_index_flags(
        GIT_INDEX_FLAGS_COMMAND[1:], "index flags"
    )
    fsmonitor_raw, fsmonitor_entries, fsmonitor_all_h = combined_live_index_flags(
        GIT_FSMONITOR_FLAGS_COMMAND[1:], "fsmonitor flags"
    )
    require(status_raw == b"", "live repository is not clean")
    require(diff_raw == b"", "live repository tracked diff is not empty")
    require(
        index_entries == fsmonitor_entries and index_entries > 0,
        "live repository index entry counts differ",
    )
    require(index_all_h, "live repository has assume-unchanged/skip-worktree state")
    require(fsmonitor_all_h, "live repository has fsmonitor-valid state")
    configured_fetch = git_line(
        ["remote", "get-url", "--all", "origin"], "origin fetch URL"
    )
    exact_literal(
        configured_fetch,
        FORMAL_CONFIGURED_ORIGIN,
        "live configured origin fetch URL",
    )
    configured_push = git_line(
        ["remote", "get-url", "--push", "--all", "origin"],
        "origin push URL",
    )
    exact_literal(
        configured_push,
        FORMAL_CONFIGURED_ORIGIN,
        "live configured origin push URL",
    )
    require(
        not os.path.lexists("/.git"),
        "fixed remote query could discover root-local Git configuration",
    )
    remote_raw = git_output(
        GIT_REMOTE_QUERY_COMMAND[1:],
        "fixed remote codex/wasm advertisement",
        cwd=pathlib.Path("/"),
    )
    parse_remote_advertisement(remote_raw, source)
    require(bool(index_raw) and bool(fsmonitor_raw), "live index closure is empty")
    return {
        "head": revisions["head"],
        "commit_timestamp": commit_timestamp,
        "clean": True,
        "branch": branch,
        "local_codex_wasm_head": revisions["local"],
        "local_tracking_codex_wasm_head": revisions["tracking"],
        "configured_fetch_url": configured_fetch,
        "configured_push_url": configured_push,
        "remote_query_url": FORMAL_REMOTE_URL,
        "remote_ref": FORMAL_REMOTE_REF,
        "advertised_remote_head": source,
        "status_command": GIT_STATUS_COMMAND,
        "diff_command": GIT_DIFF_COMMAND,
        "index_flags_command": GIT_INDEX_FLAGS_COMMAND,
        "fsmonitor_flags_command": GIT_FSMONITOR_FLAGS_COMMAND,
        "remote_query_command": GIT_REMOTE_QUERY_COMMAND,
        "status_porcelain_v1_z_sha256": EMPTY_SHA256,
        "tracked_diff_head_binary_sha256": EMPTY_SHA256,
        "index_flags_sha256": hashlib.sha256(index_raw).hexdigest(),
        "fsmonitor_flags_sha256": hashlib.sha256(fsmonitor_raw).hexdigest(),
        "index_entries": index_entries,
        "index_flags_all_h": True,
        "fsmonitor_flags_all_h": True,
        "remote_response_sha256": hashlib.sha256(remote_raw).hexdigest(),
        "local_configs": live_local_config_records(),
    }


def parse_tree_inventory(raw: bytes, label: str) -> list[tuple[str, str, str, str]]:
    require(raw.endswith(b"\0"), f"{label} is not NUL terminated")
    records: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for encoded in raw[:-1].split(b"\0"):
        header, separator, raw_path = encoded.partition(b"\t")
        require(separator == b"\t", f"{label} entry has no path separator")
        fields = header.split(b" ")
        require(len(fields) == 3, f"{label} entry header differs")
        try:
            mode, kind, object_id = (
                field.decode("ascii", errors="strict") for field in fields
            )
            path = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise VerificationError(
                f"{label} entry is not canonical ASCII/UTF-8"
            ) from error
        require(mode in {"100644", "100755", "160000"}, f"{label} mode differs")
        require(
            kind == ("commit" if mode == "160000" else "blob"),
            f"{label} type differs",
        )
        exact_commit(object_id, f"{label} object id")
        pure = pathlib.PurePosixPath(path)
        require(
            path
            and not pure.is_absolute()
            and ".." not in pure.parts
            and path == pure.as_posix(),
            f"{label} path is unsafe",
        )
        require(path not in seen, f"{label} repeats path {path}")
        seen.add(path)
        records.append((mode, kind, object_id, path))
    require(bool(records), f"{label} has no entries")
    return records


def live_object_inventory(
    git_prefix: list[str], commit: str, label: str
) -> tuple[list[tuple[str, str, str, str]], dict[str, Any]]:
    commit = exact_commit(commit, f"{label} commit")
    tree_raw = git_output(
        [*git_prefix, "rev-parse", "--verify", f"{commit}^{{tree}}"],
        f"{label} tree",
    )
    require(
        tree_raw.endswith(b"\n") and tree_raw.count(b"\n") == 1,
        f"{label} tree output differs",
    )
    try:
        tree = exact_commit(tree_raw[:-1].decode("ascii"), f"{label} tree")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} tree is not ASCII") from error
    raw = git_output(
        [*git_prefix, "ls-tree", "-rz", "--full-tree", commit],
        f"{label} inventory",
    )
    entries = parse_tree_inventory(raw, label)
    return entries, {
        "commit": commit,
        "tree": tree,
        "inventory_sha256": hashlib.sha256(raw).hexdigest(),
        "entries": len(entries),
    }


def live_expected_materialization(
    source: str,
) -> tuple[dict[str, tuple[str, str]], dict[str, Any]]:
    root_entries, superproject = live_object_inventory([], source, "superproject")
    gitlinks = {
        path: object_id for mode, _, object_id, path in root_entries if mode == "160000"
    }
    exact_literal(set(gitlinks), set(EXPECTED_SUBMODULES), "superproject gitlink set")
    expected = {
        path: (mode, object_id)
        for mode, _, object_id, path in root_entries
        if mode != "160000"
    }
    submodules: list[dict[str, Any]] = []
    for path in sorted(EXPECTED_SUBMODULES):
        git_dir = (ROOT / EXPECTED_SUBMODULES[path]).resolve(strict=True)
        require(git_dir.is_dir(), f"submodule object database is missing: {path}")
        entries, record = live_object_inventory(
            [f"--git-dir={git_dir}"], gitlinks[path], f"submodule {path}"
        )
        require(
            all(mode != "160000" for mode, _, _, _ in entries),
            f"nested gitlinks are not allowed in {path}",
        )
        submodules.append({"path": path, **record})
        for mode, _, object_id, relative in entries:
            combined = f"{path}/{relative}"
            require(combined not in expected, f"materialized path overlaps: {combined}")
            expected[combined] = (mode, object_id)
    record = {
        "method": "exact-commit-raw-blob-export-v1",
        "decision_eligible": True,
        "superproject": superproject,
        "submodules": submodules,
        "ignored_worktree_inputs": "excluded-not-copied",
        "cargo_target": "fresh-private",
        "materialized_files": len(expected),
    }
    return expected, record


def git_blob_oid(raw: bytes) -> str:
    header = b"blob " + str(len(raw)).encode("ascii") + b"\0"
    return hashlib.sha1(header + raw).hexdigest()  # noqa: S324 - Git object identity


def verify_materialized_files(
    source_root: pathlib.Path, expected: dict[str, tuple[str, str]]
) -> None:
    require(source_root.is_absolute(), "materialized source path must be absolute")
    try:
        root_metadata = source_root.lstat()
    except OSError as error:
        raise VerificationError(
            f"cannot inspect materialized source: {error}"
        ) from error
    require(
        stat.S_ISDIR(root_metadata.st_mode) and not source_root.is_symlink(),
        "materialized source is not a regular directory",
    )
    observed: set[str] = set()
    for directory, directory_names, filenames in os.walk(
        source_root, followlinks=False
    ):
        base = pathlib.Path(directory)
        for name in tuple(directory_names):
            path = base / name
            metadata = path.lstat()
            require(
                stat.S_ISDIR(metadata.st_mode) and not path.is_symlink(),
                f"materialized source directory is unsafe: {path}",
            )
        for name in filenames:
            path = base / name
            relative = path.relative_to(source_root).as_posix()
            require(relative not in observed, f"materialized source repeats {relative}")
            observed.add(relative)
            require(
                relative in expected, f"materialized source has extra file {relative}"
            )
            metadata = path.lstat()
            require(
                stat.S_ISREG(metadata.st_mode)
                and not path.is_symlink()
                and metadata.st_nlink == 1,
                f"materialized source file is unsafe: {relative}",
            )
            mode, object_id = expected[relative]
            exact_literal(
                stat.S_IMODE(metadata.st_mode),
                0o755 if mode == "100755" else 0o644,
                f"materialized source mode {relative}",
            )
            raw = read_regular(path, f"materialized source {relative}", 1 << 30)
            exact_literal(git_blob_oid(raw), object_id, f"materialized blob {relative}")
    missing = sorted(set(expected) - observed)
    require(not missing, f"materialized source files are missing: {missing[:8]}")


def validate_inventory_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(value, {"commit", "tree", "inventory_sha256", "entries"}, label)
    exact_commit(record["commit"], f"{label}.commit")
    exact_commit(record["tree"], f"{label}.tree")
    exact_sha256(record["inventory_sha256"], f"{label}.inventory_sha256")
    require(exact_int(record["entries"], f"{label}.entries") > 0, f"{label} empty")
    return record


def validate_source_materialization(
    value: Any,
    source: str,
    *,
    publication: bool,
    verify_live: bool,
    materialized_source: pathlib.Path | None,
) -> dict[str, Any]:
    record = exact_keys(
        value,
        {
            "method",
            "decision_eligible",
            "superproject",
            "submodules",
            "ignored_worktree_inputs",
            "cargo_target",
            "materialized_files",
        },
        "environment.source_materialization",
    )
    superproject = validate_inventory_record(
        record["superproject"], "source materialization superproject"
    )
    exact_literal(superproject["commit"], source, "materialization source commit")
    submodules = record["submodules"]
    require(
        type(submodules) is list and len(submodules) == len(EXPECTED_SUBMODULES),
        "source materialization submodule list differs",
    )
    observed_paths: list[str] = []
    for index, item in enumerate(submodules):
        item = exact_keys(
            item,
            {"path", "commit", "tree", "inventory_sha256", "entries"},
            f"source materialization submodule {index}",
        )
        path = exact_text(
            item["path"], f"source materialization submodule {index}.path"
        )
        observed_paths.append(path)
        validate_inventory_record(
            {
                key: item[key]
                for key in ("commit", "tree", "inventory_sha256", "entries")
            },
            f"source materialization submodule {path}",
        )
    exact_literal(
        observed_paths,
        sorted(EXPECTED_SUBMODULES),
        "source materialization submodule order",
    )
    require(
        exact_int(record["materialized_files"], "materialized file count") > 0,
        "source materialization file count must be positive",
    )
    exact_literal(record["cargo_target"], "fresh-private", "private Cargo target")
    if publication:
        exact_literal(
            record["method"], "exact-commit-raw-blob-export-v1", "materialization method"
        )
        exact_literal(record["decision_eligible"], True, "materialization eligibility")
        exact_literal(
            record["ignored_worktree_inputs"],
            "excluded-not-copied",
            "materialization ignored inputs",
        )
        if verify_live:
            require(
                materialized_source is not None,
                "formal verification requires the live materialized source",
            )
            expected, expected_record = live_expected_materialization(source)
            exact_literal(record, expected_record, "live source materialization record")
            verify_materialized_files(materialized_source, expected)
    else:
        exact_literal(
            record["method"],
            "dirty-worktree-smoke-not-evidence",
            "smoke materialization method",
        )
        exact_literal(
            record["decision_eligible"], False, "smoke materialization eligibility"
        )
        exact_literal(
            record["ignored_worktree_inputs"],
            "not-excluded-smoke-only",
            "smoke ignored inputs",
        )
        require(
            materialized_source is None,
            "smoke must not claim an exact materialized source",
        )
    return record


def read_tree_file(path: pathlib.Path, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
        require(
            stat.S_ISREG(before.st_mode)
            and not path.is_symlink()
            and before.st_nlink == 1
            and 0 <= before.st_size <= maximum,
            f"{label} is not one bounded regular file",
        )
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot read {label}: {error}") from error
    require(
        (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
        and len(raw) == before.st_size,
        f"{label} changed while reading",
    )
    return raw


def strict_tree_identity(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        requested = pathlib.Path(os.path.abspath(os.fspath(path)))
        requested_metadata = requested.lstat()
        require(
            not stat.S_ISLNK(requested_metadata.st_mode),
            f"{label} root cannot itself be a symbolic link",
        )
        root = requested.resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as error:
        raise VerificationError(f"cannot resolve {label} tree: {error}") from error
    require(stat.S_ISDIR(root_metadata.st_mode) and not root.is_symlink(), f"{label} root differs")
    entries: list[tuple[bytes, str, pathlib.Path, os.stat_result]] = []
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        base = pathlib.Path(directory)
        for name in (*directory_names, *filenames):
            candidate = base / name
            metadata = candidate.lstat()
            relative = candidate.relative_to(root).as_posix()
            encoded = relative.encode("utf-8", errors="strict")
            if stat.S_ISDIR(metadata.st_mode):
                kind = "d"
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                kind = "f"
            else:
                raise VerificationError(f"{label} has unsafe entry {relative}")
            entries.append((encoded, kind, candidate, metadata))
    digest = hashlib.sha256()
    files = 0
    directories = 1
    byte_count = 0
    root_mode = stat.S_IMODE(root_metadata.st_mode)
    digest.update((f"d\0.\0{root_mode:04o}\0" + "0\0-\n").encode("ascii"))
    for _, kind, candidate, expected in sorted(entries, key=lambda item: item[0]):
        relative = candidate.relative_to(root).as_posix()
        mode = stat.S_IMODE(expected.st_mode)
        if kind == "d":
            directories += 1
            size = 0
            content = "-"
        else:
            raw = read_tree_file(candidate, f"{label} {relative}", expected.st_size)
            size = len(raw)
            content = hashlib.sha256(raw).hexdigest()
            files += 1
            byte_count += size
        digest.update(
            f"{kind}\0{relative}\0{mode:04o}\0{size}\0{content}\n".encode("utf-8")
        )
    return {
        "policy": "strict-tree-content-mode-v1",
        "sha256": digest.hexdigest(),
        "files": files,
        "directories": directories,
        "bytes": byte_count,
    }


def canonical_live_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    require(path.is_absolute(), f"{label} path is not absolute")
    try:
        metadata = path.lstat()
        require(
            stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
            f"{label} is not one direct directory",
        )
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise VerificationError(f"cannot resolve {label}: {error}") from error
    exact_literal(path, resolved, f"{label} canonical path")
    return resolved


def private_cargo_home_identity(
    cargo_home: pathlib.Path, generated_config: dict[str, Any]
) -> dict[str, Any]:
    root = canonical_live_directory(cargo_home, "private Cargo home")
    require(
        stat.S_IMODE(root.lstat().st_mode) == 0o700,
        "private Cargo home mode differs",
    )
    try:
        entries = tuple(root.iterdir())
    except OSError as error:
        raise VerificationError(f"cannot inspect private Cargo home: {error}") from error
    require(
        [entry.name for entry in entries] == ["config.toml"],
        "private Cargo home must contain exactly config.toml",
    )
    config = entries[0]
    try:
        metadata = config.lstat()
    except OSError as error:
        raise VerificationError(f"cannot inspect private Cargo config: {error}") from error
    require(
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o400,
        "private Cargo config type/mode differs",
    )
    current = {
        "path": "<private-cargo-home>/config.toml",
        **live_identity(config),
    }
    exact_literal(current, generated_config, "live private Cargo config identity")
    return {
        "policy": "exact-private-cargo-home-config-only-v1",
        "root_mode": "0700",
        "entries": [{**current, "mode": "0400", "links": 1}],
    }


def parse_locked_crates(
    lock_path: pathlib.Path,
    *,
    logical_path: str,
    expected_sha256: str,
    expected_bytes: int,
    expected_packages: int,
    expected_package_set_sha256: str,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    raw = read_regular(lock_path, logical_path, MAX_CONTRACT_BYTES)
    try:
        document = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"materialized Cargo.lock differs: {error}") from error
    packages = document.get("package")
    require(type(packages) is list, "Cargo.lock package table differs")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for package in packages:
        require(type(package) is dict, "Cargo.lock package entry differs")
        source = package.get("source")
        if source is None:
            require(package.get("checksum") is None, "path package checksum differs")
            continue
        exact_literal(source, CRATES_IO_SOURCE, "Cargo.lock registry source")
        name, version, checksum = (
            package.get("name"),
            package.get("version"),
            package.get("checksum"),
        )
        require(
            type(name) is str
            and type(version) is str
            and type(checksum) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", name) is not None
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", version) is not None
            and HEX64.fullmatch(checksum) is not None,
            "Cargo.lock package identity differs",
        )
        key = (name, version)
        require(key not in seen, "Cargo.lock repeats a registry package")
        seen.add(key)
        result.append({"name": name, "version": version, "checksum": checksum})
    result.sort(key=lambda value: (value["name"], value["version"]))
    package_set = b"".join(
        f"{item['name']}\0{item['version']}\0{item['checksum']}\n".encode("ascii")
        for item in result
    )
    record = {
        "path": logical_path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "registry_source": CRATES_IO_SOURCE,
        "packages": len(result),
        "package_set_sha256": hashlib.sha256(package_set).hexdigest(),
    }
    exact_literal(
        record,
        {
            "path": logical_path,
            "sha256": expected_sha256,
            "bytes": expected_bytes,
            "registry_source": CRATES_IO_SOURCE,
            "packages": expected_packages,
            "package_set_sha256": expected_package_set_sha256,
        },
        f"frozen {logical_path}",
    )
    return result, record


def parse_locked_crate_union(
    source_root: pathlib.Path, rust_src: pathlib.Path
) -> tuple[list[dict[str, str]], dict[str, Any], set[tuple[str, str, str]]]:
    project, project_record = parse_locked_crates(
        source_root / "Cargo.lock",
        logical_path="Cargo.lock",
        expected_sha256=PINNED_CARGO_LOCK_SHA256,
        expected_bytes=PINNED_CARGO_LOCK_BYTES,
        expected_packages=PINNED_CARGO_PACKAGES,
        expected_package_set_sha256=PINNED_CARGO_PACKAGE_SET_SHA256,
    )
    rust, rust_record = parse_locked_crates(
        rust_src / "Cargo.lock",
        logical_path="lib/rustlib/src/rust/library/Cargo.lock",
        expected_sha256=PINNED_RUST_SRC_CARGO_LOCK["sha256"],
        expected_bytes=PINNED_RUST_SRC_CARGO_LOCK["bytes"],
        expected_packages=PINNED_RUST_SRC_CARGO_PACKAGES,
        expected_package_set_sha256=PINNED_RUST_SRC_CARGO_PACKAGE_SET_SHA256,
    )
    project_set = {
        (item["name"], item["version"], item["checksum"]) for item in project
    }
    rust_set = {(item["name"], item["version"], item["checksum"]) for item in rust}
    keyed: dict[tuple[str, str], str] = {}
    for name, version, checksum in sorted(project_set | rust_set):
        key = (name, version)
        previous = keyed.setdefault(key, checksum)
        require(previous == checksum, f"Cargo lock checksum conflict: {name}-{version}")
    union = [
        {"name": name, "version": version, "checksum": checksum}
        for (name, version), checksum in sorted(keyed.items())
    ]
    package_set = b"".join(
        f"{item['name']}\0{item['version']}\0{item['checksum']}\n".encode("ascii")
        for item in union
    )
    union_record = {
        "packages": len(union),
        "exact_overlap": len(project_set & rust_set),
        "project_only": len(project_set - rust_set),
        "rust_src_only": len(rust_set - project_set),
        "package_set_sha256": hashlib.sha256(package_set).hexdigest(),
    }
    exact_literal(
        union_record,
        {
            "packages": PINNED_CARGO_UNION_PACKAGES,
            "exact_overlap": PINNED_CARGO_UNION_EXACT_OVERLAP,
            "project_only": PINNED_CARGO_UNION_PROJECT_ONLY,
            "rust_src_only": PINNED_CARGO_UNION_RUST_SRC_ONLY,
            "package_set_sha256": PINNED_CARGO_UNION_PACKAGE_SET_SHA256,
        },
        "frozen project/rust-src Cargo.lock union",
    )
    return (
        union,
        {
            "policy": "project-plus-pinned-rust-src-lock-union-v1",
            "project": project_record,
            "rust_src": rust_record,
            "union": union_record,
        },
        project_set,
    )


def verify_private_crates(
    source_root: pathlib.Path,
    rust_src: pathlib.Path,
    vendor: pathlib.Path,
    archives: pathlib.Path,
    record: dict[str, Any],
) -> None:
    packages, cargo_locks, project_packages = parse_locked_crate_union(
        source_root, rust_src
    )
    exact_literal(record["cargo_locks"], cargo_locks, "build input Cargo locks")
    expected_archive_names = [
        f"{index:04d}.crate" for index in range(PINNED_CARGO_PACKAGES)
    ]
    require(
        sorted(path.name for path in archives.iterdir()) == expected_archive_names,
        "private crate archive set differs",
    )
    archive_bytes = 0
    source_files = 0
    source_bytes = 0
    archive_index = 0
    rust_src_vendor_count = 0

    def safe_relative(
        relative: str, label: str, *, allow_checksum: bool = False
    ) -> pathlib.PurePosixPath:
        pure = pathlib.PurePosixPath(relative)
        require(
            relative
            and (allow_checksum or relative != ".cargo-checksum.json")
            and relative == pure.as_posix()
            and not pure.is_absolute()
            and ".." not in pure.parts
            and "." not in pure.parts
            and "" not in pure.parts
            and not relative.endswith("/")
            and "\\" not in relative
            and "\x00" not in relative
            and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in relative),
            f"{label} differs",
        )
        return pure

    def direct_tree_entries(root: pathlib.Path, label: str) -> tuple[set[str], set[str]]:
        root_metadata = root.lstat()
        require(
            stat.S_ISDIR(root_metadata.st_mode) and not root.is_symlink(),
            f"{label} root differs",
        )
        files: set[str] = set()
        directories: set[str] = set()
        for directory, directory_names, filenames in os.walk(root, followlinks=False):
            base = pathlib.Path(directory)
            for name in (*directory_names, *filenames):
                candidate = base / name
                metadata = candidate.lstat()
                relative = candidate.relative_to(root).as_posix()
                safe_relative(relative, f"{label} path", allow_checksum=True)
                if stat.S_ISDIR(metadata.st_mode):
                    directories.add(relative)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    files.add(relative)
                else:
                    raise VerificationError(f"{label} contains an unsafe entry")
        return files, directories

    for package in packages:
        package_name = f"{package['name']}-{package['version']}"
        package_root = vendor / package_name
        identity_tuple = (package["name"], package["version"], package["checksum"])
        if identity_tuple not in project_packages:
            rust_src_vendor_count += 1
            source_package = rust_src / "vendor" / package_name
            checksum_raw = read_regular(
                source_package / ".cargo-checksum.json",
                f"rust-src vendor checksum {package_name}",
                4 * 1024 * 1024,
            )
            checksum_value = strict_json_bytes(
                checksum_raw, f"rust-src vendor checksum {package_name}"
            )
            require(
                type(checksum_value) is dict
                and set(checksum_value) == {"$comment", "files", "package"}
                and checksum_value.get("$comment")
                == (
                    "This file only protects against accidental modifications. It is not a "
                    "security mechanism and does not protect against malicious changes."
                )
                and checksum_value.get("package") == package["checksum"]
                and type(checksum_value.get("files")) is dict,
                f"rust-src vendor checksum contract differs: {package_name}",
            )
            raw_checksums = checksum_value["files"]
            assert type(raw_checksums) is dict
            checksums: dict[str, str] = {}
            expected_directories: set[str] = set()
            for relative, checksum in raw_checksums.items():
                require(
                    type(relative) is str
                    and type(checksum) is str
                    and HEX64.fullmatch(checksum) is not None,
                    f"rust-src vendor file checksum differs: {package_name}",
                )
                pure = safe_relative(relative, f"rust-src vendor path {package_name}")
                checksums[relative] = checksum
                parent = pure.parent
                while parent != pathlib.PurePosixPath("."):
                    expected_directories.add(parent.as_posix())
                    parent = parent.parent
            observed_files, observed_directories = direct_tree_entries(
                source_package, f"rust-src vendor package {package_name}"
            )
            exact_literal(
                observed_files,
                set(checksums) | {".cargo-checksum.json"},
                "rust-src vendor file inventory",
            )
            exact_literal(
                observed_directories,
                expected_directories,
                "rust-src vendor directory inventory",
            )
            for relative, checksum in sorted(checksums.items()):
                pure = safe_relative(relative, f"rust-src vendor path {package_name}")
                source_path = source_package.joinpath(*pure.parts)
                raw = read_tree_file(
                    source_path,
                    f"rust-src vendor file {package_name}/{relative}",
                    512 * 1024 * 1024,
                )
                exact_literal(
                    hashlib.sha256(raw).hexdigest(), checksum, "rust-src vendor file checksum"
                )
                installed = package_root.joinpath(*pure.parts)
                exact_literal(
                    read_tree_file(installed, "private crate source", len(raw)),
                    raw,
                    "private crate source bytes",
                )
                expected_mode = 0o500 if stat.S_IMODE(source_path.lstat().st_mode) & 0o100 else 0o400
                require(
                    stat.S_IMODE(installed.lstat().st_mode) == expected_mode,
                    "private crate source mode differs",
                )
                source_files += 1
                source_bytes += len(raw)
            installed_checksum = canonical_compact_json(
                {"files": dict(sorted(checksums.items())), "package": package["checksum"]}
            )
            checksum_path = package_root / ".cargo-checksum.json"
            exact_literal(
                read_regular(checksum_path, "private Cargo checksum", MAX_JSON_BYTES),
                installed_checksum,
                "private Cargo checksum bytes",
            )
            require(
                stat.S_IMODE(checksum_path.lstat().st_mode) == 0o400,
                "private checksum mode differs",
            )
            continue
        archive_path = archives / f"{archive_index:04d}.crate"
        archive_index += 1
        archive_raw = read_regular(
            archive_path, "private crate archive", 32 * 1024 * 1024
        )
        exact_literal(
            hashlib.sha256(archive_raw).hexdigest(),
            package["checksum"],
            "private crate archive checksum",
        )
        require(stat.S_IMODE(archive_path.lstat().st_mode) == 0o400, "private archive mode differs")
        archive_bytes += len(archive_raw)
        checksums: dict[str, str] = {}
        with tarfile.open(
            fileobj=io.BytesIO(archive_raw), mode="r:gz", encoding="utf-8", errors="strict"
        ) as bundle:
            for member in bundle.getmembers():
                require(member.isfile(), "crate archive contains a link or special entry")
                prefix = package_name + "/"
                require(member.name.startswith(prefix), "crate archive prefix differs")
                relative = member.name[len(prefix) :]
                pure = safe_relative(relative, "crate archive path")
                require(relative not in checksums, "crate archive repeats a path")
                extracted = bundle.extractfile(member)
                require(extracted is not None, "crate archive member cannot be read")
                raw = extracted.read()
                require(len(raw) == member.size, "crate archive member length differs")
                checksums[relative] = hashlib.sha256(raw).hexdigest()
                installed = package_root.joinpath(*pure.parts)
                exact_literal(
                    read_tree_file(installed, "private crate source", len(raw)),
                    raw,
                    "private crate source bytes",
                )
                expected_mode = 0o500 if member.mode & 0o111 else 0o400
                require(stat.S_IMODE(installed.lstat().st_mode) == expected_mode, "private crate source mode differs")
                source_files += 1
                source_bytes += len(raw)
        checksum_raw = canonical_compact_json(
            {"files": dict(sorted(checksums.items())), "package": package["checksum"]}
        )
        checksum_path = package_root / ".cargo-checksum.json"
        exact_literal(
            read_regular(checksum_path, "private Cargo checksum", MAX_JSON_BYTES),
            checksum_raw,
            "private Cargo checksum bytes",
        )
        require(stat.S_IMODE(checksum_path.lstat().st_mode) == 0o400, "private checksum mode differs")
    exact_literal(archive_bytes, 23_706_909, "private archive bytes")
    exact_literal(archive_index, PINNED_CARGO_PACKAGES, "private archive count")
    exact_literal(
        rust_src_vendor_count,
        PINNED_CARGO_UNION_RUST_SRC_ONLY,
        "rust-src vendor package count",
    )
    exact_literal(source_files, 11_391, "private source files")
    exact_literal(source_bytes, 137_564_030, "private source bytes")
    exact_literal(strict_tree_identity(vendor, "private crate sources"), PINNED_PRIVATE_CRATE_TREE, "private crate tree")


def live_identity(path: pathlib.Path) -> dict[str, Any]:
    metadata = path.lstat()
    raw = read_regular(path, "Mach-O runtime", max(metadata.st_size, 1))
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def run_otool(arguments: list[str]) -> str:
    environment = {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    completed = subprocess.run(
        [str(PINNED_OTOOL_INVOCATION), *arguments],
        cwd=pathlib.Path("/"),
        env=environment,
        stdin=subprocess.DEVNULL,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    require(completed.returncode == 0 and not completed.stderr, "otool inspection failed")
    return completed.stdout


def macho_metadata(path: pathlib.Path) -> tuple[list[str], list[str]]:
    lines = run_otool(["-L", str(path)]).splitlines()
    require(len(lines) >= 2 and lines[0] == f"{path}:", "otool header differs")
    dependencies: list[str] = []
    for line in lines[1:]:
        match = re.fullmatch(r"\t(.+) \(compatibility version .+\)", line)
        require(match is not None, "otool dependency line differs")
        dependencies.append(match.group(1))
    load_lines = run_otool(["-l", str(path)]).splitlines()
    rpaths: list[str] = []
    for index, line in enumerate(load_lines):
        if line.strip() == "cmd LC_RPATH":
            require(index + 2 < len(load_lines), "truncated LC_RPATH")
            match = re.fullmatch(r"\s*path (.+) \(offset [0-9]+\)", load_lines[index + 2])
            require(match is not None, "LC_RPATH differs")
            rpaths.append(match.group(1))
    return dependencies, rpaths


def resolve_symlinks(path: pathlib.Path) -> tuple[pathlib.Path, list[dict[str, str]]]:
    require(path.is_absolute(), "Mach-O path must be absolute")
    pending = list(path.parts[1:])
    current = pathlib.Path("/")
    links: list[dict[str, str]] = []
    while pending:
        current = current / pending.pop(0)
        metadata = current.lstat()
        if not stat.S_ISLNK(metadata.st_mode):
            continue
        require(len(links) < 32, "too many Mach-O symlinks")
        target = os.readlink(current)
        links.append({"path": str(current), "target": target})
        replacement = pathlib.Path(target)
        if not replacement.is_absolute():
            replacement = current.parent / replacement
        replacement = pathlib.Path(os.path.normpath(replacement))
        pending = [*replacement.parts[1:], *pending]
        current = pathlib.Path("/")
    return current, links


def live_otool_custody_record() -> dict[str, Any]:
    resolved, links = resolve_symlinks(PINNED_OTOOL_INVOCATION)
    resolved = resolved.resolve(strict=True)
    exact_literal(resolved, PINNED_OTOOL_RESOLVED, "direct CLT otool resolution")
    tool_identity = live_identity(resolved)
    exact_literal(
        tool_identity,
        {"sha256": PINNED_OTOOL_SHA256, "bytes": PINNED_OTOOL_BYTES},
        "direct CLT llvm-otool identity",
    )
    environment = {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    completed = subprocess.run(
        ["/usr/sbin/pkgutil", f"--pkg-info={PINNED_CLT_PACKAGE_ID}"],
        cwd=pathlib.Path("/"),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=30,
    )
    require(
        completed.returncode == 0 and not completed.stderr,
        "Command Line Tools package query failed",
    )
    fields: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition(": ")
        require(separator == ": " and key not in fields, "CLT package output differs")
        fields[key] = value
    exact_literal(fields.get("package-id"), PINNED_CLT_PACKAGE_ID, "CLT package id")
    exact_literal(fields.get("version"), PINNED_CLT_VERSION, "CLT package version")
    exact_literal(fields.get("volume"), "/", "CLT package volume")
    exact_literal(fields.get("location"), "/", "CLT package location")
    return {
        "policy": OTOOL_CUSTODY_POLICY,
        "invocation_path": str(PINNED_OTOOL_INVOCATION),
        "resolved_path": str(resolved),
        "symlinks": links,
        **tool_identity,
        "package_id": PINNED_CLT_PACKAGE_ID,
        "package_version": PINNED_CLT_VERSION,
    }


def expand_anchor(value: str, loader: pathlib.Path, executable: pathlib.Path) -> pathlib.Path:
    for prefix, base in (("@loader_path", loader.parent), ("@executable_path", executable.parent)):
        if value == prefix:
            return base
        if value.startswith(prefix + "/"):
            return base / value[len(prefix) + 1 :]
    path = pathlib.Path(value)
    require(path.is_absolute(), "unsupported Mach-O path anchor")
    return path


def linker_runtime_closure(invocation: pathlib.Path) -> dict[str, Any]:
    executable, invocation_links = resolve_symlinks(invocation)
    pending = [executable]
    nodes: dict[str, dict[str, Any]] = {}
    links = {item["path"]: item["target"] for item in invocation_links}
    executable_dependencies, executable_rpaths = macho_metadata(executable)
    while pending:
        current = pending.pop(0).resolve(strict=True)
        if str(current) in nodes:
            continue
        dependencies, rpaths = (
            (executable_dependencies, executable_rpaths)
            if current == executable
            else macho_metadata(current)
        )
        edges: list[dict[str, Any]] = []
        for install_name in dependencies:
            if install_name.startswith("/usr/lib/") or install_name.startswith("/System/Library/"):
                edges.append({"install_name": install_name, "class": "sealed-system"})
                continue
            if install_name.startswith("@rpath/"):
                suffix = install_name[len("@rpath/") :]
                candidates = []
                for rpath in [*rpaths, *executable_rpaths]:
                    candidate = pathlib.Path(os.path.normpath(expand_anchor(rpath, current, executable) / suffix))
                    if os.path.lexists(candidate):
                        candidates.append(candidate)
                unique = {str(path): path for path in candidates}
                require(len(unique) == 1, "Mach-O @rpath is ambiguous")
                lexical = next(iter(unique.values()))
            elif install_name.startswith("@loader_path") or install_name.startswith("@executable_path"):
                lexical = pathlib.Path(os.path.normpath(expand_anchor(install_name, current, executable)))
            else:
                lexical = pathlib.Path(install_name)
                require(lexical.is_absolute(), "relative Mach-O dependency")
            resolved, observed_links = resolve_symlinks(lexical)
            for link in observed_links:
                require(links.get(link["path"], link["target"]) == link["target"], "Mach-O symlink conflict")
                links[link["path"]] = link["target"]
            resolved = resolved.resolve(strict=True)
            require(str(resolved).startswith("/opt/homebrew/Cellar/"), "Mach-O dependency escaped Cellar")
            edges.append({"install_name": install_name, "class": "pinned-homebrew", "resolved_path": str(resolved)})
            if resolved != current and str(resolved) not in nodes:
                pending.append(resolved)
        nodes[str(current)] = {
            "path": str(current),
            **live_identity(current),
            "rpaths": rpaths,
            "dependencies": edges,
        }
    core = {
        "policy": "darwin-recursive-nonsystem-macho-closure-v1",
        "otool": str(PINNED_OTOOL_INVOCATION),
        "otool_custody": live_otool_custody_record(),
        "system_policy": "darwin-sealed-system-volume",
        "invocation_path": str(invocation),
        "resolved_path": str(executable),
        "symlinks": [{"path": path, "target": target} for path, target in sorted(links.items())],
        "nodes": [nodes[path] for path in sorted(nodes)],
    }
    return {
        **core,
        "sha256": hashlib.sha256(canonical_compact_json(core)).hexdigest(),
    }


def qemu_runtime_closure(invocation: pathlib.Path) -> dict[str, Any]:
    executable, invocation_links = resolve_symlinks(invocation)
    pending = [executable]
    nodes: dict[str, dict[str, Any]] = {}
    links = {item["path"]: item["target"] for item in invocation_links}
    executable_dependencies, executable_rpaths = macho_metadata(executable)
    while pending:
        current = pending.pop(0).resolve(strict=True)
        if str(current) in nodes:
            continue
        dependencies, rpaths = (
            (executable_dependencies, executable_rpaths)
            if current == executable
            else macho_metadata(current)
        )
        edges: list[dict[str, Any]] = []
        for install_name in dependencies:
            if any(
                install_name.startswith(prefix)
                for prefix in QEMU_RUNTIME_SYSTEM_PREFIXES
            ):
                edges.append({"install_name": install_name, "class": "sealed-system"})
                continue
            if install_name.startswith("@rpath/"):
                suffix = install_name[len("@rpath/") :]
                candidates = []
                for rpath in [*rpaths, *executable_rpaths]:
                    candidate = pathlib.Path(
                        os.path.normpath(expand_anchor(rpath, current, executable) / suffix)
                    )
                    if os.path.lexists(candidate):
                        candidates.append(candidate)
                unique = {str(path): path for path in candidates}
                require(len(unique) == 1, "QEMU Mach-O @rpath is ambiguous")
                lexical = next(iter(unique.values()))
            elif install_name.startswith("@loader_path") or install_name.startswith(
                "@executable_path"
            ):
                lexical = pathlib.Path(
                    os.path.normpath(expand_anchor(install_name, current, executable))
                )
            else:
                lexical = pathlib.Path(install_name)
                require(lexical.is_absolute(), "relative QEMU Mach-O dependency")
            resolved, observed_links = resolve_symlinks(lexical)
            for link in observed_links:
                require(
                    links.get(link["path"], link["target"]) == link["target"],
                    "QEMU Mach-O symlink conflict",
                )
                links[link["path"]] = link["target"]
            resolved = resolved.resolve(strict=True)
            require(
                str(resolved).startswith("/opt/homebrew/Cellar/"),
                "QEMU Mach-O dependency escaped Cellar",
            )
            edges.append(
                {
                    "install_name": install_name,
                    "class": "pinned-homebrew",
                    "resolved_path": str(resolved),
                }
            )
            if resolved != current and str(resolved) not in nodes:
                pending.append(resolved)
        nodes[str(current)] = {
            "path": str(current),
            **live_identity(current),
            "rpaths": rpaths,
            "dependencies": edges,
        }
    normalized_nodes = []
    for path in sorted(nodes):
        node = dict(nodes[path])
        if path == str(executable):
            node["path"] = "<qemu-executable>"
        normalized_nodes.append(node)
    normalized_nodes.sort(key=lambda node: str(node["path"]))
    graph_sha256 = hashlib.sha256(
        canonical_compact_json({"nodes": normalized_nodes})
    ).hexdigest()
    edge_classes = [
        edge["class"] for node in nodes.values() for edge in node["dependencies"]
    ]
    core = {
        "policy": QEMU_RUNTIME_CLOSURE_POLICY,
        "otool": str(PINNED_OTOOL_INVOCATION),
        "otool_custody": live_otool_custody_record(),
        "system_policy": "darwin-sealed-system-volume",
        "system_dependency_prefixes": list(QEMU_RUNTIME_SYSTEM_PREFIXES),
        "system_volume": live_darwin_root_volume_record(),
        "system_build": live_darwin_host_build_record(),
        "host_exclusivity_limit": QEMU_RUNTIME_HOST_LIMIT,
        "invocation_path": str(invocation),
        "resolved_path": str(executable),
        "symlinks": [
            {"path": path, "target": target} for path, target in sorted(links.items())
        ],
        "nodes": [nodes[path] for path in sorted(nodes)],
        "node_count": len(nodes),
        "load_edge_count": len(edge_classes),
        "pinned_homebrew_edge_count": edge_classes.count("pinned-homebrew"),
        "sealed_system_edge_count": edge_classes.count("sealed-system"),
        "graph_sha256": graph_sha256,
    }
    return {
        **core,
        "sha256": hashlib.sha256(canonical_compact_json(core)).hexdigest(),
    }


def validate_otool_custody_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(
        value,
        {
            "policy",
            "invocation_path",
            "resolved_path",
            "symlinks",
            "sha256",
            "bytes",
            "package_id",
            "package_version",
        },
        label,
    )
    exact_literal(record["policy"], OTOOL_CUSTODY_POLICY, f"{label}.policy")
    exact_literal(
        record["invocation_path"], str(PINNED_OTOOL_INVOCATION), f"{label}.invocation"
    )
    exact_literal(
        record["resolved_path"], str(PINNED_OTOOL_RESOLVED), f"{label}.resolved"
    )
    exact_literal(
        record["symlinks"],
        [{"path": str(PINNED_OTOOL_INVOCATION), "target": "llvm-otool"}],
        f"{label}.symlinks",
    )
    exact_literal(record["sha256"], PINNED_OTOOL_SHA256, f"{label}.sha256")
    exact_literal(record["bytes"], PINNED_OTOOL_BYTES, f"{label}.bytes")
    exact_literal(record["package_id"], PINNED_CLT_PACKAGE_ID, f"{label}.package id")
    exact_literal(
        record["package_version"], PINNED_CLT_VERSION, f"{label}.package version"
    )
    return record


def validate_qemu_runtime_closure_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(
        value,
        {
            "policy",
            "otool",
            "otool_custody",
            "system_policy",
            "system_dependency_prefixes",
            "system_volume",
            "system_build",
            "host_exclusivity_limit",
            "invocation_path",
            "resolved_path",
            "symlinks",
            "nodes",
            "node_count",
            "load_edge_count",
            "pinned_homebrew_edge_count",
            "sealed_system_edge_count",
            "graph_sha256",
            "sha256",
        },
        label,
    )
    exact_literal(record["policy"], QEMU_RUNTIME_CLOSURE_POLICY, f"{label}.policy")
    exact_literal(
        record["otool"], str(PINNED_OTOOL_INVOCATION), f"{label}.otool"
    )
    validate_otool_custody_record(record["otool_custody"], f"{label}.otool custody")
    exact_literal(
        record["system_policy"], "darwin-sealed-system-volume", f"{label}.system policy"
    )
    exact_literal(
        record["system_dependency_prefixes"],
        QEMU_RUNTIME_SYSTEM_PREFIXES,
        f"{label}.system prefixes",
    )
    exact_literal(
        record["system_volume"],
        {"filesystem": "apfs", "sealed": True, "read_only": True},
        f"{label}.system volume",
    )
    exact_literal(
        record["system_build"], PINNED_DARWIN_HOST_BUILD, f"{label}.system build"
    )
    exact_literal(
        record["host_exclusivity_limit"],
        QEMU_RUNTIME_HOST_LIMIT,
        f"{label}.host exclusivity",
    )
    invocation = pathlib.Path(
        exact_text(record["invocation_path"], f"{label}.invocation path")
    )
    resolved = pathlib.Path(
        exact_text(record["resolved_path"], f"{label}.resolved path")
    )
    require(invocation.is_absolute() and resolved.is_absolute(), f"{label} paths differ")
    links = record["symlinks"]
    require(type(links) is list, f"{label}.symlinks differs")
    seen_links: set[str] = set()
    for index, value_link in enumerate(links):
        link = exact_keys(value_link, {"path", "target"}, f"{label}.symlink {index}")
        path = exact_text(link["path"], f"{label}.symlink path")
        require(path.startswith("/") and path not in seen_links, f"{label}.symlink differs")
        seen_links.add(path)
        exact_text(link["target"], f"{label}.symlink target")
    exact_literal(links, sorted(links, key=lambda item: item["path"]), f"{label}.symlink order")
    nodes = record["nodes"]
    require(type(nodes) is list and len(nodes) > 0, f"{label}.nodes is empty")
    observed_nodes: dict[str, dict[str, Any]] = {}
    for index, value_node in enumerate(nodes):
        node = exact_keys(
            value_node,
            {"path", "sha256", "bytes", "rpaths", "dependencies"},
            f"{label}.node {index}",
        )
        path = exact_text(node["path"], f"{label}.node path")
        require(path.startswith("/") and path not in observed_nodes, f"{label}.node path differs")
        identity({"sha256": node["sha256"], "bytes": node["bytes"]}, f"{label}.node")
        rpaths = node["rpaths"]
        require(
            type(rpaths) is list
            and all(type(item) is str and item for item in rpaths),
            f"{label}.node rpaths differ",
        )
        dependencies = node["dependencies"]
        require(type(dependencies) is list, f"{label}.dependencies differ")
        for edge_index, value_edge in enumerate(dependencies):
            require(type(value_edge) is dict, f"{label}.dependency differs")
            edge = exact_keys(
                value_edge,
                (
                    {"install_name", "class"}
                    if value_edge.get("class") == "sealed-system"
                    else {"install_name", "class", "resolved_path"}
                ),
                f"{label}.dependency {edge_index}",
            )
            install_name = exact_text(
                edge["install_name"], f"{label}.dependency install name"
            )
            if edge["class"] == "sealed-system":
                require(
                    any(install_name.startswith(prefix) for prefix in QEMU_RUNTIME_SYSTEM_PREFIXES),
                    f"{label}.system dependency escaped sealed prefixes",
                )
            else:
                exact_literal(edge["class"], "pinned-homebrew", f"{label}.dependency class")
                dependency_path = exact_text(
                    edge["resolved_path"], f"{label}.dependency resolved path"
                )
                require(
                    dependency_path.startswith("/opt/homebrew/Cellar/"),
                    f"{label}.dependency escaped Homebrew Cellar",
                )
        observed_nodes[path] = node
    exact_literal(nodes, [observed_nodes[path] for path in sorted(observed_nodes)], f"{label}.node order")
    require(str(resolved) in observed_nodes, f"{label}.root node is missing")
    for node in nodes:
        for edge in node["dependencies"]:
            if edge["class"] == "pinned-homebrew":
                require(
                    edge["resolved_path"] in observed_nodes,
                    f"{label}.dependency node is missing",
                )
    edge_classes = [
        edge["class"] for node in nodes for edge in node["dependencies"]
    ]
    observed_counts = {
        "nodes": len(nodes),
        "load_edges": len(edge_classes),
        "pinned_homebrew_edges": edge_classes.count("pinned-homebrew"),
        "sealed_system_edges": edge_classes.count("sealed-system"),
    }
    recorded_counts = {
        "nodes": exact_int(record["node_count"], f"{label}.node count"),
        "load_edges": exact_int(
            record["load_edge_count"], f"{label}.load edge count"
        ),
        "pinned_homebrew_edges": exact_int(
            record["pinned_homebrew_edge_count"],
            f"{label}.pinned Homebrew edge count",
        ),
        "sealed_system_edges": exact_int(
            record["sealed_system_edge_count"],
            f"{label}.sealed-system edge count",
        ),
    }
    exact_literal(recorded_counts, observed_counts, f"{label}.recomputed counts")
    exact_literal(
        recorded_counts, PINNED_QEMU_RUNTIME_COUNTS, f"{label}.preparation counts"
    )
    normalized_nodes = []
    for node in nodes:
        normalized = dict(node)
        if node["path"] == str(resolved):
            normalized["path"] = "<qemu-executable>"
        normalized_nodes.append(normalized)
    normalized_nodes.sort(key=lambda node: str(node["path"]))
    exact_literal(
        record["graph_sha256"],
        hashlib.sha256(canonical_compact_json({"nodes": normalized_nodes})).hexdigest(),
        f"{label}.graph hash",
    )
    exact_literal(
        record["graph_sha256"],
        PINNED_QEMU_RUNTIME_GRAPH_SHA256,
        f"{label}.preparation graph pin",
    )
    core = {key: record[key] for key in record if key != "sha256"}
    exact_literal(
        record["sha256"],
        hashlib.sha256(canonical_compact_json(core)).hexdigest(),
        f"{label}.closure hash",
    )
    return record


def validate_qemu_runtime_closures(
    value: Any,
    *,
    qemu_bin: pathlib.Path | None,
    execution_qemu_bin: pathlib.Path | None,
    actual_argv: list[str],
    verify_live: bool,
) -> None:
    record = exact_keys(
        value,
        {
            "policy",
            "host_exclusivity_limit",
            "module_search",
            "source",
            "execution_custody",
        },
        "environment.qemu.runtime_closures",
    )
    exact_literal(
        record["policy"],
        "source-and-execution-custody-pre-post-final-v1",
        "QEMU runtime phase policy",
    )
    exact_literal(
        record["host_exclusivity_limit"],
        QEMU_RUNTIME_HOST_LIMIT,
        "QEMU runtime host-exclusivity limit",
    )
    module_candidates = [
        PINNED_QEMU_PREFIX / "lib/qemu",
        pathlib.Path("/opt/homebrew/lib/qemu"),
        PINNED_QEMU_PREFIX / "qemu-bundle",
        PINNED_QEMU_PREFIX / "libexec/qemu",
    ]
    require(
        actual_argv.count("-no-user-config") == 1 and actual_argv.count("-L") == 1,
        "actual QEMU argv does not disable user config/data search",
    )
    data_directory = pathlib.Path(actual_argv[actual_argv.index("-L") + 1])
    exact_literal(
        record["module_search"],
        {
            "policy": "no-plugin-argv-and-absent-qemu-module-directories-v1",
            "qemu_prefix": str(PINNED_QEMU_PREFIX),
            "environment_override": "QEMU_MODULE_DIR",
            "environment_override_absent": True,
            "plugin_argv_absent": True,
            "user_config_disabled": True,
            "data_directory": {
                "path": str(data_directory),
                "mode": QEMU_DATA_DIRECTORY_MODE,
                "empty": True,
            },
            "candidate_directories": [
                {"path": str(path), "absent": True} for path in module_candidates
            ],
            "scope_limit": (
                "closes QEMU module/plugin search; generic library-internal dlopen is not "
                "claimed beyond the recursive Mach-O load-command graph"
            ),
        },
        "QEMU module search closure",
    )
    require(
        "-plugin" not in actual_argv
        and all(not item.startswith("-plugin=") for item in actual_argv),
        "actual QEMU argv enables plugin loading",
    )
    phase_records: dict[str, dict[str, dict[str, Any]]] = {}
    for role in ("source", "execution_custody"):
        phases = exact_keys(
            record[role], {"before", "after", "final"}, f"QEMU runtime {role}"
        )
        checked = {
            phase: validate_qemu_runtime_closure_record(
                phases[phase], f"QEMU runtime {role}.{phase}"
            )
            for phase in ("before", "after", "final")
        }
        exact_literal(checked["after"], checked["before"], f"QEMU runtime {role} after")
        exact_literal(checked["final"], checked["before"], f"QEMU runtime {role} final")
        phase_records[role] = checked
    exact_literal(
        phase_records["source"]["before"]["graph_sha256"],
        phase_records["execution_custody"]["before"]["graph_sha256"],
        "source/custody QEMU runtime graph",
    )
    if verify_live:
        require(qemu_bin is not None and execution_qemu_bin is not None, "live QEMU closure paths are missing")
        exact_literal(
            qemu_bin.resolve(strict=True).parent.parent,
            PINNED_QEMU_PREFIX,
            "live QEMU installation prefix",
        )
        require(
            all(not os.path.lexists(path) for path in module_candidates),
            "a live QEMU module search directory is present",
        )
        data_status = data_directory.lstat()
        require(
            stat.S_ISDIR(data_status.st_mode)
            and not data_directory.is_symlink()
            and data_status.st_uid == os.getuid()
            and stat.S_IMODE(data_status.st_mode) == int(QEMU_DATA_DIRECTORY_MODE, 8)
            and not tuple(data_directory.iterdir()),
            "live QEMU data directory differs",
        )
        exact_literal(
            qemu_runtime_closure(qemu_bin),
            phase_records["source"]["before"],
            "live source QEMU runtime closure",
        )
        exact_literal(
            qemu_runtime_closure(execution_qemu_bin),
            phase_records["execution_custody"]["before"],
            "live custody QEMU runtime closure",
        )


def normalize_actual_qemu_argv(
    value: Any,
    *,
    execution_qemu_bin: pathlib.Path | None,
    execution_bios_bin: pathlib.Path | None,
    execution_kernel_bin: pathlib.Path | None,
    verify_live: bool,
) -> list[str]:
    require(
        type(value) is list and all(type(item) is str and item for item in value),
        "environment.qemu.actual_argv differs",
    )
    actual = list(value)
    require(len(actual) == len(NORMALIZED_QEMU_ARGV), "actual QEMU argv length differs")
    qemu = pathlib.Path(actual[0])
    require(qemu.is_absolute() and qemu.name == CUSTODY_ROLES["qemu"][0], "actual QEMU executable differs")
    require(
        actual.count("-no-user-config") == 1
        and actual.count("-L") == 1
        and actual.count("-bios") == 1
        and actual.count("-kernel") == 1,
        "actual QEMU configuration/binary arguments differ",
    )
    data_directory = pathlib.Path(actual[actual.index("-L") + 1])
    bios = pathlib.Path(actual[actual.index("-bios") + 1])
    kernel = pathlib.Path(actual[actual.index("-kernel") + 1])
    require(
        bios.is_absolute()
        and kernel.is_absolute()
        and bios.name == CUSTODY_ROLES["bios"][0]
        and kernel.name == CUSTODY_ROLES["kernel_elf"][0]
        and qemu.parent == bios.parent == kernel.parent,
        "actual QEMU custody paths differ",
    )
    require(
        data_directory.is_absolute()
        and data_directory.name == "data"
        and data_directory.parent.name == "qemu-environment",
        "actual QEMU private data directory differs",
    )
    port_pattern = re.compile(
        r"hostfwd=tcp:127\.0\.0\.1:([1-9][0-9]{0,4})-10\.0\.2\.15:2222"
    )
    matches = [
        (index, match)
        for index, item in enumerate(actual)
        if (match := port_pattern.search(item)) is not None
    ]
    require(len(matches) == 1, "actual QEMU host-forward binding differs")
    port = int(matches[0][1].group(1), 10)
    require(1 <= port <= 65535, "actual QEMU host-forward port differs")
    normalized = list(actual)
    normalized[0] = "qemu-system-riscv64"
    normalized[normalized.index("-L") + 1] = "<qemu-data>"
    normalized[normalized.index("-bios") + 1] = "<opensbi>"
    normalized[normalized.index("-kernel") + 1] = "<kernel>"
    index, match = matches[0]
    normalized[index] = normalized[index].replace(
        match.group(0),
        "hostfwd=tcp:127.0.0.1:<host-port>-10.0.2.15:2222",
    )
    exact_literal(normalized, NORMALIZED_QEMU_ARGV, "normalized actual QEMU argv")
    if verify_live:
        exact_literal(qemu, execution_qemu_bin, "actual/live QEMU executable")
        exact_literal(bios, execution_bios_bin, "actual/live QEMU BIOS")
        exact_literal(kernel, execution_kernel_bin, "actual/live QEMU kernel")
        status = data_directory.lstat()
        require(
            stat.S_ISDIR(status.st_mode)
            and not data_directory.is_symlink()
            and status.st_uid == os.getuid()
            and stat.S_IMODE(status.st_mode) == int(QEMU_DATA_DIRECTORY_MODE, 8)
            and not tuple(data_directory.iterdir()),
            "live QEMU private data directory differs",
        )
    return normalized


def parse_toolchain_pin() -> tuple[str, str]:
    try:
        source = read_regular(
            ROOT / "rust-toolchain.toml", "rust-toolchain.toml", MAX_CONTRACT_BYTES
        ).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError(
            f"rust-toolchain.toml is not strict UTF-8: {error}"
        ) from error
    channel = re.search(r'^channel = "([^"]+)"$', source, re.MULTILINE)
    commit = re.search(r"^# rustc-commit: ([0-9a-f]{40})$", source, re.MULTILINE)
    require(
        channel is not None and commit is not None, "rust-toolchain.toml pin differs"
    )
    return channel.group(1), commit.group(1)


def validate_tool_file(value: Any, label: str, *, verify_live: bool) -> dict[str, Any]:
    record = exact_keys(value, {"path", "sha256", "bytes"}, label)
    path = pathlib.Path(exact_text(record["path"], f"{label}.path"))
    require(path.is_absolute(), f"{label}.path must be absolute provenance")
    identity({"sha256": record["sha256"], "bytes": record["bytes"]}, label)
    if verify_live:
        verify_local_identity(record, path, label)
    return record


def validate_linker_runtime_record(value: Any, label: str) -> dict[str, Any]:
    record = exact_keys(
        value,
        {
            "policy",
            "otool",
            "otool_custody",
            "system_policy",
            "invocation_path",
            "resolved_path",
            "symlinks",
            "nodes",
            "sha256",
        },
        label,
    )
    exact_literal(
        record["policy"],
        "darwin-recursive-nonsystem-macho-closure-v1",
        f"{label}.policy",
    )
    exact_literal(
        record["otool"], str(PINNED_OTOOL_INVOCATION), f"{label}.otool"
    )
    validate_otool_custody_record(record["otool_custody"], f"{label}.otool custody")
    exact_literal(
        record["system_policy"],
        "darwin-sealed-system-volume",
        f"{label}.system_policy",
    )
    invocation = pathlib.Path(
        exact_text(record["invocation_path"], f"{label}.invocation_path")
    )
    resolved = pathlib.Path(
        exact_text(record["resolved_path"], f"{label}.resolved_path")
    )
    require(
        invocation.is_absolute()
        and resolved.is_absolute()
        and str(resolved).startswith("/opt/homebrew/Cellar/"),
        f"{label} paths differ",
    )
    require(type(record["symlinks"]) is list, f"{label}.symlinks differs")
    require(
        type(record["nodes"]) is list and bool(record["nodes"]),
        f"{label}.nodes differs",
    )
    digest = exact_text(record["sha256"], f"{label}.sha256")
    require(HEX64.fullmatch(digest) is not None, f"{label}.sha256 differs")
    core = {name: record[name] for name in record if name != "sha256"}
    exact_literal(
        hashlib.sha256(canonical_compact_json(core)).hexdigest(),
        digest,
        f"{label} canonical core digest",
    )
    exact_literal(digest, PINNED_LLD_RUNTIME_SHA256, f"{label} pinned digest")
    return record


def validate_toolchain(
    value: Any,
    source: str,
    challenge: str,
    capture_mode: str,
    source_commit_timestamp: str,
    *,
    verify_live: bool = True,
    build_source_root: pathlib.Path | None = None,
    private_cargo_home: pathlib.Path | None = None,
    private_crate_sources: pathlib.Path | None = None,
    private_crate_archives: pathlib.Path | None = None,
    cargo_target_path: pathlib.Path | None = None,
    toolchain_root_path: pathlib.Path | None = None,
    rust_src_path: pathlib.Path | None = None,
    linker_bin: pathlib.Path | None = None,
) -> None:
    toolchain = exact_keys(
        value,
        {
            "channel",
            "pinned_rustc_commit",
            "rustc_vv",
            "cargo_version",
            "rustup",
            "cargo",
            "rustc",
            "rustdoc",
            "linker",
            "cargo_command",
            "build_environment_policy",
            "build_input_closure",
        },
        "environment.toolchain",
    )
    channel, commit = parse_toolchain_pin()
    exact_literal(toolchain["channel"], channel, "toolchain.channel")
    exact_literal(
        toolchain["pinned_rustc_commit"], commit, "toolchain.pinned_rustc_commit"
    )
    rustc_vv = exact_text(toolchain["rustc_vv"], "toolchain.rustc_vv", maximum=16_384)
    require(
        re.search(rf"^commit-hash: {commit}$", rustc_vv, re.MULTILINE) is not None,
        "toolchain rustc -Vv does not prove the pinned commit",
    )
    require(
        exact_text(toolchain["cargo_version"], "toolchain.cargo_version").startswith(
            "cargo "
        ),
        "toolchain Cargo version differs",
    )
    tools = {
        name: validate_tool_file(
            toolchain[name], f"toolchain.{name}", verify_live=verify_live
        )
        for name in ("rustup", "cargo", "rustc", "rustdoc")
    }
    expected_toolchain_root = pathlib.Path(EXPECTED_PLATFORM["rust_toolchain_root"])
    for name in ("cargo", "rustc", "rustdoc"):
        exact_literal(
            pathlib.Path(tools[name]["path"]),
            expected_toolchain_root / "bin" / name,
            f"toolchain-bound {name} path",
        )
    linker = exact_keys(
        toolchain["linker"],
        {"invocation_path", "resolved_path", "sha256", "bytes"},
        "toolchain.linker",
    )
    invocation = pathlib.Path(
        exact_text(linker["invocation_path"], "linker.invocation_path")
    )
    resolved = pathlib.Path(exact_text(linker["resolved_path"], "linker.resolved_path"))
    require(
        invocation.is_absolute() and resolved.is_absolute(),
        "linker paths must be absolute provenance",
    )
    require(invocation.name == "ld.lld", "linker invocation must be ld.lld")
    identity({"sha256": linker["sha256"], "bytes": linker["bytes"]}, "toolchain.linker")
    if verify_live:
        verify_local_identity(linker, resolved, "toolchain.linker")

    command = toolchain["cargo_command"]
    feature = (
        "wasm-c84-qemu-aot-decision"
        if capture_mode == FORMAL_CAPTURE_MODE
        else "wasm-c84-qemu-aot-decision-smoke"
    )
    expected_command = [
        tools["cargo"]["path"],
        "build",
        "--manifest-path",
        (
            "<materialized-source>/firmware/qemu-virt/Cargo.toml"
            if capture_mode == FORMAL_CAPTURE_MODE
            else "<dirty-worktree>/firmware/qemu-virt/Cargo.toml"
        ),
        "--release",
        "--locked",
        "--offline",
        "--no-default-features",
        "--features",
        feature,
    ]
    exact_literal(command, expected_command, "toolchain.cargo_command")

    policy = exact_keys(
        toolchain["build_environment_policy"],
        {
            "ambient_variables",
            "cargo_home",
            "cargo_net_offline",
            "path_entries",
            "allowed_names",
            "normalized_values",
        },
        "toolchain.build_environment_policy",
    )
    exact_literal(
        policy["ambient_variables"], "denied-by-default", "build env ambient policy"
    )
    exact_literal(
        policy["cargo_home"],
        "private-generated-config-directory-source-only",
        "build env Cargo home policy",
    )
    exact_literal(policy["cargo_net_offline"], True, "build env offline policy")
    path_entries = policy["path_entries"]
    exact_literal(
        path_entries,
        ["/opt/homebrew/bin", "/usr/bin", "/bin"],
        "build environment PATH entries",
    )
    values = policy["normalized_values"]
    require(
        type(values) is dict, "build environment normalized_values must be an object"
    )
    exact_literal(
        policy["allowed_names"], sorted(values), "build environment allowlist"
    )
    expected_names = {
        "__CARGO_TEST_LAST_USE_NOW",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TERM_COLOR",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "RUSTC",
        "RUSTDOC",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
        "TZ",
        "VIBEOS_C84_CHALLENGE",
        "VIBEOS_C84_SOURCE_COMMIT",
    }
    exact_keys(values, expected_names, "build environment normalized_values")
    fixed = {
        "__CARGO_TEST_LAST_USE_NOW": "1234567890",
        "CARGO_HOME": "<private-cargo-home>",
        "CARGO_TARGET_DIR": "<private-target>",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "HOME": "<private-build-home>",
        "LANG": "C",
        "LC_ALL": "C",
        "RUSTC": tools["rustc"]["path"],
        "RUSTDOC": tools["rustdoc"]["path"],
        "TMPDIR": "<private-build-tmp>",
        "TZ": "UTC",
        "VIBEOS_C84_CHALLENGE": challenge,
        "VIBEOS_C84_SOURCE_COMMIT": source,
    }
    for key, expected in fixed.items():
        exact_literal(values[key], expected, f"build environment {key}")
    exact_literal(
        values["PATH"], os.pathsep.join(path_entries), "build environment PATH"
    )
    exact_literal(
        values["SOURCE_DATE_EPOCH"],
        source_commit_timestamp,
        "build environment SOURCE_DATE_EPOCH/source commit timestamp",
    )
    closure = exact_keys(
        toolchain["build_input_closure"],
        {
            "policy",
            "normalized_paths",
            "cargo_locks",
            "private_crate_sources",
            "private_crate_archives",
            "cargo_configuration",
            "toolchain_tree",
            "rust_src",
            "linker_runtime",
        },
        "toolchain.build_input_closure",
    )
    exact_literal(
        closure["policy"],
        "c84-private-build-input-closure-v1",
        "build input closure policy",
    )
    normalized_paths = exact_keys(
        closure["normalized_paths"],
        {
            "policy",
            "source_root",
            "manifest",
            "cargo_home",
            "private_crate_sources",
            "private_crate_archives",
            "cargo_target",
            "toolchain_root",
            "rust_src",
        },
        "build input normalized paths",
    )
    exact_literal(
        normalized_paths["policy"],
        "canonical-realpath-no-leaf-symlink-v1",
        "build input path policy",
    )
    recorded_paths = {
        name: pathlib.Path(
            exact_text(normalized_paths[name], f"build input path {name}")
        )
        for name in (
            "source_root",
            "manifest",
            "cargo_home",
            "private_crate_sources",
            "private_crate_archives",
            "cargo_target",
            "toolchain_root",
            "rust_src",
        )
    }
    require(
        all(path.is_absolute() and ".." not in path.parts for path in recorded_paths.values()),
        "build input paths are not normalized absolute paths",
    )
    exact_literal(
        recorded_paths["manifest"],
        recorded_paths["source_root"] / "firmware/qemu-virt/Cargo.toml",
        "build input manifest relationship",
    )
    cargo_locks = exact_keys(
        closure["cargo_locks"],
        {"policy", "project", "rust_src", "union"},
        "build input Cargo locks",
    )
    exact_literal(
        cargo_locks,
        {
            "policy": "project-plus-pinned-rust-src-lock-union-v1",
            "project": {
                "path": "Cargo.lock",
                "sha256": PINNED_CARGO_LOCK_SHA256,
                "bytes": PINNED_CARGO_LOCK_BYTES,
                "registry_source": CRATES_IO_SOURCE,
                "packages": PINNED_CARGO_PACKAGES,
                "package_set_sha256": PINNED_CARGO_PACKAGE_SET_SHA256,
            },
            "rust_src": {
                "path": "lib/rustlib/src/rust/library/Cargo.lock",
                "sha256": PINNED_RUST_SRC_CARGO_LOCK["sha256"],
                "bytes": PINNED_RUST_SRC_CARGO_LOCK["bytes"],
                "registry_source": CRATES_IO_SOURCE,
                "packages": PINNED_RUST_SRC_CARGO_PACKAGES,
                "package_set_sha256": PINNED_RUST_SRC_CARGO_PACKAGE_SET_SHA256,
            },
            "union": {
                "packages": PINNED_CARGO_UNION_PACKAGES,
                "exact_overlap": PINNED_CARGO_UNION_EXACT_OVERLAP,
                "project_only": PINNED_CARGO_UNION_PROJECT_ONLY,
                "rust_src_only": PINNED_CARGO_UNION_RUST_SRC_ONLY,
                "package_set_sha256": PINNED_CARGO_UNION_PACKAGE_SET_SHA256,
            },
        },
        "build input Cargo locks",
    )
    crate_sources = exact_keys(
        closure["private_crate_sources"],
        {
            "method",
            "archive_source",
            "rust_src_vendor_source",
            "archive_count",
            "rust_src_vendor_count",
            "archive_bytes",
            "source_files",
            "source_bytes",
            "mode_policy",
            "checksum_file_policy",
            "rust_src_materialization_before",
            "rust_src_materialization_after",
            "before",
            "after",
        },
        "private crate sources",
    )
    fixed_crates = {
        "method": "verified-project-lock-archives-plus-rust-src-vendor-union-v1",
        "archive_source": "fixed-launcher-cargo-home-registry-cache",
        "rust_src_vendor_source": "pinned-rust-src-library-vendor",
        "archive_count": 189,
        "rust_src_vendor_count": 24,
        "archive_bytes": 23_706_909,
        "source_files": 11_391,
        "source_bytes": 137_564_030,
        "mode_policy": "directories-0500-files-0400-preserve-owner-execute-0500-v1",
        "checksum_file_policy": "canonical-cargo-directory-source-json-v1",
    }
    for name, expected in fixed_crates.items():
        exact_literal(crate_sources[name], expected, f"private crate sources {name}")
    exact_literal(crate_sources["before"], PINNED_PRIVATE_CRATE_TREE, "private crate tree before")
    exact_literal(crate_sources["after"], PINNED_PRIVATE_CRATE_TREE, "private crate tree after")
    exact_literal(
        crate_sources["rust_src_materialization_before"],
        PINNED_RUST_SRC_TREE,
        "rust-src before crate materialization",
    )
    exact_literal(
        crate_sources["rust_src_materialization_after"],
        PINNED_RUST_SRC_TREE,
        "rust-src after crate materialization",
    )
    archive_closure = exact_keys(
        closure["private_crate_archives"],
        {"root", "before", "after"},
        "private crate archive closure",
    )
    recorded_archive_root = pathlib.Path(
        exact_text(archive_closure["root"], "private crate archive root")
    )
    require(
        recorded_archive_root.is_absolute(),
        "private crate archive root is not absolute",
    )
    exact_literal(
        archive_closure["before"],
        PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
        "private crate archive tree before",
    )
    exact_literal(
        archive_closure["after"],
        PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
        "private crate archive tree after",
    )
    exact_literal(
        recorded_paths["private_crate_archives"],
        recorded_archive_root,
        "normalized private crate archive root",
    )
    cargo_configuration = exact_keys(
        closure["cargo_configuration"],
        {
            "discovery_policy",
            "root_before",
            "root_after",
            "materialized_firmware",
            "generated",
            "private_home_before",
            "private_home_after",
            "cargo_subprocess_umask",
            "transient_outputs",
        },
        "Cargo configuration closure",
    )
    exact_literal(
        cargo_configuration["discovery_policy"],
        "filesystem-root-plus-private-cargo-home-v1",
        "Cargo config discovery policy",
    )
    root_absence = {
        "cwd": "/",
        "candidates": ["/.cargo/config", "/.cargo/config.toml"],
        "all_absent": True,
    }
    exact_literal(cargo_configuration["root_before"], root_absence, "root Cargo config before")
    exact_literal(cargo_configuration["root_after"], root_absence, "root Cargo config after")
    firmware_config = exact_keys(
        cargo_configuration["materialized_firmware"],
        {"path", "sha256", "bytes"},
        "materialized firmware Cargo config",
    )
    exact_literal(firmware_config["path"], "firmware/.cargo/config.toml", "firmware config path")
    identity({"sha256": firmware_config["sha256"], "bytes": firmware_config["bytes"]}, "firmware config")
    generated_config = exact_keys(
        cargo_configuration["generated"], {"path", "sha256", "bytes"}, "generated Cargo config"
    )
    exact_literal(generated_config["path"], "<private-cargo-home>/config.toml", "generated Cargo config path")
    identity({"sha256": generated_config["sha256"], "bytes": generated_config["bytes"]}, "generated Cargo config")
    private_home_expected = {
        "policy": "exact-private-cargo-home-config-only-v1",
        "root_mode": "0700",
        "entries": [
            {
                **generated_config,
                "mode": "0400",
                "links": 1,
            }
        ],
    }
    exact_literal(
        cargo_configuration["private_home_before"],
        private_home_expected,
        "private Cargo home before",
    )
    exact_literal(
        cargo_configuration["private_home_after"],
        private_home_expected,
        "private Cargo home after",
    )
    exact_literal(
        cargo_configuration["cargo_subprocess_umask"],
        "0077",
        "private Cargo subprocess umask",
    )
    exact_literal(
        cargo_configuration["transient_outputs"],
        {
            "policy": "fresh-pinned-cargo-runtime-outputs-validated-recorded-removed-v1",
            "precondition": "private-home-config-only-before-cargo",
            "entries": [
                {
                    "path": "<private-cargo-home>/.global-cache",
                    "kind": "sqlite3-global-cache",
                    "mode": "0600",
                    "links": 1,
                    "sha256": "66d946720de0afd44c2d5748698b700ce812830bd8a3dedaa589831610948d9d",
                    "bytes": 57_344,
                    "header": {
                        "magic": "SQLite format 3 NUL",
                        "page_size": 4096,
                        "write_version": 1,
                        "read_version": 1,
                        "database_pages": 14,
                        "schema_format": 4,
                        "encoding": 1,
                        "user_version": 7,
                        "sqlite_version": 3_053_002,
                    },
                },
                {
                    "path": "<private-cargo-home>/.package-cache",
                    "kind": "empty-advisory-lock",
                    "mode": "0600",
                    "links": 1,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "bytes": 0,
                },
                {
                    "path": "<private-cargo-home>/.package-cache-mutate",
                    "kind": "empty-advisory-lock",
                    "mode": "0600",
                    "links": 1,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "bytes": 0,
                },
                {
                    "path": "<private-cargo-home>/registry",
                    "kind": "directory",
                    "mode": "0700",
                    "entries": [
                        {
                            "path": "<private-cargo-home>/registry/CACHEDIR.TAG",
                            "kind": "cargo-cache-directory-tag",
                            "mode": "0600",
                            "links": 1,
                            "sha256": "6d9d1d216e0f83abc5e5662ca62c92b4f23009466b54fa27321a69acdb778bb2",
                            "bytes": 177,
                        }
                    ],
                },
            ],
        },
        "private Cargo deterministic transient outputs",
    )
    toolchain_tree = exact_keys(
        closure["toolchain_tree"], {"root", "before", "after"}, "toolchain tree"
    )
    recorded_toolchain_root = pathlib.Path(exact_text(toolchain_tree["root"], "toolchain tree root"))
    require(recorded_toolchain_root.is_absolute(), "toolchain tree root is not absolute")
    exact_literal(toolchain_tree["before"], PINNED_TOOLCHAIN_TREE, "toolchain tree before")
    exact_literal(toolchain_tree["after"], PINNED_TOOLCHAIN_TREE, "toolchain tree after")
    exact_literal(
        recorded_toolchain_root,
        expected_toolchain_root,
        "manifest-pinned toolchain root",
    )
    rust_src = exact_keys(
        closure["rust_src"],
        {"root", "relative_path", "before", "after", "cargo_toml", "cargo_lock"},
        "rust-src closure",
    )
    recorded_rust_src = pathlib.Path(exact_text(rust_src["root"], "rust-src root"))
    require(recorded_rust_src.is_absolute(), "rust-src root is not absolute")
    exact_literal(rust_src["relative_path"], "lib/rustlib/src/rust/library", "rust-src relative path")
    exact_literal(rust_src["before"], PINNED_RUST_SRC_TREE, "rust-src before")
    exact_literal(rust_src["after"], PINNED_RUST_SRC_TREE, "rust-src after")
    exact_literal(rust_src["cargo_toml"], PINNED_RUST_SRC_CARGO_TOML, "rust-src Cargo.toml")
    exact_literal(rust_src["cargo_lock"], PINNED_RUST_SRC_CARGO_LOCK, "rust-src Cargo.lock")
    exact_literal(recorded_paths["toolchain_root"], recorded_toolchain_root, "normalized toolchain root")
    exact_literal(recorded_paths["rust_src"], recorded_rust_src, "normalized rust-src root")
    exact_literal(
        recorded_rust_src,
        expected_toolchain_root / "lib/rustlib/src/rust/library",
        "toolchain-bound rust-src root",
    )
    linker_runtime = exact_keys(
        closure["linker_runtime"], {"before", "after"}, "linker runtime closure"
    )
    linker_runtime_before = validate_linker_runtime_record(
        linker_runtime["before"], "linker runtime before"
    )
    linker_runtime_after = validate_linker_runtime_record(
        linker_runtime["after"], "linker runtime after"
    )
    exact_literal(
        linker_runtime_after,
        linker_runtime_before,
        "linker runtime pre/post",
    )
    exact_literal(
        pathlib.Path(linker_runtime_before["invocation_path"]),
        invocation,
        "linker runtime invocation/tool identity",
    )
    exact_literal(
        pathlib.Path(linker_runtime_before["resolved_path"]),
        resolved,
        "linker runtime resolved/tool identity",
    )
    if verify_live:
        live_paths = (
            build_source_root,
            private_cargo_home,
            private_crate_sources,
            private_crate_archives,
            cargo_target_path,
            toolchain_root_path,
            rust_src_path,
            linker_bin,
        )
        require(all(path is not None and path.is_absolute() for path in live_paths), "build input live paths are required")
        assert build_source_root is not None
        assert private_cargo_home is not None
        assert private_crate_sources is not None
        assert private_crate_archives is not None
        assert cargo_target_path is not None
        assert toolchain_root_path is not None
        assert rust_src_path is not None
        assert linker_bin is not None
        live_directories = {
            "source_root": canonical_live_directory(build_source_root, "build source root"),
            "cargo_home": canonical_live_directory(private_cargo_home, "private Cargo home"),
            "private_crate_sources": canonical_live_directory(private_crate_sources, "private crate sources"),
            "private_crate_archives": canonical_live_directory(private_crate_archives, "private crate archives"),
            "cargo_target": canonical_live_directory(cargo_target_path, "private Cargo target"),
            "toolchain_root": canonical_live_directory(toolchain_root_path, "live toolchain root"),
            "rust_src": canonical_live_directory(rust_src_path, "live rust-src root"),
        }
        for name, path in live_directories.items():
            exact_literal(path, recorded_paths[name], f"live normalized {name}")
        exact_literal(
            strict_tree_identity(private_crate_archives, "live private crate archives"),
            PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
            "live private crate archive tree",
        )
        exact_literal(
            (build_source_root / "firmware/qemu-virt/Cargo.toml").resolve(strict=True),
            recorded_paths["manifest"],
            "live normalized manifest",
        )
        verify_private_crates(
            build_source_root,
            rust_src_path,
            private_crate_sources,
            private_crate_archives,
            {"cargo_locks": cargo_locks},
        )
        exact_literal(toolchain_root_path.resolve(strict=True), recorded_toolchain_root, "live toolchain root")
        exact_literal(
            pathlib.Path(tools["cargo"]["path"]).parent.parent.resolve(strict=True),
            recorded_toolchain_root,
            "Cargo/toolchain root",
        )
        exact_literal(strict_tree_identity(toolchain_root_path, "live toolchain"), PINNED_TOOLCHAIN_TREE, "live toolchain tree")
        exact_literal(rust_src_path.resolve(strict=True), recorded_rust_src, "live rust-src root")
        exact_literal(strict_tree_identity(rust_src_path, "live rust-src"), PINNED_RUST_SRC_TREE, "live rust-src tree")
        exact_literal(live_identity(rust_src_path / "Cargo.toml"), PINNED_RUST_SRC_CARGO_TOML, "live rust-src Cargo.toml")
        exact_literal(live_identity(rust_src_path / "Cargo.lock"), PINNED_RUST_SRC_CARGO_LOCK, "live rust-src Cargo.lock")
        firmware_raw = read_regular(
            build_source_root / "firmware/.cargo/config.toml",
            "materialized firmware Cargo config",
            MAX_CONTRACT_BYTES,
        )
        exact_literal(identity_for(firmware_raw), {"sha256": firmware_config["sha256"], "bytes": firmware_config["bytes"]}, "live firmware config")
        vendor_text = str(private_crate_sources).encode("utf-8", errors="strict")
        require(not any(byte < 0x20 or byte in (0x22, 0x5C, 0x7F) for byte in vendor_text), "private vendor TOML path differs")
        generated_raw = firmware_raw + (
            b"\n[cache]\n"
            b'auto-clean-frequency = "never"\n\n'
            b"[source.crates-io]\n"
            b'replace-with = "vibeos-c84-private"\n\n'
            b"[source.vibeos-c84-private]\n"
            + b'directory = "'
            + vendor_text
            + b'"\n'
        )
        exact_literal(
            read_regular(private_cargo_home / "config.toml", "private Cargo config", MAX_CONTRACT_BYTES),
            generated_raw,
            "private Cargo config bytes",
        )
        exact_literal(
            private_cargo_home_identity(private_cargo_home, generated_config),
            private_home_expected,
            "live exact private Cargo home",
        )
        require(not os.path.lexists("/.cargo/config") and not os.path.lexists("/.cargo/config.toml"), "root Cargo configuration appeared")
        exact_literal(linker_bin, invocation, "live linker invocation")
        live_linker = linker_runtime_closure(linker_bin)
        exact_literal(live_linker, linker_runtime_before, "live linker runtime closure")


def validate_helpers(value: Any, *, verify_live: bool) -> dict[str, dict[str, Any]]:
    helpers = exact_keys(value, set(HELPER_PATHS), "environment.helpers")
    checked: dict[str, dict[str, Any]] = {}
    for name, expected_path in HELPER_PATHS.items():
        record = path_identity(
            helpers[name], expected_path, f"environment.helpers.{name}"
        )
        if verify_live:
            verify_local_identity(
                record,
                ROOT / expected_path,
                f"environment.helpers.{name}",
            )
        checked[name] = record
    if verify_live:
        executed_base = getattr(BASE, "__vibeos_executed_source_closure__", None)
        exact_literal(
            executed_base,
            {
                str(PHYSICAL_VERIFIER_PATH): {
                    "sha256": checked["physical_contract_verifier"]["sha256"],
                    "bytes": checked["physical_contract_verifier"]["bytes"],
                }
            },
            "executed physical helper source closure",
        )
    return checked


def validate_executed_peer_sources(
    value: Any, helpers: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    expected_paths = {HELPER_PATHS[key] for key in EXECUTED_SOURCE_EVIDENCE_KEYS}
    records = exact_keys(value, expected_paths, "environment.executed_peer_sources")
    checked: dict[str, dict[str, Any]] = {}
    for key in EXECUTED_SOURCE_EVIDENCE_KEYS:
        relative = HELPER_PATHS[key]
        record = identity(records[relative], f"environment.executed_peer_sources.{relative}")
        exact_literal(
            record,
            {
                "sha256": helpers[key]["sha256"],
                "bytes": helpers[key]["bytes"],
            },
            f"executed/helper source identity {relative}",
        )
        checked[relative] = record
    return checked


def validate_live_binary(
    record: dict[str, Any],
    supplied: pathlib.Path | None,
    label: str,
    *,
    verify_live: bool,
    require_executable: bool = False,
) -> pathlib.Path:
    recorded_path = pathlib.Path(exact_text(record["path"], f"{label}.path"))
    require(recorded_path.is_absolute(), f"{label}.path must be absolute provenance")
    if not verify_live:
        return recorded_path
    require(supplied is not None, f"{label} requires an explicit live binary path")
    require(supplied.is_absolute(), f"explicit live {label} path must be absolute")
    try:
        supplied_resolved = supplied.resolve(strict=True)
        recorded_resolved = recorded_path.resolve(strict=True)
    except OSError as error:
        raise VerificationError(f"cannot resolve live {label} path: {error}") from error
    require(supplied_resolved.is_file(), f"live {label} is not a regular file")
    exact_literal(recorded_path, recorded_resolved, f"{label}.canonical path")
    exact_literal(supplied, supplied_resolved, f"explicit live {label} canonical path")
    if require_executable:
        require(
            os.access(supplied_resolved, os.X_OK), f"live {label} is not executable"
        )
    exact_literal(recorded_resolved, supplied_resolved, f"{label}.path")
    verify_local_identity(record, supplied_resolved, label)
    return supplied_resolved


def expected_darwin_system_openssh_record() -> dict[str, Any]:
    return {
        "method": DARWIN_OPENSSH_METHOD,
        "path": str(DARWIN_SYSTEM_OPENSSH),
        "mode": "0755",
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "sf_restricted": True,
        "same_device_as_root": True,
        "root_volume": {
            "filesystem": "apfs",
            "sealed": True,
            "read_only": True,
        },
        "version": PINNED_OPENSSH_VERSION,
        "sha256": PINNED_OPENSSH_SHA256,
        "bytes": PINNED_OPENSSH_BYTES,
    }


def parse_darwin_root_mount(output: str) -> dict[str, Any]:
    matches = []
    for line in output.splitlines():
        match = re.fullmatch(r".+ on / \(([^()]*)\)", line)
        if match is not None:
            matches.append(match.group(1))
    require(len(matches) == 1, "Darwin root mount record is not unique")
    options = [item.strip() for item in matches[0].split(",")]
    require(
        all(options) and len(options) == len(set(options)),
        "Darwin root mount options are malformed",
    )
    option_set = set(options)
    require("apfs" in option_set, "Darwin root filesystem is not APFS")
    require("sealed" in option_set, "Darwin root APFS volume is not sealed")
    require("read-only" in option_set, "Darwin root APFS volume is not read-only")
    return {"filesystem": "apfs", "sealed": True, "read_only": True}


def live_darwin_root_volume_record() -> dict[str, Any]:
    require(sys.platform == "darwin", "live system-volume custody requires Darwin")
    try:
        mount = subprocess.run(
            [str(DARWIN_MOUNT)],
            cwd=ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise VerificationError(f"cannot inspect Darwin root mount: {error}") from error
    require(
        mount.returncode == 0 and not mount.stderr.strip(),
        f"cannot inspect Darwin root mount: {mount.stderr.strip() or mount.returncode}",
    )
    return parse_darwin_root_mount(mount.stdout)


def live_darwin_host_build_record() -> dict[str, str]:
    environment = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"}
    try:
        version = subprocess.run(
            ["/usr/bin/sw_vers"],
            cwd=pathlib.Path("/"),
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        release = subprocess.run(
            ["/usr/bin/uname", "-r"],
            cwd=pathlib.Path("/"),
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise VerificationError(f"cannot identify Darwin host build: {error}") from error
    require(
        version.returncode == 0
        and release.returncode == 0
        and not version.stderr.strip()
        and not release.stderr.strip(),
        "cannot identify Darwin host build",
    )
    fields: dict[str, str] = {}
    for line in version.stdout.splitlines():
        key, separator, value = line.partition(":")
        require(separator == ":" and value.strip(), "Darwin sw_vers output differs")
        fields[key] = value.strip()
    record = {
        "product_name": fields.get("ProductName", ""),
        "product_version": fields.get("ProductVersion", ""),
        "build_version": fields.get("BuildVersion", ""),
        "darwin_release": release.stdout.strip(),
    }
    exact_literal(record, PINNED_DARWIN_HOST_BUILD, "Darwin host build")
    return record


def live_darwin_system_openssh_record(
    supplied: pathlib.Path | None,
) -> dict[str, Any]:
    require(sys.platform == "darwin", "live OpenSSH custody requires Darwin")
    require(supplied == DARWIN_SYSTEM_OPENSSH, "--openssh-bin must be /usr/bin/ssh")
    path = DARWIN_SYSTEM_OPENSSH
    try:
        before = path.lstat()
        root = pathlib.Path("/").lstat()
        resolved = path.resolve(strict=True)
        filesystem = os.statvfs(path)
    except OSError as error:
        raise VerificationError(
            f"cannot inspect pinned Darwin system OpenSSH: {error}"
        ) from error
    require(resolved == path, "pinned Darwin system OpenSSH path is not canonical")
    require(
        stat.S_ISREG(before.st_mode) and not path.is_symlink(),
        "pinned Darwin system OpenSSH is not a regular non-symlink file",
    )
    exact_literal(stat.S_IMODE(before.st_mode), 0o755, "pinned OpenSSH mode")
    exact_literal(before.st_uid, 0, "pinned OpenSSH uid")
    exact_literal(before.st_gid, 0, "pinned OpenSSH gid")
    exact_literal(before.st_nlink, 1, "pinned OpenSSH nlink")
    require(os.access(path, os.X_OK), "pinned OpenSSH is not executable")
    require(
        getattr(before, "st_flags", 0) & DARWIN_SF_RESTRICTED,
        "pinned OpenSSH lacks SF_RESTRICTED",
    )
    require(before.st_dev == root.st_dev, "pinned OpenSSH is not on the root device")
    require(
        filesystem.f_flag & getattr(os, "ST_RDONLY", 1),
        "pinned OpenSSH filesystem is not read-only",
    )
    root_volume = live_darwin_root_volume_record()
    observed_identity = identity_for(
        read_regular(path, "pinned Darwin system OpenSSH", 1 << 31)
    )
    exact_literal(
        observed_identity,
        {"sha256": PINNED_OPENSSH_SHA256, "bytes": PINNED_OPENSSH_BYTES},
        "pinned OpenSSH byte identity",
    )
    try:
        version_process = subprocess.run(
            [str(path), "-V"],
            cwd=ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as error:
        raise VerificationError(f"cannot execute pinned OpenSSH: {error}") from error
    version = version_process.stdout.strip()
    require(
        version_process.returncode == 0 and version == PINNED_OPENSSH_VERSION,
        "pinned OpenSSH version differs",
    )
    try:
        after = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot re-inspect pinned OpenSSH: {error}") from error
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_flags",
    )
    require(
        all(getattr(before, field) == getattr(after, field) for field in stable_fields),
        "pinned OpenSSH metadata changed during verification",
    )
    record = expected_darwin_system_openssh_record()
    exact_literal(record["root_volume"], root_volume, "Darwin root volume record")
    return record


def validate_darwin_system_openssh(
    value: Any,
    *,
    source_identity: dict[str, Any],
    source_version: str,
    supplied: pathlib.Path | None,
    verify_live: bool,
) -> dict[str, Any]:
    expected = expected_darwin_system_openssh_record()
    record = exact_keys(value, set(expected), "execution custody openssh")
    exact_literal(record, expected, "execution custody openssh")
    exact_literal(
        {"sha256": record["sha256"], "bytes": record["bytes"]},
        source_identity,
        "execution/source OpenSSH identity",
    )
    exact_literal(record["version"], source_version, "execution/source OpenSSH version")
    if verify_live:
        exact_literal(
            live_darwin_system_openssh_record(supplied),
            record,
            "live Darwin system OpenSSH custody",
        )
    return record


def validate_execution_custody(
    value: Any,
    *,
    source_identities: dict[str, dict[str, Any]],
    openssh_identity: dict[str, Any],
    openssh_version: str,
    execution_bins: dict[str, pathlib.Path | None],
    openssh_bin: pathlib.Path | None,
    verify_live: bool,
) -> dict[str, Any]:
    record = exact_keys(
        value,
        {"scheme", "private_directory_mode", "openssh", *CUSTODY_ROLES},
        "environment.execution_custody",
    )
    exact_literal(record["scheme"], CUSTODY_SCHEME, "execution custody scheme")
    exact_literal(
        record["private_directory_mode"],
        f"{CUSTODY_DIRECTORY_MODE:04o}",
        "execution custody directory mode",
    )
    require(
        set(source_identities) == set(CUSTODY_ROLES),
        "execution custody source roles differ",
    )
    require(
        set(execution_bins) == set(CUSTODY_ROLES),
        "execution custody live roles differ",
    )
    parents: set[pathlib.Path] = set()
    for role, (name, mode) in CUSTODY_ROLES.items():
        role_record = exact_keys(
            record[role],
            {"name", "mode", "sha256", "bytes"},
            f"execution custody {role}",
        )
        exact_literal(role_record["name"], name, f"execution custody {role}.name")
        exact_literal(
            role_record["mode"], f"{mode:04o}", f"execution custody {role}.mode"
        )
        role_identity = identity(
            {"sha256": role_record["sha256"], "bytes": role_record["bytes"]},
            f"execution custody {role}",
        )
        exact_literal(
            role_identity,
            source_identities[role],
            f"execution custody {role} source equality",
        )
        if not verify_live:
            continue
        supplied = execution_bins[role]
        require(supplied is not None, f"execution custody {role} live path is required")
        require(
            supplied.is_absolute(), f"execution custody {role} path must be absolute"
        )
        try:
            metadata = supplied.lstat()
        except OSError as error:
            raise VerificationError(
                f"cannot inspect execution custody {role}: {error}"
            ) from error
        require(
            stat.S_ISREG(metadata.st_mode)
            and not supplied.is_symlink()
            and metadata.st_nlink == 1,
            f"execution custody {role} is not a single-link regular file",
        )
        exact_literal(supplied.name, name, f"execution custody {role} filename")
        exact_literal(
            stat.S_IMODE(metadata.st_mode), mode, f"execution custody {role} file mode"
        )
        verify_local_identity(role_record, supplied, f"execution custody {role}")
        parents.add(supplied.parent)
    if verify_live:
        require(len(parents) == 1, "execution custody files do not share one directory")
        directory = next(iter(parents))
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise VerificationError(
                f"cannot inspect execution custody directory: {error}"
            ) from error
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not directory.is_symlink()
            and stat.S_IMODE(metadata.st_mode) == CUSTODY_DIRECTORY_MODE,
            "execution custody directory is not sealed",
        )
    validate_darwin_system_openssh(
        record["openssh"],
        source_identity=openssh_identity,
        source_version=openssh_version,
        supplied=openssh_bin,
        verify_live=verify_live,
    )
    return record


def validate_host_key_evidence(value: Any) -> dict[str, Any]:
    record = exact_keys(
        value,
        {"sha256", "bytes", "public_key", "fingerprint_sha256"},
        "environment.host_key_evidence",
    )
    exact_literal(record["public_key"], EXPECTED_HOST_PUBLIC_KEY, "host key public_key")
    exact_literal(
        record["fingerprint_sha256"],
        EXPECTED_HOST_FINGERPRINT,
        "host key fingerprint_sha256",
    )
    exact_literal(
        {"sha256": record["sha256"], "bytes": record["bytes"]},
        identity_for(EXPECTED_HOST_KEY_RAW),
        "host key canonical identity",
    )
    try:
        key_type, encoded = record["public_key"].split(" ")
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise VerificationError(
            f"host key public_key is not canonical: {error}"
        ) from error
    exact_literal(key_type, "ssh-ed25519", "host key type")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    exact_literal(
        fingerprint, record["fingerprint_sha256"], "host key derived fingerprint"
    )
    return record


def parse_utc(value: Any, label: str) -> datetime.datetime:
    text = exact_text(value, label)
    require(RFC3339_UTC.fullmatch(text) is not None, f"{label} must be RFC3339 UTC")
    try:
        return datetime.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise VerificationError(f"{label} is not a real timestamp") from error


def validate_environment(
    value: Any,
    *,
    raw: bytes,
    transcript: VerifiedTranscript,
    summary_raw: bytes,
    publication: bool,
    verify_live: bool = True,
    qemu_bin: pathlib.Path | None = None,
    bios_bin: pathlib.Path | None = None,
    kernel_bin: pathlib.Path | None = None,
    openssh_bin: pathlib.Path | None = None,
    materialized_source: pathlib.Path | None = None,
    build_source_root: pathlib.Path | None = None,
    private_cargo_home: pathlib.Path | None = None,
    private_crate_sources: pathlib.Path | None = None,
    private_crate_archives: pathlib.Path | None = None,
    cargo_target: pathlib.Path | None = None,
    toolchain_root: pathlib.Path | None = None,
    rust_src: pathlib.Path | None = None,
    linker_bin: pathlib.Path | None = None,
    execution_qemu_bin: pathlib.Path | None = None,
    execution_bios_bin: pathlib.Path | None = None,
    execution_kernel_bin: pathlib.Path | None = None,
) -> dict[str, Any]:
    environment = exact_keys(
        value,
        {
            "schema",
            "version",
            "suite_id",
            "mode",
            "platform",
            "platform_class",
            "physical_provenance",
            "source_commit",
            "challenge",
            "run_id",
            "started_at_utc",
            "ended_at_utc",
            "repository",
            "source_materialization",
            "contract",
            "runner",
            "verifier",
            "helpers",
            "executed_peer_sources",
            "python_runtime",
            "toolchain",
            "kernel_elf",
            "qemu",
            "bios",
            "openssh",
            "execution_custody",
            "host_key_evidence",
            "transcript",
            "summary",
        },
        "QEMU environment",
    )
    require(
        raw == canonical_json(environment), "QEMU environment is not canonical JSON"
    )
    fixed = {
        "schema": "vibeos.c84.qemu-aot-decision.environment",
        "version": 1,
        "suite_id": SUITE,
        "platform": PLATFORM,
        "platform_class": PLATFORM_CLASS,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "source_commit": transcript.meta["source_commit"],
        "challenge": transcript.meta["challenge"],
        "run_id": transcript.meta["run_id"],
    }
    for key, expected in fixed.items():
        exact_literal(environment[key], expected, f"environment.{key}")
    mode = exact_text(environment["mode"], "environment.mode")
    exact_literal(
        mode,
        FORMAL_CAPTURE_MODE if publication else SMOKE_CAPTURE_MODE,
        "environment.mode",
    )
    exact_literal(mode, transcript.meta["capture_mode"], "environment/META mode")
    exact_literal(
        transcript.meta["decision_eligible"],
        publication,
        "META publication eligibility",
    )
    live_repository = (
        validate_live_repository(transcript.meta["source_commit"])
        if publication and verify_live
        else None
    )
    started = parse_utc(environment["started_at_utc"], "environment.started_at_utc")
    ended = parse_utc(environment["ended_at_utc"], "environment.ended_at_utc")
    require(ended >= started, "environment capture ended before it started")
    repository = exact_keys(
        environment["repository"], {"before", "after"}, "environment.repository"
    )
    repository_before_record = validate_repository(
        repository["before"],
        transcript.meta["source_commit"],
        "repository.before",
        require_clean=publication,
    )
    if live_repository is not None:
        exact_literal(
            repository["before"], live_repository, "live repository.before closure"
        )
        exact_literal(
            repository["after"], live_repository, "live repository.after closure"
        )
    validate_source_materialization(
        environment["source_materialization"],
        transcript.meta["source_commit"],
        publication=publication,
        verify_live=verify_live,
        materialized_source=materialized_source,
    )
    repository_after_record = validate_repository(
        repository["after"],
        transcript.meta["source_commit"],
        "repository.after",
        require_clean=publication,
    )
    exact_literal(
        repository_after_record["commit_timestamp"],
        repository_before_record["commit_timestamp"],
        "repository commit timestamp closure",
    )
    exact_literal(
        environment["contract"],
        {
            "fresh_qemu_processes": 1,
            "warmups": WARMUPS,
            "retained": RETAINED,
            "timebase_hz": TIMEBASE_HZ,
            "budget_ticks": BUDGET_TICKS,
        },
        "environment.contract",
    )
    runner = path_identity(
        environment["runner"], "scripts/qemu-c84-aot-decision.py", "environment.runner"
    )
    verifier = path_identity(
        environment["verifier"],
        "scripts/verify-c84-qemu-aot-decision.py",
        "environment.verifier",
    )
    if verify_live:
        verify_local_identity(runner, ROOT / runner["path"], "environment.runner")
        verify_local_identity(verifier, SCRIPT_PATH, "environment.verifier")
    helpers = validate_helpers(environment["helpers"], verify_live=verify_live)
    executed_peer_sources = validate_executed_peer_sources(
        environment["executed_peer_sources"], helpers
    )
    python_runtime = validate_python_runtime(
        environment["python_runtime"], verify_live=verify_live
    )
    validate_toolchain(
        environment["toolchain"],
        transcript.meta["source_commit"],
        transcript.meta["challenge"],
        mode,
        repository_before_record["commit_timestamp"],
        verify_live=verify_live,
        build_source_root=build_source_root,
        private_cargo_home=private_cargo_home,
        private_crate_sources=private_crate_sources,
        private_crate_archives=private_crate_archives,
        cargo_target_path=cargo_target,
        toolchain_root_path=toolchain_root,
        rust_src_path=rust_src,
        linker_bin=linker_bin,
    )
    kernel = exact_keys(
        environment["kernel_elf"], {"path", "sha256", "bytes"}, "environment.kernel_elf"
    )
    exact_literal(
        kernel["path"],
        "<private-target>/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt",
        "environment.kernel_elf.path",
    )
    kernel_identity = identity(
        {"sha256": kernel["sha256"], "bytes": kernel["bytes"]},
        "environment.kernel_elf",
    )
    if verify_live:
        require(kernel_bin is not None, "environment.kernel_elf requires --kernel-bin")
        require(kernel_bin.is_absolute(), "--kernel-bin must be absolute")
        verify_local_identity(kernel, kernel_bin, "environment.kernel_elf")
    qemu = exact_keys(
        environment["qemu"],
        {
            "path",
            "version",
            "cwd",
            "actual_argv",
            "normalized_argv",
            "sha256",
            "bytes",
            "environment",
            "runtime_closures",
        },
        "environment.qemu",
    )
    qemu_version = exact_text(qemu["version"], "environment.qemu.version")
    exact_literal(qemu["cwd"], QEMU_PROCESS_CWD, "environment.qemu.cwd")
    exact_literal(
        qemu_version.splitlines()[0], PINNED_QEMU_VERSION, "frozen QEMU version"
    )
    independently_normalized_argv = normalize_actual_qemu_argv(
        qemu["actual_argv"],
        execution_qemu_bin=execution_qemu_bin,
        execution_bios_bin=execution_bios_bin,
        execution_kernel_bin=execution_kernel_bin,
        verify_live=verify_live,
    )
    exact_literal(
        qemu["normalized_argv"],
        independently_normalized_argv,
        "environment.qemu.normalized_argv",
    )
    exact_literal(
        qemu["environment"],
        EXPECTED_QEMU_ENVIRONMENT,
        "environment.qemu.environment",
    )
    qemu_identity = identity(
        {"sha256": qemu["sha256"], "bytes": qemu["bytes"]}, "environment.qemu"
    )
    exact_literal(
        qemu_identity,
        {"sha256": PINNED_QEMU_SHA256, "bytes": PINNED_QEMU_BYTES},
        "frozen QEMU binary identity",
    )
    validate_live_binary(
        qemu,
        qemu_bin,
        "environment.qemu",
        verify_live=verify_live,
        require_executable=True,
    )
    validate_qemu_runtime_closures(
        qemu["runtime_closures"],
        qemu_bin=qemu_bin,
        execution_qemu_bin=execution_qemu_bin,
        actual_argv=qemu["actual_argv"],
        verify_live=verify_live,
    )
    bios = exact_keys(
        environment["bios"],
        {"path", "name", "sha256", "bytes"},
        "environment.bios",
    )
    exact_literal(
        bios["name"], "opensbi-riscv64-generic-fw_dynamic.bin", "environment.bios.name"
    )
    bios_identity = identity(
        {"sha256": bios["sha256"], "bytes": bios["bytes"]}, "environment.bios"
    )
    exact_literal(
        bios_identity,
        {"sha256": PINNED_BIOS_SHA256, "bytes": PINNED_BIOS_BYTES},
        "frozen OpenSBI identity",
    )
    validate_live_binary(
        bios,
        bios_bin,
        "environment.bios",
        verify_live=verify_live,
    )
    openssh = exact_keys(
        environment["openssh"],
        {"path", "version", "sha256", "bytes"},
        "environment.openssh",
    )
    openssh_version = exact_text(openssh["version"], "environment.openssh.version")
    exact_literal(openssh_version, PINNED_OPENSSH_VERSION, "frozen OpenSSH version")
    exact_literal(openssh["path"], str(DARWIN_SYSTEM_OPENSSH), "frozen OpenSSH path")
    openssh_identity = identity(
        {"sha256": openssh["sha256"], "bytes": openssh["bytes"]}, "environment.openssh"
    )
    exact_literal(
        openssh_identity,
        {"sha256": PINNED_OPENSSH_SHA256, "bytes": PINNED_OPENSSH_BYTES},
        "frozen OpenSSH binary identity",
    )
    validate_execution_custody(
        environment["execution_custody"],
        source_identities={
            "qemu": qemu_identity,
            "bios": bios_identity,
            "kernel_elf": kernel_identity,
        },
        openssh_identity=openssh_identity,
        openssh_version=openssh_version,
        execution_bins={
            "qemu": execution_qemu_bin,
            "bios": execution_bios_bin,
            "kernel_elf": execution_kernel_bin,
        },
        openssh_bin=openssh_bin,
        verify_live=verify_live,
    )
    host_key = validate_host_key_evidence(environment["host_key_evidence"])
    exact_literal(
        environment["transcript"],
        identity_for(transcript.raw),
        "environment.transcript",
    )
    exact_literal(
        environment["summary"], identity_for(summary_raw), "environment.summary"
    )
    # Bind the complete environment bytes so all recorded versions, immutable
    # file identities, and normalized argv are decision inputs. Private paths
    # are custody provenance. /usr/bin/ssh is a pinned Darwin
    # host-custody invariant; neither kind is part of the guest platform ID.
    return {
        "value": environment,
        "identity": identity_for(raw),
        "helpers": helpers,
        "executed_peer_sources": executed_peer_sources,
        "python_runtime": python_runtime,
        "host_key_evidence": host_key,
    }


def render_decision(
    *,
    contracts: Contracts,
    transcript: VerifiedTranscript,
    summary: dict[str, Any],
    summary_raw: bytes,
    environment: dict[str, Any],
    environment_raw: bytes,
) -> dict[str, Any]:
    decision = summary["decision"]
    require(
        decision["aot_authorized"] is False
        and decision["native_code_accepted"] is False,
        "summary cannot authorize AOT or native code",
    )
    return {
        "schema": "vibeos.c84.qemu-aot-decision.evidence",
        "version": 1,
        "suite_id": SUITE,
        "mode": environment["mode"],
        "scope": TRANSCRIPT_SCOPE,
        "platform": PLATFORM,
        "platform_class": PLATFORM_CLASS,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "source_commit": transcript.meta["source_commit"],
        "challenge": transcript.meta["challenge"],
        "run_id": transcript.meta["run_id"],
        "contract": {
            "manifest": {
                "path": "benchmarks/wasm-aot-decision/workloads-qemu-v1.json",
                "sha256": contracts.manifest_sha256,
                "bytes": len(contracts.manifest_raw),
            },
            "transcript_schema": {
                "path": "benchmarks/wasm-aot-decision/schema-qemu-v1.json",
                "sha256": contracts.schema_sha256,
                "bytes": len(contracts.schema_raw),
            },
            "evidence_schema": {
                "path": "benchmarks/wasm-aot-decision/evidence-schema-qemu-v1.json",
                "sha256": contracts.evidence_schema_sha256,
                "bytes": len(contracts.evidence_schema_raw),
            },
        },
        "evidence": {
            "transcript": identity_for(transcript.raw),
            "summary": identity_for(summary_raw),
            "environment": identity_for(environment_raw),
        },
        "environment_identity": {
            "source_materialization": environment["source_materialization"],
            "qemu": {
                "version": environment["qemu"]["version"],
                "cwd": environment["qemu"]["cwd"],
                "sha256": environment["qemu"]["sha256"],
                "bytes": environment["qemu"]["bytes"],
                "actual_argv": environment["qemu"]["actual_argv"],
                "normalized_argv": environment["qemu"]["normalized_argv"],
                "runtime_closures": environment["qemu"]["runtime_closures"],
            },
            "bios": {
                "name": environment["bios"]["name"],
                "sha256": environment["bios"]["sha256"],
                "bytes": environment["bios"]["bytes"],
            },
            "openssh": {
                "version": environment["openssh"]["version"],
                "sha256": environment["openssh"]["sha256"],
                "bytes": environment["openssh"]["bytes"],
            },
            "kernel_elf": {
                "sha256": environment["kernel_elf"]["sha256"],
                "bytes": environment["kernel_elf"]["bytes"],
            },
            "toolchain": {
                "channel": environment["toolchain"]["channel"],
                "pinned_rustc_commit": environment["toolchain"]["pinned_rustc_commit"],
                "rustc_sha256": environment["toolchain"]["rustc"]["sha256"],
                "linker_sha256": environment["toolchain"]["linker"]["sha256"],
                "build_input_closure": environment["toolchain"][
                    "build_input_closure"
                ],
            },
            "helpers": environment["helpers"],
            "executed_peer_sources": environment["executed_peer_sources"],
            "python_runtime": environment["python_runtime"],
            "host_key_evidence": environment["host_key_evidence"],
            "execution_custody": environment["execution_custody"],
        },
        "population": {
            "fresh_qemu_processes": 1,
            "warmups": WARMUPS,
            "retained": RETAINED,
            "p50_sorted_index": P50_SORTED_INDEX,
            "p95_sorted_index": P95_SORTED_INDEX,
            "physical_inputs": 0,
            "audit_inputs": 0,
        },
        "statistics": summary["statistics"],
        "decision": decision,
        "next_node": (
            "none-smoke-only"
            if environment["mode"] != FORMAL_CAPTURE_MODE
            else (
                "C8.5-design-review-only"
                if decision["candidate_for_c85_design_review"]
                else "C8.8-skip-or-defer-C8.5-C8.7"
            )
        ),
        "limitations": [
            "This is a fixed-QEMU decision and makes no physical-hardware or cold-boot claim.",
            "Neither outcome authorizes AOT, JIT, RWX, external native bytes, or policy bypass.",
            "An eligible outcome opens C8.5 design review only; it does not accept native code.",
        ],
    }


def synthetic_records(
    contracts: Contracts, capture_mode: str = FORMAL_CAPTURE_MODE
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    require(capture_mode in CAPTURE_MODES, "synthetic capture mode differs")
    physical_meta, samples, ending = BASE.synthetic_transcript_records()
    meta = copy.deepcopy(physical_meta)
    meta.pop("required_cold_boots")
    meta.update(
        {
            "suite_id": SUITE,
            "manifest_sha256": contracts.manifest_sha256,
            "transcript_schema_sha256": contracts.schema_sha256,
            "platform": PLATFORM,
            "platform_class": PLATFORM_CLASS,
            "physical_provenance": PHYSICAL_PROVENANCE,
            "capture_mode": capture_mode,
            "decision_eligible": capture_mode == FORMAL_CAPTURE_MODE,
            "timebase_hz": TIMEBASE_HZ,
            "transcript_scope": TRANSCRIPT_SCOPE,
            "required_qemu_boots": 1,
            "budget_ticks": BUDGET_TICKS,
        }
    )
    meta["run_id"] = expected_run_id(meta, contracts)
    samples = copy.deepcopy(samples)
    for sample in samples:
        sample["run_id"] = meta["run_id"]
    ending = copy.deepcopy(ending)
    ending.update(
        {
            "run_id": meta["run_id"],
            "accumulator": transcript_accumulator(samples),
        }
    )
    return meta, samples, ending


def replace_durations(sample: dict[str, Any], durations: list[int]) -> None:
    require(len(durations) == len(PHASE_IDS), "synthetic duration vector differs")
    sample["phase_ticks"] = dict(zip(PHASE_IDS, durations, strict=True))
    intervals: list[dict[str, Any]] = []
    start = 0
    for sequence, (phase, duration) in enumerate(
        zip(PHASE_IDS, durations, strict=True)
    ):
        end = start + duration
        intervals.append(
            {
                "sequence": sequence,
                "phase": phase,
                "start_offset_ticks": start,
                "end_offset_ticks": end,
            }
        )
        start = end
    sample["total_ticks"] = start
    sample["interval_count"] = len(intervals)
    sample["intervals"] = intervals


_SYNTHETIC_LINKER_RUNTIME: dict[str, Any] | None = None


def synthetic_linker_runtime() -> dict[str, Any]:
    global _SYNTHETIC_LINKER_RUNTIME
    if _SYNTHETIC_LINKER_RUNTIME is None:
        _SYNTHETIC_LINKER_RUNTIME = linker_runtime_closure(PINNED_LLD_INVOCATION)
        exact_literal(
            _SYNTHETIC_LINKER_RUNTIME["sha256"],
            PINNED_LLD_RUNTIME_SHA256,
            "synthetic linker runtime pin",
        )
    return copy.deepcopy(_SYNTHETIC_LINKER_RUNTIME)


_SYNTHETIC_QEMU_RUNTIME: dict[str, Any] | None = None


def synthetic_qemu_runtime_closure(path: str) -> dict[str, Any]:
    global _SYNTHETIC_QEMU_RUNTIME
    if _SYNTHETIC_QEMU_RUNTIME is None:
        _SYNTHETIC_QEMU_RUNTIME = qemu_runtime_closure(
            pathlib.Path("/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-riscv64")
        )
        exact_literal(
            _SYNTHETIC_QEMU_RUNTIME["graph_sha256"],
            PINNED_QEMU_RUNTIME_GRAPH_SHA256,
            "synthetic QEMU runtime graph pin",
        )
    record = copy.deepcopy(_SYNTHETIC_QEMU_RUNTIME)
    original_root = record["resolved_path"]
    record["invocation_path"] = path
    record["resolved_path"] = path
    record["symlinks"] = []
    for node in record["nodes"]:
        if node["path"] == original_root:
            node["path"] = path
    record["nodes"].sort(key=lambda node: node["path"])
    core = {key: value for key, value in record.items() if key != "sha256"}
    record["sha256"] = hashlib.sha256(canonical_compact_json(core)).hexdigest()
    return record


def synthetic_toolchain(
    source: str, challenge: str, capture_mode: str
) -> dict[str, Any]:
    channel, commit = parse_toolchain_pin()
    fake = {"sha256": "1" * 64, "bytes": 1}
    rustup = {"path": "/synthetic/bin/rustup", **fake}
    synthetic_toolchain_root = pathlib.Path(EXPECTED_PLATFORM["rust_toolchain_root"])
    cargo = {"path": str(synthetic_toolchain_root / "bin/cargo"), **fake}
    rustc = {"path": str(synthetic_toolchain_root / "bin/rustc"), **fake}
    rustdoc = {"path": str(synthetic_toolchain_root / "bin/rustdoc"), **fake}
    linker_runtime = synthetic_linker_runtime()
    path_entries = [str(PINNED_LLD_INVOCATION.parent), "/usr/bin", "/bin"]
    values = {
        "__CARGO_TEST_LAST_USE_NOW": "1234567890",
        "CARGO_HOME": "<private-cargo-home>",
        "CARGO_TARGET_DIR": "<private-target>",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "HOME": "<private-build-home>",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(path_entries),
        "RUSTC": rustc["path"],
        "RUSTDOC": rustdoc["path"],
        "SOURCE_DATE_EPOCH": "1700000000",
        "TMPDIR": "<private-build-tmp>",
        "TZ": "UTC",
        "VIBEOS_C84_CHALLENGE": challenge,
        "VIBEOS_C84_SOURCE_COMMIT": source,
    }
    generated_config = {
        "path": "<private-cargo-home>/config.toml",
        **fake,
    }
    private_home = {
        "policy": "exact-private-cargo-home-config-only-v1",
        "root_mode": "0700",
        "entries": [{**generated_config, "mode": "0400", "links": 1}],
    }
    return {
        "channel": channel,
        "pinned_rustc_commit": commit,
        "rustc_vv": f"rustc synthetic\ncommit-hash: {commit}\n",
        "cargo_version": "cargo 1.0.0 (synthetic)",
        "rustup": rustup,
        "cargo": cargo,
        "rustc": rustc,
        "rustdoc": rustdoc,
        "linker": {
            "invocation_path": linker_runtime["invocation_path"],
            "resolved_path": linker_runtime["resolved_path"],
            **fake,
        },
        "cargo_command": [
            cargo["path"],
            "build",
            "--manifest-path",
            (
                "<materialized-source>/firmware/qemu-virt/Cargo.toml"
                if capture_mode == FORMAL_CAPTURE_MODE
                else "<dirty-worktree>/firmware/qemu-virt/Cargo.toml"
            ),
            "--release",
            "--locked",
            "--offline",
            "--no-default-features",
            "--features",
            (
                "wasm-c84-qemu-aot-decision"
                if capture_mode == FORMAL_CAPTURE_MODE
                else "wasm-c84-qemu-aot-decision-smoke"
            ),
        ],
        "build_environment_policy": {
            "ambient_variables": "denied-by-default",
            "cargo_home": "private-generated-config-directory-source-only",
            "cargo_net_offline": True,
            "path_entries": path_entries,
            "allowed_names": sorted(values),
            "normalized_values": values,
        },
        "build_input_closure": {
            "policy": "c84-private-build-input-closure-v1",
            "normalized_paths": {
                "policy": "canonical-realpath-no-leaf-symlink-v1",
                "source_root": "/synthetic/source",
                "manifest": "/synthetic/source/firmware/qemu-virt/Cargo.toml",
                "cargo_home": "/synthetic/cargo-home",
                "private_crate_sources": "/synthetic/vendor",
                "private_crate_archives": "/synthetic/archives",
                "cargo_target": "/synthetic/target",
                "toolchain_root": str(synthetic_toolchain_root),
                "rust_src": str(
                    synthetic_toolchain_root / "lib/rustlib/src/rust/library"
                ),
            },
            "cargo_locks": {
                "policy": "project-plus-pinned-rust-src-lock-union-v1",
                "project": {
                    "path": "Cargo.lock",
                    "sha256": PINNED_CARGO_LOCK_SHA256,
                    "bytes": PINNED_CARGO_LOCK_BYTES,
                    "registry_source": CRATES_IO_SOURCE,
                    "packages": PINNED_CARGO_PACKAGES,
                    "package_set_sha256": PINNED_CARGO_PACKAGE_SET_SHA256,
                },
                "rust_src": {
                    "path": "lib/rustlib/src/rust/library/Cargo.lock",
                    "sha256": PINNED_RUST_SRC_CARGO_LOCK["sha256"],
                    "bytes": PINNED_RUST_SRC_CARGO_LOCK["bytes"],
                    "registry_source": CRATES_IO_SOURCE,
                    "packages": PINNED_RUST_SRC_CARGO_PACKAGES,
                    "package_set_sha256": PINNED_RUST_SRC_CARGO_PACKAGE_SET_SHA256,
                },
                "union": {
                    "packages": PINNED_CARGO_UNION_PACKAGES,
                    "exact_overlap": PINNED_CARGO_UNION_EXACT_OVERLAP,
                    "project_only": PINNED_CARGO_UNION_PROJECT_ONLY,
                    "rust_src_only": PINNED_CARGO_UNION_RUST_SRC_ONLY,
                    "package_set_sha256": PINNED_CARGO_UNION_PACKAGE_SET_SHA256,
                },
            },
            "private_crate_sources": {
                "method": "verified-project-lock-archives-plus-rust-src-vendor-union-v1",
                "archive_source": "fixed-launcher-cargo-home-registry-cache",
                "rust_src_vendor_source": "pinned-rust-src-library-vendor",
                "archive_count": 189,
                "rust_src_vendor_count": 24,
                "archive_bytes": 23_706_909,
                "source_files": 11_391,
                "source_bytes": 137_564_030,
                "mode_policy": "directories-0500-files-0400-preserve-owner-execute-0500-v1",
                "checksum_file_policy": "canonical-cargo-directory-source-json-v1",
                "rust_src_materialization_before": PINNED_RUST_SRC_TREE,
                "rust_src_materialization_after": PINNED_RUST_SRC_TREE,
                "before": PINNED_PRIVATE_CRATE_TREE,
                "after": PINNED_PRIVATE_CRATE_TREE,
            },
            "private_crate_archives": {
                "root": "/synthetic/archives",
                "before": PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
                "after": PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
            },
            "cargo_configuration": {
                "discovery_policy": "filesystem-root-plus-private-cargo-home-v1",
                "root_before": {
                    "cwd": "/",
                    "candidates": ["/.cargo/config", "/.cargo/config.toml"],
                    "all_absent": True,
                },
                "root_after": {
                    "cwd": "/",
                    "candidates": ["/.cargo/config", "/.cargo/config.toml"],
                    "all_absent": True,
                },
                "materialized_firmware": {
                    "path": "firmware/.cargo/config.toml",
                    **fake,
                },
                "generated": generated_config,
                "private_home_before": private_home,
                "private_home_after": private_home,
                "cargo_subprocess_umask": "0077",
                "transient_outputs": {
                    "policy": "fresh-pinned-cargo-runtime-outputs-validated-recorded-removed-v1",
                    "precondition": "private-home-config-only-before-cargo",
                    "entries": [
                        {
                            "path": "<private-cargo-home>/.global-cache",
                            "kind": "sqlite3-global-cache",
                            "mode": "0600",
                            "links": 1,
                            "sha256": "66d946720de0afd44c2d5748698b700ce812830bd8a3dedaa589831610948d9d",
                            "bytes": 57_344,
                            "header": {
                                "magic": "SQLite format 3 NUL",
                                "page_size": 4096,
                                "write_version": 1,
                                "read_version": 1,
                                "database_pages": 14,
                                "schema_format": 4,
                                "encoding": 1,
                                "user_version": 7,
                                "sqlite_version": 3_053_002,
                            },
                        },
                        {
                            "path": "<private-cargo-home>/.package-cache",
                            "kind": "empty-advisory-lock",
                            "mode": "0600",
                            "links": 1,
                            "sha256": hashlib.sha256(b"").hexdigest(),
                            "bytes": 0,
                        },
                        {
                            "path": "<private-cargo-home>/.package-cache-mutate",
                            "kind": "empty-advisory-lock",
                            "mode": "0600",
                            "links": 1,
                            "sha256": hashlib.sha256(b"").hexdigest(),
                            "bytes": 0,
                        },
                        {
                            "path": "<private-cargo-home>/registry",
                            "kind": "directory",
                            "mode": "0700",
                            "entries": [
                                {
                                    "path": "<private-cargo-home>/registry/CACHEDIR.TAG",
                                    "kind": "cargo-cache-directory-tag",
                                    "mode": "0600",
                                    "links": 1,
                                    "sha256": "6d9d1d216e0f83abc5e5662ca62c92b4f23009466b54fa27321a69acdb778bb2",
                                    "bytes": 177,
                                }
                            ],
                        },
                    ],
                },
            },
            "toolchain_tree": {
                "root": str(synthetic_toolchain_root),
                "before": PINNED_TOOLCHAIN_TREE,
                "after": PINNED_TOOLCHAIN_TREE,
            },
            "rust_src": {
                "root": str(
                    synthetic_toolchain_root / "lib/rustlib/src/rust/library"
                ),
                "relative_path": "lib/rustlib/src/rust/library",
                "before": PINNED_RUST_SRC_TREE,
                "after": PINNED_RUST_SRC_TREE,
                "cargo_toml": PINNED_RUST_SRC_CARGO_TOML,
                "cargo_lock": PINNED_RUST_SRC_CARGO_LOCK,
            },
            "linker_runtime": {
                "before": linker_runtime,
                "after": copy.deepcopy(linker_runtime),
            },
        },
    }


def synthetic_environment(
    transcript: VerifiedTranscript, summary_raw: bytes
) -> tuple[dict[str, Any], bytes]:
    source = transcript.meta["source_commit"]
    challenge = transcript.meta["challenge"]
    capture_mode = transcript.meta["capture_mode"]
    formal = capture_mode == FORMAL_CAPTURE_MODE
    repository = {
        "head": source,
        "commit_timestamp": "1700000000",
        "clean": formal,
        "branch": FORMAL_BRANCH if formal else None,
        "local_codex_wasm_head": source if formal else None,
        "local_tracking_codex_wasm_head": source if formal else None,
        "configured_fetch_url": FORMAL_CONFIGURED_ORIGIN,
        "configured_push_url": FORMAL_CONFIGURED_ORIGIN,
        "remote_query_url": FORMAL_REMOTE_URL,
        "remote_ref": FORMAL_REMOTE_REF,
        "advertised_remote_head": source if formal else None,
        "status_command": GIT_STATUS_COMMAND,
        "diff_command": GIT_DIFF_COMMAND,
        "index_flags_command": GIT_INDEX_FLAGS_COMMAND,
        "fsmonitor_flags_command": GIT_FSMONITOR_FLAGS_COMMAND,
        "remote_query_command": GIT_REMOTE_QUERY_COMMAND,
        "status_porcelain_v1_z_sha256": EMPTY_SHA256 if formal else "2" * 64,
        "tracked_diff_head_binary_sha256": EMPTY_SHA256,
        "index_flags_sha256": "3" * 64,
        "fsmonitor_flags_sha256": "4" * 64,
        "index_entries": 931,
        "index_flags_all_h": True,
        "fsmonitor_flags_all_h": True,
        "remote_response_sha256": (
            hashlib.sha256(
                f"{source}\t{FORMAL_REMOTE_REF}\n".encode("ascii")
            ).hexdigest()
            if formal
            else EMPTY_SHA256
        ),
        "local_configs": [
            {
                "repository": repository_name,
                "path": GIT_LOCAL_CONFIG_PATHS[repository_name],
                "policy": GIT_LOCAL_CONFIG_POLICY,
                "sha256": str(index + 5) * 64,
                "bytes": index + 1,
                "entries": index + 1,
                "parsed_sha256": str(index + 6) * 64,
            }
            for index, repository_name in enumerate(
                (".", *sorted(EXPECTED_SUBMODULES))
            )
        ],
    }
    fake = {"sha256": "1" * 64, "bytes": 1}
    source_materialization = {
        "method": (
            "exact-commit-raw-blob-export-v1"
            if formal
            else "dirty-worktree-smoke-not-evidence"
        ),
        "decision_eligible": formal,
        "superproject": {
            "commit": source,
            "tree": "3" * 40,
            "inventory_sha256": "3" * 64,
            "entries": 779,
        },
        "submodules": [
            {
                "path": path,
                "commit": str(index + 4) * 40,
                "tree": str(index + 6) * 40,
                "inventory_sha256": str(index + 5) * 64,
                "entries": 76,
            }
            for index, path in enumerate(sorted(EXPECTED_SUBMODULES))
        ],
        "ignored_worktree_inputs": (
            "excluded-not-copied" if formal else "not-excluded-smoke-only"
        ),
        "cargo_target": "fresh-private",
        "materialized_files": 929,
    }
    qemu_identity = {"sha256": PINNED_QEMU_SHA256, "bytes": PINNED_QEMU_BYTES}
    bios_identity = {"sha256": PINNED_BIOS_SHA256, "bytes": PINNED_BIOS_BYTES}
    kernel_identity = dict(fake)
    openssh_identity = {
        "sha256": PINNED_OPENSSH_SHA256,
        "bytes": PINNED_OPENSSH_BYTES,
    }
    execution_custody = {
        "scheme": CUSTODY_SCHEME,
        "private_directory_mode": f"{CUSTODY_DIRECTORY_MODE:04o}",
        **{
            role: {
                "name": name,
                "mode": f"{mode:04o}",
                **{
                    "qemu": qemu_identity,
                    "bios": bios_identity,
                    "kernel_elf": kernel_identity,
                }[role],
            }
            for role, (name, mode) in CUSTODY_ROLES.items()
        },
        "openssh": expected_darwin_system_openssh_record(),
    }
    source_qemu_path = "/synthetic/bin/qemu-system-riscv64"
    custody_qemu_path = "/synthetic/custody/qemu-system-riscv64"
    custody_bios_path = "/synthetic/custody/opensbi-riscv64-generic-fw_dynamic.bin"
    custody_kernel_path = "/synthetic/custody/vibeos-qemu-virt"
    qemu_data_path = "/synthetic/qemu-environment/data"
    actual_qemu_argv = [
        custody_qemu_path
        if item == "qemu-system-riscv64"
        else custody_bios_path
        if item == "<opensbi>"
        else custody_kernel_path
        if item == "<kernel>"
        else qemu_data_path
        if item == "<qemu-data>"
        else item.replace("<host-port>", "12345")
        for item in NORMALIZED_QEMU_ARGV
    ]
    source_runtime = synthetic_qemu_runtime_closure(source_qemu_path)
    custody_runtime = synthetic_qemu_runtime_closure(custody_qemu_path)
    runtime_closures = {
        "policy": "source-and-execution-custody-pre-post-final-v1",
        "host_exclusivity_limit": QEMU_RUNTIME_HOST_LIMIT,
        "module_search": {
            "policy": "no-plugin-argv-and-absent-qemu-module-directories-v1",
            "qemu_prefix": str(PINNED_QEMU_PREFIX),
            "environment_override": "QEMU_MODULE_DIR",
            "environment_override_absent": True,
            "plugin_argv_absent": True,
            "user_config_disabled": True,
            "data_directory": {
                "path": qemu_data_path,
                "mode": QEMU_DATA_DIRECTORY_MODE,
                "empty": True,
            },
            "candidate_directories": [
                {"path": str(path), "absent": True}
                for path in (
                    PINNED_QEMU_PREFIX / "lib/qemu",
                    pathlib.Path("/opt/homebrew/lib/qemu"),
                    PINNED_QEMU_PREFIX / "qemu-bundle",
                    PINNED_QEMU_PREFIX / "libexec/qemu",
                )
            ],
            "scope_limit": (
                "closes QEMU module/plugin search; generic library-internal dlopen is not "
                "claimed beyond the recursive Mach-O load-command graph"
            ),
        },
        "source": {
            phase: copy.deepcopy(source_runtime)
            for phase in ("before", "after", "final")
        },
        "execution_custody": {
            phase: copy.deepcopy(custody_runtime)
            for phase in ("before", "after", "final")
        },
    }
    value = {
        "schema": "vibeos.c84.qemu-aot-decision.environment",
        "version": 1,
        "suite_id": SUITE,
        "mode": capture_mode,
        "platform": PLATFORM,
        "platform_class": PLATFORM_CLASS,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "source_commit": source,
        "challenge": challenge,
        "run_id": transcript.meta["run_id"],
        "started_at_utc": "2026-08-28T00:00:00.000Z",
        "ended_at_utc": "2026-08-28T00:01:00.000Z",
        "repository": {
            "before": copy.deepcopy(repository),
            "after": copy.deepcopy(repository),
        },
        "source_materialization": source_materialization,
        "contract": {
            "fresh_qemu_processes": 1,
            "warmups": WARMUPS,
            "retained": RETAINED,
            "timebase_hz": TIMEBASE_HZ,
            "budget_ticks": BUDGET_TICKS,
        },
        "runner": {"path": "scripts/qemu-c84-aot-decision.py", **fake},
        "verifier": {"path": "scripts/verify-c84-qemu-aot-decision.py", **fake},
        "helpers": {
            name: {"path": expected_path, **fake}
            for name, expected_path in HELPER_PATHS.items()
        },
        "executed_peer_sources": {
            HELPER_PATHS[name]: dict(fake) for name in EXECUTED_SOURCE_EVIDENCE_KEYS
        },
        "python_runtime": expected_python_runtime_environment(),
        "toolchain": synthetic_toolchain(source, challenge, capture_mode),
        "kernel_elf": {
            "path": "<private-target>/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt",
            **kernel_identity,
        },
        "qemu": {
            "path": source_qemu_path,
            "version": PINNED_QEMU_VERSION,
            "cwd": QEMU_PROCESS_CWD,
            "actual_argv": actual_qemu_argv,
            "normalized_argv": NORMALIZED_QEMU_ARGV,
            "environment": copy.deepcopy(EXPECTED_QEMU_ENVIRONMENT),
            "runtime_closures": runtime_closures,
            **qemu_identity,
        },
        "bios": {
            "path": "/synthetic/share/opensbi-riscv64-generic-fw_dynamic.bin",
            "name": "opensbi-riscv64-generic-fw_dynamic.bin",
            **bios_identity,
        },
        "openssh": {
            "path": str(DARWIN_SYSTEM_OPENSSH),
            "version": PINNED_OPENSSH_VERSION,
            **openssh_identity,
        },
        "execution_custody": execution_custody,
        "host_key_evidence": {
            **identity_for(EXPECTED_HOST_KEY_RAW),
            "public_key": EXPECTED_HOST_PUBLIC_KEY,
            "fingerprint_sha256": EXPECTED_HOST_FINGERPRINT,
        },
        "transcript": identity_for(transcript.raw),
        "summary": identity_for(summary_raw),
    }
    return value, canonical_json(value)


def reject_mutation(name: str, operation: Callable[[], None]) -> None:
    try:
        operation()
    except (VerificationError, OSError, UnicodeDecodeError):
        return
    raise VerificationError(f"selftest accepted mutation {name}")


def selftest(contracts: Contracts) -> int:
    rejected = 0
    test_source = "1" * 40
    clock_sources = (
        read_regular(
            ROOT / "kernel/src/wasm_aot_profile_slot.rs",
            "selftest live-tick source",
            MAX_JSON_BYTES,
        ),
        read_regular(
            ROOT / "kernel/src/lib.rs",
            "selftest kernel root source",
            MAX_JSON_BYTES,
        ),
        read_regular(
            ROOT / "runtime/riscv/src/bare.rs",
            "selftest rdtime source",
            MAX_JSON_BYTES,
        ),
        read_regular(
            ROOT / "boards/qemu-virt/src/lib.rs",
            "selftest QEMU timebase source",
            MAX_JSON_BYTES,
        ),
    )
    validate_clock_source_bytes(*clock_sources)
    lexical_fixture = (
        b"fn visible_before() {}\n"
        b"// fn hidden_line() {}\n"
        b"/* outer /* fn hidden_nested_block() {} */ outer */\n"
        b'const NORMAL: &str = "fn hidden_normal() {}";\n'
        b'const BYTE: &[u8] = b"fn hidden_byte() {}";\n'
        b'const C_STRING: &CStr = c"fn hidden_c_string() {}";\n'
        b'const RAW: &str = r###"fn hidden_raw() {}"###;\n'
        b'const BYTE_RAW: &[u8] = br##"fn hidden_byte_raw() {}"##;\n'
        b'const C_RAW: &CStr = cr#"fn hidden_c_raw() {}"#;\n'
        b"const OPEN: char = '{';\n"
        b"const CLOSE: char = '}';\n"
        b"const BYTE_OPEN: u8 = b'{';\n"
        b"const UNICODE_CLOSE: char = '\\u{7d}';\n"
        b"fn visible_after() {}\n"
    )
    lexical_masked = rust_lexical_mask(lexical_fixture, "selftest Rust lexical fixture")
    require("hidden_" not in lexical_masked, "Rust lexical masker exposed a decoy")
    require(
        len(re.findall(r"\bfn\s+visible_(?:before|after)\s*\(", lexical_masked)) == 2,
        "Rust lexical masker hid live code",
    )
    clock_mutations = (
        (
            clock_sources[0].replace(
                b"crate::sbi::time()", b"crate::sbi::time() / 2", 1
            ),
            clock_sources[1],
            clock_sources[2],
            clock_sources[3],
        ),
        (
            clock_sources[0],
            clock_sources[1].replace(
                b"pub use vibeos_runtime_riscv as sbi;",
                b"pub use vibeos_core::arch as sbi;",
                1,
            ),
            clock_sources[2],
            clock_sources[3],
        ),
        (
            clock_sources[0],
            clock_sources[1],
            clock_sources[2].replace(b'asm!("rdtime {}"', b'asm!("rdcycle {}"', 1),
            clock_sources[3],
        ),
        (
            clock_sources[0],
            clock_sources[1],
            clock_sources[2],
            clock_sources[3].replace(b"10_000_000", b"25_000_000", 1),
        ),
        (
            clock_sources[0].replace(
                b"crate::sbi::time()", b"0 /* different clock */", 1
            )
            + b"\n/* outer /* nested */ fn live_tick() -> u64 { crate::sbi::time() } */\n",
            clock_sources[1],
            clock_sources[2],
            clock_sources[3],
        ),
        (
            clock_sources[0],
            clock_sources[1],
            clock_sources[2].replace(b'asm!("rdtime {}"', b'asm!("rdcycle {}"', 1)
            + b'\nconst CLOCK_DECOY: &str = "pub fn time() -> u64 { let t: u64; unsafe { asm!(\\"rdtime {}\\", out(reg) t) }; t }";\n',
            clock_sources[3],
        ),
        (
            clock_sources[0],
            clock_sources[1],
            clock_sources[2],
            clock_sources[3].replace(b"10_000_000", b"25_000_000", 1)
            + b'\nconst CLOCK_DECOY: &str = r###"pub const TIMEBASE_HZ: u64 = 10_000_000;"###;\n',
        ),
    )
    for index, candidate in enumerate(clock_mutations):
        reject_mutation(
            f"clock-source-{index}",
            lambda candidate=candidate: validate_clock_source_bytes(*candidate),
        )
        rejected += 1
    runner_source = read_regular(
        RUNNER_PATH, "selftest QEMU runner source", MAX_JSON_BYTES
    )
    validate_runner_qemu_environment_source_bytes(runner_source)

    def replace_unique(before: bytes, after: bytes, label: str) -> bytes:
        require(
            runner_source.count(before) == 1,
            f"selftest QEMU runner {label} mutation anchor differs",
        )
        return runner_source.replace(before, after, 1)

    runner_wiring_mutations = (
        replace_unique(
            b"            toolchain = BASE.build_kernel(\n"
            b"                source_commit,\n"
            b"                challenge,\n"
            b'                firmware=source_root / "firmware/qemu-virt",\n',
            b"            toolchain = BASE.build_kernel(\n"
            b"                source_commit,\n"
            b"                challenge,\n"
            b'                firmware=source_root / "firmware/qemu-virt",\n'
            b"                private_crate_archives=private_cargo_sources,\n",
            "base-build-archive-duplicate",
        ),
        replace_unique(
            b'    require(pathlib.Path(qemu).is_absolute(), "QEMU version path is not absolute")\n'
            b"    validate_qemu_environment(qemu_environment)\n",
            b'    require(pathlib.Path(qemu).is_absolute(), "QEMU version path is not absolute")\n',
            "probe-validation",
        ),
        replace_unique(
            b") -> tuple[bytes, str, dict[str, dict[str, object]]]:\n"
            b"    validate_qemu_environment(qemu_environment)\n"
            b'    require(type(qemu_argv) is tuple, "actual QEMU argv is not immutable")\n',
            b") -> tuple[bytes, str, dict[str, dict[str, object]]]:\n"
            b'    require(type(qemu_argv) is tuple, "actual QEMU argv is not immutable")\n',
            "live-validation",
        ),
        replace_unique(
            b'            [qemu, "-no-user-config", "--version"],\n'
            b'            cwd=pathlib.Path("/"),\n'
            b"            env=qemu_environment,\n",
            b'            [qemu, "-no-user-config", "--version"],\n'
            b'            cwd=pathlib.Path("/"),\n'
            b"            env=os.environ,\n",
            "probe-env",
        ),
        replace_unique(
            b"                qemu_argv,\n"
            b'                cwd=pathlib.Path("/"),\n'
            b"                env=qemu_environment,\n",
            b"                qemu_argv,\n"
            b'                cwd=pathlib.Path("/"),\n'
            b"                env=os.environ,\n",
            "live-env",
        ),
        replace_unique(
            b"                qemu_argv,\n"
            b'                cwd=pathlib.Path("/"),\n'
            b"                env=qemu_environment,\n",
            b"                qemu_argv,\n"
            b"                cwd=ROOT,\n"
            b"                env=qemu_environment,\n",
            "live-cwd",
        ),
        replace_unique(
            b'                    str(execution_paths["qemu"]),\n'
            b"                    qemu_environment=qemu_process_environment,\n",
            b'                    str(execution_paths["qemu"]),\n'
            b"                    qemu_environment=dict(qemu_process_environment),\n",
            "main-probe-env",
        ),
        replace_unique(
            b"                    capture_mode=capture_mode,\n"
            b"                    qemu_environment=qemu_process_environment,\n",
            b"                    capture_mode=capture_mode,\n"
            b"                    qemu_environment=dict(qemu_process_environment),\n",
            "main-live-env",
        ),
        replace_unique(
            b"                    qemu_environment=qemu_environment_record,\n"
            b"                    qemu_runtime_closures=qemu_runtime_closures,\n",
            b"                    qemu_environment=qemu_process_environment,\n"
            b"                    qemu_runtime_closures=qemu_runtime_closures,\n",
            "evidence-env",
        ),
        replace_unique(
            b"                        qemu_argv=actual_qemu_argv,\n"
            b"                        data_directory=qemu_data_directory,\n"
            b"                    )\n"
            b"                    == qemu_module_search,\n",
            b"                        qemu_argv=actual_qemu_argv,\n"
            b"                    )\n"
            b"                    == qemu_module_search,\n",
            "final-module-data-directory",
        ),
    )
    for index, candidate in enumerate(runner_wiring_mutations):
        reject_mutation(
            f"runner-qemu-environment-wiring-{index}",
            lambda candidate=candidate: validate_runner_qemu_environment_source_bytes(
                candidate
            ),
        )
        rejected += 1
    base_runner_source = read_regular(
        BASE_RUNNER_PATH, "selftest QEMU base runner source", MAX_JSON_BYTES
    )
    validate_base_build_stdin_source_bytes(base_runner_source)

    def replace_base_unique(before: bytes, after: bytes, label: str) -> bytes:
        require(
            base_runner_source.count(before) == 1,
            f"selftest QEMU base runner {label} mutation anchor differs",
        )
        return base_runner_source.replace(before, after, 1)

    base_stdin_mutations = (
        replace_base_unique(
            b"    private_crate_archives: pathlib.Path | None = None,\n",
            b"    omitted_private_crate_archives: pathlib.Path | None = None,\n",
            "archive-contract",
        ),
        replace_base_unique(
            b'                cwd="/",\n'
            b"                env=environment,\n"
            b"                stdin=subprocess.DEVNULL,\n",
            b'                cwd="/",\n'
            b"                env=environment,\n"
            b"                stdin=None,\n",
            "formal-cargo-stdin",
        ),
        replace_base_unique(
            b"                    cwd=selected_firmware,\n"
            b"                    env=environment,\n"
            b"                    stdin=subprocess.DEVNULL,\n",
            b"                    cwd=selected_firmware,\n"
            b"                    env=environment,\n"
            b"                    stdin=None,\n",
            "smoke-cargo-stdin",
        ),
        replace_base_unique(
            b"                umask=0o077,\n",
            b"                umask=0o022,\n",
            "formal-cargo-umask",
        ),
        replace_base_unique(
            b'                "__CARGO_TEST_LAST_USE_NOW": "1234567890",\n',
            b'                "__CARGO_TEST_LAST_USE_NOW": "1234567891",\n',
            "cargo-cache-clock",
        ),
        replace_base_unique(
            b"        b'auto-clean-frequency = \"never\"\\n\\n'\n",
            b"        b'auto-clean-frequency = \"1 day\"\\n\\n'\n",
            "cargo-cache-auto-clean",
        ),
        replace_base_unique(
            b"66d946720de0afd44c2d5748698b700ce812830bd8a3dedaa589831610948d9d",
            b"6" * 64,
            "cargo-global-cache-identity",
        ),
    )
    for index, candidate in enumerate(base_stdin_mutations):
        reject_mutation(
            f"base-cargo-stdin-{index}",
            lambda candidate=candidate: validate_base_build_stdin_source_bytes(
                candidate
            ),
        )
        rejected += 1
    verifier_source = read_regular(
        pathlib.Path(__file__).resolve(),
        "selftest QEMU verifier checksum source",
        MAX_JSON_BYTES,
    )
    validate_private_checksum_encoder_source_bytes(verifier_source)

    def replace_verifier_unique(before: bytes, after: bytes, label: str) -> bytes:
        require(
            verifier_source.count(before) == 1,
            f"selftest QEMU verifier {label} mutation anchor differs",
        )
        return verifier_source.replace(before, after, 1)

    checksum_encoder_mutations = (
        replace_verifier_unique(
            b"            installed_checksum = canonical_compact_json(\n",
            b"            installed_checksum = canonical_json(\n",
            "rust-src-vendor-pretty-checksum",
        ),
        replace_verifier_unique(
            b"        checksum_raw = canonical_compact_json(\n",
            b"        checksum_raw = canonical_json(\n",
            "archive-pretty-checksum",
        ),
        replace_verifier_unique(
            b'                "parsed_sha256": hashlib.sha256(\n'
            b"                    canonical_compact_json(parsed)\n",
            b'                "parsed_sha256": hashlib.sha256(\n'
            b"                    canonical_json(parsed)\n",
            "local-config-pretty-checksum",
        ),
        replace_verifier_unique(
            b'        + "\\n"\n    ).encode("ascii")\n',
            b'        + ""\n    ).encode("ascii")\n',
            "compact-checksum-newline",
        ),
    )
    for index, candidate in enumerate(checksum_encoder_mutations):
        reject_mutation(
            f"verifier-private-checksum-encoder-{index}",
            lambda candidate=candidate: validate_private_checksum_encoder_source_bytes(
                candidate
            ),
        )
        rejected += 1
    exact_literal(
        parse_darwin_root_mount(
            "/dev/disk1s1 on / (apfs, sealed, local, read-only, journaled)\n"
        ),
        expected_darwin_system_openssh_record()["root_volume"],
        "selftest Darwin root mount",
    )
    for name, mount in (
        ("root-hfs", "/dev/disk1s1 on / (hfs, sealed, read-only)\n"),
        ("root-unsealed", "/dev/disk1s1 on / (apfs, read-only)\n"),
        ("root-writable", "/dev/disk1s1 on / (apfs, sealed)\n"),
    ):
        reject_mutation(name, lambda mount=mount: parse_darwin_root_mount(mount))
        rejected += 1
    valid_remote = f"{test_source}\t{FORMAL_REMOTE_REF}\n".encode("ascii")
    parse_remote_advertisement(valid_remote, test_source)
    for name, candidate in (
        ("remote-empty", b""),
        ("remote-head", valid_remote.replace(test_source.encode(), b"3" * 40, 1)),
        (
            "remote-ref",
            valid_remote.replace(FORMAL_REMOTE_REF.encode(), b"refs/heads/main"),
        ),
        ("remote-extra", valid_remote + valid_remote),
    ):
        reject_mutation(
            name,
            lambda candidate=candidate: parse_remote_advertisement(
                candidate, test_source
            ),
        )
        rejected += 1
    entries, all_h = parse_index_flags(b"H tracked\0", "selftest index")
    require(entries == 1 and all_h, "valid selftest index flags differ")
    for tag in (b"h", b"S", b"s"):
        reject_mutation(
            f"index-{tag.decode('ascii')}",
            lambda tag=tag: require(
                parse_index_flags(tag + b" tracked\0", "selftest hidden index")[1],
                "hidden index tag",
            ),
        )
        rejected += 1
    manifest_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("manifest-extra", lambda value: value.update(extra=True)),
        ("manifest-platform", lambda value: value["platform"].update(id="qemu-virt")),
        (
            "manifest-physical",
            lambda value: value["scope"].update(physical_provenance="claimed"),
        ),
        ("manifest-budget", lambda value: value["budget"].update(ticks=999_999)),
        (
            "manifest-p95-index",
            lambda value: value["sampling"]["statistics"].update(p95_sorted_index=20),
        ),
        (
            "manifest-run-domain",
            lambda value: value["transcript"]["run_id"]["domains"].update(
                {SMOKE_CAPTURE_MODE: RUN_ID_DOMAINS[FORMAL_CAPTURE_MODE]}
            ),
        ),
        (
            "manifest-qemu-environment-policy",
            lambda value: value["platform"]["qemu_environment"].update(
                policy="ambient-inherited"
            ),
        ),
        (
            "manifest-qemu-environment-injected-name",
            lambda value: value["platform"]["qemu_environment"][
                "allowed_names"
            ].append("DYLD_INSERT_LIBRARIES"),
        ),
        (
            "manifest-qemu-runtime-graph",
            lambda value: value["platform"].update(
                qemu_runtime_graph_sha256="6" * 64
            ),
        ),
        (
            "manifest-qemu-runtime-counts",
            lambda value: value["platform"]["qemu_runtime_counts"].update(
                load_edges=146
            ),
        ),
        (
            "manifest-authorization",
            lambda value: value["decision_rule"].update(aot_authorized=True),
        ),
    ]
    for name, mutation in manifest_mutations:
        candidate = copy.deepcopy(contracts.manifest)
        mutation(candidate)
        reject_mutation(name, lambda candidate=candidate: validate_manifest(candidate))
        rejected += 1
    schema_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("schema-extra", lambda value: value.update(extra=True)),
        (
            "schema-physical-platform",
            lambda value: value["$defs"]["meta"]["properties"]["platform"].update(
                const="milkv-duo-cv1800b"
            ),
        ),
        (
            "schema-timebase",
            lambda value: value["$defs"]["meta"]["properties"]["timebase_hz"].update(
                const=25_000_000
            ),
        ),
        (
            "schema-warmup",
            lambda value: value["$defs"]["end"]["properties"]["warmups"].update(
                const=2
            ),
        ),
        (
            "schema-open-sample",
            lambda value: value["$defs"]["sample"].update(additionalProperties=True),
        ),
        (
            "schema-smoke-eligible",
            lambda value: value["$defs"]["meta"]["oneOf"][1]["properties"][
                "decision_eligible"
            ].update(const=True),
        ),
    ]
    for name, mutation in schema_mutations:
        candidate = copy.deepcopy(contracts.schema)
        mutation(candidate)
        reject_mutation(name, lambda candidate=candidate: validate_schema(candidate))
        rejected += 1
    evidence_schema_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("evidence-schema-extra", lambda value: value.update(extra=True)),
        (
            "evidence-schema-open-environment",
            lambda value: value["$defs"]["environment"].update(
                additionalProperties=True
            ),
        ),
        (
            "evidence-schema-physical",
            lambda value: value["$defs"]["decisionEnvelope"]["properties"][
                "physical_provenance"
            ].update(const="claimed"),
        ),
        (
            "evidence-schema-outcome",
            lambda value: value["$defs"]["derivedDecision"]["properties"]["outcome"][
                "enum"
            ].append("aot-authorized"),
        ),
        (
            "evidence-schema-authorization",
            lambda value: value["$defs"]["derivedDecision"]["properties"][
                "aot_authorized"
            ].update(const=True),
        ),
        (
            "evidence-schema-openssh-method",
            lambda value: value["$defs"]["darwinSystemOpenSsh"]["properties"][
                "method"
            ].update(const="copied-openssh"),
        ),
        (
            "evidence-schema-root-unsealed",
            lambda value: value["$defs"]["darwinRootVolume"]["properties"][
                "sealed"
            ].update(const=False),
        ),
        (
            "evidence-schema-root-filesystem",
            lambda value: value["$defs"]["darwinRootVolume"]["properties"][
                "filesystem"
            ].update(const="hfs"),
        ),
        (
            "evidence-schema-openssh-open",
            lambda value: value["$defs"]["darwinSystemOpenSsh"].update(
                additionalProperties=True
            ),
        ),
        (
            "evidence-schema-qemu-environment-open",
            lambda value: value["$defs"]["qemuEnvironment"].update(
                additionalProperties=True
            ),
        ),
        (
            "evidence-schema-qemu-environment-injected-name",
            lambda value: value["$defs"]["qemuEnvironment"]["properties"][
                "allowed_names"
            ]["const"].append("DYLD_INSERT_LIBRARIES"),
        ),
        (
            "evidence-schema-qemu-runtime-graph",
            lambda value: value["$defs"]["qemuRuntimeClosure"]["properties"][
                "graph_sha256"
            ].update(const="6" * 64),
        ),
        (
            "evidence-schema-qemu-runtime-counts",
            lambda value: value["$defs"]["qemuRuntimeClosure"]["properties"][
                "load_edge_count"
            ].update(const=146),
        ),
    ]
    for name, mutation in evidence_schema_mutations:
        candidate = copy.deepcopy(contracts.evidence_schema)
        mutation(candidate)
        reject_mutation(
            name, lambda candidate=candidate: validate_evidence_schema(candidate)
        )
        rejected += 1
    reject_mutation(
        "evidence-schema-raw-byte",
        lambda: validate_evidence_schema_raw(contracts.evidence_schema_raw + b" "),
    )
    rejected += 1

    meta, samples, ending = synthetic_records(contracts)
    raw = serialize_transcript(meta, samples, ending)
    verified = verify_transcript(
        raw,
        contracts=contracts,
        expected_source=meta["source_commit"],
        expected_challenge=meta["challenge"],
        expected_capture_mode=FORMAL_CAPTURE_MODE,
    )
    summary = derive_summary(verified)
    summary_raw = canonical_json(summary)
    require(
        summary["decision"]["outcome"] == OTHERWISE_OUTCOME,
        "synthetic no-AOT outcome differs",
    )

    transcript_mutations: list[
        tuple[
            str, Callable[[dict[str, Any], list[dict[str, Any]], dict[str, Any]], bytes]
        ]
    ] = []

    def mutated_transcript(
        mutation: Callable[
            [dict[str, Any], list[dict[str, Any]], dict[str, Any]], None
        ],
    ) -> bytes:
        candidate_meta = copy.deepcopy(meta)
        candidate_samples = copy.deepcopy(samples)
        candidate_end = copy.deepcopy(ending)
        mutation(candidate_meta, candidate_samples, candidate_end)
        return serialize_transcript(candidate_meta, candidate_samples, candidate_end)

    transcript_mutations.extend(
        [
            (
                "physical-meta",
                lambda m, s, e: serialize_transcript(
                    {**m, "platform": "milkv-duo-cv1800b"}, s, e
                ),
            ),
            (
                "old-suite",
                lambda m, s, e: serialize_transcript(
                    {**m, "suite_id": "vibeos.c84.aot-decision"}, s, e
                ),
            ),
            (
                "timebase",
                lambda m, s, e: serialize_transcript(
                    {**m, "timebase_hz": 25_000_000}, s, e
                ),
            ),
            (
                "capture-mode-relabel",
                lambda m, s, e: serialize_transcript(
                    {
                        **m,
                        "capture_mode": SMOKE_CAPTURE_MODE,
                        "decision_eligible": False,
                    },
                    s,
                    e,
                ),
            ),
            (
                "sequence",
                lambda m, s, e: serialize_transcript(
                    m, [{**s[0], "sequence": 1}, *s[1:]], e
                ),
            ),
            (
                "accumulator",
                lambda m, s, e: serialize_transcript(
                    m, s, {**e, "accumulator": e["accumulator"] + 1}
                ),
            ),
            (
                "audit-stream",
                lambda m, s, e: FORBIDDEN_AUDIT_PREFIX.encode("ascii")
                + b"decision_eligible=0\n"
                + serialize_transcript(m, s, e),
            ),
        ]
    )
    for name, mutation in transcript_mutations:
        candidate_raw = mutation(
            copy.deepcopy(meta), copy.deepcopy(samples), copy.deepcopy(ending)
        )
        reject_mutation(
            name,
            lambda candidate_raw=candidate_raw: verify_transcript(
                candidate_raw,
                contracts=contracts,
                expected_source=meta["source_commit"],
                expected_challenge=meta["challenge"],
                expected_capture_mode=FORMAL_CAPTURE_MODE,
            ),
        )
        rejected += 1

    unstable_samples = copy.deepcopy(samples)
    for position in (22, 23):
        replace_durations(unstable_samples[position], [10, 20, 30, 5_000, 50, 60, 70])
    unstable_end = {**ending, "accumulator": transcript_accumulator(unstable_samples)}
    unstable_raw = serialize_transcript(meta, unstable_samples, unstable_end)
    reject_mutation(
        "stability",
        lambda: verify_transcript(
            unstable_raw,
            contracts=contracts,
            expected_source=meta["source_commit"],
            expected_challenge=meta["challenge"],
            expected_capture_mode=FORMAL_CAPTURE_MODE,
        ),
    )
    rejected += 1

    eligible_samples = copy.deepcopy(samples)
    for index, sample in enumerate(eligible_samples):
        replace_durations(
            sample,
            [
                100_000,
                100_000,
                100_000,
                500_000 + index * 100,
                100_000,
                100_000,
                100_000,
            ],
        )
    eligible_end = {**ending, "accumulator": transcript_accumulator(eligible_samples)}
    eligible_raw = serialize_transcript(meta, eligible_samples, eligible_end)
    eligible_verified = verify_transcript(
        eligible_raw,
        contracts=contracts,
        expected_source=meta["source_commit"],
        expected_challenge=meta["challenge"],
        expected_capture_mode=FORMAL_CAPTURE_MODE,
    )
    require(
        derive_summary(eligible_verified)["decision"]["outcome"] == ELIGIBLE_OUTCOME,
        "synthetic eligible outcome differs",
    )

    environment, environment_raw = synthetic_environment(verified, summary_raw)
    validate_environment(
        environment,
        raw=environment_raw,
        transcript=verified,
        summary_raw=summary_raw,
        publication=True,
        verify_live=False,
    )
    smoke_meta, smoke_samples, smoke_end = synthetic_records(
        contracts, SMOKE_CAPTURE_MODE
    )
    smoke_raw = serialize_transcript(smoke_meta, smoke_samples, smoke_end)
    smoke_verified = verify_transcript(
        smoke_raw,
        contracts=contracts,
        expected_source=smoke_meta["source_commit"],
        expected_challenge=smoke_meta["challenge"],
        expected_capture_mode=SMOKE_CAPTURE_MODE,
    )
    reject_mutation(
        "smoke-transcript-as-formal",
        lambda: verify_transcript(
            smoke_raw,
            contracts=contracts,
            expected_source=smoke_meta["source_commit"],
            expected_challenge=smoke_meta["challenge"],
            expected_capture_mode=FORMAL_CAPTURE_MODE,
        ),
    )
    rejected += 1
    require(
        smoke_verified.meta["run_id"] != verified.meta["run_id"],
        "formal and smoke run-id domains are not disjoint",
    )
    smoke_summary = derive_summary(smoke_verified)
    smoke_summary_raw = canonical_json(smoke_summary)
    smoke_environment, smoke_environment_raw = synthetic_environment(
        smoke_verified, smoke_summary_raw
    )
    validate_environment(
        smoke_environment,
        raw=smoke_environment_raw,
        transcript=smoke_verified,
        summary_raw=smoke_summary_raw,
        publication=False,
        verify_live=False,
    )
    smoke_other_branch = copy.deepcopy(smoke_environment)
    for repository_state in smoke_other_branch["repository"].values():
        repository_state["branch"] = "codex/development-smoke"
        repository_state["local_codex_wasm_head"] = "5" * 40
        repository_state["local_tracking_codex_wasm_head"] = None
    validate_environment(
        smoke_other_branch,
        raw=canonical_json(smoke_other_branch),
        transcript=smoke_verified,
        summary_raw=smoke_summary_raw,
        publication=False,
        verify_live=False,
    )
    smoke_decision = render_decision(
        contracts=contracts,
        transcript=smoke_verified,
        summary=smoke_summary,
        summary_raw=smoke_summary_raw,
        environment=smoke_environment,
        environment_raw=smoke_environment_raw,
    )
    require(
        smoke_decision["mode"] == SMOKE_CAPTURE_MODE
        and smoke_decision["next_node"] == "none-smoke-only",
        "dirty-smoke decision acquired publication semantics",
    )
    reject_mutation(
        "smoke-publication",
        lambda: validate_environment(
            smoke_environment,
            raw=smoke_environment_raw,
            transcript=smoke_verified,
            summary_raw=smoke_summary_raw,
            publication=True,
            verify_live=False,
        ),
    )
    rejected += 1

    def mutate_linker_runtime_core(value: dict[str, Any]) -> None:
        for stage in ("before", "after"):
            value["toolchain"]["build_input_closure"]["linker_runtime"][stage][
                "nodes"
            ][0]["bytes"] += 1

    environment_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("env-extra", lambda value: value.update(extra=True)),
        ("env-platform", lambda value: value.update(platform="qemu-virt")),
        ("env-physical", lambda value: value.update(physical_provenance="claimed")),
        (
            "env-reused-process",
            lambda value: value["contract"].update(fresh_qemu_processes=2),
        ),
        (
            "env-repository-dirty",
            lambda value: value["repository"]["after"].update(clean=False),
        ),
        (
            "env-qemu-argv",
            lambda value: value["qemu"]["actual_argv"].remove("-icount"),
        ),
        ("env-qemu-relative-path", lambda value: value["qemu"].update(path="qemu")),
        (
            "env-qemu-environment-omitted-policy",
            lambda value: value["qemu"]["environment"].pop("policy"),
        ),
        (
            "env-qemu-environment-omitted-name",
            lambda value: value["qemu"]["environment"]["allowed_names"].pop(),
        ),
        (
            "env-qemu-environment-extra-name",
            lambda value: value["qemu"]["environment"]["allowed_names"].append(
                "DYLD_INSERT_LIBRARIES"
            ),
        ),
        (
            "env-qemu-environment-injected-name",
            lambda value: value["qemu"]["environment"][
                "normalized_values"
            ].update(DYLD_INSERT_LIBRARIES="/tmp/injected.dylib"),
        ),
        (
            "env-qemu-environment-injected-path",
            lambda value: value["qemu"]["environment"][
                "normalized_values"
            ].update(PATH="/tmp/injected"),
        ),
        (
            "env-qemu-environment-allows-probe-state",
            lambda value: value["qemu"]["environment"].update(
                private_directories_must_remain_empty=False
            ),
        ),
        (
            "env-qemu-runtime-preparation-graph",
            lambda value: value["qemu"]["runtime_closures"]["source"][
                "before"
            ].update(graph_sha256="6" * 64),
        ),
        (
            "env-qemu-runtime-preparation-counts",
            lambda value: value["qemu"]["runtime_closures"]["source"][
                "before"
            ].update(load_edge_count=146),
        ),
        (
            "env-helper-path",
            lambda value: value["helpers"]["qemu_peer"].update(
                path="scripts/openssh-peer.py"
            ),
        ),
        (
            "env-executed-source-hash",
            lambda value: value["executed_peer_sources"][
                "scripts/c84-qemu-aot-decision-peer.py"
            ].update(sha256="6" * 64),
        ),
        (
            "env-python-launcher-hash",
            lambda value: value["python_runtime"]["launcher"].update(
                sha256="6" * 64
            ),
        ),
        (
            "env-python-executable-path",
            lambda value: value["python_runtime"]["executable"].update(
                path="/usr/bin/python3"
            ),
        ),
        (
            "env-python-executable-hash",
            lambda value: value["python_runtime"]["executable"].update(
                sha256="6" * 64
            ),
        ),
        (
            "env-python-version",
            lambda value: value["python_runtime"].update(version="3.14.5"),
        ),
        (
            "env-python-flag",
            lambda value: value["python_runtime"]["flags"].update(no_site=0),
        ),
        (
            "env-python-argv",
            lambda value: value["python_runtime"]["argv_prefix"].remove("-S"),
        ),
        (
            "env-python-sys-path",
            lambda value: value["python_runtime"]["effective_sys_path"].append(
                "/tmp/site-packages"
            ),
        ),
        (
            "env-python-stdlib-inventory",
            lambda value: value["python_runtime"]["stdlib_inventory"].update(
                sha256="6" * 64
            ),
        ),
        (
            "env-python-dynamic-runtime",
            lambda value: value["python_runtime"]["runtime_dynamic_closure"][
                "libcrypto"
            ].update(sha256="6" * 64),
        ),
        (
            "env-python-launch-environment",
            lambda value: value["python_runtime"]["environment"]["values"].update(
                PYTHONPATH="/tmp/injected"
            ),
        ),
        (
            "env-host-public-key",
            lambda value: value["host_key_evidence"].update(
                public_key=EXPECTED_HOST_PUBLIC_KEY + "x"
            ),
        ),
        (
            "env-repository-ref",
            lambda value: value["repository"]["after"].update(
                advertised_remote_head="4" * 40
            ),
        ),
        (
            "env-repository-index-hidden",
            lambda value: value["repository"]["after"].update(index_flags_all_h=False),
        ),
        (
            "env-repository-remote-url",
            lambda value: value["repository"]["after"].update(
                remote_query_url="https://example.invalid/vibeos.git"
            ),
        ),
        (
            "env-materialization-method",
            lambda value: value["source_materialization"].update(
                method="dirty-worktree-smoke-not-evidence"
            ),
        ),
        (
            "env-custody-role",
            lambda value: value["execution_custody"]["qemu"].update(sha256="6" * 64),
        ),
        (
            "env-openssh-method",
            lambda value: value["execution_custody"]["openssh"].update(
                method="copied-openssh"
            ),
        ),
        (
            "env-openssh-path",
            lambda value: value["execution_custody"]["openssh"].update(path="/tmp/ssh"),
        ),
        (
            "env-openssh-version",
            lambda value: value["execution_custody"]["openssh"].update(
                version="OpenSSH_other"
            ),
        ),
        (
            "env-openssh-mode",
            lambda value: value["execution_custody"]["openssh"].update(mode="0500"),
        ),
        (
            "env-openssh-uid",
            lambda value: value["execution_custody"]["openssh"].update(uid=501),
        ),
        (
            "env-openssh-gid",
            lambda value: value["execution_custody"]["openssh"].update(gid=20),
        ),
        (
            "env-openssh-nlink",
            lambda value: value["execution_custody"]["openssh"].update(nlink=2),
        ),
        (
            "env-openssh-restricted",
            lambda value: value["execution_custody"]["openssh"].update(
                sf_restricted=False
            ),
        ),
        (
            "env-openssh-root-sealed",
            lambda value: value["execution_custody"]["openssh"]["root_volume"].update(
                sealed=False
            ),
        ),
        (
            "env-openssh-root-read-only",
            lambda value: value["execution_custody"]["openssh"]["root_volume"].update(
                read_only=False
            ),
        ),
        (
            "env-openssh-root-filesystem",
            lambda value: value["execution_custody"]["openssh"]["root_volume"].update(
                filesystem="hfs"
            ),
        ),
        (
            "env-openssh-same-device",
            lambda value: value["execution_custody"]["openssh"].update(
                same_device_as_root=False
            ),
        ),
        (
            "env-openssh-source-identity",
            lambda value: value["openssh"].update(sha256="6" * 64),
        ),
        (
            "env-toolchain-feature",
            lambda value: value["toolchain"]["cargo_command"].__setitem__(
                -1, "wasm-c84-ssh-managed-child-single-boot-collector"
            ),
        ),
        (
            "env-cargo-project-lock-checksum",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_locks"
            ]["project"].update(sha256="6" * 64),
        ),
        (
            "env-cargo-rust-src-lock-checksum",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_locks"
            ]["rust_src"].update(sha256="6" * 64),
        ),
        (
            "env-cargo-lock-union",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_locks"
            ]["union"].update(packages=212),
        ),
        (
            "env-cargo-cache-clock",
            lambda value: value["toolchain"]["build_environment_policy"][
                "normalized_values"
            ].update(__CARGO_TEST_LAST_USE_NOW="1234567891"),
        ),
        (
            "env-cargo-global-cache-output",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_configuration"
            ]["transient_outputs"]["entries"][0].update(sha256="6" * 64),
        ),
        (
            "env-private-crate-tree",
            lambda value: value["toolchain"]["build_input_closure"][
                "private_crate_sources"
            ]["before"].update(sha256="6" * 64),
        ),
        (
            "env-private-crate-archive-tree",
            lambda value: value["toolchain"]["build_input_closure"][
                "private_crate_archives"
            ]["after"].update(sha256="6" * 64),
        ),
        (
            "env-private-cargo-home-extra",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_configuration"
            ]["private_home_after"]["entries"].append(
                {
                    "path": "<private-cargo-home>/registry",
                    "sha256": "6" * 64,
                    "bytes": 1,
                    "mode": "0400",
                    "links": 1,
                }
            ),
        ),
        (
            "env-root-cargo-config",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_configuration"
            ]["root_after"].update(all_absent=False),
        ),
        (
            "env-generated-cargo-config",
            lambda value: value["toolchain"]["build_input_closure"][
                "cargo_configuration"
            ]["generated"].update(sha256="6" * 64),
        ),
        (
            "env-toolchain-tree",
            lambda value: value["toolchain"]["build_input_closure"][
                "toolchain_tree"
            ]["after"].update(sha256="6" * 64),
        ),
        (
            "env-rust-src-tree",
            lambda value: value["toolchain"]["build_input_closure"]["rust_src"][
                "after"
            ].update(sha256="6" * 64),
        ),
        ("env-linker-runtime-core", mutate_linker_runtime_core),
        (
            "env-build-input-path-alias",
            lambda value: value["toolchain"]["build_input_closure"][
                "normalized_paths"
            ].update(source_root="/tmp/synthetic/source"),
        ),
        (
            "env-summary-identity",
            lambda value: value["summary"].update(bytes=len(summary_raw) + 1),
        ),
    ]
    for name, mutation in environment_mutations:
        candidate = copy.deepcopy(environment)
        mutation(candidate)
        candidate_raw = canonical_json(candidate)
        reject_mutation(
            name,
            lambda candidate=candidate, candidate_raw=candidate_raw: validate_environment(
                candidate,
                raw=candidate_raw,
                transcript=verified,
                summary_raw=summary_raw,
                publication=True,
                verify_live=False,
            ),
        )
        rejected += 1

    decision = render_decision(
        contracts=contracts,
        transcript=verified,
        summary=summary,
        summary_raw=summary_raw,
        environment=environment,
        environment_raw=environment_raw,
    )
    require(
        decision["decision"]["outcome"] == OTHERWISE_OUTCOME
        and decision["decision"]["aot_authorized"] is False
        and decision["decision"]["native_code_accepted"] is False
        and decision["population"]["physical_inputs"] == 0
        and decision["population"]["audit_inputs"] == 0,
        "synthetic final decision safety invariants differ",
    )
    strict_json_mutations = {
        "duplicate": b'{"schema":"one","schema":"two"}',
        "float": b'{"ticks":1.0}',
        "nonfinite": b'{"ticks":NaN}',
    }
    for name, candidate_raw in strict_json_mutations.items():
        reject_mutation(
            name,
            lambda candidate_raw=candidate_raw: strict_json_bytes(candidate_raw, name),
        )
        rejected += 1
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-qemu-verifier-live-tool-selftest-"
    ) as temporary_name:
        tool = pathlib.Path(temporary_name).resolve(strict=True) / "tool"
        tool.write_bytes(b"synthetic executable\n")
        tool.chmod(0o700)
        tool_record = {"path": str(tool), **identity_for(tool.read_bytes())}
        validate_live_binary(
            tool_record,
            tool,
            "synthetic live tool",
            verify_live=True,
            require_executable=True,
        )
        changed_record = {**tool_record, "sha256": "6" * 64}
        reject_mutation(
            "live-tool-identity",
            lambda: validate_live_binary(
                changed_record,
                tool,
                "synthetic live tool",
                verify_live=True,
                require_executable=True,
            ),
        )
        rejected += 1
    return rejected


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--check-manifest", action="store_true")
    value.add_argument("--selftest", action="store_true")
    value.add_argument("--publication", action="store_true")
    value.add_argument("--transcript", type=pathlib.Path)
    value.add_argument("--expect-source")
    value.add_argument("--expect-challenge")
    value.add_argument("--expect-capture-mode", choices=CAPTURE_MODES)
    summary = value.add_mutually_exclusive_group()
    summary.add_argument("--summary-in", type=pathlib.Path)
    summary.add_argument("--summary-out", type=pathlib.Path)
    value.add_argument("--environment-in", type=pathlib.Path)
    value.add_argument("--qemu-bin", type=pathlib.Path)
    value.add_argument("--bios-bin", type=pathlib.Path)
    value.add_argument("--kernel-bin", type=pathlib.Path)
    value.add_argument("--openssh-bin", type=pathlib.Path)
    value.add_argument("--materialized-source", type=pathlib.Path)
    value.add_argument("--build-source-root", type=pathlib.Path)
    value.add_argument("--private-cargo-home", type=pathlib.Path)
    value.add_argument("--private-crate-sources", type=pathlib.Path)
    value.add_argument("--private-crate-archives", type=pathlib.Path)
    value.add_argument("--cargo-target", type=pathlib.Path)
    value.add_argument("--toolchain-root", type=pathlib.Path)
    value.add_argument("--rust-src", type=pathlib.Path)
    value.add_argument("--linker-bin", type=pathlib.Path)
    value.add_argument("--execution-qemu-bin", type=pathlib.Path)
    value.add_argument("--execution-bios-bin", type=pathlib.Path)
    value.add_argument("--execution-kernel-bin", type=pathlib.Path)
    decision = value.add_mutually_exclusive_group()
    decision.add_argument("--decision-in", type=pathlib.Path)
    decision.add_argument("--decision-out", type=pathlib.Path)
    value.add_argument("--overwrite", action="store_true")
    return value


def main() -> int:
    arguments = parser().parse_args()
    transcript_only = [
        arguments.expect_source,
        arguments.expect_challenge,
        arguments.expect_capture_mode,
        arguments.summary_in,
        arguments.summary_out,
        arguments.environment_in,
        arguments.decision_in,
        arguments.decision_out,
        arguments.qemu_bin,
        arguments.bios_bin,
        arguments.kernel_bin,
        arguments.openssh_bin,
        arguments.materialized_source,
        arguments.build_source_root,
        arguments.private_cargo_home,
        arguments.private_crate_sources,
        arguments.private_crate_archives,
        arguments.cargo_target,
        arguments.toolchain_root,
        arguments.rust_src,
        arguments.linker_bin,
        arguments.execution_qemu_bin,
        arguments.execution_bios_bin,
        arguments.execution_kernel_bin,
    ]
    if arguments.transcript is None and any(
        item is not None for item in transcript_only
    ):
        parser().error("transcript evidence options require --transcript")
    if arguments.transcript is not None and (
        arguments.expect_source is None
        or arguments.expect_challenge is None
        or arguments.expect_capture_mode is None
    ):
        parser().error(
            "--transcript requires --expect-source, --expect-challenge, "
            "and --expect-capture-mode"
        )
    if arguments.environment_in is not None and arguments.summary_in is None:
        parser().error("--environment-in requires --summary-in")
    if arguments.publication and arguments.environment_in is None:
        parser().error("--publication requires --environment-in")
    if arguments.publication and (
        arguments.decision_in is None and arguments.decision_out is None
    ):
        parser().error("--publication requires --decision-in or --decision-out")
    if arguments.publication and arguments.expect_capture_mode != FORMAL_CAPTURE_MODE:
        parser().error("--publication categorically requires formal-publication mode")
    if arguments.publication and arguments.overwrite:
        parser().error("--publication forbids --overwrite")
    if (arguments.decision_in is not None or arguments.decision_out is not None) and (
        arguments.environment_in is None or arguments.summary_in is None
    ):
        parser().error(
            "decision verification requires --summary-in and --environment-in"
        )
    live_bins = (
        arguments.qemu_bin,
        arguments.bios_bin,
        arguments.kernel_bin,
        arguments.openssh_bin,
        arguments.execution_qemu_bin,
        arguments.execution_bios_bin,
        arguments.execution_kernel_bin,
        arguments.build_source_root,
        arguments.private_cargo_home,
        arguments.private_crate_sources,
        arguments.private_crate_archives,
        arguments.cargo_target,
        arguments.toolchain_root,
        arguments.rust_src,
        arguments.linker_bin,
    )
    if arguments.environment_in is not None and any(item is None for item in live_bins):
        parser().error(
            "--environment-in requires binary custody and complete live build-input paths"
        )
    if arguments.environment_in is None and any(item is not None for item in live_bins):
        parser().error("live binary options require --environment-in")
    if arguments.publication and arguments.materialized_source is None:
        parser().error("--publication requires --materialized-source")
    if not arguments.publication and arguments.materialized_source is not None:
        parser().error("--materialized-source is formal-publication only")
    if (
        arguments.environment_in is not None
        and not arguments.publication
        and arguments.expect_capture_mode != SMOKE_CAPTURE_MODE
    ):
        parser().error(
            "non-publication environment/decision verification requires "
            "dirty-smoke-not-publication mode"
        )
    if (
        arguments.overwrite
        and arguments.summary_out is None
        and arguments.decision_out is None
    ):
        parser().error("--overwrite requires an output")
    if (
        not arguments.check_manifest
        and not arguments.selftest
        and arguments.transcript is None
    ):
        parser().error("choose --check-manifest, --selftest, and/or --transcript")
    try:
        contracts = load_contracts()
        rejected = selftest(contracts) if arguments.selftest else 0
        if arguments.check_manifest:
            print(
                "PASS C8.4 fixed-QEMU contract "
                f"manifest_sha256={contracts.manifest_sha256} "
                f"schema_sha256={contracts.schema_sha256} "
                f"evidence_schema_sha256={contracts.evidence_schema_sha256}"
            )
        if arguments.selftest:
            print(
                f"PASS C8.4 fixed-QEMU verifier selftest rejected_mutations={rejected}"
            )
        if arguments.transcript is None:
            return 0

        transcript_raw = read_regular(
            arguments.transcript, "QEMU UART transcript", MAX_TRANSCRIPT_BYTES
        )
        verified = verify_transcript(
            transcript_raw,
            contracts=contracts,
            expected_source=arguments.expect_source,
            expected_challenge=arguments.expect_challenge,
            expected_capture_mode=arguments.expect_capture_mode,
        )
        derived = derive_summary(verified)
        summary_raw = canonical_json(derived)
        summary_status = "derived-only"
        if arguments.summary_in is not None:
            observed_summary_raw = read_regular(
                arguments.summary_in, "QEMU summary", MAX_JSON_BYTES
            )
            observed_summary = strict_json_bytes(observed_summary_raw, "QEMU summary")
            exact_literal(observed_summary, derived, "QEMU summary")
            require(
                observed_summary_raw == summary_raw,
                "QEMU summary is not canonical JSON",
            )
            summary_raw = observed_summary_raw
            summary_status = "checked"
        elif arguments.summary_out is not None:
            summary_raw = write_json(
                arguments.summary_out, derived, overwrite=arguments.overwrite
            )
            summary_status = "written"

        decision_status = "none"
        if arguments.environment_in is not None:
            environment_raw = read_regular(
                arguments.environment_in, "QEMU environment", MAX_JSON_BYTES
            )
            environment = strict_json_bytes(environment_raw, "QEMU environment")
            checked_environment = validate_environment(
                environment,
                raw=environment_raw,
                transcript=verified,
                summary_raw=summary_raw,
                publication=arguments.publication,
                qemu_bin=arguments.qemu_bin,
                bios_bin=arguments.bios_bin,
                kernel_bin=arguments.kernel_bin,
                openssh_bin=arguments.openssh_bin,
                materialized_source=arguments.materialized_source,
                build_source_root=arguments.build_source_root,
                private_cargo_home=arguments.private_cargo_home,
                private_crate_sources=arguments.private_crate_sources,
                private_crate_archives=arguments.private_crate_archives,
                cargo_target=arguments.cargo_target,
                toolchain_root=arguments.toolchain_root,
                rust_src=arguments.rust_src,
                linker_bin=arguments.linker_bin,
                execution_qemu_bin=arguments.execution_qemu_bin,
                execution_bios_bin=arguments.execution_bios_bin,
                execution_kernel_bin=arguments.execution_kernel_bin,
            )
            require(
                checked_environment["identity"] == identity_for(environment_raw),
                "QEMU environment identity differs",
            )
            expected_decision = render_decision(
                contracts=contracts,
                transcript=verified,
                summary=derived,
                summary_raw=summary_raw,
                environment=environment,
                environment_raw=environment_raw,
            )
            if arguments.decision_in is not None:
                decision_raw = read_regular(
                    arguments.decision_in, "QEMU DECISION.json", MAX_JSON_BYTES
                )
                observed_decision = strict_json_bytes(
                    decision_raw, "QEMU DECISION.json"
                )
                exact_literal(
                    observed_decision, expected_decision, "QEMU DECISION.json"
                )
                require(
                    decision_raw == canonical_json(expected_decision),
                    "QEMU DECISION.json is not canonical JSON",
                )
                decision_status = "checked"
            elif arguments.decision_out is not None:
                write_json(
                    arguments.decision_out,
                    expected_decision,
                    overwrite=arguments.overwrite,
                )
                decision_status = "written"

        # Close the contract and all caller-provided evidence against TOCTOU.
        closed = load_contracts()
        require(
            closed.manifest_raw == contracts.manifest_raw
            and closed.schema_raw == contracts.schema_raw
            and closed.evidence_schema_raw == contracts.evidence_schema_raw,
            "QEMU contract changed during verification",
        )
        require(
            read_regular(
                arguments.transcript, "QEMU UART transcript", MAX_TRANSCRIPT_BYTES
            )
            == transcript_raw,
            "QEMU transcript changed during verification",
        )
        if arguments.summary_in is not None:
            require(
                read_regular(arguments.summary_in, "QEMU summary", MAX_JSON_BYTES)
                == summary_raw,
                "QEMU summary changed during verification",
            )
        elif arguments.summary_out is not None:
            require(
                read_regular(arguments.summary_out, "QEMU summary", MAX_JSON_BYTES)
                == summary_raw,
                "written QEMU summary changed during verification",
            )
        if arguments.environment_in is not None:
            require(
                read_regular(
                    arguments.environment_in, "QEMU environment", MAX_JSON_BYTES
                )
                == environment_raw,
                "QEMU environment changed during verification",
            )
        if arguments.decision_in is not None:
            require(
                read_regular(
                    arguments.decision_in, "QEMU DECISION.json", MAX_JSON_BYTES
                )
                == decision_raw,
                "QEMU DECISION.json changed during verification",
            )
        elif arguments.decision_out is not None:
            require(
                read_regular(
                    arguments.decision_out, "QEMU DECISION.json", MAX_JSON_BYTES
                )
                == canonical_json(expected_decision),
                "written QEMU DECISION.json changed during verification",
            )
        if arguments.environment_in is not None:
            # Repeat every live identity and repository check after rereading all
            # evidence.  A successful result therefore closes late helper/tool,
            # HEAD/ref, and caller-file changes as well as the initial snapshot.
            validate_environment(
                environment,
                raw=environment_raw,
                transcript=verified,
                summary_raw=summary_raw,
                publication=arguments.publication,
                qemu_bin=arguments.qemu_bin,
                bios_bin=arguments.bios_bin,
                kernel_bin=arguments.kernel_bin,
                openssh_bin=arguments.openssh_bin,
                materialized_source=arguments.materialized_source,
                build_source_root=arguments.build_source_root,
                private_cargo_home=arguments.private_cargo_home,
                private_crate_sources=arguments.private_crate_sources,
                private_crate_archives=arguments.private_crate_archives,
                cargo_target=arguments.cargo_target,
                toolchain_root=arguments.toolchain_root,
                rust_src=arguments.rust_src,
                linker_bin=arguments.linker_bin,
                execution_qemu_bin=arguments.execution_qemu_bin,
                execution_bios_bin=arguments.execution_bios_bin,
                execution_kernel_bin=arguments.execution_kernel_bin,
            )
        outcome = derived["decision"]["outcome"]
        print(
            "PASS C8.4 fixed-QEMU AOT decision evidence "
            f"source={verified.meta['source_commit']} challenge={verified.meta['challenge']} "
            f"run_id={verified.meta['run_id']} samples={SAMPLES} retained={RETAINED} "
            f"capture_mode={verified.meta['capture_mode']} "
            f"p95_index={P95_SORTED_INDEX} stability=pass outcome={outcome} "
            f"summary={summary_status} decision={decision_status} "
            "physical_provenance=not-claimed aot_authorized=false native_code_accepted=false"
        )
        return 0
    except (OSError, UnicodeDecodeError, VerificationError) as error:
        print(f"FAIL verify-c84-qemu-aot-decision: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
