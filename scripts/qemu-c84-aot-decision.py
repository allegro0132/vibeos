#!/usr/bin/env python3
"""Build, capture, and verify the fixed-QEMU C8.4 AOT decision campaign.

Formal mode binds a clean Git HEAD and a fresh challenge into one dedicated
kernel, starts exactly one fixed QEMU process, drives 3 warm-up plus 21 retained
samples over real OpenSSH, freezes UART after META/24 SAMPLE/END, and invokes
the independent QEMU verifier in two stages.  ``--allow-dirty-smoke`` keeps the
same runtime contract but cannot export evidence or claim publication.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import contextlib
import ctypes
import errno
import hashlib
import io
import json
import os
import pathlib
import py_compile
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import types
from typing import Any, Callable, NoReturn


ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE_RUNNER_PATH = ROOT / "scripts/qemu-c83-runtime-costs.py"
PEER = ROOT / "scripts/c84-qemu-aot-decision-peer.py"
VERIFIER = ROOT / "scripts/verify-c84-qemu-aot-decision.py"
KEY_FIXTURE = ROOT / "scripts/openssh-test-key.py"
PORT_HELPER = ROOT / "scripts/openssh-peer.py"
LAUNCHER = ROOT / "scripts/run-c84-qemu-aot-decision.sh"
FIRMWARE = ROOT / "firmware/qemu-virt"
KERNEL_RELATIVE = pathlib.Path("riscv64imac-unknown-none-elf/release/vibeos-qemu-virt")

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
PRIVATE_CARGO_CACHE = pathlib.Path("/Users/ziangwang/.cargo")
PINNED_RUSTUP_HOME = pathlib.Path("/Users/ziangwang/.rustup")
PINNED_RUST_HOST_TRIPLE = "aarch64-apple-darwin"
PINNED_TOOLCHAIN_ROOT = (
    PINNED_RUSTUP_HOME
    / "toolchains/nightly-2026-08-01-aarch64-apple-darwin"
)
PINNED_RUST_SRC = PINNED_TOOLCHAIN_ROOT / "lib/rustlib/src/rust/library"
PINNED_RUSTUP = pathlib.Path(
    "/opt/homebrew/Cellar/rustup/1.29.0_2/bin/rustup"
)
MAX_CRATE_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_CRATE_CHECKSUM_BYTES = 4 * 1024 * 1024
MAX_CRATE_SOURCE_BYTES = 512 * 1024 * 1024
MAX_CRATE_FILES = 50_000
RUST_SRC_VENDOR_CHECKSUM_COMMENT = (
    "This file only protects against accidental modifications. It is not a "
    "security mechanism and does not protect against malicious changes."
)

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
PINNED_PYTHON_OPT_PREFIX = pathlib.Path("/opt/homebrew/opt/python@3.14")
PINNED_HASHLIB_EXTENSION = (
    PINNED_PYTHON_LIB_DYNLOAD / "_hashlib.cpython-314-darwin.so"
)
PINNED_HASHLIB_EXTENSION_SHA256 = (
    "7218f3babc5db5b091249955dbba6c2260a0dddd25560bc17d83c7da87a3e95c"
)
PINNED_HASHLIB_EXTENSION_BYTES = 97_968
PINNED_LIBCRYPTO_LINK = pathlib.Path(
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
)
PINNED_LIBCRYPTO = pathlib.Path(
    "/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib"
)
PINNED_LIBCRYPTO_SHA256 = (
    "34bc039f5c725691e757ef42d26f1709830b18046c3ad6d93985153c83d0bbbc"
)
PINNED_LIBCRYPTO_BYTES = 4_846_032
PINNED_LZMA_EXTENSION = PINNED_PYTHON_LIB_DYNLOAD / "_lzma.cpython-314-darwin.so"
PINNED_LZMA_EXTENSION_SHA256 = (
    "90f3612615d66f3cc7ebced3851f2c24ed91a142ddb5428b1ad9253d2a7fbb19"
)
PINNED_LZMA_EXTENSION_BYTES = 92_256
PINNED_LIBLZMA_LINK = pathlib.Path("/opt/homebrew/opt/xz/lib/liblzma.5.dylib")
PINNED_LIBLZMA = pathlib.Path("/opt/homebrew/Cellar/xz/5.8.3/lib/liblzma.5.dylib")
PINNED_LIBLZMA_SHA256 = (
    "3d5bfa2f097c31463642b1daab5e662b44368bb4da368f85e412e7f9adcbaa10"
)
PINNED_LIBLZMA_BYTES = 184_512
PINNED_ZSTD_EXTENSION = PINNED_PYTHON_LIB_DYNLOAD / "_zstd.cpython-314-darwin.so"
PINNED_ZSTD_EXTENSION_SHA256 = (
    "4ee39ca9e3102ca37938cd578bb8e0c1c82106be7001f329ded33a0720cbee5e"
)
PINNED_ZSTD_EXTENSION_BYTES = 114_176
PINNED_LIBZSTD_LINK = pathlib.Path("/opt/homebrew/opt/zstd/lib/libzstd.1.dylib")
PINNED_LIBZSTD = pathlib.Path(
    "/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.5.7.dylib"
)
PINNED_LIBZSTD_SHA256 = (
    "e2847c4613b386683c234913ae3b7b04299254096caf7616e3b3cd9bb97a39ab"
)
PINNED_LIBZSTD_BYTES = 649_648
PINNED_PYTHON_PYCACHE_PREFIX = pathlib.Path(
    "/var/empty/vibeos-c84-python-pyc"
)
PINNED_PYTHON_STDLIB_INVENTORY_SHA256 = (
    "59bb25e3cf5c4483dfdd8d152f41dafef62ab2f905717bcfd5f800c1a61c641a"
)
PINNED_PYTHON_STDLIB_INVENTORY_ENTRIES = 2_703
PINNED_PYTHON_STDLIB_INVENTORY_BYTES = 57_153_940
PINNED_PYTHON_STDLIB_INVENTORY_FILES = 2_498
PINNED_PYTHON_STDLIB_INVENTORY_DIRECTORIES = 203
PINNED_PYTHON_STDLIB_INVENTORY_SYMLINKS = 2
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
    "VIBEOS_C84_PYTHON_LAUNCHER": str(LAUNCHER),
    "XDG_CONFIG_HOME": "/var/empty",
    "__CF_USER_TEXT_ENCODING": "0x1F5:0x0:0x0",
}

FORMAL_FEATURE = "wasm-c84-qemu-aot-decision"
SMOKE_FEATURE = "wasm-c84-qemu-aot-decision-smoke"
FORMAL_CAPTURE_MODE = "formal-publication"
SMOKE_CAPTURE_MODE = "dirty-smoke-not-publication"
FORMAL_BRANCH = "codex/wasm"
FORMAL_LOCAL_REF = "refs/heads/codex/wasm"
FORMAL_ORIGIN_REF = "refs/remotes/origin/codex/wasm"
FORMAL_CONFIGURED_ORIGIN = "git@github.com:allegro0132/vibeos.git"
FORMAL_REMOTE_URL = "https://github.com/allegro0132/vibeos.git"
FORMAL_REMOTE_REF = "refs/heads/codex/wasm"
SOURCE_ENV = "VIBEOS_C84_SOURCE_COMMIT"
CHALLENGE_ENV = "VIBEOS_C84_CHALLENGE"
PLATFORM = "qemu-virt-rv64-tcg-icount-v1"
SUITE_ID = "vibeos.c84.qemu-aot-decision"

QEMU_MACHINE = "virt"
QEMU_CPU = "rv64"
QEMU_SMP = "1"
QEMU_MEMORY = "128M"
QEMU_ACCELERATOR = "tcg,thread=single"
QEMU_ICOUNT = "shift=0,align=off,sleep=off"
QEMU_BIOS_NAME = "opensbi-riscv64-generic-fw_dynamic.bin"
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
QEMU_RNG_ID = "vibeos-c84-aot-decision-rng"
QEMU_NET_ID = "vibeos-c84-aot-decision-net"
QEMU_ENVIRONMENT_POLICY = "deny-by-default-private-campaign-v1"
QEMU_ENVIRONMENT_APPLIES_TO = [
    "firmware-search-probe",
    "version-probe",
    "live-campaign",
]
QEMU_ENVIRONMENT_DIRECTORY_MODE = 0o700
QEMU_ENVIRONMENT_ALLOWED_NAMES = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "TMPDIR",
    "TZ",
    "XDG_CONFIG_HOME",
)
QEMU_ENVIRONMENT_PATH = "/usr/bin:/bin"
QEMU_PROCESS_CWD = "/"
QEMU_ENVIRONMENT_NORMALIZED_VALUES = {
    "HOME": "<campaign-root>/qemu-environment/home",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": QEMU_ENVIRONMENT_PATH,
    "TMPDIR": "<campaign-root>/qemu-environment/tmp",
    "TZ": "UTC",
    "XDG_CONFIG_HOME": "<campaign-root>/qemu-environment/xdg-config",
}
QEMU_RUNTIME_CLOSURE_POLICY = "darwin-qemu-recursive-nonsystem-macho-closure-v1"
QEMU_RUNTIME_SYSTEM_PREFIXES = ["/System/Library/", "/usr/lib/"]
QEMU_RUNTIME_HOST_LIMIT = (
    "same-uid-host-exclusivity-required; pre/post/final identity checks cannot "
    "exclude a same-UID swap-and-restore during a live process"
)
QEMU_DATA_DIRECTORY_MODE = 0o500

META_PREFIX = "VIBE_WASM_AOT_META "
SAMPLE_PREFIX = "VIBE_WASM_AOT_SAMPLE "
END_PREFIX = "VIBE_WASM_AOT_END "
FORMAL_PREFIXES = (META_PREFIX, SAMPLE_PREFIX, END_PREFIX)
SAMPLE_COUNT = 24
WARMUP_COUNT = 3
RETAINED_COUNT = 21
TIMEBASE_HZ = 10_000_000
BUDGET_TICKS = 1_000_000

DEFAULT_TIMEOUT_SECONDS = 900.0
DEFAULT_READY_TIMEOUT_SECONDS = 60.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 30.0
DEFAULT_MARKER_TIMEOUT_SECONDS = 30.0
END_SETTLE_SECONDS = 0.3
MAX_TRANSCRIPT_BYTES = 256 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GENERIC_WASM_FAILURE = re.compile(r"\bWASM_[A-Z0-9_]+ FAIL\b")
TEST_ONLY_SOURCE_COMMIT = "1" * 40
TEST_ONLY_CHALLENGE = "2" * 64
EVIDENCE_FILES = {
    "transcript": "uart.log",
    "summary": "summary.json",
    "environment": "environment.json",
    "decision": "DECISION.json",
}
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
GIT_REMOTE_QUERY_COMMAND = [
    "git",
    "ls-remote",
    "--exit-code",
    "--refs",
    FORMAL_REMOTE_URL,
    FORMAL_REMOTE_REF,
]
SANITIZED_GIT_PATH = os.pathsep.join(
    ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin")
)
GIT_LOCAL_CONFIG_POLICY = "raw-identity-safe-key-allowlist-v1"
EXPECTED_SUBMODULES = {
    "vendor/jitterentropy-rs": ".git/modules/vendor/jitterentropy-rs",
    "vendor/sunset": ".git/modules/vendor/sunset",
}
GIT_LOCAL_CONFIG_PATHS = {
    ".": ".git/config",
    **{
        path: f"{git_directory}/config"
        for path, git_directory in EXPECTED_SUBMODULES.items()
    },
}
CUSTODY_SCHEME = "private-qemu-bios-kernel-plus-darwin-system-openssh-v1"
CUSTODY_DIRECTORY_MODE = 0o500
CUSTODY_ROLES = {
    "qemu": ("qemu-system-riscv64", 0o500),
    "bios": (QEMU_BIOS_NAME, 0o400),
    "kernel_elf": ("vibeos-qemu-virt", 0o400),
}
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
SOURCE_CLOSURE_PREFIX = "VIBEOS_C84_EXECUTED_PYTHON_SOURCES "
EXPECTED_HOST_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAICnlgzqRWmQppOOnlIR1wzjvQ264K+ickvBZcEQD251V"
)
EXPECTED_HOST_FINGERPRINT = "SHA256:Tpigy/2zLGErAlymNq6E6LHkGOIA5S1+gJsEi5VteN8"


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


def load_base_runner() -> types.ModuleType:
    return load_source_module(
        "vibeos_c84_qemu_decision_c83_runner", BASE_RUNNER_PATH
    )


BASE = load_base_runner()


class RunnerError(RuntimeError):
    """The fixed-QEMU build, capture, closure, or publication failed."""


class PublicationDurabilityError(RunnerError):
    """Verified bytes were committed, but parent-directory durability is unknown."""


def fail(message: str) -> NoReturn:
    raise RunnerError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_hex(value: str, pattern: re.Pattern[str], length: int, label: str) -> str:
    if pattern.fullmatch(value) is None:
        fail(f"{label} must be canonical lowercase hexadecimal of length {length}")
    if not any(character != "0" for character in value):
        fail(f"{label} must not be the all-zero sentinel")
    return value


def positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not 1.0 <= parsed <= 3600.0:
        raise argparse.ArgumentTypeError("must be between 1 and 3600 seconds")
    return parsed


def strict_json_path(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        decoded = BASE.strict_json_loads(path.read_text(encoding="utf-8"), label)
    except OSError as error:
        fail(f"cannot read {label} {path}: {error}")
    if not isinstance(decoded, dict):
        fail(f"{label} is not a JSON object")
    return decoded


def run_combined_version(command: list[str], label: str) -> str:
    require(
        command and pathlib.Path(command[0]).is_absolute(),
        f"{label} path is not absolute",
    )
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as error:
        fail(f"cannot execute {label}: {error}")
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output:
        fail(f"cannot identify {label}: {output or f'exit {completed.returncode}'}")
    return output


def sanitized_git(
    arguments: list[str],
    label: str,
    *,
    cwd: pathlib.Path = ROOT,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> tuple[int, bytes]:
    executable = shutil.which("git", path=SANITIZED_GIT_PATH)
    require(executable is not None, "Git executable is unavailable")
    try:
        executable = str(pathlib.Path(executable).resolve(strict=True))
    except OSError as error:
        fail(f"cannot resolve sanitized Git executable: {error}")
    environment = {
        "HOME": "/nonexistent-vibeos-c84-qemu-runner",
        "XDG_CONFIG_HOME": "/nonexistent-vibeos-c84-qemu-runner",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": SANITIZED_GIT_PATH,
        "TMPDIR": "/tmp",
        "TZ": "UTC",
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
        fail(f"cannot run sanitized Git for {label}: {error}")
    if completed.returncode not in allowed_returncodes:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(
            f"sanitized Git {label} failed: {detail or f'exit {completed.returncode}'}"
        )
    return completed.returncode, completed.stdout


def sanitized_git_line(arguments: list[str], label: str) -> str:
    _, raw = sanitized_git(arguments, label)
    require(
        raw.endswith(b"\n") and raw.count(b"\n") == 1,
        f"sanitized Git {label} output differs",
    )
    try:
        return raw[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail(f"sanitized Git {label} output is not ASCII")


def parse_remote_advertisement(raw: bytes, source_commit: str) -> str:
    expected = f"{source_commit}\t{FORMAL_REMOTE_REF}\n".encode("ascii")
    require(raw == expected, "fixed remote did not advertise the exact source commit")
    return source_commit


def parse_index_flags(raw: bytes, label: str) -> tuple[int, bool]:
    require(raw.endswith(b"\0"), f"{label} is not NUL terminated")
    records = raw[:-1].split(b"\0") if raw else []
    require(bool(records), f"{label} has no tracked entries")
    require(all(len(record) >= 3 for record in records), f"{label} record is truncated")
    all_h = all(record.startswith(b"H ") for record in records)
    return len(records), all_h


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
        except UnicodeDecodeError:
            fail(f"{label} entry is not canonical ASCII/UTF-8")
        require(
            mode in {"100644", "100755", "160000"},
            f"{label} entry mode differs: {mode}",
        )
        require(
            kind == ("commit" if mode == "160000" else "blob"),
            f"{label} entry type differs",
        )
        require(HEX40.fullmatch(object_id) is not None, f"{label} object id differs")
        pure = pathlib.PurePosixPath(path)
        require(
            path
            and not pure.is_absolute()
            and ".." not in pure.parts
            and path == pure.as_posix(),
            f"{label} entry path is unsafe",
        )
        require(path not in seen, f"{label} repeats path {path}")
        seen.add(path)
        records.append((mode, kind, object_id, path))
    require(bool(records), f"{label} has no entries")
    return records


def git_object_inventory(
    git_prefix: list[str], commit: str, label: str
) -> tuple[list[tuple[str, str, str, str]], dict[str, object]]:
    commit = canonical_hex(commit, HEX40, 40, f"{label} commit")
    tree = canonical_hex(
        sanitized_git_line(
            [*git_prefix, "rev-parse", "--verify", f"{commit}^{{tree}}"],
            f"{label} tree",
        ),
        HEX40,
        40,
        f"{label} tree",
    )
    _, raw = sanitized_git(
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


def source_object_inventory(
    source_commit: str,
) -> tuple[
    dict[str, object],
    dict[str, tuple[list[str], list[tuple[str, str, str, str]]]],
]:
    root_entries, root_record = git_object_inventory([], source_commit, "superproject")
    gitlinks = {
        path: object_id for mode, _, object_id, path in root_entries if mode == "160000"
    }
    require(
        set(gitlinks) == set(EXPECTED_SUBMODULES),
        f"superproject gitlink set differs: {sorted(gitlinks)}",
    )
    submodule_records: list[dict[str, object]] = []
    superproject_git_dir = (ROOT / ".git").resolve(strict=True)
    require(
        superproject_git_dir.is_dir(),
        f"superproject object database is missing: {superproject_git_dir}",
    )
    export_inputs: dict[
        str, tuple[list[str], list[tuple[str, str, str, str]]]
    ] = {".": ([f"--git-dir={superproject_git_dir}"], root_entries)}
    for path in sorted(EXPECTED_SUBMODULES):
        git_dir = (ROOT / EXPECTED_SUBMODULES[path]).resolve(strict=True)
        require(git_dir.is_dir(), f"submodule object database is missing: {git_dir}")
        entries, record = git_object_inventory(
            [f"--git-dir={git_dir}"], gitlinks[path], f"submodule {path}"
        )
        require(
            all(mode != "160000" for mode, _, _, _ in entries),
            f"nested gitlinks are not allowed in {path}",
        )
        submodule_records.append({"path": path, **record})
        export_inputs[path] = ([f"--git-dir={git_dir}"], entries)
    record = {
        "method": "exact-commit-raw-blob-export-v1",
        "decision_eligible": True,
        "superproject": root_record,
        "submodules": submodule_records,
        "ignored_worktree_inputs": "excluded-not-copied",
        "cargo_target": "fresh-private",
    }
    return record, export_inputs


def export_git_tree(
    *,
    git_prefix: list[str],
    entries: list[tuple[str, str, str, str]],
    destination: pathlib.Path,
    label: str,
) -> None:
    if os.path.lexists(destination):
        try:
            metadata = destination.lstat()
        except OSError as error:
            fail(f"cannot inspect precreated {label} destination: {error}")
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not destination.is_symlink()
            and not tuple(destination.iterdir()),
            f"precreated {label} destination is not one empty directory",
        )
        destination.chmod(0o700)
    else:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    executable = shutil.which("git", path=SANITIZED_GIT_PATH)
    require(executable is not None, "Git executable is unavailable")
    executable = str(pathlib.Path(executable).resolve(strict=True))
    environment = {
        "HOME": "/nonexistent-vibeos-c84-qemu-exporter",
        "XDG_CONFIG_HOME": "/nonexistent-vibeos-c84-qemu-exporter",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": SANITIZED_GIT_PATH,
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    command = [
        executable,
        "--no-pager",
        "-c",
        "color.ui=false",
        *git_prefix,
        "cat-file",
        "--batch",
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=pathlib.Path("/"),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot start raw Git blob exporter for {label}: {error}")
    require(
        process.stdin is not None and process.stdout is not None,
        f"raw Git blob exporter pipes are missing for {label}",
    )
    try:
        for mode, kind, object_id, relative in entries:
            if kind == "commit":
                continue
            require(kind == "blob", f"{label} export object is not a blob")
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline()
            match = re.fullmatch(
                rb"([0-9a-f]{40}) blob ([1-9][0-9]*|0)\n", header
            )
            require(match is not None, f"{label} cat-file header differs")
            require(
                match.group(1).decode("ascii") == object_id,
                f"{label} cat-file returned a different object",
            )
            byte_length = int(match.group(2), 10)
            chunks: list[bytes] = []
            remaining = byte_length
            while remaining:
                chunk = process.stdout.read(min(remaining, 1024 * 1024))
                require(bool(chunk), f"{label} cat-file blob is truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            require(
                process.stdout.read(1) == b"\n",
                f"{label} cat-file blob terminator differs",
            )
            raw = b"".join(chunks)
            require(
                git_blob_oid(raw) == object_id,
                f"{label} cat-file blob identity differs: {relative}",
            )
            output = destination / relative
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            for parent in (output.parent, *output.parent.parents):
                if parent == destination.parent:
                    break
                metadata = parent.lstat()
                require(
                    stat.S_ISDIR(metadata.st_mode) and not parent.is_symlink(),
                    f"{label} export parent is unsafe: {parent}",
                )
            file_mode = 0o755 if mode == "100755" else 0o644
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(output, flags, file_mode)
            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(descriptor, raw[offset:])
                    require(written > 0, f"{label} blob export made no progress")
                    offset += written
                os.fchmod(descriptor, file_mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        process.stdin.close()
        process.stdin = None
        stderr = process.stderr.read() if process.stderr is not None else b""
        returncode = process.wait(timeout=60)
        require(
            returncode == 0 and stderr == b"",
            f"raw Git blob exporter failed for {label}",
        )
    except RunnerError:
        process.kill()
        process.wait()
        raise
    except (OSError, subprocess.SubprocessError) as error:
        process.kill()
        process.wait()
        fail(f"raw Git blob exporter failed for {label}: {error}")


def git_blob_oid(raw: bytes) -> str:
    header = b"blob " + str(len(raw)).encode("ascii") + b"\0"
    return hashlib.sha1(header + raw).hexdigest()  # noqa: S324 - Git object identity


def expected_materialized_files(
    source_commit: str,
) -> tuple[
    dict[str, tuple[str, str]],
    dict[str, object],
    dict[str, tuple[list[str], list[tuple[str, str, str, str]]]],
]:
    record, export_inputs = source_object_inventory(source_commit)
    root_entries = export_inputs["."][1]
    expected: dict[str, tuple[str, str]] = {
        path: (mode, object_id)
        for mode, _, object_id, path in root_entries
        if mode != "160000"
    }
    for path in sorted(EXPECTED_SUBMODULES):
        entries = export_inputs[path][1]
        for mode, _, object_id, relative in entries:
            combined = f"{path}/{relative}"
            require(combined not in expected, f"materialized path overlaps: {combined}")
            expected[combined] = (mode, object_id)
    record["materialized_files"] = len(expected)
    return expected, record, export_inputs


def verify_materialized_source(
    source: pathlib.Path,
    expected: dict[str, tuple[str, str]],
) -> None:
    observed: set[str] = set()
    for directory, directory_names, filenames in os.walk(source, followlinks=False):
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
            relative = path.relative_to(source).as_posix()
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
            expected_mode = 0o755 if mode == "100755" else 0o644
            require(
                stat.S_IMODE(metadata.st_mode) == expected_mode,
                f"materialized source mode differs: {relative}",
            )
            try:
                raw = path.read_bytes()
            except OSError as error:
                fail(f"cannot read materialized source {relative}: {error}")
            require(
                git_blob_oid(raw) == object_id,
                f"materialized source blob differs: {relative}",
            )
    missing = sorted(set(expected) - observed)
    require(not missing, f"materialized source files are missing: {missing[:8]}")


def materialize_source(
    source_commit: str, campaign_root: pathlib.Path
) -> tuple[pathlib.Path, dict[str, object], dict[str, tuple[str, str]]]:
    expected, record, export_inputs = expected_materialized_files(source_commit)
    source = campaign_root / "source"
    root_prefix, root_entries = export_inputs["."]
    export_git_tree(
        git_prefix=root_prefix,
        entries=root_entries,
        destination=source,
        label="superproject",
    )
    for path in sorted(EXPECTED_SUBMODULES):
        git_prefix, entries = export_inputs[path]
        export_git_tree(
            git_prefix=git_prefix,
            entries=entries,
            destination=source / path,
            label=f"submodule {path}",
        )
    verify_materialized_source(source, expected)
    return source, record, expected


def smoke_source_record(source_commit: str) -> dict[str, object]:
    _, record, _ = expected_materialized_files(source_commit)
    record.update(
        method="dirty-worktree-smoke-not-evidence",
        decision_eligible=False,
        ignored_worktree_inputs="not-excluded-smoke-only",
    )
    return record


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def locked_crates(
    lock_path: pathlib.Path,
    *,
    logical_path: str,
    expected_sha256: str,
    expected_bytes: int,
    expected_packages: int,
    expected_package_set_sha256: str,
) -> tuple[list[dict[str, str]], dict[str, object]]:
    try:
        metadata = lock_path.lstat()
        raw = lock_path.read_bytes()
        document = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse materialized Cargo.lock: {error}")
    require(
        stat.S_ISREG(metadata.st_mode)
        and not lock_path.is_symlink()
        and metadata.st_nlink == 1,
        "materialized Cargo.lock is not one regular file",
    )
    packages = document.get("package")
    require(type(packages) is list, "Cargo.lock package table differs")
    locked: list[dict[str, str]] = []
    observed: set[tuple[str, str]] = set()
    for package in packages:
        require(type(package) is dict, "Cargo.lock package entry is not an object")
        source = package.get("source")
        if source is None:
            require(
                package.get("checksum") is None,
                "path package unexpectedly carries a registry checksum",
            )
            continue
        require(source == CRATES_IO_SOURCE, f"Cargo.lock source is forbidden: {source}")
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        require(
            type(name) is str
            and type(version) is str
            and type(checksum) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", name) is not None
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", version) is not None
            and HEX64.fullmatch(checksum) is not None,
            "Cargo.lock registry identity is not canonical",
        )
        key = (name, version)
        require(key not in observed, f"Cargo.lock repeats registry package {key}")
        observed.add(key)
        locked.append({"name": name, "version": version, "checksum": checksum})
    locked.sort(key=lambda value: (value["name"], value["version"]))
    package_set = b"".join(
        (
            f"{package['name']}\0{package['version']}\0{package['checksum']}\n"
        ).encode("ascii")
        for package in locked
    )
    record = {
        "path": logical_path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "registry_source": CRATES_IO_SOURCE,
        "packages": len(locked),
        "package_set_sha256": hashlib.sha256(package_set).hexdigest(),
    }
    require(
        record
        == {
            "path": logical_path,
            "sha256": expected_sha256,
            "bytes": expected_bytes,
            "registry_source": CRATES_IO_SOURCE,
            "packages": expected_packages,
            "package_set_sha256": expected_package_set_sha256,
        },
        f"{logical_path} differs from the frozen C8.4 dependency set",
    )
    return locked, record


def locked_crate_union(
    source_root: pathlib.Path, rust_src: pathlib.Path
) -> tuple[list[dict[str, str]], dict[str, object], set[tuple[str, str, str]]]:
    project, project_record = locked_crates(
        source_root / "Cargo.lock",
        logical_path="Cargo.lock",
        expected_sha256=PINNED_CARGO_LOCK_SHA256,
        expected_bytes=PINNED_CARGO_LOCK_BYTES,
        expected_packages=PINNED_CARGO_PACKAGES,
        expected_package_set_sha256=PINNED_CARGO_PACKAGE_SET_SHA256,
    )
    rust, rust_record = locked_crates(
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
        require(
            previous == checksum,
            f"Cargo locks disagree on checksum for {name}-{version}",
        )
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
    require(
        union_record
        == {
            "packages": PINNED_CARGO_UNION_PACKAGES,
            "exact_overlap": PINNED_CARGO_UNION_EXACT_OVERLAP,
            "project_only": PINNED_CARGO_UNION_PROJECT_ONLY,
            "rust_src_only": PINNED_CARGO_UNION_RUST_SRC_ONLY,
            "package_set_sha256": PINNED_CARGO_UNION_PACKAGE_SET_SHA256,
        },
        "project and rust-src Cargo.lock union differs from the frozen contract",
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


def copy_verified_archive(source: pathlib.Path, destination: pathlib.Path, expected: str) -> int:
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_fd = os.open(source, read_flags)
        destination_fd = os.open(destination, write_flags, 0o400)
        try:
            before = os.fstat(source_fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_size > 0
                and before.st_size <= MAX_CRATE_ARCHIVE_BYTES,
                f"crate archive is not a bounded regular file: {source}",
            )
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    require(written > 0, "private crate archive copy made no progress")
                    view = view[written:]
            after = os.fstat(source_fd)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
            os.close(source_fd)
    except OSError as error:
        fail(f"cannot copy cached crate archive {source}: {error}")
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        and total == before.st_size,
        f"cached crate archive changed while copying: {source}",
    )
    require(digest.hexdigest() == expected, f"crate archive checksum differs: {source.name}")
    return total


def write_private_file(path: pathlib.Path, raw: bytes, mode: int) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                require(written > 0, f"private file write made no progress: {path}")
                view = view[written:]
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot create private file {path}: {error}")


def crate_member_relative(
    member: tarfile.TarInfo, package_name: str
) -> tuple[str, pathlib.PurePosixPath]:
    require(member.isfile(), f"crate archive has non-file member: {member.name}")
    prefix = package_name + "/"
    require(member.name.startswith(prefix), "crate archive root prefix differs")
    relative = member.name[len(prefix) :]
    return safe_crate_relative(relative, f"crate archive path {member.name}")


def safe_crate_relative(
    relative: str, label: str, *, allow_checksum: bool = False
) -> tuple[str, pathlib.PurePosixPath]:
    pure = pathlib.PurePosixPath(relative)
    require(
        relative
        and (allow_checksum or relative != ".cargo-checksum.json")
        and relative == pure.as_posix()
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "." not in pure.parts
        and "" not in pure.parts,
        f"{label} is unsafe",
    )
    require(
        not relative.endswith("/")
        and "\\" not in relative
        and "\x00" not in relative
        and all(
            ord(character) >= 0x20 and ord(character) != 0x7F
            for character in relative
        ),
        f"{label} spelling is unsafe",
    )
    return relative, pure


def read_stable_regular(path: pathlib.Path, label: str, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and 0 <= before.st_size <= limit,
                f"{label} is not one bounded regular file",
            )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit, f"{label} exceeds its byte limit")
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    require(
        (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        and total == before.st_size,
        f"{label} changed while being read",
    )
    return b"".join(chunks)


def direct_regular_tree_entries(
    root: pathlib.Path, label: str
) -> tuple[set[str], set[str]]:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    require(
        stat.S_ISDIR(root_metadata.st_mode) and not stat.S_ISLNK(root_metadata.st_mode),
        f"{label} root is not a direct directory",
    )
    files: set[str] = set()
    directories: set[str] = set()
    pending = [(root, pathlib.PurePosixPath())]
    while pending:
        directory, relative_root = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            fail(f"cannot enumerate {label}: {error}")
        for entry in entries:
            relative = (relative_root / entry.name).as_posix()
            _, pure = safe_crate_relative(
                relative, f"{label} path {relative}", allow_checksum=True
            )
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                fail(f"cannot inspect {label} path {relative}: {error}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append((pathlib.Path(entry.path), pure))
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                files.add(relative)
            else:
                fail(f"{label} contains a link, hard link, or special entry: {relative}")
    return files, directories


def copy_verified_rust_src_vendor(
    source: pathlib.Path,
    destination: pathlib.Path,
    package: dict[str, str],
) -> tuple[int, int]:
    package_name = f"{package['name']}-{package['version']}"
    checksum_path = source / ".cargo-checksum.json"
    checksum_raw = read_stable_regular(
        checksum_path,
        f"pinned rust-src vendor checksum for {package_name}",
        MAX_CRATE_CHECKSUM_BYTES,
    )
    try:
        decoded = BASE.strict_json_loads(
            checksum_raw.decode("utf-8", errors="strict"),
            f"pinned rust-src vendor checksum for {package_name}",
        )
    except UnicodeError as error:
        fail(f"pinned rust-src vendor checksum is not UTF-8: {error}")
    require(type(decoded) is dict, f"rust-src vendor checksum differs: {package_name}")
    require(
        set(decoded) == {"$comment", "files", "package"}
        and decoded.get("$comment") == RUST_SRC_VENDOR_CHECKSUM_COMMENT
        and decoded.get("package") == package["checksum"]
        and type(decoded.get("files")) is dict,
        f"rust-src vendor checksum contract differs: {package_name}",
    )
    raw_files = decoded["files"]
    assert type(raw_files) is dict
    checksums: dict[str, str] = {}
    expected_directories: set[str] = set()
    for relative, checksum in raw_files.items():
        require(
            type(relative) is str
            and type(checksum) is str
            and HEX64.fullmatch(checksum) is not None,
            f"rust-src vendor file checksum differs: {package_name}",
        )
        _, pure = safe_crate_relative(
            relative, f"rust-src vendor path {package_name}/{relative}"
        )
        require(relative not in checksums, f"rust-src vendor repeats {relative}")
        checksums[relative] = checksum
        parent = pure.parent
        while parent != pathlib.PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    observed_files, observed_directories = direct_regular_tree_entries(
        source, f"pinned rust-src vendor package {package_name}"
    )
    require(
        observed_files == set(checksums) | {".cargo-checksum.json"}
        and observed_directories == expected_directories,
        f"rust-src vendor package tree differs from its checksum inventory: {package_name}",
    )
    source_files = 0
    source_bytes = 0
    for relative, expected in sorted(checksums.items()):
        _, pure = safe_crate_relative(
            relative, f"rust-src vendor path {package_name}/{relative}"
        )
        raw = read_stable_regular(
            source.joinpath(*pure.parts),
            f"pinned rust-src vendor file {package_name}/{relative}",
            MAX_CRATE_SOURCE_BYTES,
        )
        require(
            hashlib.sha256(raw).hexdigest() == expected,
            f"rust-src vendor file checksum differs: {package_name}/{relative}",
        )
        installed = destination.joinpath(*pure.parts)
        installed.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source_mode = stat.S_IMODE(source.joinpath(*pure.parts).lstat().st_mode)
        write_private_file(installed, raw, 0o500 if source_mode & 0o100 else 0o400)
        source_files += 1
        source_bytes += len(raw)
    canonical_checksum = canonical_json_bytes(
        {"files": dict(sorted(checksums.items())), "package": package["checksum"]}
    )
    write_private_file(destination / ".cargo-checksum.json", canonical_checksum, 0o400)
    return source_files, source_bytes


def materialize_locked_crates(
    source_root: pathlib.Path, campaign_root: pathlib.Path
) -> tuple[pathlib.Path, dict[str, object]]:
    rust_src = BASE.canonical_direct_directory(PINNED_RUST_SRC, "pinned rust-src library")
    rust_src_materialization_before = BASE.strict_tree_identity(
        rust_src, "pinned rust-src library before crate materialization"
    )
    require(
        rust_src_materialization_before == PINNED_RUST_SRC_TREE,
        "pinned rust-src differs before crate materialization",
    )
    packages, cargo_locks, project_packages = locked_crate_union(source_root, rust_src)
    cache = PRIVATE_CARGO_CACHE / "registry/cache"
    try:
        cache_roots = sorted(
            (entry for entry in cache.iterdir() if entry.is_dir()), key=lambda path: path.name
        )
    except OSError as error:
        fail(f"cannot inspect fixed launcher Cargo cache: {error}")
    require(cache_roots, "fixed launcher Cargo cache has no registry cache roots")
    archives = campaign_root / "crate-archives"
    vendor = campaign_root / "private-crate-sources"
    archives.mkdir(mode=0o700)
    vendor.mkdir(mode=0o700)
    archive_bytes = 0
    source_bytes = 0
    source_files = 0
    archive_number = 0
    rust_src_vendor_count = 0
    for package in packages:
        package_name = f"{package['name']}-{package['version']}"
        package_root = vendor / package_name
        package_root.mkdir(mode=0o700)
        identity = (package["name"], package["version"], package["checksum"])
        if identity not in project_packages:
            rust_src_vendor_count += 1
            copied_files, copied_bytes = copy_verified_rust_src_vendor(
                rust_src / "vendor" / package_name,
                package_root,
                package,
            )
            source_files += copied_files
            source_bytes += copied_bytes
            require(source_files <= MAX_CRATE_FILES, "too many private crate files")
            require(
                source_bytes <= MAX_CRATE_SOURCE_BYTES,
                "private crate source bytes exceed contract",
            )
            continue
        candidates = [root / f"{package_name}.crate" for root in cache_roots]
        candidates = [path for path in candidates if os.path.lexists(path)]
        require(len(candidates) == 1, f"crate archive is missing or ambiguous: {package_name}")
        archive = archives / f"{archive_number:04d}.crate"
        archive_number += 1
        archive_bytes += copy_verified_archive(candidates[0], archive, package["checksum"])
        checksums: dict[str, str] = {}
        try:
            with tarfile.open(archive, mode="r:gz", encoding="utf-8", errors="strict") as bundle:
                members = bundle.getmembers()
                for member in members:
                    relative, pure = crate_member_relative(member, package_name)
                    require(relative not in checksums, f"crate archive repeats {relative}")
                    extracted = bundle.extractfile(member)
                    require(extracted is not None, f"cannot read crate member {relative}")
                    chunks: list[bytes] = []
                    total = 0
                    while True:
                        chunk = extracted.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        source_bytes += len(chunk)
                        require(
                            source_bytes <= MAX_CRATE_SOURCE_BYTES,
                            "private crate source bytes exceed contract",
                        )
                        chunks.append(chunk)
                    require(total == member.size, f"crate member length differs: {relative}")
                    raw = b"".join(chunks)
                    checksums[relative] = hashlib.sha256(raw).hexdigest()
                    destination = package_root.joinpath(*pure.parts)
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    mode = 0o500 if member.mode & 0o111 else 0o400
                    write_private_file(destination, raw, mode)
                    source_files += 1
                    require(source_files <= MAX_CRATE_FILES, "too many private crate files")
        except (OSError, tarfile.TarError, UnicodeError) as error:
            fail(f"cannot safely extract {package_name}: {error}")
        checksum_raw = canonical_json_bytes(
            {"files": dict(sorted(checksums.items())), "package": package["checksum"]}
        )
        write_private_file(package_root / ".cargo-checksum.json", checksum_raw, 0o400)
    for directory, directory_names, _ in os.walk(vendor, topdown=False, followlinks=False):
        for name in directory_names:
            (pathlib.Path(directory) / name).chmod(0o500)
    vendor.chmod(0o500)
    rust_src_materialization_after = BASE.strict_tree_identity(
        rust_src, "pinned rust-src library after crate materialization"
    )
    require(
        rust_src_materialization_after == rust_src_materialization_before,
        "pinned rust-src changed during crate materialization",
    )
    tree = BASE.strict_tree_identity(vendor, "private Cargo registry sources")
    require(tree == PINNED_PRIVATE_CRATE_TREE, "private Cargo source tree differs")
    record = {
        "cargo_locks": cargo_locks,
        "method": "verified-project-lock-archives-plus-rust-src-vendor-union-v1",
        "archive_source": "fixed-launcher-cargo-home-registry-cache",
        "rust_src_vendor_source": "pinned-rust-src-library-vendor",
        "archive_count": archive_number,
        "rust_src_vendor_count": rust_src_vendor_count,
        "archive_bytes": archive_bytes,
        "source_files": source_files,
        "source_bytes": source_bytes,
        "mode_policy": "directories-0500-files-0400-preserve-owner-execute-0500-v1",
        "checksum_file_policy": "canonical-cargo-directory-source-json-v1",
        "rust_src_materialization_before": rust_src_materialization_before,
        "rust_src_materialization_after": rust_src_materialization_after,
        "tree": tree,
    }
    require(archive_bytes == 23_706_909, "private crate archive byte count differs")
    require(archive_number == PINNED_CARGO_PACKAGES, "private crate archive count differs")
    require(
        rust_src_vendor_count == PINNED_CARGO_UNION_RUST_SRC_ONLY,
        "rust-src vendor package count differs",
    )
    require(source_files == 11_391, "private crate source file count differs")
    require(source_bytes == 137_564_030, "private crate source byte count differs")
    return vendor, record


def run_otool(arguments: list[str], label: str) -> str:
    environment = {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    try:
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
    except (OSError, UnicodeError) as error:
        fail(f"cannot inspect {label} Mach-O: {error}")
    require(completed.returncode == 0 and not completed.stderr, f"otool failed for {label}")
    return completed.stdout


def macho_metadata(path: pathlib.Path) -> tuple[list[str], list[str]]:
    dependencies_output = run_otool(["-L", str(path)], str(path))
    lines = dependencies_output.splitlines()
    require(len(lines) >= 2 and lines[0] == f"{path}:", "otool dependency header differs")
    dependencies: list[str] = []
    for line in lines[1:]:
        match = re.fullmatch(r"\t(.+) \(compatibility version .+\)", line)
        require(match is not None, f"otool dependency line differs: {line}")
        dependencies.append(match.group(1))
    load_output = run_otool(["-l", str(path)], str(path))
    load_lines = load_output.splitlines()
    rpaths: list[str] = []
    for index, line in enumerate(load_lines):
        if line.strip() != "cmd LC_RPATH":
            continue
        require(index + 2 < len(load_lines), "truncated LC_RPATH command")
        match = re.fullmatch(r"\s*path (.+) \(offset [0-9]+\)", load_lines[index + 2])
        require(match is not None, "LC_RPATH path differs")
        rpaths.append(match.group(1))
    return dependencies, rpaths


def symlink_chain(path: pathlib.Path) -> tuple[pathlib.Path, list[dict[str, str]]]:
    require(path.is_absolute(), f"Mach-O dependency path is not absolute: {path}")
    pending = list(path.parts[1:])
    current = pathlib.Path("/")
    records: list[dict[str, str]] = []
    hops = 0
    while pending:
        current = current / pending.pop(0)
        try:
            metadata = current.lstat()
        except OSError as error:
            fail(f"cannot resolve Mach-O dependency path {current}: {error}")
        if not stat.S_ISLNK(metadata.st_mode):
            continue
        hops += 1
        require(hops <= 32, "Mach-O dependency has too many symlinks")
        target = os.readlink(current)
        records.append({"path": str(current), "target": target})
        replacement = pathlib.Path(target)
        if not replacement.is_absolute():
            replacement = current.parent / replacement
        replacement = pathlib.Path(os.path.normpath(replacement))
        pending = [*replacement.parts[1:], *pending]
        current = pathlib.Path("/")
    return current, records


def otool_custody_record() -> dict[str, object]:
    resolved, links = symlink_chain(PINNED_OTOOL_INVOCATION)
    resolved = resolved.resolve(strict=True)
    require(resolved == PINNED_OTOOL_RESOLVED, "direct CLT otool resolution differs")
    identity = stable_runtime_file_identity(resolved)
    require(
        identity == {"sha256": PINNED_OTOOL_SHA256, "bytes": PINNED_OTOOL_BYTES},
        "direct CLT llvm-otool identity differs",
    )
    environment = {
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }
    try:
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
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        fail(f"cannot identify Command Line Tools package: {error}")
    require(
        completed.returncode == 0 and not completed.stderr,
        "Command Line Tools package query failed",
    )
    fields: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition(": ")
        require(separator == ": " and key not in fields, "CLT package output differs")
        fields[key] = value
    require(
        fields.get("package-id") == PINNED_CLT_PACKAGE_ID
        and fields.get("version") == PINNED_CLT_VERSION
        and fields.get("volume") == "/"
        and fields.get("location") == "/",
        "Command Line Tools package identity differs",
    )
    return {
        "policy": OTOOL_CUSTODY_POLICY,
        "invocation_path": str(PINNED_OTOOL_INVOCATION),
        "resolved_path": str(resolved),
        "symlinks": links,
        **identity,
        "package_id": PINNED_CLT_PACKAGE_ID,
        "package_version": PINNED_CLT_VERSION,
    }


def expand_macho_anchor(value: str, *, loader: pathlib.Path, executable: pathlib.Path) -> pathlib.Path:
    if value == "@loader_path":
        return loader.parent
    if value.startswith("@loader_path/"):
        return loader.parent / value[len("@loader_path/") :]
    if value == "@executable_path":
        return executable.parent
    if value.startswith("@executable_path/"):
        return executable.parent / value[len("@executable_path/") :]
    path = pathlib.Path(value)
    require(path.is_absolute(), f"unsupported Mach-O path anchor: {value}")
    return path


def linker_runtime_closure(invocation: pathlib.Path) -> dict[str, object]:
    executable, invocation_links = symlink_chain(invocation)
    require(executable.is_file(), "resolved ld.lld is not a regular file")
    pending = [executable]
    nodes: dict[str, dict[str, object]] = {}
    symlinks: dict[str, str] = {item["path"]: item["target"] for item in invocation_links}
    executable_dependencies, executable_rpaths = macho_metadata(executable)
    metadata_cache = {str(executable): (executable_dependencies, executable_rpaths)}
    while pending:
        current = pending.pop(0).resolve(strict=True)
        if str(current) in nodes:
            continue
        dependencies, rpaths = metadata_cache.get(str(current), macho_metadata(current))
        edges: list[dict[str, object]] = []
        for install_name in dependencies:
            if install_name.startswith("/usr/lib/") or install_name.startswith(
                "/System/Library/"
            ):
                edges.append({"install_name": install_name, "class": "sealed-system"})
                continue
            candidates: list[pathlib.Path]
            if install_name.startswith("@rpath/"):
                suffix = install_name[len("@rpath/") :]
                search = [*rpaths, *executable_rpaths]
                candidates = []
                for rpath in search:
                    base = expand_macho_anchor(
                        rpath, loader=current, executable=executable
                    )
                    candidate = pathlib.Path(os.path.normpath(base / suffix))
                    if os.path.lexists(candidate):
                        candidates.append(candidate)
                unique = {str(candidate): candidate for candidate in candidates}
                require(len(unique) == 1, f"Mach-O @rpath is missing or ambiguous: {install_name}")
                lexical = next(iter(unique.values()))
            elif install_name.startswith("@loader_path") or install_name.startswith(
                "@executable_path"
            ):
                lexical = pathlib.Path(
                    os.path.normpath(
                        expand_macho_anchor(
                            install_name, loader=current, executable=executable
                        )
                    )
                )
            else:
                lexical = pathlib.Path(install_name)
                require(lexical.is_absolute(), f"relative Mach-O dependency: {install_name}")
            resolved, links = symlink_chain(lexical)
            for link in links:
                prior = symlinks.get(link["path"])
                require(prior in (None, link["target"]), "Mach-O symlink target conflicts")
                symlinks[link["path"]] = link["target"]
            resolved = resolved.resolve(strict=True)
            require(
                str(resolved).startswith("/opt/homebrew/Cellar/"),
                f"non-system Mach-O dependency escapes pinned Homebrew Cellar: {resolved}",
            )
            record = {
                "install_name": install_name,
                "class": "pinned-homebrew",
                "resolved_path": str(resolved),
            }
            edges.append(record)
            if resolved != current and str(resolved) not in nodes:
                pending.append(resolved)
        nodes[str(current)] = {
            "path": str(current),
            **identity_only(current),
            "rpaths": rpaths,
            "dependencies": edges,
        }
    core = {
        "policy": "darwin-recursive-nonsystem-macho-closure-v1",
        "otool": str(PINNED_OTOOL_INVOCATION),
        "otool_custody": otool_custody_record(),
        "system_policy": "darwin-sealed-system-volume",
        "invocation_path": str(invocation),
        "resolved_path": str(executable),
        "symlinks": [
            {"path": path, "target": target} for path, target in sorted(symlinks.items())
        ],
        "nodes": [nodes[path] for path in sorted(nodes)],
    }
    return {**core, "sha256": hashlib.sha256(canonical_json_bytes(core)).hexdigest()}


def qemu_runtime_closure(invocation: pathlib.Path) -> dict[str, object]:
    executable, invocation_links = symlink_chain(invocation)
    require(executable.is_file(), "resolved QEMU is not a regular file")
    pending = [executable]
    nodes: dict[str, dict[str, object]] = {}
    symlinks: dict[str, str] = {
        item["path"]: item["target"] for item in invocation_links
    }
    executable_dependencies, executable_rpaths = macho_metadata(executable)
    metadata_cache = {str(executable): (executable_dependencies, executable_rpaths)}
    while pending:
        current = pending.pop(0).resolve(strict=True)
        if str(current) in nodes:
            continue
        dependencies, rpaths = metadata_cache.get(str(current), macho_metadata(current))
        edges: list[dict[str, object]] = []
        for install_name in dependencies:
            if any(
                install_name.startswith(prefix)
                for prefix in QEMU_RUNTIME_SYSTEM_PREFIXES
            ):
                edges.append({"install_name": install_name, "class": "sealed-system"})
                continue
            candidates: list[pathlib.Path]
            if install_name.startswith("@rpath/"):
                suffix = install_name[len("@rpath/") :]
                candidates = []
                for rpath in [*rpaths, *executable_rpaths]:
                    base = expand_macho_anchor(
                        rpath, loader=current, executable=executable
                    )
                    candidate = pathlib.Path(os.path.normpath(base / suffix))
                    if os.path.lexists(candidate):
                        candidates.append(candidate)
                unique = {str(candidate): candidate for candidate in candidates}
                require(
                    len(unique) == 1,
                    f"QEMU Mach-O @rpath is missing or ambiguous: {install_name}",
                )
                lexical = next(iter(unique.values()))
            elif install_name.startswith("@loader_path") or install_name.startswith(
                "@executable_path"
            ):
                lexical = pathlib.Path(
                    os.path.normpath(
                        expand_macho_anchor(
                            install_name, loader=current, executable=executable
                        )
                    )
                )
            else:
                lexical = pathlib.Path(install_name)
                require(
                    lexical.is_absolute(),
                    f"relative QEMU Mach-O dependency: {install_name}",
                )
            resolved, links = symlink_chain(lexical)
            for link in links:
                prior = symlinks.get(link["path"])
                require(
                    prior in (None, link["target"]),
                    "QEMU Mach-O symlink target conflicts",
                )
                symlinks[link["path"]] = link["target"]
            resolved = resolved.resolve(strict=True)
            require(
                str(resolved).startswith("/opt/homebrew/Cellar/"),
                f"non-system QEMU dependency escapes Homebrew Cellar: {resolved}",
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
            **stable_runtime_file_identity(current),
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
        canonical_json_bytes({"nodes": normalized_nodes})
    ).hexdigest()
    edge_classes = [
        edge["class"] for node in nodes.values() for edge in node["dependencies"]
    ]
    core = {
        "policy": QEMU_RUNTIME_CLOSURE_POLICY,
        "otool": str(PINNED_OTOOL_INVOCATION),
        "otool_custody": otool_custody_record(),
        "system_policy": "darwin-sealed-system-volume",
        "system_dependency_prefixes": list(QEMU_RUNTIME_SYSTEM_PREFIXES),
        "system_volume": darwin_root_volume_record(),
        "system_build": darwin_host_build_record(),
        "host_exclusivity_limit": QEMU_RUNTIME_HOST_LIMIT,
        "invocation_path": str(invocation),
        "resolved_path": str(executable),
        "symlinks": [
            {"path": path, "target": target} for path, target in sorted(symlinks.items())
        ],
        "nodes": [nodes[path] for path in sorted(nodes)],
        "node_count": len(nodes),
        "load_edge_count": len(edge_classes),
        "pinned_homebrew_edge_count": edge_classes.count("pinned-homebrew"),
        "sealed_system_edge_count": edge_classes.count("sealed-system"),
        "graph_sha256": graph_sha256,
    }
    return {**core, "sha256": hashlib.sha256(canonical_json_bytes(core)).hexdigest()}


def qemu_module_search_record(
    qemu: pathlib.Path,
    *,
    qemu_environment: dict[str, str],
    qemu_argv: tuple[str, ...],
    data_directory: pathlib.Path,
) -> dict[str, object]:
    validate_qemu_environment(qemu_environment)
    require(
        qemu.resolve(strict=True).parent.parent == PINNED_QEMU_PREFIX,
        "QEMU installation prefix differs",
    )
    require(
        "QEMU_MODULE_DIR" not in qemu_environment,
        "QEMU module search environment override is present",
    )
    require(
        "-plugin" not in qemu_argv
        and all(not item.startswith("-plugin=") for item in qemu_argv),
        "QEMU plugin loading is enabled by argv",
    )
    require(
        qemu_argv.count("-no-user-config") == 1
        and qemu_argv.count("-L") == 1
        and qemu_argv[qemu_argv.index("-L") + 1] == str(data_directory),
        "QEMU user configuration/data search argv differs",
    )
    data_status = data_directory.lstat()
    require(
        stat.S_ISDIR(data_status.st_mode)
        and not data_directory.is_symlink()
        and data_status.st_uid == os.getuid()
        and stat.S_IMODE(data_status.st_mode) == QEMU_DATA_DIRECTORY_MODE
        and not tuple(data_directory.iterdir()),
        "QEMU private data directory differs",
    )
    candidates = [
        PINNED_QEMU_PREFIX / "lib/qemu",
        pathlib.Path("/opt/homebrew/lib/qemu"),
        PINNED_QEMU_PREFIX / "qemu-bundle",
        PINNED_QEMU_PREFIX / "libexec/qemu",
    ]
    require(
        all(not os.path.lexists(path) for path in candidates),
        "a QEMU module search directory is present",
    )
    return {
        "policy": "no-plugin-argv-and-absent-qemu-module-directories-v1",
        "qemu_prefix": str(PINNED_QEMU_PREFIX),
        "environment_override": "QEMU_MODULE_DIR",
        "environment_override_absent": True,
        "plugin_argv_absent": True,
        "user_config_disabled": True,
        "data_directory": {
            "path": str(data_directory),
            "mode": f"{QEMU_DATA_DIRECTORY_MODE:04o}",
            "empty": True,
        },
        "candidate_directories": [
            {"path": str(path), "absent": True} for path in candidates
        ],
        "scope_limit": (
            "closes QEMU module/plugin search; generic library-internal dlopen is not "
            "claimed beyond the recursive Mach-O load-command graph"
        ),
    }


def build_kernel(
    source_commit: str,
    challenge: str,
    feature: str,
    *,
    source_root: pathlib.Path,
    cargo_target_dir: pathlib.Path,
    kernel: pathlib.Path,
    commit_timestamp: str,
    private_cargo_home: pathlib.Path,
    private_cargo_sources: pathlib.Path,
    private_crate_archives: pathlib.Path,
    private_cargo_record: dict[str, object],
) -> dict[str, object]:
    # The C8.3 runner owns the reviewed offline/pinned/sanitized Cargo build
    # implementation.  Its globals are switched only inside this private
    # module instance so the C8.4 image gets the dedicated feature and binding.
    original = (BASE.FEATURE, BASE.SOURCE_ENV, BASE.CHALLENGE_ENV)
    require(
        feature in (FORMAL_FEATURE, SMOKE_FEATURE),
        "C8.4 build feature is not mode-bound",
    )
    BASE.FEATURE = feature
    BASE.SOURCE_ENV = SOURCE_ENV
    BASE.CHALLENGE_ENV = CHALLENGE_ENV
    print(f"C8.4 QEMU decision: building dedicated {feature} image", file=sys.stderr)
    try:
        source_root = BASE.canonical_direct_directory(source_root, "build source root")
        cargo_target_dir = BASE.canonical_direct_directory(
            cargo_target_dir, "private Cargo target"
        )
        private_cargo_home = BASE.canonical_direct_directory(
            private_cargo_home, "private Cargo home"
        )
        private_cargo_sources = BASE.canonical_direct_directory(
            private_cargo_sources, "private crate sources"
        )
        private_crate_archives = BASE.canonical_direct_directory(
            private_crate_archives, "private crate archives"
        )
        require(
            BASE.strict_tree_identity(
                private_crate_archives, "private crate archives"
            )
            == PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
            "private crate archive tree differs before the formal build",
        )
        kernel = pathlib.Path(os.path.abspath(os.fspath(kernel))).resolve(strict=False)
        require(
            BASE.strict_tree_identity(PINNED_TOOLCHAIN_ROOT, "pinned Rust toolchain")
            == PINNED_TOOLCHAIN_TREE,
            "pinned Rust toolchain differs before build-tool discovery",
        )
        require(
            BASE.strict_tree_identity(PINNED_RUST_SRC, "pinned rust-src library")
            == PINNED_RUST_SRC_TREE,
            "pinned rust-src differs before build-tool discovery",
        )
        try:
            linker = BASE.resolve_linker()
        except BASE.RunnerError as error:
            fail(str(error))
        linker_before = linker_runtime_closure(
            pathlib.Path(str(linker["invocation_path"]))
        )
        require(
            linker_before["sha256"] == PINNED_LLD_RUNTIME_SHA256,
            "ld.lld dynamic runtime differs from the frozen contract",
        )
        with contextlib.redirect_stderr(io.StringIO()):
            toolchain = BASE.build_kernel(
                source_commit,
                challenge,
                firmware=source_root / "firmware/qemu-virt",
                toolchain_file=source_root / "rust-toolchain.toml",
                cargo_target_dir=cargo_target_dir,
                kernel_path=kernel,
                commit_timestamp=commit_timestamp,
                private_cargo_home=private_cargo_home,
                private_cargo_sources=private_cargo_sources,
                private_crate_archives=private_crate_archives,
                private_cargo_record=private_cargo_record,
                expected_toolchain_tree=PINNED_TOOLCHAIN_TREE,
                expected_rust_src=PINNED_RUST_SRC_TREE,
                formal_rustup_home=PINNED_RUSTUP_HOME,
                formal_host_triple=PINNED_RUST_HOST_TRIPLE,
                formal_rustup_path=PINNED_RUSTUP,
            )
        require(toolchain["linker"] == linker, "build selected a different ld.lld")
        expected_bin = PINNED_TOOLCHAIN_ROOT / "bin"
        for name in ("cargo", "rustc", "rustdoc"):
            require(
                pathlib.Path(str(toolchain[name]["path"])) == expected_bin / name,
                f"build selected an unbound {name}",
            )
        build_environment = toolchain.get("build_environment_policy")
        require(type(build_environment) is dict, "build environment policy differs")
        require(
            build_environment.get("path_entries")
            == ["/opt/homebrew/bin", "/usr/bin", "/bin"],
            "formal build PATH differs",
        )
        normalized_values = build_environment.get("normalized_values")
        require(type(normalized_values) is dict, "normalized build environment differs")
        require(
            normalized_values.get("SOURCE_DATE_EPOCH") == commit_timestamp,
            "SOURCE_DATE_EPOCH differs from the attested commit timestamp",
        )
        command = toolchain.get("cargo_command")
        require(type(command) is list and len(command) > 3, "Cargo command differs")
        require(
            command[3]
            == "<materialized-source>/firmware/qemu-virt/Cargo.toml",
            "base Cargo source provenance differs",
        )
        command[3] = (
            "<materialized-source>/firmware/qemu-virt/Cargo.toml"
            if feature == FORMAL_FEATURE
            else "<dirty-worktree>/firmware/qemu-virt/Cargo.toml"
        )
        linker_after = linker_runtime_closure(
            pathlib.Path(str(linker["invocation_path"]))
        )
        require(linker_after == linker_before, "ld.lld runtime changed during build")
        closure = toolchain.get("build_input_closure")
        require(type(closure) is dict, "formal Cargo build omitted its input closure")
        normalized_paths = closure.get("normalized_paths")
        require(type(normalized_paths) is dict, "normalized build paths differ")
        require(
            normalized_paths.get("private_crate_archives")
            == str(private_crate_archives),
            "base Cargo archive provenance differs",
        )
        require(
            closure.get("private_crate_archives")
            == {
                "root": str(private_crate_archives),
                "before": PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
                "after": PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
            },
            "private crate archive closure differs",
        )
        closure["linker_runtime"] = {
            "before": linker_before,
            "after": linker_after,
        }
        return toolchain
    except BASE.RunnerError as error:
        fail(str(error))
    finally:
        BASE.FEATURE, BASE.SOURCE_ENV, BASE.CHALLENGE_ENV = original


def resolve_qemu(name: str) -> str:
    try:
        return BASE.resolve_qemu(name)
    except BASE.RunnerError as error:
        fail(str(error))


def resolve_bios(
    qemu: str, *, qemu_environment: dict[str, str]
) -> pathlib.Path:
    require(pathlib.Path(qemu).is_absolute(), "QEMU firmware probe path is not absolute")
    validate_qemu_environment(qemu_environment)
    try:
        completed = subprocess.run(
            [qemu, "-no-user-config", "-L", "help"],
            cwd=pathlib.Path("/"),
            env=qemu_environment,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"cannot query QEMU firmware search path: {error}")
    require(
        completed.returncode == 0 and not completed.stderr.strip(),
        "QEMU firmware search probe failed",
    )
    validate_qemu_environment(qemu_environment)
    candidates: set[pathlib.Path] = set()
    for line in completed.stdout.splitlines():
        directory = pathlib.Path(line.strip())
        if directory.is_absolute():
            candidate = directory / QEMU_BIOS_NAME
            if candidate.is_file():
                candidates.add(candidate.resolve(strict=True))
    rendered = ", ".join(str(path) for path in sorted(candidates)) or "none"
    require(
        len(candidates) == 1,
        f"QEMU firmware search must resolve exactly one {QEMU_BIOS_NAME}; found {rendered}",
    )
    return next(iter(candidates))


def qemu_environment_record() -> dict[str, object]:
    return {
        "policy": QEMU_ENVIRONMENT_POLICY,
        "applies_to": list(QEMU_ENVIRONMENT_APPLIES_TO),
        "private_directory_mode": f"{QEMU_ENVIRONMENT_DIRECTORY_MODE:04o}",
        "private_directories_must_remain_empty": True,
        "allowed_names": list(QEMU_ENVIRONMENT_ALLOWED_NAMES),
        "normalized_values": dict(QEMU_ENVIRONMENT_NORMALIZED_VALUES),
        "live_data_directory": {
            "path": "<campaign-root>/qemu-environment/data",
            "mode": f"{QEMU_DATA_DIRECTORY_MODE:04o}",
            "must_remain_empty": True,
        },
    }


def validate_qemu_environment(environment: dict[str, str]) -> None:
    require(type(environment) is dict, "QEMU environment must be an exact object")
    require(
        all(
            type(name) is str and type(value) is str
            for name, value in environment.items()
        ),
        "QEMU environment names and values must be strings",
    )
    require(
        tuple(sorted(environment)) == QEMU_ENVIRONMENT_ALLOWED_NAMES,
        "QEMU environment allowlist differs",
    )
    require(environment["LANG"] == "C", "QEMU LANG differs")
    require(environment["LC_ALL"] == "C", "QEMU LC_ALL differs")
    require(environment["PATH"] == QEMU_ENVIRONMENT_PATH, "QEMU PATH differs")
    require(environment["TZ"] == "UTC", "QEMU TZ differs")

    private_root = pathlib.Path(environment["HOME"]).parent
    expected_paths = {
        "HOME": private_root / "home",
        "TMPDIR": private_root / "tmp",
        "XDG_CONFIG_HOME": private_root / "xdg-config",
    }
    require(
        private_root.is_absolute() and private_root.name == "qemu-environment",
        "QEMU private environment root differs",
    )
    for name, path in expected_paths.items():
        require(environment[name] == str(path), f"QEMU {name} path differs")
    for label, path in (("root", private_root), *expected_paths.items()):
        try:
            status = path.lstat()
        except OSError as error:
            fail(f"cannot inspect QEMU private environment {label}: {error}")
        require(
            stat.S_ISDIR(status.st_mode) and not path.is_symlink(),
            f"QEMU private environment {label} is not a directory",
        )
        require(
            status.st_uid == os.getuid(),
            f"QEMU private environment {label} owner differs",
        )
        require(
            stat.S_IMODE(status.st_mode) == QEMU_ENVIRONMENT_DIRECTORY_MODE,
            f"QEMU private environment {label} mode differs",
        )
        if label != "root":
            require(
                not tuple(path.iterdir()),
                f"QEMU private environment {label} is not empty",
            )
    data_directory = private_root / "data"
    try:
        data_status = data_directory.lstat()
    except OSError as error:
        fail(f"cannot inspect private QEMU data directory: {error}")
    require(
        stat.S_ISDIR(data_status.st_mode)
        and not data_directory.is_symlink()
        and data_status.st_uid == os.getuid()
        and stat.S_IMODE(data_status.st_mode) == QEMU_DATA_DIRECTORY_MODE
        and not tuple(data_directory.iterdir()),
        "private QEMU data directory differs",
    )


def normalized_qemu_environment(environment: dict[str, str]) -> dict[str, object]:
    validate_qemu_environment(environment)
    return qemu_environment_record()


def create_qemu_environment(
    campaign_root: pathlib.Path,
) -> tuple[dict[str, str], dict[str, object]]:
    try:
        resolved_campaign = campaign_root.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve QEMU campaign root: {error}")
    require(resolved_campaign.is_dir(), "QEMU campaign root is not a directory")
    private_root = resolved_campaign / "qemu-environment"
    paths = {
        "HOME": private_root / "home",
        "TMPDIR": private_root / "tmp",
        "XDG_CONFIG_HOME": private_root / "xdg-config",
    }
    try:
        private_root.mkdir(mode=QEMU_ENVIRONMENT_DIRECTORY_MODE)
        private_root.chmod(QEMU_ENVIRONMENT_DIRECTORY_MODE)
        for path in paths.values():
            path.mkdir(mode=QEMU_ENVIRONMENT_DIRECTORY_MODE)
            path.chmod(QEMU_ENVIRONMENT_DIRECTORY_MODE)
        data_directory = private_root / "data"
        data_directory.mkdir(mode=QEMU_DATA_DIRECTORY_MODE)
        data_directory.chmod(QEMU_DATA_DIRECTORY_MODE)
    except OSError as error:
        fail(f"cannot create private QEMU environment: {error}")
    environment = {
        "HOME": str(paths["HOME"]),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": QEMU_ENVIRONMENT_PATH,
        "TMPDIR": str(paths["TMPDIR"]),
        "TZ": "UTC",
        "XDG_CONFIG_HOME": str(paths["XDG_CONFIG_HOME"]),
    }
    record = normalized_qemu_environment(environment)
    require(
        all(not tuple(path.iterdir()) for path in paths.values()),
        "private QEMU environment did not begin empty",
    )
    return environment, record


def run_qemu_version(
    qemu: str, *, qemu_environment: dict[str, str]
) -> str:
    require(pathlib.Path(qemu).is_absolute(), "QEMU version path is not absolute")
    validate_qemu_environment(qemu_environment)
    try:
        completed = subprocess.run(
            [qemu, "-no-user-config", "--version"],
            cwd=pathlib.Path("/"),
            env=qemu_environment,
            stdin=subprocess.DEVNULL,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"cannot identify QEMU: {error}")
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output:
        detail = (completed.stderr or output).strip()
        fail(f"cannot identify QEMU: {detail or f'exit {completed.returncode}'}")
    validate_qemu_environment(qemu_environment)
    return output


def qemu_command(
    qemu: str,
    bios: pathlib.Path,
    kernel: pathlib.Path,
    data_directory: pathlib.Path,
    host_port: int,
) -> tuple[str, ...]:
    if not 1 <= host_port <= 65535:
        fail("SSH host-forward port is outside 1..65535")
    return (
        qemu,
        "-no-user-config",
        "-L",
        str(data_directory),
        "-machine",
        QEMU_MACHINE,
        "-cpu",
        QEMU_CPU,
        "-smp",
        QEMU_SMP,
        "-m",
        QEMU_MEMORY,
        "-accel",
        QEMU_ACCELERATOR,
        "-icount",
        QEMU_ICOUNT,
        "-nographic",
        "-bios",
        str(bios),
        "-kernel",
        str(kernel),
        "-object",
        f"rng-random,id={QEMU_RNG_ID},filename=/dev/urandom",
        "-device",
        f"virtio-rng-device,rng={QEMU_RNG_ID},bus=virtio-mmio-bus.1",
        "-netdev",
        (
            f"user,id={QEMU_NET_ID},net=10.0.2.0/24,host=10.0.2.2,"
            "restrict=on,ipv6=off,"
            f"hostfwd=tcp:127.0.0.1:{host_port}-10.0.2.15:2222"
        ),
        "-device",
        (
            f"virtio-net-device,netdev={QEMU_NET_ID},bus=virtio-mmio-bus.0,"
            "mac=02:00:00:00:00:01"
        ),
        "-global",
        "virtio-mmio.force-legacy=false",
    )


def normalize_qemu_command(
    command: tuple[str, ...],
    *,
    qemu: str,
    bios: pathlib.Path,
    kernel: pathlib.Path,
    data_directory: pathlib.Path,
    host_port: int,
) -> list[str]:
    require(
        command == qemu_command(qemu, bios, kernel, data_directory, host_port),
        "actual QEMU argv differs from the fixed command constructor",
    )
    normalized = list(command)
    require(normalized[0] == qemu, "actual QEMU executable differs")
    normalized[0] = "qemu-system-riscv64"
    data_index = normalized.index("-L") + 1
    bios_index = normalized.index("-bios") + 1
    kernel_index = normalized.index("-kernel") + 1
    require(normalized[bios_index] == str(bios), "actual QEMU BIOS path differs")
    require(normalized[kernel_index] == str(kernel), "actual QEMU kernel path differs")
    require(
        normalized[data_index] == str(data_directory),
        "actual QEMU data directory differs",
    )
    normalized[data_index] = "<qemu-data>"
    normalized[bios_index] = "<opensbi>"
    normalized[kernel_index] = "<kernel>"
    port_fragment = f"hostfwd=tcp:127.0.0.1:{host_port}-10.0.2.15:2222"
    matches = [index for index, item in enumerate(normalized) if port_fragment in item]
    require(len(matches) == 1, "actual QEMU host-forward port binding differs")
    normalized[matches[0]] = normalized[matches[0]].replace(
        port_fragment, "hostfwd=tcp:127.0.0.1:<host-port>-10.0.2.15:2222"
    )
    return normalized


def semantic_qemu_command(host_port: int) -> list[str]:
    command = qemu_command(
        "qemu-system-riscv64",
        pathlib.Path("<opensbi>"),
        pathlib.Path("<kernel>"),
        pathlib.Path("<qemu-data>"),
        host_port,
    )
    return normalize_qemu_command(
        command,
        qemu="qemu-system-riscv64",
        bios=pathlib.Path("<opensbi>"),
        kernel=pathlib.Path("<kernel>"),
        data_directory=pathlib.Path("<qemu-data>"),
        host_port=host_port,
    )


def pick_loopback_port() -> int:
    output = BASE.run_text(
        [*PINNED_PYTHON_ARGV_PREFIX, str(PORT_HELPER), "--pick-port"]
    )
    try:
        port = int(output, 10)
    except ValueError:
        fail(f"OpenSSH port helper returned a non-integer: {output!r}")
    if not 1 <= port <= 65535:
        fail(f"OpenSSH port helper returned an invalid port: {port}")
    return port


def generate_key(fixture: str, comment: str, destination: pathlib.Path) -> None:
    try:
        BASE.run_text(
            [
                *PINNED_PYTHON_ARGV_PREFIX,
                str(KEY_FIXTURE),
                "--fixture",
                fixture,
                "--comment",
                comment,
                "--output",
                str(destination),
            ]
        )
    except BASE.RunnerError as error:
        fail(str(error))
    if not destination.is_file() or destination.stat().st_size == 0:
        fail(f"OpenSSH {fixture} key fixture was not created")


def uart_tail(path: pathlib.Path, lines: int = 160) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    return "\n".join(
        raw.decode("utf-8", errors="replace").replace("\r", "\n").splitlines()[-lines:]
    )


def capture_failure(
    message: str, transcript: pathlib.Path, peer_output: str = ""
) -> NoReturn:
    details = []
    if peer_output.strip():
        details.append("--- OpenSSH peer output ---\n" + peer_output.strip())
    tail = uart_tail(transcript)
    if tail:
        details.append("--- QEMU UART tail ---\n" + tail)
    fail(message + ("\n" + "\n".join(details) if details else ""))


def peer_command(
    *,
    ssh: str,
    host_port: int,
    accepted_key: pathlib.Path,
    rejected_key: pathlib.Path,
    known_hosts: pathlib.Path,
    host_key: pathlib.Path,
    transcript: pathlib.Path,
    source_commit: str,
    challenge: str,
    capture_mode: str,
    ready_timeout: float,
    command_timeout: float,
    marker_timeout: float,
) -> list[str]:
    return [
        *PINNED_PYTHON_ARGV_PREFIX,
        str(PEER),
        "--ssh-bin",
        ssh,
        "--host",
        "127.0.0.1",
        "--port",
        str(host_port),
        "--accepted-key",
        str(accepted_key),
        "--rejected-key",
        str(rejected_key),
        "--known-hosts",
        str(known_hosts),
        "--host-key-output",
        str(host_key),
        "--qemu-log",
        str(transcript),
        "--expect-source",
        source_commit,
        "--expect-challenge",
        challenge,
        "--expect-mode",
        capture_mode,
        "--ready-timeout",
        str(ready_timeout),
        "--command-timeout",
        str(command_timeout),
        "--marker-timeout",
        str(marker_timeout),
    ]


def frozen_peer_command(
    transcript: pathlib.Path,
    source_commit: str,
    challenge: str,
    capture_mode: str,
) -> list[str]:
    return [
        *PINNED_PYTHON_ARGV_PREFIX,
        str(PEER),
        "--verify-log-only",
        "--qemu-log",
        str(transcript),
        "--expect-source",
        source_commit,
        "--expect-challenge",
        challenge,
        "--expect-mode",
        capture_mode,
    ]


def run_checked_capture_helper(command: list[str], label: str) -> str:
    environment = dict(PINNED_PYTHON_LAUNCH_ENVIRONMENT)
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot invoke {label}: {error}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        fail(f"{label} rejected the frozen capture: {detail}")
    return completed.stdout.strip()


def capture_qemu(
    *,
    qemu_argv: tuple[str, ...],
    ssh: str,
    host_port: int,
    timeout: float,
    ready_timeout: float,
    command_timeout: float,
    marker_timeout: float,
    transcript: pathlib.Path,
    accepted_key: pathlib.Path,
    rejected_key: pathlib.Path,
    known_hosts: pathlib.Path,
    host_key: pathlib.Path,
    source_commit: str,
    challenge: str,
    capture_mode: str,
    qemu_environment: dict[str, str],
    helper_identities: dict[str, dict[str, object]],
) -> tuple[bytes, str, dict[str, dict[str, object]]]:
    validate_qemu_environment(qemu_environment)
    require(type(qemu_argv) is tuple, "actual QEMU argv is not immutable")
    require(
        all(type(item) is str and item for item in qemu_argv),
        "actual QEMU argv contains an invalid item",
    )
    print(
        "C8.4 QEMU decision: starting one fresh process "
        f"machine={QEMU_MACHINE} cpu={QEMU_CPU} smp={QEMU_SMP} "
        f"memory={QEMU_MEMORY} accel={QEMU_ACCELERATOR} icount={QEMU_ICOUNT}",
        file=sys.stderr,
    )
    try:
        output = transcript.open("xb")
    except OSError as error:
        fail(f"cannot create temporary UART transcript: {error}")
    try:
        try:
            process = subprocess.Popen(
                qemu_argv,
                cwd=pathlib.Path("/"),
                env=qemu_environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        except OSError as error:
            fail(f"cannot start QEMU: {error}")
    finally:
        output.close()

    peer = peer_command(
        ssh=ssh,
        host_port=host_port,
        accepted_key=accepted_key,
        rejected_key=rejected_key,
        known_hosts=known_hosts,
        host_key=host_key,
        transcript=transcript,
        source_commit=source_commit,
        challenge=challenge,
        capture_mode=capture_mode,
        ready_timeout=ready_timeout,
        command_timeout=command_timeout,
        marker_timeout=marker_timeout,
    )
    peer_output = ""
    try:
        try:
            completed = subprocess.run(
                peer,
                cwd=ROOT,
                env=dict(PINNED_PYTHON_LAUNCH_ENVIRONMENT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            fragments = []
            for fragment in (error.stdout, error.stderr):
                if isinstance(fragment, bytes):
                    fragments.append(fragment.decode("utf-8", errors="replace"))
                elif fragment:
                    fragments.append(fragment)
            peer_output = "".join(fragments)
            capture_failure(
                f"OpenSSH campaign exceeded the {timeout:.1f}s whole-run timeout",
                transcript,
                peer_output,
            )
        peer_output = completed.stdout
        if completed.returncode != 0:
            capture_failure("real OpenSSH campaign failed", transcript, peer_output)
        live_source_closure = peer_source_closure(peer_output, helper_identities)
        if process.poll() is not None:
            capture_failure(
                f"QEMU exited with {process.returncode} during the OpenSSH campaign",
                transcript,
                peer_output,
            )
        time.sleep(END_SETTLE_SECONDS)
    finally:
        try:
            BASE.stop_process(process)
        except (OSError, subprocess.SubprocessError) as error:
            capture_failure(
                f"cannot stop the sole QEMU process: {error}", transcript, peer_output
            )

    try:
        raw = transcript.read_bytes()
    except OSError as error:
        fail(f"cannot read frozen QEMU UART transcript: {error}")
    if not raw or len(raw) > MAX_TRANSCRIPT_BYTES:
        capture_failure(
            f"frozen QEMU UART size is outside 1..{MAX_TRANSCRIPT_BYTES}",
            transcript,
            peer_output,
        )
    frozen_result = run_checked_capture_helper(
        frozen_peer_command(transcript, source_commit, challenge, capture_mode),
        "frozen C8.4 QEMU peer",
    )
    frozen_source_closure = peer_source_closure(frozen_result, helper_identities)
    require(
        frozen_source_closure == live_source_closure,
        "live and frozen peer executed different source closures",
    )
    return (
        raw,
        "\n".join(value for value in (peer_output.strip(), frozen_result) if value),
        {
            HELPER_PATHS["qemu_c83_base_runner"]: {
                "sha256": helper_identities["qemu_c83_base_runner"]["sha256"],
                "bytes": helper_identities["qemu_c83_base_runner"]["bytes"],
            },
            **live_source_closure,
        },
    )


def formal_metadata(
    raw: bytes, source_commit: str, challenge: str, capture_mode: str
) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict").replace("\r", "\n")
    except UnicodeDecodeError as error:
        fail(f"frozen QEMU UART is not strict UTF-8: {error}")
    if re.search(r"\bAUDIT_[A-Z0-9_]+\b", text) is not None:
        fail("frozen formal UART contains diagnostic AUDIT records")
    if GENERIC_WASM_FAILURE.search(text) is not None:
        fail("frozen formal UART contains a generic WASM failure marker")
    records: dict[str, list[dict[str, Any]]] = {
        prefix: [] for prefix in FORMAL_PREFIXES
    }
    for original in text.splitlines():
        line = (
            original[len("\x1b[2K") :] if original.startswith("\x1b[2K") else original
        )
        for prefix in FORMAL_PREFIXES:
            if prefix not in line:
                continue
            if not line.startswith(prefix) or line.count(prefix) != 1:
                fail(
                    f"formal marker {prefix.strip()} is not one exact column-zero prefix"
                )
            decoded = BASE.strict_json_loads(line[len(prefix) :], prefix.strip())
            if not isinstance(decoded, dict):
                fail(f"formal marker {prefix.strip()} payload is not an object")
            records[prefix].append(decoded)
    counts = tuple(len(records[prefix]) for prefix in FORMAL_PREFIXES)
    if counts != (1, SAMPLE_COUNT, 1):
        fail(f"frozen formal record counts differ: META/SAMPLE/END={counts}")
    meta = records[META_PREFIX][0]
    expected = {
        "source_commit": source_commit,
        "challenge": challenge,
        "suite_id": SUITE_ID,
        "platform": PLATFORM,
        "platform_class": "emulator",
        "physical_provenance": "not-claimed",
        "timebase_hz": TIMEBASE_HZ,
        "budget_ticks": BUDGET_TICKS,
        "capture_mode": capture_mode,
        "decision_eligible": capture_mode == FORMAL_CAPTURE_MODE,
    }
    for field, value in expected.items():
        if meta.get(field) != value:
            fail(f"frozen formal META {field} differs")
    run_id = meta.get("run_id")
    if not isinstance(run_id, str) or HEX64.fullmatch(run_id) is None:
        fail("frozen formal META run_id differs")
    return meta


def invoke_verifier_summary(
    transcript: pathlib.Path,
    summary: pathlib.Path,
    source_commit: str,
    challenge: str,
    capture_mode: str,
) -> str:
    command = [
        *PINNED_PYTHON_ARGV_PREFIX,
        str(VERIFIER),
        "--check-manifest",
        "--transcript",
        str(transcript),
        "--expect-source",
        source_commit,
        "--expect-challenge",
        challenge,
        "--expect-capture-mode",
        capture_mode,
        "--summary-out",
        str(summary),
    ]
    return run_checked_capture_helper(command, "independent C8.4 QEMU summary verifier")


def build_input_verifier_arguments(
    *,
    toolchain: dict[str, object],
    source_root: pathlib.Path,
    private_cargo_home: pathlib.Path,
    private_crate_sources: pathlib.Path,
    private_crate_archives: pathlib.Path,
) -> list[str]:
    closure = toolchain["build_input_closure"]
    return [
        "--build-source-root",
        str(source_root),
        "--private-cargo-home",
        str(private_cargo_home),
        "--private-crate-sources",
        str(private_crate_sources),
        "--private-crate-archives",
        str(private_crate_archives),
        "--cargo-target",
        str(closure["normalized_paths"]["cargo_target"]),
        "--toolchain-root",
        str(closure["toolchain_tree"]["root"]),
        "--rust-src",
        str(closure["rust_src"]["root"]),
        "--linker-bin",
        str(toolchain["linker"]["invocation_path"]),
    ]


def invoke_verifier_decision(
    transcript: pathlib.Path,
    summary: pathlib.Path,
    environment: pathlib.Path,
    decision: pathlib.Path,
    source_commit: str,
    challenge: str,
    capture_mode: str,
    qemu: str,
    bios: pathlib.Path,
    kernel: pathlib.Path,
    ssh: str,
    build_source_root: pathlib.Path,
    materialized_source: pathlib.Path | None,
    execution_paths: dict[str, pathlib.Path],
    toolchain: dict[str, object],
    private_cargo_home: pathlib.Path,
    private_crate_sources: pathlib.Path,
    private_crate_archives: pathlib.Path,
    *,
    publication: bool,
) -> str:
    command = [
        *PINNED_PYTHON_ARGV_PREFIX,
        str(VERIFIER),
        "--check-manifest",
        "--transcript",
        str(transcript),
        "--expect-source",
        source_commit,
        "--expect-challenge",
        challenge,
        "--expect-capture-mode",
        capture_mode,
        "--qemu-bin",
        qemu,
        "--bios-bin",
        str(bios),
        "--kernel-bin",
        str(kernel),
        "--openssh-bin",
        ssh,
        "--execution-qemu-bin",
        str(execution_paths["qemu"]),
        "--execution-bios-bin",
        str(execution_paths["bios"]),
        "--execution-kernel-bin",
        str(execution_paths["kernel_elf"]),
        "--summary-in",
        str(summary),
        "--environment-in",
        str(environment),
        "--decision-out",
        str(decision),
        *build_input_verifier_arguments(
            toolchain=toolchain,
            source_root=build_source_root,
            private_cargo_home=private_cargo_home,
            private_crate_sources=private_crate_sources,
            private_crate_archives=private_crate_archives,
        ),
    ]
    if materialized_source is not None:
        command.extend(["--materialized-source", str(materialized_source)])
    if publication:
        command.append("--publication")
    return run_checked_capture_helper(
        command, "independent C8.4 QEMU decision verifier"
    )


def invoke_verifier_staged_publication(
    bundle: dict[str, pathlib.Path],
    *,
    source_commit: str,
    challenge: str,
    capture_mode: str,
    qemu: str,
    bios: pathlib.Path,
    kernel: pathlib.Path,
    ssh: str,
    materialized_source: pathlib.Path,
    execution_paths: dict[str, pathlib.Path],
    toolchain: dict[str, object],
    private_cargo_home: pathlib.Path,
    private_crate_sources: pathlib.Path,
    private_crate_archives: pathlib.Path,
) -> None:
    require(
        capture_mode == FORMAL_CAPTURE_MODE,
        "only formal evidence may enter staged publication verification",
    )
    command = [
        *PINNED_PYTHON_ARGV_PREFIX,
        str(VERIFIER),
        "--check-manifest",
        "--publication",
        "--transcript",
        str(bundle["transcript"]),
        "--expect-source",
        source_commit,
        "--expect-challenge",
        challenge,
        "--expect-capture-mode",
        capture_mode,
        "--qemu-bin",
        qemu,
        "--bios-bin",
        str(bios),
        "--kernel-bin",
        str(kernel),
        "--openssh-bin",
        ssh,
        "--materialized-source",
        str(materialized_source),
        "--execution-qemu-bin",
        str(execution_paths["qemu"]),
        "--execution-bios-bin",
        str(execution_paths["bios"]),
        "--execution-kernel-bin",
        str(execution_paths["kernel_elf"]),
        "--summary-in",
        str(bundle["summary"]),
        "--environment-in",
        str(bundle["environment"]),
        "--decision-in",
        str(bundle["decision"]),
        *build_input_verifier_arguments(
            toolchain=toolchain,
            source_root=materialized_source,
            private_cargo_home=private_cargo_home,
            private_crate_sources=private_crate_sources,
            private_crate_archives=private_crate_archives,
        ),
    ]
    run_checked_capture_helper(
        command, "independent staged C8.4 QEMU publication verifier"
    )


def validate_summary_identity(
    summary: pathlib.Path,
    *,
    source_commit: str,
    challenge: str,
    run_id: str,
    capture_mode: str,
) -> None:
    decoded = strict_json_path(summary, "independently derived QEMU summary")
    expected = {
        "source_commit": source_commit,
        "challenge": challenge,
        "run_id": run_id,
        "platform": PLATFORM,
        "capture_mode": capture_mode,
    }
    for field, value in expected.items():
        if decoded.get(field) != value:
            fail(f"independently derived summary {field} differs from UART META")


def identity_only(path: pathlib.Path) -> dict[str, object]:
    try:
        return BASE.file_identity(path)
    except BASE.RunnerError as error:
        fail(str(error))


def stable_runtime_file_identity(path: pathlib.Path) -> dict[str, object]:
    """Hash one regular runtime file through a stable, no-symlink descriptor."""

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
        fail(f"cannot hash Python runtime file {path}: {error}")

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
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def python_stdlib_inventory() -> dict[str, object]:
    """Hash all reachable stdlib/lib-dynload entries in deterministic order."""

    root = PINNED_PYTHON_STDLIB
    try:
        root_status = root.lstat()
    except OSError as error:
        fail(f"cannot inspect fixed Python stdlib: {error}")
    require(
        stat.S_ISDIR(root_status.st_mode) and not root.is_symlink(),
        "fixed Python stdlib is not one real directory",
    )
    entries: list[dict[str, object]] = []
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
            fail(f"cannot enumerate Python runtime directory {directory}: {error}")
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
            try:
                child_status = child_path.lstat()
            except OSError as error:
                fail(f"cannot inspect Python runtime entry {child_path}: {error}")
            mode = f"{stat.S_IMODE(child_status.st_mode):04o}"
            if stat.S_ISDIR(child_status.st_mode):
                descend.append((child_path, relative))
            elif stat.S_ISREG(child_status.st_mode):
                identity = stable_runtime_file_identity(child_path)
                entries.append(
                    {"path": relative, "kind": "file", "mode": mode, **identity}
                )
                files += 1
                byte_total += int(identity["bytes"])
            elif stat.S_ISLNK(child_status.st_mode):
                try:
                    target = os.readlink(child_path)
                except OSError as error:
                    fail(f"cannot read Python runtime symlink {child_path}: {error}")
                entries.append(
                    {
                        "path": relative,
                        "kind": "symlink",
                        "mode": mode,
                        "target": target,
                    }
                )
                symlinks += 1
            else:
                fail(f"unsupported Python runtime entry type: {child_path}")
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


def python_runtime_dynamic_closure() -> dict[str, object]:
    """Bind non-system Mach-O inputs reached by the reviewed Python runtime."""

    try:
        python_opt = PINNED_PYTHON_OPT_PREFIX.resolve(strict=True)
        crypto_resolved = PINNED_LIBCRYPTO_LINK.resolve(strict=True)
        lzma_resolved, lzma_links = symlink_chain(PINNED_LIBLZMA_LINK)
        zstd_resolved, zstd_links = symlink_chain(PINNED_LIBZSTD_LINK)
    except OSError as error:
        fail(f"cannot resolve Python runtime dynamic closure: {error}")
    require(python_opt == PINNED_PYTHON_CELLAR, "python@3.14 opt link target differs")
    require(crypto_resolved == PINNED_LIBCRYPTO, "openssl@3 opt link target differs")
    require(lzma_resolved == PINNED_LIBLZMA, "xz runtime link target differs")
    require(zstd_resolved == PINNED_LIBZSTD, "zstd runtime link target differs")
    for name, path in (
        ("_hashlib", PINNED_HASHLIB_EXTENSION),
        ("_lzma", PINNED_LZMA_EXTENSION),
        ("_zstd", PINNED_ZSTD_EXTENSION),
    ):
        module = sys.modules.get(name)
        require(module is not None, f"Python runtime did not load {name}")
        require(
            getattr(module, "__file__", None) == str(path),
            f"Python runtime loaded {name} from an unexpected path",
        )
    extension_identity = stable_runtime_file_identity(PINNED_HASHLIB_EXTENSION)
    crypto_identity = stable_runtime_file_identity(PINNED_LIBCRYPTO)
    lzma_extension_identity = stable_runtime_file_identity(PINNED_LZMA_EXTENSION)
    lzma_identity = stable_runtime_file_identity(PINNED_LIBLZMA)
    zstd_extension_identity = stable_runtime_file_identity(PINNED_ZSTD_EXTENSION)
    zstd_identity = stable_runtime_file_identity(PINNED_LIBZSTD)
    require(
        extension_identity
        == {
            "sha256": PINNED_HASHLIB_EXTENSION_SHA256,
            "bytes": PINNED_HASHLIB_EXTENSION_BYTES,
        },
        "fixed Python _hashlib identity differs",
    )
    require(
        crypto_identity
        == {
            "sha256": PINNED_LIBCRYPTO_SHA256,
            "bytes": PINNED_LIBCRYPTO_BYTES,
        },
        "fixed Python libcrypto identity differs",
    )
    require(
        lzma_extension_identity
        == {"sha256": PINNED_LZMA_EXTENSION_SHA256, "bytes": PINNED_LZMA_EXTENSION_BYTES}
        and lzma_identity
        == {"sha256": PINNED_LIBLZMA_SHA256, "bytes": PINNED_LIBLZMA_BYTES},
        "fixed Python lzma runtime identity differs",
    )
    require(
        zstd_extension_identity
        == {"sha256": PINNED_ZSTD_EXTENSION_SHA256, "bytes": PINNED_ZSTD_EXTENSION_BYTES}
        and zstd_identity
        == {"sha256": PINNED_LIBZSTD_SHA256, "bytes": PINNED_LIBZSTD_BYTES},
        "fixed Python zstd runtime identity differs",
    )
    return {
        "policy": "exact-non-system-python-macho-closure-v1",
        "python_opt_prefix": {
            "path": str(PINNED_PYTHON_OPT_PREFIX),
            "resolves_to": str(PINNED_PYTHON_CELLAR),
        },
        "hashlib_extension": {"path": str(PINNED_HASHLIB_EXTENSION), **extension_identity},
        "libcrypto": {
            "link_path": str(PINNED_LIBCRYPTO_LINK),
            "path": str(PINNED_LIBCRYPTO),
            **crypto_identity,
        },
        "lzma_extension": {"path": str(PINNED_LZMA_EXTENSION), **lzma_extension_identity},
        "liblzma": {
            "link_path": str(PINNED_LIBLZMA_LINK),
            "path": str(PINNED_LIBLZMA),
            "symlinks": lzma_links,
            **lzma_identity,
        },
        "zstd_extension": {"path": str(PINNED_ZSTD_EXTENSION), **zstd_extension_identity},
        "libzstd": {
            "link_path": str(PINNED_LIBZSTD_LINK),
            "path": str(PINNED_LIBZSTD),
            "symlinks": zstd_links,
            **zstd_identity,
        },
        "openssl_configuration": {
            "conf": "/dev/null",
            "modules": "/var/empty",
            "modules_empty": True,
        },
        "system_dependencies": {
            "policy": "darwin-sealed-system-volume",
            "paths": [
                "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                "/usr/lib/libSystem.B.dylib",
            ],
        },
    }


def current_python_flags() -> dict[str, object]:
    return {name: getattr(sys.flags, name) for name in PINNED_PYTHON_FLAGS}


def python_runtime_record(*, startup: bool) -> dict[str, object]:
    """Validate and attest the formal interpreter plus its reachable runtime."""

    require(sys.executable == str(PINNED_PYTHON), "fixed Python executable path differs")
    require(
        tuple(sys.version_info[:3]) == (3, 14, 6),
        "fixed Python version differs from 3.14.6",
    )
    require(sys.prefix == str(PINNED_PYTHON_PREFIX), "fixed Python prefix differs")
    require(current_python_flags() == PINNED_PYTHON_FLAGS, "fixed Python flags differ")
    require(
        sys.pycache_prefix == str(PINNED_PYTHON_PYCACHE_PREFIX),
        "fixed Python pycache prefix differs",
    )
    require(
        sys._xoptions == {"pycache_prefix": str(PINNED_PYTHON_PYCACHE_PREFIX)},
        "fixed Python -X options differ",
    )
    expected_path = (
        PINNED_PYTHON_STARTUP_SYS_PATH
        if startup
        else PINNED_PYTHON_EFFECTIVE_SYS_PATH
    )
    require(sys.path == expected_path, "fixed Python sys.path differs")
    require(
        not os.path.lexists(PINNED_PYTHON_ZIP),
        "normally absent fixed Python stdlib zip appeared",
    )
    require(
        not os.path.lexists(PINNED_PYTHON_PYCACHE_PREFIX),
        "fixed Python pycache sink appeared",
    )
    try:
        empty_status = pathlib.Path("/var/empty").lstat()
    except OSError as error:
        fail(f"cannot inspect fixed Python pycache parent: {error}")
    require(
        stat.S_ISDIR(empty_status.st_mode)
        and not pathlib.Path("/var/empty").is_symlink()
        and stat.S_IMODE(empty_status.st_mode) == 0o755
        and empty_status.st_uid == 0
        and empty_status.st_gid == 3,
        "fixed Python pycache parent custody differs",
    )
    require(
        not tuple(pathlib.Path("/var/empty").iterdir()),
        "fixed Python OpenSSL module directory is not empty",
    )
    try:
        openssl_conf = pathlib.Path("/dev/null").lstat()
    except OSError as error:
        fail(f"cannot inspect fixed OpenSSL configuration sink: {error}")
    require(
        stat.S_ISCHR(openssl_conf.st_mode)
        and stat.S_IMODE(openssl_conf.st_mode) == 0o666
        and openssl_conf.st_uid == 0
        and openssl_conf.st_gid == 0,
        "fixed OpenSSL configuration sink differs",
    )
    require(
        hashlib.sha256(b"").hexdigest()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "fixed OpenSSL-backed SHA-256 KAT failed",
    )
    require(
        dict(os.environ) == PINNED_PYTHON_LAUNCH_ENVIRONMENT,
        "fixed Python launch environment differs",
    )
    executable_identity = stable_runtime_file_identity(PINNED_PYTHON)
    framework_identity = stable_runtime_file_identity(PINNED_PYTHON_FRAMEWORK)
    app_identity = stable_runtime_file_identity(PINNED_PYTHON_APP)
    require(
        executable_identity
        == {"sha256": PINNED_PYTHON_SHA256, "bytes": PINNED_PYTHON_BYTES},
        "fixed Python executable identity differs",
    )
    require(
        framework_identity
        == {
            "sha256": PINNED_PYTHON_FRAMEWORK_SHA256,
            "bytes": PINNED_PYTHON_FRAMEWORK_BYTES,
        },
        "fixed Python framework identity differs",
    )
    require(
        app_identity
        == {"sha256": PINNED_PYTHON_APP_SHA256, "bytes": PINNED_PYTHON_APP_BYTES},
        "fixed Python app executable identity differs",
    )
    inventory = python_stdlib_inventory()
    expected_inventory = {
        "sha256": PINNED_PYTHON_STDLIB_INVENTORY_SHA256,
        "entries": PINNED_PYTHON_STDLIB_INVENTORY_ENTRIES,
        "files": PINNED_PYTHON_STDLIB_INVENTORY_FILES,
        "directories": PINNED_PYTHON_STDLIB_INVENTORY_DIRECTORIES,
        "symlinks": PINNED_PYTHON_STDLIB_INVENTORY_SYMLINKS,
        "bytes": PINNED_PYTHON_STDLIB_INVENTORY_BYTES,
    }
    require(
        {key: inventory[key] for key in expected_inventory} == expected_inventory,
        "fixed Python stdlib inventory differs",
    )
    record = {
        "policy": "pinned-cpython-3.14-runtime-closure-v1",
        "launcher": relative_identity(
            LAUNCHER, "scripts/run-c84-qemu-aot-decision.sh"
        ),
        "argv_prefix": PINNED_PYTHON_ARGV_PREFIX,
        "environment": {
            "policy": "empty-then-exact-values-v1",
            "values": PINNED_PYTHON_LAUNCH_ENVIRONMENT,
        },
        "executable": {"path": str(PINNED_PYTHON), **executable_identity},
        "version": PINNED_PYTHON_VERSION,
        "implementation": sys.implementation.name,
        "cache_tag": sys.implementation.cache_tag,
        "prefix": str(PINNED_PYTHON_PREFIX),
        "framework": {"path": str(PINNED_PYTHON_FRAMEWORK), **framework_identity},
        "app_executable": {"path": str(PINNED_PYTHON_APP), **app_identity},
        "startup_sys_path": PINNED_PYTHON_STARTUP_SYS_PATH,
        "effective_sys_path": PINNED_PYTHON_EFFECTIVE_SYS_PATH,
        "flags": PINNED_PYTHON_FLAGS,
        "xoptions": {"pycache_prefix": str(PINNED_PYTHON_PYCACHE_PREFIX)},
        "stdlib_inventory": inventory,
        "runtime_dynamic_closure": python_runtime_dynamic_closure(),
        "pycache_custody": {
            "path": str(PINNED_PYTHON_PYCACHE_PREFIX),
            "must_remain_absent": True,
            "parent": "/var/empty",
            "parent_mode": "0755",
            "parent_uid": 0,
            "parent_gid": 3,
        },
    }
    if startup:
        sys.path[:] = PINNED_PYTHON_EFFECTIVE_SYS_PATH
    return record


def recheck_python_runtime(expected: dict[str, object]) -> None:
    require(
        python_runtime_record(startup=False) == expected,
        "fixed Python runtime changed during capture",
    )


def expected_darwin_system_openssh_record() -> dict[str, object]:
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


def parse_darwin_root_mount(output: str) -> dict[str, object]:
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


def darwin_root_volume_record() -> dict[str, object]:
    require(sys.platform == "darwin", "C8.4 fixed-QEMU OpenSSH custody requires Darwin")
    try:
        completed = subprocess.run(
            [str(DARWIN_MOUNT)],
            cwd=ROOT,
            env={"LC_ALL": "C", "LANG": "C"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot inspect Darwin root mount: {error}")
    require(
        completed.returncode == 0 and not completed.stderr.strip(),
        f"cannot inspect Darwin root mount: {completed.stderr.strip() or completed.returncode}",
    )
    return parse_darwin_root_mount(completed.stdout)


def darwin_host_build_record() -> dict[str, str]:
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
        fail(f"cannot identify Darwin host build: {error}")
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
    require(record == PINNED_DARWIN_HOST_BUILD, "Darwin host build differs")
    return record


def darwin_system_openssh_record() -> dict[str, object]:
    require(sys.platform == "darwin", "C8.4 fixed-QEMU OpenSSH custody requires Darwin")
    path = DARWIN_SYSTEM_OPENSSH
    try:
        before = path.lstat()
        root = pathlib.Path("/").lstat()
        resolved = path.resolve(strict=True)
        filesystem = os.statvfs(path)
    except OSError as error:
        fail(f"cannot inspect pinned Darwin system OpenSSH: {error}")
    require(resolved == path, "pinned Darwin system OpenSSH path is not canonical")
    require(
        stat.S_ISREG(before.st_mode) and not path.is_symlink(),
        "pinned Darwin system OpenSSH is not a regular non-symlink file",
    )
    require(stat.S_IMODE(before.st_mode) == 0o755, "pinned OpenSSH mode differs")
    require(before.st_uid == 0 and before.st_gid == 0, "pinned OpenSSH owner differs")
    require(before.st_nlink == 1, "pinned OpenSSH link count differs")
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
    root_volume = darwin_root_volume_record()
    observed_identity = identity_only(path)
    require(
        observed_identity
        == {"sha256": PINNED_OPENSSH_SHA256, "bytes": PINNED_OPENSSH_BYTES},
        "pinned OpenSSH byte identity differs",
    )
    version = run_combined_version([str(path), "-V"], "pinned Darwin system OpenSSH")
    require(version == PINNED_OPENSSH_VERSION, "pinned OpenSSH version differs")
    try:
        after = path.lstat()
    except OSError as error:
        fail(f"cannot re-inspect pinned Darwin system OpenSSH: {error}")
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
        "pinned OpenSSH metadata changed during attestation",
    )
    record = expected_darwin_system_openssh_record()
    require(record["root_volume"] == root_volume, "Darwin root volume record differs")
    return record


def copy_custody_file(
    source: pathlib.Path,
    destination: pathlib.Path,
    expected: dict[str, object],
    mode: int,
    label: str,
) -> None:
    source = source.resolve(strict=True)
    source_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd = -1
    destination_fd = -1
    digest = hashlib.sha256()
    total = 0
    try:
        source_fd = os.open(source, source_flags)
        source_before = os.fstat(source_fd)
        require(
            stat.S_ISREG(source_before.st_mode) and source_before.st_size > 0,
            f"{label} custody source is not a nonempty regular file",
        )
        destination_fd = os.open(destination, destination_flags, mode)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_fd, chunk[offset:])
                require(written > 0, f"{label} custody copy made no progress")
                offset += written
        source_after = os.fstat(source_fd)
        require(
            (
                source_before.st_dev,
                source_before.st_ino,
                source_before.st_size,
                source_before.st_mtime_ns,
                source_before.st_ctime_ns,
            )
            == (
                source_after.st_dev,
                source_after.st_ino,
                source_after.st_size,
                source_after.st_mtime_ns,
                source_after.st_ctime_ns,
            ),
            f"{label} custody source changed while copying",
        )
        observed = {"sha256": digest.hexdigest(), "bytes": total}
        require(observed == expected, f"{label} custody source bytes differ")
        os.fchmod(destination_fd, mode)
        os.fsync(destination_fd)
    except OSError as error:
        fail(f"cannot create {label} custody copy: {error}")
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)


def custody_role_record(
    path: pathlib.Path, role: str, expected: dict[str, object]
) -> dict[str, object]:
    name, mode = CUSTODY_ROLES[role]
    require(path.name == name, f"{role} custody filename differs")
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {role} custody file: {error}")
    require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_nlink == 1,
        f"{role} custody file is not private regular storage",
    )
    require(
        stat.S_IMODE(metadata.st_mode) == mode,
        f"{role} custody file mode differs",
    )
    require(identity_only(path) == expected, f"{role} custody identity differs")
    return {"name": name, "mode": f"{mode:04o}", **expected}


def create_execution_custody(
    campaign_root: pathlib.Path,
    *,
    qemu: pathlib.Path,
    bios: pathlib.Path,
    kernel: pathlib.Path,
    identities: dict[str, dict[str, object]],
    openssh_attestation: dict[str, object],
) -> tuple[pathlib.Path, dict[str, pathlib.Path], dict[str, object]]:
    require(set(identities) == set(CUSTODY_ROLES), "custody identity roles differ")
    directory = campaign_root / "execution-custody"
    directory.mkdir(mode=0o700)
    sources = {
        "qemu": qemu,
        "bios": bios,
        "kernel_elf": kernel,
    }
    paths: dict[str, pathlib.Path] = {}
    for role in CUSTODY_ROLES:
        name, mode = CUSTODY_ROLES[role]
        destination = directory / name
        copy_custody_file(sources[role], destination, identities[role], mode, role)
        paths[role] = destination
    fsync_directory(directory)
    directory.chmod(CUSTODY_DIRECTORY_MODE)
    record = {
        "scheme": CUSTODY_SCHEME,
        "private_directory_mode": f"{CUSTODY_DIRECTORY_MODE:04o}",
        **{
            role: custody_role_record(paths[role], role, identities[role])
            for role in CUSTODY_ROLES
        },
        "openssh": openssh_attestation,
    }
    require(
        openssh_attestation == expected_darwin_system_openssh_record(),
        "Darwin system OpenSSH attestation differs",
    )
    return directory, paths, record


def verify_execution_custody(
    directory: pathlib.Path,
    paths: dict[str, pathlib.Path],
    record: dict[str, object],
    *,
    observed_openssh: dict[str, object] | None = None,
) -> None:
    try:
        metadata = directory.lstat()
    except OSError as error:
        fail(f"cannot inspect execution custody directory: {error}")
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not directory.is_symlink()
        and stat.S_IMODE(metadata.st_mode) == CUSTODY_DIRECTORY_MODE,
        "execution custody directory changed",
    )
    require(
        set(paths) == set(CUSTODY_ROLES),
        "execution custody path roles differ",
    )
    require(
        set(record) == {"scheme", "private_directory_mode", "openssh", *CUSTODY_ROLES},
        "execution custody record roles differ",
    )
    require(record["scheme"] == CUSTODY_SCHEME, "execution custody scheme differs")
    require(
        record["private_directory_mode"] == f"{CUSTODY_DIRECTORY_MODE:04o}",
        "execution custody directory mode record differs",
    )
    for role in CUSTODY_ROLES:
        role_record = record[role]
        require(isinstance(role_record, dict), f"{role} custody record differs")
        expected = {
            "sha256": role_record.get("sha256"),
            "bytes": role_record.get("bytes"),
        }
        require(
            custody_role_record(paths[role], role, expected) == role_record,
            f"{role} custody record changed",
        )
    current_openssh = (
        darwin_system_openssh_record() if observed_openssh is None else observed_openssh
    )
    require(
        current_openssh == expected_darwin_system_openssh_record(),
        "live Darwin system OpenSSH attestation differs",
    )
    require(record["openssh"] == current_openssh, "OpenSSH custody record changed")


def release_execution_custody(directory: pathlib.Path | None) -> None:
    if directory is None or not os.path.lexists(directory):
        return
    try:
        directory.chmod(0o700)
    except OSError as error:
        fail(f"cannot reopen execution custody for cleanup: {error}")


def relative_identity(path: pathlib.Path, relative: str) -> dict[str, object]:
    return {"path": relative, **identity_only(path)}


def collect_helper_identities() -> dict[str, dict[str, object]]:
    identities: dict[str, dict[str, object]] = {}
    for key, relative in HELPER_PATHS.items():
        path = ROOT / relative
        if not path.is_file():
            fail(f"required maintained helper is missing: {path}")
        identities[key] = relative_identity(path, relative)
    require_executed_source_identity(BASE, BASE_RUNNER_PATH, "base runner")
    return identities


def recheck_helper_identities(
    expected: dict[str, dict[str, object]],
) -> None:
    require(set(expected) == set(HELPER_PATHS), "helper identity key set differs")
    for key, relative in HELPER_PATHS.items():
        current = relative_identity(ROOT / relative, relative)
        if current != expected[key]:
            fail(f"fixed helper {key} changed during capture")


def require_executed_source_identity(
    module: types.ModuleType, path: pathlib.Path, label: str
) -> None:
    executed = getattr(module, "__vibeos_executed_source_closure__", None)
    require(isinstance(executed, dict), f"{label} did not expose executed source")
    require(
        executed == {str(path): identity_only(path)},
        f"executed {label} source differs from its path identity",
    )


def peer_source_closure(
    output: str,
    expected_helpers: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    records = [
        line[len(SOURCE_CLOSURE_PREFIX) :]
        for line in output.splitlines()
        if line.startswith(SOURCE_CLOSURE_PREFIX)
    ]
    require(len(records) == 1, "peer did not emit one executed-source closure")
    try:
        decoded = json.loads(records[0])
    except json.JSONDecodeError as error:
        fail(f"peer executed-source closure is not strict JSON: {error}")
    require(isinstance(decoded, dict), "peer executed-source closure is not an object")
    expected = {
        str(ROOT / HELPER_PATHS[key]): {
            "sha256": expected_helpers[key]["sha256"],
            "bytes": expected_helpers[key]["bytes"],
        }
        for key in PEER_SOURCE_CLOSURE_KEYS
    }
    require(decoded == expected, "peer executed-source closure differs from helpers")
    return {
        HELPER_PATHS[key]: expected[str(ROOT / HELPER_PATHS[key])]
        for key in PEER_SOURCE_CLOSURE_KEYS
    }


def canonical_host_key_evidence(path: pathlib.Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read canonical host-key evidence {path}: {error}")
    require(
        stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
        "host-key evidence must be one regular non-symlink file",
    )
    expected_raw = (EXPECTED_HOST_PUBLIC_KEY + "\n").encode("ascii")
    require(raw == expected_raw, "captured host public key differs from the fixture")
    try:
        encoded = EXPECTED_HOST_PUBLIC_KEY.split(" ", 1)[1]
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, IndexError) as error:
        fail(f"embedded host public key is malformed: {error}")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    require(
        fingerprint == EXPECTED_HOST_FINGERPRINT,
        "embedded host public-key fingerprint differs",
    )
    return {
        **identity_only(path),
        "public_key": EXPECTED_HOST_PUBLIC_KEY,
        "fingerprint_sha256": fingerprint,
    }


def write_json_exclusive(path: pathlib.Path, value: object) -> None:
    try:
        with path.open("x", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        fail(f"refusing to replace existing file: {path}")
    except OSError as error:
        fail(f"cannot create {path}: {error}")


def write_environment(
    destination: pathlib.Path,
    *,
    capture_mode: str,
    source_commit: str,
    challenge: str,
    run_id: str,
    started_at: str,
    ended_at: str,
    repository_before: dict[str, object],
    repository_after: dict[str, object],
    source_materialization: dict[str, object],
    toolchain: dict[str, object],
    qemu_version: str,
    qemu_path: str,
    qemu_identity: dict[str, object],
    qemu_actual_argv: tuple[str, ...],
    qemu_normalized_argv: list[str],
    qemu_environment: dict[str, object],
    qemu_runtime_closures: dict[str, object],
    bios_identity: dict[str, object],
    bios_path: pathlib.Path,
    kernel_identity: dict[str, object],
    openssh_version: str,
    openssh_path: str,
    openssh_identity: dict[str, object],
    execution_custody: dict[str, object],
    host_key_identity: dict[str, object],
    helper_identities: dict[str, dict[str, object]],
    executed_peer_sources: dict[str, dict[str, object]],
    python_runtime: dict[str, object],
    transcript: pathlib.Path,
    summary: pathlib.Path,
) -> None:
    envelope = {
        "schema": "vibeos.c84.qemu-aot-decision.environment",
        "version": 1,
        "suite_id": SUITE_ID,
        "mode": capture_mode,
        "platform": PLATFORM,
        "platform_class": "emulator",
        "physical_provenance": "not-claimed",
        "source_commit": source_commit,
        "challenge": challenge,
        "run_id": run_id,
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "repository": {"before": repository_before, "after": repository_after},
        "source_materialization": source_materialization,
        "contract": {
            "fresh_qemu_processes": 1,
            "warmups": WARMUP_COUNT,
            "retained": RETAINED_COUNT,
            "timebase_hz": TIMEBASE_HZ,
            "budget_ticks": BUDGET_TICKS,
        },
        "runner": relative_identity(
            pathlib.Path(__file__).resolve(), "scripts/qemu-c84-aot-decision.py"
        ),
        "verifier": relative_identity(
            VERIFIER, "scripts/verify-c84-qemu-aot-decision.py"
        ),
        "helpers": helper_identities,
        "executed_peer_sources": executed_peer_sources,
        "python_runtime": python_runtime,
        "toolchain": toolchain,
        "kernel_elf": {
            "path": "<private-target>/riscv64imac-unknown-none-elf/release/vibeos-qemu-virt",
            **kernel_identity,
        },
        "qemu": {
            "path": qemu_path,
            "version": qemu_version,
            "cwd": QEMU_PROCESS_CWD,
            "actual_argv": list(qemu_actual_argv),
            "normalized_argv": qemu_normalized_argv,
            "environment": qemu_environment,
            "runtime_closures": qemu_runtime_closures,
            **qemu_identity,
        },
        "bios": {"path": str(bios_path), "name": QEMU_BIOS_NAME, **bios_identity},
        "openssh": {
            "path": openssh_path,
            "version": openssh_version,
            **openssh_identity,
        },
        "execution_custody": execution_custody,
        "host_key_evidence": host_key_identity,
        "transcript": identity_only(transcript),
        "summary": identity_only(summary),
    }
    write_json_exclusive(destination, envelope)


def check_evidence_destination(path: pathlib.Path | None) -> pathlib.Path | None:
    if path is None:
        return None
    absolute = pathlib.Path(os.path.abspath(os.fspath(path)))
    try:
        parent = absolute.parent.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve evidence destination parent {absolute.parent}: {error}")
    destination = parent / absolute.name
    if os.path.lexists(destination):
        fail(f"evidence destination already exists; refusing to clobber: {destination}")
    if not destination.parent.is_dir():
        fail(
            f"evidence destination parent must already be a directory: {destination.parent}"
        )
    return destination


def copy_exclusive(source: pathlib.Path, destination: pathlib.Path) -> None:
    try:
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file)
            os.fchmod(output_file.fileno(), 0o400)
            output_file.flush()
            os.fsync(output_file.fileno())
    except FileExistsError:
        fail(
            f"evidence output appeared during publication; refusing to clobber: {destination}"
        )
    except OSError as error:
        fail(f"cannot publish verified evidence {destination}: {error}")


def fsync_directory(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        fail(f"cannot fsync evidence directory {path}: {error}")


def bundle_sources(
    *,
    transcript: pathlib.Path,
    summary: pathlib.Path,
    environment: pathlib.Path,
    decision: pathlib.Path,
) -> dict[str, pathlib.Path]:
    sources = {
        "transcript": transcript,
        "summary": summary,
        "environment": environment,
        "decision": decision,
    }
    for role, path in sources.items():
        try:
            metadata = path.lstat()
        except OSError as error:
            fail(f"cannot inspect private {role} evidence {path}: {error}")
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and metadata.st_nlink == 1,
            f"private {role} evidence is not a single-link regular file",
        )
    return sources


def bundle_identities(
    sources: dict[str, pathlib.Path], label: str
) -> dict[str, dict[str, object]]:
    require(set(sources) == set(EVIDENCE_FILES), f"{label} roles differ")
    return {role: identity_only(sources[role]) for role in EVIDENCE_FILES}


def bundle_from_directory(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        fail(f"cannot inspect evidence stage {directory}: {error}")
    require(
        {entry.name for entry in entries} == set(EVIDENCE_FILES.values()),
        "evidence stage file set differs",
    )
    result: dict[str, pathlib.Path] = {}
    for role, filename in EVIDENCE_FILES.items():
        path = directory / filename
        try:
            metadata = path.lstat()
        except OSError as error:
            fail(f"cannot inspect staged evidence {path}: {error}")
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o400,
            f"staged evidence is not a regular non-symlink file: {path}",
        )
        result[role] = path
    return result


def copy_bundle(
    sources: dict[str, pathlib.Path], destination: pathlib.Path, *, seal: bool = False
) -> dict[str, pathlib.Path]:
    for role, filename in EVIDENCE_FILES.items():
        copy_exclusive(sources[role], destination / filename)
    fsync_directory(destination)
    if seal:
        destination.chmod(0o500)
        fsync_directory(destination)
    return bundle_from_directory(destination)


def require_bundle_identities(
    sources: dict[str, pathlib.Path],
    expected: dict[str, dict[str, object]],
    label: str,
) -> None:
    observed = bundle_identities(sources, label)
    require(observed == expected, f"{label} bytes changed")


def rename_directory_noreplace(source: pathlib.Path, destination: pathlib.Path) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source)
    encoded_destination = os.fsencode(destination)
    result: int
    if sys.platform == "darwin" and hasattr(library, "renamex_np"):
        operation = library.renamex_np
        operation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        operation.restype = ctypes.c_int
        result = operation(encoded_source, encoded_destination, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        operation = library.renameat2
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        result = operation(-100, encoded_source, -100, encoded_destination, 1)
    else:
        fail("atomic no-replace directory rename is unavailable on this host")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            fail(
                "evidence destination appeared during publication; refusing to clobber: "
                f"{destination}"
            )
        fail(
            f"cannot atomically finalize evidence {destination}: "
            f"{os.strerror(error_number)}"
        )


def publish_evidence(
    destination: pathlib.Path,
    *,
    transcript: pathlib.Path,
    summary: pathlib.Path,
    environment: pathlib.Path,
    decision: pathlib.Path,
    staged_verifier: Callable[[dict[str, pathlib.Path]], None],
    before_finalize: Callable[[], None] | None = None,
) -> None:
    sources = bundle_sources(
        transcript=transcript,
        summary=summary,
        environment=environment,
        decision=decision,
    )
    frozen = bundle_identities(sources, "private verified evidence")
    # The independent formal verifier must run while the worktree is still
    # clean. Validate an isolated staged copy first, then copy those exact
    # verified bytes into the hidden sibling used for atomic finalization.
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-qemu-publication-verify-", dir="/tmp"
    ) as verification_name:
        verification_directory = pathlib.Path(verification_name).resolve(strict=True)
        verification_bundle = copy_bundle(sources, verification_directory)
        require_bundle_identities(
            verification_bundle, frozen, "independent-verifier stage"
        )
        staged_verifier(verification_bundle)
        require_bundle_identities(
            verification_bundle, frozen, "independently verified stage"
        )
        require_bundle_identities(sources, frozen, "private evidence after verifier")

        try:
            staging = pathlib.Path(
                tempfile.mkdtemp(
                    prefix=f".{destination.name}.c84-stage-", dir=destination.parent
                )
            )
        except OSError as error:
            fail(f"cannot create hidden evidence stage: {error}")
        finalized = False
        try:
            staged_bundle = copy_bundle(verification_bundle, staging, seal=True)
            require_bundle_identities(staged_bundle, frozen, "hidden publication stage")
            if before_finalize is not None:
                before_finalize()
            require_bundle_identities(
                staged_bundle, frozen, "hidden publication stage before finalize"
            )
            rename_directory_noreplace(staging, destination)
            finalized = True
            try:
                fsync_directory(destination.parent)
            except RunnerError as error:
                raise PublicationDurabilityError(
                    "evidence directory contains complete independently verified bytes, "
                    f"but parent-directory durability is uncertain: {destination}: {error}"
                ) from error
        finally:
            if not finalized and os.path.lexists(staging):
                try:
                    staging.chmod(0o700)
                    shutil.rmtree(staging)
                except OSError as error:
                    fail(
                        f"cannot remove failed hidden evidence stage {staging}: {error}"
                    )


def recheck_toolchain(
    toolchain: dict[str, object],
    *,
    source_root: pathlib.Path,
    private_cargo_home: pathlib.Path,
    private_cargo_sources: pathlib.Path,
    private_crate_archives: pathlib.Path,
) -> None:
    try:
        BASE.recheck_toolchain_tools(toolchain)
    except BASE.RunnerError as error:
        fail(str(error))
    closure = toolchain.get("build_input_closure")
    require(type(closure) is dict, "toolchain omitted build input closure")
    normalized_paths = closure.get("normalized_paths")
    require(type(normalized_paths) is dict, "normalized build input paths differ")
    expected_paths = {
        "policy": "canonical-realpath-no-leaf-symlink-v1",
        "source_root": str(source_root.resolve(strict=True)),
        "manifest": str(
            (source_root / "firmware/qemu-virt/Cargo.toml").resolve(strict=True)
        ),
        "cargo_home": str(private_cargo_home.resolve(strict=True)),
        "private_crate_sources": str(private_cargo_sources.resolve(strict=True)),
        "private_crate_archives": str(private_crate_archives.resolve(strict=True)),
        "cargo_target": str(pathlib.Path(str(normalized_paths.get("cargo_target"))).resolve(strict=True)),
        "toolchain_root": str(PINNED_TOOLCHAIN_ROOT.resolve(strict=True)),
        "rust_src": str(PINNED_RUST_SRC.resolve(strict=True)),
    }
    require(normalized_paths == expected_paths, "normalized build input paths changed")
    _, cargo_locks, _ = locked_crate_union(source_root, PINNED_RUST_SRC)
    require(
        closure.get("cargo_locks") == cargo_locks,
        "project/rust-src Cargo.lock union closure changed",
    )
    crate_sources = closure.get("private_crate_sources")
    require(type(crate_sources) is dict, "private crate source closure differs")
    current_private = BASE.strict_tree_identity(
        private_cargo_sources, "private Cargo registry sources"
    )
    require(
        current_private == crate_sources.get("before") == crate_sources.get("after"),
        "private Cargo sources changed after build",
    )
    require(
        crate_sources.get("rust_src_materialization_before")
        == crate_sources.get("rust_src_materialization_after")
        == PINNED_RUST_SRC_TREE,
        "rust-src crate materialization custody differs",
    )
    archive_closure = closure.get("private_crate_archives")
    require(type(archive_closure) is dict, "private crate archive closure differs")
    current_archives = BASE.strict_tree_identity(
        private_crate_archives, "private crate archives"
    )
    require(
        archive_closure.get("root") == str(private_crate_archives.resolve(strict=True))
        and current_archives
        == archive_closure.get("before")
        == archive_closure.get("after")
        == PINNED_PRIVATE_CRATE_ARCHIVE_TREE,
        "private crate archives changed after build",
    )
    toolchain_tree = closure.get("toolchain_tree")
    require(type(toolchain_tree) is dict, "toolchain tree closure differs")
    toolchain_root = pathlib.Path(str(toolchain_tree.get("root")))
    current_toolchain = BASE.strict_tree_identity(
        toolchain_root, "pinned Rust toolchain"
    )
    require(
        current_toolchain
        == toolchain_tree.get("before")
        == toolchain_tree.get("after")
        == PINNED_TOOLCHAIN_TREE,
        "pinned Rust toolchain changed after build",
    )
    rust_src = closure.get("rust_src")
    require(type(rust_src) is dict, "rust-src closure differs")
    rust_src_root = pathlib.Path(str(rust_src.get("root")))
    current_rust_src = BASE.strict_tree_identity(
        rust_src_root, "pinned rust-src library"
    )
    require(
        current_rust_src
        == rust_src.get("before")
        == rust_src.get("after")
        == PINNED_RUST_SRC_TREE,
        "pinned rust-src changed after build",
    )
    require(
        identity_only(rust_src_root / "Cargo.toml") == PINNED_RUST_SRC_CARGO_TOML
        and identity_only(rust_src_root / "Cargo.lock") == PINNED_RUST_SRC_CARGO_LOCK,
        "pinned rust-src manifests changed after build",
    )
    cargo_configuration = closure.get("cargo_configuration")
    require(type(cargo_configuration) is dict, "Cargo configuration closure differs")
    require(
        BASE.root_cargo_config_absence()
        == cargo_configuration.get("root_before")
        == cargo_configuration.get("root_after"),
        "Cargo root configuration changed after build",
    )
    generated, firmware_record = BASE.generated_cargo_config(
        source_root / "firmware/.cargo/config.toml", private_cargo_sources
    )
    generated_path = private_cargo_home / "config.toml"
    generated_record = {
        "path": "<private-cargo-home>/config.toml",
        **identity_only(generated_path),
    }
    require(
        firmware_record == cargo_configuration.get("materialized_firmware")
        and identity_only(generated_path)
        == {
            "sha256": hashlib.sha256(generated).hexdigest(),
            "bytes": len(generated),
        }
        == {
            "sha256": cargo_configuration["generated"]["sha256"],
            "bytes": cargo_configuration["generated"]["bytes"],
        },
        "private Cargo configuration changed after build",
    )
    try:
        private_home = BASE.private_cargo_home_identity(
            private_cargo_home, generated_record
        )
    except BASE.RunnerError as error:
        fail(str(error))
    require(
        private_home
        == cargo_configuration.get("private_home_before")
        == cargo_configuration.get("private_home_after"),
        "private Cargo home changed after build",
    )
    linker_runtime = closure.get("linker_runtime")
    require(type(linker_runtime) is dict, "linker runtime closure differs")
    current_linker = linker_runtime_closure(
        pathlib.Path(str(toolchain["linker"]["invocation_path"]))
    )
    require(
        current_linker
        == linker_runtime.get("before")
        == linker_runtime.get("after")
        and current_linker["sha256"] == PINNED_LLD_RUNTIME_SHA256,
        "ld.lld runtime changed after build",
    )


def optional_git_line(arguments: list[str], label: str) -> str | None:
    returncode, raw = sanitized_git(arguments, label, allowed_returncodes=(0, 1, 128))
    if returncode != 0:
        require(raw == b"", f"sanitized Git {label} failure emitted stdout")
        return None
    require(
        raw.endswith(b"\n") and raw.count(b"\n") == 1,
        f"sanitized Git {label} output differs",
    )
    try:
        value = raw[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        fail(f"sanitized Git {label} output is not UTF-8")
    require(bool(value), f"sanitized Git {label} is empty")
    return value


def combined_index_flags(arguments: list[str], label: str) -> tuple[bytes, int, bool]:
    pieces: list[bytes] = []
    count = 0
    all_h = True
    for path in (".", *sorted(EXPECTED_SUBMODULES)):
        cwd = ROOT if path == "." else ROOT / path
        _, raw = sanitized_git(arguments[1:], f"{label} {path}", cwd=cwd)
        entries, observed_all_h = parse_index_flags(raw, f"{label} {path}")
        encoded_path = path.encode("utf-8")
        pieces.append(len(encoded_path).to_bytes(4, "big") + encoded_path + raw)
        count += entries
        all_h = all_h and observed_all_h
    return b"".join(pieces), count, all_h


def validate_local_config_entry(
    repository: str, key: str, value: str
) -> None:
    core_values = {
        "core.repositoryformatversion": "0",
        "core.filemode": "true",
        "core.bare": "false",
        "core.logallrefupdates": "true",
        "core.ignorecase": "true",
        "core.precomposeunicode": "true",
    }
    if key in core_values:
        require(value == core_values[key], f"unsafe local Git config value: {key}")
        return
    if key == "core.worktree":
        require(repository in EXPECTED_SUBMODULES, "superproject has core.worktree")
        require(
            value == f"../../../../{repository}",
            f"submodule core.worktree differs: {repository}",
        )
        return
    expected_urls = {
        ".": FORMAL_CONFIGURED_ORIGIN,
        "vendor/jitterentropy-rs": "https://github.com/qnfm/jitterentropy-rs.git",
        "vendor/sunset": "git@github.com:allegro0132/sunset.git",
    }
    if key == "remote.origin.url":
        require(value == expected_urls[repository], f"unsafe origin URL: {repository}")
        return
    if key == "remote.origin.fetch":
        require(
            value == "+refs/heads/*:refs/remotes/origin/*",
            f"unsafe origin fetch refspec: {repository}",
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
        expected = (
            "true"
            if field == "active"
            else expected_urls[name]
        )
        require(value == expected, f"unsafe local submodule config value: {key}")
        return
    fail(f"unsafe local Git config key: {key}")


def local_config_records() -> list[dict[str, object]]:
    require(
        not os.path.lexists("/.git"),
        "root directory unexpectedly exposes repository-local Git config",
    )
    records: list[dict[str, object]] = []
    for repository in (".", *sorted(EXPECTED_SUBMODULES)):
        relative = GIT_LOCAL_CONFIG_PATHS[repository]
        path = ROOT / relative
        before = stable_runtime_file_identity(path)
        _, raw = sanitized_git(
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
            except UnicodeDecodeError:
                fail(f"local config is not strict UTF-8: {repository}")
            require(key == key.lower(), f"local config key is not canonical: {key}")
            validate_local_config_entry(repository, key, value)
            parsed.append((key, value))
        require(bool(parsed), f"local config is empty: {repository}")
        require(
            len(parsed) == len(set(parsed)),
            f"local config repeats an exact entry: {repository}",
        )
        after = stable_runtime_file_identity(path)
        require(before == after, f"local config changed while parsing: {repository}")
        records.append(
            {
                "repository": repository,
                "path": relative,
                "policy": GIT_LOCAL_CONFIG_POLICY,
                **before,
                "entries": len(parsed),
                "parsed_sha256": hashlib.sha256(canonical_json_bytes(parsed)).hexdigest(),
            }
        )
    return records


def repository_attestation(
    source_commit: str, *, publication: bool
) -> dict[str, object]:
    local_configs = local_config_records()
    head = canonical_hex(
        sanitized_git_line(["rev-parse", "--verify", "HEAD^{commit}"], "HEAD"),
        HEX40,
        40,
        "repository HEAD",
    )
    commit_timestamp = sanitized_git_line(
        ["show", "-s", "--format=%ct", source_commit],
        "source commit timestamp",
    )
    require(
        commit_timestamp.isdigit() and int(commit_timestamp) > 0,
        "source commit timestamp differs",
    )
    _, status = sanitized_git(GIT_STATUS_COMMAND[1:], "status")
    _, diff = sanitized_git(GIT_DIFF_COMMAND[1:], "tracked diff")
    index_raw, index_entries, index_all_h = combined_index_flags(
        GIT_INDEX_FLAGS_COMMAND, "index flags"
    )
    fsmonitor_raw, fsmonitor_entries, fsmonitor_all_h = combined_index_flags(
        ["git", "ls-files", "-f", "-z", "--full-name"], "fsmonitor flags"
    )
    require(
        fsmonitor_entries == index_entries,
        "repository index and fsmonitor entry counts differ",
    )
    configured_fetch = sanitized_git_line(
        ["remote", "get-url", "--all", "origin"], "configured origin fetch URL"
    )
    configured_push = sanitized_git_line(
        ["remote", "get-url", "--push", "--all", "origin"],
        "configured origin push URL",
    )
    remote_raw = b""
    advertised_head: str | None = None
    if publication:
        require(
            not os.path.lexists("/.git"),
            "fixed remote query could discover root-local Git configuration",
        )
        _, remote_raw = sanitized_git(
            GIT_REMOTE_QUERY_COMMAND[1:],
            "fixed remote codex/wasm advertisement",
            cwd=pathlib.Path("/"),
        )
        advertised_head = parse_remote_advertisement(remote_raw, source_commit)
    return {
        "head": head,
        "commit_timestamp": commit_timestamp,
        "clean": (
            not status
            and not diff
            and index_all_h
            and fsmonitor_all_h
            and head == source_commit
        ),
        "branch": optional_git_line(
            ["symbolic-ref", "--quiet", "--short", "HEAD"], "branch"
        ),
        "local_codex_wasm_head": optional_git_line(
            ["rev-parse", "--verify", f"{FORMAL_LOCAL_REF}^{{commit}}"],
            "local codex/wasm ref",
        ),
        "local_tracking_codex_wasm_head": optional_git_line(
            ["rev-parse", "--verify", f"{FORMAL_ORIGIN_REF}^{{commit}}"],
            "local origin/codex/wasm tracking ref",
        ),
        "configured_fetch_url": configured_fetch,
        "configured_push_url": configured_push,
        "remote_query_url": FORMAL_REMOTE_URL,
        "remote_ref": FORMAL_REMOTE_REF,
        "advertised_remote_head": advertised_head,
        "status_command": GIT_STATUS_COMMAND,
        "diff_command": GIT_DIFF_COMMAND,
        "index_flags_command": GIT_INDEX_FLAGS_COMMAND,
        "fsmonitor_flags_command": [
            "git",
            "ls-files",
            "-f",
            "-z",
            "--full-name",
        ],
        "remote_query_command": GIT_REMOTE_QUERY_COMMAND,
        "status_porcelain_v1_z_sha256": hashlib.sha256(status).hexdigest(),
        "tracked_diff_head_binary_sha256": hashlib.sha256(diff).hexdigest(),
        "index_flags_sha256": hashlib.sha256(index_raw).hexdigest(),
        "fsmonitor_flags_sha256": hashlib.sha256(fsmonitor_raw).hexdigest(),
        "index_entries": index_entries,
        "index_flags_all_h": index_all_h,
        "fsmonitor_flags_all_h": fsmonitor_all_h,
        "remote_response_sha256": hashlib.sha256(remote_raw).hexdigest(),
        "local_configs": local_configs,
    }


def check_repository(
    source_commit: str,
    *,
    allow_dirty: bool,
    expected_local_configs: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    record = repository_attestation(source_commit, publication=not allow_dirty)
    require(
        record["head"] == source_commit,
        "repository HEAD changed during the C8.4 campaign",
    )
    if expected_local_configs is not None:
        require(
            record["local_configs"] == expected_local_configs,
            "repository-local Git configuration changed during the campaign",
        )
    require(
        record["configured_fetch_url"] == FORMAL_CONFIGURED_ORIGIN
        and record["configured_push_url"] == FORMAL_CONFIGURED_ORIGIN,
        "capture requires the pinned configured origin",
    )
    if allow_dirty:
        return record
    require(record["clean"] is True, "formal publication requires a clean repository")
    require(
        record["branch"] == FORMAL_BRANCH,
        "formal publication requires branch codex/wasm",
    )
    require(
        record["local_codex_wasm_head"] == source_commit,
        "formal publication requires refs/heads/codex/wasm exactly at HEAD",
    )
    require(
        record["local_tracking_codex_wasm_head"] == source_commit,
        "formal publication requires local origin/codex/wasm tracking at HEAD",
    )
    require(
        record["advertised_remote_head"] == source_commit,
        "formal publication requires the fixed remote to advertise HEAD",
    )
    require(
        record["index_flags_all_h"] is True and record["fsmonitor_flags_all_h"] is True,
        "formal publication rejects hidden index or fsmonitor state",
    )
    return record


def selftest() -> int:
    checks = 20
    base_keyword_defaults = BASE.build_kernel.__kwdefaults__
    require(
        type(base_keyword_defaults) is dict
        and "private_crate_archives" in base_keyword_defaults,
        "C8.3 base build contract omits private crate archives",
    )
    checks += 1
    argv = semantic_qemu_command(12345)
    require(argv[0] == "qemu-system-riscv64", "semantic QEMU executable differs")
    require(
        argv.count("-icount") == 1 and QEMU_ICOUNT in argv,
        "semantic QEMU icount differs",
    )
    require(
        "<opensbi>" in argv and "<kernel>" in argv,
        "semantic QEMU paths are not normalized",
    )
    joined = "\n".join(argv)
    require(
        "<host-port>" in joined and "12345" not in joined,
        "semantic QEMU port is not normalized",
    )
    require(
        "-bios\ndefault" not in joined, "semantic QEMU command permits implicit BIOS"
    )
    require(
        argv.count("-smp") == 1 and argv[argv.index("-smp") + 1] == "1",
        "semantic QEMU hart count differs",
    )
    require(
        parse_remote_advertisement(
            f"{TEST_ONLY_SOURCE_COMMIT}\t{FORMAL_REMOTE_REF}\n".encode("ascii"),
            TEST_ONLY_SOURCE_COMMIT,
        )
        == TEST_ONLY_SOURCE_COMMIT,
        "valid remote advertisement was rejected",
    )
    for candidate in (
        b"",
        f"{'3' * 40}\t{FORMAL_REMOTE_REF}\n".encode("ascii"),
        f"{TEST_ONLY_SOURCE_COMMIT}\trefs/heads/main\n".encode("ascii"),
        (
            f"{TEST_ONLY_SOURCE_COMMIT}\t{FORMAL_REMOTE_REF}\n"
            f"{TEST_ONLY_SOURCE_COMMIT}\t{FORMAL_REMOTE_REF}\n"
        ).encode("ascii"),
    ):
        try:
            parse_remote_advertisement(candidate, TEST_ONLY_SOURCE_COMMIT)
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a malformed remote advertisement")
    entries, all_h = parse_index_flags(b"H tracked\0", "synthetic index")
    require(entries == 1 and all_h, "valid index flags were rejected")
    for candidate in (b"h tracked\0", b"S tracked\0", b"s tracked\0"):
        _, candidate_all_h = parse_index_flags(candidate, "synthetic hidden index")
        require(not candidate_all_h, "hidden index state was accepted as all-H")
        checks += 1
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c84-qemu-decision-runner-selftest-"
    ) as temporary_name:
        temporary = pathlib.Path(temporary_name).resolve(strict=True)
        valid_member = tarfile.TarInfo("crate-1.0/src/lib.rs")
        valid_member.type = tarfile.REGTYPE
        relative, pure = crate_member_relative(valid_member, "crate-1.0")
        require(
            relative == "src/lib.rs" and pure.parts == ("src", "lib.rs"),
            "valid crate member path was rejected",
        )
        unsafe_member_names = (
            "crate-1.0/../escape",
            "crate-1.0/src//lib.rs",
            "crate-1.0/src/./lib.rs",
            "crate-1.0/src\\lib.rs",
            "crate-1.0/src/\x00evil",
            "crate-1.0/src/line\nfeed",
            "crate-1.0/src/",
        )
        for name in unsafe_member_names:
            member = tarfile.TarInfo(name)
            member.type = tarfile.REGTYPE
            try:
                crate_member_relative(member, "crate-1.0")
            except RunnerError:
                checks += 1
            else:
                fail(f"runner selftest accepted unsafe crate member {name!r}")
        linked_member = tarfile.TarInfo("crate-1.0/src/link")
        linked_member.type = tarfile.SYMTYPE
        linked_member.linkname = "../../escape"
        try:
            crate_member_relative(linked_member, "crate-1.0")
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a crate archive symbolic link")

        synthetic_package = {
            "name": "vendor-crate",
            "version": "1.0.0",
            "checksum": "1" * 64,
        }

        def write_synthetic_vendor(
            name: str,
            files: dict[str, bytes],
            checksums: dict[str, str] | None = None,
        ) -> pathlib.Path:
            root = temporary / name
            root.mkdir(mode=0o700)
            for relative, raw in files.items():
                path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(0o400)
            inventory = checksums or {
                relative: hashlib.sha256(raw).hexdigest()
                for relative, raw in files.items()
            }
            (root / ".cargo-checksum.json").write_bytes(
                canonical_json_bytes(
                    {
                        "$comment": RUST_SRC_VENDOR_CHECKSUM_COMMENT,
                        "files": inventory,
                        "package": synthetic_package["checksum"],
                    }
                )
            )
            (root / ".cargo-checksum.json").chmod(0o400)
            return root

        valid_vendor = write_synthetic_vendor(
            "valid-vendor", {"src/lib.rs": b"synthetic source\n"}
        )
        valid_destination = temporary / "valid-vendor-copy"
        valid_destination.mkdir(mode=0o700)
        copied_files, copied_bytes = copy_verified_rust_src_vendor(
            valid_vendor, valid_destination, synthetic_package
        )
        require(
            copied_files == 1 and copied_bytes == len(b"synthetic source\n"),
            "runner selftest rejected a valid rust-src vendor package",
        )
        checks += 1
        traversal_vendor = write_synthetic_vendor(
            "traversal-vendor", {}, {"../escape": "2" * 64}
        )
        checksum_vendor = write_synthetic_vendor(
            "checksum-vendor", {"src/lib.rs": b"synthetic source\n"}, {"src/lib.rs": "2" * 64}
        )
        extra_vendor = write_synthetic_vendor(
            "extra-vendor", {"src/lib.rs": b"synthetic source\n", "extra": b"extra"}, {"src/lib.rs": hashlib.sha256(b"synthetic source\n").hexdigest()}
        )
        linked_vendor = write_synthetic_vendor(
            "linked-vendor", {}, {"src/lib.rs": hashlib.sha256(b"outside").hexdigest()}
        )
        (linked_vendor / "src").mkdir(mode=0o700)
        outside = temporary / "outside-vendor-file"
        outside.write_bytes(b"outside")
        (linked_vendor / "src/lib.rs").symlink_to(outside)
        for index, candidate in enumerate(
            (traversal_vendor, checksum_vendor, extra_vendor, linked_vendor)
        ):
            destination = temporary / f"rejected-vendor-copy-{index}"
            destination.mkdir(mode=0o700)
            try:
                copy_verified_rust_src_vendor(
                    candidate, destination, synthetic_package
                )
            except RunnerError:
                checks += 1
            else:
                fail("runner selftest accepted a mutated rust-src vendor package")
        cached_archive = temporary / "cached.crate"
        cached_archive.write_bytes(b"synthetic crate archive")
        cached_archive.chmod(0o400)
        try:
            copy_verified_archive(
                cached_archive, temporary / "copied.crate", "0" * 64
            )
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a crate archive checksum mutation")
        real_tree = temporary / "real-tree"
        real_tree.mkdir(mode=0o700)
        tree_alias = temporary / "tree-alias"
        tree_alias.symlink_to(real_tree, target_is_directory=True)
        try:
            BASE.strict_tree_identity(tree_alias, "synthetic aliased tree")
        except BASE.RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a symlink tree root")
        forged_source = temporary / "forged.py"
        forged_source.write_text("VALUE = 'cached'\n", encoding="utf-8")
        original_times = forged_source.stat()
        forged_cache = (
            temporary
            / "__pycache__"
            / f"forged.{sys.implementation.cache_tag}.pyc"
        )
        forged_cache.parent.mkdir()
        py_compile.compile(
            str(forged_source),
            cfile=str(forged_cache),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
        )
        forged_source.write_text("VALUE = 'source'\n", encoding="utf-8")
        os.utime(
            forged_source,
            ns=(original_times.st_atime_ns, original_times.st_mtime_ns),
        )
        forged_module = load_source_module(
            "vibeos_c84_forged_pyc_selftest", forged_source
        )
        require(forged_cache.is_file(), "forged valid pyc selftest fixture is missing")
        require(
            forged_module.VALUE == "source",
            "source-only loader executed a forged valid ignored pyc",
        )
        require_executed_source_identity(
            forged_module, forged_source, "forged-pyc selftest module"
        )
        checks += 1
        forged_source.write_text("VALUE = 'swapped'\n", encoding="utf-8")
        try:
            require_executed_source_identity(
                forged_module, forged_source, "source-swap selftest module"
            )
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a post-load source swap")

        marker = temporary / "sitecustomize-ran"
        sitecustomize = temporary / "sitecustomize.py"
        sitecustomize.write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        site_environment = dict(PINNED_PYTHON_LAUNCH_ENVIRONMENT)
        site_environment["PYTHONPATH"] = str(temporary)
        site_process = subprocess.run(
            [*PINNED_PYTHON_ARGV_PREFIX, "-c", "pass"],
            cwd=ROOT,
            env=site_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        require(site_process.returncode == 0, "isolated sitecustomize probe failed")
        require(not os.path.lexists(marker), "isolated Python executed sitecustomize")
        checks += 1

        closure_python = {
            pathlib.Path(__file__).resolve(),
            VERIFIER,
            *(ROOT / relative for relative in HELPER_PATHS.values()),
        }
        loader_python = {
            pathlib.Path(__file__).resolve(),
            VERIFIER,
            PEER,
            ROOT / HELPER_PATHS["collector_peer"],
            ROOT / HELPER_PATHS["trusted_sample_peer"],
            ROOT / HELPER_PATHS["finish_verify_peer"],
            ROOT / HELPER_PATHS["irq_overlay_peer"],
            ROOT / HELPER_PATHS["phase_sidecar_peer"],
            ROOT / HELPER_PATHS["core_peer"],
        }
        for source_path in sorted(closure_python):
            raw_source = source_path.read_text(encoding="utf-8", errors="strict")
            syntax = ast.parse(raw_source, filename=str(source_path))
            imported = {
                (
                    node.module
                    if isinstance(node, ast.ImportFrom) and node.module is not None
                    else alias.name
                )
                for node in ast.walk(syntax)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names
            }
            require(
                not any(name == "importlib" or name.startswith("importlib.") for name in imported),
                f"Python closure imports bytecode-capable importlib: {source_path}",
            )
            require(
                not any(
                    isinstance(node, ast.Attribute)
                    and node.attr in {"spec_from_file_location", "exec_module"}
                    for node in ast.walk(syntax)
                ),
                f"Python closure contains a bytecode-capable loader: {source_path}",
            )
        for source_path in sorted(loader_python):
            raw_source = source_path.read_text(encoding="utf-8", errors="strict")
            require(
                "compile(" in raw_source
                and "types.ModuleType(" in raw_source
                and "__vibeos_executed_source_closure__" in raw_source,
                f"source-only loader/identity gate is missing: {source_path}",
            )
        checks += len(closure_python) + len(loader_python)

        qemu_environment, qemu_environment_evidence = create_qemu_environment(
            temporary
        )
        require(
            qemu_environment_evidence == qemu_environment_record(),
            "normalized QEMU environment record differs",
        )
        qemu_environment_mutations: tuple[
            tuple[str, Callable[[dict[str, str]], None]], ...
        ] = (
            ("omitted-home", lambda value: value.pop("HOME")),
            (
                "extra-dyld-insert",
                lambda value: value.update(DYLD_INSERT_LIBRARIES="/tmp/injected.dylib"),
            ),
            (
                "extra-qemu-config",
                lambda value: value.update(QEMU_AUDIO_DRV="injected"),
            ),
            (
                "extra-locale",
                lambda value: value.update(LC_CTYPE="en_US.UTF-8"),
            ),
            ("injected-path", lambda value: value.update(PATH="/tmp/injected")),
        )
        for label, mutation in qemu_environment_mutations:
            candidate = dict(qemu_environment)
            mutation(candidate)
            try:
                validate_qemu_environment(candidate)
            except RunnerError:
                checks += 1
            else:
                fail(f"runner selftest accepted QEMU environment mutation {label}")
        probe_state = pathlib.Path(qemu_environment["HOME"]) / "probe-created-state"
        write_private_file(probe_state, b"unexpected", 0o600)
        try:
            validate_qemu_environment(qemu_environment)
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted probe-created QEMU environment state")
        finally:
            probe_state.unlink()
        materialized_campaign = temporary / "materialized-campaign"
        materialized_campaign.mkdir(mode=0o700)
        materialized, _, expected = materialize_source(
            canonical_hex(
                sanitized_git_line(
                    ["rev-parse", "--verify", "HEAD^{commit}"], "selftest HEAD"
                ),
                HEX40,
                40,
                "selftest HEAD",
            ),
            materialized_campaign,
        )
        verify_materialized_source(materialized, expected)
        first_relative = sorted(expected)[0]
        first_file = materialized / first_relative
        first_file.chmod(0o600)
        try:
            verify_materialized_source(materialized, expected)
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a changed materialized source mode")

        custody_campaign = temporary / "custody-campaign"
        custody_campaign.mkdir(mode=0o700)
        custody_sources: dict[str, pathlib.Path] = {}
        custody_identities: dict[str, dict[str, object]] = {}
        for role in CUSTODY_ROLES:
            source = custody_campaign / f"source-{role}"
            source.write_bytes((role + " custody source\n").encode("ascii"))
            source.chmod(0o700)
            custody_sources[role] = source
            custody_identities[role] = identity_only(source)
        openssh_attestation = expected_darwin_system_openssh_record()
        custody_directory, custody_paths, custody_record = create_execution_custody(
            custody_campaign,
            qemu=custody_sources["qemu"],
            bios=custody_sources["bios"],
            kernel=custody_sources["kernel_elf"],
            identities=custody_identities,
            openssh_attestation=openssh_attestation,
        )
        verify_execution_custody(
            custody_directory,
            custody_paths,
            custody_record,
            observed_openssh=openssh_attestation,
        )
        custody_paths["bios"].chmod(0o600)
        try:
            verify_execution_custody(
                custody_directory,
                custody_paths,
                custody_record,
                observed_openssh=openssh_attestation,
            )
        except RunnerError:
            checks += 1
        else:
            fail("runner selftest accepted a changed custody mode")
        custody_paths["bios"].chmod(CUSTODY_ROLES["bios"][1])
        custody_mutations: tuple[
            tuple[str, Callable[[dict[str, object]], None]], ...
        ] = (
            ("scheme", lambda value: value.update(scheme="other")),
            ("method", lambda value: value["openssh"].update(method="copied")),
            ("path", lambda value: value["openssh"].update(path="/tmp/ssh")),
            ("mode", lambda value: value["openssh"].update(mode="0500")),
            ("uid", lambda value: value["openssh"].update(uid=501)),
            ("gid", lambda value: value["openssh"].update(gid=20)),
            ("nlink", lambda value: value["openssh"].update(nlink=2)),
            ("version", lambda value: value["openssh"].update(version="OpenSSH_other")),
            (
                "sf-restricted",
                lambda value: value["openssh"].update(sf_restricted=False),
            ),
            (
                "sealed",
                lambda value: value["openssh"]["root_volume"].update(sealed=False),
            ),
            (
                "read-only",
                lambda value: value["openssh"]["root_volume"].update(read_only=False),
            ),
            (
                "filesystem",
                lambda value: value["openssh"]["root_volume"].update(filesystem="hfs"),
            ),
            (
                "same-device",
                lambda value: value["openssh"].update(same_device_as_root=False),
            ),
            ("identity", lambda value: value["openssh"].update(sha256="0" * 64)),
        )
        for label, mutation in custody_mutations:
            candidate = copy.deepcopy(custody_record)
            mutation(candidate)
            try:
                verify_execution_custody(
                    custody_directory,
                    custody_paths,
                    candidate,
                    observed_openssh=openssh_attestation,
                )
            except RunnerError:
                checks += 1
            else:
                fail(f"runner selftest accepted OpenSSH custody mutation {label}")
        require(
            parse_darwin_root_mount(
                "/dev/disk1s1 on / (apfs, sealed, local, read-only, journaled)\n"
            )
            == openssh_attestation["root_volume"],
            "valid Darwin root mount record differs",
        )
        for mount in (
            "/dev/disk1s1 on / (hfs, sealed, read-only)\n",
            "/dev/disk1s1 on / (apfs, read-only)\n",
            "/dev/disk1s1 on / (apfs, sealed)\n",
        ):
            try:
                parse_darwin_root_mount(mount)
            except RunnerError:
                checks += 1
            else:
                fail("runner selftest accepted an unsafe Darwin root mount")
        release_execution_custody(custody_directory)

        sources = {
            role: temporary / f"source-{filename}"
            for role, filename in EVIDENCE_FILES.items()
        }
        for role, path in sources.items():
            path.write_bytes((role + "\n").encode("ascii"))
        host_key = temporary / "host-key.pub"
        host_key.write_bytes((EXPECTED_HOST_PUBLIC_KEY + "\n").encode("ascii"))
        host_evidence = canonical_host_key_evidence(host_key)
        require(
            host_evidence["public_key"] == EXPECTED_HOST_PUBLIC_KEY,
            "canonical host public key differs",
        )
        require(
            host_evidence["fingerprint_sha256"] == EXPECTED_HOST_FINGERPRINT,
            "canonical host-key fingerprint differs",
        )
        destination = temporary / "evidence"
        verifier_calls = 0

        def accept_stage(bundle: dict[str, pathlib.Path]) -> None:
            nonlocal verifier_calls
            verifier_calls += 1
            require(
                set(bundle) == set(EVIDENCE_FILES),
                "selftest verifier bundle differs",
            )

        publish_evidence(
            destination,
            transcript=sources["transcript"],
            summary=sources["summary"],
            environment=sources["environment"],
            decision=sources["decision"],
            staged_verifier=accept_stage,
        )
        require(verifier_calls == 1, "staged verifier invocation count differs")
        require(
            sorted(path.name for path in destination.iterdir())
            == sorted(EVIDENCE_FILES.values()),
            "published evidence file set differs",
        )
        for role, filename in EVIDENCE_FILES.items():
            require(
                (destination / filename).read_bytes() == sources[role].read_bytes(),
                f"published {role} bytes differ",
            )
            require(
                stat.S_IMODE((destination / filename).stat().st_mode) == 0o400,
                f"published {role} mode differs",
            )
        require(
            stat.S_IMODE(destination.stat().st_mode) == 0o500,
            "published evidence directory mode differs",
        )
        try:
            check_evidence_destination(destination)
        except RunnerError:
            pass
        else:
            fail("runner selftest accepted an existing evidence destination")

        mutation_destination = temporary / "mutation-evidence"

        def mutate_staged(bundle: dict[str, pathlib.Path]) -> None:
            bundle["summary"].chmod(0o600)
            bundle["summary"].write_bytes(b"mutated\n")

        try:
            publish_evidence(
                mutation_destination,
                transcript=sources["transcript"],
                summary=sources["summary"],
                environment=sources["environment"],
                decision=sources["decision"],
                staged_verifier=mutate_staged,
            )
        except RunnerError:
            pass
        else:
            fail("runner selftest accepted verifier-stage mutation")
        require(
            not os.path.lexists(mutation_destination),
            "mutation selftest left a final evidence directory",
        )

        source_mutation_destination = temporary / "source-mutation-evidence"
        original_decision = sources["decision"].read_bytes()

        def mutate_source(_: dict[str, pathlib.Path]) -> None:
            sources["decision"].write_bytes(b"source-mutated\n")

        try:
            publish_evidence(
                source_mutation_destination,
                transcript=sources["transcript"],
                summary=sources["summary"],
                environment=sources["environment"],
                decision=sources["decision"],
                staged_verifier=mutate_source,
            )
        except RunnerError:
            pass
        else:
            fail("runner selftest accepted private-source mutation")
        finally:
            sources["decision"].write_bytes(original_decision)
        require(
            not os.path.lexists(source_mutation_destination),
            "source mutation selftest left a final evidence directory",
        )

        race_destination = temporary / "race-evidence"

        def win_destination_race() -> None:
            race_destination.mkdir()

        try:
            publish_evidence(
                race_destination,
                transcript=sources["transcript"],
                summary=sources["summary"],
                environment=sources["environment"],
                decision=sources["decision"],
                staged_verifier=accept_stage,
                before_finalize=win_destination_race,
            )
        except RunnerError:
            pass
        else:
            fail("runner selftest overwrote a racing evidence destination")
        require(
            race_destination.is_dir() and not tuple(race_destination.iterdir()),
            "runner selftest changed a racing evidence destination",
        )
        require(
            not any(
                path.name.startswith(".mutation-evidence.c84-stage-")
                or path.name.startswith(".source-mutation-evidence.c84-stage-")
                or path.name.startswith(".race-evidence.c84-stage-")
                for path in temporary.iterdir()
            ),
            "runner selftest left a hidden publication stage",
        )
        destination.chmod(0o700)
    return checks


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect the fixed single-process QEMU C8.4 AOT decision.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--source-commit", help="canonical 40-hex commit to bind (defaults to HEAD)"
    )
    parser.add_argument(
        "--challenge", help="canonical nonzero 64-hex challenge (random when omitted)"
    )
    parser.add_argument(
        "--allow-dirty-smoke",
        action="store_true",
        help="allow uncommitted development sources; disables publication and evidence export",
    )
    parser.add_argument(
        "--timeout-seconds", type=positive_timeout, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--ready-timeout", type=positive_timeout, default=DEFAULT_READY_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--command-timeout",
        type=positive_timeout,
        default=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--marker-timeout",
        type=positive_timeout,
        default=DEFAULT_MARKER_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--qemu",
        default="qemu-system-riscv64",
        help="QEMU executable; platform options remain fixed",
    )
    parser.add_argument(
        "--evidence-dir",
        type=pathlib.Path,
        help="new directory receiving uart.log, summary.json, environment.json, and DECISION.json",
    )
    return parser


def main() -> int:
    arguments = argument_parser().parse_args()
    try:
        python_runtime = python_runtime_record(startup=True)
        if arguments.selftest:
            supplied_options = {
                argument.partition("=")[0]
                for argument in sys.argv[1:]
                if argument.startswith("--")
            }
            require(
                supplied_options == {"--selftest"},
                "--selftest cannot be combined with capture options",
            )
            checks = selftest()
            recheck_python_runtime(python_runtime)
            print(f"PASS qemu-c84-aot-decision selftest checks={checks}")
            return 0
        require(
            sys.platform == "darwin",
            "C8.4 fixed-QEMU capture requires pinned /usr/bin/ssh on a Darwin sealed system volume",
        )
        if arguments.allow_dirty_smoke and arguments.evidence_dir is not None:
            fail("--allow-dirty-smoke cannot export evidence")
        if not arguments.allow_dirty_smoke and arguments.evidence_dir is None:
            fail("formal publication requires --evidence-dir")
        evidence_destination = check_evidence_destination(arguments.evidence_dir)
        for required in (VERIFIER, *(ROOT / path for path in HELPER_PATHS.values())):
            if not required.is_file():
                fail(f"required maintained helper is missing: {required}")

        head = canonical_hex(
            sanitized_git_line(["rev-parse", "--verify", "HEAD^{commit}"], "HEAD"),
            HEX40,
            40,
            "git HEAD",
        )
        source_commit = canonical_hex(
            arguments.source_commit or head, HEX40, 40, "source commit"
        )
        if source_commit != head:
            fail(f"source commit must equal current HEAD {head}, got {source_commit}")
        challenge = canonical_hex(
            arguments.challenge or secrets.token_hex(32), HEX64, 64, "challenge"
        )
        publication = not arguments.allow_dirty_smoke
        capture_mode = FORMAL_CAPTURE_MODE if publication else SMOKE_CAPTURE_MODE
        feature = FORMAL_FEATURE if publication else SMOKE_FEATURE
        if publication and source_commit == TEST_ONLY_SOURCE_COMMIT:
            fail("formal publication cannot use the documented test source sentinel")
        if publication and challenge == TEST_ONLY_CHALLENGE:
            fail("formal publication cannot use the documented test challenge sentinel")
        repository_before = check_repository(
            source_commit, allow_dirty=arguments.allow_dirty_smoke
        )
        started_at = BASE.utc_now()
        if not publication:
            print(
                "WARNING: dirty smoke mode is not C8.4 decision evidence and cannot export artifacts.",
                file=sys.stderr,
            )
        print(
            f"C8.4 QEMU decision: mode={capture_mode} source={source_commit} challenge={challenge}",
            file=sys.stderr,
        )

        helper_identities = collect_helper_identities()
        runner_identity = identity_only(pathlib.Path(__file__).resolve())
        verifier_identity = identity_only(VERIFIER)
        with tempfile.TemporaryDirectory(
            prefix="vibeos-c84-qemu-decision-", dir="/tmp"
        ) as temporary_name:
            temporary = pathlib.Path(temporary_name).resolve(strict=True)
            if publication:
                source_root, source_materialization, expected_source_files = (
                    materialize_source(source_commit, temporary)
                )
            else:
                source_root = ROOT
                source_materialization = smoke_source_record(source_commit)
                expected_source_files = {}
            cargo_target = temporary / "cargo-target"
            cargo_target.mkdir(mode=0o700)
            require(
                not tuple(cargo_target.iterdir()),
                "private Cargo target must begin empty",
            )
            kernel = cargo_target / KERNEL_RELATIVE
            private_cargo_sources, private_cargo_record = materialize_locked_crates(
                source_root, temporary
            )
            private_crate_archives = temporary / "crate-archives"
            private_cargo_home = temporary / "private-cargo-home"
            private_cargo_home.mkdir(mode=0o700)
            commit_timestamp = str(repository_before["commit_timestamp"])
            toolchain = build_kernel(
                source_commit,
                challenge,
                feature,
                source_root=source_root,
                cargo_target_dir=cargo_target,
                kernel=kernel,
                commit_timestamp=commit_timestamp,
                private_cargo_home=private_cargo_home,
                private_cargo_sources=private_cargo_sources,
                private_crate_archives=private_crate_archives,
                private_cargo_record=private_cargo_record,
            )
            check_repository(
                source_commit,
                allow_dirty=arguments.allow_dirty_smoke,
                expected_local_configs=repository_before["local_configs"],
            )
            if publication:
                verify_materialized_source(source_root, expected_source_files)

            qemu_path = pathlib.Path(resolve_qemu(arguments.qemu)).resolve(strict=True)
            qemu_identity = identity_only(qemu_path)
            require(
                qemu_identity
                == {"sha256": PINNED_QEMU_SHA256, "bytes": PINNED_QEMU_BYTES},
                "QEMU binary differs from the frozen QEMU-v1 platform",
            )
            # Hash the freshly built kernel and create the shared deny-by-default
            # QEMU environment before the first QEMU execution of any kind.
            kernel_identity = identity_only(kernel)
            qemu_process_environment, qemu_environment_record = (
                create_qemu_environment(temporary)
            )
            source_runtime_before = qemu_runtime_closure(qemu_path)
            require(
                source_runtime_before["graph_sha256"]
                == PINNED_QEMU_RUNTIME_GRAPH_SHA256,
                "QEMU runtime graph differs from the preparation manifest",
            )
            require(
                {
                    "nodes": source_runtime_before["node_count"],
                    "load_edges": source_runtime_before["load_edge_count"],
                    "pinned_homebrew_edges": source_runtime_before[
                        "pinned_homebrew_edge_count"
                    ],
                    "sealed_system_edges": source_runtime_before[
                        "sealed_system_edge_count"
                    ],
                }
                == PINNED_QEMU_RUNTIME_COUNTS,
                "QEMU runtime graph counts differ from the preparation manifest",
            )
            bios = resolve_bios(
                str(qemu_path), qemu_environment=qemu_process_environment
            ).resolve(strict=True)
            require(
                identity_only(qemu_path) == qemu_identity,
                "QEMU executable changed while resolving OpenSBI",
            )
            require(
                qemu_runtime_closure(qemu_path) == source_runtime_before,
                "QEMU runtime closure changed during the firmware search probe",
            )
            require(
                identity_only(kernel) == kernel_identity,
                "kernel ELF changed during the firmware search probe",
            )
            bios_identity = identity_only(bios)
            require(
                bios_identity
                == {"sha256": PINNED_BIOS_SHA256, "bytes": PINNED_BIOS_BYTES},
                "OpenSBI firmware differs from the frozen QEMU-v1 platform",
            )
            openssh_attestation = darwin_system_openssh_record()
            ssh_path = DARWIN_SYSTEM_OPENSSH
            openssh_identity = {
                "sha256": openssh_attestation["sha256"],
                "bytes": openssh_attestation["bytes"],
            }
            openssh_version = str(openssh_attestation["version"])
            source_identities = {
                "qemu": qemu_identity,
                "bios": bios_identity,
                "kernel_elf": kernel_identity,
            }
            custody_directory: pathlib.Path | None = None
            custody_directory, execution_paths, execution_custody = (
                create_execution_custody(
                    temporary,
                    qemu=qemu_path,
                    bios=bios,
                    kernel=kernel,
                    identities=source_identities,
                    openssh_attestation=openssh_attestation,
                )
            )
            custody_runtime_before = qemu_runtime_closure(execution_paths["qemu"])
            require(
                custody_runtime_before["graph_sha256"]
                == source_runtime_before["graph_sha256"],
                "source and custody QEMU runtime graphs differ",
            )
            try:
                qemu_version = run_qemu_version(
                    str(execution_paths["qemu"]),
                    qemu_environment=qemu_process_environment,
                )
                require(
                    qemu_version.splitlines()[0] == PINNED_QEMU_VERSION,
                    "QEMU version differs from the frozen QEMU-v1 platform",
                )
                host_port = pick_loopback_port()
                qemu_data_directory = (
                    pathlib.Path(qemu_process_environment["HOME"]).parent / "data"
                )
                actual_qemu_argv = qemu_command(
                    str(execution_paths["qemu"]),
                    execution_paths["bios"],
                    execution_paths["kernel_elf"],
                    qemu_data_directory,
                    host_port,
                )
                normalized_qemu_argv = normalize_qemu_command(
                    actual_qemu_argv,
                    qemu=str(execution_paths["qemu"]),
                    bios=execution_paths["bios"],
                    kernel=execution_paths["kernel_elf"],
                    data_directory=qemu_data_directory,
                    host_port=host_port,
                )
                qemu_module_search = qemu_module_search_record(
                    qemu_path,
                    qemu_environment=qemu_process_environment,
                    qemu_argv=actual_qemu_argv,
                    data_directory=qemu_data_directory,
                )
                transcript = temporary / EVIDENCE_FILES["transcript"]
                summary = temporary / EVIDENCE_FILES["summary"]
                environment = temporary / EVIDENCE_FILES["environment"]
                decision = temporary / EVIDENCE_FILES["decision"]
                accepted_key = temporary / "id_ed25519_accepted"
                rejected_key = temporary / "id_ed25519_rejected"
                known_hosts = temporary / "known_hosts"
                host_key = temporary / "host-key.pub"
                generate_key(
                    "accepted", "vibeos-c84-qemu-decision-accepted", accepted_key
                )
                generate_key(
                    "rejected", "vibeos-c84-qemu-decision-rejected", rejected_key
                )

                verify_execution_custody(
                    custody_directory, execution_paths, execution_custody
                )
                raw, peer_result, executed_peer_sources = capture_qemu(
                    qemu_argv=actual_qemu_argv,
                    ssh=str(ssh_path),
                    host_port=host_port,
                    timeout=arguments.timeout_seconds,
                    ready_timeout=arguments.ready_timeout,
                    command_timeout=arguments.command_timeout,
                    marker_timeout=arguments.marker_timeout,
                    transcript=transcript,
                    accepted_key=accepted_key,
                    rejected_key=rejected_key,
                    known_hosts=known_hosts,
                    host_key=host_key,
                    source_commit=source_commit,
                    challenge=challenge,
                    capture_mode=capture_mode,
                    qemu_environment=qemu_process_environment,
                    helper_identities=helper_identities,
                )
                metadata = formal_metadata(raw, source_commit, challenge, capture_mode)
                run_id = metadata["run_id"]
                summary_result = invoke_verifier_summary(
                    transcript,
                    summary,
                    source_commit,
                    challenge,
                    capture_mode,
                )
                validate_summary_identity(
                    summary,
                    source_commit=source_commit,
                    challenge=challenge,
                    run_id=run_id,
                    capture_mode=capture_mode,
                )

                check_repository(
                    source_commit,
                    allow_dirty=arguments.allow_dirty_smoke,
                    expected_local_configs=repository_before["local_configs"],
                )
                if identity_only(kernel) != kernel_identity:
                    fail("kernel ELF changed between build and verified capture")
                if identity_only(qemu_path) != qemu_identity:
                    fail("QEMU executable changed during verified capture")
                if identity_only(bios) != bios_identity:
                    fail("OpenSBI firmware changed during verified capture")
                verify_execution_custody(
                    custody_directory, execution_paths, execution_custody
                )
                source_runtime_after = qemu_runtime_closure(qemu_path)
                custody_runtime_after = qemu_runtime_closure(execution_paths["qemu"])
                require(
                    source_runtime_after == source_runtime_before,
                    "source QEMU runtime closure changed during capture",
                )
                require(
                    custody_runtime_after == custody_runtime_before,
                    "custody QEMU runtime closure changed during capture",
                )
                require(
                    source_runtime_after["graph_sha256"]
                    == custody_runtime_after["graph_sha256"],
                    "source and custody QEMU runtime graphs diverged during capture",
                )
                if publication:
                    verify_materialized_source(source_root, expected_source_files)
                if identity_only(VERIFIER) != verifier_identity:
                    fail("independent verifier changed during verified capture")
                if identity_only(pathlib.Path(__file__).resolve()) != runner_identity:
                    fail("C8.4 runner changed during verified capture")
                recheck_helper_identities(helper_identities)
                recheck_toolchain(
                    toolchain,
                    source_root=source_root,
                    private_cargo_home=private_cargo_home,
                    private_cargo_sources=private_cargo_sources,
                    private_crate_archives=private_crate_archives,
                )
                require(
                    normalized_qemu_environment(qemu_process_environment)
                    == qemu_environment_record,
                    "QEMU environment changed during verified capture",
                )
                repository_after = check_repository(
                    source_commit,
                    allow_dirty=arguments.allow_dirty_smoke,
                    expected_local_configs=repository_before["local_configs"],
                )
                ended_at = BASE.utc_now()
                recheck_python_runtime(python_runtime)
                source_runtime_final = qemu_runtime_closure(qemu_path)
                custody_runtime_final = qemu_runtime_closure(execution_paths["qemu"])
                require(
                    source_runtime_final == source_runtime_before
                    and custody_runtime_final == custody_runtime_before
                    and source_runtime_final["graph_sha256"]
                    == custody_runtime_final["graph_sha256"],
                    "QEMU runtime closure changed before evidence creation",
                )
                qemu_runtime_closures = {
                    "policy": "source-and-execution-custody-pre-post-final-v1",
                    "host_exclusivity_limit": QEMU_RUNTIME_HOST_LIMIT,
                    "module_search": qemu_module_search,
                    "source": {
                        "before": source_runtime_before,
                        "after": source_runtime_after,
                        "final": source_runtime_final,
                    },
                    "execution_custody": {
                        "before": custody_runtime_before,
                        "after": custody_runtime_after,
                        "final": custody_runtime_final,
                    },
                }
                write_environment(
                    environment,
                    capture_mode=capture_mode,
                    source_commit=source_commit,
                    challenge=challenge,
                    run_id=run_id,
                    started_at=started_at,
                    ended_at=ended_at,
                    repository_before=repository_before,
                    repository_after=repository_after,
                    source_materialization=source_materialization,
                    toolchain=toolchain,
                    qemu_version=qemu_version,
                    qemu_path=str(qemu_path),
                    qemu_identity=qemu_identity,
                    qemu_actual_argv=actual_qemu_argv,
                    qemu_normalized_argv=normalized_qemu_argv,
                    qemu_environment=qemu_environment_record,
                    qemu_runtime_closures=qemu_runtime_closures,
                    bios_identity=bios_identity,
                    bios_path=bios,
                    kernel_identity=kernel_identity,
                    openssh_version=openssh_version,
                    openssh_path=str(ssh_path),
                    openssh_identity=openssh_identity,
                    execution_custody=execution_custody,
                    host_key_identity=canonical_host_key_evidence(host_key),
                    helper_identities=helper_identities,
                    executed_peer_sources=executed_peer_sources,
                    python_runtime=python_runtime,
                    transcript=transcript,
                    summary=summary,
                )
                decision_result = invoke_verifier_decision(
                    transcript,
                    summary,
                    environment,
                    decision,
                    source_commit,
                    challenge,
                    capture_mode,
                    str(qemu_path),
                    bios,
                    kernel,
                    str(ssh_path),
                    source_root,
                    source_root if publication else None,
                    execution_paths,
                    toolchain,
                    private_cargo_home,
                    private_cargo_sources,
                    private_crate_archives,
                    publication=publication,
                )
                if not decision.is_file() or decision.stat().st_size == 0:
                    fail("independent verifier did not create DECISION.json")
                check_repository(
                    source_commit,
                    allow_dirty=arguments.allow_dirty_smoke,
                    expected_local_configs=repository_before["local_configs"],
                )
                if identity_only(VERIFIER) != verifier_identity:
                    fail("independent verifier changed before publication closure")
                if identity_only(pathlib.Path(__file__).resolve()) != runner_identity:
                    fail("C8.4 runner changed before publication closure")
                recheck_helper_identities(helper_identities)
                recheck_python_runtime(python_runtime)
                if identity_only(kernel) != kernel_identity:
                    fail("kernel ELF changed before publication closure")
                if identity_only(qemu_path) != qemu_identity:
                    fail("QEMU executable changed before publication closure")
                if identity_only(bios) != bios_identity:
                    fail("OpenSBI firmware changed before publication closure")
                verify_execution_custody(
                    custody_directory, execution_paths, execution_custody
                )
                require(
                    qemu_runtime_closure(qemu_path) == source_runtime_final
                    and qemu_runtime_closure(execution_paths["qemu"])
                    == custody_runtime_final,
                    "QEMU runtime closure changed before publication closure",
                )
                require(
                    qemu_module_search_record(
                        qemu_path,
                        qemu_environment=qemu_process_environment,
                        qemu_argv=actual_qemu_argv,
                        data_directory=qemu_data_directory,
                    )
                    == qemu_module_search,
                    "QEMU module search closure changed before publication",
                )
                if publication:
                    verify_materialized_source(source_root, expected_source_files)
                recheck_toolchain(
                    toolchain,
                    source_root=source_root,
                    private_cargo_home=private_cargo_home,
                    private_cargo_sources=private_cargo_sources,
                    private_crate_archives=private_crate_archives,
                )
                if evidence_destination is not None:
                    publish_evidence(
                        evidence_destination,
                        transcript=transcript,
                        summary=summary,
                        environment=environment,
                        decision=decision,
                        staged_verifier=lambda bundle: invoke_verifier_staged_publication(
                            bundle,
                            source_commit=source_commit,
                            challenge=challenge,
                            capture_mode=capture_mode,
                            qemu=str(qemu_path),
                            bios=bios,
                            kernel=kernel,
                            ssh=str(ssh_path),
                            materialized_source=source_root,
                            execution_paths=execution_paths,
                            toolchain=toolchain,
                            private_cargo_home=private_cargo_home,
                            private_crate_sources=private_cargo_sources,
                            private_crate_archives=private_crate_archives,
                        ),
                    )
            finally:
                release_execution_custody(custody_directory)

        for result in (peer_result, summary_result, decision_result):
            if result:
                print(result)
        print(
            "PASS qemu-c84-aot-decision "
            f"mode={capture_mode} source={source_commit} challenge={challenge} "
            f"run_id={run_id} uart_sha256={hashlib.sha256(raw).hexdigest()} "
            "fresh_qemu_processes=1 physical_provenance=not-claimed"
        )
        if evidence_destination is not None:
            print(f"C8.4 QEMU evidence: {evidence_destination}")
        return 0
    except (RunnerError, BASE.RunnerError) as error:
        print(f"FAIL qemu-c84-aot-decision: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
