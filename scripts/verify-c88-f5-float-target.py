#!/usr/bin/env python3
"""Strictly verify one C8.8-F5 fixed-QEMU UART transcript.

The verifier deliberately shares no parser or record-construction code with the
Rust producer.  It accepts only the closed META -> CORE_CASE -> F3_CASE ->
F4_VECTOR -> FUEL -> LIFECYCLE -> END -> PASS grammar, binds the transcript to
the runner-produced environment envelope, and rejects every unknown, duplicate,
missing, reordered, or post-terminal C8.8-F5 family record.

The semantic digest is SHA-256 over each data record in wire order.  For each
record it hashes the ASCII family name, one NUL byte, and canonical compact JSON
of the semantic fields (all common ``schema``, ``version``, ``run_id``, and
``sequence`` fields are omitted), followed by one newline.  The digest begins
with ``SEMANTIC_DIGEST_DOMAIN``.  This makes it stable across capture challenges
while still binding every exact bit, fuel, and lifecycle observation.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
from typing import Callable, Iterable, NoReturn


ROOT = pathlib.Path(__file__).resolve().parent.parent
SUITE_ID = "vibeos.c88.f5.float-target"
SCHEMA_VERSION = 1
RUN_ID_DOMAIN = b"vibeos.c88.f5.float-target.run.v1\0"
SEMANTIC_DIGEST_DOMAIN = b"vibeos.c88.f5.float-target.semantic.v1\0"

FAMILY_PREFIX = "VIBE_C88_F5_"
PREFIXES = {
    "META": "VIBE_C88_F5_META ",
    "CORE_CASE": "VIBE_C88_F5_CORE_CASE ",
    "F3_CASE": "VIBE_C88_F5_F3_CASE ",
    "F4_VECTOR": "VIBE_C88_F5_F4_VECTOR ",
    "FUEL": "VIBE_C88_F5_FUEL ",
    "LIFECYCLE": "VIBE_C88_F5_LIFECYCLE ",
    "END": "VIBE_C88_F5_END ",
    "PASS": "VIBE_C88_F5_PASS ",
    "FAIL": "VIBE_C88_F5_FAIL",
}
FAMILY_ORDER = {
    "META": 0,
    "CORE_CASE": 1,
    "F3_CASE": 2,
    "F4_VECTOR": 3,
    "FUEL": 4,
    "LIFECYCLE": 5,
    "END": 6,
    "PASS": 7,
}
DATA_FAMILIES = ("CORE_CASE", "F3_CASE", "F4_VECTOR", "FUEL", "LIFECYCLE")

SCHEMAS = {
    "META": "vibeos.c88.f5.float-target.meta",
    "CORE_CASE": "vibeos.c88.f5.float-target.core-case",
    "F3_CASE": "vibeos.c88.f5.float-target.f3-case",
    "F4_VECTOR": "vibeos.c88.f5.float-target.f4-vector",
    "FUEL": "vibeos.c88.f5.float-target.fuel",
    "LIFECYCLE": "vibeos.c88.f5.float-target.lifecycle",
    "END": "vibeos.c88.f5.float-target.end",
    "PASS": "vibeos.c88.f5.float-target.pass",
}

MAX_UART_BYTES = 16 * 1024 * 1024
MAX_ENVIRONMENT_BYTES = 1024 * 1024
MAX_UART_LINES = 20_000
MAX_KERNEL_BYTES = 256 * 1024 * 1024
MAX_ELF_AUDIT_BYTES = 4 * 1024 * 1024
MAX_RUST_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_RUST_SOURCE_FILES = 20_000
MAX_RUST_SOURCE_BYTES = 256 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
RUST_SOURCE_TREE_DOMAIN = b"vibeos.c88.f5.rust-source-tree.v1\0"
HEX8 = re.compile(r"[0-9a-f]{8}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CASE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
RESULT_TOKEN = re.compile(r"(?:[0-9a-f]{8}|[0-9a-f]{16}|trap:[a-z0-9-]+)\Z")
FATAL_MARKERS = ("panicked at", "panic", "fatal")

EXPECTED_COMPONENT_SHA256 = (
    "5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a"
)
EXPECTED_WIT_SHA256 = "4c2b4d994caee3755671b89a0dfe92136fd3d130f001d5ac660aa988371f31ac"
EXPECTED_WORLD = "vibe:float-acceptance/lifecycle@1.0.0"
EXPECTED_EXPORT = "run"
EXPECTED_ACTIVATION_LABEL = "c88-f4-float-candidate"

EXPECTED_CANDIDATE = {
    "candidate_package": "vibeos-wasmi-softfloat",
    "candidate_version": "1.1.0-vibeos-f2.1",
    "candidate_upstream_commit": "8273dfb09d493971b7bb12fe614d740cdc857175",
    "candidate_manifest_sha256": "2d94218e4fa5eea30b8e516e055fae8f72465dbc1ef75f8b1df3495cbcd0432f",
    "candidate_patch_sha256": "3d2aec1d7e510fc3b3edb87dcacb2d4ed34eb448356704a027841b047938ec64",
    "backend_package": "rustc_apfloat",
    "backend_version": "0.2.3+llvm-462a31f5a5ab",
    "backend_archive_sha256": "486c2179b4796f65bfe2ee33679acf0927ac83ecf583ad6c91c3b4570911b9ad",
    "backend_revision": "eeaacad81247af65d4043cb3e32d023a652d7951",
    "backend_llvm_revision": "462a31f5a5abb905869ea93cc49b096079b11aa4",
    "candidate_feature_set": (
        "default-features=false,extra-checks,prefer-btree-collections;simd=false"
    ),
    "candidate_acceptance_feature": "c88-f2-acceptance",
}

EXPECTED_CORE_MODULE_SHA256 = (
    "6e1cb23543bdfbbb9397c3dd5ad69b2f023d23cf292f652029da838d098121ba"
)
EXPECTED_CORE_MODULE_BYTES = 4_179
EXPECTED_CORE_COMPILE_RESERVATION_BYTES = 135_720
EXPECTED_CORE_MEMORY_BYTES = 65_536
EXPECTED_CORE_RUNTIME_DIGEST = "3fb93000b75809b0"
EXPECTED_CORE_FOLD_DIGEST = "297281268f516746"
EXPECTED_CORE_SPIN_TRACE_DIGEST = "af2dde3985716198"
EXPECTED_SEMANTIC_SHA256 = (
    "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1"
)
EXPECTED_MANIFEST_SHA256 = (
    "39abd7d8bf25f2da2dfe76109e0811202ba05a9dbc17501ef7a6c2a905c81d76"
)
EXPECTED_MANIFEST_BYTES = 2_090
EXPECTED_QEMU_IDENTITY = {
    "path": "/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-riscv64",
    "sha256": "ef5c714232320c22561daa0998546b73672e21a2801404714dfbd4982ac7b3c0",
    "bytes": 13_511_488,
}
EXPECTED_QEMU_VERSION = (
    "QEMU emulator version 11.0.3\n"
    "Copyright (c) 2003-2026 Fabrice Bellard and the QEMU Project developers"
)
EXPECTED_BIOS_IDENTITY = {
    "path": (
        "/opt/homebrew/Cellar/qemu/11.0.3/share/qemu/"
        "opensbi-riscv64-generic-fw_dynamic.bin"
    ),
    "sha256": "49bdf7b939bda11321132d1042bf99d7324fb190f1feef423171fed3573f8705",
    "bytes": 273_048,
}
EXPECTED_BUILD_TOOLS = {
    "rustup": {
        "path": "/opt/homebrew/Cellar/rustup/1.29.0_2/bin/rustup",
        "sha256": "8e771bda7618d9712b73552ddfc8cff6fb595fc5d012671c4e4f8726f8746857",
        "bytes": 161,
    },
    "cargo": {
        "path": (
            "/Users/ziangwang/.rustup/toolchains/"
            "nightly-2026-08-01-aarch64-apple-darwin/bin/cargo"
        ),
        "sha256": "0708e47bfb74142d930fc57546e26b99772d3491759f3bada32c8c070ad1c8f3",
        "bytes": 32_102_952,
    },
    "rustc": {
        "path": (
            "/Users/ziangwang/.rustup/toolchains/"
            "nightly-2026-08-01-aarch64-apple-darwin/bin/rustc"
        ),
        "sha256": "fa817099946eee0d4a4ed1d6593b05596f34f92181363e467c6253e84ce431af",
        "bytes": 413_480,
    },
    "rustdoc": {
        "path": (
            "/Users/ziangwang/.rustup/toolchains/"
            "nightly-2026-08-01-aarch64-apple-darwin/bin/rustdoc"
        ),
        "sha256": "31483e89389e87370faf2d09fbfaa9127cae0156212056ce836c0d102a09a785",
        "bytes": 11_131_224,
    },
    "linker": {
        "path": "/opt/homebrew/Cellar/lld/22.1.8/bin/lld",
        "sha256": "49360efaf217d95b91799645d390f38eda27132d5dbdbe2ab459d361d3282f3b",
        "bytes": 41_264,
    },
}
EXPECTED_RUST_SOURCE = {
    "path": (
        "/Users/ziangwang/.rustup/toolchains/"
        "nightly-2026-08-01-aarch64-apple-darwin/lib/rustlib/src/rust/library"
    ),
    "files": 3_603,
    "bytes": 71_790_604,
    "tree_sha256": "862c90e2437d073ed9a078bb91c1aefc9280c5254e5933960093f695a0a40871",
}
EXPECTED_ELF_AUDIT_TOOL_IDENTITIES = {
    "rustc": {
        "bytes": 413_480,
        "sha256": "fa817099946eee0d4a4ed1d6593b05596f34f92181363e467c6253e84ce431af",
    },
    "llvm-readobj": {
        "bytes": 1_791_936,
        "sha256": "5c388043b0ce7698cbce64e9ca94c2d397bad0018b7a104c4da5a0b8348053a4",
    },
    "llvm-objdump": {
        "bytes": 943_328,
        "sha256": "82a155f861d4c87deaed3c85193a645f4556a60c4634ff13b09cde44fa5d6ec7",
    },
    "llvm-nm": {
        "bytes": 166_008,
        "sha256": "096bc03c2848d5d99d78e3e2c3671092c67cedafef9c8c46d9c1b54f63215d4a",
    },
}

# Ordered independently frozen F2 scalar-op matrix.  Every value is the exact
# u64 integer-bit representation crossing the candidate boundary.  The runtime
# and fold witnesses are interleaved per operation, matching the producer's
# append order; the fold path receives only the operation index and therefore
# reports zero for both dynamic input slots.
EXPECTED_CORE_VECTORS = (
    ("f32-add", "000000003fc00000", "000000003f000000", "0000000040000000"),
    ("f32-sub", "000000003fc00000", "000000003f000000", "000000003f800000"),
    ("f32-mul", "000000003fc00000", "000000003f000000", "000000003f400000"),
    ("f32-div", "000000003fc00000", "000000003f000000", "0000000040400000"),
    ("f32-min", "000000003fc00000", "000000003f000000", "000000003f000000"),
    ("f32-max", "000000003fc00000", "000000003f000000", "000000003fc00000"),
    ("f32-copysign", "000000003fc00000", "00000000bf000000", "00000000bfc00000"),
    ("f64-add", "3ff8000000000000", "3fe0000000000000", "4000000000000000"),
    ("f64-sub", "3ff8000000000000", "3fe0000000000000", "3ff0000000000000"),
    ("f64-mul", "3ff8000000000000", "3fe0000000000000", "3fe8000000000000"),
    ("f64-div", "3ff8000000000000", "3fe0000000000000", "4008000000000000"),
    ("f64-min", "3ff8000000000000", "3fe0000000000000", "3fe0000000000000"),
    ("f64-max", "3ff8000000000000", "3fe0000000000000", "3ff8000000000000"),
    ("f64-copysign", "3ff8000000000000", "bfe0000000000000", "bff8000000000000"),
    ("f32-abs", "00000000bfc00000", "0000000000000000", "000000003fc00000"),
    ("f32-neg", "000000003fc00000", "0000000000000000", "00000000bfc00000"),
    ("f32-ceil", "000000003fa00000", "0000000000000000", "0000000040000000"),
    ("f32-floor", "000000003fe00000", "0000000000000000", "000000003f800000"),
    ("f32-trunc", "00000000bfe00000", "0000000000000000", "00000000bf800000"),
    ("f32-nearest", "0000000040200000", "0000000000000000", "0000000040000000"),
    ("f32-sqrt", "0000000040800000", "0000000000000000", "0000000040000000"),
    ("f64-abs", "bff8000000000000", "0000000000000000", "3ff8000000000000"),
    ("f64-neg", "3ff8000000000000", "0000000000000000", "bff8000000000000"),
    ("f64-ceil", "3ff4000000000000", "0000000000000000", "4000000000000000"),
    ("f64-floor", "3ffc000000000000", "0000000000000000", "3ff0000000000000"),
    ("f64-trunc", "bffc000000000000", "0000000000000000", "bff0000000000000"),
    ("f64-nearest", "4004000000000000", "0000000000000000", "4000000000000000"),
    ("f64-sqrt", "4010000000000000", "0000000000000000", "4000000000000000"),
    ("f32-eq", "000000003fc00000", "000000003fc00000", "0000000000000001"),
    ("f32-ne", "000000003fc00000", "000000003f000000", "0000000000000001"),
    ("f32-lt", "000000003f000000", "000000003fc00000", "0000000000000001"),
    ("f32-gt", "000000003fc00000", "000000003f000000", "0000000000000001"),
    ("f32-le", "000000003fc00000", "000000003fc00000", "0000000000000001"),
    ("f32-ge", "000000003fc00000", "000000003fc00000", "0000000000000001"),
    ("f64-eq", "3ff8000000000000", "3ff8000000000000", "0000000000000001"),
    ("f64-ne", "3ff8000000000000", "3fe0000000000000", "0000000000000001"),
    ("f64-lt", "3fe0000000000000", "3ff8000000000000", "0000000000000001"),
    ("f64-gt", "3ff8000000000000", "3fe0000000000000", "0000000000000001"),
    ("f64-le", "3ff8000000000000", "3ff8000000000000", "0000000000000001"),
    ("f64-ge", "3ff8000000000000", "3ff8000000000000", "0000000000000001"),
    ("i32-trunc-f32-s", "00000000c0f80000", "0000000000000000", "fffffffffffffff9"),
    ("i32-trunc-f32-u", "0000000040f80000", "0000000000000000", "0000000000000007"),
    ("i64-trunc-f32-s", "00000000c0f80000", "0000000000000000", "fffffffffffffff9"),
    ("i64-trunc-f32-u", "0000000040f80000", "0000000000000000", "0000000000000007"),
    ("i32-trunc-f64-s", "c01f000000000000", "0000000000000000", "fffffffffffffff9"),
    ("i32-trunc-f64-u", "401f000000000000", "0000000000000000", "0000000000000007"),
    ("i64-trunc-f64-s", "c01f000000000000", "0000000000000000", "fffffffffffffff9"),
    ("i64-trunc-f64-u", "401f000000000000", "0000000000000000", "0000000000000007"),
    ("f32-convert-i32-s", "00000000fffffff9", "0000000000000000", "00000000c0e00000"),
    ("f32-convert-i32-u", "00000000ffffffff", "0000000000000000", "000000004f800000"),
    ("f32-convert-i64-s", "fffffffffffffff9", "0000000000000000", "00000000c0e00000"),
    ("f32-convert-i64-u", "ffffffffffffffff", "0000000000000000", "000000005f800000"),
    ("f64-convert-i32-s", "00000000fffffff9", "0000000000000000", "c01c000000000000"),
    ("f64-convert-i32-u", "00000000ffffffff", "0000000000000000", "41efffffffe00000"),
    ("f64-convert-i64-s", "fffffffffffffff9", "0000000000000000", "c01c000000000000"),
    ("f64-convert-i64-u", "ffffffffffffffff", "0000000000000000", "43f0000000000000"),
    ("f64-promote-f32", "000000003fc00000", "0000000000000000", "3ff8000000000000"),
    ("f32-demote-f64", "3ff8000000000000", "0000000000000000", "000000003fc00000"),
    ("f32-local", "000000003fc00000", "0000000000000000", "000000003fc00000"),
    ("f64-local", "3ff8000000000000", "0000000000000000", "3ff8000000000000"),
    ("f32-global", "000000003fc00000", "0000000000000000", "000000003fc00000"),
    ("f64-global", "3ff8000000000000", "0000000000000000", "3ff8000000000000"),
    ("f32-memory", "000000003fc00000", "0000000000000000", "000000003fc00000"),
    ("f64-memory", "3ff8000000000000", "0000000000000000", "3ff8000000000000"),
    ("f32-select", "000000003fc00000", "0000000000000000", "000000003fc00000"),
    ("f64-select", "3ff8000000000000", "0000000000000000", "3ff8000000000000"),
    ("f32-call", "000000003fc00000", "0000000000000000", "000000003fc00000"),
    ("f64-call", "3ff8000000000000", "0000000000000000", "3ff8000000000000"),
    ("f32-reinterpret", "000000003fc00000", "0000000000000000", "000000003fc00000"),
    ("f64-reinterpret", "3ff8000000000000", "0000000000000000", "3ff8000000000000"),
    (
        "invalid-conversion",
        "000000007f800001",
        "0000000000000000",
        "trap:invalid-conversion-to-integer",
    ),
    (
        "integer-overflow",
        "7ff0000000000000",
        "0000000000000000",
        "trap:integer-overflow",
    ),
)


def frozen_core_cases() -> tuple[dict[str, object], ...]:
    cases: list[dict[str, object]] = []
    zero = "0000000000000000"
    for op_index, (identifier, input0, input1, expected) in enumerate(
        EXPECTED_CORE_VECTORS
    ):
        cases.append(
            {
                "case_id": f"runtime-{identifier}",
                "path": "runtime",
                "op_index": op_index,
                "input0": input0,
                "input1": input1,
                "expected": expected,
            }
        )
        cases.append(
            {
                "case_id": f"fold-{identifier}",
                "path": "fold",
                "op_index": op_index,
                "input0": zero,
                "input1": zero,
                "expected": expected,
            }
        )
    for identifier in ("spin-a", "spin-b"):
        cases.append(
            {
                "case_id": identifier,
                "path": "spin",
                "op_index": len(EXPECTED_CORE_VECTORS),
                "input0": zero,
                "input1": zero,
                "expected": "trap:fuel-exhausted",
            }
        )
    return tuple(cases)


EXPECTED_CORE_CASES = frozen_core_cases()

F3_RAW_F32 = (
    "00000000",
    "80000000",
    "00000001",
    "007fffff",
    "00800000",
    "7f7fffff",
    "7f800000",
    "ff800000",
    "7fc00000",
    "7f800001",
    "ff800001",
    "ffffffff",
)
F3_RAW_F64 = (
    "0000000000000000",
    "8000000000000000",
    "0000000000000001",
    "000fffffffffffff",
    "0010000000000000",
    "7fefffffffffffff",
    "7ff0000000000000",
    "fff0000000000000",
    "7ff8000000000000",
    "7ff0000000000001",
    "fff0000000000001",
    "ffffffffffffffff",
)
F3_CASE_IDS = (
    "positive-zero",
    "negative-zero",
    "minimum-subnormal",
    "maximum-subnormal",
    "minimum-normal",
    "maximum-finite",
    "positive-infinity",
    "negative-infinity",
    "canonical-nan",
    "positive-signaling-nan",
    "negative-signaling-nan",
    "maximum-payload-nan",
)

EXPECTED_F3_SUMMARY = {
    "scalar_cases": 24,
    "flat_cases": 48,
    "memory_cases": 24,
    "indirect_cases": 3,
    "variant_cases": 1,
    "nested_cases": 1,
    "hostile_rejections": 3,
    "allocations": 4,
    "allocated_bytes": 108,
    "digest": "6a8667851156a05c",
}

# Exact image-pinned F4 vector order.  Values are raw Component inputs and the
# post-Canonical-ABI f64 result, all represented as fixed-width lowercase hex.
EXPECTED_F4_VECTORS = (
    ("positive-zero", "00000000", "0000000000000000", "0000000000000000"),
    ("negative-zero", "80000000", "8000000000000000", "8000000000000000"),
    ("opposite-zero", "80000000", "0000000000000000", "0000000000000000"),
    ("finite", "3fc00000", "4002000000000000", "400e000000000000"),
    ("finite-cancellation", "bf800000", "3ff0000000000000", "0000000000000000"),
    ("f32-subnormal-promote", "00000001", "0000000000000000", "36a0000000000000"),
    ("f64-subnormal", "00000000", "0000000000000001", "0000000000000001"),
    ("round-tie-even", "3f800000", "3ca0000000000000", "3ff0000000000000"),
    ("round-up-two-ulp", "3f800000", "3cb8000000000000", "3ff0000000000002"),
    ("opposite-infinities", "ff800000", "7ff0000000000000", "7ff8000000000000"),
    (
        "f32-signaling-nan-boundary",
        "ff800001",
        "0000000000000000",
        "7ff8000000000000",
    ),
    (
        "f64-signaling-nan-boundary",
        "00000000",
        "fff0000000000001",
        "7ff8000000000000",
    ),
)

EXPECTED_FUEL_CASE_ID = "policy-fuel-exhaustion"
EXPECTED_PENDING_FUEL_RECORDS = 999
EXPECTED_FUEL_RECORDS = EXPECTED_PENDING_FUEL_RECORDS + 1
EXPECTED_FUEL_TRACE_DIGEST = "137746153ac6133c"

EXPECTED_LIFECYCLE_STEPS = (
    ("cancelled", "cancelled"),
    ("unreachable-fault", "faulted-unreachable"),
    ("fuel-fault", "faulted-fuel-exhausted"),
    ("recovered", "idle"),
    ("revoked", "revoked"),
)

META_KEYS = {
    "schema",
    "version",
    "suite_id",
    "suite_revision",
    "source_commit",
    "source_tree",
    "challenge",
    "run_id",
    "manifest_sha256",
    "transcript_schema_sha256",
    "platform",
    "platform_class",
    "target",
    "physical_provenance",
    "artifact_profile_code",
    "artifact_abi",
    "component_profile",
    "core_profile",
    "runtime_abi",
    "stage",
    "runtime_ready",
    "native_async_runtime_ready",
    "execution_enabled",
    "current_validation_engine",
    "current_component_engine",
    "candidate_package",
    "candidate_version",
    "candidate_upstream_commit",
    "candidate_manifest_sha256",
    "candidate_patch_sha256",
    "backend_package",
    "backend_version",
    "backend_archive_sha256",
    "backend_revision",
    "backend_llvm_revision",
    "candidate_feature_set",
    "candidate_acceptance_feature",
    "candidate_production_ready",
    "core_module_sha256",
    "core_module_bytes",
    "core_compile_reservation_bytes",
    "core_memory_bytes",
    "core_runtime_digest",
    "core_fold_digest",
    "core_spin_trace_digest",
    "component_sha256",
    "component_bytes",
    "wit_sha256",
    "world",
    "export",
    "activation_label",
    "memory_bytes",
    "total_fuel",
    "poll_quantum",
    "resources",
    "embedded_modules",
    "core_instances",
    "component_instances",
    "aliases",
    "canonical_functions",
    "adapters",
    "imports",
    "host_imports",
    "exports",
    "executable_exports",
    "exact_binding",
    "core_cases",
    "f3_cases",
    "f4_vectors",
    "fuel_records",
    "lifecycle_records",
    "records",
}

COMMON_DATA_KEYS = {"schema", "version", "run_id", "sequence"}
CORE_KEYS = COMMON_DATA_KEYS | {
    "case_id",
    "path",
    "op_index",
    "input0",
    "input1",
    "expected",
    "actual",
    "outcome",
    "trace_digest",
    "consumed_fuel",
    "remaining_fuel",
    "poll_calls",
    "pending_polls",
}
F3_VECTOR_KEYS = COMMON_DATA_KEYS | {
    "case_id",
    "kind",
    "raw_f32",
    "raw_f64",
    "expected_f32",
    "expected_f64",
    "actual_f32",
    "actual_f64",
}
F3_SUMMARY_KEYS = COMMON_DATA_KEYS | {
    "case_id",
    "kind",
    "scalar_cases",
    "flat_cases",
    "memory_cases",
    "indirect_cases",
    "variant_cases",
    "nested_cases",
    "hostile_rejections",
    "allocations",
    "allocated_bytes",
    "digest",
}
F4_KEYS = COMMON_DATA_KEYS | {
    "case_id",
    "left_f32",
    "right_f64",
    "expected_f64",
    "actual_f64",
    "consumed_fuel",
    "remaining_fuel",
    "poll_calls",
    "pending_polls",
}
FUEL_KEYS = COMMON_DATA_KEYS | {
    "case_id",
    "poll_index",
    "outcome",
    "consumed_fuel",
    "remaining_fuel",
    "delta",
}
FUEL_TERMINAL_KEYS = FUEL_KEYS | {"trace_digest"}
LIFECYCLE_KEYS = COMMON_DATA_KEYS | {
    "case_id",
    "step",
    "state",
    "live_instances",
    "activations",
    "calls_started",
    "calls_completed",
    "cancellations",
    "revocations",
    "faults",
    "reclaimed_instances",
    "peak_live_instances",
    "last_consumed_fuel",
    "last_remaining_fuel",
}
TERMINAL_KEYS = {
    "schema",
    "version",
    "run_id",
    "challenge",
    "core_cases",
    "f3_cases",
    "f4_vectors",
    "fuel_records",
    "lifecycle_records",
    "records",
    "semantic_sha256",
}

ENVIRONMENT_KEYS = {
    "schema",
    "version",
    "suite_id",
    "mode",
    "source",
    "platform",
    "build",
    "build_tools",
    "dependency_archives",
    "python",
    "kernel",
    "qemu",
    "bios",
    "uart",
    "manifest",
    "producer",
    "qualification",
    "runner",
    "verifier",
    "elf_auditor",
    "elf_audit_report",
    "elf_audit",
    "challenge",
    "run_id",
    "manifest_sha256",
    "transcript_schema_sha256",
    "expected_semantic_sha256",
    "evidence_sha256",
}
SOURCE_KEYS = {
    "commit",
    "tree",
    "clean",
    "branch",
    "remote_ref",
    "remote_commit",
}
PLATFORM_KEYS = {"id", "class", "target", "physical_provenance"}
BUILD_KEYS = {
    "target",
    "package",
    "feature",
    "profile",
    "no_default_features",
    "locked",
    "offline",
    "rustflags",
}
BUILD_TOOL_KEYS = {"rustup", "cargo", "rustc", "rustdoc", "linker"}
IDENTITY_KEYS = {"path", "sha256", "bytes"}
DEPENDENCY_ARCHIVE_KEYS = {
    "cargo_lock",
    "cargo_config",
    "rust_source",
    "count",
    "records_sha256",
    "records",
}
RUST_SOURCE_KEYS = {"path", "files", "bytes", "tree_sha256"}
DEPENDENCY_ARCHIVE_RECORD_KEYS = {
    "name",
    "version",
    "source",
    "checksum",
    "filename",
    "sha256",
    "bytes",
}
QEMU_KEYS = IDENTITY_KEYS | {"version", "argv"}
ELF_AUDIT_KEYS = {
    "checks",
    "elf",
    "execution_scope",
    "mode",
    "schema",
    "schema_version",
    "status",
    "target",
    "toolchain",
}
ELF_AUDIT_ELF_KEYS = {
    "bytes",
    "control_flow",
    "e_flags",
    "entry",
    "executable_sections",
    "forbidden_opcodes",
    "program_headers",
    "riscv_arch",
    "sections",
    "sha256",
    "symbols",
}
ELF_AUDIT_CONTROL_FLOW_KEYS = {"canonical_boundaries", "direct_targets"}
ELF_AUDIT_SECTION_KEYS = {
    "address",
    "bytes",
    "four_byte_instructions",
    "instructions",
    "name",
    "sha256",
    "two_byte_instructions",
}
ELF_AUDIT_SYMBOL_KEYS = {
    "code_symbols",
    "defined",
    "forbidden_helpers",
    "raw_symtab_entries",
    "undefined",
}
ELF_AUDIT_TOOLCHAIN_KEYS = {
    "channel",
    "host",
    "llvm_build",
    "llvm_version",
    "rustc_commit",
    "rustc_release",
    "tools",
}
ELF_AUDIT_TOOL_KEYS = {"bytes", "sha256"}


class VerificationError(RuntimeError):
    """A fail-closed transcript or environment rejection."""


@dataclass(frozen=True)
class Record:
    family: str
    value: dict[str, object]
    line: int


@dataclass(frozen=True)
class VerifiedTranscript:
    metadata: dict[str, object]
    records: tuple[Record, ...]
    ending: dict[str, object]
    passing: dict[str, object]
    semantic_sha256: str
    uart_sha256: str
    uart_bytes: int


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def stop_process_group(process: subprocess.Popen[bytes], label: str) -> None:
    """Tear down one isolated subprocess session, including lingering children."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        fail(f"{label} process group did not terminate after SIGKILL")


def run_bounded_command(
    command: list[str],
    *,
    cwd: pathlib.Path | str,
    environment: dict[str, str],
    maximum_output: int,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    if not command:
        fail("cannot execute an empty verifier subprocess")
    if maximum_output <= 0 or timeout_seconds <= 0:
        fail("verifier subprocess bounds must be positive")
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
    except OSError as error:
        fail(f"cannot execute {command[0]}: {error}")
    assert process.stdout is not None and process.stderr is not None

    stdout = bytearray()
    stderr = bytearray()
    streams = {
        process.stdout.fileno(): stdout,
        process.stderr.fileno(): stderr,
    }
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(f"{command[0]} timed out after {timeout_seconds:.1f}s")
            for key, _ in selector.select(timeout=min(remaining, 0.1)):
                descriptor = key.fd
                allowance = maximum_output - len(stdout) - len(stderr)
                try:
                    chunk = os.read(descriptor, min(READ_CHUNK_BYTES, allowance + 1))
                except BlockingIOError:
                    continue
                except OSError as error:
                    fail(f"cannot read {command[0]} diagnostics: {error}")
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                streams[descriptor].extend(chunk)
                if len(stdout) + len(stderr) > maximum_output:
                    fail(
                        f"{command[0]} produced more than {maximum_output} diagnostic bytes"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail(f"{command[0]} timed out after {timeout_seconds:.1f}s")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            fail(f"{command[0]} timed out after {timeout_seconds:.1f}s")
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        # Always close the original session, even when its leader has exited.
        stop_process_group(process, command[0])
    return subprocess.CompletedProcess(
        command, returncode, bytes(stdout), bytes(stderr)
    )


def reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def reject_nonfinite(token: str) -> NoReturn:
    fail(f"non-finite JSON token {token!r}")


def strict_json_bytes(raw: bytes, label: str) -> object:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        fail(f"{label} is not strict UTF-8: {error}")
    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_members,
            parse_constant=reject_nonfinite,
        )
    except json.JSONDecodeError as error:
        fail(f"invalid {label} JSON: {error}")


def strict_json_text(text: str, label: str) -> dict[str, object]:
    value = strict_json_bytes(text.encode("utf-8"), label)
    if not isinstance(value, dict):
        fail(f"{label} must be one JSON object")
    return value


def exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{label} keys differ: missing={missing}, extra={extra}")


def integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 64) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        fail(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def string(value: object, label: str, *, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        fail(f"{label} must be a nonempty bounded string")
    return value


def canonical_hex(
    value: object,
    pattern: re.Pattern[str],
    label: str,
    *,
    nonzero: bool = False,
) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        fail(f"{label} is not canonical lowercase hexadecimal")
    if nonzero and not any(character != "0" for character in value):
        fail(f"{label} must not be the all-zero sentinel")
    return value


def case_id(value: object, label: str) -> str:
    if type(value) is not str or CASE_ID.fullmatch(value) is None:
        fail(f"{label} is not a canonical case identifier")
    return value


def result_token(value: object, label: str) -> str:
    if type(value) is not str or RESULT_TOKEN.fullmatch(value) is None:
        fail(f"{label} must be fixed-width bits or a canonical trap token")
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def environment_evidence_sha256(value: dict[str, object]) -> str:
    binding = {key: member for key, member in value.items() if key != "evidence_sha256"}
    return sha256_bytes(canonical_json(binding))


def stable_regular_bytes(path: pathlib.Path, label: str, *, maximum: int) -> bytes:
    requested = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = requested.lstat()
        resolved_path = requested.resolve(strict=True)
        if stat.S_ISLNK(before_path.st_mode):
            fail(f"{label} must not be a symbolic link")
        if resolved_path != requested:
            fail(f"{label} path must not traverse symbolic links")
        descriptor = os.open(requested, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                fail(f"{label} must be a direct singly-linked regular file")
            if before.st_size <= 0 or before.st_size > maximum:
                fail(f"{label} byte length is outside (0, {maximum}]")
            chunks: list[bytes] = []
            byte_count = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > maximum:
                    fail(f"{label} grew beyond {maximum} bytes while it was read")
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = requested.lstat()
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    initial_path_identity = (
        before_path.st_dev,
        before_path.st_ino,
        before_path.st_size,
        before_path.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    final_path_identity = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
    )
    if not (
        identity_before
        == initial_path_identity
        == identity_after
        == final_path_identity
    ):
        fail(f"{label} changed while it was read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"{label} byte length changed while it was read")
    return raw


def identity_record(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    exact_keys(value, IDENTITY_KEYS, label)
    path = string(value["path"], f"{label}.path")
    if not pathlib.PurePath(path).is_absolute():
        fail(f"{label}.path must be absolute")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        fail(f"{label}.path must not contain control characters")
    if os.path.abspath(path) != path:
        fail(f"{label}.path must be lexically canonical")
    canonical_hex(value["sha256"], HEX64, f"{label}.sha256", nonzero=True)
    integer(value["bytes"], f"{label}.bytes", minimum=1)
    return value


def stable_tree_file_bytes(path: pathlib.Path, label: str) -> bytes:
    """Read one direct rust-src file, including a legitimate empty file."""
    requested = pathlib.Path(os.path.abspath(os.fspath(path)))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = requested.lstat()
        resolved_path = requested.resolve(strict=True)
        if stat.S_ISLNK(before_path.st_mode) or resolved_path != requested:
            fail(f"{label} path must be direct and must not be a symbolic link")
        descriptor = os.open(requested, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                fail(f"{label} must be a direct singly-linked regular file")
            if before.st_size < 0 or before.st_size > MAX_RUST_SOURCE_FILE_BYTES:
                fail(f"{label} exceeds its byte bound")
            chunks: list[bytes] = []
            byte_count = 0
            while True:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > MAX_RUST_SOURCE_FILE_BYTES:
                    fail(f"{label} grew beyond its byte bound")
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = requested.lstat()
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    if not (
        before_identity
        == (
            before_path.st_dev,
            before_path.st_ino,
            before_path.st_size,
            before_path.st_mtime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        == (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_size,
            after_path.st_mtime_ns,
        )
    ):
        fail(f"{label} changed while it was read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"{label} byte length changed while it was read")
    return raw


def rust_source_tree_identity(root: pathlib.Path) -> dict[str, object]:
    """Recompute the complete pinned rust-src input to ``-Z build-std``."""
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect pinned rust-src library tree: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("pinned rust-src library root must be one direct directory")
    if resolved != root:
        fail("pinned rust-src library root must not traverse symbolic links")

    files: list[tuple[str, pathlib.Path]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
        except OSError as error:
            fail(f"cannot enumerate pinned rust-src directory {directory}: {error}")
        for entry in entries:
            try:
                entry_metadata = entry.lstat()
            except OSError as error:
                fail(f"cannot inspect pinned rust-src entry {entry}: {error}")
            if stat.S_ISLNK(entry_metadata.st_mode):
                fail(f"pinned rust-src tree contains a symbolic link: {entry}")
            if stat.S_ISDIR(entry_metadata.st_mode):
                pending.append(entry)
                continue
            if not stat.S_ISREG(entry_metadata.st_mode) or entry_metadata.st_nlink != 1:
                fail(f"pinned rust-src entry is not a direct regular file: {entry}")
            relative = entry.relative_to(root).as_posix()
            if any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in relative
            ):
                fail(f"pinned rust-src path contains a control character: {relative!r}")
            files.append((relative, entry))
            if len(files) > MAX_RUST_SOURCE_FILES:
                fail("pinned rust-src tree exceeds its file-count bound")
    files.sort(key=lambda item: item[0])
    if not files:
        fail("pinned rust-src tree contains no source files")

    digest = hashlib.sha256(RUST_SOURCE_TREE_DOMAIN)
    total_bytes = 0
    for relative, path in files:
        raw = stable_tree_file_bytes(path, f"pinned rust-src file {relative}")
        total_bytes += len(raw)
        if total_bytes > MAX_RUST_SOURCE_BYTES:
            fail("pinned rust-src tree exceeds its byte bound")
        record = canonical_json(
            {
                "path": relative,
                "sha256": sha256_bytes(raw),
                "bytes": len(raw),
            }
        )
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return {
        "path": str(root),
        "files": len(files),
        "bytes": total_bytes,
        "tree_sha256": digest.hexdigest(),
    }


def rust_source_record(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    exact_keys(value, RUST_SOURCE_KEYS, label)
    path = string(value["path"], f"{label}.path")
    if not pathlib.PurePath(path).is_absolute() or os.path.abspath(path) != path:
        fail(f"{label}.path must be a canonical absolute path")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        fail(f"{label}.path must not contain control characters")
    integer(value["files"], f"{label}.files", minimum=1, maximum=MAX_RUST_SOURCE_FILES)
    integer(value["bytes"], f"{label}.bytes", minimum=1, maximum=MAX_RUST_SOURCE_BYTES)
    canonical_hex(value["tree_sha256"], HEX64, f"{label}.tree_sha256", nonzero=True)
    return value


def require_exact_identity(
    value: dict[str, object], expected: dict[str, object], label: str
) -> None:
    if value != expected:
        fail(f"{label} differs from the fixed platform identity")


def require_local_identity(
    value: dict[str, object],
    path: pathlib.Path,
    label: str,
    *,
    maximum: int = MAX_ENVIRONMENT_BYTES,
) -> None:
    try:
        expected_path = path.resolve(strict=True)
        observed_path = pathlib.Path(str(value["path"])).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label}: {error}")
    raw = stable_regular_bytes(expected_path, label, maximum=maximum)
    if (
        observed_path != expected_path
        or value["sha256"] != sha256_bytes(raw)
        or value["bytes"] != len(raw)
    ):
        fail(f"environment {label} identity differs from the running source closure")


def git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }


def git_text(arguments: list[str], *, maximum: int = 64 * 1024) -> str:
    environment = git_environment()
    completed = run_bounded_command(
        ["/usr/bin/git", "-c", "core.fsmonitor=false", *arguments],
        cwd=ROOT,
        environment=environment,
        maximum_output=maximum,
        timeout_seconds=30.0,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        fail(f"Git source provenance check failed: {detail.strip()}")
    try:
        return completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        fail(f"Git source provenance output is not UTF-8: {error}")


def require_git_source_membership(
    source: dict[str, object],
    contracts: tuple[tuple[dict[str, object], pathlib.Path, str], ...],
) -> None:
    repository = pathlib.Path(git_text(["rev-parse", "--show-toplevel"]).strip())
    try:
        repository = repository.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve Git repository root: {error}")
    if repository != ROOT.resolve(strict=True):
        fail("verifier Git repository root differs from its source root")
    if git_text(["rev-parse", "--show-object-format"]).strip() != "sha1":
        fail("F5 verifier requires the repository's recorded SHA-1 object format")
    commit = git_text(
        ["rev-parse", "--verify", f"{source['commit']}^{{commit}}"]
    ).strip()
    tree = git_text(["rev-parse", "--verify", f"{source['commit']}^{{tree}}"]).strip()
    if commit != source["commit"] or tree != source["tree"]:
        fail("environment source commit/tree is absent or mismatched in Git")

    for identity, path, label in contracts:
        try:
            relative = path.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
        except (OSError, ValueError) as error:
            fail(f"cannot bind {label} to the source commit: {error}")
        raw = stable_regular_bytes(path, label, maximum=MAX_ENVIRONMENT_BYTES)
        header = f"blob {len(raw)}\0".encode("ascii")
        blob = hashlib.sha1(header + raw).hexdigest()
        listing = git_text(
            ["ls-tree", "-z", str(source["commit"]), "--", relative.as_posix()]
        )
        expected_suffix = f"\t{relative.as_posix()}\0"
        if listing.count("\0") != 1 or not listing.endswith(expected_suffix):
            fail(f"{label} is not one exact blob in the recorded source commit")
        metadata = listing[: -len(expected_suffix)].split(" ")
        if len(metadata) != 3 or metadata[1] != "blob" or metadata[2] != blob:
            fail(f"{label} bytes differ from the recorded source commit blob")
        if identity["sha256"] != sha256_bytes(raw) or identity["bytes"] != len(raw):
            fail(f"{label} environment identity differs during Git membership check")


def cargo_lock_registry_requirements(raw: bytes) -> list[dict[str, str]]:
    try:
        lock = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"Cargo.lock is not strict TOML: {error}")
    if lock.get("version") != 4 or not isinstance(lock.get("package"), list):
        fail("Cargo.lock must use version 4 and contain a package array")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, package in enumerate(lock["package"]):
        if not isinstance(package, dict):
            fail(f"Cargo.lock package {index} is not a table")
        source = package.get("source")
        if source is None:
            continue
        if source != CRATES_IO_SOURCE:
            fail(f"Cargo.lock package {index} has an unsupported source")
        name = package.get("name")
        version = package.get("version")
        checksum = package.get("checksum")
        if (
            type(name) is not str
            or not name
            or "/" in name
            or "\\" in name
            or type(version) is not str
            or not version
            or "/" in version
            or "\\" in version
        ):
            fail(f"Cargo.lock package {index} has an invalid name or version")
        canonical_hex(checksum, HEX64, f"Cargo.lock {name} {version} checksum")
        key = (name, version, source)
        if key in seen:
            fail(f"Cargo.lock repeats registry package {name} {version}")
        seen.add(key)
        result.append(
            {
                "name": name,
                "version": version,
                "source": source,
                "checksum": checksum,
                "filename": f"{name}-{version}.crate",
            }
        )
    result.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    if not result:
        fail("Cargo.lock contains no registry packages")
    return result


def validate_dependency_archives(
    value: object,
    *,
    verify_local_identity: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(value, dict):
        fail("environment.dependency_archives must be an object")
    exact_keys(value, DEPENDENCY_ARCHIVE_KEYS, "environment.dependency_archives")
    cargo_lock = identity_record(
        value["cargo_lock"], "environment.dependency_archives.cargo_lock"
    )
    cargo_config = identity_record(
        value["cargo_config"], "environment.dependency_archives.cargo_config"
    )
    rust_source = rust_source_record(
        value["rust_source"], "environment.dependency_archives.rust_source"
    )
    if rust_source != EXPECTED_RUST_SOURCE:
        fail("environment rust-src tree differs from the pinned build-std source")
    count = integer(
        value["count"],
        "environment.dependency_archives.count",
        minimum=1,
        maximum=10_000,
    )
    records = value["records"]
    if not isinstance(records, list) or len(records) != count:
        fail("environment dependency archive count differs from its record list")
    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    previous: tuple[str, str, str] | None = None
    for index, record in enumerate(records):
        label = f"environment.dependency_archives.records[{index}]"
        if not isinstance(record, dict):
            fail(f"{label} must be an object")
        exact_keys(record, DEPENDENCY_ARCHIVE_RECORD_KEYS, label)
        name = string(record["name"], f"{label}.name", maximum=256)
        version = string(record["version"], f"{label}.version", maximum=128)
        source = string(record["source"], f"{label}.source", maximum=256)
        filename = string(record["filename"], f"{label}.filename", maximum=512)
        if (
            "/" in name
            or "\\" in name
            or "/" in version
            or "\\" in version
            or source != CRATES_IO_SOURCE
            or filename != f"{name}-{version}.crate"
        ):
            fail(f"{label} has an invalid package identity")
        checksum = canonical_hex(record["checksum"], HEX64, f"{label}.checksum")
        archive_sha256 = canonical_hex(record["sha256"], HEX64, f"{label}.sha256")
        if archive_sha256 != checksum:
            fail(f"{label} archive hash differs from the lock checksum")
        integer(record["bytes"], f"{label}.bytes", minimum=1)
        key = (name, version, source)
        if key in seen or (previous is not None and key <= previous):
            fail("environment dependency archive records are duplicated or unsorted")
        seen.add(key)
        previous = key
        normalized.append(record)
    records_sha256 = canonical_hex(
        value["records_sha256"],
        HEX64,
        "environment.dependency_archives.records_sha256",
    )
    if records_sha256 != sha256_bytes(canonical_json(normalized)):
        fail("environment dependency archive record digest differs")

    if verify_local_identity:
        cargo_lock_path = ROOT / "Cargo.lock"
        cargo_config_path = ROOT / "firmware/.cargo/config.toml"
        require_local_identity(cargo_lock, cargo_lock_path, "Cargo.lock")
        require_local_identity(
            cargo_config,
            cargo_config_path,
            "bare-metal Cargo config",
        )
        if (
            rust_source_tree_identity(pathlib.Path(EXPECTED_RUST_SOURCE["path"]))
            != rust_source
        ):
            fail("local pinned rust-src tree differs from the formal environment")
        lock_raw = stable_regular_bytes(
            cargo_lock_path, "Cargo.lock", maximum=4 * 1024 * 1024
        )
        expected = cargo_lock_registry_requirements(lock_raw)
        observed = [
            {
                key: record[key]
                for key in ("name", "version", "source", "checksum", "filename")
            }
            for record in normalized
        ]
        if observed != expected:
            fail("environment dependency archive closure differs from Cargo.lock")
    return cargo_lock, cargo_config


def validate_elf_audit(
    value: object,
    kernel: dict[str, object],
    report_identity: dict[str, object],
) -> None:
    if not isinstance(value, dict):
        fail("environment.elf_audit must be an object")
    exact_keys(value, ELF_AUDIT_KEYS, "environment.elf_audit")
    exact_header = {
        "schema": "vibeos.c88.f5.riscv-final-elf.audit",
        "schema_version": 1,
        "mode": "audit",
        "status": "pass",
        "target": "riscv64imac-unknown-none-elf",
    }
    integer(value["schema_version"], "environment.elf_audit.schema_version", minimum=1)
    for key, expected in exact_header.items():
        if value[key] != expected:
            fail(f"environment.elf_audit.{key} differs")
    expected_checks = [
        "elf64-little-riscv-et_exec",
        "soft-abi-rvc-flags",
        "exact-rv64-imac-attributes",
        "static-no-relocations",
        "section-and-segment-wx",
        "section-load-congruent-mapping",
        "rx-exec-section-exact-coverage",
        "canonical-riscv-opcodes",
        "objdump-boundary-cross-check",
        "canonical-control-flow-targets",
        "nm-zero-float-helpers",
        "stable-input-identity",
    ]
    if value["checks"] != expected_checks:
        fail("environment.elf_audit checks differ from the closed policy")
    if value["execution_scope"] != [
        "trusted-native-control-flow",
        "canonical-decoder-boundaries",
        "arbitrary-PC-redirection-not-claimed",
        "hardware-NX-not-claimed",
    ]:
        fail("environment.elf_audit execution scope differs")

    elf = value["elf"]
    if not isinstance(elf, dict):
        fail("environment.elf_audit.elf must be an object")
    exact_keys(elf, ELF_AUDIT_ELF_KEYS, "environment.elf_audit.elf")
    integer(elf["bytes"], "environment.elf_audit.elf.bytes", minimum=1)
    if (
        elf["sha256"] != kernel["sha256"]
        or elf["bytes"] != kernel["bytes"]
        or elf["e_flags"] != "0x00000001"
        or elf["riscv_arch"]
        != (
            "rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_"
            "zaamo1p0_zalrsc1p0_zca1p0"
        )
        or elf["forbidden_opcodes"] != []
    ):
        fail("environment.elf_audit ELF identity or ISA policy differs")
    entry = string(elf["entry"], "environment.elf_audit.elf.entry", maximum=18)
    if re.fullmatch(r"0x[0-9a-f]{16}", entry) is None or entry == "0x0000000000000000":
        fail("environment.elf_audit.elf.entry is not a nonzero canonical address")
    integer(
        elf["program_headers"], "environment.elf_audit.elf.program_headers", minimum=1
    )
    integer(elf["sections"], "environment.elf_audit.elf.sections", minimum=2)

    executable = elf["executable_sections"]
    if not isinstance(executable, list) or not 1 <= len(executable) <= 64:
        fail(
            "environment.elf_audit executable section list is not bounded and nonempty"
        )
    names: set[str] = set()
    instruction_total = 0
    for index, section in enumerate(executable):
        label = f"environment.elf_audit.elf.executable_sections[{index}]"
        if not isinstance(section, dict):
            fail(f"{label} must be an object")
        exact_keys(section, ELF_AUDIT_SECTION_KEYS, label)
        name = string(section["name"], f"{label}.name", maximum=128)
        if re.fullmatch(r"[A-Za-z0-9._+-]+", name) is None or name in names:
            fail(f"{label}.name is invalid or duplicated")
        names.add(name)
        address = string(section["address"], f"{label}.address", maximum=18)
        if re.fullmatch(r"0x[0-9a-f]{16}", address) is None:
            fail(f"{label}.address is not canonical")
        byte_count = integer(section["bytes"], f"{label}.bytes", minimum=1)
        two = integer(
            section["two_byte_instructions"], f"{label}.two_byte_instructions"
        )
        four = integer(
            section["four_byte_instructions"], f"{label}.four_byte_instructions"
        )
        instructions = integer(
            section["instructions"], f"{label}.instructions", minimum=1
        )
        if instructions != two + four or byte_count != 2 * two + 4 * four:
            fail(f"{label} instruction counts do not cover its exact byte length")
        instruction_total += instructions
        canonical_hex(section["sha256"], HEX64, f"{label}.sha256", nonzero=True)

    control_flow = elf["control_flow"]
    if not isinstance(control_flow, dict):
        fail("environment.elf_audit.elf.control_flow must be an object")
    exact_keys(
        control_flow,
        ELF_AUDIT_CONTROL_FLOW_KEYS,
        "environment.elf_audit.elf.control_flow",
    )
    boundaries = integer(
        control_flow["canonical_boundaries"],
        "environment.elf_audit.elf.control_flow.canonical_boundaries",
        minimum=1,
    )
    direct_targets = integer(
        control_flow["direct_targets"],
        "environment.elf_audit.elf.control_flow.direct_targets",
    )
    if (
        boundaries != instruction_total + len(executable)
        or direct_targets > instruction_total
    ):
        fail("environment.elf_audit canonical control-flow counts differ")

    symbols = elf["symbols"]
    if not isinstance(symbols, dict):
        fail("environment.elf_audit.elf.symbols must be an object")
    exact_keys(symbols, ELF_AUDIT_SYMBOL_KEYS, "environment.elf_audit.elf.symbols")
    defined = integer(
        symbols["defined"], "environment.elf_audit.elf.symbols.defined", minimum=1
    )
    code_symbols = integer(
        symbols["code_symbols"],
        "environment.elf_audit.elf.symbols.code_symbols",
        minimum=1,
    )
    raw_entries = integer(
        symbols["raw_symtab_entries"],
        "environment.elf_audit.elf.symbols.raw_symtab_entries",
        minimum=1,
    )
    undefined = integer(
        symbols["undefined"], "environment.elf_audit.elf.symbols.undefined"
    )
    if (
        code_symbols > defined
        or defined > raw_entries
        or undefined != 0
        or symbols["forbidden_helpers"] != []
    ):
        fail("environment.elf_audit symbol closure differs")

    toolchain = value["toolchain"]
    if not isinstance(toolchain, dict):
        fail("environment.elf_audit.toolchain must be an object")
    exact_keys(toolchain, ELF_AUDIT_TOOLCHAIN_KEYS, "environment.elf_audit.toolchain")
    exact_toolchain = {
        "channel": "nightly-2026-08-01",
        "host": "aarch64-apple-darwin",
        "llvm_build": "22.1.8-rust-1.99.0-nightly",
        "llvm_version": "22.1.8",
        "rustc_commit": "ad3d0bc141a02cf446e384136d250a1f6950fed5",
        "rustc_release": "1.99.0-nightly",
    }
    for key, expected in exact_toolchain.items():
        if toolchain[key] != expected:
            fail(f"environment.elf_audit.toolchain.{key} differs")
    tools = toolchain["tools"]
    if not isinstance(tools, dict) or set(tools) != set(
        EXPECTED_ELF_AUDIT_TOOL_IDENTITIES
    ):
        fail("environment.elf_audit.toolchain.tools keys differ")
    for name, expected in EXPECTED_ELF_AUDIT_TOOL_IDENTITIES.items():
        observed = tools[name]
        if not isinstance(observed, dict):
            fail(f"environment.elf_audit.toolchain.tools.{name} must be an object")
        exact_keys(
            observed,
            ELF_AUDIT_TOOL_KEYS,
            f"environment.elf_audit.toolchain.tools.{name}",
        )
        if observed != expected:
            fail(f"environment.elf_audit.toolchain.tools.{name} identity differs")

    encoded = canonical_json(value) + b"\n"
    if report_identity["sha256"] != sha256_bytes(encoded) or report_identity[
        "bytes"
    ] != len(encoded):
        fail("environment.elf_audit_report does not bind the canonical audit object")


def expected_run_id(environment: dict[str, object]) -> str:
    source = environment["source"]
    assert isinstance(source, dict)
    fields = (
        source["commit"],
        source["tree"],
        environment["challenge"],
        environment["manifest_sha256"],
        environment["transcript_schema_sha256"],
        EXPECTED_COMPONENT_SHA256,
    )
    payload = RUN_ID_DOMAIN + b"\0".join(str(field).encode("ascii") for field in fields)
    return sha256_bytes(payload)


def validate_qemu_argv(
    qemu: dict[str, object], kernel: dict[str, object], bios: dict[str, object]
) -> None:
    raw = qemu["argv"]
    if not isinstance(raw, list) or not raw or len(raw) > 128:
        fail("environment.qemu.argv must be one bounded nonempty array")
    argv: list[str] = []
    for index, argument in enumerate(raw):
        argv.append(string(argument, f"environment.qemu.argv[{index}]", maximum=1024))
    expected = [
        str(qemu["path"]),
        "-no-user-config",
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
        "-nic",
        "none",
        "-bios",
        str(bios["path"]),
        "-kernel",
        str(kernel["path"]),
    ]
    if argv != expected:
        fail("QEMU argv differs from the exact authority-free fixed-TCG contract")


def validate_environment(
    value: object,
    uart: bytes,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC_SHA256,
) -> dict[str, object]:
    if not isinstance(value, dict):
        fail("environment must be one JSON object")
    exact_keys(value, ENVIRONMENT_KEYS, "environment")
    if value["schema"] != "vibeos.c88.f5.float-target.environment":
        fail("environment schema differs")
    if integer(value["version"], "environment.version") != SCHEMA_VERSION:
        fail("environment version differs")
    if value["suite_id"] != SUITE_ID or value["mode"] != "formal-qemu":
        fail("environment suite or mode differs")

    source = value["source"]
    if not isinstance(source, dict):
        fail("environment.source must be an object")
    exact_keys(source, SOURCE_KEYS, "environment.source")
    canonical_hex(source["commit"], HEX40, "environment.source.commit", nonzero=True)
    canonical_hex(source["tree"], HEX40, "environment.source.tree", nonzero=True)
    canonical_hex(
        source["remote_commit"],
        HEX40,
        "environment.source.remote_commit",
        nonzero=True,
    )
    if boolean(source["clean"], "environment.source.clean") is not True:
        fail("formal environment source must be clean")
    if (
        source["branch"] != "codex/wasm"
        or source["remote_ref"] != "refs/remotes/origin/codex/wasm"
        or source["remote_commit"] != source["commit"]
    ):
        fail("formal environment source is not the pushed codex/wasm commit")

    platform = value["platform"]
    if not isinstance(platform, dict):
        fail("environment.platform must be an object")
    exact_keys(platform, PLATFORM_KEYS, "environment.platform")
    if platform != {
        "id": "qemu-virt-rv64-tcg-icount-v1",
        "class": "emulator",
        "target": "riscv64imac-unknown-none-elf",
        "physical_provenance": "not-claimed",
    }:
        fail("environment platform is not the fixed non-physical QEMU contract")

    build = value["build"]
    if not isinstance(build, dict):
        fail("environment.build must be an object")
    exact_keys(build, BUILD_KEYS, "environment.build")
    boolean(build["no_default_features"], "environment.build.no_default_features")
    boolean(build["locked"], "environment.build.locked")
    boolean(build["offline"], "environment.build.offline")
    if build != {
        "target": "riscv64imac-unknown-none-elf",
        "package": "vibeos-firmware-qemu-virt",
        "feature": "wasm-c88-f5-float-qemu-acceptance",
        "profile": "release",
        "no_default_features": True,
        "locked": True,
        "offline": True,
        "rustflags": [
            "-C",
            "linker=ld.lld",
            "-C",
            "linker-flavor=ld",
            "-C",
            "target-feature=+zicsr,+zifencei",
            "-C",
            "link-arg=--gc-sections",
            "-C",
            "force-frame-pointers=yes",
            "-Z",
            "fmt-debug=none",
        ],
    }:
        fail("environment build is not the fixed F5 release contract")

    build_tools = value["build_tools"]
    if not isinstance(build_tools, dict):
        fail("environment.build_tools must be an object")
    exact_keys(build_tools, BUILD_TOOL_KEYS, "environment.build_tools")
    for tool_name in sorted(BUILD_TOOL_KEYS):
        tool = identity_record(
            build_tools[tool_name], f"environment.build_tools.{tool_name}"
        )
        require_exact_identity(
            tool,
            EXPECTED_BUILD_TOOLS[tool_name],
            f"environment.build_tools.{tool_name}",
        )
    cargo_lock, cargo_config = validate_dependency_archives(
        value["dependency_archives"],
        verify_local_identity=verify_self_identity,
    )
    python = identity_record(value["python"], "environment.python")

    kernel = identity_record(value["kernel"], "environment.kernel")
    bios = identity_record(value["bios"], "environment.bios")
    uart_record = identity_record(value["uart"], "environment.uart")
    manifest = identity_record(value["manifest"], "environment.manifest")
    producer = identity_record(value["producer"], "environment.producer")
    qualification = identity_record(value["qualification"], "environment.qualification")
    runner = identity_record(value["runner"], "environment.runner")
    verifier = identity_record(value["verifier"], "environment.verifier")
    elf_auditor = identity_record(value["elf_auditor"], "environment.elf_auditor")
    elf_audit_report = identity_record(
        value["elf_audit_report"], "environment.elf_audit_report"
    )
    require_exact_identity(bios, EXPECTED_BIOS_IDENTITY, "environment.bios")
    if (
        manifest["sha256"] != EXPECTED_MANIFEST_SHA256
        or manifest["bytes"] != EXPECTED_MANIFEST_BYTES
    ):
        fail("environment manifest differs from the frozen F5 contract")
    validate_elf_audit(value["elf_audit"], kernel, elf_audit_report)

    qemu = value["qemu"]
    if not isinstance(qemu, dict):
        fail("environment.qemu must be an object")
    exact_keys(qemu, QEMU_KEYS, "environment.qemu")
    qemu_identity = identity_record(
        {key: qemu[key] for key in IDENTITY_KEYS}, "environment.qemu"
    )
    require_exact_identity(qemu_identity, EXPECTED_QEMU_IDENTITY, "environment.qemu")
    qemu_version = string(qemu["version"], "environment.qemu.version", maximum=4096)
    if qemu_version != EXPECTED_QEMU_VERSION:
        fail("environment.qemu.version differs from the fixed QEMU banner")
    validate_qemu_argv(qemu, kernel, bios)

    if uart_record["sha256"] != sha256_bytes(uart) or uart_record["bytes"] != len(uart):
        fail("environment UART identity differs from --uart")
    canonical_hex(value["challenge"], HEX64, "environment.challenge", nonzero=True)
    canonical_hex(value["run_id"], HEX64, "environment.run_id", nonzero=True)
    canonical_hex(
        value["manifest_sha256"], HEX64, "environment.manifest_sha256", nonzero=True
    )
    canonical_hex(
        value["transcript_schema_sha256"],
        HEX64,
        "environment.transcript_schema_sha256",
        nonzero=True,
    )
    canonical_hex(
        value["expected_semantic_sha256"],
        HEX64,
        "environment.expected_semantic_sha256",
        nonzero=True,
    )
    if value["expected_semantic_sha256"] != expected_semantic_sha256:
        fail("environment semantic digest differs from the frozen host witness")
    if value["manifest_sha256"] != manifest["sha256"]:
        fail("environment manifest_sha256 differs from the manifest identity")
    if value["transcript_schema_sha256"] != verifier["sha256"]:
        fail("environment transcript schema differs from the verifier identity")
    if value["run_id"] != expected_run_id(value):
        fail("environment run_id does not match its bound inputs")
    evidence_sha256 = canonical_hex(
        value["evidence_sha256"],
        HEX64,
        "environment.evidence_sha256",
        nonzero=True,
    )
    if evidence_sha256 != environment_evidence_sha256(value):
        fail("environment evidence digest does not bind the complete envelope")

    if verify_self_identity:
        local_contracts = (
            (
                manifest,
                ROOT
                / "acceptance/wasm-float-target/artifacts/qualification-manifest.json",
                "manifest",
            ),
            (producer, ROOT / "kernel/src/wasm_float_target.rs", "producer"),
            (
                qualification,
                ROOT / "acceptance/wasm-float-target/src/lib.rs",
                "qualification",
            ),
            (runner, ROOT / "scripts/qemu-c88-f5-float-target.py", "runner"),
            (verifier, pathlib.Path(__file__), "verifier"),
            (elf_auditor, ROOT / "scripts/verify-c88-f5-riscv-elf.py", "ELF auditor"),
        )
        for identity, path, label in local_contracts:
            require_local_identity(identity, path, label)
        git_contracts = local_contracts + (
            (cargo_lock, ROOT / "Cargo.lock", "Cargo.lock"),
            (
                cargo_config,
                ROOT / "firmware/.cargo/config.toml",
                "bare-metal Cargo config",
            ),
        )
        require_git_source_membership(source, git_contracts)
        try:
            python_path = pathlib.Path(sys.executable).resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve the verifier Python interpreter: {error}")
        require_local_identity(
            python,
            python_path,
            "Python interpreter",
            maximum=MAX_KERNEL_BYTES,
        )
    return value


def parse_record(line: str, prefix: str, label: str, line_number: int) -> Record:
    payload = line[len(prefix) :]
    if not payload or payload != payload.strip():
        fail(f"line {line_number} {label} payload has surrounding whitespace")
    return Record(
        label, strict_json_text(payload, f"line {line_number} {label}"), line_number
    )


def parse_uart(uart: bytes) -> tuple[Record, tuple[Record, ...], Record, Record]:
    if not uart.endswith(b"\n"):
        fail("UART must end at an exact newline boundary")
    try:
        text = uart.decode("utf-8", errors="strict")
    except UnicodeError as error:
        fail(f"UART is not strict UTF-8: {error}")
    lines = text.splitlines()
    if len(lines) > MAX_UART_LINES:
        fail(f"UART has more than {MAX_UART_LINES} lines")
    family_records: list[Record] = []
    pass_seen = False
    previous_rank = -1
    for line_number, line in enumerate(lines, 1):
        lowered = line.lower()
        if any(marker in lowered for marker in FATAL_MARKERS):
            fail(f"UART contains fatal marker on line {line_number}")
        if FAMILY_PREFIX in line and not line.startswith(FAMILY_PREFIX):
            fail(f"C8.8-F5 family text is not column-zero on line {line_number}")
        if not line.startswith(FAMILY_PREFIX):
            continue
        if pass_seen:
            fail(f"C8.8-F5 family output appears after PASS on line {line_number}")
        if line.startswith(PREFIXES["FAIL"]):
            fail(f"guest emitted explicit C8.8-F5 FAIL on line {line_number}")
        matched: Record | None = None
        for family in ("META", *DATA_FAMILIES, "END", "PASS"):
            prefix = PREFIXES[family]
            if line.startswith(prefix):
                matched = parse_record(line, prefix, family, line_number)
                break
        if matched is None:
            fail(f"unknown C8.8-F5 family record on line {line_number}")
        rank = FAMILY_ORDER[matched.family]
        if rank < previous_rank:
            fail(f"C8.8-F5 family order regressed on line {line_number}")
        previous_rank = rank
        family_records.append(matched)
        if matched.family == "PASS":
            pass_seen = True

    metadata = [record for record in family_records if record.family == "META"]
    endings = [record for record in family_records if record.family == "END"]
    passings = [record for record in family_records if record.family == "PASS"]
    if len(metadata) != 1 or len(endings) != 1 or len(passings) != 1:
        fail(
            "UART must contain exactly one META, END, and PASS: "
            f"got {len(metadata)}, {len(endings)}, {len(passings)}"
        )
    data = tuple(record for record in family_records if record.family in DATA_FAMILIES)
    if not data:
        fail("UART contains no C8.8-F5 data records")
    if family_records[-2].family != "END" or family_records[-1].family != "PASS":
        fail("END and PASS are not the final two C8.8-F5 family records")
    return metadata[0], data, endings[0], passings[0]


def validate_schema(record: Record) -> None:
    if record.value.get("schema") != SCHEMAS[record.family]:
        fail(f"line {record.line} {record.family} schema differs")
    if (
        integer(record.value.get("version"), f"line {record.line}.version")
        != SCHEMA_VERSION
    ):
        fail(f"line {record.line} {record.family} version differs")


def validate_meta(
    record: Record, environment: dict[str, object]
) -> tuple[dict[str, object], dict[str, int]]:
    value = record.value
    exact_keys(value, META_KEYS, "META")
    validate_schema(record)
    if (
        value["suite_id"] != SUITE_ID
        or integer(value["suite_revision"], "META.suite_revision") != 1
    ):
        fail("META suite identity differs")
    source = environment["source"]
    platform = environment["platform"]
    assert isinstance(source, dict) and isinstance(platform, dict)
    bindings = {
        "source_commit": source["commit"],
        "source_tree": source["tree"],
        "challenge": environment["challenge"],
        "run_id": environment["run_id"],
        "manifest_sha256": environment["manifest_sha256"],
        "transcript_schema_sha256": environment["transcript_schema_sha256"],
        "platform": platform["id"],
        "platform_class": platform["class"],
        "target": platform["target"],
        "physical_provenance": platform["physical_provenance"],
    }
    for key, expected in bindings.items():
        if value[key] != expected:
            fail(f"META {key} differs from the environment")

    exact_values: dict[str, object] = {
        "artifact_profile_code": 5,
        "artifact_abi": 5,
        "component_profile": 2,
        "core_profile": 2,
        "runtime_abi": 5,
        "stage": "validation-only",
        "runtime_ready": False,
        "native_async_runtime_ready": False,
        "execution_enabled": False,
        "current_validation_engine": False,
        "current_component_engine": False,
        "candidate_production_ready": False,
        "core_module_sha256": EXPECTED_CORE_MODULE_SHA256,
        "core_module_bytes": EXPECTED_CORE_MODULE_BYTES,
        "core_compile_reservation_bytes": EXPECTED_CORE_COMPILE_RESERVATION_BYTES,
        "core_memory_bytes": EXPECTED_CORE_MEMORY_BYTES,
        "core_runtime_digest": EXPECTED_CORE_RUNTIME_DIGEST,
        "core_fold_digest": EXPECTED_CORE_FOLD_DIGEST,
        "core_spin_trace_digest": EXPECTED_CORE_SPIN_TRACE_DIGEST,
        "component_sha256": EXPECTED_COMPONENT_SHA256,
        "wit_sha256": EXPECTED_WIT_SHA256,
        "world": EXPECTED_WORLD,
        "export": EXPECTED_EXPORT,
        "activation_label": EXPECTED_ACTIVATION_LABEL,
        "memory_bytes": 2 * 65_536,
        "total_fuel": 100_000,
        "poll_quantum": 100,
        "resources": 0,
        "embedded_modules": 1,
        "core_instances": 1,
        "component_instances": 0,
        "aliases": 1,
        "canonical_functions": 1,
        "adapters": 0,
        "imports": 0,
        "host_imports": 0,
        "exports": 1,
        "executable_exports": 0,
        "exact_binding": True,
        **EXPECTED_CANDIDATE,
    }
    for key, expected in exact_values.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            fail(f"META {key} differs: {value[key]!r} != {expected!r}")
    if integer(value["component_bytes"], "META.component_bytes", minimum=1) != 291:
        fail("META component byte length differs from the frozen image pin")

    counts = {
        "core_cases": integer(
            value["core_cases"], "META.core_cases", minimum=1, maximum=512
        ),
        "f3_cases": integer(value["f3_cases"], "META.f3_cases", minimum=1, maximum=64),
        "f4_vectors": integer(
            value["f4_vectors"], "META.f4_vectors", minimum=1, maximum=64
        ),
        "fuel_records": integer(
            value["fuel_records"], "META.fuel_records", minimum=1, maximum=4096
        ),
        "lifecycle_records": integer(
            value["lifecycle_records"], "META.lifecycle_records", minimum=1, maximum=128
        ),
    }
    counts["records"] = integer(
        value["records"], "META.records", minimum=1, maximum=8192
    )
    if counts["f3_cases"] != len(F3_RAW_F32) + 1:
        fail("META must declare 12 F3 vectors plus one F3 summary")
    if counts["f4_vectors"] != len(EXPECTED_F4_VECTORS):
        fail("META F4 vector count differs from the frozen 12-vector table")
    if counts["fuel_records"] != EXPECTED_FUEL_RECORDS:
        fail("META must declare exactly 999 Pending fuel records plus one terminal")
    if counts["lifecycle_records"] != len(EXPECTED_LIFECYCLE_STEPS):
        fail("META lifecycle count differs from the frozen snapshot order")
    if counts["records"] != sum(
        counts[key]
        for key in (
            "core_cases",
            "f3_cases",
            "f4_vectors",
            "fuel_records",
            "lifecycle_records",
        )
    ):
        fail("META total record count differs from its family counts")
    if EXPECTED_CORE_CASES and counts["core_cases"] != len(EXPECTED_CORE_CASES):
        fail("META Core count differs from the frozen operation table")
    return value, counts


def validate_common(record: Record, run_id: str, expected_sequence: int) -> None:
    validate_schema(record)
    if record.value.get("run_id") != run_id:
        fail(f"line {record.line} run_id differs")
    if (
        integer(record.value.get("sequence"), f"line {record.line}.sequence")
        != expected_sequence
    ):
        fail(f"line {record.line} global sequence differs from {expected_sequence}")


U64_MASK = (1 << 64) - 1
MIX_MULTIPLIER = 0x0000_0100_0000_01B3
TRAP_CODES = {
    "trap:integer-overflow": 0x0202,
    "trap:invalid-conversion-to-integer": 0x0207,
    "trap:fuel-exhausted": 0x0300,
}


def mix_u64(state: int, value: int) -> int:
    multiplied = ((state ^ value) * MIX_MULTIPLIER) & U64_MASK
    return ((multiplied << 17) | (multiplied >> 47)) & U64_MASK


def core_outcome_word(outcome: str) -> int:
    if outcome.startswith("trap:"):
        code = TRAP_CODES.get(outcome)
        if code is None:
            fail(f"Core outcome has an unfrozen trap token: {outcome!r}")
        return 0x7472_6170_0000_0000 | code
    return mix_u64(0x7661_6C75_6500_0000, int(outcome, 16))


def mix_core_record(state: int, value: dict[str, object]) -> int:
    words = (
        int(value["op_index"]),
        int(str(value["input0"]), 16),
        int(str(value["input1"]), 16),
        core_outcome_word(str(value["expected"])),
        core_outcome_word(str(value["actual"])),
        int(value["consumed_fuel"]),
        int(value["remaining_fuel"]),
        int(value["poll_calls"]),
        int(str(value["trace_digest"]), 16),
    )
    for word in words:
        state = mix_u64(state, word)
    return state


def solve_final_mix_value(state: int, result: int) -> int:
    rotated_back = ((result >> 17) | (result << 47)) & U64_MASK
    multiplier_inverse = pow(MIX_MULTIPLIER, -1, 1 << 64)
    return state ^ ((rotated_back * multiplier_inverse) & U64_MASK)


def solve_core_terminal_trace(
    records: list[Record], path: str, initial: int, expected: str
) -> None:
    selected = [
        record
        for record in records
        if record.family == "CORE_CASE" and record.value["path"] == path
    ]
    state = initial
    for record in selected[:-1]:
        state = mix_core_record(state, record.value)
    terminal = selected[-1].value
    words_before_trace = (
        int(terminal["op_index"]),
        int(str(terminal["input0"]), 16),
        int(str(terminal["input1"]), 16),
        core_outcome_word(str(terminal["expected"])),
        core_outcome_word(str(terminal["actual"])),
        int(terminal["consumed_fuel"]),
        int(terminal["remaining_fuel"]),
        int(terminal["poll_calls"]),
    )
    for word in words_before_trace:
        state = mix_u64(state, word)
    trace = solve_final_mix_value(state, int(expected, 16))
    if trace == 0:
        fail("synthetic Core terminal trace unexpectedly solved to zero")
    terminal["trace_digest"] = f"{trace:016x}"


def validate_core(records: list[Record], meta: dict[str, object]) -> None:
    if len(records) != len(EXPECTED_CORE_CASES):
        fail("CORE_CASE section does not contain the frozen 146-record table")
    seen: set[str] = set()
    for index, record in enumerate(records):
        value = record.value
        exact_keys(value, CORE_KEYS, f"CORE_CASE[{index}]")
        identifier = case_id(value["case_id"], f"CORE_CASE[{index}].case_id")
        if identifier in seen:
            fail(f"duplicate Core case {identifier!r}")
        seen.add(identifier)
        if value["path"] not in ("runtime", "fold", "spin"):
            fail(f"Core case {identifier} has an invalid execution path")
        integer(value["op_index"], f"CORE_CASE[{index}].op_index", maximum=511)
        canonical_hex(value["input0"], HEX16, f"CORE_CASE[{index}].input0")
        canonical_hex(value["input1"], HEX16, f"CORE_CASE[{index}].input1")
        expected = result_token(value["expected"], f"CORE_CASE[{index}].expected")
        actual = result_token(value["actual"], f"CORE_CASE[{index}].actual")
        if expected != actual:
            fail(f"Core case {identifier} actual result differs from expected")
        if value["outcome"] not in ("ready", "trapped"):
            fail(f"Core case {identifier} has an invalid outcome")
        canonical_hex(
            value["trace_digest"],
            HEX16,
            f"CORE_CASE[{index}].trace_digest",
            nonzero=True,
        )
        consumed = integer(
            value["consumed_fuel"], f"CORE_CASE[{index}].consumed_fuel", minimum=1
        )
        remaining = integer(
            value["remaining_fuel"], f"CORE_CASE[{index}].remaining_fuel"
        )
        if consumed + remaining != meta["total_fuel"]:
            fail(f"Core case {identifier} fuel does not sum to the exact total")
        poll_calls = integer(
            value["poll_calls"],
            f"CORE_CASE[{index}].poll_calls",
            minimum=1,
            maximum=2001,
        )
        pending_polls = integer(
            value["pending_polls"], f"CORE_CASE[{index}].pending_polls", maximum=2000
        )
        if pending_polls + 1 != poll_calls:
            fail(f"Core case {identifier} poll counts do not terminate exactly once")
        if consumed < pending_polls or consumed > poll_calls * int(
            meta["poll_quantum"]
        ):
            fail(
                f"Core case {identifier} fuel is impossible for its bounded poll trace"
            )
        if value["outcome"] == "ready" and expected.startswith("trap:"):
            fail(f"ready Core case {identifier} reports a trap result")
        if value["outcome"] == "trapped" and not expected.startswith("trap:"):
            fail(f"trapped Core case {identifier} reports a value result")
        expected_record = EXPECTED_CORE_CASES[index]
        for key, frozen in expected_record.items():
            if value.get(key) != frozen:
                fail(f"Core case {index} field {key} differs from the frozen table")

    runtime_digest = 0x7275_6E74_696D_6500
    fold_digest = 0x666F_6C64_0000_0000
    for record in records[:-2]:
        if record.value["path"] == "runtime":
            runtime_digest = mix_core_record(runtime_digest, record.value)
        elif record.value["path"] == "fold":
            fold_digest = mix_core_record(fold_digest, record.value)
        else:
            fail("spin record appeared before the terminal Core pair")
    if f"{runtime_digest:016x}" != EXPECTED_CORE_RUNTIME_DIGEST:
        fail("Core runtime aggregate digest differs from the frozen host witness")
    if f"{fold_digest:016x}" != EXPECTED_CORE_FOLD_DIGEST:
        fail("Core fold aggregate digest differs from the frozen host witness")

    first_spin, second_spin = (record.value for record in records[-2:])
    spin_metrics = (99_998, 2, 1_011, 1_010, EXPECTED_CORE_SPIN_TRACE_DIGEST)
    for index, spin in enumerate((first_spin, second_spin)):
        actual = (
            spin["consumed_fuel"],
            spin["remaining_fuel"],
            spin["poll_calls"],
            spin["pending_polls"],
            spin["trace_digest"],
        )
        if actual != spin_metrics:
            fail(
                f"Core spin witness {index} differs from the frozen repeatability trace"
            )
    repeatability_fields = CORE_KEYS - COMMON_DATA_KEYS - {"case_id", "sequence"}
    for key in repeatability_fields:
        if first_spin[key] != second_spin[key]:
            fail(f"Core spin repeatability field {key} differs")


def oracle_f32(bits: str) -> str:
    value = int(bits, 16)
    if value & 0x7F80_0000 == 0x7F80_0000 and value & 0x007F_FFFF:
        return "7fc00000"
    return bits


def oracle_f64(bits: str) -> str:
    value = int(bits, 16)
    if (
        value & 0x7FF0_0000_0000_0000 == 0x7FF0_0000_0000_0000
        and value & 0x000F_FFFF_FFFF_FFFF
    ):
        return "7ff8000000000000"
    return bits


def validate_f3(records: list[Record]) -> None:
    if len(records) != len(F3_RAW_F32) + 1:
        fail("F3 section must contain 12 vectors and one summary")
    for index, (record, identifier, raw32, raw64) in enumerate(
        zip(records[:-1], F3_CASE_IDS, F3_RAW_F32, F3_RAW_F64)
    ):
        value = record.value
        exact_keys(value, F3_VECTOR_KEYS, f"F3_CASE[{index}]")
        if value["kind"] != "vector" or value["case_id"] != identifier:
            fail(f"F3 vector {index} identity or kind differs")
        actual_raw32 = canonical_hex(
            value["raw_f32"], HEX8, f"F3_CASE[{index}].raw_f32"
        )
        actual_raw64 = canonical_hex(
            value["raw_f64"], HEX16, f"F3_CASE[{index}].raw_f64"
        )
        if (actual_raw32, actual_raw64) != (raw32, raw64):
            fail(f"F3 vector {index} raw inputs differ from the frozen table")
        expected32 = oracle_f32(raw32)
        expected64 = oracle_f64(raw64)
        for key, expected, pattern in (
            ("expected_f32", expected32, HEX8),
            ("actual_f32", expected32, HEX8),
            ("expected_f64", expected64, HEX16),
            ("actual_f64", expected64, HEX16),
        ):
            observed = canonical_hex(value[key], pattern, f"F3_CASE[{index}].{key}")
            if observed != expected:
                fail(f"F3 vector {index} {key} differs from the integer oracle")

    summary = records[-1].value
    exact_keys(summary, F3_SUMMARY_KEYS, "F3_CASE summary")
    if summary["kind"] != "summary" or summary["case_id"] != "summary":
        fail("F3 summary identity or kind differs")
    for key, expected in EXPECTED_F3_SUMMARY.items():
        if key == "digest":
            canonical_hex(summary[key], HEX16, f"F3 summary {key}", nonzero=True)
        else:
            integer(summary[key], f"F3 summary {key}", minimum=1, maximum=1_000_000)
        if summary[key] != expected:
            fail(f"F3 summary {key} differs from the frozen corpus")


def validate_f4(records: list[Record], meta: dict[str, object]) -> None:
    if len(records) != len(EXPECTED_F4_VECTORS):
        fail("F4 section does not contain the frozen 12-vector table")
    for index, (record, expected_vector) in enumerate(
        zip(records, EXPECTED_F4_VECTORS)
    ):
        value = record.value
        exact_keys(value, F4_KEYS, f"F4_VECTOR[{index}]")
        identifier, left, right, result = expected_vector
        if value["case_id"] != identifier:
            fail(f"F4 vector {index} case_id differs")
        for key, expected, pattern in (
            ("left_f32", left, HEX8),
            ("right_f64", right, HEX16),
            ("expected_f64", result, HEX16),
            ("actual_f64", result, HEX16),
        ):
            observed = canonical_hex(value[key], pattern, f"F4_VECTOR[{index}].{key}")
            if observed != expected:
                fail(f"F4 vector {identifier} {key} differs")
        consumed = integer(
            value["consumed_fuel"], f"F4_VECTOR[{index}].consumed_fuel", minimum=1
        )
        remaining = integer(
            value["remaining_fuel"], f"F4_VECTOR[{index}].remaining_fuel"
        )
        poll_calls = integer(
            value["poll_calls"],
            f"F4_VECTOR[{index}].poll_calls",
            minimum=1,
            maximum=4096,
        )
        pending_polls = integer(
            value["pending_polls"], f"F4_VECTOR[{index}].pending_polls", maximum=4096
        )
        if (consumed, remaining, poll_calls, pending_polls) != (7, 99_993, 1, 0):
            fail(
                f"F4 vector {identifier} fuel or poll metrics differ from the frozen target"
            )


def validate_fuel(records: list[Record], meta: dict[str, object]) -> None:
    if len(records) != EXPECTED_FUEL_RECORDS:
        fail("FUEL section must contain exactly 999 Pending records and one terminal")
    previous_consumed = 0
    previous_remaining = int(meta["total_fuel"])
    for index, record in enumerate(records):
        value = record.value
        terminal = index == EXPECTED_PENDING_FUEL_RECORDS
        exact_keys(
            value, FUEL_TERMINAL_KEYS if terminal else FUEL_KEYS, f"FUEL[{index}]"
        )
        if value["case_id"] != EXPECTED_FUEL_CASE_ID:
            fail(f"FUEL[{index}] case_id differs")
        if integer(value["poll_index"], f"FUEL[{index}].poll_index") != index:
            fail(f"FUEL[{index}] poll index differs")
        expected_outcome = "fuel-exhausted" if terminal else "pending"
        if value["outcome"] != expected_outcome:
            fail(f"FUEL[{index}] outcome differs from {expected_outcome}")
        consumed = integer(value["consumed_fuel"], f"FUEL[{index}].consumed_fuel")
        remaining = integer(value["remaining_fuel"], f"FUEL[{index}].remaining_fuel")
        delta = integer(
            value["delta"], f"FUEL[{index}].delta", maximum=int(meta["poll_quantum"])
        )
        expected_delta = 99 if index == 0 else 100
        if delta != expected_delta:
            fail(f"FUEL[{index}] delta differs from the frozen trace")
        if (
            consumed != previous_consumed + delta
            or remaining != previous_remaining - delta
        ):
            fail(f"FUEL[{index}] does not continue the exact prior fuel state")
        if consumed + remaining != meta["total_fuel"]:
            fail(f"FUEL[{index}] fuel does not sum to the exact total")
        if terminal:
            digest = canonical_hex(
                value["trace_digest"],
                HEX16,
                f"FUEL[{index}].trace_digest",
                nonzero=True,
            )
            if digest != EXPECTED_FUEL_TRACE_DIGEST:
                fail("terminal FUEL trace digest differs from the frozen host witness")
        previous_consumed, previous_remaining = consumed, remaining
    if (previous_consumed, previous_remaining) != (99_999, 1):
        fail("terminal FUEL trace metrics differ from the frozen host witness")


def validate_lifecycle(records: list[Record], meta: dict[str, object]) -> None:
    if len(records) != len(EXPECTED_LIFECYCLE_STEPS):
        fail("LIFECYCLE section snapshot count differs")
    counter_names = (
        "activations",
        "calls_started",
        "calls_completed",
        "cancellations",
        "revocations",
        "faults",
        "reclaimed_instances",
    )
    expected_counters = (
        (1, 13, 12, 1, 0, 0, 1),
        (2, 14, 12, 1, 0, 1, 2),
        (3, 15, 12, 1, 0, 2, 3),
        (4, 16, 13, 1, 0, 2, 3),
        (4, 16, 13, 1, 1, 2, 4),
    )
    expected_last = (
        (99, 99_901),
        (5, 99_995),
        (99_999, 1),
        (7, 99_993),
        (7, 99_993),
    )
    observed_last: list[tuple[int, int]] = []
    for index, (record, expected) in enumerate(zip(records, EXPECTED_LIFECYCLE_STEPS)):
        value = record.value
        exact_keys(value, LIFECYCLE_KEYS, f"LIFECYCLE[{index}]")
        if (
            value["case_id"] != "candidate-lifecycle"
            or (value["step"], value["state"]) != expected
        ):
            fail(f"LIFECYCLE[{index}] identity, step, or state differs")
        live = integer(
            value["live_instances"], f"LIFECYCLE[{index}].live_instances", maximum=1
        )
        expected_live = 1 if value["state"] == "idle" else 0
        if live != expected_live:
            fail(f"LIFECYCLE[{index}] live-instance count differs from state")
        current = tuple(
            integer(value[name], f"LIFECYCLE[{index}].{name}") for name in counter_names
        )
        if current != expected_counters[index]:
            fail(f"LIFECYCLE[{index}] counters differ from the frozen host witness")
        if (
            integer(
                value["peak_live_instances"], f"LIFECYCLE[{index}].peak_live_instances"
            )
            != 1
        ):
            fail(f"LIFECYCLE[{index}] peak live instances differs from one")
        consumed = integer(
            value["last_consumed_fuel"], f"LIFECYCLE[{index}].last_consumed_fuel"
        )
        remaining = integer(
            value["last_remaining_fuel"], f"LIFECYCLE[{index}].last_remaining_fuel"
        )
        if (consumed, remaining) != expected_last[index]:
            fail(f"LIFECYCLE[{index}] last metrics differ from the frozen host witness")
        observed_last.append((consumed, remaining))
    if observed_last != list(expected_last):
        fail("lifecycle terminal metrics differ from the frozen host witness")


def semantic_digest(records: Iterable[Record]) -> str:
    digest = hashlib.sha256()
    digest.update(SEMANTIC_DIGEST_DOMAIN)
    for record in records:
        semantic = {
            key: value
            for key, value in record.value.items()
            if key not in COMMON_DATA_KEYS
        }
        digest.update(record.family.encode("ascii"))
        digest.update(b"\0")
        digest.update(canonical_json(semantic))
        digest.update(b"\n")
    return digest.hexdigest()


def family_counts(records: Iterable[Record]) -> dict[str, int]:
    counts = {family: 0 for family in DATA_FAMILIES}
    for record in records:
        counts[record.family] += 1
    return counts


def validate_terminal(
    record: Record,
    *,
    family: str,
    environment: dict[str, object],
    counts: dict[str, int],
    records: int,
    semantic_sha256: str,
) -> dict[str, object]:
    value = record.value
    exact_keys(value, TERMINAL_KEYS, family)
    validate_schema(record)
    canonical_hex(value["run_id"], HEX64, f"{family}.run_id", nonzero=True)
    canonical_hex(value["challenge"], HEX64, f"{family}.challenge", nonzero=True)
    for key in (
        "core_cases",
        "f3_cases",
        "f4_vectors",
        "fuel_records",
        "lifecycle_records",
        "records",
    ):
        integer(value[key], f"{family}.{key}", minimum=1, maximum=8192)
    canonical_hex(
        value["semantic_sha256"], HEX64, f"{family}.semantic_sha256", nonzero=True
    )
    expected = {
        "run_id": environment["run_id"],
        "challenge": environment["challenge"],
        "core_cases": counts["CORE_CASE"],
        "f3_cases": counts["F3_CASE"],
        "f4_vectors": counts["F4_VECTOR"],
        "fuel_records": counts["FUEL"],
        "lifecycle_records": counts["LIFECYCLE"],
        "records": records,
        "semantic_sha256": semantic_sha256,
    }
    for key, expected_value in expected.items():
        if value[key] != expected_value:
            fail(f"{family} {key} differs")
    if value["semantic_sha256"] != environment["expected_semantic_sha256"]:
        fail(f"{family} semantic digest differs from the environment")
    return value


def verify_uart_bytes(
    uart: bytes,
    environment_value: object,
    *,
    verify_self_identity: bool = True,
    expected_semantic_sha256: str = EXPECTED_SEMANTIC_SHA256,
) -> VerifiedTranscript:
    environment = validate_environment(
        environment_value,
        uart,
        verify_self_identity=verify_self_identity,
        expected_semantic_sha256=expected_semantic_sha256,
    )
    meta_record, records, end_record, pass_record = parse_uart(uart)
    meta, declared_counts = validate_meta(meta_record, environment)

    for sequence, record in enumerate(records):
        validate_common(record, str(environment["run_id"]), sequence)
    groups = {
        family: [record for record in records if record.family == family]
        for family in DATA_FAMILIES
    }
    actual_counts = family_counts(records)
    mapping = {
        "CORE_CASE": "core_cases",
        "F3_CASE": "f3_cases",
        "F4_VECTOR": "f4_vectors",
        "FUEL": "fuel_records",
        "LIFECYCLE": "lifecycle_records",
    }
    for family, meta_key in mapping.items():
        if actual_counts[family] != declared_counts[meta_key]:
            fail(f"{family} count differs from META")
    if len(records) != declared_counts["records"]:
        fail("data record count differs from META")

    validate_core(groups["CORE_CASE"], meta)
    validate_f3(groups["F3_CASE"])
    validate_f4(groups["F4_VECTOR"], meta)
    validate_fuel(groups["FUEL"], meta)
    validate_lifecycle(groups["LIFECYCLE"], meta)

    semantic_sha256 = semantic_digest(records)
    if semantic_sha256 != expected_semantic_sha256:
        fail("transcript semantic digest differs from the frozen host witness")
    ending = validate_terminal(
        end_record,
        family="END",
        environment=environment,
        counts=actual_counts,
        records=len(records),
        semantic_sha256=semantic_sha256,
    )
    passing = validate_terminal(
        pass_record,
        family="PASS",
        environment=environment,
        counts=actual_counts,
        records=len(records),
        semantic_sha256=semantic_sha256,
    )
    return VerifiedTranscript(
        metadata=meta,
        records=records,
        ending=ending,
        passing=passing,
        semantic_sha256=semantic_sha256,
        uart_sha256=sha256_bytes(uart),
        uart_bytes=len(uart),
    )


def rerun_elf_auditor(
    kernel_path: pathlib.Path,
    expected_report: bytes,
    environment: dict[str, object],
) -> None:
    try:
        python_path = pathlib.Path(sys.executable).resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve Python for final-ELF audit replay: {error}")
    build_tools = environment["build_tools"]
    assert isinstance(build_tools, dict)
    rustup = build_tools["rustup"]
    assert isinstance(rustup, dict)
    rustup_path = pathlib.Path(str(rustup["path"]))
    auditor = ROOT / "scripts/verify-c88-f5-riscv-elf.py"
    audit_environment = {
        "HOME": str(pathlib.Path.home()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join((str(rustup_path.parent), "/usr/bin", "/bin")),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    temporary_root = pathlib.Path("/private/tmp")
    try:
        temporary_metadata = temporary_root.lstat()
        resolved_temporary_root = temporary_root.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect fixed final-ELF audit replay directory: {error}")
    if (
        stat.S_ISLNK(temporary_metadata.st_mode)
        or not stat.S_ISDIR(temporary_metadata.st_mode)
        or resolved_temporary_root != temporary_root
    ):
        fail("fixed final-ELF audit replay directory must be one direct directory")
    with tempfile.TemporaryDirectory(
        prefix="vibeos-c88-f5-verify-elf-", dir=temporary_root
    ) as temporary_name:
        output = pathlib.Path(temporary_name) / "audit.json"
        completed = run_bounded_command(
            [
                str(python_path),
                "-I",
                "-B",
                str(auditor),
                "--elf",
                str(kernel_path),
                "--output",
                str(output),
            ],
            cwd=ROOT,
            environment=audit_environment,
            maximum_output=MAX_ELF_AUDIT_BYTES,
            timeout_seconds=600.0,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).decode(
                "utf-8", errors="replace"
            )
            fail(
                f"replayed final-ELF auditor rejected the retained kernel: {detail.strip()}"
            )
        if completed.stdout or completed.stderr:
            fail("successful replayed final-ELF auditor emitted process output")
        replay = stable_regular_bytes(
            output, "replayed final-ELF audit", maximum=MAX_ELF_AUDIT_BYTES
        )
        if replay != expected_report:
            fail("replayed final-ELF audit differs from the retained report")


def verify_files(
    uart_path: pathlib.Path,
    environment_path: pathlib.Path,
    kernel_path: pathlib.Path,
    elf_audit_path: pathlib.Path,
) -> VerifiedTranscript:
    direct_uart = pathlib.Path(os.path.abspath(os.fspath(uart_path)))
    uart = stable_regular_bytes(direct_uart, "UART transcript", maximum=MAX_UART_BYTES)
    environment_raw = stable_regular_bytes(
        environment_path, "environment envelope", maximum=MAX_ENVIRONMENT_BYTES
    )
    environment = strict_json_bytes(environment_raw, "environment envelope")
    verified = verify_uart_bytes(uart, environment)
    if not isinstance(environment, dict):
        fail("environment must be one JSON object")
    canonical_environment = (
        json.dumps(
            environment,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    if environment_raw != canonical_environment:
        fail("environment envelope is not the canonical serialized evidence")

    uart_identity = identity_record(environment["uart"], "environment.uart")
    if uart_identity["path"] != str(direct_uart):
        fail("environment UART path differs from --uart")

    retained_report: bytes | None = None
    direct_kernel = pathlib.Path(os.path.abspath(os.fspath(kernel_path)))
    for key, path, label, maximum in (
        ("kernel", kernel_path, "retained F5 kernel ELF", MAX_KERNEL_BYTES),
        (
            "elf_audit_report",
            elf_audit_path,
            "retained final-ELF audit report",
            MAX_ELF_AUDIT_BYTES,
        ),
    ):
        identity = identity_record(environment[key], f"environment.{key}")
        direct_path = pathlib.Path(os.path.abspath(os.fspath(path)))
        if identity["path"] != str(direct_path):
            fail(f"environment {label} path differs from its verifier argument")
        raw = stable_regular_bytes(direct_path, label, maximum=maximum)
        if identity["sha256"] != sha256_bytes(raw) or identity["bytes"] != len(raw):
            fail(f"environment identity differs from the actual {label}")
        if key == "elf_audit_report":
            expected_report = canonical_json(environment["elf_audit"]) + b"\n"
            if raw != expected_report:
                fail("retained final-ELF audit differs from environment.elf_audit")
            retained_report = raw
    if retained_report is None:
        fail("retained final-ELF audit was not verified")
    rerun_elf_auditor(direct_kernel, retained_report, environment)
    return verified


def make_record(family: str, sequence: int, run_id: str, **fields: object) -> Record:
    value: dict[str, object] = {
        "schema": SCHEMAS[family],
        "version": SCHEMA_VERSION,
        "run_id": run_id,
        "sequence": sequence,
        **fields,
    }
    return Record(family, value, 0)


def render_record(record: Record) -> str:
    return PREFIXES[record.family] + canonical_json(record.value).decode("ascii")


def synthetic_fixture() -> tuple[bytes, dict[str, object]]:
    source_commit = "1" * 40
    source_tree = "2" * 40
    challenge = "3" * 64
    manifest_sha256 = EXPECTED_MANIFEST_SHA256
    verifier_path = pathlib.Path(__file__).resolve(strict=True)
    verifier_raw = verifier_path.read_bytes()
    transcript_schema = sha256_bytes(verifier_raw)

    def identity(path: str, token: str, length: int = 1024) -> dict[str, object]:
        return {"path": path, "sha256": token * 64, "bytes": length}

    kernel_identity = identity("/evidence/vibeos-qemu-virt", "6")
    elf_audit: dict[str, object] = {
        "checks": [
            "elf64-little-riscv-et_exec",
            "soft-abi-rvc-flags",
            "exact-rv64-imac-attributes",
            "static-no-relocations",
            "section-and-segment-wx",
            "section-load-congruent-mapping",
            "rx-exec-section-exact-coverage",
            "canonical-riscv-opcodes",
            "objdump-boundary-cross-check",
            "canonical-control-flow-targets",
            "nm-zero-float-helpers",
            "stable-input-identity",
        ],
        "elf": {
            "bytes": kernel_identity["bytes"],
            "control_flow": {"canonical_boundaries": 3, "direct_targets": 0},
            "e_flags": "0x00000001",
            "entry": "0x0000000080200000",
            "executable_sections": [
                {
                    "address": "0x0000000080200000",
                    "bytes": 6,
                    "four_byte_instructions": 1,
                    "instructions": 2,
                    "name": ".text",
                    "sha256": "d" * 64,
                    "two_byte_instructions": 1,
                }
            ],
            "forbidden_opcodes": [],
            "program_headers": 3,
            "riscv_arch": (
                "rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_"
                "zaamo1p0_zalrsc1p0_zca1p0"
            ),
            "sections": 8,
            "sha256": kernel_identity["sha256"],
            "symbols": {
                "code_symbols": 2,
                "defined": 2,
                "forbidden_helpers": [],
                "raw_symtab_entries": 3,
                "undefined": 0,
            },
        },
        "execution_scope": [
            "trusted-native-control-flow",
            "canonical-decoder-boundaries",
            "arbitrary-PC-redirection-not-claimed",
            "hardware-NX-not-claimed",
        ],
        "mode": "audit",
        "schema": "vibeos.c88.f5.riscv-final-elf.audit",
        "schema_version": 1,
        "status": "pass",
        "target": "riscv64imac-unknown-none-elf",
        "toolchain": {
            "channel": "nightly-2026-08-01",
            "host": "aarch64-apple-darwin",
            "llvm_build": "22.1.8-rust-1.99.0-nightly",
            "llvm_version": "22.1.8",
            "rustc_commit": "ad3d0bc141a02cf446e384136d250a1f6950fed5",
            "rustc_release": "1.99.0-nightly",
            "tools": copy.deepcopy(EXPECTED_ELF_AUDIT_TOOL_IDENTITIES),
        },
    }
    elf_audit_bytes = canonical_json(elf_audit) + b"\n"
    dependency_records: list[dict[str, object]] = [
        {
            "name": "fixture",
            "version": "1.0.0",
            "source": CRATES_IO_SOURCE,
            "checksum": "e" * 64,
            "filename": "fixture-1.0.0.crate",
            "sha256": "e" * 64,
            "bytes": 128,
        }
    ]
    environment: dict[str, object] = {
        "schema": "vibeos.c88.f5.float-target.environment",
        "version": 1,
        "suite_id": SUITE_ID,
        "mode": "formal-qemu",
        "source": {
            "commit": source_commit,
            "tree": source_tree,
            "clean": True,
            "branch": "codex/wasm",
            "remote_ref": "refs/remotes/origin/codex/wasm",
            "remote_commit": source_commit,
        },
        "platform": {
            "id": "qemu-virt-rv64-tcg-icount-v1",
            "class": "emulator",
            "target": "riscv64imac-unknown-none-elf",
            "physical_provenance": "not-claimed",
        },
        "build": {
            "target": "riscv64imac-unknown-none-elf",
            "package": "vibeos-firmware-qemu-virt",
            "feature": "wasm-c88-f5-float-qemu-acceptance",
            "profile": "release",
            "no_default_features": True,
            "locked": True,
            "offline": True,
            "rustflags": [
                "-C",
                "linker=ld.lld",
                "-C",
                "linker-flavor=ld",
                "-C",
                "target-feature=+zicsr,+zifencei",
                "-C",
                "link-arg=--gc-sections",
                "-C",
                "force-frame-pointers=yes",
                "-Z",
                "fmt-debug=none",
            ],
        },
        "build_tools": copy.deepcopy(EXPECTED_BUILD_TOOLS),
        "dependency_archives": {
            "cargo_lock": identity("/source/Cargo.lock", "7"),
            "cargo_config": identity("/source/firmware/.cargo/config.toml", "4"),
            "rust_source": copy.deepcopy(EXPECTED_RUST_SOURCE),
            "count": len(dependency_records),
            "records_sha256": sha256_bytes(canonical_json(dependency_records)),
            "records": dependency_records,
        },
        "python": identity("/runtime/python3", "8"),
        "kernel": kernel_identity,
        "qemu": {
            **EXPECTED_QEMU_IDENTITY,
            "version": EXPECTED_QEMU_VERSION,
            "argv": [
                EXPECTED_QEMU_IDENTITY["path"],
                "-no-user-config",
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
                "-nic",
                "none",
                "-bios",
                EXPECTED_BIOS_IDENTITY["path"],
                "-kernel",
                "/evidence/vibeos-qemu-virt",
            ],
        },
        "bios": copy.deepcopy(EXPECTED_BIOS_IDENTITY),
        "uart": identity("/evidence/qemu-uart.log", "9"),
        "manifest": {
            "path": (
                "/source/acceptance/wasm-float-target/artifacts/"
                "qualification-manifest.json"
            ),
            "sha256": EXPECTED_MANIFEST_SHA256,
            "bytes": EXPECTED_MANIFEST_BYTES,
        },
        "producer": identity("/source/kernel/src/wasm_float_target.rs", "a"),
        "qualification": identity(
            "/source/acceptance/wasm-float-target/src/lib.rs", "f"
        ),
        "runner": identity("/source/scripts/qemu-c88-f5-float-target.py", "b"),
        "verifier": {
            "path": str(verifier_path),
            "sha256": sha256_bytes(verifier_raw),
            "bytes": len(verifier_raw),
        },
        "elf_auditor": identity("/source/scripts/verify-c88-f5-riscv-elf.py", "c"),
        "elf_audit_report": {
            "path": "/evidence/riscv-final-elf-audit.json",
            "sha256": sha256_bytes(elf_audit_bytes),
            "bytes": len(elf_audit_bytes),
        },
        "elf_audit": elf_audit,
        "challenge": challenge,
        "run_id": "0" * 64,
        "manifest_sha256": manifest_sha256,
        "transcript_schema_sha256": transcript_schema,
        "expected_semantic_sha256": "0" * 64,
        "evidence_sha256": "0" * 64,
    }
    environment["run_id"] = expected_run_id(environment)
    run_id = str(environment["run_id"])

    records: list[Record] = []
    sequence = 0
    for frozen in EXPECTED_CORE_CASES:
        expected = str(frozen["expected"])
        spin = frozen["path"] == "spin"
        records.append(
            make_record(
                "CORE_CASE",
                sequence,
                run_id,
                **frozen,
                actual=expected,
                outcome="trapped" if expected.startswith("trap:") else "ready",
                trace_digest=(
                    EXPECTED_CORE_SPIN_TRACE_DIGEST if spin else "1111111111111111"
                ),
                consumed_fuel=99_998 if spin else 10,
                remaining_fuel=2 if spin else 99_990,
                poll_calls=1_011 if spin else 1,
                pending_polls=1_010 if spin else 0,
            )
        )
        sequence += 1
    solve_core_terminal_trace(
        records, "runtime", 0x7275_6E74_696D_6500, EXPECTED_CORE_RUNTIME_DIGEST
    )
    solve_core_terminal_trace(
        records, "fold", 0x666F_6C64_0000_0000, EXPECTED_CORE_FOLD_DIGEST
    )
    for identifier, raw32, raw64 in zip(F3_CASE_IDS, F3_RAW_F32, F3_RAW_F64):
        records.append(
            make_record(
                "F3_CASE",
                sequence,
                run_id,
                case_id=identifier,
                kind="vector",
                raw_f32=raw32,
                raw_f64=raw64,
                expected_f32=oracle_f32(raw32),
                expected_f64=oracle_f64(raw64),
                actual_f32=oracle_f32(raw32),
                actual_f64=oracle_f64(raw64),
            )
        )
        sequence += 1
    records.append(
        make_record(
            "F3_CASE",
            sequence,
            run_id,
            case_id="summary",
            kind="summary",
            **EXPECTED_F3_SUMMARY,
        )
    )
    sequence += 1
    for identifier, left, right, result in EXPECTED_F4_VECTORS:
        records.append(
            make_record(
                "F4_VECTOR",
                sequence,
                run_id,
                case_id=identifier,
                left_f32=left,
                right_f64=right,
                expected_f64=result,
                actual_f64=result,
                consumed_fuel=7,
                remaining_fuel=99_993,
                poll_calls=1,
                pending_polls=0,
            )
        )
        sequence += 1
    consumed = 0
    for poll_index in range(EXPECTED_FUEL_RECORDS):
        delta = 99 if poll_index == 0 else 100
        consumed += delta
        terminal = poll_index == EXPECTED_PENDING_FUEL_RECORDS
        records.append(
            make_record(
                "FUEL",
                sequence,
                run_id,
                case_id=EXPECTED_FUEL_CASE_ID,
                poll_index=poll_index,
                outcome=("fuel-exhausted" if terminal else "pending"),
                consumed_fuel=consumed,
                remaining_fuel=100_000 - consumed,
                delta=delta,
                **({"trace_digest": EXPECTED_FUEL_TRACE_DIGEST} if terminal else {}),
            )
        )
        sequence += 1
    lifecycle_values = (
        ("cancelled", "cancelled", 0, 1, 13, 12, 1, 0, 0, 1, 99, 99_901),
        (
            "unreachable-fault",
            "faulted-unreachable",
            0,
            2,
            14,
            12,
            1,
            0,
            1,
            2,
            5,
            99_995,
        ),
        ("fuel-fault", "faulted-fuel-exhausted", 0, 3, 15, 12, 1, 0, 2, 3, 99_999, 1),
        ("recovered", "idle", 1, 4, 16, 13, 1, 0, 2, 3, 7, 99_993),
        ("revoked", "revoked", 0, 4, 16, 13, 1, 1, 2, 4, 7, 99_993),
    )
    for (
        step,
        state,
        live,
        activations,
        started,
        completed,
        cancellations,
        revocations,
        faults,
        reclaimed,
        last_consumed,
        last_remaining,
    ) in lifecycle_values:
        records.append(
            make_record(
                "LIFECYCLE",
                sequence,
                run_id,
                case_id="candidate-lifecycle",
                step=step,
                state=state,
                live_instances=live,
                activations=activations,
                calls_started=started,
                calls_completed=completed,
                cancellations=cancellations,
                revocations=revocations,
                faults=faults,
                reclaimed_instances=reclaimed,
                peak_live_instances=1,
                last_consumed_fuel=last_consumed,
                last_remaining_fuel=last_remaining,
            )
        )
        sequence += 1

    counts = family_counts(records)
    semantic = semantic_digest(records)
    environment["expected_semantic_sha256"] = semantic
    meta: dict[str, object] = {
        "schema": SCHEMAS["META"],
        "version": 1,
        "suite_id": SUITE_ID,
        "suite_revision": 1,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "challenge": challenge,
        "run_id": run_id,
        "manifest_sha256": manifest_sha256,
        "transcript_schema_sha256": transcript_schema,
        "platform": "qemu-virt-rv64-tcg-icount-v1",
        "platform_class": "emulator",
        "target": "riscv64imac-unknown-none-elf",
        "physical_provenance": "not-claimed",
        "artifact_profile_code": 5,
        "artifact_abi": 5,
        "component_profile": 2,
        "core_profile": 2,
        "runtime_abi": 5,
        "stage": "validation-only",
        "runtime_ready": False,
        "native_async_runtime_ready": False,
        "execution_enabled": False,
        "current_validation_engine": False,
        "current_component_engine": False,
        **EXPECTED_CANDIDATE,
        "candidate_production_ready": False,
        "core_module_sha256": EXPECTED_CORE_MODULE_SHA256,
        "core_module_bytes": EXPECTED_CORE_MODULE_BYTES,
        "core_compile_reservation_bytes": EXPECTED_CORE_COMPILE_RESERVATION_BYTES,
        "core_memory_bytes": EXPECTED_CORE_MEMORY_BYTES,
        "core_runtime_digest": EXPECTED_CORE_RUNTIME_DIGEST,
        "core_fold_digest": EXPECTED_CORE_FOLD_DIGEST,
        "core_spin_trace_digest": EXPECTED_CORE_SPIN_TRACE_DIGEST,
        "component_sha256": EXPECTED_COMPONENT_SHA256,
        "component_bytes": 291,
        "wit_sha256": EXPECTED_WIT_SHA256,
        "world": EXPECTED_WORLD,
        "export": EXPECTED_EXPORT,
        "activation_label": EXPECTED_ACTIVATION_LABEL,
        "memory_bytes": 131_072,
        "total_fuel": 100_000,
        "poll_quantum": 100,
        "resources": 0,
        "embedded_modules": 1,
        "core_instances": 1,
        "component_instances": 0,
        "aliases": 1,
        "canonical_functions": 1,
        "adapters": 0,
        "imports": 0,
        "host_imports": 0,
        "exports": 1,
        "executable_exports": 0,
        "exact_binding": True,
        "core_cases": counts["CORE_CASE"],
        "f3_cases": counts["F3_CASE"],
        "f4_vectors": counts["F4_VECTOR"],
        "fuel_records": counts["FUEL"],
        "lifecycle_records": counts["LIFECYCLE"],
        "records": len(records),
    }
    terminal = {
        "version": 1,
        "run_id": run_id,
        "challenge": challenge,
        "core_cases": counts["CORE_CASE"],
        "f3_cases": counts["F3_CASE"],
        "f4_vectors": counts["F4_VECTOR"],
        "fuel_records": counts["FUEL"],
        "lifecycle_records": counts["LIFECYCLE"],
        "records": len(records),
        "semantic_sha256": semantic,
    }
    end = Record("END", {"schema": SCHEMAS["END"], **terminal}, 0)
    passing = Record("PASS", {"schema": SCHEMAS["PASS"], **terminal}, 0)
    lines = [PREFIXES["META"] + canonical_json(meta).decode("ascii")]
    lines.extend(render_record(record) for record in records)
    lines.extend((render_record(end), render_record(passing)))
    uart = ("\n".join(lines) + "\n").encode("utf-8")
    environment["uart"] = {
        "path": "/evidence/qemu-uart.log",
        "sha256": sha256_bytes(uart),
        "bytes": len(uart),
    }
    environment["evidence_sha256"] = environment_evidence_sha256(environment)
    return uart, environment


def replace_json_line(
    lines: list[str],
    family: str,
    occurrence: int,
    update: Callable[[dict[str, object]], None],
) -> None:
    prefix = PREFIXES[family]
    positions = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    position = positions[occurrence]
    value = strict_json_text(lines[position][len(prefix) :], f"selftest {family}")
    update(value)
    lines[position] = prefix + canonical_json(value).decode("ascii")


def refresh_uart_identity(environment: dict[str, object], uart: bytes) -> None:
    uart_record = environment["uart"]
    assert isinstance(uart_record, dict)
    uart_record["sha256"] = sha256_bytes(uart)
    uart_record["bytes"] = len(uart)


def refresh_evidence_identity(environment: dict[str, object]) -> None:
    environment["evidence_sha256"] = environment_evidence_sha256(environment)


def refresh_elf_audit_identity(environment: dict[str, object]) -> None:
    report = environment["elf_audit_report"]
    audit = environment["elf_audit"]
    assert isinstance(report, dict) and isinstance(audit, dict)
    encoded = canonical_json(audit) + b"\n"
    report["sha256"] = sha256_bytes(encoded)
    report["bytes"] = len(encoded)


def selftest() -> None:
    if git_environment().get("GIT_NO_REPLACE_OBJECTS") != "1":
        fail("selftest Git replace objects are not disabled")
    try:
        python_path = pathlib.Path(sys.executable).resolve(strict=True)
    except OSError as error:
        fail(f"selftest cannot resolve Python interpreter: {error}")
    python_raw = stable_regular_bytes(
        python_path, "selftest Python interpreter", maximum=MAX_KERNEL_BYTES
    )
    if not python_raw:
        fail("selftest Python interpreter identity is empty")
    subprocess_environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    completed = run_bounded_command(
        [
            str(python_path),
            "-I",
            "-B",
            "-c",
            "import sys;sys.stdout.buffer.write(b'out');sys.stderr.buffer.write(b'err')",
        ],
        cwd=ROOT,
        environment=subprocess_environment,
        maximum_output=16,
        timeout_seconds=5.0,
    )
    if (
        completed.returncode != 0
        or completed.stdout != b"out"
        or completed.stderr != b"err"
    ):
        fail("selftest bounded subprocess capture differs")
    for label, command, maximum, timeout in (
        (
            "output limit",
            [
                str(python_path),
                "-I",
                "-B",
                "-c",
                "import sys;sys.stdout.write('x'*4096)",
            ],
            32,
            5.0,
        ),
        (
            "timeout",
            [str(python_path), "-I", "-B", "-c", "import time;time.sleep(10)"],
            32,
            0.05,
        ),
    ):
        try:
            run_bounded_command(
                command,
                cwd=ROOT,
                environment=subprocess_environment,
                maximum_output=maximum,
                timeout_seconds=timeout,
            )
        except VerificationError:
            pass
        else:
            fail(f"selftest subprocess {label} was not enforced")

    with tempfile.TemporaryDirectory(
        prefix="vibeos-c88-f5-verifier-process-selftest-", dir="/private/tmp"
    ) as temporary_name:
        marker = pathlib.Path(temporary_name) / "lingering-child-survived"
        code = (
            "import os,signal,sys,time\n"
            "read_fd,write_fd=os.pipe()\n"
            "child=os.fork()\n"
            "if child == 0:\n"
            " os.close(read_fd)\n"
            " signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            " os.write(write_fd,b'1')\n"
            " os.close(write_fd);os.close(1);os.close(2)\n"
            " time.sleep(0.5)\n"
            " open(sys.argv[1],'xb').write(b'survived')\n"
            " time.sleep(10)\n"
            "else:\n"
            " os.close(write_fd);os.read(read_fd,1);os.close(read_fd)\n"
            " print(child,flush=True)\n"
        )
        lingering = run_bounded_command(
            [str(python_path), "-I", "-B", "-c", code, str(marker)],
            cwd=ROOT,
            environment=subprocess_environment,
            maximum_output=64,
            timeout_seconds=5.0,
        )
        if lingering.returncode != 0 or not lingering.stdout.strip().isdigit():
            fail("selftest lingering-child fixture did not complete")
        time.sleep(0.75)
        if os.path.lexists(marker):
            fail("selftest leader exit allowed a same-PGID descendant to survive")

    good, good_environment = synthetic_fixture()
    fixture_semantic = str(good_environment["expected_semantic_sha256"])
    verified = verify_uart_bytes(
        good,
        good_environment,
        verify_self_identity=False,
        expected_semantic_sha256=fixture_semantic,
    )
    if len(verified.records) != 1176:
        fail("selftest good transcript record count differs")

    mutations: list[tuple[str, bytes, dict[str, object]]] = []

    def line_mutation(
        name: str,
        action: Callable[[list[str]], None],
        *,
        refresh: bool = True,
    ) -> None:
        lines = good.decode("utf-8").splitlines()
        action(lines)
        uart = ("\n".join(lines) + "\n").encode("utf-8")
        environment = copy.deepcopy(good_environment)
        if refresh:
            refresh_uart_identity(environment, uart)
        refresh_evidence_identity(environment)
        mutations.append((name, uart, environment))

    line_mutation(
        "single-field",
        lambda lines: replace_json_line(
            lines,
            "F4_VECTOR",
            0,
            lambda value: value.update(actual_f64="0000000000000001"),
        ),
    )
    line_mutation(
        "component-byte-length",
        lambda lines: replace_json_line(
            lines, "META", 0, lambda value: value.update(component_bytes=290)
        ),
    )
    line_mutation(
        "duplicate-record",
        lambda lines: lines.insert(
            next(
                index
                for index, line in enumerate(lines)
                if line.startswith(PREFIXES["CORE_CASE"])
            )
            + 1,
            next(line for line in lines if line.startswith(PREFIXES["CORE_CASE"])),
        ),
    )
    line_mutation(
        "deleted-record",
        lambda lines: lines.pop(
            next(
                index
                for index, line in enumerate(lines)
                if line.startswith(PREFIXES["F3_CASE"])
            )
        ),
    )

    def reorder(lines: list[str]) -> None:
        positions = [
            index
            for index, line in enumerate(lines)
            if line.startswith(PREFIXES["F4_VECTOR"])
        ]
        lines[positions[0]], lines[positions[1]] = (
            lines[positions[1]],
            lines[positions[0]],
        )

    line_mutation("reordered-records", reorder)
    line_mutation(
        "unknown-family",
        lambda lines: lines.insert(-2, 'VIBE_C88_F5_UNKNOWN {"version":1}'),
    )
    line_mutation(
        "post-pass-family",
        lambda lines: lines.append(
            next(line for line in lines if line.startswith(PREFIXES["FUEL"]))
        ),
    )
    line_mutation("post-pass-fatal", lambda lines: lines.append("fatal after pass"))
    line_mutation(
        "explicit-fail", lambda lines: lines.insert(-2, "VIBE_C88_F5_FAIL code=1")
    )
    line_mutation("missing-pass", lambda lines: lines.pop())
    no_final_newline = good[:-1]
    no_final_newline_environment = copy.deepcopy(good_environment)
    refresh_uart_identity(no_final_newline_environment, no_final_newline)
    refresh_evidence_identity(no_final_newline_environment)
    mutations.append(
        ("missing-final-newline", no_final_newline, no_final_newline_environment)
    )
    line_mutation(
        "extra-json-key",
        lambda lines: replace_json_line(
            lines, "F3_CASE", 0, lambda value: value.update(unexpected=True)
        ),
    )

    def duplicate_member(lines: list[str]) -> None:
        position = next(
            index
            for index, line in enumerate(lines)
            if line.startswith(PREFIXES["CORE_CASE"])
        )
        needle = '"case_id":"runtime-f32-add"'
        lines[position] = lines[position].replace(
            needle, needle + ',"case_id":"runtime-f32-add"', 1
        )

    line_mutation("duplicate-json-member", duplicate_member)
    line_mutation(
        "uart-identity",
        lambda lines: replace_json_line(
            lines, "FUEL", 0, lambda value: value.update(delta=98)
        ),
        refresh=False,
    )

    for name, mutate in (
        (
            "physical-provenance",
            lambda environment: environment["platform"].update(
                physical_provenance="physical-duo"
            ),
        ),
        (
            "qemu-authority",
            lambda environment: environment["qemu"]["argv"].extend(
                ["-drive", "file=/tmp/disk.img"]
            ),
        ),
        ("wrong-run-id", lambda environment: environment.update(run_id="f" * 64)),
        (
            "qemu-identity",
            lambda environment: environment["qemu"].update(sha256="e" * 64),
        ),
        (
            "bios-identity",
            lambda environment: environment["bios"].update(sha256="e" * 64),
        ),
        (
            "rustc-identity",
            lambda environment: environment["build_tools"]["rustc"].update(
                sha256="e" * 64
            ),
        ),
    ):
        environment = copy.deepcopy(good_environment)
        mutate(environment)
        refresh_evidence_identity(environment)
        mutations.append((name, good, environment))

    audit_environment = copy.deepcopy(good_environment)
    audit = audit_environment["elf_audit"]
    assert isinstance(audit, dict)
    audit_elf = audit["elf"]
    assert isinstance(audit_elf, dict)
    audit_symbols = audit_elf["symbols"]
    assert isinstance(audit_symbols, dict)
    audit_symbols["forbidden_helpers"] = ["__addsf3"]
    refresh_elf_audit_identity(audit_environment)
    refresh_evidence_identity(audit_environment)
    mutations.append(("elf-helper-report", good, audit_environment))

    build_boolean_environment = copy.deepcopy(good_environment)
    build_value = build_boolean_environment["build"]
    assert isinstance(build_value, dict)
    build_value["locked"] = 1
    refresh_evidence_identity(build_boolean_environment)
    mutations.append(("build-bool-as-integer", good, build_boolean_environment))

    rust_source_environment = copy.deepcopy(good_environment)
    dependency_value = rust_source_environment["dependency_archives"]
    assert isinstance(dependency_value, dict)
    rust_source_value = dependency_value["rust_source"]
    assert isinstance(rust_source_value, dict)
    rust_source_value["tree_sha256"] = "e" * 64
    refresh_evidence_identity(rust_source_environment)
    mutations.append(("rust-source-tree", good, rust_source_environment))

    audit_version_environment = copy.deepcopy(good_environment)
    audit_version = audit_version_environment["elf_audit"]
    assert isinstance(audit_version, dict)
    audit_version["schema_version"] = True
    refresh_elf_audit_identity(audit_version_environment)
    refresh_evidence_identity(audit_version_environment)
    mutations.append(("audit-integer-as-bool", good, audit_version_environment))

    undefined_environment = copy.deepcopy(good_environment)
    undefined_audit = undefined_environment["elf_audit"]
    assert isinstance(undefined_audit, dict)
    undefined_elf = undefined_audit["elf"]
    assert isinstance(undefined_elf, dict)
    undefined_symbols = undefined_elf["symbols"]
    assert isinstance(undefined_symbols, dict)
    undefined_symbols["undefined"] = False
    refresh_elf_audit_identity(undefined_environment)
    refresh_evidence_identity(undefined_environment)
    mutations.append(("undefined-integer-as-bool", good, undefined_environment))

    rejected = 0
    for name, uart, environment in mutations:
        try:
            verify_uart_bytes(
                uart,
                environment,
                verify_self_identity=False,
                expected_semantic_sha256=fixture_semantic,
            )
        except VerificationError:
            rejected += 1
        else:
            fail(f"selftest mutation was accepted: {name}")
    print(
        "verify-c88-f5-float-target.py selftest: PASS "
        f"({rejected} mutations rejected)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--uart", type=pathlib.Path, help="raw fixed-QEMU UART transcript"
    )
    parser.add_argument(
        "--environment", type=pathlib.Path, help="runner-produced environment envelope"
    )
    parser.add_argument(
        "--kernel", type=pathlib.Path, help="retained audited kernel ELF"
    )
    parser.add_argument(
        "--elf-audit", type=pathlib.Path, help="retained final-ELF audit report"
    )
    parser.add_argument(
        "--selftest", action="store_true", help="run fail-closed mutations"
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.selftest:
            if any(
                path is not None
                for path in (
                    arguments.uart,
                    arguments.environment,
                    arguments.kernel,
                    arguments.elf_audit,
                )
            ):
                fail("--selftest does not accept evidence paths")
            selftest()
            return 0
        if any(
            path is None
            for path in (
                arguments.uart,
                arguments.environment,
                arguments.kernel,
                arguments.elf_audit,
            )
        ):
            fail(
                "normal verification requires --uart, --environment, --kernel, "
                "and --elf-audit"
            )
        verified = verify_files(
            arguments.uart,
            arguments.environment,
            arguments.kernel,
            arguments.elf_audit,
        )
        print(
            "verify-c88-f5-float-target.py: PASS "
            f"records={len(verified.records)} semantic_sha256={verified.semantic_sha256} "
            f"uart_sha256={verified.uart_sha256} uart_bytes={verified.uart_bytes}"
        )
        return 0
    except VerificationError as error:
        print(f"verify-c88-f5-float-target.py: FAIL ({error})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
