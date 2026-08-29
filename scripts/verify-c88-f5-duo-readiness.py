#!/usr/bin/env python3
"""Verify the host-only C8.8-F5 Milk-V Duo compile-readiness contract.

The default mode verifies only checked-in JSON contracts and their source
wiring.  It does not build, boot, capture, package, reset, flash, access a
serial port, or claim physical provenance.  ``--elf`` optionally binds the
complete inert Duo payload and delegates the linked ELF to the independently
fail-closed C8.8-F5 RISC-V auditor.  That is structural compile-readiness only,
not formal Git/build provenance or physical evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Sequence


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_REL = (
    "acceptance/wasm-float-target/artifacts/qualification-duo-v1-manifest.json"
)
TRANSCRIPT_SCHEMA_REL = (
    "acceptance/wasm-float-target/artifacts/"
    "qualification-duo-v1-transcript-schema.json"
)
ACCEPTANCE_CARGO_REL = "acceptance/wasm-float-target/Cargo.toml"
ACCEPTANCE_BUILD_REL = "acceptance/wasm-float-target/build.rs"
ACCEPTANCE_LIB_REL = "acceptance/wasm-float-target/src/lib.rs"
ADAPTER_CARGO_REL = "services/component-image-adapter/Cargo.toml"
ADAPTER_LIB_REL = "services/component-image-adapter/src/lib.rs"
POLICY_CARGO_REL = "policy/image/Cargo.toml"
POLICY_LIB_REL = "policy/image/src/lib.rs"
KERNEL_CARGO_REL = "kernel/Cargo.toml"
KERNEL_LIB_REL = "kernel/src/lib.rs"
KERNEL_ADAPTER_REL = "kernel/src/wasm_float_target.rs"
RUNTIME_BARE_REL = "runtime/riscv/src/bare.rs"
MILKV_FIRMWARE_REL = "firmware/milkv-duo/Cargo.toml"
QEMU_FIRMWARE_REL = "firmware/qemu-virt/Cargo.toml"
BUILD_SCRIPT_REL = "scripts/build-c88-f5-duo-readiness.sh"
ELF_AUDITOR_REL = "scripts/verify-c88-f5-riscv-elf.py"
ELF_AUDITOR = ROOT / ELF_AUDITOR_REL

SOURCE_RELS = (
    MANIFEST_REL,
    TRANSCRIPT_SCHEMA_REL,
    ACCEPTANCE_CARGO_REL,
    ACCEPTANCE_BUILD_REL,
    ACCEPTANCE_LIB_REL,
    ADAPTER_CARGO_REL,
    ADAPTER_LIB_REL,
    POLICY_CARGO_REL,
    POLICY_LIB_REL,
    KERNEL_CARGO_REL,
    KERNEL_LIB_REL,
    KERNEL_ADAPTER_REL,
    RUNTIME_BARE_REL,
    MILKV_FIRMWARE_REL,
    QEMU_FIRMWARE_REL,
    BUILD_SCRIPT_REL,
    ELF_AUDITOR_REL,
)

SCHEMA = "vibeos.c88.f5.float-target.duo-v1.manifest"
SCHEMA_VERSION = 1
SUITE_ID = "vibeos.c88.f5.float-target.duo-v1"
ACCEPTANCE_FEATURE = "c88-f5-duo-compile-readiness"
IMAGE_FEATURE = "wasm-c88-f5-float-duo-compile-readiness"
PLATFORM = "milkv-duo-cv1800b-c906-v1"
PLATFORM_CLASS = "physical-target"
TARGET = "riscv64imac-unknown-none-elf"
PHYSICAL_PROVENANCE = "not-claimed"
READINESS_STAGE = "compile-only-inert-sentinel"
PHYSICAL_STATUS = "deferred"
RUN_ID_DOMAIN = "vibeos.c88.f5.float-target.duo-v1.run.v1\0"
SEMANTIC_DOMAIN = "vibeos.c88.f5.float-target.semantic.v1\0"
SEMANTIC_SHA256 = "51896391bb2a3493f1252e2633f54678bb1e69aa46a7e740dc4bc110381504f1"
CANDIDATE_SHA256 = "5fdb9dc9a48a9c54e899a5dc724445083c055dbf0d664927ba55d9780cc9996a"
SENTINEL_SOURCE_COMMIT = "d1" * 20
SENTINEL_SOURCE_TREE = "d2" * 20
SENTINEL_CHALLENGE = "d3" * 32
SENTINEL_BINDING_MODE = "reserved-non-evidence-sentinel"
ELF_ARM_MARKER = "vibeos.c88.f5.duo.compile-readiness.arm=0"
EXPECTED_SENTINEL: dict[str, Any] = {
    "kind": SENTINEL_BINDING_MODE,
    "source_commit": SENTINEL_SOURCE_COMMIT,
    "source_tree": SENTINEL_SOURCE_TREE,
    "challenge": SENTINEL_CHALLENGE,
    "candidate_sha256": CANDIDATE_SHA256,
    "manifest_sha256_source": "sha256-of-this-checked-in-manifest-bytes",
    "transcript_schema_sha256_source": ("sha256-of-checked-in-transcript-schema-bytes"),
    "run_id_source": "sha256-per-run-id-contract-with-these-sentinels",
    "arm_marker": ELF_ARM_MARKER,
    "arm_byte": 0,
}
RECORD_COUNTS = {
    "core": 146,
    "f3": 13,
    "f4": 12,
    "fuel": 1_000,
    "lifecycle": 5,
    "total": 1_176,
}
EXPECTED_FUTURE_GATE: dict[str, Any] = {
    "each_boot_operator_confirmed_power_cycle_required": True,
    "each_boot_operator_confirmed_cold_boot_required": True,
    "operator_confirmed_power_cycles_required": 3,
    "operator_confirmed_power_cycles_present": 0,
    "operator_confirmed_cold_boots_required": 3,
    "operator_confirmed_cold_boots_present": 0,
    "independent_cold_boots_required": True,
    "same_challenge_required": True,
    "same_run_id_required": True,
    "unique_capture_boot_id_required": True,
    "required_boot_ordinals": [0, 1, 2],
    "same_identity_fields_required": [
        "source_commit",
        "source_tree",
        "challenge",
        "run_id",
        "manifest_sha256",
        "transcript_schema_sha256",
        "candidate_sha256",
        "kernel_elf_sha256",
    ],
    "per_boot_transcript_order": [
        "metadata",
        "data-records:1176",
        "end",
        "pass",
    ],
    "complete_transcripts_present": 0,
    "no_fail_record_required": True,
    "terminal_quiescence_after_pass_required": True,
    "terminal_quiescences_present": 0,
    "unexpected_uart_after_pass_forbidden": True,
    "operator_power_off_after_pass_required": True,
    "operator_power_off_confirmations_present": 0,
    "same_semantic_sha256_required": True,
    "required_semantic_sha256": SEMANTIC_SHA256,
    "gate_satisfied": False,
}

MAX_CONTRACT_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MIN_DUO_ELF_BYTES = 16 * 1024 * 1024
MAX_ELF_BYTES = 256 * 1024 * 1024
MAX_AUDITOR_OUTPUT = 8 * 1024 * 1024
AUDITOR_TIMEOUT_SECONDS = 300.0
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_ELF_AUDITOR_BYTES = 92_051
EXPECTED_ELF_AUDITOR_SHA256 = (
    "3e7d9670c020de2e7ab274eb74b46d13153a0ca553f04d92134bde191e289f1b"
)
EXPECTED_MANIFEST_BYTES = 4_159
EXPECTED_MANIFEST_SHA256 = (
    "1c85f22cacee7c8eb7693578052fe0452169eace99f1dab06e08aa0e42771b11"
)
EXPECTED_TRANSCRIPT_SCHEMA_BYTES = 4_692
EXPECTED_TRANSCRIPT_SCHEMA_SHA256 = (
    "e25d9a38d194993906b7fe5ec9708654ea31e2386ac61f0fa360ed8ad1eb7439"
)
EXPECTED_SENTINEL_RUN_ID = (
    "c5c8ec42e56fbeaf38106965e5ec6735cb86a93af530cd37f5002dba1971b4ac"
)
EXPECTED_DUO_RUSTFLAGS = (
    "-C linker=ld.lld -C linker-flavor=ld -C target-feature=+zicsr,+zifencei "
    "-C link-arg=--gc-sections -C force-frame-pointers=yes -Z fmt-debug=none"
)
EXPECTED_BUILD_SCRIPT_BYTES = 4_405
EXPECTED_BUILD_SCRIPT_SHA256 = (
    "3d817b7b32a997ec3a7c1678d4ed63146eeaed5134b11c99290dc8d8ea714818"
)
MIN_DUO_ELF_INSTRUCTIONS = 380_000
MIN_DUO_ELF_CODE_SYMBOLS = 128_000
EXPECTED_ELF_EXECUTION_SCOPE = (
    "trusted-native-control-flow",
    "canonical-decoder-boundaries",
    "arbitrary-PC-redirection-not-claimed",
    "hardware-NX-not-claimed",
)
EXPECTED_ELF_AUDIT_CHECKS = (
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
)

EXPECTED_MANIFEST: dict[str, Any] = {
    "schema": SCHEMA,
    "version": SCHEMA_VERSION,
    "suite_id": SUITE_ID,
    "scope": "milkv-duo-compile-readiness",
    "run_id": {
        "sha256_domain_ascii": "vibeos.c88.f5.float-target.duo-v1.run.v1",
        "domain_nul_terminated": True,
        "nul_separated_fields": [
            "source_commit",
            "source_tree",
            "challenge",
            "manifest_sha256",
            "transcript_schema_sha256",
            "candidate_sha256",
        ],
    },
    "platform": {
        "id": PLATFORM,
        "class": PLATFORM_CLASS,
        "target": TARGET,
        "physical_provenance": PHYSICAL_PROVENANCE,
    },
    "readiness": {
        "stage": READINESS_STAGE,
        "physical_status": PHYSICAL_STATUS,
        "binding_mode": SENTINEL_BINDING_MODE,
        "runtime_bindings_required": True,
        "sentinel_bindings_present": True,
        "formal_physical_bindings_present": False,
        "execution_armed": False,
        "capture_present": False,
        "physical_evidence_present": False,
    },
    "compile_readiness_sentinel": EXPECTED_SENTINEL,
    "shared_qualification": {
        "routine": "vibeos_wasm_float_target::qualify",
        "semantic_sha256_domain_ascii": "vibeos.c88.f5.float-target.semantic.v1",
        "semantic_domain_nul_terminated": True,
        "semantic_sha256": SEMANTIC_SHA256,
        "artifact_profile_code": 5,
        "artifact_stage": "validation-only",
        "execution_enabled": False,
        "current_validation_engine": False,
        "current_component_engine": False,
        "records": {
            "core": RECORD_COUNTS["core"],
            "canonical_abi": RECORD_COUNTS["f3"],
            "component_vectors": RECORD_COUNTS["f4"],
            "fuel": RECORD_COUNTS["fuel"],
            "lifecycle": RECORD_COUNTS["lifecycle"],
            "total": RECORD_COUNTS["total"],
        },
    },
    "isolation": {
        "production_world_initialized": False,
        "usb_initialized": False,
        "network_initialized": False,
        "ssh_initialized": False,
        "command_published": False,
        "durable_object_created": False,
    },
    "completion": {
        "f5_complete": False,
        "float_complete": False,
        "c88_complete": False,
        "executable_successor_authorized": False,
    },
    "future_physical_gate": EXPECTED_FUTURE_GATE,
}


class VerificationError(RuntimeError):
    """A deterministic fail-closed contract or wiring failure."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sentinel_run_id(manifest_sha256: str, transcript_schema_sha256: str) -> str:
    fields = (
        SENTINEL_SOURCE_COMMIT,
        SENTINEL_SOURCE_TREE,
        SENTINEL_CHALLENGE,
        manifest_sha256,
        transcript_schema_sha256,
        CANDIDATE_SHA256,
    )
    digest = hashlib.sha256()
    digest.update(RUN_ID_DOMAIN.encode("ascii"))
    digest.update("\0".join(fields).encode("ascii"))
    return digest.hexdigest()


def exact_value(observed: Any, expected: Any, label: str) -> None:
    """Compare recursively without Python's bool-equals-int coercion."""

    require(
        type(observed) is type(expected),
        f"{label} type differs: expected {type(expected).__name__}",
    )
    if isinstance(expected, dict):
        observed_order = list(observed)
        expected_order = list(expected)
        observed_keys = set(observed_order)
        expected_keys = set(expected_order)
        require(
            observed_keys == expected_keys,
            f"{label} keys differ: {sorted(observed_keys ^ expected_keys)}",
        )
        require(
            observed_order == expected_order,
            f"{label} key order differs",
        )
        for key in expected:
            exact_value(observed[key], expected[key], f"{label}.{key}")
        return
    if isinstance(expected, list):
        require(len(observed) == len(expected), f"{label} length differs")
        for index, expected_item in enumerate(expected):
            exact_value(observed[index], expected_item, f"{label}[{index}]")
        return
    require(observed == expected, f"{label} differs")


def reject_json_constant(token: str) -> NoReturn:
    fail(f"non-finite JSON number is forbidden: {token}")


def reject_json_float(token: str) -> NoReturn:
    fail(f"floating-point JSON number is forbidden: {token}")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            fail(f"duplicate JSON member: {key}")
        output[key] = value
    return output


def parse_json_contract(raw: bytes, label: str) -> dict[str, Any]:
    require(raw, f"{label} is empty")
    require(len(raw) <= MAX_CONTRACT_BYTES, f"{label} exceeds the size limit")
    require(not raw.startswith(b"\xef\xbb\xbf"), f"{label} has a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
            parse_float=reject_json_float,
        )
    except VerificationError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        fail(f"{label} is not strict JSON: {error}")
    require(type(value) is dict, f"{label} root is not an object")
    return value


def read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    """Read one stable regular file without following its final symlink."""

    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot stat {label}: {error}")
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(before.st_nlink == 1, f"{label} does not have exactly one hard link")
    require(0 < before.st_size <= maximum, f"{label} size is outside the limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            f"{label} identity changed while opening",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, f"{label} grew beyond the size limit")
        after = os.fstat(descriptor)
        require(
            (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            == (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ),
            f"{label} changed while reading",
        )
    except VerificationError:
        raise
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raw = b"".join(chunks)
    require(len(raw) == before.st_size, f"{label} read length differs from stat")
    return raw


@dataclass(frozen=True)
class SourceSnapshot:
    files: dict[str, bytes]

    @classmethod
    def capture(cls, root: Path) -> "SourceSnapshot":
        files: dict[str, bytes] = {}
        for relative in SOURCE_RELS:
            maximum = (
                MAX_CONTRACT_BYTES
                if relative in (MANIFEST_REL, TRANSCRIPT_SCHEMA_REL)
                else MAX_SOURCE_BYTES
            )
            files[relative] = read_regular_file(
                root / relative, maximum, f"source {relative}"
            )
        return cls(files)

    def raw(self, relative: str) -> bytes:
        value = self.files.get(relative)
        require(value is not None, f"source snapshot is missing {relative}")
        return value

    def text(self, relative: str) -> str:
        try:
            return self.raw(relative).decode("utf-8", errors="strict")
        except UnicodeError as error:
            fail(f"source {relative} is not UTF-8: {error}")

    def toml(self, relative: str) -> dict[str, Any]:
        try:
            value = tomllib.loads(self.text(relative))
        except (tomllib.TOMLDecodeError, ValueError) as error:
            fail(f"source {relative} is not TOML: {error}")
        require(type(value) is dict, f"source {relative} TOML root is not a table")
        return value

    def replace(self, relative: str, old: bytes, new: bytes) -> "SourceSnapshot":
        original = self.raw(relative)
        require(old in original, f"selftest mutation anchor absent in {relative}")
        require(
            original.count(old) == 1,
            f"selftest mutation anchor is ambiguous in {relative}",
        )
        files = dict(self.files)
        files[relative] = original.replace(old, new, 1)
        return SourceSnapshot(files)


def feature_list(document: dict[str, Any], name: str, label: str) -> list[str]:
    features = document.get("features")
    require(type(features) is dict, f"{label} has no [features] table")
    value = features.get(name)
    require(type(value) is list, f"{label} feature {name!r} is absent or not a list")
    require(
        all(type(item) is str and item for item in value),
        f"{label} feature {name!r} has a non-string member",
    )
    require(
        len(value) == len(set(value)),
        f"{label} feature {name!r} has duplicate members",
    )
    return value


def exact_feature(
    document: dict[str, Any], name: str, expected: set[str], label: str
) -> None:
    observed = feature_list(document, name, label)
    require(
        set(observed) == expected,
        f"{label} feature {name!r} differs: {sorted(set(observed) ^ expected)}",
    )


def require_once(text: str, needle: str, label: str) -> None:
    count = text.count(needle)
    require(count == 1, f"{label} must contain exactly one {needle!r}; found {count}")


def require_absent(text: str, needle: str, label: str) -> None:
    require(needle not in text, f"{label} unexpectedly contains {needle!r}")


DUO_EXCLUDED_GUARD = f"""#[cfg(not(any(
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "{IMAGE_FEATURE}"
    )))]"""

MILKV_DUO_EXCLUDED_GUARD = f"""#[cfg(all(
        feature = "milkv-duo",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "{IMAGE_FEATURE}"
        ))
    ))]"""

QEMU_DUO_EXCLUDED_GUARD = f"""#[cfg(all(
        feature = "qemu-virt",
        not(any(
            feature = "wasm-c83-runtime-costs",
            feature = "wasm-c88-f5-float-qemu-acceptance",
            feature = "{IMAGE_FEATURE}"
        ))
    ))]"""

VSH_DUO_EXCLUDED_GUARD = f"""#[cfg(not(any(
        feature = "legacy-shell",
        feature = "wasm-c67-information-flow-acceptance",
        feature = "wasm-c74-crash-safe-publication-acceptance",
        feature = "wasm-c75-boot-revalidation-acceptance",
        feature = "wasm-c76-graph-version-replacement-acceptance",
        feature = "wasm-c83-runtime-costs",
        feature = "wasm-c88-f5-float-qemu-acceptance",
        feature = "{IMAGE_FEATURE}",
        feature = "wasm-c84-ssh-managed-child-single-boot-collector"
    )))]"""

DUO_ISOLATION_FORBIDDEN_FEATURES = [
    "legacy-shell",
    "storage-bench",
    "file-tree",
    "tcp-echo",
    "net-shell",
    "iperf3-server",
    "milkv-iperf3-server",
    "ssh-security-test",
    "ssh-test",
    "milkv-ssh-acceptance",
    "milkv-ssh",
    "milkv-jitterentropy-probe",
    "milkv-jitterentropy-ssh-probe",
    "component-graph-principals",
    "component-durable-publication",
    "ssh-component-command",
    "wasm-c48-qemu-acceptance",
    "wasm-c53-native-async-qemu-acceptance",
    "wasm-c63-graph-principal-acceptance",
    "wasm-c64-resource-route-acceptance",
    "wasm-c65-async-chain-acceptance",
    "wasm-c66-node-replacement-acceptance",
    "wasm-c67-information-flow-acceptance",
    "wasm-c73-authenticated-admission-acceptance",
    "wasm-c74-crash-safe-publication-acceptance",
    "wasm-c75-boot-revalidation-acceptance",
    "wasm-c76-graph-version-replacement-acceptance",
    "wasm-c77-ephemeral-runtime-acceptance",
    "wasm-c83-runtime-costs",
    "wasm-c84-profile-slot",
    "ssh-native-async-command",
    "ssh-native-async-qemu-acceptance",
    "ssh-native-async-revoke-qemu-acceptance",
]

RUNTIME_SHUTDOWN_SOURCE = """pub fn shutdown(failure: bool) -> ! {
    request_system_reset(
        SBI_SRST_RESET_TYPE_SHUTDOWN,
        if failure {
            SBI_SRST_RESET_REASON_SYSTEM_FAILURE
        } else {
            SBI_SRST_RESET_REASON_NONE
        },
    );
    loop {
        wait_for_interrupt();
    }
}"""


def require_guarded_site(text: str, guard: str, statement: str, label: str) -> None:
    require_once(text, f"{guard}\n    {statement}", label)


def verify_duo_isolation_sites(kernel: str) -> None:
    isolation_end_marker = (
        f'    "feature `{IMAGE_FEATURE}` is an isolated, non-production readiness image"\n'
        ");"
    )
    isolation_end = kernel.find(isolation_end_marker)
    require(isolation_end >= 0, "Duo compile-time isolation gate is incomplete")
    isolation_start = kernel.rfind("#[cfg(all(", 0, isolation_end)
    require(isolation_start >= 0, "Duo compile-time isolation gate is absent")
    isolation_block = kernel[
        isolation_start : isolation_end + len(isolation_end_marker)
    ]
    observed_features = re.findall(r'feature = "([^"]+)"', isolation_block)
    exact_value(
        observed_features,
        [IMAGE_FEATURE, *DUO_ISOLATION_FORBIDDEN_FEATURES],
        "Duo compile-time isolation feature order",
    )

    for statement in (
        "match dwc2_host::init() {",
        "if let Some(usb) = dwc2_host::telemetry() {",
        "if dwc2_host::connected() {",
        "if dwc2_host::info().is_some() {",
    ):
        require_guarded_site(
            kernel, MILKV_DUO_EXCLUDED_GUARD, statement, KERNEL_LIB_REL
        )
    for statement in (
        "world::build();",
        "let world = world::world();",
        "world::start_block_supervisor();",
        "world::start_net_supervisor();",
    ):
        require_guarded_site(kernel, DUO_EXCLUDED_GUARD, statement, KERNEL_LIB_REL)
    require_guarded_site(
        kernel,
        MILKV_DUO_EXCLUDED_GUARD,
        "world::start_usb_net_supervisor();",
        KERNEL_LIB_REL,
    )
    for statement in (
        "world::start_rng_supervisor();",
        "if xhci::info().is_some() {",
    ):
        require_guarded_site(kernel, QEMU_DUO_EXCLUDED_GUARD, statement, KERNEL_LIB_REL)

    require_once(
        kernel,
        '#[cfg(feature = "ssh-component-command")]\n    component_instances::init();',
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        """#[cfg(any(
        feature = "tcp-echo",
        feature = "net-shell",
        feature = "ssh-test",
        feature = "milkv-ssh-acceptance",
        feature = "milkv-ssh",
        feature = "iperf3-server",
        feature = "milkv-iperf3-server"
    ))]
    world::start_ipv4_stack_supervisor();""",
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        '#[cfg(any(feature = "ssh-test", feature = "milkv-ssh-acceptance"))]\n'
        "    world::start_ssh_test_supervisor();",
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        f"""{VSH_DUO_EXCLUDED_GUARD}
    {{
        let space = world.spaces["vsh"].clone();
        let mut session = vsh::Session::with_cspace(space.0.clone());
        vsh_platform::install_standard_commands(&mut session);""",
        KERNEL_LIB_REL,
    )


def verify_riscv_quiescence_wiring(snapshot: SourceSnapshot) -> None:
    kernel = snapshot.text(KERNEL_LIB_REL)
    runtime = snapshot.text(RUNTIME_BARE_REL)
    require_once(
        kernel,
        '#[cfg(all(target_arch = "riscv64", target_os = "none"))]\n'
        "pub use vibeos_runtime_riscv as sbi;",
        KERNEL_LIB_REL,
    )
    require_once(runtime, RUNTIME_SHUTDOWN_SOURCE, RUNTIME_BARE_REL)
    require_once(
        runtime,
        "the CV1800B's OpenSBI registers a T-Head reset device whose",
        RUNTIME_BARE_REL,
    )


def verify_manifest(raw: bytes) -> dict[str, Any]:
    manifest = parse_json_contract(raw, "Duo readiness manifest")
    exact_value(manifest, EXPECTED_MANIFEST, "Duo readiness manifest")
    counts = RECORD_COUNTS
    require(
        counts["core"]
        + counts["f3"]
        + counts["f4"]
        + counts["fuel"]
        + counts["lifecycle"]
        == counts["total"],
        "internal record-count contract is inconsistent",
    )
    return manifest


EXPECTED_TRANSCRIPT_SCHEMA: dict[str, Any] = {
    "schema": "vibeos.c88.f5.float-target.duo-v1.transcript-schema",
    "version": 1,
    "suite_id": SUITE_ID,
    "run_id": {
        "algorithm": "sha256",
        "domain_ascii": "vibeos.c88.f5.float-target.duo-v1.run.v1",
        "domain_nul_terminated": True,
        "nul_separated_fields": [
            "source_commit",
            "source_tree",
            "challenge",
            "manifest_sha256",
            "transcript_schema_sha256",
            "candidate_sha256",
        ],
    },
    "semantic_digest": {
        "algorithm": "sha256",
        "domain_ascii": "vibeos.c88.f5.float-target.semantic.v1",
        "domain_nul_terminated": True,
        "expected_sha256": SEMANTIC_SHA256,
        "family_order": [
            "CORE_CASE",
            "F3_CASE",
            "F4_VECTOR",
            "FUEL",
            "LIFECYCLE",
        ],
        "record_encoding": "family-nul-canonical-semantic-json-newline",
    },
    "uart": {
        "prefixes": {
            "metadata": "VIBE_C88_F5_DUO_META ",
            "core": "VIBE_C88_F5_DUO_CORE_CASE ",
            "canonical_abi": "VIBE_C88_F5_DUO_F3_CASE ",
            "component_vector": "VIBE_C88_F5_DUO_F4_VECTOR ",
            "fuel": "VIBE_C88_F5_DUO_FUEL ",
            "lifecycle": "VIBE_C88_F5_DUO_LIFECYCLE ",
            "end": "VIBE_C88_F5_DUO_END ",
            "pass": "VIBE_C88_F5_DUO_PASS ",
            "fail": "VIBE_C88_F5_DUO_FAIL ",
        },
        "schema_ids": {
            "metadata": "vibeos.c88.f5.float-target.duo-v1.meta",
            "core": "vibeos.c88.f5.float-target.duo-v1.core-case",
            "canonical_abi": "vibeos.c88.f5.float-target.duo-v1.f3-case",
            "component_vector": "vibeos.c88.f5.float-target.duo-v1.f4-vector",
            "fuel": "vibeos.c88.f5.float-target.duo-v1.fuel",
            "lifecycle": "vibeos.c88.f5.float-target.duo-v1.lifecycle",
            "end": "vibeos.c88.f5.float-target.duo-v1.end",
            "pass": "vibeos.c88.f5.float-target.duo-v1.pass",
            "fail": "vibeos.c88.f5.float-target.duo-v1.fail",
        },
    },
    "records": {
        "core": RECORD_COUNTS["core"],
        "canonical_abi": RECORD_COUNTS["f3"],
        "component_vectors": RECORD_COUNTS["f4"],
        "fuel": RECORD_COUNTS["fuel"],
        "lifecycle": RECORD_COUNTS["lifecycle"],
        "total": RECORD_COUNTS["total"],
    },
    "evidence_contract": {
        "readiness_stage": READINESS_STAGE,
        "physical_status": PHYSICAL_STATUS,
        "physical_provenance": PHYSICAL_PROVENANCE,
        "binding_mode": SENTINEL_BINDING_MODE,
        "runtime_bindings_required": True,
        "sentinel_bindings_present": True,
        "formal_physical_bindings_present": False,
        "execution_armed": False,
        "capture_present": False,
        "physical_evidence_present": False,
        "future_operator_confirmed_cold_boots_required": 3,
        "same_semantic_sha256_required": True,
    },
    "compile_readiness_sentinel": EXPECTED_SENTINEL,
    "future_physical_gate": EXPECTED_FUTURE_GATE,
}


def verify_transcript_schema(raw: bytes) -> dict[str, Any]:
    value = parse_json_contract(raw, "Duo transcript schema")
    exact_value(value, EXPECTED_TRANSCRIPT_SCHEMA, "Duo transcript schema")
    return value


def verify_acceptance_wiring(snapshot: SourceSnapshot) -> None:
    cargo = snapshot.toml(ACCEPTANCE_CARGO_REL)
    exact_feature(
        cargo,
        ACCEPTANCE_FEATURE,
        {
            "dep:sha2",
            "dep:vibeos-component-format",
            "dep:vibeos-component-image-adapter",
            "dep:vibeos-component-runtime",
            "dep:vibeos-image-policy",
            "dep:vibeos-wasm-float-candidate",
            "dep:vibeos-wasm-runtime",
            "dep:wat",
            "vibeos-component-image-adapter/c88-f4-float-candidate-duo",
            "vibeos-component-runtime/c88-f4-acceptance",
            "vibeos-image-policy/c88-f4-float-candidate",
            "vibeos-image-policy/milkv-duo-sd",
            "vibeos-wasm-float-candidate/c88-f2-acceptance",
        },
        ACCEPTANCE_CARGO_REL,
    )
    duo_members = feature_list(cargo, ACCEPTANCE_FEATURE, ACCEPTANCE_CARGO_REL)
    require(
        not any("qemu" in member.lower() for member in duo_members),
        "Duo acceptance feature crosses the QEMU policy boundary",
    )

    build = snapshot.text(ACCEPTANCE_BUILD_REL)
    require_once(
        build,
        'const DUO_MANIFEST: &str = "artifacts/qualification-duo-v1-manifest.json";',
        ACCEPTANCE_BUILD_REL,
    )
    require_once(
        build,
        "const DUO_TRANSCRIPT_SCHEMA: &str = "
        '"artifacts/qualification-duo-v1-transcript-schema.json";',
        ACCEPTANCE_BUILD_REL,
    )
    require_once(
        build,
        'out.join("qualification_duo_v1_manifest_identity.rs")',
        ACCEPTANCE_BUILD_REL,
    )
    for constant in (
        "DUO_QUALIFICATION_MANIFEST_SHA256",
        "DUO_QUALIFICATION_MANIFEST_BYTES",
        "DUO_TRANSCRIPT_SCHEMA_SHA256",
        "DUO_TRANSCRIPT_SCHEMA_BYTES",
    ):
        require_once(build, constant, ACCEPTANCE_BUILD_REL)

    library = snapshot.text(ACCEPTANCE_LIB_REL)
    require_once(
        library,
        "features `c88-f5-acceptance` and `c88-f5-duo-compile-readiness` "
        "are mutually exclusive platform selections",
        f"{ACCEPTANCE_LIB_REL} mutual-exclusion gate",
    )
    require_once(
        library,
        '"/qualification_duo_v1_manifest_identity.rs"',
        ACCEPTANCE_LIB_REL,
    )


def verify_adapter_policy_wiring(snapshot: SourceSnapshot) -> None:
    cargo = snapshot.toml(ADAPTER_CARGO_REL)
    exact_feature(
        cargo,
        "c88-f4-float-candidate-core",
        {
            "dep:vibeos-component-admission",
            "dep:vibeos-component-format",
            "dep:vibeos-component-runtime",
            "dep:vibeos-image-policy",
            "vibeos-component-admission/c88-f4-acceptance",
            "vibeos-component-runtime/c88-f4-acceptance",
            "vibeos-image-policy/c88-f4-float-candidate",
        },
        ADAPTER_CARGO_REL,
    )
    exact_feature(
        cargo,
        "c88-f4-float-candidate",
        {
            "c88-f4-float-candidate-core",
            "vibeos-image-policy/qemu-default",
        },
        ADAPTER_CARGO_REL,
    )
    exact_feature(
        cargo,
        "c88-f4-float-candidate-duo",
        {
            "c88-f4-float-candidate-core",
            "vibeos-image-policy/milkv-duo-sd",
        },
        ADAPTER_CARGO_REL,
    )
    duo = feature_list(cargo, "c88-f4-float-candidate-duo", ADAPTER_CARGO_REL)
    require(
        not any("qemu" in member.lower() for member in duo),
        "Duo adapter feature selects a QEMU policy",
    )
    source = snapshot.text(ADAPTER_LIB_REL)
    require(
        source.count('feature = "c88-f4-float-candidate-core"') == 12,
        "adapter shared-core cfg surface differs",
    )
    for guarded_declaration in (
        '#[cfg(feature = "c88-f4-float-candidate-core")]\n'
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n"
        "pub enum FloatCandidateProjectionError {",
        '#[cfg(feature = "c88-f4-float-candidate-core")]\n'
        "pub struct FloatCandidateProjection {",
        '#[cfg(feature = "c88-f4-float-candidate-core")]\n'
        "impl FloatCandidateProjection {",
        '#[cfg(feature = "c88-f4-float-candidate-core")]\n'
        "pub fn project_float_candidate(",
        '#[cfg(feature = "c88-f4-float-candidate-core")]\n'
        "const fn float_admission_limits(",
    ):
        require_once(source, guarded_declaration, ADAPTER_LIB_REL)
    require_once(
        source,
        "features `c88-f4-float-candidate` and `c88-f4-float-candidate-duo` "
        "are mutually exclusive image-policy selections",
        ADAPTER_LIB_REL,
    )

    policy_cargo = snapshot.toml(POLICY_CARGO_REL)
    exact_feature(
        policy_cargo,
        "c88-f4-float-candidate",
        set(),
        POLICY_CARGO_REL,
    )
    policy = snapshot.text(POLICY_LIB_REL)
    require_once(
        policy,
        'feature = "c88-f4-float-candidate",\n'
        '    not(any(feature = "qemu-default", feature = "milkv-duo-sd"))',
        POLICY_LIB_REL,
    )
    require_once(
        policy,
        "feature `c88-f4-float-candidate` requires an explicit QEMU or Milk-V Duo "
        "image policy",
        POLICY_LIB_REL,
    )
    require_once(
        policy,
        "exactly one image policy must be selected",
        POLICY_LIB_REL,
    )


def verify_kernel_and_firmware_wiring(snapshot: SourceSnapshot) -> None:
    kernel_cargo = snapshot.toml(KERNEL_CARGO_REL)
    exact_feature(
        kernel_cargo,
        IMAGE_FEATURE,
        {
            "dep:sha2",
            "dep:vibeos-component-format",
            "dep:vibeos-component-runtime",
            "dep:vibeos-wasm-float-target",
            f"vibeos-wasm-float-target/{ACCEPTANCE_FEATURE}",
        },
        KERNEL_CARGO_REL,
    )
    image_members = feature_list(kernel_cargo, IMAGE_FEATURE, KERNEL_CARGO_REL)
    require(
        not any("qemu" in member.lower() for member in image_members),
        "Duo kernel feature selects a QEMU feature",
    )

    milkv = snapshot.toml(MILKV_FIRMWARE_REL)
    exact_feature(
        milkv,
        IMAGE_FEATURE,
        {f"vibeos-kernel/{IMAGE_FEATURE}"},
        MILKV_FIRMWARE_REL,
    )
    default = feature_list(milkv, "default", MILKV_FIRMWARE_REL)
    require(IMAGE_FEATURE not in default, "Duo readiness image is enabled by default")

    qemu = snapshot.toml(QEMU_FIRMWARE_REL)
    qemu_features = qemu.get("features")
    require(type(qemu_features) is dict, "QEMU firmware has no [features] table")
    require(
        IMAGE_FEATURE not in qemu_features,
        "QEMU firmware forwards the physical-target readiness feature",
    )

    kernel = snapshot.text(KERNEL_LIB_REL)
    adapter = snapshot.text(KERNEL_ADAPTER_REL)
    require_once(
        kernel,
        f'"feature `{IMAGE_FEATURE}` requires the Milk-V Duo board"',
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        f'"feature `{IMAGE_FEATURE}` requires the Milk-V Duo image policy"',
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        f'"feature `{IMAGE_FEATURE}` is an isolated, non-production readiness image"',
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        "the QEMU and Milk-V Duo C8.8-F5 image contracts are mutually exclusive",
        KERNEL_LIB_REL,
    )
    require_once(
        kernel,
        f'feature = "{IMAGE_FEATURE}",\n    any(feature = "qemu-virt", '
        'feature = "qemu-default-image")',
        KERNEL_LIB_REL,
    )
    verify_duo_isolation_sites(kernel)
    require_once(
        kernel,
        f'#[cfg(feature = "{IMAGE_FEATURE}")]\n'
        '    println!("  image     isolated C8.8-F5 Milk-V Duo compile-only readiness");',
        KERNEL_LIB_REL,
    )

    duo_cfg = f'#[cfg(feature = "{IMAGE_FEATURE}")]\n'
    require_once(
        adapter,
        duo_cfg + f'const SUITE_ID: &str = "{SUITE_ID}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + f'const PLATFORM: &str = "{PLATFORM}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + f'const PLATFORM_CLASS: &str = "{PLATFORM_CLASS}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + f'const PHYSICAL_PROVENANCE: &str = "{PHYSICAL_PROVENANCE}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + 'const QUALIFICATION_MODE: &str = "physical-candidate";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + f'const READINESS_STAGE: &str = "{READINESS_STAGE}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + f'const BINDING_MODE: &str = "{SENTINEL_BINDING_MODE}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg
        + "static DUO_EXECUTION_ARM: u8 = 0;\n"
        + duo_cfg
        + f'static DUO_EXECUTION_ARM_MARKER: &[u8] = b"{ELF_ARM_MARKER}";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg
        + """#[inline(never)]
fn execution_armed() -> bool {
    // Both reads are deliberately volatile. The readiness image retains the
    // complete producer behind this runtime-opaque gate, while the immutable
    // arm byte keeps this feature inert. A future physical runner must use a
    // separate feature and arm contract; patching this image is not evidence.
    unsafe {
        let _ = core::ptr::read_volatile(DUO_EXECUTION_ARM_MARKER.as_ptr());
        core::ptr::read_volatile(core::ptr::addr_of!(DUO_EXECUTION_ARM)) == 1
    }
}""",
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        duo_cfg + f'const RUN_ID_DOMAIN: &[u8] = b"{RUN_ID_DOMAIN[:-1]}\\0";',
        KERNEL_ADAPTER_REL,
    )
    for environment_name in (
        "VIBEOS_C88_F5_DUO_SOURCE_COMMIT",
        "VIBEOS_C88_F5_DUO_SOURCE_TREE",
        "VIBEOS_C88_F5_DUO_CHALLENGE",
        "VIBEOS_C88_F5_DUO_RUN_ID",
        "VIBEOS_C88_F5_DUO_MANIFEST_SHA256",
        "VIBEOS_C88_F5_DUO_TRANSCRIPT_SCHEMA_SHA256",
    ):
        require_once(adapter, f'option_env!("{environment_name}")', KERNEL_ADAPTER_REL)
    require_once(
        adapter,
        "&& MANIFEST_SHA256 == DUO_QUALIFICATION_MANIFEST_SHA256",
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        "&& TRANSCRIPT_SCHEMA_SHA256 == DUO_TRANSCRIPT_SCHEMA_SHA256",
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        "SOURCE_COMMIT,\n        SOURCE_TREE,\n        CHALLENGE,\n        MANIFEST_SHA256,\n"
        "        TRANSCRIPT_SCHEMA_SHA256,\n        CANDIDATE_SHA256,",
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        "const SEMANTIC_DIGEST_DOMAIN: &[u8] = " f'b"{SEMANTIC_DOMAIN[:-1]}\\0";',
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        'const TARGET: &str = "riscv64imac-unknown-none-elf";',
        KERNEL_ADAPTER_REL,
    )
    require_once(adapter, f'"{SEMANTIC_SHA256}"', KERNEL_ADAPTER_REL)
    for declaration in (
        "const CORE_RECORDS: usize = CORE_CASES;",
        "const F3_RECORDS: usize = F3_VECTORS.len() + 1;",
        "const F4_RECORDS: usize = F4_VECTORS.len();",
        "const FUEL_RECORDS: usize = 1_000;",
        "const LIFECYCLE_RECORDS: usize = 5;",
        "CORE_RECORDS + F3_RECORDS + F4_RECORDS + FUEL_RECORDS + LIFECYCLE_RECORDS;",
    ):
        require_once(adapter, declaration, KERNEL_ADAPTER_REL)

    prefix_constants = {
        "META": ("VIBE_C88_F5_DUO_META ", "vibeos.c88.f5.float-target.duo-v1.meta"),
        "CORE": (
            "VIBE_C88_F5_DUO_CORE_CASE ",
            "vibeos.c88.f5.float-target.duo-v1.core-case",
        ),
        "F3": (
            "VIBE_C88_F5_DUO_F3_CASE ",
            "vibeos.c88.f5.float-target.duo-v1.f3-case",
        ),
        "F4": (
            "VIBE_C88_F5_DUO_F4_VECTOR ",
            "vibeos.c88.f5.float-target.duo-v1.f4-vector",
        ),
        "FUEL": (
            "VIBE_C88_F5_DUO_FUEL ",
            "vibeos.c88.f5.float-target.duo-v1.fuel",
        ),
        "LIFECYCLE": (
            "VIBE_C88_F5_DUO_LIFECYCLE ",
            "vibeos.c88.f5.float-target.duo-v1.lifecycle",
        ),
        "END": ("VIBE_C88_F5_DUO_END ", "vibeos.c88.f5.float-target.duo-v1.end"),
        "PASS": (
            "VIBE_C88_F5_DUO_PASS ",
            "vibeos.c88.f5.float-target.duo-v1.pass",
        ),
        "FAIL": (
            "VIBE_C88_F5_DUO_FAIL ",
            "vibeos.c88.f5.float-target.duo-v1.fail",
        ),
    }
    for family, (prefix, schema_id) in prefix_constants.items():
        require_once(
            adapter,
            duo_cfg + f'const {family}_PREFIX: &str = "{prefix}";',
            KERNEL_ADAPTER_REL,
        )
        require_once(
            adapter,
            duo_cfg + f'const {family}_SCHEMA: &str = "{schema_id}";',
            KERNEL_ADAPTER_REL,
        )
        require(
            adapter.count(f"{family}_PREFIX") >= 2,
            f"Duo {family} prefix constant is not consumed",
        )
        require(
            adapter.count(f"{family}_SCHEMA") >= 2,
            f"Duo {family} schema constant is not consumed",
        )
    for identity in (
        "DUO_QUALIFICATION_MANIFEST_BYTES",
        "DUO_QUALIFICATION_MANIFEST_SHA256",
        "DUO_TRANSCRIPT_SCHEMA_BYTES",
        "DUO_TRANSCRIPT_SCHEMA_SHA256",
        "QUALIFICATION_MODE",
    ):
        require(
            adapter.count(identity) >= 2,
            f"kernel adapter does not consume {identity}",
        )
    for metadata_fragment in (
        '\\"readiness_stage\\":\\"{}\\",\\"binding_mode\\":\\"{}\\",',
        '\\"sentinel_bindings_present\\":true,',
        '\\"formal_physical_bindings_present\\":false,\\"execution_armed\\":false,',
        '\\"physical_evidence_present\\":false,',
        '\\"future_operator_confirmed_cold_boots_required\\":3,',
        '\\"f5_complete\\":false,\\"float_complete\\":false,\\"c88_complete\\":false,',
        '\\"executable_successor_authorized\\":false,',
    ):
        require_once(adapter, metadata_fragment, KERNEL_ADAPTER_REL)
    require_once(
        adapter,
        duo_cfg
        + """fn terminal_quiesce() -> ! {
    loop {
        crate::sbi::wait_for_interrupt();
    }
}""",
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        f"""pub async fn run() {{
    {duo_cfg.strip()}
    if !execution_armed() {{
        fail(0xff00);
    }}
    if crate::online_hart_count() != 1 || !bindings_are_valid() {{
        fail(0xff01);
    }}""",
        KERNEL_ADAPTER_REL,
    )
    require_once(
        adapter,
        '#[cfg(feature = "wasm-c88-f5-float-qemu-acceptance")]\n'
        "    crate::sbi::shutdown(false);\n"
        + "    "
        + duo_cfg
        + "    terminal_quiesce()",
        KERNEL_ADAPTER_REL,
    )


EVIDENCE_BINDINGS = (
    "VIBEOS_C88_F5_SOURCE_COMMIT",
    "VIBEOS_C88_F5_SOURCE_TREE",
    "VIBEOS_C88_F5_CHALLENGE",
    "VIBEOS_C88_F5_RUN_ID",
    "VIBEOS_C88_F5_MANIFEST_SHA256",
    "VIBEOS_C88_F5_TRANSCRIPT_SCHEMA_SHA256",
    "VIBEOS_C88_F5_DUO_SOURCE_COMMIT",
    "VIBEOS_C88_F5_DUO_SOURCE_TREE",
    "VIBEOS_C88_F5_DUO_CHALLENGE",
    "VIBEOS_C88_F5_DUO_RUN_ID",
    "VIBEOS_C88_F5_DUO_MANIFEST_SHA256",
    "VIBEOS_C88_F5_DUO_TRANSCRIPT_SCHEMA_SHA256",
)

FORBIDDEN_BUILD_COMMANDS = (
    "qemu-system-riscv64",
    "qemu-system-riscv32",
    "picocom",
    "minicom",
    "screen",
    "socat",
    "openocd",
    "dfu-util",
    "flashrom",
    "rust-objcopy",
    "llvm-objcopy",
    "objcopy",
    "dd",
    "mkfs",
    "mount",
    "umount",
    "fdisk",
    "sgdisk",
    "genimage",
    "tar",
    "zip",
    "gzip",
    "docker",
    "podman",
    "curl",
    "wget",
    "ssh",
    "scp",
    "rsync",
    "reboot",
    "shutdown",
)


def uncommented_shell(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def verify_closed_shell_surface(text: str) -> None:
    """Admit only the small command grammar used by the readiness linker."""

    require("`" not in text, "build script contains backtick command substitution")
    require(
        "<(" not in text and ">(" not in text,
        "build script contains process substitution",
    )
    substitutions = (
        'script_dir=$(cd -- "$(dirname -- "$0")" && pwd)',
        'repo_root=$(cd -- "$script_dir/.." && pwd)',
        'toolchain=$(sed -n \'s/^channel = "\\([^"]*\\)"$/\\1/p\' \\',
        'pinned_cargo=$(rustup which --toolchain "$toolchain" cargo)',
        'pinned_rustc=$(rustup which --toolchain "$toolchain" rustc)',
        'pinned_rustdoc=$(rustup which --toolchain "$toolchain" rustdoc)',
    )
    for statement in substitutions:
        require_once(text, statement, BUILD_SCRIPT_REL)
    require(
        text.count("$(") == 7,
        "build script command-substitution surface is not closed",
    )

    assignment_names = {
        "script_dir",
        "repo_root",
        "toolchain",
        "pinned_cargo",
        "pinned_rustc",
        "pinned_rustdoc",
        "target_parent",
        "target_dir",
        "built_elf",
        "duo_source_commit",
        "duo_source_tree",
        "duo_challenge",
        "duo_run_id",
        "duo_manifest_sha256",
        "duo_transcript_schema_sha256",
        "duo_rustflags",
        "VIBEOS_C88_F5_DUO_SOURCE_COMMIT",
        "VIBEOS_C88_F5_DUO_SOURCE_TREE",
        "VIBEOS_C88_F5_DUO_CHALLENGE",
        "VIBEOS_C88_F5_DUO_RUN_ID",
        "VIBEOS_C88_F5_DUO_MANIFEST_SHA256",
        "VIBEOS_C88_F5_DUO_TRANSCRIPT_SCHEMA_SHA256",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "RUSTFLAGS",
        "RUSTC",
        "RUSTDOC",
    }
    command_heads = {"set", "echo", "exit", "mkdir", "unset", "readonly", "cd"}
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in {"(", ")", "fi"}:
            continue
        if line.startswith("if "):
            require(
                line.endswith("; then") or line.endswith("\\"),
                f"build script line {number} has an open conditional",
            )
            require(
                line.count(";") <= 1,
                f"build script line {number} chains an extra command",
            )
            continue
        if line.startswith("["):
            require(
                line.endswith("; then") or line.endswith("\\"),
                f"build script line {number} has an unexpected test continuation",
            )
            continue
        if line.startswith('"$repo_root/rust-toolchain.toml")'):
            require(
                line == '"$repo_root/rust-toolchain.toml")',
                f"build script line {number} extends the toolchain substitution",
            )
            continue
        if line.startswith('"$pinned_cargo" build'):
            require(
                line == '"$pinned_cargo" build \\',
                f"build script line {number} changes the Cargo command",
            )
            continue
        if line.startswith("--"):
            continue
        assignment = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=", line)
        if assignment is not None:
            require(
                assignment.group(1) in assignment_names,
                f"build script line {number} introduces an unexpected assignment",
            )
            continue
        head = line.split(None, 1)[0]
        require(
            head in command_heads,
            f"build script line {number} has unexpected command {head!r}",
        )


def verify_build_script(snapshot: SourceSnapshot) -> None:
    raw = snapshot.raw(BUILD_SCRIPT_REL)
    require(
        len(raw) == EXPECTED_BUILD_SCRIPT_BYTES,
        "readiness build script byte length differs",
    )
    require(
        sha256_hex(raw) == EXPECTED_BUILD_SCRIPT_SHA256,
        "readiness build script SHA-256 differs",
    )
    text = snapshot.text(BUILD_SCRIPT_REL)
    require(text.startswith("#!/bin/sh\n"), "readiness build script is not POSIX sh")
    require_once(text, "set -eu", BUILD_SCRIPT_REL)
    body = uncommented_shell(text)
    verify_closed_shell_surface(body)
    require_once(
        body,
        'target_dir="$target_parent/c88-f5-duo-readiness/build"',
        BUILD_SCRIPT_REL,
    )
    require_absent(body, "artifact_dir=", BUILD_SCRIPT_REL)
    require_absent(body, "output_elf=", BUILD_SCRIPT_REL)
    require_once(body, 'cd "$repo_root/firmware/milkv-duo"', BUILD_SCRIPT_REL)
    require_once(body, 'mkdir -p "$target_dir"', BUILD_SCRIPT_REL)
    build_block = (
        'VIBEOS_C88_F5_DUO_SOURCE_COMMIT="$duo_source_commit" \\\n'
        '    VIBEOS_C88_F5_DUO_SOURCE_TREE="$duo_source_tree" \\\n'
        '    VIBEOS_C88_F5_DUO_CHALLENGE="$duo_challenge" \\\n'
        '    VIBEOS_C88_F5_DUO_RUN_ID="$duo_run_id" \\\n'
        '    VIBEOS_C88_F5_DUO_MANIFEST_SHA256="$duo_manifest_sha256" \\\n'
        "    VIBEOS_C88_F5_DUO_TRANSCRIPT_SCHEMA_SHA256="
        '"$duo_transcript_schema_sha256" \\\n'
        "    CARGO_INCREMENTAL=0 \\\n"
        "    CARGO_NET_OFFLINE=true \\\n"
        '    CARGO_TARGET_DIR="$target_dir" \\\n'
        "    CARGO_TERM_COLOR=never \\\n"
        '    RUSTFLAGS="$duo_rustflags" \\\n'
        '    RUSTC="$pinned_rustc" \\\n'
        '    RUSTDOC="$pinned_rustdoc" \\\n'
        '    "$pinned_cargo" build \\'
    )
    require_once(body, build_block, BUILD_SCRIPT_REL)
    expected_flags = [
        "--release",
        "--locked",
        "--offline",
        "--no-default-features",
        f"--features {IMAGE_FEATURE}",
    ]
    for flag in expected_flags:
        require_once(body, flag, BUILD_SCRIPT_REL)
    observed_flags = [
        line.strip().removesuffix("\\").strip()
        for line in body.splitlines()
        if line.strip().startswith("--")
    ]
    require(
        observed_flags == expected_flags,
        "Cargo readiness flags are not the exact closed sequence",
    )
    require_once(
        body,
        'built_elf="$target_dir/riscv64imac-unknown-none-elf/release/'
        'vibeos-milkv-duo"',
        BUILD_SCRIPT_REL,
    )
    require_absent(body, "\ncp ", BUILD_SCRIPT_REL)
    require_once(
        body,
        'echo "Inert-sentinel compile-only ELF (not physical evidence): $built_elf"',
        BUILD_SCRIPT_REL,
    )
    require("cargo" in body and " build " in body, "build script omits Cargo build")
    require_once(body, '"$pinned_cargo" build \\', BUILD_SCRIPT_REL)
    require("cargo run" not in body, "build script executes the readiness image")
    require("--package" not in body, "build script contains a package selector token")

    cargo_position = body.find('"$pinned_cargo" build')
    require(cargo_position >= 0, "pinned Cargo build invocation is absent")
    sentinel_assignment_position = body.find(
        f"duo_source_commit={SENTINEL_SOURCE_COMMIT}"
    )
    require(sentinel_assignment_position >= 0, "sentinel assignment block is absent")
    for binding in EVIDENCE_BINDINGS:
        statement = f"unset {binding}"
        require_once(body, statement, BUILD_SCRIPT_REL)
        require(
            body.find(statement) < sentinel_assignment_position < cargo_position,
            f"{binding} is not cleared before Cargo",
        )
        if "_DUO_" not in binding:
            require(
                body[sentinel_assignment_position:].find(binding) < 0,
                f"generic QEMU binding {binding} is restored or passed to Cargo",
            )

    sentinel_assignments = {
        "duo_source_commit": SENTINEL_SOURCE_COMMIT,
        "duo_source_tree": SENTINEL_SOURCE_TREE,
        "duo_challenge": SENTINEL_CHALLENGE,
        "duo_run_id": EXPECTED_SENTINEL_RUN_ID,
        "duo_manifest_sha256": EXPECTED_MANIFEST_SHA256,
        "duo_transcript_schema_sha256": EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
        "duo_rustflags": f"'{EXPECTED_DUO_RUSTFLAGS}'",
    }
    for name, value in sentinel_assignments.items():
        require_once(body, f"{name}={value}", BUILD_SCRIPT_REL)
    require_once(
        body,
        "readonly duo_source_commit duo_source_tree duo_challenge duo_run_id",
        BUILD_SCRIPT_REL,
    )
    require_once(
        body,
        "readonly duo_manifest_sha256 duo_transcript_schema_sha256 duo_rustflags",
        BUILD_SCRIPT_REL,
    )
    for ambient in (
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_TARGET",
    ):
        require_once(body, f"unset {ambient}", BUILD_SCRIPT_REL)

    normalized = re.sub(r"\\\n\s*", " ", body)
    normalized = re.sub(r"[ \t]+", " ", normalized)
    conditions = (
        'if [ "$#" -ne 0 ]; then',
        'if [ -z "$toolchain" ] || ! command -v rustup >/dev/null 2>&1; then',
        'if [ ! -x "$pinned_cargo" ] || [ ! -x "$pinned_rustc" ] || '
        '[ ! -x "$pinned_rustdoc" ]; then',
        'if [ -L "$target_parent" ] || '
        '[ -L "$target_parent/c88-f5-duo-readiness" ] || '
        '[ -L "$target_dir" ]; then',
        'if [ ! -d "$target_dir" ] || [ -L "$target_dir" ]; then',
        'if [ -L "$built_elf" ] || [ ! -f "$built_elf" ] || '
        '[ ! -s "$built_elf" ]; then',
    )
    require(
        len(re.findall(r"(?m)^if ", normalized)) == len(conditions),
        "build script conditional surface is not closed",
    )
    for condition in conditions:
        require_once(normalized, condition, BUILD_SCRIPT_REL)

    for command in FORBIDDEN_BUILD_COMMANDS:
        pattern = re.compile(
            rf"(?m)(?:^|[;&|()])\s*(?:command\s+)?(?:/[^\s]+/)?{re.escape(command)}(?:\s|$)"
        )
        require(
            pattern.search(body) is None,
            f"build script contains forbidden command {command!r}",
        )
    require(
        re.search(r"/dev/(?:tty|cu\.)", body, flags=re.IGNORECASE) is None,
        "build script references a serial/device path",
    )
    require(
        re.search(r"\.(?:img|bin|sd|iso|tar|zip|gz)(?:[\"'\s]|$)", body) is None,
        "build script produces a non-ELF package/media artifact",
    )


def verify_source_wiring(
    snapshot: SourceSnapshot,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_raw = snapshot.raw(MANIFEST_REL)
    transcript_schema_raw = snapshot.raw(TRANSCRIPT_SCHEMA_REL)
    require(
        len(manifest_raw) == EXPECTED_MANIFEST_BYTES
        and sha256_hex(manifest_raw) == EXPECTED_MANIFEST_SHA256,
        "Duo readiness manifest byte identity differs",
    )
    require(
        len(transcript_schema_raw) == EXPECTED_TRANSCRIPT_SCHEMA_BYTES
        and sha256_hex(transcript_schema_raw) == EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
        "Duo transcript schema byte identity differs",
    )
    require(
        sentinel_run_id(EXPECTED_MANIFEST_SHA256, EXPECTED_TRANSCRIPT_SCHEMA_SHA256)
        == EXPECTED_SENTINEL_RUN_ID,
        "frozen inert-sentinel run ID derivation differs",
    )
    manifest = verify_manifest(manifest_raw)
    transcript_schema = verify_transcript_schema(transcript_schema_raw)
    verify_acceptance_wiring(snapshot)
    verify_adapter_policy_wiring(snapshot)
    verify_kernel_and_firmware_wiring(snapshot)
    verify_riscv_quiescence_wiring(snapshot)
    verify_build_script(snapshot)
    auditor = snapshot.raw(ELF_AUDITOR_REL)
    require(
        len(auditor) == EXPECTED_ELF_AUDITOR_BYTES,
        "independent ELF auditor byte length differs",
    )
    require(
        sha256_hex(auditor) == EXPECTED_ELF_AUDITOR_SHA256,
        "independent ELF auditor SHA-256 differs",
    )
    return manifest, transcript_schema


def kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        fail(f"cannot terminate ELF auditor process group: {error}")


def run_bounded(command: Sequence[str]) -> tuple[int, bytes, bytes]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONHASHSEED": "0",
    }
    for name in ("HOME", "RUSTUP_HOME", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    try:
        process = subprocess.Popen(
            list(command),
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        fail(f"cannot start ELF auditor: {error}")
    if process.stdout is None or process.stderr is None:
        kill_process_group(process)
        fail("ELF auditor pipes were not created")
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + AUDITOR_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                kill_process_group(process)
                process.wait()
                fail("ELF auditor timed out")
            events = selector.select(min(remaining, 0.25))
            for key, _mask in events:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                output = streams[stream]
                output.extend(chunk)
                if len(output) > MAX_AUDITOR_OUTPUT:
                    kill_process_group(process)
                    process.wait()
                    fail("ELF auditor output exceeds the size limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            kill_process_group(process)
            process.wait()
            fail("ELF auditor timed out after closing its output")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            kill_process_group(process)
            process.wait()
            fail("ELF auditor did not exit after closing its output")
    except BaseException:
        if process.poll() is None:
            kill_process_group(process)
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return return_code, bytes(streams[process.stdout]), bytes(streams[process.stderr])


def require_int(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"{label} is not a valid integer")
    return value


def require_string(value: Any, label: str) -> str:
    require(type(value) is str and value, f"{label} is not a non-empty string")
    return value


def require_duo_elf_size(value: Any, label: str) -> int:
    size = require_int(value, label, 1)
    require(
        MIN_DUO_ELF_BYTES <= size <= MAX_ELF_BYTES,
        f"{label} is outside the structural readiness range",
    )
    return size


def verify_elf_audit_report(report: dict[str, Any]) -> tuple[str, int]:
    exact_top = {
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
    require(set(report) == exact_top, "ELF audit top-level schema differs")
    require(
        report["schema"] == "vibeos.c88.f5.riscv-final-elf.audit",
        "ELF audit schema differs",
    )
    require(
        type(report["schema_version"]) is int and report["schema_version"] == 1,
        "ELF audit version differs",
    )
    require(report["status"] == "pass", "ELF audit did not pass")
    require(report["mode"] == "audit", "ELF audit mode differs")
    require(report["target"] == TARGET, "ELF audit target differs")
    exact_value(
        report["execution_scope"],
        list(EXPECTED_ELF_EXECUTION_SCOPE),
        "ELF audit execution_scope",
    )
    exact_value(
        report["checks"],
        list(EXPECTED_ELF_AUDIT_CHECKS),
        "ELF audit checks",
    )

    elf = report["elf"]
    require(type(elf) is dict, "ELF audit elf record is not an object")
    elf_keys = {
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
    require(set(elf) == elf_keys, "ELF audit elf schema differs")
    elf_bytes = require_duo_elf_size(elf["bytes"], "ELF audit byte count")
    elf_sha256 = require_string(elf["sha256"], "ELF audit SHA-256")
    require(HEX64.fullmatch(elf_sha256) is not None, "ELF audit SHA-256 is invalid")
    require(elf["e_flags"] == "0x00000001", "ELF audit is not soft-ABI RVC")
    require(
        elf["riscv_arch"] == "rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_"
        "zaamo1p0_zalrsc1p0_zca1p0",
        "ELF audit architecture is not exact RV64 IMAC",
    )
    exact_value(elf["forbidden_opcodes"], [], "ELF audit forbidden_opcodes")
    require_int(elf["program_headers"], "ELF audit program header count", 1)
    require_int(elf["sections"], "ELF audit section count", 1)
    require_string(elf["entry"], "ELF audit entry")

    symbols = elf["symbols"]
    require(type(symbols) is dict, "ELF audit symbols record is not an object")
    require(
        set(symbols)
        == {
            "code_symbols",
            "defined",
            "forbidden_helpers",
            "raw_symtab_entries",
            "undefined",
        },
        "ELF audit symbols schema differs",
    )
    exact_value(symbols["forbidden_helpers"], [], "ELF audit forbidden_helpers")
    require(
        type(symbols["undefined"]) is int and symbols["undefined"] == 0,
        "ELF audit has undefined symbols",
    )
    for key in ("code_symbols", "defined", "raw_symtab_entries"):
        require_int(symbols[key], f"ELF audit symbols.{key}", 1)
    require(
        symbols["code_symbols"] >= MIN_DUO_ELF_CODE_SYMBOLS,
        "Duo ELF code-symbol coverage is below the frozen producer threshold",
    )

    executable = elf["executable_sections"]
    require(
        type(executable) is list and executable, "ELF audit has no executable sections"
    )
    instruction_total = 0
    for index, section in enumerate(executable):
        require(
            type(section) is dict, f"ELF audit executable section {index} is invalid"
        )
        require(
            set(section)
            == {
                "address",
                "bytes",
                "four_byte_instructions",
                "instructions",
                "name",
                "sha256",
                "two_byte_instructions",
            },
            f"ELF audit executable section {index} schema differs",
        )
        instructions = require_int(
            section["instructions"],
            f"ELF audit executable section {index} instructions",
            1,
        )
        two_byte = require_int(
            section["two_byte_instructions"],
            f"ELF audit executable section {index} two-byte instructions",
        )
        four_byte = require_int(
            section["four_byte_instructions"],
            f"ELF audit executable section {index} four-byte instructions",
        )
        require(
            instructions == two_byte + four_byte,
            "ELF audit instruction partition differs",
        )
        require_int(section["bytes"], f"ELF audit executable section {index} bytes", 1)
        require_string(
            section["address"], f"ELF audit executable section {index} address"
        )
        require_string(section["name"], f"ELF audit executable section {index} name")
        section_sha = require_string(
            section["sha256"], f"ELF audit executable section {index} SHA-256"
        )
        require(
            HEX64.fullmatch(section_sha) is not None,
            "ELF audit section SHA-256 is invalid",
        )
        instruction_total += instructions
    require(
        instruction_total >= MIN_DUO_ELF_INSTRUCTIONS,
        "Duo ELF instruction coverage is below the frozen producer threshold",
    )

    control_flow = elf["control_flow"]
    require(type(control_flow) is dict, "ELF audit control_flow is not an object")
    require(
        set(control_flow) == {"canonical_boundaries", "direct_targets"},
        "ELF audit control_flow schema differs",
    )
    boundaries = require_int(
        control_flow["canonical_boundaries"], "ELF audit canonical boundaries", 1
    )
    require(
        boundaries == instruction_total + len(executable),
        "ELF audit canonical boundary count differs",
    )
    require_int(control_flow["direct_targets"], "ELF audit direct targets")
    require(type(report["toolchain"]) is dict, "ELF audit toolchain is not an object")
    return elf_sha256, elf_bytes


def duo_elf_payload_markers() -> tuple[bytes, ...]:
    uart = EXPECTED_TRANSCRIPT_SCHEMA["uart"]
    prefixes = uart["prefixes"]
    schema_ids = uart["schema_ids"]
    require(type(prefixes) is dict, "internal UART prefix contract is invalid")
    require(type(schema_ids) is dict, "internal UART schema contract is invalid")
    strings = [
        SUITE_ID,
        PLATFORM,
        PLATFORM_CLASS,
        TARGET,
        PHYSICAL_PROVENANCE,
        READINESS_STAGE,
        SENTINEL_BINDING_MODE,
        EXPECTED_MANIFEST_SHA256,
        EXPECTED_TRANSCRIPT_SCHEMA_SHA256,
        SENTINEL_SOURCE_COMMIT,
        SENTINEL_SOURCE_TREE,
        SENTINEL_CHALLENGE,
        EXPECTED_SENTINEL_RUN_ID,
        CANDIDATE_SHA256,
        SEMANTIC_SHA256,
        ELF_ARM_MARKER,
        *prefixes.values(),
        *schema_ids.values(),
        '"sentinel_bindings_present":true',
        '"formal_physical_bindings_present":false,"execution_armed":false',
        '"physical_evidence_present":false',
        '"future_operator_confirmed_cold_boots_required":3',
        '"f5_complete":false,"float_complete":false,"c88_complete":false',
        '"executable_successor_authorized":false',
    ]
    require(
        all(type(value) is str and value for value in strings),
        "internal Duo ELF marker contract is invalid",
    )
    return tuple(value.encode("ascii") for value in strings)


def verify_duo_elf_payload(raw: bytes) -> None:
    require(raw.startswith(b"\x7fELF"), "linked readiness input is not an ELF")
    for marker in duo_elf_payload_markers():
        require(marker in raw, f"Duo ELF payload marker is absent: {marker!r}")
    for qemu_marker in (
        b"qemu-virt-rv64-tcg-icount-v1",
        b"VIBE_C88_F5_META ",
        b"vibeos.c88.f5.float-target.meta",
    ):
        require(
            qemu_marker not in raw,
            f"Duo ELF contains a QEMU-only payload marker: {qemu_marker!r}",
        )


def audit_elf(elf_path: Path, audit_output: Path | None) -> tuple[str, int]:
    elf_path = elf_path.resolve(strict=False)
    if audit_output is not None:
        audit_output = audit_output.resolve(strict=False)
    initial_elf_raw = read_regular_file(elf_path, MAX_ELF_BYTES, "linked readiness ELF")
    verify_duo_elf_payload(initial_elf_raw)
    require_duo_elf_size(len(initial_elf_raw), "linked Duo readiness ELF byte count")
    initial_sha256 = sha256_hex(initial_elf_raw)
    initial_bytes = len(initial_elf_raw)
    auditor_raw = read_regular_file(
        ELF_AUDITOR, MAX_SOURCE_BYTES, "independent ELF auditor"
    )
    require(
        len(auditor_raw) == EXPECTED_ELF_AUDITOR_BYTES
        and sha256_hex(auditor_raw) == EXPECTED_ELF_AUDITOR_SHA256,
        "independent ELF auditor identity differs",
    )
    optimize_flag: list[str] = []
    if sys.flags.optimize == 1:
        optimize_flag = ["-O"]
    elif sys.flags.optimize >= 2:
        optimize_flag = ["-OO"]
    command = [
        sys.executable,
        *optimize_flag,
        "-I",
        str(ELF_AUDITOR),
        "--elf",
        str(elf_path),
    ]
    if audit_output is not None:
        command.extend(["--output", str(audit_output)])
    return_code, stdout, stderr = run_bounded(command)
    failure_output = stderr if stderr else stdout
    require(
        return_code == 0,
        "independent ELF auditor failed: "
        + failure_output.decode("utf-8", errors="replace").strip(),
    )
    require(not stderr, "independent ELF auditor emitted stderr on success")
    if audit_output is None:
        audit_raw = stdout
    else:
        require(not stdout, "file-output ELF audit unexpectedly emitted stdout")
        audit_raw = read_regular_file(
            audit_output, MAX_AUDITOR_OUTPUT, "ELF audit output"
        )
    report = parse_json_contract(audit_raw, "ELF audit report")
    elf_sha256, elf_bytes = verify_elf_audit_report(report)
    elf_raw = read_regular_file(elf_path, MAX_ELF_BYTES, "linked readiness ELF")
    actual_sha256, actual_bytes = sha256_hex(elf_raw), len(elf_raw)
    require(actual_sha256 == initial_sha256, "ELF changed during its audit")
    require(actual_bytes == initial_bytes, "ELF byte count changed during its audit")
    require(actual_sha256 == elf_sha256, "ELF changed or differs from its audit")
    require(actual_bytes == elf_bytes, "ELF byte count differs from its audit")
    verify_duo_elf_payload(elf_raw)
    return elf_sha256, elf_bytes


def encoded_contract(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def expect_failure(name: str, action: Any) -> None:
    try:
        action()
    except VerificationError:
        return
    fail(f"selftest mutation was accepted: {name}")


def selftest() -> int:
    snapshot = SourceSnapshot.capture(ROOT)
    verify_source_wiring(snapshot)
    mutations: list[tuple[str, Any]] = []

    alternative_report: dict[str, Any] = {
        "checks": list(EXPECTED_ELF_AUDIT_CHECKS),
        "elf": {
            "bytes": MIN_DUO_ELF_BYTES + 4_096,
            "control_flow": {
                "canonical_boundaries": MIN_DUO_ELF_INSTRUCTIONS + 1,
                "direct_targets": 1,
            },
            "e_flags": "0x00000001",
            "entry": "0x0000000080200000",
            "executable_sections": [
                {
                    "address": "0x0000000080200000",
                    "bytes": MIN_DUO_ELF_INSTRUCTIONS * 2,
                    "four_byte_instructions": 0,
                    "instructions": MIN_DUO_ELF_INSTRUCTIONS,
                    "name": ".text",
                    "sha256": "b" * 64,
                    "two_byte_instructions": MIN_DUO_ELF_INSTRUCTIONS,
                }
            ],
            "forbidden_opcodes": [],
            "program_headers": 4,
            "riscv_arch": (
                "rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_"
                "zaamo1p0_zalrsc1p0_zca1p0"
            ),
            "sections": 16,
            "sha256": "a" * 64,
            "symbols": {
                "code_symbols": MIN_DUO_ELF_CODE_SYMBOLS,
                "defined": MIN_DUO_ELF_CODE_SYMBOLS,
                "forbidden_helpers": [],
                "raw_symtab_entries": MIN_DUO_ELF_CODE_SYMBOLS,
                "undefined": 0,
            },
        },
        "execution_scope": list(EXPECTED_ELF_EXECUTION_SCOPE),
        "mode": "audit",
        "schema": "vibeos.c88.f5.riscv-final-elf.audit",
        "schema_version": 1,
        "status": "pass",
        "target": TARGET,
        "toolchain": {},
    }
    alternative_sha256, alternative_bytes = verify_elf_audit_report(alternative_report)
    require(
        alternative_sha256 == "a" * 64
        and alternative_bytes == MIN_DUO_ELF_BYTES + 4_096,
        "alternative structural ELF report did not pass",
    )

    def audit_report_mutation(name: str, mutate: Any) -> None:
        value = copy.deepcopy(alternative_report)
        mutate(value)
        mutations.append(
            (
                name,
                lambda value=value: verify_elf_audit_report(value),
            )
        )

    audit_report_mutation(
        "elf-report-truncated",
        lambda value: value["elf"].update(bytes=MIN_DUO_ELF_BYTES - 1),
    )
    audit_report_mutation(
        "elf-report-oversized",
        lambda value: value["elf"].update(bytes=MAX_ELF_BYTES + 1),
    )

    def reduce_report_instructions(value: dict[str, Any]) -> None:
        section = value["elf"]["executable_sections"][0]
        section["instructions"] = MIN_DUO_ELF_INSTRUCTIONS - 1
        section["two_byte_instructions"] = MIN_DUO_ELF_INSTRUCTIONS - 1
        value["elf"]["control_flow"]["canonical_boundaries"] = MIN_DUO_ELF_INSTRUCTIONS

    audit_report_mutation(
        "elf-report-truncated-producer",
        reduce_report_instructions,
    )
    audit_report_mutation(
        "elf-report-truncated-symbol-surface",
        lambda value: value["elf"]["symbols"].update(
            code_symbols=MIN_DUO_ELF_CODE_SYMBOLS - 1
        ),
    )
    audit_report_mutation(
        "elf-report-malformed-alternative-sha",
        lambda value: value["elf"].update(sha256="z" * 64),
    )

    def manifest_mutation(name: str, mutate: Any) -> None:
        value = copy.deepcopy(EXPECTED_MANIFEST)
        mutate(value)
        mutations.append(
            (name, lambda value=value: verify_manifest(encoded_contract(value)))
        )

    manifest_mutation("manifest-extra-key", lambda value: value.update(extra=False))
    manifest_mutation("manifest-version-bool", lambda value: value.update(version=True))
    manifest_mutation(
        "manifest-run-domain",
        lambda value: value["run_id"].update(
            sha256_domain_ascii="vibeos.c88.f5.float-target.run.v1"
        ),
    )
    manifest_mutation(
        "manifest-run-field-order",
        lambda value: value["run_id"]["nul_separated_fields"].reverse(),
    )
    manifest_mutation(
        "manifest-platform", lambda value: value["platform"].update(id="qemu-virt")
    )
    manifest_mutation(
        "manifest-provenance",
        lambda value: value["platform"].update(physical_provenance="claimed"),
    )
    manifest_mutation(
        "manifest-runtime-binding",
        lambda value: value["readiness"].update(sentinel_bindings_present=False),
    )
    manifest_mutation(
        "manifest-formal-binding",
        lambda value: value["readiness"].update(formal_physical_bindings_present=True),
    )
    manifest_mutation(
        "manifest-execution-armed",
        lambda value: value["readiness"].update(execution_armed=True),
    )
    manifest_mutation(
        "manifest-binding-mode",
        lambda value: value["readiness"].update(binding_mode="physical-evidence"),
    )
    manifest_mutation(
        "manifest-sentinel-challenge",
        lambda value: value["compile_readiness_sentinel"].update(challenge="e" * 64),
    )
    manifest_mutation(
        "manifest-sentinel-arm",
        lambda value: value["compile_readiness_sentinel"].update(arm_byte=1),
    )
    manifest_mutation(
        "manifest-capture",
        lambda value: value["readiness"].update(capture_present=True),
    )
    manifest_mutation(
        "manifest-physical-evidence",
        lambda value: value["readiness"].update(physical_evidence_present=True),
    )
    manifest_mutation(
        "manifest-f5-complete",
        lambda value: value["completion"].update(f5_complete=True),
    )
    manifest_mutation(
        "manifest-successor",
        lambda value: value["completion"].update(executable_successor_authorized=True),
    )
    manifest_mutation(
        "manifest-cold-boots-present",
        lambda value: value["future_physical_gate"].update(
            operator_confirmed_cold_boots_present=3
        ),
    )
    manifest_mutation(
        "manifest-power-cycle-required",
        lambda value: value["future_physical_gate"].update(
            each_boot_operator_confirmed_power_cycle_required=False
        ),
    )
    manifest_mutation(
        "manifest-cold-boot-required",
        lambda value: value["future_physical_gate"].update(
            each_boot_operator_confirmed_cold_boot_required=False
        ),
    )
    manifest_mutation(
        "manifest-power-cycles-present",
        lambda value: value["future_physical_gate"].update(
            operator_confirmed_power_cycles_present=3
        ),
    )
    manifest_mutation(
        "manifest-same-challenge",
        lambda value: value["future_physical_gate"].update(
            same_challenge_required=False
        ),
    )
    manifest_mutation(
        "manifest-same-run-id",
        lambda value: value["future_physical_gate"].update(same_run_id_required=False),
    )
    manifest_mutation(
        "manifest-unique-capture-boot-id",
        lambda value: value["future_physical_gate"].update(
            unique_capture_boot_id_required=False
        ),
    )
    manifest_mutation(
        "manifest-boot-ordinals",
        lambda value: value["future_physical_gate"].update(
            required_boot_ordinals=[0, 1, 3]
        ),
    )
    manifest_mutation(
        "manifest-same-identity-fields",
        lambda value: value["future_physical_gate"][
            "same_identity_fields_required"
        ].pop(),
    )
    manifest_mutation(
        "manifest-transcript-order",
        lambda value: value["future_physical_gate"][
            "per_boot_transcript_order"
        ].reverse(),
    )
    manifest_mutation(
        "manifest-complete-transcripts",
        lambda value: value["future_physical_gate"].update(
            complete_transcripts_present=3
        ),
    )
    manifest_mutation(
        "manifest-no-fail-record",
        lambda value: value["future_physical_gate"].update(
            no_fail_record_required=False
        ),
    )
    manifest_mutation(
        "manifest-successful-shutdown-claim",
        lambda value: value["future_physical_gate"].update(
            successful_sbi_shutdown_required=True
        ),
    )
    manifest_mutation(
        "manifest-terminal-quiescence-required",
        lambda value: value["future_physical_gate"].update(
            terminal_quiescence_after_pass_required=False
        ),
    )
    manifest_mutation(
        "manifest-terminal-quiescences-present",
        lambda value: value["future_physical_gate"].update(
            terminal_quiescences_present=3
        ),
    )
    manifest_mutation(
        "manifest-uart-after-pass",
        lambda value: value["future_physical_gate"].update(
            unexpected_uart_after_pass_forbidden=False
        ),
    )
    manifest_mutation(
        "manifest-operator-power-off-required",
        lambda value: value["future_physical_gate"].update(
            operator_power_off_after_pass_required=False
        ),
    )
    manifest_mutation(
        "manifest-power-off-confirmations-present",
        lambda value: value["future_physical_gate"].update(
            operator_power_off_confirmations_present=3
        ),
    )
    manifest_mutation(
        "manifest-gate-satisfied",
        lambda value: value["future_physical_gate"].update(gate_satisfied=True),
    )
    manifest_mutation(
        "manifest-future-key-order",
        lambda value: value.update(
            future_physical_gate=dict(
                reversed(list(value["future_physical_gate"].items()))
            )
        ),
    )
    manifest_mutation(
        "manifest-semantic",
        lambda value: value["shared_qualification"].update(semantic_sha256="e" * 64),
    )
    manifest_mutation(
        "manifest-record-count",
        lambda value: value["shared_qualification"]["records"].update(total=1175),
    )
    duplicate = snapshot.raw(MANIFEST_REL).replace(
        b'"version": 1,', b'"version": 1,\n  "version": 1,', 1
    )
    mutations.append(("manifest-duplicate-key", lambda: verify_manifest(duplicate)))

    def transcript_mutation(name: str, mutate: Any) -> None:
        value = copy.deepcopy(EXPECTED_TRANSCRIPT_SCHEMA)
        mutate(value)
        mutations.append(
            (
                name,
                lambda value=value: verify_transcript_schema(encoded_contract(value)),
            )
        )

    transcript_mutation("schema-extra-key", lambda value: value.update(extra=False))
    transcript_mutation(
        "schema-run-domain",
        lambda value: value["run_id"].update(
            domain_ascii="vibeos.c88.f5.float-target.run.v1"
        ),
    )
    transcript_mutation(
        "schema-run-domain-nul",
        lambda value: value["run_id"].update(domain_nul_terminated=False),
    )
    transcript_mutation(
        "schema-run-field-order",
        lambda value: value["run_id"]["nul_separated_fields"].reverse(),
    )
    transcript_mutation(
        "schema-semantic-domain",
        lambda value: value["semantic_digest"].update(
            domain_ascii="vibeos.c88.f5.float-target.duo.semantic.v1"
        ),
    )
    transcript_mutation(
        "schema-semantic-hash",
        lambda value: value["semantic_digest"].update(expected_sha256="e" * 64),
    )
    transcript_mutation(
        "schema-family-order",
        lambda value: value["semantic_digest"]["family_order"].reverse(),
    )
    transcript_mutation(
        "schema-uart-prefix",
        lambda value: value["uart"]["prefixes"].update(metadata="VIBE_C88_F5_META "),
    )
    transcript_mutation(
        "schema-id",
        lambda value: value["uart"]["schema_ids"].update(
            core="vibeos.c88.f5.float-target.core-case"
        ),
    )
    transcript_mutation(
        "schema-core-count",
        lambda value: value["records"].update(core=145),
    )
    transcript_mutation(
        "schema-total-bool",
        lambda value: value["records"].update(total=True),
    )
    transcript_mutation(
        "schema-capture",
        lambda value: value["evidence_contract"].update(capture_present=True),
    )
    transcript_mutation(
        "schema-execution-armed",
        lambda value: value["evidence_contract"].update(execution_armed=True),
    )
    transcript_mutation(
        "schema-sentinel-source",
        lambda value: value["compile_readiness_sentinel"].update(
            source_commit="e" * 40
        ),
    )
    transcript_mutation(
        "schema-future-boots",
        lambda value: value["evidence_contract"].update(
            future_operator_confirmed_cold_boots_required=0
        ),
    )
    transcript_mutation(
        "schema-future-power-cycles",
        lambda value: value["future_physical_gate"].update(
            operator_confirmed_power_cycles_required=2
        ),
    )
    transcript_mutation(
        "schema-future-semantic",
        lambda value: value["future_physical_gate"].update(
            required_semantic_sha256="e" * 64
        ),
    )
    transcript_mutation(
        "schema-future-physical-evidence",
        lambda value: value["future_physical_gate"].update(gate_satisfied=True),
    )
    transcript_mutation(
        "schema-successful-shutdown-claim",
        lambda value: value["future_physical_gate"].update(
            successful_sbi_shutdown_required=True
        ),
    )
    duplicate_schema = snapshot.raw(TRANSCRIPT_SCHEMA_REL).replace(
        b'"version": 1,', b'"version": 1,\n  "version": 1,', 1
    )
    mutations.append(
        (
            "schema-duplicate-key",
            lambda: verify_transcript_schema(duplicate_schema),
        )
    )

    source_mutations = (
        (
            "acceptance-qemu-policy",
            snapshot.replace(
                ACCEPTANCE_CARGO_REL,
                b"vibeos-component-image-adapter/c88-f4-float-candidate-duo",
                b"vibeos-component-image-adapter/c88-f4-float-candidate",
            ),
        ),
        (
            "adapter-duo-qemu-policy",
            snapshot.replace(
                ADAPTER_CARGO_REL,
                b'c88-f4-float-candidate-duo = [\n    "c88-f4-float-candidate-core",\n    "vibeos-image-policy/milkv-duo-sd",\n]',
                b'c88-f4-float-candidate-duo = [\n    "c88-f4-float-candidate-core",\n    "vibeos-image-policy/qemu-default",\n]',
            ),
        ),
        (
            "adapter-project-core-gate",
            snapshot.replace(
                ADAPTER_LIB_REL,
                b'#[cfg(feature = "c88-f4-float-candidate-core")]\n'
                b"pub fn project_float_candidate(",
                b"pub fn project_float_candidate(",
            ),
        ),
        (
            "policy-duo-boundary",
            snapshot.replace(
                POLICY_LIB_REL,
                b'feature = "c88-f4-float-candidate",\n'
                b'    not(any(feature = "qemu-default", feature = "milkv-duo-sd"))',
                b'feature = "c88-f4-float-candidate",\n'
                b'    not(feature = "qemu-default")',
            ),
        ),
        (
            "kernel-feature-forwarding",
            snapshot.replace(
                KERNEL_CARGO_REL,
                f"vibeos-wasm-float-target/{ACCEPTANCE_FEATURE}".encode(),
                b"vibeos-wasm-float-target/c88-f5-acceptance",
            ),
        ),
        (
            "firmware-feature-forwarding",
            snapshot.replace(
                MILKV_FIRMWARE_REL,
                f'"vibeos-kernel/{IMAGE_FEATURE}"'.encode(),
                b'"vibeos-kernel/wasm-c88-f5-float-qemu-acceptance"',
            ),
        ),
        (
            "kernel-platform",
            snapshot.replace(
                KERNEL_ADAPTER_REL,
                PLATFORM.encode(),
                b"qemu-virt-rv64-tcg-icount-v1",
            ),
        ),
        (
            "kernel-run-id-domain",
            snapshot.replace(
                KERNEL_ADAPTER_REL,
                RUN_ID_DOMAIN[:-1].encode(),
                b"vibeos.c88.f5.float-target.run.v1",
            ),
        ),
        (
            "kernel-manifest-identity-equality",
            snapshot.replace(
                KERNEL_ADAPTER_REL,
                b"        && MANIFEST_SHA256 == DUO_QUALIFICATION_MANIFEST_SHA256\n",
                b"",
            ),
        ),
        (
            "kernel-duo-uart-prefix",
            snapshot.replace(
                KERNEL_ADAPTER_REL,
                b"VIBE_C88_F5_DUO_CORE_CASE ",
                b"VIBE_C88_F5_CORE_CASE ",
            ),
        ),
        (
            "build-online",
            snapshot.replace(BUILD_SCRIPT_REL, b"      --offline \\\n", b""),
        ),
        (
            "build-default-features",
            snapshot.replace(
                BUILD_SCRIPT_REL, b"      --no-default-features \\\n", b""
            ),
        ),
        (
            "build-extra-cargo-option",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b"      --locked \\\n",
                b"      --locked \\\n"
                b"      --target riscv64gc-unknown-none-elf \\\n",
            ),
        ),
        (
            "build-incremental",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b"    CARGO_INCREMENTAL=0 \\",
                b"    CARGO_INCREMENTAL=1 \\",
            ),
        ),
        (
            "build-fmt-debug-none",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b" -Z fmt-debug=none'",
                b"'",
            ),
        ),
        (
            "build-shared-target",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'target_dir="$target_parent/c88-f5-duo-readiness/build"',
                b'target_dir="$repo_root/target"',
            ),
        ),
        (
            "build-binding-restored",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b"unset VIBEOS_C88_F5_DUO_RUN_ID",
                b"VIBEOS_C88_F5_DUO_RUN_ID=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        ),
        (
            "build-sentinel-run-id",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                EXPECTED_SENTINEL_RUN_ID.encode(),
                ("f" * 64).encode(),
            ),
        ),
        (
            "build-pinned-cargo-reassignment",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'(\n  cd "$repo_root/firmware/milkv-duo"',
                b"(\n  pinned_cargo=/tmp/unreviewed-cargo\n"
                b'  cd "$repo_root/firmware/milkv-duo"',
            ),
        ),
        (
            "build-target-reassignment",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'mkdir -p "$target_dir"',
                b'mkdir -p "$target_dir"\n' b"target_dir=/tmp/unreviewed-target",
            ),
        ),
        (
            "build-extra-cd",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'(\n  cd "$repo_root/firmware/milkv-duo"',
                b'(\n  cd /tmp\n  cd "$repo_root/firmware/milkv-duo"',
            ),
        ),
        (
            "build-extra-mkdir",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'mkdir -p "$target_dir"',
                b'mkdir -p "$target_dir"\nmkdir -p /tmp/unreviewed-target',
            ),
        ),
        (
            "build-exact-byte-identity",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b"# Cross-link the inert-sentinel",
                b"# Cross-link one inert-sentinel",
            ),
        ),
        (
            "build-qemu-command",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'echo "C8.8-F5 Milk-V Duo compile readiness: PASS"',
                b"qemu-system-riscv64 --version\n"
                b'echo "C8.8-F5 Milk-V Duo compile readiness: PASS"',
            ),
        ),
        (
            "build-unreviewed-command",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'echo "C8.8-F5 Milk-V Duo compile readiness: PASS"',
                b"python3 unexpected-helper.py\n"
                b'echo "C8.8-F5 Milk-V Duo compile readiness: PASS"',
            ),
        ),
        (
            "build-package-command",
            snapshot.replace(
                BUILD_SCRIPT_REL,
                b'echo "C8.8-F5 Milk-V Duo compile readiness: PASS"',
                b'rust-objcopy "$built_elf" readiness.bin\n'
                b'echo "C8.8-F5 Milk-V Duo compile readiness: PASS"',
            ),
        ),
    )
    for name, mutated_snapshot in source_mutations:
        mutations.append(
            (
                name,
                lambda mutated_snapshot=mutated_snapshot: verify_source_wiring(
                    mutated_snapshot
                ),
            )
        )

    def add_source_mutation(name: str, mutated_snapshot: SourceSnapshot) -> None:
        mutations.append(
            (
                name,
                lambda mutated_snapshot=mutated_snapshot: verify_source_wiring(
                    mutated_snapshot
                ),
            )
        )

    guarded_sites = [
        (
            "kernel-dwc2-init-exclusion",
            MILKV_DUO_EXCLUDED_GUARD,
            "match dwc2_host::init() {",
        ),
        (
            "kernel-dwc2-telemetry-exclusion",
            MILKV_DUO_EXCLUDED_GUARD,
            "if let Some(usb) = dwc2_host::telemetry() {",
        ),
        (
            "kernel-dwc2-enumeration-exclusion",
            MILKV_DUO_EXCLUDED_GUARD,
            "if dwc2_host::connected() {",
        ),
        (
            "kernel-dwc2-service-exclusion",
            MILKV_DUO_EXCLUDED_GUARD,
            "if dwc2_host::info().is_some() {",
        ),
        ("kernel-world-build-exclusion", DUO_EXCLUDED_GUARD, "world::build();"),
        (
            "kernel-world-access-exclusion",
            DUO_EXCLUDED_GUARD,
            "let world = world::world();",
        ),
        (
            "kernel-block-supervisor-exclusion",
            DUO_EXCLUDED_GUARD,
            "world::start_block_supervisor();",
        ),
        (
            "kernel-net-supervisor-exclusion",
            DUO_EXCLUDED_GUARD,
            "world::start_net_supervisor();",
        ),
        (
            "kernel-usb-net-supervisor-exclusion",
            MILKV_DUO_EXCLUDED_GUARD,
            "world::start_usb_net_supervisor();",
        ),
        (
            "kernel-rng-supervisor-exclusion",
            QEMU_DUO_EXCLUDED_GUARD,
            "world::start_rng_supervisor();",
        ),
        (
            "kernel-xhci-service-exclusion",
            QEMU_DUO_EXCLUDED_GUARD,
            "if xhci::info().is_some() {",
        ),
    ]
    for name, guard, statement in guarded_sites:
        mutated_guard = "\n".join(
            line for line in guard.splitlines() if IMAGE_FEATURE not in line
        )
        original = f"{guard}\n    {statement}".encode()
        replacement = f"{mutated_guard}\n    {statement}".encode()
        add_source_mutation(
            name,
            snapshot.replace(KERNEL_LIB_REL, original, replacement),
        )

    mutated_vsh_guard = "\n".join(
        line
        for line in VSH_DUO_EXCLUDED_GUARD.splitlines()
        if IMAGE_FEATURE not in line
    )
    add_source_mutation(
        "kernel-vsh-command-exclusion",
        snapshot.replace(
            KERNEL_LIB_REL,
            (
                f"{VSH_DUO_EXCLUDED_GUARD}\n    {{\n"
                '        let space = world.spaces["vsh"].clone();'
            ).encode(),
            (
                f"{mutated_vsh_guard}\n    {{\n"
                '        let space = world.spaces["vsh"].clone();'
            ).encode(),
        ),
    )

    kernel_source = snapshot.text(KERNEL_LIB_REL)
    isolation_end_marker = (
        f'    "feature `{IMAGE_FEATURE}` is an isolated, non-production readiness image"\n'
        ");"
    )
    isolation_end = kernel_source.find(isolation_end_marker)
    require(isolation_end >= 0, "selftest isolation mutation marker is absent")
    isolation_start = kernel_source.rfind("#[cfg(all(", 0, isolation_end)
    require(isolation_start >= 0, "selftest isolation mutation start is absent")
    isolation_block = kernel_source[
        isolation_start : isolation_end + len(isolation_end_marker)
    ]
    mutated_isolation_block = isolation_block.replace(
        '        feature = "ssh-component-command",\n', "", 1
    )
    require(
        mutated_isolation_block != isolation_block,
        "selftest isolation feature mutation did not apply",
    )
    add_source_mutation(
        "kernel-ssh-command-compile-isolation",
        snapshot.replace(
            KERNEL_LIB_REL,
            isolation_block.encode(),
            mutated_isolation_block.encode(),
        ),
    )

    add_source_mutation(
        "kernel-sbi-runtime-reexport",
        snapshot.replace(
            KERNEL_LIB_REL,
            b"pub use vibeos_runtime_riscv as sbi;",
            b"pub use vibeos_core::arch as sbi;",
        ),
    )
    add_source_mutation(
        "runtime-shutdown-wfi-loop",
        snapshot.replace(
            RUNTIME_BARE_REL,
            RUNTIME_SHUTDOWN_SOURCE.encode(),
            RUNTIME_SHUTDOWN_SOURCE.replace(
                "    loop {\n        wait_for_interrupt();\n    }",
                "    wait_for_interrupt();",
            ).encode(),
        ),
    )
    add_source_mutation(
        "kernel-duo-arm-byte",
        snapshot.replace(
            KERNEL_ADAPTER_REL,
            b"static DUO_EXECUTION_ARM: u8 = 0;",
            b"static DUO_EXECUTION_ARM: u8 = 1;",
        ),
    )
    add_source_mutation(
        "kernel-duo-arm-marker",
        snapshot.replace(
            KERNEL_ADAPTER_REL,
            ELF_ARM_MARKER.encode(),
            b"vibeos.c88.f5.duo.compile-readiness.arm=1",
        ),
    )
    add_source_mutation(
        "kernel-duo-arm-volatile",
        snapshot.replace(
            KERNEL_ADAPTER_REL,
            b"core::ptr::read_volatile(core::ptr::addr_of!(DUO_EXECUTION_ARM)) == 1",
            b"DUO_EXECUTION_ARM == 1",
        ),
    )
    add_source_mutation(
        "kernel-duo-first-fail",
        snapshot.replace(
            KERNEL_ADAPTER_REL,
            (
                f'    #[cfg(feature = "{IMAGE_FEATURE}")]\n'
                "    if !execution_armed() {\n"
                "        fail(0xff00);\n"
                "    }\n"
            ).encode(),
            b"",
        ),
    )
    add_source_mutation(
        "kernel-duo-terminal-srst",
        snapshot.replace(
            KERNEL_ADAPTER_REL,
            b"        crate::sbi::wait_for_interrupt();",
            b"        crate::sbi::shutdown(false);",
        ),
    )

    payload = b"\x7fELF" + b"\0".join(duo_elf_payload_markers())
    verify_duo_elf_payload(payload)
    for index, marker in enumerate(duo_elf_payload_markers()):
        mutated_payload = payload.replace(marker, b"x" * len(marker))
        mutations.append(
            (
                f"elf-payload-marker-{index}",
                lambda mutated_payload=mutated_payload: verify_duo_elf_payload(
                    mutated_payload
                ),
            )
        )
    mutations.append(
        (
            "elf-qemu-payload",
            lambda: verify_duo_elf_payload(
                b"\x7fELF\0qemu-virt-rv64-tcg-icount-v1\0VIBE_C88_F5_META "
            ),
        )
    )
    mutations.append(
        (
            "elf-qemu-marker-injection",
            lambda: verify_duo_elf_payload(payload + b"\0qemu-virt-rv64-tcg-icount-v1"),
        )
    )

    rejected = 0
    for name, action in mutations:
        expect_failure(name, action)
        rejected += 1
    print(
        "verify-c88-f5-duo-readiness.py selftest: PASS "
        f"({rejected} mutations rejected) physical_provenance={PHYSICAL_PROVENANCE}"
    )
    return rejected


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / MANIFEST_REL,
        help="Duo readiness manifest (the checked-in path by default)",
    )
    parser.add_argument(
        "--elf", type=Path, help="optionally audit one final linked readiness ELF"
    )
    parser.add_argument(
        "--audit-output",
        type=Path,
        help="exclusively create the delegated final-ELF audit report",
    )
    parser.add_argument(
        "--selftest", action="store_true", help="run fail-closed contract mutations"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = argument_parser().parse_args(argv)
    try:
        if arguments.selftest:
            require(
                arguments.elf is None and arguments.audit_output is None,
                "--selftest does not accept ELF evidence paths",
            )
            require(
                arguments.manifest == ROOT / MANIFEST_REL,
                "--selftest does not accept a manifest override",
            )
            selftest()
            return 0
        require(
            arguments.audit_output is None or arguments.elf is not None,
            "--audit-output requires --elf",
        )
        snapshot = SourceSnapshot.capture(ROOT)
        manifest_raw = read_regular_file(
            arguments.manifest, MAX_CONTRACT_BYTES, "Duo readiness manifest"
        )
        verify_manifest(manifest_raw)
        require(
            manifest_raw == snapshot.raw(MANIFEST_REL),
            "manifest override bytes differ from the source-wired contract",
        )
        verify_source_wiring(snapshot)
        manifest_sha256 = sha256_hex(snapshot.raw(MANIFEST_REL))
        manifest_bytes = len(snapshot.raw(MANIFEST_REL))
        transcript_schema_sha256 = sha256_hex(snapshot.raw(TRANSCRIPT_SCHEMA_REL))
        transcript_schema_bytes = len(snapshot.raw(TRANSCRIPT_SCHEMA_REL))
        if arguments.elf is None:
            print(
                "verify-c88-f5-duo-readiness.py: PASS "
                f"stage={READINESS_STAGE} platform={PLATFORM} "
                f"manifest_sha256={manifest_sha256} manifest_bytes={manifest_bytes} "
                f"transcript_schema_sha256={transcript_schema_sha256} "
                f"transcript_schema_bytes={transcript_schema_bytes} "
                f"physical_provenance={PHYSICAL_PROVENANCE} "
                f"binding_mode={SENTINEL_BINDING_MODE} "
                "sentinel_bindings_present=true "
                "formal_physical_bindings_present=false execution_armed=false "
                "source_build_provenance=not-claimed "
                "capture_present=false physical_evidence_present=false "
                "f5_complete=false executable_successor_authorized=false"
            )
            return 0
        elf_sha256, elf_bytes = audit_elf(arguments.elf, arguments.audit_output)
        print(
            "verify-c88-f5-duo-readiness.py: PASS "
            f"stage={READINESS_STAGE} platform={PLATFORM} "
            f"elf_sha256={elf_sha256} elf_bytes={elf_bytes} "
            f"manifest_sha256={manifest_sha256} manifest_bytes={manifest_bytes} "
            f"transcript_schema_sha256={transcript_schema_sha256} "
            f"transcript_schema_bytes={transcript_schema_bytes} "
            f"physical_provenance={PHYSICAL_PROVENANCE} "
            f"binding_mode={SENTINEL_BINDING_MODE} "
            "sentinel_bindings_present=true "
            "formal_physical_bindings_present=false execution_armed=false "
            "elf_payload_bound=true source_build_provenance=not-claimed "
            "capture_present=false physical_evidence_present=false "
            "f5_complete=false executable_successor_authorized=false"
        )
        return 0
    except VerificationError as error:
        print(f"verify-c88-f5-duo-readiness.py: FAIL ({error})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
