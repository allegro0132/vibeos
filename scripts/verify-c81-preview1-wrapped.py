#!/usr/bin/env python3
"""Independent, host-only verifier for the frozen C8.1 Preview1 wrapper.

Only Python's standard library and the independently maintained C7.1 CMP1
parser are used.  This verifier never instantiates a Component, maps a host
function, looks up an adapter, or grants execution authority.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "policy/image/artifacts/c81-preview1-wrapped-policy.json"
POLICY_SEMANTIC_SHA256 = "b008cde61270e3e7424367d2adf7435919bcb3a3cb93b33204415465b4b94a29"

CORE_HEADER = b"\0asm\x01\0\0\0"
COMPONENT_HEADER = b"\0asm\x0d\0\x01\0"
MAX_POLICY_BYTES = 64 * 1024
MAX_WASM_BYTES = 1024 * 1024
MAX_SECTIONS = 4096
MAX_VECTOR_ITEMS = 4096
HEX32 = re.compile(r"[0-9a-f]{64}\Z")

SECTION_NAMES = {
    0: "custom",
    1: "core_module",
    2: "core_instance",
    3: "core_type",
    4: "nested_component",
    5: "component_instance",
    6: "alias",
    7: "component_type",
    8: "canonical",
    9: "start",
    10: "import",
    11: "export",
}

EXPECTED_FIELD_SETS: dict[tuple[str, ...], set[str]] = {
    (): {"schema", "version", "profile", "transformer", "adapter", "guest_core", "component", "component_artifact", "admission"},
    ("profile",): {"name", "code", "artifact_abi", "component_profile", "core_profile", "runtime_abi", "stage", "core_revision", "component_revision", "canonical_abi_revision", "wasm_tools_revision", "wasi_revision", "canonical_features", "runtime_ready", "profile_runtime_ready"},
    ("transformer",): {"location", "implementation", "wit_component_version", "wit_component_crate_sha256", "reference_cli_version", "reference_cli_source_commit", "reference_cli_aarch64_macos_archive_sha256", "reference_cli_x86_64_linux_archive_sha256", "adapter_import_name", "validate_output", "allow_disable_validation", "allow_import_rename", "ambient_adapter_lookup", "network_lookup"},
    ("adapter",): {"release", "source_commit", "asset", "manifest_revision", "source_url", "byte_len", "sha256", "license", "target_wasi_revision", "published_asset_bytes_are_normative", "source_tag_is_bit_reproducibility_claim"},
    ("guest_core",): {"fixture", "byte_len", "sha256", "imports", "exports", "core_start_section", "memory_initial_pages", "memory_maximum_pages", "allowed_preview1_functions"},
    ("guest_core", "imports", "*"): {"module", "name", "kind", "params", "results"},
    ("component",): {"fixture", "byte_len", "sha256", "top_level_section_count", "top_level_section_occurrences", "top_level_entry_counts", "imports", "exports", "top_level_entity_pins", "embedded_core_modules", "canonical_entries", "nested_components", "nested_component_top_level_section_ordinal"},
    ("component", "top_level_section_occurrences"): {"custom", "core_module", "core_instance", "nested_component", "component_instance", "alias", "component_type", "canonical", "import", "export"},
    ("component", "top_level_entry_counts"): {"core_instance", "component_instance", "alias", "component_type", "canonical", "import", "export"},
    ("component", "embedded_core_modules", "*"): {"ordinal", "byte_len", "sha256"},
    ("component", "top_level_entity_pins", "*"): {"direction", "kind", "name", "raw_byte_len", "raw_entry_sha256"},
    ("component", "canonical_entries"): {"total", "resource_drop", "lower", "lift", "lower_fingerprint_domain", "lower_fingerprint_format", "lower_fingerprint_sha256"},
    ("component_artifact",): {"fixture", "world", "wit_package", "interface_entity_kind", "interface_diagnostic_shape", "adapter_ordinal", "adapter_revision", "signer_policy_kind", "signer_policy_digest", "instance_limits", "runtime_ready"},
    ("component_artifact", "wit_package"): {"name", "version", "source_fixture", "source_sha256"},
    ("component_artifact", "instance_limits"): {"memory_bytes", "total_fuel", "poll_quantum", "resources"},
    ("admission",): {"feature", "default_enabled", "input_kind", "raw_wasip1_admission", "validation_only_candidate", "host_mappings", "ambient_lookup", "raw_durable_ids", "no_grant_direct_move", "guest_execution", "guest_calls", "runtime_ready", "profile_runtime_ready", "guest_transformer", "kernel_transformer", "preopens", "filesystem_authority", "environment_authority", "process_authority", "socket_authority", "thread_authority", "selected_wasi_0_3_mapping", "aot", "jit"},
}


class VerificationError(ValueError):
    """Fail-closed independent verification error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _reviewed_json(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(type(key) is str, f"{label} has a non-string object key")
            require(key not in result, f"{label} repeats JSON member {key!r}")
            result[key] = value
        return result

    def reject_float(token: str) -> Any:
        raise VerificationError(f"{label} contains unsupported JSON number {token}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not strict UTF-8 JSON: {error}") from error
    return value


def _canonical_json_types(value: Any, path: tuple[str, ...] = ()) -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str and key != "", f"{'.'.join(path)} has invalid key")
            _canonical_json_types(child, path + (key,))
    elif type(value) is list:
        for child in value:
            _canonical_json_types(child, path + ("*",))
    elif type(value) is str:
        if path != ("component", "canonical_entries", "lower_fingerprint_domain"):
            require("\0" not in value, f"{'.'.join(path)} contains NUL")
    elif type(value) is int:
        require(0 <= value <= (1 << 63) - 1, f"{'.'.join(path)} integer is out of range")
    elif type(value) is bool or value is None:
        return
    else:
        raise VerificationError(f"{'.'.join(path)} has a noncanonical JSON type")


def _object_at(value: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = value
    for part in path:
        current = current[part]
    return current


def _exact_fields(value: Mapping[str, Any]) -> None:
    for path, expected in EXPECTED_FIELD_SETS.items():
        if path and path[-1] == "*":
            sequence = _object_at(value, path[:-1])
            require(type(sequence) is list, f"{'.'.join(path[:-1])} is not an array")
            for index, item in enumerate(sequence):
                require(type(item) is dict, f"{'.'.join(path[:-1])}[{index}] is not an object")
                require(set(item) == expected, f"{'.'.join(path[:-1])}[{index}] field set differs")
        else:
            item = _object_at(value, path) if path else value
            require(type(item) is dict, f"{'.'.join(path) or 'policy'} is not an object")
            require(set(item) == expected, f"{'.'.join(path) or 'policy'} field set differs")


def exact_int(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= (1 << 63) - 1, f"{label} is not an exact integer")
    return value


def exact_bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} is not an exact boolean")
    return value


def exact_text(value: Any, label: str, maximum: int = 4096) -> str:
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum and "\0" not in value, f"{label} is not bounded text")
    return value


def exact_hex(value: Any, label: str) -> str:
    require(type(value) is str and HEX32.fullmatch(value) is not None and value != "0" * 64, f"{label} is not canonical nonzero SHA-256")
    return value


@dataclass(frozen=True)
class Policy:
    path: Path
    raw: bytes
    value: dict[str, Any]

    @property
    def directory(self) -> Path:
        return self.path.parent


def validate_policy_value(value: dict[str, Any], *, require_frozen_digest: bool) -> None:
    _canonical_json_types(value)
    _exact_fields(value)
    if require_frozen_digest:
        require(sha256(canonical_json(value)).hex() == POLICY_SEMANTIC_SHA256, "policy semantic content differs from the frozen C8.1 policy")

    require(value["schema"] == "vibeos.c81.preview1-wrapped-policy", "policy schema differs")
    require(exact_int(value["version"], "version") == 1, "policy version differs")
    profile = value["profile"]
    expected_profile = {
        "name": "profile-1-preview1-wrapped",
        "code": 4,
        "artifact_abi": 4,
        "component_profile": 1,
        "core_profile": 1,
        "runtime_abi": 4,
        "stage": "validation-only",
        "core_revision": "webassembly-core-2.0-integer-v1",
        "component_revision": "wasmparser-component-model-0.255.0",
        "canonical_abi_revision": "component-model-0.255.0-sync",
        "wasm_tools_revision": "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380",
        "wasi_revision": "wasi-v0.2.12",
        "canonical_features": 7,
        "runtime_ready": False,
        "profile_runtime_ready": False,
    }
    require(profile == expected_profile, "profile identity or inert stage differs")

    transformer = value["transformer"]
    for field in ("validate_output",):
        require(exact_bool(transformer[field], f"transformer.{field}") is True, f"transformer.{field} must be true")
    for field in ("allow_disable_validation", "allow_import_rename", "ambient_adapter_lookup", "network_lookup"):
        require(exact_bool(transformer[field], f"transformer.{field}") is False, f"transformer.{field} must be false")
    require(transformer["location"] == "off-device-host-only", "transformer is not off-device-only")
    require(transformer["implementation"] == "tools/c81-preview1-componentizer", "transformer implementation differs")
    require(transformer["wit_component_version"] == "0.255.0", "wit-component version differs")
    require(transformer["adapter_import_name"] == "wasi_snapshot_preview1", "adapter import name differs")
    for field in ("wit_component_crate_sha256", "reference_cli_aarch64_macos_archive_sha256", "reference_cli_x86_64_linux_archive_sha256"):
        exact_hex(transformer[field], f"transformer.{field}")

    adapter = value["adapter"]
    require(adapter["asset"] == "wasi_snapshot_preview1.command.wasm", "adapter asset name differs")
    require(adapter["target_wasi_revision"] == "0.2.12", "adapter target differs")
    require(adapter["manifest_revision"] == "wasmtime-v48.0.0-f1412a598f96f3c261a19118d94caffcb0c36235/wasi_snapshot_preview1.command.wasm", "adapter manifest revision differs")
    require(exact_bool(adapter["published_asset_bytes_are_normative"], "adapter.published_asset_bytes_are_normative") is True, "adapter bytes are not normative")
    require(exact_bool(adapter["source_tag_is_bit_reproducibility_claim"], "adapter.source_tag_is_bit_reproducibility_claim") is False, "source tag became byte authority")
    require(exact_int(adapter["byte_len"], "adapter.byte_len", 1) == 51_828, "adapter byte length differs")
    require(exact_hex(adapter["sha256"], "adapter.sha256") == "316dfbf171591d69ae414efd13b85933ca13526af8d9e0a735ab88ae08fd85f0", "adapter digest differs")

    guest = value["guest_core"]
    require(exact_int(guest["byte_len"], "guest_core.byte_len", 1) == 145, "guest byte length differs")
    require(exact_hex(guest["sha256"], "guest_core.sha256") == "5ac1eb14874721c8355669fd91811f9a0165d96f1382ff82f08f3dfc0634bb0c", "guest digest differs")
    require(guest["imports"] == [{"module": "wasi_snapshot_preview1", "name": "fd_write", "kind": "func", "params": ["i32"] * 4, "results": ["i32"]}], "guest import contract differs")
    require(type(guest["exports"]) is list and len(guest["exports"]) == 2 and set(guest["exports"][0]) == {"name", "kind"} and set(guest["exports"][1]) == {"name", "kind", "params", "results"}, "guest export field sets differ")
    require(guest["exports"] == [{"name": "memory", "kind": "memory"}, {"name": "_start", "kind": "func", "params": [], "results": []}], "guest export contract differs")
    require(exact_bool(guest["core_start_section"], "guest_core.core_start_section") is False, "Core start section must be forbidden")
    require((exact_int(guest["memory_initial_pages"], "guest_core.memory_initial_pages"), exact_int(guest["memory_maximum_pages"], "guest_core.memory_maximum_pages")) == (1, 16), "guest memory must be exactly min=1 max=16")
    require(guest["allowed_preview1_functions"] == ["fd_write"], "Preview1 function allowlist differs")

    component = value["component"]
    require(exact_int(component["byte_len"], "component.byte_len", 1) == 17_495, "component byte length differs")
    require(exact_hex(component["sha256"], "component.sha256") == "b910b4428e9ff442649f36a59707373a34d73f50f11fc1ae1266cd9f19e9f48e", "component digest differs")
    require(exact_int(component["top_level_section_count"], "component.top_level_section_count", 1) == 86, "component section count differs")
    for key, count in component["top_level_section_occurrences"].items():
        exact_int(count, f"component.top_level_section_occurrences.{key}")
    require(sum(component["top_level_section_occurrences"].values()) == 86, "component section-id counts do not sum to 86")
    expected_entry_counts = {"core_instance": 15, "component_instance": 1, "alias": 42, "component_type": 10, "canonical": 18, "import": 8, "export": 1}
    require(component["top_level_entry_counts"] == expected_entry_counts, "component entry counts differ")
    expected_imports = [
        "wasi:io/error@0.2.12", "wasi:io/streams@0.2.12", "wasi:cli/stdin@0.2.12", "wasi:cli/stdout@0.2.12", "wasi:cli/stderr@0.2.12", "wasi:clocks/wall-clock@0.2.12", "wasi:filesystem/types@0.2.12", "wasi:filesystem/preopens@0.2.12"
    ]
    require(component["imports"] == expected_imports, "component import identities differ")
    require(component["exports"] == ["wasi:cli/run@0.2.12"], "component export identity differs")
    entity_pins = component["top_level_entity_pins"]
    require(type(entity_pins) is list and len(entity_pins) == 9, "component must pin nine top-level entities")
    entity_keys: list[tuple[str, str, str]] = []
    for index, pin in enumerate(entity_pins):
        require(pin["direction"] in ("import", "export") and pin["kind"] == "instance", f"entity pin {index} direction/kind differs")
        exact_text(pin["name"], f"entity pin {index} name", 512)
        exact_int(pin["raw_byte_len"], f"entity pin {index} raw_byte_len", 1)
        exact_hex(pin["raw_entry_sha256"], f"entity pin {index} raw_entry_sha256")
        entity_keys.append((pin["direction"], pin["kind"], pin["name"]))
    require(entity_keys == sorted(entity_keys, key=lambda item: ((0 if item[0] == "import" else 1), item[1], item[2])), "component entity pins are not in canonical order")
    require({pin["name"] for pin in entity_pins if pin["direction"] == "import"} == set(expected_imports), "component import entity pins differ")
    require([pin["name"] for pin in entity_pins if pin["direction"] == "export"] == component["exports"], "component export entity pins differ")
    modules = component["embedded_core_modules"]
    require(type(modules) is list and len(modules) == 4, "component must pin four Core modules")
    for ordinal, module in enumerate(modules):
        require(exact_int(module["ordinal"], f"module[{ordinal}].ordinal") == ordinal, "module ordinals are not contiguous")
        exact_int(module["byte_len"], f"module[{ordinal}].byte_len", 1)
        exact_hex(module["sha256"], f"module[{ordinal}].sha256")
    require(modules[0]["byte_len"] == guest["byte_len"] and modules[0]["sha256"] == guest["sha256"], "guest is not exact embedded module ordinal zero")
    canonical = component["canonical_entries"]
    require((exact_int(canonical["total"], "canonical.total"), exact_int(canonical["resource_drop"], "canonical.resource_drop"), exact_int(canonical["lower"], "canonical.lower"), exact_int(canonical["lift"], "canonical.lift")) == (18, 4, 13, 1), "canonical entry topology differs")
    require(canonical["lower_fingerprint_domain"] == "vibeos.preview1-wrapped.canonical-lowerings.v1\0", "lower fingerprint domain differs")
    require(canonical["lower_fingerprint_format"] == "sha256(domain || concat(u64le(raw_entry_len) || raw_entry_bytes))", "lower fingerprint format differs")
    exact_hex(canonical["lower_fingerprint_sha256"], "canonical.lower_fingerprint_sha256")
    require(exact_int(component["nested_components"], "component.nested_components") == 1, "nested component count differs")
    require(exact_int(component["nested_component_top_level_section_ordinal"], "component.nested_component_top_level_section_ordinal") == 82, "nested component ordinal differs")

    artifact = value["component_artifact"]
    require(artifact["fixture"] == "c81-fd-write.preview1-wrapped.cmp1", "ComponentArtifact fixture name differs")
    require(artifact["world"] == "root:component/root", "ComponentArtifact world differs")
    require(artifact["wit_package"] == {"name": "root:component", "version": "0.0.0+c81", "source_fixture": "c81-fd-write.component.wit", "source_sha256": "39c4ec95a1e92a8df777b03d0d11349b150725c50d862231fca35d61f9347ed4"}, "ComponentArtifact WIT package pin differs")
    require(artifact["interface_entity_kind"] == "interface" and artifact["interface_diagnostic_shape"] == "instance(exact-wasi-0.2.12;host-mapping=none)", "ComponentArtifact interface diagnostics differ")
    require(exact_int(artifact["adapter_ordinal"], "component_artifact.adapter_ordinal") == 0 and artifact["adapter_revision"] == adapter["manifest_revision"], "ComponentArtifact adapter identity differs")
    require(artifact["signer_policy_kind"] == "development-image-pin" and artifact["signer_policy_digest"] == "sha256(exact-policy-file-bytes)", "ComponentArtifact signer-policy contract differs")
    require(artifact["instance_limits"] == {"memory_bytes": 1_048_576, "total_fuel": 100_000, "poll_quantum": 100, "resources": 16}, "ComponentArtifact instance limits differ")
    require(exact_bool(artifact["runtime_ready"], "component_artifact.runtime_ready") is False, "ComponentArtifact became runtime-ready")

    admission = value["admission"]
    require(admission["feature"] == "preview1-wrapped-admission" and admission["default_enabled"] is False, "admission feature boundary differs")
    require(admission["input_kind"] == "ComponentArtifactV1", "raw Component became an admission input")
    require(admission["validation_only_candidate"] is True, "candidate is not validation-only")
    require(admission["host_mappings"] == [], "host mappings must remain empty")
    for field in ("ambient_lookup", "raw_durable_ids", "no_grant_direct_move", "guest_calls"):
        require(exact_int(admission[field], f"admission.{field}") == 0, f"admission.{field} must remain zero")
    for field in ("raw_wasip1_admission", "guest_execution", "runtime_ready", "profile_runtime_ready", "guest_transformer", "kernel_transformer", "preopens", "filesystem_authority", "environment_authority", "process_authority", "socket_authority", "thread_authority", "selected_wasi_0_3_mapping", "aot", "jit"):
        require(exact_bool(admission[field], f"admission.{field}") is False, f"admission.{field} must remain false")


def load_policy_bytes(raw: bytes, path: Path = DEFAULT_POLICY, *, frozen: bool = True) -> Policy:
    require(0 < len(raw) <= MAX_POLICY_BYTES, "policy size is outside the bound")
    value = _reviewed_json(raw, "C8.1 policy")
    require(type(value) is dict, "C8.1 policy root is not an object")
    validate_policy_value(value, require_frozen_digest=frozen)
    return Policy(path, raw, value)


def read_bounded(path: Path, maximum: int, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as error:
        raise VerificationError(f"cannot read {label} {path}: {error}") from error
    require(len(data) <= maximum, f"{label} exceeds its byte bound")
    return data


def load_policy(path: Path) -> Policy:
    return load_policy_bytes(read_bounded(path, MAX_POLICY_BYTES, "policy"), path)


def verify_blob(data: bytes, record: Mapping[str, Any], label: str) -> None:
    require(len(data) == exact_int(record["byte_len"], f"{label}.byte_len", 1), f"{label} byte length differs")
    require(sha256(data).hex() == exact_hex(record["sha256"], f"{label}.sha256"), f"{label} SHA-256 differs")


def encode_uleb(value: int) -> bytes:
    require(type(value) is int and value >= 0, "cannot encode negative ULEB")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


class Cursor:
    def __init__(self, data: bytes, label: str) -> None:
        self.data = data
        self.label = label
        self.offset = 0

    def take(self, count: int) -> bytes:
        require(type(count) is int and count >= 0, f"{self.label} requested a negative length")
        end = self.offset + count
        require(end <= len(self.data), f"{self.label} is truncated")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def u8(self) -> int:
        return self.take(1)[0]

    def uleb(self, bits: int = 32) -> int:
        start = self.offset
        result = 0
        shift = 0
        maximum_bytes = (bits + 6) // 7
        for _ in range(maximum_bytes):
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                require(result < (1 << bits), f"{self.label} ULEB overflows u{bits}")
                require(self.data[start:self.offset] == encode_uleb(result), f"{self.label} has noncanonical ULEB")
                return result
            shift += 7
        raise VerificationError(f"{self.label} ULEB is too long")

    def name(self, maximum: int = 1024) -> str:
        raw = self.take(self.uleb())
        require(0 < len(raw) <= maximum and b"\0" not in raw, f"{self.label} name is invalid")
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError(f"{self.label} name is not UTF-8") from error
        require(value.encode("utf-8") == raw, f"{self.label} name is not byte canonical")
        return value

    def vector_count(self) -> int:
        count = self.uleb()
        require(count <= MAX_VECTOR_ITEMS, f"{self.label} vector exceeds the bound")
        return count

    def finish(self) -> None:
        require(self.offset == len(self.data), f"{self.label} has trailing bytes")


@dataclass(frozen=True)
class Section:
    ordinal: int
    section_id: int
    start: int
    payload_start: int
    end: int
    payload: bytes


def split_sections(data: bytes, header: bytes, label: str) -> tuple[Section, ...]:
    require(8 <= len(data) <= MAX_WASM_BYTES, f"{label} size is outside the bound")
    require(data[:8] == header, f"{label} magic/version differs")
    cursor = Cursor(data[8:], label)
    sections: list[Section] = []
    while cursor.offset < len(cursor.data):
        require(len(sections) < MAX_SECTIONS, f"{label} has too many sections")
        relative_start = cursor.offset
        section_id = cursor.u8()
        require(section_id <= 13, f"{label} has unknown section id {section_id}")
        length = cursor.uleb()
        relative_payload = cursor.offset
        payload = cursor.take(length)
        sections.append(Section(len(sections), section_id, 8 + relative_start, 8 + relative_payload, 8 + cursor.offset, payload))
    cursor.finish()
    return tuple(sections)


def _valtype(byte: int) -> str:
    values = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64", 0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}
    require(byte in values, f"Core function uses unsupported value type 0x{byte:02x}")
    return values[byte]


def _core_limits(cursor: Cursor) -> tuple[int, int | None]:
    flags = cursor.uleb()
    require(flags in (0, 1), "Core memory uses memory64/shared/custom-page features")
    initial = cursor.uleb()
    maximum = cursor.uleb() if flags & 1 else None
    require(initial == 1 and maximum == 16, "Core memory must be exactly min=1 max=16 pages")
    return initial, maximum


@dataclass(frozen=True)
class CoreObservation:
    imports: tuple[tuple[str, str, str, tuple[str, ...], tuple[str, ...]], ...]
    exports: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...]


def inspect_core(core: bytes, record: Mapping[str, Any]) -> CoreObservation:
    verify_blob(core, record, "guest_core")
    sections = split_sections(core, CORE_HEADER, "guest Core module")
    last_noncustom = 0
    seen: set[int] = set()
    by_id: dict[int, bytes] = {}
    for section in sections:
        if section.section_id == 0:
            custom = Cursor(section.payload, "Core custom section")
            custom.name()
            continue
        require(section.section_id <= 12, f"guest Core module has unsupported section {section.section_id}")
        require(section.section_id > last_noncustom and section.section_id not in seen, "Core sections are duplicated or out of order")
        last_noncustom = section.section_id
        seen.add(section.section_id)
        by_id[section.section_id] = section.payload
    require(8 not in by_id, "guest Core module contains a Core start section")

    types: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    if 1 in by_id:
        cursor = Cursor(by_id[1], "Core type section")
        for _ in range(cursor.vector_count()):
            require(cursor.u8() == 0x60, "Core type is not an exact function type")
            params = tuple(_valtype(cursor.u8()) for _ in range(cursor.vector_count()))
            results = tuple(_valtype(cursor.u8()) for _ in range(cursor.vector_count()))
            require(len(params) <= 32 and len(results) <= 32, "Core function signature exceeds C8.1")
            types.append((params, results))
        cursor.finish()

    imports: list[tuple[str, str, str, tuple[str, ...], tuple[str, ...]]] = []
    function_types: list[int] = []
    if 2 in by_id:
        cursor = Cursor(by_id[2], "Core import section")
        for _ in range(cursor.vector_count()):
            module = cursor.name()
            name = cursor.name()
            kind = cursor.u8()
            require(kind == 0, "guest Core import is not a function")
            type_index = cursor.uleb()
            require(type_index < len(types), "guest Core import type index is invalid")
            params, results = types[type_index]
            imports.append((module, name, "func", params, results))
            function_types.append(type_index)
        cursor.finish()

    if 3 in by_id:
        cursor = Cursor(by_id[3], "Core function section")
        for _ in range(cursor.vector_count()):
            type_index = cursor.uleb()
            require(type_index < len(types), "defined Core function type index is invalid")
            function_types.append(type_index)
        cursor.finish()

    memory_count = 0
    if 5 in by_id:
        cursor = Cursor(by_id[5], "Core memory section")
        memory_count = cursor.vector_count()
        for _ in range(memory_count):
            _core_limits(cursor)
        cursor.finish()
    require(memory_count == 1, "guest Core module must define exactly one memory")

    raw_exports: list[tuple[str, int, int]] = []
    if 7 in by_id:
        cursor = Cursor(by_id[7], "Core export section")
        for _ in range(cursor.vector_count()):
            raw_exports.append((cursor.name(), cursor.u8(), cursor.uleb()))
        cursor.finish()

    if 10 in by_id:
        cursor = Cursor(by_id[10], "Core code section")
        code_count = cursor.vector_count()
        for _ in range(code_count):
            cursor.take(cursor.uleb())
        cursor.finish()
        require(code_count == max(0, len(function_types) - len(imports)), "Core function/code counts differ")

    expected_imports = tuple(
        (entry["module"], entry["name"], entry["kind"], tuple(entry["params"]), tuple(entry["results"]))
        for entry in record["imports"]
    )
    require(tuple(imports) == expected_imports, "guest Core imports differ from the unique fd_write pin")

    exports: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = []
    for name, kind, index in raw_exports:
        if kind == 0:
            require(index < len(function_types), "Core function export index is invalid")
            params, results = types[function_types[index]]
            exports.append((name, "func", params, results))
        elif kind == 2:
            require(index < memory_count, "Core memory export index is invalid")
            exports.append((name, "memory", (), ()))
        else:
            raise VerificationError("guest Core module has an extra non-function/non-memory export")
    expected_exports = tuple(
        (entry["name"], entry["kind"], tuple(entry.get("params", [])), tuple(entry.get("results", [])))
        for entry in record["exports"]
    )
    require(tuple(exports) == expected_exports, "guest Core memory/_start exports differ")
    require(any(name == "memory" and kind == 2 and index == 0 for name, kind, index in raw_exports), "guest Core memory export is not memory zero")
    require(len(imports) == 1 and imports[0][:3] == ("wasi_snapshot_preview1", "fd_write", "func"), "guest Core has an extra or renamed import")
    return CoreObservation(tuple(imports), tuple(exports))


def _component_extern_name(cursor: Cursor) -> str:
    require(cursor.u8() == 0, "Component external name is not the canonical 0x00 form")
    return cursor.name()


def _component_kind(cursor: Cursor) -> str:
    first = cursor.u8()
    if first == 0:
        require(cursor.u8() == 0x11, "Component module kind prefix differs")
        return "module"
    kinds = {1: "func", 2: "value", 3: "type", 4: "component", 5: "instance"}
    require(first in kinds, f"Component external kind 0x{first:02x} is invalid")
    return kinds[first]


def _component_type_ref(cursor: Cursor) -> str:
    kind = _component_kind(cursor)
    if kind in ("module", "func", "instance", "component"):
        cursor.uleb()
    elif kind == "value":
        byte = cursor.u8()
        if byte & 0x80 == 0:
            require(byte in (0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x7A, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73), "Component value type is invalid")
        else:
            raise VerificationError("Component value type index is not supported by the independent boundary parser")
    else:
        bound = cursor.u8()
        require(bound in (0, 1), "Component type bound is invalid")
        if bound == 0:
            cursor.uleb()
    return kind


def _canonical_options(cursor: Cursor) -> tuple[str, ...]:
    options: list[str] = []
    for _ in range(cursor.vector_count()):
        opcode = cursor.u8()
        if opcode == 0:
            option = "UTF8"
        elif opcode == 3:
            option = f"Memory({cursor.uleb()})"
        elif opcode == 4:
            option = f"Realloc({cursor.uleb()})"
        elif opcode == 5:
            option = f"PostReturn({cursor.uleb()})"
        else:
            raise VerificationError(f"canonical option 0x{opcode:02x} is outside C8.1")
        require(not any(previous.split("(", 1)[0] == option.split("(", 1)[0] for previous in options), "canonical options repeat a kind")
        options.append(option)
    require(len(options) <= 8, "canonical options exceed the profile bound")
    return tuple(options)


def _debug_options(options: Sequence[str]) -> str:
    return "[" + ", ".join(options) + "]"


@dataclass(frozen=True)
class ComponentObservation:
    sections: tuple[Section, ...]
    modules: tuple[bytes, ...]
    imports: tuple[str, ...]
    exports: tuple[str, ...]
    entity_pins: tuple[tuple[str, str, str, int, str], ...]
    canonical_kinds: tuple[str, ...]
    lower_fingerprint: bytes
    nested_components: int


def _count_nested(component: bytes, depth: int = 1) -> int:
    require(depth <= 16, "nested Component depth exceeds C8.1")
    sections = split_sections(component, COMPONENT_HEADER, "nested Component")
    total = 1
    for section in sections:
        if section.section_id == 4:
            total += _count_nested(section.payload, depth + 1)
    return total


def inspect_component(component: bytes, record: Mapping[str, Any], guest_core: bytes) -> ComponentObservation:
    verify_blob(component, record, "component")
    sections = split_sections(component, COMPONENT_HEADER, "wrapped Component")
    require(len(sections) == exact_int(record["top_level_section_count"], "component.top_level_section_count"), "Component top-level section count differs")
    observed_ids = Counter(SECTION_NAMES.get(section.section_id, f"unknown-{section.section_id}") for section in sections)
    expected_ids = Counter(record["top_level_section_occurrences"])
    require(observed_ids == expected_ids, f"Component section-id counts differ: {dict(observed_ids)}")

    modules = tuple(section.payload for section in sections if section.section_id == 1)
    pins = record["embedded_core_modules"]
    require(len(modules) == len(pins) == 4, "Component does not contain exactly four Core module payloads")
    for ordinal, (module, pin) in enumerate(zip(modules, pins)):
        require(pin["ordinal"] == ordinal, "Core module policy ordinal differs")
        verify_blob(module, pin, f"component.module[{ordinal}]")
        split_sections(module, CORE_HEADER, f"component.module[{ordinal}]")
    require(modules[0] == guest_core, "Component guest Core payload is not the exact raw guest bytes")

    imports: list[str] = []
    exports: list[str] = []
    entity_pins: list[tuple[str, str, str, int, str]] = []
    canonical_kinds: list[str] = []
    canonical_policy = record["canonical_entries"]
    lower_hasher = hashlib.sha256()
    lower_hasher.update(canonical_policy["lower_fingerprint_domain"].encode("utf-8"))
    canonical_ordinal = 0
    nested_total = 0
    nested_ordinals: list[int] = []
    entry_counts: Counter[str] = Counter()
    for section in sections:
        if section.section_id == 10:
            cursor = Cursor(section.payload, f"Component import section {section.ordinal}")
            count = cursor.vector_count()
            entry_counts["import"] += count
            for _ in range(count):
                entry_start = cursor.offset
                name = _component_extern_name(cursor)
                kind = _component_type_ref(cursor)
                require(kind == "instance", f"top-level import {name!r} is not an instance")
                imports.append(name)
                raw = section.payload[entry_start:cursor.offset]
                entity_pins.append(("import", kind, name, len(raw), sha256(raw).hex()))
            cursor.finish()
        elif section.section_id == 11:
            cursor = Cursor(section.payload, f"Component export section {section.ordinal}")
            count = cursor.vector_count()
            entry_counts["export"] += count
            for _ in range(count):
                entry_start = cursor.offset
                name = _component_extern_name(cursor)
                kind = _component_kind(cursor)
                cursor.uleb()
                has_type = cursor.u8()
                require(has_type in (0, 1), "Component export optional type tag is invalid")
                if has_type:
                    require(_component_type_ref(cursor) == kind, "Component export ascribed type kind differs")
                require(kind == "instance", f"top-level export {name!r} is not an instance")
                exports.append(name)
                raw = section.payload[entry_start:cursor.offset]
                entity_pins.append(("export", kind, name, len(raw), sha256(raw).hex()))
            cursor.finish()
        elif section.section_id == 8:
            cursor = Cursor(section.payload, f"canonical section {section.ordinal}")
            count = cursor.vector_count()
            entry_counts["canonical"] += count
            for _ in range(count):
                entry_start = cursor.offset
                opcode = cursor.u8()
                if opcode == 0:
                    require(cursor.u8() == 0, "canonical lift subopcode differs")
                    cursor.uleb()
                    _canonical_options(cursor)
                    cursor.uleb()
                    canonical_kinds.append("lift")
                elif opcode == 1:
                    require(cursor.u8() == 0, "canonical lower subopcode differs")
                    func_index = cursor.uleb()
                    options = _canonical_options(cursor)
                    canonical_kinds.append("lower")
                elif opcode == 3:
                    cursor.uleb()
                    canonical_kinds.append("resource_drop")
                else:
                    raise VerificationError(f"canonical entry 0x{opcode:02x} is outside the exact C8.1 topology")
                if opcode == 1:
                    raw = section.payload[entry_start:cursor.offset]
                    lower_hasher.update(struct.pack("<Q", len(raw)))
                    lower_hasher.update(raw)
                canonical_ordinal += 1
            cursor.finish()
        elif section.section_id == 4:
            nested_ordinals.append(section.ordinal)
            nested_total += _count_nested(section.payload)
        elif section.section_id == 0:
            cursor = Cursor(section.payload, f"Component custom section {section.ordinal}")
            cursor.name()
        elif section.section_id in (2, 3, 5, 6, 7):
            cursor = Cursor(section.payload, f"Component vector section {section.ordinal}")
            count = cursor.vector_count()
            if section.section_id in (2, 5, 6, 7):
                entry_counts[SECTION_NAMES[section.section_id]] += count
        elif section.section_id == 9:
            raise VerificationError("wrapped Component unexpectedly has a start section")

    require(tuple(imports) == tuple(record["imports"]), "Component top-level imports or versions differ")
    require(tuple(exports) == tuple(record["exports"]), "Component top-level exports or versions differ")
    entity_pins.sort(key=lambda item: ((0 if item[0] == "import" else 1), item[1], item[2]))
    expected_pins = tuple((pin["direction"], pin["kind"], pin["name"], pin["raw_byte_len"], pin["raw_entry_sha256"]) for pin in record["top_level_entity_pins"])
    require(tuple(entity_pins) == expected_pins, "Component top-level raw entry pins differ")
    require(entry_counts == Counter(record["top_level_entry_counts"]), f"Component top-level entry counts differ: {dict(entry_counts)}")
    canonical = canonical_policy
    observed_canonical = Counter(canonical_kinds)
    require(len(canonical_kinds) == canonical["total"] and observed_canonical == Counter({"resource_drop": canonical["resource_drop"], "lower": canonical["lower"], "lift": canonical["lift"]}), "canonical entry count/topology differs")
    lower_hash = lower_hasher.digest()
    require(lower_hash.hex() == canonical["lower_fingerprint_sha256"], "canonical lower fingerprint differs")
    require(nested_total == record["nested_components"], "nested Component count differs")
    require([ordinal + 1 for ordinal in nested_ordinals] == [record["nested_component_top_level_section_ordinal"]], "nested Component top-level ordinal differs")
    return ComponentObservation(sections, modules, tuple(imports), tuple(exports), tuple(entity_pins), tuple(canonical_kinds), lower_hash, nested_total)


def _load_c71() -> Any:
    path = Path(__file__).with_name("verify-c71-component-artifact.py")
    spec = importlib.util.spec_from_file_location("vibeos_c81_independent_c71", path)
    require(spec is not None and spec.loader is not None, "cannot load independent C7.1 parser")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.PROFILES[4] = module.Profile(
        code=4,
        stage=2,
        artifact_abi=4,
        component_profile=1,
        core_profile=1,
        runtime_abi=4,
        canonical_features=7,
        revisions=(
            "webassembly-core-2.0-integer-v1",
            "wasmparser-component-model-0.255.0",
            "component-model-0.255.0-sync",
            "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380",
            "wasi-v0.2.12",
        ),
    )
    return module


C71 = _load_c71()


def verify_component_artifact(artifact_bytes: bytes, policy: Policy, component: bytes, adapter: bytes, wit_source: bytes, observation: ComponentObservation) -> Any:
    try:
        artifact = C71.verify_artifact(artifact_bytes)
    except (C71.VerificationError, struct.error, UnicodeDecodeError) as error:
        raise VerificationError(f"ComponentArtifact is not canonical: {error}") from error
    require(artifact.profile.code == 4 and artifact.profile.stage == 2 and not artifact.runtime_ready, "ComponentArtifact is not inert profile code 4")
    artifact_policy = policy.value["component_artifact"]
    require(artifact.signer_kind == 1, "ComponentArtifact signer policy is not the development image pin")
    require(artifact.signer_policy_digest == sha256(policy.raw), "ComponentArtifact policy digest differs")
    require(artifact.instance_limits == tuple(artifact_policy["instance_limits"].values()), "ComponentArtifact instance limits differ")
    require(artifact.component == component, "ComponentArtifact does not contain the exact wrapped Component")
    expected_modules = tuple(
        C71.CoreModule(len(raw), C71.role_hash(C71.CORE_MODULE_HASH_DOMAIN, raw))
        for raw in observation.modules
    )
    require(artifact.manifest.core_modules == expected_modules, "ComponentArtifact manifest Core module topology differs")
    require(artifact.manifest.world == artifact_policy["world"], "ComponentArtifact manifest world differs")
    wit_policy = artifact_policy["wit_package"]
    require(sha256(wit_source).hex() == wit_policy["source_sha256"], "ComponentArtifact WIT source fixture digest differs")
    try:
        wit_text = wit_source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("ComponentArtifact WIT source is not UTF-8") from error
    require(artifact.manifest.wit_packages == (C71.WitPackage(wit_policy["name"], wit_policy["version"], wit_text),), "ComponentArtifact manifest WIT package differs")
    shape = artifact_policy["interface_diagnostic_shape"]
    expected_interfaces = [C71.Interface(1, 2, name, shape) for name in observation.imports]
    expected_interfaces += [C71.Interface(2, 2, name, shape) for name in observation.exports]
    expected_interfaces.sort(key=lambda entry: (entry.direction, entry.name, entry.kind, entry.diagnostic_shape))
    require(artifact.manifest.interfaces == tuple(expected_interfaces), "ComponentArtifact manifest interfaces differ")
    require(len(artifact.manifest.adapters) == 1, "ComponentArtifact manifest must contain one exact adapter")
    manifest_adapter = artifact.manifest.adapters[0]
    require(manifest_adapter.ordinal == artifact_policy["adapter_ordinal"] and manifest_adapter.revision == artifact_policy["adapter_revision"] and manifest_adapter.descriptor == adapter, "ComponentArtifact manifest adapter differs")
    require(not artifact.runtime_ready, "ComponentArtifact exposed runtime readiness")
    return artifact


def resolve_fixture(policy: Policy, override: Path | None, field: str, label: str) -> Path:
    if override is not None:
        return override
    name = exact_text(policy.value[field]["fixture"], f"{field}.fixture", 256)
    require(Path(name).name == name, f"{field}.fixture is not a local basename")
    path = policy.directory / name
    require(path.is_file(), f"{label} fixture does not exist: {path}")
    return path


def resolve_adapter(policy: Policy, override: Path | None) -> Path:
    if override is not None:
        return override
    name = exact_text(policy.value["adapter"]["asset"], "adapter.asset", 256)
    require(Path(name).name == name, "adapter.asset is not a local basename")
    path = policy.directory / name
    if path.is_file():
        return path
    require(name == "wasi_snapshot_preview1.command.wasm", "adapter local alias is not selected")
    return policy.directory / "c81-wasmtime-v48.0.0-preview1-command-adapter.wasm"


def resolve_artifact(policy: Policy, override: Path | None) -> Path:
    if override is not None:
        return override
    name = exact_text(policy.value["component_artifact"]["fixture"], "component_artifact.fixture", 256)
    require(Path(name).name == name, "component_artifact.fixture is not a local basename")
    return policy.directory / name


def verify_fixture(policy: Policy, adapter_path: Path | None, core_path: Path | None, component_path: Path | None, artifact_path: Path | None) -> dict[str, Any]:
    adapter_file = resolve_adapter(policy, adapter_path)
    core_file = resolve_fixture(policy, core_path, "guest_core", "guest Core")
    component_file = resolve_fixture(policy, component_path, "component", "Component")
    artifact_file = resolve_artifact(policy, artifact_path)
    wit_name = exact_text(policy.value["component_artifact"]["wit_package"]["source_fixture"], "component_artifact.wit_package.source_fixture", 256)
    require(Path(wit_name).name == wit_name, "WIT source fixture is not a local basename")
    wit_file = policy.directory / wit_name
    adapter = read_bounded(adapter_file, MAX_WASM_BYTES, "adapter")
    core = read_bounded(core_file, MAX_WASM_BYTES, "guest Core")
    component = read_bounded(component_file, MAX_WASM_BYTES, "wrapped Component")
    wit_source = read_bounded(wit_file, 256 * 1024, "ComponentArtifact WIT source")
    artifact_bytes = read_bounded(artifact_file, C71.MAX_ENCODED_BYTES, "ComponentArtifact")
    verify_blob(adapter, policy.value["adapter"], "adapter")
    inspect_core(core, policy.value["guest_core"])
    observation = inspect_component(component, policy.value["component"], core)
    verify_component_artifact(artifact_bytes, policy, component, adapter, wit_source, observation)
    return success_report(policy, observation, selftest_mutations=0)


def expect_rejected(action: Callable[[], Any], label: str) -> None:
    try:
        action()
    except (VerificationError, C71.VerificationError, ValueError, struct.error, UnicodeDecodeError):
        return
    raise VerificationError(f"mutation unexpectedly accepted: {label}")


def wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + encode_uleb(len(payload)) + payload


def wasm_name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return encode_uleb(len(raw)) + raw


def build_core(*, module: str = "wasi_snapshot_preview1", name: str = "fd_write", params: int = 4, core_start: bool = False, extra_import: bool = False) -> bytes:
    types = encode_uleb(2) + b"\x60" + encode_uleb(params) + b"\x7f" * params + b"\x01\x7f" + b"\x60\x00\x00"
    entry = wasm_name(module) + wasm_name(name) + b"\x00\x00"
    import_count = 2 if extra_import else 1
    imports = encode_uleb(import_count) + entry * import_count
    functions = b"\x01\x01"
    memories = b"\x01\x01\x01\x10"
    start_index = import_count
    exports = b"\x02" + wasm_name("memory") + b"\x02\x00" + wasm_name("_start") + b"\x00" + encode_uleb(start_index)
    result = CORE_HEADER + wasm_section(1, types) + wasm_section(2, imports) + wasm_section(3, functions) + wasm_section(5, memories) + wasm_section(7, exports)
    if core_start:
        result += wasm_section(8, encode_uleb(start_index))
    return result + wasm_section(10, b"\x01\x02\x00\x0b")


def rebound_blob(record: Mapping[str, Any], data: bytes) -> dict[str, Any]:
    result = copy.deepcopy(record)
    result["byte_len"] = len(data)
    result["sha256"] = sha256(data).hex()
    return result


def component_import(name: str) -> bytes:
    return encode_uleb(1) + b"\x00" + wasm_name(name) + b"\x05\x00"


def component_export(name: str) -> bytes:
    return encode_uleb(1) + b"\x00" + wasm_name(name) + b"\x05\x00\x00"


def canonical_entry(kind: str, index: int) -> bytes:
    if kind == "resource_drop":
        raw = b"\x03" + encode_uleb(index)
    elif kind == "lower":
        raw = b"\x01\x00" + encode_uleb(index) + b"\x01\x00"
    elif kind == "lift":
        raw = b"\x00\x00\x00\x01\x00\x00"
    else:
        raise AssertionError(kind)
    return encode_uleb(1) + raw


def build_component(core: bytes, record: Mapping[str, Any]) -> tuple[bytes, list[bytes]]:
    modules = [core, CORE_HEADER, CORE_HEADER + wasm_section(0, wasm_name("m2")), CORE_HEADER + wasm_section(0, wasm_name("m3"))]
    sections: list[bytes] = []
    sections += [wasm_section(0, wasm_name("c0")), wasm_section(0, wasm_name("c1"))]
    sections += [wasm_section(1, module) for module in modules]
    sections += [wasm_section(2, encode_uleb(2 if index < 3 else 1)) for index in range(12)]
    sections += [wasm_section(5, b"\x01")]
    sections += [wasm_section(6, encode_uleb(2 if index < 12 else 1)) for index in range(30)]
    sections += [wasm_section(7, encode_uleb(2 if index == 0 else 1)) for index in range(9)]
    kinds = ["resource_drop"] * 4 + ["lower"] * 13 + ["lift"]
    sections += [wasm_section(8, canonical_entry(kind, index)) for index, kind in enumerate(kinds)]
    sections += [wasm_section(10, component_import(name)) for name in record["imports"]]
    sections += [wasm_section(11, component_export(record["exports"][0]))]
    require(len(sections) == 85, "synthetic Component section seed differs")
    sections.insert(record["nested_component_top_level_section_ordinal"] - 1, wasm_section(4, COMPONENT_HEADER))
    return COMPONENT_HEADER + b"".join(sections), modules


def synthetic_policy(base: Policy) -> tuple[Policy, bytes, bytes, bytes, ComponentObservation]:
    value = copy.deepcopy(base.value)
    adapter = b"synthetic-reviewed-preview1-adapter"
    core = build_core()
    value["adapter"]["byte_len"] = len(adapter)
    value["adapter"]["sha256"] = sha256(adapter).hex()
    value["guest_core"] = rebound_blob(value["guest_core"], core)
    value["component"]["embedded_core_modules"][0] = {"ordinal": 0, "byte_len": len(core), "sha256": sha256(core).hex()}
    component, modules = build_component(core, value["component"])
    for ordinal, module in enumerate(modules):
        value["component"]["embedded_core_modules"][ordinal] = {"ordinal": ordinal, "byte_len": len(module), "sha256": sha256(module).hex()}
    value["component"]["byte_len"] = len(component)
    value["component"]["sha256"] = sha256(component).hex()
    pins: list[dict[str, Any]] = []
    for direction, names, encoder in (
        ("import", value["component"]["imports"], component_import),
        ("export", value["component"]["exports"], component_export),
    ):
        for name in names:
            payload = encoder(name)
            raw = payload[len(encode_uleb(1)):]
            pins.append({"direction": direction, "kind": "instance", "name": name, "raw_byte_len": len(raw), "raw_entry_sha256": sha256(raw).hex()})
    pins.sort(key=lambda pin: ((0 if pin["direction"] == "import" else 1), pin["kind"], pin["name"]))
    value["component"]["top_level_entity_pins"] = pins
    lower_hasher = hashlib.sha256()
    lower_hasher.update(value["component"]["canonical_entries"]["lower_fingerprint_domain"].encode("utf-8"))
    for ordinal in range(4, 17):
        payload = canonical_entry("lower", ordinal)
        raw = payload[len(encode_uleb(1)):]
        lower_hasher.update(struct.pack("<Q", len(raw)))
        lower_hasher.update(raw)
    value["component"]["canonical_entries"]["lower_fingerprint_sha256"] = lower_hasher.hexdigest()
    value["component_artifact"]["wit_package"]["source_sha256"] = sha256(SYNTHETIC_WIT).hex()
    raw = canonical_json(value)
    policy = Policy(base.path, raw, value)
    observation = inspect_component(component, value["component"], core)
    return policy, adapter, core, component, observation


SYNTHETIC_WIT = b"package test:c81@1.0.0;\nworld selftest {}\n"


def synthetic_artifact(policy: Policy, adapter: bytes, component: bytes, observation: ComponentObservation) -> bytes:
    artifact_policy = policy.value["component_artifact"]
    shape = artifact_policy["interface_diagnostic_shape"]
    interfaces = [C71.Interface(1, 2, name, shape) for name in observation.imports]
    interfaces += [C71.Interface(2, 2, name, shape) for name in observation.exports]
    interfaces.sort(key=lambda entry: (entry.direction, entry.name, entry.kind, entry.diagnostic_shape))
    manifest = C71.Manifest(
        world=artifact_policy["world"],
        wit_packages=(C71.WitPackage(artifact_policy["wit_package"]["name"], artifact_policy["wit_package"]["version"], SYNTHETIC_WIT.decode("utf-8")),),
        interfaces=tuple(interfaces),
        core_modules=tuple(C71.CoreModule(len(raw), C71.role_hash(C71.CORE_MODULE_HASH_DOMAIN, raw)) for raw in observation.modules),
        adapters=(C71.Adapter(artifact_policy["adapter_ordinal"], artifact_policy["adapter_revision"], adapter),),
    )
    artifact = C71.VerifiedArtifact(
        profile=C71.PROFILES[4],
        signer_kind=1,
        signer_policy_digest=sha256(policy.raw),
        instance_limits=(artifact_policy["instance_limits"]["memory_bytes"], artifact_policy["instance_limits"]["total_fuel"], artifact_policy["instance_limits"]["poll_quantum"], artifact_policy["instance_limits"]["resources"]),
        manifest=manifest,
        component=component,
        commitment=bytes(32),
    )
    return C71.encode_artifact(artifact)


def rebind_component_policy(policy: Policy, component: bytes) -> Policy:
    value = copy.deepcopy(policy.value)
    value["component"]["byte_len"] = len(component)
    value["component"]["sha256"] = sha256(component).hex()
    return Policy(policy.path, policy.raw, value)


def replace_encoded_section(component: bytes, section: Section, replacement: bytes) -> bytes:
    return component[:section.start] + replacement + component[section.end:]


def run_selftest(base: Policy) -> int:
    mutations = 0

    def reject(action: Callable[[], Any], label: str) -> None:
        nonlocal mutations
        expect_rejected(action, label)
        mutations += 1

    duplicate = b'{"schema":"duplicate",' + base.raw.lstrip()[1:]
    reject(lambda: load_policy_bytes(duplicate), "policy-duplicate-key")
    for label, path, replacement in (
        ("policy-boolean-type", ("admission", "runtime_ready"), 0),
        ("policy-integer-type", ("version",), True),
        ("policy-float", ("version",), 1.0),
        ("policy-hash", ("guest_core", "sha256"), "0" * 64),
    ):
        value = copy.deepcopy(base.value)
        target: Any = value
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = replacement
        reject(lambda raw=canonical_json(value): load_policy_bytes(raw), label)
    extra = copy.deepcopy(base.value)
    extra["admission"]["unexpected"] = False
    reject(lambda: load_policy_bytes(canonical_json(extra)), "policy-field-set")

    good_core = build_core()
    core_record = rebound_blob(base.value["guest_core"], good_core)
    inspect_core(good_core, core_record)
    for label, changed in (
        ("core-import-module", build_core(module="ambient")),
        ("core-import-name", build_core(name="path_open")),
        ("core-signature", build_core(params=3)),
        ("core-start", build_core(core_start=True)),
        ("core-extra-import", build_core(extra_import=True)),
    ):
        reject(lambda changed=changed: inspect_core(changed, rebound_blob(core_record, changed)), label)
    reject(lambda: inspect_core(good_core + b"\0", core_record), "core-exact-hash")

    adapter = b"synthetic-adapter"
    adapter_record = rebound_blob(base.value["adapter"], adapter)
    verify_blob(adapter, adapter_record, "adapter")
    reject(lambda: verify_blob(adapter + b"x", adapter_record, "adapter"), "adapter-length-hash")
    bad_adapter_pin = dict(adapter_record)
    bad_adapter_pin["sha256"] = "1" * 64
    reject(lambda: verify_blob(adapter, bad_adapter_pin, "adapter"), "adapter-policy-hash")

    policy, adapter, core, component, observation = synthetic_policy(base)
    inspect_core(core, policy.value["guest_core"])
    inspect_component(component, policy.value["component"], core)
    sections = observation.sections
    modules = [section for section in sections if section.section_id == 1]
    swapped = bytearray(component)
    first = component[modules[0].start:modules[0].end]
    second = component[modules[1].start:modules[1].end]
    swapped = component[:modules[0].start] + second + component[modules[0].end:modules[1].start] + first + component[modules[1].end:]
    reject(lambda: inspect_component(swapped, rebind_component_policy(policy, swapped).value["component"], core), "component-module-order")
    removed = component[:sections[0].start] + component[sections[0].end:]
    reject(lambda: inspect_component(removed, rebind_component_policy(policy, removed).value["component"], core), "component-section-count")
    first_import = next(section for section in sections if section.section_id == 10)
    changed_import_payload = first_import.payload.replace(b"wasi:io/error@0.2.12", b"wasi:io/other@0.2.12")
    changed_import = replace_encoded_section(component, first_import, wasm_section(10, changed_import_payload))
    reject(lambda: inspect_component(changed_import, rebind_component_policy(policy, changed_import).value["component"], core), "component-import-name")
    version_payload = first_import.payload.replace(b"0.2.12", b"0.2.13")
    changed_version = replace_encoded_section(component, first_import, wasm_section(10, version_payload))
    reject(lambda: inspect_component(changed_version, rebind_component_policy(policy, changed_version).value["component"], core), "component-import-version")
    nested = next(section for section in sections if section.section_id == 4)
    no_nested = replace_encoded_section(component, nested, wasm_section(0, wasm_name("not-nested")))
    reject(lambda: inspect_component(no_nested, rebind_component_policy(policy, no_nested).value["component"], core), "component-nested")
    canonical = next(section for section in sections if section.section_id == 8 and section.payload[1] == 1)
    bad_canonical_payload = bytes([canonical.payload[0], 2]) + canonical.payload[2:]
    bad_canonical = replace_encoded_section(component, canonical, wasm_section(8, bad_canonical_payload))
    reject(lambda: inspect_component(bad_canonical, rebind_component_policy(policy, bad_canonical).value["component"], core), "component-canonical")
    noncanonical = bytearray(component)
    target = next(section for section in sections if section.end - section.payload_start == 1)
    length_offset = target.start + 1
    noncanonical[length_offset:length_offset + 1] = b"\x81\x00"
    noncanonical_bytes = bytes(noncanonical)
    reject(lambda: inspect_component(noncanonical_bytes, rebind_component_policy(policy, noncanonical_bytes).value["component"], core), "component-noncanonical-uleb")
    reject(lambda: inspect_component(component + b"\0", policy.value["component"], core), "component-whole-hash")

    artifact = synthetic_artifact(policy, adapter, component, observation)
    parsed = verify_component_artifact(artifact, policy, component, adapter, SYNTHETIC_WIT, observation)
    require(parsed.profile.code == 4 and not parsed.runtime_ready, "synthetic code-4 artifact is not inert")
    reject(lambda: verify_component_artifact(C71.recommit(C71.mutate_u16(artifact, 22, 3)), policy, component, adapter, SYNTHETIC_WIT, observation), "artifact-profile-code")
    reject(lambda: verify_component_artifact(C71.recommit(C71.mutate_u16(artifact, 24, 1)), policy, component, adapter, SYNTHETIC_WIT, observation), "artifact-profile-stage")
    changed_digest = bytearray(artifact)
    changed_digest[232] ^= 1
    reject(lambda: verify_component_artifact(C71.recommit(bytes(changed_digest)), policy, component, adapter, SYNTHETIC_WIT, observation), "artifact-policy-digest")
    layout = C71.fixture_layout(artifact)
    manifest_mutation = bytearray(artifact)
    manifest_mutation[layout.module_records[0] + 8] ^= 1
    reject(lambda: verify_component_artifact(C71.reseal(bytes(manifest_mutation)), policy, component, adapter, SYNTHETIC_WIT, observation), "artifact-manifest-module")
    component_start = C71.HEADER_LEN + C71.read_u64(artifact, 48) + C71.read_u64(artifact, 56)
    whole_component = bytearray(artifact)
    whole_component[component_start] ^= 1
    reject(lambda: verify_component_artifact(C71.reseal(bytes(whole_component)), policy, component, adapter, SYNTHETIC_WIT, observation), "artifact-whole-component")
    noncanonical_artifact = bytearray(artifact)
    noncanonical_artifact[296] = 1
    reject(lambda: verify_component_artifact(C71.recommit(bytes(noncanonical_artifact)), policy, component, adapter, SYNTHETIC_WIT, observation), "artifact-noncanonical")
    return mutations


def success_report(policy: Policy, observation: ComponentObservation | None, *, selftest_mutations: int) -> dict[str, Any]:
    admission = policy.value["admission"]
    report: dict[str, Any] = {
        "ambient_lookup": admission["ambient_lookup"],
        "component_artifact_required": True,
        "guest_calls": admission["guest_calls"],
        "guest_execution": admission["guest_execution"],
        "host_mappings": len(admission["host_mappings"]),
        "no_grant_direct_move": admission["no_grant_direct_move"],
        "off_device_only": policy.value["transformer"]["location"] == "off-device-host-only",
        "profile_runtime_ready": policy.value["profile"]["profile_runtime_ready"],
        "raw_durable_ids": admission["raw_durable_ids"],
        "raw_wasip1_admission": admission["raw_wasip1_admission"],
        "runtime_ready": admission["runtime_ready"],
        "status": "ok",
    }
    if observation is not None:
        report.update({"canonical_entries": len(observation.canonical_kinds), "embedded_core_modules": len(observation.modules), "nested_components": observation.nested_components, "top_level_sections": len(observation.sections)})
    if selftest_mutations:
        report["selftest_mutations"] = selftest_mutations
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="independently verify the inert C8.1 Preview1 wrapper")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--core", type=Path)
    parser.add_argument("--component", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--fixture", action="store_true")
    args = parser.parse_args()
    if not args.selftest and not args.fixture:
        parser.error("select --selftest and/or --fixture")
    try:
        policy = load_policy(args.policy)
        mutations = run_selftest(policy) if args.selftest else 0
        if args.fixture:
            report = verify_fixture(policy, args.adapter, args.core, args.component, args.artifact)
            if mutations:
                report["selftest_mutations"] = mutations
        else:
            report = success_report(policy, None, selftest_mutations=mutations)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    except (OSError, VerificationError, C71.VerificationError, ValueError, struct.error, UnicodeDecodeError) as error:
        print(f"FAIL verify-c81-preview1-wrapped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
