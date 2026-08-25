#!/usr/bin/env python3
"""Independent, host-only verifier for the frozen C8.2 Preview1 corpus.

Only Python's standard library and the independently maintained C7.1 CMP1
parser are used.  This verifier parses bytes but never instantiates a guest,
links a host import, searches for an adapter, or grants execution authority.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "policy/image/artifacts/c82-preview1-corpus-policy.json"
RAW_POLICY_SHA256 = "5e002e1369c92253296e25abaf58f765e19b644196d125d5ea46aab783997158"
POLICY_SEMANTIC_SHA256 = "4e9725cef46f24dc854ceda9dbf518a856f0af9188646d6a78fb50eb99bc8662"

CORE_HEADER = b"\0asm\x01\0\0\0"
COMPONENT_HEADER = b"\0asm\x0d\0\x01\0"
MAX_POLICY_BYTES = 64 * 1024
MAX_SOURCE_BYTES = 64 * 1024
MAX_WIT_BYTES = 256 * 1024
MAX_WASM_BYTES = 1024 * 1024
MAX_SECTIONS = 4096
MAX_VECTOR_ITEMS = 4096
MAX_FUNCTION_BODY_BYTES = 128 * 1024
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

ARTIFACT_PINS = {
    "c82-rust-ascii-filter": {
        "byte_len": 81_203,
        "sha256": "a8a947c971be19b2b8383f78952ec6bc834fc38affd3c2ed9f6d51ccaa6a292b",
        "commitment": "6f94afb3bb90498cca67a3f3559b44e717fbafaaeaf2a78e26b18b593037aef0",
    },
    "c82-c-ascii-filter": {
        "byte_len": 81_430,
        "sha256": "4b95108669b360485c2447c054549f2d35f0451d2a2668ffb75581dd4a830078",
        "commitment": "386790cbef9aca7c8745c99acac8ae2c265da8502393dc949ab49cbd91fb554c",
    },
}

EXACT_IMPORTS = {
    "args_sizes_get": (("i32", "i32"), ("i32",)),
    "args_get": (("i32", "i32"), ("i32",)),
    "fd_read": (("i32", "i32", "i32", "i32"), ("i32",)),
    "fd_write": (("i32", "i32", "i32", "i32"), ("i32",)),
    "proc_exit": (("i32",), ()),
}

EXPECTED_TOP_FIELDS = {
    "schema",
    "version",
    "profile",
    "toolchains",
    "transformer",
    "adapter",
    "guest_contract",
    "component_surface",
    "programs",
    "component_artifact",
    "invocation",
    "corpus",
    "admission",
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


def reviewed_json(raw: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(type(key) is str, f"{label} has a non-string object key")
            require(key not in result, f"{label} repeats JSON member {key!r}")
            result[key] = value
        return result

    def reject_number(token: str) -> Any:
        raise VerificationError(f"{label} contains unsupported JSON number {token}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not strict UTF-8 JSON: {error}") from error


def canonical_json_types(value: Any, path: tuple[str, ...] = ()) -> None:
    if type(value) is dict:
        for key, child in value.items():
            require(type(key) is str and key != "", f"{'.'.join(path)} has an invalid key")
            canonical_json_types(child, path + (key,))
    elif type(value) is list:
        for child in value:
            canonical_json_types(child, path + ("*",))
    elif type(value) is str:
        if path != ("component_surface", "canonical_lowering_domain"):
            require("\0" not in value, f"{'.'.join(path)} contains NUL")
    elif type(value) is int:
        require(0 <= value <= (1 << 63) - 1, f"{'.'.join(path)} integer is out of range")
    elif type(value) is bool or value is None:
        return
    else:
        raise VerificationError(f"{'.'.join(path)} has a noncanonical JSON type")


def require_fields(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    require(type(value) is dict, f"{label} is not an object")
    require(set(value) == expected, f"{label} field set differs")
    return value


def exact_int(value: Any, label: str, minimum: int = 0) -> int:
    require(
        type(value) is int and minimum <= value <= (1 << 63) - 1,
        f"{label} is not an exact integer",
    )
    return value


def exact_bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} is not an exact boolean")
    return value


def exact_text(value: Any, label: str, maximum: int = 4096) -> str:
    require(
        type(value) is str
        and 0 < len(value.encode("utf-8")) <= maximum
        and "\0" not in value,
        f"{label} is not bounded text",
    )
    return value


def exact_hex(value: Any, label: str) -> str:
    require(
        type(value) is str
        and HEX32.fullmatch(value) is not None
        and value != "0" * 64,
        f"{label} is not a canonical nonzero SHA-256",
    )
    return value


@dataclass(frozen=True)
class Policy:
    path: Path
    raw: bytes
    value: dict[str, Any]

    @property
    def directory(self) -> Path:
        return self.path.parent


def validate_policy_value(value: dict[str, Any], *, frozen: bool) -> None:
    canonical_json_types(value)
    require_fields(value, EXPECTED_TOP_FIELDS, "policy")
    if frozen:
        require(
            sha256(canonical_json(value)).hex() == POLICY_SEMANTIC_SHA256,
            "policy canonical semantic content differs",
        )

    require(value["schema"] == "vibeos.c82.preview1-compatibility-corpus-policy", "policy schema differs")
    require(exact_int(value["version"], "version") == 1, "policy version differs")

    profile = require_fields(
        value["profile"],
        {
            "name", "code", "artifact_abi", "component_profile", "core_profile",
            "runtime_abi", "stage", "core_revision", "component_revision",
            "canonical_abi_revision", "wasm_tools_revision", "wasi_revision",
            "canonical_features", "runtime_ready", "profile_runtime_ready",
            "current_engine_identity",
        },
        "profile",
    )
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
        "current_engine_identity": False,
    }
    for field in ("runtime_ready", "profile_runtime_ready", "current_engine_identity"):
        exact_bool(profile[field], f"profile.{field}")
    require(profile == expected_profile, "profile identity or inert stage differs")

    toolchains = require_fields(value["toolchains"], {"rust", "c", "linker"}, "toolchains")
    require_fields(
        toolchains["rust"],
        {"channel", "release", "commit", "commit_date", "host", "target", "llvm", "rustc_sha256"},
        "toolchains.rust",
    )
    require_fields(
        toolchains["c"],
        {"release", "archive", "archive_sha256", "target", "clang", "llvm_commit", "clang_sha256"},
        "toolchains.c",
    )
    require_fields(
        toolchains["linker"],
        {"release", "llvm_commit", "wasm_ld_sha256"},
        "toolchains.linker",
    )
    for owner, field in (
        ("rust", "rustc_sha256"),
        ("c", "archive_sha256"),
        ("c", "clang_sha256"),
        ("linker", "wasm_ld_sha256"),
    ):
        exact_hex(toolchains[owner][field], f"toolchains.{owner}.{field}")

    transformer = require_fields(
        value["transformer"],
        {
            "location", "implementation", "sanitizer", "stack_pointer_value",
            "required_defined_globals_before", "required_global_references",
            "required_globals_after", "removed_section_bytes", "wit_component_version",
            "wit_component_crate_sha256", "reference_cli_version",
            "reference_cli_source_commit", "reference_cli_binary_sha256",
            "adapter_import_name", "validate_compiler_core", "validate_sanitized_core",
            "validate_component", "allow_disable_validation", "allow_import_rename",
            "ambient_adapter_lookup", "network_lookup",
        },
        "transformer",
    )
    require(transformer["location"] == "off-device-host-only", "transformer is not off-device-only")
    require(transformer["implementation"] == "tools/c82-preview1-corpus", "transformer implementation differs")
    require(transformer["sanitizer"] == "remove-proven-unreferenced-stack-pointer-global-section-v1", "sanitizer identity differs")
    require(
        (
            exact_int(transformer["stack_pointer_value"], "transformer.stack_pointer_value"),
            exact_int(transformer["required_defined_globals_before"], "transformer.required_defined_globals_before"),
            exact_int(transformer["required_global_references"], "transformer.required_global_references"),
            exact_int(transformer["required_globals_after"], "transformer.required_globals_after"),
            exact_int(transformer["removed_section_bytes"], "transformer.removed_section_bytes"),
        )
        == (65_536, 1, 0, 0, 10),
        "stack-pointer sanitization proof differs",
    )
    require(transformer["wit_component_version"] == "0.255.0", "wit-component version differs")
    require(transformer["adapter_import_name"] == "wasi_snapshot_preview1", "adapter import module differs")
    for field in ("validate_compiler_core", "validate_sanitized_core", "validate_component"):
        require(exact_bool(transformer[field], f"transformer.{field}") is True, f"transformer.{field} must be true")
    for field in ("allow_disable_validation", "allow_import_rename", "ambient_adapter_lookup", "network_lookup"):
        require(exact_bool(transformer[field], f"transformer.{field}") is False, f"transformer.{field} must be false")
    for field in ("wit_component_crate_sha256", "reference_cli_binary_sha256"):
        exact_hex(transformer[field], f"transformer.{field}")

    adapter = require_fields(
        value["adapter"],
        {
            "release", "source_commit", "asset", "fixture", "manifest_revision",
            "source_url", "byte_len", "sha256", "target_wasi_revision",
            "published_asset_bytes_are_normative", "source_tag_is_bit_reproducibility_claim",
        },
        "adapter",
    )
    require(adapter["fixture"] == "c81-wasmtime-v48.0.0-preview1-command-adapter.wasm", "adapter fixture differs")
    require(adapter["manifest_revision"] == "wasmtime-v48.0.0-f1412a598f96f3c261a19118d94caffcb0c36235/wasi_snapshot_preview1.command.wasm", "adapter revision differs")
    require(exact_int(adapter["byte_len"], "adapter.byte_len", 1) == 51_828, "adapter length differs")
    require(exact_hex(adapter["sha256"], "adapter.sha256") == "316dfbf171591d69ae414efd13b85933ca13526af8d9e0a735ab88ae08fd85f0", "adapter digest differs")
    require(exact_bool(adapter["published_asset_bytes_are_normative"], "adapter.published_asset_bytes_are_normative") is True, "raw published adapter is not normative")
    require(exact_bool(adapter["source_tag_is_bit_reproducibility_claim"], "adapter.source_tag_is_bit_reproducibility_claim") is False, "source tag became byte authority")

    guest = require_fields(
        value["guest_contract"],
        {
            "module", "imports_are_exact_set", "imports", "exports",
            "core_start_section", "memory_initial_pages", "memory_maximum_pages",
            "tables", "globals", "forbidden_import_families",
        },
        "guest_contract",
    )
    require(guest["module"] == "wasi_snapshot_preview1", "guest import module differs")
    require(exact_bool(guest["imports_are_exact_set"], "guest_contract.imports_are_exact_set") is True, "guest imports are not an exact set")
    expected_import_records = [
        {"name": name, "kind": "func", "params": list(signature[0]), "results": list(signature[1])}
        for name, signature in EXACT_IMPORTS.items()
    ]
    require(guest["imports"] == expected_import_records, "guest exact-five import signatures differ")
    for index, item in enumerate(guest["imports"]):
        require_fields(item, {"name", "kind", "params", "results"}, f"guest_contract.imports[{index}]")
    require(
        guest["exports"]
        == [
            {"name": "memory", "kind": "memory"},
            {"name": "_start", "kind": "func", "params": [], "results": []},
        ],
        "guest export contract differs",
    )
    require_fields(guest["exports"][0], {"name", "kind"}, "guest_contract.exports[0]")
    require_fields(guest["exports"][1], {"name", "kind", "params", "results"}, "guest_contract.exports[1]")
    require(exact_bool(guest["core_start_section"], "guest_contract.core_start_section") is False, "Core start section became allowed")
    require(
        (
            exact_int(guest["memory_initial_pages"], "guest_contract.memory_initial_pages"),
            exact_int(guest["memory_maximum_pages"], "guest_contract.memory_maximum_pages"),
            exact_int(guest["tables"], "guest_contract.tables"),
            exact_int(guest["globals"], "guest_contract.globals"),
        )
        == (2, 16, 0, 0),
        "guest memory/table/global boundary differs",
    )

    surface = require_fields(
        value["component_surface"],
        {
            "imports", "exports", "outer_host_mappings", "top_level_entity_pins",
            "canonical_lowerings", "canonical_lowering_domain",
            "canonical_lowering_sha256", "nested_components", "embedded_core_modules",
        },
        "component_surface",
    )
    require(type(surface["imports"]) is list and len(surface["imports"]) == 10 and len(set(surface["imports"])) == 10, "Component surface imports are not ten unique identities")
    require(surface["exports"] == ["wasi:cli/run@0.2.12"], "Component export surface differs")
    require(surface["outer_host_mappings"] == [], "Component acquired an outer host mapping")
    require(
        (
            exact_int(surface["canonical_lowerings"], "component_surface.canonical_lowerings"),
            exact_int(surface["nested_components"], "component_surface.nested_components"),
            exact_int(surface["embedded_core_modules"], "component_surface.embedded_core_modules"),
        )
        == (18, 1, 4),
        "Component topology differs",
    )
    require(surface["canonical_lowering_domain"] == "vibeos.preview1-wrapped.canonical-lowerings.v1\0", "canonical lowering domain differs")
    exact_hex(surface["canonical_lowering_sha256"], "component_surface.canonical_lowering_sha256")
    pins = surface["top_level_entity_pins"]
    require(type(pins) is list and len(pins) == 11, "Component must pin eleven top-level entities")
    for index, pin in enumerate(pins):
        require_fields(pin, {"direction", "kind", "name", "raw_byte_len", "raw_entry_sha256"}, f"component_surface.top_level_entity_pins[{index}]")
        require(pin["direction"] in ("import", "export") and pin["kind"] == "instance", f"entity pin {index} kind differs")
        exact_text(pin["name"], f"entity pin {index} name", 512)
        exact_int(pin["raw_byte_len"], f"entity pin {index} raw_byte_len", 1)
        exact_hex(pin["raw_entry_sha256"], f"entity pin {index} raw_entry_sha256")
    pin_keys = [(pin["direction"], pin["kind"], pin["name"]) for pin in pins]
    require(pin_keys == sorted(pin_keys, key=lambda item: ((0 if item[0] == "import" else 1), item[1], item[2])), "top-level entity pins are not canonical")
    require({pin["name"] for pin in pins if pin["direction"] == "import"} == set(surface["imports"]), "top-level import pins differ from the surface")

    programs = value["programs"]
    require(type(programs) is list and [item.get("id") for item in programs] == ["c82-rust-ascii-filter", "c82-c-ascii-filter"], "program identities/order differ")
    for index, program in enumerate(programs):
        require_fields(program, {"id", "language", "source", "build", "compiler_core", "guest_core", "component", "component_artifact"}, f"programs[{index}]")
        language = program["language"]
        require(language in ("rust", "c"), f"programs[{index}].language differs")
        source_fields = {"fixture", "sha256", "no_std", "no_main"} if language == "rust" else {"fixture", "sha256", "freestanding", "nostdlib", "no_builtin"}
        source = require_fields(program["source"], source_fields, f"programs[{index}].source")
        exact_hex(source["sha256"], f"programs[{index}].source.sha256")
        for field in source_fields - {"fixture", "sha256"}:
            require(exact_bool(source[field], f"programs[{index}].source.{field}") is True, f"programs[{index}].source.{field} must be true")
        if language == "rust":
            build = require_fields(
                program["build"],
                {
                    "edition", "crate_name", "target_cpu", "link_self_contained",
                    "panic", "opt_level", "lto", "codegen_units", "stack_bytes",
                    "initial_memory_bytes", "maximum_memory_bytes",
                },
                f"programs[{index}].build",
            )
            require(exact_bool(build["link_self_contained"], f"programs[{index}].build.link_self_contained") is False, "Rust build acquired self-contained ambient WASI")
            require(
                (
                    build["edition"], build["crate_name"], build["target_cpu"],
                    build["panic"], build["opt_level"], build["lto"],
                    build["codegen_units"], build["stack_bytes"],
                    build["initial_memory_bytes"], build["maximum_memory_bytes"],
                )
                == ("2024", "c82_rust_ascii_filter", "mvp", "abort", "z", "fat", 1, 65_536, 131_072, 1_048_576),
                "Rust build recipe differs",
            )
        else:
            build = require_fields(
                program["build"],
                {
                    "optimization", "target", "stack_bytes",
                    "initial_memory_bytes", "maximum_memory_bytes",
                },
                f"programs[{index}].build",
            )
            require(
                (
                    build["optimization"], build["target"], build["stack_bytes"],
                    build["initial_memory_bytes"], build["maximum_memory_bytes"],
                )
                == ("O2", "wasm32-wasip1", 65_536, 131_072, 1_048_576),
                "C build recipe differs",
            )
        compiler = require_fields(program["compiler_core"], {"byte_len", "sha256", "defined_globals", "global_references"}, f"programs[{index}].compiler_core")
        exact_int(compiler["byte_len"], f"programs[{index}].compiler_core.byte_len", 1)
        exact_hex(compiler["sha256"], f"programs[{index}].compiler_core.sha256")
        require((compiler["defined_globals"], compiler["global_references"]) == (1, 0), "compiler Core stack-pointer proof differs")
        core = require_fields(program["guest_core"], {"fixture", "byte_len", "sha256", "import_order", "data_segments"}, f"programs[{index}].guest_core")
        exact_int(core["byte_len"], f"programs[{index}].guest_core.byte_len", 1)
        exact_hex(core["sha256"], f"programs[{index}].guest_core.sha256")
        require(type(core["import_order"]) is list and set(core["import_order"]) == set(EXACT_IMPORTS) and len(core["import_order"]) == 5, "program import order is not one exact-five permutation")
        exact_int(core["data_segments"], f"programs[{index}].guest_core.data_segments")
        component = require_fields(program["component"], {"fixture", "byte_len", "sha256", "embedded_core_modules"}, f"programs[{index}].component")
        exact_int(component["byte_len"], f"programs[{index}].component.byte_len", 1)
        exact_hex(component["sha256"], f"programs[{index}].component.sha256")
        modules = component["embedded_core_modules"]
        require(type(modules) is list and len(modules) == 4, "program Component must pin four modules")
        for ordinal, module in enumerate(modules):
            require_fields(module, {"ordinal", "byte_len", "sha256"}, f"programs[{index}].component.embedded_core_modules[{ordinal}]")
            require(exact_int(module["ordinal"], "module.ordinal") == ordinal, "embedded module ordinals differ")
            exact_int(module["byte_len"], "module.byte_len", 1)
            exact_hex(module["sha256"], "module.sha256")
        require(modules[0]["byte_len"] == core["byte_len"] and modules[0]["sha256"] == core["sha256"], "guest is not exact embedded module ordinal zero")
        require_fields(program["component_artifact"], {"fixture"}, f"programs[{index}].component_artifact")

    artifact = require_fields(
        value["component_artifact"],
        {
            "world", "wit_package", "interface_entity_kind",
            "interface_diagnostic_shape", "adapter_ordinal", "adapter_revision",
            "signer_policy_kind", "signer_policy_digest", "instance_limits",
            "runtime_ready",
        },
        "component_artifact",
    )
    wit = require_fields(artifact["wit_package"], {"name", "version", "source_fixture", "source_sha256"}, "component_artifact.wit_package")
    require(wit["name"] == "root:component" and wit["version"] == "0.0.0+c82", "WIT package identity differs")
    exact_hex(wit["source_sha256"], "component_artifact.wit_package.source_sha256")
    limits = require_fields(artifact["instance_limits"], {"memory_bytes", "total_fuel", "poll_quantum", "resources"}, "component_artifact.instance_limits")
    require(limits == {"memory_bytes": 1_048_576, "total_fuel": 2_000_000, "poll_quantum": 1_000, "resources": 16}, "ComponentArtifact limits differ")
    require(artifact["world"] == "root:component/root", "ComponentArtifact world differs")
    require(artifact["interface_entity_kind"] == "interface" and artifact["interface_diagnostic_shape"] == "instance(exact-wasi-0.2.12;host-mapping=none)", "interface diagnostics differ")
    require(artifact["adapter_ordinal"] == 0 and artifact["adapter_revision"] == adapter["manifest_revision"], "artifact adapter identity differs")
    require(artifact["signer_policy_kind"] == "development-image-pin" and artifact["signer_policy_digest"] == "sha256(exact-policy-file-bytes)", "artifact signer policy differs")
    require(exact_bool(artifact["runtime_ready"], "component_artifact.runtime_ready") is False, "artifact became runtime-ready")

    invocation = require_fields(
        value["invocation"],
        {
            "command_name", "arguments_include_argv0", "max_arguments",
            "max_argument_bytes_including_nuls", "max_iovecs",
            "max_io_bytes_per_host_call", "max_stdin_bytes", "max_stdout_bytes",
            "max_host_calls", "stdin_fd", "stdout_fd", "stderr_policy",
            "other_fd_policy", "environment", "preopens", "initial_cwd",
            "proc_exit_semantics", "exit_code_width", "selected_host_imports",
        },
        "invocation",
    )
    require(exact_bool(invocation["arguments_include_argv0"], "invocation.arguments_include_argv0") is True, "argv0 boundary differs")
    require(
        (
            invocation["max_arguments"], invocation["max_argument_bytes_including_nuls"],
            invocation["max_iovecs"], invocation["max_io_bytes_per_host_call"],
            invocation["max_stdin_bytes"], invocation["max_stdout_bytes"],
            invocation["max_host_calls"], invocation["stdin_fd"], invocation["stdout_fd"],
            invocation["exit_code_width"],
        )
        == (2, 64, 1, 257, 4097, 4096, 64, 0, 1, 32),
        "invocation limits differ",
    )
    for field in ("max_arguments", "max_argument_bytes_including_nuls", "max_iovecs", "max_io_bytes_per_host_call", "max_stdin_bytes", "max_stdout_bytes", "max_host_calls", "stdin_fd", "stdout_fd", "exit_code_width"):
        exact_int(invocation[field], f"invocation.{field}")
    require(invocation["environment"] == [] and invocation["preopens"] == [] and invocation["initial_cwd"] is None, "invocation acquired ambient state")
    require(invocation["selected_host_imports"] == list(EXACT_IMPORTS), "invocation host import selection differs")
    require(invocation["stderr_policy"] == "closed-ebadf" and invocation["other_fd_policy"] == "closed-ebadf", "closed descriptor policy differs")
    require(invocation["proc_exit_semantics"] == "terminate-current-invocation-only", "proc_exit escaped invocation scope")

    corpus = require_fields(value["corpus"], {"program_count", "source_files_are_executed_without_edits", "maximum_filter_input_bytes", "modes", "exit_codes", "golden_cases"}, "corpus")
    require(corpus["program_count"] == 2 and corpus["maximum_filter_input_bytes"] == 4096, "corpus bound/count differs")
    require(exact_bool(corpus["source_files_are_executed_without_edits"], "corpus.source_files_are_executed_without_edits") is True, "corpus source edit boundary differs")
    require(corpus["modes"] == ["upper", "lower"], "corpus modes differ")
    require_fields(corpus["exit_codes"], {"success", "usage", "input_too_large", "software", "io"}, "corpus.exit_codes")
    require(corpus["exit_codes"] == {"success": 0, "usage": 64, "input_too_large": 65, "software": 70, "io": 74}, "corpus exit codes differ")
    require(type(corpus["golden_cases"]) is list and len(corpus["golden_cases"]) == 4, "golden corpus cases differ")
    for index, case in enumerate(corpus["golden_cases"]):
        fields = (
            {"name", "arguments", "stdin_repeat_byte", "stdin_repeat_count", "stdout_hex", "exit"}
            if "stdin_repeat_count" in case
            else {"name", "arguments", "stdin_hex", "stdout_hex", "exit"}
        )
        require_fields(case, fields, f"corpus.golden_cases[{index}]")
        require(type(case["arguments"]) is list and len(case["arguments"]) == 1, f"golden case {index} arguments differ")
        exact_int(case["exit"], f"corpus.golden_cases[{index}].exit")
        if "stdin_repeat_count" in case:
            exact_int(case["stdin_repeat_byte"], f"corpus.golden_cases[{index}].stdin_repeat_byte")
            exact_int(case["stdin_repeat_count"], f"corpus.golden_cases[{index}].stdin_repeat_count")

    admission = require_fields(
        value["admission"],
        {
            "feature", "default_enabled", "input_kind", "raw_wasip1_admission",
            "candidate_is_move_only", "fresh_revalidation_before_invocation",
            "private_guest_projection_ordinal", "raw_core_accessor",
            "validated_plan_accessor", "grant_accessor", "ordinary_admission_conversion",
            "production_guest_execution", "acceptance_guest_execution",
            "outer_component_host_mappings", "runtime_ready", "profile_runtime_ready",
            "loader_registration", "graph_registration", "vsh_registration",
            "durable_registration", "ambient_lookup", "raw_durable_ids",
            "no_grant_direct_move", "preopens", "filesystem_authority",
            "environment_authority", "process_authority", "socket_authority",
            "thread_authority", "clock_authority", "random_authority",
            "selected_wasi_0_3_mapping", "aot", "jit",
        },
        "admission",
    )
    require(admission["feature"] == "preview1-corpus-acceptance" and exact_bool(admission["default_enabled"], "admission.default_enabled") is False, "acceptance feature/default differs")
    require(admission["input_kind"] == "ComponentArtifactV1", "raw bytes became admission input")
    for field in ("candidate_is_move_only", "fresh_revalidation_before_invocation", "acceptance_guest_execution"):
        require(exact_bool(admission[field], f"admission.{field}") is True, f"admission.{field} must be true")
    for field in (
        "raw_wasip1_admission", "raw_core_accessor", "validated_plan_accessor",
        "grant_accessor", "ordinary_admission_conversion", "production_guest_execution",
        "runtime_ready", "profile_runtime_ready", "loader_registration",
        "graph_registration", "vsh_registration", "durable_registration", "preopens",
        "filesystem_authority", "environment_authority", "process_authority",
        "socket_authority", "thread_authority", "clock_authority",
        "random_authority", "selected_wasi_0_3_mapping", "aot", "jit",
    ):
        require(exact_bool(admission[field], f"admission.{field}") is False, f"admission.{field} must remain false")
    require(admission["outer_component_host_mappings"] == [], "outer host mappings must remain empty")
    for field in ("ambient_lookup", "raw_durable_ids", "no_grant_direct_move"):
        require(exact_int(admission[field], f"admission.{field}") == 0, f"admission.{field} must remain zero")
    require(exact_int(admission["private_guest_projection_ordinal"], "admission.private_guest_projection_ordinal") == 0, "private guest ordinal differs")


def load_policy_bytes(raw: bytes, path: Path = DEFAULT_POLICY, *, frozen: bool = True) -> Policy:
    require(0 < len(raw) <= MAX_POLICY_BYTES, "policy size is outside the bound")
    if frozen:
        require(sha256(raw).hex() == RAW_POLICY_SHA256, "raw policy SHA-256 differs")
    value = reviewed_json(raw, "C8.2 policy")
    require(type(value) is dict, "C8.2 policy root is not an object")
    validate_policy_value(value, frozen=frozen)
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


def verify_source(source: bytes, program: Mapping[str, Any]) -> None:
    record = program["source"]
    label = f"{program['id']} source"
    require(0 < len(source) <= MAX_SOURCE_BYTES, f"{label} size is outside the bound")
    require(sha256(source).hex() == exact_hex(record["sha256"], f"{label}.sha256"), f"{label} SHA-256 differs")
    require(b"\0" not in source, f"{label} contains NUL")
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not UTF-8") from error
    for forbidden in ("path_open", "environ_get", "environ_sizes_get", "random_get", "sock_", "thread_spawn"):
        require(forbidden not in text, f"{label} contains forbidden ambient import {forbidden}")
    if program["language"] == "rust":
        require("#![no_std]" in text and "#![no_main]" in text, "Rust source lost no_std/no_main")
        require('link(wasm_import_module = "wasi_snapshot_preview1")' in text, "Rust source import module differs")
        require("std::" not in text and "std::env" not in text, "Rust source acquired std/environment lookup")
    else:
        require("#include" not in text, "C source is no longer freestanding")
        require('import_module("wasi_snapshot_preview1")' in text, "C source import module differs")
    for name in EXACT_IMPORTS:
        require(re.search(rf"\b{name}\s*\(", text) is not None, f"{label} lacks {name}")
    require(re.search(r"\bfd_read\s*\([^;]*,\s*1\s*,", text, re.DOTALL) is not None, f"{label} fd_read iovec count is not one")
    require(re.search(r"\bfd_write\s*\([^;]*,\s*1\s*,", text, re.DOTALL) is not None, f"{label} fd_write iovec count is not one")


def encode_uleb(value: int) -> bytes:
    require(type(value) is int and value >= 0, "cannot encode a negative ULEB")
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def encode_sleb(value: int) -> bytes:
    require(type(value) is int, "cannot encode a non-integer SLEB")
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        sign = byte & 0x40
        done = (value == 0 and sign == 0) or (value == -1 and sign != 0)
        output.append(byte if done else byte | 0x80)
        if done:
            return bytes(output)


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

    def uleb(self, bits: int = 32, *, canonical: bool = True) -> int:
        start = self.offset
        result = 0
        shift = 0
        for _ in range((bits + 6) // 7):
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                require(result < (1 << bits), f"{self.label} ULEB overflows u{bits}")
                raw = self.data[start:self.offset]
                encoded = encode_uleb(result)
                require(
                    not canonical or raw == encoded,
                    f"{self.label} has noncanonical ULEB {raw.hex()} for {result} (expected {encoded.hex()})",
                )
                return result
            shift += 7
        raise VerificationError(f"{self.label} ULEB is too long")

    def sleb(self, bits: int) -> int:
        result = 0
        shift = 0
        byte = 0
        for _ in range((bits + 6) // 7):
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if byte & 0x80 == 0:
                if byte & 0x40:
                    result |= -(1 << shift)
                minimum = -(1 << (bits - 1))
                maximum = (1 << (bits - 1)) - 1
                require(minimum <= result <= maximum, f"{self.label} SLEB overflows i{bits}")
                return result
        raise VerificationError(f"{self.label} SLEB is too long")

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
        sections.append(
            Section(
                len(sections),
                section_id,
                8 + relative_start,
                8 + relative_payload,
                8 + cursor.offset,
                payload,
            )
        )
    cursor.finish()
    return tuple(sections)


def valtype(byte: int) -> str:
    values = {0x7F: "i32", 0x7E: "i64"}
    require(byte in values, f"Core uses non-integer value type 0x{byte:02x}")
    return values[byte]


def core_memory_type(cursor: Cursor) -> tuple[int, int]:
    flags = cursor.uleb()
    require(flags == 1, "Core memory is not exact wasm32 unshared min/max memory")
    initial = cursor.uleb()
    maximum = cursor.uleb()
    require((initial, maximum) == (2, 16), "Core memory must be exactly min=2 max=16 pages")
    return initial, maximum


def blocktype(cursor: Cursor) -> None:
    byte = cursor.u8()
    require(byte in (0x40, 0x7F, 0x7E), "Core block type requires a disabled feature")


MEMORY_ALIGNMENTS = {
    0x28: 2,
    0x29: 3,
    0x2C: 0,
    0x2D: 0,
    0x2E: 1,
    0x2F: 1,
    0x30: 0,
    0x31: 0,
    0x32: 1,
    0x33: 1,
    0x34: 2,
    0x35: 2,
    0x36: 2,
    0x37: 3,
    0x3A: 0,
    0x3B: 1,
    0x3C: 0,
    0x3D: 1,
    0x3E: 2,
}

NO_IMMEDIATE_INTEGER_OPS = (
    {0x00, 0x01, 0x0F, 0x1A, 0x1B, 0xA7, 0xAC, 0xAD}
    | set(range(0x45, 0x5B))
    | set(range(0x67, 0x8B))
)


def inspect_function_body(
    body: bytes,
    signature: tuple[tuple[str, ...], tuple[str, ...]],
    total_functions: int,
    label: str,
) -> int:
    require(len(body) <= MAX_FUNCTION_BODY_BYTES, f"{label} exceeds the body bound")
    cursor = Cursor(body, label)
    local_groups = cursor.vector_count()
    local_count = len(signature[0])
    for _ in range(local_groups):
        amount = cursor.uleb()
        valtype(cursor.u8())
        local_count += amount
        require(local_count <= 4096, f"{label} locals exceed the bound")

    depth = 1
    operators = 0
    while depth:
        require(cursor.offset < len(cursor.data), f"{label} lacks its final end")
        opcode = cursor.u8()
        operators += 1
        require(operators <= 1_000_000, f"{label} operator count exceeds the bound")
        if opcode in (0x02, 0x03, 0x04):
            blocktype(cursor)
            depth += 1
            require(depth <= 128, f"{label} control depth exceeds the bound")
        elif opcode == 0x05:
            require(depth > 1, f"{label} has else outside a block")
        elif opcode == 0x0B:
            depth -= 1
        elif opcode in (0x0C, 0x0D):
            target = cursor.uleb()
            require(target < depth, f"{label} branch depth is invalid")
        elif opcode == 0x0E:
            count = cursor.vector_count()
            for _ in range(count + 1):
                require(cursor.uleb() < depth, f"{label} br_table depth is invalid")
        elif opcode == 0x10:
            require(
                cursor.uleb(canonical=False) < total_functions,
                f"{label} call index is invalid",
            )
        elif opcode in (0x20, 0x21, 0x22):
            require(cursor.uleb() < local_count, f"{label} local index is invalid")
        elif opcode in (0x23, 0x24):
            raise VerificationError(f"{label} references a global")
        elif opcode in MEMORY_ALIGNMENTS:
            alignment = cursor.uleb()
            cursor.uleb(canonical=False)
            require(alignment <= MEMORY_ALIGNMENTS[opcode], f"{label} memory alignment is invalid")
        elif opcode in (0x3F, 0x40):
            require(cursor.uleb() == 0, f"{label} memory index is not zero")
        elif opcode == 0x41:
            cursor.sleb(32)
        elif opcode == 0x42:
            cursor.sleb(64)
        elif opcode in NO_IMMEDIATE_INTEGER_OPS:
            pass
        else:
            raise VerificationError(
                f"{label} opcode 0x{opcode:02x} requires a disabled float, table, "
                "reference, bulk-memory, sign-extension, SIMD, thread, GC, or exception feature"
            )
    cursor.finish()
    return operators


@dataclass(frozen=True)
class CoreObservation:
    imports: tuple[tuple[str, str, str, tuple[str, ...], tuple[str, ...]], ...]
    exports: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...]
    data_segments: int
    functions: int
    operators: int


def inspect_core(
    core: bytes,
    program: Mapping[str, Any],
    guest_contract: Mapping[str, Any],
) -> CoreObservation:
    record = program["guest_core"]
    verify_blob(core, record, f"{program['id']} guest_core")
    sections = split_sections(core, CORE_HEADER, f"{program['id']} guest Core")
    allowed_order = {1: 1, 2: 2, 3: 3, 5: 5, 7: 7, 10: 10, 11: 11}
    previous = 0
    by_id: dict[int, bytes] = {}
    for section in sections:
        require(section.section_id != 0, "sanitized guest Core contains a custom section")
        require(section.section_id in allowed_order, f"guest Core contains forbidden section {section.section_id}")
        rank = allowed_order[section.section_id]
        require(rank > previous and section.section_id not in by_id, "Core sections are duplicated or out of order")
        previous = rank
        by_id[section.section_id] = section.payload
    require(set(by_id).issuperset({1, 2, 3, 5, 7, 10}), "guest Core lacks a required section")

    types: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    cursor = Cursor(by_id[1], "Core type section")
    for _ in range(cursor.vector_count()):
        require(cursor.u8() == 0x60, "Core type is not an exact function type")
        params = tuple(valtype(cursor.u8()) for _ in range(cursor.vector_count()))
        results = tuple(valtype(cursor.u8()) for _ in range(cursor.vector_count()))
        require(len(params) <= 32 and len(results) <= 32, "Core function signature exceeds the bound")
        types.append((params, results))
    cursor.finish()
    require(0 < len(types) <= 1024, "Core type count is outside the bound")

    imports: list[tuple[str, str, str, tuple[str, ...], tuple[str, ...]]] = []
    function_types: list[int] = []
    cursor = Cursor(by_id[2], "Core import section")
    for _ in range(cursor.vector_count()):
        module = cursor.name()
        name = cursor.name()
        require(cursor.u8() == 0, "guest Core import is not a function")
        type_index = cursor.uleb()
        require(type_index < len(types), "guest Core import type index is invalid")
        params, results = types[type_index]
        imports.append((module, name, "func", params, results))
        function_types.append(type_index)
    cursor.finish()

    defined_type_indices: list[int] = []
    cursor = Cursor(by_id[3], "Core function section")
    for _ in range(cursor.vector_count()):
        type_index = cursor.uleb()
        require(type_index < len(types), "defined Core function type index is invalid")
        defined_type_indices.append(type_index)
        function_types.append(type_index)
    cursor.finish()
    require(len(function_types) <= 1024, "Core function count exceeds the bound")

    cursor = Cursor(by_id[5], "Core memory section")
    require(cursor.vector_count() == 1, "guest Core must define exactly one memory")
    core_memory_type(cursor)
    cursor.finish()

    raw_exports: list[tuple[str, int, int]] = []
    cursor = Cursor(by_id[7], "Core export section")
    for _ in range(cursor.vector_count()):
        raw_exports.append((cursor.name(), cursor.u8(), cursor.uleb()))
    cursor.finish()

    cursor = Cursor(by_id[10], "Core code section")
    code_count = cursor.vector_count()
    require(code_count == len(defined_type_indices), "Core function/code counts differ")
    operator_count = 0
    for ordinal, type_index in enumerate(defined_type_indices):
        body = cursor.take(cursor.uleb())
        operator_count += inspect_function_body(
            body,
            types[type_index],
            len(function_types),
            f"Core function body {ordinal}",
        )
    cursor.finish()

    data_segments = 0
    if 11 in by_id:
        cursor = Cursor(by_id[11], "Core data section")
        data_segments = cursor.vector_count()
        for index in range(data_segments):
            require(cursor.uleb() == 0, f"Core data segment {index} is not active memory zero")
            require(cursor.u8() == 0x41, f"Core data segment {index} offset is not i32.const")
            offset = cursor.sleb(32)
            require(cursor.u8() == 0x0B and offset >= 0, f"Core data segment {index} offset expression differs")
            payload = cursor.take(cursor.uleb())
            require(offset + len(payload) <= 2 * 65_536, f"Core data segment {index} exceeds initial memory")
        cursor.finish()
    require(data_segments == exact_int(record["data_segments"], "guest_core.data_segments"), "Core data segment count differs")

    expected_names = set(EXACT_IMPORTS)
    observed_names = [entry[1] for entry in imports]
    require(len(imports) == 5 and set(observed_names) == expected_names, "guest Core imports are not the exact five-function set")
    require(tuple(observed_names) == tuple(record["import_order"]), "guest Core observed import order differs from its provenance record")
    for module, name, kind, params, results in imports:
        require(module == guest_contract["module"] and kind == "func", f"guest import {name} module/kind differs")
        require((params, results) == EXACT_IMPORTS[name], f"guest import {name} signature differs")

    exports: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = []
    for name, kind, index in raw_exports:
        if kind == 0:
            require(index < len(function_types), "Core function export index is invalid")
            params, results = types[function_types[index]]
            exports.append((name, "func", params, results))
        elif kind == 2:
            require(index == 0, "Core memory export is not memory zero")
            exports.append((name, "memory", (), ()))
        else:
            raise VerificationError("guest Core has an extra non-function/non-memory export")
    expected_exports = tuple(
        (
            entry["name"],
            entry["kind"],
            tuple(entry.get("params", [])),
            tuple(entry.get("results", [])),
        )
        for entry in guest_contract["exports"]
    )
    require(tuple(exports) == expected_exports, "guest Core memory/_start exports differ")
    require(len(raw_exports) == 2, "guest Core has an extra export")
    return CoreObservation(tuple(imports), tuple(exports), data_segments, len(function_types), operator_count)


def component_extern_name(cursor: Cursor) -> str:
    require(cursor.u8() == 0, "Component external name is not the canonical 0x00 form")
    return cursor.name()


def component_kind(cursor: Cursor) -> str:
    first = cursor.u8()
    if first == 0:
        require(cursor.u8() == 0x11, "Component module kind prefix differs")
        return "module"
    kinds = {1: "func", 2: "value", 3: "type", 4: "component", 5: "instance"}
    require(first in kinds, f"Component external kind 0x{first:02x} is invalid")
    return kinds[first]


def component_type_ref(cursor: Cursor) -> str:
    kind = component_kind(cursor)
    if kind in ("module", "func", "instance", "component"):
        cursor.uleb()
    elif kind == "value":
        byte = cursor.u8()
        require(
            byte in (0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x7A, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73),
            "Component value type differs",
        )
    else:
        bound = cursor.u8()
        require(bound in (0, 1), "Component type bound is invalid")
        if bound == 0:
            cursor.uleb()
    return kind


def canonical_options(cursor: Cursor) -> tuple[str, ...]:
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
            raise VerificationError(f"canonical option 0x{opcode:02x} is outside C8.2")
        key = option.split("(", 1)[0]
        require(not any(previous.split("(", 1)[0] == key for previous in options), "canonical options repeat a kind")
        options.append(option)
    require(len(options) <= 8, "canonical options exceed the profile bound")
    return tuple(options)


@dataclass(frozen=True)
class ComponentObservation:
    sections: tuple[Section, ...]
    modules: tuple[bytes, ...]
    imports: tuple[str, ...]
    exports: tuple[str, ...]
    entity_pins: tuple[tuple[str, str, str, int, str], ...]
    lower_count: int
    lower_fingerprint: bytes
    nested_components: int


def count_nested(component: bytes, depth: int = 1) -> int:
    require(depth <= 16, "nested Component depth exceeds the bound")
    sections = split_sections(component, COMPONENT_HEADER, "nested Component")
    total = 1
    for section in sections:
        if section.section_id == 4:
            total += count_nested(section.payload, depth + 1)
    return total


def inspect_component(
    component: bytes,
    program: Mapping[str, Any],
    guest_core: bytes,
    surface: Mapping[str, Any],
) -> ComponentObservation:
    record = program["component"]
    verify_blob(component, record, f"{program['id']} component")
    sections = split_sections(component, COMPONENT_HEADER, f"{program['id']} wrapped Component")

    modules = tuple(section.payload for section in sections if section.section_id == 1)
    module_pins = record["embedded_core_modules"]
    require(len(modules) == len(module_pins) == 4, "Component does not contain exactly four embedded Core modules")
    for ordinal, (module, pin) in enumerate(zip(modules, module_pins)):
        require(pin["ordinal"] == ordinal, "embedded Core module ordinal differs")
        verify_blob(module, pin, f"component.module[{ordinal}]")
        split_sections(module, CORE_HEADER, f"component.module[{ordinal}]")
    require(modules[0] == guest_core, "embedded module ordinal zero is not the exact guest Core")

    imports: list[str] = []
    exports: list[str] = []
    entity_pins: list[tuple[str, str, str, int, str]] = []
    lower_hasher = hashlib.sha256()
    lower_hasher.update(surface["canonical_lowering_domain"].encode("utf-8"))
    lower_count = 0
    nested_total = 0

    for section in sections:
        if section.section_id == 10:
            cursor = Cursor(section.payload, f"Component import section {section.ordinal}")
            for _ in range(cursor.vector_count()):
                entry_start = cursor.offset
                name = component_extern_name(cursor)
                kind = component_type_ref(cursor)
                require(kind == "instance", f"top-level import {name!r} is not an instance")
                raw = section.payload[entry_start:cursor.offset]
                imports.append(name)
                entity_pins.append(("import", kind, name, len(raw), sha256(raw).hex()))
            cursor.finish()
        elif section.section_id == 11:
            cursor = Cursor(section.payload, f"Component export section {section.ordinal}")
            for _ in range(cursor.vector_count()):
                entry_start = cursor.offset
                name = component_extern_name(cursor)
                kind = component_kind(cursor)
                cursor.uleb()
                has_type = cursor.u8()
                require(has_type in (0, 1), "Component export optional type tag is invalid")
                if has_type:
                    require(component_type_ref(cursor) == kind, "Component export ascribed type differs")
                require(kind == "instance", f"top-level export {name!r} is not an instance")
                raw = section.payload[entry_start:cursor.offset]
                exports.append(name)
                entity_pins.append(("export", kind, name, len(raw), sha256(raw).hex()))
            cursor.finish()
        elif section.section_id == 8:
            cursor = Cursor(section.payload, f"canonical section {section.ordinal}")
            for _ in range(cursor.vector_count()):
                entry_start = cursor.offset
                opcode = cursor.u8()
                if opcode == 0:
                    require(cursor.u8() == 0, "canonical lift subopcode differs")
                    cursor.uleb()
                    canonical_options(cursor)
                    cursor.uleb()
                elif opcode == 1:
                    require(cursor.u8() == 0, "canonical lower subopcode differs")
                    cursor.uleb()
                    canonical_options(cursor)
                    raw = section.payload[entry_start:cursor.offset]
                    lower_hasher.update(struct.pack("<Q", len(raw)))
                    lower_hasher.update(raw)
                    lower_count += 1
                elif opcode == 3:
                    cursor.uleb()
                else:
                    raise VerificationError(f"canonical entry 0x{opcode:02x} is outside the exact C8.2 topology")
            cursor.finish()
        elif section.section_id == 4:
            nested_total += count_nested(section.payload)
        elif section.section_id == 0:
            cursor = Cursor(section.payload, f"Component custom section {section.ordinal}")
            cursor.name()
        elif section.section_id == 9:
            raise VerificationError("wrapped Component unexpectedly has a start section")
        elif section.section_id not in (1, 2, 3, 5, 6, 7):
            raise VerificationError(f"wrapped Component has unsupported section {section.section_id}")

    require(len(imports) == 10 and len(set(imports)) == 10 and set(imports) == set(surface["imports"]), "Component top-level import identities/versions differ")
    require(tuple(exports) == tuple(surface["exports"]), "Component top-level export identities/versions differ")
    entity_pins.sort(key=lambda item: ((0 if item[0] == "import" else 1), item[1], item[2]))
    expected_pins = tuple(
        (
            pin["direction"],
            pin["kind"],
            pin["name"],
            pin["raw_byte_len"],
            pin["raw_entry_sha256"],
        )
        for pin in surface["top_level_entity_pins"]
    )
    require(tuple(entity_pins) == expected_pins, "Component top-level raw entity pins differ")
    require(lower_count == surface["canonical_lowerings"], "canonical lower count differs")
    lower_fingerprint = lower_hasher.digest()
    require(lower_fingerprint.hex() == surface["canonical_lowering_sha256"], "canonical lower fingerprint differs")
    require(nested_total == surface["nested_components"], "nested Component count differs")
    return ComponentObservation(
        sections,
        modules,
        tuple(imports),
        tuple(exports),
        tuple(entity_pins),
        lower_count,
        lower_fingerprint,
        nested_total,
    )


def load_c71() -> Any:
    path = Path(__file__).with_name("verify-c71-component-artifact.py")
    spec = importlib.util.spec_from_file_location("vibeos_c82_independent_c71", path)
    require(spec is not None and spec.loader is not None, "cannot load independent C7.1 CMP1 parser")
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


C71 = load_c71()


def verify_component_artifact(
    artifact_bytes: bytes,
    policy: Policy,
    program: Mapping[str, Any],
    component: bytes,
    adapter: bytes,
    wit_source: bytes,
    observation: ComponentObservation,
    *,
    frozen_artifact: bool = True,
) -> Any:
    artifact_pin = ARTIFACT_PINS[program["id"]]
    if frozen_artifact:
        verify_blob(artifact_bytes, artifact_pin, f"{program['id']} CMP1")
    try:
        artifact = C71.verify_artifact(artifact_bytes)
    except (C71.VerificationError, struct.error, UnicodeDecodeError) as error:
        raise VerificationError(f"{program['id']} CMP1 is not canonical: {error}") from error
    require(
        artifact.profile.code == 4
        and artifact.profile.stage == 2
        and artifact.profile.artifact_abi == 4
        and not artifact.runtime_ready,
        "CMP1 is not inert profile code 4",
    )
    if frozen_artifact:
        require(
            artifact.commitment.hex() == artifact_pin["commitment"],
            f"{program['id']} CMP1 commitment differs",
        )
    require(artifact.signer_kind == 1, "CMP1 signer policy is not the development image pin")
    require(
        artifact.signer_policy_digest == sha256(policy.raw)
        and artifact.signer_policy_digest.hex() == RAW_POLICY_SHA256,
        "CMP1 signer policy digest differs from the exact raw policy bytes",
    )

    artifact_policy = policy.value["component_artifact"]
    limits = artifact_policy["instance_limits"]
    expected_limits = (
        limits["memory_bytes"],
        limits["total_fuel"],
        limits["poll_quantum"],
        limits["resources"],
    )
    require(artifact.instance_limits == expected_limits, "CMP1 instance limits differ")
    require(artifact.component == component, "CMP1 does not contain the exact wrapped Component")

    expected_modules = tuple(
        C71.CoreModule(len(raw), C71.role_hash(C71.CORE_MODULE_HASH_DOMAIN, raw))
        for raw in observation.modules
    )
    require(artifact.manifest.core_modules == expected_modules, "CMP1 manifest Core module topology differs")
    require(artifact.manifest.world == artifact_policy["world"], "CMP1 manifest world differs")

    wit_policy = artifact_policy["wit_package"]
    require(sha256(wit_source).hex() == wit_policy["source_sha256"], "CMP1 WIT source digest differs")
    try:
        wit_text = wit_source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("CMP1 WIT source is not UTF-8") from error
    require(
        artifact.manifest.wit_packages
        == (C71.WitPackage(wit_policy["name"], wit_policy["version"], wit_text),),
        "CMP1 manifest WIT package differs",
    )

    shape = artifact_policy["interface_diagnostic_shape"]
    expected_interfaces = [
        C71.Interface(1, 2, name, shape) for name in observation.imports
    ]
    expected_interfaces += [
        C71.Interface(2, 2, name, shape) for name in observation.exports
    ]
    expected_interfaces.sort(
        key=lambda entry: (
            entry.direction,
            entry.name,
            entry.kind,
            entry.diagnostic_shape,
        )
    )
    require(
        artifact.manifest.interfaces == tuple(expected_interfaces),
        "CMP1 manifest interfaces differ",
    )
    require(len(artifact.manifest.adapters) == 1, "CMP1 manifest must contain one adapter")
    manifest_adapter = artifact.manifest.adapters[0]
    require(
        manifest_adapter.ordinal == artifact_policy["adapter_ordinal"]
        and manifest_adapter.revision == artifact_policy["adapter_revision"]
        and manifest_adapter.descriptor == adapter,
        "CMP1 manifest adapter is not the exact full raw C8.1 asset",
    )
    require(
        len(manifest_adapter.descriptor) == policy.value["adapter"]["byte_len"]
        and len(observation.modules[1]) == 12_442,
        "raw manifest adapter and pruned embedded adapter module were conflated",
    )
    return artifact


def fixture_path(policy: Policy, name: Any, label: str) -> Path:
    filename = exact_text(name, label, 256)
    require(Path(filename).name == filename, f"{label} is not a local basename")
    path = policy.directory / filename
    require(path.is_file(), f"{label} does not exist: {path}")
    return path


@dataclass(frozen=True)
class ProgramFixture:
    program: Mapping[str, Any]
    source: bytes
    core: bytes
    component: bytes
    artifact_bytes: bytes
    core_observation: CoreObservation
    component_observation: ComponentObservation
    artifact: Any


def read_program_fixture(
    policy: Policy,
    program: Mapping[str, Any],
    adapter: bytes,
    wit_source: bytes,
) -> ProgramFixture:
    source = read_bounded(
        fixture_path(policy, program["source"]["fixture"], f"{program['id']} source fixture"),
        MAX_SOURCE_BYTES,
        f"{program['id']} source",
    )
    core = read_bounded(
        fixture_path(policy, program["guest_core"]["fixture"], f"{program['id']} Core fixture"),
        MAX_WASM_BYTES,
        f"{program['id']} Core",
    )
    component = read_bounded(
        fixture_path(policy, program["component"]["fixture"], f"{program['id']} Component fixture"),
        MAX_WASM_BYTES,
        f"{program['id']} Component",
    )
    artifact_bytes = read_bounded(
        fixture_path(
            policy,
            program["component_artifact"]["fixture"],
            f"{program['id']} CMP1 fixture",
        ),
        C71.MAX_ENCODED_BYTES,
        f"{program['id']} CMP1",
    )
    verify_source(source, program)
    core_observation = inspect_core(core, program, policy.value["guest_contract"])
    component_observation = inspect_component(
        component,
        program,
        core,
        policy.value["component_surface"],
    )
    artifact = verify_component_artifact(
        artifact_bytes,
        policy,
        program,
        component,
        adapter,
        wit_source,
        component_observation,
    )
    return ProgramFixture(
        program,
        source,
        core,
        component,
        artifact_bytes,
        core_observation,
        component_observation,
        artifact,
    )


def verify_fixture(policy: Policy) -> tuple[dict[str, Any], tuple[ProgramFixture, ...]]:
    adapter_path = fixture_path(policy, policy.value["adapter"]["fixture"], "adapter.fixture")
    adapter = read_bounded(adapter_path, MAX_WASM_BYTES, "raw Preview1 adapter")
    verify_blob(adapter, policy.value["adapter"], "adapter")

    wit_policy = policy.value["component_artifact"]["wit_package"]
    wit_source = read_bounded(
        fixture_path(policy, wit_policy["source_fixture"], "WIT source fixture"),
        MAX_WIT_BYTES,
        "WIT source",
    )
    require(sha256(wit_source).hex() == wit_policy["source_sha256"], "WIT source SHA-256 differs")

    fixtures = tuple(
        read_program_fixture(policy, program, adapter, wit_source)
        for program in policy.value["programs"]
    )
    require(
        fixtures[0].component_observation.modules[1]
        == fixtures[1].component_observation.modules[1],
        "C and Rust embedded adapter module ordinal one differ",
    )
    require(
        fixtures[0].component_observation.modules[2:]
        != fixtures[1].component_observation.modules[2:],
        "C and Rust generated shim modules unexpectedly coincide",
    )
    report = {
        "status": "ok",
        "raw_policy_sha256": sha256(policy.raw).hex(),
        "policy_semantic_sha256": sha256(canonical_json(policy.value)).hex(),
        "adapter_sha256": sha256(adapter).hex(),
        "programs": [
            {
                "id": fixture.program["id"],
                "source_sha256": sha256(fixture.source).hex(),
                "core_sha256": sha256(fixture.core).hex(),
                "component_sha256": sha256(fixture.component).hex(),
                "artifact_sha256": sha256(fixture.artifact_bytes).hex(),
                "artifact_commitment": fixture.artifact.commitment.hex(),
                "import_order": [entry[1] for entry in fixture.core_observation.imports],
                "operators": fixture.core_observation.operators,
                "embedded_core_modules": len(fixture.component_observation.modules),
                "canonical_lowerings": fixture.component_observation.lower_count,
            }
            for fixture in fixtures
        ],
        "off_device_only": True,
        "runtime_ready": False,
        "profile_runtime_ready": False,
        "ambient_lookup": 0,
        "outer_host_mappings": 0,
    }
    return report, fixtures


def expect_rejected(action: Callable[[], Any], label: str) -> None:
    try:
        action()
    except (
        VerificationError,
        C71.VerificationError,
        ValueError,
        struct.error,
        UnicodeDecodeError,
        KeyError,
        IndexError,
    ):
        return
    raise VerificationError(f"mutation unexpectedly accepted: {label}")


def wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + encode_uleb(len(payload)) + payload


def wasm_name(value: str) -> bytes:
    raw = value.encode("utf-8")
    return encode_uleb(len(raw)) + raw


def build_core(
    import_names: Sequence[str] = tuple(EXACT_IMPORTS),
    *,
    module: str = "wasi_snapshot_preview1",
    wrong_signature: str | None = None,
    memory: tuple[int, int] = (2, 16),
    add_global: bool = False,
    add_start: bool = False,
    body_prefix: bytes = b"",
) -> bytes:
    type_signatures = [
        (("i32", "i32"), ("i32",)),
        (("i32", "i32", "i32", "i32"), ("i32",)),
        (("i32",), ()),
        ((), ()),
    ]
    encoded_types = bytearray(encode_uleb(len(type_signatures)))
    for params, results in type_signatures:
        encoded_types.append(0x60)
        encoded_types.extend(encode_uleb(len(params)))
        encoded_types.extend(b"\x7f" * len(params))
        encoded_types.extend(encode_uleb(len(results)))
        encoded_types.extend(b"\x7f" * len(results))

    type_for_name = {
        "args_sizes_get": 0,
        "args_get": 0,
        "fd_read": 1,
        "fd_write": 1,
        "proc_exit": 2,
    }
    imports = bytearray(encode_uleb(len(import_names)))
    for name in import_names:
        type_index = type_for_name.get(name, 0)
        if name == wrong_signature:
            type_index = 3
        imports.extend(wasm_name(module))
        imports.extend(wasm_name(name))
        imports.extend(b"\x00" + encode_uleb(type_index))

    functions = b"\x01\x03"
    memories = b"\x01\x01" + encode_uleb(memory[0]) + encode_uleb(memory[1])
    start_index = len(import_names)
    exports = (
        b"\x02"
        + wasm_name("memory")
        + b"\x02\x00"
        + wasm_name("_start")
        + b"\x00"
        + encode_uleb(start_index)
    )
    function_body = b"\x00" + body_prefix + b"\x0b"
    code = b"\x01" + encode_uleb(len(function_body)) + function_body
    result = (
        CORE_HEADER
        + wasm_section(1, bytes(encoded_types))
        + wasm_section(2, bytes(imports))
        + wasm_section(3, functions)
        + wasm_section(5, memories)
    )
    if add_global:
        result += wasm_section(6, b"\x01\x7f\x00\x41\x00\x0b")
    result += wasm_section(7, exports)
    if add_start:
        result += wasm_section(8, encode_uleb(start_index))
    return result + wasm_section(10, code)


def rebound_blob(record: Mapping[str, Any], data: bytes) -> dict[str, Any]:
    result = copy.deepcopy(record)
    result["byte_len"] = len(data)
    result["sha256"] = sha256(data).hex()
    return result


def rebound_core_program(
    program: Mapping[str, Any],
    core: bytes,
    order: Sequence[str],
) -> dict[str, Any]:
    result = copy.deepcopy(program)
    result["guest_core"] = rebound_blob(result["guest_core"], core)
    result["guest_core"]["import_order"] = list(order)
    result["guest_core"]["data_segments"] = 0
    return result


def rebound_component_program(
    program: Mapping[str, Any],
    component: bytes,
) -> dict[str, Any]:
    result = copy.deepcopy(program)
    result["component"] = rebound_blob(result["component"], component)
    return result


def replace_encoded_section(
    component: bytes,
    section: Section,
    replacement: bytes,
) -> bytes:
    return component[: section.start] + replacement + component[section.end :]


def run_selftest(
    policy: Policy,
    fixtures: tuple[ProgramFixture, ...],
) -> tuple[str, ...]:
    classes: list[str] = []

    def reject(action: Callable[[], Any], label: str) -> None:
        expect_rejected(action, label)
        classes.append(label)

    def accept(action: Callable[[], Any], label: str) -> None:
        try:
            action()
        except Exception as error:
            raise VerificationError(f"positive mutation unexpectedly rejected: {label}: {error}") from error
        classes.append(label)

    reject(
        lambda: load_policy_bytes(policy.raw + b" ", policy.path),
        "policy-raw-sha",
    )
    semantic = copy.deepcopy(policy.value)
    semantic["version"] = 2
    reject(
        lambda: validate_policy_value(semantic, frozen=True),
        "policy-canonical-semantic",
    )
    duplicate_key = b'{"schema":"duplicate",' + policy.raw.lstrip()[1:]
    reject(
        lambda: load_policy_bytes(duplicate_key, policy.path, frozen=False),
        "policy-duplicate-key",
    )
    extra_field = copy.deepcopy(policy.value)
    extra_field["admission"]["unexpected"] = False
    reject(
        lambda: validate_policy_value(extra_field, frozen=False),
        "policy-field-set",
    )

    for label, field in (
        ("path-authority", "filesystem_authority"),
        ("environ-authority", "environment_authority"),
        ("socket-authority", "socket_authority"),
        ("random-authority", "random_authority"),
    ):
        mutated = copy.deepcopy(policy.value)
        mutated["admission"][field] = True
        reject(
            lambda mutated=mutated: validate_policy_value(mutated, frozen=False),
            label,
        )
    iovec = copy.deepcopy(policy.value)
    iovec["invocation"]["max_iovecs"] = 2
    reject(lambda: validate_policy_value(iovec, frozen=False), "iovec-limit")
    limit = copy.deepcopy(policy.value)
    limit["component_artifact"]["instance_limits"]["resources"] = 17
    reject(lambda: validate_policy_value(limit, frozen=False), "artifact-limit-policy")
    runtime_ready = copy.deepcopy(policy.value)
    runtime_ready["profile"]["runtime_ready"] = True
    reject(lambda: validate_policy_value(runtime_ready, frozen=False), "runtime-ready")

    first = fixtures[0]
    reject(
        lambda: verify_source(first.source + b"\n", first.program),
        "source-whole-hash",
    )
    adapter = first.artifact.manifest.adapters[0].descriptor
    changed_adapter = bytearray(adapter)
    changed_adapter[len(changed_adapter) // 2] ^= 1
    reject(
        lambda: verify_blob(bytes(changed_adapter), policy.value["adapter"], "adapter"),
        "adapter-whole-hash",
    )

    base_program = first.program
    exact_order = list(EXACT_IMPORTS)
    exact_core = build_core(exact_order)
    exact_program = rebound_core_program(base_program, exact_core, exact_order)
    accept(
        lambda: inspect_core(exact_core, exact_program, policy.value["guest_contract"]),
        "import-exact-set",
    )
    reordered = list(reversed(exact_order))
    reordered_core = build_core(reordered)
    reordered_program = rebound_core_program(base_program, reordered_core, reordered)
    accept(
        lambda: inspect_core(
            reordered_core,
            reordered_program,
            policy.value["guest_contract"],
        ),
        "import-reorder-accepted",
    )

    duplicate = exact_order[:-1] + ["fd_write"]
    duplicate_core = build_core(duplicate)
    duplicate_program = rebound_core_program(base_program, duplicate_core, duplicate)
    reject(
        lambda: inspect_core(
            duplicate_core,
            duplicate_program,
            policy.value["guest_contract"],
        ),
        "import-duplicate",
    )
    extra = exact_order + ["fd_write"]
    extra_core = build_core(extra)
    extra_program = rebound_core_program(base_program, extra_core, extra)
    reject(
        lambda: inspect_core(
            extra_core,
            extra_program,
            policy.value["guest_contract"],
        ),
        "import-extra",
    )
    signature_core = build_core(exact_order, wrong_signature="fd_read")
    signature_program = rebound_core_program(base_program, signature_core, exact_order)
    reject(
        lambda: inspect_core(
            signature_core,
            signature_program,
            policy.value["guest_contract"],
        ),
        "import-signature",
    )

    for label, forbidden in (
        ("core-path-import", "path_open"),
        ("core-environ-import", "environ_get"),
        ("core-socket-import", "sock_accept"),
        ("core-random-import", "random_get"),
    ):
        names = exact_order.copy()
        names[1] = forbidden
        changed = build_core(names)
        changed_program = rebound_core_program(base_program, changed, names)
        reject(
            lambda changed=changed, changed_program=changed_program: inspect_core(
                changed,
                changed_program,
                policy.value["guest_contract"],
            ),
            label,
        )

    for label, changed in (
        ("core-global", build_core(exact_order, add_global=True)),
        ("core-start", build_core(exact_order, add_start=True)),
        ("core-memory", build_core(exact_order, memory=(1, 16))),
        ("core-feature-float", build_core(exact_order, body_prefix=b"\x43\0\0\0\0\x1a")),
    ):
        changed_program = rebound_core_program(base_program, changed, exact_order)
        reject(
            lambda changed=changed, changed_program=changed_program: inspect_core(
                changed,
                changed_program,
                policy.value["guest_contract"],
            ),
            label,
        )

    component = first.component
    reject(
        lambda: inspect_component(
            component + b"\0",
            first.program,
            first.core,
            policy.value["component_surface"],
        ),
        "component-whole-hash",
    )
    module_sections = [
        section
        for section in first.component_observation.sections
        if section.section_id == 1
    ]
    first_encoded = component[module_sections[0].start : module_sections[0].end]
    second_encoded = component[module_sections[1].start : module_sections[1].end]
    swapped = (
        component[: module_sections[0].start]
        + second_encoded
        + component[module_sections[0].end : module_sections[1].start]
        + first_encoded
        + component[module_sections[1].end :]
    )
    swapped_program = rebound_component_program(first.program, swapped)
    reject(
        lambda: inspect_component(
            swapped,
            swapped_program,
            first.core,
            policy.value["component_surface"],
        ),
        "component-module-order",
    )

    changed_import = component.replace(
        b"wasi:cli/stderr@0.2.12",
        b"wasi:cli/stdxxx@0.2.12",
        1,
    )
    require(changed_import != component and len(changed_import) == len(component), "selftest import mutation seed differs")
    changed_import_program = rebound_component_program(first.program, changed_import)
    reject(
        lambda: inspect_component(
            changed_import,
            changed_import_program,
            first.core,
            policy.value["component_surface"],
        ),
        "component-top-entity",
    )

    lower_section = next(
        section
        for section in first.component_observation.sections
        if section.section_id == 8
        and len(section.payload) > 1
        and section.payload[1] == 1
    )
    lower_payload = bytearray(lower_section.payload)
    lower_payload[-1] ^= 1
    changed_lower = replace_encoded_section(
        component,
        lower_section,
        wasm_section(8, bytes(lower_payload)),
    )
    changed_lower_program = rebound_component_program(first.program, changed_lower)
    reject(
        lambda: inspect_component(
            changed_lower,
            changed_lower_program,
            first.core,
            policy.value["component_surface"],
        ),
        "component-lowering-pin",
    )

    artifact_bytes = first.artifact_bytes
    wit_source = read_bounded(
        fixture_path(
            policy,
            policy.value["component_artifact"]["wit_package"]["source_fixture"],
            "selftest WIT source",
        ),
        MAX_WIT_BYTES,
        "selftest WIT source",
    )
    reject(
        lambda: verify_component_artifact(
            artifact_bytes + b"\0",
            policy,
            first.program,
            first.component,
            adapter,
            wit_source,
            first.component_observation,
        ),
        "cmp1-whole-hash",
    )
    corrupted_commitment = bytearray(artifact_bytes)
    corrupted_commitment[C71.COMMITMENT_OFFSET] ^= 1
    reject(
        lambda: verify_component_artifact(
            bytes(corrupted_commitment),
            policy,
            first.program,
            first.component,
            adapter,
            wit_source,
            first.component_observation,
            frozen_artifact=False,
        ),
        "cmp1-commitment",
    )

    signer = bytearray(artifact_bytes)
    signer[232] ^= 1
    changed_signer = C71.recommit(bytes(signer))
    reject(
        lambda: verify_component_artifact(
            changed_signer,
            policy,
            first.program,
            first.component,
            adapter,
            wit_source,
            first.component_observation,
            frozen_artifact=False,
        ),
        "cmp1-signer-policy",
    )

    layout = C71.fixture_layout(artifact_bytes)
    changed_manifest = bytearray(artifact_bytes)
    changed_manifest[layout.module_records[2] + 8] ^= 1
    changed_manifest_bytes = C71.reseal(bytes(changed_manifest))
    reject(
        lambda: verify_component_artifact(
            changed_manifest_bytes,
            policy,
            first.program,
            first.component,
            adapter,
            wit_source,
            first.component_observation,
            frozen_artifact=False,
        ),
        "cmp1-manifest-module",
    )

    changed_limit = C71.mutate_u64(
        artifact_bytes,
        layout.instance_limits_start,
        first.artifact.instance_limits[0] - 1,
    )
    changed_limit = C71.reseal(changed_limit)
    reject(
        lambda: verify_component_artifact(
            changed_limit,
            policy,
            first.program,
            first.component,
            adapter,
            wit_source,
            first.component_observation,
            frozen_artifact=False,
        ),
        "cmp1-instance-limit",
    )
    return tuple(classes)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="independently verify the inert C8.2 Rust/C Preview1 corpus"
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    if not arguments.fixture and not arguments.selftest:
        parser.error("select --fixture and/or --selftest")
    try:
        policy = load_policy(arguments.policy)
        report, fixtures = verify_fixture(policy)
        if arguments.selftest:
            classes = run_selftest(policy, fixtures)
            report["selftest_mutations"] = len(classes)
            report["selftest_classes"] = list(classes)
            report["import_reorder_accepted"] = "import-reorder-accepted" in classes
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    except (
        OSError,
        VerificationError,
        C71.VerificationError,
        ValueError,
        struct.error,
        UnicodeDecodeError,
    ) as error:
        print(f"FAIL verify-c82-preview1-corpus: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
