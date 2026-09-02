#!/usr/bin/env python3
"""Independent host-only C7.8 powered-off disk and crash-corpus verifier.

The accepted-content authority is the explicitly supplied, reviewable C7.8
semantic policy plus an independently supplied Ed25519 trust anchor.  The
checked-in C7.6 byte fixture, guest reports, the production Rust decoder, and
the exporter never decide whether bytes are acceptable.  Frozen pure-Python
Storage/CAS and Component codecs are reused only below this verifier's own
policy, history, coverage, and extent-census gates.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import mmap
import os
import re
import sqlite3
import struct
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "policy/image/artifacts/c78-independent-disk-policy.json"
DEFAULT_C76_VECTORS = (
    ROOT / "policy/image/artifacts/c76-graph-version-replacement.vectors"
)

SCOPE = "frozen-c7-v1-policy-v3-component-graph"
MANIFEST_SCHEMA = "vibeos.c78.raw-disk-corpus"
POLICY_SCHEMA = "vibeos.c78.independent-disk-policy"
BLOCK = 512
PAGE = 4096
PAYLOAD = 0x50
GRAPH_SPACE = 0x5649_4245_4F53_2D47_5241_5048_2D56_3100
STORED_OBJECT_RESOURCE_KIND = 0x5354_4F52
READ = 0x01
ROOT_FLAG = 0x01
CMP1 = 0x434D_5031
CME1 = 0x434D_4531
CGE1 = 0x4347_4531
CGV1 = 0x4347_5631
EVIDENCE_LEN = 112
GRAPH_HEADER_LEN = 256
LOGICAL_RECORDS_PER_TRANSITION = 61
LOGICAL_CUTS = range(BLOCK + 1)
PHYSICAL_CUTS = range(PAGE + 1)

GRAPH_MANIFEST_DOMAIN = b"vibeos.component-graph-version.manifest.v1\0"
GRAPH_COMMITMENT_DOMAIN = b"vibeos.component-graph-version.commitment.v1\0"
ARTIFACT_EVIDENCE_COMMITMENT_DOMAIN = (
    b"vibeos.component-artifact.authentication-evidence.v1\0"
)
LEAF_SIGNATURE_DOMAIN = b"vibeos.component-artifact.operator-admission.v1\0"
GRAPH_SIGNATURE_DOMAIN = b"vibeos.component-graph.operator-admission.v1.c7\0"
WORLD_CONTRACT_DOMAIN = b"vibeos.component-graph.world-contract.v1\0"

HEX32 = re.compile(r"[0-9a-f]{64}\Z")
EVENT_TOKEN = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
CANONICAL_EVENT_FIELDS = (
    "scenario",
    "transition",
    "mode",
    "phase",
    "operation",
    "ordinal",
    "cut",
)


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_module(filename: str, name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# These modules are frozen, pure-Python decoders.  No production Rust decoder,
# exporter verdict, or fixed C7.6 vector comparison is imported as authority.
migration = load_module(
    "verify-storage-v2-migration.py", "vibeos_c78_storage_v2_parser"
)
c71 = load_module(
    "verify-c71-component-artifact.py", "vibeos_c78_component_parser"
)
c73 = load_module(
    "verify-c73-authenticated-admission.py", "vibeos_c78_signature_parser"
)
c76_codec = load_module(
    "verify-c76-graph-version-replacement.py", "vibeos_c78_graph_codec"
)
c77_reports = load_module(
    "verify-c77-ephemeral-runtime.py", "vibeos_c78_c77_report_parser"
)
legacy = migration.legacy_codec

EXPECTED_REJECTION_ERRORS = (
    VerificationError,
    migration.Violation,
    migration.storage_codec.FormatViolation,
    c71.VerificationError,
    c73.VerificationError,
    c76_codec.VerificationError,
    c77_reports.VerificationError,
    struct.error,
    UnicodeDecodeError,
)


def u16(data: bytes | bytearray | memoryview, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def u32(data: bytes | bytearray | memoryview, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def u64(data: bytes | bytearray | memoryview, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


def u128(data: bytes | bytearray | memoryview, at: int) -> int:
    return int.from_bytes(data[at : at + 16], "little")


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def framed_sha256(domain: bytes, value: bytes) -> bytes:
    return sha256(domain, struct.pack("<Q", len(value)), value)


def exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    require(set(value) == expected, f"{label} field set differs")


def exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        f"{label} is not a bounded integer",
    )
    return value


def exact_bool(value: Any, label: str) -> bool:
    require(type(value) is bool, f"{label} is not a JSON boolean")
    return value


def exact_text(value: Any, label: str, maximum: int = 4096) -> str:
    require(
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= maximum
        and "\x00" not in value,
        f"{label} is not bounded text",
    )
    return value


def exact_hex32(value: Any, label: str) -> str:
    require(isinstance(value, str) and HEX32.fullmatch(value) is not None, f"{label} is not canonical SHA-256 hex")
    return value


def parse_hex_u128(value: Any, label: str) -> int:
    require(
        isinstance(value, str)
        and re.fullmatch(r"0x[0-9a-f]+", value) is not None,
        f"{label} is not canonical hexadecimal",
    )
    parsed = int(value[2:], 16)
    require(0 < parsed < (1 << 128), f"{label} is outside u128")
    return parsed


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _load_reviewed_json(raw: bytes, label: str) -> Any:
    """Load reviewable JSON without silently normalizing ambiguous syntax."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in out, f"{label} repeats JSON member {key!r}")
            out[key] = value
        return out

    def reject_number(token: str) -> Any:
        raise VerificationError(f"{label} contains unsupported JSON number {token}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_number,
            # The frozen policy has integer budgets/ordinals only.  Rejecting
            # every fractional spelling also rejects overflow-to-infinity.
            parse_float=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not valid UTF-8 JSON: {error}") from error


_POLICY_BOOLEAN_PATHS = frozenset(
    {
        ("storage", "root_object", "granted"),
        ("storage", "attachments_inline"),
        ("storage", "attachments_ungranted"),
        ("artifact_profile", "runtime_ready"),
        ("negative_boundary", "runtime_ready"),
        ("negative_boundary", "profile_runtime_ready"),
        ("negative_boundary", "guest_execution"),
    }
)

_POLICY_INTEGER_PATHS = frozenset(
    {
        ("version",),
        ("storage", "block_bytes"),
        ("storage", "page_bytes"),
        ("storage", "geometry_profiles", "*", "*"),
        ("storage", "qemu_checkpoint_lifecycle", "*", "generation"),
        ("storage", "qemu_checkpoint_lifecycle", "*", "allocated_segments"),
        ("storage", "qemu_checkpoint_lifecycle", "*", "next_segment_generation"),
        ("storage", "qemu_checkpoint_lifecycle", "*", "allocation_root", "*"),
        ("storage", "qemu_checkpoint_lifecycle", "*", "authority_root", "*"),
        ("storage", "qemu_checkpoint_lifecycle", "*", "catalog_root", "*"),
        ("storage", "qemu_superseded_allocation_extents", "*", "*"),
        ("storage", "root_slot"),
        ("storage", "allowed_generations", "*"),
        ("storage", "root_rights"),
        ("storage", "root_object", "count"),
        ("storage", "root_object", "rights"),
        ("storage", "attachments_per_generation", "artifact"),
        ("storage", "attachments_per_generation", "artifact_evidence"),
        ("storage", "attachments_per_generation", "graph_evidence"),
        ("storage", "max_replacements"),
        ("trust", "evidence_version"),
        ("trust", "policy_generation"),
        ("leaf_policy", "generation"),
        ("leaf_policy", "signer_status"),
        ("leaf_policy", "trust_mode"),
        ("leaf_policy", "min_args"),
        ("leaf_policy", "max_args"),
        ("artifact_profile", "format_version"),
        ("artifact_profile", "manifest_version"),
        ("artifact_profile", "profile_code"),
        ("artifact_profile", "stage"),
        ("artifact_profile", "artifact_abi"),
        ("artifact_profile", "component_profile"),
        ("artifact_profile", "core_profile"),
        ("artifact_profile", "runtime_abi"),
        ("artifact_profile", "canonical_features"),
        ("artifact_profile", "signer_policy_kind"),
        ("artifact_profile", "signer_policy_version"),
        ("artifact_profile", "instance_limits", "memory_bytes"),
        ("artifact_profile", "instance_limits", "total_fuel"),
        ("artifact_profile", "instance_limits", "poll_quantum"),
        ("artifact_profile", "instance_limits", "resources"),
        ("graph", "version_ordinals", "*"),
        ("graph", "replacement_target"),
        ("graph", "nodes", "*", "ordinal"),
        ("graph", "nodes", "*", "nesting"),
        ("graph", "nodes", "*", "parent"),
        ("graph", "edges", "*", "*"),
        ("graph", "async_edges", "*", "*"),
        ("graph", "published_exports", "*", "*"),
        ("graph", "incident_edges", "*", "*"),
        ("graph", "resource_edges", "*", "*"),
        ("negative_boundary", "guest_calls"),
        ("negative_boundary", "ambient_lookup"),
        ("negative_boundary", "raw_durable_ids"),
        ("negative_boundary", "no_grant_direct_move"),
    }
)


def _policy_path_matches(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    return len(path) == len(pattern) and all(
        expected == "*" or expected == observed
        for observed, expected in zip(path, pattern)
    )


def _validate_policy_scalar_types(value: Any, path: tuple[str, ...] = ()) -> None:
    """Make every frozen numeric/boolean position type-strict.

    Python deliberately makes ``bool`` a subclass of ``int``.  A plain value
    comparison would consequently accept true for 1 and false for 0.
    """

    if isinstance(value, dict):
        for key, item in value.items():
            _validate_policy_scalar_types(item, (*path, key))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_policy_scalar_types(item, (*path, str(index)))
        return
    if type(value) is bool:
        require(path in _POLICY_BOOLEAN_PATHS, f"policy boolean appears at {'.'.join(path)}")
        return
    if type(value) is int:
        require(
            any(_policy_path_matches(path, pattern) for pattern in _POLICY_INTEGER_PATHS),
            f"policy integer appears at {'.'.join(path)}",
        )
        return
    require(not isinstance(value, float), f"policy number at {'.'.join(path)} is not an integer")


@dataclass(frozen=True)
class FrozenPolicy:
    path: Path
    document_sha256: str
    external_policy: bytes
    external_policy_sha256: str
    active_public_key: bytes
    policy_generation: int
    document: Mapping[str, Any]

    @property
    def authority_policy(self) -> Any:
        return migration.AuthorityPolicy(
            external_policy=self.external_policy,
            exact_objects=lambda state: select_c78_authority_objects(state, self),
        )


def _reject_content_pins(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = key.lower()
            forbidden = (
                "artifact_bytes",
                "descriptor_bytes",
                "evidence_bytes",
                "artifact_commitment",
                "descriptor_commitment",
                "version_commitment",
                "component_length",
                "artifact_length",
            )
            require(
                not any(token in lowered for token in forbidden),
                f"policy contains forbidden accepted-content pin at {'.'.join((*path, key))}",
            )
            _reject_content_pins(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_content_pins(item, (*path, str(index)))


def _validate_value_shape(value: Any, label: str) -> None:
    require(isinstance(value, dict), f"{label} is not a shape object")
    kind = value.get("kind")
    require(
        kind in {
            "bool", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
            "char", "string", "list", "tuple", "record", "flags", "enum", "option",
            "result", "variant", "future", "stream",
        },
        f"{label} has an unsupported shape kind",
    )
    if kind in {"bool", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "char", "string"}:
        exact_keys(value, {"kind"}, label)
    elif kind in {"list", "option"}:
        exact_keys(value, {"kind", "value"}, label)
        _validate_value_shape(value["value"], f"{label}.value")
    elif kind in {"future", "stream"}:
        exact_keys(value, {"kind", "value"}, label)
        if value["value"] is not None:
            _validate_value_shape(value["value"], f"{label}.value")
    elif kind == "tuple":
        exact_keys(value, {"kind", "values"}, label)
        require(isinstance(value["values"], list), f"{label}.values is not a list")
        for index, item in enumerate(value["values"]):
            _validate_value_shape(item, f"{label}.values[{index}]")
    elif kind == "record":
        exact_keys(value, {"kind", "fields"}, label)
        require(isinstance(value["fields"], list), f"{label}.fields is not a list")
        names = []
        for index, field in enumerate(value["fields"]):
            require(isinstance(field, dict), f"{label}.fields[{index}] is not an object")
            exact_keys(field, {"name", "value"}, f"{label}.fields[{index}]")
            names.append(exact_text(field["name"], f"{label}.fields[{index}].name", 128))
            _validate_value_shape(field["value"], f"{label}.fields[{index}].value")
        require(len(names) == len(set(names)), f"{label} repeats a field")
    elif kind in {"flags", "enum"}:
        exact_keys(value, {"kind", "names"}, label)
        require(isinstance(value["names"], list) and value["names"], f"{label}.names is empty")
        names = [exact_text(item, f"{label}.names", 128) for item in value["names"]]
        require(len(names) == len(set(names)), f"{label} repeats a name")
    elif kind == "result":
        exact_keys(value, {"kind", "ok", "error"}, label)
        for side in ("ok", "error"):
            if value[side] is not None:
                _validate_value_shape(value[side], f"{label}.{side}")
    elif kind == "variant":
        exact_keys(value, {"kind", "cases"}, label)
        require(isinstance(value["cases"], list) and value["cases"], f"{label}.cases is empty")
        names = []
        for index, case in enumerate(value["cases"]):
            exact_keys(case, {"name", "value"}, f"{label}.cases[{index}]")
            names.append(exact_text(case["name"], f"{label}.cases[{index}].name", 128))
            if case["value"] is not None:
                _validate_value_shape(case["value"], f"{label}.cases[{index}].value")
        require(len(names) == len(set(names)), f"{label} repeats a case")
    else:
        raise VerificationError(f"{label} contains a resource handle shape")


def _validate_entity(entity: Any, label: str) -> None:
    require(isinstance(entity, dict), f"{label} is not an entity object")
    kind = entity.get("kind")
    require(kind in {"function", "interface", "type"}, f"{label} has an unsupported or resource entity kind")
    if kind == "type":
        exact_keys(entity, {"kind", "value"}, label)
        _validate_value_shape(entity["value"], f"{label}.value")
    elif kind == "interface":
        exact_keys(entity, {"kind", "members"}, label)
        _validate_named_entities(entity["members"], f"{label}.members")
    else:
        exact_keys(entity, {"kind", "effect", "parameters", "result"}, label)
        require(entity["effect"] in {"sync", "async"}, f"{label}.effect differs")
        require(isinstance(entity["parameters"], list), f"{label}.parameters is not a list")
        names = []
        for index, parameter in enumerate(entity["parameters"]):
            exact_keys(parameter, {"name", "value"}, f"{label}.parameters[{index}]")
            names.append(exact_text(parameter["name"], f"{label}.parameters[{index}].name", 128))
            _validate_value_shape(parameter["value"], f"{label}.parameters[{index}].value")
        require(len(names) == len(set(names)), f"{label} repeats a parameter")
        if entity["result"] is not None:
            _validate_value_shape(entity["result"], f"{label}.result")


def _validate_named_entities(entities: Any, label: str) -> None:
    require(isinstance(entities, list), f"{label} is not a list")
    names = []
    for index, item in enumerate(entities):
        require(isinstance(item, dict), f"{label}[{index}] is not an object")
        exact_keys(item, {"name", "entity"}, f"{label}[{index}]")
        names.append(exact_text(item["name"], f"{label}[{index}].name", 256))
        _validate_entity(item["entity"], f"{label}[{index}].entity")
    require(len(names) == len(set(names)), f"{label} repeats a name")


_WIT_TOKEN = re.compile(
    r"\s+|//[^\n]*(?:\n|\Z)|/\*[\s\S]*?\*/|->|"
    r"[A-Za-z_][A-Za-z0-9_-]*|[0-9]+|[{}()<>,:;=@./]"
)


def _lex_wit(source: str) -> list[str]:
    tokens: list[str] = []
    at = 0
    while at < len(source):
        match = _WIT_TOKEN.match(source, at)
        require(match is not None, f"WIT source has an invalid token at byte {at}")
        token = match.group(0)
        at = match.end()
        if token.isspace() or token.startswith("//") or token.startswith("/*"):
            continue
        tokens.append(token)
    return tokens


class _WitParser:
    """Independent, fail-closed parser for the frozen policy's WIT subset."""

    _PRIMITIVES = {
        "bool", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
        "char", "string",
    }

    def __init__(self, source: str):
        self.tokens = _lex_wit(source)
        self.at = 0
        self.package = ""
        self.version = ""
        self.interfaces: dict[str, dict[str, Any]] = {}
        self.worlds: dict[str, dict[str, list[str]]] = {}

    def peek(self) -> str | None:
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def take(self) -> str:
        require(self.at < len(self.tokens), "WIT source ended unexpectedly")
        token = self.tokens[self.at]
        self.at += 1
        return token

    def expect(self, expected: str) -> None:
        observed = self.take()
        require(observed == expected, f"WIT expected {expected!r}, found {observed!r}")

    def identifier(self, label: str) -> str:
        token = self.take()
        require(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", token) is not None,
            f"WIT {label} is not an identifier",
        )
        return token

    def parse(self) -> dict[str, Any]:
        self.expect("package")
        namespace = self.identifier("package namespace")
        self.expect(":")
        name = self.identifier("package name")
        self.expect("@")
        version_parts = [self.take()]
        require(version_parts[0].isdigit(), "WIT package version is not numeric")
        for _ in range(2):
            self.expect(".")
            part = self.take()
            require(part.isdigit(), "WIT package version is not numeric")
            version_parts.append(part)
        self.expect(";")
        self.package = f"{namespace}:{name}"
        self.version = ".".join(version_parts)
        while self.peek() is not None:
            keyword = self.take()
            if keyword == "interface":
                self._parse_interface()
            elif keyword == "world":
                self._parse_world()
            else:
                raise VerificationError(f"WIT has unsupported top-level declaration {keyword!r}")
        require(self.interfaces and self.worlds, "WIT source lacks interface or world declarations")
        return {
            "package": self.package,
            "version": self.version,
            "interfaces": self.interfaces,
            "worlds": self.worlds,
        }

    def _parse_type(self) -> Any:
        name = self.identifier("type")
        require(name not in {"own", "borrow", "resource"}, "WIT source contains a resource handle type")
        if name in self._PRIMITIVES:
            return {"kind": name}
        if self.peek() != "<":
            return {"ref": name}
        self.expect("<")
        values: list[Any] = []
        if self.peek() != ">":
            while True:
                values.append(self._parse_type())
                if self.peek() != ",":
                    break
                self.expect(",")
        self.expect(">")
        if name in {"list", "option"}:
            require(len(values) == 1, f"WIT {name} requires exactly one type")
            return {"kind": name, "value": values[0]}
        if name in {"future", "stream"}:
            require(len(values) <= 1, f"WIT {name} has too many types")
            return {"kind": name, "value": values[0] if values else None}
        if name == "tuple":
            return {"kind": "tuple", "values": values}
        if name == "result":
            require(1 <= len(values) <= 2, "WIT result requires one or two types")
            return {
                "kind": "result",
                "ok": values[0],
                "error": values[1] if len(values) == 2 else None,
            }
        raise VerificationError(f"WIT has unsupported generic type {name!r}")

    def _parse_named_type_body(self, keyword: str) -> Any:
        self.expect("{")
        if keyword in {"enum", "flags"}:
            names: list[str] = []
            while self.peek() != "}":
                names.append(self.identifier(f"{keyword} member"))
                if self.peek() == ",":
                    self.expect(",")
                else:
                    require(self.peek() == "}", f"WIT {keyword} member lacks a comma")
            self.expect("}")
            require(names and len(names) == len(set(names)), f"WIT {keyword} is empty or repeats a name")
            return {"kind": keyword, "names": names}
        if keyword == "record":
            fields: list[dict[str, Any]] = []
            while self.peek() != "}":
                field = self.identifier("record field")
                self.expect(":")
                fields.append({"name": field, "value": self._parse_type()})
                if self.peek() == ",":
                    self.expect(",")
                else:
                    require(self.peek() == "}", "WIT record field lacks a comma")
            self.expect("}")
            require(len({item["name"] for item in fields}) == len(fields), "WIT record repeats a field")
            return {"kind": "record", "fields": fields}
        if keyword == "variant":
            cases: list[dict[str, Any]] = []
            while self.peek() != "}":
                case = self.identifier("variant case")
                value = None
                if self.peek() == "(":
                    self.expect("(")
                    value = self._parse_type()
                    self.expect(")")
                cases.append({"name": case, "value": value})
                if self.peek() == ",":
                    self.expect(",")
                else:
                    require(self.peek() == "}", "WIT variant case lacks a comma")
            self.expect("}")
            require(cases and len({item["name"] for item in cases}) == len(cases), "WIT variant is empty or repeats a case")
            return {"kind": "variant", "cases": cases}
        raise VerificationError(f"WIT has unsupported named type {keyword!r}")

    def _resolve_shape(
        self,
        value: Any,
        definitions: Mapping[str, Any],
        stack: tuple[str, ...] = (),
    ) -> Any:
        if "ref" in value:
            name = value["ref"]
            require(name in definitions, f"WIT references unknown type {name!r}")
            require(name not in stack, f"WIT type alias cycle reaches {name!r}")
            return self._resolve_shape(definitions[name], definitions, (*stack, name))
        kind = value["kind"]
        if kind in self._PRIMITIVES or kind in {"flags", "enum"}:
            return copy.deepcopy(value)
        if kind in {"list", "option"}:
            return {"kind": kind, "value": self._resolve_shape(value["value"], definitions, stack)}
        if kind in {"future", "stream"}:
            return {
                "kind": kind,
                "value": None if value["value"] is None else self._resolve_shape(value["value"], definitions, stack),
            }
        if kind == "tuple":
            return {"kind": kind, "values": [self._resolve_shape(item, definitions, stack) for item in value["values"]]}
        if kind == "record":
            return {
                "kind": kind,
                "fields": [
                    {"name": item["name"], "value": self._resolve_shape(item["value"], definitions, stack)}
                    for item in value["fields"]
                ],
            }
        if kind == "result":
            return {
                "kind": kind,
                "ok": None if value["ok"] is None else self._resolve_shape(value["ok"], definitions, stack),
                "error": None if value["error"] is None else self._resolve_shape(value["error"], definitions, stack),
            }
        if kind == "variant":
            return {
                "kind": kind,
                "cases": [
                    {
                        "name": item["name"],
                        "value": None if item["value"] is None else self._resolve_shape(item["value"], definitions, stack),
                    }
                    for item in value["cases"]
                ],
            }
        raise VerificationError(f"WIT normalization encountered unsupported type {kind!r}")

    def _parse_interface(self) -> None:
        name = self.identifier("interface name")
        require(name not in self.interfaces, f"WIT repeats interface {name!r}")
        self.expect("{")
        definitions: dict[str, Any] = {}
        declarations: list[tuple[str, str, Any]] = []
        while self.peek() != "}":
            token = self.take()
            if token == "resource":
                raise VerificationError("WIT source contains a resource declaration")
            if token in {"enum", "flags", "record", "variant"}:
                member_name = self.identifier(f"{token} name")
                require(member_name not in definitions, f"WIT repeats type {member_name!r}")
                shape = self._parse_named_type_body(token)
                definitions[member_name] = shape
                declarations.append((member_name, "type", shape))
                continue
            if token == "type":
                member_name = self.identifier("type alias")
                require(member_name not in definitions, f"WIT repeats type {member_name!r}")
                self.expect("=")
                shape = self._parse_type()
                self.expect(";")
                definitions[member_name] = shape
                declarations.append((member_name, "type", shape))
                continue
            member_name = token
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", member_name) is not None, "WIT function name is invalid")
            self.expect(":")
            effect = "sync"
            if self.peek() == "async":
                self.expect("async")
                effect = "async"
            self.expect("func")
            self.expect("(")
            parameters: list[dict[str, Any]] = []
            if self.peek() != ")":
                while True:
                    parameter = self.identifier("function parameter")
                    self.expect(":")
                    parameters.append({"name": parameter, "value": self._parse_type()})
                    if self.peek() != ",":
                        break
                    self.expect(",")
            self.expect(")")
            result = None
            if self.peek() == "->":
                self.expect("->")
                result = self._parse_type()
            self.expect(";")
            declarations.append(
                (member_name, "function", {"effect": effect, "parameters": parameters, "result": result})
            )
        self.expect("}")
        names = [item[0] for item in declarations]
        require(len(names) == len(set(names)), f"WIT interface {name!r} repeats a member")
        members: list[dict[str, Any]] = []
        for member_name, kind, entity in declarations:
            if kind == "type":
                normalized = {"kind": "type", "value": self._resolve_shape(entity, definitions, (member_name,))}
            else:
                normalized = {
                    "kind": "function",
                    "effect": entity["effect"],
                    "parameters": [
                        {"name": item["name"], "value": self._resolve_shape(item["value"], definitions)}
                        for item in entity["parameters"]
                    ],
                    "result": None if entity["result"] is None else self._resolve_shape(entity["result"], definitions),
                }
            members.append({"name": member_name, "entity": normalized})
        self.interfaces[name] = {
            "name": f"{self.package}/{name}@{self.version}",
            "members": members,
        }

    def _parse_world(self) -> None:
        name = self.identifier("world name")
        require(name not in self.worlds, f"WIT repeats world {name!r}")
        self.expect("{")
        sides: dict[str, list[str]] = {"imports": [], "exports": []}
        while self.peek() != "}":
            direction = self.take()
            require(direction in {"import", "export"}, f"WIT world has unsupported declaration {direction!r}")
            interface = self.identifier("world interface")
            self.expect(";")
            require(interface in self.interfaces, f"WIT world references unknown interface {interface!r}")
            side = "imports" if direction == "import" else "exports"
            fq_name = self.interfaces[interface]["name"]
            require(fq_name not in sides[side], f"WIT world repeats {direction} {interface!r}")
            sides[side].append(fq_name)
        self.expect("}")
        self.worlds[name] = sides


def parse_wit_policy_source(source: Any) -> dict[str, Any]:
    exact_text(source, "C7.8 WIT source", 64 * 1024)
    return _WitParser(source).parse()


def load_policy(path: Path, trust_anchor_hex: str | None) -> FrozenPolicy:
    raw = path.read_bytes()
    require(len(raw) <= 128 * 1024, "C7.8 policy exceeds its review bound")
    document = _load_reviewed_json(raw, "C7.8 policy")
    require(isinstance(document, dict), "C7.8 policy is not a JSON object")
    _reject_content_pins(document)
    exact_keys(
        document,
        {"schema", "version", "scope", "storage", "trust", "leaf_policy", "artifact_profile", "wit", "graph", "negative_boundary"},
        "C7.8 policy",
    )
    _validate_policy_scalar_types(document)
    require(
        document["schema"] == POLICY_SCHEMA
        and document["version"] == 1
        and document["scope"] == SCOPE,
        "C7.8 policy schema/version/scope differs",
    )

    storage = document["storage"]
    exact_keys(
        storage,
        {
            "block_bytes", "page_bytes", "external_policy_utf8", "external_policy_sha256",
            "geometry_profiles", "qemu_checkpoint_lifecycle",
            "qemu_superseded_allocation_extents",
            "graph_space", "root_slot", "allowed_generations", "root_rights",
            "stored_object_resource_kind", "object_kinds", "attachments_per_generation",
            "root_object", "ordered_attachment_kinds", "attachments_inline",
            "attachments_ungranted", "max_replacements",
        },
        "C7.8 storage policy",
    )
    require(storage["block_bytes"] == BLOCK and storage["page_bytes"] == PAGE, "C7.8 media geometry differs")
    geometry_profiles = storage["geometry_profiles"]
    require(isinstance(geometry_profiles, dict), "C7.8 geometry profiles are not an object")
    exact_keys(geometry_profiles, {"corpus", "qemu"}, "C7.8 geometry profiles")
    geometry_fields = {
        "managed_region_pages", "initial_range_pages", "initial_segments",
        "initial_block_count", "admitted_range_pages", "admitted_segments",
        "cleaner_reserve_segments",
    }
    expected_geometries = {
        "corpus": {
            "managed_region_pages": 32784,
            "initial_range_pages": 32784,
            "initial_segments": 32,
            "initial_block_count": 262272,
            "admitted_range_pages": 32784,
            "admitted_segments": 32,
            "cleaner_reserve_segments": 4,
        },
        "qemu": {
            "managed_region_pages": 31760,
            "initial_range_pages": 8208,
            "initial_segments": 8,
            "initial_block_count": 65664,
            "admitted_range_pages": 14352,
            "admitted_segments": 14,
            "cleaner_reserve_segments": 2,
        },
    }
    for name, expected_geometry in expected_geometries.items():
        exact_keys(geometry_profiles[name], geometry_fields, f"C7.8 {name} geometry")
        require(geometry_profiles[name] == expected_geometry, f"C7.8 {name} geometry differs")
    qemu_lifecycle = storage["qemu_checkpoint_lifecycle"]
    lifecycle_fields = {
        "generation", "classification", "allocated_segments",
        "next_segment_generation", "allocation_root", "authority_root",
        "catalog_root",
    }
    expected_lifecycle = [
        {
            "generation": 3,
            "classification": "vacant",
            "allocated_segments": 2,
            "next_segment_generation": 3,
            "allocation_root": [1, 2, 1, 3],
            "authority_root": [0, 1, 2, 2],
            "catalog_root": [0, 1, 1, 2],
        },
        {
            "generation": 4,
            "classification": "g0",
            "allocated_segments": 4,
            "next_segment_generation": 5,
            "allocation_root": [3, 4, 4, 4],
            "authority_root": [3, 4, 3, 4],
            "catalog_root": [3, 4, 2, 4],
        },
        {
            "generation": 5,
            "classification": "g1",
            "allocated_segments": 6,
            "next_segment_generation": 7,
            "allocation_root": [5, 6, 4, 5],
            "authority_root": [5, 6, 3, 5],
            "catalog_root": [5, 6, 2, 5],
        },
    ]
    require(
        isinstance(qemu_lifecycle, list) and len(qemu_lifecycle) == 3,
        "C7.8 QEMU checkpoint lifecycle cardinality differs",
    )
    for index, entry in enumerate(qemu_lifecycle):
        require(isinstance(entry, dict), "C7.8 QEMU checkpoint lifecycle entry is not an object")
        exact_keys(entry, lifecycle_fields, f"C7.8 QEMU checkpoint lifecycle[{index}]")
    require(
        qemu_lifecycle == expected_lifecycle,
        "C7.8 QEMU checkpoint lifecycle differs from the reviewed native sequence",
    )
    require(
        storage["qemu_superseded_allocation_extents"]
        == [[0, 1, 8, 3, 2], [1, 2, 2, 1, 3]],
        "C7.8 QEMU superseded allocation extent set differs",
    )
    external_policy = storage["external_policy_utf8"].encode("utf-8")
    policy_sha = exact_hex32(storage["external_policy_sha256"], "C7.8 policy-v3 digest")
    require(hashlib.sha256(external_policy).hexdigest() == policy_sha, "C7.8 policy-v3 bytes/hash differ")
    require(
        external_policy.startswith(b"vibeos.storage-v2.external-policy.v3\0")
        and external_policy.count(b"\0") == 4,
        "C7.8 external policy is not the exact policy-v3 framing",
    )
    require(parse_hex_u128(storage["graph_space"], "graph space") == GRAPH_SPACE, "C7.8 graph space differs")
    require(
        storage["root_slot"] == 0
        and storage["allowed_generations"] == [0, 1]
        and storage["root_rights"] == READ
        and parse_hex_u128(storage["stored_object_resource_kind"], "stored resource kind") == STORED_OBJECT_RESOURCE_KIND
        and storage["attachments_inline"] is True
        and storage["attachments_ungranted"] is True
        and storage["max_replacements"] == 1,
        "C7.8 durable graph policy expanded",
    )
    require(
        storage["object_kinds"]
        == {
            "artifact": f"0x{CMP1:08x}",
            "artifact_evidence": f"0x{CME1:08x}",
            "graph_evidence": f"0x{CGE1:08x}",
            "graph_version": f"0x{CGV1:08x}",
        }
        and storage["attachments_per_generation"]
        == {"artifact": 3, "artifact_evidence": 3, "graph_evidence": 1}
        and storage["root_object"]
        == {"kind": f"0x{CGV1:08x}", "count": 1, "granted": True, "rights": READ}
        and storage["ordered_attachment_kinds"]
        == [
            "artifact", "artifact", "artifact", "artifact_evidence",
            "artifact_evidence", "artifact_evidence", "graph_evidence",
        ],
        "C7.8 attachment policy differs",
    )

    trust = document["trust"]
    exact_keys(trust, {"signature_scheme", "evidence_version", "policy_generation", "active_public_key"}, "C7.8 trust policy")
    key_hex = exact_hex32(trust["active_public_key"], "C7.8 active public key")
    require(
        trust["signature_scheme"] == "ed25519"
        and trust["evidence_version"] == 1
        and trust["policy_generation"] == 1,
        "C7.8 trust profile differs",
    )
    if trust_anchor_hex is not None:
        require(HEX32.fullmatch(trust_anchor_hex) is not None, "explicit trust anchor is not canonical lowercase hex")
        require(trust_anchor_hex == key_hex, "policy key differs from explicit trust anchor")
    active_key = bytes.fromhex(key_hex)
    c73.strict_point(active_key, "C7.8 active trust anchor")

    leaf = document["leaf_policy"]
    exact_keys(
        leaf,
        {
            "operator_role_domain", "generation", "signer_status", "trust_mode",
            "command_name", "entrypoint", "min_args", "max_args", "streams",
            "interface_ceilings",
        },
        "C7.8 leaf policy",
    )
    exact_keys(leaf["streams"], {"stdin", "stdout", "stderr"}, "C7.8 leaf streams")
    require(
        leaf["operator_role_domain"] == "vibeos.c76.acceptance.operator-role.v1\0"
        and leaf["generation"] == 1
        and leaf["signer_status"] == 1
        and leaf["trust_mode"] == 2
        and leaf["command_name"] == "c76-node"
        and leaf["entrypoint"] == "run"
        and leaf["min_args"] == 0
        and leaf["max_args"] == 0
        and leaf["streams"] == {"stdin": "closed", "stdout": "closed", "stderr": "closed"}
        and leaf["interface_ceilings"] == [],
        "C7.8 leaf operator policy expanded",
    )

    profile = document["artifact_profile"]
    exact_keys(
        profile,
        {
            "format_version", "manifest_version", "profile_code", "stage", "artifact_abi",
            "component_profile", "core_profile", "runtime_abi", "canonical_features",
            "signer_policy_kind", "signer_policy_version", "revisions", "instance_limits",
            "runtime_ready",
        },
        "C7.8 artifact profile",
    )
    expected_profile = c71.PROFILES[2]
    require(
        (
            profile["format_version"], profile["manifest_version"], profile["profile_code"],
            profile["stage"], profile["artifact_abi"], profile["component_profile"],
            profile["core_profile"], profile["runtime_abi"], profile["canonical_features"],
            profile["signer_policy_kind"], profile["signer_policy_version"],
            tuple(profile["revisions"]), profile["runtime_ready"],
        )
        == (
            1, 1, 2, expected_profile.stage, expected_profile.artifact_abi,
            expected_profile.component_profile, expected_profile.core_profile,
            expected_profile.runtime_abi, expected_profile.canonical_features, 2, 1,
            expected_profile.revisions, False,
        ),
        "C7.8 artifact ABI/profile/revisions expanded",
    )
    exact_keys(profile["instance_limits"], {"memory_bytes", "total_fuel", "poll_quantum", "resources"}, "C7.8 limits")
    require(
        profile["instance_limits"]
        == {"memory_bytes": 65536, "total_fuel": 1000, "poll_quantum": 100, "resources": 8},
        "C7.8 instance limits differ",
    )

    wit = document["wit"]
    exact_keys(wit, {"package", "version", "source", "interface"}, "C7.8 WIT policy")
    require(
        wit["package"] == "test:c65-chain"
        and wit["version"] == "1.0.0"
        and wit["source"].startswith("package test:c65-chain@1.0.0;\n")
        and wit["source"].endswith("}\n"),
        "C7.8 WIT identity/source framing differs",
    )
    parsed_wit = parse_wit_policy_source(wit["source"])
    require(
        parsed_wit["package"] == wit["package"]
        and parsed_wit["version"] == wit["version"]
        and len(parsed_wit["interfaces"]) == 1,
        "C7.8 WIT source package/interface set differs",
    )
    exact_keys(wit["interface"], {"name", "members"}, "C7.8 interface policy")
    require(wit["interface"]["name"] == "test:c65-chain/pipe@1.0.0", "C7.8 interface identity differs")
    _validate_named_entities(wit["interface"]["members"], "C7.8 interface members")
    parsed_interface = next(iter(parsed_wit["interfaces"].values()))
    require(
        parsed_interface == wit["interface"],
        "C7.8 WIT source normalization differs from the reviewed interface tree",
    )
    _validate_named_entities(parsed_interface["members"], "C7.8 source-derived interface members")

    graph = document["graph"]
    exact_keys(
        graph,
        {
            "name", "version_ordinals", "replacement_target", "replacement_action",
            "incident_edge_action", "nodes", "edges", "async_edges", "published_exports",
            "incident_edges", "resource_edges", "external_imports",
        },
        "C7.8 graph policy",
    )
    require(
        graph["name"] == "c76-chain"
        and graph["version_ordinals"] == [0, 1]
        and graph["replacement_target"] == 1
        and graph["replacement_action"] == "PolicyCancel"
        and graph["incident_edge_action"] == "RecreateFresh"
        and graph["edges"] == [[0, 0, 1, 0], [1, 0, 2, 0]]
        and graph["resource_edges"] == []
        and graph["external_imports"] == []
        and graph["async_edges"] == [[0, 0, 1, 0, 1, 4, 4], [1, 0, 2, 0, 1, 4, 4]]
        and graph["published_exports"] == [[2, 0]]
        and graph["incident_edges"] == [[0, 0, 1, 0, 1], [1, 0, 2, 0, 1]],
        "C7.8 graph topology/replacement policy differs",
    )
    require(isinstance(graph["nodes"], list) and len(graph["nodes"]) == 3, "C7.8 node policy differs")
    expected_nodes = (
        (0, "source", "test:c65-chain/source@1.0.0", [], [wit["interface"]["name"]]),
        (1, "relay", "test:c65-chain/relay@1.0.0", [wit["interface"]["name"]], [wit["interface"]["name"]]),
        (2, "sink", "test:c65-chain/sink@1.0.0", [wit["interface"]["name"]], [wit["interface"]["name"]]),
    )
    graph_world_names = {
        node["world"].removeprefix(f"{parsed_wit['package']}/").removesuffix(
            f"@{parsed_wit['version']}"
        )
        for node in graph["nodes"]
        if isinstance(node, dict) and isinstance(node.get("world"), str)
    }
    require(
        set(parsed_wit["worlds"]) == graph_world_names
        and len(parsed_wit["worlds"]) == len(graph["nodes"]),
        "C7.8 WIT source world set differs from the exact graph node worlds",
    )
    for node, expected in zip(graph["nodes"], expected_nodes):
        exact_keys(node, {"ordinal", "label", "world", "nesting", "parent", "imports", "exports"}, "C7.8 node")
        require(
            (
                node["ordinal"], node["label"], node["world"], node["nesting"], node["parent"],
                node["imports"], node["exports"],
            )
            == (*expected[:3], 0, 0, expected[3], expected[4]),
            "C7.8 node identity/world contract expanded",
        )
        world_name = node["world"].removeprefix(f"{parsed_wit['package']}/").removesuffix(
            f"@{parsed_wit['version']}"
        )
        require(
            node["world"] == f"{parsed_wit['package']}/{world_name}@{parsed_wit['version']}"
            and world_name in parsed_wit["worlds"]
            and parsed_wit["worlds"][world_name]
            == {"imports": node["imports"], "exports": node["exports"]},
            "C7.8 graph node differs from its independently parsed WIT world",
        )

    boundary = document["negative_boundary"]
    exact_keys(
        boundary,
        {
            "runtime_ready", "profile_runtime_ready", "guest_calls", "guest_execution",
            "ambient_lookup", "raw_durable_ids", "no_grant_direct_move",
        },
        "C7.8 negative boundary",
    )
    require(
        boundary
        == {
            "runtime_ready": False,
            "profile_runtime_ready": False,
            "guest_calls": 0,
            "guest_execution": False,
            "ambient_lookup": 0,
            "raw_durable_ids": 0,
            "no_grant_direct_move": 0,
        },
        "C7.8 negative authorization boundary expanded",
    )
    return FrozenPolicy(
        path=path,
        document_sha256=hashlib.sha256(raw).hexdigest(),
        external_policy=external_policy,
        external_policy_sha256=policy_sha,
        active_public_key=active_key,
        policy_generation=trust["policy_generation"],
        document=document,
    )


def _hash_length(hasher: Any, length: int) -> None:
    require(0 <= length < (1 << 64), "world-contract length exceeds u64")
    hasher.update(struct.pack("<Q", length))


def _hash_text(hasher: Any, value: str) -> None:
    encoded = value.encode("utf-8")
    _hash_length(hasher, len(encoded))
    hasher.update(encoded)


VALUE_TAGS = {
    "bool": 0, "u8": 1, "u16": 2, "u32": 3, "u64": 4,
    "s8": 5, "s16": 6, "s32": 7, "s64": 8, "char": 9,
    "string": 10, "list": 11, "tuple": 12, "record": 13,
    "flags": 14, "enum": 15, "option": 16, "result": 17,
    "variant": 18, "future": 19, "stream": 20, "own": 21, "borrow": 22,
}


def _hash_optional_shape(hasher: Any, value: Any) -> None:
    if value is None:
        hasher.update(b"\x00")
    else:
        hasher.update(b"\x01")
        _hash_value_shape(hasher, value)


def _hash_value_shape(hasher: Any, value: Mapping[str, Any]) -> None:
    kind = value["kind"]
    hasher.update(bytes((VALUE_TAGS[kind],)))
    if kind in {"list", "option"}:
        _hash_value_shape(hasher, value["value"])
    elif kind in {"future", "stream"}:
        _hash_optional_shape(hasher, value["value"])
    elif kind == "tuple":
        _hash_length(hasher, len(value["values"]))
        for item in value["values"]:
            _hash_value_shape(hasher, item)
    elif kind == "record":
        _hash_length(hasher, len(value["fields"]))
        for field in value["fields"]:
            _hash_text(hasher, field["name"])
            _hash_value_shape(hasher, field["value"])
    elif kind in {"flags", "enum"}:
        _hash_length(hasher, len(value["names"]))
        for name in value["names"]:
            _hash_text(hasher, name)
    elif kind == "result":
        _hash_optional_shape(hasher, value["ok"])
        _hash_optional_shape(hasher, value["error"])
    elif kind == "variant":
        _hash_length(hasher, len(value["cases"]))
        for case in value["cases"]:
            _hash_text(hasher, case["name"])
            _hash_optional_shape(hasher, case["value"])
    elif kind in {"own", "borrow"}:
        _hash_text(hasher, value["resource"])


def _hash_named_entities(hasher: Any, entities: Sequence[Mapping[str, Any]]) -> None:
    _hash_length(hasher, len(entities))
    for item in entities:
        _hash_text(hasher, item["name"])
        _hash_entity(hasher, item["entity"])


def _hash_entity(hasher: Any, entity: Mapping[str, Any]) -> None:
    kind = entity["kind"]
    if kind == "function":
        hasher.update(b"\x00")
        hasher.update(b"\x01" if entity["effect"] == "async" else b"\x00")
        parameters = entity["parameters"]
        _hash_length(hasher, len(parameters))
        for parameter in parameters:
            _hash_text(hasher, parameter["name"])
            _hash_value_shape(hasher, parameter["value"])
        _hash_optional_shape(hasher, entity["result"])
    elif kind == "interface":
        hasher.update(b"\x01")
        _hash_named_entities(hasher, entity["members"])
    elif kind == "resource":
        hasher.update(b"\x02")
    else:
        hasher.update(b"\x03")
        _hash_value_shape(hasher, entity["value"])


def world_contract_commitment(policy: FrozenPolicy, node: Mapping[str, Any]) -> bytes:
    interface = policy.document["wit"]["interface"]
    entity = {"kind": "interface", "members": interface["members"]}
    tables = {
        "imports": [{"name": name, "entity": entity} for name in node["imports"]],
        "exports": [{"name": name, "entity": entity} for name in node["exports"]],
    }
    hasher = hashlib.sha256()
    hasher.update(WORLD_CONTRACT_DOMAIN)
    _hash_text(hasher, node["world"])
    for tag, side in ((0, "imports"), (1, "exports")):
        hasher.update(bytes((tag,)))
        _hash_named_entities(hasher, sorted(tables[side], key=lambda item: item["name"]))
    return hasher.digest()


ARTIFACT_POLICY_DOMAIN = b"vibeos.component-artifact.operator-policy.v1\0"
GRAPH_POLICY_DOMAIN = b"vibeos.component-graph.operator-policy.v1\0"


def _put_u8(hasher: Any, value: int) -> None:
    require(0 <= value <= 0xFF, "policy u8 is out of range")
    hasher.update(bytes((value,)))


def _put_u16(hasher: Any, value: int) -> None:
    require(0 <= value <= 0xFFFF, "policy u16 is out of range")
    hasher.update(struct.pack("<H", value))


def _put_u32(hasher: Any, value: int) -> None:
    require(0 <= value <= 0xFFFF_FFFF, "policy u32 is out of range")
    hasher.update(struct.pack("<I", value))


def _put_u64(hasher: Any, value: int) -> None:
    require(0 <= value <= 0xFFFF_FFFF_FFFF_FFFF, "policy u64 is out of range")
    hasher.update(struct.pack("<Q", value))


def _put_text(hasher: Any, value: str) -> None:
    encoded = value.encode("utf-8")
    _put_u32(hasher, len(encoded))
    hasher.update(encoded)


def _encode_artifact_profile(hasher: Any, policy: FrozenPolicy) -> None:
    profile = policy.document["artifact_profile"]
    for value in (
        profile["artifact_abi"],
        profile["component_profile"],
        profile["core_profile"],
        profile["runtime_abi"],
    ):
        _put_u16(hasher, value)
    _put_u64(hasher, profile["canonical_features"])
    _put_u16(hasher, profile["stage"])
    for revision in profile["revisions"]:
        _put_text(hasher, revision)


def _encode_graph_profile(hasher: Any, policy: FrozenPolicy) -> None:
    profile = policy.document["artifact_profile"]
    for value in (
        profile["artifact_abi"],
        profile["component_profile"],
        profile["core_profile"],
        profile["runtime_abi"],
        profile["stage"],
    ):
        _put_u16(hasher, value)
    _put_u64(hasher, profile["canonical_features"])
    for revision in profile["revisions"]:
        _put_text(hasher, revision)


def _encode_policy_optional_shape(hasher: Any, value: Any) -> None:
    if value is None:
        _put_u8(hasher, 0)
    else:
        _put_u8(hasher, 1)
        _encode_policy_value_shape(hasher, value)


def _encode_policy_value_shape(hasher: Any, value: Mapping[str, Any]) -> None:
    kind = value["kind"]
    _put_u8(hasher, VALUE_TAGS[kind])
    if kind in {"list", "option"}:
        _encode_policy_value_shape(hasher, value["value"])
    elif kind in {"future", "stream"}:
        _encode_policy_optional_shape(hasher, value["value"])
    elif kind == "tuple":
        _put_u32(hasher, len(value["values"]))
        for item in value["values"]:
            _encode_policy_value_shape(hasher, item)
    elif kind == "record":
        _put_u32(hasher, len(value["fields"]))
        for field in value["fields"]:
            _put_text(hasher, field["name"])
            _encode_policy_value_shape(hasher, field["value"])
    elif kind in {"flags", "enum"}:
        _put_u32(hasher, len(value["names"]))
        for name in value["names"]:
            _put_text(hasher, name)
    elif kind == "result":
        _encode_policy_optional_shape(hasher, value["ok"])
        _encode_policy_optional_shape(hasher, value["error"])
    elif kind == "variant":
        _put_u32(hasher, len(value["cases"]))
        for case in value["cases"]:
            _put_text(hasher, case["name"])
            _encode_policy_optional_shape(hasher, case["value"])
    elif kind in {"own", "borrow"}:
        _put_text(hasher, value["resource"])


def _encode_policy_entity(hasher: Any, entity: Mapping[str, Any]) -> None:
    kind = entity["kind"]
    if kind == "function":
        _put_u8(hasher, 0)
        _put_u8(hasher, 1 if entity["effect"] == "async" else 0)
        _put_u32(hasher, len(entity["parameters"]))
        for parameter in entity["parameters"]:
            _put_text(hasher, parameter["name"])
            _encode_policy_value_shape(hasher, parameter["value"])
        _encode_policy_optional_shape(hasher, entity["result"])
    elif kind == "interface":
        _put_u8(hasher, 1)
        _encode_policy_named_entities(hasher, entity["members"])
    elif kind == "resource":
        _put_u8(hasher, 2)
        _put_u8(hasher, 0)
    else:
        _put_u8(hasher, 2)
        _put_u8(hasher, 1)
        _encode_policy_value_shape(hasher, entity["value"])


def _encode_policy_named_entities(hasher: Any, entities: Sequence[Mapping[str, Any]]) -> None:
    ordered = sorted(entities, key=lambda item: item["name"])
    require(
        len({item["name"] for item in ordered}) == len(ordered),
        "policy entity names are not unique",
    )
    _put_u32(hasher, len(ordered))
    for item in ordered:
        _put_text(hasher, item["name"])
        _encode_policy_entity(hasher, item["entity"])


def _world_policy_entities(policy: FrozenPolicy, node: Mapping[str, Any], side: str) -> list[dict[str, Any]]:
    interface = policy.document["wit"]["interface"]
    entity = {"kind": "interface", "members": interface["members"]}
    return [{"name": name, "entity": entity} for name in node[side]]


def operator_role(policy: FrozenPolicy) -> bytes:
    return hashlib.sha256(
        policy.document["leaf_policy"]["operator_role_domain"].encode("utf-8")
    ).digest()


def leaf_policy_commitment(policy: FrozenPolicy, node: Mapping[str, Any]) -> bytes:
    leaf = policy.document["leaf_policy"]
    limits = policy.document["artifact_profile"]["instance_limits"]
    hasher = hashlib.sha256()
    hasher.update(ARTIFACT_POLICY_DOMAIN)
    _put_u16(hasher, 1)
    _put_u64(hasher, leaf["generation"])
    hasher.update(operator_role(policy))
    _put_u16(hasher, 1)
    hasher.update(policy.active_public_key)
    _put_u8(hasher, leaf["signer_status"])
    _put_u8(hasher, leaf["trust_mode"])
    _encode_artifact_profile(hasher, policy)
    _put_text(hasher, leaf["command_name"])
    _put_text(hasher, leaf["entrypoint"])
    _put_u64(hasher, leaf["min_args"])
    _put_u64(hasher, leaf["max_args"])
    _put_text(hasher, node["world"])
    _encode_policy_named_entities(hasher, _world_policy_entities(policy, node, "imports"))
    _encode_policy_named_entities(hasher, _world_policy_entities(policy, node, "exports"))
    _put_u64(hasher, limits["memory_bytes"])
    _put_u64(hasher, limits["total_fuel"])
    _put_u64(hasher, limits["poll_quantum"])
    _put_u16(hasher, limits["resources"])
    # Production CommandStreamMode canonical encoding is Required=1,
    # Optional=2, Closed=3.
    stream_raw = {"required": 1, "optional": 2, "closed": 3}
    for stream in ("stdin", "stdout", "stderr"):
        _put_u8(hasher, stream_raw[leaf["streams"][stream]])
    _put_u16(hasher, len(leaf["interface_ceilings"]))
    require(not leaf["interface_ceilings"], "C7.8 interface ceiling expanded")
    wit = policy.document["wit"]["source"].encode("utf-8")
    _put_u64(hasher, len(wit))
    hasher.update(wit)
    digest = hasher.digest()
    require(any(digest), "leaf policy commitment is the zero sentinel")
    return digest


def graph_policy_commitment(policy: FrozenPolicy) -> bytes:
    leaf = policy.document["leaf_policy"]
    graph = policy.document["graph"]
    hasher = hashlib.sha256()
    hasher.update(GRAPH_POLICY_DOMAIN)
    _put_u16(hasher, 1)
    _put_u64(hasher, leaf["generation"])
    hasher.update(operator_role(policy))
    _put_u16(hasher, 1)
    hasher.update(policy.active_public_key)
    _put_u8(hasher, leaf["signer_status"])
    _encode_graph_profile(hasher, policy)
    _put_text(hasher, graph["name"])
    _put_u16(hasher, len(graph["nodes"]))
    for node in graph["nodes"]:
        _put_text(hasher, node["label"])
        if node["nesting"] == 0:
            _put_u8(hasher, 0)
            _put_u16(hasher, 0)
        else:
            _put_u8(hasher, 1)
            _put_u16(hasher, node["parent"])
        hasher.update(leaf_policy_commitment(policy, node))
    _put_u16(hasher, len(graph["edges"]))
    for edge in graph["edges"]:
        for endpoint in edge:
            _put_u16(hasher, endpoint)
    _put_u16(hasher, len(graph["resource_edges"]))
    require(not graph["resource_edges"], "C7.8 resource edges expanded")
    _put_u16(hasher, len(graph["external_imports"]))
    require(not graph["external_imports"], "C7.8 external imports expanded")
    _put_u16(hasher, len(graph["published_exports"]))
    for endpoint in graph["published_exports"]:
        for value in endpoint:
            _put_u16(hasher, value)
    _put_u16(hasher, graph["replacement_target"])
    _put_u16(hasher, policy.document["storage"]["max_replacements"])
    _put_u8(hasher, 1)  # PolicyCancel
    _put_u16(hasher, len(graph["incident_edges"]))
    for incident in graph["incident_edges"]:
        for endpoint in incident[:4]:
            _put_u16(hasher, endpoint)
        _put_u8(hasher, 1)  # RecreateFresh
    digest = hasher.digest()
    require(any(digest), "graph policy commitment is the zero sentinel")
    return digest


@dataclass(frozen=True)
class VersionBundle:
    ordinal: int
    artifacts: tuple[bytes, bytes, bytes]
    evidences: tuple[bytes, bytes, bytes]
    graph_evidence: bytes
    descriptor: bytes
    parsed: Any
    verified_artifacts: tuple[Any, Any, Any]


@dataclass(frozen=True)
class ParsedHistory:
    classification: str
    record_count: int
    versions: tuple[VersionBundle, ...]


def _policy_object_kinds(policy: FrozenPolicy) -> Mapping[str, int]:
    return {
        name: int(encoded, 16)
        for name, encoded in policy.document["storage"]["object_kinds"].items()
    }


def _policy_version_kind_order(policy: FrozenPolicy) -> tuple[int, ...]:
    storage = policy.document["storage"]
    kinds = _policy_object_kinds(policy)
    attachments = tuple(kinds[name] for name in storage["ordered_attachment_kinds"])
    root = int(storage["root_object"]["kind"], 16)
    return (*attachments, root)


def select_c78_authority_objects(
    state: Any, policy: FrozenPolicy
) -> dict[int, tuple[int, bytes, int]]:
    """Storage policy selector; semantic graph authority is checked above it."""

    require(state.formatted, "C7.8 logical authority stream is not formatted")
    if not state.objects and not state.grants and not state.tombstones:
        require(not state.live and not state.slots, "vacant authority retains a live root")
        return {}
    history = c76_codec.inspect_history_state(state)
    descriptor = history["current_descriptor"]
    require(
        state.objects[descriptor][0]
        == int(policy.document["storage"]["root_object"]["kind"], 16),
        "current authority root is not the explicit root-object kind",
    )
    return {descriptor: state.objects[descriptor]}


def _validate_detached_evidence(
    encoded: bytes, magic: bytes, policy: FrozenPolicy, label: str
) -> bytes:
    require(len(encoded) == EVIDENCE_LEN, f"{label} encoded length differs")
    require(encoded[:8] == magic, f"{label} magic differs")
    require(
        u16(encoded, 8) == 1
        and u16(encoded, 10) == EVIDENCE_LEN
        and u16(encoded, 12) == 1
        and u16(encoded, 14) == 0,
        f"{label} header differs",
    )
    key = bytes(encoded[16:48])
    signature = bytes(encoded[48:112])
    require(key == policy.active_public_key, f"{label} signer differs from explicit trust anchor")
    require(any(signature), f"{label} signature is the zero sentinel")
    c73.strict_point(key, f"{label} public key")
    c73.strict_point(signature[:32], f"{label} signature R")
    require(
        int.from_bytes(signature[32:], "little") < c73.ORDER,
        f"{label} signature S is non-canonical",
    )
    return signature


def _leaf_signature_transcript(artifact: bytes, policy: FrozenPolicy) -> bytes:
    require(len(LEAF_SIGNATURE_DOMAIN) == 48, "leaf signature domain length drifted")
    out = bytearray(192)
    out[:48] = LEAF_SIGNATURE_DOMAIN
    struct.pack_into(
        "<HHHHHHHHHH",
        out,
        48,
        1,
        1,
        1,
        1,
        1,
        1,
        u16(artifact, 32),
        u16(artifact, 34),
        u16(artifact, 36),
        u16(artifact, 38),
    )
    struct.pack_into("<H", out, 68, u16(artifact, 24))
    struct.pack_into("<Q", out, 72, u64(artifact, 40))
    struct.pack_into("<Q", out, 80, len(artifact))
    out[88:120] = c73.artifact_commitment(artifact)
    out[120:152] = artifact[232:264]
    out[152:184] = policy.active_public_key
    struct.pack_into("<Q", out, 184, policy.policy_generation)
    return bytes(out)


def _graph_signature_transcript(descriptor: bytes, policy: FrozenPolicy) -> bytes:
    require(len(GRAPH_SIGNATURE_DOMAIN) == 48, "graph signature domain length drifted")
    out = bytearray(256)
    out[:48] = GRAPH_SIGNATURE_DOMAIN
    struct.pack_into("<HHHHHH", out, 48, 1, 1, 1, 1, 1, 1)
    struct.pack_into(
        "<HHHHH",
        out,
        60,
        u16(descriptor, 32),
        u16(descriptor, 34),
        u16(descriptor, 36),
        u16(descriptor, 38),
        u16(descriptor, 28),
    )
    struct.pack_into("<Q", out, 72, u64(descriptor, 40))
    struct.pack_into("<Q", out, 80, len(descriptor))
    out[88:120] = descriptor[192:224]
    out[120:152] = descriptor[128:160]
    out[152:184] = policy.active_public_key
    struct.pack_into("<Q", out, 184, policy.policy_generation)
    ordinal = u64(descriptor, 48)
    struct.pack_into("<Q", out, 192, ordinal)
    predecessor = descriptor[96:128]
    if predecessor != bytes(32):
        out[200:232] = predecessor
        out[232] = 1
    return bytes(out)


def _verify_leaf_signature(
    artifact: bytes, evidence: bytes, policy: FrozenPolicy, label: str
) -> None:
    signature = _validate_detached_evidence(evidence, b"VIBESIG\0", policy, label)
    require(
        c73.ed25519_verify(
            policy.active_public_key,
            _leaf_signature_transcript(artifact, policy),
            signature,
        ),
        f"{label} Ed25519 artifact transcript differs",
    )


def _verify_graph_signature(
    descriptor: bytes, evidence: bytes, policy: FrozenPolicy, label: str
) -> None:
    signature = _validate_detached_evidence(evidence, b"VIBEGSG\0", policy, label)
    require(
        c73.ed25519_verify(
            policy.active_public_key,
            _graph_signature_transcript(descriptor, policy),
            signature,
        ),
        f"{label} Ed25519 graph transcript differs",
    )


def _validate_artifact(
    artifact: bytes,
    evidence: bytes,
    policy: FrozenPolicy,
    node_index: int,
    label: str,
) -> Any:
    verified = c71.verify_artifact(artifact)
    profile = policy.document["artifact_profile"]
    node = policy.document["graph"]["nodes"][node_index]
    expected_limits = (
        profile["instance_limits"]["memory_bytes"],
        profile["instance_limits"]["total_fuel"],
        profile["instance_limits"]["poll_quantum"],
        profile["instance_limits"]["resources"],
    )
    require(
        artifact[:8] == b"VIBECMP\0"
        and u16(artifact, 8) == profile["format_version"]
        and u16(artifact, 22) == profile["profile_code"]
        and u16(artifact, 24) == profile["stage"]
        and u16(artifact, 26) == profile["manifest_version"]
        and u16(artifact, 28) == profile["signer_policy_kind"]
        and u16(artifact, 30) == profile["signer_policy_version"],
        f"{label} format/profile/signer policy differs",
    )
    require(
        (
            verified.profile.code,
            verified.profile.stage,
            verified.profile.artifact_abi,
            verified.profile.component_profile,
            verified.profile.core_profile,
            verified.profile.runtime_abi,
            verified.profile.canonical_features,
            verified.profile.revisions,
            verified.signer_kind,
            verified.instance_limits,
            verified.runtime_ready,
        )
        == (
            profile["profile_code"],
            profile["stage"],
            profile["artifact_abi"],
            profile["component_profile"],
            profile["core_profile"],
            profile["runtime_abi"],
            profile["canonical_features"],
            tuple(profile["revisions"]),
            profile["signer_policy_kind"],
            expected_limits,
            False,
        ),
        f"{label} verified profile/limits differ",
    )
    require(
        bytes(verified.signer_policy_digest) == leaf_policy_commitment(policy, node)
        and artifact[232:264] == leaf_policy_commitment(policy, node),
        f"{label} leaf operator-policy commitment differs",
    )
    manifest = verified.manifest
    wit = policy.document["wit"]
    require(manifest.world == node["world"], f"{label} world differs")
    require(
        len(manifest.wit_packages) == 1
        and (
            manifest.wit_packages[0].name,
            manifest.wit_packages[0].version,
            manifest.wit_packages[0].source,
        )
        == (wit["package"], wit["version"], wit["source"]),
        f"{label} exact WIT package/source differs",
    )
    expected_directions = tuple(
        sorted(
            [(1, name) for name in node["imports"]]
            + [(2, name) for name in node["exports"]]
        )
    )
    observed_directions = tuple(
        (interface.direction, interface.name) for interface in manifest.interfaces
    )
    require(
        observed_directions == expected_directions
        and all(interface.kind == 2 for interface in manifest.interfaces)
        and not manifest.adapters,
        f"{label} interface direction/kind or adapter set differs",
    )
    _verify_leaf_signature(artifact, evidence, policy, label)
    return verified


def _validate_version_bundle(
    ordinal: int,
    values: Sequence[tuple[int, bytes]],
    policy: FrozenPolicy,
) -> VersionBundle:
    require(len(values) == 8, "graph version attachment count differs")
    require(
        tuple(kind for kind, _content in values)
        == _policy_version_kind_order(policy),
        "graph version attachment kind order differs",
    )
    artifacts = tuple(values[index][1] for index in range(3))
    evidences = tuple(values[index + 3][1] for index in range(3))
    graph_evidence = values[6][1]
    descriptor = values[7][1]
    verified_artifacts = tuple(
        _validate_artifact(
            artifacts[index],
            evidences[index],
            policy,
            index,
            f"G{ordinal} node[{index}]",
        )
        for index in range(3)
    )
    parsed = c76_codec.parse_descriptor(descriptor, artifacts, evidences)
    graph = policy.document["graph"]
    require(parsed.ordinal == ordinal, f"G{ordinal} descriptor ordinal differs")
    require(
        parsed.policy_digest == graph_policy_commitment(policy)
        and descriptor[128:160] == graph_policy_commitment(policy),
        f"G{ordinal} graph operator-policy commitment differs",
    )
    require(
        parsed.name == graph["name"]
        and parsed.edges == tuple(tuple(edge) for edge in graph["edges"])
        and parsed.async_edges == tuple(tuple(edge) for edge in graph["async_edges"])
        and parsed.published == tuple(tuple(endpoint) for endpoint in graph["published_exports"])
        and parsed.incidents == tuple(tuple(edge) for edge in graph["incident_edges"]),
        f"G{ordinal} graph topology differs from explicit policy",
    )
    for index, (parsed_node, policy_node) in enumerate(zip(parsed.nodes, graph["nodes"])):
        require(
            (
                parsed_node.ordinal,
                parsed_node.nesting,
                parsed_node.parent,
                parsed_node.label,
                parsed_node.world,
                parsed_node.limits,
                parsed_node.world_contract,
            )
            == (
                policy_node["ordinal"],
                policy_node["nesting"],
                policy_node["parent"],
                policy_node["label"],
                policy_node["world"],
                (
                    policy.document["artifact_profile"]["instance_limits"]["memory_bytes"],
                    policy.document["artifact_profile"]["instance_limits"]["total_fuel"],
                    policy.document["artifact_profile"]["instance_limits"]["poll_quantum"],
                    policy.document["artifact_profile"]["instance_limits"]["resources"],
                ),
                world_contract_commitment(policy, policy_node),
            ),
            f"G{ordinal} node[{index}] identity/world/limits/contract differs",
        )
    _verify_graph_signature(descriptor, graph_evidence, policy, f"G{ordinal} graph evidence")
    return VersionBundle(
        ordinal=ordinal,
        artifacts=artifacts,  # type: ignore[arg-type]
        evidences=evidences,  # type: ignore[arg-type]
        graph_evidence=graph_evidence,
        descriptor=descriptor,
        parsed=parsed,
        verified_artifacts=verified_artifacts,  # type: ignore[arg-type]
    )


def _parse_object_transaction(
    records: list[Any], cursor: int, transaction: int, object_id: int, kind: int
) -> tuple[int, bytes]:
    # The reused function checks exact prepare/chunk/commit order, all CRC
    # bindings, and canonical object geometry.  No expected content bytes are
    # supplied to it.
    return c76_codec.parse_object_transaction(records, cursor, transaction, object_id, kind)


def _parse_root_transaction_policy(
    records: list[Any],
    cursor: int,
    transaction: int,
    derivation: int,
    descriptor: int,
    generation: int,
    policy: FrozenPolicy,
) -> int:
    storage = policy.document["storage"]
    root = storage["root_object"]
    require(cursor + 1 < len(records), "graph root transaction is truncated")
    prepare = records[cursor]
    require(
        u32(prepare.raw, PAYLOAD + 64) == storage["root_slot"]
        and u64(prepare.raw, PAYLOAD + 72) == generation
        and u32(prepare.raw, PAYLOAD + 68) == root["rights"]
        and u32(prepare.raw, PAYLOAD + 80) == int(storage["stored_object_resource_kind"], 16)
        and root["granted"] is True
        and root["count"] == 1
        and int(root["kind"], 16) == _policy_object_kinds(policy)["graph_version"],
        "graph root grant differs from the explicit root-object policy",
    )
    return c76_codec.parse_root_transaction(
        records, cursor, transaction, derivation, descriptor, generation
    )


_PARSED_HISTORY_CACHE: dict[tuple[bytes, bytes, int | None], ParsedHistory] = {}


def parse_complete_history(
    record_stream: bytes, policy: FrozenPolicy, expected_versions: int | None = None
) -> ParsedHistory:
    record_stream = bytes(record_stream)
    policy_cache_key = hashlib.sha256(
        canonical_json_bytes(policy.document)
        + policy.active_public_key
        + policy.external_policy
    ).digest()
    cache_key = (policy_cache_key, record_stream, expected_versions)
    cached = _PARSED_HISTORY_CACHE.get(cache_key)
    if cached is not None:
        return cached
    require(record_stream and len(record_stream) % BLOCK == 0, "logical history is not block aligned")
    try:
        records = c76_codec.decoded_records(record_stream)
        state = migration.recover_record_stream(record_stream)
    except ValueError as error:
        # The frozen sector codec uses builtin ValueError for CRC/seal
        # rejection. Translate it at this narrow decoder boundary; builtin
        # ValueError is intentionally not a global expected-rejection class.
        raise VerificationError(f"logical record decoder rejected bytes: {error}") from error
    require(records and records[0].kind == legacy.FORMAT, "logical history does not start with Format")
    if not state.objects and not state.grants and not state.tombstones:
        require(
            len(records) == 1 and not state.live and not state.slots,
            "Vacant history contains non-vacant logical records",
        )
        require(expected_versions in (None, 0), "Vacant history differs from expected graph state")
        result = ParsedHistory("vacant", len(records), ())
        _PARSED_HISTORY_CACHE[cache_key] = result
        return result
    structural = c76_codec.inspect_history_state(state)
    version_count = structural["versions"]
    require(version_count in (1, 2), "logical history version count differs")
    if expected_versions is not None:
        require(version_count == expected_versions, "logical history differs from expected version count")
    cursor = 1
    bases = (1, GRAPH_SPACE + 1)
    bundles = []
    root_derivations: list[int] = []
    expected_kinds = _policy_version_kind_order(policy)
    for generation in range(version_count):
        base = bases[generation]
        require(cursor < len(records), f"G{generation} high-water record is absent")
        high_water = records[cursor]
        expected_high_water = GRAPH_SPACE + 1 if generation == 0 else base + 19
        require(
            high_water.kind == legacy.HIGH_WATER
            and high_water.transaction == 0
            and u128(high_water.raw, PAYLOAD) == expected_high_water,
            f"G{generation} high-water reservation/order differs",
        )
        cursor += 1
        values: list[tuple[int, bytes]] = []
        for index, kind in enumerate(expected_kinds):
            transaction = base + index * 2
            object_id = transaction + 1
            cursor, content = _parse_object_transaction(
                records, cursor, transaction, object_id, kind
            )
            require(state.objects[object_id][1] == content, "logical recovery/object bytes differ")
            values.append((kind, content))
        if generation == 1:
            require(cursor < len(records), "G1 predecessor tombstone is absent")
            tombstone = records[cursor]
            require(
                tombstone.kind == legacy.TOMBSTONE
                and tombstone.transaction == base + 16
                and u128(tombstone.raw, PAYLOAD) == root_derivations[0],
                "G1 predecessor tombstone order/target differs",
            )
            cursor += 1
        derivation = base + (17 if generation == 0 else 18)
        root_derivations.append(derivation)
        cursor = _parse_root_transaction_policy(
            records,
            cursor,
            base + (16 if generation == 0 else 17),
            derivation,
            base + 15,
            generation,
            policy,
        )
        bundles.append(_validate_version_bundle(generation, values, policy))
    require(cursor == len(records), "logical history continues after the exact graph root")
    require(len(records) == version_count * LOGICAL_RECORDS_PER_TRANSITION, "logical record count differs from frozen transition geometry")
    g0 = bundles[0]
    require(
        g0.parsed.predecessor == bytes(32),
        "G0 descriptor unexpectedly names a predecessor",
    )
    if version_count == 2:
        g1 = bundles[1]
        require(
            g1.parsed.predecessor == g0.parsed.commitment,
            "G1 predecessor does not bind the on-disk G0 version commitment",
        )
        require(
            g0.parsed.policy_digest == g1.parsed.policy_digest
            and g0.parsed.edges == g1.parsed.edges
            and g0.parsed.async_edges == g1.parsed.async_edges
            and g0.parsed.published == g1.parsed.published
            and g0.parsed.incidents == g1.parsed.incidents,
            "G0/G1 graph policy or topology differs",
        )
        for sibling in (0, 2):
            require(
                g0.artifacts[sibling] == g1.artifacts[sibling]
                and g0.evidences[sibling] == g1.evidences[sibling]
                and g0.parsed.nodes[sibling] == g1.parsed.nodes[sibling],
                "G0/G1 stable sibling bytes or derived budgets differ",
            )
        require(
            g0.artifacts[1] != g1.artifacts[1]
            and g0.evidences[1] != g1.evidences[1]
            and g0.parsed.nodes[1] != g1.parsed.nodes[1]
            and g0.parsed.commitment != g1.parsed.commitment,
            "G1 does not replace exactly the relay node",
        )
    result = ParsedHistory(
        "g0" if version_count == 1 else "g1",
        len(records),
        tuple(bundles),
    )
    _PARSED_HISTORY_CACHE[cache_key] = result
    return result


def complete_record_prefix(raw: bytes) -> bytes:
    require(raw and len(raw) % BLOCK == 0, "authority-record-stream image is not block aligned")
    complete = bytearray()
    saw_unsealed = False
    for index in range(0, len(raw), BLOCK):
        sector = raw[index : index + BLOCK]
        try:
            decoded = legacy.decode_sector(sector, migration.M4_FIRST + index // BLOCK)
        except ValueError as error:
            raise VerificationError(f"logical prefix sector decoder rejected bytes: {error}") from error
        if decoded is None:
            saw_unsealed = True
            require(
                not any(raw[index + BLOCK :]),
                "authority-record-stream contains bytes after its first unsealed record",
            )
            break
        require(not saw_unsealed, "authority-record-stream resumes after an unsealed record")
        complete.extend(sector)
    return bytes(complete)


@dataclass(frozen=True)
class DiskGeometry:
    managed_region_pages: int
    page_size: int
    anchor_pages: int
    segment_pages: int
    data_first_page: int
    data_end_page: int
    summary_body_page: int
    summary_seal_page: int
    segment_seal_body_page: int
    segment_seal_page: int
    max_extent_payload_pages: int
    initial_range_pages: int
    first_segment_page: int
    initial_segments: int
    range_first_logical_block: int
    initial_block_count: int
    logical_block_size: int
    admitted_range_pages: int
    admitted_segments: int
    cleaner_reserve_segments: int


@dataclass(frozen=True)
class DiskAnalysis:
    classification: str
    history: ParsedHistory
    device_id: str
    store_uuid: str
    geometry: DiskGeometry
    checkpoint_generation: int
    selected_checkpoint_pair_sha256: str
    retained_checkpoint_pairs: tuple[tuple[int, str], ...]
    verified_checkpoint_copies: int
    admitted_segments: int
    physical_bindings: int
    historical_cas_descriptors: int
    sealed_extents: int
    current_or_retained_extents: int
    trace_explained_orphans: int


def _checkpoint_pair_commitments(region: Any) -> tuple[tuple[int, str], ...]:
    commitments: list[tuple[int, str]] = []
    for slot in migration.v2_checkpoint_slots(region):
        if slot["status"] != "sealed":
            continue
        body_page = slot["body_page"]
        seal_page = slot["seal_page"]
        require(seal_page == body_page + 1, "checkpoint pair is not physically adjacent")
        start = body_page * PAGE
        end = (seal_page + 1) * PAGE
        pair = bytes(region[start:end])
        require(len(pair) == 2 * PAGE, "checkpoint pair bytes are truncated")
        commitments.append(
            (slot["record"]["binding"]["generation"], hashlib.sha256(pair).hexdigest())
        )
    commitments.sort()
    require(
        commitments and len({generation for generation, _digest in commitments}) == len(commitments),
        "checkpoint pair commitments repeat a generation",
    )
    return tuple(commitments)


def _require_dual_checkpoint_endpoint(analysis: DiskAnalysis, label: str) -> None:
    """Successful published graph endpoints must retain both verified copies."""

    require(
        analysis.classification in {"g0", "g1"},
        f"{label} is not a published graph endpoint",
    )
    require(
        analysis.verified_checkpoint_copies == 2,
        f"{label} does not retain both independently verified checkpoint copies",
    )


def _require_storage_transition(
    before: DiskAnalysis,
    after: DiskAnalysis,
    label: str,
) -> None:
    """Bind a publication to one device/store and its retained predecessor."""

    if before.classification in {"g0", "g1"}:
        _require_dual_checkpoint_endpoint(before, f"{label} before endpoint")
    if after.classification in {"g0", "g1"}:
        _require_dual_checkpoint_endpoint(after, f"{label} after endpoint")

    require(
        before.device_id == after.device_id
        and before.store_uuid == after.store_uuid
        and before.geometry == after.geometry
        and before.admitted_segments == after.admitted_segments,
        f"{label} changes Storage V2 identity or admitted geometry",
    )
    require(
        after.checkpoint_generation == before.checkpoint_generation + 1,
        f"{label} is not one checkpoint generation",
    )
    before_pairs = dict(before.retained_checkpoint_pairs)
    after_pairs = dict(after.retained_checkpoint_pairs)
    require(
        before_pairs.get(before.checkpoint_generation)
        == before.selected_checkpoint_pair_sha256,
        f"{label} before image does not bind its selected checkpoint pair",
    )
    require(
        after_pairs.get(after.checkpoint_generation)
        == after.selected_checkpoint_pair_sha256,
        f"{label} after image does not bind its selected checkpoint pair",
    )
    require(
        after_pairs.get(before.checkpoint_generation)
        == before.selected_checkpoint_pair_sha256,
        f"{label} does not retain the exact predecessor checkpoint body/seal bytes",
    )


def _selected_superblock(structural: Mapping[str, Any]) -> Mapping[str, Any]:
    errors: list[str] = []
    selected = migration.storage_codec.select_superblock(
        structural["superblocks"], errors
    )
    require(not errors and selected is not None, "Storage V2 has no exact selected superblock")
    return selected["record"]


def _verify_recovered_graph_semantics(
    recovered: Mapping[str, Any],
    policy: FrozenPolicy,
    checkpoint_generation: int,
    label: str,
) -> ParsedHistory:
    """Verify logical authority and the exact current/historical CAS relation."""

    authority = recovered["authority"]
    if authority is None:
        require(
            not recovered["authority_objects"]
            and not recovered["objects"]
            and not recovered["contents"],
            f"{label} Vacant state retains authority or CAS content",
        )
        return ParsedHistory("vacant", 0, ())
    history = parse_complete_history(authority["record_stream"], policy)
    if history.classification == "vacant":
        require(
            authority["record_stream"] == migration.canonical_empty_record_stream()
            and not authority["objects"]
            and not authority["external_roots"]
            and not recovered["authority_objects"]
            and not recovered["objects"]
            and not recovered["contents"],
            f"{label} non-null Vacant authority is not the exact canonical empty snapshot",
        )
        empty_report = migration.verify_authority_bindings(
            {"recovered": recovered},
            False,
        )
        require(
            empty_report["authority_objects"] == 0
            and empty_report["cas_objects"] == 0
            and empty_report["unique_blobs"] == 0
            and empty_report["logical_bytes"] == 0
            and empty_report["attributable_physical_bytes"] == 0,
            f"{label} canonical empty authority retains accounting or CAS state",
        )
        return history
    bindings = authority["objects"]
    require(
        history.classification in {"g0", "g1"}
        and len(bindings) == 1
        and not authority["external_roots"]
        and bindings[0]["object_kind"]
        == int(policy.document["storage"]["root_object"]["kind"], 16),
        f"{label} authority is not the sole current CGV1 binding",
    )
    binding_report = migration.verify_authority_bindings(
        {"recovered": recovered},
        False,
    )
    require(
        binding_report["authority_objects"] == 1
        and binding_report["cas_objects"] == len(history.versions),
        f"{label} authority/CAS binding counts differ from exact history",
    )
    current = history.versions[-1]
    mapping = recovered["objects"].get(bindings[0]["v2_object_id"])
    require(mapping is not None, f"{label} current CGV1 binding has no CAS ObjectMapping")
    content = recovered["contents"].get(
        migration.gc_verifier.blob_key_identity(mapping["blob_key"])
    )
    require(content == current.descriptor, f"{label} current CGV1 differs from logical authority")
    require(
        checkpoint_generation >= len(history.versions),
        f"{label} checkpoint predates its graph-version history",
    )
    first_publication_generation = checkpoint_generation - len(history.versions) + 1
    observed = []
    for candidate in recovered["objects"].values():
        candidate_content = recovered["contents"].get(
            migration.gc_verifier.blob_key_identity(candidate["blob_key"])
        )
        require(
            candidate["object_kind"] == CGV1 and candidate_content is not None,
            f"{label} CAS contains a non-CGV1 or unreadable historical object",
        )
        observed.append((candidate_content, candidate["commit_generation"]))
    expected = [
        (version.descriptor, first_publication_generation + index)
        for index, version in enumerate(history.versions)
    ]
    require(
        sorted(observed) == sorted(expected),
        f"{label} CAS descriptor/publication-generation history differs from logical G0/G1 history",
    )
    return history


def _verify_corpus_checkpoint_fallbacks(
    region: Any,
    structural: Mapping[str, Any],
    superblock: Mapping[str, Any],
    selected_recovered: Mapping[str, Any],
    policy: FrozenPolicy,
) -> int:
    """Verify the exporter's production-valid allocation-v1 retained pair.

    The shared migration verifier intentionally requires a v1-to-v2 allocation
    conversion for a two-copy pair.  C7.8's production SegmentStore corpus is
    generated wholly in allocation-v1 mode, so its exact legal transition is
    checked here rather than weakening that older verifier.
    """

    sealed = sorted(
        (slot for slot in migration.v2_checkpoint_slots(region) if slot["status"] == "sealed"),
        key=lambda slot: slot["record"]["binding"]["generation"],
    )
    require(1 <= len(sealed) <= 2, "corpus retains an invalid checkpoint cardinality")
    expected_geometry = policy.document["storage"]["geometry_profiles"]["corpus"]
    recovered_by_generation: dict[int, Mapping[str, Any]] = {
        selected_recovered["checkpoint_generation"]: selected_recovered
    }
    history_by_generation: dict[int, ParsedHistory] = {}
    for checkpoint in sealed:
        errors: list[str] = []
        migration.storage_codec.verify_checkpoint_against_superblock(
            checkpoint,
            {"record": superblock},
            structural["physical_segments"],
            structural["segments"],
            errors,
        )
        require(not errors, "a corpus retained checkpoint is not independently structural")
        record = checkpoint["record"]
        generation = record["binding"]["generation"]
        if generation not in recovered_by_generation:
            candidate = dict(structural)
            candidate["checkpoint"] = checkpoint
            recovered_by_generation[generation] = migration.reconstruct_v2_checkpoint(
                region,
                candidate,
                require_authority=False,
                authority_policy=policy.authority_policy,
            )
        recovered = recovered_by_generation[generation]
        require(
            recovered["allocation_version"] == 1
            and record["binding"]["store_uuid"] == superblock["binding"]["store_uuid"]
            and record["admitted_range_pages"] == expected_geometry["admitted_range_pages"]
            and record["admitted_segments"] == expected_geometry["admitted_segments"]
            and record["cleaner_reserve_segments"] == expected_geometry["cleaner_reserve_segments"]
            and record["replay_count"] == 0
            and record["replay_tail"]["status"] == "null",
            "corpus checkpoint is outside its exact allocation-v1 profile",
        )
        history_by_generation[generation] = _verify_recovered_graph_semantics(
            recovered,
            policy,
            generation,
            f"corpus retained generation {generation}",
        )
    require(
        sealed[-1]["record"]["binding"]["generation"]
        == selected_recovered["checkpoint_generation"],
        "corpus selected checkpoint is not its newest retained copy",
    )
    if len(sealed) == 1:
        only = sealed[0]["record"]
        generation = only["binding"]["generation"]
        recovered = recovered_by_generation[generation]
        history = history_by_generation[generation]
        expected_class = {1: "vacant", 2: "g0"}.get(generation)
        expected_allocated = 2 * (generation - 1)
        allocation = recovered["allocation"]
        require(
            expected_class is not None
            and history.classification == expected_class
            and only["previous_generation"] == generation - 1
            and allocation["next_segment_generation"] == 1 + expected_allocated
            and allocation["states"][:expected_allocated]
            == [migration.gc_verifier.SEGMENT_ALLOCATED] * expected_allocated
            and allocation["states"][expected_allocated:]
            == [migration.gc_verifier.SEGMENT_FREE]
            * (expected_geometry["admitted_segments"] - expected_allocated)
            and not allocation["retired"]
            and only["replay_tail"]["status"] == "null"
            and (
                all(only[root]["status"] == "null" for root in ("catalog_root", "authority_root", "allocation_root"))
                if generation == 1
                else (
                    all(
                        only[root]["status"] == "value"
                        and only[root]["segment_no"] == expected_allocated - 1
                        and only[root]["segment_generation"] == expected_allocated
                        for root in ("catalog_root", "authority_root", "allocation_root")
                    )
                    and len(
                        {
                            migration.storage_codec.pointer_identity(only[root])
                            for root in ("catalog_root", "authority_root", "allocation_root")
                        }
                    )
                    == 3
                    and all(
                        structural["segments"][segment_no]["_generation"]
                        == segment_no + 1
                        for segment_no in range(expected_allocated)
                    )
                )
            ),
            "single-copy corpus checkpoint is not an exact Vacant/G0/G1 fallback",
        )
        return 1

    older_slot, newer_slot = sealed
    older_record = older_slot["record"]
    newer_record = newer_slot["record"]
    older_generation = older_record["binding"]["generation"]
    newer_generation = newer_record["binding"]["generation"]
    older = recovered_by_generation[older_generation]
    newer = recovered_by_generation[newer_generation]
    require(
        newer_generation == older_generation + 1
        and newer_record["previous_generation"] == older_generation
        and newer_record["binding"]["store_uuid"] == older_record["binding"]["store_uuid"]
        and newer_record["admitted_range_pages"] == older_record["admitted_range_pages"]
        and newer_record["admitted_segments"] == older_record["admitted_segments"]
        and newer_record["cleaner_reserve_segments"] == older_record["cleaner_reserve_segments"]
        and newer["allocation"]["next_segment_generation"]
        == older["allocation"]["next_segment_generation"] + 2,
        "corpus retained checkpoints are not one exact publication transition",
    )
    old_states = older["allocation"]["states"]
    new_states = newer["allocation"]["states"]
    old_allocated_prefix = next(
        (
            index
            for index, state in enumerate(old_states)
            if state != migration.gc_verifier.SEGMENT_ALLOCATED
        ),
        len(old_states),
    )
    allocated = [
        index
        for index, (before, after) in enumerate(zip(old_states, new_states))
        if before != after
        and before == migration.gc_verifier.SEGMENT_FREE
        and after == migration.gc_verifier.SEGMENT_ALLOCATED
    ]
    require(
        len(old_states) == len(new_states) == expected_geometry["admitted_segments"]
        and old_states[:old_allocated_prefix]
        == [migration.gc_verifier.SEGMENT_ALLOCATED] * old_allocated_prefix
        and old_states[old_allocated_prefix:]
        == [migration.gc_verifier.SEGMENT_FREE]
        * (expected_geometry["admitted_segments"] - old_allocated_prefix)
        and allocated == [old_allocated_prefix, old_allocated_prefix + 1]
        and all(
            before == after or index in allocated
            for index, (before, after) in enumerate(zip(old_states, new_states))
        )
        and not older["allocation"]["retired"]
        and not newer["allocation"]["retired"]
        and new_states[: old_allocated_prefix + 2]
        == [migration.gc_verifier.SEGMENT_ALLOCATED] * (old_allocated_prefix + 2)
        and new_states[old_allocated_prefix + 2 :]
        == [migration.gc_verifier.SEGMENT_FREE]
        * (expected_geometry["admitted_segments"] - old_allocated_prefix - 2)
        and all(newer_record[root]["status"] == "value" for root in ("catalog_root", "authority_root", "allocation_root"))
        and all(
            newer_record[root]["segment_no"] == allocated[1]
            and newer_record[root]["segment_generation"]
            == older["allocation"]["next_segment_generation"] + 1
            for root in ("catalog_root", "authority_root", "allocation_root")
        )
        and structural["segments"][allocated[0]]["_generation"]
        == older["allocation"]["next_segment_generation"]
        and structural["segments"][allocated[1]]["_generation"]
        == older["allocation"]["next_segment_generation"] + 1
        and len(
            {
                migration.storage_codec.pointer_identity(newer_record[root])
                for root in ("catalog_root", "authority_root", "allocation_root")
            }
        )
        == 3,
        "corpus publication is not exactly two fresh allocated segments and three new roots",
    )
    old_history = history_by_generation[older_generation]
    new_history = history_by_generation[newer_generation]
    require(
        (
            old_history.classification,
            new_history.classification,
            older_generation,
            newer_generation,
        )
        in {("vacant", "g0", 1, 2), ("g0", "g1", 2, 3)}
        and (
            older["authority"] is None
            or newer["authority"]["record_stream"].startswith(
                older["authority"]["record_stream"]
            )
        ),
        "corpus retained authority history is not the exact Vacant/G0/G1 successor",
    )
    for object_id, mapping in older["objects"].items():
        require(
            newer["objects"].get(object_id) == mapping,
            "corpus successor rewrites a retained CAS ObjectMapping",
        )
    for blob_key, content in older["contents"].items():
        require(
            newer["contents"].get(blob_key) == content,
            "corpus successor rewrites retained CAS content",
        )
    return 2


def _verify_qemu_checkpoint_profile(
    region: Any,
    structural: Mapping[str, Any],
    selected_recovered: Mapping[str, Any],
    policy: FrozenPolicy,
) -> None:
    """Pin the post-growth native QEMU retained allocation-v2 pair."""

    sealed = sorted(
        (slot for slot in migration.v2_checkpoint_slots(region) if slot["status"] == "sealed"),
        key=lambda slot: slot["record"]["binding"]["generation"],
    )
    require(len(sealed) == 2, "QEMU endpoint does not retain two sealed checkpoints")
    expected = policy.document["storage"]["geometry_profiles"]["qemu"]
    lifecycle = {
        entry["generation"]: entry
        for entry in policy.document["storage"]["qemu_checkpoint_lifecycle"]
    }
    generations = [slot["record"]["binding"]["generation"] for slot in sealed]
    require(
        generations in ([3, 4], [4, 5])
        and generations[-1] == selected_recovered["checkpoint_generation"],
        "QEMU checkpoint generations are outside exact growth/G0/G1 sequence",
    )
    classified: list[tuple[int, str]] = []
    recovered_by_generation: dict[int, Mapping[str, Any]] = {}
    for slot in sealed:
        generation = slot["record"]["binding"]["generation"]
        if generation == selected_recovered["checkpoint_generation"]:
            recovered = selected_recovered
        else:
            candidate = dict(structural)
            candidate["checkpoint"] = slot
            recovered = migration.reconstruct_v2_checkpoint(
                region,
                candidate,
                require_authority=False,
                authority_policy=policy.authority_policy,
            )
        record = slot["record"]
        require(
            recovered["allocation_version"] == migration.gc_verifier.ALLOCATION_VERSION
            and record["admitted_range_pages"] == expected["admitted_range_pages"]
            and record["admitted_segments"] == expected["admitted_segments"]
            and record["cleaner_reserve_segments"] == expected["cleaner_reserve_segments"],
            "QEMU retained checkpoint is not exact allocation-v2/14-segment state",
        )
        history = _verify_recovered_graph_semantics(
            recovered,
            policy,
            generation,
            f"QEMU retained generation {generation}",
        )
        classification = history.classification
        lifecycle_entry = lifecycle[generation]
        allocation = recovered["allocation"]
        allocated_segments = lifecycle_entry["allocated_segments"]
        expected_states = [migration.gc_verifier.SEGMENT_ALLOCATED] * allocated_segments + [
            migration.gc_verifier.SEGMENT_FREE
        ] * (expected["admitted_segments"] - allocated_segments)
        require(
            classification == lifecycle_entry["classification"]
            and allocation["states"] == expected_states
            and allocation["next_segment_generation"]
            == lifecycle_entry["next_segment_generation"],
            f"QEMU retained generation {generation} allocation lifecycle differs",
        )
        for segment_no, segment in enumerate(structural["segments"]):
            if segment_no < allocated_segments:
                require(
                    segment.get("status") == "sealed"
                    and segment.get("_generation") == segment_no + 1,
                    f"QEMU retained generation {generation} segment-generation prefix differs",
                )
            elif generation == selected_recovered["checkpoint_generation"]:
                require(
                    segment.get("status") == "empty",
                    f"QEMU retained generation {generation} has bytes beyond its allocated prefix",
                )
        for root_name in ("allocation_root", "authority_root", "catalog_root"):
            pointer = record[root_name]
            pointer_errors: list[str] = []
            extent = migration.storage_codec.resolve_extent_pointer(
                slot,
                f"QEMU generation {generation} {root_name}",
                pointer,
                structural["segments"],
                pointer_errors,
            )
            require(
                pointer["status"] == "value"
                and extent is not None
                and not pointer_errors
                and [
                    pointer["segment_no"],
                    pointer["segment_generation"],
                    pointer["ordinal"],
                    extent["binding"]["target_checkpoint_generation"],
                ]
                == lifecycle_entry[root_name],
                f"QEMU retained generation {generation} {root_name} lifecycle differs",
            )
        require(
            record["replay_tail"]["status"] == "null"
            and record["replay_count"] == 0,
            f"QEMU retained generation {generation} unexpectedly has replay state",
        )
        if generation == 3:
            require(
                classification == "vacant"
                and recovered["authority"] is not None
                and recovered["authority_generation"] == 2,
                "QEMU retained generation 3 is not the exact grown canonical-empty floor",
            )
        classified.append((generation, classification))
        recovered_by_generation[generation] = recovered
    require(
        tuple(classified)
        in {((3, "vacant"), (4, "g0")), ((4, "g0"), (5, "g1"))}
        and classified[-1][0] == selected_recovered["checkpoint_generation"],
        "QEMU retained checkpoint pair is not exact Vacant/G0 or G0/G1",
    )
    older = recovered_by_generation[generations[0]]
    newer = recovered_by_generation[generations[1]]
    if older["authority"] is not None:
        require(
            newer["authority"] is not None
            and newer["authority"]["record_stream"].startswith(
                older["authority"]["record_stream"]
            ),
            "QEMU successor rewrites its retained authority-record prefix",
        )
    for object_id, mapping in older["objects"].items():
        require(
            newer["objects"].get(object_id) == mapping,
            "QEMU successor rewrites a retained CAS ObjectMapping",
        )
    for blob_key, content in older["contents"].items():
        require(
            newer["contents"].get(blob_key) == content,
            "QEMU successor rewrites retained CAS content",
        )


def probe_v2_region(
    region: Any,
    policy: FrozenPolicy,
    *,
    geometry_profile: str,
) -> tuple[str, dict[str, Any] | None, Mapping[str, Any] | None]:
    """Probe a PageDevice image whose byte zero is Storage V2 page zero."""

    if not any(region):
        return "absent", None, None
    try:
        structural = migration.gc_verifier.parse_raw_structure(region)
        require(not structural["errors"], "Storage V2 structural verification failed")
        checkpoint = structural["checkpoint"]
        require(checkpoint is not None, "Storage V2 has no selected checkpoint")
        superblock = migration.selected_v2_superblock(region)
        record = checkpoint["record"]
        require(
            len(superblock["device_id"]) == 16
            and superblock["device_id"] != bytes(16)
            and superblock["range_first_logical_block"] == migration.V2_FIRST
            and superblock["logical_block_size"] == BLOCK,
            "Storage V2 superblock/device geometry differs",
        )
        if geometry_profile == "selftest":
            expected_geometry = {
                "managed_region_pages": 8208,
                "initial_range_pages": 8208,
                "initial_segments": 8,
                "initial_block_count": 65664,
                "admitted_range_pages": 8208,
                "admitted_segments": 8,
                "cleaner_reserve_segments": 2,
            }
        else:
            require(
                geometry_profile in {"corpus", "qemu"},
                "Storage V2 verifier geometry profile is not explicit",
            )
            expected_geometry = policy.document["storage"]["geometry_profiles"][geometry_profile]
        observed_geometry = {
            "managed_region_pages": len(region) // PAGE,
            "initial_range_pages": superblock["initial_range_pages"],
            "initial_segments": superblock["initial_segments"],
            "initial_block_count": superblock["initial_block_count"],
            "admitted_range_pages": record["admitted_range_pages"],
            "admitted_segments": record["admitted_segments"],
            "cleaner_reserve_segments": record["cleaner_reserve_segments"],
        }
        require(
            len(region) % PAGE == 0 and observed_geometry == expected_geometry,
            f"Storage V2 geometry differs from reviewed {geometry_profile} profile",
        )
        geometry = DiskGeometry(
            managed_region_pages=observed_geometry["managed_region_pages"],
            page_size=superblock["page_size"],
            anchor_pages=superblock["anchor_pages"],
            segment_pages=superblock["segment_pages"],
            data_first_page=superblock["data_first_page"],
            data_end_page=superblock["data_end_page"],
            summary_body_page=superblock["summary_body_page"],
            summary_seal_page=superblock["summary_seal_page"],
            segment_seal_body_page=superblock["segment_seal_body_page"],
            segment_seal_page=superblock["segment_seal_page"],
            max_extent_payload_pages=superblock["max_extent_payload_pages"],
            initial_range_pages=superblock["initial_range_pages"],
            first_segment_page=superblock["first_segment_page"],
            initial_segments=superblock["initial_segments"],
            range_first_logical_block=superblock["range_first_logical_block"],
            initial_block_count=superblock["initial_block_count"],
            logical_block_size=superblock["logical_block_size"],
            admitted_range_pages=record["admitted_range_pages"],
            admitted_segments=record["admitted_segments"],
            cleaner_reserve_segments=record["cleaner_reserve_segments"],
        )
        checkpoint_pairs = _checkpoint_pair_commitments(region)
        selected_generation = record["binding"]["generation"]
        selected_pair = dict(checkpoint_pairs).get(selected_generation)
        require(selected_pair is not None, "selected checkpoint lacks an exact body/seal commitment")
        base = {
            "device_id": superblock["device_id"].hex(),
            "store_uuid": record["binding"]["store_uuid"].hex(),
            "geometry": geometry,
            "selected_checkpoint_generation": selected_generation,
            "selected_checkpoint_pair_sha256": selected_pair,
            "retained_checkpoint_pairs": checkpoint_pairs,
        }
        if record["authority_root"]["status"] == "null":
            require(
                record["catalog_root"]["status"] == "null"
                and record["replay_tail"]["status"] == "null"
                and record["replay_count"] == 0,
                "unpublished Storage V2 has catalog/replay authority",
            )
            recovered = migration.reconstruct_v2_checkpoint(
                region,
                structural,
                require_authority=False,
                authority_policy=policy.authority_policy,
            )
            require(
                recovered["authority"] is None
                and not recovered["objects"]
                and not recovered["contents"],
                "formatted Vacant checkpoint retains authority or CAS content",
            )
            copies = (
                _verify_corpus_checkpoint_fallbacks(
                    region, structural, superblock, recovered, policy
                )
                if geometry_profile == "corpus"
                else migration.verify_v2_checkpoint_fallbacks(
                    region,
                    structural,
                    superblock,
                    recovered,
                    authority_policy=policy.authority_policy,
                )
            )
            return (
                "vacant",
                {
                    **base,
                    "recovered": recovered,
                    "verified_checkpoint_copies": copies,
                },
                structural,
            )
        recovered = migration.reconstruct_v2_checkpoint(
            region,
            structural,
            require_authority=True,
            authority_policy=policy.authority_policy,
        )
        copies = (
            _verify_corpus_checkpoint_fallbacks(
                region, structural, superblock, recovered, policy
            )
            if geometry_profile == "corpus"
            else migration.verify_v2_checkpoint_fallbacks(
                region,
                structural,
                superblock,
                recovered,
                authority_policy=policy.authority_policy,
            )
        )
        if geometry_profile == "qemu":
            _verify_qemu_checkpoint_profile(
                region,
                structural,
                recovered,
                policy,
            )
        return (
            "valid",
            {
                **base,
                "authority_generation": recovered["authority_generation"],
                "authority_sha256": recovered["authority_sha256"],
                "recovered": recovered,
                "verified_checkpoint_copies": copies,
            },
            structural,
        )
    except EXPECTED_REJECTION_ERRORS as error:
        return "corrupt", {"error": str(error)}, None


def _pointer_identity(pointer: Mapping[str, Any]) -> tuple[int, int, int, int]:
    return migration.storage_codec.pointer_identity(pointer)


def _checkpoint_pointer_identities(
    region: Any,
    structural: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    recovered: Mapping[str, Any],
) -> set[tuple[int, int, int, int]]:
    record = checkpoint["record"]
    identities: set[tuple[int, int, int, int]] = set()

    def add(pointer: Mapping[str, Any], label: str) -> None:
        require(pointer["status"] == "value", f"{label} pointer is Null")
        identity = _pointer_identity(pointer)
        require(identity not in identities, f"{label} aliases another physical extent")
        identities.add(identity)

    allocation = recovered["allocation"]
    resolver = migration.gc_verifier.RawImageResolver(
        region, checkpoint, structural["segments"], allocation
    )
    allocation_pointer = record["allocation_root"]
    if allocation_pointer["status"] == "value":
        add(allocation_pointer, "allocation root")
    authority_pointer = record["authority_root"]
    if authority_pointer["status"] == "value":
        add(authority_pointer, "authority root")
    catalog_pointer = record["catalog_root"]
    if catalog_pointer["status"] == "null":
        require(
            not recovered["objects"]
            and record["replay_count"] == 0
            and record["replay_tail"]["status"] == "null",
            "Null catalog root retains CAS state",
        )
        return identities
    require(
        record["replay_count"] == 0
        and record["replay_tail"]["status"] == "null",
        "C7.8 accepts only the frozen compact CAS snapshot",
    )
    add(catalog_pointer, "CAS snapshot root")
    catalog_extent, catalog_payload = resolver.resolve(
        catalog_pointer,
        migration.gc_verifier.EXTENT_CATALOG,
        "CAS snapshot root",
        metadata=True,
    )
    require(
        hashlib.sha256(catalog_payload).digest() == catalog_pointer["payload_sha256"],
        "CAS snapshot payload digest differs during census",
    )
    context = {
        "store_uuid": record["binding"]["store_uuid"],
        "admitted_segments": record["admitted_segments"],
        "next_segment_generation": record["next_segment_generation"],
    }
    snapshot = migration.gc_verifier.parse_cas_snapshot_v2(catalog_payload, context)
    require(
        snapshot["checkpoint_generation"]
        == catalog_extent["binding"]["target_checkpoint_generation"],
        "CAS snapshot generation differs during census",
    )
    for blob in snapshot["blobs"]:
        manifest_pointer = blob["manifest"]
        add(manifest_pointer, "Blob manifest")
        manifest_extent, manifest_payload = resolver.resolve(
            manifest_pointer,
            migration.gc_verifier.EXTENT_CATALOG,
            "Blob manifest",
            metadata=True,
        )
        require(
            hashlib.sha256(manifest_payload).digest()
            == manifest_pointer["payload_sha256"],
            "Blob manifest payload digest differs during census",
        )
        manifest = migration.gc_verifier.parse_blob_manifest_v2(
            manifest_payload, context
        )
        require(
            migration.gc_verifier.blob_key_identity(manifest["blob_key"])
            == migration.gc_verifier.blob_key_identity(blob["blob_key"]),
            "Blob mapping/manifest differ during census",
        )
        for item in manifest["extents"]:
            pointer = item["pointer"]
            add(pointer, "Blob payload")
            extent, payload = resolver.resolve(
                pointer,
                migration.gc_verifier.EXTENT_BLOB,
                "Blob payload",
            )
            require(
                hashlib.sha256(payload).digest() == pointer["payload_sha256"]
                and extent["binding"]["target_checkpoint_generation"]
                <= record["binding"]["generation"],
                "Blob payload differs during census",
            )
    return identities


def _extent_identity_and_pages(
    segment: Mapping[str, Any], extent: Mapping[str, Any]
) -> tuple[tuple[int, int, int, int], frozenset[int]]:
    record = extent["record"]
    segment_generation = segment.get("_generation")
    if segment_generation is None:
        header = segment.get("header", {})
        require(
            header.get("status") == "sealed",
            "extent census has no trusted segment generation",
        )
        segment_generation = header["record"]["binding"]["generation"]
    relative = record["binding"]["self_page"] - segment["base_page"]
    identity = (
        segment["segment_no"],
        segment_generation,
        relative,
        record["binding"]["ordinal"],
    )
    pages = frozenset(
        [record["binding"]["self_page"], record["binding"]["self_page"] + 1]
        + list(
            range(
                segment["base_page"] + record["payload_first_relative_page"],
                segment["base_page"]
                + record["payload_first_relative_page"]
                + record["payload_pages"],
            )
        )
    )
    return identity, pages


def _page_bytes(region: Any, page: int) -> bytes:
    raw = bytes(region[page * PAGE : (page + 1) * PAGE])
    require(len(raw) == PAGE, "extent census page is truncated")
    return raw


def _validate_extent_bytes(
    region: Any,
    segment: Mapping[str, Any],
    extent: Mapping[str, Any],
) -> frozenset[int]:
    """Re-hash exact payload bytes and require zero page-tail padding."""

    record = extent["record"]
    identity, pages = _extent_identity_and_pages(segment, extent)
    del identity
    first = segment["base_page"] + record["payload_first_relative_page"]
    raw = bytes(
        region[first * PAGE : (first + record["payload_pages"]) * PAGE]
    )
    require(
        len(raw) == record["payload_pages"] * PAGE
        and hashlib.sha256(raw[: record["payload_byte_len"]]).digest()
        == record["payload_sha256"]
        and not any(raw[record["payload_byte_len"] :]),
        "extent payload bytes/hash or final-page zero padding differ",
    )
    return pages


def _scan_incomplete_extent_prefix(
    region: Any,
    segment: Mapping[str, Any],
    *,
    validate_payload: bool = True,
) -> tuple[Mapping[str, Any], ...]:
    """Decode every fully sealed extent before an incomplete segment's cut."""

    storage = migration.storage_codec
    header = segment.get("header", {})
    if header.get("status") != "sealed":
        return ()
    binding = header["record"]["binding"]
    base = segment["base_page"]
    relative = storage.DATA_FIRST_PAGE
    ordinal = 1
    extents: list[Mapping[str, Any]] = []
    while relative + 1 < storage.DATA_END_PAGE:
        body_page = base + relative
        seal_page = body_page + 1
        body = _page_bytes(region, body_page)
        seal = _page_bytes(region, seal_page)
        if not any(body) and not any(seal):
            break
        if seal[0xFF0:0x1000] != storage.TERMINAL_MARKER:
            break
        errors: list[str] = []
        extent = storage.decode_pair(
            region,
            body_page,
            seal_page,
            4,
            f"segment {segment['segment_no']} census extent {ordinal}",
            errors,
            storage.extent_validator(
                segment["segment_no"],
                base,
                binding["generation"],
                ordinal,
                relative,
                binding["store_uuid"],
            ),
        )
        require(
            not errors and extent["status"] == "sealed",
            "incomplete segment contains a sealed but invalid extent prefix",
        )
        if validate_payload:
            _validate_extent_bytes(region, segment, extent)
        extents.append(extent)
        relative += extent["record"]["record_span_pages"]
        ordinal += 1
    return tuple(extents)


def _extent_census(
    region: Any,
    structural: Mapping[str, Any],
    selected_recovered: Mapping[str, Any],
    policy: FrozenPolicy,
    *,
    trace_pages: frozenset[int] = frozenset(),
    baseline_identities: frozenset[tuple[int, int, int, int]] = frozenset(),
    baseline_nonzero_pages: frozenset[int] = frozenset(),
    allowed_orphan_identities: frozenset[tuple[int, int, int, int]] = frozenset(),
) -> tuple[int, int, int]:
    reachable: set[tuple[int, int, int, int]] = set()
    slots = migration.v2_checkpoint_slots(region)
    sealed = sorted(
        (slot for slot in slots if slot["status"] == "sealed"),
        key=lambda slot: slot["record"]["binding"]["generation"],
    )
    require(sealed, "extent census found no sealed checkpoint")
    selected_generation = selected_recovered["checkpoint_generation"]
    for checkpoint in sealed:
        generation = checkpoint["record"]["binding"]["generation"]
        if generation == selected_generation:
            recovered = selected_recovered
        else:
            candidate = dict(structural)
            candidate["checkpoint"] = checkpoint
            recovered = migration.reconstruct_v2_checkpoint(
                region,
                candidate,
                require_authority=False,
                authority_policy=policy.authority_policy,
            )
        reachable.update(
            _checkpoint_pointer_identities(region, structural, checkpoint, recovered)
        )

    observed: dict[tuple[int, int, int, int], frozenset[int]] = {}
    allocation = selected_recovered["allocation"]
    storage = migration.storage_codec
    for segment_no, segment in enumerate(structural["segments"]):
        status = segment.get("status")
        require(
            status in {"empty", "sealed", "incomplete"},
            "extent census encountered a corrupt or unknown segment state: "
            f"segment {segment_no}, status={status}, "
            f"errors={segment.get('errors', ())}, "
            f"decode_errors={structural.get('segment_errors', ())[segment_no]}",
        )
        if status == "empty":
            continue
        require(
            trace_pages or baseline_identities or status == "sealed",
            "successful endpoint contains an incomplete non-empty segment",
        )
        if segment_no < len(allocation["states"]):
            state = allocation["states"][segment_no]
            require(
                state in {
                    migration.gc_verifier.SEGMENT_FREE,
                    migration.gc_verifier.SEGMENT_ALLOCATED,
                    migration.gc_verifier.SEGMENT_RETIRED,
                },
                "extent census encountered an unknown allocation state",
            )
        extents = (
            tuple(
                extent
                for extent in segment.get("extents", ())
                if extent.get("status") == "sealed"
            )
            if status == "sealed"
            else _scan_incomplete_extent_prefix(region, segment)
        )
        claimed_pages: set[int] = set()
        for extent in extents:
            identity, pages = _extent_identity_and_pages(segment, extent)
            require(identity not in observed, "extent census repeats a physical identity")
            require(
                not claimed_pages.intersection(pages),
                "extent census finds overlapping physical extent pages",
            )
            _validate_extent_bytes(region, segment, extent)
            if status != "sealed" and identity not in baseline_identities:
                require(
                    pages.issubset(trace_pages),
                    "incomplete-segment sealed extent is not exactly trace-introduced",
                )
            observed[identity] = pages
            claimed_pages.update(pages)

        # The summary-directed parser stops at next_free_page and returns
        # early for incomplete segments. Cover the rest of every append area
        # here so neither a hidden sealed extent nor arbitrary durable bytes
        # can live outside the authoritative census. Existing bytes in a
        # segment proven clean in the independently accepted baseline may
        # remain during a crash; all other non-zero pages must be exact trace
        # pages. Payload-page padding was checked byte-for-byte above.
        base = segment["base_page"]
        for relative in range(storage.DATA_FIRST_PAGE, storage.DATA_END_PAGE):
            page = base + relative
            if page in claimed_pages:
                continue
            raw = _page_bytes(region, page)
            if any(raw):
                require(
                    page in trace_pages or page in baseline_nonzero_pages,
                    "segment append area contains hidden non-authoritative bytes",
                )
    missing = reachable - set(observed)
    require(not missing, "checkpoint pointer escapes the allocated/retired extent census")
    require(
        allowed_orphan_identities.issubset(observed),
        "reviewed historical orphan identity is absent from the physical census",
    )
    orphans = set(observed) - reachable
    explained = set()
    for identity in orphans:
        pages = observed[identity]
        if (
            identity not in baseline_identities
            and pages
            and pages.issubset(trace_pages)
        ):
            explained.add(identity)
    unexplained = orphans - allowed_orphan_identities
    require(
        unexplained == explained,
        "sealed garbage is neither current/retained nor exactly introduced by this trace: "
        f"orphans={sorted(unexplained)}, explained={sorted(explained)}",
    )
    return len(observed), len(reachable), len(explained)


def _qemu_superseded_extent_identities(
    region: Any,
    structural: Mapping[str, Any],
    policy: FrozenPolicy,
) -> frozenset[tuple[int, int, int, int]]:
    """Validate, then authorize only the native gen2/gen3 stale metadata."""

    storage = migration.storage_codec
    lifecycle = policy.document["storage"]["qemu_checkpoint_lifecycle"]
    floor = lifecycle[0]
    specifications: list[tuple[str, Sequence[int], int]] = [
        ("catalog", floor["catalog_root"], migration.gc_verifier.EXTENT_CATALOG),
        ("authority", floor["authority_root"], migration.gc_verifier.EXTENT_AUTHORITY),
    ]
    for item in policy.document["storage"]["qemu_superseded_allocation_extents"]:
        segment_no, segment_generation, relative, ordinal, target = item
        specifications.append(
            (
                f"allocation-{target}",
                (segment_no, segment_generation, ordinal, target, relative),
                migration.gc_verifier.EXTENT_ALLOCATION,
            )
        )

    validated: list[tuple[tuple[int, int, int, int], int]] = []
    for label, specification, expected_kind in specifications:
        segment_no, segment_generation, ordinal, target_generation = specification[:4]
        expected_relative = specification[4] if len(specification) == 5 else None
        require(
            0 <= segment_no < len(structural["segments"]),
            f"QEMU superseded {label} segment is outside the image",
        )
        segment = structural["segments"][segment_no]
        matches = []
        for extent in segment.get("extents", ()):
            if extent.get("status") != "sealed":
                continue
            identity, _pages = _extent_identity_and_pages(segment, extent)
            record = extent["record"]
            if (
                identity[1] == segment_generation
                and identity[3] == ordinal
                and record["extent_kind"] == expected_kind
                and record["binding"]["target_checkpoint_generation"]
                == target_generation
                and (expected_relative is None or identity[2] == expected_relative)
            ):
                matches.append((identity, extent))
        require(
            len(matches) == 1,
            f"QEMU superseded {label} extent identity differs",
        )
        identity, extent = matches[0]
        _validate_extent_bytes(region, segment, extent)
        record = extent["record"]
        first = segment["base_page"] + record["payload_first_relative_page"]
        raw = bytes(region[first * PAGE : (first + record["payload_pages"]) * PAGE])
        payload = raw[: record["payload_byte_len"]]
        if label == "catalog":
            snapshot = migration.gc_verifier.parse_cas_snapshot_v2(
                payload,
                {
                    "store_uuid": record["binding"]["store_uuid"],
                    "admitted_segments": 8,
                    "next_segment_generation": 2,
                },
            )
            require(
                snapshot["checkpoint_generation"] == 2
                and not snapshot["objects"]
                and not snapshot["blobs"],
                "QEMU superseded catalog is not the exact empty generation-2 CAS floor",
            )
        elif label == "authority":
            require(
                payload
                == migration.canonical_empty_authority_payload(
                    2,
                    authority_policy=policy.authority_policy,
                ),
                "QEMU superseded authority is not the exact canonical generation-2 floor",
            )
        else:
            allocation = migration.gc_verifier.parse_allocation_v2(payload)
            allocated = 1 if target_generation == 2 else 2
            admitted = 8 if target_generation == 2 else 14
            require(
                allocation["checkpoint_generation"] == target_generation
                and allocation["admitted_segments"] == admitted
                and allocation["states"]
                == [migration.gc_verifier.SEGMENT_ALLOCATED] * allocated
                + [migration.gc_verifier.SEGMENT_FREE] * (admitted - allocated)
                and allocation["next_segment_generation"] == target_generation
                and allocation["cleaner_reserve_segments"] == 2
                and not allocation["retired"],
                f"QEMU superseded allocation generation {target_generation} differs",
            )
        validated.append((identity, target_generation))

    sealed_generations = [
        slot["record"]["binding"]["generation"]
        for slot in migration.v2_checkpoint_slots(region)
        if slot["status"] == "sealed"
    ]
    require(len(sealed_generations) == 2, "QEMU stale-extent census lacks a retained pair")
    oldest = min(sealed_generations)
    return frozenset(identity for identity, target in validated if target < oldest)


def analyze_storage_region(
    region: Any,
    policy: FrozenPolicy,
    *,
    geometry_profile: str,
    trace_pages: frozenset[int] = frozenset(),
    baseline_identities: frozenset[tuple[int, int, int, int]] = frozenset(),
    baseline_nonzero_pages: frozenset[int] = frozenset(),
) -> DiskAnalysis:
    status, evidence, structural = probe_v2_region(
        region,
        policy,
        geometry_profile=geometry_profile,
    )
    require(
        status in {"valid", "vacant"}
        and evidence is not None
        and structural is not None,
        "Storage V2 region is not independently recoverable: "
        + (str(evidence.get("error", "unknown probe rejection")) if evidence else "no evidence"),
    )
    allowed_orphan_identities = (
        _qemu_superseded_extent_identities(region, structural, policy)
        if geometry_profile == "qemu"
        else frozenset()
    )
    recovered = evidence["recovered"]
    authority = recovered["authority"]
    history = _verify_recovered_graph_semantics(
        recovered,
        policy,
        evidence["selected_checkpoint_generation"],
        "selected Storage V2 checkpoint",
    )
    require(
        (status == "vacant") == (history.classification == "vacant"),
        "Storage V2 probe status differs from recovered graph semantics",
    )
    bindings = [] if authority is None else authority["objects"]
    if history.classification == "vacant":
        require(
            not bindings
            and (authority is None or not authority["external_roots"])
            and not recovered["objects"]
            and not recovered["contents"],
            "Vacant physical authority retains a graph or CAS object",
        )
        sealed, reachable, explained = _extent_census(
            region,
            structural,
            recovered,
            policy,
            trace_pages=trace_pages,
            baseline_identities=baseline_identities,
            baseline_nonzero_pages=baseline_nonzero_pages,
            allowed_orphan_identities=allowed_orphan_identities,
        )
        return DiskAnalysis(
            classification="vacant",
            history=history,
            device_id=evidence["device_id"],
            store_uuid=evidence["store_uuid"],
            geometry=evidence["geometry"],
            checkpoint_generation=evidence["selected_checkpoint_generation"],
            selected_checkpoint_pair_sha256=evidence["selected_checkpoint_pair_sha256"],
            retained_checkpoint_pairs=evidence["retained_checkpoint_pairs"],
            verified_checkpoint_copies=evidence["verified_checkpoint_copies"],
            admitted_segments=recovered["allocation"]["admitted_segments"],
            physical_bindings=0,
            historical_cas_descriptors=0,
            sealed_extents=sealed,
            current_or_retained_extents=reachable,
            trace_explained_orphans=explained,
        )
    sealed, reachable, explained = _extent_census(
        region,
        structural,
        recovered,
        policy,
        trace_pages=trace_pages,
        baseline_identities=baseline_identities,
        baseline_nonzero_pages=baseline_nonzero_pages,
        allowed_orphan_identities=allowed_orphan_identities,
    )
    return DiskAnalysis(
        classification=history.classification,
        history=history,
        device_id=evidence["device_id"],
        store_uuid=evidence["store_uuid"],
        geometry=evidence["geometry"],
        checkpoint_generation=evidence["selected_checkpoint_generation"],
        selected_checkpoint_pair_sha256=evidence["selected_checkpoint_pair_sha256"],
        retained_checkpoint_pairs=evidence["retained_checkpoint_pairs"],
        verified_checkpoint_copies=evidence["verified_checkpoint_copies"],
        admitted_segments=recovered["allocation"]["admitted_segments"],
        physical_bindings=len(bindings),
        historical_cas_descriptors=len(recovered["objects"]),
        sealed_extents=sealed,
        current_or_retained_extents=reachable,
        trace_explained_orphans=explained,
    )


def _all_authoritative_extent_identities(
    region: Any,
    policy: FrozenPolicy,
    *,
    geometry_profile: str,
) -> frozenset[tuple[int, int, int, int]]:
    status, evidence, structural = probe_v2_region(
        region,
        policy,
        geometry_profile=geometry_profile,
    )
    require(status in {"valid", "vacant"} and evidence is not None and structural is not None, "baseline extent image is not valid")
    recovered = evidence["recovered"]
    identities = set()
    for segment in structural["segments"]:
        for extent in segment["extents"]:
            if extent.get("status") == "sealed":
                identity, _pages = _extent_identity_and_pages(segment, extent)
                identities.add(identity)
    return frozenset(identities)


def _baseline_nonzero_append_pages(
    region: Any,
    policy: FrozenPolicy,
    *,
    geometry_profile: str,
) -> frozenset[int]:
    """Pin only exact non-zero append pages from an accepted clean baseline."""

    status, evidence, structural = probe_v2_region(
        region,
        policy,
        geometry_profile=geometry_profile,
    )
    require(
        status in {"valid", "vacant"}
        and evidence is not None
        and structural is not None,
        "baseline append-page image is not valid",
    )
    storage = migration.storage_codec
    pages: set[int] = set()
    for segment in structural["segments"]:
        base = segment["base_page"]
        for relative in range(storage.DATA_FIRST_PAGE, storage.DATA_END_PAGE):
            page = base + relative
            if any(_page_bytes(region, page)):
                pages.add(page)
    return frozenset(pages)


def strict_json_loads(raw: bytes, label: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in out, f"{label} repeats JSON member {key!r}")
            out[key] = value
        return out

    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                VerificationError(f"{label} contains non-finite JSON number {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not canonical JSON: {error}") from error
    require(canonical_json_bytes(value) == raw, f"{label} is not canonical compact JSON")
    return value


@dataclass(frozen=True)
class StoredRef:
    path: str
    sha256: str
    byte_len: int


@dataclass(frozen=True)
class PatchRef:
    offset: int
    blob: StoredRef
    prefix_len: int


@dataclass(frozen=True)
class RecipeDefinition:
    base: StoredRef
    patches: tuple[PatchRef, ...]


def parse_stored_ref(value: Any, label: str) -> StoredRef:
    require(isinstance(value, dict), f"{label} is not a stored-byte reference")
    exact_keys(value, {"path", "sha256", "byte_len"}, label)
    path = exact_text(value["path"], f"{label}.path", 512)
    digest = exact_hex32(value["sha256"], f"{label}.sha256")
    byte_len = exact_int(value["byte_len"], f"{label}.byte_len")
    require(byte_len <= (1 << 40), f"{label}.byte_len exceeds the corpus bound")
    return StoredRef(path, digest, byte_len)


def same_stored_ref(left: StoredRef, right: StoredRef) -> bool:
    return left == right


class RecipeStore:
    """Content-addressed corpus reader backed by a compact temporary index."""

    def __init__(self, manifest: Path) -> None:
        require(manifest.is_file() and not manifest.is_symlink(), "manifest is not a regular non-symlink file")
        self.root = manifest.parent.resolve(strict=True)
        require(not manifest.parent.is_symlink(), "manifest directory is a symlink")
        self._temporary = tempfile.TemporaryDirectory(prefix="vibeos-c78-recipes-")
        self._database_path = Path(self._temporary.name) / "index.sqlite3"
        self._db = sqlite3.connect(self._database_path)
        self._db.execute("PRAGMA journal_mode=OFF")
        self._db.execute("PRAGMA synchronous=OFF")
        self._db.execute("PRAGMA temp_store=MEMORY")
        self._db.execute(
            "CREATE TABLE recipes (digest TEXT PRIMARY KEY, shard TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, referenced INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID"
        )
        self._handles: dict[str, Any] = {}
        self._verified_direct: dict[StoredRef, Path] = {}
        self._referenced_files: set[str] = {manifest.name}
        self._recipe_visiting: set[str] = set()
        self.recipe_count = 0
        self._index_recipe_shards()

    def close(self) -> None:
        for handle in self._handles.values():
            handle.close()
        self._handles.clear()
        self._db.close()
        self._temporary.cleanup()

    def __enter__(self) -> "RecipeStore":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def _safe_file(self, relative: str, label: str) -> Path:
        pure = PurePosixPath(relative)
        require(
            not pure.is_absolute()
            and pure.parts
            and all(part not in {"", ".", ".."} for part in pure.parts)
            and "\\" not in relative
            and str(pure) == relative,
            f"{label} has a non-canonical relative path",
        )
        candidate = self.root.joinpath(*pure.parts)
        current = self.root
        for part in pure.parts:
            current = current / part
            require(not current.is_symlink(), f"{label} traverses a symlink")
        resolved = candidate.resolve(strict=True)
        require(resolved.is_relative_to(self.root), f"{label} escapes the corpus root")
        require(resolved.is_file(), f"{label} is not a regular file")
        self._referenced_files.add(relative)
        return resolved

    @staticmethod
    def _parse_recipe_reference_path(reference: StoredRef, label: str) -> tuple[str, str]:
        require(reference.path.count("#") == 1, f"{label} recipe path has no exact fragment")
        relative, fragment = reference.path.split("#", 1)
        require(
            fragment == reference.sha256
            and relative == f"recipes/{fragment[:1]}.jsonl",
            f"{label} recipe path/digest/shard differ",
        )
        return relative, fragment

    @staticmethod
    def is_recipe(reference: StoredRef) -> bool:
        return "#" in reference.path

    def _validate_reference_shape(self, reference: StoredRef, label: str, *, patch_blob: bool = False) -> None:
        if self.is_recipe(reference):
            require(not patch_blob, f"{label} patch blob recursively names a recipe")
            self._parse_recipe_reference_path(reference, label)
            return
        expected = (
            f"blobs/{reference.sha256}.bin"
            if patch_blob
            else f"bases/{reference.sha256}.raw"
        )
        require(reference.path == expected, f"{label} is not an exact content-addressed path")

    def _parse_recipe_document(self, value: Any, label: str) -> RecipeDefinition:
        require(isinstance(value, dict), f"{label} is not a recipe object")
        exact_keys(value, {"base", "patches"}, label)
        base = parse_stored_ref(value["base"], f"{label}.base")
        self._validate_reference_shape(base, f"{label}.base")
        require(isinstance(value["patches"], list), f"{label}.patches is not a list")
        patches: list[PatchRef] = []
        previous_offset = -1
        previous_end = 0
        for index, item in enumerate(value["patches"]):
            patch_label = f"{label}.patches[{index}]"
            require(isinstance(item, dict), f"{patch_label} is not an object")
            exact_keys(item, {"offset", "blob", "prefix_len"}, patch_label)
            offset = exact_int(item["offset"], f"{patch_label}.offset")
            blob = parse_stored_ref(item["blob"], f"{patch_label}.blob")
            self._validate_reference_shape(blob, f"{patch_label}.blob", patch_blob=True)
            prefix_len = exact_int(item["prefix_len"], f"{patch_label}.prefix_len")
            require(
                prefix_len <= blob.byte_len
                and offset > previous_offset
                and offset >= previous_end
                and offset + prefix_len <= base.byte_len,
                f"{patch_label} violates ordered bounded overlay geometry",
            )
            previous_offset = offset
            previous_end = offset + prefix_len
            patches.append(PatchRef(offset, blob, prefix_len))
        return RecipeDefinition(base, tuple(patches))

    def _index_recipe_shards(self) -> None:
        recipes = self.root / "recipes"
        require(recipes.is_dir() and not recipes.is_symlink(), "corpus recipes directory is absent or a symlink")
        shard_paths = sorted(recipes.iterdir(), key=lambda path: path.name)
        require(shard_paths, "corpus has no recipe shards")
        for shard_path in shard_paths:
            require(
                shard_path.is_file()
                and not shard_path.is_symlink()
                and re.fullmatch(r"[0-9a-f]\.jsonl", shard_path.name) is not None,
                "recipe directory contains a non-canonical shard",
            )
            relative = f"recipes/{shard_path.name}"
            self._referenced_files.add(relative)
            shard_rows = 0
            with shard_path.open("rb") as handle:
                while True:
                    line_at = handle.tell()
                    line = handle.readline(8 * 1024 * 1024 + 1)
                    if not line:
                        break
                    require(len(line) <= 8 * 1024 * 1024 and line.endswith(b"\n"), "recipe shard has an oversized or unterminated row")
                    body = line[:-1]
                    require(body.count(b"\t") == 1, "recipe shard row has no exact digest separator")
                    digest_raw, encoded = body.split(b"\t", 1)
                    try:
                        digest = digest_raw.decode("ascii")
                    except UnicodeDecodeError as error:
                        raise VerificationError("recipe digest is not ASCII") from error
                    exact_hex32(digest, "recipe digest")
                    require(digest[:1] == shard_path.name[:1], "recipe is in the wrong digest shard")
                    require(hashlib.sha256(encoded).hexdigest() == digest, "recipe content address differs")
                    # Schema/canonical-form validation is deferred to the
                    # mandatory reference walk. finish() proves every indexed
                    # recipe was referenced, so an accepted corpus still
                    # parses every row exactly once rather than twice.
                    try:
                        self._db.execute(
                            "INSERT INTO recipes(digest,shard,offset,length) VALUES(?,?,?,?)",
                            (digest, relative, line_at + len(digest_raw) + 1, len(encoded)),
                        )
                    except sqlite3.IntegrityError as error:
                        raise VerificationError(f"duplicate recipe digest {digest}") from error
                    self.recipe_count += 1
                    shard_rows += 1
            require(shard_rows > 0, "corpus contains an empty recipe shard")
        self._db.commit()

    def verify_direct(self, reference: StoredRef, *, kind: str) -> Path:
        require(kind in {"base", "blob"}, "unknown stored-byte kind")
        self._validate_reference_shape(reference, "stored bytes", patch_blob=kind == "blob")
        cached = self._verified_direct.get(reference)
        if cached is not None:
            return cached
        path = self._safe_file(reference.path, "stored bytes")
        require(path.stat().st_size == reference.byte_len, "stored-byte length differs")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        require(digest.hexdigest() == reference.sha256, "stored-byte digest differs")
        self._verified_direct[reference] = path
        return path

    @lru_cache(maxsize=8192)
    def read_blob(self, reference: StoredRef, *, maximum: int = 8 * 1024 * 1024) -> bytes:
        require(reference.byte_len <= maximum, "blob exceeds the independent parser bound")
        return self.verify_direct(reference, kind="blob").read_bytes()

    @lru_cache(maxsize=16384)
    def recipe(self, reference: StoredRef) -> RecipeDefinition:
        relative, digest = self._parse_recipe_reference_path(reference, "recipe reference")
        require(digest not in self._recipe_visiting, "recipe graph contains a cycle")
        require(len(self._recipe_visiting) < 64, "recipe graph exceeds its frozen recursion depth")
        self._recipe_visiting.add(digest)
        try:
            return self._recipe_inner(reference, relative, digest)
        finally:
            self._recipe_visiting.remove(digest)

    def _recipe_inner(self, reference: StoredRef, relative: str, digest: str) -> RecipeDefinition:
        row = self._db.execute(
            "SELECT shard,offset,length FROM recipes WHERE digest=?", (digest,)
        ).fetchone()
        require(row is not None, f"recipe {digest} is absent")
        shard, offset, length = row
        require(shard == relative, "recipe database shard differs")
        self._db.execute("UPDATE recipes SET referenced=1 WHERE digest=?", (digest,))
        handle = self._handles.get(shard)
        if handle is None:
            handle = self._safe_file(shard, "recipe shard").open("rb")
            self._handles[shard] = handle
        handle.seek(offset)
        encoded = handle.read(length)
        require(len(encoded) == length and hashlib.sha256(encoded).hexdigest() == digest, "indexed recipe bytes differ")
        value = strict_json_loads(encoded, f"recipe {digest}")
        definition = self._parse_recipe_document(value, f"recipe {digest}")
        require(definition.base.byte_len == reference.byte_len, "recipe reconstructed length differs")
        if self.is_recipe(definition.base):
            self.recipe(definition.base)
        else:
            self.verify_direct(definition.base, kind="base")
        for patch in definition.patches:
            self.verify_direct(patch.blob, kind="blob")
        return definition

    def finish(self) -> None:
        self._db.commit()
        unreferenced = self._db.execute(
            "SELECT digest FROM recipes WHERE referenced=0 LIMIT 1"
        ).fetchone()
        require(unreferenced is None, "corpus contains an unreferenced recipe")
        actual_files = set()
        for directory in ("bases", "blobs", "recipes"):
            root = self.root / directory
            require(root.is_dir() and not root.is_symlink(), f"corpus {directory} directory differs")
            for path in root.iterdir():
                require(path.is_file() and not path.is_symlink(), f"corpus {directory} contains a non-file")
                actual_files.add(f"{directory}/{path.name}")
        expected_files = self._referenced_files - {"manifest.jsonl"}
        require(actual_files == expected_files, "corpus contains missing or unreferenced content-addressed files")


class ManifestLines:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = path.open("rb")
        self.number = 0

    def close(self) -> None:
        self.handle.close()

    def __enter__(self) -> "ManifestLines":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def next(self, expected_record: str) -> Mapping[str, Any]:
        raw = self.handle.readline(16 * 1024 * 1024 + 1)
        self.number += 1
        require(raw and len(raw) <= 16 * 1024 * 1024 and raw.endswith(b"\n"), f"manifest row {self.number} is absent, oversized, or unterminated")
        value = strict_json_loads(raw[:-1], f"manifest row {self.number}")
        require(isinstance(value, dict) and value.get("record") == expected_record, f"manifest row {self.number} is not {expected_record}")
        return value

    def finish(self) -> None:
        require(self.handle.read(1) == b"", "manifest continues after coverage")


def _validate_manifest_header(row: Mapping[str, Any], policy: FrozenPolicy) -> None:
    exact_keys(
        row,
        {
            "record", "schema", "version", "scope", "policy_sha256",
            "trust_anchor_sha256", "manifest_format", "recipe_format",
            "event_key_fields", "cuts", "trace_digest_semantics", "expected_class_semantics",
            "expected_class_verifier_authority", "verdicts_emitted",
        },
        "manifest header",
    )
    exact_keys(row["cuts"], {"logical", "physical"}, "manifest cuts")
    require(
        row["schema"] == MANIFEST_SCHEMA
        and row["version"] == 1
        and row["scope"] == SCOPE
        and row["policy_sha256"] == policy.external_policy_sha256
        and row["trust_anchor_sha256"] == hashlib.sha256(policy.active_public_key).hexdigest()
        and row["manifest_format"] == "json-lines-v1"
        and row["recipe_format"] == "recursive-base-plus-ordered-overlay-prefix-patches-v1"
        and row["event_key_fields"] == list(CANONICAL_EVENT_FIELDS)
        and row["cuts"] == {"logical": [0, BLOCK], "physical": [0, PAGE]}
        and row["trace_digest_semantics"]
        == {
            "geometry_sha256": "frozen-content-independent-coverage-identity",
            "trace_sha256": "data-driven-content-evidence",
        }
        and row["expected_class_semantics"] == "coverage-hint-only"
        and row["expected_class_verifier_authority"] is False
        and row["verdicts_emitted"] is False,
        "manifest header differs from the independently frozen corpus schema",
    )


@dataclass(frozen=True)
class EventImage:
    recipe: StoredRef
    raw_sha256: str | None


def _event_key(fields: Mapping[str, Any]) -> str:
    values: list[str] = []
    for field in CANONICAL_EVENT_FIELDS[:5]:
        value = fields[field]
        require(
            isinstance(value, str) and EVENT_TOKEN.fullmatch(value) is not None,
            f"event {field} is not a canonical token",
        )
        values.append(value)
    values.extend((str(fields["ordinal"]), str(fields["cut"])))
    return "|".join(values)


def _validate_event(
    row: Mapping[str, Any],
    *,
    scenario: str,
    transition: str,
    mode: str,
    media_kind: str,
    phase: str,
    operation: str,
    ordinal: int,
    cut: int,
    expected_hint: str,
) -> EventImage:
    exact_keys(
        row,
        {
            "record", "key", "scenario", "transition", "mode", "media_kind",
            "phase", "operation", "ordinal", "cut", "expected_class", "image",
            "detail",
        },
        "manifest event",
    )
    expected = {
        "scenario": scenario,
        "transition": transition,
        "mode": mode,
        "phase": phase,
        "operation": operation,
        "ordinal": ordinal,
        "cut": cut,
    }
    require(
        all(row[field] == value for field, value in expected.items())
        and row["media_kind"] == media_kind
        and row["expected_class"] == expected_hint
        and row["key"] == _event_key(expected),
        "manifest event differs from its independently derived canonical key/class geometry",
    )
    image = row["image"]
    require(isinstance(image, dict), "event image is not an object")
    exact_keys(image, {"path", "sha256", "byte_len", "recipe_sha256"}, "event image")
    recipe = StoredRef(
        exact_text(image["path"], "event recipe path", 512),
        exact_hex32(image["recipe_sha256"], "event recipe digest"),
        exact_int(image["byte_len"], "event image byte length"),
    )
    if image["sha256"] is None:
        raw_sha = None
    else:
        raw_sha = exact_hex32(image["sha256"], "event raw image digest")
    return EventImage(recipe, raw_sha)


def _logical_prefix_class(
    prefix: bytes,
    policy: FrozenPolicy,
    *,
    old_class: str,
) -> str:
    try:
        if not prefix:
            require(old_class == "vacant", "empty logical prefix is not Vacant")
            return "no-g0-publication"
        state = migration.recover_record_stream(prefix)
        if old_class == "vacant":
            if not state.grants and not state.live and not state.slots:
                return "no-g0-publication"
            parsed = parse_complete_history(prefix, policy)
            return parsed.classification if parsed.classification == "g0" else "reject"
        require(old_class == "g0", "unknown logical predecessor class")
        base_root = state.grants[0] if state.grants else None
        if (
            len(state.grants) == 1
            and base_root is not None
            and base_root.generation == 0
            and state.live == {base_root.derivation: base_root}
            and state.slots == {(GRAPH_SPACE, 0): (0, base_root.derivation)}
        ):
            return "no-g1-publication"
        parsed = parse_complete_history(prefix, policy)
        return parsed.classification if parsed.classification == "g1" else "reject"
    except EXPECTED_REJECTION_ERRORS:
        return "reject"


def _validate_logical_recipe(
    store: RecipeStore,
    reference: StoredRef,
    domain_base: StoredRef,
    records: Sequence[bytes],
    record_prefixes: Sequence[bytes],
    *,
    base_records: int,
    ordinal: int,
    cut: int,
) -> None:
    definition = store.recipe(reference)
    require(not store.is_recipe(definition.base), "logical recipe recursively changes its base")
    require(same_stored_ref(definition.base, domain_base), "logical recipe base differs from its domain")
    expected: list[tuple[int, bytes, int]] = []
    base_len = base_records * BLOCK
    if ordinal:
        expected.append(
            (
                base_len,
                record_prefixes[ordinal],
                ordinal * BLOCK,
            )
        )
    if cut:
        expected.append(
            (
                base_len + ordinal * BLOCK,
                records[ordinal],
                cut,
            )
        )
    require(len(definition.patches) == len(expected), "logical recipe patch count differs")
    for patch, (offset, content, prefix_len) in zip(definition.patches, expected):
        require(
            patch.offset == offset
            and patch.prefix_len == prefix_len
            and patch.blob.byte_len == len(content)
            and store.read_blob(patch.blob, maximum=LOGICAL_RECORDS_PER_TRANSITION * BLOCK) == content,
            "logical recipe patch bytes/geometry differ from the declared record prefix",
        )


def verify_logical_domain(
    lines: ManifestLines,
    store: RecipeStore,
    policy: FrozenPolicy,
    *,
    scenario: str,
    transition: str,
    old_class: str,
    after_class: str,
) -> tuple[int, ParsedHistory]:
    row = lines.next("logical-domain")
    exact_keys(
        row,
        {"record", "scenario", "transition", "base", "record_count", "record_size", "cuts", "record_blobs"},
        "logical domain",
    )
    require(
        row["scenario"] == scenario
        and row["transition"] == transition
        and row["record_count"] == LOGICAL_RECORDS_PER_TRANSITION
        and row["record_size"] == BLOCK
        and row["cuts"] == [0, BLOCK]
        and isinstance(row["record_blobs"], list)
        and len(row["record_blobs"]) == LOGICAL_RECORDS_PER_TRANSITION,
        "logical domain geometry differs",
    )
    base = parse_stored_ref(row["base"], "logical domain base")
    require(not store.is_recipe(base), "logical domain base is a recipe")
    base_path = store.verify_direct(base, kind="base")
    base_bytes = base_path.read_bytes()
    base_records = 0 if old_class == "vacant" else LOGICAL_RECORDS_PER_TRANSITION
    final_records = base_records + LOGICAL_RECORDS_PER_TRANSITION
    require(base.byte_len == final_records * BLOCK, "logical base capacity differs")
    if old_class == "vacant":
        require(not any(base_bytes), "Vacant logical base is non-zero")
    else:
        require(
            parse_complete_history(base_bytes[:base_records * BLOCK], policy, 1).classification == "g0"
            and not any(base_bytes[base_records * BLOCK:]),
            "logical upgrade base is not data-driven G0 plus an empty suffix",
        )
    record_blobs = tuple(
        parse_stored_ref(item, f"logical record blob[{index}]")
        for index, item in enumerate(row["record_blobs"])
    )
    records = tuple(store.read_blob(blob, maximum=BLOCK) for blob in record_blobs)
    require(all(len(record) == BLOCK for record in records), "logical record blob size differs")
    record_prefixes: list[bytes] = [b""]
    for record in records:
        record_prefixes.append(record_prefixes[-1] + record)
    require(
        len(record_prefixes) == LOGICAL_RECORDS_PER_TRANSITION + 1
        and all(
            len(prefix) == ordinal * BLOCK
            for ordinal, prefix in enumerate(record_prefixes)
        ),
        "logical record-prefix cache geometry differs",
    )
    final_image = bytearray(base_bytes)
    base_len = base_records * BLOCK
    final_image[base_len:] = record_prefixes[-1]
    final_history = parse_complete_history(bytes(final_image), policy, final_records // LOGICAL_RECORDS_PER_TRANSITION)
    require(final_history.classification == after_class, "logical domain final bytes differ from its frozen transition")

    # A cut shorter than one complete record cannot publish it: the final byte
    # of the mandatory seal remains zero, while the canonical seal ends in a
    # non-zero byte. Decode each complete cumulative prefix exactly once; all
    # 513 cuts per record still receive their own recipe/raw-SHA checks below.
    require(legacy.SEAL and legacy.SEAL[-1] != 0, "logical record seal lacks a non-zero terminal byte")
    complete_prefixes = tuple(
        base_bytes[:base_len] + record_prefixes[ordinal]
        for ordinal in range(LOGICAL_RECORDS_PER_TRANSITION + 1)
    )
    prefix_classes = tuple(
        _logical_prefix_class(prefix, policy, old_class=old_class)
        for prefix in complete_prefixes
    )
    event_count = 0
    for ordinal, record in enumerate(records):
        for cut in LOGICAL_CUTS:
            final = ordinal == LOGICAL_RECORDS_PER_TRANSITION - 1 and cut == BLOCK
            operation = "complete" if cut == BLOCK else "prefix"
            hint = after_class if final else f"no-{after_class}-publication"
            event = lines.next("event")
            image = _validate_event(
                event,
                scenario=scenario,
                transition=transition,
                mode="durable-record-stream",
                media_kind="authority-record-stream",
                phase="record",
                operation=operation,
                ordinal=ordinal,
                cut=cut,
                expected_hint=hint,
            )
            exact_keys(event["detail"], {"record_ordinal", "record_count"}, "logical event detail")
            require(
                event["detail"] == {"record_ordinal": ordinal, "record_count": LOGICAL_RECORDS_PER_TRANSITION},
                "logical event detail differs",
            )
            require(image.raw_sha256 is not None and image.recipe.byte_len == len(final_image), "logical event lacks its full raw digest/length")
            _validate_logical_recipe(
                store,
                image.recipe,
                base,
                records,
                record_prefixes,
                base_records=base_records,
                ordinal=ordinal,
                cut=cut,
            )
            raw = bytearray(base_bytes)
            if ordinal:
                raw[base_len:base_len + ordinal * BLOCK] = record_prefixes[ordinal]
            raw[base_len + ordinal * BLOCK:base_len + ordinal * BLOCK + cut] = record[:cut]
            require(hashlib.sha256(raw).hexdigest() == image.raw_sha256, "logical event raw image digest differs")
            cached = prefix_classes[ordinal + (1 if cut == BLOCK else 0)]
            if final:
                require(cached == after_class, "logical final event did not publish its exact graph")
            else:
                require(
                    cached in {f"no-{after_class}-publication", "reject"},
                    "logical non-final prefix published a new graph/root/version",
                )
            event_count += 1
    require(event_count == LOGICAL_RECORDS_PER_TRANSITION * (BLOCK + 1), "logical event count differs")
    return event_count, final_history


def _regular_evidence_file(path: Path, label: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"{label} is not a regular non-symlink file")


def _files_equal(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as a, right.open("rb") as b:
        while True:
            left_chunk = a.read(1024 * 1024)
            right_chunk = b.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


@contextmanager
def _mapped_file(path: Path, *, access: int = mmap.ACCESS_READ) -> Iterator[mmap.mmap]:
    with path.open("rb") as handle:
        mapped = mmap.mmap(handle.fileno(), 0, access=access)
        try:
            yield mapped
        finally:
            mapped.close()


def _analyze_qemu_image(
    path: Path,
    unmanaged_prefix: bytes,
    policy: FrozenPolicy,
    expected_class: str,
) -> DiskAnalysis:
    _regular_evidence_file(path, f"{expected_class} powered-off image")
    require(path.stat().st_size % BLOCK == 0, "powered-off QEMU image is not block aligned")
    with _mapped_file(path) as image:
        migration.verify_image(
            image,
            unmanaged_prefix,
            None,
            expect_native=True,
            authority_policy=policy.authority_policy,
        )
        first = migration.V2_FIRST * BLOCK
        end = migration.v2_managed_end(image)
        region = memoryview(image)[first:end]
        try:
            analysis = analyze_storage_region(region, policy, geometry_profile="qemu")
        finally:
            region.release()
    require(analysis.classification == expected_class, f"powered-off image is not exact {expected_class.upper()}")
    require(analysis.trace_explained_orphans == 0, "successful powered-off image contains a CAS orphan")
    _require_dual_checkpoint_endpoint(analysis, f"powered-off {expected_class.upper()} image")
    return analysis


def _require_same_bundle(left: VersionBundle, right: VersionBundle, label: str) -> None:
    require(
        left.artifacts == right.artifacts
        and left.evidences == right.evidences
        and left.graph_evidence == right.graph_evidence
        and left.descriptor == right.descriptor,
        f"{label} differs byte-for-byte across independently parsed disks",
    )


def _verify_canonical_transcript_surface(
    raw: str,
    expected_marker: str,
    label: str,
) -> None:
    """Reject serial controls and any raw durable/runtime identity spelling."""

    require(
        all(character in "\r\n" or 0x20 <= ord(character) <= 0x7E for character in raw),
        f"{label} contains non-canonical serial bytes",
    )
    lines = [line for line in raw.replace("\r", "\n").splitlines() if line]
    diagnostic_lines = [line for line in lines if line != expected_marker]
    require(
        not any(
            re.search(r"\b(?:fatal|panic|panicked)\b", line, re.IGNORECASE)
            for line in diagnostic_lines
        ),
        f"{label} contains a fatal/panic diagnostic",
    )
    forbidden_literals = (
        "ObjectId",
        "SpaceId",
        "DerivationId",
        "TransactionId",
        "ResourceToken",
        "InstanceToken",
        "TaskId",
        "ArenaId",
        "CSpaceId",
        "MemoryToken",
        "FuelToken",
        "PendingCallToken",
        "HostOperationToken",
        "AllocationDomain",
        "OwnerId",
        "Cap {",
        "Capability(",
        "public_key=",
        "signature=",
        "slot=",
        "generation=",
        "digest=",
        "sha256=",
    )
    forbidden_patterns = (
        re.compile(r"\btoken\b", re.IGNORECASE),
        re.compile(
            r"\b[A-Za-z][A-Za-z0-9]*(?:Token|Id|ID|Identity|Domain|Alias)\b"
        ),
        re.compile(
            r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
            r"(?:token|id|identity|domain|alias)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:object|space|derivation|transaction|owner|task|arena|cspace)"
            r"\s+(?:id|identity)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:cap|capability)\b(?=\s*(?:[\(\{\[<:=]|(?:0x)?[0-9]))",
            re.IGNORECASE,
        ),
    )
    require(
        not any(token in line for token in forbidden_literals for line in diagnostic_lines)
        and not any(
            pattern.search(line)
            for pattern in forbidden_patterns
            for line in diagnostic_lines
        ),
        f"{label} leaks a raw durable/runtime identity",
    )


def verify_qemu_evidence(
    policy: FrozenPolicy,
    *,
    g0_image: Path,
    g1_image: Path,
    c76_cold_image: Path,
    c77_cold1_image: Path,
    final_image: Path,
    c76_logs: Sequence[Path],
    c77_logs: Sequence[Path],
) -> tuple[dict[str, Any], ParsedHistory, ParsedHistory]:
    images = (g0_image, g1_image, c76_cold_image, c77_cold1_image, final_image)
    for index, path in enumerate(images):
        _regular_evidence_file(path, f"QEMU image[{index}]")
    require(not _files_equal(g0_image, g1_image), "G0/G1 QEMU images are byte-identical")
    for path in (c76_cold_image, c77_cold1_image, final_image):
        require(_files_equal(g1_image, path), "a cold/final QEMU image differs from powered-off G1")
    # No byte from the evidence image may choose its own immutable baseline.
    # C7.8 authorizes an all-zero unmanaged prefix and verifies every image
    # against that reviewed value.
    unmanaged_prefix = bytes(migration.M4_FIRST * BLOCK)
    g0 = _analyze_qemu_image(g0_image, unmanaged_prefix, policy, "g0")
    g1 = _analyze_qemu_image(g1_image, unmanaged_prefix, policy, "g1")
    # The three byte-identical no-write copies have already been compared over
    # every byte; parse the final one again so acceptance never rests only on a
    # comparison with an unparsed source.
    final = _analyze_qemu_image(final_image, unmanaged_prefix, policy, "g1")
    _require_storage_transition(g0, g1, "QEMU G0-to-G1 publication")
    require(
        g0.checkpoint_generation == 4
        and g1.checkpoint_generation == 5
        and final.device_id == g1.device_id
        and final.store_uuid == g1.store_uuid
        and final.geometry == g1.geometry
        and final.checkpoint_generation == g1.checkpoint_generation
        and final.selected_checkpoint_pair_sha256 == g1.selected_checkpoint_pair_sha256
        and final.retained_checkpoint_pairs == g1.retained_checkpoint_pairs,
        "QEMU graph publication checkpoint sequence differs",
    )
    _require_same_bundle(g0.history.versions[0], g1.history.versions[0], "retained G0")
    _require_same_bundle(g1.history.versions[0], final.history.versions[0], "cold retained G0")
    _require_same_bundle(g1.history.versions[1], final.history.versions[1], "cold current G1")

    require(len(c76_logs) == 3 and len(c77_logs) == 2, "boot transcript cardinality differs")
    for index, (path, expected) in enumerate(
        zip(c76_logs, (c76_codec.BOOT1_PASS, c76_codec.BOOT2_PASS, c76_codec.BOOT3_PASS)),
        1,
    ):
        _regular_evidence_file(path, f"C7.6 boot {index} transcript")
        raw = path.read_bytes().decode("utf-8")
        _verify_canonical_transcript_surface(raw, expected, f"C7.6 boot {index} transcript")
        c76_codec.verify_boot_transcript(raw, expected, index)
    for index, path in enumerate(c77_logs, 1):
        _regular_evidence_file(path, f"C7.7 boot {index} transcript")
        raw = path.read_bytes().decode("utf-8")
        _verify_canonical_transcript_surface(raw, c77_reports.C77_PASS, f"C7.7 boot {index} transcript")
        c77_reports.verify_c77_boot_transcript(raw, index)

    report = {
        "g0_checkpoint_generation": g0.checkpoint_generation,
        "g1_checkpoint_generation": g1.checkpoint_generation,
        "same_device_and_store": True,
        "reviewed_geometry_profiles_matched": True,
        "g1_retains_exact_g0_checkpoint_pair": True,
        "powered_off_images": 5,
        "byte_identical_g1_images": 4,
        "g0_versions": len(g0.history.versions),
        "g1_versions": len(g1.history.versions),
        "replacements": 1,
        "g0_sealed_extents": g0.sealed_extents,
        "g1_sealed_extents": g1.sealed_extents,
        "g0_reachable_extents": g0.current_or_retained_extents,
        "g1_reachable_extents": g1.current_or_retained_extents,
        "cas_orphans": 0,
        "c76_boot_logs": 3,
        "c77_boot_logs": 2,
    }
    return report, g0.history, g1.history


@dataclass(frozen=True)
class SnapshotRecipe:
    reference: StoredRef
    pages: Mapping[int, StoredRef]


def _snapshot_recipe(
    store: RecipeStore,
    reference: StoredRef,
    initial: StoredRef,
) -> SnapshotRecipe:
    definition = store.recipe(reference)
    require(
        not store.is_recipe(definition.base)
        and same_stored_ref(definition.base, initial),
        "physical snapshot recipe does not directly overlay its domain base",
    )
    require(initial.byte_len % PAGE == 0, "physical domain base is not page aligned")
    pages: dict[int, StoredRef] = {}
    for patch in definition.patches:
        require(
            patch.offset % PAGE == 0
            and patch.prefix_len == PAGE
            and patch.blob.byte_len == PAGE,
            "physical snapshot patch is not one complete page",
        )
        page = patch.offset // PAGE
        require(page < initial.byte_len // PAGE and page not in pages, "physical snapshot page is out of range or repeated")
        pages[page] = patch.blob
    return SnapshotRecipe(reference, pages)


@lru_cache(maxsize=131072)
def _base_page_digest(path_text: str, byte_len: int, page: int) -> str:
    path = Path(path_text)
    require(0 <= page < byte_len // PAGE, "physical page is outside its base")
    with path.open("rb") as handle:
        handle.seek(page * PAGE)
        raw = handle.read(PAGE)
    require(len(raw) == PAGE, "physical base page is truncated")
    return hashlib.sha256(raw).hexdigest()


def _snapshot_page_digest(
    store: RecipeStore,
    initial: StoredRef,
    pages: Mapping[int, StoredRef],
    page: int,
) -> str:
    blob = pages.get(page)
    if blob is not None:
        return blob.sha256
    base_path = store.verify_direct(initial, kind="base")
    return _base_page_digest(str(base_path), initial.byte_len, page)


def _changed_snapshot_pages(
    store: RecipeStore,
    initial: StoredRef,
    before: Mapping[int, StoredRef],
    after: Mapping[int, StoredRef],
) -> tuple[tuple[int, str, str], ...]:
    changed = []
    for page in sorted(set(before) | set(after)):
        before_digest = _snapshot_page_digest(store, initial, before, page)
        after_digest = _snapshot_page_digest(store, initial, after, page)
        if before_digest != after_digest:
            changed.append((page, before_digest, after_digest))
    return tuple(changed)


def _same_snapshot(
    store: RecipeStore,
    initial: StoredRef,
    left: Mapping[int, StoredRef],
    right: Mapping[int, StoredRef],
) -> bool:
    return not _changed_snapshot_pages(store, initial, left, right)


class PhysicalSnapshotClassifier:
    def __init__(
        self,
        store: RecipeStore,
        policy: FrozenPolicy,
        initial: StoredRef,
        initial_class: str,
    ) -> None:
        self.store = store
        self.policy = policy
        self.initial = initial
        self.initial_path = store.verify_direct(initial, kind="base")
        with _mapped_file(self.initial_path) as region:
            initial_analysis = analyze_storage_region(region, policy, geometry_profile="corpus")
            self.baseline_identities = _all_authoritative_extent_identities(
                region,
                policy,
                geometry_profile="corpus",
            )
            self.baseline_nonzero_pages = _baseline_nonzero_append_pages(
                region,
                policy,
                geometry_profile="corpus",
            )
        require(initial_analysis.classification == initial_class, "physical trace base class differs")
        require(initial_analysis.trace_explained_orphans == 0, "physical trace base contains an orphan")
        if initial_class in {"g0", "g1"}:
            _require_dual_checkpoint_endpoint(initial_analysis, f"physical {initial_class.upper()} before endpoint")
        self.initial_analysis = initial_analysis
        self.cache: dict[str, tuple[str, DiskAnalysis | None]] = {}
        self.rejection_reasons: dict[str, str] = {}

    def classify(
        self,
        reference: StoredRef,
        pages: Mapping[int, StoredRef],
    ) -> tuple[str, DiskAnalysis | None]:
        cached = self.cache.get(reference.sha256)
        if cached is not None:
            return cached
        try:
            with _mapped_file(self.initial_path, access=mmap.ACCESS_COPY) as region:
                for page, blob in sorted(pages.items()):
                    raw = self.store.read_blob(blob, maximum=PAGE)
                    require(len(raw) == PAGE, "physical overlay blob is not one page")
                    region[page * PAGE:(page + 1) * PAGE] = raw
                trace_pages = frozenset(
                    page
                    for page in pages
                    if _snapshot_page_digest(self.store, self.initial, {}, page)
                    != pages[page].sha256
                )
                analysis = analyze_storage_region(
                    region,
                    self.policy,
                    geometry_profile="corpus",
                    trace_pages=trace_pages,
                    baseline_identities=self.baseline_identities,
                    baseline_nonzero_pages=self.baseline_nonzero_pages,
                )
            result = (analysis.classification, analysis)
        except EXPECTED_REJECTION_ERRORS as error:
            self.rejection_reasons[reference.sha256] = str(error)
            result = ("reject", None)
        self.cache[reference.sha256] = result
        return result


def _validate_nested_page_recipe(
    store: RecipeStore,
    reference: StoredRef,
    base: StoredRef,
    *,
    page: int,
    after_blob: StoredRef,
    cut: int,
) -> None:
    definition = store.recipe(reference)
    require(
        same_stored_ref(definition.base, base)
        and len(definition.patches) == 1,
        "physical page-prefix recipe does not have its exact prior snapshot base",
    )
    patch = definition.patches[0]
    require(
        patch.offset == page * PAGE
        and same_stored_ref(patch.blob, after_blob)
        and patch.prefix_len == cut,
        "physical page-prefix recipe differs from its request prefix",
    )


def _physical_prefix_class(
    before_class: str,
    after_class: str,
    before_page: bytes,
    after_page: bytes,
    cut: int,
) -> str:
    candidate = after_page[:cut] + before_page[cut:]
    if candidate == before_page:
        return before_class
    if candidate == after_page:
        return after_class
    return "needs-independent-parse"


def _snapshot_page_bytes(
    store: RecipeStore,
    initial: StoredRef,
    pages: Mapping[int, StoredRef],
    page: int,
) -> bytes:
    blob = pages.get(page)
    if blob is not None:
        return store.read_blob(blob, maximum=PAGE)
    path = store.verify_direct(initial, kind="base")
    with path.open("rb") as handle:
        handle.seek(page * PAGE)
        raw = handle.read(PAGE)
    require(len(raw) == PAGE, "physical snapshot page is truncated")
    return raw


def _freeze_parser_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, dict):
        return tuple(
            (key, _freeze_parser_value(item))
            for key, item in sorted(value.items())
            if not key.startswith("_")
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_parser_value(item) for item in value)
    return value


def _affected_page_roles(
    structurals: Sequence[Mapping[str, Any]],
    page: int,
    *,
    extra_segment_extents: Sequence[
        tuple[Mapping[str, Any], Sequence[Mapping[str, Any]]]
    ] = (),
) -> tuple[tuple[Any, ...], ...]:
    storage = migration.storage_codec
    roles: set[tuple[Any, ...]] = set()
    anchor_pairs = (
        (0, 1, 1),
        (2, 3, 1),
        (4, 5, 2),
        (6, 7, 2),
    )
    for body, seal, kind in anchor_pairs:
        if page in {body, seal}:
            roles.add(("pair", body, seal, kind))
    if 8 <= page < storage.ANCHOR_PAGES:
        roles.add(("reserved-anchor", page))
    if page < storage.ANCHOR_PAGES:
        return tuple(sorted(roles, key=repr))
    segment_no = (page - storage.ANCHOR_PAGES) // storage.SEGMENT_PAGES
    base = storage.segment_base_page(segment_no)
    static_pairs = (
        (base, base + 1, 3),
        (base + storage.SUMMARY_BODY_PAGE, base + storage.SUMMARY_SEAL_PAGE, 5),
        (base + storage.SEGMENT_SEAL_BODY_PAGE, base + storage.SEGMENT_SEAL_PAGE, 6),
    )
    for body, seal, kind in static_pairs:
        if page in {body, seal}:
            roles.add(("pair", body, seal, kind))
    segment_extent_sources: list[
        tuple[Mapping[str, Any], Sequence[Mapping[str, Any]]]
    ] = []
    for structural in structurals:
        segments = structural.get("segments", ())
        if not (0 <= segment_no < len(segments)):
            continue
        segment = segments[segment_no]
        segment_extent_sources.append((segment, segment.get("extents", ())))
    segment_extent_sources.extend(extra_segment_extents)
    for segment, extents in segment_extent_sources:
        for extent in extents:
            if extent.get("status") != "sealed":
                continue
            record = extent["record"]
            body = record["binding"]["self_page"]
            if page in {body, body + 1}:
                roles.add(("pair", body, body + 1, 4))
            first = segment["base_page"] + record["payload_first_relative_page"]
            count = record["payload_pages"]
            if first <= page < first + count:
                roles.add(
                    (
                        "payload",
                        first,
                        count,
                        record["payload_byte_len"],
                        record["payload_sha256"].hex(),
                    )
                )
    if not roles:
        roles.add(("untyped-page", page))
    return tuple(sorted(roles, key=repr))


class PageCutEquivalenceClassifier:
    """Classify every byte cut with page-local parser equivalence classes.

    Every distinct local parser outcome is backed once by a complete
    Storage/CAS/authority analysis.  Grouping is limited to cases where the
    low-level decoder observes the same sealed/unsealed/corrupt state (or the
    same payload commitment result); candidate pages are never classified as
    reject merely because they are mixed.
    """

    def __init__(
        self,
        classifier: PhysicalSnapshotClassifier,
        prior: SnapshotRecipe,
        page: int,
        input_blob: StoredRef,
    ) -> None:
        self.classifier = classifier
        self.store = classifier.store
        self.prior = prior
        self.page = page
        self.input_blob = input_blob
        self.before = _snapshot_page_bytes(self.store, classifier.initial, prior.pages, page)
        self.after = self.store.read_blob(input_blob, maximum=PAGE)
        require(len(self.before) == PAGE and len(self.after) == PAGE, "page-cut endpoint length differs")
        self._handle = classifier.initial_path.open("rb")
        self.region = mmap.mmap(self._handle.fileno(), 0, access=mmap.ACCESS_COPY)
        for overlay_page, blob in sorted(prior.pages.items()):
            self.region[overlay_page * PAGE:(overlay_page + 1) * PAGE] = self.store.read_blob(blob, maximum=PAGE)
        before_structural = migration.gc_verifier.parse_raw_structure(self.region)
        before_extra = self._incomplete_extent_roles(before_structural)
        self.region[page * PAGE:(page + 1) * PAGE] = self.after
        after_structural = migration.gc_verifier.parse_raw_structure(self.region)
        after_extra = self._incomplete_extent_roles(after_structural)
        self.region[page * PAGE:(page + 1) * PAGE] = self.before
        self.roles = _affected_page_roles(
            (before_structural, after_structural),
            page,
            extra_segment_extents=before_extra + after_extra,
        )
        self.results: dict[Any, tuple[str, DiskAnalysis | None]] = {}

    def _incomplete_extent_roles(
        self,
        structural: Mapping[str, Any],
    ) -> tuple[tuple[Mapping[str, Any], Sequence[Mapping[str, Any]]], ...]:
        storage = migration.storage_codec
        if self.page < storage.ANCHOR_PAGES:
            return ()
        segment_no = (self.page - storage.ANCHOR_PAGES) // storage.SEGMENT_PAGES
        segments = structural.get("segments", ())
        if not (0 <= segment_no < len(segments)):
            return ()
        segment = segments[segment_no]
        if segment.get("status") != "incomplete":
            return ()
        try:
            extents = _scan_incomplete_extent_prefix(
                self.region,
                segment,
                validate_payload=False,
            )
        except EXPECTED_REJECTION_ERRORS:
            return ()
        return ((segment, extents),)

    def close(self) -> None:
        self.region.close()
        self._handle.close()

    def __enter__(self) -> "PageCutEquivalenceClassifier":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def _fingerprint(self, candidate: bytes) -> tuple[Any, ...]:
        storage = migration.storage_codec
        fingerprints: list[Any] = []
        for role in self.roles:
            if role[0] == "pair":
                _tag, body, seal, kind = role
                errors: list[str] = []
                decoded = storage.decode_pair(
                    self.region,
                    body,
                    seal,
                    kind,
                    "C7.8 affected pair",
                    errors,
                )
                status = decoded["status"]
                if status == "sealed":
                    fingerprints.append(
                        (role, status, decoded["_digest"]["body_sha256"].hex(), _freeze_parser_value(decoded["record"]))
                    )
                else:
                    # For corrupt pairs, the full parser consumes only the
                    # presence of a corruption; for unsealed/empty pairs it
                    # consumes exactly that publication state.
                    fingerprints.append((role, status))
            elif role[0] == "payload":
                _tag, first, count, byte_len, expected_sha = role
                raw = bytes(self.region[first * PAGE:(first + count) * PAGE])
                observed = hashlib.sha256(raw[:byte_len]).hexdigest()
                fingerprints.append(
                    (
                        role,
                        "match" if observed == expected_sha else "mismatch",
                        "tail-zero" if not any(raw[byte_len:]) else "tail-nonzero",
                    )
                )
            elif role[0] == "reserved-anchor":
                fingerprints.append((role, "zero" if not any(candidate) else "nonzero"))
            else:
                fingerprints.append((role, "zero" if not any(candidate) else "nonzero"))
        return tuple(fingerprints)

    def classify(self, cut: int) -> tuple[str, DiskAnalysis | None]:
        require(0 <= cut <= PAGE, "physical cut is out of range")
        candidate = self.after[:cut] + self.before[cut:]
        shortcut = _physical_prefix_class("before", "after", self.before, self.after, cut)
        if shortcut == "before":
            return self.classifier.classify(self.prior.reference, self.prior.pages)
        self.region[self.page * PAGE:(self.page + 1) * PAGE] = candidate
        fingerprint = self._fingerprint(candidate)
        cached = self.results.get(fingerprint)
        if cached is not None:
            return cached
        trace_pages = {
            overlay_page
            for overlay_page, blob in self.prior.pages.items()
            if _snapshot_page_digest(self.store, self.classifier.initial, {}, overlay_page)
            != blob.sha256
        }
        base_page = _snapshot_page_bytes(self.store, self.classifier.initial, {}, self.page)
        if candidate != base_page:
            trace_pages.add(self.page)
        try:
            analysis = analyze_storage_region(
                self.region,
                self.classifier.policy,
                geometry_profile="corpus",
                trace_pages=frozenset(trace_pages),
                baseline_identities=self.classifier.baseline_identities,
                baseline_nonzero_pages=self.classifier.baseline_nonzero_pages,
            )
            result = (analysis.classification, analysis)
        except EXPECTED_REJECTION_ERRORS:
            result = ("reject", None)
        self.results[fingerprint] = result
        return result


@dataclass(frozen=True)
class PhysicalPin:
    scenario: str
    transition: str
    mode: str
    before_class: str
    after_class: str
    operations: int
    writes: int
    flushes: int
    requested_pages: int
    geometry_sha256: str
    events: int


@dataclass(frozen=True)
class PhysicalDomainResult:
    events: int
    before: StoredRef
    after: StoredRef
    before_analysis: DiskAnalysis
    after_analysis: DiskAnalysis
    class_counts: Mapping[str, int]


PHYSICAL_PINS = (
    PhysicalPin(
        "physical-install", "vacant-to-g0", "page-fallback", "vacant", "g0",
        49, 45, 4, 45,
        "ebad5161606d8b161e7dfa1db8ee158ecc0ff08f0b975c1a2ef63c362ad9d5bc",
        184420,
    ),
    PhysicalPin(
        "physical-upgrade", "g0-to-g1", "page-fallback", "g0", "g1",
        57, 53, 4, 53,
        "d04c5be7dc64aef131f477a771bb431af1af0c2269c7be09662dff07b7be3cdf",
        217204,
    ),
    PhysicalPin(
        "physical-install", "vacant-to-g0", "cached-batch", "vacant", "g0",
        12, 8, 4, 45,
        "73f18f19d8f26aae3574b311b931b263ab219426f5364ddc0cf1caa9336408ec",
        184383,
    ),
    PhysicalPin(
        "physical-upgrade", "g0-to-g1", "cached-batch", "g0", "g1",
        12, 8, 4, 53,
        "7756b421aaf1a8dd593ccc5565d8e2e1ed217bf2c3c59ad2c288ee2296fd7b91",
        217159,
    ),
)
EXPECTED_LOGICAL_EVENTS = 62_586
EXPECTED_PHYSICAL_EVENTS = 803_166
EXPECTED_TOTAL_EVENTS = EXPECTED_LOGICAL_EVENTS + EXPECTED_PHYSICAL_EVENTS


def _validate_empty_recipe(store: RecipeStore, reference: StoredRef, base: StoredRef) -> None:
    definition = store.recipe(reference)
    require(
        not store.is_recipe(definition.base)
        and same_stored_ref(definition.base, base)
        and not definition.patches,
        "baseline recipe is not the empty overlay of its exact raw base",
    )


def _parse_changed_pages(value: Any, label: str) -> tuple[tuple[int, str, str], ...]:
    require(isinstance(value, list), f"{label} is not a list")
    out = []
    previous = -1
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        require(isinstance(item, dict), f"{item_label} is not an object")
        exact_keys(item, {"page", "before_sha256", "after_sha256"}, item_label)
        page = exact_int(item["page"], f"{item_label}.page")
        require(page > previous, f"{label} is not strictly page ordered")
        previous = page
        out.append(
            (
                page,
                exact_hex32(item["before_sha256"], f"{item_label}.before_sha256"),
                exact_hex32(item["after_sha256"], f"{item_label}.after_sha256"),
            )
        )
    return tuple(out)


@dataclass(frozen=True)
class RequestedPage:
    page: int
    before_sha256: str
    input: StoredRef
    after_sha256: str


def _parse_requested_pages(
    value: Any,
    store: RecipeStore,
    *,
    first_page: int,
    count: int,
    label: str,
) -> tuple[RequestedPage, ...]:
    require(isinstance(value, list) and len(value) == count, f"{label} cardinality differs")
    out = []
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        require(isinstance(item, dict), f"{item_label} is not an object")
        exact_keys(item, {"page", "before_sha256", "input", "after_sha256"}, item_label)
        page = exact_int(item["page"], f"{item_label}.page")
        input_ref = parse_stored_ref(item["input"], f"{item_label}.input")
        require(not store.is_recipe(input_ref), f"{item_label}.input is a recipe")
        raw = store.read_blob(input_ref, maximum=PAGE)
        before = exact_hex32(item["before_sha256"], f"{item_label}.before_sha256")
        after = exact_hex32(item["after_sha256"], f"{item_label}.after_sha256")
        require(
            page == first_page + index
            and input_ref.byte_len == PAGE
            and len(raw) == PAGE
            and after == input_ref.sha256,
            f"{item_label} does not bind its exact contiguous write input",
        )
        out.append(RequestedPage(page, before, input_ref, after))
    return tuple(out)


def _analyze_direct_physical(
    store: RecipeStore,
    reference: StoredRef,
    policy: FrozenPolicy,
    expected: str,
) -> DiskAnalysis:
    path = store.verify_direct(reference, kind="base")
    with _mapped_file(path) as region:
        analysis = analyze_storage_region(region, policy, geometry_profile="corpus")
    require(analysis.classification == expected, f"physical domain endpoint is not exact {expected}")
    require(analysis.trace_explained_orphans == 0, "physical domain endpoint contains an orphan")
    if expected in {"g0", "g1"}:
        _require_dual_checkpoint_endpoint(analysis, f"physical {expected.upper()} after endpoint")
    return analysis


def _verify_coordinated_catalog_authority_mismatch(
    store: RecipeStore,
    before_ref: StoredRef,
    after_ref: StoredRef,
    policy: FrozenPolicy,
) -> None:
    """Re-seal a structurally complete G1 image with its retained G0 CAS root.

    Both catalog pointers name real, hash-complete immutable extents from the
    same store.  Only the selected checkpoint pair is independently re-sealed;
    rejection must therefore reach the authority-root/CAS object relationship,
    rather than a torn record, hash, or snapshot-generation check.
    """

    before_path = store.verify_direct(before_ref, kind="base")
    after_path = store.verify_direct(after_ref, kind="base")
    with _mapped_file(before_path) as before_region:
        before_structural = migration.gc_verifier.parse_raw_structure(before_region)
        require(not before_structural["errors"], "coordinated selftest G0 image is not structural")
        before_checkpoint = before_structural["checkpoint"]
        require(before_checkpoint is not None, "coordinated selftest G0 has no checkpoint")
        retained_catalog = before_checkpoint["record"]["catalog_root"]
        require(retained_catalog["status"] == "value", "coordinated selftest G0 has no CAS root")
        retained_pointer = migration.storage_codec.make_pointer_bytes(retained_catalog)
    mutated = bytearray(after_path.read_bytes())
    after_structural = migration.gc_verifier.parse_raw_structure(mutated)
    require(not after_structural["errors"], "coordinated selftest G1 image is not structural")
    selected = after_structural["checkpoint"]
    require(selected is not None, "coordinated selftest G1 has no checkpoint")
    recovered = migration.reconstruct_v2_checkpoint(
        mutated,
        after_structural,
        require_authority=True,
        authority_policy=policy.authority_policy,
    )
    binding_mutation = copy.deepcopy(recovered)
    require(
        binding_mutation["authority"] is not None
        and len(binding_mutation["authority"]["objects"]) == 1,
        "coordinated binding selftest lacks one authority object",
    )
    binding_mutation["authority"]["objects"][0]["stable_object_id"] ^= 1
    try:
        migration.verify_authority_bindings({"recovered": binding_mutation}, False)
    except migration.Violation as error:
        require(
            "exact external-policy object set" in str(error),
            f"stable-id mutation failed before the authority binding gate: {error}",
        )
    else:
        raise VerificationError("stable-id authority binding mutation was accepted")

    # Keeping the authority and CAS tables mutually consistent is still not
    # enough if both forge the graph's durable publication generation.
    commit_mutation = copy.deepcopy(recovered)
    current_binding = commit_mutation["authority"]["objects"][0]
    current_mapping = commit_mutation["objects"][current_binding["v2_object_id"]]
    checkpoint_generation = recovered["checkpoint_generation"]
    require(
        current_binding["commit_generation"] == checkpoint_generation
        and current_mapping["commit_generation"] == checkpoint_generation,
        "coordinated commit-generation selftest lacks the current publication binding",
    )
    current_binding["commit_generation"] -= 1
    current_mapping["commit_generation"] -= 1
    try:
        _verify_recovered_graph_semantics(
            commit_mutation,
            policy,
            checkpoint_generation,
            "coordinated commit-generation mutation",
        )
    except EXPECTED_REJECTION_ERRORS as error:
        require(
            "publication-generation history" in str(error),
            f"commit-generation mutation failed before the semantic generation gate: {error}",
        )
    else:
        raise VerificationError("coordinated authority/CAS commit-generation mutation was accepted")

    # A sealed segment summary is not authority for bytes after its declared
    # extent prefix.  Exercise the independent full append-area census with a
    # non-zero byte in an otherwise unclaimed tail page.
    hidden_tail = bytearray(after_path.read_bytes())
    hidden_page: int | None = None
    for segment in after_structural["segments"]:
        if segment.get("status") != "sealed":
            continue
        claimed: set[int] = set()
        for extent in segment.get("extents", ()):
            if extent.get("status") == "sealed":
                _identity, pages = _extent_identity_and_pages(segment, extent)
                claimed.update(pages)
        for relative in range(
            migration.storage_codec.DATA_END_PAGE - 1,
            migration.storage_codec.DATA_FIRST_PAGE - 1,
            -1,
        ):
            page = segment["base_page"] + relative
            if page not in claimed and not any(_page_bytes(hidden_tail, page)):
                hidden_page = page
                break
        if hidden_page is not None:
            break
    require(hidden_page is not None, "coordinated selftest lacks a sealed zero tail page")
    hidden_tail[hidden_page * PAGE] = 0xA5
    try:
        analyze_storage_region(hidden_tail, policy, geometry_profile="corpus")
    except EXPECTED_REJECTION_ERRORS as error:
        require(
            "hidden non-authoritative bytes" in str(error),
            f"hidden-tail mutation failed before the full extent census: {error}",
        )
    else:
        raise VerificationError("hidden sealed-segment tail mutation was accepted")

    # Payload commitments cover the exact byte length, while C7.8 additionally
    # requires all bytes through the last physical payload page to be zero.
    padding_mutation = bytearray(after_path.read_bytes())
    padding_offset: int | None = None
    padding_segment: Mapping[str, Any] | None = None
    padding_extent: Mapping[str, Any] | None = None
    for segment in after_structural["segments"]:
        for extent in segment.get("extents", ()):
            if extent.get("status") != "sealed":
                continue
            record = extent["record"]
            if record["payload_byte_len"] < record["payload_pages"] * PAGE:
                first = segment["base_page"] + record["payload_first_relative_page"]
                padding_offset = first * PAGE + record["payload_byte_len"]
                padding_segment = segment
                padding_extent = extent
                break
        if padding_offset is not None:
            break
    require(padding_offset is not None, "coordinated selftest lacks payload-page padding")
    padding_mutation[padding_offset] = 0x5A
    try:
        require(
            padding_segment is not None and padding_extent is not None,
            "coordinated padding mutation lost its exact extent",
        )
        _validate_extent_bytes(padding_mutation, padding_segment, padding_extent)
    except EXPECTED_REJECTION_ERRORS as error:
        require(
            "zero padding" in str(error),
            f"payload-padding mutation failed before the exact byte census: {error}",
        )
    else:
        raise VerificationError("non-zero payload-page padding mutation was accepted")
    _expect_rejected(
        lambda: analyze_storage_region(
            padding_mutation,
            policy,
            geometry_profile="corpus",
        ),
        "full parser payload-page padding",
    )

    require(
        selected["record"]["catalog_root"] != retained_catalog,
        "coordinated selftest CAS roots are unexpectedly identical",
    )

    def replace_catalog(payload: bytearray) -> None:
        payload[0x40:0xA0] = retained_pointer

    migration.storage_codec.rewrite_selftest_pair(
        mutated,
        selected["body_page"],
        2,
        replace_catalog,
    )
    status, evidence, _structural = probe_v2_region(
        mutated,
        policy,
        geometry_profile="corpus",
    )
    require(status == "corrupt" and evidence is not None, "coordinated CAS/authority mismatch was accepted")
    error = str(evidence.get("error", ""))
    require(
        any(
            marker in error
            for marker in (
                "root references an unknown object",
                "persistent root references a missing ObjectMapping",
                "persistent authority binding has no CAS ObjectMapping",
                "authority binding",
            )
        ),
        f"coordinated CAS/authority mismatch failed before its semantic gate: {error}",
    )
    _expect_rejected(
        lambda: analyze_storage_region(mutated, policy, geometry_profile="corpus"),
        "coordinated authority-to-CAS semantic mismatch",
    )


def _canonical_snapshot_pages(
    store: RecipeStore,
    initial: StoredRef,
    pages: Mapping[int, StoredRef],
    page: int,
    blob: StoredRef,
) -> dict[int, StoredRef]:
    out = dict(pages)
    if blob.sha256 == _snapshot_page_digest(store, initial, {}, page):
        out.pop(page, None)
    else:
        out[page] = blob
    return out


def _snapshot_matches_direct_base(
    store: RecipeStore,
    initial: StoredRef,
    pages: Mapping[int, StoredRef],
    direct: StoredRef,
) -> bool:
    require(initial.byte_len == direct.byte_len, "snapshot/direct-base length differs")
    direct_path = store.verify_direct(direct, kind="base")
    for page in range(initial.byte_len // PAGE):
        observed = _snapshot_page_digest(store, initial, pages, page)
        expected = _base_page_digest(str(direct_path), direct.byte_len, page)
        if observed != expected:
            return False
    return True


def verify_physical_domain(
    lines: ManifestLines,
    store: RecipeStore,
    policy: FrozenPolicy,
    pin: PhysicalPin,
) -> PhysicalDomainResult:
    row = lines.next("physical-domain")
    exact_keys(
        row,
        {
            "record", "scenario", "transition", "mode", "geometry_sha256", "trace_sha256", "trace",
            "operation_count", "write_count", "flush_count", "requested_page_count",
            "page_size", "write_cuts", "flush_effects", "before", "after",
        },
        "physical domain",
    )
    trace_sha256 = exact_hex32(row["trace_sha256"], "physical domain trace digest")
    require(
        row["scenario"] == pin.scenario
        and row["transition"] == pin.transition
        and row["mode"] == pin.mode
        and row["geometry_sha256"] == pin.geometry_sha256
        and row["operation_count"] == pin.operations
        and row["write_count"] == pin.writes
        and row["flush_count"] == pin.flushes
        and row["requested_page_count"] == pin.requested_pages
        and row["page_size"] == PAGE
        and row["write_cuts"] == [0, PAGE]
        and row["flush_effects"] == ["none", "durable"],
        "physical domain differs from its independently frozen request geometry/trace pin",
    )
    trace_ref = parse_stored_ref(row["trace"], "physical trace blob")
    require(not store.is_recipe(trace_ref), "physical trace is a recipe")
    trace_bytes = store.read_blob(trace_ref, maximum=4 * 1024 * 1024)
    require(trace_ref.sha256 == trace_sha256, "physical trace blob/domain digest differ")
    before_ref = parse_stored_ref(row["before"], "physical domain before")
    after_ref = parse_stored_ref(row["after"], "physical domain after")
    require(
        not store.is_recipe(before_ref)
        and not store.is_recipe(after_ref)
        and before_ref.byte_len == after_ref.byte_len
        and before_ref.byte_len % PAGE == 0,
        "physical domain endpoint geometry differs",
    )
    before_path = store.verify_direct(before_ref, kind="base")
    after_path = store.verify_direct(after_ref, kind="base")
    classifier = PhysicalSnapshotClassifier(store, policy, before_ref, pin.before_class)
    final_analysis = _analyze_direct_physical(store, after_ref, policy, pin.after_class)
    _require_storage_transition(
        classifier.initial_analysis,
        final_analysis,
        f"{pin.scenario}/{pin.mode}",
    )

    canonical_trace = bytearray(
        f"scenario={pin.scenario};transition={pin.transition};mode={pin.mode}\n".encode()
    )
    canonical_geometry = bytearray(canonical_trace)
    event_count = 0
    class_counts = {"vacant": 0, "g0": 0, "g1": 0, "reject": 0}
    # Baseline keys are part of the independently derived event domain.
    for ordinal, (base, expected) in enumerate(((before_ref, pin.before_class), (after_ref, pin.after_class))):
        event = lines.next("event")
        image = _validate_event(
            event,
            scenario=pin.scenario,
            transition=pin.transition,
            mode=pin.mode,
            media_kind="storage-v2-page-device",
            phase="baseline",
            operation="snapshot",
            ordinal=ordinal,
            cut=PAGE,
            expected_hint=expected,
        )
        exact_keys(event["detail"], {"trace_sha256"}, "physical baseline detail")
        require(
            event["detail"]["trace_sha256"] == trace_sha256
            and image.raw_sha256 == base.sha256
            and image.recipe.byte_len == base.byte_len,
            "physical baseline event differs",
        )
        _validate_empty_recipe(store, image.recipe, base)
        class_counts[expected] += 1
        event_count += 1

    page_ordinal = 0
    observed_writes = 0
    observed_flushes = 0
    observed_requested_pages = 0
    requested_history: dict[int, list[RequestedPage]] = {}
    normal_visible: dict[int, StoredRef] = {}
    normal_durable: dict[int, StoredRef] = {}
    for mutation in range(pin.operations):
        operation = lines.next("physical-operation")
        exact_keys(
            operation,
            {
                "record", "scenario", "transition", "mode", "mutation_ordinal",
                "kind", "first_page", "page_count", "requested_pages",
                "changed_pages", "trace_sha256",
            },
            "physical operation",
        )
        kind = operation["kind"]
        require(
            operation["scenario"] == pin.scenario
            and operation["transition"] == pin.transition
            and operation["mode"] == pin.mode
            and operation["mutation_ordinal"] == mutation
            and operation["trace_sha256"] == trace_sha256
            and kind in {"write", "flush"},
            "physical operation identity/order differs",
        )
        declared_changed = _parse_changed_pages(operation["changed_pages"], "physical changed pages")
        if kind == "flush":
            observed_flushes += 1
            require(
                operation["first_page"] is None
                and operation["page_count"] == 0
                and operation["requested_pages"] == [],
                "flush operation carries write geometry",
            )
            canonical_trace.extend(f"ordinal={mutation};kind=flush;changed_pages=".encode())
            canonical_geometry.extend(f"ordinal={mutation};kind=flush\n".encode())
            canonical_trace.extend(
                ",".join(f"{page}:{before}:{after}" for page, before, after in declared_changed).encode()
            )
            canonical_trace.extend(b"\n")
            snapshots = []
            for effect_ordinal, effect in enumerate(("none", "durable")):
                event = lines.next("event")
                image = _validate_event(
                    event,
                    scenario=pin.scenario,
                    transition=pin.transition,
                    mode=pin.mode,
                    media_kind="storage-v2-page-device",
                    phase="flush",
                    operation=effect,
                    ordinal=mutation,
                    cut=effect_ordinal,
                    expected_hint=f"{pin.before_class}-or-{pin.after_class}",
                )
                exact_keys(event["detail"], {"mutation_ordinal", "trace_sha256"}, "flush event detail")
                require(
                    event["detail"] == {"mutation_ordinal": mutation, "trace_sha256": trace_sha256}
                    and image.raw_sha256 is None
                    and image.recipe.byte_len == before_ref.byte_len,
                    "flush event detail/image differs",
                )
                snapshot = _snapshot_recipe(store, image.recipe, before_ref)
                classification, _analysis = classifier.classify(snapshot.reference, snapshot.pages)
                require(classification in {pin.before_class, pin.after_class}, "flush endpoint is mixed or rejected")
                class_counts[classification] += 1
                snapshots.append(snapshot)
                event_count += 1
            observed_changed = _changed_snapshot_pages(store, before_ref, snapshots[0].pages, snapshots[1].pages)
            require(observed_changed == declared_changed, "flush changed-page declaration differs from raw snapshots")
            require(
                _same_snapshot(store, before_ref, snapshots[0].pages, normal_durable)
                and _same_snapshot(store, before_ref, snapshots[1].pages, normal_visible),
                "flush fault snapshots do not equal the normal durable/visible state-machine cuts",
            )
            normal_durable = dict(normal_visible)
            continue

        observed_writes += 1
        first_page = exact_int(operation["first_page"], "write first page")
        page_count = exact_int(operation["page_count"], "write page count", minimum=1)
        require(first_page + page_count <= before_ref.byte_len // PAGE, "write request exceeds its page device")
        requested = _parse_requested_pages(
            operation["requested_pages"],
            store,
            first_page=first_page,
            count=page_count,
            label="write requested pages",
        )
        for item in requested:
            requested_history.setdefault(item.page, []).append(item)
        observed_requested_pages += page_count
        canonical_trace.extend(
            f"ordinal={mutation};kind=write;first_page={first_page};page_count={page_count};requested_pages=".encode()
        )
        canonical_geometry.extend(
            f"ordinal={mutation};kind=write;first_page={first_page};page_count={page_count}\n".encode()
        )
        canonical_trace.extend(
            ",".join(
                f"{item.page}:{item.before_sha256}:{item.input.sha256}:{item.after_sha256}"
                for item in requested
            ).encode()
        )
        canonical_trace.extend(b"\n")

        operation_before: SnapshotRecipe | None = None
        prior: SnapshotRecipe | None = None
        for batch_page_ordinal, requested_page in enumerate(requested):
            cut_classifier: PageCutEquivalenceClassifier | None = None
            last_reference: StoredRef | None = None
            try:
                for cut in PHYSICAL_CUTS:
                    event = lines.next("event")
                    image = _validate_event(
                        event,
                        scenario=pin.scenario,
                        transition=pin.transition,
                        mode=pin.mode,
                        media_kind="storage-v2-page-device",
                        phase="write",
                        operation="complete" if cut == PAGE else "prefix",
                        ordinal=page_ordinal,
                        cut=cut,
                        expected_hint=f"{pin.before_class}-or-{pin.after_class}-or-reject",
                    )
                    exact_keys(
                        event["detail"],
                        {"mutation_ordinal", "batch_page_ordinal", "page", "trace_sha256"},
                        "write event detail",
                    )
                    require(
                        event["detail"]
                        == {
                            "mutation_ordinal": mutation,
                            "batch_page_ordinal": batch_page_ordinal,
                            "page": requested_page.page,
                            "trace_sha256": trace_sha256,
                        }
                        and image.raw_sha256 is None
                        and image.recipe.byte_len == before_ref.byte_len,
                        "write event detail/image differs",
                    )
                    if cut == 0:
                        if prior is None:
                            prior = _snapshot_recipe(store, image.recipe, before_ref)
                            operation_before = prior
                        else:
                            require(same_stored_ref(image.recipe, prior.reference), "write cut zero differs from its prior page snapshot")
                        require(
                            _snapshot_page_digest(store, before_ref, prior.pages, requested_page.page)
                            == requested_page.before_sha256,
                            "write requested before hash differs from its raw snapshot",
                        )
                        cut_classifier = PageCutEquivalenceClassifier(
                            classifier, prior, requested_page.page, requested_page.input
                        )
                    else:
                        require(prior is not None, "write prefix has no prior snapshot")
                        _validate_nested_page_recipe(
                            store,
                            image.recipe,
                            prior.reference,
                            page=requested_page.page,
                            after_blob=requested_page.input,
                            cut=cut,
                        )
                    require(cut_classifier is not None, "write cut classifier was not initialized")
                    classification, _analysis = cut_classifier.classify(cut)
                    require(
                        classification in {pin.before_class, pin.after_class, "reject"},
                        "write prefix escaped its independently parsed crash classes",
                    )
                    class_counts[classification] += 1
                    last_reference = image.recipe
                    event_count += 1
            finally:
                if cut_classifier is not None:
                    cut_classifier.close()
            require(prior is not None and last_reference is not None, "write page emitted no cuts")
            prior = SnapshotRecipe(
                last_reference,
                _canonical_snapshot_pages(
                    store,
                    before_ref,
                    prior.pages,
                    requested_page.page,
                    requested_page.input,
                ),
            )
            page_ordinal += 1

        require(operation_before is not None and prior is not None, "write operation has no requested page")
        require(
            _same_snapshot(store, before_ref, operation_before.pages, normal_durable),
            "write fail-not-submitted snapshot differs from normal durable state",
        )
        mutation_event = lines.next("event")
        mutation_image = _validate_event(
            mutation_event,
            scenario=pin.scenario,
            transition=pin.transition,
            mode=pin.mode,
            media_kind="storage-v2-page-device",
            phase="mutation",
            operation="complete",
            ordinal=mutation,
            cut=PAGE,
            expected_hint=f"{pin.before_class}-or-{pin.after_class}",
        )
        exact_keys(
            mutation_event["detail"],
            {"mutation_ordinal", "requested_page_count", "changed_page_count", "trace_sha256"},
            "mutation event detail",
        )
        require(
            mutation_event["detail"]
            == {
                "mutation_ordinal": mutation,
                "requested_page_count": page_count,
                "changed_page_count": len(declared_changed),
                "trace_sha256": trace_sha256,
            }
            and mutation_image.raw_sha256 is None,
            "mutation event differs",
        )
        operation_after = _snapshot_recipe(store, mutation_image.recipe, before_ref)
        require(
            _same_snapshot(store, before_ref, prior.pages, operation_after.pages),
            "write request-prefix endpoint differs from its after snapshot",
        )
        observed_changed = _changed_snapshot_pages(
            store, before_ref, operation_before.pages, operation_after.pages
        )
        require(observed_changed == declared_changed, "write changed-page declaration differs from raw snapshots")
        requested_changed = tuple(
            (item.page, item.before_sha256, item.after_sha256)
            for item in requested
            if item.before_sha256 != item.after_sha256
        )
        require(requested_changed == declared_changed, "write request geometry does not explain every changed page")
        expected_ambiguous = dict(normal_durable)
        for item in requested:
            expected_ambiguous = _canonical_snapshot_pages(
                store, before_ref, expected_ambiguous, item.page, item.input
            )
        require(
            _same_snapshot(store, before_ref, operation_after.pages, expected_ambiguous),
            "write ambiguous-durable snapshot is not the exact request applied to normal durable state",
        )
        for item in requested:
            normal_visible = _canonical_snapshot_pages(
                store, before_ref, normal_visible, item.page, item.input
            )
        classification, _analysis = classifier.classify(operation_after.reference, operation_after.pages)
        require(
            classification in {pin.before_class, pin.after_class, "reject"},
            "complete write mutation escaped its independently parsed crash classes: "
            f"{pin.scenario}/{pin.mode} mutation {mutation}",
        )
        class_counts[classification] += 1
        event_count += 1

    require(
        observed_writes == pin.writes
        and observed_flushes == pin.flushes
        and observed_requested_pages == pin.requested_pages
        and page_ordinal == pin.requested_pages
        and event_count == pin.events,
        "physical domain recomputed operation/event coverage differs from its frozen pin",
    )
    zero_page_sha256 = hashlib.sha256(bytes(PAGE)).hexdigest()
    repeated_pages = 0
    require(
        len(requested_history) == pin.requested_pages - 3,
        "physical write trace does not have the exact three repeated seal pages",
    )
    for page, sequence in requested_history.items():
        require(
            len(sequence) in {1, 2},
            "physical requested page occurs outside the exact 1/2-write shape",
        )
        before_endpoint_sha256 = _base_page_digest(
            str(before_path), before_ref.byte_len, page
        )
        endpoint_sha256 = _base_page_digest(str(after_path), after_ref.byte_len, page)
        require(
            before_endpoint_sha256 != endpoint_sha256,
            "physical requested page does not change across direct endpoints",
        )
        if len(sequence) == 1:
            require(
                sequence[0].input.sha256 == endpoint_sha256,
                "single-write page does not equal the independently read after endpoint",
            )
        else:
            repeated_pages += 1
            require(
                [item.input.sha256 for item in sequence]
                == [zero_page_sha256, endpoint_sha256]
                and sequence[1].before_sha256 == zero_page_sha256,
                "repeated seal page is not strict zero-then-after-endpoint publication",
            )
    require(repeated_pages == 3, "physical trace does not repeat exactly three seal pages")
    require(
        class_counts[pin.before_class] > 0
        and class_counts[pin.after_class] > 0,
        "physical crash domain did not independently observe both transition endpoints",
    )
    require(
        _same_snapshot(store, before_ref, normal_visible, normal_durable)
        and _snapshot_matches_direct_base(store, before_ref, normal_durable, after_ref),
        "normal physical trace does not end flushed at the exact declared after image",
    )
    require(
        hashlib.sha256(canonical_trace).hexdigest() == trace_sha256
        and bytes(canonical_trace) == trace_bytes,
        "physical trace bytes/digest differ from independently reconstructed operations",
    )
    require(
        hashlib.sha256(canonical_geometry).hexdigest() == pin.geometry_sha256,
        "physical operation rows differ from the frozen content-independent geometry",
    )
    return PhysicalDomainResult(
        events=event_count,
        before=before_ref,
        after=after_ref,
        before_analysis=classifier.initial_analysis,
        after_analysis=final_analysis,
        class_counts=class_counts,
    )


def verify_manifest_corpus(
    manifest: Path,
    policy: FrozenPolicy,
) -> tuple[dict[str, Any], ParsedHistory, ParsedHistory]:
    _regular_evidence_file(manifest, "C7.8 manifest")
    require(manifest.name == "manifest.jsonl", "C7.8 manifest filename differs")
    with RecipeStore(manifest) as store, ManifestLines(manifest) as lines:
        _validate_manifest_header(lines.next("header"), policy)
        logical_install_count, logical_g0 = verify_logical_domain(
            lines,
            store,
            policy,
            scenario="logical-install",
            transition="vacant-to-g0",
            old_class="vacant",
            after_class="g0",
        )
        logical_upgrade_count, logical_g1 = verify_logical_domain(
            lines,
            store,
            policy,
            scenario="logical-upgrade",
            transition="g0-to-g1",
            old_class="g0",
            after_class="g1",
        )
        logical_events = logical_install_count + logical_upgrade_count
        require(logical_events == EXPECTED_LOGICAL_EVENTS, "recomputed logical coverage differs")
        _require_same_bundle(logical_g0.versions[0], logical_g1.versions[0], "logical retained G0")

        physical_results = [
            verify_physical_domain(lines, store, policy, pin)
            for pin in PHYSICAL_PINS
        ]
        physical_events = sum(result.events for result in physical_results)
        require(physical_events == EXPECTED_PHYSICAL_EVENTS, "recomputed physical coverage differs")

        # Link all four independently declared trace domains by verified raw
        # content addresses, not by exporter verdicts or fixture equality.
        install_page, upgrade_page, install_cached, upgrade_cached = physical_results
        require(
            install_page.before == install_cached.before
            and install_page.after == upgrade_page.before
            and install_page.after == install_cached.after
            and install_cached.after == upgrade_cached.before
            and upgrade_page.after == upgrade_cached.after,
            "physical install/upgrade/mode endpoints are not one linked Vacant/G0/G1 history",
        )
        _verify_coordinated_catalog_authority_mismatch(
            store,
            upgrade_page.before,
            upgrade_page.after,
            policy,
        )
        for result in (install_page, install_cached):
            require(result.before_analysis.classification == "vacant", "physical install does not begin Vacant")
            _require_same_bundle(logical_g0.versions[0], result.after_analysis.history.versions[0], "logical/physical G0")
        for result in (upgrade_page, upgrade_cached):
            _require_same_bundle(logical_g0.versions[0], result.before_analysis.history.versions[0], "logical/physical upgrade G0")
            _require_same_bundle(logical_g1.versions[0], result.after_analysis.history.versions[0], "logical/physical retained G0")
            _require_same_bundle(logical_g1.versions[1], result.after_analysis.history.versions[1], "logical/physical G1")

        coverage = lines.next("coverage")
        exact_keys(
            coverage,
            {
                "record", "logical_events", "physical_events", "event_keys_unique",
                "recipes_content_addressed", "raw_images_reconstructable",
            },
            "manifest coverage",
        )
        require(
            coverage
            == {
                "record": "coverage",
                "logical_events": logical_events,
                "physical_events": physical_events,
                "event_keys_unique": True,
                "recipes_content_addressed": True,
                "raw_images_reconstructable": True,
            },
            "coverage cross-check differs from independently enumerated domains",
        )
        lines.finish()
        store.finish()
        combined_classes = {"vacant": 0, "g0": 0, "g1": 0, "reject": 0}
        for result in physical_results:
            for classification, count in result.class_counts.items():
                combined_classes[classification] += count
        require(combined_classes["reject"] > 0, "physical crash corpus contains no independently rejected torn state")
        report = {
            "manifest_sha256": _file_sha256(manifest),
            "logical_events": logical_events,
            "physical_events": physical_events,
            "events": logical_events + physical_events,
            "recipes": store.recipe_count,
            "physical_domains": len(physical_results),
            "physical_classifications": combined_classes,
            "physical_requested_page_sequences_verified": True,
            "page_fallback_traces": 2,
            "cached_batch_traces": 2,
            "logical_final_classes": [logical_g0.classification, logical_g1.classification],
            "coordinated_storage_semantic_mutation_rejected": True,
        }
        return report, logical_g0, logical_g1


def _expect_rejected(action: Callable[[], Any], label: str) -> None:
    try:
        action()
    except EXPECTED_REJECTION_ERRORS:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def _vacant_region_fixture() -> bytes:
    """Small independent encoder fixture for a formatted Null-authority V2."""

    storage = migration.storage_codec
    total_pages = migration.V2_COUNT * BLOCK // PAGE
    require(
        total_pages >= storage.ANCHOR_PAGES
        and (total_pages - storage.ANCHOR_PAGES) % storage.SEGMENT_PAGES == 0,
        "frozen V2 range does not have exact segment geometry",
    )
    segment_count = (total_pages - storage.ANCHOR_PAGES) // storage.SEGMENT_PAGES
    region = bytearray(total_pages * PAGE)
    store_uuid = bytes(range(1, 17))
    device_id = bytes(range(0x21, 0x31))
    for copy_index, page in ((0, 0), (1, 2)):
        payload = bytearray(0x80)
        payload[0] = copy_index
        struct.pack_into("<I", payload, 0x08, PAGE)
        struct.pack_into("<I", payload, 0x0C, storage.ANCHOR_PAGES)
        struct.pack_into("<I", payload, 0x10, storage.SEGMENT_PAGES)
        struct.pack_into("<I", payload, 0x14, storage.DATA_FIRST_PAGE)
        struct.pack_into("<I", payload, 0x18, storage.DATA_END_PAGE)
        struct.pack_into("<I", payload, 0x1C, storage.SUMMARY_BODY_PAGE)
        struct.pack_into("<I", payload, 0x20, storage.SUMMARY_SEAL_PAGE)
        struct.pack_into("<I", payload, 0x24, storage.SEGMENT_SEAL_BODY_PAGE)
        struct.pack_into("<I", payload, 0x28, storage.SEGMENT_SEAL_PAGE)
        struct.pack_into("<I", payload, 0x2C, storage.MAX_EXTENT_PAYLOAD_PAGES)
        struct.pack_into("<I", payload, 0x30, 2)
        struct.pack_into("<H", payload, 0x34, storage.HASH_ALGORITHM_SHA256)
        struct.pack_into("<Q", payload, 0x38, total_pages)
        struct.pack_into("<Q", payload, 0x40, storage.ANCHOR_PAGES)
        struct.pack_into("<Q", payload, 0x48, segment_count)
        payload[0x50:0x60] = device_id
        struct.pack_into("<Q", payload, 0x60, migration.V2_FIRST)
        struct.pack_into("<Q", payload, 0x68, migration.V2_COUNT)
        struct.pack_into("<I", payload, 0x70, BLOCK)
        struct.pack_into("<I", payload, 0x78, 64)
        binding = {
            "store_uuid": store_uuid,
            "generation": 1,
            "segment_no": storage.ANCHOR_SEGMENT_NO,
            "ordinal": copy_index,
            "self_page": page,
            "target_checkpoint_generation": 0,
        }
        storage.write_pair(region, page, 1, binding, bytes(payload))
    checkpoint = bytearray(0x1C0)
    checkpoint[0] = 0
    struct.pack_into("<Q", checkpoint, 0x08, 0)
    struct.pack_into("<Q", checkpoint, 0x10, total_pages)
    struct.pack_into("<Q", checkpoint, 0x18, segment_count)
    struct.pack_into("<Q", checkpoint, 0x20, 1)
    struct.pack_into("<I", checkpoint, 0x28, 0)
    struct.pack_into("<I", checkpoint, 0x2C, 64)
    struct.pack_into("<I", checkpoint, 0x30, 2)
    binding = {
        "store_uuid": store_uuid,
        "generation": 1,
        "segment_no": storage.ANCHOR_SEGMENT_NO,
        "ordinal": 0,
        "self_page": 4,
        "target_checkpoint_generation": 1,
    }
    storage.write_pair(region, 4, 2, binding, bytes(checkpoint))
    return bytes(region)


def _recipe_store_selftest() -> int:
    cases = 0
    with tempfile.TemporaryDirectory(prefix="vibeos-c78-selftest-") as temporary:
        root = Path(temporary)
        for child in ("bases", "blobs", "recipes"):
            (root / child).mkdir()
        (root / "manifest.jsonl").write_bytes(b"{}\n")
        base_bytes = bytes(PAGE)
        blob_bytes = bytes([0xA5]) * PAGE
        base_sha = hashlib.sha256(base_bytes).hexdigest()
        blob_sha = hashlib.sha256(blob_bytes).hexdigest()
        (root / "bases" / f"{base_sha}.raw").write_bytes(base_bytes)
        (root / "blobs" / f"{blob_sha}.bin").write_bytes(blob_bytes)
        base = {"path": f"bases/{base_sha}.raw", "sha256": base_sha, "byte_len": PAGE}
        blob = {"path": f"blobs/{blob_sha}.bin", "sha256": blob_sha, "byte_len": PAGE}
        document = {"base": base, "patches": [{"offset": 0, "blob": blob, "prefix_len": PAGE}]}
        encoded = canonical_json_bytes(document)
        digest = hashlib.sha256(encoded).hexdigest()
        shard = root / "recipes" / f"{digest[0]}.jsonl"
        shard.write_bytes(digest.encode() + b"\t" + encoded + b"\n")
        reference = StoredRef(f"recipes/{digest[0]}.jsonl#{digest}", digest, PAGE)
        with RecipeStore(root / "manifest.jsonl") as store:
            definition = store.recipe(reference)
            require(len(definition.patches) == 1, "recipe selftest lost its patch")
            cases += 1
            _expect_rejected(
                lambda: store.verify_direct(StoredRef("../escape", base_sha, PAGE), kind="base"),
                "recipe path traversal",
            )
            cases += 1
            dummy = "0" * 64
            store._recipe_visiting.add(dummy)
            try:
                _expect_rejected(
                    lambda: store.recipe(StoredRef(f"recipes/0.jsonl#{dummy}", dummy, PAGE)),
                    "recipe cycle",
                )
            finally:
                store._recipe_visiting.clear()
            cases += 1
            store._recipe_visiting.update(f"{value:064x}" for value in range(64))
            try:
                deep = "f" * 64
                _expect_rejected(
                    lambda: store.recipe(StoredRef(f"recipes/f.jsonl#{deep}", deep, PAGE)),
                    "recipe recursion depth",
                )
            finally:
                store._recipe_visiting.clear()
            cases += 1
            store.finish()
        # The index must reject a coordinated row/path whose digest does not
        # bind the canonical recipe bytes.
        bad = root / "recipes" / f"{digest[0]}.jsonl"
        bad.write_bytes(("0" * 64).encode() + b"\t" + encoded + b"\n")
        _expect_rejected(lambda: RecipeStore(root / "manifest.jsonl"), "recipe digest substitution")
        cases += 1
    return cases


def selftest(policy_path: Path) -> dict[str, Any]:
    anchor = "1dfaeb2e9d9ff3d5c4eb7f81a1197dd09f8a301a5a31b6ed15921e939574154f"
    policy = load_policy(policy_path, anchor)
    vectors = c76_codec.load_vectors(DEFAULT_C76_VECTORS)
    g0_bytes = c76_codec.logical_fixture(vectors, 1)
    g1_bytes = c76_codec.logical_fixture(vectors, 2)
    g0 = parse_complete_history(g0_bytes, policy, 1)
    g1 = parse_complete_history(g1_bytes, policy, 2)
    require(g0.classification == "g0" and g1.classification == "g1", "semantic selftest fixture did not parse")
    cases = 2
    _expect_rejected(
        lambda: _require_dual_checkpoint_endpoint(
            DiskAnalysis(
                classification="g0",
                history=g0,
                device_id="selftest-device",
                store_uuid="selftest-store",
                geometry=DiskGeometry(*(0 for _ in range(20))),
                checkpoint_generation=1,
                selected_checkpoint_pair_sha256="0" * 64,
                retained_checkpoint_pairs=((1, "0" * 64),),
                verified_checkpoint_copies=1,
                admitted_segments=0,
                physical_bindings=1,
                historical_cas_descriptors=1,
                sealed_extents=0,
                current_or_retained_extents=0,
                trace_explained_orphans=0,
            ),
            "selftest single-copy G0 endpoint",
        ),
        "single-copy published endpoint",
    )
    cases += 1
    categories = {"storage-single-checkpoint-endpoint"}

    corrupted = bytearray(g1_bytes)
    corrupted[BLOCK + 17] ^= 1
    _expect_rejected(lambda: parse_complete_history(bytes(corrupted), policy), "logical record corruption")
    cases += 1
    categories.add("logical-record-crc")

    def reject_vector_mutation(
        category: str,
        key: str,
        mutate: Callable[[bytes], bytes],
        *,
        versions: int = 1,
    ) -> None:
        nonlocal cases
        changed = dict(vectors)
        changed[key] = mutate(changed[key])
        encoded = c76_codec.logical_fixture(changed, versions)
        _expect_rejected(lambda: parse_complete_history(encoded, policy), category)
        categories.add(category)
        cases += 1

    artifact = vectors["g0_artifact_0"]
    layout = c71.fixture_layout(artifact)
    artifact_mutations: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
        ("artifact-component-bytes", lambda value: c71.reseal(c71.flip(value, len(value) - 1))),
        ("artifact-component-hash", lambda value: c71.flip(value, 104)),
        ("artifact-core-module-hash", lambda value: c71.reseal(c71.flip(value, layout.module_records[0] + 8))),
        ("artifact-manifest", lambda value: c71.reseal(c71.flip(value, layout.manifest_start + 8))),
        ("artifact-wit-source", lambda value: c71.reseal(c71.flip(value, layout.wit_records[0][2]))),
        ("artifact-world", lambda value: c71.reseal(c71.flip(value, layout.world_start))),
        ("artifact-interface", lambda value: c71.reseal(c71.flip(value, layout.interface_records[0][0]))),
        ("artifact-adapter-count", lambda value: c71.recommit(c71.mutate_u32(value, 92, 1))),
        ("artifact-abi", lambda value: c71.recommit(c71.mutate_u16(value, 32, 1))),
        ("artifact-profile", lambda value: c71.recommit(c71.mutate_u16(value, 22, 1))),
        ("artifact-revision", lambda value: c71.reseal(c71.flip(value, layout.revision_starts[0]))),
        ("artifact-canonical-features", lambda value: c71.recommit(c71.mutate_u64(value, 40, u64(value, 40) ^ 1))),
        ("artifact-instance-limits", lambda value: c71.reseal(c71.mutate_u64(value, layout.instance_limits_start, 0))),
        ("leaf-policy-commitment", lambda value: c71.recommit(c71.flip(value, 232))),
    )
    for category, mutate in artifact_mutations:
        reject_vector_mutation(category, "g0_artifact_0", mutate)
    reject_vector_mutation("leaf-evidence-signature", "g0_evidence_0", lambda value: c71.flip(value, 64))
    reject_vector_mutation("leaf-evidence-key", "g0_evidence_0", lambda value: c71.flip(value, 16))

    descriptor_mutations = (
        ("graph-node", lambda value: c71.flip(value, value.index(b"source"))),
        ("graph-topology", lambda value: c71.mutate_u16(value, 74, 3)),
        ("graph-async-edges", lambda value: c71.mutate_u16(value, 76, 1)),
        ("graph-published-exports", lambda value: c71.mutate_u16(value, 80, 0)),
        ("graph-incidents", lambda value: c71.mutate_u16(value, 86, 1)),
        ("graph-version-commitment", lambda value: c71.flip(value, 192)),
    )
    for category, mutate in descriptor_mutations:
        reject_vector_mutation(category, "g0_descriptor", mutate)
    reject_vector_mutation(
        "graph-predecessor",
        "g1_descriptor",
        lambda value: c71.flip(value, 96),
        versions=2,
    )
    reject_vector_mutation(
        "graph-version-ordinal",
        "g1_descriptor",
        lambda value: c71.mutate_u64(value, 48, 2),
        versions=2,
    )
    reject_vector_mutation(
        "graph-evidence-signature",
        "g0_graph_evidence",
        lambda value: c71.flip(value, 64),
    )

    logical_mutations = (
        ("logical-object-kind", {"g0_kind": CMP1 + 1}, 1),
        ("logical-root-rights", {"g0_rights": READ | 2}, 1),
        ("logical-root-generation", {"g1_generation": 2}, 2),
        ("logical-tombstone-target", {"tombstone_target_delta": 1}, 2),
        ("logical-root-order", {"omit_tombstone": True}, 2),
        ("logical-high-water", {"final_high_water_delta": 1}, 2),
    )
    for category, keywords, versions in logical_mutations:
        _expect_rejected(
            lambda keywords=keywords, versions=versions: parse_complete_history(
                c76_codec.logical_fixture(vectors, versions, **keywords), policy
            ),
            category,
        )
        categories.add(category)
        cases += 1

    mutated_document = copy.deepcopy(policy.document)
    mutated_document["wit"]["interface"]["members"][0]["entity"]["value"]["names"][0] = "unexpected"
    mutated_policy = FrozenPolicy(
        policy.path,
        policy.document_sha256,
        policy.external_policy,
        policy.external_policy_sha256,
        policy.active_public_key,
        policy.policy_generation,
        mutated_document,
    )
    _expect_rejected(lambda: parse_complete_history(g0_bytes, mutated_policy), "semantic WIT substitution")
    cases += 1
    categories.add("policy-wit-shape")

    def reject_policy_mutation(category: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        nonlocal cases
        document = copy.deepcopy(policy.document)
        mutate(document)
        with tempfile.TemporaryDirectory(prefix="vibeos-c78-mutated-policy-") as temporary:
            changed_path = Path(temporary) / "policy.json"
            changed_path.write_text(json.dumps(document), encoding="utf-8")
            _expect_rejected(
                lambda: parse_complete_history(
                    g0_bytes,
                    load_policy(changed_path, anchor),
                ),
                category,
            )
        categories.add(category)
        cases += 1

    policy_mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
        ("policy-world", lambda document: document["graph"]["nodes"][0].__setitem__("world", "test:c65-chain/other@1.0.0")),
        ("policy-interface", lambda document: document["graph"]["nodes"][0]["exports"].clear()),
        ("policy-abi", lambda document: document["artifact_profile"].__setitem__("artifact_abi", 1)),
        ("policy-profile", lambda document: document["artifact_profile"].__setitem__("profile_code", 1)),
        ("policy-revision", lambda document: document["artifact_profile"]["revisions"].__setitem__(0, "other")),
        ("policy-canonical-features", lambda document: document["artifact_profile"].__setitem__("canonical_features", 0)),
        ("policy-limits", lambda document: document["artifact_profile"]["instance_limits"].__setitem__("memory_bytes", 131072)),
        ("policy-runtime-ready", lambda document: document["artifact_profile"].__setitem__("runtime_ready", True)),
        (
            "policy-qemu-lifecycle",
            lambda document: document["storage"]["qemu_checkpoint_lifecycle"][1].__setitem__(
                "allocated_segments", 5
            ),
        ),
        (
            "policy-qemu-superseded-extents",
            lambda document: document["storage"]["qemu_superseded_allocation_extents"][0].__setitem__(
                3, 4
            ),
        ),
    )
    for category, mutate in policy_mutations:
        reject_policy_mutation(category, mutate)

    with tempfile.TemporaryDirectory(prefix="vibeos-c78-policy-") as temporary:
        root = Path(temporary)
        coordinated = copy.deepcopy(policy.document)
        replacement_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        coordinated["trust"]["active_public_key"] = replacement_key
        coordinated_path = root / "coordinated.json"
        coordinated_path.write_text(json.dumps(coordinated), encoding="utf-8")
        _expect_rejected(
            lambda: load_policy(coordinated_path, anchor),
            "coordinated policy/manifest signer substitution against explicit anchor",
        )
        cases += 1
        categories.add("coordinated-trust-anchor")
        resource = copy.deepcopy(policy.document)
        resource["wit"]["interface"]["members"][0]["entity"] = {"kind": "resource"}
        resource_path = root / "resource.json"
        resource_path.write_text(json.dumps(resource), encoding="utf-8")
        _expect_rejected(lambda: load_policy(resource_path, anchor), "resource-bearing policy")
        cases += 1
        categories.add("resource-shape")
        edge = copy.deepcopy(policy.document)
        edge["graph"]["resource_edges"] = [[0, 0, 1, 0]]
        edge_path = root / "resource-edge.json"
        edge_path.write_text(json.dumps(edge), encoding="utf-8")
        _expect_rejected(lambda: load_policy(edge_path, anchor), "resource-edge expansion")
        cases += 1
        categories.add("resource-edge")
        source_shadow = copy.deepcopy(policy.document)
        source_shadow["wit"]["source"] = source_shadow["wit"]["source"].replace(
            "        normal,", "        source-only-mutation,", 1
        )
        source_shadow_path = root / "source-shadow.json"
        source_shadow_path.write_text(json.dumps(source_shadow), encoding="utf-8")
        _expect_rejected(
            lambda: load_policy(source_shadow_path, anchor),
            "WIT source/shadow semantic substitution",
        )
        cases += 1
        categories.add("policy-wit-source-derivation")
        extra_world = copy.deepcopy(policy.document)
        extra_world["wit"]["source"] += "\nworld extra {\n    export pipe;\n}\n"
        extra_world_path = root / "extra-world.json"
        extra_world_path.write_text(json.dumps(extra_world), encoding="utf-8")
        _expect_rejected(
            lambda: load_policy(extra_world_path, anchor),
            "WIT source extra world",
        )
        cases += 1
        categories.add("policy-wit-world-set")

        original_policy = policy_path.read_text(encoding="utf-8")
        duplicate_path = root / "duplicate.json"
        duplicate_path.write_text(
            original_policy.replace('"version": 1,', '"version": 1,\n  "version": 1,', 1),
            encoding="utf-8",
        )
        _expect_rejected(lambda: load_policy(duplicate_path, anchor), "duplicate policy JSON key")
        cases += 1
        categories.add("policy-json-duplicate-key")
        nonfinite_path = root / "nonfinite.json"
        nonfinite_path.write_text(
            original_policy.replace('"version": 1,', '"version": NaN,', 1),
            encoding="utf-8",
        )
        _expect_rejected(lambda: load_policy(nonfinite_path, anchor), "non-finite policy JSON number")
        cases += 1
        categories.add("policy-json-nonfinite")
        for filename, path_parts, replacement in (
            ("bool-as-int.json", ("artifact_profile", "runtime_ready"), 0),
            ("int-as-bool.json", ("artifact_profile", "profile_code"), True),
        ):
            typed = copy.deepcopy(policy.document)
            typed[path_parts[0]][path_parts[1]] = replacement
            typed_path = root / filename
            typed_path.write_text(json.dumps(typed), encoding="utf-8")
            _expect_rejected(lambda typed_path=typed_path: load_policy(typed_path, anchor), filename)
            cases += 1
        categories.add("policy-scalar-type-strict")

    _verify_canonical_transcript_surface(
        c76_codec.BOOT1_PASS,
        c76_codec.BOOT1_PASS,
        "C7.8 transcript selftest",
    )
    cases += 1
    categories.add("transcript-canonical-surface")
    for category, diagnostic in (
        ("transcript-control-split-id", "Object\x1b[0mId(9)"),
        ("transcript-control-split-panic", "pan\x1b[0micked at guest"),
        ("transcript-raw-id", "owner_id=44"),
    ):
        _expect_rejected(
            lambda diagnostic=diagnostic: _verify_canonical_transcript_surface(
                c76_codec.BOOT1_PASS + "\n" + diagnostic,
                c76_codec.BOOT1_PASS,
                "C7.8 transcript selftest",
            ),
            category,
        )
        cases += 1
        categories.add(category)

    # Independent Storage record-pair and extent corruption seeds.  These do
    # not confer C7.8 authority; they exercise the same low-level page parser
    # used below the explicit policy against coordinated re-sealing attempts.
    control_body, control_seal = migration.encode_control(migration.STAGED, 2)
    bad_control = bytearray(control_body)
    bad_control[0x60] ^= 1
    _expect_rejected(lambda: migration.parse_control(bytes(bad_control), control_seal), "storage-control")
    categories.add("storage-control")
    cases += 1

    vacant = _vacant_region_fixture()
    require(
        probe_v2_region(
            bytes(len(vacant)),
            policy,
            geometry_profile="selftest",
        )[0]
        == "absent",
        "zero media is not absent",
    )
    vacant_analysis = analyze_storage_region(
        vacant,
        policy,
        geometry_profile="selftest",
    )
    require(
        vacant_analysis.classification == "vacant"
        and vacant_analysis.verified_checkpoint_copies == 1
        and vacant_analysis.physical_bindings == 0
        and vacant_analysis.trace_explained_orphans == 0,
        "single-copy formatted Null-authority checkpoint is not exact Vacant",
    )
    cases += 2
    categories.update({"storage-absent", "storage-vacant"})
    bad_checkpoint = bytearray(vacant)
    bad_checkpoint[4 * PAGE + 0x40] ^= 1
    _expect_rejected(
        lambda: analyze_storage_region(
            bytes(bad_checkpoint),
            policy,
            geometry_profile="selftest",
        ),
        "storage-checkpoint",
    )
    categories.add("storage-checkpoint")
    cases += 1

    hidden_append = bytearray(vacant)
    hidden_page = (
        migration.storage_codec.ANCHOR_PAGES
        + migration.storage_codec.DATA_FIRST_PAGE
    )
    hidden_append[hidden_page * PAGE] = 0xA5
    _expect_rejected(
        lambda: analyze_storage_region(
            hidden_append,
            policy,
            geometry_profile="selftest",
        ),
        "storage-hidden-append-byte",
    )
    categories.add("storage-hidden-append-byte")
    cases += 1

    storage_fixture = migration.storage_codec.selftest_image()
    fixture_structural = migration.gc_verifier.parse_raw_structure(storage_fixture)
    require(not fixture_structural["errors"] and fixture_structural["segments"][0]["status"] == "sealed", "storage corruption seed is not structurally valid")
    first_extent = fixture_structural["segments"][0]["extents"][0]["record"]
    payload_page = (
        fixture_structural["segments"][0]["base_page"]
        + first_extent["payload_first_relative_page"]
    )
    bad_extent = bytearray(storage_fixture)
    bad_extent[payload_page * PAGE] ^= 1
    corrupted_structural = migration.gc_verifier.parse_raw_structure(bad_extent)
    require(corrupted_structural["segments"][0]["status"] == "corrupt", "extent payload corruption was not rejected")
    categories.add("storage-extent-hash")
    cases += 1

    padding_extent = next(
        (
            extent
            for extent in fixture_structural["segments"][0]["extents"]
            if extent.get("status") == "sealed"
            and extent["record"]["payload_byte_len"]
            < extent["record"]["payload_pages"] * PAGE
        ),
        None,
    )
    require(padding_extent is not None, "storage corruption seed has no payload padding")
    padding_record = padding_extent["record"]
    padding_byte = (
        fixture_structural["segments"][0]["base_page"]
        + padding_record["payload_first_relative_page"]
    ) * PAGE + padding_record["payload_byte_len"]
    bad_padding = bytearray(storage_fixture)
    bad_padding[padding_byte] = 0x5A
    _expect_rejected(
        lambda: _validate_extent_bytes(
            bad_padding,
            fixture_structural["segments"][0],
            padding_extent,
        ),
        "storage-payload-padding",
    )
    categories.add("storage-payload-padding")
    cases += 1
    cases += _recipe_store_selftest()
    categories.update({"recipe-content-address", "recipe-path", "recipe-cycle-depth"})
    for error_type in (RuntimeError, NameError):
        try:
            _expect_rejected(
                lambda error_type=error_type: (_ for _ in ()).throw(error_type("synthetic verifier defect")),
                f"{error_type.__name__} must propagate",
            )
        except error_type:
            cases += 1
        else:
            raise VerificationError(f"{error_type.__name__} was misclassified as an expected reject")
    return {
        "schema": "vibeos.c78.independent-disk-selftest",
        "version": 1,
        "status": "ok",
        "cases": cases,
        "categories": sorted(categories),
        "category_count": len(categories),
        "semantic_corruption_rejected": True,
        "coordinated_policy_corruption_rejected": True,
        "coordinated_storage_semantic_mutation_tested": False,
        "formatted_vacant_distinct_from_absent": True,
        "recipe_cycles_rejected": True,
        "verifier_defects_propagate": True,
        "scope": SCOPE,
    }


def _required_path(parser: argparse.ArgumentParser, value: Path | None, flag: str) -> Path:
    if value is None:
        parser.error(f"{flag} is required unless only --selftest is requested")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--trust-anchor-hex")
    parser.add_argument("--g0-image", type=Path)
    parser.add_argument("--g1-image", type=Path)
    parser.add_argument("--c76-cold-image", type=Path)
    parser.add_argument("--c77-cold1-image", type=Path)
    parser.add_argument("--final-image", type=Path)
    parser.add_argument("--c76-boot1-log", type=Path)
    parser.add_argument("--c76-boot2-log", type=Path)
    parser.add_argument("--c76-boot3-log", type=Path)
    parser.add_argument("--c77-boot1-log", type=Path)
    parser.add_argument("--c77-boot2-log", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.selftest and args.manifest is None:
            print(json.dumps(selftest(args.policy), separators=(",", ":"), sort_keys=True))
            return 0
        manifest = _required_path(parser, args.manifest, "--manifest")
        require(args.trust_anchor_hex is not None, "--trust-anchor-hex is required for evidence verification")
        policy = load_policy(args.policy, args.trust_anchor_hex)
        qemu, qemu_g0, qemu_g1 = verify_qemu_evidence(
            policy,
            g0_image=_required_path(parser, args.g0_image, "--g0-image"),
            g1_image=_required_path(parser, args.g1_image, "--g1-image"),
            c76_cold_image=_required_path(parser, args.c76_cold_image, "--c76-cold-image"),
            c77_cold1_image=_required_path(parser, args.c77_cold1_image, "--c77-cold1-image"),
            final_image=_required_path(parser, args.final_image, "--final-image"),
            c76_logs=(
                _required_path(parser, args.c76_boot1_log, "--c76-boot1-log"),
                _required_path(parser, args.c76_boot2_log, "--c76-boot2-log"),
                _required_path(parser, args.c76_boot3_log, "--c76-boot3-log"),
            ),
            c77_logs=(
                _required_path(parser, args.c77_boot1_log, "--c77-boot1-log"),
                _required_path(parser, args.c77_boot2_log, "--c77-boot2-log"),
            ),
        )
        corpus, corpus_g0, corpus_g1 = verify_manifest_corpus(manifest, policy)
        require(corpus["events"] == EXPECTED_TOTAL_EVENTS, "total event coverage differs")
        _require_same_bundle(qemu_g0.versions[0], corpus_g0.versions[0], "QEMU/corpus G0")
        _require_same_bundle(qemu_g1.versions[0], corpus_g1.versions[0], "QEMU/corpus retained G0")
        _require_same_bundle(qemu_g1.versions[1], corpus_g1.versions[1], "QEMU/corpus current G1")
        graph_commitment = graph_policy_commitment(policy).hex()
        leaf_commitments = [
            leaf_policy_commitment(policy, node).hex()
            for node in policy.document["graph"]["nodes"]
        ]
        output = {
            "schema": "vibeos.c78.independent-disk-verifier",
            "version": 1,
            "status": "ok",
            "scope": SCOPE,
            "policy": {
                "document_sha256": policy.document_sha256,
                "external_policy_sha256": policy.external_policy_sha256,
                "explicit_trust_anchor_sha256": hashlib.sha256(policy.active_public_key).hexdigest(),
                "graph_policy_commitment": graph_commitment,
                "leaf_policy_commitments": leaf_commitments,
                "resource_edges": 0,
                "external_imports": 0,
                "resource_shapes": 0,
            },
            "qemu": qemu,
            "crash_corpus": corpus,
            "expected_event_keys": EXPECTED_TOTAL_EVENTS,
            "observed_event_keys": corpus["events"],
            "event_keys_exact": True,
            "qemu_corpus_bundles_byte_identical": True,
            "extent_census_complete": True,
            "fixture_bytes_as_authority": False,
            "guest_marker_is_storage_authority": False,
            "production_rust_decoder_used": False,
            "exporter_verdict_as_authority": False,
            "content_trace_digest_as_authority": False,
            "geometry_digest_content_independent": True,
            "c78_independent_disk_scope": True,
            "runtime_ready": False,
            "profile_runtime_ready": False,
            "guest_calls": 0,
            "guest_execution": False,
            "ambient_lookup": 0,
            "raw_durable_ids": 0,
            "no_grant_direct_move": 0,
        }
        print(json.dumps(output, separators=(",", ":"), sort_keys=True))
        return 0
    except Exception as error:
        print(f"FAIL verify-c78-independent-disk: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
