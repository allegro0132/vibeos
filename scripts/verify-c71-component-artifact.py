#!/usr/bin/env python3
"""Independent verifier for the canonical C7.1 ComponentArtifact v1 wire format.

This verifier intentionally uses only the Python standard library and shares no
code with the Rust codec.  Passing it proves structural canonicality and the
unkeyed content commitments only.  It does not authenticate a signer, perform
Component validation, look up an object, or confer execution authority.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


ARTIFACT_MAGIC = b"VIBECMP\0"
CONTRACT_MAGIC = b"VIBECTR\0"
MANIFEST_MAGIC = b"VIBEMNF\0"

FORMAT_VERSION = 1
HEADER_LEN = 352
OBJECT_KIND = 0x434D5031
HASH_SHA256 = 1
CONTRACT_VERSION = 1
CONTRACT_HEADER_LEN = 24
MANIFEST_VERSION = 1
MANIFEST_HEADER_LEN = 40
SIGNER_POLICY_VERSION = 1

REVISION_COUNT = 5
PROFILE_LIMIT_COUNT = 44
INSTANCE_LIMIT_COUNT = 4

MAX_METADATA_BYTES = 384 * 1024
MAX_COMPONENT_BYTES = 1024 * 1024
MAX_ENCODED_BYTES = HEADER_LEN + MAX_METADATA_BYTES + MAX_COMPONENT_BYTES
MAX_WIT_PACKAGES = 256
MAX_INTERFACES = 512
MAX_IMPORTS = 256
MAX_EXPORTS = 256
MAX_CORE_MODULES = 8
MAX_ADAPTERS = 16
MAX_WORLD_BYTES = 256
MAX_NAME_BYTES = 256
MAX_VERSION_BYTES = 512
MAX_SHAPE_BYTES = 64 * 1024
MAX_WIT_SOURCE_BYTES = 256 * 1024
MAX_ADAPTER_BYTES = 64 * 1024
MAX_CORE_MODULE_BYTES = 512 * 1024

BODY_HASH_DOMAIN = b"vibeos.component-artifact.body.v1\0"
COMMITMENT_DOMAIN = b"vibeos.component-artifact.commitment.v1\0"
COMPONENT_HASH_DOMAIN = b"vibeos.component-artifact.component.v1\0"
CONTRACT_HASH_DOMAIN = b"vibeos.component-artifact.contract.v1\0"
MANIFEST_HASH_DOMAIN = b"vibeos.component-artifact.manifest.v1\0"
WIT_SOURCE_HASH_DOMAIN = b"vibeos.component-artifact.wit-source.v1\0"
CORE_MODULE_HASH_DOMAIN = b"vibeos.component-artifact.core-module.v1\0"
ADAPTER_HASH_DOMAIN = b"vibeos.component-artifact.adapter.v1\0"
COMMITMENT_OFFSET = 264
FIXTURE_SHA256_HEX = "d299f69930d6cf01476752f9bc02f37152e2396dd788f4fdfbab3cbb71f15556"


class VerificationError(Exception):
    """A fail-closed C7.1 wire-format rejection."""


PROFILE_LIMITS = (
    1024 * 1024,  # max_artifact_bytes
    1024 * 1024,  # max_component_bytes
    512 * 1024,  # max_core_module_bytes
    16,  # max_component_nesting
    128,  # max_core_nesting
    1024,  # max_types
    1024,  # max_functions
    32,  # max_params_per_function
    32,  # max_results_per_function
    256,  # max_imports
    256,  # max_exports
    256,  # max_globals
    4096,  # max_locals_per_function
    1,  # max_memories
    16,  # max_initial_memory_pages
    256,  # max_memory_pages
    1,  # max_tables
    4096,  # max_table_elements
    256,  # max_data_segments
    256,  # max_element_segments
    256,  # max_custom_sections
    64 * 1024,  # max_custom_section_bytes
    8,  # max_embedded_modules
    16,  # max_component_instances
    256,  # max_component_definitions
    256,  # max_aliases
    256,  # max_canonical_functions
    1024,  # max_canonical_options
    8,  # max_canonical_options_per_function
    128,  # max_async_functions
    128,  # max_future_types
    128,  # max_stream_types
    16,  # max_adapters
    256,  # max_resources
    128,  # max_call_depth
    64 * 1024,  # max_canonical_value_bytes
    32,  # max_canonical_nesting
    4096,  # max_canonical_values
    256,  # max_abi_allocations
    256,  # max_cleanup_actions
    64 * 1024,  # max_string_bytes
    4096,  # max_list_elements
    10_000_000,  # total_fuel
    10_000,  # poll_quantum
)

if len(PROFILE_LIMITS) != PROFILE_LIMIT_COUNT:
    raise AssertionError("PROFILE_LIMITS must contain exactly 44 fields")


@dataclass(frozen=True)
class Profile:
    code: int
    stage: int
    artifact_abi: int
    component_profile: int
    core_profile: int
    runtime_abi: int
    canonical_features: int
    revisions: tuple[str, str, str, str, str]


CORE_REVISION = "webassembly-core-2.0-integer-v1"
SYNC_COMPONENT_REVISION = "wasmparser-component-model-0.255.0"
ASYNC_COMPONENT_REVISION = "component-model-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc"
SYNC_CANONICAL_REVISION = "component-model-0.255.0-sync"
ASYNC_CANONICAL_REVISION = (
    "canonical-abi-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc-"
    "vibe-async-callback-1"
)
NATIVE_CANONICAL_REVISION = ASYNC_CANONICAL_REVISION + "-resource-free-exec-1"
WASM_TOOLS_REVISION = (
    "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380"
)

PROFILES = {
    1: Profile(
        code=1,
        stage=1,
        artifact_abi=1,
        component_profile=1,
        core_profile=1,
        runtime_abi=1,
        canonical_features=0x7,
        revisions=(
            CORE_REVISION,
            SYNC_COMPONENT_REVISION,
            SYNC_CANONICAL_REVISION,
            WASM_TOOLS_REVISION,
            "wasi-not-selected-sync",
        ),
    ),
    2: Profile(
        code=2,
        stage=2,
        artifact_abi=2,
        component_profile=1,
        core_profile=1,
        runtime_abi=2,
        canonical_features=(1 << 14) - 1,
        revisions=(
            CORE_REVISION,
            ASYNC_COMPONENT_REVISION,
            ASYNC_CANONICAL_REVISION,
            WASM_TOOLS_REVISION,
            "wasi-v0.3.0-3ee2a590c766594ae44a54730fc74fc27da5c609",
        ),
    ),
    3: Profile(
        code=3,
        stage=2,
        artifact_abi=3,
        component_profile=1,
        core_profile=1,
        runtime_abi=3,
        canonical_features=(1 << 0)
        | (1 << 3)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | (1 << 12),
        revisions=(
            CORE_REVISION,
            ASYNC_COMPONENT_REVISION,
            NATIVE_CANONICAL_REVISION,
            WASM_TOOLS_REVISION,
            "wasi-not-selected-native-async-resource-free",
        ),
    ),
}


@dataclass(frozen=True)
class WitPackage:
    name: str
    version: str
    source: str


@dataclass(frozen=True)
class Interface:
    """Non-authoritative diagnostic summary.

    Only the exact embedded WIT source plus a fresh validator may establish an
    admission contract; this string must never select or authorize an edge.
    """

    direction: int
    kind: int
    name: str
    diagnostic_shape: str


@dataclass(frozen=True)
class CoreModule:
    byte_len: int
    commitment: bytes


@dataclass(frozen=True)
class Adapter:
    ordinal: int
    revision: str
    descriptor: bytes


@dataclass(frozen=True)
class Manifest:
    world: str
    wit_packages: tuple[WitPackage, ...]
    interfaces: tuple[Interface, ...]
    core_modules: tuple[CoreModule, ...]
    adapters: tuple[Adapter, ...]


@dataclass(frozen=True)
class VerifiedArtifact:
    profile: Profile
    signer_kind: int
    signer_policy_digest: bytes
    instance_limits: tuple[int, int, int, int]
    manifest: Manifest
    component: bytes
    commitment: bytes

    @property
    def runtime_ready(self) -> bool:
        return False


class Cursor:
    def __init__(self, data: bytes, offset: int = 0) -> None:
        if offset < 0 or offset > len(data):
            raise VerificationError("cursor starts outside section")
        self.data = data
        self.offset = offset

    def take(self, length: int) -> bytes:
        if length < 0:
            raise VerificationError("negative field length")
        end = self.offset + length
        if end > len(self.data):
            raise VerificationError("section is truncated")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise VerificationError("section has trailing bytes")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def role_hash(domain: bytes, data: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(struct.pack("<Q", len(data)))
    digest.update(data)
    return digest.digest()


def reject_zero_digest(digest: bytes, label: str) -> None:
    if len(digest) != 32 or digest == bytes(32):
        raise VerificationError(f"{label} is the all-zero sentinel")


def read_u16(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as error:
        raise VerificationError("truncated u16") from error


def read_u32(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as error:
        raise VerificationError("truncated u32") from error


def read_u64(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<Q", data, offset)[0]
    except struct.error as error:
        raise VerificationError("truncated u64") from error


def exact_slice(data: bytes, offset: int, length: int, label: str) -> bytes:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise VerificationError(f"{label} is truncated")
    return data[offset : offset + length]


def token(raw: bytes, maximum: int, label: str) -> str:
    if not raw or len(raw) > maximum or any(byte < 0x21 or byte > 0x7E for byte in raw):
        raise VerificationError(f"{label} is not canonical visible ASCII")
    return raw.decode("ascii")


def source_text(raw: bytes) -> str:
    if not raw or len(raw) > MAX_WIT_SOURCE_BYTES or b"\0" in raw:
        raise VerificationError("WIT source is empty, oversized, or contains NUL")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("WIT source is not UTF-8") from error
    if value.encode("utf-8") != raw:
        raise VerificationError("WIT source UTF-8 is not byte-canonical")
    return value


def hash_body(contract: bytes, manifest: bytes, component: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(BODY_HASH_DOMAIN)
    for section in (contract, manifest, component):
        digest.update(struct.pack("<Q", len(section)))
        digest.update(section)
    return digest.digest()


def hash_commitment(data: bytes) -> bytes:
    if len(data) < HEADER_LEN:
        raise VerificationError("artifact is shorter than its fixed header")
    digest = hashlib.sha256()
    digest.update(COMMITMENT_DOMAIN)
    digest.update(struct.pack("<Q", len(data)))
    digest.update(data[:COMMITMENT_OFFSET])
    digest.update(bytes(32))
    digest.update(data[COMMITMENT_OFFSET + 32 :])
    return digest.digest()


def encode_contract(profile: Profile, limits: tuple[int, int, int, int]) -> bytes:
    body = bytearray()
    for revision in profile.revisions:
        encoded = revision.encode("ascii")
        body += struct.pack("<I", len(encoded))
        body += encoded
    body += struct.pack("<" + "Q" * PROFILE_LIMIT_COUNT, *PROFILE_LIMITS)
    body += struct.pack("<QQQQ", *limits)
    header = struct.pack(
        "<8sHHIHHHH",
        CONTRACT_MAGIC,
        CONTRACT_VERSION,
        CONTRACT_HEADER_LEN,
        0,
        REVISION_COUNT,
        PROFILE_LIMIT_COUNT,
        INSTANCE_LIMIT_COUNT,
        0,
    )
    return header + body


def verify_instance_limits(values: tuple[int, int, int, int]) -> None:
    memory_bytes, total_fuel, poll_quantum, resources = values
    if not 0 < memory_bytes <= PROFILE_LIMITS[15] * 65_536:
        raise VerificationError("instance memory limit is out of profile")
    if not 0 < total_fuel <= PROFILE_LIMITS[42]:
        raise VerificationError("instance fuel limit is out of profile")
    if not 0 < poll_quantum <= PROFILE_LIMITS[43] or poll_quantum > total_fuel:
        raise VerificationError("instance poll quantum is out of profile")
    if not 0 < resources <= PROFILE_LIMITS[33]:
        raise VerificationError("instance resource limit is out of profile")


def decode_contract(data: bytes, profile: Profile) -> tuple[int, int, int, int]:
    if len(data) < CONTRACT_HEADER_LEN or len(data) > MAX_METADATA_BYTES:
        raise VerificationError("contract size is outside the v1 bound")
    if data[:8] != CONTRACT_MAGIC:
        raise VerificationError("contract magic differs")
    if read_u16(data, 8) != CONTRACT_VERSION or read_u16(data, 10) != CONTRACT_HEADER_LEN:
        raise VerificationError("contract version/header length differs")
    if (
        read_u16(data, 16) != REVISION_COUNT
        or read_u16(data, 18) != PROFILE_LIMIT_COUNT
        or read_u16(data, 20) != INSTANCE_LIMIT_COUNT
    ):
        raise VerificationError("contract field counts differ")
    if read_u32(data, 12) != 0 or read_u16(data, 22) != 0:
        raise VerificationError("contract reserved field is non-zero")

    cursor = Cursor(data, CONTRACT_HEADER_LEN)
    for index, expected in enumerate(profile.revisions):
        length = cursor.u32()
        if not 0 < length <= MAX_VERSION_BYTES:
            raise VerificationError(f"revision {index} length is invalid")
        actual = token(cursor.take(length), MAX_VERSION_BYTES, f"revision {index}")
        if actual != expected:
            raise VerificationError(f"revision {index} does not match the profile")
    observed_limits = tuple(cursor.u64() for _ in range(PROFILE_LIMIT_COUNT))
    if observed_limits != PROFILE_LIMITS:
        raise VerificationError("one or more of the 44 profile limits differ")
    limits = tuple(cursor.u64() for _ in range(INSTANCE_LIMIT_COUNT))
    cursor.finish()
    verify_instance_limits(limits)  # type: ignore[arg-type]
    typed_limits = (limits[0], limits[1], limits[2], limits[3])
    if encode_contract(profile, typed_limits) != data:
        raise VerificationError("contract is not in its unique canonical encoding")
    return typed_limits


def encode_manifest(manifest: Manifest) -> bytes:
    world = manifest.world.encode("ascii")
    body = bytearray(world)
    for package in manifest.wit_packages:
        name = package.name.encode("ascii")
        version = package.version.encode("ascii")
        source = package.source.encode("utf-8")
        body += struct.pack("<HHII", len(name), len(version), len(source), 0)
        body += name + version + source + role_hash(WIT_SOURCE_HASH_DOMAIN, source)
    for interface in manifest.interfaces:
        name = interface.name.encode("ascii")
        shape = interface.diagnostic_shape.encode("ascii")
        body += struct.pack(
            "<BBHHHI",
            interface.direction,
            interface.kind,
            0,
            len(name),
            0,
            len(shape),
        )
        body += name + shape
    for module in manifest.core_modules:
        body += struct.pack("<II", module.byte_len, 0) + module.commitment
    for adapter in manifest.adapters:
        revision = adapter.revision.encode("ascii")
        body += struct.pack(
            "<IHHII",
            adapter.ordinal,
            len(revision),
            0,
            len(adapter.descriptor),
            0,
        )
        body += revision + adapter.descriptor + role_hash(ADAPTER_HASH_DOMAIN, adapter.descriptor)
    header = struct.pack(
        "<8sHHIHHIIIII",
        MANIFEST_MAGIC,
        MANIFEST_VERSION,
        MANIFEST_HEADER_LEN,
        0,
        len(world),
        0,
        len(manifest.wit_packages),
        len(manifest.interfaces),
        len(manifest.core_modules),
        len(manifest.adapters),
        0,
    )
    encoded = header + body
    if len(encoded) > MAX_METADATA_BYTES:
        raise VerificationError("manifest exceeds metadata bound")
    return encoded


def decode_manifest(
    data: bytes,
    expected_counts: tuple[int, int, int, int],
) -> Manifest:
    if len(data) < MANIFEST_HEADER_LEN or len(data) > MAX_METADATA_BYTES:
        raise VerificationError("manifest size is outside the v1 bound")
    if data[:8] != MANIFEST_MAGIC:
        raise VerificationError("manifest magic differs")
    if read_u16(data, 8) != MANIFEST_VERSION or read_u16(data, 10) != MANIFEST_HEADER_LEN:
        raise VerificationError("manifest version/header length differs")
    if read_u32(data, 12) != 0 or read_u16(data, 18) != 0 or read_u32(data, 36) != 0:
        raise VerificationError("manifest reserved field is non-zero")

    world_len = read_u16(data, 16)
    counts = (
        read_u32(data, 20),
        read_u32(data, 24),
        read_u32(data, 28),
        read_u32(data, 32),
    )
    wit_count, interface_count, module_count, adapter_count = counts
    if not 0 < world_len <= MAX_WORLD_BYTES:
        raise VerificationError("manifest world length is invalid")
    if not 0 < wit_count <= MAX_WIT_PACKAGES:
        raise VerificationError("manifest WIT package count is invalid")
    if interface_count > MAX_INTERFACES:
        raise VerificationError("manifest interface count is invalid")
    if module_count > MAX_CORE_MODULES:
        raise VerificationError("manifest core-module count is invalid")
    if adapter_count > MAX_ADAPTERS:
        raise VerificationError("manifest adapter count is invalid")
    if counts != expected_counts:
        raise VerificationError("manifest counts differ from the artifact header")

    cursor = Cursor(data, MANIFEST_HEADER_LEN)
    world = token(cursor.take(world_len), MAX_WORLD_BYTES, "world")

    wit_packages: list[WitPackage] = []
    for index in range(wit_count):
        name_len = cursor.u16()
        version_len = cursor.u16()
        source_len = cursor.u32()
        if cursor.u32() != 0:
            raise VerificationError(f"WIT package {index} reserved field is non-zero")
        if not 0 < name_len <= MAX_NAME_BYTES:
            raise VerificationError(f"WIT package {index} name length is invalid")
        if not 0 < version_len <= MAX_VERSION_BYTES:
            raise VerificationError(f"WIT package {index} version length is invalid")
        if not 0 < source_len <= MAX_WIT_SOURCE_BYTES:
            raise VerificationError(f"WIT package {index} source length is invalid")
        name = token(cursor.take(name_len), MAX_NAME_BYTES, f"WIT package {index} name")
        version = token(
            cursor.take(version_len), MAX_VERSION_BYTES, f"WIT package {index} version"
        )
        source_raw = cursor.take(source_len)
        source = source_text(source_raw)
        stored_commitment = cursor.take(32)
        reject_zero_digest(stored_commitment, f"WIT package {index} source commitment")
        if stored_commitment != role_hash(WIT_SOURCE_HASH_DOMAIN, source_raw):
            raise VerificationError(f"WIT package {index} source commitment differs")
        wit_packages.append(WitPackage(name, version, source))

    wit_keys = [(entry.name, entry.version) for entry in wit_packages]
    if wit_keys != sorted(wit_keys) or len(wit_keys) != len(set(wit_keys)):
        raise VerificationError("WIT packages are not strictly canonical by name/version")

    interfaces: list[Interface] = []
    for index in range(interface_count):
        direction = cursor.u8()
        kind = cursor.u8()
        if direction not in (1, 2) or kind not in (1, 2, 3):
            raise VerificationError(f"interface {index} direction/kind is invalid")
        if cursor.u16() != 0:
            raise VerificationError(f"interface {index} reserved field 0 is non-zero")
        name_len = cursor.u16()
        if cursor.u16() != 0:
            raise VerificationError(f"interface {index} reserved field 1 is non-zero")
        shape_len = cursor.u32()
        if not 0 < name_len <= MAX_NAME_BYTES or not 0 < shape_len <= MAX_SHAPE_BYTES:
            raise VerificationError(f"interface {index} text length is invalid")
        name = token(cursor.take(name_len), MAX_NAME_BYTES, f"interface {index} name")
        diagnostic_shape = token(
            cursor.take(shape_len), MAX_SHAPE_BYTES, f"interface {index} diagnostic shape"
        )
        interfaces.append(Interface(direction, kind, name, diagnostic_shape))

    interface_keys = [
        (entry.direction, entry.name, entry.kind, entry.diagnostic_shape)
        for entry in interfaces
    ]
    duplicate_keys = [(entry.direction, entry.name) for entry in interfaces]
    if interface_keys != sorted(interface_keys) or len(duplicate_keys) != len(set(duplicate_keys)):
        raise VerificationError("interfaces are not canonical or repeat a direction/name")
    import_count = sum(entry.direction == 1 for entry in interfaces)
    export_count = len(interfaces) - import_count
    if import_count > MAX_IMPORTS or export_count > MAX_EXPORTS:
        raise VerificationError("interface direction exceeds the exact profile import/export limit")

    core_modules: list[CoreModule] = []
    for index in range(module_count):
        byte_len = cursor.u32()
        if cursor.u32() != 0:
            raise VerificationError(f"core module {index} reserved field is non-zero")
        commitment = cursor.take(32)
        if not 0 < byte_len <= MAX_CORE_MODULE_BYTES:
            raise VerificationError(f"core module {index} length is invalid")
        reject_zero_digest(commitment, f"core module {index} commitment")
        core_modules.append(CoreModule(byte_len, commitment))

    adapters: list[Adapter] = []
    for index in range(adapter_count):
        ordinal = cursor.u32()
        revision_len = cursor.u16()
        if cursor.u16() != 0:
            raise VerificationError(f"adapter {index} reserved field 0 is non-zero")
        descriptor_len = cursor.u32()
        if cursor.u32() != 0:
            raise VerificationError(f"adapter {index} reserved field 1 is non-zero")
        if not 0 < revision_len <= MAX_VERSION_BYTES:
            raise VerificationError(f"adapter {index} revision length is invalid")
        if not 0 < descriptor_len <= MAX_ADAPTER_BYTES:
            raise VerificationError(f"adapter {index} descriptor length is invalid")
        revision = token(
            cursor.take(revision_len), MAX_VERSION_BYTES, f"adapter {index} revision"
        )
        descriptor = cursor.take(descriptor_len)
        stored_commitment = cursor.take(32)
        reject_zero_digest(stored_commitment, f"adapter {index} commitment")
        if stored_commitment != role_hash(ADAPTER_HASH_DOMAIN, descriptor):
            raise VerificationError(f"adapter {index} descriptor commitment differs")
        adapters.append(Adapter(ordinal, revision, descriptor))
    cursor.finish()

    ordinals = [adapter.ordinal for adapter in adapters]
    if ordinals != list(range(adapter_count)):
        raise VerificationError("adapter ordinals are not the exact canonical 0..count sequence")

    manifest = Manifest(
        world,
        tuple(wit_packages),
        tuple(interfaces),
        tuple(core_modules),
        tuple(adapters),
    )
    if encode_manifest(manifest) != data:
        raise VerificationError("manifest is not in its unique canonical encoding")
    return manifest


def verify_artifact(data: bytes) -> VerifiedArtifact:
    if len(data) < HEADER_LEN:
        raise VerificationError("artifact is truncated before its fixed header")
    if len(data) > MAX_ENCODED_BYTES:
        raise VerificationError("artifact exceeds the aggregate v1 bound")
    if data[:8] != ARTIFACT_MAGIC:
        raise VerificationError("artifact magic differs")
    if read_u16(data, 8) != FORMAT_VERSION:
        raise VerificationError("artifact format version differs")
    if read_u16(data, 10) != HEADER_LEN or read_u32(data, 12) != 0:
        raise VerificationError("artifact header length/flags differ")
    if read_u32(data, 16) != OBJECT_KIND:
        raise VerificationError("artifact ObjectKind differs")
    if read_u16(data, 20) != HASH_SHA256:
        raise VerificationError("artifact hash algorithm differs")
    if read_u16(data, 26) != MANIFEST_VERSION or read_u16(data, 30) != SIGNER_POLICY_VERSION:
        raise VerificationError("artifact nested format version differs")
    if (
        read_u16(data, 96) != PROFILE_LIMIT_COUNT
        or read_u16(data, 98) != INSTANCE_LIMIT_COUNT
        or read_u16(data, 100) != REVISION_COUNT
    ):
        raise VerificationError("artifact frozen field counts differ")
    if read_u16(data, 102) != 0 or any(data[296:HEADER_LEN]):
        raise VerificationError("artifact reserved field is non-zero")

    profile = PROFILES.get(read_u16(data, 22))
    if profile is None:
        raise VerificationError("artifact profile code is unsupported")
    if (
        read_u16(data, 24) != profile.stage
        or read_u16(data, 32) != profile.artifact_abi
        or read_u16(data, 34) != profile.component_profile
        or read_u16(data, 36) != profile.core_profile
        or read_u16(data, 38) != profile.runtime_abi
        or read_u64(data, 40) != profile.canonical_features
    ):
        raise VerificationError("artifact profile identity differs")

    signer_kind = read_u16(data, 28)
    if signer_kind not in (1, 2):
        raise VerificationError("artifact signer-policy kind is unsupported")
    signer_policy_digest = exact_slice(data, 232, 32, "signer policy digest")
    reject_zero_digest(signer_policy_digest, "signer policy digest")

    contract_len = read_u64(data, 48)
    manifest_len = read_u64(data, 56)
    component_len = read_u64(data, 64)
    declared_total = read_u64(data, 72)
    if not 0 < component_len <= MAX_COMPONENT_BYTES:
        raise VerificationError("component length is outside the profile bound")
    if contract_len + manifest_len > MAX_METADATA_BYTES:
        raise VerificationError("artifact metadata exceeds its aggregate bound")
    total = HEADER_LEN + contract_len + manifest_len + component_len
    if total != len(data) or declared_total != total:
        raise VerificationError("artifact section lengths or total length differ")

    contract_start = HEADER_LEN
    manifest_start = contract_start + contract_len
    component_start = manifest_start + manifest_len
    contract = exact_slice(data, contract_start, contract_len, "contract")
    manifest_data = exact_slice(data, manifest_start, manifest_len, "manifest")
    component = exact_slice(data, component_start, component_len, "component")

    component_commitment = exact_slice(data, 104, 32, "component commitment")
    contract_commitment = exact_slice(data, 136, 32, "contract commitment")
    manifest_commitment = exact_slice(data, 168, 32, "manifest commitment")
    body_commitment = exact_slice(data, 200, 32, "body commitment")
    commitment = exact_slice(data, COMMITMENT_OFFSET, 32, "artifact commitment")
    reject_zero_digest(component_commitment, "component commitment")
    if component_commitment != role_hash(COMPONENT_HASH_DOMAIN, component):
        raise VerificationError("component commitment differs")
    if contract_commitment != role_hash(CONTRACT_HASH_DOMAIN, contract):
        raise VerificationError("contract commitment differs")
    if manifest_commitment != role_hash(MANIFEST_HASH_DOMAIN, manifest_data):
        raise VerificationError("manifest commitment differs")
    if body_commitment != hash_body(contract, manifest_data, component):
        raise VerificationError("body commitment differs")
    if commitment != hash_commitment(data):
        raise VerificationError("artifact commitment differs")

    limits = decode_contract(contract, profile)
    expected_counts = (
        read_u32(data, 80),
        read_u32(data, 84),
        read_u32(data, 88),
        read_u32(data, 92),
    )
    manifest = decode_manifest(manifest_data, expected_counts)
    artifact = VerifiedArtifact(
        profile,
        signer_kind,
        signer_policy_digest,
        limits,
        manifest,
        component,
        commitment,
    )
    if encode_artifact(artifact) != data:
        raise VerificationError("artifact is not in its unique canonical encoding")
    return artifact


def encode_artifact(artifact: VerifiedArtifact) -> bytes:
    verify_instance_limits(artifact.instance_limits)
    contract = encode_contract(artifact.profile, artifact.instance_limits)
    manifest = encode_manifest(artifact.manifest)
    if len(contract) + len(manifest) > MAX_METADATA_BYTES:
        raise VerificationError("artifact metadata exceeds its aggregate bound")
    if not 0 < len(artifact.component) <= MAX_COMPONENT_BYTES:
        raise VerificationError("component length is outside the profile bound")
    reject_zero_digest(artifact.signer_policy_digest, "signer policy digest")
    if artifact.signer_kind not in (1, 2):
        raise VerificationError("unsupported signer policy")

    total = HEADER_LEN + len(contract) + len(manifest) + len(artifact.component)
    if total > MAX_ENCODED_BYTES:
        raise VerificationError("artifact exceeds the aggregate v1 bound")
    out = bytearray(total)
    out[:8] = ARTIFACT_MAGIC
    struct.pack_into("<HHII", out, 8, FORMAT_VERSION, HEADER_LEN, 0, OBJECT_KIND)
    struct.pack_into(
        "<HHHHHHHHHHQ",
        out,
        20,
        HASH_SHA256,
        artifact.profile.code,
        artifact.profile.stage,
        MANIFEST_VERSION,
        artifact.signer_kind,
        SIGNER_POLICY_VERSION,
        artifact.profile.artifact_abi,
        artifact.profile.component_profile,
        artifact.profile.core_profile,
        artifact.profile.runtime_abi,
        artifact.profile.canonical_features,
    )
    struct.pack_into(
        "<QQQQ",
        out,
        48,
        len(contract),
        len(manifest),
        len(artifact.component),
        total,
    )
    struct.pack_into(
        "<IIIIHHHH",
        out,
        80,
        len(artifact.manifest.wit_packages),
        len(artifact.manifest.interfaces),
        len(artifact.manifest.core_modules),
        len(artifact.manifest.adapters),
        PROFILE_LIMIT_COUNT,
        INSTANCE_LIMIT_COUNT,
        REVISION_COUNT,
        0,
    )
    out[232:264] = artifact.signer_policy_digest

    contract_start = HEADER_LEN
    manifest_start = contract_start + len(contract)
    component_start = manifest_start + len(manifest)
    out[contract_start:manifest_start] = contract
    out[manifest_start:component_start] = manifest
    out[component_start:] = artifact.component
    out[104:136] = role_hash(COMPONENT_HASH_DOMAIN, artifact.component)
    out[136:168] = role_hash(CONTRACT_HASH_DOMAIN, contract)
    out[168:200] = role_hash(MANIFEST_HASH_DOMAIN, manifest)
    out[200:232] = hash_body(contract, manifest, artifact.component)
    out[COMMITMENT_OFFSET : COMMITMENT_OFFSET + 32] = hash_commitment(bytes(out))
    return bytes(out)


def fixture_artifact() -> bytes:
    core_a = b"\0asm\x01\0\0\0module-one"
    core_b = b"\0asm\x01\0\0\0module-two-is-distinct"
    manifest = Manifest(
        world="alpha:api/root",
        wit_packages=(
            WitPackage(
                "alpha:api",
                "1.0.0",
                "package alpha:api@1.0.0;\n\nworld alpha-world {\n  export run: func();\n}\n",
            ),
            WitPackage(
                "zeta:api",
                "2.3.0",
                "package zeta:api@2.3.0;\n\nworld zeta-world {\n  import log: func(value: string);\n}\n",
            ),
        ),
        interfaces=(
            Interface(1, 2, "alpha:api/logger", "instance{log:func(string)}"),
            Interface(2, 1, "zeta:api/run", "func(u32)->u32"),
        ),
        core_modules=(
            CoreModule(len(core_a), role_hash(CORE_MODULE_HASH_DOMAIN, core_a)),
            CoreModule(len(core_b), role_hash(CORE_MODULE_HASH_DOMAIN, core_b)),
        ),
        adapters=(
            Adapter(0, "canonical-lower-v1", b"canonical-lower-descriptor-zero"),
            Adapter(1, "canonical-lower-v2", b"canonical-lower-descriptor-one"),
        ),
    )
    unfinished = VerifiedArtifact(
        profile=PROFILES[2],
        signer_kind=2,
        signer_policy_digest=bytes([0xA5]) * 32,
        instance_limits=(8 * 65_536, 456_789, 1_000, 7),
        manifest=manifest,
        component=b"\0asm\r\0\x01\0secret-component-body-c71",
        commitment=bytes(32),
    )
    return encode_artifact(unfinished)


def reseal(data: bytes) -> bytes:
    """Recompute all outer unkeyed hashes after a fixed-length mutation."""
    out = bytearray(data)
    contract_len = read_u64(out, 48)
    manifest_len = read_u64(out, 56)
    component_len = read_u64(out, 64)
    if HEADER_LEN + contract_len + manifest_len + component_len != len(out):
        raise VerificationError("cannot reseal mutation with inconsistent lengths")
    contract = bytes(out[HEADER_LEN : HEADER_LEN + contract_len])
    manifest_start = HEADER_LEN + contract_len
    component_start = manifest_start + manifest_len
    manifest = bytes(out[manifest_start:component_start])
    component = bytes(out[component_start:])
    out[104:136] = role_hash(COMPONENT_HASH_DOMAIN, component)
    out[136:168] = role_hash(CONTRACT_HASH_DOMAIN, contract)
    out[168:200] = role_hash(MANIFEST_HASH_DOMAIN, manifest)
    out[200:232] = hash_body(contract, manifest, component)
    out[COMMITMENT_OFFSET : COMMITMENT_OFFSET + 32] = bytes(32)
    out[COMMITMENT_OFFSET : COMMITMENT_OFFSET + 32] = hash_commitment(bytes(out))
    return bytes(out)


def recommit(data: bytes) -> bytes:
    out = bytearray(data)
    out[COMMITMENT_OFFSET : COMMITMENT_OFFSET + 32] = bytes(32)
    out[COMMITMENT_OFFSET : COMMITMENT_OFFSET + 32] = hash_commitment(bytes(out))
    return bytes(out)


def expect_rejected(data: bytes, label: str) -> None:
    try:
        verify_artifact(data)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def flip(data: bytes, offset: int) -> bytes:
    out = bytearray(data)
    out[offset] ^= 1
    return bytes(out)


@dataclass(frozen=True)
class FixtureLayout:
    contract_start: int
    revision_starts: tuple[int, ...]
    profile_limits_start: int
    instance_limits_start: int
    manifest_start: int
    world_start: int
    wit_records: tuple[tuple[int, int, int, int], ...]
    interface_records: tuple[tuple[int, int], ...]
    module_records: tuple[int, ...]
    adapter_records: tuple[tuple[int, int, int], ...]


def fixture_layout(data: bytes) -> FixtureLayout:
    contract_start = HEADER_LEN
    contract_len = read_u64(data, 48)
    manifest_start = contract_start + contract_len
    contract_cursor = Cursor(data[contract_start:manifest_start], CONTRACT_HEADER_LEN)
    revisions: list[int] = []
    for _ in range(REVISION_COUNT):
        length = contract_cursor.u32()
        revisions.append(contract_start + contract_cursor.offset)
        contract_cursor.take(length)
    profile_limits_start = contract_start + contract_cursor.offset
    contract_cursor.take(PROFILE_LIMIT_COUNT * 8)
    instance_limits_start = contract_start + contract_cursor.offset

    manifest_len = read_u64(data, 56)
    manifest = data[manifest_start : manifest_start + manifest_len]
    cursor = Cursor(manifest, MANIFEST_HEADER_LEN)
    world_start = manifest_start + cursor.offset
    cursor.take(read_u16(manifest, 16))
    wit_records: list[tuple[int, int, int, int]] = []
    for _ in range(read_u32(manifest, 20)):
        start = cursor.offset
        name_len = cursor.u16()
        version_len = cursor.u16()
        source_len = cursor.u32()
        cursor.u32()
        cursor.take(name_len + version_len)
        source_start = manifest_start + cursor.offset
        cursor.take(source_len)
        hash_start = manifest_start + cursor.offset
        cursor.take(32)
        wit_records.append(
            (manifest_start + start, manifest_start + cursor.offset, source_start, hash_start)
        )
    interface_records: list[tuple[int, int]] = []
    for _ in range(read_u32(manifest, 24)):
        start = cursor.offset
        cursor.u8()
        cursor.u8()
        cursor.u16()
        name_len = cursor.u16()
        cursor.u16()
        shape_len = cursor.u32()
        cursor.take(name_len + shape_len)
        interface_records.append((manifest_start + start, manifest_start + cursor.offset))
    module_records: list[int] = []
    for _ in range(read_u32(manifest, 28)):
        module_records.append(manifest_start + cursor.offset)
        cursor.take(40)
    adapter_records: list[tuple[int, int, int]] = []
    for _ in range(read_u32(manifest, 32)):
        start = cursor.offset
        cursor.u32()
        revision_len = cursor.u16()
        cursor.u16()
        descriptor_len = cursor.u32()
        cursor.u32()
        cursor.take(revision_len)
        descriptor_start = manifest_start + cursor.offset
        cursor.take(descriptor_len)
        hash_start = manifest_start + cursor.offset
        cursor.take(32)
        adapter_records.append((manifest_start + start, descriptor_start, hash_start))
    cursor.finish()
    return FixtureLayout(
        contract_start,
        tuple(revisions),
        profile_limits_start,
        instance_limits_start,
        manifest_start,
        world_start,
        tuple(wit_records),
        tuple(interface_records),
        tuple(module_records),
        tuple(adapter_records),
    )


def mutate_u16(data: bytes, offset: int, value: int) -> bytes:
    out = bytearray(data)
    struct.pack_into("<H", out, offset, value)
    return bytes(out)


def mutate_u32(data: bytes, offset: int, value: int) -> bytes:
    out = bytearray(data)
    struct.pack_into("<I", out, offset, value)
    return bytes(out)


def mutate_u64(data: bytes, offset: int, value: int) -> bytes:
    out = bytearray(data)
    struct.pack_into("<Q", out, offset, value)
    return bytes(out)


def selftest() -> None:
    valid = fixture_artifact()
    observed_fixture_hash = hashlib.sha256(valid).hexdigest()
    if observed_fixture_hash != FIXTURE_SHA256_HEX:
        raise VerificationError(
            "independent fixture drifted: "
            f"observed={observed_fixture_hash} expected={FIXTURE_SHA256_HEX}"
        )
    parsed = verify_artifact(valid)
    if parsed.runtime_ready or parsed.profile.code != 2:
        raise VerificationError("valid fixture exposed runtime readiness or wrong profile")
    if encode_artifact(parsed) != valid or fixture_artifact() != valid:
        raise VerificationError("independent fixture is not deterministic/canonical")
    layout = fixture_layout(valid)

    for direction, maximum, label in (
        (1, MAX_IMPORTS, "imports"),
        (2, MAX_EXPORTS, "exports"),
    ):
        excessive_manifest = Manifest(
            parsed.manifest.world,
            parsed.manifest.wit_packages,
            tuple(
                Interface(direction, 1, f"test:many/entity-{index}", "func()")
                for index in range(maximum + 1)
            ),
            (),
            (),
        )
        excessive = VerifiedArtifact(
            parsed.profile,
            parsed.signer_kind,
            parsed.signer_policy_digest,
            parsed.instance_limits,
            excessive_manifest,
            parsed.component,
            bytes(32),
        )
        expect_rejected(encode_artifact(excessive), f"too-many-{label}")

    for length in range(len(valid)):
        expect_rejected(valid[:length], f"strict-prefix-{length}")
    for start in range(1, len(valid) + 1):
        expect_rejected(valid[start:], f"strict-suffix-{start}")
    for length in range(1, 17):
        expect_rejected(valid + bytes(range(length)), f"appended-bytes-{length}")

    for label, offset in (
        ("component-hash", 104),
        ("contract-hash", 136),
        ("manifest-hash", 168),
        ("body-hash", 200),
        ("commitment", COMMITMENT_OFFSET),
    ):
        expect_rejected(flip(valid, offset), label)

    header_u16_mutations = (
        ("format-version", 8, 2),
        ("header-length", 10, HEADER_LEN - 1),
        ("hash-algorithm", 20, 2),
        ("profile-code", 22, 1),
        ("profile-stage", 24, 1),
        ("manifest-version", 26, 2),
        ("signer-kind", 28, 0),
        ("signer-version", 30, 2),
        ("artifact-abi", 32, 1),
        ("component-profile", 34, 2),
        ("core-profile", 36, 2),
        ("runtime-abi", 38, 1),
        ("profile-limit-count", 96, 43),
        ("instance-limit-count", 98, 3),
        ("revision-count", 100, 4),
        ("header-reserved-short", 102, 1),
    )
    for label, offset, value in header_u16_mutations:
        expect_rejected(recommit(mutate_u16(valid, offset, value)), label)
    expect_rejected(recommit(mutate_u32(valid, 12, 1)), "header-flags")
    expect_rejected(recommit(mutate_u32(valid, 16, OBJECT_KIND + 1)), "object-kind")
    expect_rejected(recommit(mutate_u64(valid, 40, read_u64(valid, 40) ^ 1)), "features")
    for offset in range(296, HEADER_LEN):
        expect_rejected(
            recommit(flip(valid, offset)), f"header-reserved-tail-{offset}"
        )
    zero_signer = bytearray(valid)
    zero_signer[232:264] = bytes(32)
    expect_rejected(recommit(bytes(zero_signer)), "zero-signer-policy-digest")

    for label, offset in (
        ("contract-length", 48),
        ("manifest-length", 56),
        ("component-length", 64),
        ("total-length", 72),
    ):
        expect_rejected(mutate_u64(valid, offset, read_u64(valid, offset) + 1), label)
    for index, offset in enumerate((80, 84, 88, 92)):
        expect_rejected(
            recommit(mutate_u32(valid, offset, read_u32(valid, offset) + 1)),
            f"header-count-{index}",
        )

    expect_rejected(
        reseal(mutate_u16(valid, layout.contract_start + 8, 2)), "contract-version"
    )
    expect_rejected(
        reseal(mutate_u16(valid, layout.contract_start + 10, 23)), "contract-header-length"
    )
    expect_rejected(
        reseal(mutate_u32(valid, layout.contract_start + 12, 1)), "contract-flags"
    )
    for offset, label in ((16, "revisions"), (18, "profile-limits"), (20, "instance-limits")):
        expect_rejected(
            reseal(mutate_u16(valid, layout.contract_start + offset, 0)),
            f"contract-count-{label}",
        )
    expect_rejected(
        reseal(mutate_u16(valid, layout.contract_start + 22, 1)), "contract-reserved"
    )
    for index, offset in enumerate(layout.revision_starts):
        expect_rejected(reseal(flip(valid, offset)), f"revision-{index}")
    for index in range(PROFILE_LIMIT_COUNT):
        offset = layout.profile_limits_start + index * 8
        expect_rejected(
            reseal(mutate_u64(valid, offset, read_u64(valid, offset) + 1)),
            f"profile-limit-{index}",
        )
    for index in range(INSTANCE_LIMIT_COUNT):
        offset = layout.instance_limits_start + index * 8
        expect_rejected(reseal(mutate_u64(valid, offset, 0)), f"instance-limit-{index}")

    manifest_start = layout.manifest_start
    for label, offset, width, value in (
        ("manifest-version", manifest_start + 8, 2, 2),
        ("manifest-header-length", manifest_start + 10, 2, 39),
        ("manifest-flags", manifest_start + 12, 4, 1),
        ("manifest-reserved-short", manifest_start + 18, 2, 1),
        ("manifest-reserved-long", manifest_start + 36, 4, 1),
    ):
        mutated = (
            mutate_u16(valid, offset, value)
            if width == 2
            else mutate_u32(valid, offset, value)
        )
        expect_rejected(reseal(mutated), label)
    invalid_world = bytearray(valid)
    invalid_world[layout.world_start] = 0x20
    expect_rejected(reseal(bytes(invalid_world)), "world-token")

    first_wit = layout.wit_records[0]
    expect_rejected(reseal(flip(valid, first_wit[2])), "WIT-source")
    expect_rejected(reseal(flip(valid, first_wit[3])), "WIT-source-digest")
    wit_reserved = first_wit[0] + 8
    expect_rejected(reseal(mutate_u32(valid, wit_reserved, 1)), "WIT-reserved")
    swapped = bytearray(valid)
    first = valid[layout.wit_records[0][0] : layout.wit_records[0][1]]
    second = valid[layout.wit_records[1][0] : layout.wit_records[1][1]]
    swapped[layout.wit_records[0][0] : layout.wit_records[1][1]] = second + first
    expect_rejected(reseal(bytes(swapped)), "noncanonical-WIT-order")

    first_interface = layout.interface_records[0][0]
    expect_rejected(reseal(mutate_u16(valid, first_interface + 2, 1)), "interface-reserved-0")
    expect_rejected(reseal(mutate_u16(valid, first_interface + 6, 1)), "interface-reserved-1")
    expect_rejected(reseal(mutate_u16(valid, first_interface, 0)), "interface-direction-kind")

    first_module = layout.module_records[0]
    expect_rejected(reseal(mutate_u32(valid, first_module + 4, 1)), "module-reserved")
    zero_module = bytearray(valid)
    zero_module[first_module + 8 : first_module + 40] = bytes(32)
    expect_rejected(reseal(bytes(zero_module)), "module-zero-digest")

    first_adapter, second_adapter = layout.adapter_records
    expect_rejected(reseal(mutate_u16(valid, first_adapter[0] + 6, 1)), "adapter-reserved-0")
    expect_rejected(reseal(mutate_u32(valid, first_adapter[0] + 12, 1)), "adapter-reserved-1")
    expect_rejected(reseal(flip(valid, first_adapter[1])), "adapter-descriptor")
    expect_rejected(reseal(flip(valid, first_adapter[2])), "adapter-digest")
    duplicate_ordinal = mutate_u32(valid, second_adapter[0], read_u32(valid, first_adapter[0]))
    expect_rejected(reseal(duplicate_ordinal), "duplicate-adapter-ordinal")
    gap_ordinal = mutate_u32(valid, second_adapter[0], 2)
    expect_rejected(reseal(gap_ordinal), "gap-adapter-ordinal")

    # Demonstrate the precise security boundary: an attacker can construct a
    # different internally consistent, still-inert envelope because SHA-256 is
    # a commitment, not signer authentication.  C7.3 must authenticate it.
    independently_changed = bytearray(valid)
    independently_changed[first_wit[2]] ^= 1
    source_len = read_u32(independently_changed, first_wit[0] + 4)
    changed_source = bytes(independently_changed[first_wit[2] : first_wit[2] + source_len])
    independently_changed[first_wit[3] : first_wit[3] + 32] = role_hash(
        WIT_SOURCE_HASH_DOMAIN, changed_source
    )
    changed = reseal(bytes(independently_changed))
    changed_parsed = verify_artifact(changed)
    if changed_parsed.runtime_ready or changed_parsed.commitment == parsed.commitment:
        raise VerificationError("commitment/authentication boundary selftest failed")


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_ENCODED_BYTES + 1)
        if len(data) > MAX_ENCODED_BYTES:
            raise VerificationError("artifact file exceeds the aggregate v1 bound")
        return data


def describe(artifact: VerifiedArtifact) -> str:
    return (
        f"profile={artifact.profile.code} signer_policy={artifact.signer_kind} "
        f"wit={len(artifact.manifest.wit_packages)} "
        f"interfaces={len(artifact.manifest.interfaces)} "
        f"modules={len(artifact.manifest.core_modules)} "
        f"adapters={len(artifact.manifest.adapters)} "
        f"component_bytes={len(artifact.component)} runtime_ready=0 authenticated=0"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="verify a canonical, inert C7.1 ComponentArtifact v1"
    )
    parser.add_argument("artifact", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if not args.selftest and args.artifact is None:
        parser.error("provide --selftest and/or an artifact path")
    try:
        if args.selftest:
            selftest()
        if args.artifact is not None:
            artifact = verify_artifact(read_bounded(args.artifact))
            print(f"PASS verify-c71-component-artifact: {describe(artifact)}")
        elif args.selftest:
            print(
                "PASS verify-c71-component-artifact: independent canonical fixture, "
                "strict-prefix/suffix, 44+4 limits, reserved/version/hash/order "
                "mutations, runtime_ready=0 authenticated=0"
            )
    except (OSError, VerificationError, ValueError, struct.error) as error:
        print(f"FAIL verify-c71-component-artifact: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
