#!/usr/bin/env python3
"""Independent C7.6 three-boot graph-version replacement verifier.

The powered-off verifier imports the frozen low-level Storage V2 parser used
by C7.4, but supplies its own disjoint V3 policy and graph-history selector.
It imports no production Rust and does not trust a guest PASS marker as disk
authority.  Both the post-boot-1 G0 image and post-boot-2 G1 image are parsed;
the final post-boot-3 image must equal G1 byte-for-byte.

This is intentionally a narrow C7.6 verifier, not the general disk parser
reserved for C7.8.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VECTORS = (
    ROOT / "policy/image/artifacts/c76-graph-version-replacement.vectors"
)
VECTOR_MAGIC = "VIBEOS-C76-GRAPH-VERSION-REPLACEMENT-V1"
ACTIVE_PUBLIC_KEY = bytes.fromhex(
    "1dfaeb2e9d9ff3d5c4eb7f81a1197dd09f8a301a5a31b6ed15921e939574154f"
)

BLOCK = 512
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
GRAPH_MAX_LEN = 64 * 1024
NATIVE_EMPTY_CHECKPOINT_GENERATION = 2
C76_CAPACITY_PREPARATION_CHECKPOINTS = 1
C76_QEMU_ADMITTED_SEGMENTS = 14
GRAPH_MANIFEST_DOMAIN = b"vibeos.component-graph-version.manifest.v1\0"
GRAPH_COMMITMENT_DOMAIN = b"vibeos.component-graph-version.commitment.v1\0"
ARTIFACT_EVIDENCE_COMMITMENT_DOMAIN = (
    b"vibeos.component-artifact.authentication-evidence.v1\0"
)
LEAF_SIGNATURE_DOMAIN = b"vibeos.component-artifact.operator-admission.v1\0"
GRAPH_SIGNATURE_DOMAIN = b"vibeos.component-graph.operator-admission.v1.c7\0"
POLICY_GENERATION = 1

POLICY_V3 = (
    b"vibeos.storage-v2.external-policy.v3\0"
    b"persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0"
    b"program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0"
    b"graph-space=0x564942454f532d47524150482d563100,slot=0,generations=0..1,rights=r,kind=0x43475631\0"
    b"graph-attachments=exact-root-relative,per-generation=3*0x434d5031+3*0x434d4531+1*0x43474531,inline=1,ungranted=1,max-replacement=1"
)

COMMON_MARKER = (
    "runtime_ready=0 guest_calls=0 raw_ids=0 ambient_lookup=0 vsh=0"
)
BOOT1_PASS = (
    "WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=installed_g0 "
    "versions=1 replacements=0 image_candidate=1 physical_readback=1 "
    "fresh_graphs=1 current_visible=1 candidate_runtime_objects=0 "
    + COMMON_MARKER
)
BOOT2_PASS = (
    "WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=replaced_g1 "
    "versions=2 replacements=1 image_candidate=1 durable_before_candidate=1 "
    "physical_readback=1 fresh_graphs=2 policy_cancel=1 candidate_hidden=1 "
    "old_terminal_before_new_visible=1 siblings_stable=2 sibling_restarts=0 "
    "old_routes_retired=2 fresh_routes=2 stale_replacement_tokens=2 "
    "late_wake_stale=1 visibility_linearizations=1 mixed_versions=0 "
    "fail_stop_armed=1 "
    + COMMON_MARKER
)
BOOT3_PASS = (
    "WASM_C76_GRAPH_VERSION_REPLACEMENT PASS durable_state=existing_g1 "
    "versions=2 replacements=1 image_candidate=0 no_write=1 "
    "physical_readback=1 fresh_graphs=2 successor_visible=1 "
    "candidate_runtime_objects=0 "
    + COMMON_MARKER
)
FAIL_MARKER = "WASM_C76_GRAPH_VERSION_REPLACEMENT FAIL"


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


# This is the same independent low-level disk/record parser composed by C7.4,
# not C7.4's Component-specific high-level selector.
migration = load_module(
    "verify-storage-v2-migration.py", "vibeos_c76_storage_v2_disk_parser"
)
c73 = load_module(
    "verify-c73-authenticated-admission.py", "vibeos_c76_artifact_codec"
)
c71 = load_module(
    "verify-c71-component-artifact.py", "vibeos_c76_artifact_verifier"
)
legacy = migration.legacy_codec


def u16(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def u32(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def u64(data: bytes | bytearray, at: int) -> int:
    return struct.unpack_from("<Q", data, at)[0]


def u128(data: bytes | bytearray, at: int) -> int:
    return int.from_bytes(data[at : at + 16], "little")


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def framed_sha256(domain: bytes, value: bytes) -> bytes:
    return sha256(domain, struct.pack("<Q", len(value)), value)


def load_vectors(path: Path) -> dict[str, bytes]:
    lines = path.read_text(encoding="ascii").splitlines()
    require(lines and lines[0] == VECTOR_MAGIC, "C7.6 vector magic differs")
    values: dict[str, bytes] = {}
    for line in lines[1:]:
        require(line and "=" in line, "malformed C7.6 vector line")
        name, raw = line.split("=", 1)
        require(
            re.fullmatch(r"[a-z0-9_]+", name) is not None,
            "invalid C7.6 vector name",
        )
        require(name not in values, "duplicate C7.6 vector name")
        require(
            len(raw) > 0
            and len(raw) % 2 == 0
            and re.fullmatch(r"[0-9a-f]+", raw) is not None,
            "invalid C7.6 vector hex",
        )
        values[name] = bytes.fromhex(raw)
    required = {"active_public_key"}
    for generation in ("g0", "g1"):
        required.add(f"{generation}_descriptor")
        required.add(f"{generation}_graph_evidence")
        for index in range(3):
            required.add(f"{generation}_artifact_{index}")
            required.add(f"{generation}_evidence_{index}")
    require(set(values) == required, "C7.6 vector field set differs")
    require(
        values["active_public_key"] == ACTIVE_PUBLIC_KEY,
        "C7.6 vector cannot select the hand-reviewed active signer",
    )
    return values


def validate_detached_evidence(
    encoded: bytes, expected_magic: bytes, active_public_key: bytes, label: str
) -> None:
    require(len(encoded) == EVIDENCE_LEN, f"{label} encoded length differs")
    require(encoded[:8] == expected_magic, f"{label} magic differs")
    require(
        u16(encoded, 8) == 1
        and u16(encoded, 10) == EVIDENCE_LEN
        and u16(encoded, 12) == 1
        and u16(encoded, 14) == 0,
        f"{label} header differs",
    )
    key = encoded[16:48]
    signature = encoded[48:]
    require(key == active_public_key, f"{label} signer differs from active signer")
    require(any(signature), f"{label} signature is the zero sentinel")
    # Strict point/subgroup and canonical-S checks are useful even though the
    # exact checked-in evidence bytes are the independent fixture authority.
    c73.strict_point(key, f"{label} public key")
    c73.strict_point(signature[:32], f"{label} signature R")
    require(
        int.from_bytes(signature[32:], "little") < c73.ORDER,
        f"{label} signature S is non-canonical",
    )


def leaf_signature_transcript(artifact: bytes) -> bytes:
    require(len(LEAF_SIGNATURE_DOMAIN) == 48, "leaf signature domain length drifted")
    require(
        u16(artifact, 28) == 2 and u16(artifact, 30) == 1,
        "C7.6 leaf signature transcript is not operator-required v1",
    )
    out = bytearray(192)
    out[:48] = LEAF_SIGNATURE_DOMAIN
    struct.pack_into(
        "<HHHHHHHHHH",
        out,
        48,
        1,  # transcript version
        1,  # evidence version
        1,  # Ed25519
        1,  # artifact format
        1,  # artifact manifest
        1,  # artifact signer policy
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
    out[152:184] = ACTIVE_PUBLIC_KEY
    struct.pack_into("<Q", out, 184, POLICY_GENERATION)
    return bytes(out)


def verify_leaf_signature(artifact: bytes, encoded_evidence: bytes, label: str) -> None:
    validate_detached_evidence(
        encoded_evidence, b"VIBESIG\0", ACTIVE_PUBLIC_KEY, label
    )
    require(
        c73.ed25519_verify(
            ACTIVE_PUBLIC_KEY,
            leaf_signature_transcript(artifact),
            encoded_evidence[48:],
        ),
        f"{label} Ed25519 artifact transcript differs",
    )


def graph_signature_transcript(descriptor: bytes) -> bytes:
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
    out[152:184] = ACTIVE_PUBLIC_KEY
    struct.pack_into("<Q", out, 184, POLICY_GENERATION)
    ordinal = u64(descriptor, 48)
    struct.pack_into("<Q", out, 192, ordinal)
    predecessor = descriptor[96:128]
    if predecessor != bytes(32):
        out[200:232] = predecessor
        out[232] = 1
    return bytes(out)


def verify_graph_signature(
    descriptor: bytes, encoded_evidence: bytes, label: str
) -> None:
    validate_detached_evidence(
        encoded_evidence, b"VIBEGSG\0", ACTIVE_PUBLIC_KEY, label
    )
    require(
        c73.ed25519_verify(
            ACTIVE_PUBLIC_KEY,
            graph_signature_transcript(descriptor),
            encoded_evidence[48:],
        ),
        f"{label} Ed25519 graph transcript differs",
    )


class Cursor:
    def __init__(self, encoded: bytes):
        self.encoded = encoded
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        require(end <= len(self.encoded), "CGV1 body is truncated")
        value = self.encoded[self.offset : end]
        self.offset = end
        return value

    def u16(self) -> int:
        return u16(self.take(2), 0)

    def u32(self) -> int:
        return u32(self.take(4), 0)

    def u64(self) -> int:
        return u64(self.take(8), 0)

    def text(self, length: int, maximum: int, label: str) -> str:
        require(0 < length <= maximum, f"CGV1 {label} length differs")
        raw = self.take(length)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError(f"CGV1 {label} is not UTF-8") from error
        require(value.encode("utf-8") == raw, f"CGV1 {label} is non-canonical")
        require(
            all(
                ord(character) < 128
                and (character.isalnum() or character in "-_.:/@")
                for character in value
            ),
            f"CGV1 {label} contains forbidden text",
        )
        return value

    def finish(self) -> None:
        require(self.offset == len(self.encoded), "CGV1 body has trailing bytes")


@dataclass(frozen=True)
class ParsedNode:
    ordinal: int
    nesting: int
    parent: int
    label: str
    world: str
    artifact_len: int
    artifact_commitment: bytes
    evidence_commitment: bytes
    artifact_policy: bytes
    component_identity: bytes
    world_contract: bytes
    limits: tuple[int, int, int, int]
    budget: tuple[int, int, int, int, int, int, int, int]


@dataclass(frozen=True)
class ParsedDescriptor:
    ordinal: int
    predecessor: bytes
    policy_digest: bytes
    commitment: bytes
    name: str
    account: tuple[int, ...]
    nodes: tuple[ParsedNode, ...]
    edges: tuple[tuple[int, int, int, int], ...]
    async_edges: tuple[tuple[int, int, int, int, int, int, int], ...]
    published: tuple[tuple[int, int], ...]
    incidents: tuple[tuple[int, int, int, int, int], ...]


def descriptor_commitment(encoded: bytes) -> bytes:
    require(len(encoded) >= GRAPH_HEADER_LEN, "CGV1 descriptor is truncated")
    return sha256(
        GRAPH_COMMITMENT_DOMAIN,
        struct.pack("<Q", len(encoded)),
        encoded[:192],
        bytes(32),
        encoded[224:],
    )


def parse_endpoint(cursor: Cursor) -> tuple[int, int]:
    return cursor.u16(), cursor.u16()


def parse_edge(cursor: Cursor) -> tuple[int, int, int, int]:
    source = parse_endpoint(cursor)
    target = parse_endpoint(cursor)
    return source[0], source[1], target[0], target[1]


def artifact_profile(artifact: bytes) -> tuple[int, int, int, int, int, int, int]:
    verified = c71.verify_artifact(artifact)
    require(
        u16(artifact, 28) == 2 and u16(artifact, 30) == 1,
        "C7.6 CMP1 is not operator-required",
    )
    require(
        verified.profile.code == 2
        and verified.profile.stage == 2
        and not verified.runtime_ready,
        "C7.6 CMP1 is not validation-only async",
    )
    return (
        u16(artifact, 22),
        u16(artifact, 24),
        u16(artifact, 32),
        u16(artifact, 34),
        u16(artifact, 36),
        u16(artifact, 38),
        u64(artifact, 40),
    )


def parse_descriptor(
    encoded: bytes,
    artifacts: tuple[bytes, bytes, bytes],
    evidences: tuple[bytes, bytes, bytes],
) -> ParsedDescriptor:
    require(
        GRAPH_HEADER_LEN <= len(encoded) <= GRAPH_MAX_LEN,
        "CGV1 descriptor length is outside its bound",
    )
    require(encoded[:8] == b"VIBECGV\0", "CGV1 magic differs")
    require(
        u16(encoded, 8) == 1
        and u16(encoded, 10) == GRAPH_HEADER_LEN
        and u32(encoded, 12) == 0
        and u32(encoded, 16) == CGV1
        and u16(encoded, 20) == 1
        and u16(encoded, 22) == 1
        and u16(encoded, 24) == 1,
        "CGV1 fixed header differs",
    )
    require(
        u16(encoded, 26) == 2
        and u16(encoded, 28) == 2
        and u16(encoded, 30) == 1,
        "CGV1 is not the validation-only async profile",
    )
    require(
        not any(encoded[42:48])
        and u16(encoded, 94) == 0
        and not any(encoded[224:GRAPH_HEADER_LEN]),
        "CGV1 reserved header bytes are non-zero",
    )
    require(
        u64(encoded, 56) == len(encoded)
        and u64(encoded, 64) == len(encoded) - GRAPH_HEADER_LEN,
        "CGV1 declared lengths differ",
    )
    counts = tuple(u16(encoded, at) for at in range(72, 88, 2))
    require(
        counts == (3, 2, 2, 0, 1, 0, 0, 2),
        "CGV1 does not contain exactly 3 nodes/2 async edges/1 export",
    )
    require(
        u16(encoded, 88) == 1
        and u16(encoded, 90) == 1
        and u16(encoded, 92) == 1,
        "CGV1 replacement target/max/PolicyCancel differs",
    )
    body = encoded[GRAPH_HEADER_LEN:]
    require(
        encoded[160:192] == framed_sha256(GRAPH_MANIFEST_DOMAIN, body),
        "CGV1 manifest hash differs",
    )
    commitment = descriptor_commitment(encoded)
    require(encoded[192:224] == commitment, "CGV1 commitment differs")
    policy_digest = encoded[128:160]
    require(any(policy_digest), "CGV1 policy digest is zero")

    cursor = Cursor(body)
    account = tuple(cursor.u64() for _ in range(13))
    name = cursor.text(cursor.u16(), 64, "name")
    nodes: list[ParsedNode] = []
    graph_profile = (
        u16(encoded, 26),
        u16(encoded, 28),
        u16(encoded, 32),
        u16(encoded, 34),
        u16(encoded, 36),
        u16(encoded, 38),
        u64(encoded, 40),
    )
    for index in range(3):
        ordinal = cursor.u16()
        nesting = cursor.u16()
        parent = cursor.u16()
        require(cursor.u16() == 0, "CGV1 node reserved word is non-zero")
        artifact_len = cursor.u64()
        digests = tuple(cursor.take(32) for _ in range(5))
        require(all(any(value) for value in digests), "CGV1 node has a zero digest")
        limits = tuple(cursor.u64() for _ in range(4))
        budget = tuple(cursor.u64() for _ in range(8))
        label_len = cursor.u16()
        world_len = cursor.u16()
        require(cursor.u32() == 0, "CGV1 node text reserved word is non-zero")
        label = cursor.text(label_len, 128, "node label")
        world = cursor.text(world_len, 256, "node world")
        require(":" in world, "CGV1 node world is not a qualified world")
        require(ordinal == index, "CGV1 node ordinals are not dense")
        require(
            (nesting == 0 and parent == 0) or (nesting == 1 and parent < index),
            "CGV1 node nesting differs",
        )
        artifact = artifacts[index]
        evidence = evidences[index]
        verified_artifact = c71.verify_artifact(artifact)
        require(artifact_profile(artifact) == graph_profile, "CMP1/CGV1 profiles differ")
        require(artifact_len == len(artifact), "CGV1 node artifact length differs")
        require(
            digests[0] == c73.artifact_commitment(artifact),
            "CGV1 node artifact commitment differs",
        )
        require(
            digests[1]
            == framed_sha256(ARTIFACT_EVIDENCE_COMMITMENT_DOMAIN, evidence),
            "CGV1 node evidence commitment differs",
        )
        require(digests[2] == artifact[232:264], "CGV1 node artifact policy differs")
        component = verified_artifact.component
        require(digests[3] == hashlib.sha256(component).digest(), "CGV1 component identity differs")
        require(
            world == verified_artifact.manifest.world
            and limits == verified_artifact.instance_limits
            and budget[0] == len(component)
            # ComponentPlan counts instantiated cores, not merely embedded
            # module declarations.  The fixed source/relay/sink fixtures each
            # independently validate to two instances and no adapter/resource.
            and budget[1] == 2
            and budget[2] == len(verified_artifact.manifest.adapters) == 0
            and budget[3] == 0
            and limits[3] == budget[4]
            and limits[:3] == budget[5:8]
            and all(limits)
            and limits[2] <= limits[1],
            "CGV1 node budget/instance limits differ",
        )
        nodes.append(
            ParsedNode(
                ordinal,
                nesting,
                parent,
                label,
                world,
                artifact_len,
                digests[0],
                digests[1],
                digests[2],
                digests[3],
                digests[4],
                limits,
                budget,
            )
        )
    require(len({node.label for node in nodes}) == 3, "CGV1 node labels alias")

    edges = tuple(parse_edge(cursor) for _ in range(2))
    require(tuple(sorted(edges)) == edges and len(set(edges)) == 2, "CGV1 edge order differs")
    require(
        edges[0][0] == 0
        and edges[0][2] == 1
        and edges[1][0] == 1
        and edges[1][2] == 2,
        "CGV1 topology is not the fixed source/relay/sink chain",
    )
    require(len({edge[2:] for edge in edges}) == 2, "CGV1 edge targets alias")

    async_edges = []
    for _ in range(2):
        edge = parse_edge(cursor)
        async_functions = cursor.u32()
        streams = cursor.u32()
        futures = cursor.u32()
        require(cursor.u32() == 0, "CGV1 async edge reserved word is non-zero")
        require(async_functions > 0, "CGV1 async edge has no async function")
        async_edges.append((*edge, async_functions, streams, futures))
    require(
        tuple(item[:4] for item in async_edges) == edges,
        "CGV1 async metadata is not exact for both edges",
    )

    published = (parse_endpoint(cursor),)
    require(published[0][0] == 2, "CGV1 does not publish the sink")
    incidents = []
    for _ in range(2):
        edge = parse_edge(cursor)
        action = cursor.u16()
        require(cursor.u16() == 0, "CGV1 incident reserved word is non-zero")
        require(action == 1, "CGV1 incident edge is not RecreateFresh")
        incidents.append((*edge, action))
    cursor.finish()
    require(
        tuple(item[:4] for item in incidents) == edges,
        "CGV1 incident-edge set does not exactly cover the replacement target",
    )
    require(
        nodes[1].nesting == 0
        and not any(node.nesting == 1 and node.parent == 1 for node in nodes),
        "CGV1 replacement target owns an unsupported nested node",
    )

    maximum_nesting = 1
    for node in nodes:
        if node.nesting == 1:
            depth = 2
            parent = node.parent
            while nodes[parent].nesting == 1:
                depth += 1
                parent = nodes[parent].parent
            maximum_nesting = max(maximum_nesting, depth)
    expected_account = (
        3,
        2,
        maximum_nesting,
        0,
        1,
        sum(node.budget[0] for node in nodes),
        sum(node.budget[1] for node in nodes),
        sum(node.budget[2] for node in nodes),
        sum(node.budget[3] for node in nodes),
        sum(node.budget[4] for node in nodes),
        sum(node.budget[5] for node in nodes),
        sum(node.budget[6] for node in nodes),
        max(node.budget[7] for node in nodes),
    )
    require(account == expected_account, "CGV1 aggregate account differs")
    return ParsedDescriptor(
        u64(encoded, 48),
        encoded[96:128],
        policy_digest,
        commitment,
        name,
        account,
        tuple(nodes),
        edges,
        tuple(async_edges),
        published,
        tuple(incidents),
    )


def validate_vectors(vectors: dict[str, bytes]) -> tuple[ParsedDescriptor, ParsedDescriptor]:
    active = vectors["active_public_key"]
    require(
        active == ACTIVE_PUBLIC_KEY,
        "C7.6 vectors differ from the hand-reviewed active signer",
    )
    c73.strict_point(active, "active graph signer")
    parsed: list[ParsedDescriptor] = []
    for generation in ("g0", "g1"):
        artifacts = tuple(vectors[f"{generation}_artifact_{index}"] for index in range(3))
        evidences = tuple(vectors[f"{generation}_evidence_{index}"] for index in range(3))
        for index, (artifact, evidence) in enumerate(zip(artifacts, evidences)):
            verify_leaf_signature(
                artifact, evidence, f"{generation} CME1[{index}]"
            )
        descriptor = vectors[f"{generation}_descriptor"]
        parsed.append(parse_descriptor(descriptor, artifacts, evidences))
        verify_graph_signature(
            descriptor,
            vectors[f"{generation}_graph_evidence"],
            f"{generation} CGE1",
        )
    g0, g1 = parsed
    require(g0.ordinal == 0 and g0.predecessor == bytes(32), "G0 predecessor relation differs")
    require(
        g1.ordinal == 1 and g1.predecessor == g0.commitment,
        "G1 does not name the exact G0 predecessor commitment",
    )
    require(
        g0.name == g1.name
        and g0.policy_digest == g1.policy_digest
        and g0.edges == g1.edges
        and g0.async_edges == g1.async_edges
        and g0.published == g1.published
        and g0.incidents == g1.incidents,
        "G0/G1 graph policy or topology differs",
    )
    for sibling in (0, 2):
        require(
            vectors[f"g0_artifact_{sibling}"] == vectors[f"g1_artifact_{sibling}"]
            and vectors[f"g0_evidence_{sibling}"] == vectors[f"g1_evidence_{sibling}"]
            and g0.nodes[sibling] == g1.nodes[sibling],
            "G0/G1 stable sibling bytes differ",
        )
    require(
        vectors["g0_artifact_1"] != vectors["g1_artifact_1"]
        and g0.nodes[1] != g1.nodes[1]
        and g0.commitment != g1.commitment,
        "G1 did not replace exactly the relay node",
    )
    return g0, g1


def version_values(vectors: dict[str, bytes], generation: int) -> tuple[tuple[int, bytes], ...]:
    prefix = f"g{generation}"
    return (
        *((CMP1, vectors[f"{prefix}_artifact_{index}"]) for index in range(3)),
        *((CME1, vectors[f"{prefix}_evidence_{index}"]) for index in range(3)),
        (CGE1, vectors[f"{prefix}_graph_evidence"]),
        (CGV1, vectors[f"{prefix}_descriptor"]),
    )


def structural_version_values(state: Any, base: int) -> tuple[tuple[int, bytes], ...]:
    values = []
    expected_kinds = (CMP1, CMP1, CMP1, CME1, CME1, CME1, CGE1, CGV1)
    for index, kind in enumerate(expected_kinds):
        object_id = base + index * 2 + 1
        value = state.objects.get(object_id)
        require(value is not None and value[0] == kind, "C7.6 object layout/kind differs")
        require(value[1], "C7.6 retained object is empty")
        if kind in (CME1, CGE1):
            require(len(value[1]) == EVIDENCE_LEN, "C7.6 evidence length differs")
        values.append((kind, value[1]))
    return tuple(values)


def inspect_history_state(state: Any) -> dict[str, Any]:
    require(state.formatted, "C7.6 logical authority is not formatted")
    require(len(state.grants) in (1, 2), "C7.6 root history count differs")
    require(len(state.objects) == len(state.grants) * 8, "C7.6 object history count differs")
    require(
        all(kind in (CMP1, CME1, CGE1, CGV1) for kind, _bytes, _seq in state.objects.values()),
        "C7.6 contains a foreign ObjectKind",
    )
    roots = state.grants
    base0 = 1
    base1 = GRAPH_SPACE + 1
    expected_bases = (base0,) if len(roots) == 1 else (base0, base1)
    for generation, (root, base) in enumerate(zip(roots, expected_bases)):
        expected_derivation = base + (17 if generation == 0 else 18)
        descriptor_id = base + 15
        require(
            (
                root.derivation,
                root.parent,
                root.object_id,
                root.space,
                root.slot,
                root.generation,
                root.rights,
                root.resource_kind,
                root.flags,
            )
            == (
                expected_derivation,
                0,
                descriptor_id,
                GRAPH_SPACE,
                0,
                generation,
                READ,
                STORED_OBJECT_RESOURCE_KIND,
                ROOT_FLAG,
            ),
            "C7.6 exact graph root differs",
        )
        structural_version_values(state, base)
        require(
            all(grant.object_id not in {base + index * 2 + 1 for index in range(7)} for grant in roots),
            "C7.6 attachment unexpectedly has a grant",
        )
    current = roots[-1]
    require(
        state.live == {current.derivation: current}
        and state.slots == {(GRAPH_SPACE, 0): (len(roots) - 1, current.derivation)},
        "C7.6 live graph slot differs",
    )
    if len(roots) == 1:
        require(not state.tombstones, "G0 contains a tombstone")
        require(state.high_water == base1, "G0 high-water differs")
    else:
        require(
            state.tombstones == {roots[0].derivation: roots[1].commit_sequence - 2},
            "G1 tombstone is absent, late, or ambiguous",
        )
        require(state.high_water == base1 + 19, "G1 high-water differs")
    return {
        "versions": len(roots),
        "current_descriptor": current.object_id,
        "current_generation": len(roots) - 1,
    }


def exact_policy_objects(state: Any) -> dict[int, tuple[int, bytes, int]]:
    """V3 selector supplied to the independent Storage V2 disk parser."""

    if not state.objects and not state.grants and not state.tombstones:
        require(state.formatted and not state.live and not state.slots, "empty V3 floor retains authority")
        return {}
    history = inspect_history_state(state)
    descriptor = history["current_descriptor"]
    return {descriptor: state.objects[descriptor]}


def decoded_records(record_stream: bytes) -> list[Any]:
    require(record_stream and len(record_stream) % BLOCK == 0, "C7.6 record stream is not aligned")
    records = []
    previous_sequence = 0
    previous_crc = 0
    for index in range(0, len(record_stream), BLOCK):
        raw = record_stream[index : index + BLOCK]
        record = legacy.decode_sector(raw, migration.M4_FIRST + index // BLOCK)
        require(record is not None, "C7.6 stream contains an empty or torn logical record")
        require(
            record.sequence == previous_sequence + 1
            and record.previous_sequence == previous_sequence
            and record.previous_crc == previous_crc,
            "C7.6 record chain is not exact and dense",
        )
        records.append(record)
        previous_sequence = record.sequence
        previous_crc = record.crc
    return records


def parse_object_transaction(
    records: list[Any], cursor: int, transaction: int, object_id: int, kind: int
) -> tuple[int, bytes]:
    require(cursor < len(records), "C7.6 object prepare is absent")
    prepare = records[cursor]
    require(
        prepare.kind == legacy.OBJECT_PREPARE
        and prepare.transaction == transaction
        and u128(prepare.raw, PAYLOAD) == object_id
        and u32(prepare.raw, PAYLOAD + 16) == kind
        and u32(prepare.raw, PAYLOAD + 20) == 0,
        "C7.6 object prepare metadata/order differs",
    )
    length = u64(prepare.raw, PAYLOAD + 24)
    chunks = u32(prepare.raw, PAYLOAD + 32)
    require(length > 0 and chunks == (length + 359) // 360, "C7.6 object geometry differs")
    encoded = bytearray()
    chunk_crcs = bytearray()
    for index in range(chunks):
        at = cursor + 1 + index
        require(at < len(records), "C7.6 object chunks are truncated")
        chunk = records[at]
        expected_len = min(360, length - index * 360)
        require(
            chunk.kind == legacy.OBJECT_CHUNK
            and chunk.transaction == transaction
            and u128(chunk.raw, PAYLOAD) == object_id
            and u32(chunk.raw, PAYLOAD + 16) == index
            and u16(chunk.raw, PAYLOAD + 20) == expected_len
            and u16(chunk.raw, PAYLOAD + 22) == 0,
            "C7.6 object chunk ordering/binding differs",
        )
        encoded.extend(chunk.raw[PAYLOAD + 24 : PAYLOAD + 24 + expected_len])
        chunk_crcs.extend(struct.pack("<I", chunk.crc))
    commit_at = cursor + 1 + chunks
    require(commit_at < len(records), "C7.6 object commit is absent")
    commit = records[commit_at]
    require(
        commit.kind == legacy.OBJECT_COMMIT
        and commit.transaction == transaction
        and u128(commit.raw, PAYLOAD) == object_id
        and u64(commit.raw, PAYLOAD + 16) == prepare.sequence
        and u32(commit.raw, PAYLOAD + 24) == prepare.crc
        and u32(commit.raw, PAYLOAD + 28) == chunks
        and u64(commit.raw, PAYLOAD + 32) == records[cursor + 1].sequence
        and u32(commit.raw, PAYLOAD + 40) == legacy.crc32c(bytes(chunk_crcs))
        and u32(commit.raw, PAYLOAD + 44) == legacy.crc32c(bytes(encoded))
        and u32(prepare.raw, PAYLOAD + 36) == legacy.crc32c(bytes(encoded)),
        "C7.6 object commit does not exactly bind its prepare/chunks",
    )
    return commit_at + 1, bytes(encoded)


def parse_root_transaction(
    records: list[Any], cursor: int, transaction: int, derivation: int,
    descriptor: int, generation: int
) -> int:
    require(cursor + 1 < len(records), "C7.6 root transaction is truncated")
    prepare, commit = records[cursor], records[cursor + 1]
    require(
        prepare.kind == legacy.GRANT_PREPARE
        and prepare.transaction == transaction
        and (
            u128(prepare.raw, PAYLOAD),
            u128(prepare.raw, PAYLOAD + 16),
            u128(prepare.raw, PAYLOAD + 32),
            u128(prepare.raw, PAYLOAD + 48),
            u32(prepare.raw, PAYLOAD + 64),
            u64(prepare.raw, PAYLOAD + 72),
            u32(prepare.raw, PAYLOAD + 68),
            u32(prepare.raw, PAYLOAD + 80),
            u32(prepare.raw, PAYLOAD + 84),
        )
        == (
            derivation,
            0,
            descriptor,
            GRAPH_SPACE,
            0,
            generation,
            READ,
            STORED_OBJECT_RESOURCE_KIND,
            ROOT_FLAG,
        ),
        "C7.6 graph root prepare differs",
    )
    require(
        commit.kind == legacy.GRANT_COMMIT
        and commit.transaction == transaction
        and u64(commit.raw, PAYLOAD) == prepare.sequence
        and u32(commit.raw, PAYLOAD + 8) == prepare.crc
        and u32(commit.raw, PAYLOAD + 12) == 0
        and u128(commit.raw, PAYLOAD + 16) == derivation,
        "C7.6 graph root commit differs",
    )
    return cursor + 2


def validate_exact_logical(
    record_stream: bytes,
    vectors: dict[str, bytes],
    expected_versions: int,
    *,
    validate_bundle: bool = True,
) -> dict[str, Any]:
    require(expected_versions in (1, 2), "C7.6 selftest requested an invalid version count")
    if validate_bundle:
        validate_vectors(vectors)
    records = decoded_records(record_stream)
    state = migration.recover_record_stream(record_stream)
    history = inspect_history_state(state)
    require(history["versions"] == expected_versions, "C7.6 logical version count differs")
    require(records[0].kind == legacy.FORMAT, "C7.6 stream does not start with Format")
    cursor = 1
    bases = (1, GRAPH_SPACE + 1)
    recovered_values: list[tuple[tuple[int, bytes], ...]] = []
    root_derivations = []
    for generation in range(expected_versions):
        base = bases[generation]
        require(cursor < len(records), "C7.6 high-water record is absent")
        high_water = records[cursor]
        expected_high_water = GRAPH_SPACE + 1 if generation == 0 else base + 19
        require(
            high_water.kind == legacy.HIGH_WATER
            and high_water.transaction == 0
            and u128(high_water.raw, PAYLOAD) == expected_high_water,
            "C7.6 high-water reservation/order differs",
        )
        cursor += 1
        values = []
        for index, (expected_kind, expected_bytes) in enumerate(
            version_values(vectors, generation)
        ):
            transaction = base + index * 2
            object_id = transaction + 1
            cursor, observed = parse_object_transaction(
                records, cursor, transaction, object_id, expected_kind
            )
            require(observed == expected_bytes, "C7.6 durable bytes differ from exact vectors")
            require(state.objects[object_id][1] == observed, "C7.6 recovered object bytes differ")
            values.append((expected_kind, observed))
        recovered_values.append(tuple(values))
        if generation == 1:
            require(cursor < len(records), "C7.6 G0 tombstone is absent")
            tombstone = records[cursor]
            require(
                tombstone.kind == legacy.TOMBSTONE
                and tombstone.transaction == base + 16
                and u128(tombstone.raw, PAYLOAD) == root_derivations[0],
                "C7.6 G0 tombstone is absent, early, late, or ambiguous",
            )
            cursor += 1
        derivation = base + (17 if generation == 0 else 18)
        root_derivations.append(derivation)
        cursor = parse_root_transaction(
            records,
            cursor,
            base + (16 if generation == 0 else 17),
            derivation,
            base + 15,
            generation,
        )
    require(cursor == len(records), "C7.6 stream has history after the exact graph root")
    require(
        sum(record.kind == legacy.HIGH_WATER for record in records) == expected_versions,
        "C7.6 contains a foreign high-water record",
    )
    return {
        "versions": expected_versions,
        "record_count": len(records),
        "component_artifacts": expected_versions * 3,
        "component_evidence": expected_versions * 3,
        "graph_evidence": expected_versions,
        "graph_descriptors": expected_versions,
        "attachments_ungranted": expected_versions * 7,
        "tombstones": expected_versions - 1,
        "current_generation": expected_versions - 1,
    }


PHYSICAL_AUTHORITY_POLICY = migration.AuthorityPolicy(
    external_policy=POLICY_V3,
    exact_objects=exact_policy_objects,
)


def verify_powered_off_image(
    image: bytes, vectors_path: Path, expected_versions: int
) -> dict[str, Any]:
    vectors = load_vectors(vectors_path)
    validate_vectors(vectors)
    require(len(image) % BLOCK == 0, "powered-off C7.6 image is not block aligned")
    require(not any(image[: migration.M4_FIRST * BLOCK]), "C7.6 unmanaged prefix changed")
    m4_start = migration.M4_FIRST * BLOCK
    m4_end = (migration.M4_FIRST + migration.M4_COUNT) * BLOCK
    require(not any(image[m4_start:m4_end]), "C7.6 wrote the frozen M4 range")
    physical = migration.verify_image(
        image,
        bytes(migration.M4_FIRST * BLOCK),
        expect_native=True,
        authority_policy=PHYSICAL_AUTHORITY_POLICY,
    )
    status, evidence = migration.probe_v2(
        image, authority_policy=PHYSICAL_AUTHORITY_POLICY
    )
    require(status == "valid" and evidence is not None, "C7.6 V3 authority is not recoverable")
    recovered = evidence["recovered"]
    authority = recovered["authority"]
    require(authority is not None, "C7.6 checkpoint has no authority payload")
    # Native provisioning publishes the canonical empty authority at
    # generation 2.  The fixed 128 MiB QEMU profile then performs exactly one
    # policy-bound foreground-capacity growth before its first graph append;
    # G0 and G1 each consume exactly one further authority checkpoint.  Keep
    # the capacity transition explicit rather than folding it into a relaxed
    # generation range: in particular, replacement must advance G0 -> G1 by
    # one checkpoint and cold G1 recovery must not advance it at all.
    expected_checkpoint = (
        NATIVE_EMPTY_CHECKPOINT_GENERATION
        + C76_CAPACITY_PREPARATION_CHECKPOINTS
        + expected_versions
    )
    require(
        evidence["selected_checkpoint_generation"] == expected_checkpoint
        and evidence["authority_generation"] == expected_checkpoint,
        "C7.6 checkpoint generation does not equal native floor plus exact capacity/graph appends",
    )
    allocation = recovered["allocation"]
    require(
        allocation["checkpoint_generation"] == expected_checkpoint
        and allocation["admitted_segments"] == C76_QEMU_ADMITTED_SEGMENTS
        and allocation["counts"]["retired"] == 0,
        "C7.6 allocation state differs from the single fixed capacity preparation",
    )
    require(
        evidence["verified_checkpoint_copies"] == 2,
        "C7.6 did not retain two verified checkpoint copies",
    )
    logical = validate_exact_logical(
        authority["record_stream"], vectors, expected_versions
    )
    bindings = authority["objects"]
    require(
        len(bindings) == 1
        and not authority["external_roots"]
        and bindings[0]["object_kind"] == CGV1,
        "C7.6 physical binding table is not the sole current CGV1 root",
    )
    current_prefix = f"g{expected_versions - 1}"
    current_descriptor = vectors[f"{current_prefix}_descriptor"]
    current_stable = (1 if expected_versions == 1 else GRAPH_SPACE + 1) + 15
    require(
        bindings[0]["stable_object_id"] == current_stable,
        "C7.6 physical binding names a non-current descriptor",
    )
    mapping = recovered["objects"].get(bindings[0]["v2_object_id"])
    require(mapping is not None, "C7.6 current descriptor has no CAS mapping")
    content = recovered["contents"].get(
        migration.gc_verifier.blob_key_identity(mapping["blob_key"])
    )
    require(content == current_descriptor, "C7.6 physical CGV1 readback differs")
    equivalence = migration.verify_authority_bindings(evidence)
    expected_cas = sorted(
        (
            vectors[f"g{generation}_descriptor"],
            NATIVE_EMPTY_CHECKPOINT_GENERATION
            + C76_CAPACITY_PREPARATION_CHECKPOINTS
            + generation
            + 1,
        )
        for generation in range(expected_versions)
    )
    observed_cas = []
    for candidate in recovered["objects"].values():
        candidate_content = recovered["contents"].get(
            migration.gc_verifier.blob_key_identity(candidate["blob_key"])
        )
        require(
            candidate["object_kind"] == CGV1 and candidate_content is not None,
            "C7.6 CAS catalog contains a non-CGV1 or unreadable object",
        )
        observed_cas.append((candidate_content, candidate["commit_generation"]))
    require(
        equivalence["authority_objects"] == 1
        and equivalence["cas_objects"] == expected_versions
        and equivalence["unique_blobs"] == expected_versions
        and sorted(observed_cas) == expected_cas,
        "C7.6 physical catalog differs from the exact retained descriptor history",
    )
    return {
        "mode": physical["mode"],
        "selected_checkpoint_generation": expected_checkpoint,
        "admitted_segments": allocation["admitted_segments"],
        "verified_checkpoint_copies": evidence["verified_checkpoint_copies"],
        "policy_v3": True,
        "graph_root_slot": 0,
        "graph_root_generation": expected_versions - 1,
        "physical_bindings": 1,
        "historical_cas_descriptors": expected_versions,
        "external_roots": 0,
        "cas_orphans": 0,
        "logical": logical,
    }


def normalize_lines(raw: str) -> list[str]:
    return [line for line in raw.replace("\r", "\n").splitlines() if line]


def verify_boot_transcript(raw: str, expected: str, boot: int) -> None:
    lines = normalize_lines(raw)
    reports = [line for line in lines if line.startswith("WASM_C76_GRAPH_VERSION_REPLACEMENT")]
    require(reports == [expected], f"C7.6 boot {boot} report is missing, duplicate, or non-exact")
    require(FAIL_MARKER not in lines, f"C7.6 boot {boot} guest reported FAIL")
    require(
        not any(re.search(r"\[!\] (fatal|panic)|panicked at", line) for line in lines),
        f"C7.6 boot {boot} guest reported panic/fatal",
    )
    transcript_forbidden = (
        "ObjectId",
        "SpaceId",
        "DerivationId",
        "TransactionId",
        "Cap {",
        "public_key=",
        "signature=",
    )
    require(
        not any(token in line for token in transcript_forbidden for line in lines),
        f"C7.6 boot {boot} transcript leaks durable/signer identity material",
    )
    forbidden = (
        "ObjectId",
        "SpaceId",
        "DerivationId",
        "TransactionId",
        "Capability",
        "Cap {",
        "slot=",
        "generation=",
        "public_key=",
        "signature=",
        "digest=",
        "sha256=",
    )
    require(
        not any(token in reports[0] for token in forbidden),
        f"C7.6 boot {boot} report leaks durable/signer identity material",
    )


def verify_evidence(
    g0_image: bytes,
    g1_image: bytes,
    final_image: bytes,
    vectors_path: Path,
    boot1_transcript: str,
    boot2_transcript: str,
    boot3_transcript: str,
) -> dict[str, Any]:
    verify_boot_transcript(boot1_transcript, BOOT1_PASS, 1)
    verify_boot_transcript(boot2_transcript, BOOT2_PASS, 2)
    verify_boot_transcript(boot3_transcript, BOOT3_PASS, 3)
    require(g0_image != g1_image, "C7.6 boot 2 did not change the G0 disk")
    require(g1_image == final_image, "C7.6 boot 3 changed the committed G1 disk")
    g0 = verify_powered_off_image(g0_image, vectors_path, 1)
    g1 = verify_powered_off_image(g1_image, vectors_path, 2)
    require(
        g1["selected_checkpoint_generation"]
        == g0["selected_checkpoint_generation"] + 1
        and g1["admitted_segments"] == g0["admitted_segments"],
        "C7.6 replacement did not use exactly one checkpoint without further capacity growth",
    )
    return {
        "schema": "vibeos.c76.graph-version-replacement-verifier",
        "version": 1,
        "status": "ok",
        "storage": {
            "mode": g1["mode"],
            "policy_v3": True,
            "g0_checkpoint_generation": g0["selected_checkpoint_generation"],
            "g1_checkpoint_generation": g1["selected_checkpoint_generation"],
            "capacity_preparation_checkpoints": C76_CAPACITY_PREPARATION_CHECKPOINTS,
            "admitted_segments": g1["admitted_segments"],
            "boot2_changed_disk": True,
            "boot3_exact_no_write": True,
            "physical_bindings": g1["physical_bindings"],
            "external_roots": 0,
            "cas_orphans": 0,
        },
        "durable_graph": {
            "versions": 2,
            "replacements": 1,
            "component_artifacts": 6,
            "component_evidence": 6,
            "graph_evidence": 2,
            "graph_descriptors": 2,
            "retained_ungranted_attachments": 14,
            "live_root_generation": 1,
            "retirement_action": "PolicyCancel",
            "incident_edge_action": "RecreateFresh",
            "incident_edges": 2,
            "siblings_stable": 2,
            "mixed_versions": 0,
            "old_terminal_before_new_visible": True,
        },
        "boot_evidence": {
            "boots": 3,
            "fresh_graph_validations": 5,
            "image_candidate_uses": 2,
            "candidate_runtime_objects_before_durability": 0,
            "visibility": ["G0", "Transitioning", "G1"],
            "profile_stage": "validation_only",
            "profile_runtime_ready": False,
            "runtime_ready": False,
            "guest_calls": 0,
            "guest_execution": 0,
            "durable_grants": 0,
            "durable_invokes": 0,
            "no_grant_direct_move": True,
            "raw_ids": 0,
            "ambient_lookup": 0,
            "vsh": 0,
        },
        "guest_marker_is_storage_authority": False,
        "c78_independent_disk_scope": False,
    }


class LogicalBuilder:
    """Selftest-only encoder for the frozen 512-byte logical-record ABI."""

    def __init__(self) -> None:
        self.records: list[bytes] = []
        self.previous_sequence = 0
        self.previous_crc = 0

    def append(self, kind: int, payload: bytes, transaction: int = 0) -> Any:
        sequence = self.previous_sequence + 1
        raw = legacy.encode_record(
            kind,
            payload,
            sequence,
            self.previous_sequence,
            self.previous_crc,
            transaction,
        )
        record = legacy.decode_sector(raw, migration.M4_FIRST + len(self.records))
        require(record is not None, "C7.6 selftest encoder produced no record")
        self.records.append(raw)
        self.previous_sequence = sequence
        self.previous_crc = record.crc
        return record


def append_object(
    builder: LogicalBuilder, transaction: int, object_id: int, kind: int, content: bytes
) -> None:
    chunks = (len(content) + 359) // 360
    prepare_payload = bytearray(40)
    prepare_payload[:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<I", prepare_payload, 16, kind)
    struct.pack_into("<Q", prepare_payload, 24, len(content))
    struct.pack_into("<I", prepare_payload, 32, chunks)
    struct.pack_into("<I", prepare_payload, 36, legacy.crc32c(content))
    prepare = builder.append(legacy.OBJECT_PREPARE, bytes(prepare_payload), transaction)
    chunk_crcs = bytearray()
    first_sequence = 0
    for index in range(chunks):
        value = content[index * 360 : (index + 1) * 360]
        payload = bytearray(384)
        payload[:16] = object_id.to_bytes(16, "little")
        struct.pack_into("<I", payload, 16, index)
        struct.pack_into("<H", payload, 20, len(value))
        payload[24 : 24 + len(value)] = value
        record = builder.append(legacy.OBJECT_CHUNK, bytes(payload), transaction)
        if index == 0:
            first_sequence = record.sequence
        chunk_crcs.extend(struct.pack("<I", record.crc))
    payload = bytearray(48)
    payload[:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<Q", payload, 16, prepare.sequence)
    struct.pack_into("<I", payload, 24, prepare.crc)
    struct.pack_into("<I", payload, 28, chunks)
    struct.pack_into("<Q", payload, 32, first_sequence)
    struct.pack_into("<I", payload, 40, legacy.crc32c(bytes(chunk_crcs)))
    struct.pack_into("<I", payload, 44, legacy.crc32c(content))
    builder.append(legacy.OBJECT_COMMIT, bytes(payload), transaction)


def append_root(
    builder: LogicalBuilder, transaction: int, derivation: int,
    descriptor: int, generation: int, *, rights: int = READ
) -> None:
    payload = bytearray(88)
    payload[:16] = derivation.to_bytes(16, "little")
    payload[32:48] = descriptor.to_bytes(16, "little")
    payload[48:64] = GRAPH_SPACE.to_bytes(16, "little")
    struct.pack_into("<I", payload, 64, 0)
    struct.pack_into("<I", payload, 68, rights)
    struct.pack_into("<Q", payload, 72, generation)
    struct.pack_into("<I", payload, 80, STORED_OBJECT_RESOURCE_KIND)
    struct.pack_into("<I", payload, 84, ROOT_FLAG)
    prepare = builder.append(legacy.GRANT_PREPARE, bytes(payload), transaction)
    commit = bytearray(32)
    struct.pack_into("<Q", commit, 0, prepare.sequence)
    struct.pack_into("<I", commit, 8, prepare.crc)
    commit[16:32] = derivation.to_bytes(16, "little")
    builder.append(legacy.GRANT_COMMIT, bytes(commit), transaction)


def synthetic_vectors() -> dict[str, bytes]:
    key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    def evidence(magic: bytes, tag: int) -> bytes:
        # RFC 8032 test-vector signature material supplies canonical non-zero
        # fields; bundle semantics are deliberately disabled for this logical
        # record-layout selftest.
        signature = bytes([tag]) * 64
        return magic + struct.pack("<HHHH", 1, 112, 1, 0) + key + signature

    values = {"active_public_key": key}
    for generation in range(2):
        prefix = f"g{generation}"
        values[f"{prefix}_descriptor"] = f"descriptor-{generation}".encode()
        values[f"{prefix}_graph_evidence"] = evidence(b"VIBEGSG\0", 0x30 + generation)
        for index in range(3):
            middle = generation if index == 1 else 0
            values[f"{prefix}_artifact_{index}"] = (
                f"artifact-{index}-{middle}".encode() * (index + 1)
            )
            values[f"{prefix}_evidence_{index}"] = evidence(
                b"VIBESIG\0", 0x40 + index + middle
            )
    return values


def logical_fixture(
    vectors: dict[str, bytes],
    versions: int = 2,
    *,
    g0_kind: int = CMP1,
    g0_rights: int = READ,
    g1_generation: int = 1,
    tombstone_target_delta: int = 0,
    omit_tombstone: bool = False,
    final_high_water_delta: int = 0,
) -> bytes:
    builder = LogicalBuilder()
    builder.append(legacy.FORMAT, b"")
    builder.append(legacy.HIGH_WATER, (GRAPH_SPACE + 1).to_bytes(16, "little"))
    base0 = 1
    for index, (kind, content) in enumerate(version_values(vectors, 0)):
        append_object(
            builder,
            base0 + index * 2,
            base0 + index * 2 + 1,
            g0_kind if index == 0 else kind,
            content,
        )
    append_root(builder, base0 + 16, base0 + 17, base0 + 15, 0, rights=g0_rights)
    if versions == 1:
        return b"".join(builder.records)
    base1 = GRAPH_SPACE + 1
    builder.append(
        legacy.HIGH_WATER,
        (base1 + 19 + final_high_water_delta).to_bytes(16, "little"),
    )
    for index, (kind, content) in enumerate(version_values(vectors, 1)):
        append_object(
            builder,
            base1 + index * 2,
            base1 + index * 2 + 1,
            kind,
            content,
        )
    if not omit_tombstone:
        builder.append(
            legacy.TOMBSTONE,
            (base0 + 17 + tombstone_target_delta).to_bytes(16, "little"),
            base1 + 16,
        )
    append_root(
        builder, base1 + 17, base1 + 18, base1 + 15, g1_generation
    )
    return b"".join(builder.records)


def expect_rejected(action: Callable[[], None], label: str) -> None:
    try:
        action()
    except (
        VerificationError,
        ValueError,
        struct.error,
        c71.VerificationError,
        c73.VerificationError,
    ):
        return
    raise VerificationError(f"mutation unexpectedly accepted: {label}")


def selftest(vectors_path: Path) -> dict[str, Any]:
    vectors = synthetic_vectors()
    valid_g0 = logical_fixture(vectors, 1)
    valid_g1 = logical_fixture(vectors, 2)
    validate_exact_logical(valid_g0, vectors, 1, validate_bundle=False)
    validate_exact_logical(valid_g1, vectors, 2, validate_bundle=False)
    verify_boot_transcript(BOOT1_PASS, BOOT1_PASS, 1)
    verify_boot_transcript(BOOT2_PASS, BOOT2_PASS, 2)
    verify_boot_transcript(BOOT3_PASS, BOOT3_PASS, 3)
    cases = 5

    logical_invalid = [
        (logical_fixture(vectors, 2, g0_kind=CME1), "kind"),
        (logical_fixture(vectors, 2, g0_rights=READ | 0x10), "root-rights"),
        (logical_fixture(vectors, 2, g1_generation=0), "root-generation"),
        (logical_fixture(vectors, 2, tombstone_target_delta=1), "tombstone-target"),
        (logical_fixture(vectors, 2, omit_tombstone=True), "missing-tombstone"),
        (logical_fixture(vectors, 2, final_high_water_delta=1), "high-water"),
    ]
    for candidate, label in logical_invalid:
        expect_rejected(
            lambda value=candidate: validate_exact_logical(
                value, vectors, 2, validate_bundle=False
            ),
            label,
        )
        cases += 1
    mutated_vectors = dict(vectors)
    mutated_vectors["g1_artifact_1"] += b"mutation"
    expect_rejected(
        lambda: validate_exact_logical(
            valid_g1, mutated_vectors, 2, validate_bundle=False
        ),
        "exact-vector-bytes",
    )
    cases += 1

    canonical = bytearray(
        migration.canonical_empty_authority_payload(
            2, authority_policy=PHYSICAL_AUTHORITY_POLICY
        )
    )
    policy_v2 = (
        b"vibeos.storage-v2.external-policy.v2\0"
        b"persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0"
        b"program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0"
        b"component-space=0x564942454f532d434f4d504f4e454e54,slot=0,generation=0,rights=r,kind=0x434d5031\0"
        b"component-evidence=exact-root-relative,kind=0x434d4531,len=112,inline=1,ungranted=1\0"
        b"sealed-singleton-optional=0x53534801"
    )
    canonical[0x18:0x38] = hashlib.sha256(policy_v2).digest()
    expect_rejected(
        lambda: migration.parse_authority_snapshot(
            bytes(canonical),
            2,
            authority_policy=PHYSICAL_AUTHORITY_POLICY,
        ),
        "policy-v2-as-v3",
    )
    cases += 1

    transcript_invalid = [
        (BOOT1_PASS + "\n" + BOOT1_PASS, BOOT1_PASS, 1, "duplicate"),
        (BOOT2_PASS + "\n" + FAIL_MARKER, BOOT2_PASS, 2, "fail-after-pass"),
        (BOOT3_PASS + " extra=1", BOOT3_PASS, 3, "unknown-field"),
        (
            BOOT2_PASS.replace("mixed_versions=0", "mixed_versions=1"),
            BOOT2_PASS,
            2,
            "mixed-version",
        ),
        (
            BOOT2_PASS.replace("policy_cancel=1", "policy_cancel=0"),
            BOOT2_PASS,
            2,
            "missing-policy-cancel",
        ),
        (
            BOOT2_PASS.replace(
                "old_terminal_before_new_visible=1",
                "old_terminal_before_new_visible=0",
            ),
            BOOT2_PASS,
            2,
            "early-visible",
        ),
        (BOOT3_PASS.replace("no_write=1", "no_write=0"), BOOT3_PASS, 3, "write"),
        (BOOT1_PASS + " ObjectId=1", BOOT1_PASS, 1, "identity"),
        (BOOT3_PASS + "\npanicked at synthetic fault", BOOT3_PASS, 3, "panic"),
    ]
    for raw, expected, boot, label in transcript_invalid:
        expect_rejected(
            lambda value=raw, marker=expected, number=boot: verify_boot_transcript(
                value, marker, number
            ),
            label,
        )
        cases += 1

    # When the checked-in fixture has been populated, exercise its complete
    # independent CGV1/CMP1/evidence cross-check during --selftest too.  The
    # one-line placeholder used while generating vectors is not blessed.
    lines = vectors_path.read_text(encoding="ascii").splitlines()
    if len(lines) > 1:
        checked_vectors = load_vectors(vectors_path)
        validate_vectors(checked_vectors)
        validate_exact_logical(
            logical_fixture(checked_vectors, 1), checked_vectors, 1
        )
        validate_exact_logical(
            logical_fixture(checked_vectors, 2), checked_vectors, 2
        )
        cases += 3

        evidence_names = [
            f"{generation}_evidence_{index}"
            for generation in ("g0", "g1")
            for index in range(3)
        ] + ["g0_graph_evidence", "g1_graph_evidence"]
        for name in evidence_names:
            signature_mutation = dict(checked_vectors)
            encoded = bytearray(signature_mutation[name])
            # Change the low byte of S so the encoded point and canonical-S
            # checks still pass and rejection exercises Ed25519 verification.
            encoded[80] ^= 1
            signature_mutation[name] = bytes(encoded)
            expect_rejected(
                lambda candidate=signature_mutation: validate_vectors(candidate),
                f"{name}-ed25519-signature",
            )
            cases += 1

        # Model the old self-referential trust-root failure: an attacker edits
        # the advertised key and coordinates every evidence key/signature with
        # it.  Use only already-public canonical evidence, never a seed or a
        # signing implementation.  The hand-written C7.6 root must reject the
        # substitution before vector-controlled provenance is considered.
        c73_vectors = c73.load_vectors(c73.DEFAULT_VECTORS)
        alternate = c73.decode_evidence(c73_vectors["unknown_signer_evidence"])
        coordinated = dict(checked_vectors)
        coordinated["active_public_key"] = alternate.key
        for name in evidence_names:
            encoded = bytearray(coordinated[name])
            encoded[16:48] = alternate.key
            encoded[48:112] = alternate.signature
            coordinated[name] = bytes(encoded)
        require(
            all(coordinated[name][16:48] == alternate.key for name in evidence_names),
            "coordinated signer substitution selftest is incomplete",
        )
        expect_rejected(
            lambda: validate_vectors(coordinated),
            "coordinated-key-and-evidence-resign-substitution",
        )
        cases += 1
    return {
        "schema": "vibeos.c76.graph-version-replacement-selftest",
        "version": 1,
        "status": "ok",
        "cases": cases,
        "c78_independent_disk_scope": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, help="post-boot-3 final G1 image")
    parser.add_argument("--g0-image", type=Path, help="powered-off post-boot-1 G0 snapshot")
    parser.add_argument("--g1-image", type=Path, help="powered-off post-boot-2 G1 snapshot")
    parser.add_argument("--boot1-log", type=Path)
    parser.add_argument("--boot2-log", type=Path)
    parser.add_argument("--boot3-log", type=Path)
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    evidence_args = (
        args.image,
        args.g0_image,
        args.g1_image,
        args.boot1_log,
        args.boot2_log,
        args.boot3_log,
    )
    if any(value is not None for value in evidence_args) and not all(
        value is not None for value in evidence_args
    ):
        parser.error(
            "image, --g0-image, --g1-image, and all three boot logs are required together"
        )
    if not args.selftest and args.image is None:
        parser.error("provide three-boot powered-off evidence and/or --selftest")
    try:
        outputs = []
        if args.selftest:
            outputs.append(selftest(args.vectors))
        if args.image is not None:
            assert args.g0_image is not None and args.g1_image is not None
            assert args.boot1_log is not None and args.boot2_log is not None
            assert args.boot3_log is not None
            outputs.append(
                verify_evidence(
                    args.g0_image.read_bytes(),
                    args.g1_image.read_bytes(),
                    args.image.read_bytes(),
                    args.vectors,
                    args.boot1_log.read_text(encoding="utf-8", errors="replace"),
                    args.boot2_log.read_text(encoding="utf-8", errors="replace"),
                    args.boot3_log.read_text(encoding="utf-8", errors="replace"),
                )
            )
        for output in outputs:
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    except (
        OSError,
        UnicodeError,
        ValueError,
        struct.error,
        c71.VerificationError,
        c73.VerificationError,
        migration.Violation,
    ) as error:
        print(f"FAIL verify-c76-graph-version-replacement: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
