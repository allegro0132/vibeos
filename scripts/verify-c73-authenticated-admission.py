#!/usr/bin/env python3
"""Independent C7.3 authenticated-admission and target-report verifier.

This verifier uses only Python's standard library. It neither imports nor
executes production Rust. The small Edwards25519 implementation is scoped to
strictly verifying the fixed C7.3 Ed25519 evidence profile and to maintaining
public acceptance vectors; it is not a general-purpose cryptography API.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


POLICY_DOMAIN = b"vibeos.component-artifact.operator-policy.v1\0"
OPERATOR_ROLE_DOMAIN = b"vibeos.c73.acceptance.operator-role.v1\0"
DEVELOPMENT_POLICY_DOMAIN = b"vibeos.c73.acceptance.development-image-policy.v1\0"
SIGNATURE_DOMAIN = b"vibeos.component-artifact.operator-admission.v1\0"
ARTIFACT_COMMITMENT_DOMAIN = b"vibeos.component-artifact.commitment.v1\0"
VECTOR_MAGIC = "VIBEOS-C73-AUTHENTICATED-ADMISSION-V1"
EVIDENCE_MAGIC = b"VIBESIG\0"
EVIDENCE_LEN = 112
TRANSCRIPT_LEN = 192
ARTIFACT_HEADER_LEN = 352
ARTIFACT_COMMITMENT_OFFSET = 264
ARTIFACT_POLICY_OFFSET = 232
# The repository's deterministic SSH host-signer test fixture uses RFC 8032
# vector 1. It remains useful for checking this verifier's arithmetic, but it
# is explicitly forbidden from every C7.3 operator role.
SSH_TEST_SIGNER_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

PASS = (
    "WASM_C73_AUTHENTICATED_ADMISSION PASS development_accepted=1 "
    "operator_p1_accepted=2 operator_p2_accepted=1 wrong_signer_rejected=1 "
    "unknown_signer_rejected=1 revoked_signer_rejected=1 old_policy_rejected=1 "
    "artifact_mutations_rejected=2 module_mutations_rejected=2 "
    "wit_mutations_rejected=2 adapter_mutations_rejected=2 "
    "limit_mutations_rejected=2 profile_mutations_rejected=2 "
    "signature_replays_rejected=2 content_hash_only_rejected=1 "
    "runtime_unavailable=4 runtime_ready=0 guest_calls=0 raw_ids=0"
)
FAIL = "WASM_C73_AUTHENTICATED_ADMISSION FAIL"

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VECTORS = ROOT / "policy/image/artifacts/c73-authenticated-admission.vectors"


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


# Minimal RFC 8032 Edwards25519 arithmetic. Points are affine (x, y), encoded
# canonically as little-endian y with the x parity bit in bit 255.
FIELD = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, FIELD - 2, FIELD)) % FIELD
SQRT_M1 = pow(2, (FIELD - 1) // 4, FIELD)
IDENTITY = (0, 1)
BASE_Y = (4 * pow(5, FIELD - 2, FIELD)) % FIELD


def recover_x(y: int, sign: int) -> int:
    xx = ((y * y - 1) * pow(CURVE_D * y * y + 1, FIELD - 2, FIELD)) % FIELD
    x = pow(xx, (FIELD + 3) // 8, FIELD)
    if (x * x - xx) % FIELD != 0:
        x = (x * SQRT_M1) % FIELD
    require((x * x - xx) % FIELD == 0, "point is not on Edwards25519")
    if (x & 1) != sign:
        x = FIELD - x
    require(not (x == 0 and sign == 1), "non-canonical x sign bit")
    return x


BASE = (recover_x(BASE_Y, 0), BASE_Y)


def point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = (CURVE_D * x1 * x2 * y1 * y2) % FIELD
    x3 = ((x1 * y2 + y1 * x2) * pow(1 + product, FIELD - 2, FIELD)) % FIELD
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - product, FIELD - 2, FIELD)) % FIELD
    return x3, y3


def scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def decode_point(encoded: bytes) -> tuple[int, int]:
    require(len(encoded) == 32, "Ed25519 point length differs")
    raw = int.from_bytes(encoded, "little")
    y = raw & ((1 << 255) - 1)
    require(y < FIELD, "non-canonical Edwards25519 y coordinate")
    point = (recover_x(y, raw >> 255), y)
    require(encode_point(point) == encoded, "non-canonical point encoding")
    return point


def strict_point(encoded: bytes, label: str) -> tuple[int, int]:
    point = decode_point(encoded)
    require(point != IDENTITY, f"{label} is the identity")
    require(scalar_mult(point, 8) != IDENTITY, f"{label} has small order")
    require(scalar_mult(point, ORDER) == IDENTITY, f"{label} is outside the prime subgroup")
    return point


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        require(len(public_key) == 32, "Ed25519 public key length differs")
        require(len(signature) == 64, "Ed25519 signature length differs")
        encoded_r, encoded_s = signature[:32], signature[32:]
        scalar_s = int.from_bytes(encoded_s, "little")
        require(scalar_s < ORDER, "Ed25519 S is non-canonical")
        public = strict_point(public_key, "public key")
        point_r = strict_point(encoded_r, "signature R")
        challenge = int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(), "little"
        ) % ORDER
        require(
            scalar_mult(BASE, scalar_s) == point_add(point_r, scalar_mult(public, challenge)),
            "Ed25519 equation differs",
        )
        return True
    except VerificationError:
        return False


def ed25519_sign_for_vector(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Maintain public acceptance vectors from deterministic test seeds."""
    require(len(seed) == 32, "acceptance seed length differs")
    expanded = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(
        bytes([expanded[0] & 248]) + expanded[1:31] + bytes([(expanded[31] & 63) | 64]),
        "little",
    )
    prefix = expanded[32:]
    public_key = encode_point(scalar_mult(BASE, scalar))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % ORDER
    encoded_r = encode_point(scalar_mult(BASE, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % ORDER
    signature = encoded_r + ((nonce + challenge * scalar) % ORDER).to_bytes(32, "little")
    require(ed25519_verify(public_key, message, signature), "maintained vector did not verify")
    return public_key, signature


@dataclass(frozen=True)
class Evidence:
    key: bytes
    signature: bytes


def encode_evidence(key: bytes, signature: bytes) -> bytes:
    require(len(key) == 32 and len(signature) == 64, "evidence input length differs")
    return EVIDENCE_MAGIC + struct.pack("<HHHH", 1, EVIDENCE_LEN, 1, 0) + key + signature


def decode_evidence(encoded: bytes) -> Evidence:
    require(len(encoded) == EVIDENCE_LEN, "authentication evidence length differs")
    require(encoded[:8] == EVIDENCE_MAGIC, "authentication evidence magic differs")
    require(struct.unpack_from("<H", encoded, 8)[0] == 1, "evidence version differs")
    require(struct.unpack_from("<H", encoded, 10)[0] == EVIDENCE_LEN, "evidence encoded length differs")
    require(struct.unpack_from("<H", encoded, 12)[0] == 1, "evidence algorithm differs")
    require(struct.unpack_from("<H", encoded, 14)[0] == 0, "evidence flags are non-zero")
    return Evidence(encoded[16:48], encoded[48:112])


def artifact_commitment(artifact: bytes) -> bytes:
    require(len(artifact) >= ARTIFACT_HEADER_LEN, "artifact is truncated")
    require(artifact[:8] == b"VIBECMP\0", "artifact magic differs")
    require(struct.unpack_from("<H", artifact, 8)[0] == 1, "artifact format differs")
    require(struct.unpack_from("<H", artifact, 10)[0] == ARTIFACT_HEADER_LEN, "artifact header differs")
    require(struct.unpack_from("<Q", artifact, 72)[0] == len(artifact), "artifact total length differs")
    observed = sha256(
        ARTIFACT_COMMITMENT_DOMAIN,
        struct.pack("<Q", len(artifact)),
        artifact[:ARTIFACT_COMMITMENT_OFFSET],
        bytes(32),
        artifact[ARTIFACT_COMMITMENT_OFFSET + 32 :],
    )
    require(
        artifact[ARTIFACT_COMMITMENT_OFFSET : ARTIFACT_COMMITMENT_OFFSET + 32] == observed,
        "artifact commitment differs",
    )
    return observed


def artifact_component_bytes(artifact: bytes) -> bytes:
    artifact_commitment(artifact)
    contract_len = struct.unpack_from("<Q", artifact, 48)[0]
    manifest_len = struct.unpack_from("<Q", artifact, 56)[0]
    component_len = struct.unpack_from("<Q", artifact, 64)[0]
    start = ARTIFACT_HEADER_LEN + contract_len + manifest_len
    end = start + component_len
    require(end == len(artifact), "artifact section lengths do not end at total length")
    require(component_len != 0, "artifact component payload is empty")
    return artifact[start:end]


class Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        end = self.offset + length
        require(end <= len(self.data), "policy stream is truncated")
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

    def text(self) -> str:
        raw = self.take(self.u32())
        require(raw and b"\0" not in raw, "policy text is empty or contains NUL")
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError("policy text is not UTF-8") from error
        require(value.encode("utf-8") == raw, "policy text encoding is non-canonical")
        return value


@dataclass(frozen=True)
class Policy:
    generation: int
    role: bytes
    signers: tuple[tuple[bytes, int], ...]
    profile: tuple[int, int, int, int, int, int]
    revisions: tuple[str, str, str, str, str]
    command: str
    entrypoint: str
    arguments: tuple[int, int]
    world: str
    world_shape: bytes
    limits: tuple[int, int, int, int]
    streams: tuple[int, int, int]
    ceilings: tuple[tuple[str, str, int, int], ...]
    exact_wit: bytes


def parse_value(cursor: Cursor, budget: list[int]) -> None:
    budget[0] += 1
    require(budget[0] <= 4096, "policy shape budget exceeded")
    tag = cursor.u8()
    require(tag <= 22, "unknown value-shape tag")
    if tag in (11, 16):  # list, option
        parse_value(cursor, budget)
    elif tag == 12:  # tuple
        for _ in range(cursor.u32()):
            parse_value(cursor, budget)
    elif tag == 13:  # record
        for _ in range(cursor.u32()):
            cursor.text()
            parse_value(cursor, budget)
    elif tag in (14, 15):  # flags, enum
        for _ in range(cursor.u32()):
            cursor.text()
    elif tag == 17:  # result
        for _ in range(2):
            present = cursor.u8()
            require(present in (0, 1), "invalid result option tag")
            if present:
                parse_value(cursor, budget)
    elif tag == 18:  # variant
        for _ in range(cursor.u32()):
            cursor.text()
            present = cursor.u8()
            require(present in (0, 1), "invalid variant option tag")
            if present:
                parse_value(cursor, budget)
    elif tag in (19, 20):  # future, stream
        present = cursor.u8()
        require(present in (0, 1), "invalid async option tag")
        if present:
            parse_value(cursor, budget)
    elif tag in (21, 22):  # own, borrow nominal diagnostic name
        cursor.text()


def parse_entity(cursor: Cursor, budget: list[int]) -> None:
    tag = cursor.u8()
    require(tag <= 2, "unknown entity-shape tag")
    if tag == 0:  # function
        require(cursor.u8() in (0, 1), "invalid function effect")
        for _ in range(cursor.u32()):
            cursor.text()
            parse_value(cursor, budget)
        present = cursor.u8()
        require(present in (0, 1), "invalid function result option")
        if present:
            parse_value(cursor, budget)
    elif tag == 1:  # interface
        parse_named_entities(cursor, budget)
    elif tag == 2:  # type, followed by Resource=0 / Value=1
        subtype = cursor.u8()
        require(subtype in (0, 1), "unknown type-entity subtype")
        if subtype == 1:
            parse_value(cursor, budget)


def parse_named_entities(cursor: Cursor, budget: list[int]) -> None:
    previous = None
    for _ in range(cursor.u32()):
        name = cursor.text()
        require(previous is None or previous < name, "named entities are not canonical")
        previous = name
        parse_entity(cursor, budget)


def parse_policy(encoded: bytes) -> Policy:
    cursor = Cursor(encoded)
    require(cursor.u16() == 1, "operator policy version differs")
    generation = cursor.u64()
    require(generation != 0, "operator policy generation is zero")
    role = cursor.take(32)
    require(any(role), "operator role identity is zero")
    signers = []
    for _ in range(cursor.u16()):
        key = cursor.take(32)
        status = cursor.u8()
        require(status in (1, 2), "operator signer status differs")
        signers.append((key, status))
    require(signers and signers == sorted(signers), "operator signers are empty or non-canonical")
    require(len({key for key, _ in signers}) == len(signers), "duplicate operator signer")
    require(cursor.u8() == 2, "operator trust mode differs")
    profile = (
        cursor.u16(),
        cursor.u16(),
        cursor.u16(),
        cursor.u16(),
        cursor.u64(),
        cursor.u16(),
    )
    require(profile[-1] in (1, 2), "profile stage differs")
    revisions = tuple(cursor.text() for _ in range(5))
    command = cursor.text()
    entrypoint = cursor.text()
    arguments = (cursor.u64(), cursor.u64())
    world = cursor.text()
    budget = [0]
    world_shape_start = cursor.offset
    parse_named_entities(cursor, budget)
    parse_named_entities(cursor, budget)
    world_shape = encoded[world_shape_start : cursor.offset]
    memory = cursor.u64()
    fuel = cursor.u64()
    quantum = cursor.u64()
    resources = cursor.u16()
    require(memory and fuel and quantum and resources, "zero admission limit")
    require(quantum <= fuel, "poll quantum exceeds fuel")
    streams = (cursor.u8(), cursor.u8(), cursor.u8())
    require(all(mode in (1, 2, 3) for mode in streams), "stream mode differs")
    previous_ceiling = None
    ceilings = []
    for _ in range(cursor.u16()):
        label = cursor.text()
        interface = cursor.text()
        kind = cursor.u8()
        rights = cursor.u32()
        ceiling = (label, interface, kind, rights)
        require(previous_ceiling is None or previous_ceiling < ceiling, "ceilings are non-canonical")
        require(1 <= kind <= 6 and rights != 0, "invalid interface ceiling")
        previous_ceiling = ceiling
        ceilings.append(ceiling)
    exact_wit = cursor.take(cursor.u64())
    require(exact_wit, "exact WIT source is empty")
    try:
        exact_wit_text = exact_wit.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("exact WIT source is not UTF-8") from error
    require(exact_wit_text.encode("utf-8") == exact_wit, "exact WIT encoding is non-canonical")
    require(cursor.offset == len(encoded), "operator policy has trailing bytes")
    return Policy(
        generation,
        role,
        tuple(signers),
        profile,
        revisions,
        command,
        entrypoint,
        arguments,
        world,
        world_shape,
        (memory, fuel, quantum, resources),
        streams,
        tuple(ceilings),
        exact_wit,
    )


def policy_commitment(policy: bytes) -> bytes:
    parse_policy(policy)
    return sha256(POLICY_DOMAIN, policy)


def signature_transcript(artifact: bytes, policy: bytes, signer: bytes) -> bytes:
    parsed_policy = parse_policy(policy)
    commitment = policy_commitment(policy)
    require(artifact[28:30] == struct.pack("<H", 2), "artifact is not operator-required")
    require(artifact[30:32] == struct.pack("<H", 1), "artifact signer-policy version differs")
    require(artifact[ARTIFACT_POLICY_OFFSET:ARTIFACT_POLICY_OFFSET + 32] == commitment, "artifact policy commitment differs")
    result = bytearray(TRANSCRIPT_LEN)
    result[:48] = SIGNATURE_DOMAIN
    struct.pack_into("<HHHHHHHHHH", result, 48, 1, 1, 1, 1, 1, 1,
                     struct.unpack_from("<H", artifact, 32)[0],
                     struct.unpack_from("<H", artifact, 34)[0],
                     struct.unpack_from("<H", artifact, 36)[0],
                     struct.unpack_from("<H", artifact, 38)[0])
    struct.pack_into("<H", result, 68, struct.unpack_from("<H", artifact, 24)[0])
    # offset 70 is reserved zero
    struct.pack_into("<Q", result, 72, struct.unpack_from("<Q", artifact, 40)[0])
    struct.pack_into("<Q", result, 80, len(artifact))
    result[88:120] = artifact_commitment(artifact)
    result[120:152] = commitment
    result[152:184] = signer
    struct.pack_into("<Q", result, 184, parsed_policy.generation)
    return bytes(result)


def authenticate(artifact: bytes, policy: bytes, encoded_evidence: bytes) -> None:
    evidence = decode_evidence(encoded_evidence)
    parsed_policy = parse_policy(policy)
    statuses = [status for key, status in parsed_policy.signers if key == evidence.key]
    require(len(statuses) == 1, "operator signer is unknown")
    require(statuses[0] == 1, "operator signer is revoked")
    transcript = signature_transcript(artifact, policy, evidence.key)
    require(ed25519_verify(evidence.key, transcript, evidence.signature), "operator signature differs")


def load_vectors(path: Path) -> dict[str, bytes]:
    lines = path.read_text(encoding="ascii").splitlines()
    require(lines and lines[0] == VECTOR_MAGIC, "C7.3 vector magic differs")
    values: dict[str, bytes] = {}
    for line in lines[1:]:
        require(line and "=" in line, "malformed C7.3 vector line")
        name, raw = line.split("=", 1)
        require(re.fullmatch(r"[a-z0-9_]+", name) is not None, "invalid vector name")
        require(name not in values, "duplicate vector name")
        require(len(raw) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", raw) is not None, "invalid vector hex")
        values[name] = bytes.fromhex(raw)
    return values


def expect_rejected(action, label: str) -> None:
    try:
        action()
    except VerificationError:
        return
    raise VerificationError(f"mutation unexpectedly accepted: {label}")


def verify_vectors(path: Path) -> None:
    vectors = load_vectors(path)
    required = {
        "policy_p1", "policy_p2", "development_artifact",
        "operator_a_p1_artifact", "operator_a_p1_evidence",
        "operator_b_p1_artifact", "operator_b_p1_evidence",
        "operator_a_p2_artifact", "operator_a_p2_evidence",
        "wrong_signer_evidence", "unknown_signer_evidence", "revoked_signer_evidence",
        "content_hash_only_evidence",
    }
    for name in ("artifact", "module", "wit", "adapter", "limit", "profile"):
        required.update({f"mutation_{name}_artifact", f"mutation_{name}_evidence"})
    require(set(vectors) == required, "C7.3 vector field set differs")

    p1, p2 = vectors["policy_p1"], vectors["policy_p2"]
    parsed_p1, parsed_p2 = parse_policy(p1), parse_policy(p2)
    require((parsed_p1.generation, parsed_p2.generation) == (1, 2), "rotation generations differ")
    require(parsed_p1.role == parsed_p2.role and parsed_p1.signers == parsed_p2.signers, "rotation changed unrelated policy")
    require(parsed_p1.role == sha256(OPERATOR_ROLE_DOMAIN), "operator role identity differs")
    def framed_text(value: str) -> bytes:
        encoded = value.encode("utf-8")
        return struct.pack("<I", len(encoded)) + encoded

    expected_world_shape = (
        struct.pack("<I", 0)
        + struct.pack("<I", 1)
        + framed_text("run")
        + bytes((0, 0))
        + struct.pack("<I", 1)
        + framed_text("input")
        + bytes((11, 1, 1, 11, 1))
    )
    expected_configuration = (
        (1, 1, 1, 1, 7, 1),
        (
            "webassembly-core-2.0-integer-v1",
            "wasmparser-component-model-0.255.0",
            "component-model-0.255.0-sync",
            "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380",
            "wasi-not-selected-sync",
        ),
        "c73-filter",
        "run",
        (0, 0),
        "vibe:bytes/filter@1.0.0",
        expected_world_shape,
        (512 * 1024, 100_000, 100, 4),
        (1, 1, 2),
        (),
    )
    for parsed in (parsed_p1, parsed_p2):
        require(
            (
                parsed.profile,
                parsed.revisions,
                parsed.command,
                parsed.entrypoint,
                parsed.arguments,
                parsed.world,
                parsed.world_shape,
                parsed.limits,
                parsed.streams,
                parsed.ceilings,
            )
            == expected_configuration,
            "operator policy configuration differs",
        )
    require(parsed_p1.exact_wit == parsed_p2.exact_wit, "rotation changed exact WIT source")
    require(
        parsed_p1.exact_wit == (ROOT / "policy/image/artifacts/c73-byte-filter.wit").read_bytes(),
        "operator policy does not bind the checked-in exact WIT bytes",
    )
    require(policy_commitment(p1) != policy_commitment(p2), "rotation did not change commitment")

    development = vectors["development_artifact"]
    artifact_commitment(development)
    require(struct.unpack_from("<H", development, 28)[0] == 1, "development artifact kind differs")
    expected_development_policy = sha256(
        DEVELOPMENT_POLICY_DOMAIN,
        struct.pack("<Q", len(parsed_p1.exact_wit)),
        parsed_p1.exact_wit,
    )
    require(
        development[ARTIFACT_POLICY_OFFSET : ARTIFACT_POLICY_OFFSET + 32]
        == expected_development_policy,
        "development signer-policy digest is not independently image-pinned",
    )
    require(
        artifact_component_bytes(development)
        == artifact_component_bytes(vectors["operator_a_p1_artifact"]),
        "development and operator-A artifacts do not pin the same exact Component bytes",
    )
    expect_rejected(
        lambda: authenticate(development, p1, vectors["operator_a_p1_evidence"]),
        "development-as-operator",
    )

    for prefix, policy in [
        ("operator_a_p1", p1),
        ("operator_b_p1", p1),
        ("operator_a_p2", p2),
    ]:
        authenticate(vectors[f"{prefix}_artifact"], policy, vectors[f"{prefix}_evidence"])
    require(vectors["operator_a_p1_artifact"] != vectors["operator_b_p1_artifact"], "two deployable artifacts alias")
    require(
        artifact_component_bytes(vectors["operator_a_p1_artifact"])
        == artifact_component_bytes(vectors["operator_a_p2_artifact"]),
        "policy rotation changed operator-A Component bytes",
    )
    require(
        artifact_component_bytes(vectors["operator_a_p1_artifact"])
        != artifact_component_bytes(vectors["operator_b_p1_artifact"]),
        "two operator artifacts do not contain distinct Component payloads",
    )

    baseline_artifact = vectors["operator_a_p1_artifact"]
    wrong = decode_evidence(vectors["wrong_signer_evidence"])
    unknown = decode_evidence(vectors["unknown_signer_evidence"])
    revoked = decode_evidence(vectors["revoked_signer_evidence"])
    baseline_key = decode_evidence(vectors["operator_a_p1_evidence"]).key
    require(
        baseline_key.hex()
        == "8d178a30c5be443f7e948f4ddfcec37561e885b7de631add2b63502f754cf187",
        "active signer is not the C7.3-only operator key",
    )
    require(
        revoked.key.hex()
        == "ea4c611e9361cd8ead0f533f825769cbbc7ebedaf1c38e649fe7892f4d29e1ac",
        "revoked signer is not the C7.3-only operator key",
    )
    require(
        unknown.key.hex()
        == "f9e108c9be890b59e403c526baffa1dd2b965dc280b733022566054a9161df25",
        "unknown signer is not the C7.3-only adjacent key",
    )
    require(
        len({baseline_key, revoked.key, unknown.key}) == 3,
        "C7.3 active, revoked, and unknown operator keys alias",
    )
    require(
        SSH_TEST_SIGNER_PUBLIC_KEY not in {baseline_key, revoked.key, unknown.key},
        "C7.3 operator role reused the SSH test signer",
    )
    require((baseline_key, 1) in parsed_p1.signers, "active signer is absent from policy")
    require((revoked.key, 2) in parsed_p1.signers, "revoked signer state differs")
    require(unknown.key not in {key for key, _ in parsed_p1.signers}, "unknown signer is configured")
    require(wrong.key == baseline_key, "wrong-signature fixture does not claim the active signer")
    require(
        ed25519_verify(
            unknown.key,
            signature_transcript(baseline_artifact, p1, wrong.key),
            wrong.signature,
        ),
        "wrong-signer fixture is not a valid adjacent-key signature",
    )
    require(
        ed25519_verify(
            unknown.key,
            signature_transcript(baseline_artifact, p1, unknown.key),
            unknown.signature,
        ),
        "unknown-signer fixture is not cryptographically valid",
    )
    require(
        ed25519_verify(
            revoked.key,
            signature_transcript(baseline_artifact, p1, revoked.key),
            revoked.signature,
        ),
        "revoked-signer fixture is not cryptographically valid",
    )

    expect_rejected(
        lambda: authenticate(vectors["operator_a_p1_artifact"], p1, vectors["wrong_signer_evidence"]),
        "wrong-signer",
    )
    expect_rejected(
        lambda: authenticate(vectors["operator_a_p1_artifact"], p1, vectors["unknown_signer_evidence"]),
        "unknown-signer",
    )
    expect_rejected(
        lambda: authenticate(vectors["operator_a_p1_artifact"], p1, vectors["revoked_signer_evidence"]),
        "revoked-signer",
    )
    expect_rejected(
        lambda: authenticate(vectors["operator_b_p1_artifact"], p1, vectors["operator_a_p1_evidence"]),
        "artifact-replay",
    )
    expect_rejected(
        lambda: authenticate(vectors["operator_a_p2_artifact"], p2, vectors["operator_a_p1_evidence"]),
        "policy-replay",
    )
    expect_rejected(
        lambda: authenticate(vectors["operator_a_p1_artifact"], p2, vectors["operator_a_p1_evidence"]),
        "old-policy-after-rotation",
    )

    baseline_evidence = vectors["operator_a_p1_evidence"]
    for name in ("artifact", "module", "wit", "adapter", "limit", "profile"):
        artifact = vectors[f"mutation_{name}_artifact"]
        evidence = vectors[f"mutation_{name}_evidence"]
        require(artifact != vectors["operator_a_p1_artifact"], f"{name} mutation did not alter artifact")
        expect_rejected(lambda a=artifact: authenticate(a, p1, baseline_evidence), f"stale-{name}")
        # The active signer really signed the mutation. Production semantic
        # admission must still reject it at the named fresh-validation gate.
        authenticate(artifact, p1, evidence)

    hash_only = decode_evidence(vectors["content_hash_only_evidence"])
    require(hash_only.key == decode_evidence(baseline_evidence).key, "hash-only signer key differs")
    require(
        hash_only.signature == sha256(vectors["operator_a_p1_artifact"]) * 2,
        "hash-only fixture is not exactly the repeated raw content hash",
    )
    expect_rejected(
        lambda: authenticate(
            vectors["operator_a_p1_artifact"], p1, vectors["content_hash_only_evidence"]
        ),
        "content-hash-only",
    )


def normalize_lines(raw: str) -> list[str]:
    return [line for line in raw.replace("\r", "\n").splitlines() if line]


def verify_qemu_transcript(raw: str) -> None:
    lines = normalize_lines(raw)
    c73 = [line for line in lines if line.startswith("WASM_C73_AUTHENTICATED_ADMISSION")]
    require(c73 == [PASS], "C7.3 target report is missing, duplicated, reordered, or unknown")
    require(FAIL not in lines, "C7.3 guest reported failure")
    require(not any(re.search(r"\[!\] (fatal|panic)|panicked at", line) for line in lines), "guest panic/fatal output")
    forbidden = ("ObjectId", "SpaceId", "DerivationId", "Cap {", "slot=", "generation=", "0x", "public_key=", "signature=", "digest=", "sha256=")
    require(not any(token in c73[0] for token in forbidden), "C7.3 report leaks forbidden identity material")


def selftest(vectors: Path) -> None:
    # RFC 8032 test vector 1: empty message.
    public = SSH_TEST_SIGNER_PUBLIC_KEY
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    require(ed25519_verify(public, b"", signature), "RFC 8032 vector was rejected")
    changed = bytearray(signature)
    changed[0] ^= 1
    require(not ed25519_verify(public, b"", bytes(changed)), "mutated RFC signature accepted")
    require(not ed25519_verify(bytes(32), b"", signature), "weak public key accepted")
    for encoded in (bytes((2, 0)), bytes((2, 1, 1))):
        cursor = Cursor(encoded)
        parse_entity(cursor, [0])
        require(cursor.offset == len(encoded), "type-entity parser did not consume its exact shape")
    for encoded in (bytes((2, 2)), bytes((3,))):
        expect_rejected(lambda value=encoded: parse_entity(Cursor(value), [0]), "type-entity-tag")
    verify_vectors(vectors)
    verify_qemu_transcript(PASS)
    for label, raw in [
        ("duplicate", PASS + "\n" + PASS),
        ("fail", PASS + "\n" + FAIL),
        ("unknown-field", PASS + " extra=1"),
        ("panic", PASS + "\npanicked at synthetic C7.3 fault"),
    ]:
        expect_rejected(lambda value=raw: verify_qemu_transcript(value), label)


def emit_vectors(directory: Path) -> None:
    """Emit checked-in public vectors from build-generated unsigned inputs."""
    seeds = {
        "active": bytes.fromhex("20c484cd660dbe4fdcac63f8126a5b70fbeec38a6a37c9a8be0670592036bd75"),
        "revoked": bytes.fromhex("c278fee12fde9294f67d9e818cb04864c4d5079cf27a27c750163d1dcbb52527"),
        "unknown": bytes.fromhex("97d2a95e414d8b9374c419d8ce6b2699b132b4fba9ab0f8956feef7f8ee70d85"),
    }

    def read(name: str, suffix: str) -> bytes:
        return (directory / f"c73-{name}.{suffix}").read_bytes()

    fields: list[tuple[str, bytes]] = [
        ("policy_p1", read("policy-p1", "bin")),
        ("policy_p2", read("policy-p2", "bin")),
        ("development_artifact", read("development", "artifact")),
    ]
    for name in ("operator-a-p1", "operator-b-p1", "operator-a-p2"):
        transcript = read(name, "transcript")
        key, signature = ed25519_sign_for_vector(seeds["active"], transcript)
        fields.extend([
            (name.replace("-", "_") + "_artifact", read(name, "artifact")),
            (name.replace("-", "_") + "_evidence", encode_evidence(key, signature)),
        ])
    for name in ("artifact", "module", "wit", "adapter", "limit", "profile"):
        source = "mutation-" + name
        transcript = read(source, "transcript")
        key, signature = ed25519_sign_for_vector(seeds["active"], transcript)
        fields.extend([
            (f"mutation_{name}_artifact", read(source, "artifact")),
            (f"mutation_{name}_evidence", encode_evidence(key, signature)),
        ])

    wrong_transcript = read("wrong-signer", "transcript")
    active_key, _ = ed25519_sign_for_vector(seeds["active"], wrong_transcript)
    _, wrong_signature = ed25519_sign_for_vector(seeds["unknown"], wrong_transcript)
    unknown_transcript = read("unknown-signer", "transcript")
    unknown_key, unknown_signature = ed25519_sign_for_vector(seeds["unknown"], unknown_transcript)
    revoked_transcript = read("revoked-signer", "transcript")
    revoked_key, revoked_signature = ed25519_sign_for_vector(seeds["revoked"], revoked_transcript)
    fields.extend([
        ("wrong_signer_evidence", encode_evidence(active_key, wrong_signature)),
        ("unknown_signer_evidence", encode_evidence(unknown_key, unknown_signature)),
        ("revoked_signer_evidence", encode_evidence(revoked_key, revoked_signature)),
        (
            "content_hash_only_evidence",
            encode_evidence(
                active_key,
                sha256(read("operator-a-p1", "artifact")) * 2,
            ),
        ),
    ])
    print(VECTOR_MAGIC)
    for name, value in fields:
        print(f"{name}={value.hex()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", nargs="?", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--emit-vectors", type=Path, metavar="BUILD_OUT_DIR")
    args = parser.parse_args()
    if not args.selftest and args.log is None and args.emit_vectors is None:
        parser.error("provide --selftest, --emit-vectors, and/or a QEMU log")
    try:
        if args.emit_vectors is not None:
            emit_vectors(args.emit_vectors)
        if args.selftest:
            selftest(args.vectors)
        if args.log is not None:
            verify_qemu_transcript(args.log.read_bytes().decode("utf-8", errors="replace"))
    except (OSError, UnicodeError, ValueError, struct.error, VerificationError) as error:
        print(f"FAIL verify-c73-authenticated-admission: {error}", file=sys.stderr)
        return 1
    if args.emit_vectors is None:
        print("PASS verify-c73-authenticated-admission: independent policy, signature, mutation, and target gates accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
