#!/usr/bin/env python3
"""Independent M4.5 saved-program image and strict-prefix verifier.

The canonical journal parser is shared with the M4.3 host verifier, while the
ProgramArtifact and VIBEEXE parsers below are independent of all Rust code.
They validate the powered-off disk rather than trusting the guest transcript.
"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path


def load_journal_parser():
    path = Path(__file__).with_name("persistent-cspace-image.py")
    spec = importlib.util.spec_from_file_location("vibeos_persistent_parser", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the canonical journal verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


J = load_journal_parser()

PROGRAM_SPACE_ID = 0x5052_4F47
PROGRAM_SLOT = 0
PROGRAM_OBJECT_KIND = 0x5052_4731
STORED_OBJECT_RESOURCE_KIND = 0x5354_4F52
PROGRAM_RIGHTS = 0x01
CONSOLE_RIGHTS = 0x02
MEMORY_RIGHTS = 0x03

PROGRAM_MAGIC = b"VIBEPGM\0"
PROGRAM_VERSION = 1
PROGRAM_HEADER_LEN = 160
PROGRAM_AUTHORITY_ABI = 1
PROGRAM_ALIAS = b"hello"
PROGRAM_SOURCE_ABI = 1
PROGRAM_EXECUTABLE_ABI = 1
PROGRAM_RUNTIME_ABI = 1
PROGRAM_AUTHORITY_COUNT = 2
PROGRAM_CONSOLE_KIND = 1
PROGRAM_MEMORY_KIND = 2

EXE_MAGIC = b"VIBEEXE\0"
EXE_VERSION = 1
EXE_HEADER_LEN = 64
EXE_TARGET_ABI = 1
EXE_COMPILER_ABI = 1
EXE_RUNTIME_ABI = 1
EXE_RELOCATION_LEN = 16
RET = 0x0000_8067
JALR_RA_T0 = 0x0002_80E7


def fail(message: str) -> "None":
    raise ValueError(message)


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def crc32c(data: bytes) -> int:
    return J.crc32c(data)


def li64_words(register: int) -> list[int]:
    words = [(register << 7) | 0x13]
    shift = (11 << 20) | (register << 15) | (1 << 12) | (register << 7) | 0x13
    add_zero = (register << 15) | (register << 7) | 0x13
    for _ in range(5):
        words.extend((shift, add_zero))
    return words


def verify_vibeexe(executable: bytes, source: bytes) -> None:
    if len(executable) < EXE_HEADER_LEN or len(executable) > 360 * 1024:
        fail("VIBEEXE size is outside the v1 bounds")
    if executable[:8] != EXE_MAGIC:
        fail("VIBEEXE magic mismatch")
    if (
        u16(executable, 8) != EXE_VERSION
        or u16(executable, 10) != EXE_HEADER_LEN
        or u32(executable, 12) != EXE_TARGET_ABI
        or u32(executable, 16) != EXE_COMPILER_ABI
        or u32(executable, 20) != EXE_RUNTIME_ABI
        or u32(executable, 24) != 0
        or u32(executable, 60) != 0
    ):
        fail("VIBEEXE header/ABI is non-canonical")

    funcs = u32(executable, 28)
    data_len = u32(executable, 32)
    code_words = u32(executable, 36)
    relocation_count = u32(executable, 40)
    declared_imports = u32(executable, 44)
    if declared_imports & ~0x0F:
        fail("VIBEEXE names an unknown runtime import")
    if u32(executable, 48) != len(source) or u32(executable, 52) != crc32c(source):
        fail("VIBEEXE source identity does not match ProgramArtifact")

    padding = (-data_len) % 4
    code_bytes = code_words * 4
    relocation_bytes = relocation_count * EXE_RELOCATION_LEN
    expected = EXE_HEADER_LEN + data_len + padding + code_bytes + relocation_bytes
    if expected != len(executable):
        fail("VIBEEXE length metadata is inconsistent")
    body = executable[EXE_HEADER_LEN:]
    if crc32c(body) != u32(executable, 56):
        fail("VIBEEXE body CRC32C mismatch")
    if any(executable[EXE_HEADER_LEN + data_len : EXE_HEADER_LEN + data_len + padding]):
        fail("VIBEEXE data padding is non-zero")

    code_start = EXE_HEADER_LEN + data_len + padding
    relocation_start = code_start + code_bytes
    code = [
        u32(executable, offset)
        for offset in range(code_start, relocation_start, 4)
    ]
    if funcs == 0 or not code or code.count(RET) != funcs:
        fail("VIBEEXE function-count/entry shape is invalid")

    required_imports = 0
    sites: dict[int, int] = {}
    previous_site = -1
    previous_end = 0
    for offset in range(relocation_start, len(executable), EXE_RELOCATION_LEN):
        site = u32(executable, offset)
        kind = u16(executable, offset + 4)
        reserved0 = u16(executable, offset + 6)
        target = u32(executable, offset + 8)
        reserved1 = u32(executable, offset + 12)
        if reserved0 or reserved1 or kind not in (1, 2, 3):
            fail("VIBEEXE relocation is non-canonical")
        end = site + 11
        if site <= previous_site or site < previous_end or end > len(code):
            fail("VIBEEXE relocation sites are unordered, overlapping, or out of range")
        previous_site, previous_end = site, end
        register = 10 if kind == 1 else 5
        if code[site:end] != li64_words(register):
            fail("VIBEEXE relocation does not name a canonical zero li64")
        if kind == 1:
            if target > data_len:
                fail("VIBEEXE data relocation is out of range")
        else:
            if end >= len(code) or code[end] != JALR_RA_T0:
                fail("VIBEEXE call relocation lacks canonical jalr")
            if kind == 2 and target >= len(code):
                fail("VIBEEXE code relocation is out of range")
            if kind == 3:
                if target not in (1, 2, 3, 4):
                    fail("VIBEEXE runtime import is unknown")
                required_imports |= 1 << (target - 1)
        sites[site] = kind
    if len(sites) != relocation_count or required_imports != declared_imports:
        fail("VIBEEXE relocation/import metadata is inconsistent")

    # Every compiler-owned zero address template is understood and declared.
    # T0 is reserved for calls, so a bare T0 template is non-canonical even
    # when it is not followed by the canonical jalr instruction.
    a0_template = li64_words(10)
    t0_template = li64_words(5)
    for site in range(max(0, len(code) - 10)):
        words = code[site : site + 11]
        if words == a0_template and sites.get(site) != 1:
            fail("VIBEEXE omitted a data relocation")
        if words == t0_template:
            if site + 11 >= len(code) or code[site + 11] != JALR_RA_T0:
                fail("VIBEEXE contains an unrecognized T0 address placeholder")
            if sites.get(site) not in (2, 3):
                fail("VIBEEXE omitted a call relocation")


def decode_program_artifact(content: bytes) -> tuple[bytes, bytes]:
    if len(content) < PROGRAM_HEADER_LEN or len(content) > 360 * 1024:
        fail("ProgramArtifact size is outside the v1 bounds")
    if content[:8] != PROGRAM_MAGIC:
        fail("ProgramArtifact magic mismatch")
    if (
        u16(content, 8) != PROGRAM_VERSION
        or u16(content, 10) != PROGRAM_HEADER_LEN
        or u32(content, 12) != 0
        or u32(content, 16) != PROGRAM_AUTHORITY_ABI
        or u32(content, 28) != 0
        or u32(content, 108) != PROGRAM_SOURCE_ABI
        or u32(content, 112) != PROGRAM_EXECUTABLE_ABI
        or u32(content, 116) != PROGRAM_RUNTIME_ABI
        or u16(content, 120) != PROGRAM_AUTHORITY_COUNT
        or u16(content, 122) != 0
        or u32(content, 124) != PROGRAM_CONSOLE_KIND
        or u32(content, 128) != PROGRAM_MEMORY_KIND
        or u16(content, 132) != len(PROGRAM_ALIAS)
        or u16(content, 134) != 0
        or content[136 : 136 + len(PROGRAM_ALIAS)] != PROGRAM_ALIAS
        or any(content[136 + len(PROGRAM_ALIAS) : PROGRAM_HEADER_LEN])
    ):
        fail("ProgramArtifact header/ABI is non-canonical")
    if (
        u32(content, 96) != PROGRAM_RIGHTS
        or u32(content, 100) != CONSOLE_RIGHTS
        or u32(content, 104) != MEMORY_RIGHTS
    ):
        fail("ProgramArtifact authority manifest is not exact")
    source_len = u32(content, 20)
    executable_len = u32(content, 24)
    if source_len == 0 or source_len > 64 * 1024:
        fail("ProgramArtifact source length is invalid")
    if executable_len == 0 or executable_len > 288 * 1024:
        fail("ProgramArtifact executable length is invalid")
    if PROGRAM_HEADER_LEN + source_len + executable_len != len(content):
        fail("ProgramArtifact length metadata is inconsistent")
    source = content[PROGRAM_HEADER_LEN : PROGRAM_HEADER_LEN + source_len]
    executable = content[PROGRAM_HEADER_LEN + source_len :]
    if hashlib.sha256(source).digest() != content[32:64]:
        fail("ProgramArtifact source SHA-256 mismatch")
    if hashlib.sha256(executable).digest() != content[64:96]:
        fail("ProgramArtifact executable SHA-256 mismatch")
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"ProgramArtifact source is not UTF-8: {error}")
    verify_vibeexe(executable, source)
    return source, executable


def verify_acceptance(state) -> None:
    if not state.formatted:
        fail("saved-program journal is not formatted")
    program_objects = {
        object_id: (content, sequence)
        for object_id, (kind, content, sequence) in state.objects.items()
        if kind == PROGRAM_OBJECT_KIND
    }
    if not program_objects:
        fail("expected at least one committed ProgramArtifact object")

    roots = [
        grant
        for grant in state.live.values()
        if grant.space == PROGRAM_SPACE_ID and grant.flags == 1 and grant.parent == 0
    ]
    if len(roots) != 1:
        fail(f"expected one live saved-program root, found {len(roots)}")
    root = roots[0]
    object_entry = program_objects.get(root.object_id)
    if object_entry is None:
        fail("saved-program root references no ProgramArtifact object")
    content, object_sequence = object_entry
    decode_program_artifact(content)

    if (
        root.slot != PROGRAM_SLOT
        or root.generation != 0
        or root.rights != PROGRAM_RIGHTS
        or root.resource_kind != STORED_OBJECT_RESOURCE_KIND
        or root.commit_sequence <= object_sequence
    ):
        fail("saved-program root policy/object binding is not exact")
    program_grants = [grant for grant in state.grants if grant.space == PROGRAM_SPACE_ID]
    if program_grants != [root]:
        fail("saved-program image contains unexpected durable authority history")
    grants_by_derivation = {grant.derivation: grant for grant in state.grants}
    if any(derivation not in grants_by_derivation for derivation in state.tombstones):
        fail("saved-program image contains an unattributed durable tombstone")
    if any(
        grants_by_derivation[derivation].space == PROGRAM_SPACE_ID
        for derivation in state.tombstones
    ):
        fail("saved-program image contains a program-partition tombstone")
    program_slots = {
        key: value for key, value in state.slots.items() if key[0] == PROGRAM_SPACE_ID
    }
    if program_slots != {(PROGRAM_SPACE_ID, PROGRAM_SLOT): (0, root.derivation)}:
        fail("saved-program slot history is not exact")

    # ObjectCommit is intentionally earlier than GrantCommit. A crash followed
    # by a retry can therefore leave one or more committed but authority-inert
    # ProgramArtifacts. They are valid only when no grant ever references them.
    referenced_objects = {grant.object_id for grant in state.grants}
    for object_id, (candidate, _sequence) in program_objects.items():
        if object_id == root.object_id:
            continue
        if object_id in referenced_objects:
            fail("an unselected ProgramArtifact object is referenced by authority history")
        decode_program_artifact(candidate)
    if state.high_water <= max(
        PROGRAM_SPACE_ID, *program_objects, root.derivation
    ):
        fail("saved-program IDs were not covered by a flushed high-water mark")


def minimal_vibeexe(source: bytes, data: bytes = b"") -> bytes:
    padding = bytes((-len(data)) % 4)
    body = data + padding + struct.pack("<I", RET)
    out = bytearray(EXE_HEADER_LEN)
    out[:8] = EXE_MAGIC
    struct.pack_into(
        "<HHIIIIIIIIIII",
        out,
        8,
        EXE_VERSION,
        EXE_HEADER_LEN,
        EXE_TARGET_ABI,
        EXE_COMPILER_ABI,
        EXE_RUNTIME_ABI,
        0,
        1,
        len(data),
        1,
        0,
        0,
        len(source),
        crc32c(source),
    )
    struct.pack_into("<I", out, 56, crc32c(body))
    return bytes(out) + body


def encode_artifact(source: bytes, executable: bytes) -> bytes:
    out = bytearray(PROGRAM_HEADER_LEN + len(source) + len(executable))
    out[:8] = PROGRAM_MAGIC
    struct.pack_into(
        "<HHIIII",
        out,
        8,
        PROGRAM_VERSION,
        PROGRAM_HEADER_LEN,
        0,
        PROGRAM_AUTHORITY_ABI,
        len(source),
        len(executable),
    )
    out[32:64] = hashlib.sha256(source).digest()
    out[64:96] = hashlib.sha256(executable).digest()
    struct.pack_into("<III", out, 96, PROGRAM_RIGHTS, CONSOLE_RIGHTS, MEMORY_RIGHTS)
    struct.pack_into(
        "<IIIHHIIH",
        out,
        108,
        PROGRAM_SOURCE_ABI,
        PROGRAM_EXECUTABLE_ABI,
        PROGRAM_RUNTIME_ABI,
        PROGRAM_AUTHORITY_COUNT,
        0,
        PROGRAM_CONSOLE_KIND,
        PROGRAM_MEMORY_KIND,
        len(PROGRAM_ALIAS),
    )
    out[136 : 136 + len(PROGRAM_ALIAS)] = PROGRAM_ALIAS
    out[PROGRAM_HEADER_LEN : PROGRAM_HEADER_LEN + len(source)] = source
    out[PROGRAM_HEADER_LEN + len(source) :] = executable
    return bytes(out)


def fixture_artifact() -> tuple[bytes, bytes]:
    source = b"fn main() {}\n"
    # 160 + 13 + (64 + 600 + 4) = 841 bytes, the same three-chunk shape as
    # the accepted `hello` artifact recorded by the QEMU golden transcript.
    return source, encode_artifact(source, minimal_vibeexe(source, bytes(600)))


def append_fixture_publication(
    records: list[bytes], artifact: bytes, first: int
) -> tuple[int, int, int]:
    object_tx, object_id = first, first + 1
    grant_tx, derivation = first + 2, first + 3
    J.append_fixture_record(records, J.HIGH_WATER, (first + 4).to_bytes(16, "little"))

    chunk_count = (len(artifact) + 359) // 360
    prepare = bytearray(40)
    prepare[:16] = object_id.to_bytes(16, "little")
    struct.pack_into("<I", prepare, 16, PROGRAM_OBJECT_KIND)
    struct.pack_into("<QII", prepare, 24, len(artifact), chunk_count, crc32c(artifact))
    object_prepare = J.append_fixture_record(records, J.OBJECT_PREPARE, bytes(prepare), object_tx)
    chunks = []
    for index in range(chunk_count):
        data = artifact[index * 360 : (index + 1) * 360]
        payload = bytearray(384)
        payload[:16] = object_id.to_bytes(16, "little")
        struct.pack_into("<IH", payload, 16, index, len(data))
        payload[24 : 24 + len(data)] = data
        chunks.append(J.append_fixture_record(records, J.OBJECT_CHUNK, bytes(payload), object_tx))
    commit = bytearray(48)
    commit[:16] = object_id.to_bytes(16, "little")
    digest = crc32c(b"".join(struct.pack("<I", chunk.crc) for chunk in chunks))
    struct.pack_into(
        "<QIIQII",
        commit,
        16,
        object_prepare.sequence,
        object_prepare.crc,
        chunk_count,
        chunks[0].sequence,
        digest,
        crc32c(artifact),
    )
    J.append_fixture_record(records, J.OBJECT_COMMIT, bytes(commit), object_tx)
    object_commit_index = len(records) - 1
    grant_prepare_index = len(records)
    J.append_fixture_grant(
        records,
        grant_tx,
        J.grant_payload(
            derivation,
            0,
            object_id,
            PROGRAM_SPACE_ID,
            PROGRAM_SLOT,
            0,
            PROGRAM_RIGHTS,
            STORED_OBJECT_RESOURCE_KIND,
            1,
        ),
    )
    return object_id, object_commit_index, grant_prepare_index


def fixture_records() -> list[bytes]:
    _source, artifact = fixture_artifact()
    records: list[bytes] = []
    J.append_fixture_record(records, J.FORMAT, b"")
    append_fixture_publication(records, artifact, PROGRAM_SPACE_ID + 1)
    return records


def selftest() -> None:
    records = fixture_records()
    baselines = [J.recover(J.image_with(records[:count])) for count in range(len(records) + 1)]
    for count, baseline in enumerate(baselines[:-1]):
        for cut in range(J.SECTOR_SIZE):
            observed = J.recover(J.image_with(records[:count], records[count][:cut]))
            if observed.fingerprint() != baseline.fingerprint():
                fail(f"record {count + 1} byte-prefix cut {cut} changed recovered state")
    if baselines[-2].live or len(baselines[-2].objects) != 1:
        fail("grant prepare published authority or object publication drifted")
    verify_acceptance(baselines[-1])

    state = baselines[-1]
    _object_id, (_kind, content, _sequence) = next(iter(state.objects.items()))
    for offset in (
        0,
        16,
        32,
        64,
        96,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        PROGRAM_HEADER_LEN,
        len(content) - 1,
    ):
        corrupted = bytearray(content)
        corrupted[offset] ^= 1
        try:
            decode_program_artifact(bytes(corrupted))
        except ValueError:
            pass
        else:
            fail(f"ProgramArtifact negative mutation at {offset} was accepted")

    source = b"fn main() {}\n"
    t0_words = li64_words(5) + [RET]
    t0_body = b"".join(struct.pack("<I", word) for word in t0_words)
    t0_executable = bytearray(minimal_vibeexe(source)[:EXE_HEADER_LEN])
    struct.pack_into("<I", t0_executable, 36, len(t0_words))
    struct.pack_into("<I", t0_executable, 56, crc32c(t0_body))
    t0_artifact = encode_artifact(source, bytes(t0_executable) + t0_body)
    try:
        decode_program_artifact(t0_artifact)
    except ValueError as error:
        if "unrecognized T0 address placeholder" not in str(error):
            fail(f"bare T0 negative fixture failed for the wrong reason: {error}")
    else:
        fail("bare T0 address placeholder was accepted")

    # Reproduce the two acknowledged crash states that contain a complete
    # orphan object: immediately after ObjectCommit, and after GrantPrepare but
    # before GrantCommit. Reboot/retry must publish one new rooted artifact
    # without making the earlier object authoritative or unverifiable.
    _source, artifact = fixture_artifact()
    first_attempt: list[bytes] = []
    J.append_fixture_record(first_attempt, J.FORMAT, b"")
    first_object, object_commit_index, grant_prepare_index = append_fixture_publication(
        first_attempt, artifact, PROGRAM_SPACE_ID + 1
    )
    for name, count in (
        ("ObjectCommit", object_commit_index + 1),
        ("GrantPrepare", grant_prepare_index + 1),
    ):
        retried = first_attempt[:count]
        crashed = J.recover(J.image_with(retried))
        if crashed.live or set(crashed.objects) != {first_object}:
            fail(f"{name} crash fixture exposed authority or lost its orphan object")
        retry_object, _, _ = append_fixture_publication(
            retried, artifact, crashed.high_water
        )
        recovered = J.recover(J.image_with(retried))
        verify_acceptance(recovered)
        if set(recovered.objects) != {first_object, retry_object}:
            fail(f"{name} retry fixture did not retain exactly one inert orphan")
    print(
        f"ok   saved-program strict-prefix/retry fixtures ({len(records)} records x {J.SECTOR_SIZE} cuts)"
    )


def verify(path: Path) -> None:
    state = J.recover(path.read_bytes())
    verify_acceptance(state)
    print("ok   saved-program backing (source, VIBEEXE, root, and authority manifest verified)")


def main() -> int:
    try:
        if sys.argv[1:] == ["--selftest"]:
            selftest()
        elif len(sys.argv) == 2:
            verify(Path(sys.argv[1]))
        else:
            print(f"usage: {Path(sys.argv[0]).name} [--selftest | DISK.raw]", file=sys.stderr)
            return 2
    except (OSError, ValueError) as error:
        print(f"FAIL saved-program verifier: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
