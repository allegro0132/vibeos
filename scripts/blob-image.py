#!/usr/bin/env python3
"""Independent verifier for the minimal BlobFS/Merkle QEMU image."""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path


OBJECT_KIND = 0x424C_4F42
BYTE_LEN = 4_203
LEAF_SIZE = 4_096
HEADER_SIZE = 128
HASH_SIZE = 32
MARKER = b"VIBEOS-MERKLE-BLOB-v1"
LEAF_DOMAIN = b"VIBEBLOB-LEAF-v1\0"
EMPTY_DOMAIN = b"VIBEBLOB-EMPTY-v1\0"
NODE_DOMAIN = b"VIBEBLOB-NODE-v1\0"
ROOT_DOMAIN = b"VIBEBLOB-ROOT-v1\0"


def fail(message: str) -> "None":
    raise ValueError(message)


def digest(*parts: bytes) -> bytes:
    value = hashlib.sha256()
    for part in parts:
        value.update(part)
    return value.digest()


def expected_payload() -> bytes:
    data = bytearray((index * 29 + 7) % 251 for index in range(BYTE_LEN))
    data[: len(MARKER)] = MARKER
    return bytes(data)


def encode_blob(content: bytes) -> bytes:
    leaf_count = max(1, (len(content) + LEAF_SIZE - 1) // LEAF_SIZE)
    padded_leaves = 1 << (leaf_count - 1).bit_length()
    tree = []
    for index in range(padded_leaves):
        if index < leaf_count:
            chunk = content[index * LEAF_SIZE : (index + 1) * LEAF_SIZE]
            tree.append(
                digest(
                    LEAF_DOMAIN,
                    struct.pack("<III", OBJECT_KIND, index, len(chunk)),
                    chunk,
                )
            )
        else:
            tree.append(digest(EMPTY_DOMAIN, struct.pack("<II", OBJECT_KIND, index)))
    level_base = 0
    level_width = padded_leaves
    level = 1
    while level_width > 1:
        for offset in range(0, level_width, 2):
            tree.append(
                digest(
                    NODE_DOMAIN,
                    struct.pack("<I", level),
                    tree[level_base + offset],
                    tree[level_base + offset + 1],
                )
            )
        level_base += level_width
        level_width //= 2
        level += 1

    root = digest(
        ROOT_DOMAIN,
        struct.pack("<IQII", OBJECT_KIND, len(content), LEAF_SIZE, leaf_count),
        tree[-1],
    )
    tree_bytes = b"".join(tree)
    tree_offset = HEADER_SIZE + len(content)
    encoded_len = tree_offset + len(tree_bytes)
    header = bytearray(HEADER_SIZE)
    header[:8] = b"VIBEBLB\0"
    struct.pack_into("<HHHBBI", header, 8, 1, HEADER_SIZE, 1, 12, 0, OBJECT_KIND)
    struct.pack_into("<QII", header, 24, len(content), leaf_count, len(tree))
    header[40:72] = root
    struct.pack_into("<QQQ", header, 72, HEADER_SIZE, tree_offset, encoded_len)
    return bytes(header) + content + tree_bytes


def verify_blob(encoded: bytes) -> None:
    if len(encoded) < HEADER_SIZE or encoded[:8] != b"VIBEBLB\0":
        fail("bad BlobFS magic or truncated header")
    version, header_len, algorithm = struct.unpack_from("<HHH", encoded, 8)
    if (version, header_len, algorithm, encoded[14], encoded[15]) != (1, 128, 1, 12, 0):
        fail("non-canonical BlobFS version/hash/leaf geometry")
    if struct.unpack_from("<I", encoded, 16)[0] != OBJECT_KIND:
        fail("BlobFS inner object kind mismatch")
    if any(encoded[20:24]) or any(encoded[96:128]):
        fail("BlobFS reserved header bytes are non-zero")
    byte_len, leaf_count, node_count = struct.unpack_from("<QII", encoded, 24)
    data_offset, tree_offset, encoded_len = struct.unpack_from("<QQQ", encoded, 72)
    if (
        byte_len != BYTE_LEN
        or leaf_count != 2
        or node_count != 3
        or data_offset != HEADER_SIZE
        or tree_offset != HEADER_SIZE + BYTE_LEN
        or encoded_len != len(encoded)
    ):
        fail("BlobFS canonical lengths changed")
    if encoded[HEADER_SIZE:tree_offset] != expected_payload():
        fail("BlobFS content differs from the guest acceptance payload")
    if encoded != encode_blob(expected_payload()):
        fail("BlobFS Merkle tree or bound root is invalid")


def load_store_verifier():
    path = Path(__file__).with_name("store-image.py")
    spec = importlib.util.spec_from_file_location("vibeos_store_image", path)
    if spec is None or spec.loader is None:
        fail("cannot load the object-store verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(path: Path) -> None:
    encoded = encode_blob(expected_payload())
    verify_blob(encoded)
    store = load_store_verifier()
    records = store.verify_image(path.read_bytes(), [(OBJECT_KIND, encoded)])
    expected_kinds = [1, 2, 6] + [7] * 13 + [8]
    if [record["kind"] for record in records] != expected_kinds:
        fail("BlobFS journal is not one exact committed 13-chunk object")
    print("ok   BlobFS backing (journal, canonical blob, Merkle tree, and root verified)")


def self_test() -> None:
    encoded = encode_blob(expected_payload())
    verify_blob(encoded)
    corrupt = bytearray(encoded)
    corrupt[HEADER_SIZE + 17] ^= 1
    try:
        verify_blob(bytes(corrupt))
    except ValueError:
        print("ok   BlobFS host verifier self-test")
        return
    fail("BlobFS verifier accepted corrupted content")


def main(argv: list[str]) -> int:
    try:
        if argv == ["--selftest"]:
            self_test()
        elif len(argv) == 1:
            verify(Path(argv[0]))
        else:
            print("usage: blob-image.py [--selftest|IMAGE]", file=sys.stderr)
            return 2
    except (OSError, ValueError) as error:
        print(f"FAIL BlobFS backing: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
