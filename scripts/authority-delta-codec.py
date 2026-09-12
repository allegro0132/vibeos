#!/usr/bin/env python3
"""Independent experimental authority-delta byte oracle, not disk admission.

The production migration verifier does not yet admit this format. Callers must
still resolve/authenticate physical extents and apply external authority policy.
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


media = module("storage-v2-image.py", "authority_delta_media")
legacy = module("persistent-cspace-image.py", "authority_delta_legacy")
MAX_BYTES = 64 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(data, offset, size=8):
    require(offset + size <= len(data), "truncated integer")
    return int.from_bytes(data[offset:offset + size], "little")


def snapshot(data, expected_store_id):
    require(128 <= len(data) <= MAX_BYTES and data[:8] == b"VIBEAUT2", "snapshot size/magic")
    require(integer(data, 8, 2) == 2 and integer(data, 10, 2) == 128, "snapshot version")
    require(not any(data[12:16]), "snapshot reserved")
    objects, principals, records = (integer(data, at, 4) for at in (56, 60, 64))
    roots = integer(data, 112, 4)
    require(principals <= 256 and records > 0, "snapshot counts")
    require(tuple(integer(data, at, 4) for at in (68, 72, 76, 116)) == (48, 64, 512, 32), "snapshot widths")
    principal_offset = 128 + objects * 48
    root_offset = principal_offset + principals * 64
    record_offset = root_offset + roots * 32
    require(tuple(integer(data, at) for at in (80, 88, 96, 104, 120)) ==
            (128, principal_offset, record_offset, len(data), root_offset), "snapshot offsets")
    require(record_offset + records * 512 == len(data), "snapshot length")
    require(integer(data, 16) > 0 and any(data[24:56]), "snapshot identity")
    generation = integer(data, 16)
    previous = 0
    backend_ids = set()
    for index in range(objects):
        at = 128 + index * 48
        stable, backend = integer(data, at, 16), integer(data, at + 16, 16)
        require(stable > previous and backend > 0 and backend not in backend_ids and
                0 < integer(data, at + 32) <= generation and integer(data, at + 40, 4) > 0 and
                integer(data, at + 44, 4) == 0, "object binding")
        previous = stable
        backend_ids.add(backend)
    previous = bytes(16)
    for index in range(principals):
        at = principal_offset + index * 64
        identity = data[at:at + 16]
        logical, physical, used_logical, used_physical = (integer(data, at + n) for n in (16,24,32,40))
        require(identity > previous and logical > 0 and physical > 0 and
                used_logical <= logical and used_physical <= physical and
                data[at + 48] <= 1 and not any(data[at + 49:at + 64]), "principal policy")
        previous = identity
    previous = 0
    for index in range(roots):
        at = root_offset + index * 32
        identity = integer(data, at, 16)
        require(identity > previous and identity not in backend_ids and 0 < integer(data, at + 16) <= generation and
                integer(data, at + 24, 4) > 0 and integer(data, at + 28, 4) == 0, "external root")
        previous = identity
    # Independent logical-record oracle: strict seals/CRC/sequence/semantics.
    state = legacy.recover_record_stream(data[record_offset:], max_records=MAX_BYTES // 512, allow_external=True, expected_store_id=expected_store_id)
    require(state.formatted, "unformatted stream")
    # External policy and graph-to-table admission still belong to the normal
    # snapshot verifier. Structural table validity is not capability authority.
    return integer(data, 16), record_offset


def reconstruct(base, link, predecessor_pointer, predecessor_depth, *, store_uuid,
                admitted_segments, next_segment_generation, checkpoint_generation, expected_store_id):
    require(256 <= len(link) <= MAX_BYTES and link[:8] == b"VIBEAUL1", "link size/magic")
    depth = integer(link, 8, 4)
    require(1 <= depth <= 32 and depth == predecessor_depth + 1 and not any(link[12:16]), "link depth/reserved")
    require(link[16:112] == predecessor_pointer, "wrong resolved predecessor")
    pointer = media.parse_pointer(predecessor_pointer)
    require(pointer["status"] == "value" and pointer["store_uuid"] == store_uuid and
            pointer["segment_no"] < admitted_segments and
            0 < pointer["segment_generation"] < next_segment_generation and
            pointer["extent_kind"] == 3 and 0 < pointer["payload_pages"] <= 256,
            "pointer context")
    base_generation, generation = integer(link, 112), integer(link, 120)
    require(0 < base_generation < generation <= checkpoint_generation, "link generation")
    delta = link[128:]
    require(delta[:8] == b"VIBEAUD1" and integer(delta, 8, 2) == 1 and integer(delta, 10, 2) == 128,
            "delta version")
    require(not any(delta[12:16] + delta[120:128]), "delta reserved")
    base_len, base_offset, output_len, output_offset, common = (integer(delta, at) for at in (16,24,32,40,48))
    require(base_len == len(base) <= MAX_BYTES and output_len <= MAX_BYTES and
            common > 0 and common % 512 == 0 and base_offset + common == len(base) and
            output_offset + common < output_len and len(delta) == 128 + output_len - common and
            len(delta) < output_len and 128 + output_offset <= len(delta), "delta bounds")
    require(hashlib.sha256(base).digest() == delta[56:88], "base digest")
    require(snapshot(base, expected_store_id) == (base_generation, base_offset), "base layout/generation")
    result = delta[128:128 + output_offset] + base[base_offset:] + delta[128 + output_offset:]
    require(len(result) == output_len and hashlib.sha256(result).digest() == delta[88:120], "result digest")
    require(snapshot(result, expected_store_id) == (generation, output_offset), "result layout/generation")
    return result


def selftest(root):
    base, first, middle, second, result = ((root / name).read_bytes() for name in
                                        ("base.bin", "first.bin", "middle.bin", "second.bin", "result.bin"))
    context = dict(store_uuid=bytes([7]) * 16, admitted_segments=16,
                   next_segment_generation=8, checkpoint_generation=5, expected_store_id=7)
    def apply(data):
        return reconstruct(base, data, first[16:112], 0, **context)
    require(apply(first) == middle, "Rust/Python first snapshot differs")
    require(reconstruct(middle, second, second[16:112], 1, **context) == result, "Rust/Python result differs")
    rejected = 0
    for bad in ([first[:n] for n in range(len(first))] +
                [first[:n] + bytes([first[n] ^ 1]) + first[n+1:] for n in range(len(first))] + [first + b"\0"]):
        try:
            apply(bad)
        except (ValueError, RuntimeError):
            rejected += 1
        else:
            raise AssertionError("accepted damaged link")
    # Recompute the result hash after corrupting the appended record: CRC/chain
    # validation must still reject the payload rather than trust its digest.
    changed = bytearray(first); changed[-1] ^= 1
    expected = bytearray(middle); expected[-1] ^= 1
    changed[216:248] = hashlib.sha256(expected).digest()
    try:
        apply(bytes(changed))
    except (ValueError, RuntimeError):
        rejected += 1
    else:
        raise AssertionError("accepted rehashed bad record")
    # Mutate valid successor metadata and bind the new digest in the delta.
    # All offsets lie in the copied current metadata prefix.
    principal = integer(middle, 88)
    for offset, replacement in [
        (principal, bytes(16)), (principal + 16, bytes(8)),
        (principal + 32, (101).to_bytes(8, "little")),
        (principal + 48, b"\x02"), (principal + 49, b"\x01"),
        (24, bytes(32)),
    ]:
        changed = bytearray(first)
        changed[256+offset:256+offset+len(replacement)] = replacement
        expected = bytearray(middle)
        expected[offset:offset+len(replacement)] = replacement
        changed[216:248] = hashlib.sha256(expected).digest()
        try:
            apply(bytes(changed))
        except (ValueError, RuntimeError):
            rejected += 1
        else:
            raise AssertionError("accepted rehashed invalid metadata")
    wrong = dict(context, expected_store_id=8)
    try:
        reconstruct(base, first, first[16:112], 0, **wrong)
    except (ValueError, RuntimeError):
        rejected += 1
    else:
        raise AssertionError("accepted wrong expected StoreId")
    rich_base, rich_link, rich_result = ((root / name).read_bytes() for name in
                                       ("rich-base.bin", "rich-link.bin", "rich-result.bin"))
    def apply_rich(data):
        return reconstruct(rich_base, data, rich_link[16:112], 0, **context)
    require(apply_rich(rich_link) == rich_result, "Rust/Python rich snapshot differs")
    external = integer(rich_result, 120)
    for offset, replacement in [
        (128, bytes(16)), (144, bytes(16)), (160, bytes(8)),
        (160, (5).to_bytes(8, "little")), (168, bytes(4)), (172, b"\x01"),
        (external, bytes(16)), (external, integer(rich_result, 144, 16).to_bytes(16, "little")),
        (external + 16, bytes(8)),
        (external + 16, (5).to_bytes(8, "little")),
        (external + 24, bytes(4)), (external + 28, b"\x01"),
    ]:
        changed = bytearray(rich_link)
        changed[256+offset:256+offset+len(replacement)] = replacement
        expected = bytearray(rich_result)
        expected[offset:offset+len(replacement)] = replacement
        changed[216:248] = hashlib.sha256(expected).digest()
        try:
            apply_rich(bytes(changed))
        except (ValueError, RuntimeError):
            rejected += 1
        else:
            raise AssertionError("accepted rehashed invalid binding/root")
    return dict(status="ok", reconstructed_links=3, rejected_cases=rejected)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    print(json.dumps(selftest(args.fixtures), indent=2))
