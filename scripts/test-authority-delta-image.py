#!/usr/bin/env python3
"""Verify Rust-exported experimental delta checkpoint regions independently.

Input fixtures come from experimental_delta_checkpoint_cold_mount_and_gc_materialize
with VIBE_DELTA_IMAGE_FIXTURES set. These are V2 regions, not migration containers.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("delta_image_verifier", Path(__file__).with_name("verify-storage-v2-migration.py"))
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


def empty_objects(state):
    verifier.require(not state.objects, "fixture unexpectedly contains objects")
    return {}


def live_object(state):
    verifier.require(set(state.objects) == {2} and len(state.grants) == 1 and not state.tombstones,
                     "live fixture object/grant history differs")
    grant = state.grants[0]
    verifier.require((grant.derivation, grant.parent, grant.object_id, grant.space, grant.slot,
                      grant.generation, grant.rights, grant.resource_kind, grant.flags) ==
                     (5, 0, 2, 6, 0, 0, 1, 0x41555432, 1), "root grant differs from external policy")
    verifier.require(state.live == {5: grant} and state.slots == {(6, 0): (0, 5)},
                     "live grant/slot differs")
    kind, content, sequence = state.objects[2]
    verifier.require(kind == 0x41555432 and content == bytes(n % 251 for n in range(4096))
                     and sequence < grant.commit_sequence, "fixture object content/order differs")
    return {2: state.objects[2]}


def fused_objects(state):
    # The external policy permits exactly the known prefix at either durable
    # checkpoint, including the older two-object fallback of the final append.
    count = len(state.objects)
    expected_ids = [8193, 8198, 8203][:count]
    verifier.require(count <= 3 and set(state.objects) == set(expected_ids)
                     and len(state.grants) == count and not state.tombstones,
                     "fused fixture history differs")
    live, slots = {}, {}
    for index, (object_id, grant) in enumerate(zip(expected_ids, state.grants)):
        derivation, space = 8195 + 5 * index, 8196 + 5 * index
        verifier.require((grant.derivation, grant.parent, grant.object_id, grant.space,
                          grant.slot, grant.generation, grant.rights, grant.resource_kind, grant.flags)
                         == (derivation, 0, object_id, space, 0, 0, 1, 0x41555432, 1),
                         "fused root policy differs")
        kind, content, sequence = state.objects[object_id]
        verifier.require(kind == 0x41555432 and content == bytes([0x61 if index < 2 else 0x62]) * 4096
                         and sequence < grant.commit_sequence, "fused object differs")
        live[derivation] = grant
        slots[(space, 0)] = (0, derivation)
    verifier.require(state.live == live and state.slots == slots, "fused grant/slot state differs")
    return {object_id: state.objects[object_id] for object_id in expected_ids}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    results = {}
    rejected = 0
    fixtures = [("delta.raw", 3), ("materialized.raw", 0),
                ("live-delta.raw", 3), ("live-materialized.raw", 0)]
    if any((args.fixtures / name).exists() for name in ("fused-delta.raw", "fused-materialized.raw")):
        fixtures += [("fused-delta.raw", 3), ("fused-materialized.raw", 0)]
    for name, depth in fixtures:
        fused = name.startswith("fused-")
        live = fused or name.startswith("live-")
        selector = fused_objects if fused else live_object if live else empty_objects
        policy = verifier.AuthorityPolicy(b"test authority roots v1", selector, 0x415554482D5445535401)
        image = (args.fixtures / name).read_bytes()
        structure = verifier.gc_verifier.parse_raw_structure(image)
        verifier.require(not structure["errors"], str(structure["errors"]))
        def recover(data=image, structural=structure, supplied_policy=policy, enabled=True):
            return verifier.reconstruct_v2_checkpoint(memoryview(data), structural,
                require_authority=True, authority_policy=supplied_policy,
                allow_experimental_delta=enabled)
        if depth:
            try:
                recover(enabled=False)
            except ValueError as error:
                verifier.require("admission is disabled" in str(error), str(error))
                rejected += 1
            else:
                raise AssertionError("default accepted experimental delta")
        result = recover()
        assert result["experimental_authority_depth"] == depth
        # Prove both durable alternatives, including the incremental fixture's
        # older delta checkpoint, rather than only the selected tip.
        superblock = verifier.selected_v2_superblock(memoryview(image))
        fallback_copies = verifier.verify_v2_checkpoint_fallbacks(
            memoryview(image), structure, superblock, result,
            authority_policy=policy, allow_experimental_delta=True)
        assert fallback_copies == 2, "fixture must exercise both checkpoint slots"
        older = min(verifier.v2_checkpoint_slots(memoryview(image)),
                    key=lambda slot: slot["record"]["binding"]["generation"])
        older_structure = dict(structure, checkpoint=older)
        older_result = verifier.reconstruct_v2_checkpoint(memoryview(image), older_structure,
            require_authority=False, authority_policy=policy, allow_experimental_delta=True)
        if older_result["experimental_authority_depth"]:
            try:
                verifier.verify_v2_checkpoint_fallbacks(memoryview(image), structure,
                    superblock, result, authority_policy=policy)
            except ValueError as error:
                verifier.require("admission is disabled" in str(error), str(error))
                rejected += 1
            else:
                raise AssertionError("default fallback verifier accepted experimental delta")
        bindings = verifier.verify_authority_bindings({"recovered": result})
        expected_objects = 3 if fused else int(live)
        assert bindings["authority_objects"] == expected_objects
        assert bindings["logical_bytes"] == 4096 * expected_objects
        for bad_policy in [verifier.AuthorityPolicy(b"wrong policy", selector, policy.store_id),
                           verifier.AuthorityPolicy(policy.external_policy, selector, policy.store_id + 1)]:
            try:
                recover(supplied_policy=bad_policy)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError("foreign external policy or record store admitted")
        # Corrupt every physically stored authority payload in the image, one
        # at a time. For the incremental checkpoint all four are required.
        if depth:
            corrupted_ancestors = 0
            corrupted_blobs = 0
            for segment in structure["segments"]:
                for framed in segment.get("extents", []):
                    extent = framed.get("record", {})
                    kind = extent.get("extent_kind")
                    if kind != 3 and not (live and kind == 1):
                        continue
                    page = extent["binding"]["segment_no"] * verifier.storage_codec.SEGMENT_PAGES + verifier.storage_codec.ANCHOR_PAGES + extent["payload_first_relative_page"]
                    corrupted_ancestors += int(kind == 3)
                    corrupted_blobs += int(kind == 1)
                    damaged = bytearray(image)
                    damaged[page * 4096] ^= 1
                    broken = verifier.gc_verifier.parse_raw_structure(damaged)
                    try:
                        recover(damaged, broken)
                    except ValueError:
                        rejected += 1
                    else:
                        raise AssertionError("corrupt authority ancestor admitted")
            assert corrupted_ancestors == depth + 1, "ancestor corruption loop did not cover the chain"
            assert not live or corrupted_blobs > 0, "live fixture never checked damaged object content"
        results[name] = {"depth": depth, "checkpoint_generation": result["checkpoint_generation"],
                         "verified_checkpoint_copies": fallback_copies,
                         "fallback_authority_depth": older_result["experimental_authority_depth"],
                         "verified_objects": bindings["authority_objects"], "logical_bytes": bindings["logical_bytes"]}
    print(json.dumps({"status": "ok", "regions": results, "rejected_cases": rejected}, indent=2))


if __name__ == "__main__":
    main()
