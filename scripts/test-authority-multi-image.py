#!/usr/bin/env python3
"""Verify Rust-exported multi-extent authority bases and their delta successors."""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("delta_image_tests", Path(__file__).with_name("test-authority-delta-image.py"))
tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tests)
v = tests.verifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    policy = v.AuthorityPolicy(b"test authority roots v1", tests.empty_objects, 0x415554482D5445535401)
    results = {}
    rejected = 0
    for name, depth in [("multi-base.raw", 0), ("multi-delta.raw", 1), ("multi-large-delta.raw", 2)]:
        image = (args.fixtures / name).read_bytes()
        def recover(data):
            structural = v.gc_verifier.parse_raw_structure(data)
            v.require(not structural["errors"], str(structural["errors"]))
            return v.reconstruct_v2_checkpoint(memoryview(data), structural,
                require_authority=True, authority_policy=policy, allow_experimental_delta=True)
        result = recover(image)
        assert result["experimental_authority_depth"] == depth
        assert v.verify_authority_bindings({"recovered": result})["authority_objects"] == 0
        structural = v.gc_verifier.parse_raw_structure(image)
        copies = v.verify_v2_checkpoint_fallbacks(memoryview(image), structural,
            v.selected_v2_superblock(memoryview(image)), result,
            authority_policy=policy, allow_experimental_delta=True)
        assert copies == 2, "multi-extent fixtures must retain both checkpoints"
        if depth == 2:
            try:
                v.verify_v2_checkpoint_fallbacks(memoryview(image), structural,
                    v.selected_v2_superblock(memoryview(image)), result, authority_policy=policy)
            except ValueError as error:
                v.require("admission is disabled" in str(error), str(error))
                rejected += 1
            else:
                raise AssertionError("default fallback admitted multi-extent experimental history")
        pointer = structural["checkpoint"]["record"]["authority_root"]
        resolver = v.gc_verifier.RawImageResolver(image, structural["checkpoint"],
            structural["segments"], result["allocation"])
        _, payload, parts = v.resolve_authority_payload(resolver, pointer, "budget fixture")
        _, exact, _ = v.resolve_authority_payload(resolver, pointer, "exact budget", maximum=len(payload))
        assert exact == payload
        for maximum, expected_reads in [(pointer["exact_byte_len"] - 1, 0),
                                        (len(payload) - 1, int(len(parts) > 1))]:
            limited = v.gc_verifier.RawImageResolver(image, structural["checkpoint"],
                structural["segments"], result["allocation"])
            read = limited.resolve
            calls = []
            def counted(*args, **kwargs):
                calls.append(1)
                return read(*args, **kwargs)
            limited.resolve = counted
            try:
                v.resolve_authority_payload(limited, pointer, "short budget", maximum=maximum)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError("short payload budget accepted")
            assert len(calls) == expected_reads, "must reject before loading excess siblings"
        extents = [framed["record"] for segment in structural["segments"]
                   for framed in segment.get("extents", [])
                   if framed.get("record", {}).get("extent_kind") == v.gc_verifier.EXTENT_AUTHORITY]
        base_generation = min(extent["binding"]["target_checkpoint_generation"] for extent in extents)
        base = [extent for extent in extents if extent["binding"]["target_checkpoint_generation"] == base_generation]
        assert len(base) == 5 and {extent["extent_index"] for extent in base} == set(range(5))
        assert len({extent["binding"]["segment_no"] for extent in base}) >= 2, "must span segments"
        if depth == 2:
            tip_generation = result["authority_generation"]
            tip = [extent for extent in extents if extent["binding"]["target_checkpoint_generation"] == tip_generation]
            assert len(tip) == 5 and {extent["extent_index"] for extent in tip} == set(range(5))
            assert len({extent["binding"]["segment_no"] for extent in tip}) >= 2
        # Damage every base chunk and the successor link individually. Parse
        # again from bytes, so this exercises physical sealing, not a mocked index.
        for extent in extents:
            damaged = bytearray(image)
            page = v.storage_codec.segment_base_page(extent["binding"]["segment_no"]) + extent["payload_first_relative_page"]
            damaged[page * v.storage_codec.PAGE_SIZE] ^= 1
            try:
                recover(damaged)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError(f"{name}: damaged extent admitted")
        results[name] = {"depth": depth, "verified_checkpoint_copies": copies, "base_extents": len(base), "damaged_extents_rejected": len(extents)}
    print(json.dumps({"status": "ok", "regions": results, "rejected_cases": rejected}, indent=2))


if __name__ == "__main__":
    main()
