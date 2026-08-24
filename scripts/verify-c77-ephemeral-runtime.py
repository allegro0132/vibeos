#!/usr/bin/env python3
"""Host evidence verifier for the exact C7.7 ephemeral-runtime fixture.

This verifier first composes the narrow C7.6 verifier to prove that its seed is
the checked-in, two-version C7.6 G1 fixture.  It then accepts exactly two C7.7
cold-boot reports and requires the seed, post-boot-1, and post-boot-2 images to
be byte-for-byte identical.

It intentionally does not claim to recognize arbitrary Storage V3 histories or
the broader independent disk scope reserved for C7.8.  Guest reports are runtime
evidence only; they never substitute for the composed powered-off C7.6 proof.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VECTORS = (
    ROOT / "policy/image/artifacts/c76-graph-version-replacement.vectors"
)
BLOCK = 512

# This is the expected host/guest ABI for the C7.7 mainline handoff.  Keep the
# whole report exact so the Rust implementation can be aligned in one place.
C77_COMMON = (
    "durable_state=existing_g1 graph_only=1 physical_readback=1 "
    "fresh_validation=1 same_manifest=1 cold_start_empty=1 fresh_tasks=3 "
    "fresh_arenas=3 fresh_cspaces=3 fresh_memories=3 memory_bytes=196608 "
    "fresh_resource_tables=3 live_resources=4 fresh_fuel_accounts=3 "
    "fuel_consumed=0 fresh_pending_ledgers=3 active_pending_calls=1 "
    "pending_cut=parked cold_no_write=1 runtime_ready=0 guest_calls=0 "
    "raw_ids=0 ambient_lookup=0 vsh=0"
)
C77_PASS = "WASM_C77_EPHEMERAL_RUNTIME PASS " + C77_COMMON
C77_FAIL = "WASM_C77_EPHEMERAL_RUNTIME FAIL"
C77_FAMILY = "WASM_C77_EPHEMERAL_RUNTIME"


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


c76 = load_module(
    "verify-c76-graph-version-replacement.py",
    "vibeos_c77_exact_c76_g1_verifier",
)


def normalize_lines(raw: str) -> list[str]:
    return [line for line in raw.replace("\r", "\n").splitlines() if line]


def verify_c77_boot_transcript(raw: str, boot: int) -> None:
    # QEMU's acceptance serial ABI is printable ASCII with CR/LF framing.
    # Reject controls, ANSI escapes, C1 bytes, tabs, and non-ASCII format
    # characters before line normalization so none can split a forbidden
    # identifier into regex-invisible fragments.
    require(
        all(character in "\r\n" or 0x20 <= ord(character) <= 0x7E for character in raw),
        f"C7.7 cold boot {boot} transcript contains non-canonical serial bytes",
    )
    lines = normalize_lines(raw)
    reports = [line for line in lines if C77_FAMILY in line]
    require(
        reports == [C77_PASS],
        f"C7.7 cold boot {boot} report is missing, duplicate, or non-exact",
    )
    require(
        not any(C77_FAIL in line for line in lines),
        f"C7.7 cold boot {boot} reported FAIL",
    )
    require(
        not any(
            re.search(r"\[!\] (fatal|panic)|panicked at", line) for line in lines
        ),
        f"C7.7 cold boot {boot} reported panic/fatal",
    )

    # Reject both durable identifiers and boot-local runtime token renderings
    # anywhere in the transcript.  Plural zero-count fields in the exact marker
    # are intentionally not token values and do not match these expressions.
    diagnostic_lines = [line for line in lines if line != C77_PASS]
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
    )
    forbidden_patterns = (
        re.compile(r"\btoken\b", re.IGNORECASE),
        re.compile(
            r"\b[A-Za-z][A-Za-z0-9]*(?:Token|Id|ID|Identity|Domain|Alias)"
            r"\b"
        ),
        re.compile(
            r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)*_"
            r"(?:token|id|identity|domain|alias)\b",
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
        f"C7.7 cold boot {boot} transcript leaks a raw durable/runtime token",
    )


def verify_exact_no_write_images(
    seed_image: bytes, cold1_image: bytes, cold2_image: bytes
) -> None:
    require(seed_image, "C7.7 exact C7.6 G1 seed is empty")
    require(
        len(seed_image) % BLOCK == 0
        and len(cold1_image) % BLOCK == 0
        and len(cold2_image) % BLOCK == 0,
        "C7.7 powered-off image is not block aligned",
    )
    require(
        seed_image == cold1_image,
        "C7.7 first cold boot changed the exact C7.6 G1 seed",
    )
    require(
        seed_image == cold2_image,
        "C7.7 second cold boot changed the exact C7.6 G1 seed",
    )


def verify_evidence(
    c76_g0_image: bytes,
    c76_g1_image: bytes,
    seed_image: bytes,
    cold1_image: bytes,
    cold2_image: bytes,
    vectors_path: Path,
    c76_boot1_transcript: str,
    c76_boot2_transcript: str,
    c76_boot3_transcript: str,
    c77_boot1_transcript: str,
    c77_boot2_transcript: str,
) -> dict[str, Any]:
    seed = c76.verify_evidence(
        c76_g0_image,
        c76_g1_image,
        seed_image,
        vectors_path,
        c76_boot1_transcript,
        c76_boot2_transcript,
        c76_boot3_transcript,
    )
    require(seed.get("status") == "ok", "composed C7.6 G1 seed proof failed")
    require(
        seed.get("c78_independent_disk_scope") is False,
        "composed seed verifier exceeded the pre-C7.8 scope",
    )
    durable_graph = seed.get("durable_graph", {})
    require(
        durable_graph.get("versions") == 2
        and durable_graph.get("replacements") == 1
        and durable_graph.get("live_root_generation") == 1,
        "C7.7 seed is not the exact final C7.6 G1 fixture",
    )

    verify_c77_boot_transcript(c77_boot1_transcript, 1)
    verify_c77_boot_transcript(c77_boot2_transcript, 2)
    verify_exact_no_write_images(seed_image, cold1_image, cold2_image)

    seed_storage = seed.get("storage", {})
    return {
        "schema": "vibeos.c77.ephemeral-runtime-verifier",
        "version": 1,
        "status": "ok",
        "scope": "exact-c76-g1-fixture-only",
        "storage": {
            "mode": seed_storage.get("mode"),
            "policy_v3": seed_storage.get("policy_v3") is True,
            "seed_checkpoint_generation": seed_storage.get(
                "g1_checkpoint_generation"
            ),
            "seed_versions": 2,
            "seed_replacements": 1,
            "cold_boots": 2,
            "cold_boot1_exact_no_write": True,
            "cold_boot2_exact_no_write": True,
            "physical_bindings": seed_storage.get("physical_bindings"),
        },
        "runtime_evidence": {
            "fresh_tasks_per_boot": 3,
            "fresh_arenas_per_boot": 3,
            "fresh_cspaces_per_boot": 3,
            "fresh_memories_per_boot": 3,
            "memory_bytes_per_boot": 196608,
            "fresh_resource_tables_per_boot": 3,
            "live_resources_per_boot": 4,
            "fresh_fuel_accounts_per_boot": 3,
            "fuel_consumed": 0,
            "fresh_pending_ledgers_per_boot": 3,
            "active_pending_calls_at_cut": 1,
            "pending_cut": "parked",
            "cold_start_empty": True,
            "persisted_numeric_tokens": 0,
            "raw_tokens": 0,
            "raw_ids": 0,
            "runtime_ready": False,
            "guest_calls": 0,
        },
        "guest_marker_is_storage_authority": False,
        "c78_independent_disk_scope": False,
    }


def expect_rejected(action: Callable[[], None], label: str) -> None:
    try:
        action()
    except (VerificationError, ValueError):
        return
    raise VerificationError(f"mutation unexpectedly accepted: {label}")


def selftest(vectors_path: Path) -> dict[str, Any]:
    # Reuse every exact C7.6 codec/signature/history mutation before testing the
    # C7.7-only serial and no-write boundaries.  This remains fixture-specific.
    base = c76.selftest(vectors_path)
    require(base.get("status") == "ok", "composed C7.6 selftest failed")
    require(
        base.get("c78_independent_disk_scope") is False,
        "composed C7.6 selftest exceeded the pre-C7.8 scope",
    )
    verify_c77_boot_transcript(C77_PASS, 1)
    verify_c77_boot_transcript(C77_PASS, 2)
    image = bytes(BLOCK * 2)
    verify_exact_no_write_images(image, image, image)
    cases = int(base["cases"]) + 3

    transcript_mutations = [
        (C77_PASS + "\n" + C77_PASS, "duplicate"),
        (C77_PASS + "\n" + C77_FAIL, "fail-after-pass"),
        (C77_PASS + "\nprefix " + C77_PASS, "prefixed-extra-pass"),
        (C77_PASS + "\nprefix " + C77_FAIL, "prefixed-fail"),
        (C77_PASS + " extra=1", "unknown-field"),
        (C77_PASS.replace("cold_no_write=1", "cold_no_write=0"), "write"),
        (C77_PASS.replace("graph_only=1", "graph_only=0"), "non-graph-state"),
        (
            C77_PASS.replace("fresh_validation=1", "fresh_validation=0"),
            "fresh-validation",
        ),
        (C77_PASS.replace("same_manifest=1", "same_manifest=0"), "manifest"),
        (
            C77_PASS.replace("cold_start_empty=1", "cold_start_empty=0"),
            "non-empty-start",
        ),
        (C77_PASS.replace("fresh_tasks=3", "fresh_tasks=2"), "task-count"),
        (C77_PASS.replace("fresh_arenas=3", "fresh_arenas=2"), "arena-count"),
        (C77_PASS.replace("fresh_cspaces=3", "fresh_cspaces=2"), "cspace-count"),
        (C77_PASS.replace("fresh_memories=3", "fresh_memories=2"), "memory-count"),
        (
            C77_PASS.replace("memory_bytes=196608", "memory_bytes=196607"),
            "memory-bytes",
        ),
        (
            C77_PASS.replace("fresh_resource_tables=3", "fresh_resource_tables=2"),
            "resource-table-count",
        ),
        (C77_PASS.replace("live_resources=4", "live_resources=3"), "resource-count"),
        (
            C77_PASS.replace("fresh_fuel_accounts=3", "fresh_fuel_accounts=2"),
            "fuel-account-count",
        ),
        (C77_PASS.replace("fuel_consumed=0", "fuel_consumed=1"), "fuel-consumed"),
        (
            C77_PASS.replace("fresh_pending_ledgers=3", "fresh_pending_ledgers=2"),
            "pending-ledger-count",
        ),
        (
            C77_PASS.replace("active_pending_calls=1", "active_pending_calls=0"),
            "pending-call-count",
        ),
        (C77_PASS.replace("pending_cut=parked", "pending_cut=ready"), "pending-cut"),
        (C77_PASS.replace("runtime_ready=0", "runtime_ready=1"), "runtime-ready"),
        (C77_PASS.replace("guest_calls=0", "guest_calls=1"), "guest-call"),
        (C77_PASS + "\nResourceToken(7)", "resource-token-leak"),
        (C77_PASS + "\nObjectId(9)", "durable-id-leak"),
        (C77_PASS + "\ntoken=41", "generic-token-leak"),
        (C77_PASS + "\ninstance_token=41", "instance-token-leak"),
        (C77_PASS + "\nArenaId(7)", "arena-id-leak"),
        (C77_PASS + "\nMemoryToken(9)", "memory-token-leak"),
        (C77_PASS + "\npending_call_token: 12", "pending-token-leak"),
        (C77_PASS + "\nborrow_alias=33", "borrow-alias-leak"),
        (C77_PASS + "\nowner_id=44", "owner-id-leak"),
        (C77_PASS + "\nCapability(55)", "capability-leak"),
        (C77_PASS + "\nTaskIdentity(56)", "task-identity-leak"),
        (C77_PASS + "\nBorrowAlias{57}", "borrow-alias-camel-leak"),
        (
            C77_PASS + "\nInstanceContinuationToken(61)",
            "continuation-token-leak",
        ),
        (
            C77_PASS + "\ninstance_continuation_token=62",
            "continuation-token-snake-leak",
        ),
        (C77_PASS + "\nCrossTableBorrowAlias(69)", "cross-borrow-alias-leak"),
        (C77_PASS + "\nHostWakeToken(77)", "host-wake-token-leak"),
        (C77_PASS + "\nStorageV2ObjectToken(81)", "storage-token-leak"),
        (C77_PASS + "\nallocation_domain=72", "allocation-domain-leak"),
        (C77_PASS + "\nCap(73)", "cap-short-leak"),
        (C77_PASS + "\nCapability { raw:75 }", "capability-debug-leak"),
        (C77_PASS + "\nborrow_token=67", "borrow-token-leak"),
        (C77_PASS + "\nInstanceContinuationToken 101", "bare-camel-token-leak"),
        (
            C77_PASS + "\ninstance_continuation_token 102",
            "bare-snake-token-leak",
        ),
        (C77_PASS + "\ntoken 103", "bare-generic-token-leak"),
        (C77_PASS + "\nCap 104", "bare-cap-leak"),
        (C77_PASS + "\nInstanceContinuationToken[105]", "bracket-token-leak"),
        (C77_PASS + "\nCrossTableBorrowAlias<106>", "angle-alias-leak"),
        (
            C77_PASS + '\n{"instance_continuation_token":107,"task_id":108}',
            "json-token-id-leak",
        ),
        (
            C77_PASS + "\nINSTANCE_CONTINUATION_TOKEN=110",
            "uppercase-snake-token-leak",
        ),
        (C77_PASS + "\nTask\x1b[31mId=123", "ansi-task-id-split"),
        (C77_PASS + "\nObject\x1b[0mId(9)", "ansi-object-id-split"),
        (
            C77_PASS + "\ninstance_\x1b[32mtoken=41",
            "ansi-snake-token-split",
        ),
        (C77_PASS + "\nCap\x08ability(55)", "backspace-capability-split"),
        (C77_PASS + "\nTask\u200bId=124", "zero-width-task-id-split"),
        (C77_PASS + "\npanicked at synthetic C7.7 fault", "panic"),
        (C77_FAIL, "failure-only"),
    ]
    for raw, label in transcript_mutations:
        expect_rejected(
            lambda value=raw: verify_c77_boot_transcript(value, 1),
            label,
        )
        cases += 1

    first_changed = bytearray(image)
    first_changed[0] = 1
    second_changed = bytearray(image)
    second_changed[-1] = 1
    image_mutations = [
        (b"", image, image, "empty-seed"),
        (image, image[:-1], image, "misaligned-first-boot"),
        (image, bytes(first_changed), image, "first-boot-write"),
        (image, image, bytes(second_changed), "second-boot-write"),
    ]
    for seed, cold1, cold2, label in image_mutations:
        expect_rejected(
            lambda before=seed, first=cold1, second=cold2: verify_exact_no_write_images(
                before, first, second
            ),
            label,
        )
        cases += 1

    return {
        "schema": "vibeos.c77.ephemeral-runtime-selftest",
        "version": 1,
        "status": "ok",
        "cases": cases,
        "scope": "exact-c76-g1-fixture-only",
        "c78_independent_disk_scope": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path, help="post-C7.7-boot-2 image")
    parser.add_argument("--c76-g0-image", type=Path)
    parser.add_argument("--c76-g1-image", type=Path)
    parser.add_argument("--seed-image", type=Path, help="post-C7.6-boot-3 exact G1")
    parser.add_argument("--cold1-image", type=Path, help="post-C7.7-boot-1 image")
    parser.add_argument("--c76-boot1-log", type=Path)
    parser.add_argument("--c76-boot2-log", type=Path)
    parser.add_argument("--c76-boot3-log", type=Path)
    parser.add_argument("--boot1-log", type=Path, help="first C7.7 cold-boot log")
    parser.add_argument("--boot2-log", type=Path, help="second C7.7 cold-boot log")
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    evidence_args = (
        args.image,
        args.c76_g0_image,
        args.c76_g1_image,
        args.seed_image,
        args.cold1_image,
        args.c76_boot1_log,
        args.c76_boot2_log,
        args.c76_boot3_log,
        args.boot1_log,
        args.boot2_log,
    )
    if any(value is not None for value in evidence_args) and not all(
        value is not None for value in evidence_args
    ):
        parser.error("all seed, cold-boot image, and five boot-log arguments are required")
    if not args.selftest and args.image is None:
        parser.error("provide exact seed/cold-boot evidence and/or --selftest")

    try:
        outputs = []
        if args.selftest:
            outputs.append(selftest(args.vectors))
        if args.image is not None:
            assert args.c76_g0_image is not None
            assert args.c76_g1_image is not None
            assert args.seed_image is not None
            assert args.cold1_image is not None
            assert args.c76_boot1_log is not None
            assert args.c76_boot2_log is not None
            assert args.c76_boot3_log is not None
            assert args.boot1_log is not None
            assert args.boot2_log is not None
            outputs.append(
                verify_evidence(
                    args.c76_g0_image.read_bytes(),
                    args.c76_g1_image.read_bytes(),
                    args.seed_image.read_bytes(),
                    args.cold1_image.read_bytes(),
                    args.image.read_bytes(),
                    args.vectors,
                    args.c76_boot1_log.read_text(
                        encoding="utf-8", errors="replace"
                    ),
                    args.c76_boot2_log.read_text(
                        encoding="utf-8", errors="replace"
                    ),
                    args.c76_boot3_log.read_text(
                        encoding="utf-8", errors="replace"
                    ),
                    args.boot1_log.read_text(encoding="utf-8", errors="replace"),
                    args.boot2_log.read_text(encoding="utf-8", errors="replace"),
                )
            )
        for output in outputs:
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    except (OSError, UnicodeError, ValueError, c76.VerificationError) as error:
        print(f"FAIL verify-c77-ephemeral-runtime: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
