#!/usr/bin/env python3
"""C7.5 two-boot revalidation evidence verifier.

This deliberately composes the already-frozen C7.4 powered-off Storage V2
parser instead of claiming the broader independent raw-disk coverage reserved
for C7.8. It additionally accepts exactly one first-install serial report and
one cold-existing serial report. Serial evidence is never treated as storage
authority: the disk is parsed only after both QEMU processes have stopped.
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
DEFAULT_VECTORS = ROOT / "policy/image/artifacts/c73-authenticated-admission.vectors"

COMMON = (
    "physical_readback=1 fresh_component=1 fresh_core=1 fresh_wit=1 "
    "fresh_adapter_absence=1 fresh_hashes=1 fresh_limits=1 fresh_signer=1 "
    "fresh_engine_identity=1 publication_after_validation=1 "
    "early_runtime_objects=0 component_cspaces=0 component_resources=0 "
    "component_tasks=0 runtime_ready=0 guest_calls=0 raw_ids=0 "
    "ambient_lookup=0 vsh=0"
)
BOOT1_PASS = (
    "WASM_C75_BOOT_REVALIDATION PASS durable_state=installed "
    "image_candidate=1 preappend_validation=1 " + COMMON
)
BOOT2_PASS = (
    "WASM_C75_BOOT_REVALIDATION PASS durable_state=existing "
    "image_candidate=0 preappend_validation=0 " + COMMON
)
FAIL = "WASM_C75_BOOT_REVALIDATION FAIL"


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


c74 = load_module(
    "verify-c74-crash-safe-publication.py", "vibeos_c75_c74_disk_verifier"
)


def normalize_lines(raw: str) -> list[str]:
    return [line for line in raw.replace("\r", "\n").splitlines() if line]


def verify_boot_transcript(raw: str, expected: str) -> None:
    lines = normalize_lines(raw)
    reports = [line for line in lines if line.startswith("WASM_C75_BOOT_REVALIDATION")]
    require(reports == [expected], "C7.5 report is missing, duplicated, or non-exact")
    require(FAIL not in lines, "C7.5 guest reported failure")
    require(
        not any(
            re.search(r"\[!\] (fatal|panic)|panicked at", line) for line in lines
        ),
        "C7.5 guest reported a panic or fatal error",
    )
    forbidden = (
        "ObjectId",
        "SpaceId",
        "DerivationId",
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
        "C7.5 report leaks forbidden identity material",
    )


def verify_evidence(
    image: bytes,
    vectors_path: Path,
    boot1_transcript: str,
    boot2_transcript: str,
) -> dict[str, Any]:
    verify_boot_transcript(boot1_transcript, BOOT1_PASS)
    verify_boot_transcript(boot2_transcript, BOOT2_PASS)
    physical = c74.verify_image(image, vectors_path)
    return {
        "schema": "vibeos.c75.boot-revalidation-verifier",
        "version": 1,
        "status": "ok",
        "storage": physical["storage"],
        "logical": physical["logical"],
        "physical_bindings": physical["physical_bindings"],
        "boot_evidence": {
            "boot1": "installed",
            "boot2": "existing",
            "fresh_validations": 2,
            "image_candidate_uses": 1,
            "prevalidation_runtime_objects": 0,
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
    # Retain every C7.4 disk/layout/signature mutation case, then prove that
    # the boot-role discriminator and exact no-runtime-object report are live.
    base = c74.selftest(vectors_path)
    require(base["status"] == "ok", "C7.4 composed selftest did not pass")
    verify_boot_transcript(BOOT1_PASS, BOOT1_PASS)
    verify_boot_transcript(BOOT2_PASS, BOOT2_PASS)
    cases = int(base["cases"]) + 2

    invalid = [
        (BOOT1_PASS + "\n" + BOOT1_PASS, BOOT1_PASS, "duplicate-boot1"),
        (BOOT2_PASS + "\n" + FAIL, BOOT2_PASS, "fail-after-pass"),
        (BOOT2_PASS, BOOT1_PASS, "existing-as-install"),
        (BOOT1_PASS, BOOT2_PASS, "install-as-existing"),
        (BOOT1_PASS + " extra=1", BOOT1_PASS, "unknown-field"),
        (
            BOOT1_PASS.replace("early_runtime_objects=0", "early_runtime_objects=1"),
            BOOT1_PASS,
            "early-object",
        ),
        (
            BOOT2_PASS.replace("image_candidate=0", "image_candidate=1"),
            BOOT2_PASS,
            "existing-image-candidate",
        ),
        (BOOT2_PASS + "\npanicked at synthetic C7.5 fault", BOOT2_PASS, "panic"),
    ]
    for raw, expected, label in invalid:
        expect_rejected(
            lambda value=raw, marker=expected: verify_boot_transcript(value, marker),
            label,
        )
        cases += 1
    return {
        "schema": "vibeos.c75.boot-revalidation-selftest",
        "version": 1,
        "status": "ok",
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", type=Path)
    parser.add_argument("--boot1-log", type=Path)
    parser.add_argument("--boot2-log", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    args = parser.parse_args()
    if (args.image is None and (args.boot1_log is not None or args.boot2_log is not None)) or (
        args.image is not None and (args.boot1_log is None or args.boot2_log is None)
    ):
        parser.error("image, --boot1-log, and --boot2-log must be supplied together")
    if args.image is None and not args.selftest:
        parser.error("provide powered-off boot evidence and/or --selftest")
    try:
        outputs = []
        if args.selftest:
            outputs.append(selftest(args.vectors))
        if args.image is not None:
            require(args.boot1_log is not None and args.boot2_log is not None, "logs absent")
            outputs.append(
                verify_evidence(
                    args.image.read_bytes(),
                    args.vectors,
                    args.boot1_log.read_text(encoding="utf-8", errors="replace"),
                    args.boot2_log.read_text(encoding="utf-8", errors="replace"),
                )
            )
        for output in outputs:
            print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    except (OSError, UnicodeError, ValueError, c74.VerificationError) as error:
        print(f"FAIL verify-c75-boot-revalidation: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
