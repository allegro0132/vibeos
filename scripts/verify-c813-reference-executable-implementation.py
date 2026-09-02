#!/usr/bin/env python3
"""Verify the C8.13-E2 independently numbered implementation boundary."""
import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "acceptance/wasm-reference-target/artifacts/c813-reference-executable-implementation-v1-contract.json"

def require(value, message):
    if not value: raise RuntimeError(message)

def validate(value):
    require(value["schema"] == "vibeos.c813.reference-executable-implementation-v1.contract", "schema")
    require(value["identity"] == {"artifact_abi": 10, "artifact_profile_code": 10, "component_profile": 7, "core_profile": 7, "runtime_abi": 10, "stage": "executable"}, "identity")
    require(value["engine"]["package"] == "vibeos-wasmi-reference-executable" and value["engine"]["version"] == "1.1.0-vibeos-ref2.1" and value["engine"]["manifest_sha256"] == "1cd48cdf8897bee4d20a4bd29355f6309b7b4bb699063b1a5cd180534e733f32", "engine")
    require(value["implementation"]["fuel_bounded"] and value["implementation"]["imports_permitted"] == 0 and value["implementation"]["volatile_only"], "runtime")
    require(value["authority"]["sealed_volatile_admission"] and not any(value["authority"][key] for key in ("durable_publication", "migration", "ordinary_command", "production", "release")), "authority")
    require(value["boundaries"]["code5_permanently_inert"] and not value["boundaries"]["code9_current"] and not value["boundaries"]["code9_executable"] and value["boundaries"]["physical_inputs"] == 0, "containment")
    require(value["riscv_object_audit"]["status"] == "passed" and value["riscv_object_audit"]["target"] == "riscv64imac-unknown-none-elf" and not value["riscv_object_audit"]["native_float_helpers_reachable"], "RISC-V audit")
    require(value["roadmap"]["current_position"] == "c813-e2-reference-executable-implemented-pre-qemu" and value["roadmap"]["next_node"] == "C8.13-E3", "roadmap")

def verify_files(value):
    for key in ("facade", "executor", "admission"):
        path = ROOT / value["implementation"][key]
        require(path.is_file() and not path.is_symlink(), f"missing {key}")
    text = "\n".join((ROOT / p).read_text() for p in ("component-format/src/lib.rs", "component-format/src/engine.rs", "wasm-runtime/src/lib.rs"))
    for token in ("PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE", "vibeos-wasmi-reference-executable", "PROFILE_2_SYNC_FLOAT"):
        require(token in text, f"missing {token}")

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--selftest", action="store_true"); args = parser.parse_args()
    raw = CONTRACT.read_bytes(); value = json.loads(raw)
    require((json.dumps(value, sort_keys=True, indent=2) + "\n").encode() == raw, "noncanonical")
    validate(value); verify_files(value)
    if args.selftest:
        changed = copy.deepcopy(value); changed["boundaries"]["code5_permanently_inert"] = False
        try: validate(changed)
        except RuntimeError: pass
        else: raise RuntimeError("mutation accepted")
    print("c813_e2_status=pass")
    print("current_roadmap_position=c813-e2-reference-executable-implemented-pre-qemu")
    return 0

if __name__ == "__main__": raise SystemExit(main())
