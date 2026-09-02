#!/usr/bin/env python3
"""Verify C8.13-E3 pre-evidence fixed-QEMU harness without booting QEMU."""
import argparse, hashlib, json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/"acceptance/wasm-reference-target/artifacts/c813-e3-qualification-manifest.json"
EXPECTED_SHA="f27036d546cb62e89f8931c65281656d61f034514bffd341510289a865938e38"
EXPECTED_BYTES=2284
def require(v,m):
    if not v: raise RuntimeError(m)
def check():
    raw=MANIFEST.read_bytes(); require(len(raw)==EXPECTED_BYTES and hashlib.sha256(raw).hexdigest()==EXPECTED_SHA,"manifest identity")
    value=json.loads(raw); require((json.dumps(value,sort_keys=True,indent=2)+"\n").encode()==raw,"manifest canonical")
    require(value["artifact_profile_code"]==10 and value["runtime_abi"]==10 and value["stage"]=="executable","identity")
    require(value["qualification"]["qemu_boots"]==1 and value["hardware"]["physical_inputs_required"]==0 and value["hardware"]["physical_inputs_permitted"]==0,"qualification policy")
    require(value["isolation"]["code5_permanently_inert"] and not value["isolation"]["code9_current_engine"] and not value["isolation"]["code9_execution_authorized"],"predecessor isolation")
    for path,token in (("kernel/src/wasm_reference_executable_target.rs","VIBE_C813_E3_PASS"),("scripts/qemu-c813-e3-reference.py","wasm-c813-e3-reference-qemu-qualification"),("scripts/verify-c813-e3-reference-evidence.py","EXPECTED_SEMANTIC")):
        data=(ROOT/path).read_text(); require(token in data,f"missing {path}")
    require(not list((ROOT/"acceptance/wasm-reference-target/artifacts").glob("c813-e3-*-receipt.json")),"formal receipts exist before campaign")
    print("c813_e3_harness_status=pass"); print("qemu_boots_per_formal_campaign=1"); print("physical_inputs=0")
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--selftest",action="store_true"); parser.parse_args(); check(); return 0
if __name__=="__main__": raise SystemExit(main())
