#!/usr/bin/env python3
"""Verify sealed C8.13-E3 fixed-QEMU qualification receipts and decision."""
import argparse, copy, hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"acceptance/wasm-reference-target/artifacts/c813-e3-fixed-qemu-qualification-v1-contract.json"
CONTRACT_BYTES=3203
CONTRACT_SHA256="510941c382f1069cd2baae16b5e3f04baac8b27f4e3f9b6e5d79f1b205baedff"
def require(v,m):
    if not v: raise RuntimeError(m)
def read(path): return path.read_bytes()
def identity(spec):
    raw=read(ROOT/spec["path"]); require(len(raw)==spec["bytes"] and hashlib.sha256(raw).hexdigest()==spec["sha256"],f"identity {spec['path']}"); return json.loads(raw)
def validate(value):
    require(value["schema"]=="vibeos.c813.e3.fixed-qemu-qualification-v1.contract" and value["status"]=="c813-e3-qualified-sealed-reference-runtime-released","contract")
    require(value["identity"]["artifact_profile_code"]==10 and value["identity"]["runtime_abi"]==10 and value["identity"]["stage"]=="executable","identity")
    require(value["qualification"]=={"elf_no_native_float_helpers":True,"elf_no_riscv_f_d_or_v":True,"normal_verified":True,"optimized_verified":True,"platform":"qemu-virt-rv64-tcg-icount-v1","qemu_boots":1},"qualification")
    require(value["authority"]["sealed_volatile_code10_runtime_released"] and not value["authority"]["durable_publication_authorized"] and not value["authority"]["migration_authorized"] and not value["authority"]["ordinary_command_authorized"],"authority")
    require(value["boundaries"]["code5_permanently_inert"] and not value["boundaries"]["code9_current_engine"] and not value["boundaries"]["code9_execution_authorized"] and not value["boundaries"]["code9_promoted"],"predecessors")
    require(value["hardware_policy"]=={"duo_gate_effect":False,"duo_inputs":0,"fixed_qemu_is_hardware_equivalent":False,"physical_provenance":"not-claimed"},"hardware")
    ev=value["evidence"]; normal=identity(ev["normal_receipt"]); optimized=identity(ev["optimized_receipt"]); manifest=identity(ev["manifest"]); decision=identity(ev["release_decision"])
    for receipt,mode in ((normal,"normal"),(optimized,"optimized")):
        require(receipt["mode"]==mode and receipt["status"]=="pass" and receipt["records"]==9 and receipt["physical_inputs"]==0,"receipt")
        require(receipt["source_commit"]==value["basis"]["source_commit"] and receipt["source_tree"]==value["basis"]["source_tree"] and receipt["run_id"]==ev["run_id"] and receipt["semantic_sha256"]==ev["semantic_sha256"],"binding")
    require(manifest["qualification"]["qemu_boots"]==1 and manifest["hardware"]["physical_inputs_required"]==0,"manifest")
    require(decision["authority"]["sealed_volatile_code10_runtime"] and decision["decision"]=="release-sealed-volatile-code10-reference-runtime","decision")
    require(value["roadmap"]=={"completed_node":"C8.13-E3","current_position":"c813-e3-qualified-sealed-reference-runtime-released","next_node":"unallocated"},"roadmap")
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--selftest",action="store_true"); parser.add_argument("--check-contract",action="store_true"); args=parser.parse_args()
    raw=read(CONTRACT); require(len(raw)==CONTRACT_BYTES and hashlib.sha256(raw).hexdigest()==CONTRACT_SHA256,"contract identity"); value=json.loads(raw); require((json.dumps(value,sort_keys=True,indent=2)+"\n").encode()==raw,"canonical"); validate(value)
    if args.selftest:
        changed=copy.deepcopy(value); changed["boundaries"]["code5_permanently_inert"]=False
        try: validate(changed)
        except RuntimeError: pass
        else: raise RuntimeError("mutation accepted")
    print("C8.13-E3 fixed-QEMU qualification verification: PASS"); return 0
if __name__=="__main__": raise SystemExit(main())
