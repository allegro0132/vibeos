#!/usr/bin/env python3
"""Verify C8.13-E3 fixed-QEMU code-10 Reference Types evidence."""
from __future__ import annotations
import copy, hashlib, importlib.util, pathlib, sys

HERE = pathlib.Path(__file__).resolve()
SPEC = importlib.util.spec_from_file_location("_vibeos_c813_e3_base", HERE.with_name("verify-c812-r3-reference-evidence.py"))
if SPEC is None or SPEC.loader is None: raise RuntimeError("cannot load fixed-QEMU verifier")
OLD = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = OLD; SPEC.loader.exec_module(OLD)
BASE = OLD.BASE
ORIGINAL_VALIDATE_ENVIRONMENT = OLD.ORIGINAL_VALIDATE_ENVIRONMENT
EXPECTED_SEMANTIC = "6a654a8428f4f4479db637ab90d391c989c43b2c67dfc51570bd4ac617cc1a49"
EXPECTED_MANIFEST_SHA256 = "f27036d546cb62e89f8931c65281656d61f034514bffd341510289a865938e38"
EXPECTED_MANIFEST_BYTES = 2_284
CASE_IDS = ["nullable-funcref-execution", "table-operations-execution", "externref-containment", "reference-boundary-containment", "adjacent-proposals", "current-engine-binding", "predecessor-inertness", "fuel-containment"]
PREFIXES = {"META":"VIBE_C813_E3_META ", "CASE":"VIBE_C813_E3_CASE ", "CONTAINMENT":"VIBE_C813_E3_CONTAINMENT ", "END":"VIBE_C813_E3_END ", "PASS":"VIBE_C813_E3_PASS "}
SEMANTIC_DOMAIN = b"vibeos.c813.e3.reference.fixed-qemu.semantic.v1\0"
BASE.__file__ = str(HERE)
BASE.SUITE_ID = "vibeos.c813.e3.reference-fixed-qemu"
BASE.RUN_ID_DOMAIN = b"vibeos.c813.e3.reference-fixed-qemu.run.v1\0"
BASE.EXPECTED_COMPONENT_SHA256 = "38b29ea038466e0b3c75b6477dae6f91d6addd5ab97ffefccaaca638ae1ec8c0"
BASE.EXPECTED_MANIFEST_SHA256 = EXPECTED_MANIFEST_SHA256
BASE.EXPECTED_MANIFEST_BYTES = EXPECTED_MANIFEST_BYTES
BASE.EXPECTED_SEMANTIC_SHA256 = EXPECTED_SEMANTIC

def records(uart, family):
    prefix = PREFIXES[family]
    try: text = uart.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error: BASE.fail(f"UART is not strict UTF-8: {error}")
    found=[]
    for line_number,line in enumerate(text.splitlines(),1):
        if "VIBE_C813_E3_" in line and not line.startswith("VIBE_C813_E3_"): BASE.fail(f"family text not column-zero on line {line_number}")
        if line.startswith(prefix):
            payload=line[len(prefix):]; value=BASE.strict_json_text(payload,f"{family} line {line_number}")
            if not isinstance(value,dict) or BASE.canonical_json(value).decode()!=payload: BASE.fail(f"{family} not canonical")
            found.append(BASE.Record(family,value,line_number))
    return found

def semantic_digest(data):
    digest=hashlib.sha256(SEMANTIC_DOMAIN)
    for record in data:
        payload=BASE.canonical_json(record.value); digest.update(len(payload).to_bytes(8,"big")); digest.update(payload)
    return digest.hexdigest()

def validate_semantics(uart, expected):
    text=uart.decode("utf-8",errors="strict")
    for line_number,line in enumerate(text.splitlines(),1):
        if line.startswith("VIBE_C813_E3_") and not any(line.startswith(p) for p in PREFIXES.values()) and not line.startswith("VIBE_C813_E3_FAIL"): BASE.fail(f"unknown family on line {line_number}")
    meta=records(uart,"META"); cases=records(uart,"CASE"); containment=records(uart,"CONTAINMENT"); endings=records(uart,"END"); passings=records(uart,"PASS")
    if b"VIBE_C813_E3_FAIL" in uart: BASE.fail("explicit failure")
    if [len(meta),len(cases),len(containment),len(endings),len(passings)] != [1,8,1,1,1]: BASE.fail("record counts differ")
    expected_meta={"artifact_abi":10,"artifact_profile_code":10,"challenge":expected["challenge"],"code5_inert":True,"code9_inert":True,"component_profile":7,"core_profile":7,"engine":"vibeos-wasmi-reference-executable@1.1.0-vibeos-ref2.1","manifest_sha256":expected["manifest_sha256"],"node":"C8.13-E3","physical_inputs":0,"release_authorized_before_qualification":False,"run_id":expected["run_id"],"runtime_abi":10,"source_commit":expected["source"]["commit"],"source_tree":expected["source"]["tree"],"stage":"executable","transcript_schema_sha256":expected["transcript_schema_sha256"],"world":"vibe:references/runtime@1.0.0"}
    if meta[0].value != expected_meta: BASE.fail("META differs")
    for index,record in enumerate(cases):
        if record.value != {"id":CASE_IDS[index],"passed":True}: BASE.fail(f"CASE[{index}] differs")
    exact={"code5_inert":True,"code9_inert":True,"durable_authorized":False,"migration_authorized":False,"passed":True}
    if containment[0].value != exact: BASE.fail("CONTAINMENT differs")
    data=cases+containment; semantic=semantic_digest(data)
    if semantic != EXPECTED_SEMANTIC or expected["expected_semantic_sha256"] != semantic: BASE.fail("semantic differs")
    terminal={"challenge":expected["challenge"],"run_id":expected["run_id"],"semantic_sha256":semantic}
    if endings[0].value != terminal or passings[0].value != terminal: BASE.fail("terminal differs")
    return BASE.VerifiedTranscript(meta[0].value,tuple(data),endings[0].value,passings[0].value,semantic,hashlib.sha256(uart).hexdigest(),len(uart))

def validate_environment(value, uart, *, verify_self_identity=True, expected_semantic_sha256=EXPECTED_SEMANTIC):
    if not isinstance(value,dict) or value.get("schema")!="vibeos.c813.e3.reference-fixed-qemu.environment" or value.get("suite_id")!=BASE.SUITE_ID: BASE.fail("environment identity differs")
    if value.get("evidence_sha256") != BASE.environment_evidence_sha256(value): BASE.fail("environment digest differs")
    build=value.get("build")
    if not isinstance(build,dict) or build.get("feature")!="wasm-c813-e3-reference-qemu-qualification": BASE.fail("build feature differs")
    transformed=copy.deepcopy(value); transformed["schema"]="vibeos.c88.f5.float-target.environment"; transformed["build"]["feature"]="wasm-c88-f5-float-qemu-acceptance"; transformed["evidence_sha256"]=BASE.environment_evidence_sha256(transformed)
    validated=ORIGINAL_VALIDATE_ENVIRONMENT(transformed,uart,verify_self_identity=False,expected_semantic_sha256=expected_semantic_sha256)
    if verify_self_identity:
        source=value["source"]
        contracts=((BASE.identity_record(value["manifest"],"manifest"),BASE.ROOT/"acceptance/wasm-reference-target/artifacts/c813-e3-qualification-manifest.json","manifest"),(BASE.identity_record(value["producer"],"producer"),BASE.ROOT/"kernel/src/wasm_reference_executable_target.rs","producer"),(BASE.identity_record(value["qualification"],"qualification"),BASE.ROOT/"acceptance/wasm-reference-target/src/lib.rs","qualification"),(BASE.identity_record(value["runner"],"runner"),HERE.with_name("qemu-c813-e3-reference.py"),"runner"),(BASE.identity_record(value["verifier"],"verifier"),HERE,"verifier"),(BASE.identity_record(value["elf_auditor"],"ELF auditor"),BASE.ROOT/"scripts/verify-c88-f5-riscv-elf.py","ELF auditor"))
        for identity,path,label in contracts: BASE.require_local_identity(identity,path,label)
        cargo_lock,cargo_config=BASE.validate_dependency_archives(value["dependency_archives"],verify_local_identity=True)
        BASE.require_git_source_membership(source,contracts+((cargo_lock,BASE.ROOT/"Cargo.lock","Cargo.lock"),(cargo_config,BASE.ROOT/"firmware/.cargo/config.toml","Cargo config")))
        BASE.require_local_identity(BASE.identity_record(value["python"],"Python interpreter"),pathlib.Path(sys.executable).resolve(strict=True),"Python interpreter",maximum=BASE.MAX_KERNEL_BYTES)
    return validated

def verify_uart_bytes(uart,environment_value,*,verify_self_identity=True,expected_semantic_sha256=EXPECTED_SEMANTIC):
    validate_environment(environment_value,uart,verify_self_identity=verify_self_identity,expected_semantic_sha256=expected_semantic_sha256)
    return validate_semantics(uart,environment_value)

def selftest():
    source={"commit":"1"*40,"tree":"2"*40}; expected={"source":source,"challenge":"3"*64,"run_id":"4"*64,"manifest_sha256":"5"*64,"transcript_schema_sha256":"6"*64,"expected_semantic_sha256":EXPECTED_SEMANTIC}
    meta={"artifact_abi":10,"artifact_profile_code":10,"challenge":expected["challenge"],"code5_inert":True,"code9_inert":True,"component_profile":7,"core_profile":7,"engine":"vibeos-wasmi-reference-executable@1.1.0-vibeos-ref2.1","manifest_sha256":expected["manifest_sha256"],"node":"C8.13-E3","physical_inputs":0,"release_authorized_before_qualification":False,"run_id":expected["run_id"],"runtime_abi":10,"source_commit":source["commit"],"source_tree":source["tree"],"stage":"executable","transcript_schema_sha256":expected["transcript_schema_sha256"],"world":"vibe:references/runtime@1.0.0"}
    lines=[PREFIXES["META"]+BASE.canonical_json(meta).decode()]+[PREFIXES["CASE"]+BASE.canonical_json({"id":case,"passed":True}).decode() for case in CASE_IDS]
    lines.append(PREFIXES["CONTAINMENT"]+BASE.canonical_json({"code5_inert":True,"code9_inert":True,"durable_authorized":False,"migration_authorized":False,"passed":True}).decode())
    terminal={"challenge":expected["challenge"],"run_id":expected["run_id"],"semantic_sha256":EXPECTED_SEMANTIC}; lines += [PREFIXES["END"]+BASE.canonical_json(terminal).decode(),PREFIXES["PASS"]+BASE.canonical_json(terminal).decode()]
    uart=("\n".join(lines)+"\n").encode(); validate_semantics(uart,expected)
    for mutation in (uart.replace(b'"artifact_profile_code":10',b'"artifact_profile_code":9',1),uart.replace(b'"passed":true',b'"passed":false',1),uart+b"VIBE_C813_E3_FAIL {}\n"):
        try: validate_semantics(mutation,expected)
        except BASE.VerificationError: continue
        BASE.fail("mutation accepted")
    print("verify-c813-e3-reference-evidence.py selftest: PASS cases=3 records=9")

BASE.validate_environment=validate_environment; BASE.verify_uart_bytes=verify_uart_bytes; BASE.selftest=selftest
if __name__ == "__main__": raise SystemExit(BASE.main())
