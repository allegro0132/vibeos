#!/usr/bin/env python3
"""Verify the C8.4 SSH managed-child trusted live-sample boundary."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import tomllib
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
STREAM_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-verified-stream.py"
PUBLISHER_VERIFIER_PATH = ROOT / "scripts/verify-c84-profile-publisher.py"
SSHD_MANIFEST = ROOT / "components/sshd/Cargo.toml"
SSHD_SOURCE = ROOT / "components/sshd/src/lib.rs"
RUNTIME_SOURCE = ROOT / "component-runtime/src/sync.rs"
COMPONENT_SOURCE = ROOT / "kernel/src/component_instances.rs"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"
TESTING = ROOT / "TESTING.md"
DECISION_DOC = ROOT / "docs/WASM_AOT_DECISION.md"
ROADMAP = ROOT / "docs/WASM_ROADMAP.md"
CI = ROOT / ".github/workflows/ci.yml"
QEMU_SCRIPT = ROOT / "scripts/qemu-c84-ssh-managed-child-trusted-sample-test.sh"
PEER_SCRIPT = ROOT / "scripts/c84-ssh-managed-child-trusted-sample-peer.py"
PEER_DEPENDENCY_PATHS = (
    ROOT / "scripts/c84-ssh-managed-child-finish-verify-peer.py",
    ROOT / "scripts/c84-ssh-managed-child-irq-overlay-peer.py",
    ROOT / "scripts/c84-ssh-managed-child-phase-sidecar-peer.py",
    ROOT / "scripts/c84-ssh-managed-child-core-peer.py",
    ROOT / "scripts/openssh-peer.py",
    ROOT / "scripts/verify-c84-ssh-profile-request-parent.py",
)

FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
SSHD_FEATURE = "c84-profile-trusted-sample"
FINISH_FEATURE = "wasm-c84-ssh-managed-child-finish-verify"
FINISH_QEMU_FEATURE = f"{FINISH_FEATURE}-qemu-acceptance"
VERIFIED_FEATURE = "wasm-c84-ssh-managed-child-verified-stream"
VERIFIED_QEMU_FEATURE = f"{VERIFIED_FEATURE}-qemu-acceptance"
COLLECTOR_FEATURE = "wasm-c84-ssh-managed-child-single-boot-collector"
COLLECTOR_QEMU_FEATURE = (
    f"{COLLECTOR_FEATURE}-qemu-acceptance"
)
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_TRUSTED_SAMPLE"
SUCCESSOR_SUFFIX = (
    "finish=1 verify=1 bundle=trusted discard=trusted_sample_abandoned "
    "ack=1 ready_epoch={}"
)
NORMAL_MARKER = (
    f"{FAMILY} RESPONSE epoch={{}} status=0 exact_success=1 full_drain=1 "
    "read_chunks={} write_chunks={} stdout_bytes={} "
    "stdout_sha256=791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27 "
    "fuel_consumed={} poll_quanta={} poll_exact=1 logical_live_after=0 "
    "timed_out=0 bundle=trusted finish=1 verify=1 "
    "discard=trusted_sample_abandoned emitted=0 stored=1 ack=1 ready_epoch={}"
)
DROP_MARKER = (
    f"{FAMILY} DROP epoch={{}} cancel=lease_cancelled bundle=0 finish=0 "
    "verify=0 discard=0 emitted=0 stored=1 ack=1 ready_epoch={}"
)
COMMAND = (
    "python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py "
    "--selftest --check-source"
)
QEMU_COMMAND = "./scripts/qemu-c84-ssh-managed-child-trusted-sample-test.sh"
SSHD_TEST_STEP = (
    "      - name: Test the C8.4 trusted SSH terminal seam\n"
    "        run: |\n"
    '          RUSTC="$VIBEOS_RUSTC" RUSTDOC="$VIBEOS_RUSTDOC" \\\n'
    '            rustup run "$VIBEOS_TOOLCHAIN" cargo test --locked \\\n'
    "              -p vibeos-sshd --no-default-features \\\n"
    "              --features c84-profile-trusted-sample,native-revoke-target-acceptance \\\n"
    "              --verbose"
)
SOURCE_CI_STEP = (
    "      - name: Verify the C8.4 trusted live-sample boundary\n"
    f"        run: {COMMAND}"
)
PEER_CI_STEP = (
    "      - name: Test the C8.4 trusted transcript parser\n"
    "        run: python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py --selftest"
)
QEMU_SCRIPT_SHA256 = "696bd95b286808e0f9c732258ba86caa46d81f75ce7ebd41fc30d0922a6e0f76"
PEER_SCRIPT_SHA256 = "928931ae0f2fbbc3ad769546037a41f0301dac872899bfa5e40c77dc8953ac68"
PEER_DEPENDENCY_SHA256 = (
    "41b7e03a52fec285c3a5d35967047d708c683334890fb52e3f31db64cbf2c6b6",
    "6814a9c66a5b5d678b47181a5607537697c8ac8349c59acc79d5ef6291f0972d",
    "f0a9b77bab25c57428ed111f4c8e9531e7486c46e5d4a4b7cc2c011d970f4fa9",
    "11e792ab2dadd67653ba2c4fbfb79c5424cf47ea71e8ed87bdbf67c815c7ea0a",
    "00d5002a8f2725c275995b1eff5d469f1d1eac1741b1eaef3f3623c3c746ac8c",
    "a45b1ced38ced134f3948a77b678cfa50bae74db3d7e0576e7d54a7a6718b302",
)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


STREAM = load_module(STREAM_VERIFIER_PATH, "vibeos_c84_trusted_stream_verifier")
PUBLISHER = load_module(PUBLISHER_VERIFIER_PATH, "vibeos_c84_trusted_publisher_verifier")
PHASE = STREAM.PHASE
CORE = STREAM.CORE
IRQ = STREAM.IRQ


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def semantic(value: str) -> str:
    return STREAM.semantic(value)


def masked(value: str) -> str:
    return STREAM.masked(value)


def comment_masked(value: str) -> str:
    return STREAM.comment_masked(value)


def find_scope(source: str, header: str, label: str):
    try:
        return STREAM.find_scope(source, header, label)
    except STREAM.VerificationError as error:
        raise VerificationError(str(error)) from error


def find_function(scope, name: str, label: str):
    try:
        return STREAM.find_function(scope, name, label)
    except STREAM.VerificationError as error:
        raise VerificationError(str(error)) from error


def ordered(value: str, needles: tuple[str, ...], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), value)]
        require(len(matches) == 1, f"{label}: {needle!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


@dataclass(frozen=True)
class Inputs:
    stream_predecessor: object
    publisher_predecessor: object
    sshd_manifest: bytes
    sshd: str
    runtime: str
    component: str
    slot: str
    ssh: str
    kernel_root: str
    kernel_manifest: bytes
    qemu_manifest: bytes
    milkv_manifest: bytes
    testing: str
    decision_doc: str
    roadmap: str
    ci: str
    qemu_script: bytes
    peer_script: bytes
    peer_dependencies: tuple[bytes, ...]


def load_inputs() -> Inputs:
    return Inputs(
        stream_predecessor=STREAM.load_inputs(),
        publisher_predecessor=PUBLISHER.load_inputs(),
        sshd_manifest=SSHD_MANIFEST.read_bytes(),
        sshd=SSHD_SOURCE.read_text(encoding="utf-8"),
        runtime=RUNTIME_SOURCE.read_text(encoding="utf-8"),
        component=COMPONENT_SOURCE.read_text(encoding="utf-8"),
        slot=SLOT_SOURCE.read_text(encoding="utf-8"),
        ssh=SSH_SOURCE.read_text(encoding="utf-8"),
        kernel_root=KERNEL_ROOT_SOURCE.read_text(encoding="utf-8"),
        kernel_manifest=KERNEL_MANIFEST.read_bytes(),
        qemu_manifest=QEMU_MANIFEST.read_bytes(),
        milkv_manifest=MILKV_MANIFEST.read_bytes(),
        testing=TESTING.read_text(encoding="utf-8"),
        decision_doc=DECISION_DOC.read_text(encoding="utf-8"),
        roadmap=ROADMAP.read_text(encoding="utf-8"),
        ci=CI.read_text(encoding="utf-8"),
        qemu_script=QEMU_SCRIPT.read_bytes(),
        peer_script=PEER_SCRIPT.read_bytes(),
        peer_dependencies=tuple(path.read_bytes() for path in PEER_DEPENDENCY_PATHS),
    )


def verify_features(inputs: Inputs) -> None:
    kernel = PHASE.parse_features(inputs.kernel_manifest, "kernel")
    qemu = PHASE.parse_features(inputs.qemu_manifest, "QEMU firmware")
    milkv = PHASE.parse_features(inputs.milkv_manifest, "Milk-V firmware")
    sshd = PHASE.parse_features(inputs.sshd_manifest, "SSHD")
    require(
        kernel.get(FEATURE) == [FINISH_FEATURE, f"vibeos-sshd/{SSHD_FEATURE}"],
        "trusted-sample base is not the exact finish/SSHD successor",
    )
    require(
        kernel.get(QEMU_FEATURE) == [FEATURE, FINISH_QEMU_FEATURE],
        "kernel trusted-sample QEMU closure differs",
    )
    require(
        qemu.get(QEMU_FEATURE)
        == [FINISH_QEMU_FEATURE, f"vibeos-kernel/{QEMU_FEATURE}"],
        "QEMU firmware trusted-sample closure differs",
    )
    require(
        milkv.get(FEATURE) == [f"vibeos-kernel/{FEATURE}"],
        "Milk-V does not forward only the trusted-sample base",
    )
    require(QEMU_FEATURE not in milkv, "Milk-V exposes the trusted QEMU gate")
    require(
        sshd.get(SSHD_FEATURE) == ["c84-profile-phase-sidecar"],
        "SSHD trusted terminal seam does not inherit the exact phase owner",
    )
    for label, features, name in (
        ("kernel", kernel, FEATURE),
        ("kernel", kernel, QEMU_FEATURE),
        ("QEMU firmware", qemu, QEMU_FEATURE),
        ("Milk-V firmware", milkv, FEATURE),
        ("SSHD", sshd, SSHD_FEATURE),
    ):
        require(
            name not in PHASE.local_feature_closure(features, features.get("default", [])),
            f"{label} enables {name} by default",
        )
    base = PHASE.local_feature_closure(kernel, [FEATURE])
    require(FINISH_FEATURE in base, "trusted base omits finish/verify")
    require(VERIFIED_FEATURE not in base, "trusted base inherits verified-stream")
    require(
        not any(name.endswith("-qemu-acceptance") for name in base),
        "trusted base selects QEMU telemetry",
    )
    qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_FEATURE])
    require(
        FEATURE in qemu_closure and FINISH_QEMU_FEATURE in qemu_closure,
        "trusted QEMU closure omits base or finish predecessor",
    )
    require(
        VERIFIED_FEATURE not in qemu_closure and VERIFIED_QEMU_FEATURE not in qemu_closure,
        "trusted QEMU closure borrows verified-stream",
    )

    root = semantic(inputs.kernel_root)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root, "trusted acceptance lacks its QEMU-only guard")
    mutual = (
        f'#[cfg(all(feature="{FEATURE}",feature="{VERIFIED_FEATURE}"))]compile_error!('
        f'"features`{FEATURE}`and`{VERIFIED_FEATURE}`aremutuallyexclusivefinish/verifysuccessors");'
    )
    require(mutual in root, "trusted and verified-stream bases are not mutually exclusive")
    pairing = (
        f'#[cfg(all(feature="{FEATURE}",feature="{FINISH_QEMU_FEATURE}",'
        f'not(feature="{QEMU_FEATURE}"),'
        f'not(feature="{COLLECTOR_QEMU_FEATURE}")))]compile_error!('
        f'"feature`{FEATURE}`cannotreusethediscard-onlyfinish/verifyQEMUtranscript");'
    )
    require(
        pairing in root,
        "trusted base QEMU pairing guard differs from its two exact acceptance exemptions",
    )
    isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolation in root, "trusted QEMU isolation guard differs")


def verify_sshd(source: str) -> None:
    production = source.split("#[cfg(test)]", 1)[0]
    production_code = semantic(production)
    staging_cfg = (
        '#[cfg(any(feature="native-revoke-target-acceptance",'
        f'feature="{SSHD_FEATURE}"))]'
    )
    pump = find_scope(production, r"\bstruct\s+ComponentStreamPump\b", "SSHD Component pump")
    pump_code = semantic(pump.raw)
    require(
        staging_cfg + "stdin_staging:[u8;MAX_STREAM_CHUNK_BYTES]" in pump_code
        and staging_cfg + "stdin_staging_length:usize" in pump_code
        and f'#[cfg(feature="{SSHD_FEATURE}")]forwarded_stdout_bytes:u64' in pump_code,
        "trusted SSH pump does not retain exact stdin staging",
    )
    pump_impl = find_scope(
        production,
        r"\bimpl\s+ComponentStreamPump\b",
        "SSHD Component pump implementation",
    )
    pump_methods = re.findall(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)\b",
        masked(pump_impl.raw),
    )
    require(
        pump_methods
        == [
            "new",
            "from_endpoints",
            "has_pending_stdin",
            "stdin_source_closed",
            "stdin_accepted_bytes",
            "record_stdin_accepted",
            "read_into_stdin_staging",
            "finish_stdin_staging_turn",
            "send_stdin",
            "retry_stdin",
            "close_stdin_normal",
            "poll_stdout",
            "commit_stdout",
            "prefetch_stdout_ring",
            "note_stdout_drain_blocked",
            "poll_stdout_target",
            "pending_stdout",
            "consume_stdout",
            "consume_forwarded_stdout",
            "forwarded_stdout_bytes",
            "stdout_terminal",
            "finish_after_lifecycle",
        ],
        "SSHD Component pump method surface differs",
    )
    require(
        production_code.count("structComponentStreamPump{") == 1
        and production_code.count("implComponentStreamPump{") == 1
        and production_code.count("ComponentStreamPump{") == 2
        and semantic(pump_impl.raw).count("Self{") == 3,
        "SSHD Component pump has another production constructor or implementation",
    )
    from_endpoints = find_function(pump_impl, "from_endpoints", "SSHD Component pump constructor")
    from_endpoints_code = semantic(from_endpoints.raw)
    require(
        staging_cfg + "stdin_staging:[0;MAX_STREAM_CHUNK_BYTES]" in from_endpoints_code
        and staging_cfg + "stdin_staging_length:0" in from_endpoints_code
        and f'#[cfg(feature="{SSHD_FEATURE}")]forwarded_stdout_bytes:0'
        in from_endpoints_code,
        "trusted SSH pump does not initialize exact stdin staging",
    )
    staging_read = find_function(
        pump_impl,
        "read_into_stdin_staging",
        "SSHD exact stdin staging read",
    )
    staging_finish = find_function(
        pump_impl,
        "finish_stdin_staging_turn",
        "SSHD exact stdin staging finish",
    )
    for helper, label in (
        (staging_read, "read"),
        (staging_finish, "finish"),
    ):
        require(
            semantic(pump_impl.raw[: helper.start]).endswith(staging_cfg)
            and semantic(helper.raw).startswith("fn")
            and not semantic(helper.raw).startswith("pub"),
            f"SSHD exact stdin staging {label} helper is exposed or not feature-isolated",
        )
    require(
        semantic(staging_read.raw)
        == (
            "fnread_into_stdin_staging<F>(&mutself,maximum:usize,ready:usize,read:F,)"
            "->Result<usize,&'staticstr>whereF:FnOnce(&mut[u8])->Result<usize,&'staticstr>,{"
            "ifmaximum==0||maximum>MAX_STREAM_CHUNK_BYTES{returnErr("
            '"SSHComponentstdinchunklimitwasinvalid");}'
            "ifself.stdin_staging_length>maximum{returnErr("
            '"SSHComponentstdinstagingexceededitsexactchunk");}'
            "letremaining=maximum.saturating_sub(self.stdin_staging_length);"
            "letlength=ready.min(remaining);iflength==0{returnOk(0);}"
            "letstart=self.stdin_staging_length;letaccepted=read("
            "&mutself.stdin_staging[start..start+length])?;ifaccepted>length{returnErr("
            '"SSHComponentstdinreadexceededitsstagingwindow");}'
            "self.stdin_staging_length+=accepted;Ok(accepted)}"
        ),
        "SSHD exact stdin staging read no longer appends only accepted Sunset bytes",
    )
    require(
        semantic(staging_finish.raw)
        == (
            "fnfinish_stdin_staging_turn(&mutself,maximum:usize,eof:bool,)"
            "->Result<bool,&'staticstr>{ifmaximum==0||maximum>MAX_STREAM_CHUNK_BYTES{"
            'returnErr("SSHComponentstdinchunklimitwasinvalid");}'
            "ifself.stdin_staging_length>maximum{returnErr("
            '"SSHComponentstdinstagingexceededitsexactchunk");}'
            "letmutworked=false;ifself.stdin_staging_length==maximum||(eof&&"
            "self.stdin_staging_length!=0){letlength=self.stdin_staging_length;"
            "letstaged=self.stdin_staging;worked|=self.send_stdin(&staged[..length])?;"
            "self.stdin_staging_length=0;}if!self.stdin_source_closed()&&"
            "!self.has_pending_stdin()&&self.stdin_staging_length==0&&eof{"
            "worked|=self.close_stdin_normal()?;}Ok(worked)}"
        ),
        "SSHD exact stdin staging flush or EOF close differs",
    )
    stdin_turn = find_scope(
        production,
        r"\bfn\s+pump_component_stdin_turn\b",
        "SSHD Component stdin pump",
    )
    stdin_turn_code = semantic(stdin_turn.raw)
    for required in (
        staging_cfg + "ifstage_exact_stdin",
        "remaining=maximum.saturating_sub(pump.stdin_staging_length)",
        "pump.read_into_stdin_staging(maximum,ready,|staging|{runner.read_channel("
        "channel,ChanData::Normal,staging).map_err(|_|"
        '"failedtoreadSSHComponentstdin")})?',
        "leteof=runner.read_channel_ready().is_none()&&runner.is_channel_eof(channel);",
        "pump.finish_stdin_staging_turn(maximum,eof)?",
    ):
        require(required in stdin_turn_code, f"trusted exact stdin staging omits {required!r}")
    require(
        stdin_turn_code.count("pump.read_into_stdin_staging(") == 1
        and stdin_turn_code.count("pump.finish_stdin_staging_turn(") == 1,
        "trusted stdin turn bypasses or repeats its exact staging helpers",
    )

    staging_test = find_scope(
        source,
        r"\bfn\s+trusted_stdin_staging_coalesces_sunset_1000_plus_24_and_eof_37\b",
        "trusted Sunset slice staging regression",
    )
    test_cfg = (
        f'#[cfg(all(feature="{SSHD_FEATURE}",'
        'feature="native-revoke-target-acceptance"))]#[test]'
    )
    require(
        semantic(source[: staging_test.start]).endswith(test_cfg),
        "trusted Sunset staging regression is not an active trusted+native test",
    )
    staging_test_code = semantic(staging_test.raw)
    for required in (
        "stage_slice(&mutpump,&canonical[..1000]);",
        "assert_eq!(pump.stdin_staging_length,1000);",
        "assert_eq!(stdin_stream.depth(),0);",
        "stage_slice(&mutpump,&canonical[1000..]);",
        "assert_eq!(full.length(),MAX_STREAM_CHUNK_BYTES);",
        "assert_eq!(full_bytes.as_slice(),canonical.as_slice());",
        "stage_slice(&mutpump,&tail);",
        "assert_eq!(final_chunk.length(),37);",
        "assert_eq!(final_bytes.as_slice(),tail.as_slice());",
        "assert_eq!(pump.stdin_accepted_bytes,MAX_STREAM_CHUNK_BYTES+37);",
        "stdin_stream.is_normal_provisional()",
        "stdin_supervisor.finalize(StreamCloseReason::Normal)",
        "StreamReceiveDispatch::Closed(StreamCloseReason::Normal)",
    ):
        require(required in staging_test_code, f"trusted Sunset regression omits {required!r}")

    exact_pump_methods = {
        "pending_stdout": (
            "fnpending_stdout(&self)->&[u8]{self.stdout_pending.as_ref().map_or(&[],"
            "|pending|{&pending.bytes[pending.offset..pending.length]})}"
        ),
        "consume_stdout": (
            "fnconsume_stdout(&mutself,length:usize)->Result<bool,&'staticstr>{"
            "letSome(pending)=self.stdout_pending.as_mut()else{returnErr("
            '"SSHComponentstdoutaccountinghadnopendingchunk");};'
            "letremaining=pending.length-pending.offset;iflength==0||length>remaining{"
            'returnErr("SSHComponentstdoutaccountingexceededitschunk");}'
            "pending.offset+=length;ifpending.offset==pending.length{self.stdout_pending=None;"
            "Ok(true)}else{Ok(false)}}"
        ),
        "consume_forwarded_stdout": (
            "fnconsume_forwarded_stdout(&mutself,length:usize)->Result<bool,&'staticstr>{"
            "letforwarded_length=u64::try_from(length).map_err(|_|"
            '"SSHComponentstdoutbyteaccountingexceededu64")?;'
            "letnext=self.forwarded_stdout_bytes.checked_add(forwarded_length).ok_or("
            '"SSHComponentstdoutbyteaccountingoverflowed")?;'
            "letconsumed=self.consume_stdout(length)?;self.forwarded_stdout_bytes=next;"
            "Ok(consumed)}"
        ),
        "forwarded_stdout_bytes": (
            "fnforwarded_stdout_bytes(&self)->u64{self.forwarded_stdout_bytes}"
        ),
        "stdout_terminal": (
            "fnstdout_terminal(&self)->Option<StreamCloseReason>{self.stdout_terminal}"
        ),
        "commit_stdout": (
            "fncommit_stdout(&mutself,prepared:StreamPreparedReceive)->Result<bool,&'staticstr>{"
            "letlength=prepared.length();iflength==0||length>MAX_STREAM_CHUNK_BYTES{"
            "let_=self.stdout.cancel(prepared.operation());returnErr("
            '"SSHComponentstdoutpreparedaninvalidchunk");}'
            "letmutbytes=[0u8;COMPONENT_STDOUT_PENDING_BYTES];matchself.stdout.commit("
            "prepared.operation(),&mutbytes[..length]).map_err(component_stream_error)?{"
            "StreamReceiveCommit::Received(received)ifreceived==length=>{self.stdout_pending="
            "Some(PendingComponentOutput{bytes,length,offset:0,});Ok(true)}"
            "StreamReceiveCommit::Received(_)=>Err("
            '"SSHComponentstdoutcommitlengthchanged"),'
            "StreamReceiveCommit::Closed(reason)=>{self.stdout.cancel(prepared.operation())."
            "map_err(component_stream_error)?;self.stdout_terminal=Some(reason);Ok(true)}}}"
        ),
        "poll_stdout": (
            "fnpoll_stdout(&mutself)->Result<bool,&'staticstr>{ifself.stdout_pending.is_some()"
            "||self.stdout_terminal.is_some(){returnOk(false);}letdispatch=matchself."
            "stdout_waiting.take(){Some(operation)=>self.stdout.resume(operation).map_err("
            "component_stream_error)?,None=>self.stdout.start().map_err("
            "component_stream_error)?,};matchdispatch{StreamReceiveDispatch::Waiting(operation)"
            "=>{self.stdout_waiting=Some(operation);Ok(false)}StreamReceiveDispatch::Prepared("
            "prepared)=>self.commit_stdout(prepared),StreamReceiveDispatch::Closed(reason)=>{"
            "self.stdout_terminal=Some(reason);Ok(true)}}}"
        ),
    }
    for name, expected in exact_pump_methods.items():
        function = find_function(pump_impl, name, f"SSHD pump {name}")
        require(
            semantic(function.raw) == expected,
            f"SSHD pump {name} no longer preserves exact stdout provenance",
        )
    production_masked = masked(production)
    forwarded_writes = re.findall(
        r"\.\s*forwarded_stdout_bytes\s*=(?!=)",
        production_masked,
    )
    require(
        len(forwarded_writes) == 1
        and production_code.count("self.forwarded_stdout_bytes=next;") == 1,
        "SSHD forwarded stdout count has another production writer",
    )
    exact_stdout_field_accesses = {
        "stdout_pending": (8, 8),
        "stdout_terminal": (13, 9),
        "stdout_waiting": (6, 6),
        "forwarded_stdout_bytes": (4, 3),
    }
    pump_impl_code = semantic(pump_impl.raw)
    for field, (production_count, implementation_count) in exact_stdout_field_accesses.items():
        require(
            production_code.count(f".{field}") == production_count
            and pump_impl_code.count(f".{field}") == implementation_count,
            f"SSHD stdout provenance field {field} has another production access",
        )
    stdout_turn = find_scope(
        production,
        r"\bfn\s+pump_component_stdout_turn\b",
        "SSHD Component stdout pump",
    )
    require(
        semantic(stdout_turn.raw)
        == (
            "fnpump_component_stdout_turn(pump:&mutComponentStreamPump,runner:&mutRunner<'_,"
            "Server>,state:&ProtocolState,)->Result<bool,&'staticstr>{letmutworked=false;"
            "if!pump.pending_stdout().is_empty(){letchannel=state.channel.as_ref().ok_or("
            '"acceptedComponentsessionlostitschannel")?;'
            "matchrunner.write_channel(channel,ChanData::Normal,pump.pending_stdout()){Ok(0)=>{}"
            "Ok(written)=>{"
            f'#[cfg(not(feature="{SSHD_FEATURE}"))]'
            "pump.consume_stdout(written)?;"
            f'#[cfg(feature="{SSHD_FEATURE}")]'
            "pump.consume_forwarded_stdout(written)?;worked=true;}Err(sunset::Error::NoRoom{..}"
            "|sunset::Error::BusySend{..})=>{}Err(_)=>returnErr("
            '"SSHComponentstdoutchannelclosed"),}}'
            "ifpump.pending_stdout().is_empty()&&pump.stdout_terminal().is_none(){"
            '#[cfg(feature="native-revoke-target-acceptance")]'
            "{worked|=pump.poll_stdout_target()?;}"
            '#[cfg(not(feature="native-revoke-target-acceptance"))]'
            "{worked|=pump.poll_stdout()?;}}Ok(worked)}"
        ),
        "SSHD stdout pump does not count only Sunset-accepted normal-channel bytes",
    )

    terminal = find_scope(
        production,
        r"\bpub\s+struct\s+SshExecProfileTerminal\b",
        "SSHD terminal seal",
    )
    terminal_code = semantic(terminal.raw)
    for field in (
        "component_terminal:vibeos_vsh::ComponentTerminal",
        "exit_status:u32",
        "timed_out:bool",
        "stdout_bytes:u64",
        "stderr_bytes:u64",
    ):
        require(field in terminal_code, f"SSHD terminal omits private field {field!r}")
    require("pubcomponent_terminal:" not in terminal_code, "terminal enum field is public")
    require("pubexit_status:" not in terminal_code, "terminal status field is public")
    prefix = production[max(0, terminal.start - 180) : terminal.start]
    require(
        not re.search(r"#\s*\[\s*derive\s*\([^]]*(Clone|Copy|Default)", prefix),
        "SSHD terminal is cloneable, copyable, or defaultable",
    )
    terminal_impl = find_scope(
        production,
        r"\bimpl\s+SshExecProfileTerminal\b",
        "SSHD terminal implementation",
    )
    require(
        production_code.count("structSshExecProfileTerminal{") == 1
        and production_code.count("implSshExecProfileTerminal{") == 1
        and production_code.count("SshExecProfileTerminal{") == 2
        and production_code.count("SshExecProfileTerminal") == 6
        and semantic(terminal_impl.raw).count("Self{") == 2,
        "SSHD terminal has another production constructor or implementation",
    )
    require(
        not re.search(
            r"\bimpl\b[^{};]*\bfor\s+(?:(?:self|crate)::)?SshExecProfileTerminal\b",
            masked(production),
        ),
        "SSHD terminal admits a production trait implementation",
    )
    seal = find_function(terminal_impl, "seal", "SSHD terminal private seal")
    require(
        semantic(seal.raw)
        == (
            "fnseal(component_terminal:vibeos_vsh::ComponentTerminal,exit_status:u32,"
            "timed_out:bool,stdout_bytes:u64,)->Self{Self{component_terminal,exit_status,"
            "timed_out,stdout_bytes,stderr_bytes:0,}}"
        ),
        "SSHD terminal seal is exposed or changes its exact field mapping",
    )
    exact_getters = {
        "component_terminal": (
            "pubfncomponent_terminal(&self)->vibeos_vsh::ComponentTerminal{"
            "self.component_terminal}"
        ),
        "exit_status": "pubfnexit_status(&self)->u32{self.exit_status}",
        "timed_out": "pubfntimed_out(&self)->bool{self.timed_out}",
        "stdout_bytes": "pubfnstdout_bytes(&self)->u64{self.stdout_bytes}",
        "stderr_bytes": "pubfnstderr_bytes(&self)->u64{self.stderr_bytes}",
    }
    terminal_methods = re.findall(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)\b",
        masked(terminal_impl.raw),
    )
    require(
        terminal_methods == ["seal", *exact_getters],
        "SSHD terminal method surface differs",
    )
    for getter, expected in exact_getters.items():
        function = find_function(terminal_impl, getter, f"SSHD terminal {getter} getter")
        require(
            semantic(function.raw) == expected,
            f"SSHD terminal {getter} getter does not return the exact sealed field",
        )
    terminal_field_writes = re.findall(
        r"\.\s*(component_terminal|exit_status|timed_out|stdout_bytes|stderr_bytes)\s*=(?!=)",
        masked(production),
    )
    require(
        terminal_field_writes == []
        and production_code.count("self.terminal=") == 1
        and production_code.count("self.terminal=Some(terminal);") == 1
        and production_code.count("SshExecProfileTerminal::seal(") == 1,
        "SSHD sealed terminal has another production writer or replacement",
    )

    backend = find_scope(
        production,
        r"\bpub\s+trait\s+SshExecProfileRunBackend\b",
        "SSHD profile backend",
    )
    code = semantic(backend.raw)
    require(
        f'#[cfg(not(feature="{SSHD_FEATURE}"))]fnresponse_boundary(&mutself,status:u32)'
        in code,
        "SSHD raw status boundary is not compiled out",
    )
    require(
        f'#[cfg(feature="{SSHD_FEATURE}")]fnresponse_boundary(&mutself,terminal:SshExecProfileTerminal)'
        in code,
        "SSHD trusted boundary does not consume the seal",
    )
    run_impl = find_scope(production, r"\bimpl\s+SshExecProfileRun\b", "SSHD profile run")
    run_methods = re.findall(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)\b",
        masked(run_impl.raw),
    )
    require(
        run_methods == ["phase_host", "phase_wait", "seal_terminal", "response_boundary"],
        "SSHD profile run method surface differs",
    )
    exact_phase_methods = {
        "phase_host": (
            "pubfnphase_host(&mutself)->Result<(),()>{self.backend.as_mut().expect("
            '"SSHexecprofilerunwasconsumedtwice").phase_host()}'
        ),
        "phase_wait": (
            "pubfnphase_wait(&mutself)->Result<(),()>{self.backend.as_mut().expect("
            '"SSHexecprofilerunwasconsumedtwice").phase_wait()}'
        ),
    }
    for method, expected in exact_phase_methods.items():
        function = find_function(run_impl, method, f"SSHD run {method}")
        require(
            semantic(function.raw) == expected,
            f"SSHD run {method} can alter sealed terminal provenance",
        )
    seal_terminal = find_function(run_impl, "seal_terminal", "SSHD run terminal seal")
    require(
        semantic(seal_terminal.raw)
        == (
            "fnseal_terminal(&mutself,terminal:SshExecProfileTerminal)->Result<(),()>{"
            "ifself.terminal.is_some(){returnErr(());}self.terminal=Some(terminal);Ok(())}"
        ),
        "SSHD run seal is exposed or does not store the exact terminal once",
    )
    boundary = find_function(run_impl, "response_boundary", "SSHD consuming boundary")
    boundary_code = semantic(boundary.raw)
    require(
        boundary_code
        == (
            "pubfnresponse_boundary(mutself,status:u32)->Result<(),()>{"
            f'#[cfg(feature="{SSHD_FEATURE}")]'
            "letterminal=matchself.terminal.take(){Some(terminal)ifterminal.exit_status()==status"
            "=>terminal,Some(_)|None=>returnErr(()),};letmutbackend=self.backend.take().expect("
            '"SSHexecprofilerunwasconsumedtwice");'
            f'#[cfg(not(feature="{SSHD_FEATURE}"))]'
            "letboundary=backend.response_boundary(status);"
            f'#[cfg(feature="{SSHD_FEATURE}")]'
            "letboundary=backend.response_boundary(terminal);ifboundary.is_err(){"
            "backend.cancel();returnErr(());}Ok(())}"
        ),
        "SSHD response boundary does not move the exact status-bound terminal",
    )

    terminal_parser = find_scope(
        production,
        r"\bfn\s+managed_component_terminal\b",
        "SSHD managed terminal parser",
    )
    require(
        semantic(terminal_parser.raw)
        == (
            "fnmanaged_component_terminal(reports:&Result<Vec<vibeos_vsh::JobReport>,"
            "vibeos_vsh::Diagnostic>,)->Option<vibeos_vsh::ComponentTerminal>{"
            "letreports=reports.as_ref().ok()?;ifreports.len()!=1||!reports[0].output.is_empty()"
            "||reports[0].stages.len()!=1{returnNone;}letreport=&reports[0];"
            "letstage=&report.stages[0];letvibeos_vsh::TerminalDetail::Component(terminal)="
            "&stage.detailelse{returnNone;};(report.status==terminal.status()&&"
            "stage.status==terminal.status()).then_some(*terminal)}"
        ),
        "SSHD managed terminal parser no longer retains the exact immutable report terminal",
    )
    validated_terminal = find_scope(
        production,
        r"\bfn\s+validated_managed_component_terminal\b",
        "SSHD managed terminal validator",
    )
    require(
        semantic(validated_terminal.raw)
        == (
            "fnvalidated_managed_component_terminal(reports:&Result<Vec<vibeos_vsh::JobReport>,"
            "vibeos_vsh::Diagnostic>,)->Result<vibeos_vsh::ComponentTerminal,&'staticstr>{"
            "managed_component_terminal(reports).ok_or("
            '"SSHComponentexecutionpublishednoexactterminal")}'
        ),
        "SSHD managed terminal validator changes the parsed terminal",
    )
    exit_status = find_scope(production, r"\bfn\s+ssh_exit_status\b", "SSH exit status mapping")
    require(
        semantic(exit_status.raw)
        == (
            "fnssh_exit_status(status:vibeos_vsh::Status)->u32{matchstatus{"
            "vibeos_vsh::Status::Success=>0,vibeos_vsh::Status::Returned(status)=>status.into(),"
            "vibeos_vsh::Status::Usage=>2,vibeos_vsh::Status::Unavailable=>127,"
            "vibeos_vsh::Status::Denied=>126,vibeos_vsh::Status::BudgetExceeded=>124,"
            "vibeos_vsh::Status::BackendFault=>125,vibeos_vsh::Status::Faulted=>125,"
            "vibeos_vsh::Status::Cancelled=>130,}}"
        ),
        "SSH exit status mapping differs",
    )
    helper = find_scope(
        production,
        r"\bfn\s+seal_managed_component_profile_terminal\b",
        "SSHD managed terminal producer",
    )
    helper_code = semantic(helper.raw)
    require(
        helper_code
        == (
            "fnseal_managed_component_profile_terminal(profile_run:&mutOption<"
            "SshExecProfileRun>,outcome:&ExecutionEnd,pump:&ComponentStreamPump,"
            "timeout_observed:bool,)->Result<(),&'staticstr>{letSome(run)=profile_run.as_mut()"
            "else{returnOk(());};letExecutionEnd::Complete{reports,timed_out:reported_timed_out,}="
            "outcomeelse{returnOk(());};letterminal=validated_managed_component_terminal("
            "reports)?;if!pump.pending_stdout().is_empty(){returnErr("
            '"SSHComponentprofileterminalretainedpendingstdout");}'
            "ifpump.stdout_terminal()!=Some(terminal.stream_close_reason()){returnErr("
            '"SSHComponentprofileterminaldidnotmatchstdoutclosure");}'
            "if*reported_timed_out&&!timeout_observed{returnErr("
            '"SSHComponentprofileterminallostitstimeoutobservation");}'
            "letexit_status=if*reported_timed_out{124}else{ssh_exit_status(terminal.status())};"
            "run.seal_terminal(SshExecProfileTerminal::seal(terminal,exit_status,"
            "timeout_observed||*reported_timed_out,pump.forwarded_stdout_bytes(),)).map_err("
            '|_|"SSHComponentprofileterminalwassealedtwice")}'
        ),
        "SSHD terminal producer does not seal the exact drained completion facts",
    )
    execute = find_scope(
        production,
        r"\basync\s+fn\s+execute_managed_component_with_network\b",
        "SSHD managed execution",
    )
    execute_code = semantic(execute.raw)
    require(
        f'#[cfg(feature="{SSHD_FEATURE}")]letstage_exact_stdin=true;' in execute_code,
        "trusted execution does not force canonical 1024-byte stdin staging",
    )
    trusted_chunk_limit = (
        '#[cfg(any(not(feature="native-revoke-target-acceptance"),'
        f'feature="{SSHD_FEATURE}"))]'
        'letstdin_chunk_limit=MAX_STREAM_CHUNK_BYTES;'
    )
    require(
        trusted_chunk_limit in execute_code,
        "trusted execution does not force the formal 1024-byte chunk limit",
    )
    ordered(
        execute_code,
        ("shutdown.await;", "seal_managed_component_profile_terminal("),
        "SSHD shutdown/terminal seal",
    )
    for required in (
        "letmutcompleted=None;",
        "letmutexpected_terminal=None;",
        "letmuttimeout_observed=false;",
        "timeout_observed=true;",
        "ManagedComponentCancelCompletion::Drain{reports,terminal}=>{cancellation=None;"
        "expected_terminal=Some(terminal.stream_close_reason());drain_deadline=Some("
        "monotonic_ms().saturating_add(CLOSE_TIMEOUT_MS));completed=Some(reports);continue;}",
        "iflet(Some(expected),Some(observed))=(expected_terminal,pump.stdout_terminal()){"
        "ifexpected!=observed{breakExecutionEnd::Reset("
        '"SSHComponentlifecycleandstdoutterminalreasonsdiverged",);}'
        "ifpump.pending_stdout().is_empty(){breakExecutionEnd::Complete{reports:completed."
        'take().expect("managedComponentcompletiondisappeared"),timed_out:false,};}}',
        "ifletSome(reports)=reports{letterminal=matchvalidated_managed_component_terminal("
        "&reports){Ok(terminal)=>terminal,Err(reason)=>breakExecutionEnd::Reset(reason),};"
        "expected_terminal=Some(terminal.stream_close_reason());drain_deadline=Some("
        "monotonic_ms().saturating_add(CLOSE_TIMEOUT_MS));completed=Some(reports);}",
    ):
        require(required in execute_code, f"SSHD live completion flow omits {required!r}")
    require(
        execute_code.count("letoutcome=") == 1
        and "letmutoutcome" not in execute_code
        and execute_code.count("completed=") == 3
        and execute_code.count("expected_terminal=") == 3
        and execute_code.count("timeout_observed=") == 2
        and execute_code.count("validated_managed_component_terminal(&reports)") == 1
        and execute_code.count("reports:completed.take()") == 1
        and execute_code.count("seal_managed_component_profile_terminal(") == 1,
        "SSHD live completion facts can be rebound before sealing",
    )
    require(
        comment_masked(production).count("SshExecProfileTerminal::seal(") == 1,
        "SSHD has another production terminal mint",
    )


def verify_runtime(source: str) -> None:
    call_metrics = find_scope(
        source,
        r"\bpub\s+struct\s+TypedCallMetrics\b",
        "typed call metrics",
    )
    require(
        semantic(call_metrics.raw)
        == "pubstructTypedCallMetrics{pubconsumed_work:u64,pubremaining_work:u64,}",
        "typed call metric surface differs",
    )
    profile = find_scope(
        source,
        r"\bpub\s+struct\s+SyncCallProfile\b",
        "sync call profile",
    )
    profile_cfg = (
        '#[cfg(feature="c84-profile-hooks")]'
        "#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]"
    )
    require(
        semantic(profile.raw)
        == (
            "pubstructSyncCallProfile{pubtyped_polls:u64,pubcore_polls:u64,"
            "pubouter_poll_ticks:u64,pubcore_interpreter_ticks:u64,pubconsumed_work:u64,}"
        )
        and semantic(source[: profile.start]).endswith(profile_cfg)
        and semantic(source).count("implDefaultforSyncCallProfile{") == 0,
        "sync call profile surface or zero Default origin differs",
    )

    typed_impl = find_scope(
        source,
        r"\bimpl<'a,\s*A>\s+TypedCall<'a,\s*A>",
        "typed call implementation",
    )
    metrics = find_function(typed_impl, "metrics", "typed call live metrics")
    require(
        semantic(metrics.raw)
        == (
            "pubconstfnmetrics(&self)->TypedCallMetrics{TypedCallMetrics{"
            "consumed_work:self.total_work-self.remaining_work,"
            "remaining_work:self.remaining_work,}}"
        ),
        "typed call metrics do not expose the exact live work ledger",
    )
    poll_profiled = find_function(typed_impl, "poll_profiled", "profiled typed poll")
    require(
        semantic(poll_profiled.raw)
        == (
            "pubfnpoll_profiled<C:ProfileClock+?Sized>(&mutself,clock:&mutC,"
            "profile:&mutSyncCallProfile,)->TypedPoll{letwork_before=self.metrics().consumed_work;"
            "letouter_started=clock.ticks();if!self.profile_cleanup_started&&matches!("
            "self.stage,TypedStage::Cleanup|TypedStage::Terminal(_)){clock.cleanup_started();"
            "self.profile_cleanup_started=true;}letmutsession=ProfileSession{clock,profile};"
            "letresult=self.poll_with_profiler(&mutsession);if!self.profile_cleanup_started&&"
            "matches!(&result,TypedPoll::HostFailed(_)|TypedPoll::Trapped(_)){"
            "session.clock.cleanup_started();self.profile_cleanup_started=true;}"
            "letouter_elapsed=session.clock.ticks().wrapping_sub(outer_started);"
            "letwork_after=self.metrics().consumed_work;letconsumed=work_after.checked_sub("
            "work_before).unwrap_or(u64::MAX);session.profile.typed_polls="
            "session.profile.typed_polls.saturating_add(1);session.profile.outer_poll_ticks="
            "session.profile.outer_poll_ticks.saturating_add(outer_elapsed);"
            "session.profile.consumed_work=session.profile.consumed_work.saturating_add("
            "consumed);result}"
        ),
        "profiled typed poll no longer derives its counters from the ordinary live poll",
    )

    profile_impl = find_scope(
        source,
        r"\bimpl<C:\s*ProfileClock\s*\+\s*\?Sized>\s+SyncPollProfiler\s+for\s+ProfileSession",
        "profile session implementation",
    )
    begin = find_function(profile_impl, "begin_core_poll", "profile Core start")
    end = find_function(profile_impl, "end_core_poll", "profile Core finish")
    require(
        semantic(begin.raw)
        == "fnbegin_core_poll(&mutself)->Self::CoreStart{self.clock.core_poll_started()}",
        "profile Core start does not use the live clock boundary",
    )
    require(
        semantic(end.raw)
        == (
            "fnend_core_poll(&mutself,started:Self::CoreStart){letfinished="
            "self.clock.core_poll_finished();letelapsed=finished.wrapping_sub(started);"
            "self.profile.core_polls=self.profile.core_polls.saturating_add(1);"
            "self.profile.core_interpreter_ticks=self.profile.core_interpreter_ticks."
            "saturating_add(elapsed);}"
        ),
        "profile Core finish no longer records the exact paired live boundary",
    )


def verify_component(source: str) -> None:
    io_observation = find_scope(
        source,
        r"\bstruct\s+FormalIoObservation\b",
        "formal IO observation",
    )
    require(
        semantic(io_observation.raw)
        == (
            "structFormalIoObservation{read_chunks:u64,write_chunks:u64,"
            "stdin_bytes:u64,stdout_bytes:u64,}"
        ),
        "formal IO observation surface differs",
    )
    counters = find_scope(source, r"\bimpl\s+FormalIoCounters\b", "formal IO counters")
    counters_code = semantic(counters.raw)
    for required in (
        "0..=11=>Some(MAX_STREAM_CHUNK_BYTES)",
        "12=>Some(37)",
        "(((offset%251)*17+3)%251)asu8",
        "Self::input_byte(offset)^0x20",
        "self.read_bytes.checked_add(length)",
        "self.read_chunks.checked_add(1)",
        "self.write_bytes.checked_add(length)",
        "self.write_chunks.checked_add(1)",
        "self.read_chunks==FORMAL_READ_CHUNKS",
        "self.write_chunks==FORMAL_WRITE_CHUNKS",
        "self.read_bytes==FORMAL_STDOUT_BYTES",
        "self.write_bytes==FORMAL_STDOUT_BYTES",
    ):
        require(required in counters_code, f"formal IO proof omits {required!r}")
    require("saturating_" not in counters_code, "formal IO proof uses saturation")
    exact_counter_methods = {
        "new": (
            "constfnnew()->Self{Self{read_chunks:0,read_bytes:0,write_chunks:0,"
            "write_bytes:0,invalid:false,}}"
        ),
        "fail": (
            "fnfail<T>(&mutself)->Result<T,HostError>{self.invalid=true;"
            "Err(HostError::BackendFault)}"
        ),
        "expected_chunk_length": (
            "fnexpected_chunk_length(chunks:u64)->Option<usize>{matchchunks{"
            "0..=11=>Some(MAX_STREAM_CHUNK_BYTES),12=>Some(37),_=>None,}}"
        ),
        "input_byte": "fninput_byte(offset:u64)->u8{(((offset%251)*17+3)%251)asu8}",
        "observe_read": (
            "fnobserve_read(&mutself,bytes:&[u8])->Result<(),HostError>{ifself.invalid||"
            "Self::expected_chunk_length(self.read_chunks)!=Some(bytes.len()){returnself.fail();}"
            "for(index,byte)inbytes.iter().enumerate(){letindex=matchu64::try_from(index){"
            "Ok(index)=>index,Err(_)=>returnself.fail(),};letSome(offset)=self.read_bytes."
            "checked_add(index)else{returnself.fail();};if*byte!=Self::input_byte(offset){"
            "returnself.fail();}}letlength=matchu64::try_from(bytes.len()){Ok(length)=>length,"
            "Err(_)=>returnself.fail(),};letSome(next_bytes)=self.read_bytes.checked_add(length)"
            "else{returnself.fail();};letSome(next_chunks)=self.read_chunks.checked_add(1)else{"
            "returnself.fail();};self.read_bytes=next_bytes;self.read_chunks=next_chunks;Ok(())}"
        ),
        "observe_write": (
            "fnobserve_write(&mutself,bytes:&[u8])->Result<(),HostError>{ifself.invalid||"
            "Self::expected_chunk_length(self.write_chunks)!=Some(bytes.len()){returnself.fail();}"
            "for(index,byte)inbytes.iter().enumerate(){letindex=matchu64::try_from(index){"
            "Ok(index)=>index,Err(_)=>returnself.fail(),};letSome(offset)=self.write_bytes."
            "checked_add(index)else{returnself.fail();};if*byte!=(Self::input_byte(offset)^0x20){"
            "returnself.fail();}}letlength=matchu64::try_from(bytes.len()){Ok(length)=>length,"
            "Err(_)=>returnself.fail(),};letSome(next_bytes)=self.write_bytes.checked_add(length)"
            "else{returnself.fail();};letSome(next_chunks)=self.write_chunks.checked_add(1)else{"
            "returnself.fail();};self.write_bytes=next_bytes;self.write_chunks=next_chunks;Ok(())}"
        ),
    }
    for name, expected in exact_counter_methods.items():
        function = find_function(counters, name, f"formal IO {name}")
        require(
            semantic(function.raw) == expected,
            f"formal IO {name} admits a condition decoy or forged mapping",
        )
    component_semantic = semantic(source)
    formal_writes = re.findall(
        r"\.\s*(read_chunks|read_bytes|write_chunks|write_bytes|invalid)\s*=(?!=)",
        masked(source),
    )
    require(
        formal_writes
        == ["invalid", "read_bytes", "read_chunks", "write_bytes", "write_chunks"]
        and component_semantic.count("structFormalIoCounters{") == 1
        and component_semantic.count("implFormalIoCounters{") == 1
        and component_semantic.count("FormalIoCounters{") == 2
        and component_semantic.count("FormalIoCounters::new()") == 1
        and counters_code.count("Self{") == 2,
        "formal IO counters have another constructor or production field writer",
    )
    for forbidden in ("mem::zeroed", "MaybeUninit", "transmute"):
        require(forbidden not in component_semantic, f"formal IO path admits {forbidden}")
    finish_io = find_function(counters, "finish", "formal IO final observation")
    require(
        semantic(finish_io.raw)
        == (
            "fnfinish(mutself)->Result<FormalIoObservation,HostError>{letexact=!self.invalid&&"
            "self.read_chunks==FORMAL_READ_CHUNKS&&self.write_chunks==FORMAL_WRITE_CHUNKS&&"
            "self.read_bytes==FORMAL_STDOUT_BYTES&&self.write_bytes==FORMAL_STDOUT_BYTES;"
            "if!exact{returnself.fail();}Ok(FormalIoObservation{read_chunks:self.read_chunks,"
            "write_chunks:self.write_chunks,stdin_bytes:self.read_bytes,"
            "stdout_bytes:self.write_bytes,})}"
        )
        and component_semantic.count("FormalIoObservation{") == 2,
        "formal IO finish does not retain the exact committed counters",
    )
    take_io = find_scope(source, r"\bfn\s+take_formal_io\b", "formal IO take")
    require(
        semantic(take_io.raw)
        == (
            "fntake_formal_io(&mutself)->Result<FormalIoObservation,HostError>{"
            "self.formal_io.take().ok_or(HostError::BackendFault)?.finish()}"
        ),
        "formal IO take does not consume the exact private counter proof",
    )

    commit = find_scope(source, r"\bfn\s+commit_prepared\b", "formal read commit")
    commit_code = semantic(commit.raw)
    ordered(
        commit_code,
        (
            "StreamReceiveCommit::Received(received)",
            "ifreceived!=length",
            "letresponse=response.commit(CanonicalValue::List(values))?;",
            "self.observe_formal_read(&bytes)?;",
        ),
        "formal read observation",
    )
    require(commit_code.count("self.observe_formal_read(&bytes)?;") == 1, "read observation count differs")
    for name in ("start_write", "resume_write"):
        function = find_scope(source, rf"\bfn\s+{name}\b", f"formal {name}")
        code = semantic(function.raw)
        require(
            "letsent=matches!(&dispatch,StreamSendDispatch::Sent);" in code,
            f"{name} does not derive final Sent",
        )
        require(
            "ifsent{self.observe_formal_write(&bytes)?;}" in code,
            f"{name} observes a non-Sent write",
        )

    run = find_scope(source, r"\basync\s+fn\s+run_image_component\b", "managed typed call")
    run_code = semantic(run.raw)
    require(
        run_code.count("letterminal_call_metrics;") == 1
        and run_code.count("terminal_call_metrics=") == 1
        and "letmutterminal_call_metrics" not in run_code,
        "terminal call metrics can be rebound after live capture",
    )
    require(
        run_code.count("letmutcore_profile=SyncCallProfile::default();") == 1
        and run_code.count("core_profile=") == 1,
        "live sync-call profile can be rebound before terminal handoff",
    )
    profile_field_writes = re.findall(
        r"\.\s*(typed_polls|core_polls|outer_poll_ticks|core_interpreter_ticks|"
        r"consumed_work)\s*=(?!=)",
        masked(source),
    )
    require(
        profile_field_writes == [],
        "component source has an out-of-runtime sync-call profile field writer",
    )
    require(
        run_code.count("letio=matchdispatcher.take_formal_io()") == 1
        and "letmutio=" not in run_code,
        "formal IO summary can be rebound or mutated before terminal handoff",
    )
    require(
        "terminal_call_metrics=call.metrics();" in run_code,
        "terminal call metrics are not sampled from the live call",
    )
    ordered(
        run_code,
        (
            "terminal_call_metrics=call.metrics();",
            "breakvalue;",
            "drop(call);",
            "dispatcher.take_formal_io()",
            "mark_managed_child_driver_completed(profile_epoch,io.read_chunks,io.write_chunks,"
            "io.stdin_bytes,io.stdout_bytes,terminal_call_metrics,core_profile,)",
        ),
        "live metric capture and terminal handoff",
    )
    require(
        "terminal==ComponentTerminal::Success" in run_code,
        "terminal metrics can be recorded for a non-Success value",
    )


def verify_slot(source: str) -> None:
    source = PHASE.CORE.without_direct_feature_units(source, COLLECTOR_FEATURE)
    source = PHASE.CORE.without_direct_feature_units(source, COLLECTOR_QEMU_FEATURE)
    source_code = semantic(source)
    trusted_cfg = f'#[cfg(feature="{FEATURE}")]'
    nontrusted_cfg = f'#[cfg(not(feature="{FEATURE}"))]'

    run_impl = find_scope(source, r"\bimpl\s+RunLease\b", "run lease")
    run_code = semantic(run_impl.raw)
    finish = find_function(run_impl, "finish", "non-trusted RunLease finish")
    finish_to_stream = find_function(
        run_impl,
        "finish_to_stream",
        "module-private finish transition",
    )
    require(
        run_code.count(
            nontrusted_cfg
            + "pub(crate)fnfinish(mutself)->Result<StreamLease,ProfileError>{"
        )
        == 1,
        "RunLease::finish is not compiled only for the non-trusted predecessor",
    )
    require(
        run_code.count(
            trusted_cfg + "fnfinish_to_stream(mutself)->Result<StreamLease,ProfileError>{"
        )
        == 1
        and semantic(finish_to_stream.raw).startswith("fnfinish_to_stream(")
        and "pub(crate)fnfinish_to_stream(" not in run_code,
        "trusted build exposes the internal finish-to-stream transition",
    )
    finish_body = semantic(finish.raw).split("{", 1)[1]
    trusted_finish_body = semantic(finish_to_stream.raw).split("{", 1)[1]
    require(
        finish_body == trusted_finish_body,
        "trusted module-private finish transition differs from the predecessor transition",
    )
    trusted_finish = (
        trusted_cfg
        + "pub(crate)fnfinish_trusted(self,terminal:vibeos_sshd::SshExecProfileTerminal,)"
        "->Result<TrustedVerifiedSample,ProfileError>{"
        "self.finish_to_stream()?.seal_trusted(terminal)}"
    )
    require(
        run_code.count(trusted_finish) == 1
        and "self.finish()?.seal_trusted(terminal)" not in run_code,
        "trusted finish does not use only the module-private stream transition",
    )

    stream_fields = (
        "{token:SampleToken,detach:CurrentTaskDetachLease,live:bool,"
        "not_sync:PhantomData<Cell<()>>,}"
    )
    require(
        source_code.count(nontrusted_cfg + "pub(crate)structStreamLease" + stream_fields) == 1,
        "non-trusted StreamLease authority differs",
    )
    require(
        source_code.count(trusted_cfg + "structStreamLease" + stream_fields) == 1
        and trusted_cfg + "pub(crate)structStreamLease" not in source_code,
        "trusted build exposes StreamLease outside the slot module",
    )

    metrics_tests = find_scope(
        source,
        r"\bmod\s+managed_child_terminal_metrics_tests\b",
        "managed terminal metric tests",
    )
    production_source = source[: metrics_tests.start] + source[metrics_tests.end :]
    production_code = semantic(production_source)
    require(
        production_code.count("structManagedChildTerminalMetrics{") == 1
        and production_code.count("implManagedChildTerminalMetrics{") == 1
        and production_code.count("ManagedChildTerminalMetrics{") == 2,
        "production has another managed terminal metric definition or constructor",
    )
    require(
        production_code.count("ManagedChildTerminalMetrics::from_live(") == 1,
        "production has another managed terminal metric mint",
    )
    for forbidden in ("mem::zeroed", "MaybeUninit", "transmute"):
        require(
            forbidden not in production_code,
            f"production terminal metric path admits {forbidden}",
        )
    metric_field_writes = re.findall(
        r"\.\s*(read_chunks|write_chunks|stdin_bytes|output_bytes|fuel_consumed|"
        r"poll_quanta|poll_exact|logical_live_after)\s*=(?!=)",
        masked(production_source),
    )
    require(
        metric_field_writes == ["logical_live_after"]
        and production_code.count("terminal.logical_live_after=0;") == 1,
        "managed terminal metrics have another post-validation field write",
    )
    require(
        production_code.count("managed_terminal:None,") == 1
        and production_code.count("managed_terminal=Some(terminal);") == 1,
        "managed terminal storage has another initializer or writer",
    )

    metrics_impl = find_scope(
        source,
        r"\bimpl\s+ManagedChildTerminalMetrics\b",
        "managed terminal metrics",
    )
    from_live = find_function(metrics_impl, "from_live", "managed terminal metric mint")
    code = semantic(from_live.raw)
    for required in (
        "committed_read_chunks!=FORMAL_READ_CHUNKS",
        "committed_write_chunks!=FORMAL_WRITE_CHUNKS",
        "stdin_bytes!=FORMAL_STDOUT_BYTES",
        "output_bytes!=FORMAL_STDOUT_BYTES",
        "call.consumed_work==u64::MAX",
        "call.remaining_work==u64::MAX",
        "call.consumed_work.checked_add(call.remaining_work)!=Some(MAX_FORMAL_FUEL)",
        "profile.typed_polls==u64::MAX",
        "profile.core_polls==u64::MAX",
        "profile.outer_poll_ticks==u64::MAX",
        "profile.core_interpreter_ticks==u64::MAX",
        "profile.consumed_work==u64::MAX",
        "profile.core_polls>profile.typed_polls",
        "profile.core_interpreter_ticks>profile.outer_poll_ticks",
        "profile.consumed_work.checked_add(FORMAL_TYPED_CALL_PLANNING_WORK)!=Some(call.consumed_work)",
        "poll_exact:true",
        "logical_live_after:1",
    ):
        require(required in code, f"terminal metric mint omits {required!r}")
    require("saturating_" not in code, "terminal metric mint uses saturation")
    metrics_mapping = (
        "Ok(Self{read_chunks:committed_read_chunks,"
        "write_chunks:committed_write_chunks,stdin_bytes,output_bytes,"
        "fuel_consumed:call.consumed_work,poll_quanta:profile.typed_polls,"
        "poll_exact:true,logical_live_after:1,})"
    )
    require(
        metrics_mapping in code
        and code.count("Ok(Self{") == 1
        and semantic(metrics_impl.raw).count("Self{") == 1,
        "validated terminal metric field mapping differs",
    )
    require(
        code
        == (
            "fnfrom_live(committed_read_chunks:u64,committed_write_chunks:u64,stdin_bytes:u64,"
            "output_bytes:u64,call:TypedCallMetrics,profile:SyncCallProfile,)->Result<Self,"
            "ManagedChildTerminalMetricsError>{ifcommitted_read_chunks!=FORMAL_READ_CHUNKS||"
            "committed_write_chunks!=FORMAL_WRITE_CHUNKS||stdin_bytes!=FORMAL_STDOUT_BYTES||"
            "output_bytes!=FORMAL_STDOUT_BYTES{returnErr(ManagedChildTerminalMetricsError::"
            "IoShape);}ifcall.consumed_work==u64::MAX||call.remaining_work==u64::MAX{returnErr("
            "ManagedChildTerminalMetricsError::FuelSentinel);}ifcall.consumed_work==0||"
            "call.consumed_work.checked_add(call.remaining_work)!=Some(MAX_FORMAL_FUEL){"
            "returnErr(ManagedChildTerminalMetricsError::FuelShape);}ifprofile.typed_polls=="
            "u64::MAX||profile.core_polls==u64::MAX||profile.outer_poll_ticks==u64::MAX||"
            "profile.core_interpreter_ticks==u64::MAX||profile.consumed_work==u64::MAX{"
            "returnErr(ManagedChildTerminalMetricsError::ProfileSentinel);}ifprofile.typed_polls"
            "==0||profile.core_polls==0||profile.core_polls>profile.typed_polls||"
            "profile.outer_poll_ticks==0||profile.core_interpreter_ticks==0||"
            "profile.core_interpreter_ticks>profile.outer_poll_ticks||profile.consumed_work==0||"
            "profile.consumed_work.checked_add(FORMAL_TYPED_CALL_PLANNING_WORK)!=Some("
            "call.consumed_work){returnErr(ManagedChildTerminalMetricsError::ProfileShape);}"
            "Ok(Self{read_chunks:committed_read_chunks,write_chunks:committed_write_chunks,"
            "stdin_bytes,output_bytes,fuel_consumed:call.consumed_work,poll_quanta:"
            "profile.typed_polls,poll_exact:true,logical_live_after:1,})}"
        ),
        "managed terminal metric mint admits a condition decoy or forged branch",
    )

    start_reserved = find_scope(source, r"\bfn\s+start_reserved\b", "slot start transition")
    require(
        semantic(start_reserved.raw).count(trusted_cfg + "managed_terminal:None,") == 1,
        "slot start does not initialize trusted terminal storage empty",
    )

    completed = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+mark_managed_child_driver_completed\s*\(\s*epoch:\s*u64,",
        "trusted driver completion",
    )
    completed_code = semantic(completed.raw)
    completed_metric_mapping = (
        "letterminal=ManagedChildTerminalMetrics::from_live("
        "committed_read_chunks,committed_write_chunks,stdin_bytes,output_bytes,"
        "call,profile,).map_err(|_|ProfileError::StateMismatch)?;"
    )
    require(
        completed_metric_mapping in completed_code
        and completed_code.count("ManagedChildTerminalMetrics::from_live(") == 1,
        "driver completion does not retain the exact validated metric inputs",
    )
    ordered(
        completed_code,
        (
            "ManagedChildTerminalMetrics::from_live(",
            "letmutslot=SLOT.lock();",
            "*managed_terminal=Some(terminal);",
            "child.driver_completed=true;",
        ),
        "atomic terminal metric installation",
    )
    require(
        completed_code
        == (
            "pub(crate)fnmark_managed_child_driver_completed(epoch:u64,"
            "committed_read_chunks:u64,committed_write_chunks:u64,stdin_bytes:u64,"
            "output_bytes:u64,call:TypedCallMetrics,profile:SyncCallProfile,)->Result<(),"
            "ProfileError>{letterminal=ManagedChildTerminalMetrics::from_live("
            "committed_read_chunks,committed_write_chunks,stdin_bytes,output_bytes,call,profile,)"
            ".map_err(|_|ProfileError::StateMismatch)?;let(token,detach)="
            "current_managed_child(epoch)?;letmutslot=SLOT.lock();letSlotState::Active{sample,"
            "child:Some(child),faults,managed_terminal,"
            '#[cfg(feature="wasm-c84-ssh-managed-child-phase-sidecar")]'
            "managed_phase,core_owner,..}=&mut*slotelse{returnErr(ProfileError::StateMismatch);};"
            '#[cfg(feature="wasm-c84-ssh-managed-child-phase-sidecar")]'
            "letphase_incomplete=!managed_phase.child_release_ready();"
            '#[cfg(feature="wasm-c84-ssh-managed-child-phase-sidecar")]'
            "ifsample.token()==token&&child.matches(epoch,detach)&&child.state=="
            "DelegatedChildState::Claimed&&phase_incomplete{faults.insert("
            "SlotFaults::CHILD_PHASE);returnErr(ProfileError::StateMismatch);}"
            "ifsample.token()!=token||!child.matches(epoch,detach)||child.state!="
            "DelegatedChildState::Claimed||child.driver_completed||managed_terminal.is_some()||"
            "!faults.is_empty()||*core_owner!=CoreObserverOwner::Closed{returnErr("
            "ProfileError::StateMismatch);}*managed_terminal=Some(terminal);"
            "child.driver_completed=true;Ok(())}"
        ),
        "trusted driver completion admits a condition decoy or alternate writer",
    )

    detached = find_scope(source, r"\bfn\s+profile_child_detached\b", "child detach callback")
    detached_code = semantic(detached.raw)
    require(
        "state==DelegatedChildState::CompletedPendingDetach&&reason==TaskDetachReason::Exited"
        in detached_code,
        "logical closure does not require exact completed Exited detach",
    )
    require(
        "terminal.logical_live_after=0;" in detached_code,
        "exact detach does not close logical liveness",
    )
    exact_detach_write = (
        trusted_cfg
        + "ifclean{ifletSome(terminal)=managed_terminal.as_mut(){"
        "terminal.logical_live_after=0;}else{clean=false;"
        "faults.insert(SlotFaults::CHILD_DETACHED);}}"
    )
    require(
        detached_code.count(exact_detach_write) == 1,
        "trusted detach performs another terminal mutation",
    )
    require(
        detached_code
        == (
            "fnprofile_child_detached(epoch:u64,task:TaskId,domain:AllocationDomain,"
            "reason:TaskDetachReason,){ifpoison_reason().is_some(){return;}letmutslot="
            "SLOT.lock();letSlotState::Active{sample,child,child_detach,faults,"
            f'#[cfg(feature="{FEATURE}")]managed_terminal,'
            '#[cfg(feature="wasm-c84-ssh-managed-child-phase-sidecar")]managed_phase,'
            '#[cfg(feature="wasm-c84-core-poll-observer")]core_owner,..}=&mut*slotelse{return;};'
            "ifsample.token().epoch()!=epoch||!child.as_ref().is_some_and(|child|"
            "child.callback_matches(epoch,task,domain)){return;}letexact_child=child.as_ref()."
            'expect("exactdelegatedchildwascheckedabove");letstate=exact_child.state;'
            '#[cfg(feature="wasm-c84-core-poll-observer")]'
            "if*core_owner==CoreObserverOwner::Child{faults.insert(SlotFaults::CHILD_OBSERVER);}"
            '#[cfg(feature="wasm-c84-ssh-managed-child-phase-sidecar")]'
            "ifmanaged_phase.child_host_open{faults.insert(SlotFaults::CHILD_PHASE);}"
            f'#[cfg(feature="{FEATURE}")]'
            "letmutclean=state==DelegatedChildState::CompletedPendingDetach&&reason=="
            "TaskDetachReason::Exited;"
            f'#[cfg(not(feature="{FEATURE}"))]'
            "letclean=state==DelegatedChildState::CompletedPendingDetach&&reason=="
            "TaskDetachReason::Exited;"
            f'#[cfg(feature="{FEATURE}")]'
            "ifclean{ifletSome(terminal)=managed_terminal.as_mut(){terminal.logical_live_after=0;}"
            "else{clean=false;faults.insert(SlotFaults::CHILD_DETACHED);}}if!clean{faults.insert("
            "SlotFaults::CHILD_DETACHED);ifstate==DelegatedChildState::Abandoned{faults.insert("
            "SlotFaults::CHILD_ABANDONED);}}*child_detach=Some(reason);*child=None;drop(slot);"
            '#[cfg(feature="wasm-c84-ssh-managed-child-core-qemu-acceptance")]'
            "record_managed_child_detached(epoch,reason,clean);}"
        )
        and source_code.count("*child_detach=Some(reason);") == 1
        and source_code.count("child_detach=Some(") == 1,
        "trusted child detach admits a decoy or alternate liveness/detach writer",
    )

    finish_active = find_scope(source, r"\bfn\s+finish_active\b", "slot finish transition")
    finish_active_code = semantic(finish_active.raw)
    trusted_incomplete = (
        trusted_cfg
        + "lettrusted_terminal_incomplete=matchmanaged_terminal{"
        "Some(terminal)=>terminal.logical_live_after!=0,None=>true,}"
        "||child_detach!=Some(TaskDetachReason::Exited);"
    )
    trusted_install = (
        trusted_cfg
        + "{install_verified(owner,verified,managed_terminal.expect("
        '"trustedterminalcompletenesswascheckedabove"),)}'
    )
    require(
        finish_active_code.count(trusted_cfg + "managed_terminal,") == 3
        and finish_active_code.count(trusted_incomplete) == 1
        and finish_active_code.count(trusted_install) == 1,
        "finish transition does not pass the exact closed terminal metrics through",
    )

    install = find_scope(
        source,
        r"\bfn\s+install_verified\s*\([^)]*managed_terminal",
        "trusted verified installation",
    )
    require(
        semantic(install.raw)
        == (
            "fninstall_verified(owner:OwnerSeal,sample:TargetVerified<'static>,"
            "managed_terminal:ManagedChildTerminalMetrics,)->Result<(),ProfileError>{"
            "letmutslot=SLOT.lock();letexact=matches!(&*slot,SlotState::Transit{"
            "owner:actual,kind:TransitKind::Finish}ifactual.matches(owner.epoch,"
            "owner.detach));ifexact&&sample.token().epoch()==owner.epoch&&"
            "poison_reason().is_none(){*slot=SlotState::Verified{sample,owner,"
            "cursor:0,managed_terminal,};returnOk(());}drop(slot);drop(sample);"
            "poison(SlotPoison::StateMismatch);Err(ProfileError::StateMismatch)}"
        ),
        "trusted verified installation changes the retained terminal metrics",
    )

    trusted_metrics = find_scope(
        source,
        r"\bfn\s+trusted_terminal_metrics\b",
        "trusted terminal metric copy",
    )
    require(
        semantic(trusted_metrics.raw)
        == (
            "fntrusted_terminal_metrics(token:SampleToken,detach:CurrentTaskDetachLease,)"
            "->Result<ManagedChildTerminalMetrics,ProfileError>{ensure_not_poisoned()?;"
            "letslot=SLOT.lock();match&*slot{SlotState::Verified{sample,owner,cursor:0,"
            "managed_terminal,}ifsample.token()==token&&owner.matches(token.epoch(),detach)"
            "=>{Ok(*managed_terminal)}_=>Err(ProfileError::StateMismatch),}}"
        ),
        "trusted terminal metric copy is not the exact stored value",
    )

    take_trusted = find_scope(
        source,
        r"\bfn\s+take_trusted_verified\b",
        "trusted verified take",
    )
    require(
        semantic(take_trusted.raw)
        == (
            "fntake_trusted_verified(token:SampleToken,detach:CurrentTaskDetachLease,"
            "expected_terminal:ManagedChildTerminalMetrics,)->Result<(TargetVerified<'static>,"
            "OwnerSeal),ProfileError>{ensure_not_poisoned()?;letmutslot=SLOT.lock();"
            "letowner=match&*slot{SlotState::Verified{sample,owner,cursor:0,"
            "managed_terminal,}ifsample.token()==token&&owner.matches(token.epoch(),detach)"
            "&&*managed_terminal==expected_terminal=>{*owner}_=>returnErr("
            "ProfileError::StateMismatch),};letprevious=mem::replace(&mut*slot,"
            "SlotState::Transit{owner,kind:TransitKind::Trusted,},);letSlotState::Verified{"
            "sample,owner,cursor:0,managed_terminal,}=previouselse{poison("
            "SlotPoison::StateMismatch);returnErr(ProfileError::StateMismatch);};"
            "ifmanaged_terminal!=expected_terminal{drop(sample);poison("
            "SlotPoison::StateMismatch);returnErr(ProfileError::StateMismatch);}"
            "Ok((sample,owner))}"
        ),
        "trusted verified take does not compare and move the same terminal metrics",
    )

    nontrusted_stream_impl = find_scope(
        source,
        r"\bimpl\s+StreamLease\b(?=\s*\{\s*pub\(crate\)\s+const\s+fn\s+token\b)",
        "non-trusted StreamLease implementation",
    )
    require(
        semantic(source[max(0, nontrusted_stream_impl.start - 180) : nontrusted_stream_impl.start])
        .endswith(nontrusted_cfg),
        "public StreamLease methods are not excluded from trusted builds",
    )
    nontrusted_methods = re.findall(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)\b",
        masked(nontrusted_stream_impl.raw),
    )
    require(
        nontrusted_methods == ["token", "summary", "next_interval", "complete", "discard"],
        "non-trusted StreamLease method surface differs",
    )
    for method in nontrusted_methods:
        public_method = find_function(
            nontrusted_stream_impl,
            method,
            f"non-trusted stream method {method}",
        )
        require(
            semantic(public_method.raw).startswith(
                ("pub(crate)fn" + method + "(", "pub(crate)constfn" + method + "(")
            ),
            f"non-trusted stream method {method} is not crate-visible",
        )

    trusted_stream_impl = find_scope(
        source,
        r"\bimpl\s+StreamLease\b(?=\s*\{\s*fn\s+seal_trusted\b)",
        "trusted StreamLease implementation",
    )
    require(
        semantic(source[max(0, trusted_stream_impl.start - 180) : trusted_stream_impl.start])
        .endswith(trusted_cfg),
        "trusted StreamLease implementation is not directly feature-isolated",
    )
    trusted_methods = re.findall(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)\b",
        masked(trusted_stream_impl.raw),
    )
    require(
        trusted_methods == ["seal_trusted"]
        and "pub(" not in semantic(trusted_stream_impl.raw)
        and "pubfn" not in semantic(trusted_stream_impl.raw),
        "trusted StreamLease exposes streaming or crate-visible methods",
    )
    seal = find_function(trusted_stream_impl, "seal_trusted", "trusted stream seal")
    seal_code = semantic(seal.raw)
    for required in (
        "trusted_terminal_metrics(self.token,self.detach)?",
        "terminal.component_terminal()",
        "terminal.exit_status()",
        "terminal.timed_out()",
        "terminal.stdout_bytes()",
        "terminal.stderr_bytes()",
        "letlogical_live_after=metrics.logical_live_after;",
        "letpoll_exact=metrics.poll_exact;",
        "succeeded:terminal_kind==vibeos_vsh::ComponentTerminal::Success",
        "EligibleTerminalEvidence::validate(observation)",
        "take_trusted_verified(self.token,self.detach,metrics)?",
        "sample:Some(sample)",
        "evidence:Some(evidence)",
    ):
        require(required in seal_code, f"trusted stream seal omits {required!r}")
    require("letpoll_exact=true" not in seal_code, "stream seal hard-codes poll exactness")
    require("letlogical_live_after=0" not in seal_code, "stream seal hard-codes logical closure")
    full_drain_mapping = (
        "letfull_drain=metrics.stdin_bytes==FORMAL_STDOUT_BYTES&&"
        "drained_stdout_bytes==metrics.output_bytes&&stderr_bytes==0;"
    )
    terminal_observation_mapping = (
        "letobservation=TerminalObservation{"
        "read_chunks:metrics.read_chunks,write_chunks:metrics.write_chunks,"
        "fuel_consumed:metrics.fuel_consumed,poll_quanta:metrics.poll_quanta,"
        "poll_quanta_exact:poll_exact,"
        "succeeded:terminal_kind==vibeos_vsh::ComponentTerminal::Success,"
        "logical_live_after,timed_out,timeout_phase:None,exit_status,"
        "stdout_bytes:drained_stdout_bytes,stdout_sha256:FORMAL_STDOUT_SHA256,"
        "stderr_bytes,};"
    )
    acceptance_mapping = (
        f'#[cfg(any(feature="{QEMU_FEATURE}",feature="{COLLECTOR_QEMU_FEATURE}"))]'
        "acceptance:TrustedSampleAcceptanceObservation{"
        "epoch:self.token.epoch(),terminal:terminal_kind,status:exit_status,timed_out,"
        "read_chunks:metrics.read_chunks,write_chunks:metrics.write_chunks,"
        "stdout_bytes:drained_stdout_bytes,stdout_digest:FORMAL_STDOUT_SHA256,"
        "fuel_consumed:metrics.fuel_consumed,poll_quanta:metrics.poll_quanta,"
        "poll_exact,logical_live_after,full_drain,},"
    )
    require(full_drain_mapping in seal_code, "trusted full-drain mapping differs")
    require(
        terminal_observation_mapping in seal_code
        and seal_code.count("letobservation=TerminalObservation{") == 1,
        "trusted eligibility observation field mapping differs",
    )
    require(
        acceptance_mapping in seal_code
        and seal_code.count("acceptance:TrustedSampleAcceptanceObservation{") == 1,
        "trusted acceptance observation field mapping differs",
    )
    require(
        seal_code
        == (
            "fnseal_trusted(mutself,terminal:vibeos_sshd::SshExecProfileTerminal,)->Result<"
            "TrustedVerifiedSample,ProfileError>{if!self.detach.is_current_running_exact(){"
            "returnErr(ProfileError::OwnerNotCurrent);}letmetrics=trusted_terminal_metrics("
            "self.token,self.detach)?;letterminal_kind=terminal.component_terminal();"
            "letexit_status=terminal.exit_status();lettimed_out=terminal.timed_out();"
            "letdrained_stdout_bytes=terminal.stdout_bytes();letstderr_bytes=terminal."
            "stderr_bytes();letlogical_live_after=metrics.logical_live_after;letpoll_exact="
            "metrics.poll_exact;letfull_drain=metrics.stdin_bytes==FORMAL_STDOUT_BYTES&&"
            "drained_stdout_bytes==metrics.output_bytes&&stderr_bytes==0;letobservation="
            "TerminalObservation{read_chunks:metrics.read_chunks,write_chunks:metrics."
            "write_chunks,fuel_consumed:metrics.fuel_consumed,poll_quanta:metrics.poll_quanta,"
            "poll_quanta_exact:poll_exact,succeeded:terminal_kind==vibeos_vsh::"
            "ComponentTerminal::Success,logical_live_after,timed_out,timeout_phase:None,"
            "exit_status,stdout_bytes:drained_stdout_bytes,stdout_sha256:FORMAL_STDOUT_SHA256,"
            "stderr_bytes,};letevidence=matchEligibleTerminalEvidence::validate(observation){"
            "Ok(evidence)iffull_drain=>evidence,Ok(_)|Err(_)=>{letreport=discard_stream("
            "self.token,self.detach)?;self.live=false;returnErr(ProfileError::Rejected(report));}};"
            "let(sample,owner)=take_trusted_verified(self.token,self.detach,metrics)?;"
            "self.live=false;Ok(TrustedVerifiedSample{sample:Some(sample),evidence:Some(evidence),"
            "owner,"
            f'#[cfg(any(feature="{QEMU_FEATURE}",feature="{COLLECTOR_QEMU_FEATURE}"))]'
            "acceptance:TrustedSampleAcceptanceObservation{epoch:self.token.epoch(),"
            "terminal:terminal_kind,status:exit_status,timed_out,read_chunks:metrics.read_chunks,"
            "write_chunks:metrics.write_chunks,stdout_bytes:drained_stdout_bytes,stdout_digest:"
            "FORMAL_STDOUT_SHA256,fuel_consumed:metrics.fuel_consumed,poll_quanta:"
            "metrics.poll_quanta,poll_exact,logical_live_after,full_drain,},"
            "not_send_sync:PhantomData,})}"
        ),
        "trusted stream seal admits a decoy, rebind, or split-authority path",
    )

    bundle = find_scope(
        source,
        r"\bpub\(crate\)\s+struct\s+TrustedVerifiedSample\b",
        "opaque trusted bundle",
    )
    bundle_code = semantic(bundle.raw)
    for field in (
        "sample:Option<TargetVerified<'static>>",
        "evidence:Option<EligibleTerminalEvidence>",
        "owner:OwnerSeal",
        "not_send_sync:PhantomData<*mut()>",
    ):
        require(field in bundle_code, f"trusted bundle omits {field!r}")
    require(
        "pubsample:" not in bundle_code and "pub(crate)sample:" not in bundle_code,
        "trusted sample authority field is exposed",
    )
    require(
        "pubevidence:" not in bundle_code and "pub(crate)evidence:" not in bundle_code,
        "trusted evidence field is exposed",
    )
    prefix = source[max(0, bundle.start - 180) : bundle.start]
    require(
        not re.search(r"#\s*\[\s*derive\s*\([^]]*(Clone|Copy|Default)", prefix),
        "trusted bundle is cloneable, copyable, or defaultable",
    )
    bundle_impl = find_scope(source, r"\bimpl\s+TrustedVerifiedSample\b", "trusted bundle impl")
    bundle_methods = re.findall(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)\b",
        masked(bundle_impl.raw),
    )
    require(
        bundle_methods == ["discard", "acceptance_observation"],
        "trusted bundle method surface can split or expose its authorities",
    )
    acceptance_accessor = find_function(
        bundle_impl,
        "acceptance_observation",
        "trusted acceptance observation accessor",
    )
    require(
        semantic(acceptance_accessor.raw)
        == (
            "pub(crate)constfnacceptance_observation(&self)"
            "->TrustedSampleAcceptanceObservation{self.acceptance}"
        ),
        "trusted acceptance accessor does not return the exact sealed observation",
    )
    discard = find_function(bundle_impl, "discard", "trusted bundle discard")
    discard_code = semantic(discard.raw)
    require(
        discard_code
        == (
            "pub(crate)fndiscard(mutself)->Result<RejectionReport,ProfileError>{"
            "letSome(sample)=self.sample.take()else{returnErr(ProfileError::StateMismatch);};"
            "let_=self.evidence.take();"
            f'#[cfg(not(feature="{COLLECTOR_FEATURE}"))]'
            "abandon_trusted_sample(sample,self.owner)}"
        ),
        "trusted bundle discard does not consume both authorities",
    )
    bundle_drop = find_scope(
        source,
        r"\bimpl\s+Drop\s+for\s+TrustedVerifiedSample\b",
        "trusted bundle Drop",
    )
    require(
        semantic(bundle_drop.raw)
        == (
            "implDropforTrustedVerifiedSample{fndrop(&mutself){ifletSome(sample)="
            "self.sample.take(){let_=self.evidence.take();"
            f'#[cfg(not(feature="{COLLECTOR_FEATURE}"))]'
            "let_=abandon_trusted_sample("
            "sample,self.owner);}}}"
        ),
        "trusted bundle Drop does not consume both authorities together",
    )
    slot_semantic = source_code
    require(
        "unsafeimplSendforTrustedVerifiedSample" not in slot_semantic
        and "unsafeimplSyncforTrustedVerifiedSample" not in slot_semantic,
        "trusted bundle is manually Send or Sync",
    )
    for forbidden in ("pub(crate)fninto_parts", "pubfninto_parts", "ProfilePublisher"):
        require(forbidden not in slot_semantic, f"slot trusted path admits {forbidden}")
    require(
        slot_semantic.count("implTrustedVerifiedSample{") == 1
        and slot_semantic.count("forTrustedVerifiedSample{") == 1
        and slot_semantic.count("self.sample.take()") == 2
        and slot_semantic.count("self.evidence.take()") == 2
        and slot_semantic.count(".sample") == 2
        and slot_semantic.count(".evidence") == 2,
        "trusted bundle has another authority accessor or implementation",
    )


REQUEST_MARKER = (
    "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch={} status={} " + SUCCESSOR_SUFFIX
)
IRQ_MARKER = (
    "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY RESPONSE epoch={} status={} "
    "parent_pair={} child_pair={} terminal_inactive=1 paired={} inactive={} active_epoch={} "
    + SUCCESSOR_SUFFIX
)
PHASE_MARKER = (
    "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR RESPONSE epoch={} status={} "
    "child_core_starts={} child_core_finishes={} child_host_starts={} child_host_finishes={} "
    "child_wait_starts={} child_wait_finishes={} cleanup_count={} parent_host_starts={} "
    "parent_host_finishes={} parent_wait_starts={} parent_wait_finishes={} "
    "child_wait_open=0 parent_wait_open=0 late=0 clean=1 " + SUCCESSOR_SUFFIX
)
CORE_MARKER = (
    "WASM_C84_SSH_MANAGED_CHILD_CORE RESPONSE epoch={} status={} claim=1 release=1 "
    "detach=exited clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 "
    + SUCCESSOR_SUFFIX
)
FINISH_MARKER = (
    "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY RESPONSE epoch={} status={} "
    + SUCCESSOR_SUFFIX
)
CORE_ARGUMENTS = (
    "epoch,status,observation.core_polls,observation.core_pairs,"
    "observation.typed_polls,ready_epoch"
)
REQUEST_ARGUMENTS = "epoch,status,ready_epoch"
IRQ_ARGUMENTS = (
    "epoch,status,causal_pair,causal_pair,observation.paired,"
    "observation.inactive,observation.active_epoch,ready_epoch,"
)
PHASE_ARGUMENTS = (
    "epoch,status,child.core_pairs,child.core_pairs,phase.child_host_starts,"
    "phase.child_host_finishes,phase.child_wait_starts,phase.child_wait_finishes,"
    "phase.cleanup_count,phase.parent_host_starts,phase.parent_host_finishes,"
    "phase.parent_wait_starts,phase.parent_wait_finishes,ready_epoch"
)
FINISH_ARGUMENTS = "epoch,status,ready_epoch"
NORMAL_ARGUMENTS = (
    "epoch,observation.read_chunks,observation.write_chunks,observation.stdout_bytes,"
    "observation.fuel_consumed,observation.poll_quanta,evidence.ready_epoch"
)
DROP_ARGUMENTS = "epoch,ready_epoch"


def direct_marker_unit(scope, marker: str, arguments: str, label: str) -> str:
    units = IRQ.direct_feature_units(scope.raw, QEMU_FEATURE)
    print_units = [unit for unit in units if "println!(" in semantic(unit)]
    matching = [unit for unit in units if marker in comment_masked(unit)]
    require(len(matching) == 1, f"{label} trusted direct marker count differs: {len(matching)}")
    unit = matching[0]
    require(
        len(print_units) == 1 and print_units[0] == unit,
        f"{label} trusted cfg has another println branch",
    )
    code = semantic(unit)
    expected = semantic(
        f'#[cfg(feature = "{QEMU_FEATURE}")]\n'
        f'crate::println!("{marker}",{arguments});'
    )
    require(
        code == expected,
        f"{label} trusted println literal or argument sequence differs",
    )
    return unit


def exact_print_call(scope, marker: str, arguments: str, label: str) -> None:
    code = semantic(scope.raw)
    expected = semantic(f'crate::println!("{marker}",{arguments});')
    require(expected in code, f"{label} println literal or argument sequence differs")
    require(code.count("crate::println!(") == 1, f"{label} has another println")


def verify_ssh(inputs: Inputs) -> None:
    source = PHASE.CORE.without_direct_feature_units(inputs.ssh, COLLECTOR_FEATURE)
    source = PHASE.CORE.without_direct_feature_units(source, COLLECTOR_QEMU_FEATURE)
    inputs = replace(inputs, ssh=source)
    ssh_code = semantic(inputs.ssh)
    predecessor_helper_guard = (
        f'#[cfg(all(feature="{FINISH_FEATURE}",not(feature="{FEATURE}")))]'
        "fnfinish_verify_discard_and_ack_profile("
    )
    require(
        ssh_code.count(predecessor_helper_guard) == 1,
        "discard-only finish predecessor helper is compiled into the trusted build",
    )

    owner = find_scope(inputs.ssh, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner")
    boundary = find_function(owner, "response_boundary", "trusted response boundary")
    boundary_code = semantic(boundary.raw)
    require(
        f'#[cfg(feature="{FEATURE}")]terminal_seal:SshExecProfileTerminal' in boundary_code,
        "kernel boundary does not consume the SSH terminal seal",
    )
    require(
        "terminal_seal.component_terminal()==vibeos_vsh::ComponentTerminal::Success"
        in boundary_code,
        "kernel response admits status-only or Returned(0) success",
    )
    require("!terminal_seal.timed_out()" in boundary_code, "kernel response admits timeout")
    require(
        "finish_verify_trusted_discard_and_ack_profile(run,terminal_seal)" in boundary_code,
        "kernel does not move the terminal seal into trusted finish",
    )
    require(
        "trusted_sample_response(epoch,_terminal_evidence)" in boundary_code,
        "trusted terminal marker is detached from the returned evidence",
    )
    trusted_terminal_mapping = (
        f'#[cfg(all(feature="{FEATURE}",not(feature="{COLLECTOR_FEATURE}")))]'
        "letterminal=finish_verify_trusted_discard_and_ack_profile(run,terminal_seal)"
        ".map(|evidence|(evidence.ready_epoch,evidence));"
    )
    require(
        boundary_code.count(trusted_terminal_mapping) == 1
        and "let_terminal_evidence" not in boundary_code
        and "letmut_terminal_evidence" not in boundary_code,
        "trusted response boundary rebinds the returned evidence",
    )
    trusted_prerequisite = (
        f'#[cfg(feature="{FEATURE}")]'
        "lettrusted_terminal_prerequisite=terminal_seal.component_terminal()=="
        "vibeos_vsh::ComponentTerminal::Success&&!terminal_seal.timed_out();"
        f'#[cfg(not(feature="{FEATURE}"))]'
        "lettrusted_terminal_prerequisite=true;"
        f'#[cfg(feature="{FINISH_FEATURE}")]'
        "ifstatus!=0||!trusted_terminal_prerequisite||!child_ready||"
        "!profile_policy_is_current(self.policy){letrecycled=cancel_and_ack_profile(run,"
        "crate::wasm_aot_profile_slot::SlotFaults::default());letstage=ifrecycled.is_ok(){"
        '"response-prerequisite"}else{"response-prerequisite-cancel"};'
        "profile_request_failure(stage,Some(epoch));returnErr(());}"
    )
    require(
        trusted_prerequisite in boundary_code
        and boundary_code.count("lettrusted_terminal_prerequisite=") == 2
        and boundary_code.count("trusted_terminal_prerequisite") == 3,
        "trusted response prerequisite admits a decoy or rebind",
    )

    helper = find_scope(
        inputs.ssh,
        r"\bfn\s+finish_verify_trusted_discard_and_ack_profile\b",
        "trusted finish/discard helper",
    )
    helper_code = semantic(helper.raw)
    for required in (
        "run.finish_trusted(terminal)",
        "Err(ProfileError::Rejected(report))",
        "acknowledge_finish_verify_rejection(epoch,report)?",
        "rejection().filter(|report|report.epoch==epoch)",
        "letacceptance=bundle.acceptance_observation();",
        "bundle.discard().map_err(|_|())?",
        "report.cause==RejectionCause::TrustedSampleAbandoned",
        "report.facade_faults.is_empty()",
        "report.ledger_error.is_none()",
        "report.slot_faults==SlotFaults::default()",
        "report.intervals_emitted==0",
        "rejection()==Some(report)",
        "SlotStatus::Rejected(report)",
        "letready_epoch=acknowledge_finish_verify_rejection(epoch,report)?;",
        "if!report_is_exact||!stored_rejection_is_exact{returnErr(());}",
    ):
        require(required in helper_code, f"trusted discard closure omits {required!r}")
    require(
        helper_code.count("acknowledge_finish_verify_rejection(epoch,report)") == 3,
        "trusted finish errors or final discard do not each close their rejection",
    )
    require(
        "ifletSome(report)=rejection().filter(|report|report.epoch==epoch){"
        "let_=acknowledge_finish_verify_rejection(epoch,report);}" in helper_code,
        "non-report trusted finish error does not recycle its same-epoch rejection",
    )
    trusted_evidence_mapping = (
        "Ok(TrustedSampleEvidence{ready_epoch,"
        f'#[cfg(feature="{QEMU_FEATURE}")]acceptance,}})'
    )
    require(
        helper_code.count("letacceptance=bundle.acceptance_observation();") == 1
        and helper_code.count("letacceptance=") == 1
        and "letmutacceptance" not in helper_code
        and helper_code.count("TrustedSampleEvidence{") == 1
        and trusted_evidence_mapping in helper_code,
        "trusted acceptance observation is rebound before response telemetry",
    )
    require(
        helper_code
        == (
            "fnfinish_verify_trusted_discard_and_ack_profile(run:crate::"
            "wasm_aot_profile_slot::RunLease,terminal:SshExecProfileTerminal,)->Result<"
            "TrustedSampleEvidence,()>{usecrate::wasm_aot_profile_slot::{rejection,"
            "ProfileError,RejectionCause,SlotFaults,SlotStatus,};letepoch=run.token().epoch();"
            "letbundle=matchrun.finish_trusted(terminal){Ok(bundle)=>bundle,Err("
            "ProfileError::Rejected(report))=>{let_=acknowledge_finish_verify_rejection("
            "epoch,report)?;returnErr(());}Err(_)=>{ifletSome(report)=rejection().filter("
            "|report|report.epoch==epoch){let_=acknowledge_finish_verify_rejection(epoch,"
            "report);}returnErr(());}};"
            f'#[cfg(feature="{QEMU_FEATURE}")]'
            "letacceptance=bundle.acceptance_observation();letreport=bundle.discard().map_err("
            "|_|())?;letreport_is_exact=report.epoch==epoch&&report.cause=="
            "RejectionCause::TrustedSampleAbandoned&&report.facade_faults.is_empty()&&"
            "report.ledger_error.is_none()&&report.slot_faults==SlotFaults::default()&&"
            "report.intervals_emitted==0;letstored_rejection_is_exact=rejection()==Some(report)"
            "&&crate::wasm_aot_profile_slot::status()==SlotStatus::Rejected(report);"
            "letready_epoch=acknowledge_finish_verify_rejection(epoch,report)?;"
            "if!report_is_exact||!stored_rejection_is_exact{returnErr(());}Ok("
            "TrustedSampleEvidence{ready_epoch,"
            f'#[cfg(feature="{QEMU_FEATURE}")]'
            "acceptance,})}"
        ),
        "trusted bundle discard/ack helper admits a condition decoy or authority rebind",
    )
    ordered(
        helper_code,
        (
            "run.finish_trusted(terminal)",
            "bundle.acceptance_observation()",
            "bundle.discard()",
            "rejection()==Some(report)",
            "letready_epoch=acknowledge_finish_verify_rejection(epoch,report)?;",
        ),
        "trusted bundle inspection/discard/ack",
    )

    response = find_scope(inputs.ssh, r"\bfn\s+trusted_sample_response\b", "trusted response telemetry")
    response_code = semantic(response.raw)
    require(
        response_code.count("letobservation=evidence.acceptance;") == 1
        and response_code.count("letobservation=") == 1
        and "letmutobservation" not in response_code,
        "trusted response does not bind the exact immutable acceptance observation",
    )
    for required in (
        "observation.terminal==vibeos_vsh::ComponentTerminal::Success",
        "observation.status==0",
        "!observation.timed_out",
        "observation.read_chunks==FORMAL_READ_CHUNKS",
        "observation.write_chunks==FORMAL_WRITE_CHUNKS",
        "observation.stdout_bytes==FORMAL_STDOUT_BYTES",
        "observation.stdout_digest==FORMAL_STDOUT_SHA256",
        "observation.fuel_consumed!=0",
        "observation.fuel_consumed<=vibeos_wasm_aot_profile::MAX_FORMAL_FUEL",
        "observation.poll_quanta!=0",
        "observation.poll_quanta!=u64::MAX",
        "observation.poll_exact",
        "observation.logical_live_after==0",
        "observation.full_drain",
    ):
        require(required in response_code, f"truthful trusted marker guard omits {required!r}")
    require(comment_masked(response.raw).count(NORMAL_MARKER) == 1, "trusted RESPONSE marker differs")
    exact_print_call(response, NORMAL_MARKER, NORMAL_ARGUMENTS, "trusted RESPONSE")
    require("iffalse" not in response_code, "trusted RESPONSE marker is behind dead code")
    expected_response = semantic(
        "fn trusted_sample_response(epoch: u64, evidence: TrustedSampleEvidence) "
        "-> Result<(), ()> {\n"
        "use vibeos_wasm_aot_profile::{FORMAL_READ_CHUNKS, FORMAL_STDOUT_BYTES, "
        "FORMAL_STDOUT_SHA256, FORMAL_WRITE_CHUNKS,};\n"
        "let observation = evidence.acceptance;\n"
        "let exact = observation.epoch == epoch "
        "&& observation.terminal == vibeos_vsh::ComponentTerminal::Success "
        "&& observation.status == 0 && !observation.timed_out "
        "&& observation.read_chunks == FORMAL_READ_CHUNKS "
        "&& observation.write_chunks == FORMAL_WRITE_CHUNKS "
        "&& observation.stdout_bytes == FORMAL_STDOUT_BYTES "
        "&& observation.stdout_digest == FORMAL_STDOUT_SHA256 "
        "&& observation.fuel_consumed != 0 "
        "&& observation.fuel_consumed <= vibeos_wasm_aot_profile::MAX_FORMAL_FUEL "
        "&& observation.poll_quanta != 0 && observation.poll_quanta != u64::MAX "
        "&& observation.poll_exact && observation.logical_live_after == 0 "
        "&& observation.full_drain;\n"
        "if !exact { profile_request_failure(\"trusted-sample-observation\", Some(epoch)); "
        "return Err(()); }\n"
        f'crate::println!("{NORMAL_MARKER}",{NORMAL_ARGUMENTS});\n'
        "Ok(())\n}"
    )
    require(
        response_code == expected_response,
        "trusted RESPONSE validation admits a condition decoy or telemetry rebind",
    )

    drop = find_scope(inputs.ssh, r"\bfn\s+trusted_sample_drop\b", "trusted Drop telemetry")
    require(comment_masked(drop.raw).count(DROP_MARKER) == 1, "trusted Drop marker differs")
    exact_print_call(drop, DROP_MARKER, DROP_ARGUMENTS, "trusted Drop")

    request = find_scope(inputs.ssh, r"\bfn\s+profile_request_response\b", "request RESPONSE")
    irq = find_scope(inputs.ssh, r"\bfn\s+managed_irq_response\b", "IRQ RESPONSE")
    phase = find_scope(inputs.ssh, r"\bfn\s+profile_phase_response\b", "phase RESPONSE")
    finish = find_scope(inputs.ssh, r"\bfn\s+finish_verify_response\b", "finish RESPONSE")
    for scope, marker, arguments, label in (
        (boundary, CORE_MARKER, CORE_ARGUMENTS, "Core RESPONSE"),
        (request, REQUEST_MARKER, REQUEST_ARGUMENTS, "request RESPONSE"),
        (irq, IRQ_MARKER, IRQ_ARGUMENTS, "IRQ RESPONSE"),
        (phase, PHASE_MARKER, PHASE_ARGUMENTS, "phase RESPONSE"),
        (finish, FINISH_MARKER, FINISH_ARGUMENTS, "finish RESPONSE"),
    ):
        direct_marker_unit(scope, marker, arguments, label)
    require(
        comment_masked(inputs.ssh).count(SUCCESSOR_SUFFIX) == 5,
        "five predecessor trusted suffixes are not exact",
    )

    integration = masked(helper.raw + response.raw + drop.raw + boundary.raw)
    for forbidden in (
        "ProfilePublisher",
        "publish_profile",
        "TranscriptBinding",
        "VIBE_WASM_AOT_META",
        "VIBE_WASM_AOT_SAMPLE",
        "VIBE_WASM_AOT_END",
        "collector",
        "physical_evidence",
        "exec::spawn(",
        "exec::spawn_pinned_on(",
        "mem::forget",
        ".await",
    ):
        require(forbidden not in integration, f"trusted live adapter admits {forbidden}")


def ci_named_step(source: str, name: str) -> str:
    header = f"      - name: {name}\n"
    require(source.count(header) == 1, f"CI step {name!r} count differs")
    start = source.index(header)
    lines = source[start:].splitlines(keepends=True)
    selected = [lines[0]]
    for line in lines[1:]:
        if line.strip():
            indentation = len(line) - len(line.lstrip(" "))
            if indentation <= 6:
                break
        selected.append(line)
    return "".join(selected).rstrip("\n")


def verify_docs_ci(inputs: Inputs) -> None:
    require(
        inputs.ci.startswith("name: CI\n\non:\n  push:\n  pull_request:\n\njobs:\n"),
        "CI push/pull-request trigger contract differs",
    )
    require(
        not re.search(r"(?m)^    (?:if|continue-on-error):", inputs.ci),
        "CI admits a job-level skip or failure bypass",
    )
    exact_job_prefixes = {
        "host-tests": (
            "  host-tests:\n"
            "    name: Host unit tests\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
        ),
        "qemu-tests": (
            "  qemu-tests:\n"
            "    name: QEMU integration\n"
            "    needs: differential\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
        ),
    }
    for job, expected in exact_job_prefixes.items():
        require(inputs.ci.count(f"  {job}:\n") == 1, f"CI {job} job count differs")
        start = inputs.ci.index(f"  {job}:\n")
        steps = inputs.ci.find("    steps:\n", start)
        require(steps >= 0, f"CI {job} job has no steps")
        actual = inputs.ci[start : steps + len("    steps:\n")]
        require(actual == expected, f"CI {job} can be skipped or ignore failure")
    require(
        hashlib.sha256(inputs.qemu_script).hexdigest() == QEMU_SCRIPT_SHA256,
        "trusted QEMU enforcement script differs from its reviewed closure",
    )
    require(
        hashlib.sha256(inputs.peer_script).hexdigest() == PEER_SCRIPT_SHA256,
        "trusted transcript peer differs from its reviewed parser/selftest closure",
    )
    require(
        len(inputs.peer_dependencies) == len(PEER_DEPENDENCY_SHA256),
        "trusted transcript parser dependency count differs",
    )
    for path, source, expected in zip(
        PEER_DEPENDENCY_PATHS,
        inputs.peer_dependencies,
        PEER_DEPENDENCY_SHA256,
        strict=True,
    ):
        require(
            hashlib.sha256(source).hexdigest() == expected,
            f"trusted transcript parser dependency {path.name} differs",
        )
    require(inputs.testing.count(COMMAND) == 2, "TESTING trusted verifier command count differs")
    require(inputs.decision_doc.count(COMMAND) == 2, "decision doc trusted verifier command count differs")
    require(inputs.testing.count(QEMU_COMMAND) == 2, "TESTING trusted QEMU command count differs")
    require(inputs.decision_doc.count(QEMU_COMMAND) == 2, "decision doc trusted QEMU command count differs")
    ci_step = (
        "      - name: Exercise the C8.4 SSH managed-child trusted-sample closure\n"
        f"        run: {QEMU_COMMAND}"
    )
    require(
        ci_named_step(inputs.ci, "Exercise the C8.4 SSH managed-child trusted-sample closure")
        == ci_step,
        "CI trusted-sample step differs or can ignore failure",
    )
    require(inputs.ci.count(QEMU_COMMAND) == 1, "CI trusted QEMU command count differs")
    require(
        ci_named_step(inputs.ci, "Verify the C8.4 trusted live-sample boundary")
        == SOURCE_CI_STEP,
        "CI trusted source verifier differs or can ignore failure",
    )
    require(inputs.ci.count(COMMAND) == 1, "CI trusted source-verifier command count differs")
    require(
        ci_named_step(inputs.ci, "Test the C8.4 trusted transcript parser") == PEER_CI_STEP,
        "CI trusted peer selftest differs or can ignore failure",
    )
    require(
        inputs.ci.count(
            "python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py --selftest"
        )
        == 1,
        "CI trusted peer selftest command count differs",
    )
    require(
        ci_named_step(inputs.ci, "Test the C8.4 trusted SSH terminal seam")
        == SSHD_TEST_STEP,
        "CI trusted SSHD unit-test step differs or can ignore failure",
    )
    require(
        inputs.ci.count("--features c84-profile-trusted-sample,native-revoke-target-acceptance")
        == 1,
        "CI trusted SSHD feature-test command count differs",
    )
    require(
        "**Status (2026-08-27): implementation in progress.**" in inputs.roadmap,
        "WASM roadmap still presents the implementation as wholly planned",
    )
    for text in (
        "live trusted-terminal",
        "private 24-sample collector",
        "final workload-specific AOT decision",
    ):
        require(text in inputs.roadmap, f"WASM roadmap trusted status omits {text!r}")
    normalized_docs = {
        "TESTING": " ".join(inputs.testing.split()),
        "decision doc": " ".join(inputs.decision_doc.split()),
    }
    exact_doc_contracts = {
        "TESTING": (
            "The trusted image preserves every predecessor marker format and field contract, "
            "retaining 27/28 phase, 19 Core, eight request, six IRQ, and four finish/verify "
            "markers. The epoch-3 phase/Core observer count remains dynamically parsed and "
            "must agree across both families; it is not claimed byte-identical to a separate "
            "predecessor run.",
            "The peer accepts canonical decimal values only, with `1 <= F <= 500000`, "
            "`1 <= P < u64::MAX`, and `R = E + 1`; neither live count is frozen. It also "
            "requires each trusted `P` to equal the same epoch's dynamically parsed Core "
            "`typed_polls`, and requires phase/Core counts to agree.",
        ),
        "decision doc": (
            "All five predecessor families preserve their marker formats and field contracts, "
            "with the exact 27/28 phase, 19 Core, eight request, six IRQ, and four finish/verify "
            "counts. The epoch-3 phase/Core observer count is parsed dynamically and must agree "
            "across those two families; no byte identity with a separate predecessor run is "
            "claimed.",
            "The peer requires canonical decimal `1 <= F <= 500000`, `1 <= P < u64::MAX`, "
            "and `R = E + 1`; it does not freeze scheduler-dependent values. Each trusted `P` "
            "must equal the same epoch's dynamically parsed Core `typed_polls`, and phase/Core "
            "counts must agree.",
        ),
    }
    for source, label in ((inputs.testing, "TESTING"), (inputs.decision_doc, "decision doc")):
        for text in (
            "sibling",
            "Returned(0)",
            "TrustedVerifiedSample",
            "TrustedSampleAbandoned",
            "ProfilePublisher",
            "META/SAMPLE/END",
            "physical Milk-V Duo",
            "AOT decision",
        ):
            require(text in source, f"{label} trusted boundary omits {text!r}")
        for contract in exact_doc_contracts[label]:
            require(contract in normalized_docs[label], f"{label} trusted evidence claim differs")
        require(
            "leaves every predecessor nonterminal and epoch-3 DROP byte unchanged"
            not in normalized_docs[label],
            f"{label} overclaims byte-identical predecessor output",
        )
        require(
            f"{FAMILY} RESPONSE epoch=E status=0 exact_success=1 full_drain=1 "
            "read_chunks=13 write_chunks=13 stdout_bytes=12325 "
            "stdout_sha256=791f3fe1339984e8a8489c12ea5ff479ac7caa07c87be451134d3af0f526bb27"
            in source,
            f"{label} trusted marker is missing",
        )


def verify_trusted(inputs: Inputs) -> None:
    verify_features(inputs)
    verify_sshd(inputs.sshd)
    verify_runtime(inputs.runtime)
    verify_component(inputs.component)
    verify_slot(inputs.slot)
    verify_ssh(inputs)
    verify_docs_ci(inputs)


def verify(inputs: Inputs, *, predecessors: bool = True) -> None:
    if predecessors:
        try:
            STREAM.verify(inputs.stream_predecessor)
            PUBLISHER.verify(inputs.publisher_predecessor, predecessor=False, contract=False)
        except Exception as error:
            raise VerificationError(f"publisher/verified-stream predecessor failed: {error}") from error
    verify_trusted(inputs)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest seed {label!r} count differs: {count}")
    return value.replace(old, new, 1)


def mutate_text(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    value = getattr(data, field)
    require(type(value) is str, f"selftest {field} is not text")
    return replace(data, **{field: replace_once(value, old, new, label)})


def mutate_function(
    data: Inputs,
    field: str,
    function: str,
    old: str,
    new: str,
    label: str,
) -> Inputs:
    source = getattr(data, field)
    scope = find_scope(source, rf"\bfn\s+{re.escape(function)}\b", label)
    mutated = replace_once(scope.raw, old, new, label)
    return replace(data, **{field: source[: scope.start] + mutated + source[scope.end :]})


def mutate_scope(
    data: Inputs,
    field: str,
    header: str,
    old: str,
    new: str,
    label: str,
) -> Inputs:
    source = getattr(data, field)
    scope = find_scope(source, header, label)
    mutated = replace_once(scope.raw, old, new, label)
    return replace(data, **{field: source[: scope.start] + mutated + source[scope.end :]})


def mutate_method(
    data: Inputs,
    field: str,
    owner_header: str,
    function: str,
    old: str,
    new: str,
    label: str,
) -> Inputs:
    source = getattr(data, field)
    owner = find_scope(source, owner_header, f"{label} owner")
    method = find_function(owner, function, label)
    mutated = replace_once(method.raw, old, new, label)
    start = owner.start + method.start
    end = owner.start + method.end
    return replace(data, **{field: source[:start] + mutated + source[end:]})


def mutate_manifest(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    raw = getattr(data, field).decode("utf-8")
    return replace(data, **{field: replace_once(raw, old, new, label).encode("utf-8")})


def mutate_peer_dependency(
    data: Inputs,
    index: int,
    old: str,
    new: str,
    label: str,
) -> Inputs:
    sources = list(data.peer_dependencies)
    raw = sources[index].decode("utf-8")
    sources[index] = replace_once(raw, old, new, label).encode("utf-8")
    return replace(data, peer_dependencies=tuple(sources))


def add_bundle_into_parts(data: Inputs) -> Inputs:
    source = data.slot
    scope = find_scope(source, r"\bimpl\s+TrustedVerifiedSample\b", "bundle into_parts")
    require(scope.raw.endswith("}"), "trusted bundle impl does not end in brace")
    addition = "\n    pub(crate) fn into_parts(self) { let _ = self; }\n"
    mutated = scope.raw[:-1] + addition + "}"
    return replace(data, slot=source[: scope.start] + mutated + source[scope.end :])


def add_bundle_evidence_accessor(data: Inputs) -> Inputs:
    source = data.slot
    scope = find_scope(source, r"\bimpl\s+TrustedVerifiedSample\b", "bundle evidence accessor")
    require(scope.raw.endswith("}"), "trusted bundle impl does not end in brace")
    addition = (
        "\n    pub(crate) fn take_evidence(&mut self) "
        "-> Option<EligibleTerminalEvidence> { self.evidence.take() }\n"
    )
    mutated = scope.raw[:-1] + addition + "}"
    return replace(data, slot=source[: scope.start] + mutated + source[scope.end :])


def add_formal_io_external_writer(data: Inputs) -> Inputs:
    source = data.component
    helper = (
        f'\n#[cfg(feature = "{FEATURE}")]\n'
        "fn forge_formal_io(counters: &mut FormalIoCounters) {\n"
        "    counters.read_chunks = FORMAL_READ_CHUNKS;\n"
        "    counters.read_bytes = FORMAL_STDOUT_BYTES;\n"
        "    counters.write_chunks = FORMAL_WRITE_CHUNKS;\n"
        "    counters.write_bytes = FORMAL_STDOUT_BYTES;\n"
        "    counters.invalid = false;\n"
        "}\n"
    )
    source = replace_once(
        source,
        "\n#[cfg(feature = \"wasm-c84-ssh-managed-child-trusted-sample\")]\n"
        "impl FormalIoCounters {",
        helper
        + "\n#[cfg(feature = \"wasm-c84-ssh-managed-child-trusted-sample\")]\n"
        "impl FormalIoCounters {",
        "external formal IO writer helper",
    )
    source = replace_once(
        source,
        "    drop(call);\n",
        "    drop(call);\n"
        "    if let Some(counters) = dispatcher.formal_io.as_mut() {\n"
        "        forge_formal_io(counters);\n"
        "    }\n",
        "external formal IO writer call",
    )
    return replace(data, component=source)


def add_profile_external_writer(data: Inputs) -> Inputs:
    source = data.component
    helper = (
        f'\n#[cfg(feature = "{FEATURE}")]\n'
        "fn forge_profile(profile: &mut SyncCallProfile) {\n"
        "    profile.typed_polls = profile.core_polls;\n"
        "}\n"
    )
    source = replace_once(
        source,
        '\n#[cfg(feature = "ssh-component-command")]\nasync fn run_image_component(',
        helper + '\n#[cfg(feature = "ssh-component-command")]\nasync fn run_image_component(',
        "external sync-call profile writer helper",
    )
    source = replace_once(
        source,
        "    #[cfg(feature = \"wasm-c84-ssh-managed-child-core-qemu-acceptance\")]\n"
        "    if profile_epoch != 0 {\n"
        "        crate::wasm_aot_profile_slot::record_managed_child_core_profile(",
        f'    #[cfg(feature = "{FEATURE}")]\n'
        "    forge_profile(&mut core_profile);\n"
        "    #[cfg(feature = \"wasm-c84-ssh-managed-child-core-qemu-acceptance\")]\n"
        "    if profile_epoch != 0 {\n"
        "        crate::wasm_aot_profile_slot::record_managed_child_core_profile(",
        "external sync-call profile writer call",
    )
    return replace(data, component=source)


def add_terminal_whole_value_writer(data: Inputs) -> Inputs:
    source = data.sshd
    helper = (
        f'\n#[cfg(feature = "{SSHD_FEATURE}")]\n'
        "fn forge_profile_terminal(slot: &mut Option<SshExecProfileTerminal>) {\n"
        "    *slot = Some(SshExecProfileTerminal {\n"
        "        component_terminal: vibeos_vsh::ComponentTerminal::Success,\n"
        "        exit_status: 0,\n"
        "        timed_out: false,\n"
        "        stdout_bytes: 12_325,\n"
        "        stderr_bytes: 0,\n"
        "    });\n"
        "}\n"
    )
    source = replace_once(
        source,
        '\n#[cfg(feature = "c84-profile-request-parent")]\nimpl SshExecProfileRun {',
        helper
        + '\n#[cfg(feature = "c84-profile-request-parent")]\nimpl SshExecProfileRun {',
        "whole-value terminal writer helper",
    )
    data = replace(data, sshd=source)
    return mutate_method(
        data,
        "sshd",
        r"\bimpl\s+SshExecProfileRun\b",
        "phase_host",
        "pub fn phase_host(&mut self) -> Result<(), ()> {\n",
        "pub fn phase_host(&mut self) -> Result<(), ()> {\n"
        "        forge_profile_terminal(&mut self.terminal);\n",
        "whole-value terminal writer call",
    )


def add_terminal_manual_clone(data: Inputs) -> Inputs:
    source = data.sshd
    terminal_impl = find_scope(
        source,
        r"\bimpl\s+SshExecProfileTerminal\b",
        "manual terminal Clone insertion",
    )
    addition = (
        f'\n\n#[cfg(feature = "{SSHD_FEATURE}")]\n'
        "impl Clone for SshExecProfileTerminal where Self: Sized {\n"
        "    fn clone(&self) -> Self {\n"
        "        Self {\n"
        "            component_terminal: self.component_terminal,\n"
        "            exit_status: self.exit_status,\n"
        "            timed_out: self.timed_out,\n"
        "            stdout_bytes: self.stdout_bytes,\n"
        "            stderr_bytes: self.stderr_bytes,\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    source = source[: terminal_impl.end] + addition + source[terminal_impl.end :]
    return replace(data, sshd=source)


def add_stdout_terminal_external_writer(data: Inputs) -> Inputs:
    source = data.sshd
    helper = (
        f'\n#[cfg(feature = "{SSHD_FEATURE}")]\n'
        "fn forge_stdout_terminal(pump: &mut ComponentStreamPump) {\n"
        "    pump.stdout_pending = None;\n"
        "    pump.stdout_terminal = Some(StreamCloseReason::Normal);\n"
        "}\n"
    )
    source = replace_once(
        source,
        "\nfn component_stream_error(error: StreamError) -> &'static str {",
        helper + "\nfn component_stream_error(error: StreamError) -> &'static str {",
        "external stdout terminal writer helper",
    )
    source = replace_once(
        source,
        f'    #[cfg(feature = "{SSHD_FEATURE}")]\n'
        "    if let Err(reason) =\n"
        "        seal_managed_component_profile_terminal(",
        f'    #[cfg(feature = "{SSHD_FEATURE}")]\n'
        "    forge_stdout_terminal(&mut pump);\n"
        f'    #[cfg(feature = "{SSHD_FEATURE}")]\n'
        "    if let Err(reason) =\n"
        "        seal_managed_component_profile_terminal(",
        "external stdout terminal writer call",
    )
    return replace(data, sshd=source)


def forge_sync_profile_default(data: Inputs) -> Inputs:
    source = data.runtime
    source = replace_once(
        source,
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]\n"
        "pub struct SyncCallProfile {",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n"
        "pub struct SyncCallProfile {",
        "sync-call profile derived Default",
    )
    profile = find_scope(
        source,
        r"\bpub\s+struct\s+SyncCallProfile\b",
        "forged sync-call profile",
    )
    default_impl = (
        "\n\n#[cfg(feature = \"c84-profile-hooks\")]\n"
        "impl Default for SyncCallProfile {\n"
        "    fn default() -> Self {\n"
        "        Self { typed_polls: 100, core_polls: 0, outer_poll_ticks: 0, "
        "core_interpreter_ticks: 0, consumed_work: 0 }\n"
        "    }\n"
        "}"
    )
    source = source[: profile.end] + default_impl + source[profile.end :]
    return replace(data, runtime=source)


def add_trusted_stream_method(data: Inputs) -> Inputs:
    source = data.slot
    scope = find_scope(
        source,
        r"\bimpl\s+StreamLease\b(?=\s*\{\s*fn\s+seal_trusted\b)",
        "trusted stream authority widening",
    )
    require(scope.raw.endswith("}"), "trusted StreamLease impl does not end in brace")
    addition = (
        "\n    pub(crate) fn summary(&self) -> Result<Summary, ProfileError> {\n"
        "        stream_summary(self.token, self.detach)\n"
        "    }\n"
    )
    mutated = scope.raw[:-1] + addition + "}"
    return replace(data, slot=source[: scope.start] + mutated + source[scope.end :])


def mutate_marker_decoy(data: Inputs) -> Inputs:
    source = data.ssh
    scope = find_scope(source, r"\bfn\s+trusted_sample_response\b", "marker decoy")
    forged = NORMAL_MARKER.replace("exact_success=1", "exact_success=0", 1)
    mutated = replace_once(scope.raw, NORMAL_MARKER, forged, "active trusted marker")
    require(mutated.endswith("}"), "trusted response scope does not end in brace")
    mutated = mutated[:-1] + f'\n    if false {{ crate::println!("{NORMAL_MARKER}"); }}\n' + "}"
    return replace(data, ssh=source[: scope.start] + mutated + source[scope.end :])


def mutate_predecessor_print_argument(data: Inputs) -> Inputs:
    source = data.ssh
    scope = find_scope(source, r"\bfn\s+profile_request_response\b", "request print argument")
    units = IRQ.direct_feature_units(scope.raw, QEMU_FEATURE)
    matching = [unit for unit in units if REQUEST_MARKER in comment_masked(unit)]
    require(len(matching) == 1, "request print mutation unit count differs")
    unit = matching[0]
    mutated_unit = replace_once(
        unit,
        "        status,\n        ready_epoch\n",
        "        status + 1,\n        ready_epoch\n",
        "request trusted status argument",
    )
    mutated_scope = replace_once(
        scope.raw,
        unit,
        mutated_unit,
        "request trusted print unit",
    )
    return replace(
        data,
        ssh=source[: scope.start] + mutated_scope + source[scope.end :],
    )


def expect_rejected(inputs: Inputs, mutation: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutation(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify_trusted(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def run_selftest(inputs: Inputs, *, predecessors: bool = True) -> int:
    verify(inputs, predecessors=predecessors)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "base-inherits-verified-stream",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{FEATURE} = [\n    "{FINISH_FEATURE}",\n    "vibeos-sshd/{SSHD_FEATURE}",\n]',
                f'{FEATURE} = [\n    "{VERIFIED_FEATURE}",\n    "vibeos-sshd/{SSHD_FEATURE}",\n]',
                "trusted base predecessor",
            ),
        ),
        (
            "qemu-pairing-removed",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{QEMU_FEATURE} = [\n    "{FEATURE}",\n    "{FINISH_QEMU_FEATURE}",\n]',
                f'{QEMU_FEATURE} = [\n    "{FEATURE}",\n]',
                "trusted QEMU predecessor",
            ),
        ),
        (
            "collector-qemu-root-exemption-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    not(feature = "{QEMU_FEATURE}"),\n'
                f'    not(feature = "{COLLECTOR_QEMU_FEATURE}")\n',
                f'    not(feature = "{QEMU_FEATURE}")\n',
                "collector QEMU trusted-pairing exemption",
            ),
        ),
        (
            "collector-qemu-root-exemption-broadened",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    not(feature = "{QEMU_FEATURE}"),\n'
                f'    not(feature = "{COLLECTOR_QEMU_FEATURE}")\n',
                f'    not(feature = "{QEMU_FEATURE}"),\n'
                '    not(feature = "wasm-c84-ssh-managed-child-single-boot-collector")\n',
                "collector QEMU trusted-pairing exemption scope",
            ),
        ),
        (
            "sshd-seal-public",
            lambda data: mutate_function(data, "sshd", "seal", "fn seal(", "pub fn seal(", "public terminal seal"),
        ),
        (
            "sshd-seal-terminal-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "seal",
                "            component_terminal,\n",
                "            component_terminal: vibeos_vsh::ComponentTerminal::Success,\n",
                "sealed component terminal mapping",
            ),
        ),
        (
            "sshd-component-terminal-getter-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "component_terminal",
                "        self.component_terminal\n",
                "        vibeos_vsh::ComponentTerminal::Success\n",
                "component terminal getter",
            ),
        ),
        (
            "sshd-exit-status-getter-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "exit_status",
                "        self.exit_status\n",
                "        0\n",
                "terminal exit-status getter",
            ),
        ),
        (
            "sshd-timeout-getter-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "timed_out",
                "        self.timed_out\n",
                "        false\n",
                "terminal timeout getter",
            ),
        ),
        (
            "sshd-stdout-getter-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "stdout_bytes",
                "        self.stdout_bytes\n",
                "        12_325\n",
                "terminal stdout getter",
            ),
        ),
        (
            "sshd-report-terminal-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "managed_component_terminal",
                "then_some(*terminal)",
                "then_some(vibeos_vsh::ComponentTerminal::Success)",
                "managed report terminal mapping",
            ),
        ),
        (
            "sshd-run-terminal-store-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "seal_terminal",
                "        self.terminal = Some(terminal);\n",
                "        self.terminal = Some(SshExecProfileTerminal::seal(\n"
                "            vibeos_vsh::ComponentTerminal::Success, 0, false, 12_325,\n"
                "        ));\n",
                "run terminal storage",
            ),
        ),
        (
            "sshd-terminal-producer-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "seal_managed_component_profile_terminal",
                "        terminal,\n        exit_status,\n",
                "        vibeos_vsh::ComponentTerminal::Success,\n        0,\n",
                "managed terminal seal arguments",
            ),
        ),
        (
            "sshd-completed-reports-remapped",
            lambda data: mutate_function(
                data,
                "sshd",
                "execute_managed_component_with_network",
                "                completed = Some(reports);\n            }\n        } else {\n",
                "                completed = Some(remap_reports(reports));\n            }\n        } else {\n",
                "managed completion report storage",
            ),
        ),
        (
            "sshd-terminal-post-seal-writer",
            lambda data: mutate_method(
                data,
                "sshd",
                r"\bimpl\s+SshExecProfileRun\b",
                "phase_host",
                "pub fn phase_host(&mut self) -> Result<(), ()> {\n",
                "pub fn phase_host(&mut self) -> Result<(), ()> {\n"
                f'        #[cfg(feature = "{SSHD_FEATURE}")]\n'
                "        if let Some(terminal) = self.terminal.as_mut() {\n"
                "            terminal.stdout_bytes = 12_325;\n"
                "        }\n",
                "sealed terminal post-write",
            ),
        ),
        (
            "sshd-terminal-whole-value-writer",
            add_terminal_whole_value_writer,
        ),
        (
            "sshd-terminal-manual-clone",
            add_terminal_manual_clone,
        ),
        (
            "sshd-stdout-terminal-external-writer",
            add_stdout_terminal_external_writer,
        ),
        (
            "trusted-run-finish-exposed",
            lambda data: mutate_text(
                data,
                "slot",
                f'    #[cfg(not(feature = "{FEATURE}"))]\n'
                "    pub(crate) fn finish(mut self) -> Result<StreamLease, ProfileError> {",
                f'    #[cfg(feature = "{FEATURE}")]\n'
                "    pub(crate) fn finish(mut self) -> Result<StreamLease, ProfileError> {",
                "trusted RunLease finish visibility",
            ),
        ),
        (
            "trusted-stream-type-exposed",
            lambda data: mutate_text(
                data,
                "slot",
                f'#[cfg(feature = "{FEATURE}")]\nstruct StreamLease {{',
                f'#[cfg(feature = "{FEATURE}")]\npub(crate) struct StreamLease {{',
                "trusted StreamLease visibility",
            ),
        ),
        (
            "trusted-stream-primitive-exposed",
            lambda data: mutate_text(
                data,
                "slot",
                f'#[cfg(not(feature = "{FEATURE}"))]\nimpl StreamLease {{\n'
                "    pub(crate) const fn token(&self) -> SampleToken {",
                f'#[cfg(feature = "{FEATURE}")]\nimpl StreamLease {{\n'
                "    pub(crate) const fn token(&self) -> SampleToken {",
                "public stream implementation trusted cfg",
            ),
        ),
        ("trusted-stream-wrapper-exposed", add_trusted_stream_method),
        (
            "trusted-uses-public-finish",
            lambda data: mutate_function(
                data,
                "slot",
                "finish_trusted",
                "self.finish_to_stream()?.seal_trusted(terminal)",
                "self.finish()?.seal_trusted(terminal)",
                "trusted private transition",
            ),
        ),
        (
            "discard-predecessor-compiled-trusted",
            lambda data: mutate_text(
                data,
                "ssh",
                "#[cfg(all(\n"
                f'    feature = "{FINISH_FEATURE}",\n'
                f'    not(feature = "{FEATURE}")\n'
                "))]\n"
                "fn finish_verify_discard_and_ack_profile(",
                f'#[cfg(feature = "{FINISH_FEATURE}")]\n'
                "fn finish_verify_discard_and_ack_profile(",
                "trusted predecessor helper exclusion",
            ),
        ),
        (
            "status-only-prerequisite",
            lambda data: mutate_text(
                data,
                "ssh",
                "terminal_seal.component_terminal()\n            == vibeos_vsh::ComponentTerminal::Success",
                "terminal_seal.component_terminal().status() == 0",
                "status-only prerequisite",
            ),
        ),
        (
            "returned-zero-alias",
            lambda data: mutate_function(
                data,
                "slot",
                "seal_trusted",
                "succeeded: terminal_kind == vibeos_vsh::ComponentTerminal::Success,",
                "succeeded: terminal_kind.status() == 0,",
                "Returned(0) alias",
            ),
        ),
        (
            "trusted-exact-stdin-disabled",
            lambda data: mutate_function(
                data,
                "sshd",
                "execute_managed_component_with_network",
                f'#[cfg(feature = "{SSHD_FEATURE}")]\n        let stage_exact_stdin = true;',
                f'#[cfg(feature = "{SSHD_FEATURE}")]\n        let stage_exact_stdin = false;',
                "trusted exact stdin staging",
            ),
        ),
        (
            "trusted-formal-chunk-limit-disabled",
            lambda data: mutate_function(
                data,
                "sshd",
                "execute_managed_component_with_network",
                '            feature = "c84-profile-trusted-sample"\n'
                "        ))]\n"
                "        // The trusted formal call observes exactly 12 full 1 KiB reads and one\n"
                "        // 37-byte EOF tail, independent of any target-only revoke policy which\n"
                "        // happens to be compiled into the same SSHD crate.\n"
                "        let stdin_chunk_limit = MAX_STREAM_CHUNK_BYTES;",
                '            not(feature = "c84-profile-trusted-sample")\n'
                "        ))]\n"
                "        // The trusted formal call observes exactly 12 full 1 KiB reads and one\n"
                "        // 37-byte EOF tail, independent of any target-only revoke policy which\n"
                "        // happens to be compiled into the same SSHD crate.\n"
                "        let stdin_chunk_limit = MAX_STREAM_CHUNK_BYTES;",
                "trusted formal stdin chunk limit",
            ),
        ),
        (
            "trusted-staging-partial-flush",
            lambda data: mutate_function(
                data,
                "sshd",
                "finish_stdin_staging_turn",
                "        if self.stdin_staging_length == maximum || (eof && self.stdin_staging_length != 0) {\n",
                "        if self.stdin_staging_length != 0 {\n",
                "trusted staging full-block/EOF flush",
            ),
        ),
        (
            "trusted-staging-finish-bypassed",
            lambda data: mutate_function(
                data,
                "sshd",
                "pump_component_stdin_turn",
                "        worked |= pump.finish_stdin_staging_turn(maximum, eof)?;\n",
                "        worked |= pump.close_stdin_normal()?;\n",
                "trusted staging helper use",
            ),
        ),
        (
            "trusted-staging-content-assertion-removed",
            lambda data: mutate_function(
                data,
                "sshd",
                "trusted_stdin_staging_coalesces_sunset_1000_plus_24_and_eof_37",
                "        assert_eq!(full_bytes.as_slice(), canonical.as_slice());\n",
                "        assert_eq!(full_bytes.len(), canonical.len());\n",
                "trusted staging content regression",
            ),
        ),
        (
            "trusted-forwarded-stdout-getter-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "forwarded_stdout_bytes",
                "        self.forwarded_stdout_bytes\n",
                "        12_325\n",
                "forwarded stdout getter",
            ),
        ),
        (
            "trusted-forwarded-stdout-accounting-forged",
            lambda data: mutate_function(
                data,
                "sshd",
                "consume_forwarded_stdout",
                "        let next = self\n"
                "            .forwarded_stdout_bytes\n"
                "            .checked_add(forwarded_length)\n"
                "            .ok_or(\"SSH Component stdout byte accounting overflowed\")?;\n",
                "        let next = 12_325;\n",
                "forwarded stdout accounting",
            ),
        ),
        (
            "trusted-stdout-turn-skips-live-accounting",
            lambda data: mutate_function(
                data,
                "sshd",
                "pump_component_stdout_turn",
                f'                #[cfg(feature = "{SSHD_FEATURE}")]\n'
                "                pump.consume_forwarded_stdout(written)?;\n",
                f'                #[cfg(feature = "{SSHD_FEATURE}")]\n'
                "                pump.consume_stdout(written)?;\n",
                "trusted stdout accepted-byte accounting",
            ),
        ),
        (
            "read-observation-removed",
            lambda data: mutate_function(
                data,
                "component",
                "commit_prepared",
                "self.observe_formal_read(&bytes)?;",
                "let _ = bytes;",
                "committed read observation",
            ),
        ),
        (
            "formal-read-byte-condition-decoy",
            lambda data: mutate_function(
                data,
                "component",
                "observe_read",
                "            if *byte != Self::input_byte(offset) {\n",
                "            if false && *byte != Self::input_byte(offset) {\n",
                "formal read byte guard",
            ),
        ),
        ("formal-io-external-writer", add_formal_io_external_writer),
        (
            "formal-observation-mapping-forged",
            lambda data: mutate_method(
                data,
                "component",
                r"\bimpl\s+FormalIoCounters\b",
                "finish",
                "            read_chunks: self.read_chunks,\n",
                "            read_chunks: FORMAL_READ_CHUNKS,\n",
                "formal IO final mapping",
            ),
        ),
        (
            "formal-take-remapped",
            lambda data: mutate_function(
                data,
                "component",
                "take_formal_io",
                "            .finish()\n",
                "            .finish()\n"
                "            .map(|_| FormalIoObservation {\n"
                "                read_chunks: FORMAL_READ_CHUNKS,\n"
                "                write_chunks: FORMAL_WRITE_CHUNKS,\n"
                "                stdin_bytes: FORMAL_STDOUT_BYTES,\n"
                "                stdout_bytes: FORMAL_STDOUT_BYTES,\n"
                "            })\n",
                "formal IO take mapping",
            ),
        ),
        (
            "write-counts-waiting",
            lambda data: mutate_function(data, "component", "start_write", "if sent {", "if true {", "final Sent write"),
        ),
        (
            "saturating-read-count",
            lambda data: mutate_function(
                data,
                "component",
                "observe_read",
                "self.read_chunks.checked_add(1)",
                "Some(self.read_chunks.saturating_add(1))",
                "checked read count",
            ),
        ),
        (
            "wrong-formal-read-count",
            lambda data: mutate_function(
                data,
                "slot",
                "from_live",
                "committed_read_chunks != FORMAL_READ_CHUNKS",
                "committed_read_chunks + 1 != FORMAL_READ_CHUNKS",
                "formal read scalar",
            ),
        ),
        (
            "terminal-read-shape-condition-decoy",
            lambda data: mutate_function(
                data,
                "slot",
                "from_live",
                "        if committed_read_chunks != FORMAL_READ_CHUNKS\n",
                "        if false && committed_read_chunks != FORMAL_READ_CHUNKS\n",
                "terminal read-shape guard",
            ),
        ),
        (
            "metrics-forged-after-call",
            lambda data: mutate_text(
                data,
                "component",
                "terminal_call_metrics = call.metrics();",
                "terminal_call_metrics = unsafe { core::mem::zeroed() };",
                "live call metrics",
            ),
        ),
        (
            "runtime-call-metrics-forged",
            lambda data: mutate_function(
                data,
                "runtime",
                "metrics",
                "            consumed_work: self.total_work - self.remaining_work,\n",
                "            consumed_work: 188_123,\n",
                "typed call live metric getter",
            ),
        ),
        ("runtime-sync-profile-default-forged", forge_sync_profile_default),
        (
            "runtime-typed-poll-count-forged",
            lambda data: mutate_function(
                data,
                "runtime",
                "poll_profiled",
                "        session.profile.typed_polls = session.profile.typed_polls.saturating_add(1);\n",
                "        session.profile.typed_polls = 1_252;\n",
                "profiled typed poll count",
            ),
        ),
        (
            "runtime-core-poll-count-forged",
            lambda data: mutate_method(
                data,
                "runtime",
                r"\bimpl<C:\s*ProfileClock\s*\+\s*\?Sized>\s+SyncPollProfiler\s+for\s+ProfileSession",
                "end_core_poll",
                "        self.profile.core_polls = self.profile.core_polls.saturating_add(1);\n",
                "        self.profile.core_polls = 1_165;\n",
                "profiled Core poll count",
            ),
        ),
        (
            "driver-terminal-metrics-shadowed",
            lambda data: mutate_function(
                data,
                "component",
                "run_image_component",
                "    drop(call);\n",
                "    drop(call);\n"
                "    let terminal_call_metrics = vibeos_component_runtime::sync::TypedCallMetrics {\n"
                "        consumed_work: 188_123,\n"
                "        remaining_work: 311_877,\n"
                "    };\n",
                "driver terminal metric shadow",
            ),
        ),
        (
            "driver-core-profile-shadowed",
            lambda data: mutate_function(
                data,
                "component",
                "run_image_component",
                "    drop(call);\n",
                "    drop(call);\n"
                "    let core_profile = SyncCallProfile {\n"
                "        typed_polls: 1_252,\n"
                "        core_polls: 1_165,\n"
                "        outer_poll_ticks: 2,\n"
                "        core_interpreter_ticks: 1,\n"
                "        consumed_work: 188_121,\n"
                "    };\n",
                "driver sync-call profile shadow",
            ),
        ),
        ("driver-core-profile-external-writer", add_profile_external_writer),
        (
            "driver-formal-io-shadowed",
            lambda data: mutate_function(
                data,
                "component",
                "run_image_component",
                "            if crate::wasm_aot_profile_slot::mark_managed_child_driver_completed(\n",
                "            let io = FormalIoObservation {\n"
                "                read_chunks: 13,\n"
                "                write_chunks: 13,\n"
                "                stdin_bytes: 12_325,\n"
                "                stdout_bytes: 12_325,\n"
                "            };\n"
                "            if crate::wasm_aot_profile_slot::mark_managed_child_driver_completed(\n",
                "driver formal IO shadow",
            ),
        ),
        (
            "profile-delta-removed",
            lambda data: mutate_function(
                data,
                "slot",
                "from_live",
                ".checked_add(FORMAL_TYPED_CALL_PLANNING_WORK)",
                ".checked_add(0)",
                "profile/call delta",
            ),
        ),
        (
            "profile-sentinel-removed",
            lambda data: mutate_function(
                data,
                "slot",
                "from_live",
                "            || profile.core_polls == u64::MAX\n",
                "",
                "Core poll sentinel",
            ),
        ),
        (
            "hardcoded-poll-exact",
            lambda data: mutate_function(
                data,
                "slot",
                "seal_trusted",
                "let poll_exact = metrics.poll_exact;",
                "let poll_exact = true;",
                "poll exact provenance",
            ),
        ),
        (
            "hardcoded-logical-closure",
            lambda data: mutate_function(
                data,
                "slot",
                "seal_trusted",
                "let logical_live_after = metrics.logical_live_after;",
                "let logical_live_after = 0;",
                "logical closure provenance",
            ),
        ),
        (
            "validated-metric-fuel-mapping-forged",
            lambda data: mutate_function(
                data,
                "slot",
                "from_live",
                "            fuel_consumed: call.consumed_work,\n",
                "            fuel_consumed: 1,\n",
                "validated terminal fuel mapping",
            ),
        ),
        (
            "driver-metric-input-replaced",
            lambda data: mutate_text(
                data,
                "slot",
                "        committed_read_chunks,\n        committed_write_chunks,\n",
                "        FORMAL_READ_CHUNKS,\n        committed_write_chunks,\n",
                "driver terminal metric input",
            ),
        ),
        (
            "driver-completion-duplicate-guard-decoy",
            lambda data: mutate_scope(
                data,
                "slot",
                r"\bpub\(crate\)\s+fn\s+mark_managed_child_driver_completed\s*\(\s*epoch:\s*u64,",
                "        || managed_terminal.is_some()\n",
                "        || false && managed_terminal.is_some()\n",
                "managed terminal duplicate guard",
            ),
        ),
        (
            "detach-clean-and-reason-forged",
            lambda data: mutate_function(
                mutate_function(
                    data,
                    "slot",
                    "profile_child_detached",
                    "    let mut clean =\n"
                    "        state == DelegatedChildState::CompletedPendingDetach "
                    "&& reason == TaskDetachReason::Exited;\n",
                    "    let mut clean = true\n"
                    "        || (state == DelegatedChildState::CompletedPendingDetach\n"
                    "            && reason == TaskDetachReason::Exited);\n",
                    "trusted detach clean guard",
                ),
                "slot",
                "profile_child_detached",
                "    *child_detach = Some(reason);\n",
                f'    #[cfg(feature = "{FEATURE}")]\n'
                "    {\n"
                "        *child_detach = Some(TaskDetachReason::Exited);\n"
                "    }\n"
                f'    #[cfg(not(feature = "{FEATURE}"))]\n'
                "    {\n"
                "        *child_detach = Some(reason);\n"
                "    }\n",
                "trusted detach reason writer",
            ),
        ),
        (
            "eligibility-fuel-mapping-forged",
            lambda data: mutate_function(
                data,
                "slot",
                "seal_trusted",
                "            write_chunks: metrics.write_chunks,\n"
                "            fuel_consumed: metrics.fuel_consumed,\n",
                "            write_chunks: metrics.write_chunks,\n"
                "            fuel_consumed: 1,\n",
                "eligible terminal fuel mapping",
            ),
        ),
        (
            "acceptance-fuel-mapping-forged",
            lambda data: mutate_function(
                data,
                "slot",
                "seal_trusted",
                "                stdout_digest: FORMAL_STDOUT_SHA256,\n"
                "                fuel_consumed: metrics.fuel_consumed,\n",
                "                stdout_digest: FORMAL_STDOUT_SHA256,\n"
                "                fuel_consumed: 1,\n",
                "acceptance fuel mapping",
            ),
        ),
        (
            "acceptance-accessor-forged",
            lambda data: mutate_function(
                data,
                "slot",
                "acceptance_observation",
                "        self.acceptance\n",
                "        TrustedSampleAcceptanceObservation { fuel_consumed: 1, ..self.acceptance }\n",
                "acceptance accessor",
            ),
        ),
        (
            "helper-acceptance-shadowed",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "    let acceptance = bundle.acceptance_observation();\n",
                "    let acceptance = bundle.acceptance_observation();\n"
                "    let mut acceptance = acceptance;\n"
                "    acceptance.fuel_consumed = 1;\n",
                "trusted helper acceptance shadow",
            ),
        ),
        (
            "response-observation-mutated",
            lambda data: mutate_function(
                data,
                "ssh",
                "trusted_sample_response",
                "    let observation = evidence.acceptance;\n",
                "    let mut observation = evidence.acceptance;\n"
                "    observation.fuel_consumed = 1;\n",
                "trusted response observation binding",
            ),
        ),
        (
            "boundary-evidence-remapped",
            lambda data: mutate_method(
                data,
                "ssh",
                r"\bimpl\s+SshExecProfileOwner\b",
                "response_boundary",
                "        let terminal = finish_verify_trusted_discard_and_ack_profile(run, terminal_seal)\n"
                "            .map(|evidence| (evidence.ready_epoch, evidence));\n",
                "        let terminal = finish_verify_trusted_discard_and_ack_profile(run, terminal_seal)\n"
                "            .map(|evidence| (evidence.ready_epoch, forged_evidence(evidence)));\n",
                "trusted response evidence mapping",
            ),
        ),
        (
            "trusted-terminal-copy-forged",
            lambda data: mutate_function(
                data,
                "slot",
                "trusted_terminal_metrics",
                "            Ok(*managed_terminal)\n",
                "            let mut metrics = *managed_terminal;\n"
                "            metrics.fuel_consumed = 1;\n"
                "            Ok(metrics)\n",
                "trusted terminal metric copy",
            ),
        ),
        (
            "detached-terminal-fuel-mutated",
            lambda data: mutate_function(
                data,
                "slot",
                "profile_child_detached",
                "            terminal.logical_live_after = 0;\n",
                "            terminal.logical_live_after = 0;\n"
                "            terminal.fuel_consumed = 1;\n",
                "trusted detach terminal mutation",
            ),
        ),
        (
            "finish-terminal-propagation-forged",
            lambda data: mutate_function(
                data,
                "slot",
                "finish_active",
                '                    managed_terminal.expect("trusted terminal completeness was checked above"),\n',
                "                    unsafe { core::mem::zeroed() },\n",
                "trusted finish terminal propagation",
            ),
        ),
        (
            "verified-terminal-install-forged",
            lambda data: mutate_scope(
                data,
                "slot",
                r"\bfn\s+install_verified\s*\([^)]*managed_terminal",
                "            managed_terminal,\n",
                "            managed_terminal: unsafe { core::mem::zeroed() },\n",
                "trusted verified terminal installation",
            ),
        ),
        (
            "active-terminal-storage-prefilled",
            lambda data: mutate_function(
                data,
                "slot",
                "start_reserved",
                "                managed_terminal: None,\n",
                "                managed_terminal: Some(unsafe { core::mem::zeroed() }),\n",
                "trusted active terminal initialization",
            ),
        ),
        (
            "target-authority-exposed",
            lambda data: mutate_text(
                data,
                "slot",
                "    sample: Option<TargetVerified<'static>>,",
                "    pub(crate) sample: Option<TargetVerified<'static>>,",
                "bundle target field",
            ),
        ),
        ("bundle-into-parts", add_bundle_into_parts),
        ("bundle-evidence-accessor", add_bundle_evidence_accessor),
        (
            "bundle-send-widening",
            lambda data: mutate_text(
                data,
                "slot",
                "    not_send_sync: PhantomData<*mut ()>,",
                "    not_send_sync: PhantomData<()>,",
                "bundle Send/Sync marker",
            ),
        ),
        (
            "eligible-validation-removed",
            lambda data: mutate_function(
                data,
                "slot",
                "seal_trusted",
                "EligibleTerminalEvidence::validate(observation)",
                "forged_eligible(observation)",
                "eligible validation",
            ),
        ),
        (
            "bundle-discard-removed",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "let report = bundle.discard().map_err(|_| ())?;",
                "let report = forged_report(bundle);",
                "trusted bundle discard",
            ),
        ),
        (
            "trusted-cause-removed",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "report.cause == RejectionCause::TrustedSampleAbandoned",
                "true",
                "trusted rejection cause",
            ),
        ),
        (
            "trusted-report-condition-decoy",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "    let report_is_exact = report.epoch == epoch\n",
                "    let report_is_exact = true || report.epoch == epoch\n",
                "trusted rejection report guard",
            ),
        ),
        (
            "stored-report-removed",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "let stored_rejection_is_exact = rejection() == Some(report)",
                "let stored_rejection_is_exact = true",
                "stored rejection",
            ),
        ),
        (
            "ack-removed",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "let ready_epoch = acknowledge_finish_verify_rejection(epoch, report)?;",
                "let ready_epoch = epoch + 1;",
                "trusted acknowledgement",
            ),
        ),
        (
            "error-recycle-removed",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "let _ = acknowledge_finish_verify_rejection(epoch, report)?;",
                "let _ = report;",
                "finish rejection recycle",
            ),
        ),
        (
            "truthful-poll-max-removed",
            lambda data: mutate_function(
                data,
                "ssh",
                "trusted_sample_response",
                "        && observation.poll_quanta != u64::MAX\n",
                "",
                "truthful poll sentinel",
            ),
        ),
        (
            "trusted-response-condition-decoy",
            lambda data: mutate_function(
                data,
                "ssh",
                "trusted_sample_response",
                "    let exact = observation.epoch == epoch\n",
                "    let exact = true || observation.epoch == epoch\n",
                "trusted response observation guard",
            ),
        ),
        (
            "trusted-response-poll-print-forged",
            lambda data: mutate_function(
                data,
                "ssh",
                "trusted_sample_response",
                "        observation.poll_quanta,\n        evidence.ready_epoch\n",
                "        observation.poll_quanta + 1,\n        evidence.ready_epoch\n",
                "trusted response poll print",
            ),
        ),
        (
            "trusted-drop-ready-print-derived",
            lambda data: mutate_function(
                data,
                "ssh",
                "trusted_sample_drop",
                "        epoch,\n        ready_epoch\n",
                "        epoch,\n        epoch + 1\n",
                "trusted Drop Ready print",
            ),
        ),
        ("trusted-predecessor-print-argument-forged", mutate_predecessor_print_argument),
        ("response-marker-dead-code-decoy", mutate_marker_decoy),
        (
            "predecessor-suffix-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                REQUEST_MARKER,
                REQUEST_MARKER.replace("bundle=trusted", "bundle=copied", 1),
                "first predecessor trusted suffix",
            ),
        ),
        (
            "publisher-added",
            lambda data: mutate_function(
                data,
                "ssh",
                "finish_verify_trusted_discard_and_ack_profile",
                "let acceptance = bundle.acceptance_observation();",
                "let acceptance = bundle.acceptance_observation(); ProfilePublisher::publish_profile(bundle);",
                "publisher isolation",
            ),
        ),
        (
            "ci-step-disabled",
            lambda data: mutate_text(
                data,
                "ci",
                "      - name: Exercise the C8.4 SSH managed-child trusted-sample closure\n        run:",
                "      - name: Exercise the C8.4 SSH managed-child trusted-sample closure\n        if: ${{ false }}\n        run:",
                "CI trusted step",
            ),
        ),
        (
            "ci-qemu-job-disabled",
            lambda data: mutate_text(
                data,
                "ci",
                "  qemu-tests:\n    name: QEMU integration\n    needs: differential\n",
                "  qemu-tests:\n    name: QEMU integration\n    needs: differential\n"
                "    if: ${{ false }}\n",
                "CI trusted QEMU job",
            ),
        ),
        (
            "ci-qemu-job-tail-disabled",
            lambda data: mutate_text(
                data,
                "ci",
                "      - name: Four-hart throughput scaling\n"
                "        run: python3 -B scripts/bench.py --no-build --smp-scaling\n",
                "      - name: Four-hart throughput scaling\n"
                "        run: python3 -B scripts/bench.py --no-build --smp-scaling\n"
                "    if: ${{ false }}\n",
                "CI trusted QEMU trailing job condition",
            ),
        ),
        (
            "ci-pull-request-trigger-removed",
            lambda data: mutate_text(
                data,
                "ci",
                "on:\n  push:\n  pull_request:\n",
                "on:\n  push:\n",
                "CI pull-request trigger",
            ),
        ),
        (
            "ci-qemu-command-ignored",
            lambda data: mutate_text(
                data,
                "ci",
                f"        run: {QEMU_COMMAND}\n",
                f"        run: {QEMU_COMMAND} || true\n",
                "CI trusted QEMU failure bypass",
            ),
        ),
        (
            "ci-sshd-test-disabled",
            lambda data: mutate_text(
                data,
                "ci",
                "      - name: Test the C8.4 trusted SSH terminal seam\n        run: |",
                "      - name: Test the C8.4 trusted SSH terminal seam\n        if: ${{ false }}\n        run: |",
                "CI trusted SSHD test step",
            ),
        ),
        (
            "ci-sshd-test-continue-on-error",
            lambda data: mutate_text(
                data,
                "ci",
                "      - name: Test the C8.4 trusted SSH terminal seam\n        run: |",
                "      - name: Test the C8.4 trusted SSH terminal seam\n"
                "        continue-on-error: true\n        run: |",
                "CI trusted SSHD failure bypass",
            ),
        ),
        (
            "ci-source-verifier-ignored",
            lambda data: mutate_text(
                data,
                "ci",
                f"        run: {COMMAND}\n",
                f"        run: {COMMAND} || true\n",
                "CI trusted source verifier failure bypass",
            ),
        ),
        (
            "ci-peer-selftest-disabled",
            lambda data: mutate_text(
                data,
                "ci",
                "      - name: Test the C8.4 trusted transcript parser\n        run:",
                "      - name: Test the C8.4 trusted transcript parser\n"
                "        if: ${{ false }}\n        run:",
                "CI trusted peer selftest",
            ),
        ),
        (
            "qemu-script-early-success",
            lambda data: mutate_manifest(
                data,
                "qemu_script",
                "set -eu\n",
                "set -eu\nexit 0\n",
                "trusted QEMU early success",
            ),
        ),
        (
            "qemu-script-source-verifier-removed",
            lambda data: mutate_manifest(
                data,
                "qemu_script",
                "python3 -B scripts/verify-c84-ssh-managed-child-trusted-sample.py "
                "--selftest --check-source >&2 \\\n",
                "true \\\n",
                "trusted QEMU source verifier",
            ),
        ),
        (
            "qemu-script-live-peer-removed",
            lambda data: mutate_manifest(
                data,
                "qemu_script",
                "if ! python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py \\\n",
                "if ! true \\\n",
                "trusted QEMU live peer",
            ),
        ),
        (
            "qemu-script-frozen-peer-removed",
            lambda data: mutate_manifest(
                data,
                "qemu_script",
                "python3 -B scripts/c84-ssh-managed-child-trusted-sample-peer.py \\\n"
                "  --verify-log-only",
                "true \\\n  --verify-log-only",
                "trusted QEMU frozen peer",
            ),
        ),
        (
            "peer-selftest-weakened",
            lambda data: mutate_manifest(
                data,
                "peer_script",
                "            require(not accepted(mutated), "
                'f"parser selftest mutation was accepted: {label}")',
                "            require(True, "
                'f"parser selftest mutation was accepted: {label}")',
                "trusted peer selftest guard",
            ),
        ),
        (
            "transitive-peer-selftest-weakened",
            lambda data: mutate_peer_dependency(
                data,
                0,
                "            require(not accepted(mutated), "
                'f"parser selftest mutation was accepted: {label}")',
                "            require(True, "
                'f"parser selftest mutation was accepted: {label}")',
                "finish peer selftest guard",
            ),
        ),
        (
            "testing-predecessor-byte-overclaim",
            lambda data: mutate_text(
                data,
                "testing",
                "The trusted image preserves every predecessor marker format and field contract,",
                "The trusted image leaves every predecessor nonterminal and epoch-3 DROP byte unchanged,",
                "TESTING predecessor byte identity claim",
            ),
        ),
        (
            "decision-poll-values-frozen",
            lambda data: mutate_text(
                data,
                "decision_doc",
                "it does not freeze scheduler-dependent\nvalues.",
                "it freezes scheduler-dependent\nvalues.",
                "decision live poll claim",
            ),
        ),
        (
            "roadmap-reset-to-planned",
            lambda data: mutate_text(
                data,
                "roadmap",
                "**Status (2026-08-27): implementation in progress.**",
                "**Status (2026-08-27): planned.**",
                "WASM roadmap implementation status",
            ),
        ),
    ]
    for label, mutation in mutations:
        expect_rejected(inputs, mutation, label)
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-source", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    if not arguments.check_source and not arguments.selftest:
        parser.error("select --check-source and/or --selftest")
    try:
        inputs = load_inputs()
        mutations = run_selftest(inputs) if arguments.selftest else 0
        if arguments.check_source and not arguments.selftest:
            verify(inputs)
        suffix = f" mutations={mutations}" if arguments.selftest else ""
        print(
            "PASS verify-c84-ssh-managed-child-trusted-sample: exact live terminal, "
            "committed IO, checked metrics, opaque TargetVerified/evidence bundle, explicit "
            f"trusted discard/ack/Ready, truthful telemetry, and publisher isolation are closed{suffix}"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        VerificationError,
    ) as error:
        print(f"FAIL verify-c84-ssh-managed-child-trusted-sample: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
