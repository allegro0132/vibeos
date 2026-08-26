#!/usr/bin/env python3
"""Verify the C8.4 SSH managed-child verified-stream terminal successor."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import importlib.util
from pathlib import Path
import re
import sys
import tomllib
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
FINISH_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-finish-verify.py"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"

FEATURE = "wasm-c84-ssh-managed-child-verified-stream"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
FINISH_FEATURE = "wasm-c84-ssh-managed-child-finish-verify"
FINISH_QEMU_FEATURE = f"{FINISH_FEATURE}-qemu-acceptance"
TRUSTED_SAMPLE_FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
TRUSTED_SAMPLE_QEMU_FEATURE = f"{TRUSTED_SAMPLE_FEATURE}-qemu-acceptance"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_VERIFIED_STREAM"
FINISH_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY"
IRQ_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"

SUCCESSOR_SUFFIX = "finish=1 verify=1 stream=complete ack=0 ready_epoch={}"
NORMAL_MARKER = (
    f"{FAMILY} RESPONSE epoch={{}} status=0 finish=1 verify=1 summary=1 "
    "initial_cursor=0 total_ticks={} interval_capacity=65536 interval_count={} "
    "intervals_complete=1 emitted={} cursor={} sequence=exact contiguous=1 "
    "nonempty=1 adjacent_distinct=1 phase_sum=total_ticks phase_rescan=summary "
    "final_end=total_ticks stream=complete stored=0 ack=0 ready_epoch={}"
)
DROP_MARKER = (
    f"{FAMILY} DROP epoch={{}} cancel=lease_cancelled finish=0 verify=0 summary=0 "
    "stream=0 emitted=0 stored=1 ack=1 ready_epoch={}"
)
REQUEST_SUCCESS_MARKER = (
    f"{REQUEST_FAMILY} RESPONSE epoch={{}} status={{}} {SUCCESSOR_SUFFIX}"
)
IRQ_SUCCESS_MARKER = (
    f"{IRQ_FAMILY} RESPONSE epoch={{}} status={{}} parent_pair={{}} child_pair={{}} "
    "terminal_inactive=1 paired={} inactive={} active_epoch={} "
    + SUCCESSOR_SUFFIX
)
PHASE_SUCCESS_MARKER = (
    f"{PHASE_FAMILY} RESPONSE epoch={{}} status={{}} child_core_starts={{}} "
    "child_core_finishes={} child_host_starts={} child_host_finishes={} "
    "child_wait_starts={} child_wait_finishes={} cleanup_count={} "
    "parent_host_starts={} parent_host_finishes={} parent_wait_starts={} "
    "parent_wait_finishes={} child_wait_open=0 parent_wait_open=0 late=0 clean=1 "
    + SUCCESSOR_SUFFIX
)
CORE_SUCCESS_MARKER = (
    f"{CORE_FAMILY} RESPONSE epoch={{}} status={{}} claim=1 release=1 detach=exited "
    "clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 "
    + SUCCESSOR_SUFFIX
)
FINISH_SUCCESS_MARKER = (
    f"{FINISH_FAMILY} RESPONSE epoch={{}} status={{}} {SUCCESSOR_SUFFIX}"
)
REQUEST_SUCCESS_ARGUMENTS = "epoch,status,ready_epoch"
IRQ_SUCCESS_ARGUMENTS = (
    "epoch,status,causal_pair,causal_pair,observation.paired,observation.inactive,"
    "observation.active_epoch,ready_epoch,"
)
PHASE_SUCCESS_ARGUMENTS = (
    "epoch,status,child.core_pairs,child.core_pairs,phase.child_host_starts,"
    "phase.child_host_finishes,phase.child_wait_starts,phase.child_wait_finishes,"
    "phase.cleanup_count,phase.parent_host_starts,phase.parent_host_finishes,"
    "phase.parent_wait_starts,phase.parent_wait_finishes,ready_epoch"
)
CORE_SUCCESS_ARGUMENTS = (
    "epoch,status,observation.core_polls,observation.core_pairs,"
    "observation.typed_polls,ready_epoch"
)
FINISH_SUCCESS_ARGUMENTS = "epoch,status,ready_epoch"


def load_finish_verifier():
    spec = importlib.util.spec_from_file_location(
        "vibeos_c84_verified_stream_finish_verifier", FINISH_VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the finish/verify predecessor verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FINISH = load_finish_verifier()
IRQ = FINISH.IRQ
PHASE = FINISH.PHASE
CORE = FINISH.CORE


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def semantic(value: str) -> str:
    return CORE.semantic(value)


def masked(value: str) -> str:
    return CORE.rust_mask(value)


def comment_masked(value: str) -> str:
    return CORE.rust_mask(value, literals=False)


def find_scope(source: str, header: str, label: str):
    try:
        return CORE.find_scope(source, header, label)
    except CORE.VerificationError as error:
        raise VerificationError(str(error)) from error


def find_function(scope, name: str, label: str):
    try:
        return CORE.find_function(scope, name, label)
    except CORE.VerificationError as error:
        raise VerificationError(str(error)) from error


def cfg_guarded(source: str, offset: int, label: str, feature: str) -> None:
    try:
        CORE.cfg_guarded(source, offset, label, feature=feature)
    except CORE.VerificationError as error:
        raise VerificationError(str(error)) from error


def ordered(value: str, needles: tuple[str, ...], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), value)]
        require(len(matches) == 1, f"{label}: {needle!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


def direct_print_unit(scope, marker: str, arguments: str, label: str) -> str:
    units = IRQ.direct_feature_units(scope.raw, QEMU_FEATURE)
    print_units = [unit for unit in units if "println!(" in semantic(unit)]
    matching = [unit for unit in units if marker in comment_masked(unit)]
    require(len(matching) == 1, f"{label} direct marker unit count differs: {len(matching)}")
    unit = matching[0]
    require(
        len(print_units) == 1 and print_units[0] == unit,
        f"{label} verified-stream cfg has another println branch",
    )
    code = semantic(unit)
    direct_prefix = semantic(
        f'#[cfg(feature = "{QEMU_FEATURE}")]\ncrate::println!("{marker}",'
    )
    require(
        code.startswith(direct_prefix)
        and code.endswith(");")
        and code.count("crate::println!(") == 1,
        f"{label} marker is not the sole direct println in its verified-stream cfg unit",
    )
    expected = semantic(
        f'#[cfg(feature = "{QEMU_FEATURE}")]\n'
        f'crate::println!("{marker}",{arguments});'
    )
    require(
        code == expected,
        f"{label} println literal or argument sequence differs",
    )
    return unit


@dataclass(frozen=True)
class Inputs:
    predecessor: FINISH.Inputs
    slot: str
    ssh: str
    kernel_root: str
    kernel_manifest: bytes
    qemu_manifest: bytes
    milkv_manifest: bytes


def load_inputs() -> Inputs:
    return Inputs(
        predecessor=FINISH.load_inputs(),
        slot=SLOT_SOURCE.read_text(encoding="utf-8"),
        ssh=SSH_SOURCE.read_text(encoding="utf-8"),
        kernel_root=KERNEL_ROOT_SOURCE.read_text(encoding="utf-8"),
        kernel_manifest=KERNEL_MANIFEST.read_bytes(),
        qemu_manifest=QEMU_MANIFEST.read_bytes(),
        milkv_manifest=MILKV_MANIFEST.read_bytes(),
    )


def verify_features(inputs: Inputs) -> None:
    kernel = PHASE.parse_features(inputs.kernel_manifest, "kernel")
    qemu = PHASE.parse_features(inputs.qemu_manifest, "QEMU firmware")
    milkv = PHASE.parse_features(inputs.milkv_manifest, "Milk-V firmware")
    require(
        kernel.get(FEATURE) == [FINISH_FEATURE],
        "verified-stream base is not the exact finish/verify successor",
    )
    require(
        kernel.get(QEMU_FEATURE) == [FEATURE, FINISH_QEMU_FEATURE],
        "kernel verified-stream QEMU feature closure differs",
    )
    require(
        qemu.get(QEMU_FEATURE)
        == [FINISH_QEMU_FEATURE, f"vibeos-kernel/{QEMU_FEATURE}"],
        "QEMU firmware does not compose the exact finish predecessor and stream successor",
    )
    require(
        milkv.get(FEATURE) == [f"vibeos-kernel/{FEATURE}"],
        "Milk-V does not expose only the silent verified-stream base seam",
    )
    require(QEMU_FEATURE not in milkv, "Milk-V exposes the QEMU verified-stream gate")
    require(
        kernel.get(TRUSTED_SAMPLE_FEATURE)
        == [FINISH_FEATURE, "vibeos-sshd/c84-profile-trusted-sample"],
        "trusted-sample is not the exact sibling finish/verify successor",
    )
    require(
        kernel.get(TRUSTED_SAMPLE_QEMU_FEATURE)
        == [TRUSTED_SAMPLE_FEATURE, FINISH_QEMU_FEATURE],
        "kernel trusted-sample QEMU sibling closure differs",
    )
    for label, features, name in (
        ("kernel", kernel, FEATURE),
        ("kernel", kernel, QEMU_FEATURE),
        ("QEMU firmware", qemu, QEMU_FEATURE),
        ("Milk-V firmware", milkv, FEATURE),
    ):
        require(
            name not in PHASE.local_feature_closure(features, features.get("default", [])),
            f"{label} enables {name} by default",
        )
    base_closure = PHASE.local_feature_closure(kernel, [FEATURE])
    require(FINISH_FEATURE in base_closure, "verified-stream base omits finish/verify")
    require(
        not any(name.endswith("-qemu-acceptance") for name in base_closure),
        "verified-stream base selects QEMU telemetry",
    )
    qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_FEATURE])
    require(
        FEATURE in qemu_closure and FINISH_QEMU_FEATURE in qemu_closure,
        "verified-stream QEMU closure omits its base or finish predecessor",
    )
    trusted_closure = PHASE.local_feature_closure(kernel, [TRUSTED_SAMPLE_FEATURE])
    require(
        FINISH_FEATURE in trusted_closure
        and FEATURE not in trusted_closure
        and TRUSTED_SAMPLE_FEATURE not in base_closure,
        "trusted-sample and verified-stream do not remain sibling successors",
    )

    root = semantic(inputs.kernel_root)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root, "verified-stream acceptance lacks its QEMU-only guard")
    pairing = (
        f'#[cfg(all(feature="{FEATURE}",feature="{FINISH_QEMU_FEATURE}",'
        f'not(feature="{QEMU_FEATURE}")))]compile_error!('
        f'"feature`{FEATURE}`cannotreusethediscard-onlyfinish/verifyQEMUtranscript");'
    )
    require(pairing in root, "verified-stream base can reuse dishonest discard telemetry")
    isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolation in root, "verified-stream QEMU isolation guard differs")
    mutually_exclusive = (
        f'#[cfg(all(feature="{TRUSTED_SAMPLE_FEATURE}",feature="{FEATURE}"))]'
        f'compile_error!("features`{TRUSTED_SAMPLE_FEATURE}`and`{FEATURE}`'
        'aremutuallyexclusivefinish/verifysuccessors");'
    )
    require(
        mutually_exclusive in root,
        "verified-stream lacks exact mutual exclusion from trusted-sample",
    )


def verify_direct_cfg(inputs: Inputs) -> None:
    ssh = CORE.without_direct_feature_units(inputs.ssh, TRUSTED_SAMPLE_FEATURE)
    ssh = CORE.without_direct_feature_units(ssh, TRUSTED_SAMPLE_QEMU_FEATURE)
    kernel_root = CORE.without_direct_feature_units(
        inputs.kernel_root, TRUSTED_SAMPLE_FEATURE
    )
    kernel_root = CORE.without_direct_feature_units(
        kernel_root, TRUSTED_SAMPLE_QEMU_FEATURE
    )
    sources = (
        ("SSH", ssh, 6, 7, 9, 14),
        # The second base reference is the exact mutual-exclusion guard shared
        # with the trusted-sample sibling.
        ("kernel root", kernel_root, 0, 2, 0, 3),
    )
    for label, source, base_direct, base_all, qemu_direct, qemu_all in sources:
        rust = CORE.rust_mask(source, literals=False)
        for feature in (FEATURE, QEMU_FEATURE):
            assignment = IRQ.feature_assignment_pattern(feature)
            require(
                re.search(rf"\bcfg\s*!\s*\([^;{{}}]*{assignment}", rust) is None,
                f"{label} selects {feature} through cfg!",
            )
            require(
                re.search(rf"#\s*\[\s*cfg_attr\s*\([^\]]*{assignment}", rust) is None,
                f"{label} selects {feature} through cfg_attr",
            )
        require(
            len(IRQ.direct_feature_units(source, FEATURE)) == base_direct,
            f"{label} direct verified-stream base-unit count differs",
        )
        require(
            len(IRQ.cfg_units_containing_features(source, (FEATURE,))) == base_all,
            f"{label} all-form verified-stream base-unit count differs",
        )
        require(
            len(IRQ.direct_feature_units(source, QEMU_FEATURE)) == qemu_direct,
            f"{label} direct verified-stream QEMU-unit count differs",
        )
        require(
            len(IRQ.cfg_units_containing_features(source, (QEMU_FEATURE,))) == qemu_all,
            f"{label} all-form verified-stream QEMU-unit count differs",
        )

    base = masked("\n".join(IRQ.direct_feature_units(ssh, FEATURE)))
    for required in (
        "VerifiedStreamEvidence",
        "finish_verify_stream_and_complete_profile",
        "discard_and_ack_verified_stream",
        "acknowledge_consumed_stream_error",
    ):
        require(required in base, f"verified-stream base units omit {required}")
    for forbidden in (
        "publish_profile",
        "ProfilePublisher",
        "schema",
        "collector",
        "physical_evidence",
        "exec::spawn(",
        "exec::spawn_pinned_on(",
        ".await",
        "mem::forget",
    ):
        require(forbidden not in base, f"verified-stream base units admit {forbidden}")
    qemu_code = masked("\n".join(IRQ.direct_feature_units(ssh, QEMU_FEATURE)))
    for forbidden in (
        ".finish(",
        ".summary(",
        ".next_interval(",
        ".complete(",
        ".discard(",
        "StreamLease",
        "publish",
        ".await",
    ):
        require(forbidden not in qemu_code, f"verified-stream telemetry admits {forbidden}")


def verify_slot_typestate(source: str) -> None:
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    status = find_scope(source, r"\bpub\(crate\)\s+enum\s+SlotStatus\b", "SlotStatus")
    require(
        "Verified {\n        epoch: u64,\n        cursor: usize,\n        intervals: usize,\n    }"
        in status.raw,
        "SlotStatus does not expose the verified cursor and interval count",
    )
    status_fn = find_scope(source, r"\bpub\(crate\)\s+fn\s+status\b", "slot status")
    status_code = semantic(status_fn.raw)
    require(
        "intervals:sample.summary().interval_count()" in status_code,
        "verified SlotStatus interval count is not derived from the resident summary",
    )

    stream_next = find_scope(source, r"\bfn\s+stream_next\b", "stream_next")
    next_code = semantic(stream_next.raw)
    ordered(
        next_code,
        (
            "letinterval=sample.interval(*cursor);",
            "ifinterval.is_some(){*cursor+=1;}",
            "Ok(interval)",
        ),
        "stream cursor advancement",
    )
    complete = find_scope(source, r"\bfn\s+complete_stream\b", "complete_stream")
    complete_code = semantic(complete.raw)
    ordered(
        complete_code,
        (
            "take_verified(token,detach,true)",
            "letready=sample.recycle()",
            "disarm(owner.detach)",
            "letmutslot=SLOT.lock()",
            "ready.next_epoch()==owner.epoch.checked_add(1)",
            "poison_reason().is_none()",
            "*slot=SlotState::Ready(ready)",
        ),
        "complete verified stream to Ready",
    )
    stream_impl = find_scope(source, r"\bimpl\s+StreamLease\b", "StreamLease impl")
    for name, call in (
        ("summary", "stream_summary(self.token,self.detach)"),
        ("next_interval", "stream_next(self.token,self.detach)"),
        ("complete", "complete_stream(self.token,self.detach)"),
    ):
        scope = find_function(stream_impl, name, f"StreamLease {name}")
        require(call in semantic(scope.raw), f"StreamLease {name} does not use {call}")

    lease_complete = find_function(stream_impl, "complete", "StreamLease complete")
    lease_complete_code = semantic(lease_complete.raw)
    require(
        lease_complete_code.count("self.live=false;") == 1,
        "StreamLease complete changes live outside its sole success arm",
    )
    require(
        "matchcomplete_stream(self.token,self.detach){"
        "Ok(())=>{self.live=false;Ok(())}Err(error)=>Err(error),}" in lease_complete_code,
        "StreamLease complete does not leave Err live for fail-closed Drop",
    )
    lease_drop = find_scope(
        source, r"\bimpl\s+Drop\s+for\s+StreamLease\b", "StreamLease Drop"
    )
    lease_drop_code = semantic(lease_drop.raw)
    require(
        "ifself.live{self.live=false;let_=discard_stream(self.token,self.detach);}" in lease_drop_code,
        "live StreamLease Drop does not explicitly discard the resident stream",
    )
    require(
        lease_drop_code.count("self.live=false;") == 1
        and lease_drop_code.count("discard_stream(self.token,self.detach)") == 1,
        "StreamLease Drop live/discard count differs",
    )


def verify_ssh(source: str) -> None:
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    owner = find_scope(source, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner")
    response = find_function(owner, "response_boundary", "SSH response boundary")
    cancel = find_function(owner, "cancel", "SSH active Drop")
    response_code = semantic(response.raw)
    cancel_code = semantic(cancel.raw)
    require(
        response_code.count("finish_verify_stream_and_complete_profile(run)") == 1,
        "normal response does not select the verified-stream helper exactly once",
    )
    require(
        f'#[cfg(feature="{FEATURE}")]letterminal='
        "finish_verify_stream_and_complete_profile(run).map(|evidence|"
        "(evidence.ready_epoch,evidence));" in response_code,
        "verified-stream terminal is not directly feature-selected",
    )
    ordered(
        response_code,
        (
            "managed_phase_response_ready(epoch)",
            "managed_phase_observation(epoch)",
            "finish_verify_stream_and_complete_profile(run)",
            "managed_irq_acceptance_terminal_gate(epoch,ready_epoch,)",
            "profile_phase_response(",
            f'"{CORE_FAMILY}RESPONSEepoch={{}}status={{}}claim=1release=1'
            "detach=exitedclean=1core_polls={}observer_pairs={}typed_polls={}"
            "observer_closed=1finish=1verify=1stream=completeack=0ready_epoch={}",
            "profile_request_response(epoch,status,ready_epoch);",
            "managed_irq_response(epoch,status,ready_epoch,irq_observation);",
            "finish_verify_response(epoch,status,ready_epoch);",
            "verified_stream_response(epoch,_terminal_evidence);",
        ),
        "verified-stream response terminal chain",
    )
    for forbidden in (
        "finish_verify_stream_and_complete_profile",
        "VerifiedStreamEvidence",
        ".finish(",
        ".summary(",
        ".next_interval(",
        ".complete(",
    ):
        require(forbidden not in cancel_code, f"active Drop admits {forbidden}")
    ordered(
        cancel_code,
        (
            "cancel_and_ack_profile(run,expected_faults)",
            "managed_irq_acceptance_terminal_gate(epoch,ready_epoch,)",
            "profile_phase_drop(",
            f'"{CORE_FAMILY}DROPepoch={{}}',
            "profile_request_drop(epoch,ready_epoch)",
            "managed_irq_drop(epoch,ready_epoch,irq_observation)",
            "finish_verify_drop(epoch,ready_epoch)",
            "verified_stream_drop(epoch,ready_epoch)",
        ),
        "verified-stream Drop terminal chain",
    )

    evidence = find_scope(source, r"\bstruct\s+VerifiedStreamEvidence\b", "stream evidence")
    cfg_guarded(source, evidence.start, "stream evidence", FEATURE)
    evidence_code = semantic(evidence.raw)
    for field in ("ready_epoch:u64", "total_ticks:u64", "interval_count:usize"):
        require(field in evidence_code, f"stream evidence omits {field}")

    helper = find_scope(
        source,
        r"\bfn\s+finish_verify_stream_and_complete_profile\b",
        "verified-stream helper",
    )
    cfg_guarded(source, helper.start, "verified-stream helper", FEATURE)
    code = semantic(helper.raw)
    ordered(
        code,
        (
            "matchrun.finish()",
            "SlotStatus::Verified{epoch:verified_epoch,cursor:0,intervals,}",
            "letsummary=matchstream.summary()",
            "summary.interval_capacity()==INTERVAL_CAPACITY",
            "summary.intervals_complete()",
            "summary.interval_count()!=0",
            "summary.interval_count()<=summary.interval_capacity()",
            "summary.interval_count()==initial_interval_count",
            "summary.total_ticks()!=0",
            "summary.end_tick().checked_sub(summary.start_tick())==Some(summary.total_ticks())",
            "summary_phase_ticks.checked_total()==Some(summary.total_ticks())",
            "loop{letinterval=matchstream.next_interval()",
            "letduration=matchinterval.end_offset_ticks().checked_sub(interval.start_offset_ticks())",
            "emitted>summary.interval_count()",
            "interval.sequence()!=expected_sequence",
            "interval.start_offset_ticks()!=previous_end",
            "previous_phase==Some(interval.phase())",
            "add_verified_stream_phase_ticks(",
            "cursor==emitted",
            "intervals==summary.interval_count()",
            "emitted!=summary.interval_count()",
            "previous_end!=summary.total_ticks()",
            "rescanned_phase_ticks!=summary_phase_ticks",
            "stream.complete().is_err()",
            "SlotStatus::Ready{next_epoch:Some(ready_epoch),}",
            "rejection().is_some()",
            "Ok(VerifiedStreamEvidence{",
        ),
        "summary/interval rescan/complete",
    )
    require(code.count("run.finish()") == 1, "verified-stream finish count differs")
    require(
        code.count("ifstream.token().epoch()!=epoch{") == 1,
        "stream token is not bound to the run epoch",
    )
    require(
        code.count("verified_epoch==epoch") == 2,
        "initial/final verified slot epochs are not both bound to the run epoch",
    )
    require(code.count("stream.summary()") == 1, "verified-stream summary count differs")
    require(code.count("stream.next_interval()") == 1, "stream iterator call-site count differs")
    require(code.count("stream.complete()") == 1, "stream completion count differs")
    require(
        "&&summary.intervals_complete()&&summary.interval_count()!=0&&" in code,
        "summary completeness/nonempty predicates are not asserted positively",
    )
    require(
        "Some(duration)ifduration!=0=>duration" in code,
        "interval duration is not proven nonzero",
    )
    require(
        "ifemitted>summary.interval_count()||" in code,
        "stream rescan does not reject emission beyond the summary count",
    )
    zero_discard = "discard_and_ack_verified_stream(stream,epoch,0)?;"
    emitted_discard = "discard_and_ack_verified_stream(stream,epoch,emitted)?;"
    require(
        code.count("discard_and_ack_verified_stream(") == 9
        and code.count(zero_discard) == 4
        and code.count(emitted_discard) == 5,
        "verified-stream failure paths are not exactly four zero-cursor and five emitted-cursor discards",
    )
    require("drop(stream)" not in code, "verified-stream helper implicitly drops a live stream")
    for label, failure_path in (
        (
            "token mismatch",
            f"ifstream.token().epoch()!=epoch{{{zero_discard}returnErr(());}}",
        ),
        (
            "initial Verified status",
            f"ifverified_epoch==epoch=>intervals,_=>{{{zero_discard}returnErr(());}}",
        ),
        (
            "summary read",
            f"Err(_)=>{{{zero_discard}returnErr(());}}}};letsummary_phase_ticks",
        ),
        (
            "summary invariants",
            f"if!summary_is_exact{{{zero_discard}returnErr(());}}",
        ),
        (
            "next interval",
            f"Err(_)=>{{{emitted_discard}returnErr(());}}}};letSome(interval)",
        ),
        (
            "emitted overflow",
            f"emitted.checked_add(1)else{{{emitted_discard}returnErr(());}};",
        ),
        (
            "duration",
            f"Some(duration)ifduration!=0=>duration,_=>{{{emitted_discard}returnErr(());}}}};",
        ),
        (
            "interval invariants",
            f"){{{emitted_discard}returnErr(());}}previous_end=interval.end_offset_ticks()",
        ),
        (
            "final invariants",
            f"||!final_cursor_is_exact{{{emitted_discard}returnErr(());}}",
        ),
    ):
        require(
            code.count(failure_path) == 1,
            f"{label} failure does not explicitly discard and acknowledge with the exact cursor",
        )
    require(
        "Err(ProfileError::Rejected(report))=>{let_=acknowledge_finish_verify_rejection(epoch,report)?;returnErr(());}" in code,
        "finish rejection is not acknowledged before failure",
    )
    require(
        "ifstream.complete().is_err(){acknowledge_consumed_stream_error(epoch,emitted)?;returnErr(());}" in code,
        "consumed completion failure is not independently recycled",
    )
    require(
        "if!ready_is_exact||rejection().is_some(){returnErr(());}" in code,
        "successful completion does not require exact Ready with no rejection",
    )
    require(
        "letready_is_exact=crate::wasm_aot_profile_slot::status()=="
        "(SlotStatus::Ready{next_epoch:Some(ready_epoch),});" in code,
        "successful completion does not derive Ready from the global slot",
    )

    phase_add = find_scope(
        source, r"\bfn\s+add_verified_stream_phase_ticks\b", "phase rescan addition"
    )
    cfg_guarded(source, phase_add.start, "phase rescan addition", FEATURE)
    phase_code = semantic(phase_add.raw)
    for phase in (
        "Validation",
        "Instantiation",
        "Abi",
        "Interpretation",
        "Host",
        "Wait",
        "Cleanup",
    ):
        require(f"Phase::{phase}=>" in phase_code, f"phase rescan omits {phase}")
    require(
        "checked_add(ticks)" in phase_code and "iftotal==u64::MAX{returnfalse;}" in phase_code,
        "phase rescan addition is not checked",
    )

    discard = find_scope(
        source, r"\bfn\s+discard_and_ack_verified_stream\b", "stream failure discard"
    )
    cfg_guarded(source, discard.start, "stream failure discard", FEATURE)
    discard_code = semantic(discard.raw)
    discard_binding = (
        "letreport=stream.discard().map_err(|_|())?;"
        "letreport_is_exact=report.epoch==epoch"
        "&&report.cause==RejectionCause::StreamAbandoned"
        "&&report.facade_faults.is_empty()"
        "&&report.ledger_error.is_none()"
        "&&report.slot_faults==SlotFaults::default()"
        "&&report.intervals_emitted==expected_emitted;"
        "let_=acknowledge_finish_verify_rejection(epoch,report)?;"
        "if!report_is_exact{returnErr(());}Ok(())"
    )
    require(
        discard_code.count(discard_binding) == 1
        and discard_code.count("letreport_is_exact=") == 1,
        "live-stream discard report construction, acknowledgement, and mismatch failure are not uniquely bound",
    )
    ordered(
        discard_code,
        (
            "stream.discard()",
            "report.cause==RejectionCause::StreamAbandoned",
            "report.intervals_emitted==expected_emitted",
            "acknowledge_finish_verify_rejection(epoch,report)",
        ),
        "live-stream failure recycle",
    )
    consumed = find_scope(
        source, r"\bfn\s+acknowledge_consumed_stream_error\b", "completion error recycle"
    )
    cfg_guarded(source, consumed.start, "completion error recycle", FEATURE)
    consumed_code = semantic(consumed.raw)
    consumed_binding = (
        "letreport=rejection().filter(|report|report.epoch==epoch).ok_or(())?;"
        "letreport_is_exact=report.cause==RejectionCause::StreamAbandoned"
        "&&report.facade_faults.is_empty()"
        "&&report.ledger_error.is_none()"
        "&&report.slot_faults==SlotFaults::default()"
        "&&report.intervals_emitted==expected_emitted;"
        "let_=acknowledge_finish_verify_rejection(epoch,report)?;"
        "if!report_is_exact{returnErr(());}Ok(())"
    )
    require(
        consumed_code.count(consumed_binding) == 1
        and consumed_code.count("letreport_is_exact=") == 1,
        "consumed-stream report construction, acknowledgement, and mismatch failure are not uniquely bound",
    )
    ordered(
        consumed_code,
        (
            "rejection().filter(|report|report.epoch==epoch)",
            "report.cause==RejectionCause::StreamAbandoned",
            "report.intervals_emitted==expected_emitted",
            "acknowledge_finish_verify_rejection(epoch,report)",
        ),
        "consumed-stream failure recycle",
    )

    response_telemetry = find_scope(
        source, r"\bfn\s+verified_stream_response\b", "verified-stream response telemetry"
    )
    drop_telemetry = find_scope(
        source, r"\bfn\s+verified_stream_drop\b", "verified-stream Drop telemetry"
    )
    for label, scope in (("response", response_telemetry), ("Drop", drop_telemetry)):
        cfg_guarded(source, scope.start, f"verified-stream {label} telemetry", QEMU_FEATURE)
        telemetry_code = masked(scope.raw)
        for forbidden in (
            ".finish(",
            ".summary(",
            ".next_interval(",
            ".complete(",
            ".discard(",
            "StreamLease",
            "publish",
            ".await",
        ):
            require(forbidden not in telemetry_code, f"{label} telemetry admits {forbidden}")
    response_print = semantic(
        f'crate::println!("{NORMAL_MARKER}",'
        "epoch,evidence.total_ticks,evidence.interval_count,evidence.interval_count,"
        "evidence.interval_count,evidence.ready_epoch);"
    )
    response_telemetry_code = semantic(response_telemetry.raw)
    response_function = (
        "fnverified_stream_response(epoch:u64,evidence:VerifiedStreamEvidence){"
        + response_print
        + "}"
    )
    require(
        comment_masked(response_telemetry.raw).count(NORMAL_MARKER) == 1
        and response_telemetry_code.count("println!(") == 1
        and response_telemetry_code.count(response_print) == 1,
        "verified-stream RESPONSE is not one exact println with its frozen literal and arguments",
    )
    require(
        response_telemetry_code == response_function,
        "verified-stream RESPONSE println is not the function's sole direct body",
    )
    drop_print = semantic(
        f'crate::println!("{DROP_MARKER}",epoch,ready_epoch);'
    )
    drop_telemetry_code = semantic(drop_telemetry.raw)
    drop_function = (
        "fnverified_stream_drop(epoch:u64,ready_epoch:u64){" + drop_print + "}"
    )
    require(
        comment_masked(drop_telemetry.raw).count(DROP_MARKER) == 1
        and drop_telemetry_code.count("println!(") == 1
        and drop_telemetry_code.count(drop_print) == 1,
        "verified-stream Drop is not one exact println with its frozen literal and arguments",
    )
    require(
        drop_telemetry_code == drop_function,
        "verified-stream Drop println is not the function's sole direct body",
    )

    request_response = find_scope(
        source, r"\bfn\s+profile_request_response\b", "request RESPONSE telemetry"
    )
    irq_response = find_scope(
        source, r"\bfn\s+managed_irq_response\b", "IRQ RESPONSE telemetry"
    )
    phase_response = find_scope(
        source, r"\bfn\s+profile_phase_response\b", "phase RESPONSE telemetry"
    )
    finish_response = find_scope(
        source, r"\bfn\s+finish_verify_response\b", "finish RESPONSE telemetry"
    )
    predecessor_markers = (
        (
            "request",
            request_response,
            REQUEST_SUCCESS_MARKER,
            REQUEST_SUCCESS_ARGUMENTS,
        ),
        ("IRQ", irq_response, IRQ_SUCCESS_MARKER, IRQ_SUCCESS_ARGUMENTS),
        ("phase", phase_response, PHASE_SUCCESS_MARKER, PHASE_SUCCESS_ARGUMENTS),
        ("Core", response, CORE_SUCCESS_MARKER, CORE_SUCCESS_ARGUMENTS),
        (
            "finish",
            finish_response,
            FINISH_SUCCESS_MARKER,
            FINISH_SUCCESS_ARGUMENTS,
        ),
    )
    predecessor_units = [
        direct_print_unit(
            scope,
            literal,
            arguments,
            f"verified-stream {label} predecessor",
        )
        for label, scope, literal, arguments in predecessor_markers
    ]
    predecessor_code = "\n".join(comment_masked(unit) for unit in predecessor_units)
    require(
        predecessor_code.count(SUCCESSOR_SUFFIX) == 5,
        "not all five predecessor RESPONSE families expose the complete-stream suffix",
    )

    integration = (
        owner.raw
        + evidence.raw
        + helper.raw
        + phase_add.raw
        + discard.raw
        + consumed.raw
        + response_telemetry.raw
        + drop_telemetry.raw
        + request_response.raw
        + irq_response.raw
        + phase_response.raw
        + finish_response.raw
    )
    integration_code = masked(integration)
    for forbidden in (
        "ProfilePublisher",
        "publish_profile",
        "schema",
        "collector",
        "physical_evidence",
        "exec::spawn(",
        "exec::spawn_pinned_on(",
        "mem::forget",
        ".await",
    ):
        require(forbidden not in integration_code, f"verified-stream integration admits {forbidden}")


def verify_stream(inputs: Inputs) -> None:
    verify_features(inputs)
    verify_direct_cfg(inputs)
    verify_slot_typestate(inputs.slot)
    verify_ssh(inputs.ssh)


def verify(inputs: Inputs, *, predecessor: bool = True) -> None:
    if predecessor:
        try:
            FINISH.verify(inputs.predecessor)
        except FINISH.VerificationError as error:
            raise VerificationError(f"predecessor verifier failed: {error}") from error
    verify_stream(inputs)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest seed {label!r} count differs: {count}")
    return value.replace(old, new, 1)


def mutate_text(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    return replace(data, **{field: replace_once(getattr(data, field), old, new, label)})


def mutate_function_text(
    data: Inputs,
    field: str,
    function: str,
    old: str,
    new: str,
    label: str,
) -> Inputs:
    source = getattr(data, field)
    scope = find_scope(source, rf"\bfn\s+{re.escape(function)}\b", function)
    mutated = replace_once(scope.raw, old, new, label)
    return replace(data, **{field: source[: scope.start] + mutated + source[scope.end :]})


def mutate_response_marker_with_comment_decoy(data: Inputs) -> Inputs:
    source = data.ssh
    scope = find_scope(
        source, r"\bfn\s+verified_stream_response\b", "verified-stream response telemetry"
    )
    forged = NORMAL_MARKER.replace("summary=1", "summary=0", 1)
    mutated = replace_once(scope.raw, NORMAL_MARKER, forged, "real RESPONSE marker")
    return replace(
        data,
        ssh=source[: scope.start]
        + mutated
        + source[scope.end :]
        + f"\n// {NORMAL_MARKER}\n",
    )


def mutate_marker_with_dead_code_decoy(
    data: Inputs,
    function: str,
    marker: str,
    forged: str,
    arguments: str,
    label: str,
) -> Inputs:
    source = data.ssh
    scope = find_scope(source, rf"\bfn\s+{re.escape(function)}\b", label)
    mutated = replace_once(scope.raw, marker, forged, f"real {label} marker")
    require(mutated.endswith("}"), f"{label} mutation scope does not end in a brace")
    dead_code = (
        "\n    if false {\n"
        "        crate::println!(\n"
        f'            "{marker}",\n'
        f"{arguments}\n"
        "        );\n"
        "    }\n"
    )
    mutated = mutated[:-1] + dead_code + "}"
    return replace(data, ssh=source[: scope.start] + mutated + source[scope.end :])


def mutate_direct_print_first_argument(
    data: Inputs,
    function: str,
    marker: str,
    label: str,
) -> Inputs:
    source = data.ssh
    if function == "SshExecProfileOwner::response_boundary":
        owner = find_scope(
            source, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner"
        )
        scope = find_function(owner, "response_boundary", "SSH response boundary")
    else:
        scope = find_scope(source, rf"\bfn\s+{re.escape(function)}\b", label)
    units = IRQ.direct_feature_units(scope.raw, QEMU_FEATURE)
    matching = [unit for unit in units if marker in comment_masked(unit)]
    require(len(matching) == 1, f"selftest {label} direct unit count differs")
    unit = matching[0]
    pattern = re.compile(rf'("{re.escape(marker)}",)(\s*)epoch,')
    matches = list(pattern.finditer(unit))
    require(len(matches) == 1, f"selftest {label} first epoch argument count differs")
    mutated_unit = pattern.sub(
        lambda match: match.group(1) + match.group(2) + "{ return; 0 },",
        unit,
        count=1,
    )
    mutated_source = replace_once(source, unit, mutated_unit, f"{label} direct unit")
    return replace(data, ssh=mutated_source)


def mutate_manifest(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    raw = getattr(data, field).decode("utf-8")
    return replace(
        data,
        **{field: replace_once(raw, old, new, label).encode("utf-8")},
    )


def expect_rejected(inputs: Inputs, mutation: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutation(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify_stream(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def run_selftest(inputs: Inputs) -> int:
    verify(inputs)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "base-predecessor-removed",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{FEATURE} = [\n    "{FINISH_FEATURE}",\n]',
                f"{FEATURE} = []",
                "base predecessor",
            ),
        ),
        (
            "qemu-predecessor-removed",
            lambda data: mutate_manifest(
                data,
                "qemu_manifest",
                f'{QEMU_FEATURE} = [\n'
                f'    "{FINISH_QEMU_FEATURE}",\n'
                f'    "vibeos-kernel/{QEMU_FEATURE}",\n'
                "]",
                f'{QEMU_FEATURE} = [\n'
                f'    "vibeos-kernel/{QEMU_FEATURE}",\n'
                "]",
                "QEMU predecessor",
            ),
        ),
        (
            "milkv-selects-qemu",
            lambda data: mutate_manifest(
                data,
                "milkv_manifest",
                f'["vibeos-kernel/{FEATURE}"]',
                f'["vibeos-kernel/{QEMU_FEATURE}"]',
                "Milk-V QEMU widening",
            ),
        ),
        (
            "qemu-only-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    feature = "{QEMU_FEATURE}",\n    not(feature = "qemu-virt")',
                f'    feature = "{QEMU_FEATURE}",\n    feature = "qemu-virt"',
                "QEMU-only guard",
            ),
        ),
        (
            "pairing-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                f'    "feature `{FEATURE}` cannot reuse the discard-only finish/verify QEMU transcript"',
                '    "verified-stream pairing disabled"',
                "pairing guard",
            ),
        ),
        (
            "stream-complete-clears-live-before-result",
            lambda data: mutate_text(
                data,
                "slot",
                "    pub(crate) fn complete(mut self) -> Result<(), ProfileError> {\n"
                "        if !self.detach.is_current_running_exact() {",
                "    pub(crate) fn complete(mut self) -> Result<(), ProfileError> {\n"
                "        self.live = false;\n"
                "        if !self.detach.is_current_running_exact() {",
                "StreamLease early live clear",
            ),
        ),
        (
            "stream-drop-discard-removed",
            lambda data: mutate_text(
                data,
                "slot",
                "let _ = discard_stream(self.token, self.detach);",
                "let _ = (self.token, self.detach);",
                "StreamLease Drop discard",
            ),
        ),
        (
            "terminal-helper-replaced",
            lambda data: mutate_text(
                data,
                "ssh",
                "finish_verify_stream_and_complete_profile(run)\n            .map(|evidence| (evidence.ready_epoch, evidence))",
                "finish_verify_discard_and_ack_profile(run)\n            .map(|ready| (ready, ready))",
                "stream terminal helper",
            ),
        ),
        (
            "run-finish-replaced",
            lambda data: mutate_text(
                data,
                "ssh",
                "let mut stream = match run.finish() {",
                "let mut stream = match run.cancel() {",
                "run finish",
            ),
        ),
        (
            "initial-cursor-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "cursor: 0,\n            intervals,",
                "cursor: 1,\n            intervals,",
                "initial cursor",
            ),
        ),
        (
            "stream-epoch-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "if stream.token().epoch() != epoch {",
                "if stream.token().epoch() == epoch {",
                "stream epoch",
            ),
        ),
        (
            "token-mismatch-implicitly-drops",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_stream_and_complete_profile",
                "if stream.token().epoch() != epoch {\n"
                "        discard_and_ack_verified_stream(stream, epoch, 0)?;\n"
                "        return Err(());\n"
                "    }",
                "if stream.token().epoch() != epoch {\n"
                "        drop(stream);\n"
                "        return Err(());\n"
                "    }",
                "token mismatch explicit discard",
            ),
        ),
        (
            "summary-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "let summary = match stream.summary() {",
                "let summary = match forged_summary() {",
                "summary read",
            ),
        ),
        (
            "capacity-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "summary.interval_capacity() == INTERVAL_CAPACITY",
                "summary.interval_capacity() > 0",
                "interval capacity",
            ),
        ),
        (
            "empty-admitted",
            lambda data: mutate_text(
                data,
                "ssh",
                "&& summary.interval_count() != 0",
                "&& summary.interval_count() == 0",
                "nonempty summary",
            ),
        ),
        (
            "capacity-upper-bound-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "&& summary.interval_count() <= summary.interval_capacity()",
                "&& summary.interval_count() > summary.interval_capacity()",
                "summary capacity upper bound",
            ),
        ),
        (
            "incomplete-admitted",
            lambda data: mutate_text(
                data,
                "ssh",
                "&& summary.intervals_complete()",
                "&& !summary.intervals_complete()",
                "complete summary",
            ),
        ),
        (
            "tick-span-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "summary.end_tick().checked_sub(summary.start_tick()) == Some(summary.total_ticks())",
                "summary.end_tick() == summary.total_ticks()",
                "summary tick span",
            ),
        ),
        (
            "phase-sum-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "summary_phase_ticks.checked_total() == Some(summary.total_ticks())",
                "summary_phase_ticks.checked_total().is_some()",
                "summary phase sum",
            ),
        ),
        (
            "iterator-replaced",
            lambda data: mutate_text(
                data,
                "ssh",
                "let interval = match stream.next_interval() {",
                "let interval = match forged_interval() {",
                "stream iterator",
            ),
        ),
        (
            "zero-duration-admitted",
            lambda data: mutate_text(
                data,
                "ssh",
                "Some(duration) if duration != 0 => duration,",
                "Some(duration) => duration,",
                "nonzero duration",
            ),
        ),
        (
            "emitted-upper-bound-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "if emitted > summary.interval_count()",
                "if emitted == usize::MAX",
                "emitted upper bound",
            ),
        ),
        (
            "sequence-check-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "|| interval.sequence() != expected_sequence",
                "|| interval.sequence() == usize::MAX",
                "interval sequence",
            ),
        ),
        (
            "contiguity-check-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "|| interval.start_offset_ticks() != previous_end",
                "|| interval.start_offset_ticks() == u64::MAX",
                "interval contiguity",
            ),
        ),
        (
            "adjacent-phase-check-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "|| previous_phase == Some(interval.phase())",
                "|| previous_phase == None",
                "adjacent phase",
            ),
        ),
        (
            "phase-rescan-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "|| !add_verified_stream_phase_ticks(",
                "|| !forged_phase_ticks(",
                "phase rescan",
            ),
        ),
        (
            "count-check-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "if emitted != summary.interval_count()",
                "if emitted == usize::MAX",
                "emitted count",
            ),
        ),
        (
            "final-end-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "|| previous_end != summary.total_ticks()",
                "|| previous_end == u64::MAX",
                "final endpoint",
            ),
        ),
        (
            "phase-comparison-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "|| rescanned_phase_ticks != summary_phase_ticks",
                "|| rescanned_phase_ticks == vibeos_wasm_aot_profile::PhaseTicks::ZERO",
                "phase comparison",
            ),
        ),
        (
            "cursor-check-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "&& cursor == emitted",
                "&& cursor == 0",
                "final cursor",
            ),
        ),
        (
            "final-verified-epoch-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "} if verified_epoch == epoch\n            && cursor == emitted",
                "} if verified_epoch != epoch\n            && cursor == emitted",
                "final verified epoch",
            ),
        ),
        (
            "completion-replaced",
            lambda data: mutate_text(
                data,
                "ssh",
                "if stream.complete().is_err() {",
                "if stream.discard().is_err() {",
                "stream completion",
            ),
        ),
        (
            "completion-error-recycle-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error(epoch, emitted)?;",
                "let _ = (epoch, emitted);",
                "completion error recycle",
            ),
        ),
        (
            "ready-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "if stream.complete().is_err() {\n"
                "        acknowledge_consumed_stream_error(epoch, emitted)?;\n"
                "        return Err(());\n"
                "    }\n"
                "    let ready_epoch = epoch.checked_add(1).ok_or(())?;\n"
                "    let ready_is_exact = crate::wasm_aot_profile_slot::status()",
                "if stream.complete().is_err() {\n"
                "        acknowledge_consumed_stream_error(epoch, emitted)?;\n"
                "        return Err(());\n"
                "    }\n"
                "    let ready_epoch = epoch.checked_add(1).ok_or(())?;\n"
                "    let ready_is_exact = forged_status()",
                "Ready proof",
            ),
        ),
        (
            "stored-rejection-admitted",
            lambda data: mutate_text(
                data,
                "ssh",
                "if !ready_is_exact || rejection().is_some() {",
                "if !ready_is_exact && rejection().is_some() {",
                "stored rejection",
            ),
        ),
        (
            "discard-report-epoch-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "let report_is_exact = report.epoch == epoch\n"
                "        && report.cause == RejectionCause::StreamAbandoned",
                "let report_is_exact = true\n"
                "        && report.cause == RejectionCause::StreamAbandoned",
                "discard report epoch",
            ),
        ),
        (
            "discard-report-cause-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "report.cause == RejectionCause::StreamAbandoned",
                "true",
                "discard report cause",
            ),
        ),
        (
            "discard-report-facade-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "report.facade_faults.is_empty()",
                "true",
                "discard report facade faults",
            ),
        ),
        (
            "discard-report-ledger-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "report.ledger_error.is_none()",
                "true",
                "discard report ledger error",
            ),
        ),
        (
            "discard-report-slot-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "report.slot_faults == SlotFaults::default()",
                "true",
                "discard report slot faults",
            ),
        ),
        (
            "discard-emitted-forged",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "&& report.intervals_emitted == expected_emitted;",
                "&& report.intervals_emitted == 0;",
                "discard emitted cursor",
            ),
        ),
        (
            "discard-ack-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "let _ = acknowledge_finish_verify_rejection(epoch, report)?;",
                "let _ = report;",
                "discard report acknowledgement",
            ),
        ),
        (
            "discard-report-mismatch-ignored",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "if !report_is_exact {\n        return Err(());\n    }",
                "let _ = report_is_exact;",
                "discard report mismatch",
            ),
        ),
        (
            "discard-report-shadowed-true",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "discard_and_ack_verified_stream",
                "        && report.intervals_emitted == expected_emitted;\n"
                "    // Discard has installed a known rejection.",
                "        && report.intervals_emitted == expected_emitted;\n"
                "    let report_is_exact = true;\n"
                "    // Discard has installed a known rejection.",
                "discard report shadow",
            ),
        ),
        (
            "consumed-report-epoch-filter-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "let report = rejection()\n"
                "        .filter(|report| report.epoch == epoch)\n"
                "        .ok_or(())?;",
                "let report = rejection().ok_or(())?;",
                "consumed report epoch filter",
            ),
        ),
        (
            "consumed-report-cause-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "report.cause == RejectionCause::StreamAbandoned",
                "true",
                "consumed report cause",
            ),
        ),
        (
            "consumed-report-facade-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "report.facade_faults.is_empty()",
                "true",
                "consumed report facade faults",
            ),
        ),
        (
            "consumed-report-ledger-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "report.ledger_error.is_none()",
                "true",
                "consumed report ledger error",
            ),
        ),
        (
            "consumed-report-slot-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "report.slot_faults == SlotFaults::default()",
                "true",
                "consumed report slot faults",
            ),
        ),
        (
            "consumed-report-emitted-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "report.intervals_emitted == expected_emitted;",
                "true;",
                "consumed report emitted cursor",
            ),
        ),
        (
            "consumed-ack-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "let _ = acknowledge_finish_verify_rejection(epoch, report)?;",
                "let _ = report;",
                "consumed report acknowledgement",
            ),
        ),
        (
            "consumed-report-mismatch-ignored",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "if !report_is_exact {\n        return Err(());\n    }",
                "let _ = report_is_exact;",
                "consumed report mismatch",
            ),
        ),
        (
            "consumed-report-shadowed-true",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "acknowledge_consumed_stream_error",
                "        && report.intervals_emitted == expected_emitted;\n"
                "    let _ = acknowledge_finish_verify_rejection(epoch, report)?;",
                "        && report.intervals_emitted == expected_emitted;\n"
                "    let report_is_exact = true;\n"
                "    let _ = acknowledge_finish_verify_rejection(epoch, report)?;",
                "consumed report shadow",
            ),
        ),
        (
            "response-marker-capacity",
            lambda data: mutate_text(
                data,
                "ssh",
                "interval_capacity=65536 interval_count={}",
                "interval_capacity=65535 interval_count={}",
                "response capacity marker",
            ),
        ),
        (
            "response-marker-comment-decoy",
            mutate_response_marker_with_comment_decoy,
        ),
        (
            "response-marker-dead-code-decoy",
            lambda data: mutate_marker_with_dead_code_decoy(
                data,
                "verified_stream_response",
                NORMAL_MARKER,
                NORMAL_MARKER.replace("summary=1", "summary=0", 1),
                "            epoch,\n"
                "            evidence.total_ticks,\n"
                "            evidence.interval_count,\n"
                "            evidence.interval_count,\n"
                "            evidence.interval_count,\n"
                "            evidence.ready_epoch",
                "verified-stream RESPONSE",
            ),
        ),
        (
            "drop-marker-dead-code-decoy",
            lambda data: mutate_marker_with_dead_code_decoy(
                data,
                "verified_stream_drop",
                DROP_MARKER,
                DROP_MARKER.replace("summary=0", "summary=1", 1),
                "            epoch,\n            ready_epoch",
                "verified-stream Drop",
            ),
        ),
        (
            "request-response-control-flow-argument",
            lambda data: mutate_direct_print_first_argument(
                data,
                "profile_request_response",
                REQUEST_SUCCESS_MARKER,
                "request RESPONSE",
            ),
        ),
        (
            "irq-response-control-flow-argument",
            lambda data: mutate_direct_print_first_argument(
                data,
                "managed_irq_response",
                IRQ_SUCCESS_MARKER,
                "IRQ RESPONSE",
            ),
        ),
        (
            "phase-response-control-flow-argument",
            lambda data: mutate_direct_print_first_argument(
                data,
                "profile_phase_response",
                PHASE_SUCCESS_MARKER,
                "phase RESPONSE",
            ),
        ),
        (
            "core-response-control-flow-argument",
            lambda data: mutate_direct_print_first_argument(
                data,
                "SshExecProfileOwner::response_boundary",
                CORE_SUCCESS_MARKER,
                "Core RESPONSE",
            ),
        ),
        (
            "finish-response-control-flow-argument",
            lambda data: mutate_direct_print_first_argument(
                data,
                "finish_verify_response",
                FINISH_SUCCESS_MARKER,
                "finish RESPONSE",
            ),
        ),
        (
            "drop-streams",
            lambda data: mutate_text(
                data,
                "ssh",
                "verified_stream_drop(epoch, ready_epoch);",
                "let _ = finish_verify_stream_and_complete_profile(run); verified_stream_drop(epoch, ready_epoch);",
                "Drop stream",
            ),
        ),
        (
            "publisher-added",
            lambda data: mutate_text(
                data,
                "ssh",
                "let summary = match stream.summary() {",
                "publish_profile(&stream); let summary = match stream.summary() {",
                "publisher",
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
            "PASS verify-c84-ssh-managed-child-verified-stream: exact summary, bounded full "
            "interval rescan, cursor equality, explicit complete/Ready, fail-closed recycle, "
            f"unchanged Drop, and diagnostic isolation are closed{suffix}"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        VerificationError,
    ) as error:
        print(f"FAIL verify-c84-ssh-managed-child-verified-stream: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
