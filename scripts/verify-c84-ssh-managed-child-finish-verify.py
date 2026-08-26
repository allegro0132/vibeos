#!/usr/bin/env python3
"""Verify the C8.4 SSH managed-child finish/verify terminal successor."""

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
IRQ_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-irq-overlay.py"
TARGET_SOURCE = ROOT / "wasm-aot-profile/src/target.rs"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
SSHD_SOURCE = ROOT / "components/sshd/src/lib.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"

FEATURE = "wasm-c84-ssh-managed-child-finish-verify"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
VERIFIED_STREAM_FEATURE = "wasm-c84-ssh-managed-child-verified-stream"
VERIFIED_STREAM_QEMU_FEATURE = f"{VERIFIED_STREAM_FEATURE}-qemu-acceptance"
TRUSTED_SAMPLE_FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
TRUSTED_SAMPLE_QEMU_FEATURE = f"{TRUSTED_SAMPLE_FEATURE}-qemu-acceptance"
SSHD_TRUSTED_SAMPLE_FEATURE = "c84-profile-trusted-sample"
IRQ_FEATURE = "wasm-c84-ssh-managed-child-irq-overlay"
IRQ_QEMU_FEATURE = f"{IRQ_FEATURE}-qemu-acceptance"
STANDALONE_IRQ_QEMU_FEATURE = "wasm-c84-profile-irq-overlay-qemu-acceptance"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_FINISH_VERIFY"
PHASE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
CORE_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_CORE"
REQUEST_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"
IRQ_FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"

NORMAL_MARKER = (
    f"{FAMILY} RESPONSE epoch={{}} status={{}} finish=1 verify=1 cursor=0 "
    "discard=stream_abandoned emitted=0 stored=1 ack=1 ready_epoch={}"
)
DROP_MARKER = (
    f"{FAMILY} DROP epoch={{}} cancel=lease_cancelled finish=0 verify=0 stream=0 "
    "emitted=0 stored=1 ack=1 ready_epoch={}"
)
SUCCESSOR_SUFFIX = "finish=1 verify=1 discard=stream_abandoned ack=1 ready_epoch={}"
CORE_SUCCESSOR_MARKER = (
    f"{CORE_FAMILY} RESPONSE epoch={{}} status={{}} claim=1 release=1 detach=exited "
    "clean=1 core_polls={} observer_pairs={} typed_polls={} observer_closed=1 "
    + SUCCESSOR_SUFFIX
)


def load_irq_verifier():
    spec = importlib.util.spec_from_file_location(
        "vibeos_c84_finish_verify_irq_verifier", IRQ_VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the managed-child IRQ predecessor verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


IRQ = load_irq_verifier()
PHASE = IRQ.PHASE
CORE = IRQ.CORE


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def semantic(value: str) -> str:
    return CORE.semantic(value)


def masked(value: str) -> str:
    return CORE.rust_mask(value)


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


def cfg_guarded_finish_without_trusted(source: str, offset: int, label: str) -> None:
    attributes = semantic(CORE.adjacent_outer_attributes(source, offset))
    expected = semantic(
        f'#[cfg(all(feature = "{FEATURE}", '
        f'not(feature = "{TRUSTED_SAMPLE_FEATURE}")))]'
    )
    require(
        attributes == expected,
        f"{label} is not guarded by exact finish/verify minus trusted-sample",
    )


def ordered(value: str, needles: tuple[str, ...], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), value)]
        require(len(matches) == 1, f"{label}: {needle!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


@dataclass(frozen=True)
class Inputs:
    predecessor: IRQ.Inputs
    target: str
    slot: str
    ssh: str
    sshd: str
    kernel_root: str
    kernel_manifest: bytes
    qemu_manifest: bytes
    milkv_manifest: bytes


def load_inputs() -> Inputs:
    predecessor = IRQ.load_inputs()
    return Inputs(
        predecessor=predecessor,
        target=TARGET_SOURCE.read_text(encoding="utf-8"),
        slot=SLOT_SOURCE.read_text(encoding="utf-8"),
        ssh=SSH_SOURCE.read_text(encoding="utf-8"),
        sshd=SSHD_SOURCE.read_text(encoding="utf-8"),
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
        kernel.get(FEATURE) == [IRQ_FEATURE],
        "finish/verify base is not the exact IRQ-overlay successor",
    )
    require(
        kernel.get(QEMU_FEATURE) == [FEATURE, IRQ_QEMU_FEATURE],
        "kernel finish/verify QEMU feature closure differs",
    )
    require(
        qemu.get(QEMU_FEATURE)
        == [IRQ_QEMU_FEATURE, f"vibeos-kernel/{QEMU_FEATURE}"],
        "QEMU firmware does not compose the exact IRQ predecessor and finish successor",
    )
    require(
        milkv.get(FEATURE) == [f"vibeos-kernel/{FEATURE}"],
        "Milk-V does not expose only the silent finish/verify base seam",
    )
    require(QEMU_FEATURE not in milkv, "Milk-V exposes the QEMU finish/verify gate")
    require(
        kernel.get(TRUSTED_SAMPLE_FEATURE)
        == [FEATURE, "vibeos-sshd/c84-profile-trusted-sample"],
        "trusted-sample base is not the exact finish/verify successor",
    )
    require(
        kernel.get(TRUSTED_SAMPLE_QEMU_FEATURE)
        == [TRUSTED_SAMPLE_FEATURE, QEMU_FEATURE],
        "kernel trusted-sample QEMU closure differs",
    )
    require(
        qemu.get(TRUSTED_SAMPLE_QEMU_FEATURE)
        == [QEMU_FEATURE, f"vibeos-kernel/{TRUSTED_SAMPLE_QEMU_FEATURE}"],
        "QEMU firmware does not compose the exact finish predecessor and trusted successor",
    )
    require(
        milkv.get(TRUSTED_SAMPLE_FEATURE)
        == [f"vibeos-kernel/{TRUSTED_SAMPLE_FEATURE}"],
        "Milk-V does not expose only the silent trusted-sample base seam",
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
    require(IRQ_FEATURE in base_closure, "finish/verify base omits the IRQ predecessor")
    require(
        not any(name.endswith("-qemu-acceptance") for name in base_closure),
        "finish/verify base selects QEMU telemetry",
    )
    qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_FEATURE])
    require(
        FEATURE in qemu_closure and IRQ_QEMU_FEATURE in qemu_closure,
        "finish/verify QEMU closure omits its base or IRQ predecessor",
    )
    require(
        STANDALONE_IRQ_QEMU_FEATURE not in qemu_closure,
        "finish/verify composition selects the standalone IRQ worker",
    )
    trusted_closure = PHASE.local_feature_closure(kernel, [TRUSTED_SAMPLE_FEATURE])
    trusted_qemu_closure = PHASE.local_feature_closure(kernel, [TRUSTED_SAMPLE_QEMU_FEATURE])
    verified_closure = PHASE.local_feature_closure(kernel, [VERIFIED_STREAM_FEATURE])
    require(FEATURE in trusted_closure, "trusted-sample omits finish/verify")
    require(QEMU_FEATURE in trusted_qemu_closure, "trusted-sample QEMU omits finish/verify QEMU")
    require(
        VERIFIED_STREAM_FEATURE not in trusted_closure
        and TRUSTED_SAMPLE_FEATURE not in verified_closure,
        "trusted-sample and verified-stream are not sibling finish successors",
    )

    root = semantic(inputs.kernel_root)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root, "finish/verify acceptance lacks its QEMU-only guard")
    pairing = (
        f'#[cfg(all(feature="{FEATURE}",feature="{IRQ_QEMU_FEATURE}",'
        f'not(feature="{QEMU_FEATURE}")))]compile_error!('
        f'"feature`{FEATURE}`cannotreusethecancel-onlyIRQQEMUtranscript");'
    )
    require(pairing in root, "finish base can be paired with dishonest legacy IRQ telemetry")
    isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        f'feature="{STANDALONE_IRQ_QEMU_FEATURE}",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolation in root, "finish/verify QEMU isolation guard differs")
    mutually_exclusive = (
        f'#[cfg(all(feature="{TRUSTED_SAMPLE_FEATURE}",'
        f'feature="{VERIFIED_STREAM_FEATURE}"))]compile_error!('
        f'"features`{TRUSTED_SAMPLE_FEATURE}`and`{VERIFIED_STREAM_FEATURE}`'
        'aremutuallyexclusivefinish/verifysuccessors");'
    )
    require(
        mutually_exclusive in root,
        "trusted-sample and verified-stream lack their exact mutual-exclusion guard",
    )
    require(
        f'#[cfg(feature="{QEMU_FEATURE}")]exec::spawn' not in root,
        "finish/verify acceptance adds a standalone worker",
    )


def verify_direct_cfg(inputs: Inputs) -> None:
    ssh = CORE.without_direct_feature_units(inputs.ssh, VERIFIED_STREAM_FEATURE)
    ssh = CORE.without_direct_feature_units(ssh, VERIFIED_STREAM_QEMU_FEATURE)
    ssh = CORE.without_direct_feature_units(ssh, TRUSTED_SAMPLE_FEATURE)
    ssh = CORE.without_direct_feature_units(ssh, TRUSTED_SAMPLE_QEMU_FEATURE)
    kernel_root = CORE.without_direct_feature_units(
        inputs.kernel_root, VERIFIED_STREAM_FEATURE
    )
    kernel_root = CORE.without_direct_feature_units(
        kernel_root, VERIFIED_STREAM_QEMU_FEATURE
    )
    kernel_root = CORE.without_direct_feature_units(
        kernel_root, TRUSTED_SAMPLE_FEATURE
    )
    kernel_root = CORE.without_direct_feature_units(
        kernel_root, TRUSTED_SAMPLE_QEMU_FEATURE
    )
    sources = (
        ("SSH", ssh, 4, 7, 8, 12),
        # The fifth all-form QEMU reference is the trusted sibling's pairing
        # guard against reuse of this predecessor's discard transcript.
        ("kernel root", kernel_root, 0, 1, 0, 5),
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
            f"{label} direct finish/verify base-unit count differs",
        )
        require(
            len(IRQ.cfg_units_containing_features(source, (FEATURE,))) == base_all,
            f"{label} all-form finish/verify base-unit count differs",
        )
        require(
            len(IRQ.direct_feature_units(source, QEMU_FEATURE)) == qemu_direct,
            f"{label} direct finish/verify QEMU-unit count differs",
        )
        require(
            len(IRQ.cfg_units_containing_features(source, (QEMU_FEATURE,))) == qemu_all,
            f"{label} all-form finish/verify QEMU-unit count differs",
        )

    base_units = IRQ.direct_feature_units(ssh, FEATURE)
    base_code = masked("\n".join(base_units))
    for forbidden in (
        ".summary(",
        ".next_interval(",
        ".complete(",
        "mem::forget",
        "Box<",
        "Vec<",
        ".await",
        "publish_profile",
        "ProfilePublisher",
        "physical_evidence",
        "exec::spawn(",
    ):
        require(forbidden not in base_code, f"finish/verify base unit admits {forbidden}")
    qemu_code = masked("\n".join(IRQ.direct_feature_units(ssh, QEMU_FEATURE)))
    for forbidden in (
        ".finish(",
        ".discard(",
        "StreamLease",
        ".summary(",
        ".next_interval(",
        ".complete(",
        ".await",
        "publish_profile",
        "physical_evidence",
        "exec::spawn(",
    ):
        require(forbidden not in qemu_code, f"finish/verify telemetry unit admits {forbidden}")


def verify_target_typestate(source: str) -> None:
    active = find_scope(source, r"\bimpl<'a>\s+TargetActive<'a>", "TargetActive impl")
    finish = find_function(active, "finish", "TargetActive finish")
    finish_code = semantic(finish.raw)
    require(
        "Result<TargetFinished<'a>,TargetRejected<'a>>" in finish_code,
        "TargetActive finish does not produce the closed unverified typestate",
    )
    finished = find_scope(source, r"\bimpl<'a>\s+TargetFinished<'a>", "TargetFinished impl")
    verify = find_function(finished, "verify", "TargetFinished verify")
    verify_code = semantic(verify.raw)
    require(
        "Result<TargetVerified<'a>,TargetRejected<'a>>" in verify_code
        and "self.ledger.verify()" in verify_code
        and "Ok(ledger)=>Ok(TargetVerified{" in verify_code,
        "TargetFinished does not perform the independent verify transition",
    )
    require(verify_code.count(".verify()") == 1, "target verification count differs")


def verify_slot_typestate(source: str) -> None:
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    finish_active = find_scope(source, r"\bfn\s+finish_active\b", "slot finish_active")
    finish_code = semantic(finish_active.raw)
    ordered(
        finish_code,
        (
            "clear_active_epoch(token.epoch())",
            "kind:TransitKind::Finish",
            "sample.finish(token,context,tick)",
            "finished.verify()",
            "install_verified(owner,verified)",
        ),
        "target finish/verify/install",
    )
    require(finish_code.count("finished.verify()") == 1, "slot verify count differs")

    install = find_scope(source, r"\bfn\s+install_verified\b", "install verified")
    install_code = semantic(install.raw)
    require(
        "SlotState::Verified{sample,owner,cursor:0,}" in install_code,
        "verified slot is not installed at cursor zero",
    )

    run_impl = find_scope(source, r"\bimpl\s+RunLease\b", "RunLease impl")
    run_finish = find_function(run_impl, "finish", "RunLease finish")
    run_code = semantic(run_finish.raw)
    ordered(
        run_code,
        ("finish_active(self.token,self.detach)", "Ok(())=>", "Ok(StreamLease{"),
        "RunLease finish to StreamLease",
    )
    require(run_code.count("finish_active(") == 1, "RunLease finish count differs")

    discard = find_scope(source, r"\bfn\s+discard_stream\b", "discard stream")
    discard_code = semantic(discard.raw)
    ordered(
        discard_code,
        (
            "take_verified(token,detach,false)",
            "cause:RejectionCause::StreamAbandoned",
            "intervals_emitted:cursor",
            "sample.recycle()",
            "install_rejected(owner,TransitKind::Recycle,ready,report)",
        ),
        "verified stream abandonment",
    )
    for exact in (
        "facade_faults:FacadeFaults::NONE",
        "ledger_error:None",
        "slot_faults:SlotFaults::NONE",
    ):
        require(exact in discard_code, f"stream abandonment omits {exact}")

    stream_impl = find_scope(source, r"\bimpl\s+StreamLease\b", "StreamLease impl")
    explicit = find_function(stream_impl, "discard", "StreamLease discard")
    require(
        "discard_stream(self.token,self.detach)" in semantic(explicit.raw),
        "explicit StreamLease discard no longer uses discard_stream",
    )
    acknowledge = find_scope(
        source, r"\bpub\(crate\)\s+fn\s+acknowledge_rejection\b", "acknowledge rejection"
    )
    acknowledge_code = semantic(acknowledge.raw)
    ordered(
        acknowledge_code,
        (
            "letreport=match&*slot{",
            "letprevious=mem::replace(&mut*slot,SlotState::Uninitialized)",
            "*slot=SlotState::Ready(ready)",
            "Ok(report)",
        ),
        "rejection acknowledgement to Ready",
    )


def verify_sshd_boundary(source: str) -> None:
    source = CORE.without_direct_feature_units(source, SSHD_TRUSTED_SAMPLE_FEATURE)
    backend = find_scope(
        source,
        r"\btrait\s+SshExecProfileRunBackend\b",
        "SSHD run backend trait",
    )
    code = masked(backend.raw)
    for forbidden in ("StreamLease", "TargetFinished", "TargetVerified", "fn finish"):
        require(forbidden not in code, f"SSHD public boundary exposes {forbidden}")
    require(
        semantic(backend.raw).count("fnresponse_boundary(") == 1,
        "SSHD response boundary count differs",
    )


def verify_ssh(source: str) -> None:
    trusted_owner = find_scope(
        source, r"\bimpl\s+SshExecProfileOwner\b", "trusted SSH profile owner"
    )
    trusted_response = find_function(
        trusted_owner, "response_boundary", "trusted SSH response boundary"
    )
    trusted_response_code = semantic(trusted_response.raw)
    trusted_prerequisite = (
        f'#[cfg(feature="{TRUSTED_SAMPLE_FEATURE}")]'
        "lettrusted_terminal_prerequisite=terminal_seal.component_terminal()=="
        "vibeos_vsh::ComponentTerminal::Success&&!terminal_seal.timed_out();"
    )
    require(
        trusted_prerequisite in trusted_response_code,
        "trusted sibling does not preserve exact Success plus no-timeout prerequisite",
    )
    source = CORE.without_direct_feature_units(source, VERIFIED_STREAM_FEATURE)
    source = CORE.without_direct_feature_units(source, VERIFIED_STREAM_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    owner = find_scope(source, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner")
    response = find_function(owner, "response_boundary", "SSH response boundary")
    cancel = find_function(owner, "cancel", "SSH active Drop")
    response_code = semantic(response.raw)
    cancel_code = semantic(cancel.raw)
    require(
        response_code.count("finish_verify_discard_and_ack_profile(run)") == 1,
        "normal successor does not call the finish/verify helper exactly once",
    )
    require(
        f'#[cfg(feature="{FEATURE}")]'
        f'#[cfg(not(any(feature="{VERIFIED_STREAM_FEATURE}",'
        f'feature="{TRUSTED_SAMPLE_FEATURE}")))]'
        "letterminal=finish_verify_discard_and_ack_profile(run)"
        ".map(|ready_epoch|(ready_epoch,()));"
        in response_code,
        "normal finish terminal is not directly feature-selected",
    )
    require(
        f'#[cfg(not(feature="{FEATURE}"))]letterminal=cancel_and_ack_profile('
        in response_code,
        "legacy cancel terminal is not the exact complement of finish/verify",
    )
    prerequisite = (
        f'#[cfg(not(feature="{TRUSTED_SAMPLE_FEATURE}"))]'
        "lettrusted_terminal_prerequisite=true;"
        f'#[cfg(feature="{FEATURE}")]'
        "ifstatus!=0||!trusted_terminal_prerequisite||!child_ready||"
        "!profile_policy_is_current(self.policy){"
        "letrecycled=cancel_and_ack_profile(run,"
        "crate::wasm_aot_profile_slot::SlotFaults::default());"
    )
    require(
        prerequisite in response_code and "returnErr(());" in response_code,
        "finish successor does not cancel/ack and fail a nonzero, unready, or stale response",
    )
    require(
        response_code.index(prerequisite)
        < response_code.index("finish_verify_discard_and_ack_profile(run)"),
        "finish runs before the response prerequisites are closed",
    )
    ordered(
        response_code,
        (
            "managed_phase_response_ready(epoch)",
            "managed_phase_observation(epoch)",
            "finish_verify_discard_and_ack_profile(run)",
            "managed_irq_acceptance_terminal_gate(epoch,ready_epoch,)",
            "profile_phase_response(",
            f'"{CORE.semantic(CORE_SUCCESSOR_MARKER)}"',
            "profile_request_response(epoch,status,ready_epoch);",
            "managed_irq_response(epoch,status,ready_epoch,irq_observation);",
            "finish_verify_response(epoch,status,ready_epoch);",
        ),
        "finish/verify response terminal chain",
    )
    for forbidden in (
        "finish_verify_discard_and_ack_profile",
        "StreamLease",
        ".finish(",
        ".discard(",
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
        ),
        "finish/verify Drop terminal chain",
    )

    finish_helper = find_scope(
        source,
        r"\bfn\s+finish_verify_discard_and_ack_profile\b",
        "finish/verify/discard helper",
    )
    cfg_guarded_finish_without_trusted(
        source, finish_helper.start, "finish/verify/discard helper"
    )
    helper_code = semantic(finish_helper.raw)
    ordered(
        helper_code,
        (
            "run.finish()",
            "SlotStatus::Verified{epoch:verified_epoch,cursor:0,..}",
            "stream.discard()",
            "report.cause==RejectionCause::StreamAbandoned",
            "report.intervals_emitted==0",
            "letready_epoch=acknowledge_finish_verify_rejection(epoch,report)?;",
        ),
        "finish/verify/discard/ack",
    )
    require(helper_code.count("run.finish()") == 1, "normal finish count differs")
    require(helper_code.count("stream.discard()") == 1, "explicit discard count differs")
    for exact in (
        "stream.token().epoch()==epoch",
        "report.facade_faults.is_empty()",
        "report.ledger_error.is_none()",
        "report.slot_faults==SlotFaults::default()",
    ):
        require(exact in helper_code, f"finish helper omits {exact}")
    for forbidden in (
        "run.cancel()",
        ".summary(",
        ".next_interval(",
        ".complete(",
        "drop(stream)",
        "mem::forget",
        "publish_profile",
        "physical_evidence",
        ".await",
    ):
        require(forbidden not in helper_code, f"finish helper admits {forbidden}")
    require(
        "Err(ProfileError::Rejected(report))=>{"
        "let_=acknowledge_finish_verify_rejection(epoch,report)?;returnErr(());}" in helper_code,
        "finish/verify rejection is not acknowledged back to Ready before failure",
    )

    ack = find_scope(
        source,
        r"\bfn\s+acknowledge_finish_verify_rejection\b",
        "finish/verify acknowledgement helper",
    )
    cfg_guarded(source, ack.start, "finish/verify acknowledgement helper", FEATURE)
    ack_code = semantic(ack.raw)
    ordered(
        ack_code,
        (
            "rejection()==Some(report)",
            "acknowledge_rejection(report.epoch)",
            "acknowledged==report",
            "letready_is_exact=crate::wasm_aot_profile_slot::status()==(SlotStatus::Ready{next_epoch:Some(ready_epoch),});",
        ),
        "stored rejection/ack/Ready",
    )
    require(
        ack_code.count("acknowledge_rejection(") == 1,
        "finish rejection acknowledgement count differs",
    )
    require(
        "report.epoch!=expected_epoch" in ack_code,
        "finish acknowledgement does not bind the expected epoch",
    )

    finish_response = find_scope(
        source, r"\bfn\s+finish_verify_response\b", "finish/verify response telemetry"
    )
    finish_drop = find_scope(
        source, r"\bfn\s+finish_verify_drop\b", "finish/verify Drop telemetry"
    )
    for label, scope in (("response", finish_response), ("Drop", finish_drop)):
        cfg_guarded(source, scope.start, f"finish/verify {label} telemetry", QEMU_FEATURE)
        code = masked(scope.raw)
        for forbidden in (
            ".finish(",
            ".discard(",
            "StreamLease",
            ".summary(",
            ".next_interval(",
            ".complete(",
            "publish",
            ".await",
        ):
            require(forbidden not in code, f"finish/verify {label} telemetry admits {forbidden}")
    require(source.count(NORMAL_MARKER) == 1, "finish/verify RESPONSE marker count differs")
    require(source.count(DROP_MARKER) == 1, "finish/verify DROP marker count differs")

    successor_literals = (
        f"{REQUEST_FAMILY} RESPONSE epoch={{}} status={{}} {SUCCESSOR_SUFFIX}",
        f"{IRQ_FAMILY} RESPONSE epoch={{}} status={{}} parent_pair={{}} child_pair={{}} "
        "terminal_inactive=1 paired={} inactive={} active_epoch={} " + SUCCESSOR_SUFFIX,
        f"{PHASE_FAMILY} RESPONSE epoch={{}} status={{}} child_core_starts={{}}",
        f"{CORE_FAMILY} RESPONSE epoch={{}} status={{}} claim=1 release=1",
    )
    for literal in successor_literals:
        require(literal in source, f"successor predecessor terminal literal missing: {literal}")
    require(
        source.count("finish=1 verify=1 discard=stream_abandoned ack=1 ready_epoch={}")
        >= 4,
        "not all four predecessor RESPONSE families expose the finish terminal suffix",
    )

    integration = owner.raw + finish_helper.raw + ack.raw + finish_response.raw + finish_drop.raw
    integration_code = masked(integration)
    for forbidden in (
        "ProfilePublisher",
        "publish_profile",
        "schema",
        "collector",
        "physical_evidence",
        "exec::spawn(",
        "exec::spawn_pinned_on(",
    ):
        require(forbidden not in integration_code, f"finish integration admits {forbidden}")


def verify_finish(inputs: Inputs) -> None:
    verify_features(inputs)
    verify_direct_cfg(inputs)
    verify_target_typestate(inputs.target)
    verify_slot_typestate(inputs.slot)
    verify_sshd_boundary(inputs.sshd)
    verify_ssh(inputs.ssh)


def verify(inputs: Inputs, *, predecessor: bool = True) -> None:
    if predecessor:
        try:
            IRQ.verify(inputs.predecessor)
        except IRQ.VerificationError as error:
            raise VerificationError(f"predecessor verifier failed: {error}") from error
    verify_finish(inputs)


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
        verify_finish(mutated)
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
                f'{FEATURE} = [\n    "{IRQ_FEATURE}",\n]',
                f"{FEATURE} = []",
                "base predecessor",
            ),
        ),
        (
            "qemu-predecessor-removed",
            lambda data: mutate_manifest(
                data,
                "qemu_manifest",
                f'    "{IRQ_QEMU_FEATURE}",\n',
                "",
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
            "legacy-pairing-guard-removed",
            lambda data: mutate_text(
                data,
                "kernel_root",
                '    "feature `wasm-c84-ssh-managed-child-finish-verify` cannot reuse the cancel-only IRQ QEMU transcript"',
                '    "finish pairing disabled"',
                "pairing guard",
            ),
        ),
        (
            "normal-terminal-cancels",
            lambda data: mutate_text(
                data,
                "ssh",
                "let terminal =\n"
                "            finish_verify_discard_and_ack_profile(run)"
                ".map(|ready_epoch| (ready_epoch, ()));",
                "let terminal = cancel_and_ack_profile(\n"
                "            run, crate::wasm_aot_profile_slot::SlotFaults::default(),\n"
                "        ).map(|ready_epoch| (ready_epoch, ()));",
                "normal terminal",
            ),
        ),
        (
            "response-status-prerequisite-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "if status != 0\n"
                "            || !trusted_terminal_prerequisite\n"
                "            || !child_ready\n"
                "            || !profile_policy_is_current(self.policy)\n"
                "        {",
                "if !trusted_terminal_prerequisite\n"
                "            || !child_ready\n"
                "            || !profile_policy_is_current(self.policy)\n"
                "        {",
                "response status prerequisite",
            ),
        ),
        (
            "response-prerequisite-cancel-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "let recycled =\n                cancel_and_ack_profile(run, crate::wasm_aot_profile_slot::SlotFaults::default());",
                "let recycled = Ok(epoch + 1);",
                "response prerequisite cancel",
            ),
        ),
        (
            "finish-guard-widened",
            lambda data: mutate_text(
                data,
                "ssh",
                "#[cfg(all(\n"
                f'    feature = "{FEATURE}",\n'
                f'    not(feature = "{TRUSTED_SAMPLE_FEATURE}")\n'
                "))]\n"
                "fn finish_verify_discard_and_ack_profile",
                f'#[cfg(feature = "{FEATURE}")]\n'
                "fn finish_verify_discard_and_ack_profile",
                "finish helper guard",
            ),
        ),
        (
            "finish-cfg-bang",
            lambda data: mutate_text(
                data,
                "ssh",
                f'#[cfg(feature = "{FEATURE}")]\n'
                "        #[cfg(not(any(\n"
                f'            feature = "{VERIFIED_STREAM_FEATURE}",\n'
                f'            feature = "{TRUSTED_SAMPLE_FEATURE}"\n'
                "        )))]\n"
                "        let terminal =\n"
                "            finish_verify_discard_and_ack_profile(run)"
                ".map(|ready_epoch| (ready_epoch, ()));",
                f'let terminal = if cfg!(feature = "{FEATURE}") {{\n'
                "            finish_verify_discard_and_ack_profile(run)"
                ".map(|ready_epoch| (ready_epoch, ()))\n"
                "        } else { unreachable!() };",
                "finish cfg!",
            ),
        ),
        (
            "run-finish-replaced",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "let stream = match run.finish() {",
                "let stream = match run.cancel() {",
                "run finish",
            ),
        ),
        (
            "finish-rejection-ack-removed",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "let _ = acknowledge_finish_verify_rejection(epoch, report)?;\n            return Err(());",
                "let _ = report;\n            return Err(());",
                "finish rejection acknowledgement",
            ),
        ),
        (
            "implicit-stream-drop",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "let report = stream.discard().map_err(|_| ())?;",
                "drop(stream); return Err(());",
                "explicit stream discard",
            ),
        ),
        (
            "stream-complete",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "stream.discard()",
                "stream.complete()",
                "stream complete",
            ),
        ),
        (
            "summary-read",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "let report = stream.discard().map_err(|_| ())?;",
                "let _ = stream.summary(); let report = stream.discard().map_err(|_| ())?;",
                "summary read",
            ),
        ),
        (
            "wrong-abandonment-cause",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "report.cause == RejectionCause::StreamAbandoned",
                "report.cause == RejectionCause::LeaseCancelled",
                "abandonment cause",
            ),
        ),
        (
            "nonzero-emitted",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "report.slot_faults == SlotFaults::default()\n        && report.intervals_emitted == 0",
                "report.slot_faults == SlotFaults::default()\n        && report.intervals_emitted == 1",
                "zero emitted",
            ),
        ),
        (
            "verified-cursor-forged",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "cursor: 0,",
                "cursor: 1,",
                "verified cursor",
            ),
        ),
        (
            "stored-rejection-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "let stored_rejection_is_exact = rejection() == Some(report);\n    // Use the installed report's own epoch",
                "let stored_rejection_is_exact = true;\n    // Use the installed report's own epoch",
                "stored rejection",
            ),
        ),
        (
            "ack-removed",
            lambda data: mutate_text(
                data,
                "ssh",
                "let acknowledged = acknowledge_rejection(report.epoch).map_err(|_| ())?;",
                "let acknowledged = report;",
                "acknowledgement",
            ),
        ),
        (
            "ready-forged",
            lambda data: mutate_text(
                data,
                "ssh",
                "let ready_epoch = report.epoch.checked_add(1).ok_or(())?;\n    let ready_is_exact = crate::wasm_aot_profile_slot::status()",
                "let ready_epoch = report.epoch.checked_add(1).ok_or(())?;\n    let ready_is_exact = forged_status()",
                "Ready proof",
            ),
        ),
        (
            "drop-finishes",
            lambda data: mutate_text(
                data,
                "ssh",
                "match cancel_and_ack_profile(run, expected_faults) {",
                "let _ = run.finish(); match cancel_and_ack_profile(run, expected_faults) {",
                "Drop finish",
            ),
        ),
        (
            "response-marker-cursor",
            lambda data: mutate_text(
                data,
                "ssh",
                "finish=1 verify=1 cursor=0 discard=stream_abandoned emitted=0",
                "finish=1 verify=1 cursor=1 discard=stream_abandoned emitted=0",
                "response marker cursor",
            ),
        ),
        (
            "publisher-added",
            lambda data: mutate_function_text(
                data,
                "ssh",
                "finish_verify_discard_and_ack_profile",
                "let report = stream.discard().map_err(|_| ())?;",
                "publish_profile(&stream); let report = stream.discard().map_err(|_| ())?;",
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
            "PASS verify-c84-ssh-managed-child-finish-verify: exact target finish/independent "
            "verify, zero-cursor explicit StreamAbandoned discard, stored rejection/ack/Ready, "
            f"unchanged Drop and predecessor authority, and diagnostic isolation are closed{suffix}"
        )
        return 0
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        VerificationError,
    ) as error:
        print(f"FAIL verify-c84-ssh-managed-child-finish-verify: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
