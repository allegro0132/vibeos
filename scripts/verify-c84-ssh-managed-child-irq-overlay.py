#!/usr/bin/env python3
"""Verify the default-off C8.4 SSH managed-child IRQ-overlay composition."""

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
PHASE_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-phase-sidecar.py"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
TRAP_SOURCE = ROOT / "kernel/src/trap.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"

FEATURE = "wasm-c84-ssh-managed-child-irq-overlay"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
PHASE_FEATURE = "wasm-c84-ssh-managed-child-phase-sidecar"
PHASE_QEMU_FEATURE = f"{PHASE_FEATURE}-qemu-acceptance"
IRQ_FEATURE = "wasm-c84-profile-irq-overlay"
IRQ_QEMU_FEATURE = f"{IRQ_FEATURE}-qemu-acceptance"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_IRQ_OVERLAY"
FINISH_FEATURE = "wasm-c84-ssh-managed-child-finish-verify"
FINISH_QEMU_FEATURE = f"{FINISH_FEATURE}-qemu-acceptance"
VERIFIED_STREAM_FEATURE = "wasm-c84-ssh-managed-child-verified-stream"
VERIFIED_STREAM_QEMU_FEATURE = f"{VERIFIED_STREAM_FEATURE}-qemu-acceptance"
TRUSTED_SAMPLE_FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
TRUSTED_SAMPLE_QEMU_FEATURE = f"{TRUSTED_SAMPLE_FEATURE}-qemu-acceptance"


def load_phase_verifier():
    spec = importlib.util.spec_from_file_location(
        "vibeos_c84_managed_child_irq_phase_verifier", PHASE_VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the managed-child phase predecessor verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PHASE = load_phase_verifier()
CORE = PHASE.CORE


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def semantic(value: str) -> str:
    return PHASE.semantic(value)


def find_scope(source: str, header: str, label: str):
    try:
        return PHASE.find_scope(source, header, label)
    except PHASE.VerificationError as error:
        raise VerificationError(str(error)) from error


def find_function(scope, name: str, label: str):
    try:
        return PHASE.find_function(scope, name, label)
    except PHASE.VerificationError as error:
        raise VerificationError(str(error)) from error


def cfg_guarded(source: str, offset: int, label: str, feature: str = QEMU_FEATURE) -> None:
    try:
        PHASE.cfg_guarded(source, offset, label, feature=feature)
    except PHASE.VerificationError as error:
        raise VerificationError(str(error)) from error


def ordered(scope: str, needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), scope)]
        require(len(matches) == 1, f"{label}: {needle!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


def feature_assignment_pattern(feature: str) -> str:
    """Match a Rust cfg feature value in ordinary or raw-string syntax."""

    escaped = re.escape(feature)
    return rf'feature\s*=\s*(?:"{escaped}"|r\#*"{escaped}"\#*)'


def direct_feature_units(source: str, feature: str) -> list[str]:
    """Extract syntax units guarded by one direct, exact feature cfg."""

    masked = CORE.rust_mask(source, literals=False)
    assignment = feature_assignment_pattern(feature)
    attribute = re.compile(rf'#\s*\[\s*cfg\s*\(\s*{assignment}\s*\)\s*\]')

    def matching(opening: int, left: str, right: str) -> int:
        depth = 0
        for cursor in range(opening, len(masked)):
            if masked[cursor] == left:
                depth += 1
            elif masked[cursor] == right:
                depth -= 1
                if depth == 0:
                    return cursor + 1
        raise VerificationError(f"unbalanced {left}{right} after direct {feature} cfg")

    units: list[str] = []
    for match in attribute.finditer(masked):
        cursor = match.end()
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        require(cursor < len(masked), f"direct {feature} cfg has no syntax unit")

        while masked.startswith("#[", cursor):
            cursor = matching(cursor + 1, "[", "]")
            while cursor < len(masked) and masked[cursor].isspace():
                cursor += 1

        parens = brackets = braces = 0
        first_brace = -1
        end = -1
        index = cursor
        while index < len(masked):
            character = masked[index]
            if character == "(":
                parens += 1
            elif character == ")":
                parens -= 1
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets -= 1
            elif character == "{":
                if parens == 0 and brackets == 0 and braces == 0 and first_brace < 0:
                    first_brace = index
                braces += 1
            elif character == "}":
                braces -= 1
                if braces == 0 and first_brace >= 0 and parens == 0 and brackets == 0:
                    end = index + 1
                    probe = end
                    while probe < len(masked) and masked[probe].isspace():
                        probe += 1
                    if probe < len(masked) and masked[probe] == ";":
                        end = probe + 1
                    break
            elif character in ";," and parens == 0 and brackets == 0 and braces == 0:
                end = index + 1
                break
            require(
                parens >= 0 and brackets >= 0 and braces >= 0,
                f"unbalanced syntax unit after direct {feature} cfg",
            )
            index += 1
        require(end >= 0, f"direct {feature} cfg syntax unit is unterminated")
        units.append(source[match.start() : end])
    return units


def cfg_units_containing_features(source: str, features: tuple[str, ...]) -> list[str]:
    """Extract every cfg syntax unit whose expression names either feature."""

    masked = CORE.rust_mask(source, literals=False)
    cfg_start = re.compile(r"#\s*\[\s*cfg\s*\(")

    def matching(opening: int, left: str, right: str) -> int:
        depth = 0
        for cursor in range(opening, len(masked)):
            if masked[cursor] == left:
                depth += 1
            elif masked[cursor] == right:
                depth -= 1
                if depth == 0:
                    return cursor + 1
        raise VerificationError(f"unbalanced {left}{right} in feature cfg")

    units: list[str] = []
    for match in cfg_start.finditer(masked):
        opening = masked.find("(", match.start(), match.end())
        require(opening >= 0, "cfg attribute has no opening parenthesis")
        expression_end = matching(opening, "(", ")")
        bracket = expression_end
        while bracket < len(masked) and masked[bracket].isspace():
            bracket += 1
        require(bracket < len(masked) and masked[bracket] == "]", "cfg attribute has no closing bracket")
        attribute_end = bracket + 1
        attribute = source[match.start() : attribute_end]
        if not any(re.search(feature_assignment_pattern(feature), attribute) for feature in features):
            continue

        cursor = attribute_end
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        require(cursor < len(masked), "selected feature cfg has no syntax unit")
        while masked.startswith("#[", cursor):
            cursor = matching(cursor + 1, "[", "]")
            while cursor < len(masked) and masked[cursor].isspace():
                cursor += 1

        parens = brackets = braces = 0
        first_brace = -1
        end = -1
        index = cursor
        while index < len(masked):
            character = masked[index]
            if character == "(":
                parens += 1
            elif character == ")":
                parens -= 1
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets -= 1
            elif character == "{":
                if parens == 0 and brackets == 0 and braces == 0 and first_brace < 0:
                    first_brace = index
                braces += 1
            elif character == "}":
                braces -= 1
                if braces == 0 and first_brace >= 0 and parens == 0 and brackets == 0:
                    end = index + 1
                    probe = end
                    while probe < len(masked) and masked[probe].isspace():
                        probe += 1
                    if probe < len(masked) and masked[probe] == ";":
                        end = probe + 1
                    break
            elif character in ";," and parens == 0 and brackets == 0 and braces == 0:
                end = index + 1
                break
            require(
                parens >= 0 and brackets >= 0 and braces >= 0,
                "unbalanced syntax unit after selected feature cfg",
            )
            index += 1
        require(end >= 0, "selected feature cfg syntax unit is unterminated")
        units.append(source[match.start() : end])
    return units


@dataclass(frozen=True)
class Inputs:
    phase: PHASE.Inputs
    trap: str


def load_inputs() -> Inputs:
    return Inputs(phase=PHASE.load_inputs(), trap=TRAP_SOURCE.read_text(encoding="utf-8"))


def verify_features(inputs: Inputs) -> None:
    kernel = PHASE.parse_features(inputs.phase.kernel_manifest, "kernel")
    qemu = PHASE.parse_features(inputs.phase.qemu_manifest, "QEMU firmware")
    milkv = PHASE.parse_features(inputs.phase.milkv_manifest, "Milk-V firmware")

    require(
        kernel.get(FEATURE) == [PHASE_FEATURE, IRQ_FEATURE],
        "kernel managed-child IRQ base closure differs",
    )
    require(
        kernel.get(QEMU_FEATURE) == [FEATURE, PHASE_QEMU_FEATURE],
        "kernel managed-child IRQ QEMU closure differs",
    )
    require(
        qemu.get(QEMU_FEATURE)
        == [PHASE_QEMU_FEATURE, f"vibeos-kernel/{QEMU_FEATURE}"],
        "QEMU firmware does not compose the exact phase predecessor and IRQ successor",
    )
    require(
        milkv.get(FEATURE) == [f"vibeos-kernel/{FEATURE}"],
        "Milk-V does not expose only the reusable managed-child IRQ base seam",
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
    require(
        f"vibeos-kernel/{QEMU_FEATURE}"
        not in PHASE.feature_member_closure(qemu, qemu.get("default", [])),
        "QEMU firmware default enables the IRQ acceptance directly",
    )
    require(
        f"vibeos-kernel/{FEATURE}"
        not in PHASE.feature_member_closure(milkv, milkv.get("default", [])),
        "Milk-V default enables the IRQ composition directly",
    )

    base_closure = PHASE.local_feature_closure(kernel, [FEATURE])
    require(
        PHASE_FEATURE in base_closure and IRQ_FEATURE in base_closure,
        "managed-child IRQ base omits its phase or production IRQ predecessor",
    )
    require(
        not any(name.endswith("-qemu-acceptance") for name in base_closure),
        "managed-child IRQ base enables acceptance-only telemetry",
    )
    qemu_closure = PHASE.local_feature_closure(kernel, [QEMU_FEATURE])
    require(PHASE_QEMU_FEATURE in qemu_closure, "IRQ QEMU feature omits the phase QEMU predecessor")
    require(IRQ_QEMU_FEATURE not in qemu_closure, "IRQ composition selects the standalone IRQ worker")
    trusted_closure = PHASE.local_feature_closure(kernel, [TRUSTED_SAMPLE_FEATURE])
    trusted_qemu_closure = PHASE.local_feature_closure(kernel, [TRUSTED_SAMPLE_QEMU_FEATURE])
    require(FEATURE in trusted_closure, "trusted-sample omits the managed-child IRQ predecessor")
    require(
        QEMU_FEATURE in trusted_qemu_closure,
        "trusted-sample QEMU omits the managed-child IRQ QEMU predecessor",
    )

    root = semantic(inputs.phase.kernel_root)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root, "managed-child IRQ acceptance lacks its QEMU-only guard")
    isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        f'feature="{IRQ_QEMU_FEATURE}",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolation in root, "managed-child IRQ acceptance isolation guard differs")
    compatibility = (
        f'#[cfg(all(feature="{IRQ_FEATURE}",not(feature="{QEMU_FEATURE}"),any('
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-ssh-request-parent-qemu-acceptance")))]'
        'compile_error!("C8.4IRQoverlaycannotmodifyanexact-transcriptQEMUacceptanceimage");'
    )
    require(compatibility in root, "IRQ/exact-transcript exception is not narrowed to this successor")
    require(
        f'#[cfg(feature="{QEMU_FEATURE}")]exec::spawn' not in root
        and "wasm-c84-ssh-managed-child-irq-overlay-acceptance" not in inputs.phase.kernel_root,
        "managed-child IRQ acceptance adds a standalone worker",
    )


def verify_direct_acceptance_units(inputs: Inputs) -> None:
    sources = (
        ("slot", inputs.phase.slot, 11, 16),
        ("SSH", inputs.phase.ssh, 7, 8),
        # The fourth and fifth all-form references are the finish/verify
        # successor's fail-closed pairing guard and the disjoint formal-QEMU
        # image guard; neither may reuse this gate's legacy cancel telemetry.
        ("kernel root", inputs.phase.kernel_root, 0, 5),
        ("trap", inputs.trap, 0, 2),
    )
    all_units: list[str] = []
    selected_units: list[str] = []
    for label, source, expected_direct, expected_selected in sources:
        masked = CORE.rust_mask(source, literals=False)
        for feature in (FEATURE, QEMU_FEATURE):
            feature_assignment = feature_assignment_pattern(feature)
            require(
                re.search(rf"\bcfg\s*!\s*\([^;{{}}]*{feature_assignment}", masked) is None,
                f"{label} selects {feature} through unsupported cfg! syntax",
            )
            require(
                re.search(rf"#\s*\[\s*cfg_attr\s*\([^\]]*{feature_assignment}", masked) is None,
                f"{label} selects {feature} through unsupported cfg_attr syntax",
            )
        units = direct_feature_units(source, QEMU_FEATURE)
        require(
            len(units) == expected_direct,
            f"{label} direct managed-child IRQ acceptance unit count differs: {len(units)}",
        )
        all_units.extend(units)
        base_units = cfg_units_containing_features(source, (FEATURE,))
        require(
            not base_units,
            f"{label} adds a Rust unit directly gated by the silent composition base",
        )
        selected = cfg_units_containing_features(source, (QEMU_FEATURE,))
        require(
            len(selected) == expected_selected,
            f"{label} all-form managed-child IRQ acceptance unit count differs: {len(selected)}",
        )
        selected_units.extend(selected)
    code = CORE.rust_mask("\n".join([*all_units, *selected_units]))
    for forbidden in (
        ".finish(",
        "StreamLease",
        "stream_verified",
        "publish_profile",
        "physical_evidence",
        "ProfilePublisher",
        "exec::spawn(",
        "exec::spawn_pinned_on(",
        ".await",
    ):
        require(forbidden not in code, f"direct IRQ acceptance unit admits forbidden {forbidden}")


def verify_production_irq(source: str) -> None:
    masked = CORE.rust_mask(source)
    active_matches = list(re.finditer(r"\bstatic\s+ACTIVE_EPOCH\s*:\s*AtomicU64\s*=", masked))
    require(len(active_matches) == 1, f"ACTIVE_EPOCH static count differs: {len(active_matches)}")
    cfg_guarded(source, active_matches[0].start(), "ACTIVE_EPOCH", IRQ_FEATURE)
    require(
        "staticACTIVE_EPOCH:AtomicU64=AtomicU64::new(0);" in semantic(source),
        "ACTIVE_EPOCH is not a zero-initialized atomic",
    )

    poison = find_scope(source, r"\bfn\s+poison\b", "slot poison")
    require(
        'ACTIVE_EPOCH.store(0,Ordering::Release);' in semantic(poison.raw),
        "slot poison does not fail-close the active IRQ gate",
    )
    publish = find_scope(source, r"\bfn\s+publish_active_epoch\b", "active epoch publish")
    clear = find_scope(source, r"\bfn\s+clear_active_epoch\b", "active epoch clear")
    cfg_guarded(source, publish.start, "active epoch publish", IRQ_FEATURE)
    cfg_guarded(source, clear.start, "active epoch clear", IRQ_FEATURE)
    publish_code = semantic(publish.raw)
    clear_code = semantic(clear.raw)
    for exact in (
        "ifepoch==0",
        ".compare_exchange(0,epoch,Ordering::Release,Ordering::Acquire)",
        "poison(SlotPoison::IrqStateMismatch);",
    ):
        require(exact in publish_code, f"active epoch publish omits {exact}")
    for exact in (
        "ifepoch==0",
        ".compare_exchange(epoch,0,Ordering::AcqRel,Ordering::Acquire)",
        "poison(SlotPoison::IrqStateMismatch);",
    ):
        require(exact in clear_code, f"active epoch clear omits {exact}")

    start = find_scope(source, r"\bfn\s+start_reserved\b", "slot Active installation")
    start_code = semantic(start.raw)
    ordered(
        start_code,
        [
            "lettoken=sample.token();",
            "publish_active_epoch(token.epoch())",
            "*slot=SlotState::Active",
        ],
        "active epoch publication",
    )
    for name, kind in (("finish_active", "Finish"), ("cancel_active", "Cancel")):
        terminal = find_scope(source, rf"\bfn\s+{name}\b", f"slot {kind} transition")
        terminal_code = semantic(terminal.raw)
        ordered(
            terminal_code,
            [
                "clear_active_epoch(token.epoch())",
                f"kind:TransitKind::{kind}",
            ],
            f"{kind} active epoch clear",
        )

    enter = find_scope(source, r"\bpub\(crate\)\s+fn\s+profile_irq_enter\b", "IRQ entry")
    exit_scope = find_scope(source, r"\bpub\(crate\)\s+fn\s+profile_irq_exit\b", "IRQ exit")
    cfg_guarded(source, enter.start, "IRQ entry", IRQ_FEATURE)
    cfg_guarded(source, exit_scope.start, "IRQ exit", IRQ_FEATURE)
    enter_code = semantic(enter.raw)
    exit_code = semantic(exit_scope.raw)
    ordered(
        enter_code,
        [
            "letepoch=ACTIVE_EPOCH.load(Ordering::Acquire);",
            "ifepoch==0",
            "letmutslot=SLOT.lock();",
            "letSlotState::Active",
            "iftoken.epoch()!=epoch",
            "if!owner.detach.is_current_irq_scope_exact()",
            "if!faults.is_empty()",
            "sample.interrupt_enter(token,context,irq_entry)",
        ],
        "IRQ entry exact owner/cookie",
    )
    require(
        "child.as_ref().is_some_and(|child|child.current_irq_owner())" in enter_code,
        "IRQ entry omits the exact delegated child owner",
    )
    ordered(
        exit_code,
        [
            "ifcookie.epoch==0",
            "ACTIVE_EPOCH.load(Ordering::Acquire)!=cookie.epoch",
            "letmutslot=SLOT.lock();",
            "letSlotState::Active",
            "iftoken.epoch()!=cookie.epoch",
            "if!owner.detach.is_current_irq_scope_exact()",
            "letapplied=cookie.inner.is_active();",
            "sample.interrupt_exit(cookie.inner,context,exit_tick);",
        ],
        "IRQ exit exact owner/cookie",
    )
    require(
        "child.as_ref().is_some_and(|child|child.current_irq_owner())" in exit_code,
        "IRQ exit omits the exact delegated child owner",
    )
    for label, scope in (("IRQ entry", enter), ("IRQ exit", exit_scope)):
        code = CORE.rust_mask(scope.raw)
        require("println!" not in scope.raw and ".await" not in code, f"{label} admits UART or await")


def verify_trap(source: str) -> None:
    handler = find_scope(source, r"\bfn\s+__trap_handler\b", "trap handler")
    code = semantic(handler.raw)
    ssip = find_scope(handler.raw, r"\bif\s+code\s*==\s*1", "SSIP early-return branch")
    ssip_code = semantic(ssip.raw)
    ordered(
        ssip_code,
        [
            "ipi::acknowledge_current();",
            "letapplied=crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq,sbi::time());",
            "profile_irq_acceptance_note_ssip(applied);",
            "let_=crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq,sbi::time());",
            "IN_INTERRUPT[hart].store(false,Ordering::Release);",
            "return;",
        ],
        "SSIP acknowledge/exit/accounting",
    )
    acceptance_cfg = (
        f'#[cfg(any(feature="{IRQ_QEMU_FEATURE}",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance",'
        f'feature="{QEMU_FEATURE}"))]'
    )
    production_cfg = (
        f'#[cfg(all(feature="{IRQ_FEATURE}",not(any(feature="{IRQ_QEMU_FEATURE}",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance",'
        f'feature="{QEMU_FEATURE}"))))]'
    )
    require(acceptance_cfg in ssip_code, "SSIP acceptance branch omits the combined IRQ feature")
    require(production_cfg in ssip_code, "production SSIP branch does not exclude every acceptance counter")
    require(ssip_code.count("profile_irq_acceptance_note_ssip(applied);") == 1, "SSIP accounting count differs")
    require(code.count("profile_irq_exit(profile_irq,sbi::time());") == 3, "trap IRQ exit path count differs")
    require("println!" not in ssip.raw and ".await" not in ssip_code, "SSIP branch admits UART or await")


def verify_force_ssip(source: str):
    force = find_scope(source, r"\bfn\s+force_boot_self_ssip\b", "forced boot self-SSIP")
    force_code = semantic(force.raw)
    attributes = semantic(CORE.adjacent_outer_attributes(source, force.start))
    require(
        attributes.startswith("#[cfg(any(")
        and f'feature="{IRQ_QEMU_FEATURE}"' in attributes
        and 'feature="wasm-c84-profile-child-delegation-qemu-acceptance"' in attributes
        and f'feature="{QEMU_FEATURE}"' in attributes,
        "forced SSIP helper omits one exact acceptance feature",
    )
    ordered(
        force_code,
        [
            "letbefore=crate::ipi::stats(hart);",
            "letpaired_before=ACCEPTANCE_SSIP_PAIRED.load(Ordering::Acquire);",
            "letinactive_before=ACCEPTANCE_SSIP_INACTIVE.load(Ordering::Acquire);",
            "crate::ipi::publish_runnable(hart)!=DoorbellDisposition::Local",
            "crate::ipi::retry_pending(hart)!=DoorbellDisposition::Sent",
            "observed.acknowledged.wrapping_sub(before.acknowledged)==1",
            "observed.pending_reasons==0",
            "after.notifications.wrapping_sub(before.notifications)<1",
            "after.doorbells.wrapping_sub(before.doorbells)!=1",
            "letpaired_delta=ACCEPTANCE_SSIP_PAIRED",
            "letinactive_delta=ACCEPTANCE_SSIP_INACTIVE",
        ],
        "forced boot self-SSIP causal proof",
    )
    for exact in (
        "after.send_failures!=before.send_failures",
        "after.idle_consumed!=before.idle_consumed",
        "after.stale!=before.stale",
        "expect_profiled&&(paired_delta!=1||inactive_delta!=0)",
        "!expect_profiled&&(paired_delta!=0||inactive_delta!=1)",
    ):
        require(exact in force_code, f"forced self-SSIP proof omits {exact}")
    require("SLOT.lock" not in force.raw and "println!" not in force.raw and ".await" not in force_code, "forced SSIP helper holds SLOT, prints, or awaits")
    return force


def verify_acceptance_slot(source: str) -> None:
    verify_force_ssip(source)

    note = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+profile_irq_acceptance_note_ssip\b",
        "SSIP acceptance attribution",
    )
    note_code = semantic(note.raw)
    require(
        "ifapplied{ACCEPTANCE_SSIP_PAIRED.fetch_add(1,Ordering::Relaxed);}" in note_code
        and "else{ACCEPTANCE_SSIP_INACTIVE.fetch_add(1,Ordering::Relaxed);}" in note_code,
        "SSIP acceptance attribution does not increment exactly one causal counter",
    )
    note_attributes = semantic(CORE.adjacent_outer_attributes(source, note.start))
    require(
        note_attributes.startswith("#[cfg(any(") and f'feature="{QEMU_FEATURE}"' in note_attributes,
        "SSIP acceptance attribution omits the combined QEMU cfg",
    )

    observation = find_scope(source, r"\bpub\(crate\)\s+struct\s+ManagedIrqObservation\b", "managed IRQ observation")
    cfg_guarded(source, observation.start, "managed IRQ observation")
    observation_code = semantic(observation.raw)
    for field in ("paired:u64", "inactive:u64", "active_epoch:u64"):
        require(field in observation_code, f"managed IRQ observation omits {field}")
    for forbidden in ("Vec<", "Box<", "String", "StreamLease", "SampleToken", "RunLease"):
        require(forbidden not in observation.raw, f"managed IRQ observation admits {forbidden}")
    observe = find_scope(
        source,
        r"\bfn\s+managed_irq_acceptance_observation\b",
        "managed IRQ observation snapshot",
    )
    cfg_guarded(source, observe.start, "managed IRQ observation snapshot")
    observe_code = semantic(observe.raw)
    for exact in (
        "paired:ACCEPTANCE_SSIP_PAIRED.load(Ordering::Acquire)",
        "inactive:ACCEPTANCE_SSIP_INACTIVE.load(Ordering::Acquire)",
        "active_epoch:ACTIVE_EPOCH.load(Ordering::Acquire)",
    ):
        require(exact in observe_code, f"managed IRQ observation snapshot omits {exact}")
    require("println!" not in observe.raw and "SLOT.lock" not in observe.raw, "IRQ observation snapshot prints or locks SLOT")

    statics = semantic(source)
    for name in ("ACCEPTANCE_SSIP_PAIRED", "ACCEPTANCE_SSIP_INACTIVE"):
        matches = list(re.finditer(rf"\bstatic\s+{name}\s*:\s*AtomicU64\s*=", CORE.rust_mask(source)))
        require(len(matches) == 1, f"{name} static count differs: {len(matches)}")
        attributes = semantic(CORE.adjacent_outer_attributes(source, matches[0].start()))
        require(
            attributes.startswith("#[cfg(any(") and f'feature="{QEMU_FEATURE}"' in attributes,
            f"{name} omits the combined QEMU acceptance cfg",
        )
        require(
            f"static{name}:AtomicU64=AtomicU64::new(0);" in statics,
            f"{name} is not uniquely zero-initialized",
        )
    require(
        "staticMANAGED_IRQ_ACCEPTANCE_STAGE:AtomicU8=AtomicU8::new(0);" in statics,
        "managed IRQ one-shot stage is not a zero-initialized AtomicU8",
    )
    require(
        "staticMANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH:AtomicU64=AtomicU64::new(1);" in statics,
        "managed IRQ terminal epoch atomic does not start at epoch 1",
    )

    parent = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_parent_host\b",
        "parent Host IRQ acceptance",
    )
    child = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_child_core_started\b",
        "child Core IRQ acceptance",
    )
    terminal = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_irq_acceptance_terminal_gate\b",
        "terminal IRQ acceptance",
    )
    for label, scope in (("parent", parent), ("child", child), ("terminal", terminal)):
        cfg_guarded(source, scope.start, f"{label} IRQ acceptance")
        code = semantic(scope.raw)
        require("println!" not in scope.raw and ".await" not in code, f"{label} IRQ helper prints or awaits")
        require("SLOT.lock" not in scope.raw and "SpinLock" not in scope.raw, f"{label} IRQ helper holds a slot/state lock across self-SSIP")

    parent_code = semantic(parent.raw)
    child_code = semantic(child.raw)
    terminal_code = semantic(terminal.raw)
    for code, label, expected_force in (
        (parent_code, "parent", "force_boot_self_ssip(true)?;"),
        (child_code, "child", "force_boot_self_ssip(true)?;"),
        (terminal_code, "terminal", "force_boot_self_ssip(false)?;"),
    ):
        require(code.count(expected_force) == 1, f"{label} IRQ helper force kind/count differs")
    require("ifepoch!=1" in parent_code and "Ok(None)" in parent_code, "parent helper does not isolate epochs 2-4")
    require("ifepoch!=1" in child_code and "Ok(None)" in child_code, "child helper does not isolate epochs 2-4")
    require(".compare_exchange(0,1," in parent_code, "parent helper lacks Idle -> ParentInFlight CAS")
    require(".compare_exchange(1,2," in parent_code, "parent helper lacks ParentInFlight -> ParentDone CAS")
    require(".compare_exchange(2,3," in child_code, "child helper lacks ParentDone -> ChildInFlight CAS")
    require(".compare_exchange(3,4," in child_code, "child helper lacks ChildInFlight -> ChildDone CAS")
    for code, label, paired in (
        (parent_code, "parent", 1),
        (child_code, "child", 2),
    ):
        expected = (
            "observation!=(ManagedIrqObservation{"
            f"paired:{paired},inactive:0,active_epoch:1,}})"
        )
        require(expected in code, f"{label} causal observation values differ")
    for exact in (
        "if!(1..=4).contains(&epoch)",
        "MANAGED_IRQ_ACCEPTANCE_STAGE.load(Ordering::Acquire)!=4",
        "ready_epoch!=epoch.checked_add(1).ok_or(ProfileError::StateMismatch)?",
        "SlotStatus::Ready{next_epoch:Some(ready_epoch),}",
        "before.paired!=2",
        "before.inactive!=epoch-1",
        "before.active_epoch!=0",
        "observation!=(ManagedIrqObservation{paired:2,inactive:epoch,active_epoch:0,})",
    ):
        require(exact in terminal_code, f"terminal inactive gate omits {exact}")
    require(
        ".compare_exchange(epoch,u64::MAX,Ordering::AcqRel,Ordering::Acquire)" in terminal_code
        and "MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH.store(ready_epoch,Ordering::Release);"
        in terminal_code,
        "terminal inactive gate does not claim and publish one ordered terminal epoch",
    )

    clock_struct = find_scope(
        source,
        r"\bpub\(crate\)\s+struct\s+ManagedChildSlotCorePollClock\b",
        "managed-child Core clock",
    )
    require(
        f'#[cfg(feature="{QEMU_FEATURE}")]pending_irq_observation:Option<ManagedIrqObservation>,'
        in semantic(clock_struct.raw),
        "managed-child clock lacks its directly acceptance-gated lexical IRQ observation",
    )
    clock_impl = find_scope(
        source,
        r"\bimpl\s+ProfileClock\s+for\s+ManagedChildSlotCorePollClock\b",
        "managed-child ProfileClock",
    )
    started = find_function(clock_impl, "core_poll_started", "managed-child Core start")
    finished = find_function(clock_impl, "core_poll_finished", "managed-child Core finish")
    started_code = semantic(started.raw)
    finished_code = semantic(finished.raw)
    ordered(
        started_code,
        [
            "begin_child_core_phase(self.token,self.detach)",
            "self.owns_open=error.is_none();",
            "self.latch(error);",
            "managed_irq_acceptance_child_core_started(self.token.epoch())",
            "self.pending_irq_observation=observation",
        ],
        "child causal SSIP after Core open",
    )
    require(
        started_code.endswith("live_tick()}"),
        "child Core start tick is not sampled after the injected self-SSIP",
    )
    require("println!" not in started.raw, "child start prints before Core closes")
    ordered(
        finished_code,
        [
            "letboundary=end_child_core_phase(self.token,self.detach);",
            "self.latch(boundary.error);",
            "self.pending_irq_observation.take()",
            f'"{FAMILY}CHILD_SSIPepoch={{}}causal=1',
            "boundary.tick",
        ],
        "child IRQ observation after Core close",
    )
    require(
        "letcore_closed=boundary.error.is_none();" in finished_code and "ifcore_closed" in finished_code,
        "child marker is not gated by a successful end_child_core_phase boundary",
    )
    clock_drop = find_scope(source, r"\bimpl\s+Drop\s+for\s+ManagedChildSlotCorePollClock\b", "managed-child clock Drop")
    require(FAMILY not in clock_drop.raw and "pending_irq_observation.take" not in clock_drop.raw, "clock Drop fabricates a child IRQ success marker")

    acceptance_integration = (
        observation.raw
        + observe.raw
        + note.raw
        + parent.raw
        + child.raw
        + terminal.raw
        + clock_struct.raw
        + started.raw
        + finished.raw
        + clock_drop.raw
    )
    acceptance_code = CORE.rust_mask(acceptance_integration)
    for forbidden in (
        ".finish(",
        "StreamLease",
        "stream_verified",
        "publish_profile",
        "physical_evidence",
        "ProfilePublisher",
        ".await",
    ):
        require(forbidden not in acceptance_code, f"slot IRQ acceptance admits forbidden {forbidden}")

    for marker in (
        f"{FAMILY} CHILD_SSIP epoch={{}} causal=1 paired={{}} inactive={{}} active_epoch={{}}",
    ):
        require(source.count(marker) == 1, f"slot IRQ marker count differs: {marker}")
    require(
        FAMILY not in CORE.without_direct_feature_units(source, QEMU_FEATURE),
        "slot IRQ telemetry is not directly acceptance-gated",
    )


def verify_ssh(source: str) -> None:
    source = CORE.without_direct_feature_units(source, FINISH_FEATURE)
    source = CORE.without_direct_feature_units(source, FINISH_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, VERIFIED_STREAM_FEATURE)
    source = CORE.without_direct_feature_units(source, VERIFIED_STREAM_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    backend = find_scope(
        source,
        r"\bimpl\s+SshExecProfileRunBackend\s+for\s+SshExecProfileOwner\b",
        "kernel SSH profile backend",
    )
    host = find_function(backend, "phase_host", "kernel SSH parent Host")
    host_code = semantic(host.raw)
    ordered(
        host_code,
        [
            "run.managed_parent_host()",
            "managed_irq_acceptance_parent_host(epoch)",
            f'"{FAMILY}PARENT_SSIPepoch={{}}causal=1',
        ],
        "parent Host causal self-SSIP",
    )
    require(
        CORE.rust_mask(host.raw).count("managed_irq_acceptance_parent_host(") == 1,
        "parent Host calls the IRQ acceptance helper anything other than once",
    )
    require("SLOT.lock" not in host.raw and ".await" not in host_code, "parent Host helper holds SLOT or awaits")

    owner = find_scope(source, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner")
    response = find_function(owner, "response_boundary", "SSH response boundary")
    cancel = find_function(owner, "cancel", "SSH active Drop")
    response_code = semantic(response.raw)
    cancel_code = semantic(cancel.raw)
    ordered(
        response_code,
        [
            "cancel_and_ack_profile(run,crate::wasm_aot_profile_slot::SlotFaults::default())",
            "managed_irq_acceptance_terminal_gate(epoch,ready_epoch,)",
            "profile_phase_response(",
            "profile_request_response(epoch,status,ready_epoch);",
            "managed_irq_response(epoch,status,ready_epoch,irq_observation);",
        ],
        "response cancel/terminal proof/UART",
    )
    ordered(
        cancel_code,
        [
            "cancel_and_ack_profile(run,expected_faults)",
            "managed_irq_acceptance_terminal_gate(epoch,ready_epoch,)",
            "profile_phase_drop(",
            "profile_request_drop(epoch,ready_epoch)",
            "managed_irq_drop(epoch,ready_epoch,irq_observation)",
        ],
        "Drop cancel/terminal proof/UART",
    )

    irq_response = find_scope(source, r"\bfn\s+managed_irq_response\b", "IRQ response telemetry")
    irq_drop = find_scope(source, r"\bfn\s+managed_irq_drop\b", "IRQ Drop telemetry")
    for label, scope in (("response", irq_response), ("Drop", irq_drop)):
        cfg_guarded(source, scope.start, f"IRQ {label} telemetry")
        code = semantic(scope.raw)
        for exact in (
            "observation.paired",
            "observation.inactive",
            "observation.active_epoch",
        ):
            require(exact in code, f"IRQ {label} telemetry omits {exact}")
    require(
        "letcausal_pair=u8::from(epoch==1);" in semantic(irq_response.raw),
        "IRQ response does not derive both active-pair bits only from epoch 1",
    )
    require("status" in semantic(irq_response.raw), "IRQ response telemetry does not bind status")
    for marker, count in (
        (f"{FAMILY} PARENT_SSIP epoch={{}} causal=1 paired={{}} inactive={{}} active_epoch={{}}", 1),
        (f"{FAMILY} RESPONSE epoch={{}} status={{}} parent_pair={{}} child_pair={{}} terminal_inactive=1 paired={{}} inactive={{}} active_epoch={{}} cancel=1 ack=1 ready_epoch={{}}", 1),
        (f"{FAMILY} DROP epoch={{}} parent_pair=0 child_pair=0 terminal_inactive=1 paired={{}} inactive={{}} active_epoch={{}} cancel=1 ack=1 ready_epoch={{}}", 1),
    ):
        require(source.count(marker) == count, f"SSH IRQ marker count differs: {marker}")
    require(
        FAMILY not in CORE.without_direct_feature_units(source, QEMU_FEATURE),
        "SSH IRQ telemetry is not directly acceptance-gated",
    )

    integration = host.raw + response.raw + cancel.raw + irq_response.raw + irq_drop.raw
    code = CORE.rust_mask(integration)
    for forbidden in (".finish(", "StreamLease", "publish_profile", "physical_evidence", ".await"):
        require(forbidden not in code, f"SSH IRQ composition admits forbidden {forbidden}")


def verify_incremental(inputs: Inputs) -> None:
    verify_features(inputs)
    verify_direct_acceptance_units(inputs)
    verify_production_irq(inputs.phase.slot)
    verify_trap(inputs.trap)
    verify_acceptance_slot(inputs.phase.slot)
    verify_ssh(inputs.phase.ssh)


def verify(inputs: Inputs, *, predecessor: bool = True) -> None:
    if predecessor:
        try:
            PHASE.verify(inputs.phase)
        except PHASE.VerificationError as error:
            raise VerificationError(f"predecessor verifier failed: {error}") from error
    verify_incremental(inputs)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest seed {label!r} count differs: {count}")
    return value.replace(old, new, 1)


def mutate_phase_text(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    return replace(data, phase=replace(data.phase, **{field: replace_once(getattr(data.phase, field), old, new, label)}))


def append_phase_text(data: Inputs, field: str, suffix: str) -> Inputs:
    return replace(data, phase=replace(data.phase, **{field: getattr(data.phase, field) + suffix}))


def mutate_trap(data: Inputs, old: str, new: str, label: str) -> Inputs:
    return replace(data, trap=replace_once(data.trap, old, new, label))


def mutate_manifest(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    raw = getattr(data.phase, field).decode("utf-8")
    phase = replace(data.phase, **{field: replace_once(raw, old, new, label).encode("utf-8")})
    return replace(data, phase=phase)


def expect_rejected(inputs: Inputs, mutation: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutation(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify_incremental(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def run_selftest(inputs: Inputs) -> int:
    verify(inputs)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "kernel-default-enables-base",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                'default = ["qemu-virt", "qemu-default-image"]',
                f'default = ["qemu-virt", "qemu-default-image", "{FEATURE}"]',
                "kernel-default-enables-base",
            ),
        ),
        (
            "base-selects-qemu-telemetry",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{FEATURE} = [\n    "{PHASE_FEATURE}",\n    "{IRQ_FEATURE}",\n]',
                f'{FEATURE} = [\n    "{PHASE_FEATURE}",\n    "{IRQ_FEATURE}",\n    "{QEMU_FEATURE}",\n]',
                "base-selects-qemu-telemetry",
            ),
        ),
        (
            "qemu-selects-standalone-irq-worker",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{QEMU_FEATURE} = [\n    "{FEATURE}",\n    "{PHASE_QEMU_FEATURE}",\n]',
                f'{QEMU_FEATURE} = [\n    "{FEATURE}",\n    "{PHASE_QEMU_FEATURE}",\n    "{IRQ_QEMU_FEATURE}",\n]',
                "qemu-selects-standalone-irq-worker",
            ),
        ),
        (
            "active-publish-relaxed",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "if epoch == 0\n        || ACTIVE_EPOCH\n"
                "            .compare_exchange(0, epoch, Ordering::Release, Ordering::Acquire)",
                "if epoch == 0\n        || ACTIVE_EPOCH\n"
                "            .compare_exchange(0, epoch, Ordering::Relaxed, Ordering::Acquire)",
                "active-publish-relaxed",
            ),
        ),
        (
            "active-clear-relaxed",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "if epoch == 0\n        || ACTIVE_EPOCH\n"
                "            .compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire)",
                "if epoch == 0\n        || ACTIVE_EPOCH\n"
                "            .compare_exchange(epoch, 0, Ordering::Relaxed, Ordering::Acquire)",
                "active-clear-relaxed",
            ),
        ),
        (
            "parent-active-force-removed",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)\n"
                "        .map_err(|_| ProfileError::StateMismatch)?;\n"
                "    force_boot_self_ssip(true)?;",
                "        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)\n"
                "        .map_err(|_| ProfileError::StateMismatch)?;\n"
                "    force_boot_self_ssip(false)?;",
                "parent-active-force-removed",
            ),
        ),
        (
            "terminal-inactive-force-active",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "        .compare_exchange(epoch, u64::MAX, Ordering::AcqRel, Ordering::Acquire)\n"
                "        .map_err(|_| ProfileError::StateMismatch)?;\n"
                "    force_boot_self_ssip(false)?;",
                "        .compare_exchange(epoch, u64::MAX, Ordering::AcqRel, Ordering::Acquire)\n"
                "        .map_err(|_| ProfileError::StateMismatch)?;\n"
                "    force_boot_self_ssip(true)?;",
                "terminal-inactive-force-active",
            ),
        ),
        (
            "child-cas-skips-parent",
            lambda data: mutate_phase_text(
                data,
                "slot",
                ".compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)",
                ".compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)",
                "child-cas-skips-parent",
            ),
        ),
        (
            "terminal-active-epoch-widened",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "before.active_epoch != 0",
                "before.active_epoch == u64::MAX",
                "terminal-active-epoch-widened",
            ),
        ),
        (
            "terminal-epoch-starts-zero",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "static MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH: AtomicU64 = AtomicU64::new(1);",
                "static MANAGED_IRQ_ACCEPTANCE_TERMINAL_EPOCH: AtomicU64 = AtomicU64::new(0);",
                "terminal-epoch-starts-zero",
            ),
        ),
        (
            "paired-counter-starts-one",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "static ACCEPTANCE_SSIP_PAIRED: AtomicU64 = AtomicU64::new(0);",
                "static ACCEPTANCE_SSIP_PAIRED: AtomicU64 = AtomicU64::new(1);",
                "paired-counter-starts-one",
            ),
        ),
        (
            "inactive-counter-starts-one",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "static ACCEPTANCE_SSIP_INACTIVE: AtomicU64 = AtomicU64::new(0);",
                "static ACCEPTANCE_SSIP_INACTIVE: AtomicU64 = AtomicU64::new(1);",
                "inactive-counter-starts-one",
            ),
        ),
        (
            "terminal-range-widened",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "if !(1..=4).contains(&epoch)",
                "if !(1..=5).contains(&epoch)",
                "terminal-range-widened",
            ),
        ),
        (
            "paired-attribution-swapped",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "ACCEPTANCE_SSIP_PAIRED.fetch_add(1, Ordering::Relaxed);",
                "ACCEPTANCE_SSIP_INACTIVE.fetch_add(1, Ordering::Relaxed);",
                "paired-attribution-swapped",
            ),
        ),
        (
            "active-observation-relaxed",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "active_epoch: ACTIVE_EPOCH.load(Ordering::Acquire),",
                "active_epoch: ACTIVE_EPOCH.load(Ordering::Relaxed),",
                "active-observation-relaxed",
            ),
        ),
        (
            "terminal-opens-finish-surface",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "    force_boot_self_ssip(false)?;\n"
                "    let observation = managed_irq_acceptance_observation();",
                "    force_boot_self_ssip(false)?;\n"
                "    let _ = run.finish();\n"
                "    let observation = managed_irq_acceptance_observation();",
                "terminal-opens-finish-surface",
            ),
        ),
        (
            "hidden-direct-slot-authority",
            lambda data: append_phase_text(
                data,
                "slot",
                f'\n#[cfg(feature = "{QEMU_FEATURE}")]\n'
                "fn hidden_irq_acceptance_surface() {\n"
                "    run.finish();\n"
                "    publish_profile();\n"
                "}\n",
            ),
        ),
        (
            "hidden-direct-root-worker",
            lambda data: append_phase_text(
                data,
                "kernel_root",
                f'\n#[cfg(feature = "{QEMU_FEATURE}")]\n'
                'fn hidden_irq_worker() { crate::exec::spawn("hidden", async {}); }\n',
            ),
        ),
        (
            "hidden-all-form-root-worker",
            lambda data: append_phase_text(
                data,
                "kernel_root",
                f'\n#[cfg(all(feature = "{QEMU_FEATURE}", feature = "qemu-virt"))]\n'
                'fn hidden_all_irq_worker() { crate::exec::spawn("hidden-all", async {}); }\n',
            ),
        ),
        (
            "hidden-raw-cfg-root-worker",
            lambda data: append_phase_text(
                data,
                "kernel_root",
                f'\n#[cfg(all(feature = r#"{QEMU_FEATURE}"#, feature = "qemu-virt"))]\n'
                'fn hidden_raw_irq_worker() { crate::exec::spawn("hidden-raw", async {}); }\n',
            ),
        ),
        (
            "hidden-base-authority",
            lambda data: append_phase_text(
                data,
                "slot",
                f'\n#[cfg(feature = "{FEATURE}")]\n'
                "fn hidden_base_irq_authority() {\n"
                "    run.finish();\n"
                "    publish_profile();\n"
                "}\n",
            ),
        ),
        (
            "hidden-cfg-macro-worker",
            lambda data: append_phase_text(
                data,
                "kernel_root",
                "\nfn hidden_cfg_macro_worker() {\n"
                f'    if cfg!(feature = "{QEMU_FEATURE}") {{\n'
                '        crate::exec::spawn("hidden-cfg-macro", async {});\n'
                "    }\n"
                "}\n",
            ),
        ),
        (
            "hidden-cfg-attr-worker",
            lambda data: append_phase_text(
                data,
                "kernel_root",
                f'\n#[cfg_attr(not(feature = "{QEMU_FEATURE}"), cfg(any()))]\n'
                'fn hidden_cfg_attr_worker() { crate::exec::spawn("hidden-cfg-attr", async {}); }\n',
            ),
        ),
        (
            "child-marker-before-close",
            lambda data: mutate_phase_text(
                data,
                "slot",
                "        let boundary = end_child_core_phase(self.token, self.detach);",
                f'        crate::println!("{FAMILY} CHILD_SSIP epoch={{}} causal=1 paired=2 inactive=0 active_epoch=1", self.token.epoch());\n        let boundary = end_child_core_phase(self.token, self.detach);',
                "child-marker-before-close",
            ),
        ),
        (
            "trap-note-before-exit",
            lambda data: mutate_trap(
                data,
                "            let applied = crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq, sbi::time());\n            crate::wasm_aot_profile_slot::profile_irq_acceptance_note_ssip(applied);",
                "            crate::wasm_aot_profile_slot::profile_irq_acceptance_note_ssip(false);\n            let applied = crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq, sbi::time());",
                "trap-note-before-exit",
            ),
        ),
        (
            "parent-hook-before-host",
            lambda data: mutate_phase_text(
                data,
                "ssh",
                "        run.managed_parent_host().map_err(|_| {",
                "        let _ = crate::wasm_aot_profile_slot::managed_irq_acceptance_parent_host(run.token().epoch());\n        run.managed_parent_host().map_err(|_| {",
                "parent-hook-before-host",
            ),
        ),
        (
            "response-irq-terminal-before-request",
            lambda data: mutate_phase_text(
                data,
                "ssh",
                "                profile_request_response(epoch, status, ready_epoch);\n"
                f'                #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                managed_irq_response(epoch, status, ready_epoch, irq_observation);",
                f'                #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                managed_irq_response(epoch, status, ready_epoch, irq_observation);\n"
                "                profile_request_response(epoch, status, ready_epoch);",
                "response-irq-terminal-before-request",
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
            "PASS verify-c84-ssh-managed-child-irq-overlay: default-off parent/child causal "
            "self-SSIP, exact atomic one-shot order, inactive terminal closure, unchanged "
            f"phase/Core/request authority, and diagnostic isolation are closed{suffix}"
        )
        return 0
    except (
        OSError,
        UnicodeError,
        RuntimeError,
        tomllib.TOMLDecodeError,
        VerificationError,
    ) as error:
        print(f"FAIL verify-c84-ssh-managed-child-irq-overlay: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
