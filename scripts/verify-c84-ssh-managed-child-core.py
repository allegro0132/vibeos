#!/usr/bin/env python3
"""Verify the default-off C8.4 SSH managed-child/Core composition seam.

This is deliberately a source and ownership verifier.  It proves that the
ordinary managed Component child borrows the authenticated request lineage,
that its ordinary synchronous Core polls use the portable lexical observer,
and that both response and request-Drop paths remain diagnostic cancel/ack
paths.  It rejects result publication, phase sidecars, and IRQ composition.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
COMPONENT_SOURCE = ROOT / "kernel/src/component_instances.rs"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
RUNTIME_SOURCE = ROOT / "component-runtime/src/sync.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"

FEATURE = "wasm-c84-ssh-managed-child-core"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
REQUEST_FEATURE = "wasm-c84-ssh-request-parent"
REQUEST_QEMU_FEATURE = f"{REQUEST_FEATURE}-qemu-acceptance"
CHILD_FEATURE = "wasm-c84-profile-child-delegation"
CORE_FEATURE = "wasm-c84-core-poll-observer"
IRQ_FEATURE = "wasm-c84-profile-irq-overlay"
PHASE_SIDECAR_FEATURE = "wasm-c84-ssh-managed-child-phase-sidecar"


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


@lru_cache(maxsize=256)
def rust_mask(source: str, *, literals: bool = True) -> str:
    """Mask nested Rust comments and optionally literals, preserving offsets."""

    output = list(source)
    index = 0
    length = len(source)
    block_depth = 0
    state = "code"
    raw_hashes = 0

    def blank(start: int, end: int) -> None:
        for cursor in range(start, end):
            if output[cursor] not in "\r\n":
                output[cursor] = " "

    while index < length:
        if state == "line-comment":
            if source[index] in "\r\n":
                state = "code"
                index += 1
            else:
                blank(index, index + 1)
                index += 1
            continue
        if state == "block-comment":
            if source.startswith("/*", index):
                blank(index, index + 2)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index, index + 2)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
            else:
                blank(index, index + 1)
                index += 1
            continue
        if state in ("string", "char"):
            quote = '"' if state == "string" else "'"
            if source[index] == "\\":
                if literals:
                    blank(index, min(index + 2, length))
                index += 2
            elif source[index] == quote:
                if literals:
                    blank(index, index + 1)
                index += 1
                state = "code"
            else:
                if literals:
                    blank(index, index + 1)
                index += 1
            continue
        if state == "raw-string":
            ending = '"' + "#" * raw_hashes
            if source.startswith(ending, index):
                if literals:
                    blank(index, index + len(ending))
                index += len(ending)
                state = "code"
            else:
                if literals:
                    blank(index, index + 1)
                index += 1
            continue

        if source.startswith("//", index):
            blank(index, index + 2)
            index += 2
            state = "line-comment"
            continue
        if source.startswith("/*", index):
            blank(index, index + 2)
            index += 2
            block_depth = 1
            state = "block-comment"
            continue
        raw = re.match(r'r(#+)?"', source[index:])
        if raw is not None:
            raw_hashes = len(raw.group(1) or "")
            end = index + raw.end()
            if literals:
                blank(index, end)
            index = end
            state = "raw-string"
            continue
        if source[index] == '"':
            if literals:
                blank(index, index + 1)
            index += 1
            state = "string"
            continue
        if source[index] == "'" and re.match(r"'(?:\\.|[^\\'\r\n])'", source[index:]):
            if literals:
                blank(index, index + 1)
            index += 1
            state = "char"
            continue
        index += 1

    require(
        state not in ("block-comment", "string", "char", "raw-string"),
        "unterminated Rust lexical item",
    )
    return "".join(output)


@dataclass(frozen=True)
class Scope:
    raw: str
    code: str
    start: int
    end: int


def find_scope(source: str, header: str, label: str, *, flags: int = 0) -> Scope:
    masked = rust_mask(source)
    matches = list(re.finditer(header, masked, flags))
    require(len(matches) == 1, f"{label} count differs: {len(matches)}")
    match = matches[0]
    opening = masked.find("{", match.end())
    require(opening >= 0, f"{label} has no body")
    depth = 0
    for cursor in range(opening, len(masked)):
        if masked[cursor] == "{":
            depth += 1
        elif masked[cursor] == "}":
            depth -= 1
            if depth == 0:
                return Scope(
                    source[match.start() : cursor + 1],
                    masked[match.start() : cursor + 1],
                    match.start(),
                    cursor + 1,
                )
    raise VerificationError(f"{label} body is unbalanced")


def find_function(scope: Scope, name: str, label: str) -> Scope:
    return find_scope(
        scope.raw,
        rf"\b(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?fn\s+{re.escape(name)}\b",
        label,
    )


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def semantic(value: str) -> str:
    return compact(rust_mask(value, literals=False))


@lru_cache(maxsize=256)
def without_direct_feature_units(source: str, feature: str) -> str:
    """Mask only syntax units directly guarded by one exact feature cfg.

    The managed-child/Core predecessor must keep rejecting phase-sidecar code
    in its own path.  Its successor is allowed to add Host/Wait/Cleanup code,
    but only behind a direct, exact cfg on the affected Rust statement or
    item.  This small scanner deliberately does not understand cfg(any(...)),
    cfg_attr, or an enclosing module: those broader forms remain visible to
    the predecessor's forbidden-token checks.
    """

    masked = rust_mask(source, literals=False)
    attribute = re.compile(
        rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(feature)}"\s*\)\s*\]'
    )
    spans: list[tuple[int, int]] = []

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

    for match in attribute.finditer(masked):
        cursor = match.end()
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        require(cursor < len(masked), f"direct {feature} cfg has no syntax unit")

        # Permit harmless secondary attributes only after the exact feature
        # guard. They are part of the same directly guarded syntax unit.
        while masked.startswith("#[", cursor):
            bracket = matching(cursor + 1, "[", "]")
            cursor = bracket
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
                # A directly guarded parameter lives inside parentheses that
                # started before the attribute. Its own unit must have ended
                # at the preceding comma; reaching this delimiter is invalid.
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
        spans.append((match.start(), end))

    output = list(source)
    for start, end in spans:
        for cursor in range(start, end):
            if output[cursor] not in "\r\n":
                output[cursor] = " "
    return "".join(output)


def ordered(scope: str, needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), scope)]
        require(
            len(matches) == 1,
            f"{label}: {needle!r} count differs: {len(matches)}",
        )
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


def adjacent_outer_attributes(source: str, offset: int) -> str:
    prefix = rust_mask(source[:offset], literals=False)
    cursor = len(prefix)
    attributes: list[str] = []
    while True:
        while cursor > 0 and prefix[cursor - 1].isspace():
            cursor -= 1
        if cursor == 0 or prefix[cursor - 1] != "]":
            break
        depth = 0
        opening = -1
        for index in range(cursor - 1, -1, -1):
            if prefix[index] == "]":
                depth += 1
            elif prefix[index] == "[":
                depth -= 1
                if depth == 0:
                    opening = index
                    break
        if opening <= 0 or prefix[opening - 1] != "#":
            break
        attributes.append(prefix[opening - 1 : cursor])
        cursor = opening - 1
    return "\n".join(reversed(attributes))


def cfg_guarded(source: str, offset: int, label: str, feature: str = FEATURE) -> None:
    attributes = adjacent_outer_attributes(source, offset)
    require(
        re.search(
            rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(feature)}"\s*\)\s*\]',
            attributes,
        )
        is not None,
        f"{label} is not directly guarded by {feature}",
    )


def parse_features(raw: bytes, label: str) -> dict[str, list[str]]:
    manifest = tomllib.loads(raw.decode("utf-8"))
    features = manifest.get("features")
    require(isinstance(features, dict), f"{label} has no feature table")
    for name, members in features.items():
        require(isinstance(members, list), f"{label} feature {name} is not a list")
        require(
            all(isinstance(member, str) for member in members),
            f"{label} feature {name} has a non-string member",
        )
    return features


def local_feature_closure(features: dict[str, list[str]], roots: list[str]) -> set[str]:
    closure: set[str] = set()
    pending = list(roots)
    while pending:
        feature = pending.pop()
        if feature in closure or feature not in features:
            continue
        closure.add(feature)
        for member in features[feature]:
            if "/" not in member and not member.startswith("dep:"):
                pending.append(member.rstrip("?"))
    return closure


def verify_features(inputs: "Inputs") -> None:
    kernel = parse_features(inputs.kernel_manifest, "kernel")
    qemu = parse_features(inputs.qemu_manifest, "qemu firmware")
    milkv = parse_features(inputs.milkv_manifest, "Milk-V firmware")

    require(
        kernel.get(FEATURE) == [REQUEST_FEATURE, CHILD_FEATURE, CORE_FEATURE],
        "kernel managed-child feature closure differs",
    )
    require(
        kernel.get(QEMU_FEATURE) == [FEATURE, REQUEST_QEMU_FEATURE],
        "kernel managed-child QEMU feature closure differs",
    )
    require(
        kernel.get(CORE_FEATURE)
        == [
            "wasm-c84-profile-slot",
            "dep:vibeos-component-runtime",
            "vibeos-component-runtime/c84-profile-hooks",
        ],
        "ordinary Core observer no longer selects only the portable hook seam",
    )
    default_closure = local_feature_closure(kernel, kernel.get("default", []))
    require(FEATURE not in default_closure, "kernel enables managed-child composition by default")
    require(QEMU_FEATURE not in default_closure, "kernel enables managed-child QEMU gate by default")
    feature_closure = local_feature_closure(kernel, [FEATURE])
    require(IRQ_FEATURE not in feature_closure, "managed-child composition enables the IRQ overlay")
    require(
        not any(name.endswith("-qemu-acceptance") for name in feature_closure),
        "base managed-child composition enables QEMU acceptance code",
    )

    require(
        qemu.get(QEMU_FEATURE)
        == ["vibeos-kernel/ssh-test", f"vibeos-kernel/{QEMU_FEATURE}"],
        "QEMU firmware gate is not the isolated single-hart SSH composition",
    )
    require(
        QEMU_FEATURE not in local_feature_closure(qemu, qemu.get("default", [])),
        "QEMU firmware enables the managed-child gate by default",
    )
    require(
        milkv.get(FEATURE) == [f"vibeos-kernel/{FEATURE}"],
        "Milk-V does not expose the exact reusable base feature",
    )
    require(
        FEATURE not in local_feature_closure(milkv, milkv.get("default", [])),
        "Milk-V enables the managed-child composition by default",
    )

    root = semantic(inputs.kernel_root)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root, "managed-child acceptance lacks its QEMU-only compile guard")
    isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolation in root, "managed-child acceptance isolation guard differs")
    irq_guard = (
        '#[cfg(all(feature="wasm-c84-profile-irq-overlay",'
        'not(feature="wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance"),any('
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        f'feature="{REQUEST_QEMU_FEATURE}")))]'
        'compile_error!("C8.4IRQoverlaycannotmodifyanexact-transcriptQEMUacceptanceimage");'
    )
    require(irq_guard in root, "request-backed QEMU gate is not protected from the IRQ overlay")


def verify_runtime(source: str) -> Scope:
    typed_impl = find_scope(source, r"\bimpl<'a,\s*A>\s+TypedCall<'a,\s*A>", "TypedCall impl")
    poll_profiled = find_function(typed_impl, "poll_profiled", "portable poll_profiled")
    profile_code = semantic(poll_profiled.raw)
    ordered(
        profile_code,
        [
            "letmutsession=ProfileSession{clock,profile};",
            "self.poll_with_profiler(&mutsession)",
            "session.profile.typed_polls=",
        ],
        "portable profiled typed poll",
    )
    require(profile_code.endswith("result}"), "portable profiled poll does not return its ordinary result")
    measured = find_function(typed_impl, "poll_instance_measured", "ordinary Core poll wrapper")
    measured_code = semantic(measured.raw)
    ordered(
        measured_code,
        [
            "profile.begin_core_poll()",
            "self.component.modules.poll_call(instance)",
            "profile.end_core_poll(core_started)",
        ],
        "ordinary Core observer pair",
    )
    require(
        measured_code.count("self.component.modules.poll_call(instance)") == 1,
        "ordinary Core path does not contain exactly one observed poll_call",
    )
    return poll_profiled


def verify_component(source: str) -> tuple[Scope, Scope, Scope]:
    start = find_scope(
        source,
        r"\bfn\s+start_image_instance_under_control\b",
        "managed instance start",
    )
    # The successor may add its own directly guarded parent phase predicate.
    # Remove only that syntax unit so it cannot satisfy or hide the exact
    # predecessor target predicate below.
    start_code = semantic(
        without_direct_feature_units(start.raw, PHASE_SIDECAR_FEATURE)
    )
    for exact in (
        f'#[cfg(feature="{FEATURE}")]letchild_registration_reserve=3;',
        f'#[cfg(not(feature="{FEATURE}"))]letchild_registration_reserve=2;',
        "batch.try_reserve_prepared_task_registrations(0,child_registration_reserve)",
        "batch.try_reserve_prepared_task_registrations(1,2)",
        "ifgate==StartPolicyGate::Sync&&mode==PayloadMode::CommandSync&&input.kind()==ControlStartKind::ManagedSync",
        "attach_current_request_managed_child(&mutbatch,0)",
        "#[cfg(feature=\"wasm-c84-ssh-managed-child-core\")]profile_epoch,",
    ):
        require(exact in start_code, f"managed start is missing {exact!r}")
    require(
        start_code.count("attach_current_request_managed_child(&mutbatch,0)") == 1,
        "managed child is not attached exactly once at prepared index zero",
    )
    ordered(
        start_code,
        [
            "batch.prepare_managed_instance_owned(core_token,domain,command_name,child)",
            "letchild_registration_reserve=3;",
            "batch.try_reserve_prepared_task_registrations(0,child_registration_reserve)",
            "attach_current_request_managed_child(&mutbatch,0)",
            "letprepared_child=batch.prepared_handles().first()",
            "batch.install_prepared_task_detach(0,child_target)",
            "batch.stage_exclusive_reclaimable_with(",
            "stage.publish_ready_if(permit,expected)",
        ],
        "reserve/bind/publish managed child",
    )

    future_impl = find_scope(
        source,
        r"\bimpl\s+Future\s+for\s+ManagedChildFuture\b",
        "ManagedChildFuture impl",
    )
    poll = find_function(future_impl, "poll", "ManagedChildFuture poll")
    poll_code = semantic(poll.raw)
    require(
        poll_code.count("claim_current_request_managed_child()") == 1,
        "managed future claim count differs",
    )
    first_gate = poll_code.find("child_start_gate(")
    claim = poll_code.find("claim_current_request_managed_child()")
    require(claim >= 0 and claim < first_gate, "managed child does not claim before its start gate")
    ordered(
        poll_code,
        [
            "current_managed_child_driver_state()",
            "completion==terminal_word(ComponentTerminal::Success)",
            "(Ok(Some((epoch,true))),true)=>{",
            "release_current_request_managed_child()",
        ],
        "final registry Success plus successful-driver release",
    )
    require(
        "(Ok(Some((_,_))),false)|(Ok(Some((_,false))),true)|(Ok(None),_)=>{}"
        in poll_code,
        "non-Success or incomplete driver can be washed into an explicit release",
    )
    require(
        poll_code.count("release_current_request_managed_child()") == 1,
        "managed future release count differs",
    )

    future_drop = find_scope(
        source,
        r"\bimpl\s+Drop\s+for\s+ManagedChildFuture\b",
        "ManagedChildFuture Drop",
    )
    cfg_guarded(source, future_drop.start, "ManagedChildFuture Drop")
    drop_body = find_function(future_drop, "drop", "ManagedChildFuture Drop body")
    require(
        semantic(drop_body.raw).count("abandon_current_request_managed_child();") == 1,
        "managed future Drop does not record abandonment exactly once",
    )

    lazy_impl = find_scope(source, r"\bimpl\s+LazyComponentPayload\b", "lazy payload impl")
    lazy_new = find_function(lazy_impl, "new", "lazy payload constructor")
    require(
        semantic(lazy_new.raw).count("profile_epoch") == 2,
        "target epoch is not carried exactly through the lazy payload constructor",
    )
    payload_impl = find_scope(
        source,
        r"\bunsafe\s+impl\s+InstancePayload\s+for\s+LazyComponentPayload\b",
        "lazy payload InstancePayload impl",
    )
    payload_poll = find_function(payload_impl, "poll_quantum", "lazy payload poll")
    require(
        "run_image_component(" in payload_poll.raw
        and "self.profile_epoch" in payload_poll.raw,
        "lazy payload does not pass the bound epoch to the real driver",
    )

    run = find_scope(source, r"\basync\s+fn\s+run_image_component\b", "real Component driver")
    run_code = semantic(run.raw)
    target_branch = find_scope(
        run.raw,
        r"\blet\s+polled\s*=\s*if\s+profile_epoch\s*==\s*0\s*\{\s*call\.poll\(\)\s*\}\s*else\b",
        "target profiled branch",
    )
    branch_code = semantic(target_branch.raw)
    require(
        "letpolled=ifprofile_epoch==0{call.poll()}else{" in branch_code,
        "target branch is not paired with the ordinary non-target call.poll path",
    )
    require(branch_code.count("call.poll()") == 1, "non-target ordinary poll count differs")
    require(branch_code.count("call.poll_profiled(") == 1, "target profiled poll count differs")
    ordered(
        branch_code,
        [
            "ManagedChildSlotCorePollClock::current(profile_epoch,)",
            "call.poll_profiled(&mutclock,&mutcore_profile)",
            "clock.error().is_some()",
            "!clock.core_is_closed()",
        ],
        "lexical target Core observer",
    )
    require(branch_code.endswith("result}"), "target observer does not return within its lexical scope")
    require(
        "ifclock.error().is_some()||!clock.core_is_closed(){returnterminal_word(ComponentTerminal::RunnerFault);}" in branch_code,
        "target driver does not fail closed on observer error/open state",
    )
    require(
        "#[cfg(not(feature=\"wasm-c84-ssh-managed-child-core\"))]letpolled=call.poll();"
        in run_code,
        "feature-off driver no longer uses ordinary call.poll",
    )
    success_gate = (
        "ifprofile_epoch!=0&&terminal==ComponentTerminal::Success&&"
        "crate::wasm_aot_profile_slot::mark_managed_child_driver_completed(profile_epoch).is_err()"
        "{returnterminal_word(ComponentTerminal::RunnerFault);}"
    )
    require(success_gate in run_code, "successful driver bit is not gated by exact Success")
    ordered(
        run_code,
        [
            "TypedPoll::Ready(value)=>breakvalue",
            "letterminal=matchvalue",
            "terminal==ComponentTerminal::Success",
            "mark_managed_child_driver_completed(profile_epoch)",
        ],
        "driver completion authorization",
    )
    require(run_code.endswith("terminal_word(terminal)}"), "driver does not return after success marking")

    forbidden = (
        ".finish(",
        "StreamLease",
        "stream_verified",
        "publish_profile",
        "physical_evidence",
        "Phase::Host",
        "Phase::Wait",
        "Phase::Cleanup",
        "begin_cleanup",
        "profile_irq_",
        "TrapIrqCookie",
    )
    integration = start.raw + future_impl.raw + future_drop.raw + run.raw
    integration_code = rust_mask(
        without_direct_feature_units(integration, PHASE_SIDECAR_FEATURE)
    )
    for token in forbidden:
        require(token not in integration_code, f"managed child integration admits forbidden {token}")
    return start, poll, run


def verify_slot(source: str) -> tuple[Scope, ...]:
    attach = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+attach_current_request_managed_child\b",
        "current-request child attach",
    )
    cfg_guarded(source, attach.start, "current-request child attach")
    attach_code = semantic(attach.raw)
    require(
        "Some((sample.token(),owner.detach))" in attach_code
        and "if!parent.is_current_running_exact(){returnOk(None);}" in attach_code,
        "child attach is not derived from the current exact request parent",
    )
    require(
        "attach_prepared_child(token,parent,batch,task_index)?;Ok(Some(token.epoch()))"
        in attach_code,
        "child attach leaks authority or fails to return only its epoch",
    )
    for forbidden in ("RunLease", "ChildRunLease", "StreamLease", ".finish("):
        require(forbidden not in attach.code, f"child attach exposes forbidden {forbidden}")

    claim = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+claim_current_request_managed_child\b",
        "current managed-child claim",
    )
    claim_code = semantic(claim.raw)
    require(
        "if!detach.is_current_first_poll_exact(){returnErr(ProfileError::DelegatedChildUnavailable);}" in claim_code,
        "managed child claim is not sealed to its first exact poll",
    )
    require(
        "DelegatedChildState::Attached=>" in claim_code
        and "DelegatedChildState::Claimed=>Ok(Some((token.epoch(),false)))" in claim_code,
        "managed child claim/revalidation states differ",
    )

    state = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+current_managed_child_driver_state\b",
        "managed-child driver state",
    )
    state_code = semantic(state.raw)
    require(
        "child.state==DelegatedChildState::Claimed" in state_code
        and "child.driver_completed" in state_code
        and "detach.is_current_running_exact()" in state_code,
        "successful-driver state is not tied to the current claimed task",
    )

    release = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+release_current_request_managed_child\b",
        "current managed-child release",
    )
    release_code = semantic(release.raw)
    ordered(
        release_code,
        [
            "current_managed_child_driver_state()",
            "if!completed{returnErr(ProfileError::StateMismatch);}",
            "current_managed_child(epoch)",
            "release_child(token,detach)",
        ],
        "successful managed-child release",
    )

    abandon = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+abandon_current_request_managed_child\b",
        "current managed-child abandonment",
    )
    abandon_code = semantic(abandon.raw)
    require(
        "child.state==DelegatedChildState::Claimed" in abandon_code
        and "detach.is_current_running_exact()||detach.is_current_reclaiming_exact()" in abandon_code
        and "abandon_child(token,detach);" in abandon_code,
        "Drop abandonment is not confined to the exact claimed child",
    )

    mark = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+mark_managed_child_driver_completed\b",
        "managed-child successful driver marker",
    )
    mark_code = semantic(mark.raw)
    for exact in (
        "child.state!=DelegatedChildState::Claimed",
        "child.driver_completed",
        "!faults.is_empty()",
        "*core_owner!=CoreObserverOwner::Closed",
        "child.driver_completed=true;",
    ):
        require(exact in mark_code, f"successful driver marker is missing {exact!r}")
    require(
        mark_code.rfind("child.driver_completed=true;") > mark_code.find("returnErr(ProfileError::StateMismatch)"),
        "successful driver marker is set before validation",
    )

    clock_struct = find_scope(
        source,
        r"\bpub\(crate\)\s+struct\s+ManagedChildSlotCorePollClock\b",
        "managed-child clock storage",
    )
    require(
        "not_send:PhantomData<*mut()>" in semantic(clock_struct.raw),
        "managed-child lexical clock can move or synchronize across a poll boundary",
    )
    clock_impl = find_scope(
        source,
        r"\bimpl\s+ManagedChildSlotCorePollClock\b",
        "managed-child clock impl",
    )
    closed = find_function(clock_impl, "core_is_closed", "managed-child Core closed check")
    require(
        "if!self.detach.is_current_running_exact()" in semantic(closed.raw)
        and "mark_child_fault(self.token,self.detach);" in semantic(closed.raw)
        and "mark_child_observer_fault(self.token,self.detach);" in semantic(closed.raw),
        "managed-child closed check does not revalidate exact current ownership",
    )
    clock = find_scope(
        source,
        r"\bimpl\s+ProfileClock\s+for\s+ManagedChildSlotCorePollClock\b",
        "managed-child ProfileClock",
    )
    clock_code = semantic(clock.raw)
    started = find_function(clock, "core_poll_started", "managed-child Core start")
    finished = find_function(clock, "core_poll_finished", "managed-child Core finish")
    require(
        "if!self.detach.is_current_running_exact()" in semantic(started.raw)
        and "mark_child_fault(self.token,self.detach);" in semantic(started.raw)
        and "begin_child_core_phase(self.token,self.detach)" in semantic(started.raw),
        "managed-child clock does not open the ordinary child Core boundary",
    )
    require(
        "if!self.detach.is_current_running_exact()" in semantic(finished.raw)
        and "mark_child_fault(self.token,self.detach);" in semantic(finished.raw)
        and "end_child_core_phase(self.token,self.detach)" in semantic(finished.raw),
        "managed-child clock does not close the ordinary child Core boundary",
    )
    require(
        clock_code.count("self.owns_open=false;") >= 1,
        "managed-child clock does not close lexical ownership",
    )
    clock_drop = find_scope(
        source,
        r"\bimpl\s+Drop\s+for\s+ManagedChildSlotCorePollClock\b",
        "managed-child clock Drop",
    )
    require(
        "self.detach.is_current_running_exact()" in semantic(clock_drop.raw)
        and "self.detach.is_current_reclaiming_exact()" in semantic(clock_drop.raw)
        and "mark_child_observer_fault(self.token,self.detach);" in semantic(clock_drop.raw),
        "open lexical observer Drop is not a sticky child fault",
    )

    response = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_child_response_ready\b",
        "managed-child response readiness",
    )
    response_code = semantic(response.raw)
    for exact in (
        "child:None",
        "child_detach:Some(TaskDetachReason::Exited)",
        "faults.is_empty()",
        "*core_owner==CoreObserverOwner::Closed",
    ):
        require(exact in response_code, f"normal response proof is missing {exact!r}")

    drop_faults = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_child_drop_faults\b",
        "managed-child Drop fault set",
    )
    drop_code = semantic(drop_faults.raw)
    exact_drop_fragments = (
        "letmutdetached=SlotFaults::NONE;",
        "detached.insert(SlotFaults::CHILD_DETACHED);",
        "letmutabandoned=detached;",
        "abandoned.insert(SlotFaults::CHILD_ABANDONED);",
        "(None,None,exact)ifexact.is_empty()=>Ok(exact)",
        "(None,Some(TaskDetachReason::Exited),exact)ifexact.is_empty()||exact==abandoned=>{Ok(exact)}",
        "(None,Some(TaskDetachReason::Cancelled|TaskDetachReason::Faulted),exact)ifexact==detached||exact==abandoned=>{Ok(exact)}",
        "_=>Err(ProfileError::SlotFault(*faults))",
    )
    for exact in exact_drop_fragments:
        require(exact in drop_code, f"request-Drop exact fault lattice is missing {exact!r}")

    active_drop = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_child_active_drop_ready\b",
        "managed-child QEMU active-Drop proof",
    )
    cfg_guarded(source, active_drop.start, "managed-child QEMU active-Drop proof", feature=QEMU_FEATURE)
    active_drop_code = semantic(active_drop.raw)
    for exact in (
        "child:None",
        "child_detach:Some(TaskDetachReason::Exited)",
        "*faults==SlotFaults::CHILD_ABANDONED_DETACHED",
        "*core_owner==CoreObserverOwner::Closed",
    ):
        require(exact in active_drop_code, f"QEMU active-Drop proof is missing {exact!r}")

    detached = find_scope(
        source,
        r"\bunsafe\s+fn\s+profile_child_detached\b",
        "profile child detach callback",
    )
    detached_code = semantic(detached.raw)
    require(
        "letclean=state==DelegatedChildState::CompletedPendingDetach&&reason==TaskDetachReason::Exited;"
        in detached_code,
        "normal child detach is not exactly released plus Exited",
    )
    require(
        "if!clean{faults.insert(SlotFaults::CHILD_DETACHED);ifstate==DelegatedChildState::Abandoned{faults.insert(SlotFaults::CHILD_ABANDONED);}}"
        in detached_code,
        "non-normal detach does not preserve exact detached/abandoned faults",
    )
    ordered(
        detached_code,
        ["*child=None;", "drop(slot);", "record_managed_child_detached(epoch,reason,clean)"],
        "detach callback releases SLOT before acceptance trace",
    )

    for item, label in (
        (claim, "current managed-child claim"),
        (state, "managed-child driver state"),
        (release, "current managed-child release"),
        (abandon, "current managed-child abandonment"),
        (mark, "managed-child successful driver marker"),
        (clock_struct, "managed-child clock storage"),
        (clock_impl, "managed-child clock impl"),
        (clock, "managed-child ProfileClock"),
        (clock_drop, "managed-child clock Drop"),
        (response, "managed-child response readiness"),
        (drop_faults, "managed-child Drop fault set"),
    ):
        cfg_guarded(source, item.start, label)

    integration = "".join(
        item.raw
        for item in (
            attach,
            claim,
            state,
            release,
            abandon,
            mark,
            clock_impl,
            clock,
            response,
            drop_faults,
            active_drop,
            detached,
        )
    )
    predecessor_integration = rust_mask(
        without_direct_feature_units(integration, PHASE_SIDECAR_FEATURE)
    )
    for forbidden in (
        ".finish(",
        "StreamLease",
        "stream_verified",
        "publish_profile",
        "physical_evidence",
        "Phase::Host",
        "Phase::Wait",
        "Phase::Cleanup",
        "begin_cleanup",
        "profile_irq_",
        "TrapIrqCookie",
    ):
        require(forbidden not in predecessor_integration, f"slot composition admits forbidden {forbidden}")
    return attach, claim, release, abandon, mark, clock, response, drop_faults, detached


def verify_ssh(source: str) -> tuple[Scope, Scope, Scope]:
    owner = find_scope(source, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner")
    response = find_function(owner, "response_boundary", "SSH response boundary")
    cancel = find_function(owner, "cancel", "SSH request Drop/cancel")
    response_code = semantic(response.raw)
    cancel_code = semantic(cancel.raw)
    require(
        "managed_child_response_ready(epoch).is_ok()" in response_code,
        "SSH normal response does not require managed-child readiness",
    )
    require(
        response_code.count(
            "cancel_and_ack_profile(run,crate::wasm_aot_profile_slot::SlotFaults::default())"
        )
        == 1,
        "SSH normal response does not cancel/ack with the exact empty fault set",
    )
    ordered(
        response_code,
        [
            "managed_child_response_ready(epoch)",
            "cancel_and_ack_profile(run,crate::wasm_aot_profile_slot::SlotFaults::default())",
            "profile_request_response(epoch,status,ready_epoch)",
        ],
        "normal managed-child response",
    )
    require(
        "managed_child_drop_faults(epoch)" in cancel_code
        and "letexpectation_exact=drop_expectation.is_ok();" in cancel_code
        and "letexpected_faults=drop_expectation.unwrap_or_default();" in cancel_code,
        "SSH Drop does not derive one exact managed-child fault set",
    )
    require(
        "letexpectation_exact=drop_expectation.is_ok()&&crate::wasm_aot_profile_slot::managed_child_active_drop_ready(epoch).is_ok();"
        in cancel_code
        and "Ok((core_pairs,crate::exec::TaskDetachReason::Exited))=>" in cancel_code
        and "detach=exited" in cancel.raw,
        "QEMU active-Drop marker is not bound to abandoned+detached plus Exited",
    )
    ordered(
        cancel_code,
        [
            "managed_child_drop_faults(epoch)",
            "letexpectation_exact=drop_expectation.is_ok();",
            "managed_child_active_drop_ready(epoch)",
            "cancel_and_ack_profile(run,expected_faults)",
            "Ok(ready_epoch)ifexpectation_exact",
            "profile_request_drop(epoch,ready_epoch)",
        ],
        "managed-child request Drop",
    )

    close = find_scope(source, r"\bfn\s+cancel_and_ack_profile\b", "SSH cancel/ack close")
    close_code = semantic(close.raw)
    ordered(
        close_code,
        [
            "run.cancel()",
            "report.slot_faults==expected_slot_faults",
            "rejection()==Some(report)",
            "acknowledge_rejection(epoch)",
            "SlotStatus::Ready{next_epoch:Some(ready_epoch),}",
        ],
        "parent cancel/rejection/ack/reuse",
    )
    require(close_code.count("run.cancel()") == 1, "parent cancel count differs")
    require(
        close_code.count("acknowledge_rejection(epoch)") == 1,
        "parent acknowledgement count differs",
    )
    integration = owner.raw + close.raw
    predecessor_integration = rust_mask(
        without_direct_feature_units(integration, PHASE_SIDECAR_FEATURE)
    )
    for forbidden in (
        ".finish(",
        "StreamLease",
        "stream_verified",
        "publish_profile",
        "physical_evidence",
        "Phase::Host",
        "Phase::Wait",
        "Phase::Cleanup",
        "begin_cleanup",
        "profile_irq_",
        "TrapIrqCookie",
    ):
        require(forbidden not in predecessor_integration, f"SSH parent admits forbidden {forbidden}")
    return response, cancel, close


@dataclass(frozen=True)
class Inputs:
    component: str
    slot: str
    ssh: str
    kernel_root: str
    runtime: str
    kernel_manifest: bytes
    qemu_manifest: bytes
    milkv_manifest: bytes


def load_inputs() -> Inputs:
    return Inputs(
        component=COMPONENT_SOURCE.read_text(encoding="utf-8"),
        slot=SLOT_SOURCE.read_text(encoding="utf-8"),
        ssh=SSH_SOURCE.read_text(encoding="utf-8"),
        kernel_root=KERNEL_ROOT_SOURCE.read_text(encoding="utf-8"),
        runtime=RUNTIME_SOURCE.read_text(encoding="utf-8"),
        kernel_manifest=KERNEL_MANIFEST.read_bytes(),
        qemu_manifest=QEMU_MANIFEST.read_bytes(),
        milkv_manifest=MILKV_MANIFEST.read_bytes(),
    )


def verify(inputs: Inputs) -> None:
    verify_features(inputs)
    verify_runtime(inputs.runtime)
    verify_component(inputs.component)
    verify_slot(inputs.slot)
    verify_ssh(inputs.ssh)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest seed {label!r} count differs: {count}")
    return value.replace(old, new, 1)


def mutate_manifest(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    raw = getattr(data, field)
    changed = replace_once(raw.decode("utf-8"), old, new, label).encode("utf-8")
    return replace(data, **{field: changed})


def expect_rejected(inputs: Inputs, mutate: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutate(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def move_attach_after_publish(data: Inputs) -> Inputs:
    component = replace_once(
        data.component,
        "crate::wasm_aot_profile_slot::attach_current_request_managed_child(&mut batch, 0)",
        "crate::wasm_aot_profile_slot::attach_current_request_managed_child_AFTER_PUBLISH(&mut batch, 0)",
        "attach-after-publish/remove",
    )
    component = replace_once(
        component,
        "let ready = unsafe { stage.publish_ready_if(permit, expected) };",
        "let ready = unsafe { stage.publish_ready_if(permit, expected) };\n"
        "    let _ = crate::wasm_aot_profile_slot::attach_current_request_managed_child(&mut batch, 0);",
        "attach-after-publish/insert",
    )
    return replace(data, component=component)


def move_claim_after_start_gate(data: Inputs) -> Inputs:
    component = replace_once(
        data.component,
        "crate::wasm_aot_profile_slot::claim_current_request_managed_child()",
        "crate::wasm_aot_profile_slot::claim_current_request_managed_child_BEFORE_GATE()",
        "claim-after-start-gate/remove",
    )
    component = replace_once(
        component,
        "        let (permit, expected) = lifecycle_poll_permit();\n",
        "        let _ = crate::wasm_aot_profile_slot::claim_current_request_managed_child();\n"
        "        let (permit, expected) = lifecycle_poll_permit();\n",
        "claim-after-start-gate/insert",
    )
    return replace(data, component=component)


def remove_c48_from_acceptance_isolation(data: Inputs) -> Inputs:
    old = (
        f'#[cfg(all(\n    feature = "{QEMU_FEATURE}",\n    any(\n'
        '        feature = "wasm-c48-qemu-acceptance",\n'
    )
    new = f'#[cfg(all(\n    feature = "{QEMU_FEATURE}",\n    any(\n'
    return replace(
        data,
        kernel_root=replace_once(
            data.kernel_root,
            old,
            new,
            "managed-child-c48-isolation",
        ),
    )


def run_selftest(inputs: Inputs) -> int:
    verify(inputs)
    guarded_successor = replace(
        inputs,
        component=replace_once(
            inputs.component,
            "            let result = call.poll_profiled(&mut clock, &mut core_profile);",
            f'            #[cfg(feature = "{PHASE_SIDECAR_FEATURE}")]\n'
            "            let _successor_only = Phase::Host;\n"
            "            let result = call.poll_profiled(&mut clock, &mut core_profile);",
            "direct-successor-cfg-allowance",
        ),
    )
    verify(guarded_successor)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "kernel-feature-default-on",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                'default = ["qemu-virt", "qemu-default-image"]',
                f'default = ["qemu-virt", "qemu-default-image", "{FEATURE}"]',
                "kernel-feature-default-on",
            ),
        ),
        (
            "feature-closure-loses-core",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{FEATURE} = [\n'
                f'    "{REQUEST_FEATURE}",\n'
                f'    "{CHILD_FEATURE}",\n'
                f'    "{CORE_FEATURE}",\n'
                ']\n',
                f'{FEATURE} = [\n'
                f'    "{REQUEST_FEATURE}",\n'
                f'    "{CHILD_FEATURE}",\n'
                ']\n',
                "feature-closure-loses-core",
            ),
        ),
        (
            "feature-closure-adds-irq",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{FEATURE} = [\n'
                f'    "{REQUEST_FEATURE}",\n'
                f'    "{CHILD_FEATURE}",\n'
                f'    "{CORE_FEATURE}",\n'
                ']\n',
                f'{FEATURE} = [\n'
                f'    "{REQUEST_FEATURE}",\n'
                f'    "{CHILD_FEATURE}",\n'
                f'    "{CORE_FEATURE}",\n'
                f'    "{IRQ_FEATURE}",\n'
                ']\n',
                "feature-closure-adds-irq",
            ),
        ),
        (
            "qemu-guard-removed",
            lambda data: replace(
                data,
                kernel_root=replace_once(
                    data.kernel_root,
                    f'#[cfg(all(\n    feature = "{QEMU_FEATURE}",\n    not(feature = "qemu-virt")\n))]\n'
                    f'compile_error!("feature `{QEMU_FEATURE}` is QEMU-only");\n\n',
                    "",
                    "qemu-guard-removed",
                ),
            ),
        ),
        ("managed-child-c48-isolation-removed", remove_c48_from_acceptance_isolation),
        (
            "qemu-firmware-default-on",
            lambda data: mutate_manifest(
                data,
                "qemu_manifest",
                "default = []",
                f'default = ["{QEMU_FEATURE}"]',
                "qemu-firmware-default-on",
            ),
        ),
        (
            "claim-feature-guard-removed",
            lambda data: replace(
                data,
                slot=replace_once(
                    data.slot,
                    f'#[cfg(feature = "{FEATURE}")]\n'
                    "pub(crate) fn claim_current_request_managed_child",
                    "pub(crate) fn claim_current_request_managed_child",
                    "claim-feature-guard-removed",
                ),
            ),
        ),
        (
            "child-reserve-reduced",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "let child_registration_reserve = 3;",
                    "let child_registration_reserve = 2;",
                    "child-reserve-reduced",
                ),
            ),
        ),
        (
            "child-index-not-zero",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "attach_current_request_managed_child(&mut batch, 0)",
                    "attach_current_request_managed_child(&mut batch, 1)",
                    "child-index-not-zero",
                ),
            ),
        ),
        ("attach-after-publication", move_attach_after_publish),
        (
            "attach-target-widened",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "let profile_epoch = if gate == StartPolicyGate::Sync",
                    "let profile_epoch = if gate != StartPolicyGate::Sync",
                    "attach-target-widened",
                ),
            ),
        ),
        (
            "claim-after-start-gate",
            move_claim_after_start_gate,
        ),
        (
            "target-poll-unprofiled",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "let result = call.poll_profiled(&mut clock, &mut core_profile);",
                    "let result = call.poll();",
                    "target-poll-unprofiled",
                ),
            ),
        ),
        (
            "observer-error-ignored",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "if clock.error().is_some() || !clock.core_is_closed() {",
                    "if false {",
                    "observer-error-ignored",
                ),
            ),
        ),
        (
            "non-target-profiled",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "let polled = if profile_epoch == 0 {\n            call.poll()",
                    "let polled = if profile_epoch == 0 {\n            call.poll_profiled(&mut clock, &mut core_profile)",
                    "non-target-profiled",
                ),
            ),
        ),
        (
            "ordinary-core-observer-unpaired",
            lambda data: replace(
                data,
                runtime=replace_once(
                    data.runtime,
                    "        profile.end_core_poll(core_started);\n",
                    "",
                    "ordinary-core-observer-unpaired",
                ),
            ),
        ),
        (
            "driver-success-bit-unconditional",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "        && terminal == ComponentTerminal::Success\n",
                    "        && true\n",
                    "driver-success-bit-unconditional",
                ),
            ),
        ),
        (
            "registry-success-word-ignored",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "completion == terminal_word(ComponentTerminal::Success)",
                    "true",
                    "registry-success-word-ignored",
                ),
            ),
        ),
        (
            "release-ignores-success-bit",
            lambda data: replace(
                data,
                slot=replace_once(
                    data.slot,
                    "    if !completed {\n        return Err(ProfileError::StateMismatch);\n    }\n",
                    "",
                    "release-ignores-success-bit",
                ),
            ),
        ),
        (
            "cooperative-cancel-released",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "                    (Ok(Some((_, _))), false) | (Ok(Some((_, false))), true) | (Ok(None), _) => {}",
                    "                    (Ok(Some((_, _))), false) | (Ok(Some((_, false))), true) | (Ok(None), _) => { let _ = crate::wasm_aot_profile_slot::release_current_request_managed_child(); }",
                    "cooperative-cancel-released",
                ),
            ),
        ),
        (
            "active-drop-fault-bits-forged",
            lambda data: replace(
                data,
                slot=replace_once(
                    data.slot,
                    "            && *faults == SlotFaults::CHILD_ABANDONED_DETACHED\n",
                    "            && faults.is_empty()\n",
                    "active-drop-fault-bits-forged",
                ),
            ),
        ),
        (
            "clock-start-owner-revalidation-removed",
            lambda data: replace(
                data,
                slot=replace_once(
                    data.slot,
                    "    fn core_poll_started(&mut self) -> u64 {\n        if !self.detach.is_current_running_exact() {\n",
                    "    fn core_poll_started(&mut self) -> u64 {\n        if false {\n",
                    "clock-start-owner-revalidation-removed",
                ),
            ),
        ),
        (
            "future-drop-abandonment-removed",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "        crate::wasm_aot_profile_slot::abandon_current_request_managed_child();",
                    "",
                    "future-drop-abandonment-removed",
                ),
            ),
        ),
        (
            "normal-response-allows-faults",
            lambda data: replace(
                data,
                slot=replace_once(
                    data.slot,
                    "            && faults.is_empty()\n            && *core_owner == CoreObserverOwner::Closed =>",
                    "            && *core_owner == CoreObserverOwner::Closed =>",
                    "normal-response-allows-faults",
                ),
            ),
        ),
        (
            "drop-fault-lattice-widened",
            lambda data: replace(
                data,
                slot=replace_once(
                    data.slot,
                    "        {\n            Ok(exact)\n        }\n        _ => Err(ProfileError::SlotFault(*faults)),\n    }\n}\n\n/// The QEMU active-kill proof",
                    "        {\n            Ok(exact)\n        }\n        _ => Ok(*faults),\n    }\n}\n\n/// The QEMU active-kill proof",
                    "drop-fault-lattice-widened",
                ),
            ),
        ),
        (
            "parent-normal-finish-fabricated",
            lambda data: replace(
                data,
                ssh=replace_once(
                    data.ssh,
                    "let report = run.cancel()",
                    "let report = run.finish()",
                    "parent-normal-finish-fabricated",
                ),
            ),
        ),
        (
            "parent-ack-removed",
            lambda data: replace(
                data,
                ssh=replace_once(
                    data.ssh,
                    "acknowledge_rejection(epoch)",
                    "forget_rejection(epoch)",
                    "parent-ack-removed",
                ),
            ),
        ),
        (
            "sidecar-host-phase-added",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "let result = call.poll_profiled(&mut clock, &mut core_profile);",
                    "let _ = Phase::Host; let result = call.poll_profiled(&mut clock, &mut core_profile);",
                    "sidecar-host-phase-added",
                ),
            ),
        ),
        (
            "sidecar-host-phase-broad-cfg",
            lambda data: replace(
                data,
                component=replace_once(
                    data.component,
                    "            let result = call.poll_profiled(&mut clock, &mut core_profile);",
                    f'            #[cfg(any(feature = "{PHASE_SIDECAR_FEATURE}"))]\n'
                    "            let _successor_only = Phase::Host;\n"
                    "            let result = call.poll_profiled(&mut clock, &mut core_profile);",
                    "sidecar-host-phase-broad-cfg",
                ),
            ),
        ),
    ]
    for label, mutation in mutations:
        expect_rejected(inputs, mutation, label)
    return len(mutations)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-source",
        action="store_true",
        help="verify the checked-in Rust/Cargo managed-child composition",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run in-memory mutations against every ownership/source gate",
    )
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
            "PASS verify-c84-ssh-managed-child-core: default-off exact child bind/claim, "
            "ordinary lexical Core observation, success-only release, Drop abandonment, "
            f"and parent cancel/ack are closed{suffix}"
        )
        return 0
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, VerificationError) as error:
        print(f"FAIL verify-c84-ssh-managed-child-core: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
