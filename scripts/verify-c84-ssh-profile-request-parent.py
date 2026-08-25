#!/usr/bin/env python3
"""Verify the default-off C8.4 authenticated SSH request-parent seam.

This is a source/ownership verifier, not a profiling result verifier.  It
checks the exact OpenSSH admission/start/response ordering and the kernel slot
cleanup which makes the next request reusable.  It deliberately rejects any
finish, stream, publication, or physical-evidence claim in this seam.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
SSHD_SOURCE = ROOT / "components/sshd/src/lib.rs"
SSHD_MANIFEST = ROOT / "components/sshd/Cargo.toml"
KERNEL_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
FEATURE = "c84-profile-request-parent"
KERNEL_FEATURE = "wasm-c84-ssh-request-parent"
QEMU_FEATURE = "wasm-c84-ssh-request-parent-qemu-acceptance"
QEMU_FAMILY = "WASM_C84_SSH_REQUEST_PARENT"


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def rust_mask(source: str, *, literals: bool = True) -> str:
    """Mask Rust comments and optionally literals, preserving byte positions."""

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

        raw = re.match(r"r(#+)?\"", source[index:])
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
        # A lifetime starts with apostrophe too. Treat only a quote which has a
        # closing apostrophe within a Rust char literal's small lexical window.
        if source[index] == "'" and re.match(r"'(?:\\.|[^\\'\r\n])'", source[index:]):
            if literals:
                blank(index, index + 1)
            index += 1
            state = "char"
            continue
        index += 1

    require(state not in ("block-comment", "string", "char", "raw-string"), "unterminated Rust lexical item")
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
                return Scope(source[match.start() : cursor + 1], masked[match.start() : cursor + 1], match.start(), cursor + 1)
    raise VerificationError(f"{label} body is unbalanced")


def find_function(scope: Scope, name: str, label: str) -> Scope:
    return find_scope(scope.raw, rf"\b(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(name)}\b", label)


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def semantic(value: str) -> str:
    """Return compact Rust with comments removed and literals retained."""

    return compact(rust_mask(value, literals=False))


def ordered(scope: str, needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), scope)]
        require(len(matches) == 1, f"{label}: {needle!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


def adjacent_outer_attributes(source: str, offset: int) -> str:
    """Return only attributes immediately preceding an item header."""

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


def cfg_guarded(
    source: str,
    offset: int,
    label: str,
    *,
    feature: str = FEATURE,
) -> None:
    attributes = adjacent_outer_attributes(source, offset)
    require(
        re.search(
            rf'#\s*\[\s*cfg\s*\(\s*feature\s*=\s*"{re.escape(feature)}"\s*\)\s*\]',
            attributes,
        ),
        f"{label} is not directly guarded by {feature}",
    )


def verify_feature_manifest(raw: bytes, label: str, feature: str) -> None:
    manifest = tomllib.loads(raw.decode("utf-8"))
    features = manifest.get("features")
    require(isinstance(features, dict), f"{label} has no feature table")
    require(feature in features, f"{label} does not declare {feature}")
    default = features.get("default", [])
    require(isinstance(default, list), f"{label} default feature list differs")
    require(feature not in default, f"{label} enables {feature} by default")


def verify_sshd(source: str, manifest: bytes) -> None:
    verify_feature_manifest(manifest, "vibeos-sshd", FEATURE)
    production = source.split("#[cfg(test)]\nmod tests", 1)[0]

    permit_trait = find_scope(production, r"\bpub\s+trait\s+SshExecProfilePermitBackend\b", "permit backend trait")
    run_trait = find_scope(production, r"\bpub\s+trait\s+SshExecProfileRunBackend\b", "run backend trait")
    permit_struct = find_scope(production, r"\bpub\s+struct\s+SshExecProfilePermit\b", "permit wrapper")
    run_struct = find_scope(production, r"\bpub\s+struct\s+SshExecProfileRun\b", "run wrapper")
    target_struct = find_scope(production, r"\bpub\s+struct\s+SshExecProfileTarget\b", "profile target")
    for item, label in (
        (permit_trait, "permit backend trait"),
        (run_trait, "run backend trait"),
        (permit_struct, "permit wrapper"),
        (run_struct, "run wrapper"),
        (target_struct, "profile target"),
    ):
        cfg_guarded(production, item.start, label)

    permit_api = compact(permit_trait.code)
    require("fnstart(&mutself)->Result<(),()>;" in permit_api, "permit backend start signature differs")
    require("fninto_run(self:Box<Self>)->Box<dynSshExecProfileRunBackend>;" in permit_api, "permit backend transfer signature differs")
    require(permit_api.count("fncancel(&mutself);") == 1, "permit backend cancel signature differs")
    require("finish" not in permit_api and "publish" not in permit_api and "stream" not in permit_api, "permit backend exposes a result/evidence API")

    run_api = compact(run_trait.code)
    require("fnresponse_boundary(&mutself,status:u32)->Result<(),()>;" in run_api, "run backend response signature differs")
    require(run_api.count("fncancel(&mutself);") == 1, "run backend cancel signature differs")
    require("finish" not in run_api and "publish" not in run_api and "stream" not in run_api, "run backend exposes a result/evidence API")

    require("Option<Box<dynSshExecProfilePermitBackend>>" in compact(permit_struct.code), "permit wrapper is not one optional backend owner")
    require("Option<Box<dynSshExecProfileRunBackend>>" in compact(run_struct.code), "run wrapper is not one optional backend owner")
    target_fields = compact(target_struct.code)
    require("source:&'astr" in target_fields and "policy:SshExecComponentSessionPolicy" in target_fields, "profile target does not bind source plus accepted policy")
    require("pubsource:" not in target_fields and "pubpolicy:" not in target_fields, "profile target construction fields became public")

    permit_impl = find_scope(production, r"\bimpl\s+SshExecProfilePermit\b", "permit wrapper impl")
    permit_start = find_function(permit_impl, "start", "permit start")
    permit_start_code = compact(permit_start.code)
    ordered(permit_start_code, [".take()", "backend.start()", "backend.into_run()"], "permit start")
    require("ifbackend.start().is_err(){backend.cancel();returnErr(());}" in permit_start_code, "start failure does not cancel its exact backend")

    permit_drop = find_scope(production, r"\bimpl\s+Drop\s+for\s+SshExecProfilePermit\b", "permit Drop")
    permit_drop_fn = find_function(permit_drop, "drop", "permit Drop body")
    require(compact(permit_drop_fn.code).count("backend.cancel();") == 1, "unstarted permit Drop does not cancel exactly once")

    run_impl = find_scope(production, r"\bimpl\s+SshExecProfileRun\b", "run wrapper impl")
    response = find_function(run_impl, "response_boundary", "run response boundary")
    response_code = compact(response.code)
    ordered(response_code, [".take()", "backend.response_boundary(status)"], "run response boundary")
    require("ifbackend.response_boundary(status).is_err(){backend.cancel();returnErr(());}" in response_code, "failed response boundary does not cancel the exact run")

    run_drop = find_scope(production, r"\bimpl\s+Drop\s+for\s+SshExecProfileRun\b", "run Drop")
    run_drop_fn = find_function(run_drop, "drop", "run Drop body")
    require(compact(run_drop_fn.code).count("backend.cancel();") == 1, "post-start Drop does not cancel exactly once")

    platform = find_scope(production, r"\bpub\s+trait\s+Platform\b", "Platform trait")
    prepare_hook = find_function(platform, "prepare_ssh_exec_profile", "Platform prepare hook")
    cfg_guarded(platform.raw, prepare_hook.start, "Platform prepare hook")
    hook_code = compact(prepare_hook.code)
    require("SshExecProfileTarget<'_>" in prepare_hook.raw, "Platform prepare hook target differs")
    require("Result<Option<SshExecProfilePermit>,()>" in hook_code, "Platform prepare hook result differs")
    require("Ok(None)" in hook_code, "Platform prepare hook default is not inert")

    target_impl = find_scope(production, r"\bimpl<'a>\s+SshExecProfileTarget<'a>\s*", "profile target impl")
    constructor = find_function(target_impl, "new", "private profile target constructor")
    require("pub fn new" not in constructor.raw and "pub const fn new" not in constructor.raw, "profile target constructor became public")

    prepared_struct = find_scope(production, r"\bstruct\s+PreparedExec\b", "PreparedExec")
    accepted_struct = find_scope(production, r"\bstruct\s+AcceptedExec\b", "AcceptedExec")
    require("profile:Option<SshExecProfilePermit>" in compact(prepared_struct.code), "PreparedExec does not own the reservation")
    require("profile:Option<SshExecProfileRun>" in compact(accepted_struct.code), "AcceptedExec does not own the run")

    prepared_impl = find_scope(production, r"\bimpl\s+PreparedExec\b", "PreparedExec impl")
    prepare = find_function(prepared_impl, "prepare", "PreparedExec prepare")
    prepare_code = compact(prepare.code)
    ordered(prepare_code, ["matchcomponent", "Some(policy)", ".prepare_ssh_exec_profile(", "None=>None"], "profile preparation")
    require(prepare_code.count(".prepare_ssh_exec_profile(") == 1, "profile preparation call count differs")
    require("SshExecProfileTarget::new(&command,policy)" in prepare_code, "profile preparation is not bound to command plus accepted policy")

    accept = find_function(prepared_impl, "accept", "PreparedExec accept")
    accept_code = compact(accept.code)
    ordered(accept_code, ["succeed()?", ".map(SshExecProfilePermit::start)", "Ok(AcceptedExec{"], "prepare/succeed/start/accept")
    require("mem::forget" not in accept_code and "ManuallyDrop" not in accept_code, "accept bypasses permit Drop")

    protocol_signal = find_scope(production, r"\benum\s+ProtocolSignal\b", "ProtocolSignal")
    require("Exec(AcceptedExec)" in compact(protocol_signal.code), "ProtocolSignal does not carry AcceptedExec")

    public_gate = find_scope(production, r"\bfn\s+accepted_ssh_component_policy\b", "public-key Component gate")
    public_code = compact(public_gate.code)
    require("if!public_key_credential{returnNone;}" in public_code, "Component profile no longer requires a public-key credential")
    require(".filter(|policy|policy.matches(profile))" in public_code, "Component profile no longer rebinds the committed profile")
    require("validate_ssh_exec_with_component_name(source,policy.command_name())==Ok(true)" in public_code, "Component profile no longer requires exact one-name grammar")

    session_exec = find_scope(production, r"Event::Serv\(ServEvent::SessionExec\(event\)\)\s*=>", "authenticated SessionExec arm")
    session_code = compact(session_exec.code)
    ordered(
        session_code,
        [
            "revalidate_candidate(",
            "event.command()",
            "accepted_ssh_component_policy(",
            "PreparedExec::prepare(",
            "prepared.accept(",
            "event.succeed()",
            "ProtocolSignal::Exec(accepted)",
        ],
        "authenticated SessionExec acceptance",
    )
    require(session_code.count("PreparedExec::prepare(") == 1, "SessionExec preparation count differs")
    require(session_code.count("event.succeed()") == 1, "SessionExec success response count differs")

    serve = find_scope(production, r"\basync\s+fn\s+serve_connection\b", "SSH request parent")
    serve_code = compact(serve.code)
    require("SessionStart::Exec(accepted)" in serve_code, "request parent does not receive AcceptedExec")
    require("profile:mutprofile_run" in serve_code, "request parent does not retain the run")
    require(serve_code.count("&mutprofile_run") == 2, "request parent does not pass its run to both exec completion paths")
    execute_call = re.search(r"execute_with_network\((.*?)\)\.await", serve_code)
    require(execute_call is not None and "profile_run" not in execute_call.group(1), "request run leaked into the managed child execution call")

    reach = find_scope(production, r"\bfn\s+reach_profile_response_boundary\b", "response-boundary take helper")
    cfg_guarded(production, reach.start, "response-boundary take helper")
    reach_code = compact(reach.code)
    ordered(reach_code, ["profile_run.take()", "run.response_boundary(status)"], "response-boundary take")
    require(reach_code.count("profile_run.take()") == 1, "response boundary is not consume-once")

    finish_exec = find_scope(production, r"\basync\s+fn\s+finish_exec\b", "SSH exec completion")
    finish_code = compact(finish_exec.code)
    require("profile_run:&mutOption<SshExecProfileRun>" in finish_code, "finish_exec does not borrow the parent-owned run")
    reaches = [
        match.start()
        for match in re.finditer(
            re.escape("reach_profile_response_boundary(profile_run,status)?;"),
            finish_code,
        )
    ]
    progresses = [match.start() for match in re.finditer(re.escape("progress_protocol("), finish_code)]
    tcp_finishes = [match.start() for match in re.finditer(re.escape("finish_tcp_after_ssh("), finish_code)]
    require(len(reaches) == 2, f"response-boundary completion-site count differs: {len(reaches)}")
    require(len(progresses) == 1, f"finish_exec protocol-progress count differs: {len(progresses)}")
    require(len(tcp_finishes) == 2, f"finish_exec TCP-finish count differs: {len(tcp_finishes)}")
    require(reaches[0] < progresses[0] < tcp_finishes[0], "Defunct response boundary is not recorded before protocol progress/TCP teardown")
    require(progresses[0] < reaches[1] < tcp_finishes[1], "ordinary response boundary is not recorded before TCP teardown")
    require("completion_confirmed_before_progress{reach_profile_response_boundary" in finish_code, "pre-progress response call is not guarded by the complete response predicate")
    bottom_predicate = "ifclose_sent&&protocol.channel.is_none()&&runner.is_output_drained(){"
    bottom = finish_code.rfind(bottom_predicate)
    require(bottom >= 0 and bottom < reaches[1], "ordinary response call is not guarded by the complete response predicate")

    finish_tcp = find_scope(production, r"\basync\s+fn\s+finish_tcp_after_ssh\b", "TCP teardown")
    require("SshExecProfile" not in finish_tcp.raw and "response_boundary" not in finish_tcp.raw, "profile ownership escaped into TCP teardown")
    finish_tcp_code = compact(finish_tcp.code)
    require(
        "ifnetwork.connection_ended||stack.is_listening(){returnOk(());}" in finish_tcp_code,
        "TCP completion does not hand a replacement generation to fresh ownership",
    )

    capability_transport = find_scope(
        production,
        r"\bimpl\s+TcpTransport\s+for\s+CapabilityTcpTransport<'_>",
        "capability TCP transport",
    )
    capability_poll = find_function(capability_transport, "poll_network", "capability TCP poll")
    capability_poll_code = compact(capability_poll.code)
    ordered(
        capability_poll_code,
        [
            "letgeneration_replaced=connection_generation_replaced(self.connection,&snapshot)",
            "ifgeneration_replaced{self.connection=None;}",
            "if!generation_replaced&&self.connection.is_none()",
            "letgeneration_replaced_after_accept=connection_started&&connection_generation_replaced(self.connection,&snapshot)",
            "letconnection_ended=generation_replaced||generation_replaced_after_accept||",
            "ifconnection_ended{self.connection=None;connection_started=false;}",
        ],
        "two-phase TCP generation rollover",
    )

    wait_connection = find_scope(production, r"\basync\s+fn\s+wait_for_connection\b", "fresh connection wait")
    require(
        "if!report.connection_ended&&matches!(stack.stream_status().state,TcpStreamState::Established|TcpStreamState::PeerClosed)"
        in compact(wait_connection.code),
        "fresh connection wait can return on the retired generation",
    )
    rearm = find_scope(production, r"\basync\s+fn\s+rearm_listener\b", "listener rearm")
    require(
        "ifreport.connection_started||stack.is_listening(){returnOk(());}" in compact(rearm.code),
        "listener rearm does not hand an already-started generation to the fresh Runner",
    )


def verify_kernel(source: str, root_source: str, manifest: bytes) -> None:
    verify_feature_manifest(manifest, "vibeos-kernel", KERNEL_FEATURE)
    verify_feature_manifest(manifest, "vibeos-kernel", QEMU_FEATURE)
    parsed_manifest = tomllib.loads(manifest.decode("utf-8"))
    kernel_features = parsed_manifest["features"]
    require(
        kernel_features[KERNEL_FEATURE]
        == [
            "ssh-component-command",
            "wasm-c84-profile-slot",
            "vibeos-sshd/c84-profile-request-parent",
        ],
        "kernel request-parent feature dependency closure differs",
    )
    require(
        kernel_features.get(QEMU_FEATURE) == [KERNEL_FEATURE],
        "QEMU telemetry feature is not a narrow child of the base seam",
    )

    root_code = semantic(root_source)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root_code, "request-parent telemetry is not guarded as QEMU-only")
    isolated = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance"'
        ')))]compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolated in root_code, "request-parent telemetry is not isolated from other C8.4 acceptances")
    production = source

    prepare_impl = find_scope(
        production,
        r"\bimpl\s+SshExecProfilePermitBackend\s+for\s+SshExecProfileOwner\b",
        "kernel permit backend",
    )
    transfer = find_function(prepare_impl, "into_run", "kernel permit-to-run transfer")
    require(
        compact(transfer.code)
        == "fninto_run(self:Box<Self>)->Box<dynSshExecProfileRunBackend>{self}",
        "kernel permit-to-run transition does not preserve the exact Box allocation",
    )
    run_impl = find_scope(
        production,
        r"\bimpl\s+SshExecProfileRunBackend\s+for\s+SshExecProfileOwner\b",
        "kernel run backend",
    )
    platform = find_scope(production, r"\bimpl\s+SshdPlatform\s+for\s+SshPlatform\b", "kernel SSH Platform impl")
    prepare_hook = find_function(platform, "prepare_ssh_exec_profile", "kernel prepare hook")
    cfg_guarded(
        platform.raw,
        prepare_hook.start,
        "kernel prepare hook",
        feature=KERNEL_FEATURE,
    )
    prepare_code = semantic(prepare_hook.raw)

    # The public-key requirement and exact grammar have already produced the
    # immutable policy. The kernel still narrows the multi-Component selector
    # to the frozen case-filter target and revalidates every policy coordinate.
    for token in (
        "letsource=target.source()",
        'ifsource!="case-filter"{returnOk(None);}',
        'accepted.command_name()!="case-filter"',
        "current.profile()!=accepted.profile()",
        "current.command_name()!=accepted.command_name()",
        "current.incarnation()!=accepted.incarnation()",
        "current.artifact_sha256()!=accepted.artifact_sha256()",
        "prepare_current()",
        "SshExecProfilePermit::new(",
    ):
        require(token in prepare_code, f"kernel exact case-filter preparation is missing {token!r}")
    require("native-case-filter" not in prepare_hook.raw, "native Component can arm the profile parent")

    owner_state = find_scope(production, r"\benum\s+SshExecProfileOwnerState\b", "kernel profile owner state")
    require(
        compact(owner_state.code).count("Reserved(") == 1
        and compact(owner_state.code).count("Active(") == 1
        and "Closed" in owner_state.code,
        "kernel owner is not the exact Reserved/Active/Closed typestate",
    )
    owner_impl = find_scope(production, r"\bimpl\s+SshExecProfileOwner\b", "kernel profile owner impl")
    owner_start = find_function(owner_impl, "start", "kernel owner start")
    owner_response = find_function(owner_impl, "response_boundary", "kernel owner response")
    owner_cancel = find_function(owner_impl, "cancel", "kernel owner cancel")
    for item, label in (
        (owner_start, "kernel owner start"),
        (owner_response, "kernel owner response"),
        (owner_cancel, "kernel owner cancel"),
    ):
        require(
            "core::mem::replace(&mutself.state,SshExecProfileOwnerState::Closed)"
            in compact(item.code),
            f"{label} does not close ownership before fallible work",
        )
    require(
        "Reserved(permit)" in owner_start.code and "permit.start()" in compact(owner_start.code),
        "kernel owner start is not the sole Reserved -> Active transition",
    )
    response_code = compact(owner_response.code)
    require(
        "Active(run)" in owner_response.code
        and response_code.count("cancel_and_ack_profile(run)") == 1
        and response_code.count("profile_request_response(epoch,status,ready_epoch)") == 1,
        "response boundary does not close and report one exact active run",
    )
    cancel_code = compact(owner_cancel.code)
    require(
        cancel_code.count("Reserved(permit)=>drop(permit)") == 1
        and cancel_code.count("cancel_and_ack_profile(run)") == 1
        and "Closed=>{}" in cancel_code,
        "permit/run Drop cleanup is not exactly-once and closed-idempotent",
    )

    for backend, label in ((prepare_impl, "permit backend"), (run_impl, "run backend")):
        cancel = find_function(backend, "cancel", f"{label} cancel")
        require(
            compact(cancel.code).count("SshExecProfileOwner::cancel(self)") == 1,
            f"{label} does not delegate to the shared owner close path exactly once",
        )
    backend_response = find_function(run_impl, "response_boundary", "kernel backend response")
    require(
        compact(backend_response.code).count("SshExecProfileOwner::response_boundary(self,status)") == 1,
        "run backend response does not delegate to the owner boundary exactly once",
    )
    owner_drop = find_scope(production, r"\bimpl\s+Drop\s+for\s+SshExecProfileOwner\b", "kernel owner Drop")
    require(
        compact(find_function(owner_drop, "drop", "kernel owner Drop body").code).count("self.cancel()") == 1,
        "kernel backend Drop does not share the idempotent cancel path",
    )

    close = find_scope(production, r"\bfn\s+cancel_and_ack_profile\b", "kernel profile close path")
    close_code = compact(close.code)
    ordered(
        close_code,
        [
            "run.cancel()",
            "letreport_is_exact=",
            "letstored_rejection_is_exact=rejection()",
            "acknowledge_rejection(epoch)",
            "letacknowledgement_is_exact=",
            "letready_is_exact=",
        ],
        "cancel/rejection/acknowledge/ready",
    )
    require(close_code.count(".cancel()") == 1, "kernel close path cancels more or less than once")
    require(close_code.count("rejection()") == 1, "kernel close path does not read the stored rejection exactly once")
    require(close_code.count("acknowledge_rejection(") == 1, "kernel close path does not acknowledge exactly once")
    require(
        "stored_rejection_is_exact=rejection()==Some(report)" in close_code,
        "kernel close path does not compare the stored rejection with the cancel report",
    )
    require("acknowledged==report" in close_code, "kernel close path does not compare acknowledged and returned rejection")
    require(
        "SlotStatus::Ready{next_epoch:Some(ready_epoch),}" in close_code,
        "kernel close path does not prove reusable Ready(next epoch)",
    )
    require(
        "if!report_is_exact||!stored_rejection_is_exact||!acknowledgement_is_exact||!ready_is_exact"
        in close_code,
        "kernel close result omits one returned/stored/acknowledged/ready check",
    )
    require(".finish(" not in close_code, "kernel close path calls finish")

    integration = owner_impl.raw + prepare_impl.raw + run_impl.raw + close.raw + prepare_hook.raw
    integration_code = compact(rust_mask(integration))
    require(".finish(" not in integration_code, "request-parent backend fabricates a finished profile")
    for forbidden in ("StreamLease", "stream_verified", "publish_profile", "physical_evidence"):
        require(forbidden not in integration, f"request-parent backend exposes {forbidden}")

    # Telemetry exists only under the QEMU child feature. The base/default
    # feature stays silent and cannot be mistaken for physical evidence.
    for function in ("profile_request_start", "profile_request_response", "profile_request_drop"):
        marker_scope = find_scope(production, rf"\bfn\s+{function}\b", f"{function} telemetry")
        require(QEMU_FEATURE in marker_scope.raw, f"{function} marker is not QEMU-only")


@dataclass(frozen=True)
class Inputs:
    sshd: str
    sshd_manifest: bytes
    kernel: str
    kernel_manifest: bytes
    kernel_root: str = KERNEL_ROOT_SOURCE.read_text(encoding="utf-8")


def load_inputs() -> Inputs:
    return Inputs(
        sshd=SSHD_SOURCE.read_text(encoding="utf-8"),
        sshd_manifest=SSHD_MANIFEST.read_bytes(),
        kernel=KERNEL_SOURCE.read_text(encoding="utf-8"),
        kernel_root=KERNEL_ROOT_SOURCE.read_text(encoding="utf-8"),
        kernel_manifest=KERNEL_MANIFEST.read_bytes(),
    )


def verify(inputs: Inputs) -> None:
    verify_sshd(inputs.sshd, inputs.sshd_manifest)
    verify_kernel(inputs.kernel, inputs.kernel_root, inputs.kernel_manifest)


EXPECTED_QEMU_MARKERS = [
    "WASM_C84_SSH_REQUEST_PARENT START epoch=1",
    "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch=1 status=0 cancel=1 ack=1 ready_epoch=2",
    "WASM_C84_SSH_REQUEST_PARENT START epoch=2",
    "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch=2 status=0 cancel=1 ack=1 ready_epoch=3",
    "WASM_C84_SSH_REQUEST_PARENT START epoch=3",
    "WASM_C84_SSH_REQUEST_PARENT DROP epoch=3 cancel=1 ack=1 ready_epoch=4",
    "WASM_C84_SSH_REQUEST_PARENT START epoch=4",
    "WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch=4 status=0 cancel=1 ack=1 ready_epoch=5",
]


def normalize_serial_line(line: str) -> str:
    clear = "\x1b[2K"
    return line[len(clear) :] if line.startswith(clear) else line


def verify_qemu_transcript(raw: bytes) -> None:
    transcript = raw.decode("utf-8", errors="replace").replace("\r", "\n")
    lines = [normalize_serial_line(line) for line in transcript.splitlines()]
    require(
        not any(f"{QEMU_FAMILY} FAIL" in line for line in lines),
        "QEMU guest reported a request-parent failure",
    )
    require(
        not any(re.search(r"\[!\]\s+(?:fatal|panic)|panicked at", line) for line in lines),
        "QEMU guest reported a panic or fatal error",
    )
    family = [line for line in lines if QEMU_FAMILY in line]
    require(
        family == EXPECTED_QEMU_MARKERS,
        f"QEMU request-parent marker sequence differs: observed={family!r}",
    )


def run_transcript_selftest() -> int:
    valid = "\n".join(["boot", *EXPECTED_QEMU_MARKERS, "listener rearmed", ""])
    verify_qemu_transcript(valid.encode())
    mutations = [
        valid.replace(EXPECTED_QEMU_MARKERS[0] + "\n", "", 1),
        valid.replace(EXPECTED_QEMU_MARKERS[1], EXPECTED_QEMU_MARKERS[1].replace("ack=1", "ack=2"), 1),
        valid.replace(EXPECTED_QEMU_MARKERS[3], EXPECTED_QEMU_MARKERS[3].replace("ready_epoch=3", "ready_epoch=2"), 1),
        valid.replace(EXPECTED_QEMU_MARKERS[5], EXPECTED_QEMU_MARKERS[5].replace("DROP", "RESPONSE status=0"), 1),
        valid.replace(EXPECTED_QEMU_MARKERS[7], EXPECTED_QEMU_MARKERS[7] + "\n" + EXPECTED_QEMU_MARKERS[7], 1),
        valid + f"{QEMU_FAMILY} FAIL stage=synthetic epoch=4\n",
        valid + "panicked at synthetic post-response fault\n",
    ]
    for index, mutation in enumerate(mutations, start=1):
        try:
            verify_qemu_transcript(mutation.encode())
        except VerificationError:
            continue
        raise VerificationError(f"QEMU transcript selftest mutation {index} was accepted")
    return len(mutations)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    require(value.count(old) == 1, f"selftest seed {label!r} count differs: {value.count(old)}")
    return value.replace(old, new, 1)


def expect_rejected(inputs: Inputs, mutate: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutate(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def move_succeed_after_start(data: Inputs) -> Inputs:
    changed = replace_once(data.sshd, "        succeed()?;\n", "", "start-before-succeed/remove")
    changed = replace_once(
        changed,
        "        Ok(AcceptedExec {\n",
        "        succeed()?;\n        Ok(AcceptedExec {\n",
        "start-before-succeed/insert",
    )
    return Inputs(changed, data.sshd_manifest, data.kernel, data.kernel_manifest)


def rebox_permit_to_run(data: Inputs) -> Inputs:
    changed = replace_once(
        data.kernel,
        "    fn into_run(self: Box<Self>) -> Box<dyn SshExecProfileRunBackend> {\n"
        "        self\n"
        "    }",
        "    fn into_run(self: Box<Self>) -> Box<dyn SshExecProfileRunBackend> {\n"
        "        Box::new(*self)\n"
        "    }",
        "kernel-permit-to-run-rebox",
    )
    return Inputs(data.sshd, data.sshd_manifest, changed, data.kernel_manifest, data.kernel_root)


def remove_qemu_only_guard(data: Inputs) -> Inputs:
    guard = (
        '#[cfg(all(\n'
        '    feature = "wasm-c84-ssh-request-parent-qemu-acceptance",\n'
        '    not(feature = "qemu-virt")\n'
        '))]\n'
        'compile_error!("feature `wasm-c84-ssh-request-parent-qemu-acceptance` is QEMU-only");\n\n'
    )
    changed = replace_once(data.kernel_root, guard, "", "request-parent-qemu-only-guard")
    return Inputs(data.sshd, data.sshd_manifest, data.kernel, data.kernel_manifest, changed)


def remove_acceptance_isolation_guard(data: Inputs) -> Inputs:
    guard = (
        '#[cfg(all(\n'
        '    feature = "wasm-c84-ssh-request-parent-qemu-acceptance",\n'
        '    any(\n'
        '        feature = "wasm-c84-profile-slot-qemu-acceptance",\n'
        '        feature = "wasm-c84-core-poll-qemu-acceptance",\n'
        '        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",\n'
        '        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"\n'
        '    )\n'
        '))]\n'
        'compile_error!("C8.4 QEMU acceptances are isolated images");\n\n'
    )
    changed = replace_once(data.kernel_root, guard, "", "request-parent-acceptance-isolation")
    return Inputs(data.sshd, data.sshd_manifest, data.kernel, data.kernel_manifest, changed)


def run_selftest(inputs: Inputs) -> int:
    verify(inputs)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "feature-default-on",
            lambda data: Inputs(data.sshd, replace_once(data.sshd_manifest.decode(), "default = []", f'default = ["{FEATURE}"]', "feature-default-on").encode(), data.kernel, data.kernel_manifest),
        ),
        (
            "target-feature-guard-removed",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    '#[cfg(feature = "c84-profile-request-parent")]\n#[derive(Clone, Copy)]\npub struct SshExecProfileTarget',
                    '#[derive(Clone, Copy)]\npub struct SshExecProfileTarget',
                    "target-feature-guard",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "public-key-gate-removed",
            lambda data: Inputs(replace_once(data.sshd, "if !public_key_credential {", "if false {", "public-key-gate"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "start-before-succeed",
            move_succeed_after_start,
        ),
        (
            "permit-drop-cancel-removed",
            lambda data: Inputs(replace_once(data.sshd, "            backend.cancel();\n        }\n    }\n}\n\n/// Linear ownership held", "            let _ = backend;\n        }\n    }\n}\n\n/// Linear ownership held", "permit-drop-cancel"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "response-not-consume-once",
            lambda data: Inputs(replace_once(data.sshd, "let Some(run) = profile_run.take()", "let Some(run) = profile_run.as_mut()", "response-take"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "pre-progress-boundary-removed",
            lambda data: Inputs(replace_once(data.sshd, "        if completion_confirmed_before_progress {\n            reach_profile_response_boundary(profile_run, status)?;\n        }", "        if completion_confirmed_before_progress {}", "pre-progress-boundary"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "ordinary-boundary-removed",
            lambda data: Inputs(replace_once(data.sshd, "            reach_profile_response_boundary(profile_run, status)?;\n            return finish_tcp_after_ssh(", "            return finish_tcp_after_ssh(", "ordinary-boundary"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "tcp-generation-rollover-ignored",
            lambda data: Inputs(replace_once(data.sshd, "let generation_replaced = connection_generation_replaced(self.connection, &snapshot);", "let generation_replaced = false;", "tcp-generation-rollover"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "accepted-token-rollover-ignored",
            lambda data: Inputs(replace_once(data.sshd, "let generation_replaced_after_accept =\n            connection_started && connection_generation_replaced(self.connection, &snapshot);", "let generation_replaced_after_accept = false;", "accepted-token-rollover"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "rearm-started-edge-ignored",
            lambda data: Inputs(replace_once(data.sshd, "if report.connection_started || stack.is_listening() {", "if stack.is_listening() {", "rearm-started-edge"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "fresh-wait-returns-retired-generation",
            lambda data: Inputs(replace_once(data.sshd, "if !report.connection_ended\n            && matches!(", "if matches!(", "fresh-wait-ended-edge"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "tcp-finish-reads-retired-token",
            lambda data: Inputs(replace_once(data.sshd, "if network.connection_ended || stack.is_listening() {", "if stack.is_listening() {", "tcp-finish-ended-edge"), data.sshd_manifest, data.kernel, data.kernel_manifest),
        ),
        (
            "native-target-enabled",
            lambda data: Inputs(data.sshd, data.sshd_manifest, replace_once(data.kernel, 'source != "case-filter"', 'source != "native-case-filter"', "native-target"), data.kernel_manifest),
        ),
        (
            "kernel-finish-fabrication",
            lambda data: Inputs(data.sshd, data.sshd_manifest, replace_once(data.kernel, "let report = run.cancel()", "let report = run.finish()", "kernel-finish"), data.kernel_manifest),
        ),
        (
            "kernel-stored-rejection-forged",
            lambda data: Inputs(data.sshd, data.sshd_manifest, replace_once(data.kernel, "let stored_rejection_is_exact = rejection() == Some(report);", "let stored_rejection_is_exact = true;", "stored-rejection"), data.kernel_manifest),
        ),
        (
            "kernel-ack-removed",
            lambda data: Inputs(data.sshd, data.sshd_manifest, replace_once(data.kernel, "acknowledge_rejection(", "forget_rejection(", "kernel-ack"), data.kernel_manifest),
        ),
        ("kernel-permit-to-run-reboxed", rebox_permit_to_run),
        ("request-parent-qemu-only-guard-removed", remove_qemu_only_guard),
        ("request-parent-acceptance-isolation-removed", remove_acceptance_isolation_guard),
    ]
    for label, mutation in mutations:
        expect_rejected(inputs, mutation, label)
    return len(mutations) + run_transcript_selftest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-source", action="store_true", help="verify the checked-in Rust/Cargo wiring")
    parser.add_argument("--selftest", action="store_true", help="run in-memory source mutations against every gate")
    parser.add_argument("--qemu-log", type=Path, help="verify one closed single-hart UART transcript")
    arguments = parser.parse_args()
    if not arguments.check_source and not arguments.selftest and arguments.qemu_log is None:
        parser.error("select --check-source, --selftest, and/or --qemu-log")

    try:
        inputs = load_inputs()
        mutations = run_selftest(inputs) if arguments.selftest else 0
        if arguments.check_source and not arguments.selftest:
            verify(inputs)
        if arguments.qemu_log is not None:
            verify_qemu_transcript(arguments.qemu_log.read_bytes())
        suffix = f" mutations={mutations}" if arguments.selftest else ""
        print(
            "PASS verify-c84-ssh-profile-request-parent: "
            "authenticated prepare/succeed/start, request-parent cancel/reuse, "
            f"and pre-TCP response boundary are closed{suffix}"
        )
        return 0
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, VerificationError) as error:
        print(f"FAIL verify-c84-ssh-profile-request-parent: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
