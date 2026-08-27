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
FINISH_FEATURE = "wasm-c84-ssh-managed-child-finish-verify"
FINISH_QEMU_FEATURE = f"{FINISH_FEATURE}-qemu-acceptance"
VERIFIED_STREAM_FEATURE = "wasm-c84-ssh-managed-child-verified-stream"
VERIFIED_STREAM_QEMU_FEATURE = f"{VERIFIED_STREAM_FEATURE}-qemu-acceptance"
TRUSTED_SAMPLE_FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
TRUSTED_SAMPLE_QEMU_FEATURE = f"{TRUSTED_SAMPLE_FEATURE}-qemu-acceptance"
SSHD_TRUSTED_SAMPLE_FEATURE = "c84-profile-trusted-sample"


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
        scope.raw, rf"\b(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(name)}\b", label
    )


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def semantic(value: str) -> str:
    """Return compact Rust with comments removed and literals retained."""

    return compact(rust_mask(value, literals=False))


def without_direct_feature_units(source: str, feature: str) -> str:
    """Mask only syntax units guarded by one direct, exact feature cfg."""

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


def local_feature_closure(features: dict[str, list[str]], roots: list[str]) -> set[str]:
    closure: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        for member in features.get(name, []):
            if "/" not in member and not member.startswith("dep:"):
                pending.append(member)
    return closure


def verify_sshd(source: str, manifest: bytes) -> None:
    verify_feature_manifest(manifest, "vibeos-sshd", FEATURE)
    verify_feature_manifest(manifest, "vibeos-sshd", SSHD_TRUSTED_SAMPLE_FEATURE)
    sshd_features = tomllib.loads(manifest.decode("utf-8"))["features"]
    require(
        sshd_features.get(SSHD_TRUSTED_SAMPLE_FEATURE) == ["c84-profile-phase-sidecar"],
        "sshd trusted-sample is not the exact phase-sidecar successor",
    )
    production = source.split("#[cfg(test)]\nmod tests", 1)[0]
    production = without_direct_feature_units(production, SSHD_TRUSTED_SAMPLE_FEATURE)

    permit_trait = find_scope(
        production,
        r"\bpub\s+trait\s+SshExecProfilePermitBackend\b",
        "permit backend trait",
    )
    run_trait = find_scope(
        production, r"\bpub\s+trait\s+SshExecProfileRunBackend\b", "run backend trait"
    )
    permit_struct = find_scope(
        production, r"\bpub\s+struct\s+SshExecProfilePermit\b", "permit wrapper"
    )
    run_struct = find_scope(
        production, r"\bpub\s+struct\s+SshExecProfileRun\b", "run wrapper"
    )
    target_struct = find_scope(
        production, r"\bpub\s+struct\s+SshExecProfileTarget\b", "profile target"
    )
    for item, label in (
        (permit_trait, "permit backend trait"),
        (run_trait, "run backend trait"),
        (permit_struct, "permit wrapper"),
        (run_struct, "run wrapper"),
        (target_struct, "profile target"),
    ):
        cfg_guarded(production, item.start, label)

    prepare_error = find_scope(
        production,
        r"\bpub\s+enum\s+SshExecProfilePrepareError\b",
        "profile prepare error",
    )
    cfg_guarded(production, prepare_error.start, "profile prepare error")
    require(
        semantic(prepare_error.raw)
        == "pubenumSshExecProfilePrepareError{Failed,Reject,}",
        "profile prepare error no longer separates fatal failure from terminal rejection",
    )

    permit_api = compact(permit_trait.code)
    require(
        "fnstart(&mutself)->Result<(),()>;" in permit_api,
        "permit backend start signature differs",
    )
    require(
        "fninto_run(self:Box<Self>)->Box<dynSshExecProfileRunBackend>;" in permit_api,
        "permit backend transfer signature differs",
    )
    require(
        permit_api.count("fncancel(&mutself);") == 1,
        "permit backend cancel signature differs",
    )
    require(
        "finish" not in permit_api
        and "publish" not in permit_api
        and "stream" not in permit_api,
        "permit backend exposes a result/evidence API",
    )

    run_api = compact(run_trait.code)
    require(
        "fnresponse_boundary(&mutself,status:u32)->Result<(),()>;" in run_api,
        "run backend response signature differs",
    )
    require(
        run_api.count("fncancel(&mutself);") == 1,
        "run backend cancel signature differs",
    )
    require(
        "finish" not in run_api
        and "publish" not in run_api
        and "stream" not in run_api,
        "run backend exposes a result/evidence API",
    )

    require(
        "Option<Box<dynSshExecProfilePermitBackend>>" in compact(permit_struct.code),
        "permit wrapper is not one optional backend owner",
    )
    require(
        "Option<Box<dynSshExecProfileRunBackend>>" in compact(run_struct.code),
        "run wrapper is not one optional backend owner",
    )
    target_fields = compact(target_struct.code)
    require(
        "source:&'astr" in target_fields
        and "policy:SshExecComponentSessionPolicy" in target_fields,
        "profile target does not bind source plus accepted policy",
    )
    require(
        "pubsource:" not in target_fields and "pubpolicy:" not in target_fields,
        "profile target construction fields became public",
    )

    permit_impl = find_scope(
        production, r"\bimpl\s+SshExecProfilePermit\b", "permit wrapper impl"
    )
    permit_start = find_function(permit_impl, "start", "permit start")
    permit_start_code = compact(permit_start.code)
    ordered(
        permit_start_code,
        [".take()", "backend.start()", "backend.into_run()"],
        "permit start",
    )
    require(
        "ifbackend.start().is_err(){backend.cancel();returnErr(());}"
        in permit_start_code,
        "start failure does not cancel its exact backend",
    )

    permit_drop = find_scope(
        production, r"\bimpl\s+Drop\s+for\s+SshExecProfilePermit\b", "permit Drop"
    )
    permit_drop_fn = find_function(permit_drop, "drop", "permit Drop body")
    require(
        compact(permit_drop_fn.code).count("backend.cancel();") == 1,
        "unstarted permit Drop does not cancel exactly once",
    )

    run_impl = find_scope(
        production, r"\bimpl\s+SshExecProfileRun\b", "run wrapper impl"
    )
    response = find_function(run_impl, "response_boundary", "run response boundary")
    response_code = compact(response.code)
    ordered(
        response_code,
        [
            ".take()",
            "letboundary=backend.response_boundary(status);",
            "ifboundary.is_err()",
        ],
        "run response boundary",
    )
    require(
        "letboundary=backend.response_boundary(status);ifboundary.is_err(){backend.cancel();returnErr(());}"
        in response_code,
        "failed response boundary does not cancel the exact run",
    )

    run_drop = find_scope(
        production, r"\bimpl\s+Drop\s+for\s+SshExecProfileRun\b", "run Drop"
    )
    run_drop_fn = find_function(run_drop, "drop", "run Drop body")
    require(
        compact(run_drop_fn.code).count("backend.cancel();") == 1,
        "post-start Drop does not cancel exactly once",
    )

    platform = find_scope(production, r"\bpub\s+trait\s+Platform\b", "Platform trait")
    prepare_hook = find_function(
        platform, "prepare_ssh_exec_profile", "Platform prepare hook"
    )
    cfg_guarded(platform.raw, prepare_hook.start, "Platform prepare hook")
    hook_code = compact(prepare_hook.code)
    require(
        "SshExecProfileTarget<'_>" in prepare_hook.raw,
        "Platform prepare hook target differs",
    )
    require(
        "Result<Option<SshExecProfilePermit>,SshExecProfilePrepareError>" in hook_code,
        "Platform prepare hook result differs",
    )
    require("Ok(None)" in hook_code, "Platform prepare hook default is not inert")

    target_impl = find_scope(
        production, r"\bimpl<'a>\s+SshExecProfileTarget<'a>\s*", "profile target impl"
    )
    constructor = find_function(
        target_impl, "new", "private profile target constructor"
    )
    require(
        "pub fn new" not in constructor.raw
        and "pub const fn new" not in constructor.raw,
        "profile target constructor became public",
    )

    reject_status = (
        '#[cfg(feature="c84-profile-request-parent")]'
        "constSSH_EXEC_PRESTART_REJECT_STATUS:u32=126;"
    )
    require(
        semantic(production).count(reject_status) == 1,
        "terminal pre-start rejection does not use one fixed status 126",
    )

    prepared_exec = find_scope(production, r"\benum\s+PreparedExec\b", "PreparedExec")
    require(
        semantic(prepared_exec.raw)
        == (
            "enumPreparedExec{Execute{command:String,component:Option<SshExecComponentSessionPolicy>,"
            '#[cfg(feature="c84-profile-request-parent")]profile:Option<SshExecProfilePermit>,},'
            '#[cfg(feature="c84-profile-request-parent")]Reject,}'
        ),
        "PreparedExec rejection gained a command, component, or permit",
    )
    accepted_exec = find_scope(production, r"\benum\s+AcceptedExec\b", "AcceptedExec")
    require(
        semantic(accepted_exec.raw)
        == (
            "enumAcceptedExec{Execute{command:String,component:Option<SshExecComponentSessionPolicy>,"
            '#[cfg(feature="c84-profile-request-parent")]profile:Option<SshExecProfileRun>,},'
            '#[cfg(feature="c84-profile-request-parent")]Reject{status:u32},}'
        ),
        "AcceptedExec rejection gained a command, component, or run",
    )

    prepared_impl = find_scope(
        production, r"\bimpl\s+PreparedExec\b", "PreparedExec impl"
    )
    prepare = find_function(prepared_impl, "prepare", "PreparedExec prepare")
    prepare_code = semantic(prepare.raw)
    expected_prepare = (
        "fnprepare(space:&Space,command:String,"
        "component:Option<SshExecComponentSessionPolicy>,)->Result<Self,&'staticstr>{"
        '#[cfg(feature="c84-profile-request-parent")]letprofile=matchcomponent{'
        "Some(policy)=>{matchspace.prepare_ssh_exec_profile("
        "SshExecProfileTarget::new(&command,policy)){Ok(profile)=>profile,"
        "Err(SshExecProfilePrepareError::Failed)=>{"
        'returnErr("SSHexecprofilepreparationfailed")} '
        "Err(SshExecProfilePrepareError::Reject)=>returnOk(Self::Reject),}}"
        "None=>None,};"
        '#[cfg(not(feature="c84-profile-request-parent"))]let_=space;'
        "Ok(Self::Execute{command,component,"
        '#[cfg(feature="c84-profile-request-parent")]profile,})}'
    ).replace(" ", "")
    require(
        prepare_code == expected_prepare,
        "PreparedExec prepare semantic body differs",
    )
    ordered(
        prepare_code,
        [
            "matchcomponent",
            "Some(policy)",
            ".prepare_ssh_exec_profile(",
            "Err(SshExecProfilePrepareError::Failed)",
            "Err(SshExecProfilePrepareError::Reject)=>returnOk(Self::Reject)",
            "None=>None",
            "Ok(Self::Execute{",
        ],
        "profile preparation",
    )
    require(
        "Ok(profile)=>profile" in prepare_code,
        "successful profile preparation does not preserve the exact permit",
    )
    require(
        'Err(SshExecProfilePrepareError::Failed)=>{returnErr("SSH exec profile preparation failed")} '.replace(
            " ", ""
        )
        in prepare_code,
        "fatal profile preparation no longer terminates the connection",
    )
    require(
        "Err(SshExecProfilePrepareError::Reject)=>returnOk(Self::Reject)"
        in prepare_code,
        "terminal profile rejection is not mapped to the commandless prepared variant",
    )
    require(
        prepare_code.count(".prepare_ssh_exec_profile(") == 1,
        "profile preparation call count differs",
    )
    require(
        "SshExecProfileTarget::new(&command,policy)" in prepare_code,
        "profile preparation is not bound to command plus accepted policy",
    )
    prepared_execute = (
        "Ok(Self::Execute{command,component,"
        '#[cfg(feature="c84-profile-request-parent")]profile,})'
    )
    require(
        prepare_code.count(prepared_execute) == 1,
        "profile preparation does not preserve the exact command/component/permit",
    )

    accept = find_function(prepared_impl, "accept", "PreparedExec accept")
    accept_code = semantic(accept.raw)
    expected_accept = (
        "fnaccept<F>(self,succeed:F)->Result<AcceptedExec,&'staticstr>"
        "whereF:FnOnce()->Result<(),&'staticstr>,{succeed()?;matchself{"
        "Self::Execute{command,component,"
        '#[cfg(feature="c84-profile-request-parent")]profile,}=>{'
        '#[cfg(feature="c84-profile-request-parent")]letprofile='
        "profile.map(SshExecProfilePermit::start).transpose()"
        '.map_err(|_|"SSHexecprofilestartfailed")?;'
        "Ok(AcceptedExec::Execute{command,component,"
        '#[cfg(feature="c84-profile-request-parent")]profile,})}'
        '#[cfg(feature="c84-profile-request-parent")]Self::Reject=>'
        "Ok(AcceptedExec::Reject{status:SSH_EXEC_PRESTART_REJECT_STATUS,}),}}"
    )
    require(
        accept_code == expected_accept,
        "PreparedExec accept semantic body differs",
    )
    ordered(
        accept_code,
        [
            "succeed()?",
            "matchself",
            "Self::Execute",
            ".map(SshExecProfilePermit::start)",
            "Ok(AcceptedExec::Execute{",
            "Self::Reject",
            "status:SSH_EXEC_PRESTART_REJECT_STATUS",
        ],
        "prepare/succeed/start/accept",
    )
    require(
        "Self::Reject=>Ok(AcceptedExec::Reject{status:SSH_EXEC_PRESTART_REJECT_STATUS,})"
        in accept_code,
        "terminal prepared rejection is not mapped to the fixed accepted rejection",
    )
    accepted_execute_source = (
        "Self::Execute{command,component,"
        '#[cfg(feature="c84-profile-request-parent")]profile,}=>{'
    )
    accepted_execute_result = (
        "Ok(AcceptedExec::Execute{command,component,"
        '#[cfg(feature="c84-profile-request-parent")]profile,})'
    )
    require(
        accept_code.count(accepted_execute_source) == 1
        and accept_code.count(accepted_execute_result) == 1,
        "profile acceptance does not preserve the exact command/component/permit",
    )
    require(
        "mem::forget" not in accept_code and "ManuallyDrop" not in accept_code,
        "accept bypasses permit Drop",
    )

    protocol_signal = find_scope(
        production, r"\benum\s+ProtocolSignal\b", "ProtocolSignal"
    )
    require(
        "Exec(AcceptedExec)" in compact(protocol_signal.code),
        "ProtocolSignal does not carry AcceptedExec",
    )

    public_gate = find_scope(
        production,
        r"\bfn\s+accepted_ssh_component_policy\b",
        "public-key Component gate",
    )
    public_code = compact(public_gate.code)
    require(
        "if!public_key_credential{returnNone;}" in public_code,
        "Component profile no longer requires a public-key credential",
    )
    require(
        ".filter(|policy|policy.matches(profile))" in public_code,
        "Component profile no longer rebinds the committed profile",
    )
    require(
        "validate_ssh_exec_with_component_name(source,policy.command_name())==Ok(true)"
        in public_code,
        "Component profile no longer requires exact one-name grammar",
    )

    session_exec = find_scope(
        production,
        r"Event::Serv\(ServEvent::SessionExec\(event\)\)\s*=>",
        "authenticated SessionExec arm",
    )
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
    require(
        session_code.count("PreparedExec::prepare(") == 1,
        "SessionExec preparation count differs",
    )
    require(
        session_code.count("event.succeed()") == 1,
        "SessionExec success response count differs",
    )

    serve = find_scope(
        production, r"\basync\s+fn\s+serve_connection\b", "SSH request parent"
    )
    serve_code = compact(serve.code)
    exec_arm = find_scope(
        serve.raw,
        r"\bSessionStart::Exec\(accepted\)\s*=>",
        "accepted exec request-parent arm",
    )
    exec_arm_code = semantic(exec_arm.raw)
    reject_prefix = (
        "SessionStart::Exec(accepted)=>{"
        '#[cfg(feature="c84-profile-request-parent")]'
        "ifletAcceptedExec::Reject{status}=&accepted{"
    )
    require(
        exec_arm_code.startswith(reject_prefix),
        "terminal Reject drain is not the first executable branch in the exec arm",
    )
    require(
        exec_arm_code.count("AcceptedExec::Reject") == 1,
        "exec arm contains an alternate terminal Reject branch",
    )
    reject = find_scope(
        serve.raw,
        r"\bif\s+let\s+AcceptedExec::Reject\s*\{\s*status\s*\}\s*=\s*&accepted",
        "terminal Reject drain",
    )
    reject_code = semantic(reject.raw)
    require(
        reject_code
        == (
            "ifletAcceptedExec::Reject{status}=&accepted{letstatus=*status;letmutprofile_run=None;"
            "returnmatchfinish_exec(&mutrunner,&mutsigner,space,control,bound_epoch,policy,stack,"
            "&mutbridge,&mutprotocol,&mutprofile_run,&[],status,require_carrier,).await{"
            "Ok(())=>ConnectionEnd::ExecComplete(status),"
            "Err(ConnectionEnd::Reset(reason))=>reset_connection(stack,reason),Err(other)=>other,};}"
        ),
        "terminal Reject does not use the existing empty-output completion drain",
    )
    for forbidden in (
        "command",
        "component",
        "profile.start",
        "execute_with_network",
        "execute_stream_with_network",
        "ssh_exec_component_completed",
    ):
        require(
            forbidden not in reject.raw,
            f"terminal Reject enters execution via {forbidden!r}",
        )

    arm_reject = find_scope(
        exec_arm.raw,
        r"\bif\s+let\s+AcceptedExec::Reject\s*\{\s*status\s*\}\s*=\s*&accepted",
        "exec-arm terminal Reject drain",
    )
    exec_arm_without_reject = (
        exec_arm.raw[: arm_reject.start]
        + " " * (arm_reject.end - arm_reject.start)
        + exec_arm.raw[arm_reject.end :]
    )
    exec_identity_code = semantic(exec_arm_without_reject)
    feature_execute_binding = (
        '#[cfg(feature="c84-profile-request-parent")]'
        "letAcceptedExec::Execute{command,component:accepted_component,"
        "profile:mutprofile_run,}=acceptedelse{"
        'unreachable!("rejectedSSHexecreturnedbeforecommandexecution")};'
    )
    legacy_execute_binding = (
        '#[cfg(not(feature="c84-profile-request-parent"))]'
        "letAcceptedExec::Execute{command,component:accepted_component,}=accepted;"
    )
    require(
        exec_identity_code.count(feature_execute_binding) == 1
        and exec_identity_code.count(legacy_execute_binding) == 1,
        "accepted exec fields are not bound by the two exact cfg-exclusive destructures",
    )
    masked_exec_identity = rust_mask(exec_arm_without_reject)
    for identifier, expected_count in (
        ("accepted", 3),
        ("command", 4),
        ("accepted_component", 5),
        ("profile_run", 4),
    ):
        actual_count = len(re.findall(rf"\b{identifier}\b", masked_exec_identity))
        require(
            actual_count == expected_count,
            f"accepted exec identity {identifier!r} occurrence count differs: "
            f"{actual_count}",
        )
    require(
        exec_identity_code.count(
            ".then(||space.open_streaming_exec(&command)).flatten()"
        )
        == 1,
        "streaming execution is not bound to the accepted command",
    )
    execute_identity = (
        "letexecution=execute_with_network(&command,&mutrunner,&mutsigner,space,"
        "control,bound_epoch,policy,stack,&mutbridge,&mutprotocol,"
        '#[cfg(feature="c84-profile-phase-sidecar")]&mutprofile_run,'
        "require_carrier,accepted_component,).await;"
    )
    require(
        exec_identity_code.count(execute_identity) == 1,
        "managed execution is not bound to the accepted command/component/run",
    )
    require(
        exec_identity_code.count(
            "ifletSome(component)=accepted_component{"
            "space.ssh_exec_component_completed(component,status);}"
        )
        == 1,
        "component completion is not bound to the accepted component",
    )

    serve_without_reject = (
        serve.raw[: reject.start]
        + " " * (reject.end - reject.start)
        + serve.raw[reject.end :]
    )
    serve_semantic = semantic(serve_without_reject)
    require(
        "SessionStart::Exec(accepted)" in serve_code,
        "request parent does not receive AcceptedExec",
    )
    require(
        semantic(serve.raw).find("ifletAcceptedExec::Reject")
        < semantic(serve.raw).find("letAcceptedExec::Execute"),
        "terminal Reject is destructured as an executable command first",
    )
    require(
        "profile:mutprofile_run" in serve_code, "request parent does not retain the run"
    )
    phase_sidecar_borrow = '#[cfg(feature="c84-profile-phase-sidecar")]&mutprofile_run'
    require(
        serve_semantic.count(phase_sidecar_borrow) == 1,
        "request parent phase-sidecar borrow is not one exact guarded transport borrow",
    )
    completion_code = serve_semantic.replace(phase_sidecar_borrow, "")
    require(
        completion_code.count("&mutprofile_run") == 2,
        "request parent does not pass its run to both exec completion paths",
    )
    execute_call = re.search(r"execute_with_network\((.*?)\)\.await", serve_semantic)
    require(execute_call is not None, "managed execution call is missing")
    execute_arguments = execute_call.group(1)
    require(
        execute_arguments.count(phase_sidecar_borrow) == 1
        and "profile_run" not in execute_arguments.replace(phase_sidecar_borrow, ""),
        "request run escaped its exact guarded phase-sidecar transport borrow",
    )

    reach = find_scope(
        production,
        r"\bfn\s+reach_profile_response_boundary\b",
        "response-boundary take helper",
    )
    cfg_guarded(production, reach.start, "response-boundary take helper")
    reach_code = compact(reach.code)
    ordered(
        reach_code,
        ["profile_run.take()", "run.response_boundary(status)"],
        "response-boundary take",
    )
    require(
        reach_code.count("profile_run.take()") == 1,
        "response boundary is not consume-once",
    )

    finish_exec = find_scope(
        production, r"\basync\s+fn\s+finish_exec\b", "SSH exec completion"
    )
    finish_code = compact(finish_exec.code)
    require(
        "profile_run:&mutOption<SshExecProfileRun>" in finish_code,
        "finish_exec does not borrow the parent-owned run",
    )
    reaches = [
        match.start()
        for match in re.finditer(
            re.escape("reach_profile_response_boundary(profile_run,status)?;"),
            finish_code,
        )
    ]
    progresses = [
        match.start()
        for match in re.finditer(re.escape("progress_protocol("), finish_code)
    ]
    tcp_finishes = [
        match.start()
        for match in re.finditer(re.escape("finish_tcp_after_ssh("), finish_code)
    ]
    require(
        len(reaches) == 2,
        f"response-boundary completion-site count differs: {len(reaches)}",
    )
    require(
        len(progresses) == 1,
        f"finish_exec protocol-progress count differs: {len(progresses)}",
    )
    require(
        len(tcp_finishes) == 2,
        f"finish_exec TCP-finish count differs: {len(tcp_finishes)}",
    )
    require(
        reaches[0] < progresses[0] < tcp_finishes[0],
        "Defunct response boundary is not recorded before protocol progress/TCP teardown",
    )
    require(
        progresses[0] < reaches[1] < tcp_finishes[1],
        "ordinary response boundary is not recorded before TCP teardown",
    )
    require(
        "completion_confirmed_before_progress{reach_profile_response_boundary"
        in finish_code,
        "pre-progress response call is not guarded by the complete response predicate",
    )
    bottom_predicate = (
        "ifclose_sent&&protocol.channel.is_none()&&runner.is_output_drained(){"
    )
    bottom = finish_code.rfind(bottom_predicate)
    require(
        bottom >= 0 and bottom < reaches[1],
        "ordinary response call is not guarded by the complete response predicate",
    )

    finish_tcp = find_scope(
        production, r"\basync\s+fn\s+finish_tcp_after_ssh\b", "TCP teardown"
    )
    require(
        "SshExecProfile" not in finish_tcp.raw
        and "response_boundary" not in finish_tcp.raw,
        "profile ownership escaped into TCP teardown",
    )
    finish_tcp_code = compact(finish_tcp.code)
    require(
        "ifnetwork.connection_ended||stack.is_listening(){returnOk(());}"
        in finish_tcp_code,
        "TCP completion does not hand a replacement generation to fresh ownership",
    )

    capability_transport = find_scope(
        production,
        r"\bimpl\s+TcpTransport\s+for\s+CapabilityTcpTransport<'_>",
        "capability TCP transport",
    )
    capability_poll = find_function(
        capability_transport, "poll_network", "capability TCP poll"
    )
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

    wait_connection = find_scope(
        production, r"\basync\s+fn\s+wait_for_connection\b", "fresh connection wait"
    )
    require(
        "if!report.connection_ended&&matches!(stack.stream_status().state,TcpStreamState::Established|TcpStreamState::PeerClosed)"
        in compact(wait_connection.code),
        "fresh connection wait can return on the retired generation",
    )
    rearm = find_scope(production, r"\basync\s+fn\s+rearm_listener\b", "listener rearm")
    require(
        "ifreport.connection_started||stack.is_listening(){returnOk(());}"
        in compact(rearm.code),
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
    require(
        kernel_features.get(TRUSTED_SAMPLE_FEATURE)
        == [FINISH_FEATURE, "vibeos-sshd/c84-profile-trusted-sample"],
        "kernel trusted-sample feature closure differs",
    )
    require(
        kernel_features.get(TRUSTED_SAMPLE_QEMU_FEATURE)
        == [TRUSTED_SAMPLE_FEATURE, FINISH_QEMU_FEATURE],
        "kernel trusted-sample QEMU closure differs",
    )
    trusted_closure = local_feature_closure(kernel_features, [TRUSTED_SAMPLE_FEATURE])
    verified_closure = local_feature_closure(kernel_features, [VERIFIED_STREAM_FEATURE])
    require(
        KERNEL_FEATURE in trusted_closure and FINISH_FEATURE in trusted_closure,
        "trusted-sample does not inherit the request parent through finish/verify",
    )
    require(
        VERIFIED_STREAM_FEATURE not in trusted_closure
        and TRUSTED_SAMPLE_FEATURE not in verified_closure,
        "trusted-sample and verified-stream are not sibling successors",
    )

    root_code = semantic(root_source)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(
        qemu_only in root_code, "request-parent telemetry is not guarded as QEMU-only"
    )
    isolated = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance"'
        ')))]compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(
        isolated in root_code,
        "request-parent telemetry is not isolated from other C8.4 acceptances",
    )
    mutually_exclusive = (
        f'#[cfg(all(feature="{TRUSTED_SAMPLE_FEATURE}",'
        f'feature="{VERIFIED_STREAM_FEATURE}"))]compile_error!('
        f'"features`{TRUSTED_SAMPLE_FEATURE}`and`{VERIFIED_STREAM_FEATURE}`'
        'aremutuallyexclusivefinish/verifysuccessors");'
    )
    require(
        mutually_exclusive in root_code,
        "trusted-sample and verified-stream lack their exact mutual-exclusion guard",
    )

    full_platform = find_scope(
        source,
        r"\bimpl\s+SshdPlatform\s+for\s+SshPlatform\b",
        "full kernel SSH Platform impl",
    )
    full_prepare_hook = find_function(
        full_platform,
        "prepare_ssh_exec_profile",
        "full kernel prepare hook",
    )
    full_prepare_code = semantic(full_prepare_hook.raw)
    collector_reject = (
        '#[cfg(feature="wasm-c84-ssh-managed-child-single-boot-collector")]'
        "Err(error)ifcrate::wasm_aot_profile_slot::collector_terminal_reject(error)=>{"
        "returnErr(SshExecProfilePrepareError::Reject);}"
    )
    require(
        collector_reject in full_prepare_code,
        "collector terminal condition is not the sole deliberate pre-start rejection",
    )
    require(
        full_prepare_code.count("SshExecProfilePrepareError::Reject") == 1
        and full_prepare_code.count("SshExecProfilePrepareError::Failed") == 3,
        "kernel prepare error classification count differs",
    )
    require(
        full_prepare_code.find(collector_reject) < full_prepare_code.find("Err(_)=>{"),
        "collector terminal rejection is shadowed by the ordinary failure fallback",
    )
    require(
        full_prepare_code.find("SshExecProfilePrepareError::Reject")
        < full_prepare_code.find("SshExecProfilePermit::new"),
        "collector terminal rejection is mapped after constructing a permit",
    )
    require(
        "profile_request_start" not in full_prepare_hook.raw,
        "kernel logs or starts a target before terminal rejection",
    )

    # The committed request-parent contract remains cancel-only. Ignore only
    # syntax units directly guarded by the exact finish/verify successor; broad
    # or indirect cfg forms remain visible and therefore fail predecessor checks.
    production = without_direct_feature_units(source, FINISH_FEATURE)
    production = without_direct_feature_units(production, FINISH_QEMU_FEATURE)
    production = without_direct_feature_units(production, VERIFIED_STREAM_FEATURE)
    production = without_direct_feature_units(production, VERIFIED_STREAM_QEMU_FEATURE)
    production = without_direct_feature_units(production, TRUSTED_SAMPLE_FEATURE)
    production = without_direct_feature_units(production, TRUSTED_SAMPLE_QEMU_FEATURE)

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
    platform = find_scope(
        production,
        r"\bimpl\s+SshdPlatform\s+for\s+SshPlatform\b",
        "kernel SSH Platform impl",
    )
    prepare_hook = find_function(
        platform, "prepare_ssh_exec_profile", "kernel prepare hook"
    )
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
        require(
            token in prepare_code,
            f"kernel exact case-filter preparation is missing {token!r}",
        )
    for failure, label in (
        (
            'profile_request_failure("policy-missing",None);'
            "returnErr(SshExecProfilePrepareError::Failed);",
            "missing policy",
        ),
        (
            'profile_request_failure("policy-mismatch",None);'
            "returnErr(SshExecProfilePrepareError::Failed);",
            "mismatched policy",
        ),
        (
            'Err(_)=>{profile_request_failure("prepare",None);'
            "returnErr(SshExecProfilePrepareError::Failed);}",
            "ordinary slot preparation error",
        ),
    ):
        require(
            failure in prepare_code, f"kernel {label} is not a fatal prepare failure"
        )
    require(
        "Ok(permit)=>permit" in prepare_code,
        "kernel successful slot preparation does not preserve the exact permit",
    )
    require(
        "Ok(Some(SshExecProfilePermit::new(SshExecProfileOwner::reserved(accepted,permit),)))"
        in prepare_code,
        "kernel successful preparation does not return the exact reserved permit",
    )
    require(
        "native-case-filter" not in prepare_hook.raw,
        "native Component can arm the profile parent",
    )

    owner_state = find_scope(
        production, r"\benum\s+SshExecProfileOwnerState\b", "kernel profile owner state"
    )
    require(
        compact(owner_state.code).count("Reserved(") == 1
        and compact(owner_state.code).count("Active(") == 1
        and "Closed" in owner_state.code,
        "kernel owner is not the exact Reserved/Active/Closed typestate",
    )
    owner_impl = find_scope(
        production, r"\bimpl\s+SshExecProfileOwner\b", "kernel profile owner impl"
    )
    owner_start = find_function(owner_impl, "start", "kernel owner start")
    owner_response = find_function(
        owner_impl, "response_boundary", "kernel owner response"
    )
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
        "Reserved(permit)" in owner_start.code
        and "permit.start()" in compact(owner_start.code),
        "kernel owner start is not the sole Reserved -> Active transition",
    )
    response_code = compact(owner_response.code)
    require(
        "Active(run)" in owner_response.code
        and response_code.count(
            "cancel_and_ack_profile(run,crate::wasm_aot_profile_slot::SlotFaults::default())"
        )
        == 1
        and response_code.count("profile_request_response(epoch,status,ready_epoch)")
        == 1,
        "response boundary does not close and report one exact active run",
    )
    cancel_code = compact(owner_cancel.code)
    require(
        cancel_code.count("Reserved(permit)=>drop(permit)") == 1
        and cancel_code.count("cancel_and_ack_profile(run,expected_faults)") == 1
        and cancel_code.count(
            "letexpected_faults=crate::wasm_aot_profile_slot::SlotFaults::default();"
        )
        == 1
        and "Closed=>{}" in cancel_code,
        "permit/run Drop cleanup is not exactly-once and closed-idempotent",
    )

    for backend, label in ((prepare_impl, "permit backend"), (run_impl, "run backend")):
        cancel = find_function(backend, "cancel", f"{label} cancel")
        require(
            compact(cancel.code).count("SshExecProfileOwner::cancel(self)") == 1,
            f"{label} does not delegate to the shared owner close path exactly once",
        )
    backend_response = find_function(
        run_impl, "response_boundary", "kernel backend response"
    )
    require(
        compact(backend_response.code).count(
            "SshExecProfileOwner::response_boundary(self,status)"
        )
        == 1,
        "run backend response does not delegate to the owner boundary exactly once",
    )
    owner_drop = find_scope(
        production, r"\bimpl\s+Drop\s+for\s+SshExecProfileOwner\b", "kernel owner Drop"
    )
    require(
        compact(find_function(owner_drop, "drop", "kernel owner Drop body").code).count(
            "self.cancel()"
        )
        == 1,
        "kernel backend Drop does not share the idempotent cancel path",
    )

    close = find_scope(
        production, r"\bfn\s+cancel_and_ack_profile\b", "kernel profile close path"
    )
    close_code = compact(close.code)
    require(
        "expected_slot_faults:crate::wasm_aot_profile_slot::SlotFaults" in close_code,
        "kernel close path does not bind one exact expected child-fault set",
    )
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
    require(
        close_code.count(".cancel()") == 1,
        "kernel close path cancels more or less than once",
    )
    require(
        close_code.count("rejection()") == 1,
        "kernel close path does not read the stored rejection exactly once",
    )
    require(
        close_code.count("acknowledge_rejection(") == 1,
        "kernel close path does not acknowledge exactly once",
    )
    require(
        "stored_rejection_is_exact=rejection()==Some(report)" in close_code,
        "kernel close path does not compare the stored rejection with the cancel report",
    )
    require(
        "report.slot_faults==expected_slot_faults" in close_code,
        "kernel close path does not compare the returned child faults exactly",
    )
    require(
        "acknowledged==report" in close_code,
        "kernel close path does not compare acknowledged and returned rejection",
    )
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

    integration = (
        owner_impl.raw + prepare_impl.raw + run_impl.raw + close.raw + prepare_hook.raw
    )
    integration_code = compact(rust_mask(integration))
    require(
        ".finish(" not in integration_code,
        "request-parent backend fabricates a finished profile",
    )
    for forbidden in (
        "StreamLease",
        "stream_verified",
        "publish_profile",
        "physical_evidence",
    ):
        require(
            forbidden not in integration, f"request-parent backend exposes {forbidden}"
        )

    # Telemetry exists only under the QEMU child feature. The base/default
    # feature stays silent and cannot be mistaken for physical evidence.
    for function in (
        "profile_request_start",
        "profile_request_response",
        "profile_request_drop",
    ):
        marker_scope = find_scope(
            production, rf"\bfn\s+{function}\b", f"{function} telemetry"
        )
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


LEGACY_CANCEL = "legacy-cancel"
FINISH_VERIFY = "finish-verify"
VERIFIED_STREAM = "verified-stream"


def response_terminal_suffix(terminal_mode: str) -> str:
    require(
        terminal_mode in (LEGACY_CANCEL, FINISH_VERIFY, VERIFIED_STREAM),
        f"unknown request-parent terminal mode: {terminal_mode!r}",
    )
    if terminal_mode == LEGACY_CANCEL:
        return "cancel=1 ack=1"
    if terminal_mode == FINISH_VERIFY:
        return "finish=1 verify=1 discard=stream_abandoned ack=1"
    return "finish=1 verify=1 stream=complete ack=0"


def expected_qemu_markers(terminal_mode: str = LEGACY_CANCEL) -> list[str]:
    suffix = response_terminal_suffix(terminal_mode)
    return [
        "WASM_C84_SSH_REQUEST_PARENT START epoch=1",
        f"WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch=1 status=0 {suffix} ready_epoch=2",
        "WASM_C84_SSH_REQUEST_PARENT START epoch=2",
        f"WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch=2 status=0 {suffix} ready_epoch=3",
        "WASM_C84_SSH_REQUEST_PARENT START epoch=3",
        "WASM_C84_SSH_REQUEST_PARENT DROP epoch=3 cancel=1 ack=1 ready_epoch=4",
        "WASM_C84_SSH_REQUEST_PARENT START epoch=4",
        f"WASM_C84_SSH_REQUEST_PARENT RESPONSE epoch=4 status=0 {suffix} ready_epoch=5",
    ]


# Compatibility export for every already-committed predecessor gate. Successor
# peers opt into a successor mode explicitly and cannot mutate this frozen list.
EXPECTED_QEMU_MARKERS = expected_qemu_markers()


def normalize_serial_line(line: str) -> str:
    clear = "\x1b[2K"
    return line[len(clear) :] if line.startswith(clear) else line


def verify_qemu_transcript(raw: bytes, terminal_mode: str = LEGACY_CANCEL) -> None:
    transcript = raw.decode("utf-8", errors="replace").replace("\r", "\n")
    lines = [normalize_serial_line(line) for line in transcript.splitlines()]
    require(
        not any(f"{QEMU_FAMILY} FAIL" in line for line in lines),
        "QEMU guest reported a request-parent failure",
    )
    require(
        not any(
            re.search(r"\[!\]\s+(?:fatal|panic)|panicked at", line) for line in lines
        ),
        "QEMU guest reported a panic or fatal error",
    )
    family = [line for line in lines if QEMU_FAMILY in line]
    expected = expected_qemu_markers(terminal_mode)
    require(
        family == expected,
        f"QEMU request-parent marker sequence differs: observed={family!r}",
    )


def run_transcript_selftest() -> int:
    valid = "\n".join(["boot", *EXPECTED_QEMU_MARKERS, "listener rearmed", ""])
    verify_qemu_transcript(valid.encode())
    mutations = [
        valid.replace(EXPECTED_QEMU_MARKERS[0] + "\n", "", 1),
        valid.replace(
            EXPECTED_QEMU_MARKERS[1],
            EXPECTED_QEMU_MARKERS[1].replace("ack=1", "ack=2"),
            1,
        ),
        valid.replace(
            EXPECTED_QEMU_MARKERS[3],
            EXPECTED_QEMU_MARKERS[3].replace("ready_epoch=3", "ready_epoch=2"),
            1,
        ),
        valid.replace(
            EXPECTED_QEMU_MARKERS[5],
            EXPECTED_QEMU_MARKERS[5].replace("DROP", "RESPONSE status=0"),
            1,
        ),
        valid.replace(
            EXPECTED_QEMU_MARKERS[7],
            EXPECTED_QEMU_MARKERS[7] + "\n" + EXPECTED_QEMU_MARKERS[7],
            1,
        ),
        valid + f"{QEMU_FAMILY} FAIL stage=synthetic epoch=4\n",
        valid + "panicked at synthetic post-response fault\n",
    ]
    for index, mutation in enumerate(mutations, start=1):
        try:
            verify_qemu_transcript(mutation.encode())
        except VerificationError:
            continue
        raise VerificationError(
            f"QEMU transcript selftest mutation {index} was accepted"
        )

    successor_markers = expected_qemu_markers(FINISH_VERIFY)
    successor = "\n".join(["boot", *successor_markers, "listener rearmed", ""])
    verify_qemu_transcript(successor.encode(), FINISH_VERIFY)
    successor_mutations = [
        successor.replace("finish=1 verify=1", "finish=1 verify=0", 1),
        successor.replace("discard=stream_abandoned", "discard=complete", 1),
        successor.replace(successor_markers[3], EXPECTED_QEMU_MARKERS[3], 1),
        successor.replace(
            successor_markers[5],
            successor_markers[5].replace("cancel=1", "finish=1"),
            1,
        ),
    ]
    for index, mutation in enumerate(successor_mutations, start=1):
        try:
            verify_qemu_transcript(mutation.encode(), FINISH_VERIFY)
        except VerificationError:
            continue
        raise VerificationError(
            f"successor QEMU transcript selftest mutation {index} was accepted"
        )
    try:
        verify_qemu_transcript(successor.encode(), LEGACY_CANCEL)
    except VerificationError:
        pass
    else:
        raise VerificationError(
            "legacy terminal mode accepted the successor transcript"
        )

    stream_markers = expected_qemu_markers(VERIFIED_STREAM)
    stream = "\n".join(["boot", *stream_markers, "listener rearmed", ""])
    verify_qemu_transcript(stream.encode(), VERIFIED_STREAM)
    stream_mutations = [
        stream.replace("stream=complete", "stream=partial", 1),
        stream.replace("ack=0", "ack=1", 1),
        stream.replace(stream_markers[3], successor_markers[3], 1),
        stream.replace(
            stream_markers[5], stream_markers[5].replace("cancel=1", "complete=1"), 1
        ),
    ]
    for index, mutation in enumerate(stream_mutations, start=1):
        try:
            verify_qemu_transcript(mutation.encode(), VERIFIED_STREAM)
        except VerificationError:
            continue
        raise VerificationError(
            f"verified-stream QEMU transcript selftest mutation {index} was accepted"
        )
    for wrong_mode in (LEGACY_CANCEL, FINISH_VERIFY):
        try:
            verify_qemu_transcript(stream.encode(), wrong_mode)
        except VerificationError:
            continue
        raise VerificationError(f"{wrong_mode} accepted the verified-stream transcript")
    return len(mutations) + len(successor_mutations) + len(stream_mutations) + 3


def replace_once(value: str, old: str, new: str, label: str) -> str:
    require(
        value.count(old) == 1,
        f"selftest seed {label!r} count differs: {value.count(old)}",
    )
    return value.replace(old, new, 1)


def expect_rejected(
    inputs: Inputs, mutate: Callable[[Inputs], Inputs], label: str
) -> None:
    mutated = mutate(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify(mutated)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def sshd_failed_prepare_becomes_reject(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "Err(SshExecProfilePrepareError::Failed) => {\n"
        '                        return Err("SSH exec profile preparation failed")\n'
        "                    }",
        "Err(SshExecProfilePrepareError::Failed) => return Ok(Self::Reject),",
        "sshd-failed-prepare-becomes-reject",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_successful_prepare_drops_permit(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "Ok(profile) => profile,",
        "Ok(_) => None,",
        "sshd-successful-prepare-drops-permit",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_reject_prepare_becomes_fatal(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "Err(SshExecProfilePrepareError::Reject) => return Ok(Self::Reject),",
        'Err(SshExecProfilePrepareError::Reject) => return Err("synthetic fatal"),',
        "sshd-reject-prepare-becomes-fatal",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_prepare_profile_shadowed(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        '        };\n        #[cfg(not(feature = "c84-profile-request-parent"))]\n',
        "        };\n"
        '        #[cfg(feature = "c84-profile-request-parent")]\n'
        "        let profile = None;\n"
        '        #[cfg(not(feature = "c84-profile-request-parent"))]\n',
        "prepare-profile-shadowed",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_prepared_command_shadowed(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "        let _ = space;\n\n        Ok(Self::Execute {",
        "        let _ = space;\n\n"
        "        let command = String::new();\n"
        "        Ok(Self::Execute {",
        "prepared-command-shadow",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_dead_succeed(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "        succeed()?;\n        match self {",
        "        if false {\n            succeed()?;\n        }\n        match self {",
        "sshd-dead-succeed",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_dead_start(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        '                #[cfg(feature = "c84-profile-request-parent")]\n'
        "                let profile = profile\n"
        "                    .map(SshExecProfilePermit::start)\n"
        "                    .transpose()\n"
        '                    .map_err(|_| "SSH exec profile start failed")?;\n',
        '                #[cfg(feature = "c84-profile-request-parent")]\n'
        "                let profile = if false {\n"
        "                    profile\n"
        "                        .map(SshExecProfilePermit::start)\n"
        "                        .transpose()\n"
        '                        .map_err(|_| "SSH exec profile start failed")?\n'
        "                } else {\n"
        "                    None\n"
        "                };\n",
        "sshd-dead-start",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_accepted_command_shadowed(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        '                    .map_err(|_| "SSH exec profile start failed")?;\n'
        "                Ok(AcceptedExec::Execute {",
        '                    .map_err(|_| "SSH exec profile start failed")?;\n'
        "                let command = String::new();\n"
        "                Ok(AcceptedExec::Execute {",
        "accepted-command-shadow",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_early_reject_bypass(data: Inputs) -> Inputs:
    reject = (
        '            #[cfg(feature = "c84-profile-request-parent")]\n'
        "            if let AcceptedExec::Reject { status } = &accepted {\n"
    )
    changed = replace_once(
        data.sshd,
        reject,
        '            #[cfg(feature = "c84-profile-request-parent")]\n'
        "            if matches!(&accepted, AcceptedExec::Reject { .. }) {\n"
        "                return ConnectionEnd::ExecComplete(\n"
        "                    SSH_EXEC_PRESTART_REJECT_STATUS,\n"
        "                );\n"
        "            }\n" + reject,
        "sshd-early-reject-bypass",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_execution_command_shadowed(data: Inputs) -> Inputs:
    anchor = (
        "                component: accepted_component,\n"
        "            } = accepted;\n"
        '            #[cfg(feature = "qualification-stream")]\n'
    )
    changed = replace_once(
        data.sshd,
        anchor,
        "                component: accepted_component,\n"
        "            } = accepted;\n"
        "            let command = String::new();\n"
        '            #[cfg(feature = "qualification-stream")]\n',
        "execution-command-shadow",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_execution_component_shadowed(data: Inputs) -> Inputs:
    anchor = (
        "                component: accepted_component,\n"
        "            } = accepted;\n"
        '            #[cfg(feature = "qualification-stream")]\n'
    )
    changed = replace_once(
        data.sshd,
        anchor,
        "                component: accepted_component,\n"
        "            } = accepted;\n"
        "            let accepted_component = None;\n"
        '            #[cfg(feature = "qualification-stream")]\n',
        "execution-component-shadow",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_execution_profile_shadowed(data: Inputs) -> Inputs:
    anchor = (
        "                component: accepted_component,\n"
        "            } = accepted;\n"
        '            #[cfg(feature = "qualification-stream")]\n'
    )
    changed = replace_once(
        data.sshd,
        anchor,
        "                component: accepted_component,\n"
        "            } = accepted;\n"
        '            #[cfg(feature = "c84-profile-request-parent")]\n'
        "            let mut profile_run = None;\n"
        '            #[cfg(feature = "qualification-stream")]\n',
        "execution-profile-shadow",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_prepared_command_substituted(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "        Ok(Self::Execute {\n            command,\n            component,",
        "        Ok(Self::Execute {\n"
        "            command: String::new(),\n"
        "            component,",
        "sshd-prepared-command-substituted",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_accepted_command_substituted(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "                Ok(AcceptedExec::Execute {\n"
        "                    command,\n"
        "                    component,",
        "                Ok(AcceptedExec::Execute {\n"
        "                    command: String::new(),\n"
        "                    component,",
        "sshd-accepted-command-substituted",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def sshd_accepted_component_dropped(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd,
        "                Ok(AcceptedExec::Execute {\n"
        "                    command,\n"
        "                    component,",
        "                Ok(AcceptedExec::Execute {\n"
        "                    command,\n"
        "                    component: None,",
        "sshd-accepted-component-dropped",
    )
    return Inputs(
        changed,
        data.sshd_manifest,
        data.kernel,
        data.kernel_manifest,
        data.kernel_root,
    )


def kernel_collector_reject_becomes_failed(data: Inputs) -> Inputs:
    changed = replace_once(
        data.kernel,
        "Err(error) if crate::wasm_aot_profile_slot::collector_terminal_reject(error) => {\n"
        "                return Err(SshExecProfilePrepareError::Reject);\n"
        "            }",
        "Err(error) if crate::wasm_aot_profile_slot::collector_terminal_reject(error) => {\n"
        "                return Err(SshExecProfilePrepareError::Failed);\n"
        "            }",
        "kernel-collector-reject-becomes-failed",
    )
    return Inputs(
        data.sshd,
        data.sshd_manifest,
        changed,
        data.kernel_manifest,
        data.kernel_root,
    )


def kernel_collector_reject_logs_start(data: Inputs) -> Inputs:
    changed = replace_once(
        data.kernel,
        "Err(error) if crate::wasm_aot_profile_slot::collector_terminal_reject(error) => {\n",
        "Err(error) if crate::wasm_aot_profile_slot::collector_terminal_reject(error) => {\n"
        "                profile_request_start(0);\n",
        "kernel-collector-reject-logs-start",
    )
    return Inputs(
        data.sshd,
        data.sshd_manifest,
        changed,
        data.kernel_manifest,
        data.kernel_root,
    )


def kernel_policy_missing_becomes_reject(data: Inputs) -> Inputs:
    changed = replace_once(
        data.kernel,
        'profile_request_failure("policy-missing", None);\n'
        "            return Err(SshExecProfilePrepareError::Failed);",
        'profile_request_failure("policy-missing", None);\n'
        "            return Err(SshExecProfilePrepareError::Reject);",
        "kernel-policy-missing-becomes-reject",
    )
    return Inputs(
        data.sshd,
        data.sshd_manifest,
        changed,
        data.kernel_manifest,
        data.kernel_root,
    )


def move_succeed_after_start(data: Inputs) -> Inputs:
    changed = replace_once(
        data.sshd, "        succeed()?;\n", "", "start-before-succeed/remove"
    )
    changed = replace_once(
        changed,
        "                Ok(AcceptedExec::Execute {\n",
        "                succeed()?;\n                Ok(AcceptedExec::Execute {\n",
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
    return Inputs(
        data.sshd, data.sshd_manifest, changed, data.kernel_manifest, data.kernel_root
    )


def remove_qemu_only_guard(data: Inputs) -> Inputs:
    guard = (
        "#[cfg(all(\n"
        '    feature = "wasm-c84-ssh-request-parent-qemu-acceptance",\n'
        '    not(feature = "qemu-virt")\n'
        "))]\n"
        'compile_error!("feature `wasm-c84-ssh-request-parent-qemu-acceptance` is QEMU-only");\n\n'
    )
    changed = replace_once(
        data.kernel_root, guard, "", "request-parent-qemu-only-guard"
    )
    return Inputs(
        data.sshd, data.sshd_manifest, data.kernel, data.kernel_manifest, changed
    )


def remove_acceptance_isolation_guard(data: Inputs) -> Inputs:
    guard = (
        "#[cfg(all(\n"
        '    feature = "wasm-c84-ssh-request-parent-qemu-acceptance",\n'
        "    any(\n"
        '        feature = "wasm-c48-qemu-acceptance",\n'
        '        feature = "wasm-c84-profile-slot-qemu-acceptance",\n'
        '        feature = "wasm-c84-core-poll-qemu-acceptance",\n'
        '        feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",\n'
        '        feature = "wasm-c84-profile-child-delegation-qemu-acceptance"\n'
        "    )\n"
        "))]\n"
        'compile_error!("C8.4 QEMU acceptances are isolated images");\n\n'
    )
    changed = replace_once(
        data.kernel_root, guard, "", "request-parent-acceptance-isolation"
    )
    return Inputs(
        data.sshd, data.sshd_manifest, data.kernel, data.kernel_manifest, changed
    )


def run_selftest(inputs: Inputs) -> int:
    verify(inputs)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "feature-default-on",
            lambda data: Inputs(
                data.sshd,
                replace_once(
                    data.sshd_manifest.decode(),
                    "default = []",
                    f'default = ["{FEATURE}"]',
                    "feature-default-on",
                ).encode(),
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "target-feature-guard-removed",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    '#[cfg(feature = "c84-profile-request-parent")]\n#[derive(Clone, Copy)]\npub struct SshExecProfileTarget',
                    "#[derive(Clone, Copy)]\npub struct SshExecProfileTarget",
                    "target-feature-guard",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "public-key-gate-removed",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "if !public_key_credential {",
                    "if false {",
                    "public-key-gate",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "start-before-succeed",
            move_succeed_after_start,
        ),
        (
            "sshd-dead-succeed",
            sshd_dead_succeed,
        ),
        (
            "sshd-dead-start",
            sshd_dead_start,
        ),
        (
            "sshd-failed-prepare-becomes-reject",
            sshd_failed_prepare_becomes_reject,
        ),
        (
            "sshd-successful-prepare-drops-permit",
            sshd_successful_prepare_drops_permit,
        ),
        (
            "sshd-reject-prepare-becomes-fatal",
            sshd_reject_prepare_becomes_fatal,
        ),
        (
            "prepare-profile-shadowed",
            sshd_prepare_profile_shadowed,
        ),
        (
            "prepared-command-shadow",
            sshd_prepared_command_shadowed,
        ),
        (
            "sshd-prepared-command-substituted",
            sshd_prepared_command_substituted,
        ),
        (
            "accepted-command-shadow",
            sshd_accepted_command_shadowed,
        ),
        (
            "sshd-accepted-command-substituted",
            sshd_accepted_command_substituted,
        ),
        (
            "sshd-accepted-component-dropped",
            sshd_accepted_component_dropped,
        ),
        (
            "sshd-early-reject-bypass",
            sshd_early_reject_bypass,
        ),
        (
            "execution-command-shadow",
            sshd_execution_command_shadowed,
        ),
        (
            "execution-component-shadow",
            sshd_execution_component_shadowed,
        ),
        (
            "execution-profile-shadow",
            sshd_execution_profile_shadowed,
        ),
        (
            "kernel-collector-reject-becomes-failed",
            kernel_collector_reject_becomes_failed,
        ),
        (
            "kernel-collector-reject-logs-start",
            kernel_collector_reject_logs_start,
        ),
        (
            "kernel-policy-missing-becomes-reject",
            kernel_policy_missing_becomes_reject,
        ),
        (
            "permit-drop-cancel-removed",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "            backend.cancel();\n        }\n    }\n}\n\n/// Linear ownership held",
                    "            let _ = backend;\n        }\n    }\n}\n\n/// Linear ownership held",
                    "permit-drop-cancel",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "response-not-consume-once",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "let Some(run) = profile_run.take()",
                    "let Some(run) = profile_run.as_mut()",
                    "response-take",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "phase-sidecar-run-borrow-widened",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    '                #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                    "                &mut profile_run,\n",
                    "                &mut profile_run,\n",
                    "phase-sidecar-run-borrow-widened",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "pre-progress-boundary-removed",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "        if completion_confirmed_before_progress {\n            reach_profile_response_boundary(profile_run, status)?;\n        }",
                    "        if completion_confirmed_before_progress {}",
                    "pre-progress-boundary",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "ordinary-boundary-removed",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "            reach_profile_response_boundary(profile_run, status)?;\n            return finish_tcp_after_ssh(",
                    "            return finish_tcp_after_ssh(",
                    "ordinary-boundary",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "tcp-generation-rollover-ignored",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "let generation_replaced = connection_generation_replaced(self.connection, &snapshot);",
                    "let generation_replaced = false;",
                    "tcp-generation-rollover",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "accepted-token-rollover-ignored",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "let generation_replaced_after_accept =\n            connection_started && connection_generation_replaced(self.connection, &snapshot);",
                    "let generation_replaced_after_accept = false;",
                    "accepted-token-rollover",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "rearm-started-edge-ignored",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "if report.connection_started || stack.is_listening() {",
                    "if stack.is_listening() {",
                    "rearm-started-edge",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "fresh-wait-returns-retired-generation",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "if !report.connection_ended\n            && matches!(",
                    "if matches!(",
                    "fresh-wait-ended-edge",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "tcp-finish-reads-retired-token",
            lambda data: Inputs(
                replace_once(
                    data.sshd,
                    "if network.connection_ended || stack.is_listening() {",
                    "if stack.is_listening() {",
                    "tcp-finish-ended-edge",
                ),
                data.sshd_manifest,
                data.kernel,
                data.kernel_manifest,
            ),
        ),
        (
            "native-target-enabled",
            lambda data: Inputs(
                data.sshd,
                data.sshd_manifest,
                replace_once(
                    data.kernel,
                    'source != "case-filter"',
                    'source != "native-case-filter"',
                    "native-target",
                ),
                data.kernel_manifest,
            ),
        ),
        (
            "kernel-finish-fabrication",
            lambda data: Inputs(
                data.sshd,
                data.sshd_manifest,
                replace_once(
                    data.kernel,
                    "let report = run.cancel()",
                    "let report = run.finish()",
                    "kernel-finish",
                ),
                data.kernel_manifest,
            ),
        ),
        (
            "kernel-stored-rejection-forged",
            lambda data: Inputs(
                data.sshd,
                data.sshd_manifest,
                replace_once(
                    data.kernel,
                    "let stored_rejection_is_exact = rejection() == Some(report);\n"
                    "    // A successful cancel has already installed one diagnostic rejection.",
                    "let stored_rejection_is_exact = true;\n"
                    "    // A successful cancel has already installed one diagnostic rejection.",
                    "stored-rejection",
                ),
                data.kernel_manifest,
            ),
        ),
        (
            "kernel-ack-removed",
            lambda data: Inputs(
                data.sshd,
                data.sshd_manifest,
                replace_once(
                    data.kernel,
                    "let acknowledged = acknowledge_rejection(epoch).map_err(|_| ())?;",
                    "let acknowledged = forget_rejection(epoch).map_err(|_| ())?;",
                    "kernel-ack",
                ),
                data.kernel_manifest,
            ),
        ),
        ("kernel-permit-to-run-reboxed", rebox_permit_to_run),
        ("request-parent-qemu-only-guard-removed", remove_qemu_only_guard),
        (
            "request-parent-acceptance-isolation-removed",
            remove_acceptance_isolation_guard,
        ),
    ]
    for label, mutation in mutations:
        expect_rejected(inputs, mutation, label)
    return len(mutations) + run_transcript_selftest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-source",
        action="store_true",
        help="verify the checked-in Rust/Cargo wiring",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run in-memory source mutations against every gate",
    )
    parser.add_argument(
        "--qemu-log", type=Path, help="verify one closed single-hart UART transcript"
    )
    arguments = parser.parse_args()
    if (
        not arguments.check_source
        and not arguments.selftest
        and arguments.qemu_log is None
    ):
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
