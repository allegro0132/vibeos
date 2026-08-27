#!/usr/bin/env python3
"""Verify the default-off C8.4 SSH managed-child phase sidecar composition."""

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
CORE_VERIFIER_PATH = ROOT / "scripts/verify-c84-ssh-managed-child-core.py"
COMPONENT_SOURCE = ROOT / "kernel/src/component_instances.rs"
SLOT_SOURCE = ROOT / "kernel/src/wasm_aot_profile_slot.rs"
SSH_SOURCE = ROOT / "kernel/src/ssh_platform.rs"
KERNEL_ROOT_SOURCE = ROOT / "kernel/src/lib.rs"
RUNTIME_SOURCE = ROOT / "component-runtime/src/sync.rs"
SSHD_SOURCE = ROOT / "components/sshd/src/lib.rs"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
QEMU_MANIFEST = ROOT / "firmware/qemu-virt/Cargo.toml"
MILKV_MANIFEST = ROOT / "firmware/milkv-duo/Cargo.toml"
SSHD_MANIFEST = ROOT / "components/sshd/Cargo.toml"

FEATURE = "wasm-c84-ssh-managed-child-phase-sidecar"
QEMU_FEATURE = f"{FEATURE}-qemu-acceptance"
CORE_FEATURE = "wasm-c84-ssh-managed-child-core"
CORE_QEMU_FEATURE = f"{CORE_FEATURE}-qemu-acceptance"
SSHD_FEATURE = "c84-profile-phase-sidecar"
SSHD_PARENT_FEATURE = "c84-profile-request-parent"
IRQ_FEATURE = "wasm-c84-profile-irq-overlay"
FAMILY = "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR"
FINISH_FEATURE = "wasm-c84-ssh-managed-child-finish-verify"
FINISH_QEMU_FEATURE = f"{FINISH_FEATURE}-qemu-acceptance"
VERIFIED_STREAM_FEATURE = "wasm-c84-ssh-managed-child-verified-stream"
VERIFIED_STREAM_QEMU_FEATURE = f"{VERIFIED_STREAM_FEATURE}-qemu-acceptance"
TRUSTED_SAMPLE_FEATURE = "wasm-c84-ssh-managed-child-trusted-sample"
TRUSTED_SAMPLE_QEMU_FEATURE = f"{TRUSTED_SAMPLE_FEATURE}-qemu-acceptance"
COLLECTOR_FEATURE = "wasm-c84-ssh-managed-child-single-boot-collector"
COLLECTOR_QEMU_FEATURE = f"{COLLECTOR_FEATURE}-qemu-acceptance"
SSHD_TRUSTED_SAMPLE_FEATURE = "c84-profile-trusted-sample"


def load_core_verifier():
    spec = importlib.util.spec_from_file_location("vibeos_c84_managed_child_core_verifier", CORE_VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the managed-child/Core predecessor verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CORE = load_core_verifier()


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def semantic(value: str) -> str:
    return CORE.semantic(value)


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


def cfg_guarded(source: str, offset: int, label: str, feature: str = FEATURE) -> None:
    try:
        CORE.cfg_guarded(source, offset, label, feature=feature)
    except CORE.VerificationError as error:
        raise VerificationError(str(error)) from error


def ordered(scope: str, needles: list[str], label: str) -> None:
    positions: list[int] = []
    for needle in needles:
        matches = [match.start() for match in re.finditer(re.escape(needle), scope)]
        require(len(matches) == 1, f"{label}: {needle!r} count differs: {len(matches)}")
        positions.append(matches[0])
    require(positions == sorted(positions), f"{label} order differs: {needles!r}")


def parse_features(raw: bytes, label: str) -> dict[str, list[str]]:
    try:
        return CORE.parse_features(raw, label)
    except CORE.VerificationError as error:
        raise VerificationError(str(error)) from error


def local_feature_closure(features: dict[str, list[str]], roots: list[str]) -> set[str]:
    return CORE.local_feature_closure(features, roots)


def feature_member_closure(features: dict[str, list[str]], roots: list[str]) -> set[str]:
    """Return local feature names plus dependency feature members they select."""

    local = local_feature_closure(features, roots)
    # Cargo permits dependency-feature strings directly in `default`, where
    # they are intentionally absent from the local-feature traversal.
    members = set(roots) | local
    for feature in local:
        members.update(features.get(feature, []))
    return members


@dataclass(frozen=True)
class Inputs:
    component: str
    slot: str
    ssh: str
    kernel_root: str
    runtime: str
    sshd: str
    kernel_manifest: bytes
    qemu_manifest: bytes
    milkv_manifest: bytes
    sshd_manifest: bytes

    def predecessor(self):
        return CORE.Inputs(
            component=self.component,
            slot=self.slot,
            ssh=self.ssh,
            kernel_root=self.kernel_root,
            runtime=self.runtime,
            kernel_manifest=self.kernel_manifest,
            qemu_manifest=self.qemu_manifest,
            milkv_manifest=self.milkv_manifest,
        )


def load_inputs() -> Inputs:
    return Inputs(
        component=COMPONENT_SOURCE.read_text(encoding="utf-8"),
        slot=SLOT_SOURCE.read_text(encoding="utf-8"),
        ssh=SSH_SOURCE.read_text(encoding="utf-8"),
        kernel_root=KERNEL_ROOT_SOURCE.read_text(encoding="utf-8"),
        runtime=RUNTIME_SOURCE.read_text(encoding="utf-8"),
        sshd=SSHD_SOURCE.read_text(encoding="utf-8"),
        kernel_manifest=KERNEL_MANIFEST.read_bytes(),
        qemu_manifest=QEMU_MANIFEST.read_bytes(),
        milkv_manifest=MILKV_MANIFEST.read_bytes(),
        sshd_manifest=SSHD_MANIFEST.read_bytes(),
    )


def verify_features(inputs: Inputs) -> None:
    kernel = parse_features(inputs.kernel_manifest, "kernel")
    qemu = parse_features(inputs.qemu_manifest, "QEMU firmware")
    milkv = parse_features(inputs.milkv_manifest, "Milk-V firmware")
    sshd = parse_features(inputs.sshd_manifest, "sshd")

    require(
        kernel.get(FEATURE) == [CORE_FEATURE, f"vibeos-sshd/{SSHD_FEATURE}"],
        "kernel phase-sidecar feature closure differs",
    )
    require(
        kernel.get(QEMU_FEATURE) == [FEATURE, CORE_QEMU_FEATURE],
        "kernel phase-sidecar QEMU closure differs",
    )
    require(
        qemu.get(QEMU_FEATURE)
        == [CORE_QEMU_FEATURE, f"vibeos-kernel/{QEMU_FEATURE}"],
        "QEMU firmware does not compose the exact predecessor gate and phase sidecar",
    )
    require(
        milkv.get(FEATURE) == [f"vibeos-kernel/{FEATURE}"],
        "Milk-V does not expose the reusable base phase sidecar",
    )
    require(
        sshd.get(SSHD_FEATURE) == [SSHD_PARENT_FEATURE],
        "sshd phase-sidecar feature does not extend only the request parent",
    )
    require(
        sshd.get(SSHD_TRUSTED_SAMPLE_FEATURE) == [SSHD_FEATURE],
        "sshd trusted-sample feature does not extend only the phase sidecar",
    )

    for label, features, name in (
        ("kernel", kernel, FEATURE),
        ("kernel", kernel, QEMU_FEATURE),
        ("QEMU firmware", qemu, QEMU_FEATURE),
        ("Milk-V firmware", milkv, FEATURE),
        ("sshd", sshd, SSHD_FEATURE),
    ):
        require(
            name not in local_feature_closure(features, features.get("default", [])),
            f"{label} enables {name} by default",
        )
    require(
        f"vibeos-sshd/{SSHD_FEATURE}"
        not in feature_member_closure(kernel, kernel.get("default", [])),
        "kernel default enables the sshd phase backend directly",
    )
    require(
        f"vibeos-kernel/{QEMU_FEATURE}"
        not in feature_member_closure(qemu, qemu.get("default", [])),
        "QEMU firmware default enables the kernel phase acceptance directly",
    )
    require(
        f"vibeos-kernel/{FEATURE}"
        not in feature_member_closure(qemu, qemu.get("default", [])),
        "QEMU firmware default enables the kernel phase sidecar directly",
    )
    require(
        f"vibeos-kernel/{FEATURE}"
        not in feature_member_closure(milkv, milkv.get("default", [])),
        "Milk-V default enables the kernel phase sidecar directly",
    )
    base_closure = local_feature_closure(kernel, [FEATURE])
    require(IRQ_FEATURE not in base_closure, "base phase sidecar enables the IRQ overlay")
    require(
        not any(name.endswith("-qemu-acceptance") for name in base_closure),
        "base phase sidecar enables acceptance-only telemetry",
    )
    trusted_closure = local_feature_closure(kernel, [TRUSTED_SAMPLE_FEATURE])
    trusted_qemu_closure = local_feature_closure(kernel, [TRUSTED_SAMPLE_QEMU_FEATURE])
    require(FEATURE in trusted_closure, "trusted-sample omits the phase-sidecar predecessor")
    require(
        QEMU_FEATURE in trusted_qemu_closure,
        "trusted-sample QEMU omits the phase-sidecar QEMU predecessor",
    )

    root = semantic(inputs.kernel_root)
    qemu_only = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",not(feature="qemu-virt")))]'
        f'compile_error!("feature`{QEMU_FEATURE}`isQEMU-only");'
    )
    require(qemu_only in root, "phase-sidecar acceptance lacks its QEMU-only guard")
    isolation = (
        f'#[cfg(all(feature="{QEMU_FEATURE}",any('
        'feature="wasm-c48-qemu-acceptance",'
        'feature="wasm-c84-profile-slot-qemu-acceptance",'
        'feature="wasm-c84-core-poll-qemu-acceptance",'
        'feature="wasm-c84-profile-irq-overlay-qemu-acceptance",'
        'feature="wasm-c84-profile-child-delegation-qemu-acceptance")))]'
        'compile_error!("C8.4QEMUacceptancesareisolatedimages");'
    )
    require(isolation in root, "phase-sidecar acceptance isolation guard differs")


def verify_runtime(source: str) -> None:
    clock = find_scope(source, r"\bpub\s+trait\s+ProfileClock\b", "ProfileClock trait")
    cleanup = find_function(clock, "cleanup_started", "default cleanup callback")
    require(
        semantic(cleanup.raw) == "fncleanup_started(&mutself){}",
        "ProfileClock cleanup callback is not a default no-op",
    )

    typed = find_scope(source, r"\bpub\s+struct\s+TypedCall\b", "TypedCall storage")
    require(
        '#[cfg(feature="c84-profile-hooks")]profile_cleanup_started:bool,' in semantic(typed.raw),
        "TypedCall cleanup-once bit is absent or not hook-gated",
    )
    typed_impl = find_scope(source, r"\bimpl<'a,\s*A>\s+TypedCall<'a,\s*A>", "TypedCall impl")
    poll = find_function(typed_impl, "poll_profiled", "profiled typed poll")
    code = semantic(poll.raw)
    ordered(
        code,
        [
            "letouter_started=clock.ticks();",
            "matches!(self.stage,TypedStage::Cleanup|TypedStage::Terminal(_))",
            "letmutsession=ProfileSession{clock,profile};",
            "letresult=self.poll_with_profiler(&mutsession);",
            "matches!(&result,TypedPoll::HostFailed(_)|TypedPoll::Trapped(_))",
            "letouter_elapsed=session.clock.ticks().wrapping_sub(outer_started);",
        ],
        "cleanup-once callback order",
    )
    require(code.count("cleanup_started();") == 2, "profiled poll cleanup callback count differs")
    require(
        code.find("matches!(self.stage,TypedStage::Cleanup|TypedStage::Terminal(_))")
        < code.find("clock.cleanup_started();")
        < code.find("letmutsession=ProfileSession{clock,profile};"),
        "successful cleanup callback is not before the first cleanup work",
    )
    require(
        code.find("matches!(&result,TypedPoll::HostFailed(_)|TypedPoll::Trapped(_))")
        < code.find("session.clock.cleanup_started();")
        < code.find("letouter_elapsed=session.clock.ticks().wrapping_sub(outer_started);"),
        "late failure cleanup callback is not before the outer finish sample",
    )
    require(
        code.count("self.profile_cleanup_started=true;") == 2,
        "profiled poll does not latch both cleanup notification paths",
    )
    require(".await" not in code, "synchronous cleanup callback crosses an await")


def verify_sshd(source: str) -> None:
    source = CORE.without_direct_feature_units(source, SSHD_TRUSTED_SAMPLE_FEATURE)
    poll_import = "use core::future::{poll_fn, Future};"
    require(
        source.count(poll_import) == 1,
        "sshd poll-boundary proof does not import the exact core::future::poll_fn",
    )
    poll_import_start = source.index(poll_import)
    poll_import_range = (poll_import_start, poll_import_start + len(poll_import))

    backend = find_scope(
        source,
        r"\bpub\s+trait\s+SshExecProfileRunBackend\b",
        "sshd profile backend",
    )
    for method in ("phase_host", "phase_wait"):
        declaration = re.search(
            rf"\bfn\s+{re.escape(method)}\s*\(\s*&mut\s+self\s*\)\s*->\s*Result\s*<\s*\(\s*\)\s*,\s*\(\s*\)\s*>\s*;",
            CORE.rust_mask(backend.raw, literals=False),
        )
        require(
            declaration is not None,
            f"sshd backend {method} is not non-consuming",
        )
        assert declaration is not None
        cfg_guarded(
            source,
            backend.start + declaration.start(),
            f"sshd backend {method}",
            SSHD_FEATURE,
        )

    wrapper = find_scope(source, r"\bimpl\s+SshExecProfileRun\b", "sshd profile run wrapper")
    for method in ("phase_host", "phase_wait"):
        scope = find_function(wrapper, method, f"sshd wrapper {method}")
        cfg_guarded(source, wrapper.start + scope.start, f"sshd wrapper {method}", SSHD_FEATURE)
        code = semantic(scope.raw)
        require(
            f".{method}()" in code and "self.backend" in code,
            f"sshd wrapper {method} does not borrow the active backend",
        )
        for forbidden in ("take()", ".finish(", "StreamLease", "publish"):
            require(forbidden not in code, f"sshd wrapper {method} consumes forbidden {forbidden}")

    host_helper = find_scope(source, r"\bfn\s+reach_profile_host_phase\b", "sshd Host helper")
    wait_helper = find_scope(source, r"\bfn\s+reach_profile_wait_phase\b", "sshd Wait helper")
    cfg_guarded(source, host_helper.start, "sshd Host helper", SSHD_FEATURE)
    cfg_guarded(source, wait_helper.start, "sshd Wait helper", SSHD_FEATURE)
    require(
        semantic(host_helper.raw)
        == (
            "fnreach_profile_host_phase(profile_run:&mutOption<SshExecProfileRun>)"
            "->Result<(),()>{letSome(run)=profile_run.as_mut()else{returnOk(());};"
            "run.phase_host()}"
        ),
        "sshd Host helper does not borrow the exact active run",
    )
    require(
        semantic(wait_helper.raw)
        == (
            "fnreach_profile_wait_phase(profile_run:&mutOption<SshExecProfileRun>)"
            "->Result<(),()>{letSome(run)=profile_run.as_mut()else{returnOk(());};"
            "run.phase_wait()}"
        ),
        "sshd Wait helper does not borrow the exact active run",
    )

    poll_wait_helper = find_scope(
        source,
        r"\basync\s+fn\s+wait_with_profile\b",
        "sshd poll-boundary Wait helper",
    )
    cfg_guarded(source, poll_wait_helper.start, "sshd poll-boundary Wait helper", SSHD_FEATURE)
    poll_wait_code = semantic(poll_wait_helper.raw)
    expected_poll_wait = (
        "asyncfnwait_with_profile<F:Future>("
        "future:F,profile_run:&mutOption<SshExecProfileRun>,"
        ")->Result<F::Output,()>{"
        "letmutfuture=core::pin::pin!(future);"
        "poll_fn(|cx|{"
        "ifreach_profile_host_phase(profile_run).is_err(){"
        "returnPoll::Ready(Err(()));"
        "}"
        "matchfuture.as_mut().poll(cx){"
        "Poll::Ready(output)=>Poll::Ready(Ok(output)),"
        "Poll::Pending=>matchreach_profile_wait_phase(profile_run){"
        "Ok(())=>Poll::Pending,"
        "Err(())=>Poll::Ready(Err(())),"
        "},"
        "}"
        "}).await"
        "}"
    )
    require(
        poll_wait_code == expected_poll_wait,
        "sshd poll-boundary helper does not enter Host before every poll and Wait only after Pending",
    )
    execution_poll_helper = find_scope(
        source,
        r"\basync\s+fn\s+wait_for_execution_or\b",
        "sshd execution poll helper",
    )
    poll_fn_offsets = [
        match.start()
        for match in re.finditer(r"\bpoll_fn\b", CORE.rust_mask(source))
    ]
    poll_fn_ranges = (
        poll_import_range,
        (execution_poll_helper.start, execution_poll_helper.end),
        (poll_wait_helper.start, poll_wait_helper.end),
    )
    require(
        len(poll_fn_offsets) == 3
        and all(
            sum(start <= offset < end for start, end in poll_fn_ranges) == 1
            for offset in poll_fn_offsets
        )
        and all(
            sum(start <= offset < end for offset in poll_fn_offsets) == 1
            for start, end in poll_fn_ranges
        ),
        "core::future::poll_fn is shadowed or escapes its exact import/two call sites",
    )
    wait_phase_offsets = [
        match.start()
        for match in re.finditer(
            r"\breach_profile_wait_phase\b",
            CORE.rust_mask(source, literals=False),
        )
    ]
    require(
        len(wait_phase_offsets) == 2
        and sum(wait_helper.start <= offset < wait_helper.end for offset in wait_phase_offsets) == 1
        and sum(
            poll_wait_helper.start <= offset < poll_wait_helper.end for offset in wait_phase_offsets
        )
        == 1,
        "sshd phase integration retains a direct Wait-before-await bypass",
    )
    source_code = semantic(source)
    require(
        source_code.count("wait_with_profile(") == 5,
        "sshd phase integration poll-boundary helper call count differs",
    )

    managed = find_scope(
        source,
        r"\basync\s+fn\s+execute_managed_component_with_network\b",
        "managed SSH execution",
    )
    managed_code = semantic(managed.raw)
    require(
        '#[cfg(feature="c84-profile-phase-sidecar")]profile_run:&mutOption<SshExecProfileRun>'
        in managed_code,
        "managed SSH execution does not borrow the phase run",
    )
    require(
        len(re.findall(r"\bprofile_run\b", CORE.rust_mask(managed.raw))) == 10,
        "managed SSH execution shadows, consumes, replaces, or otherwise aliases the phase run",
    )
    require(
        managed_code.count("reach_profile_host_phase(profile_run)") == 5,
        "managed SSH execution direct Host edge count differs",
    )
    require(
        "reach_profile_wait_phase(profile_run)" not in managed_code,
        "managed SSH execution bypasses the poll-boundary helper with a direct Wait",
    )
    require(".phase_wait()" not in managed_code, "managed SSH execution calls phase_wait directly")
    require(
        managed_code.count("wait_with_profile(") == 4,
        "managed SSH execution does not route all four suspension paths through the poll-boundary helper",
    )
    require(
        managed_code.count(".await") == 8,
        "managed SSH execution adds a suspension outside the four feature-on wrappers/four feature-off awaits",
    )
    host_guard = (
        '#[cfg(feature="c84-profile-phase-sidecar")]'
        'ifreach_profile_host_phase(profile_run).is_err(){'
        'breakExecutionEnd::Reset("SSHexecprofileHostphasefailed");}'
    )
    require(
        f"letoutcome=loop{{{host_guard}letnow=monotonic_ms();" in managed_code,
        "managed SSH loop does not enter each runnable turn in Host",
    )
    for operation in (
        "letwire=matchbridge.drive(runner,stack,now)",
        "letsignal=matchprogress_protocol(runner,signer,space,policy,protocol)",
        "letinput_work=matchpump_component_stdin_turn(",
        "matchpump_component_stdout_turn(",
    ):
        require(managed_code.count(operation) == 1, f"managed SSH operation count differs: {operation}")
        require(
            f"{host_guard}{operation}" in managed_code,
            f"managed SSH operation lacks its own synchronous Host edge: {operation}",
        )
    cancellation_branch = find_scope(
        managed.raw,
        r"\bif\s+let\s+Some\s*\(\s*\(\s*kind\s*,\s*deadline\s*\)\s*\)\s*=\s*cancellation",
        "managed SSH cancellation branch",
    )
    cancellation_code = semantic(cancellation_branch.raw)
    cancellation_wait = (
        "letwait=wait_for_execution_or("
        "execution.as_mut(),"
        "vibeos_core::exec::sleep_ms(deadline.saturating_sub(now)),"
        ");"
        '#[cfg(feature="c84-profile-phase-sidecar")]'
        "letwaited=matchwait_with_profile(wait,profile_run).await{"
        "Ok(waited)=>waited,"
        'Err(())=>breakExecutionEnd::Reset("SSHexecprofileWaitphasefailed"),'
        "};"
        '#[cfg(not(feature="c84-profile-phase-sidecar"))]'
        "letwaited=wait.await;"
    )
    require(
        managed_code.count("letwait=wait_for_execution_or(") == 1
        and cancellation_code.startswith(
            "ifletSome((kind,deadline))=cancellation{"
            "ifcompleted.is_some(){breakkind.after_managed_completion();}"
            + cancellation_wait
            + "matchwaited{"
        )
        and (
            ');#[cfg(feature="c84-profile-phase-sidecar")]'
            'letwaited=matchwait_with_profile(wait,profile_run).await{'
            'Ok(waited)=>waited,'
            'Err(())=>breakExecutionEnd::Reset("SSHexecprofileWaitphasefailed"),'
            '};#[cfg(not(feature="c84-profile-phase-sidecar"))]'
            'letwaited=wait.await;'
        )
        in managed_code,
        "managed SSH cancellation future bypasses the poll-boundary helper",
    )
    execution_branch = find_scope(
        managed.raw,
        r"\bif\s+completed\.is_none\(\)\s*(?=\{)",
        "managed SSH execution-turn branch",
    )
    execution_code = semantic(execution_branch.raw)
    require(
        managed_code.count("letwait=wait_for_execution_turn(") == 1
        and execution_code.startswith(
            "ifcompleted.is_none(){"
            "letwait=wait_for_execution_turn("
            "execution.as_mut(),wait_worked,wire.next_poll_delay_ms,"
            "Some(execution_deadline),);"
            '#[cfg(feature="c84-profile-phase-sidecar")]'
            "letreports=matchwait_with_profile(wait,profile_run).await{"
            "Ok(reports)=>reports,"
            'Err(())=>breakExecutionEnd::Reset("SSHexecprofileWaitphasefailed"),'
            "};"
            '#[cfg(not(feature="c84-profile-phase-sidecar"))]'
            "letreports=wait.await;"
            "ifletSome(reports)=reports{"
        )
        and (
            ');#[cfg(feature="c84-profile-phase-sidecar")]'
            'letreports=matchwait_with_profile(wait,profile_run).await{'
            'Ok(reports)=>reports,'
            'Err(())=>breakExecutionEnd::Reset("SSHexecprofileWaitphasefailed"),'
            '};#[cfg(not(feature="c84-profile-phase-sidecar"))]'
            'letreports=wait.await;'
        )
        in managed_code,
        "managed SSH execution-turn future bypasses the poll-boundary helper",
    )
    require(
        managed_code.count("letwait=cooperate(") == 1
        and (
            "}else{"
            "letwait=cooperate(wait_worked,wire.next_poll_delay_ms);"
            '#[cfg(feature="c84-profile-phase-sidecar")]'
            "ifwait_with_profile(wait,profile_run).await.is_err(){"
            'breakExecutionEnd::Reset("SSHexecprofileWaitphasefailed");'
            "}"
            '#[cfg(not(feature="c84-profile-phase-sidecar"))]'
            "wait.await;"
            "}"
        )
        in managed_code
        and (
            'letwait=cooperate(wait_worked,wire.next_poll_delay_ms);'
            '#[cfg(feature="c84-profile-phase-sidecar")]'
            'ifwait_with_profile(wait,profile_run).await.is_err(){'
            'breakExecutionEnd::Reset("SSHexecprofileWaitphasefailed");'
            '}#[cfg(not(feature="c84-profile-phase-sidecar"))]wait.await;'
        )
        in managed_code,
        "managed SSH cooperative future bypasses the poll-boundary helper",
    )
    require(
        managed_code.count("letshutdown=session.shutdown();") == 1
        and managed_code.endswith(
            "};drop(execution);"
            "letshutdown=session.shutdown();"
            '#[cfg(feature="c84-profile-phase-sidecar")]'
            "ifwait_with_profile(shutdown,profile_run).await.is_err(){"
            'returnExecutionEnd::Reset("SSHexecprofileWaitphasefailed");'
            "}"
            '#[cfg(not(feature="c84-profile-phase-sidecar"))]'
            "shutdown.await;outcome}"
        )
        and (
            'letshutdown=session.shutdown();'
            '#[cfg(feature="c84-profile-phase-sidecar")]'
            'ifwait_with_profile(shutdown,profile_run).await.is_err(){'
            'returnExecutionEnd::Reset("SSHexecprofileWaitphasefailed");'
            '}#[cfg(not(feature="c84-profile-phase-sidecar"))]shutdown.await;'
        )
        in managed_code,
        "managed SSH shutdown future bypasses the poll-boundary helper",
    )

    finish = find_scope(source, r"\basync\s+fn\s+finish_exec\b", "SSH finish transport")
    finish_code = semantic(finish.raw)
    require(
        '#[cfg(feature="c84-profile-request-parent")]profile_run:&mutOption<SshExecProfileRun>'
        in finish_code,
        "SSH finish transport does not borrow the exact parent phase run",
    )
    require(
        len(re.findall(r"\bprofile_run\b", CORE.rust_mask(finish.raw))) == 5,
        "SSH finish transport shadows, prematurely consumes, replaces, or aliases the phase run",
    )
    require(
        finish_code.count("reach_profile_host_phase(profile_run)") == 1
        and "reach_profile_wait_phase(profile_run)" not in finish_code
        and ".phase_wait()" not in finish_code
        and finish_code.count("wait_with_profile(") == 1,
        "SSH finish transport phase edge count differs",
    )
    require(
        finish_code.count(".await") == 4,
        "SSH finish transport adds a suspension outside its two terminal handoffs and feature wait pair",
    )
    ordered(
        finish_code,
        [
            "loop{",
            "reach_profile_host_phase(profile_run)",
            "bridge.drive(runner,stack,now)",
            "progress_protocol(runner,signer,space,policy,protocol)",
            "letwait=cooperate(",
            "wait_with_profile(wait,profile_run).await",
        ],
        "SSH response drain Host/poll-boundary order",
    )
    require(
        (
            ');#[cfg(feature="c84-profile-phase-sidecar")]'
            'wait_with_profile(wait,profile_run).await.map_err(|_|'
            'ConnectionEnd::Reset("SSHexecprofileWaitphasefailed"))?;'
            '#[cfg(not(feature="c84-profile-phase-sidecar"))]wait.await;'
        )
        in finish_code,
        "SSH finish cooperative future bypasses the poll-boundary helper",
    )
    require(
        finish_code.endswith(
            "letwait=cooperate("
            "wire.worked||application_work||matches!(signal,ProtocolSignal::Progressed),"
            "wire.next_poll_delay_ms,);"
            '#[cfg(feature="c84-profile-phase-sidecar")]'
            "wait_with_profile(wait,profile_run).await.map_err(|_|"
            'ConnectionEnd::Reset("SSHexecprofileWaitphasefailed"))?;'
            '#[cfg(not(feature="c84-profile-phase-sidecar"))]'
            "wait.await;}}"
        ),
        "SSH finish cooperative wait is not the live loop tail",
    )
    helper_occurrences = (
        (
            "reach_profile_host_phase",
            8,
            ((host_helper, 1), (poll_wait_helper, 1), (managed, 5), (finish, 1)),
        ),
        (
            "reach_profile_wait_phase",
            2,
            ((wait_helper, 1), (poll_wait_helper, 1), (managed, 0), (finish, 0)),
        ),
        (
            "wait_with_profile",
            6,
            ((poll_wait_helper, 1), (managed, 4), (finish, 1)),
        ),
    )
    masked_sshd = CORE.rust_mask(source)
    for identifier, expected_total, scoped_counts in helper_occurrences:
        offsets = [
            match.start()
            for match in re.finditer(rf"\b{re.escape(identifier)}\b", masked_sshd)
        ]
        require(
            len(offsets) == expected_total
            and all(
                sum(scope.start <= offset < scope.end for scope, _ in scoped_counts) == 1
                for offset in offsets
            )
            and all(
                sum(scope.start <= offset < scope.end for offset in offsets) == expected_count
                for scope, expected_count in scoped_counts
            ),
            f"sshd helper {identifier} is shadowed or escapes its exact definition/call sites",
        )
    integration = (
        backend.raw
        + wrapper.raw
        + host_helper.raw
        + wait_helper.raw
        + poll_wait_helper.raw
        + managed.raw
        + finish.raw
    )
    for forbidden in ("StreamLease", "publish_profile", "physical_evidence", "profile_irq_", "TrapIrqCookie"):
        require(forbidden not in CORE.rust_mask(integration), f"sshd phase sidecar admits forbidden {forbidden}")


def verify_slot(source: str) -> None:
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, COLLECTOR_FEATURE)
    source = CORE.without_direct_feature_units(source, COLLECTOR_QEMU_FEATURE)
    sidecar = find_scope(source, r"\bstruct\s+ManagedPhaseSidecar\b", "phase sidecar storage")
    cfg_guarded(source, sidecar.start, "phase sidecar storage")
    sidecar_code = semantic(sidecar.raw)
    for field in (
        "parent_waiting:bool",
        "parent_host_active:bool",
        "child_waiting:bool",
        "child_host_open:bool",
        "child_base:ManagedChildBasePhase",
        "cleanup_latched:bool",
        "parent_host_starts:u64",
        "parent_host_finishes:u64",
        "parent_wait_starts:u64",
        "parent_wait_finishes:u64",
        "child_host_starts:u64",
        "child_host_finishes:u64",
        "child_wait_starts:u64",
        "child_wait_finishes:u64",
        "cleanup_count:u64",
    ):
        require(field in sidecar_code, f"phase sidecar storage is missing {field}")

    sidecar_impl = find_scope(source, r"\bimpl\s+ManagedPhaseSidecar\b", "phase sidecar state machine")
    parent_host = find_function(sidecar_impl, "parent_host", "parent Host transition")
    parent_wait = find_function(sidecar_impl, "parent_wait", "parent Wait transition")
    child_wait = find_function(sidecar_impl, "child_enter_wait", "child Wait entry")
    child_resume = find_function(sidecar_impl, "child_resume_from_wait", "child Wait resume")
    cleanup = find_function(sidecar_impl, "child_begin_cleanup", "child Cleanup latch")
    for exact in (
        "self.parent_waiting=false;",
        "self.parent_host_starts=self.parent_host_starts.saturating_add(1);",
        "self.parent_host_finishes=self.parent_host_finishes.saturating_add(1);",
        "self.parent_wait_finishes=self.parent_wait_finishes.saturating_add(1);",
    ):
        require(exact in semantic(parent_host.raw), f"parent Host transition is missing {exact}")
    require(
        "ifself.parent_waiting{returnErr(());}" in semantic(parent_wait.raw)
        and "self.parent_waiting=true;" in semantic(parent_wait.raw),
        "parent Wait does not reject a stale open Wait",
    )
    require(
        "ifself.child_waiting||self.child_host_open{returnErr(());}" in semantic(child_wait.raw),
        "child Wait can overlap Wait or Host",
    )
    require(
        "if!self.child_waiting||self.child_host_open{returnErr(());}" in semantic(child_resume.raw)
        and "Ok(self.child_base.phase())" in semantic(child_resume.raw)
        and "self.child_base=" not in semantic(child_resume.raw),
        "child Wait resume does not restore its stored base",
    )
    require(
        "ifself.cleanup_latched||self.child_waiting||self.child_host_open{returnErr(());}" in semantic(cleanup.raw)
        and "self.cleanup_latched=true;" in semantic(cleanup.raw)
        and "self.child_base=ManagedChildBasePhase::Cleanup;" in semantic(cleanup.raw),
        "Cleanup is not an irreversible exactly-once latch",
    )

    run_impl = find_scope(source, r"\bimpl\s+RunLease\b", "RunLease impl")
    for name, change in (("managed_parent_host", "ManagedParentPhaseChange::Host"), ("managed_parent_wait", "ManagedParentPhaseChange::Wait")):
        scope = find_function(run_impl, name, f"RunLease {name}")
        cfg_guarded(source, run_impl.start + scope.start, f"RunLease {name}")
        code = semantic(scope.raw)
        require("self.detach.is_current_running_exact()" in code, f"RunLease {name} skips owner revalidation")
        require(change in code, f"RunLease {name} selects the wrong phase")
        require("self" in code and "mutself" not in code, f"RunLease {name} consumes mutable authority")

    parent_instantiation = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_current_parent_set_instantiation\b",
        "current parent Instantiation",
    )
    cfg_guarded(source, parent_instantiation.start, "current parent Instantiation")
    parent_code = semantic(parent_instantiation.raw)
    ordered(
        parent_code,
        [
            "letcandidate={letslot=SLOT.lock();",
            "};letSome((token,detach))=candidateelse",
            "detach.is_current_running_exact()",
            "apply_managed_parent_phase(",
        ],
        "current parent revalidation",
    )

    parent_drop_bypass = find_scope(
        source,
        r"\bfn\s+managed_parent_phase_bypasses_child_drop\b",
        "exact parent child-Drop bypass predicate",
    )
    cfg_guarded(source, parent_drop_bypass.start, "exact parent child-Drop bypass predicate")
    parent_drop_bypass_code = semantic(parent_drop_bypass.raw)
    expected_parent_drop_bypass = (
        "fnmanaged_parent_phase_bypasses_child_drop("
        "change:ManagedParentPhaseChange,"
        "child_attached:bool,"
        "child_detach:Option<TaskDetachReason>,"
        "faults:SlotFaults,"
        "core_owner:CoreObserverOwner,"
        "parent_waiting:bool,"
        "child_waiting:bool,"
        "child_host_open:bool,"
        ")->bool{"
        "matches!(change,ManagedParentPhaseChange::Host|ManagedParentPhaseChange::Wait)"
        "&&!child_attached"
        "&&child_detach==Some(TaskDetachReason::Exited)"
        "&&faults==SlotFaults::CHILD_ABANDONED_DETACHED"
        "&&core_owner==CoreObserverOwner::Closed"
        "&&parent_waiting"
        "&&child_waiting"
        "&&!child_host_open"
        "}"
    )
    require(
        parent_drop_bypass_code == expected_parent_drop_bypass,
        "parent child-Drop bypass is not exact Host|Wait, faults, Wait-open, Host-closed state",
    )
    apply_parent = find_scope(
        source,
        r"\bfn\s+apply_managed_parent_phase\b",
        "parent phase application",
    )
    cfg_guarded(source, apply_parent.start, "parent phase application")
    apply_parent_code = semantic(apply_parent.raw)
    bypass_call = (
        "ifmanaged_parent_phase_bypasses_child_drop("
        "change,child.is_some(),*child_detach,*faults,*core_owner,"
        "managed_phase.parent_waiting,managed_phase.child_waiting,"
        "managed_phase.child_host_open,){returnOk(());}"
    )
    ordered(
        apply_parent_code,
        [
            "ifsample.token()!=token||!owner.matches(token.epoch(),detach)",
            "if*core_owner!=CoreObserverOwner::Closed",
            bypass_call,
            "if!faults.is_empty()",
        ],
        "parent owner/Core proof, child-Drop bypass, and generic fault rejection",
    )

    cancel_wait = find_scope(
        source,
        r"\bpub\(crate\)\s+fn\s+managed_child_cancel_bypasses_host\b",
        "child cancel Host-bypass query",
    )
    cfg_guarded(source, cancel_wait.start, "child cancel Host-bypass query")
    cancel_wait_code = semantic(cancel_wait.raw)
    expected_cancel_wait = (
        "pub(crate)fnmanaged_child_cancel_bypasses_host(epoch:u64)"
        "->Result<bool,ProfileError>{"
        "ensure_not_poisoned()?;"
        "letcandidate={letslot=SLOT.lock();match&*slot{"
        "SlotState::Active{sample,child:Some(child),..}if"
        "sample.token().epoch()==epoch&&child.epoch==epoch&&matches!("
        "child.state,DelegatedChildState::Claimed|DelegatedChildState::Abandoned)"
        "=>Some((sample.token(),child.detach)),_=>None,}}"
        ".ok_or(ProfileError::DelegatedChildUnavailable)?;"
        "let(token,detach)=candidate;"
        "if!detach.is_current_running_exact()&&!detach.is_current_reclaiming_exact(){"
        "mark_child_fault(token,detach);returnErr(ProfileError::OwnerNotCurrent);}"
        "letslot=SLOT.lock();letSlotState::Active{sample,child:Some(child),faults,"
        "managed_phase,core_owner,..}=&*slotelse{returnErr(ProfileError::StateMismatch);};"
        "ifsample.token()!=token||!child.matches(epoch,detach)||"
        "*core_owner!=CoreObserverOwner::Closed{returnErr(ProfileError::StateMismatch);}"
        "matchchild.state{"
        "DelegatedChildState::Claimediffaults.is_empty()=>Ok(managed_phase.child_waiting),"
        "DelegatedChildState::Abandonedif*faults==SlotFaults::CHILD_ABANDONED=>Ok(true),"
        "_=>Err(ProfileError::SlotFault(*faults)),}}"
    )
    require(
        cancel_wait_code == expected_cancel_wait,
        "child cancel Host-bypass query is not the exact current-task/Core/fault/Wait predicate",
    )
    require("&*slot" in cancel_wait.raw, "child cancel Host-bypass query mutates the sidecar")

    set_phase = find_scope(source, r"\bpub\(crate\)\s+fn\s+managed_child_set_phase\b", "child phase setter")
    enter_wait = find_scope(source, r"\bpub\(crate\)\s+fn\s+managed_child_enter_wait\b", "child Wait entry API")
    resume_wait = find_scope(source, r"\bpub\(crate\)\s+fn\s+managed_child_resume_from_wait\b", "child Wait resume API")
    begin_cleanup = find_scope(source, r"\bpub\(crate\)\s+fn\s+managed_child_begin_cleanup\b", "child Cleanup API")
    for scope, label in (
        (set_phase, "child phase setter"),
        (enter_wait, "child Wait entry API"),
        (resume_wait, "child Wait resume API"),
        (begin_cleanup, "child Cleanup API"),
    ):
        cfg_guarded(source, scope.start, label)
        code = semantic(scope.raw)
        require("managed_child_phase_parts(epoch)" in code, f"{label} skips current-task revalidation")
        require(".await" not in code, f"{label} holds state across await")
    require(
        "matches!(phase,Phase::Validation|Phase::Instantiation|Phase::Abi)" in semantic(set_phase.raw),
        "child phase setter accepts Host/Wait/Cleanup/Interpretation",
    )
    require("Phase::Wait" in semantic(enter_wait.raw), "child Wait entry does not reach Wait")
    require(
        "letphase=matchmanaged_phase.child_resume_from_wait()" in semantic(resume_wait.raw)
        and "sample.set_phase(token,live_context(),live_tick(),phase)" in semantic(resume_wait.raw),
        "child Wait resume does not use the storage-resident base",
    )
    require(
        "managed_phase.child_begin_cleanup()" in semantic(begin_cleanup.raw)
        and "sample.begin_cleanup(token,live_context(),live_tick())" in semantic(begin_cleanup.raw)
        and semantic(begin_cleanup.raw).find("managed_phase.child_begin_cleanup()")
        < semantic(begin_cleanup.raw).find("sample.begin_cleanup(token,live_context(),live_tick())"),
        "child Cleanup API does not latch before changing the ledger",
    )

    host_guard = find_scope(source, r"\bpub\(crate\)\s+struct\s+ManagedChildHostPhase\b", "child Host guard")
    cfg_guarded(source, host_guard.start, "child Host guard")
    require(
        "not_send:PhantomData<*mut()>" in semantic(host_guard.raw),
        "child Host guard is not !Send/!Sync",
    )
    host_impl = find_scope(source, r"\bimpl\s+ManagedChildHostPhase\b", "child Host guard impl")
    host_enter = find_function(host_impl, "enter", "child Host enter")
    host_finish = find_function(host_impl, "finish", "child Host finish")
    require("managed_child_open_host(token,detach)?;" in semantic(host_enter.raw), "Host guard does not open synchronously")
    require("managed_child_close_host(self.token,self.detach)" in semantic(host_finish.raw), "Host guard does not close exactly")
    host_drop = find_scope(source, r"\bimpl\s+Drop\s+for\s+ManagedChildHostPhase\b", "child Host guard Drop")
    drop_code = semantic(host_drop.raw)
    require(
        "ifself.live" in drop_code
        and "mark_managed_child_phase_fault(self.token,self.detach);" in drop_code,
        "forgot child Host guard is not a sticky phase fault",
    )

    release = find_scope(source, r"\bpub\(crate\)\s+fn\s+release_current_request_managed_child\b", "managed-child release")
    release_child = find_scope(source, r"\bfn\s+release_child\b", "delegated-child release")
    release_code = semantic(release_child.raw)
    require(
        "managed_phase.child_release_ready()" in release_code
        and "faults.insert(SlotFaults::CHILD_PHASE);" in release_code,
        "child release does not require closed Host/Wait and Cleanup",
    )
    response = find_scope(source, r"\bpub\(crate\)\s+fn\s+managed_phase_response_ready\b", "phase response readiness")
    response_code = semantic(response.raw)
    for exact in (
        "ifmanaged_phase.parent_waiting",
        "managed_phase.child_waiting",
        "managed_phase.child_host_open",
        "!managed_phase.cleanup_latched",
        "child.is_none()",
        "*child_detach==Some(TaskDetachReason::Exited)",
        "*core_owner==CoreObserverOwner::Closed",
    ):
        require(exact in response_code, f"phase response readiness is missing {exact}")

    observation = find_scope(source, r"\bpub\(crate\)\s+fn\s+managed_phase_observation\b", "phase observation")
    cfg_guarded(source, observation.start, "phase observation", QEMU_FEATURE)
    observation_code = semantic(observation.raw)
    for field in (
        "parent_host_starts",
        "parent_host_finishes",
        "parent_wait_starts",
        "parent_wait_finishes",
        "child_host_starts",
        "child_host_finishes",
        "child_wait_starts",
        "child_wait_finishes",
        "cleanup_count",
        "parent_wait_open",
        "child_wait_open",
        "child_host_open",
        "child_phase_fault",
        "parent_phase_fault",
    ):
        require(field in observation_code, f"phase observation omits {field}")
    require("&*slot" in observation.raw, "phase observation mutates the slot")

    clock = find_scope(
        source,
        r"\bimpl\s+ProfileClock\s+for\s+ManagedChildSlotCorePollClock\b",
        "managed-child ProfileClock",
    )
    clock_cleanup = find_function(clock, "cleanup_started", "managed-child Cleanup callback")
    cfg_guarded(source, clock.start + clock_cleanup.start, "managed-child Cleanup callback")
    clock_cleanup_code = semantic(clock_cleanup.raw)
    require(
        "managed_child_begin_cleanup(epoch).err()" in clock_cleanup_code
        and f'"{FAMILY}CHILD_PHASEepoch={{}}phase=cleanup"' in clock_cleanup_code,
        "managed-child Cleanup callback does not latch before exact telemetry",
    )
    require("SLOT.lock" not in clock_cleanup.raw, "Cleanup telemetry is emitted while holding SLOT")
    require(
        source.count(f"{FAMILY} CHILD_PHASE epoch={{}} phase=cleanup") == 1,
        "Cleanup telemetry marker count differs",
    )
    require(
        FAMILY not in CORE.without_direct_feature_units(source, QEMU_FEATURE),
        "slot phase telemetry is not directly acceptance-gated",
    )

    integration = "".join(
        scope.raw
        for scope in (
            sidecar,
            sidecar_impl,
            parent_instantiation,
            parent_drop_bypass,
            apply_parent,
            cancel_wait,
            set_phase,
            enter_wait,
            resume_wait,
            begin_cleanup,
            host_guard,
            host_impl,
            host_drop,
            release_child,
            release,
            response,
            observation,
            clock_cleanup,
        )
    )
    for forbidden in (".finish(", "StreamLease", "publish_profile", "physical_evidence", "profile_irq_", "TrapIrqCookie"):
        require(forbidden not in CORE.rust_mask(integration), f"phase slot admits forbidden {forbidden}")


def verify_component(source: str) -> None:
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    start = find_scope(source, r"\bfn\s+start_image_instance_under_control\b", "managed instance start")
    start_code = semantic(start.raw)
    ordered(
        start_code,
        [
            "managed_current_parent_set_instantiation()",
            "HEAP.create_owner(INSTANCE_HEAP_QUOTA)",
            "attach_current_request_managed_child(&mutbatch,0)",
            "epoch==parent_profile_epoch",
            "stage.publish_ready_if(permit,expected)",
        ],
        "parent Instantiation/bind/publication",
    )

    delayed_stdin_evidence = find_scope(
        source,
        r"\bstruct\s+C84DelayedStdinPending\b",
        "delayed-stdin evidence token",
    )
    cfg_guarded(
        source,
        delayed_stdin_evidence.start,
        "delayed-stdin evidence token",
        QEMU_FEATURE,
    )
    require(
        semantic(delayed_stdin_evidence.raw)
        == "structC84DelayedStdinPending{epoch:u64,operation:HostOperationToken,}",
        "delayed-stdin evidence does not bind only the exact epoch and operation token",
    )
    masked_source = CORE.rust_mask(source, literals=False)
    delayed_stdin_static_matches = list(
        re.finditer(
            r"\bstatic\s+C84_DELAYED_STDIN_PENDING\s*:\s*"
            r"SpinLock\s*<\s*Option\s*<\s*C84DelayedStdinPending\s*>\s*>",
            masked_source,
        )
    )
    require(
        len(delayed_stdin_static_matches) == 1,
        f"delayed-stdin evidence latch count differs: {len(delayed_stdin_static_matches)}",
    )
    delayed_stdin_static_start = delayed_stdin_static_matches[0].start()
    delayed_stdin_static_end = masked_source.find(";", delayed_stdin_static_start) + 1
    require(delayed_stdin_static_end > 0, "delayed-stdin evidence latch has no terminator")
    cfg_guarded(
        source,
        delayed_stdin_static_start,
        "delayed-stdin evidence latch",
        QEMU_FEATURE,
    )
    delayed_stdin_static_raw = source[delayed_stdin_static_start:delayed_stdin_static_end]
    require(
        semantic(delayed_stdin_static_raw)
        == "staticC84_DELAYED_STDIN_PENDING:SpinLock<Option<C84DelayedStdinPending>>="
        "SpinLock::new(None);",
        "delayed-stdin evidence latch is not one acceptance-only optional record",
    )
    record_delayed_stdin = find_scope(
        source,
        r"\bfn\s+record_c84_delayed_stdin_pending\b",
        "delayed-stdin evidence record",
    )
    take_delayed_stdin = find_scope(
        source,
        r"\bfn\s+take_c84_delayed_stdin_pending\b",
        "delayed-stdin evidence consume",
    )
    for evidence_scope, label in (
        (record_delayed_stdin, "delayed-stdin evidence record"),
        (take_delayed_stdin, "delayed-stdin evidence consume"),
    ):
        cfg_guarded(source, evidence_scope.start, label, QEMU_FEATURE)
        evidence_code = semantic(evidence_scope.raw)
        require(".await" not in evidence_code, f"{label} holds its latch across an await")
        require("println!" not in evidence_scope.raw, f"{label} emits UART while holding its latch")
    require(
        semantic(record_delayed_stdin.raw)
        == (
            "fnrecord_c84_delayed_stdin_pending(epoch:u64,operation:HostOperationToken,)"
            "->Result<(),HostError>{"
            "ifepoch!=2{returnOk(());}"
            "letmutpending=C84_DELAYED_STDIN_PENDING.lock();"
            "ifpending.is_some(){drop(pending);lifecycle_fail_stop();"
            "returnErr(HostError::BackendFault);}"
            "*pending=Some(C84DelayedStdinPending{epoch,operation});"
            "Ok(())}"
        ),
        "delayed-stdin evidence record is not exact epoch 2 and fail-closed once-only storage",
    )
    require(
        semantic(take_delayed_stdin.raw)
        == (
            "fntake_c84_delayed_stdin_pending(epoch:u64,operation:HostOperationToken)->bool{"
            "letmutpending=C84_DELAYED_STDIN_PENDING.lock();"
            "if*pending==Some(C84DelayedStdinPending{epoch,operation}){"
            "*pending=None;true}else{false}}"
        ),
        "delayed-stdin evidence consume does not match and clear the exact epoch/operation record",
    )
    acceptance_item_ranges = (
        (delayed_stdin_evidence.start, delayed_stdin_evidence.end),
        (delayed_stdin_static_start, delayed_stdin_static_end),
        (record_delayed_stdin.start, record_delayed_stdin.end),
        (take_delayed_stdin.start, take_delayed_stdin.end),
    )
    for identifier, expected_count in (
        ("C84DelayedStdinPending", 4),
        ("C84_DELAYED_STDIN_PENDING", 3),
    ):
        offsets = [
            match.start()
            for match in re.finditer(
                rf"\b{re.escape(identifier)}\b",
                CORE.rust_mask(source),
            )
        ]
        require(
            len(offsets) == expected_count
            and all(
                any(start <= offset < end for start, end in acceptance_item_ranges)
                for offset in offsets
            ),
            f"delayed-stdin evidence storage {identifier} escapes its acceptance-only items",
        )

    dispatcher = find_scope(source, r"\bstruct\s+RegistryStreamDispatcher\b", "stream dispatcher")
    require(
        '#[cfg(feature="wasm-c84-ssh-managed-child-phase-sidecar")]profile_epoch:u64,'
        in semantic(dispatcher.raw),
        "dispatcher does not carry only the copied phase epoch",
    )
    host_helper = find_scope(source, r"\bfn\s+with_managed_child_host_phase\b", "dispatcher Host guard helper")
    cfg_guarded(source, host_helper.start, "dispatcher Host guard helper")
    helper_code = semantic(host_helper.raw)
    ordered(
        helper_code,
        [
            "ManagedChildHostPhase::enter(epoch)",
            "letresult=operation();",
            "phase.finish()",
        ],
        "synchronous dispatcher Host guard",
    )
    require(".await" not in helper_code, "dispatcher Host guard crosses an await")
    require(
        helper_code.count("phase.finish()") == 1 and helper_code.count(".finish(") == 1,
        "dispatcher Host helper has anything other than its one lexical guard finish",
    )
    cancel_helper = find_scope(
        source,
        r"\bfn\s+with_managed_child_cancel_phase\b",
        "dispatcher cancel phase helper",
    )
    cfg_guarded(source, cancel_helper.start, "dispatcher cancel phase helper")
    cancel_helper_code = semantic(cancel_helper.raw)
    expected_cancel_helper = (
        "fnwith_managed_child_cancel_phase<T>(epoch:u64,"
        "operation:implFnOnce()->Result<T,HostError>,)->Result<T,HostError>{"
        "ifepoch==0{returnoperation();}"
        "matchcrate::wasm_aot_profile_slot::managed_child_cancel_bypasses_host(epoch){"
        "Ok(true)=>operation(),"
        "Ok(false)=>with_managed_child_host_phase(epoch,operation),"
        "Err(_)=>{lifecycle_fail_stop();Err(HostError::BackendFault)}}}"
    )
    require(
        cancel_helper_code == expected_cancel_helper,
        "cancel phase helper is not the exact zero-epoch/narrow-query/Host fallback control flow",
    )
    require(".await" not in cancel_helper_code, "cancel phase helper crosses an await")
    dispatcher_impl = find_scope(
        source,
        r"\bimpl\s+HostDispatcher<ComponentAuthority>\s+for\s+RegistryStreamDispatcher\b",
        "stream HostDispatcher impl",
    )
    for name in ("start", "register_wake", "resume", "commit_prepared"):
        scope = find_function(dispatcher_impl, name, f"dispatcher {name}")
        require(
            "with_managed_child_host_phase(profile_epoch," in semantic(scope.raw),
            f"dispatcher {name} is not inside one synchronous Host guard",
        )
    register_wake = find_function(dispatcher_impl, "register_wake", "dispatcher register_wake")
    read_waiting = find_scope(
        register_wake.raw,
        r"PendingStreamKind::ReadWaiting\s*=>",
        "stdin ReadWaiting wake registration",
    )
    require(
        semantic(read_waiting.raw)
        == (
            "PendingStreamKind::ReadWaiting=>{"
            "with_active_reader(self.instance,self.streams,|reader,supervisor|{"
            "promote_provisional_eof(supervisor)?;"
            "reader.register_wake(operation,wake).map_err(map_stream_error)"
            "})??;"
            f'#[cfg(feature="{QEMU_FEATURE}")]'
            "record_c84_delayed_stdin_pending(profile_epoch,operation)?;"
            "}"
        ),
        "delayed-stdin evidence is not recorded only after exact ReadWaiting backend registration succeeds",
    )
    cancel = find_function(dispatcher_impl, "cancel", "dispatcher cancel")
    cancel_code = semantic(cancel.raw)
    require(
        "with_managed_child_cancel_phase(profile_epoch,action)" in cancel_code,
        "dispatcher cancel bypasses the narrow Wait-open cancel helper",
    )
    require(
        "with_managed_child_host_phase(profile_epoch,action)" not in cancel_code,
        "dispatcher cancel cannot preserve a legal open Wait",
    )
    resume = find_function(dispatcher_impl, "resume", "dispatcher resume")
    require(
        "self.cancel(" not in semantic(resume.raw) and "self.cancel_pending(" in semantic(resume.raw),
        "dispatcher resume nests its public Host guard",
    )
    dispatcher_drop = find_scope(
        source,
        r"\bimpl\s+Drop\s+for\s+RegistryStreamDispatcher\b",
        "stream dispatcher Drop",
    )
    dispatcher_drop_code = semantic(dispatcher_drop.raw)
    require(
        "self.cancel_exact_pending(pending)" in dispatcher_drop_code,
        "dispatcher Drop does not cancel its exact pending operation",
    )
    require(
        "with_managed_child_host_phase" not in dispatcher_drop_code
        and "ManagedChildHostPhase" not in dispatcher_drop_code,
        "dispatcher Drop opens a Host guard during legal Wait-open cancellation",
    )

    run = find_scope(source, r"\basync\s+fn\s+run_image_component\b", "real Component driver")
    run_code = semantic(run.raw)
    ordered(
        run_code,
        [
            "managed_child_set_phase(profile_epoch,Phase::Validation)",
            "revalidate_image_root(root)",
            "managed_child_set_phase(profile_epoch,Phase::Instantiation,)",
            "ProfileEngine::new()",
            "component.start_typed_call_with_host(",
            "managed_child_set_phase(profile_epoch,Phase::Abi)",
        ],
        "real child Validation/Instantiation/ABI",
    )
    require(run_code.count("managed_child_enter_wait(profile_epoch)") == 2, "child Wait entry count differs")
    require(run_code.count("managed_child_resume_from_wait(profile_epoch)") == 2, "child Wait resume count differs")
    for branch_name in ("TypedPoll::Pending(_)", "TypedPoll::HostPending(operation)"):
        branch = find_scope(run.raw, re.escape(branch_name) + r"\s*=>", f"{branch_name} branch")
        code = semantic(branch.raw)
        ordered(
            code,
            [
                "managed_child_enter_wait(profile_epoch)",
                "continuation.await",
                "managed_child_resume_from_wait(profile_epoch)",
            ],
            f"{branch_name} Wait/revalidation",
        )
        require("ManagedChildHostPhase" not in code, f"{branch_name} carries a Host guard across await")
    host_pending = find_scope(
        run.raw,
        r"TypedPoll::HostPending\(operation\)\s*=>",
        "TypedPoll HostPending branch",
    )
    host_pending_code = semantic(host_pending.raw)
    ordered(
        host_pending_code,
        [
            "call.register_host_wake(operation,wake)",
            "managed_child_enter_wait(profile_epoch)",
            "letdelayed_stdin_pending=take_c84_delayed_stdin_pending(profile_epoch,operation);",
            f'crate::println!("{FAMILY}CHILD_HOST_PENDINGepoch=2state=opendelayed_stdin=1");',
            "continuation.await",
        ],
        "delayed-stdin register/Wait/consume/UART/suspend order",
    )
    require(
        (
            f'#[cfg(feature="{QEMU_FEATURE}")]'
            "{letdelayed_stdin_pending="
            "take_c84_delayed_stdin_pending(profile_epoch,operation);"
        )
        in host_pending_code,
        "delayed-stdin evidence is not consumed for every acceptance HostPending after Wait opens",
    )
    require(
        (
            "ifprofile_epoch==2"
            "&&first_wait_reported"
            "&&delayed_stdin_pending"
            "&&!epoch_two_host_pending_reported"
            "{"
            f'crate::println!("{FAMILY}CHILD_HOST_PENDINGepoch=2state=opendelayed_stdin=1");'
            "epoch_two_host_pending_reported=true;"
            "}"
        )
        in host_pending_code,
        "epoch-2 delayed-stdin UART is not gated by the consumed exact evidence",
    )
    require(
        host_pending_code.count("take_c84_delayed_stdin_pending(profile_epoch,operation)") == 1
        and "C84_DELAYED_STDIN_PENDING" not in host_pending_code
        and ".lock()" not in host_pending_code,
        "HostPending branch bypasses the synchronous evidence consumer or carries its latch",
    )
    evidence_identifier_scopes = (
        (
            "record_c84_delayed_stdin_pending",
            (
                (record_delayed_stdin.start, record_delayed_stdin.end),
                (
                    dispatcher_impl.start + register_wake.start + read_waiting.start,
                    dispatcher_impl.start + register_wake.start + read_waiting.end,
                ),
            ),
        ),
        (
            "take_c84_delayed_stdin_pending",
            (
                (take_delayed_stdin.start, take_delayed_stdin.end),
                (run.start + host_pending.start, run.start + host_pending.end),
            ),
        ),
    )
    masked_component = CORE.rust_mask(source)
    for identifier, allowed_ranges in evidence_identifier_scopes:
        offsets = [
            match.start()
            for match in re.finditer(rf"\b{re.escape(identifier)}\b", masked_component)
        ]
        require(
            len(offsets) == 2
            and all(
                sum(start <= offset < end for start, end in allowed_ranges) == 1
                for offset in offsets
            )
            and all(
                sum(start <= offset < end for offset in offsets) == 1
                for start, end in allowed_ranges
            ),
            f"delayed-stdin helper {identifier} is shadowed or escapes its exact definition/call site",
        )
    require(
        "!first_wait_reported&&core_profile.core_polls>0" in run_code,
        "WAIT-open acceptance marker is not downstream of a real Core pair",
    )
    for marker, count in (
        (f"{FAMILY} CHILD_PHASE epoch={{}} phase=validation", 1),
        (f"{FAMILY} CHILD_PHASE epoch={{}} phase=instantiation", 1),
        (f"{FAMILY} CHILD_PHASE epoch={{}} phase=abi", 1),
        (f"{FAMILY} CHILD_WAIT epoch={{}} state=open first=1", 2),
        (f"{FAMILY} CHILD_HOST_PENDING epoch=2 state=open delayed_stdin=1", 1),
    ):
        require(source.count(marker) == count, f"component telemetry marker count differs: {marker}")
    require(
        FAMILY not in CORE.without_direct_feature_units(source, QEMU_FEATURE),
        "component phase telemetry is not directly acceptance-gated",
    )

    integration = (
        start.raw
        + delayed_stdin_evidence.raw
        + delayed_stdin_static_raw
        + record_delayed_stdin.raw
        + take_delayed_stdin.raw
        + dispatcher.raw
        + cancel_helper.raw
        + dispatcher_impl.raw
        + dispatcher_drop.raw
        + run.raw
    )
    integration_code = CORE.rust_mask(integration)
    for forbidden in (".finish(", "StreamLease", "publish_profile", "physical_evidence", "profile_irq_", "TrapIrqCookie"):
        require(forbidden not in integration_code, f"component phase integration admits forbidden {forbidden}")


def verify_ssh(source: str) -> None:
    source = CORE.without_direct_feature_units(source, FINISH_FEATURE)
    source = CORE.without_direct_feature_units(source, FINISH_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, VERIFIED_STREAM_FEATURE)
    source = CORE.without_direct_feature_units(source, VERIFIED_STREAM_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_FEATURE)
    source = CORE.without_direct_feature_units(source, TRUSTED_SAMPLE_QEMU_FEATURE)
    source = CORE.without_direct_feature_units(source, COLLECTOR_FEATURE)
    source = CORE.without_direct_feature_units(source, COLLECTOR_QEMU_FEATURE)
    backend = find_scope(
        source,
        r"\bimpl\s+SshExecProfileRunBackend\s+for\s+SshExecProfileOwner\b",
        "kernel SSH profile backend",
    )
    for name, target in (("phase_host", "run.managed_parent_host()"), ("phase_wait", "run.managed_parent_wait()")):
        scope = find_function(backend, name, f"kernel SSH {name}")
        cfg_guarded(source, backend.start + scope.start, f"kernel SSH {name}")
        code = semantic(scope.raw)
        require(target in code, f"kernel SSH {name} does not map the active RunLease")
        require("SshExecProfileOwnerState::Active(run)" in code, f"kernel SSH {name} accepts a closed run")

    owner = find_scope(source, r"\bimpl\s+SshExecProfileOwner\b", "SSH profile owner")
    response = find_function(owner, "response_boundary", "SSH response boundary")
    cancel = find_function(owner, "cancel", "SSH cancel/Drop")
    response_code = semantic(response.raw)
    cancel_code = semantic(cancel.raw)
    ordered(
        response_code,
        [
            "managed_phase_response_ready(epoch)",
            "managed_phase_observation(epoch)",
            "cancel_and_ack_profile(run,crate::wasm_aot_profile_slot::SlotFaults::default())",
            "profile_phase_response(",
            "profile_request_response(epoch,status,ready_epoch)",
        ],
        "phase response/cancel/telemetry",
    )
    response_telemetry = find_scope(
        source,
        r"\bfn\s+profile_phase_response\b",
        "phase response telemetry",
    )
    cfg_guarded(source, response_telemetry.start, "phase response telemetry", QEMU_FEATURE)
    response_telemetry_code = semantic(response_telemetry.raw)
    for exact in (
        "phase.parent_host_starts>0",
        "phase.parent_host_starts==phase.parent_host_finishes",
        "phase.parent_wait_starts>0",
        "phase.parent_wait_starts==phase.parent_wait_finishes",
        "phase.child_host_starts>0",
        "phase.child_host_starts==phase.child_host_finishes",
        "phase.child_wait_starts>0",
        "phase.child_wait_starts==phase.child_wait_finishes",
        "phase.cleanup_count==1",
        "phase.cleanup_latched",
        "!phase.parent_wait_open",
        "!phase.child_wait_open",
        "!phase.child_host_open",
        "!phase.child_phase_fault",
        "!phase.parent_phase_fault",
        "!phase.child_attached",
        "phase.child_detach==Some(TaskDetachReason::Exited)",
        "child.core_pairs>0",
        "child.core_pairs==child.core_polls",
        f'"{FAMILY}RESPONSEepoch={{}}status={{}}',
    ):
        require(exact in response_telemetry_code, f"phase response proof omits {exact}")
    for field in (
        "child_core_starts",
        "child_core_finishes",
        "child_host_starts",
        "child_host_finishes",
        "child_wait_starts",
        "child_wait_finishes",
        "cleanup_count",
        "parent_host_starts",
        "parent_host_finishes",
        "parent_wait_starts",
        "parent_wait_finishes",
        "child_wait_open=0",
        "parent_wait_open=0",
        "late=0",
        "clean=1",
        "cancel=1",
        "ack=1",
    ):
        require(field in response_telemetry.raw, f"phase RESPONSE telemetry omits {field}")
    ordered(
        cancel_code,
        [
            "managed_child_drop_faults(epoch)",
            "managed_child_active_drop_ready(epoch)",
            "managed_phase_observation(epoch)",
            "cancel_and_ack_profile(run,expected_faults)",
            "profile_phase_drop(",
            "profile_request_drop(epoch,ready_epoch)",
        ],
        "phase active-Drop/cancel/telemetry",
    )
    drop_telemetry = find_scope(
        source,
        r"\bfn\s+profile_phase_drop\b",
        "phase Drop telemetry",
    )
    cfg_guarded(source, drop_telemetry.start, "phase Drop telemetry", QEMU_FEATURE)
    drop_telemetry_code = semantic(drop_telemetry.raw)
    for exact in (
        "letparent_open=u64::from(phase.parent_wait_open);",
        "0=>!phase.cleanup_latched&&phase.child_base!=Phase::Cleanup",
        "1=>phase.cleanup_latched&&phase.child_base==Phase::Cleanup",
        "phase.parent_host_starts>0",
        "phase.parent_host_starts==phase.parent_host_finishes",
        "phase.parent_wait_starts>0",
        "phase.parent_wait_starts==phase.parent_wait_finishes.saturating_add(parent_open)",
        "phase.child_host_starts==phase.child_host_finishes",
        "phase.child_wait_starts>0",
        "phase.child_wait_starts==phase.child_wait_finishes.saturating_add(1)",
        "phase.child_wait_open",
        "!phase.child_host_open",
        "!phase.child_phase_fault",
        "!phase.parent_phase_fault",
        "phase.slot_faults==expected_faults",
        "detach==TaskDetachReason::Exited",
        "core_pairs>0",
        f'"{FAMILY}DROPepoch={{}}release=0detach=exitedclean=0',
    ):
        require(exact in drop_telemetry_code, f"phase Drop proof omits {exact}")
    for field in (
        "child_wait_open_at_cancel=1",
        "parent_wait_open_at_cancel={}",
        "child_faults=abandoned+detached",
        "late=0",
        "cancel=1",
        "ack=1",
    ):
        require(field in drop_telemetry.raw, f"phase DROP telemetry omits {field}")
    family_offsets = [match.start() for match in re.finditer(re.escape(FAMILY), source)]
    require(len(family_offsets) == 3, f"SSH phase telemetry family count differs: {len(family_offsets)}")
    telemetry_scopes = (response_telemetry, drop_telemetry)
    require(
        all(any(scope.start <= offset < scope.end for scope in telemetry_scopes) for offset in family_offsets),
        "SSH phase telemetry escapes its directly acceptance-gated helpers",
    )
    integration = backend.raw + owner.raw + response_telemetry.raw + drop_telemetry.raw
    for forbidden in (".finish(", "StreamLease", "publish_profile", "physical_evidence", "profile_irq_", "TrapIrqCookie"):
        require(forbidden not in CORE.rust_mask(integration), f"SSH phase parent admits forbidden {forbidden}")


def verify_phase(inputs: Inputs) -> None:
    verify_features(inputs)
    verify_runtime(inputs.runtime)
    verify_sshd(inputs.sshd)
    verify_slot(inputs.slot)
    verify_component(inputs.component)
    verify_ssh(inputs.ssh)


def verify(inputs: Inputs, *, predecessor: bool = True) -> None:
    if predecessor:
        try:
            CORE.verify(inputs.predecessor())
        except CORE.VerificationError as error:
            raise VerificationError(f"predecessor verifier failed: {error}") from error
    verify_phase(inputs)


def replace_once(value: str, old: str, new: str, label: str) -> str:
    count = value.count(old)
    require(count == 1, f"selftest seed {label!r} count differs: {count}")
    return value.replace(old, new, 1)


def mutate_text(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    return replace(data, **{field: replace_once(getattr(data, field), old, new, label)})


def mutate_manifest(data: Inputs, field: str, old: str, new: str, label: str) -> Inputs:
    raw = getattr(data, field).decode("utf-8")
    return replace(data, **{field: replace_once(raw, old, new, label).encode("utf-8")})


def expect_rejected(inputs: Inputs, mutation: Callable[[Inputs], Inputs], label: str) -> None:
    mutated = mutation(inputs)
    require(mutated != inputs, f"selftest mutation made no change: {label}")
    try:
        verify(mutated, predecessor=False)
    except VerificationError:
        return
    raise VerificationError(f"selftest mutation unexpectedly accepted: {label}")


def shadow_sshd_poll_fn(inputs: Inputs) -> Inputs:
    sshd = replace_once(
        inputs.sshd,
        "use core::future::{poll_fn, Future};",
        "use core::future::Future;",
        "sshd-poll-fn-shadow-import",
    )
    sshd = replace_once(
        sshd,
        '#[cfg(feature = "c84-profile-phase-sidecar")]\nasync fn wait_with_profile',
        '#[cfg(feature = "c84-profile-phase-sidecar")]\n'
        "fn poll_fn<T, F>(_operation: F) -> impl Future<Output = T>\n"
        "where\n"
        "    F: FnMut(&mut core::task::Context<'_>) -> Poll<T>,\n"
        "{\n"
        "    core::future::pending()\n"
        "}\n\n"
        '#[cfg(feature = "c84-profile-phase-sidecar")]\n'
        "async fn wait_with_profile",
        "sshd-poll-fn-shadow-definition",
    )
    return replace(inputs, sshd=sshd)


def run_selftest(inputs: Inputs) -> int:
    verify(inputs)
    mutations: list[tuple[str, Callable[[Inputs], Inputs]]] = [
        (
            "kernel-default-on",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                'default = ["qemu-virt", "qemu-default-image"]',
                f'default = ["qemu-virt", "qemu-default-image", "{FEATURE}"]',
                "kernel-default-on",
            ),
        ),
        (
            "feature-adds-irq",
            lambda data: mutate_manifest(
                data,
                "kernel_manifest",
                f'{FEATURE} = [\n    "{CORE_FEATURE}",\n    "vibeos-sshd/{SSHD_FEATURE}",\n]',
                f'{FEATURE} = [\n    "{CORE_FEATURE}",\n    "vibeos-sshd/{SSHD_FEATURE}",\n    "{IRQ_FEATURE}",\n]',
                "feature-adds-irq",
            ),
        ),
        (
            "sshd-parent-closure-removed",
            lambda data: mutate_manifest(
                data,
                "sshd_manifest",
                f'{SSHD_FEATURE} = ["{SSHD_PARENT_FEATURE}"]',
                f'{SSHD_FEATURE} = []',
                "sshd-parent-closure-removed",
            ),
        ),
        (
            "milkv-default-enables-external-phase",
            lambda data: mutate_manifest(
                data,
                "milkv_manifest",
                'default = ["milkv-ssh"]',
                f'default = ["milkv-ssh", "vibeos-kernel/{FEATURE}"]',
                "milkv-default-enables-external-phase",
            ),
        ),
        (
            "qemu-default-enables-external-base-phase",
            lambda data: mutate_manifest(
                data,
                "qemu_manifest",
                "default = []",
                f'default = ["vibeos-kernel/{FEATURE}"]',
                "qemu-default-enables-external-base-phase",
            ),
        ),
        (
            "runtime-cleanup-default-removed",
            lambda data: mutate_text(
                data,
                "runtime",
                "    fn cleanup_started(&mut self) {}",
                "    fn cleanup_started(&mut self);",
                "runtime-cleanup-default-removed",
            ),
        ),
        (
            "runtime-cleanup-repeat-enabled",
            lambda data: mutate_text(
                data,
                "runtime",
                "            clock.cleanup_started();\n            self.profile_cleanup_started = true;",
                "            clock.cleanup_started();\n            self.profile_cleanup_started = false;",
                "runtime-cleanup-repeat-enabled",
            ),
        ),
        (
            "sshd-wait-helper-calls-host",
            lambda data: mutate_text(
                data,
                "sshd",
                "    run.phase_wait()\n}",
                "    run.phase_host()\n}",
                "sshd-wait-helper-calls-host",
            ),
        ),
        (
            "sshd-managed-shadows-poll-wrapper",
            lambda data: mutate_text(
                data,
                "sshd",
                ") -> ExecutionEnd {\n"
                "    let mut pump = ComponentStreamPump::new(io);",
                ") -> ExecutionEnd {\n"
                "    fn wait_with_profile<'a, F: Future + 'a>(\n"
                "        future: F,\n"
                "        _profile_run: &'a mut Option<SshExecProfileRun>,\n"
                "    ) -> impl Future<Output = Result<F::Output, ()>> + 'a {\n"
                "        async move { Ok(future.await) }\n"
                "    }\n"
                "    let mut pump = ComponentStreamPump::new(io);",
                "sshd-managed-shadows-poll-wrapper",
            ),
        ),
        (
            "sshd-core-poll-fn-shadowed",
            shadow_sshd_poll_fn,
        ),
        (
            "sshd-managed-consumes-profile-run",
            lambda data: mutate_text(
                data,
                "sshd",
                ") -> ExecutionEnd {\n"
                "    let mut pump = ComponentStreamPump::new(io);",
                ") -> ExecutionEnd {\n"
                '    #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "    let _ = profile_run.take();\n"
                "    let mut pump = ComponentStreamPump::new(io);",
                "sshd-managed-consumes-profile-run",
            ),
        ),
        (
            "sshd-managed-shadows-profile-run",
            lambda data: mutate_text(
                data,
                "sshd",
                ") -> ExecutionEnd {\n"
                "    let mut pump = ComponentStreamPump::new(io);",
                ") -> ExecutionEnd {\n"
                '    #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "    let mut disabled_profile_run = None;\n"
                '    #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "    let profile_run = &mut disabled_profile_run;\n"
                "    let mut pump = ComponentStreamPump::new(io);",
                "sshd-managed-shadows-profile-run",
            ),
        ),
        (
            "sshd-poll-wrapper-host-only-once",
            lambda data: mutate_text(
                data,
                "sshd",
                "    let mut future = core::pin::pin!(future);\n"
                "    poll_fn(|cx| {\n"
                "        if reach_profile_host_phase(profile_run).is_err() {\n"
                "            return Poll::Ready(Err(()));\n"
                "        }\n"
                "        match future.as_mut().poll(cx) {",
                "    let mut future = core::pin::pin!(future);\n"
                "    reach_profile_host_phase(profile_run)?;\n"
                "    poll_fn(|cx| {\n"
                "        match future.as_mut().poll(cx) {",
                "sshd-poll-wrapper-host-only-once",
            ),
        ),
        (
            "sshd-poll-wrapper-wait-before-poll",
            lambda data: mutate_text(
                data,
                "sshd",
                "        if reach_profile_host_phase(profile_run).is_err() {\n"
                "            return Poll::Ready(Err(()));\n"
                "        }\n"
                "        match future.as_mut().poll(cx) {",
                "        if reach_profile_wait_phase(profile_run).is_err() {\n"
                "            return Poll::Ready(Err(()));\n"
                "        }\n"
                "        match future.as_mut().poll(cx) {",
                "sshd-poll-wrapper-wait-before-poll",
            ),
        ),
        (
            "sshd-poll-wrapper-ready-enters-wait",
            lambda data: mutate_text(
                data,
                "sshd",
                "            Poll::Ready(output) => Poll::Ready(Ok(output)),",
                "            Poll::Ready(output) => {\n"
                "                let _ = reach_profile_wait_phase(profile_run);\n"
                "                Poll::Ready(Ok(output))\n"
                "            }",
                "sshd-poll-wrapper-ready-enters-wait",
            ),
        ),
        (
            "sshd-poll-wrapper-pending-bypasses-wait",
            lambda data: mutate_text(
                data,
                "sshd",
                "            Poll::Pending => match reach_profile_wait_phase(profile_run) {\n"
                "                Ok(()) => Poll::Pending,\n"
                "                Err(()) => Poll::Ready(Err(())),\n"
                "            },",
                "            Poll::Pending => Poll::Pending,",
                "sshd-poll-wrapper-pending-bypasses-wait",
            ),
        ),
        (
            "sshd-cancellation-restores-wait-before-await",
            lambda data: mutate_text(
                data,
                "sshd",
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            let waited = match wait_with_profile(wait, profile_run).await {\n"
                "                Ok(waited) => waited,\n"
                '                Err(()) => break ExecutionEnd::Reset("SSH exec profile Wait phase failed"),\n'
                "            };\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            let waited = wait.await;",
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            let waited = {\n"
                "                if reach_profile_wait_phase(profile_run).is_err() {\n"
                '                    break ExecutionEnd::Reset("SSH exec profile Wait phase failed");\n'
                "                }\n"
                "                wait.await\n"
                "            };\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            let waited = wait.await;",
                "sshd-cancellation-restores-wait-before-await",
            ),
        ),
        (
            "sshd-execution-turn-bypasses-poll-wrapper",
            lambda data: mutate_text(
                data,
                "sshd",
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            let reports = match wait_with_profile(wait, profile_run).await {\n"
                "                Ok(reports) => reports,\n"
                '                Err(()) => break ExecutionEnd::Reset("SSH exec profile Wait phase failed"),\n'
                "            };\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            let reports = wait.await;",
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            let reports = wait.await;\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            let reports = wait.await;",
                "sshd-execution-turn-bypasses-poll-wrapper",
            ),
        ),
        (
            "sshd-execution-turn-dead-wrapper-live-direct-await",
            lambda data: mutate_text(
                data,
                "sshd",
                "        if completed.is_none() {\n"
                "            let wait = wait_for_execution_turn(\n"
                "                execution.as_mut(),\n"
                "                wait_worked,\n"
                "                wire.next_poll_delay_ms,\n"
                "                Some(execution_deadline),\n"
                "            );\n"
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            let reports = match wait_with_profile(wait, profile_run).await {\n"
                "                Ok(reports) => reports,\n"
                '                Err(()) => break ExecutionEnd::Reset("SSH exec profile Wait phase failed"),\n'
                "            };\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            let reports = wait.await;\n"
                "            if let Some(reports) = reports {",
                "        if completed.is_none() {\n"
                "            if false {\n"
                "                let wait = wait_for_execution_turn(\n"
                "                    execution.as_mut(),\n"
                "                    wait_worked,\n"
                "                    wire.next_poll_delay_ms,\n"
                "                    Some(execution_deadline),\n"
                "                );\n"
                '                #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "                let reports = match wait_with_profile(wait, profile_run).await {\n"
                "                    Ok(reports) => reports,\n"
                '                    Err(()) => break ExecutionEnd::Reset("SSH exec profile Wait phase failed"),\n'
                "                };\n"
                '                #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "                let reports = wait.await;\n"
                "                let _ = reports;\n"
                "            }\n"
                "            let reports = (wait_for_execution_turn)(\n"
                "                execution.as_mut(),\n"
                "                wait_worked,\n"
                "                wire.next_poll_delay_ms,\n"
                "                Some(execution_deadline),\n"
                "            )\n"
                "            .await;\n"
                "            if let Some(reports) = reports {",
                "sshd-execution-turn-dead-wrapper-live-direct-await",
            ),
        ),
        (
            "sshd-cooperate-bypasses-poll-wrapper",
            lambda data: mutate_text(
                data,
                "sshd",
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            if wait_with_profile(wait, profile_run).await.is_err() {\n"
                '                break ExecutionEnd::Reset("SSH exec profile Wait phase failed");\n'
                "            }\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            wait.await;",
                '            #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "            wait.await;\n"
                '            #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "            wait.await;",
                "sshd-cooperate-bypasses-poll-wrapper",
            ),
        ),
        (
            "sshd-shutdown-bypasses-poll-wrapper",
            lambda data: mutate_text(
                data,
                "sshd",
                '    #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "    if wait_with_profile(shutdown, profile_run).await.is_err() {\n"
                '        return ExecutionEnd::Reset("SSH exec profile Wait phase failed");\n'
                "    }\n"
                '    #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "    shutdown.await;",
                '    #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "    shutdown.await;\n"
                '    #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "    shutdown.await;",
                "sshd-shutdown-bypasses-poll-wrapper",
            ),
        ),
        (
            "sshd-finish-bypasses-poll-wrapper",
            lambda data: mutate_text(
                data,
                "sshd",
                '        #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "        wait_with_profile(wait, profile_run)\n"
                "            .await\n"
                '            .map_err(|_| ConnectionEnd::Reset("SSH exec profile Wait phase failed"))?;\n'
                '        #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "        wait.await;",
                '        #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "        wait.await;\n"
                '        #[cfg(not(feature = "c84-profile-phase-sidecar"))]\n'
                "        wait.await;",
                "sshd-finish-bypasses-poll-wrapper",
            ),
        ),
        (
            "sshd-bridge-host-edge-removed",
            lambda data: mutate_text(
                data,
                "sshd",
                '        #[cfg(feature = "c84-profile-phase-sidecar")]\n'
                "        if reach_profile_host_phase(profile_run).is_err() {\n"
                '            break ExecutionEnd::Reset("SSH exec profile Host phase failed");\n'
                "        }\n"
                "        let wire = match bridge.drive(runner, stack, now) {",
                "        let wire = match bridge.drive(runner, stack, now) {",
                "sshd-bridge-host-edge-removed",
            ),
        ),
        (
            "child-wait-overlaps-host",
            lambda data: mutate_text(
                data,
                "slot",
                "    fn child_enter_wait(&mut self) -> Result<(), ()> {\n        if self.child_waiting || self.child_host_open {",
                "    fn child_enter_wait(&mut self) -> Result<(), ()> {\n        if self.child_waiting {",
                "child-wait-overlaps-host",
            ),
        ),
        (
            "cleanup-repeats",
            lambda data: mutate_text(
                data,
                "slot",
                "        if self.cleanup_latched || self.child_waiting || self.child_host_open {\n            return Err(());\n        }",
                "        if self.child_waiting || self.child_host_open {\n            return Err(());\n        }",
                "cleanup-repeats",
            ),
        ),
        (
            "parent-drop-bypass-allows-extra-fault-bit",
            lambda data: mutate_text(
                data,
                "slot",
                "        && faults == SlotFaults::CHILD_ABANDONED_DETACHED",
                "        && faults.contains(SlotFaults::CHILD_ABANDONED_DETACHED)",
                "parent-drop-bypass-allows-extra-fault-bit",
            ),
        ),
        (
            "host-guard-send",
            lambda data: mutate_text(
                data,
                "slot",
                "pub(crate) struct ManagedChildHostPhase {\n    token: SampleToken,\n    detach: PreparedTaskDetachSeal,\n    live: bool,\n    not_send: PhantomData<*mut ()>,",
                "pub(crate) struct ManagedChildHostPhase {\n    token: SampleToken,\n    detach: PreparedTaskDetachSeal,\n    live: bool,\n    not_send: PhantomData<()>,",
                "host-guard-send",
            ),
        ),
        (
            "host-drop-fault-removed",
            lambda data: mutate_text(
                data,
                "slot",
                "            if !exact_scope {\n                mark_child_fault(self.token, self.detach);\n            }\n            mark_managed_child_phase_fault(self.token, self.detach);",
                "            if !exact_scope {\n                mark_child_fault(self.token, self.detach);\n            }\n            let _ = (self.token, self.detach);",
                "host-drop-fault-removed",
            ),
        ),
        (
            "child-phase-allows-cleanup",
            lambda data: mutate_text(
                data,
                "slot",
                "Phase::Validation | Phase::Instantiation | Phase::Abi",
                "Phase::Validation | Phase::Instantiation | Phase::Abi | Phase::Cleanup",
                "child-phase-allows-cleanup",
            ),
        ),
        (
            "resume-restores-abi",
            lambda data: mutate_text(
                data,
                "slot",
                "    fn child_resume_from_wait(&mut self) -> Result<Phase, ()> {\n        if !self.child_waiting || self.child_host_open {\n            return Err(());\n        }\n        self.child_waiting = false;",
                "    fn child_resume_from_wait(&mut self) -> Result<Phase, ()> {\n        if !self.child_waiting || self.child_host_open {\n            return Err(());\n        }\n        self.child_waiting = false;\n        self.child_base = ManagedChildBasePhase::Abi;",
                "resume-restores-abi",
            ),
        ),
        (
            "release-ignores-phase-ready",
            lambda data: mutate_text(
                data,
                "slot",
                "    if !managed_phase.child_release_ready() {",
                "    if false {",
                "release-ignores-phase-ready",
            ),
        ),
        (
            "response-allows-parent-wait",
            lambda data: mutate_text(
                data,
                "slot",
                "    if managed_phase.parent_waiting {",
                "    if false {",
                "response-allows-parent-wait",
            ),
        ),
        (
            "parent-instantiation-after-owner",
            lambda data: mutate_text(
                data,
                "component",
                "crate::wasm_aot_profile_slot::managed_current_parent_set_instantiation()",
                "crate::wasm_aot_profile_slot::managed_current_parent_set_instantiation_AFTER_OWNER()",
                "parent-instantiation-after-owner",
            ),
        ),
        (
            "dispatcher-resume-nested-cancel",
            lambda data: mutate_text(
                data,
                "component",
                "self.cancel_pending(unexposed.token)",
                "self.cancel(unexposed.token)",
                "dispatcher-resume-nested-cancel",
            ),
        ),
        (
            "stdin-evidence-base-feature-leak",
            lambda data: mutate_text(
                data,
                "component",
                f'#[cfg(feature = "{QEMU_FEATURE}")]\n'
                "#[derive(Clone, Copy, PartialEq, Eq)]\n"
                "struct C84DelayedStdinPending {",
                "#[derive(Clone, Copy, PartialEq, Eq)]\n"
                "struct C84DelayedStdinPending {",
                "stdin-evidence-base-feature-leak",
            ),
        ),
        (
            "stdin-evidence-records-write-waiting",
            lambda data: mutate_text(
                data,
                "component",
                "            match pending.kind {\n"
                "                PendingStreamKind::ReadWaiting => {",
                "            match pending.kind {\n"
                "                PendingStreamKind::ReadWaiting | PendingStreamKind::WriteWaiting => {",
                "stdin-evidence-records-write-waiting",
            ),
        ),
        (
            "stdin-evidence-record-helper-shadowed",
            lambda data: mutate_text(
                data,
                "component",
                "            match pending.kind {\n"
                "                PendingStreamKind::ReadWaiting => {",
                f'            #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "            let record_c84_delayed_stdin_pending =\n"
                "                |_: u64, _: HostOperationToken| Ok::<(), HostError>(());\n"
                "            match pending.kind {\n"
                "                PendingStreamKind::ReadWaiting => {",
                "stdin-evidence-record-helper-shadowed",
            ),
        ),
        (
            "stdin-evidence-ignores-register-result",
            lambda data: mutate_text(
                data,
                "component",
                "                    })??;\n"
                f'                    #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                    record_c84_delayed_stdin_pending(profile_epoch, operation)?;",
                "                    });\n"
                f'                    #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                    record_c84_delayed_stdin_pending(profile_epoch, operation)?;",
                "stdin-evidence-ignores-register-result",
            ),
        ),
        (
            "stdin-evidence-consumed-before-wait-opens",
            lambda data: mutate_text(
                data,
                "component",
                "                if profile_epoch != 0 {\n"
                "                    if crate::wasm_aot_profile_slot::managed_child_enter_wait(profile_epoch)\n"
                "                        .is_err()\n"
                "                    {\n"
                "                        return terminal_word(ComponentTerminal::RunnerFault);\n"
                "                    }\n"
                f'                    #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                    {\n"
                "                        let delayed_stdin_pending =\n"
                "                            take_c84_delayed_stdin_pending(profile_epoch, operation);",
                "                if profile_epoch != 0 {\n"
                f'                    #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                    let delayed_stdin_pending =\n"
                "                        take_c84_delayed_stdin_pending(profile_epoch, operation);\n"
                "                    if crate::wasm_aot_profile_slot::managed_child_enter_wait(profile_epoch)\n"
                "                        .is_err()\n"
                "                    {\n"
                "                        return terminal_word(ComponentTerminal::RunnerFault);\n"
                "                    }\n"
                f'                    #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "                    {",
                "stdin-evidence-consumed-before-wait-opens",
            ),
        ),
        (
            "stdin-evidence-consume-ignores-operation",
            lambda data: mutate_text(
                data,
                "component",
                "    if *pending == Some(C84DelayedStdinPending { epoch, operation }) {",
                "    if pending.as_ref().is_some_and(|pending| pending.epoch == epoch) {",
                "stdin-evidence-consume-ignores-operation",
            ),
        ),
        (
            "stdin-evidence-consume-does-not-clear",
            lambda data: mutate_text(
                data,
                "component",
                "        *pending = None;\n"
                "        true",
                "        true",
                "stdin-evidence-consume-does-not-clear",
            ),
        ),
        (
            "stdin-evidence-take-helper-shadowed",
            lambda data: mutate_text(
                data,
                "component",
                ") -> u64 {\n"
                "    #[cfg(not(any(",
                ") -> u64 {\n"
                f'    #[cfg(feature = "{QEMU_FEATURE}")]\n'
                "    let take_c84_delayed_stdin_pending =\n"
                "        |_: u64, _: HostOperationToken| true;\n"
                "    #[cfg(not(any(",
                "stdin-evidence-take-helper-shadowed",
            ),
        ),
        (
            "stdin-evidence-marker-ignores-proof",
            lambda data: mutate_text(
                data,
                "component",
                "                            && delayed_stdin_pending\n"
                "                            && !epoch_two_host_pending_reported",
                "                            && !epoch_two_host_pending_reported",
                "stdin-evidence-marker-ignores-proof",
            ),
        ),
        (
            "cancel-wait-reclaiming-rejected",
            lambda data: mutate_text(
                data,
                "slot",
                "    if !detach.is_current_running_exact() && !detach.is_current_reclaiming_exact() {",
                "    if !detach.is_current_running_exact() {",
                "cancel-wait-reclaiming-rejected",
            ),
        ),
        (
            "cancel-bypass-query-early-true",
            lambda data: mutate_text(
                data,
                "slot",
                "pub(crate) fn managed_child_cancel_bypasses_host(epoch: u64) -> Result<bool, ProfileError> {\n"
                "    ensure_not_poisoned()?;",
                "pub(crate) fn managed_child_cancel_bypasses_host(epoch: u64) -> Result<bool, ProfileError> {\n"
                "    if epoch != 0 {\n"
                "        return Ok(true);\n"
                "    }\n"
                "    ensure_not_poisoned()?;",
                "cancel-bypass-query-early-true",
            ),
        ),
        (
            "abandoned-cancel-faults-widened",
            lambda data: mutate_text(
                data,
                "slot",
                "        DelegatedChildState::Abandoned if *faults == SlotFaults::CHILD_ABANDONED => Ok(true),",
                "        DelegatedChildState::Abandoned if faults.contains(SlotFaults::CHILD_ABANDONED) => Ok(true),",
                "abandoned-cancel-faults-widened",
            ),
        ),
        (
            "wait-closed-cancel-bypasses-host",
            lambda data: mutate_text(
                data,
                "component",
                "        Ok(false) => with_managed_child_host_phase(epoch, operation),",
                "        Ok(false) => operation(),",
                "wait-closed-cancel-bypasses-host",
            ),
        ),
        (
            "cancel-phase-helper-early-operation",
            lambda data: mutate_text(
                data,
                "component",
                "fn with_managed_child_cancel_phase<T>(\n"
                "    epoch: u64,\n"
                "    operation: impl FnOnce() -> Result<T, HostError>,\n"
                ") -> Result<T, HostError> {\n"
                "    if epoch == 0 {",
                "fn with_managed_child_cancel_phase<T>(\n"
                "    epoch: u64,\n"
                "    operation: impl FnOnce() -> Result<T, HostError>,\n"
                ") -> Result<T, HostError> {\n"
                "    if epoch != 0 {\n"
                "        return operation();\n"
                "    }\n"
                "    if epoch == 0 {",
                "cancel-phase-helper-early-operation",
            ),
        ),
        (
            "public-cancel-skips-narrow-helper",
            lambda data: mutate_text(
                data,
                "component",
                "            with_managed_child_cancel_phase(profile_epoch, action)",
                "            action()",
                "public-cancel-skips-narrow-helper",
            ),
        ),
        (
            "pending-wait-entry-removed",
            lambda data: mutate_text(
                data,
                "component",
                "            TypedPoll::Pending(_) => {",
                "            TypedPoll::Pending_REMOVED(_) => {",
                "pending-wait-entry-removed",
            ),
        ),
        (
            "cleanup-telemetry-widened",
            lambda data: mutate_text(
                data,
                "slot",
                f'"{FAMILY} CHILD_PHASE epoch={{}} phase=cleanup"',
                f'"{FAMILY} CHILD_PHASE epoch={{}} phase=cleanup cleanup_latched=1"',
                "cleanup-telemetry-widened",
            ),
        ),
        (
            "validation-telemetry-guard-removed",
            lambda data: mutate_text(
                data,
                "component",
                f'        #[cfg(feature = "{QEMU_FEATURE}")]\n        crate::println!(\n            "{FAMILY} CHILD_PHASE epoch={{}} phase=validation",',
                f'        crate::println!(\n            "{FAMILY} CHILD_PHASE epoch={{}} phase=validation",',
                "validation-telemetry-guard-removed",
            ),
        ),
        (
            "cleanup-telemetry-guard-removed",
            lambda data: mutate_text(
                data,
                "slot",
                f'        #[cfg(feature = "{QEMU_FEATURE}")]\n        if error.is_none() {{',
                "        if error.is_none() {",
                "cleanup-telemetry-guard-removed",
            ),
        ),
        (
            "extra-host-finish-outside-helper",
            lambda data: mutate_text(
                data,
                "component",
                "            let result = call.poll_profiled(&mut clock, &mut core_profile);",
                "            phase.finish();\n            let result = call.poll_profiled(&mut clock, &mut core_profile);",
                "extra-host-finish-outside-helper",
            ),
        ),
        (
            "ssh-parent-host-calls-wait",
            lambda data: mutate_text(
                data,
                "ssh",
                "        run.managed_parent_host().map_err(|_| {",
                "        run.managed_parent_wait().map_err(|_| {",
                "ssh-parent-host-calls-wait",
            ),
        ),
        (
            "ssh-response-finish",
            lambda data: mutate_text(
                data,
                "ssh",
                f'#[cfg(not(feature = "{FINISH_FEATURE}"))]\n'
                "        let terminal =\n"
                "            cancel_and_ack_profile(run, crate::wasm_aot_profile_slot::SlotFaults::default())\n"
                "                .map(|ready_epoch| (ready_epoch, ()));",
                f'#[cfg(not(feature = "{FINISH_FEATURE}"))]\n'
                "        let terminal =\n"
                "            finish_and_ack_profile(run, crate::wasm_aot_profile_slot::SlotFaults::default())\n"
                "                .map(|ready_epoch| (ready_epoch, ()));",
                "ssh-response-finish",
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
            "PASS verify-c84-ssh-managed-child-phase-sidecar: default-off parent/child "
            "Host/Wait/Cleanup ownership, per-poll Host/Pending-only Wait boundaries, "
            "synchronous !Send Host guards, exact wait resume, "
            f"cancel/ack closure, and diagnostic isolation are closed{suffix}"
        )
        return 0
    except (
        OSError,
        UnicodeError,
        RuntimeError,
        tomllib.TOMLDecodeError,
        VerificationError,
    ) as error:
        print(f"FAIL verify-c84-ssh-managed-child-phase-sidecar: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
