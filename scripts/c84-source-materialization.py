#!/usr/bin/env python3
"""Materialize and verify the frozen C8.4 source snapshot.

This tool has two formal modes:

``materialize``
    Starting from an initialized operator superproject at an exact detached or
    attached commit, create three local Git bundles (the superproject and the
    exact ``vendor/jitterentropy-rs`` and ``vendor/sunset`` gitlinks), clone
    each bundle without network access into a random sibling staging directory,
    apply the repository-recorded jitterentropy patch, remove all
    remotes/ordinary refs/reflogs/hooks, close each local Git config, run strict
    ``git fsck``, prove that no source/clone Git-admin regular file shares a
    device+inode pair, freeze every source/admin path except ``target/``, then
    atomically publish that entire directory with kernel no-replace semantics
    and parent-directory ``fsync``.  The two cloned submodules keep real,
    independent ``.git`` directories.  The destination parent and staging
    directory remain bound by open directory descriptors and device+inode
    identity through publication.

``verify``
    Recompute the exact patched worktree snapshot, Git-admin closure, fsck,
    write-protection, and content-addressed envelope.  No clean-baseline mode
    exists: the only accepted state contains the exact reviewed patch.  When
    ``--operator-source`` is supplied, verification also repeats the zero
    shared-device+inode proof against that source repository.  The restricted
    ``--container-mounted-read-only`` form is only admitted at the fixed
    ``/home/vibeos`` runtime mount: it rechecks content, permissions, file
    counts, single-link files, and clone/clone disjointness in the guest inode
    namespace while retaining the host inode proof from the envelope.  The
    host launcher and final offline verifier still run the full form.

The envelope is canonical JSON and is atomically/no-clobber published at
``target/c84-source-materialization/<commit>/<challenge>/`` beneath the clone.
The tool uses only the Python standard library and local ``git``.  Its Git
environment disables replacement objects, lazy fetch, optional locks, prompts,
hooks, fsmonitor, system/global configuration, alternate object directories,
and every protocol except ``file``.  Operator local configs are stably read;
includes and executable/external-command keys are rejected.  Inert remote,
branch, and submodule URL metadata is never followed.

``--selftest`` constructs a tiny, entirely local three-repository fixture and
exercises the positive path plus duplicate JSON, wrong identity, dirty and
untracked worktrees, wrong submodule HEAD, alternates, replacement refs,
shallow state, writable Git admin, swapped/truncated envelopes, and no-clobber
publication.  It also attacks parent/stage path replacement, an external
same-byte hardlink, and an executable ``core.fsmonitor`` sentinel.
``--selftest --check-source`` additionally checks this script's own closed
implementation surface.  Neither self-test uses the network, Docker, a UART,
or a physical device.
"""

from __future__ import annotations

import argparse
import ast
import ctypes
import datetime
import errno
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, NoReturn, Sequence


SCRIPT_PATH = pathlib.Path(__file__).resolve()
ROOT = SCRIPT_PATH.parent.parent
SCHEMA = "vibeos.c84.source-materialization-envelope"
VERSION = 1
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_ENVELOPE_BYTES = 16_777_216
PATCH_RELATIVE = pathlib.PurePosixPath(
    "patches/jitterentropy-rs/0001-vibeos-qualification.patch"
)
PATCH_SHA256 = "4f815887ca98efe34ec51a918a5e8c495e4540d93ef40dfbf79611eb30314f00"
PATCH_BYTES = 3_238
FORMAL_SUBMODULES = (
    ("vendor/jitterentropy-rs", "c5bd2e17194fe3a04d17f74027bb67622579405f"),
    ("vendor/sunset", "f686eaaaba8b2eda3f83e23b4bb3005cae31ce5e"),
)
ENVELOPE_RELATIVE_ROOT = pathlib.PurePosixPath("target/c84-source-materialization")
CLOSED_CONFIG = (
    b"[core]\n"
    b"\trepositoryformatversion = 0\n"
    b"\tfilemode = true\n"
    b"\tbare = false\n"
    b"\tlogallrefupdates = false\n"
)
SNAPSHOT_DOMAIN = b"vibeos.c84.frozen-source-snapshot.v1\0"
ADMIN_DOMAIN = b"vibeos.c84.closed-git-admin.v1\0"
INODE_DOMAIN = b"vibeos.c84.git-admin-inodes.v1\0"
MATERIALIZATION_METHOD = (
    "three-local-bundles; standalone-clones; exact-jitterentropy-patch; "
    "closed-git-admin; frozen-source-except-target; sibling-stage; "
    "kernel-atomic-no-replace-publish; parent-directory-fsync"
)
DESTINATION_PUBLISH_POLICY = (
    "Linux renameat2(RENAME_NOREPLACE) or Darwin renameatx_np(RENAME_EXCL); "
    "held O_DIRECTORY|O_NOFOLLOW parent/stage descriptors; bound dev+ino; "
    "same-parent staging; same-parent-descriptor fsync"
)
SAFE_GIT_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=/usr/bin/false",
    "-c",
    "core.sshCommand=/usr/bin/false",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.file.allow=always",
)


class MaterializationError(RuntimeError):
    """The source materialization boundary is not closed."""


def fail(message: str) -> NoReturn:
    raise MaterializationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


@dataclass(frozen=True)
class SubmoduleSpec:
    path: str
    commit: str


@dataclass(frozen=True)
class Contract:
    submodules: tuple[SubmoduleSpec, ...]
    patch_relative: pathlib.PurePosixPath
    patch_sha256: str
    patch_bytes: int


@dataclass(frozen=True)
class RepoFacts:
    root: pathlib.Path
    git_dir: pathlib.Path
    common_dir: pathlib.Path
    head: str
    tree: str
    object_format: str


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    kind: str
    oid: str
    path: str


@dataclass(frozen=True)
class FileIdentity:
    sha256: str
    bytes: int

    def as_dict(self) -> dict[str, object]:
        return {"bytes": self.bytes, "sha256": self.sha256}


@dataclass(frozen=True)
class DirectoryBinding:
    path: pathlib.Path
    fd: int
    device: int
    inode: int


@dataclass(frozen=True)
class TreeSummary:
    sha256: str
    entries: int
    bytes: int

    def as_dict(self) -> dict[str, object]:
        return {
            "algorithm": "sha256(domain-NUL,path-NUL,mode-NUL,kind-NUL,length-NUL,bytes)*",
            "bytes": self.bytes,
            "entries": self.entries,
            "sha256": self.sha256,
        }


FORMAL_CONTRACT = Contract(
    submodules=tuple(SubmoduleSpec(*item) for item in FORMAL_SUBMODULES),
    patch_relative=PATCH_RELATIVE,
    patch_sha256=PATCH_SHA256,
    patch_bytes=PATCH_BYTES,
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_commit(value: str, label: str) -> str:
    require(HEX40.fullmatch(value) is not None, f"{label} must be 40 lowercase hex")
    require(value != "0" * 40, f"{label} must not be all zero")
    require(value != "1" * 40, f"{label} must not use the test sentinel")
    return value


def canonical_challenge(value: str, label: str) -> str:
    require(HEX64.fullmatch(value) is not None, f"{label} must be 64 lowercase hex")
    require(value != "0" * 64, f"{label} must not be all zero")
    require(value != "2" * 64, f"{label} must not use the QEMU sentinel")
    return value


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(set(value) == keys, f"{label} fields are not closed")
    return value


def stable_regular_bytes(
    path: pathlib.Path,
    label: str,
    *,
    maximum: int | None = None,
    require_single_link: bool = True,
) -> bytes:
    require(hasattr(os, "O_NOFOLLOW"), "platform lacks O_NOFOLLOW")
    descriptor: int | None = None
    try:
        before_lstat = path.lstat()
        require(
            stat.S_ISREG(before_lstat.st_mode)
            and not stat.S_ISLNK(before_lstat.st_mode),
            f"{label} is not a regular non-symlink file: {path}",
        )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        require(
            (before_lstat.st_dev, before_lstat.st_ino)
            == (before.st_dev, before.st_ino),
            f"{label} path was replaced while opened",
        )
        require(stat.S_ISREG(before.st_mode), f"{label} descriptor is not regular")
        require(
            not require_single_link or before.st_nlink == 1, f"{label} is hardlinked"
        )
        require(
            maximum is None or before.st_size <= maximum,
            f"{label} exceeds its byte bound",
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        after_lstat = path.lstat()
    except OSError as error:
        fail(f"cannot read {label} {path}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    require(
        tuple(getattr(before_lstat, field) for field in fields)
        == tuple(getattr(before, field) for field in fields)
        == tuple(getattr(after, field) for field in fields)
        == tuple(getattr(after_lstat, field) for field in fields),
        f"{label} changed while it was read",
    )
    require(len(raw) == before.st_size, f"{label} was truncated while read")
    return raw


def identity(
    path: pathlib.Path, label: str, *, require_single_link: bool = True
) -> FileIdentity:
    raw = stable_regular_bytes(path, label, require_single_link=require_single_link)
    return FileIdentity(sha256_bytes(raw), len(raw))


def git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    environment = {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SSH_ASKPASS": "/usr/bin/false",
        "TZ": "UTC",
    }
    if extra:
        environment.update(extra)
    return environment


def run_command(
    arguments: Sequence[str],
    *,
    cwd: pathlib.Path | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    command = list(arguments)
    if command and pathlib.Path(command[0]).name == "git":
        command[1:1] = SAFE_GIT_OPTIONS
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=git_environment(extra_env),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot execute {arguments[0]!r}: {error}")
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(errors="replace").strip()
        fail(f"command failed ({' '.join(command)}): {detail}")
    return completed


def git(
    repo: pathlib.Path,
    *arguments: str,
    check: bool = True,
    input_bytes: bytes | None = None,
) -> bytes:
    completed = run_command(
        ["git", "--no-optional-locks", "-C", str(repo), *arguments],
        input_bytes=input_bytes,
        check=check,
    )
    return completed.stdout


def canonical_existing_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    require(path.is_absolute(), f"{label} must be an absolute path")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label} {path}: {error}")
    require(
        stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode),
        f"{label} is not a fixed directory",
    )
    require(resolved == path, f"{label} must be canonical: {path}")
    return resolved


def directory_open_flags() -> int:
    require(hasattr(os, "O_DIRECTORY"), "platform lacks O_DIRECTORY")
    require(hasattr(os, "O_NOFOLLOW"), "platform lacks O_NOFOLLOW")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def stat_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def verify_directory_binding(binding: DirectoryBinding, label: str) -> None:
    try:
        descriptor_info = os.fstat(binding.fd)
        path_info = binding.path.lstat()
    except OSError as error:
        fail(f"cannot revalidate {label}: {error}")
    expected = (binding.device, binding.inode)
    require(
        stat.S_ISDIR(descriptor_info.st_mode)
        and stat.S_ISDIR(path_info.st_mode)
        and not stat.S_ISLNK(path_info.st_mode)
        and stat_identity(descriptor_info) == expected
        and stat_identity(path_info) == expected,
        f"{label} path or descriptor was replaced",
    )


def verify_stage_binding(
    parent: DirectoryBinding, stage: DirectoryBinding, stage_name: str
) -> None:
    verify_directory_binding(parent, "destination parent")
    try:
        entry_info = os.stat(stage_name, dir_fd=parent.fd, follow_symlinks=False)
        descriptor_info = os.fstat(stage.fd)
    except OSError as error:
        fail(f"cannot revalidate sibling staging directory: {error}")
    expected = (stage.device, stage.inode)
    require(
        stat.S_ISDIR(entry_info.st_mode)
        and stat.S_ISDIR(descriptor_info.st_mode)
        and stat_identity(entry_info) == expected
        and stat_identity(descriptor_info) == expected,
        "sibling staging directory name or descriptor was replaced",
    )


def verify_published_binding(
    parent: DirectoryBinding,
    stage: DirectoryBinding,
    destination: pathlib.Path,
) -> None:
    verify_directory_binding(parent, "destination parent")
    try:
        published = os.stat(destination.name, dir_fd=parent.fd, follow_symlinks=False)
        descriptor_info = os.fstat(stage.fd)
    except OSError as error:
        fail(f"cannot revalidate published destination: {error}")
    expected = (stage.device, stage.inode)
    require(
        stat.S_ISDIR(published.st_mode)
        and stat.S_ISDIR(descriptor_info.st_mode)
        and stat_identity(published) == expected
        and stat_identity(descriptor_info) == expected,
        "published destination is not the verified staging inode",
    )


def nonexistent_destination(
    path: pathlib.Path,
) -> tuple[pathlib.Path, DirectoryBinding]:
    require(path.is_absolute(), "destination must be absolute")
    require(path.name not in {"", ".", ".."}, "destination basename is unsafe")
    parent_path = path.parent
    descriptor: int | None = None
    try:
        descriptor = os.open(parent_path, directory_open_flags())
        descriptor_info = os.fstat(descriptor)
        path_info = parent_path.lstat()
        resolved = parent_path.resolve(strict=True)
        require(
            stat.S_ISDIR(descriptor_info.st_mode)
            and stat.S_ISDIR(path_info.st_mode)
            and not stat.S_ISLNK(path_info.st_mode)
            and stat_identity(descriptor_info) == stat_identity(path_info),
            "destination parent path changed while opened",
        )
        require(resolved == parent_path, "destination parent must be canonical")
        require(path == parent_path / path.name, "destination path is not canonical")
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"destination is no-clobber and already exists: {path}")
        binding = DirectoryBinding(
            parent_path,
            descriptor,
            descriptor_info.st_dev,
            descriptor_info.st_ino,
        )
        descriptor = None
        verify_directory_binding(binding, "destination parent")
        return path, binding
    except OSError as error:
        fail(f"cannot bind destination parent {parent_path}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def create_sibling_stage(
    parent: DirectoryBinding, destination_name: str
) -> tuple[str, DirectoryBinding]:
    """Reserve an unpredictable, same-parent directory for the complete build."""
    verify_directory_binding(parent, "destination parent")
    for _attempt in range(128):
        stage_name = f".{destination_name}.c84-stage-{secrets.token_hex(32)}"
        try:
            os.mkdir(stage_name, mode=0o700, dir_fd=parent.fd)
        except FileExistsError:
            continue
        except OSError as error:
            fail(f"cannot reserve sibling staging directory: {error}")
        descriptor: int | None = None
        try:
            descriptor = os.open(stage_name, directory_open_flags(), dir_fd=parent.fd)
            info = os.fstat(descriptor)
            require(
                stat.S_ISDIR(info.st_mode) and info.st_dev == parent.device,
                "sibling staging directory is not a same-filesystem directory",
            )
            stage = DirectoryBinding(
                parent.path / stage_name, descriptor, info.st_dev, info.st_ino
            )
            descriptor = None
            verify_stage_binding(parent, stage, stage_name)
            return stage_name, stage
        finally:
            if descriptor is not None:
                os.close(descriptor)
    fail("cannot reserve a unique sibling staging directory")


def atomic_publish_directory(
    stage_name: str,
    stage: DirectoryBinding,
    destination: pathlib.Path,
    parent: DirectoryBinding,
) -> None:
    """Publish ``stage`` with a kernel-enforced no-replace directory rename."""
    require(stage.path.parent == parent.path, "stage is not a destination sibling")
    require(
        destination.parent == parent.path,
        "destination moved away from its validated parent",
    )
    require(stage.path.name == stage_name, "staging name differs from its binding")
    verify_stage_binding(parent, stage, stage_name)
    library = ctypes.CDLL(None, use_errno=True)
    old_name = os.fsencode(stage_name)
    new_name = os.fsencode(destination.name)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError:
            fail("Darwin libc does not expose renameatx_np for atomic publication")
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            parent.fd, old_name, parent.fd, new_name, 0x00000004
        )  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError:
            fail("Linux libc does not expose renameat2 for atomic publication")
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            parent.fd, old_name, parent.fd, new_name, 0x00000001
        )  # RENAME_NOREPLACE
    else:
        fail(f"unsupported platform for atomic no-replace publication: {sys.platform}")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            fail(f"destination publication is no-clobber: {destination}")
        fail(
            "kernel atomic no-replace publication failed: "
            f"{os.strerror(error_number)} (errno {error_number})"
        )
    try:
        verify_published_binding(parent, stage, destination)
        try:
            os.stat(stage_name, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail("staging name survived atomic publication")
        verify_directory_binding(parent, "destination parent")
        os.fsync(parent.fd)
    except OSError as error:
        fail(f"cannot fsync destination parent after publication: {error}")


def resolve_git_path(repo: pathlib.Path, argument: str, label: str) -> pathlib.Path:
    raw = git(repo, "rev-parse", "--path-format=absolute", argument).decode().strip()
    path = pathlib.Path(raw)
    require(path.is_absolute(), f"{label} is not absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label} {path}: {error}")
    require(resolved.is_dir(), f"{label} is not a directory")
    return resolved


def config_records(repo: pathlib.Path) -> list[tuple[str, str]]:
    completed = run_command(
        [
            "git",
            "--no-optional-locks",
            "-C",
            str(repo),
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--list",
        ],
        check=True,
    )
    records: list[tuple[str, str]] = []
    for field in completed.stdout.split(b"\0"):
        if not field:
            continue
        try:
            key, value = field.split(b"\n", 1)
            records.append((key.decode("utf-8").lower(), value.decode("utf-8")))
        except (ValueError, UnicodeDecodeError) as error:
            fail(f"cannot parse local Git config in {repo}: {error}")
    return records


def config_file_records(path: pathlib.Path) -> list[tuple[str, str]]:
    completed = run_command(
        [
            "git",
            "config",
            "--file",
            str(path),
            "--no-includes",
            "--null",
            "--list",
        ]
    )
    records: list[tuple[str, str]] = []
    for field in completed.stdout.split(b"\0"):
        if not field:
            continue
        try:
            key, value = field.split(b"\n", 1)
            records.append((key.decode("utf-8").lower(), value.decode("utf-8")))
        except (ValueError, UnicodeDecodeError) as error:
            fail(f"cannot parse Git config file {path}: {error}")
    return records


def dangerous_operator_config(key: str, value: str) -> bool:
    if key.startswith(("include.", "includeif.")):
        return True
    if key in {
        "core.alternaterefscommand",
        "core.askpass",
        "core.attributesfile",
        "core.editor",
        "core.excludesfile",
        "core.fsmonitor",
        "core.gitproxy",
        "core.hookspath",
        "core.pager",
        "core.sshcommand",
        "diff.external",
        "interactive.difffilter",
        "sequence.editor",
    }:
        return True
    if key.startswith(
        (
            "alias.",
            "browser.",
            "credential.",
            "difftool.",
            "filter.",
            "http.",
            "mergetool.",
            "protocol.",
            "sendemail.",
            "url.",
        )
    ):
        return True
    if key.startswith("diff.") and key.rsplit(".", 1)[-1] in {
        "command",
        "textconv",
    }:
        return True
    if key.startswith("merge.") and key.endswith(".driver"):
        return True
    if key.startswith("remote.") and key.rsplit(".", 1)[-1] in {
        "partialclonefilter",
        "promisor",
        "proxy",
        "proxyauthmethod",
        "receivepack",
        "uploadpack",
        "vcs",
    }:
        return True
    if (
        key.startswith("submodule.")
        and key.endswith(".update")
        and value.lstrip().startswith("!")
    ):
        return True
    return False


def validate_operator_config(facts: RepoFacts, label: str) -> None:
    config_paths = [facts.common_dir / "config"]
    worktree_config = facts.git_dir / "config.worktree"
    if os.path.lexists(worktree_config):
        config_paths.append(worktree_config)
    before = {
        path: stable_regular_bytes(path, f"{label} local config {path.name}")
        for path in config_paths
    }
    records = config_records(facts.root)
    if worktree_config in config_paths:
        records.extend(config_file_records(worktree_config))
    after = {
        path: stable_regular_bytes(path, f"{label} local config {path.name}")
        for path in config_paths
    }
    require(before == after, f"{label} local config changed during preflight")
    dangerous = sorted(
        {key for key, value in records if dangerous_operator_config(key, value)}
    )
    require(
        not dangerous,
        f"{label} local config has executable/external keys: {dangerous}",
    )


def repository_facts(
    repo: pathlib.Path,
    expected_head: str,
    label: str,
    *,
    require_standalone: bool,
) -> RepoFacts:
    root = canonical_existing_directory(repo, label)
    inside = git(root, "rev-parse", "--is-inside-work-tree").decode().strip()
    require(inside == "true", f"{label} is not a worktree")
    top_level = canonical_existing_directory(
        pathlib.Path(git(root, "rev-parse", "--show-toplevel").decode().strip()),
        f"{label} reported worktree",
    )
    require(top_level == root, f"{label} redirects to another worktree")
    git_dir = resolve_git_path(root, "--git-dir", f"{label} Git dir")
    common_dir = resolve_git_path(root, "--git-common-dir", f"{label} common dir")
    if require_standalone:
        expected_git = root / ".git"
        require(
            git_dir == expected_git and common_dir == expected_git,
            f"{label} is a shared worktree or absorbed submodule",
        )
        require(
            expected_git.is_dir() and not expected_git.is_symlink(),
            f"{label} .git is not a real directory",
        )
        require(
            not (expected_git / "commondir").exists(),
            f"{label} has a shared common-dir pointer",
        )
    shallow = git(root, "rev-parse", "--is-shallow-repository").decode().strip()
    require(shallow == "false", f"{label} is shallow")
    object_format = git(root, "rev-parse", "--show-object-format").decode().strip()
    require(object_format == "sha1", f"{label} object format is not sha1")
    replace_refs = git(
        root, "for-each-ref", "--format=%(refname)", "refs/replace"
    ).splitlines()
    require(not replace_refs, f"{label} contains replacement refs")
    for admin_root in {git_dir, common_dir}:
        require(not (admin_root / "info/grafts").exists(), f"{label} contains grafts")
        require(
            not (admin_root / "objects/info/alternates").exists(),
            f"{label} contains object alternates",
        )
        require(
            not (admin_root / "shallow").exists(), f"{label} contains shallow state"
        )
        object_root = admin_root / "objects"
        if object_root.is_dir():
            require(
                not any(object_root.rglob("*.promisor")),
                f"{label} contains promisor object markers",
            )
    for key, value in config_records(root):
        require(key != "extensions.partialclone", f"{label} is a partial clone")
        require(
            not (key.endswith(".promisor") and value.lower() == "true"),
            f"{label} has a promisor remote",
        )
        require(
            key != "core.worktree" or not require_standalone,
            f"{label} redirects its worktree",
        )
    head = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    require(head == expected_head, f"{label} HEAD is {head}, expected {expected_head}")
    tree = git(root, "rev-parse", "--verify", f"{head}^{{tree}}").decode().strip()
    require(HEX40.fullmatch(tree) is not None, f"{label} tree id is malformed")
    return RepoFacts(root, git_dir, common_dir, head, tree, object_format)


def parse_tree(repo: pathlib.Path, commit: str, label: str) -> list[TreeEntry]:
    raw = git(repo, "ls-tree", "-rz", "--full-tree", commit)
    entries: list[TreeEntry] = []
    observed: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, encoded_path = record.split(b"\t", 1)
            mode_raw, kind_raw, oid_raw = header.split(b" ", 2)
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
            path = encoded_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            fail(f"cannot parse {label} tree record: {error}")
        pure = pathlib.PurePosixPath(path)
        require(
            not pure.is_absolute() and ".." not in pure.parts and "." not in pure.parts,
            f"{label} tree path escapes: {path!r}",
        )
        require(path not in observed, f"{label} tree repeats {path!r}")
        observed.add(path)
        require(HEX40.fullmatch(oid) is not None, f"{label} object id is malformed")
        if mode in {"100644", "100755", "120000"}:
            require(kind == "blob", f"{label} {path} is not a blob")
        elif mode == "160000":
            require(kind == "commit", f"{label} {path} is not a gitlink")
        else:
            fail(f"{label} has unsupported tracked mode {mode} at {path}")
        entries.append(TreeEntry(mode, kind, oid, path))
    return entries


def git_blob_oid(raw: bytes, object_format: str) -> str:
    require(
        object_format == "sha1", "only the frozen sha1 Git object format is supported"
    )
    digest = hashlib.sha1()  # noqa: S324 - Git's frozen object identity is SHA-1.
    digest.update(f"blob {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def stable_worktree_bytes(root: pathlib.Path, entry: TreeEntry, label: str) -> bytes:
    path = root.joinpath(*pathlib.PurePosixPath(entry.path).parts)
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label} {entry.path}: {error}")
    if entry.mode == "120000":
        require(stat.S_ISLNK(before.st_mode), f"{label} {entry.path} is not a symlink")
        target = os.readlink(path)
        raw = os.fsencode(target)
        pure_target = pathlib.PurePath(target)
        require(
            not pure_target.is_absolute(),
            f"{label} {entry.path} has an absolute symlink target",
        )
        try:
            resolved_parent = path.parent.resolve(strict=True)
            resolved_target = (resolved_parent / target).resolve(strict=False)
            resolved_target.relative_to(root)
        except (OSError, ValueError):
            fail(f"{label} {entry.path} symlink escapes the source root")
        after = path.lstat()
    else:
        require(stat.S_ISREG(before.st_mode), f"{label} {entry.path} is not regular")
        executable = bool(before.st_mode & 0o111)
        require(
            executable == (entry.mode == "100755"),
            f"{label} {entry.path} executable mode differs",
        )
        raw = stable_regular_bytes(path, f"{label} {entry.path}")
        after = path.lstat()
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"{label} {entry.path} changed while read",
    )
    return raw


def verify_clean_tracked_tree(facts: RepoFacts, label: str) -> None:
    entries = parse_tree(facts.root, facts.head, label)
    require(
        all(entry.mode != "160000" for entry in entries),
        f"{label} unexpectedly nests a submodule",
    )
    for entry in entries:
        raw = stable_worktree_bytes(facts.root, entry, label)
        require(
            git_blob_oid(raw, facts.object_format) == entry.oid,
            f"{label} {entry.path} differs from Git",
        )


def split_nul(raw: bytes, label: str) -> list[str]:
    result: list[str] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            result.append(item.decode("utf-8"))
        except UnicodeDecodeError as error:
            fail(f"{label} contains a non-UTF-8 path: {error}")
    return result


def untracked_paths(repo: pathlib.Path) -> tuple[list[str], list[str]]:
    ordinary = split_nul(
        git(repo, "ls-files", "--others", "--exclude-standard", "-z"),
        "untracked paths",
    )
    ignored = split_nul(
        git(repo, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"),
        "ignored paths",
    )
    return ordinary, ignored


def verify_no_untracked(repo: pathlib.Path, label: str, *, allow_target: bool) -> None:
    ordinary, ignored = untracked_paths(repo)
    unexpected = [
        path
        for path in ordinary + ignored
        if not (allow_target and (path == "target" or path.startswith("target/")))
    ]
    require(not unexpected, f"{label} has untracked files: {unexpected[:8]}")


def verify_source_preflight(
    source: pathlib.Path,
    source_commit: str,
    contract: Contract,
) -> tuple[RepoFacts, dict[str, RepoFacts], bytes]:
    source_facts = repository_facts(
        source, source_commit, "operator superproject", require_standalone=False
    )
    validate_operator_config(source_facts, "operator superproject")
    super_entries = parse_tree(source, source_commit, "operator superproject")
    gitlinks = {
        entry.path: entry.oid for entry in super_entries if entry.mode == "160000"
    }
    expected_links = {spec.path: spec.commit for spec in contract.submodules}
    require(gitlinks == expected_links, f"operator gitlinks differ: {gitlinks}")
    submodule_facts: dict[str, RepoFacts] = {}
    for spec in contract.submodules:
        path = source.joinpath(*pathlib.PurePosixPath(spec.path).parts)
        facts = repository_facts(
            path, spec.commit, f"operator {spec.path}", require_standalone=False
        )
        validate_operator_config(facts, f"operator {spec.path}")
        submodule_facts[spec.path] = facts
    status = git(
        source,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    require(not status, "operator source and initialized submodules must be clean")
    for entry in super_entries:
        if entry.mode == "160000":
            continue
        raw = stable_worktree_bytes(source, entry, "operator superproject")
        require(
            git_blob_oid(raw, source_facts.object_format) == entry.oid,
            f"operator superproject {entry.path} differs from Git",
        )
    for spec in contract.submodules:
        path = source.joinpath(*pathlib.PurePosixPath(spec.path).parts)
        facts = submodule_facts[spec.path]
        verify_clean_tracked_tree(facts, f"operator {spec.path}")
        verify_no_untracked(path, f"operator {spec.path}", allow_target=False)
    patch_path = source.joinpath(*contract.patch_relative.parts)
    patch = stable_regular_bytes(
        patch_path, "reviewed jitterentropy patch", maximum=1_048_576
    )
    require(
        len(patch) == contract.patch_bytes,
        "reviewed jitterentropy patch byte count differs",
    )
    require(
        sha256_bytes(patch) == contract.patch_sha256,
        "reviewed jitterentropy patch digest differs",
    )
    return source_facts, submodule_facts, patch


def bundle_record(
    repo: pathlib.Path,
    bundle: pathlib.Path,
    expected_head: str,
    role: str,
) -> dict[str, object]:
    require(not os.path.lexists(bundle), f"bundle output already exists: {bundle}")
    git(repo, "bundle", "create", str(bundle), "HEAD")
    raw = stable_regular_bytes(bundle, f"{role} bundle")
    git(repo, "bundle", "verify", str(bundle))
    heads = git(repo, "bundle", "list-heads", str(bundle)).decode().splitlines()
    require(heads == [f"{expected_head} HEAD"], f"{role} bundle heads differ: {heads}")
    return {
        "bytes": len(raw),
        "head": expected_head,
        "role": role,
        "sha256": sha256_bytes(raw),
    }


def verify_bundle_stable(
    bundle: pathlib.Path, record: dict[str, object], label: str
) -> None:
    raw = stable_regular_bytes(bundle, label)
    require(len(raw) == record["bytes"], f"{label} byte count changed")
    require(sha256_bytes(raw) == record["sha256"], f"{label} was swapped or truncated")


def clone_bundle(
    bundle: pathlib.Path,
    destination: pathlib.Path,
    commit: str,
    label: str,
    *,
    allow_reserved_empty: bool = False,
) -> None:
    if os.path.lexists(destination):
        require(
            allow_reserved_empty
            and destination.is_dir()
            and not destination.is_symlink()
            and not any(destination.iterdir()),
            f"{label} destination already exists or is not the reserved empty stage",
        )
    run_command(
        [
            "git",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-tags",
            "--no-checkout",
            str(bundle),
            str(destination),
        ]
    )
    git(destination, "checkout", "--detach", "--force", commit)
    resolved = (
        git(destination, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    )
    require(resolved == commit, f"{label} clone HEAD differs")


def remove_path(path: pathlib.Path) -> None:
    if not os.path.lexists(path):
        return
    if path.is_symlink() or path.is_file():
        path.unlink()
    else:
        shutil.rmtree(path)


def close_git_admin(repo: pathlib.Path, expected_head: str, label: str) -> RepoFacts:
    facts = repository_facts(repo, expected_head, label, require_standalone=True)
    refs = git(repo, "for-each-ref", "--format=%(refname)").decode().splitlines()
    for ref in refs:
        require(ref.startswith("refs/"), f"{label} has malformed ref {ref!r}")
        git(repo, "update-ref", "-d", ref)
    for transient in (
        "refs",
        "packed-refs",
        "logs",
        "hooks",
        "branches",
        "FETCH_HEAD",
        "ORIG_HEAD",
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-apply",
        "rebase-merge",
        "rr-cache",
    ):
        remove_path(facts.git_dir / transient)
    (facts.git_dir / "refs").mkdir(mode=0o700)
    config_path = facts.common_dir / "config"
    config_path.write_bytes(CLOSED_CONFIG)
    head_path = facts.git_dir / "HEAD"
    head_path.write_text(f"{expected_head}\n", encoding="ascii")
    closed = repository_facts(repo, expected_head, label, require_standalone=True)
    verify_closed_admin(closed, expected_head, label, run_fsck=True)
    return closed


def verify_closed_admin(
    facts: RepoFacts,
    expected_head: str,
    label: str,
    *,
    run_fsck: bool,
) -> None:
    require(
        facts.git_dir == facts.common_dir == facts.root / ".git",
        f"{label} Git admin is shared",
    )
    require(
        stable_regular_bytes(facts.common_dir / "config", f"{label} config")
        == CLOSED_CONFIG,
        f"{label} local config differs",
    )
    head_raw = stable_regular_bytes(facts.git_dir / "HEAD", f"{label} HEAD")
    require(
        head_raw == f"{expected_head}\n".encode("ascii"),
        f"{label} HEAD is not exact detached identity",
    )
    require(
        not git(facts.root, "for-each-ref", "--format=%(refname)"),
        f"{label} retains ordinary refs",
    )
    require(not (facts.git_dir / "hooks").exists(), f"{label} retains hooks")
    logs = facts.git_dir / "logs"
    require(not logs.exists(), f"{label} retains reflogs")
    refs = facts.git_dir / "refs"
    require(
        refs.is_dir() and not refs.is_symlink() and not list(refs.iterdir()),
        f"{label} retains loose refs",
    )
    require(
        not (facts.git_dir / "packed-refs").exists(),
        f"{label} retains packed refs",
    )
    require(not (facts.git_dir / "branches").exists(), f"{label} retains remotes")
    require(
        not (facts.git_dir / "commondir").exists(), f"{label} has a common-dir pointer"
    )
    for key, _value in config_records(facts.root):
        require(
            key
            in {
                "core.repositoryformatversion",
                "core.filemode",
                "core.bare",
                "core.logallrefupdates",
            },
            f"{label} local config is not closed",
        )
    if run_fsck:
        git(facts.root, "fsck", "--full", "--strict", "--no-reflogs")


def apply_reviewed_patch(
    destination: pathlib.Path,
    contract: Contract,
    patch: bytes,
) -> None:
    patch_path = destination.joinpath(*contract.patch_relative.parts)
    cloned_patch = stable_regular_bytes(patch_path, "cloned jitterentropy patch")
    require(
        cloned_patch == patch, "cloned jitterentropy patch differs from operator commit"
    )
    jitter = destination / contract.submodules[0].path
    git(jitter, "apply", "--unidiff-zero", "--check", str(patch_path))
    git(jitter, "apply", "--unidiff-zero", str(patch_path))
    observed = git(
        jitter, "diff", "--no-ext-diff", "--no-textconv", "--unified=0", "--binary"
    )
    require(
        observed == patch,
        "applied jitterentropy worktree differs from the reviewed patch",
    )
    require(
        not git(
            jitter, "diff", "--no-ext-diff", "--no-textconv", "--cached", "--binary"
        ),
        "jitterentropy patch was staged",
    )
    verify_no_untracked(jitter, "patched jitterentropy", allow_target=False)


def verify_patched_state(
    destination: pathlib.Path, contract: Contract, patch: bytes
) -> None:
    jitter = destination / contract.submodules[0].path
    observed = git(
        jitter, "diff", "--no-ext-diff", "--no-textconv", "--unified=0", "--binary"
    )
    require(
        observed == patch,
        "jitterentropy worktree is not the exact reviewed patched snapshot",
    )
    require(
        not git(
            jitter, "diff", "--no-ext-diff", "--no-textconv", "--cached", "--binary"
        ),
        "jitterentropy index is dirty",
    )
    verify_no_untracked(jitter, "jitterentropy", allow_target=False)
    sunset = destination / contract.submodules[1].path
    require(
        not git(sunset, "diff", "--no-ext-diff", "--no-textconv", "--binary"),
        "sunset worktree is dirty",
    )
    require(
        not git(
            sunset, "diff", "--no-ext-diff", "--no-textconv", "--cached", "--binary"
        ),
        "sunset index is dirty",
    )
    verify_no_untracked(sunset, "sunset", allow_target=False)
    require(
        not git(
            destination,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--ignore-submodules=all",
        ),
        "superproject tracked files are dirty",
    )
    require(
        not git(
            destination,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--cached",
            "--binary",
            "--ignore-submodules=all",
        ),
        "superproject index is dirty",
    )
    verify_no_untracked(destination, "superproject", allow_target=True)


def append_snapshot_record(
    digest: Any,
    *,
    path: str,
    mode: str,
    kind: str,
    raw: bytes,
) -> None:
    for field in (
        path.encode("utf-8"),
        mode.encode("ascii"),
        kind.encode("ascii"),
        str(len(raw)).encode("ascii"),
    ):
        digest.update(field)
        digest.update(b"\0")
    digest.update(raw)


def snapshot_summary(
    destination: pathlib.Path,
    source_commit: str,
    contract: Contract,
) -> TreeSummary:
    digest = hashlib.sha256()
    digest.update(SNAPSHOT_DOMAIN)
    count = 0
    total = 0
    super_facts = repository_facts(
        destination, source_commit, "materialized superproject", require_standalone=True
    )
    for entry in sorted(
        parse_tree(destination, source_commit, "materialized superproject"),
        key=lambda item: item.path,
    ):
        if entry.mode == "160000":
            raw = entry.oid.encode("ascii")
            append_snapshot_record(
                digest, path=entry.path, mode=entry.mode, kind="gitlink", raw=raw
            )
        else:
            raw = stable_worktree_bytes(destination, entry, "materialized superproject")
            append_snapshot_record(
                digest,
                path=entry.path,
                mode=entry.mode,
                kind="blob" if entry.mode != "120000" else "symlink",
                raw=raw,
            )
            if entry.path not in {spec.path for spec in contract.submodules}:
                require(
                    git_blob_oid(raw, super_facts.object_format) == entry.oid,
                    f"materialized superproject {entry.path} differs from Git",
                )
        count += 1
        total += len(raw)
    for spec in contract.submodules:
        root = destination.joinpath(*pathlib.PurePosixPath(spec.path).parts)
        repository_facts(
            root, spec.commit, f"materialized {spec.path}", require_standalone=True
        )
        for entry in sorted(
            parse_tree(root, spec.commit, f"materialized {spec.path}"),
            key=lambda item: item.path,
        ):
            require(
                entry.mode != "160000", f"materialized {spec.path} nests a submodule"
            )
            raw = stable_worktree_bytes(root, entry, f"materialized {spec.path}")
            logical = f"{spec.path}/{entry.path}"
            append_snapshot_record(
                digest,
                path=logical,
                mode=entry.mode,
                kind="blob" if entry.mode != "120000" else "symlink",
                raw=raw,
            )
            count += 1
            total += len(raw)
    return TreeSummary(digest.hexdigest(), count, total)


def admin_roots(facts: Sequence[RepoFacts]) -> list[pathlib.Path]:
    unique: dict[pathlib.Path, None] = {}
    for item in facts:
        unique[item.git_dir] = None
        unique[item.common_dir] = None
    return sorted(unique, key=lambda path: str(path))


def regular_inode_set(
    roots: Sequence[pathlib.Path], label: str
) -> set[tuple[int, int]]:
    result: set[tuple[int, int]] = set()
    for root in roots:
        require(
            root.is_dir() and not root.is_symlink(),
            f"{label} admin root is not fixed: {root}",
        )
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = pathlib.Path(current)
            for name in [*directories, *files]:
                path = current_path / name
                info = path.lstat()
                require(
                    not stat.S_ISLNK(info.st_mode),
                    f"{label} Git admin contains symlink {path}",
                )
                if stat.S_ISREG(info.st_mode):
                    require(
                        info.st_nlink == 1,
                        f"{label} Git admin regular file is hardlinked: {path}",
                    )
                    result.add((info.st_dev, info.st_ino))
    return result


def inode_digest(values: set[tuple[int, int]]) -> str:
    digest = hashlib.sha256()
    digest.update(INODE_DOMAIN)
    for device, inode in sorted(values):
        digest.update(f"{device}:{inode}\n".encode("ascii"))
    return digest.hexdigest()


def admin_summary(
    roots: Sequence[pathlib.Path], base: pathlib.Path, label: str
) -> dict[str, object]:
    digest = hashlib.sha256()
    digest.update(ADMIN_DOMAIN)
    count = 0
    total = 0
    records: list[tuple[str, pathlib.Path]] = []
    for root in roots:
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = pathlib.Path(current)
            for name in sorted([*directories, *files]):
                path = current_path / name
                info = path.lstat()
                require(
                    not stat.S_ISLNK(info.st_mode),
                    f"{label} Git admin contains symlink {path}",
                )
                if stat.S_ISREG(info.st_mode):
                    try:
                        logical = path.relative_to(base).as_posix()
                    except ValueError:
                        logical = f"external-admin/{sha256_bytes(str(root).encode())}/{path.relative_to(root).as_posix()}"
                    records.append((logical, path))
    for logical, path in sorted(records):
        raw = stable_regular_bytes(path, f"{label} admin {logical}")
        append_snapshot_record(
            digest, path=logical, mode="regular", kind="git-admin", raw=raw
        )
        count += 1
        total += len(raw)
    return {
        "algorithm": "sha256(domain-NUL,path-NUL,regular-NUL,git-admin-NUL,length-NUL,bytes)*",
        "bytes": total,
        "regular_files": count,
        "sha256": digest.hexdigest(),
    }


def verify_independence(
    source_facts: Sequence[RepoFacts],
    clone_facts: Sequence[RepoFacts],
) -> dict[str, object]:
    source_inodes = regular_inode_set(admin_roots(source_facts), "operator source")
    clone_sets = [
        regular_inode_set([facts.git_dir], f"clone {facts.root.name}")
        for facts in clone_facts
    ]
    clone_inodes = set().union(*clone_sets)
    shared_source = source_inodes & clone_inodes
    shared_clone: set[tuple[int, int]] = set()
    for index, left in enumerate(clone_sets):
        for right in clone_sets[index + 1 :]:
            shared_clone.update(left & right)
    require(
        not shared_source,
        "clone Git admin/object files share device+inode with operator source",
    )
    require(
        not shared_clone, "the three clone object/admin stores share device+inode files"
    )
    return {
        "clone_admin_inode_set_sha256": inode_digest(clone_inodes),
        "clone_admin_regular_files": len(clone_inodes),
        "clone_pair_shared_dev_inode": 0,
        "operator_admin_inode_set_sha256": inode_digest(source_inodes),
        "operator_admin_regular_files": len(source_inodes),
        "operator_clone_shared_dev_inode": 0,
        "policy": "all regular files under Git worktree/common admin roots; exact st_dev+st_ino intersection",
    }


def ensure_target(destination: pathlib.Path) -> pathlib.Path:
    target = destination / "target"
    if not target.exists():
        target.mkdir(mode=0o700)
    require(
        target.is_dir() and not target.is_symlink(), "target is not a fixed directory"
    )
    target.chmod(0o700)
    require(
        os.access(target, os.W_OK), "target is not writable by the current credential"
    )
    return target


def paths_outside_target(destination: pathlib.Path) -> list[pathlib.Path]:
    target = destination / "target"
    result: list[pathlib.Path] = []
    for current, directories, files in os.walk(
        destination, topdown=True, followlinks=False
    ):
        current_path = pathlib.Path(current)
        if current_path == target:
            directories.clear()
            continue
        directories[:] = [name for name in directories if current_path / name != target]
        result.extend(current_path / name for name in files)
        result.extend(current_path / name for name in directories)
    result.append(destination)
    return sorted(set(result), key=lambda path: len(path.parts), reverse=True)


def freeze_source(destination: pathlib.Path) -> None:
    ensure_target(destination)
    for path in paths_outside_target(destination):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        require(
            stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
            f"unsupported source filesystem entry: {path}",
        )
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, f"source/admin file is hardlinked: {path}")
        path.chmod(stat.S_IMODE(info.st_mode) & ~0o222)
    verify_frozen_source(destination)


def verify_frozen_source(destination: pathlib.Path) -> dict[str, object]:
    target = destination / "target"
    require(
        target.is_dir() and not target.is_symlink(), "target is not a fixed directory"
    )
    require(os.access(target, os.W_OK), "target is not writable")
    checked = 0
    for path in paths_outside_target(destination):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, f"source/admin file is hardlinked: {path}")
        require(
            not (stat.S_IMODE(info.st_mode) & 0o222),
            f"source/admin path retains write bits: {path}",
        )
        require(
            not os.access(path, os.W_OK),
            f"source/admin path is writable by current credential: {path}",
        )
        checked += 1
    return {
        "checked_regular_and_directory_paths": checked,
        "policy": "all regular files outside target have st_nlink=1; all source and three Git-admin paths have no write bits and deny current-credential W_OK; target subtree excluded",
        "source_except_target_regular_files_single_link": True,
        "source_except_target_current_credential_writable": False,
        "target": "target",
        "target_current_credential_writable": True,
    }


def envelope_path(
    destination: pathlib.Path, source_commit: str, challenge: str
) -> pathlib.Path:
    return destination.joinpath(
        *ENVELOPE_RELATIVE_ROOT.parts,
        source_commit,
        challenge,
        "source-materialization-envelope.json",
    )


def atomic_publish(path: pathlib.Path, raw: bytes) -> None:
    require(not os.path.lexists(path), f"envelope publication is no-clobber: {path}")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    require(
        path.parent.is_dir() and not path.parent.is_symlink(),
        "envelope parent is not fixed",
    )
    temporary = path.parent / f".source-materialization.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "short write while publishing envelope")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except FileExistsError:
        fail(f"envelope publication raced with an existing output: {path}")
    except OSError as error:
        fail(f"cannot atomically publish envelope {path}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if os.path.lexists(temporary):
            temporary.unlink()


def git_tool_identity() -> dict[str, object]:
    executable_text = shutil.which("git")
    require(executable_text is not None, "git is required")
    executable = pathlib.Path(executable_text).resolve(strict=True)
    tool = identity(executable, "Git executable", require_single_link=False)
    version = run_command([str(executable), "--version"]).stdout.decode().strip()
    require(version.startswith("git version "), "Git version output is malformed")
    return {
        "bytes": tool.bytes,
        "path": str(executable),
        "sha256": tool.sha256,
        "version": version,
    }


def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )


def parse_utc(value: Any, label: str) -> datetime.datetime:
    require(isinstance(value, str) and value.endswith("Z"), f"{label} is not UTC")
    try:
        return datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        fail(f"{label} is invalid: {error}")


def create_content(
    *,
    source_commit: str,
    challenge: str,
    contract: Contract,
    bundles: list[dict[str, object]],
    source_facts: Sequence[RepoFacts],
    clone_facts: Sequence[RepoFacts],
    independence: dict[str, object],
    snapshot: TreeSummary,
    clone_admin: dict[str, object],
    frozen: dict[str, object],
    started: str,
    completed: str,
) -> dict[str, object]:
    submodules = [
        {
            "commit": spec.commit,
            "git_admin": f"{spec.path}/.git",
            "git_admin_kind": "standalone-directory",
            "path": spec.path,
        }
        for spec in contract.submodules
    ]
    source = {
        "head": source_commit,
        "object_format": "sha1",
        "submodule_heads": {spec.path: spec.commit for spec in contract.submodules},
        "tree": source_facts[0].tree,
    }
    return {
        "bundles": bundles,
        "challenge": challenge,
        "clone_git_admin": clone_admin,
        "command": [
            "scripts/c84-source-materialization.py",
            "materialize",
            "--source",
            "<operator-source>",
            "--destination",
            "<new-destination>",
            "--source-commit",
            source_commit,
            "--challenge",
            challenge,
        ],
        "frozen": frozen,
        "git": git_tool_identity(),
        "independence": independence,
        "materialization": {
            "atomic_destination_publish": DESTINATION_PUBLISH_POLICY,
            "destination_was_absent": True,
            "local_bundles_only": True,
            "method": MATERIALIZATION_METHOD,
            "network_allowed": False,
            "ordinary_refs_remotes_reflogs_hooks_removed": True,
            "replacement_graft_alternate_shallow_promisor_allowed": False,
        },
        "patch": {
            "applied_diff_bytes": contract.patch_bytes,
            "applied_diff_sha256": contract.patch_sha256,
            "base_submodule_commit": contract.submodules[0].commit,
            "path": contract.patch_relative.as_posix(),
            "policy": "exact git diff --unified=0 --binary; applied before source freeze",
        },
        "snapshot": snapshot.as_dict(),
        "source": source,
        "source_commit": source_commit,
        "submodules": submodules,
        "timestamps_utc": {
            "materialization_completed": completed,
            "materialization_started": started,
        },
    }


def write_envelope(path: pathlib.Path, content: dict[str, object]) -> None:
    canonical_content = canonical_json(content)
    root = {
        "content": content,
        "content_sha256": sha256_bytes(canonical_content),
        "schema": SCHEMA,
        "status": "closed",
        "version": VERSION,
    }
    atomic_publish(path, canonical_json(root) + b"\n")


def load_envelope(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    raw = stable_regular_bytes(
        path,
        "source materialization envelope",
        maximum=MAX_ENVELOPE_BYTES,
        require_single_link=True,
    )
    try:
        root = json.loads(raw, object_pairs_hook=reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode source materialization envelope: {error}")
    root = exact(
        root, {"content", "content_sha256", "schema", "status", "version"}, "envelope"
    )
    require(root["schema"] == SCHEMA, "envelope schema differs")
    require(
        type(root["version"]) is int and root["version"] == VERSION,
        "envelope version differs",
    )
    require(root["status"] == "closed", "envelope status differs")
    require(
        isinstance(root["content_sha256"], str)
        and HEX64.fullmatch(root["content_sha256"]) is not None,
        "envelope content digest is malformed",
    )
    canonical_content = canonical_json(root["content"])
    require(
        sha256_bytes(canonical_content) == root["content_sha256"],
        "envelope content address differs",
    )
    require(raw == canonical_json(root) + b"\n", "envelope is not canonical JSON")
    return root, raw


def clone_repo_facts(
    destination: pathlib.Path,
    source_commit: str,
    contract: Contract,
    *,
    run_fsck: bool,
) -> list[RepoFacts]:
    facts = [
        repository_facts(
            destination,
            source_commit,
            "materialized superproject",
            require_standalone=True,
        )
    ]
    for spec in contract.submodules:
        root = destination.joinpath(*pathlib.PurePosixPath(spec.path).parts)
        sub = repository_facts(
            root, spec.commit, f"materialized {spec.path}", require_standalone=True
        )
        facts.append(sub)
    for item, label in zip(
        facts,
        [
            "materialized superproject",
            *(f"materialized {spec.path}" for spec in contract.submodules),
        ],
    ):
        verify_closed_admin(item, item.head, label, run_fsck=run_fsck)
    return facts


def materialize(
    *,
    source: pathlib.Path,
    destination: pathlib.Path,
    source_commit: str,
    challenge: str,
    contract: Contract = FORMAL_CONTRACT,
) -> pathlib.Path:
    source_commit = canonical_commit(source_commit, "source commit")
    challenge = canonical_challenge(challenge, "challenge")
    source = canonical_existing_directory(source, "operator source")
    started = utc_now()
    source_super, source_submodules, patch = verify_source_preflight(
        source, source_commit, contract
    )
    source_fact_list = [
        source_super,
        *(source_submodules[spec.path] for spec in contract.submodules),
    ]
    parent: DirectoryBinding | None = None
    stage_binding: DirectoryBinding | None = None
    stage_name: str | None = None
    bundle_directory: pathlib.Path | None = None
    try:
        destination, parent = nonexistent_destination(destination)
        stage_name, stage_binding = create_sibling_stage(parent, destination.name)
        stage = stage_binding.path
        bundle_directory = pathlib.Path(
            tempfile.mkdtemp(prefix="vibeos-c84-source-bundles-")
        )
        bundle_inputs = [("superproject", source, source_commit)] + [
            (spec.path, source / spec.path, spec.commit) for spec in contract.submodules
        ]
        bundle_records: list[dict[str, object]] = []
        bundle_paths: list[pathlib.Path] = []
        for index, (role, repo, head) in enumerate(bundle_inputs):
            bundle = bundle_directory / f"repo-{index}.bundle"
            bundle_records.append(bundle_record(repo, bundle, head, role))
            bundle_paths.append(bundle)
        clone_bundle(
            bundle_paths[0],
            stage,
            source_commit,
            "superproject",
            allow_reserved_empty=True,
        )
        for spec, bundle in zip(contract.submodules, bundle_paths[1:]):
            submodule_destination = stage.joinpath(
                *pathlib.PurePosixPath(spec.path).parts
            )
            if submodule_destination.exists():
                require(
                    submodule_destination.is_dir()
                    and not any(submodule_destination.iterdir()),
                    f"gitlink worktree path is not empty: {spec.path}",
                )
                submodule_destination.rmdir()
            clone_bundle(bundle, submodule_destination, spec.commit, spec.path)
        for bundle, record in zip(bundle_paths, bundle_records):
            verify_bundle_stable(bundle, record, f"{record['role']} bundle")
        apply_reviewed_patch(stage, contract, patch)
        close_git_admin(stage, source_commit, "materialized superproject")
        for spec in contract.submodules:
            close_git_admin(stage / spec.path, spec.commit, f"materialized {spec.path}")
        verify_patched_state(stage, contract, patch)
        clone_facts = clone_repo_facts(stage, source_commit, contract, run_fsck=True)
        independence = verify_independence(source_fact_list, clone_facts)
        snapshot = snapshot_summary(stage, source_commit, contract)
        clone_admin = admin_summary(admin_roots(clone_facts), stage, "clone")
        ensure_target(stage)
        freeze_source(stage)
        frozen = verify_frozen_source(stage)
        completed = utc_now()
        content = create_content(
            source_commit=source_commit,
            challenge=challenge,
            contract=contract,
            bundles=bundle_records,
            source_facts=source_fact_list,
            clone_facts=clone_facts,
            independence=independence,
            snapshot=snapshot,
            clone_admin=clone_admin,
            frozen=frozen,
            started=started,
            completed=completed,
        )
        staged_path = envelope_path(stage, source_commit, challenge)
        write_envelope(staged_path, content)
        verify_materialization(
            destination=stage,
            source_commit=source_commit,
            challenge=challenge,
            operator_source=source,
            contract=contract,
        )
        envelope_raw = stable_regular_bytes(
            staged_path, "staged source materialization envelope"
        )
        for forbidden_path, label in (
            (stage, "random staging"),
            (destination, "destination"),
            (source, "operator source"),
        ):
            require(
                os.fsencode(forbidden_path) not in envelope_raw,
                f"envelope leaks the {label} path",
            )
        verify_stage_binding(parent, stage_binding, stage_name)
        atomic_publish_directory(stage_name, stage_binding, destination, parent)
        verify_published_binding(parent, stage_binding, destination)
        verify_materialization(
            destination=destination,
            source_commit=source_commit,
            challenge=challenge,
            operator_source=source,
            contract=contract,
        )
        verify_published_binding(parent, stage_binding, destination)
        return envelope_path(destination, source_commit, challenge)
    except Exception:
        if parent is not None and stage_binding is not None and stage_name is not None:
            try:
                verify_stage_binding(parent, stage_binding, stage_name)
            except (MaterializationError, OSError):
                pass
            else:
                make_tree_writable(stage_binding.path)
                shutil.rmtree(stage_binding.path, ignore_errors=True)
        raise
    finally:
        if bundle_directory is not None:
            shutil.rmtree(bundle_directory, ignore_errors=True)
        if stage_binding is not None:
            os.close(stage_binding.fd)
        if parent is not None:
            os.close(parent.fd)


def validate_bundle_records(
    value: Any, contract: Contract, source_commit: str
) -> list[dict[str, Any]]:
    require(
        isinstance(value, list) and len(value) == 1 + len(contract.submodules),
        "bundle records differ",
    )
    expected = [
        ("superproject", source_commit),
        *((spec.path, spec.commit) for spec in contract.submodules),
    ]
    result: list[dict[str, Any]] = []
    for item, (role, head) in zip(value, expected):
        record = exact(item, {"bytes", "head", "role", "sha256"}, f"bundle {role}")
        require(
            record["role"] == role and record["head"] == head,
            f"bundle {role} identity differs",
        )
        require(
            type(record["bytes"]) is int and record["bytes"] > 0,
            f"bundle {role} byte count is invalid",
        )
        require(
            isinstance(record["sha256"], str)
            and HEX64.fullmatch(record["sha256"]) is not None,
            f"bundle {role} digest is invalid",
        )
        result.append(record)
    return result


def verify_materialization(
    *,
    destination: pathlib.Path,
    source_commit: str,
    challenge: str,
    operator_source: pathlib.Path | None,
    container_mounted_read_only: bool = False,
    contract: Contract = FORMAL_CONTRACT,
) -> pathlib.Path:
    source_commit = canonical_commit(source_commit, "source commit")
    challenge = canonical_challenge(challenge, "challenge")
    destination = canonical_existing_directory(destination, "materialized destination")
    require(
        type(container_mounted_read_only) is bool,
        "container-mounted verification selector is malformed",
    )
    require(
        not container_mounted_read_only or operator_source is None,
        "container-mounted verification cannot inspect an operator source",
    )
    path = envelope_path(destination, source_commit, challenge)
    root, _raw = load_envelope(path)
    content = exact(
        root["content"],
        {
            "bundles",
            "challenge",
            "clone_git_admin",
            "command",
            "frozen",
            "git",
            "independence",
            "materialization",
            "patch",
            "snapshot",
            "source",
            "source_commit",
            "submodules",
            "timestamps_utc",
        },
        "envelope content",
    )
    require(content["source_commit"] == source_commit, "envelope source commit differs")
    require(content["challenge"] == challenge, "envelope challenge differs")
    validate_bundle_records(content["bundles"], contract, source_commit)
    materialization = exact(
        content["materialization"],
        {
            "atomic_destination_publish",
            "destination_was_absent",
            "local_bundles_only",
            "method",
            "network_allowed",
            "ordinary_refs_remotes_reflogs_hooks_removed",
            "replacement_graft_alternate_shallow_promisor_allowed",
        },
        "materialization",
    )
    require(
        materialization
        == {
            "atomic_destination_publish": DESTINATION_PUBLISH_POLICY,
            "destination_was_absent": True,
            "local_bundles_only": True,
            "method": MATERIALIZATION_METHOD,
            "network_allowed": False,
            "ordinary_refs_remotes_reflogs_hooks_removed": True,
            "replacement_graft_alternate_shallow_promisor_allowed": False,
        },
        "materialization policy differs",
    )
    expected_submodules = [
        {
            "commit": spec.commit,
            "git_admin": f"{spec.path}/.git",
            "git_admin_kind": "standalone-directory",
            "path": spec.path,
        }
        for spec in contract.submodules
    ]
    require(content["submodules"] == expected_submodules, "submodule closure differs")
    patch_record = exact(
        content["patch"],
        {
            "applied_diff_bytes",
            "applied_diff_sha256",
            "base_submodule_commit",
            "path",
            "policy",
        },
        "patch",
    )
    require(
        patch_record
        == {
            "applied_diff_bytes": contract.patch_bytes,
            "applied_diff_sha256": contract.patch_sha256,
            "base_submodule_commit": contract.submodules[0].commit,
            "path": contract.patch_relative.as_posix(),
            "policy": "exact git diff --unified=0 --binary; applied before source freeze",
        },
        "patch closure differs",
    )
    patch = stable_regular_bytes(
        destination.joinpath(*contract.patch_relative.parts),
        "materialized reviewed patch",
        maximum=1_048_576,
    )
    require(
        len(patch) == contract.patch_bytes
        and sha256_bytes(patch) == contract.patch_sha256,
        "materialized reviewed patch differs",
    )
    verify_patched_state(destination, contract, patch)
    clone_facts = clone_repo_facts(destination, source_commit, contract, run_fsck=True)
    snapshot = snapshot_summary(destination, source_commit, contract)
    require(
        content["snapshot"] == snapshot.as_dict(),
        "frozen source snapshot differs from envelope",
    )
    current_admin = admin_summary(admin_roots(clone_facts), destination, "clone")
    require(
        content["clone_git_admin"] == current_admin,
        "closed Git-admin content differs from envelope",
    )
    current_frozen = verify_frozen_source(destination)
    require(content["frozen"] == current_frozen, "source freeze closure differs")
    source_record = exact(
        content["source"],
        {"head", "object_format", "submodule_heads", "tree"},
        "source",
    )
    require(
        source_record["head"] == source_commit
        and source_record["object_format"] == "sha1",
        "source identity differs",
    )
    require(source_record["tree"] == clone_facts[0].tree, "source tree differs")
    require(
        source_record["submodule_heads"]
        == {spec.path: spec.commit for spec in contract.submodules},
        "source submodule heads differ",
    )
    independence = exact(
        content["independence"],
        {
            "clone_admin_inode_set_sha256",
            "clone_admin_regular_files",
            "clone_pair_shared_dev_inode",
            "operator_admin_inode_set_sha256",
            "operator_admin_regular_files",
            "operator_clone_shared_dev_inode",
            "policy",
        },
        "independence",
    )
    require(
        isinstance(independence["clone_admin_inode_set_sha256"], str)
        and HEX64.fullmatch(independence["clone_admin_inode_set_sha256"]) is not None
        and isinstance(independence["operator_admin_inode_set_sha256"], str)
        and HEX64.fullmatch(independence["operator_admin_inode_set_sha256"]) is not None
        and type(independence["clone_admin_regular_files"]) is int
        and independence["clone_admin_regular_files"] > 0
        and type(independence["operator_admin_regular_files"]) is int
        and independence["operator_admin_regular_files"] > 0
        and independence["policy"]
        == "all regular files under Git worktree/common admin roots; exact st_dev+st_ino intersection",
        "independence proof shape differs",
    )
    require(
        type(independence["operator_clone_shared_dev_inode"]) is int
        and independence["operator_clone_shared_dev_inode"] == 0,
        "envelope records source/clone sharing",
    )
    require(
        type(independence["clone_pair_shared_dev_inode"]) is int
        and independence["clone_pair_shared_dev_inode"] == 0,
        "envelope records clone/clone sharing",
    )
    clone_sets = [
        regular_inode_set([facts.git_dir], f"clone {facts.root.name}")
        for facts in clone_facts
    ]
    clone_inodes = set().union(*clone_sets)
    if not container_mounted_read_only:
        require(
            independence["clone_admin_inode_set_sha256"] == inode_digest(clone_inodes),
            "clone admin inode set differs",
        )
    require(
        independence["clone_admin_regular_files"] == len(clone_inodes),
        "clone admin file count differs",
    )
    for index, left in enumerate(clone_sets):
        for right in clone_sets[index + 1 :]:
            require(not (left & right), "clone Git admins now share regular files")
    if operator_source is not None:
        operator_source = canonical_existing_directory(
            operator_source, "operator source"
        )
        source_super, source_submodules, source_patch = verify_source_preflight(
            operator_source, source_commit, contract
        )
        require(source_patch == patch, "operator and clone reviewed patches differ")
        source_facts = [
            source_super,
            *(source_submodules[spec.path] for spec in contract.submodules),
        ]
        current = verify_independence(source_facts, clone_facts)
        require(
            current["operator_clone_shared_dev_inode"] == 0,
            "operator source and clone now share admin files",
        )
    timestamps = exact(
        content["timestamps_utc"],
        {"materialization_completed", "materialization_started"},
        "timestamps",
    )
    started = parse_utc(timestamps["materialization_started"], "materialization start")
    completed = parse_utc(
        timestamps["materialization_completed"], "materialization completion"
    )
    require(started <= completed, "materialization timestamps are reversed")
    expected_command = [
        "scripts/c84-source-materialization.py",
        "materialize",
        "--source",
        "<operator-source>",
        "--destination",
        "<new-destination>",
        "--source-commit",
        source_commit,
        "--challenge",
        challenge,
    ]
    require(content["command"] == expected_command, "materialization command differs")
    git_record = exact(
        content["git"], {"bytes", "path", "sha256", "version"}, "Git tool"
    )
    require(
        type(git_record["bytes"]) is int and git_record["bytes"] > 0,
        "Git tool size is invalid",
    )
    require(
        isinstance(git_record["sha256"], str)
        and HEX64.fullmatch(git_record["sha256"]) is not None,
        "Git tool digest is invalid",
    )
    require(
        isinstance(git_record["path"], str)
        and pathlib.PurePath(git_record["path"]).is_absolute(),
        "Git tool path is invalid",
    )
    require(
        isinstance(git_record["version"], str)
        and git_record["version"].startswith("git version "),
        "Git tool version is invalid",
    )
    return path


def make_tree_writable(root: pathlib.Path) -> None:
    if not os.path.lexists(root):
        return
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        for name in files:
            path = pathlib.Path(current) / name
            if not path.is_symlink():
                try:
                    path.chmod(path.lstat().st_mode | 0o600)
                except OSError:
                    pass
        for name in directories:
            path = pathlib.Path(current) / name
            if not path.is_symlink():
                try:
                    path.chmod(path.lstat().st_mode | 0o700)
                except OSError:
                    pass
    try:
        root.chmod(root.lstat().st_mode | 0o700)
    except OSError:
        pass


def expect_failure(label: str, callback: Any) -> None:
    try:
        callback()
    except (MaterializationError, OSError, subprocess.SubprocessError, ValueError):
        return
    fail(f"selftest mutation was accepted: {label}")


SELFTEST_GIT_IDENTITY = {
    "GIT_AUTHOR_EMAIL": "c84-selftest@example.invalid",
    "GIT_AUTHOR_NAME": "C84 Selftest",
    "GIT_COMMITTER_EMAIL": "c84-selftest@example.invalid",
    "GIT_COMMITTER_NAME": "C84 Selftest",
}


def test_git(repo: pathlib.Path, *arguments: str) -> bytes:
    completed = run_command(
        ["git", "--no-optional-locks", "-C", str(repo), *arguments],
        extra_env=SELFTEST_GIT_IDENTITY,
    )
    return completed.stdout


def initialize_test_repo(path: pathlib.Path, filename: str, content: bytes) -> str:
    run_command(["git", "init", "--quiet", str(path)], extra_env=SELFTEST_GIT_IDENTITY)
    (path / filename).write_bytes(content)
    test_git(path, "add", filename)
    test_git(path, "commit", "--quiet", "-m", "fixture")
    return test_git(path, "rev-parse", "HEAD").decode().strip()


def create_selftest_fixture(root: pathlib.Path) -> tuple[pathlib.Path, str, Contract]:
    jitter_source = root / "jitter-source"
    sunset_source = root / "sunset-source"
    jitter_head = initialize_test_repo(
        jitter_source, "entropy.rs", b"pub const VALUE: u32 = 7;\n"
    )
    sunset_head = initialize_test_repo(
        sunset_source, "sunset.rs", b"pub const READY: bool = true;\n"
    )
    jitter_file = jitter_source / "entropy.rs"
    jitter_file.write_bytes(b"pub const VALUE: u32 = 9;\n")
    patch = test_git(jitter_source, "diff", "--unified=0", "--binary")
    jitter_file.write_bytes(b"pub const VALUE: u32 = 7;\n")
    require(
        test_git(jitter_source, "diff", "--binary") == b"",
        "cannot restore selftest jitter source",
    )

    source = root / "operator-source"
    run_command(
        ["git", "init", "--quiet", str(source)], extra_env=SELFTEST_GIT_IDENTITY
    )
    (source / "README.md").write_text("C8.4 selftest\n", encoding="utf-8")
    patch_path = source.joinpath(*PATCH_RELATIVE.parts)
    patch_path.parent.mkdir(parents=True)
    patch_path.write_bytes(patch)
    (source / ".gitmodules").write_text(
        '[submodule "vendor/jitterentropy-rs"]\n'
        "\tpath = vendor/jitterentropy-rs\n"
        "\turl = forbidden.example.invalid/jitter\n"
        '[submodule "vendor/sunset"]\n'
        "\tpath = vendor/sunset\n"
        "\turl = forbidden.example.invalid/sunset\n",
        encoding="utf-8",
    )
    test_git(source, "add", "README.md", ".gitmodules", PATCH_RELATIVE.as_posix())
    test_git(
        source,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{jitter_head},vendor/jitterentropy-rs",
    )
    test_git(
        source,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{sunset_head},vendor/sunset",
    )
    test_git(source, "commit", "--quiet", "-m", "super fixture")
    source_commit = test_git(source, "rev-parse", "HEAD").decode().strip()
    vendor = source / "vendor"
    vendor.mkdir(exist_ok=True)
    run_command(
        [
            "git",
            "clone",
            "--quiet",
            "--no-local",
            str(jitter_source),
            str(vendor / "jitterentropy-rs"),
        ],
        extra_env=SELFTEST_GIT_IDENTITY,
    )
    run_command(
        [
            "git",
            "clone",
            "--quiet",
            "--no-local",
            str(sunset_source),
            str(vendor / "sunset"),
        ],
        extra_env=SELFTEST_GIT_IDENTITY,
    )
    contract = Contract(
        submodules=(
            SubmoduleSpec("vendor/jitterentropy-rs", jitter_head),
            SubmoduleSpec("vendor/sunset", sunset_head),
        ),
        patch_relative=PATCH_RELATIVE,
        patch_sha256=sha256_bytes(patch),
        patch_bytes=len(patch),
    )
    return source, source_commit, contract


def copy_attack(source: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    shutil.copytree(source, destination, symlinks=True)
    return destination


def writable(path: pathlib.Path, *, directory: bool = False) -> None:
    mode = path.lstat().st_mode
    path.chmod(mode | (0o700 if directory else 0o600))


def replace_bytes(path: pathlib.Path, raw: bytes) -> None:
    writable(path.parent, directory=True)
    writable(path)
    path.write_bytes(raw)


def check_source() -> None:
    raw = stable_regular_bytes(
        SCRIPT_PATH, "c84 source-materialization implementation", maximum=4_194_304
    )
    text = raw.decode("utf-8")
    syntax = ast.parse(text, str(SCRIPT_PATH))
    required = (
        '"GIT_ALLOW_PROTOCOL": "file"',
        '"GIT_NO_REPLACE_OBJECTS": "1"',
        '"GIT_OPTIONAL_LOCKS": "0"',
        '"--no-local"',
        '"--no-hardlinks"',
        '"fsck"',
        '"--strict"',
        '"core.fsmonitor=false"',
        '"O_NOFOLLOW"',
        '"renameat2"',
        '"renameatx_np"',
        '"st_nlink"',
        "ordinary_refs_remotes_reflogs_hooks_removed",
        "operator_clone_shared_dev_inode",
        "container_mounted_read_only",
        "validate_operator_config",
        "verify_frozen_source",
        "atomic_publish",
    )
    for token in required:
        require(token in text, f"implementation source lacks required token {token!r}")
    imported: set[str] = set()
    for node in ast.walk(syntax):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    forbidden_imports = {"socket", "urllib", "requests", "http"}
    require(
        not (imported & forbidden_imports),
        f"implementation source imports network modules: {sorted(imported & forbidden_imports)}",
    )


def run_selftest(*, source_check: bool) -> None:
    if source_check:
        check_source()
    temporary = pathlib.Path(
        tempfile.mkdtemp(prefix="vibeos-c84-source-materialization-selftest-")
    ).resolve(strict=True)
    try:
        source, source_commit, contract = create_selftest_fixture(temporary)
        challenge = "a" * 64
        other_challenge = "b" * 64
        destination = temporary / "materialized"
        fsmonitor_hook = temporary / "fsmonitor-sentinel.sh"
        fsmonitor_marker = temporary / "fsmonitor-sentinel.sh.executed"
        fsmonitor_hook.write_text(
            '#!/bin/sh\n: > "${0}.executed"\nexit 0\n', encoding="utf-8"
        )
        fsmonitor_hook.chmod(0o700)
        test_git(source, "config", "core.fsmonitor", str(fsmonitor_hook))
        expect_failure(
            "operator core.fsmonitor config",
            lambda: materialize(
                source=source,
                destination=temporary / "blocked-fsmonitor",
                source_commit=source_commit,
                challenge=challenge,
                contract=contract,
            ),
        )
        require(
            not fsmonitor_marker.exists(),
            "operator core.fsmonitor command executed during rejected preflight",
        )
        test_git(source, "config", "--unset", "core.fsmonitor")
        envelope = materialize(
            source=source,
            destination=destination,
            source_commit=source_commit,
            challenge=challenge,
            contract=contract,
        )
        verify_materialization(
            destination=destination,
            source_commit=source_commit,
            challenge=challenge,
            operator_source=source,
            contract=contract,
        )
        verify_materialization(
            destination=destination,
            source_commit=source_commit,
            challenge=challenge,
            operator_source=None,
            container_mounted_read_only=True,
            contract=contract,
        )
        expect_failure(
            "container-mounted operator source",
            lambda: verify_materialization(
                destination=destination,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=source,
                container_mounted_read_only=True,
                contract=contract,
            ),
        )
        expect_failure(
            "no-clobber destination",
            lambda: materialize(
                source=source,
                destination=destination,
                source_commit=source_commit,
                challenge=challenge,
                contract=contract,
            ),
        )
        raced_destination = temporary / "raced-publication"
        _raced_destination, raced_parent = nonexistent_destination(raced_destination)
        raced_stage_name, raced_stage = create_sibling_stage(
            raced_parent, raced_destination.name
        )
        try:
            (raced_stage.path / "stage-sentinel").write_text(
                "stage\n", encoding="utf-8"
            )
            raced_destination.mkdir()
            (raced_destination / "destination-sentinel").write_text(
                "destination\n", encoding="utf-8"
            )
            expect_failure(
                "kernel no-clobber publication",
                lambda: atomic_publish_directory(
                    raced_stage_name,
                    raced_stage,
                    raced_destination,
                    raced_parent,
                ),
            )
            require(
                (raced_stage.path / "stage-sentinel").read_text(encoding="utf-8")
                == "stage\n"
                and (raced_destination / "destination-sentinel").read_text(
                    encoding="utf-8"
                )
                == "destination\n",
                "failed no-clobber publication changed an existing directory",
            )
        finally:
            os.close(raced_stage.fd)
            os.close(raced_parent.fd)

        swap_container = temporary / "parent-swap-container"
        swap_container.mkdir()
        original_parent = swap_container / "bound-parent"
        original_parent.mkdir()
        parent_swap_destination = original_parent / "published"
        _swap_destination, swap_parent = nonexistent_destination(
            parent_swap_destination
        )
        swap_stage_name, swap_stage = create_sibling_stage(
            swap_parent, parent_swap_destination.name
        )
        try:
            original_parent.rename(swap_container / "moved-bound-parent")
            original_parent.mkdir()
            expect_failure(
                "destination parent path replacement",
                lambda: atomic_publish_directory(
                    swap_stage_name,
                    swap_stage,
                    parent_swap_destination,
                    swap_parent,
                ),
            )
            require(
                not parent_swap_destination.exists(),
                "parent replacement received a published destination",
            )
        finally:
            os.close(swap_stage.fd)
            os.close(swap_parent.fd)

        replacement_parent_path = temporary / "stage-replacement-parent"
        replacement_parent_path.mkdir()
        stage_replacement_destination = replacement_parent_path / "published"
        _replacement_destination, replacement_parent = nonexistent_destination(
            stage_replacement_destination
        )
        replaced_stage_name, replaced_stage = create_sibling_stage(
            replacement_parent, stage_replacement_destination.name
        )
        try:
            os.rename(
                replaced_stage_name,
                f"{replaced_stage_name}.parked",
                src_dir_fd=replacement_parent.fd,
                dst_dir_fd=replacement_parent.fd,
            )
            os.mkdir(replaced_stage_name, mode=0o700, dir_fd=replacement_parent.fd)
            expect_failure(
                "staging directory replacement",
                lambda: atomic_publish_directory(
                    replaced_stage_name,
                    replaced_stage,
                    stage_replacement_destination,
                    replacement_parent,
                ),
            )
            require(
                not stage_replacement_destination.exists(),
                "replacement staging inode was published",
            )
        finally:
            os.close(replaced_stage.fd)
            os.close(replacement_parent.fd)
        expect_failure(
            "wrong HEAD",
            lambda: verify_materialization(
                destination=destination,
                source_commit="f" * 40,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )
        expect_failure(
            "wrong challenge",
            lambda: verify_materialization(
                destination=destination,
                source_commit=source_commit,
                challenge=other_challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        def attacked(name: str) -> pathlib.Path:
            return copy_attack(destination, temporary / f"attack-{name}")

        duplicate = attacked("duplicate-json")
        duplicate_envelope = envelope_path(duplicate, source_commit, challenge)
        original_root = json.loads(envelope.read_bytes())
        duplicate_raw = (
            b'{"schema":"vibeos.c84.source-materialization-envelope",'
            b'"schema":"vibeos.c84.source-materialization-envelope",'
            b'"version":1,"status":"closed","content_sha256":"'
            + str(original_root["content_sha256"]).encode("ascii")
            + b'","content":{}}\n'
        )
        replace_bytes(duplicate_envelope, duplicate_raw)
        expect_failure(
            "duplicate JSON",
            lambda: verify_materialization(
                destination=duplicate,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        dirty = attacked("dirty")
        replace_bytes(dirty / "README.md", b"mutated\n")
        expect_failure(
            "dirty tracked file",
            lambda: verify_materialization(
                destination=dirty,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        untracked = attacked("untracked")
        writable(untracked, directory=True)
        (untracked / "rogue.txt").write_text("rogue\n", encoding="utf-8")
        expect_failure(
            "untracked file",
            lambda: verify_materialization(
                destination=untracked,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        hardlinked = attacked("external-hardlink")
        hardlinked_file = hardlinked / "README.md"
        original_bytes = hardlinked_file.read_bytes()
        external_link = temporary / "external-hardlink-to-source"
        os.link(hardlinked_file, external_link, follow_symlinks=False)
        external_link.chmod(0o600)
        external_link.write_bytes(original_bytes)
        external_link.chmod(0o444)
        require(
            hardlinked_file.read_bytes() == original_bytes,
            "hardlink attack did not preserve identical tracked bytes",
        )
        expect_failure(
            "same-byte external hardlink chmod/write",
            lambda: verify_materialization(
                destination=hardlinked,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        wrong_submodule = attacked("wrong-submodule")
        replace_bytes(
            wrong_submodule / contract.submodules[0].path / ".git/HEAD",
            f"{source_commit}\n".encode("ascii"),
        )
        expect_failure(
            "wrong submodule HEAD",
            lambda: verify_materialization(
                destination=wrong_submodule,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        alternates = attacked("alternates")
        alternates_info = alternates / ".git/objects/info"
        writable(alternates_info, directory=True)
        (alternates_info / "alternates").write_text("/nonexistent\n", encoding="utf-8")
        expect_failure(
            "alternates",
            lambda: verify_materialization(
                destination=alternates,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        replacement = attacked("replace-ref")
        refs = replacement / ".git/refs"
        writable(refs, directory=True)
        replace_dir = refs / "replace"
        replace_dir.mkdir()
        (replace_dir / source_commit).write_text(f"{source_commit}\n", encoding="ascii")
        expect_failure(
            "replacement ref",
            lambda: verify_materialization(
                destination=replacement,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        shallow = attacked("shallow")
        shallow_git = shallow / ".git"
        writable(shallow_git, directory=True)
        (shallow_git / "shallow").write_text(f"{source_commit}\n", encoding="ascii")
        expect_failure(
            "shallow repository",
            lambda: verify_materialization(
                destination=shallow,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        writable_admin = attacked("writable-admin")
        writable(writable_admin / ".git/config")
        expect_failure(
            "writable Git admin",
            lambda: verify_materialization(
                destination=writable_admin,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        truncated = attacked("truncated-envelope")
        truncated_envelope = envelope_path(truncated, source_commit, challenge)
        replace_bytes(truncated_envelope, truncated_envelope.read_bytes()[:31])
        expect_failure(
            "truncated envelope",
            lambda: verify_materialization(
                destination=truncated,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        swapped_source = temporary / "materialized-other"
        swapped_envelope = materialize(
            source=source,
            destination=swapped_source,
            source_commit=source_commit,
            challenge=other_challenge,
            contract=contract,
        )
        swapped = attacked("swapped-envelope")
        replace_bytes(
            envelope_path(swapped, source_commit, challenge),
            swapped_envelope.read_bytes(),
        )
        expect_failure(
            "swapped envelope",
            lambda: verify_materialization(
                destination=swapped,
                source_commit=source_commit,
                challenge=challenge,
                operator_source=None,
                contract=contract,
            ),
        )

        # The positive result must retain real .git directories for all three repos.
        require(
            (destination / ".git").is_dir() and not (destination / ".git").is_symlink(),
            "selftest superproject .git differs",
        )
        for spec in contract.submodules:
            require(
                (destination / spec.path / ".git").is_dir(),
                f"selftest {spec.path} does not have a real .git directory",
            )
        print("c84-source-materialization.py selftest: PASS")
    finally:
        make_tree_writable(temporary)
        shutil.rmtree(temporary, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest", action="store_true", help="run local synthetic attack tests"
    )
    parser.add_argument(
        "--check-source",
        action="store_true",
        help="with --selftest, check this implementation source",
    )
    subparsers = parser.add_subparsers(dest="operation")
    materialize_parser = subparsers.add_parser(
        "materialize", help="create and freeze an independent source clone"
    )
    materialize_parser.add_argument("--source", type=pathlib.Path, required=True)
    materialize_parser.add_argument("--destination", type=pathlib.Path, required=True)
    materialize_parser.add_argument("--source-commit", required=True)
    materialize_parser.add_argument("--challenge", required=True)
    verify_parser = subparsers.add_parser(
        "verify", help="verify the one accepted frozen patched snapshot"
    )
    verify_parser.add_argument("--destination", type=pathlib.Path, required=True)
    verify_parser.add_argument("--source-commit", required=True)
    verify_parser.add_argument("--challenge", required=True)
    verify_parser.add_argument("--operator-source", type=pathlib.Path)
    verify_parser.add_argument(
        "--container-mounted-read-only",
        action="store_true",
        help=(
            "inside the fixed /home/vibeos read-only runtime bind, retain the "
            "host inode proof while rechecking the guest content namespace"
        ),
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser()
    options = parser.parse_args(arguments)
    if options.selftest:
        require(
            options.operation is None, "--selftest does not accept a formal operation"
        )
        run_selftest(source_check=options.check_source)
        return 0
    require(not options.check_source, "--check-source requires --selftest")
    require(options.operation is not None, "materialize or verify is required")
    if options.operation == "materialize":
        path = materialize(
            source=options.source,
            destination=options.destination,
            source_commit=options.source_commit,
            challenge=options.challenge,
        )
        print(f"C8.4 source materialization: PASS envelope={path}")
        return 0
    if options.container_mounted_read_only:
        require(
            options.operator_source is None,
            "--container-mounted-read-only rejects --operator-source",
        )
        mounted_destination = canonical_existing_directory(
            options.destination, "container-mounted destination"
        )
        require(
            mounted_destination == pathlib.Path("/home/vibeos"),
            "--container-mounted-read-only requires destination /home/vibeos",
        )
    path = verify_materialization(
        destination=options.destination,
        source_commit=options.source_commit,
        challenge=options.challenge,
        operator_source=options.operator_source,
        container_mounted_read_only=options.container_mounted_read_only,
    )
    print(f"C8.4 source materialization verify: PASS envelope={path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MaterializationError as error:
        print(f"c84-source-materialization.py: {error}", file=sys.stderr)
        raise SystemExit(1) from error
