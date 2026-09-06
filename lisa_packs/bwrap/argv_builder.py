"""Pure bwrap argv construction - no I/O, no side effects."""

from __future__ import annotations

from collections.abc import Sequence

from lisa_packs.bwrap.policy import SandboxProfile

__all__ = ["build_bwrap_argv", "build_bwrap_argv_for_profile"]


def build_bwrap_argv(
    *,
    bwrap_path: str = "bwrap",
    network: bool,
    child_argv: Sequence[str],
    backend_bind_args: Sequence[str] = (),
    writable_extra: Sequence[str] = (),
) -> list[str]:
    """Build the full bwrap argument vector.

    Namespace + isolation + read-only root are added here; backend-specific
    bind/mount args (overlay upper/work dirs, or tmpfs workspace/scratch binds)
    are passed in already formed by the backend. ``writable_extra`` carries
    caller-requested read-write binds (e.g. an owned worktree outside the
    capture root) as already-formed ``--bind PATH PATH`` fragments. The child
    argv follows ``--``.
    """
    if not child_argv:
        raise ValueError("child_argv must be a non-empty argument vector")
    argv: list[str] = [bwrap_path]

    # Namespace isolation.
    argv += ["--unshare-pid", "--unshare-uts", "--unshare-ipc"]
    if not network:
        argv += ["--unshare-net"]

    # Read-only root plus standard proc/dev/tmp mounts.
    argv += ["--ro-bind", "/", "/"]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]

    # Backend-specific writable binds (overlay upper/work, or workspace RO +
    # scratch RW for tmpfs), then any caller-requested extra writable binds.
    argv += list(backend_bind_args)
    argv += list(writable_extra)

    # Lifecycle: do not outlive the parent, isolate the session.
    argv += ["--die-with-parent", "--new-session"]

    argv += ["--"]
    argv += list(child_argv)
    return argv


def build_bwrap_argv_for_profile(
    *,
    bwrap_path: str = "bwrap",
    profile: SandboxProfile,
    child_argv: Sequence[str],
    backend_bind_args: Sequence[str] = (),
) -> list[str]:
    """Build the bwrap argv from a resolved :class:`SandboxProfile`.

    The profile IS the containment: network, device, ipc, tmpfs budget and
    per-path visibility are emitted from the policy-resolved profile rather than
    the fixed skeleton, so the harness floor (not the model) decides them at
    dispatch. Backend bind args arrive already formed; per-path floor binds are
    appended after the backend binds so a floor path binds on top.
    """
    if not child_argv:
        raise ValueError("child_argv must be a non-empty argument vector")

    argv: list[str] = [bwrap_path]
    argv += ["--unshare-pid", "--unshare-uts"]
    if profile.ipc != "shared":
        argv += ["--unshare-ipc"]
    if profile.network != "allow":
        argv += ["--unshare-net"]

    # Read-only root + proc always; /dev per device tier.
    argv += ["--ro-bind", "/", "/"]
    argv += ["--proc", "/proc"]
    if profile.device == "none":
        argv += ["--dev-bind", "/dev/null", "/dev/null"]
    else:  # "dev" | "minimal" - minimal synthetic /dev is the safe default
        argv += ["--dev", "/dev"]

    # Writable /tmp, size-capped when the floor sets a budget.
    if profile.tmpfs_budget_bytes is not None:
        argv += [
            "--size",
            str(profile.tmpfs_budget_bytes),
            "--tmpfs",
            "/tmp",
        ]
    else:
        argv += ["--tmpfs", "/tmp"]

    argv += list(backend_bind_args)

    # Floor/override per-path visibility, applied after backend binds.
    for path, access in sorted(profile.paths.items()):
        if access == "rw":
            argv += ["--bind", path, path]
        elif access == "ro":
            argv += ["--ro-bind", path, path]
        # "hidden" = no bind at all.

    argv += ["--die-with-parent", "--new-session"]
    argv += ["--"]
    argv += list(child_argv)
    return argv
