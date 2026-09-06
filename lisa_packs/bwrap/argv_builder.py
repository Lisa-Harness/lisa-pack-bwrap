"""Pure bwrap argv construction - no I/O, no side effects."""

from __future__ import annotations

from collections.abc import Sequence

__all__ = ["build_bwrap_argv"]


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
