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
) -> list[str]:
    """Build the full bwrap argument vector.

    Namespace + isolation + read-only root are added here; backend-specific
    bind/mount args (overlay upper/work dirs, or nothing for tmpfs) are passed
    in already formed by the backend. The child argv follows ``--``.
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

    # Backend-specific writable binds (overlay upper/work, or none for tmpfs).
    argv += list(backend_bind_args)

    # Lifecycle: do not outlive the parent, isolate the session.
    argv += ["--die-with-parent", "--new-session"]

    argv += ["--"]
    argv += list(child_argv)
    return argv
