"""The pack's POSIX host boundary: the APIs that only exist on POSIX.

This pack implements a Linux sandbox (bubblewrap + overlayfs ``userxattr``
mounts + ``unshare`` user namespaces). A handful of the APIs it leans on -
``os.getuid``/``os.getgid``, ``pwd.getpwuid``, ``os.killpg`` and
``signal.SIGKILL`` - exist only on POSIX, so a type checker running against
a Windows interpreter reports them as missing attributes even though the code
paths are never reachable there.

Rather than silencing those reports with blanket ignores, the POSIX-only
surface is collected in this one module and reached through small wrappers
whose platform branch is explicit. The branch is not defensive
programming: it states the pack's own support boundary, so the type checker
sees exactly the code that runs on the supported host and the module
imports cleanly on a non-POSIX interpreter (where the wrappers report
"unavailable" instead of raising ``AttributeError``).

Each guard compares ``sys.platform`` directly because that is the form a
type checker can narrow on: the POSIX-only attribute is resolved only on the
branch the checker knows it can reach.
"""

from __future__ import annotations

import os
import signal
import sys

__all__ = [
    "POSIX_HOST",
    "host_gid",
    "host_uid",
    "host_user_name",
    "kill_process_group",
]

#: True when the running interpreter exposes the POSIX APIs this pack needs.
#: Computed from the interpreter, not from a hard-coded list of platforms:
#: the pack's own feature probe decides whether the host can actually run
#: the sandbox, and this flag only says whether the POSIX *API surface*
#: exists at all.
POSIX_HOST = sys.platform != "win32"


def host_uid() -> int | None:
    """The invoking user's real uid, or None on a non-POSIX host.

    The sandbox maps exactly one uid (the invoking user) to sandbox root, so
    this is the value the identity stamp reports as the host side of the
    single-entry uid map.
    """
    if sys.platform == "win32":
        return None
    return os.getuid()


def host_gid() -> int | None:
    """The invoking user's real gid, or None on a non-POSIX host."""
    if sys.platform == "win32":
        return None
    return os.getgid()


def host_user_name(uid: int) -> str:
    """The host user name for ``uid``, or an empty string when unknown.

    ``pwd`` is a POSIX-only module; on a host without it (or without an
    entry for the uid) the name stays empty and callers fall back to a
    generic label.
    """
    if sys.platform == "win32":
        return ""
    try:
        import pwd
    except ImportError:
        return ""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return ""


def kill_process_group(pid: int) -> bool:
    """SIGKILL the whole process group of ``pid``.

    Returns True when the group kill was delivered, False when the platform
    has no process groups or the signal could not be sent. Callers fall back
    to killing the direct child in that case, so a False result is not an
    error - it just means the group-wide kill was not available.
    """
    if sys.platform == "win32":
        return False
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    return True
