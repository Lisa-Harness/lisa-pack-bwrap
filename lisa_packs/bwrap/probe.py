"""Capability probing for bubblewrap sandboxing.

The bwrap pack cannot install bubblewrap or enable kernel features as a Python
dependency - they are host-level prerequisites. This module detects what is
actually present so callers can either use the sandbox or report precisely
what is missing (never degrade silently).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["BwrapCapabilities", "detect_capabilities", "bwrap_binary"]

_BWRAP_BIN = "bwrap"

#: Scratch root for the differential unshare check inside
#: :func:`_classify_overlay_failure`. The classifier creates its own dirs under
#: here so it works regardless of which ``probe_dir`` the caller passed.
_PROBE_DIR_FOR_CLASSIFY = Path("/tmp/lisa-bwrap-overlay-probe")


def _ensure_classify_probe_dirs() -> Path | None:
    """Create the dirs the differential unshare mount needs; None if impossible."""
    try:
        for name in ("upper", "work", "merged", "lower"):
            (_PROBE_DIR_FOR_CLASSIFY / name).mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return _PROBE_DIR_FOR_CLASSIFY


def bwrap_binary() -> str | None:
    """Return the absolute path to the bwrap binary, or None if absent."""
    return shutil.which(_BWRAP_BIN)


def _userns_unprivileged_allowed() -> bool:
    """Best-effort check that unprivileged user namespaces are permitted."""
    # Debian/Ubuntu gate.
    knob = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if knob.exists():
        try:
            if knob.read_text().strip() != "1":
                return False
        except OSError:
            return False
    # A disabled-userns AppArmor/profile gate on newer Ubuntu.
    aa_restriction = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if aa_restriction.exists():
        try:
            if aa_restriction.read_text().strip() == "1":
                # Still allowed if bwrap is setuid; probe with a real run below.
                pass
        except OSError:
            pass
    return True


def _probe_bwrap_run(binary: str) -> bool:
    """Run a trivial namespaced command to confirm bwrap actually works."""
    try:
        proc = subprocess.run(
            [binary, "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _probe_overlay_userxattr(binary: str, probe_dir: Path) -> tuple[bool, str]:
    """Confirm unprivileged overlayfs (userxattr) mounts work inside bwrap.

    This probe MUST mirror the real overlay argv shape (scoped RO lowerdir,
    bound upper, bound pre-created merged mountpoint, NO workdir bound in, and
    the same namespace flags as ``build_bwrap_argv``). A probe whose argv differs
    from the real path can report success while the real run fails, or vice
    versa.

    Returns ``(supported, reason)``. ``reason`` is empty on success and carries
    a precise, host-specific diagnosis on failure so the degraded report points
    at the actual blocker instead of a generic kernel suggestion.
    """
    upper = probe_dir / "upper"
    work = probe_dir / "work"
    merged = probe_dir / "merged"
    lower = probe_dir / "lower"
    for path in (upper, work, merged, lower):
        path.mkdir(parents=True, exist_ok=True)
    script = (
        "mount -t overlay -o userxattr,"
        f"lowerdir={lower},upperdir={upper},workdir={work} overlay {merged}"
    )
    try:
        proc = subprocess.run(
            [
                binary,
                "--unshare-pid", "--unshare-uts", "--unshare-ipc",
                "--ro-bind", "/", "/",
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--ro-bind", str(lower), str(lower),
                "--bind", str(upper), str(upper),
                "--bind", str(merged), str(merged),
                "--die-with-parent", "--new-session",
                "--",
                "/bin/sh", "-c", script,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "overlay probe could not run (bwrap invocation failed)"
    if proc.returncode == 0:
        return True, ""
    stderr = (proc.stderr or "").decode("utf-8", errors="replace")
    return False, _classify_overlay_failure(binary, stderr)


def _overlay_mount_works_outside_bwrap(probe_dir: Path) -> bool:
    """Check whether the SAME userxattr overlay mount succeeds via plain unshare.

    The kernel may happily allow unprivileged overlay mounts while bwrap blocks
    them (bwrap drops every capability from the child, and mount(2) needs
    CAP_SYS_ADMIN in the owning user namespace). Running the identical mount
    through ``unshare --user --map-root-user --mount`` isolates that: unshare
    keeps full userns capabilities, so a success here proves the kernel is fine
    and the blocker is bwrap itself — a structural limit, not a host-fixable
    knob.
    """
    unshare = shutil.which("unshare")
    if unshare is None:
        return False
    upper = probe_dir / "upper"
    work = probe_dir / "work"
    merged = probe_dir / "merged"
    lower = probe_dir / "lower"
    script = (
        "mount -t overlay -o userxattr,"
        f"lowerdir={lower},upperdir={upper},workdir={work} overlay {merged}"
    )
    try:
        proc = subprocess.run(
            [
                unshare,
                "--user", "--map-root-user", "--mount",
                "--pid", "--fork", "--uts", "--ipc",
                "/bin/sh", "-c", script,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _classify_overlay_failure(binary: str, stderr: str) -> str:
    """Map an overlay-probe failure to the most precise host-specific cause.

    Priority order: bwrap's capability drop (the mount was denied by EPERM
    while the kernel demonstrably allows unprivileged overlays via unshare),
    then an explicit kernel/LSM denial, then the generic unavailable message.
    """
    probe_root = _ensure_classify_probe_dirs()
    if probe_root is not None and _overlay_mount_works_outside_bwrap(probe_root):
        return (
            "bwrap drops all capabilities from the child (CapEff=0), so the "
            "overlay mount inside the namespace is denied (EPERM). The kernel "
            "itself allows unprivileged overlayfs - the same mount succeeds "
            "via 'unshare --user --map-root-user'. overlayfs capture inside "
            "bwrap is structurally unavailable with this bubblewrap build; "
            "sandboxing still works with ephemeral tmpfs."
        )
    lowered = stderr.lower()
    if "overlay" in lowered and ("not supported" in lowered or "denied" in lowered):
        return (
            "the kernel or an LSM policy denied the overlay mount syscall "
            "inside the user namespace; unprivileged overlayfs is disabled "
            "on this host"
        )
    return "unprivileged overlayfs (userxattr) mounts unavailable"


@dataclass(frozen=True, slots=True)
class BwrapCapabilities:
    """Detected sandboxing capabilities for the current host."""

    bwrap_path: str | None
    bwrap_works: bool
    overlay_supported: bool
    userns_allowed: bool
    missing: tuple[str, ...] = field(default_factory=tuple)
    #: Precise cause when ``overlay_supported`` is False (empty on success).
    overlay_reason: str = ""

    @property
    def available(self) -> bool:
        """True when a usable sandbox (bwrap running namespaced) exists."""
        return self.bwrap_path is not None and self.bwrap_works

    @property
    def can_overlay(self) -> bool:
        """True when transparent overlayfs layers can be used."""
        return self.available and self.overlay_supported


def detect_capabilities(*, probe_dir: Path | None = None) -> BwrapCapabilities:
    """Detect bubblewrap + overlayfs capabilities on this host.

    Detection is ordered and conservative: binary presence first, then a real
    namespaced run, then (only if a probe_dir is given) a real overlay mount.
    """
    missing: list[str] = []
    binary = bwrap_binary()
    if binary is None:
        missing.append("bubblewrap (bwrap) binary not found on PATH")
        return BwrapCapabilities(
            bwrap_path=None,
            bwrap_works=False,
            overlay_supported=False,
            userns_allowed=False,
            missing=tuple(missing),
        )

    userns = _userns_unprivileged_allowed()
    works = _probe_bwrap_run(binary)
    if not works:
        if not userns:
            missing.append("unprivileged user namespaces are disabled")
        else:
            missing.append("bwrap is present but a namespaced run failed")
    overlay = False
    overlay_reason = ""
    if works and probe_dir is not None:
        try:
            overlay, overlay_reason = _probe_overlay_userxattr(binary, probe_dir)
        except OSError:
            overlay = False
            overlay_reason = "overlay probe raised an unexpected error"
        if not overlay:
            missing.append(
                overlay_reason or "unprivileged overlayfs (userxattr) mounts unavailable"
            )
    return BwrapCapabilities(
        bwrap_path=binary,
        bwrap_works=works,
        overlay_supported=overlay,
        userns_allowed=userns,
        missing=tuple(missing),
        overlay_reason=overlay_reason,
    )
