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


def _probe_overlay_userxattr(binary: str, probe_dir: Path) -> bool:
    """Confirm unprivileged overlayfs (userxattr) mounts work inside bwrap."""
    upper = probe_dir / "upper"
    work = probe_dir / "work"
    merged = probe_dir / "merged"
    for path in (upper, work, merged):
        path.mkdir(parents=True, exist_ok=True)
    script = (
        "mount -t overlay -o userxattr,lowerdir=/,"
        f"upperdir={upper},workdir={work} overlay {merged}"
    )
    try:
        proc = subprocess.run(
            [
                binary,
                "--unshare-all",
                "--ro-bind", "/", "/",
                "--bind", str(upper), str(upper),
                "--bind", str(work), str(work),
                "--bind", str(merged), str(merged),
                "--die-with-parent",
                "--",
                "/bin/sh", "-c", script,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


@dataclass(frozen=True, slots=True)
class BwrapCapabilities:
    """Detected sandboxing capabilities for the current host."""

    bwrap_path: str | None
    bwrap_works: bool
    overlay_supported: bool
    userns_allowed: bool
    missing: tuple[str, ...] = field(default_factory=tuple)

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
    if works and probe_dir is not None:
        try:
            overlay = _probe_overlay_userxattr(binary, probe_dir)
        except OSError:
            overlay = False
        if not overlay:
            missing.append("unprivileged overlayfs (userxattr) mounts unavailable")
    return BwrapCapabilities(
        bwrap_path=binary,
        bwrap_works=works,
        overlay_supported=overlay,
        userns_allowed=userns,
        missing=tuple(missing),
    )
