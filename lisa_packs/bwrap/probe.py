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
    """Confirm overlayfs capture works via the launcher chain this pack uses.

    This probe MUST mirror the real capture argv shape: ``unshare --user
    --map-root-user --mount`` mounts one overlay per target onto the target's
    own path (lowerdir = the live target, upper/work under the layers dir),
    then execs bwrap which binds the merged views RW and ends
    ``--cap-drop ALL``. A probe whose argv differs from the real path can
    report success while the real run fails, or vice versa.

    The legacy child-side mount (bwrap creates the namespace, the child runs
    ``mount``) is NOT probed: bwrap always drops all capabilities from the
    child, so that path is structurally EPERM on unprivileged hosts. The
    launcher chain is the only overlay path the pack ships.

    Returns ``(supported, reason)``. ``reason`` is empty on success and carries
    a precise, host-specific diagnosis on failure so the degraded report points
    at the actual blocker instead of a generic kernel suggestion.
    """
    if shutil.which("unshare") is None:
        return False, (
            "util-linux 'unshare' not found on PATH - the overlay launcher "
            "chain requires it to create the root-mapped user namespace that "
            "performs the overlay mounts"
        )
    lower = probe_dir / "lower"
    upper = probe_dir / "upper"
    work = probe_dir / "work"
    merged = probe_dir / "merged"
    for path in (upper, work, merged, lower):
        path.mkdir(parents=True, exist_ok=True)
    marker = merged / "probe.txt"  # written via the merged view by the child
    inner_argv = [
        binary,
        "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-net",
        "--ro-bind", "/", "/",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--bind", str(merged), str(merged),
        "--die-with-parent", "--new-session", "--cap-drop", "ALL",
        "--", "sh", "-c", f"echo probe > {marker}",
    ]
    quoted = " ".join("'" + a.replace("'", "'\\''") + "'" for a in inner_argv)
    mount = (
        "mount -t overlay -o userxattr,"
        f"lowerdir={lower},upperdir={upper},workdir={work} "
        f"overlay {merged} && exec {quoted}"
    )
    try:
        proc = subprocess.run(
            [
                "unshare", "--user", "--map-root-user", "--mount", "--",
                "/bin/sh", "-c", mount,
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "overlay probe could not run (unshare invocation failed)"
    if proc.returncode == 0 and (upper / "probe.txt").is_file():
        # The child's write through the merged view lands in the overlay's
        # upper dir; the host never sees the merged view (it exists only in
        # the launcher's mount namespace), so success is asserted on upper.
        return True, ""
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    return False, _classify_overlay_failure(binary, stderr)


def _overlay_mount_works_outside_bwrap(probe_dir: Path) -> bool:
    """Check whether the SAME userxattr overlay mount succeeds via plain unshare.

    The launcher chain mounts the overlay in the ``unshare --user
    --map-root-user --mount`` stage, which keeps full user-namespace
    capabilities. Running the identical mount standalone isolates the kernel
    question from the bwrap stage: a success here proves the kernel/LSM allow
    unprivileged overlays, so a failing full chain points at the bwrap stage,
    not at the host.
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

    Priority order: the kernel demonstrably allows unprivileged overlays (the
    standalone unshare mount works) while the full launcher chain failed - so
    the blocker is the bwrap stage of the chain, reported as such; then an
    explicit kernel/LSM denial; then the generic unavailable message.
    """
    probe_root = _ensure_classify_probe_dirs()
    if probe_root is not None and _overlay_mount_works_outside_bwrap(probe_root):
        return (
            "the overlay mount works via 'unshare --user --map-root-user' but "
            "the full launcher chain (mount + bwrap bind + --cap-drop ALL) "
            "failed, so the bwrap stage is the blocker. The kernel allows "
            "unprivileged overlayfs; check the bwrap stderr above (e.g. a "
            "bubblewrap build that rejects one of the emitted flags). "
            "Sandboxing still works with ephemeral tmpfs."
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
