"""Tests for the overlay-failure classifier in the capability probe.

The classifier must distinguish the structural bwrap cap-drop cause (not
host-fixable) from kernel/LSM denials and generic unavailability, so the
degraded report points at the real blocker.
"""

from __future__ import annotations

from pathlib import Path

from lisa_packs.bwrap import probe
from lisa_packs.bwrap.probe import (
    _classify_overlay_failure,
    _probe_overlay_userxattr,
)


def test_classify_reports_cap_drop_when_unshare_mount_succeeds(
    monkeypatch, tmp_path: Path
) -> None:
    """Kernel allows the mount via unshare -> the blocker is bwrap, not the host."""

    def _fake_unshare_ok(_probe_dir: Path) -> bool:
        return True

    monkeypatch.setattr(probe, "_overlay_mount_works_outside_bwrap", _fake_unshare_ok)
    monkeypatch.setattr(probe, "_ensure_classify_probe_dirs", lambda: tmp_path)
    reason = _classify_overlay_failure("/usr/bin/bwrap", "mount: must be superuser")
    assert "bwrap drops all capabilities" in reason
    assert "unshare --user --map-root-user" in reason
    assert "structurally unavailable" in reason


def test_classify_reports_kernel_denial_when_unshare_also_fails(
    monkeypatch, tmp_path: Path
) -> None:
    """Both bwrap and unshare fail with a denial -> kernel/LSM cause."""

    def _fake_unshare_fail(_probe_dir: Path) -> bool:
        return False

    monkeypatch.setattr(probe, "_overlay_mount_works_outside_bwrap", _fake_unshare_fail)
    monkeypatch.setattr(probe, "_ensure_classify_probe_dirs", lambda: tmp_path)
    reason = _classify_overlay_failure(
        "/usr/bin/bwrap", "mount: overlay is not supported by the kernel"
    )
    assert "kernel or an LSM policy" in reason
    assert "bwrap drops" not in reason


def test_classify_generic_fallback(monkeypatch, tmp_path: Path) -> None:
    """Unrecognized failure keeps the generic unavailable message."""

    def _fake_unshare_fail(_probe_dir: Path) -> bool:
        return False

    monkeypatch.setattr(probe, "_overlay_mount_works_outside_bwrap", _fake_unshare_fail)
    monkeypatch.setattr(probe, "_ensure_classify_probe_dirs", lambda: tmp_path)
    reason = _classify_overlay_failure("/usr/bin/bwrap", "")
    assert reason == "unprivileged overlayfs (userxattr) mounts unavailable"


def test_probe_returns_reason_tuple_on_failure(monkeypatch, tmp_path: Path) -> None:
    """The real probe reports (False, reason) and never raises on mount denial."""
    monkeypatch.setattr(probe, "_classify_overlay_failure", lambda _b, _e: "cause-x")
    supported, reason = _probe_overlay_userxattr("/usr/bin/bwrap", tmp_path)
    assert supported is False
    assert reason == "cause-x"


def test_capabilities_carries_overlay_reason() -> None:
    caps = probe.BwrapCapabilities(
        bwrap_path="/usr/bin/bwrap",
        bwrap_works=True,
        overlay_supported=False,
        userns_allowed=True,
        missing=("cause-y",),
        overlay_reason="cause-y",
    )
    assert caps.available is True
    assert caps.can_overlay is False
    assert caps.overlay_reason == "cause-y"