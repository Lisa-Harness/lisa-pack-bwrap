"""Tests for the overlay-failure classifier in the capability probe.

The classifier must distinguish the structural bwrap cap-drop cause (not
host-fixable) from kernel/LSM denials and generic unavailability, so the
degraded report points at the real blocker.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from lisa_packs.bwrap import probe
from lisa_packs.bwrap.probe import (
    _classify_overlay_failure,
    _probe_overlay_userxattr,
)


def test_classify_reports_cap_drop_when_unshare_mount_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Kernel allows the mount via unshare -> the blocker is the bwrap stage."""

    def _fake_unshare_ok(_probe_dir: Path) -> bool:
        return True

    monkeypatch.setattr(probe, "_overlay_mount_works_outside_bwrap", _fake_unshare_ok)
    monkeypatch.setattr(probe, "_ensure_classify_probe_dirs", lambda: tmp_path)
    reason = _classify_overlay_failure("/usr/bin/bwrap", "mount: must be superuser")
    assert "bwrap stage is the blocker" in reason
    assert "unshare --user --map-root-user" in reason
    # The old structural message is gone: the launcher pre-mounts, so
    # bwrap's cap drop no longer blocks the mount itself.
    assert "bwrap drops all capabilities" not in reason


def test_classify_reports_kernel_denial_when_unshare_also_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both the chain and the standalone mount fail with a denial -> kernel cause."""

    def _fake_unshare_fail(_probe_dir: Path) -> bool:
        return False

    monkeypatch.setattr(probe, "_overlay_mount_works_outside_bwrap", _fake_unshare_fail)
    monkeypatch.setattr(probe, "_ensure_classify_probe_dirs", lambda: tmp_path)
    reason = _classify_overlay_failure(
        "/usr/bin/bwrap", "mount: overlay is not supported by the kernel"
    )
    assert "kernel or an LSM policy" in reason
    assert "bwrap drops" not in reason


def test_classify_generic_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Unrecognized failure keeps the generic unavailable message."""

    def _fake_unshare_fail(_probe_dir: Path) -> bool:
        return False

    monkeypatch.setattr(probe, "_overlay_mount_works_outside_bwrap", _fake_unshare_fail)
    monkeypatch.setattr(probe, "_ensure_classify_probe_dirs", lambda: tmp_path)
    reason = _classify_overlay_failure("/usr/bin/bwrap", "")
    assert reason == "unprivileged overlayfs (userxattr) mounts unavailable"


def test_probe_returns_reason_tuple_on_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the launcher chain fails, the probe reports (False, reason), never raises.

    Failure is simulated at the mount step (the sh script exits nonzero) so
    the test is host-independent: no real overlay capability is required
    either way, and the contract under test is the (False, reason) tuple.
    """
    # The probe's first step is `shutil.which("unshare")`. Hosts without
    # util-linux's unshare (macOS, Windows) would take that early return and
    # never reach the mocked subprocess path this test is about, so the
    # reason would be the "unshare not found" text instead of the mocked
    # classifier's cause. Pin the lookup so the probe always sees a launcher
    # binary and the test exercises the same branch on every host.
    # `lisa_packs.bwrap.probe.shutil` IS the `shutil` module, so patching
    # `which` on it is what the probe's own call resolves to.
    real_which = shutil.which
    monkeypatch.setattr(
        "lisa_packs.bwrap.probe.shutil.which",
        lambda cmd: "/usr/bin/unshare" if cmd == "unshare" else real_which(cmd),
    )
    monkeypatch.setattr(probe, "_classify_overlay_failure", lambda _b, _e: "cause-x")

    class _FailedMount:
        returncode = 1
        stdout = b""
        stderr = b"mount: must be superuser to use mount"

    def _fake_run(argv: list[str], **kwargs: Any) -> _FailedMount:
        return _FailedMount()

    monkeypatch.setattr("lisa_packs.bwrap.probe.subprocess.run", _fake_run)
    supported, reason = _probe_overlay_userxattr("/usr/bin/bwrap", tmp_path)
    assert supported is False
    assert reason == "cause-x"


def test_probe_reports_missing_unshare_before_running_the_chain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without util-linux's unshare the probe stops early, naming the blocker.

    This is the branch the failure test above must NOT reach: the overlay
    launcher chain needs unshare to create the root-mapped user namespace
    that performs the overlay mounts, so a host without it cannot run the
    chain at all. The reason names the missing dependency instead of
    reporting a generic overlay failure.
    """
    monkeypatch.setattr("lisa_packs.bwrap.probe.shutil.which", lambda _cmd: None)
    supported, reason = _probe_overlay_userxattr("/usr/bin/bwrap", tmp_path)
    assert supported is False
    assert "unshare" in reason
    assert "not found on PATH" in reason


def test_probe_succeeds_on_supporting_host(tmp_path: Path) -> None:
    """On a host with unprivileged userns + kernel overlay, the real chain works.

    Skipped automatically when the launcher chain is unavailable (e.g. no
    unshare, no userns, or overlay denied); on supporting hosts this is the
    end-to-end guarantee that capture ACTUALLY works, not just classifies.
    """
    import shutil as _shutil

    if _shutil.which("bwrap") is None or _shutil.which("unshare") is None:
        pytest.skip("bwrap/unshare not installed")
    supported, reason = _probe_overlay_userxattr("/usr/bin/bwrap", tmp_path)
    if not supported and ("not found on PATH" in reason or "could not run" in reason):
        pytest.skip(f"launcher chain unavailable here: {reason}")
    assert supported is True, reason


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
