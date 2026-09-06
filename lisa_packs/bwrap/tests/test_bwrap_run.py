"""Unit tests for the bwrap_run handler (subprocess + probe mocked)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kernel.models import ToolExecutionContext

from lisa_packs.bwrap.tools.bwrap_run import bwrap_run


def _ctx(**overrides) -> ToolExecutionContext:
    base = dict(
        tool_id="bwrap_run",
        workspace_id="ws",
        user_slug="u",
        surface_id="surf",
        session_plan_digest="digest",
        parameters={"argv": ["echo", "hi"]},
        data_dir="",
        pack_config={},
    )
    base.update(overrides)
    return ToolExecutionContext(**base)


@pytest.mark.asyncio
async def test_missing_bwrap_returns_sandboxed_false(monkeypatch, tmp_path: Path) -> None:
    class _Caps:
        available = False
        can_overlay = False
        bwrap_path = None
        missing = ("bubblewrap (bwrap) binary not found on PATH",)

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    ctx = _ctx(data_dir=str(tmp_path))
    result = await bwrap_run.execute(ctx)
    assert result.error
    assert "bubblewrap" in result.error
    assert result.output_json["sandboxed"] is False
    assert result.output_json["missing"]


@pytest.mark.asyncio
async def test_invalid_layer_id_rejected(monkeypatch, tmp_path: Path) -> None:
    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": ["true"], "layer_id": "../escape"})
    result = await bwrap_run.execute(ctx)
    assert "Invalid layer_id" in result.error or "layer_id" in result.error


class _Result:
    return_code = 0
    stdout = "ok\n"
    stderr = ""
    timed_out = False
    output_truncated = False


def _fake_run_process(argv, *, timeout_seconds, max_output_bytes, log_path=None):
    async def _run():
        return _Result()

    return _run()


@pytest.mark.asyncio
async def test_default_backend_is_tmpfs_not_overlay(monkeypatch, tmp_path: Path) -> None:
    """With no persist/layer_id, tmpfs is used even when overlay is available."""
    class _Caps:
        available = True
        can_overlay = True  # overlay IS available, but must not be default
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": ["echo", "hi"]})
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["backend"] == "tmpfs"
    assert result.output_json["persistence"] == "ephemeral"
    # No layer is created when not requested.
    assert "layer_id" not in result.output_json
    assert "degraded" not in result.output_json
    # The model gets a writable, host-visible scratch area in tmpfs mode.
    assert result.output_json["scratch_dir"]
    assert result.output_json["capture_root"]


@pytest.mark.asyncio
async def test_tmpfs_mode_binds_workspace_readonly_and_scratch(
    monkeypatch, tmp_path: Path
) -> None:
    """tmpfs mode must add a RO workspace bind plus a writable scratch bind."""
    class _Caps:
        available = True
        can_overlay = False
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    captured = {}

    def _capture(argv, *, timeout_seconds, max_output_bytes, log_path=None):
        captured["argv"] = list(argv)
        return _fake_run_process(argv, timeout_seconds=timeout_seconds,
                                 max_output_bytes=max_output_bytes, log_path=log_path)

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _capture)
    ws = tmp_path / "project"
    ws.mkdir()
    ctx = _ctx(
        data_dir=str(tmp_path / "data"),
        pack_config={"workspace_root": str(ws)},
        parameters={"argv": ["echo", "hi"]},
    )
    result = await bwrap_run.execute(ctx)
    argv = captured["argv"]
    scratch = result.output_json["scratch_dir"]
    # Workspace bound read-only at its own path, and scratch bound read-write.
    # Use exact flag/path triplets so we never match the "--ro-bind / /" root.
    triplets = [argv[i : i + 3] for i in range(len(argv) - 2)]
    assert ["--ro-bind", str(ws), str(ws)] in triplets
    assert ["--bind", scratch, scratch] in triplets
    assert result.output_json["capture_root"] == str(ws)


@pytest.mark.asyncio
async def test_overlay_capture_targets_workspace_not_data_dir(
    monkeypatch, tmp_path: Path
) -> None:
    """The overlay lowerdir must be the configured workspace, not ~/.lisa."""
    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ws = tmp_path / "project"
    ws.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    ctx = _ctx(
        data_dir=str(data),
        pack_config={"workspace_root": str(ws)},
        parameters={"argv": ["true"], "persist": True},
    )
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["capture_root"] == str(ws.resolve())


@pytest.mark.asyncio
async def test_overlay_opt_in_when_available(monkeypatch, tmp_path: Path) -> None:
    """persist=True with overlay available uses the overlay backend."""
    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": ["true"], "persist": True})
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["backend"] == "overlay"
    assert result.output_json["persistence"] == "persistent"
    assert result.output_json["layer_id"]


@pytest.mark.asyncio
async def test_overlay_requested_but_unavailable_reports_degraded(
    monkeypatch, tmp_path: Path
) -> None:
    """Asking for overlay on a host without it degrades explicitly to tmpfs."""
    class _Caps:
        available = True
        can_overlay = False
        bwrap_path = "/usr/bin/bwrap"
        missing = ("unprivileged overlayfs (userxattr) mounts unavailable",)

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": ["true"], "persist": True})
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["sandboxed"] is True
    assert result.output_json["backend"] == "tmpfs"
    assert result.output_json["persistence"] == "ephemeral"
    assert result.output_json["degraded"] is True
    assert "missing" in result.output_json
    # The note carries the precise cause, not the generic bwrap-install hint.
    assert result.output_json["note"].startswith(
        "overlayfs capture was requested but is unavailable on this host"
    )


@pytest.mark.asyncio
async def test_overlay_cap_drop_note_omits_install_hint(monkeypatch, tmp_path: Path) -> None:
    """The structural bwrap cap-drop cause must NOT suggest reinstalling bwrap."""
    class _Caps:
        available = True
        can_overlay = False
        bwrap_path = "/usr/bin/bwrap"
        missing = (
            "bwrap drops all capabilities from the child (CapEff=0), so the "
            "overlay mount inside the namespace is denied (EPERM)."
        )
        overlay_reason = (
            "bwrap drops all capabilities from the child (CapEff=0), so the "
            "overlay mount inside the namespace is denied (EPERM). The kernel "
            "itself allows unprivileged overlayfs - the same mount succeeds "
            "via 'unshare --user --map-root-user'. overlayfs capture inside "
            "bwrap is structurally unavailable with this bubblewrap build; "
            "sandboxing still works with ephemeral tmpfs."
        )

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": ["true"], "persist": True})
    result = await bwrap_run.execute(ctx)
    assert result.output_json["degraded"] is True
    note = result.output_json["note"]
    assert "bwrap drops all capabilities" in note
    assert "zypper install bubblewrap" not in note
