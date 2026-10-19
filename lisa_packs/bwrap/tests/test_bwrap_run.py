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
    # Error paths carry no identity stamp: the sandbox never ran.
    assert "identity" not in result.output_json


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


@pytest.mark.asyncio
async def test_argv_json_string_is_coerced_to_list(monkeypatch, tmp_path: Path) -> None:
    """A JSON-encoded string for ``argv`` is accepted as a real list.

    Same lenient-model fix as bash_run's ``commands`` (the 2026-10-18
    production incident — under a JSON-mode tool schema the model emitted
    a list-valued parameter as a STRING containing the JSON array, and
    identical ``Input should be a valid list`` validation errors repeated
    because nothing in the error told it why the shape was wrong).
    """

    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())

    seen: dict = {}

    def _fake_run_process(argv, **kwargs):
        seen["argv"] = list(argv)

        async def _run():
            return _OkResult()

        return _run()

    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": '["echo", "hi"]'})
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert "echo" in seen["argv"] and "hi" in seen["argv"]


@pytest.mark.asyncio
async def test_argv_non_json_string_still_rejected(monkeypatch, tmp_path: Path) -> None:
    """A plain (non-JSON) string for ``argv`` keeps the standard error."""

    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": "echo hi"})
    result = await bwrap_run.execute(ctx)
    assert result.error
    assert "argv" in result.error


class _OkResult:
    return_code = 0
    stdout = "ok\n"
    stderr = ""
    timed_out = False
    output_truncated = False


class _Result:
    return_code = 0
    stdout = "ok\n"
    stderr = ""
    timed_out = False
    output_truncated = False


def _fake_run_process(argv, *, timeout_seconds, max_output_bytes, log_path=None, on_output=None):
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
    # Identity mapping is stamped on every sandboxed success.
    identity = result.output_json["identity"]
    assert identity["sandbox_uid"] == 0
    assert identity["sandbox_gid"] == 0
    assert identity["host_uid"] > 0
    assert "nobody:nobody" in identity["note"]
    assert "sandbox_ownership.md" in identity["note"]
    assert "single-entry uid map" in identity["map"]


@pytest.mark.asyncio
async def test_tmpfs_mode_binds_workspace_readonly_and_scratch(monkeypatch, tmp_path: Path) -> None:
    """tmpfs mode must add a RO workspace bind plus a writable scratch bind."""

    class _Caps:
        available = True
        can_overlay = False
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    captured = {}

    def _capture(argv, *, timeout_seconds, max_output_bytes, log_path=None, on_output=None):
        captured["argv"] = list(argv)
        return _fake_run_process(
            argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            log_path=log_path,
            on_output=on_output,
        )

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
async def test_overlay_capture_targets_workspace_not_data_dir(monkeypatch, tmp_path: Path) -> None:
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
    # Staged runs point the model at the review contract doc.
    assert "STAGED" in result.output_json["note"]
    assert "layer_review.md" in result.output_json["note"]
    assert result.output_json["layer_id"] in result.output_json["note"]
    # Overlay path carries the same identity contract as tmpfs.
    identity = result.output_json["identity"]
    assert identity["sandbox_uid"] == 0
    assert identity["host_uid"] > 0
    assert "nobody:nobody" in identity["note"]
    assert "chown" in identity["note"]


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


@pytest.mark.asyncio
async def test_overlay_uses_launcher_chain_with_cap_drop(monkeypatch, tmp_path: Path) -> None:
    """The overlay run wraps the bwrap argv in the unshare pre-mount chain."""

    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    captured = {}

    def _capture(argv, *, timeout_seconds, max_output_bytes, log_path=None, on_output=None):
        captured["argv"] = list(argv)
        return _fake_run_process(
            argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            log_path=log_path,
            on_output=on_output,
        )

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _capture)
    ws = tmp_path / "project"
    ws.mkdir()
    ctx = _ctx(
        data_dir=str(tmp_path / "data"),
        pack_config={"workspace_root": str(ws)},
        parameters={"argv": ["true"], "persist": True},
    )
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    argv = captured["argv"]
    assert argv[0:5] == ["unshare", "--user", "--map-root-user", "--mount", "--"]
    script = argv[-1]
    # Mount onto the workspace's own path, then exec bwrap, ending cap-dropped.
    assert f"lowerdir='{ws}'" in script
    # Every argv token is shell-quoted before the exec.
    assert "exec '/usr/bin/bwrap'" in script
    assert "'--cap-drop' 'ALL'" in script
    # bwrap binds the merged view RW (not the old child-mount script).
    assert f"'--bind' '{ws}' '{ws}'" in script


@pytest.mark.asyncio
async def test_capture_paths_compose_extra_overlay_targets(monkeypatch, tmp_path: Path) -> None:
    """Requested capture paths become additional overlay targets, stamped."""

    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    captured = {}

    def _capture(argv, *, timeout_seconds, max_output_bytes, log_path=None, on_output=None):
        captured["argv"] = list(argv)
        return _fake_run_process(
            argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            log_path=log_path,
            on_output=on_output,
        )

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _capture)
    ws = tmp_path / "project"
    ws.mkdir()
    sys_dir = tmp_path / "sysroot"
    sys_dir.mkdir()
    ctx = _ctx(
        data_dir=str(tmp_path / "data"),
        pack_config={"workspace_root": str(ws)},
        parameters={
            "argv": ["true"],
            "overrides": {"paths": {str(sys_dir): "capture"}},
        },
    )
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["backend"] == "overlay"
    assert str(sys_dir) in result.output_json["captured_paths"]
    script = captured["argv"][-1]
    # Two mounts: the capture root and the captured path.
    assert f"lowerdir='{ws}'" in script
    assert f"lowerdir='{sys_dir}'" in script
    assert f"overlay '{sys_dir}'" in script
    # Capture implies overlay posture even without persist/layer_id.
    assert result.output_json["persistence"] == "overlay"
    # Staged runs point the model at the review contract doc.
    assert "layer_review.md" in result.output_json["note"]


@pytest.mark.asyncio
async def test_capture_paths_with_nonoverlay_persistence_rejected(
    monkeypatch, tmp_path: Path
) -> None:
    """Capture + ephemeral is a loud policy error, never a silent degrade."""

    class _Caps:
        available = True
        can_overlay = True
        bwrap_path = "/usr/bin/bwrap"
        missing = ()

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    sys_dir = tmp_path / "sysroot"
    sys_dir.mkdir()
    ctx = _ctx(
        data_dir=str(tmp_path),
        parameters={
            "argv": ["true"],
            "overrides": {"persistence": "ephemeral", "paths": {str(sys_dir): "capture"}},
        },
    )
    result = await bwrap_run.execute(ctx)
    assert result.error
    assert "capture" in result.error
    assert "overlay" in result.error


@pytest.mark.asyncio
async def test_overlay_requested_but_unavailable_reports_precise_note(
    monkeypatch, tmp_path: Path
) -> None:
    """Asking for overlay on a host without it degrades with a precise note."""

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
    assert result.output_json["degraded"] is True
    # The note carries the precise cause, not the generic bwrap-install hint.
    assert result.output_json["note"].startswith(
        "overlayfs capture was requested but is unavailable on this host"
    )


@pytest.mark.asyncio
async def test_overlay_blocker_note_omits_install_hint(monkeypatch, tmp_path: Path) -> None:
    """A chain-blocker cause (bwrap stage) must NOT suggest reinstalling bwrap."""

    class _Caps:
        available = True
        can_overlay = False
        bwrap_path = "/usr/bin/bwrap"
        missing = (
            "the overlay mount works via 'unshare --user --map-root-user' but "
            "the full launcher chain failed;"
        )
        overlay_reason = (
            "the overlay mount works via 'unshare --user --map-root-user' but "
            "the full launcher chain (mount + bwrap bind + --cap-drop ALL) "
            "failed, so the bwrap stage is the blocker. The kernel allows "
            "unprivileged overlayfs; check the bwrap stderr above. "
            "Sandboxing still works with ephemeral tmpfs."
        )

    monkeypatch.setattr(bwrap_run, "detect_capabilities", lambda probe_dir=None: _Caps())
    monkeypatch.setattr(bwrap_run, "run_process", _fake_run_process)
    ctx = _ctx(data_dir=str(tmp_path), parameters={"argv": ["true"], "persist": True})
    result = await bwrap_run.execute(ctx)
    assert result.output_json["degraded"] is True
    note = result.output_json["note"]
    assert "the bwrap stage is the blocker" in note
    assert "zypper install bubblewrap" not in note
