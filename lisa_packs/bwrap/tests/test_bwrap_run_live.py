"""Live, opt-in integration tests for bwrap_run.

Marked ``live``; requires bubblewrap installed and unprivileged userns.
Skipped automatically when bwrap is not available.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from kernel.models import OperationExecutionContext, ToolExecutionContext

from lisa_packs.bwrap.operations.layers_apply import layers_apply
from lisa_packs.bwrap.operations.layers_export import layers_export
from lisa_packs.bwrap.posix_host import host_uid
from lisa_packs.bwrap.tools.bwrap_run import bwrap_run

pytestmark = pytest.mark.live

#: Named counts used by the live export assertions, so the expected values
#: read as contract rather than magic numbers.
_EXPORTED_FILE_COUNT = 2


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed")
@pytest.mark.asyncio
async def test_bwrap_run_echo_roundtrip(tmp_path: Path) -> None:
    ctx = ToolExecutionContext(
        tool_id="bwrap_run",
        workspace_id="ws",
        parameters={"argv": ["echo", "hello-lisa"], "timeout_seconds": 30},
        data_dir=str(tmp_path),
    )
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["sandboxed"] is True
    assert "hello-lisa" in result.output_text
    assert result.output_json["return_code"] == 0
    # Real-namespace check: the identity stamp describes THIS host's mapping.
    identity = result.output_json["identity"]
    assert identity["sandbox_uid"] == 0
    assert identity["host_uid"] == host_uid()


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed")
@pytest.mark.skipif(shutil.which("unshare") is None, reason="unshare not installed")
@pytest.mark.asyncio
async def test_bwrap_run_capture_paths_live_roundtrip(tmp_path: Path) -> None:
    """Live capture: stage writes to the workspace + a capture path, then
    export diffs and apply the merge — the full tier-2 admin flow, real
    namespaces. Skipped when this host cannot do overlay capture."""
    from lisa_packs.bwrap.probe import detect_capabilities

    caps = detect_capabilities(probe_dir=tmp_path / ".probe")
    if not caps.can_overlay:
        pytest.skip(f"overlay capture unavailable here: {caps.overlay_reason}")

    ws = tmp_path / "ws"
    sys_dir = tmp_path / "etcmock"
    ws.mkdir()
    (sys_dir / "conf").mkdir(parents=True)
    (ws / "base.txt").write_text("original")
    (sys_dir / "conf" / "app.conf").write_text("port=80")

    ctx = ToolExecutionContext(
        tool_id="bwrap_run",
        workspace_id="ws",
        user_slug="u",
        surface_id="s",
        session_plan_digest="d",
        data_dir=str(tmp_path / "data"),
        pack_config={"workspace_root": str(ws)},
        parameters={
            "argv": [
                "/bin/sh",
                "-c",
                f"echo edited > {ws}/base.txt; "
                f"echo port=8080 > {sys_dir}/conf/app.conf; "
                f"echo extra >> {sys_dir}/conf/app.conf; echo done",
            ],
            "persist": True,
            "layer_id": "live-capture",
            "overrides": {"paths": {str(sys_dir): "capture"}},
        },
    )
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    oj = result.output_json
    assert oj["backend"] == "overlay"
    assert oj["sandboxed"] is True
    assert oj["captured_paths"] == [str(sys_dir)]
    assert oj["layer_id"] == "live-capture"

    # Live files untouched after capture.
    assert (ws / "base.txt").read_text() == "original"
    assert (sys_dir / "conf" / "app.conf").read_text() == "port=80"

    # Export: reviewable diffs rendered against the LIVE targets.
    octx = OperationExecutionContext(
        workspace_id="ws",
        user_slug="u",
        surface_id="s",
        session_plan_digest="d",
        data_dir=str(tmp_path / "data"),
        params={"layer_id": "live-capture"},
    )
    export = await layers_export.execute(octx)
    assert export.status == "success"
    assert export.output_json["files"] == _EXPORTED_FILE_COUNT
    export_dir = Path(export.output_json["export_dir"])
    base_diff = next(export_dir.rglob("base.txt.diff"))
    assert "-original" in base_diff.read_text()
    assert "+edited" in base_diff.read_text()
    # Nested captured paths keep their relative path in the diff name
    # (conf/app.conf -> conf__app.conf.diff).
    conf_diff = next(export_dir.rglob("conf__app.conf.diff"))
    assert "-port=80" in conf_diff.read_text()
    assert "+port=8080" in conf_diff.read_text()

    # Apply: the user-invoked merge lands exactly the captured writes.
    applied = await layers_apply.execute(octx)
    assert applied.status == "success"
    assert (ws / "base.txt").read_text() == "edited\n"
    assert (sys_dir / "conf" / "app.conf").read_text() == "port=8080\nextra\n"
