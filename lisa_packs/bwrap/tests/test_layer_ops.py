"""Unit tests for the layers_export and layers_apply operations.

Pure filesystem tests: build a layer via OverlayBackend (no subprocess), then
export and apply it against a scratch live tree.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from kernel.models import OperationExecutionContext

from lisa_packs.bwrap.backends.overlay import OverlayBackend
from lisa_packs.bwrap.operations.layers_apply import layers_apply
from lisa_packs.bwrap.operations.layers_export import layers_export

#: Named counts used by the export assertions, so the expected values read
#: as contract rather than magic numbers.
_EXPECTED_TARGET_COUNT = 2
_EXPECTED_FILE_COUNT = 3


def _ctx(data_dir: Path, layer_id: str = "") -> OperationExecutionContext:
    return OperationExecutionContext(
        workspace_id="ws",
        user_slug="u",
        surface_id="s",
        session_plan_digest="d",
        data_dir=str(data_dir),
        params={"layer_id": layer_id},
    )


def _make_layer(data_dir: Path, ws: Path, sys_dir: Path) -> OverlayBackend:
    backend = OverlayBackend(data_dir / "cache" / "layers", "L1", [ws, sys_dir])
    backend.ensure_layer()
    return backend


@pytest.mark.asyncio
async def test_export_rejects_missing_or_bad_layer_id(tmp_path: Path) -> None:
    result = await layers_export.execute(_ctx(tmp_path, ""))
    assert result.status == "error"
    result = await layers_export.execute(_ctx(tmp_path, "../escape"))
    assert result.status == "error"
    result = await layers_apply.execute(_ctx(tmp_path, ""))
    assert result.status == "error"


@pytest.mark.asyncio
async def test_export_unknown_layer_is_error(tmp_path: Path) -> None:
    result = await layers_export.execute(_ctx(tmp_path, "nope"))
    assert result.status == "error"
    assert "nothing to export" in result.output_text or "No captured targets" in result.output_text


@pytest.mark.asyncio
async def test_export_writes_diffs_inventory_and_manifest(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    sys_dir = tmp_path / "sysroot"
    ws.mkdir()
    sys_dir.mkdir()
    (ws / "base.txt").write_text("original")
    (sys_dir / "app.conf").write_text("port=80")

    backend = _make_layer(tmp_path, ws, sys_dir)
    # Captured writes: edit one, add one, delete one (whiteout).
    (backend.upper_for(ws) / "base.txt").write_text("edited")
    (backend.upper_for(ws) / "added.txt").write_text("new")
    (backend.upper_for(sys_dir) / "app.conf").write_text("port=8080\n")

    result = await layers_export.execute(_ctx(tmp_path, "L1"))
    assert result.status == "success"
    export_dir = Path(result.output_json["export_dir"])
    assert export_dir.is_dir()
    # Diffs against the LIVE tree (manifest maps keys back to ws/sys_dir).
    inventory = json.loads((export_dir / "inventory.json").read_text())
    rel_paths = {e["path"] for e in inventory}
    assert "base.txt" in rel_paths
    assert "added.txt" in rel_paths
    assert "app.conf" in rel_paths
    # Manifest records both targets and their live paths.
    manifest = json.loads((export_dir / "manifest.json").read_text())
    assert len(manifest["targets"]) == _EXPECTED_TARGET_COUNT
    assert result.output_json["files"] >= _EXPECTED_FILE_COUNT


@pytest.mark.asyncio
async def test_apply_copies_captures_to_live_targets(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    sys_dir = tmp_path / "sysroot"
    ws.mkdir()
    sys_dir.mkdir()
    (ws / "base.txt").write_text("original")
    (sys_dir / "app.conf").write_text("port=80")

    backend = _make_layer(tmp_path, ws, sys_dir)
    (backend.upper_for(ws) / "base.txt").write_text("edited")
    (backend.upper_for(ws) / "added.txt").write_text("new")
    (backend.upper_for(sys_dir) / "app.conf").write_text("port=8080")

    result = await layers_apply.execute(_ctx(tmp_path, "L1"))
    assert result.status == "success"
    assert (ws / "base.txt").read_text() == "edited"
    assert (ws / "added.txt").read_text() == "new"
    assert (sys_dir / "app.conf").read_text() == "port=8080"


@pytest.mark.asyncio
async def test_apply_without_manifest_degrades_not_mangles(tmp_path: Path) -> None:
    """A layer with no manifest cannot be mapped to live paths: no blind writes."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "base.txt").write_text("original")
    backend = OverlayBackend(tmp_path / "cache" / "layers", "L1", ws)
    backend.ensure_layer()
    (backend.upper_for(ws) / "base.txt").write_text("edited")
    # Simulate a pre-manifest layer: drop the manifest.
    (backend.layer_path / "manifest.json").unlink()

    result = await layers_apply.execute(_ctx(tmp_path, "L1"))
    assert result.status == "degraded"
    # The live file is untouched when the live root cannot be resolved.
    assert (ws / "base.txt").read_text() == "original"


@pytest.mark.asyncio
async def test_export_apply_roundtrip_with_whiteout(tmp_path: Path) -> None:
    """A whiteout (deletion) exports as a deletion and applies as one."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "gone.txt").write_text("delete me")
    (ws / "keep.txt").write_text("keep me")

    backend = OverlayBackend(tmp_path / "cache" / "layers", "L1", ws)
    backend.ensure_layer()
    # Real whiteout: character device 0:0 marker.
    import subprocess as _sp

    whiteout = backend.upper_for(ws) / "gone.txt"
    _sp.run(
        ["mknod", str(whiteout), "c", "0", "0"],
        check=False,
        capture_output=True,
    )
    if not whiteout.exists():
        pytest.skip("mknod unavailable (unprivileged environment)")
    (backend.upper_for(ws) / "keep.txt").write_text("kept + edited")

    export = await layers_export.execute(_ctx(tmp_path, "L1"))
    assert export.status == "success"
    assert export.output_json["whiteouts"] == 1

    apply_result = await layers_apply.execute(_ctx(tmp_path, "L1"))
    assert apply_result.status == "success"
    assert not (ws / "gone.txt").exists()
    assert (ws / "keep.txt").read_text() == "kept + edited"
