"""Layer lifecycle tests (tmp dirs only, no subprocess)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lisa_packs.bwrap.backends.overlay import OverlayBackend
from lisa_packs.bwrap.backends.tmpfs import TmpfsBackend
from lisa_packs.bwrap.layers import (
    default_layer_id,
    layer_size_bytes,
    list_layers,
    sanitize_layer_id,
)


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws-target"
    ws.mkdir(exist_ok=True)
    return ws


def test_overlay_backend_creates_dirs(tmp_path: Path) -> None:
    backend = OverlayBackend(tmp_path / "layers", "session-abc", _workspace(tmp_path))
    backend.ensure_layer()
    layer = tmp_path / "layers" / "session-abc"
    assert (layer / "upper").is_dir()
    assert (layer / "work").is_dir()


def test_overlay_bind_args_scope_lowerdir_and_upper(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    backend = OverlayBackend(tmp_path / "layers", "L1", ws)
    args = backend.bind_args()
    joined = " ".join(args)
    # Scoped lowerdir is read-only; upper is writable; mountpoint IS the target.
    assert ["--ro-bind", str(ws), str(ws)] == args[0:3]
    assert str(backend.upper) in joined
    # workdir must never be exposed to the namespace.
    assert str(backend.work) not in joined
    # Never use --dir (cannot create parents under a read-only root).
    assert "--dir" not in args


def test_overlay_mount_mounts_on_top_of_bind_target(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    backend = OverlayBackend(tmp_path / "layers", "L1", ws)
    script = backend.overlay_mount_script(["echo", "hi"])[-1]
    assert f"lowerdir='{ws}'" in script
    assert f" overlay '{ws}' " in script + " "
    assert "lowerdir=/" not in script.replace(f"lowerdir='{ws}'", "")
    assert "userxattr" in script


def test_overlay_workdir_reset_before_mount(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    backend = OverlayBackend(tmp_path / "layers", "L1", ws)
    backend.ensure_layer()
    # Simulate a crashed run leaving stale workdir contents.
    stale = backend.work / "scratch.tmp"
    stale.write_text("x")
    backend.ensure_layer()
    assert backend.work.is_dir()
    assert not stale.exists()


def test_overlay_backend_rejects_empty_layer_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        OverlayBackend(tmp_path, "", tmp_path)


def test_tmpfs_backend_has_no_binds() -> None:
    assert TmpfsBackend().bind_args() == []


def test_sanitize_layer_id_accepts_safe_ids() -> None:
    assert sanitize_layer_id("session-abc_1.2") == "session-abc_1.2"


@pytest.mark.parametrize("bad", ["../x", "a/b", "a..b", "", "-lead", "x y"])
def test_sanitize_layer_id_rejects_unsafe(bad: str) -> None:
    with pytest.raises(ValueError):
        sanitize_layer_id(bad)


def test_default_layer_id_prefixes_session() -> None:
    assert default_layer_id("abc").startswith("session-")


def test_list_layers_empty_dir(tmp_path: Path) -> None:
    assert list_layers(tmp_path) == []


def test_list_layers_finds_overlay_layers(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    OverlayBackend(tmp_path / "layers", "one", ws).ensure_layer()
    OverlayBackend(tmp_path / "layers", "two", ws).ensure_layer()
    (tmp_path / "layers" / "not-a-layer").mkdir()  # no upper/, ignored
    layers = list_layers(tmp_path / "layers")
    assert {layer.layer_id for layer in layers} == {"one", "two"}


def test_layer_size_bytes_sums_upper(tmp_path: Path) -> None:
    backend = OverlayBackend(tmp_path / "layers", "sz", _workspace(tmp_path))
    backend.ensure_layer()
    (backend.upper / "a.txt").write_bytes(b"x" * 100)
    (backend.upper / "b.txt").write_bytes(b"y" * 50)
    assert layer_size_bytes(backend.layer_path) == 150
