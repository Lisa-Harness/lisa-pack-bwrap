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


def test_overlay_backend_creates_upper_and_work(tmp_path: Path) -> None:
    backend = OverlayBackend(tmp_path, "session-abc")
    backend.ensure_layer()
    assert (tmp_path / "session-abc" / "upper").is_dir()
    assert (tmp_path / "session-abc" / "work").is_dir()


def test_overlay_bind_args_reference_upper_and_work(tmp_path: Path) -> None:
    backend = OverlayBackend(tmp_path, "L1")
    args = backend.bind_args()
    joined = " ".join(args)
    assert str(backend.upper) in joined
    assert str(backend.work) in joined


def test_overlay_backend_rejects_empty_layer_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        OverlayBackend(tmp_path, "")


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
    OverlayBackend(tmp_path, "one").ensure_layer()
    OverlayBackend(tmp_path, "two").ensure_layer()
    (tmp_path / "not-a-layer").mkdir()  # no upper/, ignored
    layers = list_layers(tmp_path)
    assert {layer.layer_id for layer in layers} == {"one", "two"}


def test_layer_size_bytes_sums_upper(tmp_path: Path) -> None:
    backend = OverlayBackend(tmp_path, "sz")
    backend.ensure_layer()
    (backend.upper / "a.txt").write_bytes(b"x" * 100)
    (backend.upper / "b.txt").write_bytes(b"y" * 50)
    assert layer_size_bytes(backend.layer_path) == 150
