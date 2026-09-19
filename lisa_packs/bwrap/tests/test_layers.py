"""Layer lifecycle tests (tmp dirs only, no subprocess)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lisa_packs.bwrap.backends.overlay import OverlayBackend, target_key
from lisa_packs.bwrap.backends.tmpfs import TmpfsBackend
from lisa_packs.bwrap.layers import (
    captured_targets,
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
    upper = layer / "targets" / target_key(_workspace(tmp_path)) / "upper"
    work = layer / "targets" / target_key(_workspace(tmp_path)) / "work"
    assert upper.is_dir()
    assert work.is_dir()


def test_overlay_backend_multi_target_dirs(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    sys_dir = tmp_path / "sysdir"
    sys_dir.mkdir()
    backend = OverlayBackend(tmp_path / "layers", "L1", [ws, sys_dir])
    backend.ensure_layer()
    for target in (ws, sys_dir):
        key = target_key(target)
        assert (backend.layer_path / "targets" / key / "upper").is_dir()
        assert (backend.layer_path / "targets" / key / "work").is_dir()


def test_overlay_backend_dedupes_targets(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    backend = OverlayBackend(tmp_path / "layers", "L1", [ws, ws, Path(ws)])
    assert backend.targets == [ws]


def test_overlay_backend_requires_a_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        OverlayBackend(tmp_path / "layers", "L1", [])


def test_overlay_bind_args_bind_merged_views_rw(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    backend = OverlayBackend(tmp_path / "layers", "L1", ws)
    args = backend.bind_args()
    joined = " ".join(args)
    # The merged view IS the target path, bound read-write by bwrap; the
    # mounts were done by the launcher beforehand.
    assert args == ["--bind", str(ws), str(ws)]
    # Neither upper nor work is ever exposed to the namespace.
    assert str(backend.upper) not in joined
    assert str(backend.work) not in joined
    # Never use --dir (cannot create parents under a read-only root).
    assert "--dir" not in args


def test_overlay_launcher_argv_pre_mounts_then_execs_bwrap(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    backend = OverlayBackend(tmp_path / "layers", "L1", ws)
    argv = backend.launcher_argv(["bwrap", "--ro-bind", "/", "/", "--", "true"])
    assert argv[0:5] == ["unshare", "--user", "--map-root-user", "--mount", "--"]
    script = argv[-1]
    # One mount per target, onto the target's own path, with the workdir
    # under the layer; then the bwrap exec.
    assert f"lowerdir='{ws}'" in script
    assert f" overlay '{ws}'" in script
    assert "userxattr" in script
    assert f"upperdir='{backend.upper}'" in script
    assert f"workdir='{backend.work}'" in script
    # Every argv token (flags included) is shell-quoted before the exec.
    assert "exec 'bwrap' '--ro-bind' '/' '/' '--' 'true'" in script


def test_overlay_mount_commands_per_target(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    sys_dir = tmp_path / "sysdir"
    sys_dir.mkdir()
    backend = OverlayBackend(tmp_path / "layers", "L1", [ws, sys_dir])
    commands = backend.mount_commands()
    assert len(commands) == 2
    assert f"overlay '{ws}'" in commands[0]
    assert f"overlay '{sys_dir}'" in commands[1]


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


def test_target_key_is_path_safe() -> None:
    assert target_key(Path("/etc")) == "_etc"
    assert target_key(Path("/etc/nginx/conf.d")) == "_etc_nginx_conf.d"
    assert "/" not in target_key(Path("/a/b"))


def test_list_layers_empty_dir(tmp_path: Path) -> None:
    assert list_layers(tmp_path) == []


def test_list_layers_finds_overlay_layers(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    OverlayBackend(tmp_path / "layers", "one", ws).ensure_layer()
    OverlayBackend(tmp_path / "layers", "two", ws).ensure_layer()
    (tmp_path / "layers" / "not-a-layer").mkdir()  # no upper/, ignored
    layers = list_layers(tmp_path / "layers")
    assert {layer.layer_id for layer in layers} == {"one", "two"}


def test_list_layers_tolerates_legacy_layout(tmp_path: Path) -> None:
    """Layers created before the multi-target layout still list."""
    legacy = tmp_path / "layers" / "old"
    (legacy / "upper").mkdir(parents=True)
    (legacy / "upper" / "f").write_bytes(b"x" * 10)
    layers = list_layers(tmp_path / "layers")
    assert [layer.layer_id for layer in layers] == ["old"]
    assert layers[0].size_bytes == 10


def test_captured_targets_enumerates_per_target(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    sys_dir = tmp_path / "sysdir"
    sys_dir.mkdir()
    backend = OverlayBackend(tmp_path / "layers", "L1", [ws, sys_dir])
    backend.ensure_layer()
    (backend.upper_for(ws) / "a").write_bytes(b"x" * 100)
    (backend.upper_for(sys_dir) / "b").write_bytes(b"y" * 50)
    targets = captured_targets(backend.layer_path)
    assert [t.key for t in targets] == sorted(
        [target_key(ws), target_key(sys_dir)]
    )
    sizes = {t.key: t.size_bytes for t in targets}
    assert sizes[target_key(ws)] == 100
    assert sizes[target_key(sys_dir)] == 50


def test_layer_size_bytes_sums_all_targets(tmp_path: Path) -> None:
    ws = _workspace(tmp_path)
    sys_dir = tmp_path / "sysdir"
    sys_dir.mkdir()
    backend = OverlayBackend(tmp_path / "layers", "sz", [ws, sys_dir])
    backend.ensure_layer()
    (backend.upper_for(ws) / "a.txt").write_bytes(b"x" * 100)
    (backend.upper_for(sys_dir) / "b.txt").write_bytes(b"y" * 50)
    assert layer_size_bytes(backend.layer_path) == 150
