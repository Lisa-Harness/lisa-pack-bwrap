"""Pure bwrap argv construction tests - no subprocess."""

from __future__ import annotations

from typing import Any

import pytest

from lisa_packs.bwrap.argv_builder import build_bwrap_argv


def _build(**kwargs: Any) -> list[str]:
    """Build a bwrap argv with the default skeleton plus any overrides."""
    base: dict[str, Any] = {"network": False, "child_argv": ["echo", "hi"]}
    base.update(kwargs)
    return build_bwrap_argv(**base)


def test_argv_starts_with_bwrap_and_child_after_separator() -> None:
    argv = _build()
    assert argv[0] == "bwrap"
    sep = argv.index("--")
    assert argv[sep + 1 :] == ["echo", "hi"]


def test_network_disabled_unshares_net() -> None:
    argv = _build(network=False)
    assert "--unshare-net" in argv
    assert "--unshare-pid" in argv
    assert "--unshare-uts" in argv


def test_network_enabled_keeps_net() -> None:
    argv = _build(network=True)
    assert "--unshare-net" not in argv
    # Other namespaces still isolated.
    assert "--unshare-pid" in argv


def test_read_only_root_and_lifecycle_flags() -> None:
    argv = _build()
    assert argv[argv.index("--ro-bind") : argv.index("--ro-bind") + 3] == ["--ro-bind", "/", "/"]
    assert "--die-with-parent" in argv
    assert "--new-session" in argv
    # tmpfs /tmp present
    tmpfs_idx = argv.index("--tmpfs")
    assert argv[tmpfs_idx + 1] == "/tmp"


def test_custom_bwrap_path_used() -> None:
    argv = _build(bwrap_path="/usr/bin/bwrap")
    assert argv[0] == "/usr/bin/bwrap"


def test_backend_bind_args_inserted_before_separator() -> None:
    argv = _build(backend_bind_args=["--bind", "/u", "/u"])
    sep = argv.index("--")
    bind_idx = argv.index("--bind")
    assert bind_idx < sep
    assert argv[bind_idx + 1] == "/u"


def test_empty_child_argv_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _build(child_argv=[])
