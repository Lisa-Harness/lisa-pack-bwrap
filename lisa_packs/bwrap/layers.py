"""Layer lifecycle helpers for the bwrap pack.

v1 keeps this read-mostly: create layers implicitly, and list/inspect them for
user visibility. Mutating lifecycle operations (export/apply/teardown) live in
the operations layer (``operations/layers_export`` / ``operations/layers_apply``).

A layer holds one overlay per capture target: under
``<layer_path>/targets/<key>/`` sit that target's ``upper`` (captured writes)
and ``work`` (kernel scratch, empty between runs). The workspace capture root
is simply the first target; ``capture``-posture paths add more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "LayerInfo",
    "CapturedTarget",
    "captured_targets",
    "sanitize_layer_id",
    "default_layer_id",
    "list_layers",
    "layer_size_bytes",
]

_LAYER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def sanitize_layer_id(layer_id: str) -> str:
    """Validate a caller-supplied layer id, rejecting path traversal."""
    if not _LAYER_ID_PATTERN.match(layer_id) or ".." in layer_id:
        raise ValueError(
            f"Invalid layer_id {layer_id!r}: use letters, digits, '.', '_', '-' "
            "(no path separators or '..')."
        )
    return layer_id


def default_layer_id(session_key: str) -> str:
    """Derive the transparent per-session layer id from a stable session key."""
    safe = sanitize_layer_id(session_key) if session_key else "default"
    return f"session-{safe}"


@dataclass(frozen=True, slots=True)
class LayerInfo:
    """User-visible description of one overlayfs layer."""

    layer_id: str
    path: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class CapturedTarget:
    """One capture target's upper dir inside a layer."""

    key: str
    upper_path: str
    size_bytes: int


def _upper_dirs(layer_path: Path) -> list[Path]:
    """All target upper dirs under a layer, tolerating both layouts.

    Current layout: ``targets/<key>/upper`` (one per capture target). The
    legacy single-target layout (``<layer>/upper``) is still recognized so
    pre-existing layers keep listing.
    """
    dirs: list[Path] = []
    legacy = layer_path / "upper"
    if legacy.is_dir():
        dirs.append(legacy)
    targets_dir = layer_path / "targets"
    if targets_dir.is_dir():
        for keyed in sorted(targets_dir.iterdir()):
            upper = keyed / "upper"
            if keyed.is_dir() and upper.is_dir():
                dirs.append(upper)
    return dirs


def captured_targets(layer_path: Path) -> list[CapturedTarget]:
    """Enumerate a layer's capture targets (key + upper path + size)."""
    out: list[CapturedTarget] = []
    targets_dir = layer_path / "targets"
    if targets_dir.is_dir():
        for keyed in sorted(targets_dir.iterdir()):
            upper = keyed / "upper"
            if keyed.is_dir() and upper.is_dir():
                out.append(
                    CapturedTarget(
                        key=keyed.name,
                        upper_path=str(upper),
                        size_bytes=_dir_size(upper),
                    )
                )
    legacy = layer_path / "upper"
    if legacy.is_dir() and not out:
        out.append(
            CapturedTarget(key="_", upper_path=str(legacy), size_bytes=_dir_size(legacy))
        )
    return out


def _dir_size(upper: Path) -> int:
    total = 0
    try:
        for entry in upper.rglob("*"):
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                continue
    except OSError:
        return 0
    return total


def layer_size_bytes(layer_path: Path) -> int:
    """Recursively sum file sizes under every upper dir in the layer."""
    return sum(_dir_size(upper) for upper in _upper_dirs(layer_path))


def list_layers(layers_dir: Path) -> list[LayerInfo]:
    """Enumerate layers under the layers root, sorted ascending by layer id.

    A layer is any child directory containing at least one capture target's
    ``upper`` dir (current multi-target layout or the legacy single ``upper``).
    """
    if not layers_dir.is_dir():
        return []
    layers: list[LayerInfo] = []
    for child in sorted(layers_dir.iterdir()):
        if not child.is_dir() or not _upper_dirs(child):
            continue
        layers.append(
            LayerInfo(
                layer_id=child.name,
                path=str(child),
                size_bytes=layer_size_bytes(child),
            )
        )
    return layers
