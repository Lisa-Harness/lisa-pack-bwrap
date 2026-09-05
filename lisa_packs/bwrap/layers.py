"""Layer lifecycle helpers for the bwrap pack.

v1 keeps this read-mostly: create layers implicitly, and list/inspect them for
user visibility. Mutating lifecycle operations (export/teardown/diff) are
deliberately deferred to v2 operations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

__all__ = ["LayerInfo", "sanitize_layer_id", "default_layer_id", "list_layers", "layer_size_bytes"]

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


def layer_size_bytes(layer_path: Path) -> int:
    """Recursively sum file sizes under a layer's upper dir."""
    total = 0
    upper = layer_path / "upper"
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


def list_layers(layers_dir: Path) -> list[LayerInfo]:
    """Enumerate layers under the layers root, sorted ascending by layer id."""
    if not layers_dir.is_dir():
        return []
    layers: list[LayerInfo] = []
    for child in sorted(layers_dir.iterdir()):
        if not child.is_dir() or not (child / "upper").is_dir():
            continue
        layers.append(
            LayerInfo(
                layer_id=child.name,
                path=str(child),
                size_bytes=layer_size_bytes(child),
            )
        )
    return layers
