"""Overlayfs layer backend for bwrap - the default, transparent backend.

Layers live under ``<layers_dir>/<layer_id>/`` with an ``upper`` (captured
mutations) and ``work`` dir. The overlay is mounted *inside* the bwrap
namespace via a small child script using the ``userxattr`` mount option
(required for unprivileged overlay mounts on kernel >= 5.11).
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["OverlayBackend"]

# Mount point used inside the namespace for the merged overlay view.
_MERGED = "/run/overlay/merged"


class OverlayBackend:
    """Manages overlayfs layers so mutations land in an upper dir, not the FS."""

    name = "overlay"

    def __init__(self, layers_dir: Path, layer_id: str) -> None:
        if not layer_id:
            raise ValueError("OverlayBackend requires a non-empty layer_id")
        self.layers_dir = layers_dir
        self.layer_id = layer_id

    @property
    def layer_path(self) -> Path:
        return self.layers_dir / self.layer_id

    @property
    def upper(self) -> Path:
        return self.layer_path / "upper"

    @property
    def work(self) -> Path:
        return self.layer_path / "work"

    def ensure_layer(self) -> None:
        """Create the layer directory structure on the host."""
        self.upper.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)

    def bind_args(self) -> list[str]:
        """Bind the writable upper/work dirs into the namespace.

        The child script (see :func:`overlay_mount_script`) performs the
        ``mount -t overlay`` itself once the namespace exists.
        """
        self.ensure_layer()
        return [
            "--bind", str(self.upper), str(self.upper),
            "--bind", str(self.work), str(self.work),
            "--dir", _MERGED,
        ]

    def overlay_mount_script(self, inner_argv: list[str]) -> list[str]:
        """Return a /bin/sh command that mounts the overlay then execs the child."""
        quoted_inner = " ".join(_sh_quote(a) for a in inner_argv)
        mount = (
            "mount -t overlay -o userxattr,"
            f"lowerdir=/,upperdir={_sh_quote(str(self.upper))},"
            f"workdir={_sh_quote(str(self.work))} overlay {_MERGED} && "
            f"cd / && exec {quoted_inner}"
        )
        return ["/bin/sh", "-c", mount]


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
