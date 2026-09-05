"""Tmpfs-only backend - ephemeral, no persistent layer.

Mutations go to the ``/tmp`` tmpfs provisioned by the argv builder and are
discarded when the sandbox exits. Used when overlayfs is unavailable or the
caller wants a throwaway environment.
"""

from __future__ import annotations

__all__ = ["TmpfsBackend"]


class TmpfsBackend:
    """No overlayfs; discard mutations on exit."""

    name = "tmpfs"

    def bind_args(self) -> list[str]:
        return []

    def ensure_layer(self) -> None:
        return None
