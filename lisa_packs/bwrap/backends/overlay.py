"""Overlayfs layer backend for bwrap - the opt-in mutation-capture backend.

overlayfs is NOT the default. It is used only when the caller explicitly wants
mutations captured (an explicit ``layer_id`` or ``persist=True``); see
``bwrap_run`` for the tmpfs-default policy. When it IS used, this backend is
its correct, BCP-aligned implementation.

BCP invariants implemented here (see overlayfs(5) + kernel docs):

- ``lowerdir`` is a **scoped, stable, read-only subtree** (the sandbox bind
  target), never the whole live root ``/``. Overlaying ``/`` drags ``/proc``,
  ``/sys``, ``/dev`` and other pseudo-filesystems into the merge and produces
  semantically meaningless shadow writes.
- ``upperdir`` is the only writable layer; mutations land here, not the FS.
- ``workdir`` is kernel scratch space on the SAME filesystem as ``upperdir``.
  It is **never** bind-mounted into the namespace and is **emptied before every
  mount** (overlayfs requires an empty workdir).
- The overlay is mounted **on top of the scoped ``bind_target``** (which is
  first bound read-only). The mountpoint therefore already exists in the
  namespace (it is the bound-in workspace path), avoiding any ``--dir``/mkdir
  under a read-only root. No separate ``merged`` dir is bound in.
- Unprivileged mounts require the ``userxattr`` option (kernel >= 5.11).
"""

from __future__ import annotations

import shutil
from pathlib import Path

__all__ = ["OverlayBackend"]


class OverlayBackend:
    """Manages an overlayfs layer that captures mutations to a scoped subtree.

    The overlay is mounted *inside* the bwrap namespace by a small child
    script (bwrap creates the user+mount namespace first). Only the scoped
    ``bind_target`` is overlaid - the read-only root stays genuinely read-only
    elsewhere.
    """

    name = "overlay"

    def __init__(self, layers_dir: Path, layer_id: str, bind_target: Path) -> None:
        if not layer_id:
            raise ValueError("OverlayBackend requires a non-empty layer_id")
        self.layers_dir = layers_dir
        self.layer_id = layer_id
        self.bind_target = Path(bind_target)

    @property
    def layer_path(self) -> Path:
        return self.layers_dir / self.layer_id

    @property
    def upper(self) -> Path:
        return self.layer_path / "upper"

    @property
    def work(self) -> Path:
        return self.layer_path / "work"

    @property
    def merged(self) -> Path:
        # The overlay is mounted ON TOP of the scoped bind_target path inside
        # the namespace, so the child's writes to bind_target flow to upper.
        return self.bind_target

    def ensure_layer(self) -> None:
        """Create the layer structure and reset the workdir on the host."""
        self.upper.mkdir(parents=True, exist_ok=True)
        self._reset_workdir()

    def _reset_workdir(self) -> None:
        """Ensure workdir exists and is empty (overlayfs mount precondition).

        overlayfs requires an empty workdir at mount time. A prior crashed run
        can leave stale entries; recreate the dir so the mount always succeeds.
        """
        if self.work.is_dir():
            shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir(parents=True, exist_ok=True)

    def bind_args(self) -> list[str]:
        """Bind the scoped lowerdir (RO) and the writable upper into the namespace.

        ``workdir`` is deliberately NOT bound in - it is overlayfs-internal
        scratch space and must never be visible to (or writable by) the child.
        The child script mounts the overlay ON TOP of ``bind_target`` (which was
        first bound read-only), so writes to ``bind_target`` are captured in
        ``upper``. The ``merged`` dir is only a host-side anchor and is not
        bound in.
        """
        self.ensure_layer()
        return [
            # Scoped lowerdir, bound read-only at its own path. The child mount
            # overlays exactly this path so writes to it flow to upper.
            "--ro-bind", str(self.bind_target), str(self.bind_target),
            # Writable upper (capture) - bound at its host path.
            "--bind", str(self.upper), str(self.upper),
        ]

    def overlay_mount_script(self, inner_argv: list[str]) -> list[str]:
        """Return a /bin/sh program that mounts the overlay then execs the child.

        The overlay is mounted ON TOP of the scoped ``bind_target`` path (which
        was first bound read-only as the lowerdir). The child sees a read-write
        view at exactly ``bind_target``; every write is captured in ``upper``.
        """
        quoted_inner = " ".join(_sh_quote(a) for a in inner_argv)
        mount = (
            "mount -t overlay -o userxattr,"
            f"lowerdir={_sh_quote(str(self.bind_target))},"
            f"upperdir={_sh_quote(str(self.upper))},"
            f"workdir={_sh_quote(str(self.work))} "
            f"overlay {_sh_quote(str(self.bind_target))} && "
            f"exec {quoted_inner}"
        )
        return ["/bin/sh", "-c", mount]


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
