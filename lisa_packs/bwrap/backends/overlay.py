"""Overlayfs layer backend for bwrap - the opt-in mutation-capture backend.

overlayfs is NOT the default. It is used only when the caller explicitly wants
mutations captured (an explicit ``layer_id``, ``persist=True``, or a ``capture``
path posture); see ``bwrap_run`` for the tmpfs-default policy. When it IS used,
this backend is its correct, BCP-aligned implementation.

BCP invariants implemented here (see overlayfs(5) + kernel docs):

- ``lowerdir`` is a **scoped, stable, read-only subtree** (the sandbox bind
  target), never the whole live root ``/``. Overlaying ``/`` drags ``/proc``,
  ``/sys``, ``/dev`` and other pseudo-filesystems into the merge and produces
  semantically meaningless shadow writes.
- ``upperdir`` is the only writable layer; mutations land here, not the FS.
- ``workdir`` is kernel scratch space on the SAME filesystem as ``upperdir``.
  It is **never** bind-mounted into the namespace and is **emptied before every
  mount** (overlayfs requires an empty workdir).
- The overlay is mounted **on top of the capture target's own path** by a
  root-mapped ``unshare`` launcher BEFORE bwrap runs: the child sandbox then
  merely *binds* the already-merged view at its real path. This is the
  verified-unprivileged chain (see class docstring) - a child-side ``mount``
  cannot work because bwrap always drops all capabilities from the child
  (``CapEff=0``), so ``mount(2)`` is denied (EPERM) inside the sandbox.
- One overlay **per capture target** (workspace capture root plus any
  ``capture``-posture paths); each gets its own ``upper``/``work`` pair under
  the layer directory, all sharing one ``layer_id``.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

__all__ = ["OverlayBackend", "target_key"]


def target_key(target: Path) -> str:
    """Filesystem-safe, collision-free key for one capture target path.

    ``/etc`` -> ``_etc``; ``/etc/nginx/conf.d`` -> ``_etc_nginx_conf.d``. A
    leading separator becomes a leading underscore so the key is never empty
    and never path-like (no traversal possible: separators are replaced).
    """
    text = str(target)
    key = re.sub(r"[^A-Za-z0-9._-]", "_", text)
    return key or "_"


class OverlayBackend:
    """Manage one overlayfs layer that captures mutations on scoped subtrees.

    The mounts happen in the launcher process -- ``unshare --user
    --map-root-user --mount`` -- which holds ``CAP_SYS_ADMIN`` in its own user
    namespace (kernel-permitted, no real root needed), before exec'ing
    bwrap. bwrap then only *binds* the already-merged overlay views into the
    sandbox and drops every capability from the child, so the sandboxed
    process can use the overlay but can never mount, unmount, or reach the
    workdir. Verified chain (2026-09-18, bwrap 0.12.0, kernel 7.2):

    1. launcher: mount one overlay per target onto the target's own path;
    2. exec bwrap with ``--bind <target> <target>`` per target plus the
       normal isolation argv, ending ``--cap-drop ALL``;
    3. child writes through the merged view; they land in per-target
       ``upper/`` carrying the real invoking host user's ownership.
    """

    name = "overlay"

    def __init__(
        self,
        layers_dir: Path,
        layer_id: str,
        bind_targets: list[Path] | Path,
    ) -> None:
        if not layer_id:
            raise ValueError("OverlayBackend requires a non-empty layer_id")
        if isinstance(bind_targets, Path):
            bind_targets = [bind_targets]
        if not bind_targets:
            raise ValueError("OverlayBackend requires at least one capture target")
        self.layers_dir = layers_dir
        self.layer_id = layer_id
        # De-duplicate while preserving order (a capture path could coincide
        # with the workspace capture root).
        seen: set[str] = set()
        self.targets: list[Path] = []
        for target in bind_targets:
            key = str(target)
            if key not in seen:
                seen.add(key)
                self.targets.append(Path(target))

    @property
    def layer_path(self) -> Path:
        return self.layers_dir / self.layer_id

    def upper_for(self, target: Path) -> Path:
        """Writable upper dir capturing mutations to ``target``."""
        return self.layer_path / "targets" / target_key(target) / "upper"

    def work_for(self, target: Path) -> Path:
        """Kernel scratch for the overlay on ``target`` (never sandbox-visible)."""
        return self.layer_path / "targets" / target_key(target) / "work"

    @property
    def upper(self) -> Path:
        """Legacy single-target accessor: the capture root's upper dir."""
        return self.upper_for(self.targets[0])

    @property
    def work(self) -> Path:
        """Legacy single-target accessor: the capture root's work dir."""
        return self.work_for(self.targets[0])

    def ensure_layer(self) -> None:
        """Create the layer structure and reset every workdir on the host.

        Also (re)writes the layer's ``manifest.json`` recording each capture
        target's live path - the reverse map the export/apply operations use
        to find the live tree a target's upper dir belongs to. Write failures
        are swallowed: capture still works, only export metadata degrades.
        """
        import json

        for target in self.targets:
            self.upper_for(target).mkdir(parents=True, exist_ok=True)
            self._reset_workdir(target)
        try:
            manifest = {
                "layer_id": self.layer_id,
                "targets": [
                    {
                        "key": target_key(target),
                        "path": str(target),
                        "upper": str(self.upper_for(target)),
                    }
                    for target in self.targets
                ],
            }
            marker = self.layer_path / "manifest.json"
            tmp = marker.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            tmp.replace(marker)
        except OSError:
            pass  # metadata only; capture itself must never fail here

    def _reset_workdir(self, target: Path) -> None:
        """Ensure the target's workdir exists and is empty (mount precondition).

        overlayfs requires an empty workdir at mount time. A prior crashed run
        can leave stale entries; recreate the dir so the mount always succeeds.
        """
        work = self.work_for(target)
        if work.is_dir():
            shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, exist_ok=True)

    def bind_args(self) -> list[str]:
        """Bind each already-merged overlay view into the namespace, RW.

        The mounts themselves were performed by the launcher (see
        :meth:`mount_commands`); bwrap only re-binds each merged target at its
        own real path. ``upper``/``work`` are deliberately NOT bound - they
        must never be visible to (or writable by) the child.
        """
        self.ensure_layer()
        args: list[str] = []
        for target in self.targets:
            args += ["--bind", str(target), str(target)]
        return args

    def mount_commands(self) -> list[str]:
        """The launcher's overlay mounts, one per capture target.

        Each command is quoted for use inside the ``unshare`` shell script.
        The overlay goes on top of the target's own path, so the sandbox's
        ``--bind <target> <target>`` exposes the merged view exactly where the
        real path is expected.
        """
        self.ensure_layer()
        commands: list[str] = []
        for target in self.targets:
            options = (
                "userxattr,"
                f"lowerdir={_sh_quote(str(target))},"
                f"upperdir={_sh_quote(str(self.upper_for(target)))},"
                f"workdir={_sh_quote(str(self.work_for(target)))}"
            )
            commands.append(
                f"mount -t overlay -o {options} "
                f"overlay {_sh_quote(str(target))}"
            )
        return commands

    def launcher_argv(self, bwrap_argv: list[str]) -> list[str]:
        """Wrap ``bwrap_argv`` in the verified unprivileged pre-mount chain.

        ``unshare --user --map-root-user --mount`` creates a user namespace
        where the invoking user maps to uid 0 (keeping ``CAP_SYS_ADMIN`` in
        that namespace), plus a mount namespace to receive the overlay mounts.
        The inner shell mounts one overlay per target, then execs bwrap with
        the fully-formed isolation argv (which ends ``--cap-drop ALL``). The
        mounts only ever exist in the launcher's mount namespace copy and its
        bwrap child - the host's view is untouched.
        """
        inner = "\n".join(m + " || exit 1" for m in self.mount_commands())
        inner += "\nexec " + " ".join(_sh_quote(a) for a in bwrap_argv)
        return [
            "unshare", "--user", "--map-root-user", "--mount", "--",
            "/bin/sh", "-c", inner,
        ]


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
