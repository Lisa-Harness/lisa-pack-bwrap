"""Export one overlayfs capture layer as a reviewable change set.

Renders, per capture target: a unified diff of the captured writes against the
live target tree, a file inventory (path, bytes, uid, gid, mode), and a
combined machine-readable manifest. Output lands in a caller-named directory
under ``<data_dir>/layers-exports/<layer_id>/`` so the user can review exactly
what a merge would do BEFORE ``layers_apply`` runs. Strictly read-only with
respect to the live filesystem and the layer itself.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kernel.models import OperationExecutionContext, OperationResult

from lisa_packs.bwrap.layers import captured_targets, sanitize_layer_id

OPERATION_ID = "layers_export"

#: Whiteouts: overlayfs marks deletions/renames with character-device
#: sentinel entries (0:0 char dev) named like the deleted file.
_WHITEOUT_MARKER = 0o20000  # S_IFCHR bit pattern in st_mode


@dataclass(slots=True)
class _InventoryEntry:
    rel_path: str
    size_bytes: int
    uid: int
    gid: int
    mode: str
    is_whiteout: bool


def _layers_dir(ctx: OperationExecutionContext) -> Path:
    base = Path(ctx.data_dir) if getattr(ctx, "data_dir", "") else Path.home() / ".lisa"
    from sdk.layout import CACHE_DIR  # noqa: PLC0415

    return base / CACHE_DIR / "layers"


def _is_whiteout(path: Path) -> bool:
    try:
        return (path.stat().st_mode & _WHITEOUT_MARKER) == _WHITEOUT_MARKER
    except OSError:
        return False


def _inventory(upper: Path) -> list[_InventoryEntry]:
    entries: list[_InventoryEntry] = []
    try:
        paths = sorted(upper.rglob("*"))
    except OSError:
        return entries
    for p in paths:
        try:
            st = p.stat()
        except OSError:
            continue
        rel = p.relative_to(upper).as_posix()
        if _is_whiteout(p):
            entries.append(
                _InventoryEntry(rel, 0, st.st_uid, st.st_gid, "whiteout", True)
            )
        elif p.is_file():
            entries.append(
                _InventoryEntry(
                    rel,
                    st.st_size,
                    st.st_uid,
                    st.st_gid,
                    oct(st.st_mode & 0o7777),
                    False,
                )
            )
        elif p.is_dir():
            entries.append(_InventoryEntry(rel + "/", 0, st.st_uid, st.st_gid, "dir", False))
    return entries


def _unified_diff(live_root: Path, upper: Path, rel_path: str) -> str:
    """A small, dependency-free unified diff for one file pair.

    Captured file vs the live target's same relative path; a missing live
    file renders as an addition (``--- /dev/null``), a whiteout as a deletion.
    Binary files are reported, not diffed.
    """
    captured = upper / rel_path
    live = live_root / rel_path
    try:
        captured_bytes = captured.read_bytes()
    except OSError:
        captured_bytes = b""
    live_exists = live.is_file()
    live_bytes = live.read_bytes() if live_exists else b""

    def _looks_binary(data: bytes) -> bool:
        return b"\x00" in data[:4096]

    header_a = f"live/{rel_path}" if live_exists else "/dev/null"
    header_b = f"capture/{rel_path}"
    if _is_whiteout(captured):
        return (
            f"--- {header_a}\n"
            f"+++ /dev/null\n"
            f"@@ deletion (overlayfs whiteout) of {rel_path} @@\n"
        )
    if _looks_binary(captured_bytes) or _looks_binary(live_bytes):
        return (
            f"--- {header_a}\n"
            f"+++ {header_b}\n"
            f"@@ binary file ({len(captured_bytes)} captured bytes"
            f"{'' if live_exists else ', new file'}) @@\n"
        )
    a_lines = live_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
    b_lines = captured_bytes.decode("utf-8", errors="replace").splitlines(keepends=True)
    if a_lines == b_lines:
        return f"--- {header_a}\n+++ {header_b}\n@@ identical content @@\n"
    # Minimal line diff (no Myers/histogram pretense): report changed regions
    # as paired removed/added runs, which is honest and reviewable for the
    # small config-file-sized captures this pack targets.
    import difflib

    diff = difflib.unified_diff(
        a_lines, b_lines, fromfile=header_a, tofile=header_b, lineterm=""
    )
    return "\n".join(diff) + "\n"


def _live_root_for_key(layer_path: Path, key: str) -> Path | None:
    """Reverse map a layer target key to the live capture target path.

    The key is the target path with separators replaced (``target_key``);
    the manifest stored at layer creation (``manifest.json``) is the source
    of truth when present, else the legacy single-target layout (workspace
    capture root) has no key and is handled by the caller.
    """
    manifest = _layer_manifest(layer_path)
    for entry in manifest.get("targets", []):
        if entry.get("key") == key:
            return Path(entry["path"])
    return None


def _layer_manifest(layer_path: Path) -> dict[str, Any]:
    """Read the layer's creation manifest if present (empty dict otherwise)."""
    try:
        return json.loads((layer_path / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


async def execute(ctx: OperationExecutionContext) -> OperationResult:
    """Export a layer as diffs + inventory + manifest into a review directory."""
    params = ctx.params or {}
    layer_id_raw = str(params.get("layer_id", "")).strip()
    if not layer_id_raw:
        return OperationResult(
            status="error",
            output_text="layers_export requires a layer_id parameter.",
        )
    try:
        layer_id = sanitize_layer_id(layer_id_raw)
    except ValueError as exc:
        return OperationResult(status="error", output_text=f"Invalid layer_id: {exc}")

    layers_dir = _layers_dir(ctx)
    layer_path = layers_dir / layer_id
    targets = captured_targets(layer_path)
    if not targets:
        return OperationResult(
            status="error",
            output_text=(
                f"No captured targets found for layer '{layer_id}' under "
                f"{layers_dir}; nothing to export."
            ),
        )

    base = Path(ctx.data_dir) if getattr(ctx, "data_dir", "") else Path.home() / ".lisa"
    from sdk.layout import RUN_DIR  # noqa: PLC0415

    export_root = base / RUN_DIR / "layers-exports" / layer_id
    try:
        export_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return OperationResult(
            status="error",
            output_text=f"Cannot create export directory {export_root}: {exc}",
        )

    manifest = _layer_manifest(layer_path)
    inventory: list[dict[str, Any]] = []
    for target in targets:
        upper = Path(target.upper_path)
        target_out = export_root / target.key
        target_out.mkdir(parents=True, exist_ok=True)
        live_root = _live_root_for_key(layer_path, target.key)
        entries = _inventory(upper)
        for entry in entries:
            inventory.append(
                {
                    "target_key": target.key,
                    "path": entry.rel_path,
                    "size_bytes": entry.size_bytes,
                    "uid": entry.uid,
                    "gid": entry.gid,
                    "mode": entry.mode,
                    "whiteout": entry.is_whiteout,
                }
            )
            if entry.is_whiteout or not entry.rel_path.endswith("/"):
                if live_root is not None and not entry.is_whiteout:
                    diff_text = _unified_diff(live_root, upper, entry.rel_path)
                elif entry.is_whiteout:
                    diff_text = _unified_diff(
                        live_root or Path("/nonexistent"), upper, entry.rel_path
                    )
                else:
                    diff_text = (
                        f"--- /dev/null\n+++ capture/{entry.rel_path}\n"
                        f"@@ new file ({entry.size_bytes} bytes); live target "
                        "unknown (no manifest) @@\n"
                    )
                diff_path = target_out / (entry.rel_path.replace("/", "__") + ".diff")
                try:
                    diff_path.parent.mkdir(parents=True, exist_ok=True)
                    diff_path.write_text(diff_text, encoding="utf-8")
                except OSError:
                    pass  # diff rendering must never fail the export
    try:
        (export_root / "inventory.json").write_text(
            json.dumps(inventory, indent=2), encoding="utf-8"
        )
        (export_root / "manifest.json").write_text(
            json.dumps(
                {
                    "layer_id": layer_id,
                    "targets": [
                        {
                            "key": t.key,
                            "upper_path": t.upper_path,
                            "size_bytes": t.size_bytes,
                        }
                        for t in targets
                    ],
                    "export_host_user": os.getuid(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        return OperationResult(
            status="degraded",
            output_text=f"Export wrote diffs but failed to write metadata: {exc}",
        )

    file_count = len(
        [
            e
            for e in inventory
            if not e["whiteout"] and not e["path"].endswith("/")
        ]
    )
    whiteouts = len([e for e in inventory if e["whiteout"]])
    return OperationResult(
        status="success",
        output_text=(
            f"Exported layer '{layer_id}': {file_count} captured file(s), "
            f"{whiteouts} deletion(s) across {len(targets)} target(s) to "
            f"{export_root}"
        ),
        output_json={
            "layer_id": layer_id,
            "export_dir": str(export_root),
            "targets": [
                {"key": t.key, "upper_path": t.upper_path, "size_bytes": t.size_bytes}
                for t in targets
            ],
            "files": file_count,
            "whiteouts": whiteouts,
            "inventory_path": str(export_root / "inventory.json"),
        },
    )