"""Apply one reviewed overlayfs capture layer to its live capture targets.

The merge step of the export -> review -> apply flow: every captured upper
dir is copied over its live target path (from the layer's manifest), whiteout
character-device markers become deletions, and recorded file modes are
restored. Ownership is deliberately NOT restored from the capture (the
captured uid/gid are the invoking host user's own, mapped through the user
namespace - writing them back explicitly would be a no-op at best and a
privilege confusion at worst); files simply land owned by the running user.

This operation is user-invoked (the host surfaces it after a
``layers_export`` review); it mutates the live filesystem by design.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from kernel.models import OperationExecutionContext, OperationResult

from lisa_packs.bwrap.layers import captured_targets, sanitize_layer_id

OPERATION_ID = "layers_apply"

_WHITEOUT_MARKER = 0o20000  # S_IFCHR bit pattern in st_mode


def _layers_dir(ctx: OperationExecutionContext) -> Path:
    base = Path(ctx.data_dir) if getattr(ctx, "data_dir", "") else Path.home() / ".lisa"
    from sdk.layout import CACHE_DIR  # noqa: PLC0415

    return base / CACHE_DIR / "layers"


def _is_whiteout(path: Path) -> bool:
    try:
        return (path.stat().st_mode & _WHITEOUT_MARKER) == _WHITEOUT_MARKER
    except OSError:
        return False


def _layer_manifest(layer_path: Path) -> dict[str, Any]:
    try:
        return json.loads((layer_path / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _apply_target(upper: Path, live_root: Path) -> dict[str, int]:
    """Merge one target's upper dir into its live root; returns counts."""
    copied = 0
    deleted = 0
    dirs = 0
    try:
        paths = sorted(upper.rglob("*"))
    except OSError:
        return {"copied": 0, "deleted": 0, "dirs": 0, "errors": 1}
    errors = 0
    for item in paths:
        rel = item.relative_to(upper)
        dest = live_root / rel
        if _is_whiteout(item):
            # The capture deleted (or renamed-away) this path.
            try:
                if dest.is_dir() and not dest.is_symlink():
                    shutil.rmtree(dest)
                else:
                    dest.unlink(missing_ok=True)
                deleted += 1
            except OSError:
                errors += 1
        elif item.is_dir():
            try:
                dest.mkdir(parents=True, exist_ok=True)
                dirs += 1
            except OSError:
                errors += 1
        elif item.is_file():
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, dest)  # copy2 preserves mtime + mode
                copied += 1
            except OSError:
                errors += 1
    return {"copied": copied, "deleted": deleted, "dirs": dirs, "errors": errors}


async def execute(ctx: OperationExecutionContext) -> OperationResult:
    """Apply the layer's captured writes to the live targets (user-invoked)."""
    params = ctx.params or {}
    layer_id_raw = str(params.get("layer_id", "")).strip()
    if not layer_id_raw:
        return OperationResult(
            status="error",
            output_text="layers_apply requires a layer_id parameter.",
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
                f"{layers_dir}; nothing to apply."
            ),
        )
    manifest = _layer_manifest(layer_path)
    live_by_key: dict[str, Path] = {
        entry["key"]: Path(entry["path"])
        for entry in manifest.get("targets", [])
        if isinstance(entry, dict) and entry.get("key") and entry.get("path")
    }

    summary: list[dict[str, Any]] = []
    total_errors = 0
    for target in targets:
        upper = Path(target.upper_path)
        live_root = live_by_key.get(target.key)
        if live_root is None or not live_root.is_dir():
            summary.append(
                {
                    "target_key": target.key,
                    "applied": False,
                    "reason": (
                        "live target path unknown (no manifest.json entry) "
                        "or no longer exists; re-export to refresh metadata"
                    ),
                }
            )
            total_errors += 1
            continue
        counts = _apply_target(upper, live_root)
        counts["target_key"] = target.key
        counts["live_root"] = str(live_root)
        counts["applied"] = counts.get("errors", 0) == 0
        total_errors += counts.get("errors", 0)
        summary.append(counts)

    status = "success" if total_errors == 0 else "degraded"
    parts: list[str] = []
    for s in summary:
        if s.get("applied"):
            parts.append(
                f"{s.get('target_key')}: {s.get('copied', 0)} file(s) copied, "
                f"{s.get('deleted', 0)} deleted"
            )
        else:
            parts.append(
                f"{s.get('target_key')}: NOT applied ({s.get('reason')})"
            )
    text = f"Applied layer '{layer_id}': " + "; ".join(parts)
    return OperationResult(
        status=status,
        output_text=text,
        output_json={
            "layer_id": layer_id,
            "targets": summary,
            "errors": total_errors,
        },
    )