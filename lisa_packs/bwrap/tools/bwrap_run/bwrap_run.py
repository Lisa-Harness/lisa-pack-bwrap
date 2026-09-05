"""Bubblewrap sandbox tool for Lisa.

Runs an argv inside a bubblewrap namespace with a read-only root FS. Overlayfs
layers are the default backend and are transparent to the model: mutations are
captured per session unless overlayfs is unavailable (then tmpfs, degradation
reported explicitly). The model never names overlayfs, layers, or mounts.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from kernel.models import ToolExecutionContext, ToolResult
from pydantic import BaseModel, Field

from lisa_packs.bwrap.argv_builder import build_bwrap_argv
from lisa_packs.bwrap.backends.overlay import OverlayBackend
from lisa_packs.bwrap.backends.tmpfs import TmpfsBackend
from lisa_packs.bwrap.layers import default_layer_id, sanitize_layer_id
from lisa_packs.bwrap.probe import detect_capabilities
from lisa_packs.bwrap.process import run_process

TOOL_ID = "bwrap_run"
_MAX_OUTPUT_BYTES = 512_000


class Parameters(BaseModel):
    """Structured input for bwrap_run."""

    argv: list[str] = Field(..., min_length=1, description="Command + args to run.")
    network: bool = Field(default=False, description="Allow network (default off).")
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    persist: bool = Field(
        default=False,
        description="Keep the overlay layer after this run (default: per-session).",
    )
    layer_id: str = Field(
        default="",
        description="Explicit overlay layer id (empty = transparent per-session layer).",
    )


async def execute(ctx: ToolExecutionContext) -> ToolResult:
    """Run argv inside a bubblewrap sandbox."""
    try:
        params = Parameters.model_validate(ctx.parameters)
    except Exception as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"Invalid parameters: {exc}")

    layers_dir = _resolve_layers_dir(ctx)
    probe_dir = layers_dir / ".probe"
    try:
        probe_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"Cannot prepare layers dir: {exc}")

    caps = detect_capabilities(probe_dir=probe_dir)
    if not caps.available:
        return ToolResult(
            tool_id=TOOL_ID,
            error=(
                "bubblewrap sandbox is not available: " + "; ".join(caps.missing)
            ),
            output_json={"sandboxed": False, "missing": list(caps.missing)},
        )

    session_key = _session_key(ctx)
    try:
        layer_id = (
            sanitize_layer_id(params.layer_id)
            if params.layer_id
            else default_layer_id(session_key)
        )
    except ValueError as exc:
        return ToolResult(tool_id=TOOL_ID, error=str(exc))

    degraded_overlay = not caps.can_overlay
    if degraded_overlay:
        backend = TmpfsBackend()
        child_argv = params.argv
        bind_args: list[str] = []
    else:
        overlay = OverlayBackend(layers_dir, layer_id)
        backend = overlay
        bind_args = overlay.bind_args()
        child_argv = overlay.overlay_mount_script(list(params.argv))

    try:
        argv = build_bwrap_argv(
            bwrap_path=caps.bwrap_path or "bwrap",
            network=params.network,
            child_argv=child_argv,
            backend_bind_args=bind_args,
        )
        result = await run_process(
            argv,
            timeout_seconds=params.timeout_seconds,
            max_output_bytes=_MAX_OUTPUT_BYTES,
            log_path=_session_log_path(ctx),
        )
    except Exception as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"bwrap_run failed: {exc}")

    persistence = "ephemeral" if not caps.can_overlay else ("persistent" if params.persist else "session")
    output_json = {
        "return_code": result.return_code,
        "stderr": result.stderr,
        "sandboxed": True,
        "backend": backend.name,
        "layer_id": layer_id,
        "persistence": persistence,
        "timed_out": result.timed_out,
        "truncated": result.output_truncated,
    }
    if degraded_overlay:
        output_json["degraded"] = True
        output_json["missing"] = list(caps.missing)
        output_json["note"] = (
            "overlayfs unavailable: mutations captured only in ephemeral tmpfs "
            "and discarded on exit. See sandboxing_degraded.md."
        )

    return ToolResult(
        tool_id=TOOL_ID,
        output_text=result.stdout or f"(no output; rc={result.return_code})",
        output_json=output_json,
    )


def _resolve_layers_dir(ctx: ToolExecutionContext) -> Path:
    """Resolve layer storage under the host-injected data dir."""
    base = Path(ctx.data_dir) if ctx.data_dir else Path.home() / ".lisa"
    return base / "layers"


def _session_key(ctx: ToolExecutionContext) -> str:
    """Stable, filesystem-safe key identifying the current conversation/session."""
    raw = "/".join(
        part
        for part in (ctx.workspace_id, ctx.user_slug, ctx.session_plan_digest, ctx.surface_id)
        if part
    ) or "default"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return digest


def _session_log_path(ctx: ToolExecutionContext) -> Path:
    """Per-session audit log the user can read (commands + output)."""
    base = Path(ctx.data_dir) if ctx.data_dir else Path.home() / ".lisa"
    return base / "logs" / f"bwrap-{_session_key(ctx)}.log"
