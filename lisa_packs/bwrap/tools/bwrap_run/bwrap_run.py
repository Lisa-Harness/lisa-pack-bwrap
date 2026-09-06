"""Bubblewrap sandbox tool for Lisa.

Runs an argv inside a bubblewrap namespace with a read-only root FS. The
DEFAULT backend is tmpfs: mutations go to an ephemeral tmpfs and are discarded
when the namespace exits. overlayfs is an OPT-IN capture backend - it runs only
when the caller explicitly asks to capture persistence (via ``persist=True`` or
an explicit ``layer_id``) AND unprivileged overlayfs is available; otherwise the
request degrades to tmpfs explicitly (never silently). The model never names
overlayfs, layers, or mounts.
"""

from __future__ import annotations

import hashlib
import tempfile
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

_REMEDIATION_HINT = (
    "Install the host package (openSUSE: 'zypper install bubblewrap', "
    "Fedora/RHEL: 'dnf install bubblewrap', Debian/Ubuntu: 'apt install "
    "bubblewrap', Arch: 'pacman -S bubblewrap') and ensure unprivileged user "
    "namespaces are enabled. See sandboxing_degraded.md."
)


class Parameters(BaseModel):
    """Structured input for bwrap_run."""

    argv: list[str] = Field(..., min_length=1, description="Command + args to run.")
    network: bool = Field(default=False, description="Allow network (default off).")
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    persist: bool = Field(
        default=False,
        description=(
            "Opt in to capturing mutations to the workspace in an overlayfs "
            "layer kept after this run. Default off: writes go to an ephemeral "
            "tmpfs scratch dir and are discarded. Requires unprivileged "
            "overlayfs on the host."
        ),
    )
    layer_id: str = Field(
        default="",
        description=(
            "Explicit overlay layer id (opt in to overlayfs capture). Empty = "
            "no capture; ephemeral scratch unless persist=True."
        ),
    )


async def execute(ctx: ToolExecutionContext) -> ToolResult:
    """Run argv inside a bubblewrap sandbox (tmpfs by default; overlay opt-in)."""
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
            output_json={
                "sandboxed": False,
                "missing": list(caps.missing),
                "note": _REMEDIATION_HINT,
            },
        )

    session_key = _session_key(ctx)

    # Overlayfs is opt-in: only build a layer when the caller explicitly asked
    # to capture mutations (persist=True or an explicit layer_id). Otherwise
    # mutations go to ephemeral tmpfs and are discarded - the default.
    wants_overlay = bool(params.layer_id) or params.persist

    try:
        layer_id = (
            sanitize_layer_id(params.layer_id)
            if params.layer_id
            else default_layer_id(session_key)
        )
    except ValueError as exc:
        return ToolResult(tool_id=TOOL_ID, error=str(exc))

    overlay_requested_but_unavailable = wants_overlay and not caps.can_overlay
    use_overlay = wants_overlay and caps.can_overlay

    capture_root = _resolve_workspace_root(ctx)
    scratch_dir = _make_scratch_dir(ctx, session_key)
    if use_overlay:
        overlay = OverlayBackend(layers_dir, layer_id, bind_target=capture_root)
        backend = overlay
        bind_args: list[str] = overlay.bind_args()
        child_argv = overlay.overlay_mount_script(list(params.argv))
    else:
        backend = TmpfsBackend()
        # Give the model a WRITABLE, host-visible scratch area even in tmpfs
        # mode: bind the real workspace read-only at its own path so the command
        # can analyze it, plus an ephemeral (or per-session) scratch dir it can
        # build a file copy in and test-apply a patch against. Everything under
        # scratch is discarded unless the caller persisted it via a layer.
        bind_args = [
            "--ro-bind", str(capture_root), str(capture_root),
            "--bind", str(scratch_dir), str(scratch_dir),
        ]
        child_argv = params.argv

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

    if use_overlay:
        persistence = "persistent" if params.persist else "session"
    else:
        persistence = "ephemeral"

    output_json = {
        "return_code": result.return_code,
        "stderr": result.stderr,
        "sandboxed": True,
        "backend": backend.name,
        "persistence": persistence,
        "timed_out": result.timed_out,
        "truncated": result.output_truncated,
        "capture_root": str(capture_root),
        "scratch_dir": str(scratch_dir),
    }
    if use_overlay:
        output_json["layer_id"] = layer_id
    if overlay_requested_but_unavailable:
        output_json["degraded"] = True
        output_json["missing"] = list(caps.missing)
        # ``overlay_reason`` is new; tolerate capability objects without it.
        reason = getattr(caps, "overlay_reason", "") or "; ".join(caps.missing)
        if not reason.endswith("."):
            reason += "."
        output_json["note"] = (
            "overlayfs capture was requested but is unavailable on this host: "
            f"{reason} Mutations went to ephemeral tmpfs and were discarded "
            "on exit. See sandboxing_degraded.md."
            + ("" if "bwrap drops all capabilities" in reason else f" {_REMEDIATION_HINT}")
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


def _resolve_workspace_root(ctx: ToolExecutionContext) -> Path:
    """Resolve the workspace root to capture/read from pack configuration.

    This is the fix for the overlay-capture scope bug: the pack previously
    captured ``ctx.data_dir`` (~/.lisa) instead of the user's workspace, so a
    ``persist`` run staged changes to a metadata dir while the model believed
    it had merged workspace edits. The workspace path is NOT carried on
    ``ToolExecutionContext`` (only the ``workspace_id`` slug), so it is read
    from session pack configuration — the same channel the coding pack uses —
    falling back to the process CWD and finally ``data_dir``.
    """
    raw = ""
    cfg = getattr(ctx, "pack_config", None)
    if isinstance(cfg, dict):
        raw = str(cfg.get("workspace_root", "") or "")
    else:  # tolerate a typed config object exposing the same attribute
        raw = str(getattr(cfg, "workspace_root", "") or "")
    if raw:
        candidate = Path(raw).expanduser()
        root = (candidate if candidate.is_absolute() else Path.cwd() / candidate).resolve()
        if root.is_dir():
            return root
    # No configured workspace: the process CWD is the host's working project.
    cwd = Path.cwd()
    if cwd.is_dir():
        return cwd
    return Path(ctx.data_dir) if ctx.data_dir else Path.home()


def _make_scratch_dir(ctx: ToolExecutionContext, session_key: str) -> Path:
    """A writable, host-visible scratch dir bound into the sandbox.

    Host-visible so the user can inspect patch/script artifacts the model
    staged; per-session so it survives across calls within a conversation when
    a data_dir is available (else an ephemeral temp dir per call).
    """
    if ctx.data_dir:
        scratch = Path(ctx.data_dir) / "scratch" / session_key
        try:
            scratch.mkdir(parents=True, exist_ok=True)
        except OSError:
            return Path(tempfile.mkdtemp(prefix="lisa-scratch-"))
        return scratch
    return Path(tempfile.mkdtemp(prefix="lisa-scratch-"))


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
