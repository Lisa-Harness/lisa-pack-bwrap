"""Bubblewrap sandbox tool for Lisa.

Runs an argv inside a bubblewrap namespace whose containment is decided by the
harness FLOOR, not the model. The floor is read from ``ctx.pack_config['sandbox']
['floor']`` (harness-owned session configuration - model ``parameters`` cannot
forge it); the model passes tightening ``overrides`` and may only raise
integrity above the floor. The DEFAULT backend is tmpfs (persistence
``ephemeral``): mutations go to an ephemeral layer and are discarded when the
namespace exits. overlayfs is an OPT-IN capture backend (persistence
``overlay``) that runs only when the effective persistence is overlay and
unprivileged overlayfs is available; otherwise the request degrades to
ephemeral explicitly (never silently). The model never names overlayfs,
layers, or mounts - only the persistence posture.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kernel.models import ToolExecutionContext, ToolResult
from kernel.tools.output_stream import publish_tool_output
from pydantic import BaseModel, Field

from lisa_packs.bwrap.argv_builder import build_bwrap_argv_for_profile
from lisa_packs.bwrap.backends.overlay import OverlayBackend
from lisa_packs.bwrap.backends.tmpfs import TmpfsBackend
from lisa_packs.bwrap.layers import default_layer_id, sanitize_layer_id
from lisa_packs.bwrap.policy import (
    PolicyError,
    SandboxProfile,
    floor_from_config,
    resolve_effective,
)
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


def _identity_block() -> dict[str, Any]:
    """Describe the uid/gid mapping the unprivileged sandbox imposes.

    Unprivileged bwrap can only install a single-entry user-namespace uid map
    (the invoking host user -> sandbox uid 0). ``stat(2)`` inside the sandbox
    can therefore only resolve owners inside the map: files owned by any other
    host uid render as the overflow uid 65534 (``nobody:nobody``). This is a
    display artifact, not a permissions change — we stamp it on every
    sandboxed result so the model never misreads ``ls -l`` owner columns.
    """
    host_uid = os.getuid()
    host_gid = os.getgid()
    host_user = ""
    try:  # pragma: no cover - pwd is POSIX-only; guarded for portability
        import pwd

        try:
            host_user = pwd.getpwuid(host_uid).pw_name
        except KeyError:
            host_user = ""
    except ImportError:
        host_user = ""
    map_text = (
        f"{host_user or 'host user'}({host_uid}) -> sandbox root(0) "
        "(single-entry uid map)"
    )
    return {
        "sandbox_uid": 0,
        "sandbox_gid": 0,
        "host_uid": host_uid,
        "host_gid": host_gid,
        "host_user": host_user,
        "map": map_text,
        "note": (
            "You run as mapped root via a single-entry uid map. Files owned by "
            "any host uid other than yours display as nobody:nobody (uid "
            "65534) - an overflow-uid display artifact of the user namespace. "
            "Your own files display as root:root inside the sandbox. On-disk "
            "ownership is unchanged; overlay-captured files are owned by the "
            "real host user outside the sandbox. Do NOT chown/chmod to 'fix' "
            "owners inside the sandbox. See sandbox_ownership.md."
        ),
    }


class Parameters(BaseModel):
    """Structured input for bwrap_run.

    Every field is a tightening request - the model asks for a posture; the
    harness floor decides what it is allowed to have. Asking for anything
    looser than the floor is rejected with a policy error.
    """

    argv: list[str] = Field(..., min_length=1, description="Command + args to run.")
    timeout_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
        description="Timeout for the command (subject to the floor ceiling).",
    )
    cwd: str = Field(
        default="",
        description=(
            "Working directory inside the sandbox. Empty inherits the default. "
            "It must resolve under a writable path (capture root, scratch, or a "
            "writable path override)."
        ),
    )
    overrides: dict = Field(
        default_factory=dict,
        description=(
            "Tightening overrides keyed by axis: persistence "
            "(direct-write|overlay|ephemeral|readonly), network (allow|deny), "
            "paths (map of path -> rw|ro|hidden). Overrides can only raise "
            "integrity above the harness floor, never loosen it."
        ),
    )
    persist: bool = Field(
        default=False,
        description=(
            "Retain the captured layer after the session (persistence overlay "
            "only). Mutations are captured either way; persist only controls "
            "whether the layer survives the session."
        ),
    )
    layer_id: str = Field(
        default="",
        description=(
            "Explicit overlay layer id (selects persistence 'overlay'). Empty = "
            "no overlay capture unless persistence overlay is requested."
        ),
    )

    @property
    def validated_writable_paths(self) -> list[Path]:
        """Writable paths from ``overrides['paths']`` marked ``rw``, resolved.

        Only absolute real directories marked ``rw`` are returned; everything
        else is dropped so traversal or a nonexistent path cannot weaken the
        sandbox or abort the run. Symlinks resolve to their target.
        """
        out: list[Path] = []
        raw = self.overrides.get("paths") if isinstance(self.overrides, Mapping) else None
        if not isinstance(raw, dict):
            return out
        for raw_path, access in raw.items():
            if access != "rw":
                continue
            try:
                candidate = Path(str(raw_path)).expanduser().resolve()
            except OSError:
                continue
            if candidate.is_dir():
                out.append(candidate)
        return out


def _request_profile(params: Parameters) -> SandboxProfile:
    """Build the request-side profile from the model's tightening overrides."""
    raw = params.overrides if isinstance(params.overrides, Mapping) else {}
    paths: dict[str, str] = {}
    raw_paths = raw.get("paths")
    if isinstance(raw_paths, Mapping):
        for raw_path, access in raw_paths.items():
            if isinstance(access, str) and access in ("rw", "ro", "hidden"):
                paths[str(Path(str(raw_path)).expanduser())] = access
    return SandboxProfile(
        network=raw.get("network") if raw.get("network") in ("allow", "deny") else None,
        persistence=(
            raw.get("persistence")
            if raw.get("persistence") in ("direct-write", "overlay", "ephemeral", "readonly")
            else None
        ),
        paths=paths,
    )


async def execute(ctx: ToolExecutionContext) -> ToolResult:
    """Run argv inside a bubblewrap sandbox shaped by the harness floor."""
    try:
        params = Parameters.model_validate(ctx.parameters)
    except Exception as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"Invalid parameters: {exc}")

    try:
        floor = floor_from_config(ctx.pack_config)
        request = _request_profile(params)
        # A requested layer_id / persist implies the overlay persistence posture.
        if (params.layer_id or params.persist) and request.persistence is None:
            request = SandboxProfile(
                network=request.network,
                persistence="overlay",
                paths=request.paths,
            )
        eff = resolve_effective(floor, request)
    except PolicyError as exc:
        return ToolResult(tool_id=TOOL_ID, error=str(exc))
    except Exception as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"Invalid sandbox policy: {exc}")

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

    # Overlayfs is opt-in: only build a layer when the effective persistence is
    # the overlay posture. Otherwise mutations go to ephemeral tmpfs and are
    # discarded - the default.
    wants_overlay = eff.persistence == "overlay"
    use_overlay = wants_overlay and caps.can_overlay
    overlay_requested_but_unavailable = wants_overlay and not caps.can_overlay

    try:
        layer_id = (
            sanitize_layer_id(params.layer_id)
            if params.layer_id
            else default_layer_id(session_key)
        )
    except ValueError as exc:
        return ToolResult(tool_id=TOOL_ID, error=str(exc))

    capture_root = _resolve_workspace_root(ctx)
    scratch_dir = _make_scratch_dir(ctx, session_key)

    # A caller-set cwd must exist inside the namespace: within the capture
    # root, under scratch, or one of the extra writable binds.
    cwd: Path | None = None
    if params.cwd:
        try:
            resolved_cwd = Path(params.cwd).expanduser().resolve()
        except OSError:
            resolved_cwd = None  # type: ignore[assignment]
        if resolved_cwd is not None and (
            _is_within(resolved_cwd, capture_root)
            or _is_within(resolved_cwd, scratch_dir)
            or any(_is_within(resolved_cwd, extra) for extra in params.validated_writable_paths)
        ):
            cwd = resolved_cwd

    if use_overlay:
        overlay = OverlayBackend(layers_dir, layer_id, bind_target=capture_root)
        backend = overlay
        bind_args: list[str] = overlay.bind_args()
        child_argv = overlay.overlay_mount_script(list(params.argv))
    else:
        backend = TmpfsBackend()
        # Give the model a WRITABLE, host-visible scratch area in tmpfs mode
        # (persistence ephemeral): bind the real workspace read-only at its
        # own path so the command can analyze it, plus a scratch dir it can
        # stage a file copy in and test-apply a patch against. persistence
        # 'readonly' binds NO writable paths at all.
        if eff.persistence == "readonly":
            bind_args = ["--ro-bind", str(capture_root), str(capture_root)]
        else:
            bind_args = [
                "--ro-bind", str(capture_root), str(capture_root),
                "--bind", str(scratch_dir), str(scratch_dir),
            ]
        child_argv = list(params.argv)

    if cwd is not None:
        child_argv = [
            "/bin/sh", "-c",
            f"cd {_sh_quote(str(cwd))} && exec \"$@\"",
            "_", *child_argv,
        ]

    try:
        argv = build_bwrap_argv_for_profile(
            bwrap_path=caps.bwrap_path or "bwrap",
            profile=eff,
            child_argv=child_argv,
            backend_bind_args=bind_args,
        )
        result = await run_process(
            argv,
            timeout_seconds=params.timeout_seconds,
            max_output_bytes=_MAX_OUTPUT_BYTES,
            log_path=_session_log_path(ctx),
            on_output=_tool_output_tap(ctx) if getattr(ctx, "stream_output", False) else None,
        )
    except Exception as exc:
        return ToolResult(tool_id=TOOL_ID, error=f"bwrap_run failed: {exc}")

    if use_overlay:
        # Overlay actually ran: persist controls whether the layer is retained.
        persistence = "persistent" if params.persist else "overlay"
    elif wants_overlay:
        # Overlay was requested but this host can't do it: we degraded to tmpfs,
        # so report the REAL (ephemeral) persistence, not the requested one.
        persistence = "ephemeral"
    else:
        persistence = eff.persistence or "ephemeral"

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
        "cwd": str(cwd) if cwd is not None else "",
        "writable_paths": [str(p) for p in params.validated_writable_paths],
        "identity": _identity_block(),
    }
    if use_overlay:
        output_json["layer_id"] = layer_id
    if overlay_requested_but_unavailable:
        output_json["degraded"] = True
        output_json["missing"] = list(caps.missing)
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
    from session pack configuration — via the shared
    ``sdk.workspace.resolve_workspace_root`` (lenient mode), the same single
    rule the coding pack uses (strict there) and the host command uses. A
    sandbox with no configured workspace is a degraded-but-runnable condition,
    so the lenient policy falls back across CWD then ``data_dir`` then home.
    """
    from sdk.workspace import resolve_workspace_root

    return resolve_workspace_root(ctx, require_git=False)


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


def _tool_output_tap(ctx: ToolExecutionContext) -> Any:
    """Build the incremental ``on_output(stream, line)`` callback.

    Forwards each completed line to the operator surface via the turn's
    ``lisa.tool_output`` bus topic. Only constructed when the caller (bash
    composing through this tool, or the model calling bwrap_run directly when
    its ``.tool.yml`` declares ``stream_output``) set ``ctx.stream_output``.
    Publishing is best-effort: failures never break the sandboxed call.
    """

    def _on_output(stream: str, line: str) -> None:
        if line:
            publish_tool_output(ctx, text=line, stream=stream)

    return _on_output


def _is_within(path: Path, parent: Path) -> bool:
    """Return whether ``path`` resolves under ``parent`` (or equals it)."""
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _sh_quote(value: str) -> str:
    """POSIX single-quote a fragment for the /bin/sh cwd wrapper."""
    return "'" + value.replace("'", "'\\''") + "'"
