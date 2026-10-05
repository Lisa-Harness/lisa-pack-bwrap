"""Catalog discovery test for the bwrap pack."""

from __future__ import annotations

import json

from sdk.content._catalog import build_tool_catalog_json, resolve_tool_roots

from lisa_packs.bwrap import get_content_root


def test_bwrap_pack_bwrap_run_tool_discovered() -> None:
    roots = resolve_tool_roots([get_content_root()])
    assert roots, "No tools/ directory found in bwrap pack"

    catalog = json.loads(build_tool_catalog_json(roots))

    assert "bwrap_run" in catalog
    tool = catalog["bwrap_run"]
    assert tool["tool_id"] == "bwrap_run"
    assert tool["pack_id"] == "lisa-pack-bwrap"
    assert tool["effect"] == "execute"
    # bwrap_run is the sandbox backend for bash_run, which is the approval
    # boundary; bwrap_run itself is not approval-gated to avoid a double prompt.
    assert tool["approval_required"] is False
    assert tool["exportable"] is True
    assert tool["module_path"] == "lisa_packs.bwrap.tools.bwrap_run.bwrap_run"


def test_bwrap_run_declares_itself_self_bounding() -> None:
    """``bwrap_run`` must disable the kernel wrapper (``timeout_seconds: 0``).

    Regression (2026-10-05 shell turn): with no declared value the wrapper
    inherited the 30s default while ``bash_run`` asked for an extended 630s
    grace window; the wrapper cancelled the in-flight sandbox child at 30s
    and stranded the command. bwrap_run self-bounds: its own
    ``timeout_seconds`` parameter (1–3600s, subject to the floor's
    ``timeout_ceiling_seconds``) kills a silent child, and streaming output
    publishes progress while it runs. A wrapper lifetime bound cannot be
    sized to the values the parameter itself accepts, so the tool declares
    itself self-bounding instead.
    """
    catalog = json.loads(build_tool_catalog_json(resolve_tool_roots([get_content_root()])))
    tool = catalog["bwrap_run"]
    assert int(tool["timeout_seconds"]) == 0, (
        "bwrap_run must declare timeout_seconds: 0 (self-bounding); a "
        "positive wrapper bound below the parameter ceiling cancels an "
        "extended sandboxed call mid-flight"
    )
    assert tool["stream_output"] is True, (
        "bwrap_run must keep stream_output: true alongside "
        "timeout_seconds: 0 — the operator-visible progress is what makes "
        "the self-bounding declaration safe"
    )
