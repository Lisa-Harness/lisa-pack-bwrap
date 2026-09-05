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
