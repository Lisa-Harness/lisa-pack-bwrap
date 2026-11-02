"""Pack-validation eval: the bwrap pack stays structurally healthy.

Runs under the framework's ``eval`` marker (deterministic, no model calls).
Validates the pack from source via ``packstest.catalog.validate_pack``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from packstest.catalog import validate_pack

PACK_PATH = Path(__file__).resolve().parents[4]  # .../lisa-packs/bwrap

EXPECTED_TOOLS = {"bwrap_run"}
EXPECTED_OPERATIONS = {"layers_apply", "layers_export", "layers_list"}


@pytest.mark.eval
def test_bwrap_pack_validates_from_source() -> None:
    """Entry points load, every tool YAML parses, modules import in-process."""

    report = validate_pack(PACK_PATH)
    assert report.ok, report.summary()


@pytest.mark.eval
def test_bwrap_pack_tool_catalog_complete() -> None:
    """Every expected tool is discovered with the bwrap provider id."""

    report = validate_pack(PACK_PATH)
    missing = EXPECTED_TOOLS - set(report.tools)
    unexpected = set(report.tools) - EXPECTED_TOOLS
    assert not missing, f"tools missing from catalog: {sorted(missing)}"
    assert not unexpected, f"unexpected catalog tools: {sorted(unexpected)}"
    for tool_id, tool_dict in sorted(report.tools.items()):
        assert tool_dict["tool_provider_id"] == "lisa-pack-bwrap", tool_id
        assert tool_dict["pack_id"] == "lisa-pack-bwrap", tool_id


@pytest.mark.eval
def test_bwrap_pack_entry_points_load() -> None:
    """All extension entry points resolve from source."""

    report = validate_pack(PACK_PATH)
    assert "lisa.extensions.content_roots" in report.entry_points
    assert "lisa.extensions.prerequisites" in report.entry_points
    assert "lisa.extensions.sandbox" in report.entry_points
    for group, entries in report.entry_points.items():
        for name, value in entries.items():
            assert value is not None, f"{group}:{name} failed to load"