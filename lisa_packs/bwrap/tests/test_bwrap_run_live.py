"""Live, opt-in integration tests for bwrap_run.

Marked ``live``; requires bubblewrap installed and unprivileged userns.
Skipped automatically when bwrap is not available.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from kernel.models import ToolExecutionContext

from lisa_packs.bwrap.tools.bwrap_run import bwrap_run

pytestmark = pytest.mark.live


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed")
@pytest.mark.asyncio
async def test_bwrap_run_echo_roundtrip(tmp_path: Path) -> None:
    ctx = ToolExecutionContext(
        tool_id="bwrap_run",
        workspace_id="ws",
        parameters={"argv": ["echo", "hello-lisa"], "timeout_seconds": 30},
        data_dir=str(tmp_path),
    )
    result = await bwrap_run.execute(ctx)
    assert result.error == ""
    assert result.output_json["sandboxed"] is True
    assert "hello-lisa" in result.output_text
    assert result.output_json["return_code"] == 0
    # Real-namespace check: the identity stamp describes THIS host's mapping.
    identity = result.output_json["identity"]
    assert identity["sandbox_uid"] == 0
    assert identity["host_uid"] == os.getuid()
