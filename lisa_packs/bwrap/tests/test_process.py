"""``run_process`` must return on time and never orphan a process tree.

Regression background (2026-10-12): a timeout SIGKILLed only the direct
child. An orphaned grandchild inherited the stdout/stderr write ends, so the
post-kill drain awaited blocked until the last holder exited — a ``setsid``
daemon (the dnsmasq-web ``RunDaemon`` helper pattern) holds them forever, and
the turn wedged for 47 minutes inside the check tool while no timeout could
fire (the ``wait_for`` had already completed on the child's death). The kill
must cover the whole process group, and the drains must not be awaited
unboundedly on that path.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from lisa_packs.bwrap.process import run_process

_RETURN_LIMIT_S = 10.0
_DEATH_LIMIT_S = 5.0


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def _wait_gone(pid: int) -> bool:
    for _ in range(int(_DEATH_LIMIT_S / 0.05)):
        if not _alive(pid):
            return True
        await asyncio.sleep(0.05)
    return False


def _grandchild_script(pid_file: Path) -> str:
    escaped = str(pid_file).replace("'", "'\\''")
    # The backgrounded sleep is sh's child: it survives a kill of sh alone
    # and holds the inherited stdout/stderr write ends.
    return f"sleep 900 & echo $! > '{escaped}'; sleep 900"


@pytest.mark.asyncio
async def test_timeout_kills_the_whole_child_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "grand.pid"
    argv = ["/bin/sh", "-c", _grandchild_script(pid_file)]
    result = await asyncio.wait_for(
        run_process(argv, timeout_seconds=1, max_output_bytes=1024),
        timeout=_RETURN_LIMIT_S,
    )
    assert result.timed_out
    assert pid_file.exists(), "grandchild never ran"
    grand_pid = int(pid_file.read_text().strip())
    assert grand_pid != os.getpid()
    assert await _wait_gone(grand_pid), (
        f"grandchild {grand_pid} survived the timeout kill: the kill must "
        "cover the whole process group, not only the direct child."
    )


@pytest.mark.asyncio
async def test_timeout_returns_promptly_with_a_pipe_holding_grandchild(
    tmp_path: Path,
) -> None:
    """The drains must not hold the return hostage to an orphaned writer."""
    pid_file = tmp_path / "grand.pid"
    argv = ["/bin/sh", "-c", _grandchild_script(pid_file)]
    result = await asyncio.wait_for(
        run_process(argv, timeout_seconds=1, max_output_bytes=1024),
        timeout=_RETURN_LIMIT_S,
    )
    assert result.timed_out
    grand_pid = int(pid_file.read_text().strip())
    # Cleanup is the fix's job now; give it a beat before asserting.
    assert await _wait_gone(grand_pid), (
        f"grandchild {grand_pid} still alive after return"
    )


@pytest.mark.asyncio
async def test_cancellation_kills_the_whole_child_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "grand.pid"
    argv = ["/bin/sh", "-c", _grandchild_script(pid_file)]
    task = asyncio.ensure_future(
        run_process(argv, timeout_seconds=60, max_output_bytes=1024)
    )
    for _ in range(200):
        if pid_file.exists() and pid_file.read_text().strip():
            break
        await asyncio.sleep(0.05)
    assert pid_file.exists(), "grandchild never ran"
    grand_pid = int(pid_file.read_text().strip())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=_RETURN_LIMIT_S)
    assert await _wait_gone(grand_pid), (
        f"grandchild {grand_pid} survived the caller's cancellation."
    )
