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


async def _child_env_keys() -> dict[str, str]:
    """Return the child process's env as JSON string output."""
    result = await asyncio.wait_for(
        run_process(
            ["/bin/sh", "-c", "env | sort"],
            timeout_seconds=10,
            max_output_bytes=64_000,
        ),
        timeout=_RETURN_LIMIT_S,
    )
    assert result.return_code == 0, result.stderr
    env: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            env[key] = value
    return env


@pytest.mark.asyncio
async def test_child_env_is_scrubbed_to_the_allowlist() -> None:
    """Ambient host secrets and state must not reach the sandboxed child.

    Regression background (2026-10-15): the live host exports runtime state
    (``LISA_THREAD_DIR``, ``FRAMEWORK_ROOT``) and provider credentials; the
    sandboxed child inherited them wholesale. 78 harness-suite tests then
    resolved the REAL thread dir and wrote it → ``OSError [Errno 30]`` under
    the read-only sandbox mount, and an API key reached a networked sandbox.
    The sandbox child gets a minimal allowlist; anything else is dropped.
    """

    monkey_env = {
        "LISA_THREAD_DIR": "/host/leaked/threads",
        "LISA_DATA_DIR": "/host/leaked/data",
        "FRAMEWORK_ROOT": "/host/leaked/framework",
        "OPENROUTER_API_KEY": "sk-leaked-credential",
        "AWS_SECRET_ACCESS_KEY": "hunt-for-the-bison",
    }
    for key, value in monkey_env.items():
        # Export into this parent so the default inheritance path picks them
        # up; the child env check below asserts the scrub dropped each one.
        os.environ[key] = value
    try:
        child_env = await _child_env_keys()
    finally:
        for key in monkey_env:
            os.environ.pop(key, None)
    for key in monkey_env:
        assert key not in child_env, f"{key} leaked into the sandbox child env"
    assert "PATH" in child_env, "PATH must survive the scrub for the child to work"


@pytest.mark.asyncio
async def test_explicit_extra_env_vars_are_forwarded() -> None:
    """An explicitly requested non-allowlist var overrides the scrub."""
    result = await asyncio.wait_for(
        run_process(
            ["/bin/sh", "-c", "printf '%s' \"$NEEDED_TOOL_VAR\""],
            timeout_seconds=10,
            max_output_bytes=1024,
            extra_env={"NEEDED_TOOL_VAR": "passed-through"},
        ),
        timeout=_RETURN_LIMIT_S,
    )
    assert result.stdout == "passed-through"
