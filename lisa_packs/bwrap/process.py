"""Bounded subprocess execution for the bwrap pack.

Self-contained (the SDK ``run_process`` promotion is deferred until a second
real consumer exists - see docs/SHELL_PACKS_PLAN.md section 3.2).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = ["ProcessResult", "run_process"]


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Bounded process result; output is never unbounded host memory."""

    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_truncated: bool = False


async def _drain_limited(
    stream: asyncio.StreamReader,
    *,
    limit: int,
) -> tuple[bytes, bool]:
    """Drain a subprocess stream while retaining no more than ``limit`` bytes."""
    retained = bytearray()
    overflowed = False
    while chunk := await stream.read(8192):
        remaining = limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflowed = True
    return bytes(retained), overflowed


async def run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    log_path: object | None = None,
) -> ProcessResult:
    """Execute an explicit argument vector with bounded output and timeout.

    When ``log_path`` is provided, the full invocable argv and the retained
    stdout/stderr are appended to that log file for user-visible auditing.
    """
    if not argv or not argv[0]:
        raise ValueError("A non-empty executable argument vector is required.")
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_task = asyncio.create_task(_drain_limited(process.stdout, limit=max_output_bytes))
    stderr_task = asyncio.create_task(_drain_limited(process.stderr, limit=max_output_bytes))
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
    except TimeoutError:
        timed_out = True
        process.kill()
        await process.wait()
    stdout, stdout_overflowed = await stdout_task
    stderr, stderr_overflowed = await stderr_task
    result = ProcessResult(
        return_code=process.returncode if process.returncode is not None else -1,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        output_truncated=stdout_overflowed or stderr_overflowed,
    )
    if log_path is not None:
        _append_log(log_path, argv, result)
    return result


def _append_log(log_path: object, argv: Sequence[str], result: ProcessResult) -> None:
    """Append a renderable command + result record to the audit log."""
    from pathlib import Path

    path = Path(str(log_path))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("$ " + " ".join(argv) + "\n")
            if result.stdout:
                handle.write(result.stdout)
                if not result.stdout.endswith("\n"):
                    handle.write("\n")
            if result.stderr:
                handle.write("[stderr] " + result.stderr.replace("\n", "\n[stderr] ") + "\n")
            handle.write(f"[rc={result.return_code} timed_out={result.timed_out}]\n")
    except OSError:
        # Logging must never fail the tool call.
        return
