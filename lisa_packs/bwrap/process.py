"""Bounded subprocess execution for the bwrap pack.

Self-contained: the SDK ``run_process`` promotion is deferred until a second
real consumer exists (promote shared helpers to the SDK when duplication is
real, not before).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import Callable, Sequence
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


async def _bounded_drain(
    task: asyncio.Future[tuple[bytes, bool]],
    retained: list[bytes],
) -> tuple[bytes, bool]:
    """Await one drain task with a final grace bound.

    A normally-exiting child whose orphaned descendant still holds the pipe
    write end would otherwise block on the stream EOF forever (the 2026-10-12
    ``setsid`` daemon wedge). Past the grace bound the drain is cancelled and
    ``retained`` carries whatever byte holder the drain task kept, so output
    that already arrived is never silently dropped.
    """
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=5)
    except (TimeoutError, asyncio.CancelledError):
        if task.cancelled():
            return b"", False
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        holder = retained[0] if retained and isinstance(retained[0], bytes) else b""
        return holder, False


def _kill_group(process: asyncio.subprocess.Process) -> None:
    """Deliver SIGKILL to the child's whole process group, falling back to the child.

    Regression background (2026-10-12): killing only the direct child left
    orphans holding the inherited stdout/stderr write ends, so the drain
    awaits after the kill blocked until the last holder exited — a ``setsid``
    daemon holds them forever (the 2026-10-12 dnsmasq-web check wedge, 47
    minutes inside ``coding_run_check`` with no timeout able to fire). The
    child is started in its own session (``start_new_session``), so the
    process-group kill covers its descendants.
    """
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return
    except (ProcessLookupError, PermissionError, OSError):
        pass
    with contextlib.suppress(ProcessLookupError):
        process.kill()


async def _drain_limited(
    stream: asyncio.StreamReader,
    *,
    limit: int,
    on_line: Callable[[str], None] | None = None,
    buffer: list[str] | None = None,
    retained_holder: list[bytes] | None = None,
) -> tuple[bytes, bool]:
    """Drain a subprocess stream while retaining no more than ``limit`` bytes.

    When ``on_line`` is provided, every complete line is forwarded to it as it
    arrives (incremental operator-visible output); the trailing partial line
    flushes on stream end. ``buffer`` is the mutable holder for the leftover
    partial line between stdout/stderr tasks — a shared one is only needed
    when both taps are active (unused otherwise).

    ``retained_holder`` (one-entry list, when provided) is kept current with
    the bytes retained so far, so a caller that must abandon the drain under
    the final grace bound can still salvage what already arrived.
    """
    retained = bytearray()
    overflowed = False
    pending = ""
    while chunk := await stream.read(8192):
        remaining = limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflowed = True
        if retained_holder is not None:
            retained_holder.clear()
            retained_holder.append(bytes(retained))
        if on_line is not None:
            pending += chunk.decode("utf-8", errors="replace")
            while "\n" in pending:
                line, _, pending = pending.partition("\n")
                on_line(line)
    if on_line is not None and pending:
        on_line(pending)
    if buffer is not None:
        buffer.clear()
        buffer.append(pending)
    return bytes(retained), overflowed


async def run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    log_path: object | None = None,
    on_output: Callable[[str, str], None] | None = None,
) -> ProcessResult:
    """Execute an explicit argument vector with bounded output and timeout.

    When ``log_path`` is provided, the full invocable argv and the retained
    stdout/stderr are appended to that log file for user-visible auditing.

    When ``on_output`` is provided, it is called incrementally as
    ``on_output(stream, line)`` for every complete line from either stream —
    the caller's incremental-output tap (e.g. forwarding to the turn's
    ``lisa.tool_output`` bus topic). Tap failures must be handled by the
    callback itself; this function never inspects or suppresses them.
    """
    if not argv or not argv[0]:
        raise ValueError("A non-empty executable argument vector is required.")

    def _stdout_tap(line: str) -> None:
        if on_output is not None:
            on_output("stdout", line)

    def _stderr_tap(line: str) -> None:
        if on_output is not None:
            on_output("stderr", line)

    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        # Own session + process group: a group kill takes the whole child
        # tree (grandchildren holding the output pipes must not outlive the
        # deadline or hold the drains open after the kill).
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_holder: list[bytes] = []
    stderr_holder: list[bytes] = []
    stdout_task = asyncio.create_task(
        _drain_limited(
            process.stdout,
            limit=max_output_bytes,
            on_line=_stdout_tap,
            retained_holder=stdout_holder,
        )
    )
    stderr_task = asyncio.create_task(
        _drain_limited(
            process.stderr,
            limit=max_output_bytes,
            on_line=_stderr_tap,
            retained_holder=stderr_holder,
        )
    )
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
    except TimeoutError:
        timed_out = True
        _kill_group(process)
        await process.wait()
        # The group is gone, so the pipes close. The drains finish on EOF;
        # bounded one more time so no pipe quirk can wedge the caller past
        # its deadline.
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task, return_exceptions=True),
                timeout=5,
            )
    except BaseException:
        # Cancelled (e.g. the caller's tool deadline): never orphan the
        # child tree or the drain tasks.
        if process.returncode is None:
            _kill_group(process)
        stdout_task.cancel()
        stderr_task.cancel()
        with contextlib.suppress(BaseException):
            await process.wait()
        raise
    stdout, stdout_overflowed = await _bounded_drain(stdout_task, stdout_holder)
    stderr, stderr_overflowed = await _bounded_drain(stderr_task, stderr_holder)
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
                handle.write(
                    "[stderr] " + result.stderr.replace("\n", "\n[stderr] ") + "\n"
                )
            handle.write(f"[rc={result.return_code} timed_out={result.timed_out}]\n")
    except OSError:
        # Logging must never fail the tool call.
        return
