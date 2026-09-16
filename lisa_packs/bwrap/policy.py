"""Sandbox containment policy: the harness floor and restrict-only overrides.

Pure policy logic for the bwrap pack - no I/O, no side effects (mirrors
``argv_builder``). The harness (user) sets a deterministic containment FLOOR:
the least-restrictive posture it will permit. The model (via bwrap_run/bash_run
params) may only *raise* integrity - tighten - and can never request anything
looser than the floor allows.

The trust boundary is the channel, not the contents: the floor is read from
``ctx.pack_config``, which the lisa kernel populates from the harness-owned
session ``resources.packs.configuration`` and which model tool ``parameters``
cannot forge. This module only validates and joins that trusted input.

Lattice axes (loosest -> tightest), each ordered independently:
    execution   bare < sandbox            (run on host vs. inside bwrap)
    persistence direct-write < overlay < ephemeral < readonly
    network     allow < deny              (--unshare-net)
    device      dev < minimal < none      (--dev variants)
    ipc         shared < unshared         (--unshare-ipc)
    tmpfs_budget_bytes  inf -> finite     (--tmpfs size cap)
    timeout_ceiling_seconds  inf -> finite (floor can only be lowered)
    paths       per-path rw < ro < hidden (--bind / --ro-bind / omit)

``resolve_effective`` joins the floor with a request; an *explicit* request to
loosen below the floor is a hard :class:`PolicyError`, so the boundary is taught
loudly rather than silently clamped.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from math import inf
from pathlib import Path

__all__ = [
    "Device",
    "Execution",
    "IPC",
    "PathAccess",
    "Persistence",
    "PolicyError",
    "SandboxProfile",
    "check_prerequisites",
    "default_floor",
    "floor_from_config",
    "resolve_effective",
]


class PolicyError(ValueError):
    """A request asked to loosen containment below the harness floor."""

    def __init__(self, axis: str, attempted: str, floor: str) -> None:
        self.axis = axis
        self.attempted = attempted
        self.floor = floor
        super().__init__(
            f"Refused: '{axis}' cannot be loosened to {attempted!r} - the harness "
            f"floor for this session is {floor!r}. Ask the user to raise the floor "
            "in the sandbox policy configuration."
        )


# --- Ordered axes ------------------------------------------------------------

_AXES: dict[str, tuple[str, ...]] = {
    "execution": ("bare", "sandbox"),
    "persistence": ("direct-write", "overlay", "ephemeral", "readonly"),
    "network": ("allow", "deny"),
    "device": ("dev", "minimal", "none"),
    "ipc": ("shared", "unshared"),
    "paths": ("rw", "ro", "hidden"),
}

Execution = str
Persistence = str
Device = str
IPC = str
PathAccess = str


def _level(axis: str, value: str) -> int:
    order = _AXES[axis]
    if value not in order:
        raise PolicyError(axis, value, "one of " + "/".join(order))
    return order.index(value)


def _tighten(axis: str, a: str, b: str) -> str:
    """Most-restrictive-wins join for a categorical axis."""
    order = _AXES[axis]
    return order[max(_level(axis, a), _level(axis, b))]


def _tighten_opt(axis: str, a: str | None, b: str | None) -> str | None:
    """Most-restrictive-wins join where None = unspecified (no constraint)."""
    if a is None:
        return b
    if b is None:
        return a
    return _tighten(axis, a, b)


def _tighten_budget(a: float | None, b: float | None) -> float | None:
    """Floor budget: a tighter cap is a smaller finite number; None = unbounded."""
    if a is None and b is None:
        return None
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _tighten_timeout(a: float | None, b: float | None) -> float | None:
    """Floor timeout ceiling: only a lower ceiling tightens; None = no ceiling."""
    return _tighten_budget(a, b)


# --- Profile -----------------------------------------------------------------


@dataclass(frozen=True)
class SandboxProfile:
    """A resolved sandbox request (or a floor). Fields are per-axis postures.

    All categorical fields may be ``None`` meaning "unspecified / inherit". A
    fully-specified *effective* profile has no Nones on execution/persistence/
    network/device/ipc; paths/tmpfs_budget/timeout_ceiling may remain default.
    """

    execution: Execution | None = None
    persistence: Persistence | None = None
    network: str | None = None
    device: Device | None = None
    ipc: IPC | None = None
    paths: dict[str, PathAccess] = field(default_factory=dict)
    tmpfs_budget_bytes: int | None = None
    timeout_ceiling_seconds: int | None = None


def _merge_profile(base: SandboxProfile, over: SandboxProfile) -> SandboxProfile:
    """Overlay ``over`` onto ``base``; a non-None field on ``over`` wins.

    ``paths`` merge per path (over wins per key). This is plain override, NOT
    lattice join - the floor dominance check is done separately against the
    merged candidate.
    """
    return SandboxProfile(
        execution=over.execution if over.execution is not None else base.execution,
        persistence=over.persistence if over.persistence is not None else base.persistence,
        network=over.network if over.network is not None else base.network,
        device=over.device if over.device is not None else base.device,
        ipc=over.ipc if over.ipc is not None else base.ipc,
        paths={**base.paths, **over.paths},
        tmpfs_budget_bytes=(
            over.tmpfs_budget_bytes
            if over.tmpfs_budget_bytes is not None
            else base.tmpfs_budget_bytes
        ),
        timeout_ceiling_seconds=(
            over.timeout_ceiling_seconds
            if over.timeout_ceiling_seconds is not None
            else base.timeout_ceiling_seconds
        ),
    )


def _unspecified_profile() -> SandboxProfile:
    """An all-None profile: merging a request onto it marks only explicit axes."""
    return SandboxProfile()


def _dominates(candidate: SandboxProfile, floor: SandboxProfile) -> None:
    """Raise PolicyError if ``candidate`` is looser than ``floor`` on any axis."""
    for axis in ("execution", "persistence", "network", "device", "ipc"):
        c = getattr(candidate, axis)
        f = getattr(floor, axis)
        if c is not None and f is not None and _level(axis, c) < _level(axis, f):
            raise PolicyError(axis, c, f)

    # Budget / timeout ceilings: a violation is ONLY the caller explicitly setting
    # a cap LARGER than the floor's (asking for more headroom than the floor grants).
    # An unset candidate cap (None = "didn't ask") always rides the floor, so it can
    # never be a loosening; and both-unset is nobody's constraint. A finite cap that
    # is <= the floor's cap is a tightening.
    for axis, c, f in (
        ("tmpfs_budget_bytes", candidate.tmpfs_budget_bytes, floor.tmpfs_budget_bytes),
        (
            "timeout_ceiling_seconds",
            candidate.timeout_ceiling_seconds,
            floor.timeout_ceiling_seconds,
        ),
    ):
        if c is None or f is None:
            continue  # unset-vs-anything is never a violation here
        if float(c) > float(f):
            raise PolicyError(axis, str(c), str(f))

    # Per-path: a path the floor pins may not be loosened.
    for path, floor_access in floor.paths.items():
        cand_access = candidate.paths.get(path)
        if cand_access is not None and _level("paths", cand_access) < _level(
            "paths", floor_access
        ):
            raise PolicyError(f"paths[{path}]", cand_access, floor_access)


def resolve_effective(
    floor: SandboxProfile,
    request: SandboxProfile | None,
    *,
    defaults: SandboxProfile | None = None,
) -> SandboxProfile:
    """Join a (trusted) floor with a (model) request into the effective sandbox.

    ``defaults`` fills any axis the floor leaves unspecified (pack safe default).
    The request overrides defaults; the floor constrains the merged result. Any
    explicit loosening below the floor raises :class:`PolicyError`. The returned
    profile is the candidate *tightened to the floor* on scalar axes the request
    left at looser defaults (silently) - only explicit loosen attempts error.
    """
    base = defaults or default_posture()
    candidate = _merge_profile(base, request) if request is not None else base
    # Only an EXPLICIT loosening below the floor is an error; a field the request
    # left unspecified (and which therefore rode the pack default) is silently
    # tightened to the floor below. Explicit-vs-default is decided by which
    # fields the request actually set.
    if request is not None:
        _dominates(_merge_profile(_unspecified_profile(), request), floor)

    # Tighten the candidate up to the floor on each axis (floor is a minimum
    # integrity; unspecified or looser-by-default request fields ride the floor).
    return SandboxProfile(
        execution=_tighten_opt("execution", candidate.execution, floor.execution),
        persistence=_tighten_opt(
            "persistence", candidate.persistence, floor.persistence
        ),
        network=_tighten_opt("network", candidate.network, floor.network),
        device=_tighten_opt("device", candidate.device, floor.device),
        ipc=_tighten_opt("ipc", candidate.ipc, floor.ipc),
        paths=_tighten_paths(candidate.paths, floor.paths),
        tmpfs_budget_bytes=_tighten_budget(
            candidate.tmpfs_budget_bytes, floor.tmpfs_budget_bytes
        ),
        timeout_ceiling_seconds=_tighten_timeout(
            candidate.timeout_ceiling_seconds, floor.timeout_ceiling_seconds
        ),
    )


def _tighten_paths(
    candidate: dict[str, PathAccess], floor: dict[str, PathAccess]
) -> dict[str, PathAccess]:
    """Join per-path access most-restrictive-wins, keyed by real path prefix."""
    out = dict(candidate)
    for path, floor_access in floor.items():
        cur = out.get(path)
        out[path] = (
            floor_access if cur is None else _tighten("paths", cur, floor_access)
        )
    return out


# --- Defaults + config parsing ------------------------------------------------


def default_posture() -> SandboxProfile:
    """The shape a request takes when the model specifies nothing.

    Distinct from the floor: the floor is the *allowed ceiling* (what the model
    may climb to); the posture is the *starting point* - the safe, ephemeral,
    no-network sandbox a bare request gets. The harness floor then constrains
    how far above this the model is allowed to go.
    """
    return SandboxProfile(
        execution="sandbox",
        persistence="ephemeral",
        network="deny",
        device="minimal",
        ipc="unshared",
        paths={},
        tmpfs_budget_bytes=None,
        timeout_ceiling_seconds=None,
    )


def default_floor() -> SandboxProfile:
    """The pack's shipped safe floor, used when the harness sets no floor.

    Fail-safe but capture-capable: sandboxed, overlay capture is the *allowed
    ceiling* (the model may tighten to ephemeral/readonly but never loosen to
    direct-write), no network, minimal device, workspace RO + scratch, journal
    readable, /tmp capped. The harness tightens or explicitly loosens from here.
    """
    return SandboxProfile(
        execution="sandbox",
        persistence="overlay",
        network="deny",
        device="minimal",
        ipc="unshared",
        paths={"/run/log/journal": "ro"},
        tmpfs_budget_bytes=64 * 1024 * 1024,
        timeout_ceiling_seconds=None,
    )


def floor_from_config(config: object) -> SandboxProfile:
    """Parse the harness floor out of ``ctx.pack_config['sandbox']['floor']``.

    ``config`` is the pack's pack_config mapping (trusted, harness-owned). A
    missing/!mapping sandbox section yields the safe default floor. Unknown
    keys and invalid values raise PolicyError - the floor is user-authored, so
    a typo must be loud, not silently ignored.

    The kernel freezes session-authored configuration into
    ``MappingProxyType`` trees (``SessionPackConfigurationResolver._freeze``),
    so every structural check here accepts any :class:`Mapping`, not just
    ``dict``. A plain-dict guard would silently fall back to the shipped
    default floor - dropping the harness's authored posture (e.g.
    ``execution: bare``) without a word. "direct" is accepted as an alias for
    the "direct-write" persistence value.
    """
    if not isinstance(config, Mapping):
        return default_floor()
    sandbox = config.get("sandbox")
    if not isinstance(sandbox, Mapping):
        return default_floor()
    floor: object = sandbox.get("floor")
    if floor is None:
        return default_floor()
    if not isinstance(floor, Mapping):
        raise PolicyError("sandbox.floor", type(floor).__name__, "a mapping")

    allowed = {
        "execution",
        "persistence",
        "network",
        "device",
        "ipc",
        "paths",
        "tmpfs_budget_bytes",
        "timeout_ceiling_seconds",
    }
    unknown = set(floor) - allowed
    if unknown:
        raise PolicyError(
            "sandbox.floor", ",".join(sorted(unknown)), f"known keys {sorted(allowed)}"
        )

    paths: dict[str, PathAccess] = {}
    raw_paths = floor.get("paths") or {}
    if not isinstance(raw_paths, Mapping):
        raise PolicyError("sandbox.floor.paths", type(raw_paths).__name__, "a mapping")
    for raw_path, access in raw_paths.items():
        if access not in _AXES["paths"]:
            raise PolicyError(f"sandbox.floor.paths[{raw_path}]", access, "rw/ro/hidden")
        paths[str(_normalize_path(str(raw_path)))] = access

    persistence_raw = floor.get("persistence")
    if isinstance(persistence_raw, str) and persistence_raw == "direct":
        persistence_raw = "direct-write"
    return SandboxProfile(
        execution=_opt_axis("execution", floor.get("execution")),
        persistence=_opt_axis("persistence", persistence_raw),
        network=_opt_axis("network", floor.get("network")),
        device=_opt_axis("device", floor.get("device")),
        ipc=_opt_axis("ipc", floor.get("ipc")),
        paths=paths,
        tmpfs_budget_bytes=_opt_int(floor.get("tmpfs_budget_bytes")),
        timeout_ceiling_seconds=_opt_int(floor.get("timeout_ceiling_seconds")),
    )


def _opt_axis(axis: str, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _AXES[axis]:
        raise PolicyError(axis, str(value), "one of " + "/".join(_AXES[axis]))
    return value


def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PolicyError("budget/timeout", str(value), "a non-negative integer")
    return value


def _normalize_path(raw: str) -> Path:
    """Normalize a floor path key; '~' expands, path is made absolute.

    Floor paths are trusted (harness-authored), so no existence check - they
    describe what MAY be visible, not what must exist.
    """
    return Path(raw).expanduser()


# --- Load-time prerequisites ---------------------------------------------------


def check_prerequisites() -> list[str]:
    """Host-surfaceable load prerequisites; empty list = the pack can run.

    Exposed so the lisa host's startup prerequisite-validation pass can fail
    hard (bare-vs-none elimination): if bubblewrap is absent, the pack cannot
    contain anything and the host must not silently proceed unsandboxed.
    Side-effect-free beyond a ``shutil.which`` probe - no mounts, no execution.
    """
    from lisa_packs.bwrap.probe import bwrap_binary

    if bwrap_binary() is None:
        return [
            "bubblewrap (bwrap) binary not found on PATH - the bwrap pack cannot "
            "provide sandboxed execution. Install it (openSUSE: 'zypper install "
            "bubblewrap', Fedora/RHEL: 'dnf install bubblewrap', Debian/Ubuntu: "
            "'apt install bubblewrap', Arch: 'pacman -S bubblewrap')."
        ]
    return []
