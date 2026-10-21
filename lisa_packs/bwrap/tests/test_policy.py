"""Pure sandbox-policy tests - the floor, the lattice, and the overrides."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from lisa_packs.bwrap.policy import (
    PolicyError,
    SandboxProfile,
    check_prerequisites,
    default_floor,
    floor_from_config,
    resolve_effective,
)

#: Named byte/second budgets used by the floor-parsing assertions, so the
#: expected values read as contract rather than magic numbers.
_TMPFS_BUDGET_BYTES = 67108864
_SMALL_TMPFS_BUDGET_BYTES = 1024
_TIMEOUT_CEILING_SECONDS = 120
_TIGHTENED_TMPFS_BUDGET_BYTES = 512

# --- floor parsing ------------------------------------------------------------


def test_floor_from_config_defaults_when_absent() -> None:
    assert floor_from_config({}) == default_floor()
    assert floor_from_config({"unrelated": True}) == default_floor()
    assert floor_from_config(None) == default_floor()


def test_floor_from_config_parses_frozen_session_config() -> None:
    """Frozen MappingProxyType config must parse, not fall back to defaults.

    The kernel freezes session-authored pack configuration via
    ``SessionPackConfigurationResolver._freeze``; a plain-dict guard there
    silently discarded the harness's authored floor (2026-09-16 incident).
    """
    authored = {
        "sandbox": {
            "floor": {
                "execution": "bare",
                "persistence": "direct-write",
                "network": "allow",
                "device": "dev",
                "ipc": "shared",
                "paths": {"/home/adam/Code": "rw"},
                "tmpfs_budget_bytes": _TMPFS_BUDGET_BYTES,
            }
        }
    }
    frozen = MappingProxyType({key: MappingProxyType(value) for key, value in authored.items()})
    floor = floor_from_config(frozen)
    assert floor.execution == "bare"
    assert floor.persistence == "direct-write"
    assert floor.network == "allow"
    assert floor.device == "dev"
    assert floor.ipc == "shared"
    assert floor.paths == {"/home/adam/Code": "rw"}
    assert floor.tmpfs_budget_bytes == _TMPFS_BUDGET_BYTES


def test_floor_from_config_accepts_direct_alias() -> None:
    """``persistence: direct`` is a common authoring alias for direct-write."""
    floor = floor_from_config({"sandbox": {"floor": {"persistence": "direct"}}})
    assert floor.persistence == "direct-write"


def test_floor_from_config_frozen_rejects_bad_value() -> None:
    """Frozen config still fails loudly on an invalid axis value."""
    frozen = MappingProxyType(
        {"sandbox": MappingProxyType({"floor": MappingProxyType({"network": "sometimes"})})}
    )
    with pytest.raises(PolicyError):
        floor_from_config(frozen)


def test_floor_from_config_reads_trusted_values() -> None:
    cfg = {
        "sandbox": {
            "floor": {
                "execution": "sandbox",
                "persistence": "readonly",
                "network": "deny",
                "device": "none",
                "ipc": "unshared",
                "paths": {"/run/log/journal": "ro", "/srv/etc": "hidden"},
                "tmpfs_budget_bytes": _SMALL_TMPFS_BUDGET_BYTES,
                "timeout_ceiling_seconds": _TIMEOUT_CEILING_SECONDS,
            }
        }
    }
    floor = floor_from_config(cfg)
    assert floor.persistence == "readonly"
    assert floor.device == "none"
    assert floor.paths["/run/log/journal"] == "ro"
    assert floor.paths["/srv/etc"] == "hidden"
    assert floor.tmpfs_budget_bytes == _SMALL_TMPFS_BUDGET_BYTES
    assert floor.timeout_ceiling_seconds == _TIMEOUT_CEILING_SECONDS


def test_floor_from_config_rejects_unknown_axis() -> None:
    with pytest.raises(PolicyError):
        floor_from_config({"sandbox": {"floor": {"not_an_axis": "x"}}})


def test_floor_from_config_rejects_bad_value() -> None:
    with pytest.raises(PolicyError):
        floor_from_config({"sandbox": {"floor": {"network": "sometimes"}}})


# --- lattice: restrict-only ----------------------------------------------------


def test_tightening_persistence_above_floor_allowed() -> None:
    floor = SandboxProfile(persistence="ephemeral")
    eff = resolve_effective(floor, SandboxProfile(persistence="readonly"))
    assert eff.persistence == "readonly"  # tightened is fine


def test_loosening_persistence_below_floor_rejected() -> None:
    floor = SandboxProfile(persistence="ephemeral")
    with pytest.raises(PolicyError) as exc:
        resolve_effective(floor, SandboxProfile(persistence="overlay"))
    assert "persistence" in str(exc.value)


def test_unspecified_request_rides_the_floor() -> None:
    floor = SandboxProfile(network="deny", persistence="readonly", device=None, ipc=None)
    # The request is empty: its values come from the pack safe default and are
    # then silently tightened to the floor on every floor-specified axis.
    eff = resolve_effective(floor, SandboxProfile())
    assert eff.network == "deny"
    assert eff.persistence == "readonly"


def test_network_loosen_rejected() -> None:
    floor = SandboxProfile(network="deny")
    with pytest.raises(PolicyError):
        resolve_effective(floor, SandboxProfile(network="allow"))


def test_budget_ceiling_only_tightens() -> None:
    floor = SandboxProfile(tmpfs_budget_bytes=_SMALL_TMPFS_BUDGET_BYTES)
    with pytest.raises(PolicyError):
        resolve_effective(floor, SandboxProfile(tmpfs_budget_bytes=10 * 1024))
    eff = resolve_effective(floor, SandboxProfile(tmpfs_budget_bytes=_TIGHTENED_TMPFS_BUDGET_BYTES))
    assert eff.tmpfs_budget_bytes == _TIGHTENED_TMPFS_BUDGET_BYTES


def test_per_path_floor_cannot_be_loosened() -> None:
    floor = SandboxProfile(paths={"/run/log/journal": "ro"})
    with pytest.raises(PolicyError):
        resolve_effective(floor, SandboxProfile(paths={"/run/log/journal": "rw"}))
    # and tightening a new path is fine
    eff = resolve_effective(floor, SandboxProfile(paths={"/etc": "hidden"}))
    assert eff.paths["/run/log/journal"] == "ro"
    assert eff.paths["/etc"] == "hidden"


def test_direct_write_requires_explicit_ancestor_floor_permission() -> None:
    floor = SandboxProfile(persistence="direct-write", paths={"/workspace": "rw"})
    effective = resolve_effective(
        floor,
        SandboxProfile(persistence="direct-write", paths={"/workspace/worktree": "rw"}),
    )
    assert effective.paths["/workspace/worktree"] == "rw"

    for restricted in (
        SandboxProfile(persistence="direct-write"),
        SandboxProfile(persistence="direct-write", paths={"/workspace": "ro"}),
    ):
        with pytest.raises(PolicyError, match="paths"):
            resolve_effective(
                restricted,
                SandboxProfile(
                    persistence="direct-write",
                    paths={"/workspace/worktree": "rw"},
                ),
            )


def test_nested_path_uses_nearest_floor_permission() -> None:
    floor = SandboxProfile(
        persistence="direct-write",
        paths={"/workspace": "ro", "/workspace/worktree": "rw"},
    )
    effective = resolve_effective(
        floor,
        SandboxProfile(paths={"/workspace/worktree/src": "rw"}),
    )
    assert effective.paths["/workspace/worktree/src"] == "rw"


# --- capture paths ------------------------------------------------------------


def test_capture_ordering_between_rw_and_ro() -> None:
    """capture sits between rw (real writes) and ro (no writes) on the ladder."""
    # rw request against a capture floor is a loosening -> rejected.
    floor = SandboxProfile(persistence="overlay", paths={"/etc": "capture"})
    with pytest.raises(PolicyError):
        resolve_effective(floor, SandboxProfile(paths={"/etc": "rw"}))
    # capture tightened up to ro is allowed (and stays captured: no writes).
    eff = resolve_effective(floor, SandboxProfile(paths={"/etc": "ro"}))
    assert eff.paths["/etc"] == "ro"
    # capture tightened up to hidden is allowed.
    eff = resolve_effective(floor, SandboxProfile(paths={"/etc": "hidden"}))
    assert eff.paths["/etc"] == "hidden"


def test_capture_tightens_rw_request() -> None:
    """An rw floor path joined with a capture request tightens to capture."""
    floor = SandboxProfile(persistence="overlay", paths={"/etc": "rw"})
    eff = resolve_effective(floor, SandboxProfile(persistence="overlay", paths={"/etc": "capture"}))
    assert eff.paths["/etc"] == "capture"


def test_floor_from_config_parses_capture_paths() -> None:
    cfg = {
        "sandbox": {
            "floor": {
                "execution": "sandbox",
                "persistence": "overlay",
                "paths": {"/etc": "capture", "/var/log": "ro"},
            }
        }
    }
    floor = floor_from_config(cfg)
    assert floor.paths == {"/etc": "capture", "/var/log": "ro"}


def test_capture_requires_overlay_persistence() -> None:
    """capture paths joined with a non-overlay persistence is a loud error."""
    # ephemeral default posture + capture floor path -> the effective join
    # can never honor capture; refuse rather than silently degrading.
    floor = SandboxProfile(persistence="overlay", paths={"/etc": "capture"})
    request = SandboxProfile(persistence="ephemeral")  # explicit tighten away
    with pytest.raises(PolicyError) as exc:
        resolve_effective(floor, request)
    assert "capture" in str(exc.value)
    assert "overlay" in str(exc.value)


def test_capture_with_overlay_persistence_is_consistent() -> None:
    floor = SandboxProfile(persistence="overlay", paths={"/etc": "capture", "/srv": "rw"})
    eff = resolve_effective(floor, SandboxProfile(persistence="overlay", paths={"/srv": "rw"}))
    assert eff.paths == {"/etc": "capture", "/srv": "rw"}
    assert eff.persistence == "overlay"


def test_capture_floor_with_ephemeral_default_is_loud() -> None:
    """A capture floor path with the pack's ephemeral default is an authoring error.

    default_posture() starts ephemeral; if the floor pins capture on a path
    but leaves persistence unset, the tightened persistence stays ephemeral
    and capture could not work - the join must refuse loudly instead.
    """
    floor = SandboxProfile(paths={"/etc": "capture"})  # no persistence pinned
    with pytest.raises(PolicyError) as exc:
        resolve_effective(floor, SandboxProfile())
    assert "capture" in str(exc.value)


# --- load-time prerequisites ---------------------------------------------------


def test_check_prerequisites_reports_missing_bwrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lisa_packs.bwrap.probe.bwrap_binary", lambda: None)
    assert check_prerequisites() != []


def test_check_prerequisites_empty_when_bwrap_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lisa_packs.bwrap.probe.bwrap_binary", lambda: "/usr/bin/bwrap")
    assert check_prerequisites() == []


def test_check_prerequisites_reports_non_posix_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-POSIX host is named as unsupported, not probed for bubblewrap.

    The pack implements a Linux-only sandbox, so the honest prerequisite
    failure on macOS/Windows names the platform boundary instead of
    suggesting a bubblewrap install that could never work there.
    """
    monkeypatch.setattr("lisa_packs.bwrap.posix_host.POSIX_HOST", False)
    reasons = check_prerequisites()
    assert reasons != []
    assert "Linux-only" in reasons[0]
