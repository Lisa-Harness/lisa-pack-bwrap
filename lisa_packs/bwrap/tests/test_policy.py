"""Pure sandbox-policy tests - the floor, the lattice, and the overrides."""

from __future__ import annotations

import pytest

from lisa_packs.bwrap.policy import (
    PolicyError,
    SandboxProfile,
    check_prerequisites,
    default_floor,
    floor_from_config,
    resolve_effective,
)

# --- floor parsing ------------------------------------------------------------


def test_floor_from_config_defaults_when_absent() -> None:
    assert floor_from_config({}) == default_floor()
    assert floor_from_config({"unrelated": True}) == default_floor()
    assert floor_from_config(None) == default_floor()  # type: ignore[arg-type]


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
                "tmpfs_budget_bytes": 1024,
                "timeout_ceiling_seconds": 120,
            }
        }
    }
    floor = floor_from_config(cfg)
    assert floor.persistence == "readonly"
    assert floor.device == "none"
    assert floor.paths["/run/log/journal"] == "ro"
    assert floor.paths["/srv/etc"] == "hidden"
    assert floor.tmpfs_budget_bytes == 1024
    assert floor.timeout_ceiling_seconds == 120


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
    floor = SandboxProfile(tmpfs_budget_bytes=1024)
    with pytest.raises(PolicyError):
        resolve_effective(floor, SandboxProfile(tmpfs_budget_bytes=10 * 1024))
    eff = resolve_effective(floor, SandboxProfile(tmpfs_budget_bytes=512))
    assert eff.tmpfs_budget_bytes == 512


def test_per_path_floor_cannot_be_loosened() -> None:
    floor = SandboxProfile(paths={"/run/log/journal": "ro"})
    with pytest.raises(PolicyError):
        resolve_effective(
            floor, SandboxProfile(paths={"/run/log/journal": "rw"})
        )
    # and tightening a new path is fine
    eff = resolve_effective(floor, SandboxProfile(paths={"/etc": "hidden"}))
    assert eff.paths["/run/log/journal"] == "ro"
    assert eff.paths["/etc"] == "hidden"


# --- load-time prerequisites ---------------------------------------------------


def test_check_prerequisites_reports_missing_bwrap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lisa_packs.bwrap.probe.bwrap_binary", lambda: None)
    assert check_prerequisites() != []


def test_check_prerequisites_empty_when_bwrap_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("lisa_packs.bwrap.probe.bwrap_binary", lambda: "/usr/bin/bwrap")
    assert check_prerequisites() == []
