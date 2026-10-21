"""Tests for the bwrap pack's sandbox-capability ownership declaration."""

from __future__ import annotations

import pytest

from lisa_packs.bwrap.policy import PolicyError
from lisa_packs.bwrap.sandbox import describe_sandbox


def test_declaration_names_the_pack_and_exposes_a_validator() -> None:
    declared = describe_sandbox()
    assert declared["pack_name"] == "lisa-pack-bwrap"
    assert callable(declared["validate_floor"])


def test_validator_accepts_a_valid_floor() -> None:
    declared = describe_sandbox()
    declared["validate_floor"](
        {
            "execution": "sandbox",
            "persistence": "direct-write",
            "paths": {"/wt": "rw"},
        }
    )


def test_validator_rejects_unknown_keys_loudly() -> None:
    declared = describe_sandbox()
    with pytest.raises(PolicyError):
        declared["validate_floor"]({"execution": "sandbox", "not_a_key": True})


def test_validator_rejects_invalid_axis_values() -> None:
    declared = describe_sandbox()
    with pytest.raises(PolicyError):
        declared["validate_floor"]({"network": "sometimes"})


def test_validator_accepts_capture_paths() -> None:
    # Capture consistency is enforced at dispatch time by resolve_effective
    # (a floor may allow capture while persistence defaults looser — the
    # request must then tighten to overlay). Load-time validation only
    # rejects what floor_from_config rejects: unknown keys, invalid values.
    declared = describe_sandbox()
    declared["validate_floor"]({"persistence": "ephemeral", "paths": {"/etc": "capture"}})
