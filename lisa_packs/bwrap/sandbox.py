"""The bwrap pack's sandbox-capability ownership declaration.

The kernel owns the sandbox *concept* (a named capability with a
declarative floor vocabulary — see ``kernel.sandbox_floor``); this pack owns
the *implementation*. This module exposes the implementation declaration the
runtime resolves like the memory capability: explicit session selection
(``providers.capabilities.sandbox``) wins, a single registered
implementation auto-owns, ambiguity raises.

``describe_sandbox()`` returns the declaration consumed by
``kernel.sandbox_floor.discover_sandbox_implementations``. The
``validate_floor`` hook wraps this pack's own ``floor_from_config`` parser:
it is the single loud validator for floor values (unknown keys, invalid axis
values, cross-axis constraints like capture paths requiring the overlay
posture). The runtime applies it to the *merged* floor — authored floor plus
pack contributions — so a merge can never produce a floor the enforcer
cannot parse. Errors surface at session assembly (load time), not at first
dispatch.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from lisa_packs.bwrap.policy import floor_from_config


def describe_sandbox() -> Mapping[str, Any]:
    """Return this pack's sandbox implementation declaration.

    Shape: ``{"pack_name": "lisa-pack-bwrap", "validate_floor": callable}``.
    A mapping is returned (not the kernel dataclass) so the pack does not
    import kernel internals beyond the entry-point contract; discovery
    accepts either form.
    """
    return {
        "pack_name": "lisa-pack-bwrap",
        "validate_floor": _validate_floor,
    }


def _validate_floor(floor: Mapping[str, Any]) -> None:
    """Parse the final merged floor with the pack's own policy parser.

    ``floor_from_config`` raises ``PolicyError`` (a ``ValueError``) on any
    unknown key, invalid axis value, or inconsistent combination, with an
    actionable message naming the fix — exactly what load-time validation
    should give the operator. The result is discarded; only validation
    matters here.
    """
    floor_from_config({"sandbox": {"floor": dict(floor)}})


__all__ = ["describe_sandbox"]
