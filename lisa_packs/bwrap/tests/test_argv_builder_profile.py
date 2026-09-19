"""Profile-driven bwrap argv construction tests - no subprocess."""

from __future__ import annotations

from lisa_packs.bwrap.argv_builder import build_bwrap_argv_for_profile
from lisa_packs.bwrap.policy import SandboxProfile


def _build(**kwargs):
    base = dict(
        profile=SandboxProfile(
            execution="sandbox",
            persistence="ephemeral",
            network="deny",
            device="minimal",
            ipc="unshared",
        ),
        child_argv=["echo", "hi"],
    )
    base.update(kwargs)
    return build_bwrap_argv_for_profile(**base)


def test_profile_argv_starts_with_bwrap_and_child_after_separator():
    argv = _build()
    assert argv[0] == "bwrap"
    sep = argv.index("--")
    assert argv[sep + 1 :] == ["echo", "hi"]


def test_deny_network_unshares_net():
    assert "--unshare-net" in _build()


def test_allow_network_keeps_net():
    profile = SandboxProfile(
        execution="sandbox", persistence="ephemeral", network="allow",
        device="minimal", ipc="unshared",
    )
    argv = _build(profile=profile)
    assert "--unshare-net" not in argv
    assert "--unshare-pid" in argv


def test_device_none_binds_dev_null_not_dev():
    profile = SandboxProfile(
        execution="sandbox", persistence="ephemeral", network="deny",
        device="none", ipc="unshared",
    )
    argv = _build(profile=profile)
    assert ["--dev-bind", "/dev/null", "/dev/null"] == argv[
        argv.index("--dev-bind") : argv.index("--dev-bind") + 3
    ]
    assert "--dev" not in argv


def test_tmpfs_budget_caps_size():
    profile = SandboxProfile(
        execution="sandbox", persistence="ephemeral", network="deny",
        device="minimal", ipc="unshared", tmpfs_budget_bytes=1024,
    )
    argv = _build(profile=profile)
    size_idx = argv.index("--size")
    assert argv[size_idx + 1] == "1024"
    assert argv[argv.index("--tmpfs") + 1] == "/tmp"


def test_shared_ipc_keeps_ipc_namespace_shared():
    profile = SandboxProfile(
        execution="sandbox", persistence="ephemeral", network="deny",
        device="minimal", ipc="shared",
    )
    assert "--unshare-ipc" not in _build(profile=profile)


def test_floor_paths_bound_after_backend_binds():
    profile = SandboxProfile(
        execution="sandbox", persistence="ephemeral", network="deny",
        device="minimal", ipc="unshared",
        paths={"/run/log/journal": "ro", "/srv/safe": "rw", "/srv/hide": "hidden"},
    )
    argv = _build(
        profile=profile,
        backend_bind_args=["--bind", "/scratch", "/scratch"],
    )
    triplets = [argv[i : i + 3] for i in range(len(argv) - 2)]
    assert ["--ro-bind", "/run/log/journal", "/run/log/journal"] in triplets
    assert ["--bind", "/srv/safe", "/srv/safe"] in triplets
    # A hidden floor path is NOT bound at all.
    assert not any(t[1:] == ["/srv/hide", "/srv/hide"] for t in triplets if t)
    # Backend binds precede floor paths.
    assert argv.index("/scratch") < argv.index("/run/log/journal")


def test_capture_paths_not_bound_by_builder():
    """Capture entries are backend-owned: never a plain bind from the builder."""
    profile = SandboxProfile(
        execution="sandbox", persistence="overlay", network="deny",
        device="minimal", ipc="unshared",
        paths={"/etc": "capture", "/srv/safe": "rw"},
    )
    argv = _build(
        profile=profile,
        backend_bind_args=["--bind", "/etc", "/etc"],
    )
    triplets = [argv[i : i + 3] for i in range(len(argv) - 2)]
    assert ["--bind", "/srv/safe", "/srv/safe"] in triplets
    # Exactly one /etc bind pair - the backend's. The builder adds none.
    etc_binds = [t for t in triplets if t[1:] == ["/etc", "/etc"]]
    assert len(etc_binds) == 1


def test_drop_all_caps_emits_cap_drop():
    argv = _build(drop_all_caps=True)
    i = argv.index("--cap-drop")
    assert argv[i + 1] == "ALL"
    # Cap-drop precedes the lifecycle flags and the child separator.
    assert argv.index("--cap-drop") < argv.index("--die-with-parent")
    assert argv.index("--cap-drop") < argv.index("--")


def test_no_cap_drop_by_default():
    assert "--cap-drop" not in _build()
