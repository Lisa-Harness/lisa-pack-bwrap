# Bubblewrap sandboxing is degraded

Lisa's shell is running, but the bubblewrap sandbox (and/or transparent
overlayfs layers) is not available on this host. What that means and how to
fix it:

## What is degraded

- **Without bwrap** — commands run directly on the host with no namespace
  isolation. Every result from the shell carries `sandboxed: false` so this is
  visible, not hidden.
- **Without overlayfs** — the sandbox still runs (namespaces work), but file
  mutations go to ephemeral tmpfs and are **discarded when the run exits**
  (`persistence: "ephemeral"`). Nothing you create inside the run is kept.

## Why it matters

The sandbox is the policy boundary that makes shell execution safe to approve:
read-only root, optional network isolation, and captured mutations.

## How to enable it

Bubblewrap is a host package; it cannot be installed as a Python dependency.

- **Fedora / RHEL**: `sudo dnf install bubblewrap`
- **Debian / Ubuntu**: `sudo apt install bubblewrap`
- **Arch**: `sudo pacman -S bubblewrap`

If `bwrap` is installed but sandboxed runs still fail, unprivileged user
namespaces may be disabled. On Debian/Ubuntu:

```bash
sudo sysctl kernel.unprivileged_userns_clone=1
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/90-userns.conf
```

For overlayfs persistence, the kernel must allow unprivileged overlay mounts
(kernel >= 5.11 with `userxattr`). This is standard on current distributions,
but two different blockers exist:

1. **The kernel or an LSM policy denies the overlay `mount` syscall** even
   inside a user namespace (e.g. a hardened or custom kernel without
   unprivileged overlay support). In that case the sandbox still isolates
   namespaces, but mutations fall back to ephemeral tmpfs. This may be
   fixable by enabling unprivileged overlay mounts or adjusting LSM policy.
2. **bwrap drops all capabilities from the child process** (`CapEff=0`), and
   `mount(2)` requires `CAP_SYS_ADMIN` in the owning user namespace. The
   pack's probe detects this differentially (the same mount succeeds via
   `unshare --user --map-root-user`), and reports it as:
   *"bwrap drops all capabilities from the child ... overlayfs capture inside
   bwrap is structurally unavailable"*. This is **not host-fixable** — no
   sysctl or package install changes it. The sandbox still works with
   ephemeral tmpfs; do not retry with `persist`/`layer_id`, and do not tell
   the user to reinstall anything.

When `bwrap` and overlayfs are both present, sandboxing is used automatically -
no configuration needed.
