# The admin posture: system management without going bare

You want Lisa to help manage this machine — read logs, edit configs under
`/etc`, stage service changes — without handing over unsandboxed host
execution. The sandbox policy supports a three-tier posture that keeps
almost all of that work contained. **Privileged verbs (`systemctl`,
`zypper`/`dnf`/`apt install`, user management) can never run inside an
unprivileged sandbox** — those stay on the bare tier, where every call is
approval-prompted and audited.

## Tier 1 — contained diagnosis (read-only, zero risk)

The sandbox's read-only root bind already exposes the whole system for
*reading*: `journalctl`, `systemctl status`, `ls /etc`, config linting. With a
floor of `execution: sandbox` and `persistence: readonly` (or the default
`ephemeral`), the model can diagnose freely and cannot mutate anything.

## Tier 2 — captured mutation (the sysadmin sweet spot)

Pin the paths you want manageable as **`capture`** in the floor. Inside the
sandbox they appear writable; every write is staged into an overlayfs layer
instead of touching the live filesystem. Nothing merges until you review and
apply it:

```yaml
lisa-pack-bwrap:
  sandbox:
    floor:
      execution: sandbox
      persistence: overlay
      network: deny
      paths:
        /etc: capture
        /usr/local/etc: capture
        /var/log: ro
```

- The model edits `/etc/foo.conf` inside the sandbox; the live file is
  untouched. The change sits in `<data_dir>/cache/layers/<layer_id>/`.
- Review it with the `layers_export` operation (unified diffs + inventory
  under `<data_dir>/runs/layers-exports/<layer_id>/`).
- Apply it yourself with `layers_apply` — user-invoked, approval-gated,
  audited. The model never merges on its own.
- `capture` requires the overlay posture; combining capture paths with a
  looser persistence is a loud policy error, never a silent degrade.

Because captured writes are isolated in every other dimension (no network,
no capabilities — `CapEff=0`, isolated pid/ipc namespaces, capped tmpfs),
approval fatigue drops: the risky surface is exactly the merge step, which
you control.

## Tier 3 — privileged verbs (bare + approval, deliberately)

`systemctl restart`, package installs, and anything needing real host
privilege cannot be contained by an unprivileged namespace — and pretending
otherwise would be a security hole. These run under the **bare** tier:
`execution: bare` in the floor (or per-call when the floor permits), where
the containment fact marks the session not-contained, the host approval
engine prompts on mutating commands, and everything lands in the audit log.
Bare here means *visible and deliberate*, never silent.

## Choosing the floor

| Goal | Floor |
| --- | --- |
| Diagnosis only | `execution: sandbox`, `persistence: readonly` |
| Manage configs with review | add `paths: {/etc: capture, ...}` as above |
| Run privileged commands | `execution: bare` (approval engine gates every call) |

The model can only tighten above whatever floor you author — a request to
loosen any axis is rejected with the axis, the attempt, and your floor named
in the error.
