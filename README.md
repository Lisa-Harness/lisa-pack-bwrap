# lisa-pack-bwrap

Bubblewrap sandbox capability for Lisa: namespace isolation with transparent
overlayfs capture layers. This pack owns the **containment policy** — a
harness-set floor the model can only tighten, never loosen — and the sandbox
runtime that `bash_run` composes through.

> The model-facing shell is the sibling pack [`lisa-pack-bash`](../bash/README.md).
> `bash_run` is the user-facing approval boundary; this pack is its sandbox
> backend. `bwrap_pack` also works standalone (its `bwrap_run` tool runs an
> argv directly inside a sandbox).

## What the pack provides

| Kind | Id | Role |
| --- | --- | --- |
| Tool | `bwrap_run` | Run an argv inside a bubblewrap sandbox whose containment is set by the harness floor, not the model. `approval_required: false` — approval lives on `bash_run`. |
| Operation | `layers_list` | Read-only: list overlayfs layers (id, path, size) so the user/model can inspect sandbox-captured state. |
| Operation | `layers_export` | Read-only: render a layer as reviewable unified diffs + inventory + manifest under `<data_dir>/runs/layers-exports/<id>/`. |
| Operation | `layers_apply` | User-invoked write: apply a reviewed layer's captured writes to the live capture targets (honors whiteouts). |
| Entry point | `lisa.extensions.prerequisites` | `policy.check_prerequisites` — host startup fails hard if bubblewrap is absent (no silent unsandboxed proceed). |
| Entry point | `lisa.extensions.content_roots` | `lisa_packs.bwrap:get_content_root`. |

## The trust model: harness floor + tighten-only overrides

Containment is decided by the **harness floor** — the least-restrictive
posture the user (harness) will permit — read from
`ctx.pack_config['sandbox']['floor']`. That channel is trusted (populated by
the lisa kernel from session `resources.packs.configuration`); model tool
parameters cannot forge it. The model passes tightening `overrides` and may
only *raise* integrity above the floor; asking for anything looser is a hard
`PolicyError` that names the axis, the attempt, and the floor — the boundary
is taught loudly, not silently clamped.

### Containment axes (loosest → tightest)

Each axis is ordered independently; the effective profile is the
most-restrictive join of floor and request (with pack defaults filling axes
the floor leaves unspecified):

| Axis | Order | Effect |
| --- | --- | --- |
| `execution` | `bare` < `sandbox` | Run on host vs. inside bwrap. |
| `persistence` | `direct-write` < `overlay` < `ephemeral` < `readonly` | Where writes land (see backends). |
| `network` | `allow` < `deny` | `deny` emits `--unshare-net`. |
| `device` | `dev` < `minimal` < `none` | `none` binds only `/dev/null`; `minimal` is the safe synthetic `/dev`. |
| `ipc` | `shared` < `unshared` | `unshared` emits `--unshare-ipc`. |
| `tmpfs_budget_bytes` | unbounded → finite | Size cap on the writable `/tmp` tmpfs (`--size N`). |
| `timeout_ceiling_seconds` | unbounded → finite | Floor can only be lowered; only an explicitly larger requested cap violates. |
| `paths` | per-path `rw` < `capture` < `ro` < `hidden` | Per-path visibility: real bind / overlay-captured bind / ro-bind / omit. `capture` stages writes for that path into the layer instead of the live filesystem (requires the overlay posture; a capture path joined with a looser persistence is a loud `PolicyError`). |

```python
resolve_effective(floor, request, defaults=default_posture())
```

joins the floor with a model request into the effective profile. An
*explicit* request to loosen below the floor raises `PolicyError`; a request
field left unspecified (riding the pack default) is silently tightened up to
the floor.

### Shipped defaults

- **`default_posture()`** — what a bare model request starts from:
  sandboxed, ephemeral persistence, no network, minimal `/dev`, unshared IPC.
- **`default_floor()`** — the pack's fail-safe floor when the harness sets
  none: sandboxed; overlay as the *allowed ceiling* (model may tighten to
  ephemeral/readonly but never loosen to direct-write); network denied;
  minimal device; `/run/log/journal` read-only; `/tmp` capped at 64 MiB.

The harness overrides any axis via `packs.configuration` → `sandbox.floor`
(unknown keys or invalid values are loud `PolicyError`s — a typo in policy
must never be silent).

## Backends: where writes actually go

Two capture backends, chosen by the effective persistence posture:

### tmpfs (default — `persistence: ephemeral` / `readonly`)

`TmpfsBackend`: mutations go to an ephemeral in-sandbox tmpfs and are
**discarded when the namespace exits**. This is the default — writes never
touch the real filesystem.

- `ephemeral`: the workspace is bound **read-only at its real path**, plus a
  writable, host-visible per-session scratch dir
  (`<data_dir>/scratch/<session_key>`, tempdir fallback when no `data_dir`).
  The model analyzes the RO workspace and stages a patch/script under
  `scratch_dir` for the user.
- `readonly`: binds **no** writable paths at all.

### overlay (opt-in — `persistence: overlay`, `persist`, `layer_id`, or a `capture` path)

`OverlayBackend`: writes are captured in a per-target overlayfs `upper` under
`<data_dir>/layers/<layer_id>/targets/<key>/`, one overlay **per capture
target** — the workspace capture root plus any `capture`-posture path — each
sharing the layer id. Runs only when the effective persistence is overlay
**and** the launcher chain probe passes; otherwise the request degrades to
ephemeral *explicitly* (`degraded: true` + reason) — never silently.

The mounts are performed by a root-mapped launcher — `unshare --user
--map-root-user --mount` — **before** bwrap runs, because bwrap always drops
every capability from the child (`CapEff=0`), so a child-side `mount(2)` is
structurally denied (EPERM). The verified chain: the launcher mounts one
overlay per target onto the target's own path, then execs bwrap which binds
each merged view read-write at its real path and ends `--cap-drop ALL`. The
sandboxed child can read and write through the merged views but can never
mount, unmount, or see the workdirs; captured files land owned by the real
host user.

- Mutations are captured either way; `persist` only controls whether the layer
  is retained past the session (`persistence: "persistent"` vs `"session"`).
- `layer_id` is validated against path traversal (`sanitize_layer_id`);
  empty defaults to a per-session id (`session-<key>`). Result JSON reports
  `backend`, `persistence`, `layer_id`, `capture_root`, `scratch_dir`, and
  `captured_paths` (the extra capture targets beyond the workspace).
- `layers_list` enumerates layers; `layers_export` renders a reviewable
  diff/inventory; `layers_apply` (user-invoked) merges a reviewed layer onto
  the live targets. The model relays the `layer_id`; the user reviews and
  applies — the model-facing contract is `content/prompts/layer_review.md`,
  and the sysadmin setup is the next section.

## The admin posture: system management without going bare

You want Lisa to help manage this machine — read logs, edit configs under
`/etc`, stage service changes — without handing over unsandboxed host
execution. The containment axes support a three-tier posture that keeps
almost all of that work contained. **Privileged verbs (`systemctl`,
`zypper`/`dnf`/`apt install`, user management) can never run inside an
unprivileged sandbox** — those stay on the bare tier, where every call is
approval-prompted and audited.

### Tier 1 — contained diagnosis (read-only, zero risk)

The sandbox's read-only root bind already exposes the whole system for
*reading*: `journalctl`, `systemctl status`, `ls /etc`, config linting. With a
floor of `execution: sandbox` and `persistence: readonly` (or the default
`ephemeral`), the model can diagnose freely and cannot mutate anything.

### Tier 2 — captured mutation (the sysadmin sweet spot)

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

### Tier 3 — privileged verbs (bare + approval, deliberately)

`systemctl restart`, package installs, and anything needing real host
privilege cannot be contained by an unprivileged namespace — and pretending
otherwise would be a security hole. These run under the **bare** tier:
`execution: bare` in the floor (or per-call when the floor permits), where
the containment fact marks the session not-contained, the host approval
engine prompts on mutating commands, and everything lands in the audit log.
Bare here means *visible and deliberate*, never silent.

### Choosing the floor

| Goal | Floor |
| --- | --- |
| Diagnosis only | `execution: sandbox`, `persistence: readonly` |
| Manage configs with review | add `paths: {/etc: capture, ...}` as above |
| Run privileged commands | `execution: bare` (approval engine gates every call) |

The model can only tighten above whatever floor you author — a request to
loosen any axis is rejected with the axis, the attempt, and your floor named
in the error.

## `bwrap_run` parameters

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `argv` | list[string] | **required** | Command + args to run inside the sandbox. |
| `timeout_seconds` | int | `60` | 1–3600; subject to the floor's `timeout_ceiling_seconds`. This kills a silent child. The kernel wrapper is disabled for this tool (`timeout_seconds: 0` in `bwrap_run.tool.yml`) — bwrap_run self-bounds. |
| `cwd` | string | `""` | Working directory inside the sandbox; must resolve under the capture root, scratch dir, or a writable path override (anything else is ignored). |
| `overrides` | object | `{}` | Tightening-only: `persistence` (`direct-write`\|`overlay`\|`ephemeral`\|`readonly`), `network` (`allow`\|`deny`), `paths` (`{path: rw\|capture\|ro\|hidden}`). Only `rw` paths that are real absolute directories are honored as extra writable binds; `capture` paths that are real absolute directories are honored as extra overlay targets (implying the overlay posture). |
| `persist` | bool | `false` | Retain the captured overlay layer after the session (overlay only). |
| `layer_id` | string | `""` | Explicit overlay layer id; selects the overlay posture. |

A requested `layer_id`/`persist` implies `persistence: "overlay"` when the
request didn't already set it.

### Why the tool disables the kernel wrapper

The kernel wraps every tool call in
`asyncio.wait_for(..., timeout=timeout_seconds)` unless the `.tool.yml`
declares `timeout_seconds: 0`, and defaults to **30 s** when the value is
omitted. `bwrap_run` is dispatched by `bash_run` with a deliberately extended
timeout (the sandboxed auto-background grace window — up to 3600 s), so no
static wrapper bound can be sized to it. The 2026-10-05 shell turn lost a
command exactly this way: the inherited 30 s wrapper cancelled `bash_run` at
30 s, then the in-flight `bwrap_run` child at 33 s, and the orphaned task
surfaced as "Task exception was never retrieved". `bwrap_run.tool.yml`
therefore declares `timeout_seconds: 0` (self-bounding): its own parameter
kills a silent child and `stream_output: true` publishes progress on
`lisa.tool_output` while it runs. The declaration is pinned by
`tests/test_catalog.py`.

Every result carries its real posture: `sandboxed: true`, `backend`,
`persistence`, `return_code`, `stderr`, `timed_out`, `truncated`,
`capture_root`, `scratch_dir`, `cwd`, `writable_paths`, `captured_paths`, plus
`layer_id` when overlay ran and the `identity` block on every sandboxed
success (error paths carry none — the sandbox never ran). Output is capped at
512 KiB; commands and output are appended to a per-session audit log at
`<data_dir>/logs/bwrap-<key>.log`.

### File ownership inside the sandbox (the `identity` block)

Unprivileged bwrap can only install a **single-entry uid map** — the invoking
host user maps to sandbox uid 0, nothing else is mapped. `stat(2)` inside the
namespace can only resolve owners inside the map, so:

- the model runs as **mapped root**; its own files display as `root:root`;
- files owned by any *other* host uid — including real root's — display as
  `nobody:nobody` (overflow uid 65534).

That is a **display artifact of the user namespace, not a permissions or
ownership change**. On-disk ownership is unchanged, and overlay-captured
files map back to the real host user outside the sandbox. Every sandboxed
result stamps an `identity` block (`sandbox_uid`, `sandbox_gid`, `host_uid`,
`host_gid`, `host_user`, `map`, `note`) so the model never misreads owner
columns — and the long-form guidance lives in
`content/prompts/sandbox_ownership.md` (the never-`chown` rule, the `ls -n`
recommendation, and when `nobody:nobody` genuinely matters). The
`bwrap_run.tool.yml` description teaches the same contract in the catalog.

### The generated argv

`argv_builder.build_bwrap_argv_for_profile` emits the containment from the
resolved profile: `--unshare-pid --unshare-uts` (plus `--unshare-ipc`,
`--unshare-net` per floor), a read-only root bind, `/proc`, `/dev` per device
tier, size-capped `/tmp`, backend bind args, then floor/override per-path
binds on top. Lifecycle flags `--die-with-parent --new-session` keep the
sandbox from outliving the parent. Pure argv construction — no I/O, no side
effects.

## Capability probing & graceful degradation

`probe.detect_capabilities()` is a *real* runtime probe, not a `which` check:
it runs a trivial namespaced command, then probes the exact **launcher chain**
the overlay backend uses (`unshare --user --map-root-user --mount` mounts an
overlay, then execs bwrap which binds the merged view and ends `--cap-drop
ALL`). A probe whose argv differs from the real path can lie in both
directions — so this one mirrors it faithfully. The probe tells apart:

1. **binary absent** → sandbox unavailable, remediation points at the host
   package (`zypper/dnf/apt/pacman install bubblewrap`) and unprivileged
   user namespaces;
2. **kernel/LSM denies the overlay mount** → namespaces still isolate;
   mutations fall back to ephemeral tmpfs (host-fixable: enable unprivileged
   overlay / adjust LSM policy);
3. **`unshare` absent** → the launcher chain cannot run; capture is
   unavailable (install util-linux) but ephemeral tmpfs still works.

When the pack is registered but the host can't run it, every error path
carries a `missing` list, and results are stamped `sandboxed: false` /
`degraded: true` with `content/prompts/sandboxing_degraded.md` attached —
capability detection at routing time is never confused with runtime
availability. Model-facing authored docs under `content/prompts/`:

- `sandboxing_degraded.md` — what is degraded and how to enable the sandbox.
- `sandbox_ownership.md` — the uid-map identity contract: why `nobody:nobody`
  appears inside the sandbox, why it is not an error, and the never-chown
  rule. The `lisa.extensions.prerequisites` entry point
(`check_prerequisites`) lets the host fail hard at startup when bubblewrap is
absent, so it never silently proceeds unsandboxed.

## Relationship to `lisa-pack-bash`

`bash_run` composes through this pack as its sandbox backend using a child
`ToolExecutionContext` (pack config forwarded so the floor and workspace
resolution keep working). Approval stays on `bash_run`; this pack emits the
containment fact and the policy join. `bwrap_run` can also be called directly
when a raw sandboxed argv (rather than a shell command) is wanted. See the
[bash README](../bash/README.md) for the session, state carryover, and job
model the sandbox plugs into.

## Development

```bash
cd bwrap
/home/adam/Code/lisa/.venv/bin/python -m pytest -p no:cacheprovider
```

Tests live in `lisa_packs/bwrap/tests/`. The `live` marker runs a real bwrap
sandbox and requires bubblewrap + unprivileged user namespaces on the host;
run `-m "not live"` and `-m live` separately. Policy and argv construction are
pure and unit-tested without a sandbox.
