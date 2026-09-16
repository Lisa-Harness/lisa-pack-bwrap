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
| `paths` | per-path `rw` < `ro` < `hidden` | Per-path visibility (bind / ro-bind / omit). |

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

### overlay (opt-in — `persistence: overlay`, `persist`, or `layer_id`)

`OverlayBackend`: writes are captured in an overlayfs `upper` under
`<data_dir>/layers/<layer_id>/`, with the workspace as lowerdir at its real
path (`capture_root`). Runs **only** when the effective persistence is overlay
**and** unprivileged overlayfs (`userxattr`) is available; otherwise the
request degrades to ephemeral *explicitly* (`degraded: true` + reason) — never
silently.

- Mutations are captured either way; `persist` only controls whether the layer
  is retained past the session (`persistence: "persistent"` vs `"session"`).
- `layer_id` is validated against path traversal (`sanitize_layer_id`);
  empty defaults to a per-session id (`session-<key>`). Result JSON reports
  `backend`, `persistence`, `layer_id`, `capture_root`, `scratch_dir`.
- `layers_list` enumerates layers (id, path, recursive size) for inspection.
  v1 is deliberately read-mostly; export/teardown/diff are deferred to v2.

## `bwrap_run` parameters

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `argv` | list[string] | **required** | Command + args to run inside the sandbox. |
| `timeout_seconds` | int | `60` | 1–3600; subject to the floor's `timeout_ceiling_seconds`. |
| `cwd` | string | `""` | Working directory inside the sandbox; must resolve under the capture root, scratch dir, or a writable path override (anything else is ignored). |
| `overrides` | object | `{}` | Tightening-only: `persistence` (`direct-write`\|`overlay`\|`ephemeral`\|`readonly`), `network` (`allow`\|`deny`), `paths` (`{path: rw|ro|hidden}`). Only `rw` paths that are real absolute directories are honored as extra writable binds. |
| `persist` | bool | `false` | Retain the captured overlay layer after the session (overlay only). |
| `layer_id` | string | `""` | Explicit overlay layer id; selects the overlay posture. |

A requested `layer_id`/`persist` implies `persistence: "overlay"` when the
request didn't already set it.

Every result carries its real posture: `sandboxed: true`, `backend`,
`persistence`, `return_code`, `stderr`, `timed_out`, `truncated`,
`capture_root`, `scratch_dir`, `cwd`, `writable_paths`, plus `layer_id` when
overlay ran and the `identity` block on every sandboxed success (error paths
carry none — the sandbox never ran). Output is capped at 512 KiB; commands
and output are appended to a per-session audit log at
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
it runs a trivial namespaced command, then differentially classifies whether
unprivileged overlayfs mounts work inside bwrap (mirroring the real overlay
argv shape). The probe tells apart:

1. **binary absent** → sandbox unavailable, remediation points at the host
   package (`zypper/dnf/apt/pacman install bubblewrap`) and unprivileged
   user namespaces;
2. **kernel/LSM denies the overlay mount** → namespaces still isolate;
   mutations fall back to ephemeral tmpfs (host-fixable: enable unprivileged
   overlay / adjust LSM policy);
3. **bwrap drops all capabilities** (`CapEff=0`; `mount(2)` needs
   `CAP_SYS_ADMIN` in the owning userns) → overlay capture is *structurally*
   unavailable; ephemeral tmpfs still works. **Not host-fixable** — don't
   retry `persist`/`layer_id`, don't tell the user to reinstall.

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
