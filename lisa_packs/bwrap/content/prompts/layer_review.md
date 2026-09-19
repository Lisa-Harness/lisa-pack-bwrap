# Reviewing and applying a captured layer

When a sandboxed run reports `backend: "overlay"`, its writes were **staged
into a capture layer** — a proposal, not an applied fix. The live filesystem
is untouched. The flow to finish that work is **export → review → apply**, and
the user drives the apply.

## The flow

1. **Relay the layer id.** Every overlay result carries `layer_id` (and
   `captured_paths` when extra capture paths were staged). Tell the user the
   change is staged and give them the `layer_id`.

2. **Export for review** — the `layers_export` operation renders the layer
   into a review directory:
   - one unified `.diff` per captured file (against the live target),
   - `inventory.json` (paths, sizes, modes, whiteouts),
   - `manifest.json` (which live path each captured target belongs to).
   Export is read-only; it writes only into the export directory.

3. **The user reviews.** The diffs live under
   `<data_dir>/runs/layers-exports/<layer_id>/`. Summarize them when asked,
   but the decision to merge is the user's — never claim a captured change is
   "done" or "applied".

4. **Apply is user-invoked** — `layers_apply` copies the captured upper dirs
   onto the live targets (honoring whiteouts as deletions). It mutates the
   live filesystem by design. Do not run it on your own initiative; the host
   surfaces it after review, and it may be approval-gated.

## What a layer contains

- Per capture target (the workspace capture root plus any `capture`-posture
  path pinned by the floor or requested via overrides), a `targets/<key>/`
  pair: `upper/` (the captured writes, owned by the real host user) and
  `work/` (overlayfs kernel scratch — ignore it).
- Whiteouts: character-device marker entries meaning "this file was deleted
  in the sandbox". Export renders them as deletions; apply performs them.

## Rules

- Never describe a staged change as merged, applied, or permanent until
  `layers_apply` actually ran.
- Never recommend `chown`/`chmod` on captured files "to fix ownership" —
  captured files are already owned by the user (see sandbox_ownership.md).
- If export or apply reports `degraded`, read the per-target reasons before
  advising; a missing manifest entry means the layer predates multi-target
  capture and should be re-captured, not force-applied.