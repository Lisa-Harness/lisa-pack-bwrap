# File ownership inside the sandbox

Every sandboxed result carries an `identity` block. Read it before you interpret
any `ls -l`, `stat`, or `find -printf %u:%g` output from inside the sandbox.

## What you will see

- You run as **mapped root** (uid 0) inside the sandbox.
- **Your own files display as `root:root`** inside the sandbox.
- **Files owned by any other host uid — including the real root's files —
  display as `nobody:nobody`** (the numeric overflow uid 65534).

## Why: the single-entry uid map

Unprivileged bubblewrap creates a user namespace with a **single-entry uid
map**: your host user (for example `adam(1000)`) maps to sandbox uid 0, and
nothing else is mapped. When a process inside the namespace asks `stat(2)` who
owns a file, the kernel can only translate uids that exist in the map. Any uid
outside it — host root (0), other users, daemon accounts — falls through to the
overflow uid 65534, which `ls` renders as `nobody:nobody`.

This is a **display artifact of the namespace view**, not a permissions or
ownership change.

## What is true on disk

- On-disk ownership is **unchanged** by the sandbox.
- Overlay-captured writes (persistence `overlay`) land in the layer's `upper/`
  directory carrying the mapped uid, which **maps back to your real host uid**
  outside the sandbox. Files the user inspects after capture are owned by them,
  not by nobody or root.
- tmpfs scratch writes (persistence `ephemeral`) vanish with the namespace
  regardless.

## What you must NOT do

- **Never `chown` or `chmod` to "repair" owners inside the sandbox.** The
  `nobody:nobody` you see is not wrong; "fixing" it is.
  - In ephemeral mode such writes are discarded (harmless, but wasted).
  - In overlay mode they pollute the capture layer with bogus ownership
    metadata that flows into the merge proposal.
- Do not report `nobody:nobody` as an error condition to the user. If it
  matters for the task, explain it as the uid-map artifact it is.
- Numeric ids (`ls -n`, `stat -c %u:%g`) are more reliable than names here:
  anything mapping to 65534 means "owner is outside the sandbox's uid map".

## When it actually matters

`nobody:nobody` would be a real problem if the user sees it **outside** the
sandbox (on the host) — for example on a network mount or a botched rsync.
Inside the sandbox it is expected. Distinguish by checking `sandboxed` on the
result before drawing conclusions from owner columns.