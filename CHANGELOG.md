# Changelog

All notable changes to the Lisa bwrap pack are documented here.

## [0.1.1]

### Fixed

#### A malformed layer manifest no longer crashes the layer operations

- **What:** the export and apply paths read the layer's `manifest.json`
  and iterated its `targets` entries directly. A row that was not a dict
  raised `AttributeError` from `entry.get`, and an entry missing its key
  or path was used as-is. Both are now skipped: the export path treats an
  unusable row as "unknown live target", and the apply path drops an entry
  without a usable key/path pair rather than pointing the merge at a
  bogus path.
- **Why:** the manifest is written at layer creation, but it is also a
  file on disk that a user can edit and that a partial write can
  truncate. A malformed manifest turned a reviewable export into a
  stack trace, and could have pointed an apply at the wrong path.
- **What:** the behavior is now covered by tests that fail against the
  old code.

### Changed

- The POSIX-only surface the pack calls (`os.getuid`, `os.getgid`,
  `os.killpg`, `pwd.getpwuid`) is now collected behind small wrappers in
  `posix_host.py`, each guarded by an explicit platform check. On a
  supported host the calls are unchanged; on a non-POSIX host the
  wrappers report "unavailable" instead of raising `AttributeError`.
- The pack now ships a CI workflow that gates it with `ruff format`,
  `ruff check`, `mypy`, and its non-live tests, and `.gitattributes`
  keeps line endings as LF so a Windows checkout cannot rewrite them and
  fail the format check.
- The CI matrix is Linux-only on purpose: bubblewrap, overlayfs mounts
  with the `userxattr` option, and `unshare --user --map-root-user` are
  all Linux kernel features, so a green job on another host would only
  prove the code imports.

## [0.1.0]

- First public release.
