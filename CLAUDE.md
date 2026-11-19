Read `AGENTS.md`

## libsmb2 comes from our fork

SwiftSMB uses its own fork of libsmb2 directly:
[RuiNelson/libsmb2-SwiftSMB](https://github.com/RuiNelson/libsmb2-SwiftSMB), the Git submodule
`Vendored/libsmb2-SwiftSMB`. Upstream is [sahlberg/libsmb2](https://github.com/sahlberg/libsmb2).

- Keep the fork at least at the latest stable upstream release (`libsmb2-X.Y.Z` tag). Merge upstream `master` too
  when SwiftSMB needs a fix or feature from it.
- Merge upstream into the fork, never rebase, and keep our modifications through every merge.
- Changes to libsmb2 itself (code, configuration, crypto) are made in the fork, not as patches in SwiftSMB.
- `MODS.md` at the root of the fork lists every difference from upstream: what, why, files, upstream issue, and when
  to drop it. Update it in the same commit as the change, and update its "Upstream base" table after every merge.
- Code added to the fork must have an LGPL-2.1-compatible license (libsmb2 is LGPL-2.1-or-later): no Apache-2.0
  (OpenSSL 3+) or LGPL-3/GPL code. Bring in third-party code only for what libsmb2 lacks.
- Report bugs and offer fixes upstream, and drop a modification once upstream has an equivalent.

The move is in progress. SwiftSMB still builds from the old submodule `Sources/libsmb2/upstream` (pinned to
`libsmb2-7.0.0`), with the modifications in `Sources/libsmb2/patches`, `Sources/libsmb2/gcm` and
`Sources/libsmb2/include`. `MODS.md` lists them as M1–M5. Until they move into the fork and `Package.swift` builds
from `Vendored/libsmb2-SwiftSMB`, the libsmb2 rules in `AGENTS.md` describe that old layout. Where they disagree with
this section, this section wins. Update `AGENTS.md` as part of the move.
