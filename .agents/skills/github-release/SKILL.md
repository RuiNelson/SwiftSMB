---
name: github-release
description: Prepare SwiftSMB GitHub releases. Use when drafting release notes, choosing a semantic version, validating release readiness, creating or inspecting a Git tag, or publishing a GitHub release for this repository.
---

# GitHub Release

Use this skill to prepare and publish SwiftSMB releases on GitHub. Keep the process self-contained; do not depend on
release template files in the repository. The workflow, notes format and guardrails are shared with the sibling
SwiftSFTP/SwiftSMB skills; only `Project Conventions` differs between them.

## Workflow

1. Inspect repository state.
   - Check `git status --short`, the current branch, the latest tag, and the commits since that tag.
   - Do not overwrite or revert unrelated user changes. Do not release from a dirty tree unless the remaining changes
     are unrelated and the user confirms proceeding.
2. Choose the version with Semantic Versioning (`MAJOR.MINOR.PATCH`). If the user did not give one, propose it from
   the changes since the latest tag and confirm it:
   - Patch for backwards-compatible bug fixes.
   - Minor for backwards-compatible features or improvements.
   - Major for breaking API or behavior changes.
3. Draft release notes from the changes since the previous tag. Prefer commit history, merged PRs, changelog entries,
   and user-provided context over guesswork. Follow `Release Notes Format` and `Notes Style`.
4. Validate release readiness with the format, build and test commands in `Project Conventions`. Report any step that
   could not run (for example, no Docker test server) instead of skipping it silently.
5. Prepare the release commit, only when files change.
   - Update the version in the installation snippets (`from: "X.Y.Z"`) in the files listed in `Project Conventions`,
     and keep `README.md` and the guides in sync with public API changes.
   - Run the format script, then commit with Conventional Commits: `chore: prepare X.Y.Z release`.
   - Push the release commit before tagging.
6. Tag the release commit.
   - Tags are `v`-prefixed and annotated: `git tag -a vX.Y.Z -m "Version X.Y.Z"`, then `git push origin vX.Y.Z`.
   - If the tag or release already exists, inspect it first. Do not overwrite a tag unless the user explicitly asks;
     prefer editing an existing draft or release over creating a duplicate.
7. Publish the GitHub release for tag `vX.Y.Z` with title `Version X.Y.Z` and the drafted notes. Use the GitHub tools
   when available; otherwise `gh release create vX.Y.Z --title "Version X.Y.Z" --notes-file <notes>`, or
   `gh release edit` to fix an existing one.
8. Report the version, tag, validation performed (and anything not run), and the release URL.

## Project Conventions

- Format: `./format.sh`.
- Build: `swift build --traits EXIFKit`.
- Test: `SWIFTSMB_SKIP_INTEGRATION_TESTS=1 swift test --traits EXIFKit`. If the release touches real SMB server
  behavior, start the Docker test server (`source TestServer/up.sh`) and run focused integration tests.
- Vendored sources: libsmb2 comes from the pinned `Sources/libsmb2/upstream` submodule; keep it read-only.
- Version snippets: `README.md` and `docs/`.

## Release Notes Format

Use only the sections that apply.

````markdown
## What's New

- **Feature description** - You can now...
- **Improvement description** - Now, you don't have to...

Add short code examples when they help adopters understand a new capability:

```swift
// Example usage
```

## Bug Fixes

- Fixed an issue where...
- Resolved a crash when...

## Migration Guide

Describe breaking changes and what adopters need to update.

**Before:**

```swift
// Old usage
```

**After:**

```swift
// New usage
```
````

## Notes Style

- Write for adopters of the library, not for maintainers.
- Group changes by user impact.
- Include only changes that affect how adopters use the library or the behavior they experience.
- Omit CI, release automation, repository maintenance, internal benchmarks, formatting-only changes, and other
  maintainer-facing work.
- Omit build-system or packaging changes unless they alter a supported platform, compatibility requirement, dependency,
  installation workflow, or another outcome visible to adopters.
- Omit empty sections.
- Keep bullets concrete and concise.
- Mention breaking changes in `Migration Guide`; do not bury them under features.
- Include code examples only when they clarify usage or migration.
- Never include credentials, password-file APIs, or private test-server details.
