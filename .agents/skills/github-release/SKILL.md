---
name: github-release
description: Prepare SwiftSMB GitHub releases. Use when Codex needs to draft release notes, validate release readiness, create or inspect a Git tag, or publish a GitHub release for this repository using the project's Semantic Versioning, Conventional Commits, and release-note conventions.
---

# GitHub Release

Use this skill to prepare and publish SwiftSMB releases on GitHub.

## Workflow

1. Establish the target version.
   - Use Semantic Versioning: `MAJOR.MINOR.PATCH`.
   - If the user did not provide a version, inspect tags, recent commits, and user intent before choosing one.
   - Release titles must be `Version X.X.X`.

2. Check repository readiness.
   - Inspect `git status --short`; do not overwrite unrelated user changes.
   - Inspect the current branch, latest tag, and commits since the latest tag.
   - Before committing release-related changes, run `format.sh`.
   - Run `SWIFTSMB_SKIP_INTEGRATION_TESTS=1 swift test` unless the user explicitly asks to skip tests or the environment cannot run them.
   - If release changes touch real SMB server behavior, start the Docker test server and run focused integration tests.

3. Draft release notes.
   - Use this exact structure, omitting sections with no content:

````markdown
## What's New

- **Feature description** - You can now...
- **Improvement description** - Now, you don't have to...

## Bug Fixes

- Fixed an issue where...
- Resolved a crash when...

## Migration Guide

Describe any breaking changes and what adopters need to update.

**Before:**

```swift
// Old usage
```

**After:**

```swift
// New usage
```
````

   - Add Swift examples when they help adopters understand a new capability.
   - Keep notes user-facing. Avoid internal-only commit noise unless it affects adopters.

4. Commit release preparation only when files changed.
   - Use Conventional Commits.
   - Example commit message: `chore: prepare 1.2.3 release`.

5. Tag and publish.
   - Prefer annotated tags: `git tag -a X.X.X -m "Version X.X.X"` unless the project already uses another tag style.
   - Push the release commit before publishing.
   - Push the tag.
   - Create the GitHub release with title `Version X.X.X` and the drafted notes.
   - Use the GitHub app tools when available; use `gh release create` or `gh release edit` as a fallback.

## Guardrails

- Do not expose credentials, password-file APIs, or private test-server details in release notes.
- Keep `README.md` and `docs/` in sync with public API changes before releasing.
- Do not create a release from a dirty tree unless the remaining changes are explicitly unrelated and the user confirms proceeding.
- If a tag or release already exists, inspect it before modifying it. Prefer editing the existing draft/release over creating a duplicate.
