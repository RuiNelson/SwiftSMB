# SwiftSMB Agent Notes

## Project Overview

SwiftSMB is a Swift Package Manager library that wraps `libsmb2` to access SMB shares from Swift. It is cross-platform and aims to be compatible with Linux and Windows in addition to Apple platforms.

The user-facing cookbook lives in `README.md` (quick examples) and `docs/` (detailed guides). Keep those in sync when public APIs change.

## Project Tree

```text
.
├── libsmb2                                   # Git submodule of libsmb2.
├── Package.swift                             # Swift Package Manager manifest.
├── Sources
│   └── SwiftSMB
│       ├── Bridge                            # Internal libsmb2 bridge; no public API here.
│       │   ├── Extensions
│       │   │   ├── Int.swift                 # Extensions to `Int`
│       │   │   └── String?.swift             # Extensions to `String?`
│       │   ├── Bridge.swift                  # High-level synchronous POSIX-like bridge calls.
│       │   ├── SMB2BridgeTypes.swift         # Bridge structs/enums/options nested under `extension Bridge`.
│       │   └── SMBError+Bridge.swift         # SMB.Error bridge factory and check() helper.
│       └── PublicAPI                         # User-facing API, all organized under SMB.
│           ├── SMB.swift                     # public final class SMB; no public initializers.
│           ├── SMBOperations.swift           # Static top-level operations: connect/listShares/parseURL.
│           ├── SMBConfiguration.swift        # Server, credentials, and connection configuration.
│           ├── SMBConnection.swift           # Connection handle, state, and primitive bridge operations.
│           ├── SMBConnection-Conv.swift      # Connection convenience methods built from primitives.
│           ├── SMBConnection-Conv-Pipe.swift # Named-pipe convenience methods.
│           ├── SMBFile.swift                 # OOP file handle.
│           ├── SMBFile-Conv.swift            # File convenience methods built from primitives.
│           ├── SMBDirectory.swift            # OOP directory handle.
│           ├── SMBDirectory-Conv.swift       # Directory convenience methods built from primitives.
│           ├── SMBNotify.swift               # Delegate-based public SMB directory notifications.
│           ├── SMBValues.swift               # Public value types.
│           ├── SMBError.swift                # Public error type.
│           ├── SMBError-InvalidArgument.swift # Typed invalid-argument operations and causes.
│           ├── SMBPathValidation.swift       # Share-name and share-relative path validation.
│           ├── SMBStatus.swift               # SMB.SMBStatus and SMB.SMBStatusSeverity.
│           └── Util
│               ├── DataPipe.swift            # A bounded data pipe that synchronises a single producer with a single consumer.
│               ├── Date+.swift               # Date helpers for SMB timestamp values.
│               ├── OptionSet+DebugDescription.swift # Shared debug formatting helpers.
│               └── Protected.swift           # DispatchQueue-backed state wrapper for Sendable handles.
├── Tests
│   └── SwiftSMBTests
│       ├── Bridge                            # Bridge tests; most are Samba integration tests.
│       │   ├── ConnectionTests.swift         # Context configuration and connection lifecycle tests.
│       │   ├── DirectoryTests.swift          # Directory create, remove, and list tests.
│       │   ├── FileTests.swift               # File open, read, write, seek, and stat tests.
│       │   ├── IntegrationSupport.swift      # Shared helpers and server credentials for integration tests.
│       │   ├── ShareTests.swift              # Share enumeration and info tests.
│       │   └── TypeTests.swift               # Value types, errors, and enum raw-value unit tests (no server).
│       ├── PublicAPI                         # Public API unit tests.
│       │   ├── SMBConnectionDirectoryTests.swift # Directory convenience public API tests.
│       │   ├── SMBConnectionPipeTests.swift  # Named-pipe public API tests.
│       │   ├── SMBNotifyTests.swift          # Notification public API and integration tests.
│       │   └── SMBPublicAPITests.swift       # URL parsing and public value type tests.
│       └── Utils
│           └── DataPipeTests.swift           # DataPipe backpressure and ring-buffer unit tests.
└── TestServer                                # Docker Samba server for integration tests.
```

## Bridge Layer

- `Bridge` is a `class` (not a namespace enum) with all-static methods. All bridge types (e.g., `SMB2Context`, `SMB2FileHandle`, `SMB2OpenFlags`) are nested inside `Bridge` via `extension Bridge { ... }` in `SMB2BridgeTypes.swift`.
- Outside the `Bridge` class, reference bridge types with the `Bridge.` prefix (e.g., `Bridge.SMB2Context`). Inside the class or its extensions, types resolve without prefix.
- Keep `Bridge.swift` focused on the high-level synchronous POSIX-like API described in `libsmb2/include/smb2/libsmb2.h`.
- Bridge functions should expose Swift-shaped arguments and return values (`String`, `Bool`, `UInt64`, `Int64`, Swift structs/enums/options) and convert to C types only at the boundary.
- Functions that correspond directly to C `get` functions should keep `get` in the Swift bridge name, even though this is not typical Swift style.
- Do not expose raw C flags as plain integers. Use Swift `enum` or `OptionSet` types instead. Examples: `Bridge.SMB2OpenFlags`, `Bridge.SMB2SecurityMode`, `Bridge.SMB2AuthenticationMethod`.
- C return values that signal errors through negative `errno` values or `NULL` should become `throw`.
- Keep SMB/NT status handling granular. Public status values live under `SMB.SMBStatus` and `SMB.SMBStatusSeverity`; unknown NTSTATUS values should still preserve their raw value in `SMB.Error.unknownNTStatus`.
- Passing `Bridge.SMB2Context` as a normal parameter is preferred for now. It is a lightweight Swift wrapper around a C pointer; avoid `inout`, `borrowing`, or `consuming` unless the type is redesigned for explicit ownership.
- Path separator: `libsmb2` accepts `/` (POSIX-style) in its public API but converts to `\` (Windows-style) internally before sending SMB2 requests to the server (see `libsmb2.c:smb2_rename` and `smb2-cmd-create.c`). Use `/` in the Swift public API and bridge layer.
- `libsmb2` contexts are not safe to service concurrently. Public API calls should go through `Bridge.sync { ... }` so bridge work is serialized behind the bridge queue. Notification watcher bridge calls (`notifyChange`, `serviceNotifyEvents`, `cancel`, and close) must also go through this path.
- The bridge intentionally exposes a one-shot raw-PDU notification primitive. The public layer owns the directory handle, re-arms requests for continuous watching, cancels pending requests before close/context teardown, and services the context while the watcher is active.
- Keep notify response decoding defensive. Do not call the recursive C `smb2_decode_filenotifychangeinformation` helper from public watcher paths unless it has been audited for malformed server data; the Swift decoder currently validates entry bounds, monotonic offsets, and an entry-count cap.
- Retry `poll` on `EINTR` in Swift-owned service loops.

## Public API

- `SMB` is a `public final class` with no public initializers. Use static methods for top-level operations such as `connect`, `listShares`, and `parseURL`.
- Keep `SMB.Connection`, `SMB.File`, `SMB.Directory`, and `SMB.NotifyWatcher` as OOP handles nested under `SMB`.
- Use Swift strict concurrency checking. Public handle types should conform to `Sendable`; protect mutable/internal state with `DispatchQueue`-backed wrappers such as `Protected` under `Sources/SwiftSMB/PublicAPI/Util`.
- Prefer friendly API behavior when it is unambiguous. For example, clamp requested transfer block sizes to the server maximum and return the accepted value from accepted block-size helpers.
- Keep credentials out of `SMB.Configuration`; pass them to connection/listing entry points.
- Do not expose password-file APIs publicly.
- Add DocC comments to public API at Apple documentation quality. Private and internal members may use concise one-line comments where useful. `SMB.SMBStatus` does not need exhaustive DocC.
- Public share names and share-relative paths are validated through `SMBPathValidation.swift` using PathWorks. Leading `/` is normalized away for paths; the share root is accepted only when the operation explicitly allows it.
- File convenience methods are named `loadFile(at:)` and `dumpToFile(_:to:)`; avoid reintroducing the older `readFile`/`writeFile` names.
- Directory conveniences include recursive `makeDirectory(at:makePath:)`, recursive `removeItem(at:)`, `listDirectory(at:)`, and `itemExists(at:)`.
- File transfer convenience APIs use `DataPipe`, support cancellation/progress, and may create temporary remote paths for atomic uploads. Preserve the `.start` / `.data` / `.finish` / `.broken` package protocol.
- Public notifications are delegate-based: `SMB.Connection.watchDirectory(...)` returns `SMB.NotifyWatcher`, which calls `SMB.NotifyWatcherDelegate`. Keep the delegate weak, deliver callbacks on the requested queue, and keep watcher cancellation idempotent.
- `SMB.NotifyWatcherDelegate.notifyWatcherDidStart(_:)` is used by tests and clients to know the first notify request has been armed; do not replace it with sleeps or timing assumptions.
- Public values generally conform to `CustomDebugStringConvertible`; use `describeFlags` and `hex` helpers from `PublicAPI/Util/OptionSet+DebugDescription.swift` for consistent debug output.

## Testing

- Unit tests (no server needed): `TypeTests.swift` covers value types, error cases, and enum raw values.
- Integration tests (need server): most tests under `Tests/SwiftSMBTests/Bridge/`, plus public API integration suites such as directory, pipe, and notify tests under `Tests/SwiftSMBTests/PublicAPI/`. Tagged with `.integration`.
- Run all tests: `swift test`
- Run a subset: `swift test --filter 'ConnectionTests'`
- Notification-focused tests: `swift test --filter 'SMBNotify'`
- The test server is a Docker-based Samba container.
  - Check whether it is already running: `docker ps --filter ancestor=swiftsmb-testserver`
  - Start: `source TestServer/up.sh`
  - Stop: `source TestServer/down.sh`
  - Dockerfile with SAMBA configuration in `TestServer/Dockerfile`
  - Port: localhost:44445 (mapped from container 445)
- If integration tests fail with connection refusals, check that the test server is running (`docker ps`).

## Concurrency & Dispatch

- **Never use `DispatchQueue.global()`.** The global concurrent queue has a limited thread pool subject to exhaustion under heavy system load. Blocking work dispatched there can hang when all threads are occupied, because a caller waiting on a semaphore or pipe may never see the dispatched block execute. Use dedicated serial dispatch queues (created with `DispatchQueue(label:)`) for all async work, especially producer/consumer patterns that rely on semaphore-based backpressure like `DataPipe`.

## Code Style & Commits

- **Before committing**, always format the code with:
  ```bash
  format.sh
  ```
- SwiftFormat may rewrite nearby numeric literals or trailing commas. That is expected; keep formatter output unless it causes a functional problem.

## Versioning & Releases

- This project follows **Semantic Versioning** (`MAJOR.MINOR.PATCH`).
- Use the Conventional Commits specification for all commit messages.
- Use the release notes template at `etc/Release Template.md` for all GitHub releases.
- Omit sections that have no content (e.g., skip "Migration Guide" if there are no breaking changes).
