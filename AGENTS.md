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
│       │   │   ├── Int.swift                 # Extensions to `Int`.
│       │   │   ├── String?.swift             # Extensions to `String?`.
│       │   │   └── SMB.Error.swift           # SMB.Error bridge factory and check() helper.
│       │   ├── Bridge.swift                  # High-level async POSIX-like bridge calls on per-context queues.
│       │   ├── BridgeTypes.swift             # Bridge structs/enums/options nested under `extension Bridge`.
│       │   ├── Bridge-Links.swift            # Symlink read/create bridge calls.
│       │   ├── Bridge-Locks.swift            # Byte-range lock bridge calls.
│       │   ├── Bridge-Notifications.swift    # Directory change-notification bridge calls.
│       │   ├── Bridge-ShareEnum.swift        # IPC$ share enumeration bridge calls.
│       │   └── Bridge-URL.swift              # SMB URL parsing bridge calls.
│       └── PublicAPI                         # User-facing API, all organized under SMB.
│           ├── SMB.swift                     # public final class SMB; no public initializers.
│           ├── Operations.swift              # Static top-level operations: connect/listShares/parseURL.
│           ├── Configuration.swift           # Server, credentials, and connection configuration.
│           ├── Connection.swift              # Connection handle, state, and primitive bridge operations.
│           ├── Connection-Conv.swift         # Connection convenience methods built from primitives.
│           ├── Connection-Conv-Transfer.swift # Upload/download convenience methods.
│           ├── File.swift                    # OOP file handle.
│           ├── Directory.swift               # OOP directory handle.
│           ├── Directory-Conv.swift          # Directory convenience methods built from primitives.
│           ├── Notify.swift                  # AsyncSequence-based public SMB directory notifications.
│           ├── Types.swift                   # Public value types.
│           ├── Error.swift                   # Public error type.
│           ├── Error-InvalidArgument.swift   # Typed invalid-argument operations and causes.
│           ├── Error-Status.swift            # SMB.SMBStatus and SMB.SMBStatusSeverity.
│           └── Util
│               ├── Date+.swift               # Date helpers for SMB timestamp values.
│               ├── OptionSet+.swift          # Shared debug formatting helpers.
│               ├── PathValidation.swift      # Share-name and share-relative path validation.
│               ├── Protected.swift           # Mutex/NSLock-backed state wrapper for Sendable handles.
│               └── ProtectedHandle.swift     # Protected<Handle?> wrapper shared by File/Directory/Connection.
├── Tests
│   ├── SwiftSMBUnitTests                     # Unit tests (no server needed); always run in CI.
│   │   ├── Bridge
│   │   │   ├── ConnectionConfigurationTests.swift # Context configuration unit tests.
│   │   │   └── TypeTests.swift               # Value types, errors, and enum raw-value unit tests.
│   │   └── PublicAPI
│   │       └── SMBPublicAPITests.swift       # URL parsing and public value type tests.
│   └── SwiftSMBTests                         # Integration tests; need the Docker test server.
│       ├── Bridge                            # Bridge-level Samba integration tests.
│       │   ├── ConnectionTests.swift         # Context configuration and connection lifecycle tests.
│       │   ├── DirectoryTests.swift          # Directory create, remove, and list tests.
│       │   ├── FileTests.swift               # File open, read, write, seek, and stat tests.
│       │   ├── IntegrationSupport.swift      # Shared helpers and server credentials for integration tests.
│       │   ├── OpLockTests.swift             # Oplock and lease bridge tests.
│       │   └── ShareTests.swift              # Share enumeration and info tests.
│       ├── Cookbook                          # README/docs example coverage.
│       ├── PublicAPI                         # Public API integration tests.
│       │   ├── SMBConnectionAuthTests.swift  # Authentication and connection setup tests.
│       │   ├── SMBConnectionDirectoryTests.swift # Directory convenience public API tests.
│       │   ├── SMBConnectionFileTests.swift  # File convenience public API tests.
│       │   ├── SMBConnectionTransferTests.swift # Upload/download convenience public API tests.
│       │   ├── SMBFileLockTests.swift        # File byte-range lock public API tests.
│       │   ├── SMBFileOpLockTests.swift      # File oplock/lease public API tests.
│       │   ├── SMBNotifyTests.swift          # Notification public API and integration tests.
│       │   └── SMBPublicAPIIntegrationTests.swift # Connection-level public API integration tests.
│       └── Utils
└── TestServer                                # Docker Samba server for integration tests.
```

## Bridge Layer

- `Bridge` is a `class` (not a namespace enum) with all-static methods. All bridge types (e.g., `Context`, `FileHandle`, `OpenOptions`) are nested inside `Bridge` via `extension Bridge { ... }` in `BridgeTypes.swift`.
- Outside the `Bridge` class, reference bridge types with the `Bridge.` prefix (e.g., `Bridge.SMB2Context`). Inside the class or its extensions, types resolve without prefix.
- Keep `Bridge.swift` focused on the high-level POSIX-like API described in `libsmb2/include/smb2/libsmb2.h`, exposed as `async` functions.
- Bridge functions should expose Swift-shaped arguments and return values (`String`, `Bool`, `UInt64`, `Int64`, Swift structs/enums/options) and convert to C types only at the boundary.
- Functions that correspond directly to C `get` functions should keep `get` in the Swift bridge name, even though this is not typical Swift style.
- Do not expose raw C flags as plain integers. Use Swift `enum` or `OptionSet` types instead. Examples: `Bridge.SMB2OpenFlags`, `Bridge.SMB2SecurityMode`, `Bridge.SMB2AuthenticationMethod`.
- C return values that signal errors through negative `errno` values or `NULL` should become `throw`.
- Keep SMB/NT status handling granular. Public status values live under `SMB.SMBStatus` and `SMB.SMBStatusSeverity`; unknown NTSTATUS values should still preserve their raw value in `SMB.Error.unknownNTStatus`.
- `Bridge.Context` is a `final class` that owns the C pointer, the context's serial queue, and a queue-confined liveness flag. Pass it as a normal parameter; avoid `inout`, `borrowing`, or `consuming`.
- Path separator: `libsmb2` accepts `/` (POSIX-style) in its public API but converts to `\` (Windows-style) internally before sending SMB2 requests to the server (see `libsmb2.c:smb2_rename` and `smb2-cmd-create.c`). Use `/` in the Swift public API and bridge layer.
- `libsmb2` contexts are not safe to service concurrently. Every bridge function that touches a shared context is `async` and runs its body on that context's serial queue through `Bridge.perform(on:_:)`. The private `_name` functions hold the synchronous C calls and must only run on the context queue, or on a context that is never shared (such as `Bridge.parseURL`'s private context). Notification watcher bridge calls (`notifyChange`, `serviceNotifyEvents`, `cancel`, and close) follow the same rule.
- Operations on different contexts run in parallel. `smb2_init_context` and `smb2_destroy_context` mutate process-wide libsmb2 state (the `active_contexts` list and the `srandom` seed), so they run under `Bridge.lifecycleLock`. When wrapping new libsmb2 APIs, check them for other process-wide state and serialize it the same way.
- Known, accepted risk: the fork's SwiftPM `include/apple/config.h` and `include/linux/config.h` do not enable `HAVE_ARC4RANDOM_BUF`/`HAVE_GETRANDOM`, so `smb2_random_bytes` falls back to `random()`. `smb3_encrypt_pdu` calls it for every sealed PDU, and Darwin's `random()` is not thread-safe, so sealed connections running in parallel race on its state (the fallback also makes nonces predictable). Fixing it means enabling a strong random source in those fork config headers.
- Never run blocking libsmb2 calls on the Swift concurrency cooperative thread pool; always hop to the context queue.
- `smb2_connect_share` treats the command timeout as a connection window checked against `time(NULL)` before the event that completes the TCP connect is handled, so a timeout of `0` fails any connect that crosses a wall-clock second boundary ("Timeout expired and no connection exists"; seen when many connections open concurrently). `Bridge._connectShare` therefore connects with `Bridge.defaultConnectTimeoutSeconds` when the timeout is `0` and restores `0` afterwards; keep that when touching the connect path.
- Loops that service a context themselves (`Bridge.serviceUntilFinished`, `Bridge.serviceNotifyEvents`) must fail when `smb2_get_fd` is negative: `smb2_service` returns success without a connection and `poll` ignores negative descriptors, so they would spin forever and block the context queue.
- Commands that pass `Unmanaged.passRetained(state)` as callback data must balance it with `Bridge.releaseWhenFinished`: libsmb2 can invoke a queued PDU's callbacks after the caller stopped waiting (e.g. `SMB2_STATUS_SHUTDOWN` on destroy after a network error), so unfinished state is leaked rather than freed.
- `Bridge.shutdown(_:)` disconnects, closes, and destroys a context in one queue operation. Never split those steps across separate `perform` calls, or another operation can run on a half-torn-down context.
- The notify watcher services its context with a zero-timeout poll and waits between polls off the queue (`Task.sleep`), so an idle watcher never holds its connection's queue.
- `Bridge.perform(on:_:)` throws ``SMB/Error/operationRequestedAfterConnectionClosed`` once the context has been destroyed instead of touching freed memory. It does not check task cancellation, so cleanup (closing handles, removing temporary files) still runs in cancelled tasks.
- `deinit` cannot await. Use the `…InBackground` helpers (`teardownInBackground`, `closeInBackground`, `closeDirInBackground`, `cancelInBackground`), which enqueue on the context queue; FIFO order guarantees that handle cleanup enqueued first runs before a later teardown.
- The bridge intentionally exposes a one-shot raw-PDU notification primitive. The public layer owns the directory handle, re-arms requests for continuous watching, cancels pending requests before close/context teardown, and services the context while the watcher is active.
- Keep notify response decoding defensive. Do not call the recursive C `smb2_decode_filenotifychangeinformation` helper from public watcher paths unless it has been audited for malformed server data; the Swift decoder currently validates entry bounds, monotonic offsets, and an entry-count cap.
- Retry `poll` on `EINTR` in Swift-owned service loops.

## Public API

- `SMB` is a `public final class` with no public initializers. Use static methods for top-level operations such as `connect`, `listShares`, and `parseURL`.
- Keep `SMB.Connection`, `SMB.File`, `SMB.Directory`, and `SMB.NotifyWatcher` as OOP handles nested under `SMB`.
- Use Swift strict concurrency checking. Public handle types should conform to `Sendable`; protect mutable/internal state with `Mutex`/`NSLock`-backed wrappers such as `Protected` and `ProtectedHandle` under `Sources/SwiftSMB/PublicAPI/Util`.
- All public operations that reach the server are `async`. Pure value operations (`SMB.parseURL`, validation, value types) stay synchronous. Long loops (`File.read`/`write`, transfers, recursive `removeItem`) call `Task.checkCancellation()` between steps.
- Prefer friendly API behavior when it is unambiguous. For example, clamp requested transfer block sizes to the server maximum and return the accepted value from accepted block-size helpers.
- Keep credentials out of `SMB.Configuration`; pass them to connection/listing entry points.
- Do not expose password-file APIs publicly.
- Add DocC comments to public API at Apple documentation quality. Private and internal members may use concise one-line comments where useful. `SMB.SMBStatus` does not need exhaustive DocC.
- Public share names and share-relative paths are validated through `SMBPathValidation.swift` using PathWorks. Leading `/` is normalized away for paths; the share root is accepted only when the operation explicitly allows it.
- File convenience methods are named `loadFile(at:)` and `dumpToFile(_:to:)`; avoid reintroducing the older `readFile`/`writeFile` names.
- Directory conveniences include recursive `makeDirectory(at:makePath:)`, recursive `removeItem(at:)`, `listDirectory(at:)`, and `itemExists(at:)`.
- File transfer convenience APIs (`uploadFile`/`downloadFile`) support cancellation/progress and may create temporary remote paths for atomic uploads. They overlap local disk I/O with the network transfer using small queue-confined helpers in `Connection-Conv-Transfer.swift`; keep local disk work off the caller thread but do not reintroduce a general producer/consumer pipe. The helpers resume awaiting callers from their queue instead of blocking them. Task cancellation is checked between blocks and throws `CancellationError`; returning `false` from the progress closure still cancels without throwing.
- Public notifications are an `AsyncSequence`: `SMB.Connection.watchDirectory(...)` is `async` and returns an already-armed `SMB.NotifyWatcher` whose elements are `[SMB.NotifyChange]` batches. The notification loop runs in a `Task` that hops to the context queue. The iterator retains its watcher so ARC cannot cancel it mid-iteration. Cancellation (`cancel()`, cancelling the iterating task, disconnect, or deinit) is idempotent and ends iteration normally; errors end it by throwing.
- `watchDirectory` returns only after the server has registered the first notify request: `armRequest` only queues it, so an echo round trip on the same connection follows (requests on a connection are sent and processed in order). Tests and clients rely on that instead of sleeps or timing assumptions.
- Public values generally conform to `CustomDebugStringConvertible`; use `describeFlags` and `hex` helpers from `PublicAPI/Util/OptionSet+.swift` for consistent debug output.
- `Connection-Conv-Transfer.swift`'s private helpers are file-scope free functions taking `on connection: SMB.Connection` as their first argument, while `Connection-Conv.swift`'s private helpers are `private extension SMB.Connection` methods. Both styles are intentional — don't "fix" one file to match the other.
- `SMB.Configuration.Dialect` (negotiation preference, includes `.any`/`.anySMB2`/`.anySMB3`) and `SMB.NegotiatedDialect` (the actual dialect a server negotiated, with an `.unknown(UInt16)` fallback) are intentionally separate types with different case sets — don't merge them.

## Testing

- Unit tests (no server needed): `Tests/SwiftSMBUnitTests` covers value types, error cases, enum raw values, and context configuration. These always run, including in CI.
- Integration tests (need server): `Tests/SwiftSMBTests`, including the Bridge-level Samba tests, the Cookbook examples, and the public API integration suites. Tagged with `.integration`. Skip them by setting `SWIFTSMB_SKIP_INTEGRATION_TESTS=1`.
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
- Integration tests that wait for asynchronous events use `withTimeout(seconds:_:)` from `Tests/SwiftSMBTests/Utils` rather than sleeps.
- AddressSanitizer: SwiftPM does not link the ASan runtime into the dynamic `libsmb2` product, so pass it explicitly: `RT=$(xcrun clang -print-file-name=libclang_rt.asan_osx_dynamic.dylib); swift test --sanitize=address -Xlinker "$RT" -Xlinker -rpath -Xlinker "$(dirname "$RT")"`. The Swift 6.4 toolchain reports a false `stack-buffer-overflow` (a 9-byte read in `_convertToAnyHashable`) for `#expect` on `Optional<UInt64>`; add `-Xswiftc -sanitize-recover=address -Xcc -fsanitize-recover=address` and `ASAN_OPTIONS=halt_on_error=0` to keep going past it.

## Dependency Updates

- `libsmb2` is a Git submodule. Synchronize the fork before updating SwiftSMB's submodule pointer:
  ```bash
  git -C libsmb2 fetch origin
  git -C libsmb2 fetch upstream
  git -C libsmb2 checkout xcode_compat
  git -C libsmb2 merge upstream/master
  ```
- Preserve the fork-specific `xcode_compat` patches. If upstream reorganizes files, keep SwiftPM/Xcode compatibility fixes in the fork rather than patching generated build products in SwiftSMB.
- After merging upstream, inspect the public C headers, especially `libsmb2/include/smb2/libsmb2.h`, `libsmb2/include/smb2/libsmb2-share-enum.h`, and `libsmb2/include/smb2/libsmb2-raw.h`, for new APIs that should be wrapped by `Sources/SwiftSMB/Bridge` and exposed under `SMB`.
- Do not expose every upstream addition automatically. Prefer APIs that fit SwiftSMB's client-file-management scope. Large optional subsystems such as full DCE/RPC should stay out of the SwiftPM product unless there is a deliberate public API and linking decision.
- If upstream adds non-C source files under `libsmb2/lib` or splits libraries, update `Package.swift` excludes and the fork's `include/module.modulemap` so `swift build` compiles only the intended `libsmb2` client surface.
- Run `SWIFTSMB_SKIP_INTEGRATION_TESTS=1 swift test` after dependency updates. If new wrapped functionality touches real SMB server behavior, start the Docker server with `source TestServer/up.sh`, run a focused integration test.
- Once the submodule builds and tests pass, commit and push the `libsmb2` fork branch first, then update the submodule pointer in the main SwiftSMB repository.

## Concurrency & Dispatch

- **Never run blocking libsmb2 or disk work on the Swift concurrency cooperative thread pool.** Hop to a dedicated serial queue and resume the caller with a checked continuation.
- **Never use `DispatchQueue.global()`.** The global concurrent queue has a limited thread pool subject to exhaustion under heavy system load. Blocking work dispatched there can hang when all threads are occupied, because a caller waiting on a semaphore or pipe may never see the dispatched block execute. Use dedicated serial dispatch queues (created with `DispatchQueue(label:)`) for all async work, especially producer/consumer patterns that block the caller for backpressure, like the transfer disk workers.

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
