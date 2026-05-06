# SwiftSMB Agent Notes

## Project Overview

SwiftSMB is a Swift Package Manager library that wraps `libsmb2` to access SMB shares from Swift.

## Project Tree

```text
.
├── libsmb2
├── Package.swift
├── Sources
│   └── SwiftSMB
│       ├── Bridge                         # Internal libsmb2 bridge; no public API here.
│       │   ├── Extensions
│       │   ├── SMB2Bridge.swift           # High-level synchronous POSIX-like bridge calls.
│       │   ├── SMB2Bridge-ListShares.swift # SRVSVC/DCERPC share enumeration.
│       │   ├── SMB2Bridge-Notify.swift    # Notification bridge; do not expose publicly yet.
│       │   ├── SMB2BridgeTypes.swift      # Internal Swift-shaped bridge structs/enums/options.
│       │   └── SMB2Error.swift            # Bridge errors preserving raw NTSTATUS values.
│       └── PublicAPI                      # User-facing API, all organized under SMB.
│           ├── SMB.swift                  # public final class SMB; no public initializers.
│           ├── SMBOperations.swift        # Static top-level operations: connect/listShares/parseURL.
│           ├── SMBConfiguration.swift     # Server, credentials, and connection configuration.
│           ├── SMBConnection.swift        # Connection handle, state, and primitive bridge operations.
│           ├── SMBConnection-Conv.swift   # Connection convenience methods built from primitives.
│           ├── SMBFile.swift              # OOP file handle.
│           ├── SMBFile-Conv.swift         # File convenience methods built from primitives.
│           ├── SMBDirectory.swift         # OOP directory handle.
│           ├── SMBDirectory-Conv.swift    # Directory convenience methods built from primitives.
│           ├── SMBValues.swift            # Public value types.
│           ├── SMBError.swift             # Public error type.
│           ├── SMBStatus.swift            # SMB.SMBStatus and SMB.SMBStatusSeverity.
│           └── Util
│               └── SMBProtected.swift     # DispatchQueue-backed state wrapper for Sendable handles.
├── Tests
│   └── SwiftSMBTests
│       ├── Bridge                         # Bridge tests; most are Samba integration tests.
│       └── PublicAPI                      # Public API unit tests.
└── TestServer                             # Docker Samba server for integration tests.
```

## Bridge Layer

- Keep `SMB2Bridge.swift` focused on the high-level synchronous POSIX-like API described in `libsmb2/include/smb2/libsmb2.h`.
- Prefer free internal functions over namespace enums for bridge calls.
- Bridge functions should expose Swift-shaped arguments and return values (`String`, `Bool`, `UInt64`, `Int64`, Swift structs/enums/options) and convert to C types only at the boundary.
- Functions that correspond directly to C `get` functions should keep `get` in the Swift bridge name, even though this is not typical Swift style.
- Do not expose raw C flags as plain integers. Use Swift `enum` or `OptionSet` types instead. Examples: `SMB2OpenFlags`, `SMB2SecurityMode`, `SMB2AuthenticationMethod`.
- C return values that signal errors through negative `errno` values or `NULL` should become `throw`.
- Keep SMB/NT status handling granular. Public status values live under `SMB.SMBStatus` and `SMB.SMBStatusSeverity`; unknown NTSTATUS values should still preserve their raw value in `SMB2Error`.
- Passing `SMB2Context` as a normal parameter is preferred for now. It is a lightweight Swift wrapper around a C pointer; avoid `inout`, `borrowing`, or `consuming` unless the type is redesigned for explicit ownership.

## Public API

- `SMB` is a `public final class` with no public initializers. Use static methods for top-level operations such as `connect`, `listShares`, and `parseURL`.
- Keep `SMB.Connection`, `SMB.File`, and `SMB.Directory` as OOP handles nested under `SMB`.
- Use Swift strict concurrency checking. Public handle types should conform to `Sendable`; protect mutable/internal state with `DispatchQueue`-backed wrappers such as `SMBProtected` under `Sources/SwiftSMB/PublicAPI/Util`.
- Prefer friendly API behavior when it is unambiguous. For example, clamp requested transfer block sizes to the server maximum and return the accepted value from accepted block-size helpers.
- Keep credentials out of `SMB.Configuration`; pass them to connection/listing entry points.
- Do not expose password-file APIs publicly.
- Add DocC comments to public API at Apple documentation quality. Private and internal members may use concise one-line comments where useful. `SMB.SMBStatus` does not need exhaustive DocC.

## Testing

- Unit tests (no server needed): `TypeTests.swift` covers value types, error cases, and enum raw values.
- Integration tests (need server): most tests under `Tests/SwiftSMBTests/Bridge/`. Tagged with `.integration`.
- Run all tests: `swift test`
- Run a subset: `swift test --filter 'ConnectionTests'`
- The test server is a Docker-based Samba container.
  - Check whether it is already running: `docker ps --filter ancestor=swiftsmb-testserver`
  - Start: `source TestServer/up.sh`
  - Stop: `source TestServer/down.sh`
  - Dockerfile with SAMBA configuration in `TestServer/Dockerfile`
  - Port: localhost:44445 (mapped from container 445)
- If integration tests fail with connection refusals, check that the test server is running (`docker ps`).

## Code Style & Commits

- **Before committing**, always format the Swift source code with `swiftformat`:
  ```bash
  swiftformat .
  ```
