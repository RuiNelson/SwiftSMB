# SwiftSMB Agent Notes

## Project Overview

SwiftSMB is a Swift Package Manager library that wraps `libsmb2` to access SMB shares from Swift.

## Bridge Layer

- `Sources/SwiftSMB/Bridge` is an **internal** bridge over `libsmb2`. It should not define public API.
- Keep `SMB2Bridge.swift` focused on the high-level synchronous POSIX-like API described in `libsmb2/include/smb2/libsmb2.h`.
- Put share enumeration through SRVSVC/DCERPC in `SMB2Bridge-ListShares.swift`.
- Prefer free internal functions over namespace enums for bridge calls.
- Bridge functions should expose Swift-shaped arguments and return values (`String`, `Bool`, `UInt64`, `Int64`, Swift structs/enums/options) and convert to C types only at the boundary.
- Functions that correspond directly to C `get` functions should keep `get` in the Swift bridge name, even though this is not typical Swift style.
- Do not expose raw C flags as plain integers. Use Swift `enum` or `OptionSet` types instead. Examples: `SMB2OpenFlags`, `SMB2SecurityMode`, `SMB2AuthenticationMethod`.
- C return values that signal errors through negative `errno` values or `NULL` should become `throw`.
- Keep SMB/NT status handling granular. `SMB2Status` is a `UInt32` enum for known `SMB2_STATUS_*` error codes, with computed `name` and `severity`; unknown NTSTATUS values should still preserve their raw value in `SMB2Error`.
- Passing `SMB2Context` as a normal parameter is preferred for now. It is a lightweight Swift wrapper around a C pointer; avoid `inout`, `borrowing`, or `consuming` unless the type is redesigned for explicit ownership.

## Testing

- Tests live in `Tests/SwiftSMBTests/Bridge/` organized by area (Connection, Share, Directory, File, Type).
- Unit tests (no server needed): `TypeTests.swift` covers value types, error cases, and enum raw values.
- Integration tests (need server): all other test files. Tagged with `.integration`.
- Run all tests: `swift test`
- Run a subset: `swift test --filter 'ConnectionTests'`
- The test server is a Docker-based Samba container defined in `TestServer/`.
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
