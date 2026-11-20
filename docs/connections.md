# Connections

This cookbook covers connecting to a share, configuring the connection, running operations in parallel, and
disconnecting.

All examples assume a server and credentials:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
```

## Connecting

``SMB.connect(server:credentials:share:configuration:)`` opens a connection to one share:

```swift
let connection = try await SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? await connection.disconnect() }
```

Pass an ``SMB.Configuration`` to change how the connection is negotiated and how it behaves. The sections below cover
the options you are most likely to need.

## Adjusting command timeouts

Pass ``SMB.Configuration.timeout`` when connecting to have `libsmb2` abort operations that take too long:

```swift
let connection = try await SMB.connect(
    server: server,
    credentials: credentials,
    share: "Documents",
    configuration: SMB.Configuration(timeout: 30)
)
```

Use ``SMB.Connection.setTimeout(_:)`` to change the timeout for subsequent operations on an existing connection. Pass
`0` to disable command timeouts. Establishing a connection always has a deadline: the configured timeout when it is
positive, otherwise 30 seconds.

```swift
try await connection.setTimeout(10)
try await connection.setTimeout(0)
```

## Choosing an encryption policy

``SMB/Configuration/Encryption`` represents all three `libsmb2` encryption states:

- `.automatic` advertises encryption support and uses it when the server or share requires it. This is the default.
- `.disabled` does not advertise encryption; connections to encryption-only servers or shares fail.
- `.required` fails unless SMB encryption is negotiated.

```swift
let configuration = SMB.Configuration(encryption: .required)
```

## Validating paths

Paths are checked before they are sent to the server. SMB does not tell the client which file system holds a share,
and each one accepts different names: `CON` is a valid directory name on a Mac or a Samba server, but not on NTFS.
``SMB/Configuration/PathValidation`` chooses which rules are checked locally:

- `.smb` checks only the rules of the SMB protocol and lets the server decide the rest. This is the default.
- `.ntfsOverSMB` also rejects names NTFS refuses, such as names ending in a space or a period and reserved device names
  like `CON`, `PRN` or `COM1`.
- `.unixOverSMB` also rejects components longer than 255 bytes in UTF-8, the limit of ext4, APFS and ZFS.

```swift
let configuration = SMB.Configuration(pathValidation: .ntfsOverSMB)
```

The server always has the final word: a stricter level only rejects such names before any request is sent.

## Running operations in parallel

Operations on a connection run one at a time, in the order they were requested. Open separate connections to run
operations in parallel. ``SMB.Connection.fork()`` opens another connection to the same share, with the same
credentials and configuration:

```swift
let secondConnection = try await connection.fork()
defer { try? await secondConnection.disconnect() }

async let photos = connection.listDirectory(at: "Photos")
async let videos = secondConnection.listDirectory(at: "Videos")
let (photoEntries, videoEntries) = try await (photos, videos)
```

A fork reads and writes in the block sizes the server accepted for the original connection, rather than the configured
`transferBlockSize`, and starts with its current command timeout. A cache attached to the original connection is
attached to the fork too; see [Block-Level Cache](block-level-cache.md#forks-several-shares-and-closing).

## Checking the negotiated dialect

``SMB.Connection.negotiatedDialect`` returns the raw SMB dialect revision the server agreed to after connecting:

```swift
let rawDialect = try await connection.negotiatedDialect
```

``SMB.Connection.negotiatedDialectKind`` maps that raw value to ``SMB.NegotiatedDialect``, a typed enum covering the
known SMB2/SMB3 dialects with a `.unknown(UInt16)` fallback for revisions this library doesn't recognize yet:

```swift
switch try await connection.negotiatedDialectKind {
case .smb3_11:
    print("Connected using SMB 3.1.1")
case .unknown(let rawValue):
    print("Connected using an unrecognized dialect: \(rawValue)")
default:
    break
}
```

## Identifying the server

``SMB/Connection/serverGUID`` returns the identifier negotiated with the server as Foundation's native ``UUID``:

```swift
let serverID: UUID = try await connection.serverGUID
```

The SMB GUID wire fields are normalized to the byte order used by `UUID.uuidString`.

``SMB/libsmb2Version`` tells which libsmb2 release SwiftSMB is built on, which is useful in bug reports:

```swift
print("libsmb2 \(SMB.libsmb2Version)") // libsmb2 7.0.0
```

## Disconnecting

``SMB.Connection.disconnect()`` cancels watchers and closes all file and directory handles before destroying the
connection. Use ``SMB.Connection.disconnectGracefully()`` to let operations already in progress finish first, including
multi-block reads, writes, and uploads or downloads:

```swift
try await connection.disconnectGracefully()
```

Once graceful disconnection starts, new operations fail with ``SMB.Error.operationRequestedAfterConnectionClosed``.
The nested operations and cleanup needed by an existing operation can still finish. Calling `disconnect()` explicitly
during the wait interrupts those operations.
