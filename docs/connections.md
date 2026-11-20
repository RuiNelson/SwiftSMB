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

## Keeping a connection alive

Servers and network equipment close connections that stay quiet for too long. ``SMB.Connection.startKeepAlive(_:)``
sends an SMB echo while the connection is idle, and tells you when it stops answering:

```swift
let keepAlive = SMB.KeepAliveConfiguration(interval: 30, timeout: 1) { [weak connection] problem in
    switch problem {
    case .slow(let roundTrip):
        print("The server answered in \(roundTrip) s")
    case .noResponse, .failed:
        // The connection is most likely broken, and the keep-alive has stopped.
        try? await connection?.disconnect()
    }
}
try connection.startKeepAlive(keepAlive)

// Later:
connection.stopKeepAlive()
```

The callback captures the connection `weak`: the keep-alive holds its callback, so a strong capture would keep the
connection alive, and connected, until the keep-alive stops, and releasing the connection would no longer stop it.

The keep-alive is not part of ``SMB.Configuration`` so that it can be started and stopped while the connection is open.

- **Idle only.** Every operation, from the moment it starts until it finishes, postpones the next echo by a whole
  `interval`, so a connection that is being used sends none. Starting counts as activity.
- **Deadline.** `timeout` (1 second by default) is how long an echo may take to answer, counted from when the echo
  starts running on the connection. It is enforced by SwiftSMB, and is reduced to the connection's command timeout
  (``SMB.Configuration/timeout``, or the value set with ``SMB.Connection/setTimeout(_:)``) when that is not zero.
- **Command timeout.** An echo to a server that stopped answering holds the connection until it gives up, and
  without a command timeout libsmb2 would wait for the operating system to drop the TCP connection, with a
  `disconnect()` from the callback stuck behind it. So while the keep-alive runs, a connection with no command timeout
  gets one: `timeout` rounded up to whole seconds (libsmb2 counts whole seconds), so 2.1 s becomes 3 s. It applies to
  **every** operation on the connection, not only to echoes: a single request that takes longer, such as a large block
  over a slow link, fails with ``SMB.SMBStatus/ioTimeout``. On slow connections set a command timeout of your own; the
  keep-alive never changes one that is set. When the keep-alive stops it removes the timeout it set, unless
  ``SMB.Connection/setTimeout(_:)`` was called meanwhile. ``SMB.Connection/fork()`` starts the new connection with the
  command timeout in force, including one the keep-alive set.
- **Problems.** The callback receives ``SMB.KeepAliveProblem/slow(roundTrip:)`` when the answer takes longer than
  `slowRoundTrip` (the keep-alive goes on), and ``SMB.KeepAliveProblem/noResponse(timeout:)`` or
  ``SMB.KeepAliveProblem/failed(_:)`` when the connection looks broken. After those two the keep-alive stops once the
  callback returns; it never reconnects, so the callback is the place to disconnect or to connect again. The callback
  is `async`, and the keep-alive waits for it. A `slowRoundTrip` at or above the deadline never reports `.slow`, since
  such an answer is `.noResponse`. When the connection's command timeout expires first, that is `.noResponse` too. An
  echo that gets no answer while another operation started on the connection reports nothing: that operation meets
  the problem itself, and the keep-alive tries again after the next idle `interval`.
- **Starting again** replaces the running keep-alive. ``SMB.Connection/isKeepAliveRunning`` tells whether one is running.
  It cannot start once the connection is closed or disconnecting gracefully.
- **Stopping.** ``SMB.Connection/stopKeepAlive()`` is synchronous and may be called from the callback, as may
  `startKeepAlive(_:)` and `disconnect()`. No callback starts after it returns, but one that was already starting at
  that moment can still run. Disconnecting, gracefully or not, and releasing the connection stop it too. The
  keep-alive does not keep the connection alive, but a callback that captures the connection strongly does until the
  keep-alive stops.

`interval`, `timeout` and `slowRoundTrip` must be finite and greater than zero; anything else is a programmer error and
traps.

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
