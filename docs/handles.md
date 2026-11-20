# Working with File and Directory Handles

This cookbook covers low-level handle-based I/O for when you need streaming, random access, or fine-grained control
over reads and writes. Connecting, configuring, and disconnecting are covered in [Connections](connections.md).

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try await SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? await connection.disconnect() }
```

## Opening a file handle

``SMB.Connection.openFile(at:accessMode:options:)`` returns an ``SMB.File`` handle:

```swift
let file = try await connection.openFile(at: "Anna/Inbox/report.pdf")
defer { try? await file.close() }
```

### Access modes

- ``SMB.File.AccessMode.readOnly`` — read only (default)
- ``SMB.File.AccessMode.writeOnly`` — write only
- ``SMB.File.AccessMode.readWrite`` — read and write

### Open options

Combine flags from ``SMB.File.OpenOptions``:

- `.create` — create the file if it does not exist
- `.exclusive` — fail if the file already exists
- `.truncate` — truncate the file on open
- `.append` — append writes to the end
- `.synchronous` — open in synchronous mode

```swift
let file = try await connection.openFile(
    at: "Anna/Inbox/log.txt",
    accessMode: .readWrite,
    options: [.create, .append]
)
```

Append refreshes the file's length before each write. If multiple connections append to the same file, coordinate
their writes with an exclusive file lock to prevent them from choosing the same offset. Append does not acquire locks
automatically.

## Reading from a file handle

Read from the current offset until end of file:

```swift
let file = try await connection.openFile(at: "report.pdf")
defer { try? await file.close() }

let data = try await file.read()
```

Read a specific number of bytes from the current offset:

```swift
let chunk = try await file.read(upTo: 65536)
```

Read at an explicit offset using `seek` first:

```swift
let info = try await file.stat()
try await file.seek(offset: 0, from: .start)
let header = try await file.read(upTo: 1024)
try await file.seek(offset: Int64(info.size - 1024), from: .start)
let footer = try await file.read(upTo: 1024)
```

Or pass the offset to `read(upTo:atOffset:)`, which neither uses nor moves the current offset. Concurrent tasks can
read different ranges of the same handle this way without coordinating seeks:

```swift
let info = try await file.stat()
async let header = file.read(upTo: 1024, atOffset: 0)
async let footer = file.read(upTo: 1024, atOffset: info.size - 1024)
let (first, last) = try await (header, footer)
```

The result is shorter than `upTo` when the end of the file is reached, and empty when the offset is at or past it.

## Writing to a file handle

Write all data:

```swift
let file = try await connection.openFile(
    at: "output.bin",
    accessMode: .writeOnly,
    options: [.create, .truncate]
)
defer { try? await file.close() }

try await file.write(largeData)
```

Write at a specific offset using `seek`:

```swift
try await file.seek(offset: 4096, from: .start)
try await file.write(data)
```

Or pass the offset to `write(_:atOffset:)`, which, like `read(upTo:atOffset:)`, neither uses nor moves the current
offset. Writing past the end of the file extends it, and the gap reads back as zeros on Windows and Samba servers:

```swift
try await file.write(data, atOffset: 4096)
```

## Seeking

``SMB.File.seek(offset:from:)`` moves the current file offset:

```swift
// Seek to the beginning
try await file.seek(offset: 0, from: .start)

// Skip ahead 1024 bytes
try await file.seek(offset: 1024, from: .current)

// Seek to the end
try await file.seek(offset: 0, from: .end)
```

The method returns the new absolute offset.

## File metadata from a handle

```swift
let info = try await file.stat()
print("Size: \(info.size)")
print("Modified: \(info.modificationTime)")
```

## Truncating a file handle

```swift
try await file.truncate(toLength: 1024)
```

## Flushing writes

```swift
try await file.sync()
```

## Opening a directory handle

``SMB.Connection.openDirectory(at:)`` returns an ``SMB.Directory`` handle:

```swift
let directory = try await connection.openDirectory(at: "Anna/Inbox")
defer { await directory.close() }
```

## Reading directory entries

Read one entry at a time:

```swift
while let entry = try await directory.readNext() {
    print("\(entry.name) — \(entry.stat.size) bytes")
}
```

Or read all remaining entries at once:

```swift
let entries = try await directory.readAll()
```

Or check whether any of the remaining entries matches a predicate, which may throw and use `await`:

```swift
let hasPDF = try await directory.contains { $0.name.hasSuffix(".pdf") }

// `catalog` is an actor that knows which files were already backed up.
let hasNewFile = try await directory.contains { entry in
    await !catalog.contains(entry.name)
}
```

`contains(where:)` stops at the first match, so the stream continues after that entry, or is exhausted when nothing
matches. Rewind or seek to read the entries again.

## Directory stream positioning

You can bookmark a position and return to it later:

```swift
let mark = try await directory.tell()

// Read some entries...
_ = try await directory.readNext()
_ = try await directory.readNext()

// Go back
try await directory.seek(to: mark)
```

Rewind to the beginning:

```swift
try await directory.rewind()
```

## Closing handles

Close a file handle when you are done:

```swift
try await file.close()
```

Close a directory handle:

```swift
await directory.close()
```

Both handles close automatically when they go out of scope, but explicit close is recommended in tight loops or when you open many handles.

## Locking a file handle

Acquire an exclusive (write) lock on the entire file:

```swift
let file = try await connection.openFile(
    at: "Anna/Inbox/draft.txt",
    accessMode: .readWrite,
)
defer { try? await file.close() }

try await file.lock(.exclusive, nonBlocking: false)
// ... perform exclusive writes ...
try await file.unlock()
```

Acquire a shared (read) lock that allows concurrent readers:

```swift
let file = try await connection.openFile(at: "report.pdf")
defer { try? await file.close() }

try await file.lock(.shared, nonBlocking: false)
let data = try await file.read()
try await file.unlock()
```

Set `nonBlocking` to `true` to fail immediately when the lock conflicts with an existing one, instead of waiting:

```swift
try await file.lock(.exclusive, nonBlocking: true)
```

A blocking lock waits until the conflicting lock is released, and other operations on the same connection wait behind
it. To stop waiting, cancel the task that requested the lock. The server withdraws the request, so the lock is never
granted later, and `lock` throws `CancellationError`:

```swift
let lockTask = Task {
    try await file.lock(.exclusive, nonBlocking: false)
}
// ...
lockTask.cancel()
```

The connection's command timeout and disconnecting also withdraw a waiting lock.

A keep-alive changes how long a blocking lock waits. While ``SMB/Connection/startKeepAlive(_:)`` runs on a connection
that had no command timeout, it imposes one (1 second by default), so a lock that would otherwise wait indefinitely
fails with ``SMB/SMBStatus/ioTimeout`` after about a second. To wait for locks on a connection with a keep-alive, set a
command timeout of your own, greater than zero and long enough, before starting the keep-alive (with
``SMB/Configuration/timeout`` or ``SMB/Connection/setTimeout(_:)``), or use non-blocking locks.

Lock a specific byte range instead of the entire file:

```swift
try await file.lock(.exclusive, nonBlocking: false, range: 1024..<2048)
// ... work within the locked range ...
try await file.unlock(range: 1024..<2048)
```

`lock` and `unlock` also take a `Range<SMB.Offset>` (``SMB.Offset`` is a `UInt64`, the type of every file offset), which
can address offsets above `Int64.max`. Integer literals such as `1024..<2048` keep selecting the `Range<Int64>`
overload; a range of `SMB.Offset` values selects the other one.

Only one mode can be active at a time—shared and exclusive are mutually exclusive. The lock is associated with the open handle and is automatically released when the file is closed.

## Oplocks, leases, and their breaks

An oplock or a lease lets the client cache a file: reads (``SMB/File/LeaseState/readCaching``), writes
(``SMB/File/LeaseState/writeCaching``), and the open handle itself (``SMB/File/LeaseState/handleCaching``). Ask for one
when opening the file:

```swift
let file = try await connection.openFile(
    at: "report.docx",
    accessMode: .readWrite,
    opLock: .lease([.readCaching, .writeCaching, .handleCaching])
)
```

When another client opens the file in a way that conflicts with that caching, the server breaks the oplock or lease:
it lowers what this client may cache. ``SMB/File/opLockBreaks`` delivers those breaks. For a lease that held write
caching, the server holds the other client's open back until this client has written its cached changes and
acknowledged the break:

```swift
for try await opLockBreak in file.opLockBreaks {
    if case let .lease(_, to) = opLockBreak.change, !to.contains(.writeCaching) {
        try await writeCachedChanges(to: file)
    }
    if opLockBreak.requiresAcknowledgement {
        try await file.acknowledgeOpLockBreak()
    }
}
```

- While the breaks are iterated, SwiftSMB services the connection in the background, so breaks arrive even when the
  connection is otherwise idle.
- Acknowledge promptly: the server waits 35 seconds at most, then lowers the lease to no caching by itself. Pass
  `keeping:` to keep less than the server allows.
- Breaks that arrive while nobody iterates, and breaks of classic oplocks (``SMB/File/OpLock/levelII``,
  ``SMB/File/OpLock/exclusive``, ``SMB/File/OpLock/batch``), are acknowledged by SwiftSMB with the level the server
  asked for. They are still delivered, with ``SMB/File/OpLockBreak/requiresAcknowledgement`` set to `false`.
- Iteration ends when the file is closed or the connection is disconnected. A file opened without an oplock has no
  breaks.
