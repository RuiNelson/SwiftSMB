# Working with File and Directory Handles

This cookbook covers low-level handle-based I/O for when you need streaming, random access, or fine-grained control over reads and writes.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? connection.disconnect() }
```

## Opening a file handle

``SMB.Connection.openFile(at:accessMode:options:)`` returns an ``SMB.File`` handle:

```swift
let file = try connection.openFile(at: "Anna/Inbox/report.pdf")
defer { try? file.close() }
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
let file = try connection.openFile(
    at: "Anna/Inbox/log.txt",
    accessMode: .readWrite,
    options: [.create, .append]
)
```

## Reading from a file handle

Read from the current offset until end of file:

```swift
let file = try connection.openFile(at: "report.pdf")
defer { try? file.close() }

let data = try file.readToEnd()
```

Read a specific number of bytes from the current offset:

```swift
let chunk = try file.read(upToByteCount: 65536)
```

Read at an explicit offset without changing the current offset:

```swift
let header = try file.read(upToByteCount: 1024, atOffset: 0)
let footer = try file.read(upToByteCount: 1024, atOffset: fileSize - 1024)
```

## Writing to a file handle

Write all data in a loop, automatically splitting into accepted block sizes:

```swift
let file = try connection.openFile(
    at: "output.bin",
    accessMode: .writeOnly,
    options: [.create, .truncate]
)
defer { try? file.close() }

try file.write(largeData)
```

## Seeking

``SMB.File.seek(offset:from:)`` moves the current file offset:

```swift
// Seek to the beginning
try file.seek(offset: 0, from: .start)

// Skip ahead 1024 bytes
try file.seek(offset: 1024, from: .current)

// Seek to the end
try file.seek(offset: 0, from: .end)
```

The method returns the new absolute offset.

## File metadata from a handle

```swift
let info = try file.stat()
print("Size: \(info.size)")
print("Modified: \(info.modificationTime)")
```

## Truncating a file handle

```swift
try file.truncate(toLength: 1024)
```

## Flushing writes

```swift
try file.sync()
```

## Opening a directory handle

``SMB.Connection.openDirectory(at:)`` returns an ``SMB.Directory`` handle:

```swift
let directory = try connection.openDirectory(at: "Anna/Inbox")
defer { directory.close() }
```

## Reading directory entries

Read one entry at a time:

```swift
while let entry = try directory.readNext() {
    print("\(entry.name) — \(entry.stat.size) bytes")
}
```

Or read all remaining entries at once:

```swift
let entries = try directory.readAll()
```

## Directory stream positioning

You can bookmark a position and return to it later:

```swift
let mark = try directory.tell()

// Read some entries...
_ = try directory.readNext()
_ = try directory.readNext()

// Go back
try directory.seek(to: mark)
```

Rewind to the beginning:

```swift
try directory.rewind()
```

## Closing handles

Close a file handle when you are done:

```swift
try file.close()
```

Close a directory handle:

```swift
directory.close()
```

Both handles close automatically when they go out of scope, but explicit close is recommended in tight loops or when you open many handles.
