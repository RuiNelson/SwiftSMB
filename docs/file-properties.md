# Changing File Properties

This cookbook covers reading and modifying file timestamps, attributes, and other metadata on an SMB share.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try await SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? await connection.disconnect() }
```

## Reading file attributes

``SMB.Connection.attributes(at:)`` returns the SMB file attributes for a path:

```swift
let attrs = try await connection.attributes(at: "Anna/Inbox/report.pdf")

if attrs.contains(.hidden) {
    print("File is hidden")
}

if attrs.contains(.readOnly) {
    print("File is read-only")
}

if attrs.contains(.archive) {
    print("Archive bit is set")
}
```

Available attributes include:

- ``SMB.FileAttributes.readOnly``
- ``SMB.FileAttributes.hidden``
- ``SMB.FileAttributes.system``
- ``SMB.FileAttributes.directory``
- ``SMB.FileAttributes.archive``
- ``SMB.FileAttributes.normal``
- ``SMB.FileAttributes.temporary``
- ``SMB.FileAttributes.sparseFile``
- ``SMB.FileAttributes.reparsePoint``
- ``SMB.FileAttributes.compressed``
- ``SMB.FileAttributes.offline``
- ``SMB.FileAttributes.notContentIndexed``
- ``SMB.FileAttributes.encrypted``

## Changing file attributes

``SMB.Connection.changeAttributes(at:_:)`` lets you modify attributes while preserving the ones you do not touch:

```swift
// Make a file hidden and read-only
try await connection.changeAttributes(at: "report.pdf") { attrs in
    attrs.union([.hidden, .readOnly])
}

// Remove the hidden flag
try await connection.changeAttributes(at: "report.pdf") { attrs in
    attrs.subtracting(.hidden)
}

// Toggle the archive flag
try await connection.changeAttributes(at: "report.pdf") { attrs in
    attrs.symmetricDifference(.archive)
}
```

The closure receives the current attributes and must return the new set.

## Changing timestamps

``SMB.Connection.changeDate(at:creation:change:write:access:)`` updates one or more timestamps. Omitted timestamps are left unchanged:

```swift
let now = Date()

// Update only the modification time
try await connection.changeDate(at: "report.pdf", write: now)

// Update creation and last-access time
try await connection.changeDate(
    at: "report.pdf",
    creation: now,
    access: now
)

// Touch all timestamps
try await connection.changeDate(
    at: "report.pdf",
    creation: now,
    change: now,
    write: now,
    access: now
)
```

## Reading timestamps

Use ``SMB.Connection.stat(at:)`` to read the current metadata:

```swift
let info = try await connection.stat(at: "report.pdf")

print("Created:      \(info.birthTime)")
print("Modified:     \(info.modificationTime)")
print("Accessed:     \(info.accessTime)")
print("Meta changed: \(info.changeTime)")
```

Timestamps before 1970-01-01, including the zero timestamp some servers report for an unknown time, are not
represented correctly: `libsmb2` converts them with unsigned arithmetic, so they read back as dates far in the future.

## Reading the node type and attributes

The same ``SMB/Stat`` value reports the kind of node and the raw Windows attributes:

```swift
let info = try await connection.stat(at: "report.pdf")

switch info.type {
case .file: print("Regular file")
case .directory: print("Directory")
case .link: print("Symbolic link")
case .fifo, .characterDevice, .blockDevice, .socket: print("Special file created by WSL")
case let .unknown(raw): print("Unrecognized node type \(raw)")
}

if info.attributes.contains(.reparsePoint), let tag = info.reparseTag {
    print("Reparse point with tag 0x\(String(tag, radix: 16))")
}
```

``SMB/Stat/reparseTag`` is `nil` for items that are not reparse points and for servers that do not report the tag.
The special file types are only reported for the reparse points that WSL uses to store them on a Windows filesystem.

## Filesystem statistics

``SMB.Connection.statFilesystem(at:)`` returns capacity and usage information for the share:

```swift
let fs = try await connection.statFilesystem()

print("Total space:  \(UInt64(fs.blockSize) * fs.blocks)")
print("Free space:   \(fs.freeBytes)")
print("Avail space:  \(fs.availableBytes)")
print("Max filename: \(fs.maximumNameLength)")
```

## Truncating a file

``SMB.Connection.truncateFile(at:toLength:)`` resizes a file by path:

```swift
// Empty a log file
try await connection.truncateFile(at: "app.log", toLength: 0)

// Shrink a file to 1024 bytes
try await connection.truncateFile(at: "data.bin", toLength: 1024)
```

You can also truncate through an open file handle:

```swift
let file = try await connection.openFile(at: "data.bin", accessMode: .readWrite)
defer { try? await file.close() }
try await file.truncate(toLength: 1024)
```
