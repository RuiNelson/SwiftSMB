# Changing File Properties

This cookbook covers reading and modifying file timestamps, attributes, and other metadata on an SMB share.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? connection.disconnect() }
```

## Reading file attributes

``SMB.Connection.attributes(at:)`` returns the SMB file attributes for a path:

```swift
let attrs = try connection.attributes(at: "Anna/Inbox/report.pdf")

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
try connection.changeAttributes(at: "report.pdf") { attrs in
    attrs.union([.hidden, .readOnly])
}

// Remove the hidden flag
try connection.changeAttributes(at: "report.pdf") { attrs in
    attrs.subtracting(.hidden)
}

// Toggle the archive flag
try connection.changeAttributes(at: "report.pdf") { attrs in
    attrs.symmetricDifference(.archive)
}
```

The closure receives the current attributes and must return the new set.

## Changing timestamps

``SMB.Connection.changeDate(at:creation:change:write:access:)`` updates one or more timestamps. Omitted timestamps are left unchanged:

```swift
let now = Date()

// Update only the modification time
try connection.changeDate(at: "report.pdf", write: now)

// Update creation and last-access time
try connection.changeDate(
    at: "report.pdf",
    creation: now,
    access: now
)

// Touch all timestamps
try connection.changeDate(
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
let info = try connection.stat(at: "report.pdf")

print("Created:      \(info.birthTime)")
print("Modified:     \(info.modificationTime)")
print("Accessed:     \(info.accessTime)")
print("Meta changed: \(info.changeTime)")
```

## Filesystem statistics

``SMB.Connection.statFilesystem(at:)`` returns capacity and usage information for the share:

```swift
let fs = try connection.statFilesystem()

print("Total space:  \(UInt64(fs.blockSize) * fs.blocks)")
print("Free space:   \(fs.freeBytes)")
print("Avail space:  \(fs.availableBytes)")
print("Max filename: \(fs.maximumNameLength)")
```

## Truncating a file

``SMB.Connection.truncateFile(at:toLength:)`` resizes a file by path:

```swift
// Empty a log file
try connection.truncateFile(at: "app.log", toLength: 0)

// Shrink a file to 1024 bytes
try connection.truncateFile(at: "data.bin", toLength: 1024)
```

You can also truncate through an open file handle:

```swift
let file = try connection.openFile(at: "data.bin", accessMode: .readWrite)
defer { try? file.close() }
try file.truncate(toLength: 1024)
```
