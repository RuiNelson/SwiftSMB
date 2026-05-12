# File Management

This cookbook covers creating, copying, deleting, renaming, and inspecting files and directories on an SMB share.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? connection.disconnect() }
```

## Creating directories

``SMB.Connection.makeDirectory(at:makePath:)`` creates a single directory. Pass `makePath: true` to create any missing parent directories automatically:

```swift
// Creates "Anna" if needed, then "Inbox"
try connection.makeDirectory(at: "Anna/Inbox", makePath: true)

// Creates just "Backups" (fails if the parent does not exist)
try connection.makeDirectory(at: "Backups")
```

## Removing items

``SMB.Connection.removeItem(at:)`` removes a file, link, or directory. Directories are removed **recursively**:

```swift
// Remove a single file
try connection.removeItem(at: "Anna/Inbox/old_report.pdf")

// Remove a directory and everything inside it
try connection.removeItem(at: "Anna/Trash")
```

If you only want to remove an empty directory, use ``SMB.Connection.removeDirectory(at:)``:

```swift
try connection.removeDirectory(at: "EmptyFolder")
```

Remove a single file or link with ``SMB.Connection.removeFile(at:)``:

```swift
try connection.removeFile(at: "Anna/Inbox/old_report.pdf")
```

## Moving and renaming

``SMB.Connection.move(from:to:)`` moves or renames a share-relative path:

```swift
// Rename a file
try connection.move(from: "draft.txt", to: "final.txt")

// Move a file into a different folder
try connection.move(from: "draft.txt", to: "Archive/draft.txt")
```

## Copying files server-side

``SMB.Connection.copyFile(from:to:)`` copies a file directly on the server without sending the data through the client. This is efficient for large files and works when the server supports the SMB2 server-side copy extension.

```swift
// Duplicate a file within the same share
try connection.copyFile(from: "Photos/vacation.jpg", to: "Photos/vacation_backup.jpg")

// Copy into a different folder
try connection.copyFile(from: "draft.txt", to: "Archive/draft.txt")
```

If the destination file already exists, an error is thrown. The source file must exist and the server must support the SMB2 server-side copy extension.

## Checking whether a path exists

``SMB.Connection.itemExists(at:)`` tells you whether something is at a path and what kind of item it is:

```swift
let existence = try connection.itemExists(at: "Anna/Inbox/report.pdf")

switch existence {
case .false:
    print("Nothing there")
case .file:
    print("It's a file")
case .directory:
    print("It's a directory")
case .link:
    print("It's a symbolic link")
case .other:
    print("It's something else")
}
```

## Reading metadata

``SMB.Connection.stat(at:)`` returns metadata for any path:

```swift
let info = try connection.stat(at: "Anna/Inbox/report.pdf")

print("Size: \(info.size) bytes")
print("Modified: \(info.modificationTime)")
print("Created: \(info.birthTime)")

if info.type == .directory {
    print("It's a directory")
}
```

## Truncating a file

``SMB.Connection.truncateFile(at:toLength:)`` resizes a file by path:

```swift
try connection.truncateFile(at: "log.txt", toLength: 0)
```

## Creating a symbolic link

``SMB.Connection.makeLink(at:pointingTo:)`` creates a symbolic link at the given path:

```swift
try connection.makeLink(at: "shortcuts/projects", pointingTo: "shared/projects")
```

## Reading a symbolic link

``SMB.Connection.readLink(at:bufferSize:)`` returns the target of a symbolic link:

```swift
let target = try connection.readLink(at: "shortcuts/projects")
print("Points to: \(target)")
```

## Filesystem statistics

``SMB.Connection.statFilesystem(at:)`` reports space information for the share:

```swift
let fs = try connection.statFilesystem()

let totalBytes = UInt64(fs.blockSize) * fs.blocks

print("Total:      \(totalBytes) bytes")
print("Free:       \(fs.freeBytes) bytes")
print("Available:  \(fs.availableBytes) bytes")
print("Max filename length: \(fs.maximumNameLength)")
```
