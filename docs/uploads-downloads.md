# Uploads and Downloads

This cookbook covers the high-level convenience methods for transferring files between the local machine and an SMB share.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? connection.disconnect() }
```

## Uploading a local file

``SMB.Connection.uploadFile(local:remote:chunkSize:progress:)`` copies a local file to the share. By default it stages the upload through a temporary remote file and renames it into place when the transfer succeeds, so the destination path never contains a partial file:

```swift
let localURL = URL(fileURLWithPath: "/Users/Anna/Desktop/report.pdf")

try connection.uploadFile(
    local: localURL,
    remote: "Anna/Inbox/report.pdf"
) { completed, total, lastBlockSpeed, averageSpeed in
    let speed = 0.5 * Double(lastBlockSpeed) + 0.5 * Double(averageSpeed)
    print("Uploaded \(completed) of \(total) bytes at \(round(speed / 1024.0)) kiB/s")
    return true
}
```

Return `false` from the progress closure to cancel the upload. The temporary staging file is cleaned up automatically.

You can also pass a preferred block size. Values above the server maximum are clamped automatically:

```swift
try connection.uploadFile(
    local: localURL,
    remote: "Anna/Inbox/report.pdf",
    chunkSize: 256 * 1024
) { _, _, _, _ in true }
```

## Downloading a remote file

``SMB.Connection.downloadFile(remote:local:chunkSize:progress:)`` copies a file from the share to local storage. The download is written to a temporary local file first and moved into place after the transfer succeeds:

```swift
let localURL = URL(fileURLWithPath: "/Users/Anna/Downloads/report.pdf")

try connection.downloadFile(
    remote: "Anna/Inbox/report.pdf",
    local: localURL
) { completed, total, lastBlockSpeed, averageSpeed in
    print("Downloaded \(completed) of \(total) bytes")
    return true
}
```

Return `false` from the progress closure to cancel the download. The temporary local file is removed automatically.

## Loading a file into memory

If the file is small enough to fit in memory, ``SMB.Connection.loadFile(at:chunkSize:)`` reads the entire file in one call:

```swift
let data = try connection.loadFile(at: "Anna/Inbox/report.pdf")
print("Loaded \(data.count) bytes")
```

## Writing to a file from memory

``SMB.Connection.dumpToFile(_:to:options:chunkSize:)`` writes a `Data` value to a share path. By default it creates the file if needed and truncates any existing content:

```swift
let payload = Data("Hello, SMB!".utf8)
try connection.dumpToFile(payload, to: "greeting.txt")
```

You can control how the file is opened with ``SMB.File.OpenOptions``:

```swift
// Append instead of replacing
try connection.dumpToFile(
    payload,
    to: "log.txt",
    options: [.create, .append]
)
```

## Choosing a block size

Both upload and download accept an optional `chunkSize`. The library clamps the value to the server's maximum automatically, so you can safely request a large block size:

```swift
let maxRead = try connection.acceptedReadBlockSize(128 * 1024 * 1024)
let data = try connection.loadFile(at: "big.bin", chunkSize: maxRead)
```
