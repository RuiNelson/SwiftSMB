# Watching File System Changes

This cookbook covers using the SMB change-notification API to watch a directory (and optionally its subtree) for file system events.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try await SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? await connection.disconnect() }
```

## Starting a watcher

``SMB.Connection.watchDirectory(at:options:filter:)`` returns a ``SMB.NotifyWatcher``, an `AsyncSequence` of change batches. The watcher is already armed when the method returns, so changes made after that point are reported:

```swift
let watcher = try await connection.watchDirectory(at: "Anna/Inbox")

for try await changes in watcher {
    for change in changes {
        switch change.action {
        case .added:
            print("Added: \(change.name)")
        case .removed:
            print("Removed: \(change.name)")
        case .modified:
            print("Modified: \(change.name)")
        case .renamedOldName:
            print("Renamed from: \(change.name)")
        case .renamedNewName:
            print("Renamed to: \(change.name)")
        default:
            print("Other action on: \(change.name)")
        }
    }
}
print("Watcher stopped")
```

Each element is the batch of changes reported by one SMB notification. The loop ends normally when the watcher is cancelled, and throws when the server or the network reports an error.

If the server can no longer list the individual changes, typically because too many happened at once, the loop throws
``SMB.Error`` with ``SMB.SMBStatus.notifyEnumDir``. Re-read the directory to pick up what changed, then start a new
watcher:

```swift
do {
    for try await changes in watcher {
        handle(changes)
    }
}
catch SMB.Error.ntStatus(.notifyEnumDir, _, _, _) {
    let entries = try await connection.listDirectory(at: "Inbox")
    rescan(entries)
}
```

## Filtering events

You can restrict the kinds of changes the server reports with ``SMB.NotifyFilter``:

```swift
let watcher = try await connection.watchDirectory(
    at: "Anna/Inbox",
    filter: [.fileName, .directoryName, .size]
)
```

Available filters:

- ``SMB.NotifyFilter.fileName``
- ``SMB.NotifyFilter.directoryName``
- ``SMB.NotifyFilter.attributes``
- ``SMB.NotifyFilter.size``
- ``SMB.NotifyFilter.lastWrite``
- ``SMB.NotifyFilter.lastAccess``
- ``SMB.NotifyFilter.creation``
- ``SMB.NotifyFilter.extendedAttributes``
- ``SMB.NotifyFilter.security``
- ``SMB.NotifyFilter.streamName``
- ``SMB.NotifyFilter.streamSize``
- ``SMB.NotifyFilter.streamWrite``
- ``SMB.NotifyFilter.all`` — the default

## Watching recursively

Pass ``SMB.NotifyOptions.recursive`` to watch the entire subtree rooted at the requested directory:

```swift
let watcher = try await connection.watchDirectory(
    at: "Anna",
    options: .recursive
)
```

## Watching in the background

A `for try await` loop suspends until the watcher stops, so run it in its own task when you need to keep doing other work:

```swift
let watchTask = Task {
    for try await changes in watcher {
        print("Received \(changes.count) changes")
    }
}

// Later, when you no longer need notifications:
watchTask.cancel()
```

Cancelling the task that iterates the watcher also cancels the watcher.

## Cancelling a watcher

Call ``SMB.NotifyWatcher.cancel()`` when you no longer need notifications. Cancellation is idempotent, returns immediately, and ends the iteration normally:

```swift
watcher.cancel()
```

The watcher also cancels automatically when it is deallocated and nothing is iterating it, but explicit cancellation is recommended so you control the timing.

## Important notes

- Iterate a watcher from one task at a time.
- Change batches that arrive while nothing is iterating are buffered until they are consumed.
- The watcher re-arms itself automatically after each batch of changes, so it runs continuously until cancelled.
- Watches are cancelled automatically when the parent ``SMB.Connection`` is disconnected or deallocated; iteration then ends normally.
- A watcher checks for replies about every 50 ms without holding its connection, so other operations on the same connection are not delayed noticeably.
