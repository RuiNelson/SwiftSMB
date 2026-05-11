# Watching File System Changes

This cookbook covers using the SMB change-notification API to watch a directory (and optionally its subtree) for file system events.

All examples assume you already have an open ``SMB.Connection``:

```swift
let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try SMB.connect(server: server, credentials: credentials, share: "Documents")
defer { try? connection.disconnect() }
```

## Starting a watcher

``SMB.Connection.watchDirectory(at:options:filter:delegate:callbackQueue:)`` returns a ``SMB.NotifyWatcher`` that reports changes as they happen:

```swift
class MyWatcherDelegate: SMB.NotifyWatcherDelegate {
    func notifyWatcher(
        _ watcher: SMB.NotifyWatcher,
        didReceive changes: [SMB.NotifyChange]
    ) {
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

    func notifyWatcherDidStart(_ watcher: SMB.NotifyWatcher) {
        print("Watcher is now active")
    }

    func notifyWatcher(
        _ watcher: SMB.NotifyWatcher,
        didFailWith error: Swift.Error
    ) {
        print("Watcher failed: \(error)")
    }

    func notifyWatcherDidCancel(_ watcher: SMB.NotifyWatcher) {
        print("Watcher stopped")
    }
}

let delegate = MyWatcherDelegate()
let watcher = try connection.watchDirectory(
    at: "Anna/Inbox",
    delegate: delegate
)

// Keep watcher alive as long as you need notifications.
// Call cancel() when done:
// watcher.cancel()
```

## Filtering events

You can restrict the kinds of changes the server reports with ``SMB.NotifyFilter``:

```swift
let watcher = try connection.watchDirectory(
    at: "Anna/Inbox",
    filter: [.fileName, .directoryName, .size],
    delegate: delegate
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
let watcher = try connection.watchDirectory(
    at: "Anna",
    options: .recursive,
    delegate: delegate
)
```

## Controlling the callback queue

By default delegate callbacks are delivered on the main queue. You can specify a different queue:

```swift
let queue = DispatchQueue(label: "com.example.smb-watcher")
let watcher = try connection.watchDirectory(
    at: "Anna/Inbox",
    delegate: delegate,
    callbackQueue: queue
)
```

## Cancelling a watcher

Call ``SMB.NotifyWatcher.cancel()`` when you no longer need notifications. Cancellation is idempotent and safe to call multiple times:

```swift
watcher.cancel()
```

The watcher also cancels automatically when it is deallocated, but explicit cancellation is recommended so you control the timing.

## Important notes

- The watcher holds a **weak** reference to its delegate. Keep your delegate object alive for as long as the watcher is running.
- Only one watcher callback will be in flight at a time per watcher.
- The watcher re-arms itself automatically after each batch of changes, so it runs continuously until cancelled.
- Watches are cancelled automatically when the parent ``SMB.Connection`` is disconnected or deallocated.
