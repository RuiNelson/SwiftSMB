# Playing Media with AVFoundation

The `SwiftSMBAVFoundation` product streams audio and video files from an SMB share into AVFoundation, so you can play
them with `AVPlayer` without downloading them first. Playback starts as soon as AVFoundation has the bytes it needs, and
seeking only fetches the ranges around the new position.

It is available on macOS 11+, iOS 14+, macCatalyst 14+, tvOS 14+, and visionOS 1+. On watchOS, Linux, and Android the
module builds empty, because AVFoundation's resource loader isn't available there.

## Adding the product

Add `SwiftSMBAVFoundation` next to `SwiftSMB` in your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "SwiftSMB", package: "SwiftSMB"),
        .product(name: "SwiftSMBAVFoundation", package: "SwiftSMB"),
    ]
)
```

All examples assume you already have an open ``SMB.Connection``:

```swift
import AVFoundation
import SwiftSMB
import SwiftSMBAVFoundation

let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try await SMB.connect(server: server, credentials: credentials, share: "Documents")
```

## Playing a file

`makePlayerItem(at:)` returns an `AVPlayerItem` backed by the SMB file:

```swift
let player = AVPlayer(playerItem: connection.makePlayerItem(at: "Videos/holiday.mp4"))
player.play()
```

In SwiftUI, hand the player to `VideoPlayer`:

```swift
VideoPlayer(player: player)
```

## Working with the asset

`makeAsset(at:)` returns the underlying `AVURLAsset`, for anything else AVFoundation does with assets, such as loading
properties, generating thumbnails, or reading samples:

```swift
let asset = connection.makeAsset(at: "Videos/holiday.mp4")
let duration = try await asset.load(.duration)

let generator = AVAssetImageGenerator(asset: asset)
let (thumbnail, _) = try await generator.image(at: .zero)
```

Pass `options` to forward `AVURLAsset` options, for example
`[AVURLAssetPreferPreciseDurationAndTimingKey: true]`.

## Content type

AVFoundation needs to know the file's format. SwiftSMB infers it from the path's extension. For files without an
extension, or with one that doesn't match their contents, pass it explicitly:

```swift
let item = connection.makePlayerItem(at: "Videos/holiday", contentType: .mpeg4Movie)
```

When the path has no extension, or one with no registered type, `.movie` is used.

## Connection lifetime and errors

The asset reads through the connection you created it from and keeps it alive for as long as the asset exists. Keep the
connection connected while playing: after `disconnect()`, further reads fail.

While the asset is alive, it keeps the file open on the server, so other clients can't delete or rename it until
the asset is released.

Creating the asset doesn't reach the server. Problems such as a missing file, missing permissions, or a lost connection
show up the way AVFoundation reports any loading failure: `asset.load(_:)` throws, and the player item's `status`
becomes `.failed`. AVFoundation reports its own error and keeps only a POSIX code from the SMB error,
``SMB.Error.posixCode``, as its underlying `NSPOSIXErrorDomain` error: `ENOENT` for a missing file, `EACCES` for missing
permissions, and `ENOTCONN` after `disconnect()`.

```swift
let item = connection.makePlayerItem(at: "Videos/holiday.mp4")
// Keep the observation alive for as long as you need it.
let observation = item.observe(\.status) { item, _ in
    guard item.status == .failed, let error = item.error as NSError? else { return }
    let posixError = error.userInfo[NSUnderlyingErrorKey] as? NSError
    if posixError?.domain == NSPOSIXErrorDomain, posixError?.code == Int(ENOENT) {
        print("The file doesn't exist")
    }
    else {
        print("Playback failed: \(error)")
    }
}
```

## Performance notes

- All requests from AVFoundation share one read-only file handle and read with `SMB.File.read(upTo:atOffset:)`, in
  blocks of `SMB.Connection.acceptedReadBlockSize`. Set `SMB.Configuration.transferBlockSize` to tune it.
- Operations on one connection run one after another, so playback shares the connection with anything else you do on
  it. Use a separate connection for playback if you run large transfers at the same time.

## Sample app

[SampleApp/SMB+AV](../SampleApp/SMB+AV) is a minimal SwiftUI app that connects to a share and plays an audio or video
file from it, on iOS and macOS. Its `ContentView.swift` is the whole example.
