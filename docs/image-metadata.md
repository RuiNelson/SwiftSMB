# Reading and Editing Image Metadata

The `SwiftSMBEXIFKit` product reads, edits, and removes the EXIF metadata of images on an SMB share with
[EXIFKit](https://github.com/RuiNelson/EXIFKit). Reading fetches only the byte ranges that hold metadata, typically a
few kilobytes, instead of downloading the whole image. It supports every format EXIFKit does: JPEG, HEIF, JPEG XL, PNG,
TIFF, DNG, and the camera RAW formats.

The module builds on every platform SwiftSMB supports, including Linux and Android.

## Adding the product

Add `SwiftSMBEXIFKit` next to `SwiftSMB` in your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "SwiftSMB", package: "SwiftSMB"),
        .product(name: "SwiftSMBEXIFKit", package: "SwiftSMB"),
    ]
)
```

The module re-exports EXIFKit, so `import SwiftSMBEXIFKit` also brings in EXIFKit's types, such as `TIFFStructure`,
`Tag`, and `ReadOptions`. All examples assume you already have an open `SMB.Connection`:

```swift
import SwiftSMB
import SwiftSMBEXIFKit

let server = SMB.Server(host: "RASPBERRYPI.local")
let credentials = SMB.Credentials(user: "Anna", password: "1987")
let connection = try await SMB.connect(server: server, credentials: credentials, share: "Photos")
```

## Reading metadata

`imageMetadata(at:)` opens the image read-only, reads its metadata and embedded thumbnail, and closes the file before
returning, also when reading fails:

```swift
let metadata = try await connection.imageMetadata(at: "2026/IMG_0001.HEIC")
print(metadata.make, metadata.model, metadata.dateTimeOriginal)

if let thumbnail = try await metadata.readThumbnail() {
    // JPEG bytes of the embedded preview.
}
```

The image format is detected from the file's contents. Pass `format:` to skip detection, for example
`format: .jpeg`.

## Editing metadata

Change the structure and write it back. `writeImageMetadata(_:at:)` replaces the image in place:

```swift
var metadata = try await connection.imageMetadata(at: "2026/IMG_0001.JPG")
metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Anna"))
try await connection.writeImageMetadata(metadata, at: "2026/IMG_0001.JPG")
```

Pass `to:` to write the edited image to another file and leave the original untouched:

```swift
try await connection.writeImageMetadata(metadata, at: "2026/IMG_0001.JPG", to: "Shared/IMG_0001.JPG")
```

EXIFKit validates the whole edit before writing anything and throws if the format cannot hold it.

## Removing metadata

`removeImageMetadata(at:)` removes the EXIF, GPS, and interoperability structures that the format allows, and keeps the
image readable. Use it before sharing a photo to drop its location:

```swift
try await connection.removeImageMetadata(at: "2026/IMG_0001.JPG", to: "Shared/IMG_0001.JPG")
```

## How edits replace files

An edit by path reads the whole image once, writes the new image to a temporary file next to the destination (named
`.<name>.<random>.exifkit.tmp`), and then renames it over the destination. SMB renames never replace an existing file,
so an existing destination is first renamed to a backup next to it (`.<name>.<random>.exifkit.bak`), renamed back if
the final rename fails, and removed once it succeeds.

- A failure or cancellation leaves the image and any existing destination as they were, and removes the temporary file.
- The new image is a new file. It gets the attributes and security descriptor that the server gives new files in its
  directory, not those of the original image.
- A destination that is a directory makes the edit fail.
- Other clients that hold the image open can make the server refuse the rename (`STATUS_SHARING_VIOLATION`).

## Working with file handles

The same operations exist on `SMB.File` for handles you open yourself:

```swift
let source = try await connection.openFile(at: "2026/IMG_0001.JPG")
defer { try? await source.close() }

var metadata = try await source.imageMetadata()
metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Anna"))

let destination = try await connection.openFile(
    at: "Shared/IMG_0001.JPG",
    accessMode: .readWrite,
    options: [.create, .truncate]
)
defer { try? await destination.close() }

try await source.writeImageMetadata(metadata, to: destination)
```

`EXIFKit.read(file:)`, `EXIFKit.write(_:from:to:)`, and `EXIFKit.strip(from:to:)` are equivalent spellings.

- The structure returned by `imageMetadata()` keeps the handle to read its thumbnail later, and an edit may read the
  thumbnail from it. Keep the handle open while you use the structure, or call `loadingThumbnail()` to copy the
  thumbnail into the structure first.
- The destination must be opened `.readWrite`. EXIFKit truncates it, writes the new image from the start, and flushes it.
  A failure can leave a partial image in it; edit by path to replace files safely.
- An edit throws `SMBFileHandleForEXIFKitError.sameSourceAndDestination` when the source and destination are the same
  handle. Never pass two handles on the same file.
- Reads and writes are positional (`read(upTo:atOffset:)` and `write(_:atOffset:)`), so they neither use nor move the
  handle's current offset, and EXIFKit's concurrent reads can share one handle.

## Read options and performance

Each read is a network round trip, so the conveniences read in aligned 128 KiB blocks, twice EXIFKit's default. A
typical JPEG, HEIF, or RAW file needs one to four reads. Tune the block size and limits with `ReadOptions`:

```swift
let metadata = try await connection.imageMetadata(
    at: "2026/IMG_0001.CR3",
    options: ReadOptions(readAheadBytes: 256 * 1024)
)
```

Every read and write is split into blocks the size of the server's maximum read or write size.

## Errors

- SMB failures surface as `SMB.Error`, for example a missing file or `operationRequestedAfterConnectionClosed` once the
  connection is closed.
- Files that are not images, or are damaged, throw EXIFKit's parsing errors.
- A file that ends before the size the server reported throws EXIFKit's `FileAccessError.shortRead(expected:actual:)`.
- Cancelling the task stops reading and writing with `CancellationError`.
