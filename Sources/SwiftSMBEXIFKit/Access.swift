//
// Part of SwiftSMB
// Access.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import EXIFKit
import Foundation
import PathWorks
import SwiftSMB

public extension EXIFKit {
    /// Reads the metadata of an image in a remote file through an open SMB file handle.
    ///
    /// EXIFKit fetches only the byte ranges that hold metadata, in aligned blocks of `options.readAheadBytes`. Each
    /// read is a network round trip, so the default blocks are 128 KiB, twice EXIFKit's own default.
    ///
    /// The returned structure keeps `file` to read its thumbnail later, with `readThumbnail()` or when passed to
    /// ``write(_:from:to:format:options:)``. Close `file` once you no longer need either. Reads are positional, so they
    /// neither use nor move the handle's current offset.
    ///
    /// - Parameters:
    ///   - file: An SMB file handle opened for reading. It stays yours to close.
    ///   - format: The image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for the read.
    /// - Returns: The image's metadata.
    /// - Throws: ``SMB/Error``, or EXIFKit's `FileAccessError` and parsing errors.
    static func read(
        file: SMB.File,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws -> TIFFStructure {
        try await read(from: SMBFileHandleForEXIFKit(file), format: format, options: options)
    }

    /// Writes a copy of the image in `source` into `destination`, with its metadata replaced by `metadata`.
    ///
    /// EXIFKit plans and validates the whole edit before touching `destination`, then truncates it, writes the new
    /// image from the start, copying every byte of `source` that is not metadata, and flushes it: editing a remote
    /// image reads all of it once. An I/O failure or cancellation can leave a partial image in `destination`. To
    /// replace a file safely, use ``SMB/Connection/writeImageMetadata(_:at:to:format:options:)``.
    ///
    /// - Parameters:
    ///   - metadata: The metadata to write, usually read from `source` and then changed. The handle it was read from
    /// must still be open, because EXIFKit may read the thumbnail from it.
    ///   - source: The image to copy, opened for reading. It stays yours to close.
    ///   - destination: Another file handle, opened for reading and writing, that receives the new image. It stays
    /// yours to close.
    ///   - format: The source's image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for reading the source.
    /// - Throws: ``SMBFileHandleForEXIFKitError/sameSourceAndDestination`` when `source` and `destination` are the same
    /// handle, ``SMB/Error``, or EXIFKit's errors, such as for an edit the format cannot hold.
    static func write(
        _ metadata: TIFFStructure,
        from source: SMB.File,
        to destination: SMB.File,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws {
        guard source !== destination else {
            throw SMBFileHandleForEXIFKitError.sameSourceAndDestination
        }
        try await write(
            metadata,
            from: SMBFileHandleForEXIFKit(source),
            to: SMBFileHandleForEXIFKit(destination),
            format: format,
            options: options
        )
    }

    /// Writes a copy of the image in `source` into `destination`, with its EXIF metadata removed.
    ///
    /// Like ``write(_:from:to:format:options:)``, but without EXIF: EXIFKit removes the EXIF, GPS and interoperability
    /// structures that the format allows it to, and keeps the image readable.
    ///
    /// - Parameters:
    ///   - source: The image to copy, opened for reading. It stays yours to close.
    ///   - destination: Another file handle, opened for reading and writing, that receives the new image. It stays
    /// yours to close.
    ///   - format: The source's image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for reading the source.
    /// - Throws: ``SMBFileHandleForEXIFKitError/sameSourceAndDestination`` when `source` and `destination` are the same
    /// handle, ``SMB/Error``, or EXIFKit's errors.
    static func strip(
        from source: SMB.File,
        to destination: SMB.File,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws {
        guard source !== destination else {
            throw SMBFileHandleForEXIFKitError.sameSourceAndDestination
        }
        try await strip(
            from: SMBFileHandleForEXIFKit(source),
            to: SMBFileHandleForEXIFKit(destination),
            format: format,
            options: options
        )
    }
}

public extension SMB.File {
    /// Reads the metadata of the image in this remote file.
    ///
    /// The same as ``EXIFKit/read(file:format:options:)`` with this file handle, which the returned structure keeps to
    /// read its thumbnail later. Close the handle once you no longer need the thumbnail.
    ///
    /// - Parameters:
    ///   - format: The image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for the read.
    /// - Returns: The image's metadata.
    /// - Throws: ``SMB/Error``, or EXIFKit's `FileAccessError` and parsing errors.
    func imageMetadata(
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws -> TIFFStructure {
        try await EXIFKit.read(file: self, format: format, options: options)
    }

    /// Writes a copy of the image in this file into `destination`, with its metadata replaced by `metadata`.
    ///
    /// The same as ``EXIFKit/write(_:from:to:format:options:)`` with this file handle as the source.
    ///
    /// - Parameters:
    ///   - metadata: The metadata to write, usually read from this file and then changed.
    ///   - destination: Another file handle, opened for reading and writing, that receives the new image.
    ///   - format: This file's image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for reading this file.
    /// - Throws: ``SMBFileHandleForEXIFKitError/sameSourceAndDestination`` when `destination` is this handle,
    /// ``SMB/Error``, or EXIFKit's errors.
    func writeImageMetadata(
        _ metadata: TIFFStructure,
        to destination: SMB.File,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws {
        try await EXIFKit.write(metadata, from: self, to: destination, format: format, options: options)
    }

    /// Writes a copy of the image in this file into `destination`, with its EXIF metadata removed.
    ///
    /// The same as ``EXIFKit/strip(from:to:format:options:)`` with this file handle as the source.
    ///
    /// - Parameters:
    ///   - destination: Another file handle, opened for reading and writing, that receives the new image.
    ///   - format: This file's image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for reading this file.
    /// - Throws: ``SMBFileHandleForEXIFKitError/sameSourceAndDestination`` when `destination` is this handle,
    /// ``SMB/Error``, or EXIFKit's errors.
    func removeImageMetadata(
        to destination: SMB.File,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws {
        try await EXIFKit.strip(from: self, to: destination, format: format, options: options)
    }
}

public extension SMB.Connection {
    /// Opens a remote image read-only, reads its metadata, and closes the file.
    ///
    /// The file is closed before this returns, also when reading fails. The embedded thumbnail, if the image has one,
    /// is read first and kept in the returned structure, which costs one more request. `readThumbnail()` and edits
    /// therefore work without the file.
    ///
    /// - Parameters:
    ///   - path: The path of the image, relative to the share root.
    ///   - format: The image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for the read; see ``EXIFKit/read(file:format:options:)``.
    /// - Returns: The image's metadata.
    /// - Throws: ``SMB/Error``, for example when the file doesn't exist, or EXIFKit's `FileAccessError` and parsing
    /// errors.
    func imageMetadata(
        at path: String,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws -> TIFFStructure {
        let file = try await openFile(at: path)
        let metadata: TIFFStructure
        do {
            metadata = try await file.imageMetadata(format: format, options: options).loadingThumbnail()
        }
        catch {
            try? await file.close()
            throw error
        }
        try await file.close()
        return metadata
    }

    /// Replaces the metadata of a remote image, in place or into another file.
    ///
    /// The new image is written to a temporary file next to the destination, then renamed over it, so a failure leaves
    /// both the image and an existing destination as they were, and removes the temporary file. SMB renames never
    /// replace an existing file, so an existing destination is first renamed to a backup next to it, which is renamed
    /// back if the final rename fails and removed once it succeeds. The new image is a new file: it takes the
    /// attributes and security descriptor that the server gives new files in its directory, not those of the image.
    ///
    /// ```swift
    /// var metadata = try await connection.imageMetadata(at: "Photos/IMG_0001.JPG")
    /// metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Photographer"))
    /// try await connection.writeImageMetadata(metadata, at: "Photos/IMG_0001.JPG")
    /// ```
    ///
    /// - Parameters:
    ///   - metadata: The metadata to write. EXIFKit copies the embedded thumbnail from the handle the metadata was read
    /// from, so keep that handle open, unless the metadata holds its thumbnail, as metadata from
    /// ``imageMetadata(at:format:options:)`` or `loadingThumbnail()` does.
    ///   - path: The path of the image, relative to the share root.
    ///   - destinationPath: Where to put the new image, replacing any file there, or `nil` to replace the image at
    /// `path`.
    ///   - format: The image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for reading the image.
    /// - Throws: ``SMB/Error``, for example when a path is invalid or the destination is a directory, or EXIFKit's
    /// errors, such as for an edit the format cannot hold.
    func writeImageMetadata(
        _ metadata: TIFFStructure,
        at path: String,
        to destinationPath: String? = nil,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws {
        try await replaceImage(at: destinationPath ?? path, with: path) { source, temporary in
            try await source.writeImageMetadata(metadata, to: temporary, format: format, options: options)
        }
    }

    /// Removes the EXIF metadata of a remote image, in place or into another file.
    ///
    /// Like ``writeImageMetadata(_:at:to:format:options:)``, the new image goes through a temporary file that is
    /// renamed over the destination.
    ///
    /// - Parameters:
    ///   - path: The path of the image, relative to the share root.
    ///   - destinationPath: Where to put the new image, replacing any file there, or `nil` to replace the image at
    /// `path`.
    ///   - format: The image format, or `nil` to detect it from the file's contents.
    ///   - options: Limits and block size for reading the image.
    /// - Throws: ``SMB/Error``, or EXIFKit's errors.
    func removeImageMetadata(
        at path: String,
        to destinationPath: String? = nil,
        format: ImageFormat? = nil,
        options: ReadOptions = ReadOptions(readAheadBytes: 128 * 1024)
    ) async throws {
        try await replaceImage(at: destinationPath ?? path, with: path) { source, temporary in
            try await source.removeImageMetadata(to: temporary, format: format, options: options)
        }
    }
}

private extension SMB.Connection {
    /// Opens the image at `sourcePath`, lets `edit` write the new image into a temporary file next to
    /// `destinationPath`, and renames the temporary file over `destinationPath`.
    ///
    /// On failure, both handles are closed and the temporary file is removed.
    func replaceImage(
        at destinationPath: String,
        with sourcePath: String,
        _ edit: (_ source: SMB.File, _ temporary: SMB.File) async throws -> Void
    ) async throws {
        let temporaryPath = try Self.siblingPath(of: destinationPath, suffix: "tmp")

        let source = try await openFile(at: sourcePath)
        var openSource: SMB.File? = source
        var temporary: SMB.File?
        var createdTemporary = false
        do {
            let file = try await openFile(at: temporaryPath, accessMode: .readWrite, options: [.create, .exclusive])
            temporary = file
            createdTemporary = true

            try await edit(source, file)

            temporary = nil
            try await file.close()
            // A server may refuse to rename a file that is open, as the source is in an in-place edit.
            openSource = nil
            try await source.close()
            try await moveReplacing(from: temporaryPath, to: destinationPath)
        }
        catch {
            try? await temporary?.close()
            try? await openSource?.close()
            if createdTemporary {
                try? await removeFile(at: temporaryPath)
            }
            throw error
        }
    }

    /// Renames `sourcePath` to `destinationPath`, replacing the file or link there.
    ///
    /// libsmb2 renames without `ReplaceIfExists`, so an existing file first moves to a backup path, and back when the
    /// rename fails. A directory, or anything else that is not a file, stays where it is and makes the rename fail.
    func moveReplacing(from sourcePath: String, to destinationPath: String) async throws {
        let backup: String?
        switch try await itemExists(at: destinationPath) {
        case .file, .link:
            let path = try Self.siblingPath(of: destinationPath, suffix: "bak")
            try await move(from: destinationPath, to: path)
            backup = path
        case .false, .directory, .other:
            backup = nil
        }

        do {
            try await move(from: sourcePath, to: destinationPath)
        }
        catch {
            if let backup {
                try? await move(from: backup, to: destinationPath)
            }
            throw error
        }
        if let backup {
            try? await removeFile(at: backup)
        }
    }

    /// A unique path in the directory of `path`, named after its last component.
    static func siblingPath(of path: String, suffix: String) throws -> String {
        guard let name = path.lastPathComponent, !name.isEmpty else {
            throw SMB.Error.invalidArgument(cause: .pathMustContainAtLeastOneComponent, onOperation: .smb2Open)
        }
        let sibling = ".\(name).\(UUID().uuidString.prefix(8)).exifkit.\(suffix)"
        let directory = path.removingLastPathComponent
        return directory.isEmpty ? sibling : directory.appendingPathComponent(sibling)
    }
}
