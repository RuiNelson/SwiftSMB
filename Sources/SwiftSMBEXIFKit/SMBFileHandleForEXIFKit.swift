//
// Part of SwiftSMB
// SMBFileHandleForEXIFKit.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import EXIFKit
import Foundation
import SwiftSMB

/// An EXIFKit file handle that reads and writes a remote file through an open SMB file handle.
///
/// The public conveniences in `Access.swift` wrap SMB handles in this type. EXIFKit reads only the byte ranges that
/// hold metadata, so reading a remote image's EXIF transfers a few kilobytes, not the whole file.
///
/// ### Positional I/O
///
/// Reads and writes go through `SMB.File.read(upTo:atOffset:transferChunkSize:)` and
/// `SMB.File.write(_:atOffset:transferChunkSize:)`, which neither use nor move the handle's current offset. EXIFKit's
/// concurrent reads therefore share one handle without coordinating, and the handle stays usable for other positional
/// reads while EXIFKit works with it.
///
/// ### Ownership
///
/// This type never closes ``file``. A `TIFFStructure` read through it keeps it, and so the SMB handle, to read its
/// thumbnail later.
///
/// EXIFKit rejects an edit whose source and destination are the same wrapper, but it cannot tell two wrappers of one
/// SMB handle, or two handles on one remote file, apart. The public edits in `Access.swift` reject the same SMB handle
/// themselves.
///
/// ### Errors
///
/// SMB failures surface unchanged as `SMB.Error`, for example `operationRequestedAfterConnectionClosed` once the
/// connection is closed. Reads past the end throw EXIFKit's `FileAccessError.invalidRange(offset:count:size:)`, and a
/// file that ends before the size it reported throws `FileAccessError.shortRead(expected:actual:)`.
final class SMBFileHandleForEXIFKit: AbstractFileHandle, Sendable {
    /// The SMB file handle that this handle reads and writes. It stays yours to close.
    let file: SMB.File

    /// Creates an EXIFKit file handle for an open SMB file handle.
    ///
    /// - Parameter file: An open SMB file handle, opened for reading, and for reading and writing when EXIFKit writes
    /// to it.
    init(_ file: SMB.File) {
        self.file = file
    }

    /// The remote file's current length, from the server's metadata for the open handle.
    ///
    /// - Throws: `SMB.Error` if the metadata cannot be read.
    var size: UInt64 {
        get async throws {
            try await file.stat().size
        }
    }

    /// Reads exactly `count` bytes starting at `offset`.
    ///
    /// - Throws: `FileAccessError.invalidRange(offset:count:size:)` for a negative count or a range that extends past
    /// the end, `FileAccessError.shortRead(expected:actual:)` when the file ends early, `CancellationError`, or
    /// `SMB.Error`.
    func read(at offset: UInt64, count: Int) async throws -> Data {
        guard count > 0 else {
            let size = try await size
            guard count == 0, offset <= size else {
                throw FileAccessError.invalidRange(offset: offset, count: count, size: size)
            }
            return Data()
        }
        let (end, overflow) = offset.addingReportingOverflow(UInt64(count))
        guard !overflow else {
            throw try await FileAccessError.invalidRange(offset: offset, count: count, size: size)
        }

        let data = try await file.read(upTo: Int64(count), atOffset: offset)
        guard data.count == count else {
            // Only an unexpected end costs the round trip that tells the two failures apart.
            let size = try await size
            guard end <= size else {
                throw FileAccessError.invalidRange(offset: offset, count: count, size: size)
            }
            throw FileAccessError.shortRead(expected: count, actual: data.count)
        }
        return data
    }

    /// Writes `data` at `offset`, extending the remote file as needed.
    ///
    /// Writing past the end leaves a gap that the server fills as its file system does; Windows and Samba servers read
    /// it back as zeros.
    ///
    /// - Throws: `FileAccessError.invalidRange(offset:count:size:)` when the file would grow past `UInt64.max` bytes,
    /// `CancellationError`, or `SMB.Error`.
    func write(_ data: Data, at offset: UInt64) async throws {
        guard !data.isEmpty else {
            return
        }
        guard UInt64(data.count) <= UInt64.max - offset else {
            throw try await FileAccessError.invalidRange(offset: offset, count: data.count, size: size)
        }
        try await file.write(data, atOffset: offset)
    }

    /// Sets the remote file's length to `size` bytes.
    ///
    /// - Throws: `SMB.Error` if the server rejects the length.
    func truncate(to size: UInt64) async throws {
        try await file.truncate(toLength: size)
    }

    /// Asks the server to flush the remote file to stable storage.
    ///
    /// Writes and truncations reach the remote file as soon as the server acknowledges them, before this call.
    ///
    /// - Throws: `SMB.Error` if the flush fails.
    func synchronize() async throws {
        try await file.sync()
    }
}
