//
// Part of SwiftSMB
// EXIFKitIntegrationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMBEXIFKit
import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct EXIFKitIntegrationTests {
    @Test("EXIFKit reads, edits and strips a remote image through SMB handles")
    func readEditAndStrip() async throws {
        try await withTestDirectory { connection, directory in
            let original = "\(directory)/original.jpg"
            let edited = "\(directory)/edited.jpg"
            let stripped = "\(directory)/stripped.jpg"
            let jpeg = makeJPEG(make: "SwiftSMB")
            try await connection.dumpToFile(jpeg, to: original)

            try await withFile(connection, at: original) { sourceFile in
                let source = SMBFileHandleForEXIFKit(sourceFile)
                var metadata = try await EXIFKit.read(from: source)
                #expect(metadata.make == "SwiftSMB")
                metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Photographer"))

                try await withFile(connection, at: edited, accessMode: .readWrite, options: [.create]) { file in
                    try await EXIFKit.write(metadata, from: source, to: SMBFileHandleForEXIFKit(file))
                }
                try await withFile(connection, at: stripped, accessMode: .readWrite, options: [.create]) { file in
                    try await EXIFKit.strip(from: source, to: SMBFileHandleForEXIFKit(file))
                }
            }

            let metadata = try await connection.imageMetadata(at: edited)
            #expect(metadata.make == "SwiftSMB")
            #expect(metadata.artist == "Photographer")

            let contents = try await connection.loadFile(at: stripped)
            #expect(contents.count < jpeg.count)
            #expect(contents.range(of: Data("SwiftSMB".utf8)) == nil)
            #expect(contents.suffix(2) == Data([0xFF, 0xD9]))
        }
    }

    @Test("concurrent reads through one handle return their own ranges and leave the file offset")
    func concurrentReads() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/ranges.bin"
            let content = Data((0 ..< 64 * 1024).map { UInt8(truncatingIfNeeded: $0 &* 31) })
            try await connection.dumpToFile(content, to: path)

            try await withFile(connection, at: path) { file in
                try await file.seek(offset: 5, from: .start)
                let handle = SMBFileHandleForEXIFKit(file)
                let ranges = stride(from: 0, to: content.count, by: 4096).map { $0 ..< $0 + 4096 }
                let results = try await withThrowingTaskGroup(of: (Range<Int>, Data).self) { group in
                    for range in ranges {
                        group.addTask {
                            try await (range, handle.read(at: UInt64(range.lowerBound), count: range.count))
                        }
                    }
                    return try await group.reduce(into: []) { $0.append($1) }
                }
                #expect(results.count == ranges.count)
                for (range, data) in results {
                    #expect(data == content[range])
                }
                #expect(try await file.seek(offset: 0, from: .current) == 5)
            }
        }
    }

    @Test("metadata read by path keeps the thumbnail after the file is closed, and edits keep it")
    func imageMetadataAtPathKeepsThumbnail() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/thumbnail.jpg"
            let thumbnail = Data([0xFF, 0xD8, 0xFF, 0xD9, 1, 2, 3, 4])
            try await connection.dumpToFile(makeJPEG(make: "SwiftSMB", thumbnail: thumbnail), to: path)

            var metadata = try await connection.imageMetadata(at: path)
            #expect(try await metadata.readThumbnail() == thumbnail)

            metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Photographer"))
            try await connection.writeImageMetadata(metadata, at: path)
            let edited = try await connection.imageMetadata(at: path)
            #expect(edited.artist == "Photographer")
            #expect(try await edited.readThumbnail() == thumbnail)
        }
    }

    @Test("a connection reads a remote image's metadata by path")
    func imageMetadataAtPath() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/photo.jpg"
            try await connection.dumpToFile(makeJPEG(make: "SwiftSMB"), to: path)

            let metadata = try await connection.imageMetadata(at: path)
            #expect(metadata.make == "SwiftSMB")
            #expect(try await metadata.readThumbnail() == nil)
        }
    }

    @Test("reading metadata by path throws for a missing file or one that is not an image")
    func imageMetadataFailure() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/not-an-image.bin"
            try await connection.dumpToFile(Data(repeating: 0x42, count: 4096), to: path)

            await #expect(throws: (any Error).self) {
                try await connection.imageMetadata(at: path)
            }
            await #expect(throws: SMB.Error.self) {
                try await connection.imageMetadata(at: "\(directory)/missing.jpg")
            }
            // Both files were closed: the server deletes only files that nobody holds open.
            try await connection.removeFile(at: path)
        }
    }

    @Test("a connection replaces a remote image's metadata in place, leaving no other file behind")
    func writeImageMetadataInPlace() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/in-place.jpg"
            try await connection.dumpToFile(makeJPEG(make: "SwiftSMB"), to: path)

            var metadata = try await connection.imageMetadata(at: path)
            metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Photographer"))
            try await connection.writeImageMetadata(metadata, at: path)

            let edited = try await connection.imageMetadata(at: path)
            #expect(edited.make == "SwiftSMB")
            #expect(edited.artist == "Photographer")
            #expect(try await names(in: directory, on: connection) == ["in-place.jpg"])
        }
    }

    @Test("a connection removes a remote image's metadata into another file, replacing it, and keeps the original")
    func removeImageMetadataIntoAnotherFile() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/original.jpg"
            let copy = "\(directory)/stripped.jpg"
            let jpeg = makeJPEG(make: "SwiftSMB")
            try await connection.dumpToFile(jpeg, to: path)
            try await connection.dumpToFile(Data("previous".utf8), to: copy)

            try await connection.removeImageMetadata(at: path, to: copy)

            let contents = try await connection.loadFile(at: copy)
            #expect(contents.range(of: Data("SwiftSMB".utf8)) == nil)
            #expect(contents.suffix(2) == Data([0xFF, 0xD9]))
            #expect(try await connection.loadFile(at: path) == jpeg)
            #expect(try await names(in: directory, on: connection) == ["original.jpg", "stripped.jpg"])
        }
    }

    @Test("a failed edit by path leaves the file as it was and no temporary file behind")
    func failedEditLeavesFileIntact() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/not-an-image.bin"
            let bytes = Data(repeating: 0x42, count: 4096)
            try await connection.dumpToFile(bytes, to: path)

            await #expect(throws: (any Error).self) {
                try await connection.removeImageMetadata(at: path)
            }
            #expect(try await connection.loadFile(at: path) == bytes)
            #expect(try await names(in: directory, on: connection) == ["not-an-image.bin"])
        }
    }

    @Test("an edit into a directory fails and removes its temporary file")
    func editIntoDirectoryFails() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/photo.jpg"
            let target = "\(directory)/folder"
            try await connection.dumpToFile(makeJPEG(make: "SwiftSMB"), to: path)
            try await connection.makeDirectory(at: target)

            await #expect(throws: SMB.Error.self) {
                try await connection.removeImageMetadata(at: path, to: target)
            }
            #expect(try await connection.itemExists(at: target) == .directory)
            #expect(try await names(in: directory, on: connection) == ["folder", "photo.jpg"])
        }
    }

    @Test("an edit rejects the same handle as source and destination")
    func sameSourceAndDestination() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/photo.jpg"
            let jpeg = makeJPEG(make: "SwiftSMB")
            try await connection.dumpToFile(jpeg, to: path)

            try await withFile(connection, at: path, accessMode: .readWrite) { file in
                let metadata = try await file.imageMetadata()
                await #expect(throws: SMBFileHandleForEXIFKitError.sameSourceAndDestination) {
                    try await file.writeImageMetadata(metadata, to: file)
                }
                await #expect(throws: SMBFileHandleForEXIFKitError.sameSourceAndDestination) {
                    try await file.removeImageMetadata(to: file)
                }
            }
            #expect(try await connection.loadFile(at: path) == jpeg)
        }
    }

    @Test("writes past the end and growing truncation read back as zeros on the server")
    func sparseWritesAndTruncation() async throws {
        try await withTestDirectory { connection, directory in
            let path = "\(directory)/sparse.bin"
            try await withFile(connection, at: path, accessMode: .readWrite, options: [.create]) { file in
                let handle = SMBFileHandleForEXIFKit(file)
                #expect(try await handle.size == 0)
                try await handle.write(Data([1, 2, 3]), at: 0)
                try await handle.write(Data([9]), at: 6)
                #expect(try await handle.size == 7)
                #expect(try await handle.read(at: 0, count: 7) == Data([1, 2, 3, 0, 0, 0, 9]))
                #expect(try await handle.read(at: 7, count: 0).isEmpty)

                try await handle.truncate(to: 2)
                try await handle.truncate(to: 4)
                #expect(try await handle.read(at: 0, count: 4) == Data([1, 2, 0, 0]))
                await #expect(throws: FileAccessError.self) {
                    try await handle.read(at: 2, count: 3)
                }
                await #expect(throws: FileAccessError.self) {
                    try await handle.read(at: 5, count: 0)
                }
                await #expect(throws: FileAccessError.self) {
                    try await handle.read(at: 0, count: -1)
                }
                try await handle.synchronize()
            }
        }
    }
}

/// Runs `body` with a connection to the public share and a new directory in it, then removes the directory.
private func withTestDirectory(_ body: (SMB.Connection, String) async throws -> Void) async throws {
    let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
    defer { try? await connection.disconnect() }

    let directory = uniquePath("exifkit")
    try await connection.makeDirectory(at: directory)
    do {
        try await body(connection, directory)
    }
    catch {
        try? await connection.removeItem(at: directory)
        throw error
    }
    try await connection.removeItem(at: directory)
}

/// Opens `path`, runs `body` with the handle, and closes the handle whether or not `body` throws.
private func withFile(
    _ connection: SMB.Connection,
    at path: String,
    accessMode: SMB.File.AccessMode = .readOnly,
    options: SMB.File.OpenOptions = [],
    _ body: (SMB.File) async throws -> Void
) async throws {
    let file = try await connection.openFile(at: path, accessMode: accessMode, options: options)
    do {
        try await body(file)
    }
    catch {
        try? await file.close()
        throw error
    }
    try await file.close()
}

/// The sorted names of the entries in `directory`, without `.` and `..`.
private func names(in directory: String, on connection: SMB.Connection) async throws -> [String] {
    try await connection.listDirectory(at: directory).map(\.name).filter { $0 != "." && $0 != ".." }.sorted()
}

/// A minimal JPEG that EXIFKit reads and edits: SOI, an APP1 segment whose IFD0 holds only `Make`, optionally an IFD1
/// with a JPEG thumbnail, a scan, and EOI.
func makeJPEG(make: String, thumbnail: Data? = nil) -> Data {
    func le16(_ value: UInt16) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
    func le32(_ value: UInt32) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
    var value = Data(make.utf8) + [0]
    if value.count % 2 == 1 {
        value.append(0)
    }
    let ifd1Offset = UInt32(8 + 2 + 12 + 4 + value.count)
    var tiff = Data([0x49, 0x49, 0x2A, 0x00]) + le32(8) + le16(1)
    tiff += le16(0x010F) + le16(2) + le32(UInt32(value.count)) + le32(8 + 2 + 12 + 4)
    tiff += le32(thumbnail == nil ? 0 : ifd1Offset) + value
    if let thumbnail {
        // Compression, JPEGInterchangeFormat and JPEGInterchangeFormatLength, then the next-IFD offset.
        tiff += le16(3)
        tiff += le16(0x0103) + le16(3) + le32(1) + le16(6) + le16(0)
        tiff += le16(0x0201) + le16(4) + le32(1) + le32(ifd1Offset + 2 + 3 * 12 + 4)
        tiff += le16(0x0202) + le16(4) + le32(1) + le32(UInt32(thumbnail.count))
        tiff += le32(0) + thumbnail
    }
    let payload = Data("Exif".utf8) + [0, 0] + tiff
    let length = UInt16(payload.count + 2)
    let scan = Data([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00])
        + Data((0 ..< 256 * 1024).map { UInt8($0 % 0xFF) })
    return Data([0xFF, 0xD8, 0xFF, 0xE1, UInt8(length >> 8), UInt8(length & 0xFF)]) + payload + scan + [0xFF, 0xD9]
}
