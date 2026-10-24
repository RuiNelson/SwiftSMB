//
// Part of SwiftSMB
// CookbookImageMetadataTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import SwiftSMBEXIFKit
import Testing

@Suite(.tags(.integration))
struct CookbookImageMetadataTests {
    @Test("read, edit and remove metadata by path compiles and runs")
    func byPath() async throws {
        try await withCookbookPhoto { connection, photo, shared in
            let metadata = try await connection.imageMetadata(at: photo)
            print(metadata.make as Any, metadata.model as Any, metadata.dateTimeOriginal as Any)
            if let thumbnail = try await metadata.readThumbnail() {
                #expect(!thumbnail.isEmpty)
            }

            var edited = try await connection.imageMetadata(at: photo)
            edited.ifd0.set(tagID: Tag.artist, value: .ascii("Anna"))
            try await connection.writeImageMetadata(edited, at: photo)
            try await connection.writeImageMetadata(edited, at: photo, to: shared)
            try await connection.removeImageMetadata(at: photo, to: shared)

            let tuned = try await connection.imageMetadata(at: photo, options: ReadOptions(readAheadBytes: 256 * 1024))
            #expect(tuned.artist == "Anna")
            #expect(try await connection.loadFile(at: shared).range(of: Data("Anna".utf8)) == nil)
        }
    }

    @Test("edit through file handles compiles and runs")
    func withHandles() async throws {
        try await withCookbookPhoto { connection, photo, shared in
            do {
                let source = try await connection.openFile(at: photo)
                defer { try? await source.close() }

                var metadata = try await source.imageMetadata()
                metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Anna"))

                let destination = try await connection.openFile(
                    at: shared,
                    accessMode: .readWrite,
                    options: [.create, .truncate]
                )
                defer { try? await destination.close() }

                try await source.writeImageMetadata(metadata, to: destination)
            }
            #expect(try await connection.imageMetadata(at: shared).artist == "Anna")
        }
    }
}

/// Runs `body` with a photo and a destination path for its edited copy, in a directory removed afterwards.
private func withCookbookPhoto(_ body: (SMB.Connection, String, String) async throws -> Void) async throws {
    let connection = try await cookbookConnection()
    defer { try? await connection.disconnect() }

    let directory = uniquePath("cookbook-exif")
    try await connection.makeDirectory(at: directory)
    do {
        let photo = "\(directory)/IMG_0001.JPG"
        try await connection.dumpToFile(makeJPEG(make: "SwiftSMB"), to: photo)
        try await body(connection, photo, "\(directory)/shared.jpg")
    }
    catch {
        try? await connection.removeItem(at: directory)
        throw error
    }
    try await connection.removeItem(at: directory)
}
