//
// Part of SwiftSMB
// EXIFKit+Cache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(EXIFKit)
    import Foundation
    import SwiftSMB
    import SwiftSMBEXIFKit
    import Testing

    @Suite("Cache: EXIFKit edits", .tags(.integration), .serialized)
    struct EXIFKitCacheTests {
        @Test("an in-place edit reads through the cache and reports its temporary file and renames")
        func inPlaceEdit() async throws {
            try await withCacheTestDirectory { connection, directory in
                let path = "\(directory)/image.jpg"
                try await connection.dumpToFile(makeJPEG(make: "SwiftSMB"), to: path)
                let cache = RecordingCache()
                connection.attachCache(cache)

                var metadata = try await connection.imageMetadata(at: path)
                metadata.ifd0.set(tagID: Tag.artist, value: .ascii("Photographer"))
                try await connection.writeImageMetadata(metadata, at: path)

                connection.detachCache()
                let edited = try await connection.imageMetadata(at: path)
                let events = await cache.events

                #expect(edited.artist == "Photographer")
                #expect(events.contains(.retrieveBlock(path: path, offset: 0, upTo: 128 * 1024)))

                // The image moves to a backup, the temporary file takes its place, and the backup is removed.
                let renames = events.compactMap { event -> (from: String, to: String)? in
                    guard case let .didRename(from, to) = event else { return nil }
                    return (from, to)
                }
                #expect(renames.count == 2)
                let backup = try #require(renames.first?.to)
                let temporary = try #require(renames.last?.from)
                #expect(renames.first?.from == path)
                #expect(renames.last?.to == path)
                #expect(events.contains(.invalidate(path: temporary)))
                #expect(events.contains { event in
                    if case let .storeBlock(written, _, _, source) = event {
                        return written == temporary && source == .upload
                    }
                    return false
                })
                #expect(events.last == .invalidate(path: backup))
                #expect(await cache.requestContractViolations() == [])
            }
        }
    }
#endif
