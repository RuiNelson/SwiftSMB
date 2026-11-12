//
// Part of SwiftSMB
// ReferenceCacheRaceIntegrationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

/// The reference cache attached to a real connection, on the test server, with single cache calls held back to put the
/// calls of two tasks in a chosen order. The connection makes its calls from the tasks its operations run on, so the
/// order in which the calls of two operations reach the cache is not the order in which the server ran them: every
/// order held here is one that scheduling alone can produce.
///
/// Samba refuses to rename or delete a file that is open, or a directory above one, so the orderings in which a rename
/// or a delete overtakes a report of an open file are left to `ReferenceCacheSimulationTests`. Here a rename of an open
/// file fails, as it does on Samba, and silences the file.
///
/// After each scenario, what the cached connection reads is compared with what a connection without a cache reads.
@Suite("ReferenceCache: orderings with a live connection", .tags(.integration), .serialized)
struct ReferenceCacheRaceIntegrationTests {
    static let payload = cachePayload(byteCount: 64 * 1024)
    static let other = Data(cachePayload(byteCount: 64 * 1024).reversed())
    static let marker = Data(repeating: 0xEE, count: 1000)

    static let matchings: [SMB.ReferenceCache.PathMatching] = [.exact, .caseInsensitive]

    // MARK: Reports held across changes

    @Test("bytes read before a write, held on their way to the cache until after it, are not kept")
    func downloadHeldAcrossAWrite() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)

            let reader = try await connections.connection.openFile(at: path)
            let gate = connections.gated.hold(.storeDownload, path: path)
            let reading = Task { try await reader.read(upTo: 8192, atOffset: 0) }
            try await gate.waitUntilReached()

            try await overwriteRemote(connections.fork, path, at: 1000, with: Self.marker)

            gate.open()
            _ = try await reading.value
            try await reader.close()

            let cached = try await readRemote(connections.connection, path, at: 0, count: 8192)
            let held = try await readRemote(connections.truth, path, at: 0, count: 8192)

            #expect(held == overwritten(Self.payload, at: 1000, with: Self.marker).prefix(8192))
            #expect(cached == held)
        }
    }

    @Test("a stat fetched before a delete, held until after it, is neither kept nor answered from")
    func statHeldAcrossADelete() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 60, includingMissing: true))
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.marker)

            let gate = connections.gated.hold(.storeStat, path: path)
            let connection = connections.connection
            let statting = Task { try await connection.stat(at: path) }
            try await gate.waitUntilReached()

            try await connections.fork.removeFile(at: path)
            gate.open()
            #expect(try await statting.value.size == UInt64(Self.marker.count))

            #expect(try await connections.connection.itemExists(at: path) == .false)
            #expect(try await connections.truth.itemExists(at: path) == .false)
        }
    }

    @Test("a listing fetched before a delete, held until after it, is neither kept nor answered from")
    func listingHeldAcrossADelete() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 60, includingMissing: true))
        try await withCachedConnections(configuration) { connections in
            let directory = connections.directory
            try await writeRemote(connections.truth, "\(directory)/deleted", Self.marker)
            try await writeRemote(connections.truth, "\(directory)/kept", Self.marker)

            let gate = connections.gated.hold(.storeDirectoryListing, path: directory)
            let connection = connections.connection
            let listing = Task { try await connection.listDirectory(at: directory) }
            try await gate.waitUntilReached()

            try await connections.fork.removeFile(at: "\(directory)/deleted")
            gate.open()
            _ = try await listing.value

            let after = try await connections.connection.listDirectory(at: directory)
            let exists = try await connections.connection.itemExists(at: "\(directory)/deleted")

            #expect(Set(after.map(\.name)).subtracting([".", ".."]) == ["kept"])
            #expect(exists == .false)
        }
    }

    @Test("a final stat of a written file, held across a truncation by path, does not vouch for the written bytes")
    func finalStatHeldAcrossATruncation() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)

            let writer = try await connections.connection.openFile(at: path, accessMode: .readWrite)
            try await writer.write(Self.marker, atOffset: 30000)

            // The final stat of the close is answered; its report waits while the file is cut short and grown back.
            let gate = connections.gated.hold(.storeStat, path: path)
            let closing = Task { try await writer.close() }
            try await gate.waitUntilReached()
            try await connections.fork.truncateFile(at: path, toLength: 100)
            try await connections.fork.truncateFile(at: path, toLength: UInt64(Self.payload.count))
            gate.open()
            try await closing.value

            let cached = try await readRemote(connections.connection, path)
            let held = try await readRemote(connections.truth, path)

            #expect(held == Self.payload.prefix(100) + Data(count: Self.payload.count - 100))
            #expect(cached == held)
        }
    }

    // MARK: Changes reported in the other order

    @Test(
        "two writes to the same bytes through two handles, reported in the other order, leave the cache with the last"
    )
    func overlappingWritesReportedOutOfOrder() async throws {
        let earlier = Data(repeating: 0xA1, count: 1000)
        let later = Data(repeating: 0xB2, count: 1000)

        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            let first = try await connections.connection.openFile(at: path, accessMode: .writeOnly)
            let second = try await connections.fork.openFile(at: path, accessMode: .writeOnly)

            // The server takes the first write, whose report is held, then the second, over it.
            let gate = connections.gated.hold(.storeUpload, path: path)
            let writing = Task { try await first.write(earlier, atOffset: 2000) }
            try await gate.waitUntilReached()
            try await second.write(later, atOffset: 2000)
            gate.open()
            try await writing.value
            try await first.close()
            try await second.close()

            let cached = try await readRemote(connections.connection, path, at: 2000, count: 1000)
            let held = try await readRemote(connections.truth, path, at: 2000, count: 1000)

            #expect(held == later)
            #expect(cached == held)
        }
    }

    @Test(
        "two writes to the same bytes through handles opened under names that differ in case, reported in the other order",
        arguments: matchings
    )
    func overlappingWritesThroughTwoSpellings(matching: SMB.ReferenceCache.PathMatching) async throws {
        let earlier = Data(repeating: 0xA1, count: 1000)
        let later = Data(repeating: 0xB2, count: 1000)

        try await withCachedConnections(.init(pathMatching: matching)) { connections in
            let path = "\(connections.directory)/file.bin"
            let respelled = "\(connections.directory)/FILE.bin"
            try await writeRemote(connections.truth, path, Self.payload)

            // Samba ignores case: one file, two handles.
            let first = try await connections.connection.openFile(at: path, accessMode: .writeOnly)
            let second = try await connections.fork.openFile(at: respelled, accessMode: .writeOnly)

            let gate = connections.gated.hold(.storeUpload, path: path)
            let writing = Task { try await first.write(earlier, atOffset: 2000) }
            try await gate.waitUntilReached()
            try await second.write(later, atOffset: 2000)
            gate.open()
            try await writing.value
            try await first.close()
            try await second.close()

            let cached = try await readRemote(connections.connection, path, at: 2000, count: 1000)
            let cachedRespelled = try await readRemote(connections.connection, respelled, at: 2000, count: 1000)
            let held = try await readRemote(connections.truth, path, at: 2000, count: 1000)

            #expect(held == later)
            #expect(cached == held)
            #expect(cachedRespelled == held)
        }
    }

    @Test("an append reported after another handle's write to the file does not leave the old bytes cached")
    func appendReportedAfterAWrite() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)

            // Cached as it is now.
            _ = try await readRemote(connections.connection, path)

            let appender = try await connections.connection.openFile(
                at: path,
                accessMode: .writeOnly,
                options: [.append]
            )
            let gate = connections.gated.hold(.didAppend, path: path)
            let appending = Task { try await appender.write(Self.marker) }
            try await gate.waitUntilReached()
            try await overwriteRemote(connections.fork, path, at: 0, with: Self.marker)
            gate.open()
            try await appending.value
            try await appender.close()

            let cached = try await readRemote(connections.connection, path)
            let held = try await readRemote(connections.truth, path)

            #expect(held == overwritten(Self.payload, at: 0, with: Self.marker) + Self.marker)
            #expect(cached == held)
        }
    }

    @Test(
        "a size change and a rename of one file, reported in the other order, do not leave the old bytes at the new path"
    )
    func sizeChangeAndRenameReportedOutOfOrder() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            let renamed = "\(connections.directory)/renamed.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            _ = try await readRemote(connections.connection, path)

            // The server cuts the file short, then renames it. The cache hears of the rename first.
            let gate = connections.gated.hold(.invalidate, path: path)
            let connection = connections.connection
            let truncating = Task { try await connection.truncateFile(at: path, toLength: 100) }
            try await gate.waitUntilReached()
            try await connections.fork.move(from: path, to: renamed)
            gate.open()
            try await truncating.value

            let cached = try await readRemote(connections.connection, renamed)
            let held = try await readRemote(connections.truth, renamed)

            #expect(held == Self.payload.prefix(100))
            #expect(cached == held)
        }
    }

    @Test(
        "a size change under one spelling and a rename of its directory, reported in the other order",
        arguments: matchings
    )
    func sizeChangeAndDirectoryRenameSpelledDifferently(matching: SMB.ReferenceCache.PathMatching) async throws {
        try await withCachedConnections(.init(pathMatching: matching)) { connections in
            let directory = "\(connections.directory)/inner"
            let moved = "\(connections.directory)/moved"
            try await connections.truth.makeDirectory(at: directory)
            try await writeRemote(connections.truth, "\(directory)/file.bin", Self.payload)
            _ = try await readRemote(connections.connection, "\(directory)/file.bin")

            // The server cuts the file short under another spelling of its directory, then renames the directory. The
            // cache hears of the rename first.
            let respelled = "\(connections.directory)/INNER/file.bin"
            let gate = connections.gated.hold(.invalidate, path: respelled)
            let connection = connections.connection
            let truncating = Task { try await connection.truncateFile(at: respelled, toLength: 100) }
            try await gate.waitUntilReached()
            try await connections.fork.move(from: directory, to: moved)
            gate.open()
            try await truncating.value

            let cached = try await readRemote(connections.connection, "\(moved)/file.bin")
            let held = try await readRemote(connections.truth, "\(moved)/file.bin")

            #expect(held == Self.payload.prefix(100))
            #expect(cached == held)
        }
    }

    @Test("a stat of an open file that a size change overlapped is not answered from before the client invalidates it")
    func overlappedStatIsNotAnswered() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 60, includingMissing: false))
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            let handle = try await connections.connection.openFile(at: path, accessMode: .readWrite)

            // The server answers the stat. Before its report reaches the cache, the file is cut to nothing.
            let report = connections.gated.hold(.storeStat, path: path)
            let statting = Task { try await handle.stat() }
            try await report.waitUntilReached()
            try await connections.fork.truncateFile(at: path, toLength: 0)

            // The report arrives, and the connection is about to invalidate what it now knows to be stale.
            let invalidation = connections.gated.hold(.invalidate, path: path)
            report.open()
            try await invalidation.waitUntilReached()
            let answered = try await connections.fork.stat(at: path)
            invalidation.open()
            _ = try await statting.value
            try await handle.close()

            #expect(answered.size == 0)
        }
    }

    @Test(
        "a stat held while another spelling of the path is changed is neither kept nor answered from",
        arguments: matchings
    )
    func statHeldAcrossAChangeByAnotherSpelling(matching: SMB.ReferenceCache.PathMatching) async throws {
        let configuration = SMB.ReferenceCache.Configuration(
            metadata: .answer(for: 60, includingMissing: true),
            pathMatching: matching
        )
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            let respelled = "\(connections.directory)/File.BIN"
            try await writeRemote(connections.truth, path, Self.payload)

            let gate = connections.gated.hold(.storeStat, path: path)
            let connection = connections.connection
            let statting = Task { try await connection.stat(at: path) }
            try await gate.waitUntilReached()
            try await connections.fork.truncateFile(at: respelled, toLength: 10)
            gate.open()
            _ = try await statting.value

            #expect(try await connections.connection.stat(at: path).size == 10)
            #expect(try await connections.connection.stat(at: respelled).size == 10)
            #expect(try await readRemote(connections.connection, path) == Self.payload.prefix(10))
        }
    }

    // MARK: Renames Samba refuses

    @Test("a file still written through its handle after a rename of it failed does not leave the cache behind")
    func writesAfterARefusedRename() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            let writer = try await connections.connection.openFile(at: path, accessMode: .readWrite)

            // Samba refuses to rename an open file: the connection reports the rename as failed, which may have
            // happened, and the file stops reporting.
            await #expect(throws: (any Error).self) {
                try await connections.fork.move(from: path, to: "\(connections.directory)/moved.bin")
            }
            #expect(writer.cachePath == nil)

            let reader = try await connections.connection.openFile(at: path)
            let first = try await reader.read(upTo: Int64(Self.payload.count), atOffset: 0)

            try await writer.write(Self.marker, atOffset: 0)
            try await writer.close()

            let second = try await reader.read(upTo: Int64(Self.payload.count), atOffset: 0)
            try await reader.close()
            let held = try await readRemote(connections.truth, path)

            #expect(first == Self.payload)
            #expect(held == overwritten(Self.payload, at: 0, with: Self.marker))
            #expect(second == held)
        }
    }

    @Test("a file under a directory whose rename failed, written through its handle, does not leave the cache behind")
    func writesAfterARefusedDirectoryRename() async throws {
        try await withCachedConnections { connections in
            let directory = "\(connections.directory)/inner"
            let path = "\(directory)/file.bin"
            try await connections.truth.makeDirectory(at: directory)
            try await writeRemote(connections.truth, path, Self.payload)
            let writer = try await connections.connection.openFile(at: path, accessMode: .readWrite)
            _ = try await writer.read(upTo: Int64(Self.payload.count), atOffset: 0)

            await #expect(throws: (any Error).self) {
                try await connections.connection.move(from: directory, to: "\(connections.directory)/moved")
            }

            _ = try await readRemote(connections.fork, path)
            try await writer.write(Self.marker, atOffset: 5000)
            let throughHandle = try await writer.read(upTo: 8192, atOffset: 4096)
            try await writer.close()

            let cached = try await readRemote(connections.fork, path)
            let held = try await readRemote(connections.truth, path)

            #expect(held == overwritten(Self.payload, at: 5000, with: Self.marker))
            #expect(throughHandle == held[4096 ..< 12288])
            #expect(cached == held)
        }
    }

    // MARK: Spellings

    @Test(
        "files whose names differ only in Unicode normalization are read as the two files they are",
        arguments: matchings
    )
    func normalizationForms(matching: SMB.ReferenceCache.PathMatching) async throws {
        try await withCachedConnections(.init(pathMatching: matching)) { connections in
            let composed = "\(connections.directory)/caf\u{E9}.bin"
            let decomposed = "\(connections.directory)/cafe\u{301}.bin"
            try await writeRemote(connections.truth, composed, Self.payload)
            try await writeRemote(connections.truth, decomposed, Self.other)

            // Samba keeps both: it compares the bytes of names.
            let heldComposed = try await readRemote(connections.truth, composed)
            let heldDecomposed = try await readRemote(connections.truth, decomposed)
            #expect(heldComposed == Self.payload)
            #expect(heldDecomposed == Self.other)

            #expect(try await readRemote(connections.connection, composed) == Self.payload)
            #expect(try await readRemote(connections.connection, decomposed) == Self.other)
            #expect(try await readRemote(connections.connection, composed) == Self.payload)
            #expect(try await connections.connection.stat(at: decomposed).size == UInt64(Self.other.count))

            // A change to one form drops what is cached of the other, which some shares take to be the same file, and
            // leaves the other as it is on this one.
            try await overwriteRemote(connections.fork, decomposed, at: 0, with: Self.marker)
            #expect(try await readRemote(connections.connection, composed) == Self.payload)
            #expect(
                try await readRemote(connections.connection, decomposed)
                    == overwritten(Self.other, at: 0, with: Self.marker)
            )
        }
    }

    @Test(
        "names that differ only in case lead to one file, and a change under one is seen under the other",
        arguments: matchings
    )
    func caseVariants(matching: SMB.ReferenceCache.PathMatching) async throws {
        try await withCachedConnections(.init(pathMatching: matching)) { connections in
            let path = "\(connections.directory)/Photo.jpg"
            let lower = "\(connections.directory)/photo.JPG"
            try await writeRemote(connections.truth, path, Self.payload)

            #expect(try await readRemote(connections.connection, path) == Self.payload)
            #expect(try await readRemote(connections.connection, lower) == Self.payload)

            // Written under one spelling, by the fork, while a handle under the other stays open.
            let reader = try await connections.connection.openFile(at: lower)
            _ = try await reader.read(upTo: 8192, atOffset: 0)
            try await overwriteRemote(connections.fork, path, at: 100, with: Self.marker)
            let throughHandle = try await reader.read(upTo: 8192, atOffset: 0)
            try await reader.close()

            let expected = overwritten(Self.payload, at: 100, with: Self.marker)
            #expect(throughHandle == expected.prefix(8192))
            #expect(try await readRemote(connections.connection, path) == expected)
            #expect(try await readRemote(connections.connection, lower) == expected)

            // A rename that changes only the case of the name.
            let respelled = "\(connections.directory)/PHOTO.jpg"
            try await connections.connection.move(from: path, to: respelled)
            let listed = try await connections.connection.listDirectory(at: connections.directory)
            #expect(listed.map(\.name).contains("PHOTO.jpg"))
            #expect(try await readRemote(connections.connection, respelled) == expected)
            #expect(try await readRemote(connections.connection, path) == expected)

            try await connections.fork.truncateFile(at: lower, toLength: 10)
            #expect(try await readRemote(connections.connection, respelled) == expected.prefix(10))
            #expect(try await readRemote(connections.connection, path) == expected.prefix(10))
        }
    }

    @Test(
        "a rename to the very path it was given, which respells the name the share kept, is not hidden by a listing",
        arguments: matchings
    )
    func renameToTheSamePath(matching: SMB.ReferenceCache.PathMatching) async throws {
        let configuration = SMB.ReferenceCache.Configuration(
            metadata: .answer(for: 60, includingMissing: true),
            pathMatching: matching
        )
        try await withCachedConnections(configuration) { connections in
            try await writeRemote(connections.truth, "\(connections.directory)/Photo.jpg", Self.marker)
            func names(_ connection: SMB.Connection) async throws -> [[Unicode.Scalar]] {
                try await connection.listDirectory(at: connections.directory)
                    .map { Array($0.name.unicodeScalars) }
                    .filter { $0 != ["."] && $0 != [".", "."] }
            }
            #expect(try await names(connections.connection) == [Array("Photo.jpg".unicodeScalars)])

            // Samba keeps the name as created; a rename to the path as given takes the case it is given in.
            let path = "\(connections.directory)/photo.jpg"
            try await connections.connection.move(from: path, to: path)

            let held = try await names(connections.truth)
            #expect(try await names(connections.connection) == held)
            #expect(try await names(connections.fork) == held)
        }
    }
}
