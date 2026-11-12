//
// Part of SwiftSMB
// BlockLevelCacheTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite("Cache: reads, writes, and metadata", .tags(.integration), .serialized)
struct BlockLevelCacheTests {
    static let payload = cachePayload(byteCount: 64 * 1024)

    @Test("opening a file for reading stats it for the cache; a write-only file is not stat'ed")
    func openStat() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            connection.attachCache(cache)

            let reader = try await connection.openFile(at: path)
            try await reader.close()
            let readWrite = try await connection.openFile(at: path, accessMode: .readWrite)
            try await readWrite.close()
            let writer = try await connection.openFile(at: path, accessMode: .writeOnly)
            try await writer.close()

            #expect(await cache.events == [
                .storeStat(path: path, size: 100),
                .storeStat(path: path, size: 100),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a miss reads from the server and hands the bytes to the cache")
    func miss() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload)
            let cache = RecordingCache()
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path)
            let data = try await file.read(upTo: 1000)
            let offset = try await file.seek(offset: 0, from: .current)
            try await file.close()

            #expect(data == Self.payload.prefix(1000))
            #expect(offset == 1000)
            #expect(await cache.events.filter(\.isBlockEvent) == [
                .retrieveBlock(path: path, offset: 0, upTo: 1000),
                .storeBlock(path: path, offset: 0, data: Self.payload.prefix(1000), source: .download),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a full hit is served from the cache, cut to the size asked for, and the next read continues after it")
    func fullHit() async throws {
        let cached = Data(repeating: 0xAB, count: 32)

        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload)
            let cache = RecordingCache()
            await cache.answerBlock(cached, path: path, offset: 0)
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path)
            let first = try await file.read(upTo: 16)
            let offsetAfterHit = try await file.seek(offset: 0, from: .current)
            let second = try await file.read(upTo: 16)
            try await file.close()

            #expect(first == cached.prefix(16))
            #expect(offsetAfterHit == 16)
            #expect(second == Self.payload[16 ..< 32])
            #expect(await cache.events.filter(\.isBlockEvent) == [
                .retrieveBlock(path: path, offset: 0, upTo: 16),
                .retrieveBlock(path: path, offset: 16, upTo: 16),
                .storeBlock(path: path, offset: 16, data: Self.payload[16 ..< 32], source: .download),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a partial hit reads the rest from the server and hands only those bytes to the cache")
    func partialHit() async throws {
        let cached = Data(repeating: 0xAB, count: 10)

        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload)
            let cache = RecordingCache()
            await cache.answerBlock(cached, path: path, offset: 0)
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path)
            let data = try await file.read(upTo: 100, transferChunkSize: 32)
            let offsetAfterRead = try await file.seek(offset: 0, from: .current)
            try await file.close()

            #expect(data == cached + Self.payload[10 ..< 100])
            #expect(offsetAfterRead == 100)
            #expect(await cache.events.filter(\.isBlockEvent) == [
                .retrieveBlock(path: path, offset: 0, upTo: 100),
                .storeBlock(path: path, offset: 10, data: Self.payload[10 ..< 100], source: .download),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("reading to the end of the file asks the cache once and reads the rest in chunks")
    func readToEnd() async throws {
        let cached = Data(repeating: 0xCD, count: 100)

        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(5000))
            let cache = RecordingCache()
            await cache.answerBlock(cached, path: path, offset: 0)
            connection.attachCache(cache)

            let data = try await connection.loadFile(at: path, chunkSize: 1024)

            #expect(data == cached + Self.payload[100 ..< 5000])
            #expect(await cache.events.filter(\.isBlockEvent) == [
                .retrieveBlock(path: path, offset: 0, upTo: .max),
                .storeBlock(path: path, offset: 100, data: Self.payload[100 ..< 5000], source: .download),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("positional reads ask the cache at their offset and leave the file offset alone")
    func positionalReads() async throws {
        let cached = Data(repeating: 0xEF, count: 20)

        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(1000))
            let cache = RecordingCache()
            await cache.answerBlock(cached, path: path, offset: 500)
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path)
            try await file.seek(offset: 7, from: .start)
            let miss = try await file.read(upTo: 50, atOffset: 100)
            let hit = try await file.read(upTo: 50, atOffset: 500)
            let atEnd = try await file.read(upTo: 50, atOffset: 1000)
            let offset = try await file.seek(offset: 0, from: .current)
            try await file.close()

            #expect(miss == Self.payload[100 ..< 150])
            #expect(hit == cached + Self.payload[520 ..< 550])
            #expect(atEnd.isEmpty)
            #expect(offset == 7)
            #expect(await cache.events.filter(\.isBlockEvent) == [
                .retrieveBlock(path: path, offset: 100, upTo: 50),
                .storeBlock(path: path, offset: 100, data: Self.payload[100 ..< 150], source: .download),
                .retrieveBlock(path: path, offset: 500, upTo: 50),
                .storeBlock(path: path, offset: 520, data: Self.payload[520 ..< 550], source: .download),
                .retrieveBlock(path: path, offset: 1000, upTo: 50),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a file not opened for reading never reads from the cache")
    func writeOnlySkipsCache() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            await cache.answerBlock(Self.payload.prefix(100), path: path, offset: 0)
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path, accessMode: .writeOnly)
            await #expect(throws: (any Error).self) {
                _ = try await file.read(upTo: 10)
            }
            await #expect(throws: (any Error).self) {
                _ = try await file.read(upTo: 10, atOffset: 0)
            }
            try await file.close()

            #expect(await cache.events.filter(\.isBlockEvent).isEmpty)
        }
    }

    @Test("acknowledged writes go to the cache, and closing reports the file's final metadata")
    func writes() async throws {
        let first = Self.payload.prefix(1000)
        let second = Self.payload[1000 ..< 3000]
        let positional = Self.payload[3000 ..< 3100]

        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            let cache = RecordingCache()
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.create, .truncate])
            try await file.write(first)
            try await file.write(second, transferChunkSize: 700)
            try await file.write(positional, atOffset: 5000)
            try await file.close()

            let events = await cache.events
            #expect(events.filter(\.isBlockEvent) == [
                .storeBlock(path: path, offset: 0, data: first, source: .upload),
                .storeBlock(path: path, offset: 1000, data: second, source: .upload),
                .storeBlock(path: path, offset: 5000, data: positional, source: .upload),
            ])
            #expect(events.filter(\.isChange) == [.invalidate(path: path)])
            #expect(events.last == .storeStat(path: path, size: 5100))
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("writes to a file opened for appending report how much they appended; positional writes their bytes")
    func append() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.append])
            try await file.write(Data(repeating: 1, count: 50))
            try await file.write(Data(repeating: 2, count: 5), atOffset: 0)
            try await file.close()

            let events = await cache.events
            #expect(events.filter(\.isBlockEvent) == [
                .storeBlock(path: path, offset: 0, data: Data(repeating: 2, count: 5), source: .upload),
            ])
            #expect(events.filter(\.isChange) == [.didAppend(path: path, byteCount: 50)])
            #expect(events.last == .storeStat(path: path, size: 150))
        }
    }

    @Test("a write that fails after its bytes reached the server invalidates the file")
    func failedWrite() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            connection.attachCache(cache)

            let file = try await connection.openFile(at: path, accessMode: .readWrite)
            await cache.reset()
            // A cancelled task stops before its first chunk: nothing reached the server, so nothing is reported.
            let cancelled = Task {
                while !Task.isCancelled {
                    await Task.yield()
                }
                return try await file.write(Self.payload.prefix(10))
            }
            cancelled.cancel()
            await #expect(throws: CancellationError.self) {
                _ = try await cancelled.value
            }
            let afterCancel = await cache.events

            // A write the server refuses, past the largest offset it takes: the refused chunk may have reached the file
            // as far as the connection knows, so the file is invalidated.
            await cache.reset()
            let refused = await Result {
                try await file.write(Self.payload.prefix(20), atOffset: UInt64(Int64.max) - 10, transferChunkSize: 10)
            }
            let afterRefusal = await cache.events
            try await file.close()

            #expect(afterCancel.isEmpty)
            if case .success = refused {
                Issue.record("a write past the largest offset succeeded")
            }
            #expect(afterRefusal == [.invalidate(path: path)])
        }
    }

    @Test("stats and listings come from the cache when it answers, and from the server otherwise")
    func metadata() async throws {
        try await withCacheTestDirectory { connection, directory in
            let file = "\(directory)/file"
            let missing = "\(directory)/missing"
            try await makeRemoteFile(connection, path: file, contents: Self.payload.prefix(10))
            let otherStat = try await connection.stat(at: TestContent.helloPath)
            let otherListing = try await connection.listDirectory(at: TestContent.testdirPath)
            let cache = RecordingCache()
            connection.attachCache(cache)

            let stat = try await connection.stat(at: file)
            let listing = try await connection.listDirectory(at: directory)
            let missingError = await Result { try await connection.stat(at: missing) }

            await cache.answerStat(.doesNotExist, path: file)
            let cachedMissing = await Result { try await connection.stat(at: file) }
            let existence = try await connection.itemExists(at: file)

            await cache.answerStat(.exists(otherStat), path: file)
            let cachedStat = try await connection.stat(at: file)

            await cache.answerListing(otherListing, path: directory)
            let cachedListing = try await connection.listDirectory(at: directory)

            #expect(stat.size == 10)
            #expect(listing.map(\.name).contains("file"))
            #expect((missingError.error as? SMB.Error)?.posixCode == ENOENT)
            #expect((cachedMissing.error as? SMB.Error)?.posixCode == ENOENT)
            #expect(existence == .false)
            #expect(cachedStat == otherStat)
            #expect(cachedListing == otherListing)
            #expect(await cache.events == [
                .retrieveStat(path: file),
                .storeStat(path: file, size: 10),
                .retrieveDirectoryListing(path: directory),
                .storeDirectoryListing(path: directory, names: Set(listing.map(\.name))),
                .retrieveStat(path: missing),
                .storeStat(path: missing, size: nil),
                .retrieveStat(path: file),
                .retrieveStat(path: file),
                .retrieveStat(path: file),
                .retrieveDirectoryListing(path: directory),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("changes made through the connection are reported, also when their calls fail")
    func changes() async throws {
        try await withCacheTestDirectory { connection, directory in
            let subdirectory = "\(directory)/sub"
            let file = "\(directory)/file"
            let renamed = "\(directory)/renamed"
            let copy = "\(directory)/copy"
            let link = "\(directory)/link"
            let hardLink = "\(directory)/hard"
            let missing = "\(directory)/missing"
            let cache = RecordingCache()
            connection.attachCache(cache)

            try await connection.makeDirectory(at: subdirectory)
            let created = try await connection.openFile(at: file, accessMode: .writeOnly, options: [.create])
            try await created.close()
            try await connection.truncateFile(at: file, toLength: 0)
            try await connection.changeDate(at: file, write: Date(timeIntervalSince1970: 1_000_000))
            try await connection.changeAttributes(at: file) { $0.union(.archive) }
            _ = try? await connection.setSecurityDescriptor(SMB.SecurityDescriptor(), at: file)
            try await connection.copyFile(from: file, to: copy)
            try await connection.move(from: file, to: renamed)
            try await connection.makeLink(at: link, pointingTo: "renamed", isDirectory: false)
            _ = try? await connection.makeHardLink(at: hardLink, pointingTo: renamed)
            try? await connection.removeFile(at: hardLink)
            try await connection.removeFile(at: link)
            try await connection.removeFile(at: renamed)
            try await connection.removeFile(at: copy)
            await #expect(throws: SMB.Error.self) {
                try await connection.removeFile(at: missing)
            }
            await #expect(throws: SMB.Error.self) {
                try await connection.move(from: missing, to: file)
            }
            try await connection.removeItem(at: subdirectory)

            #expect(await cache.events.filter(\.isChange) == [
                .invalidate(path: subdirectory),
                .invalidate(path: file),
                .invalidate(path: file),
                .invalidate(path: file),
                .invalidate(path: file),
                .invalidate(path: file),
                .invalidate(path: copy),
                .didRename(from: file, to: renamed),
                .invalidate(path: link),
                .invalidate(path: hardLink),
                .invalidate(path: renamed),
                .invalidate(path: hardLink),
                .invalidate(path: link),
                .invalidate(path: renamed),
                .invalidate(path: copy),
                .invalidate(path: missing),
                .invalidate(path: missing),
                .invalidate(path: file),
                .invalidate(path: subdirectory),
            ])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("open files keep their cache, forks made after attaching inherit it, and disconnecting detaches it")
    func lifecycle() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let control = try await connection.fork()
            let cache = RecordingCache()
            connection.attachCache(cache)
            let fork = try await connection.fork()

            let kept = try await connection.openFile(at: path)
            connection.detachCache()
            let uncached = try await connection.openFile(at: path)
            await cache.reset()

            _ = try await kept.read(upTo: 10)
            _ = try await uncached.read(upTo: 10)
            _ = try await control.stat(at: path)
            let eventsAfterDetach = await cache.events

            await cache.reset()
            _ = try await fork.stat(at: path)
            let forkEvents = await cache.events
            let forkHadCache = fork.hasCacheAttached()
            try await fork.disconnect()

            try await kept.close()
            try await uncached.close()
            try await control.disconnect()

            #expect(eventsAfterDetach == [
                .retrieveBlock(path: path, offset: 0, upTo: 10),
                .storeBlock(path: path, offset: 0, data: Self.payload.prefix(10), source: .download),
            ])
            #expect(forkEvents == [
                .retrieveStat(path: path),
                .storeStat(path: path, size: 100),
            ])
            #expect(forkHadCache)
            #expect(!fork.hasCacheAttached())
            #expect(!control.hasCacheAttached())
        }
    }

    @Test("transfers read and write through the cache")
    func transfers() async throws {
        try await withCacheTestDirectory { connection, directory in
            let remote = "\(directory)/uploaded"
            let content = Self.payload.prefix(3000)
            let local = FileManager.default.temporaryDirectory.appendingPathComponent(uniquePath("cache-upload"))
            let downloaded = FileManager.default.temporaryDirectory.appendingPathComponent(uniquePath("cache-down"))
            try content.write(to: local)
            defer {
                try? FileManager.default.removeItem(at: local)
                try? FileManager.default.removeItem(at: downloaded)
            }
            let cache = RecordingCache()
            connection.attachCache(cache)

            try await connection.uploadFile(local: local, remote: remote, maxBlockSize: 1000) { _, _, _, _ in true }
            let uploadEvents = await cache.events

            // The download is served from what the cache answers, so its bytes are told apart from the server's.
            let fake = Data(repeating: 0x5A, count: content.count)
            await cache.answerBlock(fake, path: remote, offset: 0)
            await cache.reset()
            try await connection.downloadFile(remote: remote, local: downloaded, maxBlockSize: 8192) { _, _, _, _ in
                true
            }
            let downloadEvents = await cache.events

            #expect(try Data(contentsOf: downloaded) == fake)
            #expect(try await connection.loadFile(at: remote).count == content.count)

            // The atomic upload writes a temporary file, then renames it to the destination.
            let renames = uploadEvents.compactMap { event -> (String, String)? in
                guard case let .didRename(from, to) = event else { return nil }
                return (from, to)
            }
            let temporary = try #require(renames.last?.0)
            #expect(renames.last?.1 == remote)
            #expect(uploadEvents.contains(.storeBlock(
                path: temporary,
                offset: 0,
                data: content.prefix(1000),
                source: .upload
            )))
            #expect(uploadEvents.contains(.storeStat(path: temporary, size: UInt64(content.count))))
            #expect(downloadEvents.contains(.retrieveBlock(path: remote, offset: 0, upTo: content.count)))
            #expect(!downloadEvents.contains {
                if case .storeBlock = $0 {
                    true
                }
                else {
                    false
                }
            })
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("compareFiles reads through the cache")
    func compare() async throws {
        try await withCacheTestDirectory { connection, directory in
            let first = "\(directory)/a"
            let second = "\(directory)/b"
            try await makeRemoteFile(connection, path: first, contents: Self.payload.prefix(1000))
            try await makeRemoteFile(connection, path: second, contents: Self.payload.prefix(1000))
            let identicalOnServer = try await connection.compareFiles(first, second)

            let cache = RecordingCache()
            await cache.answerBlock(Data(repeating: 0, count: 1000), path: second, offset: 0)
            connection.attachCache(cache)
            let identicalThroughCache = try await connection.compareFiles(first, second)

            #expect(identicalOnServer)
            #expect(!identicalThroughCache)
            #expect(await cache.events.contains { $0.isBlockEvent && $0.paths == [second] })
        }
    }
}

extension Result {
    /// The error, or `nil` on success.
    var error: Failure? {
        if case let .failure(error) = self {
            return error
        }
        return nil
    }
}
