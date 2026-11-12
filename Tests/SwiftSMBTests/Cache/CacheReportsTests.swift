//
// Part of SwiftSMB
// CacheReportsTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite("Cache: reports about open files", .tags(.integration), .serialized)
struct CacheReportsTests {
    static let payload = cachePayload(byteCount: 64 * 1024)

    @Test("every lookup ends its request once, after its store, however the request ends")
    func requestsEndOnce() async throws {
        try await withCacheTestDirectory { connection, directory in
            let file = "\(directory)/file"
            try await makeRemoteFile(connection, path: file, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            connection.attachCache(cache)

            // A stat and a listing missed, then answered, and a listing the server fails.
            let stat = try await connection.stat(at: file)
            _ = try await connection.listDirectory(at: directory)
            await cache.answerStat(.doesNotExist, path: file)
            _ = try await connection.itemExists(at: file)
            await cache.answerListing([], path: directory)
            _ = try await connection.listDirectory(at: directory)
            await #expect(throws: (any Error).self) {
                _ = try await connection.listDirectory(at: "\(directory)/missing")
            }
            await cache.answerStat(.exists(stat), path: file)

            // A full hit, a partial hit, a miss, a read at the end of the file, a stat, and a failed read.
            await cache.answerBlock(Self.payload.prefix(10), path: file, offset: 0)
            let handle = try await connection.openFile(at: file)
            _ = try await handle.read(upTo: 5)
            try await handle.seek(offset: 0, from: .start)
            _ = try await handle.read(upTo: 50)
            _ = try await handle.read(upTo: 10)
            try await handle.seek(offset: 100, from: .start)
            let atEnd = try await handle.read(upTo: 10)
            _ = try await handle.stat()
            let cancelled = Task {
                while !Task.isCancelled {
                    await Task.yield()
                }
                return try await handle.read(upTo: 10, atOffset: 50)
            }
            cancelled.cancel()
            _ = await Result { try await cancelled.value }
            try await handle.close()

            #expect(atEnd.isEmpty)
            #expect(await cache.requestContractViolations() == [])
            #expect(await cache.requestCalls.count > 20)
        }
    }

    @Test("a failed read leaves the file offset where it was")
    func failedReadRestoresOffset() async throws {
        try await withCacheTestDirectory { connection, directory in
            let file = "\(directory)/file"
            try await makeRemoteFile(connection, path: file, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            await cache.answerBlock(Self.payload.prefix(10), path: file, offset: 20)
            connection.attachCache(cache)

            let handle = try await connection.openFile(at: file)
            try await handle.seek(offset: 20, from: .start)
            let read = Task {
                while !Task.isCancelled {
                    await Task.yield()
                }
                return try await handle.read(upTo: 50)
            }
            read.cancel()
            let result = await Result { try await read.value }
            let offset = try await handle.seek(offset: 0, from: .current)
            try await handle.close()

            #expect(result.error is CancellationError)
            #expect(offset == 20)
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a file renamed while open, by its connection or a fork, reports under its new path, or stops reporting")
    func renameWhileOpen() async throws {
        try await withCacheTestDirectory { connection, directory in
            let first = "\(directory)/a"
            let second = "\(directory)/b"
            let cache = RecordingCache()
            connection.attachCache(cache)
            let fork = try await connection.fork()

            let handle = try await connection.openFile(at: first, accessMode: .readWrite, options: [.create])
            try await handle.write(Self.payload.prefix(100))
            await cache.reset()
            let renamed = await Result { try await fork.move(from: first, to: second) }
            try await handle.write(Self.payload[100 ..< 200])
            _ = try await handle.stat()
            try await handle.close()
            try await fork.disconnect()

            let events = await cache.events
            if renamed.succeeded {
                #expect(events == [
                    .didRename(from: first, to: second),
                    .storeBlock(path: second, offset: 100, data: Self.payload[100 ..< 200], source: .upload),
                    .storeStat(path: second, size: 200),
                    .storeStat(path: second, size: 200),
                ])
            }
            else {
                // Servers refuse to rename a file opened without delete sharing. The rename may still have happened, so
                // both paths are invalidated, and the file stops reporting: its write invalidates every path it may be
                // at.
                #expect(events == [
                    .invalidate(path: first),
                    .invalidate(path: second),
                    .invalidate(path: first),
                    .invalidate(path: second),
                ])
            }
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a file under a directory renamed while it is open reports under the new directory, or stops reporting")
    func directoryRenameWhileOpen() async throws {
        try await withCacheTestDirectory { connection, directory in
            let folder = "\(directory)/folder"
            let renamedFolder = "\(directory)/renamed"
            try await connection.makeDirectory(at: folder)
            let cache = RecordingCache()
            connection.attachCache(cache)

            let handle = try await connection.openFile(
                at: "\(folder)/file",
                accessMode: .writeOnly,
                options: [.create]
            )
            await cache.reset()
            let renamed = await Result { try await connection.move(from: folder, to: renamedFolder) }
            try await handle.write(Self.payload.prefix(10))
            try await handle.close()

            let events = await cache.events
            if renamed.succeeded {
                #expect(events == [
                    .didRename(from: folder, to: renamedFolder),
                    .storeBlock(
                        path: "\(renamedFolder)/file",
                        offset: 0,
                        data: Self.payload.prefix(10),
                        source: .upload
                    ),
                    .storeStat(path: "\(renamedFolder)/file", size: 10),
                ])
            }
            else {
                #expect(events == [
                    .invalidate(path: folder),
                    .invalidate(path: renamedFolder),
                    .invalidate(path: "\(folder)/file"),
                    .invalidate(path: "\(renamedFolder)/file"),
                ])
            }
        }
    }

    @Test("a file deleted while open, or whose delete failed, stops reporting to the cache")
    func deleteWhileOpen() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            let cache = RecordingCache()
            connection.attachCache(cache)
            let fork = try await connection.fork()

            let handle = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.create])
            try await handle.write(Self.payload.prefix(10))
            let deleted = await Result { try await fork.removeFile(at: path) }
            try await handle.write(Self.payload[10 ..< 20])
            try await handle.truncate(toLength: 5)
            // Servers refuse to stat a handle opened only for writing; either way, the cache hears nothing of it.
            _ = try? await handle.stat()
            try await handle.close()
            try await fork.disconnect()

            // Opening with `.create` invalidates the file, then its first write is kept.
            let events = await cache.events
            let prefix: [RecordingCache.Event] = [
                .invalidate(path: path),
                .storeBlock(path: path, offset: 0, data: Self.payload.prefix(10), source: .upload),
                .invalidate(path: path),
            ]
            if deleted.succeeded {
                // The delete through the fork is the last the cache hears of the file.
                #expect(events == prefix)
            }
            else {
                // The file may still be at its path: changes through it invalidate the path, nothing else.
                #expect(events == prefix + [.invalidate(path: path), .invalidate(path: path)])
            }
        }
    }

    @Test("a store about an open file that a change at its path overlapped is followed by an invalidation")
    func changeOverlappingOpenFileReport() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            connection.attachCache(cache)
            let fork = try await connection.fork()
            let handle = try await connection.openFile(at: path, accessMode: .readWrite)

            // A stat of the open file, still on its way to the cache while a fork changes the file's timestamps.
            await cache.reset()
            await cache.holdNextStore()
            let stat = Task { try await handle.stat() }
            await cache.waitForHeldStore()
            try await fork.changeDate(at: path, write: Date(timeIntervalSince1970: 1_000_000))
            await cache.releaseHeldStore()
            _ = try await stat.value
            let afterStat = await cache.events

            // A write, still on its way to the cache while the connection truncates the file.
            await cache.reset()
            await cache.holdNextStore()
            let write = Task { try await handle.write(Self.payload.prefix(50)) }
            await cache.waitForHeldStore()
            try await connection.truncateFile(at: path, toLength: 0)
            await cache.releaseHeldStore()
            _ = try await write.value
            let afterWrite = await cache.events

            // Without an overlapping change, the stat stands: the truncation came after the write.
            await cache.reset()
            _ = try await handle.stat()
            let quiet = await cache.events

            try await handle.close()
            try await fork.disconnect()

            #expect(afterStat == [
                .invalidate(path: path),
                .storeStat(path: path, size: 100),
                .invalidate(path: path),
            ])
            #expect(afterWrite == [
                .invalidate(path: path),
                .storeBlock(path: path, offset: 0, data: Self.payload.prefix(50), source: .upload),
                .invalidate(path: path),
            ])
            #expect(quiet == [.storeStat(path: path, size: 0)])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a read whose file was renamed while the cache answered drops the answer and invalidates both paths")
    func readOverlappingRename() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            let moved = "\(directory)/moved"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            let cache = RecordingCache()
            connection.attachCache(cache)
            let handle = try await connection.openFile(at: path)

            // The download is held on its way to the cache while the file's directory entry moves elsewhere. Samba
            // refuses to rename the open file, so the rename's report is an invalidation of both paths either way.
            await cache.reset()
            await cache.holdNextStore()
            let read = Task { try await handle.read(upTo: 10) }
            await cache.waitForHeldStore()
            _ = await Result { try await connection.move(from: path, to: moved) }
            await cache.releaseHeldStore()
            let data = try await read.value
            let events = await cache.events
            try await handle.close()

            #expect(data == Self.payload.prefix(10))
            // Whatever the rename did, the read's bytes may have reached the old path late: it is invalidated after.
            let afterStore = eventsAfter({
                if case .storeBlock = $0 {
                    true
                }
                else {
                    false
                }
            }, in: events)
            #expect(afterStore.contains(.invalidate(path: path)))
            #expect(afterStore.contains(.invalidate(path: moved)))
        }
    }

    @Test("closing a written file after its connection disconnected invalidates it, since the final stat is skipped")
    func closeAfterDisconnect() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            let writer = try await connection.fork()
            let cache = RecordingCache()
            writer.attachCache(cache)

            let handle = try await writer.openFile(at: path, accessMode: .writeOnly, options: [.create])
            try await handle.write(Self.payload.prefix(100))
            try await writer.disconnect()
            #expect(!writer.hasCacheAttached())
            await cache.reset()
            let closed = await Result { try await handle.close() }

            #expect(!closed.succeeded)
            #expect(!handle.isOpen)
            #expect(await cache.events == [.invalidate(path: path)])
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a cancelled close still hands the cache the file's final metadata")
    func cancelledClose() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            let cache = RecordingCache()
            connection.attachCache(cache)

            let handle = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.create])
            try await handle.write(Self.payload.prefix(1000))

            let close = Task {
                while !Task.isCancelled {
                    await Task.yield()
                }
                try await handle.close()
            }
            close.cancel()
            try await close.value

            #expect(!handle.isOpen)
            #expect(await cache.events.last == .storeStat(path: path, size: 1000))
            #expect(await cache.requestContractViolations() == [])
        }
    }

    @Test("a file opened under an attachment no longer attached keeps reporting, but renames no longer reach it")
    func detachedAttachment() async throws {
        try await withCacheTestDirectory { connection, directory in
            let path = "\(directory)/file"
            let other = "\(directory)/other"
            try await makeRemoteFile(connection, path: path, contents: Self.payload.prefix(100))
            try await makeRemoteFile(connection, path: other, contents: Self.payload.prefix(10))
            let cache = RecordingCache()
            connection.attachCache(cache)

            let handle = try await connection.openFile(at: path, accessMode: .readWrite)
            connection.detachCache()
            await cache.reset()
            try await connection.removeFile(at: other)
            try await handle.write(Self.payload.prefix(10), atOffset: 0)
            try await handle.close()

            #expect(await cache.events == [
                .storeBlock(path: path, offset: 0, data: Self.payload.prefix(10), source: .upload),
                .storeStat(path: path, size: 100),
            ])
        }
    }
}
