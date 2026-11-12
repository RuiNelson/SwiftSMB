//
// Part of SwiftSMB
// StalledConnection+Cache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

/// A connection held behind a blocking byte-range lock that another connection holds: the lock waits on the server and
/// holds the connection's queue, so every server call of the connection waits behind it, while its cache calls, and
/// everything its fork does, go on.
private struct Stall {
    let ownerFile: SMB.File
    let stalledFile: SMB.File
    let locking: Task<Void, any Error>

    /// Stalls `connection` behind a lock on a file of its own in `directory`, held by `owner`.
    static func begin(_ connection: SMB.Connection, owner: SMB.Connection, directory: String) async throws -> Stall {
        let path = "\(directory)/lock-\(UUID().uuidString.prefix(8))"
        try await writeRemote(owner, path, Data("lock".utf8))
        let ownerFile = try await owner.openFile(at: path, accessMode: .readWrite)
        try await ownerFile.lock(.exclusive, nonBlocking: true)

        let stalledFile = try await connection.openFile(at: path, accessMode: .readWrite)
        let locking = Task { try await stalledFile.lock(.exclusive, nonBlocking: false) }
        // Long enough for the request to reach the server and wait there, holding the connection's queue.
        try await Task.sleep(for: .milliseconds(500))
        return Stall(ownerFile: ownerFile, stalledFile: stalledFile, locking: locking)
    }

    /// Releases the owner's lock, so the stalled lock is granted and the connection goes on.
    func release() async throws {
        try await ownerFile.unlock()
        try await locking.value
        try await stalledFile.unlock()
        try await stalledFile.close()
        try await ownerFile.close()
    }
}

/// Cache reports of operations on a connection stalled behind a blocking byte-range lock, while its fork, which shares
/// its cache, goes on: what the stalled calls hand the cache arrives after the fork's, though the stalled calls began
/// first.
@Suite("Cache: a connection stalled behind a blocking lock", .tags(.integration), .serialized)
struct StalledConnectionCacheTests {
    static let payload = cachePayload(byteCount: 64 * 1024)
    static let marker = Data(repeating: 0xEE, count: 1000)

    @Test(
        "a read whose lookup came before a fork's write, and whose server call came after, keeps what the server held"
    )
    func readStalledAcrossAWrite() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            let reader = try await connections.connection.openFile(at: path)

            let stall = try await Stall.begin(
                connections.connection,
                owner: connections.truth,
                directory: connections.directory
            )
            let looked = connections.gated.hold(.retrieveBlock, path: path, after: true)
            let reading = Task { try await reader.read(upTo: 8192, atOffset: 0) }
            try await looked.waitUntilReached()
            looked.open()
            try await Task.sleep(for: .milliseconds(200))

            try await overwriteRemote(connections.fork, path, at: 1000, with: Self.marker)
            try await stall.release()
            let read = try await reading.value
            try await reader.close()

            let expected = overwritten(Self.payload, at: 1000, with: Self.marker)
            #expect(read == expected.prefix(8192))
            #expect(try await readRemote(connections.connection, path) == expected)
            #expect(try await readRemote(connections.fork, path) == expected)
        }
    }

    @Test(
        "a write that reaches the server after the fork cached the bytes it overwrites leaves the cache with the write"
    )
    func writeStalledWhileTheForkReads() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            let writer = try await connections.connection.openFile(at: path, accessMode: .readWrite)

            let stall = try await Stall.begin(
                connections.connection,
                owner: connections.truth,
                directory: connections.directory
            )
            let writing = Task { try await writer.write(Self.marker, atOffset: 2000) }
            try await Task.sleep(for: .milliseconds(200))

            #expect(try await readRemote(connections.fork, path) == Self.payload)
            try await stall.release()
            try await writing.value
            try await writer.close()

            let expected = overwritten(Self.payload, at: 2000, with: Self.marker)
            #expect(try await readRemote(connections.truth, path) == expected)
            #expect(try await readRemote(connections.fork, path) == expected)
            #expect(try await readRemote(connections.connection, path) == expected)
        }
    }

    @Test(
        "a rename that reaches the server after the fork opened the file is refused, and the fork's handle stops reporting"
    )
    func renameStalledWhileTheForkOpens() async throws {
        try await withCachedConnections { connections in
            let path = "\(connections.directory)/file.bin"
            let moved = "\(connections.directory)/moved.bin"
            try await writeRemote(connections.truth, path, Self.payload)

            let stall = try await Stall.begin(
                connections.connection,
                owner: connections.truth,
                directory: connections.directory
            )
            let connection = connections.connection
            let renaming = Task { try await connection.move(from: path, to: moved) }
            try await Task.sleep(for: .milliseconds(200))

            let handle = try await connections.fork.openFile(at: path, accessMode: .readWrite)
            #expect(try await handle.read(upTo: 8192, atOffset: 0) == Self.payload.prefix(8192))
            #expect(handle.cachePath == path)

            try await stall.release()
            await #expect(throws: (any Error).self) { try await renaming.value }
            #expect(handle.cachePath == nil)

            // Written through the silenced handle: the cache drops the path instead of keeping the bytes there.
            try await handle.write(Self.marker, atOffset: 0)
            let throughHandle = try await handle.read(upTo: 8192, atOffset: 0)
            try await handle.close()

            let expected = overwritten(Self.payload, at: 0, with: Self.marker)
            #expect(throughHandle == expected.prefix(8192))
            #expect(try await readRemote(connections.connection, path) == expected)
            #expect(try await readRemote(connections.truth, path) == expected)
        }
    }

    @Test("a close waiting behind a lock that the command timeout withdraws still reports the file's final metadata")
    func closeBehindATimedOutLock() async throws {
        try await withCacheTestDirectory { connection, directory in
            let owner = try await connection.fork()
            let path = "\(directory)/file"
            let cache = RecordingCache()
            connection.attachCache(cache)
            try await connection.setTimeout(1)

            let handle = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.create])
            try await handle.write(Self.payload.prefix(1000))

            let stall = try await Stall.begin(connection, owner: owner, directory: directory)
            await cache.reset()
            let closing = Task { try await handle.close() }

            // The command timeout withdraws the lock, and the close goes on.
            do {
                try await stall.locking.value
                Issue.record("Expected the blocking lock to time out")
            }
            catch let SMB.Error.ntStatus(status, _, _, _) {
                #expect(status == .ioTimeout)
            }
            try await closing.value
            try await stall.stalledFile.close()
            try await stall.ownerFile.close()
            try? await owner.disconnect()

            #expect(!handle.isOpen)
            #expect(await cache.events.contains(.storeStat(path: path, size: 1000)))
            #expect(await cache.requestContractViolations() == [])
        }
    }
}
