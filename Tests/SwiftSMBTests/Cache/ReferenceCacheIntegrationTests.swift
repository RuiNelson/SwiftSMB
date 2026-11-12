//
// Part of SwiftSMB
// ReferenceCacheIntegrationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

/// The checks ``SMB/ReferenceCache`` makes through its control connection, against the test server.
///
/// The cache is fed directly, the way a connection reports to it, so that these tests depend on nothing but the cache
/// and the server.
@Suite(.tags(.integration))
struct ReferenceCacheIntegrationTests {
    /// 40 000 bytes: three blocks of the 16 KiB sampling grid, of 13 334, 13 333, and 13 333 bytes.
    private static let payload = Data((0 ..< 40000).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ ($0 >> 9)) })

    @Test("statOnServer drops the bytes of a file another connection rewrote, keeping its size")
    func statOnServerNoticesARewrite() async throws {
        try await withReferenceCacheDirectory { connection, directory in
            let path = "\(directory)/file.bin"
            try await connection.dumpToFile(Self.payload, to: path)

            let control = try await connection.fork()
            let cache = SMB.ReferenceCache(
                controlConnection: control,
                configuration: .init(trustPolicy: .statOnServer, revalidationInterval: 0)
            )
            try await feed(cache, from: connection, path: path)

            // Checked and unchanged: the bytes are handed back.
            #expect(await retrieve(cache, path: path) == Self.payload)

            // Another connection writes other bytes over the file.
            let writer = try await connection.fork()
            var changed = Self.payload
            changed[20000] ^= 0xFF
            try await writer.dumpToFile(changed, to: path, options: [])
            try await writer.disconnect()

            #expect(await retrieve(cache, path: path) == nil)
            #expect(await cache.cachedRanges(path: path) == [])

            await cache.close()
            try await control.disconnect()
        }
    }

    @Test("statOnServer drops the bytes of a file another connection deleted")
    func statOnServerNoticesADelete() async throws {
        try await withReferenceCacheDirectory { connection, directory in
            let path = "\(directory)/file.bin"
            try await connection.dumpToFile(Self.payload, to: path)

            let control = try await connection.fork()
            let cache = SMB.ReferenceCache(
                controlConnection: control,
                configuration: .init(trustPolicy: .statOnServer, revalidationInterval: 0)
            )
            try await feed(cache, from: connection, path: path)
            #expect(await retrieve(cache, path: path) == Self.payload)

            try await connection.removeItem(at: path)
            #expect(await retrieve(cache, path: path) == nil)

            await cache.close()
            try await control.disconnect()
        }
    }

    @Test("sampleBlocks drops the bytes of a file another connection rewrote")
    func sampleBlocksNoticesARewrite() async throws {
        try await withReferenceCacheDirectory { connection, directory in
            let path = "\(directory)/file.bin"
            try await connection.dumpToFile(Self.payload, to: path)

            let control = try await connection.fork()
            let cache = SMB.ReferenceCache(
                controlConnection: control,
                configuration: .init(trustPolicy: .sampleBlocks(count: 3), revalidationInterval: 0)
            )
            try await feed(cache, from: connection, path: path)
            #expect(await retrieve(cache, path: path) == Self.payload)

            let writer = try await connection.fork()
            var changed = Self.payload
            changed[100] ^= 0xFF
            try await writer.dumpToFile(changed, to: path, options: [])
            try await writer.disconnect()

            #expect(await retrieve(cache, path: path) == nil)

            await cache.close()
            try await control.disconnect()
        }
    }

    @Test("sampleBlocks compares the cached blocks with the server's, picking up where the last check stopped")
    func sampleBlocksComparesBytes() async throws {
        try await withReferenceCacheDirectory { connection, directory in
            let path = "\(directory)/file.bin"
            try await connection.dumpToFile(Self.payload, to: path)

            let control = try await connection.fork()
            let cache = SMB.ReferenceCache(
                controlConnection: control,
                configuration: .init(trustPolicy: .sampleBlocks(count: 1), revalidationInterval: 0)
            )

            // The cache holds bytes that differ from the server's in the middle block only, of a version the server
            // still has: only comparing that block tells them apart. Bisection compares the first block, then the last,
            // then the middle one.
            var wrong = Self.payload
            wrong[20000] ^= 0xFF
            try await feed(cache, from: connection, path: path, bytes: wrong)

            #expect(await retrieve(cache, path: path, upTo: 100) == wrong.prefix(100))
            #expect(await retrieve(cache, path: path, upTo: 100) == wrong.prefix(100))
            #expect(await retrieve(cache, path: path, upTo: 100) == nil)
            #expect(await cache.cachedRanges(path: path) == [])

            await cache.close()
            try await control.disconnect()
        }
    }

    @Test("closing the cache leaves the control connection open, and checks fail from then on")
    func closeLeavesTheControlConnectionOpen() async throws {
        try await withReferenceCacheDirectory { connection, directory in
            let path = "\(directory)/file.bin"
            try await connection.dumpToFile(Self.payload, to: path)

            let control = try await connection.fork()
            let cache = SMB.ReferenceCache(
                controlConnection: control,
                configuration: .init(trustPolicy: .statOnServer, revalidationInterval: 0)
            )
            try await feed(cache, from: connection, path: path)
            #expect(await retrieve(cache, path: path) == Self.payload)

            await cache.close()
            #expect(control.isConnected)
            #expect(try await control.stat(at: path).size == UInt64(Self.payload.count))

            // Still attached somewhere, the cache stores, but cannot vouch for what it stores.
            try await feed(cache, from: connection, path: path)
            #expect(await retrieve(cache, path: path) == nil)

            try await control.disconnect()
        }
    }
}

// MARK: Helpers

/// Hands `cache` a stat of `path` and its contents, the way a connection that opened and read it does. `bytes` stand in
/// for the contents when given.
private func feed(
    _ cache: SMB.ReferenceCache,
    from connection: SMB.Connection,
    path: String,
    bytes: Data? = nil
) async throws {
    let statRequest = SMB.CacheRequestID()
    _ = await cache.retrieveStat(path: path, request: statRequest)
    let stat = try await connection.stat(at: path)
    await cache.storeStat(stat, path: path, request: statRequest)
    await cache.requestEnded(statRequest)

    let contents: Data = if let bytes {
        bytes
    }
    else {
        try await connection.loadFile(at: path)
    }
    let readRequest = SMB.CacheRequestID()
    _ = await cache.retrieveBlock(path: path, offset: 0, upTo: contents.count, request: readRequest)
    await cache.storeBlock(contents, path: path, offset: 0, source: .download, request: readRequest)
    await cache.requestEnded(readRequest)
}

/// Asks `cache` for the bytes of `path` from its start, ending the request at once.
private func retrieve(_ cache: SMB.ReferenceCache, path: String, upTo: Int = 1 << 20) async -> Data? {
    let request = SMB.CacheRequestID()
    let data = await cache.retrieveBlock(path: path, offset: 0, upTo: upTo, request: request)
    await cache.requestEnded(request)
    return data
}

/// Runs `body` with a connection to the public share and a new directory in it, then removes the directory.
private func withReferenceCacheDirectory(_ body: (SMB.Connection, String) async throws -> Void) async throws {
    let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
    let directory = uniquePath("reference_cache")
    try await connection.makeDirectory(at: directory)

    let result: Result<Void, any Error>
    do {
        try await body(connection, directory)
        result = .success(())
    }
    catch {
        result = .failure(error)
    }

    try? await connection.removeItem(at: directory)
    try? await connection.disconnect()
    try result.get()
}
