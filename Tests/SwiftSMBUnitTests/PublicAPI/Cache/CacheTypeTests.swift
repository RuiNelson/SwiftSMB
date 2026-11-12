//
// Part of SwiftSMB
// CacheTypeTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite("Cache: identifiers")
struct CacheIdentifierTests {
    @Test("request identifiers never repeat, even when made concurrently")
    func requestIDsAreUnique() async {
        let ids = await withTaskGroup(of: [SMB.CacheRequestID].self) { group in
            for _ in 0 ..< 8 {
                group.addTask {
                    (0 ..< 1000).map { _ in SMB.CacheRequestID() }
                }
            }
            return await group.reduce(into: []) { $0 += $1 }
        }
        #expect(ids.count == 8000)
        #expect(Set(ids).count == ids.count)
    }

    @Test("file identifiers never repeat, even when made concurrently")
    func fileIDsAreUnique() async {
        let ids = await withTaskGroup(of: [SMB.CacheFileID].self) { group in
            for _ in 0 ..< 8 {
                group.addTask {
                    (0 ..< 1000).map { _ in SMB.CacheFileID() }
                }
            }
            return await group.reduce(into: []) { $0 += $1 }
        }
        #expect(ids.count == 8000)
        #expect(Set(ids).count == ids.count)
    }

    @Test("an identifier equals only itself")
    func identifierEquality() {
        let request = SMB.CacheRequestID()
        let copy = request
        #expect(request == copy)
        #expect(request != SMB.CacheRequestID())

        let file = SMB.CacheFileID()
        #expect(file == file)
        #expect(file != SMB.CacheFileID())
    }

    @Test("the counter hands out increasing values")
    func counterIncreases() {
        let counter = ProcessUniqueCounter(label: "test")
        #expect(counter.next() == 1)
        #expect(counter.next() == 2)
        #expect(counter.next() == 3)
    }

    @Test("identifiers describe themselves")
    func descriptions() {
        #expect(SMB.CacheRequestID().debugDescription.hasPrefix("SMB.CacheRequestID("))
        #expect(SMB.CacheFileID().debugDescription.hasPrefix("SMB.CacheFileID("))
        #expect(SMB.CacheFileID().description.hasPrefix("CacheFileID("))
        #expect(SMB.CacheBlockSource.download.debugDescription == "SMB.CacheBlockSource.download")
        #expect(SMB.CachedStat.doesNotExist.debugDescription == "SMB.CachedStat.doesNotExist")
    }
}

@Suite("Cache: ReferenceCache configuration")
struct ReferenceCacheConfigurationTests {
    @Test("defaults trust reports, keep uploads, and match paths exactly")
    func defaults() {
        let configuration = SMB.ReferenceCache.Configuration()
        #expect(configuration.keepsUploads)
        #expect(configuration.trustPolicy == .trustReports)
        #expect(configuration.revalidationInterval == 30)
        #expect(configuration.metadata == .neverAnswer)
        #expect(configuration.pathMatching == .exact)
        #expect(!configuration.needsControlConnection)
    }

    @Test("checks against the server need a control connection")
    func controlConnection() {
        #expect(SMB.ReferenceCache.Configuration(trustPolicy: .statOnServer).needsControlConnection)
        #expect(SMB.ReferenceCache.Configuration(trustPolicy: .sampleBlocks(count: 4)).needsControlConnection)
        #expect(
            !SMB.ReferenceCache.Configuration(
                metadata: .answer(for: 5, includingMissing: true),
                pathMatching: .caseInsensitive
            ).needsControlConnection
        )
    }

    @Test("sampling scans by bisection unless told otherwise")
    func sampleBlocksDefaultScan() {
        #expect(
            SMB.ReferenceCache.TrustPolicy.sampleBlocks(count: 2)
                == .sampleBlocks(count: 2, scan: .bisection)
        )
        #expect(
            SMB.ReferenceCache.TrustPolicy.sampleBlocks(count: 2, scan: .startToEnd)
                != .sampleBlocks(count: 2, scan: .bisection)
        )
    }

    @Test("valid configurations pass validation")
    func validation() {
        SMB.ReferenceCache.Configuration(
            trustPolicy: .sampleBlocks(count: 1, scan: .endToStart),
            revalidationInterval: 0,
            metadata: .answer(for: 0, includingMissing: false)
        ).validate()
        SMB.ReferenceCache.Configuration(revalidationInterval: nil).validate()
    }

    @Test("debug descriptions name every value")
    func debugDescription() {
        let configuration = SMB.ReferenceCache.Configuration(
            keepsUploads: false,
            trustPolicy: .sampleBlocks(count: 3, scan: .startToEnd),
            revalidationInterval: nil,
            metadata: .answer(for: 5, includingMissing: true),
            pathMatching: .caseInsensitive
        )
        #expect(
            configuration.debugDescription
                == "SMB.ReferenceCache.Configuration(keepsUploads: false, trustPolicy: SMB.ReferenceCache.TrustPolicy.sampleBlocks(count: 3, scan: SMB.FileCompareScan.startToEnd), revalidationInterval: nil, metadata: SMB.ReferenceCache.MetadataPolicy.answer(for: 5.0, includingMissing: true), pathMatching: SMB.ReferenceCache.PathMatching.caseInsensitive)"
        )
    }
}

@Suite("Cache: attaching to a connection")
struct ConnectionCacheAttachmentTests {
    /// A connection around a context that never connected, which is all attaching needs.
    private func makeConnection() throws -> SMB.Connection {
        try SMB.Connection(
            server: SMB.Server(host: "localhost"),
            share: "share",
            configuration: SMB.Configuration(),
            credentials: nil,
            context: Bridge.createContext(),
            maxReadSize: 65536,
            maxWriteSize: 65536
        )
    }

    @Test("attach, replace, and detach")
    func attachAndDetach() async throws {
        let connection = try makeConnection()
        #expect(!connection.hasCacheAttached())

        let first = RecordingCache()
        connection.attachCache(first)
        #expect(connection.hasCacheAttached())
        #expect(connection.cache as? RecordingCache === first)

        let second = RecordingCache()
        connection.attachCache(second)
        #expect(connection.cache as? RecordingCache === second)

        connection.detachCache()
        #expect(!connection.hasCacheAttached())
        #expect(connection.cache == nil)

        connection.detachCache()
        #expect(!connection.hasCacheAttached())

        try? await connection.disconnect()
    }

    @Test("disconnecting detaches the cache, and a disconnected connection takes none")
    func disconnectDetaches() async throws {
        let connection = try makeConnection()
        connection.attachCache(RecordingCache())
        #expect(connection.hasCacheAttached())

        try? await connection.disconnect()
        #expect(!connection.hasCacheAttached())

        connection.attachCache(RecordingCache())
        #expect(!connection.hasCacheAttached())
    }

    @Test("graceful disconnection detaches the cache")
    func gracefulDisconnectDetaches() async throws {
        let connection = try makeConnection()
        connection.attachCache(RecordingCache())

        try? await connection.disconnectGracefully()
        #expect(!connection.hasCacheAttached())
    }

    @Test("every attachment is a new one, even of the same cache")
    func attachmentsAreDistinct() async throws {
        let connection = try makeConnection()
        let cache = RecordingCache()

        connection.attachCache(cache)
        let first = try #require(connection.cacheAttachment)
        connection.attachCache(cache)
        let second = try #require(connection.cacheAttachment)
        #expect(first.cache as? RecordingCache === second.cache as? RecordingCache)

        try? await connection.disconnect()
    }
}

/// A cache that answers nothing and records what it was told, to check that the protocol can be adopted.
private actor RecordingCache: SMB.BlockLevelReadCache {
    private(set) var calls: [String] = []

    func storeBlock(
        _ data: Data,
        path: String,
        offset: UInt64,
        source: SMB.CacheBlockSource,
        request: SMB.CacheRequestID?
    ) {
        calls.append("storeBlock(\(path), \(offset), \(data.count))")
    }

    func retrieveBlock(path: String, offset: UInt64, upTo: Int, request: SMB.CacheRequestID) -> Data? {
        calls.append("retrieveBlock(\(path), \(offset), \(upTo))")
        return nil
    }

    func storeStat(_ result: SMB.Stat?, path: String, request: SMB.CacheRequestID) {
        calls.append("storeStat(\(path))")
    }

    func storeDirectoryListing(_ entries: [SMB.DirectoryEntry], path: String, request: SMB.CacheRequestID) {
        calls.append("storeDirectoryListing(\(path), \(entries.count))")
    }

    func retrieveStat(path: String, request: SMB.CacheRequestID) -> SMB.CachedStat? {
        calls.append("retrieveStat(\(path))")
        return nil
    }

    func retrieveDirectoryListing(path: String, request: SMB.CacheRequestID) -> [SMB.DirectoryEntry]? {
        calls.append("retrieveDirectoryListing(\(path))")
        return nil
    }

    func beginRequest(_ request: SMB.CacheRequestID) {
        calls.append("beginRequest")
    }

    func requestEnded(_ request: SMB.CacheRequestID) {
        calls.append("requestEnded")
    }

    func didRename(from: String, to: String) {
        calls.append("didRename(\(from), \(to))")
    }

    func didAppend(path: String, byteCount: UInt64) {
        calls.append("didAppend(\(path), \(byteCount))")
    }

    func invalidate(path: String) {
        calls.append("invalidate(\(path))")
    }
}
