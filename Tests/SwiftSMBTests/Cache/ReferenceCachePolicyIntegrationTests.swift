//
// Part of SwiftSMB
// ReferenceCachePolicyIntegrationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

/// Every documented trust policy and metadata policy of ``SMB/ReferenceCache``, through a real connection on the test
/// server, against changes made by a connection the cache does not hear from.
///
/// Samba updates a file's change time on every write, and does not let a client set it back, so a stat tells every
/// version of a file apart: what the policies differ in is when a stat, or a check, is made.
@Suite("ReferenceCache: trust and metadata policies through a live connection", .tags(.integration), .serialized)
struct ReferenceCachePolicyIntegrationTests {
    static let payload = cachePayload(byteCount: 40000)
    static let marker = Data(repeating: 0xEE, count: 1000)
    static let changed = overwritten(payload, at: 20000, with: marker)

    /// Writes the payload, opens it through the cached connection and reads it whole, so the cache holds it, then has a
    /// connection the cache does not hear from change it in place, keeping its size.
    ///
    /// - Returns: The handle, still open.
    private static func cacheThenChangeElsewhere(_ connections: CachedConnections, path: String) async throws -> SMB
    .File {
        try await writeRemote(connections.truth, path, payload)
        let handle = try await connections.connection.openFile(at: path)
        #expect(try await handle.read(upTo: Int64(payload.count), atOffset: 0) == payload)
        #expect(try await handle.read(upTo: Int64(payload.count), atOffset: 0) == payload)
        #expect(connections.gated.hits > 0)

        try await overwriteRemote(connections.truth, path, at: 20000, with: marker)
        return handle
    }

    // MARK: Trust policies

    @Test("trustReports: a file kept open misses a change made elsewhere until it is stat'ed or opened anew")
    func trustReports() async throws {
        try await withCachedConnections(.init(trustPolicy: .trustReports)) { connections in
            let path = "\(connections.directory)/file.bin"
            let handle = try await Self.cacheThenChangeElsewhere(connections, path: path)

            // Documented: without a check, nothing stats the file while it stays open.
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.payload)

            // Opening it anew stats it, which shows the new version.
            #expect(try await readRemote(connections.connection, path) == Self.changed)

            // So does a stat of the open file.
            _ = try await handle.stat()
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)
            try await handle.close()
        }
    }

    @Test("statOnServer with an interval of zero: a file kept open sees a change made elsewhere at its next read")
    func statOnServerEveryRead() async throws {
        try await withCachedConnections(.init(trustPolicy: .statOnServer, revalidationInterval: 0)) { connections in
            let path = "\(connections.directory)/file.bin"
            let handle = try await Self.cacheThenChangeElsewhere(connections, path: path)

            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)
            #expect(await connections.cache.cachedRanges(path: path) == [0 ..< 40000])
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)
            try await handle.close()
        }
    }

    @Test("statOnServer without an interval: checked once per stat, so a file kept open misses later changes")
    func statOnServerOncePerStat() async throws {
        try await withCachedConnections(.init(trustPolicy: .statOnServer, revalidationInterval: nil)) { connections in
            let path = "\(connections.directory)/file.bin"
            let handle = try await Self.cacheThenChangeElsewhere(connections, path: path)

            // The stat made when the file was opened was its check.
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.payload)

            // The next stat makes it due again.
            _ = try await handle.stat()
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)
            try await handle.close()
        }
    }

    @Test("statOnServer with an interval: a check stays good for the interval, and the next one sees the change")
    func statOnServerWithAnInterval() async throws {
        try await withCachedConnections(.init(trustPolicy: .statOnServer, revalidationInterval: 1)) { connections in
            let path = "\(connections.directory)/file.bin"
            let handle = try await Self.cacheThenChangeElsewhere(connections, path: path)

            try await Task.sleep(for: .milliseconds(1200))
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)
            try await handle.close()
        }
    }

    @Test("sampleBlocks with an interval of zero: a file kept open sees a change made elsewhere at its next read")
    func sampleBlocks() async throws {
        let configuration = SMB.ReferenceCache.Configuration(
            trustPolicy: .sampleBlocks(count: 3),
            revalidationInterval: 0
        )
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            let handle = try await Self.cacheThenChangeElsewhere(connections, path: path)

            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)

            // Checked and unchanged, the bytes are handed out again.
            let hits = connections.gated.hits
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)
            #expect(connections.gated.hits > hits)
            try await handle.close()
        }
    }

    @Test(
        "every trust policy: changes through the connection and its fork are never missed",
        arguments: [
            SMB.ReferenceCache.TrustPolicy.trustReports,
            .statOnServer,
            .sampleBlocks(count: 2, scan: .startToEnd),
        ]
    )
    func changesThroughTheConnection(policy: SMB.ReferenceCache.TrustPolicy) async throws {
        try await withCachedConnections(.init(trustPolicy: policy, revalidationInterval: nil)) { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            let handle = try await connections.connection.openFile(at: path)
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.payload)

            try await overwriteRemote(connections.fork, path, at: 20000, with: Self.marker)
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.changed)

            try await connections.connection.truncateFile(at: path, toLength: 100)
            #expect(try await handle.read(upTo: 40000, atOffset: 0) == Self.payload.prefix(100))
            try await handle.close()
        }
    }

    // MARK: Metadata policies

    @Test("neverAnswer: every stat and listing goes to the server")
    func neverAnswer() async throws {
        try await withCachedConnections(.init(metadata: .neverAnswer)) { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            #expect(try await connections.connection.stat(at: path).size == 40000)
            _ = try await connections.connection.listDirectory(at: connections.directory)

            try await connections.truth.truncateFile(at: path, toLength: 10)
            try await writeRemote(connections.truth, "\(connections.directory)/new.bin", Self.marker)

            #expect(try await connections.connection.stat(at: path).size == 10)
            let names = try await connections.connection.listDirectory(at: connections.directory).map(\.name)
            #expect(Set(names).isSuperset(of: ["file.bin", "new.bin"]))
        }
    }

    @Test("answer without missing: stats and listings stored are answered, absences are always asked")
    func answerWithoutMissing() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 60, includingMissing: false))
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            let missing = "\(connections.directory)/missing.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            #expect(try await connections.connection.stat(at: path).size == 40000)
            #expect(try await connections.connection.itemExists(at: missing) == .false)

            try await connections.truth.truncateFile(at: path, toLength: 10)
            try await writeRemote(connections.truth, missing, Self.marker)

            // Documented: changes made elsewhere go unnoticed while the answer is young.
            #expect(try await connections.connection.stat(at: path).size == 40000)
            // Absences are never answered from the cache.
            #expect(try await connections.connection.itemExists(at: missing) == .file)

            // A change through the fork is never missed.
            try await connections.fork.truncateFile(at: path, toLength: 20)
            #expect(try await connections.connection.stat(at: path).size == 20)
        }
    }

    @Test("answer with missing: absences are answered too, and changes through the connection are never missed")
    func answerWithMissing() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 60, includingMissing: true))
        try await withCachedConnections(configuration) { connections in
            let missing = "\(connections.directory)/missing.bin"
            #expect(try await connections.connection.itemExists(at: missing) == .false)

            // Documented: an item created elsewhere looks missing while the answer is young.
            try await writeRemote(connections.truth, missing, Self.marker)
            #expect(try await connections.connection.itemExists(at: missing) == .false)

            try await connections.fork.truncateFile(at: missing, toLength: 5)
            #expect(try await connections.connection.itemExists(at: missing) == .file)
            #expect(try await connections.connection.stat(at: missing).size == 5)

            // A listing stored is answered, and a delete through the connection drops it.
            let listed = try await connections.connection.listDirectory(at: connections.directory)
            #expect(listed.map(\.name).contains("missing.bin"))
            try await connections.connection.removeFile(at: missing)
            let after = try await connections.connection.listDirectory(at: connections.directory)
            #expect(!after.map(\.name).contains("missing.bin"))
            #expect(try await connections.connection.itemExists(at: missing) == .false)
        }
    }

    @Test("answer for a second: once the answer is older, the server is asked again")
    func answerExpires() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 1, includingMissing: true))
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            #expect(try await connections.connection.stat(at: path).size == 40000)

            try await connections.truth.truncateFile(at: path, toLength: 10)
            try await Task.sleep(for: .milliseconds(1200))
            #expect(try await connections.connection.stat(at: path).size == 10)
        }
    }

    @Test("answered stats do not stand in for the stat opening a file makes: a file opened anew shows its version")
    func openingComparesWhatever() async throws {
        let configuration = SMB.ReferenceCache.Configuration(metadata: .answer(for: 60, includingMissing: true))
        try await withCachedConnections(configuration) { connections in
            let path = "\(connections.directory)/file.bin"
            try await writeRemote(connections.truth, path, Self.payload)
            #expect(try await connections.connection.stat(at: path).size == 40000)
            #expect(try await readRemote(connections.connection, path) == Self.payload)

            try await overwriteRemote(connections.truth, path, at: 20000, with: Self.marker)

            // The stat is answered from the cache, but the handle's own stat goes to the server.
            #expect(try await connections.connection.stat(at: path).size == 40000)
            #expect(try await readRemote(connections.connection, path) == Self.changed)
        }
    }
}
