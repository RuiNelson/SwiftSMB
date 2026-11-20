//
// Part of SwiftSMB
// SMBFileOpLockBreakTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

/// Breaks are caused by a second connection opening the file in a way that conflicts with the first one's oplock or
/// lease. The server holds that open back until the break is acknowledged, or until its break timeout (35 seconds)
/// expires, so every conflicting open here runs under a timeout well below it.
@Suite(.tags(.integration), .serverConcurrencyLimit)
struct SMBFileOpLockBreakTests {
    private static let fullLease: SMB.File.LeaseState = [.readCaching, .writeCaching, .handleCaching]

    @Test("a lease break is delivered and waits for the acknowledgement")
    func leaseBreakIsAcknowledged() async throws {
        try await withConflictingConnections(prefix: "lease-break-ack") { owner, other, path in
            let file = try await owner.openFile(at: path, accessMode: .readWrite, opLock: .lease(Self.fullLease))
            defer { try? await file.close() }
            let listener = try await listen(to: file, acknowledgingAfter: 0)

            let conflicting = try await withTimeout(seconds: 20) {
                try await other.openFile(at: path, accessMode: .readWrite)
            }
            try await conflicting.close()

            let opLockBreak = try #require(try await withTimeout(seconds: 10) { try await listener.value })
            #expect(opLockBreak.requiresAcknowledgement)
            guard case let .lease(from, to) = opLockBreak.change else {
                Issue.record("Expected a lease break, got \(opLockBreak.debugDescription)")
                return
            }
            #expect(from == Self.fullLease)
            #expect(!to.contains(.writeCaching))
        }
    }

    @Test("the conflicting open waits until the lease break is acknowledged")
    func conflictingOpenWaitsForAcknowledgement() async throws {
        try await withConflictingConnections(prefix: "lease-break-wait") { owner, other, path in
            let file = try await owner.openFile(at: path, accessMode: .readWrite, opLock: .lease(Self.fullLease))
            defer { try? await file.close() }
            let delay = 2.0
            let listener = try await listen(to: file, acknowledgingAfter: delay)

            let start = ContinuousClock.now
            let conflicting = try await withTimeout(seconds: 20) {
                try await other.openFile(at: path, accessMode: .readWrite)
            }
            let waited = ContinuousClock.now - start
            try await conflicting.close()

            _ = try await withTimeout(seconds: 10) { try await listener.value }
            #expect(waited >= .seconds(delay * 0.75))
            #expect(waited < .seconds(30))
        }
    }

    @Test("a lease break nobody listens to is acknowledged while the connection is in use")
    func unheardLeaseBreakIsAcknowledged() async throws {
        try await withConflictingConnections(prefix: "lease-break-unheard") { owner, other, path in
            let file = try await owner.openFile(at: path, accessMode: .readWrite, opLock: .lease(Self.fullLease))
            defer { try? await file.close() }

            // Nobody iterates the breaks, so nothing services the owner in the background. Its own requests service it,
            // and the break they come across is acknowledged right away.
            let requests = Task {
                while !Task.isCancelled {
                    _ = try? await file.stat()
                    try? await Task.sleep(nanoseconds: 50_000_000)
                }
            }
            let start = ContinuousClock.now
            let conflicting = try await withTimeout(seconds: 20) {
                try await other.openFile(at: path, accessMode: .readWrite)
            }
            requests.cancel()
            await requests.value
            try await conflicting.close()
            #expect(ContinuousClock.now - start < .seconds(20))

            var iterator = file.opLockBreaks.makeAsyncIterator()
            let opLockBreak = try #require(try await iterator.next())
            #expect(!opLockBreak.requiresAcknowledgement)
            try await file.acknowledgeOpLockBreak()
        }
    }

    @Test("a batch oplock break is delivered and acknowledged by SwiftSMB")
    func batchOpLockBreak() async throws {
        try await withConflictingConnections(prefix: "oplock-break-batch") { owner, other, path in
            let file = try await owner.openFile(at: path, accessMode: .readWrite, opLock: .batch)
            defer { try? await file.close() }
            let listener = try await listen(to: file, acknowledgingAfter: 0)

            let conflicting = try await withTimeout(seconds: 20) {
                try await other.openFile(at: path, accessMode: .readOnly)
            }
            try await conflicting.close()

            let opLockBreak = try #require(try await withTimeout(seconds: 10) { try await listener.value })
            #expect(!opLockBreak.requiresAcknowledgement)
            guard case let .opLock(to) = opLockBreak.change else {
                Issue.record("Expected an oplock break, got \(opLockBreak.debugDescription)")
                return
            }
            #expect(to == .levelII || to == .none)
        }
    }

    @Test("a file opened without an oplock has no breaks")
    func noOpLockHasNoBreaks() async throws {
        try await withConflictingConnections(prefix: "oplock-break-none") { owner, _, path in
            let file = try await owner.openFile(at: path)
            defer { try? await file.close() }
            let breaks = try await withTimeout(seconds: 5) {
                var breaks: [SMB.File.OpLockBreak] = []
                for try await opLockBreak in file.opLockBreaks {
                    breaks.append(opLockBreak)
                }
                return breaks
            }
            #expect(breaks.isEmpty)
        }
    }

    @Test("closing the file ends the iteration of its breaks")
    func closingEndsIteration() async throws {
        try await withConflictingConnections(prefix: "oplock-break-close") { owner, _, path in
            let file = try await owner.openFile(at: path, accessMode: .readWrite, opLock: .lease(Self.fullLease))
            let (started, startedContinuation) = AsyncStream<Void>.makeStream()
            let iteration = Task {
                var count = 0
                var iterator = file.opLockBreaks.makeAsyncIterator()
                startedContinuation.yield()
                while try await iterator.next() != nil {
                    count += 1
                }
                return count
            }
            for await _ in started {
                break
            }
            try await file.close()
            let count = try await withTimeout(seconds: 10) { try await iteration.value }
            #expect(count == 0)
        }
    }
}

// MARK: - Helpers

/// Starts iterating a file's breaks, and returns once the iteration listens. The task acknowledges the first break
/// after `delay` seconds when it needs it, and returns it.
private func listen(
    to file: SMB.File,
    acknowledgingAfter delay: Double
) async throws -> Task<SMB.File.OpLockBreak?, any Error> {
    let (started, startedContinuation) = AsyncStream<Void>.makeStream()
    let task = Task {
        var iterator = file.opLockBreaks.makeAsyncIterator()
        startedContinuation.yield()
        guard let opLockBreak = try await iterator.next() else { return SMB.File.OpLockBreak?.none }
        if opLockBreak.requiresAcknowledgement {
            if delay > 0 {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
            try await file.acknowledgeOpLockBreak()
        }
        return opLockBreak
    }
    for await _ in started {
        break
    }
    return task
}

/// Runs `body` with two connections to the public share and a fixture file the second one will conflict on.
private func withConflictingConnections(
    prefix: String,
    body: (SMB.Connection, SMB.Connection, String) async throws -> Void
) async throws {
    let owner = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
    defer { try? await owner.disconnect() }
    let other = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
    defer { try? await other.disconnect() }

    let path = uniquePath("pub-\(prefix)") + ".txt"
    try await owner.dumpToFile(Data(TestContent.helloBytes), to: path)
    defer { try? await owner.removeFile(at: path) }
    try await body(owner, other, path)
}
