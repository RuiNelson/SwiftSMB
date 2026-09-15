//
// Part of SwiftSMB
// SMBNotifyTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

struct SMBNotifyPublicAPITests {
    @Test("notify options and filters compose") func notifyOptionsAndFiltersCompose() {
        let options: SMB.NotifyOptions = [.recursive]
        let filter: SMB.NotifyFilter = [.fileName, .directoryName, .lastWrite]

        #expect(options.contains(.recursive))
        #expect(filter.contains(.fileName))
        #expect(filter.contains(.directoryName))
        #expect(filter.contains(.lastWrite))
        #expect(!filter.contains(.security))
    }

    @Test("notify change exposes action and name") func notifyChangeExposesActionAndName() {
        let change = SMB.NotifyChange(action: .added, name: "new.txt")

        #expect(change.action == .added)
        #expect(change.name == "new.txt")
    }
}

@Suite(.tags(.integration))
struct SMBNotifyIntegrationTests {
    @Test("watchDirectory reports file changes")
    func watchDirectoryReportsFileChanges() async throws {
        let watcherConnection = try await publicNotifyConnection()
        let writerConnection = try await publicNotifyConnection()
        defer { try? await watcherConnection.disconnect() }
        defer { try? await writerConnection.disconnect() }

        let root = uniquePath("notify")
        let file = root + "/created.txt"
        try await writerConnection.makeDirectory(at: root)
        defer { try? await writerConnection.removeItem(at: root) }

        let watcher = try await watcherConnection.watchDirectory(at: root, filter: [.fileName, .lastWrite])
        defer { watcher.cancel() }

        try await writerConnection.dumpToFile(Data("hello".utf8), to: file)

        let changes = try await firstBatch(from: watcher)
        #expect(changes?.contains { $0.name.hasSuffix("created.txt") } == true)
    }

    @Test("watchDirectory cancellation ends iteration normally")
    func watchDirectoryCancellationEndsIterationNormally() async throws {
        let connection = try await publicNotifyConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("notify-cancel")
        try await connection.makeDirectory(at: root)
        defer { try? await connection.removeItem(at: root) }

        let watcher = try await connection.watchDirectory(at: root)
        let iteration = Task {
            var batches = 0
            for try await _ in watcher {
                batches += 1
            }
            return batches
        }

        watcher.cancel()
        #expect(try await withTimeout(seconds: 5) { try await iteration.value } == 0)
    }

    @Test("cancelling the iterating task cancels the watcher")
    func cancellingIteratingTaskCancelsWatcher() async throws {
        let connection = try await publicNotifyConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("notify-task-cancel")
        try await connection.makeDirectory(at: root)
        defer { try? await connection.removeItem(at: root) }

        let watcher = try await connection.watchDirectory(at: root)
        let iteration = Task {
            for try await _ in watcher {
            }
        }

        iteration.cancel()
        try await withTimeout(seconds: 5) { try await iteration.value }
    }

    @Test("disconnect ends watcher iteration normally")
    func disconnectEndsWatcherIterationNormally() async throws {
        let setupConnection = try await publicNotifyConnection()
        defer { try? await setupConnection.disconnect() }

        let root = uniquePath("notify-disconnect")
        try await setupConnection.makeDirectory(at: root)
        defer { try? await setupConnection.removeItem(at: root) }

        let connection = try await publicNotifyConnection()
        let watcher = try await connection.watchDirectory(at: root)
        let iteration = Task {
            for try await _ in watcher {
            }
        }

        try await connection.disconnect()
        try await withTimeout(seconds: 5) { try await iteration.value }
    }

    @Test("releasing a connection with an active watcher ends iteration")
    func releasingConnectionWithActiveWatcherEndsIteration() async throws {
        let setupConnection = try await publicNotifyConnection()
        defer { try? await setupConnection.disconnect() }

        let root = uniquePath("notify-release")
        try await setupConnection.makeDirectory(at: root)
        defer { try? await setupConnection.removeItem(at: root) }

        var connection: SMB.Connection? = try await publicNotifyConnection()
        let watcher = try await connection!.watchDirectory(at: root)
        let iteration = Task {
            for try await _ in watcher {
            }
        }

        connection = nil
        try await withTimeout(seconds: 5) { try await iteration.value }
    }
}

/// Returns the first change batch reported by `watcher`, or `nil` if the watcher stops first.
private func firstBatch(from watcher: SMB.NotifyWatcher) async throws -> [SMB.NotifyChange]? {
    try await withTimeout(seconds: 5) {
        var iterator = watcher.makeAsyncIterator()
        return try await iterator.next()
    }
}

private func publicNotifyConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
