//
// Part of SwiftSMB
// SMBNotifyTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Dispatch
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
    @Test("watchDirectory reports file changes through delegate")
    func watchDirectoryReportsFileChangesThroughDelegate() throws {
        let watcherConnection = try publicNotifyConnection()
        let writerConnection = try publicNotifyConnection()
        defer { try? watcherConnection.disconnect() }
        defer { try? writerConnection.disconnect() }

        let root = uniquePath("notify")
        let file = root + "/created.txt"
        try writerConnection.makeDirectory(at: root)
        defer { try? writerConnection.removeItem(at: root) }

        let delegate = RecordingNotifyWatcherDelegate()
        let watcher = try watcherConnection.watchDirectory(
            at: root,
            filter: [.fileName, .lastWrite],
            delegate: delegate,
            callbackQueue: DispatchQueue(label: "com.ruinelson.SwiftSMB.SwiftSMBTests.NotifyDelegate"),
        )
        defer { watcher.cancel() }

        #expect(delegate.waitForStart(timeout: 5))
        try writerConnection.dumpToFile(Data("hello".utf8), to: file)

        let changes = delegate.waitForChanges(timeout: 5)
        #expect(delegate.failure == nil)
        #expect(changes?.contains { $0.name.hasSuffix("created.txt") } == true)
    }

    @Test("watchDirectory cancellation reports cancellation")
    func watchDirectoryCancellationReportsCancellation() throws {
        let connection = try publicNotifyConnection()
        defer { try? connection.disconnect() }

        let root = uniquePath("notify-cancel")
        try connection.makeDirectory(at: root)
        defer { try? connection.removeItem(at: root) }

        let delegate = RecordingNotifyWatcherDelegate()
        let watcher = try connection.watchDirectory(
            at: root,
            delegate: delegate,
            callbackQueue: DispatchQueue(label: "com.ruinelson.SwiftSMB.SwiftSMBTests.NotifyCancelDelegate"),
        )

        #expect(delegate.waitForStart(timeout: 5))
        watcher.cancel()

        #expect(delegate.waitForCancel(timeout: 5))
        #expect(delegate.failure == nil)
    }
}

private final class RecordingNotifyWatcherDelegate: SMB.NotifyWatcherDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let startSemaphore = DispatchSemaphore(value: 0)
    private let changesSemaphore = DispatchSemaphore(value: 0)
    private let cancelSemaphore = DispatchSemaphore(value: 0)
    private var receivedChanges: [[SMB.NotifyChange]] = []
    private var receivedFailure: (any Error)?

    var failure: (any Error)? {
        lock.lock()
        defer { lock.unlock() }
        return receivedFailure
    }

    func notifyWatcherDidStart(_: SMB.NotifyWatcher) {
        startSemaphore.signal()
    }

    func notifyWatcherDidCancel(_: SMB.NotifyWatcher) {
        cancelSemaphore.signal()
    }

    func notifyWatcher(_: SMB.NotifyWatcher, didReceive changes: [SMB.NotifyChange]) {
        lock.lock()
        receivedChanges.append(changes)
        lock.unlock()
        changesSemaphore.signal()
    }

    func notifyWatcher(_: SMB.NotifyWatcher, didFailWith error: any Error) {
        lock.lock()
        receivedFailure = error
        lock.unlock()
        changesSemaphore.signal()
    }

    func waitForStart(timeout: TimeInterval) -> Bool {
        startSemaphore.wait(timeout: .now() + timeout) == .success
    }

    func waitForCancel(timeout: TimeInterval) -> Bool {
        cancelSemaphore.wait(timeout: .now() + timeout) == .success
    }

    func waitForChanges(timeout: TimeInterval) -> [SMB.NotifyChange]? {
        guard changesSemaphore.wait(timeout: .now() + timeout) == .success else {
            return nil
        }

        lock.lock()
        defer { lock.unlock() }
        return receivedChanges.last
    }
}

private func publicNotifyConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}
