//
// Part of SwiftSMB
// CookbookWatchingChangesTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Dispatch
import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookWatchingChangesTests {
    @Test("watchDirectory compiles and runs")
    func watchDirectory() throws {
        let watcherConnection = try cookbookConnection()
        let writerConnection = try cookbookConnection()
        defer { try? watcherConnection.disconnect() }
        defer { try? writerConnection.disconnect() }

        let root = uniquePath("cookbook-notify")
        try writerConnection.makeDirectory(at: root)
        defer { try? writerConnection.removeItem(at: root) }

        let delegate = CookbookWatcherDelegate()
        let watcher = try watcherConnection.watchDirectory(
            at: root,
            delegate: delegate,
        )
        defer { watcher.cancel() }

        #expect(delegate.waitForStart(timeout: 5))
        try writerConnection.dumpToFile(Data("hello".utf8), to: root + "/created.txt")
        _ = delegate.waitForChanges(timeout: 5)
    }

    @Test("watchDirectory with filter compiles and runs")
    func watchDirectoryWithFilter() throws {
        let watcherConnection = try cookbookConnection()
        let writerConnection = try cookbookConnection()
        defer { try? watcherConnection.disconnect() }
        defer { try? writerConnection.disconnect() }

        let root = uniquePath("cookbook-notify-filter")
        try writerConnection.makeDirectory(at: root)
        defer { try? writerConnection.removeItem(at: root) }

        let delegate = CookbookWatcherDelegate()
        let watcher = try watcherConnection.watchDirectory(
            at: root,
            filter: [.fileName, .directoryName, .size],
            delegate: delegate,
        )
        defer { watcher.cancel() }

        #expect(delegate.waitForStart(timeout: 5))
    }

    @Test("watchDirectory recursive compiles and runs")
    func watchDirectoryRecursive() throws {
        let watcherConnection = try cookbookConnection()
        let writerConnection = try cookbookConnection()
        defer { try? watcherConnection.disconnect() }
        defer { try? writerConnection.disconnect() }

        let root = uniquePath("cookbook-notify-rec")
        try writerConnection.makeDirectory(at: root)
        defer { try? writerConnection.removeItem(at: root) }

        let delegate = CookbookWatcherDelegate()
        let watcher = try watcherConnection.watchDirectory(
            at: root,
            options: .recursive,
            delegate: delegate,
        )
        defer { watcher.cancel() }

        #expect(delegate.waitForStart(timeout: 5))
    }

    @Test("watchDirectory with callback queue compiles and runs")
    func watchDirectoryWithCallbackQueue() throws {
        let watcherConnection = try cookbookConnection()
        let writerConnection = try cookbookConnection()
        defer { try? watcherConnection.disconnect() }
        defer { try? writerConnection.disconnect() }

        let root = uniquePath("cookbook-notify-queue")
        try writerConnection.makeDirectory(at: root)
        defer { try? writerConnection.removeItem(at: root) }

        let queue = DispatchQueue(label: "com.example.smb-watcher")
        let delegate = CookbookWatcherDelegate()
        let watcher = try watcherConnection.watchDirectory(
            at: root,
            delegate: delegate,
            callbackQueue: queue,
        )
        defer { watcher.cancel() }

        #expect(delegate.waitForStart(timeout: 5))
    }

    @Test("cancel watcher compiles and runs")
    func cancelWatcher() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }

        let root = uniquePath("cookbook-notify-cancel")
        try connection.makeDirectory(at: root)
        defer { try? connection.removeItem(at: root) }

        let delegate = CookbookWatcherDelegate()
        let watcher = try connection.watchDirectory(
            at: root,
            delegate: delegate,
        )

        #expect(delegate.waitForStart(timeout: 5))
        watcher.cancel()
        #expect(delegate.waitForCancel(timeout: 5))
    }
}

private final class CookbookWatcherDelegate: SMB.NotifyWatcherDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private let startSemaphore = DispatchSemaphore(value: 0)
    private let changesSemaphore = DispatchSemaphore(value: 0)
    private let cancelSemaphore = DispatchSemaphore(value: 0)
    private var receivedChanges: [[SMB.NotifyChange]] = []
    private var receivedFailure: (any Error)?

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
