//
// Part of SwiftSMB
// CookbookWatchingChangesTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookWatchingChangesTests {
    @Test("watchDirectory compiles and runs")
    func watchDirectory() async throws {
        let watcherConnection = try await cookbookConnection()
        let writerConnection = try await cookbookConnection()
        defer { try? await watcherConnection.disconnect() }
        defer { try? await writerConnection.disconnect() }

        let root = uniquePath("cookbook-notify")
        try await writerConnection.makeDirectory(at: root)
        defer { try? await writerConnection.removeItem(at: root) }

        let watcher = try await watcherConnection.watchDirectory(at: root)
        defer { watcher.cancel() }

        try await writerConnection.dumpToFile(Data("hello".utf8), to: root + "/created.txt")

        let received = try await withTimeout(seconds: 5) {
            for try await changes in watcher {
                for change in changes {
                    switch change.action {
                    case .added:
                        print("Added: \(change.name)")
                    case .removed:
                        print("Removed: \(change.name)")
                    case .modified:
                        print("Modified: \(change.name)")
                    case .renamedOldName:
                        print("Renamed from: \(change.name)")
                    case .renamedNewName:
                        print("Renamed to: \(change.name)")
                    default:
                        print("Other action on: \(change.name)")
                    }
                }
                return changes
            }
            return []
        }
        #expect(!received.isEmpty)
    }

    @Test("watchDirectory with filter compiles and runs")
    func watchDirectoryWithFilter() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("cookbook-notify-filter")
        try await connection.makeDirectory(at: root)
        defer { try? await connection.removeItem(at: root) }

        let watcher = try await connection.watchDirectory(
            at: root,
            filter: [.fileName, .directoryName, .size]
        )
        watcher.cancel()
    }

    @Test("watchDirectory recursive compiles and runs")
    func watchDirectoryRecursive() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("cookbook-notify-rec")
        try await connection.makeDirectory(at: root)
        defer { try? await connection.removeItem(at: root) }

        let watcher = try await connection.watchDirectory(
            at: root,
            options: .recursive
        )
        watcher.cancel()
    }

    @Test("watching in a background task compiles and runs")
    func watchInBackgroundTask() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("cookbook-notify-task")
        try await connection.makeDirectory(at: root)
        defer { try? await connection.removeItem(at: root) }

        let watcher = try await connection.watchDirectory(at: root)
        let watchTask = Task {
            for try await changes in watcher {
                print("Received \(changes.count) changes")
            }
        }

        watchTask.cancel()
        try await withTimeout(seconds: 5) { try await watchTask.value }
    }

    @Test("cancel watcher compiles and runs")
    func cancelWatcher() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("cookbook-notify-cancel")
        try await connection.makeDirectory(at: root)
        defer { try? await connection.removeItem(at: root) }

        let watcher = try await connection.watchDirectory(at: root)
        let watchTask = Task {
            for try await _ in watcher {
            }
            print("Watcher stopped")
        }

        watcher.cancel()
        try await withTimeout(seconds: 5) { try await watchTask.value }
    }
}
