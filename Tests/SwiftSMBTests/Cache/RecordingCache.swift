//
// Part of SwiftSMB
// RecordingCache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

/// A cache that records every call, and answers only with what a test gave it.
actor RecordingCache: SMB.BlockLevelReadCache {
    enum Event: Equatable, CustomStringConvertible {
        case storeBlock(path: String, offset: UInt64, data: Data, source: SMB.CacheBlockSource)
        case retrieveBlock(path: String, offset: UInt64, upTo: Int)
        case storeStat(path: String, size: UInt64?)
        case storeDirectoryListing(path: String, names: Set<String>)
        case retrieveStat(path: String)
        case retrieveDirectoryListing(path: String)
        case didRename(from: String, to: String)
        case didAppend(path: String, byteCount: UInt64)
        case invalidate(path: String)

        var isBlockEvent: Bool {
            switch self {
            case .storeBlock, .retrieveBlock: true
            default: false
            }
        }

        var isChange: Bool {
            switch self {
            case .didRename, .didAppend, .invalidate: true
            default: false
            }
        }

        /// The paths the event is about.
        var paths: [String] {
            switch self {
            case let .storeBlock(path, _, _, _), let .retrieveBlock(path, _, _), let .storeStat(path, _),
                 let .storeDirectoryListing(path, _), let .retrieveStat(path), let .retrieveDirectoryListing(path),
                 let .didAppend(path, _), let .invalidate(path):
                [path]
            case let .didRename(from, to):
                [from, to]
            }
        }

        var description: String {
            switch self {
            case let .storeBlock(path, offset, data, source):
                "storeBlock(\(path), \(offset), \(data.count) bytes, \(source))"
            case let .retrieveBlock(path, offset, upTo):
                "retrieveBlock(\(path), \(offset), upTo: \(upTo))"
            case let .storeStat(path, size):
                "storeStat(\(path), size: \(size.map(String.init) ?? "nil"))"
            case let .storeDirectoryListing(path, names):
                "storeDirectoryListing(\(path), \(names.sorted()))"
            case let .retrieveStat(path):
                "retrieveStat(\(path))"
            case let .retrieveDirectoryListing(path):
                "retrieveDirectoryListing(\(path))"
            case let .didRename(from, to):
                "didRename(\(from) -> \(to))"
            case let .didAppend(path, byteCount):
                "didAppend(\(path), \(byteCount))"
            case let .invalidate(path):
                "invalidate(\(path))"
            }
        }
    }

    /// A call that carries a request identifier.
    enum RequestCall: Equatable {
        case lookup(SMB.CacheRequestID)
        case begin(SMB.CacheRequestID)
        case store(SMB.CacheRequestID?)
        case end(SMB.CacheRequestID)
    }

    private(set) var events: [Event] = []
    private(set) var requestCalls: [RequestCall] = []
    private var blocks: [String: (offset: UInt64, data: Data)] = [:]
    private var stats: [String: SMB.CachedStat] = [:]
    private var listings: [String: [SMB.DirectoryEntry]] = [:]

    /// Whether the next store is held on its way in, before it is recorded.
    private var holdsNextStore = false
    /// The store held, until ``releaseHeldStore()``.
    private var heldStore: CheckedContinuation<Void, Never>?
    /// Tasks waiting in ``waitForHeldStore()``.
    private var heldStoreWaiters: [CheckedContinuation<Void, Never>] = []

    /// Has ``retrieveBlock(path:offset:upTo:request:)`` answer with `data` for reads starting at `offset`.
    func answerBlock(_ data: Data, path: String, offset: UInt64) {
        blocks[path] = (offset, data)
    }

    func answerStat(_ answer: SMB.CachedStat?, path: String) {
        stats[path] = answer
    }

    func answerListing(_ entries: [SMB.DirectoryEntry]?, path: String) {
        listings[path] = entries
    }

    func reset() {
        events = []
        requestCalls = []
    }

    /// Holds the next ``storeBlock(_:path:offset:source:request:)`` or ``storeStat(_:path:request:)`` before it is
    /// recorded, as if it were still on its way, until ``releaseHeldStore()``. Other calls go on meanwhile.
    func holdNextStore() {
        holdsNextStore = true
    }

    /// Waits until a store is held.
    func waitForHeldStore() async {
        guard heldStore == nil else {
            return
        }
        await withCheckedContinuation { heldStoreWaiters.append($0) }
    }

    /// Lets the held store through.
    func releaseHeldStore() {
        heldStore?.resume()
        heldStore = nil
    }

    private func holdIfAsked() async {
        guard holdsNextStore else {
            return
        }

        holdsNextStore = false
        await withCheckedContinuation { continuation in
            heldStore = continuation
            for waiter in heldStoreWaiters {
                waiter.resume()
            }
            heldStoreWaiters = []
        }
    }

    /// What breaks the request contract in the calls so far: a store for a request without a lookup or after its end, a
    /// request ended twice or without a lookup, and requests never ended.
    func requestContractViolations() -> [String] {
        var open = Set<SMB.CacheRequestID>()
        var ended = Set<SMB.CacheRequestID>()
        var violations: [String] = []

        for (index, call) in requestCalls.enumerated() {
            switch call {
            case let .lookup(request), let .begin(request):
                if open.contains(request) || ended.contains(request) {
                    violations.append("call \(index): a second lookup for one request")
                }
                open.insert(request)

            case let .store(request?):
                if !open.contains(request) {
                    violations.append("call \(index): a store outside its request")
                }

            case .store(nil):
                break

            case let .end(request):
                if !open.contains(request) {
                    violations.append("call \(index): an end without an open request")
                }
                open.remove(request)
                ended.insert(request)
            }
        }

        if !open.isEmpty {
            violations.append("\(open.count) requests never ended")
        }
        return violations
    }

    // MARK: SMB.BlockLevelReadCache

    func storeBlock(
        _ data: Data,
        path: String,
        offset: UInt64,
        source: SMB.CacheBlockSource,
        request: SMB.CacheRequestID?
    ) async {
        await holdIfAsked()
        events.append(.storeBlock(path: path, offset: offset, data: data, source: source))
        requestCalls.append(.store(request))
    }

    func retrieveBlock(path: String, offset: UInt64, upTo: Int, request: SMB.CacheRequestID) -> Data? {
        events.append(.retrieveBlock(path: path, offset: offset, upTo: upTo))
        requestCalls.append(.lookup(request))
        guard let block = blocks[path], block.offset == offset else {
            return nil
        }
        return block.data
    }

    func storeStat(_ result: SMB.Stat?, path: String, request: SMB.CacheRequestID) async {
        await holdIfAsked()
        events.append(.storeStat(path: path, size: result?.size))
        requestCalls.append(.store(request))
    }

    func storeDirectoryListing(_ entries: [SMB.DirectoryEntry], path: String, request: SMB.CacheRequestID) {
        events.append(.storeDirectoryListing(path: path, names: Set(entries.map(\.name))))
        requestCalls.append(.store(request))
    }

    func retrieveStat(path: String, request: SMB.CacheRequestID) -> SMB.CachedStat? {
        events.append(.retrieveStat(path: path))
        requestCalls.append(.lookup(request))
        return stats[path]
    }

    func retrieveDirectoryListing(path: String, request: SMB.CacheRequestID) -> [SMB.DirectoryEntry]? {
        events.append(.retrieveDirectoryListing(path: path))
        requestCalls.append(.lookup(request))
        return listings[path]
    }

    func beginRequest(_ request: SMB.CacheRequestID) {
        requestCalls.append(.begin(request))
    }

    func requestEnded(_ request: SMB.CacheRequestID) {
        requestCalls.append(.end(request))
    }

    func didRename(from: String, to: String) {
        events.append(.didRename(from: from, to: to))
    }

    func didAppend(path: String, byteCount: UInt64) {
        events.append(.didAppend(path: path, byteCount: byteCount))
    }

    func invalidate(path: String) {
        events.append(.invalidate(path: path))
    }
}

// MARK: - Helpers

/// Bytes whose value depends on their position, so a misplaced block is told apart from the right one.
func cachePayload(byteCount: Int) -> Data {
    Data((0 ..< byteCount).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ ($0 >> 8)) })
}

/// Connects to the public test share.
func connectForCacheTests() async throws -> SMB.Connection {
    try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
}

/// Runs `body` with a connection to the public share and a new directory in it, then removes the directory through a
/// connection that uses no cache. `body` may disconnect or detach the connection it is given.
func withCacheTestDirectory(_ body: (SMB.Connection, String) async throws -> Void) async throws {
    let connection = try await connectForCacheTests()
    let directory = uniquePath("cache")
    try await connection.makeDirectory(at: directory)

    let result: Result<Void, any Error>
    do {
        try await body(connection, directory)
        result = .success(())
    }
    catch {
        result = .failure(error)
    }

    try? await connection.disconnect()
    let cleanup = try await connectForCacheTests()
    try? await cleanup.removeItem(at: directory)
    try? await cleanup.disconnect()
    try result.get()
}

/// Creates a file holding `contents`. Call it before attaching a cache, or the cache records the write.
func makeRemoteFile(_ connection: SMB.Connection, path: String, contents: Data) async throws {
    try await connection.dumpToFile(contents, to: path)
}

/// The events recorded after the first one matching `isMarker`.
func eventsAfter(
    _ isMarker: (RecordingCache.Event) -> Bool,
    in events: [RecordingCache.Event]
) -> [RecordingCache.Event] {
    guard let index = events.firstIndex(where: isMarker) else {
        return []
    }
    return Array(events[(index + 1)...])
}

extension Result where Failure == any Error {
    /// The outcome of `body`.
    init(awaiting body: () async throws -> Success) async {
        do {
            self = try await .success(body())
        }
        catch {
            self = .failure(error)
        }
    }

    var succeeded: Bool {
        if case .success = self {
            return true
        }
        return false
    }
}
