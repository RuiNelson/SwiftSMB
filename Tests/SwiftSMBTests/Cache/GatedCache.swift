//
// Part of SwiftSMB
// GatedCache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: Gated cache

/// An ``SMB/ReferenceCache`` behind a door: every call goes through to it unchanged, except that a test can hold a
/// chosen call at the door for a while, the way a cache busy with other calls keeps one waiting.
///
/// The connection makes its calls from the tasks its operations run on, so the order in which two of them reach the
/// cache is not the order in which the server answered them. Holding one call while others go through makes such an
/// order happen on purpose.
final class GatedCache: SMB.BlockLevelReadCache, @unchecked Sendable {
    /// The calls a gate can hold.
    enum Call: Sendable, Hashable {
        case storeDownload
        case storeUpload
        case retrieveBlock
        case storeStat
        case storeDirectoryListing
        case retrieveStat
        case retrieveDirectoryListing
        case didRename
        case didAppend
        case invalidate
    }

    /// A call did not reach its gate in time.
    struct NeverReached: Error {
    }

    /// Holds one call until it is opened.
    final class Gate: @unchecked Sendable {
        private let lock = NSLock()
        private var isOpen = false
        private var isReached = false
        private var held: [CheckedContinuation<Void, Never>] = []

        /// Keeps the calling cache call waiting until the gate opens.
        fileprivate func pass() async {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow = lock.withLock { () -> Bool in
                    isReached = true
                    if !isOpen {
                        held.append(continuation)
                    }
                    return isOpen
                }

                if resumeNow {
                    continuation.resume()
                }
            }
        }

        /// Whether a call reached the gate.
        var reached: Bool {
            lock.withLock { isReached }
        }

        /// Waits until a call is held at the gate.
        ///
        /// - Throws: ``NeverReached`` when none arrives within `timeout` seconds, so a test waiting for a call that is
        /// never made fails instead of hanging.
        func waitUntilReached(timeout: TimeInterval = 20) async throws {
            let deadline = Date().addingTimeInterval(timeout)
            while !reached {
                guard Date() < deadline else {
                    throw NeverReached()
                }
                try await Task.sleep(nanoseconds: 2_000_000)
            }
        }

        /// Lets the held call through, and every later one.
        func open() {
            let held = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
                isOpen = true
                let held = self.held
                self.held = []
                return held
            }

            for continuation in held {
                continuation.resume()
            }
        }
    }

    let inner: SMB.ReferenceCache

    private let lock = NSLock()
    private var gates: [(call: Call, path: String?, after: Bool, gate: Gate)] = []
    private var everyGate: [Gate] = []
    private var answeredReads = 0

    init(_ inner: SMB.ReferenceCache) {
        self.inner = inner
    }

    /// Holds the next `call`, about `path` when given (compared byte by byte), until the returned gate opens. Other
    /// calls go on meanwhile.
    ///
    /// - Parameter after: Whether to hold the call once the cache has taken it in, on its way back to the connection,
    /// as when the calling task is not scheduled again at once, rather than on its way in.
    func hold(_ call: Call, path: String? = nil, after: Bool = false) -> Gate {
        let gate = Gate()
        lock.withLock {
            gates.append((call, path, after, gate))
            everyGate.append(gate)
        }
        return gate
    }

    /// Opens every gate, held or not, so that nothing stays waiting when a test ends early.
    func openAll() {
        let all = lock.withLock { () -> [Gate] in
            gates = []
            return everyGate
        }
        for gate in all {
            gate.open()
        }
    }

    /// How many reads the cache answered with bytes: a test whose cache never answers checks nothing.
    var hits: Int {
        lock.withLock { answeredReads }
    }

    /// Waits at the first gate set for `call` and `path` on this side of the cache, if any, and uses it up.
    private func pass(_ call: Call, _ path: String, after: Bool = false) async {
        let gate = lock.withLock { () -> Gate? in
            let index = gates.firstIndex { gate in
                gate.call == call && gate.after == after
                    && (gate.path.map { $0.utf8.elementsEqual(path.utf8) } ?? true)
            }
            return index.map { gates.remove(at: $0).gate }
        }

        await gate?.pass()
    }

    // MARK: BlockLevelReadCache

    func storeBlock(
        _ data: Data,
        path: String,
        offset: UInt64,
        source: SMB.CacheBlockSource,
        request: SMB.CacheRequestID?
    ) async {
        let call: Call = source == .download ? .storeDownload : .storeUpload
        await pass(call, path)
        await inner.storeBlock(data, path: path, offset: offset, source: source, request: request)
        await pass(call, path, after: true)
    }

    func retrieveBlock(path: String, offset: UInt64, upTo: Int, request: SMB.CacheRequestID) async -> Data? {
        await pass(.retrieveBlock, path)
        let answer = await inner.retrieveBlock(path: path, offset: offset, upTo: upTo, request: request)
        if answer != nil {
            lock.withLock { answeredReads += 1 }
        }
        await pass(.retrieveBlock, path, after: true)
        return answer
    }

    func storeStat(_ result: SMB.Stat?, path: String, request: SMB.CacheRequestID) async {
        await pass(.storeStat, path)
        await inner.storeStat(result, path: path, request: request)
        await pass(.storeStat, path, after: true)
    }

    func storeDirectoryListing(_ entries: [SMB.DirectoryEntry], path: String, request: SMB.CacheRequestID) async {
        await pass(.storeDirectoryListing, path)
        await inner.storeDirectoryListing(entries, path: path, request: request)
        await pass(.storeDirectoryListing, path, after: true)
    }

    func retrieveStat(path: String, request: SMB.CacheRequestID) async -> SMB.CachedStat? {
        await pass(.retrieveStat, path)
        let answer = await inner.retrieveStat(path: path, request: request)
        await pass(.retrieveStat, path, after: true)
        return answer
    }

    func retrieveDirectoryListing(path: String, request: SMB.CacheRequestID) async -> [SMB.DirectoryEntry]? {
        await pass(.retrieveDirectoryListing, path)
        let answer = await inner.retrieveDirectoryListing(path: path, request: request)
        await pass(.retrieveDirectoryListing, path, after: true)
        return answer
    }

    func beginRequest(_ request: SMB.CacheRequestID) async {
        await inner.beginRequest(request)
    }

    func requestEnded(_ request: SMB.CacheRequestID) async {
        await inner.requestEnded(request)
    }

    func didRename(from: String, to: String) async {
        await pass(.didRename, from)
        await inner.didRename(from: from, to: to)
        await pass(.didRename, from, after: true)
    }

    func didAppend(path: String, byteCount: UInt64) async {
        await pass(.didAppend, path)
        await inner.didAppend(path: path, byteCount: byteCount)
        await pass(.didAppend, path, after: true)
    }

    func invalidate(path: String) async {
        await pass(.invalidate, path)
        await inner.invalidate(path: path)
        await pass(.invalidate, path, after: true)
    }
}

// MARK: Connections around a reference cache

/// A connection with an ``SMB/ReferenceCache`` attached behind a ``GatedCache``, and the connections around it.
struct CachedConnections: Sendable {
    /// The connection the cache is attached to.
    let connection: SMB.Connection
    /// A fork made after attaching: it shares the cache, and the registry of the files open with it.
    let fork: SMB.Connection
    /// A connection that uses no cache: what it reads is what the server holds.
    let truth: SMB.Connection
    let cache: SMB.ReferenceCache
    let gated: GatedCache
    /// A directory of the test's own, which is removed afterwards.
    let directory: String
}

/// Runs `body` with a cache of `configuration`, storing up to `byteBudget` bytes, attached to a connection to the
/// public share, and closes everything afterwards. A configuration that checks against the server gets a control
/// connection forked before the cache is attached.
func withCachedConnections(
    _ configuration: SMB.ReferenceCache.Configuration = .init(),
    byteBudget: Int = 64 * 1024 * 1024,
    _ body: (CachedConnections) async throws -> Void
) async throws {
    let connection = try await connectForCacheTests()
    let truth = try await connection.fork()
    let directory = uniquePath("cache_race")
    try await truth.makeDirectory(at: directory)

    let storage = SMB.InMemoryCacheStorage(byteBudget: byteBudget)
    let control = configuration.needsControlConnection ? try await connection.fork() : nil
    let cache = if let control {
        SMB.ReferenceCache(storage: storage, controlConnection: control, configuration: configuration)
    }
    else {
        SMB.ReferenceCache(storage: storage, configuration: configuration)
    }
    let gated = GatedCache(cache)
    connection.attachCache(gated)

    let result: Result<Void, any Error>
    do {
        let fork = try await connection.fork()
        do {
            try await body(CachedConnections(
                connection: connection,
                fork: fork,
                truth: truth,
                cache: cache,
                gated: gated,
                directory: directory
            ))
            result = .success(())
        }
        catch {
            result = .failure(error)
        }
        gated.openAll()
        try? await fork.disconnect()
    }
    catch {
        result = .failure(error)
    }

    gated.openAll()
    try? await connection.disconnect()
    await cache.close()
    try? await control?.disconnect()
    try? await truth.removeItem(at: directory)
    try? await truth.disconnect()
    try result.get()
}

// MARK: File helpers

/// Creates or replaces the file at `path` with `contents`.
func writeRemote(_ connection: SMB.Connection, _ path: String, _ contents: Data) async throws {
    try await connection.dumpToFile(contents, to: path)
}

/// Reads the whole file at `path` through a handle of its own.
func readRemote(_ connection: SMB.Connection, _ path: String) async throws -> Data {
    try await connection.loadFile(at: path)
}

/// Reads up to `count` bytes at `offset` of the file at `path` through a handle of its own.
func readRemote(_ connection: SMB.Connection, _ path: String, at offset: UInt64, count: Int) async throws -> Data {
    let handle = try await connection.openFile(at: path)
    let data = await Result(awaiting: { try await handle.read(upTo: Int64(count), atOffset: offset) })
    try await handle.close()
    return try data.get()
}

/// Writes `bytes` at `offset` of the existing file at `path` through a handle of its own.
func overwriteRemote(_ connection: SMB.Connection, _ path: String, at offset: UInt64, with bytes: Data) async throws {
    let handle = try await connection.openFile(at: path, accessMode: .writeOnly)
    let written = await Result(awaiting: { try await handle.write(bytes, atOffset: offset) })
    try await handle.close()
    _ = try written.get()
}

/// `original` with `bytes` written over it at `offset`.
func overwritten(_ original: Data, at offset: Int, with bytes: Data) -> Data {
    var result = original
    result.replaceSubrange(offset ..< offset + bytes.count, with: bytes)
    return result
}
