//
// Part of SwiftSMB
// InMemoryCacheStorage.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// A ``SMB/CacheStorage`` that keeps file contents in memory, up to a byte budget.
    ///
    /// To stay within ``byteBudget``, the storage drops whole files, least recently used first, so a stored file never
    /// has holes that would break up sequential reads. A file that alone would go over the budget is not kept. On Apple
    /// platforms it also drops files when the system runs short of memory: down to half the budget on a warning, and
    /// everything when memory is critical.
    ///
    /// Several caches can share one storage, and one budget with it:
    ///
    /// ```swift
    /// let storage = SMB.InMemoryCacheStorage(byteBudget: 128 * 1024 * 1024)
    /// photos.attachCache(SMB.ReferenceCache(storage: storage, configuration: .init()))
    /// videos.attachCache(SMB.ReferenceCache(storage: storage, configuration: .init()))
    /// ```
    final class InMemoryCacheStorage: CacheStorage, Sendable {
        /// Most bytes of file contents kept, across all files. `0` keeps nothing.
        public let byteBudget: Int

        /// Size above which a file is not kept, or `nil` for no limit other than ``byteBudget``.
        ///
        /// The cache learns sizes from stats and directory listings, so a file whose size it has not seen yet is kept
        /// until it does.
        public let maximumFileSize: UInt64?

        private let state = Protected(State(), label: "com.ruinelson.SwiftSMB.SMB.InMemoryCacheStorage.state")

        #if canImport(Darwin)
            private let memoryPressureObserver = MemoryPressureObserver()
        #endif

        /// Creates an empty storage.
        ///
        /// - Parameters:
        ///   - byteBudget: Most bytes of file contents kept, across all files. 256 MiB by default. Must not be
        /// negative.
        ///   - maximumFileSize: Size above which a file is not kept; no limit by default.
        public init(byteBudget: Int = 256 * 1024 * 1024, maximumFileSize: UInt64? = nil) {
            precondition(byteBudget >= 0, "byteBudget must not be negative")
            self.byteBudget = byteBudget
            self.maximumFileSize = maximumFileSize

            #if canImport(Darwin)
                memoryPressureObserver.start { [weak self] critical in
                    self?.relieveMemoryPressure(critical: critical)
                }
            #endif
        }

        /// Bytes held across all files.
        public var byteCount: Int {
            state.withLock { $0.byteCount }
        }

        // MARK: CacheStorage

        /// Accepts files no larger than ``maximumFileSize`` and ``byteBudget``.
        public func accepts(fileSize: UInt64) -> Bool {
            fileSize <= min(maximumFileSize ?? .max, UInt64(byteBudget))
        }

        /// Stores the bytes, then drops the least recently used other files until the bytes held fit the budget.
        ///
        /// Drops `file` instead, and returns `false`, when its bytes alone go over the budget.
        @discardableResult
        public func write(_ data: Data, at offset: UInt64, of file: CacheFileID) -> Bool {
            guard !data.isEmpty else {
                return true
            }

            let budget = byteBudget
            return state.withLock { state in
                state.tick += 1
                let tick = state.tick
                let fileByteCount = state.update(file, creating: true) { stored in
                    stored.blocks.write(data, at: offset)
                    stored.lastUsed = tick
                    return stored.blocks.byteCount
                } ?? 0

                guard fileByteCount <= budget else {
                    state.take(file)
                    return false
                }

                state.evict(downTo: budget, protecting: file)
                return true
            }
        }

        /// The stored run of `file` at `offset`, counting as a use of the file.
        public func read(_ file: CacheFileID, at offset: UInt64, upTo: Int) -> Data? {
            state.withLock { state in
                guard let run = state.files[file]?.blocks.run(at: offset, upTo: upTo) else {
                    return nil
                }
                state.tick += 1
                state.files[file]?.lastUsed = state.tick
                return run
            }
        }

        public func ranges(of file: CacheFileID) -> [Range<UInt64>] {
            state.withLock { state in
                state.files[file]?.blocks.ranges ?? []
            }
        }

        public func retain(_ ranges: [Range<UInt64>], of file: CacheFileID) {
            state.withLock { state in
                state.update(file, creating: false) { stored in
                    stored.blocks.retain(ranges)
                }
                if state.files[file]?.blocks.isEmpty == true {
                    state.take(file)
                }
            }
        }

        public func remove(_ file: CacheFileID) {
            state.withLock { state in
                state.take(file)
            }
        }

        // MARK: Internal

        /// Drops files to make room for the system: down to half the budget on a warning, and every file when memory is
        /// critical.
        func relieveMemoryPressure(critical: Bool) {
            let target = critical ? 0 : byteBudget / 2
            state.withLock { state in
                state.evict(downTo: target, protecting: nil)
            }
        }

        /// The stored bytes of `file`, for inspection.
        func blocks(of file: CacheFileID) -> FileBlocks? {
            state.withLock { state in
                state.files[file]?.blocks
            }
        }

        /// The files stored, for inspection.
        var storedFiles: Set<CacheFileID> {
            state.withLock { state in
                Set(state.files.keys)
            }
        }
    }
}

// MARK: State

extension SMB.InMemoryCacheStorage {
    /// One stored file: its bytes, and its last use for least-recently-used eviction.
    struct StoredFile {
        var blocks: FileBlocks
        var lastUsed: UInt64
    }

    /// Everything the storage holds, behind its lock.
    struct State {
        /// Stored files.
        var files: [SMB.CacheFileID: StoredFile] = [:]

        /// Bytes held across all files.
        var byteCount = 0

        /// Counts uses, for least-recently-used eviction.
        var tick: UInt64 = 0

        /// Mutates the stored file in place, keeping ``byteCount`` in step. The file leaves the dictionary meanwhile,
        /// so changing its bytes never copies them.
        @discardableResult
        mutating func update<Result>(
            _ file: SMB.CacheFileID,
            creating: Bool,
            _ body: (inout StoredFile) -> Result
        ) -> Result? {
            var stored: StoredFile
            if let existing = files.removeValue(forKey: file) {
                stored = existing
            }
            else if creating {
                stored = StoredFile(blocks: FileBlocks(), lastUsed: tick)
            }
            else {
                return nil
            }

            byteCount -= stored.blocks.byteCount
            let result = body(&stored)
            byteCount += stored.blocks.byteCount
            files[file] = stored
            return result
        }

        mutating func take(_ file: SMB.CacheFileID) {
            if let stored = files.removeValue(forKey: file) {
                byteCount -= stored.blocks.byteCount
            }
        }

        /// Drops the least recently used files, other than `protected`, until at most `target` bytes remain.
        mutating func evict(downTo target: Int, protecting protected: SMB.CacheFileID?) {
            guard byteCount > target else {
                return
            }

            let candidates = files
                .compactMap { file, stored in file != protected ? (file, stored.lastUsed) : nil }
                .sorted { $0.1 < $1.1 }
            for (file, _) in candidates {
                guard byteCount > target else {
                    break
                }
                take(file)
            }
        }
    }
}
