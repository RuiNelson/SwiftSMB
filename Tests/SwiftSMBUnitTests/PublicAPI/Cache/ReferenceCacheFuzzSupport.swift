//
// Part of SwiftSMB
// ReferenceCacheFuzzSupport.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import SMB2
import Testing

// MARK: Deterministic randomness

/// SplitMix64: one seed gives one sequence, on every run, so a failing randomized test can be run again.
struct SeededGenerator: RandomNumberGenerator {
    private var state: UInt64

    /// Seeds start far apart in the generator's one sequence, so that the runs of two seeds share nothing: started side
    /// by side, one would be the other a few values late.
    init(seed: UInt64) {
        state = seed
        state = next()
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }

    /// A value in `range`.
    mutating func int(_ range: ClosedRange<Int>) -> Int {
        Int.random(in: range, using: &self)
    }

    /// `true` with the given probability.
    mutating func chance(_ probability: Double) -> Bool {
        Double.random(in: 0 ..< 1, using: &self) < probability
    }

    /// One of `items`, which must not be empty.
    mutating func pick<T>(_ items: [T]) -> T {
        items[int(0 ... items.count - 1)]
    }

    /// `count` random bytes.
    mutating func bytes(_ count: Int) -> Data {
        Data((0 ..< count).map { _ in UInt8(truncatingIfNeeded: next()) })
    }
}

// MARK: Shared helpers

/// Helpers shared by the unit, randomized, and edge-case tests of ``SMB/ReferenceCache``.
enum CacheFuzz {
    /// The seeds a randomized test runs with: `count` of them, counting up from zero.
    ///
    /// `SWIFTSMB_CACHE_FUZZ_SEED` runs that one seed only, to reproduce a failure. `SWIFTSMB_CACHE_FUZZ_SCALE`
    /// multiplies
    /// `count`, for a longer soak.
    static func seeds(_ count: Int) -> [UInt64] {
        let environment = ProcessInfo.processInfo.environment
        if let only = environment["SWIFTSMB_CACHE_FUZZ_SEED"].flatMap(UInt64.init) {
            return [only]
        }

        let scale = environment["SWIFTSMB_CACHE_FUZZ_SCALE"].flatMap(Int.init) ?? 1
        return (0 ..< UInt64(count * max(scale, 1))).map(\.self)
    }

    /// How many of the last steps a failing randomized test reports: `SWIFTSMB_CACHE_FUZZ_LOG_LINES`, 30 by default.
    static var logLines: Int {
        ProcessInfo.processInfo.environment["SWIFTSMB_CACHE_FUZZ_LOG_LINES"].flatMap(Int.init) ?? 30
    }

    /// Runs `body` once per seed, in parallel, and fails with the first seed that reports something wrong, naming the
    /// others.
    ///
    /// - Parameter body: Returns what went wrong for a seed, or `nil`.
    static func forEachSeed(
        _ seeds: [UInt64],
        sourceLocation: SourceLocation = #_sourceLocation,
        _ body: @escaping @Sendable (UInt64) async -> String?
    ) async {
        var failures: [(seed: UInt64, failure: String)] = []

        await withTaskGroup(of: (UInt64, String?).self) { group in
            for seed in seeds {
                group.addTask {
                    await (seed, body(seed))
                }
            }

            for await (seed, failure) in group {
                if let failure {
                    failures.append((seed, failure))
                }
            }
        }

        failures.sort { $0.seed < $1.seed }
        if let first = failures.first {
            Issue.record(
                """
                \(failures.count) of \(seeds.count) seeds failed: \(failures.map(\.seed)). The first:
                \(first.failure)
                """,
                sourceLocation: sourceLocation
            )
        }
    }

    // MARK: Values

    /// A stat as the server reports it.
    static func stat(
        type: Int32,
        size: UInt64,
        modificationTime: UInt64,
        changeTime: UInt64?,
        attributes: SMB.FileAttributes = [],
        accessTime: UInt64 = 99,
        birthTime: UInt64 = 1
    ) -> SMB.Stat {
        var raw = smb2_stat_64()
        raw.smb2_type = UInt32(type)
        raw.smb2_size = size
        raw.smb2_mtime = modificationTime
        raw.smb2_mtime_nsec = 500
        raw.smb2_ctime = changeTime ?? modificationTime
        raw.smb2_ctime_nsec = 700
        raw.smb2_atime = accessTime
        raw.smb2_btime = birthTime
        raw.smb2_nlink = 1
        raw.smb2_attributes = attributes.rawValue
        return SMB.Stat(Bridge.Stat(raw))
    }

    /// A stat of a regular file.
    static func file(
        size: UInt64,
        modificationTime: UInt64 = 1000,
        changeTime: UInt64? = nil,
        accessTime: UInt64 = 99,
        birthTime: UInt64 = 1
    ) -> SMB.Stat {
        stat(
            type: SMB2_TYPE_FILE,
            size: size,
            modificationTime: modificationTime,
            changeTime: changeTime,
            accessTime: accessTime,
            birthTime: birthTime
        )
    }

    /// A stat of a directory.
    static func directory(modificationTime: UInt64 = 1000) -> SMB.Stat {
        stat(
            type: SMB2_TYPE_DIRECTORY,
            size: 0,
            modificationTime: modificationTime,
            changeTime: nil,
            attributes: .directory
        )
    }

    /// A stat of a symbolic link, as a listing reports it.
    static func link(modificationTime: UInt64 = 1000) -> SMB.Stat {
        stat(
            type: SMB2_TYPE_LINK,
            size: 7,
            modificationTime: modificationTime,
            changeTime: nil,
            attributes: .reparsePoint
        )
    }

    /// A directory entry named `name`.
    static func entry(_ name: String, _ stat: SMB.Stat) -> SMB.DirectoryEntry {
        var raw = smb2dirent()
        raw.st.smb2_type = stat.type == .file ? UInt32(SMB2_TYPE_FILE)
            : stat.type == .directory ? UInt32(SMB2_TYPE_DIRECTORY) : UInt32(SMB2_TYPE_LINK)
        raw.st.smb2_size = stat.size
        raw.st.smb2_mtime = stat.modificationTimeSeconds
        raw.st.smb2_mtime_nsec = stat.modificationTimeNanoseconds
        raw.st.smb2_ctime = stat.changeTimeSeconds
        raw.st.smb2_ctime_nsec = stat.changeTimeNanoseconds
        raw.st.smb2_atime = stat.accessTimeSeconds
        raw.st.smb2_btime = stat.birthTimeSeconds
        raw.st.smb2_nlink = stat.linkCount
        raw.st.smb2_attributes = stat.attributes.rawValue
        return name.withCString { pointer in
            raw.name = pointer
            return SMB.DirectoryEntry(Bridge.DirectoryEntry(raw))
        }
    }

    /// `count` bytes counting up from `first`, so bytes from different places never match.
    static func bytes(_ count: Int, from first: Int = 0) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: first + $0) })
    }

    // MARK: Calls, the way the connection makes them

    /// Hands the cache a stat the way the connection does when the cache does not answer: a lookup, the store, and the
    /// end of the request.
    static func stat(_ cache: any SMB.BlockLevelReadCache, _ result: SMB.Stat?, path: String) async {
        let request = SMB.CacheRequestID()
        _ = await cache.retrieveStat(path: path, request: request)
        await cache.storeStat(result, path: path, request: request)
        await cache.requestEnded(request)
    }

    /// Hands the cache a listing the way the connection does when the cache does not answer.
    static func list(_ cache: any SMB.BlockLevelReadCache, _ entries: [SMB.DirectoryEntry], path: String) async {
        let request = SMB.CacheRequestID()
        _ = await cache.retrieveDirectoryListing(path: path, request: request)
        await cache.storeDirectoryListing(entries, path: path, request: request)
        await cache.requestEnded(request)
    }

    /// Hands the cache downloaded bytes the way the connection does: a lookup that does not cover them, the store, and
    /// the end of the request.
    static func download(_ cache: any SMB.BlockLevelReadCache, _ data: Data, path: String, offset: UInt64 = 0) async {
        let request = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: offset, upTo: .max, request: request)
        await cache.storeBlock(data, path: path, offset: offset, source: .download, request: request)
        await cache.requestEnded(request)
    }

    /// Hands the cache bytes written through the connection.
    static func upload(_ cache: any SMB.BlockLevelReadCache, _ data: Data, path: String, offset: UInt64 = 0) async {
        await cache.storeBlock(data, path: path, offset: offset, source: .upload, request: nil)
    }

    /// Asks the cache for bytes, ending the request at once.
    static func retrieve(
        _ cache: any SMB.BlockLevelReadCache,
        path: String,
        offset: UInt64 = 0,
        upTo: Int
    ) async -> Data? {
        let request = SMB.CacheRequestID()
        let data = await cache.retrieveBlock(path: path, offset: offset, upTo: upTo, request: request)
        await cache.requestEnded(request)
        return data
    }

    /// Asks the cache for a stat, ending the request at once.
    static func cachedStat(_ cache: any SMB.BlockLevelReadCache, path: String) async -> SMB.CachedStat? {
        let request = SMB.CacheRequestID()
        let answer = await cache.retrieveStat(path: path, request: request)
        await cache.requestEnded(request)
        return answer
    }

    /// Asks the cache for a listing, ending the request at once.
    static func cachedListing(_ cache: any SMB.BlockLevelReadCache, path: String) async -> [SMB.DirectoryEntry]? {
        let request = SMB.CacheRequestID()
        let answer = await cache.retrieveDirectoryListing(path: path, request: request)
        await cache.requestEnded(request)
        return answer
    }

    /// Has the cache learn that `path` is a regular file holding `contents`, then hands it those bytes as if
    /// downloaded.
    static func cacheFile(
        _ cache: any SMB.BlockLevelReadCache,
        path: String,
        contents: Data,
        modificationTime: UInt64 = 1000
    ) async {
        await stat(cache, file(size: UInt64(contents.count), modificationTime: modificationTime), path: path)
        await download(cache, contents, path: path)
    }

    /// A cache without a control connection.
    static func makeCache(
        byteBudget: Int = 1024 * 1024,
        maximumFileSize: UInt64? = nil,
        keepsUploads: Bool = true,
        metadata: SMB.ReferenceCache.MetadataPolicy = .neverAnswer,
        pathMatching: SMB.ReferenceCache.PathMatching = .exact
    ) -> SMB.ReferenceCache {
        SMB.ReferenceCache(
            storage: SMB.InMemoryCacheStorage(byteBudget: byteBudget, maximumFileSize: maximumFileSize),
            configuration: .init(keepsUploads: keepsUploads, metadata: metadata, pathMatching: pathMatching)
        )
    }

    /// A cache whose trust policy needs a control connection it does not have, as one whose connection is lost.
    static func uncheckableCache(
        _ policy: SMB.ReferenceCache.TrustPolicy,
        revalidationInterval: TimeInterval?
    ) -> SMB.ReferenceCache {
        SMB.ReferenceCache(
            checkedConfiguration: .init(trustPolicy: policy, revalidationInterval: revalidationInterval),
            storage: SMB.InMemoryCacheStorage(),
            control: nil
        )
    }
}

// MARK: Invariants

extension FileBlocks {
    /// What is wrong with the runs, whatever was stored before: nothing, unless there is a bug.
    func invariantViolations() -> [String] {
        var violations: [String] = []
        var total = 0
        var previousEnd: UInt64?

        for segment in segments {
            total += segment.bytes.count
            if segment.bytes.isEmpty {
                violations.append("an empty run at \(segment.start)")
            }
            if segment.bytes.startIndex != 0 {
                violations.append("the run at \(segment.start) is indexed from \(segment.bytes.startIndex), not zero")
            }
            if let previousEnd, segment.start <= previousEnd {
                violations.append("the run at \(segment.start) overlaps or touches the one ending at \(previousEnd)")
            }
            previousEnd = segment.end
        }

        if total != byteCount {
            violations.append("byteCount is \(byteCount), the runs hold \(total)")
        }

        return violations
    }
}

extension SMB.ReferenceCache {
    /// Hands over a stat, as the connection does: under `request`, or, for `nil`, as the stat of an open file, under a
    /// request of its own that begins just before.
    func storeStat(_ result: SMB.Stat?, path: String, request: SMB.CacheRequestID?) async {
        if let request {
            await storeStat(result, path: path, request: request)
            return
        }

        let own = SMB.CacheRequestID()
        await beginRequest(own)
        await storeStat(result, path: path, request: own)
        await requestEnded(own)
    }

    /// What is wrong with the cache's state between two calls, whatever was called before: nothing, unless there is a
    /// bug.
    func invariantViolations() -> [String] {
        var violations: [String] = []
        var identifiers = Set<SMB.CacheFileID>()

        for (key, entry) in files {
            let ranges = storage.ranges(of: entry.id)
            if let blocks = memoryStorage.blocks(of: entry.id) {
                violations += blocks.invariantViolations().map { "\(key): \($0)" }
            }

            if !identifiers.insert(entry.id).inserted {
                violations.append("\(key): entry id \(entry.id) is used twice")
            }
            if let size = entry.knownSize, let last = ranges.last, last.upperBound > size {
                violations.append("\(key): holds bytes up to \(last.upperBound), past the known size \(size)")
            }
            if entry.isTooLarge, !ranges.isEmpty {
                violations.append("\(key): holds bytes though the storage could not hold the file")
            }
            if entry.lastUsed > tick {
                violations.append("\(key): last used at \(entry.lastUsed), after the clock \(tick)")
            }
            if !configuration.keepsUploads, !entry.uploaded.isEmpty {
                violations.append("\(key): tracks written ranges though uploads are not kept")
            }
            var previousUpper: UInt64?
            for range in entry.uploaded {
                if range.isEmpty || previousUpper.map({ range.lowerBound <= $0 }) == true {
                    violations.append("\(key): the written ranges \(entry.uploaded) are not sorted and merged")
                    break
                }
                previousUpper = range.upperBound
            }

            // The entry is filed where its path says.
            let location = locate(normalized: entry.path)
            if !CachePath.sameBytes(location.key, key) {
                violations.append("\(key): filed under another key than its path \(entry.path) has")
            }
            if !CachePath.sameBytes(CachePath.normalize(entry.path), entry.path) {
                violations.append("\(key): the path \(entry.path) is not normalized")
            }
            if entry.equivalenceKey != location.equivalenceKey {
                violations.append("\(key): equivalence key \(entry.equivalenceKey), its path has another")
            }
            if fileTree.items(at: key) != [key] {
                violations.append("\(key): the file tree holds \(fileTree.items(at: key)) at the key")
            }
            if !equivalents.items(at: entry.equivalenceKey).contains(key) {
                violations.append("\(key): not filed under its equivalence key")
            }
        }

        let filed = fileTree.items(atOrUnder: CachePath.root)
        if filed.count != files.count || Set(filed) != Set(files.keys) {
            violations.append("the file tree holds \(filed.count) keys, \(files.count) files are tracked")
        }
        let equivalent = equivalents.items(atOrUnder: CachePath.root)
        if equivalent.count != files.count || Set(equivalent) != Set(files.keys) {
            violations.append("the equivalence index holds \(equivalent.count) keys, \(files.count) files are tracked")
        }

        let orphans = memoryStorage.storedFiles.subtracting(identifiers)
        if !orphans.isEmpty {
            violations.append("the storage holds bytes of \(orphans.count) files the cache no longer tracks")
        }
        violations += memoryStorage.invariantViolations()
        if files.count > Self.entryLimit {
            violations.append("\(files.count) files tracked, over the limit")
        }
        if stats.count > Self.metadataLimit || listings.count > Self.metadataLimit {
            violations.append("\(stats.count) stats and \(listings.count) listings stored, over the limit")
        }
        if requests.count > RequestLog.limit {
            violations.append("\(requests.count) requests remembered, over the limit")
        }
        if case .neverAnswer = configuration.metadata, !stats.isEmpty || !listings.isEmpty {
            violations.append("stats or listings stored though the cache never answers them")
        }

        return violations
    }

    /// Tracks `count` files under `directory`, each from a stat of its own, without leaving the actor in between.
    func trackFiles(under directory: String, count: Int, size: UInt64 = 10) async {
        for index in 0 ..< count {
            await storeStat(CacheFuzz.file(size: size), path: "\(directory)/file\(index)", request: nil)
        }
    }

    /// The size the cache believes the file at `path` has.
    func knownSize(path: String) -> UInt64? {
        files[locate(path).key]?.knownSize
    }

    /// The paths of the tracked files, sorted.
    var trackedPaths: [String] {
        files.values.map(\.path).sorted()
    }

    /// The cached bytes of the file at the key `key`, by position.
    func cachedBytes(key: String) -> [UInt64: UInt8] {
        var result: [UInt64: UInt8] = [:]
        for segment in files[key].flatMap({ memoryStorage.blocks(of: $0.id) })?.segments ?? [] {
            for (index, byte) in segment.bytes.enumerated() {
                result[segment.start + UInt64(index)] = byte
            }
        }
        return result
    }

    /// The cache's storage, which the tests make in memory.
    var memoryStorage: SMB.InMemoryCacheStorage {
        storage as! SMB.InMemoryCacheStorage
    }

    /// Bytes the cache's storage holds.
    var storedByteCount: Int {
        memoryStorage.byteCount
    }

    /// Relieves memory pressure the way the system's warnings do: the storage drops bytes, and the cache drops its
    /// stats and listings when memory is critical.
    func relieveMemoryPressure(critical: Bool) {
        memoryStorage.relieveMemoryPressure(critical: critical)
        if critical {
            relieveMemoryPressure()
        }
    }
}

extension SMB.InMemoryCacheStorage {
    /// What is wrong with the storage's bookkeeping: nothing, unless there is a bug.
    func invariantViolations() -> [String] {
        var violations: [String] = []
        var held = 0
        for file in storedFiles {
            guard let blocks = blocks(of: file) else {
                continue
            }
            held += blocks.byteCount
            if blocks.isEmpty {
                violations.append("the storage keeps \(file) without bytes")
            }
            violations += blocks.invariantViolations()
        }
        if held != byteCount {
            violations.append("the storage counts \(byteCount) bytes, its files hold \(held)")
        }
        if byteCount > byteBudget {
            violations.append("\(byteCount) bytes stored, over the budget of \(byteBudget)")
        }
        return violations
    }
}
