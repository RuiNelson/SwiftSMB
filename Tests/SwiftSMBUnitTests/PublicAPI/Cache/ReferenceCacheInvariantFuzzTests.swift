//
// Part of SwiftSMB
// ReferenceCacheInvariantFuzzTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import SMB2
import Testing

/// Calls of every kind, in any order and with any arguments, including ones the connection never makes: whatever it is
/// told, the cache must keep its books straight and hand out only bytes it was given.
@Suite("ReferenceCache: any calls in any order")
struct ReferenceCacheInvariantFuzzTests {
    /// Paths as a connection sends them, and as it never would: unnormalized, above the share root, spelled in other
    /// cases, and two spellings of one accented name.
    static let paths = [
        "",
        "/",
        ".",
        "a",
        "A",
        "a/f",
        "a/F",
        "A/f",
        "a/g",
        "a/s",
        "a/s/f",
        "b",
        "b/f",
        "f",
        "../f",
        "..",
        "a//f",
        "/a/./f",
        "a/s/../f",
        "a/f/",
        #"a\f"#,
        "a/..",
        "caf\u{E9}/f",
        "cafe\u{301}/f",
        "CAF\u{C9}/f",
        "a/\u{1F600}",
        "100%/f",
    ]

    /// Names a listing could hold.
    static let names = ["f", "F", "g", "s", "caf\u{E9}", "cafe\u{301}", ".", "..", "", "x/y"]

    /// What a stat could say is at a path.
    static func stat(_ generator: inout SeededGenerator) -> SMB.Stat? {
        let sizes: [UInt64] = [0, 10, 50, 100, 5000]
        let size = generator.pick(sizes)
        let time = UInt64(1000 + generator.int(0 ... 2))

        switch generator.int(0 ... 9) {
        case 0 ..< 2:
            return nil

        case 2 ..< 7:
            return CacheFuzz.file(size: size, modificationTime: time, changeTime: UInt64(1000 + generator.int(0 ... 1)))

        case 7:
            return CacheFuzz.directory(modificationTime: time)

        case 8:
            return CacheFuzz.link(modificationTime: time)

        default:
            // A file that is a reparse point, as the server may report one it followed or did not.
            return CacheFuzz.stat(
                type: SMB2_TYPE_FILE,
                size: size,
                modificationTime: time,
                changeTime: nil,
                attributes: .reparsePoint
            )
        }
    }

    /// Makes 300 calls drawn from `seed`, and returns what went wrong, if anything did.
    static func fuzz(seed: UInt64) async -> String? {
        var generator = SeededGenerator(seed: seed)
        let budgets = [0, 1, 64, 500, 1 << 20]
        let fileSizes: [UInt64?] = [nil, nil, 0, 50, 1000]
        let policies: [SMB.ReferenceCache.MetadataPolicy] = [
            .neverAnswer,
            .answer(for: 3600, includingMissing: true),
            .answer(for: 3600, includingMissing: false),
            .answer(for: 0, includingMissing: true),
        ]
        let storage = SMB.InMemoryCacheStorage(
            byteBudget: generator.pick(budgets),
            maximumFileSize: generator.pick(fileSizes)
        )
        let configuration = SMB.ReferenceCache.Configuration(
            keepsUploads: generator.chance(0.7),
            metadata: generator.pick(policies),
            pathMatching: generator.chance(0.5) ? .exact : .caseInsensitive
        )
        let cache = SMB.ReferenceCache(storage: storage, configuration: configuration)

        var open: [SMB.CacheRequestID] = []
        var ended: [SMB.CacheRequestID] = []
        var calls: [String] = []

        // Every byte ever handed over, by key and position: the cache can answer with nothing else.
        var given: [String: [UInt64: Set<UInt8>]] = [:]

        func fail(_ step: Int, _ message: String) -> String {
            """
            seed \(seed) [\(configuration.debugDescription)], call \(step): \(message)
            last calls:
            \(calls.suffix(CacheFuzz.logLines).joined(separator: "\n"))
            """
        }

        /// A request for a store: mostly one whose lookup is open, sometimes one that ended, never looked up, or none.
        func request(_ generator: inout SeededGenerator) -> SMB.CacheRequestID? {
            switch generator.int(0 ... 9) {
            case 0 ..< 6:
                open.last ?? SMB.CacheRequestID()

            case 6 ..< 8:
                open.isEmpty ? nil : generator.pick(open)

            case 8:
                ended.isEmpty ? SMB.CacheRequestID() : generator.pick(ended)

            default:
                nil
            }
        }

        for step in 0 ..< 300 {
            let path = generator.pick(paths)
            let key = cache.locate(path).key
            let offset = UInt64(generator.pick([0, 0, 1, 10, 50, 100, 1000]))

            switch generator.int(0 ... 99) {
            case 0 ..< 18:
                let upTo = generator.pick([-5, 0, 1, 7, 64, 1000, .max])
                let lookup = SMB.CacheRequestID()
                open.append(lookup)
                let answer = await cache.retrieveBlock(path: path, offset: offset, upTo: upTo, request: lookup)
                calls
                    .append(
                        "retrieveBlock(\(path.debugDescription), \(offset), upTo: \(upTo)) -> \(answer?.count ?? -1)"
                    )

                if let answer {
                    guard !answer.isEmpty, answer.count <= upTo else {
                        return fail(step, "an answer of \(answer.count) bytes for a read of up to \(upTo)")
                    }
                    if let size = await cache.knownSize(path: path), offset + UInt64(answer.count) > size {
                        return fail(step, "an answer that runs past the file's known size of \(size)")
                    }

                    let known = given[key] ?? [:]
                    for (index, byte) in answer.enumerated()
                        where known[offset + UInt64(index)]?.contains(byte) != true {
                        return fail(step, "byte \(offset + UInt64(index)) of the answer was never handed to the cache")
                    }
                }

            case 18 ..< 44:
                let data = generator.bytes(generator.pick([0, 1, 5, 30, 80]))
                let isUpload = generator.chance(0.45)
                let stored = isUpload ? nil : request(&generator)
                for (index, byte) in data.enumerated() {
                    given[key, default: [:]][offset + UInt64(index), default: []].insert(byte)
                }

                await cache.storeBlock(
                    data,
                    path: path,
                    offset: offset,
                    source: isUpload ? .upload : .download,
                    request: stored
                )
                calls
                    .append(
                        "storeBlock(\(data.count) bytes, \(path.debugDescription), \(offset), \(isUpload ? "upload" : "download"))"
                    )

            case 44 ..< 58:
                let result = stat(&generator)
                await cache.storeStat(result, path: path, request: request(&generator))
                calls.append("storeStat(\(result.map(\.debugDescription) ?? "nothing"), \(path.debugDescription))")

            case 58 ..< 64:
                var entries: [SMB.DirectoryEntry] = []
                for _ in 0 ..< generator.int(0 ... 5) {
                    if let entry = stat(&generator) {
                        entries.append(CacheFuzz.entry(generator.pick(names), entry))
                    }
                }
                let listing = request(&generator) ?? SMB.CacheRequestID()
                await cache.storeDirectoryListing(entries, path: path, request: listing)
                calls.append("storeDirectoryListing(\(entries.map(\.name)), \(path.debugDescription))")

            case 64 ..< 72:
                let lookup = SMB.CacheRequestID()
                open.append(lookup)
                let answer = await cache.retrieveStat(path: path, request: lookup)
                calls.append("retrieveStat(\(path.debugDescription)) -> \(answer?.debugDescription ?? "nil")")
                if case .neverAnswer = configuration.metadata, answer != nil {
                    return fail(step, "a stat answered by a cache that never answers")
                }

            case 72 ..< 76:
                let lookup = SMB.CacheRequestID()
                open.append(lookup)
                let answer = await cache.retrieveDirectoryListing(path: path, request: lookup)
                calls.append("retrieveDirectoryListing(\(path.debugDescription)) -> \(answer?.count ?? -1)")
                if case .neverAnswer = configuration.metadata, answer != nil {
                    return fail(step, "a listing answered by a cache that never answers")
                }

            case 76 ..< 80:
                if !open.isEmpty {
                    let ending = open.remove(at: generator.int(0 ... open.count - 1))
                    ended.append(ending)
                    await cache.requestEnded(ending)
                    calls.append("requestEnded")
                }

            case 80 ..< 82:
                let begun = SMB.CacheRequestID()
                open.append(begun)
                await cache.beginRequest(begun)
                calls.append("beginRequest")

            case 82 ..< 89:
                let destination = generator.pick(paths)
                let target = cache.locate(destination).key

                // The bytes of everything at or under the source may now be answered under the destination.
                if !CachePath.sameBytes(CachePath.normalize(path), CachePath.normalize(destination)) {
                    for (source, bytes) in given where CachePath.isPath(source, atOrUnder: key) {
                        let moved = CachePath.rebase(source, from: key, to: target)
                        for (position, values) in bytes {
                            given[moved, default: [:]][position, default: []].formUnion(values)
                        }
                    }
                }
                await cache.didRename(from: path, to: destination)
                calls.append("didRename(\(path.debugDescription), \(destination.debugDescription))")

            case 89 ..< 93:
                let byteCount = UInt64(generator.pick([0, 1, 30, 1000]))
                await cache.didAppend(path: path, byteCount: byteCount)
                calls.append("didAppend(\(path.debugDescription), \(byteCount))")

            case 93 ..< 98:
                await cache.invalidate(path: path)
                calls.append("invalidate(\(path.debugDescription))")

            case 98:
                let critical = generator.chance(0.3)
                await cache.relieveMemoryPressure(critical: critical)
                calls.append("relieveMemoryPressure(critical: \(critical))")

            default:
                await cache.close()
                calls.append("close()")
            }

            let violations = await cache.invariantViolations()
            if !violations.isEmpty {
                return fail(step, violations.joined(separator: "; "))
            }
        }

        return nil
    }

    @Test("no sequence of calls breaks the cache's bookkeeping, or has it answer with bytes it was never given")
    func anyCallsInAnyOrder() async {
        await CacheFuzz.forEachSeed(CacheFuzz.seeds(500)) { seed in
            await Self.fuzz(seed: seed)
        }
    }
}

// MARK: Limits

@Suite("ReferenceCache: limits")
struct ReferenceCacheLimitTests {
    @Test("tracking more files than the limit forgets the least recently used, and keeps the byte count exact")
    func entryLimit() async {
        let cache = CacheFuzz.makeCache()
        let limit = SMB.ReferenceCache.entryLimit

        // The first files hold bytes, and are the least recently used once the others are tracked.
        for index in 0 ..< 10 {
            await CacheFuzz.cacheFile(cache, path: "old/file\(index)", contents: CacheFuzz.bytes(10))
        }
        let inFlight = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: "old/file0", offset: 5, upTo: 100, request: inFlight)

        await cache.trackFiles(under: "new", count: limit - 10)
        #expect(await cache.files.count == limit)
        #expect(await cache.storedByteCount == 100)

        // One more is one too many.
        await cache.trackFiles(under: "last", count: 1)
        let tracked = await cache.files.count
        #expect(tracked <= limit)
        #expect(tracked >= limit / 2, "forgot all but \(tracked) files")
        #expect(await cache.files["last/file0"] != nil)
        #expect(await cache.files["old/file0"] == nil)
        #expect(await cache.storedByteCount == 0)
        #expect(await cache.invariantViolations() == [])

        // A file tracked again is a new one: bytes read from the forgotten one are not for it.
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 10), path: "old/file0")
        await cache.storeBlock(CacheFuzz.bytes(5), path: "old/file0", offset: 5, source: .download, request: inFlight)
        await cache.requestEnded(inFlight)
        #expect(await cache.cachedRanges(path: "old/file0") == [])
    }

    @Test("requests that never end are forgotten oldest first, and their stores refused")
    func requestLimit() async {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)

        var requests: [SMB.CacheRequestID] = []
        for _ in 0 ... RequestLog.limit {
            let request = SMB.CacheRequestID()
            _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 10, request: request)
            requests.append(request)
        }
        #expect(await cache.requests.count == RequestLog.limit)

        await cache.storeBlock(CacheFuzz.bytes(10), path: path, offset: 0, source: .download, request: requests[0])
        #expect(await cache.cachedRanges(path: path) == [])
        await cache.storeBlock(CacheFuzz.bytes(10), path: path, offset: 0, source: .download, request: requests[1])
        #expect(await cache.cachedRanges(path: path) == [0 ..< 10])

        for request in requests {
            await cache.requestEnded(request)
        }
        #expect(await cache.requests.count == 0)
    }

    @Test("stored stats and listings stay within their limit, and the newest still answer")
    func metadataLimit() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 3600, includingMissing: false))
        let count = SMB.ReferenceCache.metadataLimit + 200

        await cache.trackFiles(under: "d", count: count)
        #expect(await cache.stats.count <= SMB.ReferenceCache.metadataLimit)
        #expect(await CacheFuzz.cachedStat(cache, path: "d/file\(count - 1)") != nil)
        #expect(await cache.invariantViolations() == [])

        let listed = CacheFuzz.makeCache(metadata: .answer(for: 3600, includingMissing: false))
        for index in 0 ..< count {
            await CacheFuzz.list(listed, [CacheFuzz.entry("f", CacheFuzz.file(size: 1))], path: "l\(index)")
        }
        #expect(await listed.listings.count <= SMB.ReferenceCache.metadataLimit)
        #expect(await CacheFuzz.cachedListing(listed, path: "l\(count - 1)") != nil)
        #expect(await listed.invariantViolations() == [])
    }

    @Test("storing a listing does not take longer the more files the cache tracks elsewhere")
    func listingCost() async {
        /// How long 100 listings of directories the cache tracks nothing in take to store.
        func cost(tracking count: Int) async -> Duration {
            let cache = CacheFuzz.makeCache()
            await cache.trackFiles(under: "tracked", count: count)

            let clock = ContinuousClock()
            let start = clock.now
            for index in 0 ..< 100 {
                await CacheFuzz.list(
                    cache,
                    [CacheFuzz.entry("f", CacheFuzz.file(size: 1))],
                    path: "listed/directory\(index)"
                )
            }
            return clock.now - start
        }

        let few = await cost(tracking: 10)
        let many = await cost(tracking: SMB.ReferenceCache.entryLimit)

        // Walking a large tree stores one listing per directory: a cost that grows with every file tracked anywhere
        // turns that walk quadratic. Generous, so that a busy machine does not fail it.
        #expect(many < few * 20 + .milliseconds(200), "\(many) with every file tracked, \(few) with ten")
    }

    @Test("more changed paths than the log remembers refuse what was in flight, and nothing read afterwards")
    func changeLogLimit() async {
        let cache = CacheFuzz.makeCache()
        let path = "kept/file"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)
        await CacheFuzz.download(cache, CacheFuzz.bytes(50), path: path)

        let inFlight = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 50, upTo: 10, request: inFlight)
        for index in 0 ... ChangeLog.pathLimit {
            await cache.invalidate(path: "changed/file\(index)")
        }

        // The log no longer knows whether the file changed since the lookup: it must assume so.
        await cache.storeBlock(
            CacheFuzz.bytes(10, from: 50),
            path: path,
            offset: 50,
            source: .download,
            request: inFlight
        )
        await cache.requestEnded(inFlight)
        #expect(await cache.cachedRanges(path: path) == [0 ..< 50])

        // A read made from now on is kept as before.
        await CacheFuzz.download(cache, CacheFuzz.bytes(50, from: 50), path: path, offset: 50)
        #expect(await CacheFuzz.retrieve(cache, path: path, upTo: 100) == CacheFuzz.bytes(100))
        #expect(await cache.invariantViolations() == [])
    }

    @Test("many tasks storing and reading different files at once leave the books straight")
    func concurrentCallers() async {
        let cache = CacheFuzz.makeCache(byteBudget: 4000, metadata: .answer(for: 3600, includingMissing: true))

        let wrong = await withTaskGroup(of: [String].self) { group in
            for task in 0 ..< 16 {
                group.addTask {
                    var generator = SeededGenerator(seed: UInt64(task))
                    var wrong: [String] = []
                    let directory = "t\(task % 4)"

                    for round in 0 ..< 150 {
                        // Each task owns its files, so it knows what they hold, while sharing directories, the budget,
                        // and the change log with the others.
                        let name = "owned\(task)-\(generator.int(0 ... 2))"
                        let path = "\(directory)/\(name)"
                        let contents = CacheFuzz.bytes(generator.int(1 ... 200), from: task * 7 + round)
                        let time = UInt64(1000 + round)

                        await CacheFuzz.cacheFile(cache, path: path, contents: contents, modificationTime: time)
                        if let answer = await CacheFuzz.retrieve(cache, path: path, upTo: contents.count),
                           answer != contents.prefix(answer.count) {
                            wrong.append("\(path): read back other bytes than were stored in round \(round)")
                        }

                        switch generator.int(0 ... 5) {
                        case 0:
                            await cache.invalidate(path: path)

                        case 1:
                            await cache.didRename(from: path, to: path + "-moved")
                            await cache.didRename(from: path + "-moved", to: path)

                        case 2:
                            await CacheFuzz.list(
                                cache,
                                [CacheFuzz.entry(
                                    name,
                                    CacheFuzz.file(size: UInt64(contents.count), modificationTime: time)
                                )],
                                path: directory
                            )

                        case 3:
                            await CacheFuzz.upload(cache, CacheFuzz.bytes(5), path: path, offset: 0)

                        default:
                            break
                        }
                    }
                    return wrong
                }
            }

            var wrong: [String] = []
            for await found in group {
                wrong += found
            }
            return wrong
        }

        #expect(wrong == [])
        #expect(await cache.invariantViolations() == [])
        #expect(await cache.requests.count == 0)
    }
}

// MARK: Checks without a server

@Suite("ReferenceCache: checks that cannot reach the server")
struct ReferenceCacheUncheckableTests {
    static let policies: [SMB.ReferenceCache.TrustPolicy] = [
        .statOnServer,
        .sampleBlocks(count: 2),
        .sampleBlocks(count: 1, scan: .endToStart),
    ]

    @Test("bytes due for a check that cannot be made are dropped, not handed out", arguments: policies)
    func dueBytesAreDropped(policy: SMB.ReferenceCache.TrustPolicy) async {
        // An interval of zero has every hit checked first.
        let cache = CacheFuzz.uncheckableCache(policy, revalidationInterval: 0)
        await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(40))

        #expect(await CacheFuzz.retrieve(cache, path: "f", upTo: 40) == nil)
        #expect(await cache.storedByteCount == 0)
        #expect(await cache.checks.isEmpty)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("bytes read before a failed check dropped the file's bytes are refused afterwards", arguments: policies)
    func storeAfterFailedCheck(policy: SMB.ReferenceCache.TrustPolicy) async {
        let cache = CacheFuzz.uncheckableCache(policy, revalidationInterval: 0)
        let path = "f"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)

        // A read in flight while other bytes of the file are stored, then checked for another read.
        let inFlight = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 40, upTo: 20, request: inFlight)
        await CacheFuzz.download(cache, CacheFuzz.bytes(40), path: path)
        #expect(await CacheFuzz.retrieve(cache, path: path, upTo: 40) == nil)

        await cache.storeBlock(
            CacheFuzz.bytes(20, from: 40),
            path: path,
            offset: 40,
            source: .download,
            request: inFlight
        )
        await cache.requestEnded(inFlight)
        #expect(await cache.cachedRanges(path: path) == [])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("many reads of one file wait on one check at a time, and none is handed unchecked bytes", arguments: policies)
    func concurrentReadsOfAnUncheckableFile(policy: SMB.ReferenceCache.TrustPolicy) async {
        let cache = CacheFuzz.uncheckableCache(policy, revalidationInterval: 0)
        await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(40))

        let answers = await withTaskGroup(of: Data?.self) { group in
            for _ in 0 ..< 50 {
                group.addTask {
                    await CacheFuzz.retrieve(cache, path: "f", upTo: 40)
                }
            }

            var answers: [Data?] = []
            for await answer in group {
                answers.append(answer)
            }
            return answers
        }

        #expect(answers.allSatisfy { $0 == nil })
        #expect(await cache.checks.isEmpty)
        #expect(await cache.requests.count == 0)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a check is due before the first hit, after the interval, or with no interval after each stat")
    func dueness() async {
        // statOnServer counts every stat as a check.
        let stats = CacheFuzz.uncheckableCache(.statOnServer, revalidationInterval: nil)
        await CacheFuzz.cacheFile(stats, path: "f", contents: CacheFuzz.bytes(40))
        #expect(await CacheFuzz.retrieve(stats, path: "f", upTo: 40) == CacheFuzz.bytes(40))

        // Written bytes come without a stat: the first hit needs a check.
        await CacheFuzz.upload(stats, CacheFuzz.bytes(10), path: "written")
        #expect(await CacheFuzz.retrieve(stats, path: "written", upTo: 10) == nil)

        // sampleBlocks checks once after each stat.
        let samples = CacheFuzz.uncheckableCache(.sampleBlocks(count: 1), revalidationInterval: nil)
        await CacheFuzz.cacheFile(samples, path: "f", contents: CacheFuzz.bytes(40))
        #expect(await CacheFuzz.retrieve(samples, path: "f", upTo: 40) == nil)

        // A long interval keeps a check good.
        let long = CacheFuzz.uncheckableCache(.statOnServer, revalidationInterval: 3600)
        await CacheFuzz.cacheFile(long, path: "f", contents: CacheFuzz.bytes(40))
        #expect(await CacheFuzz.retrieve(long, path: "f", upTo: 40) == CacheFuzz.bytes(40))
    }
}
