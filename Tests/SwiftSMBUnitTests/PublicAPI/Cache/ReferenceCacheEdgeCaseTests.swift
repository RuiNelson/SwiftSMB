//
// Part of SwiftSMB
// ReferenceCacheEdgeCaseTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import SMB2
import Testing

// MARK: Paths

@Suite("ReferenceCache: paths")
struct ReferenceCachePathTests {
    @Test(
        "spellings of one path share one file: leading, doubled, trailing, and back separators, and . and .. segments"
    )
    func spellingsOfOnePath() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        await CacheFuzz.cacheFile(cache, path: "a/b/f", contents: CacheFuzz.bytes(40))

        for spelling in [
            "/a/b/f",
            "a//b/f",
            "a/b/f/",
            "a/./b/f",
            "a/x/../b/f",
            "a/b/./f/.",
            "//a/b/f",
            "../a/b/f",
            #"a\b\f"#,
        ] {
            #expect(await CacheFuzz.retrieve(cache, path: spelling, upTo: 40) == CacheFuzz.bytes(40), "\(spelling)")
            #expect(await CacheFuzz.cachedStat(cache, path: spelling) != nil, "\(spelling)")
        }

        // A change reported under another spelling of the directory reaches the file.
        await cache.invalidate(path: "a/x/../b/")
        #expect(await cache.cachedRanges(path: "a/b/f") == [])
        #expect(await CacheFuzz.cachedStat(cache, path: "a/b/f") == nil)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("the share root covers every path, however it is spelled")
    func shareRoot() async {
        for root in ["", "/", ".", "a/.."] {
            let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
            await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(10))
            await CacheFuzz.cacheFile(cache, path: "d/f", contents: CacheFuzz.bytes(10))
            await CacheFuzz.list(cache, [CacheFuzz.entry("f", CacheFuzz.file(size: 10))], path: "")

            await cache.invalidate(path: root)
            #expect(await cache.files.isEmpty, "\(root)")
            #expect(await cache.storedByteCount == 0)
            #expect(await cache.stats.isEmpty)
            #expect(await cache.listings.isEmpty)
            #expect(await cache.invariantViolations() == [])
        }
    }

    @Test("a stat or a listing of the share root is kept like any other")
    func rootMetadata() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        let root = CacheFuzz.directory()
        await CacheFuzz.stat(cache, root, path: "")
        await CacheFuzz.list(cache, [CacheFuzz.entry("f", CacheFuzz.file(size: 1))], path: "/")

        #expect(await CacheFuzz.cachedStat(cache, path: "/") == .exists(root))
        #expect(await CacheFuzz.cachedListing(cache, path: "")?.map(\.name) == ["f"])
        #expect(await CacheFuzz.cachedStat(cache, path: "missing") == .doesNotExist)
    }
}

// MARK: Values at the edge of their range

#if os(macOS) || os(Linux) || os(FreeBSD) || os(Windows)
    /// Calls with values at the ends of their ranges, each in a process of its own: a trap in the cache would otherwise
    /// take every other test down with it.
    @Suite("ReferenceCache: values at the edge of their range")
    struct ReferenceCacheExtremeValueTests {
        @Test("the last positions a file can have are stored, handed out, and sized")
        func largestValidValues() async {
            await #expect(processExitsWith: .success) {
                let cache = SMB.ReferenceCache(configuration: .init())
                let path = "far"
                let last = Data(repeating: 7, count: 8)

                // The last eight bytes a file can hold.
                await cache.storeBlock(last, path: path, offset: .max - 8, source: .upload, request: nil)
                let request = SMB.CacheRequestID()
                let answer = await cache.retrieveBlock(path: path, offset: .max - 8, upTo: .max, request: request)
                await cache.requestEnded(request)
                precondition(answer == last, "the bytes at the far end were not handed back")

                let pastTheEnd = SMB.CacheRequestID()
                let nothing = await cache.retrieveBlock(path: path, offset: .max, upTo: .max, request: pastTheEnd)
                await cache.requestEnded(pastTheEnd)
                precondition(nothing == nil)

                await cache.storeStat(CacheFuzz.file(size: .max), path: path, request: nil)
                await cache.didAppend(path: path, byteCount: 0)
                await cache.invalidate(path: path)
                let violations = await cache.invariantViolations()
                precondition(violations.isEmpty, "\(violations)")
            }
        }

        @Test("appending to a file whose server reports a size at the top of the range does not trap")
        func appendToFileOfLargestSize() async {
            await #expect(processExitsWith: .success) {
                let cache = SMB.ReferenceCache(configuration: .init())
                let path = "huge"

                // A size only a hostile or broken server reports, but one it can report.
                await cache.storeStat(CacheFuzz.file(size: .max - 4), path: path, request: nil)
                await cache.didAppend(path: path, byteCount: 16)
                await cache.storeStat(CacheFuzz.file(size: .max, modificationTime: 2000), path: path, request: nil)
            }
        }

        @Test("appends that add up past the top of the range do not trap")
        func appendsPastTheLargestCount() async {
            await #expect(processExitsWith: .success) {
                let cache = SMB.ReferenceCache(configuration: .init())
                let path = "appended"

                // Tracked from a write, so of unknown size.
                await cache.storeBlock(
                    Data(repeating: 1, count: 4),
                    path: path,
                    offset: 0,
                    source: .upload,
                    request: nil
                )
                await cache.didAppend(path: path, byteCount: .max - 2)
                await cache.didAppend(path: path, byteCount: 16)
            }
        }

        @Test("bytes that would run past the last position a file can have are cut, not fatal")
        func bytesPastTheLastPosition() async {
            await #expect(processExitsWith: .success) {
                let cache = SMB.ReferenceCache(configuration: .init())
                await cache.storeBlock(
                    Data(repeating: 1, count: 16),
                    path: "far",
                    offset: .max - 8,
                    source: .upload,
                    request: nil
                )
                let ranges = await cache.cachedRanges(path: "far")
                precondition(ranges == [.max - 8 ..< .max], "\(ranges)")

                // Downloaded into a file whose size the server reports at the top of the range.
                let path = "sized"
                await cache.storeStat(CacheFuzz.file(size: .max), path: path, request: nil)
                let request = SMB.CacheRequestID()
                _ = await cache.retrieveBlock(path: path, offset: .max - 8, upTo: 16, request: request)
                await cache.storeBlock(
                    Data(repeating: 1, count: 16),
                    path: path,
                    offset: .max - 8,
                    source: .download,
                    request: request
                )
                await cache.requestEnded(request)
            }
        }

        @Test("checks of a file whose size is at the top of the range do not trap")
        func samplingTheLargestFile() async {
            await #expect(processExitsWith: .success) {
                let plan = SMB.ReferenceCache.samplePlan(
                    size: .max,
                    cached: [.max - 40000 ..< .max],
                    cursor: .max,
                    count: 3,
                    scan: .endToStart
                )
                precondition(plan.blocks.count == 2, "\(plan.blocks)")
            }
        }
    }
#endif

// MARK: Bytes

@Suite("ReferenceCache: bytes at the edges")
struct ReferenceCacheByteEdgeTests {
    @Test("bytes handed over as a slice of a larger buffer are stored like any others, and handed back from zero")
    func slicedData() async throws {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        let buffer = CacheFuzz.bytes(200)
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)

        // Each slice keeps the indices it had in the buffer.
        await CacheFuzz.download(cache, buffer[50 ..< 90], path: path, offset: 0)
        await CacheFuzz.upload(cache, buffer[120 ..< 140], path: path, offset: 20)
        await CacheFuzz.upload(cache, buffer[150 ..< 170], path: path, offset: 35)

        // Cut to the 20 bytes the file has left from 80 on.
        await CacheFuzz.download(cache, buffer[10 ..< 60], path: path, offset: 80)

        let head = try #require(await CacheFuzz.retrieve(cache, path: path, upTo: 100))
        #expect(head == CacheFuzz.bytes(20, from: 50) + CacheFuzz.bytes(15, from: 120) + CacheFuzz.bytes(20, from: 150))
        #expect(head.startIndex == 0)

        let tail = try #require(await CacheFuzz.retrieve(cache, path: path, offset: 85, upTo: 100))
        #expect(tail == CacheFuzz.bytes(15, from: 15))
        #expect(tail.startIndex == 0)
        #expect(await cache.cachedRanges(path: path) == [0 ..< 55, 80 ..< 100])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("empty stores, and lookups for nothing or less, change nothing and open no request")
    func emptyCalls() async {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)
        await CacheFuzz.upload(cache, Data(), path: "untracked")
        await CacheFuzz.download(cache, Data(), path: path)
        #expect(await cache.trackedPaths == [path])
        #expect(await cache.storedByteCount == 0)

        for upTo in [0, -1, .min] {
            let request = SMB.CacheRequestID()
            #expect(await cache.retrieveBlock(path: path, offset: 0, upTo: upTo, request: request) == nil)
            #expect(await cache.requests.count == 0)

            // No lookup was made, so there is no request to store for.
            await cache.storeBlock(CacheFuzz.bytes(10), path: path, offset: 0, source: .download, request: request)
            await cache.requestEnded(request)
        }
        #expect(await cache.cachedRanges(path: path) == [])
    }

    @Test("an empty file is tracked, answers nothing, and keeps nothing")
    func emptyFile() async {
        let cache = CacheFuzz.makeCache()
        let path = "empty"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 0), path: path)

        #expect(await CacheFuzz.retrieve(cache, path: path, upTo: 10) == nil)
        await CacheFuzz.download(cache, CacheFuzz.bytes(10), path: path)
        #expect(await cache.cachedRanges(path: path) == [])

        // Written to, it holds what was written.
        await CacheFuzz.upload(cache, CacheFuzz.bytes(10), path: path)
        #expect(await CacheFuzz.retrieve(cache, path: path, upTo: 100) == CacheFuzz.bytes(10))
        #expect(await cache.knownSize(path: path) == 10)
    }

    @Test("a budget of zero keeps no bytes, whatever is stored")
    func zeroBudget() async {
        let cache = CacheFuzz.makeCache(byteBudget: 0, metadata: .answer(for: 60, includingMissing: false))
        await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(40))
        await CacheFuzz.upload(cache, CacheFuzz.bytes(10), path: "f", offset: 5)
        await CacheFuzz.upload(cache, CacheFuzz.bytes(10), path: "g")

        #expect(await cache.storedByteCount == 0)
        #expect(await CacheFuzz.retrieve(cache, path: "f", upTo: 40) == nil)
        #expect(await CacheFuzz.retrieve(cache, path: "g", upTo: 10) == nil)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("with keepsUploads off, a write drops the file's blocks instead of keeping its bytes")
    func uploadsNotKept() async {
        let cache = CacheFuzz.makeCache(keepsUploads: false)
        await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(40))
        await CacheFuzz.upload(cache, CacheFuzz.bytes(5), path: "f", offset: 10)
        await CacheFuzz.upload(cache, CacheFuzz.bytes(5), path: "new")

        #expect(await cache.cachedRanges(path: "f") == [])
        #expect(await cache.trackedPaths == ["f"])
        #expect(await cache.invariantViolations() == [])
    }
}

// MARK: Budget

@Suite("ReferenceCache: budget")
struct ReferenceCacheBudgetTests {
    @Test("storing into a file drops others, least recently used first, and never the file itself")
    func evictionOrder() async {
        let cache = CacheFuzz.makeCache(byteBudget: 100)
        for name in ["a", "b", "c"] {
            await CacheFuzz.cacheFile(cache, path: name, contents: CacheFuzz.bytes(30))
        }

        // Reading a leaves b the least recently used.
        #expect(await CacheFuzz.retrieve(cache, path: "a", upTo: 1) != nil)
        await CacheFuzz.cacheFile(cache, path: "d", contents: CacheFuzz.bytes(30))
        #expect(await cache.cachedRanges(path: "b") == [])
        #expect(await cache.storedByteCount == 90)

        // d grows to 60 bytes: c goes, and d itself stays.
        await CacheFuzz.cacheFile(cache, path: "d", contents: CacheFuzz.bytes(60), modificationTime: 2000)
        #expect(await cache.cachedRanges(path: "c") == [])
        #expect(await cache.cachedRanges(path: "a") == [0 ..< 30])
        #expect(await cache.cachedRanges(path: "d") == [0 ..< 60])
        #expect(await cache.storedByteCount == 90)

        // Files stay tracked without their bytes, and take bytes again.
        #expect(await cache.files.count == 4)
        await CacheFuzz.download(cache, CacheFuzz.bytes(10), path: "b")
        #expect(await cache.cachedRanges(path: "b") == [0 ..< 10])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a file exactly as large as the budget is cached, and one byte larger is not")
    func budgetBoundary() async {
        let cache = CacheFuzz.makeCache(byteBudget: 100)
        await CacheFuzz.cacheFile(cache, path: "exact", contents: CacheFuzz.bytes(100))
        #expect(await cache.cachedRanges(path: "exact") == [0 ..< 100])

        await CacheFuzz.cacheFile(cache, path: "over", contents: CacheFuzz.bytes(101))
        #expect(await cache.cachedRanges(path: "over") == [])
        #expect(await cache.cachedRanges(path: "exact") == [0 ..< 100])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a file that outgrew the budget is cached again once a stat shows a version that fits")
    func outgrownFileComesBack() async {
        let cache = CacheFuzz.makeCache(byteBudget: 100)
        await CacheFuzz.upload(cache, CacheFuzz.bytes(60), path: "g", offset: 0)
        await CacheFuzz.upload(cache, CacheFuzz.bytes(60), path: "g", offset: 60)
        #expect(await cache.cachedRanges(path: "g") == [])

        await CacheFuzz.cacheFile(cache, path: "g", contents: CacheFuzz.bytes(50), modificationTime: 2000)
        #expect(await cache.cachedRanges(path: "g") == [0 ..< 50])
    }

    @Test("a file appended past the maximum file size stops holding bytes")
    func appendPastMaximumFileSize() async {
        let cache = CacheFuzz.makeCache(maximumFileSize: 50)
        await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(50))
        #expect(await cache.storedByteCount == 50)

        // The file is now larger than the cache keeps: its bytes are no longer handed out, and only take up room.
        await cache.didAppend(path: "f", byteCount: 10)
        #expect(await CacheFuzz.retrieve(cache, path: "f", upTo: 10) == nil)
        #expect(await cache.storedByteCount == 0)
    }

    @Test(
        "a memory warning halves the bytes kept, least recently used first, and a critical one drops every byte and stat"
    )
    func memoryPressure() async {
        let cache = CacheFuzz.makeCache(byteBudget: 100, metadata: .answer(for: 60, includingMissing: false))
        for name in ["a", "b", "c"] {
            await CacheFuzz.cacheFile(cache, path: name, contents: CacheFuzz.bytes(30))
        }

        await cache.relieveMemoryPressure(critical: false)
        #expect(await cache.cachedRanges(path: "a") == [])
        #expect(await cache.cachedRanges(path: "b") == [])
        #expect(await cache.cachedRanges(path: "c") == [0 ..< 30])
        #expect(await CacheFuzz.cachedStat(cache, path: "a") != nil)

        let inFlight = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: "c", offset: 30, upTo: 10, request: inFlight)
        await cache.relieveMemoryPressure(critical: true)
        #expect(await cache.storedByteCount == 0)
        #expect(await cache.cachedRanges(path: "c") == [])
        #expect(await CacheFuzz.cachedStat(cache, path: "a") == nil)

        // Dropping bytes changes nothing on the server: what was in flight is kept, and the cache goes on working.
        await cache.storeBlock(CacheFuzz.bytes(10), path: "c", offset: 0, source: .download, request: inFlight)
        await cache.requestEnded(inFlight)
        #expect(await cache.cachedRanges(path: "c") == [0 ..< 10])
        await CacheFuzz.download(cache, CacheFuzz.bytes(30), path: "c")
        #expect(await cache.cachedRanges(path: "c") == [0 ..< 30])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("closing drops everything, refuses what was in flight, can be repeated, and leaves a working cache")
    func close() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        await CacheFuzz.cacheFile(cache, path: "f", contents: CacheFuzz.bytes(40))
        await cache.storeStat(CacheFuzz.file(size: 100), path: "f", request: nil)

        let inFlight = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: "f", offset: 50, upTo: 10, request: inFlight)

        await cache.close()
        await cache.close()
        #expect(await cache.files.isEmpty)
        #expect(await cache.stats.isEmpty)
        #expect(await cache.storedByteCount == 0)

        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: "f")
        await cache.storeBlock(CacheFuzz.bytes(10), path: "f", offset: 50, source: .download, request: inFlight)
        await cache.requestEnded(inFlight)
        #expect(await cache.cachedRanges(path: "f") == [])

        await CacheFuzz.download(cache, CacheFuzz.bytes(40), path: "f")
        #expect(await CacheFuzz.retrieve(cache, path: "f", upTo: 40) == CacheFuzz.bytes(40))
        #expect(await cache.invariantViolations() == [])
    }
}

// MARK: Stores out of order

@Suite("ReferenceCache: more stores out of order")
struct ReferenceCacheLateStoreTests {
    @Test(
        "bytes read before a write, an append, or a close are refused when they arrive after it",
        arguments: ["write", "append", "close"]
    )
    func storeAfterChange(change: String) async {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)

        let stale = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 50, request: stale)

        switch change {
        case "write":
            await CacheFuzz.upload(cache, CacheFuzz.bytes(10, from: 200), path: path, offset: 20)

        case "append":
            await cache.didAppend(path: path, byteCount: 5)

        default:
            await cache.close()
            await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)
        }

        await cache.storeBlock(CacheFuzz.bytes(50), path: path, offset: 0, source: .download, request: stale)
        await cache.requestEnded(stale)

        let ranges = await cache.cachedRanges(path: path)
        #expect(!ranges.contains { $0.contains(0) }, "kept \(ranges)")
        #expect(await cache.invariantViolations() == [])
    }

    @Test("bytes read before the storage dropped the file's bytes to make room are still good, and kept")
    func storeAfterEviction() async {
        let cache = CacheFuzz.makeCache(byteBudget: 100)
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: "a")
        await CacheFuzz.download(cache, CacheFuzz.bytes(60), path: "a")

        let request = SMB.CacheRequestID()
        #expect(await cache.retrieveBlock(path: "a", offset: 60, upTo: 20, request: request) == nil)
        await CacheFuzz.cacheFile(cache, path: "b", contents: CacheFuzz.bytes(60))
        #expect(await cache.cachedRanges(path: "a") == [])

        await cache.storeBlock(
            CacheFuzz.bytes(20, from: 60),
            path: "a",
            offset: 60,
            source: .download,
            request: request
        )
        await cache.requestEnded(request)
        #expect(await cache.cachedRanges(path: "a") == [60 ..< 80])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("of two reads in flight across a change, only the one that looked up after it is kept")
    func readsOnEitherSideOfAChange() async {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)

        let before = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 10, request: before)
        await CacheFuzz.upload(cache, CacheFuzz.bytes(5, from: 200), path: path, offset: 50)
        let after = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 10, upTo: 10, request: after)

        // The later read's bytes arrive first.
        await cache.storeBlock(CacheFuzz.bytes(10, from: 10), path: path, offset: 10, source: .download, request: after)
        await cache.storeBlock(CacheFuzz.bytes(10), path: path, offset: 0, source: .download, request: before)
        await cache.requestEnded(after)
        await cache.requestEnded(before)

        #expect(await cache.cachedRanges(path: path) == [10 ..< 20, 50 ..< 55])
    }

    @Test("the rest of a read the cache answered in part is kept after the part it answered")
    func restOfAPartialAnswer() async {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 100), path: path)
        await CacheFuzz.download(cache, CacheFuzz.bytes(30), path: path)

        let request = SMB.CacheRequestID()
        let answer = await cache.retrieveBlock(path: path, offset: 10, upTo: 60, request: request)
        #expect(answer == CacheFuzz.bytes(20, from: 10))
        await cache.storeBlock(
            CacheFuzz.bytes(40, from: 30),
            path: path,
            offset: 30,
            source: .download,
            request: request
        )
        await cache.requestEnded(request)

        #expect(await CacheFuzz.retrieve(cache, path: path, upTo: 100) == CacheFuzz.bytes(70))
        #expect(await cache.requests.count == 0)
    }

    @Test("a stat fetched before a change to a sibling is kept, and one fetched before a change underneath is not")
    func statsAroundChangesNearby() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))

        let besideChange = SMB.CacheRequestID()
        _ = await cache.retrieveStat(path: "d/file", request: besideChange)
        await cache.invalidate(path: "d/other")
        await cache.storeStat(CacheFuzz.file(size: 1), path: "d/file", request: besideChange)
        await cache.requestEnded(besideChange)
        #expect(await CacheFuzz.cachedStat(cache, path: "d/file") != nil)

        // A directory's own times change with what is created or removed in it.
        let aboveChange = SMB.CacheRequestID()
        _ = await cache.retrieveStat(path: "e", request: aboveChange)
        await cache.invalidate(path: "e/sub/deep")
        await cache.storeStat(CacheFuzz.directory(), path: "e", request: aboveChange)
        await cache.requestEnded(aboveChange)
        #expect(await CacheFuzz.cachedStat(cache, path: "e") == nil)

        // And a change to a directory reaches everything under it.
        let belowChange = SMB.CacheRequestID()
        _ = await cache.retrieveStat(path: "g/sub/file", request: belowChange)
        await cache.didRename(from: "g", to: "h")
        await cache.storeStat(CacheFuzz.file(size: 1), path: "g/sub/file", request: belowChange)
        await cache.requestEnded(belowChange)
        #expect(await CacheFuzz.cachedStat(cache, path: "g/sub/file") == nil)

        // A change under another spelling of the path counts too.
        let otherSpelling = SMB.CacheRequestID()
        _ = await cache.retrieveStat(path: "k/File", request: otherSpelling)
        await cache.invalidate(path: "K/FILE")
        await cache.storeStat(CacheFuzz.file(size: 1), path: "k/File", request: otherSpelling)
        await cache.requestEnded(otherSpelling)
        #expect(await CacheFuzz.cachedStat(cache, path: "k/File") == nil)
    }
}

// MARK: Versions

@Suite("ReferenceCache: more versions and changes")
struct ReferenceCacheVersionEdgeTests {
    @Test("a path that turns out to hold a directory, or nothing, stops being a file, with what was under it")
    func noLongerAFile() async {
        let cache = CacheFuzz.makeCache()
        await CacheFuzz.cacheFile(cache, path: "d", contents: CacheFuzz.bytes(10))
        await CacheFuzz.stat(cache, CacheFuzz.directory(), path: "d")
        #expect(await cache.files.isEmpty)
        #expect(await cache.storedByteCount == 0)

        await CacheFuzz.cacheFile(cache, path: "e/a", contents: CacheFuzz.bytes(10))
        await CacheFuzz.cacheFile(cache, path: "e/sub/b", contents: CacheFuzz.bytes(10))
        await CacheFuzz.cacheFile(cache, path: "ee/c", contents: CacheFuzz.bytes(10))
        await CacheFuzz.stat(cache, nil, path: "e")
        #expect(await cache.trackedPaths == ["ee/c"])
        #expect(await cache.storedByteCount == 10)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a listing leaves alone what it does not list directly, and what it lists as a link or reparse point")
    func listingEdges() async {
        let cache = CacheFuzz.makeCache()
        for path in ["d/file", "d/link", "d/reparse", "d/nowDirectory", "d/sub/deep", "dd/beside", "d"] {
            await CacheFuzz.cacheFile(cache, path: path, contents: CacheFuzz.bytes(10))
        }

        await CacheFuzz.list(
            cache,
            [
                CacheFuzz.entry("file", CacheFuzz.file(size: 10)),
                CacheFuzz.entry("link", CacheFuzz.link()),
                CacheFuzz.entry(
                    "reparse",
                    CacheFuzz.stat(
                        type: SMB2_TYPE_FILE,
                        size: 1,
                        modificationTime: 5,
                        changeTime: nil,
                        attributes: .reparsePoint
                    )
                ),
                CacheFuzz.entry("nowDirectory", CacheFuzz.directory()),
                CacheFuzz.entry("sub", CacheFuzz.directory()),
                // Entries that do not name a child of the directory say nothing about it.
                CacheFuzz.entry(".", CacheFuzz.directory()),
                CacheFuzz.entry("..", CacheFuzz.directory()),
                CacheFuzz.entry("", CacheFuzz.file(size: 1)),
                CacheFuzz.entry("x/y", CacheFuzz.file(size: 1)),
            ],
            path: "d"
        )

        #expect(await cache.trackedPaths == ["d", "d/file", "d/link", "d/reparse", "d/sub/deep", "dd/beside"])
        #expect(await cache.cachedRanges(path: "d/file") == [0 ..< 10])
        #expect(await cache.cachedRanges(path: "d/link") == [0 ..< 10])
        #expect(await cache.cachedRanges(path: "d/reparse") == [0 ..< 10])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("appended files keep the bytes before the appends through writes on either side of them")
    func appendsAndWrites() async {
        let cache = CacheFuzz.makeCache()
        let path = "f"
        await CacheFuzz.cacheFile(cache, path: path, contents: CacheFuzz.bytes(100))

        // Written past the end, then appended to: the appends start where the write ended.
        await CacheFuzz.upload(cache, CacheFuzz.bytes(20, from: 100), path: path, offset: 100)
        await cache.didAppend(path: path, byteCount: 30)
        #expect(await cache.knownSize(path: path) == 150)

        // And part of what was appended written over, through another handle.
        await CacheFuzz.upload(cache, Data(repeating: 0xEE, count: 10), path: path, offset: 130)
        await cache.storeStat(CacheFuzz.file(size: 150, modificationTime: 2000), path: path, request: nil)
        #expect(await cache.cachedRanges(path: path) == [0 ..< 120, 130 ..< 140])
        #expect(await CacheFuzz.retrieve(cache, path: path, upTo: 200) == CacheFuzz.bytes(120))

        // Appends to a file the cache does not track are nothing to it.
        await cache.didAppend(path: "untracked", byteCount: 10)
        #expect(await cache.trackedPaths == [path])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("what was written or appended since the last stat moves with a renamed file")
    func renameMovesPendingWrites() async {
        let cache = CacheFuzz.makeCache()
        await CacheFuzz.cacheFile(cache, path: "x", contents: CacheFuzz.bytes(100))
        await CacheFuzz.upload(cache, Data(repeating: 0xEE, count: 10), path: "x", offset: 40)
        await cache.didAppend(path: "x", byteCount: 25)

        let inFlight = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: "x", offset: 100, upTo: 25, request: inFlight)
        await cache.didRename(from: "x", to: "y")

        // Bytes read under the old path have no file there to go to.
        await cache.storeBlock(CacheFuzz.bytes(25), path: "x", offset: 100, source: .download, request: inFlight)
        await cache.requestEnded(inFlight)
        #expect(await cache.trackedPaths == ["y"])

        // The final stat of the renamed file shows it grown by what was appended: everything before is kept.
        await cache.storeStat(CacheFuzz.file(size: 125, modificationTime: 2000), path: "y", request: nil)
        #expect(await cache.cachedRanges(path: "y") == [0 ..< 100])
        #expect(await CacheFuzz.retrieve(cache, path: "y", offset: 40, upTo: 10) == Data(repeating: 0xEE, count: 10))

        // Renamed back and forth, it is the same file.
        await cache.didRename(from: "y", to: "x")
        await cache.didRename(from: "x", to: "y")
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 125, modificationTime: 2000), path: "y")
        #expect(await cache.cachedRanges(path: "y") == [0 ..< 100])
        #expect(await cache.invariantViolations() == [])
    }

    @Test(
        "renaming something the cache does not track onto a file drops that file, and onto itself keeps its blocks only"
    )
    func renameEdges() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        await CacheFuzz.cacheFile(cache, path: "d/f", contents: CacheFuzz.bytes(10))
        await CacheFuzz.cacheFile(cache, path: "e/g", contents: CacheFuzz.bytes(10))

        // Onto itself: nothing moves, but a share that ignores case may have respelled the name, so the stored stat,
        // and listings that show the old name, are dropped.
        await cache.didRename(from: "d/f", to: "d/./f")
        #expect(await cache.cachedRanges(path: "d/f") == [0 ..< 10])
        #expect(await CacheFuzz.cachedStat(cache, path: "d/f") == nil)
        await CacheFuzz.stat(cache, CacheFuzz.file(size: 10), path: "d/f")
        #expect(await CacheFuzz.cachedStat(cache, path: "d/f") != nil)

        await cache.didRename(from: "untracked", to: "d/f")
        #expect(await cache.cachedRanges(path: "d/f") == [])
        #expect(await CacheFuzz.cachedStat(cache, path: "d/f") == nil)

        // A directory the cache tracks nothing under, renamed over one it does.
        await cache.didRename(from: "empty", to: "e")
        #expect(await cache.files.isEmpty)
        #expect(await cache.storedByteCount == 0)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a rename into the directory it renames, which no server allows, leaves the books straight")
    func renameIntoItself() async {
        let cache = CacheFuzz.makeCache()
        await CacheFuzz.cacheFile(cache, path: "a/f", contents: CacheFuzz.bytes(10))
        await cache.didRename(from: "a", to: "a/b")
        #expect(await cache.trackedPaths == ["a/b/f"])
        await cache.didRename(from: "a/b", to: "a")
        #expect(await cache.trackedPaths == ["a/f"])
        #expect(await cache.invariantViolations() == [])
    }
}

// MARK: Metadata

@Suite("ReferenceCache: more metadata answers")
struct ReferenceCacheMetadataEdgeTests {
    @Test(
        "a change inside a directory drops what a listing of the directory above says about that directory",
        arguments: ["created or deleted", "renamed away", "renamed in"]
    )
    func listingAboveAChangedDirectory(change: String) async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        let directory = CacheFuzz.directory()
        await CacheFuzz.list(
            cache,
            [CacheFuzz.entry("sub", directory), CacheFuzz.entry("f", CacheFuzz.file(size: 1))],
            path: "d"
        )
        #expect(await CacheFuzz.cachedStat(cache, path: "d/sub") == .exists(directory))

        // Each of these changes the times of d/sub, which the listing of d shows.
        switch change {
        case "created or deleted":
            await cache.invalidate(path: "d/sub/file")

        case "renamed away":
            await cache.didRename(from: "d/sub/file", to: "elsewhere/file")

        default:
            await cache.didRename(from: "elsewhere/file", to: "d/sub/file")
        }

        #expect(await CacheFuzz.cachedStat(cache, path: "d/sub") == nil)
    }

    @Test("a file whose stat the cache answered from a listing still has its downloaded bytes kept")
    func fileKnownOnlyFromAListing() async {
        let cache = CacheFuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        let file = CacheFuzz.file(size: 40)
        await CacheFuzz.list(cache, [CacheFuzz.entry("f", file)], path: "d")

        // Opening the file stats it. The cache answers from the listing, so the connection makes no stat of its own,
        // and then reads the file.
        #expect(await CacheFuzz.cachedStat(cache, path: "d/f") == .exists(file))
        await CacheFuzz.download(cache, CacheFuzz.bytes(40), path: "d/f")
        #expect(await cache.cachedRanges(path: "d/f") == [0 ..< 40])
    }

    @Test("an answer interval of zero never answers, and stored metadata expires")
    func expiry() async throws {
        let never = CacheFuzz.makeCache(metadata: .answer(for: 0, includingMissing: true))
        await CacheFuzz.stat(never, CacheFuzz.file(size: 1), path: "f")
        await CacheFuzz.list(never, [CacheFuzz.entry("f", CacheFuzz.file(size: 1))], path: "d")
        #expect(await CacheFuzz.cachedStat(never, path: "f") == nil)
        #expect(await CacheFuzz.cachedStat(never, path: "d/missing") == nil)
        #expect(await CacheFuzz.cachedListing(never, path: "d") == nil)

        let brief = CacheFuzz.makeCache(metadata: .answer(for: 0.05, includingMissing: true))
        await CacheFuzz.stat(brief, CacheFuzz.file(size: 1), path: "f")
        await CacheFuzz.list(brief, [CacheFuzz.entry("f", CacheFuzz.file(size: 1))], path: "d")
        try await Task.sleep(nanoseconds: 120_000_000)
        #expect(await CacheFuzz.cachedStat(brief, path: "f") == nil)
        #expect(await CacheFuzz.cachedStat(brief, path: "d/f") == nil)
        #expect(await CacheFuzz.cachedListing(brief, path: "d") == nil)
    }

    @Test("two stats of one path disagree the same way whichever comes first, and a stat never with itself")
    func disagreementIsSymmetric() {
        let answers: [SMB.Stat?] = [
            nil,
            CacheFuzz.file(size: 1),
            CacheFuzz.file(size: 2),
            CacheFuzz.file(size: 1, modificationTime: 2000),
            CacheFuzz.file(size: 1, changeTime: 3000),
            CacheFuzz.directory(),
            CacheFuzz.link(),
        ]

        for first in answers {
            for second in answers {
                #expect(SMB.ReferenceCache.disagree(first, second) == SMB.ReferenceCache.disagree(second, first))
            }
            #expect(!SMB.ReferenceCache.disagree(first, first))
        }
    }
}
