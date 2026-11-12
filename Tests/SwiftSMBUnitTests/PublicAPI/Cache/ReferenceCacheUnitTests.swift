//
// Part of SwiftSMB
// ReferenceCacheUnitTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

private typealias Fuzz = CacheFuzz

/// `count` bytes counting up from `first`.
private func bytes(_ count: Int, from first: Int = 0) -> Data {
    CacheFuzz.bytes(count, from: first)
}

// MARK: Block storage

@Suite("ReferenceCache: block storage")
struct ReferenceCacheBlockStorageTests {
    @Test("runs merge: new bytes overwrite the bytes they overlap, and touching runs join")
    func blocksMerge() {
        var blocks = FileBlocks()
        blocks.write(bytes(20, from: 10), at: 10)
        blocks.write(bytes(20, from: 50), at: 50)
        #expect(blocks.ranges == [10 ..< 30, 50 ..< 70])

        // Overlaps both runs.
        blocks.write(Data(repeating: 0xEE, count: 30), at: 25)
        #expect(blocks.ranges == [10 ..< 70])
        #expect(blocks.byteCount == 60)

        // Touches the end, then lands before the start without touching it.
        blocks.write(bytes(10, from: 70), at: 70)
        blocks.write(bytes(5, from: 0), at: 0)
        #expect(blocks.ranges == [0 ..< 5, 10 ..< 80])

        // Inside one run, replaced in place.
        blocks.write(Data(repeating: 0xAA, count: 4), at: 12)

        let expected = bytes(2, from: 10) + Data(repeating: 0xAA, count: 4) + bytes(9, from: 16)
            + Data(repeating: 0xEE, count: 30) + bytes(15, from: 55) + bytes(10, from: 70)
        #expect(blocks.run(at: 10, upTo: 1000) == expected)
        #expect(blocks.run(at: 3, upTo: 1000) == bytes(2, from: 3))
        #expect(blocks.run(at: 7, upTo: 1000) == nil)
        #expect(blocks.byteCount == 75)
    }

    @Test("retaining ranges keeps only their bytes, split runs included, and a single prefix trims in place")
    func retainRanges() {
        var blocks = FileBlocks()
        blocks.write(bytes(100), at: 0)
        blocks.write(Data(repeating: 1, count: 20), at: 10)
        blocks.write(Data(repeating: 2, count: 10), at: 50)

        blocks.retain([10 ..< 30, 50 ..< 55])
        #expect(blocks.ranges == [10 ..< 30, 50 ..< 55])
        #expect(blocks.run(at: 50, upTo: 100) == Data(repeating: 2, count: 5))
        #expect(blocks.byteCount == 25)

        blocks.retain([0 ..< 20])
        #expect(blocks.ranges == [10 ..< 20])
        #expect(blocks.byteCount == 10)

        blocks.retain([])
        #expect(blocks.isEmpty && blocks.byteCount == 0)
    }

    @Test("stored ranges merge in the cache, with later bytes over earlier ones")
    func cacheMergesRanges() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)

        await Fuzz.download(cache, bytes(20, from: 10), path: path, offset: 10)
        await Fuzz.download(cache, bytes(20, from: 50), path: path, offset: 50)
        await Fuzz.download(cache, Data(repeating: 0xEE, count: 30), path: path, offset: 25)

        #expect(await cache.cachedRanges(path: path) == [10 ..< 70])
        #expect(await cache.storedByteCount == 60)
        #expect(
            await Fuzz.retrieve(cache, path: path, offset: 10, upTo: 100)
                == bytes(15, from: 10) + Data(repeating: 0xEE, count: 30) + bytes(15, from: 55)
        )
    }

    @Test("a read gets the cached run from its offset, however short, or nothing when no byte is cached there")
    func prefixAnswers() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)
        await Fuzz.download(cache, bytes(40), path: path, offset: 0)

        // A prefix of what was asked for, starting exactly at the offset.
        #expect(await Fuzz.retrieve(cache, path: path, offset: 0, upTo: 100) == bytes(40))
        #expect(await Fuzz.retrieve(cache, path: path, offset: 5, upTo: 1000) == bytes(35, from: 5))
        #expect(await Fuzz.retrieve(cache, path: path, offset: 0, upTo: 8) == bytes(8))
        #expect(await Fuzz.retrieve(cache, path: path, offset: 39, upTo: 100) == bytes(1, from: 39))

        // Nothing cached at the offset.
        #expect(await Fuzz.retrieve(cache, path: path, offset: 40, upTo: 10) == nil)
        #expect(await Fuzz.retrieve(cache, path: "data/other", offset: 0, upTo: 10) == nil)
    }

    @Test("bytes past the known size are neither kept nor handed out")
    func trimmedAtKnownSize() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)
        await Fuzz.download(cache, bytes(40, from: 80), path: path, offset: 80)

        #expect(await cache.cachedRanges(path: path) == [80 ..< 100])
        #expect(await Fuzz.retrieve(cache, path: path, offset: 90, upTo: 100) == bytes(10, from: 90))
        #expect(await Fuzz.retrieve(cache, path: path, offset: 100, upTo: 100) == nil)

        // The file shrinks: a version of its own, though the times stay.
        await Fuzz.stat(cache, Fuzz.file(size: 95), path: path)
        #expect(await cache.cachedRanges(path: path) == [])
    }

    @Test("the least recently used files go whole to stay within the budget")
    func leastRecentlyUsedEviction() async {
        let cache = Fuzz.makeCache(byteBudget: 100)
        await Fuzz.cacheFile(cache, path: "a", contents: bytes(40))
        await Fuzz.cacheFile(cache, path: "b", contents: bytes(40, from: 1))
        // Using a makes b the least recently used.
        #expect(await Fuzz.retrieve(cache, path: "a", offset: 0, upTo: 10) == bytes(10))

        await Fuzz.cacheFile(cache, path: "c", contents: bytes(40, from: 2))

        #expect(await cache.cachedRanges(path: "a") == [0 ..< 40])
        #expect(await cache.cachedRanges(path: "b") == [])
        #expect(await cache.cachedRanges(path: "c") == [0 ..< 40])
        #expect(await cache.storedByteCount == 80)

        // A file larger than the whole budget is never cached.
        await Fuzz.cacheFile(cache, path: "big", contents: bytes(101))
        #expect(await cache.cachedRanges(path: "big") == [])
        #expect(await cache.storedByteCount == 80)
    }

    @Test("a file of unknown size that outgrows the budget alone is dropped, and others stay")
    func fileOutgrowingBudget() async {
        let cache = Fuzz.makeCache(byteBudget: 100)
        await Fuzz.cacheFile(cache, path: "a", contents: bytes(40))

        // Written through the connection: no size known.
        await Fuzz.upload(cache, bytes(60), path: "growing", offset: 0)
        await Fuzz.upload(cache, bytes(60, from: 60), path: "growing", offset: 60)

        #expect(await cache.cachedRanges(path: "growing") == [])
        #expect(await cache.cachedRanges(path: "a") == [0 ..< 40])
        #expect(await cache.storedByteCount == 40)

        // Until its version changes.
        await Fuzz.upload(cache, bytes(10), path: "growing", offset: 0)
        #expect(await cache.cachedRanges(path: "growing") == [])
    }

    @Test("files known to be larger than the maximum file size are not cached")
    func maximumFileSize() async {
        let cache = Fuzz.makeCache(maximumFileSize: 50)
        await Fuzz.cacheFile(cache, path: "small", contents: bytes(50))
        await Fuzz.cacheFile(cache, path: "large", contents: bytes(51))

        #expect(await cache.cachedRanges(path: "small") == [0 ..< 50])
        #expect(await cache.cachedRanges(path: "large") == [])
        #expect(await Fuzz.retrieve(cache, path: "large", offset: 0, upTo: 10) == nil)

        // The small file grows past the maximum.
        await Fuzz.stat(cache, Fuzz.file(size: 60, modificationTime: 2000), path: "small")
        #expect(await cache.cachedRanges(path: "small") == [])
        #expect(await cache.storedByteCount == 0)
    }

    @Test("caches sharing a storage keep their files apart, share its budget, and close without touching each other")
    func sharedStorage() async {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 100)
        let first = SMB.ReferenceCache(storage: storage, configuration: .init())
        let second = SMB.ReferenceCache(storage: storage, configuration: .init())

        // The same path on two shares: two files.
        await Fuzz.cacheFile(first, path: "f", contents: bytes(40))
        await Fuzz.cacheFile(second, path: "f", contents: bytes(40, from: 100))
        #expect(await Fuzz.retrieve(first, path: "f", upTo: 40) == bytes(40))
        #expect(await Fuzz.retrieve(second, path: "f", upTo: 40) == bytes(40, from: 100))
        #expect(storage.byteCount == 80)

        // One budget: the second cache's next file pushes out the least recently used, which is the first cache's.
        await Fuzz.cacheFile(second, path: "g", contents: bytes(40, from: 200))
        #expect(await first.cachedRanges(path: "f") == [])
        #expect(await second.cachedRanges(path: "f") == [0 ..< 40])
        #expect(await second.cachedRanges(path: "g") == [0 ..< 40])

        // Bytes the storage dropped are downloaded again into the same tracked file.
        await Fuzz.download(first, bytes(40), path: "f")
        #expect(await first.cachedRanges(path: "f") == [0 ..< 40])
        #expect(await second.cachedRanges(path: "f") == [])

        // Closing drops only the closed cache's bytes.
        await first.close()
        #expect(await second.cachedRanges(path: "g") == [0 ..< 40])
        #expect(await second.invariantViolations() == [])
        #expect(storage.byteCount == 40)
    }
}

// MARK: Versions and changes

@Suite("ReferenceCache: versions and changes")
struct ReferenceCacheVersionTests {
    @Test("a new version drops the blocks, except those written through the connection since the previous stat")
    func versionChange() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.cacheFile(cache, path: path, contents: bytes(100))

        // The same version keeps everything.
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)
        #expect(await cache.cachedRanges(path: path) == [0 ..< 100])

        // Written through the connection, then the file is closed: the final stat shows a new version.
        let written = Data(repeating: 0xEE, count: 10)
        await Fuzz.upload(cache, written, path: path, offset: 10)
        await Fuzz.stat(cache, Fuzz.file(size: 100, modificationTime: 2000), path: path)
        #expect(await cache.cachedRanges(path: path) == [10 ..< 20])
        #expect(await Fuzz.retrieve(cache, path: path, offset: 10, upTo: 10) == written)

        // Those bytes belong to that version: a further version drops them too.
        await Fuzz.stat(cache, Fuzz.file(size: 100, modificationTime: 3000), path: path)
        #expect(await cache.cachedRanges(path: path) == [])
    }

    @Test("the size, the last write time, and the change time each tell versions apart")
    func versionFields() async {
        let base = Fuzz.file(size: 100, modificationTime: 1000, changeTime: 1000)
        let others = [
            Fuzz.file(size: 101, modificationTime: 1000, changeTime: 1000),
            Fuzz.file(size: 100, modificationTime: 1001, changeTime: 1000),
            Fuzz.file(size: 100, modificationTime: 1000, changeTime: 1001),
        ]

        for other in others {
            let cache = Fuzz.makeCache()
            await Fuzz.stat(cache, base, path: "f")
            await Fuzz.download(cache, bytes(100), path: "f")
            #expect(await cache.cachedRanges(path: "f") == [0 ..< 100])

            await Fuzz.stat(cache, other, path: "f")
            #expect(await cache.cachedRanges(path: "f") == [], "\(other)")
        }

        // The access and creation times say nothing about the contents.
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: "f", contents: bytes(100))
        await Fuzz.stat(cache, Fuzz.file(size: 100, accessTime: 5000, birthTime: 7), path: "f")
        #expect(await cache.cachedRanges(path: "f") == [0 ..< 100])
    }

    @Test("a stat that finds nothing, a directory, or a link drops the file")
    func statsOfOtherEntries() async {
        for result in [nil, Fuzz.directory(), Fuzz.link()] as [SMB.Stat?] {
            let cache = Fuzz.makeCache()
            let path = "data/file"
            await Fuzz.cacheFile(cache, path: path, contents: bytes(100))

            await Fuzz.stat(cache, result, path: path)
            #expect(await cache.cachedRanges(path: path) == [])
            #expect(await cache.files.isEmpty)
        }
    }

    @Test("a listing versions the files it lists, and drops the ones it no longer lists")
    func listingVersions() async {
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: "d/same", contents: bytes(10))
        await Fuzz.cacheFile(cache, path: "d/changed", contents: bytes(10))
        await Fuzz.cacheFile(cache, path: "d/gone", contents: bytes(10))
        await Fuzz.cacheFile(cache, path: "d/sub/deeper", contents: bytes(10))

        await Fuzz.list(
            cache,
            [
                Fuzz.entry("same", Fuzz.file(size: 10)),
                Fuzz.entry("changed", Fuzz.file(size: 10, modificationTime: 2000)),
            ],
            path: "d"
        )

        #expect(await cache.cachedRanges(path: "d/same") == [0 ..< 10])
        #expect(await cache.cachedRanges(path: "d/changed") == [])
        #expect(await cache.cachedRanges(path: "d/gone") == [])
        // Not directly in the listed directory: the listing says nothing about it.
        #expect(await cache.cachedRanges(path: "d/sub/deeper") == [0 ..< 10])
    }

    @Test("invalidating a path drops it, everything under it, and its parent's listing")
    func invalidateSubtree() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        await Fuzz.cacheFile(cache, path: "d/a", contents: bytes(10))
        await Fuzz.cacheFile(cache, path: "d/sub/b", contents: bytes(10))
        await Fuzz.cacheFile(cache, path: "d/subway", contents: bytes(10))
        await Fuzz.cacheFile(cache, path: "other/c", contents: bytes(10))
        await Fuzz.list(
            cache,
            [Fuzz.entry("a", Fuzz.file(size: 10)), Fuzz.entry("subway", Fuzz.file(size: 10))],
            path: "d"
        )
        await Fuzz.list(cache, [Fuzz.entry("b", Fuzz.file(size: 10))], path: "d/sub")
        await Fuzz.list(cache, [Fuzz.entry("c", Fuzz.file(size: 10))], path: "other")

        await cache.invalidate(path: "d/sub")

        #expect(await cache.cachedRanges(path: "d/sub/b") == [])
        #expect(await cache.cachedRanges(path: "d/a") == [0 ..< 10])
        #expect(await cache.cachedRanges(path: "d/subway") == [0 ..< 10])
        #expect(await cache.cachedRanges(path: "other/c") == [0 ..< 10])

        #expect(await Fuzz.cachedListing(cache, path: "d") == nil)
        #expect(await Fuzz.cachedListing(cache, path: "d/sub") == nil)
        #expect(await Fuzz.cachedListing(cache, path: "other") != nil)
        #expect(await Fuzz.cachedStat(cache, path: "d/sub/b") == nil)
        #expect(await Fuzz.cachedStat(cache, path: "d/a") != nil)
    }

    @Test("renaming a file moves its blocks over whatever the destination held")
    func renameFile() async {
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: "x", contents: bytes(10, from: 1))
        await Fuzz.cacheFile(cache, path: "y", contents: bytes(20, from: 2))

        await cache.didRename(from: "x", to: "y")

        #expect(await cache.cachedRanges(path: "x") == [])
        #expect(await Fuzz.retrieve(cache, path: "y", offset: 0, upTo: 100) == bytes(10, from: 1))

        // The moved file keeps its version, so the stat that opening it makes keeps the blocks.
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: "y")
        #expect(await cache.cachedRanges(path: "y") == [0 ..< 10])
        #expect(await cache.trackedPaths == ["y"])
    }

    @Test("renaming a directory moves everything under it over what the destination held")
    func renameDirectory() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        await Fuzz.cacheFile(cache, path: "d1/a", contents: bytes(10, from: 1))
        await Fuzz.cacheFile(cache, path: "d1/s/b", contents: bytes(10, from: 2))
        await Fuzz.cacheFile(cache, path: "d2/a", contents: bytes(10, from: 3))
        await Fuzz.cacheFile(cache, path: "d2/z", contents: bytes(10, from: 4))
        await Fuzz.cacheFile(cache, path: "d10/a", contents: bytes(10, from: 5))
        await Fuzz.list(cache, [Fuzz.entry("a", Fuzz.file(size: 10))], path: "d1")
        await Fuzz.list(cache, [], path: "")

        await cache.didRename(from: "d1", to: "d2")

        #expect(await cache.cachedRanges(path: "d1/a") == [])
        #expect(await cache.cachedRanges(path: "d1/s/b") == [])
        #expect(await Fuzz.retrieve(cache, path: "d2/a", offset: 0, upTo: 100) == bytes(10, from: 1))
        #expect(await Fuzz.retrieve(cache, path: "d2/s/b", offset: 0, upTo: 100) == bytes(10, from: 2))
        #expect(await cache.cachedRanges(path: "d2/z") == [])
        #expect(await cache.cachedRanges(path: "d10/a") == [0 ..< 10])
        #expect(await Fuzz.cachedListing(cache, path: "d1") == nil)
        #expect(await Fuzz.cachedListing(cache, path: "") == nil)
        #expect(await cache.invariantViolations() == [])
    }
}

// MARK: Out-of-order stores

@Suite("ReferenceCache: out-of-order stores")
struct ReferenceCacheOrderingTests {
    @Test("bytes read before an invalidation are refused when they arrive after it")
    func storeAfterInvalidate() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)

        // A read misses; before its bytes arrive, the file changes and is opened again.
        let stale = SMB.CacheRequestID()
        #expect(await cache.retrieveBlock(path: path, offset: 0, upTo: 50, request: stale) == nil)
        await cache.invalidate(path: path)
        await Fuzz.stat(cache, Fuzz.file(size: 100, modificationTime: 2000), path: path)
        await cache.storeBlock(bytes(50, from: 1), path: path, offset: 0, source: .download, request: stale)
        await cache.requestEnded(stale)
        #expect(await cache.cachedRanges(path: path) == [])

        // A read made after the change is kept.
        await Fuzz.download(cache, bytes(50, from: 2), path: path)
        #expect(await Fuzz.retrieve(cache, path: path, upTo: 50) == bytes(50, from: 2))
    }

    @Test("bytes read before a rename replaced the file, or before a new version, are refused")
    func storeAfterRenameOrNewVersion() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)

        let beforeRename = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 50, request: beforeRename)
        await cache.didRename(from: "data/other", to: path)
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)
        await cache.storeBlock(bytes(50, from: 1), path: path, offset: 0, source: .download, request: beforeRename)
        await cache.requestEnded(beforeRename)
        #expect(await cache.cachedRanges(path: path) == [])

        // The stat of a newer version arrives between the server read and the store: the bytes may be of the older
        // version.
        let beforeVersion = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 50, request: beforeVersion)
        await Fuzz.stat(cache, Fuzz.file(size: 100, modificationTime: 2000), path: path)
        await cache.storeBlock(bytes(50, from: 2), path: path, offset: 0, source: .download, request: beforeVersion)
        await cache.requestEnded(beforeVersion)
        #expect(await cache.cachedRanges(path: path) == [])
    }

    @Test("bytes read while the cache did not track the file are refused once a stat starts tracking it")
    func storeIntoEntryCreatedAfterLookup() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"

        // The lookup finds nothing tracked. A stat of a newer version, made by another task, starts tracking the file
        // before the bytes, which may be of the older version, arrive.
        let untracked = SMB.CacheRequestID()
        #expect(await cache.retrieveBlock(path: path, offset: 0, upTo: 50, request: untracked) == nil)
        await cache.storeStat(Fuzz.file(size: 100, modificationTime: 2000), path: path, request: nil)
        await cache.storeBlock(bytes(50, from: 1), path: path, offset: 0, source: .download, request: untracked)
        await cache.requestEnded(untracked)
        #expect(await cache.cachedRanges(path: path) == [])

        // Read once the file is tracked, they are kept.
        await Fuzz.download(cache, bytes(50, from: 2), path: path)
        #expect(await cache.cachedRanges(path: path) == [0 ..< 50])
    }

    @Test("bytes without an open request are refused: none, ended, forgotten, or never looked up")
    func storesWithoutOpenRequest() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)

        await cache.storeBlock(bytes(10), path: path, offset: 0, source: .download, request: nil)
        await cache.storeBlock(bytes(10), path: path, offset: 0, source: .download, request: SMB.CacheRequestID())

        let ended = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 10, request: ended)
        await cache.requestEnded(ended)
        await cache.storeBlock(bytes(10), path: path, offset: 0, source: .download, request: ended)
        #expect(await cache.cachedRanges(path: path) == [])

        // Nothing is ever stored for a file the cache does not track.
        await Fuzz.download(cache, bytes(10), path: "data/unknown")
        #expect(await cache.cachedRanges(path: "data/unknown") == [])
    }

    @Test("a request that never stores leaves nothing behind that refuses later reads at its position")
    func requestsThatNeverStore() async {
        let cache = Fuzz.makeCache()
        let path = "data/file"
        await Fuzz.stat(cache, Fuzz.file(size: 100), path: path)

        // A read that fails, then a change, then the file is read again from the same position.
        let failed = SMB.CacheRequestID()
        _ = await cache.retrieveBlock(path: path, offset: 0, upTo: 50, request: failed)
        await cache.requestEnded(failed)
        await Fuzz.upload(cache, bytes(10, from: 90), path: path, offset: 90)
        #expect(await cache.requests.count == 0)

        await Fuzz.download(cache, bytes(50, from: 3), path: path)
        #expect(await cache.cachedRanges(path: path) == [0 ..< 50, 90 ..< 100])
    }

    @Test("a stat or listing fetched before a change is refused when it arrives after it")
    func metadataAfterChange() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        let file = "d/file"

        // Stat'ed before a delete through the connection, stored after it: the cache must not answer that it exists.
        let statBeforeDelete = SMB.CacheRequestID()
        #expect(await cache.retrieveStat(path: file, request: statBeforeDelete) == nil)
        await cache.invalidate(path: file)
        await cache.storeStat(Fuzz.file(size: 10), path: file, request: statBeforeDelete)
        await cache.requestEnded(statBeforeDelete)
        #expect(await Fuzz.cachedStat(cache, path: file) == nil)

        // Listed before a rename of an entry in it, stored after it.
        let listingBeforeRename = SMB.CacheRequestID()
        _ = await cache.retrieveDirectoryListing(path: "d", request: listingBeforeRename)
        await cache.didRename(from: file, to: "elsewhere")
        await cache.storeDirectoryListing(
            [Fuzz.entry("file", Fuzz.file(size: 10))],
            path: "d",
            request: listingBeforeRename
        )
        await cache.requestEnded(listingBeforeRename)
        #expect(await Fuzz.cachedListing(cache, path: "d") == nil)
        #expect(await Fuzz.cachedStat(cache, path: file) == nil)

        // A listing covers changes deep under its directory too.
        let rootListing = SMB.CacheRequestID()
        _ = await cache.retrieveDirectoryListing(path: "", request: rootListing)
        await Fuzz.upload(cache, bytes(10), path: "d/sub/deep")
        await cache.storeDirectoryListing([], path: "", request: rootListing)
        await cache.requestEnded(rootListing)
        #expect(await Fuzz.cachedListing(cache, path: "") == nil)

        // Fetched after the change, they are kept.
        await Fuzz.stat(cache, nil, path: file)
        #expect(await Fuzz.cachedStat(cache, path: file) == .doesNotExist)
    }

    @Test("a stat of an open file, begun with beginRequest, is kept unless a change overlapped it")
    func statsOfOpenFiles() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        let file = "d/file"
        await cache.invalidate(path: file)
        await cache.storeStat(Fuzz.file(size: 10), path: file, request: nil)
        #expect(await Fuzz.cachedStat(cache, path: file) == .exists(Fuzz.file(size: 10)))

        let overlapped = SMB.CacheRequestID()
        await cache.beginRequest(overlapped)
        await Fuzz.upload(cache, bytes(5), path: file)
        await cache.storeStat(Fuzz.file(size: 99), path: file, request: overlapped)
        await cache.requestEnded(overlapped)
        #expect(await Fuzz.cachedStat(cache, path: file) == nil)
        #expect(await cache.knownSize(path: file) == 10)
    }
}

// MARK: Metadata

@Suite("ReferenceCache: metadata answers")
struct ReferenceCacheMetadataTests {
    @Test("with neverAnswer, stats and listings always go to the server")
    func neverAnswer() async {
        let cache = Fuzz.makeCache()
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: "f")
        await Fuzz.list(cache, [Fuzz.entry("f", Fuzz.file(size: 10))], path: "")

        #expect(await Fuzz.cachedStat(cache, path: "f") == nil)
        #expect(await Fuzz.cachedListing(cache, path: "") == nil)
        #expect(await cache.stats.isEmpty)
        #expect(await cache.listings.isEmpty)
    }

    @Test("stored stats and listings answer until they expire, and missing paths only when asked to")
    func answers() async throws {
        let file = Fuzz.file(size: 10)
        let link = Fuzz.link()
        let listing = [Fuzz.entry("f", file), Fuzz.entry("link", link)]

        for includingMissing in [false, true] {
            let cache = Fuzz.makeCache(metadata: .answer(for: 0.5, includingMissing: includingMissing))
            await Fuzz.stat(cache, file, path: "d/f")
            await Fuzz.stat(cache, nil, path: "gone")
            await Fuzz.list(cache, listing, path: "d")

            #expect(await Fuzz.cachedStat(cache, path: "d/f") == .exists(file))
            #expect(await Fuzz.cachedListing(cache, path: "d") == listing)

            // From the listing: a link is described as itself, while a stat of its path may follow it.
            #expect(await Fuzz.cachedStat(cache, path: "d/link") == nil)

            let missing: SMB.CachedStat? = includingMissing ? .doesNotExist : nil
            #expect(await Fuzz.cachedStat(cache, path: "gone") == missing)
            #expect(await Fuzz.cachedStat(cache, path: "d/missing") == missing)
            #expect(await Fuzz.cachedStat(cache, path: "elsewhere") == nil)

            try await Task.sleep(nanoseconds: 600_000_000)
            #expect(await Fuzz.cachedStat(cache, path: "d/f") == nil)
            #expect(await Fuzz.cachedStat(cache, path: "gone") == nil)
            #expect(await Fuzz.cachedStat(cache, path: "d/missing") == nil)
            #expect(await Fuzz.cachedListing(cache, path: "d") == nil)
        }
    }

    @Test("a stored stat of a link, which a stat by path reported as such, answers as the server did")
    func storedLinkStat() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        await Fuzz.stat(cache, Fuzz.link(), path: "d/link")
        #expect(await Fuzz.cachedStat(cache, path: "d/link") == .exists(Fuzz.link()))
        #expect(await cache.files.isEmpty)
    }
}

// MARK: Metadata after writes

@Suite("ReferenceCache: metadata after writes")
struct ReferenceCacheMetadataAfterWritesTests {
    @Test("a write drops the file's stored stat and its parent's listing")
    func writeDropsMetadata() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        let file = "d/file"
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: file)
        await Fuzz.list(cache, [Fuzz.entry("file", Fuzz.file(size: 10))], path: "d")
        await Fuzz.list(cache, [Fuzz.entry("x", Fuzz.file(size: 1))], path: "other")

        await Fuzz.upload(cache, bytes(20), path: file)

        #expect(await Fuzz.cachedStat(cache, path: file) == nil)
        #expect(await Fuzz.cachedListing(cache, path: "d") == nil)
        #expect(await Fuzz.cachedListing(cache, path: "other") != nil)
    }

    @Test("a stat showing a new version drops the listings that disagree with it")
    func newVersionDropsDisagreeingMetadata() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        let file = "d/file"
        let old = Fuzz.file(size: 10)
        let new = Fuzz.file(size: 30, modificationTime: 2000)
        await Fuzz.list(cache, [Fuzz.entry("file", old)], path: "d")
        await Fuzz.list(cache, [Fuzz.entry("d", Fuzz.directory())], path: "")

        // The same version keeps it.
        await cache.storeStat(old, path: file, request: nil)
        #expect(await Fuzz.cachedListing(cache, path: "d") != nil)

        // A new one drops it, and only it.
        await cache.storeStat(new, path: file, request: nil)
        #expect(await Fuzz.cachedStat(cache, path: file) == .exists(new))
        #expect(await Fuzz.cachedListing(cache, path: "d") == nil)
        #expect(await Fuzz.cachedListing(cache, path: "") != nil)

        // A listed link says nothing about what a stat of its path finds.
        await Fuzz.list(cache, [Fuzz.entry("link", Fuzz.link())], path: "e")
        await cache.storeStat(Fuzz.file(size: 99), path: "e/link", request: nil)
        #expect(await Fuzz.cachedListing(cache, path: "e") != nil)
    }

    @Test("a listing drops the stored stats of the entries it shows otherwise")
    func listingDropsDisagreeingStats() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: "d/a")
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: "d/b")
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: "d/c")
        await Fuzz.stat(cache, Fuzz.directory(), path: "d")

        await Fuzz.list(cache, [Fuzz.entry("a", Fuzz.file(size: 10)), Fuzz.entry("b", Fuzz.file(size: 20))], path: "d")

        #expect(await cache.stats["d/a"] != nil)
        #expect(await cache.stats["d/b"] == nil)
        #expect(await cache.stats["d/c"] == nil)
        // The directory's own stat is not an entry of its listing.
        #expect(await cache.stats["d"] != nil)
        #expect(await Fuzz.cachedStat(cache, path: "d/b") == .exists(Fuzz.file(size: 20)))
        #expect(await Fuzz.cachedStat(cache, path: "d/c") == .doesNotExist)
    }

    @Test("appending drops the stored metadata but keeps the bytes before the old end, once the size adds up")
    func appendKeepsExistingBytes() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: false))
        let file = "d/file"
        await Fuzz.cacheFile(cache, path: file, contents: bytes(100))
        await Fuzz.list(cache, [Fuzz.entry("file", Fuzz.file(size: 100))], path: "d")

        await cache.didAppend(path: file, byteCount: 30)
        await cache.didAppend(path: file, byteCount: 20)
        #expect(await Fuzz.cachedStat(cache, path: file) == nil)
        #expect(await Fuzz.cachedListing(cache, path: "d") == nil)
        #expect(await cache.cachedRanges(path: file) == [0 ..< 100])

        // The close stat shows the file grown by exactly what was appended.
        await cache.storeStat(Fuzz.file(size: 150, modificationTime: 2000), path: file, request: nil)
        #expect(await Fuzz.retrieve(cache, path: file, upTo: 100) == bytes(100))

        // Grown by something else as well: the bytes may no longer be what the file holds.
        await cache.didAppend(path: file, byteCount: 10)
        await cache.storeStat(Fuzz.file(size: 170, modificationTime: 3000), path: file, request: nil)
        #expect(await cache.cachedRanges(path: file) == [])
    }
}

// MARK: Renames and accounting

@Suite("ReferenceCache: renames and byte accounting")
struct ReferenceCacheRenameAccountingTests {
    @Test("renames over existing files keep the stored byte count exact, directories included")
    func renameAccounting() async {
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: "x", contents: bytes(10, from: 1))
        await Fuzz.cacheFile(cache, path: "y", contents: bytes(30, from: 2))
        await Fuzz.cacheFile(cache, path: "d1/a", contents: bytes(5, from: 3))
        await Fuzz.cacheFile(cache, path: "d2/a", contents: bytes(7, from: 4))
        #expect(await cache.storedByteCount == 52)

        await cache.didRename(from: "x", to: "y")
        await cache.didRename(from: "d1", to: "d2")

        #expect(await cache.storedByteCount == 15)
        #expect(await cache.invariantViolations() == [])
        #expect(await Fuzz.retrieve(cache, path: "y", upTo: 100) == bytes(10, from: 1))
        #expect(await Fuzz.retrieve(cache, path: "d2/a", upTo: 100) == bytes(5, from: 3))
    }
}

// MARK: Bookkeeping

@Suite("ReferenceCache: generation bookkeeping")
struct ReferenceCacheBookkeepingTests {
    @Test("a change reaches the path and everything under it, and nothing beside it")
    func changeLogSubtrees() {
        var log = ChangeLog()
        log.recordChange(at: "d")
        let changed = log.clock

        #expect(log.generation(of: "d") == changed)
        #expect(log.generation(of: "d/a/b") == changed)
        #expect(log.generation(of: "dd") == 0)
        #expect(log.generation(of: "") == 0)

        log.recordChangeEverywhere()
        #expect(log.generation(of: "elsewhere") == log.clock)
    }

    @Test("the latest change at or under a directory includes changes deep below it, and none beside it")
    func changeLogBelow() {
        var log = ChangeLog()
        log.recordChange(at: "d/sub/file")
        let deep = log.clock

        #expect(log.generation(of: "d") == 0)
        #expect(log.latestChange(atOrUnder: "d") == deep)
        #expect(log.latestChange(atOrUnder: "d/sub") == deep)
        #expect(log.latestChange(atOrUnder: "") == deep)
        #expect(log.latestChange(atOrUnder: "dd") == 0)
        #expect(log.latestChange(atOrUnder: "d/other") == 0)

        log.recordChange(at: "")
        #expect(log.latestChange(atOrUnder: "d/other") == log.clock)
    }

    @Test("the change log stays bounded by treating everything as changed")
    func changeLogBound() {
        var log = ChangeLog()
        for index in 0 ... ChangeLog.pathLimit {
            log.recordChange(at: "file\(index)")
        }
        #expect(log.generation(of: "never-changed") == log.clock)
        #expect(log.latestChange(atOrUnder: "never-changed") == log.clock)
    }

    @Test("a request keeps the clock of its first lookup until it ends")
    func requestLogLifecycle() {
        var requests = RequestLog()
        let request = SMB.CacheRequestID()
        requests.begin(request, at: 3)
        requests.begin(request, at: 5)

        #expect(requests.clock(of: request) == 3)
        requests.end(request)
        #expect(requests.clock(of: request) == nil)
        #expect(requests.count == 0)
        #expect(requests.clock(of: SMB.CacheRequestID()) == nil)
    }

    @Test("past the limit the oldest requests are forgotten, so a connection that never ends them cannot grow the log")
    func requestLogBound() {
        var requests = RequestLog()
        let ids = (0 ... RequestLog.limit).map { _ in SMB.CacheRequestID() }
        for (index, id) in ids.enumerated() {
            requests.begin(id, at: UInt64(index))
        }

        #expect(requests.count == RequestLog.limit)
        #expect(requests.clock(of: ids[0]) == nil)
        #expect(requests.clock(of: ids[1]) == 1)

        for _ in 0 ..< 4 * RequestLog.limit {
            requests.begin(SMB.CacheRequestID(), at: 0)
        }
        #expect(requests.count == RequestLog.limit)

        // Requests that end leave nothing behind.
        var prompt = RequestLog()
        for _ in 0 ..< 4 * RequestLog.limit {
            let id = SMB.CacheRequestID()
            prompt.begin(id, at: 1)
            prompt.end(id)
        }
        #expect(prompt.count == 0)
    }

    @Test("the path index finds what is at or under a path, and forgets directories left empty")
    func pathIndex() {
        var index = PathIndex()
        index.insert("one", at: "a/b/c")
        index.insert("two", at: "a/b/c")
        index.insert("three", at: "a/bc")
        index.insert("four", at: "a")
        index.insert("five", at: "x")

        #expect(Set(index.items(atOrUnder: "a")) == ["one", "two", "three", "four"])
        #expect(Set(index.items(atOrUnder: "a/b")) == ["one", "two"])
        #expect(index.items(atOrUnder: "a/b/c/d").isEmpty)
        #expect(Set(index.items(atOrUnder: "")) == ["one", "two", "three", "four", "five"])
        #expect(index.children(of: "a") == ["a/b", "a/bc"])
        #expect(index.items(at: "a/b/c") == ["one", "two"])

        index.remove("one", at: "a/b/c")
        index.remove("two", at: "a/b/c")
        index.remove("two", at: "a/b/c")
        #expect(index.children(of: "a") == ["a/bc"])
        #expect(index.children(of: "a/b").isEmpty)

        for (item, path) in [("three", "a/bc"), ("four", "a"), ("five", "x")] {
            index.remove(item, at: path)
        }
        #expect(index.isEmpty)
        #expect(index.children(of: "").isEmpty)
    }
}
