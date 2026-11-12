//
// Part of SwiftSMB
// ReferenceCachePathMatchingTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

private typealias Fuzz = CacheFuzz

/// One name spelled two ways: `é` as one scalar, and as `e` followed by a combining accent. Windows and Samba hold them
/// as two files, macOS as one, while `String` calls them equal.
private let composed = "d/caf\u{E9}.txt"
private let decomposed = "d/cafe\u{301}.txt"

// MARK: Keys

@Suite("ReferenceCache: path keys")
struct ReferenceCachePathKeyTests {
    @Test("paths are normalized relative to the share root, with backslashes as separators")
    func normalization() {
        let spellings = [
            "a/b/f",
            "/a/b/f",
            "a//b/f",
            "a/b/f/",
            "./a/b/f",
            "a/./b/f",
            "a/x/../b/f",
            "../a/b/f",
            #"a\b\f"#,
        ]
        for spelling in spellings {
            #expect(CachePath.normalize(spelling) == "a/b/f", "\(spelling)")
        }
        for root in ["", "/", ".", "..", "a/..", "//"] {
            #expect(CachePath.normalize(root) == "", "\(root)")
        }
    }

    @Test("exact keys tell apart every byte, normalization included, and stand for their path")
    func exactKeys() {
        #expect(CachePath.exactKey(composed) != CachePath.exactKey(decomposed))
        #expect(CachePath.exactKey("A") != CachePath.exactKey("a"))
        #expect(CachePath.exactKey("100%") == "100%25")
        for path in [composed, decomposed, "100%/x", "\u{1F600}/a"] {
            let key = CachePath.exactKey(path)
            #expect(key.utf8.allSatisfy { $0 < 0x80 })
            #expect(CachePath.sameBytes(CachePath.path(ofExactKey: key), path))
        }
    }

    @Test("case-insensitive keys fold case scalar by scalar, as SMB servers do, and keep normalization apart")
    func caseInsensitiveKeys() {
        let same: [(String, String)] = [
            ("Photos/A.jpg", "photos/a.JPG"),
            ("\u{C9}t\u{E9}", "\u{E9}T\u{C9}"),
            // Dotless i and i both have I as their uppercase.
            ("f\u{131}le", "FILE"),
            // Final and medial sigma.
            ("\u{3C2}", "\u{3C3}"),
        ]
        for (first, second) in same {
            #expect(CachePath.caseInsensitiveKey(first) == CachePath.caseInsensitiveKey(second), "\(first) \(second)")
        }

        // Sharp s has no one-scalar uppercase: it stays itself.
        #expect(CachePath.caseInsensitiveKey("stra\u{DF}e") != CachePath.caseInsensitiveKey("STRASSE"))
        #expect(CachePath.caseInsensitiveKey(composed) != CachePath.caseInsensitiveKey(decomposed))
        #expect(CachePath.caseInsensitiveKey("a/b").split(separator: "/").count == 2)
    }

    @Test("equivalence keys are shared by every spelling a share may take for one name")
    func equivalenceKeys() {
        let same: [(String, String)] = [
            (composed, decomposed),
            ("Photos/A.jpg", "photos/a.JPG"),
            ("stra\u{DF}e", "STRASSE"),
            ("f\u{131}le", "file"),
            ("D/CAFE\u{301}.TXT", composed),
        ]
        for (first, second) in same {
            #expect(CachePath.equivalenceKey(first) == CachePath.equivalenceKey(second), "\(first) \(second)")
        }
        #expect(CachePath.equivalenceKey("a/b") != CachePath.equivalenceKey("a/c"))

        // Whatever two spellings share a case-insensitive key share an equivalence key.
        for (first, second) in [("f\u{131}le", "FILE"), ("\u{3C2}", "\u{3A3}"), ("\u{1C5}", "\u{1C6}")] {
            #expect(CachePath.caseInsensitiveKey(first) == CachePath.caseInsensitiveKey(second))
            #expect(CachePath.equivalenceKey(first) == CachePath.equivalenceKey(second))
        }
    }

    @Test("path arithmetic works on the share root and on whole components")
    func arithmetic() {
        #expect(CachePath.parent(of: "a/b/c") == "a/b")
        #expect(CachePath.parent(of: "a") == "")
        #expect(CachePath.parent(of: "") == "")
        #expect(CachePath.ancestors(of: "a/b/c") == ["a/b", "a", ""])
        #expect(CachePath.ancestors(of: "").isEmpty)
        #expect(CachePath.isPath("a/b", atOrUnder: ""))
        #expect(CachePath.isPath("a/b", atOrUnder: "a"))
        #expect(!CachePath.isPath("ab", atOrUnder: "a"))
        #expect(CachePath.rebase("a/b/c", from: "a", to: "x/y") == "x/y/b/c")
        #expect(CachePath.rebase("a", from: "a", to: "x") == "x")
        #expect(CachePath.rebase("a/b", from: "a", to: "") == "b")
        #expect(CachePath.rebase("A/b", from: "a", to: "x") == "x/b")
        #expect(CachePath.child("f", of: "") == "f")
        #expect(CachePath.child("f", of: "d") == "d/f")
        for name in ["", ".", "..", "a/b", #"a\b"#] {
            #expect(CachePath.child(name, of: "d") == nil)
        }
    }
}

// MARK: Exact matching

@Suite("ReferenceCache: exact path matching")
struct ReferenceCacheExactMatchingTests {
    @Test("names that differ in case or Unicode normalization are files of their own, with bytes of their own")
    func spellingsKeepTheirBytesApart() async {
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: composed, contents: Fuzz.bytes(40, from: 1))

        // Another spelling, of the same size and times, none of whose bytes the cache has seen.
        for other in [decomposed, "D/CAF\u{C9}.TXT"] {
            await Fuzz.stat(cache, Fuzz.file(size: 40), path: other)
            #expect(await Fuzz.retrieve(cache, path: other, upTo: 40) == nil)
        }

        await Fuzz.download(cache, Fuzz.bytes(40, from: 100), path: decomposed)
        #expect(await Fuzz.retrieve(cache, path: composed, upTo: 40) == Fuzz.bytes(40, from: 1))
        #expect(await Fuzz.retrieve(cache, path: decomposed, upTo: 40) == Fuzz.bytes(40, from: 100))
        #expect(await cache.invariantViolations() == [])
    }

    @Test(
        "a change under one spelling drops what every spelling holds",
        arguments: ["invalidate", "rename away", "rename onto", "write", "append"]
    )
    func changesReachEverySpelling(change: String) async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        let spellings = ["Photos/IMG.jpg", "photos/img.JPG", "PHOTOS/img.jpg", "Photos/IMG.jpg/inside"]
        for (index, spelling) in spellings.enumerated() {
            await Fuzz.cacheFile(cache, path: spelling, contents: Fuzz.bytes(10, from: index))
        }
        await Fuzz.cacheFile(cache, path: "Photos/other.jpg", contents: Fuzz.bytes(10))
        await Fuzz.list(cache, [Fuzz.entry("img.JPG", Fuzz.file(size: 10))], path: "photos")
        #expect(await cache.files.count == 5)
        #expect(await Fuzz.cachedListing(cache, path: "photos") != nil)

        let changed = "photos/IMG.JPG"
        switch change {
        case "invalidate":
            await cache.invalidate(path: changed)

        case "rename away":
            await cache.didRename(from: changed, to: "elsewhere")

        case "rename onto":
            await cache.didRename(from: "elsewhere", to: changed)

        case "write":
            await Fuzz.upload(cache, Fuzz.bytes(5), path: changed)

        default:
            await cache.didAppend(path: changed, byteCount: 5)
        }

        for spelling in spellings {
            #expect(await cache.cachedRanges(path: spelling) == [], "\(spelling)")
            #expect(await Fuzz.cachedStat(cache, path: spelling) == nil, "\(spelling)")
        }
        #expect(await cache.cachedRanges(path: "Photos/other.jpg") == [0 ..< 10])
        #expect(await Fuzz.cachedListing(cache, path: "photos") == nil)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a change to a directory reaches the files under every spelling of it")
    func directoryChangesReachEverySpelling() async {
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: "Albums/2024/a.jpg", contents: Fuzz.bytes(10))
        await Fuzz.cacheFile(cache, path: "albums/2024/b.jpg", contents: Fuzz.bytes(10))
        await Fuzz.cacheFile(cache, path: "albums2/c.jpg", contents: Fuzz.bytes(10))

        await cache.invalidate(path: "ALBUMS")
        #expect(await cache.trackedPaths == ["albums2/c.jpg"])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a rename that only changes case moves the bytes to the new spelling, and drops the others")
    func caseOnlyRename() async {
        let cache = Fuzz.makeCache()
        await Fuzz.cacheFile(cache, path: "d/Report.txt", contents: Fuzz.bytes(10, from: 1))
        await Fuzz.cacheFile(cache, path: "d/REPORT.txt", contents: Fuzz.bytes(10, from: 2))

        await cache.didRename(from: "d/Report.txt", to: "d/report.txt")
        #expect(await cache.trackedPaths == ["d/report.txt"])
        #expect(await Fuzz.retrieve(cache, path: "d/report.txt", upTo: 10) == Fuzz.bytes(10, from: 1))
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a stat or a listing of one spelling answers for no other, and no listing denies a spelling it may hold")
    func spellingsKeepTheirMetadataApart() async {
        let file = Fuzz.file(size: 40)

        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        await Fuzz.stat(cache, file, path: composed)
        #expect(await Fuzz.cachedStat(cache, path: decomposed) == nil)
        #expect(await Fuzz.cachedStat(cache, path: "D/CAF\u{C9}.TXT") == nil)

        // The listing shows one spelling: the share may hold the others under it, so it does not say they are missing.
        let listed = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        await Fuzz.list(listed, [Fuzz.entry("caf\u{E9}.txt", file)], path: "d")
        #expect(await Fuzz.cachedStat(listed, path: composed) == .exists(file))
        #expect(await Fuzz.cachedStat(listed, path: decomposed) == nil)
        #expect(await Fuzz.cachedStat(listed, path: "d/CAF\u{C9}.txt") == nil)
        #expect(await Fuzz.cachedStat(listed, path: "d/other.txt") == .doesNotExist)
    }

    @Test("a stat of one spelling showing another version drops what other spellings hold of the file")
    func versionsReachEverySpelling() async {
        let cache = Fuzz.makeCache(metadata: .answer(for: 60, includingMissing: true))
        await Fuzz.cacheFile(cache, path: "d/A.jpg", contents: Fuzz.bytes(10))
        await Fuzz.list(cache, [Fuzz.entry("A.jpg", Fuzz.file(size: 10))], path: "d")

        // The same version leaves them; another one drops them, and the listing that shows the old one.
        await Fuzz.stat(cache, Fuzz.file(size: 10), path: "d/a.jpg")
        #expect(await cache.cachedRanges(path: "d/A.jpg") == [0 ..< 10])
        // The stat of an open file: the stored one would answer a lookup.
        await cache.storeStat(Fuzz.file(size: 12, modificationTime: 2000), path: "d/a.jpg", request: nil)
        #expect(await cache.cachedRanges(path: "d/A.jpg") == [])
        #expect(await Fuzz.cachedListing(cache, path: "d") == nil)

        // So does a listing.
        await Fuzz.cacheFile(cache, path: "e/B.jpg", contents: Fuzz.bytes(10))
        await Fuzz.list(cache, [Fuzz.entry("b.jpg", Fuzz.file(size: 10, modificationTime: 3000))], path: "e")
        #expect(await cache.cachedRanges(path: "e/B.jpg") == [])
        #expect(await cache.invariantViolations() == [])
    }
}

// MARK: Case-insensitive matching

@Suite("ReferenceCache: case-insensitive path matching")
struct ReferenceCacheCaseInsensitiveMatchingTests {
    static func makeCache(metadata: SMB.ReferenceCache.MetadataPolicy = .neverAnswer) -> SMB.ReferenceCache {
        Fuzz.makeCache(metadata: metadata, pathMatching: .caseInsensitive)
    }

    @Test("spellings that differ only in case share one file, its bytes, and its changes")
    func caseVariantsShareAFile() async {
        let cache = Self.makeCache()
        await Fuzz.cacheFile(cache, path: "Photos/A.jpg", contents: Fuzz.bytes(40))

        #expect(await Fuzz.retrieve(cache, path: "photos/a.JPG", upTo: 40) == Fuzz.bytes(40))
        await Fuzz.upload(cache, Data(repeating: 0xEE, count: 5), path: "PHOTOS/a.jpg", offset: 10)
        #expect(await Fuzz.retrieve(cache, path: "Photos/A.jpg", offset: 10, upTo: 5) == Data(
            repeating: 0xEE,
            count: 5
        ))
        #expect(await cache.files.count == 1)

        await cache.invalidate(path: "photos")
        #expect(await cache.files.isEmpty)
        #expect(await cache.invariantViolations() == [])
    }

    @Test("spellings that differ in normalization are files of their own, and a change to one drops the other")
    func normalizationVariantsStayApart() async {
        let cache = Self.makeCache()
        await Fuzz.cacheFile(cache, path: composed, contents: Fuzz.bytes(40, from: 1))
        await Fuzz.cacheFile(cache, path: decomposed, contents: Fuzz.bytes(40, from: 2))
        #expect(await cache.files.count == 2)
        #expect(await Fuzz.retrieve(cache, path: decomposed.uppercased(), upTo: 40) == Fuzz.bytes(40, from: 2))

        await Fuzz.upload(cache, Fuzz.bytes(1), path: composed)
        #expect(await cache.trackedPaths == [composed])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("a rename that only changes case keeps the bytes, under the new spelling")
    func caseOnlyRename() async {
        let cache = Self.makeCache()
        await Fuzz.cacheFile(cache, path: "Albums/Trip/a.jpg", contents: Fuzz.bytes(10))

        await cache.didRename(from: "Albums/Trip", to: "albums/TRIP")
        #expect(await cache.trackedPaths == ["albums/TRIP/a.jpg"])
        #expect(await Fuzz.retrieve(cache, path: "albums/trip/A.JPG", upTo: 10) == Fuzz.bytes(10))

        // Renamed to itself, nothing happens.
        await cache.didRename(from: "albums/TRIP/a.jpg", to: "albums/TRIP/a.jpg")
        #expect(await cache.trackedPaths == ["albums/TRIP/a.jpg"])
        #expect(await cache.invariantViolations() == [])
    }

    @Test("listings answer for every case of a name, and for none of names they do not tell apart")
    func listings() async {
        let cache = Self.makeCache(metadata: .answer(for: 60, includingMissing: true))
        let file = Fuzz.file(size: 10)
        await Fuzz.list(cache, [Fuzz.entry("Readme.TXT", file)], path: "Docs")

        #expect(await Fuzz.cachedStat(cache, path: "docs/README.txt") == .exists(file))
        #expect(await Fuzz.cachedStat(cache, path: "DOCS/other") == .doesNotExist)
        #expect(await Fuzz.cachedListing(cache, path: "docs")?.map(\.name) == ["Readme.TXT"])

        // A case-sensitive share lists both.
        await Fuzz.list(
            cache,
            [Fuzz.entry("a", Fuzz.file(size: 1)), Fuzz.entry("A", Fuzz.file(size: 2))],
            path: "Mixed"
        )
        #expect(await Fuzz.cachedStat(cache, path: "Mixed/a") == nil)
        #expect(await Fuzz.cachedStat(cache, path: "Mixed/b") == .doesNotExist)

        // A listed name in another normalization may be the asked one.
        await Fuzz.list(cache, [Fuzz.entry("caf\u{E9}.txt", file)], path: "d")
        #expect(await Fuzz.cachedStat(cache, path: decomposed) == nil)
    }
}

// MARK: Cost

@Suite("ReferenceCache: cost of reaching equivalent paths")
struct ReferenceCacheEquivalenceCostTests {
    @Test("a change does not take longer the more files the cache tracks elsewhere")
    func changeCost() async {
        /// How long 200 changes to paths the cache tracks nothing at take.
        func cost(tracking count: Int) async -> Duration {
            let cache = Fuzz.makeCache()
            await cache.trackFiles(under: "tracked", count: count)

            let clock = ContinuousClock()
            let start = clock.now
            for index in 0 ..< 200 {
                await cache.invalidate(path: "changed/Directory\(index)/File")
                await Fuzz.upload(cache, Fuzz.bytes(1), path: "written/File\(index)")
            }
            return clock.now - start
        }

        let few = await cost(tracking: 10)
        let many = await cost(tracking: SMB.ReferenceCache.entryLimit)

        // Generous, so that a busy machine does not fail it: a scan of every tracked file per change costs far more.
        #expect(many < few * 20 + .milliseconds(200), "\(many) with every file tracked, \(few) with ten")
    }
}
