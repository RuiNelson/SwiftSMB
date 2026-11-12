//
// Part of SwiftSMB
// ReferenceCacheBlockFuzzTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: Model

/// What a ``FileBlocks`` and its written ranges should hold, kept the slow and obvious way: one entry per byte.
private struct ModelBlocks {
    var bytes: [UInt64: UInt8] = [:]
    var uploaded: Set<UInt64> = []

    mutating func write(_ data: Data, at offset: UInt64, isUpload: Bool) {
        for (index, byte) in data.enumerated() {
            let position = offset + UInt64(index)
            bytes[position] = byte
            if isUpload {
                uploaded.insert(position)
            }
            else {
                uploaded.remove(position)
            }
        }
    }

    mutating func keepOnlyUploaded(andBefore end: UInt64) {
        bytes = bytes.filter { uploaded.contains($0.key) || $0.key < end }
        uploaded = []
    }

    mutating func truncate(to size: UInt64) {
        bytes = bytes.filter { $0.key < size }
        uploaded = uploaded.filter { $0 < size }
    }

    /// The maximal runs of consecutive positions among `positions`.
    static func ranges(of positions: some Sequence<UInt64>) -> [Range<UInt64>] {
        var result: [Range<UInt64>] = []
        for position in positions.sorted() {
            if let last = result.last, last.upperBound == position {
                result[result.count - 1] = last.lowerBound ..< position + 1
            }
            else {
                result.append(position ..< position + 1)
            }
        }
        return result
    }

    var ranges: [Range<UInt64>] {
        Self.ranges(of: bytes.keys)
    }

    var uploadedRanges: [Range<UInt64>] {
        Self.ranges(of: uploaded)
    }

    func run(at offset: UInt64, upTo: Int, end: UInt64?) -> Data? {
        guard upTo > 0, bytes[offset] != nil, offset < end ?? .max else {
            return nil
        }

        var result = Data()
        var position = offset
        while result.count < upTo, position < end ?? .max, let byte = bytes[position] {
            result.append(byte)
            position += 1
        }
        return result
    }
}

// MARK: Harness

/// A file's stored bytes and the ranges written to them, kept the way ``SMB/ReferenceCache`` keeps them: the bytes in
/// ``FileBlocks``, the written ranges beside them.
private struct CachedFile {
    var blocks = FileBlocks()
    var uploaded: [Range<UInt64>] = []

    var ranges: [Range<UInt64>] {
        blocks.ranges
    }

    var byteCount: Int {
        blocks.byteCount
    }

    var isEmpty: Bool {
        blocks.isEmpty
    }

    func contains(_ offset: UInt64) -> Bool {
        blocks.contains(offset)
    }

    mutating func write(_ data: Data, at offset: UInt64, isUpload: Bool) {
        guard !data.isEmpty else {
            return
        }
        blocks.write(data, at: offset)
        let range = offset ..< offset + UInt64(data.count)
        uploaded = isUpload ? ByteRanges.union(uploaded, range) : ByteRanges.subtracting(range, from: uploaded)
    }

    /// What a new version keeps: the written ranges, and the bytes before `end`.
    mutating func keepOnlyUploaded(andBefore end: UInt64 = 0) {
        blocks.retain(ByteRanges.union(uploaded, 0 ..< end))
        uploaded = []
    }

    mutating func forgetUploads() {
        uploaded = []
    }

    mutating func truncate(to size: UInt64) {
        blocks.retain(ByteRanges.clamping([0 ..< .max], to: 0 ..< size))
        uploaded = ByteRanges.subtracting(size ..< .max, from: uploaded)
    }

    mutating func removeAll() {
        blocks.removeAll()
        uploaded = []
    }

    /// The run at `offset`, cut at `end` the way the cache cuts it at the file's known size.
    func run(at offset: UInt64, upTo: Int, end: UInt64?) -> Data? {
        var limit = upTo
        if let end {
            guard offset < end, upTo > 0 else {
                return nil
            }
            limit = Int(min(UInt64(upTo), end - offset))
        }
        return blocks.run(at: offset, upTo: limit)
    }

    func invariantViolations() -> [String] {
        var violations = blocks.invariantViolations()
        var previousUpper: UInt64?
        for range in uploaded {
            if range.isEmpty {
                violations.append("an empty written range at \(range.lowerBound)")
            }
            if let previousUpper, range.lowerBound <= previousUpper {
                violations.append("the written range \(range) overlaps or touches the one ending at \(previousUpper)")
            }
            previousUpper = range.upperBound

            let covered = blocks.segments.contains { $0.start <= range.lowerBound && $0.end >= range.upperBound }
            if !covered, !range.isEmpty {
                violations.append("the written range \(range) is not stored")
            }
        }
        return violations
    }
}

// MARK: Tests

@Suite("ReferenceCache: block storage against a model")
struct ReferenceCacheBlockFuzzTests {
    /// Where the positions of a run start: at the start of a file, past four gigabytes, and as far as positions go.
    static let bases: [UInt64] = [0, 0, 1 << 32, UInt64(Int.max) - 150, .max - 1000]

    @Test(
        "random writes, truncations, and version changes leave the runs a per-byte model predicts",
        arguments: CacheFuzz.seeds(300)
    )
    func blocksMatchModel(seed: UInt64) {
        var generator = SeededGenerator(seed: seed)
        let base = generator.pick(Self.bases)
        var blocks = CachedFile()
        var model = ModelBlocks()
        var saved: (blocks: CachedFile, model: ModelBlocks, step: Int)?
        var handedOut: [(run: Data, copy: [UInt8], step: Int)] = []

        /// A position in a window narrow enough for writes to overlap, touch, and leave gaps.
        func position(_ generator: inout SeededGenerator) -> UInt64 {
            base + UInt64(generator.int(0 ... 260))
        }

        for step in 0 ..< 400 {
            var description: String

            switch generator.int(0 ... 99) {
            case 0 ..< 60:
                let offset = position(&generator)
                let longest = generator.pick([1, 3, 12, 40, 90])
                let count = generator.int(1 ... longest)
                let isUpload = generator.chance(0.4)

                // A slice of a larger buffer: its indices do not start at zero.
                let lead = generator.pick([0, 0, 1, 7])
                let whole = generator.bytes(lead + count + 3)
                let data = whole[lead ..< lead + count]

                blocks.write(data, at: offset, isUpload: isUpload)
                model.write(data, at: offset, isUpload: isUpload)
                description = "write \(count) bytes at +\(offset - base), upload: \(isUpload), slice from \(lead)"

            case 60 ..< 70:
                let size = position(&generator)
                blocks.truncate(to: size)
                model.truncate(to: size)
                description = "truncate to +\(size - base)"

            case 70 ..< 78:
                let end = generator.chance(0.5) ? 0 : position(&generator)
                blocks.keepOnlyUploaded(andBefore: end)
                model.keepOnlyUploaded(andBefore: end)
                description = "keepOnlyUploaded(andBefore: \(end))"

            case 78 ..< 84:
                blocks.forgetUploads()
                model.uploaded = []
                description = "forgetUploads"

            case 84 ..< 86:
                blocks.removeAll()
                model = ModelBlocks()
                description = "removeAll"

            case 86 ..< 92:
                // A copy taken now must not see what happens to the original later.
                saved = (blocks, model, step)
                description = "copy"

            default:
                let offset = position(&generator)
                let upTo = generator.int(1 ... 120)
                let end: UInt64? = generator.chance(0.5) ? nil : position(&generator)
                let run = blocks.run(at: offset, upTo: upTo, end: end)
                description = "run(at: +\(offset - base), upTo: \(upTo), end: \(end.map { "+\($0 - base)" } ?? "nil"))"

                guard run == model.run(at: offset, upTo: upTo, end: end) else {
                    Issue.record("seed \(seed), step \(step): \(description) returned the wrong bytes")
                    return
                }
                if let run {
                    guard run.startIndex == 0 else {
                        Issue.record("seed \(seed), step \(step): \(description) is not indexed from zero")
                        return
                    }
                    handedOut.append((run, Array(run), step))
                }
            }

            let violations = blocks.invariantViolations()
            guard violations.isEmpty else {
                Issue.record("seed \(seed), step \(step), after \(description): \(violations)")
                return
            }
            guard blocks.ranges == model.ranges, blocks.byteCount == model.bytes.count,
                  blocks.uploaded == model.uploadedRanges, blocks.isEmpty == model.bytes.isEmpty else {
                Issue.record(
                    """
                    seed \(seed), step \(step), after \(description): the runs are \(blocks.ranges) with written \
                    ranges \(blocks.uploaded), expected \(model.ranges) with \(model.uploadedRanges)
                    """
                )
                return
            }

            for range in blocks.ranges {
                let held = blocks.run(at: range.lowerBound, upTo: Int(range.count), end: nil)
                let expected = model.run(at: range.lowerBound, upTo: Int(range.count), end: nil)
                guard held == expected else {
                    Issue.record("seed \(seed), step \(step), after \(description): wrong bytes in \(range)")
                    return
                }
            }

            let probe = position(&generator)
            guard blocks.contains(probe) == (model.bytes[probe] != nil) else {
                Issue.record("seed \(seed), step \(step), after \(description): contains(+\(probe - base)) is wrong")
                return
            }
        }

        if let saved {
            #expect(saved.blocks.ranges == saved.model.ranges, "seed \(seed): a copy from step \(saved.step) changed")
            for range in saved.blocks.ranges {
                #expect(
                    saved.blocks.run(at: range.lowerBound, upTo: Int(range.count), end: nil)
                        == saved.model.run(at: range.lowerBound, upTo: Int(range.count), end: nil),
                    "seed \(seed): the bytes of a copy from step \(saved.step) changed"
                )
            }
        }

        // Bytes handed out are the caller's: later writes must not reach into them.
        for (run, copy, step) in handedOut {
            #expect(Array(run) == copy, "seed \(seed): bytes handed out at step \(step) changed afterwards")
        }
    }

    @Test("ranges add and subtract like sets of positions", arguments: CacheFuzz.seeds(200))
    func rangeArithmetic(seed: UInt64) {
        var generator = SeededGenerator(seed: seed)
        var ranges: [Range<UInt64>] = []
        var positions = Set<UInt64>()

        for step in 0 ..< 60 {
            let lower = UInt64(generator.int(0 ... 80))
            let range = lower ..< lower + UInt64(generator.int(0 ... 25))

            if generator.chance(0.6) {
                guard !range.isEmpty else {
                    continue
                }
                ranges = ByteRanges.union(ranges, range)
                positions.formUnion(range)
            }
            else {
                ranges = ByteRanges.subtracting(range, from: ranges)
                positions.subtract(range)
            }

            guard ranges == ModelBlocks.ranges(of: positions) else {
                Issue.record("seed \(seed), step \(step): \(ranges), expected \(ModelBlocks.ranges(of: positions))")
                return
            }
        }
    }

    @Test("writes at the edges of runs: empty, touching on either side, spanning many, and exactly over one")
    func writeEdges() {
        var blocks = CachedFile()
        blocks.write(Data(), at: 10, isUpload: true)
        #expect(blocks.isEmpty && blocks.uploaded.isEmpty)

        blocks.write(CacheFuzz.bytes(10, from: 20), at: 20, isUpload: false)
        blocks.write(CacheFuzz.bytes(10, from: 40), at: 40, isUpload: false)
        blocks.write(CacheFuzz.bytes(10, from: 60), at: 60, isUpload: false)
        #expect(blocks.ranges == [20 ..< 30, 40 ..< 50, 60 ..< 70])

        // Touching the start of a run, then the end of one: each joins.
        blocks.write(CacheFuzz.bytes(5, from: 15), at: 15, isUpload: false)
        blocks.write(CacheFuzz.bytes(5, from: 70), at: 70, isUpload: false)
        #expect(blocks.ranges == [15 ..< 30, 40 ..< 50, 60 ..< 75])

        // Exactly over one run, replaced in place.
        blocks.write(Data(repeating: 0xAA, count: 10), at: 40, isUpload: true)
        #expect(blocks.ranges == [15 ..< 30, 40 ..< 50, 60 ..< 75])
        #expect(blocks.run(at: 40, upTo: 100, end: nil) == Data(repeating: 0xAA, count: 10))

        // One write from inside the first run to inside the last.
        blocks.write(Data(repeating: 0xBB, count: 45), at: 25, isUpload: false)
        #expect(blocks.ranges == [15 ..< 75])
        #expect(blocks.byteCount == 60)
        #expect(blocks.uploaded.isEmpty)
        #expect(
            blocks.run(at: 15, upTo: 100, end: nil)
                == CacheFuzz.bytes(10, from: 15) + Data(repeating: 0xBB, count: 45) + CacheFuzz.bytes(5, from: 70)
        )
        #expect(blocks.invariantViolations() == [])
    }

    @Test("a run is cut at the end it is given, and nothing is handed out from that end on")
    func runEnds() {
        var blocks = CachedFile()
        blocks.write(CacheFuzz.bytes(20, from: 10), at: 10, isUpload: false)

        #expect(blocks.run(at: 10, upTo: 100, end: 15) == CacheFuzz.bytes(5, from: 10))
        #expect(blocks.run(at: 14, upTo: 100, end: 15) == CacheFuzz.bytes(1, from: 14))
        #expect(blocks.run(at: 15, upTo: 100, end: 15) == nil)
        #expect(blocks.run(at: 20, upTo: 100, end: 12) == nil)
        #expect(blocks.run(at: 10, upTo: 100, end: 0) == nil)
        #expect(blocks.run(at: 10, upTo: 0, end: nil) == nil)
        #expect(blocks.run(at: 10, upTo: -1, end: nil) == nil)
        #expect(blocks.run(at: 9, upTo: 100, end: nil) == nil)
        #expect(blocks.run(at: 30, upTo: 100, end: nil) == nil)
        #expect(blocks.run(at: 29, upTo: .max, end: .max) == CacheFuzz.bytes(1, from: 29))
    }

    @Test("truncating at, inside, and past runs, and keeping written ranges that split a run")
    func truncateAndKeepEdges() {
        var blocks = CachedFile()
        blocks.write(CacheFuzz.bytes(10, from: 0), at: 0, isUpload: false)
        blocks.write(CacheFuzz.bytes(10, from: 20), at: 20, isUpload: true)

        blocks.truncate(to: 100)
        #expect(blocks.ranges == [0 ..< 10, 20 ..< 30])
        blocks.truncate(to: 30)
        #expect(blocks.ranges == [0 ..< 10, 20 ..< 30])
        blocks.truncate(to: 25)
        #expect(blocks.ranges == [0 ..< 10, 20 ..< 25])
        #expect(blocks.uploaded == [20 ..< 25])
        blocks.truncate(to: 20)
        #expect(blocks.ranges == [0 ..< 10])
        #expect(blocks.uploaded.isEmpty)
        blocks.truncate(to: 0)
        #expect(blocks.isEmpty && blocks.byteCount == 0)

        // Written ranges in the middle of a downloaded run: only they survive a new version.
        blocks.write(CacheFuzz.bytes(100), at: 0, isUpload: false)
        blocks.write(Data(repeating: 1, count: 5), at: 10, isUpload: true)
        blocks.write(Data(repeating: 2, count: 5), at: 15, isUpload: true)
        blocks.write(Data(repeating: 3, count: 5), at: 50, isUpload: true)
        #expect(blocks.uploaded == [10 ..< 20, 50 ..< 55])

        var appended = blocks
        blocks.keepOnlyUploaded()
        #expect(blocks.ranges == [10 ..< 20, 50 ..< 55])
        #expect(blocks.byteCount == 15)

        // Bytes before the old end of an appended file stay too, joined to the written ranges they touch.
        appended.keepOnlyUploaded(andBefore: 12)
        #expect(appended.ranges == [0 ..< 20, 50 ..< 55])
        #expect(appended.run(at: 0, upTo: 100, end: nil) == CacheFuzz.bytes(10) + Data(repeating: 1, count: 5)
            + Data(repeating: 2, count: 5))
        #expect(appended.invariantViolations() == [])
        #expect(blocks.invariantViolations() == [])
    }

    @Test("positions up to the last one a file can have are stored and read back")
    func farPositions() {
        var blocks = CachedFile()
        let far = UInt64.max - 20

        // The last byte a file can hold is at `.max - 1`: the run ends at `.max`.
        blocks.write(CacheFuzz.bytes(10), at: far, isUpload: true)
        blocks.write(CacheFuzz.bytes(10, from: 10), at: far + 10, isUpload: false)
        #expect(blocks.ranges == [far ..< .max])
        #expect(blocks.run(at: far + 5, upTo: .max, end: nil) == CacheFuzz.bytes(15, from: 5))
        #expect(blocks.run(at: far + 5, upTo: .max, end: .max) == CacheFuzz.bytes(15, from: 5))
        #expect(blocks.contains(.max - 1))
        #expect(!blocks.contains(.max))

        blocks.truncate(to: far + 3)
        #expect(blocks.ranges == [far ..< far + 3])
        #expect(blocks.uploaded == [far ..< far + 3])
        #expect(blocks.invariantViolations() == [])
    }
}

// MARK: Sampled blocks

@Suite("ReferenceCache: blocks picked for sampleBlocks checks")
struct ReferenceCacheSampleFuzzTests {
    @Test("the bisection position of every block is where the order emits it")
    func bisectionPositions() {
        for blockCount in Array(UInt64(1) ... 300) + [511, 512, 513, 1000, 4097] {
            for (position, index) in FileCompareBlockOrder(blockCount: blockCount, scan: .bisection).enumerated() {
                let found = SMB.ReferenceCache.bisectionPosition(of: index, blockCount: blockCount)
                guard found == UInt64(position) else {
                    Issue.record("block \(index) of \(blockCount): position \(found), emitted at \(position)")
                    return
                }
            }
        }
    }

    @Test("the block holding a byte is the one whose range holds it")
    func blockIndices() {
        for size: UInt64 in [1, 2, 16383, 16384, 16385, 100_000, 1 << 20, 5_000_001] {
            let grid = FileCompareGrid(size: size, maximumBlockSize: SMB.ReferenceCache.sampleLength)
            for index in [0, grid.blockCount / 2, grid.blockCount - 1] {
                let start = grid.offset(index)
                let end = start + grid.length(index)
                for offset in [start, end - 1, start + (end - start) / 2] {
                    #expect(SMB.ReferenceCache.blockIndex(containing: offset, of: grid) == index, "\(size) \(offset)")
                }
            }
        }
    }

    @Test(
        "a check takes the next cached whole blocks in scan order from where the last one stopped, wrapping around",
        arguments: CacheFuzz.seeds(200)
    )
    func samplePlanMatchesModel(seed: UInt64) {
        var generator = SeededGenerator(seed: seed)
        let size = UInt64(generator.pick([1, 100, 16384, 16385, 50000, 200_000, 1_000_003]))
        let scan = generator.pick([SMB.FileCompareScan.startToEnd, .endToStart, .bisection])
        let grid = FileCompareGrid(size: size, maximumBlockSize: SMB.ReferenceCache.sampleLength)

        var cached: [Range<UInt64>] = []
        for _ in 0 ..< generator.int(0 ... 8) {
            let lower = UInt64(generator.int(0 ... Int(size - 1)))
            let length = UInt64(generator.int(1 ... 60000))
            cached = ByteRanges.union(cached, lower ..< min(size, lower + length))
        }

        // The model walks the whole order.
        let order = Array(FileCompareBlockOrder(blockCount: grid.blockCount, scan: scan))
        let whole = order.enumerated().filter { _, index in
            let block = grid.offset(index) ..< grid.offset(index) + grid.length(index)
            return cached.contains { $0.lowerBound <= block.lowerBound && $0.upperBound >= block.upperBound }
        }

        var cursor = UInt64(generator.int(0 ... 3 * Int(grid.blockCount)))
        var compared: [UInt64] = []
        for round in 0 ..< 6 {
            let count = generator.int(1 ... 4)
            let start = cursor % grid.blockCount
            let rotated = whole.filter { UInt64($0.offset) >= start } + whole.filter { UInt64($0.offset) < start }
            let expected = rotated.prefix(count)
            let expectedCursor = expected.count == count
                ? (UInt64(expected.last!.offset) + 1) % grid.blockCount
                : start

            let plan = SMB.ReferenceCache.samplePlan(
                size: size,
                cached: cached,
                cursor: cursor,
                count: count,
                scan: scan
            )
            let expectedBlocks = expected
                .map { grid.offset($0.element) ..< grid.offset($0.element) + grid.length($0.element) }
            guard plan.blocks == expectedBlocks, plan.cursor == expectedCursor else {
                Issue.record(
                    """
                    seed \(seed), round \(round), size \(size), \(scan), cursor \(cursor), count \(count): \
                    \(plan.blocks) next \(plan.cursor), expected \(expectedBlocks) next \(expectedCursor)
                    """
                )
                return
            }
            compared += expected.map(\.element)
            cursor = plan.cursor
        }

        // Checks made often enough compare every cached block.
        if whole.count <= 6 {
            #expect(Set(compared) == Set(whole.map(\.element)), "seed \(seed)")
        }
    }

    @Test("nothing to sample in an empty file, an empty storage, or for no blocks")
    func nothingToSample() {
        #expect(SMB.ReferenceCache.samplePlan(size: 0, cached: [], cursor: 5, count: 3, scan: .bisection).blocks
            .isEmpty)
        let none = SMB.ReferenceCache.samplePlan(size: 100_000, cached: [], cursor: 5, count: 3, scan: .bisection)
        #expect(none.blocks.isEmpty && none.cursor == 5)
        #expect(SMB.ReferenceCache.samplePlan(size: 100, cached: [0 ..< 100], cursor: 0, count: 0, scan: .bisection)
            .blocks.isEmpty)

        // A partial block is never compared: the server would hold more bytes of it than the cache.
        let partial = SMB.ReferenceCache.samplePlan(
            size: 40000,
            cached: [0 ..< 13333, 13334 ..< 40000],
            cursor: 0,
            count: 3,
            scan: .startToEnd
        )
        #expect(partial.blocks == [13334 ..< 26667, 26667 ..< 40000])
        #expect(partial.cursor == 0)
    }
}
