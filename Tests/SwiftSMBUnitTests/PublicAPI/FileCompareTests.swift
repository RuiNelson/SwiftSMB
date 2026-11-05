//
// Part of SwiftSMB
// FileCompareTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

private let allScans: [SMB.FileCompareScan] = [.startToEnd, .endToStart, .bisection]

@Suite("CompareFiles: block order")
struct FileCompareBlockOrderTests {
    @Test("every scan visits each block exactly once", arguments: allScans)
    func everyScanIsAPermutation(scan: SMB.FileCompareScan) {
        for count in UInt64(0) ... 300 {
            let order = Array(FileCompareBlockOrder(blockCount: count, scan: scan))
            #expect(order.count == Int(count))
            #expect(Set(order) == Set(0 ..< count))
        }
    }

    @Test("linear scans run forwards and backwards")
    func linearScans() {
        #expect(Array(FileCompareBlockOrder(blockCount: 4, scan: .startToEnd)) == [0, 1, 2, 3])
        #expect(Array(FileCompareBlockOrder(blockCount: 4, scan: .endToStart)) == [3, 2, 1, 0])
    }

    @Test("an exhausted order keeps returning nil", arguments: allScans)
    func exhaustedOrderStaysExhausted(scan: SMB.FileCompareScan) {
        var order = FileCompareBlockOrder(blockCount: 5, scan: scan)
        while order.next() != nil {
        }
        #expect(order.next() == nil)
        #expect(order.next() == nil)
    }

    @Test("scans describe themselves")
    func debugDescriptions() {
        #expect(allScans.map(\.debugDescription) == [
            "SMB.FileCompareScan.startToEnd",
            "SMB.FileCompareScan.endToStart",
            "SMB.FileCompareScan.bisection",
        ])
    }
}

@Suite("CompareFiles: bisection")
struct FileCompareBisectionTests {
    private func bisection(_ count: UInt64) -> [UInt64] {
        Array(FileCompareBlockOrder(blockCount: count, scan: .bisection))
    }

    @Test("small grids follow the exact breadth-first order")
    func exactOrders() {
        #expect(bisection(0) == [])
        #expect(bisection(1) == [0])
        #expect(bisection(2) == [0, 1])
        #expect(bisection(3) == [0, 2, 1])
        #expect(bisection(4) == [0, 3, 1, 2])
        #expect(bisection(5) == [0, 4, 2, 1, 3])
        #expect(bisection(8) == [0, 7, 3, 1, 5, 2, 4, 6])
        #expect(bisection(11) == [0, 10, 5, 2, 7, 1, 3, 6, 8, 4, 9])
        #expect(bisection(16) == [0, 15, 7, 3, 11, 1, 5, 9, 13, 2, 4, 6, 8, 10, 12, 14])
    }

    @Test("starts with the first and the last block", arguments: [UInt64(2), 3, 10, 1000, 1 << 40, .max])
    func startsWithEnds(count: UInt64) {
        var order = FileCompareBlockOrder(blockCount: count, scan: .bisection)
        #expect(order.next() == 0)
        let last = count - 1
        #expect(order.next() == last)
    }

    @Test("visits every block exactly once", arguments: [UInt64(0), 1, 2, 3, 7, 64, 65, 1023, 1024, 1025, 100_003])
    func isAPermutation(count: UInt64) {
        var seen = Set<UInt64>()
        for index in FileCompareBlockOrder(blockCount: count, scan: .bisection) {
            #expect(index < count)
            #expect(seen.insert(index).inserted, "block \(index) visited twice")
        }
        #expect(seen.count == Int(count))
    }

    @Test("each block after the ends is the middle of the gap it splits")
    func splitsGapsAtTheMiddle() {
        for count in UInt64(3) ... 200 {
            var visited: [UInt64] = []
            for (position, index) in bisection(count).enumerated() {
                let insertion = visited.firstIndex { $0 > index } ?? visited.endIndex
                if position >= 2 {
                    let lower = visited[insertion - 1]
                    let upper = visited[insertion]
                    let middle = lower + (upper - lower) / 2
                    #expect(index == middle, "count \(count), block \(index)")
                }
                visited.insert(index, at: insertion)
            }
        }
    }

    @Test("each pass halves the largest gap left uncompared")
    func passesHalveTheLargestGap() {
        for count in UInt64(3) ... 300 {
            let order = bisection(count)
            var pass = 1
            // The ends, then 1, 2, 4, … middles per pass: pass `p` completes after 2 + (2^p - 1) blocks.
            while 2 + (1 << pass) - 1 <= order.count {
                let prefix = order.prefix(2 + (1 << pass) - 1).sorted()
                let largestGap = zip(prefix, prefix.dropFirst()).map { $1 - $0 }.max() ?? 0
                let bound = (count - 1 + (1 << pass) - 1) >> pass
                #expect(largestGap <= bound, "count \(count), pass \(pass)")
                pass += 1
            }
        }
    }

    @Test("is deterministic")
    func isDeterministic() {
        #expect(bisection(1234) == bisection(1234))
    }

    @Test("starts lazily on grids too large to enumerate")
    func lazyOnHugeGrids() {
        let count = UInt64.max
        let prefix = Array(FileCompareBlockOrder(blockCount: count, scan: .bisection).prefix(5))
        let middle = (count - 1) / 2
        let expected = [0, count - 1, middle, middle / 2, middle + (count - 1 - middle) / 2]
        #expect(prefix == expected)
    }
}

@Suite("CompareFiles: block grid")
struct FileCompareGridTests {
    private func lengths(_ grid: FileCompareGrid) -> [UInt64] {
        (0 ..< grid.blockCount).map(grid.length)
    }

    @Test("splits a file into equal blocks without a short last one")
    func equalBlocks() {
        let grid = FileCompareGrid(size: 10500, maximumBlockSize: 1000)
        #expect(grid.blockCount == 11)
        #expect(lengths(grid) == Array(repeating: 955, count: 6) + Array(repeating: 954, count: 5))
        #expect(grid.offset(6) == 6 * 955)
        #expect(grid.offset(11) == 10500)
    }

    @Test("an exact multiple keeps the maximum block size")
    func exactMultiple() {
        let grid = FileCompareGrid(size: 3000, maximumBlockSize: 1000)
        #expect(lengths(grid) == [1000, 1000, 1000])
        #expect((0 ... 3).map(grid.offset) == [0, 1000, 2000, 3000])
    }

    @Test("small files and empty files")
    func smallFiles() {
        #expect(FileCompareGrid(size: 0, maximumBlockSize: 1000).blockCount == 0)
        #expect(lengths(FileCompareGrid(size: 1, maximumBlockSize: 1000)) == [1])
        #expect(lengths(FileCompareGrid(size: 999, maximumBlockSize: 1000)) == [999])
        #expect(lengths(FileCompareGrid(size: 1001, maximumBlockSize: 1000)) == [501, 500])
        #expect(lengths(FileCompareGrid(size: 5, maximumBlockSize: 1)) == [1, 1, 1, 1, 1])
    }

    @Test("blocks tile the file, use the fewest blocks and differ by at most one byte")
    func gridProperties() {
        for maximum in UInt64(1) ... 40 {
            for size in UInt64(0) ... 400 {
                let grid = FileCompareGrid(size: size, maximumBlockSize: maximum)
                let context: Comment = "size \(size), maximum \(maximum)"
                let fewestBlocks = (size + maximum - 1) / maximum
                #expect(grid.blockCount == fewestBlocks, context)
                #expect(grid.offset(0) == 0, context)
                #expect(grid.offset(grid.blockCount) == size, context)

                let blockLengths = lengths(grid)
                for index in 0 ..< grid.blockCount {
                    let end = grid.offset(index) + grid.length(index)
                    #expect(end == grid.offset(index + 1), context)
                }
                if let shortest = blockLengths.min(), let longest = blockLengths.max() {
                    #expect(shortest > 0, context)
                    #expect(longest <= maximum, context)
                    #expect(longest - shortest <= 1, context)
                    // Longer blocks come first.
                    #expect(blockLengths == blockLengths.sorted(by: >), context)
                }
            }
        }
    }

    @Test("huge files do not overflow")
    func hugeFiles() {
        let grid = FileCompareGrid(size: .max, maximumBlockSize: 1 << 20)
        let expectedCount = UInt64.max / (1 << 20) + 1
        #expect(grid.blockCount == expectedCount)
        #expect(grid.offset(grid.blockCount) == .max)
        #expect(grid.length(0) <= 1 << 20)
        let shortest = grid.length(0) - 1
        #expect(grid.length(grid.blockCount - 1) >= shortest)
    }
}

@Suite("CompareFiles: block comparison")
struct FileBlockComparisonTests {
    /// Records each block the comparison asks for.
    private actor Recorder {
        var blocks: [(offset: UInt64, length: Int)] = []

        func record(_ offset: UInt64, _ length: Int) {
            blocks.append((offset, length))
        }
    }

    @Test("blocks follow the equal-size grid")
    func gridCoversFile() async throws {
        let recorder = Recorder()
        let result = try await FileBlockComparison(
            size: 2500,
            scan: .startToEnd,
            maximumBlockSize: 1000,
            minimumCoverage: 1
        )
        .run { offset, length in
            await recorder.record(offset, length)
            return true
        }

        #expect(result)
        let blocks = await recorder.blocks
        #expect(blocks.map(\.offset) == [0, 834, 1667])
        #expect(blocks.map(\.length) == [834, 833, 833])
    }

    @Test("a differing block ends the comparison as conclusive")
    func mismatchIsConclusive() async throws {
        let recorder = Recorder()
        let result = try await FileBlockComparison(
            size: 8000,
            scan: .bisection,
            maximumBlockSize: 1000,
            minimumCoverage: 1
        )
        .run { offset, length in
            await recorder.record(offset, length)
            return offset != 3000
        }

        #expect(!result)
        #expect(await recorder.blocks.map(\.offset) == [0, 7000, 3000])
    }

    @Test("stops once the minimum coverage is reached")
    func stopsAtMinimumCoverage() async throws {
        let recorder = Recorder()
        let result = try await FileBlockComparison(
            size: 10000,
            scan: .startToEnd,
            maximumBlockSize: 1000,
            minimumCoverage: 0.25
        )
        .run { offset, length in
            await recorder.record(offset, length)
            return true
        }

        #expect(result)
        #expect(await recorder.blocks.map(\.offset) == [0, 1000, 2000])
    }

    @Test("an end-to-start scan reads the last block first")
    func endToStart() async throws {
        let recorder = Recorder()
        _ = try await FileBlockComparison(size: 2500, scan: .endToStart, maximumBlockSize: 1000, minimumCoverage: 1)
            .run { offset, length in
                await recorder.record(offset, length)
                return true
            }

        #expect(await recorder.blocks.map(\.offset) == [1667, 834, 0])
    }

    @Test("a block size beyond Int is clamped")
    func hugeBlockSize() async throws {
        let recorder = Recorder()
        _ = try await FileBlockComparison(size: 10, scan: .bisection, maximumBlockSize: .max, minimumCoverage: 1)
            .run { offset, length in
                await recorder.record(offset, length)
                return true
            }

        let blocks = await recorder.blocks
        #expect(blocks.map(\.offset) == [0])
        #expect(blocks.map(\.length) == [10])
    }

    @Test("cancellation throws instead of reporting a result")
    func cancellationThrows() async {
        let task = Task {
            try await FileBlockComparison(size: 10000, scan: .startToEnd, maximumBlockSize: 1000, minimumCoverage: 1)
                .run { _, _ in
                    withUnsafeCurrentTask { $0?.cancel() }
                    // A cancelled read reports a difference; the comparison must still throw.
                    return false
                }
        }

        await #expect(throws: CancellationError.self) {
            try await task.value
        }
    }
}
