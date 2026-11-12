//
// Part of SwiftSMB
// ByteRangesTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Testing

@Suite("Cache: byte ranges")
struct ByteRangesTests {
    // MARK: union

    @Test("adding to no ranges gives the range")
    func unionIntoEmpty() {
        #expect(ByteRanges.union([], 10 ..< 20) == [10 ..< 20])
    }

    @Test("adding an empty range changes nothing")
    func unionEmptyRange() {
        #expect(ByteRanges.union([0 ..< 5, 10 ..< 20], 7 ..< 7) == [0 ..< 5, 10 ..< 20])
        #expect(ByteRanges.union([], 3 ..< 3) == [])
    }

    @Test("disjoint ranges stay sorted wherever the new one lands")
    func unionDisjoint() {
        let ranges: [Range<UInt64>] = [10 ..< 20, 30 ..< 40]
        #expect(ByteRanges.union(ranges, 0 ..< 5) == [0 ..< 5, 10 ..< 20, 30 ..< 40])
        #expect(ByteRanges.union(ranges, 22 ..< 25) == [10 ..< 20, 22 ..< 25, 30 ..< 40])
        #expect(ByteRanges.union(ranges, 50 ..< 60) == [10 ..< 20, 30 ..< 40, 50 ..< 60])
    }

    @Test("touching ranges merge")
    func unionTouching() {
        #expect(ByteRanges.union([0 ..< 10], 10 ..< 20) == [0 ..< 20])
        #expect(ByteRanges.union([10 ..< 20], 0 ..< 10) == [0 ..< 20])
        #expect(ByteRanges.union([0 ..< 10, 20 ..< 30], 10 ..< 20) == [0 ..< 30])
    }

    @Test("overlapping ranges merge, swallowing those inside")
    func unionOverlapping() {
        #expect(ByteRanges.union([0 ..< 10], 5 ..< 15) == [0 ..< 15])
        #expect(ByteRanges.union([0 ..< 10, 20 ..< 30, 40 ..< 50], 5 ..< 45) == [0 ..< 50])
        #expect(ByteRanges.union([5 ..< 8, 12 ..< 14], 0 ..< 20) == [0 ..< 20])
        #expect(ByteRanges.union([0 ..< 20], 5 ..< 8) == [0 ..< 20])
    }

    @Test("ranges at the top of the offset space merge")
    func unionAtTheTop() {
        let top = UInt64.max
        #expect(ByteRanges.union([top - 10 ..< top], top - 20 ..< top - 10) == [top - 20 ..< top])
    }

    // MARK: subtracting

    @Test("subtracting a range that misses changes nothing")
    func subtractingMiss() {
        #expect(ByteRanges.subtracting(20 ..< 30, from: [0 ..< 10, 40 ..< 50]) == [0 ..< 10, 40 ..< 50])
        #expect(ByteRanges.subtracting(10 ..< 20, from: [0 ..< 10, 20 ..< 30]) == [0 ..< 10, 20 ..< 30])
        #expect(ByteRanges.subtracting(5 ..< 5, from: [0 ..< 10]) == [0 ..< 10])
    }

    @Test("subtracting trims ends, splits middles, and drops covered ranges")
    func subtractingOverlap() {
        #expect(ByteRanges.subtracting(0 ..< 5, from: [0 ..< 10]) == [5 ..< 10])
        #expect(ByteRanges.subtracting(5 ..< 10, from: [0 ..< 10]) == [0 ..< 5])
        #expect(ByteRanges.subtracting(3 ..< 7, from: [0 ..< 10]) == [0 ..< 3, 7 ..< 10])
        #expect(ByteRanges.subtracting(0 ..< 10, from: [0 ..< 10]) == [])
        #expect(ByteRanges.subtracting(5 ..< 45, from: [0 ..< 10, 20 ..< 30, 40 ..< 50]) == [0 ..< 5, 45 ..< 50])
    }

    // MARK: clamping

    @Test("clamping keeps only the parts inside the range")
    func clamping() {
        let ranges: [Range<UInt64>] = [0 ..< 10, 20 ..< 30, 40 ..< 50]
        #expect(ByteRanges.clamping(ranges, to: 5 ..< 45) == [5 ..< 10, 20 ..< 30, 40 ..< 45])
        #expect(ByteRanges.clamping(ranges, to: 10 ..< 20) == [])
        #expect(ByteRanges.clamping(ranges, to: 0 ..< 100) == ranges)
        #expect(ByteRanges.clamping([], to: 0 ..< 100) == [])
    }

    // MARK: Model check

    @Test("union and subtracting match a byte-set model")
    func matchesModel() {
        var generator = SplitMix64(seed: 0x5EED)
        var ranges: [Range<UInt64>] = []
        var bytes = Set<UInt64>()

        for _ in 0 ..< 2000 {
            let lower = generator.next() % 200
            let upper = lower + generator.next() % 40
            let range = lower ..< upper
            if generator.next() % 3 == 0 {
                ranges = ByteRanges.subtracting(range, from: ranges)
                bytes.subtract(range)
            }
            else {
                ranges = ByteRanges.union(ranges, range)
                bytes.formUnion(range)
            }

            #expect(Set(ranges.flatMap(\.self)) == bytes)
            #expect(ranges.allSatisfy { !$0.isEmpty })
            #expect(zip(ranges, ranges.dropFirst()).allSatisfy { $0.upperBound < $1.lowerBound })
        }
    }
}

/// A small deterministic generator, so a failing model check can be replayed.
private struct SplitMix64 {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
