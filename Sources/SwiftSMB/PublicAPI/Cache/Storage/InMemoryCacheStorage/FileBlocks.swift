//
// Part of SwiftSMB
// FileBlocks.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

/// The stored bytes of one file: sorted runs that neither overlap nor touch.
struct FileBlocks {
    /// A run of contiguous stored bytes.
    struct Segment: Equatable {
        /// Position of the first byte in the file.
        var start: UInt64

        /// The bytes, indexed from zero.
        var bytes: Data

        /// Position just past the last byte.
        var end: UInt64 {
            start + UInt64(bytes.count)
        }
    }

    /// The runs, sorted by position. Two runs never overlap or touch.
    private(set) var segments: [Segment] = []

    /// Total bytes held.
    private(set) var byteCount = 0

    var isEmpty: Bool {
        segments.isEmpty
    }

    /// The stored ranges, sorted.
    var ranges: [Range<UInt64>] {
        segments.map { $0.start ..< $0.end }
    }

    // MARK: Reading

    /// Whether a run holds the byte at `offset`.
    func contains(_ offset: UInt64) -> Bool {
        segmentIndex(containing: offset) != nil
    }

    /// A copy of the stored bytes starting exactly at `offset`, at most `upTo` of them.
    ///
    /// - Returns: The bytes, or `nil` when no run holds the byte at `offset`.
    func run(at offset: UInt64, upTo: Int) -> Data? {
        guard upTo > 0, let index = segmentIndex(containing: offset) else {
            return nil
        }

        let segment = segments[index]
        let count = Int(min(UInt64(upTo), segment.end - offset))
        return copy(of: segment, from: offset, count: count)
    }

    // MARK: Writing

    /// Stores `data` at `offset`, over any bytes already stored there.
    mutating func write(_ data: Data, at offset: UInt64) {
        guard !data.isEmpty else {
            return
        }

        let end = offset + UInt64(data.count)

        // Overwriting bytes inside one run: replace them in place. No local copy of the run may hold its storage
        // meanwhile, or replacing would copy all of it.
        if let index = segmentIndex(containing: offset), end <= segments[index].end {
            let from = segments[index].bytes.startIndex + Int(offset - segments[index].start)
            segments[index].bytes.replaceSubrange(from ..< from + data.count, with: data)
            return
        }

        // Every run that overlaps or touches the new bytes merges with them into one.
        let low = firstSegmentIndex(endingAtOrAfter: offset)
        var high = low
        while high < segments.count, segments[high].start <= end {
            high += 1
        }

        guard low < high else {
            segments.insert(Segment(start: offset, bytes: Self.copy(data)), at: low)
            byteCount += data.count
            return
        }

        let removed = segments[low ..< high].reduce(0) { $0 + $1.bytes.count }
        let start = min(segments[low].start, offset)

        // The bytes of the last run past the new ones. When the first run also holds them, the new bytes fall inside it
        // and were replaced in place above.
        let lastEnd = segments[high - 1].end
        let tail: Data? = if lastEnd > end {
            Self.copy(segments[high - 1].bytes.suffix(Int(lastEnd - end)))
        }
        else {
            nil
        }

        var merged: Data
        if segments[low].start < offset {
            // Take the first run's storage over, so appending does not copy it.
            let kept = Int(offset - segments[low].start)
            merged = Data()
            swap(&merged, &segments[low].bytes)
            merged.removeSubrange(merged.startIndex + kept ..< merged.endIndex)
            merged.append(data)
        }
        else {
            merged = Self.copy(data)
        }

        if let tail {
            merged.append(tail)
        }

        segments.replaceSubrange(low ..< high, with: [Segment(start: start, bytes: merged)])
        byteCount += merged.count - removed
    }

    /// Drops every byte outside `keptRanges`, which are sorted and neither overlap nor touch.
    mutating func retain(_ keptRanges: [Range<UInt64>]) {
        // Only cutting the end off: trim in place, so the runs before it are not copied.
        if keptRanges.count <= 1, keptRanges.first?.lowerBound ?? 0 == 0 {
            truncate(to: keptRanges.first?.upperBound ?? 0)
            return
        }

        var kept: [Segment] = []
        for range in keptRanges {
            for segment in segments where segment.start < range.upperBound && segment.end > range.lowerBound {
                let from = max(segment.start, range.lowerBound)
                let to = min(segment.end, range.upperBound)
                kept.append(Segment(start: from, bytes: copy(of: segment, from: from, count: Int(to - from))))
            }
        }

        // The kept ranges are merged, so the kept runs neither overlap nor touch.
        segments = kept
        byteCount = kept.reduce(0) { $0 + $1.bytes.count }
    }

    /// Drops every byte.
    mutating func removeAll() {
        segments = []
        byteCount = 0
    }

    // MARK: Private

    /// Drops every byte at or past `size`.
    private mutating func truncate(to size: UInt64) {
        while let index = segments.indices.last, segments[index].end > size {
            let count = segments[index].bytes.count
            if segments[index].start >= size {
                segments.removeLast()
                byteCount -= count
            }
            else {
                let kept = Int(size - segments[index].start)
                let from = segments[index].bytes.startIndex + kept
                segments[index].bytes.removeSubrange(from ..< from + (count - kept))
                byteCount -= count - kept
            }
        }
    }

    /// Index of the run holding the byte at `offset`.
    private func segmentIndex(containing offset: UInt64) -> Int? {
        let index = firstSegmentIndex(endingAtOrAfter: offset)
        guard index < segments.count, segments[index].start <= offset, segments[index].end > offset else {
            return nil
        }
        return index
    }

    /// Index of the first run that ends at or after `offset`, or the number of runs.
    private func firstSegmentIndex(endingAtOrAfter offset: UInt64) -> Int {
        var low = 0
        var high = segments.count
        while low < high {
            let middle = (low + high) / 2
            if segments[middle].end < offset {
                low = middle + 1
            }
            else {
                high = middle
            }
        }
        return low
    }

    /// A copy of `count` bytes of `segment` starting at file position `offset`, in storage of its own.
    private func copy(of segment: Segment, from offset: UInt64, count: Int) -> Data {
        let from = segment.bytes.startIndex + Int(offset - segment.start)
        return Self.copy(segment.bytes[from ..< from + count])
    }

    /// `data` in storage of its own, indexed from zero, so it neither pins a larger buffer nor shares one that later
    /// changes.
    private static func copy(_ data: Data) -> Data {
        data.withUnsafeBytes { buffer in
            buffer.baseAddress.map { Data(bytes: $0, count: buffer.count) } ?? Data()
        }
    }
}
