//
// Part of SwiftSMB
// ByteRanges.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// Operations on sorted lists of byte ranges that neither overlap nor touch.
enum ByteRanges {
    /// `ranges` with `range` added, sorted and merged.
    static func union(_ ranges: [Range<UInt64>], _ range: Range<UInt64>) -> [Range<UInt64>] {
        guard !range.isEmpty else {
            return ranges
        }

        var lower = range.lowerBound
        var upper = range.upperBound
        var result: [Range<UInt64>] = []
        var inserted = false
        for existing in ranges {
            if existing.upperBound < lower {
                result.append(existing)
            }
            else if existing.lowerBound > upper {
                if !inserted {
                    result.append(lower ..< upper)
                    inserted = true
                }
                result.append(existing)
            }
            else {
                lower = min(lower, existing.lowerBound)
                upper = max(upper, existing.upperBound)
            }
        }
        if !inserted {
            result.append(lower ..< upper)
        }
        return result
    }

    /// `ranges` without `range`.
    static func subtracting(_ range: Range<UInt64>, from ranges: [Range<UInt64>]) -> [Range<UInt64>] {
        var result: [Range<UInt64>] = []
        for existing in ranges {
            guard existing.overlaps(range) else {
                result.append(existing)
                continue
            }
            if existing.lowerBound < range.lowerBound {
                result.append(existing.lowerBound ..< range.lowerBound)
            }
            if existing.upperBound > range.upperBound {
                result.append(range.upperBound ..< existing.upperBound)
            }
        }
        return result
    }

    /// The parts of `ranges` inside `range`.
    static func clamping(_ ranges: [Range<UInt64>], to range: Range<UInt64>) -> [Range<UInt64>] {
        ranges.compactMap { existing in
            existing.overlaps(range) ? existing.clamped(to: range) : nil
        }
    }
}
