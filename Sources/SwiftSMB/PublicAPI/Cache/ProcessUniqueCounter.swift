//
// Part of SwiftSMB
// ProcessUniqueCounter.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// Hands out increasing values, each one once in the process, for identifiers that must never repeat.
final class ProcessUniqueCounter: Sendable {
    private let last: Protected<UInt64>

    init(label: String) {
        last = Protected(0, label: label)
    }

    /// The next value, greater than every value handed out before it.
    func next() -> UInt64 {
        last.withLock { last in
            last &+= 1
            return last
        }
    }
}
