//
// Part of SwiftSMB
// AsyncTimeout.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

/// Thrown by ``withTimeout(seconds:_:)`` when the operation does not finish in time.
struct TimeoutError: Error, CustomStringConvertible {
    let seconds: Double

    var description: String {
        "Operation did not finish within \(seconds) seconds"
    }
}

/// Runs `operation`, cancelling it and throwing ``TimeoutError`` if it does not finish within `seconds`.
func withTimeout<T: Sendable>(
    seconds: Double,
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TimeoutError(seconds: seconds)
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}
