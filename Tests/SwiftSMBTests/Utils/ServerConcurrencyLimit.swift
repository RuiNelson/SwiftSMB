//
// Part of SwiftSMB
// ServerConcurrencyLimit.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import Testing

/// Limits how many integration test cases talk to the Docker Samba server at the same time.
///
/// Swift Testing runs every suite that is not `.serialized` in parallel. With hundreds of integration tests, each
/// opening its own connections, the single test container falls behind: notifications miss their `withTimeout` deadline
/// and the server closes connections mid-test, while the same tests pass when run alone or with
/// `--no-parallel`. Each test case waits for a slot before it starts, so the time spent waiting does not count
/// against the timeouts inside the test.
///
/// Applied to every integration suite next to `.tags(.integration)`; it is recursive, so nested suites and
/// parameterized test cases are covered. The limit is ``ServerConcurrencyLimit/defaultWidth`` and can be changed with
/// the `SWIFTSMB_INTEGRATION_PARALLELISM` environment variable (`1` runs the integration tests one at a time).
struct ServerConcurrencyLimit: SuiteTrait, TestTrait, TestScoping {
    static let defaultWidth = 4

    static let width: Int = {
        if let value = ProcessInfo.processInfo.environment["SWIFTSMB_INTEGRATION_PARALLELISM"],
           let width = Int(value), width > 0 {
            return width
        }
        return defaultWidth
    }()

    static let slots = AsyncSlots(count: width)

    var isRecursive: Bool {
        true
    }

    func provideScope(
        for _: Test,
        testCase: Test.Case?,
        performing function: @Sendable () async throws -> Void
    ) async throws {
        // Suites and test functions are scopes around their test cases; only a test case holds a slot, so a suite never
        // waits for a slot its own tests need.
        guard testCase != nil else {
            try await function()
            return
        }
        await Self.slots.acquire()
        do {
            try await function()
        }
        catch {
            await Self.slots.release()
            throw error
        }
        await Self.slots.release()
    }
}

extension Trait where Self == ServerConcurrencyLimit {
    /// Limits how many integration test cases run against the test server at once (see ``ServerConcurrencyLimit``).
    static var serverConcurrencyLimit: Self {
        Self()
    }
}

/// A first-in, first-out counting semaphore for async code.
actor AsyncSlots {
    private var available: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(count: Int) {
        available = count
    }

    func acquire() async {
        if available > 0 {
            available -= 1
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            available += 1
        }
        else {
            // The slot passes straight to the next waiter.
            waiters.removeFirst().resume()
        }
    }
}
