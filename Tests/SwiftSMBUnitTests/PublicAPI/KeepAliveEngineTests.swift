//
// Part of SwiftSMB
// KeepAliveEngineTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

struct KeepAliveEngineTests {
    // MARK: Scheduling

    @Test("nothing is sent while an operation is running")
    func busyConnectionWaitsAWholeInterval() {
        let step = SMBKeepAliveEngine.nextStep(activeCount: 2, lastActivity: 0, now: 100 * second, interval: 30)
        #expect(step == .wait(30))
    }

    @Test("an echo waits for what is left of the interval after the last activity")
    func recentActivityPostponesTheEcho() {
        let step = SMBKeepAliveEngine.nextStep(
            activeCount: 0,
            lastActivity: 10 * second,
            now: 25 * second,
            interval: 30
        )
        #expect(step == .wait(15))
    }

    @Test("an echo is sent once the connection has been idle for the interval", arguments: [30, 31, 500])
    func idleConnectionSendsAnEcho(idleSeconds: UInt64) {
        let step = SMBKeepAliveEngine.nextStep(
            activeCount: 0,
            lastActivity: 5 * second,
            now: (5 + idleSeconds) * second,
            interval: 30
        )
        #expect(step == .sendEcho)
    }

    @Test("a clock reading before the last activity counts as no idle time")
    func clockGoingBackwardsDoesNotSendAnEcho() {
        let step = SMBKeepAliveEngine.nextStep(activeCount: 0, lastActivity: 10 * second, now: 5 * second, interval: 30)
        #expect(step == .wait(30))
    }

    // MARK: Deadline

    @Test("the deadline never exceeds the connection's command timeout", arguments: [
        (configured: 1.0, connection: 0, expected: 1.0),
        (configured: 5.0, connection: 0, expected: 5.0),
        (configured: 5.0, connection: 2, expected: 2.0),
        (configured: 1.0, connection: 30, expected: 1.0),
        (configured: 2.5, connection: 3, expected: 2.5),
    ])
    func effectiveTimeout(configured: TimeInterval, connection: Int, expected: TimeInterval) {
        #expect(SMBKeepAliveEngine.effectiveTimeout(
            configured: configured,
            connectionTimeoutSeconds: connection
        ) == expected)
    }

    // MARK: Echo race

    @Test("an echo that answers in time reports its round trip")
    func raceAnswered() async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 5) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        guard case let .answered(roundTrip) = outcome else {
            Issue.record("expected an answer, got \(outcome)")
            return
        }
        // Only a lower bound: the rest of the suite can starve the thread pool for a long time.
        #expect(roundTrip >= 0.04)
    }

    @Test("an echo that never answers is reported at the deadline, without waiting for it")
    func raceNoResponse() async {
        let release = Flag()
        let finished = Flag()
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 0.1) {
            while !release.isSet {
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            finished.set()
        }
        guard case let .noResponse(timeout) = outcome else {
            Issue.record("expected no response, got \(outcome)")
            release.set()
            return
        }
        #expect(timeout == 0.1)
        // The race returned while the echo was still pending, which is what a task group could not do.
        #expect(!finished.isSet)
        release.set()
    }

    @Test("a failing echo is reported with its error")
    func raceFailed() async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 5) {
            throw SMB.Error.posix(code: POSIXErrorCode.ECONNRESET.rawValue, operation: "echo", message: "failed")
        }
        guard case let .failed(error) = outcome, let smbError = error as? SMB.Error else {
            Issue.record("expected a failure, got \(outcome)")
            return
        }
        #expect(smbError.posixCode == POSIXErrorCode.ECONNRESET.rawValue)
    }

    @Test("an echo on a closed connection stops the keep-alive quietly")
    func raceClosed() async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 5) {
            throw SMB.Error.operationRequestedAfterConnectionClosed
        }
        guard case .stopped = outcome else {
            Issue.record("expected stopped, got \(outcome)")
            return
        }
    }

    @Test("cancelling the task resolves the race at once")
    func raceCancelled() async {
        let task = Task {
            await SMBKeepAliveEchoRace.run(timeout: 30) {
                try await Task.sleep(nanoseconds: 30 * 1_000_000_000)
            }
        }
        try? await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()
        let outcome = await task.value
        guard case .stopped = outcome else {
            Issue.record("expected stopped, got \(outcome)")
            return
        }
    }

    // MARK: Run loop

    @Test("an idle connection gets an echo every interval")
    func idleConnectionIsPinged() async {
        let harness = Harness(interval: 0.05)
        let task = harness.start()
        await harness.waitUntil { harness.echoCount >= 3 }
        task.cancel()
        await task.value
        #expect(harness.echoCount >= 3)
        #expect(harness.problems.isEmpty)
    }

    @Test("a connection that is being used gets no echo")
    func busyConnectionIsLeftAlone() async {
        let harness = Harness(interval: 0.05)
        harness.activeCount = 1
        let task = harness.start()
        try? await Task.sleep(nanoseconds: 400_000_000)
        task.cancel()
        await task.value
        #expect(harness.echoCount == 0)
    }

    @Test("activity postpones the echo")
    func activityPostponesTheEcho() async {
        let harness = Harness(interval: 0.05)
        // Every look at the connection finds it just used, as when operations keep coming.
        harness.touchOnSnapshot = true
        let task = harness.start()
        await harness.waitUntil { harness.snapshotCount >= 6 }
        task.cancel()
        await task.value
        #expect(harness.echoCount == 0)
    }

    @Test("no answer is reported once and stops the keep-alive")
    func noResponseStops() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .noResponse(timeout: 1)
        await harness.start().value
        #expect(harness.echoCount == 1)
        #expect(harness.problems == ["noResponse(1.0)"])
    }

    @Test("a failed echo is reported once and stops the keep-alive")
    func failureStops() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .failed(SMB.Error.posix(
            code: POSIXErrorCode.EPIPE.rawValue,
            operation: "echo",
            message: "failed"
        ))
        await harness.start().value
        #expect(harness.echoCount == 1)
        #expect(harness.problems.count == 1)
        #expect(harness.problems.first?.hasPrefix("failed") == true)
    }

    @Test("a slow answer is reported and the keep-alive goes on")
    func slowAnswerContinues() async {
        let harness = Harness(interval: 0.05, slowRoundTrip: 0.5)
        harness.outcome = .answered(roundTrip: 0.8)
        let task = harness.start()
        await harness.waitUntil { harness.problems.count >= 2 }
        task.cancel()
        await task.value
        #expect(harness.problems.count >= 2)
        #expect(Set(harness.problems) == ["slow(0.8)"])
    }

    @Test("an answer at the threshold is not slow")
    func thresholdIsNotSlow() async {
        let harness = Harness(interval: 0.05, slowRoundTrip: 0.5)
        harness.outcome = .answered(roundTrip: 0.5)
        let task = harness.start()
        await harness.waitUntil { harness.echoCount >= 2 }
        task.cancel()
        await task.value
        #expect(harness.problems.isEmpty)
    }

    @Test("no callback starts once the run is no longer current")
    func staleRunStaysSilent() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .noResponse(timeout: 1)
        harness.current = false
        await harness.start().value
        #expect(harness.problems.isEmpty)
    }

    @Test("a stopped outcome ends the run without a callback")
    func stoppedEndsQuietly() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .stopped
        await harness.start().value
        #expect(harness.echoCount == 1)
        #expect(harness.problems.isEmpty)
    }

    @Test("the run ends when the connection is gone")
    func goneConnectionEndsTheRun() async {
        let harness = Harness(interval: 0.05)
        harness.gone = true
        await harness.start().value
        #expect(harness.echoCount == 0)
    }
}

private let second: UInt64 = 1_000_000_000

private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set() {
        lock.lock()
        defer { lock.unlock() }
        value = true
    }
}

/// A keep-alive run driven by fakes instead of a connection.
private final class Harness: @unchecked Sendable {
    private let lock = NSLock()
    private var _activeCount = 0
    private var _lastActivity = DispatchTime.now().uptimeNanoseconds
    private var _echoCount = 0
    private var _outcome = SMBKeepAliveEchoOutcome.answered(roundTrip: 0.001)
    private var _problems: [String] = []
    private var _current = true
    private var _gone = false
    private var _touchOnSnapshot = false
    private var _snapshotCount = 0
    private let interval: TimeInterval
    private let slowRoundTrip: TimeInterval

    init(interval: TimeInterval, slowRoundTrip: TimeInterval = 0.5) {
        self.interval = interval
        self.slowRoundTrip = slowRoundTrip
    }

    var activeCount: Int {
        get { locked { _activeCount } }
        set { locked { _activeCount = newValue } }
    }

    var echoCount: Int {
        locked { _echoCount }
    }

    var problems: [String] {
        locked { _problems }
    }

    var outcome: SMBKeepAliveEchoOutcome {
        get { locked { _outcome } }
        set { locked { _outcome = newValue } }
    }

    var current: Bool {
        get { locked { _current } }
        set { locked { _current = newValue } }
    }

    var gone: Bool {
        get { locked { _gone } }
        set { locked { _gone = newValue } }
    }

    var touchOnSnapshot: Bool {
        get { locked { _touchOnSnapshot } }
        set { locked { _touchOnSnapshot = newValue } }
    }

    var snapshotCount: Int {
        locked { _snapshotCount }
    }

    func markActivity() {
        locked { _lastActivity = DispatchTime.now().uptimeNanoseconds }
    }

    func start() -> Task<Void, Never> {
        let configuration = SMB.KeepAliveConfiguration(
            interval: interval,
            timeout: 1,
            slowRoundTrip: slowRoundTrip,
            onProblem: { [self] problem in
                locked { _problems.append(Self.describe(problem)) }
            }
        )
        return Task { [self] in
            await SMBKeepAliveEngine.run(
                configuration: configuration,
                isCurrent: { self.current },
                snapshot: {
                    self.locked {
                        self._snapshotCount += 1
                        if self._touchOnSnapshot {
                            self._lastActivity = DispatchTime.now().uptimeNanoseconds
                        }
                        return self._gone ? nil : (self._activeCount, self._lastActivity)
                    }
                },
                sendEcho: {
                    self.locked {
                        self._echoCount += 1
                        return self._outcome
                    }
                },
                markActivity: { self.markActivity() }
            )
        }
    }

    func waitUntil(timeout: TimeInterval = 120, _ condition: () -> Bool) async {
        let started = DispatchTime.now().uptimeNanoseconds
        while !condition() {
            if SMBKeepAliveEngine.seconds(from: started, to: DispatchTime.now().uptimeNanoseconds) > timeout {
                Issue.record("timed out waiting for the condition")
                return
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    private static func describe(_ problem: SMB.KeepAliveProblem) -> String {
        switch problem {
        case let .slow(roundTrip): "slow(\(roundTrip))"
        case let .noResponse(timeout): "noResponse(\(timeout))"
        case let .failed(error): "failed(\(error))"
        }
    }
}
