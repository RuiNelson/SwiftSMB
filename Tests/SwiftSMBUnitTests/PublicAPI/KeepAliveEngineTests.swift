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

    @Test("the timeout the keep-alive imposes is its deadline rounded up to whole seconds", arguments: [
        (timeout: 1.0, expected: 1),
        (timeout: 2.1, expected: 3),
        (timeout: 0.001, expected: 1),
        (timeout: 30.0, expected: 30),
        (timeout: 1e12, expected: Int(Int32.max)),
    ])
    func imposedTimeout(timeout: TimeInterval, expected: Int) {
        #expect(SMBKeepAliveEngine.imposedTimeoutSeconds(for: timeout) == expected)
    }

    @Test("with the imposed timeout, the deadline in force is the configured one", arguments: [0.5, 1.0, 2.1, 7.9])
    func imposedTimeoutKeepsTheDeadline(timeout: TimeInterval) {
        let imposed = SMBKeepAliveEngine.imposedTimeoutSeconds(for: timeout)
        #expect(SMBKeepAliveEngine.effectiveTimeout(configured: timeout, connectionTimeoutSeconds: imposed) == timeout)
    }

    // MARK: Command timeout

    @Test("a connection with no command timeout gets the keep-alive's, and loses it when the keep-alive stops")
    func commandTimeoutImposedAndRestored() {
        var timeout = SMBCommandTimeout(seconds: 0)
        let imposed = timeout.imposeForKeepAlive(timeout: 2.1)
        #expect(imposed)
        #expect(timeout == SMBCommandTimeout(seconds: 3, imposedByKeepAlive: true))
        let restored = timeout.restoreAfterKeepAlive()
        #expect(restored)
        #expect(timeout == SMBCommandTimeout(seconds: 0))
        let restoredAgain = timeout.restoreAfterKeepAlive()
        #expect(!restoredAgain)
    }

    @Test("a replacing keep-alive imposes its own deadline")
    func commandTimeoutReplaced() {
        var timeout = SMBCommandTimeout(seconds: 0)
        _ = timeout.imposeForKeepAlive(timeout: 1)
        let replaced = timeout.imposeForKeepAlive(timeout: 4.5)
        #expect(replaced)
        #expect(timeout == SMBCommandTimeout(seconds: 5, imposedByKeepAlive: true))
        let replacedWithSameSeconds = timeout.imposeForKeepAlive(timeout: 5)
        #expect(!replacedWithSameSeconds)
        let restored = timeout.restoreAfterKeepAlive()
        #expect(restored)
        #expect(timeout.seconds == 0)
    }

    @Test("a command timeout the user chose is never touched")
    func commandTimeoutOfTheUser() {
        var timeout = SMBCommandTimeout(seconds: 45)
        let imposed = timeout.imposeForKeepAlive(timeout: 1)
        #expect(!imposed)
        #expect(timeout == SMBCommandTimeout(seconds: 45))
        let restored = timeout.restoreAfterKeepAlive()
        #expect(!restored)
        #expect(timeout.seconds == 45)
    }

    @Test("a timeout set while the keep-alive runs becomes the user's and stays", arguments: [0, 1, 10])
    func commandTimeoutSetByUserMeanwhile(seconds: Int) {
        var timeout = SMBCommandTimeout(seconds: 0)
        _ = timeout.imposeForKeepAlive(timeout: 2)
        timeout.setByUser(seconds)
        let restored = timeout.restoreAfterKeepAlive()
        #expect(!restored)
        #expect(timeout == SMBCommandTimeout(seconds: seconds))
    }

    // MARK: Echo race

    @Test("an echo that answers in time reports its round trip")
    func raceAnswered() async {
        // This echo waits on the thread pool, which the rest of the suite can starve for over a minute, so the deadline
        // is far beyond that. An echo on a connection waits on its queue instead (see `raceAnsweredOnTheQueue`).
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 3600) { started, _ in
            started()
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
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 0.1) { started, _ in
            started()
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
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 5) { started, _ in
            started()
            throw SMB.Error.posix(code: ECONNRESET, operation: "echo", message: "failed")
        }
        guard case let .failed(error) = outcome, let smbError = error as? SMB.Error else {
            Issue.record("expected a failure, got \(outcome)")
            return
        }
        #expect(smbError.posixCode == ECONNRESET)
    }

    @Test("an echo on a closed connection stops the keep-alive quietly")
    func raceClosed() async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 5) { _, _ in
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
            await SMBKeepAliveEchoRace.run(timeout: 30) { started, _ in
                started()
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

    @Test("the deadline starts when the echo starts, not while it waits to run")
    func raceDeadlineStartsWithTheEcho() async {
        let release = Flag()
        let racing = Task {
            await SMBKeepAliveEchoRace.run(timeout: 0.2) { started, _ in
                // Waiting for the connection's queue, for longer than the deadline.
                while !release.isSet {
                    try await Task.sleep(nanoseconds: 10_000_000)
                }
                started()
            }
        }
        try? await Task.sleep(nanoseconds: 500_000_000)
        release.set()
        let outcome = await racing.value
        guard case .answered = outcome else {
            Issue.record("expected an answer, got \(outcome)")
            return
        }
    }

    @Test("an echo that has not started is never timed out, and cancelling still resolves the race")
    func raceUnstartedEchoHasNoDeadline() async {
        let release = Flag()
        let racing = Task {
            await SMBKeepAliveEchoRace.run(timeout: 0.05) { _, _ in
                while !release.isSet {
                    try await Task.sleep(nanoseconds: 10_000_000)
                }
            }
        }
        // Several deadlines go by, so a deadline counted from the request would have resolved the race.
        try? await Task.sleep(nanoseconds: 400_000_000)
        racing.cancel()
        let outcome = await racing.value
        release.set()
        guard case .stopped = outcome else {
            Issue.record("expected stopped, got \(outcome)")
            return
        }
    }

    @Test("the round trip is counted from when the echo starts")
    func raceRoundTripStartsWithTheEcho() async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 30) { started, _ in
            try await Task.sleep(nanoseconds: 1_000_000_000)
            started()
        }
        guard case let .answered(roundTrip) = outcome else {
            Issue.record("expected an answer, got \(outcome)")
            return
        }
        // The second spent before `started` is not part of it. The echo answers right after `started`, with no
        // suspension in between, so a busy thread pool cannot stretch the round trip anywhere near that second.
        #expect(roundTrip < 1)
    }

    @Test("the deadline timer is released once the race resolves", arguments: [true, false])
    func raceReleasesItsTimer(answers: Bool) async {
        let race = SMBKeepAliveEchoRace(timeout: 30)
        let outcome = await race.run { started, _ in
            started()
            if !answers {
                throw SMB.Error.posix(code: POSIXErrorCode.EPIPE.rawValue, operation: "echo", message: "failed")
            }
        }
        if answers {
            guard case .answered = outcome else {
                Issue.record("expected an answer, got \(outcome)")
                return
            }
        }
        #expect(!race.hasPendingTimer)
    }

    @Test("a deadline that expires releases its timer")
    func raceTimerReleasedAtTheDeadline() async {
        let release = Flag()
        let race = SMBKeepAliveEchoRace(timeout: 0.05)
        let outcome = await race.run { started, _ in
            started()
            while !release.isSet {
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        release.set()
        guard case .noResponse = outcome else {
            Issue.record("expected no response, got \(outcome)")
            return
        }
        #expect(!race.hasPendingTimer)
    }

    @Test("an echo that starts after the race resolved starts no timer")
    func raceLateStartStartsNoTimer() async {
        let release = Flag()
        let startedLate = Flag()
        let race = SMBKeepAliveEchoRace(timeout: 0.05)
        let racing = Task {
            await race.run { started, _ in
                while !release.isSet {
                    try? await Task.sleep(nanoseconds: 10_000_000)
                }
                started()
                startedLate.set()
            }
        }
        try? await Task.sleep(nanoseconds: 50_000_000)
        racing.cancel()
        _ = await racing.value
        release.set()
        await waitForCondition { startedLate.isSet }
        #expect(!race.hasPendingTimer)
    }

    @Test("a race that is already cancelled sends no echo and starts no timer")
    func raceAlreadyCancelled() async {
        let echoed = Flag()
        let race = SMBKeepAliveEchoRace(timeout: 0.05)
        let outcome = await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await race.run { started, _ in
                echoed.set()
                started()
            }
        }.value
        guard case .stopped = outcome else {
            Issue.record("expected stopped, got \(outcome)")
            return
        }
        // Only a lower bound on the time an echo task would need to run, so this can miss a bug but never fails a
        // correct implementation.
        try? await Task.sleep(nanoseconds: 200_000_000)
        #expect(!echoed.isSet)
        #expect(!race.hasPendingTimer)
    }

    @Test("an echo that finished on the queue in time is answered, however late its task resumes")
    func raceAnsweredOnTheQueue() async {
        let release = Flag()
        let returned = Flag()
        let race = SMBKeepAliveEchoRace(timeout: 0.2)
        let racing = Task {
            await race.run { started, finished in
                // What the connection's queue does: stamp the start, send, stamp the end.
                started()
                finished(nil)
                // The task awaiting the queue resumes much later than the deadline, as on a saturated thread pool.
                while !release.isSet {
                    try? await Task.sleep(nanoseconds: 10_000_000)
                }
                returned.set()
            }
        }
        // Several deadlines go by before the echo's task may return.
        try? await Task.sleep(nanoseconds: 600_000_000)
        let outcome = await racing.value
        // The race resolved from the stamps on the queue, not when the echo's task returned.
        #expect(!returned.isSet)
        release.set()
        guard case let .answered(roundTrip) = outcome else {
            Issue.record("expected an answer, got \(outcome)")
            return
        }
        // An answer is never later than the deadline: the stamps decided, not the scheduling.
        #expect(roundTrip <= 0.2)
        #expect(!race.hasPendingTimer)
    }

    @Test("the round trip is the time between the stamps on the queue")
    func raceRoundTripComesFromTheStamps() async {
        let release = Flag()
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 30) { started, finished in
            started()
            // The echo itself takes this long on the queue, which blocks its thread.
            blockThread(seconds: 0.1)
            finished(nil)
            while !release.isSet {
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        // Resolved while the echo's task was still held, so the round trip cannot include its resumption.
        release.set()
        guard case let .answered(roundTrip) = outcome else {
            Issue.record("expected an answer, got \(outcome)")
            return
        }
        #if os(Windows)
            // Thread.sleep and DispatchTime read different Windows clocks, so a 0.1 s sleep can measure slightly less.
            #expect(roundTrip >= 0.09)
        #else
            #expect(roundTrip >= 0.1)
        #endif
    }

    @Test("an echo that finished on the queue after the deadline is no response, whichever side notices")
    func raceFinishedAfterTheDeadline() async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 0.05) { started, finished in
            started()
            blockThread(seconds: 0.2)
            finished(nil)
        }
        guard case let .noResponse(timeout) = outcome else {
            Issue.record("expected no response, got \(outcome)")
            return
        }
        #expect(timeout == 0.05)
    }

    @Test("a failure stamped on the queue is reported with its error")
    func raceFailureStampedOnTheQueue() async {
        let release = Flag()
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 30) { started, finished in
            started()
            finished(SMB.Error.posix(code: ECONNRESET, operation: "echo", message: "failed"))
            while !release.isSet {
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        release.set()
        guard case let .failed(error) = outcome, let smbError = error as? SMB.Error else {
            Issue.record("expected a failure, got \(outcome)")
            return
        }
        #expect(smbError.posixCode == ECONNRESET)
    }

    @Test("libsmb2's own command timeout is reported as no response", arguments: [
        SMB.Error.ntStatus(.ioTimeout, posixCode: nil, operation: "smb2_echo", message: ""),
        SMB.Error.posix(code: ETIMEDOUT, operation: "smb2_echo", message: ""),
    ])
    func raceLibraryTimeoutIsNoResponse(error: SMB.Error) async {
        let outcome = await SMBKeepAliveEchoRace.run(timeout: 3) { started, _ in
            started()
            throw error
        }
        guard case let .noResponse(timeout) = outcome else {
            Issue.record("expected no response, got \(outcome)")
            return
        }
        #expect(timeout == 3)
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

    @Test("no callback starts once the run is no longer current", arguments: [
        SMBKeepAliveEchoOutcome.noResponse(timeout: 1),
        .failed(SMB.Error.posix(code: POSIXErrorCode.EPIPE.rawValue, operation: "echo", message: "failed")),
        .answered(roundTrip: 0.8),
    ])
    func staleRunStaysSilent(outcome: SMBKeepAliveEchoOutcome) async {
        let harness = Harness(interval: 0.05, slowRoundTrip: 0.5)
        harness.outcome = outcome
        // Stopped or replaced while the echo ran: the run was current when it decided to send it.
        harness.onEcho = { _ in harness.current = false }
        await harness.start().value
        #expect(harness.echoCount == 1)
        #expect(harness.problems.isEmpty)
    }

    @Test("a callback that stops the keep-alive is not cancelled with it, and the run ends after it returns")
    func callbackIsNotCancelledByStopping() async {
        let runTask = Locked<Task<Void, Never>?>(nil)
        let observed = Locked<(cancelled: Bool, slept: Bool)?>(nil)
        let calls = Locked(0)
        let configuration = SMB.KeepAliveConfiguration(interval: 0.05, timeout: 1, slowRoundTrip: 0.5) { _ in
            calls.update { $0 += 1 }
            while runTask.value == nil {
                try? await Task.sleep(nanoseconds: 1_000_000)
            }
            // What stopKeepAlive(), startKeepAlive(_:) and disconnect() do to the keep-alive's task.
            runTask.value?.cancel()
            var slept = true
            do {
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            catch {
                slept = false
            }
            observed.value = (Task.isCancelled, slept)
        }
        let task = Task {
            await SMBKeepAliveEngine.run(
                configuration: configuration,
                isCurrent: { true },
                snapshot: { (0, 0) },
                sendEcho: { .answered(roundTrip: 0.8) },
                markActivity: {
                }
            )
        }
        runTask.value = task
        await task.value
        #expect(observed.value?.cancelled == false)
        #expect(observed.value?.slept == true)
        // A slow answer does not stop the keep-alive, so only the cancellation ended the run.
        #expect(calls.value == 1)
    }

    @Test("a stopped outcome ends the run without a callback")
    func stoppedEndsQuietly() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .stopped
        await harness.start().value
        #expect(harness.echoCount == 1)
        #expect(harness.problems.isEmpty)
    }

    @Test("no answer while another operation was admitted is inconclusive, and the next idle echo reports it")
    func noResponseWithActivityIsInconclusive() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .noResponse(timeout: 1)
        // The first echo sees an operation admitted while it waited, which stamps the last activity.
        harness.onEcho = { number in
            if number == 1 {
                harness.markActivity()
            }
        }
        await harness.start().value
        #expect(harness.echoCount == 2)
        #expect(harness.problems == ["noResponse(1.0)"])
    }

    @Test("no answer while an operation is running is inconclusive until the connection is idle again")
    func noResponseWhileBusyIsInconclusive() async {
        let harness = Harness(interval: 0.05)
        harness.outcome = .noResponse(timeout: 1)
        harness.onEcho = { number in
            if number == 1 {
                harness.activeCount = 1
            }
        }
        let task = harness.start()
        await harness.waitUntil { harness.echoCount == 1 && harness.snapshotCount >= 4 }
        #expect(harness.problems.isEmpty)
        #expect(harness.echoCount == 1)
        harness.activeCount = 0
        await task.value
        #expect(harness.echoCount == 2)
        #expect(harness.problems == ["noResponse(1.0)"])
    }

    @Test("the inconclusive check compares the activity before and after the echo", arguments: [
        (activeCount: 0, after: UInt64(5), inconclusive: false),
        (activeCount: 1, after: UInt64(5), inconclusive: true),
        (activeCount: 0, after: UInt64(6), inconclusive: true),
    ])
    func inconclusive(activeCount: Int, after: UInt64, inconclusive: Bool) {
        #expect(SMBKeepAliveEngine.isInconclusive(before: 5, after: (activeCount, after)) == inconclusive)
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

/// Blocks the calling thread, as the echo blocks the connection's queue.
private func blockThread(seconds: TimeInterval) {
    Thread.sleep(forTimeInterval: seconds)
}

private func waitForCondition(timeout: TimeInterval = 120, _ condition: () -> Bool) async {
    let started = DispatchTime.now().uptimeNanoseconds
    while !condition() {
        if SMBKeepAliveEngine.seconds(from: started, to: DispatchTime.now().uptimeNanoseconds) > timeout {
            Issue.record("timed out waiting for the condition")
            return
        }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
}

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

private final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Value

    init(_ value: Value) {
        _value = value
    }

    var value: Value {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _value
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _value = newValue
        }
    }

    func update(_ body: (inout Value) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        body(&_value)
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
    private var _onEcho: (@Sendable (Int) -> Void)?
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

    /// Called with the echo's number, from 1, before it returns its outcome.
    var onEcho: (@Sendable (Int) -> Void)? {
        get { locked { _onEcho } }
        set { locked { _onEcho = newValue } }
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
                    let (number, hook) = self.locked {
                        self._echoCount += 1
                        return (self._echoCount, self._onEcho)
                    }
                    hook?(number)
                    return self.outcome
                },
                markActivity: { self.markActivity() }
            )
        }
    }

    func waitUntil(timeout: TimeInterval = 120, _ condition: () -> Bool) async {
        await waitForCondition(timeout: timeout, condition)
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
