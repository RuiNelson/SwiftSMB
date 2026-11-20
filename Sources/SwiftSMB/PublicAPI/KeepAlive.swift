//
// Part of SwiftSMB
// KeepAlive.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// How a connection's keep-alive behaves, passed to ``SMB/Connection/startKeepAlive(_:)``.
    ///
    /// The keep-alive sends an SMB echo only when the connection has been idle for ``interval``: every operation on the
    /// connection, from the moment it starts until it finishes, postpones the next echo.
    struct KeepAliveConfiguration: Sendable, CustomDebugStringConvertible {
        /// The default for ``interval``, in seconds.
        public static let defaultInterval: TimeInterval = 30

        /// The default for ``timeout``, in seconds.
        public static let defaultTimeout: TimeInterval = 1

        /// The default for ``slowRoundTrip``, in seconds.
        public static let defaultSlowRoundTrip: TimeInterval = 0.5

        /// How long the connection has to be idle before an echo is sent, in seconds. Always finite and greater than
        /// zero.
        public var interval: TimeInterval {
            didSet { Self.validate(interval, named: "interval") }
        }

        /// How long to wait for the echo's answer, in seconds. Always finite and greater than zero.
        ///
        /// The deadline starts when the echo starts running on the connection, not while it waits behind other
        /// operations. The keep-alive enforces it itself, independently of the command timeout `libsmb2` applies. The
        /// deadline in force is never longer than the connection's command timeout (``SMB/Configuration/timeout``, or
        /// the value set with ``SMB/Connection/setTimeout(_:)``) when that is not zero, so a larger value is reduced to
        /// it.
        ///
        /// A connection with no command timeout gets one while the keep-alive runs: this value rounded up to whole
        /// seconds (`libsmb2` counts whole seconds), so that an echo to a server that no longer answers cannot hold the
        /// connection forever. That command timeout applies to every operation on the connection, not only to the echo:
        /// a single request that takes longer fails with ``SMB/SMBStatus/ioTimeout``, and ``SMB/Connection/fork()``
        /// starts the new connection with it. On a slow link, or with large transfer blocks, set a command timeout of
        /// your own, with ``SMB/Configuration/timeout`` or ``SMB/Connection/setTimeout(_:)``; the keep-alive leaves it
        /// alone. The keep-alive puts back "no command timeout" when it stops, unless ``SMB/Connection/setTimeout(_:)``
        /// was called meanwhile.
        public var timeout: TimeInterval {
            didSet { Self.validate(timeout, named: "timeout") }
        }

        /// The round-trip time above which an answered echo is reported as ``KeepAliveProblem/slow(roundTrip:)``, in
        /// seconds. Always finite and greater than zero.
        ///
        /// The round trip is measured from when the echo starts running on the connection. An echo that takes longer
        /// than the deadline in force (see ``timeout``) is reported as ``KeepAliveProblem/noResponse(timeout:)``, so a
        /// value at or above that deadline never reports a slow answer.
        public var slowRoundTrip: TimeInterval {
            didSet { Self.validate(slowRoundTrip, named: "slowRoundTrip") }
        }

        /// Called when the keep-alive finds a problem.
        ///
        /// The keep-alive waits for the closure to return before it goes on. After
        /// ``KeepAliveProblem/noResponse(timeout:)`` or ``KeepAliveProblem/failed(_:)`` it stops itself once the
        /// closure returns, so the closure is the place to disconnect, reconnect or call
        /// ``SMB/Connection/startKeepAlive(_:)`` again. It may call
        /// ``SMB/Connection/stopKeepAlive()``. The keep-alive holds the closure, so a closure that captures the
        /// connection strongly keeps it alive until the keep-alive stops; capture it `weak` instead.
        ///
        /// A call that was already starting when ``SMB/Connection/stopKeepAlive()`` or
        /// ``SMB/Connection/startKeepAlive(_:)`` was called can still run once; none starts later.
        public var onProblem: @Sendable (KeepAliveProblem) async -> Void

        /// Creates a keep-alive configuration.
        ///
        /// - Parameters:
        ///   - interval: How long the connection has to be idle before an echo is sent, in seconds.
        ///   - timeout: How long to wait for the echo's answer, in seconds.
        ///   - slowRoundTrip: The round-trip time above which an answered echo is reported as slow, in seconds.
        ///   - onProblem: Called when the keep-alive finds a problem.
        ///
        /// A value that is not finite or not greater than zero is a programmer error and traps.
        public init(
            interval: TimeInterval = defaultInterval,
            timeout: TimeInterval = defaultTimeout,
            slowRoundTrip: TimeInterval = defaultSlowRoundTrip,
            onProblem: @escaping @Sendable (KeepAliveProblem) async -> Void
        ) {
            Self.validate(interval, named: "interval")
            Self.validate(timeout, named: "timeout")
            Self.validate(slowRoundTrip, named: "slowRoundTrip")
            self.interval = interval
            self.timeout = timeout
            self.slowRoundTrip = slowRoundTrip
            self.onProblem = onProblem
        }

        public var debugDescription: String {
            "SMB.KeepAliveConfiguration(interval: \(interval), timeout: \(timeout), slowRoundTrip: \(slowRoundTrip))"
        }

        private static func validate(_ value: TimeInterval, named name: StaticString) {
            precondition(value.isFinite && value > 0, "\(name) must be finite and greater than zero")
        }
    }

    /// A problem a connection's keep-alive found.
    enum KeepAliveProblem: Sendable, CustomDebugStringConvertible {
        /// The server answered, but later than ``KeepAliveConfiguration/slowRoundTrip``. The keep-alive goes on.
        case slow(roundTrip: TimeInterval)

        /// The server did not answer within the deadline, in seconds, or the connection's command timeout expired
        /// first. The connection is most likely broken. The keep-alive stops.
        ///
        /// It is not reported when another operation started on the connection while the echo was waiting for its
        /// answer: that operation meets the same problem itself, and the keep-alive tries again once the connection has
        /// been idle for a whole ``KeepAliveConfiguration/interval``.
        case noResponse(timeout: TimeInterval)

        /// The echo failed. The connection is most likely broken. The keep-alive stops.
        case failed(any Swift.Error)

        public var debugDescription: String {
            switch self {
            case let .slow(roundTrip):
                "SMB.KeepAliveProblem.slow(roundTrip: \(roundTrip))"
            case let .noResponse(timeout):
                "SMB.KeepAliveProblem.noResponse(timeout: \(timeout))"
            case let .failed(error):
                "SMB.KeepAliveProblem.failed(\(error))"
            }
        }
    }
}

// MARK: - Engine

/// What a keep-alive echo came to.
enum SMBKeepAliveEchoOutcome: Sendable {
    case answered(roundTrip: TimeInterval)
    case noResponse(timeout: TimeInterval)
    case failed(any Error)
    /// The connection is closed or closing, or the keep-alive was cancelled: stop without telling anyone.
    case stopped
}

/// What the keep-alive does next.
enum SMBKeepAliveStep: Equatable {
    case sendEcho
    /// Wait this many seconds.
    case wait(TimeInterval)
}

/// The keep-alive's scheduling and reporting, independent of any connection so it can be tested without one.
enum SMBKeepAliveEngine {
    /// An echo is due only when no operation is running and the connection has been idle for a whole interval.
    ///
    /// Times are `DispatchTime` uptime nanoseconds, which do not jump with the wall clock.
    static func nextStep(
        activeCount: Int,
        lastActivity: UInt64,
        now: UInt64,
        interval: TimeInterval
    ) -> SMBKeepAliveStep {
        guard activeCount == 0 else { return .wait(interval) }
        let idle = seconds(from: lastActivity, to: now)
        return idle >= interval ? .sendEcho : .wait(interval - idle)
    }

    static func seconds(from start: UInt64, to end: UInt64) -> TimeInterval {
        end > start ? TimeInterval(end - start) / 1_000_000_000 : 0
    }

    static func sleep(seconds: TimeInterval) async throws {
        let nanoseconds = (seconds * 1_000_000_000).rounded(.up)
        try await Task.sleep(nanoseconds: nanoseconds >= Double(UInt64.max) ? UInt64.max : UInt64(max(nanoseconds, 1)))
    }

    /// The deadline in force: the configured one, reduced to the connection's command timeout when that is set.
    static func effectiveTimeout(configured: TimeInterval, connectionTimeoutSeconds: Int) -> TimeInterval {
        guard connectionTimeoutSeconds > 0 else { return configured }
        return min(configured, TimeInterval(connectionTimeoutSeconds))
    }

    /// The command timeout the keep-alive gives a connection that has none: its deadline rounded up to whole seconds,
    /// because `libsmb2` counts whole seconds (`time(NULL)`). Never longer than `Int32.max`, which `libsmb2` stores.
    static func imposedTimeoutSeconds(for timeout: TimeInterval) -> Int {
        Int(min(timeout.rounded(.up), TimeInterval(Int32.max)))
    }

    /// Whether a `.noResponse` says nothing about the connection, because another operation was admitted while the echo
    /// ran: an operation running now, or activity stamped since the echo was decided on. That operation meets the same
    /// problem itself, so the keep-alive waits for the connection to be idle again rather than report it.
    static func isInconclusive(
        before lastActivityBefore: UInt64,
        after state: (activeCount: Int, lastActivity: UInt64)
    ) -> Bool {
        state.activeCount > 0 || state.lastActivity != lastActivityBefore
    }

    /// Runs until a failure, until it is no longer current, or until its task is cancelled.
    ///
    /// - Parameters:
    ///   - isCurrent: Whether this run is still the connection's keep-alive. Checked before every callback, so none
    /// starts once the keep-alive was stopped or replaced, except one that was already starting at that moment.
    ///   - snapshot: The connection's operation count and last activity, or `nil` when the connection is gone.
    ///   - sendEcho: Sends one echo, with the deadline in force.
    ///   - markActivity: Records that the connection was just used.
    static func run(
        configuration: SMB.KeepAliveConfiguration,
        isCurrent: @Sendable () -> Bool,
        snapshot: @Sendable () -> (activeCount: Int, lastActivity: UInt64)?,
        sendEcho: @Sendable () async -> SMBKeepAliveEchoOutcome,
        markActivity: @Sendable () -> Void
    ) async {
        let interval = configuration.interval
        // Starting counts as activity, so the first echo comes a whole interval from now.
        markActivity()

        while !Task.isCancelled, isCurrent() {
            guard let state = snapshot() else { return }
            switch nextStep(
                activeCount: state.activeCount,
                lastActivity: state.lastActivity,
                now: DispatchTime.now().uptimeNanoseconds,
                interval: interval
            ) {
            case let .wait(delay):
                do {
                    try await sleep(seconds: delay)
                }
                catch {
                    return
                }
            case .sendEcho:
                switch await sendEcho() {
                case let .answered(roundTrip):
                    markActivity()
                    if roundTrip > configuration.slowRoundTrip, isCurrent() {
                        await configuration.onProblem(.slow(roundTrip: roundTrip))
                    }
                case let .noResponse(timeout):
                    guard let after = snapshot() else { return }
                    if isInconclusive(before: state.lastActivity, after: after) {
                        continue
                    }
                    if isCurrent() {
                        await configuration.onProblem(.noResponse(timeout: timeout))
                    }
                    return
                case let .failed(error):
                    if isCurrent() {
                        await configuration.onProblem(.failed(error))
                    }
                    return
                case .stopped:
                    return
                }
            }
        }
    }
}

/// Runs an echo against a deadline that is enforced in Swift.
///
/// An echo waiting on its connection's queue cannot be cancelled, so a task group would wait for it past the deadline.
/// This resolves on whichever of the echo, the deadline and cancellation comes first, and leaves the echo running.
///
/// The deadline, and the round trip, start when the echo calls the `started` closure it is given, which the connection
/// does once the echo runs on its queue: time spent waiting behind other operations is not the server's. An echo that
/// never starts has no deadline: the keep-alive only sends an echo when no operation is running, an operation that
/// starts later queues behind it, and while the keep-alive runs the connection has a command timeout unless the user
/// set it to zero, so nothing holds the queue for long. Stopping or replacing the keep-alive, or disconnecting, cancels
/// the wait.
final class SMBKeepAliveEchoRace: Sendable {
    private enum Phase {
        case waiting
        case suspended(CheckedContinuation<SMBKeepAliveEchoOutcome, Never>)
        case resolved(SMBKeepAliveEchoOutcome)
        case delivered
    }

    private struct State {
        var phase = Phase.waiting
        /// When the echo started, in `DispatchTime` uptime nanoseconds.
        var startedAt: UInt64?
        var timer: Task<Void, Never>?

        var isResolved: Bool {
            switch phase {
            case .waiting, .suspended: false
            case .resolved, .delivered: true
            }
        }
    }

    private let timeout: TimeInterval
    private let createdAt = DispatchTime.now().uptimeNanoseconds
    private let state = Protected(State(), label: "com.ruinelson.SwiftSMB.keepAlive.echoRace")

    /// Whether a deadline timer is still held. It is cancelled and released as soon as the race resolves.
    var hasPendingTimer: Bool {
        state.withLock { $0.timer != nil }
    }

    /// - Parameter timeout: The deadline, in seconds, counted from when the echo starts.
    init(timeout: TimeInterval) {
        self.timeout = timeout
    }

    /// Runs `echo` against `timeout`.
    ///
    /// - Parameters:
    ///   - timeout: The deadline, in seconds, counted from when the echo starts.
    ///   - echo: Sends the echo and throws when it fails. It calls the closure it is given when the echo starts.
    static func run(
        timeout: TimeInterval,
        echo: @escaping @Sendable (_ started: @escaping @Sendable () -> Void) async throws -> Void
    ) async -> SMBKeepAliveEchoOutcome {
        await SMBKeepAliveEchoRace(timeout: timeout).run(echo: echo)
    }

    /// Runs `echo` against the deadline. A race runs once.
    func run(
        echo: @escaping @Sendable (_ started: @escaping @Sendable () -> Void) async throws -> Void
    ) async -> SMBKeepAliveEchoOutcome {
        let timeout = timeout
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                // Already cancelled: no echo is sent and no timer is started.
                guard !install(continuation) else { return }
                Task {
                    do {
                        try await echo { self.start() }
                        resolve(.answered(roundTrip: roundTrip()))
                    }
                    catch {
                        resolve(Self.outcome(for: error, timeout: timeout))
                    }
                }
            }
        } onCancel: {
            resolve(.stopped)
        }
    }

    private static func outcome(for error: any Error, timeout: TimeInterval) -> SMBKeepAliveEchoOutcome {
        guard let error = error as? SMB.Error else { return .failed(error) }
        switch error {
        case .operationRequestedAfterConnectionClosed:
            return .stopped
        // libsmb2's own command timeout expired, which can happen first when the Swift deadline equals it.
        case .ntStatus(.ioTimeout, _, _, _):
            return .noResponse(timeout: timeout)
        case let .posix(code, _, _) where code == POSIXErrorCode.ETIMEDOUT.rawValue:
            return .noResponse(timeout: timeout)
        default:
            return .failed(error)
        }
    }

    /// Stores the continuation, or resumes it at once when the race is already resolved.
    ///
    /// - Returns: Whether the race was already resolved, in which case nothing must be started.
    private func install(_ continuation: CheckedContinuation<SMBKeepAliveEchoOutcome, Never>) -> Bool {
        let ready = state.withLock { state -> SMBKeepAliveEchoOutcome? in
            switch state.phase {
            case let .resolved(outcome):
                state.phase = .delivered
                return outcome
            default:
                state.phase = .suspended(continuation)
                return nil
            }
        }
        guard let ready else { return false }
        continuation.resume(returning: ready)
        return true
    }

    /// Records that the echo started and starts the deadline. Only the first call has an effect.
    func start() {
        let now = DispatchTime.now().uptimeNanoseconds
        let startsTimer = state.withLock { state -> Bool in
            guard state.startedAt == nil else { return false }
            state.startedAt = now
            return !state.isResolved
        }
        guard startsTimer else { return }
        let timeout = timeout
        let timer = Task {
            do {
                try await SMBKeepAliveEngine.sleep(seconds: timeout)
                self.resolve(.noResponse(timeout: timeout))
            }
            catch {
            }
        }
        // The race may have resolved while the timer was being created: then nobody else will cancel it.
        let keptTimer = state.withLock { state -> Bool in
            guard !state.isResolved else { return false }
            state.timer = timer
            return true
        }
        if !keptTimer {
            timer.cancel()
        }
    }

    private func roundTrip() -> TimeInterval {
        let end = DispatchTime.now().uptimeNanoseconds
        let start = state.withLock { $0.startedAt } ?? createdAt
        return SMBKeepAliveEngine.seconds(from: start, to: end)
    }

    /// Only the first call has an effect. Cancels the deadline timer.
    private func resolve(_ outcome: SMBKeepAliveEchoOutcome) {
        let (continuation, timer) = state.withLock { state in
            let timer = state.timer
            state.timer = nil
            switch state.phase {
            case .waiting:
                state.phase = .resolved(outcome)
                return (CheckedContinuation<SMBKeepAliveEchoOutcome, Never>?.none, timer)
            case let .suspended(continuation):
                state.phase = .delivered
                return (continuation, timer)
            case .resolved, .delivered:
                return (nil, timer)
            }
        }
        timer?.cancel()
        continuation?.resume(returning: outcome)
    }
}
