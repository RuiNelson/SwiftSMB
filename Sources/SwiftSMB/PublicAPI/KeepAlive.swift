//
// Part of SwiftSMB
// KeepAlive.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
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
        /// a single request that takes longer fails with ``SMB/SMBStatus/ioTimeout``, and a blocking
        /// ``SMB/File/lock(_:nonBlocking:range:)`` that used to wait indefinitely gives up with
        /// ``SMB/SMBStatus/ioTimeout`` once it expires. On a slow link, with large transfer blocks, or to wait for
        /// locks, set a command timeout of your own, greater than zero and long enough, with
        /// ``SMB/Configuration/timeout`` or ``SMB/Connection/setTimeout(_:)`` before starting the keep-alive; the
        /// keep-alive leaves it alone. ``SMB/Connection/fork()`` does not inherit the imposed timeout. The imposed
        /// timeout is removed by ``SMB/Connection/stopKeepAlive()``, unless ``SMB/Connection/setTimeout(_:)`` was
        /// called meanwhile; it stays after a problem stops the keep-alive, and when the connection disconnects (see
        /// ``SMB/Connection/startKeepAlive(_:)``).
        ///
        /// Setting the command timeout to `0` with ``SMB/Connection/setTimeout(_:)`` while the keep-alive runs removes
        /// that protection: an echo to a server that no longer answers can then hold the connection, and a
        /// ``SMB/Connection/disconnect()`` behind it, until the operating system gives up on the TCP connection. A
        /// later ``SMB/Connection/startKeepAlive(_:)`` imposes a timeout again over that `0`.
        public var timeout: TimeInterval {
            didSet { Self.validate(timeout, named: "timeout") }
        }

        /// The round-trip time above which an answered echo is reported as ``KeepAliveProblem/slow(roundTrip:)``, in
        /// seconds. Always finite and greater than zero.
        ///
        /// The round trip is measured on the connection, from when the echo starts running there until its answer is
        /// processed, so a busy thread pool does not lengthen it. An echo that takes longer than the deadline in force
        /// (see ``timeout``) is reported as ``KeepAliveProblem/noResponse(timeout:)``, so a value at or above that
        /// deadline never reports a slow answer.
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
        /// The closure runs in a task of its own, which inherits neither the caller's task-local values nor its
        /// cancellation: stopping or replacing the keep-alive, or disconnecting, from inside the closure does not
        /// cancel the rest of it, so it can go on sleeping, reconnecting or using another connection. The keep-alive
        /// still ends once the closure returns.
        ///
        /// A call that was already starting when ``SMB/Connection/stopKeepAlive()`` or
        /// ``SMB/Connection/startKeepAlive(_:)`` was called can still run once; none starts later. Stopping does not
        /// wait for a call that is running.
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

    /// Calls `onProblem` in a task of its own and waits for it to return.
    ///
    /// Stopping, replacing or disconnecting from inside the callback cancels the keep-alive's task. The callback must
    /// not run cancelled because of that, so it is not a child of that task, and inherits neither its cancellation nor
    /// its task-local values. Cancelling the keep-alive's task does not interrupt the wait either: the run ends once
    /// the callback returns.
    static func report(
        _ problem: SMB.KeepAliveProblem,
        to onProblem: @escaping @Sendable (SMB.KeepAliveProblem) async -> Void
    ) async {
        await Task.detached {
            await onProblem(problem)
        }.value
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
                        await report(.slow(roundTrip: roundTrip), to: configuration.onProblem)
                    }
                case let .noResponse(timeout):
                    guard let after = snapshot() else { return }
                    if isInconclusive(before: state.lastActivity, after: after) {
                        continue
                    }
                    if isCurrent() {
                        await report(.noResponse(timeout: timeout), to: configuration.onProblem)
                    }
                    return
                case let .failed(error):
                    if isCurrent() {
                        await report(.failed(error), to: configuration.onProblem)
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
/// does once the echo runs on its queue: time spent waiting behind other operations is not the server's. The echo calls
/// `finished` on the queue too, as soon as the answer (or the failure) is processed, and that resolves the race there
/// and then, with the round trip between the two stamps. Neither depends on when a task resumes on the thread pool, so
/// a saturated pool cannot turn an answer in time into `.noResponse` or `.slow`: the outcome follows the order of the
/// stamps, and an echo that finishes more than the deadline after it started is `.noResponse` whichever side notices.
///
/// An echo that never starts has no deadline: the keep-alive only sends an echo when no operation is running, an
/// operation that starts later queues behind it, and while the keep-alive runs the connection has a command timeout
/// unless the user set it to zero, so nothing holds the queue for long. Stopping or replacing the keep-alive, or
/// disconnecting, cancels the wait.
final class SMBKeepAliveEchoRace: Sendable {
    /// Sends the echo and throws when it fails. It calls `started` when the echo starts running, and `finished` with
    /// its error, or `nil`, as soon as it ends; both must return quickly. An echo that ends without calling `finished`
    /// is taken as finished when it returns or throws.
    typealias Echo = @Sendable (
        _ started: @escaping @Sendable () -> Void,
        _ finished: @escaping @Sendable (any Error?) -> Void
    ) async throws -> Void

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
    ///   - echo: Sends the echo (see ``Echo``).
    static func run(timeout: TimeInterval, echo: @escaping Echo) async -> SMBKeepAliveEchoOutcome {
        await SMBKeepAliveEchoRace(timeout: timeout).run(echo: echo)
    }

    /// Runs `echo` against the deadline. A race runs once.
    func run(echo: @escaping Echo) async -> SMBKeepAliveEchoOutcome {
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                // Already cancelled: no echo is sent and no timer is started.
                guard !install(continuation) else { return }
                Task {
                    do {
                        try await echo({ self.start() }, { self.finish($0) })
                        finish(nil)
                    }
                    catch {
                        finish(error)
                    }
                }
            }
        } onCancel: {
            resolve { _, _ in .stopped }
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
            // `Task.sleep` may not use the clock of the stamps, so the stamps decide, and it sleeps again if needed.
            var remaining = timeout
            while true {
                do {
                    try await SMBKeepAliveEngine.sleep(seconds: remaining)
                }
                catch {
                    return
                }
                guard let left = self.expire() else { return }
                remaining = left
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

    /// Records that the echo finished, with its error or `nil`, and resolves the race from the stamps. Only the first
    /// call has an effect. The connection calls it on its queue, right after the echo.
    func finish(_ error: any Error?) {
        let timeout = timeout
        let createdAt = createdAt
        resolve { startedAt, now in
            if let error, case .stopped = Self.outcome(for: error, timeout: timeout) {
                return .stopped
            }
            if let startedAt, SMBKeepAliveEngine.seconds(from: startedAt, to: now) > timeout {
                return .noResponse(timeout: timeout)
            }
            if let error {
                return Self.outcome(for: error, timeout: timeout)
            }
            return .answered(roundTrip: SMBKeepAliveEngine.seconds(from: startedAt ?? createdAt, to: now))
        }
    }

    /// Resolves the race as `.noResponse` once more than the deadline has passed since the echo started.
    ///
    /// - Returns: `nil` when the race is resolved, or the seconds left before the deadline.
    private func expire() -> TimeInterval? {
        let timeout = timeout
        var left: TimeInterval?
        resolve { startedAt, now in
            // The timer only exists once the echo started.
            guard let startedAt else { return nil }
            let elapsed = SMBKeepAliveEngine.seconds(from: startedAt, to: now)
            guard elapsed > timeout else {
                left = timeout - elapsed
                return nil
            }
            return .noResponse(timeout: timeout)
        }
        return left
    }

    /// Resolves the race with what `decide` returns, unless it is already resolved or `decide` returns `nil`. `decide`
    /// runs under the lock with the time the echo started and the current time, both stamped under it, so the order of
    /// the stamps is the order in which the race sees them. Cancels the deadline timer when it resolves.
    private func resolve(_ decide: (_ startedAt: UInt64?, _ now: UInt64) -> SMBKeepAliveEchoOutcome?) {
        let (continuation, timer, outcome) = state.withLock { state in
            guard !state.isResolved,
                  let outcome = decide(state.startedAt, DispatchTime.now().uptimeNanoseconds) else {
                return (
                    CheckedContinuation<SMBKeepAliveEchoOutcome, Never>?.none,
                    Task<Void, Never>?.none,
                    SMBKeepAliveEchoOutcome?.none
                )
            }
            let timer = state.timer
            state.timer = nil
            switch state.phase {
            case let .suspended(continuation):
                state.phase = .delivered
                return (continuation, timer, outcome)
            default:
                state.phase = .resolved(outcome)
                return (nil, timer, outcome)
            }
        }
        timer?.cancel()
        if let continuation, let outcome {
            continuation.resume(returning: outcome)
        }
    }
}
