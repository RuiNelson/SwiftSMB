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
        /// The keep-alive enforces this deadline itself, independently of the command timeout `libsmb2` applies. The
        /// deadline in force is never longer than the connection's command timeout (``SMB/Configuration/timeout``, or
        /// the value set with ``SMB/Connection/setTimeout(_:)``) when that is not zero, so a larger value is reduced to
        /// it. With no command timeout, this value is used as it is.
        public var timeout: TimeInterval {
            didSet { Self.validate(timeout, named: "timeout") }
        }

        /// The round-trip time above which an answered echo is reported as ``KeepAliveProblem/slow(roundTrip:)``, in
        /// seconds. Always finite and greater than zero.
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
        /// connection keeps it alive until the keep-alive stops.
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

        /// The server did not answer within the deadline, in seconds. The connection is most likely broken. The
        /// keep-alive stops.
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

    /// Runs until a failure, until it is no longer current, or until its task is cancelled.
    ///
    /// - Parameters:
    ///   - isCurrent: Whether this run is still the connection's keep-alive. Checked before every callback, so none
    /// starts once the keep-alive was stopped or replaced.
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
final class SMBKeepAliveEchoRace: Sendable {
    private enum State {
        case waiting
        case suspended(CheckedContinuation<SMBKeepAliveEchoOutcome, Never>)
        case resolved(SMBKeepAliveEchoOutcome)
        case delivered
    }

    private let state = Protected(State.waiting, label: "com.ruinelson.SwiftSMB.keepAlive.echoRace")
    private let timer = Protected<Task<Void, Never>?>(nil, label: "com.ruinelson.SwiftSMB.keepAlive.echoRace.timer")

    /// Runs `echo` against `timeout`.
    ///
    /// - Parameters:
    ///   - timeout: The deadline, in seconds.
    ///   - echo: Sends the echo and throws when it fails.
    static func run(
        timeout: TimeInterval,
        echo: @escaping @Sendable () async throws -> Void
    ) async -> SMBKeepAliveEchoOutcome {
        let race = SMBKeepAliveEchoRace()
        let start = DispatchTime.now().uptimeNanoseconds
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                race.install(continuation)
                race.timer.current = Task {
                    do {
                        try await SMBKeepAliveEngine.sleep(seconds: timeout)
                        race.resolve(.noResponse(timeout: timeout))
                    }
                    catch {
                    }
                }
                Task {
                    do {
                        try await echo()
                        let end = DispatchTime.now().uptimeNanoseconds
                        race.resolve(.answered(roundTrip: SMBKeepAliveEngine.seconds(from: start, to: end)))
                    }
                    catch {
                        race.resolve(Self.outcome(for: error))
                    }
                }
            }
        } onCancel: {
            race.resolve(.stopped)
        }
    }

    private static func outcome(for error: any Error) -> SMBKeepAliveEchoOutcome {
        if let error = error as? SMB.Error, case .operationRequestedAfterConnectionClosed = error {
            return .stopped
        }
        return .failed(error)
    }

    private func install(_ continuation: CheckedContinuation<SMBKeepAliveEchoOutcome, Never>) {
        let ready = state.withLock { state -> SMBKeepAliveEchoOutcome? in
            switch state {
            case let .resolved(outcome):
                state = .delivered
                return outcome
            default:
                state = .suspended(continuation)
                return nil
            }
        }
        if let ready {
            continuation.resume(returning: ready)
        }
    }

    /// Only the first call has an effect.
    private func resolve(_ outcome: SMBKeepAliveEchoOutcome) {
        let continuation = state.withLock { state -> CheckedContinuation<SMBKeepAliveEchoOutcome, Never>? in
            switch state {
            case .waiting:
                state = .resolved(outcome)
                return nil
            case let .suspended(continuation):
                state = .delivered
                return continuation
            case .resolved, .delivered:
                return nil
            }
        }
        timer.take(replacingWith: nil)?.cancel()
        continuation?.resume(returning: outcome)
    }
}
