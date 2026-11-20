//
// Part of SwiftSMB
// Connection-KeepAlive.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

/// The connection's keep-alive: its task, and which start it belongs to.
struct SMBKeepAliveRegistry: Sendable {
    /// Increases on every start and stop, so a run can tell that it was stopped or replaced.
    var generation: UInt64 = 0
    var task: Task<Void, Never>?
}

/// The command timeout in force on a connection's context, and whether the keep-alive imposed it.
struct SMBCommandTimeout: Sendable, Equatable {
    /// In seconds. `0` disables command timeouts.
    var seconds: Int
    /// Whether ``seconds`` is the keep-alive's, given because the connection had no command timeout. The keep-alive
    /// puts back `0` when it stops, unless the user set a timeout meanwhile.
    var imposedByKeepAlive = false

    /// Gives a connection with no command timeout, or with one an earlier keep-alive imposed, the keep-alive's deadline
    /// in whole seconds. A timeout the user chose is left alone.
    ///
    /// - Returns: Whether ``seconds`` changed.
    mutating func imposeForKeepAlive(timeout: TimeInterval) -> Bool {
        guard seconds == 0 || imposedByKeepAlive else { return false }
        let imposed = SMBKeepAliveEngine.imposedTimeoutSeconds(for: timeout)
        let changed = seconds != imposed
        seconds = imposed
        imposedByKeepAlive = true
        return changed
    }

    /// Puts back "no command timeout" when the keep-alive imposed the current one.
    ///
    /// - Returns: Whether ``seconds`` changed.
    mutating func restoreAfterKeepAlive() -> Bool {
        guard imposedByKeepAlive else { return false }
        imposedByKeepAlive = false
        let changed = seconds != 0
        seconds = 0
        return changed
    }

    /// A timeout set with ``SMB/Connection/setTimeout(_:)``, which the keep-alive never restores.
    mutating func setByUser(_ seconds: Int) {
        self.seconds = seconds
        imposedByKeepAlive = false
    }
}

/// Lets the keep-alive's task refer to its connection without keeping it alive.
private final class SMBWeakConnection: Sendable {
    weak let connection: SMB.Connection?

    init(_ connection: SMB.Connection) {
        self.connection = connection
    }
}

public extension SMB.Connection {
    /// A Boolean value indicating whether a keep-alive is running on this connection.
    ///
    /// It becomes `false` after ``stopKeepAlive()``, after a problem that stops the keep-alive, and when the connection
    /// is disconnected.
    var isKeepAliveRunning: Bool {
        protectedKeepAlive.withLock { $0.task != nil }
    }

    /// Starts sending SMB echo requests while the connection is idle, so that the server and the network between keep
    /// it open, and tells you when the connection stops answering.
    ///
    /// The keep-alive is quiet while the connection is used: every operation, from the moment it starts until it
    /// finishes, postpones the next echo, so a busy connection sends none. Starting counts as activity, so the first
    /// echo comes after a whole ``SMB/KeepAliveConfiguration/interval``.
    ///
    /// ``SMB/KeepAliveConfiguration/onProblem`` is called when the server answers slowly, which does not stop the
    /// keep-alive, and when it does not answer or the echo fails, after which the keep-alive stops. Calling this method
    /// while a keep-alive is running replaces it, so the previous configuration is no longer used: no callback of it
    /// starts after this method returns, although one that was already starting may still run.
    ///
    /// The keep-alive also stops with ``stopKeepAlive()``, ``disconnect()``, ``disconnectGracefully()`` and when the
    /// connection is deallocated. It never keeps the connection alive by itself, but a callback that captures the
    /// connection strongly does until the keep-alive stops. It does not reconnect.
    ///
    /// - Important: If the connection has no command timeout (``SMB/Configuration/timeout`` is `nil` or `0`, and
    ///   ``setTimeout(_:)`` was not called with a positive value), the keep-alive gives it one while it runs:
    ///   ``SMB/KeepAliveConfiguration/timeout`` rounded up to whole seconds (2.1 s becomes 3 s). Otherwise an echo to a
    ///   server that no longer answers would hold the connection, and a ``disconnect()`` behind it, until the operating
    /// system gives up on the TCP connection. That timeout applies to every operation on the connection: a single
    /// request that takes longer, such as a large block on a slow link, fails with ``SMB/SMBStatus/ioTimeout``, and
    ///   ``fork()`` starts the new connection with it. Set a command timeout of your own on slow connections; the
    ///   keep-alive leaves it alone. When the keep-alive stops, it puts back "no command timeout", unless
    ///   ``setTimeout(_:)`` was called meanwhile, whose value then stays.
    ///
    /// - Parameter configuration: How the keep-alive behaves and where it reports.
    /// - Throws: ``SMB/Error/operationRequestedAfterConnectionClosed`` if the connection is closed, or is disconnecting
    /// gracefully.
    func startKeepAlive(_ configuration: SMB.KeepAliveConfiguration) throws {
        let weakConnection = SMBWeakConnection(self)
        // Admission is checked under the keep-alive's lock, and disconnection closes admission before it stops the
        // keep-alive under that lock, so a keep-alive is never left running on a closed connection.
        let started = protectedKeepAlive.withLock { registry -> Result<(Task<Void, Never>?, Bool), SMB.Error> in
            guard isConnected, protectedOperations.withLock({ $0.phase == .accepting }) else {
                return .failure(.operationRequestedAfterConnectionClosed)
            }
            let previous = registry.task
            registry.generation += 1
            let generation = registry.generation
            let timeoutChanged = protectedCommandTimeout.withLock {
                $0.imposeForKeepAlive(timeout: configuration.timeout)
            }
            registry.task = Task {
                await SMBKeepAliveEngine.run(
                    configuration: configuration,
                    isCurrent: { weakConnection.connection?.isCurrentKeepAlive(generation) ?? false },
                    snapshot: { weakConnection.connection?.keepAliveSnapshot() },
                    sendEcho: {
                        guard let connection = weakConnection.connection else { return .stopped }
                        return await connection.sendKeepAliveEcho(configuredTimeout: configuration.timeout)
                    },
                    markActivity: { weakConnection.connection?.markActivity() }
                )
                weakConnection.connection?.finishKeepAlive(generation)
            }
            return .success((previous, timeoutChanged))
        }
        let (previous, timeoutChanged) = try started.get()
        previous?.cancel()
        if timeoutChanged {
            applyCommandTimeoutInBackground()
        }
    }

    /// Stops the keep-alive. Does nothing when none is running.
    ///
    /// The call does not wait for the keep-alive's task, so it may be made from
    /// ``SMB/KeepAliveConfiguration/onProblem``. No callback starts after it returns, although one that was already
    /// starting may still run. A command timeout the keep-alive imposed is removed (see ``startKeepAlive(_:)``).
    func stopKeepAlive() {
        let (task, timeoutChanged) = protectedKeepAlive.withLock { registry -> (Task<Void, Never>?, Bool) in
            registry.generation += 1
            let task = registry.task
            registry.task = nil
            return (task, protectedCommandTimeout.withLock { $0.restoreAfterKeepAlive() })
        }
        task?.cancel()
        if timeoutChanged {
            applyCommandTimeoutInBackground()
        }
    }
}

private extension SMB.Connection {
    func isCurrentKeepAlive(_ generation: UInt64) -> Bool {
        protectedKeepAlive.withLock { $0.generation == generation }
    }

    /// Clears the keep-alive that ended by itself, unless it was stopped or replaced meanwhile, and removes the command
    /// timeout it imposed.
    func finishKeepAlive(_ generation: UInt64) {
        let timeoutChanged = protectedKeepAlive.withLock { registry -> Bool in
            guard registry.generation == generation else { return false }
            registry.task = nil
            return protectedCommandTimeout.withLock { $0.restoreAfterKeepAlive() }
        }
        if timeoutChanged {
            applyCommandTimeoutInBackground()
        }
    }

    /// Brings the context's command timeout in line with ``protectedCommandTimeout``. The value is read on the queue,
    /// so whichever change is enqueued last, the context ends with the latest one.
    func applyCommandTimeoutInBackground() {
        guard let context = try? requireContext() else { return }
        let commandTimeout = protectedCommandTimeout
        Bridge.setTimeoutInBackground(context: context) { commandTimeout.current.seconds }
    }

    /// The operation count and last activity, or `nil` when the connection no longer takes operations.
    func keepAliveSnapshot() -> (activeCount: Int, lastActivity: UInt64)? {
        guard isConnected else { return nil }
        return protectedOperations.withLock { state in
            state.phase == .accepting ? (state.activeCount, state.lastActivity) : nil
        }
    }

    func markActivity() {
        protectedOperations.withLock { $0.lastActivity = DispatchTime.now().uptimeNanoseconds }
    }

    /// Sends one echo that does not count as activity, against the deadline in force.
    ///
    /// The deadline uses the command timeout kept in Swift, so nothing waits on the context queue before the echo, and
    /// it starts when the echo starts running on the queue.
    func sendKeepAliveEcho(configuredTimeout: TimeInterval) async -> SMBKeepAliveEchoOutcome {
        do {
            return try await withOperation(trackingActivity: false) {
                let context = try requireContext()
                let timeout = SMBKeepAliveEngine.effectiveTimeout(
                    configured: configuredTimeout,
                    connectionTimeoutSeconds: commandTimeoutSeconds
                )
                return await SMBKeepAliveEchoRace.run(timeout: timeout) { started in
                    try await Bridge.echo(context: context, onStart: started)
                }
            }
        }
        catch SMB.Error.operationRequestedAfterConnectionClosed {
            return .stopped
        }
        catch {
            return .failed(error)
        }
    }
}
