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
    /// while a keep-alive is running replaces it, so the previous configuration is no longer used and no callback of it
    /// starts after this method returns.
    ///
    /// The keep-alive also stops with ``stopKeepAlive()``, ``disconnect()``, ``disconnectGracefully()`` and when the
    /// connection is deallocated. It never keeps the connection alive. It does not reconnect.
    ///
    /// - Parameter configuration: How the keep-alive behaves and where it reports.
    /// - Throws: ``SMB/Error/operationRequestedAfterConnectionClosed`` if the connection is closed.
    func startKeepAlive(_ configuration: SMB.KeepAliveConfiguration) throws {
        guard isConnected else { throw SMB.Error.operationRequestedAfterConnectionClosed }
        protectedKeepAlive.withLock { registry in
            registry.task?.cancel()
            registry.generation += 1
            let generation = registry.generation
            let weakConnection = SMBWeakConnection(self)
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
        }
    }

    /// Stops the keep-alive. Does nothing when none is running.
    ///
    /// The call does not wait for the keep-alive's task, so it may be made from
    /// ``SMB/KeepAliveConfiguration/onProblem``. No callback starts after it returns.
    func stopKeepAlive() {
        let task = protectedKeepAlive.withLock { registry -> Task<Void, Never>? in
            registry.generation += 1
            let task = registry.task
            registry.task = nil
            return task
        }
        task?.cancel()
    }
}

private extension SMB.Connection {
    func isCurrentKeepAlive(_ generation: UInt64) -> Bool {
        protectedKeepAlive.withLock { $0.generation == generation }
    }

    /// Clears the keep-alive that ended by itself, unless it was stopped or replaced meanwhile.
    func finishKeepAlive(_ generation: UInt64) {
        protectedKeepAlive.withLock { registry in
            if registry.generation == generation {
                registry.task = nil
            }
        }
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
    func sendKeepAliveEcho(configuredTimeout: TimeInterval) async -> SMBKeepAliveEchoOutcome {
        do {
            return try await withOperation(trackingActivity: false) {
                let context = try requireContext()
                let commandTimeout = try await Bridge.timeout(context: context)
                let timeout = SMBKeepAliveEngine.effectiveTimeout(
                    configured: configuredTimeout,
                    connectionTimeoutSeconds: commandTimeout
                )
                return await SMBKeepAliveEchoRace.run(timeout: timeout) {
                    try await Bridge.echo(context: context)
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
