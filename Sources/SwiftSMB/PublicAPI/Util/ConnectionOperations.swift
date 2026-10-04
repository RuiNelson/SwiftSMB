//
// Part of SwiftSMB
// ConnectionOperations.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// Admission and completion state for complete public operations on a connection.
struct SMBConnectionOperations: Sendable {
    enum Phase: Equatable, Sendable {
        case accepting
        case draining
        case closed
    }

    var phase: Phase = .accepting
    var activeCount = 0
    var waiters: [CheckedContinuation<Void, Never>] = []
}

/// Keeps an operation admitted until its entire async body and cleanup have completed.
private final class SMBConnectionOperation: Sendable {
    private let protectedConnection: Protected<SMB.Connection?>

    var isActive: Bool {
        protectedConnection.current != nil
    }

    init(connection: SMB.Connection) {
        protectedConnection = Protected(connection, label: "com.ruinelson.SwiftSMB.operation.connection")
    }

    deinit {
        finish()
    }

    func finish() {
        // Child tasks can retain a completed task-local scope. Release the connection at completion so those scopes
        // cannot keep a connection and its watcher tasks alive through a retain cycle.
        guard let connection = protectedConnection.take(replacingWith: nil) else { return }
        connection.finishOperation()
    }
}

extension SMB.Connection {
    @TaskLocal private static var operationScopes: [ObjectIdentifier: SMBConnectionOperation] = [:]

    /// Admits a complete operation, including calls it makes while graceful disconnection is draining.
    nonisolated(nonsending) func withOperation<T: Sendable>(_ body: () async throws -> T) async throws -> T {
        let identity = ObjectIdentifier(self)
        let inheritedOperation = Self.operationScopes[identity]
        let admission = protectedOperations.withLock { state -> Result<SMBConnectionOperation, SMB.Error> in
            let isNested = inheritedOperation?.isActive == true
            guard state.phase != .closed,
                  state.phase == .accepting || isNested,
                  isConnected else {
                return .failure(SMB.Error.operationRequestedAfterConnectionClosed)
            }
            state.activeCount += 1
            return .success(SMBConnectionOperation(connection: self))
        }
        let operation = try admission.get()
        defer { operation.finish() }

        var scopes = Self.operationScopes
        scopes[identity] = operation
        return try await Self.$operationScopes.withValue(scopes) {
            try await body()
        }
    }

    fileprivate func finishOperation() {
        let waiters = protectedOperations.withLock { state in
            state.activeCount -= 1
            guard state.activeCount == 0 else { return [CheckedContinuation<Void, Never>]() }
            let waiters = state.waiters
            state.waiters.removeAll()
            return waiters
        }
        for waiter in waiters {
            waiter.resume()
        }
    }

    /// Stops new external operations and waits for all admitted operations to finish.
    func drainOperations() async {
        await withCheckedContinuation { continuation in
            let waitImmediately = protectedOperations.withLock { state in
                guard state.phase != .closed else { return true }
                state.phase = .draining
                guard state.activeCount > 0 else { return true }
                state.waiters.append(continuation)
                return false
            }
            if waitImmediately {
                continuation.resume()
            }
        }
    }

    /// Closes admission immediately. Explicit disconnection takes precedence over graceful draining.
    func closeOperationAdmission() {
        let waiters = protectedOperations.withLock { state in
            state.phase = .closed
            let waiters = state.waiters
            state.waiters.removeAll()
            return waiters
        }
        for waiter in waiters {
            waiter.resume()
        }
    }
}
