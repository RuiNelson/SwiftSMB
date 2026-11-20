//
// Part of SwiftSMB
// SMBKeepAliveTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite(.tags(.integration), .serverConcurrencyLimit)
struct SMBKeepAliveTests {
    /// Below any real round trip, so every answered echo is reported as slow: the observable sign that one was sent.
    private static let reportEveryEcho: TimeInterval = 1e-9

    private func makeConfiguration(
        interval: TimeInterval = 0.1,
        timeout: TimeInterval = 2,
        slowRoundTrip: TimeInterval = 5,
        problems: ProblemLog = ProblemLog()
    ) -> SMB.KeepAliveConfiguration {
        SMB.KeepAliveConfiguration(interval: interval, timeout: timeout, slowRoundTrip: slowRoundTrip) { problem in
            problems.record(problem)
        }
    }

    private func connect(timeout: Int? = nil) async throws -> SMB.Connection {
        try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: SMB.Configuration(timeout: timeout)
        )
    }

    // MARK: Echoes

    @Test("an idle connection gets echoes that the server answers, and stays usable")
    func idleConnectionStaysUsable() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }
        let problems = ProblemLog()

        try connection.startKeepAlive(makeConfiguration(slowRoundTrip: Self.reportEveryEcho, problems: problems))
        #expect(connection.isKeepAliveRunning)

        // Each answered echo is reported as slow, so two reports prove that echoes went out and came back.
        try await waitUntil { problems.slowCount >= 2 }
        #expect(connection.isKeepAliveRunning)
        #expect(problems.otherCount == 0)
        _ = try await connection.listDirectory(at: "")
    }

    @Test("stopKeepAlive stops it and may be called again")
    func stopKeepAlive() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }

        #expect(!connection.isKeepAliveRunning)
        connection.stopKeepAlive()
        try connection.startKeepAlive(makeConfiguration())
        #expect(connection.isKeepAliveRunning)
        connection.stopKeepAlive()
        #expect(!connection.isKeepAliveRunning)
        connection.stopKeepAlive()
    }

    @Test("starting again replaces the running keep-alive, whose configuration is no longer used")
    func startReplaces() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }
        let first = ProblemLog()
        let second = ProblemLog()

        try connection.startKeepAlive(makeConfiguration(slowRoundTrip: Self.reportEveryEcho, problems: first))
        try connection.startKeepAlive(makeConfiguration(slowRoundTrip: Self.reportEveryEcho, problems: second))
        #expect(connection.isKeepAliveRunning)

        // The first one would have reported its first echo after the same interval.
        try await waitUntil { second.slowCount >= 2 }
        #expect(first.count == 0)
        connection.stopKeepAlive()
        #expect(!connection.isKeepAliveRunning)
    }

    // MARK: Disconnection

    @Test("disconnecting stops the keep-alive and a closed connection refuses to start one")
    func disconnectStops() async throws {
        let connection = try await connect()
        let problems = ProblemLog()
        try connection.startKeepAlive(makeConfiguration(problems: problems))

        try await connection.disconnect()
        #expect(!connection.isKeepAliveRunning)
        try await Task.sleep(nanoseconds: 400_000_000)
        #expect(problems.count == 0)

        #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try connection.startKeepAlive(makeConfiguration())
        }
    }

    @Test("disconnecting gracefully stops a keep-alive that was sending echoes, without reporting a problem")
    func gracefulDisconnectStops() async throws {
        let connection = try await connect()
        let problems = ProblemLog()
        try connection.startKeepAlive(makeConfiguration(slowRoundTrip: Self.reportEveryEcho, problems: problems))
        try await waitUntil { problems.slowCount >= 1 }

        try await connection.disconnectGracefully()
        #expect(!connection.isKeepAliveRunning)
        let reported = problems.count
        // Several intervals go by: no echo is answered or fails on the closed connection.
        try await Task.sleep(nanoseconds: 500_000_000)
        #expect(problems.count == reported)
        #expect(problems.otherCount == 0)
    }

    @Test("startKeepAlive throws while the connection disconnects gracefully")
    func startDuringGracefulDisconnectThrows() async throws {
        let connection = try await connect()
        let release = Flag()
        let holding = Task {
            try await connection.withOperation {
                while !release.isSet {
                    try await Task.sleep(nanoseconds: 10_000_000)
                }
            }
        }
        try await waitUntil { connection.protectedOperations.current.activeCount > 0 }
        let disconnecting = Task { try await connection.disconnectGracefully() }
        try await waitUntil { connection.protectedOperations.current.phase == .draining }

        #expect(connection.isConnected)
        #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try connection.startKeepAlive(makeConfiguration())
        }
        #expect(!connection.isKeepAliveRunning)

        release.set()
        try await holding.value
        try await disconnecting.value
        #expect(!connection.isConnected)
    }

    @Test("the keep-alive does not keep its connection alive")
    func doesNotRetainTheConnection() async throws {
        let box = try await startedConnectionBox()
        try await withTimeout(seconds: 10) {
            while box.connection != nil {
                try await Task.sleep(nanoseconds: 20_000_000)
            }
        }
        #expect(box.connection == nil)
    }

    // MARK: Callbacks

    @Test("the callback may stop the keep-alive")
    func callbackStops() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }
        let returned = Flag()
        let work = CallbackWork()
        let weakConnection = WeakConnection(connection)

        try connection.startKeepAlive(SMB.KeepAliveConfiguration(
            interval: 0.1,
            slowRoundTrip: Self.reportEveryEcho
        ) { _ in
            guard !returned.isSet, let connection = weakConnection.connection else { return }
            connection.stopKeepAlive()
            // The rest of the callback is not cancelled by the stop: it can still wait and use the connection.
            await work.record(on: connection)
            returned.set()
        })
        try await waitUntil { returned.isSet }
        #expect(!connection.isKeepAliveRunning)
        work.expectNotCancelled(listed: true)
        _ = try await connection.listDirectory(at: "")
    }

    @Test("the callback may start another keep-alive")
    func callbackRestarts() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }
        let replacement = ProblemLog()
        let weakConnection = WeakConnection(connection)
        let replacementConfiguration = makeConfiguration(slowRoundTrip: Self.reportEveryEcho, problems: replacement)
        let restarted = Flag()
        let returned = Flag()
        let work = CallbackWork()

        try connection.startKeepAlive(SMB.KeepAliveConfiguration(
            interval: 0.1,
            slowRoundTrip: Self.reportEveryEcho
        ) { _ in
            guard !restarted.isSet, let connection = weakConnection.connection else { return }
            restarted.set()
            try? connection.startKeepAlive(replacementConfiguration)
            await work.record(on: connection)
            returned.set()
        })
        try await waitUntil { replacement.slowCount >= 1 && returned.isSet }
        #expect(connection.isKeepAliveRunning)
        work.expectNotCancelled(listed: true)
    }

    @Test("the callback may disconnect")
    func callbackDisconnects() async throws {
        let connection = try await connect()
        let returned = Flag()
        let weakConnection = WeakConnection(connection)
        let work = CallbackWork()

        try connection.startKeepAlive(SMB.KeepAliveConfiguration(
            interval: 0.1,
            timeout: 2,
            slowRoundTrip: Self.reportEveryEcho
        ) { _ in
            guard !returned.isSet, let connection = weakConnection.connection else { return }
            try? await connection.disconnect()
            // Nothing to list on a closed connection, but the callback still runs uncancelled.
            await work.record(on: nil)
            returned.set()
        })
        try await waitUntil { returned.isSet }
        #expect(!connection.isConnected)
        #expect(!connection.isKeepAliveRunning)
        work.expectNotCancelled(listed: false)
        // The disconnection kept the command timeout the keep-alive imposed instead of restoring 0 before it.
        #expect(connection.protectedCommandTimeout.current == SMBCommandTimeout(seconds: 2, imposedByKeepAlive: true))
    }

    // MARK: Activity

    @Test("tracked operations stamp the last activity, untracked ones (the keep-alive's echo) do not")
    func operationsStampActivity() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }

        let initial = connection.protectedOperations.current.lastActivity
        try await Task.sleep(nanoseconds: 2_000_000)
        try await connection.withOperation(trackingActivity: false) {
            #expect(connection.protectedOperations.current.lastActivity == initial)
        }
        #expect(connection.protectedOperations.current.lastActivity == initial)

        try await connection.withOperation {
            #expect(connection.protectedOperations.current.lastActivity > initial)
        }
        let admittedAndFinished = connection.protectedOperations.current.lastActivity
        #expect(admittedAndFinished > initial)

        try await Task.sleep(nanoseconds: 2_000_000)
        try await connection.echo()
        #expect(connection.protectedOperations.current.lastActivity > admittedAndFinished)
    }

    // MARK: Command timeout

    @Test("a connection with no command timeout gets the keep-alive's, rounded up, until it stops")
    func imposesAndRestoresTheCommandTimeout() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }

        try connection.startKeepAlive(makeConfiguration(timeout: 2.1))
        #expect(connection.commandTimeoutSeconds == 3)
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 3)

        connection.stopKeepAlive()
        #expect(connection.commandTimeoutSeconds == 0)
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 0)
    }

    @Test("a replacing keep-alive imposes its own timeout, and a fork does not inherit it")
    func replacementImposesAndForkKeepsTheUsersTimeout() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }

        try connection.startKeepAlive(makeConfiguration(timeout: 1))
        try connection.startKeepAlive(makeConfiguration(timeout: 4.5))
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 5)

        let fork = try await connection.fork()
        defer { try? await fork.disconnect() }
        // The user chose no command timeout, which the fork keeps in its configured form.
        #expect(fork.configuration.timeout == nil)
        #expect(fork.commandTimeoutSeconds == 0)
        #expect(try await Bridge.timeout(context: fork.requireContext()) == 0)
        #expect(!fork.isKeepAliveRunning)
    }

    @Test("a fork inherits the timeout set with setTimeout, not one the keep-alive imposes over it")
    func forkInheritsTheUsersTimeout() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }

        try await connection.setTimeout(9)
        try connection.startKeepAlive(makeConfiguration(timeout: 1))
        let fork = try await connection.fork()
        defer { try? await fork.disconnect() }
        #expect(fork.configuration.timeout == 9)
        #expect(try await Bridge.timeout(context: fork.requireContext()) == 9)

        // An explicit 0 under a running keep-alive, imposed over again by a new start: the fork gets nothing.
        try await connection.setTimeout(0)
        try connection.startKeepAlive(makeConfiguration(timeout: 1))
        #expect(connection.commandTimeoutSeconds == 1)
        let secondFork = try await connection.fork()
        defer { try? await secondFork.disconnect() }
        #expect(secondFork.commandTimeoutSeconds == 0)
        #expect(try await Bridge.timeout(context: secondFork.requireContext()) == 0)
    }

    @Test("a timeout set while the keep-alive runs is the user's and stays")
    func userTimeoutIsNotRestored() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }

        try connection.startKeepAlive(makeConfiguration(timeout: 1))
        try await connection.setTimeout(7)
        connection.stopKeepAlive()
        #expect(connection.commandTimeoutSeconds == 7)
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 7)
    }

    @Test("a connection that has a command timeout keeps it")
    func existingTimeoutIsLeftAlone() async throws {
        let connection = try await connect(timeout: 45)
        defer { try? await connection.disconnect() }

        try connection.startKeepAlive(makeConfiguration(timeout: 1))
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 45)
        connection.stopKeepAlive()
        #expect(connection.commandTimeoutSeconds == 45)
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 45)
    }

    @Test("a keep-alive the callback stops removes the timeout it imposed")
    func callbackStopRestoresTheTimeout() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }
        let returned = Flag()
        let weakConnection = WeakConnection(connection)

        try connection.startKeepAlive(SMB.KeepAliveConfiguration(
            interval: 0.1,
            timeout: 2,
            slowRoundTrip: Self.reportEveryEcho
        ) { _ in
            weakConnection.connection?.stopKeepAlive()
            returned.set()
        })
        #expect(connection.commandTimeoutSeconds == 2)
        try await waitUntil { returned.isSet }
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 0)
    }

    @Test("disconnecting keeps the imposed command timeout and enqueues no change for the closed context")
    func disconnectKeepsTheImposedTimeout() async throws {
        let connection = try await connect()
        try connection.startKeepAlive(makeConfiguration(timeout: 2))
        let context = try connection.requireContext()
        #expect(try await Bridge.timeout(context: context) == 2)

        try await connection.disconnect()
        #expect(!connection.isKeepAliveRunning)
        // Not restored: restoring would have set 0 and enqueued smb2_set_timeout(0) ahead of the shutdown.
        #expect(connection.protectedCommandTimeout.current == SMBCommandTimeout(seconds: 2, imposedByKeepAlive: true))
        #expect(!context.isAlive)
    }

    @Test("disconnecting gracefully keeps the imposed command timeout")
    func gracefulDisconnectKeepsTheImposedTimeout() async throws {
        let connection = try await connect()
        try connection.startKeepAlive(makeConfiguration(timeout: 2))
        try await connection.disconnectGracefully()
        #expect(!connection.isKeepAliveRunning)
        #expect(connection.protectedCommandTimeout.current == SMBCommandTimeout(seconds: 2, imposedByKeepAlive: true))
    }

    @Test("a problem that stops the keep-alive keeps its timeout until stopKeepAlive removes it")
    func problemKeepsTheImposedTimeout() async throws {
        let connection = try await connect()
        defer { try? await connection.disconnect() }
        let problems = ProblemLog()
        let runningDuringCallback = Locked<Bool?>(nil)
        let weakConnection = WeakConnection(connection)

        try connection.startKeepAlive(SMB.KeepAliveConfiguration(interval: 0.1, timeout: 2) { problem in
            runningDuringCallback.value = weakConnection.connection?.isKeepAliveRunning
            problems.record(problem)
        })
        // Break the transport under the connection, so the next echo fails or gets no answer.
        try await Bridge.closeContext(context: connection.requireContext())
        try await waitUntil { problems.otherCount == 1 && !connection.isKeepAliveRunning }
        #expect(problems.slowCount == 0)
        #expect(runningDuringCallback.value == true)
        #expect(connection.commandTimeoutSeconds == 2)
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 2)

        // An explicit stop removes it, although the keep-alive already stopped.
        connection.stopKeepAlive()
        #expect(connection.commandTimeoutSeconds == 0)
        #expect(try await Bridge.timeout(context: connection.requireContext()) == 0)
    }

    /// Connects and starts a keep-alive, and returns only a weak reference, so the connection is released on return.
    private func startedConnectionBox() async throws -> WeakConnection {
        let connection = try await connect()
        try connection.startKeepAlive(makeConfiguration())
        return WeakConnection(connection)
    }

    private func waitUntil(_ condition: @escaping @Sendable () -> Bool) async throws {
        try await withTimeout(seconds: 120) {
            while !condition() {
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }
    }
}

private final class WeakConnection: Sendable {
    weak let connection: SMB.Connection?

    init(_ connection: SMB.Connection) {
        self.connection = connection
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

private final class ProblemLog: @unchecked Sendable {
    private let problems = NSLock()
    private var values: [SMB.KeepAliveProblem] = []

    var count: Int {
        problems.lock()
        defer { problems.unlock() }
        return values.count
    }

    var slowCount: Int {
        problems.lock()
        defer { problems.unlock() }
        return values.count {
            if case .slow = $0 {
                true
            }
            else {
                false
            }
        }
    }

    var otherCount: Int {
        problems.lock()
        defer { problems.unlock() }
        return values.count {
            if case .slow = $0 {
                false
            }
            else {
                true
            }
        }
    }

    func record(_ problem: SMB.KeepAliveProblem) {
        problems.lock()
        defer { problems.unlock() }
        values.append(problem)
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
}

/// What a callback could still do after it stopped, replaced or disconnected the keep-alive.
private final class CallbackWork: Sendable {
    private let cancelled = Locked<Bool?>(nil)
    private let slept = Locked(false)
    private let listed = Locked(false)

    func record(on connection: SMB.Connection?) async {
        do {
            try await Task.sleep(nanoseconds: 20_000_000)
            slept.value = true
        }
        catch {
        }
        if let connection {
            listed.value = await (try? connection.listDirectory(at: "")) != nil
        }
        cancelled.value = Task.isCancelled
    }

    func expectNotCancelled(listed expectedListed: Bool) {
        #expect(cancelled.value == false)
        #expect(slept.value)
        #expect(listed.value == expectedListed)
    }
}
