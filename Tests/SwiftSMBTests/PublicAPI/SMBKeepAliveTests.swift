//
// Part of SwiftSMB
// SMBKeepAliveTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBKeepAliveTests {
    private func makeConfiguration(
        interval: TimeInterval = 0.1,
        problems: ProblemLog = ProblemLog()
    ) -> SMB.KeepAliveConfiguration {
        SMB.KeepAliveConfiguration(interval: interval, timeout: 2, slowRoundTrip: 5) { problem in
            problems.record(problem)
        }
    }

    @Test("an idle connection stays healthy and usable under the keep-alive")
    func idleConnectionStaysUsable() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }
        let problems = ProblemLog()

        try connection.startKeepAlive(makeConfiguration(problems: problems))
        #expect(connection.isKeepAliveRunning)

        try await Task.sleep(nanoseconds: 800_000_000)
        #expect(connection.isKeepAliveRunning)
        #expect(problems.count == 0)
        _ = try await connection.listDirectory(at: "")
    }

    @Test("stopKeepAlive stops it and may be called again")
    func stopKeepAlive() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        #expect(!connection.isKeepAliveRunning)
        connection.stopKeepAlive()
        try connection.startKeepAlive(makeConfiguration())
        #expect(connection.isKeepAliveRunning)
        connection.stopKeepAlive()
        #expect(!connection.isKeepAliveRunning)
        connection.stopKeepAlive()
    }

    @Test("starting again replaces the running keep-alive")
    func startReplaces() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        try connection.startKeepAlive(makeConfiguration())
        try connection.startKeepAlive(makeConfiguration(interval: 0.2))
        #expect(connection.isKeepAliveRunning)
        connection.stopKeepAlive()
        #expect(!connection.isKeepAliveRunning)
    }

    @Test("disconnecting stops the keep-alive and a closed connection refuses to start one")
    func disconnectStops() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
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

    @Test("disconnecting gracefully stops the keep-alive without reporting a problem")
    func gracefulDisconnectStops() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        let problems = ProblemLog()
        try connection.startKeepAlive(makeConfiguration(problems: problems))
        try await Task.sleep(nanoseconds: 300_000_000)

        try await connection.disconnectGracefully()
        #expect(!connection.isKeepAliveRunning)
        #expect(problems.count == 0)
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

    /// Connects and starts a keep-alive, and returns only a weak reference, so the connection is released on return.
    private func startedConnectionBox() async throws -> WeakConnection {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        try connection.startKeepAlive(makeConfiguration())
        return WeakConnection(connection)
    }
}

private final class WeakConnection: Sendable {
    weak let connection: SMB.Connection?

    init(_ connection: SMB.Connection) {
        self.connection = connection
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

    func record(_ problem: SMB.KeepAliveProblem) {
        problems.lock()
        defer { problems.unlock() }
        values.append(problem)
    }
}
