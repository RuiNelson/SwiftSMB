//
// Part of SwiftSMB
// SMBConcurrencyTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConcurrencyTests {
    /// Connections run on their own queues, so many connects overlap. With `libsmb2`'s default timeout of 0, a connect
    /// whose TCP handshake crossed a wall-clock second boundary could fail with "Timeout expired and no connection
    /// exists"; `Bridge.defaultConnectTimeoutSeconds` prevents that.
    @Test("many concurrent connects with the default configuration succeed")
    func manyConcurrentConnectsWithDefaultConfigurationSucceed() async throws {
        for _ in 0 ..< 4 {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0 ..< 48 {
                    group.addTask {
                        let connection = try await SMB.connect(
                            server: SMB.Server(host: testServerHost),
                            share: TestShare.public
                        )
                        try await connection.echo()
                        try await connection.disconnect()
                    }
                }
                try await group.waitForAll()
            }
        }
    }

    /// `disconnect()` used to disconnect, close, and destroy the context in separate queue operations; an operation
    /// that
    /// slipped in after the close found no connection and serviced the context forever.
    @Test("disconnect while operations are in flight completes")
    func disconnectWhileOperationsAreInFlightCompletes() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        let path = uniquePath("in-flight") + ".txt"
        try await connection.dumpToFile(Data("in flight".utf8), to: path)

        try await withTimeout(seconds: 20) {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0 ..< 16 {
                    group.addTask {
                        for _ in 0 ..< 20 {
                            // Each call either succeeds or throws once the connection is closed; it must never hang.
                            _ = try? await connection.attributes(at: path)
                        }
                    }
                }
                group.addTask {
                    try await connection.disconnect()
                }
                try await group.waitForAll()
            }
        }

        let cleanup = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        try? await cleanup.removeFile(at: path)
        try? await cleanup.disconnect()
    }
}
