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
}
