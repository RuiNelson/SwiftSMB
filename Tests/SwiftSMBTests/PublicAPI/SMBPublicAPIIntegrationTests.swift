//
// Part of SwiftSMB
// SMBPublicAPIIntegrationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite(.tags(.integration))
struct SMBPublicAPIIntegrationTests {
    @Test("connection timeout can be changed after connect")
    func connectionTimeoutCanBeChangedAfterConnect() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        try await connection.setTimeout(45)
        await #expect(try Bridge.getTimeout(on: connection.requireContext()) == 45)

        try await connection.setTimeout(-1)
        await #expect(try Bridge.getTimeout(on: connection.requireContext()) == 0)

        try await connection.setTimeout(Int.max)
        await #expect(try Bridge.getTimeout(on: connection.requireContext()) == Int32.max)
    }

    @Test("negotiated dialect kind matches raw negotiated dialect")
    func negotiatedDialectKindMatchesRawNegotiatedDialect() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        let rawDialect = try await connection.negotiatedDialect
        let dialectKind = try await connection.negotiatedDialectKind

        #expect(dialectKind == SMB.NegotiatedDialect(rawValue: rawDialect))
        if case .unknown = dialectKind {
            Issue.record("Expected a known negotiated dialect, got raw value \(rawDialect)")
        }
    }

    @Test("connection timeout throws after disconnect")
    func connectionTimeoutThrowsAfterDisconnect() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        try await connection.disconnect()

        await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try await connection.setTimeout(30)
        }
    }

    @Test("server GUID is exposed as a native UUID")
    func serverGUIDIsExposedAsNativeUUID() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        await #expect(try connection.serverGUID != UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
    }

    @Test("default configuration keeps command timeouts disabled after connect")
    func defaultConfigurationKeepsCommandTimeoutsDisabledAfterConnect() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        // The connect deadline applied while connecting must not leak into command timeouts.
        #expect(try await Bridge.getTimeout(on: connection.requireContext()) == 0)
    }

    @Test("fork opens an independent connection with the same credentials")
    func forkOpensAnIndependentConnectionWithTheSameCredentials() async throws {
        // The private share rejects connections without credentials, so the fork must reuse them.
        let connection = try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            credentials: SMB.Credentials(user: TestCredentials.user, password: TestCredentials.password),
            share: TestShare.private
        )
        defer { try? await connection.disconnect() }

        let fork = try await connection.fork()
        defer { try? await fork.disconnect() }

        #expect(fork.server == connection.server)
        #expect(fork.share == connection.share)
        let sessionID = try await connection.sessionID
        let forkSessionID = try await fork.sessionID
        #expect(forkSessionID != sessionID)

        let path = uniquePath("fork")
        let contents = Data("forked".utf8)
        try await connection.dumpToFile(contents, to: path)
        defer { try? await fork.removeFile(at: path) }
        #expect(try await fork.loadFile(at: path) == contents)

        try await connection.disconnect()
        #expect(fork.isConnected)
        try await fork.echo()
    }

    @Test(
        "fork prefers the block sizes the server accepted over the configured one",
        arguments: [nil, 4096, 1 << 30] as [Int?]
    )
    func forkPrefersTheBlockSizesTheServerAccepted(transferBlockSize: Int?) async throws {
        let connection = try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: SMB.Configuration(transferBlockSize: transferBlockSize)
        )
        defer { try? await connection.disconnect() }

        let fork = try await connection.fork()
        defer { try? await fork.disconnect() }

        let acceptedReadBlockSize = try await connection.acceptedReadBlockSize
        let acceptedWriteBlockSize = try await connection.acceptedWriteBlockSize
        let expectedBlockSize = max(acceptedReadBlockSize, acceptedWriteBlockSize)
        #expect(fork.configuration.transferBlockSize == expectedBlockSize)
        #expect(try await fork.acceptedReadBlockSize == acceptedReadBlockSize)
        #expect(try await fork.acceptedWriteBlockSize == acceptedWriteBlockSize)
    }

    @Test("fork inherits the command timeout in effect")
    func forkInheritsTheCommandTimeoutInEffect() async throws {
        let connection = try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: SMB.Configuration(timeout: 30)
        )
        defer { try? await connection.disconnect() }

        try await connection.setTimeout(45)
        let fork = try await connection.fork()
        defer { try? await fork.disconnect() }

        #expect(fork.configuration.timeout == 45)
        #expect(try await Bridge.getTimeout(on: fork.requireContext()) == 45)
    }

    @Test("fork keeps the rest of the configuration")
    func forkKeepsTheRestOfTheConfiguration() async throws {
        let configuration = SMB.Configuration(dialect: .anySMB3, encryption: .disabled)
        let connection = try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: configuration
        )
        defer { try? await connection.disconnect() }

        let fork = try await connection.fork()
        defer { try? await fork.disconnect() }

        var expectedConfiguration = configuration
        expectedConfiguration.transferBlockSize = try await connection.acceptedReadBlockSize
        #expect(fork.configuration == expectedConfiguration)
        #expect(try await fork.negotiatedDialectKind == connection.negotiatedDialectKind)
    }

    @Test("fork throws after disconnect")
    func forkThrowsAfterDisconnect() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        try await connection.disconnect()

        await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try await connection.fork()
        }
    }
}
