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
}
