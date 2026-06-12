//
// Part of SwiftSMB
// SMBPublicAPIIntegrationTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite(.tags(.integration))
struct SMBPublicAPIIntegrationTests {
    @Test("connection timeout can be changed after connect")
    func connectionTimeoutCanBeChangedAfterConnect() throws {
        let connection = try SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? connection.disconnect() }

        try connection.setTimeout(45)
        #expect(try Bridge.getTimeout(on: connection.requireContext()) == 45)

        try connection.setTimeout(-1)
        #expect(try Bridge.getTimeout(on: connection.requireContext()) == 0)

        try connection.setTimeout(Int.max)
        #expect(try Bridge.getTimeout(on: connection.requireContext()) == Int32.max)
    }

    @Test("negotiated dialect kind matches raw negotiated dialect")
    func negotiatedDialectKindMatchesRawNegotiatedDialect() throws {
        let connection = try SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? connection.disconnect() }

        let rawDialect = try connection.negotiatedDialect
        let dialectKind = try connection.negotiatedDialectKind

        #expect(dialectKind == SMB.NegotiatedDialect(rawValue: rawDialect))
        if case .unknown = dialectKind {
            Issue.record("Expected a known negotiated dialect, got raw value \(rawDialect)")
        }
    }

    @Test("connection timeout throws after disconnect")
    func connectionTimeoutThrowsAfterDisconnect() throws {
        let connection = try SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        try connection.disconnect()

        #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try connection.setTimeout(30)
        }
    }
}
