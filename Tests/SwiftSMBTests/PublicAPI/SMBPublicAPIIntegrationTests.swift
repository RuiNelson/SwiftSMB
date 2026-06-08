//
// Part of SwiftSMB
// SMBPublicAPIIntegrationTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBPublicAPIIntegrationTests {
    @Test("connection timeout can be changed after connect")
    func connectionTimeoutCanBeChangedAfterConnect() throws {
        let connection = try SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? connection.disconnect() }

        try connection.setTimeout(45)
        #expect(connection.debugDescription.contains("timeout: 45"))

        try connection.setTimeout(-1)
        #expect(connection.debugDescription.contains("timeout: 0"))

        try connection.setTimeout(Int.max)
        #expect(connection.debugDescription.contains("timeout: \(Int32.max)"))
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
