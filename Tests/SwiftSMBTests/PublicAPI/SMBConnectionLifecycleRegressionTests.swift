//
// Part of SwiftSMB
// SMBConnectionLifecycleRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionLifecycleRegressionTests {
    @Test("itemExists returns false when an ancestor directory is missing")
    func missingAncestorReturnsFalse() async throws {
        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }

        let missingPath = uniquePath("missing-parent") + "/missing-child.txt"
        #expect(try await connection.itemExists(at: missingPath) == .false)
    }

    @Test("disconnect marks open file and directory handles closed")
    func disconnectClosesPublicHandles() async throws {
        let setupConnection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await setupConnection.disconnect() }
        let root = uniquePath("handle-disconnect")
        try await setupConnection.makeDirectory(at: root)
        defer { try? await setupConnection.removeItem(at: root) }

        let connection = try await SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? await connection.disconnect() }
        let file = try await connection.openFile(
            at: root + "/file.txt",
            accessMode: .readWrite,
            options: [.create, .exclusive]
        )
        let directory = try await connection.openDirectory(at: root)
        #expect(file.isOpen)
        #expect(directory.isOpen)

        try await connection.disconnect()
        #expect(!file.isOpen)
        #expect(!directory.isOpen)
    }
}
