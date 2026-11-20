//
// Part of SwiftSMB
// SMBEncryptionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

/// Round trips over sealed and signed (AES-128-CMAC) sessions. The test server seals SMB 3.0 and 3.0.2 with AES-128-CCM
/// and SMB 3.1.1 with AES-128-GCM, its first choice. The server checks every tag and signature the client sends, and
/// the client checks the server's, so a wrong byte in either direction fails the transfer. The payload spans several
/// PDUs and ends in a partial AES block.
@Suite(.tags(.integration))
struct SMBEncryptionTests {
    private static let payloadSize = 3 * 1024 * 1024 + 37

    @Test("an encrypted session reads back what it wrote", arguments: [SMB.Dialect.smb3_00, .smb3_02, .smb3_11])
    func encryptedRoundTrip(dialect: SMB.Dialect) async throws {
        try await roundTrip(configuration: SMB.Configuration(dialect: dialect, encryption: .required))
    }

    @Test("a signed session reads back what it wrote", arguments: [SMB.Dialect.smb3_00, .smb3_11])
    func signedRoundTrip(dialect: SMB.Dialect) async throws {
        try await roundTrip(
            configuration: SMB.Configuration(dialect: dialect, encryption: .disabled, signing: .required)
        )
    }

    private func roundTrip(configuration: SMB.Configuration) async throws {
        let connection = try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            credentials: SMB.Credentials(user: TestCredentials.user, password: TestCredentials.password),
            share: TestShare.private,
            configuration: configuration
        )
        defer { try? await connection.disconnect() }

        let payload = Self.randomPayload(size: Self.payloadSize)
        let path = uniquePath("encryption")
        defer { try? await connection.removeFile(at: path) }

        let file = try await connection.openFile(at: path, accessMode: .readWrite, options: [.create, .truncate])
        try await file.write(payload)
        let readBack = try await file.read(upTo: Int64(payload.count), atOffset: 0)
        try await file.close()

        #expect(readBack.count == payload.count)
        #expect(readBack == payload)
    }

    private static func randomPayload(size: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        var data = Data(count: size)
        data.withUnsafeMutableBytes { buffer in
            for index in buffer.indices {
                buffer[index] = generator.next()
            }
        }
        return data
    }
}
