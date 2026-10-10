//
// Part of SwiftSMB
// SMBListSharesTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite(.tags(.integration))
struct SMBListSharesTests {
    private let server = SMB.Server(host: testServerHost)
    private let credentials = SMB.Credentials(user: TestCredentials.user, password: TestCredentials.password)

    @Test("standard detail is the default and leaves the full information unset")
    func standardDetailIsTheDefaultAndLeavesFullInformationUnset() async throws {
        let shares = try await SMB.listShares(server: server, credentials: credentials)
        let explicit = try await SMB.listShares(server: server, credentials: credentials, detail: .standard)

        #expect(shares == explicit)
        #expect(shares.contains { $0.name == TestShare.public })
        for share in shares {
            #expect(share.path == nil)
            #expect(share.permissions == nil)
            #expect(share.maximumUsers == nil)
            #expect(share.currentUsers == nil)
        }
    }

    @Test("full detail reports path, permissions and user counts")
    func fullDetailReportsPathPermissionsAndUserCounts() async throws {
        let shares = try await SMB.listShares(server: server, credentials: credentials, detail: .full)

        #expect(shares.contains { $0.name == TestShare.public })
        for share in shares {
            #expect(share.kind == .diskTree)
            #expect(!(share.path ?? "").isEmpty, "Share \(share.name) should report its path")
            #expect(share.permissions != nil)
            #expect(share.currentUsers != nil)
            // Samba reports -1, which means no limit.
            #expect(share.maximumUsers == nil)
        }
    }

    @Test("full detail returns the same shares as standard detail")
    func fullDetailReturnsTheSameSharesAsStandardDetail() async throws {
        let standard = try await SMB.listShares(server: server, credentials: credentials, detail: .standard)
        let full = try await SMB.listShares(server: server, credentials: credentials, detail: .full)

        #expect(full.map(\.name) == standard.map(\.name))
        #expect(full.map(\.kind) == standard.map(\.kind))
        #expect(full.map(\.attributes) == standard.map(\.attributes))
    }

    @Test("full detail counts an open connection") func fullDetailCountsAnOpenConnection() async throws {
        let connection = try await SMB.connect(server: server, credentials: credentials, share: TestShare.private)
        defer { try? await connection.disconnect() }

        let shares = try await SMB.listShares(server: server, credentials: credentials, detail: .full)
        let privateShare = try #require(shares.first { $0.name == TestShare.private })

        // Other suites connect to this share too, so only a lower bound is stable.
        #expect(try #require(privateShare.currentUsers) >= 1)
    }
}
