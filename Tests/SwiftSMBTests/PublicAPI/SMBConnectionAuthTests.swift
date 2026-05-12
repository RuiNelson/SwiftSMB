//
// Part of SwiftSMB
// SMBConnectionAuthTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionAuthTests {
    @Test("connect with wrong password throws logon failure")
    func connectWithWrongPasswordThrowsLogonFailure() throws {
        let server = SMB.Server(host: testServerHost)
        let credentials = SMB.Credentials(
            user: TestCredentials.user,
            password: "wrong_password",
        )

        do {
            _ = try SMB.connect(
                server: server,
                credentials: credentials,
                share: TestShare.private,
            )
            Issue.record("Expected connection to fail with wrong password")
        }
        catch let error as SMB.Error {
            #expect(error.operation == "smb2_connect_share")
            if case let .ntStatus(status, _, _, _) = error {
                #expect(status == .logonFailure)
            }
            else {
                Issue.record("Expected .logonFailure, got \(error)")
            }
        }
    }

    @Test("connect without credentials to private share throws logon failure")
    func connectWithoutCredentialsToPrivateShareThrowsLogonFailure() throws {
        let server = SMB.Server(host: testServerHost)

        do {
            _ = try SMB.connect(
                server: server,
                share: TestShare.private,
            )
            Issue.record("Expected connection to fail without credentials")
        }
        catch let error as SMB.Error {
            #expect(error.operation == "smb2_connect_share")
            if case let .ntStatus(status, _, _, _) = error {
                #expect([SMB.SMBStatus.logonFailure, .accessDenied].contains(status))
            }
            else {
                Issue.record("Expected .logonFailure or .accessDenied, got \(error)")
            }
        }
    }
}
