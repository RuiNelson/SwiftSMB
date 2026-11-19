//
// Part of SwiftSMB
// ConnectionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import SMB2
import Testing

// MARK: - Live connection tests

@Suite(.tags(.integration))
struct ConnectionTests {
    @Test("connect to public share as guest") func connectToPublicShareAsGuest() async throws {
        try await withFreshContext { ctx in
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("connect to private share with credentials") func connectToPrivateShareWithCredentials() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setUser(context: ctx, user: TestCredentials.user)
            try await Bridge.setPassword(context: ctx, password: TestCredentials.password)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("connect to readonly share") func connectToReadonlyShare() async throws {
        try await withFreshContext { ctx in
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.readonly)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("echo succeeds on public share") func echoSucceedsOnPublicShare() async throws {
        try await withPublicShare { ctx in
            try await Bridge.echo(context: ctx)
        }
    }

    @Test("session ID is non zero after connect") func sessionIDIsNonZeroAfterConnect() async throws {
        try await withPublicShare { ctx in
            let sessionID = try await Bridge.sessionID(context: ctx)
            #expect(sessionID != 0)
        }
    }

    @Test("dialect is set after connect") func dialectIsSetAfterConnect() async throws {
        try await withPublicShare { ctx in
            let dialect = try await Bridge.dialect(context: ctx)
            #expect(dialect.rawValue != 0)
        }
    }

    @Test("max read size is positive after connect") func maxReadSizeIsPositiveAfterConnect() async throws {
        try await withPublicShare { ctx in
            let mrs = try await Bridge.maxReadSize(context: ctx)
            #expect(mrs > 0)
        }
    }

    @Test("max write size is positive after connect") func maxWriteSizeIsPositiveAfterConnect() async throws {
        try await withPublicShare { ctx in
            let mws = try await Bridge.maxWriteSize(context: ctx)
            #expect(mws > 0)
        }
    }

    @Test("wrong password throws") func wrongPasswordThrows() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setUser(context: ctx, user: TestCredentials.user)
            try await Bridge.setPassword(context: ctx, password: "wrong_password")
            await #expect(throws: SMB.Error.self) {
                try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            }
        }
    }

    @Test("non existent share throws") func nonExistentShareThrows() async throws {
        try await withFreshContext { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.connectShare(context: ctx, server: testServerHost, share: "doesnotexist")
            }
        }
    }

    @Test("ntlmssp authentication works") func ntlmsspAuthenticationWorks() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setAuthentication(context: ctx, method: .ntlmssp)
            try await Bridge.setUser(context: ctx, user: TestCredentials.user)
            try await Bridge.setPassword(context: ctx, password: TestCredentials.password)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set timeout before connect") func setTimeoutBeforeConnect() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setTimeout(context: ctx, seconds: 30)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set version SMB2 before connect") func setVersionSmb2BeforeConnect() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setDialect(context: ctx, dialect: .anySMB2)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            let dialect = try await Bridge.dialect(context: ctx)
            #expect(dialect.rawValue != 0)
            #expect(!dialect.isSMB3)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set version SMB3 before connect") func setVersionSmb3BeforeConnect() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setDialect(context: ctx, dialect: .smb3_00)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            let dialect = try await Bridge.dialect(context: ctx)
            #expect(dialect == .smb3_00)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set security mode before connect") func setSecurityModeBeforeConnect() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSecurityMode(context: ctx, mode: .signingEnabled)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("close context does not destroy") func closeContextDoesNotDestroy() async throws {
        try await withFreshContext { ctx in
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            await Bridge.closeContext(context: ctx)
            // Context object still valid after closeContext; destroyContext cleans up
        }
    }

    @Test("connect share with user parameter") func connectShareWithUserParameter() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setPassword(context: ctx, password: TestCredentials.password)
            try await Bridge.connectShare(
                context: ctx,
                server: testServerHost,
                share: TestShare.private,
                user: TestCredentials.user
            )
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set seal false before connect") func setSealFalseBeforeConnect() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSeal(context: ctx, enabled: false)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set seal true requires encryption") func setSealTrueRequiresEncryption() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSeal(context: ctx, enabled: true)
            await #expect(throws: SMB.Error.self) {
                try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            }
        }
    }

    @Test("set sign false before connect") func setSignFalseBeforeConnect() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSign(context: ctx, required: false)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try await Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set sign true requires signing") func setSignTrueRequiresSigning() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSign(context: ctx, required: true)
            await #expect(throws: SMB.Error.self) {
                try await Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            }
        }
    }
}
