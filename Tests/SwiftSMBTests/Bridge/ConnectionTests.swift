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
    @Test("connect to public share as guest") func connectToPublicShareAsGuest() throws {
        try withFreshContext { ctx in
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("connect to private share with credentials") func connectToPrivateShareWithCredentials() throws {
        try withFreshContext { ctx in
            Bridge.setUser(TestCredentials.user, on: ctx)
            Bridge.setPassword(TestCredentials.password, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("connect to readonly share") func connectToReadonlyShare() throws {
        try withFreshContext { ctx in
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.readonly)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("echo succeeds on public share") func echoSucceedsOnPublicShare() throws {
        try withPublicShare { ctx in
            try Bridge.echo(context: ctx)
        }
    }

    @Test("session ID is non zero after connect") func sessionIDIsNonZeroAfterConnect() throws {
        try withPublicShare { ctx in
            let sessionID = try Bridge.getSessionID(context: ctx)
            #expect(sessionID != 0)
        }
    }

    @Test("dialect is set after connect") func dialectIsSetAfterConnect() throws {
        try withPublicShare { ctx in
            let dialect = Bridge.getDialect(on: ctx)
            #expect(dialect != 0)
        }
    }

    @Test("max read size is positive after connect") func maxReadSizeIsPositiveAfterConnect() throws {
        try withPublicShare { ctx in
            let mrs = Bridge.getMaxReadSize(context: ctx)
            #expect(mrs > 0)
        }
    }

    @Test("max write size is positive after connect") func maxWriteSizeIsPositiveAfterConnect() throws {
        try withPublicShare { ctx in
            let mws = Bridge.getMaxWriteSize(context: ctx)
            #expect(mws > 0)
        }
    }

    @Test("wrong password throws") func wrongPasswordThrows() throws {
        try withFreshContext { ctx in
            Bridge.setUser(TestCredentials.user, on: ctx)
            Bridge.setPassword("wrong_password", on: ctx)
            #expect(throws: SMB.Error.self) {
                try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            }
        }
    }

    @Test("non existent share throws") func nonExistentShareThrows() throws {
        try withFreshContext { ctx in
            #expect(throws: SMB.Error.self) {
                try Bridge.connectShare(context: ctx, server: testServerHost, share: "doesnotexist")
            }
        }
    }

    @Test("ntlmssp authentication works") func ntlmsspAuthenticationWorks() throws {
        try withFreshContext { ctx in
            Bridge.setAuthentication(.ntlmssp, on: ctx)
            Bridge.setUser(TestCredentials.user, on: ctx)
            Bridge.setPassword(TestCredentials.password, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set timeout before connect") func setTimeoutBeforeConnect() throws {
        try withFreshContext { ctx in
            Bridge.setTimeout(30, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set version SMB2 before connect") func setVersionSmb2BeforeConnect() throws {
        try withFreshContext { ctx in
            Bridge.setVersion(SMB2_VERSION_ANY2, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            let dialect = Bridge.getDialect(on: ctx)
            #expect(dialect != 0)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set version SMB3 before connect") func setVersionSmb3BeforeConnect() throws {
        try withFreshContext { ctx in
            Bridge.setVersion(SMB2_VERSION_0300, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            let dialect = Bridge.getDialect(on: ctx)
            #expect(dialect != 0)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set security mode before connect") func setSecurityModeBeforeConnect() throws {
        try withFreshContext { ctx in
            Bridge.setSecurityMode(.signingEnabled, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("close context does not destroy") func closeContextDoesNotDestroy() throws {
        try withFreshContext { ctx in
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            Bridge.closeContext(ctx)
            // Context object still valid after closeContext; destroyContext cleans up
        }
    }

    @Test("connect share with user parameter") func connectShareWithUserParameter() throws {
        try withFreshContext { ctx in
            Bridge.setPassword(TestCredentials.password, on: ctx)
            try Bridge.connectShare(
                context: ctx,
                server: testServerHost,
                share: TestShare.private,
                user: TestCredentials.user
            )
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set seal false before connect") func setSealFalseBeforeConnect() throws {
        try withFreshContext { ctx in
            Bridge.setSeal(false, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set seal true requires encryption") func setSealTrueRequiresEncryption() throws {
        try withFreshContext { ctx in
            Bridge.setSeal(true, on: ctx)
            #expect(throws: SMB.Error.self) {
                try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            }
        }
    }

    @Test("set sign false before connect") func setSignFalseBeforeConnect() throws {
        try withFreshContext { ctx in
            Bridge.setSign(false, on: ctx)
            try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try Bridge.disconnectShare(context: ctx)
        }
    }

    @Test("set sign true requires signing") func setSignTrueRequiresSigning() throws {
        try withFreshContext { ctx in
            Bridge.setSign(true, on: ctx)
            #expect(throws: SMB.Error.self) {
                try Bridge.connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            }
        }
    }
}
