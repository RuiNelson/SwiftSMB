//
// Part of SwiftSMB
// ConnectionTests.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

@testable import SwiftSMB
import SMB2
import Testing

// MARK: - Context configuration (no server required)

struct ContextConfigurationTests {
    @Test func `set and get user`() throws {
        try withFreshContext { ctx in
            setUser("alice", on: ctx)
            #expect(getUser(on: ctx) == "alice")
        }
    }

    @Test func `set and get domain`() throws {
        try withFreshContext { ctx in
            setDomain("CORP", on: ctx)
            #expect(getDomain(on: ctx) == "CORP")
        }
    }

    @Test func `set and get workstation`() throws {
        try withFreshContext { ctx in
            setWorkstation("MYPC", on: ctx)
            #expect(getWorkstation(on: ctx) == "MYPC")
        }
    }
}

// MARK: - URL parsing (context required, no server connection)

struct URLParsingTests {
    @Test func `parses basic URL`() throws {
        try withFreshContext { ctx in
            let url = try parseURL("smb://myserver/myshare", context: ctx)
            #expect(url.server == "myserver")
            #expect(url.share == "myshare")
            #expect(url.user == nil)
            #expect(url.domain == nil)
            #expect(url.path == nil)
        }
    }

    @Test func `parses URL with user`() throws {
        try withFreshContext { ctx in
            let url = try parseURL("smb://alice@myserver/myshare", context: ctx)
            #expect(url.user == "alice")
            #expect(url.server == "myserver")
            #expect(url.share == "myshare")
        }
    }

    @Test func `parses URL with domain`() throws {
        try withFreshContext { ctx in
            let url = try parseURL("smb://CORP;alice@myserver/myshare", context: ctx)
            #expect(url.domain == "CORP")
            #expect(url.user == "alice")
            #expect(url.server == "myserver")
        }
    }

    @Test func `parses URL with port`() throws {
        try withFreshContext { ctx in
            let url = try parseURL("smb://myserver:4445/myshare", context: ctx)
            // libsmb2 embeds the port in the server string
            #expect(url.server.hasPrefix("myserver"))
            #expect(url.share == "myshare")
        }
    }

    @Test func `parses URL with path`() throws {
        try withFreshContext { ctx in
            let url = try parseURL("smb://myserver/myshare/some/path", context: ctx)
            #expect(url.server == "myserver")
            #expect(url.share == "myshare")
            #expect(url.path == "some/path")
        }
    }

    @Test func `invalid URL throws`() throws {
        try withFreshContext { ctx in
            #expect(throws: SMB2Error.self) {
                try parseURL("not-an-smb-url", context: ctx)
            }
        }
    }
}

// MARK: - Live connection tests

@Suite(.tags(.integration))
struct ConnectionTests {
    @Test func `connect to public share as guest`() throws {
        try withFreshContext { ctx in
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `connect to private share with credentials`() throws {
        try withFreshContext { ctx in
            setUser(TestCredentials.user, on: ctx)
            setPassword(TestCredentials.password, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `connect to readonly share`() throws {
        try withFreshContext { ctx in
            try connectShare(context: ctx, server: testServerHost, share: TestShare.readonly)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `echo succeeds on public share`() throws {
        try withPublicShare { ctx in
            try echo(context: ctx)
        }
    }

    @Test func `session ID is non zero after connect`() throws {
        try withPublicShare { ctx in
            let sessionID = try getSessionID(context: ctx)
            #expect(sessionID != 0)
        }
    }

    @Test func `dialect is set after connect`() throws {
        try withPublicShare { ctx in
            let dialect = getDialect(on: ctx)
            #expect(dialect != 0)
        }
    }

    @Test func `max read size is positive after connect`() throws {
        try withPublicShare { ctx in
            #expect(getMaxReadSize(context: ctx) > 0)
        }
    }

    @Test func `max write size is positive after connect`() throws {
        try withPublicShare { ctx in
            #expect(getMaxWriteSize(context: ctx) > 0)
        }
    }

    @Test func `wrong password throws`() throws {
        try withFreshContext { ctx in
            setUser(TestCredentials.user, on: ctx)
            setPassword("wrong_password", on: ctx)
            #expect(throws: SMB2Error.self) {
                try connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            }
        }
    }

    @Test func `non existent share throws`() throws {
        try withFreshContext { ctx in
            #expect(throws: SMB2Error.self) {
                try connectShare(context: ctx, server: testServerHost, share: "doesnotexist")
            }
        }
    }

    @Test func `ntlmssp authentication works`() throws {
        try withFreshContext { ctx in
            setAuthentication(.ntlmssp, on: ctx)
            setUser(TestCredentials.user, on: ctx)
            setPassword(TestCredentials.password, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.private)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set timeout before connect`() throws {
        try withFreshContext { ctx in
            setTimeout(30, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set version SMB2 before connect`() throws {
        try withFreshContext { ctx in
            setVersion(SMB2_VERSION_ANY2, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            let dialect = getDialect(on: ctx)
            #expect(dialect != 0)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set version SMB3 before connect`() throws {
        try withFreshContext { ctx in
            setVersion(SMB2_VERSION_0300, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            let dialect = getDialect(on: ctx)
            #expect(dialect != 0)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set security mode before connect`() throws {
        try withFreshContext { ctx in
            setSecurityMode(.signingEnabled, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `close context does not destroy`() throws {
        try withFreshContext { ctx in
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            closeContext(ctx)
            // Context object still valid after closeContext; destroyContext cleans up
        }
    }

    @Test func `connect share with user parameter`() throws {
        try withFreshContext { ctx in
            setPassword(TestCredentials.password, on: ctx)
            try connectShare(
                context: ctx,
                server: testServerHost,
                share: TestShare.private,
                user: TestCredentials.user,
            )
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set seal false before connect`() throws {
        try withFreshContext { ctx in
            setSeal(false, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set seal true requires encryption`() throws {
        try withFreshContext { ctx in
            setSeal(true, on: ctx)
            #expect(throws: SMB2Error.self) {
                try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            }
        }
    }

    @Test func `set sign false before connect`() throws {
        try withFreshContext { ctx in
            setSign(false, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            try disconnectShare(context: ctx)
        }
    }

    @Test func `set sign true requires signing`() throws {
        try withFreshContext { ctx in
            setSign(true, on: ctx)
            #expect(throws: SMB2Error.self) {
                try connectShare(context: ctx, server: testServerHost, share: TestShare.public)
            }
        }
    }
}
