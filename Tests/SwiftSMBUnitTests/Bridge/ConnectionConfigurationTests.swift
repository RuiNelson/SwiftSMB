//
// Part of SwiftSMB
// ConnectionConfigurationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import SMB2
import Testing

// MARK: - Context configuration (no server required)

struct ContextConfigurationTests {
    @Test("set and get user") func setAndGetUser() throws {
        try withFreshContext { ctx in
            Bridge.setUser("alice", on: ctx)
            #expect(Bridge.getUser(on: ctx) == "alice")
        }
    }

    @Test("set and get domain") func setAndGetDomain() throws {
        try withFreshContext { ctx in
            Bridge.setDomain("CORP", on: ctx)
            #expect(Bridge.getDomain(on: ctx) == "CORP")
        }
    }

    @Test("set and get workstation") func setAndGetWorkstation() throws {
        try withFreshContext { ctx in
            Bridge.setWorkstation("MYPC", on: ctx)
            #expect(Bridge.getWorkstation(on: ctx) == "MYPC")
        }
    }

    @Test("server GUID converts SMB wire byte order to UUID")
    func serverGUIDConvertsSMBWireByteOrderToUUID() throws {
        try withFreshContext { ctx in
            let wireBytes: [UInt8] = [
                0x33,
                0x22,
                0x11,
                0x00,
                0x55,
                0x44,
                0x77,
                0x66,
                0x88,
                0x99,
                0xAA,
                0xBB,
                0xCC,
                0xDD,
                0xEE,
                0xFF,
            ]
            withUnsafeMutableBytes(of: &ctx.raw.pointee.server_guid) { buffer in
                buffer.copyBytes(from: wireBytes)
            }

            #expect(Bridge.getServerGUID(on: ctx).uuidString == "00112233-4455-6677-8899-AABBCCDDEEFF")
        }
    }

    @Test("typed encryption policy configures libsmb2 tri-state")
    func typedEncryptionPolicyConfiguresLibSMB2TriState() throws {
        try withFreshContext { ctx in
            try SMB.configure(ctx, with: SMB.Configuration(encryption: .automatic))
            #expect(ctx.raw.pointee.seal_requested == 0)

            try SMB.configure(ctx, with: SMB.Configuration(encryption: .disabled))
            #expect(ctx.raw.pointee.seal_requested == -1)

            try SMB.configure(ctx, with: SMB.Configuration(encryption: .required))
            #expect(ctx.raw.pointee.seal_requested == 1)
        }
    }
}

// MARK: - URL parsing (context required, no server connection)

struct URLParsingTests {
    @Test("parses basic URL") func parsesBasicURL() throws {
        try withFreshContext { ctx in
            let url = try Bridge.parseURL("smb://myserver/myshare", context: ctx)
            #expect(url.server == "myserver")
            #expect(url.share == "myshare")
            #expect(url.user == nil)
            #expect(url.domain == nil)
            #expect(url.path == nil)
        }
    }

    @Test("parses URL with user") func parsesURLWithUser() throws {
        try withFreshContext { ctx in
            let url = try Bridge.parseURL("smb://alice@myserver/myshare", context: ctx)
            #expect(url.user == "alice")
            #expect(url.server == "myserver")
            #expect(url.share == "myshare")
        }
    }

    @Test("parses URL with domain") func parsesURLWithDomain() throws {
        try withFreshContext { ctx in
            let url = try Bridge.parseURL("smb://CORP;alice@myserver/myshare", context: ctx)
            #expect(url.domain == "CORP")
            #expect(url.user == "alice")
            #expect(url.server == "myserver")
        }
    }

    @Test("parses URL with port") func parsesURLWithPort() throws {
        try withFreshContext { ctx in
            let url = try Bridge.parseURL("smb://myserver:4445/myshare", context: ctx)
            // libsmb2 embeds the port in the server string
            #expect(url.server.hasPrefix("myserver"))
            #expect(url.share == "myshare")
        }
    }

    @Test("parses URL with path") func parsesURLWithPath() throws {
        try withFreshContext { ctx in
            let url = try Bridge.parseURL("smb://myserver/myshare/some/path", context: ctx)
            #expect(url.server == "myserver")
            #expect(url.share == "myshare")
            #expect(url.path == "some/path")
        }
    }

    @Test("invalid URL throws") func invalidURLThrows() throws {
        try withFreshContext { ctx in
            #expect(throws: SMB.Error.self) {
                try Bridge.parseURL("not-an-smb-url", context: ctx)
            }
        }
    }
}

@discardableResult
private func withFreshContext<T>(_ body: (Bridge.Context) throws -> T) throws -> T {
    let ctx = try Bridge.createContext()
    defer { Bridge.destroyContext(ctx) }
    return try body(ctx)
}
