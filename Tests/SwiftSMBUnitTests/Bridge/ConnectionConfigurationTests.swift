//
// Part of SwiftSMB
// ConnectionConfigurationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import SMB2
import Testing

// MARK: - Context configuration (no server required)

struct ContextConfigurationTests {
    @Test("set and get user") func setAndGetUser() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setUser("alice", on: ctx)
            #expect(try await Bridge.getUser(on: ctx) == "alice")
        }
    }

    @Test("set and get domain") func setAndGetDomain() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setDomain("CORP", on: ctx)
            #expect(try await Bridge.getDomain(on: ctx) == "CORP")
        }
    }

    @Test("set and get workstation") func setAndGetWorkstation() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setWorkstation("MYPC", on: ctx)
            #expect(try await Bridge.getWorkstation(on: ctx) == "MYPC")
        }
    }

    @Test("server GUID converts SMB wire byte order to UUID")
    func serverGUIDConvertsSMBWireByteOrderToUUID() async throws {
        try await withFreshContext { ctx in
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

            let guid = try await Bridge.getServerGUID(on: ctx)
            #expect(guid.uuidString == "00112233-4455-6677-8899-AABBCCDDEEFF")
        }
    }

    @Test("typed encryption policy configures libsmb2 tri-state")
    func typedEncryptionPolicyConfiguresLibSMB2TriState() async throws {
        try await withFreshContext { ctx in
            try await SMB.configure(ctx, with: SMB.Configuration(encryption: .automatic))
            #expect(ctx.raw.pointee.seal_requested == 0)

            try await SMB.configure(ctx, with: SMB.Configuration(encryption: .disabled))
            #expect(ctx.raw.pointee.seal_requested == -1)

            try await SMB.configure(ctx, with: SMB.Configuration(encryption: .required))
            #expect(ctx.raw.pointee.seal_requested == 1)
        }
    }

    @Test("operations on a destroyed context throw instead of touching it")
    func operationsOnDestroyedContextThrow() async throws {
        let ctx = try Bridge.createContext()
        await Bridge.destroyContext(ctx)

        await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try await Bridge.getUser(on: ctx)
        }
        // Destroying twice is a no-op.
        await Bridge.destroyContext(ctx)
    }

    @Test("commands on a context without a connection fail instead of hanging")
    func commandsOnContextWithoutConnectionFail() async throws {
        try await withFreshContext { ctx in
            // `getFileAttributes` services the context itself; without a connection poll() ignores the descriptor.
            // Destroying the context afterwards runs the queued callbacks, which must not touch freed state.
            await #expect(throws: SMB.Error.posix(
                code: POSIXErrorCode.ENOTCONN.rawValue,
                operation: "smb2_service",
                message: "No connection exists"
            )) {
                try await Bridge.getFileAttributes(context: ctx, path: "missing")
            }
        }
    }

    @Test("separate contexts can be created and destroyed concurrently")
    func separateContextsCanBeCreatedAndDestroyedConcurrently() async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0 ..< 32 {
                group.addTask {
                    try await withFreshContext { ctx in
                        try await Bridge.setUser("user\(index)", on: ctx)
                        #expect(try await Bridge.getUser(on: ctx) == "user\(index)")
                    }
                }
            }
            try await group.waitForAll()
        }
    }
}

// MARK: - URL parsing (no server connection)

struct URLParsingTests {
    @Test("parses basic URL") func parsesBasicURL() throws {
        let url = try Bridge.parseURL("smb://myserver/myshare")
        #expect(url.server == "myserver")
        #expect(url.share == "myshare")
        #expect(url.user == nil)
        #expect(url.domain == nil)
        #expect(url.path == nil)
    }

    @Test("parses URL with user") func parsesURLWithUser() throws {
        let url = try Bridge.parseURL("smb://alice@myserver/myshare")
        #expect(url.user == "alice")
        #expect(url.server == "myserver")
        #expect(url.share == "myshare")
    }

    @Test("parses URL with domain") func parsesURLWithDomain() throws {
        let url = try Bridge.parseURL("smb://CORP;alice@myserver/myshare")
        #expect(url.domain == "CORP")
        #expect(url.user == "alice")
        #expect(url.server == "myserver")
    }

    @Test("parses URL with port") func parsesURLWithPort() throws {
        let url = try Bridge.parseURL("smb://myserver:4445/myshare")
        // libsmb2 embeds the port in the server string
        #expect(url.server.hasPrefix("myserver"))
        #expect(url.share == "myshare")
    }

    @Test("parses URL with path") func parsesURLWithPath() throws {
        let url = try Bridge.parseURL("smb://myserver/myshare/some/path")
        #expect(url.server == "myserver")
        #expect(url.share == "myshare")
        #expect(url.path == "some/path")
    }

    @Test("invalid URL throws") func invalidURLThrows() {
        #expect(throws: SMB.Error.self) {
            try Bridge.parseURL("not-an-smb-url")
        }
    }
}

@discardableResult
private func withFreshContext<T>(_ body: (Bridge.Context) async throws -> T) async throws -> T {
    let ctx = try Bridge.createContext()
    defer { await Bridge.destroyContext(ctx) }
    return try await body(ctx)
}
