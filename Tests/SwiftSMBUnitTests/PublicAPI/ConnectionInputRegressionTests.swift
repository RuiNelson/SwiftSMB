//
// Part of SwiftSMB
// ConnectionInputRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

struct ConnectionInputRegressionTests {
    @Test("SMB URL parsing rejects embedded NUL instead of silently truncating")
    func rejectsNULInURL() {
        #expect(throws: SMB.Error.invalidArgument(cause: .stringContainsNUL, onOperation: .smb2ParseURL)) {
            try SMB.parseURL("smb://server/share\0/hidden")
        }
    }

    @Test("connecting rejects an embedded NUL in the host before reaching the network")
    func rejectsNULInHost() async {
        await #expect(throws: SMB.Error.invalidArgument(cause: .stringContainsNUL, onOperation: .smb2ConnectShare)) {
            try await SMB.connect(server: SMB.Server(host: "server\0.example"), share: "share")
        }
    }

    @Test("credentials reject embedded NUL characters", arguments: [
        (SMB.Credentials(user: "user\0name"), SMB.Error.InvalidArgumentOperation.smb2SetUser),
        (SMB.Credentials(password: "password\0suffix"), .smb2SetPassword),
        (SMB.Credentials(domain: "domain\0suffix"), .smb2SetDomain),
        (SMB.Credentials(workstation: "workstation\0suffix"), .smb2SetWorkstation),
    ])
    func rejectsNULInCredentials(
        _ credentials: SMB.Credentials,
        operation: SMB.Error.InvalidArgumentOperation
    ) async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }

        await #expect(throws: SMB.Error.invalidArgument(cause: .stringContainsNUL, onOperation: operation)) {
            try await SMB.configureCredentials(credentials, server: SMB.Server(host: "server"), on: context)
        }
    }

    @Test("the server domain rejects embedded NUL characters")
    func rejectsNULInServerDomain() async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }

        await #expect(throws: SMB.Error.invalidArgument(cause: .stringContainsNUL, onOperation: .smb2SetDomain)) {
            try await SMB.configureCredentials(
                nil,
                server: SMB.Server(host: "server", domain: "domain\0suffix"),
                on: context
            )
        }
    }

    @Test("watcher registration rejects a closed connection")
    func rejectsWatcherRegistrationAfterDisconnect() async throws {
        let context = try Bridge.createContext()
        let connection = SMB.Connection(
            server: SMB.Server(host: "server"),
            share: "share",
            configuration: SMB.Configuration(),
            context: context,
            maxReadSize: 1024,
            maxWriteSize: 1024
        )
        // Destroying before disconnect lets this unit test mark the public connection closed without a network call.
        await Bridge.destroyContext(context)
        try? await connection.disconnect()

        let (_, continuation) = AsyncThrowingStream<[SMB.NotifyChange], any Swift.Error>.makeStream()
        let state = SMBNotifyWatcherState(
            context: context,
            directory: Bridge.FileHandle(raw: OpaquePointer(bitPattern: 1)!),
            options: [],
            filter: .all,
            continuation: continuation,
            onFinish: { _ in }
        )

        #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try connection.registerAndStartNotifyWatcher(state)
        }
        #expect(connection.protectedNotifyWatchers.current.isEmpty)
    }

    @Test("a fatal bridge service error marks the public connection disconnected")
    func fatalServiceFailureClosesPublicConnection() async throws {
        let context = try Bridge.createContext()
        let connection = SMB.Connection(
            server: SMB.Server(host: "server"),
            share: "share",
            configuration: SMB.Configuration(),
            context: context,
            maxReadSize: 1024,
            maxWriteSize: 1024
        )
        defer { await Bridge.destroyContext(context) }

        await #expect(throws: SMB.Error.self) {
            try await Bridge.getFileAttributes(context: context, path: "missing")
        }
        #expect(!connection.isConnected)
        #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try connection.requireContext()
        }
    }

    @Test("a fatal notification service error destroys its shared context")
    func fatalNotificationServiceFailureDestroysContext() async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }

        await #expect(throws: SMB.Error.self) {
            try await Bridge.serviceNotifyEvents(context: context)
        }
        #expect(!context.isAlive)
        await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
            try await Bridge.getUser(on: context)
        }
    }
}
