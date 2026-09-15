//
// Part of SwiftSMB
// SMBFileOpLockTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBPublicAPIFileOpLockTests {
    @Test("openFile default opLock opens file") func openFileDefaultOpLockOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-oplock-default") { path, content in
            let file = try await connection.openFile(at: path)
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with none opLock opens file") func openFileWithNoneOpLockOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-oplock-none") { path, content in
            let file = try await connection.openFile(at: path, opLock: .none)
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with levelII opLock opens file") func openFileWithLevelIIOpLockOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-oplock-levelII") { path, content in
            let file = try await connection.openFile(at: path, opLock: .levelII)
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with exclusive opLock opens file") func openFileWithExclusiveOpLockOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-oplock-exclusive") { path, content in
            let file = try await connection.openFile(at: path, opLock: .exclusive)
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with batch opLock opens file") func openFileWithBatchOpLockOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-oplock-batch") { path, content in
            let file = try await connection.openFile(at: path, opLock: .batch)
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with lease readCaching opens file") func openFileWithLeaseReadCachingOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-lease-read") { path, content in
            let file = try await connection.openFile(at: path, opLock: .lease(.readCaching))
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with lease handle caching opens file") func openFileWithLeaseHandleCachingOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-lease-handle") { path, content in
            let file = try await connection.openFile(
                at: path,
                opLock: .lease([.readCaching, .handleCaching])
            )
            defer { try? await file.close() }
            let data = try await file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with lease write caching opens file") func openFileWithLeaseWriteCachingOpensFile() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("pub-lease-full") + ".txt"
        defer { try? await connection.removeFile(at: path) }
        let content = Data("lease write caching test".utf8)
        try await connection.dumpToFile(content, to: path)

        let file = try await connection.openFile(
            at: path,
            opLock: .lease([.readCaching, .handleCaching, .writeCaching])
        )
        defer { try? await file.close() }
        let data = try await file.read()
        #expect(data == content)
    }

    @Test("openFile with opLock then write and read back") func openFileWithOpLockThenWriteAndReadBack() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("pub-oplock") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        let content = Data("oplock read-write test".utf8)

        let wh = try await connection.openFile(
            at: path,
            accessMode: .readWrite,
            options: [.create, .exclusive],
            opLock: .batch
        )
        _ = try await wh.write(content)
        try await wh.close()

        let rh = try await connection.openFile(at: path)
        defer { try? await rh.close() }
        let readBack = try await rh.read()
        #expect(readBack == content)
    }

    @Test("openFile with lease then write and read back") func openFileWithLeaseThenWriteAndReadBack() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("pub-lease") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        let content = Data("lease read-write test".utf8)

        let wh = try await connection.openFile(
            at: path,
            accessMode: .readWrite,
            options: [.create, .exclusive],
            opLock: .lease([.readCaching, .writeCaching])
        )
        _ = try await wh.write(content)
        try await wh.close()

        let rh = try await connection.openFile(at: path)
        defer { try? await rh.close() }
        let readBack = try await rh.read()
        #expect(readBack == content)
    }

    @Test("openFile with opLock stat succeeds") func openFileWithOpLockStatSucceeds() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-oplock-stat") { path, content in
            let file = try await connection.openFile(at: path, opLock: .levelII)
            defer { try? await file.close() }
            let stat = try await file.stat()
            #expect(stat.type == .file)
            #expect(stat.size == UInt64(content.count))
        }
    }

    @Test("openFile with lease stat succeeds") func openFileWithLeaseStatSucceeds() async throws {
        let connection = try await publicConnection()
        defer { try? await connection.disconnect() }

        try await withPublicFixtureFile(on: connection, prefix: "pub-lease-stat") { path, content in
            let file = try await connection.openFile(
                at: path,
                opLock: .lease(.readCaching)
            )
            defer { try? await file.close() }
            let stat = try await file.stat()
            #expect(stat.type == .file)
            #expect(stat.size == UInt64(content.count))
        }
    }
}

private func publicConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}

private func withPublicFixtureFile<T>(
    on connection: SMB.Connection,
    prefix: String,
    body: (String, Data) async throws -> T
) async throws -> T {
    let path = uniquePath(prefix) + ".txt"
    let content = Data(TestContent.helloBytes)
    try await connection.dumpToFile(content, to: path)
    defer { try? await connection.removeFile(at: path) }
    return try await body(path, content)
}
