//
// Part of SwiftSMB
// SMBFileOpLockTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBPublicAPIFileOpLockTests {
    @Test("openFile default opLock opens file") func openFileDefaultOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-oplock-default") { path, content in
            let file = try connection.openFile(at: path)
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with none opLock opens file") func openFileWithNoneOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-oplock-none") { path, content in
            let file = try connection.openFile(at: path, opLock: .none)
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with levelII opLock opens file") func openFileWithLevelIIOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-oplock-levelII") { path, content in
            let file = try connection.openFile(at: path, opLock: .levelII)
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with exclusive opLock opens file") func openFileWithExclusiveOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-oplock-exclusive") { path, content in
            let file = try connection.openFile(at: path, opLock: .exclusive)
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with batch opLock opens file") func openFileWithBatchOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-oplock-batch") { path, content in
            let file = try connection.openFile(at: path, opLock: .batch)
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with lease readCaching opens file") func openFileWithLeaseReadCachingOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-lease-read") { path, content in
            let file = try connection.openFile(at: path, opLock: .lease(.readCaching))
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with lease handle caching opens file") func openFileWithLeaseHandleCachingOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-lease-handle") { path, content in
            let file = try connection.openFile(
                at: path,
                opLock: .lease([.readCaching, .handleCaching]),
            )
            defer { try? file.close() }
            let data = try file.read()
            #expect(data == content)
        }
    }

    @Test("openFile with lease write caching opens file") func openFileWithLeaseWriteCachingOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pub-lease-full") + ".txt"
        defer { try? connection.removeFile(at: path) }
        let content = Data("lease write caching test".utf8)
        try connection.dumpToFile(content, to: path)

        let file = try connection.openFile(
            at: path,
            opLock: .lease([.readCaching, .handleCaching, .writeCaching]),
        )
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == content)
    }

    @Test("openFile with opLock then write and read back") func openFileWithOpLockThenWriteAndReadBack() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pub-oplock") + ".txt"
        defer { try? connection.removeFile(at: path) }

        let content = Data("oplock read-write test".utf8)

        let wh = try connection.openFile(
            at: path,
            accessMode: .readWrite,
            options: [.create, .exclusive],
            opLock: .batch,
        )
        _ = try wh.write(content)
        try wh.close()

        let rh = try connection.openFile(at: path)
        defer { try? rh.close() }
        let readBack = try rh.read()
        #expect(readBack == content)
    }

    @Test("openFile with lease then write and read back") func openFileWithLeaseThenWriteAndReadBack() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pub-lease") + ".txt"
        defer { try? connection.removeFile(at: path) }

        let content = Data("lease read-write test".utf8)

        let wh = try connection.openFile(
            at: path,
            accessMode: .readWrite,
            options: [.create, .exclusive],
            opLock: .lease([.readCaching, .writeCaching]),
        )
        _ = try wh.write(content)
        try wh.close()

        let rh = try connection.openFile(at: path)
        defer { try? rh.close() }
        let readBack = try rh.read()
        #expect(readBack == content)
    }

    @Test("openFile with opLock stat succeeds") func openFileWithOpLockStatSucceeds() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-oplock-stat") { path, content in
            let file = try connection.openFile(at: path, opLock: .levelII)
            defer { try? file.close() }
            let stat = try file.stat()
            #expect(stat.type == .file)
            #expect(stat.size == UInt64(content.count))
        }
    }

    @Test("openFile with lease stat succeeds") func openFileWithLeaseStatSucceeds() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        try withPublicFixtureFile(on: connection, prefix: "pub-lease-stat") { path, content in
            let file = try connection.openFile(
                at: path,
                opLock: .lease(.readCaching),
            )
            defer { try? file.close() }
            let stat = try file.stat()
            #expect(stat.type == .file)
            #expect(stat.size == UInt64(content.count))
        }
    }
}

private func publicConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}

private func withPublicFixtureFile<T>(
    on connection: SMB.Connection,
    prefix: String,
    body: (String, Data) throws -> T,
) throws -> T {
    let path = uniquePath(prefix) + ".txt"
    let content = Data(TestContent.helloBytes)
    try connection.dumpToFile(content, to: path)
    defer { try? connection.removeFile(at: path) }
    return try body(path, content)
}
