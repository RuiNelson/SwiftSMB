//
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

        let file = try connection.openFile(at: TestContent.helloPath)
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with none opLock opens file") func openFileWithNoneOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(at: TestContent.helloPath, opLock: .none)
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with levelII opLock opens file") func openFileWithLevelIIOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(at: TestContent.helloPath, opLock: .levelII)
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with exclusive opLock opens file") func openFileWithExclusiveOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(at: TestContent.helloPath, opLock: .exclusive)
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with batch opLock opens file") func openFileWithBatchOpLockOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(at: TestContent.helloPath, opLock: .batch)
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with lease readCaching opens file") func openFileWithLeaseReadCachingOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(at: TestContent.helloPath, opLock: .lease(.readCaching))
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with lease handle caching opens file") func openFileWithLeaseHandleCachingOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(
            at: TestContent.helloPath,
            opLock: .lease([.readCaching, .handleCaching]),
        )
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
    }

    @Test("openFile with lease write caching opens file") func openFileWithLeaseWriteCachingOpensFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(
            at: TestContent.helloPath,
            opLock: .lease([.readCaching, .handleCaching, .writeCaching]),
        )
        defer { try? file.close() }
        let data = try file.read()
        #expect(data == Data(TestContent.helloBytes))
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

        let file = try connection.openFile(at: TestContent.helloPath, opLock: .levelII)
        defer { try? file.close() }
        let stat = try file.stat()
        #expect(stat.type == .file)
        #expect(stat.size == UInt64(TestContent.helloBytes.count))
    }

    @Test("openFile with lease stat succeeds") func openFileWithLeaseStatSucceeds() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let file = try connection.openFile(
            at: TestContent.helloPath,
            opLock: .lease(.readCaching),
        )
        defer { try? file.close() }
        let stat = try file.stat()
        #expect(stat.type == .file)
        #expect(stat.size > 0)
    }
}

private func publicConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}
