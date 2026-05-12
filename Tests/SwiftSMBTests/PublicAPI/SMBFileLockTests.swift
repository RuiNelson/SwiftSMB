//
// Part of SwiftSMB
// SMBFileLockTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBFileLockTests {
    @Test("public lock exclusive succeeds") func publicLockExclusiveSucceeds() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-lock") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        defer { try? file.close() }
        try file.lock(.exclusive, nonBlocking: false)
    }

    @Test("public lock shared succeeds") func publicLockSharedSucceeds() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-lock-shared") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        defer { try? file.close() }
        try file.lock(.shared, nonBlocking: false)
    }

    @Test("public unlock after lock succeeds") func publicUnlockAfterLockSucceeds() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-unlock") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        defer { try? file.close() }
        try file.lock(.exclusive, nonBlocking: false)
        try file.unlock()
    }

    @Test("public lock on closed file throws") func publicLockOnClosedFileThrows() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-lock-closed") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        try file.close()

        #expect(throws: SMB.Error.self) {
            try file.lock(.exclusive, nonBlocking: false)
        }
    }

    @Test("public unlock on closed file throws") func publicUnlockOnClosedFileThrows() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-unlock-closed") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        try file.close()

        #expect(throws: SMB.Error.self) {
            try file.unlock()
        }
    }

    @Test("public lock with range succeeds") func publicLockWithRangeSucceeds() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-lock-range") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        defer { try? file.close() }
        try file.lock(.exclusive, nonBlocking: false, range: 10 ..< 110)
        try file.unlock(range: 10 ..< 110)
    }

    @Test("public lock with negative range throws") func publicLockWithNegativeRangeThrows() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-lock-neg") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        defer { try? file.close() }

        #expect(throws: SMB.Error.self) {
            try file.lock(.exclusive, nonBlocking: false, range: -5 ..< 5)
        }
    }

    @Test("public lock with empty range throws") func publicLockWithEmptyRangeThrows() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("public-lock-empty") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try connection.openFile(at: path, accessMode: .readWrite)
        defer { try? file.close() }

        #expect(throws: SMB.Error.self) {
            try file.lock(.exclusive, nonBlocking: false, range: 5 ..< 5)
        }
    }
}

private func publicFileConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}
