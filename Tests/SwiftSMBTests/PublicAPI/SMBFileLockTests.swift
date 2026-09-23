//
// Part of SwiftSMB
// SMBFileLockTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBFileLockTests {
    @Test("public lock exclusive succeeds") func publicLockExclusiveSucceeds() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-lock") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        defer { try? await file.close() }
        try await file.lock(.exclusive, nonBlocking: false)
    }

    @Test("public lock shared succeeds") func publicLockSharedSucceeds() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-lock-shared") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        defer { try? await file.close() }
        try await file.lock(.shared, nonBlocking: false)
    }

    @Test("public unlock after lock succeeds") func publicUnlockAfterLockSucceeds() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-unlock") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        defer { try? await file.close() }
        try await file.lock(.exclusive, nonBlocking: false)
        try await file.unlock()
    }

    @Test("public lock on closed file throws") func publicLockOnClosedFileThrows() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-lock-closed") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        try await file.close()

        await #expect(throws: SMB.Error.self) {
            try await file.lock(.exclusive, nonBlocking: false)
        }
    }

    @Test("public unlock on closed file throws") func publicUnlockOnClosedFileThrows() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-unlock-closed") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        try await file.close()

        await #expect(throws: SMB.Error.self) {
            try await file.unlock()
        }
    }

    @Test("public lock with range succeeds") func publicLockWithRangeSucceeds() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-lock-range") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        defer { try? await file.close() }
        try await file.lock(.exclusive, nonBlocking: false, range: 10 ..< 110)
        try await file.unlock(range: 10 ..< 110)
    }

    @Test("public lock with negative range throws") func publicLockWithNegativeRangeThrows() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-lock-neg") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        defer { try? await file.close() }

        await #expect(throws: SMB.Error.self) {
            try await file.lock(.exclusive, nonBlocking: false, range: -5 ..< 5)
        }
    }

    @Test("lock conflict after an unrelated failure reports the lock status")
    func lockConflictAfterUnrelatedFailureReportsLockStatus() async throws {
        let owner = try await publicFileConnection()
        let contender = try await publicFileConnection()
        defer { try? await owner.disconnect() }
        defer { try? await contender.disconnect() }

        let path = uniquePath("public-lock-stale") + ".txt"
        defer { try? await owner.removeFile(at: path) }

        try await owner.dumpToFile(Data("lock test".utf8), to: path)
        let ownerFile = try await owner.openFile(at: path, accessMode: .readWrite)
        defer { try? await ownerFile.close() }
        let contenderFile = try await contender.openFile(at: path, accessMode: .readWrite)
        defer { try? await contenderFile.close() }
        try await ownerFile.lock(.exclusive, nonBlocking: true)

        // A failed open leaves STATUS_OBJECT_NAME_NOT_FOUND in the libsmb2 context; it must not leak into the next
        // error.
        _ = try? await contender.openFile(at: uniquePath("missing") + ".txt")

        do {
            try await contenderFile.lock(.exclusive, nonBlocking: true)
            Issue.record("Expected the conflicting lock to fail")
        }
        catch let SMB.Error.ntStatus(status, _, _, message) {
            #expect(status == .lockNotGranted)
            #expect(!message.contains("Open failed"))
        }
    }

    @Test("public lock with empty range throws") func publicLockWithEmptyRangeThrows() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("public-lock-empty") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("lock test".utf8), to: path)
        let file = try await connection.openFile(at: path, accessMode: .readWrite)
        defer { try? await file.close() }

        await #expect(throws: SMB.Error.self) {
            try await file.lock(.exclusive, nonBlocking: false, range: 5 ..< 5)
        }
    }
}

private func publicFileConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
