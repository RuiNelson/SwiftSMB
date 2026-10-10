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

    // MARK: - Withdrawing blocking locks

    @Test("cancelling the task withdraws a waiting blocking lock", .timeLimit(.minutes(1)))
    func cancellingTaskWithdrawsWaitingBlockingLock() async throws {
        try await withLockContention("public-lock-cancel") { ownerFile, contender, contenderFile in
            let lockTask = Task {
                try await contenderFile.lock(.exclusive, nonBlocking: false)
            }
            // Long enough for the server to answer the request as pending, so the CANCEL names it by its AsyncId.
            try await Task.sleep(for: .seconds(1))
            let start = ContinuousClock.now
            lockTask.cancel()

            await #expect(throws: CancellationError.self) { try await lockTask.value }
            #expect(ContinuousClock.now - start < .seconds(5))
            try await contender.echo()
            try await expectNoLeftoverLock(ownerFile: ownerFile)
        }
    }

    @Test("cancelling the task before a blocking lock is sent withdraws it", .timeLimit(.minutes(1)))
    func cancellingTaskBeforeBlockingLockIsSentWithdrawsIt() async throws {
        try await withLockContention("public-lock-cancel-early") { ownerFile, contender, contenderFile in
            let lockTask = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                try await contenderFile.lock(.exclusive, nonBlocking: false)
            }

            await #expect(throws: CancellationError.self) { try await lockTask.value }
            try await contender.echo()
            try await expectNoLeftoverLock(ownerFile: ownerFile)
        }
    }

    @Test("the command timeout withdraws a waiting blocking lock", .timeLimit(.minutes(1)))
    func commandTimeoutWithdrawsWaitingBlockingLock() async throws {
        try await withLockContention("public-lock-timeout") { ownerFile, contender, contenderFile in
            try await contender.setTimeout(1)

            do {
                try await contenderFile.lock(.exclusive, nonBlocking: false)
                Issue.record("Expected the blocking lock to time out")
            }
            catch let SMB.Error.ntStatus(status, _, _, _) {
                #expect(status == .ioTimeout)
            }
            try await contender.echo()
            try await expectNoLeftoverLock(ownerFile: ownerFile)
        }
    }

    @Test("disconnecting withdraws a waiting blocking lock", .timeLimit(.minutes(1)))
    func disconnectingWithdrawsWaitingBlockingLock() async throws {
        try await withLockContention("public-lock-disconnect") { ownerFile, contender, contenderFile in
            let lockTask = Task {
                try await contenderFile.lock(.exclusive, nonBlocking: false)
            }
            try await Task.sleep(for: .seconds(1))

            try await contender.disconnect()
            await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) { try await lockTask.value }
            try await expectNoLeftoverLock(ownerFile: ownerFile)
        }
    }

    @Test("a blocking lock granted in a cancelled task is held")
    func blockingLockGrantedInCancelledTaskIsHeld() async throws {
        let owner = try await publicFileConnection()
        defer { try? await owner.disconnect() }
        let contender = try await publicFileConnection()
        defer { try? await contender.disconnect() }

        let path = uniquePath("public-lock-cancelled-granted") + ".txt"
        defer { try? await owner.removeFile(at: path) }
        try await owner.dumpToFile(Data("lock test".utf8), to: path)
        let ownerFile = try await owner.openFile(at: path, accessMode: .readWrite)
        defer { try? await ownerFile.close() }
        let contenderFile = try await contender.openFile(at: path, accessMode: .readWrite)
        defer { try? await contenderFile.close() }

        // Nothing conflicts, so the server grants the lock before the CANCEL reaches it.
        try await Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await ownerFile.lock(.exclusive, nonBlocking: false)
        }.value

        do {
            try await contenderFile.lock(.exclusive, nonBlocking: true)
            Issue.record("Expected the lock granted in the cancelled task to be held")
        }
        catch let SMB.Error.ntStatus(status, _, _, _) {
            #expect(status == .lockNotGranted)
        }
    }
}

private func publicFileConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}

/// Runs `body` while an owner connection holds an exclusive lock on a file that a contender connection has open too.
private func withLockContention(
    _ prefix: String,
    body: (_ ownerFile: SMB.File, _ contender: SMB.Connection, _ contenderFile: SMB.File) async throws -> Void
) async throws {
    let owner = try await publicFileConnection()
    defer { try? await owner.disconnect() }
    let contender = try await publicFileConnection()
    defer { try? await contender.disconnect() }

    let path = uniquePath(prefix) + ".txt"
    defer { try? await owner.removeFile(at: path) }
    try await owner.dumpToFile(Data("lock test".utf8), to: path)

    let ownerFile = try await owner.openFile(at: path, accessMode: .readWrite)
    defer { try? await ownerFile.close() }
    let contenderFile = try await contender.openFile(at: path, accessMode: .readWrite)
    defer { try? await contenderFile.close() }

    try await ownerFile.lock(.exclusive, nonBlocking: true)
    try await body(ownerFile, contender, contenderFile)
}

/// Checks that the server did not keep the contender's withdrawn lock pending.
///
/// A lock still pending would be granted to the contender once the owner releases its own, and the owner could then
/// not lock the file again.
private func expectNoLeftoverLock(ownerFile: SMB.File) async throws {
    try await ownerFile.unlock()
    // Samba grants pending locks asynchronously, from the contender's own server process.
    try await Task.sleep(for: .milliseconds(500))
    try await ownerFile.lock(.exclusive, nonBlocking: true)
}
