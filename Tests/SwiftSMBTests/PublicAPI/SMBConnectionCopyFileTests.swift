//
// Part of SwiftSMB
// SMBConnectionCopyFileTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

/// `copyFile` with its `overwrite` option and progress reporting.
@Suite(.tags(.integration))
struct SMBConnectionCopyFileTests {
    /// A copy takes several requests only when the file is larger than what one request may carry (Samba: 16 MiB, after
    /// the first request, as large as the maximum write size, is rejected). This one is two and a half times the
    /// maximum write size, ending on an uneven chunk.
    private static func largeContent(for connection: SMB.Connection) async throws -> Data {
        let size = try await Int(connection.maxWriteSize) * 5 / 2 + 12345
        var content = Data(count: size)
        for index in stride(from: 0, to: content.count, by: 4096) {
            content[index] = UInt8(truncatingIfNeeded: index >> 12)
        }
        return content
    }

    @Test("copyFile to an existing destination throws a typed error that reports EEXIST")
    func existingDestinationThrowsTypedError() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy-exists") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }
        try await connection.dumpToFile(Data("KEEP".utf8), to: destPath)

        let error = await #expect(throws: SMB.Error.self) {
            try await connection.copyFile(from: TestContent.helloPath, to: destPath)
        }
        #expect(error == .invalidArgument(cause: .remoteDestinationAlreadyExists, onOperation: .smbConnectionCopyFile))
        #expect(error?.posixCode == EEXIST)
        #expect(try await connection.loadFile(at: destPath) == Data("KEEP".utf8))
    }

    @Test("copyFile with overwrite replaces a longer destination")
    func overwriteReplacesLongerDestination() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy-overwrite") + ".bin"
        defer { try? await connection.removeFile(at: destPath) }
        try await connection.dumpToFile(Data(repeating: 0x41, count: 100_000), to: destPath)

        try await connection.copyFile(from: TestContent.helloPath, to: destPath, overwrite: true)

        #expect(try await Array(connection.loadFile(at: destPath)) == TestContent.helloBytes)
    }

    @Test("copyFile with overwrite creates a missing destination")
    func overwriteCreatesMissingDestination() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy-overwrite-new") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        try await connection.copyFile(from: TestContent.helloPath, to: destPath, overwrite: true)

        #expect(try await Array(connection.loadFile(at: destPath)) == TestContent.helloBytes)
    }

    @Test("copyFile with overwrite refuses to copy a file onto itself")
    func overwriteRefusesSameFile() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("copy-self") + ".txt"
        defer { try? await connection.removeFile(at: path) }
        try await connection.dumpToFile(Data("PRECIOUS".utf8), to: path)

        await #expect(throws: SMB.Error.invalidArgument(
            cause: .sourceAndDestinationAreTheSameFile,
            onOperation: .smbConnectionCopyFile
        )) {
            try await connection.copyFile(from: path, to: path, overwrite: true)
        }
        #expect(try await connection.loadFile(at: path) == Data("PRECIOUS".utf8))
    }

    @Test("stopping an overwriting copy removes a destination that did not exist")
    func stopRemovesNewDestinationDespiteOverwrite() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy-stop-new-src") + ".bin"
        let destPath = uniquePath("copy-stop-new-dst") + ".bin"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }
        try await connection.dumpToFile(Self.largeContent(for: connection), to: sourcePath)

        try await connection.copyFile(from: sourcePath, to: destPath, overwrite: true) { _, _, _, _ in false }

        #expect(try await connection.itemExists(at: destPath) == .false)
    }

    @Test("cancelling during the report of the last request keeps the complete copy")
    func cancellationAfterLastRequestKeepsCopy() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy-cancel-last") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        // The file is smaller than one request, so the first report is the last request's.
        try await Task {
            try await connection.copyFile(from: TestContent.helloPath, to: destPath) { _, _, _, _ in
                withUnsafeCurrentTask { $0?.cancel() }
                return true
            }
        }.value

        #expect(try await Array(connection.loadFile(at: destPath)) == TestContent.helloBytes)
    }

    @Test("copyFile with overwrite refuses a destination that differs only in case")
    func overwriteRefusesCaseAlias() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("copy-case") + ".txt"
        defer { try? await connection.removeFile(at: path) }
        try await connection.dumpToFile(Data("PRECIOUS".utf8), to: path)

        // The test share is case-insensitive, so the upper-case spelling is the same file.
        let alias = path.uppercased()
        guard try await connection.itemExists(at: alias) != .false else { return }

        await #expect(throws: SMB.Error.invalidArgument(
            cause: .sourceAndDestinationAreTheSameFile,
            onOperation: .smbConnectionCopyFile
        )) {
            try await connection.copyFile(from: path, to: alias, overwrite: true)
        }
        #expect(try await connection.loadFile(at: path) == Data("PRECIOUS".utf8))
    }

    @Test("copyFile with overwrite copies between canonically equivalent but distinct names")
    func overwriteAllowsCanonicallyEquivalentNames() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let stem = uniquePath("copy-nfc")
        let composed = "\(stem)-\u{E9}.txt"
        let decomposed = "\(stem)-e\u{301}.txt"
        defer {
            try? await connection.removeFile(at: composed)
            try? await connection.removeFile(at: decomposed)
        }
        try await connection.dumpToFile(Data("SOURCE".utf8), to: composed)
        try await connection.dumpToFile(Data("OLD".utf8), to: decomposed)

        // The server may treat the two spellings as one name; only then is a refusal right.
        let first = try await connection.stat(at: composed)
        let second = try await connection.stat(at: decomposed)
        guard first.inode != second.inode else { return }

        try await connection.copyFile(from: composed, to: decomposed, overwrite: true)

        #expect(try await connection.loadFile(at: decomposed) == Data("SOURCE".utf8))
    }

    @Test("a task that is already cancelled copies nothing and creates no destination")
    func cancelledTaskCreatesNothing() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy-precancelled") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await connection.copyFile(from: TestContent.helloPath, to: destPath)
        }
        await #expect(throws: CancellationError.self) {
            try await task.value
        }
        #expect(try await connection.itemExists(at: destPath) == .false)
    }

    @Test("overwrite creates a destination that a stale cache still reports as present")
    func overwriteIgnoresStalePresentEntry() async throws {
        let cached = try await copyConnection()
        let other = try await copyConnection()
        defer {
            Task { try? await cached.disconnect() }
            Task { try? await other.disconnect() }
        }
        cached.attachCache(SMB.ReferenceCache(configuration: .init(metadata: .answer(
            for: 60,
            includingMissing: false
        ))))

        let destPath = uniquePath("copy-stale-present") + ".txt"
        defer { try? await other.removeFile(at: destPath) }
        try await other.dumpToFile(Data("OLD".utf8), to: destPath)
        _ = try await cached.stat(at: destPath) // now cached as a file
        try await other.removeFile(at: destPath)

        try await cached.copyFile(from: TestContent.helloPath, to: destPath, overwrite: true)

        #expect(try await Array(other.loadFile(at: destPath)) == TestContent.helloBytes)
    }

    @Test("overwrite replaces a destination that a stale cache still reports as missing")
    func overwriteIgnoresStaleMissingEntry() async throws {
        let cached = try await copyConnection()
        let other = try await copyConnection()
        defer {
            Task { try? await cached.disconnect() }
            Task { try? await other.disconnect() }
        }
        cached.attachCache(SMB.ReferenceCache(configuration: .init(metadata: .answer(for: 60, includingMissing: true))))

        let destPath = uniquePath("copy-stale-missing") + ".txt"
        defer { try? await other.removeFile(at: destPath) }
        #expect(try await cached.itemExists(at: destPath) == .false) // now cached as missing
        try await other.dumpToFile(Data("OLD".utf8), to: destPath)

        try await cached.copyFile(from: TestContent.helloPath, to: destPath, overwrite: true)

        #expect(try await Array(other.loadFile(at: destPath)) == TestContent.helloBytes)
    }

    @Test("without overwrite a destination that a stale cache reports as missing still throws the typed error")
    func staleMissingEntryThrowsTypedError() async throws {
        let cached = try await copyConnection()
        let other = try await copyConnection()
        defer {
            Task { try? await cached.disconnect() }
            Task { try? await other.disconnect() }
        }
        cached.attachCache(SMB.ReferenceCache(configuration: .init(metadata: .answer(for: 60, includingMissing: true))))

        let destPath = uniquePath("copy-stale-typed") + ".txt"
        defer { try? await other.removeFile(at: destPath) }
        #expect(try await cached.itemExists(at: destPath) == .false)
        try await other.dumpToFile(Data("KEEP".utf8), to: destPath)

        await #expect(throws: SMB.Error.invalidArgument(
            cause: .remoteDestinationAlreadyExists,
            onOperation: .smbConnectionCopyFile
        )) {
            try await cached.copyFile(from: TestContent.helloPath, to: destPath)
        }
        #expect(try await other.loadFile(at: destPath) == Data("KEEP".utf8))
    }

    @Test("copyFile rejects a directory destination even with overwrite")
    func overwriteRejectsDirectoryDestination() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        await #expect(throws: SMB.Error.invalidArgument(
            cause: .remoteDestinationIsNotAFile,
            onOperation: .smbConnectionCopyFile
        )) {
            try await connection.copyFile(from: TestContent.helloPath, to: TestContent.testdirPath, overwrite: true)
        }
    }

    @Test("copyFile reports progress after each request and once on completion")
    func reportsProgress() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy-progress-src") + ".bin"
        let destPath = uniquePath("copy-progress-dst") + ".bin"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }
        let content = try await Self.largeContent(for: connection)
        try await connection.dumpToFile(content, to: sourcePath)

        let reports = SendableBox<[(transferred: UInt64, total: UInt64, latest: Double)]>([])
        try await connection.copyFile(from: sourcePath, to: destPath) { transferred, total, latest, _ in
            await Task.yield()
            reports.value.append((transferred, total, latest))
            return true
        }

        let size = UInt64(content.count)
        // At least two requests (the server allows 16 MiB per request) and the completion. Only the reports before the
        // last request are partial.
        #expect(reports.value.count >= 3)
        #expect(reports.value.dropLast(2).allSatisfy { $0.transferred < size })
        #expect(reports.value.allSatisfy { $0.total == size })
        let transferred = reports.value.map(\.transferred)
        #expect(transferred == transferred.sorted())
        #expect(transferred.last == size)
        #expect(reports.value.last?.latest == 0)
        #expect(try await connection.loadFile(at: destPath) == content)
    }

    @Test("copyFile with a synchronous progress closure copies the file")
    func synchronousProgress() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy-sync-progress") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        let last = SendableBox<UInt64>(0)
        try await connection.copyFile(from: TestContent.helloPath, to: destPath) { transferred, _, _, _ in
            last.value = transferred
            return true
        }

        #expect(last.value == UInt64(TestContent.helloBytes.count))
        #expect(try await Array(connection.loadFile(at: destPath)) == TestContent.helloBytes)
    }

    @Test("copyFile of an empty file reports a single completion")
    func emptyFileReportsCompletion() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy-empty-src") + ".txt"
        let destPath = uniquePath("copy-empty-dst") + ".txt"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }
        try await connection.dumpToFile(Data(), to: sourcePath)

        let reports = SendableBox<[UInt64]>([])
        try await connection.copyFile(from: sourcePath, to: destPath) { transferred, total, _, _ in
            reports.value.append(transferred + total)
            return true
        }

        #expect(reports.value == [0])
        #expect(try await connection.stat(at: destPath).size == 0)
    }

    @Test("stopping from the progress closure returns and removes a destination the copy created")
    func stopRemovesCreatedDestination() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy-stop-src") + ".bin"
        let destPath = uniquePath("copy-stop-dst") + ".bin"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }
        try await connection.dumpToFile(Self.largeContent(for: connection), to: sourcePath)

        let calls = SendableBox(0)
        try await connection.copyFile(from: sourcePath, to: destPath) { _, _, _, _ in
            calls.value += 1
            return false
        }

        #expect(calls.value == 1)
        #expect(try await connection.itemExists(at: destPath) == .false)
    }

    @Test("stopping an overwriting copy leaves the truncated, partially written destination")
    func stopKeepsOverwrittenDestination() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy-stop-over-src") + ".bin"
        let destPath = uniquePath("copy-stop-over-dst") + ".bin"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }
        let content = try await Self.largeContent(for: connection)
        try await connection.dumpToFile(content, to: sourcePath)
        try await connection.dumpToFile(Data("OLD".utf8), to: destPath)

        try await connection.copyFile(from: sourcePath, to: destPath, overwrite: true) { _, _, _, _ in false }

        let size = try await connection.stat(at: destPath).size
        #expect(size > 0)
        #expect(size < UInt64(content.count))
    }

    @Test("cancelling the task stops the copy and removes the destination it created")
    func taskCancellationStopsCopy() async throws {
        let connection = try await copyConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy-cancel-src") + ".bin"
        let destPath = uniquePath("copy-cancel-dst") + ".bin"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }
        try await connection.dumpToFile(Self.largeContent(for: connection), to: sourcePath)

        let task = Task {
            try await connection.copyFile(from: sourcePath, to: destPath) { _, _, _, _ in
                withUnsafeCurrentTask { $0?.cancel() }
                return true
            }
        }
        await #expect(throws: CancellationError.self) {
            try await task.value
        }
        #expect(try await connection.itemExists(at: destPath) == .false)
    }
}

private func copyConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
