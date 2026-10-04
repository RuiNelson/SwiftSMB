//
// Part of SwiftSMB
// SMBConvenienceRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

private final class TransferProgressValues: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [UInt64] = []

    func append(_ value: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        values.append(value)
    }

    var snapshot: [UInt64] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }
}

private final class GracefulDisconnectRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Void, Swift.Error>?

    func request(on connection: SMB.Connection) {
        lock.lock()
        defer { lock.unlock() }
        guard task == nil else { return }
        task = Task { try await connection.disconnectGracefully() }
    }

    var requestedTask: Task<Void, Swift.Error>? {
        lock.lock()
        defer { lock.unlock() }
        return task
    }
}

@Suite(.tags(.integration))
struct SMBConvenienceRegressionTests {
    @Test("graceful disconnect waits for the complete atomic upload and its commit")
    func gracefulDisconnectFinishesAtomicUpload() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let verificationConnection = try await convenienceRegressionConnection()
        defer { try? await verificationConnection.disconnect() }
        let directory = uniquePath("upload-graceful-disconnect")
        try await verificationConnection.makeDirectory(at: directory)
        defer { try? await verificationConnection.removeItem(at: directory) }
        let remote = directory + "/destination.bin"
        try await verificationConnection.dumpToFile(Data([0xAA]), to: remote)
        let local = convenienceRegressionLocalURL()
        defer { try? FileManager.default.removeItem(at: local) }
        let expected = Data((0 ..< 64 * 1024).map { UInt8(truncatingIfNeeded: $0) })
        try expected.write(to: local)
        let disconnection = GracefulDisconnectRequest()

        try await connection
            .uploadFile(local: local, remote: remote, maxBlockSize: 256) { transferred, total, latestSpeed, _ in
                if transferred == 256 {
                    #expect(transferred < total)
                    disconnection.request(on: connection)
                }
                if latestSpeed == 0 {
                    #expect(transferred == UInt64(expected.count))
                    #expect(connection.isConnected)
                }
                return true
            }
        let disconnectTask = try #require(disconnection.requestedTask)
        try await withTimeout(seconds: 5) { try await disconnectTask.value }
        #expect(!connection.isConnected)
        await #expect(try verificationConnection.loadFile(at: remote) == expected)
        let entries = try await verificationConnection.listDirectory(at: directory)
        #expect(entries.filter { $0.name != "." && $0.name != ".." }.map(\.name) == ["destination.bin"])
    }

    @Test("explicit transfer blocks override the configured default")
    func explicitBlockSizesOverrideConfiguredDefault() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("transfer-preferred-block")
        defer { try? await connection.removeFile(at: remote) }
        let local = convenienceRegressionLocalURL()
        let downloaded = convenienceRegressionLocalURL()
        defer {
            try? FileManager.default.removeItem(at: local)
            try? FileManager.default.removeItem(at: downloaded)
        }
        let expected = Data((0 ..< 19).map(UInt8.init))
        try expected.write(to: local)

        let uploadBlocks = TransferProgressValues()
        try await connection.uploadFile(local: local, remote: remote, maxBlockSize: 16) { transferred, _, _, _ in
            uploadBlocks.append(transferred)
            return true
        }
        #expect(uploadBlocks.snapshot == [16, 19, 19])

        let downloadBlocks = TransferProgressValues()
        try await connection.downloadFile(remote: remote, local: downloaded, maxBlockSize: 16) { transferred, _, _, _ in
            downloadBlocks.append(transferred)
            return true
        }
        #expect(downloadBlocks.snapshot == [16, 19, 19])
        #expect(try Data(contentsOf: downloaded) == expected)
    }

    #if !os(Windows)
        @Test("uploading a local symbolic link uses its target size")
        func uploadLocalSymbolicLinkUsesTargetSize() async throws {
            let connection = try await convenienceRegressionConnection()
            defer { try? await connection.disconnect() }
            let remote = uniquePath("upload-local-symlink")
            defer { try? await connection.removeFile(at: remote) }
            let source = convenienceRegressionLocalURL()
            let link = convenienceRegressionLocalURL()
            defer {
                try? FileManager.default.removeItem(at: link)
                try? FileManager.default.removeItem(at: source)
            }
            let expected = Data(repeating: 0x5A, count: 97)
            try expected.write(to: source)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)

            try await connection.uploadFile(local: link, remote: remote) { transferred, total, _, _ in
                #expect(total == UInt64(expected.count))
                #expect(transferred <= total)
                return true
            }
            await #expect(try connection.loadFile(at: remote) == expected)
        }
    #endif

    @Test("a shrinking source cannot replace an atomic upload destination")
    func shrinkingLocalSourceDoesNotCommitPartialUpload() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let directory = uniquePath("upload-shrinking-source")
        try await connection.makeDirectory(at: directory)
        defer { try? await connection.removeItem(at: directory) }
        let remote = directory + "/destination.bin"
        let previous = Data([0xAA, 0xBB])
        try await connection.dumpToFile(previous, to: remote)
        let local = convenienceRegressionLocalURL()
        try Data(repeating: 0x42, count: 64).write(to: local)
        defer { try? FileManager.default.removeItem(at: local) }

        await #expect(throws: SMB.Error.self) {
            try await connection.uploadFile(local: local, remote: remote, maxBlockSize: 4) { transferred, _, _, _ in
                if transferred == 4 {
                    do {
                        let handle = try FileHandle(forWritingTo: local)
                        defer { try? handle.close() }
                        try handle.truncate(atOffset: 0)
                    }
                    catch {
                        Issue.record(error)
                    }
                }
                return true
            }
        }
        await #expect(try connection.loadFile(at: remote) == previous)
        let entries = try await connection.listDirectory(at: directory)
        #expect(entries.filter { $0.name != "." && $0.name != ".." }.map(\.name) == ["destination.bin"])
    }

    @Test("a growing upload source stops at its advertised transfer length")
    func growingLocalSourceDoesNotExceedAdvertisedLength() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("upload-growing-source")
        defer { try? await connection.removeFile(at: remote) }
        let local = convenienceRegressionLocalURL()
        defer { try? FileManager.default.removeItem(at: local) }
        let expected = Data([1, 2, 3, 4])
        try expected.write(to: local)

        try await connection.uploadFile(local: local, remote: remote, maxBlockSize: 2) { transferred, total, _, _ in
            #expect(total == 4)
            #expect(transferred <= total)
            if transferred == 2 {
                do {
                    let handle = try FileHandle(forWritingTo: local)
                    defer { try? handle.close() }
                    try handle.seekToEnd()
                    try handle.write(contentsOf: Data(repeating: 0xFF, count: 16))
                }
                catch {
                    Issue.record(error)
                }
            }
            return true
        }
        await #expect(try connection.loadFile(at: remote) == expected)
    }

    @Test("an invalid local upload source does not create remote ancestors")
    func invalidLocalSourceDoesNotCreateRemoteParents() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let directory = uniquePath("upload-invalid-source")
        defer { try? await connection.removeItem(at: directory) }

        await #expect(throws: SMB.Error.self) {
            try await connection.uploadFile(
                local: convenienceRegressionLocalURL(),
                remote: directory + "/one/file.bin"
            ) { _, _, _, _ in true }
        }
        await #expect(try connection.itemExists(at: directory) == .false)
    }

    @Test("an already cancelled recursive removal preserves a file and empty directory")
    func cancelledRemoveItemPreservesEntries() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let directory = uniquePath("remove-cancelled-directory")
        let file = uniquePath("remove-cancelled-file")
        try await connection.makeDirectory(at: directory)
        try await connection.dumpToFile(Data([1]), to: file)
        defer {
            try? await connection.removeDirectory(at: directory)
            try? await connection.removeFile(at: file)
        }

        for path in [directory, file] {
            let task = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                try await connection.removeItem(at: path)
            }
            await #expect(throws: CancellationError.self) { try await task.value }
        }
        await #expect(try connection.itemExists(at: directory) == .directory)
        await #expect(try connection.itemExists(at: file) == .file)
    }

    @Test("an already cancelled directory read leaves the stream untouched")
    func cancelledReadAllDoesNotConsumeStream() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let directory = try await connection.openDirectory(at: TestContent.testdirPath)
        defer { await directory.close() }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await directory.readAll()
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(try await directory.readNext() != nil)
    }

    @Test("competing copies preserve the destination created by the successful copy")
    func competingCopiesPreserveSuccessfulDestination() async throws {
        let connection = try await convenienceRegressionConnection()
        defer { try? await connection.disconnect() }
        let destination = uniquePath("copy-competing-destination")
        defer { try? await connection.removeFile(at: destination) }

        func copy() async -> Bool {
            do {
                try await connection.copyFile(from: TestContent.helloPath, to: destination)
                return true
            }
            catch {
                return false
            }
        }
        async let first = copy()
        async let second = copy()
        let results = await [first, second]
        #expect(results.filter(\.self).count == 1)
        await #expect(try connection.loadFile(at: destination) == Data(TestContent.helloBytes))
    }
}

private func convenienceRegressionConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
        configuration: SMB.Configuration(transferBlockSize: 4)
    )
}

private func convenienceRegressionLocalURL() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
}
