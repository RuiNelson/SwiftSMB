//
// Part of SwiftSMB
// SMBConnectionPipeTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

final class SendableBox<Value>: @unchecked Sendable {
    var value: Value
    init(_ value: Value) {
        self.value = value
    }
}

@Suite(.serialized, .tags(.integration))
struct SMBConnectionPipeTests {
    @Test("write from pipe stores remote file")
    func writeFromPipeStoresRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-write") + ".bin"
        defer { try? connection.removeFile(at: path) }

        let pipe = DataPipe(maxPackages: 4, label: "SwiftSMBTests.SMBConnectionPipeTests.write")
        pipe.send(.start)
        pipe.send(.data(Data([0x01, 0x02])))
        pipe.send(.data(Data([0x03, 0x04])))
        pipe.send(.finish)

        let progress = SendableBox<[UInt64]>([])
        try connection.write(fromPipe: pipe, toFile: path) { transferred, _, _ in
            progress.value.append(transferred)
            return true
        }

        #expect(try connection.loadFile(at: path) == Data([0x01, 0x02, 0x03, 0x04]))
        #expect(progress.value.last == 4)
    }

    @Test("write from broken pipe throws")
    func writeFromBrokenPipeThrows() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-broken") + ".bin"
        defer { try? connection.removeFile(at: path) }

        let pipe = DataPipe(maxPackages: 2, label: "SwiftSMBTests.SMBConnectionPipeTests.broken")
        pipe.send(.start)
        pipe.send(.broken)

        #expect(throws: (any Error).self) {
            try connection.write(fromPipe: pipe, toFile: path) { _, _, _ in true }
        }
    }

    @Test("write from pipe requires start package")
    func writeFromPipeRequiresStartPackage() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-missing-start") + ".bin"

        let pipe = DataPipe(maxPackages: 2, label: "SwiftSMBTests.SMBConnectionPipeTests.missingStart")
        pipe.send(.data(Data([0x01])))
        pipe.send(.finish)

        #expect(throws: (any Error).self) {
            try connection.write(fromPipe: pipe, toFile: path) { _, _, _ in true }
        }
    }

    @Test("leading slash in remote path is ignored")
    func leadingSlashInRemotePathIsIgnored() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("leading-slash") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("ok".utf8), to: "/" + path)

        #expect(try connection.loadFile(at: path) == Data("ok".utf8))
        #expect(try connection.loadFile(at: "/" + path) == Data("ok".utf8))
    }

    @Test("read to pipe transfers remote file")
    func readToPipeTransfersRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-read") + ".bin"
        defer { try? connection.removeFile(at: path) }

        let expected = Data([0xAA, 0xBB, 0xCC, 0xDD])
        try connection.dumpToFile(expected, to: path)

        let pipe = DataPipe(maxPackages: 3, label: "SwiftSMBTests.SMBConnectionPipeTests.read")
        let progress = SendableBox<[UInt64]>([])
        try connection.read(fromFile: path, toPipe: pipe) { transferred, _, _ in
            progress.value.append(transferred)
            return true
        }

        var received = Data()
        var isComplete = false
        while !isComplete, let package = pipe.receive(timeout: nil) {
            switch package {
            case .start:
                continue
            case let .data(chunk):
                received.append(chunk)
            case .finish:
                isComplete = true
            case .broken:
                Issue.record("Pipe broke before the file was fully read")
                isComplete = true
            }
        }

        #expect(received == expected)
        #expect(progress.value.last == UInt64(expected.count))
    }

    @Test("read to pipe honors max block size")
    func readToPipeHonorsMaxBlockSize() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-read-block-size") + ".bin"
        defer { try? connection.removeFile(at: path) }

        let expected = Data([0x10, 0x11, 0x12, 0x13])
        try connection.dumpToFile(expected, to: path)

        let pipe = DataPipe(maxPackages: 3, label: "SwiftSMBTests.SMBConnectionPipeTests.readBlockSize")
        let progress = SendableBox<[UInt64]>([])
        try connection.read(fromFile: path, toPipe: pipe, maxBlockSize: 2) { transferred, _, _ in
            progress.value.append(transferred)
            return true
        }

        var received = Data()
        var isComplete = false
        while !isComplete, let package = pipe.receive(timeout: nil) {
            switch package {
            case .start:
                continue
            case let .data(chunk):
                received.append(chunk)
            case .finish:
                isComplete = true
            case .broken:
                Issue.record("Pipe broke before the file was fully read")
                isComplete = true
            }
        }

        #expect(received == expected)
        #expect(progress.value == [2, 4, 4])
    }

    @Test("upload file writes remote file")
    func uploadFileWritesRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        let expected = Data((0 ..< 17).map { UInt8($0) })
        try expected.write(to: local)

        let progress = SendableBox<[UInt64]>([])
        let latestSpeeds = SendableBox<[Double]>([])
        try connection.uploadFile(local: local, remote: remote, maxBlockSize: 4) { transferred, total, latestSpeed, _ in
            progress.value.append(transferred)
            latestSpeeds.value.append(latestSpeed)
            #expect(total == UInt64(expected.count))
            return true
        }

        #expect(try connection.loadFile(at: remote) == expected)
        #expect(progress.value.last == UInt64(expected.count))
        #expect(latestSpeeds.value.last == 0)
    }

    @Test("atomic upload replaces existing remote file")
    func atomicUploadReplacesExistingRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload-replace") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        try connection.dumpToFile(Data([0xAA, 0xBB, 0xCC]), to: remote)

        let expected = Data((0 ..< 11).map { UInt8(80 + $0) })
        try expected.write(to: local)

        try connection.uploadFile(local: local, remote: remote, maxBlockSize: 4) { _, _, _, _ in true }

        #expect(try connection.loadFile(at: remote) == expected)
    }

    @Test("download file writes local file")
    func downloadFileWritesLocalFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("download") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        try? FileManager.default.removeItem(at: local)
        defer { try? FileManager.default.removeItem(at: local) }

        let expected = Data((0 ..< 19).map { UInt8(255 - $0) })
        try connection.dumpToFile(expected, to: remote)

        let progress = SendableBox<[UInt64]>([])
        let latestSpeeds = SendableBox<[Double]>([])
        try connection
            .downloadFile(remote: remote, local: local, maxBlockSize: 5) { transferred, total, latestSpeed, _ in
                progress.value.append(transferred)
                latestSpeeds.value.append(latestSpeed)
                #expect(total == UInt64(expected.count))
                return true
            }

        #expect(try Data(contentsOf: local) == expected)
        #expect(progress.value.last == UInt64(expected.count))
        #expect(latestSpeeds.value.last == 0)
    }

    @Test("download with offset resumes into local file")
    func downloadWithOffsetResumesIntoLocalFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("download-resume") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        let expected = Data((0 ..< 10).map { UInt8($0) })
        try connection.dumpToFile(expected, to: remote)
        try expected.prefix(4).write(to: local)

        let totals = SendableBox<[UInt64]>([])
        try connection
            .downloadFile(
                remote: remote,
                local: local,
                from: .offset(byte: 4),
                maxBlockSize: 3,
            ) { transferred, total, _, _ in
                totals.value.append(total)
                #expect(transferred <= total)
                return true
            }

        #expect(try Data(contentsOf: local) == expected)
        #expect(totals.value.last == 6)
    }

    @Test("upload with offset resumes from local file")
    func uploadWithOffsetResumesFromLocalFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload-resume") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        let expected = Data((0 ..< 10).map { UInt8($0) })
        try expected.write(to: local)
        try connection.dumpToFile(expected.prefix(4), to: remote)

        let totals = SendableBox<[UInt64]>([])
        try connection
            .uploadFile(
                local: local,
                remote: remote,
                from: .offset(byte: 4),
                maxBlockSize: 3,
            ) { transferred, total, _, _ in
                totals.value.append(total)
                #expect(transferred <= total)
                return true
            }

        #expect(try connection.loadFile(at: remote) == expected)
        #expect(totals.value.last == 6)
    }

    @Test("nonatomic upload writes remote file")
    func nonatomicUploadWritesRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload-direct") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        let expected = Data((0 ..< 9).map { UInt8(42 + $0) })
        try expected.write(to: local)

        try connection.uploadFile(
            local: local,
            remote: remote,
            options: [.create, .truncate],
            maxBlockSize: 4,
            atomic: false,
        ) { _, _, _, _ in true }

        #expect(try connection.loadFile(at: remote) == expected)
    }

    @Test("empty files transfer successfully")
    func emptyFilesTransferSuccessfully() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let uploadRemote = uniquePath("empty-upload") + ".bin"
        let downloadRemote = uniquePath("empty-download") + ".bin"
        defer {
            try? connection.removeFile(at: uploadRemote)
            try? connection.removeFile(at: downloadRemote)
        }

        let uploadLocal = try localTemporaryFileURL()
        let downloadLocal = try localTemporaryFileURL()
        try? FileManager.default.removeItem(at: downloadLocal)
        defer {
            try? FileManager.default.removeItem(at: uploadLocal)
            try? FileManager.default.removeItem(at: downloadLocal)
        }

        let uploadProgress = SendableBox<[UInt64]>([])
        try connection
            .uploadFile(
                local: uploadLocal,
                remote: uploadRemote,
                maxBlockSize: 4,
            ) { transferred, total, latestSpeed, _ in
                uploadProgress.value.append(transferred)
                #expect(total == 0)
                #expect(latestSpeed == 0)
                return true
            }
        #expect(try connection.stat(at: uploadRemote).size == 0)
        #expect(uploadProgress.value == [0])

        try connection.dumpToFile(Data(), to: downloadRemote)
        let downloadProgress = SendableBox<[UInt64]>([])
        try connection
            .downloadFile(
                remote: downloadRemote,
                local: downloadLocal,
                maxBlockSize: 4,
            ) { transferred, total, latestSpeed, _ in
                downloadProgress.value.append(transferred)
                #expect(total == 0)
                #expect(latestSpeed == 0)
                return true
            }
        #expect(try Data(contentsOf: downloadLocal).isEmpty)
        #expect(downloadProgress.value == [0])
    }

    @Test("download cancellation does not throw")
    func downloadCancellationDoesNotThrow() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("download-cancel") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        try? FileManager.default.removeItem(at: local)
        defer { try? FileManager.default.removeItem(at: local) }

        try connection.dumpToFile(Data((0 ..< 12).map { UInt8($0) }), to: remote)

        try connection.downloadFile(remote: remote, local: local, maxBlockSize: 4) { transferred, _, _, _ in
            transferred < 4
        }

        #expect(!FileManager.default.fileExists(atPath: local.path))
    }

    @Test("upload cancellation does not throw")
    func uploadCancellationDoesNotThrow() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload-cancel") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        try Data((0 ..< 12).map { UInt8($0) }).write(to: local)

        try connection.uploadFile(local: local, remote: remote, maxBlockSize: 4) { transferred, _, _, _ in
            transferred < 4
        }

        #expect(throws: (any Error).self) {
            try connection.stat(at: remote)
        }
    }

    @Test("download offset requires local prefix")
    func downloadOffsetRequiresLocalPrefix() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("download-short-prefix") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        try connection.dumpToFile(Data((0 ..< 8).map { UInt8($0) }), to: remote)
        try Data([0xAA, 0xBB]).write(to: local)

        #expect(throws: (any Error).self) {
            try connection
                .downloadFile(remote: remote, local: local, from: .offset(byte: 4), maxBlockSize: 4) { _, _, _, _ in
                    true
                }
        }
    }

    @Test("upload offset requires remote prefix")
    func uploadOffsetRequiresRemotePrefix() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload-short-prefix") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        try Data((0 ..< 8).map { UInt8($0) }).write(to: local)
        try connection.dumpToFile(Data([0xAA, 0xBB]), to: remote)

        #expect(throws: (any Error).self) {
            try connection
                .uploadFile(local: local, remote: remote, from: .offset(byte: 4), maxBlockSize: 4) { _, _, _, _ in
                    true
                }
        }
    }

    @Test("upload 100MB file")
    func upload100MBFile() throws {
        let connection = try SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: SMB.Configuration(),
        )
        defer { try? connection.disconnect() }

        let remote = uniquePath("upload-100mb") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: local) }

        let chunk = Data((0 ..< 1024).map { UInt8($0 % 256) })
        let handle = try FileHandle(forWritingTo: local)
        for _ in 0 ..< (100 * 1024) {
            handle.write(chunk)
        }
        try handle.close()

        let progress = SendableBox<[UInt64]>([])
        try connection.uploadFile(local: local, remote: remote) { transferred, total, _, _ in
            progress.value.append(transferred)
            #expect(total == 100 * 1024 * 1024)
            return true
        }

        let remoteStat = try connection.stat(at: remote)
        #expect(remoteStat.size == 100 * 1024 * 1024)
        #expect(progress.value.last == 100 * 1024 * 1024)

        let file = try connection.openFile(at: remote, accessMode: .readOnly)
        defer { try? file.close() }
        let firstChunk = try file.read(upToByteCount: 1024)
        let lastChunk = try file.read(upToByteCount: 1024, atOffset: UInt64(100 * 1024 * 1024 - 1024))
        #expect(firstChunk == chunk)
        #expect(lastChunk == chunk)
    }

    @Test("download 100MB file")
    func download100MBFile() throws {
        let connection = try SMB.connect(
            server: SMB.Server(host: testServerHost),
            share: TestShare.public,
            configuration: SMB.Configuration(),
        )
        defer { try? connection.disconnect() }

        let remote = uniquePath("download-100mb") + ".bin"
        defer { try? connection.removeFile(at: remote) }

        let local = try localTemporaryFileURL()
        try? FileManager.default.removeItem(at: local)
        defer { try? FileManager.default.removeItem(at: local) }

        let data = Data(repeating: 0xCD, count: 100 * 1024 * 1024)
        try connection.dumpToFile(data, to: remote)

        let progress = SendableBox<[UInt64]>([])
        try connection.downloadFile(remote: remote, local: local) { transferred, total, _, _ in
            progress.value.append(transferred)
            #expect(total == 100 * 1024 * 1024)
            return true
        }

        let localSize = try (FileManager.default.attributesOfItem(atPath: local.path)[.size] as? NSNumber)?.uint64Value
        #expect(localSize == 100 * 1024 * 1024)
        #expect(progress.value.last == 100 * 1024 * 1024)

        let handle = try FileHandle(forReadingFrom: local)
        defer { try? handle.close() }
        let firstChunk = handle.readData(ofLength: 1024)
        handle.seek(toFileOffset: UInt64(100 * 1024 * 1024 - 1024))
        let lastChunk = handle.readData(ofLength: 1024)
        #expect(firstChunk == Data(repeating: 0xCD, count: 1024))
        #expect(lastChunk == Data(repeating: 0xCD, count: 1024))
    }
}

private func publicConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
        configuration: SMB.Configuration(transferBlockSize: 4),
    )
}

private func localTemporaryFileURL() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    FileManager.default.createFile(atPath: url.path, contents: nil)
    return url
}
