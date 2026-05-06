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

@Suite(.tags(.integration))
struct SMBConnectionPipeTests {
    @Test("write from pipe stores remote file")
    func writeFromPipeStoresRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-write") + ".bin"
        defer { try? connection.removeFile(at: path) }

        let pipe = DataPipe(totalCapacity: 6, slotCount: 3)
        pipe.send(Data([0x01, 0x02]))
        pipe.send(Data([0x03, 0x04]))
        pipe.endOfProduction()

        var progress: [UInt64] = []
        try connection.write(fromPipe: pipe, toFile: path) { transferred, _, _ in
            progress.append(transferred)
            return true
        }

        #expect(try connection.readFile(at: path) == Data([0x01, 0x02, 0x03, 0x04]))
        #expect(progress.last == 4)
    }

    @Test("read to pipe transfers remote file")
    func readToPipeTransfersRemoteFile() throws {
        let connection = try publicConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("pipe-read") + ".bin"
        defer { try? connection.removeFile(at: path) }

        let expected = Data([0xAA, 0xBB, 0xCC, 0xDD])
        try connection.writeFile(expected, to: path)

        let pipe = DataPipe(totalCapacity: 6, slotCount: 3)
        var progress: [UInt64] = []
        try connection.read(fromFile: path, toPipe: pipe) { transferred, _, _ in
            progress.append(transferred)
            return true
        }

        var received = Data()
        while let chunk = pipe.receive() {
            received.append(chunk)
        }

        #expect(received == expected)
        #expect(progress.last == UInt64(expected.count))
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

        var progress: [UInt64] = []
        var latestSpeeds: [Double] = []
        try connection.uploadFile(local: local, remote: remote, maxBlockSize: 4) { transferred, total, latestSpeed, _ in
            progress.append(transferred)
            latestSpeeds.append(latestSpeed)
            #expect(total == UInt64(expected.count))
            return true
        }

        #expect(try connection.readFile(at: remote) == expected)
        #expect(progress.last == UInt64(expected.count))
        #expect(latestSpeeds.last == 0)
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
        try connection.writeFile(expected, to: remote)

        var progress: [UInt64] = []
        var latestSpeeds: [Double] = []
        try connection
            .downloadFile(remote: remote, local: local, maxBlockSize: 5) { transferred, total, latestSpeed, _ in
                progress.append(transferred)
                latestSpeeds.append(latestSpeed)
                #expect(total == UInt64(expected.count))
                return true
            }

        #expect(try Data(contentsOf: local) == expected)
        #expect(progress.last == UInt64(expected.count))
        #expect(latestSpeeds.last == 0)
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
        try connection.writeFile(expected, to: remote)
        try expected.prefix(4).write(to: local)

        var totals: [UInt64] = []
        try connection
            .downloadFile(
                remote: remote,
                local: local,
                from: .offset(byte: 4),
                maxBlockSize: 3,
            ) { transferred, total, _, _ in
                totals.append(total)
                #expect(transferred <= total)
                return true
            }

        #expect(try Data(contentsOf: local) == expected)
        #expect(totals.last == 6)
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
        try connection.writeFile(expected.prefix(4), to: remote)

        var totals: [UInt64] = []
        try connection
            .uploadFile(
                local: local,
                remote: remote,
                from: .offset(byte: 4),
                maxBlockSize: 3,
            ) { transferred, total, _, _ in
                totals.append(total)
                #expect(transferred <= total)
                return true
            }

        #expect(try connection.readFile(at: remote) == expected)
        #expect(totals.last == 6)
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

        #expect(try connection.readFile(at: remote) == expected)
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

        var uploadProgress: [UInt64] = []
        try connection
            .uploadFile(
                local: uploadLocal,
                remote: uploadRemote,
                maxBlockSize: 4,
            ) { transferred, total, latestSpeed, _ in
                uploadProgress.append(transferred)
                #expect(total == 0)
                #expect(latestSpeed == 0)
                return true
            }
        #expect(try connection.stat(at: uploadRemote).size == 0)
        #expect(uploadProgress == [0])

        try connection.writeFile(Data(), to: downloadRemote)
        var downloadProgress: [UInt64] = []
        try connection
            .downloadFile(
                remote: downloadRemote,
                local: downloadLocal,
                maxBlockSize: 4,
            ) { transferred, total, latestSpeed, _ in
                downloadProgress.append(transferred)
                #expect(total == 0)
                #expect(latestSpeed == 0)
                return true
            }
        #expect(try Data(contentsOf: downloadLocal).isEmpty)
        #expect(downloadProgress == [0])
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

        try connection.writeFile(Data((0 ..< 12).map { UInt8($0) }), to: remote)

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

        try connection.writeFile(Data((0 ..< 8).map { UInt8($0) }), to: remote)
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
        try connection.writeFile(Data([0xAA, 0xBB]), to: remote)

        #expect(throws: (any Error).self) {
            try connection
                .uploadFile(local: local, remote: remote, from: .offset(byte: 4), maxBlockSize: 4) { _, _, _, _ in
                    true
                }
        }
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
