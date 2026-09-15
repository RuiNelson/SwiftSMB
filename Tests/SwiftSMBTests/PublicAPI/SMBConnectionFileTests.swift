//
// Part of SwiftSMB
// SMBConnectionFileTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionFileTests {
    @Test("copyFile copies known file") func copyFileCopiesKnownFile() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        try await connection.copyFile(from: TestContent.helloPath, to: destPath)

        let data = try await connection.loadFile(at: destPath)
        #expect(Array(data) == TestContent.helloBytes)
    }

    @Test("write accepts a Data slice with non-zero start index") func writeAcceptsDataSlice() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("slice") + ".bin"
        defer { try? await connection.removeFile(at: path) }

        let full = Data("prefix-payload".utf8)
        let slice = full[full.index(full.startIndex, offsetBy: 7)...]
        #expect(slice.startIndex != 0)

        let file = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.create, .truncate])
        // Chunk size 3 forces multiple write iterations over the slice.
        try await file.write(slice, transferChunkSize: 3)
        try await file.close()

        await #expect(try connection.loadFile(at: path) == Data("payload".utf8))
    }

    @Test("write rejects a non-positive chunk size") func writeRejectsNonPositiveChunkSize() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("badchunk") + ".bin"
        defer { try? await connection.removeFile(at: path) }

        let file = try await connection.openFile(at: path, accessMode: .writeOnly, options: [.create, .truncate])
        defer { try? await file.close() }

        await #expect(throws: SMB.Error.self) {
            try await file.write(Data("x".utf8), transferChunkSize: 0)
        }
        await #expect(throws: SMB.Error.self) {
            try await file.write(Data("x".utf8), transferChunkSize: -1)
        }
    }

    @Test("copyFile throws when destination exists") func copyFileThrowsWhenDestinationExists() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        try await connection.dumpToFile(Data("WRONG CONTENT".utf8), to: destPath)

        await #expect(throws: SMB.Error.self) {
            try await connection.copyFile(from: TestContent.helloPath, to: destPath)
        }
    }

    @Test("copyFile copies empty file") func copyFileCopiesEmptyFile() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("empty_source") + ".txt"
        let destPath = uniquePath("empty_dest") + ".txt"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }

        try await connection.dumpToFile(Data(), to: sourcePath)

        try await connection.copyFile(from: sourcePath, to: destPath)

        let stat = try await connection.stat(at: destPath)
        #expect(stat.type == .file)
        #expect(stat.size == 0)
    }

    @Test("copyFile copies file larger than the server chunk limit") func copyFileCopiesLargeFile() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let sourcePath = uniquePath("copy_large_src") + ".bin"
        let destPath = uniquePath("copy_large_dst") + ".bin"
        defer {
            try? await connection.removeFile(at: sourcePath)
            try? await connection.removeFile(at: destPath)
        }

        // Samba caps COPYCHUNK at 1 MiB per chunk, so this size forces the limit renegotiation path and an uneven final
        // chunk.
        var content = Data(count: 3 * 1024 * 1024 + 12345)
        for index in stride(from: 0, to: content.count, by: 4096) {
            content[index] = UInt8(truncatingIfNeeded: index >> 12)
        }
        try await connection.dumpToFile(content, to: sourcePath)

        try await connection.copyFile(from: sourcePath, to: destPath)

        await #expect(try connection.loadFile(at: destPath) == content)
    }

    @Test("copyFile throws for nonexistent source") func copyFileThrowsForNonexistentSource() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let destPath = uniquePath("copy") + ".txt"
        defer { try? await connection.removeFile(at: destPath) }

        await #expect(throws: SMB.Error.self) {
            try await connection.copyFile(from: "nonexistent_\(uniquePath()).txt", to: destPath)
        }
    }

    @Test("changeDate preserves file attributes") func changeDatePreservesFileAttributes() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("dates") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("visible file".utf8), to: path)
        let before = try await connection.attributes(at: path)

        try await connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let after = try await connection.attributes(at: path)
        #expect(after == before)
        #expect(!after.contains(.hidden))
        #expect(!after.contains(.system))
        #expect(!after.contains(.temporary))
        #expect(!after.contains(.offline))
    }

    @Test("changeDate with all timestamps preserves file attributes")
    func changeDateAllTimestampsPreserveAttributes() async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("dates_all") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("all timestamps".utf8), to: path)
        let before = try await connection.attributes(at: path)

        let epoch = Date(timeIntervalSince1970: 1_704_067_200)
        try await connection.changeDate(
            at: path,
            creation: epoch,
            change: epoch.addingTimeInterval(60),
            write: epoch.addingTimeInterval(120),
            access: epoch.addingTimeInterval(180)
        )

        let after = try await connection.attributes(at: path)
        #expect(after == before)
        #expect(!after.contains(.hidden))
        #expect(!after.contains(.system))
        #expect(!after.contains(.offline))
    }

    @Test("changeDate on authenticated share preserves attributes")
    func changeDateAuthenticatedPreservesAttributes() async throws {
        let connection = try await SMB.connect(
            server: SMB.Server(host: testServerHost),
            credentials: .init(user: TestCredentials.user, password: TestCredentials.password),
            share: TestShare.private
        )
        defer { try? await connection.disconnect() }

        let path = uniquePath("auth_dates") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("authenticated file".utf8), to: path)
        let before = try await connection.attributes(at: path)

        try await connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let after = try await connection.attributes(at: path)
        #expect(after == before)
        #expect(!after.contains(SMB.FileAttributes.hidden))
        #expect(!after.contains(SMB.FileAttributes.system))
    }

    @Test("changeDate preserves archive attribute") func changeDatePreservesArchiveAttribute()
    async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("archive") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        try await connection.dumpToFile(Data("archive test".utf8), to: path)
        let before = try await connection.attributes(at: path)

        // Newly created files typically have the archive bit set
        try await connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let after = try await connection.attributes(at: path)
        #expect(after.contains(.archive) == before.contains(.archive))
        #expect(after == before)
    }

    @Test("file remains readable after changeDate") func fileRemainsReadableAfterChangeDate()
    async throws {
        let connection = try await publicFileConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("readback") + ".txt"
        defer { try? await connection.removeFile(at: path) }

        let content = Data("still readable after date change".utf8)
        try await connection.dumpToFile(content, to: path)

        try await connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let readBack = try await connection.loadFile(at: path)
        #expect(readBack == content)

        let stat = try await connection.stat(at: path)
        #expect(stat.type == .file)
        #expect(stat.size == content.count)
    }
}

private func publicFileConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
