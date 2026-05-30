//
// Part of SwiftSMB
// SMBConnectionFileTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionFileTests {
    @Test("copyFile copies known file") func copyFileCopiesKnownFile() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let destPath = uniquePath("copy") + ".txt"
        defer { try? connection.removeFile(at: destPath) }

        try connection.copyFile(from: TestContent.helloPath, to: destPath)

        let data = try connection.loadFile(at: destPath)
        #expect(Array(data) == TestContent.helloBytes)
    }

    @Test("copyFile throws when destination exists") func copyFileThrowsWhenDestinationExists() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let destPath = uniquePath("copy") + ".txt"
        defer { try? connection.removeFile(at: destPath) }

        try connection.dumpToFile(Data("WRONG CONTENT".utf8), to: destPath)

        #expect(throws: SMB.Error.self) {
            try connection.copyFile(from: TestContent.helloPath, to: destPath)
        }
    }

    @Test("copyFile copies empty file") func copyFileCopiesEmptyFile() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let sourcePath = uniquePath("empty_source") + ".txt"
        let destPath = uniquePath("empty_dest") + ".txt"
        defer {
            try? connection.removeFile(at: sourcePath)
            try? connection.removeFile(at: destPath)
        }

        try connection.dumpToFile(Data(), to: sourcePath)

        try connection.copyFile(from: sourcePath, to: destPath)

        let stat = try connection.stat(at: destPath)
        #expect(stat.type == .file)
        #expect(stat.size == 0)
    }

    @Test("copyFile throws for nonexistent source") func copyFileThrowsForNonexistentSource() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let destPath = uniquePath("copy") + ".txt"
        defer { try? connection.removeFile(at: destPath) }

        #expect(throws: SMB.Error.self) {
            try connection.copyFile(from: "nonexistent_\(uniquePath()).txt", to: destPath)
        }
    }

    @Test("changeDate preserves file attributes") func changeDatePreservesFileAttributes() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("dates") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("visible file".utf8), to: path)
        let before = try connection.attributes(at: path)

        try connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let after = try connection.attributes(at: path)
        #expect(after == before)
        #expect(!after.contains(.hidden))
        #expect(!after.contains(.system))
        #expect(!after.contains(.temporary))
        #expect(!after.contains(.offline))
    }

    @Test("changeDate with all timestamps preserves file attributes")
    func changeDateAllTimestampsPreserveAttributes() throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("dates_all") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("all timestamps".utf8), to: path)
        let before = try connection.attributes(at: path)

        let epoch = Date(timeIntervalSince1970: 1_704_067_200)
        try connection.changeDate(
            at: path,
            creation: epoch,
            change: epoch.addingTimeInterval(60),
            write: epoch.addingTimeInterval(120),
            access: epoch.addingTimeInterval(180),
        )

        let after = try connection.attributes(at: path)
        #expect(after == before)
        #expect(!after.contains(.hidden))
        #expect(!after.contains(.system))
        #expect(!after.contains(.offline))
    }

    @Test("changeDate on authenticated share preserves attributes")
    func changeDateAuthenticatedPreservesAttributes() throws {
        let connection = try SMB.connect(
            server: SMB.Server(host: testServerHost),
            credentials: .init(user: TestCredentials.user, password: TestCredentials.password),
            share: TestShare.private,
        )
        defer { try? connection.disconnect() }

        let path = uniquePath("auth_dates") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("authenticated file".utf8), to: path)
        let before = try connection.attributes(at: path)

        try connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let after = try connection.attributes(at: path)
        #expect(after == before)
        #expect(!after.contains(SMB.FileAttributes.hidden))
        #expect(!after.contains(SMB.FileAttributes.system))
    }

    @Test("changeDate preserves archive attribute") func changeDatePreservesArchiveAttribute()
    throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("archive") + ".txt"
        defer { try? connection.removeFile(at: path) }

        try connection.dumpToFile(Data("archive test".utf8), to: path)
        let before = try connection.attributes(at: path)

        // Newly created files typically have the archive bit set
        try connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let after = try connection.attributes(at: path)
        #expect(after.contains(.archive) == before.contains(.archive))
        #expect(after == before)
    }

    @Test("file remains readable after changeDate") func fileRemainsReadableAfterChangeDate()
    throws {
        let connection = try publicFileConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("readback") + ".txt"
        defer { try? connection.removeFile(at: path) }

        let content = Data("still readable after date change".utf8)
        try connection.dumpToFile(content, to: path)

        try connection.changeDate(at: path, creation: Date(timeIntervalSince1970: 1_704_067_200))

        let readBack = try connection.loadFile(at: path)
        #expect(readBack == content)

        let stat = try connection.stat(at: path)
        #expect(stat.type == .file)
        #expect(stat.size == content.count)
    }
}

private func publicFileConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}
