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
}

private func publicFileConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}
