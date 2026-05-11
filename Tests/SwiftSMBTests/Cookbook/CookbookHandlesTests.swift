//
// Part of SwiftSMB
// CookbookHandlesTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookHandlesTests {
    @Test("openFile and read compiles and runs")
    func openFileAndRead() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let file = try connection.openFile(at: "report.pdf")
        defer { try? file.close() }
        let data = try file.read()
        _ = data.count
    }

    @Test("openFile with access mode and options compiles and runs")
    func openFileWithAccessModeAndOptions() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-log") + ".txt"
        defer { try? connection.removeFile(at: remote) }
        let file = try connection.openFile(
            at: remote,
            accessMode: .readWrite,
            options: [.create, .append],
        )
        do { try? file.close() }
    }

    @Test("read upTo compiles and runs")
    func readUpTo() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let file = try connection.openFile(at: "report.pdf")
        defer { try? file.close() }
        let chunk = try file.read(upTo: 65536)
        _ = chunk.count
    }

    @Test("seek and read at offset compiles and runs")
    func seekAndReadAtOffset() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let file = try connection.openFile(at: "report.pdf")
        defer { try? file.close() }
        let info = try file.stat()
        try file.seek(offset: 0, from: .start)
        let header = try file.read(upTo: 1024)
        _ = header.count
        try file.seek(offset: Int64(info.size - 1024), from: .start)
        let footer = try file.read(upTo: 1024)
        _ = footer.count
    }

    @Test("write and seek compiles and runs")
    func writeAndSeek() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-output") + ".bin"
        defer { try? connection.removeFile(at: remote) }
        let file = try connection.openFile(
            at: remote,
            accessMode: .writeOnly,
            options: [.create, .truncate],
        )
        defer { try? file.close() }
        try file.write(Data("Hello, World!".utf8))
        try file.seek(offset: 4096, from: .start)
        try file.write(Data("at offset".utf8))
    }

    @Test("seek origins compiles and runs")
    func seekOrigins() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-seek") + ".bin"
        defer { try? connection.removeFile(at: remote) }
        let file = try connection.openFile(
            at: remote,
            accessMode: .readWrite,
            options: [.create, .truncate],
        )
        defer { try? file.close() }
        try file.write(Data("0123456789".utf8))
        try file.seek(offset: 0, from: .start)
        try file.seek(offset: 1024, from: .current)
        try file.seek(offset: 0, from: .end)
    }

    @Test("truncate handle compiles and runs")
    func truncateHandle() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-truncate") + ".bin"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("1234567890".utf8), to: remote)
        let file = try connection.openFile(at: remote, accessMode: .readWrite)
        defer { try? file.close() }
        try file.truncate(toLength: 1024)
    }

    @Test("sync handle compiles and runs")
    func syncHandle() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-sync") + ".bin"
        defer { try? connection.removeFile(at: remote) }
        let file = try connection.openFile(
            at: remote,
            accessMode: .writeOnly,
            options: [.create, .truncate],
        )
        defer { try? file.close() }
        try file.write(Data("sync me".utf8))
        try file.sync()
    }

    @Test("openDirectory and readNext compiles and runs")
    func openDirectoryAndReadNext() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let directory = try connection.openDirectory(at: "Anna/Inbox")
        defer { directory.close() }
        while let entry = try directory.readNext() {
            _ = entry.name
            _ = entry.stat.size
        }
    }

    @Test("openDirectory and readAll compiles and runs")
    func openDirectoryAndReadAll() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let directory = try connection.openDirectory(at: "Anna/Inbox")
        defer { directory.close() }
        let entries = try directory.readAll()
        for entry in entries {
            _ = entry.name
        }
    }

    @Test("directory tell and seek compiles and runs")
    func directoryTellAndSeek() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let directory = try connection.openDirectory(at: "Anna/Inbox")
        defer { directory.close() }
        let mark = try directory.tell()
        _ = try directory.readNext()
        _ = try directory.readNext()
        try directory.seek(to: mark)
    }

    @Test("directory rewind compiles and runs")
    func directoryRewind() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let directory = try connection.openDirectory(at: "Anna/Inbox")
        defer { directory.close() }
        try directory.rewind()
    }

    @Test("close handles compiles and runs")
    func closeHandles() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let file = try connection.openFile(at: "report.pdf")
        try file.close()
        let directory = try connection.openDirectory(at: "Anna/Inbox")
        directory.close()
    }
}
