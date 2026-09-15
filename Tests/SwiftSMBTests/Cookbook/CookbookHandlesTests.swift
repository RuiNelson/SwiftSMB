//
// Part of SwiftSMB
// CookbookHandlesTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookHandlesTests {
    @Test("negotiated dialect compiles and runs")
    func negotiatedDialect() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let rawDialect = try await connection.negotiatedDialect
        _ = rawDialect

        switch try await connection.negotiatedDialectKind {
        case .smb3_11:
            break
        case let .unknown(rawValue):
            _ = rawValue
        default:
            break
        }
    }

    @Test("openFile and read compiles and runs")
    func openFileAndRead() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = try await connection.openFile(at: "report.pdf")
        defer { try? await file.close() }
        let data = try await file.read()
        _ = data.count
    }

    @Test("openFile with access mode and options compiles and runs")
    func openFileWithAccessModeAndOptions() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-log") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        let file = try await connection.openFile(
            at: remote,
            accessMode: .readWrite,
            options: [.create, .append]
        )
        do { try? await file.close() }
    }

    @Test("read upTo compiles and runs")
    func readUpTo() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = try await connection.openFile(at: "report.pdf")
        defer { try? await file.close() }
        let chunk = try await file.read(upTo: 65536)
        _ = chunk.count
    }

    @Test("seek and read at offset compiles and runs")
    func seekAndReadAtOffset() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = try await connection.openFile(at: "report.pdf")
        defer { try? await file.close() }
        let info = try await file.stat()
        try await file.seek(offset: 0, from: .start)
        let header = try await file.read(upTo: 1024)
        _ = header.count
        try await file.seek(offset: Int64(info.size - 1024), from: .start)
        let footer = try await file.read(upTo: 1024)
        _ = footer.count
    }

    @Test("write and seek compiles and runs")
    func writeAndSeek() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-output") + ".bin"
        defer { try? await connection.removeFile(at: remote) }
        let file = try await connection.openFile(
            at: remote,
            accessMode: .writeOnly,
            options: [.create, .truncate]
        )
        defer { try? await file.close() }
        try await file.write(Data("Hello, World!".utf8))
        try await file.seek(offset: 4096, from: .start)
        try await file.write(Data("at offset".utf8))
    }

    @Test("seek origins compiles and runs")
    func seekOrigins() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-seek") + ".bin"
        defer { try? await connection.removeFile(at: remote) }
        let file = try await connection.openFile(
            at: remote,
            accessMode: .readWrite,
            options: [.create, .truncate]
        )
        defer { try? await file.close() }
        try await file.write(Data("0123456789".utf8))
        try await file.seek(offset: 0, from: .start)
        try await file.seek(offset: 1024, from: .current)
        try await file.seek(offset: 0, from: .end)
    }

    @Test("truncate handle compiles and runs")
    func truncateHandle() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-truncate") + ".bin"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("1234567890".utf8), to: remote)
        let file = try await connection.openFile(at: remote, accessMode: .readWrite)
        defer { try? await file.close() }
        try await file.truncate(toLength: 1024)
    }

    @Test("sync handle compiles and runs")
    func syncHandle() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-sync") + ".bin"
        defer { try? await connection.removeFile(at: remote) }
        let file = try await connection.openFile(
            at: remote,
            accessMode: .writeOnly,
            options: [.create, .truncate]
        )
        defer { try? await file.close() }
        try await file.write(Data("sync me".utf8))
        try await file.sync()
    }

    @Test("openDirectory and readNext compiles and runs")
    func openDirectoryAndReadNext() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let directory = try await connection.openDirectory(at: "Anna/Inbox")
        defer { await directory.close() }
        while let entry = try await directory.readNext() {
            _ = entry.name
            _ = entry.stat.size
        }
    }

    @Test("openDirectory and readAll compiles and runs")
    func openDirectoryAndReadAll() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let directory = try await connection.openDirectory(at: "Anna/Inbox")
        defer { await directory.close() }
        let entries = try await directory.readAll()
        for entry in entries {
            _ = entry.name
        }
    }

    @Test("directory tell and seek compiles and runs")
    func directoryTellAndSeek() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let directory = try await connection.openDirectory(at: "Anna/Inbox")
        defer { await directory.close() }
        let mark = try await directory.tell()
        _ = try await directory.readNext()
        _ = try await directory.readNext()
        try await directory.seek(to: mark)
    }

    @Test("directory rewind compiles and runs")
    func directoryRewind() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let directory = try await connection.openDirectory(at: "Anna/Inbox")
        defer { await directory.close() }
        try await directory.rewind()
    }

    @Test("close handles compiles and runs")
    func closeHandles() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = try await connection.openFile(at: "report.pdf")
        try await file.close()
        let directory = try await connection.openDirectory(at: "Anna/Inbox")
        await directory.close()
    }

    @Test("lock exclusive compiles and runs")
    func lockExclusive() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-lock") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("lock test".utf8), to: remote)
        let file = try await connection.openFile(
            at: remote,
            accessMode: .readWrite
        )
        defer { try? await file.close() }
        try await file.lock(.exclusive, nonBlocking: false)
        try await file.unlock()
    }

    @Test("lock shared compiles and runs")
    func lockShared() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = try await connection.openFile(at: "report.pdf")
        defer { try? await file.close() }
        try await file.lock(.shared, nonBlocking: false)
        let data = try await file.read()
        _ = data.count
        try await file.unlock()
    }

    @Test("lock nonBlocking compiles and runs")
    func lockNonBlocking() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-lock-nb") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("lock test".utf8), to: remote)
        let file = try await connection.openFile(
            at: remote,
            accessMode: .readWrite
        )
        defer { try? await file.close() }
        try await file.lock(.exclusive, nonBlocking: true)
        try await file.unlock()
    }

    @Test("lock with range compiles and runs")
    func lockWithRange() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-lock-range") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("lock test".utf8), to: remote)
        let file = try await connection.openFile(
            at: remote,
            accessMode: .readWrite
        )
        defer { try? await file.close() }
        try await file.lock(.exclusive, nonBlocking: false, range: 1024 ..< 2048)
        try await file.unlock(range: 1024 ..< 2048)
    }
}
