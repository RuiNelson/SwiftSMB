//
// Part of SwiftSMB
// CookbookFilePropertiesTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookFilePropertiesTests {
    @Test("attributes compiles and runs")
    func attributes() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let attrs = try await connection.attributes(at: "report.pdf")
        if attrs.contains(.hidden) {
            _ = "File is hidden"
        }
        if attrs.contains(.readOnly) {
            _ = "File is read-only"
        }
        if attrs.contains(.archive) {
            _ = "Archive bit is set"
        }
    }

    @Test("changeAttributes compiles and runs")
    func changeAttributes() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-attrs") + ".pdf"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("x".utf8), to: remote)
        try await connection.changeAttributes(at: remote) { attrs in
            attrs.union([.hidden, .readOnly])
        }
        try await connection.changeAttributes(at: remote) { attrs in
            attrs.subtracting(.hidden)
        }
        try await connection.changeAttributes(at: remote) { attrs in
            attrs.symmetricDifference(.archive)
        }
    }

    @Test("changeDate compiles and runs")
    func changeDate() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-dates") + ".pdf"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("x".utf8), to: remote)
        let now = Date()
        try await connection.changeDate(at: remote, write: now)
        try await connection.changeDate(
            at: remote,
            creation: now,
            access: now
        )
        try await connection.changeDate(
            at: remote,
            creation: now,
            change: now,
            write: now,
            access: now
        )
        try await connection.changeDate(
            at: remote,
            creation: now,
            change: now,
            write: now,
            access: now
        )
    }

    @Test("read timestamps via stat compiles and runs")
    func readTimestampsViaStat() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let info = try await connection.stat(at: "report.pdf")
        _ = info.birthTime
        _ = info.modificationTime
        _ = info.accessTime
        _ = info.changeTime
    }

    @Test("statFilesystem properties compiles and runs")
    func statFilesystemProperties() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let fs = try await connection.statFilesystem()
        _ = UInt64(fs.blockSize) * fs.blocks
        _ = fs.freeBytes
        _ = fs.availableBytes
        _ = fs.maximumNameLength
    }

    @Test("truncateFile by path compiles and runs")
    func truncateFileByPath() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-truncate-prop") + ".log"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("app log".utf8), to: remote)
        try await connection.truncateFile(at: remote, toLength: 0)
        try await connection.truncateFile(at: remote, toLength: 1024)
    }

    @Test("truncate via handle compiles and runs")
    func truncateViaHandle() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-truncate-handle") + ".bin"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("1234567890".utf8), to: remote)
        let file = try await connection.openFile(at: remote, accessMode: .readWrite)
        defer { try? await file.close() }
        try await file.truncate(toLength: 1024)
    }
}
