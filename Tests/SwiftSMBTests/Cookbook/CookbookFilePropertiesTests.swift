//
// Part of SwiftSMB
// CookbookFilePropertiesTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.serialized, .tags(.integration))
struct CookbookFilePropertiesTests {
    @Test("attributes compiles and runs")
    func attributes() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let attrs = try connection.attributes(at: "report.pdf")
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
    func changeAttributes() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-attrs") + ".pdf"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("x".utf8), to: remote)
        try connection.changeAttributes(at: remote) { attrs in
            attrs.union([.hidden, .readOnly])
        }
        try connection.changeAttributes(at: remote) { attrs in
            attrs.subtracting(.hidden)
        }
        try connection.changeAttributes(at: remote) { attrs in
            attrs.symmetricDifference(.archive)
        }
    }

    @Test("changeDate compiles and runs")
    func changeDate() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-dates") + ".pdf"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("x".utf8), to: remote)
        let now = Date()
        try connection.changeDate(at: remote, write: now)
        try connection.changeDate(
            at: remote,
            creation: now,
            access: now,
        )
        try connection.changeDate(
            at: remote,
            creation: now,
            change: now,
            write: now,
            access: now,
        )
        try? connection.changeDate(
            at: remote,
            creation: now,
            change: now,
            write: now,
            access: now,
        )
    }

    @Test("read timestamps via stat compiles and runs")
    func readTimestampsViaStat() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let info = try connection.stat(at: "report.pdf")
        _ = info.birthTime
        _ = info.modificationTime
        _ = info.accessTime
        _ = info.changeTime
    }

    @Test("statFilesystem properties compiles and runs")
    func statFilesystemProperties() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let fs = try connection.statFilesystem()
        _ = UInt64(fs.blockSize) * fs.blocks
        _ = fs.freeBytes
        _ = fs.availableBytes
        _ = fs.maximumNameLength
    }

    @Test("truncateFile by path compiles and runs")
    func truncateFileByPath() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-truncate-prop") + ".log"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("app log".utf8), to: remote)
        try connection.truncateFile(at: remote, toLength: 0)
        try connection.truncateFile(at: remote, toLength: 1024)
    }

    @Test("truncate via handle compiles and runs")
    func truncateViaHandle() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-truncate-handle") + ".bin"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("1234567890".utf8), to: remote)
        let file = try connection.openFile(at: remote, accessMode: .readWrite)
        defer { try? file.close() }
        try file.truncate(toLength: 1024)
    }
}
