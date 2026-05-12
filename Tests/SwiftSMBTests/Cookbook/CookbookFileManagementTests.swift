//
// Part of SwiftSMB
// CookbookFileManagementTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookFileManagementTests {
    @Test("makeDirectory with makePath compiles and runs")
    func makeDirectoryWithMakePath() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let root = uniquePath("cookbook-makepath")
        defer { try? connection.removeItem(at: root) }
        try connection.makeDirectory(at: root + "/one/two", makePath: true)
        try connection.makeDirectory(at: uniquePath("cookbook-backups"))
    }

    @Test("removeItem compiles and runs")
    func removeItem() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let file = uniquePath("cookbook-remove-file") + ".pdf"
        let dir = uniquePath("cookbook-remove-dir")
        defer {
            try? connection.removeItem(at: dir)
        }
        try connection.dumpToFile(Data("x".utf8), to: file)
        try connection.removeItem(at: file)
        try connection.makeDirectory(at: dir + "/sub", makePath: true)
        try connection.removeItem(at: dir)
    }

    @Test("removeDirectory compiles and runs")
    func removeDirectory() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let dir = uniquePath("cookbook-rmdir")
        try connection.makeDirectory(at: dir)
        try connection.removeDirectory(at: dir)
    }

    @Test("removeFile compiles and runs")
    func removeFile() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let file = uniquePath("cookbook-rm") + ".pdf"
        try connection.dumpToFile(Data("x".utf8), to: file)
        try connection.removeFile(at: file)
    }

    @Test("move compiles and runs")
    func move() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let from = uniquePath("cookbook-move") + ".txt"
        let to = uniquePath("cookbook-moved") + ".txt"
        let folder = uniquePath("cookbook-move-folder")
        defer {
            try? connection.removeFile(at: from)
            try? connection.removeFile(at: to)
            try? connection.removeItem(at: folder)
        }
        try connection.dumpToFile(Data("x".utf8), to: from)
        try connection.move(from: from, to: to)
        try connection.makeDirectory(at: folder)
        try connection.move(from: to, to: folder + "/" + to)
    }

    @Test("itemExists compiles and runs")
    func itemExists() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let existence = try connection.itemExists(at: "report.pdf")
        switch existence {
        case .false:
            _ = "Nothing there"
        case .file:
            _ = "It's a file"
        case .directory:
            _ = "It's a directory"
        case .link:
            _ = "It's a symbolic link"
        case .other:
            _ = "It's something else"
        }
    }

    @Test("stat compiles and runs")
    func stat() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let info = try connection.stat(at: "report.pdf")
        _ = info.size
        _ = info.modificationTime
        _ = info.birthTime
        if info.type == .directory {
            _ = "It's a directory"
        }
    }

    @Test("truncateFile compiles and runs")
    func truncateFile() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let remote = uniquePath("cookbook-truncate") + ".txt"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("1234567890".utf8), to: remote)
        try connection.truncateFile(at: remote, toLength: 0)
    }

    @Test("readLink compiles and runs")
    func readLink() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let target = try connection.readLink(at: "shortcuts/projects")
        _ = target
    }

    @Test("makeLink compiles and runs")
    func makeLink() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let linkPath = uniquePath("cookbook-link")
        defer { try? connection.removeFile(at: linkPath) }
        try connection.makeLink(at: linkPath, pointingTo: "hello.txt")
        let target = try connection.readLink(at: linkPath)
        #expect(target == "hello.txt")
    }

    @Test("makeLink with nested path compiles and runs")
    func makeLinkNestedPath() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let dirPath = uniquePath("cookbook-nested-dir")
        let linkPath = "\(dirPath)/nested_link"
        defer {
            try? connection.removeFile(at: linkPath)
            try? connection.removeDirectory(at: dirPath)
        }
        try connection.makeDirectory(at: dirPath)
        try connection.makeLink(at: linkPath, pointingTo: "greeting.txt")
        let target = try connection.readLink(at: linkPath)
        #expect(target == "greeting.txt")
    }

    @Test("statFilesystem compiles and runs")
    func statFilesystem() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let fs = try connection.statFilesystem()
        let totalBytes = UInt64(fs.blockSize) * fs.blocks
        _ = totalBytes
        _ = fs.freeBytes
        _ = fs.availableBytes
        _ = fs.maximumNameLength
    }
}
