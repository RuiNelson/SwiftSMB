//
// Part of SwiftSMB
// CookbookFileManagementTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookFileManagementTests {
    @Test("makeDirectory with makePath compiles and runs")
    func makeDirectoryWithMakePath() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let root = uniquePath("cookbook-makepath")
        defer { try? await connection.removeItem(at: root) }
        try await connection.makeDirectory(at: root + "/one/two", makePath: true)
        try await connection.makeDirectory(at: uniquePath("cookbook-backups"))
    }

    @Test("removeItem compiles and runs")
    func removeItem() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = uniquePath("cookbook-remove-file") + ".pdf"
        let dir = uniquePath("cookbook-remove-dir")
        defer {
            try? await connection.removeItem(at: dir)
        }
        try await connection.dumpToFile(Data("x".utf8), to: file)
        try await connection.removeItem(at: file)
        try await connection.makeDirectory(at: dir + "/sub", makePath: true)
        try await connection.removeItem(at: dir)
    }

    @Test("removeDirectory compiles and runs")
    func removeDirectory() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let dir = uniquePath("cookbook-rmdir")
        try await connection.makeDirectory(at: dir)
        try await connection.removeDirectory(at: dir)
    }

    @Test("removeFile compiles and runs")
    func removeFile() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let file = uniquePath("cookbook-rm") + ".pdf"
        try await connection.dumpToFile(Data("x".utf8), to: file)
        try await connection.removeFile(at: file)
    }

    @Test("move compiles and runs")
    func move() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let from = uniquePath("cookbook-move") + ".txt"
        let to = uniquePath("cookbook-moved") + ".txt"
        let folder = uniquePath("cookbook-move-folder")
        defer {
            try? await connection.removeFile(at: from)
            try? await connection.removeFile(at: to)
            try? await connection.removeItem(at: folder)
        }
        try await connection.dumpToFile(Data("x".utf8), to: from)
        try await connection.move(from: from, to: to)
        try await connection.makeDirectory(at: folder)
        try await connection.move(from: to, to: folder + "/" + to)
    }

    @Test("itemExists compiles and runs")
    func itemExists() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let existence = try await connection.itemExists(at: "report.pdf")
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
    func stat() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let info = try await connection.stat(at: "report.pdf")
        _ = info.size
        _ = info.modificationTime
        _ = info.birthTime
        if info.type == .directory {
            _ = "It's a directory"
        }
    }

    @Test("truncateFile compiles and runs")
    func truncateFile() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let remote = uniquePath("cookbook-truncate") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("1234567890".utf8), to: remote)
        try await connection.truncateFile(at: remote, toLength: 0)
    }

    @Test("readLink compiles and runs")
    func readLink() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let target = try await connection.readLink(at: "shortcuts/projects")
        _ = target
    }

    @Test("makeLink compiles and runs")
    func makeLink() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let linkPath = uniquePath("cookbook-link")
        defer { try? await connection.removeFile(at: linkPath) }
        try await connection.makeLink(at: linkPath, pointingTo: "hello.txt")
        let target = try await connection.readLink(at: linkPath)
        #expect(target == "hello.txt")
    }

    @Test("makeLink with nested path compiles and runs")
    func makeLinkNestedPath() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let dirPath = uniquePath("cookbook-nested-dir")
        let linkPath = "\(dirPath)/nested_link"
        defer {
            try? await connection.removeFile(at: linkPath)
            try? await connection.removeDirectory(at: dirPath)
        }
        try await connection.makeDirectory(at: dirPath)
        try await connection.makeLink(at: linkPath, pointingTo: "greeting.txt")
        let target = try await connection.readLink(at: linkPath)
        #expect(target == "greeting.txt")
    }

    @Test("makeHardLink compiles and runs")
    func makeHardLink() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let targetPath = uniquePath("cookbook-hardlink-target")
        let linkPath = uniquePath("cookbook-hardlink")
        defer {
            try? await connection.removeFile(at: linkPath)
            try? await connection.removeFile(at: targetPath)
        }

        try await connection.dumpToFile(Data("hard link content".utf8), to: targetPath)
        try await connection.makeHardLink(at: linkPath, pointingTo: targetPath)

        let targetStat = try await connection.stat(at: targetPath)
        let linkStat = try await connection.stat(at: linkPath)
        #expect(targetStat.inode == linkStat.inode)
        #expect(targetStat.linkCount >= 2)
        #expect(linkStat.linkCount >= 2)
    }

    @Test("statFilesystem compiles and runs")
    func statFilesystem() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let fs = try await connection.statFilesystem()
        let totalBytes = UInt64(fs.blockSize) * fs.blocks
        _ = totalBytes
        _ = fs.freeBytes
        _ = fs.availableBytes
        _ = fs.maximumNameLength
    }
}
