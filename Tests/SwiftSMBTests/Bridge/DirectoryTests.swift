//
// Part of SwiftSMB
// DirectoryTests.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

@testable import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct DirectoryTests {
    @Test func `open and close root directory`() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: "")
            closeDir(context: ctx, directory: dir)
        }
    }

    @Test func `root directory contains known entries`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: "")
            let names = entries.map(\.name)
            #expect(names.contains(TestContent.testdirPath))
            #expect(names.contains(TestContent.emptyDirPath))
        }
    }

    @Test func `dot and dot dot are present`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: "")
            let names = entries.map(\.name)
            #expect(names.contains("."))
            #expect(names.contains(".."))
        }
    }

    @Test func `dir contains hello file`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.testdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("hello.txt"))
        }
    }

    @Test func `dir contains subdir and links`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.testdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("subdir"))
            #expect(names.contains("link_to_file"))
            #expect(names.contains("link_to_dir"))
        }
    }

    @Test func `empty dir has only dot entries`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.emptyDirPath)
            let names = entries.map(\.name)
            #expect(names.contains("."))
            #expect(names.contains(".."))
            #expect(names.count == 2)
        }
    }

    @Test func `rewind directory reads from start`() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: TestContent.testdirPath)
            defer { closeDir(context: ctx, directory: dir) }

            let first = allEntries(context: ctx, directory: dir)
            rewindDir(context: ctx, directory: dir)
            let second = allEntries(context: ctx, directory: dir)

            #expect(first.map(\.name) == second.map(\.name))
        }
    }

    @Test func `tell dir at start is zero`() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: TestContent.testdirPath)
            defer { closeDir(context: ctx, directory: dir) }
            #expect(tellDir(context: ctx, directory: dir) == 0)
        }
    }

    @Test func `tell and seek return to same position`() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: TestContent.testdirPath)
            defer { closeDir(context: ctx, directory: dir) }

            let firstEntry = readDir(context: ctx, directory: dir)
            let posAfterFirst = tellDir(context: ctx, directory: dir)

            let secondEntry = readDir(context: ctx, directory: dir)
            let posAfterSecond = tellDir(context: ctx, directory: dir)

            #expect(firstEntry?.name != secondEntry?.name)
            #expect(posAfterFirst != posAfterSecond)

            seekDir(context: ctx, directory: dir, location: posAfterFirst)
            let reRead = readDir(context: ctx, directory: dir)
            #expect(reRead?.name == secondEntry?.name)
        }
    }

    @Test func `create and remove directory`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("dir")
            try makeDir(context: ctx, path: path)
            defer { try? removeDir(context: ctx, path: path) }

            try removeDir(context: ctx, path: path)

            #expect(throws: SMB2Error.self) {
                try fileStatistics(context: ctx, path: path)
            }
        }
    }

    @Test func `removing non existent directory throws`() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB2Error.self) {
                try removeDir(context: ctx, path: "nonexistent_\(uniquePath())")
            }
        }
    }

    @Test func `nested directory listing`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.subdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("nested.dat"))
        }
    }

    @Test func `directory entry type is directory`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: "")
            let testdir = try #require(entries.first { $0.name == TestContent.testdirPath })
            #expect(testdir.stat.type == .directory)
        }
    }

    @Test func `file entry type is file`() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.testdirPath)
            let hello = try #require(entries.first { $0.name == "hello.txt" })
            #expect(hello.stat.type == .file)
        }
    }
}
