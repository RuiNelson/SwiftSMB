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
    @Test("open and close root directory") func openAndCloseRootDirectory() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: "")
            closeDir(context: ctx, directory: dir)
        }
    }

    @Test("root directory contains known entries") func rootDirectoryContainsKnownEntries() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: "")
            let names = entries.map(\.name)
            #expect(names.contains(TestContent.testdirPath))
            #expect(names.contains(TestContent.emptyDirPath))
        }
    }

    @Test("dot and dot dot are present") func dotAndDotDotArePresent() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: "")
            let names = entries.map(\.name)
            #expect(names.contains("."))
            #expect(names.contains(".."))
        }
    }

    @Test("dir contains hello file") func dirContainsHelloFile() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.testdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("hello.txt"))
        }
    }

    @Test("dir contains subdir and links") func dirContainsSubdirAndLinks() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.testdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("subdir"))
            #expect(names.contains("link_to_file"))
            #expect(names.contains("link_to_dir"))
        }
    }

    @Test("empty dir has only dot entries") func emptyDirHasOnlyDotEntries() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.emptyDirPath)
            let names = entries.map(\.name)
            #expect(names.contains("."))
            #expect(names.contains(".."))
            #expect(names.count == 2)
        }
    }

    @Test("rewind directory reads from start") func rewindDirectoryReadsFromStart() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: TestContent.testdirPath)
            defer { closeDir(context: ctx, directory: dir) }

            let first = allEntries(context: ctx, directory: dir)
            rewindDir(context: ctx, directory: dir)
            let second = allEntries(context: ctx, directory: dir)

            #expect(first.map(\.name) == second.map(\.name))
        }
    }

    @Test("tell dir at start is zero") func tellDirAtStartIsZero() throws {
        try withPublicShare { ctx in
            let dir = try openDir(context: ctx, path: TestContent.testdirPath)
            defer { closeDir(context: ctx, directory: dir) }
            #expect(tellDir(context: ctx, directory: dir) == 0)
        }
    }

    @Test("tell and seek return to same position") func tellAndSeekReturnToSamePosition() throws {
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

    @Test("create and remove directory") func createAndRemoveDirectory() throws {
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

    @Test("removing non existent directory throws") func removingNonExistentDirectoryThrows() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB2Error.self) {
                try removeDir(context: ctx, path: "nonexistent_\(uniquePath())")
            }
        }
    }

    @Test("nested directory listing") func nestedDirectoryListing() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.subdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("nested.dat"))
        }
    }

    @Test("directory entry type is directory") func directoryEntryTypeIsDirectory() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: "")
            let testdir = try #require(entries.first { $0.name == TestContent.testdirPath })
            #expect(testdir.stat.type == .directory)
        }
    }

    @Test("file entry type is file") func fileEntryTypeIsFile() throws {
        try withPublicShare { ctx in
            let entries = try listDirectory(context: ctx, path: TestContent.testdirPath)
            let hello = try #require(entries.first { $0.name == "hello.txt" })
            #expect(hello.stat.type == .file)
        }
    }
}
