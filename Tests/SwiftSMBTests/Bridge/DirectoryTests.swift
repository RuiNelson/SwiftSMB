//
// Part of SwiftSMB
// DirectoryTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct DirectoryTests {
    @Test("open and close root directory") func openAndCloseRootDirectory() async throws {
        try await withPublicShare { ctx in
            let dir = try await Bridge.openDir(context: ctx, path: "")
            try await Bridge.closeDir(context: ctx, directory: dir)
        }
    }

    @Test("root directory contains known entries") func rootDirectoryContainsKnownEntries() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: "")
            let names = entries.map(\.name)
            #expect(names.contains(TestContent.testdirPath))
            #expect(names.contains(TestContent.emptyDirPath))
        }
    }

    @Test("dot and dot dot are present") func dotAndDotDotArePresent() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: "")
            let names = entries.map(\.name)
            #expect(names.contains("."))
            #expect(names.contains(".."))
        }
    }

    @Test("dir contains hello file") func dirContainsHelloFile() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: TestContent.testdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("hello.txt"))
        }
    }

    @Test("dir contains subdir and links") func dirContainsSubdirAndLinks() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: TestContent.testdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("subdir"))
            #expect(names.contains("link_to_file"))
            #expect(names.contains("link_to_dir"))
        }
    }

    @Test("empty dir has only dot entries") func emptyDirHasOnlyDotEntries() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: TestContent.emptyDirPath)
            let names = entries.map(\.name)
            #expect(names.contains("."))
            #expect(names.contains(".."))
            #expect(names.count == 2)
        }
    }

    @Test("rewind directory reads from start") func rewindDirectoryReadsFromStart() async throws {
        try await withPublicShare { ctx in
            let dir = try await Bridge.openDir(context: ctx, path: TestContent.testdirPath)
            defer { try? await Bridge.closeDir(context: ctx, directory: dir) }

            let first = try await allEntries(context: ctx, directory: dir)
            try await Bridge.rewindDir(context: ctx, directory: dir)
            let second = try await allEntries(context: ctx, directory: dir)

            #expect(first.map(\.name) == second.map(\.name))
        }
    }

    @Test("tell dir at start is zero") func tellDirAtStartIsZero() async throws {
        try await withPublicShare { ctx in
            let dir = try await Bridge.openDir(context: ctx, path: TestContent.testdirPath)
            defer { try? await Bridge.closeDir(context: ctx, directory: dir) }
            #expect(try await Bridge.tellDir(context: ctx, directory: dir) == 0)
        }
    }

    @Test("tell and seek return to same position") func tellAndSeekReturnToSamePosition() async throws {
        try await withPublicShare { ctx in
            let dir = try await Bridge.openDir(context: ctx, path: TestContent.testdirPath)
            defer { try? await Bridge.closeDir(context: ctx, directory: dir) }

            let firstEntry = try await Bridge.readDir(context: ctx, directory: dir)
            let posAfterFirst = try await Bridge.tellDir(context: ctx, directory: dir)

            let secondEntry = try await Bridge.readDir(context: ctx, directory: dir)
            let posAfterSecond = try await Bridge.tellDir(context: ctx, directory: dir)

            #expect(firstEntry?.name != secondEntry?.name)
            #expect(posAfterFirst != posAfterSecond)

            try await Bridge.seekDir(context: ctx, directory: dir, location: posAfterFirst)
            let reRead = try await Bridge.readDir(context: ctx, directory: dir)
            #expect(reRead?.name == secondEntry?.name)
        }
    }

    @Test("create and remove directory") func createAndRemoveDirectory() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("dir")
            try await Bridge.makeDir(context: ctx, path: path)
            defer { try? await Bridge.removeDir(context: ctx, path: path) }

            try await Bridge.removeDir(context: ctx, path: path)

            await #expect(throws: SMB.Error.self) {
                try await Bridge.fileStatistics(context: ctx, path: path)
            }
        }
    }

    @Test("removing non existent directory throws") func removingNonExistentDirectoryThrows() async throws {
        try await withPublicShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.removeDir(context: ctx, path: "nonexistent_\(uniquePath())")
            }
        }
    }

    @Test("nested directory listing") func nestedDirectoryListing() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: TestContent.subdirPath)
            let names = entries.map(\.name)
            #expect(names.contains("nested.dat"))
        }
    }

    @Test("directory entry type is directory") func directoryEntryTypeIsDirectory() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: "")
            let testdir = try #require(entries.first { $0.name == TestContent.testdirPath })
            #expect(testdir.stat.type == .directory)
        }
    }

    @Test("file entry type is file") func fileEntryTypeIsFile() async throws {
        try await withPublicShare { ctx in
            let entries = try await listDirectory(context: ctx, path: TestContent.testdirPath)
            let hello = try #require(entries.first { $0.name == "hello.txt" })
            #expect(hello.stat.type == .file)
        }
    }
}
