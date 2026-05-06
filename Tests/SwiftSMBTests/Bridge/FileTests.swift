//
// Part of SwiftSMB
// FileTests.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

@testable import SwiftSMB
import Darwin
import Testing

// MARK: - Stat tests

@Suite(.tags(.integration))
struct StatTests {
    @Test func `stat known file returns file type`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.type == .file)
        }
    }

    @Test func `stat known file has positive size`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.size > 0)
        }
    }

    @Test func `stat known directory returns directory type`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.testdirPath)
            #expect(stat.type == .directory)
        }
    }

    @Test func `stat non existent path throws`() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB2Error.self) {
                try fileStatistics(context: ctx, path: "nonexistent_\(uniquePath())")
            }
        }
    }

    @Test func `stat from handle matches stat from path`() throws {
        try withPublicShare { ctx in
            let pathStat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            let handle = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: handle) }
            let handleStat = try fileStatistics(context: ctx, file: handle)

            #expect(handleStat.size == pathStat.size)
            #expect(handleStat.type == pathStat.type)
        }
    }

    @Test func `stat VFS has positive block size`() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.blockSize > 0)
        }
    }

    @Test func `stat VFS has positive block count`() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.blocks > 0)
        }
    }

    @Test func `stat VFS returns struct`() throws {
        // Samba may return f_namemax = 0; just verify the call succeeds
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            _ = vfs.maximumNameLength
        }
    }

    @Test func `hello file has expected size`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.size == UInt64(TestContent.helloBytes.count))
        }
    }
}

// MARK: - File read tests

@Suite(.tags(.integration))
struct FileReadTests {
    @Test func `open and close file`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            try close(context: ctx, file: fh)
        }
    }

    @Test func `read hello file content`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes == TestContent.helloBytes)
        }
    }

    @Test func `read nested file content`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.nestedPath)
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes == TestContent.nestedBytes)
        }
    }

    @Test func `read at offset skips prefix`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            // "Hello, SMB!\n" → offset 7 gives "SMB!\n"
            let bytes = try readSomeBytesAt(context: ctx, file: fh, count: 64, offset: 7)
            let expected = Array("SMB!\n".utf8)
            #expect(bytes == expected)
        }
    }

    @Test func `read at offset beyond end returns empty`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            let bytes = try readSomeBytesAt(context: ctx, file: fh, count: 64, offset: stat.size + 1)
            #expect(bytes.isEmpty)
        }
    }

    @Test func `seek set and read`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let newOffset = try seek(context: ctx, file: fh, offset: 7, whence: SEEK_SET)
            #expect(newOffset == 7)

            let bytes = try readSomeBytes(context: ctx, file: fh, count: 64)
            let expected = Array("SMB!\n".utf8)
            #expect(bytes == expected)
        }
    }

    @Test func `seek cur advances position`() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let offset = try seek(context: ctx, file: fh, offset: 3, whence: SEEK_CUR)
            #expect(offset == 3)
        }
    }

    @Test func `seek end positions at end of file`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let offset = try seek(context: ctx, file: fh, offset: 0, whence: SEEK_END)
            #expect(offset == stat.size)
        }
    }

    @Test func `open non existent file throws`() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB2Error.self) {
                try open(context: ctx, path: "nonexistent_\(uniquePath()).txt")
            }
        }
    }

    @Test func `private share file is readable`() throws {
        try withPrivateShare { ctx in
            let fh = try open(context: ctx, path: "secret.txt")
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(!bytes.isEmpty)
        }
    }
}

// MARK: - File write tests

@Suite(.tags(.integration))
struct FileWriteTests {
    @Test func `create write read and delete file`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let content = Array("Test content for integration test.".utf8)

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            let written = try writeAllBytes(context: ctx, file: wh, data: content)
            try close(context: ctx, file: wh)
            #expect(written == content.count)

            let rh = try open(context: ctx, path: path)
            defer { try? close(context: ctx, file: rh) }
            let readBack = try readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }

    @Test func `write at offset pads file`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".bin"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            let data = Array("HELLO".utf8)
            let written = try writeAllBytesAt(context: ctx, file: wh, data: data, offset: 10)
            try close(context: ctx, file: wh)
            #expect(written == data.count)

            // Stat by path after closing the write-only handle
            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.size == 15) // 10 (hole) + 5 (HELLO)
        }
    }

    @Test func `truncate by path shortens file`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let content = Array("ABCDEFGHIJ".utf8)
            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            _ = try writeAllBytes(context: ctx, file: wh, data: content)
            try close(context: ctx, file: wh)

            try truncate(context: ctx, path: path, length: 5)

            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.size == 5)

            let rh = try open(context: ctx, path: path)
            defer { try? close(context: ctx, file: rh) }
            let bytes = try readAllBytes(context: ctx, file: rh)
            #expect(bytes == Array("ABCDE".utf8))
        }
    }

    @Test func `truncate by handle shortens file`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let content = Array("ABCDEFGHIJ".utf8)
            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            _ = try writeAllBytes(context: ctx, file: wh, data: content)
            try truncate(context: ctx, file: wh, length: 3)
            try close(context: ctx, file: wh)

            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.size == 3)
        }
    }

    @Test func `rename file`() throws {
        try withPublicShare { ctx in
            let oldPath = uniquePath("old") + ".txt"
            let newPath = uniquePath("new") + ".txt"
            defer {
                try? unlink(context: ctx, path: oldPath)
                try? unlink(context: ctx, path: newPath)
            }

            let wh = try open(
                context: ctx,
                path: oldPath,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            try rename(context: ctx, oldPath: oldPath, newPath: newPath)

            #expect(throws: SMB2Error.self) {
                try fileStatistics(context: ctx, path: oldPath)
            }

            let stat = try fileStatistics(context: ctx, path: newPath)
            #expect(stat.type == .file)
        }
    }

    @Test func `sync file succeeds`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            defer { try? close(context: ctx, file: wh) }

            _ = try writeAllBytes(context: ctx, file: wh, data: Array("data".utf8))
            try sync(context: ctx, file: wh)
        }
    }

    @Test func `unlink removes file`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            try unlink(context: ctx, path: path)

            #expect(throws: SMB2Error.self) {
                try fileStatistics(context: ctx, path: path)
            }
        }
    }

    @Test func `unlink non existent file throws`() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB2Error.self) {
                try unlink(context: ctx, path: "nonexistent_\(uniquePath()).txt")
            }
        }
    }

    @Test func `write to readonly share throws`() throws {
        try withReadonlyShare { ctx in
            #expect(throws: SMB2Error.self) {
                try open(
                    context: ctx,
                    path: uniquePath("file") + ".txt",
                    flags: SMB2OpenFlags(.writeOnly, options: [.create]),
                )
            }
        }
    }
}

// MARK: - Symlink tests

@Suite(.tags(.integration))
struct SymlinkTests {
    @Test func `read link for file symlink`() throws {
        try withPublicShare { ctx in
            let target = try readLink(context: ctx, path: TestContent.linkToFilePath)
            #expect(!target.isEmpty)
        }
    }

    @Test func `read link for directory symlink`() throws {
        try withPublicShare { ctx in
            let target = try readLink(context: ctx, path: TestContent.linkToDirPath)
            #expect(!target.isEmpty)
        }
    }

    @Test func `read link on regular file throws`() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB2Error.self) {
                try readLink(context: ctx, path: TestContent.helloPath)
            }
        }
    }

    @Test func `file symlink target contains filename`() throws {
        try withPublicShare { ctx in
            let target = try readLink(context: ctx, path: TestContent.linkToFilePath)
            #expect(target.contains("hello.txt"))
        }
    }

}

// MARK: - Read-only share tests

@Suite(.tags(.integration))
struct ReadonlyShareTests {
    @Test func `read file from readonly share`() throws {
        try withReadonlyShare { ctx in
            let fh = try open(context: ctx, path: "readme.txt")
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes == Array("readme\n".utf8))
        }
    }

    @Test func `stat from readonly share`() throws {
        try withReadonlyShare { ctx in
            let stat = try fileStatistics(context: ctx, path: "readme.txt")
            #expect(stat.type == .file)
            #expect(stat.size > 0)
        }
    }
}

// MARK: - Read-write mode and stat detail tests

@Suite(.tags(.integration))
struct StatDetailTests {
    @Test func `stat has positive access time`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.accessTime > 0)
        }
    }

    @Test func `stat has positive modification time`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.modificationTime > 0)
        }
    }

    @Test func `stat has positive inode`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.inode > 0)
        }
    }

    @Test func `stat file has link count`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.linkCount >= 1)
        }
    }

    @Test func `stat directory link count is at least one`() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.testdirPath)
            #expect(stat.linkCount >= 1)
        }
    }

    @Test func `stat VFS free blocks is positive`() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.freeBlocks > 0)
        }
    }

    @Test func `stat VFS available blocks is positive`() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.availableBlocks > 0)
        }
    }

    @Test func `stat VFS file count is accessible`() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            _ = vfs.fileCount
        }
    }
}

// MARK: - Read-write file mode tests

@Suite(.tags(.integration))
struct ReadWriteModeTests {
    @Test func `open file readWrite and write read back`() throws {
        try withPublicShare { ctx in
            let path = uniquePath("rw") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.readWrite, options: [.create, .exclusive]),
            )
            let content = Array("read-write test".utf8)
            _ = try writeAllBytes(context: ctx, file: wh, data: content)

            _ = try seek(context: ctx, file: wh, offset: 0, whence: SEEK_SET)
            let readBack = try readAllBytes(context: ctx, file: wh)
            try close(context: ctx, file: wh)

            #expect(readBack == content)
        }
    }

    @Test func `read private large file content length`() throws {
        try withPrivateShare { ctx in
            let fh = try open(context: ctx, path: "largefile.bin")
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes.count == 5 * 1024 * 1024)
        }
    }
}

// MARK: - Large file tests

@Suite(.tags(.integration))
struct LargeFileTests {
    @Test func `largefile 5 MB is on private share`() throws {
        try withPrivateShare { ctx in
            let stat = try fileStatistics(context: ctx, path: "largefile.bin")
            #expect(stat.size == 5 * 1024 * 1024)
        }
    }

    @Test func `largefile xor hash matches expected`() throws {
        // File is generated in the Docker image as bytes i%251 for i in 0..<5*1024*1024.
        // Pre-computed XOR of that sequence: 0x08.
        try withPrivateShare { ctx in
            let fh = try open(context: ctx, path: "largefile.bin")
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            let hash = bytes.reduce(0 as UInt8, ^)
            #expect(hash == 0x08)
        }
    }
}
