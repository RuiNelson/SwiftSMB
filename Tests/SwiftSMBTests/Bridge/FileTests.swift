//
// Part of SwiftSMB
// FileTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Darwin
import Foundation
import Testing

// MARK: - Stat tests

@Suite(.tags(.integration))
struct StatTests {
    @Test("stat known file returns file type") func statKnownFileReturnsFileType() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.type == .file)
        }
    }

    @Test("stat known file has positive size") func statKnownFileHasPositiveSize() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.size > 0)
        }
    }

    @Test("stat known directory returns directory type") func statKnownDirectoryReturnsDirectoryType() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.testdirPath)
            #expect(stat.type == .directory)
        }
    }

    @Test("stat non existent path throws") func statNonExistentPathThrows() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB.Error.self) {
                try fileStatistics(context: ctx, path: "nonexistent_\(uniquePath())")
            }
        }
    }

    @Test("stat from handle matches stat from path") func statFromHandleMatchesStatFromPath() throws {
        try withPublicShare { ctx in
            let pathStat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            let handle = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: handle) }
            let handleStat = try fileStatistics(context: ctx, file: handle)

            #expect(handleStat.size == pathStat.size)
            #expect(handleStat.type == pathStat.type)
        }
    }

    @Test("stat VFS has positive block size") func statVfsHasPositiveBlockSize() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.blockSize > 0)
        }
    }

    @Test("stat VFS has positive block count") func statVfsHasPositiveBlockCount() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.blocks > 0)
        }
    }

    @Test("stat VFS returns struct") func statVfsReturnsStruct() throws {
        // Samba may return f_namemax = 0; just verify the call succeeds
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            _ = vfs.maximumNameLength
        }
    }

    @Test("hello file has expected size") func helloFileHasExpectedSize() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.size == UInt64(TestContent.helloBytes.count))
        }
    }
}

// MARK: - File read tests

@Suite(.tags(.integration))
struct FileReadTests {
    @Test("open and close file") func openAndCloseFile() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            try close(context: ctx, file: fh)
        }
    }

    @Test("read hello file content") func readHelloFileContent() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes == TestContent.helloBytes)
        }
    }

    @Test("read nested file content") func readNestedFileContent() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.nestedPath)
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes == TestContent.nestedBytes)
        }
    }

    @Test("read at offset skips prefix") func readAtOffsetSkipsPrefix() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            // "Hello, SMB!\n" → offset 7 gives "SMB!\n"
            let bytes = try readSomeBytesAt(context: ctx, file: fh, count: 64, offset: 7)
            let expected = Array("SMB!\n".utf8)
            #expect(bytes == expected)
        }
    }

    @Test("read at offset beyond end returns empty") func readAtOffsetBeyondEndReturnsEmpty() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            let bytes = try readSomeBytesAt(context: ctx, file: fh, count: 64, offset: stat.size + 1)
            #expect(bytes.isEmpty)
        }
    }

    @Test("seek set and read") func seekSetAndRead() throws {
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

    @Test("seek cur advances position") func seekCurAdvancesPosition() throws {
        try withPublicShare { ctx in
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let offset = try seek(context: ctx, file: fh, offset: 3, whence: SEEK_CUR)
            #expect(offset == 3)
        }
    }

    @Test("seek end positions at end of file") func seekEndPositionsAtEndOfFile() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            let fh = try open(context: ctx, path: TestContent.helloPath)
            defer { try? close(context: ctx, file: fh) }

            let offset = try seek(context: ctx, file: fh, offset: 0, whence: SEEK_END)
            #expect(offset == stat.size)
        }
    }

    @Test("open non existent file throws") func openNonExistentFileThrows() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB.Error.self) {
                try open(context: ctx, path: "nonexistent_\(uniquePath()).txt")
            }
        }
    }

    @Test("private share file is readable") func privateShareFileIsReadable() throws {
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
    @Test("create write read and delete file") func createWriteReadAndDeleteFile() throws {
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

    @Test("write at offset pads file") func writeAtOffsetPadsFile() throws {
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

    @Test("truncate by path shortens file") func truncateByPathShortensFile() throws {
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

    @Test("truncate by handle shortens file") func truncateByHandleShortensFile() throws {
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

    @Test("rename file") func renameFile() throws {
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

            #expect(throws: SMB.Error.self) {
                try fileStatistics(context: ctx, path: oldPath)
            }

            let stat = try fileStatistics(context: ctx, path: newPath)
            #expect(stat.type == .file)
        }
    }

    @Test("sync file succeeds") func syncFileSucceeds() throws {
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

    @Test("unlink removes file") func unlinkRemovesFile() throws {
        try withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            try unlink(context: ctx, path: path)

            #expect(throws: SMB.Error.self) {
                try fileStatistics(context: ctx, path: path)
            }
        }
    }

    @Test("unlink non existent file throws") func unlinkNonExistentFileThrows() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB.Error.self) {
                try unlink(context: ctx, path: "nonexistent_\(uniquePath()).txt")
            }
        }
    }

    @Test("write to readonly share throws") func writeToReadonlyShareThrows() throws {
        try withReadonlyShare { ctx in
            #expect(throws: SMB.Error.self) {
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
    @Test("read link for file symlink") func readLinkForFileSymlink() throws {
        try withPublicShare { ctx in
            let target = try readLink(context: ctx, path: TestContent.linkToFilePath)
            #expect(!target.isEmpty)
        }
    }

    @Test("read link for directory symlink") func readLinkForDirectorySymlink() throws {
        try withPublicShare { ctx in
            let target = try readLink(context: ctx, path: TestContent.linkToDirPath)
            #expect(!target.isEmpty)
        }
    }

    @Test("read link on regular file throws") func readLinkOnRegularFileThrows() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB.Error.self) {
                try readLink(context: ctx, path: TestContent.helloPath)
            }
        }
    }

    @Test("file symlink target contains filename") func fileSymlinkTargetContainsFilename() throws {
        try withPublicShare { ctx in
            let target = try readLink(context: ctx, path: TestContent.linkToFilePath)
            #expect(target.contains("hello.txt"))
        }
    }
}

// MARK: - Read-only share tests

@Suite(.tags(.integration))
struct ReadonlyShareTests {
    @Test("read file from readonly share") func readFileFromReadonlyShare() throws {
        try withReadonlyShare { ctx in
            let fh = try open(context: ctx, path: "readme.txt")
            defer { try? close(context: ctx, file: fh) }
            let bytes = try readAllBytes(context: ctx, file: fh)
            #expect(bytes == Array("readme\n".utf8))
        }
    }

    @Test("stat from readonly share") func statFromReadonlyShare() throws {
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
    @Test("stat has positive access time") func statHasPositiveAccessTime() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.accessTime > 0)
        }
    }

    @Test("stat has positive modification time") func statHasPositiveModificationTime() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.modificationTime > 0)
        }
    }

    @Test("stat has positive inode") func statHasPositiveInode() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.inode > 0)
        }
    }

    @Test("stat file has link count") func statFileHasLinkCount() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.linkCount >= 1)
        }
    }

    @Test("stat directory link count is at least one") func statDirectoryLinkCountIsAtLeastOne() throws {
        try withPublicShare { ctx in
            let stat = try fileStatistics(context: ctx, path: TestContent.testdirPath)
            #expect(stat.linkCount >= 1)
        }
    }

    @Test("stat VFS free blocks is positive") func statVfsFreeBlocksIsPositive() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.freeBlocks > 0)
        }
    }

    @Test("stat VFS available blocks is positive") func statVfsAvailableBlocksIsPositive() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            #expect(vfs.availableBlocks > 0)
        }
    }

    @Test("stat VFS file count is accessible") func statVfsFileCountIsAccessible() throws {
        try withPublicShare { ctx in
            let vfs = try statVFS(context: ctx, path: "")
            _ = vfs.fileCount
        }
    }
}

// MARK: - Read-write file mode tests

@Suite(.tags(.integration))
struct ReadWriteModeTests {
    @Test("open file readWrite and write read back") func openFileReadwriteAndWriteReadBack() throws {
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

    @Test("read private large file content length") func readPrivateLargeFileContentLength() throws {
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
    @Test("largefile 5 MB is on private share") func largefile5MbIsOnPrivateShare() throws {
        try withPrivateShare { ctx in
            let stat = try fileStatistics(context: ctx, path: "largefile.bin")
            #expect(stat.size == 5 * 1024 * 1024)
        }
    }

    @Test("largefile xor hash matches expected") func largefileXorHashMatchesExpected() throws {
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

    @Test("upload and download 10 MB file preserves data") func uploadAndDownload10MBFilePreservesData() throws {
        try withPublicShare { ctx in
            let path = uniquePath("large") + ".bin"
            defer { try? unlink(context: ctx, path: path) }

            let size = 10 * 1024 * 1024 + 1
            let content = [UInt8](unsafeUninitializedCapacity: size) { buf, count in
                for i in 0 ..< size {
                    buf[i] = UInt8(i % 251)
                }
                count = size
            }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            let written = try writeAllBytesChunked(context: ctx, file: wh, data: content)
            try close(context: ctx, file: wh)
            #expect(written == size)

            let rh = try open(context: ctx, path: path)
            defer { try? close(context: ctx, file: rh) }
            let readBack = try readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }
}

// MARK: - Set basic info tests

@Suite(.tags(.integration))
struct SetBasicInfoTests {
    @Test("set modification time") func setModificationTime() throws {
        try withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            let newTime = Date(timeIntervalSince1970: 1_700_000_000)
            try setStats(context: ctx, path: path, lastWriteTime: newTime)

            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.modificationTime == UInt64(newTime.timeIntervalSince1970))
        }
    }

    @Test("set access time") func setAccessTime() throws {
        try withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            let newTime = Date(timeIntervalSince1970: 1_600_000_000)
            try setStats(context: ctx, path: path, lastAccessTime: newTime)

            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.accessTime == UInt64(newTime.timeIntervalSince1970))
        }
    }

    @Test("set creation time") func setCreationTime() throws {
        try withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            let newTime = Date(timeIntervalSince1970: 1_800_000_000)
            try setStats(context: ctx, path: path, creationTime: newTime)

            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.birthTime == UInt64(newTime.timeIntervalSince1970))
        }
    }

    @Test("set multiple timestamps") func setMultipleTimestamps() throws {
        try withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            let access = Date(timeIntervalSince1970: 1_550_000_000)
            let write = Date(timeIntervalSince1970: 1_650_000_000)
            let change = Date(timeIntervalSince1970: 1_750_000_000)
            let creation = Date(timeIntervalSince1970: 1_850_000_000)

            try setStats(
                context: ctx,
                path: path,
                creationTime: creation,
                lastAccessTime: access,
                lastWriteTime: write,
                changeTime: change,
            )

            let stat = try fileStatistics(context: ctx, path: path)
            #expect(stat.accessTime == UInt64(access.timeIntervalSince1970))
            #expect(stat.modificationTime == UInt64(write.timeIntervalSince1970))
            // Samba reports change time as server-maintained metadata ctime.
            #expect(stat.birthTime == UInt64(creation.timeIntervalSince1970))
        }
    }

    @Test("get and set file attributes") func getAndSetFileAttributes() throws {
        try withPublicShare { ctx in
            let path = uniquePath("setattr") + ".txt"
            defer { try? unlink(context: ctx, path: path) }

            let wh = try open(
                context: ctx,
                path: path,
                flags: SMB2OpenFlags(.writeOnly, options: [.create, .exclusive]),
            )
            try close(context: ctx, file: wh)

            let initial = try getFileAttributes(context: ctx, path: path)
            #expect(initial == 0x0000_0020) // SMB2_FILE_ATTRIBUTE_ARCHIVE

            try setStats(context: ctx, path: path, fileAttributes: 0x0000_0002)

            let updated = try getFileAttributes(context: ctx, path: path)
            #expect(updated == 0x0000_0002) // SMB2_FILE_ATTRIBUTE_HIDDEN
        }
    }

    @Test("set basic info on nonexistent file throws") func setBasicInfoOnNonexistentFileThrows() throws {
        try withPublicShare { ctx in
            #expect(throws: SMB.Error.self) {
                try setStats(
                    context: ctx,
                    path: "nonexistent_\(uniquePath()).txt",
                    lastWriteTime: Date(),
                )
            }
        }
    }
}
