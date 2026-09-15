//
// Part of SwiftSMB
// FileTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: - Stat tests

@Suite(.tags(.integration))
struct StatTests {
    @Test("stat known file returns file type") func statKnownFileReturnsFileType() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.type == .file)
        }
    }

    @Test("stat known file has positive size") func statKnownFileHasPositiveSize() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.size > 0)
        }
    }

    @Test("stat known directory returns directory type") func statKnownDirectoryReturnsDirectoryType() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.testdirPath)
            #expect(stat.type == .directory)
        }
    }

    @Test("stat non existent path throws") func statNonExistentPathThrows() async throws {
        try await withPublicShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.fileStatistics(context: ctx, path: "nonexistent_\(uniquePath())")
            }
        }
    }

    @Test("stat from handle matches stat from path") func statFromHandleMatchesStatFromPath() async throws {
        try await withPublicShare { ctx in
            let pathStat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            let handle = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: handle) }
            let handleStat = try await Bridge.fileStatistics(context: ctx, file: handle)

            #expect(handleStat.size == pathStat.size)
            #expect(handleStat.type == pathStat.type)
        }
    }

    @Test("stat VFS has positive block size") func statVfsHasPositiveBlockSize() async throws {
        try await withPublicShare { ctx in
            let vfs = try await Bridge.statVFS(context: ctx, path: "")
            #expect(vfs.blockSize > 0)
        }
    }

    @Test("stat VFS has positive block count") func statVfsHasPositiveBlockCount() async throws {
        try await withPublicShare { ctx in
            let vfs = try await Bridge.statVFS(context: ctx, path: "")
            #expect(vfs.blocks > 0)
        }
    }

    @Test("stat VFS returns struct") func statVfsReturnsStruct() async throws {
        // Samba may return f_namemax = 0; just verify the call succeeds
        try await withPublicShare { ctx in
            let vfs = try await Bridge.statVFS(context: ctx, path: "")
            _ = vfs.maximumNameLength
        }
    }

    @Test("hello file has expected size") func helloFileHasExpectedSize() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.size == UInt64(TestContent.helloBytes.count))
        }
    }
}

// MARK: - File read tests

@Suite(.tags(.integration))
struct FileReadTests {
    @Test("open and close file") func openAndCloseFile() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            try await Bridge.close(context: ctx, file: fh)
        }
    }

    @Test("read hello file content") func readHelloFileContent() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }
            let bytes = try await readAllBytes(context: ctx, file: fh)
            #expect(bytes == TestContent.helloBytes)
        }
    }

    @Test("read nested file content") func readNestedFileContent() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.nestedPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }
            let bytes = try await readAllBytes(context: ctx, file: fh)
            #expect(bytes == TestContent.nestedBytes)
        }
    }

    @Test("read at offset skips prefix") func readAtOffsetSkipsPrefix() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }

            // "Hello, SMB!\n" → offset 7 gives "SMB!\n"
            let bytes = try await readSomeBytesAt(context: ctx, file: fh, count: 64, offset: 7)
            let expected = Array("SMB!\n".utf8)
            #expect(bytes == expected)
        }
    }

    @Test("read at offset beyond end returns empty") func readAtOffsetBeyondEndReturnsEmpty() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }

            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            let bytes = try await readSomeBytesAt(context: ctx, file: fh, count: 64, offset: stat.size + 1)
            #expect(bytes.isEmpty)
        }
    }

    @Test("seek set and read") func seekSetAndRead() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }

            let newOffset = try await Bridge.seek(context: ctx, file: fh, offset: 7, whence: SEEK_SET)
            #expect(newOffset == 7)

            let bytes = try await readSomeBytes(context: ctx, file: fh, count: 64)
            let expected = Array("SMB!\n".utf8)
            #expect(bytes == expected)
        }
    }

    @Test("seek cur advances position") func seekCurAdvancesPosition() async throws {
        try await withPublicShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }

            let offset = try await Bridge.seek(context: ctx, file: fh, offset: 3, whence: SEEK_CUR)
            #expect(offset == 3)
        }
    }

    @Test("seek end positions at end of file") func seekEndPositionsAtEndOfFile() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            let fh = try await Bridge.open(context: ctx, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: ctx, file: fh) }

            let offset = try await Bridge.seek(context: ctx, file: fh, offset: 0, whence: SEEK_END)
            #expect(offset == stat.size)
        }
    }

    @Test("open non existent file throws") func openNonExistentFileThrows() async throws {
        try await withPublicShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.open(context: ctx, path: "nonexistent_\(uniquePath()).txt")
            }
        }
    }

    @Test("private share file is readable") func privateShareFileIsReadable() async throws {
        try await withPrivateShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: "secret.txt")
            defer { try? await Bridge.close(context: ctx, file: fh) }
            let bytes = try await readAllBytes(context: ctx, file: fh)
            #expect(!bytes.isEmpty)
        }
    }
}

// MARK: - File write tests

@Suite(.tags(.integration), .serialized)
struct FileWriteTests {
    @Test("create write read and delete file") func createWriteReadAndDeleteFile() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let content = Array("Test content for integration test.".utf8)

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            let written = try await writeAllBytes(context: ctx, file: wh, data: content)
            try await Bridge.close(context: ctx, file: wh)
            #expect(written == content.count)

            let rh = try await Bridge.open(context: ctx, path: path)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let readBack = try await readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }

    @Test("write at offset pads file") func writeAtOffsetPadsFile() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("file") + ".bin"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            let data = Array("HELLO".utf8)
            let written = try await writeAllBytesAt(context: ctx, file: wh, data: data, offset: 10)
            try await Bridge.close(context: ctx, file: wh)
            #expect(written == data.count)

            // Stat by path after closing the write-only handle
            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.size == 15) // 10 (hole) + 5 (HELLO)
        }
    }

    @Test("truncate by path shortens file") func truncateByPathShortensFile() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let content = Array("ABCDEFGHIJ".utf8)
            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            _ = try await writeAllBytes(context: ctx, file: wh, data: content)
            try await Bridge.close(context: ctx, file: wh)

            try await Bridge.truncate(context: ctx, path: path, length: 5)

            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.size == 5)

            let rh = try await Bridge.open(context: ctx, path: path)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let bytes = try await readAllBytes(context: ctx, file: rh)
            #expect(bytes == Array("ABCDE".utf8))
        }
    }

    @Test("truncate by handle shortens file") func truncateByHandleShortensFile() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let content = Array("ABCDEFGHIJ".utf8)
            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            _ = try await writeAllBytes(context: ctx, file: wh, data: content)
            try await Bridge.truncate(context: ctx, file: wh, length: 3)
            try await Bridge.close(context: ctx, file: wh)

            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.size == 3)
        }
    }

    @Test("rename file") func renameFile() async throws {
        try await withPublicShare { ctx in
            let oldPath = uniquePath("old") + ".txt"
            let newPath = uniquePath("new") + ".txt"
            defer {
                try? await Bridge.unlink(context: ctx, path: oldPath)
                try? await Bridge.unlink(context: ctx, path: newPath)
            }

            let wh = try await Bridge.open(
                context: ctx,
                path: oldPath,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            try await Bridge.rename(context: ctx, oldPath: oldPath, newPath: newPath)

            await #expect(throws: SMB.Error.self) {
                try await Bridge.fileStatistics(context: ctx, path: oldPath)
            }

            let stat = try await Bridge.fileStatistics(context: ctx, path: newPath)
            #expect(stat.type == .file)
        }
    }

    @Test("sync file succeeds") func syncFileSucceeds() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: ctx, file: wh) }

            _ = try await writeAllBytes(context: ctx, file: wh, data: Array("data".utf8))
            try await Bridge.sync(context: ctx, file: wh)
        }
    }

    @Test("unlink removes file") func unlinkRemovesFile() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("file") + ".txt"
            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            try await Bridge.unlink(context: ctx, path: path)

            await #expect(throws: SMB.Error.self) {
                try await Bridge.fileStatistics(context: ctx, path: path)
            }
        }
    }

    @Test("unlink non existent file throws") func unlinkNonExistentFileThrows() async throws {
        try await withPublicShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.unlink(context: ctx, path: "nonexistent_\(uniquePath()).txt")
            }
        }
    }

    @Test("write to readonly share throws") func writeToReadonlyShareThrows() async throws {
        try await withReadonlyShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.open(
                    context: ctx,
                    path: uniquePath("file") + ".txt",
                    flags: Bridge.OpenFlags(.writeOnly, options: [.create])
                )
            }
        }
    }
}

// MARK: - Symlink tests

@Suite(.tags(.integration))
struct SymlinkTests {
    @Test("read link for file symlink") func readLinkForFileSymlink() async throws {
        try await withPublicShare { ctx in
            let target = try await Bridge.readLink(context: ctx, path: TestContent.linkToFilePath)
            #expect(!target.isEmpty)
        }
    }

    @Test("read link for directory symlink") func readLinkForDirectorySymlink() async throws {
        try await withPublicShare { ctx in
            let target = try await Bridge.readLink(context: ctx, path: TestContent.linkToDirPath)
            #expect(!target.isEmpty)
        }
    }

    @Test("read link on regular file throws") func readLinkOnRegularFileThrows() async throws {
        try await withPublicShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.readLink(context: ctx, path: TestContent.helloPath)
            }
        }
    }

    @Test("file symlink target contains filename") func fileSymlinkTargetContainsFilename() async throws {
        try await withPublicShare { ctx in
            let target = try await Bridge.readLink(context: ctx, path: TestContent.linkToFilePath)
            #expect(target.contains("hello.txt"))
        }
    }

    @Test("create and read symlink") func makeLinkAndReadLink() async throws {
        try await withPrivateShare { ctx in
            let targetPath = uniquePath("target") + ".txt"
            let linkPath = uniquePath("link")
            defer {
                try? await Bridge.unlink(context: ctx, path: linkPath)
                try? await Bridge.unlink(context: ctx, path: targetPath)
            }
            let handle = try await Bridge.open(
                context: ctx,
                path: targetPath,
                flags: .init(.writeOnly, options: .create)
            )
            defer { try? await Bridge.close(context: ctx, file: handle) }
            let data = Array("target content".utf8)
            _ = try await Bridge.write(context: ctx, file: handle, data: Data(data))
            try await Bridge.makeLink(context: ctx, path: linkPath, destination: targetPath)
            let readTarget = try await Bridge.readLink(context: ctx, path: linkPath)
            #expect(readTarget == targetPath)
        }
    }

    @Test("create nested symlink") func makeLinkNestedPath() async throws {
        try await withPrivateShare { ctx in
            let dirPath = uniquePath("nested_dir")
            let targetPath = "target.txt"
            let linkPath = "\(dirPath)/nested_link"
            defer {
                try? await Bridge.unlink(context: ctx, path: linkPath)
                try? await Bridge.removeDir(context: ctx, path: dirPath)
            }
            try await Bridge.makeDir(context: ctx, path: dirPath)
            try await Bridge.makeLink(context: ctx, path: linkPath, destination: targetPath)
            let readTarget = try await Bridge.readLink(context: ctx, path: linkPath)
            #expect(readTarget == targetPath)
        }
    }

    @Test("create hard link") func makeHardLink() async throws {
        try await withPrivateShare { ctx in
            let targetPath = uniquePath("hardlink-target") + ".txt"
            let linkPath = uniquePath("hardlink")
            defer {
                try? await Bridge.unlink(context: ctx, path: linkPath)
                try? await Bridge.unlink(context: ctx, path: targetPath)
            }

            do {
                let handle = try await Bridge.open(
                    context: ctx,
                    path: targetPath,
                    flags: .init(.writeOnly, options: .create)
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let data = Array("hard link content".utf8)
                _ = try await Bridge.write(context: ctx, file: handle, data: Data(data))
            }

            try await Bridge.makeHardLink(context: ctx, existingPath: targetPath, newPath: linkPath)

            let targetStat = try await Bridge.fileStatistics(context: ctx, path: targetPath)
            let linkStat = try await Bridge.fileStatistics(context: ctx, path: linkPath)
            #expect(targetStat.inode == linkStat.inode)
            #expect(targetStat.linkCount >= 2)
            #expect(linkStat.linkCount >= 2)
        }
    }
}

// MARK: - Read-only share tests

@Suite(.tags(.integration))
struct ReadonlyShareTests {
    @Test("read file from readonly share") func readFileFromReadonlyShare() async throws {
        try await withReadonlyShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: "readme.txt")
            defer { try? await Bridge.close(context: ctx, file: fh) }
            let bytes = try await readAllBytes(context: ctx, file: fh)
            #expect(bytes == Array("readme\n".utf8))
        }
    }

    @Test("stat from readonly share") func statFromReadonlyShare() async throws {
        try await withReadonlyShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: "readme.txt")
            #expect(stat.type == .file)
            #expect(stat.size > 0)
        }
    }
}

// MARK: - Read-write mode and stat detail tests

@Suite(.tags(.integration))
struct StatDetailTests {
    @Test("stat has positive access time") func statHasPositiveAccessTime() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.accessTime > 0)
        }
    }

    @Test("stat has positive modification time") func statHasPositiveModificationTime() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.modificationTime > 0)
        }
    }

    @Test("stat has positive inode") func statHasPositiveInode() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.inode > 0)
        }
    }

    @Test("stat file has link count") func statFileHasLinkCount() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.helloPath)
            #expect(stat.linkCount >= 1)
        }
    }

    @Test("stat directory link count is at least one") func statDirectoryLinkCountIsAtLeastOne() async throws {
        try await withPublicShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: TestContent.testdirPath)
            #expect(stat.linkCount >= 1)
        }
    }

    @Test("stat VFS free blocks is positive") func statVfsFreeBlocksIsPositive() async throws {
        try await withPublicShare { ctx in
            let vfs = try await Bridge.statVFS(context: ctx, path: "")
            #expect(vfs.freeBlocks > 0)
        }
    }

    @Test("stat VFS available blocks is positive") func statVfsAvailableBlocksIsPositive() async throws {
        try await withPublicShare { ctx in
            let vfs = try await Bridge.statVFS(context: ctx, path: "")
            #expect(vfs.availableBlocks > 0)
        }
    }

    @Test("stat VFS file count is accessible") func statVfsFileCountIsAccessible() async throws {
        try await withPublicShare { ctx in
            let vfs = try await Bridge.statVFS(context: ctx, path: "")
            _ = vfs.fileCount
        }
    }
}

// MARK: - Read-write file mode tests

@Suite(.tags(.integration))
struct ReadWriteModeTests {
    @Test("open file readWrite and write read back") func openFileReadwriteAndWriteReadBack() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("rw") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive])
            )
            let content = Array("read-write test".utf8)
            _ = try await writeAllBytes(context: ctx, file: wh, data: content)

            _ = try await Bridge.seek(context: ctx, file: wh, offset: 0, whence: SEEK_SET)
            let readBack = try await readAllBytes(context: ctx, file: wh)
            try await Bridge.close(context: ctx, file: wh)

            #expect(readBack == content)
        }
    }

    @Test("read private large file content length") func readPrivateLargeFileContentLength() async throws {
        try await withPrivateShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: "largefile.bin")
            defer { try? await Bridge.close(context: ctx, file: fh) }
            let bytes = try await readAllBytes(context: ctx, file: fh)
            #expect(bytes.count == 5 * 1024 * 1024)
        }
    }
}

// MARK: - Large file tests

@Suite(.tags(.integration))
struct LargeFileTests {
    @Test("largefile 5 MB is on private share") func largefile5MbIsOnPrivateShare() async throws {
        try await withPrivateShare { ctx in
            let stat = try await Bridge.fileStatistics(context: ctx, path: "largefile.bin")
            #expect(stat.size == 5 * 1024 * 1024)
        }
    }

    @Test("largefile xor hash matches expected") func largefileXorHashMatchesExpected() async throws {
        // File is generated in the Docker image as bytes i%251 for i in 0..<5*1024*1024. Pre-computed XOR of that
        // sequence: 0x08.
        try await withPrivateShare { ctx in
            let fh = try await Bridge.open(context: ctx, path: "largefile.bin")
            defer { try? await Bridge.close(context: ctx, file: fh) }
            let bytes = try await readAllBytes(context: ctx, file: fh)
            let hash = bytes.reduce(0 as UInt8, ^)
            #expect(hash == 0x08)
        }
    }

    @Test("upload and download 10 MB file preserves data") func uploadAndDownload10MBFilePreservesData() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("large") + ".bin"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let size = 10 * 1024 * 1024 + 1
            let content = [UInt8](unsafeUninitializedCapacity: size) { buf, count in
                for i in 0 ..< size {
                    buf[i] = UInt8(i % 251)
                }
                count = size
            }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            let written = try await writeAllBytesChunked(context: ctx, file: wh, data: content)
            try await Bridge.close(context: ctx, file: wh)
            #expect(written == size)

            let rh = try await Bridge.open(context: ctx, path: path)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let readBack = try await readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }
}

// MARK: - Set basic info tests

@Suite(.tags(.integration))
struct SetBasicInfoTests {
    @Test("set modification time") func setModificationTime() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            let newTime = Date(timeIntervalSince1970: 1_700_000_000)
            try await Bridge.setStats(context: ctx, path: path, lastWriteTime: newTime)

            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.modificationTime == UInt64(newTime.timeIntervalSince1970))
        }
    }

    @Test("set access time") func setAccessTime() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            let newTime = Date(timeIntervalSince1970: 1_600_000_000)
            try await Bridge.setStats(context: ctx, path: path, lastAccessTime: newTime)

            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.accessTime == UInt64(newTime.timeIntervalSince1970))
        }
    }

    @Test("set creation time") func setCreationTime() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            let newTime = Date(timeIntervalSince1970: 1_800_000_000)
            try await Bridge.setStats(context: ctx, path: path, creationTime: newTime)

            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.birthTime == UInt64(newTime.timeIntervalSince1970))
        }
    }

    @Test("set multiple timestamps") func setMultipleTimestamps() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("settime") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            let access = Date(timeIntervalSince1970: 1_550_000_000)
            let write = Date(timeIntervalSince1970: 1_650_000_000)
            let change = Date(timeIntervalSince1970: 1_750_000_000)
            let creation = Date(timeIntervalSince1970: 1_850_000_000)

            try await Bridge.setStats(
                context: ctx,
                path: path,
                creationTime: creation,
                lastAccessTime: access,
                lastWriteTime: write,
                changeTime: change
            )

            let stat = try await Bridge.fileStatistics(context: ctx, path: path)
            #expect(stat.accessTime == UInt64(access.timeIntervalSince1970))
            #expect(stat.modificationTime == UInt64(write.timeIntervalSince1970))
            // Samba reports change time as server-maintained metadata ctime.
            #expect(stat.birthTime == UInt64(creation.timeIntervalSince1970))
        }
    }

    @Test("get and set file attributes") func getAndSetFileAttributes() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("setattr") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            let initial = try await Bridge.getFileAttributes(context: ctx, path: path)
            #expect(initial == 0x0000_0020) // SMB2_FILE_ATTRIBUTE_ARCHIVE

            try await Bridge.setStats(context: ctx, path: path, fileAttributes: 0x0000_0002)

            let updated = try await Bridge.getFileAttributes(context: ctx, path: path)
            #expect(updated == 0x0000_0002) // SMB2_FILE_ATTRIBUTE_HIDDEN
        }
    }

    @Test("set basic info on nonexistent file throws") func setBasicInfoOnNonexistentFileThrows() async throws {
        try await withPublicShare { ctx in
            await #expect(throws: SMB.Error.self) {
                try await Bridge.setStats(
                    context: ctx,
                    path: "nonexistent_\(uniquePath()).txt",
                    lastWriteTime: Date()
                )
            }
        }
    }
}

// MARK: - Server-side copy tests

@Suite(.tags(.integration))
struct ServerSideCopyTests {
    @Test("serverSideCopy copies known file") func serverSideCopyCopiesKnownFile() async throws {
        try await withPublicShare { ctx in
            let destPath = uniquePath("copy") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: destPath) }

            try await Bridge.serverSideCopy(context: ctx, sourcePath: TestContent.helloPath, destinationPath: destPath)

            let rh = try await Bridge.open(context: ctx, path: destPath)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let bytes = try await readAllBytes(context: ctx, file: rh)
            #expect(bytes == TestContent.helloBytes)
        }
    }

    @Test("serverSideCopy overwrites existing file") func serverSideCopyOverwritesExistingFile() async throws {
        try await withPublicShare { ctx in
            let destPath = uniquePath("copy") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: destPath) }

            let wh = try await Bridge.open(
                context: ctx,
                path: destPath,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            _ = try await writeAllBytes(context: ctx, file: wh, data: Array("WRONG CONTENT".utf8))
            try await Bridge.close(context: ctx, file: wh)

            try await Bridge.serverSideCopy(context: ctx, sourcePath: TestContent.helloPath, destinationPath: destPath)

            let rh = try await Bridge.open(context: ctx, path: destPath)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let bytes = try await readAllBytes(context: ctx, file: rh)
            #expect(bytes == TestContent.helloBytes)
        }
    }

    @Test("serverSideCopy copies empty file") func serverSideCopyCopiesEmptyFile() async throws {
        try await withPublicShare { ctx in
            let sourcePath = uniquePath("empty_source") + ".txt"
            let destPath = uniquePath("empty_dest") + ".txt"
            defer {
                try? await Bridge.unlink(context: ctx, path: sourcePath)
                try? await Bridge.unlink(context: ctx, path: destPath)
            }

            let wh = try await Bridge.open(
                context: ctx,
                path: sourcePath,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: ctx, file: wh)

            try await Bridge.serverSideCopy(context: ctx, sourcePath: sourcePath, destinationPath: destPath)

            let stat = try await Bridge.fileStatistics(context: ctx, path: destPath)
            #expect(stat.type == .file)
            #expect(stat.size == 0)
        }
    }

    @Test("serverSideCopy throws for nonexistent source") func serverSideCopyThrowsForNonexistentSource() async throws {
        try await withPublicShare { ctx in
            let destPath = uniquePath("copy") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: destPath) }

            await #expect(throws: SMB.Error.self) {
                try await Bridge.serverSideCopy(
                    context: ctx,
                    sourcePath: "nonexistent_\(uniquePath()).txt",
                    destinationPath: destPath
                )
            }
        }
    }
}

// MARK: - File lock tests

@Suite(.tags(.integration))
struct FileLockTests {
    @Test("lock shared succeeds") func lockSharedSucceeds() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("lock") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: ctx, file: wh) }
            try await Bridge.lock(context: ctx, file: wh, flags: .shared)
        }
    }

    @Test("lock exclusive succeeds") func lockExclusiveSucceeds() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("lock") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: ctx, file: wh) }
            try await Bridge.lock(context: ctx, file: wh, flags: .exclusive)
        }
    }

    @Test("unlock after lock succeeds") func unlockAfterLockSucceeds() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("lock") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.writeOnly, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: ctx, file: wh) }
            try await Bridge.lock(context: ctx, file: wh, flags: .exclusive)
            try await Bridge.unlock(context: ctx, file: wh)
        }
    }

    @Test("lock shared then exclusive on same handle succeeds") func lockSharedThenExclusiveOnSameHandleSucceeds(
    ) async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("lock") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: ctx, file: wh) }
            try await Bridge.lock(context: ctx, file: wh, flags: .shared)
            try await Bridge.unlock(context: ctx, file: wh)
            try await Bridge.lock(context: ctx, file: wh, flags: .exclusive)
            try await Bridge.unlock(context: ctx, file: wh)
        }
    }

    @Test("lock with offset and length succeeds") func lockWithOffsetAndLengthSucceeds() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("lock") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: ctx, file: wh) }
            try await Bridge.lock(context: ctx, file: wh, flags: .exclusive, offset: 10, length: 100)
            try await Bridge.unlock(context: ctx, file: wh, offset: 10, length: 100)
        }
    }
}
