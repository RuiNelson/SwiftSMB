//
// Part of SwiftSMB
// BridgeHandleRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite(.tags(.integration))
struct BridgeHandleRegressionTests {
    @Test("negative directory positions are rejected without moving the stream")
    func negativeDirectoryPositionsRejected() async throws {
        try await withPublicShare { context in
            let directory = try await Bridge.openDir(context: context, path: "")
            defer { try? await Bridge.closeDir(context: context, directory: directory) }
            #expect(try await Bridge.tellDir(context: context, directory: directory) == 0)
            await #expect(throws: SMB.Error.self) {
                try await Bridge.seekDir(context: context, directory: directory, location: -1)
            }
            #expect(try await Bridge.tellDir(context: context, directory: directory) == 0)
        }
    }

    @Test("positional reads and writes preserve the sequential offset")
    func positionalIOPreservesOffset() async throws {
        try await withPublicShare { context in
            let path = uniquePath() + ".txt"
            defer { try? await Bridge.unlink(context: context, path: path) }
            let file = try await Bridge.open(
                context: context,
                path: path,
                flags: .init(.readWrite, options: [.create, .exclusive])
            )
            defer { try? await Bridge.close(context: context, file: file) }
            _ = try await Bridge.write(context: context, file: file, data: Data("abcdef".utf8))
            _ = try await Bridge.seek(context: context, file: file, offset: 1, whence: SEEK_SET)
            #expect(try await Bridge.read(context: context, file: file, count: 2, offset: 3) == Data("de".utf8))
            #expect(try await Bridge.seek(context: context, file: file, offset: 0, whence: SEEK_CUR) == 1)
            #expect(try await Bridge.write(context: context, file: file, data: Data("xy".utf8), offset: 3) == 2)
            #expect(try await Bridge.seek(context: context, file: file, offset: 0, whence: SEEK_CUR) == 1)
            #expect(try await Bridge.read(context: context, file: file, count: 5) == Data("bcxyf".utf8))
        }
    }

    @Test("append handles preserve existing data after reopen and seek")
    func appendAfterReopenAndSeek() async throws {
        try await withPublicShare { context in
            let path = uniquePath() + ".txt"
            defer { try? await Bridge.unlink(context: context, path: path) }
            let original = try await Bridge.open(
                context: context,
                path: path,
                flags: .init(.writeOnly, options: [.create, .exclusive])
            )
            _ = try await Bridge.write(context: context, file: original, data: Data("before".utf8))
            #expect(try await Bridge.seek(context: context, file: original, offset: 0, whence: SEEK_END) == 6)
            try await Bridge.close(context: context, file: original)

            let appended = try await Bridge.open(
                context: context,
                path: path,
                flags: .init(.writeOnly, options: [.append])
            )
            defer { try? await Bridge.close(context: context, file: appended) }
            #expect(try await Bridge.seek(context: context, file: appended, offset: 0, whence: SEEK_END) == 6)
            _ = try await Bridge.write(context: context, file: appended, data: Data("-middle".utf8))
            _ = try await Bridge.seek(context: context, file: appended, offset: 0, whence: SEEK_SET)
            _ = try await Bridge.write(context: context, file: appended, data: Data("-after".utf8))
            try await Bridge.close(context: context, file: appended)

            let reader = try await Bridge.open(context: context, path: path)
            defer { try? await Bridge.close(context: context, file: reader) }
            #expect(try await Bridge
                .read(context: context, file: reader, count: 100) == Data("before-middle-after".utf8))
        }
    }

    @Test("failed relative seek preserves the current offset")
    func failedSeekPreservesOffset() async throws {
        try await withPublicShare { context in
            let file = try await Bridge.open(context: context, path: TestContent.helloPath)
            defer { try? await Bridge.close(context: context, file: file) }
            await #expect(throws: SMB.Error.self) {
                try await Bridge.seek(context: context, file: file, offset: -1, whence: SEEK_CUR)
            }
            #expect(try await Bridge.seek(context: context, file: file, offset: 0, whence: SEEK_CUR) == 0)
            #expect(try await Bridge.read(context: context, file: file, count: 1) == Data([TestContent.helloBytes[0]]))
            await #expect(throws: SMB.Error.self) {
                try await Bridge.seek(context: context, file: file, offset: -100, whence: SEEK_END)
            }
            #expect(try await Bridge.seek(context: context, file: file, offset: 0, whence: SEEK_CUR) == 1)
            _ = try await Bridge.seek(context: context, file: file, offset: Int64.max, whence: SEEK_SET)
            await #expect(throws: SMB.Error.self) {
                try await Bridge.seek(context: context, file: file, offset: 1, whence: SEEK_CUR)
            }
            #expect(try await Bridge
                .seek(context: context, file: file, offset: 0, whence: SEEK_CUR) == UInt64(Int64.max))
        }
    }

    @Test("explicit Unix epoch modification time reaches the server")
    func unixEpochModificationTime() async throws {
        try await withPublicShare { context in
            let path = uniquePath() + ".txt"
            defer { try? await Bridge.unlink(context: context, path: path) }
            let file = try await Bridge.open(
                context: context,
                path: path,
                flags: .init(.writeOnly, options: [.create, .exclusive])
            )
            try await Bridge.close(context: context, file: file)
            try await Bridge.setStats(context: context, path: path, lastWriteTime: Date(timeIntervalSince1970: 0))
            #expect(try await Bridge.fileStatistics(context: context, path: path).modificationTime == 0)
        }
    }
}
