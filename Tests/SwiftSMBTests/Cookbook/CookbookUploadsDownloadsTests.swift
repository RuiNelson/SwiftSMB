//
// Part of SwiftSMB
// CookbookUploadsDownloadsTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookUploadsDownloadsTests {
    @Test("uploadFile with maxBlockSize compiles and runs")
    func uploadFileWithChunkSize() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let localURL = try cookbookTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: localURL) }
        try Data("report".utf8).write(to: localURL)

        let remote = uniquePath("cookbook-upload-chunk") + ".pdf"
        defer { try? await connection.removeFile(at: remote) }

        try await connection.uploadFile(
            local: localURL,
            remote: remote,
            maxBlockSize: UInt64(256 * 1024)
        ) { _, _, _, _ in true }
    }

    @Test("downloadFile compiles and runs")
    func downloadFile() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let remote = uniquePath("cookbook-download") + ".pdf"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("report".utf8), to: remote)

        let localURL = try cookbookTemporaryFileURL()
        try? FileManager.default.removeItem(at: localURL)
        defer { try? FileManager.default.removeItem(at: localURL) }

        try await connection.downloadFile(
            remote: remote,
            local: localURL
        ) { completed, total, latestSpeed, averageSpeed in
            _ = completed
            _ = total
            return true
        }
    }

    @Test("downloadFile with async progress compiles and runs")
    func downloadFileWithAsyncProgress() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let remote = uniquePath("cookbook-download-async") + ".pdf"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(Data("report".utf8), to: remote)

        let localURL = try cookbookTemporaryFileURL()
        try? FileManager.default.removeItem(at: localURL)
        defer { try? FileManager.default.removeItem(at: localURL) }

        let status = CookbookTransferStatus()

        try await connection.downloadFile(
            remote: remote,
            local: localURL
        ) { completed, _, _, _ in
            await status.update(completed)
            return true
        }

        #expect(await status.completed == 6)
    }

    @Test("loadFile compiles and runs")
    func loadFile() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let data = try await connection.loadFile(at: "report.pdf")
        _ = data.count
    }

    @Test("dumpToFile compiles and runs")
    func dumpToFile() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let payload = Data("Hello, SMB!".utf8)
        let remote = uniquePath("cookbook-dump") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(payload, to: remote)
    }

    @Test("dumpToFile with options compiles and runs")
    func dumpToFileWithOptions() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let payload = Data("Hello, SMB!".utf8)
        let remote = uniquePath("cookbook-append") + ".txt"
        defer { try? await connection.removeFile(at: remote) }
        try await connection.dumpToFile(payload, to: remote)
        try await connection.dumpToFile(
            payload,
            to: remote,
            options: [.create, .append]
        )
    }

    @Test("acceptedReadBlockSize compiles and runs")
    func acceptedReadBlockSize() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let maxRead = try await connection.acceptedReadBlockSize(128 * 1024 * 1024)
        _ = maxRead
        let data = try await connection.loadFile(at: "report.pdf", chunkSize: maxRead)
        _ = data.count
    }
}

/// The actor from the "Awaiting inside the progress closure" example in `docs/uploads-downloads.md`.
private actor CookbookTransferStatus {
    var completed: UInt64 = 0
    func update(_ completed: UInt64) {
        self.completed = completed
    }
}
