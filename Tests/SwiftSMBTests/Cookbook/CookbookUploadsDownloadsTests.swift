//
// Part of SwiftSMB
// CookbookUploadsDownloadsTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookUploadsDownloadsTests {
    @Test("uploadFile with maxBlockSize compiles and runs")
    func uploadFileWithChunkSize() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }

        let localURL = try cookbookTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: localURL) }
        try Data("report".utf8).write(to: localURL)

        let remote = uniquePath("cookbook-upload-chunk") + ".pdf"
        defer { try? connection.removeFile(at: remote) }

        try connection.uploadFile(
            local: localURL,
            remote: remote,
            maxBlockSize: UInt64(256 * 1024),
        ) { _, _, _, _ in true }
    }

    @Test("downloadFile compiles and runs")
    func downloadFile() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }

        let remote = uniquePath("cookbook-download") + ".pdf"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(Data("report".utf8), to: remote)

        let localURL = try cookbookTemporaryFileURL()
        try? FileManager.default.removeItem(at: localURL)
        defer { try? FileManager.default.removeItem(at: localURL) }

        try connection.downloadFile(
            remote: remote,
            local: localURL,
        ) { completed, total, latestSpeed, averageSpeed in
            _ = completed
            _ = total
            return true
        }
    }

    @Test("loadFile compiles and runs")
    func loadFile() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let data = try connection.loadFile(at: "report.pdf")
        _ = data.count
    }

    @Test("dumpToFile compiles and runs")
    func dumpToFile() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let payload = Data("Hello, SMB!".utf8)
        let remote = uniquePath("cookbook-dump") + ".txt"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(payload, to: remote)
    }

    @Test("dumpToFile with options compiles and runs")
    func dumpToFileWithOptions() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let payload = Data("Hello, SMB!".utf8)
        let remote = uniquePath("cookbook-append") + ".txt"
        defer { try? connection.removeFile(at: remote) }
        try connection.dumpToFile(payload, to: remote)
        try connection.dumpToFile(
            payload,
            to: remote,
            options: [.create, .append],
        )
    }

    @Test("acceptedReadBlockSize compiles and runs")
    func acceptedReadBlockSize() throws {
        let connection = try cookbookConnection()
        defer { try? connection.disconnect() }
        let maxRead = try connection.acceptedReadBlockSize(128 * 1024 * 1024)
        _ = maxRead
        let data = try connection.loadFile(at: "report.pdf", chunkSize: maxRead)
        _ = data.count
    }
}
