//
// Part of SwiftSMB
// CookbookReadmeTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CookbookReadmeTests {
    @Test("listShares compiles and runs")
    func listSharesCompilesAndRuns() async throws {
        let server = SMB.Server(host: cookbookServerHost)
        let credentials = SMB.Credentials(user: "Anna", password: "1987")
        let shares = try await SMB.listShares(
            server: server,
            credentials: credentials
        )
        for share in shares {
            _ = share.name
        }
    }

    @Test("connect compiles and runs")
    func connectCompilesAndRuns() async throws {
        let server = SMB.Server(host: cookbookServerHost)
        let credentials = SMB.Credentials(user: "Anna", password: "1987")
        let connection = try await SMB.connect(
            server: server,
            credentials: credentials,
            share: "Documents"
        )
        defer { try? await connection.disconnect() }
        _ = connection.isConnected
    }

    @Test("listDirectory compiles and runs")
    func listDirectoryCompilesAndRuns() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }
        let entries = try await connection.listDirectory(at: "Anna/Inbox")
        for entry in entries {
            _ = entry.name
        }
    }

    @Test("uploadFile compiles and runs")
    func uploadFileCompilesAndRuns() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let localURL = try cookbookTemporaryFileURL()
        defer { try? FileManager.default.removeItem(at: localURL) }
        try Data("report".utf8).write(to: localURL)

        let remote = uniquePath("cookbook-readme-upload") + ".pdf"
        defer { try? await connection.removeFile(at: remote) }

        try await connection.uploadFile(
            local: localURL,
            remote: remote
        ) { completed, total, lastBlockSpeed, averageSpeed in
            let speed = 0.5 * lastBlockSpeed + 0.5 * averageSpeed
            _ = speed
            return true
        }
    }

    @Test("downloadFile compiles and runs")
    func downloadFileCompilesAndRuns() async throws {
        let connection = try await cookbookConnection()
        defer { try? await connection.disconnect() }

        let remote = uniquePath("cookbook-readme-download") + ".pdf"
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
            _ = latestSpeed
            _ = averageSpeed
            return true
        }
    }
}
