//
// Part of SwiftSMB
// SMBConnectionDirectoryTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionDirectoryTests {
    @Test("makeDirectory makePath creates ancestors")
    func makeDirectoryMakePathCreatesAncestors() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("make-path")
        let path = root + "/one/two/three"
        defer { try? await connection.removeItem(at: root) }

        try await connection.makeDirectory(at: path, makePath: true)

        await #expect(try connection.stat(at: root).type == .directory)
        await #expect(try connection.stat(at: root + "/one").type == .directory)
        await #expect(try connection.stat(at: root + "/one/two").type == .directory)
        await #expect(try connection.stat(at: path).type == .directory)
    }

    @Test("makeDirectory without makePath still requires parent")
    func makeDirectoryWithoutMakePathStillRequiresParent() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let path = uniquePath("make-dir-no-parent") + "/child"

        await #expect(throws: SMB.Error.self) {
            try await connection.makeDirectory(at: path)
        }
    }

    @Test("makeDirectory makePath still fails when target exists")
    func makeDirectoryMakePathStillFailsWhenTargetExists() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("make-path-existing")
        let path = root + "/one"
        defer { try? await connection.removeItem(at: root) }

        try await connection.makeDirectory(at: path, makePath: true)

        await #expect(throws: SMB.Error.self) {
            try await connection.makeDirectory(at: path, makePath: true)
        }
    }

    @Test("makeDirectory makePath accepts leading slash")
    func makeDirectoryMakePathAcceptsLeadingSlash() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = uniquePath("make-path-leading")
        let path = root + "/one/two"
        defer { try? await connection.removeItem(at: root) }

        try await connection.makeDirectory(at: "/" + path, makePath: true)

        await #expect(try connection.stat(at: path).type == .directory)
    }

    @Test("itemExists reports item state")
    func itemExistsReportsItemState() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let directory = uniquePath("directory-exists")
        let file = uniquePath("directory-exists-file") + ".txt"
        defer { try? await connection.removeDirectory(at: directory) }
        defer { try? await connection.removeFile(at: file) }

        try await connection.makeDirectory(at: directory)
        try await connection.dumpToFile(Data("not a directory".utf8), to: file)

        await #expect(try connection.itemExists(at: directory) == .directory)
        await #expect(try connection.itemExists(at: "/" + directory) == .directory)
        await #expect(try connection.itemExists(at: file) == .file)
        await #expect(try connection.itemExists(at: uniquePath("directory-missing")) == .false)
    }

    @Test("makeDirectory makePath fails when ancestor is not directory")
    func makeDirectoryMakePathFailsWhenAncestorIsNotDirectory() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let file = uniquePath("make-path-file") + ".txt"
        defer { try? await connection.removeFile(at: file) }

        try await connection.dumpToFile(Data("not a directory".utf8), to: file)

        await #expect(throws: SMB.Error.self) {
            try await connection.makeDirectory(at: file + "/child", makePath: true)
        }
    }
}

private func publicDirectoryConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
