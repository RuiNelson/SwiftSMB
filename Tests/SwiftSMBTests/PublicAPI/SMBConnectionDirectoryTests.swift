//
// Part of SwiftSMB
// SMBConnectionDirectoryTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionDirectoryTests {
    @Test("makeDirectory makePath creates ancestors")
    func makeDirectoryMakePathCreatesAncestors() throws {
        let connection = try publicDirectoryConnection()
        defer { try? connection.disconnect() }

        let root = uniquePath("make-path")
        let path = root + "/one/two/three"
        defer { try? connection.removeItem(at: root) }

        try connection.makeDirectory(at: path, makePath: true)

        #expect(try connection.stat(at: root).type == .directory)
        #expect(try connection.stat(at: root + "/one").type == .directory)
        #expect(try connection.stat(at: root + "/one/two").type == .directory)
        #expect(try connection.stat(at: path).type == .directory)
    }

    @Test("makeDirectory without makePath still requires parent")
    func makeDirectoryWithoutMakePathStillRequiresParent() throws {
        let connection = try publicDirectoryConnection()
        defer { try? connection.disconnect() }

        let path = uniquePath("make-dir-no-parent") + "/child"

        #expect(throws: SMB.Error.self) {
            try connection.makeDirectory(at: path)
        }
    }

    @Test("makeDirectory makePath still fails when target exists")
    func makeDirectoryMakePathStillFailsWhenTargetExists() throws {
        let connection = try publicDirectoryConnection()
        defer { try? connection.disconnect() }

        let root = uniquePath("make-path-existing")
        let path = root + "/one"
        defer { try? connection.removeItem(at: root) }

        try connection.makeDirectory(at: path, makePath: true)

        #expect(throws: SMB.Error.self) {
            try connection.makeDirectory(at: path, makePath: true)
        }
    }

    @Test("makeDirectory makePath accepts leading slash")
    func makeDirectoryMakePathAcceptsLeadingSlash() throws {
        let connection = try publicDirectoryConnection()
        defer { try? connection.disconnect() }

        let root = uniquePath("make-path-leading")
        let path = root + "/one/two"
        defer { try? connection.removeItem(at: root) }

        try connection.makeDirectory(at: "/" + path, makePath: true)

        #expect(try connection.stat(at: path).type == .directory)
    }

    @Test("itemExists reports item state")
    func itemExistsReportsItemState() throws {
        let connection = try publicDirectoryConnection()
        defer { try? connection.disconnect() }

        let directory = uniquePath("directory-exists")
        let file = uniquePath("directory-exists-file") + ".txt"
        defer { try? connection.removeDirectory(at: directory) }
        defer { try? connection.removeFile(at: file) }

        try connection.makeDirectory(at: directory)
        try connection.writeFile(Data("not a directory".utf8), to: file)

        #expect(try connection.itemExists(at: directory) == .directory)
        #expect(try connection.itemExists(at: "/" + directory) == .directory)
        #expect(try connection.itemExists(at: file) == .file)
        #expect(try connection.itemExists(at: uniquePath("directory-missing")) == .false)
    }

    @Test("makeDirectory makePath fails when ancestor is not directory")
    func makeDirectoryMakePathFailsWhenAncestorIsNotDirectory() throws {
        let connection = try publicDirectoryConnection()
        defer { try? connection.disconnect() }

        let file = uniquePath("make-path-file") + ".txt"
        defer { try? connection.removeFile(at: file) }

        try connection.writeFile(Data("not a directory".utf8), to: file)

        #expect(throws: SMB.Error.self) {
            try connection.makeDirectory(at: file + "/child", makePath: true)
        }
    }
}

private func publicDirectoryConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public,
    )
}
