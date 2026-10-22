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

    @Test("directory contains(where:) stops after the first match")
    func directoryContainsStopsAfterFirstMatch() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = try await makeDirectoryWithFiles(["a.txt", "b.txt", "c.txt"], on: connection)
        defer { try? await connection.removeItem(at: root) }

        let directory = try await connection.openDirectory(at: root)
        defer { await directory.close() }

        #expect(try await directory.contains { $0.name == "b.txt" })
        let remaining = try await directory.readAll().map(\.name)
        #expect(!remaining.contains("b.txt"))
    }

    @Test("directory contains(where:) exhausts the stream without a match")
    func directoryContainsExhaustsStreamWithoutMatch() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = try await makeDirectoryWithFiles(["a.txt"], on: connection)
        defer { try? await connection.removeItem(at: root) }

        let directory = try await connection.openDirectory(at: root)
        defer { await directory.close() }

        #expect(try await !directory.contains { $0.name == "missing.txt" })
        #expect(try await directory.readNext() == nil)

        try await directory.rewind()
        #expect(try await directory.contains { $0.name == "a.txt" })
    }

    @Test("directory contains(where:) propagates predicate errors")
    func directoryContainsPropagatesPredicateErrors() async throws {
        struct PredicateError: Error, Equatable {
        }

        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = try await makeDirectoryWithFiles(["a.txt"], on: connection)
        defer { try? await connection.removeItem(at: root) }

        let directory = try await connection.openDirectory(at: root)
        defer { await directory.close() }

        await #expect(throws: PredicateError()) {
            try await directory.contains { _ in throw PredicateError() }
        }
    }

    @Test("directory contains(where:) awaits an async predicate")
    func directoryContainsAwaitsAsyncPredicate() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = try await makeDirectoryWithFiles(["small.txt", "large.txt"], on: connection)
        defer { try? await connection.removeItem(at: root) }
        try await connection.dumpToFile(Data(repeating: 1, count: 32), to: root + "/large.txt")

        let directory = try await connection.openDirectory(at: root)
        defer { await directory.close() }

        let found = try await directory.contains { entry in
            guard entry.stat.type == .file else { return false }
            return try await connection.stat(at: root + "/" + entry.name).size == 32
        }
        #expect(found)
    }

    @Test("directory contains(where:) checks cancellation before reading")
    func directoryContainsChecksCancellationBeforeReading() async throws {
        let connection = try await publicDirectoryConnection()
        defer { try? await connection.disconnect() }

        let root = try await makeDirectoryWithFiles(["a.txt"], on: connection)
        defer { try? await connection.removeItem(at: root) }

        let directory = try await connection.openDirectory(at: root)
        defer { await directory.close() }

        let search = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await directory.contains { _ in true }
        }
        await #expect(throws: CancellationError.self) {
            try await search.value
        }
        #expect(try await directory.readAll().map(\.name).contains("a.txt"))
    }
}

/// Creates a uniquely named directory containing empty files with the given names, and returns its path.
private func makeDirectoryWithFiles(_ names: [String], on connection: SMB.Connection) async throws -> String {
    let root = uniquePath("contains")
    try await connection.makeDirectory(at: root)
    for name in names {
        try await connection.dumpToFile(Data(), to: root + "/" + name)
    }
    return root
}

private func publicDirectoryConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
