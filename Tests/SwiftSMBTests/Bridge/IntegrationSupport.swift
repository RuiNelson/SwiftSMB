//
// Part of SwiftSMB
// IntegrationSupport.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: - Server configuration

let testServerHost = "localhost:44445"

enum TestShare {
    static let `public` = "public"
    static let `private` = "private"
    static let readonly = "readonly"
    static let hidden = "hidden$"
}

enum TestCredentials {
    static let user = "smbuser"
    static let password = "smbpass123"
    static let adminUser = "smbadmin"
    static let adminPassword = "smbadmin123"
}

// MARK: - Known test content (baked into the Dockerfile)

enum TestContent {
    static let helloPath = "testdir/hello.txt"
    static let helloBytes = Array("Hello, SMB!\n".utf8)

    static let nestedPath = "testdir/subdir/nested.dat"
    static let nestedBytes = Array("nested content\n".utf8)

    static let subdirPath = "testdir/subdir"
    static let testdirPath = "testdir"
    static let emptyDirPath = "empty_dir"

    static let linkToFilePath = "testdir/link_to_file"
    static let linkToDirPath = "testdir/link_to_dir"
}

// MARK: - Tag

extension Tag {
    @Tag static var integration: Self
}

// MARK: - Context helpers

@discardableResult
func withFreshContext<T>(_ body: (Bridge.Context) async throws -> T) async throws -> T {
    let ctx = try Bridge.createContext()
    defer { await Bridge.destroyContext(ctx) }
    return try await body(ctx)
}

private func withShare<T>(
    _ shareName: String,
    credentials: (user: String, password: String)? = nil,
    body: (Bridge.Context) async throws -> T
) async throws -> T {
    let ctx = try Bridge.createContext()
    if let credentials {
        try await Bridge.setUser(credentials.user, on: ctx)
        try await Bridge.setPassword(credentials.password, on: ctx)
    }
    try await Bridge.connectShare(context: ctx, server: testServerHost, share: shareName)
    defer {
        try? await Bridge.disconnectShare(context: ctx)
        await Bridge.destroyContext(ctx)
    }
    return try await body(ctx)
}

@discardableResult
func withPublicShare<T>(_ body: (Bridge.Context) async throws -> T) async throws -> T {
    try await withShare(TestShare.public, body: body)
}

@discardableResult
func withPrivateShare<T>(_ body: (Bridge.Context) async throws -> T) async throws -> T {
    try await withShare(TestShare.private, credentials: (TestCredentials.user, TestCredentials.password), body: body)
}

@discardableResult
func withReadonlyShare<T>(_ body: (Bridge.Context) async throws -> T) async throws -> T {
    try await withShare(TestShare.readonly, body: body)
}

// MARK: - Directory helpers

func allEntries(context: Bridge.Context, directory: Bridge.DirectoryHandle) async throws -> [Bridge.DirectoryEntry] {
    var entries: [Bridge.DirectoryEntry] = []
    while let entry = try await Bridge.readDir(context: context, directory: directory) {
        entries.append(entry)
    }
    return entries
}

func listDirectory(context: Bridge.Context, path: String) async throws -> [Bridge.DirectoryEntry] {
    let dir = try await Bridge.openDir(context: context, path: path)
    defer { try? await Bridge.closeDir(context: context, directory: dir) }
    return try await allEntries(context: context, directory: dir)
}

// MARK: - I/O helpers

func readAllBytes(context: Bridge.Context, file: Bridge.FileHandle, chunkSize: Int = 65536) async throws -> [UInt8] {
    var result: [UInt8] = []
    while true {
        let data = try await Bridge.read(context: context, file: file, count: chunkSize)
        guard !data.isEmpty else { break }
        result.append(contentsOf: data)
    }
    return result
}

func readSomeBytes(context: Bridge.Context, file: Bridge.FileHandle, count: Int) async throws -> [UInt8] {
    try await Array(Bridge.read(context: context, file: file, count: count))
}

func readSomeBytesAt(
    context: Bridge.Context,
    file: Bridge.FileHandle,
    count: Int,
    offset: UInt64
) async throws -> [UInt8] {
    try await Array(Bridge.read(context: context, file: file, count: count, offset: offset))
}

func writeAllBytes(context: Bridge.Context, file: Bridge.FileHandle, data: [UInt8]) async throws -> Int {
    try await Bridge.write(context: context, file: file, data: Data(data))
}

func writeAllBytesAt(
    context: Bridge.Context,
    file: Bridge.FileHandle,
    data: [UInt8],
    offset: UInt64
) async throws -> Int {
    try await Bridge.write(context: context, file: file, data: Data(data), offset: offset)
}

func writeAllBytesChunked(context: Bridge.Context, file: Bridge.FileHandle, data: [UInt8]) async throws -> Int {
    let chunkSize = try await min(65536, Int(Bridge.getMaxWriteSize(context: context)))
    var offset = 0
    while offset < data.count {
        let chunk = Array(data[offset ..< min(offset + chunkSize, data.count)])
        let n = try await writeAllBytesAt(context: context, file: file, data: chunk, offset: UInt64(offset))
        guard n > 0 else {
            throw SMB.Error.unknown(
                operation: "smb2_write",
                message: "Write made no progress before all test data was written"
            )
        }
        offset += n
    }
    return offset
}

// MARK: - Test isolation

func uniquePath(_ prefix: String = "test") -> String {
    "\(prefix)_\(String(UInt64.random(in: .min ... .max), radix: 16, uppercase: true).prefix(8))"
}
