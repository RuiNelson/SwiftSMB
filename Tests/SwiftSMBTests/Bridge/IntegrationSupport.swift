//
// Part of SwiftSMB
// IntegrationSupport.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Darwin
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
func withFreshContext<T>(_ body: (Bridge.Context) throws -> T) throws -> T {
    let ctx = try Bridge.createContext()
    defer { Bridge.destroyContext(ctx) }
    return try body(ctx)
}

private func withShare<T>(
    _ shareName: String,
    credentials: (user: String, password: String)? = nil,
    body: (Bridge.Context) throws -> T,
) throws -> T {
    let ctx = try Bridge.createContext()
    if let credentials {
        Bridge.setUser(credentials.user, on: ctx)
        Bridge.setPassword(credentials.password, on: ctx)
    }
    try Bridge.connectShare(context: ctx, server: testServerHost, share: shareName)
    defer {
        try? Bridge.disconnectShare(context: ctx)
        Bridge.destroyContext(ctx)
    }
    return try body(ctx)
}

@discardableResult
func withPublicShare<T>(_ body: (Bridge.Context) throws -> T) throws -> T {
    try withShare(TestShare.public, body: body)
}

@discardableResult
func withPrivateShare<T>(_ body: (Bridge.Context) throws -> T) throws -> T {
    try withShare(TestShare.private, credentials: (TestCredentials.user, TestCredentials.password), body: body)
}

@discardableResult
func withReadonlyShare<T>(_ body: (Bridge.Context) throws -> T) throws -> T {
    try withShare(TestShare.readonly, body: body)
}

// MARK: - Directory helpers

func allEntries(context: Bridge.Context, directory: Bridge.DirectoryHandle) -> [Bridge.DirectoryEntry] {
    var entries: [Bridge.DirectoryEntry] = []
    while let entry = Bridge.readDir(context: context, directory: directory) {
        entries.append(entry)
    }
    return entries
}

func listDirectory(context: Bridge.Context, path: String) throws -> [Bridge.DirectoryEntry] {
    let dir = try Bridge.openDir(context: context, path: path)
    defer { Bridge.closeDir(context: context, directory: dir) }
    return allEntries(context: context, directory: dir)
}

// MARK: - I/O helpers

func readAllBytes(context: Bridge.Context, file: Bridge.FileHandle, chunkSize: Int = 65536) throws -> [UInt8] {
    var result: [UInt8] = []
    var buffer = [UInt8](repeating: 0, count: chunkSize)
    while true {
        let n = try buffer.withUnsafeMutableBytes { rawBuf in
            try Bridge.read(context: context, file: file, into: MutableRawSpan(_unsafeBytes: rawBuf))
        }
        guard n > 0 else { break }
        result.append(contentsOf: buffer.prefix(n))
    }
    return result
}

func readSomeBytes(context: Bridge.Context, file: Bridge.FileHandle, count: Int) throws -> [UInt8] {
    var buffer = [UInt8](repeating: 0, count: count)
    let n = try buffer.withUnsafeMutableBytes { rawBuf in
        try Bridge.read(context: context, file: file, into: MutableRawSpan(_unsafeBytes: rawBuf))
    }
    buffer.removeLast(count - n)
    return buffer
}

func readSomeBytesAt(
    context: Bridge.Context,
    file: Bridge.FileHandle,
    count: Int,
    offset: UInt64,
) throws -> [UInt8] {
    var buffer = [UInt8](repeating: 0, count: count)
    let n = try buffer.withUnsafeMutableBytes { rawBuf in
        try Bridge.read(context: context, file: file, into: MutableRawSpan(_unsafeBytes: rawBuf), offset: offset)
    }
    buffer.removeLast(count - n)
    return buffer
}

func writeAllBytes(context: Bridge.Context, file: Bridge.FileHandle, data: [UInt8]) throws -> Int {
    try data.withUnsafeBytes { rawBuf in
        try Bridge.write(context: context, file: file, bytes: RawSpan(_unsafeBytes: rawBuf))
    }
}

func writeAllBytesAt(
    context: Bridge.Context,
    file: Bridge.FileHandle,
    data: [UInt8],
    offset: UInt64,
) throws -> Int {
    try data.withUnsafeBytes { rawBuf in
        try Bridge.write(context: context, file: file, bytes: RawSpan(_unsafeBytes: rawBuf), offset: offset)
    }
}

func writeAllBytesChunked(context: Bridge.Context, file: Bridge.FileHandle, data: [UInt8]) throws -> Int {
    let chunkSize = min(65536, Int(Bridge.getMaxWriteSize(context: context)))
    var offset = 0
    while offset < data.count {
        let chunk = Array(data[offset ..< min(offset + chunkSize, data.count)])
        let n = try writeAllBytesAt(context: context, file: file, data: chunk, offset: UInt64(offset))
        guard n > 0 else {
            throw SMB.Error.unknown(
                operation: "smb2_write",
                message: "Write made no progress before all test data was written",
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
