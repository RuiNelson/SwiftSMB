//
// Part of SwiftSMB
// OpLockTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: - Bridge open with oplock/lease

@Suite(.tags(.integration))
struct OpLockBridgeTests {
    @Test("open with none oplock level succeeds") func openWithNoneOpLockLevelSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "oplock-none") { path, content in
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .none,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with levelII oplock succeeds") func openWithLevelIIOpLockSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "oplock-levelII") { path, content in
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .levelII,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with batch oplock succeeds") func openWithBatchOpLockSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "oplock-batch") { path, content in
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .batch,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with exclusive oplock succeeds") func openWithExclusiveOpLockSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "oplock-exclusive") { path, content in
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .exclusive,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with lease read caching succeeds") func openWithLeaseReadCachingSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "lease-read") { path, content in
                let leaseKey = Data((0 ..< 16).map { UInt8($0) })
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .lease,
                    leaseState: .readCaching,
                    leaseKey: leaseKey,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with lease read and handle caching succeeds") func openWithLeaseReadHandleCachingSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "lease-handle") { path, content in
                let leaseKey = Data((0 ..< 16).map { UInt8($0) })
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .lease,
                    leaseState: [.readCaching, .handleCaching],
                    leaseKey: leaseKey,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with lease full state succeeds") func openWithLeaseFullStateSucceeds() throws {
        try withPublicShare { ctx in
            try withBridgeFixtureFile(context: ctx, prefix: "lease-full") { path, content in
                let leaseKey = Data((0 ..< 16).map { UInt8($0) })
                let handle = try Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .lease,
                    leaseState: [.readCaching, .handleCaching, .writeCaching],
                    leaseKey: leaseKey,
                )
                defer { try? Bridge.close(context: ctx, file: handle) }
                let bytes = try readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with oplock then write and read back") func openWithOpLockThenWriteAndReadBack() throws {
        try withPublicShare { ctx in
            let path = uniquePath("oplock") + ".txt"
            defer { try? Bridge.unlink(context: ctx, path: path) }

            let content = Array("oplock write test".utf8)

            let wh = try Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive]),
                opLockLevel: .batch,
            )
            _ = try writeAllBytes(context: ctx, file: wh, data: content)
            try Bridge.close(context: ctx, file: wh)

            let rh = try Bridge.open(context: ctx, path: path)
            defer { try? Bridge.close(context: ctx, file: rh) }
            let readBack = try readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }

    @Test("open with lease then write and read back") func openWithLeaseThenWriteAndReadBack() throws {
        try withPublicShare { ctx in
            let path = uniquePath("lease") + ".txt"
            defer { try? Bridge.unlink(context: ctx, path: path) }

            let content = Array("lease write test".utf8)
            let leaseKey = Data((0 ..< 16).map { UInt8($0) })

            let wh = try Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive]),
                opLockLevel: .lease,
                leaseState: [.readCaching, .handleCaching, .writeCaching],
                leaseKey: leaseKey,
            )
            _ = try writeAllBytes(context: ctx, file: wh, data: content)
            try Bridge.close(context: ctx, file: wh)

            let rh = try Bridge.open(context: ctx, path: path)
            defer { try? Bridge.close(context: ctx, file: rh) }
            let readBack = try readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }

    @Test("open without lease key falls back to non-lease path") func openWithoutLeaseKeyFallsBack() throws {
        try withPublicShare { ctx in
            // lease level but no lease key → treated as plain open
            let handle = try Bridge.open(
                context: ctx,
                path: TestContent.helloPath,
                flags: Bridge.OpenFlags(.readOnly),
                opLockLevel: .lease,
                leaseState: .readCaching,
                leaseKey: nil,
            )
            defer { try? Bridge.close(context: ctx, file: handle) }
            let bytes = try readAllBytes(context: ctx, file: handle)
            #expect(bytes == TestContent.helloBytes)
        }
    }
}

private func withBridgeFixtureFile<T>(
    context: Bridge.Context,
    prefix: String,
    body: (String, [UInt8]) throws -> T,
) throws -> T {
    let path = uniquePath(prefix) + ".txt"
    let content = TestContent.helloBytes
    let writer = try Bridge.open(
        context: context,
        path: path,
        flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive]),
    )
    _ = try writeAllBytes(context: context, file: writer, data: content)
    try Bridge.close(context: context, file: writer)
    defer { try? Bridge.unlink(context: context, path: path) }
    return try body(path, content)
}
