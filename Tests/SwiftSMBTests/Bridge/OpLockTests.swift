//
// Part of SwiftSMB
// OpLockTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: - Bridge open with oplock/lease

@Suite(.tags(.integration))
struct OpLockBridgeTests {
    @Test("open with none oplock level succeeds") func openWithNoneOpLockLevelSucceeds() async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "oplock-none") { path, content in
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .none
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with levelII oplock succeeds") func openWithLevelIIOpLockSucceeds() async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "oplock-levelII") { path, content in
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .levelII
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with batch oplock succeeds") func openWithBatchOpLockSucceeds() async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "oplock-batch") { path, content in
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .batch
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with exclusive oplock succeeds") func openWithExclusiveOpLockSucceeds() async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "oplock-exclusive") { path, content in
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .exclusive
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with lease read caching succeeds") func openWithLeaseReadCachingSucceeds() async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "lease-read") { path, content in
                let leaseKey = Data((0 ..< 16).map { UInt8($0) })
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .lease,
                    leaseState: .readCaching,
                    leaseKey: leaseKey
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with lease read and handle caching succeeds") func openWithLeaseReadHandleCachingSucceeds(
    ) async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "lease-handle") { path, content in
                let leaseKey = Data((0 ..< 16).map { UInt8($0) })
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .lease,
                    leaseState: [.readCaching, .handleCaching],
                    leaseKey: leaseKey
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with lease full state succeeds") func openWithLeaseFullStateSucceeds() async throws {
        try await withPublicShare { ctx in
            try await withBridgeFixtureFile(context: ctx, prefix: "lease-full") { path, content in
                let leaseKey = Data((0 ..< 16).map { UInt8($0) })
                let handle = try await Bridge.open(
                    context: ctx,
                    path: path,
                    flags: Bridge.OpenFlags(.readOnly),
                    opLockLevel: .lease,
                    leaseState: [.readCaching, .handleCaching, .writeCaching],
                    leaseKey: leaseKey
                )
                defer { try? await Bridge.close(context: ctx, file: handle) }
                let bytes = try await readAllBytes(context: ctx, file: handle)
                #expect(bytes == content)
            }
        }
    }

    @Test("open with oplock then write and read back") func openWithOpLockThenWriteAndReadBack() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("oplock") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let content = Array("oplock write test".utf8)

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive]),
                opLockLevel: .batch
            )
            _ = try await writeAllBytes(context: ctx, file: wh, data: content)
            try await Bridge.close(context: ctx, file: wh)

            let rh = try await Bridge.open(context: ctx, path: path)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let readBack = try await readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }

    @Test("open with lease then write and read back") func openWithLeaseThenWriteAndReadBack() async throws {
        try await withPublicShare { ctx in
            let path = uniquePath("lease") + ".txt"
            defer { try? await Bridge.unlink(context: ctx, path: path) }

            let content = Array("lease write test".utf8)
            let leaseKey = Data((0 ..< 16).map { UInt8($0) })

            let wh = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive]),
                opLockLevel: .lease,
                leaseState: [.readCaching, .handleCaching, .writeCaching],
                leaseKey: leaseKey
            )
            _ = try await writeAllBytes(context: ctx, file: wh, data: content)
            try await Bridge.close(context: ctx, file: wh)

            let rh = try await Bridge.open(context: ctx, path: path)
            defer { try? await Bridge.close(context: ctx, file: rh) }
            let readBack = try await readAllBytes(context: ctx, file: rh)
            #expect(readBack == content)
        }
    }

    @Test("open without lease key falls back to non-lease path") func openWithoutLeaseKeyFallsBack() async throws {
        try await withPublicShare { ctx in
            // lease level but no lease key → treated as plain open
            let handle = try await Bridge.open(
                context: ctx,
                path: TestContent.helloPath,
                flags: Bridge.OpenFlags(.readOnly),
                opLockLevel: .lease,
                leaseState: .readCaching,
                leaseKey: nil
            )
            defer { try? await Bridge.close(context: ctx, file: handle) }
            let bytes = try await readAllBytes(context: ctx, file: handle)
            #expect(bytes == TestContent.helloBytes)
        }
    }
}

private func withBridgeFixtureFile<T>(
    context: Bridge.Context,
    prefix: String,
    body: (String, [UInt8]) async throws -> T
) async throws -> T {
    let path = uniquePath(prefix) + ".txt"
    let content = TestContent.helloBytes
    let writer = try await Bridge.open(
        context: context,
        path: path,
        flags: Bridge.OpenFlags(.readWrite, options: [.create, .exclusive])
    )
    _ = try await writeAllBytes(context: context, file: writer, data: content)
    try await Bridge.close(context: context, file: writer)
    defer { try? await Bridge.unlink(context: context, path: path) }
    return try await body(path, content)
}
