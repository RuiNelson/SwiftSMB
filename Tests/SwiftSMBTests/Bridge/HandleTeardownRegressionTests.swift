//
// Part of SwiftSMB
// HandleTeardownRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Dispatch
import Testing

@Suite(.tags(.integration))
struct HandleTeardownRegressionTests {
    @Test("shutdown releases retained file and directory storage before late close")
    func shutdownInvalidatesRetainedHandles() async throws {
        try await withPublicShare { context in
            let (files, directories) = try await openTeardownRegressionHandles(on: context)

            try await Bridge.shutdown(context)
            try await assertTeardownRegressionHandlesClosed(files, directories: directories, on: context)

            // Late explicit closes must remain safe even though shutdown already freed the C allocations.
            for file in files {
                await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
                    try await Bridge.close(context: context, file: file)
                }
            }
            for directory in directories {
                await #expect(throws: SMB.Error.operationRequestedAfterConnectionClosed) {
                    try await Bridge.closeDir(context: context, directory: directory)
                }
            }
        }
    }

    @Test("direct context destruction releases every retained child handle")
    func destroyContextInvalidatesRetainedHandles() async throws {
        try await withPublicShare { context in
            let (files, directories) = try await openTeardownRegressionHandles(on: context)

            await Bridge.destroyContext(context)
            try await assertTeardownRegressionHandlesClosed(files, directories: directories, on: context)

            // Destroying twice and enqueuing deinit-style cleanup after destruction must not double-free storage.
            await Bridge.destroyContext(context)
            for file in files {
                Bridge.closeInBackground(context: context, file: file)
            }
            for directory in directories {
                Bridge.closeDirInBackground(context: context, directory: directory)
            }
            await Bridge.waitForPendingOperations(on: context)
        }
    }

    @Test("background connection teardown invalidates retained child handles")
    func backgroundTeardownInvalidatesRetainedHandles() async throws {
        try await withPublicShare { context in
            let (files, directories) = try await openTeardownRegressionHandles(on: context)

            Bridge.teardownInBackground(context)
            await Bridge.waitForPendingOperations(on: context)
            try await assertTeardownRegressionHandlesClosed(files, directories: directories, on: context)
        }
    }

    @Test("closing a socket invalidates child handles while preserving context configuration")
    func closeContextPreservesConfigurationWhileInvalidatingHandles() async throws {
        try await withPublicShare { context in
            let (files, directories) = try await openTeardownRegressionHandles(on: context)

            await Bridge.closeContext(context)
            try await assertTeardownRegressionHandlesClosed(files, directories: directories, on: context)

            // closeContext preserves configuration and allocation; it does not promise reuse for a new connection.
            #expect(try await Bridge.perform(on: context) { context.isAlive })
            try await Bridge.setUser("", on: context)
            #expect(try await Bridge.getUser(on: context) == "")
            try await assertTeardownRegressionHandlesClosed(files, directories: directories, on: context)
        }
    }
}

/// Retains multiple allocations of each kind so teardown must drain all children, rather than only the last handle.
private func openTeardownRegressionHandles(
    on context: Bridge.Context
) async throws -> ([Bridge.FileHandle], [Bridge.DirectoryHandle]) {
    var files: [Bridge.FileHandle] = []
    var directories: [Bridge.DirectoryHandle] = []
    for _ in 0 ..< 3 {
        try await files.append(Bridge.open(context: context, path: TestContent.helloPath))
        try await directories.append(Bridge.openDir(context: context, path: TestContent.testdirPath))
    }
    return (files, directories)
}

/// Checks Swift liveness on the owning queue after destruction without reading the freed C context or handles.
private func assertTeardownRegressionHandlesClosed(
    _ files: [Bridge.FileHandle],
    directories: [Bridge.DirectoryHandle],
    on context: Bridge.Context
) async throws {
    for file in files {
        await #expect(throws: SMB.Error.invalidArgument(cause: .fileAlreadyClosed, onOperation: .smb2Read)) {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
                context.queue.async {
                    continuation.resume(with: Result { _ = try file.requireRaw(operation: .smb2Read) })
                }
            }
        }
    }
    for directory in directories {
        await #expect(throws: SMB.Error.invalidArgument(cause: .directoryAlreadyClosed, onOperation: .smb2Readdir)) {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
                context.queue.async {
                    continuation.resume(with: Result { _ = try directory.requireRaw(operation: .smb2Readdir) })
                }
            }
        }
    }
}
