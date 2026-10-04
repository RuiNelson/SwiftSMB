//
// Part of SwiftSMB
// BridgeRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import SMB2
import Testing

struct BridgeRegressionTests {
    @Test("captured file handles reject every operation after close")
    func capturedFileHandleRejectsOperationsAfterClose() async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }
        // A stale pointer must never reach C. Removing it on the queue models a close that ran after a caller captured
        // the wrapper but before that caller's operation was enqueued.
        let file = Bridge.FileHandle(raw: OpaquePointer(bitPattern: 1)!)
        _ = try await Bridge.perform(on: context) { file.takeRaw() != nil }

        await #expect(throws: closedFileError(.smb2Read)) {
            try await Bridge.read(context: context, file: file, count: 1)
        }
        await #expect(throws: closedFileError(.smb2Pread)) {
            try await Bridge.read(context: context, file: file, count: 1, offset: 0)
        }
        await #expect(throws: closedFileError(.smb2Write)) {
            try await Bridge.write(context: context, file: file, data: Data([1]))
        }
        await #expect(throws: closedFileError(.smb2Pwrite)) {
            try await Bridge.write(context: context, file: file, data: Data([1]), offset: 0)
        }
        await #expect(throws: closedFileError(.smb2Lseek)) {
            try await Bridge.seek(context: context, file: file, offset: 0, whence: SEEK_SET)
        }
        await #expect(throws: closedFileError(.smb2Fsync)) {
            try await Bridge.sync(context: context, file: file)
        }
        await #expect(throws: closedFileError(.smb2Fstat)) {
            try await Bridge.fileStatistics(context: context, file: file)
        }
        await #expect(throws: closedFileError(.smb2Ftruncate)) {
            try await Bridge.truncate(context: context, file: file, length: 0)
        }
        await #expect(throws: closedFileError(.smb2Flock)) {
            try await Bridge.lock(context: context, file: file, flags: .exclusive)
        }
        await #expect(throws: closedFileError(.smb2GetFileID)) {
            try await Bridge.notifyChange(context: context, directory: file) { _ in }
        }
        try await Bridge.close(context: context, file: file)
    }

    @Test("captured directory handles reject operations after close")
    func capturedDirectoryHandleRejectsOperationsAfterClose() async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }
        let pointer = UnsafeMutablePointer<smb2dir>.allocate(capacity: 1)
        defer { pointer.deallocate() }
        let directory = Bridge.DirectoryHandle(raw: pointer)
        _ = try await Bridge.perform(on: context) { directory.takeRaw() != nil }

        await #expect(throws: closedDirectoryError(.smb2Readdir)) {
            try await Bridge.readDir(context: context, directory: directory)
        }
        await #expect(throws: closedDirectoryError(.smb2Rewinddir)) {
            try await Bridge.rewindDir(context: context, directory: directory)
        }
        await #expect(throws: closedDirectoryError(.smb2Telldir)) {
            try await Bridge.tellDir(context: context, directory: directory)
        }
        await #expect(throws: closedDirectoryError(.smb2Seekdir)) {
            try await Bridge.seekDir(context: context, directory: directory, location: 0)
        }
        try await Bridge.closeDir(context: context, directory: directory)
    }

    @Test("relative seek arithmetic rejects underflow and overflow")
    func relativeSeekRejectsOverflow() throws {
        #expect(try Bridge.seekDestination(from: 10, offset: -10) == 0)
        #expect(try Bridge.seekDestination(from: 10, offset: -9) == 1)
        #expect(throws: SMB.Error.self) { try Bridge.seekDestination(from: 0, offset: -1) }
        #expect(throws: SMB.Error.self) { try Bridge.seekDestination(from: 0, offset: Int64.min) }
        #expect(throws: SMB.Error.self) { try Bridge.seekDestination(from: UInt64(Int64.max), offset: 1) }
        #expect(throws: SMB.Error.self) { try Bridge.seekDestination(from: UInt64.max, offset: 1) }
    }

    @Test("basic information timestamps handle the Unix epoch and invalid dates")
    func basicInformationTimestamps() throws {
        var epoch = try Bridge.basicInfoTimeval(from: Date(timeIntervalSince1970: 0))
        #expect(epoch.tv_sec != 0 || epoch.tv_usec != 0)
        #expect(smb2_timeval_to_win(&epoch) == 116_444_736_000_000_000)

        let omitted = try Bridge.basicInfoTimeval(from: nil)
        #expect(omitted.tv_sec == 0xFFFF_FFFF)
        #expect(UInt32(truncatingIfNeeded: omitted.tv_usec) == UInt32.max)
        for interval in [Double.nan, .infinity, -.infinity, Double.greatestFiniteMagnitude, -11_644_473_601] {
            #expect(throws: SMB.Error.self) {
                try Bridge.basicInfoTimeval(from: Date(timeIntervalSince1970: interval))
            }
        }
    }

    @Test("oversized ACL wire lengths are rejected before queuing a request")
    func oversizedACLRejected() async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }
        let entry = Bridge.AccessControlEntry(
            kind: 0,
            flags: 0,
            accessMask: 1,
            trustee: Bridge.SecurityIdentifier(revision: 1, identifierAuthority: 1, subauthorities: [])
        )
        let descriptor = Bridge.SecurityDescriptor(
            owner: nil,
            group: nil,
            discretionaryAccessControlList: Bridge.AccessControlList(
                revision: 2,
                entries: Array(repeating: entry, count: 4096)
            )
        )
        await #expect(throws: SMB.Error.posix(
            code: POSIXErrorCode.EINVAL.rawValue,
            operation: "SMB.Connection.setSecurityDescriptor",
            message: "Access-control list exceeds the maximum SMB wire size"
        )) {
            try await Bridge.setSecurityDescriptor(context: context, path: "unused", descriptor: descriptor)
        }
    }

    @Test("invalid lease key lengths are rejected before C reads their bytes")
    func invalidLeaseKeyLengthsRejected() async throws {
        let context = try Bridge.createContext()
        defer { await Bridge.destroyContext(context) }
        for count in [0, 1, 15, 17] {
            await #expect(throws: SMB.Error.posix(
                code: POSIXErrorCode.EINVAL.rawValue,
                operation: "smb2_open_async_with_oplock_or_lease",
                message: "Lease key must contain exactly 16 bytes"
            )) {
                try await Bridge.open(
                    context: context,
                    path: "unused",
                    opLockLevel: .lease,
                    leaseState: .readCaching,
                    leaseKey: Data(repeating: 0, count: count)
                )
            }
        }
    }
}

private func closedFileError(_ operation: SMB.Error.InvalidArgumentOperation) -> SMB.Error {
    .invalidArgument(cause: .fileAlreadyClosed, onOperation: operation)
}

private func closedDirectoryError(_ operation: SMB.Error.InvalidArgumentOperation) -> SMB.Error {
    .invalidArgument(cause: .directoryAlreadyClosed, onOperation: operation)
}
