//
// Part of SwiftSMB
// Connection-Conv.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation
import PathWorks

public extension SMB.Connection {
    /// The default read block size accepted by the server.
    ///
    /// This value is the configured transfer block size, or the library default, clamped to ``maxReadSize``.
    ///
    /// - Throws: ``SMB/Error`` if the connection is closed or no valid block size can be determined.
    var acceptedReadBlockSize: Int {
        get async throws {
            try await self.withOperation {
                try await acceptedReadBlockSize()
            }
        }
    }

    /// The default write block size accepted by the server.
    ///
    /// This value is the configured transfer block size, or the library default, clamped to ``maxWriteSize``.
    ///
    /// - Throws: ``SMB/Error`` if the connection is closed or no valid block size can be determined.
    var acceptedWriteBlockSize: Int {
        get async throws {
            try await self.withOperation {
                try await acceptedWriteBlockSize()
            }
        }
    }

    /// Closes the connection.
    ///
    /// This is equivalent to ``disconnect()``.
    ///
    /// - Throws: ``SMB/Error`` if the server reports a disconnection error.
    func close() async throws {
        try await disconnect()
    }

    /// Reads an entire file into memory.
    ///
    /// - Parameters:
    ///   - path: The path to the file, relative to the share root.
    ///   - chunkSize: The preferred read block size. Values above the server maximum are clamped automatically.
    /// - Returns: The file contents.
    /// - Throws: ``SMB/Error`` if the file cannot be opened or read.
    func loadFile(at path: String, chunkSize: Int? = nil) async throws -> Data {
        try await self.withOperation {
            let path = try self.validatePath(path, operation: .smbConnectionReadFile)
            let file = try await openFile(at: path)
            defer { try? await file.close() }
            return try await file.read(transferChunkSize: chunkSize.map { Int64($0) })
        }
    }

    /// Writes data to a file.
    ///
    /// By default, this creates the file if needed and truncates any existing file at `path`.
    ///
    /// - Parameters:
    ///   - data: The bytes to write.
    ///   - path: The path to write, relative to the share root.
    ///   - options: File open options.
    ///   - chunkSize: The preferred write block size. Values above the server maximum are clamped automatically.
    /// - Throws: ``SMB/Error`` if the file cannot be opened or written.
    func dumpToFile(
        _ data: Data,
        to path: String,
        options: SMB.File.OpenOptions = [.create, .truncate],
        chunkSize: Int? = nil
    ) async throws {
        try await self.withOperation {
            let path = try self.validatePath(path, operation: .smbConnectionWriteFile)
            let file = try await openFile(at: path, accessMode: .writeOnly, options: options)
            defer { try? await file.close() }
            _ = try await file.write(data, transferChunkSize: chunkSize.map { Int64($0) })
        }
    }

    /// Lists all entries in a directory.
    ///
    /// While a cache is attached with ``SMB/Connection/attachCache(_:)``, the cache may answer instead of the server.
    /// Directories read through an ``SMB/Directory`` handle never use the cache.
    ///
    /// - Parameter path: The directory path, relative to the share root.
    /// - Returns: The directory entries returned by the server.
    /// - Throws: ``SMB/Error`` if the directory cannot be opened or read.
    func listDirectory(at path: String = "") async throws -> [SMB.DirectoryEntry] {
        try await self.withOperation {
            let path = try self.validatePath(path, operation: .smbConnectionListDirectory, allowRoot: true)
            func listOnServer() async throws -> [SMB.DirectoryEntry] {
                let directory = try await openDirectory(at: path)
                defer { await directory.close() }
                return try await directory.readAll()
            }

            guard let cache else {
                return try await listOnServer()
            }

            return try await withCacheRequest(on: cache) { request in
                if let entries = await cache.retrieveDirectoryListing(path: path, request: request) {
                    return entries
                }

                let entries = try await listOnServer()
                await cache.storeDirectoryListing(entries, path: path, request: request)
                return entries
            }
        }
    }

    /// Removes a file, link, or directory.
    ///
    /// Directories are removed recursively: all children are removed first, then the directory itself. The share root
    /// cannot be removed through this convenience method.
    ///
    /// - Parameter path: The path to remove, relative to the share root.
    /// - Throws: ``SMB/Error`` if the path cannot be inspected or removed, or `CancellationError` if the task is
    /// cancelled between items. Items removed before cancellation stay removed.
    func removeItem(at path: String) async throws {
        try await self.withOperation {
            let path = try self.validatePath(path, operation: .smbConnectionRemoveItem, allowRoot: false)
            try Task.checkCancellation()

            let entryStat = try await stat(at: path)
            guard entryStat.type == .directory else {
                try Task.checkCancellation()
                try await removeFile(at: path)
                return
            }

            let entries = try await listDirectory(at: path)
            for entry in entries where entry.name != "." && entry.name != ".." {
                try Task.checkCancellation()
                try await removeItem(at: path.appendingPathComponent(entry.name))
            }
            try Task.checkCancellation()
            try await removeDirectory(at: path)
        }
    }

    /// Copies a file from one path to another on the connected share using server-side copy.
    ///
    /// Data is copied directly on the server without transferring through the client. The source file must exist and
    /// must not be a directory.
    ///
    /// By default the destination must not exist: if it does, the method throws an ``SMB/Error`` whose cause is
    /// ``SMB/Error/InvalidArgumentException/remoteDestinationAlreadyExists`` (its ``SMB/Error/posixCode`` is `EEXIST`).
    /// If the copy fails or is cancelled after it created the destination, the partial destination file is removed.
    ///
    /// With `overwrite` set to `true` an existing destination file is replaced. The server truncates it when the copy
    /// starts, so a copy that fails or is cancelled leaves the destination partially written and the previous contents
    /// lost; copy to a new path and move it into place when that matters. Copying a file onto itself throws
    /// ``SMB/Error/InvalidArgumentException/sourceAndDestinationAreTheSameFile``.
    ///
    /// The copy stops between requests when the task is cancelled, and throws `CancellationError`. To follow the
    /// progress or stop the copy without an error, use
    /// ``copyFile(from:to:overwrite:continuation:)-(_,_,_,FileProgress)``.
    ///
    /// - Parameters:
    ///   - sourcePath: The source file path, relative to the share root.
    ///   - destinationPath: The destination file path, relative to the share root.
    ///   - overwrite: A Boolean value indicating whether to replace an existing destination file.
    /// - Throws: ``SMB/Error`` if the source cannot be opened or is a directory, the destination exists and `overwrite`
    /// is `false` or is not a file, or the server does not support server-side copy.
    func copyFile(from sourcePath: String, to destinationPath: String, overwrite: Bool = false) async throws {
        let progress: AsyncFileProgress = { _, _, _, _ in true }
        try await copyFile(from: sourcePath, to: destinationPath, overwrite: overwrite, continuation: progress)
    }

    /// Copies a file on the share using server-side copy, reporting progress through a closure that can suspend.
    ///
    /// Behaves like ``copyFile(from:to:overwrite:)``. The server copies the file in requests of up to its advertised
    /// chunk limits (typically a few megabytes), and `continuation` is called after each one and once more when the
    /// copy has completed, with a latest speed of `0`. The copy waits for it to return before it sends the next
    /// request. Return `true` to continue, or `false` to stop the copy, which makes the method return normally; the
    /// destination is then removed if the copy created it, and left partially written if it replaced an existing file.
    ///
    /// - Parameters:
    ///   - sourcePath: The source file path, relative to the share root.
    ///   - destinationPath: The destination file path, relative to the share root.
    ///   - overwrite: A Boolean value indicating whether to replace an existing destination file.
    ///   - continuation: A progress closure; see ``AsyncFileProgress``. `totalBytes` is the size of the source.
    /// - Throws: ``SMB/Error`` as ``copyFile(from:to:overwrite:)`` does, or `CancellationError` if the task is
    /// cancelled.
    func copyFile(
        from sourcePath: String,
        to destinationPath: String,
        overwrite: Bool = false,
        continuation: @escaping AsyncFileProgress
    ) async throws {
        try await self.withOperation {
            let sourcePath = try self.validatePath(sourcePath, operation: .smbConnectionCopyFile)
            let destinationPath = try self.validatePath(destinationPath, operation: .smbConnectionCopyFile)
            try await copyRemoteFile(
                on: self,
                from: sourcePath,
                to: destinationPath,
                overwrite: overwrite,
                continuation: continuation
            )
        }
    }

    /// Copies a file on the share using server-side copy, reporting progress through a synchronous closure.
    ///
    /// Behaves like ``copyFile(from:to:overwrite:continuation:)-(_,_,_,AsyncFileProgress)``; Swift selects this method
    /// when the progress closure doesn't use `await`.
    ///
    /// - Parameters:
    ///   - sourcePath: The source file path, relative to the share root.
    ///   - destinationPath: The destination file path, relative to the share root.
    ///   - overwrite: A Boolean value indicating whether to replace an existing destination file.
    ///   - continuation: A progress closure; see ``FileProgress``. `totalBytes` is the size of the source.
    /// - Throws: ``SMB/Error`` as ``copyFile(from:to:overwrite:)`` does, or `CancellationError` if the task is
    /// cancelled.
    func copyFile(
        from sourcePath: String,
        to destinationPath: String,
        overwrite: Bool = false,
        continuation: @escaping FileProgress
    ) async throws {
        // Passing `continuation` directly would select the non-suspending overload again.
        let progress: AsyncFileProgress = continuation
        try await copyFile(from: sourcePath, to: destinationPath, overwrite: overwrite, continuation: progress)
    }

    /// Returns a read block size accepted by the server.
    ///
    /// - Parameter preferredBlockSize: A preferred block size, or `nil` to use the connection configuration/default.
    /// - Returns: The smaller of the preferred size and server maximum.
    /// - Throws: ``SMB/Error`` if no valid block size can be determined.
    func acceptedReadBlockSize(_ preferredBlockSize: Int? = nil) async throws -> Int {
        try await self.withOperation {
            try await acceptedBlockSize(
                preferredBlockSize,
                serverMaximum: Int(clamping: maxReadSize),
                operation: .smb2GetMaxReadSize
            )
        }
    }

    /// Returns a write block size accepted by the server.
    ///
    /// - Parameter preferredBlockSize: A preferred block size, or `nil` to use the connection configuration/default.
    /// - Returns: The smaller of the preferred size and server maximum.
    /// - Throws: ``SMB/Error`` if no valid block size can be determined.
    func acceptedWriteBlockSize(_ preferredBlockSize: Int? = nil) async throws -> Int {
        try await self.withOperation {
            try await acceptedBlockSize(
                preferredBlockSize,
                serverMaximum: Int(clamping: maxWriteSize),
                operation: .smb2GetMaxWriteSize
            )
        }
    }

    /// Clamps a preferred block size to a server maximum.
    private func acceptedBlockSize(
        _ preferredBlockSize: Int?,
        serverMaximum: Int,
        operation: SMB.Error.InvalidArgumentOperation
    ) throws -> Int {
        let chunkSize = preferredBlockSize ?? configuration.transferBlockSize ?? 65536
        guard chunkSize > 0 else {
            throw SMB.Error.invalidArgument(
                cause: .blockSizeMustBeGreaterThanZero,
                onOperation: operation
            )
        }
        guard serverMaximum > 0 else {
            throw SMB.Error.invalidArgument(
                cause: .serverMaximumBlockSizeMustBeGreaterThanZero,
                onOperation: operation
            )
        }
        return min(chunkSize, serverMaximum)
    }
}
