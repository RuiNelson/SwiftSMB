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
            try await acceptedReadBlockSize()
        }
    }

    /// The default write block size accepted by the server.
    ///
    /// This value is the configured transfer block size, or the library default, clamped to ``maxWriteSize``.
    ///
    /// - Throws: ``SMB/Error`` if the connection is closed or no valid block size can be determined.
    var acceptedWriteBlockSize: Int {
        get async throws {
            try await acceptedWriteBlockSize()
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
        let path = try SMB.validatePath(path, operation: .smbConnectionReadFile)
        let file = try await openFile(at: path)
        defer { try? await file.close() }
        return try await file.read(transferChunkSize: chunkSize.map { Int64($0) })
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
        let path = try SMB.validatePath(path, operation: .smbConnectionWriteFile)
        let file = try await openFile(at: path, accessMode: .writeOnly, options: options)
        defer { try? await file.close() }
        _ = try await file.write(data, transferChunkSize: chunkSize.map { Int64($0) })
    }

    /// Lists all entries in a directory.
    ///
    /// - Parameter path: The directory path, relative to the share root.
    /// - Returns: The directory entries returned by the server.
    /// - Throws: ``SMB/Error`` if the directory cannot be opened or read.
    func listDirectory(at path: String = "") async throws -> [SMB.DirectoryEntry] {
        let path = try SMB.validatePath(path, operation: .smbConnectionListDirectory, allowRoot: true)
        let directory = try await openDirectory(at: path)
        defer { await directory.close() }
        return try await directory.readAll()
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
        let path = try SMB.validatePath(path, operation: .smbConnectionRemoveItem, allowRoot: false)

        let entryStat = try await stat(at: path)
        guard entryStat.type == .directory else {
            try await removeFile(at: path)
            return
        }

        let entries = try await listDirectory(at: path)
        for entry in entries where entry.name != "." && entry.name != ".." {
            try Task.checkCancellation()
            try await removeItem(at: path.appendingPathComponent(entry.name))
        }
        try await removeDirectory(at: path)
    }

    /// Copies a file from one path to another on the connected share using server-side copy.
    ///
    /// Data is copied directly on the server without transferring through the client. The source file must exist and
    /// must not be a directory. If the destination file already exists, an error is thrown. If the copy fails after the
    /// destination was created, the partial destination file is removed.
    ///
    /// - Parameters:
    ///   - sourcePath: The source file path, relative to the share root.
    ///   - destinationPath: The destination file path, relative to the share root.
    /// - Throws: ``SMB/Error`` if the source cannot be opened or is a directory, the destination already exists, or the
    /// server does not support server-side copy.
    func copyFile(from sourcePath: String, to destinationPath: String) async throws {
        let sourcePath = try SMB.validatePath(sourcePath, operation: .smbConnectionCopyFile)
        let destinationPath = try SMB.validatePath(destinationPath, operation: .smbConnectionCopyFile)
        let context = try requireContext()

        switch try await itemExists(at: destinationPath) {
        case .false:
            break
        case .file, .link:
            throw SMB.Error.posix(
                code: POSIXErrorCode.EEXIST.rawValue,
                operation: "SMB.Connection.copyFile",
                message: "Destination file already exists"
            )
        case .directory, .other:
            throw SMB.Error.invalidArgument(
                cause: .remoteDestinationIsNotAFile,
                onOperation: .smbConnectionCopyFile
            )
        }

        do {
            try await Bridge.serverSideCopy(
                context: context,
                sourcePath: sourcePath,
                destinationPath: destinationPath
            )
        }
        catch {
            // The destination did not exist before, so anything there now is a partial copy. Leaving it would also
            // make a retry fail because the destination exists.
            try? await removeFile(at: destinationPath)
            throw error
        }
    }

    /// Returns a read block size accepted by the server.
    ///
    /// - Parameter preferredBlockSize: A preferred block size, or `nil` to use the connection configuration/default.
    /// - Returns: The smaller of the preferred size and server maximum.
    /// - Throws: ``SMB/Error`` if no valid block size can be determined.
    func acceptedReadBlockSize(_ preferredBlockSize: Int? = nil) async throws -> Int {
        try await acceptedBlockSize(
            preferredBlockSize,
            serverMaximum: Int(maxReadSize),
            operation: .smb2GetMaxReadSize
        )
    }

    /// Returns a write block size accepted by the server.
    ///
    /// - Parameter preferredBlockSize: A preferred block size, or `nil` to use the connection configuration/default.
    /// - Returns: The smaller of the preferred size and server maximum.
    /// - Throws: ``SMB/Error`` if no valid block size can be determined.
    func acceptedWriteBlockSize(_ preferredBlockSize: Int? = nil) async throws -> Int {
        try await acceptedBlockSize(
            preferredBlockSize,
            serverMaximum: Int(maxWriteSize),
            operation: .smb2GetMaxWriteSize
        )
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
