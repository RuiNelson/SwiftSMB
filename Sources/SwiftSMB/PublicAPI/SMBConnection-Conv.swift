//
// Part of SwiftSMB
// SMBConnection-Conv.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import PathWorks

public extension SMB.Connection {
    /// The default read block size accepted by the server.
    ///
    /// This value is the configured transfer block size, or the library
    /// default, clamped to ``maxReadSize``.
    ///
    /// - Throws: ``SMB/Error`` if the connection is closed or no valid block
    ///   size can be determined.
    var acceptedReadBlockSize: Int {
        get throws {
            try acceptedReadBlockSize()
        }
    }

    /// The default write block size accepted by the server.
    ///
    /// This value is the configured transfer block size, or the library
    /// default, clamped to ``maxWriteSize``.
    ///
    /// - Throws: ``SMB/Error`` if the connection is closed or no valid block
    ///   size can be determined.
    var acceptedWriteBlockSize: Int {
        get throws {
            try acceptedWriteBlockSize()
        }
    }

    /// Closes the connection.
    ///
    /// This is equivalent to ``disconnect()``.
    ///
    /// - Throws: ``SMB/Error`` if the server reports a disconnection error.
    func close() throws {
        try disconnect()
    }

    /// Reads an entire file into memory.
    ///
    /// - Parameters:
    ///   - path: The path to the file, relative to the share root.
    ///   - chunkSize: The preferred read block size. Values above the
    ///     server maximum are clamped automatically.
    /// - Returns: The file contents.
    /// - Throws: ``SMB/Error`` if the file cannot be opened or read.
    func readFile(at path: String, chunkSize: Int? = nil) throws -> Data {
        let file = try openFile(at: path)
        defer { try? file.close() }
        return try file.readToEnd(chunkSize: chunkSize)
    }

    /// Writes data to a file.
    ///
    /// By default, this creates the file if needed and truncates any
    /// existing file at `path`.
    ///
    /// - Parameters:
    ///   - data: The bytes to write.
    ///   - path: The path to write, relative to the share root.
    ///   - options: File open options.
    ///   - chunkSize: The preferred write block size. Values above the
    ///     server maximum are clamped automatically.
    /// - Throws: ``SMB/Error`` if the file cannot be opened or written.
    func writeFile(
        _ data: Data,
        to path: String,
        options: SMB.File.OpenOptions = [.create, .truncate],
        chunkSize: Int? = nil,
    ) throws {
        let file = try openFile(at: path, accessMode: .writeOnly, options: options)
        defer { try? file.close() }
        _ = try file.writeAll(data, chunkSize: chunkSize)
    }

    /// Lists all entries in a directory.
    ///
    /// - Parameter path: The directory path, relative to the share root.
    /// - Returns: The directory entries returned by the server.
    /// - Throws: ``SMB/Error`` if the directory cannot be opened or read.
    func listDirectory(at path: String = "") throws -> [SMB.DirectoryEntry] {
        let directory = try openDirectory(at: path)
        defer { directory.close() }
        return try directory.readAll()
    }

    /// Removes a file, link, or directory.
    ///
    /// Directories are removed recursively: all children are removed first,
    /// then the directory itself. The share root cannot be removed through
    /// this convenience method.
    ///
    /// - Parameter path: The path to remove, relative to the share root.
    /// - Throws: ``SMB/Error`` if the path cannot be inspected or removed.
    func removeItem(at path: String) throws {
        guard !path.isEmpty, path != ".", path != "/" else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.removeItem",
                message: "Refusing to remove the share root",
            )
        }

        let entryStat = try stat(at: path)
        guard entryStat.type == .directory else {
            try removeFile(at: path)
            return
        }

        let entries = try listDirectory(at: path)
        for entry in entries where entry.name != "." && entry.name != ".." {
            try removeItem(at: path.appendingPathComponent(entry.name))
        }
        try removeDirectory(at: path)
    }

    /// Returns a read block size accepted by the server.
    ///
    /// - Parameter preferredBlockSize: A preferred block size, or `nil` to
    ///   use the connection configuration/default.
    /// - Returns: The smaller of the preferred size and server maximum.
    /// - Throws: ``SMB/Error`` if no valid block size can be determined.
    func acceptedReadBlockSize(_ preferredBlockSize: Int? = nil) throws -> Int {
        try acceptedBlockSize(
            preferredBlockSize,
            serverMaximum: Int(maxReadSize),
            operation: "smb2_get_max_read_size",
        )
    }

    /// Returns a write block size accepted by the server.
    ///
    /// - Parameter preferredBlockSize: A preferred block size, or `nil` to
    ///   use the connection configuration/default.
    /// - Returns: The smaller of the preferred size and server maximum.
    /// - Throws: ``SMB/Error`` if no valid block size can be determined.
    func acceptedWriteBlockSize(_ preferredBlockSize: Int? = nil) throws -> Int {
        try acceptedBlockSize(
            preferredBlockSize,
            serverMaximum: Int(maxWriteSize),
            operation: "smb2_get_max_write_size",
        )
    }

    /// Clamps a preferred block size to a server maximum.
    private func acceptedBlockSize(
        _ preferredBlockSize: Int?,
        serverMaximum: Int,
        operation: String,
    ) throws -> Int {
        let chunkSize = preferredBlockSize ?? configuration.transferBlockSize ?? 65536
        guard chunkSize > 0 else {
            throw SMB.Error.invalidArgument(
                operation: operation,
                message: "Block size must be greater than zero",
            )
        }
        guard serverMaximum > 0 else {
            throw SMB.Error.invalidArgument(
                operation: operation,
                message: "Server maximum block size must be greater than zero",
            )
        }
        return min(chunkSize, serverMaximum)
    }
}
