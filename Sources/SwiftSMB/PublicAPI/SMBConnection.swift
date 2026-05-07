//
// Part of SwiftSMB
// SMBConnection.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Dispatch
import Foundation

public extension SMB {
    /// An open connection to an SMB share.
    ///
    /// A connection owns the underlying `libsmb2` context and provides methods
    /// for file, directory, and metadata operations on a single connected share.
    final class Connection: Sendable {
        /// The server this connection is attached to.
        public let server: Server

        /// The connected share name.
        public let share: String

        /// The configuration used to create the connection.
        public let configuration: Configuration

        private let protectedContext = Protected<SMB2Context?>(nil, label: "SwiftSMB.SMB.Connection.context")

        /// The live bridge context, if the connection is still open.
        private var context: SMB2Context? {
            get {
                protectedContext.current
            }
            set {
                protectedContext.current = newValue
            }
        }

        /// Creates a connection around an already connected bridge context.
        init(server: Server, share: String, configuration: Configuration, context: SMB2Context) {
            self.server = server
            self.share = share
            self.configuration = configuration
            self.context = context
        }

        deinit {
            if let context = takeContext() {
                try? disconnectShare(context: context)
                destroyContext(context)
            }
        }

        /// A Boolean value indicating whether the connection still owns an open context.
        public var isConnected: Bool {
            context != nil
        }

        /// The negotiated SMB dialect.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var negotiatedDialect: UInt16 {
            get throws {
                let context = try requireContext(operation: "smb2_get_dialect")
                return SwiftSMB.getDialect(on: context)
            }
        }

        /// The SMB session identifier.
        ///
        /// - Throws: ``SMB/Error`` if the connection is closed or the session ID
        ///   cannot be retrieved.
        public var sessionID: UInt64 {
            get throws {
                let context = try requireContext(operation: "smb2_get_session_id")
                return try SMB.run {
                    try SwiftSMB.getSessionID(context: context)
                }
            }
        }

        /// The maximum read size advertised by the connected server.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var maxReadSize: UInt32 {
            get throws {
                let context = try requireContext(operation: "smb2_get_max_read_size")
                return SwiftSMB.getMaxReadSize(context: context)
            }
        }

        /// The maximum write size advertised by the connected server.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var maxWriteSize: UInt32 {
            get throws {
                let context = try requireContext(operation: "smb2_get_max_write_size")
                return SwiftSMB.getMaxWriteSize(context: context)
            }
        }

        /// Disconnects from the share and destroys the underlying context.
        ///
        /// Calling this method more than once is allowed. After disconnection,
        /// operations on this connection or handles created from it throw
        /// ``SMB/Error/invalidArgument(operation:message:)``.
        ///
        /// - Throws: ``SMB/Error`` if the server reports a disconnection error.
        public func disconnect() throws {
            guard let context = takeContext() else { return }

            do {
                try SMB.run {
                    try SwiftSMB.disconnectShare(context: context)
                }
                destroyContext(context)
            }
            catch {
                destroyContext(context)
                throw error
            }
        }

        /// Sends an SMB echo request and returns the round-trip latency.
        ///
        /// - Returns: The elapsed time, in seconds.
        /// - Throws: ``SMB/Error`` if the connection is closed or the echo
        ///   request fails.
        @discardableResult public func echo() throws -> Double {
            let context = try requireContext(operation: "smb2_echo")
            let start = DispatchTime.now()
            try SMB.run {
                try SwiftSMB.echo(context: context)
            }
            let end = DispatchTime.now()
            return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000
        }

        /// Opens a file on the connected share.
        ///
        /// - Parameters:
        ///   - path: The path to the file, relative to the share root.
        ///   - accessMode: The access mode to request.
        ///   - options: Additional open options.
        /// - Returns: An open file handle.
        /// - Throws: ``SMB/Error`` if the connection is closed or the file
        ///   cannot be opened.
        public func openFile(
            at path: String,
            accessMode: File.AccessMode = .readOnly,
            options: File.OpenOptions = [],
        ) throws -> File {
            let context = try requireContext(operation: "smb2_open")
            let handle = try SMB.run {
                try SwiftSMB.open(
                    context: context,
                    path: path,
                    flags: SMB2OpenFlags(accessMode.bridgeValue, options: options.bridgeValue),
                )
            }
            return File(connection: self, path: path, handle: handle)
        }

        /// Opens a directory on the connected share.
        ///
        /// - Parameter path: The directory path, relative to the share root.
        /// - Returns: An open directory handle.
        /// - Throws: ``SMB/Error`` if the directory cannot be opened.
        public func openDirectory(at path: String = "") throws -> Directory {
            let context = try requireContext(operation: "smb2_opendir")
            let handle = try SMB.run {
                try SwiftSMB.openDir(context: context, path: path)
            }
            return Directory(connection: self, path: path, handle: handle)
        }

        /// Creates a directory.
        ///
        /// - Parameter path: The directory path, relative to the share root.
        /// - Throws: ``SMB/Error`` if the directory cannot be created.
        public func makeDirectory(at path: String) throws {
            let context = try requireContext(operation: "smb2_mkdir")
            try SMB.run {
                try SwiftSMB.makeDir(context: context, path: path)
            }
        }

        /// Removes an empty directory.
        ///
        /// - Parameter path: The directory path, relative to the share root.
        /// - Throws: ``SMB/Error`` if the directory cannot be removed.
        public func removeDirectory(at path: String) throws {
            let context = try requireContext(operation: "smb2_rmdir")
            try SMB.run {
                try SwiftSMB.removeDir(context: context, path: path)
            }
        }

        /// Removes a file or link.
        ///
        /// - Parameter path: The path to remove, relative to the share root.
        /// - Throws: ``SMB/Error`` if the path cannot be removed.
        public func removeFile(at path: String) throws {
            let context = try requireContext(operation: "smb2_unlink")
            try SMB.run {
                try SwiftSMB.unlink(context: context, path: path)
            }
        }

        /// Renames or moves a share entry.
        ///
        /// - Parameters:
        ///   - oldPath: The current path, relative to the share root.
        ///   - newPath: The destination path, relative to the share root.
        /// - Throws: ``SMB/Error`` if the rename fails.
        public func rename(from oldPath: String, to newPath: String) throws {
            let context = try requireContext(operation: "smb2_rename")
            try SMB.run {
                try SwiftSMB.rename(context: context, oldPath: oldPath, newPath: newPath)
            }
        }

        /// Truncates a file by path.
        ///
        /// - Parameters:
        ///   - path: The file path, relative to the share root.
        ///   - length: The target file length, in bytes.
        /// - Throws: ``SMB/Error`` if the file cannot be truncated.
        public func truncateFile(at path: String, toLength length: UInt64) throws {
            let context = try requireContext(operation: "smb2_truncate")
            try SMB.run {
                try SwiftSMB.truncate(context: context, path: path, length: length)
            }
        }

        /// Reads the destination of a symbolic link.
        ///
        /// - Parameters:
        ///   - path: The link path, relative to the share root.
        ///   - bufferSize: The maximum number of bytes to read for the target.
        /// - Returns: The link target path.
        /// - Throws: ``SMB/Error`` if the link cannot be read.
        public func readLink(at path: String, bufferSize: Int = 4096) throws -> String {
            let context = try requireContext(operation: "smb2_readlink")
            return try SMB.run {
                try SwiftSMB.readLink(context: context, path: path, bufferSize: bufferSize)
            }
        }

        /// Returns metadata for a path.
        ///
        /// - Parameter path: The path to inspect, relative to the share root.
        /// - Returns: File metadata.
        /// - Throws: ``SMB/Error`` if metadata cannot be read.
        public func stat(at path: String) throws -> Stat {
            let context = try requireContext(operation: "smb2_stat")
            return try SMB.run {
                try Stat(SwiftSMB.fileStatistics(context: context, path: path))
            }
        }

        /// Returns filesystem statistics for a path.
        ///
        /// - Parameter path: A path on the share.
        /// - Returns: Filesystem statistics reported by the server.
        /// - Throws: ``SMB/Error`` if statistics cannot be read.
        public func statFilesystem(at path: String = "") throws -> FilesystemStat {
            let context = try requireContext(operation: "smb2_statvfs")
            return try SMB.run {
                try FilesystemStat(SwiftSMB.statVFS(context: context, path: path))
            }
        }

        /// Returns the live bridge context or throws if the connection is closed.
        func requireContext(operation: String) throws -> SMB2Context {
            guard let context else {
                throw SMB.Error.invalidArgument(operation: operation, message: "Connection is already closed")
            }
            return context
        }

        /// Takes ownership of the context and marks the connection closed.
        private func takeContext() -> SMB2Context? {
            protectedContext.take(replacingWith: nil)
        }
    }
}
