//
// Part of SwiftSMB
// Connection.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Dispatch
import Foundation
import PathWorks

public extension SMB {
    /// An open connection to an SMB share.
    ///
    /// A connection owns the underlying `libsmb2` context and provides methods for file, directory, and metadata
    /// operations on a single connected share.
    ///
    /// Operations on one connection run one at a time, in the order they were requested, on a queue owned by the
    /// connection. Use separate connections to run operations in parallel.
    final class Connection: CustomDebugStringConvertible, Sendable {
        /// The server this connection is attached to.
        public let server: Server

        /// The connected share name.
        public let share: String

        /// The configuration used to create the connection.
        public let configuration: Configuration

        /// The maximum read size negotiated when connecting. It does not change afterwards.
        private let negotiatedMaxReadSize: UInt32

        /// The maximum write size negotiated when connecting. It does not change afterwards.
        private let negotiatedMaxWriteSize: UInt32

        private let protectedContext = ProtectedHandle<Bridge.Context>(
            label: "com.ruinelson.SwiftSMB.SMB.Connection.context"
        )
        /// Active notification watchers that must be cancelled before context teardown.
        let protectedNotifyWatchers = Protected<[UUID: SMBNotifyWatcherState]>(
            [:],
            label: "com.ruinelson.SwiftSMB.SMB.Connection.notifyWatchers"
        )

        /// The live bridge context, if the connection is still open.
        private var context: Bridge.Context? {
            get {
                protectedContext.current
            }
            set {
                protectedContext.current = newValue
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
            get async throws {
                let context = try requireContext()
                return try await Bridge.getDialect(on: context)
            }
        }

        /// The negotiated SMB dialect, as a known dialect case.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var negotiatedDialectKind: NegotiatedDialect {
            get async throws {
                try await NegotiatedDialect(rawValue: negotiatedDialect)
            }
        }

        /// The GUID that uniquely identifies the connected SMB server.
        ///
        /// The value is returned as Foundation's native ``UUID`` type. SMB wire byte order is normalized before the
        /// UUID is constructed.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var serverGUID: UUID {
            get async throws {
                let context = try requireContext()
                return try await Bridge.getServerGUID(on: context)
            }
        }

        /// The SMB session identifier.
        ///
        /// - Throws: ``SMB/Error`` if the connection is closed or the session ID cannot be retrieved.
        public var sessionID: UInt64 {
            get async throws {
                let context = try requireContext()
                return try await Bridge.getSessionID(context: context)
            }
        }

        /// The maximum read size advertised by the connected server.
        ///
        /// The value is negotiated when connecting and does not change afterwards.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var maxReadSize: UInt32 {
            get async throws {
                _ = try requireContext()
                return negotiatedMaxReadSize
            }
        }

        /// The maximum write size advertised by the connected server.
        ///
        /// The value is negotiated when connecting and does not change afterwards.
        ///
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public var maxWriteSize: UInt32 {
            get async throws {
                _ = try requireContext()
                return negotiatedMaxWriteSize
            }
        }
        
        // MARK: Lifecycle
        
        /// Creates a connection around an already connected bridge context and its negotiated transfer limits.
        init(
            server: Server,
            share: String,
            configuration: Configuration,
            context: Bridge.Context,
            maxReadSize: UInt32,
            maxWriteSize: UInt32
        ) {
            self.server = server
            self.share = share
            self.configuration = configuration
            negotiatedMaxReadSize = maxReadSize
            negotiatedMaxWriteSize = maxWriteSize
            self.context = context
        }
        
        deinit {
            // `deinit` cannot await. Watcher cleanup and teardown are enqueued on the context queue in this order.
            cancelNotifyWatchersInBackground()
            if let context = takeContext() {
                Bridge.teardownInBackground(context)
            }
        }

        /// Disconnects from the share and destroys the underlying context.
        ///
        /// Active directory watchers are cancelled first. Calling this method more than once is allowed. After
        /// disconnection, operations on this connection or handles created from it throw
        /// ``SMB/Error/operationRequestedAfterConnectionClosed``.
        ///
        /// - Throws: ``SMB/Error`` if the server reports a disconnection error.
        public func disconnect() async throws {
            await cancelNotifyWatchers()
            guard let context = takeContext() else { return }
            try await Bridge.shutdown(context)
        }

        /// Disconnects from the share after waiting for in-flight operations to complete.
        ///
        /// Operations already requested on this connection (file reads, writes, directory listings, metadata queries,
        /// etc.) finish before the share is disconnected.
        ///
        /// Calling this method more than once is allowed.
        ///
        /// - Throws: ``SMB/Error`` if the server reports a disconnection error.
        public func disconnectGracefully() async throws {
            if let context {
                await Bridge.waitForPendingOperations(on: context)
            }
            try await disconnect()
        }

        /// Sends an SMB echo request and returns the round-trip latency.
        ///
        /// - Returns: The elapsed time, in seconds.
        /// - Throws: ``SMB/Error`` if the connection is closed or the echo request fails.
        @discardableResult public func echo() async throws -> Double {
            let context = try requireContext()
            let start = DispatchTime.now()
            try await Bridge.echo(context: context)
            let end = DispatchTime.now()
            return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000
        }

        /// Sets the command timeout for subsequent operations on this connection.
        ///
        /// Commands that exceed the timeout are aborted by `libsmb2` with an I/O timeout status. Pass `0` to disable
        /// command timeouts. Negative values are treated as `0`; values larger than `Int32.max` are clamped.
        ///
        /// - Parameter timeout: The timeout interval, in seconds.
        /// - Throws: ``SMB/Error`` if the connection is already closed.
        public func setTimeout(_ timeout: Int) async throws {
            let context = try requireContext()
            let int32val = timeout >= 0 ? Int32(clamping: timeout) : 0
            try await Bridge.setTimeout(int32val, on: context)
        }

        /// Sets the owner, group, or discretionary access-control list for an item.
        ///
        /// Only non-`nil` descriptor components are sent. Supplying an empty access-control list sets an empty DACL; it
        /// does not leave the existing DACL unchanged.
        ///
        /// - Parameters:
        ///   - descriptor: The security descriptor components to update.
        ///   - path: The path to the item, relative to the share root.
        /// - Throws: ``SMB/Error`` if the connection is closed, the descriptor is invalid, or the server rejects the
        /// security update.
        public func setSecurityDescriptor(_ descriptor: SecurityDescriptor, at path: String) async throws {
            let path = try SMB.validatePath(path, operation: .smbConnectionSetSecurityDescriptor)
            let context = try requireContext()
            try await Bridge.setSecurityDescriptor(context: context, path: path, descriptor: descriptor.bridgeValue)
        }

        // MARK: Handles

        /// Opens a file on the connected share.
        ///
        /// - Parameters:
        ///   - path: The path to the file, relative to the share root.
        ///   - accessMode: The access mode to request.
        ///   - options: Additional open options.
        ///   - opLock: The opportunistic lock level to request, or ``File/OpLock/none`` for no oplock.
        /// - Returns: An open file handle.
        /// - Throws: ``SMB/Error`` if the connection is closed or the file cannot be opened.
        public func openFile(
            at path: String,
            accessMode: File.AccessMode = .readOnly,
            options: File.OpenOptions = [],
            opLock: File.OpLock = .none
        ) async throws -> File {
            let path = try SMB.validatePath(path, operation: .smb2Open)
            let context = try requireContext()

            let bridgeLeaseState: Bridge.LeaseState
            let leaseKey: Data?
            if case let .lease(state) = opLock {
                bridgeLeaseState = state.bridgeValue
                leaseKey = Self.generateLeaseKey()
            }
            else {
                bridgeLeaseState = []
                leaseKey = nil
            }

            let handle = try await Bridge.open(
                context: context,
                path: path,
                flags: Bridge.OpenFlags(accessMode.bridgeValue, options: options.bridgeValue),
                opLockLevel: opLock.bridgeValue,
                leaseState: bridgeLeaseState,
                leaseKey: leaseKey
            )
            return File(connection: self, path: path, handle: handle)
        }

        /// Generates a random 16-byte lease key.
        private static func generateLeaseKey() -> Data {
            withUnsafeBytes(of: UUID().uuid) { Data($0) }
        }

        /// Opens a directory on the connected share.
        ///
        /// - Parameter path: The directory path, relative to the share root.
        /// - Returns: An open directory handle.
        /// - Throws: ``SMB/Error`` if the directory cannot be opened.
        public func openDirectory(at path: String = "") async throws -> Directory {
            let path = try SMB.validatePath(path, operation: .smb2Opendir, allowRoot: true)
            let context = try requireContext()
            let handle = try await Bridge.openDir(context: context, path: path)
            return Directory(connection: self, path: path, handle: handle)
        }
        
        // MARK: Management

        /// Creates a directory.
        ///
        /// - Parameters:
        ///   - path: The directory path, relative to the share root.
        ///   - makePath: A Boolean value indicating whether to create missing ancestor directories before creating
        /// `path`.
        /// - Throws: ``SMB/Error`` if the directory cannot be created.
        public func makeDirectory(at path: String, makePath: Bool = false) async throws {
            let path = try SMB.validatePath(path, operation: .smb2Mkdir)
            
            if makePath {
                // check if directory is in the root of the share
                guard path.pathComponents.count > 1 else {
                    try await makeDirectory(at: path, makePath: false)
                    return
                }
                
                // create previous directory if it doesn't exist
                let previous = path.removingLastPathComponent
                
                switch try await itemExists(at: previous) {
                case .false:
                    try await makeDirectory(at: previous, makePath: true)
                case .directory:
                    break
                case .file, .link, .other:
                    throw SMB.Error.posix(
                        code: POSIXErrorCode.EEXIST.rawValue,
                        operation: "SMB.Connection.makeDirectory",
                        message: "Path component already exists and is not a directory"
                    )
                }
            }
            
            let context = try requireContext()
            try await Bridge.makeDir(context: context, path: path)
        }

        /// Removes an empty directory.
        ///
        /// - Parameter path: The directory path, relative to the share root.
        /// - Throws: ``SMB/Error`` if the directory cannot be removed.
        public func removeDirectory(at path: String) async throws {
            let path = try SMB.validatePath(path, operation: .smb2Rmdir)
            let context = try requireContext()
            try await Bridge.removeDir(context: context, path: path)
        }

        /// Removes a file or link.
        ///
        /// - Parameter path: The path to remove, relative to the share root.
        /// - Throws: ``SMB/Error`` if the path cannot be removed.
        public func removeFile(at path: String) async throws {
            let path = try SMB.validatePath(path, operation: .smb2Unlink)
            let context = try requireContext()
            try await Bridge.unlink(context: context, path: path)
        }

        /// Moves or renames a share entry.
        ///
        /// - Parameters:
        ///   - oldPath: The current path, relative to the share root.
        ///   - newPath: The destination path, relative to the share root.
        /// - Throws: ``SMB/Error`` if the move fails.
        public func move(from oldPath: String, to newPath: String) async throws {
            let oldPath = try SMB.validatePath(oldPath, operation: .smb2Rename)
            let newPath = try SMB.validatePath(newPath, operation: .smb2Rename)
            let context = try requireContext()
            try await Bridge.rename(context: context, oldPath: oldPath, newPath: newPath)
        }

        /// Truncates a file by path.
        ///
        /// - Parameters:
        ///   - path: The file path, relative to the share root.
        ///   - length: The target file length, in bytes.
        /// - Throws: ``SMB/Error`` if the file cannot be truncated.
        public func truncateFile(at path: String, toLength length: UInt64) async throws {
            let path = try SMB.validatePath(path, operation: .smb2Truncate)
            let context = try requireContext()
            try await Bridge.truncate(context: context, path: path, length: length)
        }

        /// Reads the destination of a symbolic link.
        ///
        /// - Parameters:
        ///   - path: The link path, relative to the share root.
        ///   - bufferSize: The maximum number of bytes to read for the target.
        /// - Returns: The link target path.
        /// - Throws: ``SMB/Error`` if the link cannot be read.
        public func readLink(at path: String, bufferSize: Int = 16384) async throws -> String {
            let path = try SMB.validatePath(path, operation: .smb2Readlink)
            let context = try requireContext()
            return try await Bridge.readLink(context: context, path: path, bufferSize: bufferSize)
        }
        
        /// Creates a symbolic link at the given path.
        ///
        /// - Parameters:
        ///   - path: The link path, relative to the share root.
        ///   - pointingTo: The target path that the link will point to.
        /// - Throws: ``SMB/Error`` if the link cannot be created.
        public func makeLink(at path: String, pointingTo: String) async throws {
            let path = try SMB.validatePath(path, operation: .smb2MakeLink)
            guard !pointingTo.isEmpty else {
                throw SMB.Error.invalidArgument(cause: .pathMustNotBeEmpty, onOperation: .smb2MakeLink)
            }
            let context = try requireContext()
            try await Bridge.makeLink(context: context, path: path, destination: pointingTo)
        }

        /// Creates a hard link to an existing file.
        ///
        /// Both paths must be relative to the same share. The source file must exist, and the destination path must not
        /// already exist.
        ///
        /// - Parameters:
        ///   - path: The new hard-link path, relative to the share root.
        ///   - existingPath: The existing file path that the new link will point to.
        /// - Throws: ``SMB/Error`` if the hard link cannot be created.
        public func makeHardLink(at path: String, pointingTo existingPath: String) async throws {
            let path = try SMB.validatePath(path, operation: .smb2Link)
            let existingPath = try SMB.validatePath(existingPath, operation: .smb2Link)
            let context = try requireContext()
            try await Bridge.makeHardLink(context: context, existingPath: existingPath, newPath: path)
        }
        
        /// Returns metadata for a path.
        ///
        /// - Parameter path: The path to inspect, relative to the share root.
        /// - Returns: File metadata.
        /// - Throws: ``SMB/Error`` if metadata cannot be read.
        public func stat(at path: String) async throws -> Stat {
            let path = try SMB.validatePath(path, operation: .smb2Stat, allowRoot: true)
            let context = try requireContext()
            return try await Stat(Bridge.fileStatistics(context: context, path: path))
        }
        
        /// Returns whether an item exists at a path, and what kind of item it is.
        ///
        /// This method returns ``SMB/ItemExistence/false`` when the server reports that `path` does not exist. When an
        /// item exists, the result describes the node kind reported by the server.
        ///
        /// A leading `/` in `path` is ignored, so `"/folder"` is treated as `"folder"` relative to the connected share
        /// root.
        ///
        /// - Parameter path: The item path to inspect, relative to the share root.
        /// - Returns: The existence and kind of the item at `path`.
        /// - Throws: ``SMB/Error`` if the connection is closed, metadata cannot be read, or `path` is invalid.
        public func itemExists(at path: String) async throws -> SMB.ItemExistence {
            do {
                let stat = try await stat(at: path)
                return SMB.ItemExistence(stat.type)
            }
            catch let error as SMB.Error {
                if error.isPathNotFound {
                    return .false
                }
                else {
                    throw error
                }
            }
        }
        
        /// Changes the timestamps of a file or directory.
        ///
        /// Only the timestamps that are provided are updated; omitted timestamps are left unchanged on the server.
        ///
        /// - Parameters:
        ///   - path: The path to the file or directory, relative to the share root.
        ///   - creation: The new creation time, or `nil` to leave it unchanged.
        ///   - change: The new metadata-change time, or `nil` to leave it unchanged.
        ///   - write: The new last-write time, or `nil` to leave it unchanged.
        ///   - access: The new last-access time, or `nil` to leave it unchanged.
        /// - Throws: ``SMB/Error`` if the connection is closed, the path is invalid, or the server rejects the update.
        public func changeDate(
            at path: String,
            creation: Date? = nil,
            change: Date? = nil,
            write: Date? = nil,
            access: Date? = nil
        ) async throws {
            let path = try SMB.validatePath(path, operation: .smb2SetBasicInfo)
            let context = try requireContext()
            try await Bridge.setStats(
                context: context,
                path: path,
                creationTime: creation,
                lastAccessTime: access,
                lastWriteTime: write,
                changeTime: change
            )
        }

        /// Returns the file attributes for a path.
        ///
        /// - Parameter path: The path to the file or directory, relative to the share root.
        /// - Returns: The current file attributes.
        /// - Throws: ``SMB/Error`` if the connection is closed, the path is invalid, or the server rejects the query.
        public func attributes(at path: String) async throws -> FileAttributes {
            let path = try SMB.validatePath(path, operation: .smb2SetBasicInfo, allowRoot: true)
            let context = try requireContext()
            let raw = try await Bridge.getFileAttributes(context: context, path: path)
            return FileAttributes(rawValue: raw)
        }

        /// Changes the attributes of a file or directory.
        ///
        /// The closure receives the current attributes and returns the new ones, making it easy to mutate individual
        /// flags while leaving others intact.
        ///
        /// - Parameters:
        ///   - path: The path to the file or directory, relative to the share root.
        ///   - change: A closure that receives the current attributes and returns the updated attributes.
        /// - Throws: ``SMB/Error`` if the connection is closed, the path is invalid, or the server rejects the update.
        public func changeAttributes(
            at path: String,
            _ change: (FileAttributes) -> FileAttributes
        ) async throws {
            let path = try SMB.validatePath(path, operation: .smb2SetBasicInfo)
            let context = try requireContext()
            let current = try await attributes(at: path)
            let new = change(current)
            // On the wire, FileAttributes 0 means "leave unchanged" (MS-FSCC); clearing every flag must be sent as
            // FILE_ATTRIBUTE_NORMAL instead.
            try await Bridge.setStats(
                context: context,
                path: path,
                fileAttributes: new.isEmpty ? FileAttributes.normal.rawValue : new.rawValue
            )
        }

        /// Returns filesystem statistics for a path.
        ///
        /// - Parameter path: A path on the share.
        /// - Returns: Filesystem statistics reported by the server.
        /// - Throws: ``SMB/Error`` if statistics cannot be read.
        public func statFilesystem(at path: String = "") async throws -> FilesystemStat {
            let path = try SMB.validatePath(path, operation: .smb2Statvfs, allowRoot: true)
            let context = try requireContext()
            return try await FilesystemStat(Bridge.statVFS(context: context, path: path))
        }

        /// Returns the live bridge context or throws if the connection is closed.
        func requireContext() throws -> Bridge.Context {
            try protectedContext.require {
                .operationRequestedAfterConnectionClosed
            }
        }

        /// Takes ownership of the context and marks the connection closed.
        private func takeContext() -> Bridge.Context? {
            protectedContext.take()
        }

        public var debugDescription: String {
            "SMB.Connection(server: \(server.debugDescription), share: \(share), isConnected: \(isConnected))"
        }
    }
}

private extension SMB.Error {
    /// A Boolean value indicating whether the error represents a missing path.
    var isPathNotFound: Bool {
        switch self {
        case let .ntStatus(status, _, _, _):
            status == .noSuchFile || status == .objectNameNotFound
        case let .posix(code, _, _):
            code == POSIXErrorCode.ENOENT.rawValue
        default:
            false
        }
    }
}
