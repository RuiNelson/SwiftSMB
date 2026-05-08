//
// Part of SwiftSMB
// SMBDirectory.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

public extension SMB {
    /// An open directory handle on an SMB share.
    final class Directory: CustomDebugStringConvertible, Sendable {
        /// The path used to open the directory.
        public let path: String

        private let connection: Connection
        private let protectedHandle = Protected<SMB2DirectoryHandle?>(nil, label: "SwiftSMB.SMB.Directory.handle")

        /// The live bridge directory handle, if the directory is still open.
        private var handle: SMB2DirectoryHandle? {
            get {
                protectedHandle.current
            }
            set {
                protectedHandle.current = newValue
            }
        }

        /// Creates a public directory wrapper around an open bridge handle.
        init(connection: Connection, path: String, handle: SMB2DirectoryHandle) {
            self.connection = connection
            self.path = path
            self.handle = handle
        }

        deinit {
            if let handle = takeHandle(), let context = try? connection.requireContext() {
                try? SMB.run {
                    SwiftSMB.closeDir(context: context, directory: handle)
                }
            }
        }

        /// A Boolean value indicating whether the directory handle is still open.
        public var isOpen: Bool {
            handle != nil
        }

        /// Closes the directory handle.
        ///
        /// Calling this method more than once is allowed.
        public func close() {
            guard let handle = takeHandle(),
                  let context = try? connection.requireContext() else {
                return
            }
            try? SMB.run {
                SwiftSMB.closeDir(context: context, directory: handle)
            }
        }

        /// Reads the next directory entry.
        ///
        /// - Returns: The next entry, or `nil` when the directory stream is exhausted.
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func readNext() throws -> DirectoryEntry? {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Readdir)
            return try SMB.run {
                SwiftSMB.readDir(context: context, directory: handle).map(DirectoryEntry.init)
            }
        }

        /// Rewinds the directory stream to the beginning.
        ///
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func rewind() throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Rewinddir)
            try SMB.run {
                SwiftSMB.rewindDir(context: context, directory: handle)
            }
        }

        /// Returns the current directory stream location.
        ///
        /// - Returns: A stream position that can be passed to ``seek(to:)``.
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func tell() throws -> Int {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Telldir)
            return try SMB.run {
                SwiftSMB.tellDir(context: context, directory: handle)
            }
        }

        /// Moves the directory stream to a previous location.
        ///
        /// - Parameter location: A position returned by ``tell()``.
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func seek(to location: Int) throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Seekdir)
            try SMB.run {
                SwiftSMB.seekDir(context: context, directory: handle, location: location)
            }
        }

        /// Returns the live bridge handle or throws if the directory is closed.
        private func requireHandle(operation: SMB.Error.InvalidArgumentOperation) throws -> SMB2DirectoryHandle {
            guard let handle else {
                throw SMB.Error.invalidArgument(cause: .directoryAlreadyClosed, onOperation: operation)
            }
            return handle
        }

        /// Takes ownership of the handle and marks the directory closed.
        private func takeHandle() -> SMB2DirectoryHandle? {
            protectedHandle.take(replacingWith: nil)
        }

        public var debugDescription: String {
            "SMB.Directory(path: \(path), isOpen: \(isOpen))"
        }
    }
}
