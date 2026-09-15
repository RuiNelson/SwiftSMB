//
// Part of SwiftSMB
// Directory.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB {
    /// An open directory handle on an SMB share.
    final class Directory: CustomDebugStringConvertible, Sendable {
        /// The path used to open the directory.
        public let path: String

        private let connection: Connection
        private let protectedHandle = ProtectedHandle<Bridge.DirectoryHandle>(
            label: "com.ruinelson.SwiftSMB.SMB.Directory.handle"
        )

        /// The live bridge directory handle, if the directory is still open.
        private var handle: Bridge.DirectoryHandle? {
            get {
                protectedHandle.current
            }
            set {
                protectedHandle.current = newValue
            }
        }

        /// Creates a public directory wrapper around an open bridge handle.
        init(connection: Connection, path: String, handle: Bridge.DirectoryHandle) {
            self.connection = connection
            self.path = path
            self.handle = handle
        }

        deinit {
            if let handle = takeHandle(), let context = try? connection.requireContext() {
                Bridge.closeDirInBackground(context: context, directory: handle)
            }
        }

        /// A Boolean value indicating whether the directory handle is still open.
        public var isOpen: Bool {
            handle != nil
        }

        /// Closes the directory handle.
        ///
        /// Calling this method more than once is allowed.
        public func close() async {
            guard let handle = takeHandle(),
                  let context = try? connection.requireContext() else {
                return
            }
            try? await Bridge.closeDir(context: context, directory: handle)
        }

        /// Reads the next directory entry.
        ///
        /// - Returns: The next entry, or `nil` when the directory stream is exhausted.
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func readNext() async throws -> DirectoryEntry? {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Readdir)
            return try await Bridge.readDir(context: context, directory: handle).map(DirectoryEntry.init)
        }

        /// Rewinds the directory stream to the beginning.
        ///
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func rewind() async throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Rewinddir)
            try await Bridge.rewindDir(context: context, directory: handle)
        }

        /// Returns the current directory stream location.
        ///
        /// - Returns: A stream position that can be passed to ``seek(to:)``.
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func tell() async throws -> Int {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Telldir)
            return try await Bridge.tellDir(context: context, directory: handle)
        }

        /// Moves the directory stream to a previous location.
        ///
        /// - Parameter location: A position returned by ``tell()``.
        /// - Throws: ``SMB/Error`` if the directory is closed.
        public func seek(to location: Int) async throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Seekdir)
            try await Bridge.seekDir(context: context, directory: handle, location: location)
        }

        /// Returns the live bridge handle or throws if the directory is closed.
        private func requireHandle(operation: SMB.Error.InvalidArgumentOperation) throws -> Bridge.DirectoryHandle {
            try protectedHandle.require {
                .invalidArgument(cause: .directoryAlreadyClosed, onOperation: operation)
            }
        }

        /// Takes ownership of the handle and marks the directory closed.
        private func takeHandle() -> Bridge.DirectoryHandle? {
            protectedHandle.take()
        }

        public var debugDescription: String {
            "SMB.Directory(path: \(path), isOpen: \(isOpen))"
        }
    }
}
