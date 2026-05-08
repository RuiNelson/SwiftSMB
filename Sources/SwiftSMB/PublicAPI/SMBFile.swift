//
// Part of SwiftSMB
// SMBFile.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Darwin
import Dispatch
import Foundation

public extension SMB {
    /// An open file handle on an SMB share.
    final class File: Sendable, CustomDebugStringConvertible {
        /// File access modes.
        public enum AccessMode: Equatable, Sendable {
            /// Open the file for reading.
            case readOnly

            /// Open the file for writing.
            case writeOnly

            /// Open the file for reading and writing.
            case readWrite

            /// The bridge representation for this access mode.
            var bridgeValue: SMB2OpenAccessMode {
                switch self {
                case .readOnly:
                    .readOnly
                case .writeOnly:
                    .writeOnly
                case .readWrite:
                    .readWrite
                }
            }
        }

        /// Additional options used when opening a file.
        public struct OpenOptions: OptionSet, Equatable, CustomDebugStringConvertible, Sendable {
            /// The raw option bitfield.
            public let rawValue: Int32

            /// Open the file in synchronous mode.
            public static let synchronous = OpenOptions(rawValue: 1 << 0)

            /// Create the file if it does not exist.
            public static let create = OpenOptions(rawValue: 1 << 1)

            /// Fail if the file already exists.
            public static let exclusive = OpenOptions(rawValue: 1 << 2)

            /// Truncate the file when opening it.
            public static let truncate = OpenOptions(rawValue: 1 << 3)

            /// Append writes to the end of the file.
            public static let append = OpenOptions(rawValue: 1 << 4)

            /// Creates an open options value from a raw bitfield.
            public init(rawValue: Int32) {
                self.rawValue = rawValue
            }

            public var debugDescription: String {
                describeFlags([
                    (.synchronous, "synchronous"),
                    (.create, "create"),
                    (.exclusive, "exclusive"),
                    (.truncate, "truncate"),
                    (.append, "append"),
                ], typeName: "SMB.File.OpenOptions")
            }

            /// The bridge representation for these options.
            var bridgeValue: SMB2OpenOptions {
                var options = SMB2OpenOptions()
                if contains(.synchronous) {
                    options.insert(.synchronous)
                }
                if contains(.create) {
                    options.insert(.create)
                }
                if contains(.exclusive) {
                    options.insert(.exclusive)
                }
                if contains(.truncate) {
                    options.insert(.truncate)
                }
                if contains(.append) {
                    options.insert(.append)
                }
                return options
            }
        }

        /// Origins used when seeking in a file.
        public enum SeekOrigin: Equatable, Sendable {
            /// Seek relative to the beginning of the file.
            case start

            /// Seek relative to the current file offset.
            case current

            /// Seek relative to the end of the file.
            case end

            /// The POSIX `whence` value for this origin.
            var bridgeValue: Int32 {
                switch self {
                case .start:
                    SEEK_SET
                case .current:
                    SEEK_CUR
                case .end:
                    SEEK_END
                }
            }

            public var debugDescription: String {
                String(reflecting: self)
            }
        }

        /// The path used to open the file.
        public let path: String

        let connection: Connection
        private let protectedHandle = Protected<SMB2FileHandle?>(nil, label: "SwiftSMB.SMB.File.handle")

        /// The live bridge file handle, if the file is still open.
        private var handle: SMB2FileHandle? {
            get {
                protectedHandle.current
            }
            set {
                protectedHandle.current = newValue
            }
        }

        /// Creates a public file wrapper around an open bridge handle.
        init(connection: Connection, path: String, handle: SMB2FileHandle) {
            self.connection = connection
            self.path = path
            self.handle = handle
        }

        deinit {
            if let handle = takeHandle(), let context = try? connection.requireContext() {
                try? SMB.run {
                    try SwiftSMB.close(context: context, file: handle)
                }
            }
        }

        /// A Boolean value indicating whether the file handle is still open.
        public var isOpen: Bool {
            handle != nil
        }

        /// Closes the file handle.
        ///
        /// Calling this method more than once is allowed.
        ///
        /// - Throws: ``SMB/Error`` if the server reports a close error.
        public func close() throws {
            guard let handle = takeHandle() else { return }
            let context = try connection.requireContext()
            try SMB.run {
                try SwiftSMB.close(context: context, file: handle)
            }
        }

        /// Reads bytes from the current file offset.
        ///
        /// If `byteCount` is larger than the server's maximum read size, the
        /// request is clamped to the accepted read block size.
        ///
        /// - Parameter byteCount: The preferred number of bytes to read.
        /// - Returns: The bytes read. An empty value indicates end of file.
        /// - Throws: ``SMB/Error`` if the read fails.
        public func read(upToByteCount byteCount: Int) throws -> Data {
            try readBytes(upToByteCount: byteCount, atOffset: nil)
        }

        /// Reads bytes at an explicit file offset.
        ///
        /// If `byteCount` is larger than the server's maximum read size, the
        /// request is clamped to the accepted read block size.
        ///
        /// - Parameters:
        ///   - byteCount: The preferred number of bytes to read.
        ///   - offset: The file offset to read from.
        /// - Returns: The bytes read. An empty value indicates end of file.
        /// - Throws: ``SMB/Error`` if the read fails.
        public func read(upToByteCount byteCount: Int, atOffset offset: UInt64) throws -> Data {
            try readBytes(upToByteCount: byteCount, atOffset: offset)
        }

        /// Writes bytes at the current file offset.
        ///
        /// - Parameter data: The bytes to write.
        /// - Returns: The number of bytes written.
        /// - Throws: ``SMB/Error`` if the write fails.
        @discardableResult
        public func write(_ data: Data) throws -> Int {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Write)
            return try SMB.run {
                try data.withUnsafeBytes { rawBuffer in
                    try SwiftSMB.write(context: context, file: handle, bytes: RawSpan(_unsafeBytes: rawBuffer))
                }
            }
        }

        /// Writes bytes at an explicit file offset.
        ///
        /// - Parameters:
        ///   - data: The bytes to write.
        ///   - offset: The file offset to write to.
        /// - Returns: The number of bytes written.
        /// - Throws: ``SMB/Error`` if the write fails.
        @discardableResult
        public func write(_ data: Data, atOffset offset: UInt64) throws -> Int {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Pwrite)
            return try SMB.run {
                try data.withUnsafeBytes { rawBuffer in
                    try SwiftSMB.write(
                        context: context,
                        file: handle,
                        bytes: RawSpan(_unsafeBytes: rawBuffer),
                        offset: offset,
                    )
                }
            }
        }

        /// Moves the current file offset.
        ///
        /// - Parameters:
        ///   - offset: The offset to apply.
        ///   - origin: The origin from which `offset` is interpreted.
        /// - Returns: The resulting absolute file offset.
        /// - Throws: ``SMB/Error`` if seeking fails.
        @discardableResult
        public func seek(offset: Int64, from origin: SeekOrigin) throws -> UInt64 {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Lseek)
            return try SMB.run {
                try SwiftSMB.seek(context: context, file: handle, offset: offset, whence: origin.bridgeValue)
            }
        }

        /// Flushes pending writes for the file.
        ///
        /// - Throws: ``SMB/Error`` if the sync operation fails.
        public func sync() throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Fsync)
            try SMB.run {
                try SwiftSMB.sync(context: context, file: handle)
            }
        }

        /// Truncates the file to a length in bytes.
        ///
        /// - Parameter length: The target file length.
        /// - Throws: ``SMB/Error`` if truncation fails.
        public func truncate(toLength length: UInt64) throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Ftruncate)
            try SMB.run {
                try SwiftSMB.truncate(context: context, file: handle, length: length)
            }
        }

        /// Returns metadata for the open file.
        ///
        /// - Returns: File metadata reported by the server.
        /// - Throws: ``SMB/Error`` if metadata cannot be read.
        public func stat() throws -> Stat {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Fstat)
            return try SMB.run {
                try Stat(SwiftSMB.fileStatistics(context: context, file: handle))
            }
        }

        /// Shared implementation for positioned and unpositioned reads.
        private func readBytes(upToByteCount byteCount: Int, atOffset offset: UInt64?) throws -> Data {
            let operation: SMB.Error.InvalidArgumentOperation = offset == nil ? .smb2Read : .smb2Pread
            guard byteCount >= 0 else {
                throw SMB.Error.invalidArgument(
                    cause: .byteCountMustBeNonNegative,
                    onOperation: operation,
                )
            }
            guard byteCount > 0 else {
                return Data()
            }
            let acceptedByteCount = try connection.acceptedReadBlockSize(byteCount)
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: operation)
            var data = Data(repeating: 0, count: acceptedByteCount)
            let readCount = try SMB.run {
                try data.withUnsafeMutableBytes { rawBuffer in
                    if let offset {
                        try SwiftSMB.read(
                            context: context,
                            file: handle,
                            into: MutableRawSpan(_unsafeBytes: rawBuffer),
                            offset: offset,
                        )
                    }
                    else {
                        try SwiftSMB.read(
                            context: context,
                            file: handle,
                            into: MutableRawSpan(_unsafeBytes: rawBuffer),
                        )
                    }
                }
            }

            return data.prefix(readCount)
        }

        /// Returns the live bridge handle or throws if the file is closed.
        private func requireHandle(operation: SMB.Error.InvalidArgumentOperation) throws -> SMB2FileHandle {
            guard let handle else {
                throw SMB.Error.invalidArgument(cause: .fileAlreadyClosed, onOperation: operation)
            }
            return handle
        }

        /// Takes ownership of the handle and marks the file closed.
        private func takeHandle() -> SMB2FileHandle? {
            protectedHandle.take(replacingWith: nil)
        }

        public var debugDescription: String {
            "SMB.File(path: \(path), isOpen: \(isOpen))"
        }
    }
}
