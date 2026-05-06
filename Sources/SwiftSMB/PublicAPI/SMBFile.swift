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
    final class File: Sendable {
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
        public struct OpenOptions: OptionSet, Equatable, Sendable {
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
        }

        /// The path used to open the file.
        public let path: String

        private let connection: Connection
        private let protectedHandle = SMBProtected<SMB2FileHandle?>(nil, label: "SwiftSMB.SMB.File.handle")

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
            if let handle = takeHandle(), let context = try? connection.requireContext(operation: "smb2_close") {
                try? SwiftSMB.close(context: context, file: handle)
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
            let context = try connection.requireContext(operation: "smb2_close")
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

        /// Reads from the current file offset until end of file.
        ///
        /// - Parameter chunkSize: The preferred read block size. Values above
        ///   the server maximum are clamped automatically.
        /// - Returns: All bytes from the current file offset to end of file.
        /// - Throws: ``SMB/Error`` if any read fails.
        public func readToEnd(chunkSize: Int? = nil) throws -> Data {
            let resolvedChunkSize = try connection.acceptedReadBlockSize(chunkSize)
            var result = Data()

            while true {
                let chunk = try read(upToByteCount: resolvedChunkSize)
                guard !chunk.isEmpty else { break }
                result.append(chunk)
            }

            return result
        }

        /// Writes bytes at the current file offset.
        ///
        /// - Parameter data: The bytes to write.
        /// - Returns: The number of bytes written.
        /// - Throws: ``SMB/Error`` if the write fails.
        @discardableResult
        public func write(_ data: Data) throws -> Int {
            let context = try connection.requireContext(operation: "smb2_write")
            let handle = try requireHandle(operation: "smb2_write")
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
            let context = try connection.requireContext(operation: "smb2_pwrite")
            let handle = try requireHandle(operation: "smb2_pwrite")
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

        /// Writes all bytes, splitting the transfer into accepted block sizes.
        ///
        /// - Parameters:
        ///   - data: The bytes to write.
        ///   - chunkSize: The preferred write block size. Values above the
        ///     server maximum are clamped automatically.
        /// - Returns: The total number of bytes written.
        /// - Throws: ``SMB/Error`` if any write fails or no progress is made.
        @discardableResult
        public func writeAll(_ data: Data, chunkSize: Int? = nil) throws -> Int {
            let resolvedChunkSize = try connection.acceptedWriteBlockSize(chunkSize)
            var written = 0

            while written < data.count {
                let end = min(written + resolvedChunkSize, data.count)
                let count = try write(data.subdata(in: written ..< end))
                guard count > 0 else {
                    throw SMB.Error.unknown(
                        operation: "smb2_write",
                        message: "Write made no progress before all data was written",
                    )
                }
                written += count
            }

            return written
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
            let context = try connection.requireContext(operation: "smb2_lseek")
            let handle = try requireHandle(operation: "smb2_lseek")
            return try SMB.run {
                try SwiftSMB.seek(context: context, file: handle, offset: offset, whence: origin.bridgeValue)
            }
        }

        /// Flushes pending writes for the file.
        ///
        /// - Throws: ``SMB/Error`` if the sync operation fails.
        public func sync() throws {
            let context = try connection.requireContext(operation: "smb2_fsync")
            let handle = try requireHandle(operation: "smb2_fsync")
            try SMB.run {
                try SwiftSMB.sync(context: context, file: handle)
            }
        }

        /// Truncates the file to a length in bytes.
        ///
        /// - Parameter length: The target file length.
        /// - Throws: ``SMB/Error`` if truncation fails.
        public func truncate(toLength length: UInt64) throws {
            let context = try connection.requireContext(operation: "smb2_ftruncate")
            let handle = try requireHandle(operation: "smb2_ftruncate")
            try SMB.run {
                try SwiftSMB.truncate(context: context, file: handle, length: length)
            }
        }

        /// Returns metadata for the open file.
        ///
        /// - Returns: File metadata reported by the server.
        /// - Throws: ``SMB/Error`` if metadata cannot be read.
        public func stat() throws -> Stat {
            let context = try connection.requireContext(operation: "smb2_fstat")
            let handle = try requireHandle(operation: "smb2_fstat")
            return try SMB.run {
                try Stat(SwiftSMB.fileStatistics(context: context, file: handle))
            }
        }

        /// Shared implementation for positioned and unpositioned reads.
        private func readBytes(upToByteCount byteCount: Int, atOffset offset: UInt64?) throws -> Data {
            guard byteCount >= 0 else {
                throw SMB.Error.invalidArgument(
                    operation: offset == nil ? "smb2_read" : "smb2_pread",
                    message: "Byte count must be greater than or equal to zero",
                )
            }
            guard byteCount > 0 else {
                return Data()
            }

            let operation = offset == nil ? "smb2_read" : "smb2_pread"
            let acceptedByteCount = try connection.acceptedReadBlockSize(byteCount)
            let context = try connection.requireContext(operation: operation)
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
        private func requireHandle(operation: String) throws -> SMB2FileHandle {
            guard let handle else {
                throw SMB.Error.invalidArgument(operation: operation, message: "File is already closed")
            }
            return handle
        }

        /// Takes ownership of the handle and marks the file closed.
        private func takeHandle() -> SMB2FileHandle? {
            protectedHandle.take(replacingWith: nil)
        }
    }
}
