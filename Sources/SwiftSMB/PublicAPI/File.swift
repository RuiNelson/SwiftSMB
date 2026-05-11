//
// Part of SwiftSMB
// File.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

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
            var bridgeValue: Bridge.OpenAccessMode {
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
            var bridgeValue: Bridge.OpenOptions {
                var options = Bridge.OpenOptions()
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
        private let protectedHandle = Protected<Bridge.FileHandle?>(nil, label: "SwiftSMB.SMB.File.handle")

        /// The live bridge file handle, if the file is still open.
        private var handle: Bridge.FileHandle? {
            get {
                protectedHandle.current
            }
            set {
                protectedHandle.current = newValue
            }
        }

        /// Creates a public file wrapper around an open bridge handle.
        init(connection: Connection, path: String, handle: Bridge.FileHandle) {
            self.connection = connection
            self.path = path
            self.handle = handle
        }

        deinit {
            if let handle = takeHandle(), let context = try? connection.requireContext() {
                try? Bridge.close(context: context, file: handle)
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
            try Bridge.close(context: context, file: handle)
        }
        
        /// Reads bytes from the file.
        ///
        /// When `upTo` is `nil`, reads until end of file. Reading to end of file
        /// may consume unbounded memory for large files.
        ///
        /// - Parameters:
        ///   - upTo: The maximum number of bytes to read, or `nil` to read to EOF.
        ///   - transferChunkSize: The preferred transfer block size, or `nil` to
        ///     use the server's maximum read size.
        /// - Returns: The bytes read. An empty value indicates end of file.
        /// - Throws: ``SMB/Error`` if the read fails.
        public func read(
            upTo: Int64? = nil,
            transferChunkSize: Int64? = nil,
        ) throws -> Data {
            if let upTo, upTo <= 0 { return Data() }

            let chunkSize = try transferChunkSize ?? Int64(connection.maxReadSize)
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Read)

            var result = Data()
            var remaining = upTo

            while remaining == nil || remaining! > 0 {
                let byteCount = remaining.map { Int(min($0, chunkSize)) } ?? Int(chunkSize)
                let accepted = try connection.acceptedReadBlockSize(byteCount)
                var buffer = Data(repeating: 0, count: accepted)
                let readCount = try buffer.withUnsafeMutableBytes { rawBuffer in
                    try Bridge.read(
                        context: context,
                        file: handle,
                        into: MutableRawSpan(_unsafeBytes: rawBuffer),
                    )
                }
                guard readCount > 0 else { break }
                result.append(buffer.prefix(readCount))
                remaining = remaining.map { $0 - Int64(readCount) }
            }

            return result
        }

        /// Writes bytes to the file.
        ///
        /// Data larger than the transfer chunk size is automatically split into
        /// accepted block sizes.
        ///
        /// - Parameters:
        ///   - data: The bytes to write.
        ///   - transferChunkSize: The preferred transfer block size, or `nil` to
        ///     use the server's maximum write size.
        /// - Returns: The total number of bytes written.
        /// - Throws: ``SMB/Error`` if the write fails or no progress is made.
        @discardableResult
        public func write(
            _ data: Data,
            transferChunkSize: Int64? = nil,
        ) throws -> Int64 {
            let chunkSize = try transferChunkSize ?? Int64(connection.maxWriteSize)
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Write)

            var written: Int64 = 0

            while written < data.count {
                let end = min(Int(written) + Int(chunkSize), data.count)
                let count = try data.subdata(in: Int(written) ..< end).withUnsafeBytes { rawBuffer in
                    try Bridge.write(
                        context: context,
                        file: handle,
                        bytes: RawSpan(_unsafeBytes: rawBuffer),
                    )
                }
                guard count > 0 else {
                    throw SMB.Error.unknown(
                        operation: "smb2_write",
                        message: "Write made no progress before all data was written",
                    )
                }
                written += Int64(count)
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
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Lseek)
            return try Bridge.seek(context: context, file: handle, offset: offset, whence: origin.bridgeValue)
        }

        /// Flushes pending writes for the file.
        ///
        /// - Throws: ``SMB/Error`` if the sync operation fails.
        public func sync() throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Fsync)
            try Bridge.sync(context: context, file: handle)
        }

        /// Truncates the file to a length in bytes.
        ///
        /// - Parameter length: The target file length.
        /// - Throws: ``SMB/Error`` if truncation fails.
        public func truncate(toLength length: UInt64) throws {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Ftruncate)
            try Bridge.truncate(context: context, file: handle, length: length)
        }

        /// Returns metadata for the open file.
        ///
        /// - Returns: File metadata reported by the server.
        /// - Throws: ``SMB/Error`` if metadata cannot be read.
        public func stat() throws -> Stat {
            let context = try connection.requireContext()
            let handle = try requireHandle(operation: .smb2Fstat)
            return try Stat(Bridge.fileStatistics(context: context, file: handle))
        }

        /// Returns the live bridge handle or throws if the file is closed.
        private func requireHandle(operation: SMB.Error.InvalidArgumentOperation) throws -> Bridge.FileHandle {
            guard let handle else {
                throw SMB.Error.invalidArgument(cause: .fileAlreadyClosed, onOperation: operation)
            }
            return handle
        }

        /// Takes ownership of the handle and marks the file closed.
        private func takeHandle() -> Bridge.FileHandle? {
            protectedHandle.take(replacingWith: nil)
        }

        public var debugDescription: String {
            "SMB.File(path: \(path), isOpen: \(isOpen))"
        }
    }
}
