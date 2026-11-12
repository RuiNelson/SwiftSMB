//
// Part of SwiftSMB
// File.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
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
            ///
            /// Each write refreshes the file's current length. Writers on separate connections must coordinate access,
            /// for example with an exclusive file lock, to prevent concurrent append writes from overlapping.
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
        private let protectedHandle = ProtectedHandle<Bridge.FileHandle>(
            label: "com.ruinelson.SwiftSMB.SMB.File.handle"
        )

        /// The live bridge file handle, if the file is still open.
        private var handle: Bridge.FileHandle? {
            get {
                protectedHandle.current
            }
            set {
                protectedHandle.current = newValue
            }
        }

        /// The access mode the file was opened with.
        let accessMode: AccessMode

        /// The options the file was opened with.
        let options: OpenOptions

        /// The connection's cache attachment when the file was opened, kept until the file closes. See
        /// ``Connection/attachCache(_:)``.
        let cacheAttachment: SMBCacheAttachment?

        /// The file's registration in the attachment's ``OpenFileRegistry``, made before the server opened it.
        let registration: UInt64?

        /// Whether a write was attempted, so closing the file reports its final metadata to the cache.
        let protectedWroteToFile = Protected(false, label: "com.ruinelson.SwiftSMB.SMB.File.wroteToFile")

        /// Creates a public file wrapper around an open bridge handle.
        ///
        /// - Parameters:
        ///   - cacheAttachment: The connection's cache attachment when the file was opened.
        ///   - registration: The file's registration with the attachment's ``OpenFileRegistry``.
        init(
            connection: Connection,
            path: String,
            handle: Bridge.FileHandle,
            accessMode: AccessMode = .readOnly,
            options: OpenOptions = [],
            cacheAttachment: SMBCacheAttachment? = nil,
            registration: UInt64? = nil
        ) {
            self.connection = connection
            self.path = path
            self.accessMode = accessMode
            self.options = options
            self.cacheAttachment = cacheAttachment
            self.registration = cacheAttachment == nil ? nil : registration
            self.handle = handle
        }

        deinit {
            let handle = takeHandle()
            if let handle, let context = try? connection.requireContext() {
                Bridge.closeInBackground(context: context, file: handle)
            }
            if handle != nil {
                abandonCacheReportsInBackground()
            }
        }

        /// A Boolean value indicating whether the file handle is still open.
        public var isOpen: Bool {
            handle != nil && connection.isConnected
        }

        /// Closes the file handle.
        ///
        /// A file written while it used a cache stats itself before closing, one more round trip, so the cache learns
        /// which version of the file the written blocks belong to. Calling this method more than once is allowed.
        ///
        /// - Throws: ``SMB/Error`` if the server reports a close error.
        public func close() async throws {
            guard let handle = takeHandle() else { return }
            guard cacheAttachment != nil else {
                let context = try connection.requireContext()
                try await Bridge.close(context: context, file: handle)
                return
            }
            try await closeReportingToCache(handle)
        }
        
        /// Reads bytes from the file.
        ///
        /// When `upTo` is `nil`, reads until end of file. Reading to end of file may consume unbounded memory for large
        /// files.
        ///
        /// A file opened for reading while a cache was attached reads what the cache holds first, and only the rest
        /// from the server. A read that fails then leaves the file's current offset where it was.
        ///
        /// - Parameters:
        ///   - upTo: The maximum number of bytes to read, or `nil` to read to EOF.
        ///   - transferChunkSize: The preferred transfer block size, or `nil` to use the server's maximum read size.
        /// - Returns: The bytes read. An empty value indicates end of file.
        /// - Throws: ``SMB/Error`` if the read fails, or `CancellationError` if the task is cancelled between chunks.
        public func read(
            upTo: Int64? = nil,
            transferChunkSize: Int64? = nil
        ) async throws -> Data {
            try await connection.withOperation {
                if let upTo, upTo <= 0 {
                    return Data()
                }

                // Clamps to the server maximum and rejects non-positive sizes.
                let chunkSize = try await connection
                    .acceptedReadBlockSize(transferChunkSize.map { Int(clamping: $0) } ?? .max)
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Read)

                if consultsCache {
                    return try await readAtPositionThroughCache(
                        upTo: upTo,
                        chunkSize: chunkSize,
                        context: context,
                        handle: handle
                    )
                }

                var result = Data()
                var remaining = upTo

                while remaining == nil || remaining! > 0 {
                    try Task.checkCancellation()
                    let byteCount = remaining.map { Int(min($0, Int64(chunkSize))) } ?? chunkSize
                    let data = try await Bridge.read(context: context, file: handle, count: byteCount)
                    guard !data.isEmpty else { break }
                    result.append(data)
                    remaining = remaining.map { $0 - Int64(data.count) }
                }

                return result
            }
        }

        /// Reads bytes from the file, starting at an explicit offset.
        ///
        /// Unlike ``read(upTo:transferChunkSize:)``, this method doesn't use or move the file's current offset, so
        /// concurrent tasks can read different ranges of the same handle without coordinating seeks. Like it, the
        /// method reads what an attached cache holds first.
        ///
        /// - Parameters:
        ///   - upTo: The maximum number of bytes to read.
        ///   - offset: The absolute file offset at which reading starts.
        ///   - transferChunkSize: The preferred transfer block size, or `nil` to use the server's maximum read size.
        /// - Returns: The bytes read. The value is shorter than `upTo` when the end of the file is reached, and empty
        /// when `offset` is at or past the end of the file.
        /// - Throws: ``SMB/Error`` if the read fails, or `CancellationError` if the task is cancelled between chunks.
        public func read(
            upTo: Int64,
            atOffset offset: UInt64,
            transferChunkSize: Int64? = nil
        ) async throws -> Data {
            try await connection.withOperation {
                guard upTo > 0 else {
                    return Data()
                }

                // Clamps to the server maximum and rejects non-positive sizes.
                let chunkSize = try await connection
                    .acceptedReadBlockSize(transferChunkSize.map { Int(clamping: $0) } ?? .max)
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Pread)

                return try await readThroughCache(
                    upTo: Int(clamping: upTo),
                    atOffset: offset,
                    chunkSize: chunkSize,
                    context: context,
                    handle: handle
                )
            }
        }

        /// Reads up to `upTo` bytes from the server starting at `offset`, in blocks of `chunkSize`, without moving the
        /// file's current offset.
        ///
        /// - Returns: The bytes read, shorter than `upTo` at the end of the file.
        func readFromServer(
            upTo: Int,
            atOffset offset: UInt64,
            chunkSize: Int,
            context: Bridge.Context,
            handle: Bridge.FileHandle
        ) async throws -> Data {
            var result = Data()
            var remaining = upTo
            var position = offset

            while remaining > 0 {
                try Task.checkCancellation()
                let byteCount = min(remaining, chunkSize)
                let data = try await Bridge.read(context: context, file: handle, count: byteCount, offset: position)
                guard !data.isEmpty else { break }
                result.append(data)
                remaining -= data.count
                let (next, overflow) = position.addingReportingOverflow(UInt64(data.count))
                guard !overflow else { break }
                position = next
            }

            return result
        }

        /// Writes bytes to the file.
        ///
        /// Data larger than the transfer chunk size is automatically split into accepted block sizes.
        ///
        /// - Parameters:
        ///   - data: The bytes to write.
        ///   - transferChunkSize: The preferred transfer block size, or `nil` to use the server's maximum write size.
        /// Values above the server maximum are clamped.
        /// - Returns: The total number of bytes written.
        /// - Throws: ``SMB/Error`` if the write fails or no progress is made, or `CancellationError` if the task is
        /// cancelled between chunks. Chunks written before cancellation stay written.
        @discardableResult
        public func write(
            _ data: Data,
            transferChunkSize: Int64? = nil
        ) async throws -> Int64 {
            try await connection.withOperation {
                let maxWriteSize = try await Int64(connection.maxWriteSize)
                // The server accepts at most `maxWriteSize` bytes per write, so a larger chunk would only be copied
                // again, minus the accepted prefix, on every iteration.
                let chunkSize = min(transferChunkSize ?? maxWriteSize, maxWriteSize)
                guard chunkSize > 0 else {
                    throw SMB.Error.invalidArgument(
                        cause: .blockSizeMustBeGreaterThanZero,
                        onOperation: .smb2Write
                    )
                }
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Write)

                // The server decides where appended bytes land, so only other writes need the position they start at.
                let appends = options.contains(.append)
                let cacheOffset: UInt64? = if cacheAttachment != nil, !appends {
                    try await Bridge.seek(context: context, file: handle, offset: 0, whence: SEEK_CUR)
                }
                else {
                    nil
                }
                let snapshot = changeSnapshot
                if !data.isEmpty {
                    protectedWroteToFile.current = true
                }

                // Index relative to startIndex: `data` may be a slice whose indices do not begin at zero.
                let maxChunk = Int(min(chunkSize, Int64(data.count)))
                var written: Int64 = 0
                // Bytes handed to a write call that has not returned, which may reach the file if it fails.
                var inFlight = 0

                do {
                    while written < data.count {
                        try Task.checkCancellation()
                        let start = data.startIndex + Int(written)
                        let end = min(start + maxChunk, data.endIndex)
                        inFlight = end - start
                        let count = try await Bridge.write(
                            context: context,
                            file: handle,
                            data: data.subdata(in: start ..< end)
                        )
                        inFlight = 0
                        guard count > 0 else {
                            throw SMB.Error.unknown(
                                operation: "smb2_write",
                                message: "Write made no progress before all data was written"
                            )
                        }
                        written += Int64(count)
                    }
                }
                catch {
                    await reportWrite(
                        data,
                        at: cacheOffset,
                        appends: appends,
                        acknowledged: Int(written),
                        inFlight: inFlight,
                        since: snapshot
                    )
                    throw error
                }

                await reportWrite(
                    data,
                    at: cacheOffset,
                    appends: appends,
                    acknowledged: Int(written),
                    inFlight: 0,
                    since: snapshot
                )
                return written
            }
        }

        /// Writes bytes to the file, starting at an explicit offset.
        ///
        /// Unlike ``write(_:transferChunkSize:)``, this method doesn't use or move the file's current offset, so
        /// concurrent tasks can write different ranges of the same handle without coordinating seeks. Writing past the
        /// end of the file extends it; the server fills the gap as its file system does, usually with zeros. The
        /// ``OpenOptions/append`` option doesn't apply: the bytes always go to `offset`.
        ///
        /// - Parameters:
        ///   - data: The bytes to write.
        ///   - offset: The absolute file offset at which writing starts.
        ///   - transferChunkSize: The preferred transfer block size, or `nil` to use the server's maximum write size.
        /// Values above the server maximum are clamped.
        /// - Returns: The total number of bytes written.
        /// - Throws: ``SMB/Error`` if the write fails, makes no progress, or would end past the largest representable
        /// offset, or `CancellationError` if the task is cancelled between chunks. Chunks written before cancellation
        /// stay written.
        @discardableResult
        public func write(
            _ data: Data,
            atOffset offset: UInt64,
            transferChunkSize: Int64? = nil
        ) async throws -> Int64 {
            try await connection.withOperation {
                let maxWriteSize = try await Int64(connection.maxWriteSize)
                let chunkSize = min(transferChunkSize ?? maxWriteSize, maxWriteSize)
                guard chunkSize > 0 else {
                    throw SMB.Error.invalidArgument(
                        cause: .blockSizeMustBeGreaterThanZero,
                        onOperation: .smb2Pwrite
                    )
                }
                guard UInt64(data.count) <= UInt64.max - offset else {
                    throw SMB.Error.posix(
                        code: POSIXErrorCode.EFBIG.rawValue,
                        operation: "smb2_pwrite",
                        message: "Write would end past the largest representable file offset"
                    )
                }
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Pwrite)
                let snapshot = changeSnapshot
                if !data.isEmpty {
                    protectedWroteToFile.current = true
                }

                // Index relative to startIndex: `data` may be a slice whose indices do not begin at zero.
                let maxChunk = Int(min(chunkSize, Int64(data.count)))
                var written: Int64 = 0
                // Bytes handed to a write call that has not returned, which may reach the file if it fails.
                var inFlight = 0

                do {
                    while written < data.count {
                        try Task.checkCancellation()
                        let start = data.startIndex + Int(written)
                        let end = min(start + maxChunk, data.endIndex)
                        inFlight = end - start
                        let count = try await Bridge.write(
                            context: context,
                            file: handle,
                            data: data.subdata(in: start ..< end),
                            offset: offset + UInt64(written)
                        )
                        inFlight = 0
                        guard count > 0 else {
                            throw SMB.Error.unknown(
                                operation: "smb2_pwrite",
                                message: "Write made no progress before all data was written"
                            )
                        }
                        written += Int64(count)
                    }
                }
                catch {
                    await reportWrite(
                        data,
                        at: offset,
                        appends: false,
                        acknowledged: Int(written),
                        inFlight: inFlight,
                        since: snapshot
                    )
                    throw error
                }

                await reportWrite(
                    data,
                    at: offset,
                    appends: false,
                    acknowledged: Int(written),
                    inFlight: 0,
                    since: snapshot
                )
                return written
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
        public func seek(offset: Int64, from origin: SeekOrigin) async throws -> UInt64 {
            try await connection.withOperation {
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Lseek)
                return try await Bridge.seek(context: context, file: handle, offset: offset, whence: origin.bridgeValue)
            }
        }

        /// Flushes pending writes for the file.
        ///
        /// - Throws: ``SMB/Error`` if the sync operation fails.
        public func sync() async throws {
            try await connection.withOperation {
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Fsync)
                try await Bridge.sync(context: context, file: handle)
            }
        }

        /// Truncates the file to a length in bytes.
        ///
        /// - Parameter length: The target file length.
        /// - Throws: ``SMB/Error`` if truncation fails.
        public func truncate(toLength length: UInt64) async throws {
            try await connection.withOperation {
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Ftruncate)
                do {
                    try await Bridge.truncate(context: context, file: handle, length: length)
                }
                catch {
                    // The truncation may have reached the server anyway.
                    await reportContentsChange()
                    throw error
                }
                await reportContentsChange()
            }
        }

        /// Returns metadata for the open file.
        ///
        /// - Returns: File metadata reported by the server.
        /// - Throws: ``SMB/Error`` if metadata cannot be read.
        public func stat() async throws -> Stat {
            try await connection.withOperation {
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Fstat)
                return try await statReportingToCache(context: context, handle: handle)
            }
        }
        
        /// Releases a byte-range lock previously acquired on the file.
        ///
        /// The unlock range must match the lock range exactly. Sub-ranges cannot be unlocked independently.
        ///
        /// - Parameter range: The byte range to unlock, or `nil` to unlock the entire file (matching a lock acquired
        /// without a range).
        /// - Throws: ``SMB/Error`` if the file is closed or the server reports an error.
        public func unlock(range: Range<Int64>? = nil) async throws {
            try await connection.withOperation {
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Flock)
                let (offset, length) = try Self.validateLockRange(range)
                try await Bridge.unlock(context: context, file: handle, offset: offset, length: length)
            }
        }

        /// The type of byte-range lock to acquire.
        public enum LockMode: Sendable {
            /// A shared (read) lock that allows other opens to read or take shared locks on the same range, but blocks
            /// writes.
            case shared

            /// An exclusive (write) lock that blocks other opens from reading, writing, or locking the same range.
            case exclusive
        }

        /// Opportunistic lock levels that can be requested when opening a file.
        ///
        /// OpLocks allow the client to cache data locally, reducing network round trips. The server may grant a lower
        /// level than requested.
        public enum OpLock: Sendable, Equatable {
            /// No oplock requested.
            case none

            /// Level II (shared) oplock — multiple readers can cache.
            case levelII

            /// Exclusive oplock — only one client may have the file open.
            case exclusive

            /// Batch oplock — like exclusive but also allows the client to pretend-closed the file without actually
            /// closing it.
            case batch

            /// Lease — SMB3 leasing with fine-grained caching states.
            case lease(LeaseState)

            /// The bridge oplock level for this oplock request.
            var bridgeValue: Bridge.OpLockLevel {
                switch self {
                case .none:
                    .none
                case .levelII:
                    .levelII
                case .exclusive:
                    .exclusive
                case .batch:
                    .batch
                case .lease:
                    .lease
                }
            }
        }

        /// Caching states for an SMB3 lease.
        ///
        /// These flags control which data the client may cache locally when a lease is granted.
        public struct LeaseState: OptionSet, Sendable, Equatable, CustomDebugStringConvertible {
            /// The raw lease state bitfield.
            public let rawValue: UInt32

            /// The client may cache reads.
            public static let readCaching = LeaseState(rawValue: 0x01)

            /// The client may cache handles (keeps the file open on the server).
            public static let handleCaching = LeaseState(rawValue: 0x02)

            /// The client may cache writes.
            public static let writeCaching = LeaseState(rawValue: 0x04)

            /// Creates a lease state from a raw bitfield.
            public init(rawValue: UInt32) {
                self.rawValue = rawValue
            }

            public var debugDescription: String {
                describeFlags([
                    (.readCaching, "readCaching"),
                    (.handleCaching, "handleCaching"),
                    (.writeCaching, "writeCaching"),
                ], typeName: "SMB.File.LeaseState")
            }

            /// The bridge representation for this lease state.
            var bridgeValue: Bridge.LeaseState {
                Bridge.LeaseState(rawValue: rawValue)
            }
        }

        /// Acquires a byte-range lock on the file.
        ///
        /// When `range` is `nil`, the lock covers the whole file. Only one mode can be specified at a time—shared and
        /// exclusive are mutually exclusive.
        ///
        /// A blocking lock (`nonBlocking: false`) waits until the conflicting lock is released, and other operations on
        /// the connection wait behind it. The server is asked to withdraw the request when the task is cancelled, when
        /// the connection's command timeout expires, or when the connection is disconnected, so the lock is never
        /// granted after this method has thrown. If the server grants the lock before the request is withdrawn, the
        /// lock is held and this method returns normally.
        ///
        /// - Parameters:
        ///   - mode: The lock mode, either ``LockMode/shared`` or ``LockMode/exclusive``.
        ///   - nonBlocking: When `true`, the operation fails immediately if the lock conflicts with an existing lock
        /// instead of waiting.
        ///   - range: The byte range to lock, or `nil` to lock the entire file.
        /// - Throws: ``SMB/Error`` if the file is closed, the lock range is invalid, the lock conflicts with an
        /// existing lock, the command timeout expires (``SMB/SMBStatus/ioTimeout``), the connection is disconnected
        /// while waiting (``SMB/Error/operationRequestedAfterConnectionClosed``), or the server reports an error.
        /// `CancellationError` if the task is cancelled while waiting.
        public func lock(_ mode: LockMode, nonBlocking: Bool, range: Range<Int64>? = nil) async throws {
            try await connection.withOperation {
                let context = try connection.requireContext()
                let handle = try requireHandle(operation: .smb2Flock)
                var flags: Bridge.LockFlags = switch mode {
                case .shared:
                    .shared
                case .exclusive:
                    .exclusive
                }
                if nonBlocking {
                    flags = Bridge.LockFlags(rawValue: flags.rawValue | Bridge.LockFlags.failImmediately.rawValue)
                }
                let (offset, length) = try Self.validateLockRange(range)
                try await Bridge.lock(context: context, file: handle, flags: flags, offset: offset, length: length)
            }
        }

        private static func validateLockRange(_ range: Range<Int64>?) throws -> (offset: UInt64, length: UInt64) {
            guard let range else {
                return (0, UInt64.max)
            }
            guard range.lowerBound >= 0 else {
                throw SMB.Error.invalidArgument(
                    cause: .invalidLockRange("lowerBound must be non-negative"),
                    onOperation: .smb2Flock
                )
            }
            guard !range.isEmpty else {
                throw SMB.Error.invalidArgument(
                    cause: .invalidLockRange("range must not be empty"),
                    onOperation: .smb2Flock
                )
            }
            let offset = UInt64(range.lowerBound)
            let length = UInt64(range.upperBound - range.lowerBound)
            return (offset, length)
        }

        /// Returns the live bridge handle or throws if the file is closed.
        func requireHandle(operation: SMB.Error.InvalidArgumentOperation) throws -> Bridge.FileHandle {
            try protectedHandle.require {
                .invalidArgument(cause: .fileAlreadyClosed, onOperation: operation)
            }
        }

        /// Takes ownership of the handle and marks the file closed.
        private func takeHandle() -> Bridge.FileHandle? {
            protectedHandle.take()
        }

        public var debugDescription: String {
            "SMB.File(path: \(path), isOpen: \(isOpen))"
        }
    }
}
