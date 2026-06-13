//
// Part of SwiftSMB
// Connection-Conv-Transfer.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

#if canImport(Android)
import Android
#endif
import Foundation
import PathWorks

public extension SMB.Connection {
    /// The starting position for a file transfer.
    ///
    /// Use this value to start an upload or download operation at the beginning of the file or at a specific byte
    /// offset. Offset-based transfers are useful for resuming an interrupted operation when the caller has already
    /// verified that the source and destination share the same prefix.
    enum FromArgument {
        /// Start the transfer at byte offset zero.
        case beginning

        /// Start the transfer at an explicit byte offset.
        ///
        /// - Parameter byte: The zero-based byte offset at which transfer should begin.
        case offset(byte: UInt64)

        var offsetValue: UInt64 {
            switch self {
            case .beginning:
                0
            case let .offset(byte):
                byte
            }
        }
    }

    /// Reports progress for a local file transfer.
    ///
    /// The closure is called after each block is transferred between local storage and the SMB share and once more when
    /// the transfer completes successfully. The completion call reports a latest speed of `0`. Return `true` to
    /// continue, or `false` to cancel the operation. Cancellation is treated as a successful early return and does not
    /// throw.
    ///
    /// - Parameters:
    ///   - bytesTransferred: The cumulative number of bytes transferred since the operation began, excluding any resume
    /// offset.
    ///   - totalBytes: The total number of bytes expected to be transferred, excluding any resume offset.
    ///   - latestSpeed: The transfer rate for the most recent block, in bytes per second, or `0` for the completion
    /// call.
    ///   - averageSpeed: The average transfer rate since the operation began, in bytes per second.
    /// - Returns: `true` to continue the transfer, or `false` to cancel it.
    typealias FileProgress = @Sendable (UInt64, UInt64, Double, Double) -> Bool

    /// Downloads a file from the SMB share to a local URL.
    ///
    /// The download is written to a temporary file first. When the transfer completes successfully, the temporary file
    /// replaces `local` atomically where the platform supports it, or is moved into place when no destination exists.
    /// If the transfer fails or is cancelled, the temporary file is removed and any existing file at `local` is left
    /// untouched. Local disk writes happen on a background queue so they overlap the network reads.
    ///
    /// To resume a partial download, pass an offset with ``FromArgument/offset(byte:)``. The existing local file must
    /// contain at least that many bytes; those bytes are copied into the temporary file before new data is appended.
    ///
    /// If `continuation` returns `false`, the method cancels the download and returns normally.
    ///
    /// - Parameters:
    ///   - remote: The share-relative source file path.
    ///   - local: The destination file URL on local storage.
    ///   - from: The byte offset at which downloading should begin.
    ///   - options: Options used when opening the remote source file.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values larger than the server's maximum read size
    /// are clamped.
    ///   - continuation: A progress closure called after each block is read from the share and once after the completed
    /// download is moved into place.
    /// - Throws: ``SMB/Error`` if the connection is closed, the remote file cannot be inspected or read, the resume
    /// offset is invalid, or a local file operation fails.
    func downloadFile(
        remote: String,
        local: URL,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64? = nil,
        continuation: @escaping FileProgress
    ) throws {
        let remote = try SMB.validatePath(remote, operation: .smbConnectionDownloadFile)
        let offset = from.offsetValue
        let operation = SMB.Error.InvalidArgumentOperation.smbConnectionDownloadFile

        let remoteStat = try validateRemoteFile(
            on: self,
            at: remote,
            minimumSize: offset,
            operation: operation
        )
        let totalBytes = remoteStat.size - offset
        let blockSize = try transferBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())

        try assertValidLocalDestination(local, operation: operation)
        let tempFile = try createUniqueLocalTempFile(near: local, operation: operation)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        if offset > 0 {
            try copyLocalPrefix(from: local, to: tempFile, byteCount: offset, operation: operation)
        }

        let writer = try BackgroundFileWriter(appendingTo: tempFile)
        defer { try? writer.finish() }

        let result = try transferRemoteFileToWriter(
            on: self,
            remote: remote,
            writer: writer,
            startingOffset: offset,
            blockSize: blockSize,
            totalBytes: totalBytes,
            options: options,
            continuation: continuation
        )

        try writer.finish()
        guard !result.cancelled else { return }
        try moveTempFile(tempFile, to: local)
        _ = continuation(result.transferred, totalBytes, 0, result.averageSpeed)
    }

    /// Uploads a local file to the SMB share.
    ///
    /// When `atomic` is `true`, the upload is written to a temporary path in the destination directory and renamed to
    /// `remote` only after the transfer completes successfully. If the transfer fails or is cancelled, the temporary
    /// remote file is removed. When `atomic` is `false`, bytes are written directly to `remote` using `options`;
    /// cancellation or failure may leave a partially written remote file. Local disk reads happen on a background queue
    /// one block ahead, so they overlap the network writes.
    ///
    /// To resume a partial upload, pass an offset with ``FromArgument/offset(byte:)``. For atomic resumed uploads, the
    /// existing remote file must contain at least that many bytes; that prefix is copied into the temporary remote file
    /// before the remaining local bytes are uploaded.
    ///
    /// If `continuation` returns `false`, the method cancels the upload and returns normally.
    ///
    /// - Parameters:
    ///   - local: The source file URL on local storage.
    ///   - remote: The share-relative destination file path.
    ///   - from: The byte offset at which uploading should begin.
    ///   - options: Options used when opening `remote` for a non-atomic upload.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values larger than the server's maximum write size
    /// are clamped.
    ///   - makePath: A Boolean value indicating whether to create missing ancestor directories before writing the file.
    /// When `false`, the method throws if the parent directory does not exist.
    ///   - atomic: A Boolean value indicating whether to upload through a temporary remote file before renaming it into
    /// place.
    ///   - continuation: A progress closure called after each SMB write block and once after the completed upload is in
    /// place.
    /// - Throws: ``SMB/Error`` if the connection is closed, a remote operation fails, the resume offset is invalid, or
    /// a local file operation fails.
    func uploadFile(
        local: URL,
        remote: String,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        atomic: Bool = true,
        continuation: @escaping FileProgress
    ) throws {
        let remote = try SMB.validatePath(remote, operation: .smbConnectionUploadFile)
        let offset = from.offsetValue
        let operation = SMB.Error.InvalidArgumentOperation.smbConnectionUploadFile

        try validateOrCreateRemoteParent(
            on: self,
            for: remote,
            makePath: makePath,
            operation: operation
        )

        let fileSize = try localFileSize(for: local, operation: operation)
        guard offset <= fileSize else {
            throw SMB.Error.invalidArgument(
                cause: .offsetBeyondEndOfLocalFile,
                onOperation: operation
            )
        }

        let totalBytes = fileSize - offset
        let blockSize = try transferBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())

        let target: String
        let openOptions: SMB.File.OpenOptions
        if atomic {
            target = try uniqueRemoteTemporaryPath(near: remote, on: self)
            openOptions = (offset == 0) ? [.create, .exclusive] : []
            try prepareAtomicUploadTarget(
                on: self,
                remote: remote,
                target: target,
                offset: offset,
                blockSize: blockSize,
                operation: operation
            )
        }
        else {
            target = remote
            openOptions = options
        }

        var shouldRemoveRemoteTemp = atomic
        defer {
            if shouldRemoveRemoteTemp {
                try? removeFile(at: target)
            }
        }

        if offset > 0 {
            try validateRemoteFile(on: self, at: target, minimumSize: offset, operation: operation)
        }
        else {
            try validateRemoteDestinationForNewFile(on: self, at: target, options: openOptions, operation: operation)
        }

        let reader = try ReadAheadFileReader(reading: local, offset: offset, blockSize: blockSize)

        let result = try transferReaderToRemoteFile(
            on: self,
            reader: reader,
            target: target,
            openOptions: openOptions,
            startingOffset: offset,
            totalBytes: totalBytes,
            continuation: continuation
        )

        guard !result.cancelled else { return }

        if atomic {
            try commitAtomicUpload(from: target, to: remote, on: self, operation: operation)
            shouldRemoveRemoteTemp = false
            try changeAttributes(at: remote) { $0.subtracting(.temporary) }
        }

        _ = continuation(result.transferred, totalBytes, 0, result.averageSpeed)
    }
}

// MARK: - Transfer Engine

private struct TransferResult {
    let transferred: UInt64
    let cancelled: Bool
    let averageSpeed: Double
}

/// Tracks cumulative bytes transferred and reports progress through a `FileProgress` continuation.
private struct ProgressTracker {
    private(set) var transferred: UInt64
    private let totalBytes: UInt64
    private let operationStart = DispatchTime.now()

    init(totalBytes: UInt64) {
        transferred = 0
        self.totalBytes = totalBytes
    }

    /// The average transfer rate since the operation began, in bytes per second.
    var averageSpeed: Double {
        speed(bytes: transferred, from: operationStart, to: .now())
    }

    /// Records a transferred block and reports progress.
    ///
    /// - Returns: `false` if `continuation` requested cancellation.
    mutating func record(
        bytes: UInt64,
        blockStart: DispatchTime,
        continuation: SMB.Connection.FileProgress
    ) -> Bool {
        transferred += bytes
        let latestSpeed = speed(bytes: bytes, from: blockStart, to: .now())
        return continuation(transferred, totalBytes, latestSpeed, averageSpeed)
    }

    /// Builds a `TransferResult` reflecting the bytes transferred so far.
    func result(cancelled: Bool) -> TransferResult {
        TransferResult(transferred: transferred, cancelled: cancelled, averageSpeed: averageSpeed)
    }
}

/// Reads the remote file in server-sized blocks and hands each block to the background writer, so the disk write of one
/// block overlaps the network read of the next. Reports progress after each block.
private func transferRemoteFileToWriter(
    on connection: SMB.Connection,
    remote: String,
    writer: BackgroundFileWriter,
    startingOffset: UInt64,
    blockSize: Int,
    totalBytes: UInt64,
    options: SMB.File.OpenOptions,
    continuation: SMB.Connection.FileProgress
) throws -> TransferResult {
    let file = try connection.openFile(at: remote, accessMode: .readOnly, options: options)
    defer { try? file.close() }

    var remoteOffset = startingOffset
    var tracker = ProgressTracker(totalBytes: totalBytes)

    while true {
        let blockStart = DispatchTime.now()
        _ = try file.seek(offset: Int64(remoteOffset), from: .start)
        let data = try file.read(upTo: Int64(blockSize))
        guard !data.isEmpty else {
            return tracker.result(cancelled: false)
        }

        try writer.append(data)
        remoteOffset += UInt64(data.count)

        guard tracker.record(bytes: UInt64(data.count), blockStart: blockStart, continuation: continuation) else {
            return tracker.result(cancelled: true)
        }
    }
}

/// Writes blocks produced by the read-ahead reader to the remote file, so the disk read of one block overlaps the
/// network write of the previous one. Each block may be split into multiple SMB writes when the server accepts only a
/// prefix. Reports progress after each SMB write.
private func transferReaderToRemoteFile(
    on connection: SMB.Connection,
    reader: ReadAheadFileReader,
    target: String,
    openOptions: SMB.File.OpenOptions,
    startingOffset: UInt64,
    totalBytes: UInt64,
    continuation: SMB.Connection.FileProgress
) throws -> TransferResult {
    let file = try connection.openFile(at: target, accessMode: .writeOnly, options: openOptions)
    defer { try? file.close() }

    var remoteOffset = startingOffset
    var tracker = ProgressTracker(totalBytes: totalBytes)

    while true {
        let data = try reader.next()
        guard !data.isEmpty else {
            return tracker.result(cancelled: false)
        }

        var cancelled = false
        try writeEntireData(data, to: file, atOffset: remoteOffset) { written, blockStart in
            remoteOffset += UInt64(written)
            if !tracker.record(bytes: UInt64(written), blockStart: blockStart, continuation: continuation) {
                cancelled = true
            }
        }
        if cancelled {
            return tracker.result(cancelled: true)
        }
    }
}

// MARK: - Local Disk Workers

/// Appends downloaded blocks to a local file on a dedicated serial queue so disk writes overlap network reads.
///
/// ``append(_:)`` waits for the previously queued block to reach disk before queuing the next one, bounding the
/// buffered data to two blocks.
private final class BackgroundFileWriter: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.SMB.Connection.downloadFile.disk")
    private let handle: FileHandle
    /// The first error raised by a queued write. Guarded by `queue`.
    private var pendingError: Swift.Error?
    /// Whether the handle has been closed. Guarded by `queue`.
    private var isFinished = false

    init(appendingTo url: URL) throws {
        handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
    }

    deinit {
        try? finish()
    }

    /// Queues a block for writing, blocking until the previously queued block is on disk. Throws when an earlier queued
    /// write failed.
    func append(_ data: Data) throws {
        try queue.sync {
            if let error = pendingError {
                throw error
            }
        }
        queue.async {
            do {
                try self.handle.write(contentsOf: data)
            }
            catch {
                self.pendingError = self.pendingError ?? error
            }
        }
    }

    /// Waits for queued writes to complete and closes the file, throwing when any of them failed. Safe to call more
    /// than once.
    func finish() throws {
        try queue.sync {
            guard !isFinished else { return }
            isFinished = true
            do {
                try handle.close()
            }
            catch {
                pendingError = pendingError ?? error
            }
            if let error = pendingError {
                throw error
            }
        }
    }
}

/// Reads upload blocks from a local file on a dedicated serial queue, one block ahead of the consumer, so disk reads
/// overlap network writes.
private final class ReadAheadFileReader: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.SMB.Connection.uploadFile.disk")
    private let handle: FileHandle
    private let blockSize: Int
    /// The result of the most recent read-ahead. Guarded by `queue`.
    private var buffered: Result<Data, Swift.Error> = .success(Data())

    init(reading url: URL, offset: UInt64, blockSize: Int) throws {
        handle = try FileHandle(forReadingFrom: url)
        try handle.seek(toOffset: offset)
        self.blockSize = blockSize
        scheduleRead()
    }

    /// Returns the next block, scheduling the read of the following block before returning. An empty block signals
    /// end-of-file. Throws when the read-ahead failed.
    func next() throws -> Data {
        let data = try queue.sync { buffered }.get()
        if !data.isEmpty {
            scheduleRead()
        }
        return data
    }

    private func scheduleRead() {
        queue.async {
            self.buffered = Result { try self.handle.read(upToCount: self.blockSize) ?? Data() }
        }
    }
}

// MARK: - Validation & Preparation

/// Checks that a remote path is usable for creating or truncating a file.
private func validateRemoteDestinationForNewFile(
    on connection: SMB.Connection,
    at path: String,
    options: SMB.File.OpenOptions,
    operation: SMB.Error.InvalidArgumentOperation
) throws {
    switch try connection.itemExists(at: path) {
    case .false:
        guard options.contains(.create) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.ENOENT.rawValue,
                operation: operation.description,
                message: "Remote file does not exist"
            )
        }
    case .file, .link:
        guard !options.contains(.exclusive) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EEXIST.rawValue,
                operation: operation.description,
                message: "Remote file already exists"
            )
        }
    case .directory, .other:
        throw SMB.Error.invalidArgument(
            cause: .remoteDestinationIsNotAFile,
            onOperation: operation
        )
    }
}

/// Ensures the local destination URL is inside an existing directory and is not itself a directory.
private func assertValidLocalDestination(_ url: URL, operation: SMB.Error.InvalidArgumentOperation) throws {
    let parent = url.deletingLastPathComponent()
    var isDirectory = ObjCBool(false)

    guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &isDirectory) else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOENT.rawValue,
            operation: operation.description,
            message: "Local parent directory does not exist"
        )
    }
    guard isDirectory.boolValue else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOTDIR.rawValue,
            operation: operation.description,
            message: "Local parent path is not a directory"
        )
    }

    if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EISDIR.rawValue,
            operation: operation.description,
            message: "Local destination is a directory"
        )
    }
}

/// Creates a uniquely-named temporary file in the same directory as `near`.
private func createUniqueLocalTempFile(near: URL, operation: SMB.Error.InvalidArgumentOperation) throws -> URL {
    let directory = near.deletingLastPathComponent()
    for _ in 0 ..< 100 {
        let candidate = directory.appendingPathComponent("SwiftSMB.\(UUID().uuidString).tmp")
        if FileManager.default.createFile(atPath: candidate.path, contents: nil) {
            return candidate
        }
    }
    throw SMB.Error.unknown(
        operation: "SMB.Connection.uniqueTemporaryFileURL",
        message: "Unable to create a unique temporary file"
    )
}

/// Copies the first `byteCount` bytes from `source` into `destination`.
private func copyLocalPrefix(
    from source: URL,
    to destination: URL,
    byteCount: UInt64,
    operation: SMB.Error.InvalidArgumentOperation
) throws {
    let existingSize = try localFileSize(for: source, operation: operation)
    guard existingSize >= byteCount else {
        throw SMB.Error.invalidArgument(
            cause: .localFileShorterThanResumeOffset,
            onOperation: operation
        )
    }

    let input = try FileHandle(forReadingFrom: source)
    defer { try? input.close() }
    let output = try FileHandle(forWritingTo: destination)
    defer { try? output.close() }

    var remaining = byteCount
    while remaining > 0 {
        let chunkSize = min(Int(remaining), 1024 * 1024)
        guard let data = try input.read(upToCount: chunkSize), !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                cause: .localFileShorterThanResumeOffset,
                onOperation: operation
            )
        }
        try output.write(contentsOf: data)
        remaining -= UInt64(data.count)
    }
}

/// Seeds the temporary remote file for an atomic resumed upload by copying the trusted remote prefix.
private func prepareAtomicUploadTarget(
    on connection: SMB.Connection,
    remote: String,
    target: String,
    offset: UInt64,
    blockSize: Int,
    operation: SMB.Error.InvalidArgumentOperation
) throws {
    guard offset > 0 else {
        switch try connection.itemExists(at: remote) {
        case .false, .file, .link:
            return
        case .directory, .other:
            throw SMB.Error.invalidArgument(
                cause: .remoteDestinationIsNotAFile,
                onOperation: operation
            )
        }
    }

    _ = try validateRemoteFile(
        on: connection,
        at: remote,
        minimumSize: offset,
        operation: operation
    )

    let input = try connection.openFile(at: remote, accessMode: .readOnly)
    defer { try? input.close() }
    let output = try connection.openFile(at: target, accessMode: .writeOnly, options: [.create, .exclusive])
    defer { try? output.close() }

    try connection.changeAttributes(at: target) { $0.union(.temporary) }

    var copied: UInt64 = 0
    while copied < offset {
        let requested = min(UInt64(blockSize), offset - copied)
        _ = try input.seek(offset: Int64(copied), from: .start)
        let data = try input.read(upTo: Int64(requested))
        guard !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                cause: .remoteFileShorterThanResumeOffset,
                onOperation: operation
            )
        }
        try writeEntireData(data, to: output, atOffset: copied)
        copied += UInt64(data.count)
    }
}

/// Writes a complete data buffer to a remote file, retrying internally if the server accepts only a prefix.
///
/// - Parameter onBlockWritten: Called after each SMB write with the number of bytes written and the time the write
/// started.
private func writeEntireData(
    _ data: Data,
    to file: SMB.File,
    atOffset baseOffset: UInt64,
    onBlockWritten: (UInt64, DispatchTime) -> Void = { _, _ in }
) throws {
    var dataOffset = 0
    var fileOffset = baseOffset
    while dataOffset < data.count {
        let blockStart = DispatchTime.now()
        _ = try file.seek(offset: Int64(fileOffset), from: .start)
        let written = try file.write(data.subdata(in: dataOffset ..< data.count))
        guard written > 0 else {
            throw SMB.Error.unknown(
                operation: "smb2_write",
                message: "Write made no progress before all data was written"
            )
        }
        dataOffset += Int(written)
        fileOffset += UInt64(written)
        onBlockWritten(UInt64(written), blockStart)
    }
}

// MARK: - Atomic Commit

/// Renames the temporary upload file into place, preserving the old destination via a backup path when necessary.
private func commitAtomicUpload(
    from target: String,
    to remote: String,
    on connection: SMB.Connection,
    operation: SMB.Error.InvalidArgumentOperation
) throws {
    let backup: String?
    switch try connection.itemExists(at: remote) {
    case .false:
        backup = nil
    case .file, .link:
        let backupPath = try uniqueRemoteTemporaryPath(near: remote, on: connection)
        try connection.move(from: remote, to: backupPath)
        backup = backupPath
    case .directory, .other:
        throw SMB.Error.invalidArgument(
            cause: .remoteDestinationIsNotAFile,
            onOperation: operation
        )
    }

    do {
        try connection.move(from: target, to: remote)
    }
    catch {
        if let backup {
            try? connection.move(from: backup, to: remote)
        }
        throw error
    }

    if let backup {
        try? connection.removeFile(at: backup)
    }
}

// MARK: - Block Size & Speed

/// Resolves a caller-preferred block size against the server limit.
private func transferBlockSize(_ preferred: UInt64?, acceptedBlockSize: Int) throws -> Int {
    guard let preferred else {
        return acceptedBlockSize
    }
    guard preferred > 0, preferred <= UInt64(Int.max) else {
        throw SMB.Error.invalidArgument(
            cause: .blockSizeMustBePositiveAndFitInInt,
            onOperation: .smbConnectionTransferBlockSize
        )
    }
    return min(Int(preferred), acceptedBlockSize)
}

/// Calculates bytes per second for an elapsed interval.
private func speed(bytes: UInt64, from start: DispatchTime, to end: DispatchTime) -> Double {
    let elapsed = Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000
    guard elapsed > 0 else { return 0 }
    return Double(bytes) / elapsed
}

// MARK: - Remote Validation

/// Validates that a remote path exists, is a regular file, and is large enough for a resume offset.
@discardableResult
private func validateRemoteFile(
    on connection: SMB.Connection,
    at path: String,
    minimumSize: UInt64,
    operation: SMB.Error.InvalidArgumentOperation
) throws -> SMB.Stat {
    let stat = try connection.stat(at: path)
    guard stat.type == .file else {
        throw SMB.Error.invalidArgument(cause: .remotePathIsNotAFile, onOperation: operation)
    }
    guard stat.size >= minimumSize else {
        throw SMB.Error.invalidArgument(
            cause: .remoteFileShorterThanResumeOffset,
            onOperation: operation
        )
    }
    return stat
}

/// Validates or creates the parent directory for a remote destination path.
private func validateOrCreateRemoteParent(
    on connection: SMB.Connection,
    for path: String,
    makePath: Bool,
    operation: SMB.Error.InvalidArgumentOperation
) throws {
    let parent = path.removingLastPathComponent
    guard !parent.isEmpty else { return }

    let existence = try connection.itemExists(at: parent)
    switch existence {
    case .directory:
        return
    case .false:
        guard makePath else {
            throw SMB.Error.invalidArgument(
                cause: .remoteParentDirectoryDoesNotExist,
                onOperation: operation
            )
        }
        try connection.makeDirectory(at: parent, makePath: true)
    case .file, .link, .other:
        throw SMB.Error.invalidArgument(
            cause: .remoteParentPathIsNotADirectory,
            onOperation: operation
        )
    }
}

// MARK: - Local File Helpers

/// Returns the size of a local regular file.
private func localFileSize(for url: URL, operation: SMB.Error.InvalidArgumentOperation) throws -> UInt64 {
    let operationString = operation.description
    var isDirectory = ObjCBool(false)
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOENT.rawValue,
            operation: operationString,
            message: "Local file does not exist"
        )
    }
    guard !isDirectory.boolValue else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EISDIR.rawValue,
            operation: operationString,
            message: "Local path is a directory"
        )
    }

    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    if let size = attributes[.size] as? NSNumber {
        return size.uint64Value
    }
    if let size = attributes[.size] as? UInt64 {
        return size
    }
    if let size = attributes[.size] as? Int, size >= 0 {
        return UInt64(size)
    }

    throw SMB.Error.invalidArgument(cause: .unableToDetermineLocalFileSize, onOperation: operation)
}

/// Builds a temporary remote path that does not currently exist.
private func uniqueRemoteTemporaryPath(near remote: String, on connection: SMB.Connection) throws -> String {
    for _ in 0 ..< 100 {
        let name = "partial-xfer.\(UUID().uuidString).tmp"
        let directory = remote.removingLastPathComponent
        let candidate = directory.isEmpty ? name : directory.appendingPathComponent(name)
        if try connection.itemExists(at: candidate) == .false {
            return candidate
        }
    }

    throw SMB.Error.unknown(
        operation: "SMB.Connection.uniqueRemoteTemporaryPath",
        message: "Unable to create a unique temporary remote path"
    )
}

/// Moves a completed temporary file into its final destination.
private func moveTempFile(_ temp: URL, to destination: URL) throws {
    if FileManager.default.fileExists(atPath: destination.path) {
        _ = try FileManager.default.replaceItemAt(destination, withItemAt: temp)
    }
    else {
        try FileManager.default.moveItem(at: temp, to: destination)
    }
}
