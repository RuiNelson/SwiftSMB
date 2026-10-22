//
// Part of SwiftSMB
// Connection-Conv-Transfer.swift
//
// Licensed under Apache License v2.0
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
    /// throw. To await inside the closure, use ``AsyncFileProgress`` instead.
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

    /// Reports progress for a local file transfer from a closure that can suspend.
    ///
    /// The closure is called at the same points and with the same arguments as ``FileProgress``. The transfer waits for
    /// the closure to return before it continues, so work awaited inside the closure delays the next block. Return
    /// `true` to continue, or `false` to cancel the operation. Cancellation is treated as a successful early return and
    /// does not throw.
    ///
    /// Swift selects the transfer methods that take this type when the progress closure uses `await`, and the ones that
    /// take ``FileProgress`` otherwise.
    ///
    /// - Parameters:
    ///   - bytesTransferred: The cumulative number of bytes transferred since the operation began, excluding any resume
    /// offset.
    ///   - totalBytes: The total number of bytes expected to be transferred, excluding any resume offset.
    ///   - latestSpeed: The transfer rate for the most recent block, in bytes per second, or `0` for the completion
    /// call.
    ///   - averageSpeed: The average transfer rate since the operation began, in bytes per second.
    /// - Returns: `true` to continue the transfer, or `false` to cancel it.
    typealias AsyncFileProgress = @Sendable (UInt64, UInt64, Double, Double) async -> Bool

    /// Downloads a file from the SMB share to a local URL.
    ///
    /// When `atomic` is `true` (the default), the download is written to a temporary file first. When the transfer
    /// completes successfully, the temporary file replaces `local` atomically where the platform supports it, or is
    /// moved into place when no destination exists. If the transfer fails or is cancelled, the temporary file is
    /// removed and any existing file at `local` is left untouched. When `atomic` is `false`, bytes are written directly
    /// to
    /// `local`; cancellation or failure leaves the partially written file at `local` in place. Local disk writes happen
    /// on a background queue so they overlap the network reads.
    ///
    /// To resume a partial download, pass an offset with ``FromArgument/offset(byte:)``. The existing local file must
    /// contain at least that many bytes. For atomic downloads, those bytes are copied into the temporary file before
    /// new data is appended. For non-atomic downloads, `local` is truncated to the resume offset and new data is
    /// appended directly.
    ///
    /// If `continuation` returns `false`, the method cancels the download and returns normally. If the task is
    /// cancelled, the download stops between blocks and throws `CancellationError`; cleanup is the same as for a
    /// failure.
    ///
    /// The transfer reads the size reported when it begins. Data appended later is excluded; if the source becomes
    /// shorter before those bytes have been read, the transfer fails instead of committing a partial download.
    ///
    /// - Parameters:
    ///   - remote: The share-relative source file path.
    ///   - local: The destination file URL on local storage.
    ///   - from: The byte offset at which downloading should begin.
    ///   - options: Options used when opening the remote source file.
    ///   - maxBlockSize: The preferred maximum transfer block size, overriding the configured/default block size.
    /// Values larger than the server's maximum read size are clamped.
    ///   - atomic: A Boolean value indicating whether to download through a temporary local file before moving it into
    /// place. When `false`, bytes are written directly to `local` and are not removed if the transfer fails or is
    /// cancelled.
    ///   - continuation: A progress closure called after each block is read from the share and once after the completed
    /// download is moved into place. The download waits for it to return before reading the next block.
    /// - Throws: ``SMB/Error`` if the connection is closed, the remote file cannot be inspected or read, the resume
    /// offset is invalid, or a local file operation fails.
    func downloadFile(
        remote: String,
        local: URL,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64? = nil,
        atomic: Bool = true,
        continuation: @escaping AsyncFileProgress
    ) async throws {
        try await self.withOperation {
            let remote = try SMB.validatePath(remote, operation: .smbConnectionDownloadFile)
            try Task.checkCancellation()
            let offset = from.offsetValue
            let operation = SMB.Error.InvalidArgumentOperation.smbConnectionDownloadFile
            let disk = LocalDiskWorker()

            let remoteStat = try await validateRemoteFile(
                on: self,
                at: remote,
                minimumSize: offset,
                operation: operation
            )
            let totalBytes = remoteStat.size - offset
            let preferredBlockSize = try transferBlockSize(maxBlockSize)
            let blockSize = try await acceptedReadBlockSize(preferredBlockSize)

            try await disk.perform { try assertValidLocalDestination(local, operation: operation) }

            let tempFile = atomic ? try await disk.perform {
                try createUniqueLocalTempFile(near: local, operation: operation)
            } : nil
            // Registered before anything else can fail, so the temporary file never outlives a failed download.
            defer {
                if let tempFile {
                    try? await disk.perform { try FileManager.default.removeItem(at: tempFile) }
                }
            }

            if let tempFile, offset > 0 {
                try await copyLocalPrefix(
                    from: local,
                    to: tempFile,
                    byteCount: offset,
                    operation: operation,
                    disk: disk
                )
            }
            let writer = try await disk.perform {
                if let tempFile {
                    return try BackgroundFileWriter(appendingTo: tempFile)
                }
                return try BackgroundFileWriter(writingDirectlyTo: local, offset: offset, operation: operation)
            }
            defer { try? await writer.finish() }

            let result = try await transferRemoteFileToWriter(
                on: self,
                remote: remote,
                writer: writer,
                startingOffset: offset,
                blockSize: blockSize,
                totalBytes: totalBytes,
                options: options,
                operation: operation,
                continuation: continuation
            )

            try await writer.finish()
            guard !result.cancelled else { return }
            try Task.checkCancellation()
            if let tempFile {
                try await disk.perform { try moveTempFile(tempFile, to: local) }
            }
            _ = await continuation(result.transferred, totalBytes, 0, result.averageSpeed)
        }
    }

    /// Downloads a file from the SMB share to a local URL, reporting progress through a synchronous closure.
    ///
    /// This method behaves exactly like the overload that takes an ``AsyncFileProgress``. Swift selects it when the
    /// progress closure doesn't use `await`.
    ///
    /// - Parameters:
    ///   - remote: The share-relative source file path.
    ///   - local: The destination file URL on local storage.
    ///   - from: The byte offset at which downloading should begin.
    ///   - options: Options used when opening the remote source file.
    ///   - maxBlockSize: The preferred maximum transfer block size, overriding the configured/default block size.
    /// Values larger than the server's maximum read size are clamped.
    ///   - atomic: A Boolean value indicating whether to download through a temporary local file before moving it into
    /// place. When `false`, bytes are written directly to `local` and are not removed if the transfer fails or is
    /// cancelled.
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
        atomic: Bool = true,
        continuation: @escaping FileProgress
    ) async throws {
        // Passing `continuation` directly would select this overload again.
        let progress: AsyncFileProgress = continuation
        try await downloadFile(
            remote: remote,
            local: local,
            from: from,
            options: options,
            maxBlockSize: maxBlockSize,
            atomic: atomic,
            continuation: progress
        )
    }

    /// Uploads a local file to the SMB share.
    ///
    /// When `atomic` is `true`, the upload is written to a temporary path in the destination directory and renamed to
    /// `remote` only after the transfer completes successfully. If the transfer fails or is cancelled, the temporary
    /// remote file is removed. When `atomic` is `false`, bytes are written directly to `remote` using `options`;
    /// cancellation or failure may leave a partially written remote file. Local disk reads happen on a background queue
    /// one block ahead, so they overlap the network writes.
    ///
    /// To resume a partial upload, pass an offset with ``FromArgument/offset(byte:)``. The existing remote file must
    /// contain at least that many bytes. For atomic resumed uploads, that prefix is copied into the temporary remote
    /// file before the remaining local bytes are uploaded. Resumed uploads never truncate `remote`, so
    /// ``SMB/File/OpenOptions/truncate`` is ignored when the offset is not zero.
    ///
    /// If `continuation` returns `false`, the method cancels the upload and returns normally. If the task is cancelled,
    /// the upload stops between blocks and throws `CancellationError`; cleanup is the same as for a failure.
    ///
    /// The transfer reads the local file's size when it begins, following symbolic links to their target. Data appended
    /// later is excluded; if the source becomes shorter before those bytes have been read, the transfer fails instead
    /// of committing a partial atomic upload.
    ///
    /// - Parameters:
    ///   - local: The source file URL on local storage.
    ///   - remote: The share-relative destination file path.
    ///   - from: The byte offset at which uploading should begin.
    ///   - options: Options used when opening `remote` for a non-atomic upload. The default creates the file if needed
    /// and truncates any existing content, so `remote` ends up identical to `local`.
    ///   - maxBlockSize: The preferred maximum transfer block size, overriding the configured/default block size.
    /// Values larger than the server's maximum write size are clamped.
    ///   - makePath: A Boolean value indicating whether to create missing ancestor directories before writing the file.
    /// When `false`, the method throws if the parent directory does not exist.
    ///   - atomic: A Boolean value indicating whether to upload through a temporary remote file before renaming it into
    /// place.
    ///   - continuation: A progress closure called after each SMB write block and once after the completed upload is in
    /// place. The upload waits for it to return before writing the next block.
    /// - Throws: ``SMB/Error`` if the connection is closed, a remote operation fails, the resume offset is invalid, or
    /// a local file operation fails.
    func uploadFile(
        local: URL,
        remote: String,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [.create, .truncate],
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        atomic: Bool = true,
        continuation: @escaping AsyncFileProgress
    ) async throws {
        try await self.withOperation {
            let remote = try SMB.validatePath(remote, operation: .smbConnectionUploadFile)
            try Task.checkCancellation()
            let offset = from.offsetValue
            let operation = SMB.Error.InvalidArgumentOperation.smbConnectionUploadFile
            let disk = LocalDiskWorker()
            let fileSize = try await disk.perform { try localFileSize(for: local, operation: operation) }
            guard offset <= fileSize else {
                throw SMB.Error.invalidArgument(
                    cause: .offsetBeyondEndOfLocalFile,
                    onOperation: operation
                )
            }

            let preferredBlockSize = try transferBlockSize(maxBlockSize)
            let blockSize = try await acceptedWriteBlockSize(preferredBlockSize)

            try await uploadBlocks(
                on: self,
                to: remote,
                totalBytes: fileSize - offset,
                offset: offset,
                options: options,
                blockSize: blockSize,
                makePath: makePath,
                atomic: atomic,
                operation: operation,
                continuation: continuation
            ) {
                try await disk.perform {
                    try ReadAheadFileReader(reading: local, offset: offset, blockSize: blockSize)
                }
            }
        }
    }

    /// Uploads a local file to the SMB share, reporting progress through a synchronous closure.
    ///
    /// This method behaves exactly like the overload that takes an ``AsyncFileProgress``. Swift selects it when the
    /// progress closure doesn't use `await`.
    ///
    /// - Parameters:
    ///   - local: The source file URL on local storage.
    ///   - remote: The share-relative destination file path.
    ///   - from: The byte offset at which uploading should begin.
    ///   - options: Options used when opening `remote` for a non-atomic upload. The default creates the file if needed
    /// and truncates any existing content, so `remote` ends up identical to `local`.
    ///   - maxBlockSize: The preferred maximum transfer block size, overriding the configured/default block size.
    /// Values larger than the server's maximum write size are clamped.
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
        options: SMB.File.OpenOptions = [.create, .truncate],
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        atomic: Bool = true,
        continuation: @escaping FileProgress
    ) async throws {
        // Passing `continuation` directly would select this overload again.
        let progress: AsyncFileProgress = continuation
        try await uploadFile(
            local: local,
            remote: remote,
            from: from,
            options: options,
            maxBlockSize: maxBlockSize,
            makePath: makePath,
            atomic: atomic,
            continuation: progress
        )
    }
}

// MARK: - Stream Transfers

public extension SMB.Connection {
    /// Uploads the contents of an input stream to a file on the SMB share.
    ///
    /// The upload reads `stream` from its current position until the end of the stream, or until it has read `length`
    /// bytes when you pass a length, and never reads past that point. If `stream` isn't open yet, the method opens it.
    /// The method never closes the stream, so you can keep reading from it afterwards; close it when you're done. Don't
    /// use the stream elsewhere while the upload is in progress. Stream reads happen on a background queue one block
    /// ahead, so they overlap the network writes.
    ///
    /// When `atomic` is `true` (the default), the upload is written to a temporary path in the destination directory
    /// and renamed to `remote` only after the transfer completes successfully. If the transfer fails or is cancelled,
    /// the temporary remote file is removed. When `atomic` is `false`, bytes are written directly to `remote` using
    /// `options`; cancellation or failure may leave a partially written remote file.
    ///
    /// To resume a partial upload, pass an offset with ``FromArgument/offset(byte:)``. The offset applies only to
    /// `remote`, which must already contain at least that many bytes. Those bytes are kept, and `stream` supplies the
    /// bytes that follow them, starting at its current position. For atomic resumed uploads, the remote prefix is
    /// copied into the temporary remote file first. Resumed uploads never truncate `remote`, so
    /// ``SMB/File/OpenOptions/truncate`` is ignored when the offset is not zero.
    ///
    /// Without a `length`, the size of the upload isn't known in advance, so `continuation` receives the number of
    /// bytes transferred so far as the total. With a `length`, a stream that ends before supplying that many bytes
    /// fails the upload instead of committing a partial file.
    ///
    /// If `continuation` returns `false`, the method cancels the upload and returns normally. If the task is cancelled,
    /// the upload stops between blocks and throws `CancellationError`; cleanup is the same as for a failure. After a
    /// cancelled or failed upload, the stream may have been read past the last byte that reached the share.
    ///
    /// - Parameters:
    ///   - remote: The share-relative destination file path.
    ///   - stream: The stream that supplies the bytes to upload.
    ///   - length: The number of bytes to read from `stream`, or `nil` to read until the end of the stream.
    ///   - from: The byte offset in `remote` at which uploading should begin.
    ///   - options: Options used when opening `remote` for a non-atomic upload. The default creates the file if needed
    /// and truncates any existing content, so `remote` ends up containing exactly the uploaded bytes.
    ///   - maxBlockSize: The preferred maximum transfer block size, overriding the configured/default block size.
    /// Values larger than the server's maximum write size are clamped.
    ///   - makePath: A Boolean value indicating whether to create missing ancestor directories before writing the file.
    /// When `false`, the method throws if the parent directory does not exist.
    ///   - atomic: A Boolean value indicating whether to upload through a temporary remote file before renaming it into
    /// place.
    ///   - continuation: A progress closure called after each SMB write block and once after the completed upload is in
    /// place. The upload waits for it to return before writing the next block.
    /// - Throws: ``SMB/Error`` if the connection is closed, a remote operation fails, the resume offset is invalid, the
    /// stream is closed, or the stream ends before supplying `length` bytes; or the error that `stream` reports when
    /// reading from it fails.
    nonisolated(nonsending) func streamToRemote(
        remote: String,
        stream: InputStream,
        length: UInt64? = nil,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [.create, .truncate],
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        atomic: Bool = true,
        continuation: @escaping AsyncFileProgress
    ) async throws {
        try await self.withOperation {
            let operation = SMB.Error.InvalidArgumentOperation.smbConnectionStreamToRemote
            let remote = try SMB.validatePath(remote, operation: operation)
            try Task.checkCancellation()
            let preferredBlockSize = try transferBlockSize(maxBlockSize)
            let blockSize = try await acceptedWriteBlockSize(preferredBlockSize)

            let reader = ReadAheadStreamReader(
                reading: stream,
                limit: length,
                blockSize: blockSize,
                operation: operation
            )
            try await reader.open()
            // The stream belongs to the caller, so no read-ahead may outlive the upload.
            defer { await reader.finish() }

            try await uploadBlocks(
                on: self,
                to: remote,
                totalBytes: length,
                offset: from.offsetValue,
                options: options,
                blockSize: blockSize,
                makePath: makePath,
                atomic: atomic,
                operation: operation,
                continuation: continuation
            ) { reader }
        }
    }

    /// Downloads a file from the SMB share into an output stream.
    ///
    /// The download writes the bytes of `remote`, starting at `from`, to `stream`. If `stream` isn't open yet, the
    /// method opens it. The method never closes the stream, so afterwards you can keep writing to it, or read the data
    /// written to a memory stream; close it when you're done. Don't use the stream elsewhere while the download is in
    /// progress. Stream writes happen on a background queue so they overlap the network reads.
    ///
    /// Bytes reach `stream` as they arrive, so a cancelled or failed download leaves the bytes written so far in the
    /// stream. If `continuation` returns `false`, the method cancels the download and returns normally. If the task is
    /// cancelled, the download stops between blocks and throws `CancellationError`.
    ///
    /// The transfer reads the size reported when it begins. Data appended later is excluded; if the source becomes
    /// shorter before those bytes have been read, the transfer fails.
    ///
    /// - Parameters:
    ///   - remote: The share-relative source file path.
    ///   - stream: The stream that receives the downloaded bytes.
    ///   - from: The byte offset in `remote` at which downloading should begin.
    ///   - options: Options used when opening the remote source file.
    ///   - maxBlockSize: The preferred maximum transfer block size, overriding the configured/default block size.
    /// Values larger than the server's maximum read size are clamped.
    ///   - continuation: A progress closure called after each block is read from the share and once after the last
    /// block has been written to `stream`. The download waits for it to return before reading the next block.
    /// - Throws: ``SMB/Error`` if the connection is closed, the remote file cannot be inspected or read, the resume
    /// offset is invalid, or the stream is closed; or the error that `stream` reports when writing to it fails.
    nonisolated(nonsending) func streamFromRemote(
        remote: String,
        stream: OutputStream,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64? = nil,
        continuation: @escaping AsyncFileProgress
    ) async throws {
        try await self.withOperation {
            let operation = SMB.Error.InvalidArgumentOperation.smbConnectionStreamFromRemote
            let remote = try SMB.validatePath(remote, operation: operation)
            try Task.checkCancellation()
            let offset = from.offsetValue

            let remoteStat = try await validateRemoteFile(
                on: self,
                at: remote,
                minimumSize: offset,
                operation: operation
            )
            let totalBytes = remoteStat.size - offset
            let preferredBlockSize = try transferBlockSize(maxBlockSize)
            let blockSize = try await acceptedReadBlockSize(preferredBlockSize)

            let writer = BackgroundStreamWriter(writingTo: stream, operation: operation)
            try await writer.open()
            // The stream belongs to the caller, so no queued write may outlive the download.
            defer { try? await writer.finish() }

            let result = try await transferRemoteFileToWriter(
                on: self,
                remote: remote,
                writer: writer,
                startingOffset: offset,
                blockSize: blockSize,
                totalBytes: totalBytes,
                options: options,
                operation: operation,
                continuation: continuation
            )

            try await writer.finish()
            guard !result.cancelled else { return }
            try Task.checkCancellation()
            _ = await continuation(result.transferred, totalBytes, 0, result.averageSpeed)
        }
    }
}

// MARK: - Upload Pipeline

/// Uploads the blocks of the reader that `makeReader` creates once the destination is prepared, staging them through a
/// temporary remote file when `atomic` is `true`. When `totalBytes` is `nil`, the upload ends at the reader's first
/// empty block and reports the bytes transferred so far as the total.
private func uploadBlocks(
    on connection: SMB.Connection,
    to remote: String,
    totalBytes: UInt64?,
    offset: UInt64,
    options: SMB.File.OpenOptions,
    blockSize: Int,
    makePath: Bool,
    atomic: Bool,
    operation: SMB.Error.InvalidArgumentOperation,
    continuation: SMB.Connection.AsyncFileProgress,
    makeReader: () async throws -> some UploadBlockReader
) async throws {
    try Task.checkCancellation()
    try await validateOrCreateRemoteParent(
        on: connection,
        for: remote,
        makePath: makePath,
        operation: operation
    )

    let target = atomic ? try await uniqueRemoteTemporaryPath(near: remote, on: connection) : remote
    let openOptions: SMB.File.OpenOptions = if atomic {
        (offset == 0) ? [.create, .exclusive] : []
    }
    else {
        // Truncating on open would discard the prefix a resumed upload continues from.
        (offset == 0) ? options : options.subtracting(.truncate)
    }

    // Cleanup owns only a temporary file successfully created by this transfer.
    var shouldRemoveRemoteTemp = false
    defer {
        if shouldRemoveRemoteTemp {
            try? await connection.removeFile(at: target)
        }
    }

    if atomic {
        try await prepareAtomicUploadTarget(
            on: connection,
            remote: remote,
            target: target,
            offset: offset,
            blockSize: blockSize,
            operation: operation,
            onTargetCreated: { shouldRemoveRemoteTemp = true }
        )
    }

    if offset > 0 {
        try await validateRemoteFile(on: connection, at: target, minimumSize: offset, operation: operation)
    }
    else {
        try await validateRemoteDestinationForNewFile(
            on: connection,
            at: target,
            options: openOptions,
            operation: operation
        )
    }

    let reader = try await makeReader()

    let result = try await transferReaderToRemoteFile(
        on: connection,
        reader: reader,
        target: target,
        openOptions: openOptions,
        startingOffset: offset,
        totalBytes: totalBytes,
        operation: operation,
        onTargetOpened: { shouldRemoveRemoteTemp = atomic },
        continuation: continuation
    )

    guard !result.cancelled else { return }
    try Task.checkCancellation()

    if atomic {
        // Finish fallible metadata changes before replacing the destination.
        try await connection.changeAttributes(at: target) { $0.subtracting(.temporary) }
        try Task.checkCancellation()
        try await commitAtomicUpload(from: target, to: remote, on: connection, operation: operation)
        shouldRemoveRemoteTemp = false
    }

    _ = await continuation(result.transferred, totalBytes ?? result.transferred, 0, result.averageSpeed)
}

// MARK: - Transfer Engine

/// Produces upload blocks, reading ahead on its own queue. An empty block marks the end of the source.
private protocol UploadBlockReader: Sendable {
    func next() async throws -> Data
}

/// Consumes downloaded blocks, writing them on its own queue.
private protocol DownloadBlockWriter: Sendable {
    func append(_ data: Data) async throws
    func finish() async throws
}

private struct TransferResult {
    let transferred: UInt64
    let cancelled: Bool
    let averageSpeed: Double
}

/// Tracks cumulative bytes transferred and reports progress through an `AsyncFileProgress` continuation.
private struct ProgressTracker {
    private(set) var transferred: UInt64
    /// The bytes the transfer expects, or `nil` when the source length is unknown.
    private let totalBytes: UInt64?
    private let operationStart = DispatchTime.now()

    init(totalBytes: UInt64?) {
        transferred = 0
        self.totalBytes = totalBytes
    }

    /// The bytes still expected, or `nil` when the source length is unknown.
    var remaining: UInt64? {
        totalBytes.map { $0 - transferred }
    }

    /// The average transfer rate since the operation began, in bytes per second.
    var averageSpeed: Double {
        speed(bytes: transferred, from: operationStart, to: .now())
    }

    /// Records a transferred block and reports progress. Without a known length, the bytes transferred so far are
    /// reported as the total.
    ///
    /// - Returns: `false` if `continuation` requested cancellation.
    mutating func record(
        bytes: UInt64,
        blockStart: DispatchTime,
        continuation: SMB.Connection.AsyncFileProgress
    ) async -> Bool {
        transferred += bytes
        let latestSpeed = speed(bytes: bytes, from: blockStart, to: .now())
        return await continuation(transferred, totalBytes ?? transferred, latestSpeed, averageSpeed)
    }

    /// Builds a `TransferResult` reflecting the bytes transferred so far.
    func result(cancelled: Bool) -> TransferResult {
        TransferResult(transferred: transferred, cancelled: cancelled, averageSpeed: averageSpeed)
    }
}

/// Reads the remote file in server-sized blocks and hands each block to the background writer, so the local write of
/// one block overlaps the network read of the next. Reports progress after each block.
private func transferRemoteFileToWriter(
    on connection: SMB.Connection,
    remote: String,
    writer: some DownloadBlockWriter,
    startingOffset: UInt64,
    blockSize: Int,
    totalBytes: UInt64,
    options: SMB.File.OpenOptions,
    operation: SMB.Error.InvalidArgumentOperation,
    continuation: SMB.Connection.AsyncFileProgress
) async throws -> TransferResult {
    let file = try await connection.openFile(at: remote, accessMode: .readOnly, options: options)
    defer { try? await file.close() }

    var remoteOffset = startingOffset
    var tracker = ProgressTracker(totalBytes: totalBytes)

    while tracker.transferred < totalBytes {
        try Task.checkCancellation()
        let blockStart = DispatchTime.now()
        _ = try await file.seek(offset: signedTransferOffset(remoteOffset), from: .start)
        let requested = min(UInt64(blockSize), totalBytes - tracker.transferred)
        let data = try await file.read(upTo: Int64(requested))
        guard !data.isEmpty else {
            throw unexpectedTransferEOF(operation: operation)
        }

        try await writer.append(data)
        remoteOffset += UInt64(data.count)

        guard await tracker.record(bytes: UInt64(data.count), blockStart: blockStart, continuation: continuation) else {
            return tracker.result(cancelled: true)
        }
    }
    try await file.close()
    return tracker.result(cancelled: false)
}

/// Writes blocks produced by the read-ahead reader to the remote file, so the local read of one block overlaps the
/// network write of the previous one. Each block may be split into multiple SMB writes when the server accepts only a
/// prefix. Reports progress after each SMB write. When `totalBytes` is `nil`, the transfer ends at the reader's first
/// empty block.
private func transferReaderToRemoteFile(
    on connection: SMB.Connection,
    reader: some UploadBlockReader,
    target: String,
    openOptions: SMB.File.OpenOptions,
    startingOffset: UInt64,
    totalBytes: UInt64?,
    operation: SMB.Error.InvalidArgumentOperation,
    onTargetOpened: () -> Void,
    continuation: SMB.Connection.AsyncFileProgress
) async throws -> TransferResult {
    let file = try await connection.openFile(at: target, accessMode: .writeOnly, options: openOptions)
    onTargetOpened()
    defer { try? await file.close() }

    var remoteOffset = startingOffset
    var tracker = ProgressTracker(totalBytes: totalBytes)

    // Without a known length, `remaining` stays `nil` and only an empty block ends the loop.
    while tracker.remaining != 0 {
        try Task.checkCancellation()
        let data = try await reader.next()
        guard !data.isEmpty else {
            guard tracker.remaining == nil else {
                throw unexpectedTransferEOF(operation: operation)
            }
            break
        }
        let remaining = tracker.remaining ?? UInt64(data.count)
        let block = data.prefix(Int(min(UInt64(data.count), remaining)))

        var cancelled = false
        try await writeEntireData(block, to: file, atOffset: remoteOffset) { written, blockStart in
            remoteOffset += UInt64(written)
            if await !tracker.record(bytes: UInt64(written), blockStart: blockStart, continuation: continuation) {
                cancelled = true
            }
        }
        if cancelled {
            return tracker.result(cancelled: true)
        }
    }
    try await file.close()
    return tracker.result(cancelled: false)
}

// MARK: - Local Disk Workers

/// Runs local file setup, metadata, commit, and cleanup off the Swift concurrency cooperative pool.
private final class LocalDiskWorker: Sendable {
    private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.SMB.Connection.transfer.setup")

    func perform<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try body() })
            }
        }
    }
}

/// Appends downloaded blocks to a local file on a dedicated serial queue so disk writes overlap network reads.
///
/// ``append(_:)`` waits for the previously queued block to reach disk before queuing the next one, bounding the
/// buffered data to two blocks. Callers suspend instead of blocking while they wait.
private final class BackgroundFileWriter: DownloadBlockWriter, @unchecked Sendable {
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

    /// Opens `url` for writing in place, creating it if it does not exist. The file is truncated to `offset` bytes,
    /// discarding any stale data beyond a previous attempt's resume point, and the handle is positioned at `offset` so
    /// new data is appended from there.
    init(writingDirectlyTo url: URL, offset: UInt64, operation: SMB.Error.InvalidArgumentOperation) throws {
        if !FileManager.default.fileExists(atPath: url.path) {
            guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
                throw SMB.Error.posix(
                    code: POSIXErrorCode.EIO.rawValue,
                    operation: operation.description,
                    message: "Unable to create local file"
                )
            }
        }

        let handle = try FileHandle(forWritingTo: url)
        let existingSize = try handle.seekToEnd()
        guard existingSize >= offset else {
            try? handle.close()
            throw SMB.Error.invalidArgument(
                cause: .localFileShorterThanResumeOffset,
                onOperation: operation
            )
        }

        try handle.truncate(atOffset: offset)
        try handle.seek(toOffset: offset)
        self.handle = handle
    }

    deinit {
        // Queued writes retain `self`, so none are pending here.
        if !isFinished {
            let handle = handle
            queue.async { try? handle.close() }
        }
    }

    /// Queues a block for writing once the previously queued block is on disk. Throws when an earlier queued write
    /// failed.
    func append(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            queue.async {
                if let error = self.pendingError {
                    continuation.resume(throwing: error)
                    return
                }

                // Let the caller fetch the next block while this one is written.
                continuation.resume()
                do {
                    try self.handle.write(contentsOf: data)
                }
                catch {
                    self.pendingError = self.pendingError ?? error
                }
            }
        }
    }

    /// Waits for queued writes to complete and closes the file, throwing when any of them failed. Safe to call more
    /// than once.
    func finish() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            queue.async {
                continuation.resume(with: Result { try self.finishOnQueue() })
            }
        }
    }

    /// Closes the file once and reports the first write or close error. Must run on `queue`.
    private func finishOnQueue() throws {
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

/// Reads upload blocks from a local file on a dedicated serial queue, one block ahead of the consumer, so disk reads
/// overlap network writes.
private final class ReadAheadFileReader: UploadBlockReader, @unchecked Sendable {
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

    deinit {
        let handle = handle
        queue.async { try? handle.close() }
    }

    /// Returns the next block, scheduling the read of the following block before returning. An empty block signals
    /// end-of-file. Throws when the read-ahead failed.
    func next() async throws -> Data {
        let data = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Swift.Error>) in
            queue.async {
                continuation.resume(with: self.buffered)
            }
        }
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

// MARK: - Stream Workers

/// Reads upload blocks from a caller-supplied input stream on a dedicated serial queue, one block ahead of the
/// consumer, so stream reads overlap network writes. Nothing is read before the first block is requested, and nothing
/// past
/// `limit`. The stream belongs to the caller and is never closed.
private final class ReadAheadStreamReader: UploadBlockReader, @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.SMB.Connection.streamToRemote.stream")
    private let stream: InputStream
    private let blockSize: Int
    private let operation: SMB.Error.InvalidArgumentOperation
    /// The bytes left to read before `limit`, or `nil` to read until the end of the stream. Guarded by `queue`.
    private var remaining: UInt64?
    /// The result of the most recent read-ahead, or `nil` until the first block is requested. Guarded by `queue`.
    private var buffered: Result<Data, Swift.Error>?

    init(reading stream: InputStream, limit: UInt64?, blockSize: Int, operation: SMB.Error.InvalidArgumentOperation) {
        self.stream = stream
        self.blockSize = blockSize
        self.operation = operation
        remaining = limit
    }

    /// Opens the stream if it isn't open yet. Throws when the stream is closed or has failed.
    func open() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            queue.async {
                continuation.resume(with: Result { try openStream(self.stream, operation: self.operation) })
            }
        }
    }

    /// Returns the next block, scheduling the read of the following block before returning. An empty block signals the
    /// end of the stream or of `limit`. Throws when reading from the stream failed.
    func next() async throws -> Data {
        let data = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Swift.Error>) in
            queue.async {
                continuation.resume(with: self.buffered ?? Result { try self.readBlock() })
            }
        }
        if !data.isEmpty {
            scheduleRead()
        }
        return data
    }

    /// Waits for a pending read-ahead, so the stream is no longer used once this returns.
    func finish() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                continuation.resume()
            }
        }
    }

    private func scheduleRead() {
        queue.async {
            self.buffered = Result { try self.readBlock() }
        }
    }

    /// Reads up to one block, stopping early only at `limit` or at the end of the stream. Must run on `queue`.
    private func readBlock() throws -> Data {
        let count = remaining.map { Int(min(UInt64(blockSize), $0)) } ?? blockSize
        var data = Data(count: count)
        var filled = 0
        while filled < count {
            let read = data.withUnsafeMutableBytes { buffer in
                stream.read(buffer.baseAddress!.assumingMemoryBound(to: UInt8.self) + filled, maxLength: count - filled)
            }
            guard read >= 0 else {
                throw streamFailure(stream, operation: operation, message: "Unable to read from the input stream")
            }
            guard read > 0 else { break }
            filled += read
        }
        data.count = filled
        remaining = remaining.map { $0 - UInt64(filled) }
        return data
    }
}

/// Writes downloaded blocks to a caller-supplied output stream on a dedicated serial queue so stream writes overlap
/// network reads.
///
/// ``append(_:)`` waits for the previously queued block to reach the stream before queuing the next one, bounding the
/// buffered data to two blocks. The stream belongs to the caller and is never closed.
private final class BackgroundStreamWriter: DownloadBlockWriter, @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.SMB.Connection.streamFromRemote.stream")
    private let stream: OutputStream
    private let operation: SMB.Error.InvalidArgumentOperation
    /// The first error raised by a queued write. Guarded by `queue`.
    private var pendingError: Swift.Error?

    init(writingTo stream: OutputStream, operation: SMB.Error.InvalidArgumentOperation) {
        self.stream = stream
        self.operation = operation
    }

    /// Opens the stream if it isn't open yet. Throws when the stream is closed or has failed.
    func open() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            queue.async {
                continuation.resume(with: Result { try openStream(self.stream, operation: self.operation) })
            }
        }
    }

    /// Queues a block for writing once the previously queued block is in the stream. Throws when an earlier queued
    /// write failed.
    func append(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            queue.async {
                if let error = self.pendingError {
                    continuation.resume(throwing: error)
                    return
                }

                // Let the caller fetch the next block while this one is written.
                continuation.resume()
                do {
                    try self.write(data)
                }
                catch {
                    self.pendingError = self.pendingError ?? error
                }
            }
        }
    }

    /// Waits for queued writes to complete, throwing when any of them failed. Safe to call more than once.
    func finish() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Swift.Error>) in
            queue.async {
                if let error = self.pendingError {
                    continuation.resume(throwing: error)
                }
                else {
                    continuation.resume()
                }
            }
        }
    }

    /// Writes the whole block, continuing while the stream accepts only part of it. Must run on `queue`.
    private func write(_ data: Data) throws {
        try data.withUnsafeBytes { buffer in
            var written = 0
            while written < buffer.count {
                let count = stream.write(
                    buffer.baseAddress!.assumingMemoryBound(to: UInt8.self) + written,
                    maxLength: buffer.count - written
                )
                // Zero means that a fixed-capacity stream is full.
                guard count > 0 else {
                    throw streamFailure(stream, operation: operation, message: "Unable to write to the output stream")
                }
                written += count
            }
        }
    }
}

/// Opens a caller-supplied stream that isn't open yet, and rejects one that can no longer be used. Must run on the
/// queue that owns the stream.
private func openStream(_ stream: Stream, operation: SMB.Error.InvalidArgumentOperation) throws {
    if stream.streamStatus == .notOpen {
        stream.open()
    }
    switch stream.streamStatus {
    case .closed:
        throw SMB.Error.posix(
            code: POSIXErrorCode.EBADF.rawValue,
            operation: operation.description,
            message: "Stream is closed"
        )
    case .error:
        throw streamFailure(stream, operation: operation, message: "Unable to open the stream")
    default:
        return
    }
}

/// Returns the error a stream reports for a failed call, or a generic I/O error when it reports none.
private func streamFailure(
    _ stream: Stream,
    operation: SMB.Error.InvalidArgumentOperation,
    message: String
) -> Swift.Error {
    stream.streamError ?? SMB.Error.posix(
        code: POSIXErrorCode.EIO.rawValue,
        operation: operation.description,
        message: message
    )
}

// MARK: - Validation & Preparation

/// Checks that a remote path is usable for creating or truncating a file.
private func validateRemoteDestinationForNewFile(
    on connection: SMB.Connection,
    at path: String,
    options: SMB.File.OpenOptions,
    operation: SMB.Error.InvalidArgumentOperation
) async throws {
    switch try await connection.itemExists(at: path) {
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
    operation: SMB.Error.InvalidArgumentOperation,
    disk: LocalDiskWorker
) async throws {
    let existingSize = try await disk.perform { try localFileSize(for: source, operation: operation) }
    guard existingSize >= byteCount else {
        throw SMB.Error.invalidArgument(
            cause: .localFileShorterThanResumeOffset,
            onOperation: operation
        )
    }

    let input = try await disk.perform { try ReadAheadFileReader(reading: source, offset: 0, blockSize: 1024 * 1024) }
    let output = try await disk.perform { try BackgroundFileWriter(appendingTo: destination) }
    defer { try? await output.finish() }

    var remaining = byteCount
    while remaining > 0 {
        try Task.checkCancellation()
        let data = try await input.next()
        guard !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                cause: .localFileShorterThanResumeOffset,
                onOperation: operation
            )
        }
        let prefix = data.prefix(Int(min(remaining, UInt64(data.count))))
        try await output.append(prefix)
        remaining -= UInt64(prefix.count)
    }
    try await output.finish()
}

/// Seeds the temporary remote file for an atomic resumed upload by copying the trusted remote prefix.
private func prepareAtomicUploadTarget(
    on connection: SMB.Connection,
    remote: String,
    target: String,
    offset: UInt64,
    blockSize: Int,
    operation: SMB.Error.InvalidArgumentOperation,
    onTargetCreated: () -> Void
) async throws {
    guard offset > 0 else {
        switch try await connection.itemExists(at: remote) {
        case .false, .file, .link:
            return
        case .directory, .other:
            throw SMB.Error.invalidArgument(
                cause: .remoteDestinationIsNotAFile,
                onOperation: operation
            )
        }
    }

    _ = try await validateRemoteFile(
        on: connection,
        at: remote,
        minimumSize: offset,
        operation: operation
    )

    let input = try await connection.openFile(at: remote, accessMode: .readOnly)
    defer { try? await input.close() }
    let output = try await connection.openFile(at: target, accessMode: .writeOnly, options: [.create, .exclusive])
    onTargetCreated()
    defer { try? await output.close() }

    try await connection.changeAttributes(at: target) { $0.union(.temporary) }

    var copied: UInt64 = 0
    while copied < offset {
        try Task.checkCancellation()
        let requested = min(UInt64(blockSize), offset - copied)
        _ = try await input.seek(offset: signedTransferOffset(copied), from: .start)
        let data = try await input.read(upTo: Int64(requested))
        guard !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                cause: .remoteFileShorterThanResumeOffset,
                onOperation: operation
            )
        }
        try await writeEntireData(data, to: output, atOffset: copied)
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
    onBlockWritten: (UInt64, DispatchTime) async -> Void = { _, _ in }
) async throws {
    var dataOffset = 0
    var fileOffset = baseOffset
    while dataOffset < data.count {
        try Task.checkCancellation()
        let blockStart = DispatchTime.now()
        _ = try await file.seek(offset: signedTransferOffset(fileOffset), from: .start)
        let written = try await file.write(data.subdata(in: dataOffset ..< data.count))
        guard written > 0 else {
            throw SMB.Error.unknown(
                operation: "smb2_write",
                message: "Write made no progress before all data was written"
            )
        }
        dataOffset += Int(written)
        fileOffset += UInt64(written)
        await onBlockWritten(UInt64(written), blockStart)
    }
}

// MARK: - Atomic Commit

/// Renames the temporary upload file into place, preserving the old destination via a backup path when necessary.
private func commitAtomicUpload(
    from target: String,
    to remote: String,
    on connection: SMB.Connection,
    operation: SMB.Error.InvalidArgumentOperation
) async throws {
    let backup: String?
    switch try await connection.itemExists(at: remote) {
    case .false:
        backup = nil
    case .file, .link:
        let backupPath = try await uniqueRemoteTemporaryPath(near: remote, on: connection)
        try await connection.move(from: remote, to: backupPath)
        backup = backupPath
    case .directory, .other:
        throw SMB.Error.invalidArgument(
            cause: .remoteDestinationIsNotAFile,
            onOperation: operation
        )
    }

    do {
        try await connection.move(from: target, to: remote)
    }
    catch {
        if let backup {
            try? await connection.move(from: backup, to: remote)
        }
        throw error
    }

    if let backup {
        try? await connection.removeFile(at: backup)
    }
}

// MARK: - Block Size & Speed

/// Validates a caller-preferred block size before the connection clamps it to its server limit.
private func transferBlockSize(_ preferred: UInt64?) throws -> Int? {
    guard let preferred else {
        return nil
    }
    guard preferred > 0, preferred <= UInt64(Int.max) else {
        throw SMB.Error.invalidArgument(
            cause: .blockSizeMustBePositiveAndFitInInt,
            onOperation: .smbConnectionTransferBlockSize
        )
    }
    return Int(preferred)
}

/// Rejects an offset that the signed seek API cannot represent rather than trapping during integer conversion.
private func signedTransferOffset(_ offset: UInt64) throws -> Int64 {
    guard let offset = Int64(exactly: offset) else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EINVAL.rawValue,
            operation: "smb2_lseek",
            message: "Transfer offset must fit in Int64"
        )
    }
    return offset
}

/// An EOF before the advertised length must not commit an incomplete atomic transfer.
private func unexpectedTransferEOF(operation: SMB.Error.InvalidArgumentOperation) -> SMB.Error {
    SMB.Error.posix(
        code: POSIXErrorCode.EIO.rawValue,
        operation: operation.description,
        message: "Source ended before the expected transfer length"
    )
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
) async throws -> SMB.Stat {
    let stat = try await connection.stat(at: path)
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
) async throws {
    let parent = path.removingLastPathComponent
    guard !parent.isEmpty else { return }

    let existence = try await connection.itemExists(at: parent)
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
        try await connection.makeDirectory(at: parent, makePath: true)
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

    let attributes = try FileManager.default.attributesOfItem(atPath: url.resolvingSymlinksInPath().path)
    guard attributes[.type] as? FileAttributeType == .typeRegular else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EINVAL.rawValue,
            operation: operationString,
            message: "Local source must be a regular file"
        )
    }
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
private func uniqueRemoteTemporaryPath(near remote: String, on connection: SMB.Connection) async throws -> String {
    for _ in 0 ..< 100 {
        let name = "partial-xfer.\(UUID().uuidString).tmp"
        let directory = remote.removingLastPathComponent
        let candidate = directory.isEmpty ? name : directory.appendingPathComponent(name)
        if try await connection.itemExists(at: candidate) == .false {
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
