//
// Part of SwiftSMB
// Connection-Conv-Pipe.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import PathWorks

public extension SMB.Connection {
    /// The starting position for a file transfer.
    ///
    /// Use this value to start a pipe, upload, or download operation at the beginning of the file or at a specific byte
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

    /// Reports progress for a pipe-backed SMB transfer.
    ///
    /// The closure is called after each SMB block is transferred and once more when the transfer completes
    /// successfully. The completion call reports a latest speed of `0`. Return `true` to continue, or `false` to cancel
    /// the operation. Cancellation is treated as a successful early return and does not throw.
    ///
    /// - Parameters:
    ///   - bytesTransferred: The cumulative number of bytes transferred since the operation began, excluding any resume
    /// offset.
    ///   - latestSpeed: The transfer rate for the most recent block, in bytes per second, or `0` for the completion
    /// call.
    ///   - averageSpeed: The average transfer rate since the operation began, in bytes per second.
    /// - Returns: `true` to continue the transfer, or `false` to cancel it.
    typealias PipeProgress = @Sendable (UInt64, Double, Double) -> Bool

    /// Writes data from a pipe to a file on the SMB share.
    ///
    /// This method consumes a started `pipe` until the producer finishes it, breaks it, or the progress closure returns
    /// `false`. Each data package may be split into multiple SMB writes when the slot is larger than the server's
    /// accepted write block size.
    ///
    /// If `continuation` returns `false`, the method stops transferring and returns normally. Data already written to
    /// the remote file is left in place.
    ///
    /// - Parameters:
    ///   - pipe: The data pipe to consume.
    ///   - path: The share-relative destination file path.
    ///   - from: The remote file offset at which writing should begin.
    ///   - options: Options used when opening the destination file.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values larger than the server's maximum write size
    /// are clamped.
    ///   - makePath: A Boolean value indicating whether to create missing ancestor directories before writing the file.
    /// When `false`, the method throws if the parent directory does not exist.
    ///   - continuation: A progress closure called after each SMB write block and once after the pipe is finished.
    /// - Throws: ``SMB/Error`` if the connection is closed, the file cannot be opened, a write fails, or the server
    /// reports that a write made no progress.
    func write(
        fromPipe pipe: DataPipe,
        toFile path: String,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [.create, .truncate],
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        continuation: @escaping PipeProgress,
    ) throws {
        let path = try SMB.validatePath(path, operation: .smbConnectionWriteFromPipeToFile)
        let offset = from.offsetValue
        let operation = SMB.Error.InvalidArgumentOperation.smbConnectionWriteFromPipeToFile

        try prepareRemoteDestination(
            on: self,
            path: path,
            offset: offset,
            options: options,
            makePath: makePath,
            operation: operation,
        )

        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())
        try expectStartPackage(from: pipe, operation: operation, strict: true)

        let file = try openFile(at: path, accessMode: .writeOnly, options: options)
        defer { try? file.close() }

        _ = try transferPipeToFile(
            pipe: pipe,
            file: file,
            startingOffset: offset,
            blockSize: blockSize,
            operation: operation,
            continuation: continuation,
        )
    }

    /// Reads a file from the SMB share into a pipe.
    ///
    /// The method reads from `path` in server-accepted blocks and sends each block into `pipe`. The method sends
    /// ``DataPipe/Package/start`` before reading, then ``DataPipe/Package/finish`` on successful completion or caller
    /// cancellation. It sends ``DataPipe/Package/broken`` when the transfer fails after startup.
    ///
    /// If `continuation` returns `false`, the method stops transferring and returns normally. The pipe remains readable
    /// until any already-sent data has been drained.
    ///
    /// - Parameters:
    ///   - path: The share-relative source file path.
    ///   - pipe: The data pipe that receives file contents.
    ///   - from: The remote file offset at which reading should begin.
    ///   - options: Options used when opening the source file.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values larger than the server's maximum read size
    /// are clamped.
    ///   - continuation: A progress closure called after each SMB read block and once after the remote file reaches
    /// end-of-file.
    /// - Throws: ``SMB/Error`` if the connection is closed, the file cannot be opened, or a read fails.
    func read(
        fromFile path: String,
        toPipe pipe: DataPipe,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64? = nil,
        continuation: @escaping PipeProgress,
    ) throws {
        let path = try SMB.validatePath(path, operation: .smbConnectionReadFromFileToPipe)
        let offset = from.offsetValue
        let operation = SMB.Error.InvalidArgumentOperation.smbConnectionReadFromFileToPipe

        try validateRemoteFile(
            on: self,
            at: path,
            minimumSize: offset,
            operation: operation,
        )
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())

        try startPipeReadWorker(
            on: self,
            path: path,
            offset: offset,
            blockSize: blockSize,
            options: options,
            operation: operation,
            pipe: pipe,
            continuation: continuation,
        )
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
    /// untouched.
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
    ///   - continuation: A progress closure called after each block is written locally and once after the completed
    /// download is moved into place.
    /// - Throws: ``SMB/Error`` if the connection is closed, the remote file cannot be inspected or read, the resume
    /// offset is invalid, or a local file operation fails.
    func downloadFile(
        remote: String,
        local: URL,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64? = nil,
        continuation: @escaping FileProgress,
    ) throws {
        let remote = try SMB.validatePath(remote, operation: .smbConnectionDownloadFile)
        let offset = from.offsetValue
        let operation = SMB.Error.InvalidArgumentOperation.smbConnectionDownloadFile

        let remoteStat = try validateRemoteFile(
            on: self,
            at: remote,
            minimumSize: offset,
            operation: operation,
        )
        let totalBytes = remoteStat.size - offset

        try assertValidLocalDestination(local, operation: operation)
        let tempFile = try createUniqueLocalTempFile(near: local, operation: operation)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        if offset > 0 {
            try copyLocalPrefix(from: local, to: tempFile, byteCount: offset, operation: operation)
        }

        let pipe = DataPipe(maxPackages: 3, label: "com.ruinelson.SwiftSMB.SMB.Connection.downloadFile")
        let consumer = try startLocalFileConsumer(
            pipe: pipe,
            destination: tempFile,
            operation: operation,
            on: self,
        )

        let reportedBytes = Protected<UInt64>(
            0,
            label: "com.ruinelson.SwiftSMB.SMB.Connection.downloadFile.reportedBytes",
        )
        let finalAverageSpeed = Protected<Double>(
            0,
            label: "com.ruinelson.SwiftSMB.SMB.Connection.downloadFile.finalAverageSpeed",
        )
        let cancelled = Protected(false, label: "com.ruinelson.SwiftSMB.SMB.Connection.downloadFile.cancelled")

        do {
            try read(
                fromFile: remote,
                toPipe: pipe,
                from: from,
                options: options,
                maxBlockSize: maxBlockSize,
            ) { completed, latestSpeed, averageSpeed in
                let shouldContinue = adaptPipeProgressToFileProgress(
                    pipeProgress: continuation,
                    reportedBytes: reportedBytes,
                    finalAverageSpeed: finalAverageSpeed,
                    completed: completed,
                    totalBytes: totalBytes,
                    latestSpeed: latestSpeed,
                    averageSpeed: averageSpeed,
                )
                if !shouldContinue {
                    cancelled.current = true
                }
                return shouldContinue
            }

            try consumer.wait()
            guard !cancelled.current else { return }
            try moveTempFile(tempFile, to: local)
            _ = continuation(reportedBytes.current, totalBytes, 0, finalAverageSpeed.current)
        }
        catch {
            consumer.cancel()
            try consumer.wait()
            throw error
        }
    }

    /// Uploads a local file to the SMB share.
    ///
    /// When `atomic` is `true`, the upload is written to a temporary path in the destination directory and renamed to
    /// `remote` only after the transfer completes successfully. If the transfer fails or is cancelled, the temporary
    /// remote file is removed. When `atomic` is `false`, bytes are written directly to `remote` using `options`;
    /// cancellation or failure may leave a partially written remote file.
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
        continuation: @escaping FileProgress,
    ) throws {
        let remote = try SMB.validatePath(remote, operation: .smbConnectionUploadFile)
        let offset = from.offsetValue
        let operation = SMB.Error.InvalidArgumentOperation.smbConnectionUploadFile

        try validateOrCreateRemoteParent(
            on: self,
            for: remote,
            makePath: makePath,
            operation: operation,
        )

        let fileSize = try localFileSize(for: local, operation: operation)
        guard offset <= fileSize else {
            throw SMB.Error.invalidArgument(
                cause: .offsetBeyondEndOfLocalFile,
                onOperation: operation,
            )
        }

        let totalBytes = fileSize - offset
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())

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
                operation: operation,
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

        let cancelled = Protected(false, label: "com.ruinelson.SwiftSMB.SMB.Connection.uploadFile.cancelled")
        let pipe = DataPipe(maxPackages: 3, label: "com.ruinelson.SwiftSMB.SMB.Connection.uploadFile")
        let producer = try startLocalFileProducer(
            pipe: pipe,
            source: local,
            offset: offset,
            blockSize: blockSize,
            cancelled: cancelled,
            operation: operation,
            on: self,
        )

        let reportedBytes = Protected<UInt64>(
            0,
            label: "com.ruinelson.SwiftSMB.SMB.Connection.uploadFile.reportedBytes",
        )
        let finalAverageSpeed = Protected<Double>(
            0,
            label: "com.ruinelson.SwiftSMB.SMB.Connection.uploadFile.finalAverageSpeed",
        )

        do {
            try write(
                fromPipe: pipe,
                toFile: target,
                from: from,
                options: openOptions,
                maxBlockSize: maxBlockSize,
            ) { completed, latestSpeed, averageSpeed in
                let shouldContinue = adaptPipeProgressToFileProgress(
                    pipeProgress: continuation,
                    reportedBytes: reportedBytes,
                    finalAverageSpeed: finalAverageSpeed,
                    completed: completed,
                    totalBytes: totalBytes,
                    latestSpeed: latestSpeed,
                    averageSpeed: averageSpeed,
                )
                if !shouldContinue {
                    cancelled.current = true
                }
                return shouldContinue
            }

            if cancelled.current {
                drain(pipe)
            }
            try producer.wait()
            guard !cancelled.current else { return }

            if atomic {
                try commitAtomicUpload(from: target, to: remote, on: self, operation: operation)
                shouldRemoveRemoteTemp = false
                try changeAttributes(at: remote) { $0.subtracting(.temporary) }
            }

            _ = continuation(reportedBytes.current, totalBytes, 0, finalAverageSpeed.current)
        }
        catch {
            cancelled.current = true
            drain(pipe)
            try producer.wait()
            throw error
        }
    }
}

// MARK: - Pipe Transfer Engine

/// Transfers all data from a pipe into an already-open remote file. Returns the total number of bytes transferred
/// (excluding the resume offset).
private func transferPipeToFile(
    pipe: DataPipe,
    file: SMB.File,
    startingOffset: UInt64,
    blockSize: Int,
    operation: SMB.Error.InvalidArgumentOperation,
    continuation: SMB.Connection.PipeProgress,
) throws -> UInt64 {
    var remoteOffset = startingOffset
    var transferred: UInt64 = 0
    let operationStart = DispatchTime.now()

    while true {
        let package = try receivePackage(from: pipe, operation: operation)
        switch package {
        case .start:
            continue
        case .finish:
            _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
            return transferred
        case .broken:
            throw brokenPipeError(operation: operation)
        case let .data(data):
            let shouldContinue = try writeDataBlock(
                data,
                to: file,
                at: &remoteOffset,
                blockSize: blockSize,
                operationStart: operationStart,
                operation: operation,
                continuation: continuation,
                globalTransferred: &transferred,
            )
            guard shouldContinue else {
                _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
                return transferred
            }
        }
    }
}

/// Writes a single pipe data package to the remote file, splitting it into server-sized blocks and reporting progress
/// for each block. Returns `true` if the entire package was written; `false` if cancellation was requested mid-block.
private func writeDataBlock(
    _ data: Data,
    to file: SMB.File,
    at remoteOffset: inout UInt64,
    blockSize: Int,
    operationStart: DispatchTime,
    operation: SMB.Error.InvalidArgumentOperation,
    continuation: SMB.Connection.PipeProgress,
    globalTransferred: inout UInt64,
) throws -> Bool {
    var dataOffset = 0

    while dataOffset < data.count {
        let blockEnd = min(dataOffset + blockSize, data.count)
        let block = data.subdata(in: dataOffset ..< blockEnd)
        let blockStart = DispatchTime.now()

        _ = try file.seek(offset: Int64(remoteOffset), from: .start)
        let written = try file.write(block)
        guard written > 0 else {
            throw SMB.Error.unknown(
                operation: "smb2_write",
                message: "Write made no progress before all pipe data was written",
            )
        }

        dataOffset += Int(written)
        remoteOffset += UInt64(written)
        globalTransferred += UInt64(written)

        let latestSpeed = speed(bytes: UInt64(written), from: blockStart, to: .now())
        let averageSpeed = speed(bytes: globalTransferred, from: operationStart, to: .now())
        guard continuation(globalTransferred, latestSpeed, averageSpeed) else {
            return false
        }
    }

    return true
}

// MARK: - Pipe Read Worker

/// Starts an asynchronous worker that reads a remote file into a pipe. Blocks until the file is successfully opened,
/// propagating startup errors to the caller synchronously.
private func startPipeReadWorker(
    on connection: SMB.Connection,
    path: String,
    offset: UInt64,
    blockSize: Int,
    options: SMB.File.OpenOptions,
    operation: SMB.Error.InvalidArgumentOperation,
    pipe: DataPipe,
    continuation: @escaping SMB.Connection.PipeProgress,
) throws {
    let startup = DispatchSemaphore(value: 0)
    let startupError = Protected<Swift.Error?>(
        nil,
        label: "com.ruinelson.SwiftSMB.SMB.Connection.read.startupError",
    )

    connection.readWorkerQueue.async {
        var didSignalReady = false
        func signalReady(_ error: Swift.Error?) {
            guard !didSignalReady else { return }
            didSignalReady = true
            startupError.current = error
            startup.signal()
        }

        do {
            try sendPackage(.start, to: pipe, operation: operation)
            let file = try connection.openFile(at: path, accessMode: .readOnly, options: options)
            signalReady(nil)

            _ = try transferFileToPipe(
                file: file,
                pipe: pipe,
                startingOffset: offset,
                blockSize: blockSize,
                operation: operation,
                continuation: continuation,
            )

            try? file.close()
            try sendPackage(.finish, to: pipe, operation: operation)
        }
        catch {
            signalReady(error)
            try? sendPackage(.broken, to: pipe, operation: operation)
        }
    }

    startup.wait()
    if let error = startupError.current {
        throw error
    }
}

/// Reads blocks from an open remote file and pushes them into a pipe. Returns the total bytes transferred and the final
/// average speed.
private func transferFileToPipe(
    file: SMB.File,
    pipe: DataPipe,
    startingOffset: UInt64,
    blockSize: Int,
    operation: SMB.Error.InvalidArgumentOperation,
    continuation: SMB.Connection.PipeProgress,
) throws -> (transferred: UInt64, finalAverageSpeed: Double) {
    var remoteOffset = startingOffset
    var transferred: UInt64 = 0
    let operationStart = DispatchTime.now()

    while true {
        let blockStart = DispatchTime.now()
        _ = try file.seek(offset: Int64(remoteOffset), from: .start)
        let data = try file.read(upTo: Int64(blockSize))

        guard !data.isEmpty else {
            let finalAverage = speed(bytes: transferred, from: operationStart, to: .now())
            _ = continuation(transferred, 0, finalAverage)
            return (transferred, finalAverage)
        }

        try sendPackage(.data(data), to: pipe, operation: operation)
        remoteOffset += UInt64(data.count)
        transferred += UInt64(data.count)

        let latestSpeed = speed(bytes: UInt64(data.count), from: blockStart, to: .now())
        let averageSpeed = speed(bytes: transferred, from: operationStart, to: .now())
        guard continuation(transferred, latestSpeed, averageSpeed) else {
            return (transferred, averageSpeed)
        }
    }
}

// MARK: - Local File Consumer / Producer

/// Represents an asynchronous local-file consumer that can be awaited.
private struct LocalFileConsumer {
    private let group: DispatchGroup
    private let errorBox: Protected<Swift.Error?>
    private let cancelledBox: Protected<Bool>

    init(group: DispatchGroup, errorBox: Protected<Swift.Error?>, cancelledBox: Protected<Bool>) {
        self.group = group
        self.errorBox = errorBox
        self.cancelledBox = cancelledBox
    }

    /// Waits for the consumer to finish and throws if it failed.
    func wait() throws {
        group.wait()
        if let error = errorBox.current {
            throw error
        }
    }

    /// Signals cancellation so the consumer stops writing and finishes cleanly.
    func cancel() {
        cancelledBox.current = true
    }
}

/// Starts an asynchronous worker that consumes a pipe and writes to a local file.
private func startLocalFileConsumer(
    pipe: DataPipe,
    destination: URL,
    operation: SMB.Error.InvalidArgumentOperation,
    on connection: SMB.Connection,
) throws -> LocalFileConsumer {
    let group = DispatchGroup()
    let errorBox = Protected<Swift.Error?>(nil, label: "com.ruinelson.SwiftSMB.consumer.error")
    let cancelledBox = Protected(false, label: "com.ruinelson.SwiftSMB.consumer.cancelled")

    group.enter()
    connection.downloaderQueue.async {
        defer { group.leave() }
        do {
            let handle = try FileHandle(forWritingTo: destination)
            defer { try? handle.close() }
            handle.seekToEndOfFile()

            try consumePipePackages(pipe: pipe, handle: handle, cancelled: cancelledBox, operation: operation)
        }
        catch {
            errorBox.current = error
            cancelledBox.current = true
            drain(pipe)
        }
    }

    return LocalFileConsumer(group: group, errorBox: errorBox, cancelledBox: cancelledBox)
}

/// Reads packages from a pipe and writes data to a local file handle.
private func consumePipePackages(
    pipe: DataPipe,
    handle: FileHandle,
    cancelled: Protected<Bool>,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    // Ignore any noise before .start.
    try expectStartPackage(from: pipe, operation: operation, timeout: nil)

    var isFinished = false
    while !isFinished {
        let package = try receivePackage(from: pipe, operation: operation, timeout: nil)
        switch package {
        case .start:
            continue
        case .finish:
            isFinished = true
        case .broken:
            throw brokenPipeError(operation: operation)
        case let .data(data):
            if !cancelled.current {
                handle.write(data)
            }
        }
    }
}

/// Represents an asynchronous local-file producer that can be awaited.
private struct LocalFileProducer {
    private let group: DispatchGroup
    private let errorBox: Protected<Swift.Error?>

    init(group: DispatchGroup, errorBox: Protected<Swift.Error?>) {
        self.group = group
        self.errorBox = errorBox
    }

    func wait() throws {
        group.wait()
        if let error = errorBox.current {
            throw error
        }
    }
}

/// Starts an asynchronous worker that reads a local file and produces into a pipe.
private func startLocalFileProducer(
    pipe: DataPipe,
    source: URL,
    offset: UInt64,
    blockSize: Int,
    cancelled: Protected<Bool>,
    operation: SMB.Error.InvalidArgumentOperation,
    on connection: SMB.Connection,
) throws -> LocalFileProducer {
    let group = DispatchGroup()
    let errorBox = Protected<Swift.Error?>(nil, label: "com.ruinelson.SwiftSMB.producer.error")

    group.enter()
    connection.uploadProducerQueue.async {
        var didBreak = false
        defer {
            if !didBreak {
                try? sendPackage(.finish, to: pipe, operation: operation)
            }
            group.leave()
        }

        do {
            let handle = try FileHandle(forReadingFrom: source)
            defer { try? handle.close() }
            handle.seek(toFileOffset: offset)

            try sendPackage(.start, to: pipe, operation: operation)
            while !cancelled.current {
                let data = handle.readData(ofLength: blockSize)
                guard !data.isEmpty else { return }
                try sendPackage(.data(data), to: pipe, operation: operation)
            }
        }
        catch {
            errorBox.current = error
            didBreak = true
            try? sendPackage(.broken, to: pipe, operation: operation)
        }
    }

    return LocalFileProducer(group: group, errorBox: errorBox)
}

// MARK: - Validation & Preparation

/// Validates the remote destination before writing, creating parent directories if requested, and checking
/// preconditions based on the resume offset.
private func prepareRemoteDestination(
    on connection: SMB.Connection,
    path: String,
    offset: UInt64,
    options: SMB.File.OpenOptions,
    makePath: Bool,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    try validateOrCreateRemoteParent(
        on: connection,
        for: path,
        makePath: makePath,
        operation: operation,
    )

    if offset > 0 {
        try validateRemoteFile(
            on: connection,
            at: path,
            minimumSize: offset,
            operation: operation,
        )
    }
    else {
        try validateRemoteDestinationForNewFile(
            on: connection,
            at: path,
            options: options,
            operation: operation,
        )
    }
}

/// Checks that a remote path is usable for creating or truncating a file.
private func validateRemoteDestinationForNewFile(
    on connection: SMB.Connection,
    at path: String,
    options: SMB.File.OpenOptions,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    switch try connection.itemExists(at: path) {
    case .false:
        guard options.contains(.create) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.ENOENT.rawValue,
                operation: operation.description,
                message: "Remote file does not exist",
            )
        }
    case .file, .link:
        guard !options.contains(.exclusive) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EEXIST.rawValue,
                operation: operation.description,
                message: "Remote file already exists",
            )
        }
    case .directory, .other:
        throw SMB.Error.invalidArgument(
            cause: .remoteDestinationIsNotAFile,
            onOperation: operation,
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
            message: "Local parent directory does not exist",
        )
    }
    guard isDirectory.boolValue else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOTDIR.rawValue,
            operation: operation.description,
            message: "Local parent path is not a directory",
        )
    }

    if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory), isDirectory.boolValue {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EISDIR.rawValue,
            operation: operation.description,
            message: "Local destination is a directory",
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
        message: "Unable to create a unique temporary file",
    )
}

/// Copies the first `byteCount` bytes from `source` into `destination`.
private func copyLocalPrefix(
    from source: URL,
    to destination: URL,
    byteCount: UInt64,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    let existingSize = try localFileSize(for: source, operation: operation)
    guard existingSize >= byteCount else {
        throw SMB.Error.invalidArgument(
            cause: .localFileShorterThanResumeOffset,
            onOperation: operation,
        )
    }

    let input = try FileHandle(forReadingFrom: source)
    defer { try? input.close() }
    let output = try FileHandle(forWritingTo: destination)
    defer { try? output.close() }

    var remaining = byteCount
    while remaining > 0 {
        let chunkSize = min(Int(remaining), 1024 * 1024)
        let data = input.readData(ofLength: chunkSize)
        guard !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                cause: .localFileShorterThanResumeOffset,
                onOperation: operation,
            )
        }
        output.write(data)
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
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    guard offset > 0 else {
        switch try connection.itemExists(at: remote) {
        case .false, .file, .link:
            return
        case .directory, .other:
            throw SMB.Error.invalidArgument(
                cause: .remoteDestinationIsNotAFile,
                onOperation: operation,
            )
        }
    }

    _ = try validateRemoteFile(
        on: connection,
        at: remote,
        minimumSize: offset,
        operation: operation,
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
                onOperation: operation,
            )
        }
        try writeEntireData(data, to: output, atOffset: copied, operation: operation)
        copied += UInt64(data.count)
    }
}

/// Writes a complete data buffer to a remote file, retrying internally if the server accepts only a prefix.
private func writeEntireData(
    _ data: Data,
    to file: SMB.File,
    atOffset baseOffset: UInt64,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    var dataOffset = 0
    var fileOffset = baseOffset
    while dataOffset < data.count {
        _ = try file.seek(offset: Int64(fileOffset), from: .start)
        let written = try file.write(data.subdata(in: dataOffset ..< data.count))
        guard written > 0 else {
            throw SMB.Error.unknown(
                operation: "smb2_write",
                message: "Write made no progress while copying the remote prefix",
            )
        }
        dataOffset += Int(written)
        fileOffset += UInt64(written)
    }
}

// MARK: - Atomic Commit

/// Renames the temporary upload file into place, preserving the old destination via a backup path when necessary.
private func commitAtomicUpload(
    from target: String,
    to remote: String,
    on connection: SMB.Connection,
    operation: SMB.Error.InvalidArgumentOperation,
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
            onOperation: operation,
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

// MARK: - Progress Adaptation

/// Adapts a ``SMB.Connection.FileProgress`` closure to the shape expected by pipe operations, deduplicating the final
/// zero-speed call and caching the last average speed for the explicit completion call.
private func adaptPipeProgressToFileProgress(
    pipeProgress: @escaping SMB.Connection.FileProgress,
    reportedBytes: Protected<UInt64>,
    finalAverageSpeed: Protected<Double>,
    completed: UInt64,
    totalBytes: UInt64,
    latestSpeed: Double,
    averageSpeed: Double,
) -> Bool {
    if completed == reportedBytes.current, latestSpeed == 0 {
        finalAverageSpeed.current = averageSpeed
        return true
    }
    reportedBytes.current = completed
    return pipeProgress(completed, totalBytes, latestSpeed, averageSpeed)
}

// MARK: - Pipe Protocol Primitives

/// Expects and consumes a `.start` package from the pipe. When `strict` is `true`, receiving `.data` or `.finish`
/// before `.start` is treated as an invalid-argument error rather than ignored.
private func expectStartPackage(
    from pipe: DataPipe,
    operation: SMB.Error.InvalidArgumentOperation,
    strict: Bool = false,
    timeout: TimeInterval? = pipePackageTimeout,
) throws {
    while true {
        let package = try receivePackage(from: pipe, operation: operation, timeout: timeout)
        switch package {
        case .start:
            return
        case .broken:
            throw brokenPipeError(operation: operation)
        case .data, .finish:
            if strict {
                throw SMB.Error.invalidArgument(
                    cause: .pipeDataMustBeginWithStartPackage,
                    onOperation: operation,
                )
            }
            continue
        }
    }
}

/// Sends a package to a pipe, translating timeout into a typed error.
private func sendPackage(
    _ package: DataPipe.Package,
    to pipe: DataPipe,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    guard pipe.send(package, timeout: pipePackageTimeout) else {
        throw pipeTimeoutError(operation: operation)
    }
}

/// Receives a package from a pipe, translating timeout into a typed error.
private func receivePackage(
    from pipe: DataPipe,
    operation: SMB.Error.InvalidArgumentOperation,
    timeout: TimeInterval? = pipePackageTimeout,
) throws -> DataPipe.Package {
    guard let package = pipe.receive(timeout: timeout) else {
        throw pipeTimeoutError(operation: operation)
    }
    return package
}

/// Consumes pending pipe packages until a terminal package is received.
private func drain(_ pipe: DataPipe) {
    while let package = pipe.receive(timeout: pipePackageTimeout), package != .finish, package != .broken {
    }
}

// MARK: - Block Size & Speed

/// Resolves a caller-preferred block size against the server limit.
private func pipeBlockSize(_ preferred: UInt64?, acceptedBlockSize: Int) throws -> Int {
    guard let preferred else {
        return acceptedBlockSize
    }
    guard preferred > 0, preferred <= UInt64(Int.max) else {
        throw SMB.Error.invalidArgument(
            cause: .blockSizeMustBePositiveAndFitInInt,
            onOperation: .smbConnectionPipeBlockSize,
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

// MARK: - Error Factories

private let pipePackageTimeout: TimeInterval = 30

private func brokenPipeError(operation: SMB.Error.InvalidArgumentOperation) -> SMB.Error {
    SMB.Error.posix(
        code: POSIXErrorCode.EPIPE.rawValue,
        operation: operation.description,
        message: "Pipe was broken before the transfer completed",
    )
}

private func pipeTimeoutError(operation: SMB.Error.InvalidArgumentOperation) -> SMB.Error {
    SMB.Error.posix(
        code: POSIXErrorCode.ETIMEDOUT.rawValue,
        operation: operation.description,
        message: "Timed out waiting for pipe activity",
    )
}

// MARK: - Remote Validation

/// Validates that a remote path exists, is a regular file, and is large enough for a resume offset.
@discardableResult
private func validateRemoteFile(
    on connection: SMB.Connection,
    at path: String,
    minimumSize: UInt64,
    operation: SMB.Error.InvalidArgumentOperation,
) throws -> SMB.Stat {
    let stat = try connection.stat(at: path)
    guard stat.type == .file else {
        throw SMB.Error.invalidArgument(cause: .remotePathIsNotAFile, onOperation: operation)
    }
    guard stat.size >= minimumSize else {
        throw SMB.Error.invalidArgument(
            cause: .remoteFileShorterThanResumeOffset,
            onOperation: operation,
        )
    }
    return stat
}

/// Validates or creates the parent directory for a remote destination path.
private func validateOrCreateRemoteParent(
    on connection: SMB.Connection,
    for path: String,
    makePath: Bool,
    operation: SMB.Error.InvalidArgumentOperation,
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
                onOperation: operation,
            )
        }
        try connection.makeDirectory(at: parent, makePath: true)
    case .file, .link, .other:
        throw SMB.Error.invalidArgument(
            cause: .remoteParentPathIsNotADirectory,
            onOperation: operation,
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
            message: "Local file does not exist",
        )
    }
    guard !isDirectory.boolValue else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EISDIR.rawValue,
            operation: operationString,
            message: "Local path is a directory",
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
        message: "Unable to create a unique temporary remote path",
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
