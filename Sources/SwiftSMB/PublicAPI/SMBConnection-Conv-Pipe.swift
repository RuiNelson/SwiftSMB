//
// Part of SwiftSMB
// SMBConnection-Conv-Pipe.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import PathWorks

public extension SMB.Connection {
    /// The starting position for a file transfer.
    ///
    /// Use this value to start a pipe, upload, or download operation at the
    /// beginning of the file or at a specific byte offset. Offset-based
    /// transfers are useful for resuming an interrupted operation when the
    /// caller has already verified that the source and destination share the
    /// same prefix.
    enum FromArgument {
        /// Start the transfer at byte offset zero.
        case beginning

        /// Start the transfer at an explicit byte offset.
        ///
        /// - Parameter byte: The zero-based byte offset at which transfer
        ///   should begin.
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
    /// The closure is called after each SMB block is transferred and once more
    /// when the transfer completes successfully. The completion call reports a
    /// latest speed of `0`. Return `true` to continue, or `false` to cancel
    /// the operation. Cancellation is treated as a successful early return and
    /// does not throw.
    ///
    /// - Parameters:
    ///   - bytesTransferred: The cumulative number of bytes transferred since
    ///     the operation began, excluding any resume offset.
    ///   - latestSpeed: The transfer rate for the most recent block, in bytes
    ///     per second, or `0` for the completion call.
    ///   - averageSpeed: The average transfer rate since the operation began,
    ///     in bytes per second.
    /// - Returns: `true` to continue the transfer, or `false` to cancel it.
    typealias PipeProgress = (UInt64, Double, Double) -> Bool

    /// Writes data from a pipe to a file on the SMB share.
    ///
    /// This method consumes data packages from `pipe` until the producer
    /// finishes the pipe, breaks the pipe, or the progress closure returns
    /// `false`. Each data package may be split
    /// into multiple SMB writes when the slot is larger than the server's
    /// accepted write block size.
    ///
    /// If `continuation` returns `false`, the method stops transferring and
    /// returns normally. Data already written to the remote file is left in
    /// place.
    ///
    /// - Parameters:
    ///   - pipe: The data pipe to consume.
    ///   - path: The share-relative destination file path.
    ///   - from: The remote file offset at which writing should begin.
    ///   - options: Options used when opening the destination file.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values
    ///     larger than the server's maximum write size are clamped.
    ///   - continuation: A progress closure called after each SMB write block
    ///     and once after the pipe is finished.
    /// - Throws: ``SMB/Error`` if the connection is closed, the file cannot be
    ///   opened, a write fails, or the server reports that a write made no
    ///   progress.
    func write(
        fromPipe pipe: DataPipe,
        toFile path: String,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [.create, .truncate],
        maxBlockSize: UInt64 = (10 * 1024 * 1024),
        continuation: @escaping PipeProgress,
    ) throws {
        let path = try SMB.validatePath(path, operation: "SMB.Connection.write(fromPipe:toFile:)")
        let offset = from.offsetValue
        try validateRemoteWriteTarget(
            on: self,
            at: path,
            options: options,
            offset: offset,
            operation: "SMB.Connection.write(fromPipe:toFile:)",
        )
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())

        let group = DispatchGroup()
        let transferError = Protected<Swift.Error?>(nil, label: "SwiftSMB.SMB.Connection.write.error")
        let callback = UncheckedSendable(continuation)

        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }

            do {
                try writePipeContents(
                    from: pipe,
                    to: self,
                    path: path,
                    offset: offset,
                    options: options,
                    blockSize: blockSize,
                    continuation: callback.value,
                )
            }
            catch {
                transferError.current = error
            }
        }

        group.wait()
        if let error = transferError.current {
            throw error
        }
    }

    /// Reads a file from the SMB share into a pipe.
    ///
    /// The method reads from `path` in server-accepted blocks and sends each
    /// block into `pipe`. The method sends ``DataPipe/Package/start`` before
    /// reading, then ``DataPipe/Package/finish`` on success or
    /// ``DataPipe/Package/broken`` on cancellation or failure.
    ///
    /// If `continuation` returns `false`, the method stops transferring and
    /// returns normally. The pipe remains readable until any already-sent data
    /// has been drained.
    ///
    /// - Parameters:
    ///   - path: The share-relative source file path.
    ///   - pipe: The data pipe that receives file contents.
    ///   - from: The remote file offset at which reading should begin.
    ///   - options: Options used when opening the source file.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values
    ///     larger than the server's maximum read size are clamped.
    ///   - continuation: A progress closure called after each SMB read block
    ///     and once after the remote file reaches end-of-file.
    /// - Throws: ``SMB/Error`` if the connection is closed, the file cannot be
    ///   opened, or a read fails.
    func read(
        fromFile path: String,
        toPipe pipe: DataPipe,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64 = (10 * 1024 * 1024),
        continuation: @escaping PipeProgress,
    ) throws {
        let path = try SMB.validatePath(path, operation: "SMB.Connection.read(fromFile:toPipe:)")
        let offset = from.offsetValue
        try validateRemoteFile(
            on: self,
            at: path,
            minimumSize: offset,
            operation: "SMB.Connection.read(fromFile:toPipe:)",
        )
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())

        let startup = DispatchSemaphore(value: 0)
        let startupError = Protected<Swift.Error?>(nil, label: "SwiftSMB.SMB.Connection.read.startupError")
        let callback = UncheckedSendable(continuation)

        DispatchQueue.global().async {
            do {
                try readFileContents(
                    from: self,
                    path: path,
                    to: pipe,
                    offset: offset,
                    options: options,
                    blockSize: blockSize,
                    ready: { error in
                        startupError.current = error
                        startup.signal()
                    },
                    continuation: callback.value,
                )
            }
            catch {
                startupError.current = error
            }
        }

        startup.wait()
        if let error = startupError.current {
            throw error
        }
    }

    /// Reports progress for a local file transfer.
    ///
    /// The closure is called after each block is transferred between local
    /// storage and the SMB share and once more when the transfer completes
    /// successfully. The completion call reports a latest speed of `0`.
    /// Return `true` to continue, or `false` to cancel the operation.
    /// Cancellation is treated as a successful early return and does not
    /// throw.
    ///
    /// - Parameters:
    ///   - bytesTransferred: The cumulative number of bytes transferred since
    ///     the operation began, excluding any resume offset.
    ///   - totalBytes: The total number of bytes expected to be transferred,
    ///     excluding any resume offset.
    ///   - latestSpeed: The transfer rate for the most recent block, in bytes
    ///     per second, or `0` for the completion call.
    ///   - averageSpeed: The average transfer rate since the operation began,
    ///     in bytes per second.
    /// - Returns: `true` to continue the transfer, or `false` to cancel it.
    typealias FileProgress = (UInt64, UInt64, Double, Double) -> Bool

    /// Downloads a file from the SMB share to a local URL.
    ///
    /// The download is written to a temporary file first. When the transfer
    /// completes successfully, the temporary file replaces `local`
    /// atomically where the platform supports it, or is moved into place when
    /// no destination exists. If the transfer fails or is cancelled, the
    /// temporary file is removed and any existing file at `local` is left
    /// untouched.
    ///
    /// To resume a partial download, pass an offset with
    /// ``FromArgument/offset(byte:)``. The existing local file must contain at
    /// least that many bytes; those bytes are copied into the temporary file
    /// before new data is appended.
    ///
    /// If `continuation` returns `false`, the method cancels the download and
    /// returns normally.
    ///
    /// - Parameters:
    ///   - remote: The share-relative source file path.
    ///   - local: The destination file URL on local storage.
    ///   - from: The byte offset at which downloading should begin.
    ///   - options: Options used when opening the remote source file.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values
    ///     larger than the server's maximum read size are clamped.
    ///   - continuation: A progress closure called after each block is written
    ///     locally and once after the completed download is moved into place.
    /// - Throws: ``SMB/Error`` if the connection is closed, the remote file
    ///   cannot be inspected or read, the resume offset is invalid, or a local
    ///   file operation fails.
    func downloadFile(
        remote: String,
        local: URL,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64 = (10 * 1024 * 1024),
        continuation: @escaping FileProgress,
    ) throws {
        let remote = try SMB.validatePath(remote, operation: "SMB.Connection.downloadFile")
        let offset = from.offsetValue
        let remoteStat = try validateRemoteFile(
            on: self,
            at: remote,
            minimumSize: offset,
            operation: "SMB.Connection.downloadFile",
        )
        let totalBytes = remoteStat.size - offset
        _ = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())

        try validateLocalDestination(local, operation: "SMB.Connection.downloadFile")
        let tempFile = try uniqueTemporaryFileURL(near: local)
        var shouldRemoveTemp = true
        defer {
            if shouldRemoveTemp {
                try? FileManager.default.removeItem(at: tempFile)
            }
        }

        try preparePrefix(for: local, into: tempFile, byteCount: offset)

        let pipe = DataPipe(maxPackages: 3, label: "SwiftSMB.SMB.Connection.downloadFile")
        let consumer = DispatchGroup()
        let consumerError = Protected<Swift.Error?>(nil, label: "SwiftSMB.SMB.Connection.downloadFile.error")
        let cancelled = Protected(false, label: "SwiftSMB.SMB.Connection.downloadFile.cancelled")

        consumer.enter()
        DispatchQueue.global().async {
            defer { consumer.leave() }

            var shouldDrain = true
            do {
                let handle = try FileHandle(forWritingTo: tempFile)
                defer { try? handle.close() }
                handle.seekToEndOfFile()

                while true {
                    let package = try receivePackage(from: pipe, operation: "SMB.Connection.downloadFile")
                    switch package {
                    case .start:
                        break
                    case .broken:
                        shouldDrain = false
                        throw brokenPipeError(operation: "SMB.Connection.downloadFile")
                    case .data, .finish:
                        continue
                    }
                    break
                }

                var isFinished = false
                while !isFinished {
                    let package = try receivePackage(from: pipe, operation: "SMB.Connection.downloadFile")
                    switch package {
                    case .start:
                        continue
                    case .finish:
                        shouldDrain = false
                        isFinished = true
                    case .broken:
                        shouldDrain = false
                        throw brokenPipeError(operation: "SMB.Connection.downloadFile")
                    case let .data(data):
                        if consumerError.current == nil {
                            handle.write(data)
                        }
                    }
                }
            }
            catch {
                consumerError.current = error
                cancelled.current = true
                if shouldDrain {
                    drain(pipe)
                }
            }
        }

        var reportedBytes: UInt64 = 0
        var finalAverageSpeed: Double = 0

        do {
            try read(
                fromFile: remote,
                toPipe: pipe,
                from: from,
                options: options,
                maxBlockSize: maxBlockSize,
            ) { completed, latestSpeed, averageSpeed in
                if consumerError.current != nil {
                    cancelled.current = true
                    finalAverageSpeed = averageSpeed
                    return false
                }

                if completed == reportedBytes, latestSpeed == 0 {
                    finalAverageSpeed = averageSpeed
                    return true
                }

                reportedBytes = completed
                let shouldContinue = continuation(completed, totalBytes, latestSpeed, averageSpeed)
                if !shouldContinue {
                    cancelled.current = true
                }
                return shouldContinue
            }

            consumer.wait()
            if let error = consumerError.current {
                throw error
            }

            guard !cancelled.current else { return }

            try replaceItem(at: local, with: tempFile)
            shouldRemoveTemp = false
            _ = continuation(reportedBytes, totalBytes, 0, finalAverageSpeed)
        }
        catch {
            cancelled.current = true
            consumer.wait()
            throw error
        }
    }

    /// Uploads a local file to the SMB share.
    ///
    /// When `atomic` is `true`, the upload is written to a temporary path in
    /// the destination directory and renamed to `remote` only after the
    /// transfer completes successfully. If the transfer fails or is cancelled,
    /// the temporary remote file is removed. When `atomic` is `false`, bytes
    /// are written directly to `remote` using `options`; cancellation or
    /// failure may leave a partially written remote file.
    ///
    /// To resume a partial upload, pass an offset with
    /// ``FromArgument/offset(byte:)``. For atomic resumed uploads, the existing
    /// remote file must contain at least that many bytes; that prefix is copied
    /// into the temporary remote file before the remaining local bytes are
    /// uploaded.
    ///
    /// If `continuation` returns `false`, the method cancels the upload and
    /// returns normally.
    ///
    /// - Parameters:
    ///   - local: The source file URL on local storage.
    ///   - remote: The share-relative destination file path.
    ///   - from: The byte offset at which uploading should begin.
    ///   - options: Options used when opening `remote` for a non-atomic
    ///     upload.
    ///   - maxBlockSize: The preferred maximum transfer block size. Values
    ///     larger than the server's maximum write size are clamped.
    ///   - atomic: A Boolean value indicating whether to upload through a
    ///     temporary remote file before renaming it into place.
    ///   - continuation: A progress closure called after each SMB write block
    ///     and once after the completed upload is in place.
    /// - Throws: ``SMB/Error`` if the connection is closed, a remote operation
    ///   fails, the resume offset is invalid, or a local file operation fails.
    func uploadFile(
        local: URL,
        remote: String,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        maxBlockSize: UInt64 = (10 * 1024 * 1024),
        atomic: Bool = true,
        continuation: @escaping FileProgress,
    ) throws {
        let remote = try SMB.validatePath(remote, operation: "SMB.Connection.uploadFile")
        try validateRemoteParentExists(on: self, for: remote, operation: "SMB.Connection.uploadFile")

        let offset = from.offsetValue
        let fileSize = try localFileSize(for: local, operation: "SMB.Connection.uploadFile")
        guard offset <= fileSize else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.uploadFile",
                message: "Offset is beyond the end of the local file",
            )
        }

        let totalBytes = fileSize - offset
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())
        let target = atomic ? temporaryRemotePath(near: remote) : remote
        let cancelled = Protected(false, label: "SwiftSMB.SMB.Connection.uploadFile.cancelled")
        let producerError = Protected<Swift.Error?>(nil, label: "SwiftSMB.SMB.Connection.uploadFile.error")
        let producer = DispatchGroup()
        let pipe = DataPipe(maxPackages: 3, label: "SwiftSMB.SMB.Connection.uploadFile")
        var shouldRemoveRemoteTemp = atomic

        defer {
            if shouldRemoveRemoteTemp {
                try? removeFile(at: target)
            }
        }

        if offset > 0 {
            _ = try validateRemoteFile(
                on: self,
                at: remote,
                minimumSize: offset,
                operation: "SMB.Connection.uploadFile",
            )
        }
        if atomic, offset > 0 {
            try copyRemotePrefix(on: self, from: remote, to: target, byteCount: offset, blockSize: blockSize)
        }
        else if atomic {
            try validateRemoteDestination(on: self, remote, operation: "SMB.Connection.uploadFile")
        }

        producer.enter()
        DispatchQueue.global().async {
            var didBreak = false
            defer {
                if !didBreak {
                    do {
                        try sendPackage(.finish, to: pipe, operation: "SMB.Connection.uploadFile")
                    }
                    catch {
                        producerError.current = producerError.current ?? error
                    }
                }
                producer.leave()
            }

            do {
                let handle = try FileHandle(forReadingFrom: local)
                defer { try? handle.close() }
                handle.seek(toFileOffset: offset)

                try sendPackage(.start, to: pipe, operation: "SMB.Connection.uploadFile")
                while !cancelled.current {
                    let data = handle.readData(ofLength: blockSize)
                    guard !data.isEmpty else { return }
                    try sendPackage(.data(data), to: pipe, operation: "SMB.Connection.uploadFile")
                }
            }
            catch {
                producerError.current = error
                didBreak = true
                try? sendPackage(.broken, to: pipe, operation: "SMB.Connection.uploadFile")
            }
        }

        var reportedBytes: UInt64 = 0
        var finalAverageSpeed: Double = 0

        do {
            let openOptions: SMB.File.OpenOptions = if atomic {
                offset == 0 ? [.create, .truncate] : []
            }
            else {
                options
            }

            try write(
                fromPipe: pipe,
                toFile: target,
                from: from,
                options: openOptions,
                maxBlockSize: maxBlockSize,
            ) { completed, latestSpeed, averageSpeed in
                if completed == reportedBytes, latestSpeed == 0 {
                    finalAverageSpeed = averageSpeed
                    return true
                }

                reportedBytes = completed
                let shouldContinue = continuation(completed, totalBytes, latestSpeed, averageSpeed)
                if !shouldContinue {
                    cancelled.current = true
                }
                return shouldContinue
            }

            if cancelled.current {
                drain(pipe)
            }
            producer.wait()

            if let error = producerError.current, !cancelled.current {
                throw error
            }
            guard !cancelled.current else { return }

            if atomic {
                try replaceRemoteItem(on: self, at: remote, with: target)
                shouldRemoveRemoteTemp = false
            }

            _ = continuation(reportedBytes, totalBytes, 0, finalAverageSpeed)
        }
        catch {
            cancelled.current = true
            drain(pipe)
            producer.wait()
            throw error
        }
    }
}

/// Calculates bytes per second for an elapsed interval.
private func speed(bytes: UInt64, from start: DispatchTime, to end: DispatchTime) -> Double {
    let elapsed = Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000
    guard elapsed > 0 else { return 0 }
    return Double(bytes) / elapsed
}

private struct UncheckedSendable<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

private let pipePackageTimeout: TimeInterval = 30

private func writePipeContents(
    from pipe: DataPipe,
    to connection: SMB.Connection,
    path: String,
    offset: UInt64,
    options: SMB.File.OpenOptions,
    blockSize: Int,
    continuation: @escaping SMB.Connection.PipeProgress,
) throws {
    try waitForPipeStart(pipe, operation: "SMB.Connection.write(fromPipe:toFile:)")

    let file = try connection.openFile(at: path, accessMode: .writeOnly, options: options)
    defer { try? file.close() }

    var remoteOffset = offset
    var transferred: UInt64 = 0
    let operationStart = DispatchTime.now()

    while true {
        let package = try receivePackage(from: pipe, operation: "SMB.Connection.write(fromPipe:toFile:)")
        switch package {
        case .start:
            continue
        case .finish:
            _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
            return
        case .broken:
            throw brokenPipeError(operation: "SMB.Connection.write(fromPipe:toFile:)")
        case let .data(data):
            var dataOffset = 0
            while dataOffset < data.count {
                let blockEnd = min(dataOffset + blockSize, data.count)
                let block = data.subdata(in: dataOffset ..< blockEnd)
                let blockStart = DispatchTime.now()
                let written = try file.write(block, atOffset: remoteOffset)
                guard written > 0 else {
                    throw SMB.Error.unknown(
                        operation: "smb2_write",
                        message: "Write made no progress before all pipe data was written",
                    )
                }

                dataOffset += written
                remoteOffset += UInt64(written)
                transferred += UInt64(written)

                let end = DispatchTime.now()
                let latestSpeed = speed(bytes: UInt64(written), from: blockStart, to: end)
                let averageSpeed = speed(bytes: transferred, from: operationStart, to: end)
                guard continuation(transferred, latestSpeed, averageSpeed) else { return }
            }
        }
    }
}

private func readFileContents(
    from connection: SMB.Connection,
    path: String,
    to pipe: DataPipe,
    offset: UInt64,
    options: SMB.File.OpenOptions,
    blockSize: Int,
    ready: (Swift.Error?) -> Void,
    continuation: @escaping SMB.Connection.PipeProgress,
) throws {
    var didSignalReady = false
    func signalReady(_ error: Swift.Error?) {
        guard !didSignalReady else { return }
        didSignalReady = true
        ready(error)
    }

    do {
        try sendPackage(.start, to: pipe, operation: "SMB.Connection.read(fromFile:toPipe:)")

        let file = try connection.openFile(at: path, accessMode: .readOnly, options: options)
        signalReady(nil)

        var remoteOffset = offset
        var transferred: UInt64 = 0
        let operationStart = DispatchTime.now()

        while true {
            let blockStart = DispatchTime.now()
            let data = try file.read(upToByteCount: blockSize, atOffset: remoteOffset)
            guard !data.isEmpty else {
                _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
                try? file.close()
                try sendPackage(.finish, to: pipe, operation: "SMB.Connection.read(fromFile:toPipe:)")
                return
            }

            try sendPackage(.data(data), to: pipe, operation: "SMB.Connection.read(fromFile:toPipe:)")
            remoteOffset += UInt64(data.count)
            transferred += UInt64(data.count)

            let end = DispatchTime.now()
            let latestSpeed = speed(bytes: UInt64(data.count), from: blockStart, to: end)
            let averageSpeed = speed(bytes: transferred, from: operationStart, to: end)
            guard continuation(transferred, latestSpeed, averageSpeed) else {
                try? file.close()
                try sendPackage(.finish, to: pipe, operation: "SMB.Connection.read(fromFile:toPipe:)")
                return
            }
        }
    }
    catch {
        signalReady(error)
        try? sendPackage(.broken, to: pipe, operation: "SMB.Connection.read(fromFile:toPipe:)")
        throw error
    }
}

private func waitForPipeStart(_ pipe: DataPipe, operation: String) throws {
    while true {
        let package = try receivePackage(from: pipe, operation: operation)
        switch package {
        case .start:
            return
        case .broken:
            throw brokenPipeError(operation: operation)
        case .data, .finish:
            continue
        }
    }
}

private func brokenPipeError(operation: String) -> SMB.Error {
    SMB.Error.posix(
        code: POSIXErrorCode.EPIPE.rawValue,
        operation: operation,
        message: "Pipe was broken before the transfer completed",
    )
}

private func pipeTimeoutError(operation: String) -> SMB.Error {
    SMB.Error.posix(
        code: POSIXErrorCode.ETIMEDOUT.rawValue,
        operation: operation,
        message: "Timed out waiting for pipe activity",
    )
}

private func sendPackage(_ package: DataPipe.Package, to pipe: DataPipe, operation: String) throws {
    guard pipe.send(package, timeout: pipePackageTimeout) else {
        throw pipeTimeoutError(operation: operation)
    }
}

private func receivePackage(from pipe: DataPipe, operation: String) throws -> DataPipe.Package {
    guard let package = pipe.receive(timeout: pipePackageTimeout) else {
        throw pipeTimeoutError(operation: operation)
    }
    return package
}

/// Resolves a caller-preferred block size against the server limit.
private func pipeBlockSize(_ preferred: UInt64, acceptedBlockSize: Int) throws -> Int {
    guard preferred > 0, preferred <= UInt64(Int.max) else {
        throw SMB.Error.invalidArgument(
            operation: "SMB.Connection.pipeBlockSize",
            message: "Block size must be greater than zero and fit in Int",
        )
    }
    return min(Int(preferred), acceptedBlockSize)
}

/// Consumes pending pipe packages until a terminal package is received.
private func drain(_ pipe: DataPipe) {
    while let package = pipe.receive(timeout: pipePackageTimeout), package != .finish, package != .broken {
    }
}

/// Validates a remote write destination before opening it.
private func validateRemoteWriteTarget(
    on connection: SMB.Connection,
    at path: String,
    options: SMB.File.OpenOptions,
    offset: UInt64,
    operation: String,
) throws {
    try validateRemoteParentExists(on: connection, for: path, operation: operation)

    if offset > 0 {
        try validateRemoteFile(on: connection, at: path, minimumSize: offset, operation: operation)
        return
    }

    switch try connection.itemExists(at: path) {
    case .false:
        guard options.contains(.create) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.ENOENT.rawValue,
                operation: operation,
                message: "Remote file does not exist",
            )
        }
    case .file, .link:
        guard !options.contains(.exclusive) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EEXIST.rawValue,
                operation: operation,
                message: "Remote file already exists",
            )
        }
    case .directory, .other:
        throw SMB.Error.invalidArgument(operation: operation, message: "Remote destination is not a file")
    }
}

/// Validates that a remote path exists, is a regular file, and is large enough for a resume offset.
@discardableResult
private func validateRemoteFile(
    on connection: SMB.Connection,
    at path: String,
    minimumSize: UInt64,
    operation: String,
) throws -> SMB.Stat {
    let stat = try connection.stat(at: path)
    guard stat.type == .file else {
        throw SMB.Error.invalidArgument(operation: operation, message: "Remote path is not a file")
    }
    guard stat.size >= minimumSize else {
        throw SMB.Error.invalidArgument(
            operation: operation,
            message: "Remote file is shorter than the requested resume offset",
        )
    }
    return stat
}

/// Validates the parent directory for a remote destination path.
private func validateRemoteParentExists(on connection: SMB.Connection, for path: String, operation: String) throws {
    let parent = path.removingLastPathComponent
    guard !parent.isEmpty else { return }

    let existence = try connection.itemExists(at: parent)
    guard existence == .directory else {
        throw SMB.Error.invalidArgument(operation: operation, message: "Remote parent directory does not exist")
    }
}

/// Validates that a remote destination can be replaced by a file.
private func validateRemoteDestination(on connection: SMB.Connection, _ path: String, operation: String) throws {
    switch try connection.itemExists(at: path) {
    case .false, .file, .link:
        return
    case .directory, .other:
        throw SMB.Error.invalidArgument(operation: operation, message: "Remote destination is not a file")
    }
}

/// Returns the size of a local regular file.
private func localFileSize(for url: URL, operation: String) throws -> UInt64 {
    var isDirectory = ObjCBool(false)
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOENT.rawValue,
            operation: operation,
            message: "Local file does not exist",
        )
    }
    guard !isDirectory.boolValue else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EISDIR.rawValue,
            operation: operation,
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

    throw SMB.Error.invalidArgument(operation: operation, message: "Unable to determine local file size")
}

/// Validates a local download destination and its parent directory.
private func validateLocalDestination(_ url: URL, operation: String) throws {
    let parent = url.deletingLastPathComponent()
    var parentIsDirectory = ObjCBool(false)
    guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &parentIsDirectory) else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOENT.rawValue,
            operation: operation,
            message: "Local parent directory does not exist",
        )
    }
    guard parentIsDirectory.boolValue else {
        throw SMB.Error.posix(
            code: POSIXErrorCode.ENOTDIR.rawValue,
            operation: operation,
            message: "Local parent path is not a directory",
        )
    }

    var destinationIsDirectory = ObjCBool(false)
    if FileManager.default.fileExists(atPath: url.path, isDirectory: &destinationIsDirectory),
       destinationIsDirectory.boolValue {
        throw SMB.Error.posix(
            code: POSIXErrorCode.EISDIR.rawValue,
            operation: operation,
            message: "Local destination is a directory",
        )
    }
}

/// Creates an empty temporary file beside a destination URL.
private func uniqueTemporaryFileURL(near destination: URL) throws -> URL {
    let directory = destination.deletingLastPathComponent()

    for _ in 0 ..< 100 {
        let candidate = directory.appendingPathComponent(".SwiftSMB.\(UUID().uuidString).tmp")
        if FileManager.default.createFile(atPath: candidate.path, contents: nil) {
            return candidate
        }
    }

    throw SMB.Error.unknown(
        operation: "SMB.Connection.uniqueTemporaryFileURL",
        message: "Unable to create a unique temporary file",
    )
}

/// Copies an already-downloaded local prefix into a temporary destination.
private func preparePrefix(for local: URL, into tempFile: URL, byteCount: UInt64) throws {
    guard byteCount > 0 else { return }

    let existingSize = try localFileSize(for: local, operation: "SMB.Connection.downloadFile")
    guard existingSize >= byteCount else {
        throw SMB.Error.invalidArgument(
            operation: "SMB.Connection.downloadFile",
            message: "Local file is shorter than the requested resume offset",
        )
    }

    let input = try FileHandle(forReadingFrom: local)
    defer { try? input.close() }
    let output = try FileHandle(forWritingTo: tempFile)
    defer { try? output.close() }

    var remaining = byteCount
    while remaining > 0 {
        let chunkSize = min(Int(remaining), 1024 * 1024)
        let data = input.readData(ofLength: chunkSize)
        guard !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.downloadFile",
                message: "Local file is shorter than the requested resume offset",
            )
        }
        output.write(data)
        remaining -= UInt64(data.count)
    }
}

/// Replaces an existing destination or moves the source into place.
private func replaceItem(at destination: URL, with source: URL) throws {
    if FileManager.default.fileExists(atPath: destination.path) {
        _ = try FileManager.default.replaceItemAt(destination, withItemAt: source)
    }
    else {
        try FileManager.default.moveItem(at: source, to: destination)
    }
}

/// Builds a temporary remote path beside the final destination.
private func temporaryRemotePath(near remote: String) -> String {
    let name = ".SwiftSMB.\(UUID().uuidString).tmp"
    let directory = remote.removingLastPathComponent
    return directory.isEmpty ? name : directory.appendingPathComponent(name)
}

/// Replaces an existing remote file or moves the temporary file into place.
private func replaceRemoteItem(on connection: SMB.Connection, at destination: String, with source: String) throws {
    switch try connection.itemExists(at: destination) {
    case .false:
        break
    case .file, .link:
        try connection.removeFile(at: destination)
    case .directory, .other:
        throw SMB.Error.invalidArgument(
            operation: "SMB.Connection.uploadFile",
            message: "Remote destination is not a file",
        )
    }

    try connection.rename(from: source, to: destination)
}

/// Copies a remote prefix when preparing an atomic resumed upload.
private func copyRemotePrefix(
    on connection: SMB.Connection,
    from source: String,
    to destination: String,
    byteCount: UInt64,
    blockSize: Int,
) throws {
    let input = try connection.openFile(at: source, accessMode: .readOnly)
    defer { try? input.close() }
    let output = try connection.openFile(at: destination, accessMode: .writeOnly, options: [.create, .truncate])
    defer { try? output.close() }

    var copied: UInt64 = 0
    while copied < byteCount {
        let requested = min(blockSize, Int(byteCount - copied))
        let data = try input.read(upToByteCount: requested, atOffset: copied)
        guard !data.isEmpty else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.uploadFile",
                message: "Remote file is shorter than the requested resume offset",
            )
        }

        var dataOffset = 0
        while dataOffset < data.count {
            let written = try output.write(data.subdata(in: dataOffset ..< data.count), atOffset: copied)
            guard written > 0 else {
                throw SMB.Error.unknown(
                    operation: "smb2_write",
                    message: "Write made no progress while copying the remote prefix",
                )
            }
            copied += UInt64(written)
            dataOffset += written
        }
    }
}
