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
    typealias PipeProgress = @Sendable (UInt64, Double, Double) -> Bool

    /// Writes data from a pipe to a file on the SMB share.
    ///
    /// This method consumes a started `pipe` until the producer finishes it,
    /// breaks it, or the progress closure returns `false`. Each data package
    /// may be split into multiple SMB writes when the slot is larger than the
    /// server's accepted write block size.
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
    ///   - makePath: A Boolean value indicating whether to create missing
    ///     ancestor directories before writing the file. When `false`, the
    ///     method throws if the parent directory does not exist.
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
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        continuation: @escaping PipeProgress,
    ) throws {
        let path = try SMB.validatePath(path, operation: .smbConnectionWriteFromPipeToFile)
        let offset = from.offsetValue

        try validateOrCreateRemoteParent(
            on: self,
            for: path,
            makePath: makePath,
            operation: .smbConnectionWriteFromPipeToFile,
        )

        if offset > 0 {
            try validateRemoteFile(
                on: self,
                at: path,
                minimumSize: offset,
                operation: .smbConnectionWriteFromPipeToFile,
            )
        }
        else {
            switch try itemExists(at: path) {
            case .false:
                guard options.contains(.create) else {
                    throw SMB.Error.posix(
                        code: POSIXErrorCode.ENOENT.rawValue,
                        operation: SMB.Error.InvalidArgumentOperation.smbConnectionWriteFromPipeToFile.description,
                        message: "Remote file does not exist",
                    )
                }
            case .file, .link:
                guard !options.contains(.exclusive) else {
                    throw SMB.Error.posix(
                        code: POSIXErrorCode.EEXIST.rawValue,
                        operation: SMB.Error.InvalidArgumentOperation.smbConnectionWriteFromPipeToFile.description,
                        message: "Remote file already exists",
                    )
                }
            case .directory, .other:
                throw SMB.Error.invalidArgument(
                    cause: .remoteDestinationIsNotAFile,
                    onOperation: .smbConnectionWriteFromPipeToFile,
                )
            }
        }

        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())

        while true {
            let package = try receivePackage(from: pipe, operation: .smbConnectionWriteFromPipeToFile)
            switch package {
            case .start:
                break
            case .broken:
                throw brokenPipeError(operation: .smbConnectionWriteFromPipeToFile)
            case .data, .finish:
                // Treat malformed producer order as a caller bug. Silently skipping
                // data here would make uploads appear successful while losing bytes.
                throw SMB.Error.invalidArgument(
                    cause: .pipeDataMustBeginWithStartPackage,
                    onOperation: .smbConnectionWriteFromPipeToFile,
                )
            }
            break
        }

        let file = try openFile(at: path, accessMode: .writeOnly, options: options)
        defer { try? file.close() }

        var remoteOffset = offset
        var transferred: UInt64 = 0
        let operationStart = DispatchTime.now()

        while true {
            let package = try receivePackage(from: pipe, operation: .smbConnectionWriteFromPipeToFile)
            switch package {
            case .start:
                continue
            case .finish:
                _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
                return
            case .broken:
                throw brokenPipeError(operation: .smbConnectionWriteFromPipeToFile)
            case let .data(data):
                // A pipe package may be larger than the negotiated SMB write size.
                // Split it here so callers can use convenient local buffer sizes.
                var dataOffset = 0
                while dataOffset < data.count {
                    let blockEnd = min(dataOffset + blockSize, data.count)
                    let block = data.subdata(in: dataOffset ..< blockEnd)
                    let blockStart = DispatchTime.now()
                    let written = try file._write(block, atOffset: remoteOffset)
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

    /// Reads a file from the SMB share into a pipe.
    ///
    /// The method reads from `path` in server-accepted blocks and sends each
    /// block into `pipe`. The method sends ``DataPipe/Package/start`` before
    /// reading, then ``DataPipe/Package/finish`` on successful completion or
    /// caller cancellation. It sends ``DataPipe/Package/broken`` when the
    /// transfer fails after startup.
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
        maxBlockSize: UInt64? = nil,
        continuation: @escaping PipeProgress,
    ) throws {
        let path = try SMB.validatePath(path, operation: .smbConnectionReadFromFileToPipe)
        let offset = from.offsetValue
        try validateRemoteFile(
            on: self,
            at: path,
            minimumSize: offset,
            operation: .smbConnectionReadFromFileToPipe,
        )
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())

        let startup = DispatchSemaphore(value: 0)
        let startupError = Protected<Swift.Error?>(nil, label: "SwiftSMB.SMB.Connection.read.startupError")

        DispatchQueue.global().async {
            var didSignalReady = false
            func signalReady(_ error: Swift.Error?) {
                guard !didSignalReady else { return }
                didSignalReady = true
                startupError.current = error
                startup.signal()
            }

            do {
                // Signal .start before opening the remote file so consumers can begin
                // waiting immediately; startup errors are still reported through ready.
                try sendPackage(.start, to: pipe, operation: .smbConnectionReadFromFileToPipe)

                let file = try self.openFile(at: path, accessMode: .readOnly, options: options)
                signalReady(nil)

                var remoteOffset = offset
                var transferred: UInt64 = 0
                let operationStart = DispatchTime.now()

                while true {
                    let blockStart = DispatchTime.now()
                    let data = try file.read(upToByteCount: blockSize, atOffset: remoteOffset)
                    guard !data.isEmpty else {
                        // EOF is reported as both final progress and .finish so high-level
                        // file transfers can delay their own final callback until commit.
                        _ = continuation(
                            transferred,
                            0,
                            speed(bytes: transferred, from: operationStart, to: .now()),
                        )
                        try? file.close()
                        try sendPackage(.finish, to: pipe, operation: .smbConnectionReadFromFileToPipe)
                        return
                    }

                    try sendPackage(.data(data), to: pipe, operation: .smbConnectionReadFromFileToPipe)
                    remoteOffset += UInt64(data.count)
                    transferred += UInt64(data.count)

                    let end = DispatchTime.now()
                    let latestSpeed = speed(bytes: UInt64(data.count), from: blockStart, to: end)
                    let averageSpeed = speed(bytes: transferred, from: operationStart, to: end)
                    guard continuation(transferred, latestSpeed, averageSpeed) else {
                        // Caller cancellation is a clean stop: sent data remains readable
                        // and the terminal package is .finish, not .broken.
                        try? file.close()
                        try sendPackage(.finish, to: pipe, operation: .smbConnectionReadFromFileToPipe)
                        return
                    }
                }
            }
            catch {
                signalReady(error)
                try? sendPackage(.broken, to: pipe, operation: .smbConnectionReadFromFileToPipe)
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
    typealias FileProgress = @Sendable (UInt64, UInt64, Double, Double) -> Bool

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
        maxBlockSize: UInt64? = nil,
        continuation: @escaping FileProgress,
    ) throws {
        let remote = try SMB.validatePath(remote, operation: .smbConnectionDownloadFile)
        let offset = from.offsetValue
        let remoteStat = try validateRemoteFile(
            on: self,
            at: remote,
            minimumSize: offset,
            operation: .smbConnectionDownloadFile,
        )
        let totalBytes = remoteStat.size - offset
        _ = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())

        let parent = local.deletingLastPathComponent()
        var parentIsDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: parent.path, isDirectory: &parentIsDirectory) else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.ENOENT.rawValue,
                operation: SMB.Error.InvalidArgumentOperation.smbConnectionDownloadFile.description,
                message: "Local parent directory does not exist",
            )
        }
        guard parentIsDirectory.boolValue else {
            throw SMB.Error.posix(
                code: POSIXErrorCode.ENOTDIR.rawValue,
                operation: SMB.Error.InvalidArgumentOperation.smbConnectionDownloadFile.description,
                message: "Local parent path is not a directory",
            )
        }

        var destinationIsDirectory = ObjCBool(false)
        if FileManager.default.fileExists(atPath: local.path, isDirectory: &destinationIsDirectory),
           destinationIsDirectory.boolValue {
            throw SMB.Error.posix(
                code: POSIXErrorCode.EISDIR.rawValue,
                operation: SMB.Error.InvalidArgumentOperation.smbConnectionDownloadFile.description,
                message: "Local destination is a directory",
            )
        }

        let tempFile: URL = try {
            let directory = local.deletingLastPathComponent()

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
        }()
        var shouldRemoveTemp = true
        defer {
            if shouldRemoveTemp {
                try? FileManager.default.removeItem(at: tempFile)
            }
        }

        if offset > 0 {
            let existingSize = try localFileSize(for: local, operation: .smbConnectionDownloadFile)
            guard existingSize >= offset else {
                throw SMB.Error.invalidArgument(
                    cause: .localFileShorterThanResumeOffset,
                    onOperation: .smbConnectionDownloadFile,
                )
            }

            let input = try FileHandle(forReadingFrom: local)
            defer { try? input.close() }
            let output = try FileHandle(forWritingTo: tempFile)
            defer { try? output.close() }

            var remaining = offset
            while remaining > 0 {
                let chunkSize = min(Int(remaining), 1024 * 1024)
                let data = input.readData(ofLength: chunkSize)
                guard !data.isEmpty else {
                    throw SMB.Error.invalidArgument(
                        cause: .localFileShorterThanResumeOffset,
                        onOperation: .smbConnectionDownloadFile,
                    )
                }
                output.write(data)
                remaining -= UInt64(data.count)
            }
        }

        let pipe = DataPipe(maxPackages: 3, label: "SwiftSMB.SMB.Connection.downloadFile")
        let consumer = DispatchGroup()
        let consumerError = Protected<Swift.Error?>(nil, label: "SwiftSMB.SMB.Connection.downloadFile.error")
        let cancelled = Protected(false, label: "SwiftSMB.SMB.Connection.downloadFile.cancelled")

        // The SMB reader owns the producer side of the pipe; this consumer keeps
        // local file I/O off that path so slow disks naturally apply back-pressure.
        consumer.enter()
        DispatchQueue.global().async {
            defer { consumer.leave() }

            var shouldDrain = true
            do {
                let handle = try FileHandle(forWritingTo: tempFile)
                defer { try? handle.close() }
                handle.seekToEndOfFile()

                // Ignore any noise before .start so a future producer wrapper can
                // still send setup metadata without making the download fail.
                while true {
                    let package = try receivePackage(from: pipe, operation: .smbConnectionDownloadFile)
                    switch package {
                    case .start:
                        break
                    case .broken:
                        shouldDrain = false
                        throw brokenPipeError(operation: .smbConnectionDownloadFile)
                    case .data, .finish:
                        continue
                    }
                    break
                }

                var isFinished = false
                while !isFinished {
                    let package = try receivePackage(from: pipe, operation: .smbConnectionDownloadFile)
                    switch package {
                    case .start:
                        continue
                    case .finish:
                        shouldDrain = false
                        isFinished = true
                    case .broken:
                        shouldDrain = false
                        throw brokenPipeError(operation: .smbConnectionDownloadFile)
                    case let .data(data):
                        // FileHandle.write can throw Objective-C exceptions on
                        // some platforms; once an error is observed, stop writing
                        // but keep consuming until the producer can stop cleanly.
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

        let reportedBytes = Protected<UInt64>(0, label: "SwiftSMB.SMB.Connection.downloadFile.reportedBytes")
        let finalAverageSpeed = Protected<Double>(0, label: "SwiftSMB.SMB.Connection.downloadFile.finalAverageSpeed")

        do {
            try read(
                fromFile: remote,
                toPipe: pipe,
                from: from,
                options: options,
                maxBlockSize: maxBlockSize,
            ) { completed, latestSpeed, averageSpeed in
                // If the local writer failed, ask the remote reader to stop so it
                // sends a terminal package instead of filling a pipe nobody wants.
                if consumerError.current != nil {
                    cancelled.current = true
                    finalAverageSpeed.current = averageSpeed
                    return false
                }

                // read(fromFile:toPipe:) emits a final progress call with the same
                // byte count and latestSpeed == 0. Save the final average, but let
                // downloadFile report completion only after the temp file is moved.
                if completed == reportedBytes.current, latestSpeed == 0 {
                    finalAverageSpeed.current = averageSpeed
                    return true
                }

                reportedBytes.current = completed
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

            if FileManager.default.fileExists(atPath: local.path) {
                _ = try FileManager.default.replaceItemAt(local, withItemAt: tempFile)
            }
            else {
                try FileManager.default.moveItem(at: tempFile, to: local)
            }
            shouldRemoveTemp = false
            _ = continuation(reportedBytes.current, totalBytes, 0, finalAverageSpeed.current)
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
    ///   - makePath: A Boolean value indicating whether to create missing
    ///     ancestor directories before writing the file. When `false`, the
    ///     method throws if the parent directory does not exist.
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
        maxBlockSize: UInt64? = nil,
        makePath: Bool = true,
        atomic: Bool = true,
        continuation: @escaping FileProgress,
    ) throws {
        let remote = try SMB.validatePath(remote, operation: .smbConnectionUploadFile)
        try validateOrCreateRemoteParent(
            on: self,
            for: remote,
            makePath: makePath,
            operation: .smbConnectionUploadFile,
        )

        let offset = from.offsetValue
        let fileSize = try localFileSize(for: local, operation: .smbConnectionUploadFile)
        guard offset <= fileSize else {
            throw SMB.Error.invalidArgument(
                cause: .offsetBeyondEndOfLocalFile,
                onOperation: .smbConnectionUploadFile,
            )
        }

        let totalBytes = fileSize - offset
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())
        let target: String = if atomic {
            // libsmb2 rename cannot replace in place, so the upload is staged
            // under a unique sibling path and swapped after all bytes land.
            try uniqueRemoteTemporaryPath(near: remote, on: self)
        }
        else {
            remote
        }
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
                operation: .smbConnectionUploadFile,
            )
        }
        if atomic, offset > 0 {
            // For resumed atomic uploads, seed the temp file with the trusted
            // remote prefix before appending bytes from the local resume offset.
            let input = try openFile(at: remote, accessMode: .readOnly)
            defer { try? input.close() }
            let output = try openFile(at: target, accessMode: .writeOnly, options: [.create, .exclusive])
            defer { try? output.close() }

            var copied: UInt64 = 0
            while copied < offset {
                let requested = min(blockSize, Int(offset - copied))
                let data = try input.read(upToByteCount: requested, atOffset: copied)
                guard !data.isEmpty else {
                    throw SMB.Error.invalidArgument(
                        cause: .remoteFileShorterThanResumeOffset,
                        onOperation: .smbConnectionUploadFile,
                    )
                }

                var dataOffset = 0
                while dataOffset < data.count {
                    // Continue from dataOffset because SMB writes may accept only a
                    // prefix of the buffer even when the read returned a full chunk.
                    let written = try output._write(data.subdata(in: dataOffset ..< data.count), atOffset: copied)
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
        else if atomic {
            switch try itemExists(at: remote) {
            case .false, .file, .link:
                break
            case .directory, .other:
                throw SMB.Error.invalidArgument(
                    cause: .remoteDestinationIsNotAFile,
                    onOperation: .smbConnectionUploadFile,
                )
            }
        }

        producer.enter()
        DispatchQueue.global().async {
            var didBreak = false
            defer {
                // A normal return from the producer is EOF or cancellation, both
                // represented as .finish. Real local I/O failures send .broken.
                if !didBreak {
                    do {
                        try sendPackage(.finish, to: pipe, operation: .smbConnectionUploadFile)
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

                // The pipe protocol requires .start first; write(fromPipe:) now
                // rejects data before start instead of silently discarding it.
                try sendPackage(.start, to: pipe, operation: .smbConnectionUploadFile)
                while !cancelled.current {
                    let data = handle.readData(ofLength: blockSize)
                    guard !data.isEmpty else { return }
                    try sendPackage(.data(data), to: pipe, operation: .smbConnectionUploadFile)
                }
            }
            catch {
                producerError.current = error
                didBreak = true
                try? sendPackage(.broken, to: pipe, operation: .smbConnectionUploadFile)
            }
        }

        let reportedBytes = Protected<UInt64>(0, label: "SwiftSMB.SMB.Connection.uploadFile.reportedBytes")
        let finalAverageSpeed = Protected<Double>(0, label: "SwiftSMB.SMB.Connection.uploadFile.finalAverageSpeed")

        do {
            let openOptions: SMB.File.OpenOptions = if atomic {
                offset == 0 ? [.create, .exclusive] : []
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
                if completed == reportedBytes.current, latestSpeed == 0 {
                    finalAverageSpeed.current = averageSpeed
                    return true
                }

                reportedBytes.current = completed
                let shouldContinue = continuation(completed, totalBytes, latestSpeed, averageSpeed)
                if !shouldContinue {
                    cancelled.current = true
                }
                return shouldContinue
            }

            if cancelled.current {
                // Cancellation can leave producer packages queued. Drain them before
                // waiting so a blocked producer has room to send its terminal package.
                drain(pipe)
            }
            producer.wait()

            if let error = producerError.current, !cancelled.current {
                throw error
            }
            guard !cancelled.current else { return }

            if atomic {
                // Keep the old destination recoverable until the temp file has been
                // renamed into place.
                let backup: String?
                switch try itemExists(at: remote) {
                case .false:
                    backup = nil
                case .file, .link:
                    // libsmb2 sets replace_if_exist = 0 for rename, so move the old file
                    // aside first. This gives us a chance to restore it if the final rename
                    // fails after the upload itself has completed.
                    let backupPath = try uniqueRemoteTemporaryPath(near: remote, on: self)
                    try move(from: remote, to: backupPath)
                    backup = backupPath
                case .directory, .other:
                    throw SMB.Error.invalidArgument(
                        cause: .remoteDestinationIsNotAFile,
                        onOperation: .smbConnectionUploadFile,
                    )
                }

                do {
                    try move(from: target, to: remote)
                }
                catch {
                    if let backup {
                        // Best-effort rollback: preserving the user's existing file matters
                        // more than surfacing a secondary cleanup failure here.
                        try? move(from: backup, to: remote)
                    }
                    throw error
                }

                if let backup {
                    try? removeFile(at: backup)
                }
                shouldRemoveRemoteTemp = false
            }

            _ = continuation(reportedBytes.current, totalBytes, 0, finalAverageSpeed.current)
        }
        catch {
            cancelled.current = true
            // On failures, unblock the producer before waiting for it; otherwise a
            // full pipe can deadlock the cleanup path.
            drain(pipe)
            producer.wait()
            if let producerError = producerError.current {
                throw producerError
            }
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

private func sendPackage(
    _ package: DataPipe.Package,
    to pipe: DataPipe,
    operation: SMB.Error.InvalidArgumentOperation,
) throws {
    guard pipe.send(package, timeout: pipePackageTimeout) else {
        throw pipeTimeoutError(operation: operation)
    }
}

private func receivePackage(from pipe: DataPipe, operation: SMB.Error.InvalidArgumentOperation) throws -> DataPipe
.Package {
    guard let package = pipe.receive(timeout: pipePackageTimeout) else {
        throw pipeTimeoutError(operation: operation)
    }
    return package
}

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

/// Consumes pending pipe packages until a terminal package is received.
private func drain(_ pipe: DataPipe) {
    while let package = pipe.receive(timeout: pipePackageTimeout), package != .finish, package != .broken {
    }
}

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
