//
// Part of SwiftSMB
// SMBConnection-Conv-Pipe.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

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
    /// This method consumes slots from `pipe` until the producer ends the pipe
    /// or the progress closure returns `false`. Each pipe slot may be split
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
    ///   - continuation: A progress closure called after each SMB write block
    ///     and once after the pipe is drained.
    /// - Throws: ``SMB/Error`` if the connection is closed, the file cannot be
    ///   opened, a write fails, or the server reports that a write made no
    ///   progress.
    func write(
        fromPipe pipe: DataPipe,
        toFile path: String,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [.create, .truncate],
        continuation: @escaping PipeProgress,
    ) throws {
        let file = try openFile(at: path, accessMode: .writeOnly, options: options)
        defer { try? file.close() }

        let blockSize = try acceptedWriteBlockSize()
        var remoteOffset = from.offset
        var transferred: UInt64 = 0
        let operationStart = DispatchTime.now()

        while let slot = pipe.receive({ Data($0) }) {
            var slotOffset = 0
            while slotOffset < slot.count {
                let blockEnd = min(slotOffset + blockSize, slot.count)
                let block = slot.subdata(in: slotOffset ..< blockEnd)
                let blockStart = DispatchTime.now()
                let written = try write(block, to: file, at: remoteOffset)
                guard written > 0 else {
                    throw SMB.Error.unknown(
                        operation: "smb2_write",
                        message: "Write made no progress before all pipe data was written",
                    )
                }

                slotOffset += written
                remoteOffset += UInt64(written)
                transferred += UInt64(written)

                let latestSpeed = speed(bytes: UInt64(written), from: blockStart, to: .now())
                let totalSpeed = speed(bytes: transferred, from: operationStart, to: .now())
                guard continuation(transferred, latestSpeed, totalSpeed) else { return }
            }
        }

        _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
    }

    /// Reads a file from the SMB share into a pipe.
    ///
    /// The method reads from `path` in server-accepted blocks and sends each
    /// block into `pipe`. The pipe is ended before this method returns,
    /// regardless of success, cancellation, or failure.
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
    ///   - continuation: A progress closure called after each SMB read block
    ///     and once after the remote file reaches end-of-file.
    /// - Throws: ``SMB/Error`` if the connection is closed, the file cannot be
    ///   opened, or a read fails.
    func read(
        fromFile path: String,
        toPipe pipe: DataPipe,
        from: FromArgument = .beginning,
        options: SMB.File.OpenOptions = [],
        continuation: @escaping PipeProgress,
    ) throws {
        let file = try openFile(at: path, accessMode: .readOnly, options: options)
        defer {
            try? file.close()
            pipe.endOfProduction()
        }

        let blockSize = try min(acceptedReadBlockSize(), pipe.slotCapacity)
        var remoteOffset = from.offset
        var transferred: UInt64 = 0
        let operationStart = DispatchTime.now()

        while true {
            let blockStart = DispatchTime.now()
            let data = try read(from: file, byteCount: blockSize, at: remoteOffset)
            guard !data.isEmpty else {
                _ = continuation(transferred, 0, speed(bytes: transferred, from: operationStart, to: .now()))
                return
            }

            pipe.send(data)
            remoteOffset += UInt64(data.count)
            transferred += UInt64(data.count)

            let latestSpeed = speed(bytes: UInt64(data.count), from: blockStart, to: .now())
            let totalSpeed = speed(bytes: transferred, from: operationStart, to: .now())
            guard continuation(transferred, latestSpeed, totalSpeed) else { return }
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
        let offset = from.offset
        let stat = try stat(at: remote)
        let total = stat.size
        guard offset <= total else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.downloadFile",
                message: "Offset is beyond the end of the remote file",
            )
        }

        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedReadBlockSize())
        let pipe = DataPipe(totalCapacity: blockSize * 3, slotCount: 3)
        let tempFile = try uniqueTemporaryFileURL()
        var shouldRemoveTemp = true
        defer {
            if shouldRemoveTemp {
                try? FileManager.default.removeItem(at: tempFile)
            }
        }
        var cancelled = false
        let protectedCancelled = SMBProtected(false, label: "SwiftSMB.downloadFile.cancelled")
        let producer = DispatchGroup()
        let producerError = SMBProtected<Swift.Error?>(nil, label: "SwiftSMB.downloadFile.error")

        producer.enter()
        Thread.detachNewThread {
            defer {
                pipe.endOfProduction()
                producer.leave()
            }
            do {
                let file = try self.openFile(at: remote, accessMode: .readOnly, options: options)
                defer { try? file.close() }
                var remoteOffset = offset
                while !protectedCancelled.current {
                    let data = try self.read(from: file, byteCount: blockSize, at: remoteOffset)
                    guard !data.isEmpty else { return }
                    pipe.send(data)
                    remoteOffset += UInt64(data.count)
                }
            }
            catch {
                producerError.current = error
            }
        }

        do {
            try preparePrefix(for: local, into: tempFile, byteCount: offset)
            let handle = try FileHandle(forWritingTo: tempFile)
            defer { try? handle.close() }
            handle.seekToEndOfFile()

            var transferred: UInt64 = 0
            let operationStart = DispatchTime.now()
            while let data = pipe.receive() {
                let blockStart = DispatchTime.now()
                handle.write(data)
                transferred += UInt64(data.count)
                let latestSpeed = speed(bytes: UInt64(data.count), from: blockStart, to: .now())
                let totalSpeed = speed(bytes: transferred, from: operationStart, to: .now())
                guard continuation(transferred, total - offset, latestSpeed, totalSpeed) else {
                    cancelled = true
                    protectedCancelled.current = true
                    drain(pipe)
                    break
                }
            }

            if !cancelled {
                producer.wait()
                if let error = producerError.current { throw error }
                try replaceItem(at: local, with: tempFile)
                shouldRemoveTemp = false
                _ = continuation(
                    transferred,
                    total - offset,
                    0,
                    speed(bytes: transferred, from: operationStart, to: .now()),
                )
            }
        }
        catch {
            protectedCancelled.current = true
            drain(pipe)
            producer.wait()
            throw error
        }

        if cancelled {
            producer.wait()
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
        let offset = from.offset
        let attributes = try FileManager.default.attributesOfItem(atPath: local.path)
        guard let fileSize = attributes[.size] as? UInt64 else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.uploadFile",
                message: "Unable to determine local file size",
            )
        }
        guard offset <= fileSize else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.uploadFile",
                message: "Offset is beyond the end of the local file",
            )
        }

        let target = atomic ? temporaryRemotePath(near: remote) : remote
        let blockSize = try pipeBlockSize(maxBlockSize, acceptedBlockSize: acceptedWriteBlockSize())
        let pipe = DataPipe(totalCapacity: blockSize * 3, slotCount: 3)
        let protectedCancelled = SMBProtected(false, label: "SwiftSMB.uploadFile.cancelled")
        let producer = DispatchGroup()
        let producerError = SMBProtected<Swift.Error?>(nil, label: "SwiftSMB.uploadFile.error")
        var cancelled = false
        var shouldRemoveRemoteTemp = atomic
        defer {
            if shouldRemoveRemoteTemp {
                try? removeFile(at: target)
            }
        }

        if atomic, offset > 0 {
            try copyRemotePrefix(from: remote, to: target, byteCount: offset, blockSize: blockSize)
        }

        producer.enter()
        Thread.detachNewThread {
            defer {
                pipe.endOfProduction()
                producer.leave()
            }
            do {
                let handle = try FileHandle(forReadingFrom: local)
                defer { try? handle.close() }
                handle.seek(toFileOffset: offset)
                while !protectedCancelled.current {
                    let data = handle.readData(ofLength: blockSize)
                    guard !data.isEmpty else { return }
                    pipe.send(data)
                }
            }
            catch {
                producerError.current = error
            }
        }

        do {
            let openOptions: SMB.File.OpenOptions = if atomic {
                offset == 0 ? [.create, .truncate] : []
            }
            else {
                options
            }
            let file = try openFile(at: target, accessMode: .writeOnly, options: openOptions)
            defer { try? file.close() }

            var remoteOffset = offset
            var transferred: UInt64 = 0
            let operationStart = DispatchTime.now()
            while let data = pipe.receive() {
                var dataOffset = 0
                while dataOffset < data.count {
                    let blockEnd = min(dataOffset + blockSize, data.count)
                    let block = data.subdata(in: dataOffset ..< blockEnd)
                    let blockStart = DispatchTime.now()
                    let written = try write(block, to: file, at: remoteOffset)
                    guard written > 0 else {
                        throw SMB.Error.unknown(
                            operation: "smb2_write",
                            message: "Write made no progress before all local data was uploaded",
                        )
                    }
                    dataOffset += written
                    remoteOffset += UInt64(written)
                    transferred += UInt64(written)

                    let latestSpeed = speed(bytes: UInt64(written), from: blockStart, to: .now())
                    let totalSpeed = speed(bytes: transferred, from: operationStart, to: .now())
                    guard continuation(transferred, fileSize - offset, latestSpeed, totalSpeed) else {
                        cancelled = true
                        protectedCancelled.current = true
                        drain(pipe)
                        break
                    }
                }
                if cancelled { break }
            }

            producer.wait()
            if !cancelled, let error = producerError.current { throw error }

            if atomic, !cancelled {
                try file.close()
                try? removeFile(at: remote)
                try rename(from: target, to: remote)
                shouldRemoveRemoteTemp = false
            }
            if !cancelled {
                _ = continuation(
                    transferred,
                    fileSize - offset,
                    0,
                    speed(bytes: transferred, from: operationStart, to: .now()),
                )
            }
        }
        catch {
            protectedCancelled.current = true
            drain(pipe)
            producer.wait()
            throw error
        }
    }
}

private extension SMB.Connection.FromArgument {
    /// The zero-based offset represented by this transfer origin.
    var offset: UInt64 {
        switch self {
        case .beginning:
            0
        case let .offset(byte):
            byte
        }
    }
}

private extension SMB.Connection {
    /// Writes a data block at an absolute remote file offset.
    func write(_ data: Data, to file: SMB.File, at offset: UInt64) throws -> Int {
        try file.write(data, atOffset: offset)
    }

    /// Reads a data block at an absolute remote file offset.
    func read(from file: SMB.File, byteCount: Int, at offset: UInt64) throws -> Data {
        try file.read(upToByteCount: byteCount, atOffset: offset)
    }

    /// Resolves a caller-preferred block size against the server limit.
    func pipeBlockSize(_ preferred: UInt64, acceptedBlockSize: Int) throws -> Int {
        guard preferred > 0, preferred <= UInt64(Int.max) else {
            throw SMB.Error.invalidArgument(
                operation: "SMB.Connection.pipeBlockSize",
                message: "Block size must be greater than zero and fit in Int",
            )
        }
        return min(Int(preferred), acceptedBlockSize)
    }

    /// Calculates bytes per second for an elapsed interval.
    func speed(bytes: UInt64, from start: DispatchTime, to end: DispatchTime) -> Double {
        let elapsed = Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000
        guard elapsed > 0 else { return 0 }
        return Double(bytes) / elapsed
    }

    /// Consumes pending pipe slots until the producer ends the pipe.
    func drain(_ pipe: DataPipe) {
        while pipe.receive() != nil {
        }
    }

    /// Creates an empty temporary file with a unique name.
    func uniqueTemporaryFileURL() throws -> URL {
        while true {
            let candidate = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            if FileManager.default.createFile(atPath: candidate.path, contents: nil) {
                return candidate
            }
        }
    }

    /// Copies the already-downloaded prefix into a temporary destination.
    func preparePrefix(for local: URL, into tempFile: URL, byteCount: UInt64) throws {
        guard byteCount > 0 else { return }

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
    func replaceItem(at destination: URL, with source: URL) throws {
        if FileManager.default.fileExists(atPath: destination.path) {
            _ = try FileManager.default.replaceItemAt(destination, withItemAt: source)
        }
        else {
            let parent = destination.deletingLastPathComponent()
            if !FileManager.default.fileExists(atPath: parent.path) {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            }
            try FileManager.default.moveItem(at: source, to: destination)
        }
    }

    /// Builds a temporary remote path beside the final destination.
    func temporaryRemotePath(near remote: String) -> String {
        let name = UUID().uuidString + ".tmp"
        guard let slash = remote.lastIndex(of: "/") else { return name }
        return String(remote[..<remote.index(after: slash)]) + name
    }

    /// Copies a remote prefix when preparing an atomic resumed upload.
    func copyRemotePrefix(from source: String, to destination: String, byteCount: UInt64, blockSize: Int) throws {
        let input = try openFile(at: source, accessMode: .readOnly)
        defer { try? input.close() }
        let output = try openFile(at: destination, accessMode: .writeOnly, options: [.create, .truncate])
        defer { try? output.close() }

        var copied: UInt64 = 0
        while copied < byteCount {
            let requested = min(blockSize, Int(byteCount - copied))
            let data = try read(from: input, byteCount: requested, at: copied)
            guard !data.isEmpty else {
                throw SMB.Error.invalidArgument(
                    operation: "SMB.Connection.uploadFile",
                    message: "Remote file is shorter than the requested resume offset",
                )
            }
            var dataOffset = 0
            while dataOffset < data.count {
                let written = try write(data.subdata(in: dataOffset ..< data.count), to: output, at: copied)
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
}
