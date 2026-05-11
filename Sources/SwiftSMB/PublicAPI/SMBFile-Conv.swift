//
// Part of SwiftSMB
// SMBFile-Conv.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

public extension SMB.File {
    /// Reads from the current file offset until end of file.
    ///
    /// - Parameter chunkSize: The preferred read block size. Values above
    ///   the server maximum are clamped automatically.
    /// - Returns: All bytes from the current file offset to end of file.
    /// - Throws: ``SMB/Error`` if any read fails.
    func readToEnd(chunkSize: Int? = nil) throws -> Data {
        let resolvedChunkSize = try connection.acceptedReadBlockSize(chunkSize)
        var result = Data()

        while true {
            let chunk = try read(upToByteCount: resolvedChunkSize)
            guard !chunk.isEmpty else { break }
            result.append(chunk)
        }

        return result
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
    func write(_ data: Data, chunkSize: Int? = nil) throws -> Int {
        let resolvedChunkSize = try connection.acceptedWriteBlockSize(chunkSize)
        var written = 0

        while written < data.count {
            let end = min(written + resolvedChunkSize, data.count)
            let count = try _write(data.subdata(in: written ..< end))
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
}
