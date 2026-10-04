//
// Part of SwiftSMB
// Directory-Conv.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

public extension SMB.Directory {
    /// Reads all remaining entries from the directory stream.
    ///
    /// - Returns: The remaining directory entries.
    /// - Throws: ``SMB/Error`` if the directory is closed, or `CancellationError` if the task is cancelled between
    /// entries.
    func readAll() async throws -> [SMB.DirectoryEntry] {
        try await connection.withOperation {
            var entries: [SMB.DirectoryEntry] = []
            while true {
                try Task.checkCancellation()
                guard let entry = try await readNext() else { break }
                entries.append(entry)
            }
            return entries
        }
    }
}
