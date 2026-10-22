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

    /// Returns a Boolean value indicating whether any of the remaining entries in the directory stream satisfies the
    /// given predicate.
    ///
    /// Like ``readAll()``, the method reads from the current position of the directory stream. It stops at the first
    /// entry that satisfies `predicate`, so the stream continues after that entry; otherwise the stream is exhausted.
    /// Use ``tell()`` and ``seek(to:)``, or ``rewind()``, to read the entries again.
    ///
    /// - Parameter predicate: A closure that takes a directory entry and returns whether it matches.
    /// - Returns: `true` if an entry satisfies `predicate`; otherwise, `false`.
    /// - Throws: ``SMB/Error`` if the directory is closed, `CancellationError` if the task is cancelled between
    /// entries, or the error thrown by `predicate`.
    nonisolated(nonsending) func contains(
        where predicate: (SMB.DirectoryEntry) throws -> Bool
    ) async throws -> Bool {
        try await connection.withOperation {
            while true {
                try Task.checkCancellation()
                guard let entry = try await readNext() else { return false }
                if try predicate(entry) {
                    return true
                }
            }
        }
    }
}
