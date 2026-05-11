//
// Part of SwiftSMB
// Directory-Conv.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

public extension SMB.Directory {
    /// Reads all remaining entries from the directory stream.
    ///
    /// - Returns: The remaining directory entries.
    /// - Throws: ``SMB/Error`` if the directory is closed.
    func readAll() throws -> [SMB.DirectoryEntry] {
        var entries: [SMB.DirectoryEntry] = []
        while let entry = try readNext() {
            entries.append(entry)
        }
        return entries
    }
}
