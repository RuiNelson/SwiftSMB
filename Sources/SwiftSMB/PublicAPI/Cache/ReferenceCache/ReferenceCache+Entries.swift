//
// Part of SwiftSMB
// ReferenceCache+Entries.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

extension SMB.ReferenceCache {
    /// What the cache knows about one file.
    struct FileEntry {
        /// Tells this entry apart from one created later at the same key, and names its bytes in the storage.
        let id: SMB.CacheFileID

        /// The normalized path the file was last reported under, which the checks send to the server.
        var path: String

        /// ``CachePath/equivalenceKey(_:)`` of ``path``, under which the entry is filed for changes to equivalent
        /// paths.
        var equivalenceKey: String

        /// Ranges written through the connection since the last stat, sorted and merged. They belong to whatever
        /// version the next stat shows, so a new version keeps the bytes the storage still holds in them.
        var uploaded: [Range<UInt64>] = []

        /// The version the blocks came from, from the last stat or listing; `nil` before the first.
        var version: FileVersion?

        /// Size the file last had: the stat's, grown by writes through the connection since. Bytes at or past it are
        /// neither stored nor handed out.
        var knownSize: UInt64?

        /// Value of ``SMB/ReferenceCache/tick`` at the last use, for dropping the least recently used files past
        /// ``SMB/ReferenceCache/entryLimit``.
        var lastUsed: UInt64

        /// Bytes the connection appended since the last stat, or `nil` when it appended none.
        var appends: Appends?

        /// Uptime of the last check against the server, or `nil` before the first.
        var lastCheck: TimeInterval?

        /// Whether a stat arrived since the last check.
        var statSinceCheck: Bool

        /// Where the next ``TrustPolicy/sampleBlocks(count:scan:)`` check picks up, as a position in the block order of
        /// the file's grid.
        var sampleCursor: UInt64 = 0

        /// Changes whenever the blocks stop matching what a check in flight looked at: dropped, rewritten, or moved.
        var contentEpoch: UInt64 = 0

        /// Whether the storage could not hold the file, so it is not cached until its version changes.
        var isTooLarge = false

        init(
            id: SMB.CacheFileID,
            path: String,
            version: FileVersion?,
            knownSize: UInt64?,
            lastUsed: UInt64,
            lastCheck: TimeInterval?,
            statSinceCheck: Bool
        ) {
            self.id = id
            self.path = path
            equivalenceKey = CachePath.equivalenceKey(path)
            self.version = version
            self.knownSize = knownSize
            self.lastUsed = lastUsed
            self.lastCheck = lastCheck
            self.statSinceCheck = statSinceCheck
        }
    }

    /// Bytes the connection appended to a file since its last stat, which leave the bytes before them as they were.
    struct Appends {
        /// The size the file had before the first of them, or `nil` when unknown.
        let base: UInt64?
        /// Bytes appended.
        var byteCount: UInt64
    }

    /// The size, last write time, and change time of a version of a file.
    struct FileVersion: Equatable {
        let size: UInt64
        let modificationSeconds: UInt64
        let modificationNanoseconds: UInt64
        let changeSeconds: UInt64
        let changeNanoseconds: UInt64

        init(_ stat: SMB.Stat) {
            size = stat.size
            modificationSeconds = stat.modificationTimeSeconds
            modificationNanoseconds = stat.modificationTimeNanoseconds
            changeSeconds = stat.changeTimeSeconds
            changeNanoseconds = stat.changeTimeNanoseconds
        }

        /// Whether both versions are known to be the same.
        func isSame(as other: FileVersion?) -> Bool {
            self == other
        }
    }

    struct StoredStat {
        /// The stat's result, or `nil` when nothing existed at the path.
        let stat: SMB.Stat?
        /// ``CachePath/equivalenceKey(_:)`` of the path.
        let equivalenceKey: String
        /// Uptime when it was stored.
        let time: TimeInterval
    }

    /// What a listing says about one key.
    enum ListedEntry {
        /// The entry, the only one listed under the key.
        case entry(SMB.Stat)
        /// Several entries the key does not tell apart, as names that differ only in case with
        /// ``PathMatching/caseInsensitive``: the listing answers for none of them.
        case ambiguous
    }

    struct StoredListing {
        let entries: [SMB.DirectoryEntry]
        /// What the listing says about each child, by key.
        let byKey: [String: ListedEntry]
        /// The listed children, by ``CachePath/equivalenceKey(_:)``.
        let byEquivalenceKey: [String: [SMB.Stat]]
        /// ``CachePath/equivalenceKey(_:)`` of the directory.
        let equivalenceKey: String
        /// Uptime when it was stored.
        let time: TimeInterval
    }

    struct RunningCheck {
        let token: UInt64
        let task: Task<Void, Never>
    }
}
