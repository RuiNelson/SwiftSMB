//
// Part of SwiftSMB
// ReferenceCache+Configuration.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB.ReferenceCache {
    /// How an ``SMB/ReferenceCache`` caches blocks, checks them against the server, matches paths, and answers metadata
    /// lookups.
    ///
    /// How many bytes are kept is up to the cache's ``SMB/CacheStorage``.
    struct Configuration: Equatable, CustomDebugStringConvertible, Sendable {
        /// Whether bytes written through the connection are kept, so reading them back needs no download.
        ///
        /// When `false`, a write drops the cached blocks of the file it writes to.
        public var keepsUploads: Bool

        /// What the cache does, beyond comparing every stat and listing it sees, to make sure cached blocks still match
        /// the server.
        public var trustPolicy: TrustPolicy

        /// How long a check by ``trustPolicy`` stays good, or `nil` to check again only after the next stat of the
        /// file.
        ///
        /// Before answering a read of a file whose last check is older than this, the cache checks the file again. With
        /// `nil`, the cache checks a file once after each stat of it, which the connection makes when it opens the file
        /// for reading, so roughly once per open. A file kept open is then not checked again until it is opened anew.
        ///
        /// The default, 30 seconds, bounds how long a file kept open goes unchecked, at the cost of one check per file
        /// every 30 seconds of reading. Ignored by ``TrustPolicy/trustReports``.
        public var revalidationInterval: TimeInterval?

        /// Whether the cache answers stats and directory listings itself.
        public var metadata: MetadataPolicy

        /// How the cache tells whether two paths name the same file.
        public var pathMatching: PathMatching

        /// Creates a configuration.
        ///
        /// - Parameters:
        ///   - keepsUploads: Whether written bytes are kept. `true` by default.
        ///   - trustPolicy: Checks made against the server. ``TrustPolicy/trustReports`` by default.
        ///   - revalidationInterval: How long a check stays good, or `nil` to check after each stat. 30 seconds by
        /// default.
        ///   - metadata: Whether stats and listings are answered from the cache. ``MetadataPolicy/neverAnswer`` by
        /// default.
        ///   - pathMatching: How paths are matched to cached files. ``PathMatching/exact`` by default.
        public init(
            keepsUploads: Bool = true,
            trustPolicy: TrustPolicy = .trustReports,
            revalidationInterval: TimeInterval? = 30,
            metadata: MetadataPolicy = .neverAnswer,
            pathMatching: PathMatching = .exact
        ) {
            self.keepsUploads = keepsUploads
            self.trustPolicy = trustPolicy
            self.revalidationInterval = revalidationInterval
            self.metadata = metadata
            self.pathMatching = pathMatching
        }

        public var debugDescription: String {
            "SMB.ReferenceCache.Configuration(keepsUploads: \(keepsUploads), trustPolicy: \(trustPolicy.debugDescription), revalidationInterval: \(String(describing: revalidationInterval)), metadata: \(metadata.debugDescription), pathMatching: \(pathMatching.debugDescription))"
        }
    }

    /// What an ``SMB/ReferenceCache`` does to make sure cached blocks still match the file on the server.
    ///
    /// Whatever the policy, the cache compares every stat and directory listing the connection makes, and the final
    /// stat the connection makes when it closes a file it wrote, with the size, last write time
    /// (``SMB/Stat/modificationTime``), and change time (``SMB/Stat/changeTime``) of the version its blocks came from,
    /// and drops the blocks of a file that no longer matches. It also drops what the connection reports as changed.
    /// That costs nothing. SMB servers keep times in 100-nanosecond units and `libsmb2` reports them to the
    /// microsecond, so two versions of a file rarely look alike, though a server may update the times of a file another
    /// client is writing only when that client closes it. Without a check, changes made by anything else while a file
    /// stays open go unnoticed, since nothing stats the file then.
    ///
    /// The other policies add checks over the cache's control connection, before the cache answers a read with cached
    /// bytes of a file that ``Configuration/revalidationInterval`` says is due for one. A file that fails a check,
    /// because it changed, disappeared, or the check itself failed, loses its cached blocks, and the read goes to the
    /// server; a check that finds a new version treats it like any other stat, keeping what the connection wrote since
    /// the previous one. Only one check of a file runs at a time; reads of the file wait for it.
    enum TrustPolicy: Equatable, CustomDebugStringConvertible, Sendable {
        /// Relies on the stats, listings, and change reports the connection makes. Needs no control connection.
        case trustReports

        /// Also stats the file on the server, comparing its size, last write time, and change time.
        ///
        /// One round trip per check. Notices changes to a file that stays open, as soon as the server updates its
        /// times. Every stat the connection reports counts as a check too, so with a `nil`
        /// ``Configuration/revalidationInterval`` this only adds a stat of a file written through the connection before
        /// the connection's own final stat of it.
        case statOnServer

        /// Also stats the file on the server, as ``statOnServer`` does, then reads `count` cached blocks again and
        /// compares their bytes.
        ///
        /// The blocks come from a grid that divides the file into the fewest equal blocks of at most 16 KiB, the way
        /// ``SMB/Connection/compareFiles(_:_:scan:maximumBlockSize:minimumCoverage:)`` divides files. Only blocks the
        /// cache holds whole are compared, in `scan` order. Each check of a file picks up where the previous one
        /// stopped, and starts over once every cached block has been compared, so a file checked often enough is
        /// eventually compared in full.
        ///
        /// A few round trips per check: opening the file, the stat, one read per block, and closing it. Notices a
        /// change that keeps the size and times only where a block lands, so it suits files rewritten as a whole, or
        /// whose changes span much of the cached contents.
        ///
        /// - Parameters:
        ///   - count: Blocks compared per check. Must be greater than zero.
        ///   - scan: The order in which blocks are picked. ``SMB/FileCompareScan/bisection`` by default, which spreads
        /// the first checks across the file.
        case sampleBlocks(count: Int, scan: SMB.FileCompareScan = .bisection)

        public var debugDescription: String {
            switch self {
            case .trustReports:
                "SMB.ReferenceCache.TrustPolicy.trustReports"
            case .statOnServer:
                "SMB.ReferenceCache.TrustPolicy.statOnServer"
            case let .sampleBlocks(count, scan):
                "SMB.ReferenceCache.TrustPolicy.sampleBlocks(count: \(count), scan: \(scan.debugDescription))"
            }
        }
    }

    /// Whether an ``SMB/ReferenceCache`` answers stats and directory listings itself.
    enum MetadataPolicy: Equatable, CustomDebugStringConvertible, Sendable {
        /// Never answers: every stat and listing goes to the server.
        ///
        /// Stats and listings made through the connection still compare the files they show with the versions whose
        /// blocks are cached.
        case neverAnswer

        /// Answers stats and listings from what the connection stored in the last `for` seconds.
        ///
        /// A stat is answered from a stored stat of the same path, or from a stored listing of its parent directory,
        /// unless the listed entry is a symbolic link. Changes made by anything other than the connection and its forks
        /// go unnoticed by answered stats and listings for up to `for` seconds. Opening a file for reading still stats
        /// the open file on the server, whatever the cache answers, so the file's cached blocks are compared with it as
        /// with ``neverAnswer``.
        ///
        /// - Parameters:
        ///   - for: Seconds a stored stat or listing is used for.
        ///   - includingMissing: Whether to answer that nothing exists at a path. A stale answer makes the connection
        /// act as if an item that is in fact there were missing: ``SMB/Connection/itemExists(at:)``, for one, then
        /// returns ``SMB/ItemExistence/false``.
        case answer(for: TimeInterval, includingMissing: Bool)

        public var debugDescription: String {
            switch self {
            case .neverAnswer:
                "SMB.ReferenceCache.MetadataPolicy.neverAnswer"
            case let .answer(maximumAge, includingMissing):
                "SMB.ReferenceCache.MetadataPolicy.answer(for: \(maximumAge), includingMissing: \(includingMissing))"
            }
        }
    }

    /// How an ``SMB/ReferenceCache`` tells whether two paths name the same file.
    ///
    /// Most SMB shares ignore case in names, and some servers, such as macOS, also ignore differences in Unicode
    /// normalization, while Windows and Samba compare those bytes. The cache cannot ask the share which rules it
    /// follows, so it lets you choose.
    enum PathMatching: Equatable, CustomDebugStringConvertible, Sendable {
        /// Matches paths byte by byte, but lets a change reach every path that may name the same file.
        ///
        /// A file read under `Photos/A.jpg` and under `photos/a.jpg` is cached twice, once per path. A change reported
        /// under any path drops what is cached under every path that differs from it only in case or in Unicode
        /// normalization, so the cache is never left with stale bytes, whatever rules the share follows. Correct on
        /// every share.
        case exact

        /// Matches paths without regard to case, so a file read under `Photos/A.jpg` and under `photos/a.jpg` shares
        /// one cache entry.
        ///
        /// Names are compared with the simple, character-by-character case folding SMB servers use, without Unicode
        /// normalization: names that differ in normalization are still different entries, and a change to one still
        /// drops the others, as with ``exact``. Use this only on shares that ignore case, as most do: on a
        /// case-sensitive share, `A.jpg` and `a.jpg` are different files, and the cache could answer a read of one with
        /// the bytes of the other.
        case caseInsensitive

        public var debugDescription: String {
            switch self {
            case .exact: "SMB.ReferenceCache.PathMatching.exact"
            case .caseInsensitive: "SMB.ReferenceCache.PathMatching.caseInsensitive"
            }
        }
    }
}

// MARK: Internal

extension SMB.ReferenceCache.Configuration {
    /// Whether the configuration needs a control connection to the server.
    var needsControlConnection: Bool {
        trustPolicy != .trustReports
    }

    /// Checks the values that have a valid range.
    func validate() {
        if let revalidationInterval {
            precondition(revalidationInterval >= 0, "revalidationInterval must not be negative")
        }
        if case let .sampleBlocks(count, _) = trustPolicy {
            precondition(count > 0, "sampleBlocks needs a count greater than zero")
        }
        if case let .answer(maximumAge, _) = metadata {
            precondition(maximumAge >= 0, "The metadata answer interval must not be negative")
        }
    }
}

extension SMB.ReferenceCache {
    /// Longest block compared by one sample of ``TrustPolicy/sampleBlocks(count:scan:)``.
    static let sampleLength: UInt64 = 16 * 1024
}
