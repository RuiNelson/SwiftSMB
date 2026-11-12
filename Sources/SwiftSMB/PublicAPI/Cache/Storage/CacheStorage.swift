//
// Part of SwiftSMB
// CacheStorage.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// Where an ``SMB/ReferenceCache`` keeps the bytes of the files it caches.
    ///
    /// The storage holds bytes and nothing else: runs of a file's contents by position, under the ``SMB/CacheFileID``
    /// the cache gave the file. Which bytes are current, which version they belong to, and when they stop being valid
    /// is up to the cache. The storage decides how much it keeps: it may drop the bytes of any file at any time, as
    /// long as it drops whole files, so that a file it holds never has holes the cache did not leave. To the cache, a
    /// file whose bytes are gone is simply not cached.
    ///
    /// ## Calls
    ///
    /// The cache calls these methods synchronously, from its own isolation, and relies on each one finishing before it
    /// does anything else: implementations must not block for long. Local memory or disk is fine; the network is not.
    /// Several caches may share one storage, and a storage may drop bytes on its own, from any thread, so
    /// implementations synchronize access themselves. They cannot throw: a storage that fails behaves as if it held
    /// nothing for the file, which costs a download but never returns wrong bytes.
    protocol CacheStorage: AnyObject, Sendable {
        /// Whether the storage would keep the bytes of a file of `fileSize` bytes.
        ///
        /// The cache neither stores nor hands out bytes of files the storage does not accept.
        ///
        /// - Parameter fileSize: Size of the file.
        /// - Returns: `false` when the storage would not keep the file whole.
        func accepts(fileSize: UInt64) -> Bool

        /// Stores `data` at `offset` of `file`, over any bytes already stored there.
        ///
        /// - Parameters:
        ///   - data: The bytes, of any length.
        ///   - offset: Position of the first byte in the file.
        ///   - file: The file the bytes belong to.
        /// - Returns: `false` when the storage cannot hold what it would hold of `file` with these bytes. It then holds
        /// no byte of `file`, and the cache stops storing the file until its version changes.
        @discardableResult
        func write(_ data: Data, at offset: UInt64, of file: CacheFileID) -> Bool

        /// The stored bytes of `file` starting exactly at `offset`, at most `upTo` of them, counting as a use of the
        /// file.
        ///
        /// - Parameters:
        ///   - file: The file to read.
        ///   - offset: Position of the first byte wanted.
        ///   - upTo: Most bytes wanted.
        /// - Returns: The stored run of bytes starting at `offset`, or `nil` when the byte at `offset` is not stored.
        func read(_ file: CacheFileID, at offset: UInt64, upTo: Int) -> Data?

        /// The ranges of `file` the storage holds, sorted, neither overlapping nor touching.
        ///
        /// - Parameter file: The file.
        /// - Returns: The ranges, or an empty array when the storage holds nothing of `file`.
        func ranges(of file: CacheFileID) -> [Range<UInt64>]

        /// Drops every byte of `file` outside `ranges`.
        ///
        /// - Parameters:
        ///   - ranges: The ranges to keep, sorted, neither overlapping nor touching.
        ///   - file: The file.
        func retain(_ ranges: [Range<UInt64>], of file: CacheFileID)

        /// Drops every byte of `file`.
        ///
        /// - Parameter file: The file.
        func remove(_ file: CacheFileID)
    }
}
