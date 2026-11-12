//
// Part of SwiftSMB
// BlockLevelReadCache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// A cache that an ``SMB/Connection`` consults before going to the server and keeps informed of what it reads,
    /// writes, and changes.
    ///
    /// Attach a cache with ``SMB/Connection/attachCache(_:)``. The connection only reports what happened. Every policy
    /// belongs to the implementation: where data is stored, which blocks are kept, and when cached data stops being
    /// valid. An implementation may check cached data against the server through a connection of its own; see
    /// ``SMB/Connection/attachCache(_:)`` for how to set one up.
    ///
    /// One cache object serves one share. An implementation that keeps data for several shares hands each connection
    /// its own object, and those objects may share storage.
    ///
    /// ## Calls
    ///
    /// The connection calls these methods from the tasks that run its operations, never on its own serial queue,
    /// possibly at the same time from several open files and from connections forked from it. They cannot throw: a
    /// cache that fails behaves as if it had nothing cached, and its failures never fail an SMB operation.
    ///
    /// ## Requests
    ///
    /// Every lookup starts a request with an identifier of its own: ``retrieveBlock(path:offset:upTo:request:)``,
    /// ``retrieveStat(path:request:)``, and ``retrieveDirectoryListing(path:request:)``. When the cache does not
    /// answer,
    /// or answers only part of a read, the connection asks the server and hands over the answer with a store call that
    /// carries the same identifier. A stat of a file the connection has open starts its request with
    /// ``beginRequest(_:)`` instead, since the connection asks the server whatever the cache holds. Then the connection
    /// calls ``requestEnded(_:)`` for that identifier exactly once, after the store if there was one, however the
    /// request ended: answered by the cache, stored, at the end of the file, failed, or cancelled.
    ///
    /// Calls of one request arrive in that order, but calls of different requests interleave freely: a request's store
    /// can arrive after an ``invalidate(path:)`` or ``didRename(from:to:)`` for the same path, reported by another task
    /// while the server answered. The answer may then describe the path as it was before that change. A cache that
    /// keeps answers tells such a store apart by what changed at the path between the request's lookup and its store,
    /// and refuses it.
    ///
    /// Reports of changes carry no identifier: bytes the connection wrote, and appends. The connection hands those over
    /// once the server answered. A change at the file's path, or at a path that differs from it only in case or in
    /// Unicode normalization, that the connection or one of its forks reports while such a call is on its way, from its
    /// start to the end of its report, may leave the report describing the file as it was before that change. The
    /// connection then follows the report with ``invalidate(path:)``: after written bytes, for changes other than
    /// writes, and for writes through another handle to bytes it also wrote; after appends, for any other change. A
    /// stat of an open file that such a change overlaps is followed by
    /// ``invalidate(path:)`` too, for any change, another write to the file included.
    ///
    /// ## Paths
    ///
    /// Paths arrive as the connection sends them to the server, after validation: relative to the share root, with `/`
    /// separators, and without a leading `/` or `.` components. The share root is the empty string.
    ///
    /// The same file can arrive under different paths. Most SMB servers compare names without regard to case, so
    /// `Photos/A.jpg` and `photos/a.JPG` usually name the same file, though a share can be case-sensitive. Whether
    /// names
    /// that differ only in Unicode normalization name the same file depends on the server: Windows and Samba compare
    /// their bytes, macOS compares them as equal. `String` compares such names as equal in `==` and as dictionary keys,
    /// so an implementation that must tell them apart compares their bytes. A file can also be reached through a
    /// symbolic link, or through several hard links (``SMB/Stat/linkCount`` above one), and the connection reports a
    /// change only under the path it made the change through.
    ///
    /// A file renamed through the connection, or one of its forks, while open reports from then on under its new path,
    /// if it was renamed by the path it was opened with or by a directory above it. A file that a call through the
    /// connection or one of its forks deleted while open, or may have, stops reporting: the connection neither asks the
    /// cache about it nor hands over anything about it from then on, except that a change through it, which may still
    /// reach a file a path leads to, is reported with ``invalidate(path:)`` for every path the file may be at. That
    /// covers deletes, deletes and renames whose call fails, and renames and deletes of the path while the file is
    /// being opened. A read or a report of the file on its way while it is renamed or deleted may reach the cache under
    /// the path the file left; the connection then calls ``invalidate(path:)`` for that path, and for the file's new
    /// path after a rename, and does not use what the cache answered. Renames and deletes reach open files only by the
    /// paths they were opened with, compared byte by byte: not through symbolic links, hard links, or names that differ
    /// only in case.
    ///
    /// SwiftSMB opens files without delete sharing, so servers normally refuse to rename or delete a file that is open,
    /// or a directory above it. The connection does not rely on that.
    ///
    /// ## Changes
    ///
    /// The connection reports every change it makes. Two changes to related paths, such as a rename and a size change
    /// of the file it renames, may reach the cache in the other order than the server applied them. The connection then
    /// follows the later report with ``invalidate(path:)`` for the paths either change may have left wrong, the paths a
    /// rename moved them to included.
    ///
    /// A change whose call fails may still have happened on the server: a timeout, a cancellation, or a lost connection
    /// can come after the server applied it. The connection reports those too, with ``invalidate(path:)`` for every
    /// path the call may have changed, both paths of a move. A request that `libsmb2` gave up on after the command
    /// timeout may still reach the server later, after the report; only checks against the server notice such a change.
    ///
    /// Changes made on the server by anything other than this connection and its forks are not reported.
    protocol BlockLevelReadCache: Sendable {
        // MARK: Blocks

        /// Hands over bytes the connection read from, or wrote to, the file at `path`.
        ///
        /// Downloaded bytes come with the request whose ``retrieveBlock(path:offset:upTo:request:)`` they complete.
        /// Written bytes come without a request, once the server has acknowledged them, including the acknowledged part
        /// of a write that fails or is cancelled. Such a write may have sent bytes the server has not acknowledged, so
        /// the connection first calls ``invalidate(path:)``. Bytes written with
        /// ``SMB/File/write(_:transferChunkSize:)`` to a file opened with ``SMB/File/OpenOptions/append`` are not
        /// handed over, since the server decides where they land; the connection reports them with
        /// ``didAppend(path:byteCount:)``.
        ///
        /// - Parameters:
        ///   - data: The bytes, of any length.
        ///   - path: Share-relative path of the file.
        ///   - offset: Position of the first byte in the file.
        ///   - source: Whether the bytes were downloaded or uploaded.
        ///   - request: The request the bytes were downloaded for, or `nil` for uploaded bytes.
        func storeBlock(
            _ data: Data,
            path: String,
            offset: UInt64,
            source: CacheBlockSource,
            request: CacheRequestID?
        ) async

        /// Returns cached bytes of the file at `path` starting exactly at `offset`, or `nil` to have the connection
        /// read them from the server.
        ///
        /// The cache may return fewer than `upTo` bytes, and the connection reads the rest from the server, then hands
        /// them over with ``storeBlock(_:path:offset:source:request:)`` under the same `request`. Bytes past `upTo` are
        /// ignored. The connection asks only for files it opened with ``SMB/File/AccessMode/readOnly`` or
        /// ``SMB/File/AccessMode/readWrite``.
        ///
        /// - Parameters:
        ///   - path: Share-relative path of the file.
        ///   - offset: Position in the file of the first byte wanted.
        ///   - upTo: Most bytes wanted.
        ///   - request: The request this lookup starts.
        /// - Returns: Bytes starting at `offset`, or `nil`.
        func retrieveBlock(path: String, offset: UInt64, upTo: Int, request: CacheRequestID) async -> Data?

        // MARK: Metadata

        /// Hands over the result of a stat on `path`.
        ///
        /// A stat the connection made because ``retrieveStat(path:request:)`` did not answer, for
        /// ``SMB/Connection/stat(at:)`` or ``SMB/Connection/itemExists(at:)``, comes with that request. A stat of a
        /// file
        /// the connection has open comes with the request ``beginRequest(_:)`` started before the connection asked the
        /// server: the connection makes one when it opens a file with ``SMB/File/AccessMode/readOnly`` or
        /// ``SMB/File/AccessMode/readWrite``, and for every ``SMB/File/stat()``. Before closing a file it wrote to, the
        /// connection stats it that way and reports the result here, describing the file the written blocks belong to;
        /// when that stat is skipped, because the connection is closed, or fails, it calls ``invalidate(path:)``
        /// instead.
        ///
        /// A stat by path, like opening a file, follows a symbolic link at `path` when the server resolves it.
        ///
        /// - Parameters:
        ///   - result: Metadata of the entry, or `nil` when nothing exists at `path`.
        ///   - path: Share-relative path that was stat'ed.
        ///   - request: The request the stat answers.
        func storeStat(_ result: Stat?, path: String, request: CacheRequestID) async

        /// Hands over the entries of a directory listing of `path`, made for ``SMB/Connection/listDirectory(at:)``
        /// because ``retrieveDirectoryListing(path:request:)`` did not answer.
        ///
        /// Directories read through an ``SMB/Directory`` handle are neither looked up nor handed over.
        ///
        /// - Parameters:
        ///   - entries: The entries listed, in the order the server returned them, `.` and `..` included when the
        /// server lists them. Entries whose names differ only in Unicode normalization are different entries. The entry
        /// of a symbolic link describes the link itself, while a stat of its path may describe what it leads to, so a
        /// cache that answers stats from listings does not answer one from such an entry.
        ///   - path: Share-relative path of the directory.
        ///   - request: The request the listing answers.
        func storeDirectoryListing(_ entries: [DirectoryEntry], path: String, request: CacheRequestID) async

        /// Answers a stat on `path` from the cache.
        ///
        /// - Parameters:
        ///   - path: Share-relative path to stat.
        ///   - request: The request this lookup starts.
        /// - Returns: The cached answer, or `nil` to have the connection ask the server and hand over its answer with
        /// ``storeStat(_:path:request:)``.
        func retrieveStat(path: String, request: CacheRequestID) async -> CachedStat?

        /// Answers a directory listing of `path` from the cache.
        ///
        /// - Parameters:
        ///   - path: Share-relative path of the directory.
        ///   - request: The request this lookup starts.
        /// - Returns: The cached entries, or `nil` to have the connection ask the server and hand over its answer with
        /// ``storeDirectoryListing(_:path:request:)``.
        func retrieveDirectoryListing(path: String, request: CacheRequestID) async -> [DirectoryEntry]?

        /// Starts a request that no lookup starts: the connection is about to ask the server for the metadata of a file
        /// it has open, and hands it over with ``storeStat(_:path:request:)`` under `request`.
        ///
        /// - Parameter request: The request this call starts.
        func beginRequest(_ request: CacheRequestID) async

        /// Reports that `request` is over: no store for it follows.
        ///
        /// Called exactly once for every request a lookup or ``beginRequest(_:)`` started, after its store if there was
        /// one, whether the request was answered by the cache, stored, reached the end of the file, failed, or was
        /// cancelled.
        ///
        /// - Parameter request: The request that ended.
        func requestEnded(_ request: CacheRequestID) async

        // MARK: Changes

        /// Reports that the server renamed `from` to `to`, through ``SMB/Connection/move(from:to:)``.
        ///
        /// Called only after the server confirmed the rename. `from` may be a directory, in which case everything under
        /// it moved too. SwiftSMB never asks the server to replace an existing entry, so nothing was at `to` before,
        /// unless `from` and `to` name the same entry, as in a rename that changes only the case of a name on a share
        /// that ignores case. `from` and `to` may even be the same string: a share that ignores case may have kept the
        /// entry under another spelling, which the rename changes to the one `to` has. A rename that fails is reported
        /// with ``invalidate(path:)`` on both paths instead, since it may still have happened.
        ///
        /// - Parameters:
        ///   - from: Share-relative path before the rename.
        ///   - to: Share-relative path after the rename.
        func didRename(from: String, to: String) async

        /// Reports that the connection appended bytes to the file at `path`, which it opened with
        /// ``SMB/File/OpenOptions/append``.
        ///
        /// The server put the bytes at the end of the file, wherever that was, so the bytes already in the file are
        /// unchanged, while its size and modification time are not. A write that fails may have appended more than
        /// `byteCount` bytes.
        ///
        /// - Parameters:
        ///   - path: Share-relative path of the file.
        ///   - byteCount: Bytes the server acknowledged.
        func didAppend(path: String, byteCount: UInt64) async

        /// Reports that the contents, attributes, or existence of `path` changed through the connection, or may have.
        ///
        /// Covers `path`, everything under it, and the listing of its parent directory. The connection calls this after
        /// deletes, truncations, changes of timestamps, attributes, or security descriptors, server-side copies onto
        /// `path`, directory and link creation (hard links included), and writes that fail with bytes the server has
        /// not acknowledged, and when it opens a file with ``SMB/File/OpenOptions/create`` or
        /// ``SMB/File/OpenOptions/truncate``. It calls this for those changes also when their call fails, and for both
        /// paths of a move whose call fails, since the server may have applied the change anyway. It also calls this
        /// when the final stat of a written file is skipped or fails, and after a read or a report of an open file that
        /// a rename, a delete, or another change overlapped; see ``SMB/BlockLevelReadCache``.
        ///
        /// - Parameter path: Share-relative path that changed.
        func invalidate(path: String) async
    }
}
