//
// Part of SwiftSMB
// File-Cache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation

// MARK: Cache reports

extension SMB.File {
    /// Whether reads consult the cache: the file uses one, and was opened for reading. A file not opened for reading
    /// fails its reads at the server, whatever the cache holds.
    var consultsCache: Bool {
        cacheAttachment != nil && registration != nil && accessMode != .writeOnly
    }

    /// The path the file reports to the cache under, which follows renames through the connection and its forks, or
    /// `nil` when the file uses no cache or stopped reporting: it closed, or was deleted or replaced while open.
    var cachePath: String? {
        registration.flatMap { cacheAttachment?.openFiles.path(of: $0) }
    }

    /// The changes counted against the file so far, taken before a server call whose answer the file reports, or `nil`
    /// when it reports nothing; see ``OpenFileRegistry``.
    var changeSnapshot: OpenFileRegistry.ChangeCounts? {
        registration.flatMap { cacheAttachment?.openFiles.changeCounts(of: $0) }
    }

    /// Hands the cache a report about the file, under the path it has now.
    ///
    /// A rename or a delete of the file through the connection or a fork can overlap the report, which may then land
    /// under a path the file has left. Another change at the file's path, reported through the connection or a fork
    /// after `snapshot` was taken, can make the report describe the file as it was before that change. The paths the
    /// report may have reached wrongly either way are invalidated afterwards.
    ///
    /// A change through a file that stopped reporting is reported as invalidations of the paths it may still be at.
    ///
    /// - Parameters:
    ///   - kind: What the report is about.
    ///   - snapshot: ``changeSnapshot`` before the server call the report is about, or `nil` for a report about no
    /// server answer.
    ///   - range: For a write, the bytes it wrote, or `nil` when the server decides where they land.
    ///   - body: Makes the report, given the cache and the path.
    nonisolated(nonsending) func report(
        _ kind: OpenFileRegistry.ReportKind,
        since snapshot: OpenFileRegistry.ChangeCounts? = nil,
        range: Range<UInt64>? = nil,
        _ body: (any SMB.BlockLevelReadCache, String) async -> Void
    ) async {
        guard let cacheAttachment, let registration,
              let ticket = cacheAttachment.openFiles.beginReport(registration, kind, since: snapshot, range: range) else {
            return
        }

        if ticket.reports {
            await body(cacheAttachment.cache, ticket.path)
        }
        else {
            await cacheAttachment.invalidate(ticket.paths)
        }
        await endReport(ticket)
    }

    /// Ends a report of the file, invalidating the paths a rename, a delete, or another change that overlapped it may
    /// have left wrong.
    func endReport(_ ticket: OpenFileRegistry.ReportTicket) async {
        guard let cacheAttachment, let registration else {
            return
        }
        await cacheAttachment.invalidate(cacheAttachment.openFiles.endReport(registration, ticket))
    }

    /// Reports that the file's contents or metadata changed through the handle, or may have.
    func reportContentsChange() async {
        // Counted as a change, so reports of the file that it overlapped are invalidated too.
        await report(.attributes) { cache, path in
            await cache.invalidate(path: path)
        }
    }

    /// Hands the cache the bytes a write acknowledged, after invalidating the file when bytes the server did not
    /// acknowledge may still have reached it. Appends report only how many bytes they appended.
    ///
    /// - Parameters:
    ///   - data: The bytes the write was given.
    ///   - offset: Where the write started in the file, or `nil` when it appends or the file uses no cache.
    ///   - appends: Whether the server decided where the bytes landed.
    ///   - acknowledged: Bytes the server acknowledged, from the start of `data`.
    ///   - inFlight: Bytes after those, handed to a call that failed, which may have reached the file.
    ///   - snapshot: ``changeSnapshot`` before the write began.
    func reportWrite(
        _ data: Data,
        at offset: UInt64?,
        appends: Bool,
        acknowledged: Int,
        inFlight: Int,
        since snapshot: OpenFileRegistry.ChangeCounts?
    ) async {
        guard cacheAttachment != nil, acknowledged > 0 || inFlight > 0 else {
            return
        }

        // The bytes the write may have reached: unknown for an append, where the server decides.
        let reach = UInt64(acknowledged + inFlight)
        let range: Range<UInt64>? = if appends {
            nil
        }
        else if let offset {
            offset.addingReportingOverflow(reach).overflow ? offset ..< .max : offset ..< offset + reach
        }
        else {
            0 ..< .max
        }

        await report(.write, since: snapshot, range: range) { cache, path in
            if appends {
                // The server decides where the bytes land, so their offset is unknown, while the bytes already in the
                // file stay as they were.
                await cache.didAppend(path: path, byteCount: UInt64(acknowledged))
                return
            }

            // Bytes the server did not acknowledge may land over whatever the cache holds for their range.
            if inFlight > 0 {
                await cache.invalidate(path: path)
            }

            // Acknowledged bytes are in the file whatever went wrong after them.
            if acknowledged > 0, let offset {
                let start = data.startIndex
                await cache.storeBlock(
                    data.subdata(in: start ..< start + acknowledged),
                    path: path,
                    offset: offset,
                    source: .upload,
                    request: nil
                )
            }
        }
    }
}

// MARK: Reads

extension SMB.File {
    /// Reads up to `upTo` bytes starting at `offset`: what the cache has from there on, then the rest from the server,
    /// handing those bytes to the cache. Reads from the server only when the file does not consult the cache.
    ///
    /// - Returns: The bytes read, shorter than `upTo` at the end of the file.
    func readThroughCache(
        upTo: Int,
        atOffset offset: UInt64,
        chunkSize: Int,
        context: Bridge.Context,
        handle: Bridge.FileHandle
    ) async throws -> Data {
        // A rename or a delete of the file while the read is on its way can leave its bytes under a path it has left.
        guard consultsCache, let cacheAttachment, let registration,
              let ticket = cacheAttachment.openFiles.beginReport(registration, .read, since: nil) else {
            return try await readFromServer(
                upTo: upTo,
                atOffset: offset,
                chunkSize: chunkSize,
                context: context,
                handle: handle
            )
        }

        let cache = cacheAttachment.cache
        let openFiles = cacheAttachment.openFiles
        let result: Result<Data, any Error>
        do {
            result = try await .success(connection.withCacheRequest(on: cache) { request in
                let path = ticket.path
                var cached = await cache.retrieveBlock(path: path, offset: offset, upTo: upTo, request: request)
                    .map { Data($0.prefix(upTo)) } ?? Data()

                // The cache answered for what the path leads to. Renamed or deleted since the read began, the file may
                // no longer be there: its bytes come from the server then, and do not go to the cache.
                let isCurrent = openFiles.isCurrent(registration, ticket)
                if !isCurrent {
                    cached = Data()
                }

                let (resume, overflow) = offset.addingReportingOverflow(UInt64(cached.count))
                guard cached.count < upTo, !overflow else {
                    return cached
                }

                let fetched = try await readFromServer(
                    upTo: upTo - cached.count,
                    atOffset: resume,
                    chunkSize: chunkSize,
                    context: context,
                    handle: handle
                )
                if isCurrent, !fetched.isEmpty {
                    await cache.storeBlock(fetched, path: path, offset: resume, source: .download, request: request)
                }
                return cached + fetched
            })
        }
        catch {
            result = .failure(error)
        }

        await endReport(ticket)
        return try result.get()
    }

    /// Reads up to `upTo` bytes, or to the end of the file when `nil`, from the file's current offset through the
    /// cache, then moves the offset past them. A read that fails leaves the offset where it was.
    func readAtPositionThroughCache(
        upTo: Int64?,
        chunkSize: Int,
        context: Bridge.Context,
        handle: Bridge.FileHandle
    ) async throws -> Data {
        let start = try await Bridge.seek(context: context, file: handle, offset: 0, whence: SEEK_CUR)
        let data = try await readThroughCache(
            upTo: upTo.map { Int(clamping: $0) } ?? .max,
            atOffset: start,
            chunkSize: chunkSize,
            context: context,
            handle: handle
        )
        if !data.isEmpty {
            let end = start.addingReportingOverflow(UInt64(data.count))
            _ = try await Bridge.seek(
                context: context,
                file: handle,
                offset: Int64(clamping: end.overflow ? .max : end.partialValue),
                whence: SEEK_SET
            )
        }
        return data
    }
}

// MARK: Metadata

extension SMB.File {
    /// Stats the open file on the server and, when the file uses a cache, hands the cache the result in a request of
    /// its own, so the cache can refuse it if anything changed at the file's path since it began.
    func statReportingToCache(context: Bridge.Context, handle: Bridge.FileHandle) async throws -> SMB.Stat {
        guard let cache = cacheAttachment?.cache, changeSnapshot != nil else {
            return try await SMB.Stat(Bridge.fileStatistics(context: context, file: handle))
        }

        return try await connection.withCacheRequest(on: cache) { request in
            await cache.beginRequest(request)
            let snapshot = changeSnapshot
            let stat = try await SMB.Stat(Bridge.fileStatistics(context: context, file: handle))

            // Opening the file followed any link at its path.
            await report(.stat, since: snapshot) { cache, path in
                await cache.storeStat(stat, path: path, request: request)
            }
            return stat
        }
    }

    /// Hands the cache the metadata of a file just opened for reading, so it can tell whether the blocks it holds are
    /// of the file now at the path. A failure is ignored: the cache never makes an open fail.
    func reportMetadataAfterOpen() async {
        guard consultsCache else {
            return
        }
        _ = try? await stat()
    }
}

// MARK: Closing

extension SMB.File {
    /// Closes `handle`, taken from the file, and reports the file's final metadata to the cache when the file was
    /// written: the written blocks belong to the file as it is then. When that stat is skipped, because the connection
    /// is closed, or fails, the file is invalidated instead.
    func closeReportingToCache(_ handle: Bridge.FileHandle) async throws {
        let wroteToFile = protectedWroteToFile.current
        let cache = cacheAttachment?.cache

        // The final stat of a written file is a request of its own, so the cache can refuse it if anything changed at
        // the file's path since it began.
        let request: SMB.CacheRequestID? = if cache != nil, wroteToFile, changeSnapshot != nil {
            SMB.CacheRequestID()
        }
        else {
            nil
        }
        if let cache, let request {
            await cache.beginRequest(request)
        }
        let snapshot = changeSnapshot

        var finalStat: SMB.Stat?
        let failure: any Error?
        do {
            let context = try connection.requireContext()
            if request != nil {
                finalStat = try? await finalMetadata(context: context, handle: handle)
            }
            try await Bridge.close(context: context, file: handle)
            failure = nil
        }
        catch {
            failure = error
        }

        if wroteToFile {
            if let finalStat, let request {
                await report(.stat, since: snapshot) { cache, path in
                    await cache.storeStat(finalStat, path: path, request: request)
                }
            }
            else {
                // Without the final metadata, the cache cannot tell which version the written blocks belong to.
                await report(.invalidation) { cache, path in
                    await cache.invalidate(path: path)
                }
            }
        }

        if let cache, let request {
            await cache.requestEnded(request)
        }
        if let registration {
            cacheAttachment?.openFiles.unregister(registration)
        }

        if let failure {
            throw failure
        }
    }

    /// The metadata of the file before it closes.
    ///
    /// Servers refuse to stat a handle opened only for writing, since it lacks the right to read attributes, so such a
    /// file is stat'ed by the path it reports under. The registry tells whether that path still led to the file: a
    /// rename or a delete of it while the stat is on its way makes the report invalidate instead.
    private func finalMetadata(context: Bridge.Context, handle: Bridge.FileHandle) async throws -> SMB.Stat? {
        guard accessMode == .writeOnly else {
            return try await SMB.Stat(Bridge.fileStatistics(context: context, file: handle))
        }
        guard let path = cachePath else {
            return nil
        }
        return try await SMB.Stat(Bridge.fileStatistics(context: context, path: path))
    }

    /// Forgets the file in the registry when it is released without being closed, and invalidates it if it was written,
    /// since its final metadata never reaches the cache.
    func abandonCacheReportsInBackground() {
        guard let cacheAttachment, let registration else {
            return
        }

        let path = protectedWroteToFile.current ? cacheAttachment.openFiles.path(of: registration) : nil
        cacheAttachment.openFiles.unregister(registration)
        if let path {
            let cache = cacheAttachment.cache
            Task {
                await cache.invalidate(path: path)
            }
        }
    }
}
