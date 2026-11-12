//
// Part of SwiftSMB
// ReferenceCache.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// A reference ``SMB/BlockLevelReadCache`` that keeps file contents in a ``SMB/CacheStorage``, and optionally
    /// metadata in memory.
    ///
    /// Attach one cache to a connection, and the connections forked from it, all on one share:
    ///
    /// ```swift
    /// let connection = try await SMB.connect(server: server, credentials: credentials, share: "Photos")
    ///
    /// let control = try await connection.fork()
    /// let cache = SMB.ReferenceCache(
    ///     storage: SMB.InMemoryCacheStorage(byteBudget: 64 * 1024 * 1024),
    ///     controlConnection: control,
    ///     configuration: .init(trustPolicy: .statOnServer, revalidationInterval: 10)
    /// )
    /// connection.attachCache(cache)
    /// // …
    /// connection.detachCache()
    /// await cache.close()
    /// try await control.disconnect()
    /// ```
    ///
    /// ## Storage
    ///
    /// The cache keeps the bytes the connection reads and writes in its ``SMB/CacheStorage``, which decides how many it
    /// keeps and which it drops; ``SMB/InMemoryCacheStorage`` by default. The cache decides which bytes are current: it
    /// stores and hands back only bytes of the version of a file it tracks, and never past the size the file last had.
    /// Caches for several shares can share one storage.
    ///
    /// On Apple platforms the cache drops the stats and listings it keeps when the system's memory is critical.
    ///
    /// ## Staying current
    ///
    /// The cache compares every stat and directory listing the connection makes with the size, last write time, and
    /// change time of the version its blocks came from, and drops the blocks of a file that changed. Bytes written
    /// through the connection since the previous stat belong to the new version, so they are kept. It also drops what
    /// the connection reports as changed, and moves what the connection renames. ``Configuration/trustPolicy`` adds
    /// checks against the server on top; see ``TrustPolicy`` for what each one costs and guarantees.
    ///
    /// Bytes, stats, and listings fetched for a request whose lookup came before a change at their path are not kept,
    /// even when they reach the cache after it, and downloaded bytes go only to a file the cache tracked when the read
    /// looked it up. The cache remembers every open request until the connection ends it, up to a limit past which the
    /// oldest are forgotten and their stores refused.
    ///
    /// Bytes appended through the connection keep the bytes before them: once a stat shows the file grown by exactly
    /// the bytes appended since the previous one, the cache keeps what it held as part of the new version.
    ///
    /// ## Paths
    ///
    /// ``Configuration/pathMatching`` decides which paths share a cache entry. Whichever it is, a change reported under
    /// one path also drops what is cached under every path that differs from it only in case or in Unicode
    /// normalization, since the share may take such paths to name the same file.
    ///
    /// ## Control connection
    ///
    /// Checks against the server need a connection of the cache's own, given to
    /// ``init(storage:controlConnection:configuration:)``. The caller opens that connection, typically by forking the
    /// connection the cache is for before attaching the cache, and disconnects it after closing the cache: neither
    /// ``close()`` nor disconnecting the connections the cache is attached to disconnects it.
    actor ReferenceCache: BlockLevelReadCache {
        // MARK: Limits

        /// Most files tracked, with or without cached bytes.
        static let entryLimit = 16384

        /// Most stats, and most listings, kept to answer from.
        static let metadataLimit = 4096

        // MARK: State

        let configuration: Configuration

        /// Where the bytes of tracked files are kept, by ``FileEntry/id``.
        let storage: any CacheStorage

        /// The cache's own connection, without a cache attached.
        let control: Connection?

        /// Tracked files, by key: ``CachePath/exactKey(_:)`` or ``CachePath/caseInsensitiveKey(_:)`` of the path, as
        /// ``Configuration/pathMatching`` says.
        var files: [String: FileEntry] = [:]

        /// The keys in ``files``, filed by key, to find those at or under a path, or directly in a directory.
        var fileTree = PathIndex()

        /// The keys in ``files``, filed by ``FileEntry/equivalenceKey``, to find those a change to an equivalent path
        /// reaches.
        var equivalents = PathIndex()

        /// Counts uses, for dropping the least recently used files past ``entryLimit``.
        var tick: UInt64 = 0

        /// Changes, by ``CachePath/equivalenceKey(_:)``.
        var changeLog = ChangeLog()

        /// Requests whose lookup the cache did not answer in full, until the connection ends them.
        var requests = RequestLog()

        /// Stored stats to answer from, by key.
        var stats: [String: StoredStat] = [:]

        /// Stored listings to answer from, by key of the directory.
        var listings: [String: StoredListing] = [:]

        /// Checks in flight, by key.
        var checks: [String: RunningCheck] = [:]
        var nextCheckToken: UInt64 = 0

        var isClosed = false

        #if canImport(Darwin)
            let memoryPressureObserver: MemoryPressureObserver
        #endif

        // MARK: Initialization

        /// Creates a cache without a control connection.
        ///
        /// The configuration must not need one: its trust policy must be ``TrustPolicy/trustReports``. Use
        /// ``init(storage:controlConnection:configuration:)`` otherwise.
        ///
        /// - Parameters:
        ///   - storage: Where the bytes of cached files are kept. A new ``SMB/InMemoryCacheStorage`` by default.
        ///   - configuration: How the cache stores, checks, matches paths, and answers.
        public init(storage: any CacheStorage = InMemoryCacheStorage(), configuration: Configuration) {
            precondition(
                !configuration.needsControlConnection,
                "This configuration needs a control connection: create the cache with init(storage:controlConnection:configuration:)"
            )
            self.init(checkedConfiguration: configuration, storage: storage, control: nil)
        }

        /// Creates a cache with `control` as its control connection.
        ///
        /// Open `control` yourself, typically with ``SMB/Connection/fork()`` on the connection the cache is for. Fork
        /// before attaching any cache to that connection: a fork made while a cache is attached starts with that cache,
        /// and the control connection must not use one. Use `control` for nothing else afterwards.
        ///
        /// `control` stays the caller's: the cache never disconnects it. Disconnect it after ``close()``, once the
        /// cache is done with it.
        ///
        /// - Parameters:
        ///   - storage: Where the bytes of cached files are kept. A new ``SMB/InMemoryCacheStorage`` by default.
        ///   - control: A connection to the share whose files the cache keeps, without a cache attached.
        ///   - configuration: How the cache stores, checks, matches paths, and answers.
        public init(
            storage: any CacheStorage = InMemoryCacheStorage(),
            controlConnection control: Connection,
            configuration: Configuration
        ) {
            precondition(
                !control.hasCacheAttached(),
                "The control connection must not use a cache: fork it before attaching any cache to the connection"
            )
            self.init(checkedConfiguration: configuration, storage: storage, control: control)
        }

        init(checkedConfiguration configuration: Configuration, storage: any CacheStorage, control: Connection?) {
            configuration.validate()
            self.configuration = configuration
            self.storage = storage
            self.control = control

            #if canImport(Darwin)
                let observer = MemoryPressureObserver()
                memoryPressureObserver = observer
                observer.start { [weak self] critical in
                    guard critical else {
                        return
                    }
                    Task {
                        await self?.relieveMemoryPressure()
                    }
                }
            #endif
        }

        /// Drops everything cached, its files' bytes in the storage included, and waits for the checks in flight to
        /// finish.
        ///
        /// Call this when done with the cache, after detaching it from every connection; then disconnect the control
        /// connection, if the cache has one, which this does not disconnect. Once this returns, the cache no longer
        /// uses the control connection. A cache still attached goes on storing and answering, but every check that
        /// needs the control connection fails from then on, dropping the bytes it was about. Closing more than once
        /// does nothing.
        public func close() async {
            guard !isClosed else {
                return
            }

            isClosed = true
            let running = checks.values.map(\.task)
            for task in running {
                task.cancel()
            }
            removeAll()

            for task in running {
                await task.value
            }
        }

        // MARK: BlockLevelReadCache: Blocks

        /// Keeps downloaded bytes, when the request that fetched them is still open, the file its lookup found is still
        /// tracked, and nothing changed at the file since, its version included; and written bytes, when
        /// ``Configuration/keepsUploads`` is on.
        ///
        /// Bytes past the file's known size, and bytes of files the storage does not accept, are not kept. Written
        /// bytes also drop what is cached under paths that may name the same file.
        public func storeBlock(
            _ data: Data,
            path: String,
            offset: UInt64,
            source: CacheBlockSource,
            request: CacheRequestID?
        ) async {
            // No byte of a file lies at or past the last position a file can have: only a broken server sends one.
            let room = UInt64.max - offset
            let data = UInt64(data.count) > room ? data.prefix(Int(room)) : data
            guard !data.isEmpty else {
                return
            }

            let location = locate(path)
            switch source {
            case .download:
                storeDownload(data, location: location, offset: offset, request: request)

            case .upload:
                storeUpload(data, location: location, offset: offset)
            }
        }

        /// Hands back the cached run starting at `offset`, after checking the file against the server if the trust
        /// policy says it is due.
        public func retrieveBlock(path: String, offset: UInt64, upTo: Int, request: CacheRequestID) async -> Data? {
            guard upTo > 0 else {
                return nil
            }

            let key = locate(path).key
            var answer: Data?
            if let found = probe(key, offset: offset), found.holdsOffset, await verify(key: key) {
                answer = hit(key, offset: offset, upTo: upTo)
            }

            // The connection reads the rest from the server and hands it over: remember when, and into which tracked
            // file, after every wait above.
            if answer?.count ?? 0 < upTo {
                requests.begin(request, at: changeLog.clock, entry: files[key]?.id)
            }

            return answer
        }

        // MARK: BlockLevelReadCache: Metadata

        /// Compares the stat with the version the file's blocks came from, dropping them if it changed, and keeps it to
        /// answer from when ``Configuration/metadata`` says so.
        ///
        /// A stat is refused when anything changed at or under its path, or a path that may name the same entry, since
        /// its request started, or when the request is no longer open.
        public func storeStat(_ result: Stat?, path: String, request: CacheRequestID) async {
            let location = locate(path)
            guard let started = requests.start(of: request),
                  changeLog.latestChange(atOrUnder: location.equivalenceKey) <= started.clock else {
                return
            }

            storeStatAnswer(result, location: location)

            guard let result else {
                // Nothing at the path, so nothing under it either.
                if removeEntries(atOrUnderEquivalentsOf: location) {
                    changeLog.recordChange(at: location.equivalenceKey)
                }
                return
            }

            if result.type == .file {
                dropDisagreeingEquivalents(of: location, version: FileVersion(result))
                applyVersion(result, location: location, createIfMissing: true)
            }
            else {
                removeEntries(equivalentTo: location)
            }
        }

        /// Compares every listed file the cache tracks with the version its blocks came from, drops tracked files the
        /// directory no longer holds, and keeps the listing to answer from when ``Configuration/metadata`` says so.
        ///
        /// A listing is refused when anything changed at or under its directory since the request's lookup, or when the
        /// request is no longer open. Entries of symbolic links and other reparse points describe the entry itself, so
        /// they leave the files tracked at their paths alone.
        public func storeDirectoryListing(_ entries: [DirectoryEntry], path: String, request: CacheRequestID) async {
            let directory = locate(path)
            guard let started = requests.clock(of: request),
                  changeLog.latestChange(atOrUnder: directory.equivalenceKey) <= started else {
                return
            }

            if case .answer = configuration.metadata {
                storeListing(entries, directory: directory)
            }

            guard !files.isEmpty else {
                return
            }

            var listed = Set<String>()
            for entry in entries {
                guard let childPath = CachePath.child(entry.name, of: directory.path) else {
                    continue
                }
                let child = locate(normalized: childPath)
                listed.insert(child.key)

                if Self.isLinkLike(entry.stat) {
                    continue
                }
                if entry.stat.type == .file {
                    dropDisagreeingEquivalents(of: child, version: FileVersion(entry.stat))
                    applyVersion(entry.stat, location: child, createIfMissing: false)
                }
                else {
                    removeEntries(equivalentTo: child)
                }
            }

            // Files the cache tracks directly in the directory that the listing does not show are gone.
            let gone = fileTree.children(of: directory.key).filter { files[$0] != nil && !listed.contains($0) }
            for key in gone {
                removeEntry(key)
            }
        }

        /// Answers from a stored stat of the path, or a stored listing of its directory, as ``Configuration/metadata``
        /// allows.
        ///
        /// A listing answers that nothing exists at a path only when it shows no entry whose name may name the same
        /// file. A regular file the answer shows is tracked from then on, so that the bytes the connection reads after
        /// opening it can be kept even before the stat of the open file reaches the cache.
        public func retrieveStat(path: String, request: CacheRequestID) async -> CachedStat? {
            let location = locate(path)
            guard let answer = storedStat(location) else {
                requests.begin(request, at: changeLog.clock)
                return nil
            }

            if case let .exists(stat) = answer, stat.type == .file, files[location.key] == nil {
                createEntry(location, version: FileVersion(stat))
            }
            return answer
        }

        /// Answers from a stored listing of the same directory, as ``Configuration/metadata`` allows.
        public func retrieveDirectoryListing(path: String, request: CacheRequestID) async -> [DirectoryEntry]? {
            guard case let .answer(maximumAge, _) = configuration.metadata,
                  let listing = listings[locate(path).key],
                  Self.uptime() - listing.time < maximumAge else {
                requests.begin(request, at: changeLog.clock)
                return nil
            }

            return listing.entries
        }

        /// Remembers when the request started, so its store is refused if anything changed at its path since.
        public func beginRequest(_ request: CacheRequestID) async {
            requests.begin(request, at: changeLog.clock)
        }

        /// Forgets the request, so a store for it is refused from now on.
        public func requestEnded(_ request: CacheRequestID) async {
            requests.end(request)
        }

        // MARK: BlockLevelReadCache: Changes

        /// Moves the blocks and versions at and under `from` to the same places under `to`, after dropping what is
        /// cached at either path, and under paths that may name the same entries.
        public func didRename(from: String, to: String) async {
            let source = locate(from)
            let destination = locate(to)
            guard !CachePath.sameBytes(source.path, destination.path) else {
                // The share may have kept the entry under another spelling, which the rename gave the name `to` has:
                // nothing moves, but listings that show the old name, and stats of the entry and its directory, are
                // stale, and so is what requests in flight about it bring.
                changeLog.recordChange(at: source.equivalenceKey)
                dropMetadata(around: source, parentChanged: true)
                return
            }

            // Requests about either path in flight are stale.
            changeLog.recordChange(at: source.equivalenceKey)
            changeLog.recordChange(at: destination.equivalenceKey)

            // Take what moves out first, so dropping what the paths may name leaves it alone.
            let moving = fileTree.items(atOrUnder: source.key).compactMap { key in
                takeEntry(key, keepingBytes: true).map { (key, $0) }
            }
            removeEntries(atOrUnderEquivalentsOf: source)
            removeEntries(atOrUnderEquivalentsOf: destination)

            for (key, entry) in moving {
                var entry = entry
                entry.path = CachePath.rebase(entry.path, from: source.path, to: destination.path)
                entry.equivalenceKey = CachePath.equivalenceKey(entry.path)
                entry.contentEpoch += 1
                insertEntry(CachePath.rebase(key, from: source.key, to: destination.key), entry)
            }

            dropMetadata(around: source, parentChanged: true)
            dropMetadata(around: destination, parentChanged: true)
        }

        /// Drops the stored stats and listings of the file at `path`, and keeps its cached bytes: appending left them
        /// as they were. The next stat that shows the size those bytes and the appended ones add up to keeps them as
        /// part of the new version.
        public func didAppend(path: String, byteCount: UInt64) async {
            let location = locate(path)
            changeLog.recordChange(at: location.equivalenceKey)
            dropMetadata(around: location, parentChanged: false)
            removeEntries(atOrUnderEquivalentsOf: location, keeping: location.key)

            updateEntry(location.key) { entry in
                // Sizes past the last a file can have come only from a broken server: they stay at the last.
                var appends = entry.appends ?? Appends(base: entry.knownSize, byteCount: 0)
                appends.byteCount = Self.saturatingSum(appends.byteCount, byteCount)
                entry.appends = appends
                entry.knownSize = entry.knownSize.map { Self.saturatingSum($0, byteCount) }
                entry.contentEpoch += 1
                if !isCacheable(entry) {
                    dropBlocks(of: &entry)
                }
            }
        }

        /// Drops the blocks at and under `path`, and under every path that may name the same entry, and the stored
        /// stats and listings the change makes stale.
        public func invalidate(path: String) async {
            let location = locate(path)
            changeLog.recordChange(at: location.equivalenceKey)
            removeEntries(atOrUnderEquivalentsOf: location)
            dropMetadata(around: location, parentChanged: true)
        }
    }
}

// MARK: Blocks

extension SMB.ReferenceCache {
    /// What a read of `key` at `offset` needs to know, or `nil` when the cache does not track the file, will not cache
    /// it, or knows `offset` to be past its end.
    func probe(_ key: String, offset: UInt64) -> (knownSize: UInt64?, holdsOffset: Bool)? {
        guard let entry = files[key], isCacheable(entry) else {
            return nil
        }
        if let size = entry.knownSize, offset >= size {
            return nil
        }
        return (entry.knownSize, storage.ranges(of: entry.id).contains { $0.contains(offset) })
    }

    /// The cached run of `key` at `offset`, cut at the file's known size.
    func hit(_ key: String, offset: UInt64, upTo: Int) -> Data? {
        guard let entry = files[key], isCacheable(entry) else {
            return nil
        }

        var limit = upTo
        if let size = entry.knownSize {
            guard offset < size else {
                return nil
            }
            limit = Int(min(UInt64(upTo), size - offset))
        }
        guard let run = storage.read(entry.id, at: offset, upTo: limit), !run.isEmpty else {
            return nil
        }

        tick += 1
        files[key]?.lastUsed = tick
        return run
    }

    /// Keeps downloaded bytes, when `request` is still open, the file its lookup found is still tracked, and nothing
    /// changed at the file since the lookup.
    func storeDownload(_ data: Data, location: Location, offset: UInt64, request: SMB.CacheRequestID?) {
        // A file tracked only since the lookup has a version the bytes may predate: a new version records a change, a
        // new entry does not.
        guard let request, let lookup = requests.start(of: request),
              let entry = files[location.key], entry.id == lookup.entry,
              changeLog.generation(of: location.equivalenceKey) <= lookup.clock,
              changeLog.generation(of: entry.equivalenceKey) <= lookup.clock,
              isCacheable(entry) else {
            return
        }

        var bytes = data
        if let size = entry.knownSize {
            guard offset < size else {
                return
            }
            if UInt64(bytes.count) > size - offset {
                bytes = bytes.prefix(Int(size - offset))
            }
        }

        tick += 1
        let kept = storage.write(bytes, at: offset, of: entry.id)
        updateEntry(location.key) { entry in
            entry.lastUsed = tick
            if kept {
                entry.uploaded = ByteRanges.subtracting(offset ..< offset + UInt64(bytes.count), from: entry.uploaded)
            }
            else {
                entry.uploaded = []
                entry.isTooLarge = true
            }
        }
    }

    /// Keeps written bytes, when ``Configuration/keepsUploads`` is on, or drops the file's blocks, and drops the stored
    /// stats and listings the write makes stale, and what is cached under paths that may name the same file.
    func storeUpload(_ data: Data, location: Location, offset: UInt64) {
        // Bytes, stats, and listings fetched before this write landed must not be stored over it.
        changeLog.recordChange(at: location.equivalenceKey)
        dropMetadata(around: location, parentChanged: false)
        removeEntries(atOrUnderEquivalentsOf: location, keeping: location.key)

        guard configuration.keepsUploads else {
            updateEntry(location.key) { entry in
                dropBlocks(of: &entry)
                entry.contentEpoch += 1
            }
            return
        }

        if files[location.key] == nil {
            createEntry(location, version: nil)
        }

        tick += 1
        updateEntry(location.key) { entry in
            let end = offset + UInt64(data.count)
            if let size = entry.knownSize, end > size {
                entry.knownSize = end
            }

            entry.lastUsed = tick
            entry.contentEpoch += 1

            guard isCacheable(entry) else {
                dropBlocks(of: &entry)
                return
            }
            if storage.write(data, at: offset, of: entry.id) {
                entry.uploaded = ByteRanges.union(entry.uploaded, offset ..< end)
            }
            else {
                entry.uploaded = []
                entry.isTooLarge = true
            }
        }
    }

    /// Whether the cache stores and hands out bytes of `entry`.
    func isCacheable(_ entry: FileEntry) -> Bool {
        !entry.isTooLarge && storage.accepts(fileSize: entry.knownSize ?? 0)
    }

    /// Drops the bytes of `entry` from the storage, and the ranges written to them.
    func dropBlocks(of entry: inout FileEntry) {
        storage.remove(entry.id)
        entry.uploaded = []
    }

    /// Drops the stored stats and listings, which may be large, when the system's memory is critical. The storage
    /// relieves the pressure on bytes itself.
    func relieveMemoryPressure() {
        stats.removeAll()
        listings.removeAll()
    }

    /// Drops everything cached.
    func removeAll() {
        for entry in files.values {
            storage.remove(entry.id)
        }
        files.removeAll()
        fileTree.removeAll()
        equivalents.removeAll()
        stats.removeAll()
        listings.removeAll()
        changeLog.recordChangeEverywhere()
    }
}

// MARK: Versions

extension SMB.ReferenceCache {
    /// Compares a stat of the file at `location` with the version its blocks came from, dropping the blocks if it
    /// changed.
    ///
    /// Blocks written through the connection since the last stat belong to the new version, so they are kept, and so
    /// are the blocks before bytes the connection appended.
    func applyVersion(_ stat: SMB.Stat, location: Location, createIfMissing: Bool) {
        let version = FileVersion(stat)
        guard files[location.key] != nil else {
            if createIfMissing {
                createEntry(location, version: version)
            }
            return
        }
        applyVersion(version, key: location.key)
    }

    /// Compares `version` with the version the blocks of the tracked file at `key` came from.
    func applyVersion(_ version: FileVersion, key: String) {
        let now = Self.uptime()
        updateEntry(key) { entry in
            // The ranges whose bytes stay, or `nil` for every byte.
            var kept: [Range<UInt64>]?
            if !version.isSame(as: entry.version) {
                changeLog.recordChange(at: entry.equivalenceKey)
                // Bytes written since the last stat belong to the new version. Appending through the connection left
                // the bytes before the old end as they were, as long as nothing else changed the size.
                if let appends = entry.appends, let base = appends.base,
                   case let (sum, overflow) = base.addingReportingOverflow(appends.byteCount), !overflow,
                   version.size == sum {
                    kept = ByteRanges.union(entry.uploaded, 0 ..< base)
                }
                else {
                    kept = entry.uploaded
                }
                entry.version = version
                entry.contentEpoch += 1
                entry.isTooLarge = false
                entry.lastCheck = nil
                entry.sampleCursor = 0
            }

            entry.uploaded = []
            entry.appends = nil
            entry.knownSize = version.size
            kept = ByteRanges.clamping(kept ?? [0 ..< .max], to: 0 ..< version.size)

            // A stat is all a statOnServer check does.
            if configuration.trustPolicy == .statOnServer {
                entry.lastCheck = now
                entry.statSinceCheck = false
            }
            else {
                entry.statSinceCheck = true
            }

            if !isCacheable(entry) {
                dropBlocks(of: &entry)
            }
            else if let kept {
                storage.retain(kept, of: entry.id)
            }
        }
    }

    /// Drops the tracked files at paths that differ from `location` only in case or Unicode normalization and whose
    /// version is not `version`: the share may take them to name the file the stat or listing describes.
    func dropDisagreeingEquivalents(of location: Location, version: FileVersion) {
        for key in equivalents.items(at: location.equivalenceKey) where key != location.key {
            if files[key].map({ !version.isSame(as: $0.version) }) == true {
                removeEntry(key)
            }
        }
    }

    func createEntry(_ location: Location, version: FileVersion?) {
        tick += 1
        let checked = configuration.trustPolicy == .statOnServer && version != nil
        insertEntry(location.key, FileEntry(
            id: SMB.CacheFileID(),
            path: location.path,
            version: version,
            knownSize: version?.size,
            lastUsed: tick,
            lastCheck: checked ? Self.uptime() : nil,
            statSinceCheck: !checked
        ))

        if files.count > Self.entryLimit {
            // Down to nine tenths, so the next few files do not each sort every entry again.
            let victims = files
                .map { ($0.key, $0.value.lastUsed) }
                .sorted { $0.1 < $1.1 }
                .prefix(files.count - Self.entryLimit * 9 / 10)
            for (victim, _) in victims {
                removeEntry(victim)
            }
        }
    }

    /// Mutates the entry at `key` in place.
    @discardableResult
    func updateEntry<Result>(_ key: String, _ body: (inout FileEntry) -> Result) -> Result? {
        guard files[key] != nil else {
            return nil
        }
        return body(&files[key]!)
    }

    /// Stops tracking the file at `key`, and drops its bytes. Reads of it in flight are stale from now on.
    func removeEntry(_ key: String) {
        guard let entry = takeEntry(key) else {
            return
        }
        changeLog.recordChange(at: entry.equivalenceKey)
    }

    /// Stops tracking every file at or under `location`, and at or under every path that differs from it only in case
    /// or Unicode normalization, but `kept`, and drops their bytes, without recording a change.
    ///
    /// - Returns: Whether any file was tracked there.
    @discardableResult
    func removeEntries(atOrUnderEquivalentsOf location: Location, keeping kept: String? = nil) -> Bool {
        var keys = Set(fileTree.items(atOrUnder: location.key))
        keys.formUnion(equivalents.items(atOrUnder: location.equivalenceKey))
        if let kept {
            keys.remove(kept)
        }
        for key in keys {
            takeEntry(key)
        }
        return !keys.isEmpty
    }

    /// Stops tracking the files at `location`, and at every path that differs from it only in case or Unicode
    /// normalization, and drops their bytes. Reads of them in flight are stale from now on.
    func removeEntries(equivalentTo location: Location) {
        for key in equivalents.items(at: location.equivalenceKey).union([location.key]) {
            removeEntry(key)
        }
    }

    /// Starts tracking `entry` at `key`, where no file is tracked.
    func insertEntry(_ key: String, _ entry: FileEntry) {
        if files[key] != nil {
            takeEntry(key)
        }
        files[key] = entry
        fileTree.insert(key, at: key)
        equivalents.insert(key, at: entry.equivalenceKey)
    }

    /// Stops tracking the file at `key`, without recording a change.
    ///
    /// - Parameter keepingBytes: Whether the file's bytes stay in the storage, for an entry that moves to another key.
    /// - Returns: The file's entry, or `nil` when no file was tracked there.
    @discardableResult
    func takeEntry(_ key: String, keepingBytes: Bool = false) -> FileEntry? {
        guard let entry = files.removeValue(forKey: key) else {
            return nil
        }

        fileTree.remove(key, at: key)
        equivalents.remove(key, at: entry.equivalenceKey)
        if !keepingBytes {
            storage.remove(entry.id)
        }
        return entry
    }

    /// `first + second`, or the largest value on overflow.
    static func saturatingSum(_ first: UInt64, _ second: UInt64) -> UInt64 {
        let (sum, overflow) = first.addingReportingOverflow(second)
        return overflow ? .max : sum
    }
}

// MARK: Metadata

extension SMB.ReferenceCache {
    /// The answer a stored stat of `location`, or a stored listing of its directory, gives, if
    /// ``Configuration/metadata`` allows answering.
    func storedStat(_ location: Location) -> SMB.CachedStat? {
        guard case let .answer(maximumAge, includingMissing) = configuration.metadata else {
            return nil
        }

        let now = Self.uptime()
        if let stored = stats[location.key], now - stored.time < maximumAge {
            if let stat = stored.stat {
                return .exists(stat)
            }
            return includingMissing ? .doesNotExist : nil
        }

        // The listing of the parent directory, which lists links and other reparse points themselves rather than what a
        // stat of their path describes.
        guard !location.path.isEmpty,
              let listing = listings[CachePath.parent(of: location.key)],
              now - listing.time < maximumAge else {
            return nil
        }

        switch listing.byKey[location.key] {
        case let .entry(stat)?:
            return Self.isLinkLike(stat) ? nil : .exists(stat)

        case .ambiguous?:
            return nil

        case nil:
            // A listed name that may name the same file: the share may hold it under the asked path.
            guard listing.byEquivalenceKey[location.equivalenceKey] == nil else {
                return nil
            }
            return includingMissing ? .doesNotExist : nil
        }
    }

    /// Keeps a stat of `location` to answer from, when ``Configuration/metadata`` says so, and drops the stored stats
    /// and listings that describe the entry otherwise.
    func storeStatAnswer(_ result: SMB.Stat?, location: Location) {
        guard case .answer = configuration.metadata else {
            return
        }

        stats[location.key] = StoredStat(stat: result, equivalenceKey: location.equivalenceKey, time: Self.uptime())

        // Other spellings of the path, which the share may take to name the same entry.
        stats = stats.filter { key, stored in
            key == location.key || stored.equivalenceKey != location.equivalenceKey
                || !Self.disagree(stored.stat, result)
        }

        if !location.path.isEmpty {
            let parent = CachePath.parent(of: location.equivalenceKey)
            listings = listings.filter { _, listing in
                listing.equivalenceKey != parent
                    || !Self.contradicts(result, equivalenceKey: location.equivalenceKey, listing)
            }
        }

        pruneMetadata()
    }

    /// Keeps a listing of `directory` to answer from, and drops the stored stats of the entries it covers that it
    /// describes otherwise.
    func storeListing(_ entries: [SMB.DirectoryEntry], directory: Location) {
        var byKey: [String: ListedEntry] = [:]
        var byEquivalenceKey: [String: [SMB.Stat]] = [:]
        for entry in entries {
            guard let childPath = CachePath.child(entry.name, of: directory.path) else {
                continue
            }
            let child = locate(normalized: childPath)
            byKey[child.key] = byKey[child.key] == nil ? .entry(entry.stat) : .ambiguous
            byEquivalenceKey[child.equivalenceKey, default: []].append(entry.stat)
        }

        let listing = StoredListing(
            entries: entries,
            byKey: byKey,
            byEquivalenceKey: byEquivalenceKey,
            equivalenceKey: directory.equivalenceKey,
            time: Self.uptime()
        )
        listings[directory.key] = listing

        stats = stats.filter { _, stored in
            let covered = stored.equivalenceKey != directory.equivalenceKey
                && CachePath.parent(of: stored.equivalenceKey) == directory.equivalenceKey
            return !(covered && Self.contradicts(stored.stat, equivalenceKey: stored.equivalenceKey, listing))
        }

        pruneMetadata()
    }

    /// Whether a stat of a path whose equivalence key is `equivalenceKey`, which follows symbolic links the server
    /// resolves, and the listing of its directory cannot both be current.
    ///
    /// The listing describes every entry whose name may name the same file. A link or another reparse point among them
    /// describes itself, while the stat may describe what it leads to, so it contradicts nothing.
    static func contradicts(_ stat: SMB.Stat?, equivalenceKey: String, _ listing: StoredListing) -> Bool {
        let listed = listing.byEquivalenceKey[equivalenceKey] ?? []
        guard !listed.contains(where: isLinkLike) else {
            return false
        }
        guard let stat else {
            return !listed.isEmpty
        }
        return listed.isEmpty || listed.contains { !describeSameVersion($0, stat) }
    }

    /// Whether two stats of one path cannot both be current.
    static func disagree(_ first: SMB.Stat?, _ second: SMB.Stat?) -> Bool {
        switch (first, second) {
        case (nil, nil):
            false

        case let (first?, second?):
            !describeSameVersion(first, second)

        default:
            true
        }
    }

    /// Whether `first` and `second` show an entry of the same type, size, last write time, and change time.
    static func describeSameVersion(_ first: SMB.Stat, _ second: SMB.Stat) -> Bool {
        first.type == second.type && FileVersion(first) == FileVersion(second)
    }

    /// Whether a listed entry describes itself rather than what a stat of its path describes: a symbolic link, or
    /// another reparse point, which the server may follow.
    static func isLinkLike(_ stat: SMB.Stat) -> Bool {
        stat.type == .link || stat.attributes.contains(.reparsePoint)
    }

    /// Drops stored stats and listings a change at `location` makes stale: those at or under it, its parent's, and
    /// those of every path that differs from them only in case or Unicode normalization.
    ///
    /// - Parameter parentChanged: Whether the change may have added or removed an entry at `location`, which changes
    /// the times of its parent, so that listings of the directory holding the parent are stale too.
    func dropMetadata(around location: Location, parentChanged: Bool) {
        guard case .answer = configuration.metadata else {
            return
        }

        let changed = location.equivalenceKey
        let parent = CachePath.parent(of: changed)
        let grandparent = parentChanged ? CachePath.parent(of: parent) : parent
        stats = stats.filter { _, stored in
            !CachePath.isPath(stored.equivalenceKey, atOrUnder: changed) && stored.equivalenceKey != parent
        }
        listings = listings.filter { _, listing in
            !CachePath.isPath(listing.equivalenceKey, atOrUnder: changed)
                && listing.equivalenceKey != parent
                && listing.equivalenceKey != grandparent
        }
    }

    /// Keeps the stored stats and listings within ``metadataLimit``, dropping expired ones, then the oldest.
    func pruneMetadata() {
        guard case let .answer(maximumAge, _) = configuration.metadata else {
            return
        }

        let now = Self.uptime()
        if stats.count > Self.metadataLimit {
            stats = stats.filter { now - $0.value.time < maximumAge }
            if stats.count > Self.metadataLimit {
                let oldest = stats.sorted { $0.value.time < $1.value.time }.prefix(stats.count - Self.metadataLimit / 2)
                for (key, _) in oldest {
                    stats[key] = nil
                }
            }
        }

        if listings.count > Self.metadataLimit {
            listings = listings.filter { now - $0.value.time < maximumAge }
            if listings.count > Self.metadataLimit {
                let oldest = listings.sorted { $0.value.time < $1.value.time }
                    .prefix(listings.count - Self.metadataLimit / 2)
                for (key, _) in oldest {
                    listings[key] = nil
                }
            }
        }
    }
}

// MARK: Paths

extension SMB.ReferenceCache {
    /// A path as the cache files it.
    struct Location {
        /// The normalized path.
        let path: String
        /// The key of the file at the path, as ``Configuration/pathMatching`` says.
        let key: String
        /// ``CachePath/equivalenceKey(_:)`` of the path.
        let equivalenceKey: String
    }

    /// Where the cache files `path`.
    nonisolated func locate(_ path: String) -> Location {
        locate(normalized: CachePath.normalize(path))
    }

    /// Where the cache files the normalized `path`.
    nonisolated func locate(normalized path: String) -> Location {
        let key = switch configuration.pathMatching {
        case .exact:
            CachePath.exactKey(path)

        case .caseInsensitive:
            CachePath.caseInsensitiveKey(path)
        }
        return Location(path: path, key: key, equivalenceKey: CachePath.equivalenceKey(path))
    }

    static func uptime() -> TimeInterval {
        ProcessInfo.processInfo.systemUptime
    }
}

// MARK: Inspection

extension SMB.ReferenceCache {
    /// The cached ranges of the file at `path`, sorted.
    func cachedRanges(path: String) -> [Range<UInt64>] {
        files[locate(path).key].map { storage.ranges(of: $0.id) } ?? []
    }
}
