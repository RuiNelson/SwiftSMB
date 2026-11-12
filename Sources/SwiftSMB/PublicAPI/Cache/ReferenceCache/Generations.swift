//
// Part of SwiftSMB
// Generations.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// Generations of paths, which tell answers fetched before a change from answers fetched after it.
///
/// One clock counts every change. A path's generation is the clock value of the last change at the path or at a
/// directory above it, so changing a directory changes everything under it. Generations only grow. The
/// ``SMB/ReferenceCache`` records changes under equivalence keys (``CachePath/equivalenceKey(_:)``), so a change
/// reaches every spelling of a path that may name the same file.
struct ChangeLog {
    /// Most paths whose last change is remembered, and most directories whose last change below them is. Past either,
    /// the log forgets them all and raises ``floor`` instead, as if everything had changed: answers in flight are
    /// refused, never wrongly accepted.
    static let pathLimit = 8192

    /// Clock value of the last change.
    private(set) var clock: UInt64 = 0

    /// Generation of every path whose own changes are forgotten.
    private var floor: UInt64 = 0

    /// Clock value of the last change at each path.
    private var changes: [String: UInt64] = [:]

    /// Clock value of the last change anywhere under each directory above a changed path.
    private var changesBelow: [String: UInt64] = [:]

    /// Records a change at `path`, and so at everything under it.
    mutating func recordChange(at path: String) {
        clock += 1
        if (changes.count >= Self.pathLimit && changes[path] == nil) || changesBelow.count >= Self.pathLimit {
            changes.removeAll(keepingCapacity: true)
            changesBelow.removeAll(keepingCapacity: true)
            floor = clock
            return
        }

        changes[path] = clock
        for ancestor in CachePath.ancestors(of: path) {
            changesBelow[ancestor] = clock
        }
    }

    /// Records a change everywhere at once.
    mutating func recordChangeEverywhere() {
        clock += 1
        changes.removeAll(keepingCapacity: true)
        changesBelow.removeAll(keepingCapacity: true)
        floor = clock
    }

    /// The generation of `path`: the clock value of the last change at it or at a directory above it.
    func generation(of path: String) -> UInt64 {
        guard !changes.isEmpty else {
            return floor
        }

        var generation = max(floor, changes[path] ?? 0)
        for ancestor in CachePath.ancestors(of: path) {
            generation = max(generation, changes[ancestor] ?? 0)
        }
        return generation
    }

    /// The clock value of the last change at `path`, at a directory above it, or anywhere under it.
    func latestChange(atOrUnder path: String) -> UInt64 {
        max(generation(of: path), changesBelow[path] ?? 0)
    }
}

/// The requests whose lookup the cache did not answer in full, or that ``SMB/BlockLevelReadCache/beginRequest(_:)``
/// started, and that have not ended yet, with the clock value at each start, so a store is kept only if nothing changed
/// at its path since, and for a read the file the cache tracked then, so its bytes go to no other.
struct RequestLog {
    /// Most requests remembered. Past it, the oldest are forgotten first, and their stores refused: a connection that
    /// never ends its requests cannot make the log grow without limit.
    static let limit = 4096

    /// What a request started from.
    struct Start {
        /// ``ChangeLog/clock`` when the request started.
        let clock: UInt64
        /// ``SMB/ReferenceCache/FileEntry/id`` of the file a read's lookup found, or `nil`.
        let entry: SMB.CacheFileID?
    }

    private struct Record {
        let start: Start
        /// When the record was made, to forget the oldest first.
        let sequence: UInt64
    }

    private var records: [SMB.CacheRequestID: Record] = [:]
    private var order: [(request: SMB.CacheRequestID, sequence: UInt64)] = []
    private var orderStart = 0
    private var nextSequence: UInt64 = 0

    /// Requests remembered.
    var count: Int {
        records.count
    }

    /// Remembers that `request` started at `clock`, its lookup finding the tracked file `entry`. A request started
    /// again keeps its first start, so its store is checked against everything since.
    mutating func begin(_ request: SMB.CacheRequestID, at clock: UInt64, entry: SMB.CacheFileID? = nil) {
        guard records[request] == nil else {
            return
        }

        nextSequence += 1
        records[request] = Record(start: Start(clock: clock, entry: entry), sequence: nextSequence)
        order.append((request, nextSequence))

        while records.count > Self.limit, orderStart < order.count {
            let oldest = order[orderStart]
            orderStart += 1
            if records[oldest.request]?.sequence == oldest.sequence {
                records[oldest.request] = nil
            }
        }

        // Drop the order entries of records already ended or forgotten. At most `limit` records remain, so this runs at
        // most once every `limit` new records.
        if order.count > 2 * Self.limit {
            order = order[orderStart...].filter { records[$0.request]?.sequence == $0.sequence }
            orderStart = 0
        }
    }

    /// The clock value when `request` started, or `nil` when the request ended, was forgotten, or never started.
    func clock(of request: SMB.CacheRequestID) -> UInt64? {
        records[request]?.start.clock
    }

    /// What `request` started from, or `nil` when the request ended, was forgotten, or never started.
    func start(of request: SMB.CacheRequestID) -> Start? {
        records[request]?.start
    }

    /// Forgets `request`.
    mutating func end(_ request: SMB.CacheRequestID) {
        records[request] = nil
    }
}

/// Items filed by path, with the paths below each directory, so the items at or under a path are found without visiting
/// every item.
///
/// The ``SMB/ReferenceCache`` files its tracked files by key, and again by equivalence key, so that a change reaches
/// every file whose path may name the changed one at the cost of the files there.
struct PathIndex {
    /// Items filed at each path.
    private var items: [String: Set<String>] = [:]

    /// The paths directly under each directory that hold items, or directories that do.
    private var children: [String: Set<String>] = [:]

    var isEmpty: Bool {
        items.isEmpty
    }

    /// Files `item` at `path`.
    mutating func insert(_ item: String, at path: String) {
        items[path, default: []].insert(item)

        var current = path
        while !current.isEmpty {
            let parent = CachePath.parent(of: current)
            guard children[parent, default: []].insert(current).inserted else {
                break
            }
            current = parent
        }
    }

    /// Removes `item` from `path`, and the directories left holding nothing.
    mutating func remove(_ item: String, at path: String) {
        guard items[path]?.remove(item) != nil else {
            return
        }
        if items[path]?.isEmpty == true {
            items[path] = nil
        }

        var current = path
        while !current.isEmpty, items[current] == nil, children[current] == nil {
            let parent = CachePath.parent(of: current)
            children[parent]?.remove(current)
            if children[parent]?.isEmpty == true {
                children[parent] = nil
            }
            current = parent
        }
    }

    /// The items filed at `path`.
    func items(at path: String) -> Set<String> {
        items[path] ?? []
    }

    /// The items filed at `path` or under it.
    func items(atOrUnder path: String) -> [String] {
        var result: [String] = []
        var pending = [path]
        while let current = pending.popLast() {
            result += items[current] ?? []
            pending += children[current] ?? []
        }
        return result
    }

    /// The paths directly under `directory` that hold items, or directories that do.
    func children(of directory: String) -> Set<String> {
        children[directory] ?? []
    }

    mutating func removeAll() {
        items.removeAll()
        children.removeAll()
    }
}
