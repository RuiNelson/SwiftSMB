//
// Part of SwiftSMB
// ReferenceCache+Checks.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

// MARK: Checks against the server

extension SMB.ReferenceCache {
    /// Whether `entry` needs a check by the trust policy before its bytes are handed out.
    func isDue(_ entry: FileEntry) -> Bool {
        guard configuration.trustPolicy != .trustReports else {
            return false
        }
        guard let lastCheck = entry.lastCheck else {
            return true
        }
        if let interval = configuration.revalidationInterval {
            return Self.uptime() - lastCheck >= interval
        }
        return entry.statSinceCheck
    }

    /// Checks the file at `key` if it is due, waiting for a check already in flight.
    ///
    /// - Returns: Whether the file's bytes may be handed out.
    func verify(key: String) async -> Bool {
        guard configuration.trustPolicy != .trustReports else {
            return true
        }

        if let running = checks[key] {
            await running.task.value
        }
        guard let due = files[key].map(isDue) else {
            return false
        }
        guard due else {
            return true
        }

        // Anything may have changed across the waits: decide on the state after them. A check whose result was dropped
        // leaves the last check where it was. One that failed dropped the bytes it was about.
        let started = Self.uptime()
        await startCheck(key: key).value
        return files[key].map { ($0.lastCheck ?? -.infinity) >= started } ?? false
    }

    /// Starts checking the file at `key`, unless a check of it is already in flight.
    ///
    /// - Returns: The check in flight.
    @discardableResult
    func startCheck(key: String) -> Task<Void, Never> {
        if let running = checks[key] {
            return running.task
        }

        nextCheckToken += 1
        let token = nextCheckToken
        // The task runs on the actor, so it cannot start before it is registered.
        let task = Task {
            await check(key: key, token: token)
        }
        checks[key] = RunningCheck(token: token, task: task)
        return task
    }

    /// Checks the file at `key` against the server with the trust policy.
    ///
    /// The checks wait on the server, so the entry may change meanwhile. A result about an entry that changed is
    /// dropped: the bytes it would vouch for, or condemn, are gone.
    func check(key: String, token: UInt64) async {
        defer {
            if checks[key]?.token == token {
                checks[key] = nil
            }
        }

        guard let entry = files[key] else {
            return
        }
        let snapshot = CheckSnapshot(entry)
        guard let control, !isClosed else {
            failCheck(key, snapshot)
            return
        }

        switch configuration.trustPolicy {
        case .trustReports:
            return

        case .statOnServer:
            let stat: SMB.Stat?
            do {
                stat = try await control.stat(at: entry.path)
            }
            catch let error as SMB.Error where error.isPathNotFound {
                stat = nil
            }
            catch {
                failCheck(key, snapshot)
                return
            }

            guard isCurrent(key, snapshot) else {
                return
            }
            guard let stat, stat.type == .file else {
                failCheck(key, snapshot)
                return
            }
            applyVersion(FileVersion(stat), key: key)

        case let .sampleBlocks(count, scan):
            await sampleCheck(key: key, snapshot: snapshot, count: count, scan: scan, control: control)
        }
    }

    /// Stats the file at `key` through `control`, then compares cached blocks with the server's.
    private func sampleCheck(
        key: String,
        snapshot: CheckSnapshot,
        count: Int,
        scan: SMB.FileCompareScan,
        control: SMB.Connection
    ) async {
        guard let path = files[key]?.path else {
            return
        }

        let file: SMB.File
        do {
            file = try await control.openFile(at: path, accessMode: .readOnly)
        }
        catch {
            failCheck(key, snapshot)
            return
        }

        var snapshot = snapshot
        var samples = SampleSet(blocks: [], cursor: 0)
        let matches: Bool
        do {
            let stat = try await file.stat()
            guard isCurrent(key, snapshot) else {
                try? await file.close()
                return
            }
            guard stat.type == .file else {
                try? await file.close()
                failCheck(key, snapshot)
                return
            }

            // A new version drops the blocks it does not keep: compare those it does.
            applyVersion(FileVersion(stat), key: key)
            guard let entry = files[key] else {
                try? await file.close()
                return
            }
            snapshot = CheckSnapshot(entry)
            samples = sampleBlocks(of: entry, count: count, scan: scan)

            matches = try await Self.serverHolds(samples.blocks, file: file)
            try? await file.close()
        }
        catch {
            try? await file.close()
            failCheck(key, snapshot)
            return
        }

        guard isCurrent(key, snapshot) else {
            return
        }
        if matches {
            updateEntry(key) { entry in
                markChecked(&entry)
                entry.sampleCursor = samples.cursor
            }
        }
        else {
            failCheck(key, snapshot)
        }
    }

    /// Up to `count` blocks of the grid ``TrustPolicy/sampleBlocks(count:scan:)`` lays over `entry` that the storage
    /// holds whole, with their contents, in `scan` order from where the previous check stopped.
    func sampleBlocks(of entry: FileEntry, count: Int, scan: SMB.FileCompareScan) -> SampleSet {
        guard let size = entry.knownSize else {
            return SampleSet(blocks: [], cursor: 0)
        }

        let plan = Self.samplePlan(
            size: size,
            cached: storage.ranges(of: entry.id),
            cursor: entry.sampleCursor,
            count: count,
            scan: scan
        )

        // The storage may drop the file meanwhile: a block it no longer holds whole is left out.
        let blocks = plan.blocks.compactMap { block -> (offset: UInt64, bytes: Data)? in
            guard let bytes = storage.read(entry.id, at: block.lowerBound, upTo: Int(block.count)),
                  bytes.count == block.count else {
                return nil
            }
            return (block.lowerBound, bytes)
        }
        return SampleSet(blocks: blocks, cursor: plan.cursor)
    }

    /// Up to `count` blocks of the grid of a file of `size` bytes, with blocks of at most ``sampleLength`` bytes, that
    /// `cached` holds whole, in `scan` order from position `cursor` of that order, wrapping around once.
    ///
    /// Costs time in proportion to the blocks `cached` holds whole, not to the blocks of the grid, so a check of a
    /// large file of which little is cached stays cheap.
    ///
    /// - Parameters:
    ///   - size: Size of the file.
    ///   - cached: The ranges held, sorted, neither overlapping nor touching.
    ///   - cursor: Where in the order the previous check stopped.
    ///   - count: Most blocks wanted.
    ///   - scan: The order.
    /// - Returns: The blocks, in the order they come, and the position in the order just past the last one, where the
    /// next check picks up: back at `cursor` when fewer than `count` blocks are held whole.
    static func samplePlan(
        size: UInt64,
        cached: [Range<UInt64>],
        cursor: UInt64,
        count: Int,
        scan: SMB.FileCompareScan
    ) -> (blocks: [Range<UInt64>], cursor: UInt64) {
        guard size > 0, count > 0 else {
            return ([], 0)
        }

        let grid = FileCompareGrid(size: size, maximumBlockSize: sampleLength)
        let blockCount = grid.blockCount
        let start = cursor % blockCount

        func position(_ index: UInt64) -> UInt64 {
            switch scan {
            case .startToEnd: index
            case .endToStart: blockCount - 1 - index
            case .bisection: bisectionPosition(of: index, blockCount: blockCount)
            }
        }

        // The `count` blocks held whole that come first from `start` on, sorted by how far they come after it.
        var chosen: [(distance: UInt64, position: UInt64, index: UInt64)] = []
        for range in cached {
            var index = blockIndex(containing: range.lowerBound, of: grid)
            if grid.offset(index) < range.lowerBound {
                index += 1
            }
            while index < blockCount, grid.offset(index) + grid.length(index) <= range.upperBound {
                let found = position(index)
                let distance = found >= start ? found - start : found + (blockCount - start)
                if chosen.count < count || distance < chosen[chosen.count - 1].distance {
                    let slot = chosen.firstIndex { $0.distance > distance } ?? chosen.count
                    chosen.insert((distance, found, index), at: slot)
                    if chosen.count > count {
                        chosen.removeLast()
                    }
                }
                index += 1
            }
        }

        let blocks = chosen.map { grid.offset($0.index) ..< grid.offset($0.index) + grid.length($0.index) }
        guard chosen.count == count, let last = chosen.last else {
            return (blocks, start)
        }
        return (blocks, (last.position + 1) % blockCount)
    }

    /// The block of `grid` that holds the byte at `offset`, which lies within the file.
    static func blockIndex(containing offset: UInt64, of grid: FileCompareGrid) -> UInt64 {
        // The first `remainder` blocks hold one byte more than the others.
        let base = grid.size / grid.blockCount
        let remainder = grid.size % grid.blockCount
        let longBlocks = remainder * (base + 1)
        return offset < longBlocks ? offset / (base + 1) : remainder + (offset - longBlocks) / base
    }

    /// The position of block `index` in the ``SMB/FileCompareScan/bisection`` order of `blockCount` blocks, as
    /// ``FileCompareBlockOrder`` emits it, found without walking the order.
    ///
    /// The order takes the first block, the last one, and then the middles of a tree of intervals, level by level and
    /// left to right. The intervals of one level have at most two widths, a width `w` splits into `w / 2` and
    /// `w - w / 2`, and only intervals two or more wide have a middle, so counting the intervals of each width, on the
    /// whole level and to the left of the interval `index` is in, gives the position in at most 64 levels.
    static func bisectionPosition(of index: UInt64, blockCount: UInt64) -> UInt64 {
        if index == 0 {
            return 0
        }
        if index == blockCount - 1 {
            return 1
        }

        /// The middles the intervals of these widths have, each of these many intervals.
        func middles(_ widths: [UInt64: UInt64]) -> UInt64 {
            widths.reduce(0) { $0 + ($1.key >= 2 ? $1.value : 0) }
        }

        /// The widths of the intervals the intervals of these widths split into.
        func split(_ widths: [UInt64: UInt64]) -> [UInt64: UInt64] {
            var result: [UInt64: UInt64] = [:]
            for (width, count) in widths where width >= 2 {
                result[width / 2, default: 0] += count
                result[width - width / 2, default: 0] += count
            }
            return result
        }

        var lower: UInt64 = 0
        var upper = blockCount - 1
        var level: [UInt64: UInt64] = [upper: 1]
        var left: [UInt64: UInt64] = [:]
        var before: UInt64 = 2
        while true {
            let middle = lower + (upper - lower) / 2
            if index == middle {
                return before + middles(left)
            }

            before += middles(level)
            level = split(level)
            left = split(left)
            if index < middle {
                upper = middle
            }
            else {
                left[middle - lower, default: 0] += 1
                lower = middle
            }
        }
    }

    /// Blocks picked for a ``TrustPolicy/sampleBlocks(count:scan:)`` check.
    struct SampleSet {
        /// The blocks, with the bytes the storage holds for them.
        let blocks: [(offset: UInt64, bytes: Data)]
        /// Where the next check picks up, as a position in the block order.
        let cursor: UInt64
    }

    // MARK: Private

    /// What a check started from, to tell whether its result still applies.
    struct CheckSnapshot {
        let id: SMB.CacheFileID
        let contentEpoch: UInt64

        init(_ entry: FileEntry) {
            id = entry.id
            contentEpoch = entry.contentEpoch
        }
    }

    private func isCurrent(_ key: String, _ snapshot: CheckSnapshot) -> Bool {
        files[key].map { $0.id == snapshot.id && $0.contentEpoch == snapshot.contentEpoch } ?? false
    }

    private func markChecked(_ entry: inout FileEntry) {
        entry.lastCheck = Self.uptime()
        entry.statSinceCheck = false
    }

    /// Drops the bytes of the file at `key` after a failed check, unless the file changed since the check started.
    private func failCheck(_ key: String, _ snapshot: CheckSnapshot) {
        guard isCurrent(key, snapshot), let equivalenceKey = files[key]?.equivalenceKey else {
            return
        }

        // Reads in flight may carry bytes of the content that failed.
        changeLog.recordChange(at: equivalenceKey)
        updateEntry(key) { entry in
            dropBlocks(of: &entry)
            entry.contentEpoch += 1
            // Not checked again before it is due, so a server that cannot be checked is not asked on every read.
            markChecked(&entry)
        }
    }

    /// Whether `ranges`, sorted, neither overlapping nor touching, hold every byte of `range`.
    static func holds(_ ranges: [Range<UInt64>], _ range: Range<UInt64>) -> Bool {
        var low = 0
        var high = ranges.count
        while low < high {
            let middle = (low + high) / 2
            if ranges[middle].upperBound <= range.lowerBound {
                low = middle + 1
            }
            else {
                high = middle
            }
        }
        return low < ranges.count && ranges[low].lowerBound <= range.lowerBound
            && ranges[low].upperBound >= range.upperBound
    }

    /// Whether `file` holds `samples` on the server.
    private static func serverHolds(_ samples: [(offset: UInt64, bytes: Data)], file: SMB.File) async throws -> Bool {
        for sample in samples {
            let received = try await file.read(upTo: Int64(sample.bytes.count), atOffset: sample.offset)
            if received != sample.bytes {
                return false
            }
        }
        return true
    }
}
