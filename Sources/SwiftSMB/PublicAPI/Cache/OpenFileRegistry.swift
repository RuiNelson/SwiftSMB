//
// Part of SwiftSMB
// OpenFileRegistry.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// The files open with one cache attachment, across the connection it was attached to and the forks that inherited it,
/// with the path each one reports under.
///
/// A rename through any connection of that family moves the files open at or under its source to the same place under
/// its destination, so they go on reporting under the path the file has now. A delete, or a change that may have
/// removed or replaced the file, stops the files open there from reporting: a write to a file no longer at its path
/// must not create cache entries for that path. Such a file is silenced rather than forgotten: it keeps the paths it
/// may still be at, and a change through it invalidates them, since a path may still lead to it.
///
/// A file is registered before the server opens it, so that a rename or a delete of its path while it is being opened
/// reaches it: the server may have opened the file on either side of that change, so it is silenced.
///
/// Paths are compared as sent to the server, after validation, byte by byte to tell which files a rename or a delete
/// reaches. Changes count against the files open at paths that may name the same entry, regardless of case and Unicode
/// normalization, and changes by path are related to one another the same way, since the share may ignore either. The
/// share root is the empty string.
///
/// A file's report and a rename of the file can overlap: the report may land in the cache on either side of
/// ``SMB/BlockLevelReadCache/didRename(from:to:)``. Each report therefore runs between
/// ``beginReport(_:_:since:range:)`` and ``endReport(_:_:)``, and each rename between ``beginRename(from:to:change:)``
/// and ``finishRename(_:)``. A report that overlapped a rename names the paths its bytes may have reached wrongly,
/// which the caller then invalidates.
///
/// A report can also describe the file as it was before another change at its path: a stat or a write the server
/// answered before that change, reported after it. Changes reported through the family count against the files open
/// where they happened, and a report that a change overlapped, from the ``changeCounts(of:)`` taken before its server
/// call to its end, names its path to invalidate. A stat is overlapped by any change; written bytes by changes other
/// than writes, and by writes through other handles to bytes they also wrote, so that writes to different parts of a
/// file through several handles keep their bytes.
///
/// Changes by path, renames included, can reach the cache in the other order than the server applied them too. Each
/// runs from ``beginChange()``, taken before its server call, to ``endChange(_:)``, called after its report, and is
/// logged in between, before its report: the later of two related changes to reach the cache finds the other in the
/// log, and names the paths either may have left wrong.
final class OpenFileRegistry: Sendable {
    /// What a report is about, which decides the changes it counts and those that overlap it.
    enum ReportKind: Equatable, Sendable {
        /// A read's lookup and the store that may follow it, which the cache checks against changes by their request:
        /// overlapped only by renames and deletes.
        case read
        /// An invalidation that is not itself a change: overlapped only by renames and deletes.
        case invalidation
        /// Metadata the server reported: overlapped by every change.
        case stat
        /// Bytes written or appended: a change that counts against every file open at the path, overlapped by changes
        /// other than writes, and by writes to the same bytes.
        case write
        /// New metadata or contents, which the report invalidates: a change that counts against every file open at the
        /// path.
        case attributes
    }

    /// Changes counted against a file so far.
    struct ChangeCounts: Equatable, Sendable {
        /// Writes and appends reported by files open at the path.
        var writes: UInt64 = 0
        /// Every other change at the path or a directory above it, other than renames.
        var others: UInt64 = 0
    }

    /// A write a report is about: the bytes it wrote, or `nil` when the server decides where they land, and its own
    /// count among the file's writes.
    struct WriteMark: Equatable, Sendable {
        let range: Range<UInt64>?
        let count: UInt64
    }

    /// What a report started from, to tell whether a rename, a delete, or another change overlapped it.
    struct ReportTicket: Equatable, Sendable {
        /// The paths to report under: the path the file reports under, or, for a file that stopped reporting, the paths
        /// it may still be at.
        let paths: [String]
        /// Whether the file reports under ``path``. A file that stopped reporting invalidates ``paths`` instead.
        let reports: Bool
        /// The file's renames when the report started.
        let renames: UInt64
        /// Whether no rename of the file was in progress when the report started.
        let quiet: Bool
        /// The change counts the report expects at its end: the snapshot taken before its server call, with the
        /// report's own change counted.
        let counts: ChangeCounts
        /// Whether writes the report did not expect overlap it.
        let comparesWrites: Bool
        /// Whether other changes the report did not expect overlap it.
        let comparesOthers: Bool
        /// For a write, what it wrote.
        let write: WriteMark?

        /// The path the file reports under.
        var path: String {
            paths[0]
        }
    }

    /// A change by path in progress, from ``beginChange()`` to ``endChange(_:)``.
    struct ChangeTicket: Hashable, Sendable {
        fileprivate let id: UInt64
    }

    /// A rename in progress, from ``beginRename(from:to:change:)`` to ``finishRename(_:)``.
    struct Rename: Sendable {
        let from: String
        let to: String
        /// The files the rename moves.
        fileprivate let files: [UInt64]
        /// Paths reports of the files the rename replaced had reached during another rename, still to invalidate.
        let orphanedStrayPaths: [String]
    }

    /// Most writes remembered per file. A write report whose snapshot is older than all of them is taken as overlapped.
    static let writeLimit = 64

    /// Most changes logged. A change that began before the oldest of them is taken as overlapped by a rename.
    static let logLimit = 4096

    /// Most paths a silenced file keeps.
    static let candidateLimit = 32

    private let state = Protected(State(), label: "com.ruinelson.SwiftSMB.OpenFileRegistry.state")

    // MARK: Files

    /// Registers a file about to be opened at `path`, before the server opens it. Call ``finishOpen(_:)`` once it is
    /// open, or ``unregister(_:)`` if the open fails.
    ///
    /// - Returns: The file's registration.
    func beginOpen(path: String) -> UInt64 {
        state.withLock { $0.beginOpen(path: path) }
    }

    /// Lets a file the server opened report, unless a change of its path while it was being opened silenced it.
    func finishOpen(_ id: UInt64) {
        state.withLock { $0.finishOpen(id) }
    }

    /// Registers a file opened at `path`.
    ///
    /// - Returns: The file's registration.
    func register(path: String) -> UInt64 {
        state.withLock { state in
            let id = state.beginOpen(path: path)
            state.finishOpen(id)
            return id
        }
    }

    /// Forgets a file that closed, or whose open failed. A file closing while a rename of it is in progress is kept
    /// until the rename is through, to invalidate the paths its reports reached meanwhile.
    func unregister(_ id: UInt64) {
        state.withLock { $0.unregister(id) }
    }

    /// The path the file reports under, or `nil` once it stopped reporting.
    func path(of id: UInt64) -> String? {
        state.withLock { $0.path(of: id) }
    }

    /// The number of files the registry keeps, closed ones kept until a rename is through included.
    var count: Int {
        state.withLock { $0.entries.count }
    }

    // MARK: Reports

    /// The changes counted against the file so far, or `nil` when it stopped reporting. Taken before a server call
    /// whose answer the file reports, and handed to ``beginReport(_:_:since:range:)``.
    func changeCounts(of id: UInt64) -> ChangeCounts? {
        state.withLock { $0.changeCounts(of: id) }
    }

    /// Starts a report of the file, or returns `nil` when there is nothing to report.
    ///
    /// A ``ReportKind/write`` or ``ReportKind/attributes`` report counts as a change against every file open at the
    /// path, this one included, before it reaches the cache. A file that stopped reporting reports only those, as
    /// invalidations of the paths it may still be at.
    ///
    /// - Parameters:
    ///   - kind: What the report is about.
    ///   - snapshot: What ``changeCounts(of:)`` returned before the server call the report is about, or `nil` to count
    /// changes from now on only.
    ///   - range: For a write, the bytes it wrote, or `nil` when the server decides where they land.
    func beginReport(
        _ id: UInt64,
        _ kind: ReportKind,
        since snapshot: ChangeCounts?,
        range: Range<UInt64>? = nil
    ) -> ReportTicket? {
        state.withLock { $0.beginReport(id, kind, since: snapshot, range: range) }
    }

    /// Whether nothing that may have made the file's path lead elsewhere happened since the report began: no rename of
    /// the file, and nothing that stopped it reporting. What the cache answered for the report describes the file only
    /// then.
    func isCurrent(_ id: UInt64, _ ticket: ReportTicket) -> Bool {
        state.withLock { $0.isCurrent(id, ticket) }
    }

    /// Ends a report of the file.
    ///
    /// - Returns: Paths the caller must invalidate, because a rename, a delete, or another change at the file's path
    /// overlapped the report: empty when none did, or when a rename still in progress will take care of them.
    func endReport(_ id: UInt64, _ ticket: ReportTicket) -> [String] {
        state.withLock { $0.endReport(id, ticket) }
    }

    // MARK: Changes by path

    /// Starts a change by path, before its server call. End it with ``endChange(_:)`` once it is reported, whether it
    /// succeeded or not.
    func beginChange() -> ChangeTicket {
        state.withLock { $0.beginChange() }
    }

    /// Counts a change at `paths`, other than a write or a rename, against the files open at or under them, so that
    /// their reports it overlaps are invalidated. Called before the cache hears of the change.
    ///
    /// - Parameter change: The change, which this logs.
    func noteChanges(atOrUnder paths: [String], change: ChangeTicket? = nil) {
        state.withLock { state in
            state.countChange(atOrUnder: paths, \.others)
            state.logChange(change, paths: paths, isRename: false)
        }
    }

    /// Ends a change by path, once the cache has heard of it.
    ///
    /// - Returns: Paths to invalidate, because a rename and another change at related paths overlapped, and the cache
    /// may have heard of them in the other order than the server applied them: the change's own paths, and where the
    /// renames moved them.
    func endChange(_ change: ChangeTicket) -> [String] {
        state.withLock { $0.endChange(change) }
    }

    /// Stops the files open at or under any of `paths` from reporting, as after a delete, or a change that may have
    /// replaced them. They may still be where they were, unless the server confirmed it removed them.
    ///
    /// - Parameters:
    ///   - change: The change, which this logs.
    ///   - removed: Whether the server confirmed it removed what was at `paths`, so the files no longer have a path.
    /// - Returns: Paths reports of those files reached during a rename still in progress, for the caller to invalidate.
    func stopReporting(atOrUnder paths: [String], change: ChangeTicket? = nil, removed: Bool = false) -> [String] {
        state.withLock { state in
            state.logChange(change, paths: paths, isRename: false)
            return state.silence { path in
                guard paths.contains(where: { RegistryPath.isPath(path, atOrUnder: $0) }) else {
                    return nil
                }
                return removed ? [] : [path]
            }
        }
    }

    /// Stops the files open at or under `from` or `to` from reporting, after a rename whose call failed: it may have
    /// moved the files at `from`, and replaced those at `to`, or not.
    ///
    /// - Parameter change: The change, which this logs.
    /// - Returns: Paths reports of those files reached during a rename still in progress, for the caller to invalidate.
    func stopReportingAfterFailedRename(from: String, to: String, change: ChangeTicket? = nil) -> [String] {
        state.withLock { state in
            state.logChange(change, paths: [from, to], isRename: false)
            return state.silence { path in
                if RegistryPath.isPath(path, atOrUnder: from) {
                    return [path, RegistryPath.rebase(path, from: from, to: to)]
                }
                return RegistryPath.isPath(path, atOrUnder: to) ? [path] : nil
            }
        }
    }

    // MARK: Renames

    /// Starts moving the files open at or under `from` to the same place under `to`, after the server renamed `from`.
    ///
    /// Files open at or under `to`, other than those moving, were replaced: they stop reporting. Files being opened at
    /// or under either path may have been opened on either side of the rename: they stop reporting too.
    ///
    /// - Parameter change: The rename, which this logs.
    func beginRename(from: String, to: String, change: ChangeTicket? = nil) -> Rename {
        state.withLock { $0.beginRename(from: from, to: to, change: change) }
    }

    /// Moves the files of `rename` to their new paths, once the cache has heard of the rename.
    ///
    /// - Returns: Paths to invalidate: those that reports overlapping the rename reached, and the new paths of their
    /// files.
    func finishRename(_ rename: Rename) -> [String] {
        state.withLock { $0.finishRename(rename) }
    }
}

// MARK: - State

private extension OpenFileRegistry {
    struct Entry {
        enum Phase {
            /// Registered before the server opened it.
            case opening
            /// Reporting under ``Entry/paths``' only path.
            case open
            /// Stopped reporting: changes through it invalidate ``Entry/paths``, where it may still be.
            case silenced
            /// Closed during a rename, kept only until the rename is through to invalidate its stray paths.
            case closed
        }

        var phase: Phase
        var paths: [String]
        /// Renames of the file begun so far.
        var renames: UInt64 = 0
        /// Renames of the file in progress.
        var renamesInProgress = 0
        /// Changes counted against the file so far.
        var counts = ChangeCounts()
        /// The latest writes counted against the file.
        var writes: [WriteMark] = []
        /// Paths reports reached while a rename of the file was in progress, to invalidate once it is through.
        var strayPaths: [String] = []

        var isReporting: Bool {
            phase == .open
        }
    }

    /// A change by path logged before its report.
    struct LoggedChange {
        let sequence: UInt64
        let paths: [String]
        let isRename: Bool
    }

    /// A change by path in progress.
    struct OpenChange {
        /// ``State/sequence`` when the change began.
        let snapshot: UInt64
        /// The change, once logged.
        var logged: LoggedChange?
    }

    struct State {
        var nextID: UInt64 = 0
        /// The files that still report to the cache, or may still be at a path, by registration.
        var entries: [UInt64: Entry] = [:]

        var sequence: UInt64 = 0
        var log: [LoggedChange] = []
        /// The newest sequence dropped from the log for its limit.
        var logFloor: UInt64 = 0
        var changes: [UInt64: OpenChange] = [:]
        var nextChangeID: UInt64 = 0

        mutating func beginOpen(path: String) -> UInt64 {
            nextID += 1
            entries[nextID] = Entry(phase: .opening, paths: [path])
            return nextID
        }

        mutating func finishOpen(_ id: UInt64) {
            if entries[id]?.phase == .opening {
                entries[id]?.phase = .open
            }
        }

        mutating func unregister(_ id: UInt64) {
            if let entry = entries[id], entry.renamesInProgress > 0 {
                entries[id]?.phase = .closed
            }
            else {
                entries[id] = nil
            }
        }

        func path(of id: UInt64) -> String? {
            entries[id].flatMap { $0.isReporting ? $0.paths.first : nil }
        }

        func changeCounts(of id: UInt64) -> ChangeCounts? {
            entries[id].flatMap { $0.isReporting ? $0.counts : nil }
        }

        mutating func beginReport(
            _ id: UInt64,
            _ kind: ReportKind,
            since snapshot: ChangeCounts?,
            range: Range<UInt64>?
        ) -> ReportTicket? {
            guard let entry = entries[id] else {
                return nil
            }

            switch entry.phase {
            case .opening, .closed:
                return nil

            case .silenced:
                guard kind == .write || kind == .attributes, !entry.paths.isEmpty else {
                    return nil
                }
                countChange(atOrUnder: entry.paths, kind == .write ? \.writes : \.others, range: range)
                return ReportTicket(
                    paths: entry.paths,
                    reports: false,
                    renames: entry.renames,
                    quiet: entry.renamesInProgress == 0,
                    counts: entry.counts,
                    comparesWrites: false,
                    comparesOthers: false,
                    write: nil
                )

            case .open:
                break
            }

            var expected = snapshot ?? entry.counts
            var write: WriteMark?
            switch kind {
            case .write:
                countChange(atOrUnder: entry.paths, \.writes, range: range)
                expected.writes &+= 1
                write = WriteMark(range: range, count: entries[id]?.counts.writes ?? 0)

            case .attributes:
                countChange(atOrUnder: entry.paths, \.others)
                expected.others &+= 1

            case .read, .invalidation, .stat:
                break
            }

            return ReportTicket(
                paths: entry.paths,
                reports: true,
                renames: entry.renames,
                quiet: entry.renamesInProgress == 0,
                counts: expected,
                comparesWrites: kind == .stat,
                comparesOthers: kind == .stat || kind == .write,
                write: write
            )
        }

        func isCurrent(_ id: UInt64, _ ticket: ReportTicket) -> Bool {
            guard let entry = entries[id] else {
                return false
            }
            return entry.isReporting && ticket.quiet && entry.renamesInProgress == 0 && entry.renames == ticket.renames
        }

        mutating func endReport(_ id: UInt64, _ ticket: ReportTicket) -> [String] {
            // Forgotten while the report was on its way: it may have recreated what a delete dropped.
            guard let entry = entries[id] else {
                return ticket.paths
            }

            // A file that stopped reporting while the report was on its way may have left its path, and the report may
            // have recreated what a delete dropped.
            let changed = (ticket.reports && !entry.isReporting)
                || (ticket.comparesWrites && entry.counts.writes != ticket.counts.writes)
                || (ticket.comparesOthers && entry.counts.others != ticket.counts.others)
                || overlappingWrite(in: entry, since: ticket)
            if ticket.quiet, entry.renames == ticket.renames, !changed {
                return []
            }

            if entry.renamesInProgress > 0 {
                entries[id]?.strayPaths += ticket.paths
                return []
            }

            return RegistryPath.unique(ticket.paths + entry.paths)
        }

        mutating func beginChange() -> ChangeTicket {
            nextChangeID += 1
            changes[nextChangeID] = OpenChange(snapshot: sequence)
            return ChangeTicket(id: nextChangeID)
        }

        mutating func endChange(_ change: ChangeTicket) -> [String] {
            defer { pruneLog() }
            guard let open = changes.removeValue(forKey: change.id), let own = open.logged else {
                return []
            }

            var paths = own.paths
            var related = open.snapshot < logFloor
            for other in log where other.sequence > open.snapshot && other.sequence != own.sequence {
                guard own.isRename || other.isRename else {
                    continue
                }

                // Compared as paths that may name the same entry: the share may ignore case or normalization.
                let touches = paths.contains { path in
                    other.paths.contains { RegistryPath.mayBeRelated(path, $0) }
                }
                guard touches else {
                    continue
                }
                related = true

                // Where the other rename moved what this change touched, or what it moved out from under it.
                if other.isRename {
                    let (from, to) = (other.paths[0], other.paths[1])
                    for path in paths {
                        if RegistryPath.mayName(path, atOrUnder: from) {
                            // Component by component, since `path` may spell `from` differently.
                            paths.append(CachePath.rebase(path, from: from, to: to))
                        }
                        else if RegistryPath.mayName(from, atOrUnder: path) {
                            paths.append(to)
                        }
                    }
                    paths = RegistryPath.unique(paths)
                }
            }

            return related ? paths : []
        }

        mutating func beginRename(from: String, to: String, change: ChangeTicket?) -> Rename {
            logChange(change, paths: [from, to], isRename: true)

            var moving: [UInt64] = []
            var orphaned: [String] = []
            for (id, entry) in entries {
                switch entry.phase {
                case .closed:
                    continue

                case .opening:
                    if let path = entry.paths.first, RegistryPath.isPath(path, atOrUnder: from) {
                        entries[id]?.phase = .silenced
                        entries[id]?.paths = RegistryPath.unique([path, RegistryPath.rebase(path, from: from, to: to)])
                    }
                    else if let path = entry.paths.first, RegistryPath.isPath(path, atOrUnder: to) {
                        entries[id]?.phase = .silenced
                    }

                case .open:
                    if RegistryPath.isPath(entry.paths[0], atOrUnder: from) {
                        moving.append(id)
                        entries[id]?.renames += 1
                        entries[id]?.renamesInProgress += 1
                    }
                    else if RegistryPath.isPath(entry.paths[0], atOrUnder: to) {
                        // Replaced: the file no longer has a path.
                        orphaned += entry.strayPaths
                        entries[id]?.strayPaths = []
                        entries[id]?.phase = .silenced
                        entries[id]?.paths = []
                    }

                case .silenced:
                    // A path the rename replaced no longer leads to the file.
                    let kept = entry.paths.filter {
                        !RegistryPath.isPath($0, atOrUnder: to) || RegistryPath.isPath($0, atOrUnder: from)
                    }
                    entries[id]?.paths = kept
                    if kept.contains(where: { RegistryPath.isPath($0, atOrUnder: from) }) {
                        moving.append(id)
                        entries[id]?.renames += 1
                        entries[id]?.renamesInProgress += 1
                    }
                }
            }

            return Rename(from: from, to: to, files: moving, orphanedStrayPaths: orphaned)
        }

        mutating func finishRename(_ rename: Rename) -> [String] {
            var stray = rename.orphanedStrayPaths
            for id in rename.files {
                guard var entry = entries[id] else {
                    continue
                }

                entry.paths = RegistryPath.unique(entry.paths.map { path in
                    RegistryPath.isPath(path, atOrUnder: rename.from)
                        ? RegistryPath.rebase(path, from: rename.from, to: rename.to)
                        : path
                })
                entry.renamesInProgress -= 1
                if entry.renamesInProgress == 0, !entry.strayPaths.isEmpty {
                    stray += entry.strayPaths + entry.paths
                    entry.strayPaths = []
                }

                entries[id] = entry.phase == .closed && entry.renamesInProgress == 0 ? nil : entry
            }

            return RegistryPath.unique(stray)
        }

        /// Silences the files open or being opened where `paths` gives the paths each may still be at, and adds those
        /// of files already silenced.
        ///
        /// - Returns: Paths reports of the silenced files reached during a rename still in progress.
        mutating func silence(_ paths: (String) -> [String]?) -> [String] {
            var stray: [String] = []
            for (id, entry) in entries {
                switch entry.phase {
                case .closed:
                    continue

                case .opening, .open:
                    guard let path = entry.paths.first, let candidates = paths(path) else {
                        continue
                    }
                    entries[id]?.phase = .silenced
                    entries[id]?.paths = RegistryPath.unique(candidates)
                    stray += entry.strayPaths
                    entries[id]?.strayPaths = []

                case .silenced:
                    let added = entry.paths.flatMap { paths($0) ?? [] }
                    if !added.isEmpty {
                        entries[id]?.paths = Array(
                            RegistryPath.unique(entry.paths + added).prefix(OpenFileRegistry.candidateLimit)
                        )
                    }
                }
            }
            return RegistryPath.unique(stray)
        }

        /// Counts a change of the kind `counter` names against the files at or under `paths`, or under paths that may
        /// name the same entries: a file opened as `Photo.jpg` is changed by a write through a handle opened as
        /// `photo.jpg` on a share that ignores case, and counting a change against a file it did not reach only makes
        /// the file's overlapped reports invalidate their paths.
        ///
        /// - Parameter range: For a write, the bytes it wrote, or `nil` when unknown.
        mutating func countChange(
            atOrUnder paths: [String],
            _ counter: WritableKeyPath<ChangeCounts, UInt64>,
            range: Range<UInt64>? = nil
        ) {
            let changed = paths.map(CachePath.equivalenceKey)
            for (id, entry) in entries where entry.phase != .closed && entry.paths.contains(where: { path in
                let key = CachePath.equivalenceKey(path)
                return changed.contains { RegistryPath.isPath(key, atOrUnder: $0) }
            }) {
                entries[id]?.counts[keyPath: counter] &+= 1
                if counter == \ChangeCounts.writes, let count = entries[id]?.counts.writes {
                    entries[id]?.writes.append(WriteMark(range: range, count: count))
                    if entry.writes.count >= OpenFileRegistry.writeLimit {
                        entries[id]?.writes.removeFirst()
                    }
                }
            }
        }

        /// Whether a write through another handle, counted against the file since the snapshot of `ticket`, wrote bytes
        /// the report also wrote: the server may have applied the two in the other order than their reports reach the
        /// cache.
        func overlappingWrite(in entry: Entry, since ticket: ReportTicket) -> Bool {
            guard let own = ticket.write else {
                return false
            }

            let since = ticket.counts.writes &- 1
            guard entry.counts.writes > since else {
                return false
            }

            // Writes counted since then, other than this one, that the file no longer remembers: taken as overlapping.
            let remembered = entry.writes.filter { $0.count > since }
            if UInt64(remembered.count) < entry.counts.writes - since {
                return true
            }

            return remembered.contains { write in
                guard write.count != own.count else {
                    return false
                }
                guard let range = write.range, let ownRange = own.range else {
                    return true
                }
                return range.overlaps(ownRange)
            }
        }

        /// Logs `change`, about to be reported.
        mutating func logChange(_ change: ChangeTicket?, paths: [String], isRename: Bool) {
            guard let change, changes[change.id] != nil else {
                return
            }

            sequence += 1
            let logged = LoggedChange(sequence: sequence, paths: paths, isRename: isRename)
            changes[change.id]?.logged = logged
            log.append(logged)
        }

        /// Drops the logged changes no change in progress began before.
        mutating func pruneLog() {
            let oldest = changes.values.map(\.snapshot).min() ?? sequence
            log.removeAll { $0.sequence <= oldest }
            if log.count > OpenFileRegistry.logLimit {
                let dropped = log.prefix(log.count - OpenFileRegistry.logLimit)
                logFloor = dropped.last?.sequence ?? logFloor
                log.removeFirst(dropped.count)
            }
        }
    }
}

// MARK: - Paths

/// Path arithmetic on share-relative paths as the connection sends them to the server: `/` separators, no leading `/`,
/// no `.` components, and the empty string for the share root. Paths are compared byte by byte, except by
/// ``mayName(_:atOrUnder:)`` and ``mayBeRelated(_:_:)``.
enum RegistryPath {
    /// Whether `first` and `second` hold the same bytes.
    static func sameBytes(_ first: String, _ second: String) -> Bool {
        first.utf8.elementsEqual(second.utf8)
    }

    /// Whether `path` is `ancestor` itself or lies under it, comparing bytes. Every path lies under the share root.
    static func isPath(_ path: String, atOrUnder ancestor: String) -> Bool {
        if ancestor.isEmpty || sameBytes(path, ancestor) {
            return true
        }
        let pathBytes = path.utf8
        let ancestorBytes = ancestor.utf8
        return pathBytes.count > ancestorBytes.count
            && pathBytes.starts(with: ancestorBytes)
            && pathBytes.dropFirst(ancestorBytes.count).first == UInt8(ascii: "/")
    }

    /// `path`, which is `from` or lies under it, moved to the same place under `to`.
    static func rebase(_ path: String, from: String, to: String) -> String {
        guard !sameBytes(path, from) else {
            return to
        }
        let skipped = from.isEmpty ? 0 : from.utf8.count + 1
        let relative = String(decoding: path.utf8.dropFirst(skipped), as: UTF8.self)
        return to.isEmpty ? relative : to + "/" + relative
    }

    /// Whether `path` is `ancestor`, or lies under it, when compared regardless of case and Unicode normalization: the
    /// share may take them to name the same entry.
    static func mayName(_ path: String, atOrUnder ancestor: String) -> Bool {
        isPath(CachePath.equivalenceKey(path), atOrUnder: CachePath.equivalenceKey(ancestor))
    }

    /// Whether one of the paths may name the other, or an entry under it; see ``mayName(_:atOrUnder:)``.
    static func mayBeRelated(_ first: String, _ second: String) -> Bool {
        mayName(first, atOrUnder: second) || mayName(second, atOrUnder: first)
    }

    /// `paths` without repeats, compared byte by byte, in their order.
    static func unique(_ paths: [String]) -> [String] {
        var seen = Set<[UInt8]>()
        return paths.filter { seen.insert(Array($0.utf8)).inserted }
    }
}
