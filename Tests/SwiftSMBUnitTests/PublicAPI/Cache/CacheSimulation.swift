//
// Part of SwiftSMB
// CacheSimulation.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

/// A client and a server in miniature, around a real ``SMB/ReferenceCache`` and a real ``OpenFileRegistry``.
///
/// The simulated client makes, for each operation, the calls ``SMB/Connection`` and ``SMB/File`` make, in their order,
/// against a ``SimulatedServer``. It makes them one step at a time, where a step is one server call, one registry call,
/// or one cache call, and the steps of the operations in flight together interleave in an order drawn from the seed,
/// the way tasks interleave. Every change to the server goes through the client, so the cache hears of all of them.
///
/// Everything the cache answers is checked against the server: bytes, stats, and listings must show what the server
/// held at some moment since the oldest change still in flight began, and what it holds now when none is. The cache's
/// own invariants are checked after every step, and whenever nothing is in flight an audit reads every file back
/// through the cache.
///
/// Paths are spelled in several ways that the server may take to name one entry: in another case, and in another
/// Unicode normalization. The server compares them as its ``SimulatedServerRules`` say, and the checks follow the
/// server.
final class CacheSimulation {
    /// The limits of the in-memory storage the cache keeps its bytes in.
    struct StorageLimits: Sendable {
        var byteBudget = 256 * 1024 * 1024
        var maximumFileSize: UInt64?
    }

    struct Options: CustomStringConvertible, Sendable {
        var configuration: SMB.ReferenceCache.Configuration

        var limits = StorageLimits()

        /// How the server compares names, and whether it refuses to rename or delete open files.
        var server = SimulatedServerRules.samba

        /// Whether paths are also spelled in another case and another Unicode normalization. Only with a server that
        /// refuses to rename or delete open files: renames and deletes reach open files only by the spelling they were
        /// opened with.
        var spellsPathsDifferently = true

        /// Most operations in flight together.
        var concurrency = 1

        /// Steps taken before the last audit.
        var steps = 400

        /// Whether there are only a few places a file can be, so that most operations in flight together are about the
        /// same file.
        var crowded = false

        /// Whether changes whose outcome depends on which of them the server applies first may be in flight together:
        /// writes to the same bytes through two handles, and renames, deletes, creations, and size changes of paths at
        /// or under one another.
        var racesChanges = false

        /// Whether a read takes its registry ticket and makes its lookup as two steps, with others in between, rather
        /// than as one.
        var splitsReadLookups = false

        /// Whether a file may be opened while a change to its path by name is in flight, and registers only at the end
        /// of its open, as in the client: a rename or a delete of the path can then land between the server opening the
        /// file and the registry hearing of it. Otherwise no such change overlaps an open, and the file is registered
        /// in the step that opens it.
        var racesOpens = false

        /// Whether other steps can come between a report of an open file that a change overlapped and the invalidation
        /// the client follows it with, as they can in the client. Otherwise the two reach the cache as one step.
        var exposesOverlappedReports = false

        /// Whether a file may close while a rename is in flight, and a rename start while a file is closing.
        var closesDuringRenames = false

        /// Whether answers must show the modification time a directory has, and not only that it is one.
        var checksDirectoryTimes = false

        /// Whether a file that stopped reporting while a path still leads to it, as after a rename whose call failed
        /// without renaming anything, goes on being written through its handle.
        var writesThroughSilencedHandles = false

        var description: String {
            """
            budget \(limits.byteBudget), maximumFileSize \(limits.maximumFileSize.map(String.init) ?? "nil"), \
            keepsUploads \(configuration.keepsUploads), metadata \(configuration.metadata.debugDescription), \
            pathMatching \(configuration.pathMatching.debugDescription), server [\(server)], \
            spellsPathsDifferently \(spellsPathsDifferently), concurrency \(concurrency), crowded \(crowded), \
            racesChanges \(racesChanges), splitsReadLookups \(splitsReadLookups), racesOpens \(racesOpens), \
            exposesOverlappedReports \(exposesOverlappedReports), closesDuringRenames \(closesDuringRenames), \
            checksDirectoryTimes \(checksDirectoryTimes), writesThroughSilencedHandles \(writesThroughSilencedHandles)
            """
        }
    }

    /// An open file: bound to the file it opened, wherever that file's path goes.
    final class Handle {
        enum Access {
            case readOnly
            case readWrite
            case writeOnly
        }

        let id: Int
        let inode: Int
        let registration: UInt64
        let access: Access
        let appends: Bool
        var offset: UInt64 = 0
        var wroteToFile = false
        var isBusy = false

        var reads: Bool {
            access != .writeOnly
        }

        var writes: Bool {
            access != .readOnly
        }

        init(id: Int, inode: Int, registration: UInt64, access: Access, appends: Bool) {
            self.id = id
            self.inode = inode
            self.registration = registration
            self.access = access
            self.appends = appends
        }
    }

    /// One operation of the client, as the steps it takes.
    final class Operation {
        typealias Step = (CacheSimulation, Operation) async -> Void

        let id: Int
        let name: String

        /// Whether the operation may change the server, so that answers given while it is in flight may show the server
        /// on either side of it.
        let mutates: Bool

        /// The paths the operation changes by name, and the bytes it writes through a handle.
        var paths: [String] = []
        var writes: (inode: Int, range: Range<UInt64>)?

        var steps: [Step]
        var next = 0
        var windowStart = 0

        /// How many of the next steps follow the one being taken at once, with no step of another operation between.
        var immediate = 0

        /// The step before which the operation is held back once, as a task that is not scheduled for a while, and for
        /// how many steps of the simulation.
        var stall: (before: Int, steps: Int)?
        var stalledUntil = 0

        /// Whether the operation closes a file, renames, or reads, and the path it opens.
        var isClose = false
        var isRename = false
        var isRead = false
        var opens: String?
        var handle: Handle?

        /// What a read returned.
        var result: Data?

        init(id: Int, name: String, mutates: Bool, steps: [Step]) {
            self.id = id
            self.name = name
            self.mutates = mutates
            self.steps = steps
        }

        var isFinished: Bool {
            next >= steps.count
        }

        /// Ends the operation where it is.
        func abandon() {
            steps.removeSubrange(next...)
        }
    }

    // MARK: Universe

    /// Every spelling of a directory there can be, and of a file.
    let directoryPaths: [String]
    let filePaths: [String]

    // MARK: State

    let seed: UInt64
    let options: Options
    let cache: SMB.ReferenceCache
    let registry = OpenFileRegistry()
    private(set) var server: SimulatedServer
    private var generator: SeededGenerator

    private var handles: [Handle] = []
    private var inFlight: [Operation] = []

    /// Changes whose report was dropped, with the changes in flight then: see ``windowStart``.
    private var droppedReports: [(windowStart: Int, waitingFor: Set<Int>)] = []

    /// Steps taken so far, and operations held back until a later step: see ``advanceOne()``.
    private var stepCount = 0
    private var nextIdentifier = 0
    private var lastOpened: Handle?
    private var isAuditing = false

    private(set) var log: [String] = []
    private(set) var violations: [String] = []

    /// Lookups the cache answered with bytes, and reads altogether: a simulation whose cache never answers checks
    /// nothing.
    private(set) var hits = 0
    private(set) var reads = 0

    init(seed: UInt64, options: Options) {
        precondition(
            !options.spellsPathsDifferently || options.server.refusesChangesToOpenFiles,
            "Renames and deletes reach open files only by the spelling they were opened with"
        )
        self.seed = seed
        self.options = options

        let directories: [String]
        let names: [String]
        switch (options.spellsPathsDifferently, options.crowded) {
        case (false, false):
            directories = ["a", "b", "c", "a/s", "b/s", "c/s"]
            names = ["f", "g", "h"]

        case (false, true):
            directories = ["a"]
            names = ["f"]

        case (true, false):
            directories = ["a", "A", "b", "a/s", "A/S", "b/s"]
            names = ["f", "F", "\u{E9}", "e\u{301}", "\u{C9}", "g"]

        case (true, true):
            directories = ["a", "A"]
            names = ["f", "F", "\u{E9}", "e\u{301}"]
        }
        directoryPaths = directories
        filePaths = ([""] + directories).flatMap { directory in
            names.map { directory.isEmpty ? $0 : "\(directory)/\($0)" }
        }

        cache = SMB.ReferenceCache(
            storage: SMB.InMemoryCacheStorage(
                byteBudget: options.limits.byteBudget,
                maximumFileSize: options.limits.maximumFileSize
            ),
            configuration: options.configuration
        )
        server = SimulatedServer(rules: options.server)
        generator = SeededGenerator(seed: seed)
    }

    // MARK: Running

    /// Runs the simulation to its end, or to the first thing the cache gets wrong.
    func run() async {
        populate()

        for step in 0 ..< options.steps {
            guard violations.isEmpty else {
                return
            }

            if generator.chance(0.08) {
                server.tick()
                note("server: the clock moves to \(server.clock)")
            }

            if inFlight.isEmpty || (inFlight.count < options.concurrency && generator.chance(0.45)),
               let operation = makeRandomOperation() {
                start(operation, stalling: true)
            }

            await advanceOne()

            if step % 90 == 89 {
                await audit()
            }
        }

        await audit()
    }

    /// The first thing the cache got wrong, with the steps that led to it, or `nil`.
    ///
    /// `SWIFTSMB_CACHE_FUZZ_LOG_LINES` sets how many of the last steps are listed.
    var failure: String? {
        guard let first = violations.first else {
            return nil
        }

        return """
        seed \(seed) [\(options)]
        \(first)
        last steps:
        \(log.suffix(max(CacheFuzz.logLines, 70)).joined(separator: "\n"))
        """
    }

    // MARK: Scheduling

    private func start(_ operation: Operation, stalling: Bool = false) {
        operation.windowStart = server.mutations
        operation.handle?.isBusy = true
        if stalling, options.concurrency > 1, operation.steps.count > 1, generator.chance(0.2) {
            operation.stall = (generator.int(1 ... operation.steps.count - 1), generator.int(6 ... 40))
        }
        if stalling, options.splitsReadLookups, operation.isRead, generator.chance(0.5) {
            operation.stall = (1, generator.int(15 ... 60))
        }
        inFlight.append(operation)
        note(operation, "starts")
    }

    private func advance(_ operation: Operation) async {
        guard !operation.isFinished else {
            finish(operation)
            return
        }

        operation.immediate = 0
        repeat {
            operation.immediate = max(operation.immediate - 1, 0)
            let step = operation.steps[operation.next]
            operation.next += 1
            await step(self, operation)
        }
        while operation.immediate > 0 && !operation.isFinished && violations.isEmpty

        if operation.isFinished {
            finish(operation)
        }

        // An audit takes thousands of steps, one operation at a time: checked once per operation there.
        guard !isAuditing || operation.isFinished else {
            return
        }
        let broken = await cache.invariantViolations()
        if !broken.isEmpty {
            violate("after a step of [\(operation.id) \(operation.name)]: \(broken.joined(separator: "; "))")
        }
    }

    private func finish(_ operation: Operation) {
        inFlight.removeAll { $0 === operation }
        operation.handle?.isBusy = false
    }

    /// Takes the steps of one operation, and nothing else, until it ends.
    private func runToCompletion(_ operation: Operation) async {
        start(operation)
        while !operation.isFinished, violations.isEmpty {
            await advance(operation)
        }
        finish(operation)
    }

    /// Finishes everything in flight, in an order drawn from the seed.
    private func drain() async {
        while !inFlight.isEmpty, violations.isEmpty {
            await advanceOne()
        }
    }

    /// Takes a step of one of the operations in flight, other than those held back, unless all are.
    private func advanceOne() async {
        stepCount += 1
        for operation in inFlight {
            if let stall = operation.stall, operation.next == stall.before {
                operation.stall = nil
                operation.stalledUntil = stepCount + stall.steps
                note(operation, "is held back for \(stall.steps) steps")
            }
        }

        let ready = inFlight.filter { $0.stalledUntil <= stepCount }
        if !ready.isEmpty {
            await advance(generator.pick(ready))
        }
        else if !inFlight.isEmpty {
            await advance(generator.pick(inFlight))
        }
    }

    /// The moment answers may go back to: when the oldest change still in flight began, or now.
    ///
    /// A change whose report was dropped because its file had just stopped reporting counts as in flight until the
    /// changes that were in flight with it are through: one of them silenced the file, and has yet to tell the cache.
    private var windowStart: Int {
        let inFlightIdentifiers = Set(inFlight.map(\.id))
        droppedReports.removeAll { $0.waitingFor.isDisjoint(with: inFlightIdentifiers) }

        let starts = inFlight.filter(\.mutates).map(\.windowStart) + droppedReports.map(\.windowStart)
        return starts.min() ?? server.mutations
    }

    /// Notes that the report of `operation`, a change, was dropped because its file stopped reporting.
    private func noteDroppedReport(_ operation: Operation) {
        note(operation, "the file stopped reporting: nothing is handed to the cache")
        guard !options.exposesOverlappedReports else {
            return
        }

        let others = inFlight.filter { $0.mutates && $0 !== operation }.map(\.id)
        droppedReports.append((operation.windowStart, Set(others)))
    }

    /// Notes that a report of `operation` under `path` ended while a rename of that path is in flight. The registry
    /// leaves the paths of a report a rename overlapped for that rename to invalidate once it is through, so until then
    /// the cache may hold what the report said.
    private func noteReportLeftToRename(_ operation: Operation, path: String) {
        guard !options.exposesOverlappedReports else {
            return
        }

        // The registry compares paths byte by byte.
        let renames = inFlight.filter { rename in
            rename.isRename && rename.paths.contains {
                CachePath.isPath(path, atOrUnder: $0) || CachePath.isPath($0, atOrUnder: path)
            }
        }
        if !renames.isEmpty {
            droppedReports.append((operation.windowStart, Set(renames.map(\.id))))
        }
    }

    /// Whether `operation` and a change in flight could each land before the other with a different outcome.
    private func races(_ operation: Operation) -> Bool {
        guard operation.mutates else {
            return false
        }

        return inFlight.contains { other in
            guard other.mutates else {
                return false
            }
            if let mine = operation.writes, let theirs = other.writes, mine.inode == theirs.inode,
               mine.range.overlaps(theirs.range) {
                return true
            }
            return operation.paths.contains { path in
                other.paths.contains { ServerKey.areRelated(server.key(path), server.key($0)) }
            }
        }
    }

    // MARK: Logging

    private func note(_ line: String) {
        log.append(line)
    }

    private func note(_ operation: Operation, _ line: String) {
        log.append("[\(operation.id) \(operation.name)] \(line)")
    }

    /// Has the next `count` steps of `operation` follow the one being taken at once, unless the simulation exposes what
    /// lies between a report and its invalidation.
    private func glue(_ operation: Operation, _ count: Int = 1) {
        if !options.exposesOverlappedReports {
            operation.immediate = count
        }
    }

    private func violate(_ message: String) {
        violations.append(message)
        log.append("!!! \(message)")
    }

    private static func describe(_ stat: SimulatedServer.Stat?) -> String {
        guard let stat else {
            return "nothing"
        }
        return stat.kind == .file
            ? "file of \(stat.size) bytes at \(stat.modificationTime)/\(stat.changeTime)"
            : "directory at \(stat.modificationTime)"
    }

    private static func describe(_ stat: SMB.Stat) -> String {
        stat.type == .file
            ? "file of \(stat.size) bytes at \(stat.modificationTimeSeconds)/\(stat.changeTimeSeconds)"
            : "\(stat.type) at \(stat.modificationTimeSeconds)"
    }

    private static func describe(_ answer: SMB.CachedStat?) -> String {
        switch answer {
        case nil:
            "no answer"

        case .doesNotExist:
            "does not exist"

        case let .exists(stat):
            describe(stat)
        }
    }

    private static func describe(_ data: Data?) -> String {
        guard let data else {
            return "nothing"
        }
        return "\(data.count) bytes [\(data.prefix(6).map { String($0, radix: 16) }.joined(separator: " "))…]"
    }

    /// `path` with its scalars written out, so that spellings that look alike are told apart in the log.
    private static func spell(_ path: String) -> String {
        guard path.unicodeScalars.contains(where: { !$0.isASCII }) else {
            return path.isEmpty ? "(root)" : path
        }
        return path.unicodeScalars.map { $0.isASCII ? String($0) : "\\u{\(String($0.value, radix: 16))}" }.joined()
    }

    // MARK: Checks

    private static func smbStat(_ stat: SimulatedServer.Stat) -> SMB.Stat {
        switch stat.kind {
        case .file:
            CacheFuzz.file(size: stat.size, modificationTime: stat.modificationTime, changeTime: stat.changeTime)

        case .directory:
            CacheFuzz.directory(modificationTime: stat.modificationTime)
        }
    }

    /// Whether `answer` describes an entry as `stat` does.
    private func describes(_ answer: SMB.Stat, _ stat: SimulatedServer.Stat) -> Bool {
        switch stat.kind {
        case .file:
            answer.type == .file && answer.size == stat.size && answer.modificationTimeSeconds == stat.modificationTime
                && answer.changeTimeSeconds == stat.changeTime

        case .directory:
            answer.type == .directory
                && (!options.checksDirectoryTimes || answer.modificationTimeSeconds == stat.modificationTime)
        }
    }

    /// Whether `answer` describes the entry `inode` is, as it was at some moment since ``windowStart``.
    ///
    /// A change through an open file and a rename or a delete of its path in flight together may land in either order,
    /// so an answer may show the file as a change left it after the path stopped leading to it.
    private func describes(_ answer: SMB.Stat, inode: Int) -> Bool {
        server.stats(of: inode, since: windowStart).contains { describes(answer, $0) }
    }

    /// Checks bytes the cache handed out for the file `inode` is against what that file held since ``windowStart``.
    private func checkBlocks(_ data: Data, inode: Int, offset: UInt64, _ operation: Operation, _ call: String) {
        let candidates = server.contents(of: inode, since: windowStart)
        for (index, byte) in data.enumerated() {
            let position = Int(offset) + index
            guard !candidates.contains(where: { position < $0.count && $0[position] == byte }) else {
                continue
            }

            let held = candidates.map { position < $0.count ? String($0[position], radix: 16) : "nothing" }
            violate(
                """
                [\(operation.id) \(operation.name)] \(call) answered \(Self.describe(data)): byte \(position) is \
                \(String(byte, radix: 16)), while inode \(inode) held \(held) there over the \(candidates.count) \
                states it had since the oldest change in flight began
                """
            )
            return
        }
    }

    /// Checks a stat the cache answered against what was at `path` since ``windowStart``.
    private func checkStat(_ answer: SMB.CachedStat, path: String, _ operation: Operation) {
        let key = server.key(path)
        let matches = server.snapshots(since: windowStart).contains { snapshot in
            switch answer {
            case .doesNotExist:
                snapshot.links[key] == nil

            case let .exists(stat):
                snapshot.links[key].map { describes(stat, inode: $0) } ?? false
            }
        }

        if !matches {
            let held = server.snapshots(since: windowStart).map { snapshot in
                Self.describe(snapshot.links[key].map { server.stat(inode: $0) })
            }
            violate(
                """
                [\(operation.id) \(operation.name)] the cache answered a stat of \(Self.spell(path)) with \
                \(Self.describe(answer)), while the server had \(held) there over the states it had since the oldest \
                change in flight began (now: \(Self.describe(server.stat(path))))
                """
            )
        }
    }

    /// Checks a listing the cache answered against what `path` listed since ``windowStart``. Names are compared by
    /// their scalars, as the server keeps them; `.` and `..` are left out.
    private func checkListing(_ answer: [SMB.DirectoryEntry], path: String, _ operation: Operation) {
        let directory = server.key(path)
        let entries = answer.filter { $0.name != "." && $0.name != ".." }
        let matches = server.snapshots(since: windowStart).contains { snapshot in
            guard let inode = snapshot.links[directory], server.kind(of: inode) == .directory else {
                return false
            }
            let children = snapshot.links.filter { $0.key != directory && $0.key.parent == directory }
            guard children.count == entries.count else {
                return false
            }
            return entries.allSatisfy { entry in
                let child = children.first { key, _ in
                    snapshot.names[key].map { Array($0.unicodeScalars) == Array(entry.name.unicodeScalars) } ?? false
                }
                return child.map { describes(entry.stat, inode: $0.value) } ?? false
            }
        }

        if !matches {
            let listed = entries.map { "\(Self.spell($0.name)): \(Self.describe($0.stat))" }.sorted()
            let held = (server.list(path) ?? []).map {
                "\(Self.spell($0.name)): \(Self.describe(server.stat(inode: $0.inode)))"
            }
            violate(
                """
                [\(operation.id) \(operation.name)] the cache answered a listing of \(Self.spell(path)) with \
                \(listed), while the server lists \(held) now, and nothing like the answer over the states it had \
                since the oldest change in flight began
                """
            )
        }
    }

    // MARK: Setup

    /// Puts directories and files on the server before the cache hears of anything.
    private func populate() {
        for directory in directoryPaths where generator.chance(0.7) {
            _ = server.makeDirectory(directory)
        }
        for path in filePaths where generator.chance(options.crowded ? 0.8 : 0.4) {
            if let inode = server.open(path, create: true, truncate: false) {
                server.write(inode, at: 0, generator.bytes(generator.int(0 ... 120)))
                server.close(inode)
            }
        }
        note("server: starts with \(server.existingPaths.map(Self.spell))")
    }

    // MARK: Audit

    /// With nothing in flight, reads everything back through the cache: through the handles that stayed open, which no
    /// stat stands in front of, through files opened anew, and through stats and listings.
    private func audit() async {
        await drain()
        guard violations.isEmpty else {
            return
        }
        note("--- audit ---")
        isAuditing = true
        defer { isAuditing = false }

        for handle in handles where handle.reads {
            guard let path = registry.path(of: handle.registration) else {
                continue
            }

            let content = server.content(of: handle.inode)
            var position = 0
            while position < content.count + 4 {
                let upTo = generator.int(1 ... 48)
                let answer = await CacheFuzz.retrieve(cache, path: path, offset: UInt64(position), upTo: upTo)
                guard let answer else {
                    position += 1
                    continue
                }

                hits += 1
                guard !answer.isEmpty, answer.count <= upTo, position + answer.count <= content.count,
                      content[position ..< position + answer.count] == answer else {
                    violate(
                        """
                        audit: handle \(handle.id), open on inode \(handle.inode) and reporting as \(Self
                            .spell(path)), \
                        was answered \(Self.describe(answer)) at \(position) for a read of up to \(upTo), while the \
                        file holds \(content.count) bytes, \
                        \(Self.describe(position < content.count ? Data(content[position...].prefix(upTo)) : nil)) \
                        from there
                        """
                    )
                    return
                }
                position += answer.count
            }
        }

        for path in filePaths {
            lastOpened = nil
            await runToCompletion(makeOpen(
                path: path,
                access: .readOnly,
                appends: false,
                create: false,
                truncate: false
            ))
            guard violations.isEmpty else {
                return
            }
            guard let handle = lastOpened else {
                if server.stat(path)?.kind == .file {
                    violate("audit: \(Self.spell(path)) is a file on the server, and could not be opened")
                    return
                }
                continue
            }

            var contents = Data()
            while violations.isEmpty, contents.count < 100_000 {
                let read = makeRead(handle: handle, upTo: generator.int(1 ... 64), repositioning: false)
                await runToCompletion(read)
                guard let chunk = read.result else {
                    break
                }
                contents.append(chunk)
            }

            guard violations.isEmpty else {
                return
            }
            if contents != server.content(of: handle.inode) {
                violate(
                    """
                    audit: reading \(Self.spell(path)) anew returned \(Self.describe(contents)), while the server \
                    holds \(Self.describe(server.content(of: handle.inode)))
                    """
                )
                return
            }
            await runToCompletion(makeClose(handle: handle))
        }

        for path in [""] + directoryPaths + filePaths where violations.isEmpty {
            await runToCompletion(makeStat(path: path))
        }
        for path in [""] + directoryPaths where violations.isEmpty {
            await runToCompletion(makeList(path: path))
        }
        note("--- audit done ---")
    }

    // MARK: Choosing operations

    private func makeRandomOperation() -> Operation? {
        for _ in 0 ..< 8 {
            guard let operation = randomOperation() else {
                continue
            }
            if !options.closesDuringRenames {
                guard !(operation.isClose && inFlight.contains(where: \.isRename)),
                      !(operation.isRename && inFlight.contains(where: \.isClose)) else {
                    continue
                }
            }
            if !options.racesOpens, racesAnOpen(operation) {
                continue
            }
            if options.racesChanges || !races(operation) {
                return operation
            }
        }
        return nil
    }

    /// Whether `operation` opens a path while a change to that path by name is in flight, or changes one that is being
    /// opened: the server may then open the file on either side of the change, whatever the cache has heard.
    private func racesAnOpen(_ operation: Operation) -> Bool {
        inFlight.contains { other in
            let pairs = [(operation.opens, other), (other.opens, operation)]
            return pairs.contains { opened, changing in
                guard let opened, changing.mutates else {
                    return false
                }
                return changing.paths.contains { ServerKey.areRelated(server.key(opened), server.key($0)) }
            }
        }
    }

    private func freeHandle(where matches: (Handle) -> Bool) -> Handle? {
        let free = handles.filter { !$0.isBusy && matches($0) }
        return free.isEmpty ? nil : generator.pick(free)
    }

    /// A free handle to change its file through.
    private func freeHandleForChange(where matches: (Handle) -> Bool) -> Handle? {
        freeHandle { matches($0) && mayChange(through: $0) }
    }

    /// Whether the simulation changes a file through `handle` now. A file that stopped reporting is changed without the
    /// cache hearing of it, which matters only while a path still leads to that file.
    private func mayChange(through handle: Handle) -> Bool {
        options.writesThroughSilencedHandles || registry.path(of: handle.registration) != nil
            || !server.isLinked(handle.inode)
    }

    /// Gives up `operation`, a change through `handle`, if the file stopped reporting since the operation started while
    /// a path still leads to it.
    ///
    /// - Returns: Whether the operation goes on.
    private func goesOn(_ operation: Operation, changingThrough handle: Handle) -> Bool {
        guard !mayChange(through: handle) else {
            return true
        }
        note(operation, "given up: the file stopped reporting while a path still leads to it")
        operation.abandon()
        return false
    }

    /// A file path: mostly one that exists, spelled as the server lists it or in another way.
    private func randomFilePath() -> String {
        let existing = server.existingFiles
        if !existing.isEmpty, generator.chance(0.75) {
            let path = generator.pick(existing)
            // Spelled another way that leads to the same file.
            let alike = filePaths.filter { server.key($0) == server.key(path) }
            return alike.isEmpty || generator.chance(0.5) ? path : generator.pick(alike)
        }
        return generator.pick(filePaths)
    }

    /// A directory path: mostly one that exists.
    private func randomDirectoryPath() -> String {
        let existing = server.existingDirectories
        if !existing.isEmpty, generator.chance(0.7) {
            let path = generator.pick(existing)
            let alike = directoryPaths.filter { server.key($0) == server.key(path) }
            return alike.isEmpty || generator.chance(0.5) ? path : generator.pick(alike)
        }
        return generator.pick(directoryPaths)
    }

    private func randomOpen() -> Operation {
        let path = randomFilePath()
        switch generator.int(0 ... 99) {
        case 0 ..< 45:
            return makeOpen(path: path, access: .readOnly, appends: false, create: false, truncate: false)

        case 45 ..< 60:
            return makeOpen(path: path, access: .readWrite, appends: false, create: false, truncate: false)

        case 60 ..< 68:
            return makeOpen(path: path, access: .writeOnly, appends: false, create: false, truncate: false)

        case 68 ..< 80:
            return makeOpen(path: path, access: .readWrite, appends: false, create: true, truncate: false)

        case 80 ..< 90:
            return makeOpen(
                path: path,
                access: generator.chance(0.5) ? .writeOnly : .readWrite,
                appends: false,
                create: true,
                truncate: true
            )

        default:
            return makeOpen(
                path: path,
                access: generator.chance(0.7) ? .writeOnly : .readWrite,
                appends: true,
                create: generator.chance(0.3),
                truncate: false
            )
        }
    }

    private func randomOperation() -> Operation? {
        guard handles.count < 7 else {
            return freeHandle { _ in true }.map { makeClose(handle: $0) }
        }

        switch generator.int(0 ... 99) {
        case 0 ..< 26:
            guard let handle = freeHandle(where: \.reads) else {
                return randomOpen()
            }
            return makeRead(handle: handle, upTo: generator.int(1 ... 64), repositioning: generator.chance(0.3))

        case 26 ..< 40:
            guard let handle = freeHandleForChange(where: { $0.writes && !$0.appends }) else {
                return randomOpen()
            }
            if generator.chance(0.5) {
                handle.offset = UInt64(generator.int(0 ... server.content(of: handle.inode).count + 8))
            }
            return makeWrite(handle: handle, data: generator.bytes(generator.int(1 ... 40)))

        case 40 ..< 44:
            guard let handle = freeHandleForChange(where: \.appends) else {
                return randomOpen()
            }
            return makeAppend(handle: handle, data: generator.bytes(generator.int(1 ... 30)))

        case 44 ..< 56:
            return randomOpen()

        case 56 ..< 63:
            return freeHandle { _ in true }.map { makeClose(handle: $0) }

        case 63 ..< 71:
            return makeStat(path: generator.chance(0.7) ? randomFilePath() : randomDirectoryPath())

        case 71 ..< 76:
            return makeList(path: generator.chance(0.2) ? "" : randomDirectoryPath())

        case 76 ..< 83:
            if generator.chance(0.75) {
                let from = randomFilePath()
                // Sometimes a rename that only respells the name.
                let alike = filePaths.filter { server.key($0) == server.key(from) && $0 != from }
                let to = !alike.isEmpty && generator.chance(0.2) ? generator.pick(alike) : generator.pick(filePaths)
                return makeRename(from: from, to: to)
            }
            let from = randomDirectoryPath()
            let sameDepth = directoryPaths.filter { SimulatedServer.depth($0) == SimulatedServer.depth(from) }
            return makeRename(from: from, to: generator.pick(sameDepth))

        case 83 ..< 87:
            return makeDeleteFile(path: randomFilePath())

        case 87 ..< 89:
            return makeDeleteDirectory(path: randomDirectoryPath())

        case 89 ..< 92:
            return makeCreateDirectory(path: generator.pick(directoryPaths))

        case 92 ..< 94:
            return makeSetSize(path: randomFilePath(), size: UInt64(generator.int(0 ... 130)))

        case 94 ..< 96:
            return freeHandleForChange(where: \.writes).map {
                makeSetSize(handle: $0, size: UInt64(generator.int(0 ... 130)))
            }

        case 96 ..< 98:
            return freeHandle { _ in true }.map { makeFileStat(handle: $0) }

        default:
            let path = generator.chance(0.8) ? randomFilePath() : randomDirectoryPath()
            // Any time, one the entry had before included.
            let time = server.clock - UInt64(generator.int(0 ... 3))
            return makeSetModificationTime(path: path, time: time)
        }
    }

    // MARK: Operations

    private func makeOperation(_ name: String, mutates: Bool, _ steps: [Operation.Step]) -> Operation {
        nextIdentifier += 1
        return Operation(id: nextIdentifier, name: name, mutates: mutates, steps: steps)
    }

    private static func invalidation(_ path: String) -> Operation.Step {
        { simulation, operation in
            await simulation.cache.invalidate(path: path)
            simulation.note(operation, "invalidate(\(spell(path)))")
        }
    }

    /// The steps of `SMB.Connection.stat(at:)`.
    private func makeStat(path: String) -> Operation {
        let request = SMB.CacheRequestID()
        var answered = false
        var stat: SimulatedServer.Stat?

        return makeOperation("stat \(Self.spell(path))", mutates: false, [
            { simulation, operation in
                let answer = await simulation.cache.retrieveStat(path: path, request: request)
                simulation.note(operation, "retrieveStat -> \(Self.describe(answer))")
                if let answer {
                    simulation.checkStat(answer, path: path, operation)
                    answered = true
                }
            },
            { simulation, operation in
                guard !answered else {
                    return
                }
                stat = simulation.server.stat(path)
                simulation.note(operation, "server: stat -> \(Self.describe(stat))")
            },
            { simulation, operation in
                guard !answered else {
                    return
                }
                await simulation.cache.storeStat(stat.map(Self.smbStat), path: path, request: request)
                simulation.note(operation, "storeStat(\(Self.spell(path)))")
            },
            { simulation, _ in
                await simulation.cache.requestEnded(request)
            },
        ])
    }

    /// The steps of `SMB.Connection.listDirectory(at:)`.
    private func makeList(path: String) -> Operation {
        let request = SMB.CacheRequestID()
        var answered = false
        var entries: [SMB.DirectoryEntry]?

        return makeOperation("list \(Self.spell(path))", mutates: false, [
            { simulation, operation in
                let answer = await simulation.cache.retrieveDirectoryListing(path: path, request: request)
                simulation.note(
                    operation,
                    "retrieveDirectoryListing -> \(answer.map { "\($0.count) entries" } ?? "no answer")"
                )
                if let answer {
                    simulation.checkListing(answer, path: path, operation)
                    answered = true
                }
            },
            { simulation, operation in
                guard !answered else {
                    return
                }
                let server = simulation.server
                guard let listed = server.list(path), let directory = server.inode(at: path) else {
                    simulation.note(operation, "server: list fails")
                    return
                }

                // Samba lists `.` and `..`, which describe the directory and its parent.
                let parent = path.isEmpty ? directory : server.inode(at: CachePath.parent(of: path)) ?? directory
                entries = [
                    CacheFuzz.entry(".", Self.smbStat(server.stat(inode: directory))),
                    CacheFuzz.entry("..", Self.smbStat(server.stat(inode: parent))),
                ] + listed.map { CacheFuzz.entry($0.name, Self.smbStat(server.stat(inode: $0.inode))) }
                simulation.note(operation, "server: list -> \(listed.map { Self.spell($0.name) })")
            },
            { simulation, operation in
                guard !answered, let entries else {
                    return
                }
                await simulation.cache.storeDirectoryListing(entries, path: path, request: request)
                simulation.note(operation, "storeDirectoryListing")
            },
            { simulation, _ in
                await simulation.cache.requestEnded(request)
            },
        ])
    }

    /// The steps of `SMB.Connection.openFile(at:accessMode:options:)`, the stat of the file that a file opened for
    /// reading makes included.
    private func makeOpen(
        path: String,
        access: Handle.Access,
        appends: Bool,
        create: Bool,
        truncate: Bool
    ) -> Operation {
        let changes = create || truncate
        var inode: Int?
        var registration: UInt64?
        var change: OpenFileRegistry.ChangeTicket?
        var registered = false

        let register: Operation.Step = { simulation, operation in
            guard let registration, !registered else {
                return
            }

            registered = true
            guard let inode else {
                simulation.registry.unregister(registration)
                operation.abandon()
                return
            }

            simulation.registry.finishOpen(registration)
            simulation.nextIdentifier += 1
            let handle = Handle(
                id: simulation.nextIdentifier,
                inode: inode,
                registration: registration,
                access: access,
                appends: appends
            )

            // Nothing uses the file before the open returns it.
            handle.isBusy = true
            operation.handle = handle
            simulation.handles.append(handle)
            simulation.lastOpened = handle
            simulation.note(operation, "opens handle \(handle.id) on inode \(inode)")

            // A file opened for reading stats itself for the cache.
            if handle.reads {
                operation.steps += simulation.fileStatSteps(handle)
            }
        }

        let steps: [Operation.Step] = [
            { simulation, operation in
                // Registered before the server opens the file, as the client does.
                registration = simulation.registry.beginOpen(path: path)
                if changes {
                    change = simulation.registry.beginChange()
                }
                inode = simulation.server.open(path, create: create, truncate: truncate)
                simulation.note(
                    operation,
                    "server: open(create: \(create), truncate: \(truncate)) -> \(inode.map { "inode \($0)" } ?? "fails")"
                )
                if inode == nil, !changes {
                    await register(simulation, operation)
                }
                if !simulation.options.racesOpens {
                    await register(simulation, operation)
                }
            },
            { simulation, _ in
                if let change {
                    simulation.registry.noteChanges(atOrUnder: [path], change: change)
                }
            },
            { simulation, operation in
                if changes {
                    await simulation.cache.invalidate(path: path)
                    simulation.note(operation, "invalidate(\(Self.spell(path)))")
                }
            },
            { simulation, operation in
                if let change {
                    simulation.endChange(change, operation)
                }
            },
            register,
        ]

        let flags = [
            "\(access)",
            appends ? "append" : nil,
            create ? "create" : nil,
            truncate ? "truncate" : nil,
        ].compactMap(\.self).joined(separator: "+")
        let operation = makeOperation("open \(Self.spell(path)) \(flags)", mutates: changes, steps)
        operation.paths = changes ? [path] : []
        operation.opens = path
        return operation
    }

    /// The steps of `SMB.File.read(upTo:)` and `SMB.File.read(upTo:atOffset:)` on a file opened for reading with a
    /// cache attached.
    private func makeRead(handle: Handle, upTo: Int, repositioning: Bool) -> Operation {
        if repositioning {
            handle.offset = UInt64(generator.int(0 ... server.content(of: handle.inode).count + 4))
        }

        let request = SMB.CacheRequestID()
        let start = handle.offset
        var ticket: OpenFileRegistry.ReportTicket?
        var cached = Data()
        var fetched: Data?
        var isCurrent = false

        let begin: Operation.Step = { simulation, operation in
            simulation.reads += 1
            ticket = simulation.registry.beginReport(handle.registration, .read, since: nil)
            guard ticket == nil else {
                return
            }

            // The file stopped reporting: the read goes straight to the server.
            let data = simulation.server.read(handle.inode, at: start, upTo: upTo)
            simulation.note(operation, "server: read at \(start) without the cache -> \(Self.describe(data))")
            operation.result = data
            handle.offset = start + UInt64(data?.count ?? 0)
            operation.abandon()
        }

        let lookup: Operation.Step = { simulation, operation in
            guard let ticket else {
                return
            }

            let answer = await simulation.cache.retrieveBlock(
                path: ticket.path,
                offset: start,
                upTo: upTo,
                request: request
            )
            let call = "retrieveBlock(\(Self.spell(ticket.path)), offset: \(start), upTo: \(upTo))"
            simulation.note(operation, "\(call) -> \(Self.describe(answer))")

            // The client drops what the cache answered when the file was renamed or deleted since the read began.
            isCurrent = simulation.registry.isCurrent(handle.registration, ticket)
            guard let answer else {
                return
            }
            guard isCurrent else {
                simulation.note(
                    operation,
                    "the file was renamed or deleted since the read began: the answer is dropped"
                )
                return
            }

            simulation.hits += 1
            if answer.isEmpty {
                simulation.violate("[\(operation.id) \(operation.name)] \(call) answered with no bytes")
            }
            cached = Data(answer.prefix(upTo))
            simulation.checkBlocks(cached, inode: handle.inode, offset: start, operation, call)
        }

        let steps: [Operation.Step] = [
            { simulation, operation in
                guard ticket != nil, cached.count < upTo else {
                    return
                }
                let from = start + UInt64(cached.count)
                fetched = simulation.server.read(handle.inode, at: from, upTo: upTo - cached.count)
                simulation.note(operation, "server: read at \(from) -> \(Self.describe(fetched))")
            },
            { simulation, operation in
                guard let ticket, let fetched, isCurrent else {
                    return
                }
                let from = start + UInt64(cached.count)
                await simulation.cache.storeBlock(
                    fetched,
                    path: ticket.path,
                    offset: from,
                    source: .download,
                    request: request
                )
                simulation.note(operation, "storeBlock(\(Self.spell(ticket.path)), offset: \(from), download)")
            },
            { simulation, operation in
                await simulation.cache.requestEnded(request)
                let data = cached + (fetched ?? Data())
                operation.result = data.isEmpty ? nil : data
                handle.offset = start + UInt64(data.count)
            },
            { simulation, operation in
                guard let ticket else {
                    return
                }
                let paths = simulation.registry.endReport(handle.registration, ticket).sorted()
                if !paths.isEmpty {
                    simulation.note(operation, "the read was overlapped: \(paths.map(Self.spell)) to invalidate")
                }
                for path in paths {
                    operation.steps.append(Self.invalidation(path))
                }
            },
        ]

        let first: [Operation.Step] = if options.splitsReadLookups {
            [begin, lookup]
        }
        else {
            [{ simulation, operation in
                await begin(simulation, operation)
                await lookup(simulation, operation)
            }]
        }

        let operation = makeOperation(
            "read \(upTo) at \(start) through handle \(handle.id)",
            mutates: false,
            first + steps
        )
        operation.handle = handle
        operation.isRead = true
        return operation
    }

    /// Ends a report of `handle`, queueing the invalidations the registry asks for.
    private static func endReport(
        _ handle: Handle,
        _ ticket: OpenFileRegistry.ReportTicket,
        _ simulation: CacheSimulation,
        _ operation: Operation
    ) {
        let paths = simulation.registry.endReport(handle.registration, ticket).sorted()
        if !paths.isEmpty {
            simulation.note(operation, "the report was overlapped: \(paths.map(spell)) to invalidate")
        }
        else {
            simulation.noteReportLeftToRename(operation, path: ticket.path)
        }
        for path in paths {
            operation.steps.append(invalidation(path))
        }
        simulation.glue(operation, paths.count)
    }

    /// The steps of `SMB.File.write(_:)` and `SMB.File.write(_:atOffset:)`, other than appends.
    private func makeWrite(handle: Handle, data: Data) -> Operation {
        let offset = handle.offset
        var snapshot: OpenFileRegistry.ChangeCounts?
        var ticket: OpenFileRegistry.ReportTicket?

        // A write that fails part way: the server acknowledged some of the bytes, and the call that failed may have
        // written some of the rest.
        let fails = generator.chance(0.1)
        let acknowledged = fails ? generator.int(0 ... data.count - 1) : data.count
        let inFlight = data.count - acknowledged
        let landed = fails ? generator.int(acknowledged ... data.count) : data.count

        let operation = makeOperation(
            "write \(data.count) at \(offset) through handle \(handle.id)\(fails ? ", failing after \(acknowledged)" : "")",
            mutates: true,
            [
                { simulation, _ in
                    handle.wroteToFile = true
                    snapshot = simulation.registry.changeCounts(of: handle.registration)
                },
                { simulation, operation in
                    guard simulation.goesOn(operation, changingThrough: handle) else {
                        return
                    }
                    simulation.server.write(handle.inode, at: offset, Data(data.prefix(landed)))
                    handle.offset = offset + UInt64(acknowledged)
                    simulation.note(operation, "server: wrote \(landed) bytes at \(offset) of inode \(handle.inode)")
                },
                { simulation, operation in
                    ticket = simulation.registry.beginReport(
                        handle.registration,
                        .write,
                        since: snapshot,
                        range: offset ..< offset + UInt64(acknowledged + inFlight)
                    )
                    if ticket == nil {
                        simulation.noteDroppedReport(operation)
                        operation.abandon()
                    }
                },
                { simulation, operation in
                    guard let ticket else {
                        return
                    }
                    if !ticket.reports {
                        await simulation.invalidateSilenced(ticket, operation)
                        return
                    }
                    guard inFlight > 0 else {
                        return
                    }
                    await simulation.cache.invalidate(path: ticket.path)
                    simulation.note(
                        operation,
                        "invalidate(\(Self.spell(ticket.path))), for the bytes still on their way"
                    )
                },
                { simulation, operation in
                    guard let ticket, ticket.reports, acknowledged > 0 else {
                        return
                    }
                    await simulation.cache.storeBlock(
                        Data(data.prefix(acknowledged)),
                        path: ticket.path,
                        offset: offset,
                        source: .upload,
                        request: nil
                    )
                    simulation.note(
                        operation,
                        "storeBlock(\(Self.spell(ticket.path)), offset: \(offset), upload, \(acknowledged) bytes)"
                    )
                    simulation.glue(operation)
                },
                { simulation, operation in
                    if let ticket {
                        Self.endReport(handle, ticket, simulation, operation)
                    }
                },
            ]
        )
        operation.handle = handle
        operation.writes = (handle.inode, offset ..< offset + UInt64(data.count))
        return operation
    }

    /// The steps of `SMB.File.write(_:)` on a file opened for appending.
    private func makeAppend(handle: Handle, data: Data) -> Operation {
        var snapshot: OpenFileRegistry.ChangeCounts?
        var ticket: OpenFileRegistry.ReportTicket?

        let fails = generator.chance(0.1)
        let acknowledged = fails ? generator.int(0 ... data.count - 1) : data.count
        let landed = fails ? generator.int(acknowledged ... data.count) : data.count

        let name = "append \(data.count) through handle \(handle.id)\(fails ? ", failing after \(acknowledged)" : "")"
        let operation = makeOperation(name, mutates: true, [
            { simulation, _ in
                handle.wroteToFile = true
                snapshot = simulation.registry.changeCounts(of: handle.registration)
            },
            { simulation, operation in
                guard simulation.goesOn(operation, changingThrough: handle) else {
                    return
                }
                simulation.server.append(handle.inode, Data(data.prefix(landed)))
                simulation.note(operation, "server: appended \(landed) bytes to inode \(handle.inode)")
            },
            { simulation, operation in
                ticket = simulation.registry.beginReport(handle.registration, .write, since: snapshot)
                if ticket == nil {
                    simulation.noteDroppedReport(operation)
                    operation.abandon()
                }
            },
            { simulation, operation in
                guard let ticket else {
                    return
                }
                guard ticket.reports else {
                    await simulation.invalidateSilenced(ticket, operation)
                    return
                }
                await simulation.cache.didAppend(path: ticket.path, byteCount: UInt64(acknowledged))
                simulation.note(operation, "didAppend(\(Self.spell(ticket.path)), \(acknowledged))")
                simulation.glue(operation)
            },
            { simulation, operation in
                if let ticket {
                    Self.endReport(handle, ticket, simulation, operation)
                }
            },
        ])
        operation.handle = handle
        return operation
    }

    /// The steps of `SMB.File.close()`.
    private func makeClose(handle: Handle) -> Operation {
        var snapshot: OpenFileRegistry.ChangeCounts?
        var finalStat: SimulatedServer.Stat?
        var ticket: OpenFileRegistry.ReportTicket?
        var request: SMB.CacheRequestID?
        let statFails = generator.chance(0.1)

        let unregister: Operation.Step = { simulation, operation in
            if let request {
                await simulation.cache.requestEnded(request)
            }
            simulation.registry.unregister(handle.registration)
            simulation.handles.removeAll { $0 === handle }
            simulation.note(operation, "closed")
        }

        let operation = makeOperation("close handle \(handle.id)", mutates: false, [
            { simulation, _ in
                // The final stat is a request of its own.
                if handle.wroteToFile, simulation.registry.changeCounts(of: handle.registration) != nil {
                    let begun = SMB.CacheRequestID()
                    request = begun
                    await simulation.cache.beginRequest(begun)
                }
            },
            { simulation, _ in
                snapshot = simulation.registry.changeCounts(of: handle.registration)
            },
            { simulation, operation in
                // The final stat, made only for a file that was written and still reports. A file opened only for
                // writing cannot stat its handle, so it stats the path it reports under.
                if request != nil, !statFails {
                    switch handle.access {
                    case .readOnly, .readWrite:
                        finalStat = simulation.server.stat(inode: handle.inode)
                        simulation.note(operation, "server: final fstat -> \(Self.describe(finalStat))")

                    case .writeOnly:
                        let path = simulation.registry.path(of: handle.registration)
                        finalStat = path.flatMap { simulation.server.stat($0) }
                        simulation.note(
                            operation,
                            "server: final stat of \(path.map(Self.spell) ?? "no path") -> \(Self.describe(finalStat))"
                        )
                    }
                }
                simulation.server.close(handle.inode)
            },
            { simulation, operation in
                guard handle.wroteToFile else {
                    operation.steps.append(unregister)
                    return
                }

                ticket = finalStat == nil
                    ? simulation.registry.beginReport(handle.registration, .invalidation, since: nil)
                    : simulation.registry.beginReport(handle.registration, .stat, since: snapshot)
                guard let ticket else {
                    operation.steps.append(unregister)
                    return
                }

                operation.steps.append { simulation, operation in
                    if !ticket.reports {
                        await simulation.invalidateSilenced(ticket, operation)
                    }
                    else if let finalStat, let request {
                        await simulation.cache.storeStat(Self.smbStat(finalStat), path: ticket.path, request: request)
                        simulation.note(operation, "storeStat(\(Self.spell(ticket.path))), the final one")
                    }
                    else {
                        await simulation.cache.invalidate(path: ticket.path)
                        simulation.note(operation, "invalidate(\(Self.spell(ticket.path))), without a final stat")
                    }
                    simulation.glue(operation)
                }
                operation.steps.append { simulation, operation in
                    Self.endReport(handle, ticket, simulation, operation)
                    operation.steps.append(unregister)
                }
            },
        ])
        operation.handle = handle
        operation.isClose = true
        return operation
    }

    /// The steps of `SMB.File.stat()`.
    private func fileStatSteps(_ handle: Handle) -> [Operation.Step] {
        var snapshot: OpenFileRegistry.ChangeCounts?
        var stat: SimulatedServer.Stat?
        var ticket: OpenFileRegistry.ReportTicket?
        var request: SMB.CacheRequestID?

        return [
            { simulation, _ in
                // A request of its own, for a file that reports.
                if simulation.registry.changeCounts(of: handle.registration) != nil {
                    let begun = SMB.CacheRequestID()
                    request = begun
                    await simulation.cache.beginRequest(begun)
                }
            },
            { simulation, _ in
                snapshot = simulation.registry.changeCounts(of: handle.registration)
            },
            { simulation, operation in
                // The server refuses to stat a handle opened only for writing.
                stat = handle.access == .writeOnly ? nil : simulation.server.stat(inode: handle.inode)
                simulation.note(operation, "server: fstat of handle \(handle.id) -> \(Self.describe(stat))")
            },
            { simulation, _ in
                if request != nil, stat != nil {
                    ticket = simulation.registry.beginReport(handle.registration, .stat, since: snapshot)
                }
            },
            { simulation, operation in
                guard let ticket, let stat, let request else {
                    return
                }
                if !ticket.reports {
                    await simulation.invalidateSilenced(ticket, operation)
                    return
                }
                await simulation.cache.storeStat(Self.smbStat(stat), path: ticket.path, request: request)
                simulation.note(operation, "storeStat(\(Self.spell(ticket.path))), of the open file")
                simulation.glue(operation)
            },
            { simulation, operation in
                if let ticket {
                    Self.endReport(handle, ticket, simulation, operation)
                }
                operation.steps.append { simulation, _ in
                    if let request {
                        await simulation.cache.requestEnded(request)
                    }
                }
            },
        ]
    }

    private func makeFileStat(handle: Handle) -> Operation {
        let operation = makeOperation("fstat handle \(handle.id)", mutates: false, fileStatSteps(handle))
        operation.handle = handle
        return operation
    }

    /// The steps of `SMB.File.truncate(toLength:)`.
    private func makeSetSize(handle: Handle, size: UInt64) -> Operation {
        var ticket: OpenFileRegistry.ReportTicket?

        let operation = makeOperation("set size \(size) through handle \(handle.id)", mutates: true, [
            { simulation, operation in
                guard simulation.goesOn(operation, changingThrough: handle) else {
                    return
                }
                simulation.server.setSize(inode: handle.inode, to: size)
                simulation.note(operation, "server: inode \(handle.inode) now has \(size) bytes")
            },
            { simulation, operation in
                ticket = simulation.registry.beginReport(handle.registration, .attributes, since: nil)
                if ticket == nil {
                    simulation.noteDroppedReport(operation)
                    operation.abandon()
                }
            },
            { simulation, operation in
                guard let ticket else {
                    return
                }
                for path in ticket.paths {
                    await simulation.cache.invalidate(path: path)
                    simulation.note(operation, "invalidate(\(Self.spell(path)))")
                }
            },
            { simulation, operation in
                if let ticket {
                    Self.endReport(handle, ticket, simulation, operation)
                }
            },
        ])
        operation.handle = handle
        operation.writes = (handle.inode, 0 ..< .max)
        return operation
    }

    /// The steps of a change by path that `SMB.Connection.reportingChange` reports, other than removals:
    /// `truncate(at:toLength:)` and `changeDate(at:...)`.
    private func makeChange(
        _ name: String,
        path: String,
        _ change: @escaping (inout SimulatedServer) -> Bool
    ) -> Operation {
        var ticket: OpenFileRegistry.ChangeTicket?
        let operation = makeOperation(name, mutates: true, [
            { simulation, operation in
                ticket = simulation.registry.beginChange()
                let done = change(&simulation.server)
                simulation.note(operation, "server: \(done ? "done" : "fails")")
            },
            { simulation, _ in
                simulation.registry.noteChanges(atOrUnder: [path], change: ticket)
            },
            Self.invalidation(path),
            { simulation, operation in
                if let ticket {
                    simulation.endChange(ticket, operation)
                }
            },
        ])
        operation.paths = [path]
        return operation
    }

    private func makeSetSize(path: String, size: UInt64) -> Operation {
        makeChange("set size \(size) of \(Self.spell(path))", path: path) { server in
            server.setSize(path: path, to: size)
        }
    }

    private func makeSetModificationTime(path: String, time: UInt64) -> Operation {
        makeChange("set the modification time of \(Self.spell(path)) to \(time)", path: path) { server in
            server.setModificationTime(path: path, to: time)
        }
    }

    private func makeCreateDirectory(path: String) -> Operation {
        makeChange("create directory \(Self.spell(path))", path: path) { server in
            server.makeDirectory(path)
        }
    }

    /// The steps of `SMB.Connection.removeFile(at:)` and `removeDirectory(at:)`.
    private func makeRemoval(_ name: String, path: String, _ remove: @escaping (inout SimulatedServer) -> Bool)
    -> Operation {
        var change: OpenFileRegistry.ChangeTicket?
        var removed = false

        // A call that fails at the client, as on a timeout, whether or not the server removed the entry.
        let callFails = generator.chance(0.08)

        let operation = makeOperation("\(name)\(callFails ? ", with the call failing" : "")", mutates: true, [
            { simulation, operation in
                change = simulation.registry.beginChange()
                removed = remove(&simulation.server)
                simulation.note(operation, "server: \(removed ? "done" : "fails")")
            },
            { simulation, operation in
                // A removal the client saw succeed leaves the files open there without a path.
                let strays = simulation.registry
                    .stopReporting(atOrUnder: [path], change: change, removed: removed && !callFails)
                for path in RegistryPath.unique([path] + strays) {
                    operation.steps.append(Self.invalidation(path))
                }
                operation.steps.append { simulation, operation in
                    if let change {
                        simulation.endChange(change, operation)
                    }
                }
            },
        ])
        operation.paths = [path]
        return operation
    }

    private func makeDeleteFile(path: String) -> Operation {
        makeRemoval("delete \(Self.spell(path))", path: path) { server in
            server.unlink(path)
        }
    }

    private func makeDeleteDirectory(path: String) -> Operation {
        makeRemoval("remove directory \(Self.spell(path))", path: path) { server in
            server.removeDirectory(path)
        }
    }

    /// The steps of `SMB.Connection.move(from:to:)`.
    private func makeRename(from: String, to: String) -> Operation {
        var renamed = false
        var rename: OpenFileRegistry.Rename?
        var change: OpenFileRegistry.ChangeTicket?

        // A call that fails at the client, as on a timeout, whether or not the server renamed.
        let callFails = generator.chance(0.12)

        let operation = makeOperation(
            "rename \(Self.spell(from)) to \(Self.spell(to))\(callFails ? ", with the call failing" : "")",
            mutates: true,
            [
                { simulation, operation in
                    change = simulation.registry.beginChange()
                    renamed = simulation.server.rename(from, to: to)
                    simulation.note(operation, "server: rename \(renamed ? "done" : "fails")")
                },
                { simulation, operation in
                    if renamed, !callFails {
                        rename = simulation.registry.beginRename(from: from, to: to, change: change)
                        return
                    }

                    // Both paths may have changed, and the files open at either stop reporting.
                    let strays = simulation.registry.stopReportingAfterFailedRename(from: from, to: to, change: change)
                    for path in RegistryPath.unique([from, to] + strays) {
                        operation.steps.append(Self.invalidation(path))
                    }
                    operation.steps.append { simulation, operation in
                        if let change {
                            simulation.endChange(change, operation)
                        }
                    }
                },
                { simulation, operation in
                    guard rename != nil else {
                        return
                    }
                    await simulation.cache.didRename(from: from, to: to)
                    simulation.note(operation, "didRename(\(Self.spell(from)), \(Self.spell(to)))")
                },
                { simulation, operation in
                    guard rename != nil else {
                        return
                    }
                    if let rename {
                        for path in RegistryPath.unique(simulation.registry.finishRename(rename)) {
                            operation.steps.append(Self.invalidation(path))
                        }
                    }
                    operation.steps.append { simulation, operation in
                        if let change {
                            simulation.endChange(change, operation)
                        }
                    }
                },
            ]
        )
        operation.paths = [from, to]
        operation.isRename = true
        return operation
    }

    /// Ends a change by path, queueing the invalidations the registry asks for.
    private func endChange(_ change: OpenFileRegistry.ChangeTicket, _ operation: Operation) {
        let paths = RegistryPath.unique(registry.endChange(change))
        if !paths.isEmpty {
            note(operation, "a related change overlapped: \(paths.map(Self.spell)) to invalidate")
        }
        for path in paths {
            operation.steps.append(Self.invalidation(path))
        }
    }

    /// Reports a change through a file that stopped reporting: invalidations of the paths it may still be at.
    private func invalidateSilenced(_ ticket: OpenFileRegistry.ReportTicket, _ operation: Operation) async {
        for path in RegistryPath.unique(ticket.paths) {
            await cache.invalidate(path: path)
            note(operation, "invalidate(\(Self.spell(path))), where the silenced file may be")
        }
    }
}
