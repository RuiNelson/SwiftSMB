//
// Part of SwiftSMB
// SimulatedServer.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation

// MARK: Rules

/// How a ``SimulatedServer`` compares names, and what it refuses to do to open files.
struct SimulatedServerRules: Equatable, CustomStringConvertible, Sendable {
    enum Folding: Equatable, Sendable {
        /// Names are compared byte by byte, as on a case-sensitive share.
        case none
        /// Names are compared regardless of case, by simple one-scalar uppercase mappings, and byte by byte otherwise:
        /// Samba on a Linux file system, and Windows.
        case caseInsensitive
        /// Names are compared regardless of case and of Unicode normalization: a macOS server.
        case caseAndNormalizationInsensitive
    }

    var folding: Folding

    /// Whether renaming or deleting an open file, or a directory above one, fails, as on Samba and Windows: SwiftSMB
    /// opens files without delete sharing.
    var refusesChangesToOpenFiles: Bool

    /// Samba on Linux, as the test server runs it.
    static let samba = SimulatedServerRules(folding: .caseInsensitive, refusesChangesToOpenFiles: true)

    var description: String {
        "folding \(folding), refusesChangesToOpenFiles \(refusesChangesToOpenFiles)"
    }
}

// MARK: Keys

/// A path as the server finds it: its scalars after the server's folding, compared one by one. `String` compares names
/// that differ only in Unicode normalization as equal, so it cannot stand in for one.
struct ServerKey: Hashable, Comparable, CustomStringConvertible {
    let scalars: [UInt32]

    static let root = ServerKey(scalars: [])
    private static let slash = UInt32(UInt8(ascii: "/"))

    /// The directory holding the entry: the root for the root and its children.
    var parent: ServerKey {
        guard let slash = scalars.lastIndex(of: Self.slash) else {
            return .root
        }
        return ServerKey(scalars: Array(scalars[..<slash]))
    }

    /// Whether the key is `ancestor`, or lies under it. Everything lies under the root.
    func isAtOrUnder(_ ancestor: ServerKey) -> Bool {
        if ancestor.scalars.isEmpty || self == ancestor {
            return true
        }
        return scalars.count > ancestor.scalars.count && scalars.starts(with: ancestor.scalars)
            && scalars[ancestor.scalars.count] == Self.slash
    }

    /// Whether one of the keys is the other, or lies under it.
    static func areRelated(_ first: ServerKey, _ second: ServerKey) -> Bool {
        first.isAtOrUnder(second) || second.isAtOrUnder(first)
    }

    /// The key, which is `from` or lies under it, moved to the same place under `to`.
    func rebased(from: ServerKey, to: ServerKey) -> ServerKey {
        ServerKey(scalars: to.scalars + scalars.dropFirst(from.scalars.count))
    }

    static func < (lhs: ServerKey, rhs: ServerKey) -> Bool {
        lhs.scalars.lexicographicallyPrecedes(rhs.scalars)
    }

    var description: String {
        String(String.UnicodeScalarView(scalars.compactMap(Unicode.Scalar.init)))
    }
}

// MARK: Server

/// A miniature SMB server: enough of a share to tell what a client reads from it, and what it held at any earlier
/// moment.
///
/// It compares names as its ``SimulatedServerRules`` say and keeps the spelling each entry was created or last renamed
/// with, as case-preserving shares do. Like SMB, it never renames over an existing entry, except one that a rename only
/// respells.
struct SimulatedServer {
    enum Kind: Equatable {
        case file
        case directory
    }

    /// What a stat of an entry reports.
    struct Stat: Equatable {
        var kind: Kind
        var size: UInt64
        var modificationTime: UInt64
        var changeTime: UInt64
    }

    /// The namespace at one moment: the inode each key led to, and the name each entry had.
    struct Snapshot {
        let links: [ServerKey: Int]
        let names: [ServerKey: String]
    }

    private struct Inode {
        var kind: Kind
        var content = Data()
        var modificationTime: UInt64
        var changeTime: UInt64
    }

    let rules: SimulatedServerRules

    /// The server's clock in seconds, which times are taken from. It moves only when told to, so many changes land
    /// within one second: a server's times are much finer, but a cache that relies on them is wrong when they agree.
    private(set) var clock: UInt64 = 1000

    private var links: [ServerKey: Int] = [.root: 0]
    private var names: [ServerKey: String] = [.root: ""]
    private var inodes: [Int: Inode] = [0: Inode(kind: .directory, modificationTime: 1000, changeTime: 1000)]
    private var nextInode = 1

    /// Handles the server has open, by inode.
    private var openCounts: [Int: Int] = [:]

    /// How many times the server changed so far.
    private(set) var mutations = 0

    /// What each file held after each change to it.
    private var contentHistory: [Int: [(mutation: Int, content: Data)]] = [:]

    /// The namespace after each change.
    private var namespaceHistory: [(mutation: Int, snapshot: Snapshot)] = [
        (0, Snapshot(links: [.root: 0], names: [.root: ""])),
    ]

    /// What a stat of each inode reported after each change to it.
    private var statHistory: [Int: [(mutation: Int, stat: Stat)]] = [
        0: [(0, Stat(kind: .directory, size: 0, modificationTime: 1000, changeTime: 1000))],
    ]

    init(rules: SimulatedServerRules) {
        self.rules = rules
    }

    // MARK: Paths

    /// The key the server finds `path` by.
    func key(_ path: String) -> ServerKey {
        let folded = switch rules.folding {
        case .none:
            path

        case .caseInsensitive:
            Self.simpleUppercased(path)

        case .caseAndNormalizationInsensitive:
            Self.simpleUppercased(path.precomposedStringWithCanonicalMapping)
        }
        return ServerKey(scalars: folded.unicodeScalars.map(\.value))
    }

    /// The last component of `path`.
    static func name(_ path: String) -> String {
        path.split(separator: "/", omittingEmptySubsequences: false).last.map(String.init) ?? ""
    }

    /// How many components `path` has.
    static func depth(_ path: String) -> Int {
        path.isEmpty ? 0 : path.split(separator: "/", omittingEmptySubsequences: false).count
    }

    private static func simpleUppercased(_ path: String) -> String {
        var result = String.UnicodeScalarView()
        for scalar in path.unicodeScalars {
            let mapping = scalar.properties.uppercaseMapping.unicodeScalars
            if mapping.count == 1, let upper = mapping.first {
                result.append(upper)
            }
            else {
                result.append(scalar)
            }
        }
        return String(result)
    }

    // MARK: Reading

    func stat(_ path: String) -> Stat? {
        links[key(path)].map(stat(inode:))
    }

    func stat(inode: Int) -> Stat {
        guard let node = inodes[inode] else {
            preconditionFailure("no inode \(inode)")
        }
        return Stat(
            kind: node.kind,
            size: node.kind == .file ? UInt64(node.content.count) : 0,
            modificationTime: node.modificationTime,
            changeTime: node.changeTime
        )
    }

    func kind(of inode: Int) -> Kind? {
        inodes[inode]?.kind
    }

    /// The inode `path` leads to now.
    func inode(at path: String) -> Int? {
        links[key(path)]
    }

    /// The entries of the directory at `path`, by name, or `nil` when there is no directory there.
    func list(_ path: String) -> [(name: String, inode: Int)]? {
        let directory = key(path)
        guard let inode = links[directory], inodes[inode]?.kind == .directory else {
            return nil
        }
        return links.filter { $0.key != directory && $0.key.parent == directory }
            .sorted { $0.key < $1.key }
            .map { (names[$0.key] ?? "", $0.value) }
    }

    /// The bytes of the file `inode` is, whether or not a path still leads to it.
    func content(of inode: Int) -> Data {
        inodes[inode]?.content ?? Data()
    }

    func read(_ inode: Int, at offset: UInt64, upTo: Int) -> Data? {
        let content = content(of: inode)
        guard upTo > 0, offset < UInt64(content.count) else {
            return nil
        }
        let start = Int(offset)
        return Data(content[start ..< min(start + upTo, content.count)])
    }

    /// Whether a path still leads to `inode`.
    func isLinked(_ inode: Int) -> Bool {
        links.values.contains(inode)
    }

    /// The paths of the files that exist, spelled as the server lists them.
    var existingFiles: [String] {
        links.filter { inodes[$0.value]?.kind == .file }.keys.sorted().map(spelling(of:))
    }

    /// The paths of the directories that exist, other than the root, spelled as the server lists them.
    var existingDirectories: [String] {
        links.filter { $0.key != .root && inodes[$0.value]?.kind == .directory }.keys.sorted().map(spelling(of:))
    }

    /// Every existing path, spelled as the server lists it.
    var existingPaths: [String] {
        links.keys.sorted().map(spelling(of:))
    }

    /// `key` spelled with the names its entry and the directories above it have.
    private func spelling(of key: ServerKey) -> String {
        var components: [String] = []
        var current = key
        while current != .root {
            components.append(names[current] ?? "?")
            current = current.parent
        }
        return components.reversed().joined(separator: "/")
    }

    // MARK: History

    /// What `inode` held at every moment since the server had changed `mutation` times.
    func contents(of inode: Int, since mutation: Int) -> [Data] {
        let history = contentHistory[inode] ?? []
        let before = history.last { $0.mutation <= mutation }
        return (before.map { [$0.content] } ?? []) + history.filter { $0.mutation > mutation }.map(\.content)
    }

    /// The namespace at every moment since the server had changed `mutation` times.
    func snapshots(since mutation: Int) -> [Snapshot] {
        let before = namespaceHistory.last { $0.mutation <= mutation }
        return (before.map { [$0.snapshot] } ?? []) + namespaceHistory.filter { $0.mutation > mutation }.map(\.snapshot)
    }

    /// What a stat of `inode` reported at every moment since the server had changed `mutation` times, whether or not a
    /// path led to it.
    func stats(of inode: Int, since mutation: Int) -> [Stat] {
        let history = statHistory[inode] ?? []
        let before = history.last { $0.mutation <= mutation }
        return (before.map { [$0.stat] } ?? []) + history.filter { $0.mutation > mutation }.map(\.stat)
    }

    // MARK: Changing

    /// Moves the clock to the next second.
    mutating func tick() {
        clock += 1
    }

    /// Opens the file at `path`, as SMB2 CREATE does.
    ///
    /// - Returns: The file's inode, or `nil` when the open fails.
    mutating func open(_ path: String, create: Bool, truncate: Bool) -> Int? {
        let key = key(path)
        if let inode = links[key] {
            guard inodes[inode]?.kind == .file else {
                return nil
            }
            openCounts[inode, default: 0] += 1
            if truncate {
                inodes[inode]?.content = Data()
                touch(inode)
                commit(file: inode)
            }
            return inode
        }

        guard create, let parent = links[key.parent], inodes[parent]?.kind == .directory else {
            return nil
        }

        let inode = nextInode
        nextInode += 1
        inodes[inode] = Inode(kind: .file, modificationTime: clock, changeTime: clock)
        links[key] = inode
        names[key] = Self.name(path)
        openCounts[inode, default: 0] += 1
        touch(parent)
        commit(file: inode)
        return inode
    }

    /// Closes a handle on `inode`.
    mutating func close(_ inode: Int) {
        openCounts[inode, default: 1] -= 1
        if openCounts[inode] == 0 {
            openCounts[inode] = nil
        }
    }

    mutating func write(_ inode: Int, at offset: UInt64, _ data: Data) {
        guard !data.isEmpty, var content = inodes[inode]?.content else {
            return
        }

        let start = Int(offset)
        if content.count < start + data.count {
            content.append(Data(count: start + data.count - content.count))
        }
        content.replaceSubrange(start ..< start + data.count, with: data)
        inodes[inode]?.content = content
        touch(inode)
        commit(file: inode)
    }

    mutating func append(_ inode: Int, _ data: Data) {
        guard !data.isEmpty else {
            return
        }
        inodes[inode]?.content.append(data)
        touch(inode)
        commit(file: inode)
    }

    mutating func setSize(inode: Int, to size: UInt64) {
        guard var content = inodes[inode]?.content else {
            return
        }

        if content.count > Int(size) {
            content = Data(content.prefix(Int(size)))
        }
        else {
            content.append(Data(count: Int(size) - content.count))
        }
        inodes[inode]?.content = content
        touch(inode)
        commit(file: inode)
    }

    /// - Returns: Whether a file is at `path`.
    mutating func setSize(path: String, to size: UInt64) -> Bool {
        guard let inode = links[key(path)], inodes[inode]?.kind == .file else {
            return false
        }
        setSize(inode: inode, to: size)
        return true
    }

    /// Sets the last write time of the entry at `path`, as SMB2 SET_INFO does, to any time: also one the entry had
    /// before.
    ///
    /// - Returns: Whether an entry is at `path`.
    mutating func setModificationTime(path: String, to time: UInt64) -> Bool {
        guard let inode = links[key(path)] else {
            return false
        }
        inodes[inode]?.modificationTime = time
        inodes[inode]?.changeTime = clock
        commit(file: nil)
        return true
    }

    /// - Returns: Whether a file was at `path`, and was removed.
    mutating func unlink(_ path: String) -> Bool {
        let key = key(path)
        guard let inode = links[key], inodes[inode]?.kind == .file else {
            return false
        }
        if rules.refusesChangesToOpenFiles, openCounts[inode] != nil {
            return false
        }
        links[key] = nil
        names[key] = nil
        touchDirectory(key.parent)
        commit(file: nil)
        return true
    }

    /// - Returns: Whether an empty directory was at `path`, and was removed.
    mutating func removeDirectory(_ path: String) -> Bool {
        let key = key(path)
        guard key != .root, let inode = links[key], inodes[inode]?.kind == .directory,
              !links.keys.contains(where: { $0 != key && $0.isAtOrUnder(key) }) else {
            return false
        }
        links[key] = nil
        names[key] = nil
        touchDirectory(key.parent)
        commit(file: nil)
        return true
    }

    /// - Returns: Whether the directory was created.
    mutating func makeDirectory(_ path: String) -> Bool {
        let key = key(path)
        guard links[key] == nil, let parent = links[key.parent], inodes[parent]?.kind == .directory else {
            return false
        }
        links[key] = nextInode
        names[key] = Self.name(path)
        inodes[nextInode] = Inode(kind: .directory, modificationTime: clock, changeTime: clock)
        nextInode += 1
        touch(parent)
        commit(file: nil)
        return true
    }

    /// Renames as SMB2 SET_INFO with `ReplaceIfExists = 0` does: never over an existing entry, unless the two paths
    /// name the same entry, which the rename only respells.
    ///
    /// - Returns: Whether the rename happened.
    mutating func rename(_ from: String, to: String) -> Bool {
        let source = key(from)
        let destination = key(to)
        guard source != .root, destination != .root, let moving = links[source] else {
            return false
        }

        if rules.refusesChangesToOpenFiles,
           links.contains(where: { $0.key.isAtOrUnder(source) && openCounts[$0.value] != nil }) {
            return false
        }

        if source == destination {
            // A rename to the very name the entry has does nothing, as on Samba and POSIX file systems.
            guard names[source].map({ Array($0.unicodeScalars) }) != Array(Self.name(to).unicodeScalars) else {
                return true
            }
            names[source] = Self.name(to)
            inodes[moving]?.changeTime = clock
            touchDirectory(source.parent)
            commit(file: nil)
            return true
        }

        guard !destination.isAtOrUnder(source), links[destination] == nil, let newParent = links[destination.parent],
              inodes[newParent]?.kind == .directory else {
            return false
        }

        let moved = links.filter { $0.key.isAtOrUnder(source) }
        let movedNames = names.filter { $0.key.isAtOrUnder(source) }
        for key in moved.keys {
            links[key] = nil
            names[key] = nil
        }
        for (key, inode) in moved {
            links[key.rebased(from: source, to: destination)] = inode
        }
        for (key, name) in movedNames {
            names[key.rebased(from: source, to: destination)] = name
        }
        names[destination] = Self.name(to)
        inodes[moving]?.changeTime = clock

        touchDirectory(source.parent)
        touchDirectory(destination.parent)
        commit(file: nil)
        return true
    }

    // MARK: Private

    private mutating func touch(_ inode: Int) {
        inodes[inode]?.modificationTime = clock
        inodes[inode]?.changeTime = clock
    }

    private mutating func touchDirectory(_ key: ServerKey) {
        if let inode = links[key] {
            touch(inode)
        }
    }

    /// Records the server as it is after a change, to `file` if it changed a file's contents.
    private mutating func commit(file inode: Int?) {
        mutations += 1
        if let inode, let node = inodes[inode] {
            contentHistory[inode, default: []].append((mutations, node.content))
        }
        namespaceHistory.append((mutations, Snapshot(links: links, names: names)))
        for inode in inodes.keys {
            let current = stat(inode: inode)
            if statHistory[inode]?.last?.stat != current {
                statHistory[inode, default: []].append((mutations, current))
            }
        }
    }
}
