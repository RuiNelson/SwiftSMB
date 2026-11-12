//
// Part of SwiftSMB
// OpenFileRegistryTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Testing

@Suite("Cache: OpenFileRegistry paths")
struct RegistryPathTests {
    @Test("a path lies under itself, its ancestors, and the share root, comparing whole components")
    func atOrUnder() {
        #expect(RegistryPath.isPath("a/b/c", atOrUnder: "a/b"))
        #expect(RegistryPath.isPath("a/b", atOrUnder: "a/b"))
        #expect(RegistryPath.isPath("a/b", atOrUnder: ""))
        #expect(RegistryPath.isPath("", atOrUnder: ""))
        #expect(!RegistryPath.isPath("a/bc", atOrUnder: "a/b"))
        #expect(!RegistryPath.isPath("a", atOrUnder: "a/b"))
        #expect(!RegistryPath.isPath("", atOrUnder: "a"))
        // Case matters: the registry compares bytes.
        #expect(!RegistryPath.isPath("A/b", atOrUnder: "a"))
    }

    @Test("names that differ only in Unicode normalization are different paths")
    func normalization() {
        let composed = "caf\u{E9}"
        let decomposed = "cafe\u{301}"
        #expect(composed == decomposed)
        #expect(!RegistryPath.sameBytes(composed, decomposed))
        #expect(!RegistryPath.isPath("\(composed)/x", atOrUnder: decomposed))
        #expect(RegistryPath.unique([composed, decomposed, composed]).count == 2)
    }

    @Test("rebasing moves a path to the same place under the destination")
    func rebase() {
        #expect(RegistryPath.rebase("a/b", from: "a/b", to: "c") == "c")
        #expect(RegistryPath.rebase("a/b/c/d", from: "a/b", to: "x/y") == "x/y/c/d")
        #expect(RegistryPath.rebase("a/b", from: "", to: "x") == "x/a/b")
        #expect(RegistryPath.rebase("a/b", from: "a", to: "") == "b")
    }
}

@Suite("Cache: OpenFileRegistry")
struct OpenFileRegistryTests {
    // MARK: Files

    @Test("a registered file reports under its path until it is unregistered")
    func registration() {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "a/file")
        #expect(registry.path(of: id) == "a/file")
        #expect(registry.changeCounts(of: id) == OpenFileRegistry.ChangeCounts())

        registry.unregister(id)
        #expect(registry.path(of: id) == nil)
        #expect(registry.count == 0)
    }

    @Test("a file being opened does not report until the open finishes")
    func opening() {
        let registry = OpenFileRegistry()
        let id = registry.beginOpen(path: "file")
        #expect(registry.path(of: id) == nil)
        #expect(registry.beginReport(id, .write, since: nil) == nil)

        registry.finishOpen(id)
        #expect(registry.path(of: id) == "file")
    }

    // MARK: Renames

    @Test("a rename moves the files open at or under its source, and nothing else")
    func renameRebases() {
        let registry = OpenFileRegistry()
        let file = registry.register(path: "a/file")
        let nested = registry.register(path: "a/sub/file")
        let sibling = registry.register(path: "ab/file")

        let rename = registry.beginRename(from: "a", to: "b")
        #expect(registry.path(of: file) == "a/file")
        #expect(registry.finishRename(rename) == [])

        #expect(registry.path(of: file) == "b/file")
        #expect(registry.path(of: nested) == "b/sub/file")
        #expect(registry.path(of: sibling) == "ab/file")
    }

    @Test("a rename onto an open file's path replaces it: it stops reporting and has no path left")
    func renameReplaces() {
        let registry = OpenFileRegistry()
        let moving = registry.register(path: "source")
        let replaced = registry.register(path: "target")

        let rename = registry.beginRename(from: "source", to: "target")
        _ = registry.finishRename(rename)

        #expect(registry.path(of: moving) == "target")
        #expect(registry.path(of: replaced) == nil)
        #expect(registry.beginReport(replaced, .write, since: nil) == nil)
    }

    @Test("a rename of the path of a file being opened silences it at both paths")
    func renameWhileOpening() throws {
        let registry = OpenFileRegistry()
        let id = registry.beginOpen(path: "old")
        _ = registry.finishRename(registry.beginRename(from: "old", to: "new"))
        registry.finishOpen(id)

        #expect(registry.path(of: id) == nil)
        let ticket = try #require(registry.beginReport(id, .write, since: nil, range: 0 ..< 10))
        #expect(!ticket.reports)
        #expect(ticket.paths == ["old", "new"])
        #expect(registry.beginReport(id, .stat, since: nil) == nil)
        #expect(registry.beginReport(id, .read, since: nil) == nil)
    }

    @Test("a report that a rename overlapped names the old and the new path")
    func reportOverlappingRename() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "old")

        let ticket = try #require(registry.beginReport(id, .read, since: nil))
        #expect(registry.isCurrent(id, ticket))
        let rename = registry.beginRename(from: "old", to: "new")
        #expect(!registry.isCurrent(id, ticket))
        #expect(registry.finishRename(rename) == [])
        #expect(registry.endReport(id, ticket) == ["old", "new"])

        // A report that starts after the rename is untouched.
        let later = try #require(registry.beginReport(id, .read, since: nil))
        #expect(later.path == "new")
        #expect(registry.isCurrent(id, later))
        #expect(registry.endReport(id, later) == [])
    }

    @Test("a report that ends while a rename is in progress leaves its paths to the rename")
    func reportEndingMidRename() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "old")

        let ticket = try #require(registry.beginReport(id, .read, since: nil))
        let rename = registry.beginRename(from: "old", to: "new")
        #expect(registry.endReport(id, ticket) == [])
        #expect(registry.finishRename(rename) == ["old", "new"])
    }

    @Test("a file closing while a rename of it is in progress is kept until the rename is through")
    func closeMidRename() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "old")

        let ticket = try #require(registry.beginReport(id, .read, since: nil))
        let rename = registry.beginRename(from: "old", to: "new")
        #expect(registry.endReport(id, ticket) == [])
        registry.unregister(id)
        #expect(registry.count == 1)
        #expect(registry.path(of: id) == nil)

        #expect(registry.finishRename(rename) == ["old", "new"])
        #expect(registry.count == 0)
    }

    @Test("a rename whose call failed silences the files at both paths, keeping where they may be")
    func failedRename() throws {
        let registry = OpenFileRegistry()
        let source = registry.register(path: "dir/file")
        let target = registry.register(path: "other/file")

        #expect(registry.stopReportingAfterFailedRename(from: "dir", to: "other") == [])

        #expect(registry.path(of: source) == nil)
        #expect(registry.path(of: target) == nil)
        let sourceTicket = try #require(registry.beginReport(source, .attributes, since: nil))
        #expect(sourceTicket.paths == ["dir/file", "other/file"])
        let targetTicket = try #require(registry.beginReport(target, .write, since: nil))
        #expect(targetTicket.paths == ["other/file"])
    }

    @Test("a silenced file follows a later rename of a path it may be at, and drops a path the rename replaced")
    func silencedFollowsRename() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "a")
        _ = registry.stopReporting(atOrUnder: ["a"])

        _ = registry.finishRename(registry.beginRename(from: "a", to: "b"))
        #expect(try #require(registry.beginReport(id, .write, since: nil)).paths == ["b"])

        let other = registry.register(path: "c")
        _ = registry.stopReporting(atOrUnder: ["c"])
        _ = registry.finishRename(registry.beginRename(from: "d", to: "c"))
        #expect(registry.beginReport(other, .write, since: nil) == nil)
    }

    // MARK: Deletes

    @Test("a delete stops the files at or under its path from reporting")
    func deleteSilences() throws {
        let registry = OpenFileRegistry()
        let file = registry.register(path: "dir/file")
        let other = registry.register(path: "elsewhere")

        _ = registry.stopReporting(atOrUnder: ["dir"])
        #expect(registry.path(of: file) == nil)
        #expect(registry.path(of: other) == "elsewhere")

        // A delete that may not have happened keeps the path to invalidate through the file.
        let ticket = try #require(registry.beginReport(file, .write, since: nil))
        #expect(!ticket.reports)
        #expect(ticket.paths == ["dir/file"])
        #expect(registry.endReport(file, ticket) == [])
    }

    @Test("a delete the server confirmed leaves the file no path to invalidate")
    func confirmedDelete() {
        let registry = OpenFileRegistry()
        let file = registry.register(path: "file")
        _ = registry.stopReporting(atOrUnder: ["file"], removed: true)
        #expect(registry.beginReport(file, .write, since: nil) == nil)
        #expect(registry.beginReport(file, .attributes, since: nil) == nil)
    }

    @Test("a report that a delete overlapped names its path")
    func reportOverlappingDelete() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "file")

        let ticket = try #require(registry.beginReport(id, .read, since: nil))
        _ = registry.stopReporting(atOrUnder: ["file"])
        #expect(!registry.isCurrent(id, ticket))
        #expect(registry.endReport(id, ticket) == ["file"])
    }

    @Test("a report of a file forgotten while it was on its way names its paths")
    func reportAfterUnregister() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "file")
        let ticket = try #require(registry.beginReport(id, .stat, since: nil))
        registry.unregister(id)
        #expect(registry.endReport(id, ticket) == ["file"])
    }

    // MARK: Overlapping changes

    @Test("a stat is overlapped by any change at its path, a write through the same file included")
    func statOverlapped() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "file")

        let snapshot = try #require(registry.changeCounts(of: id))
        registry.noteChanges(atOrUnder: ["file"])
        let ticket = try #require(registry.beginReport(id, .stat, since: snapshot))
        #expect(registry.endReport(id, ticket) == ["file"])

        let writeSnapshot = try #require(registry.changeCounts(of: id))
        let write = try #require(registry.beginReport(id, .write, since: nil, range: 0 ..< 1))
        _ = registry.endReport(id, write)
        let stat = try #require(registry.beginReport(id, .stat, since: writeSnapshot))
        #expect(registry.endReport(id, stat) == ["file"])

        // Nothing since the snapshot: the stat stands.
        let quiet = try #require(registry.beginReport(id, .stat, since: registry.changeCounts(of: id)))
        #expect(registry.endReport(id, quiet) == [])
    }

    @Test("changes count against files open under paths that differ only in case or Unicode normalization")
    func respelledChangesCount() throws {
        let registry = OpenFileRegistry()
        let first = registry.register(path: "dir/Photo.jpg")
        let second = registry.register(path: "DIR/photo.JPG")
        let composed = registry.register(path: "caf\u{E9}")
        let unrelated = registry.register(path: "dir/other.jpg")

        // Two writes to the same bytes through handles that a share ignoring case takes to be one file.
        let snapshot = try #require(registry.changeCounts(of: first))
        let ticket = try #require(registry.beginReport(first, .write, since: snapshot, range: 0 ..< 10))
        let other = try #require(registry.beginReport(second, .write, since: snapshot, range: 5 ..< 15))
        #expect(registry.endReport(second, other) == ["DIR/photo.JPG"])
        #expect(registry.endReport(first, ticket) == ["dir/Photo.jpg"])

        // A change by a path spelled another way, and in the other normalization.
        let before = try #require(registry.changeCounts(of: composed))
        registry.noteChanges(atOrUnder: ["CAFE\u{301}"])
        #expect(registry.changeCounts(of: composed)?.others == before.others + 1)
        #expect(registry.changeCounts(of: unrelated)?.writes == 0)
        #expect(registry.changeCounts(of: unrelated)?.others == 0)

        // Renames still move only the files opened under the very path.
        let rename = registry.beginRename(from: "dir/Photo.jpg", to: "dir/moved.jpg")
        _ = registry.finishRename(rename)
        #expect(registry.path(of: first) == "dir/moved.jpg")
        #expect(registry.path(of: second) == "DIR/photo.JPG")
    }

    @Test("a change by path and a rename of a directory spelled another way are related")
    func respelledChangeAndRename() {
        let registry = OpenFileRegistry()
        let truncation = registry.beginChange()
        let renaming = registry.beginChange()
        let rename = registry.beginRename(from: "inner", to: "moved", change: renaming)
        _ = registry.finishRename(rename)
        #expect(registry.endChange(renaming) == [])

        // The truncation reached the cache after the rename, under the directory's other spelling.
        registry.noteChanges(atOrUnder: ["INNER/file.bin"], change: truncation)
        #expect(Set(registry.endChange(truncation)) == ["INNER/file.bin", "moved/file.bin"])
    }

    @Test("a change under a directory counts against the files open under it")
    func directoryChangeCounts() throws {
        let registry = OpenFileRegistry()
        let id = registry.register(path: "dir/file")
        let snapshot = try #require(registry.changeCounts(of: id))
        registry.noteChanges(atOrUnder: ["dir"])
        registry.noteChanges(atOrUnder: ["other"])
        #expect(registry.changeCounts(of: id)?.others == snapshot.others + 1)
    }

    @Test("written bytes are overlapped by other changes, and by writes through other handles to the same bytes")
    func writeOverlap() throws {
        let registry = OpenFileRegistry()
        let first = registry.register(path: "file")
        let second = registry.register(path: "file")

        // Writes to different bytes through two handles, in flight together, keep their bytes.
        var snapshot = try #require(registry.changeCounts(of: first))
        var ticket = try #require(registry.beginReport(first, .write, since: snapshot, range: 0 ..< 10))
        var other = try #require(registry.beginReport(second, .write, since: snapshot, range: 10 ..< 20))
        #expect(registry.endReport(second, other) == [])
        #expect(registry.endReport(first, ticket) == [])

        // Writes to the same bytes do not: either may have reached the server last.
        snapshot = try #require(registry.changeCounts(of: first))
        ticket = try #require(registry.beginReport(first, .write, since: snapshot, range: 0 ..< 10))
        other = try #require(registry.beginReport(second, .write, since: snapshot, range: 5 ..< 15))
        #expect(registry.endReport(second, other) == ["file"])
        #expect(registry.endReport(first, ticket) == ["file"])

        // An append overlaps every write, since its bytes land where the server decides.
        snapshot = try #require(registry.changeCounts(of: first))
        ticket = try #require(registry.beginReport(first, .write, since: snapshot, range: 0 ..< 10))
        other = try #require(registry.beginReport(second, .write, since: snapshot, range: nil))
        #expect(registry.endReport(first, ticket) == ["file"])
        _ = registry.endReport(second, other)

        // A change other than a write overlaps written bytes.
        snapshot = try #require(registry.changeCounts(of: first))
        registry.noteChanges(atOrUnder: ["file"])
        ticket = try #require(registry.beginReport(first, .write, since: snapshot, range: 0 ..< 10))
        #expect(registry.endReport(first, ticket) == ["file"])
    }

    @Test("a write whose snapshot is older than every write the file remembers is taken as overlapped")
    func forgottenWrites() throws {
        let registry = OpenFileRegistry()
        let first = registry.register(path: "file")
        let second = registry.register(path: "file")

        let snapshot = try #require(registry.changeCounts(of: first))
        for index in 0 ..< OpenFileRegistry.writeLimit + 1 {
            let offset = UInt64(100 + index)
            let ticket = try #require(registry.beginReport(second, .write, since: nil, range: offset ..< offset + 1))
            _ = registry.endReport(second, ticket)
        }
        let ticket = try #require(registry.beginReport(first, .write, since: snapshot, range: 0 ..< 1))
        #expect(registry.endReport(first, ticket) == ["file"])
    }

    @Test("an attribute change through a file counts against every file open at its path")
    func attributesCount() throws {
        let registry = OpenFileRegistry()
        let first = registry.register(path: "file")
        let second = registry.register(path: "file")

        let snapshot = try #require(registry.changeCounts(of: second))
        let change = try #require(registry.beginReport(first, .attributes, since: nil))
        #expect(registry.endReport(first, change) == [])
        let stat = try #require(registry.beginReport(second, .stat, since: snapshot))
        #expect(registry.endReport(second, stat) == ["file"])
    }

    // MARK: Changes by path

    @Test("a change and a rename of a related path in progress together name where the rename moved things")
    func changeOverlappingRename() {
        let registry = OpenFileRegistry()

        let change = registry.beginChange()
        let rename = registry.beginChange()
        _ = registry.finishRename(registry.beginRename(from: "dir", to: "moved", change: rename))
        registry.noteChanges(atOrUnder: ["dir/file"], change: change)

        #expect(registry.endChange(change) == ["dir/file", "moved/file"])
        #expect(registry.endChange(rename) == ["dir", "moved"])
    }

    @Test("changes that began after a rename was logged, or touch other paths, name nothing")
    func unrelatedChanges() {
        let registry = OpenFileRegistry()

        let rename = registry.beginChange()
        _ = registry.finishRename(registry.beginRename(from: "a", to: "b", change: rename))
        let unrelated = registry.beginChange()
        registry.noteChanges(atOrUnder: ["c"], change: unrelated)
        #expect(registry.endChange(rename) == [])
        #expect(registry.endChange(unrelated) == [])

        let later = registry.beginChange()
        registry.noteChanges(atOrUnder: ["a/file"], change: later)
        #expect(registry.endChange(later) == [])

        // Two changes that are not renames never name anything.
        let first = registry.beginChange()
        let second = registry.beginChange()
        registry.noteChanges(atOrUnder: ["x"], change: first)
        registry.noteChanges(atOrUnder: ["x"], change: second)
        #expect(registry.endChange(first) == [])
        #expect(registry.endChange(second) == [])
    }

    @Test("a change that was never logged names nothing")
    func unloggedChange() {
        let registry = OpenFileRegistry()
        #expect(registry.endChange(registry.beginChange()) == [])
    }
}
