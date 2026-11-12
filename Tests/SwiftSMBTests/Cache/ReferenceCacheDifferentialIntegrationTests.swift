//
// Part of SwiftSMB
// ReferenceCacheDifferentialIntegrationTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

// MARK: Helpers

/// SplitMix64, as the unit tests' `SeededGenerator`: one seed gives one sequence of operations on every run.
private struct OperationGenerator: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
        state = next()
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }

    mutating func int(_ range: ClosedRange<Int>) -> Int {
        Int.random(in: range, using: &self)
    }

    mutating func chance(_ probability: Double) -> Bool {
        Double.random(in: 0 ..< 1, using: &self) < probability
    }

    mutating func pick<T>(_ items: [T]) -> T {
        items[int(0 ... items.count - 1)]
    }

    mutating func bytes(_ count: Int) -> Data {
        Data((0 ..< count).map { _ in UInt8(truncatingIfNeeded: next()) })
    }
}

/// The contents of the file at `path`, or `nil` when it cannot be opened or read.
private func contents(_ connection: SMB.Connection, _ path: String) async -> Data? {
    try? await connection.loadFile(at: path)
}

/// Everything a handle reads from the start of its file, or `nil` when the read fails.
private func contents(of handle: SMB.File) async -> Data? {
    try? await handle.read(upTo: 1 << 20, atOffset: 0)
}

private func describe(_ data: Data?) -> String {
    guard let data else {
        return "nothing"
    }
    return "\(data.count) bytes [\(data.prefix(4).map { String($0, radix: 16) }.joined(separator: " "))…]"
}

/// A name with its scalars written out, so that spellings that look alike are told apart.
private func spell(_ name: String) -> String {
    name.unicodeScalars.map { $0.isASCII ? String($0) : "\\u{\(String($0.value, radix: 16))}" }.joined()
}

private typealias KeptPair = (cached: SMB.File, held: SMB.File, index: Int)

// MARK: Tests

/// Random operations through a connection with the reference cache attached, and its fork, with what they then read,
/// stat, and list compared with a connection that uses no cache. Every change goes through the cached connection or its
/// fork, so the cache hears of them all, and whatever it answers must be what the server holds.
///
/// Files are reached under several spellings: Samba ignores case, so `file0.bin` and `FILE0.BIN` are one file, while it
/// compares the bytes of names otherwise, so two names that differ only in Unicode normalization are two files.
///
/// `SWIFTSMB_CACHE_FUZZ_SEED` picks the seed, and `SWIFTSMB_CACHE_FUZZ_SCALE` multiplies the operations.
@Suite("ReferenceCache: the cached connection against an uncached one", .tags(.integration), .serialized)
struct ReferenceCacheDifferentialIntegrationTests {
    struct Setup: Sendable, CustomTestStringConvertible {
        let name: String
        let configuration: SMB.ReferenceCache.Configuration

        /// Most bytes the cache's storage keeps.
        var byteBudget = 64 * 1024 * 1024

        var testDescription: String {
            name
        }
    }

    static let setups: [Setup] = [
        Setup(name: "defaults", configuration: .init()),
        Setup(name: "paths matched regardless of case", configuration: .init(pathMatching: .caseInsensitive)),
        Setup(
            name: "metadata answers",
            configuration: .init(metadata: .answer(for: 60, includingMissing: true))
        ),
        Setup(
            name: "metadata answers, paths matched regardless of case",
            configuration: .init(metadata: .answer(for: 60, includingMissing: true), pathMatching: .caseInsensitive)
        ),
        Setup(name: "uploads not kept", configuration: .init(keepsUploads: false)),
        Setup(name: "a budget of 20 KiB", configuration: .init(), byteBudget: 20 * 1024),
        Setup(
            name: "statOnServer before every hit",
            configuration: .init(trustPolicy: .statOnServer, revalidationInterval: 0)
        ),
        Setup(
            name: "sampleBlocks before every hit",
            configuration: .init(trustPolicy: .sampleBlocks(count: 2), revalidationInterval: 0)
        ),
    ]

    /// The files of a run, by the name the server keeps: two of them differ only in Unicode normalization.
    static let names = ["file0.bin", "File1.bin", "caf\u{E9}.bin", "cafe\u{301}.bin"]

    /// Other spellings of each name, which Samba takes to be the same file.
    static let spellings = [
        ["file0.bin", "FILE0.BIN", "File0.Bin"],
        ["File1.bin", "file1.BIN"],
        ["caf\u{E9}.bin", "CAF\u{C9}.BIN"],
        ["cafe\u{301}.bin", "CAFE\u{301}.bin"],
    ]

    /// Sizes few enough for different versions of a file to share one.
    static let sizes = [0, 1000, 4096, 4096, 8192, 8192, 16384]

    static var seed: UInt64 {
        ProcessInfo.processInfo.environment["SWIFTSMB_CACHE_FUZZ_SEED"].flatMap(UInt64.init) ?? 1
    }

    static var scale: Int {
        max(ProcessInfo.processInfo.environment["SWIFTSMB_CACHE_FUZZ_SCALE"].flatMap(Int.init) ?? 1, 1)
    }

    /// Compares what the cached connection and the uncached one read, stat, and list, and returns the first difference.
    private static func difference(
        _ connections: CachedConnections,
        directory: String,
        pairs: [KeptPair],
        names: [String],
        _ generator: inout OperationGenerator
    ) async -> String? {
        for name in names {
            let reader = generator.chance(0.5) ? connections.connection : connections.fork
            // By scalars: `String` takes the two normalization forms, which Samba keeps apart, to be equal.
            let alike = spellings.first { $0.contains { Array($0.unicodeScalars) == Array(name.unicodeScalars) } }
                ?? [name]
            let path = "\(directory)/\(generator.pick(alike))"
            let real = "\(directory)/\(name)"

            let held = await contents(connections.truth, real)
            let cached = await contents(reader, path)
            if cached != held {
                return "\(spell(path)) reads as \(describe(cached)) through the cache, and the server holds \(describe(held))"
            }

            let heldStat = try? await connections.truth.stat(at: real)
            let cachedStat = try? await reader.stat(at: path)
            if cachedStat?.size != heldStat?.size || (cachedStat == nil) != (heldStat == nil) {
                return """
                a stat of \(spell(path)) shows \(cachedStat.map { "\($0.size) bytes" } ?? "nothing") through the \
                cache, and \(heldStat.map { "\($0.size) bytes" } ?? "nothing") on the server
                """
            }
        }

        for pair in pairs {
            let held = await contents(of: pair.held)
            let cached = await contents(of: pair.cached)
            if cached != held {
                return """
                a handle opened on file \(pair.index) and kept open reads \(describe(cached)) through the cache, and \
                \(describe(held)) without it
                """
            }
        }

        func listed(_ connection: SMB.Connection) async -> [[UInt32]: UInt64]? {
            guard let entries = try? await connection.listDirectory(at: directory) else {
                return nil
            }
            let files = entries.filter { $0.name != "." && $0.name != ".." }
            return Dictionary(files.map { (Array($0.name.unicodeScalars.map(\.value)), $0.stat.size) }) { first, _ in
                first
            }
        }
        let heldListing = await listed(connections.truth)
        let cachedListing = await listed(connections.connection)
        if cachedListing != heldListing {
            func show(_ listing: [[UInt32]: UInt64]?) -> String {
                listing.map { listing in
                    listing
                        .map {
                            "\(spell(String(String.UnicodeScalarView($0.key.compactMap(Unicode.Scalar.init))))): \($0.value)"
                        }
                        .sorted().description
                } ?? "nothing"
            }
            return "the directory lists \(show(cachedListing)) through the cache, and \(show(heldListing)) on the server"
        }

        return nil
    }

    /// Makes one random change to the file at `path` through `connection`. Calls that fail, as on a file that does not
    /// exist, are part of the run: the connection reports those too.
    private static func change(
        _ connection: SMB.Connection,
        _ path: String,
        _ generator: inout OperationGenerator
    ) async -> String {
        switch generator.int(0 ... 11) {
        case 0 ..< 3:
            let data = generator.bytes(generator.pick(sizes))
            let done = await (try? connection.dumpToFile(data, to: path)) != nil
            return "wrote \(data.count) bytes to \(spell(path)): \(done ? "done" : "failed")"

        case 3 ..< 6:
            let data = generator.bytes(generator.int(1 ... 2000))
            let offset = UInt64(generator.int(0 ... 9000))
            let handle = try? await connection.openFile(at: path, accessMode: .writeOnly)
            _ = try? await handle?.write(data, atOffset: offset)
            try? await handle?.close()
            return "wrote \(data.count) bytes at \(offset) of \(spell(path))"

        case 6 ..< 8:
            let data = generator.bytes(generator.int(1 ... 2000))
            let handle = try? await connection.openFile(at: path, accessMode: .writeOnly, options: [.append])
            _ = try? await handle?.write(data)
            try? await handle?.close()
            return "appended \(data.count) bytes to \(spell(path))"

        case 8 ..< 10:
            let size = UInt64(generator.int(0 ... 12000))
            try? await connection.truncateFile(at: path, toLength: size)
            return "set the size of \(spell(path)) to \(size)"

        case 10:
            // A size change through a handle that reads.
            let size = UInt64(generator.int(0 ... 12000))
            let handle = try? await connection.openFile(at: path, accessMode: .readWrite)
            _ = try? await handle?.read(upTo: 4096, atOffset: 0)
            try? await handle?.truncate(toLength: size)
            try? await handle?.close()
            return "truncated \(spell(path)) to \(size) through a handle"

        default:
            // An old modification time: one the file may have had before.
            let date = Date(timeIntervalSince1970: 1_700_000_000)
            try? await connection.changeDate(at: path, write: date)
            return "set the modification time of \(spell(path))"
        }
    }

    // MARK: One operation at a time

    @Test(
        "one operation at a time: after each, the cached connection reads, stats, and lists what the server holds",
        arguments: setups
    )
    func sequential(setup: Setup) async throws {
        var generator = OperationGenerator(seed: Self.seed)

        try await withCachedConnections(setup.configuration, byteBudget: setup.byteBudget) { connections in
            let directory = connections.directory
            var names = Self.names
            var pairs: [KeptPair] = []
            var log: [String] = []
            var failure: String?

            for step in 0 ..< 70 * Self.scale {
                let actor = generator.chance(0.5) ? connections.connection : connections.fork
                let index = generator.int(0 ... Self.names.count - 1)
                let spelled = "\(directory)/\(generator.pick(Self.spellings[index]))"

                switch generator.int(0 ... 99) {
                case 0 ..< 60:
                    await log.append(Self.change(actor, spelled, &generator))

                case 60 ..< 70:
                    // To a name nothing has, or to another file's, which SMB refuses; or only respelled. Samba refuses
                    // to rename a file kept open.
                    let to = switch generator.int(0 ... 2) {
                    case 0: "\(directory)/moved\(index).bin"
                    case 1: "\(directory)/\(generator.pick(Self.names))"
                    default: "\(directory)/\(generator.pick(Self.spellings[index]))"
                    }
                    let from = generator.chance(0.5) ? spelled : "\(directory)/moved\(index).bin"
                    let renamed = await (try? actor.move(from: from, to: to)) != nil
                    log.append("renamed \(spell(from)) to \(spell(to)): \(renamed ? "done" : "failed")")
                    if renamed {
                        // Follow the file under the name the server now keeps.
                        let listed = await (try? connections.truth.listDirectory(at: directory)) ?? []
                        names = listed.map(\.name).filter { $0 != "." && $0 != ".." }
                    }

                case 70 ..< 78:
                    let deleted = await (try? actor.removeFile(at: spelled)) != nil
                    log.append("deleted \(spell(spelled)): \(deleted ? "done" : "failed")")

                case 78 ..< 90:
                    // A handle that stays open, with one on the same file that uses no cache.
                    let cached = try? await connections.connection.openFile(at: spelled)
                    let held = try? await connections.truth.openFile(at: spelled)
                    if let cached, let held {
                        pairs.append((cached, held, index))
                        log.append("opened \(spell(spelled)), and kept it open")
                    }
                    else {
                        try? await cached?.close()
                        try? await held?.close()
                        if (cached == nil) != (held == nil) {
                            failure = "\(spell(spelled)) \(cached == nil ? "could not be" : "was") opened through the cache"
                        }
                    }

                default:
                    if !pairs.isEmpty {
                        let pair = pairs.remove(at: generator.int(0 ... pairs.count - 1))
                        try? await pair.cached.close()
                        try? await pair.held.close()
                        log.append("closed a handle kept open on file \(pair.index)")
                    }
                }

                // The names the server keeps, which renames change.
                if let listed = try? await connections.truth.listDirectory(at: directory) {
                    names = listed.map(\.name).filter { $0 != "." && $0 != ".." }
                }
                if names.isEmpty {
                    names = Self.names
                }

                if failure == nil {
                    failure = await Self.difference(
                        connections,
                        directory: directory,
                        pairs: pairs,
                        names: names,
                        &generator
                    )
                }
                if let failure {
                    Issue.record(
                        """
                        \(setup.name), seed \(Self.seed), after operation \(step): \(failure)
                        last operations:
                        \(log.suffix(20).joined(separator: "\n"))
                        """
                    )
                    break
                }
            }

            for pair in pairs {
                try? await pair.cached.close()
                try? await pair.held.close()
            }
            #expect(connections.gated.hits > 0, "the cache answered no read: the run compared the server with itself")
        }
    }

    // MARK: Operations in flight together

    @Test(
        "tasks changing files of their own while reading each other's: once they are done, the cache shows the server",
        arguments: setups
    )
    func concurrent(setup: Setup) async throws {
        var generator = OperationGenerator(seed: Self.seed)

        try await withCachedConnections(setup.configuration, byteBudget: setup.byteBudget) { connections in
            let directory = connections.directory
            let count = Self.names.count

            // Each task changes one file only, under any of its spellings, so no two changes race for the same bytes or
            // the same path, while every task reads, stats, and lists what the others are changing.
            var moved = [Bool](repeating: false, count: count)
            func real(_ index: Int, _ isMoved: Bool) -> String {
                isMoved ? "\(directory)/moved\(index).bin" : "\(directory)/\(Self.names[index])"
            }

            for round in 0 ..< 5 * Self.scale {
                var pairs: [KeptPair] = []
                for index in 0 ..< count where generator.chance(0.5) {
                    let path = real(index, moved[index])
                    let cached = try? await connections.connection.openFile(at: path)
                    let held = try? await connections.truth.openFile(at: path)
                    if let cached, let held {
                        pairs.append((cached, held, index))
                    }
                    else {
                        try? await cached?.close()
                        try? await held?.close()
                    }
                }

                let state = moved
                moved = await withTaskGroup(of: (Int, Bool).self) { group in
                    for index in 0 ..< count {
                        let connection = index % 2 == 0 ? connections.connection : connections.fork
                        let seed = Self.seed &* 1000 &+ UInt64(round * 10 + index)

                        group.addTask {
                            var generator = OperationGenerator(seed: seed)
                            var isMoved = state[index]

                            for _ in 0 ..< 10 {
                                let own = isMoved ? real(index, true)
                                    : "\(directory)/\(generator.pick(Self.spellings[index]))"
                                switch generator.int(0 ... 9) {
                                case 0 ..< 5:
                                    _ = await Self.change(connection, own, &generator)

                                case 5:
                                    // To a name nothing has, and later back. Refused while a handle keeps it open.
                                    let other = real(index, !isMoved)
                                    if await (try? connection.move(from: own, to: other)) != nil {
                                        isMoved.toggle()
                                    }

                                case 6 ..< 8:
                                    let other = generator.int(0 ... count - 1)
                                    _ = await contents(connection, real(other, state[other]))

                                case 8:
                                    let other = generator.int(0 ... count - 1)
                                    _ = try? await connection.stat(at: real(other, state[other]))

                                default:
                                    _ = try? await connection.listDirectory(at: directory)
                                }
                            }
                            return (index, isMoved)
                        }
                    }

                    var moved = state
                    for await (index, isMoved) in group {
                        moved[index] = isMoved
                    }
                    return moved
                }

                let names = (0 ..< count).map { String(real($0, moved[$0]).dropFirst(directory.count + 1)) }
                let failure = await Self.difference(
                    connections,
                    directory: directory,
                    pairs: pairs,
                    names: names,
                    &generator
                )
                for pair in pairs {
                    try? await pair.cached.close()
                    try? await pair.held.close()
                }
                if let failure {
                    Issue.record("\(setup.name), seed \(Self.seed), after round \(round): \(failure)")
                    break
                }
            }
        }
    }
}
