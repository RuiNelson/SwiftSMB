//
// Part of SwiftSMB
// InMemoryCacheStorageTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

@Suite("InMemoryCacheStorage")
struct InMemoryCacheStorageTests {
    @Test("writes are read back from their offset, merged, and counted")
    func writeAndRead() {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 1000)
        let file = SMB.CacheFileID()

        #expect(storage.write(CacheFuzz.bytes(10), at: 0, of: file))
        #expect(storage.write(CacheFuzz.bytes(10, from: 10), at: 10, of: file))
        #expect(storage.write(CacheFuzz.bytes(5, from: 50), at: 50, of: file))
        #expect(storage.write(Data(), at: 500, of: file))

        #expect(storage.ranges(of: file) == [0 ..< 20, 50 ..< 55])
        #expect(storage.byteCount == 25)
        #expect(storage.read(file, at: 5, upTo: 100) == CacheFuzz.bytes(15, from: 5))
        #expect(storage.read(file, at: 5, upTo: 3) == CacheFuzz.bytes(3, from: 5))
        #expect(storage.read(file, at: 20, upTo: 100) == nil)
        #expect(storage.read(SMB.CacheFileID(), at: 0, upTo: 100) == nil)
        #expect(storage.ranges(of: SMB.CacheFileID()) == [])
        #expect(storage.invariantViolations() == [])
    }

    @Test("retaining and removing drop bytes, and a file left without bytes is no longer held")
    func retainAndRemove() {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 1000)
        let file = SMB.CacheFileID()
        let other = SMB.CacheFileID()
        storage.write(CacheFuzz.bytes(100), at: 0, of: file)
        storage.write(CacheFuzz.bytes(10), at: 0, of: other)

        storage.retain([10 ..< 20, 90 ..< 200], of: file)
        #expect(storage.ranges(of: file) == [10 ..< 20, 90 ..< 100])
        #expect(storage.byteCount == 30)

        storage.retain([], of: file)
        #expect(!storage.storedFiles.contains(file))
        storage.retain([0 ..< 5], of: SMB.CacheFileID())

        storage.remove(other)
        storage.remove(other)
        #expect(storage.byteCount == 0)
        #expect(storage.storedFiles.isEmpty)
        #expect(storage.invariantViolations() == [])
    }

    @Test("the budget drops whole files, least recently used first, and never the file being written")
    func leastRecentlyUsed() {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 100)
        let files = (0 ..< 3).map { _ in SMB.CacheFileID() }
        for file in files {
            storage.write(CacheFuzz.bytes(30), at: 0, of: file)
        }

        // Reading the first makes the second the least recently used.
        #expect(storage.read(files[0], at: 0, upTo: 1) != nil)
        let fourth = SMB.CacheFileID()
        storage.write(CacheFuzz.bytes(30), at: 0, of: fourth)
        #expect(storage.storedFiles == [files[0], files[2], fourth])

        // The file being written grows over what the others hold: they go, and it stays.
        storage.write(CacheFuzz.bytes(70), at: 30, of: fourth)
        #expect(storage.storedFiles == [fourth])
        #expect(storage.byteCount == 100)
        #expect(storage.invariantViolations() == [])
    }

    @Test("a file that alone goes over the budget is dropped, and the write reports it")
    func fileOverBudget() {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 100)
        let kept = SMB.CacheFileID()
        let large = SMB.CacheFileID()
        storage.write(CacheFuzz.bytes(50), at: 0, of: kept)

        #expect(storage.write(CacheFuzz.bytes(60), at: 0, of: large))
        #expect(!storage.write(CacheFuzz.bytes(60), at: 60, of: large))
        #expect(storage.ranges(of: large) == [])
        #expect(storage.storedFiles.isEmpty)
        #expect(storage.invariantViolations() == [])

        let none = SMB.InMemoryCacheStorage(byteBudget: 0)
        #expect(!none.write(CacheFuzz.bytes(1), at: 0, of: kept))
        #expect(none.byteCount == 0)
    }

    @Test("files are accepted up to the budget and the maximum file size")
    func accepts() {
        let budgeted = SMB.InMemoryCacheStorage(byteBudget: 100)
        #expect(budgeted.accepts(fileSize: 100))
        #expect(!budgeted.accepts(fileSize: 101))
        #expect(budgeted.maximumFileSize == nil)

        let limited = SMB.InMemoryCacheStorage(byteBudget: 100, maximumFileSize: 40)
        #expect(limited.accepts(fileSize: 0))
        #expect(limited.accepts(fileSize: 40))
        #expect(!limited.accepts(fileSize: 41))
        #expect(!limited.accepts(fileSize: .max))

        #expect(SMB.InMemoryCacheStorage().byteBudget == 256 * 1024 * 1024)
    }

    @Test("a memory warning halves what is held, least recently used first, and a critical one drops everything")
    func memoryPressure() {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 100)
        let files = (0 ..< 3).map { _ in SMB.CacheFileID() }
        for file in files {
            storage.write(CacheFuzz.bytes(30), at: 0, of: file)
        }

        storage.relieveMemoryPressure(critical: false)
        #expect(storage.storedFiles == [files[2]])
        storage.relieveMemoryPressure(critical: true)
        #expect(storage.storedFiles.isEmpty)
        #expect(storage.byteCount == 0)
    }

    @Test("several threads at once leave the books straight and the budget kept")
    func concurrentUse() async {
        let storage = SMB.InMemoryCacheStorage(byteBudget: 5000)
        await withTaskGroup(of: Void.self) { group in
            for task in 0 ..< 8 {
                group.addTask {
                    var generator = SeededGenerator(seed: UInt64(task))
                    let files = (0 ..< 4).map { _ in SMB.CacheFileID() }
                    for _ in 0 ..< 500 {
                        let file = generator.pick(files)
                        switch generator.int(0 ... 9) {
                        case 0 ..< 5:
                            storage.write(
                                generator.bytes(generator.int(1 ... 300)),
                                at: UInt64(generator.int(0 ... 2000)),
                                of: file
                            )
                        case 5 ..< 7:
                            _ = storage.read(file, at: UInt64(generator.int(0 ... 2000)), upTo: 100)
                        case 7:
                            storage.retain([0 ..< UInt64(generator.int(0 ... 1000))], of: file)
                        case 8:
                            storage.remove(file)
                        default:
                            storage.relieveMemoryPressure(critical: false)
                        }
                    }
                }
            }
        }
        #expect(storage.invariantViolations() == [])
    }
}
