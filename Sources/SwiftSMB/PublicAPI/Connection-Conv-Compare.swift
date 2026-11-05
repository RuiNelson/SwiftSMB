//
// Part of SwiftSMB
// Connection-Conv-Compare.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// The order in which ``SMB/Connection/compareFiles(_:_:scan:maximumBlockSize:minimumCoverage:)`` compares blocks.
    ///
    /// The files are divided into the fewest blocks of at most `maximumBlockSize` bytes, all of the same size give or
    /// take one byte, so no short block is left at the end. The order matters only when `minimumCoverage` is below
    /// `1.0`, where it decides which part of the files the comparison covers before it stops.
    enum FileCompareScan: Equatable, CustomDebugStringConvertible, Sendable {
        /// Compares the blocks from the first to the last.
        case startToEnd

        /// Compares the blocks from the last to the first.
        case endToStart

        /// Compares the first block, then the last, then the middle one, then the middles of each half, and so on,
        /// breadth first.
        ///
        /// Each pass halves the largest gap left uncompared, so any coverage spreads evenly across the files. This
        /// catches early the usual ways two copies drift apart: truncation, interrupted transfers, appends and changed
        /// headers.
        case bisection

        public var debugDescription: String {
            switch self {
            case .startToEnd: "SMB.FileCompareScan.startToEnd"
            case .endToStart: "SMB.FileCompareScan.endToStart"
            case .bisection: "SMB.FileCompareScan.bisection"
            }
        }
    }
}

public extension SMB.Connection {
    /// Compares two files on the share block by block, without asking the server to hash them.
    ///
    /// Sizes are compared first. Then both files are divided into equal blocks of at most `maximumBlockSize` bytes and
    /// read with positional reads in the order `scan` gives, until a block differs or the bytes compared reach
    /// `minimumCoverage` of the file size.
    ///
    /// A symbolic link compares as its target when the server resolves it, as Samba does. A link the server reports as
    /// a link isn't a regular file.
    ///
    /// - Parameters:
    ///   - pathA: The path of the first file, relative to the share root.
    ///   - pathB: The path of the second file, relative to the share root.
    ///   - scan: The order in which the blocks are compared.
    ///   - maximumBlockSize: The largest block to compare, in bytes. Blocks shrink below it so that all are the same
    /// size give or take one byte. Each block is read in requests of at most the server's maximum read size. Must be
    /// greater than zero.
    ///   - minimumCoverage: The fraction of the file, in `0 < minimumCoverage <= 1`, to compare before declaring the
    /// files equal. `1.0` compares every byte.
    /// - Returns: `true` when every compared block matches, including when both files are empty. `false` when the sizes
    /// differ, a block differs, or either path doesn't exist or isn't a regular file. Below a `minimumCoverage` of
    /// `1.0`, `true` only vouches for the blocks compared.
    /// - Throws: ``SMB/Error`` if the connection is closed, a path is invalid, or a file cannot be inspected, opened or
    /// read; `CancellationError` if the task is cancelled.
    func compareFiles(
        _ pathA: String,
        _ pathB: String,
        scan: SMB.FileCompareScan = .bisection,
        maximumBlockSize: UInt64 = 1024 * 1024,
        minimumCoverage: Double = 1.0
    ) async throws -> Bool {
        precondition(minimumCoverage > 0 && minimumCoverage <= 1.0, "minimumCoverage must be in (0, 1]")
        precondition(maximumBlockSize > 0, "maximumBlockSize must be greater than zero")

        return try await self.withOperation {
            guard let size = try await regularFileSize(at: pathA),
                  try await regularFileSize(at: pathB) == size else {
                return false
            }

            guard size > 0 else {
                return true
            }

            let fileA = try await openFile(at: pathA)
            let fileB: SMB.File
            do {
                fileB = try await openFile(at: pathB)
            }
            catch {
                try? await fileA.close()
                throw error
            }

            do {
                let result = try await FileBlockComparison(
                    size: size,
                    scan: scan,
                    maximumBlockSize: maximumBlockSize,
                    minimumCoverage: minimumCoverage
                ).run { offset, length in
                    let a = try await fileA.read(upTo: Int64(length), atOffset: offset)
                    let b = try await fileB.read(upTo: Int64(length), atOffset: offset)

                    // A file that changed size under the comparison reads short; that is a difference.
                    return a.count == length && a == b
                }

                try await fileA.close()
                try await fileB.close()
                return result
            }
            catch {
                try? await fileA.close()
                try? await fileB.close()
                throw error
            }
        }
    }

    /// Compares a local file with a file on the share block by block, for example to verify an upload or a download.
    ///
    /// Behaves like ``compareFiles(_:_:scan:maximumBlockSize:minimumCoverage:)``, reading each local block on a
    /// dedicated queue while the remote one is in flight. Symbolic links in `local` are followed.
    ///
    /// - Parameters:
    ///   - local: The local file URL.
    ///   - remote: The path of the remote file, relative to the share root.
    ///   - scan: The order in which the blocks are compared.
    ///   - maximumBlockSize: The largest block to compare, in bytes. Blocks shrink below it so that all are the same
    /// size give or take one byte. Each block is read in requests of at most the server's maximum read size. Must be
    /// greater than zero.
    ///   - minimumCoverage: The fraction of the file, in `0 < minimumCoverage <= 1`, to compare before declaring the
    /// files equal. `1.0` compares every byte.
    /// - Returns: `true` when every compared block matches, including when both files are empty. `false` when the sizes
    /// differ, a block differs, or either path doesn't exist or isn't a regular file. Below a `minimumCoverage` of
    /// `1.0`, `true` only vouches for the blocks compared.
    /// - Throws: ``SMB/Error`` if the connection is closed, `remote` is invalid, or the remote file cannot be
    /// inspected, opened or read; a local file error if the local file cannot be opened or read; `CancellationError` if
    /// the task is cancelled.
    func compareFiles(
        local: URL,
        remote: String,
        scan: SMB.FileCompareScan = .bisection,
        maximumBlockSize: UInt64 = 1024 * 1024,
        minimumCoverage: Double = 1.0
    ) async throws -> Bool {
        precondition(minimumCoverage > 0 && minimumCoverage <= 1.0, "minimumCoverage must be in (0, 1]")
        precondition(maximumBlockSize > 0, "maximumBlockSize must be greater than zero")

        return try await self.withOperation {
            let localFile = LocalCompareReader()
            defer { localFile.close() }

            guard let size = try await localFile.open(local),
                  try await regularFileSize(at: remote) == size else {
                return false
            }

            guard size > 0 else {
                return true
            }

            let remoteFile = try await openFile(at: remote)
            do {
                let result = try await FileBlockComparison(
                    size: size,
                    scan: scan,
                    maximumBlockSize: maximumBlockSize,
                    minimumCoverage: minimumCoverage
                ).run { offset, length in
                    async let localBlock = localFile.read(offset: offset, length: length)
                    let remoteBlock = try await remoteFile.read(upTo: Int64(length), atOffset: offset)
                    let localData = try await localBlock

                    // A file that changed size under the comparison reads short; that is a difference.
                    return localData.count == length && localData == remoteBlock
                }

                try await remoteFile.close()
                return result
            }
            catch {
                try? await remoteFile.close()
                throw error
            }
        }
    }
}

private extension SMB.Connection {
    /// The size of the regular file at `path`, or `nil` when nothing exists there or it isn't a regular file.
    func regularFileSize(at path: String) async throws -> UInt64? {
        do {
            let stat = try await stat(at: path)
            return stat.type == .file ? stat.size : nil
        }
        catch let error as SMB.Error where error.isPathNotFound {
            return nil
        }
    }
}

// MARK: - Local file

/// Reads blocks of a local file on a dedicated serial queue, off the Swift concurrency cooperative pool.
private final class LocalCompareReader: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.SMB.Connection.compareFiles.disk")
    /// The open file. Guarded by `queue`.
    private var handle: FileHandle?

    deinit {
        try? handle?.close()
    }

    /// Opens the file at `url` and returns its size, or `nil` when nothing exists there or it isn't a regular file.
    func open(_ url: URL) async throws -> UInt64? {
        try await perform {
            let path = url.resolvingSymlinksInPath().path
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  attributes[.type] as? FileAttributeType == .typeRegular,
                  let size = (attributes[.size] as? NSNumber)?.uint64Value else {
                return nil
            }
            self.handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
            return size
        }
    }

    /// Reads up to `length` bytes at `offset`.
    func read(offset: UInt64, length: Int) async throws -> Data {
        try await perform {
            guard let handle = self.handle else {
                return Data()
            }
            try handle.seek(toOffset: offset)
            return try handle.read(upToCount: length) ?? Data()
        }
    }

    /// Closes the file once queued reads have finished.
    func close() {
        queue.async {
            try? self.handle?.close()
            self.handle = nil
        }
    }

    private func perform<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try body() })
            }
        }
    }
}

// MARK: - Block comparison

/// Divides a file into the fewest blocks of at most `maximumBlockSize` bytes, all of the same size give or take one
/// byte.
///
/// With `size = blockCount * base + remainder`, the first `remainder` blocks hold `base + 1` bytes and the rest `base`.
struct FileCompareGrid: Equatable {
    let size: UInt64
    let blockCount: UInt64
    private let base: UInt64
    private let remainder: UInt64

    init(size: UInt64, maximumBlockSize: UInt64) {
        precondition(maximumBlockSize > 0, "maximumBlockSize must be greater than zero")
        self.size = size
        blockCount = size / maximumBlockSize + (size % maximumBlockSize == 0 ? 0 : 1)
        base = blockCount == 0 ? 0 : size / blockCount
        remainder = blockCount == 0 ? 0 : size % blockCount
    }

    /// The file offset where block `index` starts; `offset(blockCount)` is the file size.
    func offset(_ index: UInt64) -> UInt64 {
        index * base + min(index, remainder)
    }

    /// The length of block `index` in bytes.
    func length(_ index: UInt64) -> UInt64 {
        base + (index < remainder ? 1 : 0)
    }
}

/// Walks the block grid of two equally sized files in a ``SMB/FileCompareScan`` order until a block differs or the
/// coverage target is met.
struct FileBlockComparison {
    let size: UInt64
    let scan: SMB.FileCompareScan
    let maximumBlockSize: UInt64
    let minimumCoverage: Double

    /// Compares one block: returns whether the `length` bytes at `offset` match.
    typealias CompareBlock = (_ offset: UInt64, _ length: Int) async throws -> Bool

    /// The number of bytes to compare before the files count as equal: `minimumCoverage` of `size`, rounded up.
    ///
    /// `Double` holds integers exactly only up to 2^53, so `Double(size)` can round below `size` (a full comparison
    /// would then skip its last blocks) or up to 2^64 (which `UInt64` cannot hold). A full coverage therefore never
    /// goes through `Double`, and a partial one is clamped to `size`.
    static func targetBytes(size: UInt64, minimumCoverage: Double) -> UInt64 {
        guard minimumCoverage < 1 else {
            return size
        }
        let target = (minimumCoverage * Double(size)).rounded(.up)
        return target < Double(size) ? UInt64(target) : size
    }

    func run(_ compareBlock: CompareBlock) async throws -> Bool {
        // A block is held in memory as `Data`, so its length must fit in `Int`.
        let grid = FileCompareGrid(size: size, maximumBlockSize: min(maximumBlockSize, UInt64(Int.max)))
        let targetBytes = Self.targetBytes(size: size, minimumCoverage: minimumCoverage)

        var compared: UInt64 = 0
        for index in FileCompareBlockOrder(blockCount: grid.blockCount, scan: scan) {
            try Task.checkCancellation()

            let length = grid.length(index)
            let matches = try await compareBlock(grid.offset(index), Int(length))

            // A read cut short by cancellation must report the cancellation, not a difference.
            try Task.checkCancellation()
            guard matches else {
                return false
            }

            compared += length
            if compared >= targetBytes {
                break
            }
        }

        return true
    }
}

/// The block indices of a grid of `blockCount` blocks, in ``SMB/FileCompareScan`` order, each exactly once.
struct FileCompareBlockOrder: Sequence, IteratorProtocol {
    private let blockCount: UInt64
    private let scan: SMB.FileCompareScan
    private var emitted: UInt64 = 0

    /// Bisection state: open intervals `(lower, upper)` whose interior blocks are still to be emitted, breadth first.
    private var intervals: [(lower: UInt64, upper: UInt64)] = []
    private var intervalHead = 0

    init(blockCount: UInt64, scan: SMB.FileCompareScan) {
        self.blockCount = blockCount
        self.scan = scan
        if blockCount > 2 {
            intervals.append((0, blockCount - 1))
        }
    }

    mutating func next() -> UInt64? {
        guard emitted < blockCount else {
            return nil
        }

        defer { emitted += 1 }

        switch scan {
        case .startToEnd:
            return emitted

        case .endToStart:
            return blockCount - 1 - emitted

        case .bisection:
            if emitted == 0 {
                return 0
            }
            if emitted == 1 {
                return blockCount - 1
            }
            return nextMiddle()
        }
    }

    private mutating func nextMiddle() -> UInt64? {
        while intervalHead < intervals.count {
            let (lower, upper) = intervals[intervalHead]
            intervalHead += 1

            // Drop consumed intervals now and then so the queue stays proportional to the intervals still pending.
            if intervalHead >= 1024, intervalHead * 2 >= intervals.count {
                intervals.removeFirst(intervalHead)
                intervalHead = 0
            }

            guard upper - lower >= 2 else {
                continue
            }

            let middle = lower + (upper - lower) / 2
            intervals.append((lower, middle))
            intervals.append((middle, upper))
            return middle
        }

        return nil
    }
}
