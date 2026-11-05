//
// Part of SwiftSMB
// SMBConnectionCompareTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBConnectionCompareTests {
    private static let maximumBlockSize: UInt64 = 1000
    private static let scans: [SMB.FileCompareScan] = [.startToEnd, .endToStart, .bisection]

    /// 10 500 bytes: eleven blocks of 954 or 955 bytes with a 1000-byte maximum.
    private static let payload = Data((0 ..< 10500).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })

    @Test("identical files are equal", arguments: scans)
    func identicalFiles(scan: SMB.FileCompareScan) async throws {
        try await withRemoteDirectory("compare_equal") { connection, dir in
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.dumpToFile(Self.payload, to: "\(dir)/b.bin")

            let result = try await connection.compareFiles(
                "\(dir)/a.bin",
                "\(dir)/b.bin",
                scan: scan,
                maximumBlockSize: Self.maximumBlockSize
            )
            #expect(result)
        }
    }

    @Test("a single differing byte is found", arguments: [0, 4321, 10499])
    func singleByteDifference(position: Int) async throws {
        try await withRemoteDirectory("compare_byte") { connection, dir in
            var changed = Self.payload
            changed[position] ^= 0xFF
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.dumpToFile(changed, to: "\(dir)/b.bin")

            for scan in Self.scans {
                let result = try await connection.compareFiles(
                    "\(dir)/a.bin",
                    "\(dir)/b.bin",
                    scan: scan,
                    maximumBlockSize: Self.maximumBlockSize
                )
                #expect(!result, "scan \(scan)")
            }
        }
    }

    @Test("the default block size compares whole files")
    func defaultBlockSize() async throws {
        try await withRemoteDirectory("compare_default") { connection, dir in
            var changed = Self.payload
            changed[7000] ^= 0xFF
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.dumpToFile(Self.payload, to: "\(dir)/b.bin")
            try await connection.dumpToFile(changed, to: "\(dir)/c.bin")

            #expect(try await connection.compareFiles("\(dir)/a.bin", "\(dir)/b.bin"))
            #expect(try await !connection.compareFiles("\(dir)/a.bin", "\(dir)/c.bin"))
        }
    }

    @Test("files of different sizes differ")
    func differentSizes() async throws {
        try await withRemoteDirectory("compare_size") { connection, dir in
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.dumpToFile(Self.payload.dropLast(), to: "\(dir)/b.bin")

            #expect(try await !connection.compareFiles("\(dir)/a.bin", "\(dir)/b.bin"))
        }
    }

    @Test("empty files are equal")
    func emptyFiles() async throws {
        try await withRemoteDirectory("compare_empty") { connection, dir in
            try await connection.dumpToFile(Data(), to: "\(dir)/a.bin")
            try await connection.dumpToFile(Data(), to: "\(dir)/b.bin")

            #expect(try await connection.compareFiles("\(dir)/a.bin", "\(dir)/b.bin"))
        }
    }

    @Test("partial coverage stops before reaching an uncompared difference")
    func partialCoverage() async throws {
        try await withRemoteDirectory("compare_partial") { connection, dir in
            var changed = Self.payload
            // A 50% bisection of eleven blocks compares blocks 0, 10, 5, 2, 7 and 1, and never reaches block 9.
            changed[9100] ^= 0xFF
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.dumpToFile(changed, to: "\(dir)/b.bin")

            let partial = try await connection.compareFiles(
                "\(dir)/a.bin",
                "\(dir)/b.bin",
                scan: .bisection,
                maximumBlockSize: Self.maximumBlockSize,
                minimumCoverage: 0.5
            )
            #expect(partial)

            let full = try await connection.compareFiles(
                "\(dir)/a.bin",
                "\(dir)/b.bin",
                scan: .bisection,
                maximumBlockSize: Self.maximumBlockSize
            )
            #expect(!full)
        }
    }

    @Test("missing files and directories are not equal")
    func notRegularFiles() async throws {
        try await withRemoteDirectory("compare_irregular") { connection, dir in
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.makeDirectory(at: "\(dir)/sub")

            #expect(try await !connection.compareFiles("\(dir)/a.bin", "\(dir)/missing.bin"))
            #expect(try await !connection.compareFiles("\(dir)/missing.bin", "\(dir)/a.bin"))
            #expect(try await !connection.compareFiles("\(dir)/sub", "\(dir)/a.bin"))
            #expect(try await !connection.compareFiles("\(dir)/sub", "\(dir)/sub"))
        }
    }

    @Test("a link the server follows compares as its target")
    func serverFollowedLink() async throws {
        let connection = try await publicCompareConnection()
        defer { try? await connection.disconnect() }

        // Samba resolves symbolic links on the server, so the link reports as the regular file it points to.
        #expect(try await connection.compareFiles(TestContent.linkToFilePath, TestContent.helloPath))
    }

    @Test("invalid arguments throw")
    func invalidArguments() async throws {
        let connection = try await publicCompareConnection()
        defer { try? await connection.disconnect() }

        let path = TestContent.helloPath
        await #expect(throws: SMB.Error.invalidArgument(
            cause: .blockSizeMustBeGreaterThanZero,
            onOperation: .smbConnectionCompareFiles
        )) {
            try await connection.compareFiles(path, path, maximumBlockSize: 0)
        }
        for coverage in [0, -0.5, 1.5] {
            await #expect(throws: SMB.Error.invalidArgument(
                cause: .minimumCoverageOutOfRange(coverage),
                onOperation: .smbConnectionCompareFiles
            )) {
                try await connection.compareFiles(path, path, minimumCoverage: coverage)
            }
        }
        await #expect(throws: SMB.Error.self) {
            try await connection.compareFiles(path, path, minimumCoverage: .nan)
        }
        await #expect(throws: SMB.Error.self) {
            try await connection.compareFiles("", path)
        }
    }

    @Test("a local file compares against its remote copy")
    func localAgainstRemote() async throws {
        try await withRemoteDirectory("compare_local") { connection, dir in
            let local = FileManager.default.temporaryDirectory
                .appendingPathComponent("swiftsmb-compare-\(UUID().uuidString).bin")
            try Self.payload.write(to: local)
            defer { try? FileManager.default.removeItem(at: local) }

            var changed = Self.payload
            changed[5500] ^= 0xFF
            try await connection.dumpToFile(Self.payload, to: "\(dir)/same.bin")
            try await connection.dumpToFile(changed, to: "\(dir)/changed.bin")
            try await connection.dumpToFile(Self.payload.dropLast(), to: "\(dir)/shorter.bin")

            for scan in Self.scans {
                let same = try await connection.compareFiles(
                    local: local,
                    remote: "\(dir)/same.bin",
                    scan: scan,
                    maximumBlockSize: Self.maximumBlockSize
                )
                #expect(same, "scan \(scan)")

                let different = try await connection.compareFiles(
                    local: local,
                    remote: "\(dir)/changed.bin",
                    scan: scan,
                    maximumBlockSize: Self.maximumBlockSize
                )
                #expect(!different, "scan \(scan)")
            }

            let link = local.deletingPathExtension().appendingPathExtension("link")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: local)
            defer { try? FileManager.default.removeItem(at: link) }
            #expect(try await connection.compareFiles(local: link, remote: "\(dir)/same.bin"))

            #expect(try await !connection.compareFiles(local: local, remote: "\(dir)/shorter.bin"))
            #expect(try await !connection.compareFiles(local: local, remote: "\(dir)/missing.bin"))
        }
    }

    @Test("an empty local file equals an empty remote file")
    func emptyLocalFile() async throws {
        try await withRemoteDirectory("compare_local_empty") { connection, dir in
            let local = FileManager.default.temporaryDirectory
                .appendingPathComponent("swiftsmb-compare-\(UUID().uuidString).bin")
            try Data().write(to: local)
            defer { try? FileManager.default.removeItem(at: local) }
            try await connection.dumpToFile(Data(), to: "\(dir)/empty.bin")

            #expect(try await connection.compareFiles(local: local, remote: "\(dir)/empty.bin"))
        }
    }

    @Test("a local directory or missing file is not equal")
    func localNotRegularFile() async throws {
        try await withRemoteDirectory("compare_local_irregular") { connection, dir in
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")

            let directory = try await connection.compareFiles(
                local: FileManager.default.temporaryDirectory,
                remote: "\(dir)/a.bin"
            )
            #expect(!directory)

            let missing = try await connection.compareFiles(
                local: FileManager.default.temporaryDirectory.appendingPathComponent("missing-\(UUID().uuidString)"),
                remote: "\(dir)/a.bin"
            )
            #expect(!missing)
        }
    }

    @Test("cancellation throws instead of reporting a result")
    func cancellation() async throws {
        try await withRemoteDirectory("compare_cancel") { connection, dir in
            try await connection.dumpToFile(Self.payload, to: "\(dir)/a.bin")
            try await connection.dumpToFile(Self.payload, to: "\(dir)/b.bin")

            let task = Task {
                withUnsafeCurrentTask { $0?.cancel() }
                return try await connection.compareFiles(
                    "\(dir)/a.bin",
                    "\(dir)/b.bin",
                    maximumBlockSize: Self.maximumBlockSize
                )
            }
            await #expect(throws: CancellationError.self) {
                try await task.value
            }
        }
    }

    // MARK: - Helpers

    private func withRemoteDirectory(
        _ label: String,
        _ body: (SMB.Connection, String) async throws -> Void
    ) async throws {
        let connection = try await publicCompareConnection()
        defer { try? await connection.disconnect() }

        let dir = uniquePath(label)
        try await connection.makeDirectory(at: dir)
        do {
            try await body(connection, dir)
        }
        catch {
            try? await connection.removeItem(at: dir)
            throw error
        }
        try await connection.removeItem(at: dir)
    }
}

private func publicCompareConnection() async throws -> SMB.Connection {
    try await SMB.connect(
        server: SMB.Server(host: testServerHost),
        share: TestShare.public
    )
}
