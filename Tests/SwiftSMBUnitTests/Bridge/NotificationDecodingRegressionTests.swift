//
// Part of SwiftSMB
// NotificationDecodingRegressionTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

struct NotificationDecodingRegressionTests {
    @Test("notify decoding accepts aligned entries and preserves unknown actions")
    func acceptsAlignedEntries() throws {
        var bytes = entry(nextOffset: 16, action: 1, name: "a")
        bytes.append(contentsOf: [0, 0])
        bytes.append(contentsOf: entry(nextOffset: 0, action: 999, name: "folder\\file.txt"))

        let changes = try decode(bytes).get()
        #expect(changes.count == 2)
        #expect(changes[0].action == .added)
        #expect(changes[0].name == "a")
        #expect(changes[1].action == .unknown(999))
        #expect(changes[1].name == "folder/file.txt")
    }

    @Test("notify decoding rejects entries overlapping the previous filename")
    func rejectsOverlappingEntries() {
        // The first entry claims a 16-byte name, but its next offset points to the beginning of that name. Both
        // headers individually fit in the buffer, so merely checking monotonic offsets accepted this response.
        var bytes = notificationUInt32(12) + notificationUInt32(1) + notificationUInt32(16)
        bytes.append(contentsOf: entry(nextOffset: 0, action: 2, name: "ab"))
        expectMalformed(decode(bytes))
    }

    @Test("notify decoding rejects unaligned next-entry offsets")
    func rejectsUnalignedEntries() {
        var bytes = entry(nextOffset: 14, action: 1, name: "a")
        bytes.append(contentsOf: entry(nextOffset: 0, action: 2, name: "b"))
        expectMalformed(decode(bytes))
    }

    @Test("notify decoding rejects malformed lengths", arguments: malformedNotificationPackets)
    func rejectsMalformedLengths(_ bytes: [UInt8]) {
        expectMalformed(decode(bytes))
    }

    private func decode(_ bytes: [UInt8]) -> Result<[Bridge.NotifyChange], SMB.Error> {
        bytes.withUnsafeBytes { Bridge.decodeNotifyChanges($0) }
    }

    private func expectMalformed(_ result: Result<[Bridge.NotifyChange], SMB.Error>) {
        guard case .failure = result else {
            Issue.record("Expected malformed notify response to fail decoding")
            return
        }
    }

    private func entry(nextOffset: UInt32, action: UInt32, name: String) -> [UInt8] {
        let nameBytes = Array(name.data(using: .utf16LittleEndian)!)
        return notificationUInt32(nextOffset) + notificationUInt32(action) +
            notificationUInt32(UInt32(nameBytes.count)) + nameBytes
    }
}

private func notificationUInt32(_ value: UInt32) -> [UInt8] {
    withUnsafeBytes(of: value.littleEndian) { Array($0) }
}

private let malformedNotificationPackets: [[UInt8]] = {
    var oddNameLength = notificationUInt32(0)
    oddNameLength.append(contentsOf: notificationUInt32(1))
    oddNameLength.append(contentsOf: notificationUInt32(3))
    oddNameLength.append(contentsOf: [0, 0, 0])

    var excessiveNameLength = notificationUInt32(0)
    excessiveNameLength.append(contentsOf: notificationUInt32(1))
    excessiveNameLength.append(contentsOf: notificationUInt32(10))
    excessiveNameLength.append(contentsOf: [0, 0])

    var excessiveEntryOffset = notificationUInt32(UInt32.max)
    excessiveEntryOffset.append(contentsOf: notificationUInt32(1))
    excessiveEntryOffset.append(contentsOf: notificationUInt32(0))

    return [[UInt8](repeating: 0, count: 11), oddNameLength, excessiveNameLength, excessiveEntryOffset]
}()
