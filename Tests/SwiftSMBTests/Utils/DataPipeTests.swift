//
// Part of SwiftSMB
// DataPipeTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Foundation
import Testing

struct DataPipeTests {
    @Test("send and receive package round trip")
    func sendReceivePackageRoundTrip() {
        let pipe = DataPipe(label: "SwiftSMBTests.DataPipeTests.roundTrip")
        let data = Data([0x01, 0x02, 0x03])

        pipe.send(.start)
        pipe.send(.data(data))
        pipe.send(.finish)

        #expect(pipe.receive(timeout: nil) == .start)
        #expect(pipe.receive(timeout: nil) == .data(data))
        #expect(pipe.receive(timeout: nil) == .finish)
    }

    @Test("receive times out when empty")
    func receiveTimesOutWhenEmpty() {
        let pipe = DataPipe(label: "SwiftSMBTests.DataPipeTests.timeout")

        #expect(pipe.receive(timeout: 0.01) == nil)
    }

    @Test("send blocks when all packages are full")
    func sendBlocksWhenFull() async throws {
        let pipe = DataPipe(maxPackages: 1, label: "SwiftSMBTests.DataPipeTests.sendBlocksWhenFull")
        pipe.send(.data(Data([0x01])))

        let sent = Protected(false, label: "SwiftSMBTests.DataPipeTests.sendBlocksWhenFull.sent")
        Task.detached {
            pipe.send(.data(Data([0x02])))
            sent.current = true
        }

        try await Task.sleep(for: .milliseconds(100))
        #expect(sent.current == false)
        #expect(pipe.receive(timeout: nil) == .data(Data([0x01])))
        #expect(try await eventually { sent.current })
        #expect(pipe.receive(timeout: nil) == .data(Data([0x02])))
    }

    @Test("receive blocks until producer sends")
    func receiveBlocksUntilSend() async throws {
        let pipe = DataPipe(label: "SwiftSMBTests.DataPipeTests.receiveBlocksUntilSend")
        let got = Protected<DataPipe.Package?>(nil, label: "SwiftSMBTests.DataPipeTests.receiveBlocksUntilSend.got")

        Task.detached {
            got.current = pipe.receive(timeout: nil)
        }

        try await Task.sleep(for: .milliseconds(100))
        #expect(got.current == nil)
        pipe.send(.data(Data([0xEE])))
        #expect(try await eventually { got.current == .data(Data([0xEE])) })
    }

    @Test("finish and broken are delivered as terminal packages")
    func finishAndBrokenAreDelivered() {
        let pipe = DataPipe(label: "SwiftSMBTests.DataPipeTests.terminals")

        pipe.send(.finish)
        pipe.send(.broken)

        #expect(pipe.receive(timeout: nil) == .finish)
        #expect(pipe.receive(timeout: nil) == .broken)
    }

    @Test("pipe can deinitialize with undrained packages")
    func deinitializeWithUndrainedPackages() {
        do {
            let pipe = DataPipe(maxPackages: 2, label: "SwiftSMBTests.DataPipeTests.undrained")

            pipe.send(.data(Data([0x01])))
            pipe.send(.finish)
        }
    }

    @Test("concurrent producer and consumer transfer all data in order")
    func concurrentProducerConsumerOrdered() async throws {
        let pipe = DataPipe(maxPackages: 4, label: "SwiftSMBTests.DataPipeTests.concurrent")
        let completed = Protected(
            false,
            label: "SwiftSMBTests.DataPipeTests.concurrent.completed",
        )
        let producerCount = 64
        let received = Protected<[UInt8]>([], label: "SwiftSMBTests.DataPipeTests.concurrent.received")

        Task.detached {
            while let package = pipe.receive(timeout: nil) {
                switch package {
                case .start:
                    continue
                case let .data(chunk):
                    var bytes = received.current
                    bytes.append(contentsOf: chunk)
                    received.current = bytes
                case .finish:
                    completed.current = true
                    return
                case .broken:
                    return
                }
            }
        }

        Task.detached {
            pipe.send(.start)
            for i in 0 ..< producerCount {
                pipe.send(.data(Data([UInt8(i)])))
            }
            pipe.send(.finish)
        }

        #expect(try await eventually(timeout: .seconds(5)) { completed.current })
        #expect(received.current == (0 ..< producerCount).map { UInt8($0) })
    }
}

private func eventually(
    timeout: Duration = .seconds(2),
    _ condition: () -> Bool,
) async throws -> Bool {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if condition() {
            return true
        }
        try await Task.sleep(for: .milliseconds(10))
    }
    return condition()
}
