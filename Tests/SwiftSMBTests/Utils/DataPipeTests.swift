//
// Part of SwiftSMB
// DataPipeTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Dispatch
import Foundation
import Testing

struct DataPipeTests {
    // MARK: - Init / capacity

    @Test("init splits totalCapacity into equal slots")
    func initSplitsTotalCapacityIntoEqualSlots() {
        let pipe = DataPipe(totalCapacity: 32, slotCount: 4)
        #expect(pipe.totalCapacity == 32)
        #expect(pipe.slotCount == 4)
        #expect(pipe.slotCapacity == 8)
    }

    @Test("default slotCount is 4")
    func defaultSlotCountIsFour() {
        let pipe = DataPipe(totalCapacity: 16)
        #expect(pipe.slotCount == 4)
        #expect(pipe.slotCapacity == 4)
    }

    @Test("isAtEndOfProduction is false initially")
    func isAtEndInitiallyFalse() {
        let pipe = DataPipe(totalCapacity: 8, slotCount: 2)
        #expect(pipe.isAtEndOfProduction == false)
    }

    // MARK: - Single send / receive

    @Test("send and receive Data round trip")
    func sendReceiveDataRoundTrip() {
        let pipe = DataPipe(totalCapacity: 16, slotCount: 4)
        pipe.send(Data([0x01, 0x02, 0x03]))
        #expect(pipe.receive() == Data([0x01, 0x02, 0x03]))
    }

    @Test("send via writer closure and receive via reader closure")
    func sendReceiveZeroCopyRoundTrip() {
        let pipe = DataPipe(totalCapacity: 16, slotCount: 4)
        pipe.send(validByteCount: 4) { buf in
            buf.copyBytes(from: [0xAA, 0xBB, 0xCC, 0xDD] as [UInt8])
        }
        let bytes = pipe.receive { Array($0) }
        #expect(bytes == [0xAA, 0xBB, 0xCC, 0xDD])
    }

    @Test("writer receives a full slot")
    func writerReceivesFullSlot() {
        let pipe = DataPipe(totalCapacity: 16, slotCount: 4)
        pipe.send(validByteCount: 1) { buf in
            #expect(buf.count == pipe.slotCapacity)
            buf[0] = 0xAA
        }
        #expect(pipe.receive() == Data([0xAA]))
    }

    @Test("reader receives only valid bytes")
    func readerReceivesOnlyValidBytes() {
        let pipe = DataPipe(totalCapacity: 16, slotCount: 4)
        pipe.send(validByteCount: 2) { buf in
            buf.copyBytes(from: [0xAA, 0xBB, 0xCC, 0xDD] as [UInt8])
        }
        let bytes = pipe.receive { Array($0) }
        #expect(bytes == [0xAA, 0xBB])
    }

    @Test("send empty Data is a no-op")
    func sendEmptyDataIsNoOp() {
        let pipe = DataPipe(totalCapacity: 8, slotCount: 2)
        pipe.send(Data([0xAA]))
        pipe.send(Data())
        #expect(pipe.receive() == Data([0xAA]))
        pipe.endOfProduction()
        #expect(pipe.receive() == nil)
    }

    @Test("send with zero valid bytes consumes a slot")
    func sendWithZeroValidBytesConsumesSlot() {
        let pipe = DataPipe(totalCapacity: 8, slotCount: 2)
        pipe.send(validByteCount: 0) { _ in }
        let result = pipe.receive { $0.count }
        #expect(result == 0)
    }

    // MARK: - FIFO ordering and ring wrap

    @Test("multiple slots preserve FIFO order")
    func multipleSlotsPreserveFifo() {
        let pipe = DataPipe(totalCapacity: 12, slotCount: 3)
        pipe.send(Data([0x01]))
        pipe.send(Data([0x02]))
        pipe.send(Data([0x03]))
        #expect(pipe.receive() == Data([0x01]))
        #expect(pipe.receive() == Data([0x02]))
        #expect(pipe.receive() == Data([0x03]))
    }

    @Test("ring buffer wraps around")
    func ringBufferWraps() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        pipe.send(Data([0x01]))
        pipe.send(Data([0x02]))
        #expect(pipe.receive() == Data([0x01]))
        pipe.send(Data([0x03]))
        #expect(pipe.receive() == Data([0x02]))
        pipe.send(Data([0x04]))
        #expect(pipe.receive() == Data([0x03]))
        #expect(pipe.receive() == Data([0x04]))
    }

    // MARK: - Backpressure

    @Test("send blocks when all slots are full")
    func sendBlocksWhenFull() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        pipe.send(Data([0x01]))
        pipe.send(Data([0x02]))

        let sent = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            pipe.send(Data([0x03]))
            sent.signal()
        }

        #expect(sent.wait(timeout: .now() + .milliseconds(100)) == .timedOut)
        #expect(pipe.receive() == Data([0x01]))
        #expect(sent.wait(timeout: .now() + .seconds(2)) == .success)
        #expect(pipe.receive() == Data([0x02]))
        #expect(pipe.receive() == Data([0x03]))
    }

    @Test("receive blocks until producer sends")
    func receiveBlocksUntilSend() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        let received = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var got: Data?

        Thread.detachNewThread {
            got = pipe.receive()
            received.signal()
        }

        #expect(received.wait(timeout: .now() + .milliseconds(100)) == .timedOut)
        pipe.send(Data([0xEE]))
        #expect(received.wait(timeout: .now() + .seconds(2)) == .success)
        #expect(got == Data([0xEE]))
    }

    // MARK: - endOfProduction

    @Test("receive after end and drain returns nil")
    func receiveAfterEndAndDrainReturnsNil() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        pipe.send(Data([0x01]))
        pipe.endOfProduction()
        #expect(pipe.isAtEndOfProduction == true)
        #expect(pipe.receive() == Data([0x01]))
        #expect(pipe.receive() == nil)
    }

    @Test("receive after end and drain does not invoke reader")
    func receiveAfterEndAndDrainDoesNotInvokeReader() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        pipe.endOfProduction()
        var invoked = false
        let result: Int? = pipe.receive { _ in
            invoked = true
            return 1
        }
        #expect(result == nil)
        #expect(invoked == false)
    }

    @Test("blocked receive wakes and returns nil on end")
    func blockedReceiveWakesOnEnd() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        let received = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var got: Data?? = nil

        Thread.detachNewThread {
            got = pipe.receive()
            received.signal()
        }

        #expect(received.wait(timeout: .now() + .milliseconds(100)) == .timedOut)
        pipe.endOfProduction()
        #expect(received.wait(timeout: .now() + .seconds(2)) == .success)
        #expect(got == .some(nil))
    }

    @Test("end with pending slots — consumer drains then nil")
    func endWithPendingDrainsThenNil() {
        let pipe = DataPipe(totalCapacity: 6, slotCount: 3)
        pipe.send(Data([0x01]))
        pipe.send(Data([0x02]))
        pipe.endOfProduction()
        #expect(pipe.receive() == Data([0x01]))
        #expect(pipe.receive() == Data([0x02]))
        #expect(pipe.receive() == nil)
        #expect(pipe.receive() == nil)
    }

    @Test("repeated endOfProduction is idempotent")
    func repeatedEndIsIdempotent() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        pipe.endOfProduction()
        pipe.endOfProduction()
        pipe.endOfProduction()
        #expect(pipe.receive() == nil)
        #expect(pipe.receive() == nil)
    }

    // MARK: - Throws / rollback

    @Test("writer throw releases slot")
    func writerThrowReleasesSlot() {
        let pipe = DataPipe(totalCapacity: 2, slotCount: 2)
        pipe.send(Data([0x01]))

        do {
            try pipe.send(validByteCount: 1) { _ in throw TestError.testFailure }
            Issue.record("Expected throw")
        }
        catch {
        }

        #expect(pipe.receive() == Data([0x01]))
        pipe.send(Data([0x02]))
        pipe.send(Data([0x03]))
        #expect(pipe.receive() == Data([0x02]))
        #expect(pipe.receive() == Data([0x03]))
    }

    @Test("reader throw consumes the slot")
    func readerThrowConsumesSlot() {
        let pipe = DataPipe(totalCapacity: 4, slotCount: 2)
        pipe.send(Data([0x01]))
        pipe.send(Data([0x02]))

        do {
            _ = try pipe.receive { _ in throw TestError.testFailure }
            Issue.record("Expected throw")
        }
        catch {
        }

        #expect(pipe.receive() == Data([0x02]))
    }

    // MARK: - Producer/consumer integration

    @Test("concurrent producer and consumer transfer all data in order")
    func concurrentProducerConsumerOrdered() {
        let pipe = DataPipe(totalCapacity: 16, slotCount: 4)
        let sentinel = DispatchSemaphore(value: 0)
        let producerCount = 64
        nonisolated(unsafe) var received: [UInt8] = []
        received.reserveCapacity(producerCount)

        Thread.detachNewThread {
            while let chunk = pipe.receive() {
                received.append(contentsOf: chunk)
            }
            sentinel.signal()
        }

        Thread.detachNewThread {
            for i in 0 ..< producerCount {
                pipe.send(Data([UInt8(i)]))
            }
            pipe.endOfProduction()
        }

        #expect(sentinel.wait(timeout: .now() + .seconds(5)) == .success)
        #expect(received == (0 ..< producerCount).map { UInt8($0) })
    }
}

private enum TestError: Error {
    case testFailure
}
