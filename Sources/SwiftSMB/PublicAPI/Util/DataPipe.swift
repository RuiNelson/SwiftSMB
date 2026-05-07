//
// Part of SwiftSMB
// DataPipe.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Dispatch
import Foundation

/// A bounded data pipe that synchronises a single producer with a single
/// consumer, applying backpressure in both directions.
///
/// The pipe owns a fixed memory budget split into a configurable number of
/// equal-sized slots arranged as a ring buffer. ``send(validByteCount:_:)``
/// blocks the producer when every slot is pending consumption.
/// ``receive(_:)`` blocks the consumer when no slot is ready to read, and
/// returns `nil` once the producer has called ``endOfProduction()`` *and*
/// every pending slot has been drained.
///
/// The pipe is single-producer / single-consumer. Concurrent calls from more
/// than one producer or more than one consumer are not supported.
public final class DataPipe: CustomDebugStringConvertible, @unchecked Sendable {
    /// Total bytes allocated across all slots.
    public let totalCapacity: Int

    /// Number of slots in the ring buffer.
    public let slotCount: Int

    /// Bytes of capacity per slot. Equal to ``totalCapacity`` divided by
    /// ``slotCount``.
    public let slotCapacity: Int

    private let storage: UnsafeMutableRawBufferPointer
    private var slotValidByteCounts: [Int]

    private var head: Int
    private var tail: Int
    private var pendingCount: Int
    private var ended: Bool

    private let state: DispatchQueue
    private let free: DispatchSemaphore
    private let full: DispatchSemaphore

    /// Creates a data pipe with the given memory budget and slot count.
    ///
    /// - Parameters:
    ///   - totalCapacity: Total bytes allocated across all slots. Must be a
    ///     positive multiple of `slotCount`.
    ///   - slotCount: Number of slots in the ring buffer. Must be greater
    ///     than zero. Defaults to `4`.
    public init(totalCapacity: Int, slotCount: Int = 4) {
        precondition(slotCount > 0, "DataPipe slotCount must be positive")
        precondition(totalCapacity > 0, "DataPipe totalCapacity must be positive")
        precondition(totalCapacity.isMultiple(of: slotCount), "DataPipe totalCapacity must be a multiple of slotCount")
        self.totalCapacity = totalCapacity
        self.slotCount = slotCount
        self.slotCapacity = totalCapacity / slotCount
        self.storage = .allocate(byteCount: totalCapacity, alignment: MemoryLayout<UInt8>.alignment)
        self.slotValidByteCounts = Array(repeating: 0, count: slotCount)
        self.head = 0
        self.tail = 0
        self.pendingCount = 0
        self.ended = false
        self.state = DispatchQueue(label: "SwiftSMB.DataPipe")
        self.free = DispatchSemaphore(value: slotCount)
        self.full = DispatchSemaphore(value: 0)
    }

    deinit {
        storage.deallocate()
    }

    /// Signals that no more data will be sent.
    ///
    /// Pending slots remain readable via ``receive(_:)`` and ``receive()``;
    /// once they are drained, those calls return `nil`. After this call,
    /// further ``send(validByteCount:_:)`` or ``send(_:)`` triggers a
    /// precondition violation. Calling ``endOfProduction()`` more than once
    /// is a no-op.
    public func endOfProduction() {
        let alreadyEnded = state.sync { () -> Bool in
            let was = ended
            ended = true
            return was
        }
        guard !alreadyEnded else { return }
        full.signal()
    }

    /// A Boolean value indicating whether ``endOfProduction()`` has been
    /// called.
    public var isAtEndOfProduction: Bool {
        state.sync { ended }
    }

    /// Writes the next slot, blocking if every slot is pending consumption.
    ///
    /// - Parameters:
    ///   - validByteCount: Number of valid bytes the writer placed in the
    ///     slot. Must be between `0` and ``slotCapacity``.
    ///   - writer: A closure that fills the slot. Receives a mutable raw
    ///     buffer of ``slotCapacity`` bytes.
    /// - Throws: Rethrows any error from `writer`. On throw, the slot is
    ///   released back to the free pool and the pipe is unchanged.
    public func send(
        validByteCount: Int,
        _ writer: (UnsafeMutableRawBufferPointer) throws -> Void,
    ) rethrows {
        precondition(
            validByteCount >= 0 && validByteCount <= slotCapacity,
            "validByteCount must be between 0 and slotCapacity",
        )
        let endedBeforeWait = state.sync { ended }
        precondition(!endedBeforeWait, "Cannot send after endOfProduction")
        free.wait()
        let endedNow = state.sync { ended }
        precondition(!endedNow, "Cannot send after endOfProduction")
        let idx = tail
        do {
            try writer(slot(at: idx))
        }
        catch {
            free.signal()
            throw error
        }
        state.sync {
            slotValidByteCounts[idx] = validByteCount
            tail = (tail + 1) % slotCount
            pendingCount += 1
        }
        full.signal()
    }

    /// Copies the given data into the next slot, blocking if every slot is
    /// pending consumption.
    ///
    /// Empty `data` is a no-op.
    ///
    /// - Parameter data: The bytes to send. Must not exceed ``slotCapacity``.
    public func send(_ data: Data) {
        precondition(data.count <= slotCapacity, "Data exceeds DataPipe slotCapacity")
        let endedNow = state.sync { ended }
        precondition(!endedNow, "Cannot send after endOfProduction")
        guard !data.isEmpty else { return }
        send(validByteCount: data.count) { buffer in
            data.copyBytes(to: buffer)
        }
    }

    /// Reads the next slot, blocking if no slot is ready.
    ///
    /// Returns `nil` once ``endOfProduction()`` has been called *and* every
    /// pending slot has been drained.
    ///
    /// - Parameter reader: A closure that reads the slot. Receives a raw
    ///   buffer spanning the valid bytes of the slot.
    /// - Returns: The value returned by `reader`, or `nil` if the pipe is
    ///   ended and drained.
    /// - Throws: Rethrows any error from `reader`. On throw, the slot is
    ///   considered consumed and released back to the free pool.
    public func receive<R>(
        _ reader: (UnsafeRawBufferPointer) throws -> R,
    ) rethrows -> R? {
        full.wait()
        let claim: (idx: Int, count: Int)? = state.sync {
            guard pendingCount > 0 else { return nil }
            let idx = head
            let count = slotValidByteCounts[idx]
            head = (head + 1) % slotCount
            pendingCount -= 1
            return (idx, count)
        }
        guard let claim else {
            full.signal()
            return nil
        }
        defer { free.signal() }
        let buffer = UnsafeRawBufferPointer(
            start: storage.baseAddress!.advanced(by: claim.idx * slotCapacity),
            count: claim.count,
        )
        return try reader(buffer)
    }

    /// Reads the next slot as `Data`, blocking if no slot is ready.
    ///
    /// Returns `nil` once ``endOfProduction()`` has been called *and* every
    /// pending slot has been drained.
    public func receive() -> Data? {
        receive { Data($0) }
    }

    public var debugDescription: String {
        "DataPipe(totalCapacity: \(totalCapacity), slotCount: \(slotCount), slotCapacity: \(slotCapacity))"
    }

    private func slot(at index: Int) -> UnsafeMutableRawBufferPointer {
        UnsafeMutableRawBufferPointer(
            start: storage.baseAddress!.advanced(by: index * slotCapacity),
            count: slotCapacity,
        )
    }
}
