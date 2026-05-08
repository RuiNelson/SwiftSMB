//
// Part of SwiftSMB
// DataPipe.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

/// A bounded pipe that synchronises a single producer with a single consumer.
///
/// `DataPipe` implements a producer–consumer queue with back-pressure: when the
/// internal buffer is full, calls to ``send(_:)`` block the caller until the
/// consumer removes a package or the timeout expires, and when the buffer is
/// empty, calls to ``receive(timeout:)`` block until a package arrives or the
/// timeout expires.
///
/// Thread safety is provided by a serial ``DispatchQueue`` for queue access and
/// two ``DispatchSemaphore`` instances — one that counts available packages and
/// one that counts free slots.
public final class DataPipe: @unchecked Sendable {
    /// A package exchanged between the producer and the consumer.
    public enum Package: Equatable, Sendable {
        /// Sent at the beginning of a transmission to signal that the stream has started.
        case start

        /// Sent at the end of a transmission to signal that an error occurred and the stream has aborted.
        case broken

        /// Sent at the end of a transmission to signal that the stream completed successfully.
        case finish

        /// A package carrying the data payload.
        ///
        /// - Parameter d: The data transmitted in this package.
        case data(_ d: Data)
    }

    private var queue: [Package]
    private let queueSync: DispatchQueue
    private let packagesSemaphore: DispatchSemaphore
    private let isFull: DispatchSemaphore

    /// Creates a new data pipe.
    ///
    /// - Parameters:
    ///   - maxPackages: The maximum number of packages the pipe can hold before
    ///     ``send(_:)`` blocks. Defaults to `3`.
    ///   - label: A label used to name the internal serial dispatch queue.
    public init(maxPackages: Int = 3, label: String) {
        precondition(maxPackages > 0, "maxPackages must be positive")
        queue = .init()
        queueSync = .init(label: label + ".queueAccess")
        packagesSemaphore = .init(value: 0)
        isFull = .init(value: maxPackages)
    }

    private func push(_ package: Package) {
        queueSync.sync {
            queue.append(package)
        }
    }

    private func pop() -> Package? {
        queueSync.sync {
            guard queue.isEmpty == false else {
                return nil
            }
            return queue.removeFirst()
        }
    }

    /// Sends a package to the pipe, blocking the caller when the pipe is full.
    ///
    /// When the internal buffer has reached ``init(maxPackages:label:)``, this
    /// method blocks the calling thread until the consumer removes a package
    /// and frees a slot, or until `timeout` expires.
    ///
    /// - Parameters:
    ///   - package: The ``Package`` to enqueue.
    ///   - timeout: The maximum number of seconds to wait for a free slot.
    ///     Defaults to `nil`, which waits indefinitely.
    /// - Returns: `true` if the package was queued, or `false` if the timeout
    ///   expired before a free slot became available.
    @discardableResult
    public func send(_ package: Package, timeout: TimeInterval? = nil) -> Bool {
        // Wait until a free slot is available in the queue.
        if let timeout {
            guard isFull.wait(timeout: Self.deadline(after: timeout)) == .success else {
                return false
            }
        }
        else {
            isFull.wait()
        }

        // Insert the package safely on the serial queue.
        push(package)

        // Signal that a new package is available for consumption.
        packagesSemaphore.signal()
        return true
    }

    /// Receives the next package from the pipe, blocking when the pipe is empty.
    ///
    /// When the internal buffer is empty, this method blocks the calling thread
    /// until a package arrives or the timeout expires. Passing `nil` for
    /// `timeout` waits indefinitely.
    ///
    /// - Parameter timeout: The maximum number of seconds to wait for a
    ///   package. Defaults to five seconds. Pass `nil` to wait indefinitely.
    /// - Returns: The next ``Package``, or `nil` if the timeout expired before
    ///   a package became available.
    public func receive(timeout: TimeInterval? = 5) -> Package? {
        waitForPackage(deadline: timeout.map(Self.deadline(after:)))
    }

    /// Receives the next package from the pipe, blocking until an absolute deadline.
    ///
    /// Prefer ``receive(timeout:)`` for new code.
    @available(*, deprecated, message: "Use receive(timeout:) with a seconds value, or pass nil to wait indefinitely.")
    public func receive(timeOut: DispatchTime?) -> Package? {
        waitForPackage(deadline: timeOut)
    }

    private func waitForPackage(deadline: DispatchTime?) -> Package? {
        if let deadline {
            // Wait until a package is available or the timeout expires.
            guard packagesSemaphore.wait(timeout: deadline) == .success else {
                return nil
            }
        }
        else {
            packagesSemaphore.wait()
        }

        // Remove the package safely on the serial queue.
        guard let package = pop() else {
            assertionFailure("DataPipe invariant broken: package semaphore signalled but queue was empty")
            return nil
        }

        // Signal that a free slot has been opened in the queue.
        isFull.signal()

        return package
    }

    private static func deadline(after seconds: TimeInterval) -> DispatchTime {
        precondition(seconds >= 0, "timeout must be non-negative")
        precondition(seconds.isFinite, "timeout must be finite")

        let nanosecondsPerSecond = 1_000_000_000.0
        let nanoseconds = (seconds * nanosecondsPerSecond).rounded(.up)
        precondition(nanoseconds <= Double(Int.max), "timeout is too large")

        return .now() + .nanoseconds(Int(nanoseconds))
    }
}
