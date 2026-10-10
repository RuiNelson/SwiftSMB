//
// Part of SwiftSMB
// Bridge-Cancel.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - SMB2 Cancel

    /// A flag that asks a request waiting on the server to be withdrawn. Tripped from any thread.
    final class CancellationSignal: Sendable {
        private let protectedIsCancelled = Protected(false, label: "com.ruinelson.SwiftSMB.bridge.cancellation")

        /// Whether cancellation has been requested.
        var isCancelled: Bool {
            protectedIsCancelled.current
        }

        /// Requests cancellation.
        func cancel() {
            protectedIsCancelled.current = true
        }
    }

    /// Withdraws a request that legitimately waits on the server, such as a blocking lock, with an SMB2 CANCEL.
    ///
    /// The request is withdrawn when its task is cancelled, when the connection starts shutting down, or when the
    /// connection's command timeout expires. libsmb2's own timeout must be cleared on the request: it would drop the
    /// request locally while the server keeps it pending, and could still grant it later.
    ///
    /// The server answers the withdrawn request with `STATUS_CANCELLED`, or with its normal reply if it completed
    /// first. If it does not answer within ``gracePeriodNanoseconds``, ``withdrawIfRequested(context:)`` throws, and
    /// ``serviceUntilFinished(context:state:cancellation:)`` then destroys the context.
    ///
    /// Confined to the context queue, except for `signal`.
    final class RequestCancellation {
        /// Why the request was withdrawn.
        enum Reason {
            case taskCancelled
            case connectionClosing
            case timedOut
        }

        /// How often a cancellable wait checks whether it must withdraw its request.
        static let pollIntervalMilliseconds: Int32 = 100

        /// How long the server has to answer a withdrawn request.
        static let gracePeriodNanoseconds: UInt64 = 5_000_000_000

        /// The operation name reported when the command timeout expires.
        let operation: String

        private let signal: CancellationSignal
        private let messageID: UInt64
        private let deadline: UInt64?
        private var requestedAt: UInt64 = 0
        private var isSent = false

        /// Why the request was withdrawn, or `nil` if it was not.
        private(set) var reason: Reason?

        /// Creates a cancellation for a queued request.
        ///
        /// - Parameters:
        ///   - operation: The operation name reported when the command timeout expires.
        ///   - messageID: The request's MessageId, read after `smb2_queue_pdu` assigned it.
        ///   - signal: The flag tripped when the task is cancelled.
        ///   - timeoutSeconds: The connection's command timeout, or `0` for none.
        init(operation: String, messageID: UInt64, signal: CancellationSignal, timeoutSeconds: Int32) {
            self.operation = operation
            self.messageID = messageID
            self.signal = signal
            deadline = timeoutSeconds > 0
                ? DispatchTime.now().uptimeNanoseconds + UInt64(timeoutSeconds) * 1_000_000_000
                : nil
        }

        /// Sends the SMB2 CANCEL once a reason to withdraw the request appears.
        ///
        /// Retries until libsmb2 has sent the request, since only sent requests can be cancelled.
        ///
        /// - Throws: The error for ``reason`` when the server has not answered within the grace period.
        func withdrawIfRequested(context: Context) throws {
            let now = DispatchTime.now().uptimeNanoseconds
            if reason == nil {
                guard let reason = currentReason(context: context, now: now) else {
                    return
                }
                self.reason = reason
                requestedAt = now
            }
            if !isSent {
                isSent = queueCancel(context: context, messageID: messageID)
            }
            guard now - requestedAt < Self.gracePeriodNanoseconds else {
                throw error(context: context)
            }
        }

        /// The error that reports why the request was withdrawn.
        func error(context: Context) -> any Swift.Error {
            switch reason {
            case .taskCancelled:
                CancellationError()
            case .connectionClosing:
                SMB.Error.operationRequestedAfterConnectionClosed
            case .timedOut, nil:
                SMB.Error.fromBridge(
                    context,
                    operation: operation,
                    status: Int32(bitPattern: SMB.SMBStatus.ioTimeout.rawValue)
                )
            }
        }

        private func currentReason(context: Context, now: UInt64) -> Reason? {
            if context.isClosing {
                return .connectionClosing
            }
            if signal.isCancelled {
                return .taskCancelled
            }
            if let deadline, now >= deadline {
                return .timedOut
            }
            return nil
        }
    }

    /// The callback of an SMB2 CANCEL. libsmb2 calls it without checking for `NULL` when it destroys a context with
    /// the CANCEL still queued, so it cannot be omitted.
    private static let cancelCallback: smb2_command_cb = { _, _, _, _ in }

    /// Queues an SMB2 CANCEL for a request that is waiting on the server. Must run on the context queue.
    ///
    /// libsmb2 only finds requests that have been sent and not answered yet. When there is no such request, the error
    /// libsmb2 records for it is cleared, so a later failure is not reported with it.
    ///
    /// - Returns: Whether the CANCEL was queued.
    @discardableResult
    static func queueCancel(context: Context, messageID: UInt64) -> Bool {
        guard let pdu = smb2_cmd_cancel_async(context.raw, messageID, cancelCallback, nil) else {
            withUnsafeMutableBytes(of: &context.raw.pointee.error_string) { $0[0] = 0 }
            return false
        }
        smb2_queue_pdu(context.raw, pdu)
        return true
    }

    /// Runs a bridge operation whose request can be withdrawn, tripping `signal` when the task is cancelled.
    static func performCancellable<T: Sendable>(
        on context: Context,
        _ body: @escaping @Sendable (CancellationSignal) throws -> T
    ) async throws -> T {
        let signal = CancellationSignal()
        return try await withTaskCancellationHandler {
            try await perform(on: context) {
                try body(signal)
            }
        } onCancel: {
            signal.cancel()
        }
    }
}
