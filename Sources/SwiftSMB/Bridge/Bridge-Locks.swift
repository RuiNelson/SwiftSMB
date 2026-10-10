//
// Part of SwiftSMB
// Bridge-Locks.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Lock Flags

    /// SMB2 lock element flags.
    struct LockFlags: Equatable, Sendable {
        static let shared = LockFlags(rawValue: 0x0000_0001)
        static let exclusive = LockFlags(rawValue: 0x0000_0002)
        static let unlock = LockFlags(rawValue: 0x0000_0004)
        static let failImmediately = LockFlags(rawValue: 0x0000_0010)

        let rawValue: UInt32

        /// Whether a conflicting lock makes the server wait instead of failing.
        var waitsForConflicts: Bool {
            rawValue & (Self.failImmediately.rawValue | Self.unlock.rawValue) == 0
        }
    }

    // MARK: - File Locking

    private final class LockState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
    }

    private static let lockCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<LockState>.fromOpaque(callbackData).takeUnretainedValue()
        state.finish(status)
    }

    /// Locks or unlocks a byte range.
    ///
    /// A blocking lock waits on the server until the conflicting lock is released. It is withdrawn with an SMB2 CANCEL
    /// when `signal` is tripped, when the connection starts shutting down, or when the command timeout expires, so
    /// that the server can never grant it after the caller stopped waiting. If the server grants it first, the lock is
    /// held and this returns normally.
    private static func _lock(
        context: Context,
        file: FileHandle,
        flags: LockFlags,
        offset: UInt64 = 0,
        length: UInt64 = UInt64.max,
        signal: CancellationSignal? = nil
    ) throws {
        guard let fileIDPtr = try smb2_get_file_id(file.requireRaw(operation: .smb2Flock)) else {
            throw SMB.Error.fromBridge(context, operation: "smb2_get_file_id")
        }
        let fileID = fileIDPtr.pointee

        var element = smb2_lock_element(
            offset: offset,
            length: length,
            flags: flags.rawValue,
            reserved: 0
        )

        try withUnsafeMutablePointer(to: &element) { elementPointer in
            var request = smb2_lock_request(
                lock_count: 1,
                lock_sequence_number: 0,
                lock_sequence_index: 0,
                file_id: fileID,
                locks: elementPointer
            )

            let state = LockState()
            let callbackData = Unmanaged.passRetained(state).toOpaque()
            var isQueued = false
            defer {
                if !isQueued {
                    state.isFinished = true
                }
                releaseWhenFinished(state, callbackData)
            }

            let cancellation = try withUnsafeMutablePointer(to: &request) { requestPointer in
                guard let pdu = smb2_cmd_lock_async(
                    context.raw,
                    requestPointer,
                    lockCallback,
                    callbackData
                ) else {
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_lock_async")
                }

                guard let signal, flags.waitsForConflicts else {
                    smb2_queue_pdu(context.raw, pdu)
                    isQueued = true
                    return RequestCancellation?.none
                }

                // libsmb2's timeout would only drop the request locally; the cancellation enforces it instead.
                let timeoutSeconds = context.raw.pointee.timeout
                pdu.pointee.timeout = 0
                smb2_queue_pdu(context.raw, pdu)
                isQueued = true
                return RequestCancellation(
                    operation: "smb2_lock",
                    messageID: smb2_get_pdu_message_id(context.raw, pdu),
                    signal: signal,
                    timeoutSeconds: timeoutSeconds
                )
            }

            try serviceUntilFinished(context: context, state: state, cancellation: cancellation)

            if let cancellation, cancellation.reason != nil,
               UInt32(bitPattern: state.status) == SMB.SMBStatus.cancelled.rawValue {
                throw cancellation.error(context: context)
            }
            if state.status != SMB2_STATUS_SUCCESS {
                throw SMB.Error.fromBridge(context, operation: "smb2_lock", status: state.status)
            }
        }
    }

    /// Locks an open file handle.
    ///
    /// Cancelling the task withdraws a blocking lock that is still waiting and throws `CancellationError`. Shutting the
    /// connection down withdraws it too and throws ``SMB/Error/operationRequestedAfterConnectionClosed``.
    static func lock(
        context: Context,
        file: FileHandle,
        flags: LockFlags,
        offset: UInt64 = 0,
        length: UInt64 = UInt64.max
    ) async throws {
        try await performCancellable(on: context) { signal in
            try _lock(context: context, file: file, flags: flags, offset: offset, length: length, signal: signal)
        }
    }

    /// Unlocks a byte range on an open file handle.
    static func unlock(
        context: Context,
        file: FileHandle,
        offset: UInt64 = 0,
        length: UInt64 = UInt64.max
    ) async throws {
        try await lock(context: context, file: file, flags: .unlock, offset: offset, length: length)
    }
}
