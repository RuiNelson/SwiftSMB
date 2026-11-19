//
// Part of SwiftSMB
// Bridge-OpLockBreaks.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Types

    /// A 16-byte SMB2 lease key, which names a lease across the opens that share it.
    struct LeaseKey: Hashable, Sendable {
        /// The key's 16 bytes.
        let bytes: Data

        /// Creates a lease key from its bytes, or returns `nil` unless there are exactly 16 of them.
        init?(_ bytes: Data) {
            guard bytes.count == Int(SMB2_LEASE_KEY_SIZE) else { return nil }
            self.bytes = bytes
        }

        init(_ raw: smb2_lease_key) {
            bytes = withUnsafeBytes(of: raw) { Data($0) }
        }

        /// Copies the key into a C lease key.
        func copy(into raw: inout smb2_lease_key) {
            withUnsafeMutableBytes(of: &raw) { $0.copyBytes(from: bytes) }
        }
    }

    /// A break of an oplock or a lease, as the server announced it.
    enum OpLockBreak: Equatable, Sendable {
        /// The server lowers the caching state of the lease named by `key`.
        ///
        /// When `requiresAcknowledgement` is set, the server holds back the conflicting open until the client
        /// acknowledges with ``Bridge/acknowledgeLeaseBreak(context:key:state:)``, or until its break timeout expires.
        case lease(
            key: LeaseKey,
            currentState: LeaseState,
            newState: LeaseState,
            epoch: UInt16,
            requiresAcknowledgement: Bool
        )

        /// The server lowers the oplock of the open named by `fileID` to `newLevel`. libsmb2 acknowledges it itself.
        case opLock(fileID: FileID, newLevel: OpLockLevel)
    }

    /// What the context does with a lease break that the server waits to have acknowledged.
    enum OpLockBreakDisposition: Equatable, Sendable {
        /// libsmb2 acknowledges it right away, with the state the server asked for.
        case acknowledgeNow

        /// The caller acknowledges it later with ``Bridge/acknowledgeLeaseBreak(context:key:state:)``.
        case acknowledgeLater
    }

    /// Receives the breaks of a context. Runs on the context queue, while libsmb2 services the context, so it must
    /// return quickly and must not touch the context.
    typealias OpLockBreakHandler = @Sendable (OpLockBreak) -> OpLockBreakDisposition

    /// `SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED` (MS-SMB2 2.2.23.2), which libsmb2 does not define.
    private static let leaseBreakAcknowledgementRequiredFlag: UInt32 = 0x01

    // MARK: - Break Notifications

    /// Routes every break of `context` to its ``Context/opLockBreakHandler``. Called once, when the context is created.
    ///
    /// libsmb2's break callback carries no callback data, so the context is found through its opaque pointer. It is
    /// unretained: libsmb2 only calls the callback while servicing the context, through a method of that very context.
    static func installOpLockBreakCallback(context: Context) {
        smb2_set_opaque(context.raw, Unmanaged.passUnretained(context).toOpaque())
        smb2_set_oplock_or_lease_break_callback(context.raw, opLockBreakCallback)
    }

    private static let opLockBreakCallback: smb2_oplock_or_lease_break_cb = {
        rawContext, status, reply, newOpLockLevel, newLeaseState in
        guard let rawContext, let reply, let opaque = smb2_get_opaque(rawContext) else { return }
        let context = Unmanaged<Context>.fromOpaque(opaque).takeUnretainedValue()
        let message = reply.pointee

        switch message.break_type {
        case Int32(SMB2_BREAK_TYPE_OPLOCK_NOTIFICATION):
            // libsmb2 always acknowledges an oplock break. Acknowledge the level the server asked for.
            let notification = message.lock.oplock
            newOpLockLevel?.pointee = notification.oplock_level
            guard status == 0 else { return }
            _ = context.opLockBreakHandler?(.opLock(
                fileID: FileID(notification.file_id),
                newLevel: OpLockLevel(rawValue: notification.oplock_level) ?? .none
            ))

        case Int32(SMB2_BREAK_TYPE_LEASE_NOTIFICATION):
            let notification = message.lock.lease
            let requiresAcknowledgement = notification.flags & leaseBreakAcknowledgementRequiredFlag != 0
            var disposition = OpLockBreakDisposition.acknowledgeNow
            if status == 0, let handler = context.opLockBreakHandler {
                disposition = handler(.lease(
                    key: LeaseKey(notification.lease_key),
                    currentState: LeaseState(rawValue: notification.current_lease_state),
                    newState: LeaseState(rawValue: notification.new_lease_state),
                    epoch: notification.new_epoch,
                    requiresAcknowledgement: requiresAcknowledgement
                ))
            }
            // libsmb2's own acknowledgement copies the notification's flags (ACK_REQUIRED) into its Flags field, which
            // is reserved and must be zero, so Samba refuses it and holds the conflicting open until its break timeout.
            // Never let libsmb2 acknowledge a lease break: send our own acknowledgement instead. A break that needs no
            // acknowledgement must not get one, since the server would refuse it.
            newLeaseState?.pointee = UInt32(SMB2_LEASE_STATE_NO_AUTO_ACK)
            if requiresAcknowledgement, disposition == .acknowledgeNow {
                queueLeaseBreakAcknowledgement(
                    context: context,
                    key: LeaseKey(notification.lease_key),
                    state: LeaseState(rawValue: notification.new_lease_state)
                )
            }

        default:
            break
        }
    }

    /// Sets the handler that receives the breaks of a context, replacing any earlier one.
    static func setOpLockBreakHandler(context: Context, handler: OpLockBreakHandler?) async throws {
        try await perform(context: context) {
            context.opLockBreakHandler = handler
        }
    }

    // MARK: - Acknowledgements

    private final class LeaseBreakAcknowledgementState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
    }

    private static let leaseBreakAcknowledgementCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<LeaseBreakAcknowledgementState>.fromOpaque(callbackData).takeUnretainedValue().finish(status)
    }

    /// Nobody waits for the server's answer to an acknowledgement queued from the break callback, but libsmb2 calls the
    /// callback of every PDU it frees, so there must be one.
    private static let ignoredReplyCallback: smb2_command_cb = { _, _, _, _ in }

    private static func leaseBreakAcknowledgement(
        key: LeaseKey,
        state: LeaseState
    ) -> smb2_lease_break_acknowledgement {
        // Flags and LeaseDuration are reserved and stay zero (MS-SMB2 2.2.24.2).
        var request = smb2_lease_break_acknowledgement()
        request.lease_state = state.rawValue
        key.copy(into: &request.lease_key)
        return request
    }

    /// Queues a lease break acknowledgement without waiting for the server's answer. Must run on the context queue.
    /// Unlike ``acknowledgeLeaseBreak(context:key:state:)`` it never services the context, so it can run inside
    /// libsmb2's break callback, which is itself called while libsmb2 services the context.
    private static func queueLeaseBreakAcknowledgement(context: Context, key: LeaseKey, state: LeaseState) {
        var request = leaseBreakAcknowledgement(key: key, state: state)
        guard let pdu = smb2_cmd_lease_break_async(context.raw, &request, ignoredReplyCallback, nil) else { return }
        smb2_queue_pdu(context.raw, pdu)
    }

    private static func _acknowledgeLeaseBreak(context: Context, key: LeaseKey, state: LeaseState) throws {
        let operation = "smb2_cmd_lease_break_async"
        var request = leaseBreakAcknowledgement(key: key, state: state)

        let pending = LeaseBreakAcknowledgementState()
        let callbackData = Unmanaged.passRetained(pending).toOpaque()
        defer { releaseWhenFinished(pending, callbackData) }

        guard let pdu = smb2_cmd_lease_break_async(
            context.raw,
            &request,
            leaseBreakAcknowledgementCallback,
            callbackData
        ) else {
            pending.isFinished = true
            throw SMB.Error.fromBridge(context, operation: operation)
        }
        smb2_queue_pdu(context.raw, pdu)
        try serviceUntilFinished(context: context, state: pending)
        if pending.status != SMB2_STATUS_SUCCESS {
            throw SMB.Error.fromBridge(context, operation: operation, status: pending.status)
        }
    }

    /// Acknowledges a lease break, keeping `state`, which must be the new state the server announced or less.
    static func acknowledgeLeaseBreak(context: Context, key: LeaseKey, state: LeaseState) async throws {
        try await perform(context: context) {
            try _acknowledgeLeaseBreak(context: context, key: key, state: state)
        }
    }

    /// Acknowledges a lease break without waiting. Used when nobody is left to acknowledge it, which can be a `deinit`.
    static func acknowledgeLeaseBreakInBackground(context: Context, key: LeaseKey, state: LeaseState) {
        performInBackground(context: context) {
            try? _acknowledgeLeaseBreak(context: context, key: key, state: state)
        }
    }

    // MARK: - File IDs

    /// Returns the SMB2 file ID of an open file, which names its oplock in a break.
    static func fileID(context: Context, file: FileHandle) async throws -> FileID {
        try await perform(context: context) {
            guard let fileID = try smb2_get_file_id(file.requireRaw(operation: .smb2GetFileID)) else {
                throw SMB.Error.fromBridge(context, operation: "smb2_get_file_id")
            }
            return FileID(fileID.pointee)
        }
    }
}
