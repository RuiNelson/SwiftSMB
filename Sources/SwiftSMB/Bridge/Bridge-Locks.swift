//
// Part of SwiftSMB
// Bridge-Locks.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Lock Flags

    /// SMB2 lock element flags.
    struct LockFlags: Equatable {
        static let shared = LockFlags(rawValue: 0x0000_0001)
        static let exclusive = LockFlags(rawValue: 0x0000_0002)
        static let unlock = LockFlags(rawValue: 0x0000_0004)
        static let failImmediately = LockFlags(rawValue: 0x0000_0010)

        let rawValue: UInt32
    }

    // MARK: - File Locking

    private final class LockState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
    }

    private static let lockCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<LockState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
        state.isFinished = true
    }

    private static func _lock(
        context: Context,
        file: FileHandle,
        flags: LockFlags,
        offset: UInt64 = 0,
        length: UInt64 = UInt64.max,
    ) throws {
        guard let fileIDPtr = smb2_get_file_id(file.raw) else {
            throw SMB.Error.fromBridge(context, operation: "smb2_get_file_id")
        }
        let fileID = fileIDPtr.pointee

        var element = smb2_lock_element(
            offset: offset,
            length: length,
            flags: flags.rawValue,
            reserved: 0,
        )

        try withUnsafeMutablePointer(to: &element) { elementPointer in
            var request = smb2_lock_request(
                lock_count: 1,
                lock_sequence_number: 0,
                lock_sequence_index: 0,
                file_id: fileID,
                locks: elementPointer,
            )

            let state = LockState()
            let callbackData = Unmanaged.passRetained(state).toOpaque()
            defer { Unmanaged<LockState>.fromOpaque(callbackData).release() }

            try withUnsafeMutablePointer(to: &request) { requestPointer in
                guard let pdu = smb2_cmd_lock_async(
                    context.raw,
                    requestPointer,
                    lockCallback,
                    callbackData,
                ) else {
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_lock_async")
                }

                smb2_queue_pdu(context.raw, pdu)
            }

            try serviceUntilFinished(context: context, state: state)

            if state.status != SMB2_STATUS_SUCCESS {
                throw SMB.Error.fromBridge(context, operation: "smb2_lock", status: state.status)
            }
        }
    }

    /// Locks an open file handle.
    static func lock(
        context: Context,
        file: FileHandle,
        flags: LockFlags,
        offset: UInt64 = 0,
        length: UInt64 = UInt64.max,
    ) throws {
        try Bridge.sync {
            try _lock(context: context, file: file, flags: flags, offset: offset, length: length)
        }
    }

    /// Unlocks a byte range on an open file handle.
    static func unlock(
        context: Context,
        file: FileHandle,
        offset: UInt64 = 0,
        length: UInt64 = UInt64.max,
    ) throws {
        try lock(context: context, file: file, flags: .unlock, offset: offset, length: length)
    }
}
