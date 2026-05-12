//
// Part of SwiftSMB
// Bridge-Links.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Symbolic Links

    private static func _readLink(
        context: Context,
        path: String,
        bufferSize: Int = 4096,
    ) throws -> String {
        guard bufferSize > 0 else {
            throw SMB.Error.invalidArgument(
                cause: .bufferSizeMustBeGreaterThanZero,
                onOperation: .smb2Readlink,
            )
        }

        let count = try bufferSize.asUInt32(operation: .smb2Readlink)
        var buffer = [CChar](repeating: 0, count: bufferSize)
        let status = path.withCString { smb2_readlink(context.raw, $0, &buffer, count) }
        try check(status, context: context, operation: "smb2_readlink")
        return buffer.withUnsafeBufferPointer { pointer in
            guard let baseAddress = pointer.baseAddress else {
                return ""
            }
            return String(cString: baseAddress)
        }
    }

    /// Reads the destination path of a symbolic link.
    static func readLink(
        context: Context,
        path: String,
        bufferSize: Int = 16384,
    ) throws -> String {
        try Bridge.sync {
            try _readLink(context: context, path: path, bufferSize: bufferSize)
        }
    }

    private final class MakeLinkState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished: Bool = false
    }

    private static let makeLinkCreateCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<MakeLinkState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
    }

    private static let makeLinkIoctlCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<MakeLinkState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
    }

    private static let makeLinkCloseCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<MakeLinkState>.fromOpaque(callbackData).takeUnretainedValue()
        if state.status == SMB2_STATUS_SUCCESS {
            state.status = status
        }
        state.isFinished = true
    }

    private static func _makeLink(
        context: Context,
        path: String,
        destination: String,
    ) throws {
        let destination = destination.pathComponents.backslashPath
        let substituteNameData = destination.data(using: .utf16LittleEndian) ?? Data()
        let printNameData = substituteNameData

        var reparseBuffer = [UInt8]()
        reparseBuffer.reserveCapacity(20 + substituteNameData.count + printNameData.count)

        withUnsafeBytes(of: UInt32(SMB2_REPARSE_TAG_SYMLINK).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt16(12 + substituteNameData.count + printNameData.count).littleEndian) {
            reparseBuffer.append(contentsOf: $0)
        }
        withUnsafeBytes(of: UInt16(0).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt16(0).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt16(substituteNameData.count).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt16(substituteNameData.count).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt16(printNameData.count).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        withUnsafeBytes(of: UInt32(1).littleEndian) { reparseBuffer.append(contentsOf: $0) }
        reparseBuffer.append(contentsOf: substituteNameData)
        reparseBuffer.append(contentsOf: printNameData)

        let state = MakeLinkState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { Unmanaged<MakeLinkState>.fromOpaque(callbackData).release() }

        try reparseBuffer.withUnsafeMutableBytes { buffer in
            try path.withCString { pathPointer in
                var cr_req = smb2_create_request(
                    security_flags: 0,
                    requested_oplock_level: 0,
                    impersonation_level: UInt32(SMB2_IMPERSONATION_IMPERSONATION),
                    smb_create_flags: 0,
                    desired_access: UInt32(SMB2_FILE_WRITE_DATA | SMB2_FILE_WRITE_ATTRIBUTES | SMB2_SYNCHRONIZE),
                    file_attributes: 0,
                    share_access: UInt32(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE),
                    create_disposition: UInt32(SMB2_FILE_CREATE),
                    create_options: UInt32(SMB2_FILE_OPEN_REPARSE_POINT | SMB2_FILE_NON_DIRECTORY_FILE),
                    name_offset: 0,
                    name_length: 0,
                    name: pathPointer,
                    create_context_offset: 0,
                    create_context_length: 0,
                    create_context: nil,
                )

                guard let pdu = smb2_cmd_create_async(context.raw, &cr_req, makeLinkCreateCallback, callbackData) else {
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_create_async")
                }

                var ioctl_req = smb2_ioctl_request(
                    ctl_code: UInt32(SMB2_FSCTL_SET_REPARSE_POINT),
                    file_id: FileID.allOnes.raw,
                    input_offset: 0,
                    input_count: UInt32(buffer.count),
                    max_input_response: 0,
                    output_offset: 0,
                    output_count: 0,
                    max_output_response: 0,
                    flags: UInt32(SMB2_0_IOCTL_IS_FSCTL),
                    input: buffer.baseAddress,
                )

                guard let ioctl_pdu = smb2_cmd_ioctl_async(
                    context.raw,
                    &ioctl_req,
                    makeLinkIoctlCallback,
                    callbackData,
                ) else {
                    smb2_free_pdu(context.raw, pdu)
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_ioctl_async")
                }
                smb2_add_compound_pdu(context.raw, pdu, ioctl_pdu)

                var cl_req = smb2_close_request(
                    flags: 0,
                    file_id: FileID.allOnes.raw,
                )

                guard let close_pdu = smb2_cmd_close_async(context.raw, &cl_req, makeLinkCloseCallback, callbackData) else {
                    smb2_free_pdu(context.raw, pdu)
                    throw SMB.Error.fromBridge(context, operation: "smb2_cmd_close_async")
                }
                smb2_add_compound_pdu(context.raw, pdu, close_pdu)

                smb2_queue_pdu(context.raw, pdu)

                try serviceUntilFinished(context: context, state: state)

                if state.status != SMB2_STATUS_SUCCESS {
                    throw SMB.Error.fromBridge(context, operation: "FSCTL_SET_REPARSE_POINT", status: state.status)
                }
            }
        }
    }

    /// Creates a symbolic link at `path` pointing to `destination`.
    static func makeLink(
        context: Context,
        path: String,
        destination: String,
    ) throws {
        try Bridge.sync {
            try _makeLink(context: context, path: path, destination: destination)
        }
    }
}
