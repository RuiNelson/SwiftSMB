//
// Part of SwiftSMB
// Bridge-ShareEnum.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - Share Listing

    private static func _listShares(
        context: Context,
        server: String,
        user: String? = nil,
        includeHidden: Bool = false,
        level: ShareEnumerationLevel = .detailed
    ) throws -> [Share] {
        // SRVSVC enumeration needs signing enabled, but keep any stricter mode (e.g. signingRequired) the caller
        // configured instead of overwriting it.
        let configuredMode = SecurityMode(rawValue: context.raw.pointee.security_mode)
        _setSecurityMode(configuredMode.union(.signingEnabled), on: context)
        try _connectShare(context: context, server: server, share: "IPC$", user: user)

        do {
            let shares = try filterForUserVisibleDiskShares(
                _listSharesOnConnectedIPCShare(context: context, level: level),
                includeHidden: includeHidden
            )
            try _disconnectShare(context: context)
            return shares
        }
        catch {
            try? _disconnectShare(context: context)
            throw error
        }
    }

    /// Connects to IPC$, enumerates user-visible disk shares, and disconnects.
    ///
    /// `level` must report the share kind (`.detailed` or `.full`), since disk shares are picked by their kind.
    static func listShares(
        context: Context,
        server: String,
        user: String? = nil,
        includeHidden: Bool = false,
        level: ShareEnumerationLevel = .detailed
    ) async throws -> [Share] {
        try await perform(on: context) {
            try _listShares(
                context: context,
                server: server,
                user: user,
                includeHidden: includeHidden,
                level: level
            )
        }
    }

    /// Enumerates shares using SRVSVC on a context that is already connected to IPC$.
    static func listSharesOnConnectedIPCShare(
        context: Context,
        level: ShareEnumerationLevel = .detailed
    ) async throws -> [Share] {
        try await perform(on: context) {
            try _listSharesOnConnectedIPCShare(context: context, level: level)
        }
    }

    private final class ShareEnumState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
        var shares: [Share] = []
        var unsupportedLevel: UInt32?
    }

    private static let shareEnumCallback: smb2_command_cb = { rawContext, status, commandData, callbackData in
        guard let callbackData else { return }
        let state = Unmanaged<ShareEnumState>.fromOpaque(callbackData).takeUnretainedValue()
        // A WERROR from the server (a positive status) still comes with a reply, so both outcomes free it.
        if let rawContext, let commandData {
            if status == 0 {
                let reply = commandData.assumingMemoryBound(to: smb2_share_enum_reply.self)
                decodeShares(from: reply, into: state)
            }
            smb2_free_data(rawContext, commandData)
        }
        state.finish(status)
    }

    private static func _listSharesOnConnectedIPCShare(
        context: Context,
        level: ShareEnumerationLevel = .detailed
    ) throws -> [Share] {
        let operation = "smb2_share_enum_sync"
        let state = ShareEnumState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { releaseWhenFinished(state, callbackData) }
        let status = smb2_share_enum_async(context.raw, level.rawValue, shareEnumCallback, callbackData)
        guard status == 0 else {
            state.finish(status)
            throw SMB.Error.fromBridge(context, operation: operation, status: status)
        }
        try serviceUntilFinished(context: context, state: state)
        // libsmb2 reports the server's Win32 error as a positive status, where the errors of its own are negative.
        guard state.status <= 0 else {
            throw shareEnumError(werror: state.status, operation: operation)
        }
        try check(state.status, context: context, operation: operation)
        if let unsupportedLevel = state.unsupportedLevel {
            throw SMB.Error.invalidArgument(
                cause: .unsupportedShareEnumerationLevel(unsupportedLevel),
                onOperation: .smb2ShareEnumSync
            )
        }
        return state.shares
    }

    // MARK: - Share Listing Helpers

    /// The Win32 `ERROR_ACCESS_DENIED` code.
    private static let werrorAccessDenied: Int32 = 5

    /// Translates the Win32 error a failed `NetrShareEnum` call returned.
    ///
    /// Windows only returns the `.full` level to administrators and operators, so an access error is reported as
    /// the SMB status callers already handle.
    static func shareEnumError(werror: Int32, operation: String) -> SMB.Error {
        let message = String(format: "NetrShareEnum failed with WERROR 0x%08X", UInt32(bitPattern: werror))
        if werror == werrorAccessDenied {
            return .ntStatus(.accessDenied, posixCode: nil, operation: operation, message: message)
        }
        return .unknown(operation: operation, message: message)
    }

    private static func decodeShares(
        from reply: UnsafeMutablePointer<smb2_share_enum_reply>,
        into state: ShareEnumState
    ) {
        let entriesRead = reply.pointee.entries_read

        switch reply.pointee.level {
        case UInt32(SMB2_SHARE_INFO_0.rawValue):
            state.shares = shares(from: reply.pointee.share_info.info_0, count: entriesRead)
        case UInt32(SMB2_SHARE_INFO_1.rawValue):
            state.shares = shares(from: reply.pointee.share_info.info_1, count: entriesRead)
        case UInt32(SMB2_SHARE_INFO_2.rawValue):
            state.shares = shares(from: reply.pointee.share_info.info_2, count: entriesRead)
        default:
            state.unsupportedLevel = reply.pointee.level
        }
    }

    private static func shares(_ count: UInt32, _ body: (Int) -> Share) -> [Share] {
        (0 ..< Int(count)).map(body)
    }

    private static func shares(from buffer: UnsafeMutablePointer<smb2_share_info_0>?, count: UInt32) -> [Share] {
        guard let buffer else {
            return []
        }

        return shares(count) { index in
            Share(
                name: decodeString(from: buffer[index].netname),
                kind: nil,
                attributes: [],
                remark: nil
            )
        }
    }

    private static func shares(from buffer: UnsafeMutablePointer<smb2_share_info_1>?, count: UInt32) -> [Share] {
        guard let buffer else {
            return []
        }

        return shares(count) { index in
            let info = buffer[index]
            return Share(
                name: decodeString(from: info.netname),
                kind: ShareKind(rawValue: info.type),
                attributes: ShareAttributes(rawShareType: info.type),
                remark: decodeString(from: info.remark)
            )
        }
    }

    private static func shares(from buffer: UnsafeMutablePointer<smb2_share_info_2>?, count: UInt32) -> [Share] {
        guard let buffer else {
            return []
        }

        return shares(count) { index in
            let info = buffer[index]
            // `passwd` is only meaningful on servers with share-level security and is never exposed.
            return Share(
                name: decodeString(from: info.netname),
                kind: ShareKind(rawValue: info.type),
                attributes: ShareAttributes(rawShareType: info.type),
                remark: decodeString(from: info.remark),
                path: info.path.map { String(cString: $0) },
                permissions: info.permissions,
                maximumUsers: info.max_users == UInt32.max ? nil : info.max_users,
                currentUsers: info.current_users
            )
        }
    }

    private static func decodeString(from string: UnsafeMutablePointer<CChar>?) -> String {
        string.map { String(cString: $0) } ?? ""
    }

    private static func filterForUserVisibleDiskShares(_ shares: [Share], includeHidden: Bool) -> [Share] {
        shares.filter { share in
            share.kind == .diskTree && (includeHidden || !share.isHidden)
        }
    }
}
