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
        includeHidden: Bool = false
    ) throws -> [Share] {
        // SRVSVC enumeration needs signing enabled, but keep any stricter mode (e.g. signingRequired) the caller
        // configured instead of overwriting it.
        let configuredMode = SecurityMode(rawValue: context.raw.pointee.security_mode)
        _setSecurityMode(configuredMode.union(.signingEnabled), on: context)
        try _connectShare(context: context, server: server, share: "IPC$", user: user)

        do {
            let shares = try filterForUserVisibleDiskShares(
                _listSharesOnConnectedIPCShare(context: context),
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
    static func listShares(
        context: Context,
        server: String,
        user: String? = nil,
        includeHidden: Bool = false
    ) async throws -> [Share] {
        try await perform(on: context) {
            try _listShares(context: context, server: server, user: user, includeHidden: includeHidden)
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

    private static func _listSharesOnConnectedIPCShare(
        context: Context,
        level: ShareEnumerationLevel = .detailed
    ) throws -> [Share] {
        guard let response = smb2_share_enum_sync(context.raw, level.rawValue) else {
            throw SMB.Error.fromBridge(context, operation: "smb2_share_enum_sync")
        }

        defer { smb2_free_data(context.raw, response) }

        let entriesRead = response.pointee.entries_read

        switch response.pointee.level {
        case UInt32(SMB2_SHARE_INFO_0.rawValue):
            return shares(from: response.pointee.share_info.info_0, count: entriesRead)
        case UInt32(SMB2_SHARE_INFO_1.rawValue):
            return shares(from: response.pointee.share_info.info_1, count: entriesRead)
        default:
            throw SMB.Error.invalidArgument(
                cause: .unsupportedShareEnumerationLevel(response.pointee.level),
                onOperation: .smb2ShareEnumSync
            )
        }
    }

    // MARK: - Share Listing Helpers

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

    private static func decodeString(from string: UnsafeMutablePointer<CChar>?) -> String {
        string.map { String(cString: $0) } ?? ""
    }

    private static func filterForUserVisibleDiskShares(_ shares: [Share], includeHidden: Bool) -> [Share] {
        shares.filter { share in
            share.kind == .diskTree && (includeHidden || !share.isHidden)
        }
    }
}
