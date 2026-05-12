//
// Part of SwiftSMB
// Bridge-ShareEnum.swift
//
// Licensed under LGPL v2.1
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
    ) throws -> [Share] {
        setSecurityMode(.signingEnabled, on: context)
        try _connectShare(context: context, server: server, share: "IPC$", user: user)

        do {
            let shares = try filterForUserVisibleDiskShares(
                listSharesOnConnectedIPCShare(context: context),
                includeHidden: includeHidden,
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
        includeHidden: Bool = false,
    ) throws -> [Share] {
        try Bridge.sync {
            try _listShares(context: context, server: server, user: user, includeHidden: includeHidden)
        }
    }

    /// Enumerates shares using SRVSVC on a context that is already connected to IPC$.
    static func listSharesOnConnectedIPCShare(
        context: Context,
        level: ShareEnumerationLevel = .detailed,
    ) throws -> [Share] {
        guard let response = smb2_share_enum_sync(context.raw, level.rawValue) else {
            throw SMB.Error.fromBridge(context, operation: "smb2_share_enum_sync")
        }

        defer { smb2_free_data(context.raw, response) }

        switch response.pointee.ses.Level {
        case UInt32(SHARE_INFO_0.rawValue):
            return shares(from: response.pointee.ses.ShareInfo.Level0)
        case UInt32(SHARE_INFO_1.rawValue):
            return shares(from: response.pointee.ses.ShareInfo.Level1)
        default:
            throw SMB.Error.invalidArgument(
                cause: .unsupportedShareEnumerationLevel(response.pointee.ses.Level),
                onOperation: .smb2ShareEnumSync,
            )
        }
    }

    // MARK: - Share Listing Helpers

    private static func shares(_ count: UInt32, _ body: (Int) -> Share) -> [Share] {
        (0 ..< Int(count)).map(body)
    }

    private static func shares(from container: srvsvc_SHARE_INFO_0_CONTAINER) -> [Share] {
        guard let buffer = container.Buffer?.pointee.share_info_0 else {
            return []
        }

        return shares(container.EntriesRead) { index in
            Share(
                name: string(from: buffer[index].netname),
                kind: nil,
                attributes: [],
                remark: nil,
            )
        }
    }

    private static func shares(from container: srvsvc_SHARE_INFO_1_CONTAINER) -> [Share] {
        guard let buffer = container.Buffer?.pointee.share_info_1 else {
            return []
        }

        return shares(container.EntriesRead) { index in
            let info = buffer[index]
            return Share(
                name: string(from: info.netname),
                kind: ShareKind(rawValue: info.type),
                attributes: ShareAttributes(rawShareType: info.type),
                remark: string(from: info.remark),
            )
        }
    }

    private static func string(from string: dcerpc_utf16) -> String {
        string.utf8.map(String.init(cString:)) ?? ""
    }

    private static func filterForUserVisibleDiskShares(_ shares: [Share], includeHidden: Bool) -> [Share] {
        shares.filter { share in
            share.kind == .diskTree && (includeHidden || !share.isHidden)
        }
    }
}
