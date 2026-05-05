//
// Part of SwiftSMB
// SMB2Bridge-Other.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

import SMB2
import SMB2.Raw

/// Connects to IPC$, enumerates user-visible disk shares, and disconnects.
func listShares(
    context: SMB2Context,
    server: String,
    user: String? = nil,
    includeHidden: Bool = false,
) throws -> [SMB2Share] {
    setSecurityMode(.signingEnabled, on: context)
    try connectShare(context: context, server: server, share: "IPC$", user: user)

    do {
        let shares = try listSharesOnConnectedIPCShare(context: context)
            .filterForUserVisibleDiskShares(includeHidden: includeHidden)
        try disconnectShare(context: context)
        return shares
    }
    catch {
        try? disconnectShare(context: context)
        throw error
    }
}

/// Enumerates shares using SRVSVC on a context that is already connected to IPC$.
func listSharesOnConnectedIPCShare(
    context: SMB2Context,
    level: SMB2ShareEnumerationLevel = .detailed,
) throws -> [SMB2Share] {
    guard let response = smb2_share_enum_sync(context.raw, level.rawValue) else {
        throw SMB2Error.from(context, operation: "smb2_share_enum_sync")
    }

    defer { smb2_free_data(context.raw, response) }

    switch response.pointee.ses.Level {
    case UInt32(SHARE_INFO_0.rawValue):
        return shares(from: response.pointee.ses.ShareInfo.Level0)
    case UInt32(SHARE_INFO_1.rawValue):
        return shares(from: response.pointee.ses.ShareInfo.Level1)
    default:
        throw SMB2Error.invalidArgument(
            operation: "smb2_share_enum_sync",
            message: "Unsupported share enumeration level \(response.pointee.ses.Level)",
        )
    }
}

/// Builds an array of shares by mapping a C entry count.
private func shares(_ count: UInt32, _ body: (Int) -> SMB2Share) -> [SMB2Share] {
    (0 ..< Int(count)).map(body)
}

/// Converts a level-0 share container into Swift share values.
private func shares(from container: srvsvc_SHARE_INFO_0_CONTAINER) -> [SMB2Share] {
    guard let buffer = container.Buffer?.pointee.share_info_0 else {
        return []
    }

    return shares(container.EntriesRead) { index in
        SMB2Share(
            name: string(from: buffer[index].netname),
            kind: nil,
            attributes: [],
            remark: nil,
        )
    }
}

/// Converts a level-1 share container into Swift share values.
private func shares(from container: srvsvc_SHARE_INFO_1_CONTAINER) -> [SMB2Share] {
    guard let buffer = container.Buffer?.pointee.share_info_1 else {
        return []
    }

    return shares(container.EntriesRead) { index in
        let info = buffer[index]
        return SMB2Share(
            name: string(from: info.netname),
            kind: SMB2ShareKind(rawValue: info.type),
            attributes: SMB2ShareAttributes(rawShareType: info.type),
            remark: string(from: info.remark),
        )
    }
}

/// Converts a DCERPC UTF-16 string wrapper into a Swift string.
private func string(from string: dcerpc_utf16) -> String {
    string.utf8.map(String.init(cString:)) ?? ""
}

private extension [SMB2Share] {
    /// Keeps disk shares and optionally removes hidden administrative shares.
    func filterForUserVisibleDiskShares(includeHidden: Bool) -> [SMB2Share] {
        filter { share in
            share.kind == .diskTree && (includeHidden || !share.isHidden)
        }
    }
}
