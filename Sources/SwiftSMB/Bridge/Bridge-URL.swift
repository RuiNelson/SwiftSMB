//
// Part of SwiftSMB
// Bridge-URL.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    // MARK: - URL Parsing

    private static func _parseURL(_ url: String, context: Context) throws -> SMB2URL {
        let rawURL = url.withCString { smb2_parse_url(context.raw, $0) }

        guard let rawURL else {
            throw SMB.Error.fromBridge(context, operation: "smb2_parse_url")
        }

        defer { smb2_destroy_url(rawURL) }
        return SMB2URL(rawURL.pointee)
    }

    /// Parses an SMB URL into Swift-friendly URL components.
    static func parseURL(_ url: String, context: Context) throws -> SMB2URL {
        try Bridge.sync {
            try _parseURL(url, context: context)
        }
    }
}
