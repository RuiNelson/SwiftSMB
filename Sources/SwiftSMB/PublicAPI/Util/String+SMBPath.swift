//
// Part of SwiftSMB
// String+SMBPath.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

extension String {
    /// Returns this path relative to an SMB share root.
    var smbShareRelativePath: String {
        var path = self
        while path.first == "/" {
            path.removeFirst()
        }
        return path
    }
}
