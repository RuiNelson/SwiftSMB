//
// Part of SwiftSMB
// SMBPathValidation.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import PathWorks

extension SMB {
    /// Validates a share name before passing it to libsmb2.
    static func validateShareName(_ share: String, operation: String) throws {
        guard share.isSafeFilenameForNTFS else {
            throw SMB.Error.invalidArgument(operation: operation, message: "Invalid share name '\(share)'")
        }

        guard share.pathComponents.count == 1 else {
            throw SMB.Error.invalidArgument(operation: operation, message: "Share name must be a single component")
        }
    }

    /// Validates and normalizes a share-relative path before passing it to libsmb2.
    @discardableResult static func validatePath(
        _ path: String,
        operation: String,
        allowRoot: Bool = false,
    ) throws -> String {
        let path = path.smbShareRelativePath

        if allowRoot, path.isEmpty {
            return path
        }

        guard !path.isEmpty else {
            throw SMB.Error.invalidArgument(operation: operation, message: "Path must not be empty")
        }

        let components = path.pathComponents
        guard !components.isEmpty else {
            throw SMB.Error.invalidArgument(operation: operation, message: "Path must contain at least one component")
        }

        for component in components {
            guard component.isSafeFilenameForNTFS else {
                throw SMB.Error.invalidArgument(
                    operation: operation,
                    message: "Invalid path component '\(component)'",
                )
            }
        }

        return path
    }
}
