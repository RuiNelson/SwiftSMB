//
// Part of SwiftSMB
// PathValidation.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import PathWorks

extension SMB {
    /// Validates a share name before passing it to libsmb2.
    static func validateShareName(
        _ share: String,
        operation: SMB.Error.InvalidArgumentOperation,
    ) throws {
        guard share.isSafeFilenameForNTFS else {
            throw SMB.Error.invalidArgument(cause: .invalidShareName(share), onOperation: operation)
        }

        guard share.pathComponents.count == 1 else {
            throw SMB.Error.invalidArgument(cause: .shareNameMustBeSingleComponent, onOperation: operation)
        }
    }

    /// Validates and normalizes a share-relative path before passing it to libsmb2.
    @discardableResult static func validatePath(
        _ path: String,
        operation: SMB.Error.InvalidArgumentOperation,
        allowRoot: Bool = false,
    ) throws -> String {
        var pcs = path.pathComponents

        while let first = pcs.first, first == "." {
            pcs.removeFirst()
        }

        while let last = pcs.last, last == "." {
            pcs.removeLast()
        }

        let path = pcs.path

        if allowRoot, path.isEmpty {
            return path
        }

        guard !path.isEmpty else {
            throw SMB.Error.invalidArgument(cause: .pathMustNotBeEmpty, onOperation: operation)
        }

        let components = path.pathComponents
        guard !components.isEmpty else {
            throw SMB.Error.invalidArgument(cause: .pathMustContainAtLeastOneComponent, onOperation: operation)
        }

        for component in components {
            guard component.isSafeFilenameForNTFS else {
                throw SMB.Error.invalidArgument(
                    cause: .invalidPathComponent(component),
                    onOperation: operation,
                )
            }
        }

        return path
    }
}
