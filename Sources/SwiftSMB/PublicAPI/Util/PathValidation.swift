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
        operation: SMB.Error.InvalidArgumentOperation
    ) throws {
        guard share.isValidSMBShareName else {
            throw SMB.Error.invalidArgument(cause: .invalidShareName(share), onOperation: operation)
        }
    }

    /// Validates and normalizes a share-relative path before passing it to libsmb2.
    @discardableResult static func validatePath(
        _ path: String,
        operation: SMB.Error.InvalidArgumentOperation,
        allowRoot: Bool = false
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
                    onOperation: operation
                )
            }
        }

        return path
    }
}

/// A type that can be validated as an SMB share name.
public protocol CanBeSMBShareName {
    /// Returns whether the string conforms to SMB share naming rules: 1–80 characters, no leading/trailing dots or
    /// spaces, only letters, digits, spaces, and a set of allowed special characters, and not a reserved Windows device
    /// name.
    var isValidSMBShareName: Bool { get }
}

private let allowedSpecialChars = #"!@#$%^&()_-{}.~"#
private let forbiddenNames = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
]

extension String: CanBeSMBShareName {
    public var isValidSMBShareName: Bool {
        guard self.count > 0, self.count <= 80 else {
            return false
        }

        guard self.first != ".", self.first != " " else {
            return false
        }

        guard self.last != ".", self.last != " " else {
            return false
        }

        let charsOK = allSatisfy {
            $0.isLetter || $0.isNumber || $0 == " " || allowedSpecialChars.contains($0)
        }

        guard charsOK else {
            return false
        }
        
        guard !forbiddenNames.contains(self) else {
            return false
        }
        
        return true
    }
}
