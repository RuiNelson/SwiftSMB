//
// Part of SwiftSMB
// PathValidation.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import PathWorks

extension SMB {
    /// Rejects embedded terminators before a Swift string is passed to a C API.
    static func validateCString(_ value: String, operation: SMB.Error.InvalidArgumentOperation) throws {
        guard !value.utf8.contains(0) else {
            throw SMB.Error.invalidArgument(cause: .stringContainsNUL, onOperation: operation)
        }
    }

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
            guard component.isSafeFilenameForNTFSIncludingLength else {
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

private let forbiddenCharactersForShareNames: CharacterSet = {
    var set = CharacterSet()
    set.insert(charactersIn: #""\/[]:|<>+=;,*?"#)
    set.formUnion(.controlCharacters)
    return set
}()

extension String: CanBeSMBShareName {
    public var isValidSMBShareName: Bool {
        guard self.count > 0, self.count <= 80,
              rangeOfCharacter(from: forbiddenCharactersForShareNames) == nil else {
            return false
        }
        
        return true
    }
}
