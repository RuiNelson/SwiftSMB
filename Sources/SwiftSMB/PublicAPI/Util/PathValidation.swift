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

    /// The longest path SMB allows, in UTF-16 code units ([MS-FSCC] 2.1.5).
    static let maximumPathLength = 32760

    /// The longest path component SMB allows, in UTF-16 code units ([MS-FSCC] 2.1.5.2).
    static let maximumComponentLength = 255

    /// The longest path component Unix file systems such as ext4, APFS and ZFS allow, in UTF-8 bytes.
    static let maximumUnixComponentByteCount = 255

    /// Validates and normalizes a share-relative path before passing it to libsmb2.
    ///
    /// The path is split at every `/`, and empty components are dropped, so a leading `/` changes nothing. `.`
    /// components are removed and `..` components resolved against the preceding ones; a `..` with nothing left to
    /// resolve against would leave the share and is rejected. The remaining components are checked with the rules of
    /// `validation`, and keep the caller's spelling: no Unicode normalization is applied.
    ///
    /// - Parameters:
    ///   - path: The share-relative path, with `/` separators.
    ///   - operation: The operation reported in a thrown error.
    ///   - allowRoot: Whether an empty path, the root of the share, is accepted.
    ///   - validation: The rules the components must follow.
    /// - Returns: The normalized path.
    @discardableResult static func validatePath(
        _ path: String,
        operation: SMB.Error.InvalidArgumentOperation,
        allowRoot: Bool = false,
        validation: Configuration.PathValidation
    ) throws -> String {
        // PathWorks drops a leading `..` from an absolute path instead of keeping it, so the path is made relative
        // first: a `..` that would leave the share is then kept as the first component and rejected below.
        var relative = path
        while relative.unicodeScalars.first == "/" {
            relative.unicodeScalars.removeFirst()
        }
        let components = relative.pathComponents
        if components.first == ".." {
            throw SMB.Error.invalidArgument(cause: .invalidPathComponent(".."), onOperation: operation)
        }
        let path = components.path

        if allowRoot, path.isEmpty {
            return path
        }

        guard !path.isEmpty else {
            throw SMB.Error.invalidArgument(cause: .pathMustNotBeEmpty, onOperation: operation)
        }

        for component in components {
            guard component.isValidPathComponent(for: validation) else {
                throw SMB.Error.invalidArgument(
                    cause: .invalidPathComponent(component),
                    onOperation: operation
                )
            }
        }

        let length = path.utf16.count
        guard length <= maximumPathLength else {
            throw SMB.Error.invalidArgument(cause: .pathTooLong(length), onOperation: operation)
        }

        return path
    }
}

extension SMB.Connection {
    /// Validates and normalizes a share-relative path with this connection's ``SMB/Configuration/pathValidation``.
    @discardableResult func validatePath(
        _ path: String,
        operation: SMB.Error.InvalidArgumentOperation,
        allowRoot: Bool = false
    ) throws -> String {
        try SMB.validatePath(
            path,
            operation: operation,
            allowRoot: allowRoot,
            validation: configuration.pathValidation
        )
    }
}

/// Characters a filename must not contain on the wire ([MS-FSCC] 2.1.5.2): `" \ / : | < > * ?` and the control
/// characters U+0000–U+001F.
private let forbiddenCharactersForSMBFilenames: CharacterSet = {
    var set = CharacterSet(charactersIn: #""\/:|<>*?"#)
    set.insert(charactersIn: Unicode.Scalar(0x00) ... Unicode.Scalar(0x1F))
    return set
}()

private extension String {
    /// Whether the string is a valid path component under `validation`.
    func isValidPathComponent(for validation: SMB.Configuration.PathValidation) -> Bool {
        guard isValidSMBFilename else {
            return false
        }

        switch validation {
        case .smb:
            return true
        case .ntfsOverSMB:
            return isSafeFilenameForNTFSIncludingLength
        case .unixOverSMB:
            return utf8.count <= SMB.maximumUnixComponentByteCount
        }
    }

    /// Whether the string is a valid SMB filename ([MS-FSCC] 2.1.5.2): 1 to 255 UTF-16 code units and none of the
    /// forbidden characters. Dot directory names never get here:
    /// ``SMB/validatePath(_:operation:allowRoot:validation:)`` resolves them first.
    var isValidSMBFilename: Bool {
        guard !isEmpty, utf16.count <= SMB.maximumComponentLength else {
            return false
        }

        return unicodeScalars.allSatisfy { !forbiddenCharactersForSMBFilenames.contains($0) }
    }
}

/// A type that can be validated as an SMB share name.
public protocol CanBeSMBShareName {
    /// Returns whether the string conforms to SMB share naming rules: 1–80 characters, none of `" \ / [ ] : | < > + = ;
    /// , * ?`, and no control characters.
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
