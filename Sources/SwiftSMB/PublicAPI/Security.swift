//
// Part of SwiftSMB
// Security.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// A Windows security identifier (SID).
    struct SecurityIdentifier: Equatable, Hashable, CustomDebugStringConvertible, Sendable {
        /// The SID format revision.
        public let revision: UInt8

        /// The 48-bit identifier authority.
        public let identifierAuthority: UInt64

        /// The relative identifiers that form the rest of the SID.
        public let subauthorities: [UInt32]

        /// The well-known Everyone SID (`S-1-1-0`).
        public static let everyone = SecurityIdentifier(identifierAuthority: 1, subauthorities: [0])

        /// Creates a security identifier.
        ///
        /// Validation of the 48-bit authority and the SMB maximum subauthority count occurs when the SID is sent.
        public init(revision: UInt8 = 1, identifierAuthority: UInt64, subauthorities: [UInt32]) {
            self.revision = revision
            self.identifierAuthority = identifierAuthority
            self.subauthorities = subauthorities
        }

        public var debugDescription: String {
            (["S", String(revision), String(identifierAuthority)] + subauthorities.map(String.init))
                .joined(separator: "-")
        }

        var bridgeValue: Bridge.SecurityIdentifier {
            Bridge.SecurityIdentifier(
                revision: revision,
                identifierAuthority: identifierAuthority,
                subauthorities: subauthorities
            )
        }
    }

    /// Access rights carried by an access-control entry.
    struct AccessMask: OptionSet, Equatable, Hashable, CustomDebugStringConvertible, Sendable {
        /// The access-mask bits sent to the server.
        public let rawValue: UInt32

        /// Permission to read file data or list a directory.
        public static let readData = AccessMask(rawValue: 0x0000_0001)
        /// Permission to write file data or create a file in a directory.
        public static let writeData = AccessMask(rawValue: 0x0000_0002)
        /// Permission to append file data or create a subdirectory.
        public static let appendData = AccessMask(rawValue: 0x0000_0004)
        /// Permission to read extended attributes.
        public static let readExtendedAttributes = AccessMask(rawValue: 0x0000_0008)
        /// Permission to write extended attributes.
        public static let writeExtendedAttributes = AccessMask(rawValue: 0x0000_0010)
        /// Permission to execute a file or traverse a directory.
        public static let execute = AccessMask(rawValue: 0x0000_0020)
        /// Permission to delete child items from a directory.
        public static let deleteChild = AccessMask(rawValue: 0x0000_0040)
        /// Permission to read file or directory attributes.
        public static let readAttributes = AccessMask(rawValue: 0x0000_0080)
        /// Permission to write file or directory attributes.
        public static let writeAttributes = AccessMask(rawValue: 0x0000_0100)
        /// Permission to delete the item.
        public static let delete = AccessMask(rawValue: 0x0001_0000)
        /// Permission to read the security descriptor and ownership information.
        public static let readControl = AccessMask(rawValue: 0x0002_0000)
        /// Permission to modify the discretionary access-control list.
        public static let writeDACL = AccessMask(rawValue: 0x0004_0000)
        /// Permission to change the owner or group.
        public static let writeOwner = AccessMask(rawValue: 0x0008_0000)
        /// Permission to use the item for synchronization.
        public static let synchronize = AccessMask(rawValue: 0x0010_0000)
        /// Permission to access the system access-control list.
        public static let systemSecurity = AccessMask(rawValue: 0x0100_0000)
        /// Request the maximum permissions the server can grant.
        public static let maximumAllowed = AccessMask(rawValue: 0x0200_0000)
        /// Request all generic permissions.
        public static let genericAll = AccessMask(rawValue: 0x1000_0000)
        /// Request generic execution permissions.
        public static let genericExecute = AccessMask(rawValue: 0x2000_0000)
        /// Request generic write permissions.
        public static let genericWrite = AccessMask(rawValue: 0x4000_0000)
        /// Request generic read permissions.
        public static let genericRead = AccessMask(rawValue: 0x8000_0000)

        /// Creates an access mask from its SMB access bits.
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        public var debugDescription: String {
            "SMB.AccessMask(rawValue: \(hex(rawValue)))"
        }
    }

    /// An entry in a discretionary access-control list.
    struct AccessControlEntry: Equatable, Hashable, CustomDebugStringConvertible, Sendable {
        /// The effect of an access-control entry.
        public enum Kind: UInt8, Equatable, Hashable, Sendable {
            /// Grants the selected permissions.
            case allowed = 0x00
            /// Denies the selected permissions.
            case denied = 0x01
            /// Audits attempts to use the selected permissions.
            case systemAudit = 0x02
        }

        /// Inheritance and auditing behavior attached to an entry.
        public struct Flags: OptionSet, Equatable, Hashable, CustomDebugStringConvertible, Sendable {
            /// The ACE flag bits sent to the server.
            public let rawValue: UInt8

            /// Child files inherit this entry.
            public static let objectInherit = Flags(rawValue: 0x01)
            /// Child directories inherit this entry.
            public static let containerInherit = Flags(rawValue: 0x02)
            /// Inheritance stops after the immediate child.
            public static let noPropagateInherit = Flags(rawValue: 0x04)
            /// The entry applies only to inherited children.
            public static let inheritOnly = Flags(rawValue: 0x08)
            /// The entry was inherited from a parent object.
            public static let inherited = Flags(rawValue: 0x10)
            /// Audit successful access attempts.
            public static let successfulAccess = Flags(rawValue: 0x40)
            /// Audit failed access attempts.
            public static let failedAccess = Flags(rawValue: 0x80)

            /// Creates ACE flags from their SMB flag bits.
            public init(rawValue: UInt8) {
                self.rawValue = rawValue
            }

            public var debugDescription: String {
                "SMB.AccessControlEntry.Flags(rawValue: \(hex(rawValue)))"
            }
        }

        /// Whether the entry allows, denies, or audits access.
        public let kind: Kind

        /// Inheritance and auditing flags.
        public let flags: Flags

        /// The permissions controlled by the entry.
        public let accessMask: AccessMask

        /// The user or group to which the entry applies.
        public let trustee: SecurityIdentifier

        /// Creates an access-control entry.
        public init(
            kind: Kind,
            flags: Flags = [],
            accessMask: AccessMask,
            trustee: SecurityIdentifier
        ) {
            self.kind = kind
            self.flags = flags
            self.accessMask = accessMask
            self.trustee = trustee
        }

        public var debugDescription: String {
            "SMB.AccessControlEntry(kind: \(kind), flags: \(flags.debugDescription), accessMask: \(accessMask.debugDescription), trustee: \(trustee.debugDescription))"
        }

        var bridgeValue: Bridge.AccessControlEntry {
            Bridge.AccessControlEntry(
                kind: kind.rawValue,
                flags: flags.rawValue,
                accessMask: accessMask.rawValue,
                trustee: trustee.bridgeValue
            )
        }
    }

    /// A discretionary access-control list (DACL).
    struct AccessControlList: Equatable, Hashable, CustomDebugStringConvertible, Sendable {
        /// The ACL wire-format revision.
        public enum Revision: UInt8, Equatable, Hashable, Sendable {
            /// The standard ACL revision used by basic ACE types.
            case standard = 0x02
            /// The directory-service ACL revision used by object-specific ACE types.
            case directoryService = 0x04
        }

        /// The ACL wire-format revision.
        public let revision: Revision

        /// The ordered access-control entries.
        public let entries: [AccessControlEntry]

        /// Creates a discretionary access-control list.
        public init(revision: Revision = .standard, entries: [AccessControlEntry]) {
            self.revision = revision
            self.entries = entries
        }

        public var debugDescription: String {
            "SMB.AccessControlList(revision: \(revision), entries: \(entries))"
        }

        var bridgeValue: Bridge.AccessControlList {
            Bridge.AccessControlList(revision: revision.rawValue, entries: entries.map(\.bridgeValue))
        }
    }

    /// Owner, group, and discretionary access-control information for an SMB item.
    struct SecurityDescriptor: Equatable, Hashable, CustomDebugStringConvertible, Sendable {
        /// The new owner, or `nil` to leave the current owner unchanged.
        public let owner: SecurityIdentifier?

        /// The new primary group, or `nil` to leave the current group unchanged.
        public let group: SecurityIdentifier?

        /// The new DACL, or `nil` to leave the current DACL unchanged.
        public let discretionaryAccessControlList: AccessControlList?

        /// Creates a descriptor containing the security components to update.
        public init(
            owner: SecurityIdentifier? = nil,
            group: SecurityIdentifier? = nil,
            discretionaryAccessControlList: AccessControlList? = nil
        ) {
            self.owner = owner
            self.group = group
            self.discretionaryAccessControlList = discretionaryAccessControlList
        }

        public var debugDescription: String {
            "SMB.SecurityDescriptor(owner: \(String(describing: owner)), group: \(String(describing: group)), discretionaryAccessControlList: \(String(describing: discretionaryAccessControlList)))"
        }

        var bridgeValue: Bridge.SecurityDescriptor {
            Bridge.SecurityDescriptor(
                owner: owner?.bridgeValue,
                group: group?.bridgeValue,
                discretionaryAccessControlList: discretionaryAccessControlList?.bridgeValue
            )
        }
    }
}
