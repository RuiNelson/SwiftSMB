//
// Part of SwiftSMB
// LinkTargetLookup.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import PathWorks

extension SMB.Connection {
    /// The share-relative path to inspect to learn whether the target of a link is a directory, or `nil` when the
    /// target cannot be looked up through the share.
    ///
    /// A relative target is resolved against the directory that holds the link. An absolute target (one that starts
    /// with a separator, or any target when `isAbsolute` is set) is looked up from the share root. A drive-letter
    /// path names a volume on the server and cannot be reached through a share, and a relative target that climbs
    /// above the share root leaves it.
    ///
    /// - Parameters:
    ///   - target: The target the link will point to.
    ///   - linkPath: The validated, share-relative path of the link.
    ///   - isAbsolute: Whether the target is to be treated as an absolute path on the server.
    static func linkTargetLookupPath(target: String, linkPath: String, isAbsolute: Bool) -> String? {
        let target = target.replacingOccurrences(of: "\\", with: "/")

        let characters = Array(target.prefix(2))
        if characters.count == 2, characters[0].isLetter, characters[1] == ":" {
            return nil
        }

        let candidate = if isAbsolute || target.first == "/" {
            target.pathComponents.path
        }
        else {
            linkPath.removingLastPathComponent.appendingPathComponent(target)
        }

        guard !candidate.split(separator: "/").contains("..") else {
            return nil
        }
        return candidate
    }

    /// Best-effort check of whether the target of a link to be created is a directory.
    ///
    /// A target that does not exist, cannot be reached through the share, or cannot be inspected is reported as not
    /// being a directory, like a dangling link on a POSIX system.
    func linkTargetIsDirectory(target: String, linkPath: String, isAbsolute: Bool) async throws -> Bool {
        guard let lookupPath = Self.linkTargetLookupPath(target: target, linkPath: linkPath, isAbsolute: isAbsolute) else {
            return false
        }

        do {
            let stat = try await stat(at: lookupPath)
            // A directory link reports as a link, with the directory attribute set.
            return stat.type == .directory || stat.attributes.contains(.directory)
        }
        catch is SMB.Error {
            return false
        }
    }
}
