//
// Part of SwiftSMB
// CachePath.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import PathWorks

/// Path arithmetic on the share-relative paths and keys of an ``SMB/ReferenceCache``.
///
/// A normalized path has no leading `/`, no empty, `.`, or `..` components, and `/` separators. The share root is the
/// empty string.
///
/// Keys are normalized paths with every byte outside ASCII, and `%`, written as `%` and two hexadecimal digits.
/// `String` compares two names that differ only in Unicode normalization as equal, in `==` and as dictionary keys
/// alike, while keys hold ASCII only, which `String` compares byte by byte. Folding a path never changes its
/// components, so a key has as many components as its path, and every path operation works on keys too.
enum CachePath {
    /// The share root.
    static let root = ""

    // MARK: Paths

    /// `path` relative to the share root, with `\` taken as a separator, as the server takes it, and `.` and `..`
    /// resolved. `..` never climbs above the share root.
    static func normalize(_ path: String) -> String {
        let separated = path.contains("\\") ? path.replacingOccurrences(of: "\\", with: "/") : path
        return ("/" + separated).pathComponents.path
    }

    /// `path`, which is `from` or lies under it, moved to the same place under `to`, component by component.
    ///
    /// Works on paths and on keys alike, and on a path whose `from` is spelled differently, as long as it has as many
    /// components.
    static func rebase(_ path: String, from: String, to: String) -> String {
        let rest = components(of: path).dropFirst(components(of: from).count)
        guard !rest.isEmpty else {
            return to
        }
        let tail = rest.joined(separator: "/")
        return to.isEmpty ? tail : to + "/" + tail
    }

    /// `name` inside the directory `directory`, or `nil` when `name` does not name an entry of its own.
    static func child(_ name: String, of directory: String) -> String? {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\\") else {
            return nil
        }
        return directory.isEmpty ? name : directory + "/" + name
    }

    // MARK: Keys

    /// The key that tells files apart byte by byte, of the normalized `path`.
    static func exactKey(_ path: String) -> String {
        escape(path)
    }

    /// The key that tells files apart regardless of case, of the normalized `path`: each scalar mapped to its simple,
    /// one-scalar uppercase, as SMB servers compare names, without Unicode normalization.
    static func caseInsensitiveKey(_ path: String) -> String {
        escape(simpleUppercased(path))
    }

    /// The key every path that may name the same file shares, on any share, of the normalized `path`: regardless of
    /// case, by full and by simple mappings, and of Unicode normalization.
    ///
    /// Two paths whose ``caseInsensitiveKey(_:)`` is the same have the same equivalence key.
    static func equivalenceKey(_ path: String) -> String {
        escape(simpleUppercased(path).uppercased().lowercased().precomposedStringWithCanonicalMapping)
    }

    /// The path a key made by ``exactKey(_:)`` stands for.
    static func path(ofExactKey key: String) -> String {
        let bytes = Array(key.utf8)
        guard bytes.contains(percent) else {
            return key
        }

        var decoded: [UInt8] = []
        decoded.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            if bytes[index] == percent, index + 2 < bytes.count,
               let high = hexValue(bytes[index + 1]), let low = hexValue(bytes[index + 2]) {
                decoded.append(high << 4 | low)
                index += 3
            }
            else {
                decoded.append(bytes[index])
                index += 1
            }
        }
        return String(decoding: decoded, as: UTF8.self)
    }

    // MARK: Arithmetic

    /// Whether `first` and `second` hold the same bytes.
    static func sameBytes(_ first: String, _ second: String) -> Bool {
        first.utf8.elementsEqual(second.utf8)
    }

    /// Whether the path or key `path` is `ancestor` itself or lies under it, comparing bytes. Everything lies under the
    /// share root.
    static func isPath(_ path: String, atOrUnder ancestor: String) -> Bool {
        guard !ancestor.isEmpty else {
            return true
        }
        if sameBytes(path, ancestor) {
            return true
        }
        let pathBytes = path.utf8
        let ancestorBytes = ancestor.utf8
        return pathBytes.count > ancestorBytes.count
            && pathBytes.starts(with: ancestorBytes)
            && pathBytes.dropFirst(ancestorBytes.count).first == UInt8(ascii: "/")
    }

    /// The directory holding the path or key `path`: the share root for the root and its children.
    static func parent(of path: String) -> String {
        guard let slash = path.utf8.lastIndex(of: UInt8(ascii: "/")) else {
            return root
        }
        return String(path[..<slash])
    }

    /// The directories holding `path`, nearest first, down to the share root.
    static func ancestors(of path: String) -> [String] {
        var result: [String] = []
        var current = path
        while !current.isEmpty {
            current = parent(of: current)
            result.append(current)
        }
        return result
    }

    // MARK: Private

    private static let percent = UInt8(ascii: "%")

    private static func components(of path: String) -> [Substring] {
        path.isEmpty ? [] : path.split(separator: "/", omittingEmptySubsequences: false)
    }

    /// `path` with every scalar that has a one-scalar uppercase mapping replaced by it.
    private static func simpleUppercased(_ path: String) -> String {
        guard path.utf8.contains(where: { $0 >= 0x80 || (0x61 ... 0x7A).contains($0) }) else {
            return path
        }

        var result = String.UnicodeScalarView()
        for scalar in path.unicodeScalars {
            let mapping = scalar.properties.uppercaseMapping.unicodeScalars
            if mapping.count == 1, let upper = mapping.first {
                result.append(upper)
            }
            else {
                result.append(scalar)
            }
        }
        return String(result)
    }

    /// `path` with every byte outside ASCII, and `%`, written as `%XX`.
    private static func escape(_ path: String) -> String {
        let bytes = path.utf8
        guard bytes.contains(where: { $0 >= 0x80 || $0 == percent }) else {
            return path
        }

        let digits = Array("0123456789ABCDEF".utf8)
        var escaped: [UInt8] = []
        escaped.reserveCapacity(bytes.count * 3)
        for byte in bytes {
            if byte >= 0x80 || byte == percent {
                escaped += [percent, digits[Int(byte >> 4)], digits[Int(byte & 0xF)]]
            }
            else {
                escaped.append(byte)
            }
        }
        return String(decoding: escaped, as: UTF8.self)
    }

    private static func hexValue(_ digit: UInt8) -> UInt8? {
        switch digit {
        case UInt8(ascii: "0") ... UInt8(ascii: "9"):
            digit - UInt8(ascii: "0")

        case UInt8(ascii: "A") ... UInt8(ascii: "F"):
            digit - UInt8(ascii: "A") + 10

        default:
            nil
        }
    }
}
