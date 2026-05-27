//
// Part of SwiftSMB
// OptionSet+.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

extension OptionSet where Self == Self.Element {
    /// Returns a debug description listing the names of the flags present in this set, or `[]` when empty.
    ///
    /// - Parameters:
    ///   - flags: A list of known flag values paired with their names, in the order they should appear in the
    /// description.
    ///   - typeName: The qualified type name to prefix the output with.
    func describeFlags(_ flags: [(Self, String)], typeName: String) -> String {
        var names: [String] = []
        for (flag, name) in flags {
            if contains(flag) {
                names.append(name)
            }
        }
        if names.isEmpty {
            names.append("[]")
        }
        return "\(typeName)(\(names.joined(separator: ", ")))"
    }
}

extension CustomDebugStringConvertible {
    /// Formats an unsigned integer as a hexadecimal string with a `0x` prefix.
    ///
    /// Used for raw values in ``unknown``-style enum cases, for example `SMB.NodeType.unknown(0xC000_0034)`.
    func hex(_ value: some UnsignedInteger, uppercase: Bool = true) -> String {
        "0x\(String(value, radix: 16, uppercase: uppercase))"
    }
}
