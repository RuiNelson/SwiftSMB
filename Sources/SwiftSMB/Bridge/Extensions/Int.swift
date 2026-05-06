//
// Part of SwiftSMB
// Int.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

extension Int {
    /// Converts the integer to UInt32 or throws if it cannot be represented.
    func asUInt32(operation: String) throws -> UInt32 {
        guard self >= 0, self <= Int(UInt32.max) else {
            throw SMB2Error.invalidArgument(
                operation: operation,
                message: "Byte count \(self) cannot be represented as UInt32",
            )
        }
        
        return UInt32(self)
    }
}
