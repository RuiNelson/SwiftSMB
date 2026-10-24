//
// Part of SwiftSMB
// Int.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

extension Int {
    /// Converts the integer to UInt32 or throws if it cannot be represented.
    func asUInt32(operation: SMB.Error.InvalidArgumentOperation) throws -> UInt32 {
        // `Int(UInt32.max)` would trap where `Int` is 32-bit.
        guard let value = UInt32(exactly: self) else {
            throw SMB.Error.invalidArgument(
                cause: .byteCountCannotBeRepresentedAsUInt32(self),
                onOperation: operation
            )
        }

        return value
    }
}
