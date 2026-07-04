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
        guard self >= 0, self <= Int(UInt32.max) else {
            throw SMB.Error.invalidArgument(
                cause: .byteCountCannotBeRepresentedAsUInt32(self),
                onOperation: operation
            )
        }

        return UInt32(self)
    }
}
