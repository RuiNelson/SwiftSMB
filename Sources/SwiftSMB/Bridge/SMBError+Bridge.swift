//
// Part of SwiftSMB
// SMBError+Bridge.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SMB2

extension SMB.Error {
    static func fromBridge(_ context: SMB2Context, operation: String, status: Int32? = nil) -> SMB.Error {
        let message = smb2_get_error(context.raw).map(String.init(cString:)) ?? ""
        let posixCode = status.map { $0 < 0 ? -$0 : $0 }
        let ntStatusCode = smb2_get_nterror(context.raw)
        let ntStatusRawValue = UInt32(bitPattern: ntStatusCode)
        let ntStatus = ntStatusCode == 0 ? nil : SMB.SMBStatus(rawValue: ntStatusRawValue)

        if let ntStatus {
            return .ntStatus(ntStatus, posixCode: posixCode, operation: operation, message: message)
        }

        if ntStatusCode != 0 {
            return .unknownNTStatus(
                rawValue: ntStatusRawValue,
                posixCode: posixCode,
                operation: operation,
                message: message,
            )
        }

        if let posixCode {
            guard let code = POSIXErrorCode(rawValue: posixCode) else {
                return .unknownPOSIX(code: posixCode, operation: operation, message: message)
            }

            return .posix(code: code.rawValue, operation: operation, message: message)
        }

        return .unknown(operation: operation, message: message)
    }
}

/// Throws an SMB error if a C status code represents failure.
@discardableResult func check(_ status: Int32, context: SMB2Context, operation: String) throws -> Int32 {
    guard status >= 0 else {
        throw SMB.Error.fromBridge(context, operation: operation, status: status)
    }

    return status
}
