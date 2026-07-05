//
// Part of SwiftSMB
// SMB.Error.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation
import SMB2

extension SMB.Error {
    static func fromBridge(_ context: Bridge.Context, operation: String, status: Int32? = nil) -> SMB.Error {
        let message = smb2_get_error(context.raw).map(String.init(cString:)) ?? ""
        let ntStatusCode = smb2_get_nterror(context.raw)
        let ntStatusRawValue = UInt32(bitPattern: ntStatusCode)

        if ntStatusCode != 0 {
            if let ntStatus = SMB.SMBStatus(rawValue: ntStatusRawValue) {
                return .ntStatus(ntStatus, posixCode: nil, operation: operation, message: message)
            }
            return .unknownNTStatus(
                rawValue: ntStatusRawValue,
                posixCode: nil,
                operation: operation,
                message: message
            )
        }

        if let status {
            let rawNTStatus = UInt32(bitPattern: status)
            if let knownNTStatus = SMB.SMBStatus(rawValue: rawNTStatus) {
                return .ntStatus(knownNTStatus, posixCode: nil, operation: operation, message: message)
            }
            // status.magnitude, not -status: negating Int32.min (raw NT status 0x80000000) would trap.
            let absolute = status.magnitude
            if absolute > 1024 {
                return .unknownNTStatus(
                    rawValue: rawNTStatus,
                    posixCode: nil,
                    operation: operation,
                    message: message
                )
            }
            if let code = POSIXErrorCode(rawValue: Int32(absolute)) {
                return .posix(code: code.rawValue, operation: operation, message: message)
            }
            return .unknownPOSIX(code: Int32(absolute), operation: operation, message: message)
        }

        return .unknown(operation: operation, message: message)
    }
}
