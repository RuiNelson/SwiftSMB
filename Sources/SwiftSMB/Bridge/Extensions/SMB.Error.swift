//
// Part of SwiftSMB
// SMB.Error.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

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
                message: message,
            )
        }

        if let status {
            let rawNTStatus = UInt32(bitPattern: status)
            if let knownNTStatus = SMB.SMBStatus(rawValue: rawNTStatus) {
                return .ntStatus(knownNTStatus, posixCode: nil, operation: operation, message: message)
            }
            let absolute = status < 0 ? Int32(-status) : status
            if absolute > 1024 {
                return .unknownNTStatus(
                    rawValue: rawNTStatus,
                    posixCode: nil,
                    operation: operation,
                    message: message,
                )
            }
            if let code = POSIXErrorCode(rawValue: absolute) {
                return .posix(code: code.rawValue, operation: operation, message: message)
            }
            return .unknownPOSIX(code: absolute, operation: operation, message: message)
        }

        return .unknown(operation: operation, message: message)
    }
}
