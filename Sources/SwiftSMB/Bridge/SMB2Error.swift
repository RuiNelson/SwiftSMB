//
// Part of SwiftSMB
// SMB2Error.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

import Foundation
import SMB2

struct SMB2ErrorContext: Equatable {
    let operation: String
    let message: String
}

enum SMB2Error: Error, Equatable, CustomStringConvertible {
    case contextCreationFailed
    case invalidArgument(SMB2ErrorContext)
    case posix(POSIXError, context: SMB2ErrorContext)
    case unknownPOSIX(code: Int32, context: SMB2ErrorContext)
    case ntStatus(SMB2Status, posixCode: Int32?, context: SMB2ErrorContext)
    case unknownNTStatus(rawValue: UInt32, posixCode: Int32?, context: SMB2ErrorContext)
    case unknown(SMB2ErrorContext)

    var context: SMB2ErrorContext? {
        switch self {
        case .contextCreationFailed:
            nil
        case let .invalidArgument(context),
             let .posix(_, context),
             let .unknownPOSIX(_, context),
             let .ntStatus(_, _, context),
             let .unknownNTStatus(_, _, context),
             let .unknown(context):
            context
        }
    }

    var description: String {
        switch self {
        case .contextCreationFailed:
            "Failed to create SMB2 context"
        case let .invalidArgument(context):
            Self.describe("Invalid argument", context: context)
        case let .posix(error, context):
            Self.describe("POSIX error", context: context, posixError: error)
        case let .unknownPOSIX(code, context):
            Self.describe("Unknown POSIX error", context: context, posixCode: code)
        case let .ntStatus(status, posixCode, context):
            Self.describe("SMB2 status error", context: context, posixCode: posixCode, ntStatus: status)
        case let .unknownNTStatus(rawValue, posixCode, context):
            Self.describe(
                "Unknown SMB2 status error",
                context: context,
                posixCode: posixCode,
                ntStatusRawValue: rawValue,
            )
        case let .unknown(context):
            Self.describe("Unknown SMB2 error", context: context)
        }
    }
    
    var localizedDescription: String {
        description
    }

    static func from(_ context: SMB2Context, operation: String, status: Int32? = nil) -> SMB2Error {
        let message = smb2_get_error(context.raw).map(String.init(cString:)) ?? ""
        let posixCode = status.map { $0 < 0 ? -$0 : $0 }
        let ntStatusCode = smb2_get_nterror(context.raw)
        let ntStatusRawValue = UInt32(bitPattern: ntStatusCode)
        let ntStatus = ntStatusCode == 0 ? nil : SMB2Status(rawValue: ntStatusRawValue)
        let errorContext = SMB2ErrorContext(
            operation: operation,
            message: message,
        )

        if let ntStatus {
            return .ntStatus(ntStatus, posixCode: posixCode, context: errorContext)
        }

        if ntStatusCode != 0 {
            return .unknownNTStatus(rawValue: ntStatusRawValue, posixCode: posixCode, context: errorContext)
        }

        if let posixCode {
            guard let code = POSIXErrorCode(rawValue: posixCode) else {
                return .unknownPOSIX(code: posixCode, context: errorContext)
            }

            return .posix(POSIXError(code), context: errorContext)
        }

        return .unknown(errorContext)
    }

    static func invalidArgument(operation: String, message: String) -> SMB2Error {
        .invalidArgument(
            SMB2ErrorContext(
                operation: operation,
                message: message,
            ),
        )
    }

    private static func describe(
        _ label: String,
        context: SMB2ErrorContext,
        posixError: POSIXError? = nil,
        posixCode: Int32? = nil,
        ntStatus: SMB2Status? = nil,
        ntStatusRawValue: UInt32? = nil,
    ) -> String {
        var parts = ["\(label) in \(context.operation)"]

        if let posixError {
            parts.append("errno=\(posixError.code.rawValue) (\(posixError.localizedDescription))")
        }

        if let posixCode {
            parts.append("errno=\(posixCode)")
        }

        if let ntStatus {
            parts.append("ntStatus=\(ntStatus.description)")
        }

        if let ntStatusRawValue {
            parts.append("ntStatus=UNKNOWN (0x\(String(ntStatusRawValue, radix: 16, uppercase: true)))")
        }

        if !context.message.isEmpty {
            parts.append(context.message)
        }

        return parts.joined(separator: ": ")
    }
}

/// Throws an SMB2Error if a C status code represents failure.
@discardableResult func check(_ status: Int32, context: SMB2Context, operation: String) throws -> Int32 {
    guard status >= 0 else {
        throw SMB2Error.from(context, operation: operation, status: status)
    }
    
    return status
}
