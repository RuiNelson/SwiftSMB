//
// Part of SwiftSMB
// SMBError.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

import Foundation

public extension SMB {
    /// Errors thrown by the public SMB API.
    enum Error: Swift.Error, Equatable, CustomStringConvertible, LocalizedError, Sendable {
        /// A `libsmb2` context could not be created.
        case contextCreationFailed

        /// An invalid argument was supplied to the API.
        case invalidArgument(operation: String, message: String)

        /// A known POSIX error occurred.
        case posix(code: Int32, operation: String, message: String)

        /// An unknown POSIX error occurred.
        case unknownPOSIX(code: Int32, operation: String, message: String)

        /// A known SMB status error occurred.
        case ntStatus(SMBStatus, posixCode: Int32?, operation: String, message: String)

        /// An unknown SMB status error occurred.
        case unknownNTStatus(rawValue: UInt32, posixCode: Int32?, operation: String, message: String)

        /// An error occurred without a more specific classification.
        case unknown(operation: String, message: String)

        /// A human-readable description of the error.
        public var description: String {
            switch self {
            case .contextCreationFailed:
                return "Failed to create SMB context"
            case let .invalidArgument(operation, message):
                return Self.describe("Invalid argument", operation: operation, message: message)
            case let .posix(code, operation, message):
                return Self.describe("POSIX error errno=\(code)", operation: operation, message: message)
            case let .unknownPOSIX(code, operation, message):
                return Self.describe("Unknown POSIX error errno=\(code)", operation: operation, message: message)
            case let .ntStatus(status, posixCode, operation, message):
                var label = "SMB status \(status.description)"
                if let posixCode {
                    label += " errno=\(posixCode)"
                }
                return Self.describe(label, operation: operation, message: message)
            case let .unknownNTStatus(rawValue, posixCode, operation, message):
                var label = "Unknown SMB status 0x\(String(rawValue, radix: 16, uppercase: true))"
                if let posixCode {
                    label += " errno=\(posixCode)"
                }
                return Self.describe(label, operation: operation, message: message)
            case let .unknown(operation, message):
                return Self.describe("Unknown SMB error", operation: operation, message: message)
            }
        }

        /// A localized description of the error.
        public var errorDescription: String? {
            description
        }

        /// Creates a public error from a bridge error.
        init(_ bridgeError: SMB2Error) {
            switch bridgeError {
            case .contextCreationFailed:
                self = .contextCreationFailed
            case let .invalidArgument(context):
                self = .invalidArgument(operation: context.operation, message: context.message)
            case let .posix(error, context):
                self = .posix(code: error.code.rawValue, operation: context.operation, message: context.message)
            case let .unknownPOSIX(code, context):
                self = .unknownPOSIX(code: code, operation: context.operation, message: context.message)
            case let .ntStatus(status, posixCode, context):
                self = .ntStatus(
                    status,
                    posixCode: posixCode,
                    operation: context.operation,
                    message: context.message,
                )
            case let .unknownNTStatus(rawValue, posixCode, context):
                self = .unknownNTStatus(
                    rawValue: rawValue,
                    posixCode: posixCode,
                    operation: context.operation,
                    message: context.message,
                )
            case let .unknown(context):
                self = .unknown(operation: context.operation, message: context.message)
            }
        }

        /// Builds a concise error message.
        private static func describe(_ label: String, operation: String, message: String) -> String {
            if message.isEmpty {
                return "\(label) in \(operation)"
            }
            return "\(label) in \(operation): \(message)"
        }
    }
}
