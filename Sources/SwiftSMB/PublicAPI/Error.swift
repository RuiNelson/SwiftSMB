//
// Part of SwiftSMB
// Error.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// Errors thrown by the public SMB API.
    enum Error: Swift.Error, Equatable, CustomStringConvertible, CustomDebugStringConvertible, LocalizedError,
    Sendable {
        /// A `libsmb2` context could not be created.
        case contextCreationFailed
        
        case operationRequestedAfterConnectionClosed

        /// An invalid argument was supplied to the API.
        case invalidArgument(cause: InvalidArgumentException, onOperation: InvalidArgumentOperation)

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

        var posixErrorLocalizedDescription: String? {
            switch self {
            case let .posix(code, operation: _, message: _):
                guard let posixErrorCode = POSIXErrorCode(rawValue: code) else {
                    return nil
                }

                return POSIXError(posixErrorCode).localizedDescription
            default:
                return nil
            }
        }

        /// A human-readable description of the error.
        public var debugDescription: String {
            switch self {
            case .contextCreationFailed:
                return "Failed to create SMB context"
            case .operationRequestedAfterConnectionClosed:
                return "Operation requested after connection was closed"
            case let .invalidArgument(cause, operation):
                return Self.describe("Invalid argument", operation: operation.description, message: cause.description)
            case let .posix(code, operation, message):
                var label = "POSIX error errno=\(code)"
                if let posixErrorLocalizedDescription {
                    label += " (\(posixErrorLocalizedDescription))"
                }
                return Self.describe(label, operation: operation, message: message)
            case let .unknownPOSIX(code, operation, message):
                return Self.describe("Unknown POSIX error errno=\(code)", operation: operation, message: message)
            case let .ntStatus(status, posixCode, operation, message):
                var label = "SMB status \(status.description)"
                if let posixCode {
                    label += " errno=\(posixCode)"
                }
                return Self.describe(label, operation: operation, message: message)
            case let .unknownNTStatus(rawValue, posixCode, operation, message):
                var label = "Unknown SMB status \(hex(rawValue))"
                if let posixCode {
                    label += " errno=\(posixCode)"
                }
                return Self.describe(label, operation: operation, message: message)
            case let .unknown(operation, message):
                return Self.describe("Unknown SMB error", operation: operation, message: message)
            }
        }

        public var description: String {
            debugDescription
        }

        /// A localized description of the error.
        ///
        /// Apps should override this computed variable and provide localized error descriptions
        public var errorDescription: String? {
            description
        }

        /// The bridge operation that produced this error, if available.
        public var operation: String? {
            switch self {
            case .contextCreationFailed:
                nil
            case .operationRequestedAfterConnectionClosed:
                nil
            case let .invalidArgument(_, operation):
                operation.description
            case let .posix(_, operation, _),
                 let .unknownPOSIX(_, operation, _),
                 let .ntStatus(_, _, operation, _),
                 let .unknownNTStatus(_, _, operation, _),
                 let .unknown(operation, _):
                operation
            }
        }

        /// The human-readable detail message from the bridge, if available.
        public var message: String? {
            switch self {
            case .contextCreationFailed:
                nil
            case .operationRequestedAfterConnectionClosed:
                nil
            case let .invalidArgument(cause, _):
                cause.description
            case let .posix(_, _, message),
                 let .unknownPOSIX(_, _, message),
                 let .ntStatus(_, _, _, message),
                 let .unknownNTStatus(_, _, _, message),
                 let .unknown(_, message):
                message
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
