//
// Part of SwiftSMB
// SMBConfiguration.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import SMB2

public extension SMB {
    /// Identifies an SMB server.
    struct Server: Sendable {
        /// The server host name or IP address.
        public var host: String

        /// The SMB port to use, or `nil` to let `libsmb2` use its default.
        public var port: Int?

        /// The authentication domain to use when credentials don't specify one.
        public var domain: String?

        /// Creates an SMB server identifier.
        ///
        /// - Parameters:
        ///   - host: The server host name or IP address.
        ///   - port: The SMB port to use. Pass `nil` to use the default.
        ///   - domain: The default authentication domain for this server.
        public init(host: String, port: Int? = nil, domain: String? = nil) {
            self.host = host
            self.port = port
            self.domain = domain
        }

        /// Host and port in the format expected by `libsmb2`.
        var address: String {
            guard let port else { return host }
            if host.hasPrefix("[") {
                return "\(host):\(port)"
            }
            if host.contains(":") {
                return "[\(host)]:\(port)"
            }
            return "\(host):\(port)"
        }
    }

    /// Credentials used to authenticate with an SMB server.
    struct Credentials: Sendable {
        /// The user name to authenticate as.
        public var user: String?

        /// The password for `user`.
        public var password: String?

        /// The authentication domain.
        public var domain: String?

        /// The workstation name to report during authentication.
        public var workstation: String?

        /// Creates an SMB credentials value.
        ///
        /// - Parameters:
        ///   - user: The user name to authenticate as.
        ///   - password: The password for `user`.
        ///   - domain: The authentication domain.
        ///   - workstation: The workstation name to report during authentication.
        public init(
            user: String? = nil,
            password: String? = nil,
            domain: String? = nil,
            workstation: String? = nil,
        ) {
            self.user = user
            self.password = password
            self.domain = domain
            self.workstation = workstation
        }
    }

    /// Connection options that affect SMB negotiation and transfer behavior.
    struct Configuration: Sendable {
        /// The command timeout, in seconds.
        public var timeout: Int?

        /// The SMB dialect negotiation preference.
        public var dialect: Dialect?

        /// The SMB signing negotiation flags.
        public var securityMode: SecurityMode?

        /// Whether SMB encryption is required.
        public var requiresEncryption: Bool?

        /// Whether SMB signing is required.
        public var requiresSigning: Bool?

        /// The authentication mechanism to request.
        public var authentication: AuthenticationMethod?

        /// The preferred read/write block size.
        ///
        /// Values larger than the connected server supports are clamped by
        /// ``SMB/Connection/acceptedReadBlockSize(_:)`` and
        /// ``SMB/Connection/acceptedWriteBlockSize(_:)``.
        public var transferBlockSize: Int?

        /// Creates an SMB connection configuration.
        ///
        /// - Parameters:
        ///   - timeout: The command timeout, in seconds.
        ///   - dialect: The SMB dialect negotiation preference.
        ///   - securityMode: The SMB signing negotiation flags.
        ///   - requiresEncryption: Whether SMB encryption is required.
        ///   - requiresSigning: Whether SMB signing is required.
        ///   - authentication: The authentication mechanism to request.
        ///   - transferBlockSize: The preferred read/write block size.
        public init(
            timeout: Int? = nil,
            dialect: Dialect? = nil,
            securityMode: SecurityMode? = nil,
            requiresEncryption: Bool? = nil,
            requiresSigning: Bool? = nil,
            authentication: AuthenticationMethod? = nil,
            transferBlockSize: Int? = nil,
        ) {
            self.timeout = timeout
            self.dialect = dialect
            self.securityMode = securityMode
            self.requiresEncryption = requiresEncryption
            self.requiresSigning = requiresSigning
            self.authentication = authentication
            self.transferBlockSize = transferBlockSize
        }
    }

    /// SMB dialect negotiation preferences.
    enum Dialect: Equatable, Sendable {
        /// Negotiate any supported SMB2 or SMB3 dialect.
        case any

        /// Negotiate any supported SMB2 dialect.
        case anySMB2

        /// Negotiate any supported SMB3 dialect.
        case anySMB3

        /// Require SMB 2.0.2.
        case smb2_02

        /// Require SMB 2.1.
        case smb2_10

        /// Require SMB 3.0.
        case smb3_00

        /// Require SMB 3.0.2.
        case smb3_02

        /// Require SMB 3.1.1.
        case smb3_11

        /// The bridge representation for this dialect.
        var bridgeValue: smb2_negotiate_version {
            switch self {
            case .any:
                SMB2_VERSION_ANY
            case .anySMB2:
                SMB2_VERSION_ANY2
            case .anySMB3:
                SMB2_VERSION_ANY3
            case .smb2_02:
                SMB2_VERSION_0202
            case .smb2_10:
                SMB2_VERSION_0210
            case .smb3_00:
                SMB2_VERSION_0300
            case .smb3_02:
                SMB2_VERSION_0302
            case .smb3_11:
                SMB2_VERSION_0311
            }
        }
    }

    /// Authentication mechanisms supported by `libsmb2`.
    enum AuthenticationMethod: Equatable, Sendable {
        /// Let `libsmb2` choose the authentication mechanism.
        case automatic

        /// Use NTLMSSP authentication.
        case ntlmssp

        /// Use Kerberos authentication.
        case kerberos

        /// The bridge representation for this authentication method.
        var bridgeValue: SMB2AuthenticationMethod {
            switch self {
            case .automatic:
                .automatic
            case .ntlmssp:
                .ntlmssp
            case .kerberos:
                .kerberos
            }
        }
    }

    /// SMB signing negotiation flags.
    struct SecurityMode: OptionSet, Equatable, Sendable {
        /// The raw SMB security mode bitfield.
        public let rawValue: UInt16

        /// Advertise that SMB signing is supported.
        public static let signingEnabled = SecurityMode(rawValue: SMB2SecurityMode.signingEnabled.rawValue)

        /// Require SMB signing.
        public static let signingRequired = SecurityMode(rawValue: SMB2SecurityMode.signingRequired.rawValue)

        /// Creates a security mode from a raw SMB bitfield.
        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        /// The bridge representation for this security mode.
        var bridgeValue: SMB2SecurityMode {
            SMB2SecurityMode(rawValue: rawValue)
        }
    }
}
