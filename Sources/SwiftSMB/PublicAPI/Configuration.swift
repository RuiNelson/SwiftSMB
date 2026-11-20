//
// Part of SwiftSMB
// Configuration.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import SMB2

public extension SMB {
    /// Identifies an SMB server.
    struct Server: Codable, Hashable, Equatable, CustomDebugStringConvertible, Sendable {
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
        ///
        /// Bare IPv6 hosts are always bracketed: `libsmb2` splits the address at the first `:` after the host, so an
        /// unbracketed IPv6 address would be misparsed even when no port is set. A host with a single colon is treated
        /// as an embedded `host:port` and passed through unchanged.
        var address: String {
            let isBareIPv6 = !host.hasPrefix("[") && host.lazy.count(where: { $0 == ":" }) >= 2
            let bracketedHost = isBareIPv6 ? "[\(host)]" : host
            guard let port else { return bracketedHost }
            return "\(bracketedHost):\(port)"
        }

        public var debugDescription: String {
            "SMB.Server(host: \(host), port: \(String(describing: port)), domain: \(String(describing: domain)))"
        }
    }

    /// Credentials used to authenticate with an SMB server.
    struct Credentials: Codable, CustomDebugStringConvertible, Equatable, Hashable, Sendable {
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
            workstation: String? = nil
        ) {
            self.user = user
            self.password = password
            self.domain = domain
            self.workstation = workstation
        }

        public var debugDescription: String {
            "SMB.Credentials(user: \(user ?? "nil"), password: <redacted>, domain: \(domain ?? "nil"), workstation: \(workstation ?? "nil"))"
        }
    }

    /// Connection options that affect SMB negotiation and transfer behaviour.
    struct Configuration: Codable, CustomDebugStringConvertible, Equatable, Hashable, Sendable {
        /// How SMB encryption is negotiated with the server.
        public enum Encryption: String, Codable, Equatable, Hashable, Sendable {
            /// Advertise encryption support and use it when the server or share requires it.
            case automatic

            /// Do not advertise or use SMB encryption.
            ///
            /// Connections to servers or shares that require encryption fail when this value is selected.
            case disabled

            /// Require SMB encryption and fail the connection when it cannot be negotiated.
            case required
        }

        /// How SMB signing is negotiated with the server.
        public enum Signing: String, Codable, Equatable, Hashable, Sendable {
            /// Sign messages when the server or share requires it, and otherwise leave the decision to libsmb2.
            case automatic

            /// Do not require signing.
            ///
            /// Connections to servers that require signing still sign their messages, because the server does not
            /// accept unsigned ones.
            case disabled

            /// Require SMB signing and fail the connection when it cannot be negotiated.
            case required
        }

        /// The command timeout, in seconds.
        ///
        /// Commands that exceed the timeout are aborted with an I/O timeout status. `nil` or `0` disables command
        /// timeouts. Establishing the connection always has a deadline: this value when it is positive, otherwise 30
        /// seconds.
        public var timeout: Int?

        /// The SMB dialect negotiation preference.
        public var dialect: Dialect?

        /// The SMB signing negotiation flags.
        public var securityMode: SecurityMode?

        /// The encoded form of ``encryption``: `nil`, `false`, and `true` stand for ``Encryption/automatic``,
        /// ``Encryption/disabled``, and ``Encryption/required``. It is kept, under the `requiresEncryption` key, so
        /// that configurations encoded by earlier versions still decode.
        private var encryptionRequirement: Bool?

        /// The SMB encryption negotiation policy.
        public var encryption: Encryption {
            get {
                switch encryptionRequirement {
                case nil: .automatic
                case false: .disabled
                case true: .required
                }
            }
            set {
                switch newValue {
                case .automatic:
                    encryptionRequirement = nil
                case .disabled:
                    encryptionRequirement = false
                case .required:
                    encryptionRequirement = true
                }
            }
        }

        /// The encoded form of ``signing``: `nil`, `false`, and `true` stand for ``Signing/automatic``,
        /// ``Signing/disabled``, and ``Signing/required``. It is kept, under the `requiresSigning` key, so that
        /// configurations encoded by earlier versions still decode.
        private var signingRequirement: Bool?

        /// The SMB signing negotiation policy.
        public var signing: Signing {
            get {
                switch signingRequirement {
                case nil: .automatic
                case false: .disabled
                case true: .required
                }
            }
            set {
                switch newValue {
                case .automatic:
                    signingRequirement = nil
                case .disabled:
                    signingRequirement = false
                case .required:
                    signingRequirement = true
                }
            }
        }

        /// Whether SMB signing is required.
        ///
        /// `nil`, `false`, and `true` stand for ``Signing/automatic``, ``Signing/disabled``, and
        /// ``Signing/required``.
        @available(*, deprecated, message: "Use signing, which has the same three states as encryption.")
        public var requiresSigning: Bool? {
            get { signingRequirement }
            set { signingRequirement = newValue }
        }

        /// The authentication mechanism to request.
        public var authentication: AuthenticationMethod?

        /// The preferred read/write block size.
        ///
        /// Values larger than the connected server supports are clamped by ``SMB/Connection/acceptedReadBlockSize(_:)``
        /// and ``SMB/Connection/acceptedWriteBlockSize(_:)``.
        public var transferBlockSize: Int?

        /// How strictly paths are checked before they are sent to the server.
        ///
        /// SMB does not tell the client which file system holds a share, and each one accepts different names: `CON` is
        /// a valid directory on a Mac or a Samba server, but not on NTFS. The server always has the final word and
        /// returns its own error for a name its file system rejects. A stricter level only rejects such names locally,
        /// before any request is sent.
        public enum PathValidation: String, Codable, CaseIterable, Equatable, Hashable, Sendable {
            /// Only the rules of the SMB protocol ([MS-FSCC] 2.1.5): each component is 1 to 255 UTF-16 code units long,
            /// has no control characters (U+0000–U+001F) and none of `" \ / : | < > * ?`, and is not `..`; the whole
            /// path is at most 32,760 UTF-16 code units long.
            case smb

            /// The ``smb`` rules and those of NTFS: no component ends in a space or a period, and none is a reserved
            /// device name such as `CON`, `PRN`, `AUX`, `NUL`, `COM1` or `LPT1`, with or without an extension.
            case ntfsOverSMB

            /// The ``smb`` rules and those of Unix file systems such as ext4, APFS and ZFS: each component is at most
            /// 255 bytes long in UTF-8.
            case unixOverSMB
        }

        /// The encoded form of ``pathValidation``: `nil` stands for ``PathValidation/smb``, so that configurations
        /// encoded with the default level stay the same as those encoded by earlier versions.
        private var _pathValidation: PathValidation?

        /// How strictly paths are checked before they are sent to the server. The default is
        /// ``PathValidation/smb``.
        public var pathValidation: PathValidation {
            get {
                _pathValidation ?? .smb
            }
            set {
                _pathValidation = newValue == .smb ? nil : newValue
            }
        }

        /// Creates an SMB connection configuration.
        ///
        /// - Parameters:
        ///   - timeout: The command timeout, in seconds.
        ///   - dialect: The SMB dialect negotiation preference.
        ///   - securityMode: The SMB signing negotiation flags.
        ///   - encryption: The SMB encryption negotiation policy.
        ///   - signing: The SMB signing negotiation policy.
        ///   - authentication: The authentication mechanism to request.
        ///   - transferBlockSize: The preferred read/write block size.
        ///   - pathValidation: How strictly paths are checked before they are sent to the server.
        public init(
            timeout: Int? = nil,
            dialect: Dialect? = nil,
            securityMode: SecurityMode? = nil,
            encryption: Encryption = .automatic,
            signing: Signing = .automatic,
            authentication: AuthenticationMethod? = nil,
            transferBlockSize: Int? = nil,
            pathValidation: PathValidation = .smb
        ) {
            self.timeout = timeout
            self.dialect = dialect
            self.securityMode = securityMode
            self.encryption = encryption
            self.signing = signing
            self.authentication = authentication
            self.transferBlockSize = transferBlockSize
            self.pathValidation = pathValidation
        }

        /// Creates an SMB connection configuration with the signing requirement as a `Bool?`.
        ///
        /// - Parameters:
        ///   - timeout: The command timeout, in seconds.
        ///   - dialect: The SMB dialect negotiation preference.
        ///   - securityMode: The SMB signing negotiation flags.
        ///   - encryption: The SMB encryption negotiation policy.
        ///   - requiresSigning: Whether SMB signing is required.
        ///   - authentication: The authentication mechanism to request.
        ///   - transferBlockSize: The preferred read/write block size.
        ///   - pathValidation: How strictly paths are checked before they are sent to the server.
        @available(
            *,
            deprecated,
            message: "Use init(timeout:dialect:securityMode:encryption:signing:authentication:transferBlockSize:pathValidation:)."
        )
        public init(
            timeout: Int? = nil,
            dialect: Dialect? = nil,
            securityMode: SecurityMode? = nil,
            encryption: Encryption = .automatic,
            requiresSigning: Bool?,
            authentication: AuthenticationMethod? = nil,
            transferBlockSize: Int? = nil,
            pathValidation: PathValidation = .smb
        ) {
            self.init(
                timeout: timeout,
                dialect: dialect,
                securityMode: securityMode,
                encryption: encryption,
                signing: .automatic,
                authentication: authentication,
                transferBlockSize: transferBlockSize,
                pathValidation: pathValidation
            )
            signingRequirement = requiresSigning
        }

        /// Decodes a configuration.
        ///
        /// An unknown ``pathValidation`` value, such as a level added by a later version, decodes as
        /// ``PathValidation/smb``: the server still checks every name, so the configuration stays usable.
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            timeout = try container.decodeIfPresent(Int.self, forKey: .timeout)
            dialect = try container.decodeIfPresent(Dialect.self, forKey: .dialect)
            securityMode = try container.decodeIfPresent(SecurityMode.self, forKey: .securityMode)
            encryptionRequirement = try container.decodeIfPresent(Bool.self, forKey: .encryptionRequirement)
            signingRequirement = try container.decodeIfPresent(Bool.self, forKey: .signingRequirement)
            authentication = try container.decodeIfPresent(AuthenticationMethod.self, forKey: .authentication)
            transferBlockSize = try container.decodeIfPresent(Int.self, forKey: .transferBlockSize)
            let pathValidation = try container.decodeIfPresent(String.self, forKey: ._pathValidation)
            self.pathValidation = pathValidation.flatMap(PathValidation.init(rawValue:)) ?? .smb
        }

        public var debugDescription: String {
            "SMB.Configuration(timeout: \(String(describing: timeout)), dialect: \(String(describing: dialect)), securityMode: \(String(describing: securityMode)), encryption: \(encryption), signing: \(signing), authentication: \(String(describing: authentication)), transferBlockSize: \(String(describing: transferBlockSize)), pathValidation: \(pathValidation))"
        }

        private enum CodingKeys: String, CodingKey {
            case timeout
            case dialect
            case securityMode
            case encryptionRequirement = "requiresEncryption"
            case signingRequirement = "requiresSigning"
            case authentication
            case transferBlockSize
            case _pathValidation = "pathValidation"
        }
    }

    /// SMB dialect negotiation preferences.
    enum Dialect: Int, Codable, Equatable, Sendable {
        /// Negotiate any supported SMB2 or SMB3 dialect.
        case any = 0

        /// Negotiate any supported SMB2 dialect.
        case anySMB2 = 2

        /// Negotiate any supported SMB3 dialect.
        case anySMB3 = 3

        /// Require SMB 2.0.2.
        case smb2_02 = 202

        /// Require SMB 2.1.
        case smb2_10 = 210

        /// Require SMB 3.0.
        case smb3_00 = 300

        /// Require SMB 3.0.2.
        case smb3_02 = 302

        /// Require SMB 3.1.1.
        case smb3_11 = 311

        /// The bridge representation for this dialect.
        var bridgeValue: Bridge.DialectPreference {
            switch self {
            case .any: .any
            case .anySMB2: .anySMB2
            case .anySMB3: .anySMB3
            case .smb2_02: .smb2_02
            case .smb2_10: .smb2_10
            case .smb3_00: .smb3_00
            case .smb3_02: .smb3_02
            case .smb3_11: .smb3_11
            }
        }
    }

    /// Authentication mechanisms supported by `libsmb2`.
    enum AuthenticationMethod: Int, Codable, Equatable, Hashable, Sendable {
        /// Let `libsmb2` choose the authentication mechanism.
        case automatic = 0

        /// Use NTLMSSP authentication.
        case ntlmssp = 1

        /// Use Kerberos authentication.
        ///
        /// - Important: Kerberos does not work yet. SwiftSMB's libsmb2 build has no Kerberos support (it needs a GSSAPI
        /// library), so connecting with this method fails. Use ``ntlmssp`` or ``automatic`` instead. The case is kept
        /// so that the type and stored configurations stay stable until Kerberos is implemented.
        case kerberos = 2

        /// The bridge representation for this authentication method.
        var bridgeValue: Bridge.AuthenticationMethod {
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
    struct SecurityMode: OptionSet, Equatable, Hashable, CustomDebugStringConvertible, Codable, Sendable {
        /// The raw SMB security mode bitfield.
        public let rawValue: UInt16

        /// Advertise that SMB signing is supported.
        public static let signingEnabled = SecurityMode(rawValue: Bridge.SecurityMode.signingEnabled.rawValue)

        /// Require SMB signing.
        public static let signingRequired = SecurityMode(rawValue: Bridge.SecurityMode.signingRequired.rawValue)

        /// Creates a security mode from a raw SMB bitfield.
        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public var debugDescription: String {
            describeFlags([
                (.signingEnabled, "signingEnabled"),
                (.signingRequired, "signingRequired"),
            ], typeName: "SMB.SecurityMode")
        }

        /// The bridge representation for this security mode.
        var bridgeValue: Bridge.SecurityMode {
            Bridge.SecurityMode(rawValue: rawValue)
        }
    }
}
