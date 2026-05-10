//
// Part of SwiftSMB
// SMBOperations.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation

extension SMB {
    /// Lists disk shares advertised by a server.
    ///
    /// The method connects to the server's `IPC$` share, enumerates shares
    /// through SRVSVC, filters the result to disk shares, and disconnects before
    /// returning.
    ///
    /// - Parameters:
    ///   - server: The server to query.
    ///   - credentials: Optional credentials for authenticated enumeration.
    ///   - configuration: SMB negotiation and connection options.
    ///   - includeHidden: Whether to include shares marked as hidden.
    /// - Returns: The server's visible disk shares.
    /// - Throws: ``SMB/Error`` when context creation, authentication,
    ///   connection, enumeration, or disconnection fails.
    public static func listShares(
        server: Server,
        credentials: Credentials? = nil,
        configuration: Configuration = Configuration(),
        includeHidden: Bool = false,
    ) throws -> [Share] {
        let context = try Bridge.bridgeExecution {
            try Bridge.createContext()
        }
        defer { Bridge.destroyContext(context) }

        try configure(context, with: configuration)
        configureCredentials(credentials, server: server, on: context)

        return try Bridge.bridgeExecution {
            try Bridge.listShares(
                context: context,
                server: server.address,
                user: credentials?.user,
                includeHidden: includeHidden,
            ).map(Share.init)
        }
    }

    /// Connects to an SMB share.
    ///
    /// The returned ``SMB/Connection`` owns the underlying SMB context and
    /// disconnects automatically when deallocated. Call
    /// ``SMB/Connection/disconnect()`` to close the connection explicitly.
    ///
    /// - Parameters:
    ///   - server: The server hosting the share.
    ///   - credentials: Optional credentials for the connection.
    ///   - share: The share name to connect to.
    ///   - configuration: SMB negotiation and transfer options.
    /// - Returns: An open connection to `share`.
    /// - Throws: ``SMB/Error`` when the context cannot be created or the share
    ///   connection fails.
    public static func connect(
        server: Server,
        credentials: Credentials? = nil,
        share: String,
        configuration: Configuration = Configuration(),
    ) throws -> Connection {
        try validateShareName(share, operation: .smb2ConnectShare)

        let context = try Bridge.bridgeExecution {
            try Bridge.createContext()
        }

        do {
            try configure(context, with: configuration)
            configureCredentials(credentials, server: server, on: context)
            try Bridge.bridgeExecution {
                try Bridge.connectShare(
                    context: context,
                    server: server.address,
                    share: share,
                    user: credentials?.user,
                )
            }
            return Connection(server: server, share: share, configuration: configuration, context: context)
        }
        catch {
            Bridge.destroyContext(context)
            throw error
        }
    }

    /// Parses an SMB URL into its components.
    ///
    /// - Parameter string: An SMB URL, such as `smb://server/share/path`.
    /// - Returns: The parsed URL components.
    /// - Throws: ``SMB/Error`` if `string` is not a valid SMB URL.
    public static func parseURL(_ string: String) throws -> ParsedURL {
        let context = try Bridge.bridgeExecution {
            try Bridge.createContext()
        }
        defer { Bridge.destroyContext(context) }

        return try Bridge.bridgeExecution {
            let parsedURL = try ParsedURL(Bridge.parseURL(string, context: context))
            try validateShareName(parsedURL.share, operation: .smb2ParseURL)
            if let path = parsedURL.path {
                try validatePath(path, operation: .smb2ParseURL, allowRoot: true)
            }
            return parsedURL
        }
    }

    /// Applies negotiation options to a context before connection.
    static func configure(_ context: SMB2Context, with configuration: Configuration) throws {
        if let timeout = configuration.timeout {
            guard timeout >= 0, timeout <= Int(Int32.max) else {
                throw Error.invalidArgument(
                    cause: .timeoutMustFitInInt32Seconds,
                    onOperation: .smb2SetTimeout,
                )
            }
            Bridge.setTimeout(Int32(timeout), on: context)
        }

        if let dialect = configuration.dialect {
            Bridge.setVersion(dialect.bridgeValue, on: context)
        }

        if let securityMode = configuration.securityMode {
            Bridge.setSecurityMode(securityMode.bridgeValue, on: context)
        }

        if let requiresEncryption = configuration.requiresEncryption {
            Bridge.setSeal(requiresEncryption, on: context)
        }

        if let requiresSigning = configuration.requiresSigning {
            Bridge.setSign(requiresSigning, on: context)
        }

        if let authentication = configuration.authentication {
            Bridge.setAuthentication(authentication.bridgeValue, on: context)
        }
    }

    /// Applies authentication settings to a context before connection.
    static func configureCredentials(_ credentials: Credentials?, server: Server, on context: SMB2Context) {
        if let user = credentials?.user {
            Bridge.setUser(user, on: context)
        }
        if let password = credentials?.password {
            Bridge.setPassword(password, on: context)
        }
        if let domain = credentials?.domain ?? server.domain {
            Bridge.setDomain(domain, on: context)
        }
        if let workstation = credentials?.workstation {
            Bridge.setWorkstation(workstation, on: context)
        }
    }
}
