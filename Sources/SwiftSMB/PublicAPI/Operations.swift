//
// Part of SwiftSMB
// Operations.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

public extension SMB {
    /// Lists disk shares advertised by a server.
    ///
    /// The method connects to the server's `IPC$` share, enumerates shares through SRVSVC, filters the result to disk
    /// shares, and disconnects before returning.
    ///
    /// - Parameters:
    ///   - server: The server to query.
    ///   - credentials: Optional credentials for authenticated enumeration.
    ///   - configuration: SMB negotiation and connection options.
    ///   - includeHidden: Whether to include shares marked as hidden.
    /// - Returns: The server's visible disk shares.
    /// - Throws: ``SMB/Error`` when context creation, authentication, connection, enumeration, or disconnection fails.
    static func listShares(
        server: Server,
        credentials: Credentials? = nil,
        configuration: Configuration = Configuration(),
        includeHidden: Bool = false
    ) async throws -> [Share] {
        let context = try await makeConfiguredContext(
            configuration: configuration,
            credentials: credentials,
            server: server
        )
        defer { await Bridge.destroyContext(context) }

        return try await Bridge.listShares(
            context: context,
            server: server.address,
            user: credentials?.user,
            includeHidden: includeHidden
        ).map(Share.init)
    }

    /// Connects to an SMB share.
    ///
    /// The returned ``SMB/Connection`` owns the underlying SMB context and disconnects automatically when deallocated.
    /// Call ``SMB/Connection/disconnect()`` to close the connection explicitly.
    ///
    /// - Parameters:
    ///   - server: The server hosting the share.
    ///   - credentials: Optional credentials for the connection.
    ///   - share: The share name to connect to.
    ///   - configuration: SMB negotiation and transfer options.
    /// - Returns: An open connection to `share`.
    /// - Throws: ``SMB/Error`` when the context cannot be created or the share connection fails.
    static func connect(
        server: Server,
        credentials: Credentials? = nil,
        share: String,
        configuration: Configuration = Configuration()
    ) async throws -> Connection {
        try validateShareName(share, operation: .smb2ConnectShare)

        let context = try await makeConfiguredContext(
            configuration: configuration,
            credentials: credentials,
            server: server
        )

        do {
            try await Bridge.connectShare(
                context: context,
                server: server.address,
                share: share,
                user: credentials?.user
            )
            let maxReadSize = try await Bridge.getMaxReadSize(context: context)
            let maxWriteSize = try await Bridge.getMaxWriteSize(context: context)
            return Connection(
                server: server,
                share: share,
                configuration: configuration,
                context: context,
                maxReadSize: maxReadSize,
                maxWriteSize: maxWriteSize
            )
        }
        catch {
            await Bridge.destroyContext(context)
            throw error
        }
    }

    /// Parses an SMB URL into its components.
    ///
    /// - Parameter string: An SMB URL, such as `smb://server/share/path`.
    /// - Returns: The parsed URL components.
    /// - Throws: ``SMB/Error`` if `string` is not a valid SMB URL.
    static func parseURL(_ string: String) throws -> ParsedURL {
        let parsedURL = try ParsedURL(Bridge.parseURL(string))
        try validateShareName(parsedURL.share, operation: .smb2ParseURL)
        if let path = parsedURL.path {
            try validatePath(path, operation: .smb2ParseURL, allowRoot: true)
        }
        return parsedURL
    }

    /// Creates a context and applies negotiation options and credentials, destroying the context on failure.
    internal static func makeConfiguredContext(
        configuration: Configuration,
        credentials: Credentials?,
        server: Server
    ) async throws -> Bridge.Context {
        let context = try Bridge.createContext()
        do {
            try await configure(context, with: configuration)
            try await configureCredentials(credentials, server: server, on: context)
            return context
        }
        catch {
            await Bridge.destroyContext(context)
            throw error
        }
    }

    /// Applies negotiation options to a context before connection.
    internal static func configure(_ context: Bridge.Context, with configuration: Configuration) async throws {
        if let timeout = configuration.timeout {
            guard timeout >= 0, timeout <= Int(Int32.max) else {
                throw Error.invalidArgument(
                    cause: .timeoutMustFitInInt32Seconds,
                    onOperation: .smb2SetTimeout
                )
            }
            try await Bridge.setTimeout(Int32(timeout), on: context)
        }

        if let dialect = configuration.dialect {
            try await Bridge.setVersion(dialect.bridgeValue, on: context)
        }

        if let securityMode = configuration.securityMode {
            try await Bridge.setSecurityMode(securityMode.bridgeValue, on: context)
        }

        switch configuration.encryption {
        case .automatic:
            break
        case .disabled:
            try await Bridge.setSeal(false, on: context)
        case .required:
            try await Bridge.setSeal(true, on: context)
        }

        if let requiresSigning = configuration.requiresSigning {
            try await Bridge.setSign(requiresSigning, on: context)
        }

        if let authentication = configuration.authentication {
            try await Bridge.setAuthentication(authentication.bridgeValue, on: context)
        }
    }

    /// Applies authentication settings to a context before connection.
    internal static func configureCredentials(
        _ credentials: Credentials?,
        server: Server,
        on context: Bridge.Context
    ) async throws {
        if let user = credentials?.user {
            try await Bridge.setUser(user, on: context)
        }
        if let password = credentials?.password {
            try await Bridge.setPassword(password, on: context)
        }
        if let domain = credentials?.domain ?? server.domain {
            try await Bridge.setDomain(domain, on: context)
        }
        if let workstation = credentials?.workstation {
            try await Bridge.setWorkstation(workstation, on: context)
        }
    }
}
