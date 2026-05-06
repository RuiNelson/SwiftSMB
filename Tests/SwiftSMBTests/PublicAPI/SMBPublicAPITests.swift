//
// Part of SwiftSMB
// SMBPublicAPITests.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

import Foundation
import SwiftSMB
import Testing

struct SMBPublicAPITests {
    @Test("public URL parser returns SwiftSMB values") func publicURLParserReturnsSwiftSMBValues() throws {
        let url = try SMB.parseURL("smb://CORP;alice@example.test/share/path/to/file.txt")

        #expect(url.domain == "CORP")
        #expect(url.user == "alice")
        #expect(url.server == "example.test")
        #expect(url.share == "share")
        #expect(url.path == "path/to/file.txt")
    }

    @Test("public share value exposes attributes") func publicShareValueExposesAttributes() {
        let share = SMB.Share(
            name: "data$",
            kind: .diskTree,
            attributes: [.hidden, .temporary],
            remark: "Private data",
        )

        #expect(share.name == "data$")
        #expect(share.kind == .diskTree)
        #expect(share.isHidden)
        #expect(share.isTemporary)
        #expect(share.remark == "Private data")
    }

    @Test("public configuration can express connection options") func publicConfigurationCanExpressConnectionOptions() {
        let configuration = SMB.Configuration(
            timeout: 30,
            dialect: .anySMB3,
            securityMode: [.signingEnabled],
            requiresEncryption: false,
            requiresSigning: false,
            authentication: .ntlmssp,
            transferBlockSize: 65536,
        )

        #expect(configuration.timeout == 30)
        #expect(configuration.dialect == .anySMB3)
        #expect(configuration.securityMode?.contains(.signingEnabled) == true)
        #expect(configuration.authentication == .ntlmssp)
        #expect(configuration.transferBlockSize == 65536)
    }

    @Test("public server and credentials are separate") func publicServerAndCredentialsAreSeparate() {
        let server = SMB.Server(host: "example.test", port: 445, domain: "CORP")
        let credentials = SMB.Credentials(
            user: "alice",
            password: "secret",
            workstation: "LAPTOP",
        )

        #expect(server.host == "example.test")
        #expect(server.port == 445)
        #expect(server.domain == "CORP")
        #expect(credentials.user == "alice")
        #expect(credentials.password == "secret")
        #expect(credentials.workstation == "LAPTOP")
    }

    @Test("public file options compose") func publicFileOptionsCompose() {
        let options: SMB.File.OpenOptions = [.create, .exclusive, .truncate]

        #expect(options.contains(.create))
        #expect(options.contains(.exclusive))
        #expect(options.contains(.truncate))
        #expect(!options.contains(.append))
    }

    @Test("public status values are exposed") func publicStatusValuesAreExposed() {
        #expect(SMB.SMBStatus.success.name == "SMB2_STATUS_SUCCESS")
        #expect(SMB.SMBStatus.noSuchFile.severity == .error)
        #expect(SMB.SMBStatusSeverity.warning.rawValue == 0x8000_0000)
    }
}
