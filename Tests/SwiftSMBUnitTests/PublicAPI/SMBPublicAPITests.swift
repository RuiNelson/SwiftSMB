//
// Part of SwiftSMB
// SMBPublicAPITests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
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
            remark: "Private data"
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
            transferBlockSize: 65536
        )

        #expect(configuration.timeout == 30)
        #expect(configuration.dialect == .anySMB3)
        #expect(configuration.securityMode?.contains(.signingEnabled) == true)
        #expect(configuration.encryption == .disabled)
        #expect(configuration.authentication == .ntlmssp)
        #expect(configuration.transferBlockSize == 65536)
    }

    @Test("legacy encryption representation maps to the typed policy")
    func legacyEncryptionRepresentationMapsToTypedPolicy() {
        #expect(SMB.Configuration(requiresEncryption: nil).encryption == .automatic)
        #expect(SMB.Configuration(requiresEncryption: false).encryption == .disabled)
        #expect(SMB.Configuration(requiresEncryption: true).encryption == .required)
    }

    @Test("configuration preserves the legacy encryption coding key")
    func configurationPreservesLegacyEncryptionCodingKey() throws {
        let encoded = try JSONEncoder().encode(SMB.Configuration(encryption: .required))
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])

        #expect(object["requiresEncryption"] as? Bool == true)
        #expect(object["encryptionRequirement"] == nil)
        #expect(try JSONDecoder().decode(SMB.Configuration.self, from: encoded).encryption == .required)
    }

    @Test("public server and credentials are separate") func publicServerAndCredentialsAreSeparate() {
        let server = SMB.Server(host: "example.test", port: 445, domain: "CORP")
        let credentials = SMB.Credentials(
            user: "alice",
            password: "secret",
            workstation: "LAPTOP"
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

    @Test("negotiated dialect maps known raw values") func negotiatedDialectMapsKnownRawValues() {
        #expect(SMB.NegotiatedDialect(rawValue: 0x0202) == .smb2_02)
        #expect(SMB.NegotiatedDialect(rawValue: 0x0210) == .smb2_10)
        #expect(SMB.NegotiatedDialect(rawValue: 0x0300) == .smb3_00)
        #expect(SMB.NegotiatedDialect(rawValue: 0x0302) == .smb3_02)
        #expect(SMB.NegotiatedDialect(rawValue: 0x0311) == .smb3_11)
        #expect(SMB.NegotiatedDialect(rawValue: 0x9999) == .unknown(0x9999))
    }

    @Test("security values model an Everyone full-control DACL")
    func securityValuesModelEveryoneFullControlDACL() {
        let entry = SMB.AccessControlEntry(
            kind: .allowed,
            flags: [.objectInherit, .containerInherit],
            accessMask: .genericAll,
            trustee: .everyone
        )
        let dacl = SMB.AccessControlList(entries: [entry])
        let descriptor = SMB.SecurityDescriptor(discretionaryAccessControlList: dacl)

        #expect(SMB.SecurityIdentifier.everyone.debugDescription == "S-1-1-0")
        #expect(descriptor.discretionaryAccessControlList?.entries == [entry])
        #expect(entry.flags.contains(.objectInherit))
        #expect(entry.accessMask == .genericAll)
    }
}
