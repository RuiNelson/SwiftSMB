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

    @Test("public share value exposes full information") func publicShareValueExposesFullInformation() {
        let share = SMB.Share(
            name: "data",
            kind: .diskTree,
            path: #"C:\Data"#,
            permissions: [.read, .write],
            maximumUsers: 10,
            currentUsers: 2
        )

        #expect(share.path == #"C:\Data"#)
        #expect(share.permissions == [.read, .write])
        #expect(share.maximumUsers == 10)
        #expect(share.currentUsers == 2)

        let standard = SMB.Share(name: "data", kind: .diskTree)
        #expect(standard.path == nil)
        #expect(standard.permissions == nil)
        #expect(standard.maximumUsers == nil)
        #expect(standard.currentUsers == nil)
    }

    @Test("public configuration can express connection options") func publicConfigurationCanExpressConnectionOptions() {
        let configuration = SMB.Configuration(
            timeout: 30,
            dialect: .anySMB3,
            securityMode: [.signingEnabled],
            encryption: .disabled,
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

    @Test("configurations encoded with the legacy encryption key decode to the typed policy")
    func legacyEncryptionKeyDecodesToTypedPolicy() throws {
        func decode(_ json: String) throws -> SMB.Configuration.Encryption {
            try JSONDecoder().decode(SMB.Configuration.self, from: Data(json.utf8)).encryption
        }
        #expect(try decode("{}") == .automatic)
        #expect(try decode(#"{"requiresEncryption": false}"#) == .disabled)
        #expect(try decode(#"{"requiresEncryption": true}"#) == .required)
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

@Suite("SMB.LibraryVersion")
struct LibraryVersionTests {
    @Test("the linked libsmb2 reports the release SwiftSMB pins")
    func linkedVersion() {
        #expect(SMB.libsmb2Version == SMB.LibraryVersion(major: 7, minor: 0, patch: 0))
        #expect(SMB.libsmb2Version.description == "7.0.0")
    }

    @Test("versions compare component by component")
    func ordering() {
        let v6_3_2 = SMB.LibraryVersion(major: 6, minor: 3, patch: 2)
        let v7_0_0 = SMB.LibraryVersion(major: 7, minor: 0, patch: 0)
        let v7_0_1 = SMB.LibraryVersion(major: 7, minor: 0, patch: 1)
        #expect(v6_3_2 < v7_0_0)
        #expect(v7_0_0 < v7_0_1)
        #expect(!(v7_0_1 < v7_0_0))
    }
}
