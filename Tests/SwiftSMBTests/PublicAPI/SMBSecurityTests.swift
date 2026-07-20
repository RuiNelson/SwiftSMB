//
// Part of SwiftSMB
// SMBSecurityTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct SMBSecurityTests {
    @Test("sets an Everyone full-control DACL")
    func setsEveryoneFullControlDACL() throws {
        let connection = try SMB.connect(server: SMB.Server(host: testServerHost), share: TestShare.public)
        defer { try? connection.disconnect() }

        let path = uniquePath("security") + ".txt"
        let file = try connection.openFile(at: path, accessMode: .writeOnly, options: [.create, .exclusive])
        try file.close()
        defer { try? connection.removeFile(at: path) }

        let descriptor = SMB.SecurityDescriptor(
            discretionaryAccessControlList: SMB.AccessControlList(entries: [
                SMB.AccessControlEntry(
                    kind: .allowed,
                    accessMask: .genericAll,
                    trustee: .everyone
                ),
            ])
        )
        try connection.setSecurityDescriptor(descriptor, at: path)
    }
}
